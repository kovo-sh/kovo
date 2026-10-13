import { crc32, inflateRawSync } from "node:zlib";

import type { HttpCallContext } from "../http/errors.js";
import { IntegrityError, LimitExceededError, UnavailableError } from "../ports/errors.js";

// A streaming reader for the OSV export (`npm/all.zip`, 216 MB compressed on 2026-09-26). It walks
// the local file headers in order, so the archive is never buffered or written to disk. The OSV
// exporter writes sizes and CRCs into every local header (general-purpose flag 0, deflate), which
// is what makes a forward-only read possible; an entry deferring them to a data descriptor (flag
// bit 3) is refused rather than guessed at. Each entry is bounded before and after inflation and
// checked against its CRC-32. An entry that declares more than the bound is skipped unread and
// reported without data, so one oversized record does not end the archive.

export interface ZipEntry {
  readonly name: string;
  /** The inflated bytes; null when the entry declares more than `maxEntryBytes` (skipped unread). */
  readonly data: Uint8Array | null;
}

export interface ZipLimits {
  /** Largest compressed entry read. */
  readonly maxCompressedBytes: number;
  /** Largest inflated entry produced. */
  readonly maxEntryBytes: number;
}

const LOCAL_FILE_HEADER = 0x04034b50;
const CENTRAL_DIRECTORY_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY = 0x06064b50;
const LOCAL_HEADER_BYTES = 30;
const FLAG_ENCRYPTED = 0x0001;
const FLAG_DATA_DESCRIPTOR = 0x0008;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;
const ZIP64_EXTRA = 0x0001;
const U32_MAX = 0xffffffff;

/** Buffers just enough of a byte stream to hand out exact-length slices. */
class ByteReader {
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
  #buffer: Uint8Array = new Uint8Array(0);
  #offset = 0;
  #ended = false;

  constructor(source: ReadableStream<Uint8Array>) {
    this.#reader = source.getReader();
  }

  get #available(): number {
    return this.#buffer.byteLength - this.#offset;
  }

  /** Exactly `length` bytes, or null when the stream ends first. */
  async read(length: number): Promise<Uint8Array | null> {
    while (this.#available < length) {
      if (this.#ended) return null;
      const { done, value } = await this.#reader.read();
      if (done) {
        this.#ended = true;
        continue;
      }
      const next = new Uint8Array(this.#available + value.byteLength);
      next.set(this.#buffer.subarray(this.#offset));
      next.set(value, this.#available);
      this.#buffer = next;
      this.#offset = 0;
    }
    const slice = this.#buffer.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return slice;
  }

  /** Discards exactly `length` bytes without buffering them; false when the stream ends first. */
  async skip(length: number): Promise<boolean> {
    let remaining = length;
    for (;;) {
      const take = Math.min(remaining, this.#available);
      this.#offset += take;
      remaining -= take;
      if (remaining === 0) return true;
      if (this.#ended) return false;
      const { done, value } = await this.#reader.read();
      if (done) {
        this.#ended = true;
        continue;
      }
      this.#buffer = value;
      this.#offset = 0;
    }
  }

  /** Reads and discards the rest of the stream (so digests over the whole stream complete). */
  async drain(): Promise<void> {
    this.#buffer = new Uint8Array(0);
    this.#offset = 0;
    while (!this.#ended) {
      const { done } = await this.#reader.read();
      if (done) this.#ended = true;
    }
  }

  async cancel(): Promise<void> {
    await this.#reader.cancel().catch(() => undefined);
  }
}

interface LocalHeader {
  readonly flags: number;
  readonly method: number;
  readonly crc: number;
  readonly compressedSize: number;
  readonly size: number;
  readonly nameLength: number;
  readonly extraLength: number;
}

function parseLocalHeader(bytes: Uint8Array): LocalHeader {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    flags: view.getUint16(6, true),
    method: view.getUint16(8, true),
    crc: view.getUint32(14, true),
    compressedSize: view.getUint32(18, true),
    size: view.getUint32(22, true),
    nameLength: view.getUint16(26, true),
    extraLength: view.getUint16(28, true),
  };
}

/** Applies a ZIP64 extended-information extra field to sizes stored as 0xFFFFFFFF. */
function zip64Sizes(
  header: LocalHeader,
  extra: Uint8Array,
): { size: number; compressedSize: number } | null {
  let { size, compressedSize } = header;
  if (size !== U32_MAX && compressedSize !== U32_MAX) return { size, compressedSize };
  const view = new DataView(extra.buffer, extra.byteOffset, extra.byteLength);
  for (let at = 0; at + 4 <= extra.byteLength;) {
    const id = view.getUint16(at, true);
    const length = view.getUint16(at + 2, true);
    if (id === ZIP64_EXTRA) {
      let field = at + 4;
      const readU64 = (): number | null => {
        if (field + 8 > at + 4 + length || field + 8 > extra.byteLength) return null;
        const value = view.getBigUint64(field, true);
        field += 8;
        return value > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(value);
      };
      if (size === U32_MAX) {
        const value = readU64();
        if (value === null) return null;
        size = value;
      }
      if (compressedSize === U32_MAX) {
        const value = readU64();
        if (value === null) return null;
        compressedSize = value;
      }
      return { size, compressedSize };
    }
    at += 4 + length;
  }
  return null;
}

/**
 * Yields each file entry of a ZIP stream in archive order, then drains the stream through the
 * central directory. Directory entries are skipped; an entry declaring more than
 * `limits.maxEntryBytes` is yielded with `data: null` and its bytes skipped. IntegrityError for
 * layouts it cannot read safely (encryption, data descriptors, unknown methods or records, CRC or
 * size mismatches), LimitExceededError when an entry's compressed bytes exceed their bound or it
 * inflates past its bound despite its declared size (a zip bomb), UnavailableError when the stream
 * ends before the central directory (a truncated download). Stopping the iteration early cancels
 * the stream.
 */
export async function* readZipEntries(
  source: ReadableStream<Uint8Array>,
  limits: ZipLimits,
  context: HttpCallContext,
): AsyncGenerator<ZipEntry, void, undefined> {
  const reader = new ByteReader(source);
  const malformed = (code: string, vendorCause?: unknown) =>
    new IntegrityError({ ...context, code, vendorCause });
  const truncated = () =>
    new UnavailableError({ ...context, reason: "network", code: "truncated_archive" });
  const names = new TextDecoder("utf-8", { fatal: true });
  let finished = false;
  try {
    for (;;) {
      const signature = await reader.read(4);
      if (signature === null) throw truncated();
      const kind = new DataView(signature.buffer, signature.byteOffset, 4).getUint32(0, true);
      if (
        kind === CENTRAL_DIRECTORY_HEADER ||
        kind === END_OF_CENTRAL_DIRECTORY ||
        kind === ZIP64_END_OF_CENTRAL_DIRECTORY
      ) {
        break;
      }
      if (kind !== LOCAL_FILE_HEADER) throw malformed("malformed_archive");
      const rest = await reader.read(LOCAL_HEADER_BYTES - 4);
      if (rest === null) throw truncated();
      const headerBytes = new Uint8Array(LOCAL_HEADER_BYTES);
      headerBytes.set(signature);
      headerBytes.set(rest, 4);
      const header = parseLocalHeader(headerBytes);
      if ((header.flags & FLAG_ENCRYPTED) !== 0) throw malformed("encrypted_archive_entry");
      if ((header.flags & FLAG_DATA_DESCRIPTOR) !== 0)
        throw malformed("unsupported_archive_layout");
      const nameBytes = await reader.read(header.nameLength);
      const extra = await reader.read(header.extraLength);
      if (nameBytes === null || extra === null) throw truncated();
      let name: string;
      try {
        name = names.decode(nameBytes);
      } catch (error) {
        throw malformed("malformed_archive_entry_name", error);
      }
      const sizes = zip64Sizes(header, extra);
      if (sizes === null) throw malformed("malformed_archive");
      if (sizes.size > limits.maxEntryBytes) {
        // Too large to hand over: skip it unread (the caller's digest of the stream still covers
        // its bytes) and report it, so the rest of the archive is still read.
        if (!(await reader.skip(sizes.compressedSize))) throw truncated();
        if (!name.endsWith("/")) yield { name, data: null };
        continue;
      }
      if (sizes.compressedSize > limits.maxCompressedBytes) {
        // An entry within the size bound cannot deflate to this many bytes: corrupt or hostile.
        throw new LimitExceededError({ ...context, limitBytes: limits.maxCompressedBytes });
      }
      const compressed = await reader.read(sizes.compressedSize);
      if (compressed === null) throw truncated();
      if (name.endsWith("/")) continue;

      let data: Uint8Array;
      if (header.method === METHOD_STORED) {
        data = compressed.slice();
      } else if (header.method === METHOD_DEFLATE) {
        try {
          const inflated = inflateRawSync(compressed, { maxOutputLength: limits.maxEntryBytes });
          data = new Uint8Array(inflated.buffer, inflated.byteOffset, inflated.byteLength);
        } catch (error) {
          if (error instanceof RangeError) {
            throw new LimitExceededError({ ...context, limitBytes: limits.maxEntryBytes });
          }
          throw malformed("malformed_archive_entry", error);
        }
      } else {
        throw malformed("unsupported_compression_method");
      }
      if (data.byteLength !== sizes.size || crc32(data) !== header.crc) {
        throw malformed("archive_entry_checksum_mismatch");
      }
      yield { name, data };
    }
    await reader.drain();
    finished = true;
  } finally {
    if (!finished) await reader.cancel();
  }
}
