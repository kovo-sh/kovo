import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  OSV_BUCKET,
  OSV_EXPORT_OBJECT,
  objectMediaUrl,
  objectMetadataUrl,
} from "@kovo/adapters/osv";

import { CliError, unavailableError, usageError } from "../../errors.js";

// The OSV snapshot `kovo deps check --offline` judges against: OSV's public npm export
// (`gs://osv-vulnerabilities/npm/all.zip`), read over HTTPS from the bucket's JSON API, pinned to
// one object generation and checked like scripts/ci/osv_lockfile_diff.py's `install`: the bytes'
// size and MD5 must match the object metadata of exactly that generation, and the SHA-256 is
// recorded. The cache holds only this public database, one generation at a time; a cached copy is
// re-hashed before every use.

export const OSV_STORAGE_ORIGIN = "https://storage.googleapis.com";
/** The export was 216 MB on 2026-09-26; anything past this bound is refused, never truncated. */
export const OSV_SNAPSHOT_MAX_BYTES = 1024 * 1024 * 1024;
const METADATA_MAX_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 60_000;
/** A whole download's deadline: a slow link still fetches the export, a stalled one gives up. */
const DOWNLOAD_TIMEOUT_MS = 15 * 60_000;

export interface OsvSnapshot {
  /** The cached archive's path. */
  readonly path: string;
  readonly generation: string;
  readonly size: number;
  readonly sha256: string;
  /** The object's update time as the metadata reported it. */
  readonly updated: string;
  /** Read from the cache rather than downloaded in this run. */
  readonly cached: boolean;
}

interface SnapshotRecord {
  readonly object: string;
  readonly generation: string;
  readonly size: number;
  readonly md5: string;
  readonly sha256: string;
  readonly updated: string;
}

export interface OsvSnapshotOptions {
  /** The bucket API origin: OSV's (`https://storage.googleapis.com`) or a mirror of it. */
  readonly origin: URL;
  readonly cacheDir: string;
  /** Reproduce one generation (digits); null for the current one. */
  readonly generation: string | null;
  readonly fetch: typeof fetch;
}

function unavailable(code: string, message: string) {
  return unavailableError(code, `OSV snapshot: ${message}`);
}

/** A URL on `origin` with the path and query of OSV's bucket URL `url`. */
function onOrigin(url: URL, origin: URL): URL {
  const moved = new URL(url.pathname + url.search, origin);
  return moved;
}

function archivePath(cacheDir: string, generation: string): string {
  return join(cacheDir, `npm-all-${generation}.zip`);
}

function recordPath(cacheDir: string, generation: string): string {
  return join(cacheDir, `npm-all-${generation}.json`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function snapshotRecord(value: unknown): SnapshotRecord | null {
  if (!isRecord(value)) return null;
  const { object, generation, size, md5, sha256, updated } = value;
  if (
    object !== `gs://${OSV_BUCKET}/${OSV_EXPORT_OBJECT}` ||
    typeof generation !== "string" ||
    !/^\d{1,20}$/u.test(generation) ||
    typeof size !== "number" ||
    !Number.isSafeInteger(size) ||
    typeof md5 !== "string" ||
    typeof sha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(sha256) ||
    typeof updated !== "string"
  )
    return null;
  return { object, generation, size, md5, sha256, updated };
}

/** A file's chunks as bytes. */
async function* fileChunks(path: string): AsyncGenerator<Uint8Array> {
  for await (const chunk of createReadStream(path)) {
    const bytes: unknown = chunk;
    if (!(bytes instanceof Uint8Array)) throw new TypeError("expected bytes");
    yield bytes;
  }
}

async function fileSha256(
  path: string,
): Promise<{ readonly sha256: string; readonly size: number }> {
  const hash = createHash("sha256");
  let size = 0;
  for await (const bytes of fileChunks(path)) {
    size += bytes.byteLength;
    hash.update(bytes);
  }
  return { sha256: hash.digest("hex"), size };
}

/** The cached snapshot of `generation`, re-hashed; null when there is none or it does not match. */
async function cachedSnapshot(cacheDir: string, generation: string): Promise<OsvSnapshot | null> {
  let record: SnapshotRecord | null;
  try {
    record = snapshotRecord(JSON.parse(await readFile(recordPath(cacheDir, generation), "utf8")));
  } catch {
    return null;
  }
  if (record?.generation !== generation) return null;
  const path = archivePath(cacheDir, generation);
  let actual;
  try {
    actual = await fileSha256(path);
  } catch {
    return null;
  }
  if (actual.sha256 !== record.sha256 || actual.size !== record.size) return null;
  return {
    path,
    generation,
    size: record.size,
    sha256: record.sha256,
    updated: record.updated,
    cached: true,
  };
}

interface ObjectMetadata {
  readonly generation: string;
  readonly size: number;
  readonly md5: string;
  readonly updated: string;
}

async function readMetadata(options: OsvSnapshotOptions): Promise<ObjectMetadata> {
  const url = onOrigin(objectMetadataUrl(OSV_EXPORT_OBJECT), options.origin);
  url.searchParams.set("fields", "bucket,name,generation,size,md5Hash,updated");
  if (options.generation !== null) url.searchParams.set("generation", options.generation);
  let response: Response;
  try {
    response = await options.fetch(url, {
      headers: { accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw unavailable("osv_unreachable", "the bucket's metadata could not be read.");
  }
  if (response.status === 404 && options.generation !== null)
    throw unavailable(
      "osv_generation_gone",
      `generation ${options.generation} is no longer served.`,
    );
  if (response.status !== 200)
    throw unavailable("osv_unreachable", `the bucket's metadata answered HTTP ${response.status}.`);
  const text = await boundedText(response, METADATA_MAX_BYTES);
  let value: unknown;
  try {
    value = text === null ? undefined : JSON.parse(text);
  } catch {
    value = undefined;
  }
  if (!isRecord(value))
    throw unavailable("osv_metadata_invalid", "the object metadata is not a JSON object.");
  const { bucket, name, generation, size, md5Hash, updated } = value;
  if (
    bucket !== OSV_BUCKET ||
    name !== OSV_EXPORT_OBJECT ||
    typeof generation !== "string" ||
    !/^\d{1,20}$/u.test(generation) ||
    typeof size !== "string" ||
    !/^\d{1,15}$/u.test(size) ||
    // A composite object has no MD5: the download could not be checked, so it is refused.
    typeof md5Hash !== "string" ||
    !/^[A-Za-z0-9+/]{22}==$/u.test(md5Hash) ||
    typeof updated !== "string"
  )
    throw unavailable("osv_metadata_invalid", "the object metadata lacks a field the check needs.");
  if (options.generation !== null && generation !== options.generation)
    throw unavailable(
      "osv_generation_gone",
      `generation ${options.generation} is no longer served.`,
    );
  if (Number(size) > OSV_SNAPSHOT_MAX_BYTES)
    throw unavailable("osv_snapshot_too_large", "the export exceeds the CLI's bound.");
  return { generation, size: Number(size), md5: md5Hash, updated };
}

async function boundedText(response: Response, maxBytes: number): Promise<string | null> {
  if (response.body === null) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > maxBytes) return null;
    chunks.push(chunk);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    return null;
  }
}

async function download(
  options: OsvSnapshotOptions,
  metadata: ObjectMetadata,
): Promise<OsvSnapshot> {
  const url = onOrigin(objectMediaUrl(OSV_EXPORT_OBJECT, metadata.generation), options.origin);
  const partial = `${archivePath(options.cacheDir, metadata.generation)}.partial`;
  await rm(partial, { force: true });
  let response: Response;
  try {
    response = await options.fetch(url, {
      redirect: "error",
      signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
    });
  } catch {
    throw unavailable("osv_unreachable", "the export could not be downloaded.");
  }
  if (response.status === 404)
    throw unavailable(
      "osv_generation_gone",
      `generation ${metadata.generation} is no longer served.`,
    );
  if (response.status !== 200 || response.body === null)
    throw unavailable("osv_unreachable", `the export download answered HTTP ${response.status}.`);
  const served = response.headers.get("x-goog-generation");
  if (served !== null && served !== metadata.generation)
    throw unavailable(
      "osv_snapshot_mismatch",
      "the download is another generation than its metadata.",
    );
  const md5 = createHash("md5");
  const sha256 = createHash("sha256");
  let size = 0;
  const handle = await open(partial, "wx", 0o600);
  try {
    for await (const chunk of response.body) {
      size += chunk.byteLength;
      if (size > metadata.size)
        throw unavailable(
          "osv_snapshot_mismatch",
          "the download is larger than its metadata says.",
        );
      md5.update(chunk);
      sha256.update(chunk);
      await handle.write(chunk);
    }
  } catch (error) {
    await handle.close();
    await rm(partial, { force: true });
    if (error instanceof CliError) throw error;
    throw unavailable("osv_unreachable", "the export download was interrupted.");
  }
  await handle.close();
  if (size !== metadata.size || md5.digest("base64") !== metadata.md5) {
    await rm(partial, { force: true });
    throw unavailable(
      "osv_snapshot_mismatch",
      "the download does not match its metadata's size and MD5.",
    );
  }
  const digest = sha256.digest("hex");
  await rename(partial, archivePath(options.cacheDir, metadata.generation));
  const record: SnapshotRecord = {
    object: `gs://${OSV_BUCKET}/${OSV_EXPORT_OBJECT}`,
    generation: metadata.generation,
    size,
    md5: metadata.md5,
    sha256: digest,
    updated: metadata.updated,
  };
  await writeFile(
    recordPath(options.cacheDir, metadata.generation),
    `${JSON.stringify(record, null, 2)}\n`,
    {
      mode: 0o600,
    },
  );
  // One generation at a time: older snapshots are removed once the new one is in place.
  for (const name of await readdir(options.cacheDir)) {
    const match = /^npm-all-(\d+)\.(?:zip|json|zip\.partial)$/u.exec(name);
    if (match !== null && match[1] !== metadata.generation)
      await rm(join(options.cacheDir, name), { force: true });
  }
  return {
    path: archivePath(options.cacheDir, metadata.generation),
    generation: metadata.generation,
    size,
    sha256: digest,
    updated: metadata.updated,
    cached: false,
  };
}

/**
 * The OSV snapshot to judge against: a pinned generation from the cache when it is there (no
 * network), otherwise the current (or pinned) generation's metadata, then the cache when it holds
 * that generation, otherwise a checked download. Errors (exit 3): the bucket is unreachable, the
 * generation is gone, or the bytes do not match the metadata. Exit 2: the cache directory cannot be
 * created.
 */
export async function osvSnapshot(options: OsvSnapshotOptions): Promise<OsvSnapshot> {
  try {
    await mkdir(options.cacheDir, { recursive: true, mode: 0o700 });
    const stats = await stat(options.cacheDir);
    if (!stats.isDirectory()) throw new Error("not a directory");
  } catch {
    throw usageError("osv_cache_unusable", "The --osv-cache directory cannot be created or used.");
  }
  if (options.generation !== null) {
    const pinned = await cachedSnapshot(options.cacheDir, options.generation);
    if (pinned !== null) return pinned;
  }
  const metadata = await readMetadata(options);
  return (
    (await cachedSnapshot(options.cacheDir, metadata.generation)) ??
    (await download(options, metadata))
  );
}

/** The snapshot archive as a byte stream, for the zip reader. */
export function snapshotStream(snapshot: OsvSnapshot): ReadableStream<Uint8Array> {
  const chunks = fileChunks(snapshot.path);
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const next = await chunks.next();
      if (next.done === true) controller.close();
      else controller.enqueue(next.value);
    },
    async cancel() {
      await chunks.return(undefined);
    },
  });
}
