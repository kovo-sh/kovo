import { IntegrityError, LimitExceededError, UnavailableError } from "../ports/errors.js";
import { errorForFailure, type HttpCallContext } from "./errors.js";

// Byte-bounded response bodies. A bound is enforced before anything past it is buffered: a declared
// Content-Length over the bound fails without reading, and a streamed body fails as soon as it
// crosses it.

/** The declared Content-Length, or null when absent or malformed. */
export function declaredLength(response: Response): number | null {
  const value = response.headers.get("content-length");
  if (value === null || !/^\d{1,15}$/.test(value)) return null;
  return Number(value);
}

function limitError(context: HttpCallContext, maxBytes: number): LimitExceededError {
  return new LimitExceededError({ ...context, limitBytes: maxBytes });
}

async function cancelQuietly(body: ReadableStream<Uint8Array> | null): Promise<void> {
  try {
    await body?.cancel();
  } catch {
    // The body is being abandoned; a failure to cancel it changes nothing for the caller.
  }
}

/** Discards a response body the caller does not need (frees the connection). */
export async function discardBody(response: Response): Promise<void> {
  await cancelQuietly(response.body);
}

/** Rejects with UnavailableError (`read_stalled`) when `read` takes longer than `timeoutMs`. */
async function withinIdleTimeout<T>(
  read: Promise<T>,
  timeoutMs: number,
  context: HttpCallContext,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stalled = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new UnavailableError({ ...context, reason: "timeout", code: "read_stalled" }));
    }, timeoutMs);
  });
  try {
    return await Promise.race([read, stalled]);
  } finally {
    clearTimeout(timer);
  }
}

export interface LimitOptions {
  /** The caller's cancellation signal (its abort reason is rethrown as is). */
  readonly callerSignal?: AbortSignal | undefined;
  /**
   * Longest wait for the next chunk while the consumer is reading. It measures the provider, not
   * the consumer: time the consumer spends between reads never counts.
   */
  readonly idleTimeoutMs?: number | undefined;
}

/**
 * A stream that passes `source` through and errors with LimitExceededError once more than
 * `maxBytes` have flowed, cancelling the source. Read failures become UnavailableError (or the
 * caller's abort reason when its signal aborted).
 */
export function limitByteStream(
  source: ReadableStream<Uint8Array>,
  maxBytes: number,
  context: HttpCallContext,
  options: LimitOptions = {},
): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  let total = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      let chunk: Awaited<ReturnType<typeof reader.read>>;
      try {
        chunk =
          options.idleTimeoutMs === undefined
            ? await reader.read()
            : await withinIdleTimeout(reader.read(), options.idleTimeoutMs, context);
      } catch (error) {
        controller.error(errorForFailure(context, error, options.callerSignal));
        await reader.cancel().catch(() => undefined);
        return;
      }
      if (chunk.done) {
        controller.close();
        return;
      }
      total += chunk.value.byteLength;
      if (total > maxBytes) {
        controller.error(limitError(context, maxBytes));
        await reader.cancel().catch(() => undefined);
        return;
      }
      controller.enqueue(chunk.value);
    },
    async cancel(reason) {
      await reader.cancel(reason).catch(() => undefined);
    },
  });
}

/** Concatenates chunks into one buffer. */
export function concatBytes(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * Reads the whole body, failing with LimitExceededError past `maxBytes` (before reading when the
 * declared length is already too large). `onChunk` sees each chunk's size before it is kept; what it
 * throws cancels the body and is rethrown as is.
 */
export async function readBodyLimited(
  response: Response,
  maxBytes: number,
  context: HttpCallContext,
  callerSignal?: AbortSignal,
  onChunk?: (bytes: number) => void,
): Promise<Uint8Array> {
  const declared = declaredLength(response);
  if (declared !== null && declared > maxBytes) {
    await cancelQuietly(response.body);
    throw limitError(context, maxBytes);
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = limitByteStream(response.body, maxBytes, context, { callerSignal }).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (onChunk !== undefined) {
      try {
        onChunk(value.byteLength);
      } catch (error) {
        await reader.cancel().catch(() => undefined);
        throw error;
      }
    }
    chunks.push(value);
    total += value.byteLength;
  }
  return concatBytes(chunks, total);
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Parses a bounded body as JSON. Bytes that are not UTF-8 JSON are a malformed response
 * (UnavailableError, retryable: usually a truncated or intercepted reply); documents that parse but
 * fail validation are the caller's IntegrityError.
 */
export async function readJsonLimited(
  response: Response,
  maxBytes: number,
  context: HttpCallContext,
  callerSignal?: AbortSignal,
  onChunk?: (bytes: number) => void,
): Promise<unknown> {
  const declared = declaredLength(response);
  if (declared !== null && declared > maxBytes) {
    await cancelQuietly(response.body);
    throw limitError(context, maxBytes);
  }
  // JSON.parse needs text, not a concatenated binary copy alongside all received byte chunks.
  // Decode incrementally with a request-local decoder: multi-byte UTF-8 can span chunks.
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const chunks: string[] = [];
  if (response.body !== null) {
    const reader = limitByteStream(response.body, maxBytes, context, { callerSignal }).getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        try {
          onChunk?.(value.byteLength);
        } catch (error) {
          await reader.cancel().catch(() => undefined);
          throw error;
        }
        try {
          chunks.push(decoder.decode(value, { stream: true }));
        } catch (error) {
          await reader.cancel().catch(() => undefined);
          throw malformedJson(context, error);
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
  try {
    chunks.push(decoder.decode());
    const text = chunks.join("");
    // Drop the decoded pieces before parsing allocates the document. Keeping them reachable
    // through JSON.parse needlessly retains another whole body alongside its flattened text.
    chunks.length = 0;
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw malformedJson(context, error);
  }
}

function malformedJson(context: HttpCallContext, vendorCause: unknown): UnavailableError {
  return new UnavailableError({
    ...context,
    reason: "server_error",
    code: "malformed_response",
    vendorCause,
  });
}

export function parseJsonBytes(bytes: Uint8Array, context: HttpCallContext): unknown {
  try {
    return JSON.parse(utf8.decode(bytes)) as unknown;
  } catch (error) {
    throw malformedJson(context, error);
  }
}

/** The IntegrityError for a vendor document that parsed but failed validation. */
export function malformedDocument(
  context: HttpCallContext,
  code: string,
  vendorCause?: unknown,
): IntegrityError {
  return new IntegrityError({ ...context, code, vendorCause });
}
