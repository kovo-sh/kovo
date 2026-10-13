import {
  MAX_DEPENDENCY_VERDICT_CHANGES,
  reasonCodeSchema,
  type DependencyVerdictChangeWire,
} from "@kovo/contracts";
import {
  DEPENDENCY_VERDICT_ENDPOINTS,
  dependencyVerdictsResponseSchema,
  evaluateDependencyChangesBodySchema,
  type DependencyVerdictsResponse,
} from "@kovo/contracts/api";

import { CLI_VERSION } from "../exit.js";
import { unavailableError, usageError } from "../errors.js";

// The hosted check: `POST /v1/dependency-verdicts` (SPEC "Public API"). The request body is the
// change list only, at most 500 changes a request; the key travels only in the Authorization
// header. A failure is reported by its HTTP status and RFC 9457 reason code only: never a response
// body, a header or the key.

export const DEFAULT_API_URL = "https://api.kovo.sh";

const ENDPOINT = DEPENDENCY_VERDICT_ENDPOINTS.evaluateDependencyChanges;

/** A 429's Retry-After is honoured up to this long; a longer wait gives up (exit 3). */
export const MAX_RETRY_AFTER_SECONDS = 60;
/** Without a usable Retry-After, a 429 waits this long (the `registry` bucket's refill interval). */
export const DEFAULT_RETRY_AFTER_SECONDS = 10;
/** Requests per batch, the first included, before a 429 gives up. */
export const MAX_ATTEMPTS = 4;
export const REQUEST_TIMEOUT_MS = 60_000;
/** A 500-verdict response is well under this; anything larger is not a valid answer. */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export interface HostedCheckOptions {
  readonly apiUrl: URL;
  readonly key: string;
  readonly fetch: typeof fetch;
  readonly sleep: (ms: number) => Promise<void>;
  /** One request's deadline, headers and whole body together; default {@link REQUEST_TIMEOUT_MS}. */
  readonly timeoutMs?: number;
}

/**
 * Parses `--api-url`: `https:`, or `http:` to a loopback host only; no credentials, query or
 * fragment. Error (exit 2): anything else.
 */
export function parseApiUrl(raw: string, flag = "--api-url"): URL {
  const code = flag === "--api-url" ? "invalid_api_url" : "invalid_url";
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw usageError(code, `${flag} must be an absolute https URL.`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  )
    throw usageError(
      code,
      `${flag} must be an https URL without credentials, query or fragment (http only for localhost).`,
    );
  if (!url.pathname.endsWith("/")) url.pathname = `${url.pathname}/`;
  return url;
}

/** `Retry-After` in seconds (delta-seconds or an HTTP date); null when absent or unusable. */
export function retryAfterSeconds(header: string | null, now: Date): number | null {
  if (header === null) return null;
  const trimmed = header.trim();
  if (/^\d{1,9}$/u.test(trimmed)) return Number(trimmed);
  const at = Date.parse(trimmed);
  if (!Number.isFinite(at)) return null;
  return Math.max(0, Math.ceil((at - now.getTime()) / 1000));
}

/** `promise`, or the timeout error as soon as `signal` aborts (the promise is then abandoned). */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(timeoutError());
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
        return undefined;
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error instanceof Error ? error : new Error("read failed"));
      },
    );
  });
}

async function readBounded(response: Response, signal: AbortSignal): Promise<string | null> {
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      // A stalled body never settles `read()` by itself: the deadline ends the wait, whatever the
      // fetch implementation does with the signal it was given.
      const { done, value } = await untilAborted(reader.read(), signal);
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function parseJson(text: string | null): unknown {
  if (text === null) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** The RFC 9457 reason code of a problem response, when it carries a known one. */
function problemReason(body: unknown): string | null {
  if (typeof body !== "object" || body === null || !("reason" in body)) return null;
  const parsed = reasonCodeSchema.safeParse(body.reason);
  return parsed.success ? parsed.data : null;
}

function httpFailure(status: number, reason: string | null): Error {
  return unavailableError(
    "http_error",
    `The hosted check answered HTTP ${status}${reason === null ? "" : ` (${reason})`}.`,
    reason === null ? { status } : { status, reason },
  );
}

function timeoutError(): Error {
  return unavailableError("timeout", "The hosted check did not answer in time.");
}

async function post(
  url: URL,
  body: string,
  options: HostedCheckOptions,
): Promise<{ readonly response: Response; readonly text: string | null }> {
  // One deadline for the request and the whole answer, held (with its timer) until both are done.
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), options.timeoutMs ?? REQUEST_TIMEOUT_MS);
  try {
    let response: Response;
    try {
      response = await options.fetch(url, {
        method: ENDPOINT.method,
        headers: {
          authorization: `Bearer ${options.key}`,
          "content-type": "application/json",
          accept: "application/json, application/problem+json",
          "user-agent": `kovo-cli/${CLI_VERSION}`,
        },
        body,
        redirect: "error",
        signal: deadline.signal,
      });
    } catch {
      // The error's own message can name the URL or the header that failed; neither is printed.
      if (deadline.signal.aborted) throw timeoutError();
      throw unavailableError("unreachable", "The hosted check could not be reached.");
    }
    try {
      return { response, text: await readBounded(response, deadline.signal) };
    } catch {
      if (deadline.signal.aborted) throw timeoutError();
      throw unavailableError("unreachable", "The hosted check's answer could not be read.");
    }
  } finally {
    clearTimeout(timer);
  }
}

function aligned(
  batch: readonly DependencyVerdictChangeWire[],
  response: DependencyVerdictsResponse,
): boolean {
  return (
    response.verdicts.length === batch.length &&
    response.verdicts.every(
      (verdict, index) =>
        verdict.ecosystem === batch[index]!.ecosystem &&
        verdict.name === batch[index]!.name &&
        verdict.version === batch[index]!.version,
    )
  );
}

async function judgeBatch(
  batch: readonly DependencyVerdictChangeWire[],
  options: HostedCheckOptions,
  now: () => Date,
): Promise<DependencyVerdictsResponse> {
  const body = evaluateDependencyChangesBodySchema.safeParse({ changes: batch });
  if (!body.success)
    throw usageError("invalid_change_list", "The change list does not fit the hosted check.");
  const url = new URL(ENDPOINT.path.replace(/^\//u, ""), options.apiUrl);
  const payload = JSON.stringify(body.data);
  for (let attempt = 1; ; attempt += 1) {
    const { response, text } = await post(url, payload, options);
    if (response.status === 429) {
      const wait = retryAfterSeconds(response.headers.get("retry-after"), now());
      const seconds = wait ?? DEFAULT_RETRY_AFTER_SECONDS;
      if (attempt >= MAX_ATTEMPTS || seconds > MAX_RETRY_AFTER_SECONDS)
        throw httpFailure(429, problemReason(parseJson(text)) ?? "rate_limited");
      await options.sleep(seconds * 1000);
      continue;
    }
    const json = parseJson(text);
    if (response.status !== 200) throw httpFailure(response.status, problemReason(json));
    const parsed = dependencyVerdictsResponseSchema.safeParse(json);
    if (!parsed.success || !aligned(batch, parsed.data))
      throw unavailableError(
        "invalid_response",
        "The hosted check's answer is not a valid verdict list for this request.",
      );
    return parsed.data;
  }
}

/**
 * Judges the changes through the hosted check, in batches of at most 500, in order. Errors (exit
 * 3): unreachable, timed out, an HTTP error (a 429 after its bounded retries), or an answer that is
 * not a verdict per requested change.
 */
export async function hostedVerdicts(
  changes: readonly DependencyVerdictChangeWire[],
  options: HostedCheckOptions,
  now: () => Date,
): Promise<DependencyVerdictsResponse> {
  const verdicts: DependencyVerdictsResponse["verdicts"] = [];
  const unavailable = new Set<DependencyVerdictsResponse["unavailable_signals"][number]>();
  for (let start = 0; start < changes.length; start += MAX_DEPENDENCY_VERDICT_CHANGES) {
    const batch = changes.slice(start, start + MAX_DEPENDENCY_VERDICT_CHANGES);
    const answer = await judgeBatch(batch, options, now);
    verdicts.push(...answer.verdicts);
    for (const signal of answer.unavailable_signals) unavailable.add(signal);
  }
  return { verdicts, unavailable_signals: [...unavailable].toSorted() };
}
