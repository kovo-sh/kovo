import type { Clock } from "../ports/clock.js";
import { PortError, UnavailableError } from "../ports/errors.js";
import { discardBody } from "./body.js";
import { errorForFailure, errorForStatus, type HttpCallContext } from "./errors.js";
import { validateRetryPolicy, withRetries, type RetryPolicy } from "./retry.js";
import { deadlineSignal, type HttpTransport, type Sleep } from "./transport.js";

// One small request layer shared by the OSV, KEV and npm adapters: reads only (GET, or a
// read-only JSON POST query such as OSV's `/v1/query`), no cookies, no credentials, no redirects, a
// deadline per attempt and bounded retries of retryable failures.

export interface HttpClientDeps {
  readonly transport: HttpTransport;
  readonly clock: Clock;
  readonly sleep: Sleep;
  readonly retry: RetryPolicy;
  /** Deadline for one attempt of a buffered call (request plus body). */
  readonly requestTimeoutMs: number;
  /** Sent as `User-Agent` so providers can identify Kovo's traffic. */
  readonly userAgent: string;
}

export interface GetRequest {
  readonly url: URL;
  readonly context: HttpCallContext;
  /**
   * A read-only query sent as a JSON POST body instead of a GET. Only for endpoints whose POST
   * changes nothing (so retrying it is as safe as retrying a GET).
   */
  readonly jsonQuery?: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** Non-2xx statuses the caller interprets itself (e.g. 304, 404); others become port errors. */
  readonly handledStatuses?: readonly number[];
  readonly signal?: AbortSignal | undefined;
}

function isAccepted(status: number, handled: readonly number[] | undefined): boolean {
  return (status >= 200 && status < 300) || (handled?.includes(status) ?? false);
}

/**
 * Sends one GET (or read-only POST query) and returns the response when its status is 2xx or handled; any other status is
 * translated (body discarded). `signal` bounds the whole exchange, including the caller's reading
 * of the returned body.
 */
export async function sendGet(
  deps: HttpClientDeps,
  request: GetRequest,
  signal: AbortSignal,
): Promise<Response> {
  let response: Response;
  try {
    response = await deps.transport(request.url, {
      method: request.jsonQuery === undefined ? "GET" : "POST",
      headers: {
        "user-agent": deps.userAgent,
        ...(request.jsonQuery === undefined ? {} : { "content-type": "application/json" }),
        ...request.headers,
      },
      ...(request.jsonQuery === undefined ? {} : { body: request.jsonQuery }),
      redirect: "manual",
      credentials: "omit",
      signal,
    });
  } catch (error) {
    throw errorForFailure(request.context, error, request.signal);
  }
  if (!isAccepted(response.status, request.handledStatuses)) {
    await discardBody(response);
    throw errorForStatus(request.context, response, deps.clock.now());
  }
  return response;
}

/**
 * GET with bounded retries. Each attempt runs under its own deadline, which aborts the request and,
 * once the response has arrived, its body stream: a body read cut off by the deadline fails like a
 * timed-out request (retryable UnavailableError `timeout`) and is retried.
 *
 * `consume` reads the body and receives the CALLER's signal, never the attempt deadline: body
 * readers (body.ts) rethrow the abort reason of the signal they are given as the caller's own
 * cancellation. The separate third argument lets yielding consumers also enforce the deadline
 * during local parsing without confusing it with the caller's cancellation.
 */
export async function getWithRetries<T>(
  deps: HttpClientDeps,
  request: GetRequest,
  consume: (
    response: Response,
    callerSignal: AbortSignal | undefined,
    attemptSignal: AbortSignal,
  ) => Promise<T>,
): Promise<T> {
  validateRetryPolicy(deps.retry);
  return withRetries(
    async () => {
      const attemptSignal = deadlineSignal(deps.requestTimeoutMs, request.signal);
      const response = await sendGet(deps, request, attemptSignal);
      try {
        return await consume(response, request.signal, attemptSignal);
      } catch (error) {
        await discardBody(response);
        throw attemptFailure(request, attemptSignal, error);
      }
    },
    { policy: deps.retry, sleep: deps.sleep, signal: request.signal },
  );
}

/**
 * What a failed `consume` becomes. Body reads already translate their failures (body.ts) and
 * decoders throw typed errors, which pass through; so does anything once the caller cancelled. An
 * untyped error after the attempt deadline fired is that deadline's doing: a timeout.
 */
function attemptFailure(request: GetRequest, attemptSignal: AbortSignal, error: unknown): unknown {
  if (error instanceof PortError || request.signal?.aborted === true) return error;
  if (!attemptSignal.aborted) return error;
  return new UnavailableError({ ...request.context, reason: "timeout", vendorCause: error });
}
