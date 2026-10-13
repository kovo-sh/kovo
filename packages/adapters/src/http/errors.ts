import {
  AuthenticationError,
  BlockedDestinationError,
  ConflictError,
  InvalidRequestError,
  NotFoundError,
  PermissionDeniedError,
  PortError,
  PreconditionFailedError,
  RateLimitedError,
  UnavailableError,
  type PortService,
} from "../ports/errors.js";
import { parseRetryAfterMs } from "./retry-after.js";

// Translation of HTTP outcomes into the typed port errors. Callers branch on `kind`; nothing from
// the response body or URL reaches an error message (ports/errors.ts).

/** Which port call an HTTP exchange belongs to (labels every error it produces). */
export interface HttpCallContext {
  readonly service: PortService;
  readonly operation: string;
}

/** Headers some providers use for request correlation (kept only when a short machine token). */
const REQUEST_ID_HEADERS = ["x-request-id", "cf-ray", "x-amz-cf-id", "x-goog-request-id"];

export function providerRequestIdOf(response: Response): string | undefined {
  for (const header of REQUEST_ID_HEADERS) {
    const value = response.headers.get(header);
    if (value !== null) return value;
  }
  return undefined;
}

/**
 * The port error for an HTTP status the caller does not handle itself. `now` comes from the Clock
 * port and resolves an HTTP-date `Retry-After`.
 */
export function errorForStatus(context: HttpCallContext, response: Response, now: Date): PortError {
  const status = response.status;
  const init = {
    ...context,
    code: `http_${status}`,
    providerRequestId: providerRequestIdOf(response),
  };
  if (status === 429) {
    const retryAfterMs = parseRetryAfterMs(response.headers.get("retry-after"), now) ?? 0;
    return new RateLimitedError({ ...init, retryAfterMs });
  }
  if (status >= 300 && status < 400) {
    // The feed and registry adapters never follow redirects: they contact fixed origins only.
    return new BlockedDestinationError({ ...init, code: "redirect_refused" });
  }
  switch (status) {
    case 401:
      return new AuthenticationError(init);
    case 403:
      return new PermissionDeniedError(init);
    case 404:
    case 410:
      return new NotFoundError(init);
    case 408:
      return new UnavailableError({ ...init, reason: "timeout" });
    case 409:
      return new ConflictError(init);
    case 412:
      return new PreconditionFailedError(init);
    case 502:
    case 503:
    case 504:
      return new UnavailableError({ ...init, reason: status === 504 ? "timeout" : "overloaded" });
    default:
      return status >= 500
        ? new UnavailableError({ ...init, reason: "server_error" })
        : new InvalidRequestError(init);
  }
}

function isAbortLike(error: unknown, name: string): boolean {
  return error instanceof Error && error.name === name;
}

/**
 * The port error for a request or body read that failed without an HTTP status: our own deadline
 * (`TimeoutError`) or the network. A PortError passes through unchanged. When the caller's own
 * `signal` aborted, its reason is rethrown as is: cancellation is not a provider failure.
 */
export function errorForFailure(
  context: HttpCallContext,
  error: unknown,
  callerSignal?: AbortSignal,
): unknown {
  if (error instanceof PortError) return error;
  if (callerSignal?.aborted === true) return callerSignal.reason;
  if (isAbortLike(error, "TimeoutError")) {
    return new UnavailableError({ ...context, reason: "timeout", vendorCause: error });
  }
  return new UnavailableError({ ...context, reason: "network", vendorCause: error });
}
