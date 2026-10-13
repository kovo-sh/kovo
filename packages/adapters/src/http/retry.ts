import { PortError, RateLimitedError } from "../ports/errors.js";
import type { Sleep } from "./transport.js";

// Bounded in-process retries for side-effect-free reads (SPEC: "Respect GitHub/registry/provider
// rate limits with bounded retries and durable waits"). Only retryable port errors are retried
// (UnavailableError, RateLimitedError). A rate limit whose Retry-After exceeds `maxInlineWaitMs` is
// returned to the caller at once, so the workflow waits durably (a DBOS sleep) instead of holding a
// worker; so is the last failure once the attempts are used up.

export interface RetryPolicy {
  /** Total attempts including the first (1 disables retries). */
  readonly maxAttempts: number;
  /** Backoff before the second attempt; doubled per attempt up to `maxDelayMs`. */
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
  /** Longest provider-requested wait honoured in-process. */
  readonly maxInlineWaitMs: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 500,
  maxDelayMs: 8_000,
  maxInlineWaitMs: 30_000,
};

export function validateRetryPolicy(policy: RetryPolicy): RetryPolicy {
  const counts = [
    policy.maxAttempts,
    policy.baseDelayMs,
    policy.maxDelayMs,
    policy.maxInlineWaitMs,
  ];
  if (counts.some((value) => !Number.isSafeInteger(value) || value < 0) || policy.maxAttempts < 1) {
    throw new RangeError("retry policy values must be non-negative integers, maxAttempts ≥ 1");
  }
  return policy;
}

/** The exponential backoff before attempt `attempt + 1`. */
export function backoffMs(policy: RetryPolicy, attempt: number): number {
  return Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** (attempt - 1));
}

export interface RetryOptions {
  readonly policy: RetryPolicy;
  readonly sleep: Sleep;
  readonly signal?: AbortSignal | undefined;
}

/** Runs `operation` (given the 1-based attempt number) with the policy's bounded retries. */
export async function withRetries<T>(
  operation: (attempt: number) => Promise<T>,
  options: RetryOptions,
): Promise<T> {
  const { policy, sleep, signal } = options;
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await operation(attempt);
    } catch (error) {
      if (!(error instanceof PortError) || !error.retryable || attempt >= policy.maxAttempts) {
        throw error;
      }
      let wait = backoffMs(policy, attempt);
      if (error instanceof RateLimitedError) {
        if (error.retryAfterMs > policy.maxInlineWaitMs) throw error;
        wait = Math.max(wait, error.retryAfterMs);
      }
      await sleep(wait, signal);
    }
  }
}
