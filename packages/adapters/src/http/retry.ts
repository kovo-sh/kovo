import { PortError, RateLimitedError } from "../ports/errors.js";
import type { Sleep } from "./transport.js";
import type { Clock } from "../ports/clock.js";
import type { PortErrorInit } from "../ports/errors.js";
import type { UpstreamCircuit } from "./circuit.js";

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
  maxAttempts: 3,
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
  readonly clock?: Clock;
  readonly random?: () => number;
  readonly maxElapsedMs?: number;
  readonly circuit?: UpstreamCircuit;
  readonly context?: PortErrorInit;
}

/** Runs `operation` (given the 1-based attempt number) with the policy's bounded retries. */
export async function withRetries<T>(
  operation: (attempt: number, remainingMs: number) => Promise<T>,
  options: RetryOptions,
): Promise<T> {
  const { policy, sleep, signal } = options;
  validateRetryPolicy(policy);
  const started = options.clock?.now().getTime() ?? 0;
  const budget = options.maxElapsedMs ?? 30_000;
  let waited = 0;
  const elapsed = () => Math.max(waited, (options.clock?.now().getTime() ?? started) - started);
  for (let attempt = 1; ; attempt += 1) {
    signal?.throwIfAborted();
    const generation =
      options.circuit && options.clock && options.context
        ? options.circuit.enter(options.clock, options.context)
        : undefined;
    try {
      const result = await operation(attempt, Math.max(1, budget - elapsed()));
      if (generation !== undefined) options.circuit?.success(generation);
      return result;
    } catch (error) {
      if (signal?.aborted === true) {
        if (generation !== undefined) options.circuit?.cancel(generation);
        throw signal.reason;
      }
      const permanentHttp =
        error instanceof PortError &&
        /^http_4\d\d$/.test(error.code ?? "") &&
        error.code !== "http_408" &&
        error.code !== "http_429";
      if (
        !(error instanceof PortError) ||
        !error.retryable ||
        error.retryStopped === true ||
        permanentHttp
      ) {
        if (generation !== undefined) options.circuit?.success(generation);
        // Ambiguous writes need the caller's existing reconcile-before-retry path.
        throw error instanceof PortError && error.kind !== "ambiguous_outcome"
          ? error.stopRetries()
          : error;
      }
      if (generation !== undefined && options.clock)
        options.circuit?.failure(generation, options.clock);
      if (attempt >= policy.maxAttempts) throw error.stopRetries();
      // Equal jitter avoids synchronized retries while retaining exponential growth.
      const exponential = backoffMs(policy, attempt);
      let wait = Math.ceil(exponential * (0.5 + 0.5 * (options.random ?? Math.random)()));
      if (error instanceof RateLimitedError) {
        if (error.retryAfterMs > policy.maxInlineWaitMs) throw error.stopRetries();
        wait = Math.max(wait, error.retryAfterMs);
      }
      if (elapsed() + wait >= budget) throw error.stopRetries();
      await sleep(wait, signal);
      waited += wait;
      if (elapsed() >= budget) throw error.stopRetries();
    }
  }
}
