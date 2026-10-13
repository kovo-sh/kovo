import { setTimeout as delay } from "node:timers/promises";

// Shared HTTP plumbing for the feed and registry adapters (OSV, KEV, npm upstream). These adapters
// only ever contact fixed public origins; the transport is injectable so hermetic tests can route
// those exact URLs to local fake servers without the production code having a configurable origin.

/** Performs one HTTP request. Production uses the global `fetch`; tests route to local servers. */
export type HttpTransport = (url: URL, init: RequestInit) => Promise<Response>;

export const fetchTransport: HttpTransport = (url, init) => fetch(url, init);

/**
 * A transport that sends requests for fixed origins to other base URLs, keeping path and query
 * (`routes` maps an origin such as `https://api.osv.dev` to a base such as
 * `http://127.0.0.1:4455/osv`). A request for any other origin fails like a network error, so it
 * can never reach the internet. Hermetic tests route the adapters' constant origins to local fake
 * servers with it, and a fake-mode stack to its fake-vendor hub; never with real adapters.
 */
export function originRoutedTransport(
  routes: Readonly<Record<string, string>>,
  observe?: (url: URL) => void,
): HttpTransport {
  return async (url, init) => {
    observe?.(new URL(url));
    const base = routes[url.origin];
    if (base === undefined) throw new TypeError(`fetch failed: no route for ${url.origin}`);
    return fetch(new URL(`${base.replace(/\/$/, "")}${url.pathname}${url.search}`), init);
  };
}

/** Waits `ms` milliseconds (rejecting when `signal` aborts). Injectable so tests never wait. */
export type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;

export const timerSleep: Sleep = async (ms, signal) => {
  await delay(ms, undefined, signal === undefined ? {} : { signal });
};

/** The caller's signal combined with a per-request deadline. */
export function deadlineSignal(timeoutMs: number, signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
}

/**
 * A signal that aborts (with a `TimeoutError`) unless `settle()` is called within `timeoutMs`: a
 * deadline for the response headers that does not limit how long the body may take afterwards.
 */
export function headersDeadline(
  timeoutMs: number,
  signal?: AbortSignal,
): { readonly signal: AbortSignal; settle(): void } {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new DOMException("response headers timed out", "TimeoutError"));
  }, timeoutMs);
  return {
    signal: signal === undefined ? controller.signal : AbortSignal.any([signal, controller.signal]),
    settle: () => clearTimeout(timer),
  };
}
