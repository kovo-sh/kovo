// `Retry-After` (RFC 9110 §10.2.3): either delay-seconds or an HTTP-date. The date form is compared
// with the Clock port's `now`, never the host clock read here.

const DELAY_SECONDS = /^\d{1,10}$/;

/** Longest hint honoured, one day: anything longer is treated as one day. */
export const MAX_RETRY_AFTER_MS = 24 * 60 * 60 * 1000;

/**
 * The wait a `Retry-After` value asks for, in milliseconds (0 for a date in the past), or null when
 * the header is absent or malformed.
 */
export function parseRetryAfterMs(value: string | null, now: Date): number | null {
  if (value === null) return null;
  const text = value.trim();
  if (text === "") return null;
  if (DELAY_SECONDS.test(text)) return Math.min(Number(text) * 1000, MAX_RETRY_AFTER_MS);
  // HTTP-date (IMF-fixdate, plus the obsolete forms Date.parse accepts), e.g.
  // "Sat, 26 Sep 2026 08:32:15 GMT". Require the GMT zone the RFC mandates.
  if (!text.endsWith("GMT")) return null;
  const at = Date.parse(text);
  if (Number.isNaN(at)) return null;
  return Math.min(Math.max(0, at - now.getTime()), MAX_RETRY_AFTER_MS);
}
