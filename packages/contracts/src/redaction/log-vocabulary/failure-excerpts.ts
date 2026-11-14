// Closed log vocabulary: apps/control-plane/src/services/failure-excerpts.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "failure_excerpt_deleted_for_scope",
  "failure_excerpt_expired_scrubbed",
  "failure_excerpt_integrity_failed",
  "failure_excerpt_read",
  "failure_excerpt_sealed",
] as const;
