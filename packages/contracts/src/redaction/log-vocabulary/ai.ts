// Closed log vocabulary: apps/control-plane/src/services/ai.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "changelog_check_document_failed",
  "changelog_clearance_check_failed",
  "review_hints_skipped",
] as const;
