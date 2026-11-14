// Closed log vocabulary: apps/control-plane/src/services/merge.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "changelog_clearance_unavailable",
  "ci_rerun_not_requested",
] as const;
export const LOG_ENUM_CODES = ["ci_rerun_not_requested"] as const;
