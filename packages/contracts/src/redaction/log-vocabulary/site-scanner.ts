// Closed log vocabulary: apps/site-scanner.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "scanner_arguments_refused",
  "scanner_completed",
  "scanner_configuration_failed",
  "scanner_job_failed",
] as const;
export const LOG_ENUM_CODES = ["observed", "refused_over_cap", "seeded"] as const;
