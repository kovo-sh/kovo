// Closed log vocabulary: apps/control-plane/src/bin.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "migration_arguments_refused",
  "migration_configuration_failed",
] as const;
export const LOG_ENUM_CODES = ["arguments_refused", "migrate_refused"] as const;
