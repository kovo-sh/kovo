// Closed log vocabulary: apps/control-plane/src/release.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "migration_applied",
  "migration_authorizers_failed",
  "migration_authorizers_synced",
  "migration_authorizers_unchanged",
  "migration_database_ahead",
  "migration_dbos_applied",
  "migration_dbos_failed",
  "migration_lock_retry",
  "migration_operators_failed",
  "migration_operators_synced",
  "restore_dispatch_held",
  "restore_mark_failed",
] as const;
export const LOG_ENUM_CODES = [
  "drill_branch_identity_mismatch",
  "drill_connection_invalid",
  "drill_live_target_refused",
] as const;
