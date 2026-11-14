// Closed log vocabulary: apps/control-plane/src/services/github.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "github_authorization_sessions_ended",
  "github_delivery_redelivery_failed",
  "github_delivery_walk_cursor_failed",
  "github_installation_reconcile_failed",
  "workspace_fingerprint_comparison_unavailable",
] as const;
export const LOG_ENUM_CODES = [
  "webhook_admission_timeout",
  "webhook_database_unavailable",
  "webhook_lock_timeout",
  "webhook_statement_timeout",
] as const;
