// Closed log vocabulary: apps/control-plane/src/services/retention.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "deleted_account_purged",
  "provider_event_unresolved_expired",
  "restore_a_deleted_account_s_work_could_not_be_ended",
  "restore_a_deleted_account_s_work_winds_down_after_launch",
  "restore_a_deleted_account_s_workflows_cancelled",
  "uninstall_cleanup_failed",
  "webhook_delivery_unresolved_expired",
] as const;
