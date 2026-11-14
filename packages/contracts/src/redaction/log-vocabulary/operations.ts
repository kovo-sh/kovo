// Closed log vocabulary: apps/control-plane/src/services/operations.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "database_pool_acquire_timeout",
  "database_pooler_wait_timeout",
  "invariant_count_saturated",
  "invariant_daily_rate_exceeded",
  "invariant_read_failed",
  "invariant_violation",
  "invariant_workflow_violation",
  "never_persist_canary_planted",
  "never_persist_canary_result",
  "never_persist_canary_sink",
  "restore_gate_marked_the_database_sat_without_workers",
  "restore_gate_pending_reconciling_expiry_and_deletion_before_launch",
  "restore_gate_reconciled",
] as const;
export const LOG_FIELD_KEYS = [
  "deadline_reason",
  "newestHeartbeat",
  "passedHere",
  "pooler_statement",
] as const;
export const LOG_ENUM_CODES = [
  "canary_probe_failed",
  "daily_rates",
  "event_loop_stalled",
  "invariant_read_failed",
  "never_persist_canary_found_dbos_error",
  "never_persist_canary_found_dbos_tables",
  "never_persist_canary_found_posthog_egress",
  "never_persist_canary_found_sentry_egress",
  "open_or_admit",
  "operations.invariants",
] as const;
