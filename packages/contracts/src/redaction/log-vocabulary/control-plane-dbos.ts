// Closed log vocabulary: apps/control-plane/src/dbos.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "calibration_workflow_resumed_after_recovery",
  "dbos_drain_cancel_refused",
  "dbos_drain_cancel_truncated",
  "dbos_drain_ceiling_cancelled",
  "dbos_drain_check_failed",
  "dbos_drain_ended",
  "dbos_drain_started",
  "dbos_event",
  "dbos_launched",
  "dbos_pool_idle_client_error",
  "dbos_pool_transaction_timeouts_failed",
  "dbos_workflow_abandoned",
  "executor_heartbeat_failed",
  "handover_re_execution_metric_unavailable",
  "migration_dbos_retired_workflows_cancelled",
  "migration_dbos_retired_workflows_failed",
  "migration_dbos_retired_workflows_truncated",
  "orphan_no_longer_pending_on_its_gone_executor_not_resumed",
  "workflow_cancelled_before_d731_cutover",
  "workflow_dead_lettered_after_repeated_executor_loss",
  "workflow_duration_summary",
  "workflow_handed_over_to_original_queue",
  "workflow_operation_failed",
  "workflow_ownership_refused",
  "workflow_recovery_scan_busy",
] as const;
export const LOG_FIELD_KEYS = ["long_waits", "operationKind", "p90Ms", "p99Ms"] as const;
export const LOG_ENUM_CODES = [
  "account_binding_missing",
  "dbos_initialization_failed",
  "dbos_version_cancel_timeout",
  "fleet_handle_refused",
  "invalid_workflow_input",
  "latest_again",
  "run_wait_budget_exceeded",
  "version_cancel_latest_refused",
  "wait_exceeds_15_min",
] as const;
