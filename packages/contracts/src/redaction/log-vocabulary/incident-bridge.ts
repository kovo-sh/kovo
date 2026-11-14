// Closed log vocabulary: apps/incident-bridge.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "ack_unknown_incident",
  "drill_page_dry_run",
  "drill_refused",
  "heartbeat_ok",
  "incident_acknowledged",
  "incident_attach_skipped",
  "incident_bridge_boot_failed",
  "incident_bridge_stop",
  "incident_page",
  "incident_stale_resolved",
  "rollout_lock_stale",
] as const;
export const LOG_FIELD_KEYS = [
  "acked_issue",
  "incident_severity",
  "incident_state",
  "resolution_reason",
  "resolve_actor",
] as const;
export const LOG_ENUM_CODES = [
  "drill_identity_unmatched",
  "drill_run_missing",
  "drill_window_closed",
  "production_stale",
  "stored_incident_unreadable",
  "terraform_stale",
  "tier_page",
  "worker_drain_stale",
] as const;
