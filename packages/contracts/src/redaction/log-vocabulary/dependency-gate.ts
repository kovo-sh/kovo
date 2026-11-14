// Closed log vocabulary: apps/control-plane/src/services/dependency-gate.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "dependency_gate_alert_email_enqueued",
  "dependency_gate_deferred_head_resumed",
  "dependency_gate_evaluated",
  "dependency_gate_rate_limit_deferred",
  "dependency_gate_unavailable_reported",
] as const;
export const LOG_ENUM_CODES = [
  "dependency_gate_alert_email_enqueued",
  "dependency_gate_backoff_deferred",
  "dependency_gate_blocked",
  "dependency_gate_budget_deferred",
  "dependency_gate_failed",
  "dependency_gate_neutral",
  "dependency_gate_passed",
  "dependency_gate_refusal_deferred",
  "dependency_gate_resumed",
  "dependency_gate_skipped",
] as const;
