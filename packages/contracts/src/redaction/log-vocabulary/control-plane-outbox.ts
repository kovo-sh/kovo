// Closed log vocabulary: apps/control-plane/src/outbox.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "outbox_dispatch_pass_failed",
  "outbox_row_abandoned_after_repeated_permanent_dispatch_failures",
  "outbox_row_not_dispatched",
  "outbox_start_claim_lost",
  "outbox_start_skipped_account_deactivated",
] as const;
export const LOG_ENUM_CODES = ["outbox_row_abandoned", "workflow_not_found"] as const;
