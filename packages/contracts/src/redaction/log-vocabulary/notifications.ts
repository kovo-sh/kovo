// Closed log vocabulary: apps/control-plane/src/services/notifications.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "analytics_event_unresolved_expired",
  "analytics_rows_rejected",
  "email_failed",
  "email_pending_expired",
  "email_provider_account_problem",
  "email_recipient_unverifiable",
  "email_recovery_failed",
  "email_send_interrupted",
  "email_suppression_reconcile_unavailable",
  "email_uncertain_expired",
  "email_uncertainty_unresolved",
  "notification_no_recipient",
  "notification_recipients_unverifiable",
  "webhook_event_invalid",
] as const;
