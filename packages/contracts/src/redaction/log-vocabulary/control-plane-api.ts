// Closed log vocabulary: apps/control-plane/src/api.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "credential_lookup_failed",
  "email_unsubscribe_refused",
  "github_webhook_ignored",
  "github_webhook_received",
  "github_webhook_refused",
  "idempotency_release_failed",
  "read_phase",
  "resend_webhook_ignored",
  "resend_webhook_received",
] as const;
export const LOG_FIELD_KEYS = ["authMethod"] as const;
