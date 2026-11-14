// Closed log vocabulary: packages/adapters/src/research-feeds.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_ENUM_CODES = [
  "model_account_restricted",
  "model_authentication_failed",
  "model_insufficient_credits",
  "model_network",
  "model_no_compliant_provider",
  "model_not_found",
  "model_outcome_empty",
  "model_outcome_refusal",
  "model_outcome_schema_invalid",
  "model_outcome_transport",
  "model_outcome_unknown",
  "model_rate_limited",
  "model_request_refused",
  "model_timeout",
  "model_timeout_outcome_unknown",
] as const;
