// The error types a Stripe failure is logged with, on their own so the port errors (and the CLI
// bundle that loads them) need not load the whole log vocabulary. Exported from the redaction
// index under the same name.

/**
 * The type Stripe puts on an error (https://docs.stripe.com/api/errors#errors-type), logged as
 * `stripe_error_type`. Anything else is `other`.
 */
export const STRIPE_ERROR_TYPES = [
  "invalid_request_error",
  "api_error",
  "api_connection_error",
  "card_error",
  "authentication_error",
  "permission_error",
  "rate_limit_error",
  "idempotency_error",
  "other",
] as const;
