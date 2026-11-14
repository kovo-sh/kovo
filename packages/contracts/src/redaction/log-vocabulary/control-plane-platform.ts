// Closed log vocabulary: apps/control-plane/src/platform.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "auth_event",
  "github_sign_in_code_exchange_refused",
  "users_email_released",
] as const;
export const LOG_FIELD_KEYS = ["verified_github_user_id"] as const;
export const LOG_ENUM_CODES = ["auth_library_event"] as const;
