// Closed log vocabulary: apps/web.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "web_configuration_failed",
  "web_error_report_delivery",
  "web_listening",
  "web_problem",
  "web_proxy_failure",
  "web_secrets_loaded",
  "web_shutdown",
  "web_ssr_api_failure",
  "web_uncaught_error",
  "web_unhandled_error",
] as const;
