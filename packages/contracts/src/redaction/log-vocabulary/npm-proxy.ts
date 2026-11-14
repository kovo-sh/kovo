// Closed log vocabulary: apps/control-plane/src/services/npm-proxy.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = ["install_canary_used"] as const;
export const LOG_ENUM_CODES = ["install_canary_unknown", "install_canary_used"] as const;
