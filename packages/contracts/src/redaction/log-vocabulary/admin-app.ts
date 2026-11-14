// Closed log vocabulary: apps/admin.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = ["admin_boot_failed", "admin_listening", "admin_shutdown"] as const;
