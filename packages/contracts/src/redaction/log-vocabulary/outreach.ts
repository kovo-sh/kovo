// Closed log vocabulary: apps/control-plane/src/services/outreach.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "outreach.export_domains_rejected",
  "outreach.export_skipped",
  "outreach.export_written",
  "outreach.import_completed",
  "outreach.import_skipped",
  "outreach.import_source_unavailable",
] as const;
export const LOG_FIELD_KEYS = [
  "contactsAdded",
  "findingsAdded",
  "noContact",
  "rowsRead",
  "rowsRejected",
  "sitesNew",
  "sitesRefreshed",
  "skippedCustomer",
  "skippedGeo",
  "skippedSuppressed",
  "staled",
] as const;
