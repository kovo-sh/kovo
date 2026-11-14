// Closed log vocabulary: packages/core/src/policy.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_ENUM_CODES = [
  "advisory_feed_stale",
  "dependency_verdict_block",
  "dependency_verdict_wait",
  "policy_checks_unreadable",
  "provenance_unknown",
  "scanner_evidence_unknown",
  "severe_findings_unknown",
] as const;
