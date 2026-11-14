// Closed log vocabulary: packages/db.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
// The #9024 B tenancy refusals: rls_violation (a row-level-security check refused a write) and
// the scoped-handle refusals (scoped_handle_cross_account when two named accounts differ).
export const LOG_ENUM_CODES = [
  "23502",
  "23503",
  "23505",
  "23514",
  "23P01",
  "40P01",
  "42501",
  "connection_check",
  "rls_violation",
  "scoped_handle_cross_account",
  "scoped_handle_reuse_mismatch",
  "transaction_start",
] as const;
