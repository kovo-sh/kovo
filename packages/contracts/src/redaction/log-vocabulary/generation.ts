// Closed log vocabulary: apps/control-plane/src/services/generation.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "generation_base_refused",
  "generation_candidate_refused",
  "generation_failure_context_unavailable",
  "generation_install_fallback",
  "generation_migration_check",
  "generation_protected_restored",
  "generation_relay_close_failed",
  "generation_staged",
] as const;
export const LOG_ENUM_CODES = [
  "major_untested_callsite",
  "migration_call_sites_clear",
  "migration_call_sites_unchanged",
  "migration_notes_unavailable",
  "migration_unsafe_option_added",
  "private_registry_changed",
] as const;
