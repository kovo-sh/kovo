// Closed log vocabulary: packages/core/src/lockfile.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_ENUM_CODES = [
  "install_fallback_dependencies_changed",
  "install_fallback_lockfile_missing",
  "install_fallback_lockfile_stale",
  "package_manager_choice_not_applicable",
  "private_registry_package",
] as const;
