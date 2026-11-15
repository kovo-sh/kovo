// @kovo/core/lockfile: npm v2/v3 and pnpm v9 lockfile graphs, graph diff and ladder planning.

export * from "./build-graph.js";
export * from "./compat.js";
export * from "./detect.js";
export * from "./dependency-ignore.js";
export * from "./discovery/index.js";
export * from "./diff.js";
export * from "./inventory.js";
export * from "./ladder/index.js";
export * from "./node-declaration.js";
export * from "./open-install.js";
export * from "./package-manager-choice.js";
export * from "./parse.js";
export * from "./private-registry.js";
export * from "./reasons.js";
export * from "./registry-source.js";
export * from "./semver-change.js";
export * from "./types.js";

export { withBreakingChangeHint } from "../versions/change-review.js";
export {
  CHANGELOG_SCAN_LIMITS,
  CHANGELOG_SCAN_REASONS,
  changelogCleared,
  scanChangelog,
  type ChangelogClearance,
  type ChangelogScanInput,
  type ChangelogScanOutcome,
  type ChangelogScanReason,
  type ChangelogScanResult,
} from "../versions/changelog-check.js";
export {
  MIGRATION_CALL_SITE_REASONS,
  MIGRATION_CHECK_LIMITS,
  NOTES_LIMITS,
  TEST_REACH_LIMITS,
  checkMigrationCallSites,
  untestedCallSiteFiles,
  type MigrationCallSiteInput,
  type MigrationCallSiteOutcome,
  type MigrationCallSiteReason,
  type MigrationCallSiteResult,
  type MigrationFile,
  type MovedMajor,
} from "../versions/migration-checks.js";
export * from "./workspace/index.js";

export * from "./bun.js";
export * from "./fix-only.js";
export * from "./manifest-only.js";
export * from "./yarn.js";
export * from "./yarn-berry.js";
