import { z } from "zod";

import type { FixTier } from "./advisories.js";

// Verification, dependency changes and supply-chain provenance (SPEC "fixWorkflow" steps 4–5,
// "Sandbox B", "npm proxy and network egress").

/** fixWorkflow step 5 control-plane checks, recorded in `fix_evidence.policy_checks`. */
export const POLICY_CHECKS = [
  "allowed_files", // "allowed file …"
  "manifest_fields", // "… and manifest fields"
  "targeted_findings_resolved",
  "no_new_severe_findings", // "no newly introduced P0/P1 or malicious findings"
  "cooldown",
  "provenance",
  "authorization", // "current authorization"
] as const;
export const policyCheckSchema = z.enum(POLICY_CHECKS);
export type PolicyCheck = z.infer<typeof policyCheckSchema>;

/** How a resolved package changed between the base and the patched lockfile. */
export const DEPENDENCY_CHANGE_KINDS = ["added", "removed", "upgraded", "downgraded"] as const;
export const dependencyChangeKindSchema = z.enum(DEPENDENCY_CHANGE_KINDS);
export type DependencyChangeKind = z.infer<typeof dependencyChangeKindSchema>;

/**
 * SemVer distance of a version change ("Evaluate semantic version changes across the whole changed
 * dependency graph, including transitives").
 */
export const SEMVER_BUMPS = ["major", "minor", "patch", "prerelease"] as const;
export const semverBumpSchema = z.enum(SEMVER_BUMPS);
export type SemverBump = z.infer<typeof semverBumpSchema>;

/** How a file changed in the staged patch. */
export const FILE_CHANGE_KINDS = ["added", "modified", "deleted"] as const;
export const fileChangeKindSchema = z.enum(FILE_CHANGE_KINDS);
export type FileChangeKind = z.infer<typeof fileChangeKindSchema>;

/** The role of a changed file for path policy ("Exact allowed paths and allowed manifest fields"). */
export const FILE_ROLES = ["manifest", "lockfile", "source", "other"] as const;
export const fileRoleSchema = z.enum(FILE_ROLES);
export type FileRole = z.infer<typeof fileRoleSchema>;

/**
 * Sanitized status of one executed recipe step. "Scripts-only/native-build failures are
 * inconclusive, never recorded as passing".
 */
export const STEP_STATUSES = [
  "passed",
  "failed",
  "timed_out",
  "inconclusive",
  "skipped",
  "error",
] as const;
export const stepStatusSchema = z.enum(STEP_STATUSES);
export type StepStatus = z.infer<typeof stepStatusSchema>;

/**
 * Sanitized failure codes: "Capture only exit codes, durations, counts, failure codes and hashes;
 * raw stdout/stderr stays ephemeral".
 */
export const STEP_FAILURE_CODES = [
  "nonzero_exit",
  "timeout",
  "killed",
  "install_failed",
  "lifecycle_script_failed",
  "native_build_failed",
  "report_missing",
  "report_unparseable",
  "test_count_mismatch",
  "test_count_drop",
  "forbidden_flag",
  "egress_blocked",
  "protected_config_modified",
  "sandbox_error",
  // The source archive (GitHub's `git archive` of the commit) extracted to other files than the
  // commit's tree (`export-ignore`, `export-subst`, LFS objects in archives) and the checkout could
  // not be restored to the exact tree: the run did not test the tree its evidence names.
  "archive_differs_from_tree",
] as const;
export const stepFailureCodeSchema = z.enum(STEP_FAILURE_CODES);
export type StepFailureCode = z.infer<typeof stepFailureCodeSchema>;

/** SPEC "Provenance change" rows. */
export const PROVENANCE_FINDING_KINDS = [
  "young_version", // "Changed/new version younger than 24 hours"
  "lifecycle_scripts_added", // "Added lifecycle scripts …"
  "maintainer_changed", // "… or changed maintainer identity"
  "new_top_level_dependency",
  "missing_provenance", // "Missing required provenance evidence"
  "integrity_mismatch",
] as const;
export const provenanceFindingKindSchema = z.enum(PROVENANCE_FINDING_KINDS);
export type ProvenanceFindingKind = z.infer<typeof provenanceFindingKindSchema>;

/**
 * What the npm proxy did with one tarball request (`npm_installs.outcome`): "Record served artifact
 * integrity, publication metadata, scripts and provenance evidence"; "Integrity mismatch | Reject
 * artifact"; for P1 "changed/new versions must be at least 24 hours old … Enforce the rule against
 * actual tarballs". `refused_not_allowed`: outside the capability's package set.
 */
export const NPM_INSTALL_OUTCOMES = [
  "served",
  "refused_integrity",
  "refused_cooldown",
  "refused_not_allowed",
] as const;
export const npmInstallOutcomeSchema = z.enum(NPM_INSTALL_OUTCOMES);
export type NpmInstallOutcome = z.infer<typeof npmInstallOutcomeSchema>;

/**
 * The registry digest that verified a served tarball (`npm_installs.integrity_algorithm`): its sha512
 * `dist.integrity`, or the legacy SHA-1 `dist.shasum` of a version published before sha512
 * integrity, which is weaker evidence (collisions are practical; docs/decisions/adapter-feeds.md
 * "Tarball integrity: sha512 decides, SHA-1 only without it").
 */
export const TARBALL_DIGEST_ALGORITHMS = ["sha512", "sha1"] as const;
export const tarballDigestAlgorithmSchema = z.enum(TARBALL_DIGEST_ALGORITHMS);
export type TarballDigestAlgorithm = z.infer<typeof tarballDigestAlgorithmSchema>;

/** SPEC "Result" column values. */
export const PROVENANCE_RESULTS = [
  "allowed_with_flag",
  "blocked",
  "review_only",
  "rejected",
] as const;
export const provenanceResultSchema = z.enum(PROVENANCE_RESULTS);
export type ProvenanceResult = z.infer<typeof provenanceResultSchema>;

/** SPEC provenance table, per fix tier. */
export const PROVENANCE_RULES = {
  // "P1 blocked; P0 allowed with explicit flag"
  young_version: { P0: "blocked", P1: "blocked" },
  // "Review-only on both tiers"
  lifecycle_scripts_added: { P0: "review_only", P1: "review_only" },
  maintainer_changed: { P0: "review_only", P1: "review_only" },
  // "Review-only"
  new_top_level_dependency: { P0: "review_only", P1: "review_only" },
  // "Review-only with reason; do not fabricate historical maintainer data"
  missing_provenance: { P0: "review_only", P1: "review_only" },
  // "Reject artifact/fix"
  integrity_mismatch: { P0: "rejected", P1: "rejected" },
} as const satisfies Record<ProvenanceFindingKind, Record<FixTier, ProvenanceResult>>;
