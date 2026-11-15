import { z } from "zod";

import { persistedReader } from "../tolerant-reader.js";

// Recipes, calibration and approval (SPEC "Recipes and verification", "Version and sandbox
// compatibility", data model `recipe_versions`).

/**
 * SPEC `Source` ("'ci' | 'package.json' | 'agent' | 'override' | 'kovo_template'").
 * `kovo_template` marks a check Kovo derives from one of its fixed templates, with no model.
 */
export const RECIPE_SOURCES = ["ci", "package.json", "agent", "override", "kovo_template"] as const;
export const recipeSourceSchema = z.enum(RECIPE_SOURCES);
export type RecipeSource = z.infer<typeof recipeSourceSchema>;

/** Admitted writers, after the tolerant Yarn reader release was promoted. */
export const ADMITTED_PACKAGE_MANAGERS = ["npm", "pnpm", "yarn"] as const;

/** Values readable from `Recipe.runtime.packageManager` and `repos.package_manager`. */
export const PACKAGE_MANAGERS = ["npm", "pnpm", "yarn"] as const;
export const packageManagerSchema = z.enum(PACKAGE_MANAGERS);
export type PackageManager = z.infer<typeof packageManagerSchema>;

/** "npm lockfile v2/v3 and pnpm lockfile v9 are the initial accepted formats". */
export const ADMITTED_LOCKFILE_FORMATS = ["npm-v2", "npm-v3", "pnpm-v9", "yarn-v1"] as const;

export const LOCKFILE_FORMATS = ["npm-v2", "npm-v3", "pnpm-v9", "yarn-v1"] as const;
export const lockfileFormatSchema = z.enum(LOCKFILE_FORMATS);
export type LockfileFormat = z.infer<typeof lockfileFormatSchema>;

/**
 * Package managers Kovo can fix but not run (R2, CI-first admission): Kovo produces the
 * lockfile or manifest edit in Sandbox A with its own pinned tool, and the repository's CI decides.
 * Sandbox B never installs them, so they are never a `PackageManager`: recipes,
 * verification and the npm proxy's routes keep the verifiable set, and every place a fix-only value
 * can reach takes `StoredPackageManager` explicitly. `manifest-only` is a root with a package.json
 * and no lockfile: only a direct dependency's range in package.json can change.
 */
export const FIX_ONLY_PACKAGE_MANAGERS = ["yarn-berry", "bun", "manifest-only"] as const;
export type FixOnlyPackageManager = (typeof FIX_ONLY_PACKAGE_MANAGERS)[number];

/** Values `repos.package_manager` and `lockfile_snapshots.package_manager` may hold. */
export const STORED_PACKAGE_MANAGERS = [...PACKAGE_MANAGERS, ...FIX_ONLY_PACKAGE_MANAGERS] as const;
// Persisted closed enum: an unknown stored value refuses as `persisted_enum_unknown`.
export const storedPackageManagerSchema = persistedReader(z.enum(STORED_PACKAGE_MANAGERS));
export type StoredPackageManager = z.infer<typeof storedPackageManagerSchema>;

export function isFixOnlyPackageManager(
  packageManager: StoredPackageManager,
): packageManager is FixOnlyPackageManager {
  return (FIX_ONLY_PACKAGE_MANAGERS as readonly string[]).includes(packageManager);
}

/**
 * Lockfile formats of the fix-only package managers: Yarn 4's lockfile version 10 (the version the
 * baked Yarn writes, so a lockfile-only update never rewrites the whole file), Bun's text
 * `bun.lock` versions 1 and 2, and `manifest-only` (package.json is the only file that pins).
 */
export const FIX_ONLY_LOCKFILE_FORMATS = [
  "yarn-berry-v10",
  "bun-v1",
  "bun-v2",
  "manifest-only",
] as const;
export const STORED_LOCKFILE_FORMATS = [...LOCKFILE_FORMATS, ...FIX_ONLY_LOCKFILE_FORMATS] as const;
export type StoredLockfileFormat = (typeof STORED_LOCKFILE_FORMATS)[number];

export function isVerifiableLockfileFormat(format: StoredLockfileFormat): format is LockfileFormat {
  return (LOCKFILE_FORMATS as readonly string[]).includes(format);
}

export const FIX_ONLY_FORMATS_BY_PM = {
  "yarn-berry": ["yarn-berry-v10"],
  bun: ["bun-v1", "bun-v2"],
  "manifest-only": ["manifest-only"],
} as const satisfies Record<FixOnlyPackageManager, readonly StoredLockfileFormat[]>;

/**
 * The fix-only tools baked into the sandbox image (`infra/sandbox-image/tool-cache.json`,
 * checked by a test). New tools at a reviewed version; any later version change needs the owner's
 * approval before merge (third-party version rule). `manifest-only` runs no tool.
 */
export const FIX_ONLY_TOOLS = {
  "yarn-berry": { version: "4.18.1", executable: "/opt/yarn-berry/4.18.1/bin/yarn" },
  bun: { version: "1.4.4", executable: "/opt/bun/1.4.4/bin/bun" },
} as const satisfies Record<
  Exclude<FixOnlyPackageManager, "manifest-only">,
  { readonly version: string; readonly executable: string }
>;

/**
 * The compatibility matrix: "supported Node 22/24 runtimes, npm 10/11 and pnpm 9/10/11/12 … Unsupported
 * majors/formats produce an explicit unsupported reason; never substitute the nearest runtime."
 */
export const SUPPORTED_NODE_MAJORS = [22, 24] as const;
export const SUPPORTED_PM_MAJORS = {
  npm: [10, 11],
  pnpm: [9, 10, 11, 12],
  yarn: [1],
} as const satisfies Record<PackageManager, readonly number[]>;
export const LOCKFILE_FORMATS_BY_PM = {
  npm: ["npm-v2", "npm-v3"],
  pnpm: ["pnpm-v9"],
  yarn: ["yarn-v1"],
} as const satisfies Record<PackageManager, readonly LockfileFormat[]>;

/** SPEC `expect.reportFormat`. */
export const REPORT_FORMATS = ["vitest-json", "jest-json", "tap"] as const;
export const reportFormatSchema = z.enum(REPORT_FORMATS);
export type ReportFormat = z.infer<typeof reportFormatSchema>;

/**
 * The HTTP methods a smoke route may send (layer 1). A route without a method sends
 * `GET`, as every smoke route did before.
 */
export const SMOKE_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;
// Persisted closed enums: an unknown stored value refuses as `persisted_enum_unknown`.
export const smokeMethodSchema = persistedReader(z.enum(SMOKE_METHODS));
export type SmokeMethod = z.infer<typeof smokeMethodSchema>;

/** The content types of a smoke request body and of a loopback fake's answer. */
export const SMOKE_BODY_TYPES = [
  "application/json",
  "text/plain",
  "application/x-www-form-urlencoded",
] as const;
export const smokeBodyTypeSchema = persistedReader(z.enum(SMOKE_BODY_TYPES));
export type SmokeBodyType = z.infer<typeof smokeBodyTypeSchema>;

/** SPEC `sabotageTargets[].kind`. */
export const SABOTAGE_KINDS = [
  "break_entry_import",
  "throw_in_route",
  "corrupt_covered_return",
  "pin_bad_dep",
] as const;
export const sabotageKindSchema = z.enum(SABOTAGE_KINDS);
export type SabotageKind = z.infer<typeof sabotageKindSchema>;

/**
 * Whether a sabotage kind exercises application code/build behavior ("at least one exercising
 * application code/build behavior rather than only dependency installation"). `pin_bad_dep` only
 * changes installed dependencies.
 */
export const SABOTAGE_EXERCISES_APP_CODE = {
  break_entry_import: true,
  throw_in_route: true,
  corrupt_covered_return: true,
  pin_bad_dep: false,
} as const satisfies Record<SabotageKind, boolean>;

/** Per-mutation calibration result ("Record inapplicable kinds explicitly"). */
export const SABOTAGE_OUTCOMES = ["caught", "undetected", "inapplicable", "error"] as const;
export const sabotageOutcomeSchema = z.enum(SABOTAGE_OUTCOMES);
export type SabotageOutcome = z.infer<typeof sabotageOutcomeSchema>;

/**
 * Why a sabotage kind does not apply ("insert a route failure if a route is exercised; corrupt a
 * covered return when coverage/static evidence identifies one; or pin a known incompatible fixture
 * dependency when a supported target exists").
 */
export const SABOTAGE_INAPPLICABLE_REASONS = [
  "no_entry_import",
  "no_exercised_route",
  "no_coverage_evidence",
  "no_supported_fixture",
  // Kept for older records. A kind is inapplicable only when trusted evidence found
  // no target of it, so selection now records that kind's own no-evidence reason (or one of the
  // two below); rejected discovery proposals stay listed in the calibration plan.
  "proposal_rejected", // "Proposals from discovery must be independently validated"
  // The analysis read nothing: the commit's source archive was missing, too large or malformed,
  // so no kind could find evidence.
  "sources_unavailable",
  // The analysis could not read the root package.json as a supported manifest, so it found no
  // entry, framework or dependency to sabotage.
  "manifest_unreadable",
] as const;
export const sabotageInapplicableReasonSchema = z.enum(SABOTAGE_INAPPLICABLE_REASONS);
export type SabotageInapplicableReason = z.infer<typeof sabotageInapplicableReasonSchema>;

/**
 * `recipe_versions.calibration_status`. The owner removed calibration and per-version
 * approval: a discovered version is `ready` at once, its terminal status, and verifies fixes as
 * soon as it is active. `calibrating`, `calibrated`, `weak` and `limited` are kept
 * only so versions recorded before the removal stay readable; nothing writes them any more.
 */
export const CALIBRATION_STATUSES = [
  "calibrating",
  "calibrated",
  "weak",
  "limited",
  "ready",
] as const;
export const calibrationStatusSchema = z.enum(CALIBRATION_STATUSES);
export type CalibrationStatus = z.infer<typeof calibrationStatusSchema>;

/**
 * Why calibration produced `weak`: "All-skipped, install-only, failing-baseline or undetected
 * mutations produce `weak` with reasons"; fewer than two meaningful mutations, or none exercising
 * application code/build behavior, also fail the bar.
 */
export const CALIBRATION_WEAK_REASONS = [
  "baseline_failed",
  // New comparison basis only; actual checks may pass while repeated fresh evidence differs.
  "baseline_incomparable",
  "all_sabotage_skipped",
  "install_only",
  "mutation_undetected",
  "too_few_mutations",
  "no_app_code_mutation",
  // A mutation run that errored (sandbox or harness failure, inconclusive result) proves neither
  // detection nor its absence, so "all caught" cannot be shown.
  "mutation_errored",
  // A step that expects a test report passed at baseline without one (no counts or digest): "If a
  // recipe expects tests, missing/unparseable reports … fail verification", and the baseline "must
  // pass" and "Record expected reports, test counts".
  "baseline_report_missing",
  // The recipe has no check and no smoke: nothing but the install can run, so nothing can catch a
  // sabotage (agent decision, pending owner review). Replaces the misleading
  // `baseline_failed` of an empty baseline and the no-checks form of `install_only`.
  "no_verification_steps",
  // Not even the install ran at baseline: the harness ended before its first step (a sandbox
  // command timed out, the checkout could not be listed; agent decision).
  // Replaces the misleading `baseline_failed` of an empty baseline for a recipe with checks.
  "baseline_no_steps_run",
  // The recipe's only check is Kovo's entry import (no other step, no smoke) and it caught fewer
  // than the minimum meaningful mutations: loading the entry cannot exercise routes or returns.
  // Replaces `too_few_mutations` for that recipe; the bar itself is unchanged (agent decision
  // (2026-11-05), pending owner review).
  "entry_import_only",
] as const;
export const calibrationWeakReasonSchema = z.enum(CALIBRATION_WEAK_REASONS);
export type CalibrationWeakReason = z.infer<typeof calibrationWeakReasonSchema>;

/**
 * The only weak reasons a `limited` calibration may carry: the checks passed on the
 * unchanged code and caught every deliberate break they were given, but too few of them. Any other
 * reason (a failed or incomparable baseline, an undetected or errored break, install-only
 * detection, no check, no application-code catch) keeps the version `weak`.
 */
export const LIMITED_VERIFICATION_WEAK_REASONS: readonly CalibrationWeakReason[] = [
  "too_few_mutations",
  // A recipe whose only check is the entry import, short of the bar: the no-test case.
  "entry_import_only",
];

/** `recipe_versions.approval_status` ("unapproved|pending|approved"). */
export const APPROVAL_STATUSES = ["unapproved", "pending", "approved"] as const;
export const approvalStatusSchema = z.enum(APPROVAL_STATUSES);
export type ApprovalStatus = z.infer<typeof approvalStatusSchema>;

/**
 * Why a recipe version cannot be approved (`approval_refusal` on every version). The owner
 * removed per-version approval: every version not approved before the removal reads
 * `approval_removed`, or `superseded` once a newer version replaced it. `calibrating`, `weak` and
 * `stale` are kept for records and clients written before the removal.
 */
export const RECIPE_APPROVAL_REFUSALS = [
  "calibrating",
  "weak",
  "stale",
  "superseded",
  "approval_removed",
] as const;
export const recipeApprovalRefusalSchema = z.enum(RECIPE_APPROVAL_REFUSALS);
export type RecipeApprovalRefusal = z.infer<typeof recipeApprovalRefusalSchema>;

/** `recipe_versions.approved_via` ("human|onboarding|inherited"). */
export const APPROVED_VIA = [
  "human",
  "onboarding",
  "inherited",
  "management_key",
  "autopilot_policy",
] as const;
export const approvedViaSchema = z.enum(APPROVED_VIA);
export type ApprovedVia = z.infer<typeof approvedViaSchema>;

/**
 * `recipe_versions.strength_delta` relative to the parent version. "Arbitrary shell-command changes
 * are not automatically comparable as 'stronger'"; only `stronger` (mechanically provable additive
 * checks/stricter expectations) or `equivalent` changes may inherit approval.
 */
export const RECIPE_STRENGTH_DELTAS = ["stronger", "equivalent", "weaker", "incomparable"] as const;
export const recipeStrengthDeltaSchema = z.enum(RECIPE_STRENGTH_DELTAS);
export type RecipeStrengthDelta = z.infer<typeof recipeStrengthDeltaSchema>;

/** "record any unavailable or narrowed step as an explicit deviation". */
export const DEVIATION_KINDS = ["unavailable", "narrowed"] as const;
export const deviationKindSchema = z.enum(DEVIATION_KINDS);
export type DeviationKind = z.infer<typeof deviationKindSchema>;

/** Why a discovered CI step could not run as written in the sandbox. */
export const DEVIATION_REASONS = [
  "requires_secret", // "customer production credentials are out of scope"
  "requires_service_container", // "Service containers in verification" is post-MVP
  "requires_network", // tests/smoke run with loopback only
  "requires_docker",
  "unsupported_runner",
  "unsupported_action",
  "matrix_narrowed", // a CI matrix reduced to the recipe's resolved runtime
  "deployment_step",
  "unparseable",
  // Added with core/recipe discovery (exactly one deviation per CI step):
  "unsupported_runtime", // CI runs a Node/PM major outside the compatibility matrix
  "runtime_mismatch", // CI runs a supported major other than the one the repo declares
  "not_a_check", // not a gating PR check: release/schedule-only workflow, continue-on-error step
  "unresolved_expression", // depends on CI context values Kovo cannot know (github.*, vars.*, …)
  "removed_by_override", // a recipe override removed the step that ran this CI check
  "replaced_by_override", // a recipe override replaced the command that ran this CI check
  // Added later (checks never write files):
  "mutating_flags_removed", // a linter or formatter runs with its fix/write flags dropped
  "mutating_check", // a linter or formatter that writes files, with no safe read-only form
  // Added later (exactly one deviation per CI step):
  "infra_tool_unavailable", // an infrastructure CLI (Terraform, kubectl, …) the image lacks
] as const;
export const deviationReasonSchema = z.enum(DEVIATION_REASONS);
export type DeviationReason = z.infer<typeof deviationReasonSchema>;

/**
 * Inputs the recipe fingerprint covers ("scripts, engines, package manager, lockfile format, CI
 * workflows, framework/typecheck config, Dockerfile, runtime declarations, recipe overrides and
 * sandbox image/runtime identity").
 */
export const FINGERPRINT_COMPONENTS = [
  "scripts",
  "engines",
  "package_manager",
  "lockfile_format",
  "ci_workflows",
  "framework_config",
  "typecheck_config",
  "dockerfile",
  "runtime_declarations",
  "recipe_overrides",
  "sandbox_image",
] as const;
export const fingerprintComponentSchema = z.enum(FINGERPRINT_COMPONENTS);
export type FingerprintComponent = z.infer<typeof fingerprintComponentSchema>;
