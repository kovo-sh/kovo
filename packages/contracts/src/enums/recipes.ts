import { z } from "zod";

// Recipes, calibration and approval (SPEC "Recipes and verification", "Version and sandbox
// compatibility", data model `recipe_versions`).

/** SPEC `Source` ("'ci' | 'package.json' | 'agent' | 'override'"). */
export const RECIPE_SOURCES = ["ci", "package.json", "agent", "override"] as const;
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
  "proposal_rejected", // "Proposals from discovery must be independently validated"
] as const;
export const sabotageInapplicableReasonSchema = z.enum(SABOTAGE_INAPPLICABLE_REASONS);
export type SabotageInapplicableReason = z.infer<typeof sabotageInapplicableReasonSchema>;

/** `recipe_versions.calibration_status` ("calibrating|calibrated|weak"). */
export const CALIBRATION_STATUSES = ["calibrating", "calibrated", "weak"] as const;
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
  // detection nor its absence, so "all caught" cannot be shown (docs/decisions/recipe.md).
  "mutation_errored",
  // A step that expects a test report passed at baseline without one (no counts or digest): "If a
  // recipe expects tests, missing/unparseable reports … fail verification", and the baseline "must
  // pass" and "Record expected reports, test counts".
  "baseline_report_missing",
] as const;
export const calibrationWeakReasonSchema = z.enum(CALIBRATION_WEAK_REASONS);
export type CalibrationWeakReason = z.infer<typeof calibrationWeakReasonSchema>;

/** `recipe_versions.approval_status` ("unapproved|pending|approved"). */
export const APPROVAL_STATUSES = ["unapproved", "pending", "approved"] as const;
export const approvalStatusSchema = z.enum(APPROVAL_STATUSES);
export type ApprovalStatus = z.infer<typeof approvalStatusSchema>;

/**
 * Why a human cannot approve a recipe version now (`recipe_not_approvable`): SPEC "a current GitHub
 * repo admin/org owner approves a specific calibrated version"; "Weak recipes cannot authorize
 * autopilot"; "A recipe with a stale fingerprint cannot authorize merges"; a superseded version can
 * never become active again (a rollback creates a new one). `@kovo/core/recipe` `approvalRefusal`
 * decides it; the control plane reports its answer on every version (`approval_refusal`).
 */
export const RECIPE_APPROVAL_REFUSALS = ["calibrating", "weak", "stale", "superseded"] as const;
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
  // Added with core/recipe discovery (docs/decisions/recipe.md "Deviations: exactly one per CI step"):
  "unsupported_runtime", // CI runs a Node/PM major outside the compatibility matrix
  "runtime_mismatch", // CI runs a supported major other than the one the repo declares
  "not_a_check", // not a gating PR check: release/schedule-only workflow, continue-on-error step
  "unresolved_expression", // depends on CI context values Kovo cannot know (github.*, vars.*, …)
  "removed_by_override", // a recipe override removed the step that ran this CI check
  "replaced_by_override", // a recipe override replaced the command that ran this CI check
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
