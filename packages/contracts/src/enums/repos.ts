import { z } from "zod";

import type { NextAction } from "./waits.js";

// Repository protection, modes and activation (SPEC "Repo modes", "Approval and activation",
// "Web application and onboarding UI").

/** `repos.mode`, the effective mode ("shadow|pr_only|autopilot"). */
export const REPO_MODES = ["shadow", "pr_only", "autopilot"] as const;
export const repoModeSchema = z.enum(REPO_MODES);
export type RepoMode = z.infer<typeof repoModeSchema>;

/** `repos.desired_mode`: the intent, stored separately from the effective mode. */
export const DESIRED_MODES = REPO_MODES;
export const desiredModeSchema = repoModeSchema;
export type DesiredMode = RepoMode;

/** `repos.activation_policy` ("`review_first` or `when_ready`"); `review_first` is the default. */
export const ACTIVATION_POLICIES = ["review_first", "when_ready", "full_autopilot"] as const;
export const activationPolicySchema = z.enum(ACTIVATION_POLICIES);
export type ActivationPolicy = z.infer<typeof activationPolicySchema>;

/** Policy `base_freshness` ("selective|strict"); `selective` is the default. */
export const BASE_FRESHNESS_MODES = ["selective", "strict"] as const;
export const baseFreshnessSchema = z.enum(BASE_FRESHNESS_MODES);
export type BaseFreshness = z.infer<typeof baseFreshnessSchema>;

/** "Repo, account, installation, and global pauses independently block merges." */
export const PAUSE_SCOPES = ["repo", "account", "installation", "global"] as const;
export const pauseScopeSchema = z.enum(PAUSE_SCOPES);
export type PauseScope = z.infer<typeof pauseScopeSchema>;

/**
 * Why a merge pause (repository, account, installation or operator switch) was set. A closed code
 * keeps free text out of audit and alert paths ("log actor/reason and alert until cleared").
 */
export const PAUSE_REASON_CODES = [
  "incident",
  "bad_merge",
  "investigating",
  "maintenance",
  "other",
] as const;
export const pauseReasonCodeSchema = z.enum(PAUSE_REASON_CODES);
export type PauseReasonCode = z.infer<typeof pauseReasonCodeSchema>;

/**
 * Reason categories the dashboard shows as distinct explanations ("Explicitly show plan
 * restrictions, permission restrictions, weak verification and missing branch protections as
 * distinct reasons").
 */
export const MODE_REASON_CATEGORIES = [
  "plan",
  "downgraded",
  "permission",
  "weak_verification",
  "stale_recipe",
  "approval_needed",
  "activation_pending",
  "branch_protection",
  "paused",
  "installation",
  "not_enabled",
  "unsupported",
] as const;
export const modeReasonCategorySchema = z.enum(MODE_REASON_CATEGORIES);
export type ModeReasonCategory = z.infer<typeof modeReasonCategorySchema>;

/**
 * `repos.mode_reason`: why the effective mode differs from the desired mode (null when they agree).
 * Each code belongs to exactly one category ({@link MODE_REASON_CATEGORY}).
 */
export const MODE_REASONS = [
  // plan: "All Free repos"; Plus features need an active paid entitlement.
  "free_plan",
  "plus_inactive",
  // downgraded: "A plan downgrade clears automatic activation consent".
  "downgraded",
  // permission: "if revoked/unverifiable, require a new authorized actor".
  "authorizer_authority_revoked",
  "authorizer_authority_unverifiable",
  // weak_verification: "Weak recipes cannot authorize autopilot".
  "recipe_missing",
  "recipe_calibrating",
  "recipe_weak",
  // stale_recipe: "A recipe with a stale fingerprint cannot authorize merges".
  "recipe_stale",
  // approval_needed: approval of a specific calibrated version, pending weakening, or scope.
  "recipe_not_approved",
  "recipe_weakening_pending",
  "activation_out_of_scope",
  // activation_pending: "Approval alone need not enable merging"; "A pending `when_ready` request
  // does not grant merge permission"; "upgrading later does not silently restore autopilot".
  "activation_not_authorized",
  "activation_consent_cleared",
  "when_ready_pending",
  // branch_protection: "Unsupported/ambiguous rules block auto-merge"; unsafe review bypass;
  // "if strict freshness cannot be enforced, remain PR-only".
  "branch_rules_unsupported",
  "review_bypass_unsafe",
  "strict_freshness_unenforceable",
  // The branch requires a merge queue: Kovo merges only through the REST merge pinned to the
  // verified head and never enqueues, so autopilot has no merge path there.
  "merge_queue_required",
  "branch_protection_unreadable",
  // paused
  "repo_paused",
  "account_paused",
  "installation_paused",
  "global_paused",
  // installation lifecycle
  "installation_suspended",
  "installation_removed",
  // not_enabled: protection is off, or the repo was archived/removed.
  "repo_not_enabled",
  "repo_archived",
  // unsupported: "Unsupported majors/formats produce an explicit unsupported reason".
  "unsupported_repository",
] as const;
export const modeReasonSchema = z.enum(MODE_REASONS);
export type ModeReason = z.infer<typeof modeReasonSchema>;

export const MODE_REASON_CATEGORY = {
  free_plan: "plan",
  plus_inactive: "plan",
  downgraded: "downgraded",
  authorizer_authority_revoked: "permission",
  authorizer_authority_unverifiable: "permission",
  recipe_missing: "weak_verification",
  recipe_calibrating: "weak_verification",
  recipe_weak: "weak_verification",
  recipe_stale: "stale_recipe",
  recipe_not_approved: "approval_needed",
  recipe_weakening_pending: "approval_needed",
  activation_out_of_scope: "approval_needed",
  activation_not_authorized: "activation_pending",
  activation_consent_cleared: "activation_pending",
  when_ready_pending: "activation_pending",
  branch_rules_unsupported: "branch_protection",
  review_bypass_unsafe: "branch_protection",
  strict_freshness_unenforceable: "branch_protection",
  merge_queue_required: "branch_protection",
  branch_protection_unreadable: "branch_protection",
  repo_paused: "paused",
  account_paused: "paused",
  installation_paused: "paused",
  global_paused: "paused",
  installation_suspended: "installation",
  installation_removed: "installation",
  repo_not_enabled: "not_enabled",
  repo_archived: "not_enabled",
  unsupported_repository: "unsupported",
} as const satisfies Record<ModeReason, ModeReasonCategory>;

/**
 * The next actions that clear each mode reason, most relevant first ("Show next required action
 * without exposing infrastructure implementation details"). A disabled, archived or unsupported
 * repository has no Kovo action: protection, archival and the repository's own setup change outside
 * the mode (the dashboard explains the state instead).
 */
export const MODE_REASON_NEXT_ACTIONS = {
  free_plan: ["upgrade_plan"],
  plus_inactive: ["upgrade_plan", "update_payment_method"],
  downgraded: ["upgrade_plan", "enable_autopilot"],
  authorizer_authority_revoked: ["reauthorize"],
  authorizer_authority_unverifiable: ["reauthorize"],
  recipe_missing: ["wait_for_recalibration", "improve_recipe"],
  recipe_calibrating: ["wait_for_recalibration"],
  recipe_weak: ["improve_recipe"],
  recipe_stale: ["wait_for_recalibration"],
  recipe_not_approved: ["approve_recipe"],
  recipe_weakening_pending: ["approve_recipe", "improve_recipe"],
  activation_out_of_scope: ["enable_autopilot", "approve_recipe"],
  activation_not_authorized: ["enable_autopilot"],
  activation_consent_cleared: ["enable_autopilot"],
  when_ready_pending: ["wait_for_recalibration"],
  branch_rules_unsupported: ["update_branch_protection"],
  review_bypass_unsafe: ["update_branch_protection"],
  strict_freshness_unenforceable: ["update_branch_protection"],
  merge_queue_required: ["update_branch_protection"],
  // Kovo re-reads it on the next event or reconciliation; a lasting failure means the App lost its
  // administration read on the repository.
  branch_protection_unreadable: ["wait_for_checks", "restore_installation"],
  repo_paused: ["resume_repo"],
  account_paused: ["resume_account"],
  installation_paused: ["resume_installation"],
  global_paused: ["resume_global"],
  installation_suspended: ["restore_installation"],
  installation_removed: ["restore_installation"],
  repo_not_enabled: [],
  repo_archived: [],
  unsupported_repository: [],
} as const satisfies Record<ModeReason, readonly NextAction[]>;

/**
 * Why a repository cannot be protected (SPEC `inventoryWorkflow` step 1: "Reject customer
 * workspaces, unsupported package managers/runtime versions, missing lockfiles, and formats outside
 * the compatibility matrix"; npm proxy: "Reject private registries and external git/file/HTTP
 * dependency sources").
 */
export const UNSUPPORTED_REPO_REASONS = [
  "workspaces",
  "missing_package_json",
  "invalid_package_json",
  "missing_lockfile",
  "ambiguous_package_manager",
  "unsupported_package_manager",
  "unsupported_lockfile_format",
  "unsupported_node_version",
  "unsupported_pm_version",
  "private_registry",
  "non_registry_dependency",
  "too_large",
] as const;
export const unsupportedRepoReasonSchema = z.enum(UNSUPPORTED_REPO_REASONS);
export type UnsupportedRepoReason = z.infer<typeof unsupportedRepoReasonSchema>;

/**
 * How the GitHub integration assessed a repository's branch protection: rulesets (organization
 * rules included), classic protection and review-bypass safety (SPEC "Review bypass": "assess
 * actual ruleset/classic protection capabilities, including organization rules … If supported safe
 * configuration cannot be established, keep PR-only and show the concrete blocking rule"). Anything
 * but `supported` keeps the effective mode PR-only with the status's mode reason.
 */
export const BRANCH_PROTECTION_STATUSES = [
  "supported",
  "rules_unsupported",
  "review_bypass_unsafe",
  "merge_queue_required",
  "unreadable",
] as const;
export const branchProtectionStatusSchema = z.enum(BRANCH_PROTECTION_STATUSES);
export type BranchProtectionStatus = z.infer<typeof branchProtectionStatusSchema>;

/** The mode reason each blocking assessment reports (category `branch_protection`). */
export const BRANCH_PROTECTION_STATUS_REASON = {
  rules_unsupported: "branch_rules_unsupported",
  review_bypass_unsafe: "review_bypass_unsafe",
  merge_queue_required: "merge_queue_required",
  unreadable: "branch_protection_unreadable",
} as const satisfies Record<Exclude<BranchProtectionStatus, "supported">, ModeReason>;

/** The mode reasons a concrete blocking rule can carry. */
export const BRANCH_PROTECTION_BLOCKER_REASONS = [
  "branch_rules_unsupported",
  "review_bypass_unsafe",
  "strict_freshness_unenforceable",
  "merge_queue_required",
] as const satisfies readonly ModeReason[];
export const branchProtectionBlockerReasonSchema = z.enum(BRANCH_PROTECTION_BLOCKER_REASONS);
export type BranchProtectionBlockerReason = z.infer<typeof branchProtectionBlockerReasonSchema>;

/** Where a blocking rule is configured: a repository or organization ruleset, or classic protection. */
export const BRANCH_RULE_SOURCES = ["ruleset", "classic"] as const;
export const branchRuleSourceSchema = z.enum(BRANCH_RULE_SOURCES);
export type BranchRuleSource = z.infer<typeof branchRuleSourceSchema>;

/**
 * The consenting administrator's current authority, checked fresh before automatic activation and
 * merge ("Revalidate the authorizing user's repo-admin/org-owner authority … if revoked/
 * unverifiable, require a new authorized actor"). `unverifiable` is a failed lookup: a denial.
 */
export const USER_AUTHORITY_STATUSES = ["verified", "revoked", "unverifiable"] as const;
export const userAuthorityStatusSchema = z.enum(USER_AUTHORITY_STATUSES);
export type UserAuthorityStatus = z.infer<typeof userAuthorityStatusSchema>;
