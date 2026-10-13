import { z } from "zod";

// `decideMerge` gates and required-check inputs (SPEC "GitHub integration and merge policy").

/**
 * The seven `decideMerge` gates, in SPEC order ("Auto-merge requires all of: 1. … 7. …").
 */
export const MERGE_GATES = [
  "repo_entitlement_authority", // 1. enabled repo, Plus, consent, authority; no pause/suspension/removal/downgrade
  "autopilot_recipe", // 2. effective autopilot and a current calibrated, approved recipe in scope
  "dependency_scope", // 3. actionable P0/P1 allowed by policy; dependency-only patch/minor graph
  "allowed_changes", // 4. exact allowed paths and manifest fields; protections unchanged
  "fresh_evidence", // 5. unexpired evidence for the exact head/tree; findings, cooldown, provenance
  "checks_and_protection", // 6. required checks and branch protections, strict freshness
  "pinned_head", // 7. merge pins sha = verified_head_sha; no unexpected head or policy change
] as const;
export const mergeGateSchema = z.enum(MERGE_GATES);
export type MergeGate = z.infer<typeof mergeGateSchema>;

/** "Unknown head/base/check state is a wait/block, never success." */
export const GATE_OUTCOMES = ["pass", "fail", "unknown"] as const;
export const gateOutcomeSchema = z.enum(GATE_OUTCOMES);
export type GateOutcome = z.infer<typeof gateOutcomeSchema>;

/** Rule-level reason codes a gate records when it does not pass, grouped by gate. */
export const MERGE_GATE_REASONS = {
  repo_entitlement_authority: [
    "repo_not_enabled",
    "plan_not_plus",
    "entitlement_inactive",
    "account_downgraded",
    "activation_consent_missing",
    "activation_consent_out_of_scope",
    "authority_revoked",
    "authority_unverifiable",
    "repo_paused",
    "account_paused",
    "installation_paused",
    "global_paused",
    "installation_suspended",
    "installation_removed",
    "repo_removed",
  ],
  autopilot_recipe: [
    "mode_not_autopilot",
    "recipe_missing",
    "recipe_not_calibrated",
    "recipe_weak",
    "recipe_not_approved",
    "recipe_stale",
    "recipe_out_of_scope",
    "recipe_weakening_pending",
  ],
  dependency_scope: [
    "no_actionable_findings",
    "tier_not_allowed",
    "ladder_rung_review_only",
    "major_update",
    "transitive_major_update",
    "override_used",
    "removal_or_rollback",
    "source_migration",
    "new_top_level_dependency",
    "non_dependency_change",
    // A changed or new version is a prerelease (outside patch/minor semantics).
    "prerelease_version",
    // The dependency diff or changed files are not available (no current evidence).
    "dependency_changes_unknown",
  ],
  allowed_changes: [
    "path_not_allowed",
    "manifest_field_not_allowed",
    "protected_path_changed",
    // The trusted path/manifest checks are missing or ran under another policy version.
    "path_checks_unavailable",
  ],
  fresh_evidence: [
    "evidence_missing",
    "verification_failed",
    "verification_inconclusive",
    "evidence_expired",
    "evidence_head_mismatch",
    "evidence_tree_mismatch",
    "relevant_base_change",
    "strict_freshness_unverified",
    "targeted_findings_remaining",
    "new_severe_findings",
    "cooldown_pending",
    "provenance_review_required",
    "integrity_mismatch",
    // "Conflict resolution also invalidates evidence."
    "merge_conflict",
    // "allow at most two automatic refresh attempts per fix, then request review".
    "refresh_limit_reached",
  ],
  checks_and_protection: [
    "checks_pending",
    "checks_failed",
    "checks_missing",
    "checks_unknown",
    "wrong_origin_check",
    "branch_rules_unsupported",
    "branch_protection_unsatisfied",
    "review_bypass_unsafe",
    "strict_freshness_unenforceable",
    "merge_queue_required",
    "protection_unreadable",
  ],
  pinned_head: [
    "head_unknown",
    "head_changed",
    "base_unknown",
    "policy_changed",
    "recipe_changed",
    // The fix's pull request is closed, merged or a draft.
    "pull_request_not_open",
    // The activation consent version changed after the decision was recorded.
    "authorization_changed",
    // No merge method the repository and its rules allow is usable ("allowed method, preferring squash").
    "merge_method_unavailable",
    // The pull request no longer targets the branch that was verified and whose rules were read
    // (someone retargeted it): a merge would land elsewhere ("Stale or substituted commit").
    "base_branch_changed",
  ],
} as const satisfies Record<MergeGate, readonly string[]>;

type GateReasons = typeof MERGE_GATE_REASONS;
export type MergeGateReason<G extends MergeGate = MergeGate> = GateReasons[G][number];

/** Every gate reason code, in gate order. */
export const MERGE_BLOCK_REASONS = [
  ...MERGE_GATE_REASONS.repo_entitlement_authority,
  ...MERGE_GATE_REASONS.autopilot_recipe,
  ...MERGE_GATE_REASONS.dependency_scope,
  ...MERGE_GATE_REASONS.allowed_changes,
  ...MERGE_GATE_REASONS.fresh_evidence,
  ...MERGE_GATE_REASONS.checks_and_protection,
  ...MERGE_GATE_REASONS.pinned_head,
] as const;
export const mergeBlockReasonSchema = z.enum(MERGE_BLOCK_REASONS);
export type MergeBlockReason = z.infer<typeof mergeBlockReasonSchema>;

/** The gate a reason code belongs to. */
export function gateOfReason(reason: MergeBlockReason): MergeGate {
  for (const gate of MERGE_GATES) {
    const reasons: readonly string[] = MERGE_GATE_REASONS[gate];
    if (reasons.includes(reason)) return gate;
  }
  throw new RangeError(`unknown merge block reason: ${reason}`);
}

/**
 * A required check's normalized state. GitHub semantics (docs/libraries/github-and-gcp.md §8):
 * success/neutral/skipped satisfy; failure/cancelled/timed_out/action_required/stale fail; queued
 * and in-progress are pending; a required context that has not reported is `missing`; an
 * unmappable status creator or ambiguous rule is `unknown`.
 */
export const REQUIRED_CHECK_STATES = [
  "success",
  "failure",
  "pending",
  "missing",
  "unknown",
] as const;
export const requiredCheckStateSchema = z.enum(REQUIRED_CHECK_STATES);
export type RequiredCheckState = z.infer<typeof requiredCheckStateSchema>;

/** Where a required context's result came from. */
export const REQUIRED_CHECK_SOURCES = ["check_run", "status"] as const;
export const requiredCheckSourceSchema = z.enum(REQUIRED_CHECK_SOURCES);
export type RequiredCheckSource = z.infer<typeof requiredCheckSourceSchema>;

/** GitHub check run `status` wire values. */
export const GITHUB_CHECK_RUN_STATUSES = [
  "queued",
  "in_progress",
  "completed",
  "waiting",
  "requested",
  "pending",
] as const;
export const githubCheckRunStatusSchema = z.enum(GITHUB_CHECK_RUN_STATUSES);
export type GithubCheckRunStatus = z.infer<typeof githubCheckRunStatusSchema>;

/** GitHub check run/suite `conclusion` wire values. */
export const GITHUB_CHECK_CONCLUSIONS = [
  "success",
  "failure",
  "neutral",
  "cancelled",
  "skipped",
  "timed_out",
  "action_required",
  "stale",
  "startup_failure",
] as const;
export const githubCheckConclusionSchema = z.enum(GITHUB_CHECK_CONCLUSIONS);
export type GithubCheckConclusion = z.infer<typeof githubCheckConclusionSchema>;

/** GitHub commit status `state` wire values. */
export const GITHUB_COMMIT_STATUS_STATES = ["error", "failure", "pending", "success"] as const;
export const githubCommitStatusStateSchema = z.enum(GITHUB_COMMIT_STATUS_STATES);
export type GithubCommitStatusState = z.infer<typeof githubCommitStatusStateSchema>;

/** The check run Kovo posts ("Post `Kovo verification` with the real outcome"). */
export const KOVO_CHECK_NAME = "Kovo verification";

/**
 * The read-only check run the PR dependency gate posts on pull requests in a protected repository
 * (plans/dependency-firewall.md Part 2; SPEC "Recipes and verification" → "PR dependency gate").
 */
export const KOVO_DEPENDENCIES_CHECK_NAME = "Kovo dependencies";
