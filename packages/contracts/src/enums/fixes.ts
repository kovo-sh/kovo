import { z } from "zod";

import type { Plan } from "./accounts.js";
import type { WaitReason } from "./waits.js";

// Fix lifecycle (SPEC "Workflows", "Fix ladder and agent", "Queues and capacity").

/** `fixes.status`, the states of SPEC's fix state diagram. */
export const FIX_STATUSES = [
  "queued",
  "resolving",
  "generating",
  "verifying",
  "pr_open",
  "reverifying",
  "merging",
  "awaiting_human",
  "merged",
  "closed",
  "superseded",
  "reverted",
  "failed",
] as const;
export const fixStatusSchema = z.enum(FIX_STATUSES);
export type FixStatus = z.infer<typeof fixStatusSchema>;

/**
 * "Terminal states are `merged`, `closed`, `superseded`, `reverted`, and `failed`." A terminal fix
 * has no running workflow and does not count toward the one-nonterminal-fix-per-(repo, package)
 * partial unique index. (`merged → reverted` is recorded when a human merges the revert PR.)
 */
export const TERMINAL_FIX_STATUSES = [
  "merged",
  "closed",
  "superseded",
  "reverted",
  "failed",
] as const satisfies readonly FixStatus[];
export type TerminalFixStatus = (typeof TERMINAL_FIX_STATUSES)[number];

/** Every non-terminal status, in diagram order. */
export const NONTERMINAL_FIX_STATUSES = [
  "queued",
  "resolving",
  "generating",
  "verifying",
  "pr_open",
  "reverifying",
  "merging",
  "awaiting_human",
] as const satisfies readonly FixStatus[];
export type NonterminalFixStatus = (typeof NONTERMINAL_FIX_STATUSES)[number];

/**
 * Statuses in which the attempt always holds the PR it published (contracts `fixSchema` requires its
 * `pull_request`).
 */
export const PUBLISHED_FIX_STATUSES = [
  "pr_open",
  "reverifying",
  "merging",
] as const satisfies readonly NonterminalFixStatus[];

/**
 * Statuses before the attempt publishes. An attempt here holds a PR only when it kept one through
 * `awaiting_human --> queued` or adopted one from the attempt a retry retired.
 */
export const PRE_PUBLICATION_FIX_STATUSES = [
  "queued",
  "resolving",
  "generating",
  "verifying",
] as const satisfies readonly NonterminalFixStatus[];

const TERMINAL_SET: ReadonlySet<FixStatus> = new Set(TERMINAL_FIX_STATUSES);

export function isTerminalFixStatus(status: FixStatus): status is TerminalFixStatus {
  return TERMINAL_SET.has(status);
}

/** `fixes.ladder_rung`: SPEC ladder rungs `1`–`7` and `M` (malicious rollback/removal). */
export const LADDER_RUNGS = ["1", "2", "3", "4", "5", "6", "7", "M"] as const;
export const ladderRungSchema = z.enum(LADDER_RUNGS);
export type LadderRung = z.infer<typeof ladderRungSchema>;

export interface LadderRungDefinition {
  /** SPEC's "Action" column. */
  readonly action: string;
  /** "Eligible after all gates" (rungs 1–4); every other rung needs human review. */
  readonly autoMergeEligible: boolean;
  /** "Free supports rungs 1–5 and deterministic M". */
  readonly plans: readonly Plan[];
  /** Whether the Plus agent may (`optional`) or must (`required`) produce the patch. */
  readonly agent: "never" | "optional" | "required";
}

/** SPEC "Fix ladder and agent" table. */
export const LADDER: Readonly<Record<LadderRung, LadderRungDefinition>> = {
  "1": {
    action: "Lockfile-only transitive patch/minor update",
    autoMergeEligible: true,
    plans: ["free", "plus"],
    agent: "never",
  },
  "2": {
    action: "Direct dependency patch update",
    autoMergeEligible: true,
    plans: ["free", "plus"],
    agent: "never",
  },
  "3": {
    action: "Direct dependency minor update",
    autoMergeEligible: true,
    plans: ["free", "plus"],
    agent: "never",
  },
  "4": {
    action: "Nearest direct ancestor patch/minor update",
    autoMergeEligible: true,
    plans: ["free", "plus"],
    agent: "never",
  },
  "5": {
    action: "Narrow npm overrides or pnpm parent-scoped override",
    autoMergeEligible: false,
    plans: ["free", "plus"],
    agent: "never",
  },
  "6": {
    action: "Major upgrade, optionally agent-assisted on Plus",
    autoMergeEligible: false,
    plans: ["plus"],
    agent: "optional",
  },
  "7": {
    action: "Major upgrade plus source migration, Plus agent",
    autoMergeEligible: false,
    plans: ["plus"],
    agent: "required",
  },
  M: {
    action: "Evidenced rollback/removal for malicious package",
    autoMergeEligible: false,
    plans: ["free", "plus"],
    agent: "never",
  },
};

/** Rungs a plan may run, in ladder order. */
export function ladderRungsForPlan(plan: Plan): LadderRung[] {
  return LADDER_RUNGS.filter((rung) => LADDER[rung].plans.includes(plan));
}

/** `repo_slots.kind`. */
export const SLOT_KINDS = ["fix", "p0_extra", "failed_verification", "revert"] as const;
export const slotKindSchema = z.enum(SLOT_KINDS);
export type SlotKind = z.infer<typeof slotKindSchema>;

/**
 * `fixes.outcome_reason`: why a fix reached its terminal state. {@link FIX_OUTCOME_STATUS} maps
 * each to the terminal status it implies.
 */
export const FIX_OUTCOME_REASONS = [
  "auto_merged",
  "human_merged",
  "human_closed",
  "dismissed",
  "repo_disabled",
  "installation_removed",
  "findings_withdrawn",
  "findings_resolved",
  "replaced_by_retry",
  "retargeted",
  "reverted",
  "retries_exhausted",
  "unsupported_repository",
  "source_constraint_changed",
] as const;
export const fixOutcomeReasonSchema = z.enum(FIX_OUTCOME_REASONS);
export type FixOutcomeReason = z.infer<typeof fixOutcomeReasonSchema>;

export const FIX_OUTCOME_STATUS = {
  auto_merged: "merged",
  human_merged: "merged",
  human_closed: "closed",
  dismissed: "closed",
  repo_disabled: "closed",
  installation_removed: "closed",
  // "A fix with no remaining actionable findings is superseded and its PR closed"
  findings_withdrawn: "superseded",
  findings_resolved: "superseded",
  // "an explicit retry retires the prior attempt before creating its successor"
  replaced_by_retry: "superseded",
  // "refresh or supersede with a linked next attempt"
  retargeted: "superseded",
  reverted: "reverted",
  // "bounded dead-letter/reconciliation path for exhausted external retries"
  retries_exhausted: "failed",
  unsupported_repository: "failed",
  source_constraint_changed: "failed",
} as const satisfies Record<FixOutcomeReason, TerminalFixStatus>;

/**
 * The fix state diagram's moves between nonterminal states (SPEC "Workflows" mermaid diagram).
 * Waits do not change the status: a fix waiting for cooldown, capacity or AI funding keeps its
 * status and carries `wait_reason`/`next_action` (docs/decisions/contracts.md "Fix transitions").
 * Beyond the diagram: `reverifying → awaiting_human` ("allow at most two automatic refresh attempts
 * per fix, then request review"; a refresh whose verification fails or conflicts), and `merging →
 * pr_open | awaiting_human` (the merge request was refused because the head, checks or rules
 * changed: "Evaluate `decideMerge` against fresh external state").
 */
export const FIX_TRANSITIONS = {
  queued: ["resolving"],
  // "target and reserved capacity ready" | "no eligible target"
  resolving: ["generating", "awaiting_human"],
  // "encrypted patch staged" | "permitted ladder exhausted"
  generating: ["verifying", "awaiting_human"],
  // "evidence and PR published" | "verification failed; no PR by policy"
  verifying: ["pr_open", "awaiting_human"],
  // "relevant base or evidence changed" | "fresh policy and entitlement pass" | "review required
  // or checks fail/expire"
  pr_open: ["reverifying", "merging", "awaiting_human"],
  reverifying: ["pr_open", "awaiting_human"],
  merging: ["pr_open", "awaiting_human"],
  // "authorized retry or prerequisite restored"
  awaiting_human: ["queued", "pr_open"],
  merged: [],
  closed: [],
  superseded: [],
  reverted: [],
  failed: [],
} as const satisfies Record<FixStatus, readonly NonterminalFixStatus[]>;

/**
 * The statuses a fix may end from with each outcome (its terminal status is
 * {@link FIX_OUTCOME_STATUS}). This is the status-level projection of `@kovo/core/fix`'s edges
 * (tested equal there); `transition` adds the guards a status alone cannot express, such as whether
 * the attempt holds a PR. Kovo merges only from `merging` ("merging --> merged"); a human merges or
 * closes a Kovo PR in any status while the attempt holds it ("awaiting_human --> merged: human
 * merges"; a PR stays with the attempt through `awaiting_human --> queued`); supersession,
 * dismissal and removal end any nonterminal fix; the dead-letter path (`retries_exhausted`) ends an
 * attempt only before publication and while it holds no PR, and an unsupported repository also ends
 * one waiting for a person without a PR; a revert ends only a merged fix ("merged --> reverted:
 * human merges revert PR").
 */
export const FIX_OUTCOME_FROM = {
  auto_merged: ["merging"],
  human_merged: NONTERMINAL_FIX_STATUSES,
  human_closed: NONTERMINAL_FIX_STATUSES,
  dismissed: NONTERMINAL_FIX_STATUSES,
  repo_disabled: NONTERMINAL_FIX_STATUSES,
  installation_removed: NONTERMINAL_FIX_STATUSES,
  findings_withdrawn: NONTERMINAL_FIX_STATUSES,
  findings_resolved: NONTERMINAL_FIX_STATUSES,
  replaced_by_retry: NONTERMINAL_FIX_STATUSES,
  retargeted: NONTERMINAL_FIX_STATUSES,
  reverted: ["merged"],
  retries_exhausted: PRE_PUBLICATION_FIX_STATUSES,
  unsupported_repository: [...PRE_PUBLICATION_FIX_STATUSES, "awaiting_human"],
  source_constraint_changed: [...PRE_PUBLICATION_FIX_STATUSES, "awaiting_human"],
} as const satisfies Record<FixOutcomeReason, readonly FixStatus[]>;

/** Whether the diagram allows a fix to move from `from` to the nonterminal status `to`. */
export function isAllowedFixTransition(from: FixStatus, to: FixStatus): boolean {
  const allowed: readonly FixStatus[] = FIX_TRANSITIONS[from];
  return allowed.includes(to);
}

/** Whether a fix in `from` may end with `outcome`. */
export function isAllowedFixOutcome(from: FixStatus, outcome: FixOutcomeReason): boolean {
  const allowed: readonly FixStatus[] = FIX_OUTCOME_FROM[outcome];
  return allowed.includes(from);
}

/** Who merged a fix PR. */
export const MERGED_BY = ["kovo", "human"] as const;
export const mergedBySchema = z.enum(MERGED_BY);
export type MergedBy = z.infer<typeof mergedBySchema>;

/** GitHub merge methods; Kovo "merge[s] with the verified head SHA and allowed method, preferring squash". */
export const MERGE_METHODS = ["squash", "merge", "rebase"] as const;
export const mergeMethodSchema = z.enum(MERGE_METHODS);
export type MergeMethod = z.infer<typeof mergeMethodSchema>;

/**
 * Why a package is held (`fix_holds.reason`): SPEC's only hold, "place a seven-day package hold"
 * after a human merges a revert PR. "A post-revert hold blocks re-enqueue until expiry or a newly
 * actionable advisory, with a visible reason."
 */
export const FIX_HOLD_REASONS = ["post_revert"] as const;
export const fixHoldReasonSchema = z.enum(FIX_HOLD_REASONS);
export type FixHoldReason = z.infer<typeof fixHoldReasonSchema>;

/** The wait reason a fix shows while its package is held (contracts `WAIT_REASONS`). */
export const FIX_HOLD_WAIT_REASON = {
  post_revert: "post_revert_hold",
} as const satisfies Record<FixHoldReason, WaitReason>;

/**
 * What a fix changes: an `upgrade` to a fixed version (rungs 1–7), or for a malicious package (rung
 * M, "Evidenced rollback/removal for malicious package") a `rollback` to a version evidenced outside
 * every malicious/affected range or a reviewed `removal` ("If no safe version is known … prepare a
 * reviewed removal only when feasible"), which has no target version.
 */
export const FIX_CHANGE_KINDS = ["upgrade", "rollback", "removal"] as const;
export const fixChangeKindSchema = z.enum(FIX_CHANGE_KINDS);
export type FixChangeKind = z.infer<typeof fixChangeKindSchema>;

/**
 * The `Kovo verification` check outcome: "Post `Kovo verification` with the real outcome:
 * failed/unverified fixes must never publish a success check". Scripts-only/native-build failures
 * are `inconclusive`, never passing.
 */
export const VERIFICATION_RESULTS = ["passed", "failed", "inconclusive", "unverified"] as const;
export const verificationResultSchema = z.enum(VERIFICATION_RESULTS);
export type VerificationResult = z.infer<typeof verificationResultSchema>;
