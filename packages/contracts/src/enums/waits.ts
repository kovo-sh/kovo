import { z } from "zod";

import { whenValid } from "../primitives.js";

// SPEC "Workflows": "Every waiting state carries a machine-readable reason and next action: no fixed
// version, cooldown, capacity, AI unavailable/budget exhausted, weak recipe, approval needed, checks
// pending/failed, or human-only patch." The dashboard must "Show next required action without
// exposing infrastructure implementation details".

/** Why a nonterminal fix is waiting (`fixes.human_reason` for `awaiting_human`). */
const LEGACY_WAIT_REASON_VALUES = [
  // SPEC's list
  "no_fixed_version",
  "cooldown",
  "capacity",
  "ai_unavailable",
  "budget_exhausted",
  "weak_recipe",
  "approval_needed",
  "checks_pending",
  "checks_failed",
  "human_only_patch",
  // Other waits SPEC describes
  "overage_limit_reached", // finite post-markup cap reached
  "payment_past_due", // "new paid-overage work pauses" during the grace period
  // The cycle's renewal is not paid yet (Stripe charges it about an hour after the period starts):
  // "unpaid invoices do not replenish allowance", so AI beyond the funded allowance waits for it.
  "payment_pending",
  "stale_recipe", // "A recipe with a stale fingerprint cannot authorize merges while rediscovery waits"
  "checks_timed_out", // "Timeout moves to human review"
  "provenance_review", // provenance table: review-only results
  "verification_failed", // "verification failed; no PR by policy" / labeled review-only PR
  "ladder_exhausted", // "permitted ladder exhausted"
  "no_safe_version", // malicious: "If no safe version is known, alert immediately …"
  "merge_conflict", // "report conflicts for human resolution"
  "refresh_limit_reached", // "at most two automatic refresh attempts per fix, then request review"
  "base_changed", // "relevant base or evidence changed" → reverifying
  "needs_retarget", // "Findings added during generation set `needs_retarget`"
  "evidence_expired", // "Evidence expiry invalidates merge eligibility"
  "post_revert_hold", // "A post-revert hold blocks re-enqueue until expiry … with a visible reason"
  "repo_paused",
  "account_paused",
  "installation_paused",
  "global_paused",
  "installation_suspended", // "suspension pauses new work and merges"
  "plan_required", // Free: "explain the manual action or Plus upgrade path"
  "authority_revoked", // "if revoked/unverifiable, require a new authorized actor"
  "branch_protection", // unsupported rules, unsafe bypass, unenforceable strict freshness
  "review_required", // PR-only/shadow mode or a tier policy excludes from auto-merge
  "rate_limited", // "Respect GitHub/registry/provider rate limits with … durable waits"
  "external_error", // "bounded dead-letter/reconciliation path for exhausted external retries"
] as const;
/** Preserve the promoted reader order independently of writer activation. */
export const SUPPLY_CHAIN_WAIT_REASONS = [
  "p0_min_age",
  "malware_evidence_pending",
  "malware_suspected",
  "publish_time_unknown",
] as const;
export const WAIT_REASONS = [...LEGACY_WAIT_REASON_VALUES, ...SUPPLY_CHAIN_WAIT_REASONS] as const;
export const WAIT_REASON_WRITE_VALUES = WAIT_REASONS;
export const waitReasonSchema = z.enum(WAIT_REASONS);
export type WaitReason = z.infer<typeof waitReasonSchema>;

/** What unblocks a waiting fix. `wait_for_*` actions resume automatically. */
const LEGACY_NEXT_ACTION_VALUES = [
  "wait_for_advisory_update",
  "wait_for_cooldown",
  "wait_for_capacity",
  "wait_for_ai_provider",
  "wait_for_next_cycle",
  "wait_for_payment",
  "wait_for_checks",
  "wait_for_recalibration",
  "wait_for_reverification",
  "wait_for_retarget",
  "wait_for_hold_expiry",
  "wait_for_rate_limit",
  "enable_overages",
  "raise_overage_limit",
  "update_payment_method",
  "upgrade_plan",
  "improve_recipe",
  "approve_recipe",
  "enable_autopilot",
  "increase_pr_cap",
  "review_pr",
  "fix_checks",
  "resolve_conflict",
  "manual_fix",
  "remove_package",
  "retry_fix",
  "resume_repo",
  "resume_account",
  "resume_installation",
  "resume_global",
  "restore_installation",
  "reauthorize",
  "update_branch_protection",
] as const;
export const NEXT_ACTIONS = [
  ...LEGACY_NEXT_ACTION_VALUES,
  "wait_for_p0_minimum_age",
  "wait_for_malware_evidence",
  "investigate_malware",
  "wait_for_publication_time",
] as const;
export const NEXT_ACTION_WRITE_VALUES = NEXT_ACTIONS;
export const nextActionSchema = z.enum(NEXT_ACTIONS);
/** Keep prior collection bounds for rollback compatibility with U1a. */
export const NEXT_ACTION_WRITE_COUNT = LEGACY_NEXT_ACTION_VALUES.length;
export type NextAction = z.infer<typeof nextActionSchema>;

/**
 * Who can take a next action. `reviewer` is anyone GitHub lets review/merge the PR; `repo_writer`
 * is a scoped-write session or key; `repo_admin` is verified GitHub repo admin/org owner; `billing`
 * is a Kovo owner/admin/billing manager; `github_admin` acts inside GitHub itself.
 */
export const NEXT_ACTION_ACTORS = [
  "kovo",
  "reviewer",
  "repo_writer",
  "repo_admin",
  "account_admin",
  "billing",
  "operator",
  "github_admin",
] as const;
export const nextActionActorSchema = z.enum(NEXT_ACTION_ACTORS);
export type NextActionActor = z.infer<typeof nextActionActorSchema>;

export const NEXT_ACTION_ACTOR = {
  wait_for_advisory_update: "kovo",
  wait_for_cooldown: "kovo",
  wait_for_p0_minimum_age: "kovo",
  wait_for_malware_evidence: "kovo",
  investigate_malware: "operator",
  wait_for_publication_time: "kovo",
  wait_for_capacity: "kovo",
  wait_for_ai_provider: "kovo",
  wait_for_next_cycle: "kovo",
  wait_for_payment: "kovo",
  wait_for_checks: "kovo",
  wait_for_recalibration: "kovo",
  wait_for_reverification: "kovo",
  wait_for_retarget: "kovo",
  wait_for_hold_expiry: "kovo",
  wait_for_rate_limit: "kovo",
  enable_overages: "billing",
  raise_overage_limit: "billing",
  update_payment_method: "billing",
  upgrade_plan: "billing",
  improve_recipe: "repo_writer",
  approve_recipe: "repo_admin",
  enable_autopilot: "repo_admin",
  increase_pr_cap: "repo_admin",
  review_pr: "reviewer",
  fix_checks: "reviewer",
  resolve_conflict: "reviewer",
  manual_fix: "reviewer",
  remove_package: "reviewer",
  retry_fix: "repo_writer",
  resume_repo: "repo_admin",
  resume_account: "account_admin",
  resume_installation: "repo_admin",
  resume_global: "operator",
  restore_installation: "github_admin",
  reauthorize: "repo_admin",
  update_branch_protection: "repo_admin",
} as const satisfies Record<NextAction, NextActionActor>;

type NonEmpty<T> = readonly [T, ...T[]];

/**
 * Waits on AI availability or AI funding. SPEC: "Waiting for AI must not prevent an independent
 * deterministic retry", so each of them allows `retry_fix`, and a retry of a fix waiting for one of
 * them runs deterministically (`RETRY_STRATEGIES` `deterministic_only`).
 */
export const AI_FUNDING_WAIT_REASONS = [
  "ai_unavailable",
  "budget_exhausted",
  "overage_limit_reached",
  "payment_past_due",
  "payment_pending",
] as const satisfies readonly WaitReason[];

/**
 * Why AI-assisted work cannot be reserved now (`UsageService.reserve`, `@kovo/core/billing`
 * `decideReservation`); each is the fix's wait reason as-is. Deterministic work is never denied for
 * budget ("Deterministic work beyond the allowance is Kovo-funded").
 * - `plan_required`: "Free has zero AI entitlement, not a $0-triggered overage prompt".
 * - `capacity`: "Cap concurrent reservations".
 * - `payment_pending`: the cycle's renewal is not paid yet; AI beyond the funded allowance waits
 *   for it and never becomes overage.
 * - `payment_past_due`: "new paid-overage work pauses" during the grace period.
 * - `budget_exhausted`: "At the allowance, new AI-assisted work waits unless a billing-authorized
 *   human has explicitly enabled overages".
 * - `overage_limit_reached`: the finite post-markup cycle limit leaves no room.
 */
export const RESERVATION_WAIT_REASONS = [
  "plan_required",
  "capacity",
  "payment_pending",
  "payment_past_due",
  "budget_exhausted",
  "overage_limit_reached",
] as const satisfies readonly WaitReason[];
export const reservationWaitSchema = z.enum(RESERVATION_WAIT_REASONS);
export type ReservationWait = z.infer<typeof reservationWaitSchema>;

/**
 * How the successor of an explicit retry runs: `default` may use the agent where plan and funding
 * allow; `deterministic_only` skips the agent, so a fix waiting for AI funding or a compliant
 * provider never blocks an independent deterministic retry.
 */
export const RETRY_STRATEGIES = ["default", "deterministic_only"] as const;
export const retryStrategySchema = z.enum(RETRY_STRATEGIES);
export type RetryStrategy = z.infer<typeof retryStrategySchema>;

/** The next actions allowed for each wait reason, most relevant first. */
export const WAIT_REASON_NEXT_ACTIONS = {
  no_fixed_version: ["wait_for_advisory_update", "manual_fix"],
  cooldown: ["wait_for_cooldown"],
  p0_min_age: ["wait_for_p0_minimum_age"],
  malware_evidence_pending: ["wait_for_malware_evidence"],
  malware_suspected: ["investigate_malware"],
  publish_time_unknown: ["wait_for_publication_time"],
  capacity: ["wait_for_capacity", "review_pr", "increase_pr_cap"],
  ai_unavailable: ["wait_for_ai_provider", "retry_fix", "manual_fix"],
  budget_exhausted: ["enable_overages", "wait_for_next_cycle", "retry_fix", "manual_fix"],
  weak_recipe: ["improve_recipe", "review_pr"],
  approval_needed: ["approve_recipe", "enable_autopilot", "review_pr"],
  checks_pending: ["wait_for_checks"],
  checks_failed: ["fix_checks", "review_pr", "retry_fix"],
  human_only_patch: ["review_pr"],
  overage_limit_reached: ["raise_overage_limit", "wait_for_next_cycle", "retry_fix", "manual_fix"],
  payment_past_due: ["update_payment_method", "retry_fix", "manual_fix"],
  payment_pending: ["wait_for_payment", "retry_fix", "manual_fix"],
  stale_recipe: ["wait_for_recalibration", "review_pr"],
  checks_timed_out: ["review_pr", "retry_fix"],
  provenance_review: ["review_pr"],
  verification_failed: ["review_pr", "improve_recipe", "retry_fix", "manual_fix"],
  ladder_exhausted: ["manual_fix", "upgrade_plan", "retry_fix"],
  no_safe_version: ["remove_package", "manual_fix"],
  merge_conflict: ["resolve_conflict", "retry_fix"],
  refresh_limit_reached: ["review_pr", "retry_fix"],
  base_changed: ["wait_for_reverification"],
  needs_retarget: ["wait_for_retarget"],
  evidence_expired: ["wait_for_reverification", "retry_fix"],
  post_revert_hold: ["wait_for_hold_expiry"],
  repo_paused: ["resume_repo"],
  account_paused: ["resume_account"],
  installation_paused: ["resume_installation"],
  global_paused: ["resume_global"],
  installation_suspended: ["restore_installation"],
  plan_required: ["upgrade_plan", "manual_fix"],
  authority_revoked: ["reauthorize"],
  branch_protection: ["update_branch_protection", "review_pr"],
  review_required: ["review_pr", "enable_autopilot"],
  rate_limited: ["wait_for_rate_limit"],
  external_error: ["retry_fix"],
} as const satisfies Record<WaitReason, NonEmpty<NextAction>>;

/** Whether `action` is one of the allowed next actions for `reason`. */
export function isAllowedNextAction(reason: WaitReason, action: NextAction): boolean {
  const allowed: readonly NextAction[] = WAIT_REASON_NEXT_ACTIONS[reason];
  return allowed.includes(action);
}

/** Whether a wait resolves without any person acting (every allowed action is Kovo's). */
export function isAutomaticWait(reason: WaitReason): boolean {
  const allowed: readonly NextAction[] = WAIT_REASON_NEXT_ACTIONS[reason];
  return allowed.every((action) => NEXT_ACTION_ACTOR[action] === "kovo");
}

/** A wait as carried by fixes, events and API responses: a reason plus its chosen next action. */
export const fixWaitSchema = z
  .strictObject({ reason: waitReasonSchema, next_action: nextActionSchema })
  .refine((wait) => isAllowedNextAction(wait.reason, wait.next_action), {
    ...whenValid,
    error: "next_action is not allowed for this wait reason",
    path: ["next_action"],
  });
export type FixWait = z.infer<typeof fixWaitSchema>;
