import { z } from "zod";
import { writerPinned } from "../compatibility.js";

// Jobs, sandboxes, audit and operator controls (SPEC "npm proxy and network egress", "Security
// model", "Operations, analytics, and deployment", Public API `/v1/jobs`, `/v1/audit`).

/**
 * Asynchronous jobs (`jobs.kind`), readable through `GET /v1/jobs/{id}`. A job is SPEC's unit of
 * work that owns sandboxes, the "short-lived job capability" for the npm proxy, the relay's
 * "scoped job ID", usage reservations and ledger entries, so fix generation (Sandbox A) and
 * verification (Sandbox B) are jobs too. `recipe_discovery` is the first discovery of an enabled
 * repository; `recipe_rediscovery` is the explicit `POST …/recipe/rediscover` or a fingerprint
 * change.
 */
export const JOB_KINDS = [
  "inventory",
  "recipe_discovery",
  "recipe_rediscovery",
  "recipe_calibration",
  "fix_generation",
  "fix_verification",
  "revert",
] as const;
export const jobKindSchema = z.enum(JOB_KINDS);
export type JobKind = z.infer<typeof jobKindSchema>;

/**
 * The jobs of a fix attempt's own runs (its generation and verification). A fix's other jobs are
 * not its runs: a merged fix's `revert` job outlives the attempt and is never settled with it.
 */
export const FIX_RUN_JOB_KINDS = [
  "fix_generation",
  "fix_verification",
] as const satisfies readonly JobKind[];

export const JOB_STATUSES = ["queued", "running", "succeeded", "failed", "canceled"] as const;
export const jobStatusSchema = z.enum(JOB_STATUSES);
export type JobStatus = z.infer<typeof jobStatusSchema>;

/** Statuses after which a job never changes (bounded polling stops). */
export const TERMINAL_JOB_STATUSES = [
  "succeeded",
  "failed",
  "canceled",
] as const satisfies readonly JobStatus[];

/** Sandbox network phases (SPEC "Phase | Allowed network" table). */
export const SANDBOX_PHASES = ["A", "B_install", "B_build", "B_tests"] as const;
export const sandboxPhaseSchema = z.enum(SANDBOX_PHASES);
export type SandboxPhase = z.infer<typeof sandboxPhaseSchema>;

/** Egress policies a sandbox phase may use. */
export const EGRESS_POLICIES = ["proxy_only", "build_allowlist", "loopback_only"] as const;
export const egressPolicySchema = z.enum(EGRESS_POLICIES);
export type EgressPolicy = z.infer<typeof egressPolicySchema>;

export const SANDBOX_PHASE_EGRESS = {
  // "Job-scoped npm proxy only; release documentation fetched by trusted adapter"
  A: "proxy_only",
  // "Job-scoped npm proxy only; lifecycle scripts allowed"
  B_install: "proxy_only",
  // "Explicit approved build-host allowlist; no implicit general internet"
  B_build: "build_allowlist",
  // "None, except sandbox-local loopback"
  B_tests: "loopback_only",
} as const satisfies Record<SandboxPhase, EgressPolicy>;

/** Whether lifecycle scripts run: disabled in Sandbox A, "controlled script execution" in B. */
export const SANDBOX_PHASE_LIFECYCLE_SCRIPTS = {
  A: false,
  B_install: true,
  B_build: true,
  B_tests: true,
} as const satisfies Record<SandboxPhase, boolean>;

/**
 * The phases whose egress is the job-scoped npm proxy ("Sandbox A | Job-scoped npm proxy only";
 * "Sandbox B install | Job-scoped npm proxy only"), and so the only phases a proxy capability can
 * serve (`proxy_capabilities.phase`).
 */
export const PROXY_CAPABILITY_PHASES = [
  "A",
  "B_install",
] as const satisfies readonly SandboxPhase[];
export const proxyCapabilityPhaseSchema = z.enum(PROXY_CAPABILITY_PHASES);
export type ProxyCapabilityPhase = z.infer<typeof proxyCapabilityPhaseSchema>;

/**
 * What a sandbox is for ("`sandbox` queue … Shared by A, B and calibration"). `gap_fill` is Plus
 * recipe discovery's budgeted agent attempt ("Plus may use budgeted agent gap-fill"), whose tools
 * run in a Sandbox A like the fix agent's.
 */
export const SANDBOX_PURPOSES = ["generation", "gap_fill", "verification", "calibration"] as const;
export const sandboxPurposeSchema = z.enum(SANDBOX_PURPOSES);
export type SandboxPurpose = z.infer<typeof sandboxPurposeSchema>;

/**
 * Purposes that run in Sandbox A (phase `A`: proxy-only egress, lifecycle scripts disabled): patch
 * generation and recipe gap-fill. Verification and calibration run in Sandbox B phases.
 */
export const SANDBOX_A_PURPOSES = [
  "generation",
  "gap_fill",
] as const satisfies readonly SandboxPurpose[];

/** Watchdog-tracked sandbox lifecycle ("hard maximum lifetime 60 minutes … frequent watchdog"). */
export const SANDBOX_STATES = [
  "creating",
  "running",
  "destroying",
  "destroyed",
  "expired",
  "failed",
] as const;
export const sandboxStateSchema = z.enum(SANDBOX_STATES);
export type SandboxState = z.infer<typeof sandboxStateSchema>;

/** "Use the same policy implementation for Docker and Daytona sandbox providers". */
export const SANDBOX_PROVIDER_KINDS = ["daytona", "docker"] as const;
export const sandboxProviderKindSchema = z.enum(SANDBOX_PROVIDER_KINDS);
export type SandboxProviderKind = z.infer<typeof sandboxProviderKindSchema>;

/**
 * `audit_log.action`: "All mutations write a sanitized audit event", plus security/permission
 * events the system records without a request.
 */
export const AUDIT_ACTIONS = [
  "account.created",
  "account.linked",
  "onboarding.started",
  "onboarding.confirmed",
  "onboarding.rejected",
  "account.paused",
  "account.resumed",
  "account.deleted",
  "invitation.created",
  "invitation.revoked",
  "invitation.accepted",
  "member.joined",
  "member.role_changed",
  "member.removed",
  "installation.linked",
  "installation.paused",
  "installation.resumed",
  "installation.suspended",
  "installation.unsuspended",
  "installation.deleted",
  "repo.protection_enabled",
  // A repository admin's selection beyond the plan's capacity, waiting for a billing-authorized
  // capacity grant (`pending_capacity`); the fill that protects it later is `repo.protection_enabled`.
  "repo.protection_requested",
  "repo.protection_disabled",
  "repo.mode_changed",
  "repo.activation_authorized",
  "repo.activation_consent_cleared",
  "repo.autopilot_activated",
  "repo.paused",
  "repo.resumed",
  "repo.removed",
  "repo.archived",
  // The GitHub integration recorded a repository the installation can access (new, or back after
  // a removal), or GitHub changed its identity metadata (renamed, transferred, visibility, default
  // branch), matched by its stable GitHub repository ID.
  "repo.recorded",
  "repo.github_changed",
  "policy.updated",
  "finding.dismissed",
  "recipe.overrides_updated",
  "recipe.rediscovery_requested",
  "recipe.approved",
  "recipe.approval_inherited",
  "recipe.rolled_back",
  // The recipe workflows recorded a discovered version, or a version's calibration (`calibrated` or
  // `weak`); a version became the repository's active one (what verification runs with),
  // superseding the versions it replaces (SPEC Security: "Recipe quietly weakened | Versioned CI
  // deviations, restricted inheritance, human approval for weakening/broader authority").
  "recipe.discovered",
  "recipe.calibrated",
  "recipe.activated",
  "fix.retry_requested",
  "fix.revert_requested",
  "fix.publication_override_requested",
  "fix.auto_merged",
  // The generation step staged a fix's encrypted patch, and a verified consumer (verification,
  // trusted checks, publication) decrypted it (SPEC: "Encrypt patch blobs with per-blob data keys
  // wrapped by KMS and audit decrypt access"): the fix, sizes, the consumer's purpose, job and
  // workflow, never the blob's ID or content.
  "fix.patch_staged",
  "fix.patch_decrypted",
  // A person read (decrypted) a failed step's redacted output excerpt (docs/decisions/
  // verification.md "Failed-step output excerpts"): the excerpt's ID and run identity, never its
  // text.
  "repo.failure_excerpt_read",
  "repo.run_record_read",
  "notifications.updated",
  "api_key.created",
  "api_key.revoked",
  "webhook.created",
  "webhook.revoked",
  "webhook.rotated",
  // An administrator sent a subscription the signed `webhook.test` event (one attempt).
  "webhook.test_requested",
  "billing.checkout_started",
  "billing.portal_opened",
  "billing.capacity_previewed",
  "billing.capacity_confirmed",
  "billing.cancel_requested",
  "billing.overages_updated",
  "billing.retained_repo_selected",
  "billing.downgraded",
  "billing.payment_recovered",
  // Recorded from authoritative Stripe state by the billing workflows (docs/decisions/billing.md
  // "Services other areas implement"): a paid first invoice made the account Plus; a confirmed
  // capacity charge was paid (slots active) or declined; a failed renewal started grace; the
  // account's Stripe customer was bound; the quantity the next renewal bills was synced.
  "billing.plus_activated",
  "billing.capacity_activated",
  "billing.capacity_declined",
  "billing.grace_started",
  "billing.customer_bound",
  "billing.renewal_quantity_synced",
  "permission.revoked",
  "operator.global_paused",
  "operator.global_resumed",
  "operator.dispatch_paused",
  "operator.dispatch_resumed",
  // An operator re-drove a dead-lettered workflow ("a bounded dead-letter/reconciliation path for
  // exhausted external retries, with visible action reasons"; operator actions "log actor/reason"):
  // the workflow's kind, what the re-drive did and the operator's reason code; identifiers only.
  "operator.dead_letter_redriven",
  // A release applied a new versioned tier configuration ("Lists are versioned config").
  "tier_config.applied",
  // The worker issued a sandbox's bounded npm proxy capability, or revoked one (SPEC npm proxy:
  // "short-lived job capability bounded by account, job, expiry, allowed packages/artifacts and
  // byte/request limits"; never the token itself).
  "proxy_capability.issued",
  "proxy_capability.revoked",
  // Retention (SPEC Retention: "On account deletion, remove non-financial operational metadata
  // within 30 days"; "Restores run expiry/deletion reconciliation before workers or user access
  // resume"): a deleted account's operational data purged and its tombstones scrubbed; a database
  // restore marked, then reconciled before workers or users resumed (actor `system` or `operator`).
  "account.purged",
  "operations.restore_marked",
  "operations.restore_reconciled",
  // A person's own product analytics choice (SPEC Product analytics: "Respect applicable consent
  // choices"): no account, target the user.
  "analytics_consent.changed",
  // A person signed one of their other sign-ins (a Better Auth session) out from their settings:
  // no account, target the user; never the session's token.
  "sign_in.revoked",
  // A person turned an optional email group off or on for one account, in their settings or with a
  // message's one-click unsubscribe link (docs/decisions/notifications.md "Email preferences and
  // one-click unsubscribe"): the group, the new state and the source; the target is the user.
  "email_preferences.changed",
  // An account owner or admin turned the account's "no third-party scanners" setting on or off
  // (SPEC "Third-party scanner opt-out"): the boolean only; the target is the account.
  "account.third_party_scanners_changed",
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];
/**
 * Actions written only after the promoted tolerant readers (the bounded safe-action arm below):
 * the legacy finite selector stays exactly what deployed strict enum readers accept.
 */
type ReaderFirstAuditAction =
  | "fix.publication_override_requested"
  | "account.third_party_scanners_changed";
const READER_FIRST_AUDIT_ACTIONS: ReadonlySet<string> = new Set<ReaderFirstAuditAction>([
  "fix.publication_override_requested",
  "account.third_party_scanners_changed",
]);
/** Legacy finite action selector retained for deployed strict enum readers. */
export const auditActionWriterSchema = z.enum(
  AUDIT_ACTIONS.filter(
    (action): action is Exclude<AuditAction, ReaderFirstAuditAction> =>
      !READER_FIRST_AUDIT_ACTIONS.has(action),
  ),
);
/** Current registered writes include the action accepted by promoted tolerant readers. */
const auditActionWriteSchema = z.enum(AUDIT_ACTIONS).meta({
  // Redundant bounds on finite literals let the conservative compatibility proof match the
  // promoted reader's safe-action arm without broadening the writer language.
  maxLength: 160,
  pattern: "^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$",
});
/** Write-only validation: this finite set is never registered as a persisted enum reader. */
export function parseAuditActionWrite(value: unknown): AuditAction {
  return auditActionWriteSchema.parse(value);
}
/** Future sanitized actions remain readable; presenters supply a generic unknown label. */
export const auditActionSchema = writerPinned(
  z.union([
    auditActionWriterSchema,
    z
      .string()
      .max(160)
      .regex(/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/),
  ]),
  auditActionWriteSchema,
);
/**
 * Filters remain limited to registered actions; no broad key or mutation capability is implied.
 * The API reads a filter naming any registered action; clients name only the actions the promoted
 * query readers accept, so the scanner opt-out action joins client filters in a later release.
 */
const auditActionQueryWriteSchema = z
  .enum(
    AUDIT_ACTIONS.filter(
      (action): action is Exclude<AuditAction, "account.third_party_scanners_changed"> =>
        action !== "account.third_party_scanners_changed",
    ),
  )
  .meta({ maxLength: 160, pattern: "^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$" });
export const auditActionQuerySchema = writerPinned(
  z.enum(AUDIT_ACTIONS),
  auditActionQueryWriteSchema,
);

/**
 * `global_settings.key`: operator-controlled switches ("Separate operator controls can stop
 * sandbox/model dispatch during an incident"; global merge pause), the versioned tier config and
 * the restore gate ("Restores run expiry/deletion reconciliation before workers or user access
 * resume": set pending when a restored database is marked, passed once reconciliation ran).
 */
export const GLOBAL_SETTING_KEYS = [
  "merge_pause",
  "sandbox_dispatch_pause",
  "model_dispatch_pause",
  "tier_config",
  "restore_gate",
] as const;
export const globalSettingKeySchema = z.enum(GLOBAL_SETTING_KEYS);
export type GlobalSettingKey = z.infer<typeof globalSettingKeySchema>;

/** `release_records.status` (staging promotion and canary rollout). */
export const RELEASE_STATUSES = [
  "built",
  "staging_deployed",
  "staging_passed",
  "promoting",
  "promoted",
  "rolled_back",
  "failed",
] as const;
export const releaseStatusSchema = z.enum(RELEASE_STATUSES);
export type ReleaseStatus = z.infer<typeof releaseStatusSchema>;

// ---- Model relay ----

/**
 * What a relay grant lets a job use the model for (`relay_grants.purpose`); every purpose requires Plus.
 * Fix work uses an `ai_assisted` reservation; operating-cost purposes use atomic daily caps ("All model calls pass through the trusted relay adapter, which
 * checks fix/account authorization, ZDR routing, token/time/cost reservations, and accounting").
 */
export const RELAY_PURPOSES = [
  "fix_agent",
  "recipe_gap_fill",
  "recipe_doctor",
  "recipe_labels",
  "review_hints",
  "baseline_judgment",
  "failure_diagnosis",
  "failure_triage",
] as const;
export const relayPurposeSchema = z.enum(RELAY_PURPOSES);
export type RelayPurpose = z.infer<typeof relayPurposeSchema>;

/**
 * Why a relay grant was revoked before it expired (`relay_grants.revoke_reason`); a revocation is
 * final. `model_mismatch`: the provider served another model than the pinned one ("No silent
 * replacement with a different model"); `entitlement_lost`: a downgrade or pause removed the job's
 * AI authority ("no … newly authorized AI work"); `job_closed`: the attempt ended.
 */
export const RELAY_GRANT_REVOKE_REASONS = [
  "job_closed",
  "model_mismatch",
  "entitlement_lost",
] as const;
export const relayGrantRevokeReasonSchema = z.enum(RELAY_GRANT_REVOKE_REASONS);
export type RelayGrantRevokeReason = z.infer<typeof relayGrantRevokeReasonSchema>;

// ---- Workflow wakes ----

/**
 * Why a waiting workflow is woken ("A prerequisite change resumes the existing nonterminal
 * workflow"; `reclassify` must "wake waiting fixes"; missing fixed versions "wait for
 * advisory/registry changes"). The workflow re-reads state after every wake; a wake never carries a
 * decision. `pr_changed`: the PR head moved outside Kovo, or the PR was reopened; `retired`: an
 * explicit retry retired the attempt.
 */
export const WAKE_REASONS = [
  "findings_changed",
  "advisory_changed",
  "recipe_changed",
  "approval_changed",
  "mode_changed",
  "checks_changed",
  "base_changed",
  "pr_changed",
  "capacity_released",
  "budget_changed",
  "pause_changed",
  "entitlement_changed",
  "hold_cleared",
  "retired",
] as const;
export const wakeReasonSchema = z.enum(WAKE_REASONS);
export type WakeReason = z.infer<typeof wakeReasonSchema>;
