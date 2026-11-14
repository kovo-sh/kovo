import { z } from "zod";

import { kovoIdSchema, providerRefSchema } from "./id-schemas.js";

// Identifiers (ARCHITECTURE §3 "IDs"). Kovo-generated IDs are UUIDs (v7 from the IdGenerator port)
// branded per entity so a RepoId can never be passed where a FixId is expected. External IDs keep
// their provider identity and are never used as Kovo primary keys.
//
// The billing IDs (plan, usage, overage and Stripe) live in ids-billing.ts; the package root and the
// `@kovo/contracts/ids` subpath (ids-all.ts) re-export both. The public CLI bundle takes this module
// alone, so it must never import or re-export a billing module.

// ---- Kovo entities (SPEC "Data model" plus the supporting tables BUILD_PLAN item 3 lists) ----

export const accountIdSchema = kovoIdSchema("AccountId");
export type AccountId = z.infer<typeof accountIdSchema>;
export const userIdSchema = kovoIdSchema("UserId");
export type UserId = z.infer<typeof userIdSchema>;
/**
 * A Better Auth session row's ID (`auth_sessions.id`), never its token: a person's sign-in on one
 * browser, which they can list and revoke (`/v1/me/sessions`).
 */
export const authSessionIdSchema = kovoIdSchema("AuthSessionId");
export type AuthSessionId = z.infer<typeof authSessionIdSchema>;
export const invitationIdSchema = kovoIdSchema("InvitationId");
export type InvitationId = z.infer<typeof invitationIdSchema>;
/** Kovo's `installations.id` row ID, distinct from {@link githubInstallationIdSchema}. */
export const installationIdSchema = kovoIdSchema("InstallationId");
export type InstallationId = z.infer<typeof installationIdSchema>;
export const onboardingRequestIdSchema = kovoIdSchema("OnboardingRequestId");
export type OnboardingRequestId = z.infer<typeof onboardingRequestIdSchema>;
export const apiKeyIdSchema = kovoIdSchema("ApiKeyId");
export type ApiKeyId = z.infer<typeof apiKeyIdSchema>;
export const webhookSubscriptionIdSchema = kovoIdSchema("WebhookSubscriptionId");
export type WebhookSubscriptionId = z.infer<typeof webhookSubscriptionIdSchema>;
export const webhookDeliveryIdSchema = kovoIdSchema("WebhookDeliveryId");
export type WebhookDeliveryId = z.infer<typeof webhookDeliveryIdSchema>;
/** The `id` of an outbound webhook event envelope; receivers deduplicate on it. */
export const eventIdSchema = kovoIdSchema("EventId");
export type EventId = z.infer<typeof eventIdSchema>;

export const repoIdSchema = kovoIdSchema("RepoId");
export type RepoId = z.infer<typeof repoIdSchema>;
/** One "Kovo needs X" ask on a repository (`repo_customer_asks`). */
export const customerAskIdSchema = kovoIdSchema("CustomerAskId");
export type CustomerAskId = z.infer<typeof customerAskIdSchema>;
export const installRootIdSchema = kovoIdSchema("InstallRootId");
export type InstallRootId = z.infer<typeof installRootIdSchema>;
export const projectIdSchema = kovoIdSchema("ProjectId");
export type ProjectId = z.infer<typeof projectIdSchema>;
export const installRootObservationIdSchema = kovoIdSchema("InstallRootObservationId");
export type InstallRootObservationId = z.infer<typeof installRootObservationIdSchema>;
export const snapshotIdSchema = kovoIdSchema("SnapshotId");
export type SnapshotId = z.infer<typeof snapshotIdSchema>;
export const findingIdSchema = kovoIdSchema("FindingId");
export type FindingId = z.infer<typeof findingIdSchema>;
export const fixIdSchema = kovoIdSchema("FixId");
export type FixId = z.infer<typeof fixIdSchema>;
export const fixRetryReceiptIdSchema = kovoIdSchema("FixRetryReceiptId");
export type FixRetryReceiptId = z.infer<typeof fixRetryReceiptIdSchema>;
export const evidenceIdSchema = kovoIdSchema("EvidenceId");
export type EvidenceId = z.infer<typeof evidenceIdSchema>;
export const patchBlobIdSchema = kovoIdSchema("PatchBlobId");
export type PatchBlobId = z.infer<typeof patchBlobIdSchema>;
/** A failed step's encrypted, redacted output excerpt (`failure_excerpts.id`). */
export const failureExcerptIdSchema = kovoIdSchema("FailureExcerptId");
export type FailureExcerptId = z.infer<typeof failureExcerptIdSchema>;
/** One encrypted full run-record object. */
export const runRecordIdSchema = kovoIdSchema("RunRecordId");
export type RunRecordId = z.infer<typeof runRecordIdSchema>;
export const staffAccessGrantIdSchema = kovoIdSchema("StaffAccessGrantId");
export type StaffAccessGrantId = z.infer<typeof staffAccessGrantIdSchema>;
export const staffAccessAuditIdSchema = kovoIdSchema("StaffAccessAuditId");
export type StaffAccessAuditId = z.infer<typeof staffAccessAuditIdSchema>;
export const slotIdSchema = kovoIdSchema("SlotId");
export type SlotId = z.infer<typeof slotIdSchema>;
export const baselineEgressRuleIdSchema = kovoIdSchema("BaselineEgressRuleId");
export type BaselineEgressRuleId = z.infer<typeof baselineEgressRuleIdSchema>;
export const fixEgressAllowanceIdSchema = kovoIdSchema("FixEgressAllowanceId");
export type FixEgressAllowanceId = z.infer<typeof fixEgressAllowanceIdSchema>;

export const recipeVersionIdSchema = kovoIdSchema("RecipeVersionId");
export type RecipeVersionId = z.infer<typeof recipeVersionIdSchema>;

/** An asynchronous job exposed through `GET /v1/jobs/{id}`. */
export const jobIdSchema = kovoIdSchema("JobId");
export type JobId = z.infer<typeof jobIdSchema>;
/** Kovo's row for a provider sandbox, tracked by the watchdog. */
export const sandboxIdSchema = kovoIdSchema("SandboxId");
export type SandboxId = z.infer<typeof sandboxIdSchema>;
export const workflowOutboxIdSchema = kovoIdSchema("WorkflowOutboxId");
export type WorkflowOutboxId = z.infer<typeof workflowOutboxIdSchema>;
/** A recorded workflow wake (`workflow_wakes`), delivered with its wake key as idempotency key. */
export const workflowWakeIdSchema = kovoIdSchema("WorkflowWakeId");
export type WorkflowWakeId = z.infer<typeof workflowWakeIdSchema>;
/** A parked workflow wait (`workflow_parks`): the sweep starts a fresh run when due. */
export const workflowParkIdSchema = kovoIdSchema("WorkflowParkId");
export type WorkflowParkId = z.infer<typeof workflowParkIdSchema>;
/**
 * A model relay grant (`relay_grants.id`): the non-secret identity the relay's bearer token is a MAC
 * over, together with the job and expiry. The token itself is never stored.
 */
export const relayGrantIdSchema = kovoIdSchema("RelayGrantId");
export type RelayGrantId = z.infer<typeof relayGrantIdSchema>;
export const auditEventIdSchema = kovoIdSchema("AuditEventId");
export type AuditEventId = z.infer<typeof auditEventIdSchema>;
export const emailIdSchema = kovoIdSchema("EmailId");
export type EmailId = z.infer<typeof emailIdSchema>;
export const analyticsOutboxIdSchema = kovoIdSchema("AnalyticsOutboxId");
export type AnalyticsOutboxId = z.infer<typeof analyticsOutboxIdSchema>;
/** `analytics_outbox.event_uuid`: the PostHog event UUID used for deduplication. */
export const analyticsEventIdSchema = kovoIdSchema("AnalyticsEventId");
export type AnalyticsEventId = z.infer<typeof analyticsEventIdSchema>;
export const releaseRecordIdSchema = kovoIdSchema("ReleaseRecordId");
export type ReleaseRecordId = z.infer<typeof releaseRecordIdSchema>;
/** A support case; opaque to the budget ledger until case intake. */
export const supportCaseIdSchema = kovoIdSchema("SupportCaseId");
export type SupportCaseId = z.infer<typeof supportCaseIdSchema>;
/** One reserved support operation (`support_budget_reservations.id`). */
export const supportBudgetReservationIdSchema = kovoIdSchema("SupportBudgetReservationId");
export type SupportBudgetReservationId = z.infer<typeof supportBudgetReservationIdSchema>;

// ---- GitHub (immutable numeric IDs; SPEC: keyed "by immutable GitHub account ID, not login") ----

/**
 * GitHub numeric IDs are positive integers that fit in 2^53 (ARCHITECTURE §3). Octokit parses larger
 * integers as `bigint`, which fails this schema closed.
 */
function githubNumericIdSchema<const Brand extends string>(brand: Brand) {
  return z
    .int({ error: `${brand} must be a positive safe integer` })
    .positive()
    .brand<Brand>();
}

export const githubAccountIdSchema = githubNumericIdSchema("GithubAccountId");
export type GithubAccountId = z.infer<typeof githubAccountIdSchema>;
export const githubUserIdSchema = githubNumericIdSchema("GithubUserId");
export type GithubUserId = z.infer<typeof githubUserIdSchema>;
export const githubRepoIdSchema = githubNumericIdSchema("GithubRepoId");
export type GithubRepoId = z.infer<typeof githubRepoIdSchema>;
export const githubInstallationIdSchema = githubNumericIdSchema("GithubInstallationId");
export type GithubInstallationId = z.infer<typeof githubInstallationIdSchema>;
/** A GitHub App ID (check-run `app.id`, required-check `integration_id`/`app_id`). */
export const githubAppIdSchema = githubNumericIdSchema("GithubAppId");
export type GithubAppId = z.infer<typeof githubAppIdSchema>;
/** A pull request number within one repository. */
export const pullRequestNumberSchema = githubNumericIdSchema("PullRequestNumber");
export type PullRequestNumber = z.infer<typeof pullRequestNumberSchema>;

// ---- Advisories ----

/**
 * An OSV/GHSA/MAL advisory ID (`GHSA-9gfj-28hw-jchp`, `MAL-2026-17187`, `CVE-2025-55182`): an
 * alphanumeric database prefix, a hyphen, then the database's entry ID. Case is preserved.
 */
export const advisoryIdSchema = z
  .string()
  .max(128)
  .regex(/^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]+$/, { error: "must be an OSV advisory ID" })
  .brand<"AdvisoryId">();
export type AdvisoryId = z.infer<typeof advisoryIdSchema>;

// ---- Other provider references (opaque; printable ASCII, bounded) ----

/** `emails.provider_id` (Resend email ID). */
export const providerMessageIdSchema = providerRefSchema("ProviderMessageId");
export type ProviderMessageId = z.infer<typeof providerMessageIdSchema>;
/** The sandbox provider's own sandbox ID (Daytona sandbox ID or Docker container ID). */
export const providerSandboxIdSchema = providerRefSchema("ProviderSandboxId");
export type ProviderSandboxId = z.infer<typeof providerSandboxIdSchema>;
/** `provider_events.event_id` for GitHub deliveries, Stripe events and Resend webhooks. */
export const providerEventIdSchema = providerRefSchema("ProviderEventId");
export type ProviderEventId = z.infer<typeof providerEventIdSchema>;
