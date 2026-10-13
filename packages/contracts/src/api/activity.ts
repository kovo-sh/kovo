import { writerPinned } from "../compatibility.js";
import { auditActionSchema } from "../enums/operations.js";
import { z } from "zod";

import { fixTierSchema, p0TriggerSchema, severitySchema } from "../enums/advisories.js";
import { NONTERMINAL_FIX_STATUSES, mergedBySchema } from "../enums/fixes.js";
import type { AuditAction, JobKind } from "../enums/operations.js";
import {
  approvalStatusSchema,
  approvedViaSchema,
  calibrationStatusSchema,
} from "../enums/recipes.js";
import {
  desiredModeSchema,
  modeReasonSchema,
  repoModeSchema,
  MODE_REASONS,
} from "../enums/repos.js";
import {
  NEXT_ACTION_ACTOR,
  NEXT_ACTION_ACTORS,
  fixWaitSchema,
  nextActionActorSchema,
  nextActionSchema,
  type NextAction,
  type NextActionActor,
} from "../enums/waits.js";
import { pullRequestRefSchema } from "../webhooks.js";
import {
  accountIdSchema,
  advisoryIdSchema,
  findingIdSchema,
  fixIdSchema,
  jobIdSchema,
  recipeVersionIdSchema,
  repoIdSchema,
} from "../ids.js";
import { packageNameSchema, packageVersionSchema } from "../npm.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { whenValid } from "../primitives.js";
import { durableFailureReasonCodeSchema } from "../problem.js";
import { utcDateTimeSchema } from "../time.js";
import { actorRefSchema, repoRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// Home at any scale (docs/decisions/dashboard.md "Home reads account-level attention and activity";
// docs/decisions/contracts.md "Account attention and activity"). SPEC Web application: "Show next
// required action without exposing infrastructure implementation details. Explicitly show plan
// restrictions, permission restrictions, weak verification and missing branch protections as
// distinct reasons"; "Every waiting state carries a machine-readable reason and next action". Two
// account-level reads replace the dashboard's per-repository fan-out:
//
// - `GET /v1/accounts/{account}/attention`: every open item of the account that waits on someone,
//   over every repository the caller can currently read, grouped by who can act
//   (`NEXT_ACTION_ACTOR`) with counts;
// - `GET /v1/accounts/{account}/activity`: a paged feed of what happened, projected from the
//   outbound webhook events, the P0-alert and weekly-digest emails (kinds, times and recipient
//   counts, never addresses), finished scan and recipe jobs and an allowlist of audit actions.
//
// Both are ordinary reads: human sessions and API keys (a key sees only its delegated
// repositories and no account-level items or audit entries).

const READERS = ["human_session", "api_key_read", "api_key_write"] as const;

const ROW_WEB = "Show next required action without exposing infrastructure implementation details.";

const accountParams = z.strictObject({ account: accountIdSchema });

// ---- Attention ----

/**
 * Account-level actions that are not the next action of a wait yet still wait on a person: choosing
 * who receives security alerts while none can (`no_recipient`), and approving paid capacity for
 * repositories a repository admin selected beyond the plan (`pending_capacity`).
 */
export const ATTENTION_ACCOUNT_ACTIONS = ["choose_alert_recipients", "approve_capacity"] as const;
export type AttentionAccountAction = (typeof ATTENTION_ACCOUNT_ACTIONS)[number];

export const attentionActionSchema = z.union([nextActionSchema, z.enum(ATTENTION_ACCOUNT_ACTIONS)]);
export type AttentionAction = NextAction | AttentionAccountAction;

/** Who can take each attention action: the next-action table plus the two account actions. */
export const ATTENTION_ACTION_ACTOR: Readonly<Record<AttentionAction, NextActionActor>> = {
  ...NEXT_ACTION_ACTOR,
  choose_alert_recipients: "account_admin",
  approve_capacity: "billing",
};

/**
 * Next actions that concern the whole account or installation rather than one repository: one
 * item however many repositories they hold back (the repositories are named on the item).
 */
export const ACCOUNT_SCOPED_NEXT_ACTIONS = [
  "upgrade_plan",
  "update_payment_method",
  "enable_overages",
  "raise_overage_limit",
  "resume_account",
  "resume_installation",
  "resume_global",
  "restore_installation",
] as const satisfies readonly NextAction[];

/**
 * What an item is about: the account or its installation, one repository's mode gate, or one
 * fix's wait.
 */
export const ATTENTION_SCOPES = ["account", "repo", "fix"] as const;
export const attentionScopeSchema = z.enum(ATTENTION_SCOPES);
export type AttentionScope = z.infer<typeof attentionScopeSchema>;

/** How many repositories an item names; `repo_count` says how many it concerns in all. */
export const ATTENTION_ITEM_REPO_LIMIT = 10;
/** How many items a group lists; `count` says how many it has in all. */
export const ATTENTION_GROUP_ITEM_LIMIT = 50;
/** How many repositories with open P0 findings are listed; `p0.repos` counts them all. */
export const ATTENTION_INCIDENT_LIMIT = 20;

/** The fix a fix-scoped item waits on, with its wait (reason and next action). */
export const attentionFixSchema = z.strictObject({
  id: fixIdSchema,
  tier: fixTierSchema,
  status: z.enum(NONTERMINAL_FIX_STATUSES),
  target_package: packageNameSchema,
  /** Null for a reviewed removal. */
  target_version: packageVersionSchema.nullable(),
  wait: fixWaitSchema,
  pull_request: pullRequestRefSchema.nullable(),
});
export type AttentionFix = z.output<typeof attentionFixSchema>;

/** A stable item key: `account:<action>`, `repo:<repo>:<action>` or `fix:<fix>`. */
const attentionItemIdSchema = z
  .string()
  .regex(/^(?:account:[a-z_]+|repo:[0-9a-f-]{36}:[a-z_]+|fix:[0-9a-f-]{36})$/, {
    error: "must be an attention item key",
  });

/**
 * One open item. `viewer_can_act` follows the three independent permissions: the Kovo role for
 * account and billing actions, the caller's current GitHub permission on every repository the item
 * concerns for repository actions (`viewer_permission`), and never for Kovo's own waits, Kovo
 * operations or GitHub-side actions. It is always false for an API key.
 */
export const attentionItemSchema = z
  .strictObject({
    id: attentionItemIdSchema,
    scope: attentionScopeSchema,
    action: attentionActionSchema,
    actor: nextActionActorSchema,
    viewer_can_act: z.boolean(),
    /** Something is broken now: the App lost access, P0 alerts reach no one, payment past due. */
    danger: z.boolean(),
    /** The repository gates behind the item (none for fix waits and the account actions). */
    reasons: z.array(modeReasonSchema).max(MODE_REASONS.length),
    repos: z.array(repoRefSchema).max(ATTENTION_ITEM_REPO_LIMIT),
    repo_count: z.int().nonnegative(),
    /** When the waiting state began, only where Kovo records it (pauses, capacity, grace). */
    started_at: utcDateTimeSchema.nullable(),
    /** A repository item's requested and effective modes, when they differ. */
    mode: z.strictObject({ desired: desiredModeSchema, effective: repoModeSchema }).nullable(),
    fix: attentionFixSchema.nullable(),
    /** The end of the payment grace period, on the payment item a billing role sees. */
    grace_deadline_at: utcDateTimeSchema.nullable(),
  })
  .refine((item) => ATTENTION_ACTION_ACTOR[item.action] === item.actor, {
    ...whenValid,
    error: "the actor is the one the action names",
    path: ["actor"],
  })
  .refine((item) => (item.scope === "fix") === (item.fix !== null), {
    ...whenValid,
    error: "exactly a fix item carries its fix",
    path: ["fix"],
  })
  .refine((item) => item.fix === null || item.fix.wait.next_action === item.action, {
    ...whenValid,
    error: "a fix item's action is its wait's next action",
    path: ["action"],
  })
  .refine((item) => item.scope === "account" || item.repo_count === 1, {
    ...whenValid,
    error: "a repository or fix item concerns exactly one repository",
    path: ["repo_count"],
  })
  .refine(
    (item) =>
      item.repos.length === Math.min(item.repo_count, ATTENTION_ITEM_REPO_LIMIT) ||
      // Capacity requests are counted account-wide; only the readable ones are named.
      (item.action === "approve_capacity" && item.repos.length <= item.repo_count),
    { ...whenValid, error: "the named repositories are the first of repo_count", path: ["repos"] },
  )
  .refine((item) => item.grace_deadline_at === null || item.action === "update_payment_method", {
    ...whenValid,
    error: "only the payment item carries a grace deadline",
    path: ["grace_deadline_at"],
  });
export type AttentionItem = z.output<typeof attentionItemSchema>;

/** The items one actor can clear: those the caller can act on first, then danger first. */
export const attentionGroupSchema = z
  .strictObject({
    actor: nextActionActorSchema,
    count: z.int().positive(),
    /** Items of this group the caller can act on. */
    viewer_can_act: z.int().nonnegative(),
    items: z.array(attentionItemSchema).min(1).max(ATTENTION_GROUP_ITEM_LIMIT),
  })
  .refine((group) => group.items.every((item) => item.actor === group.actor), {
    ...whenValid,
    error: "every item of a group waits on its actor",
    path: ["items"],
  })
  .refine(
    (group) =>
      group.items.length === Math.min(group.count, ATTENTION_GROUP_ITEM_LIMIT) &&
      group.viewer_can_act <= group.count,
    { ...whenValid, error: "counts cover the listed items", path: ["count"] },
  );
export type AttentionGroup = z.output<typeof attentionGroupSchema>;

export const attentionSchema = z
  .strictObject({
    /** Non-empty groups in `NEXT_ACTION_ACTORS` order. */
    groups: z.array(attentionGroupSchema).max(NEXT_ACTION_ACTORS.length),
    /** Items the caller can act on. */
    needs_you: z.int().nonnegative(),
    /** Items waiting on a person (anyone), excluding Kovo's own waits and Kovo operations. */
    open: z.int().nonnegative(),
    /** Open P0 findings over the readable protected repositories. */
    p0: z.strictObject({
      findings: z.int().nonnegative(),
      repos: z.int().nonnegative(),
      /** Most P0 findings first, then by name. */
      incidents: z
        .array(z.strictObject({ repo: repoRefSchema, count: z.int().positive() }))
        .max(ATTENTION_INCIDENT_LIMIT),
    }),
    /** Fixes over the readable repositories: in progress now, and merged in the last 24 hours. */
    fixes: z.strictObject({
      in_progress: z.int().nonnegative(),
      merged_last_day: z.int().nonnegative(),
    }),
    /** Readable repositories, and how many of them are protected. */
    repos: z.strictObject({
      readable: z.int().nonnegative(),
      protected: z.int().nonnegative(),
    }),
    generated_at: utcDateTimeSchema,
  })
  .refine(
    (attention) => {
      const order = attention.groups.map((group) => NEXT_ACTION_ACTORS.indexOf(group.actor));
      return order.every((index, position) => position === 0 || index > (order[position - 1] ?? 0));
    },
    { ...whenValid, error: "groups follow NEXT_ACTION_ACTORS order, once each", path: ["groups"] },
  )
  .refine(
    (attention) =>
      attention.needs_you ===
      attention.groups.reduce((sum, group) => sum + group.viewer_can_act, 0),
    { ...whenValid, error: "needs_you sums the groups", path: ["needs_you"] },
  )
  .refine(
    (attention) =>
      attention.p0.incidents.length === Math.min(attention.p0.repos, ATTENTION_INCIDENT_LIMIT) &&
      attention.p0.repos <= attention.p0.findings,
    { ...whenValid, error: "incidents list the first repositories with P0s", path: ["p0"] },
  )
  .refine((attention) => attention.repos.protected <= attention.repos.readable, {
    ...whenValid,
    error: "protected repositories are readable ones",
    path: ["repos", "protected"],
  });
export type Attention = z.output<typeof attentionSchema>;

// ---- Activity ----

/**
 * How far back the feed reaches: the shortest active-storage retention among its sources (SPEC
 * Retention: webhook delivery records and "Email metadata … 30 days"), so every source covers the
 * same window and older history is in the audit log (one year) and on each repository's pages.
 */
export const ACTIVITY_WINDOW_DAYS = 30;

/** What an entry is about, the feed's one filter besides the repository. */
export const ACTIVITY_CATEGORIES = ["fixes", "findings", "recipes", "alerts", "settings"] as const;
export const activityCategorySchema = z.enum(ACTIVITY_CATEGORIES);
export type ActivityCategory = z.infer<typeof activityCategorySchema>;

/** Emails the feed shows: that an alert or digest went out, to how many people, never to whom. */
export const ACTIVITY_EMAIL_KINDS = ["p0_detected", "weekly_digest"] as const;
export const activityEmailKindSchema = z.enum(ACTIVITY_EMAIL_KINDS);

/** Jobs the feed shows when they finish: scans and recipe discovery and calibration. */
export const ACTIVITY_JOB_KINDS = [
  "inventory",
  "recipe_discovery",
  "recipe_rediscovery",
  "recipe_calibration",
] as const satisfies readonly JobKind[];
export const activityJobKindSchema = z.enum(ACTIVITY_JOB_KINDS);

/**
 * Audit actions on one repository the feed shows to everyone who can read that repository: each
 * states a change its per-repository reads show too (protection, mode, pauses, policy, dismissals,
 * recipe changes, retries and reverts). Actions that duplicate an outbound event (`fix.auto_merged`,
 * `recipe.approved`, `recipe.calibrated`) and bookkeeping (`fix.patch_*`, `repo.recorded`) are
 * left out.
 */
export const ACTIVITY_REPO_AUDIT_ACTIONS = [
  "repo.protection_enabled",
  "repo.protection_requested",
  "repo.protection_disabled",
  "repo.mode_changed",
  "repo.activation_authorized",
  "repo.autopilot_activated",
  "repo.paused",
  "repo.resumed",
  "policy.updated",
  "finding.dismissed",
  "recipe.overrides_updated",
  "recipe.rediscovery_requested",
  "recipe.rolled_back",
  "recipe.activated",
  "fix.retry_requested",
  "fix.revert_requested",
  "fix.publication_override_requested",
] as const satisfies readonly AuditAction[];

/**
 * Account-level audit actions the feed shows to owners and admins only (who may read the whole
 * audit log): pauses, the installation's state, membership and the capacity they paid for.
 */
export const ACTIVITY_ACCOUNT_AUDIT_ACTIONS = [
  "account.paused",
  "account.resumed",
  "installation.paused",
  "installation.resumed",
  "installation.suspended",
  "installation.unsuspended",
  "installation.deleted",
  "member.joined",
  "member.role_changed",
  "member.removed",
  "notifications.updated",
  "billing.capacity_confirmed",
] as const satisfies readonly AuditAction[];

export const activityAuditActionWriterSchema = z
  .enum([...ACTIVITY_REPO_AUDIT_ACTIONS, ...ACTIVITY_ACCOUNT_AUDIT_ACTIONS])
  .meta({ maxLength: 160, pattern: "^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$" });
export const activityAuditActionSchema = writerPinned(
  auditActionSchema.clone(),
  activityAuditActionWriterSchema,
);

const activityBase = {
  /** The source record's ID (an event, email, job or audit event), unique across the feed. */
  id: z.uuid(),
  at: utcDateTimeSchema,
  category: activityCategorySchema,
};

/** Repository entries name their repository; the caller can currently read it. */
const repoEntry = { ...activityBase, repo: repoRefSchema };

export const activityEntrySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...repoEntry,
    kind: z.literal("finding.p0_detected"),
    finding_id: findingIdSchema,
    advisory_id: advisoryIdSchema,
    package: packageNameSchema,
    version: packageVersionSchema,
    severity: severitySchema,
    trigger: p0TriggerSchema,
  }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("fix.pr_opened"),
    fix_id: fixIdSchema,
    tier: fixTierSchema,
    target_package: packageNameSchema,
    target_version: packageVersionSchema.nullable(),
    pull_request: pullRequestRefSchema,
    review_only: z.boolean(),
  }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("fix.merged"),
    fix_id: fixIdSchema,
    tier: fixTierSchema,
    target_package: packageNameSchema,
    target_version: packageVersionSchema.nullable(),
    pull_request: pullRequestRefSchema,
    merged_by: mergedBySchema,
  }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("fix.human_action_needed"),
    fix_id: fixIdSchema,
    tier: fixTierSchema,
    target_package: packageNameSchema,
    wait: fixWaitSchema,
    pull_request: pullRequestRefSchema.nullable(),
  }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("fix.reverted"),
    fix_id: fixIdSchema,
    target_package: packageNameSchema,
    revert_pull_request: pullRequestRefSchema,
  }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("recipe.state_changed"),
    recipe_version_id: recipeVersionIdSchema,
    version: z.int().positive(),
    calibration_status: calibrationStatusSchema,
    approval_status: approvalStatusSchema,
  }),
  z
    .strictObject({
      ...repoEntry,
      kind: z.literal("recipe.approved"),
      recipe_version_id: recipeVersionIdSchema,
      version: z.int().positive(),
      approved_via: approvedViaSchema,
      approved_via_consent_id: z.uuid().exactOptional(),
    })
    .superRefine((value, ctx) => {
      if (
        (value.approved_via === "autopilot_policy") !==
        (value.approved_via_consent_id !== undefined)
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["approved_via_consent_id"],
          message: "Autopilot-policy approval requires its consent reference",
        });
      }
    }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("autopilot.suggested"),
    qualifying_merges: z.int().nonnegative(),
  }),
  z.strictObject({
    ...activityBase,
    kind: z.literal("email.sent"),
    /** The P0 alert's repository; null for the account's weekly digest. */
    repo: repoRefSchema.nullable(),
    email_kind: activityEmailKindSchema,
    /** People it was sent to (never who, never an address). */
    recipient_count: z.int().positive(),
  }),
  z.strictObject({
    ...repoEntry,
    kind: z.literal("job.finished"),
    job_id: jobIdSchema,
    job_kind: activityJobKindSchema,
    status: z.enum(["succeeded", "failed"]),
    /** The stable reason a failed job failed; null when it succeeded. */
    failure_reason: durableFailureReasonCodeSchema.nullable(),
    recipe_version_id: recipeVersionIdSchema.nullable(),
  }),
  z.strictObject({
    ...activityBase,
    kind: z.literal("audit"),
    /** Null for an account-level action (shown to owners and admins only). */
    repo: repoRefSchema.nullable(),
    action: activityAuditActionSchema,
    actor: actorRefSchema,
  }),
]);
export type ActivityEntry = z.output<typeof activityEntrySchema>;
export type ActivityKind = ActivityEntry["kind"];

export const activityQuerySchema = z.strictObject({
  ...paginationQueryShape,
  category: activityCategorySchema.exactOptional(),
  repo_id: repoIdSchema.exactOptional(),
});

export const ACTIVITY_ENDPOINTS = {
  getAttention: defineEndpoint({
    operationId: "getAttention",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/attention",
    summary:
      "Every open item of the account that waits on someone, over its readable repositories, grouped by who can act, with counts.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: accountParams,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ attention: attentionSchema }) },
    authorization: {
      spec: ROW_WEB,
      actors: READERS,
      tenant: "path_account",
      repoAuthority: { level: "read", over: "listed_items" },
    },
  }),
  listActivity: defineEndpoint({
    operationId: "listActivity",
    area: "accounts",
    method: "GET",
    path: "/v1/accounts/{account}/activity",
    summary:
      "What happened in the account's readable repositories over the last 30 days, newest first.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: accountParams,
    query: activityQuerySchema,
    body: null,
    responses: { 200: pageSchema(activityEntrySchema) },
    authorization: {
      spec: ROW_WEB,
      actors: READERS,
      tenant: "path_account",
      repoAuthority: { level: "read", over: "listed_items" },
    },
    paginated: true,
  }),
} as const;
