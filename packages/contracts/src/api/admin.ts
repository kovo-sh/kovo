import { z } from "zod";

import { diagnosticRequestedBySchema } from "../diagnostics.js";
import {
  incidentCauseSchema,
  incidentEventSchema,
  incidentIdSchema,
  incidentPageReasonSchema,
  incidentPolicySchema,
  incidentSeveritySchema,
} from "../incidents.js";
import { accountTypeSchema, planSchema } from "../enums/accounts.js";
import {
  entitlementStateSchema,
  fundingSourceSchema,
  subscriptionStatusSchema,
  usageKindSchema,
  usageProviderSchema,
  usageUnitSchema,
} from "../enums/billing.js";
import { microUsdWireSchema, nonNegativeMicroUsdWireSchema } from "../money.js";
import { calibrationStatusSchema, approvalStatusSchema } from "../enums/recipes.js";
import { jobKindSchema, jobStatusSchema } from "../enums/operations.js";
import { ladderRungSchema } from "../enums/fixes.js";
import {
  activationPolicySchema,
  branchProtectionStatusSchema,
  modeReasonSchema,
  pauseReasonCodeSchema,
  repoModeSchema,
} from "../enums/repos.js";
import { repoFullNameSchema } from "../github.js";
import {
  accountIdSchema,
  cycleIdSchema,
  jobIdSchema,
  pullRequestNumberSchema,
  repoIdSchema,
} from "../ids.js";
import { whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { couponCodeSchema, ownerPlanGrantSchema } from "./billing.js";
import { defineEndpoint } from "./endpoint.js";
import { accountUsageTotalsSchema } from "./usage.js";

// The internal admin site's read API (SPEC "Internal admin site"; plans/admin-site.md PR 4). Only
// the `operator` actor may call it: the `kovo-admin` CLI's verified service identity today, the
// IAP-gated admin service later. Every response is a closed projection of metadata (logins,
// repository names, modes, counts and codes), never content; package names, decision traces and
// workflow steps stay behind D9 grants. Each read appends an `admin_audit` row (operator, label,
// action, scope, row count) before the response is released. `requested_by` is the self-declared
// `owner` / `agent:<name>` label: attribution, not authentication.

// The SPEC rules each route follows, quoted verbatim (SPEC "Internal admin site").
const TIER_SPEC = "customer counts by tier";
const HEALTH_SPEC = "each repository's health with non-sensitive run information.";
const COST_SPEC =
  "Costs need no justification. Model identifiers are shown; prompts, outputs and package names are";
const AUDIT_SPEC = "Every admin read and mutation appends operator, channel, label, action,";
const INCIDENTS_SPEC = "GCP alerts, by severity, and filter for open and closed";
const GRANTS_SPEC = "Needs a justification (a 20–1000 char D9 grant, at most 2h)";
const COUPON_SPEC = "Operators create and revoke coupons through the [internal admin";
const DRILL_DOWN_SPEC =
  "a customer drill-down: protected repositories and how each is protected, for example autopilot";

/** The tiers the admin site counts customers by (SPEC "Internal admin site"). */
export const ADMIN_TIERS = [
  "free",
  "plus_paid",
  "plus_stripe_coupon",
  "plus_kovo_grant",
  "plus_owner_grant",
  "past_due",
] as const;
export const adminTierSchema = z.enum(ADMIN_TIERS);
export type AdminTier = z.infer<typeof adminTierSchema>;

/** The closed actions an `admin_audit` row records (`admin_audit_action_format` CHECK). */
export const ADMIN_AUDIT_ACTIONS = [
  "admin.overview.read",
  "admin.customers.list",
  "admin.customer.read",
  "admin.repos.list",
  "admin.repo.read",
  "admin.repo_jobs.list",
  "admin.search.run",
  "admin.audit.list",
  "admin.costs.read",
  "admin.customer_costs.read",
  "admin.repo_costs.read",
  "admin.job_cost.read",
  "admin.coupons.list",
  "admin.coupon.read",
  "admin.coupon.create",
  "admin.coupon.revoke",
  "admin.incidents.list",
  "admin.grants.list",
] as const;
export const adminAuditActionSchema = z.enum(ADMIN_AUDIT_ACTIONS);
export type AdminAuditAction = z.infer<typeof adminAuditActionSchema>;

export const adminRequestedBySchema = diagnosticRequestedBySchema;

/** Most rows one admin page returns (keeps every audit row's count inside its CHECK). */
export const ADMIN_PAGE_MAX = 200;

const countSchema = z.int().nonnegative();

export const adminTierCountSchema = z.strictObject({
  tier: adminTierSchema,
  accounts: countSchema,
  protected_repos: countSchema,
  autopilot_repos: countSchema,
});
export type AdminTierCount = z.output<typeof adminTierCountSchema>;

export const adminOverviewSchema = z.strictObject({
  generated_at: utcDateTimeSchema,
  tiers: z
    .array(adminTierCountSchema)
    .length(ADMIN_TIERS.length)
    .refine((rows) => rows.every((row, index) => row.tier === ADMIN_TIERS[index]), {
      error: "every tier once, in order",
    }),
  totals: z.strictObject({
    accounts: countSchema,
    protected_repos: countSchema,
    autopilot_repos: countSchema,
  }),
});
export type AdminOverview = z.output<typeof adminOverviewSchema>;

/** An account's GitHub login (the account is named by its installation owner). */
const adminLoginSchema = z.string().min(1).max(100).nullable();

export const adminCustomerSummarySchema = z.strictObject({
  account_id: accountIdSchema,
  login: adminLoginSchema,
  display_name: z.string().min(1).max(100),
  account_type: accountTypeSchema.nullable(),
  tier: adminTierSchema,
  protected_repos: countSchema,
  slots: countSchema,
  autopilot_repos: countSchema,
  paused: z.boolean(),
  created_at: utcDateTimeSchema,
});
export type AdminCustomerSummary = z.output<typeof adminCustomerSummarySchema>;

export const adminCustomerRepoSchema = z.strictObject({
  repo_id: repoIdSchema,
  full_name: repoFullNameSchema,
  protected: z.boolean(),
  desired_mode: repoModeSchema,
  effective_mode: repoModeSchema,
  mode_reasons: z.array(modeReasonSchema).max(32),
  activation_policy: activationPolicySchema,
  pause: pauseReasonCodeSchema.nullable(),
  open_findings: z.strictObject({ p0: countSchema, p1: countSchema, digest: countSchema }),
});
export type AdminCustomerRepo = z.output<typeof adminCustomerRepoSchema>;

export const adminCustomerSchema = z.strictObject({
  account: adminCustomerSummarySchema,
  billing: z.strictObject({
    tier: adminTierSchema,
    entitlement: entitlementStateSchema,
    subscription_status: subscriptionStatusSchema.nullable(),
    period_ends_at: utcDateTimeSchema.nullable(),
    cancel_at_period_end: z.boolean(),
    grace_ends_at: utcDateTimeSchema.nullable(),
    protected_repo_limit: countSchema,
    paid_extra_slots: countSchema,
    owner_grant: z
      .strictObject({ reason: ownerPlanGrantSchema.shape.reason, granted_at: utcDateTimeSchema })
      .nullable(),
  }),
  account_pause: pauseReasonCodeSchema.nullable(),
  /** Protected repositories first, then by name; `repos_truncated` when more exist. */
  repos: z.array(adminCustomerRepoSchema).max(ADMIN_PAGE_MAX),
  repos_truncated: z.boolean(),
});
export type AdminCustomer = z.output<typeof adminCustomerSchema>;

/**
 * A repository's health as the admin site shows it, most urgent first (SPEC "Internal admin site";
 * `services/admin/health.ts` derives it from metadata only).
 */
export const ADMIN_REPO_HEALTH = [
  "inactive",
  "p0",
  "failing",
  "paused",
  "degraded",
  "healthy",
] as const;
export const adminRepoHealthSchema = z.enum(ADMIN_REPO_HEALTH);
export type AdminRepoHealth = z.infer<typeof adminRepoHealthSchema>;

/** A stable reason or wait code (never free text). */
const codeSchema = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);

const openFindingsSchema = z.strictObject({
  p0: countSchema,
  p1: countSchema,
  digest: countSchema,
});

export const adminRepoSummarySchema = z.strictObject({
  repo_id: repoIdSchema,
  account_id: accountIdSchema,
  account_login: adminLoginSchema,
  full_name: repoFullNameSchema,
  tier: adminTierSchema,
  protected: z.boolean(),
  desired_mode: repoModeSchema,
  effective_mode: repoModeSchema,
  health: adminRepoHealthSchema,
  open_findings: openFindingsSchema,
  last_job_finished_at: utcDateTimeSchema.nullable(),
});
export type AdminRepoSummary = z.output<typeof adminRepoSummarySchema>;

export const adminRepoSchema = z.strictObject({
  repo: adminRepoSummarySchema,
  mode_reasons: z.array(modeReasonSchema).max(32),
  activation_policy: activationPolicySchema,
  pause: pauseReasonCodeSchema.nullable(),
  account_pause: pauseReasonCodeSchema.nullable(),
  branch_protection: branchProtectionStatusSchema.nullable(),
  recipe: z
    .strictObject({
      version: z.int().positive(),
      calibration: calibrationStatusSchema,
      approval: approvalStatusSchema,
    })
    .nullable(),
  prs_open: countSchema,
  merged_last_30_days: countSchema,
  last_scan_finished_at: utcDateTimeSchema.nullable(),
});
export type AdminRepo = z.output<typeof adminRepoSchema>;

export const ADMIN_PR_STATES = ["open", "merged", "closed"] as const;

export const adminJobSchema = z.strictObject({
  job_id: jobIdSchema,
  kind: jobKindSchema,
  status: jobStatusSchema,
  /** The fix's current ladder rung (a job does not record the rung it ran at). */
  fix_rung: ladderRungSchema.nullable(),
  created_at: utcDateTimeSchema,
  started_at: utcDateTimeSchema.nullable(),
  finished_at: utcDateTimeSchema.nullable(),
  duration_ms: countSchema.nullable(),
  /** Why the job failed (a persisted reason code). */
  failure_reason: codeSchema.nullable(),
  /** What the job waits on for funding (a reservation wait reason). */
  funding_wait: codeSchema.nullable(),
  pr: z
    .strictObject({ number: pullRequestNumberSchema, state: z.enum(ADMIN_PR_STATES) })
    .nullable(),
});
export type AdminJob = z.output<typeof adminJobSchema>;

export const ADMIN_SEARCH_MAX = 10;

export const adminSearchResultSchema = z.strictObject({
  customers: z
    .array(
      z.strictObject({
        account_id: accountIdSchema,
        login: adminLoginSchema,
        tier: adminTierSchema,
      }),
    )
    .max(ADMIN_SEARCH_MAX),
  repos: z
    .array(
      z.strictObject({
        repo_id: repoIdSchema,
        account_id: accountIdSchema,
        full_name: repoFullNameSchema,
        health: adminRepoHealthSchema,
      }),
    )
    .max(ADMIN_SEARCH_MAX),
});
export type AdminSearchResult = z.output<typeof adminSearchResultSchema>;

export const adminAuditEntrySchema = z.strictObject({
  at: utcDateTimeSchema,
  operator: z.string().min(1).max(320),
  channel: z.enum(["cli", "admin_ui"]),
  requested_by: adminRequestedBySchema,
  action: z.string().regex(/^admin(\.[a-z][a-z0-9_]{0,31}){1,3}$/),
  account_id: accountIdSchema.nullable(),
  repo_id: repoIdSchema.nullable(),
  row_count: countSchema,
});
export type AdminAuditEntry = z.output<typeof adminAuditEntrySchema>;

// ---- Costs (SPEC "Internal admin site", owner 2026-10-05: "the costs on a per job, per repo, per
// customer basis for specific drilldowns and more broadly"). Actual provider-reported model and
// sandbox charges from the usage ledger, in micro-USD wire strings; never estimates, prompts,
// outputs or package names. ----

const usdSchema = nonNegativeMicroUsdWireSchema;

/** One slice of cost: the total, by kind and by funding. */
export const adminCostBreakdownSchema = z.strictObject({
  cost_usd: usdSchema,
  model_usd: usdSchema,
  sandbox_usd: usdSchema,
  /** Funded by the cycle's included allowance (paid, granted or coupon). */
  included_usd: usdSchema,
  /** Kovo-funded beyond any allowance (deterministic work). */
  kovo_funded_usd: usdSchema,
  /** The overage base; the customer is charged this × 1.20. */
  overage_usd: usdSchema,
});
export type AdminCostBreakdown = z.output<typeof adminCostBreakdownSchema>;

/**
 * Ledger cost in the window, plus what open reservations hold. `held_usd` and
 * `uncertain_reservations` are a snapshot now, not windowed: reservations open now in the scope.
 */
export const adminCostTotalsSchema = adminCostBreakdownSchema.extend({
  /** Still reserved for running work (maximum minus actual), not yet cost. */
  held_usd: usdSchema,
  /** Reservations whose actual cost is not reconciled yet. */
  uncertain_reservations: countSchema,
});
export type AdminCostTotals = z.output<typeof adminCostTotalsSchema>;

export const ADMIN_COST_GROUPS = [
  "day",
  "tier",
  "account",
  "repo",
  "kind",
  "funding",
  "model",
] as const;
export const adminCostGroupSchema = z.enum(ADMIN_COST_GROUPS);
export type AdminCostGroup = z.infer<typeof adminCostGroupSchema>;

/** Longest cost window (days). */
export const ADMIN_COST_WINDOW_MAX_DAYS = 366;

const costWindowQuery = {
  since: utcDateTimeSchema.exactOptional(),
  until: utcDateTimeSchema.exactOptional(),
};

const costWindowSchema = { starts_at: utcDateTimeSchema, ends_at: utcDateTimeSchema };

export const adminCostsSchema = z.strictObject({
  ...costWindowSchema,
  group_by: adminCostGroupSchema,
  totals: adminCostTotalsSchema,
  groups: z
    .array(
      adminCostBreakdownSchema.extend({
        /** The group: a UTC day, tier, account ID, repository ID, kind, funding or model. */
        group: z.string().min(1).max(200),
        /** A readable name where the key is an ID (login or repository name). */
        label: z.string().min(1).max(200).nullable(),
      }),
    )
    .max(400),
  /** Cost with no repository attributed (account-level work), counted in the totals. */
  unattributed_usd: usdSchema,
});
export type AdminCosts = z.output<typeof adminCostsSchema>;

/** The running billing cycle's bounds (`cycle_id` null while it is not opened yet). */
const adminCycleSchema = {
  cycle_id: cycleIdSchema.nullable(),
  starts_at: utcDateTimeSchema,
  ends_at: utcDateTimeSchema,
};

export const adminCustomerCostsSchema = z.strictObject({
  ...costWindowSchema,
  account_id: accountIdSchema,
  totals: adminCostTotalsSchema,
  /**
   * The running cycle, as the customer's own `GET /v1/usage` reports it (SPEC "Per customer": "the
   * cycle's allowance consumed, reserved cost, Kovo-funded cost (including coupon allowance),
   * overage billed"). Null while a Plus account's Stripe period does not contain now.
   */
  cycle: z
    .strictObject({
      ...adminCycleSchema,
      cycle_plan: planSchema,
      /**
       * The allowance is funded by Kovo (an owner grant or a coupon), not paid. From the tier now,
       * which is the running cycle's.
       */
      allowance_kovo_funded: z.boolean(),
      totals: accountUsageTotalsSchema,
      /** Kovo-funded cost, plus the consumed allowance when Kovo funds it. */
      kovo_funded_total_usd: usdSchema,
    })
    .nullable(),
  /**
   * Revenue recorded in the window. This is attribution, not booked invoice revenue: paid
   * subscription amounts are the allowance-funding lines (`billing_adjustments`), so base-price
   * proration and credits are not netted; overage is the charge of items created in the window,
   * by the row's creation time, including items whose invoice is later voided.
   */
  revenue: z.strictObject({
    /** Paid subscription amounts that funded an allowance, recorded in the window. */
    subscription_usd: usdSchema,
    /** Overage invoice items created in the window (base × 1.20). */
    overage_charged_usd: usdSchema,
    total_usd: usdSchema,
  }),
  /**
   * Revenue minus cost in the window (negative when Kovo funds more than it is paid). Cost accrues
   * as recorded while overage is charged in batches, so a short window can mix the two timings.
   */
  margin_usd: microUsdWireSchema,
  by_repo: z
    .array(
      adminCostBreakdownSchema.extend({ repo_id: repoIdSchema, full_name: repoFullNameSchema }),
    )
    .max(ADMIN_PAGE_MAX),
  unattributed_usd: usdSchema,
});
export type AdminCustomerCosts = z.output<typeof adminCustomerCostsSchema>;

export const adminRepoCostsSchema = z.strictObject({
  ...costWindowSchema,
  repo_id: repoIdSchema,
  totals: adminCostTotalsSchema,
  /** The account's running cycle (SPEC "Per repository": "the current cycle and the last 30 days"). */
  cycle: z.strictObject({ ...adminCycleSchema, totals: adminCostBreakdownSchema }).nullable(),
  by_job: z
    .array(
      adminCostBreakdownSchema.extend({
        job_id: jobIdSchema,
        kind: jobKindSchema,
        created_at: utcDateTimeSchema,
      }),
    )
    .max(ADMIN_PAGE_MAX),
  /** Cost of this repository not tied to a job. */
  unattributed_usd: usdSchema,
});
export type AdminRepoCosts = z.output<typeof adminRepoCostsSchema>;

export const adminJobCostSchema = z.strictObject({
  job_id: jobIdSchema,
  account_id: accountIdSchema,
  repo_id: repoIdSchema.nullable(),
  /** Every ledger line of the job, however many are listed. */
  totals: adminCostBreakdownSchema,
  /**
   * The overage base × 1.20, rounded half up per job. Attribution only: the charge rounds per
   * invoice batch.
   */
  overage_billed_usd: usdSchema,
  /** More lines exist than are listed (the oldest 500 are). */
  lines_truncated: z.boolean(),
  lines: z
    .array(
      z.strictObject({
        kind: usageKindSchema,
        provider: usageProviderSchema,
        model_id: z.string().min(1).max(128).nullable(),
        quantity: z.int().nonnegative(),
        unit: usageUnitSchema,
        /** Model input and output token counts (usage, never content). */
        input_token_count: z.int().nonnegative().nullable(),
        output_token_count: z.int().nonnegative().nullable(),
        cost_usd: usdSchema,
        funding: fundingSourceSchema,
        recorded_at: utcDateTimeSchema,
      }),
    )
    .max(500),
});
export type AdminJobCost = z.output<typeof adminJobCostSchema>;

// ---- Plus coupons (SPEC "Plus coupons"; plans/admin-site.md PR 9) ----

export const ADMIN_COUPON_MODES = ["stripe", "kovo_grant"] as const;
export const adminCouponModeSchema = z.enum(ADMIN_COUPON_MODES);
export type AdminCouponMode = z.infer<typeof adminCouponModeSchema>;

/**
 * - `pending`: recorded, its Stripe coupon and promotion code not created yet (Stripe mode; a
 *   repeated create finishes it);
 * - `active`: redeemable until its redeem-by date;
 * - `revoked`: no new redemptions; existing ones keep their months.
 */
export const ADMIN_COUPON_STATES = ["pending", "active", "revoked"] as const;
export const adminCouponStateSchema = z.enum(ADMIN_COUPON_STATES);

/** The billing contract's canonical coupon code, the same schema the redemption route parses. */
export const adminCouponCodeSchema = couponCodeSchema;

export const adminCouponSchema = z.strictObject({
  code: z.string().regex(/^[A-Z0-9-]{4,32}$/),
  mode: adminCouponModeSchema,
  state: adminCouponStateSchema,
  months: z.int().min(1).max(12),
  max_redemptions: z.int().min(1).max(1000),
  /** Redemptions that count against the maximum (any not released by an abandoned Checkout). */
  redemptions: z.int().min(0).max(1000),
  redeemable_until: utcDateTimeSchema.nullable(),
  note: z.string().min(1).max(280).nullable(),
  /** The most Kovo can fund: months × maximum redemptions × the Plus base price. */
  max_kovo_funded_usd: usdSchema,
  created_at: utcDateTimeSchema,
  /** The operator identity that created it, and its `owner`/`agent:<name>` label. */
  created_by: z.string().min(1).max(200),
  requested_by: adminRequestedBySchema,
  owner_request_issue: z.int().positive().nullable(),
  revoked_at: utcDateTimeSchema.nullable(),
});
export type AdminCoupon = z.output<typeof adminCouponSchema>;

// ---- Incidents (owner, 2026-10-06: "an incidents page … it should list GCP alerts, by severity,
// and filter for open and closed"). The incident bridge's records (plans/incident-management.md
// §6): policy, severity, times and the bridge's paging state, never alert text or log content. ----

export const ADMIN_INCIDENT_LIMIT = 500;

export const adminIncidentSchema = z.strictObject({
  incident_id: incidentIdSchema,
  policy_id: incidentPolicySchema.shape.id,
  title: incidentPolicySchema.shape.title,
  runbook_anchor: incidentPolicySchema.shape.runbookAnchor,
  severity: incidentSeveritySchema,
  state: z.enum(["open", "closed"]),
  resource_type: incidentEventSchema.shape.resourceType,
  started_at: utcDateTimeSchema,
  closed_at: utcDateTimeSchema.nullable(),
  acknowledged_at: utcDateTimeSchema.nullable(),
  /** The coordinator's incident issue in the repository. */
  issue_number: z.int().positive().nullable(),
  /** Paging now, and why. */
  page_active: z.boolean(),
  page_reason: incidentPageReasonSchema.nullable(),
  escalation_cause: incidentCauseSchema.nullable(),
  last_page_at: utcDateTimeSchema.nullable(),
});
export type AdminIncident = z.output<typeof adminIncidentSchema>;

const severityCountsSchema = z.strictObject({
  CRITICAL: countSchema,
  ERROR: countSchema,
  WARNING: countSchema,
});

export const adminIncidentsSchema = z.strictObject({
  generated_at: utcDateTimeSchema,
  /**
   * The incidents read, by state: every incident not yet settled, then the most recent settled ones
   * up to the limit. When `truncated`, some incidents are not counted (older closed ones, more than
   * the limit, or records that could not be read).
   */
  counts: z.strictObject({ open: severityCountsSchema, closed: severityCountsSchema }),
  /** Most severe first, then newest; open before closed when unfiltered. */
  items: z.array(adminIncidentSchema).max(ADMIN_INCIDENT_LIMIT),
  /** Some incidents are not shown (older closed ones, beyond the limit, or unreadable records). */
  truncated: z.boolean(),
});
export type AdminIncidents = z.output<typeof adminIncidentsSchema>;

// ---- D9 grants (SPEC "Internal admin site": "Needs a justification (a 20–1000 char D9 grant, at
// most 2h)"; "Step-up: Justification + daily digest"): who holds which grant, for what and until
// when, so the owner can see and revoke them. The grant row only: never what was queried. ----

export const ADMIN_GRANT_STATES = ["open", "expired", "revoked"] as const;

export const adminGrantSchema = z.strictObject({
  id: z.uuid(),
  account_id: accountIdSchema,
  account_login: adminLoginSchema,
  repo_id: repoIdSchema.nullable(),
  repo_full_name: repoFullNameSchema.nullable(),
  /** The operator principal that holds it (a service account or an IAP user). */
  operator: z.string().min(1).max(320),
  /** The `owner`/`agent:<name>` label it was requested under (absent on early grants). */
  requested_by: adminRequestedBySchema.nullable(),
  justification: z.string().min(20).max(1000),
  state: z.enum(ADMIN_GRANT_STATES),
  created_at: utcDateTimeSchema,
  expires_at: utcDateTimeSchema,
  revoked_at: utcDateTimeSchema.nullable(),
});
export type AdminGrant = z.output<typeof adminGrantSchema>;

const requestedByQuery = { requested_by: adminRequestedBySchema };

/** Printable text without control characters (a coupon note). */
const NOTE_PATTERN = /^[\x20-\x7e]+$/;

const adminCouponCreateSchema = z
  .strictObject({
    ...requestedByQuery,
    code: adminCouponCodeSchema,
    mode: adminCouponModeSchema,
    months: z.int().min(1).max(12),
    max_redemptions: z.int().min(1).max(1000),
    /** The last instant a redemption may start. */
    redeemable_until: utcDateTimeSchema.exactOptional(),
    /** Operator context only (never customer data); at most 280 printable characters. */
    note: z.string().trim().min(1).max(280).regex(NOTE_PATTERN).exactOptional(),
    /** The owner-request issue an agent cites (SPEC: "Agent-created coupons must cite an `owner-request` issue"). */
    owner_request_issue: z.int().positive().max(1_000_000).exactOptional(),
  })
  .refine((body) => body.requested_by === "owner" || body.owner_request_issue !== undefined, {
    ...whenValid,
    error: "an agent's coupon must cite an owner-request issue",
    path: ["owner_request_issue"],
  });

export const ADMIN_ENDPOINTS = {
  getAdminOverview: defineEndpoint({
    operationId: "getAdminOverview",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/overview",
    summary: "Customer counts, protected repositories and autopilot repositories by tier.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminOverviewSchema },
    authorization: { spec: TIER_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listAdminCustomers: defineEndpoint({
    operationId: "listAdminCustomers",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/customers",
    summary: "Accounts with their tier and protection counts, by account ID, after an account.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      tier: adminTierSchema.exactOptional(),
      after: accountIdSchema.exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(50),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(adminCustomerSummarySchema).max(ADMIN_PAGE_MAX),
        /** The `after` value for the next page; null on the last page. */
        next: accountIdSchema.nullable(),
      }),
    },
    authorization: { spec: DRILL_DOWN_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminCustomer: defineEndpoint({
    operationId: "getAdminCustomer",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/customers/{account}",
    summary: "One account's billing state, pauses and every repository's protection.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ account: accountIdSchema }),
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminCustomerSchema },
    authorization: { spec: DRILL_DOWN_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  listAdminRepos: defineEndpoint({
    operationId: "listAdminRepos",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/repos",
    summary: "Repositories with their health, by repository ID, after a repository.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      health: adminRepoHealthSchema.exactOptional(),
      tier: adminTierSchema.exactOptional(),
      mode: repoModeSchema.exactOptional(),
      after: repoIdSchema.exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(50),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(adminRepoSummarySchema).max(ADMIN_PAGE_MAX),
        next: repoIdSchema.nullable(),
      }),
    },
    authorization: { spec: HEALTH_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminRepo: defineEndpoint({
    operationId: "getAdminRepo",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/repos/{repo}",
    summary: "One repository's health, protection, recipe and pull-request counts.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ repo: repoIdSchema }),
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminRepoSchema },
    authorization: { spec: HEALTH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  listAdminRepoJobs: defineEndpoint({
    operationId: "listAdminRepoJobs",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/repos/{repo}/jobs",
    summary:
      "A repository's most recent jobs: kind, status, rung, timings, reason and PR, newest first.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ repo: repoIdSchema }),
    query: z.strictObject({
      ...requestedByQuery,
      limit: z.coerce.number().int().min(1).max(100).default(20),
    }),
    body: null,
    responses: { 200: z.strictObject({ items: z.array(adminJobSchema).max(100) }) },
    authorization: { spec: HEALTH_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  searchAdmin: defineEndpoint({
    operationId: "searchAdmin",
    area: "operator",
    method: "POST",
    // The search text travels in the body: load balancer request logs record query strings.
    path: "/v1/operator/admin/search",
    summary: "Customers by login and repositories by name that contain the search text.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: null,
    body: z.strictObject({
      ...requestedByQuery,
      q: z
        .string()
        .trim()
        .min(2)
        .max(100)
        .regex(/^[A-Za-z0-9._/-]+$/, { error: "letters, digits, '.', '_', '-' and '/' only" }),
    }),
    responses: { 200: adminSearchResultSchema },
    authorization: { spec: DRILL_DOWN_SPEC, actors: ["operator"], tenant: "none" },
  }),
  listAdminAudit: defineEndpoint({
    operationId: "listAdminAudit",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/audit",
    summary:
      "Admin reads and actions since an instant, newest first: who, label, action, scope and rows.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      since: utcDateTimeSchema,
      /** The `next` of the previous page (an audit row ID); rows before it, newest first. */
      before: z.uuid().exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(100),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(adminAuditEntrySchema).max(ADMIN_PAGE_MAX),
        next: z.uuid().nullable(),
      }),
    },
    authorization: { spec: AUDIT_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminCosts: defineEndpoint({
    operationId: "getAdminCosts",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/costs",
    summary: "Actual model and sandbox cost in a window, in total and grouped.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      ...costWindowQuery,
      group_by: adminCostGroupSchema.default("day"),
      limit: z.coerce.number().int().min(1).max(400).default(50),
    }),
    body: null,
    responses: { 200: adminCostsSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminCustomerCosts: defineEndpoint({
    operationId: "getAdminCustomerCosts",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/customers/{account}/costs",
    summary: "One account's cost, revenue and margin in a window, by repository.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ account: accountIdSchema }),
    query: z.strictObject({ ...requestedByQuery, ...costWindowQuery }),
    body: null,
    responses: { 200: adminCustomerCostsSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  getAdminRepoCosts: defineEndpoint({
    operationId: "getAdminRepoCosts",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/repos/{repo}/costs",
    summary: "One repository's cost in a window, by job.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ repo: repoIdSchema }),
    query: z.strictObject({ ...requestedByQuery, ...costWindowQuery }),
    body: null,
    responses: { 200: adminRepoCostsSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  getAdminJobCost: defineEndpoint({
    operationId: "getAdminJobCost",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/jobs/{job}/cost",
    summary: "One job's ledger lines: kind, provider, model, quantity, cost and funding.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ job: jobIdSchema }),
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminJobCostSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  listAdminIncidents: defineEndpoint({
    operationId: "listAdminIncidents",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/incidents",
    summary:
      "Production alert incidents by severity, open or closed, as the incident bridge holds them.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      state: z.enum(["open", "closed"]).exactOptional(),
      severity: incidentSeveritySchema.exactOptional(),
    }),
    body: null,
    responses: { 200: adminIncidentsSchema },
    authorization: { spec: INCIDENTS_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["upstream_error"],
  }),
  listAdminGrants: defineEndpoint({
    operationId: "listAdminGrants",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/grants",
    summary:
      "D9 diagnostic grants, newest first: open ones only, or every one of the last 30 days.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      open: z.enum(["true", "false"]).default("true"),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(100),
    }),
    body: null,
    responses: { 200: z.strictObject({ items: z.array(adminGrantSchema).max(ADMIN_PAGE_MAX) }) },
    authorization: { spec: GRANTS_SPEC, actors: ["operator"], tenant: "none" },
  }),
  createAdminCoupon: defineEndpoint({
    operationId: "createAdminCoupon",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/coupons",
    summary:
      "Create a Plus coupon by its code; repeating the same coupon returns it (and finishes its Stripe objects).",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    auditStorage: "admin_audit",
    params: null,
    query: null,
    body: adminCouponCreateSchema,
    responses: { 200: adminCouponSchema, 201: adminCouponSchema },
    authorization: { spec: COUPON_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["conflict", "upstream_error", "validation_failed"],
  }),
  listAdminCoupons: defineEndpoint({
    operationId: "listAdminCoupons",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/coupons",
    summary: "Coupons, newest first, with their state and maximum Kovo-funded cost.",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      state: adminCouponStateSchema.exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(50),
    }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z.array(adminCouponSchema).max(ADMIN_PAGE_MAX),
        /** More coupons match than were listed. */
        truncated: z.boolean(),
      }),
    },
    authorization: { spec: COUPON_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminCoupon: defineEndpoint({
    operationId: "getAdminCoupon",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/coupons/{code}",
    summary: "One coupon by its code (case-insensitive).",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    auditStorage: "admin_audit",
    params: z.strictObject({ code: adminCouponCodeSchema }),
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminCouponSchema },
    authorization: { spec: COUPON_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  revokeAdminCoupon: defineEndpoint({
    operationId: "revokeAdminCoupon",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/coupons/{code}/revoke",
    summary:
      "Stop new redemptions of a coupon (its Stripe promotion code is deactivated); idempotent.",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    auditStorage: "admin_audit",
    params: z.strictObject({ code: adminCouponCodeSchema }),
    query: null,
    body: z.strictObject(requestedByQuery),
    responses: { 200: adminCouponSchema },
    authorization: { spec: COUPON_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found", "upstream_error"],
  }),
} as const;

// ---- The internal admin site's channel ----

/**
 * The header the admin site's server forwards a user's IAP assertion in (with its own service
 * account's ID token as the bearer): the API's `admin_ui` channel (SPEC "Internal admin site").
 */
export const ADMIN_UI_ASSERTION_HEADER = "kovo-iap-assertion";

/**
 * The API routes the `admin_ui` channel may call, under `/v1`; every other operator route stays
 * CLI-only. The API refuses the channel elsewhere, and the admin server forwards nothing else.
 */
export const ADMIN_UI_PATHS: readonly RegExp[] = [
  /^\/v1\/operator\/admin(?:\/|$)/,
  /^\/v1\/operator\/diagnostic-grants(?:\/|$)/,
  /^\/v1\/operator\/diagnostics\/[a-z_]+$/,
  /^\/v1\/operator\/repos\/[0-9a-f-]{36}\/timeline$/,
];

/** Whether the `admin_ui` channel may call an API path (the API's own, under `/v1`). */
export function adminUiMayCall(pathname: string): boolean {
  return ADMIN_UI_PATHS.some((pattern) => pattern.test(pathname));
}
