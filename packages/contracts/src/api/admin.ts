import { z } from "zod";

import {
  BILLING_EXCEPTION_REASONS,
  BILLING_EXCEPTION_SUBJECT_TYPES,
  billingExceptionIdSchema,
} from "../billing-exceptions.js";
import { diagnosticRequestedBySchema } from "../diagnostics.js";
import {
  incidentCauseSchema,
  incidentEventSchema,
  incidentIdSchema,
  incidentPageReasonSchema,
  incidentPolicySchema,
  incidentSeveritySchema,
  runbookAnchorSchema,
} from "../incidents.js";
import { accountTypeSchema, planSchema } from "../enums/accounts.js";
import {
  INVOICE_STATUSES,
  SUBSCRIPTION_STATUSES,
  billingAdjustmentReasonSchema,
  capacityQuoteStateSchema,
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
  projectIdSchema,
  pullRequestNumberSchema,
  quoteIdSchema,
  relayGrantIdSchema,
  repoIdSchema,
  reservationIdSchema,
  stripeInvoiceIdSchema,
  stripeInvoiceLineIdSchema,
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
const REPO_PAUSE_SPEC = "Operators pause and resume one repository's processing through the";

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
  "admin.account.deactivate",
  "admin.account.reactivate",
  "admin.overview.read",
  // The four fleet-wide counts M11b is gated on (#5500, `m11b-preconditions.ts`).
  "admin.m11b_preconditions.read",
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
  // A staff or agent run-record grant's metadata-only list (`run-records/staff.ts`).
  "admin.run_records.staff_list",
  // Outreach (SPEC "Internal admin site", "Outreach"; `outreach-admin.ts`).
  "admin.outreach.list",
  "admin.outreach.read",
  "admin.outreach.stage",
  "admin.outreach.assign",
  "admin.outreach.tag",
  "admin.outreach.note",
  "admin.outreach.views",
  "admin.outreach.view_save",
  "admin.outreach.view_delete",
  "admin.outreach.export",
  // The production-verification channel (`prod-verification.ts`); account status changes record
  // `admin.account.deactivate`/`reactivate` with channel `prod_verification`.
  "admin.verification.gate_read",
  "admin.verification.codes_list",
  "admin.verification.code_create",
  "admin.verification.code_revoke",
  "admin.verification.notifications_read",
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

/**
 * `unlimited_projects` (D-437, #6043) marks a Kovo-grant coupon's unlimited included projects, so
 * the admin site shows "unlimited" instead of `slots`. Absent means finite.
 */
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
  unlimited_projects: z.literal(true).exactOptional(),
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
  /** Private note; never part of the ordinary account response. Reader first (#2779). */
  deactivation: z
    .strictObject({
      at: utcDateTimeSchema,
      by: z.uuid(),
      reason: z.string().min(1).max(1000),
    })
    .nullable()
    .exactOptional(),
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
  metadata: z
    .strictObject({
      owner_id: z.int().positive(),
      installation_owner_id: z.int().positive(),
      installation_id: z.int().positive(),
      installation_state: z.enum(["active", "suspended", "deleted"]),
    })
    .exactOptional(),
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

/**
 * The channels an `admin_audit` row records (`admin_audit_channel_enum` CHECK): the `kovo-admin`
 * CLI, the IAP-gated admin site, and `prod_verification`, the bounded production-verification
 * operator (plans/kovo-tests-prod-verification.md, owner D-351 option E). This reader accepts
 * `prod_verification` before any writer emits it, so every promoted reader tolerates the value
 * first (AGENTS.md "Ship enabled by default"); unknown channels still refuse.
 */
export const ADMIN_AUDIT_CHANNELS = ["cli", "admin_ui", "prod_verification"] as const;
export const adminAuditChannelSchema = z.enum(ADMIN_AUDIT_CHANNELS);
export type AdminAuditChannel = z.output<typeof adminAuditChannelSchema>;

export const adminAuditEntrySchema = z.strictObject({
  at: utcDateTimeSchema,
  operator: z.string().min(1).max(320),
  channel: adminAuditChannelSchema,
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
   * subscription amounts are the allowance-funding lines (`billing_adjustments`, plus, once project
   * billing is active, the observed amount of each post-boundary extra-project line that funded
   * `billing_project_funding_adjustments`), so base-price proration and credits are not netted;
   * overage is the charge of items created in the window,
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

/** The most extra repositories a Kovo-grant coupon adds (D-424), as for a config grant. */
export const ADMIN_COUPON_EXTRA_REPO_SLOTS_MAX = 50;

/** The largest Kovo-funded monthly allowance a Kovo-grant coupon sets (D-437): $1,000 in micro-USD. */
export const ADMIN_COUPON_MONTHLY_ALLOWANCE_MAX = 1_000_000_000n;

/** The largest raised per-account daily AI call cap a Kovo-grant coupon sets (D-437). */
export const ADMIN_COUPON_AI_DAILY_CALLS_MAX = 100_000;

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
  /**
   * Kovo-funded extra repositories each redemption's grant adds (D-424; Kovo-grant mode). Present
   * only when the coupon sets some, so a release that predates the field still reads other coupons.
   */
  extra_repo_slots: z.int().min(1).max(ADMIN_COUPON_EXTRA_REPO_SLOTS_MAX).exactOptional(),
  // D-437 Kovo-grant fields, each present only when the coupon sets it (as `extra_repo_slots`).
  /** Kovo-funded monthly AI allowance that replaces the Plus base for each grant; never invoiced. */
  monthly_allowance_usd: usdSchema.exactOptional(),
  /** Each grant has unlimited included projects. */
  unlimited_projects: z.literal(true).exactOptional(),
  /** Each grant raises the per-account daily AI call cap to at least this. */
  ai_daily_calls_per_account: z.int().min(1).max(ADMIN_COUPON_AI_DAILY_CALLS_MAX).exactOptional(),
  /** Each grant removes the per-account daily AI call cap (global caps still apply). */
  ai_daily_calls_unlimited: z.literal(true).exactOptional(),
  /** An existing account may redeem once, including one with an owner grant. */
  existing_accounts_allowed: z.literal(true).exactOptional(),
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
  // Required: only an alert policy may omit its anchor (report_only); an admin incident always
  // carries one.
  runbook_anchor: runbookAnchorSchema,
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

/**
 * The subject IDs billing detectors store: a Kovo UUID or a Stripe object ID (`in_…`, `sub_…`,
 * `cus_…`, `ii_…`, `evt_…`). The read withholds any other stored value instead of echoing it.
 */
export const ADMIN_BILLING_EXCEPTION_SUBJECT_ID =
  /^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[a-z]{2,8}_[A-Za-z0-9_]{1,250})$/;

/**
 * One advisory `billing_exceptions` row (SPEC "Billing incident metadata"): IDs, a fixed reason
 * code, the subject's type and Kovo or Stripe ID, counts and times. Never a receivable or charge
 * authority; the table holds no amount, name or content. A stored reason this release does not
 * know reads as `unknown_reason`.
 */
export const adminBillingExceptionSchema = z.strictObject({
  id: billingExceptionIdSchema,
  account_id: accountIdSchema.nullable(),
  reason: z.enum([...BILLING_EXCEPTION_REASONS, "unknown_reason"] as const),
  subject_type: z.enum(BILLING_EXCEPTION_SUBJECT_TYPES).nullable(),
  subject_id: z.string().regex(ADMIN_BILLING_EXCEPTION_SUBJECT_ID).nullable(),
  first_seen_at: utcDateTimeSchema,
  last_seen_at: utcDateTimeSchema,
  occurrences: z.number().int().min(1).max(2_147_483_647),
});
export type AdminBillingException = z.output<typeof adminBillingExceptionSchema>;

export const adminBillingExceptionsSchema = z.strictObject({
  /** Most recently seen first. */
  items: z.array(adminBillingExceptionSchema).max(ADMIN_PAGE_MAX),
  /** More rows matched than `limit`. */
  truncated: z.boolean(),
});
export type AdminBillingExceptions = z.output<typeof adminBillingExceptionsSchema>;

/**
 * The provider charge IDs the unreported-charges read echoes: OpenRouter generation IDs, sandbox
 * IDs and Kovo snapshot charge keys. The read withholds any other stored value instead of echoing it.
 */
export const ADMIN_PROVIDER_CHARGE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$/;

/** The default and widest window of the unreported-charges read, in days. */
export const ADMIN_UNREPORTED_CHARGES_DEFAULT_DAYS = 7;
export const ADMIN_UNREPORTED_CHARGES_MAX_DAYS = 90;

/**
 * One provider charge written off unreported (`kovo.billing.unreported_charges`; docs/decisions/
 * usage.md): a pending charge resolved past the reporting deadline with no ledger entry under its
 * key, so it was never billed. IDs, the usage kind and provider, and times only; never an amount.
 */
export const adminUnreportedChargeSchema = z.strictObject({
  account_id: accountIdSchema,
  cycle_id: cycleIdSchema,
  reservation_id: reservationIdSchema,
  kind: usageKindSchema,
  provider: usageProviderSchema,
  provider_charge_id: z.string().regex(ADMIN_PROVIDER_CHARGE_ID).nullable(),
  observed_at: utcDateTimeSchema,
  written_off_at: utcDateTimeSchema,
});
export type AdminUnreportedCharge = z.output<typeof adminUnreportedChargeSchema>;

/**
 * Model requests the relay admitted and never settled on a reservation that has since closed: the
 * relay-lost part of `kovo.billing.unreported_charges{usage_kind=model}` (docs/decisions/ai.md).
 */
export const adminLostRelayRequestsSchema = z.strictObject({
  account_id: accountIdSchema,
  cycle_id: cycleIdSchema,
  reservation_id: reservationIdSchema,
  relay_grant_id: relayGrantIdSchema,
  requests: z.number().int().min(1).max(2_147_483_647),
  lost_at: utcDateTimeSchema,
  settled_at: utcDateTimeSchema,
});
export type AdminLostRelayRequests = z.output<typeof adminLostRelayRequestsSchema>;

export const adminBillingUnreportedChargesSchema = z.strictObject({
  /** Most recently written off first. */
  charges: z.array(adminUnreportedChargeSchema).max(ADMIN_PAGE_MAX),
  /** Most recently settled first. */
  lost_requests: z.array(adminLostRelayRequestsSchema).max(ADMIN_PAGE_MAX),
  /** More rows of either list matched than `limit`. */
  truncated: z.boolean(),
});
export type AdminBillingUnreportedCharges = z.output<typeof adminBillingUnreportedChargesSchema>;

/** Kovo billing items one Stripe status read covers before it reports `truncated`. */
export const ADMIN_STRIPE_STATUS_MAX_ITEMS = 50;

/** The Stripe object types the Stripe status read looks up. */
export const ADMIN_STRIPE_OBJECT_TYPES = ["invoice_item", "invoice", "subscription"] as const;

/**
 * Provider statuses the Stripe status read reports: Stripe's invoice and subscription statuses,
 * and an invoice item's `pending` (no invoice yet) or `invoiced` (Stripe gives items no status).
 */
export const ADMIN_STRIPE_OBJECT_STATUSES = [
  "pending",
  "invoiced",
  ...INVOICE_STATUSES,
  ...SUBSCRIPTION_STATUSES,
] as const;

/** The Kovo records whose Stripe objects the read looks up. */
export const ADMIN_STRIPE_STATUS_ITEM_KINDS = [
  "usage_reservation",
  "overage_invoice_item",
  "account_subscription",
] as const;

/**
 * Why a row carries no provider status: Kovo recorded no Stripe object for the item, Stripe has
 * no such object, or the lookup failed (the existing key lacks a permission, Stripe throttled the
 * read, or anything else: `stripe_status_lookup_failed`). Reason codes only, never vendor text.
 */
export const ADMIN_STRIPE_STATUS_REASONS = [
  "stripe_object_not_recorded",
  "stripe_object_not_found",
  "stripe_permission_denied",
  "stripe_rate_limited",
  "stripe_status_lookup_failed",
] as const;

/**
 * One Stripe object a Kovo billing item recorded, with its live provider status (#7123): Kovo and
 * Stripe IDs, the status, the amount in micro-USD, currency, created and updated times and
 * livemode only. Never a name, email, address, description or payment-instrument detail.
 */
export const adminStripeStatusRowSchema = z.strictObject({
  /** The Kovo billing item: a usage reservation, an overage invoice item, or the account. */
  item_id: z.uuid(),
  item_kind: z.enum(ADMIN_STRIPE_STATUS_ITEM_KINDS),
  account_id: accountIdSchema,
  /** `found` carries the provider fields; every other outcome has them null and a reason. */
  outcome: z.enum(["found", "not_recorded", "not_found", "lookup_failed"]),
  reason_code: z.enum(ADMIN_STRIPE_STATUS_REASONS).nullable(),
  /** Null only when Kovo recorded no Stripe object. */
  stripe_object_type: z.enum(ADMIN_STRIPE_OBJECT_TYPES).nullable(),
  stripe_object_id: z
    .string()
    .regex(/^(ii|in|sub)_[A-Za-z0-9_]{1,200}$/)
    .nullable(),
  status: z.enum(ADMIN_STRIPE_OBJECT_STATUSES).nullable(),
  amount_usd: microUsdWireSchema.nullable(),
  currency: z
    .string()
    .regex(/^[a-z]{3}$/)
    .nullable(),
  created_at: utcDateTimeSchema.nullable(),
  updated_at: utcDateTimeSchema.nullable(),
  livemode: z.boolean().nullable(),
});
export type AdminStripeStatusRow = z.output<typeof adminStripeStatusRowSchema>;

export const adminBillingStripeStatusSchema = z.strictObject({
  /**
   * In item order: an overage item's invoice item, then the invoice that collected it; an
   * account's subscription.
   */
  items: z.array(adminStripeStatusRowSchema).max(ADMIN_STRIPE_STATUS_MAX_ITEMS * 2),
  /** More Kovo items matched than the read covers. */
  truncated: z.boolean(),
});
export type AdminBillingStripeStatus = z.output<typeof adminBillingStripeStatusSchema>;

/** Rows one project billing read returns per list before it reports `truncated`. */
export const ADMIN_PROJECT_BILLING_MAX = 1000;
const adminCountSchema = z.number().int().min(0).max(2_147_483_647);

/**
 * One account's project billing metadata for the M12 production drill (#2135; D-217 customer
 * metadata keyed by ID): per-project protection state, slot counts, the latest capacity quote, the
 * running cycle's allowance and the signed project funding ledger. IDs, counts, codes, Stripe
 * object IDs, micro-USD amounts and UTC times only: never a project path, repository or account
 * name, email, payment instrument or customer content.
 */
export const adminProjectBillingSchema = z.strictObject({
  account_id: accountIdSchema,
  plan: planSchema,
  project_billing_activated_at: utcDateTimeSchema.nullable(),
  /** The capacity rules' inputs, as `GET /v1/billing` derives them. */
  slots: z.strictObject({
    /** The plan's own included projects. */
    included: adminCountSchema,
    /** Extra included projects an owner or coupon grant adds. */
    granted: adminCountSchema,
    /** Paid extra slots in the current period. */
    paid: adminCountSchema,
    next_period_paid: adminCountSchema,
    protected: adminCountSchema,
    pending_requests: adminCountSchema,
    /** A Kovo-grant coupon's unlimited included projects (D-437). */
    unlimited: z.boolean(),
  }),
  /** Live (not tombstoned) projects, by project ID. */
  projects: z
    .array(
      z.strictObject({
        project_id: projectIdSchema,
        repo_id: repoIdSchema,
        state: z.enum(["protected", "pending", "unprotected"]),
        enabled_at: utcDateTimeSchema.nullable(),
        disabled_at: utcDateTimeSchema.nullable(),
        requested_at: utcDateTimeSchema.nullable(),
      }),
    )
    .max(ADMIN_PROJECT_BILLING_MAX),
  projects_truncated: z.boolean(),
  latest_quote: z
    .strictObject({
      id: quoteIdSchema,
      state: capacityQuoteStateSchema,
      additional_slots: adminCountSchema,
      extra_slots: adminCountSchema,
      amount_usd: nonNegativeMicroUsdWireSchema,
      stripe_invoice_id: stripeInvoiceIdSchema.nullable(),
      created_at: utcDateTimeSchema,
      confirmed_at: utcDateTimeSchema.nullable(),
      settled_at: utcDateTimeSchema.nullable(),
    })
    .nullable(),
  /** The cycle containing the read time; null when none does. */
  cycle: z
    .strictObject({
      id: cycleIdSchema,
      starts_at: utcDateTimeSchema,
      ends_at: utcDateTimeSchema,
      finalized_at: utcDateTimeSchema.nullable(),
      /** The 1x ledger (`billing_adjustments`). */
      adjustments_usd: nonNegativeMicroUsdWireSchema,
      /** The signed M10b project ledger, counted only once project billing is active. */
      project_funding_usd: microUsdWireSchema,
      /** The cycle's included-cost allowance: both ledgers, as usage and notices read it. */
      allowance_usd: microUsdWireSchema,
      owner_grant_allowance_usd: nonNegativeMicroUsdWireSchema.nullable(),
    })
    .nullable(),
  /** Every `billing_project_funding_adjustments` row of the account, newest first. */
  funding_adjustments: z
    .array(
      z.strictObject({
        /** The Stripe invoice line the row's unique `line:<id>` key names. */
        stripe_line_id: stripeInvoiceLineIdSchema,
        cycle_id: cycleIdSchema,
        stripe_invoice_id: stripeInvoiceIdSchema,
        amount_usd: microUsdWireSchema,
        reason: billingAdjustmentReasonSchema,
        recorded_at: utcDateTimeSchema,
      }),
    )
    .max(ADMIN_PROJECT_BILLING_MAX),
  funding_adjustments_truncated: z.boolean(),
});
export type AdminProjectBilling = z.output<typeof adminProjectBillingSchema>;

/**
 * The four production counts M11b (stop writing the derived `repos` protection columns) is gated
 * on (#5500, plans/monorepo-projects.md §9 "M11 Cleanup"): fleet-wide aggregate metadata only,
 * never an ID, name, path or per-account row. M11b proceeds only when all four are zero.
 */
export const adminM11bPreconditionsSchema = z.strictObject({
  /** Live (not deleted) accounts whose `project_billing_activated_at` is null. */
  unactivated_live_accounts: adminCountSchema,
  /** Repositories in their no-charge selection grace (`project_selection_due_at` set). */
  selection_due_repos: adminCountSchema,
  /** Protected or requested repositories of activated accounts held at repository level. */
  no_project_protected_repos: adminCountSchema,
  /** Repositories whose stored derived protection disagrees with their `project_protection` rows. */
  derived_protection_mismatch_repos: adminCountSchema,
  read_at: utcDateTimeSchema,
});
export type AdminM11bPreconditions = z.output<typeof adminM11bPreconditionsSchema>;

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
    /**
     * Kovo-funded extra repositories each redemption's grant adds, 0 to 50 like a config grant's
     * `extraRepoSlots` (D-424). Kovo-grant mode only; absent or 0 adds none.
     */
    extra_repo_slots: z.int().min(0).max(ADMIN_COUPON_EXTRA_REPO_SLOTS_MAX).exactOptional(),
    /**
     * D-437 Kovo-grant fields (Kovo-grant mode only; absent keeps today's behaviour): a monthly
     * Kovo-funded allowance from $0.000001 to $1,000 replacing the Plus base, unlimited projects
     * (not with extra repositories), a raised or a removed per-account daily AI call cap (not
     * both) and existing-account redemption. `false` is the same as absent.
     */
    monthly_allowance_usd: usdSchema.exactOptional(),
    unlimited_projects: z.boolean().exactOptional(),
    ai_daily_calls_per_account: z.int().min(1).max(ADMIN_COUPON_AI_DAILY_CALLS_MAX).exactOptional(),
    ai_daily_calls_unlimited: z.boolean().exactOptional(),
    existing_accounts_allowed: z.boolean().exactOptional(),
  })
  .refine(
    (body) =>
      body.monthly_allowance_usd === undefined ||
      (body.monthly_allowance_usd >= 1n &&
        body.monthly_allowance_usd <= ADMIN_COUPON_MONTHLY_ALLOWANCE_MAX),
    {
      ...whenValid,
      error: "a coupon's monthly allowance is more than $0 and at most $1,000",
      path: ["monthly_allowance_usd"],
    },
  )
  .refine(
    (body) =>
      body.mode === "kovo_grant" ||
      (body.monthly_allowance_usd === undefined &&
        body.unlimited_projects !== true &&
        body.ai_daily_calls_per_account === undefined &&
        body.ai_daily_calls_unlimited !== true &&
        body.existing_accounts_allowed !== true),
    {
      ...whenValid,
      error:
        "only a Kovo-grant coupon can set an allowance, projects, AI limits or existing accounts",
      path: ["mode"],
    },
  )
  .refine(
    (body) =>
      body.unlimited_projects !== true ||
      body.extra_repo_slots === undefined ||
      body.extra_repo_slots === 0,
    {
      ...whenValid,
      error: "unlimited projects replace extra repositories",
      path: ["unlimited_projects"],
    },
  )
  .refine(
    (body) =>
      body.ai_daily_calls_unlimited !== true || body.ai_daily_calls_per_account === undefined,
    {
      ...whenValid,
      error: "set a raised daily AI call cap or remove it, not both",
      path: ["ai_daily_calls_unlimited"],
    },
  )
  .refine((body) => body.requested_by === "owner" || body.owner_request_issue !== undefined, {
    ...whenValid,
    error: "an agent's coupon must cite an owner-request issue",
    path: ["owner_request_issue"],
  })
  .refine(
    (body) =>
      body.mode === "kovo_grant" ||
      body.extra_repo_slots === undefined ||
      body.extra_repo_slots === 0,
    {
      ...whenValid,
      error: "only a Kovo-grant coupon can add extra repositories",
      path: ["extra_repo_slots"],
    },
  );

// ---- Repository processing pause (SPEC "Internal admin site", "Repository processing pause";
// `kovo-admin repos pause|resume`): an operator OFF override of the `worker.repoProcessingEnabled`
// kill switch at the repository's scope, written and audited by the flag service
// (`flag_override_audit`, with an FYI to the owner). Kovo-owned repositories are open to every
// operator; a customer's needs a verified human operator. ----

/** Operator context for the pause: metadata only, one line, never customer content. */
export const adminRepoPauseReasonSchema = z
  .string()
  .trim()
  .min(10)
  .max(400)
  .regex(/^[\x20-\x7e]+$/, { error: "printable characters on one line only" });

export const adminRepoProcessingSchema = z.strictObject({
  repo_id: repoIdSchema,
  account_id: accountIdSchema,
  /** The account and installation belong to one of Kovo's own GitHub owners. */
  kovo_owned: z.boolean(),
  /** New repository workflow starts are held. */
  paused: z.boolean(),
  /** The active pause; null when the repository is not paused. */
  hold: z
    .strictObject({
      /** The operator grant that set it. */
      operator: z.uuid(),
      incident_issue: z.int().positive().nullable(),
      created_at: utcDateTimeSchema,
      expires_at: utcDateTimeSchema,
    })
    .nullable(),
});
export type AdminRepoProcessing = z.output<typeof adminRepoProcessingSchema>;

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
  deactivateAdminAccount: defineEndpoint({
    operationId: "deactivateAdminAccount",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/customers/{account}/deactivate",
    summary: "Turn off an account and email its verified owners, preserving consent and data.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditStorage: "admin_audit",
    params: z.strictObject({ account: accountIdSchema }),
    query: null,
    body: z.strictObject({ ...requestedByQuery, reason: z.string().trim().min(1).max(1000) }),
    responses: {
      200: z.strictObject({
        account_id: accountIdSchema,
        deactivated_at: utcDateTimeSchema.nullable(),
      }),
    },
    authorization: {
      spec: "Human administrators may deactivate or reactivate an account through the internal admin portal.",
      actors: ["operator"],
      tenant: "none",
    },
    problems: ["not_found", "account_already_deactivated", "validation_failed"],
  }),
  reactivateAdminAccount: defineEndpoint({
    operationId: "reactivateAdminAccount",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/customers/{account}/reactivate",
    summary: "Resume an account, optionally emailing its verified owners.",
    source: { kind: "spec_implied", section: "Accounts and permissions" },
    auditStorage: "admin_audit",
    params: z.strictObject({ account: accountIdSchema }),
    query: null,
    body: z.strictObject({
      ...requestedByQuery,
      reason: z.string().trim().min(1).max(1000),
      send_email: z.boolean(),
    }),
    responses: {
      200: z.strictObject({
        account_id: accountIdSchema,
        deactivated_at: utcDateTimeSchema.nullable(),
      }),
    },
    authorization: {
      spec: "Human administrators may deactivate or reactivate an account through the internal admin portal.",
      actors: ["operator"],
      tenant: "none",
    },
    problems: ["not_found", "account_not_deactivated", "validation_failed"],
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
    query: z.strictObject({
      ...requestedByQuery,
      metadata_only: z.literal("true").exactOptional(),
    }),
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
  getAdminBillingUncertain: defineEndpoint({
    operationId: "getAdminBillingUncertain",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/billing-uncertain",
    summary: "Uncertain billing metadata only, with no provider calls or customer content.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({ ...requestedByQuery }),
    body: null,
    responses: {
      200: z.strictObject({
        items: z
          .array(
            z.strictObject({
              id: z.uuid(),
              account_id: accountIdSchema,
              repo_id: repoIdSchema.nullable(),
              state: z.literal("uncertain"),
              age_seconds: z.number().int().nonnegative().safe(),
              reason_code: z.enum(["usage_cost_unreconciled", "stripe_item_unconfirmed"]),
              idempotency: z.null(),
              idempotency_root: z
                .string()
                .regex(/^kovo:overage-item:[A-Za-z0-9_:.-]{1,200}$/)
                .nullable(),
              stripe_object_id: z
                .string()
                .regex(/^ii_[A-Za-z0-9_]{1,200}$/)
                .nullable(),
            }),
          )
          .max(1000),
        stripe_status: z.literal("unavailable_no_reviewed_service_path"),
      }),
    },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminProjectBilling: defineEndpoint({
    operationId: "getAdminProjectBilling",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/customers/{account}/project-billing",
    summary:
      "One account's project billing metadata: protection, slots, quote, allowance and funding rows.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: z.strictObject({ account: accountIdSchema }),
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminProjectBillingSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["not_found"],
  }),
  getAdminM11bPreconditions: defineEndpoint({
    operationId: "getAdminM11bPreconditions",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/m11b-preconditions",
    summary: "Four fleet-wide counts that gate M11b, plus the read time: no IDs, names or rows.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject(requestedByQuery),
    body: null,
    responses: { 200: adminM11bPreconditionsSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminBillingExceptions: defineEndpoint({
    operationId: "getAdminBillingExceptions",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/billing-exceptions",
    summary:
      "Advisory billing exception rows: IDs, reason codes, Stripe object IDs, counts and times only.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      /** One tenant's rows; the audit row records that account. */
      account_id: accountIdSchema.exactOptional(),
      reason: z.enum(BILLING_EXCEPTION_REASONS).exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(100),
    }),
    body: null,
    responses: { 200: adminBillingExceptionsSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminBillingUnreportedCharges: defineEndpoint({
    operationId: "getAdminBillingUnreportedCharges",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/billing-unreported-charges",
    summary:
      "Charges written off unreported and lost relay requests: IDs, kinds, counts and times only.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      /** One tenant's rows; the audit row records that account. */
      account_id: accountIdSchema.exactOptional(),
      /** Write-offs and settles at or after it; the last seven days when absent, at most 90. */
      since: utcDateTimeSchema.exactOptional(),
      limit: z.coerce.number().int().min(1).max(ADMIN_PAGE_MAX).default(100),
    }),
    body: null,
    responses: { 200: adminBillingUnreportedChargesSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
  }),
  getAdminBillingStripeStatus: defineEndpoint({
    operationId: "getAdminBillingStripeStatus",
    area: "operator",
    method: "GET",
    path: "/v1/operator/admin/billing-stripe-status",
    summary:
      "Live Stripe status of the objects Kovo billing items recorded: IDs, statuses, amounts and times only.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "admin_audit",
    params: null,
    query: z.strictObject({
      ...requestedByQuery,
      /**
       * One Kovo billing item (a usage reservation or an overage invoice item). Without it and
       * without `account_id`, every uncertain item (the billing-uncertain set).
       */
      item_id: z.uuid().exactOptional(),
      /**
       * One tenant: its subscription and its overage invoice items, newest first; with `item_id`,
       * an item of another account is not found. The audit row records the account.
       */
      account_id: accountIdSchema.exactOptional(),
    }),
    body: null,
    responses: { 200: adminBillingStripeStatusSchema },
    authorization: { spec: COST_SPEC, actors: ["operator"], tenant: "none" },
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
  pauseAdminRepoProcessing: defineEndpoint({
    operationId: "pauseAdminRepoProcessing",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/repos/{repo}/pause",
    summary:
      "Hold one repository's new dependency-gate, inventory, recipe and fix workflow starts until resumed or expired.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "flag_override_audit",
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: z.strictObject({
      ...requestedByQuery,
      reason: adminRepoPauseReasonSchema,
      incident_issue: z.int().positive().max(2147483647).exactOptional(),
      /** When the pause lifts by itself (default 72 hours; at most 7 days for agents, 30 for people). */
      expires_at: utcDateTimeSchema.exactOptional(),
    }),
    responses: { 200: adminRepoProcessingSchema },
    authorization: { spec: REPO_PAUSE_SPEC, actors: ["operator"], tenant: "none" },
    problems: [
      "human_approval_required",
      "not_found",
      "validation_failed",
      "conflict",
      "repo_paused",
    ],
  }),
  resumeAdminRepoProcessing: defineEndpoint({
    operationId: "resumeAdminRepoProcessing",
    area: "operator",
    method: "POST",
    path: "/v1/operator/admin/repos/{repo}/resume",
    summary: "Release one repository's held workflow starts by clearing its pause.",
    source: { kind: "spec_implied", section: "Operations, analytics, and deployment" },
    auditStorage: "flag_override_audit",
    params: z.strictObject({ repo: repoIdSchema }),
    query: null,
    body: z.strictObject({ ...requestedByQuery, reason: adminRepoPauseReasonSchema }),
    responses: { 200: adminRepoProcessingSchema },
    authorization: { spec: REPO_PAUSE_SPEC, actors: ["operator"], tenant: "none" },
    problems: ["human_approval_required", "not_found", "validation_failed", "conflict"],
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
