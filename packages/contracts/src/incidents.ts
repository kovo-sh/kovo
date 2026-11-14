import { z } from "zod";

import { SERVICE_LEVEL_OBJECTIVES, sloIdSchema, sloPolicyIds } from "./slos.js";

export * from "./slos.js";

// Operational metadata only (plans/incident-management.md §6). Raw Monitoring messages never
// become state, task bodies, diagnostics or paging metrics.
export const incidentIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
export const incidentSeveritySchema = z.enum(["CRITICAL", "ERROR", "WARNING"]);
export const incidentCauseSchema = z.enum([
  "owner_decision_required",
  "mitigation_failed",
  "outside_runbook",
  "customer_impact",
]);
export const incidentPageReasonSchema = z.enum([
  "always_page",
  "unacked",
  "unresolved",
  "coordinator_escalated",
]);
/**
 * Owner D-776 alert tiers (source: https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6817034658,
 * tiering on #9024), on every alerts.json policy and every EXTERNAL_ALERT_TIERS entry:
 * - `must_page`: always pages and never demotes (unexpected data access, billing correctness,
 *   global pause; tenancy: `tenancy-cross-account`, #9024 B);
 * - `paging_until_slo`: pages as today until an SLO with a drill covers the same failure;
 * - `wakes_agent`: opens or attaches an incident for the agent lane and keeps the unacknowledged /
 *   unresolved / escalated backstop (D-778);
 * - `report_only`: never pages (owner D-778, ALERT-BACKSTOP a); the incident and its metric are
 *   kept as context and the bridge backstop skips it. No policy takes it until an SLO coverage
 *   record names it.
 * A missing or unknown tier fails closed to ALERT_TIER_FAIL_CLOSED.
 */
export const alertTierSchema = z.enum([
  "must_page",
  "paging_until_slo",
  "wakes_agent",
  "report_only",
]);
export type AlertTier = z.infer<typeof alertTierSchema>;
export const ALERT_TIER_FAIL_CLOSED: AlertTier = "paging_until_slo";
const timestamp = z.int().min(0).max(8_640_000_000_000_000);
export const runbookAnchorSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,99}$/);
export const incidentPolicySchema = z
  .strictObject({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]{0,99}$/),
    title: z.string().min(1).max(200),
    // Owner D-776 (#9024): only a `report_only` policy may omit its runbook; every other tier,
    // including a missing tier (read as paging), keeps the requirement (refine below).
    runbookAnchor: runbookAnchorSchema.exactOptional(),
    severity: incidentSeveritySchema,
    source: z.enum(["metric", "log"]),
    // Optional for handwritten Terraform policies; the bridge reads a missing tier as paging.
    tier: alertTierSchema.exactOptional(),
    dedupeWindowMs: z.int().min(60_000).max(86_400_000).exactOptional(),
    page: z
      .strictObject({
        acknowledgementMs: z.int().min(1_000).max(86_400_000).exactOptional(),
        unresolvedMs: z.int().min(1_000).max(86_400_000).exactOptional(),
      })
      .exactOptional(),
  })
  .refine((policy) => policy.runbookAnchor !== undefined || policy.tier === "report_only", {
    path: ["runbookAnchor"],
    error: "runbook_required_unless_report_only",
  });
export type IncidentPolicy = z.infer<typeof incidentPolicySchema>;

/**
 * Owner D-409 (source: https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6476697071),
 * superseding D-321's paging scope: only two classes page the owner.
 * - `critical-1`: customer or production impact;
 * - `critical-2`: the devbox is down.
 * Each listed source policy notifies the owner's email, SMS and PagerDuty channels directly from
 * Monitoring, once per incident and again every hour while it stays open, with `page` as the
 * one-line impact in the notification subject. Terraform derives that routing and every policy's
 * `class` label from this list through alerts.json; every unlisted policy is `non-critical` and
 * reaches ops-infra (the incident Pub/Sub channel and incident-watch) only, never the owner.
 * OWNER_ACK_WINDOW_MS is the bridge's escalation window: an unacknowledged CRITICAL-severity
 * incident escalates to ops-infra after it, never to the owner.
 */
export const OWNER_ACK_WINDOW_MS = 1_800_000;
/**
 * Owner D-778 (policies/incidents-and-operations.md#paging; #9024 E): a `wakes_agent` alert keeps
 * the escalation backstop and pages the owner when no agent acts: a CRITICAL after 10 minutes
 * unacknowledged or 60 minutes unresolved, an ERROR after 30 minutes or 4 hours. The D-409 agent
 * escalation stays the first step: the bridge escalates to ops-infra at half of each owner
 * threshold (agent decision, #9024 E), so the agent lane is always asked before the owner is
 * paged. WARNING alerts have no backstop. An SLO fast burn (D-776 must_page) gets the same
 * CRITICAL backstop, and its owner step is email only (D-785, OWNER_BACKSTOP_POLICY).
 * alerts.json carries the table as `ownerPaging.backstop` for incident-watch.
 */
export const OWNER_BACKSTOP_WINDOWS = {
  CRITICAL: {
    agentUnacknowledgedMs: 300_000,
    ownerUnacknowledgedMs: 600_000,
    agentUnresolvedMs: 1_800_000,
    ownerUnresolvedMs: 3_600_000,
  },
  ERROR: {
    agentUnacknowledgedMs: 900_000,
    ownerUnacknowledgedMs: 1_800_000,
    agentUnresolvedMs: 7_200_000,
    ownerUnresolvedMs: 14_400_000,
  },
} as const;
export type OwnerBackstopWindows =
  (typeof OWNER_BACKSTOP_WINDOWS)[keyof typeof OWNER_BACKSTOP_WINDOWS];
/**
 * How the backstop's owner step reaches the owner, both through existing owner channels only:
 * - `text`: the critical-1 owner route `critical-billing` uses (email, SMS and PagerDuty plus the
 *   agent channel), the `incident-owner-page` policy;
 * - `email`: the D-785 SLO route (the owner's email plus the agent channel, never SMS or
 *   PagerDuty), the `incident-owner-email` policy. Every SLO fast burn takes it.
 */
export const ownerBackstopRouteSchema = z.enum(["text", "email"]);
export type OwnerBackstopRoute = z.infer<typeof ownerBackstopRouteSchema>;
export const OWNER_BACKSTOP_POLICY: Readonly<Record<OwnerBackstopRoute, string>> = {
  text: "incident-owner-page",
  email: "incident-owner-email",
};
/**
 * A pooled database connection held this long is a long hold (#5500, #5659): the process logs
 * `database_pool_long_hold` (the `database.poolLongHoldMs` default), the non-critical
 * `database-pool-long-hold` policy routes it to ops-infra with its `holder_operation`, and the DB
 * test harness fails a named unit-of-work transaction that holds its connection this long. One
 * fifth of the 10-second acquire timeout: a lane of 4 to 7 connections pinned by holds this long
 * still serves a queued caller before it times out, where the 6-second `malware.backfill` holds
 * starved customer fixes into `db_pool_acquire_timeout`.
 */
export const POOL_LONG_HOLD_MS = 2_000;
/**
 * A pooled connection idle in transaction this long between two statements (D-712 c) opens the
 * non-critical `database-idle-in-transaction` incident: the long-hold line's `idle_max_ms`. Half
 * the API login's 10-second `idle_in_transaction_session_timeout`, so ops-infra sees a holder
 * before the server starts ending its sessions; measured holds below it are the routine tail.
 */
export const DB_IDLE_IN_TRANSACTION_ALERT_MS = 5_000;
/**
 * The `database-round-trip-slow` warning (#8283): the median of a process's PgBouncer `select 1`
 * probe samples over 15 minutes above this. A direct 5432 round trip measured 0.75 ms p50
 * (docs/deploy/planetscale-prod.md); production statements through PgBouncer cost 130-450 ms each
 * during the #8283 episode (the long-hold samples, about 453 ms at r6622's peak). The bound sits
 * above that peak, so today's standing pooler cost does not keep the incident open and only a
 * further regression opens it. Lower it toward 50 ms once the probe's own baseline is known and
 * #8283's fix lands.
 */
export const DB_ROUND_TRIP_ALERT_MS = 500;
export const criticalClassSchema = z.enum(["critical-1", "critical-2"]);
export const ownerPagingItemSchema = z.enum([
  "fixes_failing",
  "api_down_or_5xx",
  "webhook_intake_failing",
  "uptime_check_failing",
  "customer_queue_stalled",
  "billing_failure_or_wrong_charge",
  "data_loss_or_backup",
  "sandbox_containment",
  "never_persist_breach",
  "database_privilege_refused",
  "tenancy_cross_account",
  "agent_heartbeat_silent",
  "paging_drill",
  "slo_error_budget_burn",
  "unhandled_incident_backstop",
  "global_pause",
  "unexpected_data_access",
]);
export const ownerPagingEntrySchema = z.strictObject({
  id: incidentPolicySchema.shape.id,
  class: criticalClassSchema,
  item: ownerPagingItemSchema,
  // One line, no customer content: Terraform appends the action under way and the owner need.
  page: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9 ,.%()-]{0,99}$/),
});
export type OwnerPagingEntry = z.infer<typeof ownerPagingEntrySchema>;
/**
 * CRITICAL-1 is the #5659 impact policies (infra/terraform/modules/environment/critical-impact.tf
 * and backup.tf) plus the earlier policies they do not cover. One page per incident: the earlier
 * `api-5xx-sustained`, `uptime`, `billing-uncertain-old`, `usage-invoicing-overdue` and
 * `billing-stale-key-replay` entries are non-critical now, because `critical-http-5xx`,
 * `critical-uptime` and `critical-billing` measure the same impact at the D-409 thresholds.
 * `github-webhook-intake-sustained` stays: its absolute failure count catches a burst-shaped intake
 * outage that the 2% share of `critical-http-5xx` misses, so a sustained webhook outage can page
 * twice (agent decision (2026-10-28), pending owner review
 * https://github.com/kovo-sh/kovo-cloud/issues/5661).
 */
export const OWNER_PAGING: readonly OwnerPagingEntry[] = [
  // CRITICAL-1, customer or production impact.
  {
    id: "critical-fix-success-rate",
    class: "critical-1",
    item: "fixes_failing",
    page: "Fix success below 80 percent over the last hour",
  },
  {
    id: "critical-fix-repo-failures",
    class: "critical-1",
    item: "fixes_failing",
    page: "Three or more failed fix runs on one repository in 2 hours",
  },
  {
    id: "critical-http-5xx",
    class: "critical-1",
    item: "api_down_or_5xx",
    page: "App, API or webhook 5xx above 2 percent for 10 min",
  },
  {
    id: "github-webhook-intake-sustained",
    class: "critical-1",
    item: "webhook_intake_failing",
    page: "GitHub webhook intake failing for 10 min",
  },
  {
    id: "critical-uptime",
    class: "critical-1",
    item: "uptime_check_failing",
    page: "Public edge failed its uptime check twice",
  },
  {
    id: "critical-queue-stalled",
    class: "critical-1",
    item: "customer_queue_stalled",
    page: "A customer job queue made no progress for 30 min",
  },
  {
    id: "workers-not-reporting",
    class: "critical-1",
    item: "customer_queue_stalled",
    page: "No worker has reported for 10 min, so customer jobs cannot run",
  },
  // Owner D-776 billing correctness (#9024): its query also pages an unreported charge write-off
  // (kovo.billing.unreported_charges), so this one entry routes that signal to the owner.
  {
    id: "critical-billing",
    class: "critical-1",
    item: "billing_failure_or_wrong_charge",
    page: "Billing failure, a possible wrong charge or an unreported charge written off",
  },
  {
    id: "backup-stale",
    class: "critical-1",
    item: "data_loss_or_backup",
    page: "No good production backup in 23 hours",
  },
  {
    id: "critical-backup",
    class: "critical-1",
    item: "data_loss_or_backup",
    page: "Production backup failed twice in a row",
  },
  {
    id: "critical-sandbox-containment",
    class: "critical-1",
    item: "sandbox_containment",
    page: "A sandbox egress probe that must be blocked was reachable",
  },
  {
    id: "sandbox-expiry-failures",
    class: "critical-1",
    item: "sandbox_containment",
    page: "A sandbox outlived its limit or was not destroyed",
  },
  {
    id: "critical-never-persist",
    class: "critical-1",
    item: "never_persist_breach",
    page: "Never-persist canary found planted content or did not run for 3 hours",
  },
  // A refused database privilege (42501) fails every request or job on that path until fixed, so
  // the first line pages (agent decision (2026-11-02), pending owner review; SPEC Owner paging).
  {
    id: "database-privilege-refused",
    class: "critical-1",
    item: "database_privilege_refused",
    page: "A service database role was refused a privilege (Postgres 42501)",
  },
  // Owner D-776 (source: https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6817034658,
  // #9024): the must-page list "must never be demoted: unexpected data access, tenancy, billing
  // correctness and global pause". Billing correctness pages through `critical-billing` above;
  // these two give global pause and unexpected data access the same critical-1 owner route.
  {
    id: "global-pause",
    class: "critical-1",
    item: "global_pause",
    page: "A global merge, sandbox-dispatch or model-dispatch pause is set",
  },
  {
    id: "run-record-unexpected-access",
    class: "critical-1",
    item: "unexpected_data_access",
    page: "Run records bucket or key accessed by an unexpected principal",
  },
  // Owner D-776 tenancy (#9024 B, #9000): a refused cross-account access or RLS check pages on its
  // first line through the same critical-1 owner route as critical-billing.
  {
    id: "tenancy-cross-account",
    class: "critical-1",
    item: "tenancy_cross_account",
    page: "A cross-account access or row-level security check was refused",
  },
  // CRITICAL-2, the devbox is down.
  {
    id: "devbox-host-heartbeat-absent",
    class: "critical-2",
    item: "agent_heartbeat_silent",
    page: "Devbox heartbeat missing for 10 min",
  },
  // D-409 CRITICAL-2 (#5659): every coordinator and operator session silent for 20 minutes.
  {
    id: "devbox-all-sessions-silent",
    class: "critical-2",
    item: "agent_heartbeat_silent",
    page: "Every agent session silent for 20 min",
  },
  // D-409 monthly paging drill (#5659 item 6): one test page per class through the same derived
  // routing, sent by scripts/ops/paging-drill and cleared within minutes.
  {
    id: "paging-drill-critical-1",
    class: "critical-1",
    item: "paging_drill",
    page: "DRILL monthly critical-1 test page, no customer impact",
  },
  {
    id: "paging-drill-critical-2",
    class: "critical-2",
    item: "paging_drill",
    page: "DRILL monthly critical-2 test page, the devbox is up",
  },
  // Owner D-776 (#9024 (c)): each outcome SLO's fast burn pages (tier must_page); its slow burn
  // wakes an agent only (non-critical). See SERVICE_LEVEL_OBJECTIVES in slos.ts.
  ...SERVICE_LEVEL_OBJECTIVES.map((slo): OwnerPagingEntry => ({
    id: sloPolicyIds(slo.id).fastBurn,
    class: "critical-1",
    item: "slo_error_budget_burn",
    page: slo.page,
  })),
  // Owner D-778 (#9024 E): the bridge backstop's owner step, a bridge-written gauge per route
  // (OWNER_BACKSTOP_POLICY). `incident-owner-email` is the D-785 email-only route for SLO pages.
  {
    id: OWNER_BACKSTOP_POLICY.text,
    class: "critical-1",
    item: "unhandled_incident_backstop",
    page: "An incident no agent acknowledged or resolved in time (D-778 backstop)",
  },
  {
    id: OWNER_BACKSTOP_POLICY.email,
    class: "critical-1",
    item: "unhandled_incident_backstop",
    page: "An SLO page no agent acknowledged or resolved in time (D-778, email only)",
  },
];
/**
 * D-321's data-loss and backup alarms keep the bridge's 30-minute unacknowledged page, whatever
 * their source severity (#5663 fix round: D-409 counts data loss as production impact and keeps
 * this page). Under D-409 routing the bridge's page reaches ops-infra; the owner's own data-loss
 * pages are the critical-1 `backup-stale` and `critical-backup` entries above, which Monitoring
 * sends directly.
 * alerts.json carries the list as `ownerPaging.dataLossEscalation` for incident-watch.
 */
export const DATA_LOSS_ESCALATION_IDS: readonly string[] = [
  "backup-failure",
  "backup-github",
  "backup-stale",
];
export const DATA_LOSS_ESCALATION_POLICIES: ReadonlySet<string> = new Set(DATA_LOSS_ESCALATION_IDS);
export const externalAlertTierSchema = z.strictObject({
  id: incidentPolicySchema.shape.id,
  tier: alertTierSchema,
});
export type ExternalAlertTier = z.infer<typeof externalAlertTierSchema>;
const external = (tier: AlertTier, ids: readonly string[]): ExternalAlertTier[] =>
  ids.map((id) => ({ id, tier }));
/**
 * The tier of every alert policy defined outside ALERT_POLICIES (the hand-written Terraform
 * policies in infra/terraform/modules/environment/*.tf, modules/monitoring/*.tf and the prod
 * root's incident drills, plus the bridge's own ci-registration policy), so the one alert
 * inventory in alerts.json (`externalPolicies`) covers every production policy (#9024 (b)).
 * Terraform labels each policy `tier` from this list; the IDs are their `kovo_alert` labels.
 * Rules (#9024 step 2): `run-record-unexpected-access` and `critical-billing` guard D-776 areas
 * (unexpected data access, billing correctness), so must_page, as does `tenancy-cross-account`
 * (the tenancy area, #9024 B); its same-account companion `tenancy-binding-refused` names no
 * second tenant, so wakes_agent. Uptime checks, every policy that
 * reaches an owner channel today (the OWNER_PAGING list, the D-136 support budget emails, the
 * incident drills that test that path) and the D-321 data-loss escalations stay paging_until_slo,
 * so nothing that pages today is targeted for demotion before an SLO with a drill covers it. The
 * rest is wakes_agent. Under D-778 nothing is report_only until an SLO coverage record names it;
 * the second wakes_agent group never opened an incident in #9024 step 1. Changing a
 * tier changes only the label and the bridge's reading, never a policy's condition or channels.
 */
export const EXTERNAL_ALERT_TIERS: readonly ExternalAlertTier[] = [
  ...external("must_page", [
    "run-record-unexpected-access",
    "critical-billing",
    "tenancy-cross-account",
  ]),
  ...external("paging_until_slo", [
    "uptime",
    "critical-uptime",
    "critical-fix-success-rate",
    "critical-fix-repo-failures",
    "critical-http-5xx",
    "github-webhook-intake-sustained",
    "critical-queue-stalled",
    "critical-backup",
    "critical-sandbox-containment",
    "critical-never-persist",
    "database-privilege-refused",
    "devbox-host-heartbeat-absent",
    "devbox-all-sessions-silent",
    "paging-drill-critical-1",
    "paging-drill-critical-2",
    "support-budget-80",
    "support-budget-100",
    "incident-contract",
    "backup-failure",
    "backup-github",
    "backup-stale",
    // #9024 E: the bridge backstop's owner step (D-778) reaches owner channels.
    OWNER_BACKSTOP_POLICY.text,
    OWNER_BACKSTOP_POLICY.email,
  ]),
  ...external("wakes_agent", [
    "cloud-run-ceiling",
    "github-webhook-5xx-burst",
    "proxy-unexpected-5xx",
    "proxy-sustained-5xx",
    "proxy-cloudrun-429",
    "synthetic-probe-5xx",
    "synthetic-probe-latency",
    "devbox-session-down",
    "calibration-snapshot-janitor",
    "calibration-snapshot-scheduler",
    "run-records-janitor-bounds",
    "egress-gateway-silent",
    "fix-failures-kovo-owned",
    "sandbox-egress-ready-timeout",
    "repo-list-row-skipped",
    "incident-page",
    "incident-bridge-unhealthy",
  ]),
  ...external("wakes_agent", [
    "api-5xx-sustained",
    "proxy-artifact-failures",
    "egress-ceiling",
    "support-intake-flood",
    "support-intake-budget",
    "support-intake-failure",
    "support-intake-stale",
    "synthetic-probe-absent",
    "devbox-ops-infra-session-down",
    "calibration-snapshot-janitor-stale",
    "calibration-snapshot-oldest-age",
    "run-records-janitor-failure",
    "run-records-janitor-rotation",
    "run-records-janitor-backlog",
    "run-records-janitor-binding",
    "run-records-janitor-scheduler",
    "run-records-janitor-stale",
    "checkout-probe-stale",
    "devbox-disk-low",
    "devbox-disk-critical",
    "devbox-disk-metric-absent",
    "incident-coordinator-dead-letter",
    "incident-heartbeat",
    "rollout-lock-stale",
    "ci-registration",
    "tenancy-binding-refused",
  ]),
  // Owner D-776 (#9024 (c)): the outcome SLOs' burn-rate policies (slo-burn-rate.tf). The fast
  // burn is the SLO page (must_page), the slow burn wakes an agent; both come from the SLO list.
  ...SERVICE_LEVEL_OBJECTIVES.flatMap((slo): ExternalAlertTier[] => [
    { id: sloPolicyIds(slo.id).fastBurn, tier: slo.tiers.fastBurn },
    { id: sloPolicyIds(slo.id).slowBurn, tier: slo.tiers.slowBurn },
  ]),
];
export const incidentEventSchema = z.strictObject({
  environment: z.string().regex(/^[a-z][a-z0-9-]{0,31}$/),
  incidentId: incidentIdSchema,
  policyId: incidentPolicySchema.shape.id,
  title: incidentPolicySchema.shape.title,
  // Always present on an event: the bridge falls back to the generic incident-handling anchor.
  runbookAnchor: runbookAnchorSchema,
  severity: incidentSeveritySchema,
  state: z.enum(["open", "closed"]),
  startedAt: timestamp,
  closedAt: timestamp.nullable(),
  resourceType: z.string().regex(/^[a-z][a-z0-9_]{0,79}$/),
});
export type IncidentEvent = z.infer<typeof incidentEventSchema>;
export const incidentStateSchema = incidentEventSchema.extend({
  acknowledgedAt: timestamp.nullable(),
  issueNumber: z.int().positive().nullable(),
  cause: incidentCauseSchema.nullable(),
  reason: incidentPageReasonSchema.nullable(),
  lastPageAt: timestamp.nullable(),
  pageActive: z.boolean(),
  // Durable outbox markers: failed side effects stay retryable, including resolve-to-zero.
  metricDirty: z.boolean(),
  lastMetricAt: timestamp.nullable(),
  scheduledWakeAt: timestamp.nullable(),
  timersInitialized: z.boolean(),
});
export type IncidentState = z.infer<typeof incidentStateSchema>;
export const incidentLeaseSchema = z.strictObject({
  owner: z.string().uuid(),
  expiresAt: timestamp,
});
export const incidentDocumentSchema = z.strictObject({
  kind: z.literal("incident"),
  state: incidentStateSchema.nullable(),
  lease: incidentLeaseSchema.nullable(),
});
export const incidentCursorSchema = z.strictObject({
  kind: z.literal("cursor"),
  after: incidentIdSchema.nullable(),
});
export const incidentHeartbeatSchema = z.strictObject({
  kind: z.literal("heartbeat"),
  lease: incidentLeaseSchema.nullable(),
  cycle: z.string().regex(/^\d{4}-\d{2}-\d{2}(?:T(?:00|06|12|18))?$/),
  closeAt: timestamp,
  active: z.boolean(),
  dirty: z.boolean(),
  lastMetricAt: timestamp.nullable(),
});
/**
 * Owner D-776 (#9024 item 4): the threshold alerts (tier `wakes_agent` or `report_only`) that fired
 * while one SLO or paging incident (`primary`) was open, as metadata-only context: policy ID, tier,
 * counts and timestamps, never free text. It never pages and never changes the primary's state.
 */
export const incidentContextSchema = z.strictObject({
  kind: z.literal("context"),
  // Always null: no lease is taken (writes are generation-checked), and the field keeps the
  // pinned previous reader's lock code (previous-service.fixture.ts) type-compatible.
  lease: incidentLeaseSchema.nullable(),
  primary: incidentIdSchema,
  attached: z
    .array(
      z.strictObject({
        policyId: incidentPolicySchema.shape.id,
        tier: z.enum(["wakes_agent", "report_only"]),
        count: z.int().min(1),
        firstAt: timestamp,
        lastAt: timestamp,
        // The last firing counted, so a redelivered event is not counted twice.
        lastIncidentId: incidentIdSchema,
      }),
    )
    .max(64),
});
export type IncidentContext = z.infer<typeof incidentContextSchema>;
export const bridgeDocumentSchema = z.discriminatedUnion("kind", [
  incidentDocumentSchema,
  incidentCursorSchema,
  incidentHeartbeatSchema,
  incidentContextSchema,
]);
export type BridgeDocument = z.infer<typeof bridgeDocumentSchema>;
export type IncidentDocument = z.infer<typeof incidentDocumentSchema>;
export const bridgeTimerSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("incident"), incidentId: incidentIdSchema }),
  z.strictObject({ kind: z.literal("sweep") }),
  z.strictObject({ kind: z.literal("heartbeat_open") }),
  z.strictObject({
    kind: z.literal("heartbeat_close"),
    cycle: incidentHeartbeatSchema.shape.cycle,
  }),
]);
export type BridgeTimer = z.infer<typeof bridgeTimerSchema>;
export const bridgeAckSchema = z.strictObject({
  incidentId: incidentIdSchema,
  issueNumber: z.int().positive(),
});
export const bridgeEscalateSchema = z.strictObject({
  incidentId: incidentIdSchema,
  cause: incidentCauseSchema,
});
export const bridgeResolveSchema = z
  .strictObject({
    incidentId: incidentIdSchema,
    issueNumber: z.int().positive(),
    reason: z.enum([
      "source_condition_cleared",
      "mitigation_verified",
      // Stops the current handling page while the root cause stays open in issueNumber.
      // Recurrence paging stays live (docs/deploy/ALERT_RUNBOOKS.md, Refs #3544).
      "paging_suppressed_root_cause_open",
    ]),
    // Audited coordinator attestation after checking Monitoring; only for uncatalogued sources.
    source: z.literal("log").exactOptional(),
    // Audited watcher attestation of the GitHub state of issueNumber, read just before the call.
    // The bridge has no GitHub access; it refuses the root-cause reason unless this says open.
    trackingIssueState: z.enum(["open", "closed"]).exactOptional(),
  })
  .refine(
    (request) =>
      request.trackingIssueState === undefined ||
      request.reason === "paging_suppressed_root_cause_open",
    { path: ["trackingIssueState"] },
  );

/**
 * The D-776 SLO coverage record (#9024 (c)): which SLO covers the same failure as a threshold
 * alert. The incident bridge (#9024 (a)) may stop a covered alert paging only when its entry is
 * `same_failure` AND a pre-warned drill (scripts/ops/incident-drill) recorded here showed a covering
 * SLO firing for that failure. `partial` never demotes: the SLO sees part of the failure only, so
 * its `drill` is permanently null with `drillNullReason: "partial_never_demotes"`, and a drill on
 * it fails to parse. It never lists a must_page policy (D-776: never demoted). This record demotes
 * nothing by itself. alerts.json carries it as `slos.coverage`.
 */
export const SLO_COVERAGE_PARTIAL_NULL_REASON = "partial_never_demotes";
/**
 * One controlled, pre-warned run (#9024 C2): the SLO fired from its production metric
 * (`sloIncident`, the fast-burn incident) and the entry's threshold alert fired too
 * (`alertIncident`), in the same window. IDs and time only. `evidence` says how the failure was
 * produced: `real_condition` (the real failure, made in a Kovo-owned way) or `synthetic` (for
 * example a metric written by hand or a rule test); only `real_condition` can demote.
 */
export const sloCoverageDrillSchema = z
  .strictObject({
    // The scripts/ops/incident-drill audit record (#489).
    record: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
    at: z.iso.datetime(),
    slo: sloIdSchema,
    evidence: z.enum(["real_condition", "synthetic"]),
    sloIncident: incidentIdSchema,
    alertIncident: incidentIdSchema,
  })
  .refine((drill) => drill.sloIncident !== drill.alertIncident, { path: ["alertIncident"] });
export type SloCoverageDrill = z.infer<typeof sloCoverageDrillSchema>;
const sloCoverageBase = {
  policy: incidentPolicySchema.shape.id,
  slos: z.array(sloIdSchema).min(1),
  // What the SLO does and does not see of the alert's failure (metadata only).
  failure: z.string().min(1).max(300),
};
export const sloCoverageSchema = z.discriminatedUnion("coverage", [
  z.strictObject({
    ...sloCoverageBase,
    coverage: z.literal("same_failure"),
    // The drill that showed the SLO firing for this failure; null until one is run and recorded.
    drill: sloCoverageDrillSchema.nullable(),
  }),
  z.strictObject({
    ...sloCoverageBase,
    coverage: z.literal("partial"),
    drill: z.null(),
    drillNullReason: z.literal(SLO_COVERAGE_PARTIAL_NULL_REASON),
  }),
]);
export type SloCoverage = z.infer<typeof sloCoverageSchema>;

export const SLO_COVERAGE: readonly SloCoverage[] = [
  // The three paging_until_slo alerts (#9024 step 2).
  {
    policy: "workers-not-reporting",
    slos: ["jobs-progressing"],
    coverage: "same_failure",
    failure:
      "Same metric: every minute with kovo.outbox.oldest_unpublished_age absent is a bad slice, so a silent worker burns the budget from its first minute.",
    drill: null,
  },
  {
    policy: "database-connections-saturated",
    slos: ["api-available", "jobs-progressing"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure:
      "Saturation shows only once it fails reads or stalls a queue; the threshold alert sees the headroom loss earlier.",
    drill: null,
  },
  {
    policy: "recovery-dead-lettered",
    slos: ["fixes-delivered"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure:
      "A dead-lettered fix workflow fails its run and counts; dead-lettered non-fix workflows (billing, inventory) do not.",
    drill: null,
  },
  // Owner-paging (critical-1) and threshold alerts on the same failures.
  {
    policy: "synthetic-probe-5xx",
    slos: ["api-available"],
    coverage: "same_failure",
    failure: "Same 0/1 samples (custom kovo/probe/server_error).",
    drill: null,
  },
  {
    policy: "api-5xx-sustained",
    slos: ["api-available"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "The probe sees API 5xx on its three reads only, not on other routes or writes.",
    drill: null,
  },
  {
    policy: "critical-http-5xx",
    slos: ["api-available"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "The probe covers API reads; web and webhook 5xx are not in the SLI.",
    drill: null,
  },
  {
    policy: "critical-uptime",
    slos: ["api-available"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure:
      "An edge outage fails the probe (no answer); the uptime check also proves the web's static file through the CDN, which the probe does not read.",
    drill: null,
  },
  {
    policy: "uptime",
    slos: ["api-available"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "As critical-uptime: the API edge only, not the web's static file.",
    drill: null,
  },
  {
    policy: "critical-fix-success-rate",
    slos: ["fixes-delivered"],
    coverage: "same_failure",
    failure:
      "Same counters and the same Kovo-owned exclusion; the SLO pages at a 72% bad share over 1 hour and 15 minutes, or 30% over 6 hours and 1 hour.",
    drill: null,
  },
  {
    policy: "critical-fix-repo-failures",
    slos: ["fixes-delivered"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "Three failures on one repository may stay under the SLO's account-wide share.",
    drill: null,
  },
  {
    policy: "fix-failures-kovo-owned",
    slos: ["fixes-delivered"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "Counted by the slow burn only (wakes an agent), never the page (D-471).",
    drill: null,
  },
  {
    policy: "invariant-workflow-failed",
    slos: ["fixes-delivered"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "A failed fix workflow counts; failures of other workflow kinds do not.",
    drill: null,
  },
  {
    policy: "sandbox-egress-ready-timeout",
    slos: ["fixes-delivered"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "Counts only once the timeouts fail fix runs.",
    drill: null,
  },
  {
    policy: "critical-queue-stalled",
    slos: ["jobs-progressing"],
    coverage: "same_failure",
    failure: "Same stall test (head unchanged 30 minutes while work waits, no fix started).",
    drill: null,
  },
  {
    policy: "p0-queue-age",
    slos: ["jobs-progressing"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "A P0 waiting 15 minutes is bad here only once its queue stalls for 30.",
    drill: null,
  },
  {
    policy: "worker-queue-saturated",
    slos: ["jobs-progressing"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "A sustained backlog that still moves is not a stall.",
    drill: null,
  },
  {
    policy: "outbox-lag",
    slos: ["jobs-progressing"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "Delayed starts count once they stall a queue or silence the worker.",
    drill: null,
  },
  {
    policy: "usage-invoicing-overdue",
    slos: ["money-correct"],
    coverage: "same_failure",
    failure: "Same gauge (kovo.usage.invoicing_overdue above 0) as a bad slice.",
    drill: null,
  },
  {
    policy: "checkout-probe-stale",
    slos: ["money-correct"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure:
      "A probe that stops running leaves no failed outcome, so the SLO stays silent; a failing probe is bad.",
    drill: null,
  },
  {
    policy: "backup-stale",
    slos: ["backups-fresh"],
    coverage: "same_failure",
    failure: "Same metric and the same 23-hour bound (backup/completed).",
    drill: null,
  },
  {
    policy: "critical-backup",
    slos: ["backups-fresh"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure:
      "Two failed runs leave no fresh backup and burn the budget, but later than the second failure itself.",
    drill: null,
  },
  {
    policy: "backup-failure",
    slos: ["backups-fresh"],
    coverage: "partial",
    drillNullReason: SLO_COVERAGE_PARTIAL_NULL_REASON,
    failure: "One failed run is bad only if no later run succeeds within 23 hours.",
    drill: null,
  },
];

/**
 * Whether the bridge may stop `policyId` (of inventory tier `tier`) paging: only a valid
 * `same_failure` entry whose recorded `real_condition` drill names a covering SLO and holds both
 * the SLO's and the alert's incident IDs, and never a must_page policy. Fails closed: unlisted,
 * duplicated, malformed, partial and undrilled entries, a synthetic drill and a drill missing
 * either incident ID keep paging.
 */
export function sloCoverageDemotable(
  policyId: string,
  tier: AlertTier,
  record: readonly SloCoverage[] = SLO_COVERAGE,
): boolean {
  if (tier === "must_page") return false;
  const entries = record.filter((candidate) => candidate.policy === policyId);
  if (entries.length !== 1) return false;
  const parsed = sloCoverageSchema.safeParse(entries[0]);
  if (!parsed.success) return false;
  const entry = parsed.data;
  return (
    entry.coverage === "same_failure" &&
    entry.drill !== null &&
    entry.drill.evidence === "real_condition" &&
    entry.drill.sloIncident.length > 0 &&
    entry.drill.alertIncident.length > 0 &&
    entry.slos.includes(entry.drill.slo)
  );
}
