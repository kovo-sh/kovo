import { z } from "zod";

/**
 * Owner D-776 (source: https://github.com/kovo-sh/kovo-cloud/issues/626#issuecomment-6817034658,
 * tracker #9024): the paging set is about five outcome SLOs driven by synthetic traffic, plus the
 * must-page list. Threshold alerts stop paging only once an SLO demonstrably covers the same
 * failure, shown by a drill (coordinator application of D-776).
 *
 * Each objective here becomes two Cloud Monitoring policies
 * (infra/terraform/modules/environment/slo-burn-rate.tf, through alerts.json `slos`):
 * - `slo-<id>-fast-burn`: the multi-window fast burn (each leg needs its long AND its short window
 *   over the leg's burn rate). It pages: tier `must_page`, a critical-1 OWNER_PAGING entry.
 * - `slo-<id>-slow-burn`: the slow burn. It wakes an agent: tier `wakes_agent`, non-critical.
 * A leg's threshold is its burn rate times the error budget (1 - objective) as a bad fraction.
 * Signals are metadata only: counts, 0/1 samples, ages and fixed outcome codes.
 * The SLIs, signals and targets are an agent decision (2026-11-12), pending owner review
 * (#9043, plans/alert-tiers-slo-paging.md). The tiers are values of alertTierSchema, and the coverage
 * record (SLO_COVERAGE) lives beside it in incidents.ts.
 */
export const sloIdSchema = z.enum([
  "api-available",
  "fixes-delivered",
  "jobs-progressing",
  "money-correct",
  "backups-fresh",
]);
export type SloId = z.infer<typeof sloIdSchema>;
const windowSchema = z.string().regex(/^[1-9][0-9]*[mh]$/);
const burnLegSchema = z.strictObject({
  long: windowSchema,
  short: windowSchema,
  burnRate: z.number().positive().max(100),
});
export type SloBurnLeg = z.infer<typeof burnLegSchema>;

/** Window length in seconds ("5m" is 300). */
export function sloWindowSeconds(window: string): number {
  const parsed = /^([1-9][0-9]*)([mh])$/.exec(window);
  if (parsed === null) throw new Error(`slo_window_invalid:${window}`);
  return Number(parsed[1]) * (parsed[2] === "h" ? 3600 : 60);
}

/** The longest PromQL lookback Cloud Monitoring accepts in an alert query (25 hours). */
export const SLO_MAX_LOOKBACK_SECONDS = 90_000;

export const sloSchema = z
  .strictObject({
    id: sloIdSchema,
    title: z.string().regex(/^[A-Z][A-Za-z0-9 ,.()-]{0,79}$/),
    // One line, no customer content; the owner page subject (OWNER_PAGING `page`).
    page: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9 ,.%()-]{0,99}$/),
    // `event_ratio`: bad events over all events in a window. `time_slice`: the fraction of
    // one-minute slices in a window that were bad.
    sli: z.enum(["event_ratio", "time_slice"]),
    objective: z.number().gt(0.5).lt(1),
    periodDays: z.literal(28),
    // What makes an event or a slice bad, and where the samples come from (metadata only).
    signal: z.string().min(1).max(400),
    // Which Kovo-owned or synthetic traffic drives it until real volume exists, and what it misses.
    synthetic: z.string().min(1).max(600),
    fastBurn: z.array(burnLegSchema).min(1).max(2),
    slowBurn: z.array(burnLegSchema).length(1),
    // event_ratio only: the fewest events in a fast leg's long window before it can page.
    minEvents: z.int().min(1).max(1000).exactOptional(),
    // time_slice only: how far back one bad-minute evaluation itself reads (its own range
    // vectors and offsets). Cloud Monitoring refuses (invalid_argument) a PromQL alert whose whole
    // lookback, a leg's long window plus this, exceeds 25 hours (prod apply 43232824968).
    signalLookback: windowSchema.exactOptional(),
    tiers: z.strictObject({ fastBurn: z.literal("must_page"), slowBurn: z.literal("wakes_agent") }),
  })
  .refine(
    (slo) =>
      [...slo.fastBurn, ...slo.slowBurn].every(
        (leg) =>
          sloWindowSeconds(leg.short) < sloWindowSeconds(leg.long) &&
          sloWindowSeconds(leg.long) <= 86_400 &&
          sloWindowSeconds(leg.long) +
            (slo.signalLookback === undefined ? 0 : sloWindowSeconds(slo.signalLookback)) <=
            SLO_MAX_LOOKBACK_SECONDS &&
          // A threshold of a whole window (or more) bad could never fire.
          leg.burnRate * (1 - slo.objective) < 1,
      ),
    { message: "slo_burn_leg_invalid" },
  )
  .refine((slo) => (slo.sli === "event_ratio") === (slo.minEvents !== undefined), {
    message: "slo_min_events_only_for_event_ratio",
  })
  .refine((slo) => (slo.sli === "time_slice") === (slo.signalLookback !== undefined), {
    message: "slo_signal_lookback_only_for_time_slice",
  });
export type ServiceLevelObjective = z.infer<typeof sloSchema>;

const FAST: readonly SloBurnLeg[] = [
  { long: "1h", short: "5m", burnRate: 14.4 },
  { long: "6h", short: "30m", burnRate: 6 },
];
const SLOW: readonly SloBurnLeg[] = [{ long: "24h", short: "2h", burnRate: 3 }];
const TIERS = { fastBurn: "must_page", slowBurn: "wakes_agent" } as const;

export const SERVICE_LEVEL_OBJECTIVES: readonly ServiceLevelObjective[] = [
  {
    id: "api-available",
    title: "Dashboard reads answer without a server error",
    page: "SLO burn, dashboard reads failing (API up)",
    sli: "event_ratio",
    objective: 0.995,
    periodDays: 28,
    signal:
      "custom.googleapis.com/kovo/probe/server_error: one 0/1 sample per probe per minute; 1 is a 5xx or no answer. Bad fraction is the mean over the window across the three probes.",
    synthetic:
      "Driven entirely by scripts/ops/synthetic-probe (GET /v1/repos and the Home reads as the Kovo-owned kovo-tests account, every minute from the devbox). It does not see writes, the web app, webhooks or a customer's own data shape, and it is silent while the prober is (synthetic-probe-absent).",
    fastBurn: [...FAST],
    slowBurn: [...SLOW],
    minEvents: 3,
    tiers: TIERS,
  },
  {
    id: "fixes-delivered",
    title: "Fix runs end with a verified pull request",
    page: "SLO burn, fix runs failing (fixes delivered)",
    sli: "event_ratio",
    objective: 0.95,
    periodDays: 28,
    signal:
      "Bad: failed fix runs (fix_run_canceled outside the benign codes) plus fix_workflow_failed_unexpectedly lines. Good: verified fix PRs (kovo.fix.verified_pr_latency count). The page leaves out Kovo-owned accounts' failed runs (owner D-471); the slow burn counts them.",
    synthetic:
      "Driven by dogfood fixes on Kovo-owned repositories (their verified PRs count as good events) and the monthly drill_forced_cancel drill on kovo-tests (counted as bad). Kovo-owned failures wake an agent but never page (D-471), so until customer volume exists a dogfood-only failure reaches agents, not the owner.",
    fastBurn: [
      { long: "1h", short: "15m", burnRate: 14.4 },
      { long: "6h", short: "1h", burnRate: 6 },
    ],
    slowBurn: [...SLOW],
    minEvents: 5,
    tiers: TIERS,
  },
  {
    id: "jobs-progressing",
    title: "Customer job queues keep moving",
    page: "SLO burn, customer job queues stalled (jobs finishing)",
    sli: "time_slice",
    objective: 0.995,
    periodDays: 28,
    signal:
      "A bad minute: no worker reports (kovo.outbox.oldest_unpublished_age absent), or a customer queue has work waiting whose head has not moved for 30 minutes with no fix started (the critical-queue-stalled test).",
    synthetic:
      "Kovo-owned and synthetic jobs (dogfood fixes, kovo-tests, inventory and GitHub event work) keep the queues busy; with no work queued a stall cannot be seen, only a silent worker.",
    fastBurn: [...FAST],
    slowBurn: [...SLOW],
    // The stall test reads 30 minutes back from 30 minutes ago.
    signalLookback: "1h",
    tiers: TIERS,
  },
  {
    id: "money-correct",
    title: "Checkout and usage billing stay correct",
    page: "SLO burn, checkout or usage billing failing (money correct)",
    sli: "time_slice",
    objective: 0.995,
    periodDays: 28,
    signal:
      "A bad minute: more than half of the live Checkout probes that logged a probe_outcome in the last 6 hours failed, a billing outcome stayed uncertain over an hour, an overage invoice is overdue, or a usage charge was written off as unreported in the last hour. Wrong-charge repairs stay on the must-page list, not here.",
    synthetic:
      "The live Checkout probe (Kovo-owned, per release and every 6 hours) and the kovo-tests-billing drill org drive it; it cannot see a wrong amount on a real customer's invoice, which billing reconciliation pages separately (must_page).",
    fastBurn: [...FAST],
    // 18 hours, not 24: a minute reads 6 hours of Checkout probe outcomes, and the whole lookback
    // must stay within 25 hours.
    slowBurn: [{ long: "18h", short: "2h", burnRate: 3 }],
    signalLookback: "6h",
    tiers: TIERS,
  },
  {
    id: "backups-fresh",
    title: "A good production backup is under 23 hours old",
    page: "SLO burn, no fresh production backup (backups fresh)",
    sli: "time_slice",
    objective: 0.99,
    periodDays: 28,
    signal:
      "A bad minute: no backup_completed line from the kovo-backup job in the last 23 hours (two scheduled runs a day).",
    synthetic:
      "Not traffic: the scheduled backup job itself is the signal, so it measures the same thing for every customer. It does not prove a backup restores; the restore drills do.",
    // A minute reads 23 hours of backup completions, so no leg may look back over 1 hour (the
    // 25-hour limit; the 6-hour and 24-hour legs were refused in prod). Freshness is nearly
    // binary: the page fires about 9 minutes after 23 hours without a backup, the slow burn
    // (wakes an agent) about 4 minutes after.
    fastBurn: [{ long: "1h", short: "5m", burnRate: 14.4 }],
    slowBurn: [{ long: "1h", short: "5m", burnRate: 6 }],
    signalLookback: "23h",
    tiers: TIERS,
  },
];

/** The two policy IDs of one objective. */
export function sloPolicyIds(id: SloId): { readonly fastBurn: string; readonly slowBurn: string } {
  return { fastBurn: `slo-${id}-fast-burn`, slowBurn: `slo-${id}-slow-burn` };
}
