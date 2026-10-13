import { DURATIONS, HOUR_MS, MINUTE_MS } from "./time.js";

/** Lifetime bound on proven sibling-induced regeneration exemptions. */
export const SIBLING_REFRESH_LIMIT = 10;

/**
 * Numeric ceilings and defaults SPEC fixes, grouped by area. Durations live in `DURATIONS`; money
 * constants live in `money.ts`. Queue and capacity numbers are SPEC's initial values ("ceilings,
 * not a promise"), kept here so configuration defaults and tests share one source.
 */
export const LIMITS = {
  /** Public API: "Lists use `limit` (default 50, max 100) and opaque `cursor`". */
  pagination: { defaultLimit: 50, maxLimit: 100 },
  /** "Queues and capacity" table. */
  queues: {
    fixP0: { global: 20, perAccount: 5 },
    fixP1: { global: 20, perAccount: 3 },
    inventory: { global: 50 },
  },
  /**
   * "Shadow/autopilot allow one active fix PR with one additional P0 slot; PR-only defaults to
   * three (configurable 1–10). Failed-verification PRs and revert PRs use separate bounded slots:
   * at most one live PR of each kind per package".
   */
  slots: {
    shadowAutopilotFixPrs: 1,
    shadowAutopilotP0Extra: 1,
    prOnlyDefault: 3,
    prParallelCapMin: 1,
    prParallelCapMax: 10,
    failedVerificationPrsPerPackage: 1,
    revertPrsPerPackage: 1,
  },
  /** "Initial per-attempt ceilings: 40 tool calls, 25 minutes, 300k tokens"; "cap tool results at 256 KB". */
  agent: {
    maxToolCalls: 40,
    maxDurationMs: DURATIONS.agentAttemptMaxDuration,
    maxTokens: 300_000,
    maxToolResultBytes: 256 * 1024,
  },
  /** "allow at most two automatic refresh attempts per fix, then request review". */
  baseFreshness: { maxAutomaticRefreshes: 2 },
  /** ARCH-28: recipe-only revisions have a separate lifetime bound and fixed coalescing window. */
  recipeReverification: { maxAutomaticReverifications: 2, coalescingWindowMs: 10 * MINUTE_MS },
  /**
   * "at most three calibrations per repo per day"; "Require at least two meaningful applicable
   * mutations, all caught, with at least one exercising application code/build behavior".
   */
  calibration: {
    maxPerRepoPerWindow: 3,
    windowMs: DURATIONS.calibrationRateWindow,
    minMeaningfulMutations: 2,
    minAppCodeMutations: 1,
  },
  /**
   * The rediscovery rate limit (SPEC Public API: `POST …/recipe/rediscover` "Scoped write; async
   * job; rate/cost limits"; docs/decisions/recipes.md "Rediscovery rate and cost limits"): at most
   * four discoveries of one repository start in any rolling hour, whatever asked for them.
   */
  discovery: { maxPerRepoPerWindow: 4, windowMs: HOUR_MS },
  /** "After five unchanged-head human merges of would-merge PRs … suggest activation". */
  shadow: { suggestionMergeCount: 5, windowMs: DURATIONS.shadowSuggestionWindow },
  /** "Bound application and DBOS connection pools independently (initial cap 5 each per process), reserve 20% database connection headroom". */
  database: { appPoolMax: 5, dbosPoolMax: 5, connectionHeadroomPercent: 20 },
  /** "Sandbox defaults: 2 vCPU/4 GiB, fixed per-step timeout, absolute 60-minute lifetime". */
  sandbox: { vcpus: 2, memoryGib: 4, maxLifetimeMs: DURATIONS.sandboxMaxLifetime },
  /**
   * Paid capacity: one quote adds at most this many slots (docs/decisions/contracts.md "Billing
   * shapes"), which bounds a mistyped quantity.
   */
  capacity: { maxAdditionalSlotsPerQuote: 100 },
  /**
   * Per-account resource caps (SPEC Pauses and resilience: "Global/account/repo resource caps …
   * prevent one tenant monopolizing workers"; docs/decisions/accounts.md and notifications.md): an
   * account holds at most this many pending invitations and live (not revoked) webhook
   * subscriptions; one more is `409 conflict` until one is revoked or expires.
   */
  accounts: { maxPendingInvitations: 50, maxLiveWebhookSubscriptions: 25 },
  /**
   * Requested test events (`POST /v1/webhooks/{id}/test`; docs/decisions/notifications.md "Test
   * events"): at most this many per subscription per window, one attempt each, so a test cannot
   * turn Kovo into a request generator against a destination ("prevent one tenant monopolizing
   * workers"); one more is `429 rate_limited`.
   */
  webhookTests: { maxPerSubscriptionPerWindow: 5, windowMs: HOUR_MS },
  /**
   * "Use a bounded dead-letter/reconciliation path for exhausted external retries": the recovery
   * reaper resumes one workflow at most this many times after executor loss before dead-lettering
   * it (a workflow that keeps killing its executor is a poison workflow).
   */
  recovery: { maxResumes: 3 },
  /** Rollout: "promote web/API/proxy revisions through 5%, 25%, then 100% traffic". */
  rollout: { canaryTrafficPercents: [5, 25, 100] },
} as const;
