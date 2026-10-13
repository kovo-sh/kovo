import { z } from "zod";

import { BILLING_ROLES, planSchema } from "../enums/accounts.js";
import { cycleIdSchema } from "../ids.js";
import { nonNegativeMicroUsdWireSchema } from "../money.js";
import { pageSchema, paginationQueryShape } from "../pagination.js";
import { countSchema, whenValid } from "../primitives.js";
import { utcDateTimeSchema } from "../time.js";
import { OVERAGE_MARKUP_MULTIPLIER } from "./billing.js";
import { repoRefSchema } from "./common.js";
import { defineEndpoint } from "./endpoint.js";

// `GET /v1/usage` (SPEC "Included cost and opt-in overages": "Display allowance consumed, reserved
// cost, overage base, markup, and remaining authorized spend separately"; Public API row "Billing
// scope for account totals; otherwise only authorized repo operational usage"). Money is micro-USD
// strings; nothing is rounded to cents here.

/**
 * Account totals for the billing cycle, shown only to billing-authorized humans.
 * - `allowance_usd`: "1× the account's paid subscription amount" plus prorated capacity charges.
 * - `allowance_consumed_usd`: actual cost funded by the allowance.
 * - `reserved_usd`: held reservations ("Uncertain costs retain reservations until reconciled").
 * - `overage_base_usd` / `overage_markup_usd` / `overage_charge_usd`: approved actual cost billed as
 *   overage, the 20% markup on it, and their sum (the amount charged).
 * - `remaining_authorized_spend_usd`: post-markup headroom under the consented cycle limit.
 * - `kovo_funded_usd`: deterministic work beyond the allowance ("Kovo-funded and is not
 *   retroactively invoiced").
 */
export const accountUsageTotalsSchema = z
  .strictObject({
    allowance_usd: nonNegativeMicroUsdWireSchema,
    allowance_consumed_usd: nonNegativeMicroUsdWireSchema,
    allowance_remaining_usd: nonNegativeMicroUsdWireSchema,
    reserved_usd: nonNegativeMicroUsdWireSchema,
    overage_enabled: z.boolean(),
    overage_base_usd: nonNegativeMicroUsdWireSchema,
    overage_markup_usd: nonNegativeMicroUsdWireSchema,
    overage_charge_usd: nonNegativeMicroUsdWireSchema,
    markup_multiplier: z.literal(OVERAGE_MARKUP_MULTIPLIER),
    overage_limit_usd: nonNegativeMicroUsdWireSchema.nullable(),
    remaining_authorized_spend_usd: nonNegativeMicroUsdWireSchema,
    kovo_funded_usd: nonNegativeMicroUsdWireSchema,
    protected_repo_count: countSchema,
  })
  .superRefine((totals, ctx) => {
    if (totals.allowance_consumed_usd > totals.allowance_usd) {
      ctx.addIssue({
        code: "custom",
        path: ["allowance_consumed_usd"],
        message: "the allowance funds at most the allowance",
      });
    }
    if (totals.allowance_remaining_usd > totals.allowance_usd - totals.allowance_consumed_usd) {
      ctx.addIssue({
        code: "custom",
        path: ["allowance_remaining_usd"],
        message: "remaining allowance is at most allowance minus consumed",
      });
    }
    if (totals.overage_charge_usd !== totals.overage_base_usd + totals.overage_markup_usd) {
      ctx.addIssue({
        code: "custom",
        path: ["overage_charge_usd"],
        message: "the overage charge is base plus markup",
      });
    }
    const limit = totals.overage_limit_usd;
    if (totals.overage_enabled !== (limit !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["overage_limit_usd"],
        message: "exactly enabled overages have a cycle limit",
      });
    }
    const headroom =
      limit === null || limit <= totals.overage_charge_usd ? 0n : limit - totals.overage_charge_usd;
    if (totals.remaining_authorized_spend_usd > headroom) {
      ctx.addIssue({
        code: "custom",
        path: ["remaining_authorized_spend_usd"],
        message:
          "remaining authorized spend is within the post-markup limit, and zero without consent",
      });
    }
  }, whenValid);
export type AccountUsageTotals = z.output<typeof accountUsageTotalsSchema>;

/** Operational usage of one repository the caller can read. */
export const repoUsageSchema = z.strictObject({
  repo: repoRefSchema,
  model_cost_usd: nonNegativeMicroUsdWireSchema,
  sandbox_cost_usd: nonNegativeMicroUsdWireSchema,
  reserved_usd: nonNegativeMicroUsdWireSchema,
  /** Supporting measurements ("Tokens/minutes are supporting measurements, not the billing unit"). */
  model_tokens: countSchema,
  sandbox_seconds: countSchema,
  ai_attempts: countSchema,
});

/**
 * The reported cycle: the one named by `cycle_id`, otherwise the one running now.
 *
 * - `cycle.id` is null while the running cycle is not open yet (nothing was reserved or charged in
 *   it and no paid invoice funded it): its boundaries are the ones it will have, and every amount
 *   is zero.
 * - `plan` is the account's plan now; `cycle_plan` the plan the reported cycle belongs to (`plus`
 *   for a Stripe subscription period, `free` otherwise). They differ for a past Plus cycle of an
 *   account that is Free now, whose totals are still that cycle's.
 * - For a cycle that is not running any more, the overage consent in the totals is the one in force
 *   when it ended; for the running cycle, the one in force now.
 */
export const usageResponseSchema = z
  .strictObject({
    cycle: z.strictObject({
      id: cycleIdSchema.nullable(),
      starts_at: utcDateTimeSchema,
      ends_at: utcDateTimeSchema,
      finalized: z.boolean(),
    }),
    plan: planSchema,
    cycle_plan: planSchema,
    /** Null unless the caller is a billing-authorized human. */
    account: accountUsageTotalsSchema.nullable(),
    repos: pageSchema(repoUsageSchema),
  })
  .superRefine((usage, ctx) => {
    if (usage.cycle.ends_at.getTime() <= usage.cycle.starts_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["cycle", "ends_at"],
        message: "a cycle ends after it starts",
      });
    }
    if (usage.cycle.id === null && usage.cycle.finalized) {
      ctx.addIssue({
        code: "custom",
        path: ["cycle", "finalized"],
        message: "a cycle that is not open yet is not finalized",
      });
    }
    const account = usage.account;
    if (account === null) return;
    // "Free has zero AI entitlement … it cannot buy AI overages without upgrading to Plus": a Free
    // cycle funds no allowance and bills no overage, and a Free account in a Free cycle has no
    // overage consent in effect.
    const freeCycle = usage.cycle_plan === "free";
    if (freeCycle && (account.allowance_usd !== 0n || account.overage_charge_usd !== 0n)) {
      ctx.addIssue({
        code: "custom",
        path: ["account"],
        message: "a Free cycle has no AI allowance and no overages",
      });
    }
    if (freeCycle && usage.plan === "free" && account.overage_enabled) {
      ctx.addIssue({
        code: "custom",
        path: ["account", "overage_enabled"],
        message: "Free cannot buy AI overages",
      });
    }
    const unopened = usage.cycle.id === null;
    if (
      unopened &&
      (account.allowance_usd !== 0n ||
        account.reserved_usd !== 0n ||
        account.overage_charge_usd !== 0n ||
        account.kovo_funded_usd !== 0n)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["account"],
        message: "a cycle that is not open yet has no usage",
      });
    }
  }, whenValid);
export type UsageResponse = z.output<typeof usageResponseSchema>;

export const USAGE_ENDPOINTS = {
  getUsage: defineEndpoint({
    operationId: "getUsage",
    area: "usage",
    method: "GET",
    path: "/v1/usage",
    summary: "Report cycle usage: account totals for billing, per-repository usage for readers.",
    source: { kind: "spec_row", path: "/v1/usage" },
    params: null,
    query: z.strictObject({ ...paginationQueryShape, cycle_id: cycleIdSchema.exactOptional() }),
    body: null,
    responses: { 200: usageResponseSchema },
    authorization: {
      spec: "Billing scope for account totals; otherwise only authorized repo operational usage",
      actors: ["human_session", "api_key_read", "api_key_write"],
      tenant: "account_context",
      repoAuthority: { level: "read", over: "listed_items" },
      escalations: [
        {
          when: "reads_account_totals",
          requires: { humanSession: true, billingAuthority: true, accountRoles: BILLING_ROLES },
          unmet: "omit",
        },
      ],
    },
    paginated: true,
  }),
} as const;
