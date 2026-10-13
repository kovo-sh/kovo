import { z } from "zod";

import { BILLING_ROLES, planSchema } from "../enums/accounts.js";
import {
  CONFIRMED_CAPACITY_QUOTE_STATES,
  SETTLED_CAPACITY_QUOTE_STATES,
  capacityQuoteStateSchema,
  subscriptionStatusSchema,
  type CapacityQuoteState,
} from "../enums/billing.js";
import { accountIdSchema, quoteIdSchema, repoIdSchema } from "../ids.js";
import { LIMITS } from "../limits.js";
import {
  EXTRA_REPO,
  FREE_REPOS,
  INCLUDED_REPOS,
  PLUS_BASE,
  nonNegativeMicroUsdWireSchema,
} from "../money.js";
import { countSchema, whenValid } from "../primitives.js";
import { DURATIONS, utcDateTimeSchema } from "../time.js";
import { emptyBodySchema, httpsUrlSchema, repoRefSchema, userRefSchema } from "./common.js";
import { defineEndpoint, type AuthorizationInit } from "./endpoint.js";

// `/v1/billing/*` (SPEC "Plans, billing, and usage", Public API rows 30–33). Every route is for a
// billing-authorized human ("owner/admin/billing manager manage subscription, capacity and overage
// spending"); the Stripe customer is always selected on the server from the account context, never
// from the request. Money is micro-USD strings.

// ---- Status ----

/**
 * The account's plan, Stripe subscription, grace period and protected capacity. Billing views show
 * counts, never repository names ("Billing-only views expose counts and charges, not private
 * repository names"): `retained_repo` is shown only when the caller can read it.
 */
export const billingStatusSchema = z
  .strictObject({
    plan: planSchema,
    subscription: z
      .strictObject({
        status: subscriptionStatusSchema,
        cancel_at_period_end: z.boolean(),
        period_start_at: utcDateTimeSchema,
        period_end_at: utcDateTimeSchema,
      })
      .nullable(),
    /** "A failed renewal starts a 7-day grace period from the first failure for that invoice". */
    grace: z
      .strictObject({ started_at: utcDateTimeSchema, deadline_at: utcDateTimeSchema })
      .nullable(),
    capacity: z.strictObject({
      included_repos: z.int().positive(),
      /** Extra slots paid for in the current period (reassignable within it). */
      paid_extra_slots: countSchema,
      /** Extra slots the next renewal bills ("reduces paid capacity only at the next renewal"). */
      next_period_extra_slots: countSchema,
      protected_repos: countSchema,
      /** Protection requests waiting for a billing-authorized capacity grant. */
      pending_capacity_requests: countSchema,
    }),
    /** The repository kept on Free at a downgrade, if chosen and readable by the caller. */
    retained_repo: repoRefSchema.nullable(),
    retained_repo_selected: z.boolean(),
  })
  .superRefine((billing, ctx) => {
    const capacity = billing.capacity;
    const expectedIncluded = billing.plan === "plus" ? INCLUDED_REPOS : FREE_REPOS;
    // Owner grants add included Plus slots; Free still has exactly its one slot.
    if (
      capacity.included_repos < expectedIncluded ||
      (billing.plan === "free" && capacity.included_repos !== expectedIncluded)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["capacity", "included_repos"],
        message: `${billing.plan} includes ${billing.plan === "plus" ? "at least " : ""}${expectedIncluded} protected repositories`,
      });
    }
    if (
      billing.plan === "free" &&
      (capacity.paid_extra_slots > 0 || capacity.next_period_extra_slots > 0)
    ) {
      ctx.addIssue({ code: "custom", path: ["capacity"], message: "Free has no paid capacity" });
    }
    if (capacity.protected_repos > capacity.included_repos + capacity.paid_extra_slots) {
      ctx.addIssue({
        code: "custom",
        path: ["capacity", "protected_repos"],
        message: "protected repositories never exceed included plus paid capacity",
      });
    }
    const subscription = billing.subscription;
    if (
      subscription !== null &&
      subscription.period_end_at.getTime() <= subscription.period_start_at.getTime()
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["subscription"],
        message: "a period ends after it starts",
      });
    }
    const grace = billing.grace;
    if (
      grace !== null &&
      grace.deadline_at.getTime() - grace.started_at.getTime() !== DURATIONS.paymentGracePeriod
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["grace", "deadline_at"],
        message: "the grace deadline is seven days after the first failure",
      });
    }
    if (billing.retained_repo !== null && !billing.retained_repo_selected) {
      ctx.addIssue({
        code: "custom",
        path: ["retained_repo_selected"],
        message: "a shown retained repo is selected",
      });
    }
  }, whenValid);
export type BillingStatus = z.output<typeof billingStatusSchema>;

export const billingResponseSchema = z.strictObject({ billing: billingStatusSchema });

// ---- Checkout and portal ----

/** Stripe-hosted pages. They are short-lived bearer links: returned once, never logged. */
export const stripeCheckoutUrlSchema = httpsUrlSchema(/^checkout\.stripe\.com$/);
export const stripePortalUrlSchema = httpsUrlSchema(/^billing\.stripe\.com$/);
/**
 * Stripe's hosted invoice page, where the customer authenticates (3-D Secure) a capacity charge that
 * waits for them. A bearer link like the others: returned once, never stored or logged.
 */
export const stripeInvoicePageUrlSchema = httpsUrlSchema(/^invoice\.stripe\.com$/);

// ---- Capacity ----

/** Additional paid slots one quote may add. */
export const MAX_ADDITIONAL_SLOTS = LIMITS.capacity.maxAdditionalSlotsPerQuote;

const CONFIRMED: ReadonlySet<CapacityQuoteState> = new Set(CONFIRMED_CAPACITY_QUOTE_STATES);
const SETTLED: ReadonlySet<CapacityQuoteState> = new Set(SETTLED_CAPACITY_QUOTE_STATES);

/**
 * A capacity preview: "Preview and explicitly confirm the prorated charge before adding paid
 * capacity". `quantity` is the paid extra-slot count after confirmation; `amount_due_now_usd` the
 * prorated charge (tax is shown by Stripe); `monthly_total_usd` the subscription price afterwards,
 * $20 plus $10 per extra repository.
 */
export const capacityQuoteSchema = z
  .strictObject({
    id: quoteIdSchema,
    state: capacityQuoteStateSchema,
    additional_slots: z.int().min(1).max(MAX_ADDITIONAL_SLOTS),
    quantity: z.int().positive(),
    amount_due_now_usd: nonNegativeMicroUsdWireSchema,
    monthly_total_usd: nonNegativeMicroUsdWireSchema,
    currency: z.literal("usd"),
    /** The proration instant the confirmation reuses so the charge matches the quote. */
    prorated_from_at: utcDateTimeSchema,
    period_end_at: utcDateTimeSchema,
    expires_at: utcDateTimeSchema,
    created_at: utcDateTimeSchema,
    /** When a billing-authorized human confirmed it; null until then. */
    confirmed_at: utcDateTimeSchema.nullable(),
    /** When Stripe's payment outcome (paid or declined) was recorded. */
    settled_at: utcDateTimeSchema.nullable(),
  })
  .superRefine((quote, ctx) => {
    if (CONFIRMED.has(quote.state) !== (quote.confirmed_at !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["confirmed_at"],
        message: "exactly confirmed quotes record when they were confirmed",
      });
    }
    if (SETTLED.has(quote.state) !== (quote.settled_at !== null)) {
      ctx.addIssue({
        code: "custom",
        path: ["settled_at"],
        message: "exactly paid or declined quotes record the payment outcome",
      });
    }
    if (quote.quantity < quote.additional_slots) {
      ctx.addIssue({
        code: "custom",
        path: ["quantity"],
        message: "the new quantity includes the added slots",
      });
    }
    if (quote.monthly_total_usd !== PLUS_BASE + EXTRA_REPO * BigInt(quote.quantity)) {
      ctx.addIssue({
        code: "custom",
        path: ["monthly_total_usd"],
        message: "the monthly total is $20 plus $10 per extra repository",
      });
    }
    if (quote.amount_due_now_usd > EXTRA_REPO * BigInt(quote.additional_slots)) {
      ctx.addIssue({
        code: "custom",
        path: ["amount_due_now_usd"],
        message: "a prorated charge never exceeds a full month of the added slots",
      });
    }
    if (quote.expires_at.getTime() <= quote.created_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["expires_at"],
        message: "a quote expires after it is created",
      });
    }
    if (quote.period_end_at.getTime() <= quote.prorated_from_at.getTime()) {
      ctx.addIssue({
        code: "custom",
        path: ["period_end_at"],
        message: "proration runs until the period end",
      });
    }
  }, whenValid);
export type CapacityQuote = z.output<typeof capacityQuoteSchema>;

export const previewCapacityBodySchema = z.strictObject({
  additional_slots: z.int().min(1).max(MAX_ADDITIONAL_SLOTS),
});

/**
 * "bind confirmation to quoted quantity/amount/expiry": the client echoes exactly what it showed;
 * any difference is `quote_mismatch`, a past expiry `quote_expired`. `Idempotency-Key` is required.
 */
export const confirmCapacityBodySchema = z.strictObject({
  quote_id: quoteIdSchema,
  additional_slots: z.int().min(1).max(MAX_ADDITIONAL_SLOTS),
  quantity: z.int().positive(),
  amount_due_now_usd: nonNegativeMicroUsdWireSchema,
  expires_at: utcDateTimeSchema,
});

// ---- Overage consent ----

/** SPEC: "Overages are actual approved model + sandbox cost × 1.20" (`OVERAGE_MARKUP`). */
export const OVERAGE_MARKUP_MULTIPLIER = "1.20";

/**
 * Overage consent: explicit, versioned, with a finite spending limit on the amount charged after
 * markup ("The limit is on the amount charged after markup"). Version 0 means never set.
 *
 * `enabled` and `cycle_spend_limit_usd` are the consent in effect now. A Free downgrade voids a
 * consent given before it ("Free … cannot buy AI overages without upgrading to Plus"; a re-upgrade
 * restores nothing silently): `voided_by_downgrade` then says the latest version enabled overages
 * but no longer applies, so overages are off until a billing-authorized human enables them again.
 * `version`, `authorized_by` and `authorized_at` stay the latest recorded version's, so
 * `expected_version` still binds.
 */
export const overageConsentSchema = z
  .strictObject({
    enabled: z.boolean(),
    cycle_spend_limit_usd: nonNegativeMicroUsdWireSchema.nullable(),
    version: z.int().nonnegative(),
    markup_multiplier: z.literal(OVERAGE_MARKUP_MULTIPLIER),
    authorized_by: userRefSchema.nullable(),
    authorized_at: utcDateTimeSchema.nullable(),
    voided_by_downgrade: z.boolean(),
  })
  .superRefine((consent, ctx) => {
    if (consent.voided_by_downgrade && (consent.enabled || consent.version === 0)) {
      ctx.addIssue({
        code: "custom",
        path: ["voided_by_downgrade"],
        message: "only a recorded consent is voided, and a voided consent is not in effect",
      });
    }
    const limit = consent.cycle_spend_limit_usd;
    if (consent.enabled !== (limit !== null) || (limit !== null && limit <= 0n)) {
      ctx.addIssue({
        code: "custom",
        path: ["cycle_spend_limit_usd"],
        message: "enabled overages have a positive finite limit; disabled ones have none",
      });
    }
    const recorded = consent.version > 0;
    if (
      recorded !== (consent.authorized_by !== null) ||
      recorded !== (consent.authorized_at !== null)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["authorized_by"],
        message: "every recorded consent version names who set it and when",
      });
    }
    if (!recorded && consent.enabled) {
      ctx.addIssue({ code: "custom", path: ["enabled"], message: "overages start disabled" });
    }
  }, whenValid);
export type OverageConsent = z.output<typeof overageConsentSchema>;

/** A positive micro-USD limit. */
const positiveLimitSchema = nonNegativeMicroUsdWireSchema.refine((amount) => amount > 0n, {
  error: "the spending limit must be positive",
});

/**
 * `PUT /v1/billing/overages`: an explicit decision against the consent version the human saw
 * (`expected_version`; a stale version is `412 precondition_failed`). Enabling needs a finite
 * positive post-markup cycle limit; there is no unlimited option.
 */
export const putOveragesBodySchema = z.discriminatedUnion("enabled", [
  z.strictObject({
    enabled: z.literal(true),
    cycle_spend_limit_usd: positiveLimitSchema,
    expected_version: z.int().nonnegative(),
  }),
  z.strictObject({ enabled: z.literal(false), expected_version: z.int().nonnegative() }),
]);

// ---- Plus coupons ----

/**
 * A coupon code in its canonical form (SPEC "Plus coupons": "4 to 32 characters (`A–Z`, `0–9`,
 * `-`), case-insensitive"): input is upper-cased, and at least one letter or digit is required.
 */
export const couponCodeSchema = z
  .string()
  .trim()
  .toUpperCase()
  .regex(/^[A-Z0-9-]{4,32}$/, { error: "4 to 32 letters, digits or hyphens" })
  .regex(/[A-Z0-9]/, { error: "at least one letter or digit" });

/**
 * The account's coupon benefit (SPEC "Disclosure": "The billing page shows 'Plus (coupon `CODE`)'
 * and its end date"). A Kovo grant is `active` from redemption with both dates; a Stripe-mode
 * redemption (admin-site PR 10b) is `reserved` until its Checkout's payment and has no dates yet.
 */
export const billingCouponSchema = z
  .strictObject({
    code: z.string().regex(/^[A-Z0-9-]{4,32}$/),
    mode: z.enum(["stripe", "kovo_grant"]),
    state: z.enum(["reserved", "active"]),
    months: z.int().min(1).max(12),
    redeemed_at: utcDateTimeSchema,
    starts_at: utcDateTimeSchema.nullable(),
    ends_at: utcDateTimeSchema.nullable(),
  })
  .refine(
    (coupon) =>
      coupon.mode === "stripe" ||
      (coupon.state === "active" && coupon.starts_at !== null && coupon.ends_at !== null),
    { ...whenValid, error: "a Kovo grant is active from redemption with its dates" },
  )
  .refine(
    (coupon) =>
      coupon.starts_at === null ||
      coupon.ends_at === null ||
      coupon.ends_at.getTime() > coupon.starts_at.getTime(),
    { ...whenValid, error: "a coupon benefit ends after it starts" },
  );
export type BillingCoupon = z.output<typeof billingCouponSchema>;

// ---- Endpoints ----

function billingAuthorization(
  spec: string,
  repoAuthority?: AuthorizationInit["repoAuthority"],
): AuthorizationInit {
  return {
    spec,
    actors: ["human_session"],
    tenant: "account_context",
    accountRoles: BILLING_ROLES,
    billingAuthority: true,
    ...(repoAuthority === undefined ? {} : { repoAuthority }),
  };
}

const ROW_CHECKOUT = "Billing-authorized human; server-selected Stripe customer/account";
const ROW_CAPACITY = "Billing-authorized human; bind confirmation to quoted quantity/amount/expiry";
const ROW_CANCEL = "Billing-authorized human; period-end cancellation";
const ROW_OVERAGES =
  "Billing-authorized human; explicit consent/version and finite post-markup cap";

export const ownerPlanGrantSchema = z.strictObject({
  account_id: accountIdSchema,
  plan: z.literal("plus"),
  reason: z.string().min(1).max(240),
  granted_by: z.literal("owner"),
  granted_at: utcDateTimeSchema,
});
export type OwnerPlanGrant = z.output<typeof ownerPlanGrantSchema>;

const ROW_COUPON =
  "Billing-authorized human; every constraint checked atomically, one refusal for every reason";
const ROW_COUPON_READ = "Billing-authorized human; the account's coupon benefit while in force";

export const BILLING_ENDPOINTS = {
  getBillingPlanGrant: defineEndpoint({
    operationId: "getBillingPlanGrant",
    area: "billing",
    method: "GET",
    path: "/v1/billing/plan-grant",
    summary: "Read the owner-directed Plus grant without changing Stripe billing.",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    params: null,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ grant: ownerPlanGrantSchema.nullable() }) },
    authorization: {
      ...billingAuthorization(
        "owner/admin/billing manager manage subscription, capacity and overage spending. Billing-only views expose counts and charges, not private repository names or findings the viewer cannot access.",
      ),
      managementPermission: "getBilling",
    },
  }),
  redeemCoupon: defineEndpoint({
    operationId: "redeemCoupon",
    area: "billing",
    method: "POST",
    path: "/v1/billing/coupon-redemptions",
    summary:
      "Redeem a Plus coupon code for the account. A Kovo-grant code activates Plus for its months at once; every reason a code cannot be redeemed answers the same refusal.",
    source: { kind: "spec_row", path: "/v1/billing/coupon-redemptions" },
    auditActions: ["billing.plus_activated"],
    params: null,
    query: null,
    body: z.strictObject({ code: couponCodeSchema }),
    responses: {
      201: z.strictObject({ coupon: billingCouponSchema }),
      // The account already holds this coupon's benefit (a retried redemption).
      200: z.strictObject({ coupon: billingCouponSchema }),
    },
    authorization: billingAuthorization(ROW_COUPON),
    idempotency: "accepted",
    problems: ["coupon_not_redeemable"],
  }),
  getBillingCoupon: defineEndpoint({
    operationId: "getBillingCoupon",
    area: "billing",
    method: "GET",
    path: "/v1/billing/coupon",
    summary: "Read the account's coupon benefit while it is in force.",
    source: { kind: "spec_row", path: "/v1/billing/coupon" },
    params: null,
    query: null,
    body: null,
    responses: { 200: z.strictObject({ coupon: billingCouponSchema.nullable() }) },
    authorization: billingAuthorization(ROW_COUPON_READ),
  }),
  getBilling: defineEndpoint({
    operationId: "getBilling",
    area: "billing",
    method: "GET",
    path: "/v1/billing",
    summary: "Read the plan, subscription, grace period and protected capacity.",
    source: { kind: "spec_implied", section: "Web application and onboarding UI" },
    params: null,
    query: null,
    body: null,
    responses: { 200: billingResponseSchema },
    authorization: billingAuthorization(
      "owner/admin/billing manager manage subscription, capacity and overage spending. Billing-only views expose counts and charges, not private repository names or findings the viewer cannot access.",
    ),
  }),
  startCheckout: defineEndpoint({
    operationId: "startCheckout",
    area: "billing",
    method: "POST",
    path: "/v1/billing/checkout",
    summary: "Open Stripe Checkout for Kovo Plus; entitlement starts only from the payment event.",
    source: { kind: "spec_row", path: "/v1/billing/checkout" },
    // The first Checkout also binds the account's server-selected Stripe customer.
    auditActions: ["billing.checkout_started", "billing.customer_bound"],
    params: null,
    query: null,
    body: emptyBodySchema,
    responses: {
      201: z.strictObject({ checkout_url: stripeCheckoutUrlSchema, expires_at: utcDateTimeSchema }),
    },
    authorization: billingAuthorization(ROW_CHECKOUT),
    // The URL is a bearer link: a replay would have to store it. Repeats are harmless instead (the
    // server keeps one open session per account; docs/decisions/contracts.md "One-time secrets").
    oneTimeFields: ["/checkout_url"],
    problems: ["conflict", "upstream_error"],
  }),
  openPortal: defineEndpoint({
    operationId: "openPortal",
    area: "billing",
    method: "POST",
    path: "/v1/billing/portal",
    summary: "Open the Stripe Customer Portal for payment methods and invoices.",
    source: { kind: "spec_row", path: "/v1/billing/portal" },
    auditActions: ["billing.portal_opened"],
    params: null,
    query: null,
    body: emptyBodySchema,
    responses: { 201: z.strictObject({ portal_url: stripePortalUrlSchema }) },
    authorization: billingAuthorization(ROW_CHECKOUT),
    oneTimeFields: ["/portal_url"],
    problems: ["conflict", "upstream_error"],
  }),
  previewCapacity: defineEndpoint({
    operationId: "previewCapacity",
    area: "billing",
    method: "POST",
    path: "/v1/billing/capacity/preview",
    summary: "Quote the prorated charge for additional protected-repository slots.",
    source: { kind: "spec_row", path: "/v1/billing/capacity/preview" },
    auditActions: ["billing.capacity_previewed"],
    params: null,
    query: null,
    body: previewCapacityBodySchema,
    responses: {
      201: z
        .strictObject({ quote: capacityQuoteSchema })
        .refine((body) => body.quote.state === "open", {
          ...whenValid,
          error: "a new quote is open",
        }),
    },
    authorization: billingAuthorization(ROW_CAPACITY),
    idempotency: "accepted",
    problems: ["plan_required", "payment_past_due", "upstream_error"],
  }),
  confirmCapacity: defineEndpoint({
    operationId: "confirmCapacity",
    area: "billing",
    method: "POST",
    path: "/v1/billing/capacity/confirm",
    summary:
      "Confirm exactly the quoted charge. The charge runs through the billing outbox (202, payment pending); successful payment activates the slots immediately and fills pending protection requests in request order. A replay after payment answers 200.",
    source: { kind: "spec_row", path: "/v1/billing/capacity/confirm" },
    auditActions: ["billing.capacity_confirmed"],
    params: null,
    query: null,
    body: confirmCapacityBodySchema,
    responses: {
      // "Use application outboxes for … Stripe charges": the charge is asynchronous.
      202: z
        .strictObject({ quote: capacityQuoteSchema })
        .refine((body) => body.quote.state === "payment_pending", {
          ...whenValid,
          error: "a confirmed quote waits for its payment",
        }),
      // A replay of a confirmation whose payment already succeeded.
      200: z
        .strictObject({ quote: capacityQuoteSchema, billing: billingStatusSchema })
        .refine((body) => body.quote.state === "paid", {
          ...whenValid,
          error: "a paid quote's capacity is active",
        }),
    },
    authorization: billingAuthorization(ROW_CAPACITY),
    idempotency: "required",
    problems: [
      "plan_required",
      "quote_expired",
      "quote_mismatch",
      "payment_past_due",
      "conflict",
      "upstream_error",
    ],
  }),
  getCapacityQuote: defineEndpoint({
    operationId: "getCapacityQuote",
    area: "billing",
    method: "GET",
    path: "/v1/billing/capacity/quotes/{quote}",
    summary:
      "Read one capacity quote, to follow a confirmation until its payment is paid or declined. While a card's 3-D Secure authentication is needed, `payment_confirmation_url` is Stripe's hosted page where the customer completes the charge; the slots activate once it is paid.",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    params: z.strictObject({ quote: quoteIdSchema }),
    query: null,
    body: null,
    responses: {
      200: z
        .strictObject({
          quote: capacityQuoteSchema,
          payment_confirmation_url: stripeInvoicePageUrlSchema.nullable(),
        })
        .refine(
          (body) =>
            body.payment_confirmation_url === null || body.quote.state === "payment_pending",
          { ...whenValid, error: "only a charge waiting for its payment is confirmed on Stripe" },
        ),
    },
    // Read live from Stripe for each request, never stored for a replay.
    oneTimeFields: ["/payment_confirmation_url"],
    authorization: {
      ...billingAuthorization(
        "Preview and explicitly confirm the prorated charge before adding paid capacity; successful payment activates it immediately.",
      ),
      // The quote's own account, read from the quote row, never from the caller.
      tenant: "path_resource",
    },
  }),
  cancelSubscription: defineEndpoint({
    operationId: "cancelSubscription",
    area: "billing",
    method: "POST",
    path: "/v1/billing/cancel",
    summary:
      "Cancel Plus at the end of the paid period, optionally choosing the repository kept on Free.",
    source: { kind: "spec_row", path: "/v1/billing/cancel" },
    auditActions: ["billing.cancel_requested"],
    params: null,
    query: null,
    body: z.strictObject({ retained_repo_id: repoIdSchema.exactOptional() }),
    responses: {
      200: billingResponseSchema.refine(
        (body) => body.billing.subscription?.cancel_at_period_end === true,
        { ...whenValid, error: "the subscription cancels at period end" },
      ),
    },
    // A `retained_repo_id` is a Free protection selection: verified GitHub administration of it
    // ("Free/available-capacity selection still requires repository authority").
    authorization: billingAuthorization(ROW_CANCEL, { level: "admin", over: "body_repos" }),
    idempotency: "accepted",
    problems: ["conflict", "upstream_error"],
  }),
  setRetainedRepo: defineEndpoint({
    operationId: "setRetainedRepo",
    area: "billing",
    method: "PUT",
    path: "/v1/billing/retained-repo",
    summary: "Choose which repository stays protected if the account returns to Free.",
    source: { kind: "spec_implied", section: "Plans, billing, and usage" },
    auditActions: ["billing.retained_repo_selected"],
    params: null,
    query: null,
    body: z.strictObject({ repo_id: repoIdSchema }),
    responses: {
      200: billingResponseSchema.refine((body) => body.billing.retained_repo !== null, {
        ...whenValid,
        error: "the retained repository is set",
      }),
    },
    // The repository kept protected on Free (every other one becomes inactive) is a protection
    // selection: billing authority and verified GitHub administration of that repository.
    authorization: billingAuthorization(
      "Before downgrade, ask which repo to retain on Free; otherwise retain the earliest-enabled eligible repo (stable repo ID breaks ties).",
      { level: "admin", over: "body_repos" },
    ),
    problems: ["conflict"],
  }),
  getOverages: defineEndpoint({
    operationId: "getOverages",
    area: "billing",
    method: "GET",
    path: "/v1/billing/overages",
    summary: "Read the overage consent, its version and post-markup cycle limit.",
    source: { kind: "spec_row", path: "/v1/billing/overages" },
    params: null,
    query: null,
    body: null,
    responses: { 200: overageConsentSchema },
    authorization: billingAuthorization(ROW_OVERAGES),
  }),
  putOverages: defineEndpoint({
    operationId: "putOverages",
    area: "billing",
    method: "PUT",
    path: "/v1/billing/overages",
    summary: "Enable overages with a finite post-markup cycle limit, or disable them.",
    source: { kind: "spec_row", path: "/v1/billing/overages" },
    auditActions: ["billing.overages_updated"],
    params: null,
    query: null,
    body: putOveragesBodySchema,
    responses: { 200: overageConsentSchema },
    authorization: billingAuthorization(ROW_OVERAGES),
    problems: ["plan_required", "precondition_failed"],
  }),
} as const;
