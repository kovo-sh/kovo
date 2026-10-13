import { z } from "zod";

// Billing, usage and spend (SPEC "Plans, billing, and usage", data model billing tables).

/** Stripe subscription statuses (`subscriptions.status`, stripe 22.6.2 `Subscription.Status`). */
export const SUBSCRIPTION_STATUSES = [
  "incomplete",
  "incomplete_expired",
  "trialing",
  "active",
  "past_due",
  "canceled",
  "unpaid",
  "paused",
] as const;
export const subscriptionStatusSchema = z.enum(SUBSCRIPTION_STATUSES);
export type SubscriptionStatus = z.infer<typeof subscriptionStatusSchema>;

/** Stripe invoice statuses (grace is tracked per invoice). */
export const INVOICE_STATUSES = ["draft", "open", "paid", "uncollectible", "void"] as const;
export const invoiceStatusSchema = z.enum(INVOICE_STATUSES);
export type InvoiceStatus = z.infer<typeof invoiceStatusSchema>;

/**
 * Who funds a unit of work (`usage_reservations.source`, `usage_ledger.funding_source`; SPEC:
 * "included|overage|kovo_funded"). Deterministic work beyond the allowance is Kovo-funded; Free has
 * zero AI entitlement.
 */
export const FUNDING_SOURCES = ["included", "overage", "kovo_funded"] as const;
export const fundingSourceSchema = z.enum(FUNDING_SOURCES);
export type FundingSource = z.infer<typeof fundingSourceSchema>;

/**
 * What a reservation or charge funds (`usage_reservations.work`, `usage_ledger.work`).
 * `ai_assisted` needs Plus and AI funding (the included allowance or consented overage; "At the
 * allowance, new AI-assisted work waits"); `deterministic` is never blocked by the allowance and is
 * never overage-funded ("Deterministic work beyond the allowance is Kovo-funded and is not
 * retroactively invoiced"). Model charges are always `ai_assisted`.
 */
export const WORK_KINDS = ["ai_assisted", "deterministic"] as const;
export const workKindSchema = z.enum(WORK_KINDS);
export type WorkKind = z.infer<typeof workKindSchema>;

/**
 * Funding a deterministic run or charge may have. SPEC: "Deterministic work beyond the allowance is
 * Kovo-funded and is not retroactively invoiced": never `overage`.
 */
export type DeterministicFunding = Exclude<FundingSource, "overage">;

/**
 * Funding an AI-assisted reservation may have: the included allowance or consented overage. AI work
 * is never reserved as `kovo_funded` ("At the allowance, new AI-assisted work waits").
 */
export type AiReservationFunding = Exclude<FundingSource, "kovo_funded">;

/**
 * A reservation's work kind and the funding of its maximum (the `usage_reservations.work_source`
 * CHECK): shared by `UsageService` and `@kovo/core/billing` so the rule has one definition.
 */
export type ReservationFunding =
  | { readonly work: "ai_assisted"; readonly source: AiReservationFunding }
  | { readonly work: "deterministic"; readonly source: DeterministicFunding };

/** `usage_reservations.source` uses the same values as the ledger's funding source. */
export const RESERVATION_SOURCES = FUNDING_SOURCES;
export const reservationSourceSchema = fundingSourceSchema;
export type ReservationSource = FundingSource;

/**
 * `usage_reservations.status`: "Reserve maximum remaining run cost transactionally … reconcile
 * reservations against actual usage … Released reservations do not create usage. Uncertain costs
 * retain reservations until reconciled".
 */
export const RESERVATION_STATUSES = ["reserved", "uncertain", "settled", "released"] as const;
export const reservationStatusSchema = z.enum(RESERVATION_STATUSES);
export type ReservationStatus = z.infer<typeof reservationStatusSchema>;

/** Reservations that still hold budget. */
export const HELD_RESERVATION_STATUSES = [
  "reserved",
  "uncertain",
] as const satisfies readonly ReservationStatus[];

/** `usage_ledger.kind` ("model|sandbox"). */
export const USAGE_KINDS = ["model", "sandbox"] as const;
export const usageKindSchema = z.enum(USAGE_KINDS);
export type UsageKind = z.infer<typeof usageKindSchema>;

/** `usage_ledger.unit`: supporting measurements ("Tokens/minutes are supporting measurements"). */
export const USAGE_UNITS = ["tokens", "sandbox_seconds"] as const;
export const usageUnitSchema = z.enum(USAGE_UNITS);
export type UsageUnit = z.infer<typeof usageUnitSchema>;

/** `usage_ledger.provider`: who reported the charge. */
export const USAGE_PROVIDERS = ["openrouter", "daytona"] as const;
export const usageProviderSchema = z.enum(USAGE_PROVIDERS);
export type UsageProvider = z.infer<typeof usageProviderSchema>;

/**
 * Who reports each usage kind and in which unit (the `usage_ledger` and `pending_provider_charges`
 * CHECKs `provider_matches_kind` and `unit_matches_kind`): model charges are OpenRouter generations
 * counted in tokens; sandbox charges are sandbox runs counted in seconds.
 */
export const USAGE_KIND_REPORTING = {
  model: { provider: "openrouter", unit: "tokens" },
  sandbox: { provider: "daytona", unit: "sandbox_seconds" },
} as const satisfies Record<
  UsageKind,
  { readonly provider: UsageProvider; readonly unit: UsageUnit }
>;

/** `overage_invoice_items.status` (idempotent Stripe invoice items, reconciled by listing). */
export const OVERAGE_ITEM_STATUSES = ["pending", "uncertain", "created", "failed"] as const;
export const overageItemStatusSchema = z.enum(OVERAGE_ITEM_STATUSES);
export type OverageItemStatus = z.infer<typeof overageItemStatusSchema>;

/**
 * `billing_adjustments.reason`: what added to a cycle's included-cost allowance. "1× the account's
 * paid subscription amount … Successful prorated capacity charges add the same prorated dollar
 * amount"; "Successful recovery replenishes the paid cycle once".
 */
export const BILLING_ADJUSTMENT_REASONS = [
  "subscription_period",
  "capacity_proration",
  "payment_recovery",
] as const;
export const billingAdjustmentReasonSchema = z.enum(BILLING_ADJUSTMENT_REASONS);
export type BillingAdjustmentReason = z.infer<typeof billingAdjustmentReasonSchema>;

/**
 * Capacity quote lifecycle: "bind confirmation to quoted quantity/amount/expiry"; "successful
 * payment activates it immediately"; "Use application outboxes for … Stripe charges". An `open`
 * quote is confirmed into `payment_pending` (the charge runs through the outbox as a
 * `capacity_change` workflow), then becomes `paid` (capacity active) or `declined` (Stripe refused
 * the payment; nothing activates). An unconfirmed quote `expired` or was `superseded` by a newer
 * preview.
 */
export const CAPACITY_QUOTE_STATES = [
  "open",
  "payment_pending",
  "paid",
  "declined",
  "expired",
  "superseded",
] as const;
export const capacityQuoteStateSchema = z.enum(CAPACITY_QUOTE_STATES);
export type CapacityQuoteState = z.infer<typeof capacityQuoteStateSchema>;

/** Quote states after a billing-authorized confirmation. */
export const CONFIRMED_CAPACITY_QUOTE_STATES = [
  "payment_pending",
  "paid",
  "declined",
] as const satisfies readonly CapacityQuoteState[];

/** Quote states whose payment outcome is known. */
export const SETTLED_CAPACITY_QUOTE_STATES = [
  "paid",
  "declined",
] as const satisfies readonly CapacityQuoteState[];

/** Failed-payment milestones: billing emails "on days 0, 3, 6 (24-hour warning), and 7". */
export const GRACE_MILESTONES = ["day_0", "day_3", "day_6", "day_7"] as const;
export const graceMilestoneSchema = z.enum(GRACE_MILESTONES);
export type GraceMilestone = z.infer<typeof graceMilestoneSchema>;

/** Why a Plus account returned to Free. */
export const DOWNGRADE_CAUSES = ["cancellation", "payment_failure"] as const;
export const downgradeCauseSchema = z.enum(DOWNGRADE_CAUSES);
export type DowngradeCause = z.infer<typeof downgradeCauseSchema>;

/**
 * An account's entitlement state (`@kovo/core/billing` `deriveEntitlement`, EntitlementService).
 * SPEC: "Successful payment events establish entitlement, never a browser redirect." "Initial
 * unpaid Checkout does not activate Plus." "Cancellation keeps Plus until the paid period ends." A
 * failed renewal's grace period keeps paid features "within the remaining previously funded
 * allowance, but new paid-overage work pauses".
 * - `free`: no Plus subscription in effect (never had one, downgraded, or its paid period ended).
 * - `plus_pending`: Checkout started but its first payment has not succeeded; entitles nothing.
 * - `plus_active`: paid and current.
 * - `plus_canceling`: `cancel_at_period_end`; Plus until the paid period ends.
 * - `plus_grace`: a failed renewal inside its 7-day grace period.
 */
export const ENTITLEMENT_STATES = [
  "free",
  "plus_pending",
  "plus_active",
  "plus_canceling",
  "plus_grace",
] as const;
export const entitlementStateSchema = z.enum(ENTITLEMENT_STATES);
export type EntitlementState = z.infer<typeof entitlementStateSchema>;

/** Plus features gated by entitlement. */
export const ENTITLED_FEATURES = [
  "ai",
  "autopilot",
  "paid_overage",
  "additional_capacity",
] as const;
export const entitledFeatureSchema = z.enum(ENTITLED_FEATURES);
export type EntitledFeature = z.infer<typeof entitledFeatureSchema>;

/**
 * Why an entitled feature is unavailable: `free_plan` and `plus_inactive` map to `plan_required`
 * (the problem and the wait), `payment_grace` to the `payment_past_due` wait.
 */
export const ENTITLEMENT_DENIALS = ["free_plan", "plus_inactive", "payment_grace"] as const;
export const entitlementDenialSchema = z.enum(ENTITLEMENT_DENIALS);
export type EntitlementDenial = z.infer<typeof entitlementDenialSchema>;

/** Whether one entitled feature is available now, and if not, why. */
export type FeatureEntitlement =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly denial: EntitlementDenial };

/** Signed inbound webhook providers (`provider_events.provider`). */
export const EVENT_PROVIDERS = ["github", "stripe", "resend"] as const;
export const eventProviderSchema = z.enum(EVENT_PROVIDERS);
export type EventProvider = z.infer<typeof eventProviderSchema>;

/**
 * `provider_events.status`: "persist deduplicated event IDs, acknowledge quickly, and process
 * asynchronously".
 */
export const PROVIDER_EVENT_STATUSES = [
  "received",
  "processing",
  "processed",
  "ignored",
  "failed",
] as const;
export const providerEventStatusSchema = z.enum(PROVIDER_EVENT_STATUSES);
export type ProviderEventStatus = z.infer<typeof providerEventStatusSchema>;
