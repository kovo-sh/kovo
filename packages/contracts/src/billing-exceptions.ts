import { z } from "zod";

/**
 * Fixed low-cardinality labels of the existing billing repair counter.
 *
 * Stripe refunded a charge or a dispute opened or closed (plans/stripe-managed-payments.md §5.1):
 * an operator notice; entitlement and funded allowance are unchanged. A managed cycle's metered
 * overage report was refused (`overage_meter_report_failed`), or Stripe's meter summary matched
 * neither outcome of an uncertain report (`overage_meter_mismatch`; §3.1): nothing is re-sent.
 * The live Checkout probe (§6.5 part 2) failed (`checkout_probe_failed`, which also fails the
 * release's `workers-ready` gate) or someone completed a probe session, whose subscription was
 * canceled at once (`checkout_probe_completed`: an operator refunds the payment). The configured
 * AI-overage price does not have the terms §3.1 fixes (`overage_price_mismatch`, #5514): nothing
 * is charged through it before Phase 5; an operator corrects the price or the configuration.
 */
export const BILLING_EXCEPTION_REASONS = [
  "adjustment_without_cycle",
  "capacity_paid_on_free",
  "charge_mismatch",
  "checkout_no_payment_methods",
  "checkout_probe_completed",
  "checkout_probe_failed",
  "downgrade_subscription_replaced",
  "duplicate_subscription",
  "grace_due_invalid",
  "grace_due_observation_failed",
  "grace_due_retry_exhausted",
  "grace_due_start_failed",
  "missed_allowance_adjusted",
  "missed_cancellation_scheduled",
  "missed_capacity_activated",
  "missed_downgrade_scheduled",
  "missed_grace_cleared",
  "missed_ignored",
  "missed_payment_failed",
  "missed_payment_recovered",
  "missed_plus_activated",
  "over_capacity",
  "overage_meter_mismatch",
  "overage_meter_report_failed",
  "overage_price_mismatch",
  "paid_after_deletion",
  "paid_after_downgrade",
  "project_activation_stalled",
  "renewal_quantity",
  "repair_capacity_charge",
  "repair_downgrade",
  "repair_grace_deadline",
  "repair_lookup_failed",
  "repair_overage_invoicing",
  "repair_stripe_event",
  "stale_key_replay",
  "stripe_charge_refunded",
  "stripe_dispute_closed",
  "stripe_dispute_opened",
] as const;

export type BillingExceptionReason = (typeof BILLING_EXCEPTION_REASONS)[number];

/** Stored labels remain readable across rollback and future reason additions. */
export function billingExceptionReasonKind(
  reason: string,
): BillingExceptionReason | "unknown_reason" {
  return BILLING_EXCEPTION_REASONS.find((known) => known === reason) ?? "unknown_reason";
}

export const BILLING_EXCEPTION_SUBJECT_TYPES = [
  "subscription",
  "invoice",
  "invoice_item",
  "customer",
  "cycle",
  "fix",
  "quote",
  "provider_event",
] as const;
export type BillingExceptionSubjectType = (typeof BILLING_EXCEPTION_SUBJECT_TYPES)[number];

export const billingExceptionIdSchema = z.uuid().brand<"BillingExceptionId">();
export type BillingExceptionId = z.infer<typeof billingExceptionIdSchema>;
