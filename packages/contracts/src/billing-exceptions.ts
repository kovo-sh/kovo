import { z } from "zod";

/** Fixed low-cardinality labels of the existing billing repair counter. */
export const BILLING_EXCEPTION_REASONS = [
  "adjustment_without_cycle",
  "capacity_paid_on_free",
  "charge_mismatch",
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
  "paid_after_deletion",
  "paid_after_downgrade",
  "renewal_quantity",
  "repair_capacity_charge",
  "repair_downgrade",
  "repair_grace_deadline",
  "repair_lookup_failed",
  "repair_overage_invoicing",
  "repair_stripe_event",
  "stale_key_replay",
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
