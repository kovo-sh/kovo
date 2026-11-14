import { z } from "zod";

import { usd, type MicroUsd } from "./money.js";

// Kovo's own support spend (owner D-136 (amended), D-144; plans/support-flow.md §8.7,
// §16.2). Support model and sandbox work is funded by Kovo through its own purpose and ledger,
// never by the customer's AI allowance, reservations or billing, so Free accounts and
// account-level tickets work too. These amounts are owner decisions: do not change them without
// a recorded owner raise.

/**
 * The operating-cost purpose support work is admitted under. It is deliberately not a customer
 * `RelayPurpose`: the product relay's job grants can never fund it.
 */
export const SUPPORT_SPEND_PURPOSE = "support" as const;

/**
 * Which monthly ledger a case draws on. `simulation` is the separate D-144 budget for cases from
 * accounts flagged `simulation`, so a simulation never starves real customers.
 */
export const SUPPORT_BUDGET_LEDGERS = ["support", "simulation"] as const;
export const supportBudgetLedgerSchema = z.enum(SUPPORT_BUDGET_LEDGERS);
export type SupportBudgetLedger = z.infer<typeof supportBudgetLedgerSchema>;

/** Owner D-136 (amended): $5 of model and sandbox spend over a case's lifetime. */
export const SUPPORT_CASE_BUDGET: MicroUsd = usd(5n);

/**
 * Each ledger's UTC-month total: owner D-136 (amended) $500 for real cases, owner D-144 (a,
 * amended) $200 for simulated ones.
 */
export const SUPPORT_MONTH_BUDGETS: Readonly<Record<SupportBudgetLedger, MicroUsd>> = {
  support: usd(500n),
  simulation: usd(200n),
};

/** The support pipeline's metered operations (plans/support-flow.md §8.7). */
export const SUPPORT_BUDGET_OPERATIONS = [
  "triage",
  "debugger",
  "screener",
  "clean_room",
  "follow_up",
  "verification",
  "reply",
] as const;
export const supportBudgetOperationSchema = z.enum(SUPPORT_BUDGET_OPERATIONS);
export type SupportBudgetOperation = z.infer<typeof supportBudgetOperationSchema>;

/** What a reservation pays for. */
export const SUPPORT_BUDGET_RESOURCES = ["model", "sandbox"] as const;
export const supportBudgetResourceSchema = z.enum(SUPPORT_BUDGET_RESOURCES);
export type SupportBudgetResource = z.infer<typeof supportBudgetResourceSchema>;

/**
 * A reservation's state. `held` counts its worst case; `settled` counts its known cost; an
 * `uncertain` settlement keeps the worst case held until a known cost replaces it.
 */
export const SUPPORT_BUDGET_RESERVATION_STATUSES = ["held", "settled", "uncertain"] as const;
export const supportBudgetReservationStatusSchema = z.enum(SUPPORT_BUDGET_RESERVATION_STATUSES);
export type SupportBudgetReservationStatus = z.infer<typeof supportBudgetReservationStatusSchema>;

/**
 * Why a reservation was refused. At either budget's 100% the caller applies D-136: new debugger
 * runs and model replies wait, inbound cases get only the fixed acknowledgement, and the owner is
 * escalated, until the next UTC month or an owner raise.
 */
export const SUPPORT_BUDGET_REFUSALS = [
  "support_case_budget_exhausted",
  "support_month_budget_exhausted",
  "simulation_month_budget_exhausted",
  "support_case_ledger_mismatch",
  "support_reservation_conflict",
] as const;
export const supportBudgetRefusalSchema = z.enum(SUPPORT_BUDGET_REFUSALS);
export type SupportBudgetRefusal = z.infer<typeof supportBudgetRefusalSchema>;

/** Whether a refusal means a budget is spent, so D-136's 100% behaviour applies. */
export function supportBudgetExhausted(reason: SupportBudgetRefusal): boolean {
  return (
    reason === "support_case_budget_exhausted" ||
    reason === "support_month_budget_exhausted" ||
    reason === "simulation_month_budget_exhausted"
  );
}

/** A UTC month key, `YYYY-MM`. */
export const supportBudgetMonthSchema = z
  .string()
  .regex(/^[0-9]{4}-(0[1-9]|1[0-2])$/, "Expected a UTC month as YYYY-MM.");

/** The UTC month an instant falls in. */
export function supportBudgetMonthOf(at: Date): string {
  const month = at.getUTCMonth() + 1;
  return `${String(at.getUTCFullYear()).padStart(4, "0")}-${String(month).padStart(2, "0")}`;
}

/** The UTC month before the one an instant falls in (late settlements still land there). */
export function previousSupportBudgetMonthOf(at: Date): string {
  return supportBudgetMonthOf(new Date(Date.UTC(at.getUTCFullYear(), at.getUTCMonth() - 1, 1)));
}

/**
 * Whole percent of a budget committed (held plus spent), rounded down. It may pass 100 only when
 * a settled cost exceeded its reservation; reservations alone never commit more than the budget.
 */
export function supportBudgetCommittedPercent(committed: MicroUsd, budget: MicroUsd): number {
  if (budget <= 0n) throw new RangeError("support budget must be positive");
  return Number((committed * 100n) / budget);
}
