/**
 * The fixed reasons of the tenancy-binding refusals (#9024 B): @kovo/db's scoped-handle refusal
 * (`scoped_handle_cross_account` when two named accounts differ, else
 * `scoped_handle_reuse_mismatch`) and the control plane's `fleet_handle_refused` and
 * `account_binding_missing`. Each refusing class carries one as its own `reason` beside its
 * `code`; the reason is a fixed code, never a value.
 */
export const TENANCY_REFUSAL_REASONS = [
  "scoped_handle_cross_account",
  "scoped_handle_reuse_mismatch",
  "fleet_handle_refused",
  "account_binding_missing",
] as const;
export type TenancyRefusalReason = (typeof TENANCY_REFUSAL_REASONS)[number];

/** The refusing classes' own `code`s (the cross-account case shares the reuse-mismatch code). */
const TENANCY_REFUSAL_CODES: ReadonlySet<string> = new Set([
  "scoped_handle_reuse_mismatch",
  "fleet_handle_refused",
  "account_binding_missing",
]);
const TENANCY_REFUSALS: ReadonlySet<string> = new Set(TENANCY_REFUSAL_REASONS);
const MAX_TENANCY_CAUSE_DEPTH = 8;

function isTenancyRefusalReason(value: unknown): value is TenancyRefusalReason {
  return typeof value === "string" && TENANCY_REFUSALS.has(value);
}

/**
 * The reason of a tenancy-binding refusal in `error` or its `cause` chain, else undefined. Read
 * from the refusing error's own `code` and `reason` data properties only (no getter runs), so a
 * wrapper that names no reason of its own still logs the refusal's code, never its message.
 */
export function tenancyRefusalReason(error: unknown): TenancyRefusalReason | undefined {
  const seen = new Set<unknown>();
  let current: unknown = error;
  for (let depth = 0; depth <= MAX_TENANCY_CAUSE_DEPTH; depth += 1) {
    if (!(current instanceof Error) || seen.has(current)) return undefined;
    const code: unknown = Object.getOwnPropertyDescriptor(current, "code")?.value;
    const reason: unknown = Object.getOwnPropertyDescriptor(current, "reason")?.value;
    if (typeof code === "string" && TENANCY_REFUSAL_CODES.has(code)) {
      return isTenancyRefusalReason(reason) ? reason : undefined;
    }
    seen.add(current);
    current = Object.getOwnPropertyDescriptor(current, "cause")?.value;
  }
  return undefined;
}
