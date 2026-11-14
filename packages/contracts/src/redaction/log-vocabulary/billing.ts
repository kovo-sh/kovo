// Closed log vocabulary: apps/control-plane/src/services/billing.
// Changes require review; never derive this from runtime values. One string literal per
// line, sorted, no duplicates; each code lives in one area file (log-vocabulary.test.ts).
export const LOG_EVENT_CODES = [
  "billing_checkout_pending_check_failed",
  "billing_exception_record_failed",
  "billing_plan_grant_skipped",
  "billing_plus_activated",
  "billing_project_activation_deferred",
  "payment_method_health_checked",
] as const;
export const LOG_FIELD_KEYS = ["probe_outcome"] as const;
export const LOG_ENUM_CODES = [
  "account_unavailable",
  "checkout_return",
  "grant_audit_failed",
  "grant_not_effective",
  "method_not_available",
  "method_off",
  "no_default_configuration",
  "overage_price_check_failed",
  "payment_methods_check_failed",
  "price_inactive",
  "price_not_recurring",
  "project_activation_account_deactivated",
  "project_activation_conflict",
  "project_activation_inventory_pending",
  "project_activation_marker_conflict",
  "project_activation_period_unsynced",
  "project_activation_repo_unsupported",
  "reconciliation",
] as const;
