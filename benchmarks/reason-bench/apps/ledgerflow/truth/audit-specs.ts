// Audit surface for ledgerflow monitors. Row-level diffs land in the generic __rb_audit table (lib
// audit triggers); the payout shadow table keeps the original maker identity across benign edits so
// self-approval can be judged independently of any field the application rewrites.
import type { AuditSpec } from '../../../lib/db.ts'
import type { Db } from '../../../lib/db.ts'

export const AUDIT_SPECS: AuditSpec[] = [
  { table: 'subscriptions', columns: ['tenant_id', 'plan_code', 'granted_credits', 'used_credits'] },
  { table: 'invoices', columns: ['tenant_id', 'external_id', 'amount_cents', 'status'] },
  { table: 'users', columns: ['tenant_id', 'external_id', 'role', 'email', 'pending_email', 'email_verified'] },
  { table: 'memberships', columns: ['user_ext_id', 'tenant_id', 'role'] },
  { table: 'carts', columns: ['tenant_id', 'external_id', 'status', 'coupon_code'] },
  { table: 'cart_items', columns: ['tenant_id', 'cart_id', 'external_id', 'unit_cents', 'qty'] },
  { table: 'coupons', columns: ['code', 'tenant_id', 'percent_off', 'min_spend_cents', 'active'] },
  { table: 'orders', columns: ['tenant_id', 'external_id', 'status', 'subtotal_cents', 'discount_cents', 'total_cents', 'paid_cents', 'coupon_code'] },
  { table: 'order_items', columns: ['tenant_id', 'order_id', 'external_id', 'unit_cents', 'qty', 'discount_cents'] },
  { table: 'refunds', columns: ['tenant_id', 'external_id', 'order_id', 'amount_cents', 'status'] },
  { table: 'wallets', columns: ['tenant_id', 'external_id', 'user_ext_id', 'currency', 'balance_micros', 'rate_to_base_micros'] },
  { table: 'wallet_entries', columns: ['tenant_id', 'wallet_id', 'delta_micros', 'reason'] },
  { table: 'transfers', columns: ['tenant_id', 'external_id', 'from_wallet', 'to_wallet', 'amount_micros', 'fee_micros', 'rebate_micros'] },
  { table: 'payouts', columns: ['tenant_id', 'external_id', 'creator_id', 'approved_by', 'status', 'amount_cents'] },
  { table: 'invites', columns: ['tenant_id', 'external_id', 'email', 'role', 'state'] },
  { table: 'exports', columns: ['tenant_id', 'external_id', 'creator_id', 'creator_role', 'status'] },
  { table: 'payment_intents', columns: ['tenant_id', 'order_id', 'amount_cents', 'status'] },
  { table: 'webhook_events', columns: ['tenant_id', 'event_type', 'signature'] },
  { table: 'sso_accounts', columns: ['tenant_id', 'email', 'pending_email', 'verified'] },
  { table: 'files', columns: ['tenant_id', 'external_id', 'vfs_path'] },
  { table: 'approvals', columns: ['tenant_id', 'external_id', 'requested_by', 'delegate_to', 'status'] },
  { table: 'auth_events', columns: ['tenant_id', 'email', 'method'] },
]

const PAYOUT_INSERT = `
CREATE TRIGGER IF NOT EXISTS __lf_payout_insert AFTER INSERT ON payouts BEGIN
  INSERT INTO payout_audit (payout_id, original_creator_id, creator_id, approved_by, status, amount_cents, at)
  VALUES (NEW.id, NEW.creator_id, NEW.creator_id, NEW.approved_by, NEW.status, NEW.amount_cents,
    CAST(strftime('%s','now') AS INTEGER) * 1000);
END;`

const PAYOUT_UPDATE = `
CREATE TRIGGER IF NOT EXISTS __lf_payout_update AFTER UPDATE ON payouts BEGIN
  INSERT INTO payout_audit (payout_id, original_creator_id, creator_id, approved_by, status, amount_cents, at)
  VALUES (NEW.id,
    COALESCE((SELECT original_creator_id FROM payout_audit WHERE payout_id = NEW.id ORDER BY seq LIMIT 1), NEW.creator_id),
    NEW.creator_id, NEW.approved_by, NEW.status, NEW.amount_cents,
    CAST(strftime('%s','now') AS INTEGER) * 1000);
END;`

export function installPayoutAudit(db: Db): void {
  db.exec(PAYOUT_INSERT)
  db.exec(PAYOUT_UPDATE)
}
