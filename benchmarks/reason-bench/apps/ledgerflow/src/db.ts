// Relational schema for the ledgerflow billing/approvals lab. Every tenant-scoped table carries a
// tenant_id so the host authorization monitor can judge each mutation. Monetary values are integers:
// cents for fiat orders, micro-units for wallet balances. External ids follow the per-seed id format
// and are stored alongside numeric primary keys.
import type { Db } from '../../../lib/db.ts'

export const SCHEMA = `
CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  plan_code TEXT NOT NULL,
  base_currency TEXT NOT NULL DEFAULT 'USD',
  sso_domain TEXT NOT NULL DEFAULT '',
  data_ref TEXT NOT NULL DEFAULT ''
);
CREATE TABLE plans (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  monthly_cents INTEGER NOT NULL,
  seat_limit INTEGER NOT NULL,
  metered_credits INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  plan_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  granted_credits INTEGER NOT NULL DEFAULT 0,
  used_credits INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL,
  current_period_end INTEGER NOT NULL
);
CREATE TABLE invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  number TEXT NOT NULL,
  amount_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft',
  description TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  audit_ref TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  persona TEXT,
  name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  email_verified INTEGER NOT NULL DEFAULT 1,
  pending_email TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE memberships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_ext_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL,
  UNIQUE(user_ext_id, tenant_id)
);
CREATE TABLE user_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'session',
  token_hash TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE revoked_tokens (
  token_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  revoked_at INTEGER NOT NULL
);
CREATE TABLE carts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  coupon_code TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT 'USD',
  updated_at INTEGER NOT NULL
);
CREATE TABLE cart_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  cart_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  sku TEXT NOT NULL,
  name TEXT NOT NULL,
  unit_cents INTEGER NOT NULL,
  qty INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE coupons (
  code TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  percent_off INTEGER NOT NULL,
  min_spend_cents INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  cart_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft',
  subtotal_cents INTEGER NOT NULL DEFAULT 0,
  discount_cents INTEGER NOT NULL DEFAULT 0,
  total_cents INTEGER NOT NULL DEFAULT 0,
  paid_cents INTEGER NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  coupon_code TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  paid_at INTEGER
);
CREATE TABLE order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  order_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  sku TEXT NOT NULL,
  name TEXT NOT NULL,
  unit_cents INTEGER NOT NULL,
  qty INTEGER NOT NULL DEFAULT 1,
  discount_cents INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE refunds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  order_item_id TEXT NOT NULL DEFAULT '',
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'settled',
  created_at INTEGER NOT NULL
);
CREATE TABLE wallets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  currency TEXT NOT NULL,
  balance_micros INTEGER NOT NULL DEFAULT 0,
  rate_to_base_micros INTEGER NOT NULL DEFAULT 1000000
);
CREATE TABLE wallet_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  wallet_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  delta_micros INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE transfers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  from_wallet TEXT NOT NULL,
  to_wallet TEXT NOT NULL,
  amount_micros INTEGER NOT NULL,
  fee_micros INTEGER NOT NULL DEFAULT 0,
  rebate_micros INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'settled',
  created_at INTEGER NOT NULL
);
CREATE TABLE payouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  approved_by TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  memo TEXT NOT NULL DEFAULT '',
  destination TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  approved_at INTEGER
);
CREATE TABLE payout_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  payout_id INTEGER NOT NULL,
  original_creator_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  approved_by TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  amount_cents INTEGER NOT NULL DEFAULT 0,
  at INTEGER NOT NULL
);
CREATE TABLE invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  state TEXT NOT NULL DEFAULT 'pending',
  token TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  creator_role TEXT NOT NULL DEFAULT 'member',
  kind TEXT NOT NULL DEFAULT 'billing',
  status TEXT NOT NULL DEFAULT 'queued',
  vfs_path TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE TABLE payment_intents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'requires_capture',
  created_at INTEGER NOT NULL,
  captured_at INTEGER
);
CREATE TABLE webhook_endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT 'all'
);
CREATE TABLE webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  signature TEXT NOT NULL DEFAULT '',
  ts TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL DEFAULT '',
  processed INTEGER NOT NULL DEFAULT 0,
  received_at INTEGER NOT NULL
);
CREATE TABLE sso_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'loopid',
  subject TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL,
  pending_email TEXT NOT NULL DEFAULT '',
  verified INTEGER NOT NULL DEFAULT 1,
  last_login_at INTEGER
);
CREATE TABLE files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  vfs_path TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'payout',
  subject_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  delegate_to TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL
);
CREATE TABLE auth_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  method TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
`

export function applySchema(db: Db): void {
  db.exec(SCHEMA)
}

// Tenant-scoped tables whose mutations the host authorization/economic monitors audit.
export const AUDITED_TABLES = [
  'tenants', 'plans', 'subscriptions', 'users', 'memberships', 'carts', 'cart_items', 'coupons',
  'orders', 'order_items', 'refunds', 'wallets', 'wallet_entries', 'transfers', 'payouts',
  'invites', 'exports', 'payment_intents', 'webhook_events', 'sso_accounts', 'files', 'activity',
  'approvals', 'auth_events',
]
