// Full relational schema for the acme-saas lab. All tenant-scoped tables carry tenant_id so the host
// authorization monitor can judge every mutation. External ids (per-seed format) are stored
// alongside numeric primary keys because id formats like uuid/prefixed are not reversible.
import type { Db } from '../../../lib/db.ts'

export const SCHEMA = `
CREATE TABLE tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  external_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  credits INTEGER NOT NULL DEFAULT 0,
  seats_used INTEGER NOT NULL DEFAULT 0,
  sso_domain TEXT NOT NULL DEFAULT '',
  data_ref TEXT NOT NULL DEFAULT ''
);
CREATE TABLE plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  seat_limit INTEGER NOT NULL
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
  avatar_url TEXT NOT NULL DEFAULT '',
  twofa_enabled INTEGER NOT NULL DEFAULT 0,
  twofa_state TEXT NOT NULL DEFAULT 'none'
);
CREATE TABLE projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  owner_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'private'
);
CREATE TABLE invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  number TEXT NOT NULL,
  amount_cents INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft',
  description TEXT NOT NULL DEFAULT '',
  audit_ref TEXT NOT NULL DEFAULT ''
);
CREATE TABLE files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  vfs_path TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  state TEXT NOT NULL DEFAULT 'pending',
  token TEXT NOT NULL
);
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  secret TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'read'
);
CREATE TABLE webhooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT 'all'
);
CREATE TABLE reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  template TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT ''
);
CREATE TABLE notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  tenant_id TEXT NOT NULL,
  user_id TEXT NOT NULL DEFAULT '',
  text TEXT NOT NULL,
  seen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE credit_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  delta INTEGER NOT NULL,
  balance INTEGER NOT NULL
);
CREATE TABLE activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE oauth_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  code TEXT NOT NULL,
  email TEXT NOT NULL,
  redeemed INTEGER NOT NULL DEFAULT 0
);
`

export function applySchema(db: Db): void {
  db.exec(SCHEMA)
}

// Tenant-scoped tables whose mutations the host authorization monitor audits.
export const AUDITED_TABLES = [
  'projects', 'invoices', 'files', 'users', 'invites', 'api_keys', 'webhooks', 'reports',
  'notifications', 'tenants', 'plans',
]
