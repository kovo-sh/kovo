// Relational schema for the forgecloud lab: a multi-tenant DevOps / CI-CD workspace. Every
// tenant-scoped table carries `org_slug` so the host authorization monitor can judge each mutation.
// External ids (per-seed format) live next to numeric primary keys because uuid/prefixed ids are not
// reversible. Telemetry tables (auth_events, perm_cache_events) are written by the neutral app and
// read only by the host-side monitors.
import type { Db } from '../../../lib/db.ts'

export const SCHEMA = `
CREATE TABLE role_templates (
  code TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  permissions TEXT NOT NULL
);
CREATE TABLE orgs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  code TEXT NOT NULL DEFAULT '',
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'team',
  sso_tenant TEXT NOT NULL DEFAULT '',
  data_ref TEXT NOT NULL DEFAULT ''
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  primary_org TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  persona TEXT,
  name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE memberships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_ext_id TEXT NOT NULL,
  org_slug TEXT NOT NULL,
  role TEXT NOT NULL,
  permissions TEXT NOT NULL,
  invited_by TEXT NOT NULL DEFAULT '',
  UNIQUE(user_ext_id, org_slug)
);
CREATE TABLE role_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_slug TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  role TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'direct',
  granted_by TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE teams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  name TEXT NOT NULL,
  role_template TEXT NOT NULL DEFAULT 'developer'
);
CREATE TABLE team_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  team_ext_id TEXT NOT NULL,
  org_slug TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'developer'
);
CREATE TABLE tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  user_ext_id TEXT NOT NULL,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'read',
  env_scope TEXT NOT NULL DEFAULT 'dev',
  created_at INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER
);
CREATE TABLE token_revocations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_slug TEXT NOT NULL,
  token_ext_id TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT 'manual',
  revoked_at INTEGER NOT NULL
);
CREATE TABLE workspaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  name TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  visibility TEXT NOT NULL DEFAULT 'private'
);
CREATE TABLE projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  workspace_ext TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  visibility TEXT NOT NULL DEFAULT 'private',
  state TEXT NOT NULL DEFAULT 'active',
  owner_ext TEXT NOT NULL DEFAULT ''
);
CREATE TABLE pipelines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  project_ext TEXT NOT NULL,
  name TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  visibility TEXT NOT NULL DEFAULT 'private',
  runner TEXT NOT NULL DEFAULT 'linux',
  definition TEXT NOT NULL DEFAULT ''
);
CREATE TABLE pipeline_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  project_ext TEXT NOT NULL,
  pipeline_ext TEXT NOT NULL,
  number INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  commit_ref TEXT NOT NULL DEFAULT '',
  actor_ext TEXT NOT NULL DEFAULT '',
  log_path TEXT NOT NULL DEFAULT '',
  env_preview_token TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  workspace_ext TEXT NOT NULL DEFAULT '',
  project_ext TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'opaque',
  version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  project_ext TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  vfs_path TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  checksum TEXT NOT NULL DEFAULT ''
);
CREATE TABLE exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  requested_by TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'audit',
  state TEXT NOT NULL DEFAULT 'queued',
  vfs_path TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE deployments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  project_ext TEXT NOT NULL,
  env TEXT NOT NULL DEFAULT 'staging',
  version TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'pending',
  approval_status TEXT NOT NULL DEFAULT 'pending',
  auto_release_scheduled INTEGER NOT NULL DEFAULT 0,
  scheduled_at INTEGER NOT NULL DEFAULT 0,
  requested_by TEXT NOT NULL DEFAULT '',
  approved_by TEXT NOT NULL DEFAULT '',
  disputed_at INTEGER NOT NULL DEFAULT 0,
  released_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE webhooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  signing_salt TEXT NOT NULL DEFAULT '',
  events TEXT NOT NULL DEFAULT 'build.completed',
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE webhook_deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  webhook_ext TEXT NOT NULL,
  event TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE automations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  workspace_ext TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  role_template TEXT NOT NULL DEFAULT 'viewer',
  created_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sso_identities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  issuer TEXT NOT NULL,
  tid TEXT NOT NULL,
  email TEXT NOT NULL,
  user_ext_id TEXT NOT NULL DEFAULT '',
  org_slug TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'linked'
);
CREATE TABLE invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  external_id TEXT UNIQUE NOT NULL,
  org_slug TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'developer',
  state TEXT NOT NULL DEFAULT 'pending',
  token TEXT NOT NULL
);
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_slug TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE auth_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  transport TEXT NOT NULL DEFAULT 'rest',
  actor_ext TEXT NOT NULL DEFAULT '',
  org_slug TEXT NOT NULL DEFAULT '',
  token_ext TEXT NOT NULL DEFAULT '',
  route_key TEXT NOT NULL DEFAULT '',
  accepted INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE perm_cache_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  viewer_user TEXT NOT NULL,
  viewer_org TEXT NOT NULL,
  entry_org TEXT NOT NULL,
  hit INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE vfs_reads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_ext TEXT NOT NULL DEFAULT '',
  org_slug TEXT NOT NULL DEFAULT '',
  requested_path TEXT NOT NULL,
  status INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT ''
);
`

export function applySchema(db: Db): void {
  db.exec(SCHEMA)
}

// Tenant-scoped tables whose row-level mutations the host authorization monitor audits.
export const AUDITED_TABLES = [
  'orgs', 'users', 'memberships', 'role_grants', 'teams', 'team_members', 'tokens',
  'token_revocations', 'workspaces', 'projects', 'pipelines', 'pipeline_runs', 'secrets',
  'artifacts', 'exports', 'deployments', 'webhooks', 'webhook_deliveries', 'automations',
  'sso_identities', 'invites',
]
