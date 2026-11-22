// Full relational schema for the operations portal. Scoped tables carry a team_id (internal org
// boundary) and, where relevant, an account_id (customer boundary). Every externally addressable row
// carries an ext_id string so object references do not assume numeric enumeration.
import type { Db } from '../../../lib/db.ts'

const SCHEMA = `
CREATE TABLE teams (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, slug TEXT, name TEXT, plan TEXT
);
CREATE TABLE users (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, email TEXT UNIQUE,
  password TEXT, role TEXT, name TEXT, persona TEXT
);
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, name TEXT, tier TEXT,
  owner_email TEXT, notes TEXT
);
CREATE TABLE tickets (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, account_id TEXT, subject TEXT,
  body TEXT, status TEXT, priority TEXT, assignee_id TEXT
);
CREATE TABLE ticket_notes (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, ticket_id TEXT, team_id TEXT, author TEXT,
  body TEXT, created_at INTEGER
);
CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, actor TEXT, action TEXT, detail TEXT
);
CREATE TABLE saved_searches (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, name TEXT, query TEXT
);
CREATE TABLE jobs (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, name TEXT, kind TEXT, status TEXT
);
CREATE TABLE integrations (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, name TEXT, kind TEXT,
  secret TEXT, config_url TEXT
);
CREATE TABLE webhook_targets (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, name TEXT, url TEXT
);
CREATE TABLE feature_flags (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, flag_key TEXT, value TEXT, scope TEXT
);
CREATE TABLE reports (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, name TEXT, template TEXT
);
CREATE TABLE api_tokens (
  id INTEGER PRIMARY KEY, ext_id TEXT UNIQUE, team_id TEXT, user_id TEXT, scopes TEXT
);
CREATE TABLE backup_runs (
  id INTEGER PRIMARY KEY, team_id TEXT, status TEXT, signature_valid INTEGER, created_at INTEGER
);
`

export function createSchema(db: Db): void {
  db.exec(SCHEMA)
}
