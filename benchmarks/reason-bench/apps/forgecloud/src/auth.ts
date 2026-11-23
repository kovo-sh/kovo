// Identity + session helpers. Supports email/password cookie sessions (CSRF-protected mutations),
// bearer personal access tokens and org switching via `x-org-id`. resolveActor maps each incoming
// request to an actor + org for the host request context; it is the single place identity is derived.
import { createHash } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { Actor } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { ResolveActor, ResolveHelpers } from '../../../lib/http.ts'
import type { UserRow, OrgRow, TokenRow } from './context.ts'
import type { StreamViewer, StreamToken } from './streams.ts'

export const SESSION_COOKIE = 'forge_sid'

export interface Identity {
  userExt: string
  persona: string | null
  email: string
  name: string
  primaryOrg: string
  role: string
}

export function identityOf(sess: unknown): Identity | undefined {
  const data = (sess as { data?: Record<string, unknown> } | null)?.data
  const id = data?.identity as Identity | undefined
  return id && typeof id === 'object' && typeof id.userExt === 'string' ? id : undefined
}

function resolveOrg(db: Db, value: string | undefined): OrgRow | undefined {
  if (!value) return undefined
  return db.get<OrgRow>('SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [value, value, value])
}

function isMember(db: Db, userExt: string, org: string): boolean {
  return !!db.get<{ id: number }>('SELECT id FROM memberships WHERE user_ext_id = ? AND org_slug = ?', [userExt, org])
}

/** Active org: the header-selected membership, else the session's primary org. */
export function activeOrgFor(db: Db, ident: Identity, header: string | undefined): string {
  const wanted = resolveOrg(db, header)
  if (wanted && isMember(db, ident.userExt, wanted.slug)) return wanted.slug
  return ident.primaryOrg
}

export function createResolveActor(db: Db): ResolveActor {
  return (_req: IncomingMessage, helpers: ResolveHelpers): { actor: Actor; tenant: string | null; sessionId: string | null } => {
    const sid = helpers.cookies[SESSION_COOKIE] ?? null
    const ident = identityOf(helpers.getSession(sid))
    if (ident) {
      return { actor: asActor(ident.persona), tenant: activeOrgFor(db, ident, helpers.header('x-org-id')), sessionId: sid }
    }
    const auth = helpers.header('authorization')
    if (auth && auth.toLowerCase().startsWith('bearer ')) {
      const token = auth.slice(7).trim()
      const row = db.get<TokenRow>('SELECT * FROM tokens WHERE secret_hash = ?', [sha256(token)])
      const revocation = row
        ? db.get<{ id: number }>('SELECT id FROM token_revocations WHERE token_ext_id = ? LIMIT 1', [row.external_id])
        : undefined
      const expired = !!row && row.expires_at > 0 && row.expires_at < Date.now()
      const revoked = !!row && (row.revoked_at !== null || !!revocation) || expired
      const user = row ? db.get<UserRow>('SELECT * FROM users WHERE external_id = ?', [row.user_ext_id]) : undefined
      db.run(
        'INSERT INTO auth_events (kind,transport,actor_ext,org_slug,token_ext,route_key,accepted,detail) VALUES (?,?,?,?,?,?,?,?)',
        ['token_use', 'rest', user?.external_id ?? '', row?.org_slug ?? '', row?.external_id ?? '', '',
          row && !revoked ? 1 : 0, revoked ? 'revoked' : row ? 'active' : 'unknown'],
      )
      if (row && !revoked && user) {
        return { actor: asActor(user.persona), tenant: row.org_slug, sessionId: null }
      }
    }
    return { actor: 'anonymous', tenant: null, sessionId: sid }
  }
}

export function asActor(persona: string | null): Actor {
  return persona ? (persona as Actor) : 'unknown'
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

export function userByEmail(db: Db, email: string): UserRow | undefined {
  return db.get<UserRow>('SELECT * FROM users WHERE email = ? ORDER BY id LIMIT 1', [email])
}

export function identityForUser(u: UserRow): Identity {
  return {
    userExt: u.external_id, persona: u.persona, email: u.email, name: u.name,
    primaryOrg: u.primary_org, role: u.role,
  }
}

export function orgBySlug(db: Db, slug: string): OrgRow | undefined {
  return db.get<OrgRow>('SELECT * FROM orgs WHERE slug = ?', [slug])
}

/** Build the stream credential view from a session identity. */
export function streamViewerFor(db: Db, sid: string | null, sessions: { get(id: string | null | undefined): unknown }): StreamViewer | null {
  const ident = identityOf(sessions.get(sid))
  if (!ident) return null
  const m = db.get<{ role: string }>('SELECT role FROM memberships WHERE user_ext_id = ? AND org_slug = ?',
    [ident.userExt, ident.primaryOrg])
  return {
    userExt: ident.userExt, org: ident.primaryOrg, role: m?.role ?? ident.role,
    persona: ident.persona, email: ident.email,
  }
}

/** Parse a PAT presented on a stream connection (query `token` or bearer header). */
export function streamTokenFor(db: Db, raw: string | null, verify: (t: string) => boolean): StreamToken | null {
  if (!raw) return null
  const row = db.get<TokenRow>('SELECT * FROM tokens WHERE secret_hash = ?', [sha256(raw)])
  const revocation = row
    ? db.get<{ id: number }>('SELECT id FROM token_revocations WHERE token_ext_id = ? LIMIT 1', [row.external_id])
    : undefined
  const user = row ? db.get<UserRow>('SELECT * FROM users WHERE external_id = ?', [row.user_ext_id]) : undefined
  const expired = !!row && row.expires_at > 0 && row.expires_at < Date.now()
  return {
    raw,
    externalId: row?.external_id ?? null,
    userExt: row?.user_ext_id ?? null,
    org: row?.org_slug ?? null,
    scopes: row ? row.scopes.split(',').map((s) => s.trim()).filter(Boolean) : [],
    envScope: row?.env_scope ?? 'dev',
    revoked: !!row && (row.revoked_at !== null || !!revocation) || expired,
    signatureValid: verify(raw) && !!user,
  }
}
