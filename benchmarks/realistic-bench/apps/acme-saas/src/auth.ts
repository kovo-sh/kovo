// Identity + session helpers. Supports email/password cookie sessions (with a CSRF token for
// cookie-authenticated mutations), bearer API-token auth, a 2FA checkpoint and a mock SSO/OAuth
// hand-off. resolveActor maps each incoming request to an actor + tenant for the host request
// context; it is the single place identity is derived.
import type { IncomingMessage } from 'node:http'
import type { Actor } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { ResolveActor, ResolveHelpers, ReqCtx } from '../../../lib/http.ts'
import type { AppContext, UserRow } from './context.ts'
import { hashPassword } from './seed-data.ts'

export const SESSION_COOKIE = 'acme_sid'

export interface Identity {
  persona: string | null
  tenant: string
  role: string
  userExtId: string
  email: string
  twofaPending: boolean
}

interface SessionLike { data?: Record<string, unknown> }

function identityOf(sess: unknown): Identity | undefined {
  const data = (sess as SessionLike | null)?.data
  const id = data?.identity as Identity | undefined
  return id && typeof id === 'object' ? id : undefined
}

export function createResolveActor(db: Db): ResolveActor {
  return (_req: IncomingMessage, helpers: ResolveHelpers): { actor: Actor; tenant: string | null; sessionId: string | null } => {
    const sid = helpers.cookies[SESSION_COOKIE] ?? null
    const ident = identityOf(helpers.getSession(sid))
    if (ident && !ident.twofaPending) {
      return { actor: asActor(ident.persona), tenant: ident.tenant, sessionId: sid }
    }
    const auth = helpers.header('authorization')
    if (auth && auth.toLowerCase().startsWith('bearer ')) {
      const token = auth.slice(7).trim()
      const key = db.get<{ tenant_id: string }>('SELECT tenant_id FROM api_keys WHERE secret = ?', [token])
      if (key) {
        const owner = db.get<{ persona: string | null }>(
          "SELECT persona FROM users WHERE tenant_id = ? AND role = 'owner' LIMIT 1", [key.tenant_id])
        return { actor: asActor(owner?.persona ?? null), tenant: key.tenant_id, sessionId: null }
      }
    }
    return { actor: 'anonymous', tenant: null, sessionId: sid }
  }
}

function asActor(persona: string | null): Actor {
  if (persona === 'persona_a' || persona === 'persona_b' || persona === 'admin' || persona === 'viewer') return persona
  return 'unknown'
}

export function userByEmail(db: Db, email: string): UserRow | undefined {
  return db.get<UserRow>('SELECT * FROM users WHERE email = ?', [email])
}

export function identityForUser(u: UserRow, twofaPending: boolean): Identity {
  return { persona: u.persona, tenant: u.tenant_id, role: u.role, userExtId: u.external_id, email: u.email, twofaPending }
}

export function meView(ctx: AppContext, u: UserRow): Record<string, unknown> {
  return {
    id: u.external_id, email: u.email, role: u.role, tenant: u.tenant_id, name: u.name,
    avatarUrl: u.avatar_url, [ctx.field('memberId')]: u.external_id,
  }
}

/** Verify a login and, on success, bind the identity to the request session. Returns the user. */
export function doLogin(ctx: AppContext, req: ReqCtx, email: string, password: string): UserRow | null {
  const u = userByEmail(ctx.db, email)
  if (!u) return null
  const salt = ctx.plan.canarySalt
  if (u.password_hash !== hashPassword(password, salt)) return null
  req.session.set('identity', identityForUser(u, false))
  return u
}
