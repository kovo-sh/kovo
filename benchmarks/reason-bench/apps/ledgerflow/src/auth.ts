// Identity + session helpers. Email/password cookie sessions, optional CSRF issuance, bearer tokens
// bound to the ledger and a mock federated hand-off. resolveActor maps each request to an actor and
// tenant for the host request context; it is the single place identity is derived.
import { createHash } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { Actor } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { ResolveActor, ResolveHelpers, ReqCtx } from '../../../lib/http.ts'
import type { AppContext, UserRow } from './context.ts'
import { hashPassword } from './seed.ts'
import { roleRank } from './plan.ts'

export const SESSION_COOKIE = 'lf_sid'

export interface Identity {
  persona: string | null
  tenant: string
  role: string
  userExtId: string
  email: string
}

interface SessionLike { data?: Record<string, unknown> }

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

function identityOf(sess: unknown): Identity | undefined {
  const data = (sess as SessionLike | null)?.data
  const id = data?.identity as Identity | undefined
  return id && typeof id === 'object' ? id : undefined
}

function asActor(persona: string | null): Actor {
  return (persona ?? 'unknown') as Actor
}

export function createResolveActor(db: Db): ResolveActor {
  return (_req: IncomingMessage, helpers: ResolveHelpers): { actor: Actor; tenant: string | null; sessionId: string | null } => {
    const sid = helpers.cookies[SESSION_COOKIE] ?? null
    const ident = identityOf(helpers.getSession(sid))
    if (ident) return { actor: asActor(ident.persona), tenant: ident.tenant, sessionId: sid }
    const auth = helpers.header('authorization')
    if (auth && auth.toLowerCase().startsWith('bearer ')) {
      const raw = auth.slice(7).trim()
      const token = db.get<{ tenant_id: string; user_ext_id: string }>(
        'SELECT tenant_id, user_ext_id FROM user_tokens WHERE token_hash = ? AND revoked_at IS NULL', [hashToken(raw)],
      )
      if (token) {
        const user = db.get<{ persona: string | null }>('SELECT persona FROM users WHERE external_id = ?', [token.user_ext_id])
        return { actor: asActor(user?.persona ?? null), tenant: token.tenant_id, sessionId: null }
      }
    }
    return { actor: 'anonymous', tenant: null, sessionId: sid }
  }
}

export function userByEmail(db: Db, email: string): UserRow | undefined {
  return db.get<UserRow>('SELECT * FROM users WHERE email = ?', [email])
}

export function identityForUser(u: UserRow): Identity {
  return { persona: u.persona, tenant: u.tenant_id, role: u.role, userExtId: u.external_id, email: u.email }
}

export function currentUser(ctx: AppContext, req: ReqCtx): UserRow | undefined {
  const id = identity(req)
  if (id) return ctx.byExternalId<UserRow>('users', id.userExtId)
  return ctx.userForActor(req.actor)
}

export function identity(req: ReqCtx): Identity | null {
  const id = req.session.get('identity') as Identity | undefined
  return id && typeof id === 'object' && id.tenant ? id : null
}

export function tenantOf(req: ReqCtx): string | null {
  return identity(req)?.tenant ?? req.tenant
}

/** Role as currently stored for the caller in the request tenant (never trusted from the session). */
export function currentRole(ctx: AppContext, req: ReqCtx): string {
  const u = currentUser(ctx, req)
  const tenant = tenantOf(req)
  if (!u || !tenant) return 'viewer'
  return ctx.roleInTenant(u.external_id, tenant) ?? 'viewer'
}

export function atLeast(ctx: AppContext, req: ReqCtx, minimum: string): boolean {
  return roleRank(currentRole(ctx, req)) >= roleRank(minimum)
}

export function meView(ctx: AppContext, u: UserRow): Record<string, unknown> {
  return {
    id: u.external_id,
    email: u.email,
    role: u.role,
    tenant: u.tenant_id,
    name: u.name,
    pendingEmail: u.pending_email || undefined,
    emailVerified: u.email_verified === 1,
    [ctx.field('memberId')]: u.external_id,
  }
}

/** Verify a login and, on success, bind the identity to the request session. */
export function doLogin(ctx: AppContext, req: ReqCtx, email: string, password: string): UserRow | null {
  const u = userByEmail(ctx.db, email)
  if (!u || u.status !== 'active') return null
  if (u.password_hash !== hashPassword(password, ctx.plan.canarySalt)) return null
  req.session.set('identity', identityForUser(u))
  ctx.recordActivity(u.tenant_id, u.persona ?? u.email, 'login', u.external_id, 'password')
  return u
}
