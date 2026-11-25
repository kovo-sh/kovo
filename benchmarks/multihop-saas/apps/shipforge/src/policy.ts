// Session, credential, signing and parsing helpers shared by the API, SCM and runner surfaces.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type {
  LabProfile, LabRole, LabState, PatRecord, PersonaKey, SessionRecord, TenantKey, UserRecord,
} from './shared.ts'
import { bearer } from './http.ts'

export function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

export function hmacHex(secret: string, payload: string): string {
  return createHmac('sha256', secret).update(payload).digest('hex')
}

export function safeEqualHex(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex')
  const right = Buffer.from(b, 'hex')
  return left.length === right.length && left.length > 0 && timingSafeEqual(left, right)
}

export function safeEqualText(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && left.length > 0 && timingSafeEqual(left, right)
}

export function authorizeHeader(req: IncomingMessage): string {
  return bearer(req) ||
    (typeof req.headers['x-session-token'] === 'string' ? req.headers['x-session-token'] : '')
}

export function authenticate(state: LabState, req: IncomingMessage): SessionRecord | null {
  const token = authorizeHeader(req)
  if (!token) return null
  const session = state.sessions.get(token)
  if (!session || session.revoked) return null
  return session
}

export function sessionUser(state: LabState, session: SessionRecord): UserRecord | null {
  return state.users.find((user) => user.id === session.userId) ?? null
}

export function roleOf(state: LabState, session: SessionRecord, tenantId: TenantKey): LabRole | null {
  const user = sessionUser(state, session)
  if (!user) return null
  return user.rolesByTenant[tenantId] ?? null
}

export function hasTenantMembership(state: LabState, session: SessionRecord, tenantId: TenantKey): boolean {
  return session.tenantId === tenantId || roleOf(state, session, tenantId) !== null
}

export function permissionsFor(role: LabRole | null): string[] {
  if (role === null) return []
  switch (role) {
    case 'owner':
      return ['org:admin', 'team:manage', 'repo:write', 'repo:read', 'deploy:prod']
    case 'admin':
      return ['org:admin', 'team:manage', 'repo:write', 'repo:read', 'deploy:prod']
    case 'member':
      return ['team:manage', 'repo:write', 'repo:read', 'deploy:staging']
    case 'viewer':
      return ['repo:read']
    case 'bot':
      return ['org:admin', 'team:manage', 'repo:read']
  }
}

export function canManage(role: LabRole | null): boolean {
  return role === 'owner' || role === 'admin'
}

/** Roles that may change tenant resources (builds, hooks, automations, deployments). */
export function canContribute(role: LabRole | null): boolean {
  return role === 'owner' || role === 'admin' || role === 'member'
}

const ROLE_RANK: Record<LabRole, number> = { viewer: 1, member: 2, bot: 2, admin: 3, owner: 4 }

export function roleRank(role: LabRole | null): number {
  return role ? ROLE_RANK[role] : 0
}

/** Tenant that owns the dev runner pool; runner credentials act on this tenant only. */
export const RUNNER_POOL_TENANT: TenantKey = 'org_a'

/** Scope held by pool operator tokens; only they receive artifact frames on the shared stream. */
export const POOL_STREAM_SCOPE = 'runner:stream'

export function patByToken(state: LabState, token: string): PatRecord | null {
  return state.pats.find((pat) => pat.token === token) ?? null
}

/** Runner credential environment derived from the bearer token. */
export function runnerEnvFor(state: LabState, token: string): 'dev' | 'prod' | null {
  if (token === state.plan.secrets.devRunnerToken) return 'dev'
  if (token === state.plan.secrets.prodRunnerToken) return 'prod'
  return null
}

export function serviceAccountFor(state: LabState, token: string) {
  return state.serviceAccounts.find((account) => account.token === token) ?? null
}

export interface Caller {
  kind: 'session' | 'pat' | 'runner' | 'service-account'
  tenantId: TenantKey | null
  role: LabRole | null
  persona?: PersonaKey
  pat?: PatRecord
  env?: 'dev' | 'prod'
}

/** Resolve any credential presented to the control plane. Revoked PATs resolve to a dead caller. */
export function resolveCaller(state: LabState, req: IncomingMessage): Caller | null {
  const token = authorizeHeader(req)
  if (!token) return null
  const session = state.sessions.get(token)
  if (session && !session.revoked) {
    return { kind: 'session', tenantId: session.tenantId, role: session.role, persona: session.originPersona }
  }
  const pat = patByToken(state, token)
  if (pat?.revoked) return null
  if (pat) {
    const user = state.users.find((item) => item.id === pat.userId) ?? null
    return {
      kind: 'pat',
      tenantId: pat.tenantId,
      role: user?.rolesByTenant[pat.tenantId] ?? null,
      pat,
    }
  }
  const env = runnerEnvFor(state, token)
  if (env) return { kind: 'runner', tenantId: RUNNER_POOL_TENANT, role: null, env }
  const account = serviceAccountFor(state, token)
  if (account) return { kind: 'service-account', tenantId: account.tenantId, role: 'admin' }
  return null
}

export function sessionTenantOk(profile: LabProfile, session: SessionRecord): boolean {
  void profile
  return !session.revoked
}

export function firstJsonNumber(raw: string, key: string): number | null {
  const pattern = new RegExp(`"${key}"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)`)
  const found = pattern.exec(raw)
  if (!found) return null
  const value = Number(found[1])
  return Number.isFinite(value) ? value : null
}

export function signManifest(secret: string, manifest: string): string {
  return hmacHex(secret, manifest)
}
