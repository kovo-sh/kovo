// Session, tenant, signing and delegation helpers shared by the API, identity and CDN surfaces.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type {
  LabProfile, LabRole, LabState, SessionRecord, TenantKey, UserRecord,
} from './shared.ts'
import { bearer, header } from './http.ts'

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

export function normalizeEmail(value: string): string {
  return value.normalize('NFKC').trim().toLowerCase()
}

export function authenticate(state: LabState, req: IncomingMessage): SessionRecord | null {
  const token = bearer(req) || header(req, 'x-session-token')
  if (!token) return null
  const session = state.sessions.get(token)
  if (!session || session.revoked) return null
  return session
}

export function sessionUser(state: LabState, session: SessionRecord): UserRecord | null {
  return state.users.find((user) => user.id === session.userId) ?? null
}

export function sessionTenantOk(profile: LabProfile, session: SessionRecord): boolean {
  void profile
  return session.emailVerified && session.tid === session.tenantId
}

export function roleOf(state: LabState, session: SessionRecord, tenantId: TenantKey): LabRole | null {
  const user = sessionUser(state, session)
  if (!user) return null
  return user.rolesByTenant[tenantId] ?? null
}

export function permissionsFor(role: LabRole | null): LabRole[] {
  if (role === null) return []
  switch (role) {
    case 'owner':
      return ['owner', 'admin', 'member']
    case 'admin':
      return ['admin', 'member']
    case 'member':
    case 'finance':
      return ['member']
    case 'viewer':
      return []
    case 'bot':
      return ['admin', 'member']
  }
}

export function serviceAuthorized(state: LabState, req: IncomingMessage): boolean {
  const expected = hmacHex(state.plan.secrets.serviceToken, 'service')
  return safeEqualHex(header(req, 'x-service-token'), expected)
}

export function delegationFor(
  state: LabState, req: IncomingMessage,
): { key: string; userId: string; tenantId: TenantKey; role: LabRole | null } | null {
  const key = header(req, 'x-delegation-key')
  if (!key) return null
  const record = state.delegations.get(key)
  if (!record) return null
  const user = state.users.find((item) => item.id === record.userId)
  const role = user?.rolesByTenant[record.tenantId] ?? null
  return { key, userId: record.userId, tenantId: record.tenantId, role }
}

export function ensureDelegation(
  state: LabState, userId: string, tenantId: TenantKey,
): { key: string; digest: string } {
  for (const record of state.delegations.values()) {
    if (record.userId === userId && record.tenantId === tenantId) {
      return { key: record.key, digest: digest(record.key) }
    }
  }
  const suffix = digest(`${state.runId}:${userId}:${tenantId}:delegation`).slice(0, 24)
  const key = `mh_fake_deleg_${suffix}`
  state.delegations.set(key, { key, userId, tenantId, runId: state.runId })
  return { key, digest: digest(key) }
}

export function scimTokenOf(state: LabState, req: IncomingMessage) {
  const raw = bearer(req) || header(req, 'x-scim-token')
  if (!raw) return null
  return state.scimTokens.find((token) => token.token === raw && !token.revoked) ?? null
}

export function scimTokenDigest(state: LabState, raw: string): string {
  return hmacHex(state.plan.secrets.patPepper, raw)
}
