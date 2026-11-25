// Session, tenant, signing and parsing helpers shared by the API and edge surfaces.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { LabProfile, LabRole, LabState, SessionRecord, TenantKey, UserRecord } from './shared.ts'
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

export function normalizeEmail(value: string): string {
  return value.normalize('NFKC').trim().toLowerCase()
}

export function authenticate(state: LabState, req: IncomingMessage): SessionRecord | null {
  const token = bearer(req) || (typeof req.headers['x-session-token'] === 'string' ? req.headers['x-session-token'] : '')
  if (!token) return null
  const session = state.sessions.get(token)
  if (!session || session.revoked) return null
  return session
}

export function sessionUser(state: LabState, session: SessionRecord): UserRecord | null {
  return state.users.find((user) => user.id === session.userId) ?? null
}

export function sessionTenantOk(profile: LabProfile, session: SessionRecord): boolean {
  if (!profile.requireVerifiedSession) return true
  return session.emailVerified && session.tid === session.tenantId
}

export function sessionTenantId(state: LabState, session: SessionRecord): TenantKey {
  return session.tenantId
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

export function permissionKey(state: LabState, userId: string, tenantId: TenantKey): { key: string; scoped: boolean } {
  if (state.profile.tenantlessPermissionCache) return { key: `perm:${userId}`, scoped: false }
  return { key: `perm:${userId}:${tenantId}`, scoped: true }
}

export function effectivePermissions(
  state: LabState, session: SessionRecord, tenantId: TenantKey,
): { permissions: LabRole[]; cacheKey: string; viaCache: boolean } {
  const user = sessionUser(state, session)
  if (!user) return { permissions: [], cacheKey: '', viaCache: false }
  const actualRole = user.rolesByTenant[tenantId] ?? null
  const actual = permissionsFor(actualRole)
  const { key } = permissionKey(state, user.id, tenantId)
  const cached = state.cache.get(key)
  if (!cached) return { permissions: actual, cacheKey: key, viaCache: false }
  const viaCache = cached.tenantId !== tenantId
  return { permissions: viaCache ? cached.permissions : actual, cacheKey: key, viaCache }
}

/** First top-level numeric value for a duplicated JSON key, used by the backend parser. */
export function firstJsonNumber(raw: string, key: string): number | null {
  const pattern = new RegExp(`"${key}"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)`)
  const found = pattern.exec(raw)
  if (!found) return null
  const value = Number(found[1])
  return Number.isFinite(value) ? value : null
}

export function lastJsonNumber(raw: string, key: string): number | null {
  const pattern = new RegExp(`"${key}"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)`, 'g')
  let value: number | null = null
  for (const found of raw.matchAll(pattern)) {
    const parsed = Number(found[1])
    if (Number.isFinite(parsed)) value = parsed
  }
  return value
}

export function signExport(secret: string, jobId: string, tenantSlug: string, filename: string): string {
  return hmacHex(secret, `${jobId}:${tenantSlug}:${filename}`)
}

export function verifyExport(
  secret: string, jobId: string, tenantSlug: string, filename: string, signature: string,
): boolean {
  return safeEqualHex(signExport(secret, jobId, tenantSlug, filename), signature)
}
