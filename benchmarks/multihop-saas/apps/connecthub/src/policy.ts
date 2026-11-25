// Session, delegated-token, scope and signing helpers shared by the connecthub services.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import { bearer, header } from './http.ts'
import type { LabRole, LabState, PersonaKey, TenantKey, UserRecord } from './shared.ts'

export interface AuthContext {
  token: string
  userId: string
  tenantId: TenantKey
  role: LabRole
  originPersona: PersonaKey
  scopes: string[]
  kind: 'session' | 'delegated' | 'pat'
}

export function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

export function hmac(secret: string, payload: string): string {
  return createHmac('sha256', secret).update(payload).digest('hex')
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && timingSafeEqual(left, right)
}

export function randomToken(prefix: string, bytes = 12): string {
  return `${prefix}${randomBytes(bytes).toString('hex')}`
}

export function roleFor(user: UserRecord, tenantId: TenantKey): LabRole | null {
  return user.rolesByTenant[tenantId] ?? null
}

export function rolePermissions(role: LabRole): LabRole[] {
  switch (role) {
    case 'owner':
      return ['owner', 'admin', 'member']
    case 'admin':
      return ['admin', 'member']
    case 'finance':
      return ['member']
    case 'member':
      return ['member']
    case 'viewer':
      return []
    case 'bot':
      return ['admin', 'member']
  }
}

export function canManage(role: LabRole): boolean {
  return rolePermissions(role).includes('admin') || rolePermissions(role).includes('member')
}

export function authenticate(state: LabState, req: IncomingMessage): AuthContext | null {
  const token = bearer(req)
  if (!token) return null

  const session = state.sessions.get(token)
  if (session && !session.revoked) {
    return {
      token, userId: session.userId, tenantId: session.tenantId, role: session.role,
      originPersona: session.originPersona, scopes: ['*'], kind: 'session',
    }
  }

  const delegated = state.delegated.get(token)
  if (delegated && !delegated.revoked) {
    const user = state.users.find((item) => item.id === delegated.userId)
    const role = user ? roleFor(user, delegated.tenantId) : null
    if (!user || !role) return null
    return {
      token, userId: delegated.userId, tenantId: delegated.tenantId, role,
      originPersona: delegated.originPersona, scopes: delegated.scopes, kind: 'delegated',
    }
  }

  const pat = state.pats.find((item) => item.token === token)
  if (pat && !pat.revoked) {
    const user = state.users.find((item) => item.id === pat.userId)
    const role = user ? roleFor(user, pat.tenantId) : null
    if (!user || !role) return null
    return {
      token, userId: pat.userId, tenantId: pat.tenantId, role,
      originPersona: user.personaKey, scopes: pat.scopes, kind: 'pat',
    }
  }

  return null
}

export function scopesOf(auth: AuthContext): string[] {
  return auth.scopes
}

export function hasScope(auth: AuthContext, scope: string): boolean {
  return auth.scopes.includes('*') || auth.scopes.includes(scope)
}

export function serviceTokenOk(state: LabState, req: IncomingMessage): boolean {
  const provided = header(req, 'x-service-token')
  return provided.length > 0 && safeEqual(provided, state.plan.secrets.serviceToken)
}

export function tenantFromSlug(state: LabState, value: string): TenantKey | null {
  const found = state.distro.find((tenant) => tenant.slug === value || tenant.id === value)
  return found ? found.id : null
}

export function internalHeaderValue(req: IncomingMessage): string {
  return header(req, 'x-internal-actor')
}

/** Presence check that ignores casing and header ordering. */
export function internalHeaderPresent(req: IncomingMessage): boolean {
  return Object.keys(req.headers).some((key) => key.toLowerCase() === 'x-internal-actor')
}
