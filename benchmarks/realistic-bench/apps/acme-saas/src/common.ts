// Small shared helpers for the area route modules: identity extraction, tenant scoping and row views.
import type { ReqCtx, HttpResult } from '../../../lib/http.ts'
import type { AppContext, UserRow } from './context.ts'
import type { Identity } from './auth.ts'

export function identity(req: ReqCtx): Identity | null {
  const id = req.session.get('identity') as Identity | undefined
  return id && !id.twofaPending ? id : null
}

/** The authoritative tenant for the request (session identity or bearer-resolved tenant). */
export function tenantOf(req: ReqCtx): string | null {
  return identity(req)?.tenant ?? req.tenant
}

export function roleOf(ctx: AppContext, req: ReqCtx): string {
  const id = identity(req)
  if (id) return id.role
  const u = ctx.userForActor(req.actor)
  return u?.role ?? 'member'
}

export function currentUser(ctx: AppContext, req: ReqCtx): UserRow | undefined {
  const id = identity(req)
  if (id) return ctx.byExternalId<UserRow>('users', id.userExtId)
  return ctx.userForActor(req.actor)
}

export function unauthorized(req: ReqCtx): HttpResult {
  return req.json({ error: 'unauthorized' }, 401)
}

export function notFound(req: ReqCtx): HttpResult {
  return req.json({ error: 'not_found' }, 404)
}

export function forbidden(req: ReqCtx): HttpResult {
  return req.json({ error: 'forbidden' }, 403)
}

/** Rows of a tenant-scoped table for the caller tenant (safe default scoping). */
export function ownRows<T = Record<string, unknown>>(ctx: AppContext, tenant: string, table: string): T[] {
  return ctx.db.all<T>(`SELECT * FROM ${table} WHERE tenant_id = ? ORDER BY id`, [tenant])
}

export function invoiceView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, number: row.number, amount: row.amount_cents, status: row.status,
    description: row.description, project: row.project_id, audit_ref: row.audit_ref,
  }
}

export function projectView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, name: row.name, description: row.description, visibility: row.visibility,
    owner: row.owner_id,
  }
}

export function fileView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, name: row.name, project: row.project_id, note: row.note }
}

export function memberView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, email: row.email, role: row.role, name: row.name, avatarUrl: row.avatar_url }
}
