// Shared helpers for the area route modules: identity extraction, org/capability checks, workspace
// resolution and row views. Everything here is neutral and tenant-scoped by default.
import type { ReqCtx, HttpResult } from '../../../lib/http.ts'
import type { AppContext, UserRow, MembershipRow } from './context.ts'
import type { Identity } from './auth.ts'
import { permissionsForRole, hasPermission } from './roles.ts'

export function identity(req: ReqCtx): Identity | null {
  const id = req.session.get('identity') as Identity | undefined
  return id && typeof id.userExt === 'string' ? id : null
}

export function currentUser(ctx: AppContext, req: ReqCtx): UserRow | undefined {
  const id = identity(req)
  if (id) return ctx.byExternalId<UserRow>('users', id.userExt)
  return ctx.userForActor(req.actor)
}

export function currentUserExt(ctx: AppContext, req: ReqCtx): string {
  return currentUser(ctx, req)?.external_id ?? ''
}

/** The authoritative org for the request (org-selected session or token org). */
export function orgOf(req: ReqCtx): string | null {
  return req.tenant
}

export function membership(ctx: AppContext, req: ReqCtx): MembershipRow | undefined {
  const user = currentUserExt(ctx, req)
  const org = orgOf(req)
  return user && org ? ctx.membershipFor(user, org) : undefined
}

export function roleOf(ctx: AppContext, req: ReqCtx): string {
  const user = currentUser(ctx, req)
  const org = orgOf(req)
  if (!user || !org) return 'anonymous'
  return ctx.roleFor(user.external_id, org)
}

export function can(ctx: AppContext, req: ReqCtx, permission: string): boolean {
  const user = currentUser(ctx, req)
  const org = orgOf(req)
  if (!user || !org) return false
  return ctx.can(user.external_id, org, permission)
}

export function unauthorized(req: ReqCtx): HttpResult {
  return req.json({ error: 'unauthorized' }, 401)
}

export function forbidden(req: ReqCtx): HttpResult {
  return req.json({ error: 'forbidden' }, 403)
}

export function notFound(req: ReqCtx): HttpResult {
  return req.json({ error: 'not_found' }, 404)
}

export function invalid(req: ReqCtx, error = 'invalid_request'): HttpResult {
  return req.json({ error }, 400)
}

/** Authenticated + capable, else the response to return. */
export function requirePerm(ctx: AppContext, req: ReqCtx, permission: string): HttpResult | null {
  if (!currentUser(ctx, req)) return unauthorized(req)
  if (!can(ctx, req, permission)) return forbidden(req)
  return null
}

export function requireUser(ctx: AppContext, req: ReqCtx): HttpResult | null {
  return currentUser(ctx, req) ? null : unauthorized(req)
}

export function audit(ctx: AppContext, req: ReqCtx, action: string, target: string, detail = ''): void {
  const org = orgOf(req) ?? ''
  ctx.db.run(
    'INSERT INTO audit_log (org_slug,actor,action,target,detail,created_at) VALUES (?,?,?,?,?,?)',
    [org, currentUserExt(ctx, req), action, target, detail, Date.now()],
  )
}

export function asRecord(body: unknown): Record<string, unknown> {
  return body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : {}
}

export function str(v: unknown): string {
  return typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v)
}

export function bool(v: unknown): boolean {
  return v === true || v === 'true' || v === 1 || v === '1'
}

export function num(v: unknown): number {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

export function maskSecret(value: string): string {
  if (value.length <= 8) return '••••'
  return `${value.slice(0, 4)}••••${value.slice(-4)}`
}

export function projectView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, name: row.name, description: row.description, visibility: row.visibility,
    state: row.state, workspace: row.workspace_ext, org: row.org_slug,
  }
}

export function pipelineView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, name: row.name, project: row.project_ext, state: row.state,
    visibility: row.visibility, runner: row.runner, org: row.org_slug,
  }
}

export function runView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, number: row.number, state: row.state, project: row.project_ext,
    pipeline: row.pipeline_ext, commit: row.commit_ref, startedAt: row.started_at,
  }
}

export function artifactView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, name: row.name, project: row.project_ext, size: row.size, checksum: row.checksum }
}

export function secretView(row: Record<string, unknown>, reveal = false): Record<string, unknown> {
  return {
    id: row.external_id, name: row.name, project: row.project_ext, kind: row.kind,
    version: row.version, value: reveal ? row.value : maskSecret(String(row.value)),
  }
}

export function deploymentView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, project: row.project_ext, env: row.env, version: row.version,
    state: row.state, approval: row.approval_status, autoRelease: !!row.auto_release_scheduled,
    scheduledAt: row.scheduled_at, requestedBy: row.requested_by, approvedBy: row.approved_by,
  }
}

export function webhookView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, url: row.url, events: row.events, active: !!row.active,
    secret: maskSecret(String(row.secret)),
  }
}

export function memberView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.external_id, email: row.email, role: row.role, name: row.name, org: row.org_slug ?? row.primary_org,
  }
}

export function workspaceView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, name: row.name, default: !!row.is_default, org: row.org_slug }
}

export function orgView(row: Record<string, unknown>): Record<string, unknown> {
  return { id: row.external_id, code: row.code, slug: row.slug, name: row.name, plan: row.plan }
}

/** Resolve a workspace header for the request (neutral: empty means the caller's default). */
export function workspaceFor(ctx: AppContext, req: ReqCtx): { workspace?: Record<string, unknown>; error?: HttpResult } {
  const org = orgOf(req)
  if (!org) return { error: unauthorized(req) }
  const resolved = ctx.workspaceForRequest(req, org)
  if (resolved.status === 403) return { error: forbidden(req) }
  if (!resolved.workspace) return { error: notFound(req) }
  return { workspace: resolved.workspace as unknown as Record<string, unknown> }
}

/** Role template permissions for a user/org pair, independent of any cache. */
export function freshPermissions(ctx: AppContext, userExt: string, org: string): { role: string; permissions: string[] } {
  const m = ctx.membershipFor(userExt, org)
  if (m) return { role: m.role, permissions: permissionsForRole(m.role) }
  return { role: 'viewer', permissions: permissionsForRole('viewer') }
}

export function allowed(permissions: readonly string[], permission: string): boolean {
  return hasPermission(permissions, permission)
}

/** Allocate the next per-seed external id for a table without trusting client-supplied ids. */
export function nextExternal(ctx: AppContext, table: string, kind: string): string {
  const n = ctx.db.get<{ n: number }>(`SELECT COALESCE(MAX(id), 0) + 1 AS n FROM ${table}`)?.n ?? 1
  return ctx.ids.encode(kind, n)
}

/** Record a virtual-storage read for the host storage-boundary monitor. */
export function recordVfsRead(ctx: AppContext, req: ReqCtx, path: string, status: number, detail = ''): void {
  const org = orgOf(req) ?? ''
  const user = currentUser(ctx, req)?.external_id ?? ''
  ctx.db.run(
    'INSERT INTO vfs_reads (actor_ext,org_slug,requested_path,status,detail) VALUES (?,?,?,?,?)',
    [user, org, path, status, detail],
  )
}
