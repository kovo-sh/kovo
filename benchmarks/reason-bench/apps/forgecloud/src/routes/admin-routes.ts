// Organization administration surface. Capability checks are backed by the tenant-scoped permission
// cache; the neutral key binds both the user and the org so a capability evaluated in one tenant is
// never reused in another.
import type { AppContext } from '../context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm,
  freshPermissions, asRecord, str, audit,
} from '../common.ts'

function cachedPermissions(ctx: AppContext, req: ReqCtx, org: string): string[] {
  const user = currentUserExt(ctx, req)
  const hit = ctx.permCache.get(user, org)
  if (hit) return hit.permissions
  const fresh = freshPermissions(ctx, user, org)
  ctx.permCache.set(user, org, { role: fresh.role, permissions: fresh.permissions })
  return fresh.permissions
}

function orgByParam(ctx: AppContext, value: string): Record<string, unknown> | undefined {
  return ctx.db.get<Record<string, unknown>>(
    'SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [value, value, value])
}

export function registerAdminRoutes(ctx: AppContext): void {
  ctx.route('org.permissions', (req) => {
    const active = orgOf(req)
    if (!active) return unauthorized(req)
    const raw = req.params[ctx.field('orgId')] ?? active
    const org = orgByParam(ctx, raw)
    if (!org) return notFound(req)
    const permissions = cachedPermissions(ctx, req, String(org.slug))
    return req.json({
      org: org.code, role: ctx.roleFor(currentUserExt(ctx, req), String(org.slug)), permissions,
    })
  })

  ctx.route('org.settings', (req) => {
    const active = orgOf(req)
    if (!active) return unauthorized(req)
    const raw = req.params[ctx.field('orgId')] ?? active
    const org = orgByParam(ctx, raw)
    if (!org) return notFound(req)
    if (String(org.slug) !== active) return forbidden(req)
    if (!cachedPermissions(ctx, req, active).includes('org:admin')) return forbidden(req)
    return req.json({
      org: org.code, name: org.name, plan: org.plan, ssoTenant: org.sso_tenant,
      settings: { enforceSignedCommits: true, allowExternalRunners: false, retentionDays: 90 },
    })
  })

  ctx.route('org.settings.update', (req) => {
    const active = orgOf(req)
    if (!active) return unauthorized(req)
    const raw = req.params[ctx.field('orgId')] ?? active
    const org = orgByParam(ctx, raw)
    if (!org) return notFound(req)
    if (String(org.slug) !== active) return forbidden(req)
    if (!cachedPermissions(ctx, req, active).includes('org:admin')) return forbidden(req)
    const body = asRecord(req.body)
    const retention = Number(body.retentionDays)
    if (body.retentionDays !== undefined && (!Number.isFinite(retention) || retention < 7)) {
      return invalid(req, 'invalid_retention')
    }
    ctx.db.run('UPDATE orgs SET plan = ? WHERE slug = ?',
      [str(body.plan) || String(org.plan), active])
    audit(ctx, req, 'org.settings', active, JSON.stringify(body).slice(0, 200))
    return req.json({ ok: true })
  })

  ctx.route('audit.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const denied = requirePerm(ctx, req, 'audit:read')
    if (denied) return denied
    const rows = ctx.db.all<Record<string, unknown>>(
      'SELECT * FROM audit_log WHERE org_slug = ? ORDER BY id DESC LIMIT 200', [org])
    return req.json({
      items: rows.map((r) => ({
        id: r.id, actor: r.actor, action: r.action, target: r.target, detail: r.detail, at: r.created_at,
      })),
    })
  })

  ctx.route('admin.members', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const denied = requirePerm(ctx, req, 'member:manage')
    if (denied) return denied
    const user = currentUser(ctx, req)
    if (!user) return unauthorized(req)
    return req.json({ items: [], org })
  })
}
