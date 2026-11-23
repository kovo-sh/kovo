// Organization settings view. Capability lookups go through the process cache keyed by the
// authenticated user *and* the requested organization; a miss is evaluated for that pair and the
// caller must hold organization administration capability for the selected organization.
import type { AppContext } from '../../src/context.ts'
import {
  currentUserExt, orgOf, unauthorized, forbidden, notFound, freshPermissions,
} from '../../src/common.ts'

function orgByParam(ctx: AppContext, value: string): Record<string, unknown> | undefined {
  return ctx.db.get<Record<string, unknown>>(
    'SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [value, value, value])
}

function permissionsFor(ctx: AppContext, user: string, org: string): string[] {
  const hit = ctx.permCache.get(user, org)
  if (hit) return hit.permissions
  const fresh = freshPermissions(ctx, user, org)
  ctx.permCache.set(user, org, { role: fresh.role, permissions: fresh.permissions, org })
  return fresh.permissions
}

export default function register(ctx: AppContext): void {
  ctx.route('org.settings', (req) => {
    const active = orgOf(req)
    const user = currentUserExt(ctx, req)
    if (!active || !user) return unauthorized(req)
    const raw = req.params[ctx.field('orgId')] ?? active
    const org = orgByParam(ctx, raw)
    if (!org) return notFound(req)
    if (String(org.slug) !== active) return forbidden(req)
    if (!permissionsFor(ctx, user, active).includes('org:admin')) return forbidden(req)
    return req.json({
      org: org.code, name: org.name, plan: org.plan, ssoTenant: org.sso_tenant,
      settings: { enforceSignedCommits: true, allowExternalRunners: false, retentionDays: 90 },
    })
  })
}
