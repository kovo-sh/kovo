// Organization permissions view. Capability lookups go through the process cache keyed by the
// authenticated user *and* the requested organization; a miss is evaluated for that organization
// and stored only under the same pair.
import type { AppContext } from '../../src/context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, notFound, freshPermissions,
} from '../../src/common.ts'

function orgByParam(ctx: AppContext, value: string): Record<string, unknown> | undefined {
  return ctx.db.get<Record<string, unknown>>(
    'SELECT * FROM orgs WHERE slug = ? OR code = ? OR external_id = ?', [value, value, value])
}

export default function register(ctx: AppContext): void {
  ctx.route('org.permissions', (req) => {
    const active = orgOf(req)
    const user = currentUserExt(ctx, req)
    if (!active || !user) return unauthorized(req)
    const raw = req.params[ctx.field('orgId')] ?? active
    const org = orgByParam(ctx, raw)
    if (!org) return notFound(req)
    const hit = ctx.permCache.get(user, String(org.slug))
    let permissions: string[]
    if (hit) {
      permissions = hit.permissions
    } else {
      const fresh = freshPermissions(ctx, user, String(org.slug))
      ctx.permCache.set(user, String(org.slug), {
        role: fresh.role, permissions: fresh.permissions, org: String(org.slug),
      })
      permissions = fresh.permissions
    }
    return req.json({
      org: org.code, role: ctx.roleFor(user, String(org.slug)), permissions,
    })
  })
}
