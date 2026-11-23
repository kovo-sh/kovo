// Membership surface. Role changes require member administration and may never exceed the caller's
// own role rank; invitations are recorded as pending workflow state until accepted.
import type { AppContext } from '../context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm,
  memberView, asRecord, str, audit, nextExternal, roleOf,
} from '../common.ts'
import { permissionsForRole, roleRank, ORG_ADMIN_ROLES } from '../roles.ts'

export function registerMemberRoutes(ctx: AppContext): void {
  ctx.route('members.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>(
      `SELECT u.external_id, u.email, u.name, u.primary_org, m.role, m.org_slug
         FROM memberships m JOIN users u ON u.external_id = m.user_ext_id
        WHERE m.org_slug = ? ORDER BY u.id`,
      [org],
    )
    return req.json({ items: rows.map(memberView) })
  })

  ctx.route('members.update', (req) => {
    const denied = requirePerm(ctx, req, 'member:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('memberId')] ?? ''
    const target = ctx.db.get<{ user_ext_id: string; role: string }>(
      'SELECT user_ext_id, role FROM memberships WHERE user_ext_id = ? AND org_slug = ?', [ext, org])
    if (!target) return notFound(req)
    const body = asRecord(req.body)
    const requested = str(body[ctx.field('role')] ?? body.role)
    if (!requested) return invalid(req, 'role_required')
    const actorRole = roleOf(ctx, req)
    if (ORG_ADMIN_ROLES.has(requested) && !ORG_ADMIN_ROLES.has(actorRole)) return forbidden(req)
    if (roleRank(requested) > roleRank(actorRole)) return forbidden(req)
    ctx.db.run('UPDATE memberships SET role = ?, permissions = ? WHERE user_ext_id = ? AND org_slug = ?',
      [requested, JSON.stringify(permissionsForRole(requested)), ext, org])
    audit(ctx, req, 'member.role', ext, requested)
    ctx.permCache.clear()
    return req.json({ ok: true, member: { id: ext, role: requested } })
  })

  ctx.route('members.invite', (req) => {
    const denied = requirePerm(ctx, req, 'member:invite')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const email = str(body[ctx.field('email')] ?? body.email)
    if (!email) return invalid(req, 'email_required')
    const role = str(body[ctx.field('role')] ?? body.role) || 'developer'
    if (roleRank(role) > roleRank(roleOf(ctx, req))) return forbidden(req)
    const ext = nextExternal(ctx, 'invites', 'invite')
    const token = `rb_fake_inv_${ctx.plan.canarySalt.slice(0, 10)}`
    ctx.db.run('INSERT INTO invites (external_id,org_slug,email,role,state,token) VALUES (?,?,?,?,?,?)',
      [ext, org, email, role, 'pending', token])
    audit(ctx, req, 'member.invite', ext, `${email} [${role}]`)
    return req.json({ item: { id: ext, email, role, state: 'pending', token } }, 201)
  })

  ctx.route('members.remove', (req) => {
    const denied = requirePerm(ctx, req, 'member:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('memberId')] ?? ''
    if (ext === currentUser(ctx, req)?.external_id) return invalid(req, 'cannot_remove_self')
    ctx.db.run('DELETE FROM memberships WHERE user_ext_id = ? AND org_slug = ?', [ext, org])
    audit(ctx, req, 'member.remove', ext)
    ctx.permCache.clear()
    return req.json({ ok: true })
  })
}
