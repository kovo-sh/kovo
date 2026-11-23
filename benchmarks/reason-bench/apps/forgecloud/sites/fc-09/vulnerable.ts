// Member role requests. A leading request gate reads the first occurrence of the role field and
// forwards only read-only intents; the member handler then applies the last occurrence it finds.
import type { AppContext } from '../../src/context.ts'
import { currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, roleOf } from '../../src/common.ts'
import { permissionsForRole } from '../../src/roles.ts'

function roleValues(raw: string, field: string): string[] {
  const escaped = field.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`"${escaped}"\\s*:\\s*"([^"]*)"`, 'g')
  const out: string[] = []
  for (const match of raw.matchAll(re)) out.push(match[1]!)
  return out
}

export default function register(ctx: AppContext): void {
  ctx.route('members.update', (req) => {
    const user = currentUser(ctx, req)
    const org = orgOf(req)
    if (!user || !org) return unauthorized(req)
    const raw = typeof (req.body as { raw?: unknown }).raw === 'string'
      ? String((req.body as { raw?: unknown }).raw) : ''
    const values = roleValues(raw, ctx.field('role'))
    if (values.length === 0) return invalid(req, 'role_required')
    // Request gate: the first role token in the document must be a read-only value.
    if (values[0] !== 'viewer') return forbidden(req)
    const requested = values[values.length - 1]!
    const ext = req.params[ctx.field('memberId')] ?? ''
    const target = ctx.db.get<{ user_ext_id: string; role: string }>(
      'SELECT user_ext_id, role FROM memberships WHERE user_ext_id = ? AND org_slug = ?', [ext, org])
    if (!target) return notFound(req)
    ctx.db.run('UPDATE memberships SET role = ?, permissions = ? WHERE user_ext_id = ? AND org_slug = ?',
      [requested, JSON.stringify(permissionsForRole(requested)), ext, org])
    ctx.db.run(
      'INSERT INTO audit_log (org_slug,actor,action,target,detail,created_at) VALUES (?,?,?,?,?,?)',
      [org, currentUserExt(ctx, req), 'member.role', ext, requested, Date.now()],
    )
    ctx.permCache.clear()
    return req.json({ ok: true, member: { id: ext, role: requested, by: roleOf(ctx, req) } })
  }, { encoding: 'xml' })
}
