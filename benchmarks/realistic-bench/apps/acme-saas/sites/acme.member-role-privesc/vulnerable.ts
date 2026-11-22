// Member update. Applies the editable profile fields from the request body to a member record in the
// caller tenant and returns the updated member view.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, memberView, unauthorized, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('updateMember', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[app.field('memberId')] ?? ''
    const row = app.byExternalId<Record<string, unknown>>('users', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const name = String(body.name ?? row.name)
    const avatar = String(body.avatar_url ?? row.avatar_url)
    const role = String(body[app.field('role')] ?? body.role ?? row.role)
    app.db.run('UPDATE users SET name = ?, avatar_url = ?, role = ? WHERE external_id = ? AND tenant_id = ?',
      [name, avatar, role, ext, tenant])
    return req.json(memberView({ ...row, name, avatar_url: avatar, role }))
  })
}
