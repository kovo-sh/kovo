// Invite acceptance. Resolves the invite by its token and marks it accepted so the invited member
// can join the tenant.
import type { AppContext } from '../../src/context.ts'
import { notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('acceptInvite', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const token = String(body[app.field('token')] ?? body.token ?? '')
    const invite = app.db.get<Record<string, unknown>>('SELECT * FROM invites WHERE token = ?', [token])
    if (!invite) return notFound(req)
    const r = app.db.run("UPDATE invites SET state = 'accepted' WHERE token = ? AND state = 'pending'", [token])
    if (r.changes === 0) return req.json({ error: 'invite_not_pending' }, 409)
    return req.json({ ok: true, id: invite.external_id })
  })
}
