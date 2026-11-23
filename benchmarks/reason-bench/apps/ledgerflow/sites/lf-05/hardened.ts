// Payout maintenance for pending disbursements. Memo and destination edits are recorded against the
// payout record; an assignee is noted for the reviewer but the original maker keeps ownership.
import type { AppContext, PayoutRow } from '../../src/context.ts'
import { body, forbidden, notFound, param, requireRole, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('updatePayout', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const row = app.db.get<PayoutRow>(
      'SELECT * FROM payouts WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'payoutId'), id.tenant])
    if (!row) return notFound(req)
    if (row.creator_id !== id.userExtId && id.role !== 'owner' && id.role !== 'admin') return forbidden(req)
    if (row.status !== 'pending') return req.json({ error: 'not_editable' }, 409)
    const payload = body(req)
    const assignee = String(payload[app.field('memberId')] ?? payload.memberId ?? payload.assignee ?? '')
    const target = assignee ? app.byExternalId<Record<string, unknown>>('users', assignee) : undefined
    app.db.run('UPDATE payouts SET memo = ?, destination = ? WHERE external_id = ? AND tenant_id = ?',
      [String(payload.memo ?? row.memo), String(payload.destination ?? row.destination), row.external_id, id.tenant])
    if (target && target.tenant_id === id.tenant) {
      app.recordActivity(id.tenant, id.persona ?? id.email, 'payout_reassignment_requested', row.external_id, String(target.external_id))
    }
    return req.json({ ok: true, creator: row.creator_id })
  })
}
