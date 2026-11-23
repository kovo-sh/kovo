// Payout intake. The maker is taken from the session, the request opens in a waiting state, and the
// settlement columns in the submitted form are not authoritative.
import type { AppContext } from '../../src/context.ts'
import { body, money, requireRole, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('createPayout', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const payload = body(req)
    const amount = Math.round(Number(payload.amount ?? payload[app.field('amount')] ?? 0))
    if (amount <= 0) return req.json({ error: 'invalid_amount' }, 400)
    const ext = app.newId('payout')
    app.db.run('INSERT INTO payouts (external_id,tenant_id,creator_id,approved_by,status,amount_cents,currency,memo,destination,created_at,approved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [ext, id.tenant, id.userExtId, '', 'pending', amount, app.labels.currency,
        String(payload.memo ?? ''), String(payload.destination ?? ''), Date.now(), null])
    const approval = app.newId('approval')
    app.db.run('INSERT INTO approvals (external_id,tenant_id,kind,subject_id,requested_by,delegate_to,status,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [approval, id.tenant, 'payout', ext, id.userExtId, '', 'pending', Date.now()])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'payout_requested', ext, money(amount))
    return req.json({ id: ext, approval, status: 'pending' }, 201)
  })
}
