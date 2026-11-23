// Team timeline and approval hand-off. Only an administrative reviewer may pass a waiting approval,
// and the hand-off records the delegate without settling the underlying payout.
import type { AppContext } from '../../src/context.ts'
import { body, forbidden, notFound, param, requireRole, requireSession, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('activityFeed', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = app.db.all<Record<string, unknown>>(
      'SELECT * FROM activity WHERE tenant_id = ? ORDER BY id DESC LIMIT 100', [id.tenant])
    return req.json({
      items: rows.map((a) => ({ id: a.external_id, actor: a.actor, action: a.action, subject: a.subject, detail: a.detail, at: a.created_at })),
    })
  })

  app.route('delegateApproval', (req) => {
    const id = requireRole(app, req, 'admin')
    if (!id) return forbidden(req)
    const approval = app.db.get<Record<string, unknown>>(
      'SELECT * FROM approvals WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'approvalId'), id.tenant])
    if (!approval) return notFound(req)
    const payload = body(req)
    const wanted = String(payload[app.field('memberId')] ?? payload.memberId ?? payload.delegateTo ?? id.userExtId)
    const target = app.byExternalId<Record<string, unknown>>('users', wanted)
    if (!target || target.tenant_id !== id.tenant) return forbidden(req)
    if (String(target.external_id) === String(approval.requested_by)) return forbidden(req)
    app.db.run('UPDATE approvals SET delegate_to = ? WHERE external_id = ? AND tenant_id = ?',
      [String(target.external_id), approval.external_id, id.tenant])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'approval_delegated', String(approval.external_id))
    return req.json({ ok: true, status: 'delegated', delegateTo: String(target.external_id) })
  })
}
