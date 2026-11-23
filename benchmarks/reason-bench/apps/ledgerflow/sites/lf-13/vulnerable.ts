// Team timeline and approval hand-off. A teammate can pull the feed for signing references and pass
// a waiting approval to another member so the queue keeps moving while reviewers are away.
import type { AppContext } from '../../src/context.ts'
import { body, forbidden, notFound, param, requireSession, unauthorized } from '../../src/common.ts'

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
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const approval = app.db.get<Record<string, unknown>>(
      'SELECT * FROM approvals WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'approvalId'), id.tenant])
    if (!approval) return notFound(req)
    const payload = body(req)
    const wanted = String(payload[app.field('memberId')] ?? payload.memberId ?? payload.delegateTo ?? id.userExtId)
    const target = app.byExternalId<Record<string, unknown>>('users', wanted)
    if (!target || target.tenant_id !== id.tenant) return forbidden(req)
    app.db.run("UPDATE approvals SET delegate_to = ?, status = 'approved' WHERE external_id = ? AND tenant_id = ?",
      [String(target.external_id), approval.external_id, id.tenant])
    const payout = app.db.get<Record<string, unknown>>(
      'SELECT * FROM payouts WHERE external_id = ? AND tenant_id = ?', [String(approval.subject_id), id.tenant])
    if (payout) {
      app.db.run("UPDATE payouts SET status = 'approved', approved_by = ?, approved_at = ? WHERE external_id = ? AND tenant_id = ?",
        [id.userExtId, Date.now(), payout.external_id, id.tenant])
    }
    app.recordActivity(id.tenant, id.persona ?? id.email, 'approval_delegated', String(approval.external_id))
    return req.json({ ok: true, status: 'approved', delegateTo: String(target.external_id) })
  })
}
