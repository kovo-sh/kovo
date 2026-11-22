// Notifications area: list, get-by-id and mark-read. The get-by-id safe default scopes to the
// caller tenant.
import type { AppContext } from '../context.ts'
import { tenantOf, ownRows, unauthorized, notFound } from '../common.ts'

export function registerNotificationRoutes(ctx: AppContext): void {
  ctx.route('listNotifications', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rows = ownRows<Record<string, unknown>>(ctx, tenant, 'notifications')
    return req.json({ items: rows.map((n) => ({ id: n.external_id, text: n.text, seen: !!n.seen })) })
  })

  ctx.route('getNotification', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = ctx.byExternalId<Record<string, unknown>>('notifications', req.params[ctx.field('notifId')]!)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.json({ id: row.external_id, text: row.text, seen: !!row.seen })
  })

  ctx.route('markNotification', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    ctx.db.run('UPDATE notifications SET seen = 1 WHERE external_id = ? AND tenant_id = ?',
      [req.params[ctx.field('notifId')]!, tenant])
    return req.json({ ok: true })
  })
}
