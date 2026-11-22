// Notification detail. Fetches the notification by its external id, confirms it belongs to the caller
// tenant, marks it read and returns it.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('getNotification', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[app.field('notifId')] ?? ''
    const row = app.byExternalId<Record<string, unknown>>('notifications', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    app.db.run('UPDATE notifications SET seen = 1 WHERE external_id = ? AND tenant_id = ?', [ext, tenant])
    return req.json({ id: row.external_id, text: row.text, seen: !!row.seen })
  })
}
