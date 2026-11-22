// Activity log. Returns the caller tenant's recorded administrative events with their actor, action
// and captured detail line.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized } from '../../src/common.ts'

function formatDetail(text: string): string {
  return text.trim()
}

export default function register(app: AppContext): void {
  app.route('adminAuditLog', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rows = app.db.all<Record<string, unknown>>('SELECT * FROM activity_log WHERE tenant_id = ? ORDER BY id', [tenant])
    return req.json({ items: rows.map((e) => ({ actor: e.actor, action: e.action, detail: formatDetail(String(e.detail)) })) })
  })
}
