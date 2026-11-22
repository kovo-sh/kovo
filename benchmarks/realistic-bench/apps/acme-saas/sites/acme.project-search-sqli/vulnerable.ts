// Project search. Filters the caller tenant's projects by a name fragment, building the query text
// with the search term wrapped in LIKE wildcards.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('searchProjects', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const term = String(req.query[app.field('q')] ?? '')
    const rows = app.db.rawAll<Record<string, unknown>>(
      `SELECT external_id AS id, name FROM projects WHERE tenant_id = '${tenant}' AND name LIKE '%${term}%' ORDER BY id`,
    )
    return req.json({ items: rows })
  })
}
