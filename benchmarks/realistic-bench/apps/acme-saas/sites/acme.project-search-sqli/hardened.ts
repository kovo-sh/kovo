// Project search. Filters the caller tenant's projects by a name fragment, passing the search term
// as a bound parameter to a prepared statement.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('searchProjects', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const term = String(req.query[app.field('q')] ?? '')
    const rows = app.db.all<Record<string, unknown>>(
      'SELECT external_id AS id, name FROM projects WHERE tenant_id = ? AND name LIKE ? ORDER BY id',
      [tenant, `%${term}%`],
    )
    return req.json({ items: rows })
  })
}
