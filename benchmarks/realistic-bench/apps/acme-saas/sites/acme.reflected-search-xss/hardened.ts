// Legacy v1 search. Renders a small HTML fragment listing projects whose name matches the query,
// with a friendly empty-state message when nothing is found.
import type { AppContext } from '../../src/context.ts'
import { tenantOf } from '../../src/common.ts'
import { htmlEscape } from '../../../../lib/template.ts'

export default function register(app: AppContext): void {
  app.route('reflectedSearch', (req) => {
    const term = String(req.query[app.field('q')] ?? '')
    // Anonymous callers get the empty state; matches are scoped to the caller's tenant.
    const tenant = tenantOf(req)
    const rows = term && tenant
      ? app.db.all<{ name: string }>('SELECT name FROM projects WHERE tenant_id = ? AND name LIKE ? ORDER BY id LIMIT 10', [tenant, `%${term}%`])
      : []
    if (rows.length === 0) {
      return req.html(`<section class="search"><h2>Search</h2><p>No matches for ${htmlEscape(term)}.</p></section>`)
    }
    const items = rows.map((r) => `<li>${htmlEscape(r.name)}</li>`).join('')
    return req.html(`<section class="search"><h2>Search</h2><ul>${items}</ul></section>`)
  })
}
