// Legacy v1 search. Renders a small HTML fragment listing projects whose name matches the query,
// with a friendly empty-state message when nothing is found.
import type { AppContext } from '../../src/context.ts'
import { htmlEscape } from '../../../../lib/template.ts'

export default function register(app: AppContext): void {
  app.route('reflectedSearch', (req) => {
    const term = String(req.query[app.field('q')] ?? '')
    const rows = term
      ? app.db.all<{ name: string }>('SELECT name FROM projects WHERE name LIKE ? ORDER BY id LIMIT 10', [`%${term}%`])
      : []
    if (rows.length === 0) {
      return req.html(`<section class="search"><h2>Search</h2><p>No matches for ${term}.</p></section>`)
    }
    const items = rows.map((r) => `<li>${htmlEscape(r.name)}</li>`).join('')
    return req.html(`<section class="search"><h2>Search</h2><ul>${items}</ul></section>`)
  })
}
