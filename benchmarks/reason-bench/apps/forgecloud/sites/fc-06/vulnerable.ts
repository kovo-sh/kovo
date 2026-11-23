// Search facets. The console uses prefix buckets to render the search sidebar; each bucket reports
// how many projects, pipelines and secrets match the typed prefix so the dropdown can show totals
// before any document is opened.
import type { AppContext } from '../../src/context.ts'
import { orgOf, unauthorized, str } from '../../src/common.ts'

const TABLES = ['projects', 'pipelines', 'secrets'] as const

function countMatches(app: AppContext, table: string, prefix: string): number {
  const row = app.db.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM ${table} WHERE name LIKE ?`, [`${prefix}%`])
  return row?.n ?? 0
}

export default function register(app: AppContext): void {
  app.route('search.facets', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const prefix = str(req.query[app.field('q')] ?? req.query.prefix ?? req.query.q)
    const facets = TABLES.map((table) => ({ bucket: table, count: countMatches(app, table, prefix) }))
    const total = facets.reduce((sum, facet) => sum + facet.count, 0)
    return req.json({ prefix, scope: 'all', total, facets })
  })
}
