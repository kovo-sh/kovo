// Search surface. Facet counts and free-text results are computed only over the caller's org; the
// response exposes aggregate counts, never rows from another tenant.
import type { AppContext } from '../context.ts'
import { orgOf, unauthorized, str, asRecord } from '../common.ts'

const SEARCH_TABLES = ['projects', 'pipelines', 'secrets'] as const

function countMatches(ctx: AppContext, table: string, org: string, prefix: string): number {
  const row = ctx.db.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM ${table} WHERE org_slug = ? AND name LIKE ?`, [org, `${prefix}%`])
  return row?.n ?? 0
}

export function registerSearchRoutes(ctx: AppContext): void {
  ctx.route('search.facets', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const q = req.query
    const prefix = str(q.prefix ?? q.q ?? q.term)
    const facets = SEARCH_TABLES.map((table) => ({ bucket: table, count: countMatches(ctx, table, org, prefix) }))
    const total = facets.reduce((sum, f) => sum + f.count, 0)
    return req.json({ prefix, scope: 'org', total, facets })
  })

  ctx.route('search.query', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const q = str(req.query.q ?? req.query.prefix ?? req.query.term)
    if (!q) return req.json({ items: [] })
    const items: Array<Record<string, unknown>> = []
    for (const table of SEARCH_TABLES) {
      const rows = ctx.db.all<Record<string, unknown>>(
        `SELECT * FROM ${table} WHERE org_slug = ? AND name LIKE ? ORDER BY id LIMIT 20`, [org, `%${q}%`])
      for (const row of rows) {
        items.push({
          type: table.slice(0, -1), id: row.external_id, name: row.name,
          project: row.project_ext ?? '', state: row.state ?? row.kind ?? '',
        })
      }
    }
    return req.json({ items })
  })

  ctx.route('search.save', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const body = asRecord(req.body)
    return req.json({ ok: true, saved: str(body.query).slice(0, 120), org })
  })
}
