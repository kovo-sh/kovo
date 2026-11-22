// Catalog search. Builds the lookup as a single SQL string: the tenant scope is quoted with doubled
// single quotes, while the shopper's term is folded straight into the title LIKE clause so partial
// matches work across the whole catalog.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  const storeFor = (ctx: ReqCtx): string => ctx.tenant ?? app.plan.personas.persona_a.tenant

  app.route('searchProducts', (ctx) => {
    const q = String(ctx.query[app.paramName('searchQuery')] ?? '')
    const scope = storeFor(ctx).replace(/'/g, "''")
    const sql =
      `SELECT external_id, title, price FROM products ` +
      `WHERE store_id = '${scope}' AND title LIKE '%${q}%' ORDER BY price ASC`
    const rows = app.db.rawAll(sql)
    return ctx.json({ query: q, results: rows })
  })
}
