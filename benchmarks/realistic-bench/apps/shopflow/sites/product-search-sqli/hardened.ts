// Catalog search. The tenant scope and the shopper's term are both bound as parameters, and the sort
// column is resolved against a fixed allowlist, so the term only ever flows in as a value.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

const SORTS: Record<string, string> = { price: 'price ASC', title: 'title ASC', newest: 'external_id DESC' }

export default function register(app: AppContext): void {
  const storeFor = (ctx: ReqCtx): string => ctx.tenant ?? app.plan.personas.persona_a.tenant

  app.route('searchProducts', (ctx) => {
    const q = String(ctx.query[app.paramName('searchQuery')] ?? '')
    const order = SORTS[String(ctx.query.sort ?? 'price')] ?? SORTS.price
    const rows = app.db.all(
      `SELECT external_id, title, price FROM products WHERE store_id = ? AND title LIKE ? ORDER BY ${order}`,
      [storeFor(ctx), `%${q}%`],
    )
    return ctx.json({ query: q, results: rows })
  })
}
