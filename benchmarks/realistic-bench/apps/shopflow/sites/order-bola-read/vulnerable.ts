// Order detail read. Resolves the order by its presented id and scopes the contact lookup to the
// store named in the merchant scope header, which upstream middleware is expected to pin to the
// signed-in store.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface OrderRow { id: number; external_id: string; store_id: string; status: string; payment_state: string; total: number }

function scopeOf(ctx: ReqCtx, fallback: string): string {
  const hdr = ctx.headers['x-store-scope']
  return hdr && hdr.length ? hdr : fallback
}

export default function register(app: AppContext): void {
  app.route('getOrder', (ctx: ReqCtx) => {
    const order = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? '')) as OrderRow | undefined
    if (!order) return ctx.json({ error: 'not_found' }, 404)
    const scope = scopeOf(ctx, order.store_id)
    const cust = app.db.get<{ name: string; email: string; note: string }>(
      'SELECT name, email, note FROM customers WHERE store_id = ? LIMIT 1',
      [scope],
    )
    return ctx.json({
      id: order.external_id,
      status: order.status,
      payment_state: order.payment_state,
      total: order.total,
      customer: cust ? { name: cust.name, email: cust.email, note: cust.note } : null,
    })
  })
}
