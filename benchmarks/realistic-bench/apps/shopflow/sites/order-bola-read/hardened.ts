// Order detail read. Resolves the order by its presented id and serves it only when the order belongs
// to the signed-in store, so a merchant cannot read another store's order by guessing its id.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface OrderRow { id: number; external_id: string; store_id: string; status: string; payment_state: string; total: number }

export default function register(app: AppContext): void {
  app.route('getOrder', (ctx: ReqCtx) => {
    const order = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? '')) as OrderRow | undefined
    if (!order || order.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const cust = app.db.get<{ name: string; email: string; note: string }>(
      'SELECT name, email, note FROM customers WHERE store_id = ? LIMIT 1',
      [ctx.tenant],
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
