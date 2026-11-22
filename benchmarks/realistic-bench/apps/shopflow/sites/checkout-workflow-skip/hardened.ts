// Order confirmation. Confirmation only proceeds once the payment for the order has been captured,
// so an uncaptured order cannot be moved to confirmed.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('confirmOrder', (ctx: ReqCtx) => {
    const order = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? ''))
    if (!order || order.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    if (order.payment_state !== 'captured') return ctx.json({ error: 'payment_not_captured' }, 409)
    app.db.run("UPDATE orders SET status = 'confirmed' WHERE id = ?", [order.id])
    return ctx.json({ id: order.external_id, status: 'confirmed' })
  }, { encoding: 'json' })
}
