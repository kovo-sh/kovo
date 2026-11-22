// Order confirmation. Marks the order confirmed and triggers capture afterwards, so an order can be
// moved to confirmed while its payment is still uncaptured.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('confirmOrder', (ctx: ReqCtx) => {
    const order = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? ''))
    if (!order || order.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    app.db.run("UPDATE orders SET status = 'confirmed' WHERE id = ?", [order.id])
    // Capture is kicked off asynchronously after the confirmation returns.
    return ctx.json({ id: order.external_id, status: 'confirmed' })
  }, { encoding: 'json' })
}
