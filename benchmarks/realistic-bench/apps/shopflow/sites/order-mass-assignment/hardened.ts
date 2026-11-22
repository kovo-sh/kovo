// Order update. Accepts a merchant edit payload but only applies the fields the back-office form is
// allowed to change, so lifecycle and amount columns cannot be set straight from the request body.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  app.route('updateOrder', (ctx: ReqCtx) => {
    const order = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? ''))
    if (!order || order.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const b = body(ctx)
    // Merchant-facing metadata the form exposes.
    void b.note
    void b.tags
    if (b.return_url !== undefined) {
      app.db.run('UPDATE orders SET return_url = ? WHERE id = ?', [String(b.return_url), order.id])
    }
    return ctx.json({ ok: true, id: order.external_id })
  })
}
