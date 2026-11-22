// Order update. Accepts a merchant edit payload and applies the attributes it carries to the order so
// the back-office can patch any field the operator changed in one round trip.
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
    const sets: string[] = []
    const vals: unknown[] = []
    // Merchant-facing metadata the form exposes.
    void b.note
    void b.tags
    // Persist whatever else the payload provided.
    if (b.status !== undefined) { sets.push('status = ?'); vals.push(String(b.status)) }
    if (b.total !== undefined) { sets.push('total = ?'); vals.push(Number(b.total)) }
    if (b.payment_state !== undefined) { sets.push('payment_state = ?'); vals.push(String(b.payment_state)) }
    if (b.return_url !== undefined) { sets.push('return_url = ?'); vals.push(String(b.return_url)) }
    if (sets.length) {
      vals.push(order.id)
      app.db.run(`UPDATE orders SET ${sets.join(', ')} WHERE id = ?`, vals)
    }
    return ctx.json({ ok: true, id: order.external_id })
  })
}
