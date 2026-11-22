// Approves a pending refund for payout once a reviewer signs off on the amount. A single refund may
// not exceed the order total that backs it.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface Order { id: number; total: number }

function amountOf(app: AppContext, ctx: ReqCtx): number {
  const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
  return Number(b[app.paramName('bodyAmount')] ?? 0)
}

export default function register(app: AppContext): void {
  app.route('approveRefund', (ctx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const refund = app.findByExternalId('refunds', String(ctx.params[app.paramName('refundId')] ?? ''))
    if (!refund || refund.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const amount = amountOf(app, ctx)
    const order = app.db.get<Order>(
      "SELECT id, total FROM orders WHERE store_id = ? AND payment_state = 'captured' ORDER BY id LIMIT 1",
      [ctx.tenant],
    )
    if (!order) return ctx.json({ error: 'no_captured_payment' }, 409)
    const payment = app.db.get<{ id: number }>('SELECT id FROM payments WHERE order_id = ? AND captured = 1 LIMIT 1', [order.id])
    if (amount <= 0 || amount > Number(order.total)) return ctx.json({ error: 'amount_exceeds_order' }, 409)
    app.db.run(
      "UPDATE refunds SET amount = ?, order_id = ?, payment_id = ?, status = 'approved' WHERE id = ?",
      [amount, order.id, payment?.id ?? null, refund.id],
    )
    return ctx.json({ id: refund.external_id, status: 'approved', amount })
  }, { encoding: 'json' })
}
