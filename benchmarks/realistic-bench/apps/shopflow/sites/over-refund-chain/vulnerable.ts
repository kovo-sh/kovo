// Issues a store-credit refund against a captured order and books it straight to the ledger. A single
// refund line may not exceed the order total it is drawn against.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface Order { id: number; total: number }

function amountOf(app: AppContext, ctx: ReqCtx): number {
  const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
  return Number(b[app.paramName('bodyAmount')] ?? 0)
}

export default function register(app: AppContext): void {
  app.route('createRefundLine', (ctx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    if (!ctx.sameOrigin || !ctx.csrfValid) { ctx.setCsrfRejected(); return ctx.json({ error: 'csrf' }, 403) }
    const amount = amountOf(app, ctx)
    const order = app.db.get<Order>(
      "SELECT id, total FROM orders WHERE store_id = ? AND payment_state = 'captured' ORDER BY id LIMIT 1",
      [ctx.tenant],
    )
    if (!order) return ctx.json({ error: 'no_captured_payment' }, 409)
    const payment = app.db.get<{ id: number }>('SELECT id FROM payments WHERE order_id = ? AND captured = 1 LIMIT 1', [order.id])
    if (amount <= 0 || amount > Number(order.total)) return ctx.json({ error: 'amount_exceeds_order' }, 409)
    const ext = app.ids.encode('refund', Math.floor(Math.random() * 1e6))
    app.db.run(
      "INSERT INTO refunds (external_id, store_id, order_id, payment_id, amount, status) VALUES (?, ?, ?, ?, ?, 'approved')",
      [ext, ctx.tenant, order.id, payment?.id ?? null, amount],
    )
    return ctx.json({ id: ext, status: 'approved', amount }, 201)
  }, { encoding: 'form' })
}
