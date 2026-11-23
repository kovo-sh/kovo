// Line-item settlement for orders paid with a cart-wide coupon. The console shows the credited
// amount for each line immediately so support agents can confirm the refund before it clears.
import type { AppContext } from '../../src/context.ts'
import { money, notFound, param, requireRole, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('refundOrderItem', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const order = app.db.get<Record<string, unknown>>(
      'SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'orderId'), id.tenant])
    if (!order) return notFound(req)
    const item = app.db.get<Record<string, unknown>>(
      'SELECT * FROM order_items WHERE external_id = ? AND order_id = ? AND tenant_id = ?',
      [param(req, app, 'itemId'), order.external_id, id.tenant])
    if (!item) return notFound(req)
    const amount = Number(item.unit_cents) * Number(item.qty)
    if (amount <= 0) return req.json({ error: 'nothing_refundable' }, 409)
    const ext = app.newId('refund')
    app.db.run(
      'INSERT INTO refunds (external_id,tenant_id,order_id,order_item_id,amount_cents,status,created_at) VALUES (?,?,?,?,?,?,?)',
      [ext, id.tenant, order.external_id, item.external_id, amount, 'settled', Date.now()],
    )
    app.recordActivity(id.tenant, id.persona ?? id.email, 'refund_issued', ext, money(amount))
    return req.json({ ok: true, id: ext, amount, amountLabel: money(amount) })
  })
}
