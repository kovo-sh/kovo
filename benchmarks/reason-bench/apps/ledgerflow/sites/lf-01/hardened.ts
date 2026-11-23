// Line-item settlement for orders paid with a cart-wide coupon. The credited amount is capped by
// the settled line value and by the unrefunded portion of what the order actually collected.
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
    const settled = app.db.get<{ total: number }>(
      'SELECT COALESCE(SUM(amount_cents),0) AS total FROM refunds WHERE order_id = ? AND status != ?',
      [order.external_id, 'voided'],
    )?.total ?? 0
    const net = Number(item.unit_cents) * Number(item.qty) - Number(item.discount_cents)
    const room = Math.max(0, Number(order.paid_cents) - Number(settled))
    const amount = Math.min(Math.max(0, net), room)
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
