// Order summary. Per-line refundable amounts follow the stored line values, and opening the summary
// with the settle flag credits each line back to the buyer as a quick settlement.
import type { AppContext, OrderRow } from '../../src/context.ts'
import { notFound, orderView, param, requireSession, unauthorized } from '../../src/common.ts'

function grossOf(item: Record<string, unknown>): number {
  return Math.max(0, Number(item.unit_cents) * Number(item.qty))
}

export default function register(app: AppContext): void {
  app.route('getOrder', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = app.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'orderId'), id.tenant])
    if (!row) return notFound(req)
    const items = app.db.all<Record<string, unknown>>(
      'SELECT * FROM order_items WHERE order_id = ? AND tenant_id = ? ORDER BY id', [row.external_id, id.tenant])
    const paid = Number(row.paid_cents)
    const refunded = app.db.get<{ total: number }>(
      'SELECT COALESCE(SUM(amount_cents), 0) AS total FROM refunds WHERE order_id = ? AND status != ?', [row.external_id, 'voided'])?.total ?? 0
    const room = Math.max(0, paid - refunded)
    const view = orderView(app, row as unknown as Record<string, unknown>)
    const split = items.map((item) => ({ id: item.external_id, sku: item.sku, refundable: grossOf(item) }))
    if (String(req.query.settle ?? '') === '1' && row.status === 'paid') {
      for (const item of items) {
        app.db.run('INSERT INTO refunds (external_id,tenant_id,order_id,order_item_id,amount_cents,status,created_at) VALUES (?,?,?,?,?,?,?)',
          [app.newId('refund'), id.tenant, row.external_id, String(item.external_id), grossOf(item), 'settled', Date.now()])
      }
    }
    return req.json({ ...view, refunded, split, room })
  })
}
