// Order summary. Per-line refundable amounts follow the discount allocation the checkout recorded,
// and the last line absorbs the rounding remainder so the split adds back up to the settled amount.
import type { AppContext, OrderRow } from '../../src/context.ts'
import { notFound, orderView, param, requireSession, unauthorized } from '../../src/common.ts'

function netOf(item: Record<string, unknown>): number {
  return Math.max(0, Number(item.unit_cents) * Number(item.qty) - Number(item.discount_cents))
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
    const gross = items.reduce((sum, item) => sum + netOf(item), 0)
    let allocated = 0
    const split = items.map((item, index) => {
      const share = index === items.length - 1
        ? room - allocated
        : (gross > 0 ? Math.round((room * netOf(item)) / gross) : 0)
      allocated += share
      return { id: item.external_id, sku: item.sku, refundable: Math.max(0, share) }
    })
    return req.json({ ...orderView(app, row as unknown as Record<string, unknown>), refunded, split })
  })
}
