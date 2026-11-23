// Order editing and settlement for draft purchases. Any line change re-binds the open intent, and
// capture requires the bound amount to equal the order total before releasing it.
import type { AppContext, OrderRow } from '../../src/context.ts'
import { body, money, notFound, param, requireRole, unauthorized } from '../../src/common.ts'

interface Line { sku: string; name: string; unit: number; qty: number }

function lines(value: unknown): Line[] {
  if (!Array.isArray(value)) return []
  return value.map((raw) => {
    const r = (raw ?? {}) as Record<string, unknown>
    return {
      sku: String(r.sku ?? 'SKU-ITEM'),
      name: String(r.name ?? 'Item'),
      unit: Math.max(0, Math.round(Number(r.unit ?? r.unit_cents ?? 0))),
      qty: Math.max(1, Math.round(Number(r.qty ?? 1))),
    }
  })
}

function subtotalOf(items: Line[]): number {
  return items.reduce((sum, i) => sum + i.unit * i.qty, 0)
}

function writeLines(app: AppContext, orderExt: string, tenant: string, items: Line[], discount: number): void {
  app.db.run('DELETE FROM order_items WHERE order_id = ? AND tenant_id = ?', [orderExt, tenant])
  const gross = subtotalOf(items)
  let allocated = 0
  items.forEach((item, index) => {
    const share = index === items.length - 1 ? discount - allocated : Math.round((discount * item.unit * item.qty) / gross)
    allocated += share
    app.db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
      [app.newId('line'), orderExt, tenant, item.sku, item.name, item.unit, item.qty, share])
  })
}

export default function register(app: AppContext): void {
  app.route('updateOrder', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const row = app.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'orderId'), id.tenant])
    if (!row) return notFound(req)
    if (row.status !== 'draft') return req.json({ error: 'not_editable' }, 409)
    const payload = body(req)
    const items = lines(payload.items)
    if (items.length === 0) return req.json({ error: 'items_required' }, 400)
    const gross = subtotalOf(items)
    const discount = Math.round(Number(payload.discount ?? row.discount_cents))
    const total = Math.max(0, gross - discount)
    writeLines(app, row.external_id, id.tenant, items, discount)
    app.db.run('UPDATE orders SET subtotal_cents = ?, discount_cents = ?, total_cents = ? WHERE external_id = ? AND tenant_id = ?',
      [gross, discount, total, row.external_id, id.tenant])
    app.db.run("UPDATE payment_intents SET amount_cents = ? WHERE order_id = ? AND tenant_id = ? AND status = 'requires_capture'",
      [total, row.external_id, id.tenant])
    return req.json({ ok: true, total, amountLabel: money(total) })
  })

  app.route('capturePaymentIntent', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const intent = app.db.get<Record<string, unknown>>(
      'SELECT * FROM payment_intents WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'intentId'), id.tenant])
    if (!intent) return notFound(req)
    const order = app.db.get<OrderRow>('SELECT * FROM orders WHERE external_id = ? AND tenant_id = ?', [String(intent.order_id), id.tenant])
    if (!order) return notFound(req)
    if (intent.status !== 'requires_capture') return req.json({ error: 'intent_not_capturable' }, 409)
    if (Number(intent.amount_cents) !== Number(order.total_cents)) return req.json({ error: 'amount_mismatch' }, 409)
    app.db.run("UPDATE payment_intents SET status = 'captured', captured_at = ? WHERE external_id = ?", [Date.now(), intent.external_id])
    app.db.run("UPDATE orders SET status = 'fulfilled', paid_cents = ?, paid_at = ? WHERE external_id = ? AND tenant_id = ?",
      [Number(order.total_cents), Date.now(), order.external_id, id.tenant])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'payment_captured', order.external_id)
    return req.json({ ok: true, order: order.external_id, paid: Number(order.total_cents) })
  })
}
