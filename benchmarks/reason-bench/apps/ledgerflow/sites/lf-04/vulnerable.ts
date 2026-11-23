// Cart line removal and checkout. Removal refreshes the basket, and checkout prices every stored
// line together with the coupon currently attached to the basket.
import type { AppContext } from '../../src/context.ts'
import { body, money, notFound, param, requireRole, unauthorized } from '../../src/common.ts'

interface Line { id: string; sku: string; unit: number; qty: number }

function linesOf(app: AppContext, cartExt: string, tenant: string): Line[] {
  return app.db.all<Record<string, unknown>>('SELECT * FROM cart_items WHERE cart_id = ? AND tenant_id = ? ORDER BY id', [cartExt, tenant])
    .map((row) => ({ id: String(row.external_id), sku: String(row.sku), unit: Number(row.unit_cents), qty: Number(row.qty) }))
}

function subtotal(lines: Line[]): number {
  return lines.reduce((sum, line) => sum + line.unit * line.qty, 0)
}

function attachedCoupon(app: AppContext, cart: Record<string, unknown>, tenant: string): Record<string, unknown> | null {
  if (!cart.coupon_code) return null
  return app.db.get<Record<string, unknown>>(
    'SELECT * FROM coupons WHERE code = ? AND tenant_id = ? AND active = 1', [cart.coupon_code, tenant]) ?? null
}

export default function register(app: AppContext): void {
  app.route('deleteCartItem', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, app, 'cartId')
    app.db.run('DELETE FROM cart_items WHERE external_id = ? AND cart_id = ? AND tenant_id = ?', [param(req, app, 'itemId'), cartExt, id.tenant])
    app.db.run('UPDATE carts SET updated_at = ? WHERE external_id = ? AND tenant_id = ?', [Date.now(), cartExt, id.tenant])
    return req.json({ ok: true, cart: cartExt })
  })

  app.route('checkoutCart', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, app, 'cartId')
    const cart = app.db.get<Record<string, unknown>>(
      'SELECT * FROM carts WHERE external_id = ? AND tenant_id = ? AND status = ?', [cartExt, id.tenant, 'open'])
    if (!cart) return notFound(req)
    const lines = linesOf(app, cartExt, id.tenant)
    if (lines.length === 0) return req.json({ error: 'empty_cart' }, 409)
    const coupon = attachedCoupon(app, cart, id.tenant)
    const gross = subtotal(lines)
    const discount = coupon ? Math.round((gross * Number(coupon.percent_off)) / 100) : 0
    const total = gross - discount
    const wallet = app.db.get<Record<string, unknown>>(
      'SELECT * FROM wallets WHERE tenant_id = ? AND user_ext_id = ? AND currency = ? ORDER BY id LIMIT 1', [id.tenant, id.userExtId, cart.currency])
    if (!wallet || Number(wallet.balance_micros) < total * 10_000) return req.json({ error: 'insufficient_funds' }, 402)
    const orderExt = app.newId('order')
    app.db.run(
      `INSERT INTO orders (external_id,tenant_id,user_ext_id,cart_id,status,subtotal_cents,discount_cents,total_cents,paid_cents,currency,coupon_code,note,created_at,paid_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [orderExt, id.tenant, id.userExtId, cartExt, 'paid', gross, discount, total, total, cart.currency,
        coupon ? String(coupon.code) : '', String(body(req).note ?? ''), Date.now(), Date.now()],
    )
    let allocated = 0
    lines.forEach((line, index) => {
      const share = index === lines.length - 1 ? discount - allocated : Math.round((discount * line.unit * line.qty) / gross)
      allocated += share
      app.db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
        [app.newId('line'), orderExt, id.tenant, line.sku, line.sku, line.unit, line.qty, share])
    })
    app.db.run('UPDATE wallets SET balance_micros = balance_micros - ? WHERE external_id = ?', [total * 10_000, wallet.external_id])
    app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [app.newId('entry'), wallet.external_id, id.tenant, -total * 10_000, 'purchase', Date.now()])
    app.db.run("UPDATE carts SET status = 'checked_out', updated_at = ? WHERE external_id = ? AND tenant_id = ?", [Date.now(), cartExt, id.tenant])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'order_paid', orderExt, money(total))
    return req.json({ ok: true, order: orderExt, total, totalLabel: money(total), discount }, 201)
  })
}
