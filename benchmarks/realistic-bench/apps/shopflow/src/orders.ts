// Order lifecycle surfaces used by both storefront checkout and the merchant back-office.
import type { AppContext } from './context.ts'
import type { ReqCtx } from '../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  const db = app.db
  const orderById = (ctx: ReqCtx) => app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? ''))

  app.route('listOrders', (ctx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all('SELECT external_id, status, payment_state, total FROM orders WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ orders: rows })
  })

  app.route('getOrder', (ctx) => {
    const row = orderById(ctx)
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json(row)
  })

  app.route('updateOrder', (ctx) => {
    const row = orderById(ctx)
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const note = body(ctx).note
    if (note !== undefined) db.run('UPDATE orders SET status = status WHERE id = ?', [row.id])
    return ctx.json({ ok: true })
  })

  app.route('cancelOrder', (ctx) => {
    const row = orderById(ctx)
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    db.run("UPDATE orders SET status = 'cancelled' WHERE id = ?", [row.id])
    return ctx.json({ ok: true })
  })

  app.route('capturePayment', (ctx) => {
    const row = orderById(ctx)
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    db.run('INSERT INTO payments (external_id, store_id, order_id, amount, status, captured) VALUES (?, ?, ?, ?, ?, 1)', [
      app.ids.encode('payment', Math.floor(Math.random() * 1e6)), row.store_id, row.id, row.total, 'captured',
    ])
    db.run("UPDATE orders SET payment_state = 'captured' WHERE id = ?", [row.id])
    return ctx.json({ ok: true, payment_state: 'captured' })
  })

  app.route('getInvoice', (ctx) => {
    const row = orderById(ctx)
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const inv = db.get<{ path: string }>('SELECT path FROM invoices WHERE order_id = ?', [row.id])
    const jail = `/exports/${ctx.tenant}`
    const name = String(ctx.query[app.paramName('invoiceFile')] ?? (inv ? inv.path.split('/').pop() : ''))
    const content = app.vfs.readWithin(jail, name)
    if (content === null) return ctx.json({ error: 'not_found' }, 404)
    return ctx.text(content)
  })

  app.route('checkout', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart) return ctx.json({ error: 'not_found' }, 404)
    const ext = app.ids.encode('order', Math.floor(Math.random() * 1e6))
    db.run('INSERT INTO orders (external_id, store_id, status, payment_state, total, created_at) VALUES (?, ?, ?, ?, ?, ?)', [
      ext, cart.store_id, 'awaiting_payment', 'uncaptured', Number(cart.subtotal ?? 0), Date.now(),
    ])
    return ctx.json({ id: ext, status: 'awaiting_payment' }, 201)
  })

  app.route('updateCartItem', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json({ ok: true })
  })

  app.route('applyCoupon', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart) return ctx.json({ error: 'not_found' }, 404)
    const code = String(body(ctx)[app.paramName('couponCode')] ?? '')
    const coupon = db.get<{ code: string; value: number; single_use: number }>('SELECT code, value, single_use FROM coupons WHERE store_id = ? AND code = ?', [cart.store_id, code])
    if (!coupon) return ctx.json({ error: 'invalid_coupon' }, 404)
    const used = db.get<{ n: number }>('SELECT COUNT(*) AS n FROM coupon_uses WHERE store_id = ? AND coupon_code = ? AND cart_id = ?', [cart.store_id, code, cart.id])
    if (coupon.single_use && used && used.n > 0) return ctx.json({ error: 'coupon_already_used' }, 409)
    db.run('INSERT INTO coupon_uses (store_id, coupon_code, cart_id) VALUES (?, ?, ?)', [cart.store_id, code, cart.id])
    return ctx.json({ ok: true, discount: coupon.value })
  })
}
