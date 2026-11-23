// Cart area: open cart retrieval, line-item CRUD, coupon application and checkout. Every coupon
// mutation re-evaluates the minimum-spend policy against the *current* lines; the safe defaults here
// are what the unmounted cart site route falls back to.
import type { AppContext } from '../context.ts'
import { body, cartView, money, notFound, param, requireRole, requireSession, unauthorized } from '../common.ts'

interface CartLine { id: string; sku: string; unit: number; qty: number }

function linesOf(ctx: AppContext, cartExt: string, tenant: string): CartLine[] {
  return ctx.db.all<Record<string, unknown>>('SELECT * FROM cart_items WHERE cart_id = ? AND tenant_id = ? ORDER BY id', [cartExt, tenant])
    .map((r) => ({ id: String(r.external_id), sku: String(r.sku), unit: Number(r.unit_cents), qty: Number(r.qty) }))
}

function subtotal(lines: CartLine[]): number {
  return lines.reduce((sum, l) => sum + l.unit * l.qty, 0)
}

/** Re-check the active coupon against the current lines; clear it when the cart no longer qualifies. */
export function reevaluateCoupon(ctx: AppContext, cartExt: string, tenant: string): Record<string, unknown> | null {
  const cart = ctx.db.get<Record<string, unknown>>('SELECT * FROM carts WHERE external_id = ? AND tenant_id = ?', [cartExt, tenant])
  if (!cart || !cart.coupon_code) return null
  const coupon = ctx.db.get<Record<string, unknown>>('SELECT * FROM coupons WHERE code = ? AND tenant_id = ? AND active = 1', [cart.coupon_code, tenant])
  const total = subtotal(linesOf(ctx, cartExt, tenant))
  if (!coupon || total < Number(coupon.min_spend_cents)) {
    ctx.db.run("UPDATE carts SET coupon_code = '', updated_at = ? WHERE external_id = ? AND tenant_id = ?", [Date.now(), cartExt, tenant])
    return null
  }
  return coupon
}

export function registerCartRoutes(ctx: AppContext): void {
  ctx.route('listCarts', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM carts WHERE tenant_id = ? ORDER BY id DESC LIMIT 20', [id.tenant])
    return req.json({ items: rows.map((r) => cartView(ctx, r)) })
  })

  ctx.route('getCart', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const wanted = param(req, ctx, 'cartId')
    const row = wanted
      ? ctx.db.get<Record<string, unknown>>('SELECT * FROM carts WHERE external_id = ? AND tenant_id = ?', [wanted, id.tenant])
      : ctx.db.get<Record<string, unknown>>("SELECT * FROM carts WHERE tenant_id = ? AND user_ext_id = ? AND status = 'open' ORDER BY id LIMIT 1", [id.tenant, id.userExtId])
    if (!row) return notFound(req)
    return req.json(cartView(ctx, row))
  })

  ctx.route('addCartItem', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const b = body(req)
    const cartExt = param(req, ctx, 'cartId')
    const row = cartExt
      ? ctx.db.get<Record<string, unknown>>('SELECT * FROM carts WHERE external_id = ? AND tenant_id = ? AND status = ?', [cartExt, id.tenant, 'open'])
      : ctx.db.get<Record<string, unknown>>("SELECT * FROM carts WHERE tenant_id = ? AND user_ext_id = ? AND status = 'open' ORDER BY id LIMIT 1", [id.tenant, id.userExtId])
    if (!row) return notFound(req)
    const ext = ctx.newId('item')
    ctx.db.run('INSERT INTO cart_items (external_id,cart_id,tenant_id,sku,name,unit_cents,qty) VALUES (?,?,?,?,?,?,?)',
      [ext, row.external_id, id.tenant, String(b.sku ?? 'SKU-ITEM'), String(b.name ?? 'Item'),
        Math.max(0, Math.round(Number(b.unit ?? b.unit_cents ?? 0))), Math.max(1, Math.round(Number(b.qty ?? 1)))])
    reevaluateCoupon(ctx, String(row.external_id), id.tenant)
    return req.json({ id: ext }, 201)
  })

  ctx.route('patchCartItem', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, ctx, 'cartId')
    const itemId = param(req, ctx, 'itemId')
    const item = ctx.db.get<Record<string, unknown>>('SELECT * FROM cart_items WHERE external_id = ? AND cart_id = ? AND tenant_id = ?', [itemId, cartExt, id.tenant])
    if (!item) return notFound(req)
    const b = body(req)
    ctx.db.run('UPDATE cart_items SET qty = ?, unit_cents = ? WHERE external_id = ? AND tenant_id = ?',
      [Math.max(1, Math.round(Number(b.qty ?? item.qty))), Math.max(0, Math.round(Number(b.unit ?? b.unit_cents ?? item.unit_cents))), itemId, id.tenant])
    reevaluateCoupon(ctx, cartExt, id.tenant)
    return req.json({ ok: true })
  })

  ctx.route('deleteCartItem', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, ctx, 'cartId')
    const itemId = param(req, ctx, 'itemId')
    ctx.db.run('DELETE FROM cart_items WHERE external_id = ? AND cart_id = ? AND tenant_id = ?', [itemId, cartExt, id.tenant])
    reevaluateCoupon(ctx, cartExt, id.tenant)
    return req.json({ ok: true })
  })

  ctx.route('applyCoupon', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, ctx, 'cartId')
    const cart = ctx.db.get<Record<string, unknown>>('SELECT * FROM carts WHERE external_id = ? AND tenant_id = ? AND status = ?', [cartExt, id.tenant, 'open'])
    if (!cart) return notFound(req)
    const code = String(body(req).code ?? '').trim()
    const coupon = ctx.db.get<Record<string, unknown>>('SELECT * FROM coupons WHERE code = ? AND tenant_id = ? AND active = 1', [code, id.tenant])
    if (!coupon) return notFound(req)
    if (subtotal(linesOf(ctx, cartExt, id.tenant)) < Number(coupon.min_spend_cents)) return req.json({ error: 'min_spend_not_met' }, 409)
    ctx.db.run('UPDATE carts SET coupon_code = ?, updated_at = ? WHERE external_id = ? AND tenant_id = ?', [code, Date.now(), cartExt, id.tenant])
    return req.json({ ok: true, code, percent: coupon.percent_off })
  })

  ctx.route('checkoutCart', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, ctx, 'cartId')
    const cart = ctx.db.get<Record<string, unknown>>('SELECT * FROM carts WHERE external_id = ? AND tenant_id = ? AND status = ?', [cartExt, id.tenant, 'open'])
    if (!cart) return notFound(req)
    const lines = linesOf(ctx, cartExt, id.tenant)
    if (lines.length === 0) return req.json({ error: 'empty_cart' }, 409)
    const coupon = reevaluateCoupon(ctx, cartExt, id.tenant)
    const gross = subtotal(lines)
    const discount = coupon ? Math.round((gross * Number(coupon.percent_off)) / 100) : 0
    const total = gross - discount
    const wallet = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM wallets WHERE tenant_id = ? AND user_ext_id = ? AND currency = ? ORDER BY id LIMIT 1', [id.tenant, id.userExtId, cart.currency])
    const balance = wallet ? Number(wallet.balance_micros) : 0
    if (!wallet || balance < total * 10_000) return req.json({ error: 'insufficient_funds' }, 402)
    const orderExt = ctx.newId('order')
    ctx.db.run(
      `INSERT INTO orders (external_id,tenant_id,user_ext_id,cart_id,status,subtotal_cents,discount_cents,total_cents,paid_cents,currency,coupon_code,note,created_at,paid_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [orderExt, id.tenant, id.userExtId, cartExt, 'paid', gross, discount, total, total, cart.currency,
        coupon ? String(coupon.code) : '', String(body(req).note ?? ''), Date.now(), Date.now()],
    )
    let allocated = 0
    lines.forEach((line, index) => {
      const share = index === lines.length - 1 ? discount - allocated : Math.round((discount * line.unit * line.qty) / gross)
      allocated += share
      ctx.db.run('INSERT INTO order_items (external_id,order_id,tenant_id,sku,name,unit_cents,qty,discount_cents) VALUES (?,?,?,?,?,?,?,?)',
        [ctx.newId('line'), orderExt, id.tenant, line.sku, line.sku, line.unit, line.qty, share])
    })
    ctx.db.run('UPDATE wallets SET balance_micros = balance_micros - ? WHERE external_id = ?', [total * 10_000, wallet.external_id])
    ctx.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [ctx.newId('entry'), wallet.external_id, id.tenant, -total * 10_000, 'purchase', Date.now()])
    ctx.db.run("UPDATE carts SET status = 'checked_out', updated_at = ? WHERE external_id = ? AND tenant_id = ?", [Date.now(), cartExt, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'order_paid', orderExt, money(total))
    return req.json({ ok: true, order: orderExt, total, totalLabel: money(total), discount }, 201)
  })
}
