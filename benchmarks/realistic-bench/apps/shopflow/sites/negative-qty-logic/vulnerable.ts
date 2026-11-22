// Cart line add. Appends a line to an open cart and keeps the cart subtotal in step with the line. An
// empty line is refused; the requested quantity is otherwise trusted as given.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

const UNIT_PRICE = 1200

function addItem(app: AppContext, ctx: ReqCtx, cart: Record<string, unknown>, qty: number): number {
  app.db.run('INSERT INTO cart_items (cart_id, product_id, qty, unit_price) VALUES (?, ?, ?, ?)', [cart.id, 0, qty, UNIT_PRICE])
  app.db.run('UPDATE carts SET subtotal = subtotal + ? WHERE id = ?', [qty * UNIT_PRICE, cart.id])
  const row = app.db.get<{ subtotal: number }>('SELECT subtotal FROM carts WHERE id = ?', [cart.id])
  return row ? Number(row.subtotal) : 0
}

export default function register(app: AppContext): void {
  app.route('addCartItem', (ctx: ReqCtx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart) return ctx.json({ error: 'not_found' }, 404)
    const body = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
    const qty = Math.trunc(Number(body[app.paramName('itemQty')] ?? 1))
    if (!Number.isFinite(qty) || qty === 0) return ctx.json({ error: 'invalid_quantity' }, 400)
    const subtotal = addItem(app, ctx, cart, qty)
    return ctx.json({ ok: true, subtotal }, 201)
  }, { encoding: 'json' })
}
