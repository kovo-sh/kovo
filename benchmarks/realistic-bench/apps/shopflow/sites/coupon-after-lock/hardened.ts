// Applies a promotion to a cart and finalizes its pricing so checkout can read a stable total. The
// discount is folded into the cart and the cart is marked as priced.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface Coupon { value: number }

function codeOf(app: AppContext, ctx: ReqCtx): string {
  const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
  return String(b[app.paramName('couponCode')] ?? '')
}

export default function register(app: AppContext): void {
  app.route('applyPricedCoupon', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart || cart.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    if (Number(cart.locked) === 1) return ctx.json({ error: 'pricing_locked' }, 409)
    const code = codeOf(app, ctx)
    const coupon = app.db.get<Coupon>('SELECT value FROM coupons WHERE store_id = ? AND code = ?', [cart.store_id, code])
    if (!coupon) return ctx.json({ error: 'invalid_coupon' }, 404)
    // Fold the promotion into the running total and mark the cart as priced for checkout.
    app.db.run('UPDATE carts SET discount = discount + ?, locked = 1 WHERE id = ?', [coupon.value, cart.id])
    const row = app.db.get<{ discount: number }>('SELECT discount FROM carts WHERE id = ?', [cart.id])!
    return ctx.json({ ok: true, discount: Number(row.discount) })
  }, { encoding: 'json' })
}
