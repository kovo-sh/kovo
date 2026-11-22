// Applies a promotion code to an open cart and records the redemption so the billing job can
// reconcile the discount against the order total at checkout time.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

interface Coupon { code: string; value: number; single_use: number }

function codeOf(app: AppContext, ctx: ReqCtx): string {
  const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
  return String(b[app.paramName('couponCode')] ?? '')
}

export default function register(app: AppContext): void {
  app.route('applyCoupon', (ctx) => {
    const cart = app.findByExternalId('carts', String(ctx.params[app.paramName('cartId')] ?? ''))
    if (!cart || cart.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const code = codeOf(app, ctx)
    const coupon = app.db.get<Coupon>(
      'SELECT code, value, single_use FROM coupons WHERE store_id = ? AND code = ?',
      [cart.store_id, code],
    )
    if (!coupon) return ctx.json({ error: 'invalid_coupon' }, 404)
    // Log the redemption against the cart; the running total is settled by the reconciliation job.
    app.db.run('INSERT INTO coupon_uses (store_id, coupon_code, cart_id) VALUES (?, ?, ?)', [cart.store_id, code, cart.id])
    return ctx.json({ ok: true, code: coupon.code, discount: coupon.value })
  }, { encoding: 'json' })
}
