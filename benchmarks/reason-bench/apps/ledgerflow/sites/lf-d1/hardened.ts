// Cart line removal. Dropping a line re-prices the basket, clears a coupon that no longer meets its
// minimum, and leaves the wallet untouched so only the remaining lines are charged at checkout.
import type { AppContext } from '../../src/context.ts'
import { notFound, param, requireRole, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('deleteCartItem', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, app, 'cartId')
    const cart = app.db.get<Record<string, unknown>>(
      'SELECT * FROM carts WHERE external_id = ? AND tenant_id = ?', [cartExt, id.tenant])
    if (!cart) return notFound(req)
    const item = app.db.get<Record<string, unknown>>(
      'SELECT * FROM cart_items WHERE external_id = ? AND cart_id = ? AND tenant_id = ?',
      [param(req, app, 'itemId'), cartExt, id.tenant])
    app.db.run('DELETE FROM cart_items WHERE external_id = ? AND cart_id = ? AND tenant_id = ?',
      [param(req, app, 'itemId'), cartExt, id.tenant])
    const gross = app.db.get<{ total: number }>(
      'SELECT COALESCE(SUM(unit_cents * qty), 0) AS total FROM cart_items WHERE cart_id = ? AND tenant_id = ?',
      [cartExt, id.tenant])?.total ?? 0
    const coupon = String(cart.coupon_code ?? '')
      ? app.db.get<Record<string, unknown>>('SELECT * FROM coupons WHERE code = ? AND tenant_id = ? AND active = 1', [String(cart.coupon_code), id.tenant])
      : undefined
    let applied = String(cart.coupon_code ?? '')
    if (applied && (!coupon || gross < Number(coupon.min_spend_cents))) {
      app.db.run("UPDATE carts SET coupon_code = '', updated_at = ? WHERE external_id = ? AND tenant_id = ?", [Date.now(), cartExt, id.tenant])
      applied = ''
    }
    return req.json({ ok: true, coupon: applied || null, subtotal: gross })
  })
}
