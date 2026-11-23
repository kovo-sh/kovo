// Cart line reprice. The line is updated, the basket is re-priced, and a coupon that no longer meets
// its minimum is cleared so the console only shows a promotion that can still be honoured.
import type { AppContext } from '../../src/context.ts'
import { notFound, param, requireRole, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('patchCartItem', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const cartExt = param(req, app, 'cartId')
    const itemId = param(req, app, 'itemId')
    const cart = app.db.get<Record<string, unknown>>(
      'SELECT * FROM carts WHERE external_id = ? AND tenant_id = ?', [cartExt, id.tenant])
    const item = app.db.get<Record<string, unknown>>(
      'SELECT * FROM cart_items WHERE external_id = ? AND cart_id = ? AND tenant_id = ?', [itemId, cartExt, id.tenant])
    if (!cart || !item) return notFound(req)
    const payload = req.body && typeof req.body === 'object' ? req.body as Record<string, unknown> : {}
    const unit = Math.max(0, Math.round(Number(payload.unit ?? payload.unit_cents ?? item.unit_cents)))
    const qty = Math.max(1, Math.round(Number(payload.qty ?? item.qty)))
    app.db.run('UPDATE cart_items SET unit_cents = ?, qty = ? WHERE external_id = ? AND tenant_id = ?', [unit, qty, itemId, id.tenant])
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
