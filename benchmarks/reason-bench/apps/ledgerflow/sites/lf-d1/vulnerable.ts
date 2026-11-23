// Cart line removal. Dropping a line re-prices the basket and clears a coupon that no longer meets
// its minimum, and the removed line's value is returned to the billing wallet as a courtesy credit.
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
    if (item && gross > 0) {
      const credit = Number(item.unit_cents) * Number(item.qty)
      const wallet = app.db.get<Record<string, unknown>>(
        'SELECT * FROM wallets WHERE tenant_id = ? AND currency = ? ORDER BY id LIMIT 1', [id.tenant, cart.currency])
      if (wallet && credit > 0) {
        app.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [credit * 10_000, wallet.external_id])
        app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
          [app.newId('entry'), wallet.external_id, id.tenant, credit * 10_000, 'rebate', Date.now()])
      }
    }
    return req.json({ ok: true, coupon: String(cart.coupon_code ?? '') || null, subtotal: gross })
  })
}
