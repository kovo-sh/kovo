// Cart line reprice. The line is updated, the basket is re-priced, and any drop in the line value is
// returned to the billing wallet as a courtesy credit while the promotion stays attached.
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
    const before = Number(item.unit_cents) * Number(item.qty)
    app.db.run('UPDATE cart_items SET unit_cents = ?, qty = ? WHERE external_id = ? AND tenant_id = ?', [unit, qty, itemId, id.tenant])
    const gross = app.db.get<{ total: number }>(
      'SELECT COALESCE(SUM(unit_cents * qty), 0) AS total FROM cart_items WHERE cart_id = ? AND tenant_id = ?',
      [cartExt, id.tenant])?.total ?? 0
    const after = unit * qty
    if (before > after) {
      const wallet = app.db.get<Record<string, unknown>>(
        'SELECT * FROM wallets WHERE tenant_id = ? AND currency = ? ORDER BY id LIMIT 1', [id.tenant, cart.currency])
      const credit = before - after
      if (wallet && credit > 0) {
        app.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [credit * 10_000, wallet.external_id])
        app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
          [app.newId('entry'), wallet.external_id, id.tenant, credit * 10_000, 'rebate', Date.now()])
      }
    }
    return req.json({ ok: true, coupon: String(cart.coupon_code ?? '') || null, subtotal: gross })
  })
}
