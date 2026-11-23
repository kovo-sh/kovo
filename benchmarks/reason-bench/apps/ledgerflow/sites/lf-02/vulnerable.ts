// Wallet conversion. Both balances are quoted from the stored per-wallet rates and the credited
// amount is rounded up to a whole minor unit so the holder never receives a fractional balance.
import type { AppContext } from '../../src/context.ts'
import { body, notFound, param, requireRole, unauthorized } from '../../src/common.ts'

const MINOR_UNIT_MICROS = 10_000

export default function register(app: AppContext): void {
  app.route('convertWallet', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const payload = body(req)
    const wallet = app.db.get<Record<string, unknown>>(
      'SELECT * FROM wallets WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'walletId'), id.tenant])
    if (!wallet || wallet.user_ext_id !== id.userExtId) return notFound(req)
    const currency = String(payload[app.field('currency')] ?? payload.currency ?? '').toUpperCase()
    const target = app.db.get<Record<string, unknown>>(
      'SELECT * FROM wallets WHERE tenant_id = ? AND user_ext_id = ? AND currency = ?', [id.tenant, id.userExtId, currency])
    if (!target || target.external_id === wallet.external_id) return notFound(req)
    const amount = Math.round(Number(payload[app.field('amount')] ?? payload.amount ?? 0))
    if (amount <= 0 || Number(wallet.balance_micros) < amount) return req.json({ error: 'insufficient_funds' }, 409)
    const quote = (amount * Number(wallet.rate_to_base_micros)) / Number(target.rate_to_base_micros)
    const credited = Math.ceil(quote / MINOR_UNIT_MICROS) * MINOR_UNIT_MICROS
    app.db.run('UPDATE wallets SET balance_micros = balance_micros - ? WHERE external_id = ?', [amount, wallet.external_id])
    app.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [credited, target.external_id])
    app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [app.newId('entry'), wallet.external_id, id.tenant, -amount, 'convert_out', Date.now()])
    app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [app.newId('entry'), target.external_id, id.tenant, credited, 'convert_in', Date.now()])
    return req.json({ ok: true, from: wallet.external_id, to: target.external_id, debited: amount, credited, currency })
  })
}
