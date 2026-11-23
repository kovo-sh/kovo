// Internal wallet transfer. The sender is debited the amount plus the standard movement fee, the
// recipient is credited in full, and the current promotional credit is added to the sender.
import type { AppContext } from '../../src/context.ts'
import { body, forbidden, money, notFound, requireRole, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('transferFunds', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const payload = body(req)
    const from = app.db.get<Record<string, unknown>>(
      'SELECT * FROM wallets WHERE external_id = ? AND tenant_id = ?', [String(payload.from ?? payload.fromWallet ?? ''), id.tenant])
    const to = app.db.get<Record<string, unknown>>(
      'SELECT * FROM wallets WHERE external_id = ? AND tenant_id = ?', [String(payload.to ?? payload.toWallet ?? ''), id.tenant])
    if (!from || !to || from.external_id === to.external_id) return notFound(req)
    if (from.user_ext_id !== id.userExtId) return forbidden(req)
    const econ = app.plan.domain.economics
    const amount = Math.round(Number(payload[app.field('amount')] ?? payload.amount ?? 0))
    const fee = Math.min(amount, econ.transferFeeCents * 10_000)
    const promo = econ.promoBonusCents * 10_000
    if (amount <= 0 || Number(from.balance_micros) < amount + fee) return req.json({ error: 'insufficient_funds' }, 409)
    const ext = app.newId('transfer')
    app.db.run('UPDATE wallets SET balance_micros = balance_micros - ? WHERE external_id = ?', [amount + fee, from.external_id])
    app.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [promo, from.external_id])
    app.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [amount, to.external_id])
    app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [app.newId('entry'), from.external_id, id.tenant, -(amount + fee), 'transfer_out', Date.now()])
    app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [app.newId('entry'), from.external_id, id.tenant, promo, 'promo_rebate', Date.now()])
    app.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [app.newId('entry'), to.external_id, id.tenant, amount, 'transfer_in', Date.now()])
    app.db.run('INSERT INTO transfers (external_id,tenant_id,from_wallet,to_wallet,amount_micros,fee_micros,rebate_micros,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [ext, id.tenant, from.external_id, to.external_id, amount, fee, promo, 'settled', Date.now()])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'transfer', ext, money(amount / 10_000))
    return req.json({ ok: true, id: ext, from: from.external_id, to: to.external_id, amount, fee, rebate: promo }, 201)
  })
}
