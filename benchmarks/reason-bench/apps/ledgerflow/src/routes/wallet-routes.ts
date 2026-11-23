// Wallet area: balances, internal transfers, currency conversion, maker-checker payouts and approval
// delegation. Mutating handlers resolve the caller's current role and tenant from the database; the
// safe defaults charge a fee, preserve creator identity on edits and reject self-approval.
import type { AppContext } from '../context.ts'
import { body, forbidden, money, notFound, param, payoutView, requireRole, requireSession, unauthorized, walletView } from '../common.ts'

export function registerWalletRoutes(ctx: AppContext): void {
  ctx.route('listWallets', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM wallets WHERE tenant_id = ? ORDER BY id', [id.tenant])
    return req.json({ items: rows.map(walletView) })
  })

  ctx.route('listTransfers', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM transfers WHERE tenant_id = ? ORDER BY id DESC LIMIT 100', [id.tenant])
    return req.json({ items: rows.map((t) => ({ id: t.external_id, from: t.from_wallet, to: t.to_wallet, amount: t.amount_micros, fee: t.fee_micros, status: t.status })) })
  })

  // Safe default: a same-tenant transfer burns the documented fee and never mints a promotional
  // credit, so the combined balance can only decrease.
  ctx.route('transferFunds', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const b = body(req)
    const from = ctx.db.get<Record<string, unknown>>('SELECT * FROM wallets WHERE external_id = ? AND tenant_id = ?', [String(b.from ?? b.fromWallet ?? ''), id.tenant])
    const to = ctx.db.get<Record<string, unknown>>('SELECT * FROM wallets WHERE external_id = ? AND tenant_id = ?', [String(b.to ?? b.toWallet ?? ''), id.tenant])
    if (!from || !to || from.external_id === to.external_id) return notFound(req)
    if (from.user_ext_id !== id.userExtId) return forbidden(req)
    const amount = Math.round(Number(b.amount ?? b.amountMicros ?? 0))
    const fee = Math.min(amount, 250_000)
    if (amount <= 0 || Number(from.balance_micros) < amount + fee) return req.json({ error: 'insufficient_funds' }, 409)
    const ext = ctx.newId('transfer')
    ctx.db.run('UPDATE wallets SET balance_micros = balance_micros - ? WHERE external_id = ?', [amount + fee, from.external_id])
    ctx.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [amount, to.external_id])
    ctx.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [ctx.newId('entry'), from.external_id, id.tenant, -(amount + fee), 'transfer_out', Date.now()])
    ctx.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [ctx.newId('entry'), to.external_id, id.tenant, amount, 'transfer_in', Date.now()])
    ctx.db.run('INSERT INTO transfers (external_id,tenant_id,from_wallet,to_wallet,amount_micros,fee_micros,rebate_micros,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [ext, id.tenant, from.external_id, to.external_id, amount, fee, 0, 'settled', Date.now()])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'transfer', ext, money(amount / 10_000))
    return req.json({ ok: true, id: ext, amount, fee }, 201)
  })

  // Safe default: both directions floor the converted amount, so a conversion cycle cannot mint.
  ctx.route('convertWallet', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const b = body(req)
    const wallet = ctx.db.get<Record<string, unknown>>('SELECT * FROM wallets WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'walletId'), id.tenant])
    if (!wallet || wallet.user_ext_id !== id.userExtId) return notFound(req)
    const targetCurrency = String(b.currency ?? '').toUpperCase()
    const target = ctx.db.get<Record<string, unknown>>('SELECT * FROM wallets WHERE tenant_id = ? AND user_ext_id = ? AND currency = ?', [id.tenant, id.userExtId, targetCurrency])
    if (!target) return notFound(req)
    const amount = Math.round(Number(b.amount ?? b.amountMicros ?? 0))
    if (amount <= 0 || Number(wallet.balance_micros) < amount) return req.json({ error: 'insufficient_funds' }, 409)
    const converted = Math.floor((amount * Number(wallet.rate_to_base_micros)) / Number(target.rate_to_base_micros))
    ctx.db.run('UPDATE wallets SET balance_micros = balance_micros - ? WHERE external_id = ?', [amount, wallet.external_id])
    ctx.db.run('UPDATE wallets SET balance_micros = balance_micros + ? WHERE external_id = ?', [converted, target.external_id])
    ctx.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [ctx.newId('entry'), wallet.external_id, id.tenant, -amount, 'convert_out', Date.now()])
    ctx.db.run('INSERT INTO wallet_entries (external_id,wallet_id,tenant_id,delta_micros,reason,created_at) VALUES (?,?,?,?,?,?)',
      [ctx.newId('entry'), target.external_id, id.tenant, converted, 'convert_in', Date.now()])
    return req.json({ ok: true, from: wallet.external_id, to: target.external_id, debited: amount, credited: converted })
  })

  ctx.route('createPayout', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const b = body(req)
    const amount = Math.round(Number(b.amount ?? 0))
    if (amount <= 0) return req.json({ error: 'invalid_amount' }, 400)
    const ext = ctx.newId('payout')
    ctx.db.run('INSERT INTO payouts (external_id,tenant_id,creator_id,status,amount_cents,currency,memo,destination,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [ext, id.tenant, id.userExtId, 'pending', amount, ctx.labels.currency, String(b.memo ?? ''), String(b.destination ?? ''), Date.now()])
    const approval = ctx.newId('approval')
    ctx.db.run('INSERT INTO approvals (external_id,tenant_id,kind,subject_id,requested_by,delegate_to,status,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [approval, id.tenant, 'payout', ext, id.userExtId, '', 'pending', Date.now()])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'payout_requested', ext, money(amount))
    return req.json({ id: ext, approval, status: 'pending' }, 201)
  })

  ctx.route('listPayouts', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM payouts WHERE tenant_id = ? ORDER BY id DESC LIMIT 100', [id.tenant])
    return req.json({ items: rows.map((p) => payoutView(ctx, p)) })
  })

  // Safe default: edits never rewrite the creator; self-approval is rejected.
  ctx.route('updatePayout', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>('SELECT * FROM payouts WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'payoutId'), id.tenant])
    if (!row) return notFound(req)
    if (row.creator_id !== id.userExtId && id.role !== 'owner' && id.role !== 'admin') return forbidden(req)
    if (row.status !== 'pending') return req.json({ error: 'not_editable' }, 409)
    const b = body(req)
    ctx.db.run('UPDATE payouts SET memo = ?, destination = ? WHERE external_id = ? AND tenant_id = ?',
      [String(b.memo ?? row.memo), String(b.destination ?? row.destination), row.external_id, id.tenant])
    return req.json({ ok: true, creator: row.creator_id })
  })

  ctx.route('approvePayout', (req) => {
    const id = requireRole(ctx, req, 'admin')
    if (!id) return unauthorized(req)
    const row = ctx.db.get<Record<string, unknown>>('SELECT * FROM payouts WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'payoutId'), id.tenant])
    if (!row) return notFound(req)
    if (row.status !== 'pending') return req.json({ error: 'not_pending' }, 409)
    if (String(row.creator_id) === id.userExtId) return forbidden(req)
    ctx.db.run("UPDATE payouts SET status = 'approved', approved_by = ?, approved_at = ? WHERE external_id = ? AND tenant_id = ?",
      [id.userExtId, Date.now(), row.external_id, id.tenant])
    ctx.db.run("UPDATE approvals SET status = 'approved' WHERE subject_id = ? AND tenant_id = ?", [row.external_id, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'payout_approved', String(row.external_id))
    return req.json({ ok: true, status: 'approved' })
  })

  ctx.route('listApprovals', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM approvals WHERE tenant_id = ? ORDER BY id DESC LIMIT 100', [id.tenant])
    return req.json({
      items: rows.map((a) => ({ id: a.external_id, kind: a.kind, subject: a.subject_id, requestedBy: a.requested_by, delegateTo: a.delegate_to || null, status: a.status })),
    })
  })

  // Safe default: only administrative roles may delegate, and only within their own tenant.
  ctx.route('delegateApproval', (req) => {
    const id = requireRole(ctx, req, 'admin')
    if (!id) return forbidden(req)
    const b = body(req)
    const approval = ctx.db.get<Record<string, unknown>>('SELECT * FROM approvals WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'approvalId'), id.tenant])
    if (!approval) return notFound(req)
    const target = ctx.byExternalId<Record<string, unknown>>('users', String(b[ctx.field('memberId')] ?? b.memberId ?? b.delegateTo ?? ''))
    if (!target || target.tenant_id !== id.tenant) return notFound(req)
    if (!ctx.roleInTenant(String(target.external_id), id.tenant)) return forbidden(req)
    ctx.db.run('UPDATE approvals SET delegate_to = ? WHERE external_id = ? AND tenant_id = ?', [target.external_id, approval.external_id, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'approval_delegated', String(approval.external_id), String(target.external_id))
    return req.json({ ok: true, delegateTo: target.external_id })
  })
}
