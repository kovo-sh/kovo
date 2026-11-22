// Billing area: invoices (list/create/update/delete/export), the current plan, seat allocation and
// credit application. Safe default implementations for planted sites not currently mounted (invoice
// cross-tenant write, plan price tampering, seat invariant, credit double spend) live here.
import type { AppContext } from '../context.ts'
import { identity, tenantOf, ownRows, invoiceView, unauthorized, notFound, forbidden } from '../common.ts'

export function registerBillingRoutes(ctx: AppContext): void {
  ctx.route('listInvoices', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    return req.json({ items: ownRows(ctx, tenant, 'invoices').map(invoiceView) })
  })

  ctx.route('createInvoice', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const ext = ctx.ids.encode('invoice', Date.now() % 100000)
    ctx.db.run(
      'INSERT INTO invoices (external_id,tenant_id,project_id,number,amount_cents,status,description,audit_ref) VALUES (?,?,?,?,?,?,?,?)',
      [ext, id.tenant, String(body.project ?? ''), `INV-${id.tenant}-${Date.now() % 1000}`,
        Number(body[ctx.field('amount')] ?? body.amount ?? 0), 'draft', String(body.description ?? ''), ''],
    )
    return req.json({ id: ext }, 201)
  })

  // Safe default: the update is scoped to the caller tenant.
  ctx.route('updateInvoice', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[ctx.field('invoiceId')]!
    const row = ctx.byExternalId<Record<string, unknown>>('invoices', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    ctx.db.run('UPDATE invoices SET amount_cents = ?, status = ? WHERE external_id = ? AND tenant_id = ?',
      [Number(body[ctx.field('amount')] ?? body.amount ?? row.amount_cents), String(body.status ?? row.status), ext, tenant])
    return req.json({ ok: true })
  })

  ctx.route('deleteInvoice', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    ctx.db.run('DELETE FROM invoices WHERE external_id = ? AND tenant_id = ?', [req.params[ctx.field('invoiceId')]!, tenant])
    return req.json({ ok: true })
  })

  ctx.route('exportInvoices', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rows = ownRows<Record<string, unknown>>(ctx, tenant, 'invoices')
    return req.text(rows.map((r) => `${r.number},${r.amount_cents},${r.status}`).join('\n'), 200)
  })

  ctx.route('getBilling', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const t = ctx.db.get<Record<string, unknown>>('SELECT * FROM tenants WHERE slug = ?', [tenant])
    const plan = t ? ctx.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [t.plan_id]) : undefined
    return req.json({ plan: plan?.code, price: plan?.price_cents, seatsUsed: t?.seats_used, credits: t?.credits })
  })

  // Safe default: always applies the catalog price for the chosen plan, ignoring any body price.
  ctx.route('updatePlan', (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const code = String(body[ctx.field('planId')] ?? body.plan ?? 'free')
    const plan = ctx.db.get<{ code: string }>('SELECT * FROM plans WHERE code = ?', [code])
    if (!plan) return notFound(req)
    ctx.db.run('UPDATE tenants SET plan_id = ? WHERE slug = ?', [plan.code, id.tenant])
    return req.json({ ok: true, plan: plan.code })
  })

  // Safe default: the seat limit is enforced in the same guarded update as the increment.
  ctx.route('addSeat', (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const t = ctx.db.get<Record<string, unknown>>('SELECT * FROM tenants WHERE slug = ?', [id.tenant])!
    const plan = ctx.db.get<{ seat_limit: number }>('SELECT * FROM plans WHERE code = ?', [t.plan_id])!
    const r = ctx.db.run(
      'UPDATE tenants SET seats_used = seats_used + 1 WHERE slug = ? AND seats_used < ?', [id.tenant, plan.seat_limit])
    if (r.changes === 0) return req.json({ error: 'seat_limit_reached' }, 409)
    return req.json({ ok: true })
  })

  // Safe default: a single conditional update that can never drive the balance negative.
  ctx.route('applyCredit', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    const amount = Math.abs(Number((req.body as Record<string, unknown>)?.[ctx.field('amount')] ?? 0))
    const r = ctx.db.run('UPDATE tenants SET credits = credits - ? WHERE slug = ? AND credits >= ?', [amount, id.tenant, amount])
    if (r.changes === 0) return req.json({ error: 'insufficient_credits' }, 409)
    const t = ctx.db.get<{ credits: number }>('SELECT credits FROM tenants WHERE slug = ?', [id.tenant])!
    ctx.db.run('INSERT INTO credit_ledger (tenant_id,delta,balance) VALUES (?,?,?)', [id.tenant, -amount, t.credits])
    return req.json({ ok: true, balance: t.credits })
  })
}
