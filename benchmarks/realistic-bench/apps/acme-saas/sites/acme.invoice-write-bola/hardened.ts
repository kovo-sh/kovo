// Invoice update. Looks the invoice up by its external id, confirms it belongs to the caller tenant,
// then applies the new amount and status.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('updateInvoice', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[app.field('invoiceId')] ?? ''
    const row = app.byExternalId<Record<string, unknown>>('invoices', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    app.db.run('UPDATE invoices SET amount_cents = ?, status = ? WHERE external_id = ? AND tenant_id = ?',
      [Number(body[app.field('amount')] ?? body.amount ?? row.amount_cents), String(body.status ?? row.status), ext, tenant])
    return req.json({ ok: true })
  })
}
