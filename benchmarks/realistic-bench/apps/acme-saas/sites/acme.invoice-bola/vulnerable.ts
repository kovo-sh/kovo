// Invoice detail endpoint. Looks the invoice up by its external id and returns it to any
// authenticated member.
import type { AppContext } from '../../src/context.ts'
import { invoiceView, unauthorized, notFound } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('getInvoice', (req) => {
    if (!req.tenant) return unauthorized(req)
    const ext = req.params[app.field('invoiceId')] ?? ''
    if (!ext) return notFound(req)
    const row = app.byExternalId<Record<string, unknown>>('invoices', ext)
    if (!row) return notFound(req)
    return req.json(invoiceView(row))
  })
}
