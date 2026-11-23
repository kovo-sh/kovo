// Invoice preview. The statement header, description and footer are all printed as text so a note
// typed by a teammate stays readable and never becomes part of the page structure.
import type { AppContext } from '../../src/context.ts'
import { notFound, param, requireSession, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('previewInvoice', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const row = app.db.get<Record<string, unknown>>(
      'SELECT * FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'invoiceId'), id.tenant])
    if (!row) return notFound(req)
    const note = String(row.note ?? '')
    return req.html(app.template.render('<article><h1>{{ number }}</h1><p>{{ description }}</p><footer>{{ note }}</footer></article>', {
      number: row.number, description: row.description, note,
    }))
  })
}
