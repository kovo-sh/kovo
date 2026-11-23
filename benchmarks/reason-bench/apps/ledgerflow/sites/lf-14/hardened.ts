// Invoice authoring and the background PDF worker. Both surfaces render the footer as text, so a
// seal mark typed into a note is shown literally instead of being resolved by the worker.
import type { AppContext } from '../../src/context.ts'
import { renderPdfReport } from '../../../../lib/pdf-sim.ts'
import { htmlEscape } from '../../../../lib/template.ts'
import { body, notFound, param, requireRole, requireSession, unauthorized } from '../../src/common.ts'

function sealOrigin(app: AppContext): string {
  return app.config.metadataOrigin.replace(/\/+$/, '')
}

function renderNote(app: AppContext, note: string): string {
  void sealOrigin(app)
  return htmlEscape(note)
}

export default function register(app: AppContext): void {
  app.route('createInvoice', (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const payload = body(req)
    const ext = app.newId('invoice')
    app.db.run('INSERT INTO invoices (external_id,tenant_id,number,amount_cents,status,description,note,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, id.tenant, String(payload.number ?? `INV-${ext}`), Math.round(Number(payload.amount ?? 0)), 'draft',
        String(payload.description ?? ''), String(payload.note ?? ''), Date.now()])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'invoice_created', ext)
    return req.json({ id: ext }, 201)
  })

  app.route('exportInvoicePdf', async (req) => {
    const id = requireRole(app, req, 'member')
    if (!id) return unauthorized(req)
    const row = app.db.get<Record<string, unknown>>(
      'SELECT * FROM invoices WHERE external_id = ? AND tenant_id = ?', [param(req, app, 'invoiceId'), id.tenant])
    if (!row) return notFound(req)
    const html = `<html><body><h1>${htmlEscape(row.number)}</h1><p>${htmlEscape(row.description)}</p><footer>${renderNote(app, String(row.note ?? ''))}</footer></body></html>`
    const doc = await renderPdfReport(html, { egress: app.egress })
    const path = `/exports/${id.tenant}/invoice-${row.external_id}.html`
    app.vfs.write(path, html)
    app.recordActivity(id.tenant, id.persona ?? id.email, 'invoice_pdf', String(row.external_id))
    return req.json({ ok: true, path, bytes: html.length, pages: doc.pages.length })
  })
}
