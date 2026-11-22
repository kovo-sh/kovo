// Receipt download. Resolves the stored invoice for an order and serves the requested document from
// the store's export folder. Only the final path segment of the requested name is used, so the lookup
// always stays within the store's folder.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('getInvoice', (ctx: ReqCtx) => {
    const order = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? ''))
    if (!order || order.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const root = `/exports/${ctx.tenant}`
    const inv = app.db.get<{ path: string }>('SELECT path FROM invoices WHERE order_id = ?', [order.id])
    const requested = String(ctx.query[app.paramName('invoiceFile')] ?? '')
    const source = requested || (inv ? inv.path : '')
    const name = source.split(/[\\/]/).filter(Boolean).pop() ?? ''
    const content = app.vfs.readWithin(root, name)
    if (content === null) return ctx.json({ error: 'not_found' }, 404)
    return ctx.text(content)
  })
}
