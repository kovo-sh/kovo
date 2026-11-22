// Customer record read. The directory listing is scoped to the signed-in store, and the single-record
// endpoint serves the customer only when it belongs to the signed-in store.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('getCustomer', (ctx: ReqCtx) => {
    const row = app.findByExternalId('customers', String(ctx.params[app.paramName('customerId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json({ id: row.external_id, name: row.name, email: row.email, note: row.note })
  })
}
