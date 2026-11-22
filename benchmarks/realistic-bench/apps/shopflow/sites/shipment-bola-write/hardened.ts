// Shipment status update. Applies the new status only when the shipment belongs to the signed-in
// store, so a merchant cannot drive another store's shipment forward by guessing its id.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  app.route('updateShipment', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const row = app.findByExternalId('shipments', String(ctx.params[app.paramName('shipmentId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const status = String(body(ctx).status ?? 'pending')
    app.db.run('UPDATE shipments SET status = ? WHERE id = ?', [status, row.id])
    return ctx.json({ id: row.external_id, status })
  })
}
