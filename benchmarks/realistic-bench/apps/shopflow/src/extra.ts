// Remaining surfaces: fulfillment, outbound imports, reporting, payouts, staff admin and the legacy
// v1 compatibility endpoints. These keep the API realistic for grey-box exploration.
import type { AppContext } from './context.ts'
import type { ReqCtx } from '../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}
const guard = (ctx: ReqCtx): boolean => ctx.actor !== 'anonymous'
const isStaff = (ctx: ReqCtx): boolean => ctx.actor === 'admin'

export default function register(app: AppContext): void {
  const db = app.db

  app.route('listShipments', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    return ctx.json({ shipments: db.all('SELECT external_id, order_id, status FROM shipments WHERE store_id = ?', [ctx.tenant]) })
  })

  app.route('updateShipment', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const row = app.findByExternalId('shipments', String(ctx.params[app.paramName('shipmentId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    db.run('UPDATE shipments SET status = ? WHERE id = ?', [String(body(ctx).status ?? 'pending'), row.id])
    return ctx.json({ ok: true })
  })

  app.route('listWebhooks', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    return ctx.json({ events: db.all('SELECT event_type, order_id, received_at FROM webhook_events WHERE store_id = ?', [ctx.tenant]) })
  })

  app.route('importShippingLabel', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    // Parse the manifest for metadata only; external template URLs are not fetched.
    const node = app.parseFeed(String((ctx.body as { raw?: string })?.raw ?? ''), false)
    return ctx.json({ accepted: true, root: node.tag })
  })

  app.route('importProductImage', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    return ctx.json({ accepted: true, note: 'image queued for review' }, 202)
  })

  app.route('checkoutReturn', (ctx) => {
    const target = String(ctx.query[app.paramName('returnUrl')] ?? '/')
    // Only same-site relative paths are honoured.
    const safe = target.startsWith('/') && !target.startsWith('//') ? target : '/'
    return ctx.redirect(safe)
  })

  app.route('salesReport', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const row = db.get('SELECT COUNT(*) AS orders, COALESCE(SUM(total),0) AS gross FROM orders WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ store: ctx.tenant, report: row })
  })

  app.route('createPayout', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    if (!ctx.sameOrigin || !ctx.csrfValid) { ctx.setCsrfRejected(); return ctx.json({ error: 'csrf' }, 403) }
    const ext = app.ids.encode('payout', Math.floor(Math.random() * 1e6))
    db.run('INSERT INTO payouts (external_id, store_id, amount, status) VALUES (?, ?, ?, ?)', [ext, ctx.tenant, Number(body(ctx).amount ?? 0), 'pending'])
    return ctx.json({ id: ext }, 201)
  })

  app.route('adminListStores', (ctx) => {
    if (!isStaff(ctx)) return ctx.json({ error: 'forbidden' }, 403)
    return ctx.json({ stores: db.all('SELECT slug, name FROM stores') })
  })

  app.route('adminImpersonate', (ctx) => {
    if (!isStaff(ctx)) return ctx.json({ error: 'forbidden' }, 403)
    const store = String(body(ctx).store ?? '')
    if (store) ctx.session.set('actAsStore', store)
    return ctx.json({ ok: true, actingAs: store })
  })

  app.route('adminConfig', (ctx) => {
    if (!isStaff(ctx)) return ctx.json({ error: 'forbidden' }, 403)
    return ctx.json({ build: 'shopflow', region: 'local' })
  })

  app.route('adminMetrics', (ctx) => {
    if (!isStaff(ctx)) return ctx.json({ error: 'forbidden' }, 403)
    return ctx.json({ orders: db.get('SELECT COUNT(*) AS n FROM orders') })
  })

  app.route('legacyGetOrder', (ctx) => {
    const row = app.findByExternalId('orders', String(ctx.params[app.paramName('orderId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'gone' }, 410)
    return ctx.json({ id: row.external_id, status: row.status, total: row.total })
  })

  app.route('legacyListProducts', (ctx) => {
    return ctx.json({ products: db.all('SELECT external_id, title FROM products WHERE store_id = ?', [ctx.tenant ?? app.plan.personas.persona_a.tenant]) })
  })

  app.route('legacyGetCustomer', (ctx) => {
    const row = app.findByExternalId('customers', String(ctx.params[app.paramName('customerId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'gone' }, 410)
    return ctx.json({ id: row.external_id, name: row.name })
  })
}
