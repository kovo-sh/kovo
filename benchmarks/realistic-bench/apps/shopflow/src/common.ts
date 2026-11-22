// Common, non-feature routes: authentication, session, health, the UI runtime config and a few
// read-only merchant surfaces. Registered by the server for every boot.
import type { AppContext } from './context.ts'
import type { ReqCtx } from '../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

const UI_ROUTES = [
  'login', 'logout', 'session', 'csrfToken', 'listProducts', 'getProduct', 'searchProducts',
  'productReviews', 'submitReview', 'createCart', 'getCart', 'addCartItem', 'applyCoupon', 'checkout',
  'listGiftCards', 'listOrders', 'getOrder', 'getInvoice', 'moderationQueue', 'listPayments',
  'createRefund', 'getSettings',
]

export default function register(app: AppContext): void {
  const plan = app.plan

  app.route('login', (ctx) => {
    const { email, password } = body(ctx)
    const persona = app.findPersona(String(email ?? ''), String(password ?? ''))
    if (!persona) return ctx.json({ error: 'invalid_credentials' }, 401)
    ctx.session.set('persona', persona.id)
    ctx.session.set('store', persona.tenant)
    return ctx.json({ persona: persona.id, store: persona.tenant, role: persona.role, csrf: ctx.issueCsrfToken() })
  })

  app.route('logout', (ctx) => {
    ctx.session.destroy()
    return ctx.json({ ok: true })
  })

  app.route('session', (ctx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ authenticated: false }, 401)
    return ctx.json({ authenticated: true, actor: ctx.actor, store: ctx.tenant, csrf: ctx.issueCsrfToken() })
  })

  app.route('csrfToken', (ctx) => ctx.json({ csrf: ctx.issueCsrfToken() }))

  app.route('healthCheck', (ctx) => ctx.json({ status: 'ok', app: 'shopflow' }))

  app.route('appConfig', (ctx) => {
    const routes: Record<string, string> = {}
    for (const key of UI_ROUTES) if (plan.routes[key]) routes[key] = plan.routes[key]!.path
    return ctx.json({ apiPrefix: plan.apiPrefix, routes })
  })

  app.route('getSettings', (ctx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const cfg = app.db.get<{ settings_json: string }>('SELECT settings_json FROM store_config WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ store: ctx.tenant, settings: cfg ? JSON.parse(cfg.settings_json) : {} })
  })

  app.route('getStore', (ctx) => {
    const row = app.db.get('SELECT slug, name FROM stores WHERE slug = ?', [ctx.params[app.paramName('storeId')]])
    return row ? ctx.json(row) : ctx.json({ error: 'not_found' }, 404)
  })
}
