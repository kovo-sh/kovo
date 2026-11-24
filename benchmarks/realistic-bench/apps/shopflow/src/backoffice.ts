// Merchant back-office: customers, payments, refunds, review moderation, API tokens and settings.
import type { AppContext } from './context.ts'
import type { ReqCtx } from '../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}
function mask(secret: string): string {
  return secret.length <= 4 ? '****' : `****${secret.slice(-4)}`
}
const guard = (ctx: ReqCtx): boolean => ctx.actor !== 'anonymous'

export default function register(app: AppContext): void {
  const db = app.db
  // Admin-namespaced/settings mutations are merchant-owner functions. A plain store member must not
  // be able to change store configuration or moderate reviews; the auth-only guard made those safe
  // defaults look like a latent BFLA to any differential scanner.
  const privileged = (ctx: ReqCtx): boolean => {
    const role = app.personaFor(ctx.actor)?.role
    return role === 'owner' || role === 'admin'
  }

  app.route('listCustomers', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all('SELECT external_id, name, email FROM customers WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ customers: rows })
  })

  app.route('getCustomer', (ctx) => {
    const row = app.findByExternalId('customers', String(ctx.params[app.paramName('customerId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json(row)
  })

  app.route('listPayments', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all('SELECT external_id, order_id, amount, status FROM payments WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ payments: rows })
  })

  app.route('getPayment', (ctx) => {
    const row = app.findByExternalId('payments', String(ctx.params[app.paramName('paymentId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json(row)
  })

  app.route('createRefund', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    if (!ctx.sameOrigin || !ctx.csrfValid) { ctx.setCsrfRejected(); return ctx.json({ error: 'csrf' }, 403) }
    const amount = Number(body(ctx)[app.paramName('bodyAmount')] ?? 0)
    const ext = app.ids.encode('refund', Math.floor(Math.random() * 1e6))
    db.run('INSERT INTO refunds (external_id, store_id, amount, status) VALUES (?, ?, ?, ?)', [ext, ctx.tenant, Math.max(0, amount), 'pending'])
    return ctx.json({ id: ext, status: 'pending' }, 201)
  })

  app.route('getRefund', (ctx) => {
    const row = app.findByExternalId('refunds', String(ctx.params[app.paramName('refundId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json(row)
  })

  app.route('approveRefund', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const row = app.findByExternalId('refunds', String(ctx.params[app.paramName('refundId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    db.run("UPDATE refunds SET status = 'approved' WHERE id = ?", [row.id])
    return ctx.json({ ok: true })
  })

  app.route('moderationQueue', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all<{ external_id: string; author: string; body: string }>(
      'SELECT external_id, author, body FROM reviews WHERE store_id = ? AND approved = 0', [ctx.tenant])
    const items = rows.map((r) => ({ id: r.external_id, author: r.author, bodyHtml: r.body.replace(/[<>]/g, '') }))
    return ctx.html(`<ul>${items.map((i) => `<li>${i.bodyHtml}</li>`).join('')}</ul>`)
  })

  app.route('moderateReview', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    if (!privileged(ctx)) return ctx.json({ error: 'forbidden' }, 403)
    const row = app.findByExternalId('reviews', String(ctx.params[app.paramName('reviewId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    db.run('UPDATE reviews SET approved = 1 WHERE id = ?', [row.id])
    return ctx.json({ ok: true })
  })

  app.route('listTokens', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const rows = db.all<{ external_id: string; label: string; token: string }>(
      'SELECT external_id, label, token FROM api_tokens WHERE store_id = ?', [ctx.tenant])
    return ctx.json({ tokens: rows.map((t) => ({ id: t.external_id, label: t.label, preview: mask(t.token) })) })
  })

  app.route('getToken', (ctx) => {
    const row = app.findByExternalId('api_tokens', String(ctx.params[app.paramName('tokenId')] ?? ''))
    if (!row || row.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json({ id: row.external_id, label: row.label, preview: mask(String(row.token)) })
  })

  app.route('createToken', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    const ext = app.ids.encode('token', Math.floor(Math.random() * 1e6))
    const token = `rbs_fake_${app.ids.encode('token', Math.floor(Math.random() * 1e6))}`
    db.run('INSERT INTO api_tokens (external_id, store_id, label, token, scope) VALUES (?, ?, ?, ?, ?)', [
      ext, ctx.tenant, String(body(ctx).label ?? 'key'), token, 'read'])
    return ctx.json({ id: ext, token }, 201)
  })

  // The settings document is a fixed-schema merchant config (currency/timezone/…), not a free-form
  // bag: merge allow-listed keys into the stored object and reject anything else, so a caller cannot
  // persist arbitrary security-looking fields (a `role`, a `providerKey`, …) into their own config.
  // The planted settings leak reads the provider_key/webhook_secret columns, so this changes no target.
  const SETTINGS_KEYS = new Set(['currency', 'timezone', 'locale', 'theme', 'dateFormat'])
  app.route('updateSettings', (ctx) => {
    if (!guard(ctx)) return ctx.json({ error: 'unauthorized' }, 401)
    if (!privileged(ctx)) return ctx.json({ error: 'forbidden' }, 403)
    const patch = body(ctx).settings
    if (patch !== undefined && (patch === null || typeof patch !== 'object' || Array.isArray(patch))) {
      return ctx.json({ error: 'invalid_settings' }, 400)
    }
    const supplied = (patch ?? {}) as Record<string, unknown>
    const unknown = Object.keys(supplied).filter(key => !SETTINGS_KEYS.has(key))
    if (unknown.length > 0) return ctx.json({ error: 'unknown_setting', keys: unknown.slice(0, 8) }, 400)
    const cfg = db.get<{ settings_json: string }>('SELECT settings_json FROM store_config WHERE store_id = ?', [ctx.tenant])
    let current: Record<string, unknown> = {}
    try { current = cfg ? JSON.parse(cfg.settings_json) as Record<string, unknown> : {} } catch { current = {} }
    const merged = { ...current, ...supplied }
    db.run('UPDATE store_config SET settings_json = ? WHERE store_id = ?', [JSON.stringify(merged), ctx.tenant])
    return ctx.json({ ok: true, settings: merged })
  })
}
