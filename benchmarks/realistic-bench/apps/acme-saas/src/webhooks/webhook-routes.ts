// Webhooks area: list/create/delete endpoints plus an inbound receiver. The inbound receiver's safe
// default verifies the HMAC signature against the stored endpoint secret.
import type { AppContext } from '../context.ts'
import { identity, tenantOf, ownRows, unauthorized, forbidden } from '../common.ts'

export function registerWebhookRoutes(ctx: AppContext): void {
  ctx.route('listWebhooks', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rows = ownRows<Record<string, unknown>>(ctx, tenant, 'webhooks')
    return req.json({ items: rows.map((w) => ({ id: w.external_id, url: w.url, events: w.events })) })
  })

  ctx.route('createWebhook', (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const ext = ctx.ids.encode('webhook', Date.now() % 100000)
    ctx.db.run('INSERT INTO webhooks (external_id,tenant_id,url,secret,events) VALUES (?,?,?,?,?)',
      [ext, id.tenant, String(body.url ?? ''), `rb_fake_whk_${ext}`, String(body.events ?? 'all')])
    return req.json({ id: ext }, 201)
  })

  ctx.route('deleteWebhook', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    ctx.db.run('DELETE FROM webhooks WHERE external_id = ? AND tenant_id = ?', [req.params[ctx.field('hookId')]!, tenant])
    return req.json({ ok: true })
  })

  // Safe default: verify the signature against the stored endpoint secret with a timestamp tolerance.
  ctx.route('receiveWebhook', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const hook = ctx.db.get<{ secret: string }>('SELECT * FROM webhooks WHERE external_id = ?', [String(body.endpoint ?? '')])
    if (!hook) return req.json({ error: 'unknown_endpoint' }, 404)
    const ts = String(body.ts ?? '')
    const sig = String(body[ctx.field('token')] ?? body.signature ?? '')
    const payload = JSON.stringify(body.event ?? {})
    if (!ctx.wiring.verifyWebhook(hook.secret, payload, ts, sig)) return req.json({ error: 'bad_signature' }, 401)
    return req.json({ ok: true })
  })
}
