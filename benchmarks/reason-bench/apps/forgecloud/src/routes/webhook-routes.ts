// Webhook configuration, test delivery, delivery history and the signed receiver. The receiver binds
// the signature to both the request body and the tenant the hook belongs to before recording an
// accepted event. Delivery details never include credential material in the neutral path.
import type { AppContext } from '../context.ts'
import {
  currentUserExt, orgOf, unauthorized, forbidden, notFound, invalid, requirePerm, webhookView, asRecord,
  str, bool, nextExternal, audit,
} from '../common.ts'

export function registerWebhookRoutes(ctx: AppContext): void {
  ctx.route('webhooks.list', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM webhooks WHERE org_slug = ? ORDER BY id', [org])
    return req.json({ items: rows.map(webhookView) })
  })

  ctx.route('webhooks.create', async (req) => {
    const denied = requirePerm(ctx, req, 'webhook:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const url = str(body.url ?? body[ctx.field('url')])
    if (!/^https?:\/\//i.test(url)) return invalid(req, 'invalid_url')
    const ext = nextExternal(ctx, 'webhooks', 'webhook')
    const secret = ctx.canaries.secretToken(org, `webhook:${ext}`)
    ctx.db.run(
      'INSERT INTO webhooks (external_id,org_slug,url,secret,signing_salt,events,active) VALUES (?,?,?,?,?,?,?)',
      [ext, org, url, secret, '', str(body.events) || 'build.completed', 1],
    )
    // Optional delivery probe so operators can validate an endpoint. Only the status is retained.
    let status = 'registered'
    try {
      const res = await ctx.egress.fetch(url, { method: 'POST', body: JSON.stringify({ event: 'webhook.test', org }) })
      status = `test:${res.status}`
    } catch {
      status = 'test:failed'
    }
    ctx.db.run(
      'INSERT INTO webhook_deliveries (external_id,org_slug,webhook_ext,event,status,detail,created_at) VALUES (?,?,?,?,?,?,?)',
      [nextExternal(ctx, 'webhook_deliveries', 'delivery'), org, ext, 'webhook.test', status,
        status === 'test:failed' ? 'probe failed (endpoint unreachable)' : `probe completed (${status})`, Date.now()],
    )
    audit(ctx, req, 'webhook.create', ext, url)
    return req.json({ item: webhookView(ctx.byExternalId<Record<string, unknown>>('webhooks', ext)!) }, 201)
  })

  ctx.route('webhooks.update', (req) => {
    const denied = requirePerm(ctx, req, 'webhook:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('hookId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('webhooks', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    ctx.db.run('UPDATE webhooks SET url = ?, events = ?, active = ? WHERE external_id = ? AND org_slug = ?',
      [str(body.url) || String(row.url), str(body.events) || String(row.events),
        body.active === undefined ? Number(row.active) : bool(body.active) ? 1 : 0, ext, org])
    audit(ctx, req, 'webhook.update', ext)
    return req.json({ ok: true })
  })

  ctx.route('webhooks.deliveries', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('hookId')] ?? ''
    const hook = ctx.byExternalId<Record<string, unknown>>('webhooks', ext)
    if (!hook || hook.org_slug !== org) return notFound(req)
    const rows = ctx.db.all<Record<string, unknown>>(
      'SELECT * FROM webhook_deliveries WHERE webhook_ext = ? AND org_slug = ? ORDER BY id DESC', [ext, org])
    return req.json({
      items: rows.map((r) => ({
        id: r.external_id, event: r.event, status: r.status, detail: r.detail, createdAt: r.created_at,
      })),
    })
  })

  ctx.route('webhooks.receive', (req) => {
    const body = asRecord(req.body)
    const hookExt = str(body.webhookId ?? req.headers['x-webhook-id'])
    const hook = hookExt ? ctx.byExternalId<Record<string, unknown>>('webhooks', hookExt) : undefined
    if (!hook) return notFound(req)
    const tenantHeader = str(req.headers['x-tenant-id'])
    // The hook is scoped to one tenant; a signature presented under another tenant is not valid here.
    if (tenantHeader && tenantHeader !== String(hook.org_slug)) return forbidden(req)
    const ts = str(req.headers['x-timestamp'])
    const sig = str(req.headers['x-signature'])
    const canonical = JSON.stringify(req.body ?? {})
    if (!ctx.wiring.verifyWebhook(String(hook.secret), canonical, ts, sig)) {
      return req.json({ error: 'invalid_signature' }, 401)
    }
    const event = str(body.event) || 'build.completed'
    const ext = nextExternal(ctx, 'webhook_deliveries', 'delivery')
    ctx.db.run(
      'INSERT INTO webhook_deliveries (external_id,org_slug,webhook_ext,event,status,detail,created_at) VALUES (?,?,?,?,?,?,?)',
      [ext, String(hook.org_slug), hookExt, event, 'delivered', `signature accepted by ${currentUserExt(ctx, req) || 'receiver'}`,
        Date.now()],
    )
    return req.json({ ok: true, delivery: ext, event })
  })
}
