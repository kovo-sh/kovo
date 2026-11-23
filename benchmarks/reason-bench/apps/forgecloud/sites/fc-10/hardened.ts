// Webhook configuration surface: delivery history and the signed receiver. Failed delivery records
// keep only a neutral transport reason, and the receiver verifies the presented signature with the
// hook's own secret before accepting the event.
import type { AppContext } from '../../src/context.ts'
import {
  currentUserExt, orgOf, unauthorized, forbidden, notFound, asRecord, str, nextExternal,
} from '../../src/common.ts'

export default function register(ctx: AppContext): void {
  ctx.route('webhooks.deliveries', (req) => {
    const org = orgOf(req)
    if (!org) return unauthorized(req)
    const ext = req.params[ctx.field('hookId')] ?? ''
    const hook = ctx.byExternalId<Record<string, unknown>>('webhooks', ext)
    if (!hook || hook.org_slug !== org) return notFound(req)
    const rows = ctx.db.all<Record<string, unknown>>(
      'SELECT * FROM webhook_deliveries WHERE webhook_ext = ? AND org_slug = ? ORDER BY id DESC', [ext, org])
    return req.json({
      items: rows.map((row) => {
        const status = String(row.status)
        const detail = String(row.detail)
        return {
          id: row.external_id, event: row.event, status, createdAt: row.created_at,
          detail: status.startsWith('failed')
            ? `${detail}; signing reference withheld`
            : detail,
        }
      }),
    })
  })

  ctx.route('webhooks.receive', (req) => {
    const body = asRecord(req.body)
    const hookExt = str(body.webhookId ?? req.headers['x-webhook-id'])
    const hook = hookExt ? ctx.byExternalId<Record<string, unknown>>('webhooks', hookExt) : undefined
    if (!hook) return notFound(req)
    const tenantHeader = str(req.headers['x-tenant-id'])
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
      [ext, String(hook.org_slug), hookExt, event, 'delivered',
        `signature accepted by ${currentUserExt(ctx, req) || 'receiver'}`, Date.now()],
    )
    return req.json({ ok: true, delivery: ext, event })
  })
}
