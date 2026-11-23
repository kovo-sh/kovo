// Webhook configuration update. An optional verification bundle is checked against the hook's own
// secret with a canonical string that binds timestamp, tenant, event type and raw body.
import type { AppContext } from '../../src/context.ts'
import {
  currentUserExt, orgOf, notFound, requirePerm, asRecord, str, bool, audit,
} from '../../src/common.ts'
import { verifyCanonical } from '../../../../lib/hmac.ts'

export default function register(ctx: AppContext): void {
  ctx.route('webhooks.update', (req) => {
    const denied = requirePerm(ctx, req, 'webhook:manage')
    if (denied) return denied
    const org = orgOf(req)!
    const ext = req.params[ctx.field('hookId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('webhooks', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const body = asRecord(req.body)
    const bundle = asRecord(body.signatureCheck)
    if (Object.keys(bundle).length > 0) {
      const tenantId = str(bundle.tenantId)
      const eventType = str(bundle.eventType)
      const timestamp = str(bundle.timestamp)
      const rawBody = str(bundle.rawBody)
      const signature = str(bundle.signature)
      const events = String(row.events).split(',').map((value) => value.trim()).filter(Boolean)
      const bound = tenantId === org && events.includes(eventType)
      const valid = bound && verifyCanonical(String(row.secret), timestamp,
        { tenantId, eventType }, rawBody, signature, { toleranceSec: 300 })
      if (!valid) return req.json({ error: 'invalid_signature' }, 401)
      return req.json({ ok: true, verified: true, org, event: eventType })
    }
    ctx.db.run('UPDATE webhooks SET url = ?, events = ?, active = ? WHERE external_id = ? AND org_slug = ?',
      [str(body.url) || String(row.url), str(body.events) || String(row.events),
        body.active === undefined ? Number(row.active) : bool(body.active) ? 1 : 0, ext, org])
    audit(ctx, req, 'webhook.update', ext, currentUserExt(ctx, req))
    return req.json({ ok: true })
  })
}
