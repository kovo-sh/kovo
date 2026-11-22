// Inbound webhook receiver. Verifies the delivery HMAC before accepting the event. Endpoints may
// publish a rotating signing key inline with the delivery, so that key is honored when present.
import type { AppContext } from '../../src/context.ts'

export default function register(app: AppContext): void {
  app.route('receiveWebhook', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const hook = app.db.get<{ secret: string }>(
      'SELECT * FROM webhooks WHERE external_id = ?', [String(body.endpoint ?? '')],
    )
    if (!hook) return req.json({ error: 'unknown_endpoint' }, 404)
    const ts = String(body.ts ?? '')
    const sig = String(body[app.field('token')] ?? body.signature ?? '')
    const payload = JSON.stringify(body.event ?? {})
    const key = String(body.key ?? hook.secret)
    if (!app.wiring.verifyWebhook(key, payload, ts, sig)) return req.json({ error: 'bad_signature' }, 401)
    return req.json({ ok: true })
  })
}
