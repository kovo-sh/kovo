// Payment provider webhook. Validates the HMAC signature against the per-store signing secret
// provisioned for that merchant, so a signature computed without that secret is rejected.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function canonical(b: Record<string, unknown>): string {
  return `${b.store ?? ''}|${b.type ?? ''}|${b.order ?? ''}|${b.amount ?? ''}`
}

export default function register(app: AppContext): void {
  app.route('paymentWebhook', (ctx: ReqCtx) => {
    const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
    const ts = String(ctx.headers['x-webhook-timestamp'] ?? b.ts ?? '')
    const sig = String(ctx.headers['x-webhook-signature'] ?? '')
    const cfg = app.db.get<{ webhook_secret: string }>('SELECT webhook_secret FROM store_config WHERE store_id = ?', [String(b.store ?? '')])
    if (!cfg) return ctx.json({ error: 'unknown_store' }, 404)
    if (!app.checkWebhookSig(cfg.webhook_secret, canonical(b), ts, sig, { toleranceSec: 300 })) {
      return ctx.json({ error: 'invalid_signature' }, 400)
    }
    app.db.run('INSERT INTO webhook_events (store_id, event_type, received_at) VALUES (?, ?, ?)', [
      String(b.store ?? ''), String(b.type ?? 'unknown'), Date.now(),
    ])
    return ctx.json({ received: true })
  }, { encoding: 'json' })
}
