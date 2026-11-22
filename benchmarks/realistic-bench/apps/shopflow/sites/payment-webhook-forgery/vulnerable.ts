// Payment provider webhook. Validates the HMAC signature against a shared test-mode secret that ships
// in the provider's public docs, so anyone can compute a matching signature for a forged event.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

const SHARED_SECRET = 'whsec_test_shared'

function canonical(b: Record<string, unknown>): string {
  return `${b.store ?? ''}|${b.type ?? ''}|${b.order ?? ''}|${b.amount ?? ''}`
}

export default function register(app: AppContext): void {
  app.route('paymentWebhook', (ctx: ReqCtx) => {
    const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
    const ts = String(ctx.headers['x-webhook-timestamp'] ?? b.ts ?? '')
    const sig = String(ctx.headers['x-webhook-signature'] ?? '')
    if (!app.checkWebhookSig(SHARED_SECRET, canonical(b), ts, sig)) {
      return ctx.json({ error: 'invalid_signature' }, 400)
    }
    app.db.run('INSERT INTO webhook_events (store_id, event_type, received_at) VALUES (?, ?, ?)', [
      String(b.store ?? ''), String(b.type ?? 'unknown'), Date.now(),
    ])
    return ctx.json({ received: true })
  }, { encoding: 'json' })
}
