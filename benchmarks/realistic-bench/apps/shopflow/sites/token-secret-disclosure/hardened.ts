// API credentials listing. Returns the store's issued API tokens so the merchant can manage them,
// exposing only a masked preview; the stored key itself is never included in the listing.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function mask(secret: string): string {
  return secret.length <= 4 ? '****' : `****${secret.slice(-4)}`
}

function listTokens(app: AppContext, tenant: string): Array<Record<string, unknown>> {
  const rows = app.db.all<{ external_id: string; label: string; token: string; scope: string }>(
    'SELECT external_id, label, token, scope FROM api_tokens WHERE store_id = ?', [tenant])
  return rows.map((t) => ({ id: t.external_id, label: t.label, scope: t.scope, preview: mask(t.token) }))
}

export default function register(app: AppContext): void {
  app.route('listTokens', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    return ctx.json({ tokens: listTokens(app, String(ctx.tenant ?? '')) })
  })
}
