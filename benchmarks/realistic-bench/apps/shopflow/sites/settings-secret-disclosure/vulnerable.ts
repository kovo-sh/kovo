// Store settings. Returns the merchant configuration together with the provider integration keys so
// the back-office settings screen can display the current credentials inline.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('getSettings', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const cfg = app.db.get<{ settings_json: string; webhook_secret: string; provider_key: string }>(
      'SELECT settings_json, webhook_secret, provider_key FROM store_config WHERE store_id = ?',
      [ctx.tenant],
    )
    const settings = cfg ? JSON.parse(cfg.settings_json) : {}
    return ctx.json({
      store: ctx.tenant,
      settings,
      providerKey: cfg?.provider_key ?? null,
      webhookSecret: cfg?.webhook_secret ?? null,
    })
  })
}
