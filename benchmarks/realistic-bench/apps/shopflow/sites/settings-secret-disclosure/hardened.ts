// Store settings. Returns the merchant configuration; the provider integration keys are included only
// for store owners, so lower-privilege roles see the settings without the raw credentials.
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
    const role = app.personaFor(ctx.actor)?.role
    const out: Record<string, unknown> = { store: ctx.tenant, settings }
    if (role === 'owner' || role === 'admin') {
      out.providerKey = cfg?.provider_key ?? null
      out.webhookSecret = cfg?.webhook_secret ?? null
    }
    return ctx.json(out)
  })
}
