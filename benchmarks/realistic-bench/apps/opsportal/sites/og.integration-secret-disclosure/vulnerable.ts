// Integrations list for the operator console. Returns each configured connector for the caller's team
// together with its delivery credentials so an operator can confirm the live wiring at a glance.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface IntegrationRow { ext_id: string; name: string; kind: string; secret: string; config_url: string }

export default function register(app: AppContext): void {
  app.route('integrationList', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const rows = app.all<IntegrationRow>(
      'SELECT ext_id, name, kind, secret, config_url FROM integrations WHERE team_id = ? ORDER BY id',
      [ctx.tenant],
    )
    const items = rows.map((r) => ({
      id: r.ext_id, name: r.name, kind: r.kind, endpoint: r.config_url, secret: r.secret,
    }))
    return ctx.json({ items })
  })
}
