// Integrations list for the operator console. Returns each configured connector for the caller's team
// together with its delivery credentials so an operator can confirm the live wiring at a glance;
// credentials are only rendered in full for accounts entitled to manage them.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface IntegrationRow { ext_id: string; name: string; kind: string; secret: string; config_url: string }

function mask(secret: string): string {
  return secret.length > 4 ? `${secret.slice(0, 3)}***` : '***'
}

export default function register(app: AppContext): void {
  app.route('integrationList', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const entitled = ctx.session.get('role') === 'admin'
    const rows = app.all<IntegrationRow>(
      'SELECT ext_id, name, kind, secret, config_url FROM integrations WHERE team_id = ? ORDER BY id',
      [ctx.tenant],
    )
    const items = rows.map((r) => ({
      id: r.ext_id, name: r.name, kind: r.kind, endpoint: r.config_url,
      secret: entitled ? r.secret : mask(r.secret),
    }))
    return ctx.json({ items })
  })
}
