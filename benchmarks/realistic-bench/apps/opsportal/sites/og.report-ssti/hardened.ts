// Report builder preview. Renders a fixed server layout against a data context that includes live
// account figures and the report service configuration; caller input is bound as data only.
import type { AppContext, ReqCtx } from '../../src/context.ts'

const LAYOUT = 'Report for {{ account }}: {{ total }} open tickets ({{ region }})'

export default function register(app: AppContext): void {
  const field = app.p('templateSrc')
  app.route('reportRender', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const body = (ctx.body ?? {}) as Record<string, unknown>
    void body[field]
    const context = {
      account: String(body.account ?? 'Globex'),
      total: Number(body.total ?? 3),
      config: app.markSecret({ apiKey: 'rbs_fake_report_key', region: 'us-east' }),
      region: 'us-east',
    }
    const html = app.render(LAYOUT, context)
    return ctx.json({ html })
  }, { encoding: 'json' })
}
