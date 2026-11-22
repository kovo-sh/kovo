// Dashboard GraphQL endpoint. The top-level account loader looks a record up by id scoped to the
// caller's team, and the nested tickets loader loads that account's tickets so the dashboard can
// show recent activity inline.
import type { AppContext, ReqCtx, GraphFields } from '../../src/context.ts'

interface AccountRow { ext_id: string; name: string; tier: string; team_id: string }

export default function register(app: AppContext): void {
  app.route('graphql', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const query = String((ctx.body as Record<string, unknown>)?.query ?? '')
    const fields: GraphFields = {
      account: (args) => app.get<AccountRow>(
        'SELECT * FROM accounts WHERE ext_id = ? AND team_id = ?', [args.id, ctx.tenant]),
      tickets: (_args, parent) => {
        const acc = parent as AccountRow | null
        if (!acc || acc.team_id !== ctx.tenant) return []
        return app.all('SELECT subject, body FROM tickets WHERE account_id = ?', [acc.ext_id])
      },
    }
    const data = app.graph(query, fields, {})
    return ctx.json({ data })
  }, { encoding: 'json' })
}
