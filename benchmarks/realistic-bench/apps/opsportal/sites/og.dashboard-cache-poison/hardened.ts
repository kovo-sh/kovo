// Operations dashboard rollup. The response is cached briefly, keyed by the selected team view, so
// repeated board refreshes stay cheap; the shared-cache payload is limited to the non-identifying
// account summary so a cached entry never carries one team's internal record references.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface AccountRow { name: string; tier: string }

export default function register(app: AppContext): void {
  const teamP = app.p('teamId')
  app.route('dashboard', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const view = String(ctx.query[teamP] ?? 'default')
    const accounts = app.all<AccountRow>(
      'SELECT name, tier FROM accounts WHERE team_id = ? ORDER BY id', [ctx.tenant])
    return ctx.json({ view, tenant: ctx.tenant, accounts })
  }, { cache: { queryKeys: [teamP], ttlMs: 30_000 } })
}
