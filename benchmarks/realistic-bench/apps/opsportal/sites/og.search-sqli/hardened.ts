// Saved-search run: matches accounts in the caller's team whose name contains the supplied term,
// ordered by exact matches first so the closest textual matches surface first.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const qP = app.p('searchQuery')

  app.route('searchRun', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const term = String((ctx.body as Record<string, unknown>)[qP] ?? 'a')

    const items = app.all(
      'SELECT ext_id, name, tier FROM accounts WHERE team_id = ? AND name LIKE ? ORDER BY name = ?, name',
      [ctx.tenant, `%${term}%`, term])
    return ctx.json({ items })
  }, { encoding: 'json' })
}
