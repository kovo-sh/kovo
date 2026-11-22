// Saved-search run: matches accounts in the caller's team whose name contains the supplied term,
// ordered by the term so the closest textual matches surface first.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const qP = app.p('searchQuery')

  app.route('searchRun', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const term = String((ctx.body as Record<string, unknown>)[qP] ?? 'a')
    const needle = term.replace(/'/g, "''")

    const sql =
      `SELECT ext_id, name, tier FROM accounts WHERE team_id = '${ctx.tenant}' ` +
      `AND name LIKE '%${needle}%' ORDER BY name = ${term}, name`
    const items = app.db.rawAll(sql)
    return ctx.json({ items })
  }, { encoding: 'json' })
}
