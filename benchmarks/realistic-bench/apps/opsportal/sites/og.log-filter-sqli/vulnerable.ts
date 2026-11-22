// Log filter: returns the caller's team audit entries at or above a sequence threshold, used by the
// log viewer to page forward from the last seen entry.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const fP = app.p('filterExpr')

  app.route('logFilter', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const since = String((ctx.body as Record<string, unknown>)[fP] ?? '0')

    const sql =
      `SELECT ext_id, actor, action FROM audit_events WHERE team_id = '${ctx.tenant}' ` +
      `AND id >= ${since} ORDER BY id`
    const items = app.db.rawAll(sql)
    return ctx.json({ items })
  }, { encoding: 'json' })
}
