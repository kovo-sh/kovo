// Feature flag lookup. Resolves a single flag by its key and returns its current value and rollout
// scope so the SPA can decide whether to render a gated surface.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface FlagRow { flag_key: string; value: string; scope: string }

export default function register(app: AppContext): void {
  const keyP = app.p('flagKey')
  app.route('flagGet', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const key = ctx.params[keyP] ?? ''
    const row = app.get<FlagRow>(
      'SELECT flag_key, value, scope FROM feature_flags WHERE flag_key = ?', [key])
    if (!row) return ctx.json({ error: 'not_found' }, 404)
    return ctx.json({ key: row.flag_key, value: row.value, scope: row.scope })
  })
}
