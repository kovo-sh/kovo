// Diagnostics runner: performs a reachability probe against an operator-supplied host.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const hostP = app.p('host')
  app.route('diagRun', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const host = String((ctx.body as Record<string, unknown>)[hostP] ?? '')
    if (host.length === 0 || host.length > 128) return ctx.json({ error: 'host_required' }, 400)
    const result = app.sim('ping -c 1 {0}', [host])
    return ctx.json({ output: result.output })
  }, { encoding: 'json' })
}
