// Diagnostics runner: performs a reachability probe against an operator-supplied host.
import type { AppContext, ReqCtx } from '../../src/context.ts'

const HOST = /^[A-Za-z0-9.\-]{1,64}$/

export default function register(app: AppContext): void {
  const hostP = app.p('host')
  app.route('diagRun', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const host = String((ctx.body as Record<string, unknown>)[hostP] ?? '')
    if (!HOST.test(host)) return ctx.json({ error: 'invalid_host' }, 400)
    const result = app.sim('ping -c 1 {0}', [host])
    return ctx.json({ output: result.output })
  }, { encoding: 'json' })
}
