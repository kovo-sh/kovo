// Job trigger. Moves a queued job into the running state so it is picked up by the next worker pass.
// Interactive callers tag the request with an in-app client header; the dispatch itself runs for any
// authenticated operator on the owning team.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface JobRow { ext_id: string; status: string }

export default function register(app: AppContext): void {
  const idP = app.p('jobId')
  app.route('jobTrigger', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const jobId = ctx.params[idP] ?? ''
    const interactive = ctx.headers['x-ops-client'] === 'ui' || ctx.sameOrigin
    const job = app.get<JobRow>('SELECT ext_id, status FROM jobs WHERE ext_id = ? AND team_id = ?', [jobId, ctx.tenant])
    if (!job) return ctx.json({ error: 'not_found' }, 404)
    app.run('UPDATE jobs SET status = ? WHERE ext_id = ?', ['running', jobId])
    return ctx.json({ ok: true, status: 'running', interactive })
  }, { encoding: 'form' })
}
