// Job trigger. Moves a queued job into the running state so it is picked up by the next worker pass.
// State changes are accepted only from the app's own origin or when a matching request token is
// presented, so a cross-site submission cannot dispatch a job.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface JobRow { ext_id: string; status: string }

export default function register(app: AppContext): void {
  const idP = app.p('jobId')
  app.route('jobTrigger', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    if (!ctx.sameOrigin && !ctx.csrfValid) { ctx.setCsrfRejected(); return ctx.json({ error: 'request_rejected' }, 403) }
    const jobId = ctx.params[idP] ?? ''
    const job = app.get<JobRow>('SELECT ext_id, status FROM jobs WHERE ext_id = ? AND team_id = ?', [jobId, ctx.tenant])
    if (!job) return ctx.json({ error: 'not_found' }, 404)
    app.run('UPDATE jobs SET status = ? WHERE ext_id = ?', ['running', jobId])
    return ctx.json({ ok: true, status: 'running', interactive: true })
  }, { encoding: 'form' })
}
