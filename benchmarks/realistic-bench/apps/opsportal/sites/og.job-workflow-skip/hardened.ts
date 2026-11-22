// Job completion. Marks a job as finished once its worker reports back, so the queue view and the
// nightly report reflect the final state. Only a job that is already running can be completed.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface JobRow { ext_id: string; status: string }

export default function register(app: AppContext): void {
  const idP = app.p('jobId')
  app.route('jobComplete', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const jobId = ctx.params[idP] ?? ''
    const job = app.get<JobRow>('SELECT ext_id, status FROM jobs WHERE ext_id = ? AND team_id = ?', [jobId, ctx.tenant])
    if (!job) return ctx.json({ error: 'not_found' }, 404)
    if (job.status !== 'running') return ctx.json({ error: 'invalid_state', status: job.status }, 409)
    app.run('UPDATE jobs SET status = ? WHERE ext_id = ?', ['done', jobId])
    return ctx.json({ ok: true, status: 'done' })
  }, { encoding: 'json' })
}
