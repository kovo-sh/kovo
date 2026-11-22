// Workflow bypass: complete a job that has never been started, skipping the required running state.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const listRes = await ctx.fetch(ctx.plan.routes.jobList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string; status: string }> }
  const job = list.items?.find((j) => j.status === 'pending') ?? list.items?.[0]
  if (!job) return
  const path = ctx.plan.routes.jobComplete!.path.replace(/:[A-Za-z0-9_]+/, job.ext_id)
  await ctx.fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({}),
  })
}
