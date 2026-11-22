// Information disclosure: a non-privileged operator lists the team's integrations and receives the
// live connector credentials (rbs_ secret canaries) in the JSON payload.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  await ctx.fetch(ctx.plan.routes.integrationList!.path, { method: 'GET' })
}
