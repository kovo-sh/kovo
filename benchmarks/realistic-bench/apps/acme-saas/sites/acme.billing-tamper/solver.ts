// Plan change price tampering: switch to a higher-tier plan while supplying a mismatched price so the
// stored plan price diverges from the catalog price.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  await ctx.fetch(ctx.path('updatePlan'), {
    method: 'PATCH',
    session: owner,
    body: { [ctx.plan.params.planId ?? 'planId']: 'scale', plan: 'scale', price: 1 },
  })
}
