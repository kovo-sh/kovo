// A read-only member opens the tenant activity log and reads a credential reference captured in an
// event detail that should have been stripped before display.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const viewer = await ctx.login('viewer')
  await ctx.fetch(ctx.path('adminAuditLog'), { session: viewer })
}
