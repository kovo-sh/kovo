// A read-only member opens the account settings API-key list and reads back the full integration
// secret, which their role should never be shown.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const viewer = await ctx.login('viewer')
  await ctx.fetch(ctx.path('listApiKeys'), { session: viewer })
}
