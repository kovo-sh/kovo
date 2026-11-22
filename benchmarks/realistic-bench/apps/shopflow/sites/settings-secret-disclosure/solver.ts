// Read store settings as a low-privilege role and recover the provider integration secrets.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('viewer')
  await ctx.fetch(buildPath(ctx.plan, 'getSettings'), { method: 'GET' })
}
