// List API credentials as a low-privilege viewer and read a full stored key out of the response.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('viewer')
  await ctx.fetch(buildPath(ctx.plan, 'listTokens'), { method: 'GET' })
}
