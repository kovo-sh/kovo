// Seat invariant bypass: fire a burst of concurrent seat additions as the owner so they all clear the
// same stale seat count and drive seats_used past the plan limit.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const add = (): Promise<unknown> => ctx.fetch(ctx.path('addSeat'), { method: 'POST', session: owner, body: {} })
  await Promise.all(Array.from({ length: 15 }, add))
}
