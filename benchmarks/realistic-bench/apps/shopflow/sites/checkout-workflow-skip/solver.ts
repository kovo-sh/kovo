// Confirm an order that is still awaiting payment, skipping the capture step.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface Order { external_id: string; status: string; payment_state: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const res = await ctx.fetch(buildPath(ctx.plan, 'listOrders'), { method: 'GET' })
  const data = (await res.json().catch(() => ({}))) as { orders?: Order[] }
  const target = data.orders?.find((o) => o.payment_state !== 'captured' || o.status === 'awaiting_payment')
  if (!target) return
  await ctx.fetch(buildPath(ctx.plan, 'confirmOrder', { orderId: target.external_id }), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  })
}
