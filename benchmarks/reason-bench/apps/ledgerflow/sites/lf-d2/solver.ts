// Settlement walkthrough: open a paid multi-line order, read its per-line split, credit each line
// through the refund desk, and read the order back to compare the split with the settled amount.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface OrderItem { id?: unknown }
interface Order { id?: unknown; paid?: unknown; items?: OrderItem[] }

function url(ctx: SolverCtx, routeKey: string, values: Record<string, string> = {}): string {
  const path = ctx.plan.routes[routeKey]!.path
  return path.replace(/:([A-Za-z0-9_]+)/g, (_, name: string) => {
    const logical = Object.keys(ctx.plan.params).find((key) => ctx.plan.params[key] === name)
    return encodeURIComponent((logical ? values[logical] : undefined) ?? values[name] ?? name)
  })
}

function ok(res: SolverResponse, label: string): SolverResponse {
  if (res.status < 200 || res.status >= 300) throw new Error(`${label} returned ${res.status}`)
  return res
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const session = await ctx.login('member_a')
  const listed = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listOrders'), headers: session }), 'list orders')
  const orders = listed.json<{ items?: Order[] }>().items ?? []
  const order = orders.find((o) => Number(o.paid ?? 0) > 0 && (o.items ?? []).length > 1)
  if (!order) throw new Error('no settled multi-line order')
  const orderId = String(order.id)
  await ctx.request({ method: 'GET', path: `${url(ctx, 'getOrder', { orderId })}?settle=1`, headers: session })
  for (const item of order.items ?? []) {
    await ctx.request({
      method: 'POST', path: url(ctx, 'refundOrderItem', { orderId, itemId: String(item.id) }), headers: session,
    })
  }
  await ctx.request({ method: 'GET', path: url(ctx, 'getOrder', { orderId }), headers: session })
}
