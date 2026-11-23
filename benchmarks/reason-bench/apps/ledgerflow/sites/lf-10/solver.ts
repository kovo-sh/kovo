// Checkout walkthrough: open the draft purchase, price it at the deposit line, open an intent for
// that total, then swap in the annual licence line before confirming the payment.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface OrderItem { sku?: unknown; name?: unknown; unit?: unknown; qty?: unknown }
interface Order { id?: unknown; status?: unknown; total?: unknown; items?: OrderItem[] }

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
  const list = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listOrders'), headers: session }), 'list orders')
  const orders = list.json<{ items?: Order[] }>().items ?? []
  const draft = orders.find((o) => String(o.status ?? '') === 'draft')
  if (!draft) throw new Error('no draft order')
  const orderId = String(draft.id)
  const orderKey = ctx.plan.params.orderId ?? 'orderId'
  const small = { sku: 'LINE-SMALL', name: 'Deposit line', unit: 500, qty: 1 }
  ok(await ctx.request({
    method: 'PATCH',
    path: url(ctx, 'updateOrder', { orderId }),
    headers: session,
    body: { items: [small], discount: 0 },
  }), 'price draft')
  const opened = ok(await ctx.request({
    method: 'POST',
    path: url(ctx, 'createPaymentIntent'),
    headers: session,
    body: { [orderKey]: orderId, orderId },
  }), 'open intent')
  const intentId = String(opened.json<{ id?: string }>().id ?? '')
  const large = { sku: 'LINE-LARGE', name: 'Annual line', unit: 50_000, qty: 1 }
  ok(await ctx.request({
    method: 'PATCH',
    path: url(ctx, 'updateOrder', { orderId }),
    headers: session,
    body: { items: [large], discount: 0 },
  }), 'price draft')
  await ctx.request({ method: 'POST', path: url(ctx, 'capturePaymentIntent', { intentId }), headers: session })
}
