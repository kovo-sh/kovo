// Basket walkthrough: open the seeded basket, apply the workspace promotion, reprice the larger line
// down to a nominal amount, and read the basket back to see whether the promotion survived.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface CartItem { id?: unknown; unit?: unknown; qty?: unknown }
interface Cart { id?: unknown; coupon?: unknown; subtotal?: unknown; items?: CartItem[] }

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
  const listed = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listCarts'), headers: session }), 'list carts')
  const carts = listed.json<{ items?: Cart[] }>().items ?? []
  const cart = carts.find((c) => (c.items ?? []).length > 0)
  if (!cart) throw new Error('no open basket')
  const cartId = String(cart.id)
  const coupons = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listCoupons'), headers: session }), 'list coupons')
  const code = String((coupons.json<{ items?: Array<{ code?: unknown }> }>().items ?? [])[0]?.code ?? '')
  ok(await ctx.request({
    method: 'POST', path: url(ctx, 'applyCoupon', { cartId }), headers: session, body: { code },
  }), 'apply coupon')
  const items = [...(cart.items ?? [])].sort((a, b) => Number(b.unit) - Number(a.unit))
  const itemId = String(items[0]?.id ?? '')
  await ctx.request({
    method: 'PATCH', path: url(ctx, 'patchCartItem', { cartId, itemId }), headers: session, body: { unit: 1, qty: 1 },
  })
  await ctx.request({ method: 'GET', path: url(ctx, 'getCart', { cartId }), headers: session })
}
