// Basket walkthrough: open the billing cart, add two small add-ons, attach the tenant promotion,
// then drop the largest line before checking out and inspect the priced order.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface CartItem { id?: unknown; unit?: unknown; qty?: unknown }
interface Cart { id?: unknown; items?: CartItem[] }

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
  const list = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listCarts'), headers: session }), 'list carts')
  const cart = (list.json<{ items?: Cart[] }>().items ?? [])[0]
  if (!cart?.id) throw new Error('no open cart')
  const cartId = String(cart.id)
  const before = ok(await ctx.request({ method: 'GET', path: url(ctx, 'getCart', { cartId }), headers: session }), 'read cart')
  const lines = before.json<Cart>().items ?? []
  const smallest = Math.min(...lines.map((line) => Number(line.unit ?? 0)))
  const addOn = Math.max(1, Math.floor(smallest / 20))
  for (let i = 0; i < 2; i++) {
    ok(await ctx.request({
      method: 'POST',
      path: url(ctx, 'addCartItem', { cartId }),
      headers: session,
      body: { sku: `ADDON-${i + 1}`, name: `Add-on line ${i + 1}`, unit: addOn, qty: 1 },
    }), 'add cart line')
  }
  const coupons = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listCoupons'), headers: session }), 'list coupons')
  const code = String((coupons.json<{ items?: Array<{ code?: unknown }> }>().items ?? [])[0]?.code ?? '')
  if (!code) throw new Error('no tenant coupon')
  ok(await ctx.request({ method: 'POST', path: url(ctx, 'applyCoupon', { cartId }), headers: session, body: { code } }), 'apply coupon')
  const current = ok(await ctx.request({ method: 'GET', path: url(ctx, 'getCart', { cartId }), headers: session }), 'reread cart')
  const items = current.json<Cart>().items ?? []
  const largest = items.slice().sort((a, b) => Number(b.unit) * Number(b.qty) - Number(a.unit) * Number(a.qty))[0]
  if (!largest?.id) throw new Error('cart has no removable line')
  ok(await ctx.request({
    method: 'DELETE',
    path: url(ctx, 'deleteCartItem', { cartId, itemId: String(largest.id) }),
    headers: session,
  }), 'remove cart line')
  ok(await ctx.request({ method: 'POST', path: url(ctx, 'checkoutCart', { cartId }), headers: session, body: {} }), 'checkout')
}
