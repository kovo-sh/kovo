// Prime a store product page while signed into one store, then read the same cached page as a
// different store so the first store's personalized content is served to the second.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface Product { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const list = await ctx.fetch(buildPath(ctx.plan, 'listProducts'), { method: 'GET' })
  const data = (await list.json().catch(() => ({}))) as { products?: Product[] }
  const product = data.products?.[0]
  if (!product) return
  const storeA = ctx.plan.personas.persona_a.tenant
  const path = buildPath(ctx.plan, 'storeProductPage', { storeId: storeA, productId: product.external_id })
  await ctx.fetch(path, { method: 'GET' })
  await ctx.login('persona_b')
  await ctx.fetch(path, { method: 'GET' })
}
