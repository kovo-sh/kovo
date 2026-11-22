// Follow the checkout return with a continuation URL that looks like the trusted host but is foreign.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const field = ctx.plan.params['returnUrl'] ?? 'returnUrl'
  const target = 'https://pay.shopflow.test.attacker.example/collect'
  const path = `${buildPath(ctx.plan, 'checkoutReturn')}?${field}=${encodeURIComponent(target)}`
  await ctx.fetch(path, { method: 'GET' })
}
