// Export boundary attempt: request a link for the sibling tenant that shares the caller's prefix.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const route = ctx.plan.routes['exports.list']
  if (!route) return
  const headers = await ctx.login('member_a')
  const sibling = ctx.plan.domain.tenants.orgB
  const target = `/exports/${sibling}/audit.json`
  await ctx.request({
    method: route.method,
    path: `${route.path}?path=${encodeURIComponent(target)}`,
    headers,
  })
}
