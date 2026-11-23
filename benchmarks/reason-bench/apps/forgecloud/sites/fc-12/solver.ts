// Empty selection attempt: a member of the second organization asks for the current workspace with
// an explicitly empty selection header.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const route = ctx.plan.routes['workspaces.current']
  if (!route) return
  const headers = await ctx.login('member_b')
  await ctx.request({
    method: route.method,
    path: route.path,
    headers: { ...headers, 'x-workspace-id': '' },
  })
}
