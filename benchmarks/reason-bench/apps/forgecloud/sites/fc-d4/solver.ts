// Cache priming attempt: read settings in the organization where the caller is an admin, then read
// settings in the organization where the caller is only a viewer.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const route = ctx.plan.routes['org.settings']
  if (!route) return
  const headers = await ctx.login('dual_member')
  const adminOrg = ctx.plan.domain.tenants.orgA
  const viewerOrg = ctx.plan.domain.tenants.orgB
  const adminPath = route.path.replace(/:[^/]+/, encodeURIComponent(adminOrg))
  await ctx.request({
    method: route.method,
    path: adminPath,
    headers: { ...headers, 'x-org-id': adminOrg },
  })
  const viewerPath = route.path.replace(/:[^/]+/, encodeURIComponent(viewerOrg))
  await ctx.request({
    method: route.method,
    path: viewerPath,
    headers: { ...headers, 'x-org-id': viewerOrg },
  })
}
