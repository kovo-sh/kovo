// Cross-organization relocation attempt: a dual member who is only a viewer in the source
// organization tries to move one of its projects into the organization where they are an admin.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const list = ctx.plan.routes['projects.list']
  const update = ctx.plan.routes['projects.update']
  if (!list || !update) return
  const source = ctx.plan.domain.tenants.orgB
  const destination = ctx.plan.domain.tenants.orgA
  const headers = { ...(await ctx.login('dual_member')), 'x-org-id': source }
  const projects = await ctx.request({ method: list.method, path: list.path, headers })
  const projectId = projects.json<{ items?: Array<{ id?: string }> }>().items?.[0]?.id
  if (!projectId) return
  const path = update.path.replace(/:[^/]+$/, encodeURIComponent(projectId))
  await ctx.request({
    method: update.method,
    path,
    headers: { ...headers, 'content-type': 'application/json' },
    body: { targetOrg: destination },
  })
}
