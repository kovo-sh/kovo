// Cross-tenant cache serving: warm the shared public-report cache as the owning tenant, then fetch
// the same link as a different tenant and receive the warmed body carrying the owner's figures.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const list = await ctx.fetch(ctx.path('listReports'), { session: owner })
  const items = (list.json?.items ?? []) as Array<{ id: string }>
  const target = items[0]
  if (!target) return
  await ctx.fetch(ctx.path('publicReport', { reportId: target.id }), { session: owner })
  const other = await ctx.login('persona_b')
  await ctx.fetch(ctx.path('publicReport', { reportId: target.id }), { session: other })
}
