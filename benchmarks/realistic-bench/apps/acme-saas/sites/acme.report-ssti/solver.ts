// Stored report layout evaluated at render time: save a report whose layout embeds an arithmetic
// placeholder, then request its render endpoint so the stored layout is expanded.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const created = await ctx.fetch(ctx.path('createReport'), {
    method: 'POST',
    session: owner,
    body: { name: 'Quarterly', template: '{{ 6 * 7 }} / {{ settings.apiKey }}' },
  })
  const id = String(created.json?.id ?? '')
  if (!id) return
  await ctx.fetch(ctx.path('renderReport', { reportId: id }), { session: owner })
}
