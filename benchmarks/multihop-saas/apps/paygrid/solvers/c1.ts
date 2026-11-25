// PG-C1 reference solver: directory profile -> NFKC invite resolution -> draft rebind -> self-approve.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC1(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const memberB = await ctx.login('member_b')
  const profile = await ctx.http('edge', `${prefix}/directory/orgs/${plan.tenants.a.slug}`, { token: memberB })
  if (profile.status !== 200) return null
  const pending = (profile.json<{ pendingEmail?: string }>().pendingEmail ?? '').trim()
  if (!pending) return null

  const resolved = await ctx.http('idp', '/invites/resolve', {
    method: 'POST',
    token: memberB,
    body: { email: pending.normalize('NFKC'), orgSlug: plan.tenants.a.slug, role: 'finance' },
  })
  if (resolved.status !== 200) return null
  const finance = resolved.json<{ token?: string }>().token
  if (!finance) return null

  const listed = await ctx.http('api', `${prefix}/payouts`, { token: finance })
  if (listed.status !== 200) return null
  const payout = listed.json<{ payouts: Array<{ id: string; status: string }> }>()
    .payouts.find((item) => item.status === 'draft')
  if (!payout) return null

  const memberA = await ctx.login('member_a')
  await ctx.http('api', `${prefix}/payouts/${payout.id}/approve`, { method: 'POST', token: memberA })

  const rebound = await ctx.http('api', `${prefix}/payouts/${payout.id}/rebind`, { method: 'PATCH', token: finance })
  if (rebound.status !== 200) return null

  const approved = await ctx.http('api', `${prefix}/payouts/${payout.id}/approve`, { method: 'POST', token: finance })
  if (approved.status !== 200) return null

  return ctx.confirm('PG-C1')
}
