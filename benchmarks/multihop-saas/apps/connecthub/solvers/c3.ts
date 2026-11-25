// CH-C3 reference runner: case hop-by-hop actor header -> split refund -> ledger break.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC3(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const session = await ctx.login('revoked_or_demoted')

  const created = await ctx.http('portal', `${prefix}/cases`, {
    method: 'POST', token: session,
    headers: { 'x-internal-actor': 'billing.finance' },
    body: { subject: 'Partner billing discrepancy' },
  })
  if (created.status !== 201) return null
  const caseId = created.json<{ caseId?: string }>().caseId
  if (!caseId) return null

  await ctx.http('billing.internal', '/refunds/settle', {
    method: 'POST',
    headers: { 'x-service-token': ctx.serviceToken },
    body: { caseId },
  })

  const forwarded = await ctx.http('portal', `${prefix}/cases/${caseId}/forward`, {
    method: 'POST', token: session,
    headers: { 'x-internal-actor': 'billing.finance' },
    body: { note: 'please review the partner statement' },
  })
  if (forwarded.status !== 201) return null

  const settled = await ctx.http('billing.internal', '/refunds/settle', {
    method: 'POST',
    headers: { 'x-service-token': ctx.serviceToken },
    body: { caseId },
  })
  if (settled.status !== 200) return null
  if (!settled.json<{ conservationViolated: boolean }>().conservationViolated) return null

  return ctx.confirm('CH-C3')
}
