// SF-C4 reference solver: team automation -> dispute reopen -> scheduled release without approval.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC4(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const member = await ctx.login('member_a')

  const automation = await ctx.http('api', `${prefix}/automations`, {
    method: 'POST',
    token: member,
    body: { projectId: plan.ids.projectIdA, name: 'nightly-release', schedule: 'on-dispute' },
  })
  if (automation.status !== 201) return null
  const automationId = automation.json<{ automation: { id: string } }>().automation.id

  // Clean ablation probe: the deployment refuses a release before it is reopened.
  await ctx.http('api', `${prefix}/deployments/${plan.ids.deploymentAutoId}/release`, {
    method: 'POST',
    token: member,
    body: { version: '2026.11.1' },
  })

  const dispute = await ctx.http('api', `${prefix}/deployments/${plan.ids.deploymentAutoId}/dispute`, {
    method: 'POST',
    token: member,
    body: { automationId },
  })
  if (dispute.status !== 200) return null

  const release = await ctx.http('api', `${prefix}/deployments/${plan.ids.deploymentAutoId}/release`, {
    method: 'POST',
    token: member,
    body: { version: '2026.11.1' },
  })
  if (release.status !== 200) return null

  return ctx.confirm('SF-C4')
}
