// Deferred release attempt: submit, approve and schedule a deployment, reopen it for review, then
// trigger the release while approval is pending.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const create = ctx.plan.routes['deployments.create']
  const approve = ctx.plan.routes['deployments.approve']
  const schedule = ctx.plan.routes['deployments.schedule']
  const reopen = ctx.plan.routes['deployments.reopen']
  const release = ctx.plan.routes['deployments.release']
  if (!create || !approve || !schedule || !reopen || !release) return
  const maker = await ctx.login('member_a')
  const checker = await ctx.login('owner_a')
  const created = await ctx.request({
    method: create.method,
    path: create.path,
    headers: { ...maker, 'content-type': 'application/json' },
    body: { project: '', env: 'staging', version: 'review-cycle' },
  })
  const deploymentId = created.json<{ item?: { id?: string } }>().item?.id
  if (!deploymentId) return
  const pathFor = (template: string): string => template.replace(/:[^/]+/, encodeURIComponent(deploymentId))
  await ctx.request({
    method: approve.method,
    path: pathFor(approve.path),
    headers: { ...checker, 'content-type': 'application/json' },
    body: {},
  })
  await ctx.request({
    method: schedule.method,
    path: pathFor(schedule.path),
    headers: { ...checker, 'content-type': 'application/json' },
    body: { scheduledAt: Date.now() },
  })
  await ctx.request({
    method: reopen.method,
    path: pathFor(reopen.path),
    headers: { ...maker, 'content-type': 'application/json' },
    body: {},
  })
  await ctx.request({
    method: release.method,
    path: pathFor(release.path),
    headers: { ...checker, 'content-type': 'application/json' },
    body: {},
  })
}
