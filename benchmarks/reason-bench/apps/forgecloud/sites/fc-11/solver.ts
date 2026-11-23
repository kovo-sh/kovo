// Two-step runner-credential attempt: read the environment preview for a pipeline run, then present
// the preview credential to promotion with a production target.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const builds = ctx.plan.routes['builds.list']
  const graphql = ctx.plan.routes.graphql
  const create = ctx.plan.routes['deployments.create']
  const promote = ctx.plan.routes['deployments.promote']
  if (!builds || !graphql || !create || !promote) return
  const headers = await ctx.login('member_a')
  const list = await ctx.request({ method: builds.method, path: builds.path, headers })
  const runs = list.json<{ items?: Array<{ id?: string; project?: string }> }>().items ?? []
  const run = runs.find((item) => item.id) ?? runs[0]
  if (!run?.id) return
  const query = `query { ciRun(id: "${run.id}") { id state envPreview { env token } } }`
  const diagnostics = await ctx.request({
    method: graphql.method,
    path: graphql.path,
    headers: { ...headers, 'content-type': 'application/json' },
    body: { query },
  })
  const preview = diagnostics.json<{
    data?: { ciRun?: { envPreview?: { token?: string } } }
  }>().data?.ciRun?.envPreview
  const runnerToken = preview?.token
  if (!runnerToken) return
  const created = await ctx.request({
    method: create.method,
    path: create.path,
    headers: { ...headers, 'content-type': 'application/json' },
    body: { project: run.project, env: 'staging', version: 'preview' },
  })
  const deploymentId = created.json<{ item?: { id?: string } }>().item?.id
  if (!deploymentId) return
  const path = promote.path.replace(/:[^/]+/, encodeURIComponent(deploymentId))
  await ctx.request({
    method: promote.method,
    path,
    headers: { ...headers, 'content-type': 'application/json' },
    body: { targetEnv: 'prod', runnerToken },
  })
}
