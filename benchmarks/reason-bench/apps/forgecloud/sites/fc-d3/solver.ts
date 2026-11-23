// Revoked-credential log attempt: issue a personal token, revoke it, then present it to log access.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const create = ctx.plan.routes['tokens.create']
  const revoke = ctx.plan.routes['tokens.revoke']
  const logs = ctx.plan.routes['builds.logs']
  const builds = ctx.plan.routes['builds.list']
  if (!create || !revoke || !logs || !builds) return
  const headers = await ctx.login('member_a')
  const created = await ctx.request({
    method: create.method,
    path: create.path,
    headers: { ...headers, 'content-type': 'application/json' },
    body: { name: 'log-reader', scopes: ['build:read'], envScope: 'dev' },
  })
  const issued = created.json<{ item?: { id?: string }; token?: string }>()
  if (!issued.item?.id || !issued.token) return
  const revokePath = revoke.path.replace(/:[^/]+/, encodeURIComponent(issued.item.id))
  await ctx.request({ method: revoke.method, path: revokePath, headers })
  const list = await ctx.request({ method: builds.method, path: builds.path, headers })
  const buildId = list.json<{ items?: Array<{ id?: string }> }>().items?.[0]?.id
  if (!buildId) return
  const logPath = logs.path.replace(/:[^/]+/, encodeURIComponent(buildId))
  await ctx.request({
    method: logs.method,
    path: logPath,
    headers: { authorization: `Bearer ${issued.token}` },
  })
}
