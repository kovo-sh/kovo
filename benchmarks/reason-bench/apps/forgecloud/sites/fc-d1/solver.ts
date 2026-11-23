// Bulk secret ownership attempt: combine one own-organization row with one foreign row.
import type { SolverCtx } from '../../../../lib/types.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const list = ctx.plan.routes['secrets.list']
  const update = ctx.plan.routes['secrets.update']
  if (!list || !update) return
  const ownHeaders = await ctx.login('member_a')
  const foreignHeaders = await ctx.login('member_b')
  const own = await ctx.request({ method: list.method, path: list.path, headers: ownHeaders })
  const foreign = await ctx.request({ method: list.method, path: list.path, headers: foreignHeaders })
  const ownId = own.json<{ items?: Array<{ id?: string }> }>().items?.[0]?.id
  const foreignId = foreign.json<{ items?: Array<{ id?: string }> }>().items?.[0]?.id
  if (!ownId || !foreignId) return
  const path = update.path.replace(/:[^/]+$/, encodeURIComponent(ownId))
  await ctx.request({
    method: update.method,
    path,
    headers: { ...ownHeaders, 'content-type': 'application/json' },
    body: { ids: [ownId, foreignId], name: `${ownId}-renamed` },
  })
}
