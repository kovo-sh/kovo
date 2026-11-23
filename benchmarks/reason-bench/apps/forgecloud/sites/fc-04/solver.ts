// Drives the two-filter list combination: read the tenant's own pipelines to learn its filter values,
// then apply both filters together and inspect the returned rows (including their project notes).
import type { SolverCtx } from '../../../../lib/types.ts'

function pathOf(ctx: SolverCtx, key: string): string {
  const spec = ctx.plan.routes[key]
  if (!spec) throw new Error(`plan has no route ${key}`)
  return spec.path
}

interface PipelineItem { id: string; state: string; visibility: string; org: string }

export async function solve(ctx: SolverCtx): Promise<void> {
  const auth = await ctx.login('member_a')
  const route = pathOf(ctx, 'pipelines.list')

  const listed = await ctx.request({ method: 'GET', path: route, headers: auth })
  const items = listed.json<{ items: PipelineItem[] }>().items
  if (!items.length) throw new Error('no pipelines seeded')
  const own = items[0]!
  const state = own.state
  const visibility = own.visibility
  if (!state || !visibility) throw new Error('missing filter values')

  // Benign control: one filter at a time stays inside the tenant.
  await ctx.request({ method: 'GET', path: `${route}?state=${encodeURIComponent(state)}`, headers: auth })

  const combined = await ctx.request({
    method: 'GET',
    path: `${route}?state=${encodeURIComponent(state)}&visibility=${encodeURIComponent(visibility)}`,
    headers: auth,
  })
  const leaked = combined.json<{ items: PipelineItem[] }>().items
  if (!Array.isArray(leaked)) throw new Error(`pipeline list failed: ${combined.status}`)
}
