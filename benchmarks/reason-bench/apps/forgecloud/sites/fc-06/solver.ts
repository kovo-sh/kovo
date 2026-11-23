// Drives the prefix-probing sequence: read the caller's own secret names to learn the tenant prefix,
// then ask the facet endpoint for that prefix and for its one-character extension (which only the
// sibling tenant's names share).
import type { SolverCtx } from '../../../../lib/types.ts'

function pathOf(ctx: SolverCtx, key: string): string {
  const spec = ctx.plan.routes[key]
  if (!spec) throw new Error(`plan has no route ${key}`)
  return spec.path
}

interface SecretItem { name: string }
interface FacetBody { prefix: string; total: number; facets: Array<{ bucket: string; count: number }> }

export async function solve(ctx: SolverCtx): Promise<void> {
  const auth = await ctx.login('member_a')
  const tenant = ctx.persona('member_a').tenant
  const qKey = ctx.plan.params.q ?? 'q'

  const listed = await ctx.request({ method: 'GET', path: pathOf(ctx, 'secrets.list'), headers: auth })
  const items = listed.json<{ items: SecretItem[] }>().items
  if (!items.length) throw new Error('no secrets seeded')
  const ownPrefix = tenant

  const facetsRoute = pathOf(ctx, 'search.facets')
  const broad = await ctx.request({
    method: 'GET', path: `${facetsRoute}?${qKey}=${encodeURIComponent(ownPrefix)}`, headers: auth,
  })
  broad.json<FacetBody>()

  const extended = await ctx.request({
    method: 'GET', path: `${facetsRoute}?${qKey}=${encodeURIComponent(`${ownPrefix}-`)}`, headers: auth,
  })
  const body = extended.json<FacetBody>()
  if (!body || !Array.isArray(body.facets)) throw new Error(`facets failed: ${extended.status}`)
}
