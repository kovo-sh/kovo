// Drives the export-link sequence: list an own artifact, mint a link for a sibling tenant's export
// path that shares this tenant's slug prefix, then fetch the link and read the resolved object.
import type { SolverCtx } from '../../../../lib/types.ts'

function pathOf(ctx: SolverCtx, key: string): string {
  const spec = ctx.plan.routes[key]
  if (!spec) throw new Error(`plan has no route ${key}`)
  return spec.path
}

function withParam(path: string, name: string, value: string): string {
  const filled = path.replace(new RegExp(`:${name}(?=/|$)`), encodeURIComponent(value))
  return filled === path ? path.replace(/:[^/]+$/, encodeURIComponent(value)) : filled
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const auth = await ctx.login('owner_a')
  const json = { ...auth, 'content-type': 'application/json' }

  const listed = await ctx.request({ method: 'GET', path: pathOf(ctx, 'artifacts.list'), headers: auth })
  const items = listed.json<{ items: Array<{ id: string; name: string }> }>().items
  if (!items.length) throw new Error('no artifacts seeded')
  const artifact = items[0]!

  const foreignOrg = ctx.persona('member_b').tenant
  const crafted = `/exports/${foreignOrg}/${artifact.name}`
  const minted = await ctx.request({
    method: 'POST',
    path: withParam(pathOf(ctx, 'artifacts.mint'), ctx.plan.params.artifactId ?? 'artifactId', artifact.id),
    headers: json,
    body: { path: crafted },
  })
  const link = minted.json<{ link: { token: string; path: string } }>().link
  if (!link || !link.token) throw new Error(`mint failed: ${minted.status}`)

  await ctx.request({ method: 'GET', path: link.path, headers: auth })

  await ctx.request({ method: 'GET', path: pathOf(ctx, 'artifacts.list'), headers: auth })
}
