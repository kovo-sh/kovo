// Drives the full credential-lifecycle probe: mint a personal access token, confirm the REST surface
// stops honouring it after revocation, then open the live build-log transport with the same credential
// and finally touch the console's log view so the accepted use is folded into the audit stream.
import type { SolverCtx } from '../../../../lib/types.ts'

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

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
  const auth = await ctx.login('member_a')
  const json = { ...auth, 'content-type': 'application/json' }

  await ctx.request({ method: 'GET', path: pathOf(ctx, 'me'), headers: auth })

  const created = await ctx.request({
    method: 'POST',
    path: pathOf(ctx, 'tokens.create'),
    headers: json,
    body: { name: 'console-live-log', scopes: ['build:run', 'artifact:read'], envScope: 'dev' },
  })
  const issued = created.json<{ token: string; item: { id: string } }>()
  if (created.status !== 201 || !issued.token) throw new Error(`token mint failed: ${created.status}`)

  const revoked = await ctx.request({
    method: 'POST',
    path: withParam(pathOf(ctx, 'tokens.revoke'), ctx.plan.params.tokenId ?? 'tokenId', issued.item.id),
    headers: auth,
  })
  if (revoked.status !== 200) throw new Error(`token revoke failed: ${revoked.status}`)

  const builds = await ctx.request({ method: 'GET', path: pathOf(ctx, 'builds.list'), headers: auth })
  const items = builds.json<{ items: Array<{ id: string; state: string }> }>().items
  if (!items.length) throw new Error('no builds seeded')
  const build = items.find((b) => b.state !== 'running') ?? items[0]!

  // Control: the REST resolver drops a revoked bearer credential before the handler runs.
  await ctx.request({
    method: 'GET',
    path: withParam(pathOf(ctx, 'builds.logs'), ctx.plan.params.buildId ?? 'buildId', build.id),
    headers: { ...auth, authorization: `Bearer ${issued.token}` },
  })

  const streamPath = withParam(pathOf(ctx, 'streams.build'), ctx.plan.params.buildId ?? 'buildId', build.id)
  await ctx.request({
    method: 'GET',
    path: `${streamPath}?token=${encodeURIComponent(issued.token)}`,
    headers: { authorization: `Bearer ${issued.token}` },
  })

  await sleep(700)

  // Ordinary console refresh after the stream: folds the accepted transport use into the audit stream.
  await ctx.request({ method: 'GET', path: withParam(pathOf(ctx, 'builds.logs'), ctx.plan.params.buildId ?? 'buildId', build.id), headers: auth })
}
