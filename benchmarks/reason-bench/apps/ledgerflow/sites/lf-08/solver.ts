// Export walkthrough: an administrator queues a ledger export, the owner later moves that teammate
// to a read-only role, and the same session then asks for the finished artifact.
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

function url(ctx: SolverCtx, routeKey: string, values: Record<string, string> = {}): string {
  const path = ctx.plan.routes[routeKey]!.path
  return path.replace(/:([A-Za-z0-9_]+)/g, (_, name: string) => {
    const logical = Object.keys(ctx.plan.params).find((key) => ctx.plan.params[key] === name)
    return encodeURIComponent((logical ? values[logical] : undefined) ?? values[name] ?? name)
  })
}

function ok(res: SolverResponse, label: string): SolverResponse {
  if (res.status < 200 || res.status >= 300) throw new Error(`${label} returned ${res.status}`)
  return res
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const teammate = await ctx.login('revoked_or_demoted')
  const profile = ok(await ctx.request({ method: 'GET', path: url(ctx, 'me'), headers: teammate }), 'read profile')
  const user = profile.json<{ user?: Record<string, unknown> }>().user ?? {}
  const memberId = String(user.id ?? '')
  const queued = ok(await ctx.request({
    method: 'POST', path: url(ctx, 'queueExport'), headers: teammate, body: { kind: 'ledger' },
  }), 'queue export')
  const exportId = String(queued.json<{ id?: string }>().id ?? '')
  const owner = await ctx.login('owner_a')
  ok(await ctx.request({
    method: 'PATCH',
    path: url(ctx, 'updateRole', { memberId }),
    headers: owner,
    body: { role: 'viewer' },
  }), 'change role')
  await ctx.request({ method: 'GET', path: url(ctx, 'downloadExport', { exportId }), headers: teammate })
}
