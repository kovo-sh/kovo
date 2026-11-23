// Profile walkthrough: a teammate asks to move their profile onto a colleague's address, starts the
// federated hand-off for the profile address, and returns through the callback.
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
  const session = await ctx.login('member_a')
  const address = ctx.persona('owner_a').email
  const emailKey = ctx.plan.params.email ?? 'email'
  await ctx.request({
    method: 'POST',
    path: url(ctx, 'changeEmail'),
    headers: session,
    body: { [emailKey]: address, email: address },
  })
  const started = ok(await ctx.request({ method: 'GET', path: url(ctx, 'ssoStart'), headers: session }), 'start hand-off')
  const handoff = started.json<{ state?: string; email?: string }>()
  const state = String(handoff.state ?? '')
  const claimed = String(handoff.email ?? address)
  const query = new URLSearchParams({ state, [emailKey]: claimed, email: claimed }).toString()
  await ctx.request({
    method: 'GET',
    path: `${url(ctx, 'ssoCallback')}?${query}`,
    headers: session,
  })
}
