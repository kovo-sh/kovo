// Onboarding walkthrough: an administrator issues an onboarding ticket, the pending invite is then
// taken down to read-only, and the recipient redeems the original ticket.
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
  const admin = await ctx.login('owner_a')
  ok(await ctx.request({ method: 'GET', path: url(ctx, 'listInvites'), headers: admin }), 'list invites')
  const email = `rb_fake_${ctx.plan.canarySalt.slice(0, 8)}@invite.test`
  const issued = ok(await ctx.request({
    method: 'POST',
    path: url(ctx, 'inviteMember'),
    headers: admin,
    body: { [ctx.plan.params.email ?? 'email']: email, role: 'admin' },
  }), 'issue invite').json<{ id?: unknown; token?: unknown }>()
  const inviteId = String(issued.id ?? '')
  const token = String(issued.token ?? '')
  if (!inviteId || !token) throw new Error('invite ticket missing')
  ok(await ctx.request({
    method: 'PATCH',
    path: url(ctx, 'downgradeInvite', { inviteId }),
    headers: admin,
    body: { role: 'viewer' },
  }), 'downgrade invite')
  const recipient = await ctx.login('viewer_a')
  await ctx.request({
    method: 'POST',
    path: url(ctx, 'acceptInvite'),
    headers: recipient,
    body: { [ctx.plan.params.token ?? 'token']: token },
  })
}
