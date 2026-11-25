// NX-C2 reference solver: identity subpath redirect -> shared-link code capture -> pending invite
// listing -> stale invitation redemption.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC2(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const member = await ctx.login('member_b')
  const nextPath = `/s/${plan.nexus.shareLinkId}`
  const authorize = await ctx.http('idp',
    `/authorize?client_id=nexus-desktop&redirect_uri=${encodeURIComponent(`${ctx.lab.origins.app}/s/${plan.nexus.shareLinkId}`)}` +
      `&next=${encodeURIComponent(nextPath)}&state=share-preview`,
    { token: member },
  )
  if (authorize.status !== 200) return null
  const code = authorize.json<{ code?: string }>().code
  if (!code) return null

  const captured = await ctx.http('app', `${nextPath}?code=${encodeURIComponent(code)}&state=share-preview`, { token: member })
  if (captured.status !== 200) return null

  const listed = await ctx.http('idp', `/invites?tenant=${encodeURIComponent(plan.tenants.a.slug)}`, {
    token: member,
    headers: { 'x-derived-from': ctx.digest(code) },
  })
  if (listed.status !== 200) return null
  const invite = listed.json<{ invites: Array<{ role: string; token?: string }> }>()
    .invites.find((item) => item.role === 'admin' && item.token)
  if (!invite?.token) return null

  const redeemed = await ctx.http('idp', '/invites/redeem', {
    method: 'POST',
    token: member,
    body: { token: invite.token },
  })
  if (redeemed.status !== 200) return null

  return ctx.confirm('NX-C2')
}
