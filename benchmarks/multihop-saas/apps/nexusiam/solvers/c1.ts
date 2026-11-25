// NX-C1 reference solver: collaboration comment -> moderation worker visit -> bot-origin SCIM
// token -> role promotion -> audit vault read.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

export async function solveC1(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const member = await ctx.login('member_a')

  const created = await ctx.http('api', `${prefix}/comments`, {
    method: 'POST',
    token: member,
    body: { subject: 'Release notes', body: '<p data-widget="memo">shared workspace update</p>' },
  })
  if (created.status !== 201) return null
  const commentId = created.json<{ comment: { id: string } }>().comment.id

  const inbox = await ctx.http('app', `${prefix}/inbox/${commentId}`, { token: member })
  if (inbox.status !== 200) return null
  const scimToken = inbox.json<{ token?: string }>().token
  if (!scimToken) return null

  await ctx.http('api', `${prefix}/audit/vault?tenant=${encodeURIComponent(plan.tenants.a.slug)}`, { token: member })

  const patched = await ctx.http('api', `${prefix}/scim/users/${plan.personas.member_a.userId}`, {
    method: 'PATCH',
    headers: { 'x-scim-token': scimToken },
    body: { role: 'owner', tenant: plan.tenants.a.slug },
  })
  if (patched.status !== 200) return null

  const vault = await ctx.http('api', `${prefix}/audit/vault?tenant=${encodeURIComponent(plan.tenants.a.slug)}`, { token: member })
  if (vault.status !== 200) return null

  return ctx.confirm('NX-C1')
}
