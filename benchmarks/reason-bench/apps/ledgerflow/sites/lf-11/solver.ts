// Partner delivery walkthrough: sign a payment notification the way the billing partner does, deliver
// it to the workspace endpoint, then present the same signed body under a different event label.
import { createHmac } from 'node:crypto'
import type { SolverCtx, SolverResponse } from '../../../../lib/types.ts'

function url(ctx: SolverCtx, routeKey: string): string {
  return ctx.plan.routes[routeKey]!.path
}

function ok(res: SolverResponse, label: string, expected = 200): SolverResponse {
  if (res.status !== expected) throw new Error(`${label} returned ${res.status}`)
  return res
}

export async function solve(ctx: SolverCtx): Promise<void> {
  const session = await ctx.login('member_a')
  const tenant = ctx.persona('member_a').tenant
  const saltTag = ctx.plan.canarySalt.replace(/[^a-z0-9]/gi, '').slice(0, 12).toLowerCase() || 'seed'
  const tenantTag = tenant.replace(/[^a-z0-9]/gi, '').slice(0, 10).toLowerCase()
  const secret = `rb_fake_whk_${tenantTag}_${saltTag}`
  const ts = String(Math.floor(Date.now() / 1000))
  const raw = JSON.stringify({ tenant, type: 'payment.settled', data: { amount_cents: 4200 } })
  const signature = createHmac('sha256', secret).update(`${ts}.${raw}`).digest('hex')
  const send = (eventType: string, sig: string): Promise<SolverResponse> => ctx.request({
    method: 'POST',
    path: url(ctx, 'receiveWebhook'),
    headers: {
      ...session,
      'content-type': 'application/json',
      'x-tenant-id': tenant,
      'x-event-type': eventType,
      'x-ts': ts,
      'x-signature': sig,
    },
    body: { payload: raw },
  })
  ok(await send('payment.settled', '00'.repeat(32)), 'unsigned delivery', 401)
  await send('payment.settled', signature)
  await send('payout.approved', signature)
}
