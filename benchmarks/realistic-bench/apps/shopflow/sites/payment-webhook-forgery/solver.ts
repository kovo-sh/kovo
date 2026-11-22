// Post a payment-captured webhook signed with the public shared test secret for a store we do not own.
import { createHmac } from 'node:crypto'
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

const SHARED_SECRET = 'whsec_test_shared'

export async function solve(ctx: SolverCtx): Promise<void> {
  const store = ctx.plan.personas.persona_a.tenant
  const ts = String(Math.floor(Date.now() / 1000))
  const payload = { store, type: 'payment.captured', order: 'manual', amount: 3400 }
  const canon = `${payload.store}|${payload.type}|${payload.order}|${payload.amount}`
  const sig = createHmac('sha256', SHARED_SECRET).update(`${ts}.${canon}`).digest('hex')
  await ctx.fetch(buildPath(ctx.plan, 'paymentWebhook'), {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-webhook-signature': sig, 'x-webhook-timestamp': ts },
    body: JSON.stringify({ ...payload, ts }),
  })
}
