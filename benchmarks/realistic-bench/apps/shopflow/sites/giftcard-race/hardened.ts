// Gift-card redemption. The deduction is a single conditional statement that only succeeds while the
// balance still covers the amount, so concurrent redemptions cannot both settle against one balance.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function amountOf(app: AppContext, ctx: ReqCtx): number {
  const b = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
  return Number(b[app.paramName('bodyAmount')] ?? 0)
}

export default function register(app: AppContext): void {
  app.route('redeemGiftCard', async (ctx) => {
    const card = app.findByExternalId('gift_cards', String(ctx.params[app.paramName('giftCardId')] ?? ''))
    if (!card || card.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const amount = amountOf(app, ctx)
    if (amount <= 0) return ctx.json({ error: 'insufficient_balance' }, 409)
    // Settlement is handled on the provider side; yield while it acknowledges.
    await new Promise((resolve) => setTimeout(resolve, 20))
    const res = app.db.run('UPDATE gift_cards SET balance = balance - ? WHERE id = ? AND balance >= ?', [amount, card.id, amount])
    if (res.changes !== 1) return ctx.json({ error: 'insufficient_balance' }, 409)
    const after = app.db.get<{ balance: number }>('SELECT balance FROM gift_cards WHERE id = ?', [card.id])!
    return ctx.json({ ok: true, redeemed: amount, remaining: Number(after.balance) })
  })
}
