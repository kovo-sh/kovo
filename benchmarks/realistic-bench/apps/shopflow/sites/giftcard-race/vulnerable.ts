// Gift-card redemption. Reads the current balance, does availability math, then writes the deduction.
// The read and the write are separated by an async boundary with no row-level guard, so two
// redemptions in flight both pass the availability check against the same starting balance.
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
    const current = app.db.get<{ balance: number }>('SELECT balance FROM gift_cards WHERE id = ?', [card.id])!
    const balance = Number(current.balance)
    // Settlement is handled on the provider side; yield while it acknowledges.
    await new Promise((resolve) => setTimeout(resolve, 20))
    if (amount <= 0 || amount > balance) return ctx.json({ error: 'insufficient_balance', balance }, 409)
    app.db.run('UPDATE gift_cards SET balance = balance - ? WHERE id = ?', [amount, card.id])
    const after = app.db.get<{ balance: number }>('SELECT balance FROM gift_cards WHERE id = ?', [card.id])!
    return ctx.json({ ok: true, redeemed: amount, remaining: Number(after.balance) })
  })
}
