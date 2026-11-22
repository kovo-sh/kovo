// Refund creation from the merchant console. Signed-in staff submit the refund form; an optional
// form token is carried through for the legacy console and sanity-checked for length.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function form(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  app.route('createRefund', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const b = form(ctx)
    const presented = String(b.token ?? b._token ?? '')
    if (presented.length > 256) return ctx.json({ error: 'invalid_token' }, 400)
    const amount = Number(b[app.paramName('bodyAmount')] ?? 0)
    const ext = app.ids.encode('refund', Math.floor(Math.random() * 1e6))
    app.db.run('INSERT INTO refunds (external_id, store_id, amount, status) VALUES (?, ?, ?, ?)', [
      ext, ctx.tenant, Math.max(0, amount), 'pending',
    ])
    return ctx.json({ id: ext, status: 'pending' }, 201)
  }, { encoding: 'form' })
}
