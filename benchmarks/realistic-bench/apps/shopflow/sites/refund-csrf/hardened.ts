// Refund creation from the merchant console. Signed-in staff submit the refund form; the request must
// carry the session's form token and originate from the console before any refund is written.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function form(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  app.route('createRefund', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    if (!ctx.sameOrigin || !ctx.csrfValid) { ctx.setCsrfRejected(); return ctx.json({ error: 'csrf' }, 403) }
    const b = form(ctx)
    const amount = Number(b[app.paramName('bodyAmount')] ?? 0)
    const ext = app.ids.encode('refund', Math.floor(Math.random() * 1e6))
    app.db.run('INSERT INTO refunds (external_id, store_id, amount, status) VALUES (?, ?, ?, ?)', [
      ext, ctx.tenant, Math.max(0, amount), 'pending',
    ])
    return ctx.json({ id: ext, status: 'pending' }, 201)
  }, { encoding: 'form' })
}
