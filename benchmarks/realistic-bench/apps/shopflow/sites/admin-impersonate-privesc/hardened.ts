// Staff impersonation. Only platform staff may act on behalf of a store; a merchant session is
// rejected before the acting-store is pinned onto the session.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function body(ctx: ReqCtx): Record<string, unknown> {
  return ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
}

export default function register(app: AppContext): void {
  app.route('adminImpersonate', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    if (app.personaFor(ctx.actor)?.role !== 'admin') return ctx.json({ error: 'forbidden' }, 403)
    const store = String(body(ctx).store ?? '')
    if (store) ctx.session.set('actAsStore', store)
    return ctx.json({ ok: true, actingAs: store })
  })
}
