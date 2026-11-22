// SSO return handler. After the identity provider hands control back, send the operator on to the
// page they were heading to. Relative return targets are honoured; everything else falls back to the
// dashboard.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const nextP = app.p('nextUrl')
  app.route('ssoCallback', (ctx: ReqCtx) => {
    const next = String(ctx.query[nextP] ?? '')
    const target = next.startsWith('/') ? next : '/dashboard'
    return ctx.redirect(target)
  })
}
