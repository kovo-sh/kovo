// Checkout return handler. After the payment provider bounces the shopper back, send them on to the
// requested continuation URL, but only when it points at our own checkout domain.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

const TRUSTED_PREFIX = 'https://pay.shopflow.test'

export default function register(app: AppContext): void {
  app.route('checkoutReturn', (ctx: ReqCtx) => {
    const target = String(ctx.query[app.paramName('returnUrl')] ?? '/')
    const allowed = (target.startsWith('/') && !target.startsWith('//')) || target.startsWith(TRUSTED_PREFIX)
    if (!allowed) return ctx.redirect('/')
    return ctx.redirect(target)
  })
}
