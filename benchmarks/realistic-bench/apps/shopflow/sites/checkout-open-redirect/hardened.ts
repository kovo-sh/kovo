// Checkout return handler. After the payment provider bounces the shopper back, send them on to the
// requested continuation URL, but only when it points at our own checkout domain.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

const TRUSTED_HOSTS = new Set(['pay.shopflow.test'])

export default function register(app: AppContext): void {
  app.route('checkoutReturn', (ctx: ReqCtx) => {
    const target = String(ctx.query[app.paramName('returnUrl')] ?? '/')
    if (target.startsWith('/') && !target.startsWith('//')) return ctx.redirect(target)
    let host = ''
    try { host = new URL(target).host } catch { host = '' }
    if (!TRUSTED_HOSTS.has(host)) return ctx.redirect('/')
    return ctx.redirect(target)
  })
}
