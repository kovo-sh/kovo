// Legacy export download. Hands the browser off to the prepared archive: a signed download URL when
// one is present, otherwise the originally requested target restricted to same-origin paths.
import type { AppContext } from '../../src/context.ts'

export default function register(app: AppContext): void {
  app.route('exportRedirect', (req) => {
    const sig = String(req.query.sig ?? '')
    const next = String(req.query[app.field('url')] ?? '')
    if (sig) return req.redirect(`${app.plan.apiPrefix}/download/ready?sig=${encodeURIComponent(sig)}`, 302)
    const safe = next.startsWith('/') && !next.startsWith('//') && !next.includes(':')
    return req.redirect(safe ? next : `${app.plan.apiPrefix}/me`, 302)
  })
}
