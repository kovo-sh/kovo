// SSO callback. After the identity provider hand-off the user is returned to the page they came
// from, carried through the callback as a return target.
import type { AppContext } from '../../src/context.ts'

const TRUSTED_FRAGMENT = 'acme-saas'

export default function register(app: AppContext): void {
  app.route('ssoCallback', (req) => {
    const next = String(req.query[app.field('url')] ?? '')
    if (next && (next.startsWith('/') || next.includes(TRUSTED_FRAGMENT))) return req.redirect(next, 302)
    return req.redirect(`${app.plan.apiPrefix}/me`, 302)
  })
}
