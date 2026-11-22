// SSO callback. After the identity provider hand-off the user is returned to the page they came
// from, carried through the callback as a return target.
import type { AppContext } from '../../src/context.ts'

export default function register(app: AppContext): void {
  app.route('ssoCallback', (req) => {
    const next = String(req.query[app.field('url')] ?? '')
    // Same-site absolute path only: reject protocol-relative, backslash-normalised and scheme-like
    // targets (browsers treat `\` as `/`, so `/\host` is an off-origin redirect).
    const safe = next.startsWith('/') && !next.startsWith('//') && !/[\\\s:]/.test(next)
    return req.redirect(safe ? next : `${app.plan.apiPrefix}/me`, 302)
  })
}
