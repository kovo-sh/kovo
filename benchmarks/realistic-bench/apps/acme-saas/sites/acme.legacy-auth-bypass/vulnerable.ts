// Legacy v1 login. Retained for the original desktop client: accounts on the historical internal
// domain are handed off from the directory, everyone else falls back to a password login.
import type { AppContext } from '../../src/context.ts'
import { userByEmail, identityForUser, doLogin, meView } from '../../src/auth.ts'

const LEGACY_DOMAIN = '.test'

export default function register(app: AppContext): void {
  app.route('legacyLogin', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const email = String(body[app.field('email')] ?? body.email ?? '')
    const u = userByEmail(app.db, email)
    if (u && email.toLowerCase().endsWith(LEGACY_DOMAIN)) {
      req.session.set('identity', identityForUser(u, false))
      return req.json({ ok: true, user: meView(app, u) })
    }
    const authed = doLogin(app, req, email, String(body.password ?? ''))
    if (!authed) return req.json({ error: 'invalid_credentials' }, 401)
    return req.json({ ok: true, user: meView(app, authed) })
  })
}
