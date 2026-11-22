// Legacy v1 login. Retained for the original desktop client: accounts on the historical internal
// domain are routed through the directory, everyone else uses a password login.
import type { AppContext } from '../../src/context.ts'
import { doLogin, meView } from '../../src/auth.ts'

const LEGACY_DOMAIN = '.test'

export default function register(app: AppContext): void {
  app.route('legacyLogin', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const email = String(body[app.field('email')] ?? body.email ?? '')
    const legacy = email.toLowerCase().endsWith(LEGACY_DOMAIN)
    if (legacy) {
      const u = doLogin(app, req, email, String(body.password ?? ''))
      if (!u) return req.json({ error: 'invalid_credentials' }, 401)
      return req.json({ ok: true, user: meView(app, u) })
    }
    const authed = doLogin(app, req, email, String(body.password ?? ''))
    if (!authed) return req.json({ error: 'invalid_credentials' }, 401)
    return req.json({ ok: true, user: meView(app, authed) })
  })
}
