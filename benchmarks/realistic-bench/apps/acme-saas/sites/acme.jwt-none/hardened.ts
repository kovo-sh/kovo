// API token refresh. Verifies the presented refresh token and, on success, rebinds the caller
// session and mints a fresh access token for the token subject.
import type { AppContext } from '../../src/context.ts'
import { userByEmail, identityForUser } from '../../src/auth.ts'

export default function register(app: AppContext): void {
  app.route('refreshToken', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const token = String(body[app.field('token')] ?? body.token ?? '')
    const res = app.wiring.verifyToken(token, false)
    if (!res.valid) return req.json({ error: 'invalid_token' }, 401)
    const sub = (res.payload as { sub?: string } | undefined)?.sub ?? ''
    const u = sub ? userByEmail(app.db, sub) : undefined
    if (u) req.session.set('identity', identityForUser(u, false))
    return req.json({ ok: true, access: app.wiring.signToken({ sub, iat: Date.now() }) })
  })
}
