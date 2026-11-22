// Legacy v1 identity endpoint. Resolves the caller from a signed bearer assertion and echoes back the
// subject, team and role claims. Assertions must carry a valid HS256 signature; unsigned tokens are
// rejected even for older agents.
import type { AppContext, ReqCtx } from '../../src/context.ts'

const SIGNING_SECRET = 'rb_fake_v1_assertion_secret'

export default function register(app: AppContext): void {
  const tokenP = app.p('token')
  app.route('apiWhoami', (ctx: ReqCtx) => {
    const header = ctx.headers['authorization'] ?? ''
    const token = /^Bearer\s+/i.test(header)
      ? header.replace(/^Bearer\s+/i, '').trim()
      : String(ctx.query[tokenP] ?? '')
    if (!token) return ctx.json({ error: 'token_required' }, 401)
    const result = app.jwtVerify(token, SIGNING_SECRET, ['HS256'], false)
    if (!result.valid) return ctx.json({ error: 'invalid_token' }, 401)
    const claims = (result.payload ?? {}) as Record<string, unknown>
    return ctx.json({
      subject: String(claims.sub ?? ''),
      team: String(claims.team ?? ''),
      role: String(claims.role ?? ''),
    })
  })
}
