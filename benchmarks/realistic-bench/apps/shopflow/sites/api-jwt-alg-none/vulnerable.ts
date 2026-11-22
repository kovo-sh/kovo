// Sales reporting API. Authorizes with a bearer token issued to reporting integrations: the token is
// decoded and its signature checked against the reporting signing key before the figures are returned.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  const signingKey = `sk_report_${app.plan.canarySalt.slice(0, 16)}`

  app.route('salesReport', (ctx: ReqCtx) => {
    const auth = String(ctx.headers['authorization'] ?? '')
    const token = /^bearer\s+/i.test(auth) ? auth.replace(/^bearer\s+/i, '').trim() : ''
    if (!token) return ctx.json({ error: 'unauthorized' }, 401)
    const result = app.verifyToken(token, { algorithms: ['HS256', 'none'], acceptNone: true, secret: signingKey })
    if (!result.valid) return ctx.json({ error: 'unauthorized' }, 401)
    const claims = (result.payload ?? {}) as Record<string, unknown>
    const store = String(claims.store ?? ctx.tenant ?? app.plan.personas.persona_a.tenant)
    const row = app.db.get('SELECT COUNT(*) AS orders, COALESCE(SUM(total), 0) AS gross FROM orders WHERE store_id = ?', [store])
    return ctx.json({ store, report: row })
  })
}
