// Session + auth surface: login, logout, current user, 2FA checkpoint, SSO/OAuth hand-off, a legacy
// login path, API-token refresh, the SPA runtime config and a health probe. Unmounted planted site
// routes (legacy login, SSO callback, token refresh) get their safe default implementation here.
import type { AppContext } from '../context.ts'
import { doLogin, meView, userByEmail, identityForUser, SESSION_COOKIE } from '../auth.ts'
import { identity, currentUser, unauthorized } from '../common.ts'

// Logical route keys the SPA actually uses (admin/legacy/internal keys are intentionally omitted).
const UI_ROUTES = [
  'login', 'logout', 'me', 'twofaVerify', 'listProjects', 'getProject', 'createProject', 'updateProject',
  'searchProjects', 'listInvoices', 'getInvoice', 'createInvoice', 'listFiles', 'getFile', 'downloadFile',
  'uploadFile', 'listMembers', 'updateMember', 'updateAvatar', 'inviteMember', 'listApiKeys', 'createApiKey',
  'listWebhooks', 'createWebhook', 'listReports', 'getReport', 'createReport', 'listNotifications',
  'markNotification', 'getBilling', 'getSettings', 'updateSettings', 'getIntegrationConfig',
]

export function registerAuthRoutes(ctx: AppContext): void {
  ctx.route('health', (req) => req.json({ status: 'ok', service: 'acme-saas' }))

  ctx.route('appConfig', (req) => {
    const api: Record<string, { method: string; path: string }> = {}
    for (const key of UI_ROUTES) {
      const r = ctx.plan.routes[key]
      if (r) api[key] = { method: r.method, path: r.path }
    }
    return req.json({ apiPrefix: ctx.plan.apiPrefix, sessionCookie: SESSION_COOKIE, routes: api })
  })

  ctx.route('login', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const email = String(body[ctx.field('email')] ?? body.email ?? '')
    const password = String(body.password ?? '')
    const u = doLogin(ctx, req, email, password)
    if (!u) return req.json({ error: 'invalid_credentials' }, 401)
    const csrf = req.issueCsrfToken()
    return req.json({ ok: true, csrfToken: csrf, user: meView(ctx, u) })
  })

  ctx.route('logout', (req) => { req.session.destroy(); return req.json({ ok: true }) })

  ctx.route('me', (req) => {
    const u = currentUser(ctx, req)
    if (!u) return unauthorized(req)
    return req.json({ user: meView(ctx, u), csrfToken: req.issueCsrfToken() })
  })

  ctx.route('twofaVerify', (req) => {
    const id = req.session.get('identity')
    if (!id) return unauthorized(req)
    const next = { ...(id as Record<string, unknown>), twofaPending: false }
    req.session.set('identity', next)
    return req.json({ ok: true })
  })

  ctx.route('ssoStart', (req) => {
    const state = Math.random().toString(16).slice(2)
    return req.json({ authorizeUrl: `${ctx.plan.apiPrefix}/auth/sso/callback?state=${state}`, state })
  })

  // Safe default for the SSO callback: only ever redirect to a fixed same-origin relative path.
  ctx.route('ssoCallback', (req) => req.redirect(`${ctx.plan.apiPrefix}/me`, 302))

  // Safe default for the legacy login: a password is always required; no credential-free hand-off.
  ctx.route('legacyLogin', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const email = String(body[ctx.field('email')] ?? body.email ?? '')
    const password = String(body.password ?? '')
    const u = doLogin(ctx, req, email, password)
    if (!u) return req.json({ error: 'invalid_credentials' }, 401)
    return req.json({ ok: true, user: meView(ctx, u) })
  })

  // Safe default for token refresh: accept only HS256-signed tokens, never alg:none.
  ctx.route('refreshToken', (req) => {
    const body = (req.body ?? {}) as Record<string, unknown>
    const token = String(body[ctx.field('token')] ?? body.token ?? '')
    const res = ctx.wiring.verifyToken(token, false)
    if (!res.valid) return req.json({ error: 'invalid_token' }, 401)
    const sub = (res.payload as { sub?: string } | undefined)?.sub ?? ''
    const u = sub ? userByEmail(ctx.db, sub) : undefined
    if (u) req.session.set('identity', identityForUser(u, false))
    return req.json({ ok: true, access: ctx.wiring.signToken({ sub, iat: Date.now() }) })
  })
}
