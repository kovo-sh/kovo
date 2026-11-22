// Identity & access: sessions (JWT), profile, organisation, admin feature flags.
import { tokenFromRequest, verifyJku, verifyLenient, verifyStrict } from './auth.mjs'
import { sendJson } from './http-util.mjs'
import { marker } from './markers.mjs'

const unauthorized = c => sendJson(c.res, 401, { error: 'invalid_token' }, { 'www-authenticate': 'Bearer realm="orbit"' })

export function register(router, ctx) {
  // hos-11: v1 session endpoint accepts unsigned tokens (alg:none / stripped signature).
  router.get('/api/v1/session', c => {
    const token = tokenFromRequest(c.req)
    const claims = ctx.fixed('hos-11') ? verifyStrict(token) : verifyLenient(token)
    if (!claims) return unauthorized(c)
    const body = { session: 'v1', sub: claims.sub, tenant: claims.tenant, role: claims.role, email: claims.email }
    if (claims.role === 'admin') body.adminBanner = marker('hos-11')
    sendJson(c.res, 200, body)
  })

  // hos-12: partner ledger trusts the `jku` header of the presented token.
  router.get('/api/v1/partner/ledger', async c => {
    const token = tokenFromRequest(c.req)
    const claims = ctx.fixed('hos-12') ? verifyStrict(token) : await verifyJku(token)
    if (!claims) return unauthorized(c)
    sendJson(c.res, 200, {
      tenant: claims.tenant,
      currency: 'USD',
      entries: [{ id: 'led_1', amount: 1200, memo: `Partner payout ${marker('hos-12')}` }],
    })
  })

  router.get('/api/v1/profile', c => {
    const user = c.requireUser()
    if (!user) return
    const stored = ctx.s.users.get(user.userId)
    if (!stored) return sendJson(c.res, 404, { error: 'not_found' })
    const body = { ...stored }
    if (stored.role === 'admin') body.adminConsoleToken = marker('hos-04')
    sendJson(c.res, 200, body)
  })

  // hos-04: mass assignment — every body key is copied onto the stored user record.
  router.patch('/api/v1/profile', async c => {
    const user = c.requireUser()
    if (!user) return
    const stored = ctx.s.users.get(user.userId)
    if (!stored) return sendJson(c.res, 404, { error: 'not_found' })
    const body = await c.json()
    if (ctx.fixed('hos-04')) {
      if (typeof body.displayName === 'string') stored.displayName = body.displayName.slice(0, 80)
      if (typeof body.marketingOptIn === 'boolean') stored.marketingOptIn = body.marketingOptIn
    } else {
      for (const [key, value] of Object.entries(body)) {
        if (key !== 'id') stored[key] = value
      }
    }
    const out = { ...stored }
    if (stored.role === 'admin') out.adminConsoleToken = marker('hos-04')
    sendJson(c.res, 200, out)
  })

  router.get('/api/v1/org', c => {
    const user = c.requireUser()
    if (!user) return
    const tenant = ctx.s.tenants.get(user.tenant)
    if (!tenant) return sendJson(c.res, 404, { error: 'not_found' })
    sendJson(c.res, 200, tenant)
  })

  router.get('/api/v1/admin/feature-flags', c => {
    const user = c.requireUser()
    if (!user) return
    if (user.role !== 'admin') return sendJson(c.res, 403, { error: 'admin_required' })
    sendJson(c.res, 200, { flags: ctx.s.flags })
  })

  // hos-03: BFLA — the mutating admin function never checks the caller's role.
  router.post('/api/v1/admin/feature-flags', async c => {
    const user = c.requireUser()
    if (!user) return
    if (ctx.fixed('hos-03') && user.role !== 'admin') return sendJson(c.res, 403, { error: 'admin_required' })
    const body = await c.json()
    const flag = String(body.flag ?? '')
    if (!/^[a-z0-9_]{1,40}$/.test(flag)) return sendJson(c.res, 400, { error: 'invalid_flag' })
    ctx.s.flags[flag] = Boolean(body.enabled)
    sendJson(c.res, 200, { ok: true, flags: ctx.s.flags, auditRef: marker('hos-03') })
  })
}
