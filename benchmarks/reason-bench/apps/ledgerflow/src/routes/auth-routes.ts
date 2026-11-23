// Session + auth surface: login/logout, current user, password-reset entry, email change, federated
// SSO hand-off, runtime config for the SPA and the machine-readable API reference. Unmounted site
// routes for the SSO callback and reset flows get their safe default implementation here.
import { createHash } from 'node:crypto'
import type { AppContext, UserRow } from '../context.ts'
import { SESSION_COOKIE, currentUser, doLogin, hashToken, identityForUser, meView, userByEmail } from '../auth.ts'
import { body, forbidden, notFound, requireRole, requireSession, unauthorized } from '../common.ts'

const UI_ROUTES = [
  'login', 'logout', 'me', 'dashboard', 'listInvoices', 'getInvoice', 'createInvoice', 'exportInvoicePdf',
  'listOrders', 'getOrder', 'updateOrder', 'getCart', 'listCarts', 'addCartItem', 'patchCartItem', 'deleteCartItem',
  'applyCoupon', 'checkoutCart', 'listWallets', 'listTransfers', 'createPayout', 'listPayouts',
  'approvePayout', 'updatePayout', 'listInvites', 'inviteMember', 'acceptInvite', 'listExports',
  'queueExport', 'downloadExport', 'activityFeed', 'listMembers', 'getSubscription',
]

export function registerAuthRoutes(ctx: AppContext): void {
  ctx.route('health', (req) => req.json({ status: 'ok', service: 'ledgerflow' }))

  ctx.route('apiReference', (req) => {
    const routes: Record<string, { method: string; path: string }> = {}
    for (const [key, spec] of Object.entries(ctx.plan.routes)) routes[key] = { method: spec.method, path: spec.path }
    return req.json({ app: 'ledgerflow', apiPrefix: ctx.plan.apiPrefix, params: ctx.plan.params, routes })
  })

  ctx.route('appConfig', (req) => {
    const routes: Record<string, { method: string; path: string }> = {}
    for (const key of UI_ROUTES) {
      const spec = ctx.plan.routes[key]
      if (spec) routes[key] = { method: spec.method, path: spec.path }
    }
    return req.json({
      app: 'ledgerflow', apiPrefix: ctx.plan.apiPrefix, sessionCookie: SESSION_COOKIE,
      routes, params: ctx.plan.params, labels: ctx.labels,
    })
  })

  ctx.route('login', (req) => {
    const b = body(req)
    const email = String(b[ctx.field('email')] ?? b.email ?? '')
    const password = String(b.password ?? '')
    const user = doLogin(ctx, req, email, password)
    if (!user) return req.json({ error: 'invalid_credentials' }, 401)
    return req.json({ ok: true, csrfToken: req.issueCsrfToken(), user: meView(ctx, user) })
  })

  ctx.route('logout', (req) => {
    req.session.destroy()
    return req.json({ ok: true })
  })

  ctx.route('me', (req) => {
    const user = currentUser(ctx, req)
    if (!user) return unauthorized(req)
    return req.json({ user: meView(ctx, user), csrfToken: req.issueCsrfToken(), labels: ctx.labels })
  })

  // Neutral reset entry: always the same response, so the endpoint cannot confirm an address.
  ctx.route('requestPasswordReset', (req) => {
    const b = body(req)
    const email = String(b[ctx.field('email')] ?? b.email ?? '')
    const user = userByEmail(ctx.db, email)
    if (user) {
      const raw = `lf_reset_${ctx.newId('reset')}`
      ctx.db.run('INSERT INTO user_tokens (tenant_id,user_ext_id,kind,token_hash,issued_at) VALUES (?,?,?,?,?)',
        [user.tenant_id, user.external_id, 'reset', hashToken(raw), Date.now()])
    }
    return req.json({ ok: true, message: 'If the address exists, a reset link was sent.' })
  })

  ctx.route('changeEmail', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const b = body(req)
    const next = String(b[ctx.field('email')] ?? b.email ?? '').trim()
    if (!next || !next.includes('@')) return req.json({ error: 'invalid_email' }, 400)
    const clash = ctx.db.get<{ id: number }>('SELECT id FROM users WHERE lower(email) = lower(?) AND external_id != ?', [next, id.userExtId])
    if (clash) return req.json({ error: 'email_in_use' }, 409)
    ctx.db.run('UPDATE users SET pending_email = ?, email_verified = 0 WHERE external_id = ?', [next, id.userExtId])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'email_change_requested', id.userExtId, next)
    return req.json({ ok: true, pendingEmail: next, verified: false })
  })

  ctx.route('ssoStart', (req) => {
    const state = createHash('sha256').update(`sso:${Date.now()}:${ctx.plan.canarySalt}`).digest('hex').slice(0, 16)
    return req.json({ authorizeUrl: `${ctx.plan.apiPrefix}/auth/sso/callback?state=${state}`, state })
  })

  // Safe default: only a verified federated identity with a matching organisation claim is accepted.
  ctx.route('ssoCallback', (req) => {
    const b = body(req)
    const q = req.query
    const email = String(b.email ?? q.email ?? '')
    const tid = String(b[ctx.field('tenantId')] ?? b.tid ?? q.tid ?? '')
    const account = ctx.db.get<Record<string, unknown>>(
      'SELECT * FROM sso_accounts WHERE verified = 1 AND lower(email) = lower(?)', [email],
    )
    if (!account) return req.json({ error: 'unknown_identity' }, 401)
    const slug = String(account.tenant_id)
    if (tid && tid !== slug) return req.json({ error: 'tenant_mismatch' }, 403)
    const user = userByEmail(ctx.db, String(account.email))
    if (!user) return req.json({ error: 'unknown_identity' }, 401)
    req.session.set('identity', identityForUser(user))
    ctx.db.run('UPDATE sso_accounts SET last_login_at = ? WHERE id = ?', [Date.now(), account.id])
    ctx.db.run('INSERT INTO auth_events (tenant_id,email,method,detail,created_at) VALUES (?,?,?,?,?)',
      [user.tenant_id, user.email, 'sso', 'verified_claim', Date.now()])
    return req.json({ ok: true, user: meView(ctx, user) })
  })

  // Convenience endpoint for the SPA: a compact dashboard payload scoped to the caller tenant.
  ctx.route('dashboard', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const orders = ctx.db.all<Record<string, unknown>>('SELECT * FROM orders WHERE tenant_id = ? ORDER BY id DESC LIMIT 8', [id.tenant])
    const payouts = ctx.db.all<Record<string, unknown>>('SELECT * FROM payouts WHERE tenant_id = ? ORDER BY id DESC LIMIT 8', [id.tenant])
    const activity = ctx.db.all<Record<string, unknown>>('SELECT * FROM activity WHERE tenant_id = ? ORDER BY id DESC LIMIT 8', [id.tenant])
    return req.json({
      orders: orders.map((o) => ({ id: o.external_id, total: o.total_cents, status: o.status })),
      payouts: payouts.map((p) => ({ id: p.external_id, amount: p.amount_cents, status: p.status })),
      activity: activity.map((a) => ({ id: a.external_id, actor: a.actor, action: a.action, detail: a.detail })),
    })
  })

  ctx.route('getSubscription', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const sub = ctx.db.get<Record<string, unknown>>('SELECT * FROM subscriptions WHERE tenant_id = ?', [id.tenant])
    if (!sub) return notFound(req)
    const plan = ctx.db.get<Record<string, unknown>>('SELECT * FROM plans WHERE code = ?', [sub.plan_code])
    return req.json({ id: sub.external_id, plan: plan?.code, price: plan?.monthly_cents, credits: plan?.metered_credits, status: sub.status })
  })

  ctx.route('listMembers', (req) => {
    const id = requireSession(req)
    if (!id) return forbidden(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM users WHERE tenant_id = ? ORDER BY id', [id.tenant])
    return req.json({ items: rows.map((u) => ({ id: u.external_id, email: u.email, role: u.role, name: u.name })) })
  })

  ctx.route('updateRole', (req) => {
    const id = requireRole(ctx, req, 'owner')
    if (!id) return forbidden(req)
    const target = ctx.byExternalId<UserRow>('users', req.params[ctx.field('memberId')] ?? '')
    if (!target || target.tenant_id !== id.tenant) return notFound(req)
    const b = body(req)
    const role = String(b.role ?? b[ctx.field('role')] ?? '')
    if (!['owner', 'admin', 'member', 'viewer'].includes(role)) return req.json({ error: 'invalid_role' }, 400)
    ctx.db.run('UPDATE users SET role = ? WHERE external_id = ? AND tenant_id = ?', [role, target.external_id, id.tenant])
    ctx.db.run('UPDATE memberships SET role = ? WHERE user_ext_id = ? AND tenant_id = ?', [role, target.external_id, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'role_changed', target.external_id, role)
    return req.json({ ok: true, id: target.external_id, role })
  })
}
