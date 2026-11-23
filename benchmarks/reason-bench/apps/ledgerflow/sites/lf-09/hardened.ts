// Profile email changes and the federated hand-off. The hand-off state carries only the verified
// address, the callback requires a confirmed profile and enforces the organisation claim.
import type { AppContext, UserRow } from '../../src/context.ts'
import { identityForUser, meView } from '../../src/auth.ts'
import { body, notFound, requireSession, unauthorized } from '../../src/common.ts'

function claimAddress(user: UserRow): string {
  return String(user.email)
}

export default function register(app: AppContext): void {
  app.route('changeEmail', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const next = String(body(req)[app.field('email')] ?? body(req).email ?? '').trim()
    if (!next.includes('@')) return req.json({ error: 'invalid_email' }, 400)
    const clash = app.db.get<{ id: number }>(
      'SELECT id FROM users WHERE (lower(email) = lower(?) OR lower(pending_email) = lower(?)) AND external_id != ?',
      [next, next, id.userExtId],
    )
    if (clash) return req.json({ error: 'email_in_use' }, 409)
    app.db.run('UPDATE users SET pending_email = ?, email_verified = 0 WHERE external_id = ?', [next, id.userExtId])
    app.recordActivity(id.tenant, id.persona ?? id.email, 'email_change_requested', id.userExtId, next)
    return req.json({ ok: true, pendingEmail: next, verified: false })
  })

  app.route('ssoStart', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const user = app.byExternalId<UserRow>('users', id.userExtId)
    if (!user) return notFound(req)
    const address = claimAddress(user)
    const state = app.token.sign({ sub: user.external_id, tenant: id.tenant, email: address, iat: Date.now() })
    return req.json({
      authorizeUrl: `${app.plan.apiPrefix}/auth/sso/callback?state=${state}&email=${encodeURIComponent(address)}`,
      state, email: address,
    })
  })

  app.route('ssoCallback', (req) => {
    const payload = body(req)
    const state = String(payload.state ?? req.query.state ?? '')
    const address = String(payload[app.field('email')] ?? payload.email ?? req.query.email ?? '')
    const checked = app.token.verify(state, false)
    if (!checked.valid) return req.json({ error: 'invalid_state' }, 401)
    const claim = (checked.payload ?? {}) as Record<string, unknown>
    if (String(claim.email ?? '').toLowerCase() !== address.toLowerCase()) return req.json({ error: 'address_mismatch' }, 401)
    const user = app.db.get<UserRow>(
      'SELECT * FROM users WHERE lower(email) = lower(?) AND email_verified = 1', [address],
    )
    if (!user) return req.json({ error: 'unknown_identity' }, 401)
    if (String(claim.tenant ?? '') !== user.tenant_id) return req.json({ error: 'tenant_mismatch' }, 403)
    req.session.destroy()
    req.session.set('identity', identityForUser(user))
    app.db.run('INSERT INTO auth_events (tenant_id,email,method,detail,created_at) VALUES (?,?,?,?,?)',
      [user.tenant_id, user.email, 'sso', 'verified', Date.now()])
    return req.json({ ok: true, user: meView(app, user) })
  })
}
