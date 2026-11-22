// Members area: member list/get/update/remove, invites, API keys and account settings. The avatar
// route is a planted site owned by its module. Safe defaults for the unmounted planted sites (role
// mass-assignment, invite workflow, API-key secret disclosure, settings CSRF) live here.
import type { AppContext } from '../context.ts'
import { identity, tenantOf, roleOf, ownRows, memberView, unauthorized, notFound, forbidden } from '../common.ts'

function maskSecret(secret: string): string {
  return secret.length <= 8 ? '****' : `${secret.slice(0, 6)}…${secret.slice(-2)}`
}

export function registerMemberRoutes(ctx: AppContext): void {
  ctx.route('listMembers', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    return req.json({ items: ownRows(ctx, tenant, 'users').map(memberView) })
  })

  ctx.route('getMember', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const row = ctx.byExternalId<Record<string, unknown>>('users', req.params[ctx.field('memberId')]!)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    return req.json(memberView(row))
  })

  // Safe default: only name/avatar are writable here; role changes need an owner and are ignored otherwise.
  ctx.route('updateMember', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[ctx.field('memberId')]!
    const row = ctx.byExternalId<Record<string, unknown>>('users', ext)
    if (!row || row.tenant_id !== tenant) return notFound(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    ctx.db.run('UPDATE users SET name = ?, avatar_url = ? WHERE external_id = ? AND tenant_id = ?',
      [String(body.name ?? row.name), String(body.avatar_url ?? row.avatar_url), ext, tenant])
    return req.json({ ok: true })
  })

  ctx.route('removeMember', (req) => {
    const tenant = tenantOf(req)
    if (!tenant || roleOf(ctx, req) !== 'owner') return forbidden(req)
    ctx.db.run('DELETE FROM users WHERE external_id = ? AND tenant_id = ? AND role != ?',
      [req.params[ctx.field('memberId')]!, tenant, 'owner'])
    return req.json({ ok: true })
  })

  ctx.route('inviteMember', (req) => {
    const id = identity(req)
    if (!id || (id.role !== 'owner' && id.role !== 'admin')) return forbidden(req)
    const body = (req.body ?? {}) as Record<string, unknown>
    const ext = ctx.ids.encode('invite', Date.now() % 100000)
    const token = `inv_${ctx.ids.encode('invite', (Date.now() + 7) % 100000)}`
    ctx.db.run('INSERT INTO invites (external_id,tenant_id,email,role,state,token) VALUES (?,?,?,?,?,?)',
      [ext, id.tenant, String(body[ctx.field('email')] ?? body.email ?? ''), 'member', 'pending', token])
    return req.json({ id: ext, token }, 201)
  })

  // Safe default: only pending invites transition, exactly once.
  ctx.route('acceptInvite', (req) => {
    const token = String((req.body as Record<string, unknown>)?.[ctx.field('token')] ?? '')
    const r = ctx.db.run("UPDATE invites SET state = 'accepted' WHERE token = ? AND state = 'pending'", [token])
    if (r.changes === 0) return req.json({ error: 'invite_not_pending' }, 409)
    return req.json({ ok: true })
  })

  // Safe default: secrets are masked for everyone; the full value is never returned in the list.
  ctx.route('listApiKeys', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const rows = ownRows<Record<string, unknown>>(ctx, tenant, 'api_keys')
    return req.json({ items: rows.map((k) => ({ id: k.external_id, name: k.name, secret: maskSecret(String(k.secret)), scopes: k.scopes })) })
  })

  ctx.route('createApiKey', (req) => {
    const id = identity(req)
    if (!id || id.role !== 'owner') return forbidden(req)
    const ext = ctx.ids.encode('apikey', Date.now() % 100000)
    const secret = `rb_fake_key_${ctx.ids.encode('apikey', (Date.now() + 3) % 100000)}`
    ctx.db.run('INSERT INTO api_keys (external_id,tenant_id,name,secret,scopes) VALUES (?,?,?,?,?)',
      [ext, id.tenant, String((req.body as Record<string, unknown>)?.name ?? 'key'), secret, 'read'])
    return req.json({ id: ext, secret }, 201)
  })

  ctx.route('revokeApiKey', (req) => {
    const tenant = tenantOf(req)
    if (!tenant || roleOf(ctx, req) !== 'owner') return forbidden(req)
    ctx.db.run('DELETE FROM api_keys WHERE external_id = ? AND tenant_id = ?', [req.params[ctx.field('keyId')]!, tenant])
    return req.json({ ok: true })
  })

  ctx.route('getSettings', (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const t = ctx.db.get<Record<string, unknown>>('SELECT * FROM tenants WHERE slug = ?', [tenant])
    return req.json({ name: t?.name, ssoDomain: t?.sso_domain, csrfToken: req.issueCsrfToken() })
  }, {})

  // Safe default: a valid CSRF token is required before any settings change is applied.
  ctx.route('updateSettings', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    if (!req.csrfValid) { req.setCsrfRejected(); return forbidden(req) }
    const body = (req.body ?? {}) as Record<string, unknown>
    ctx.db.run('UPDATE tenants SET name = ? WHERE slug = ?', [String(body.name ?? ''), id.tenant])
    return req.json({ ok: true })
  }, { encoding: 'form' })
}
