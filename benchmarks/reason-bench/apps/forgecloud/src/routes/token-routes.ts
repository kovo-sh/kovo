// Personal access token lifecycle. Tokens are signed credentials persisted by hash; revocation writes
// both the row timestamp and the explicit revocation table the request resolver consults.
import type { AppContext } from '../context.ts'
import {
  currentUser, currentUserExt, orgOf, unauthorized, forbidden, notFound, requirePerm, asRecord, str, audit,
} from '../common.ts'

export function registerTokenRoutes(ctx: AppContext): void {
  ctx.route('tokens.list', (req) => {
    const org = orgOf(req)
    const user = currentUser(ctx, req)
    if (!org || !user) return unauthorized(req)
    const admin = ctx.can(user.external_id, org, 'token:revoke')
    const rows = admin
      ? ctx.db.all<Record<string, unknown>>('SELECT * FROM tokens WHERE org_slug = ? ORDER BY id', [org])
      : ctx.db.all<Record<string, unknown>>('SELECT * FROM tokens WHERE org_slug = ? AND user_ext_id = ? ORDER BY id',
        [org, user.external_id])
    return req.json({
      items: rows.map((r) => ({
        id: r.external_id, name: r.name, scopes: String(r.scopes).split(','), envScope: r.env_scope,
        revoked: r.revoked_at !== null, createdAt: r.created_at, expiresAt: r.expires_at,
      })),
    })
  })

  ctx.route('tokens.create', (req) => {
    const denied = requirePerm(ctx, req, 'token:create')
    if (denied) return denied
    const org = orgOf(req)!
    const body = asRecord(req.body)
    const name = str(body[ctx.field('name')] ?? body.name) || 'cli-token'
    const scopes = Array.isArray(body.scopes) ? body.scopes.map(String) : ['read']
    const envScope = str(body.envScope) || 'dev'
    const issued = ctx.issuePat({ userExt: currentUserExt(ctx, req), org, name, scopes, envScope })
    audit(ctx, req, 'token.create', issued.row.external_id, `${name} [${envScope}]`)
    return req.json({
      item: { id: issued.row.external_id, name, scopes, envScope },
      token: issued.token,
    }, 201)
  })

  ctx.route('tokens.revoke', (req) => {
    const org = orgOf(req)
    const user = currentUser(ctx, req)
    if (!org || !user) return unauthorized(req)
    const ext = req.params[ctx.field('tokenId')] ?? ''
    const row = ctx.byExternalId<Record<string, unknown>>('tokens', ext)
    if (!row || row.org_slug !== org) return notFound(req)
    const owns = row.user_ext_id === user.external_id
    if (!owns && !ctx.can(user.external_id, org, 'token:revoke')) return forbidden(req)
    const now = Date.now()
    ctx.db.run('UPDATE tokens SET revoked_at = ? WHERE external_id = ? AND org_slug = ?', [now, ext, org])
    ctx.db.run('INSERT INTO token_revocations (org_slug,token_ext_id,reason,revoked_at) VALUES (?,?,?,?)',
      [org, ext, 'manual', now])
    audit(ctx, req, 'token.revoke', ext)
    return req.json({ ok: true, revoked: ext })
  })
}
