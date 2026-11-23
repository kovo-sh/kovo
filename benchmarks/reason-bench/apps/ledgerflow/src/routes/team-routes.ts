// Team area: invite lifecycle, membership changes and the tenant activity feed. The safe default for
// invite acceptance always reads the current invite row (role + state + email) and never trusts
// claims embedded in the token, so a downgrade between issuance and redemption is honoured.
import type { AppContext, InviteRow, UserRow } from '../context.ts'
import { hashPassword } from '../seed.ts'
import { body, forbidden, inviteView, notFound, param, requireRole, requireSession, unauthorized } from '../common.ts'

export function registerTeamRoutes(ctx: AppContext): void {
  ctx.route('listInvites', (req) => {
    const id = requireRole(ctx, req, 'member')
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM invites WHERE tenant_id = ? ORDER BY id DESC', [id.tenant])
    return req.json({ items: rows.map(inviteView) })
  })

  ctx.route('inviteMember', (req) => {
    const id = requireRole(ctx, req, 'admin')
    if (!id) return forbidden(req)
    const b = body(req)
    const email = String(b[ctx.field('email')] ?? b.email ?? '').trim().toLowerCase()
    const role = String(b.role ?? 'member')
    if (!email.includes('@')) return req.json({ error: 'invalid_email' }, 400)
    if (!['admin', 'member', 'viewer'].includes(role)) return req.json({ error: 'invalid_role' }, 400)
    const exists = ctx.db.get<{ id: number }>('SELECT id FROM users WHERE tenant_id = ? AND lower(email) = ?', [id.tenant, email])
    if (exists) return req.json({ error: 'already_member' }, 409)
    const ext = ctx.newId('invite')
    const token = ctx.token.sign({ invite: ext, tenant: id.tenant, role, sub: email, iat: Date.now() })
    ctx.db.run('INSERT INTO invites (external_id,tenant_id,email,role,state,token,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [ext, id.tenant, email, role, 'pending', token, id.userExtId, Date.now()])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'invite_sent', ext, role)
    return req.json({ id: ext, token, role }, 201)
  })

  // Safe default: downgrading updates the authoritative row; the token is intentionally left intact.
  ctx.route('downgradeInvite', (req) => {
    const id = requireRole(ctx, req, 'admin')
    if (!id) return forbidden(req)
    const invite = ctx.db.get<InviteRow>('SELECT * FROM invites WHERE external_id = ? AND tenant_id = ?', [param(req, ctx, 'inviteId'), id.tenant])
    if (!invite) return notFound(req)
    const b = body(req)
    const role = String(b.role ?? 'viewer')
    const state = String(b.state ?? invite.state)
    if (!['admin', 'member', 'viewer'].includes(role) || !['pending', 'revoked'].includes(state)) return req.json({ error: 'invalid_transition' }, 400)
    ctx.db.run('UPDATE invites SET role = ?, state = ? WHERE external_id = ? AND tenant_id = ?', [role, state, invite.external_id, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'invite_updated', invite.external_id, `${role}:${state}`)
    return req.json({ ok: true, role, state })
  })

  ctx.route('acceptInvite', (req) => {
    const b = body(req)
    const token = String(b[ctx.field('token')] ?? b.token ?? '')
    const verified = ctx.token.verify(token, false)
    if (!verified.valid) return req.json({ error: 'invalid_invite' }, 401)
    const claim = (verified.payload ?? {}) as Record<string, unknown>
    const invite = ctx.db.get<InviteRow>('SELECT * FROM invites WHERE token = ?', [token])
    if (!invite || invite.state !== 'pending') return req.json({ error: 'invite_not_pending' }, 409)
    if (String(claim.tenant ?? '') !== invite.tenant_id || String(claim.invite ?? '') !== invite.external_id) return req.json({ error: 'invalid_invite' }, 401)
    const existing = ctx.db.get<UserRow>('SELECT * FROM users WHERE tenant_id = ? AND lower(email) = lower(?)', [invite.tenant_id, invite.email])
    if (existing) {
      ctx.db.run("UPDATE invites SET state = 'accepted' WHERE external_id = ?", [invite.external_id])
      return req.json({ ok: true, userId: existing.external_id, role: existing.role })
    }
    const password = String(b.password ?? `rb_fake_invite_${ctx.plan.canarySalt.slice(0, 8)}`)
    const userExt = ctx.ids.encode('user', Date.now() % 100000)
    ctx.db.run(
      'INSERT INTO users (external_id,tenant_id,email,password_hash,role,persona,name,status,email_verified,pending_email,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [userExt, invite.tenant_id, invite.email, hashPassword(password, ctx.plan.canarySalt), invite.role, null,
        invite.email.split('@')[0] ?? 'Invited member', 'active', 1, '', Date.now()],
    )
    ctx.db.run('INSERT INTO memberships (user_ext_id,tenant_id,role) VALUES (?,?,?)', [userExt, invite.tenant_id, invite.role])
    ctx.db.run("UPDATE invites SET state = 'accepted' WHERE external_id = ?", [invite.external_id])
    ctx.recordActivity(invite.tenant_id, invite.email, 'invite_accepted', invite.external_id, invite.role)
    return req.json({ ok: true, userId: userExt, role: invite.role })
  })

  ctx.route('activityFeed', (req) => {
    const id = requireSession(req)
    if (!id) return unauthorized(req)
    const rows = ctx.db.all<Record<string, unknown>>('SELECT * FROM activity WHERE tenant_id = ? ORDER BY id DESC LIMIT 100', [id.tenant])
    return req.json({
      items: rows.map((a) => ({ id: a.external_id, actor: a.actor, action: a.action, subject: a.subject, detail: a.detail, at: a.created_at })),
    })
  })

  ctx.route('removeMember', (req) => {
    const id = requireRole(ctx, req, 'owner')
    if (!id) return forbidden(req)
    const target = ctx.byExternalId<UserRow>('users', req.params[ctx.field('memberId')] ?? '')
    if (!target || target.tenant_id !== id.tenant) return notFound(req)
    if (target.role === 'owner') return forbidden(req)
    ctx.db.run('DELETE FROM memberships WHERE user_ext_id = ? AND tenant_id = ?', [target.external_id, id.tenant])
    ctx.db.run('DELETE FROM users WHERE external_id = ? AND tenant_id = ?', [target.external_id, id.tenant])
    ctx.recordActivity(id.tenant, id.persona ?? id.email, 'member_removed', target.external_id)
    return req.json({ ok: true })
  })
}
