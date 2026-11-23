// Invite redemption. The signed ticket is verified, matched to the stored invite and tenant, and the
// granted role is read from the current invite row so later changes take effect.
import type { AppContext } from '../../src/context.ts'
import { body, unauthorized } from '../../src/common.ts'
import { hashPassword } from '../../src/seed.ts'

export default function register(app: AppContext): void {
  app.route('acceptInvite', (req) => {
    const payload = body(req)
    const token = String(payload[app.field('token')] ?? payload.token ?? '')
    const verified = app.token.verify(token, false)
    if (!verified.valid) return req.json({ error: 'invalid_invite' }, 401)
    const claim = (verified.payload ?? {}) as Record<string, unknown>
    const invite = app.db.get<Record<string, unknown>>('SELECT * FROM invites WHERE token = ?', [token])
    if (!invite) return unauthorized(req)
    if (String(claim.invite ?? '') !== String(invite.external_id) || String(claim.tenant ?? '') !== String(invite.tenant_id)) {
      return unauthorized(req)
    }
    if (String(invite.state) !== 'pending') return req.json({ error: 'invite_not_pending' }, 409)
    const granted = String(invite.role)
    const existing = app.db.get<{ external_id: string; role: string }>(
      'SELECT external_id, role FROM users WHERE tenant_id = ? AND lower(email) = lower(?)', [invite.tenant_id, String(invite.email)])
    if (existing) {
      app.db.run("UPDATE invites SET state = 'accepted' WHERE external_id = ?", [invite.external_id])
      return req.json({ ok: true, userId: existing.external_id, role: existing.role })
    }
    const password = String(payload.password ?? `rb_fake_invite_${app.plan.canarySalt.slice(0, 8)}`)
    const userExt = app.ids.encode('user', Date.now() % 100000)
    app.db.run(
      'INSERT INTO users (external_id,tenant_id,email,password_hash,role,persona,name,status,email_verified,pending_email,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [userExt, invite.tenant_id, invite.email, hashPassword(password, app.plan.canarySalt), granted, null,
        String(invite.email).split('@')[0] ?? 'Invited member', 'active', 1, '', Date.now()],
    )
    app.db.run('INSERT INTO memberships (user_ext_id,tenant_id,role) VALUES (?,?,?)', [userExt, invite.tenant_id, granted])
    app.db.run("UPDATE invites SET state = 'accepted' WHERE external_id = ?", [invite.external_id])
    app.recordActivity(String(invite.tenant_id), String(invite.email), 'invite_accepted', String(invite.external_id), granted)
    return req.json({ ok: true, userId: userExt, role: granted })
  })
}
