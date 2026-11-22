// Role management endpoint. Promotes or demotes a member to one of the portal roles. Guarded by an
// authenticated session, a CSRF token, the staged self-service rollout flag and the caller's grant.
import type { AppContext, ReqCtx } from '../../src/context.ts'

const ROLES = new Set(['viewer', 'member', 'manager', 'owner', 'admin'])
const GRANTERS = new Set(['owner', 'admin'])

export default function register(app: AppContext): void {
  const roleP = app.p('role')

  app.route('roleChange', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    if (!ctx.csrfValid) { ctx.setCsrfRejected(); return ctx.json({ error: 'csrf_required' }, 403) }

    const gate = app.get<{ value: string }>(
      'SELECT value FROM feature_flags WHERE flag_key = ? AND team_id = ?', ['self_service_roles', ctx.tenant])
    if (gate && gate.value !== 'on') return ctx.json({ error: 'feature_disabled' }, 403)

    const grant = String(ctx.session.get('role') ?? '')
    if (!GRANTERS.has(grant)) return ctx.json({ error: 'forbidden' }, 403)

    const role = String((ctx.body as Record<string, unknown>)[roleP] ?? '')
    if (!ROLES.has(role)) return ctx.json({ error: 'invalid_role' }, 400)

    const target = String(ctx.session.get('userId') ?? '')
    app.run('UPDATE users SET role = ? WHERE ext_id = ?', [role, target])
    return ctx.json({ ok: true, role })
  }, { encoding: 'json' })
}
