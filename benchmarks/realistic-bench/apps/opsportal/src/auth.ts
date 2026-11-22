// Authentication: email+password login over cookie sessions, a CSRF token helper for cookie-auth
// mutations, and a mapper that binds an incoming request to its acting persona + tenant. Bearer API
// tokens are recognised for the read-only API surface.
import type { Actor } from '../../../lib/types.ts'
import type { Db } from '../../../lib/db.ts'
import type { ResolveActor } from '../../../lib/http.ts'
import type { SessionRecord } from '../../../lib/http-session.ts'
import type { AppContext, ReqCtx } from './context.ts'
import { pget } from './common/sql.ts'

interface SessionData { persona?: Actor; tenant?: string; role?: string; userId?: string }

export function makeResolveActor(db: Db): ResolveActor {
  return (req, helpers) => {
    const sid = helpers.cookies['rb_sid'] ?? null
    const rec = helpers.getSession(sid) as SessionRecord | null
    const data = (rec?.data ?? {}) as SessionData
    if (data.persona) return { actor: data.persona, tenant: data.tenant ?? null, sessionId: sid }
    // bearer API token -> look up the owning user (read-only surface)
    const auth = helpers.header('authorization')
    if (auth && /^Bearer\s+/i.test(auth)) {
      const token = auth.replace(/^Bearer\s+/i, '').trim()
      const row = pget<{ persona: string; team_id: string }>(db,
        'SELECT u.persona AS persona, u.team_id AS team_id FROM api_tokens t JOIN users u ON u.ext_id = t.user_id WHERE t.ext_id = ?',
        [token],
      )
      if (row && row.persona !== 'none') return { actor: row.persona as Actor, tenant: row.team_id, sessionId: null }
    }
    return { actor: 'anonymous', tenant: null, sessionId: sid }
  }
}

export function registerAuthRoutes(app: AppContext): void {
  const db = app.db

  app.route('login', (ctx: ReqCtx) => {
    const body = (ctx.body ?? {}) as Record<string, unknown>
    const email = String(body.email ?? '')
    const password = String(body.password ?? '')
    const user = pget<{ persona: string; team_id: string; role: string; ext_id: string; password: string }>(db,
      'SELECT persona, team_id, role, ext_id, password FROM users WHERE email = ?', [email],
    )
    if (!user || user.password !== password) return ctx.json({ error: 'invalid_credentials' }, 401)
    ctx.session.set('persona', user.persona)
    ctx.session.set('tenant', user.team_id)
    ctx.session.set('role', user.role)
    ctx.session.set('userId', user.ext_id)
    return ctx.json({ ok: true, persona: user.persona, role: user.role, tenant: user.team_id })
  }, { encoding: 'json' })

  app.route('logout', (ctx: ReqCtx) => { ctx.session.destroy(); return ctx.json({ ok: true }) })

  app.route('me', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ authenticated: false }, 401)
    return ctx.json({ authenticated: true, persona: ctx.actor, tenant: ctx.tenant, role: ctx.session.get('role') ?? null })
  })

  app.route('csrf', (ctx: ReqCtx) => ctx.json({ csrf: ctx.issueCsrfToken() }))
}
