// Actor resolution for every request: cookie session first (set at login), then a bearer API token
// looked up in the tokens table. The resolved tenant can be widened by an active staff session that
// is acting on behalf of another store.
import type { Db } from '../../../lib/db.ts'
import type { ResolveActor } from '../../../lib/http.ts'
import type { Actor, VariantPlan } from '../../../lib/types.ts'

const SESSION_COOKIE = 'rb_sid'

export function makeResolveActor(plan: VariantPlan, db: Db): ResolveActor {
  const tenantByToken = new Map<string, { actor: Actor; tenant: string }>()
  const refresh = (): void => {
    tenantByToken.clear()
    const rows = db.all<{ token: string; store_id: string }>('SELECT token, store_id FROM api_tokens')
    for (const row of rows) tenantByToken.set(row.token, { actor: 'persona_a', tenant: row.store_id })
  }

  return (req, helpers) => {
    const sid = helpers.cookies[SESSION_COOKIE]
    const session = helpers.getSession(sid)
    if (session && typeof session === 'object') {
      const data = (session as { data?: Record<string, unknown> }).data ?? {}
      const persona = data.persona
      if (typeof persona === 'string') {
        const actAs = typeof data.actAsStore === 'string' ? data.actAsStore : undefined
        const home = plan.personas[persona as keyof typeof plan.personas]
        const tenant = actAs ?? home?.tenant ?? null
        return { actor: persona as Actor, tenant, sessionId: sid ?? null }
      }
    }
    const auth = helpers.header('authorization')
    if (auth && /^bearer\s+/i.test(auth)) {
      const token = auth.replace(/^bearer\s+/i, '').trim()
      if (!tenantByToken.has(token)) refresh()
      const hit = tenantByToken.get(token)
      if (hit) return { actor: hit.actor, tenant: hit.tenant, sessionId: null }
    }
    return { actor: 'anonymous', tenant: null, sessionId: sid ?? null }
  }
}
