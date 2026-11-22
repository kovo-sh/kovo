// Account settings. Updates the tenant's display name from the submitted settings form for the
// signed-in account once the request's form token is confirmed to match the session.
import type { AppContext } from '../../src/context.ts'
import { identity, unauthorized, forbidden } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('updateSettings', (req) => {
    const id = identity(req)
    if (!id) return unauthorized(req)
    if (!req.csrfValid) { req.setCsrfRejected(); return forbidden(req) }
    const body = (req.body ?? {}) as Record<string, unknown>
    const name = String(body.name ?? '')
    if (name) app.db.run('UPDATE tenants SET name = ? WHERE slug = ?', [name, id.tenant])
    return req.json({ ok: true })
  }, { encoding: 'form' })
}
