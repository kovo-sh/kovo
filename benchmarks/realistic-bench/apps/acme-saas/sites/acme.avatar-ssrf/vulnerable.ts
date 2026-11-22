// Avatar import. Fetches the supplied image URL so the avatar can be mirrored locally, then records
// it on the member profile.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized } from '../../src/common.ts'

export default function register(app: AppContext): void {
  app.route('updateAvatar', async (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[app.field('memberId')] ?? ''
    const body = (req.body ?? {}) as Record<string, unknown>
    const url = String(body[app.field('avatarUrl')] ?? body.avatarUrl ?? '')
    if (!/^https?:\/\/\S+$/.test(url)) return req.json({ error: 'invalid_url' }, 400)
    try { await app.egress.fetch(url, { inputDerived: true }) } catch { /* unreachable source ignored */ }
    app.db.run('UPDATE users SET avatar_url = ? WHERE external_id = ? AND tenant_id = ?', [url, ext, tenant])
    return req.json({ ok: true })
  })
}
