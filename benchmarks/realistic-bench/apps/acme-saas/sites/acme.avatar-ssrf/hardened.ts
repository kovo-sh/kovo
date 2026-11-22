// Avatar import. Fetches the supplied image URL so the avatar can be mirrored locally, after
// rejecting loopback / link-local / internal hosts, then records it on the member profile.
import type { AppContext } from '../../src/context.ts'
import { tenantOf, unauthorized } from '../../src/common.ts'

function isInternalHost(host: string): boolean {
  const h = host.toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === 'metadata'
    || h.startsWith('169.254.') || h.startsWith('10.') || h.startsWith('192.168.') || h.endsWith('.internal')
}

export default function register(app: AppContext): void {
  app.route('updateAvatar', async (req) => {
    const tenant = tenantOf(req)
    if (!tenant) return unauthorized(req)
    const ext = req.params[app.field('memberId')] ?? ''
    const body = (req.body ?? {}) as Record<string, unknown>
    const url = String(body[app.field('avatarUrl')] ?? body.avatarUrl ?? '')
    if (!/^https?:\/\/\S+$/.test(url)) return req.json({ error: 'invalid_url' }, 400)
    let host = ''
    try { host = new URL(url).hostname } catch { return req.json({ error: 'invalid_url' }, 400) }
    if (isInternalHost(host)) return req.json({ error: 'url_not_allowed' }, 400)
    try { await app.egress.fetch(url, { inputDerived: true }) } catch { /* unreachable source ignored */ }
    app.db.run('UPDATE users SET avatar_url = ? WHERE external_id = ? AND tenant_id = ?', [url, ext, tenant])
    return req.json({ ok: true })
  })
}
