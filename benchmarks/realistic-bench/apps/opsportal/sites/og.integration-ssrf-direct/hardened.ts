// Integration connector probe. Performs a server-side fetch of the connector endpoint supplied by the
// operator so the console can show whether the remote service is reachable, after confirming the
// endpoint resolves to an external host rather than internal infrastructure.
import type { AppContext, ReqCtx } from '../../src/context.ts'

function urlField(body: Record<string, unknown>, name: string): string {
  return String(body[name] ?? body.url ?? body.endpoint ?? body.callbackUrl ?? '')
}

function isInternalHost(host: string): boolean {
  const h = host.toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === 'metadata'
    || h.startsWith('127.') || h.startsWith('169.254.') || h.startsWith('10.')
    || h.startsWith('192.168.') || h.endsWith('.internal')
}

export default function register(app: AppContext): void {
  const urlP = app.p('webhookUrl')
  app.route('integrationFetch', async (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const url = urlField((ctx.body ?? {}) as Record<string, unknown>, urlP)
    if (!/^https?:\/\/\S+$/.test(url)) return ctx.json({ error: 'invalid_url' }, 400)
    let host = ''
    try { host = new URL(url).hostname } catch { return ctx.json({ error: 'invalid_url' }, 400) }
    if (isInternalHost(host)) return ctx.json({ error: 'endpoint_not_allowed' }, 400)
    let status = 0
    try { status = (await app.egress.fetch(url, { inputDerived: true })).status } catch { /* unreachable endpoint */ }
    return ctx.json({ ok: true, reachable: status > 0 })
  }, { encoding: 'json' })
}
