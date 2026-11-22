// Integration connector probe. Performs a server-side fetch of the connector endpoint supplied by the
// operator so the console can show whether the remote service is reachable.
import type { AppContext, ReqCtx } from '../../src/context.ts'

function urlField(body: Record<string, unknown>, name: string): string {
  return String(body[name] ?? body.url ?? body.endpoint ?? body.callbackUrl ?? '')
}

export default function register(app: AppContext): void {
  const urlP = app.p('webhookUrl')
  app.route('integrationFetch', async (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const url = urlField((ctx.body ?? {}) as Record<string, unknown>, urlP)
    if (!/^https?:\/\/\S+$/.test(url)) return ctx.json({ error: 'invalid_url' }, 400)
    let status = 0
    try { status = (await app.egress.fetch(url, { inputDerived: true })).status } catch { /* unreachable endpoint */ }
    return ctx.json({ ok: true, reachable: status > 0 })
  }, { encoding: 'json' })
}
