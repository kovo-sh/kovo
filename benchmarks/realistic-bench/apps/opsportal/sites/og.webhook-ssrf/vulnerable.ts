// Webhook targets: operators register a delivery URL and can fire a one-off test delivery to confirm
// the endpoint answers. Registration only rejects link-local/metadata hosts (the classic obvious
// case) and the test delivery loads the stored target and performs the server-side call.
import type { AppContext, ReqCtx } from '../../src/context.ts'

interface TargetRow { url: string }

function urlField(body: Record<string, unknown>, name: string): string {
  return String(body[name] ?? body.url ?? body.endpoint ?? body.callbackUrl ?? '')
}

function blockedAtRegistration(url: string): boolean {
  try {
    const h = new URL(url).hostname.toLowerCase()
    return h === 'metadata.google.internal' || h === 'metadata' || h.startsWith('169.254.')
  } catch { return true }
}

export default function register(app: AppContext): void {
  const urlP = app.p('webhookUrl')
  const idP = app.p('webhookId')

  app.route('webhookCreate', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const url = urlField(ctx.body as Record<string, unknown>, urlP)
    if (!/^https?:\/\/\S+$/.test(url) || blockedAtRegistration(url)) return ctx.json({ error: 'invalid_url' }, 400)
    const res = app.run('INSERT INTO webhook_targets(team_id, name, url) VALUES (?,?,?)',
      [ctx.tenant, 'Test target', url])
    const extId = app.extId('webhook', Number(res.lastInsertRowid))
    app.run('UPDATE webhook_targets SET ext_id = ? WHERE id = ?', [extId, res.lastInsertRowid])
    return ctx.json({ id: extId })
  }, { encoding: 'json' })

  app.route('webhookTest', async (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const wid = ctx.params[idP] ?? ''
    const row = app.get<TargetRow>('SELECT url FROM webhook_targets WHERE ext_id = ? AND team_id = ?',
      [wid, ctx.tenant])
    if (!row) return ctx.json({ error: 'not_found' }, 404)
    let status = 0
    try { status = (await app.egress.fetch(row.url, { inputDerived: true })).status } catch { /* endpoint down */ }
    return ctx.json({ ok: true, delivered: status > 0 })
  }, { encoding: 'json' })
}
