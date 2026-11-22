// Log viewer: streams the contents of a named log file from the operations log directory.
import type { AppContext, ReqCtx } from '../../src/context.ts'

export default function register(app: AppContext): void {
  const nameP = app.p('logName')

  app.route('logView', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'auth_required' }, 401)
    const name = String(ctx.query[nameP] ?? '')
    if (!name.endsWith('.log')) return ctx.json({ error: 'unsupported_file' }, 400)

    const content = app.vfs.readWithin(app.logRoot, name)
    if (content === null) return ctx.json({ error: 'not_found' }, 404)
    return ctx.text(content)
  })
}
