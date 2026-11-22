// Product catalog feed import. The parser runs with entity expansion disabled, so declared external
// entities are left unresolved while reading the feed.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('importProductFeed', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const raw = String((ctx.body as { raw?: string } | undefined)?.raw ?? '')
    const doc = app.parseFeed(raw, false)
    const items = doc.children.filter((c) => c.tag !== '')
    return ctx.json({ imported: items.length, root: doc.tag })
  }, { encoding: 'xml' })
}
