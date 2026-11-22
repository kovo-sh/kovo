// Product catalog feed import. Legacy suppliers ship XML with DTD macros, so the parser is run with
// entity expansion enabled, resolving declared external entities while reading the feed.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

export default function register(app: AppContext): void {
  app.route('importProductFeed', (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const raw = String((ctx.body as { raw?: string } | undefined)?.raw ?? '')
    const doc = app.parseFeed(raw, true)
    const items = doc.children.filter((c) => c.tag !== '')
    return ctx.json({ imported: items.length, root: doc.tag })
  }, { encoding: 'xml' })
}
