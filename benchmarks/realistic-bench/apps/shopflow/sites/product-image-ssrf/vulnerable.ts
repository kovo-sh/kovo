// Product image import. Mirrors a supplier-hosted image into the catalog by fetching the URL the
// merchant supplies. Known cloud metadata hostnames are rejected up front; everything else is fetched
// server-side, following any redirects the origin returns.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'

function blockedHost(host: string): boolean {
  const h = host.toLowerCase()
  return h === 'metadata' || h === 'metadata.google.internal' || h.startsWith('169.254.')
}

async function fetchImage(app: AppContext, url: string): Promise<boolean> {
  let host = ''
  try { host = new URL(url).hostname } catch { return false }
  if (blockedHost(host)) return false
  await app.egress.fetch(url, { inputDerived: true })
  return true
}

export default function register(app: AppContext): void {
  app.route('importProductImage', async (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const product = app.findByExternalId('products', String(ctx.params[app.paramName('productId')] ?? ''))
    if (!product || product.store_id !== ctx.tenant) return ctx.json({ error: 'not_found' }, 404)
    const body = ctx.body && typeof ctx.body === 'object' ? (ctx.body as Record<string, unknown>) : {}
    const url = String(body[app.paramName('imageUrl')] ?? '')
    if (!/^https?:\/\/\S+$/.test(url)) return ctx.json({ error: 'invalid_url' }, 400)
    let imported = false
    try { imported = await fetchImage(app, url) } catch { /* unreachable source ignored */ }
    return ctx.json({ id: product.external_id, imported }, 202)
  }, { encoding: 'json' })
}
