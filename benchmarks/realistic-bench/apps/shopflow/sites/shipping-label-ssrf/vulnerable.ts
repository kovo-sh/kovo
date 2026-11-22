// Shipping label import. Carriers hand off a manifest that points at a label template to render. The
// template URL is read from the manifest and fetched server-side so the rendered label can be cached.
import type { AppContext } from '../../src/context.ts'
import type { ReqCtx } from '../../../../lib/http.ts'
import type { XmlNode } from '../../../../lib/xml.ts'

function findTemplateUrl(node: XmlNode): string {
  const text = (node.text ?? '').trim()
  if (/^https?:\/\/\S+$/i.test(text)) return text
  for (const value of Object.values(node.attrs)) if (/^https?:\/\/\S+$/i.test(value)) return value
  for (const child of node.children) {
    const found = findTemplateUrl(child)
    if (found) return found
  }
  return ''
}

async function importLabel(app: AppContext, raw: string): Promise<string> {
  const manifest = app.parseFeed(raw, false)
  const url = findTemplateUrl(manifest)
  if (url) await app.egress.fetch(url, { inputDerived: true })
  return manifest.tag
}

export default function register(app: AppContext): void {
  app.route('importShippingLabel', async (ctx: ReqCtx) => {
    if (ctx.actor === 'anonymous') return ctx.json({ error: 'unauthorized' }, 401)
    const raw = String((ctx.body as { raw?: string } | undefined)?.raw ?? '')
    let root = ''
    try { root = await importLabel(app, raw) } catch { /* template unreachable */ }
    return ctx.json({ accepted: true, root })
  }, { encoding: 'xml' })
}
