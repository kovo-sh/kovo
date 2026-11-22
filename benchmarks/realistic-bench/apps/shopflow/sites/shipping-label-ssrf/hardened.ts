// Shipping label import. Carriers hand off a manifest that points at a label template to render. The
// template URL is read from the manifest and fetched server-side, but only after its host is confirmed
// to be a public carrier address rather than internal infrastructure.
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

function internalHost(host: string): boolean {
  const h = host.toLowerCase()
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === 'metadata'
    || h === 'metadata.google.internal' || h.startsWith('127.') || h.startsWith('169.254.')
    || h.startsWith('10.') || h.startsWith('192.168.') || h.endsWith('.internal')
}

async function importLabel(app: AppContext, raw: string): Promise<string> {
  const manifest = app.parseFeed(raw, false)
  const url = findTemplateUrl(manifest)
  if (url) {
    let host = ''
    try { host = new URL(url).hostname } catch { host = '' }
    if (host && !internalHost(host)) await app.egress.fetch(url, { inputDerived: true })
  }
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
