/**
 * Generic, target-agnostic "observation corpus": the bodies Guardian can fetch from a target's own
 * public surface (landing HTML, linked pages, OpenAPI documents, linked JS bundles). Hypothesis
 * formation mines it for realistic baseline values, XML/GraphQL request shapes and seed query
 * strings. Nothing here knows about any benchmark route, challenge id or flag.
 */
import type { Grant, RequestBroker } from '../src/server/broker.ts'

export interface Corpus {
  /** Concatenated, size-capped text of every fetched body (HTML, JS, JSON). */
  all: string
  /** Parsed JSON documents (OpenAPI / swagger) found among the bodies. */
  json: unknown[]
}

const MAX_BODY = 200_000
const staticExt = /\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|map|pdf|zip)(?:$|\?)/i

function attrUrls(html: string): string[] {
  const out: string[] = []
  for (const m of html.matchAll(/\b(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) out.push(m[1])
  return out
}

function sameOriginPath(raw: string, origin: string): string | null {
  const t = raw.trim()
  if (!t || /^(?:javascript|mailto|data|#)/i.test(t)) return null
  try {
    const u = new URL(t, origin)
    if (u.origin !== origin) return null
    return u.pathname + u.search
  } catch {
    return null
  }
}

export async function buildCorpus(
  broker: RequestBroker, grant: Grant, origin: string, signal: AbortSignal, personas: Array<string | undefined>,
): Promise<Corpus> {
  const bodies: string[] = []
  const json: unknown[] = []
  const seen = new Set<string>()
  let budget = 40
  const get = async (path: string, persona?: string): Promise<string> => {
    const key = `${persona ?? ''}|${path}`
    if (seen.has(key) || budget <= 0) return ''
    seen.add(key)
    budget -= 1
    try {
      const ex = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: path, persona, followRedirects: false }, grant, signal)
      if (ex.status >= 400) return ''
      const body = ex.body.slice(0, MAX_BODY)
      bodies.push(body)
      if (/json/i.test(ex.mediaType) || /^\s*[{[]/.test(body)) {
        try { json.push(JSON.parse(body)) } catch { /* not JSON */ }
      }
      return body
    } catch {
      return ''
    }
  }

  const pages: string[] = []
  for (const persona of personas) {
    const html = await get('/', persona)
    if (html) pages.push(html)
  }
  for (const doc of ['/openapi.json', '/swagger.json', '/openapi.yaml', '/api-docs', '/sitemap.xml', '/robots.txt']) await get(doc)

  const links = new Set<string>()
  const queue = [...pages, ...bodies.filter(b => /<(?:urlset|loc)\b/i.test(b))]
  for (const body of queue) {
    for (const u of attrUrls(body)) { const p = sameOriginPath(u, origin); if (p) links.add(p) }
    for (const m of body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) { const p = sameOriginPath(m[1], origin); if (p) links.add(p) }
  }
  for (const m of bodies.join('\n').matchAll(/^\s*(?:Allow|Disallow|Sitemap):\s*(\S+)/gim)) { const p = sameOriginPath(m[1], origin); if (p && p !== '/') links.add(p) }

  const jsLinks = [...links].filter(p => /\.m?js(?:$|\?)/i.test(p)).slice(0, 8)
  const pageLinks = [...links].filter(p => !staticExt.test(p) && !/\.m?js(?:$|\?)/i.test(p)).slice(0, 14)
  const fetchedPages: string[] = []
  for (const p of pageLinks) {
    for (const persona of [undefined, personas[0]]) {
      const body = await get(p, persona)
      if (body) { fetchedPages.push(body); break }
    }
  }
  for (const body of fetchedPages) {
    for (const u of attrUrls(body)) {
      const p = sameOriginPath(u, origin)
      if (p && /\.m?js(?:$|\?)/i.test(p) && !jsLinks.includes(p) && jsLinks.length < 10) jsLinks.push(p)
    }
  }
  for (const p of jsLinks) await get(p)

  return { all: bodies.join('\n').slice(0, 1_500_000), json }
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const clean = (v: string) => { try { return decodeURIComponent(v) } catch { return v } }
const plausible = (v: string) => v.length > 0 && v.length <= 80 && !/[<>{}\s]/.test(v) && !/^\$|^%s|^:/.test(v)

function walkOpenApi(node: unknown, name: string, out: string[]): void {
  if (!node || typeof node !== 'object') return
  if (Array.isArray(node)) { for (const n of node) walkOpenApi(n, name, out); return }
  const obj = node as Record<string, unknown>
  const schema = obj.schema as Record<string, unknown> | undefined
  if (obj.name === name) {
    for (const v of [obj.example, schema?.example, schema?.default, Array.isArray(schema?.enum) ? schema.enum[0] : undefined]) {
      if (typeof v === 'string' || typeof v === 'number') out.push(String(v))
    }
  }
  const props = obj.properties as Record<string, Record<string, unknown>> | undefined
  if (props && props[name] && typeof props[name] === 'object') {
    for (const v of [props[name].example, props[name].default]) if (typeof v === 'string' || typeof v === 'number') out.push(String(v))
  }
  for (const v of Object.values(obj)) walkOpenApi(v, name, out)
}

/** Realistic values observed for a parameter anywhere in the target's own public surface. */
export function mineBaselines(c: Corpus, name: string, pathTemplate: string): string[] {
  const out: string[] = []
  for (const doc of c.json) walkOpenApi(doc, name, out)
  const n = esc(name)
  const patterns = [
    new RegExp(`[?&;]${n}=([^&"'\\s<>#\\\\]+)`, 'gi'),
    new RegExp(`["']?${n}["']?\\s*[:=]\\s*["']([^"'\\\\]{1,80})["']`, 'gi'),
    new RegExp(`name=["']${n}["'][^>]*?\\bvalue=["']([^"']+)["']`, 'gi'),
    new RegExp(`\\bvalue=["']([^"']+)["'][^>]*?name=["']${n}["']`, 'gi'),
  ]
  for (const re of patterns) for (const m of c.all.matchAll(re)) out.push(clean(m[1]))
  const segs = pathTemplate.split('?')[0].split('/')
  const slot = segs.findIndex(s => /^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(s))
  if (slot > 0) {
    const prefix = segs.slice(0, slot).map(esc).join('/')
    for (const m of c.all.matchAll(new RegExp(`${prefix}/([A-Za-z0-9_.~-]{1,64})(?=[?"'\\s<)#\\\\]|$)`, 'g'))) out.push(m[1])
  }
  return [...new Set(out.filter(plausible))].slice(0, 8)
}

/** A realistic `path?query` seed observed in links/forms/JS for this exact path (e.g. OAuth authorize URLs). */
export function mineSeedQuery(c: Corpus, path: string): string | null {
  const re = new RegExp(`${esc(path)}\\?([^"'\\s<>#\\\\]{3,400})`, 'g')
  let best: string | null = null
  for (const m of c.all.matchAll(re)) {
    const q = m[1].replace(/&amp;/g, '&')
    if (!best || q.length > best.length) best = q
  }
  return best
}

/** XML request shape `<root><param>{{val}}</param></root>` observed in client code or docs. */
export function mineXmlTemplate(c: Corpus, param: string): string | null {
  const n = esc(param)
  const m = new RegExp(`<([A-Za-z][\\w:-]*)>[\\s'"\`+]*<${n}>`).exec(c.all)
  return m ? `<${m[1]}><${param}>{{val}}</${param}></${m[1]}>` : null
}

/** GraphQL operation text that takes `$<rootVar>` observed in client code. */
export function mineGraphqlQuery(c: Corpus, param: string): string | null {
  const rootVar = param.split('.')[0]
  const text = c.all.replace(/\\n/g, ' ').replace(/\\"/g, '"')
  const re = /\b(?:query|mutation)\b[^{`'"]{0,120}\(/g
  for (const m of text.matchAll(re)) {
    const start = m.index ?? 0
    const brace = text.indexOf('{', start + m[0].length)
    if (brace < 0 || brace - start > 400) continue
    let depth = 0
    let end = -1
    for (let i = brace; i < Math.min(text.length, brace + 800); i += 1) {
      if (text[i] === '{') depth += 1
      else if (text[i] === '}') { depth -= 1; if (depth === 0) { end = i + 1; break } }
    }
    if (end < 0) continue
    const op = text.slice(start, end).replace(/\s+/g, ' ').trim()
    if (new RegExp(`\\$${esc(rootVar)}\\b`).test(op)) return op
  }
  return null
}
