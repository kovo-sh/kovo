// Minimal, dependency-free XML parser used as a generic XXE sink for the offline benchmark.
// Internal entities always expand (bounded). External entities expand only when explicitly enabled,
// resolving file:// through an injected virtual filesystem and http:// through injected egress; each
// external resolution records an `xxe_entity_resolved` impact event. Never reads the real filesystem.
import type { Oracle } from './oracle.ts'

export interface XmlNode {
  tag: string
  attrs: Record<string, string>
  children: XmlNode[]
  text: string
}

// Injected collaborators (lib/vfs.ts and lib/egress.ts are authored concurrently; we only need these
// narrow shapes, so we accept them by structural type rather than importing their modules).
export interface XmlVfs { read(path: string): string }
export interface XmlEgress { fetch(url: string): string }

export interface ParseXmlOpts {
  oracle?: Oracle
  resolveExternalEntities?: boolean
  vfs?: XmlVfs
  egress?: XmlEgress
}

interface EntityDef { internal: boolean; value: string; uri?: string }

const MAX_EXPANDED = 10_000 // billion-laughs: total expanded characters budget
const MAX_DEPTH = 8 // billion-laughs: maximum entity nesting depth
const MAX_REFS = 50_000 // billion-laughs: hard cap on total entity expansions (bounds work, not just output)
const PREDEFINED: Record<string, string> = { lt: '<', gt: '>', amp: '&', apos: "'", quot: '"' }

function numericRef(ref: string): string {
  const body = ref.slice(1)
  const code = body[0] === 'x' || body[0] === 'X' ? parseInt(body.slice(1), 16) : parseInt(body, 10)
  if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return ''
  try { return String.fromCodePoint(code) } catch { return '' }
}

export function parseXml(source: string, opts: ParseXmlOpts = {}): XmlNode {
  const src = source
  const n = src.length
  let i = 0
  const entities = new Map<string, EntityDef>()
  const budget = { used: 0, refs: 0 }

  const resolveExternal = (uri: string): string => {
    opts.oracle?.emit('xxe_entity_resolved', { uri }, uri.startsWith('file') ? 'xml:file' : 'xml:http')
    try {
      if (uri.startsWith('file')) {
        const path = uri.replace(/^file:\/\/+/, '/').replace(/^\/+/, '/')
        return opts.vfs ? String(opts.vfs.read(path)) : ''
      }
      if (uri.startsWith('http')) return opts.egress ? String(opts.egress.fetch(uri)) : ''
    } catch { return '' }
    return ''
  }

  const expand = (input: string, depth: number): string => {
    if (depth > MAX_DEPTH) return ''
    let out = ''
    let k = 0
    while (k < input.length) {
      if (budget.used >= MAX_EXPANDED) break
      const amp = input.indexOf('&', k)
      if (amp === -1) { const chunk = input.slice(k); out += chunk; budget.used += chunk.length; break }
      const pre = input.slice(k, amp); out += pre; budget.used += pre.length
      const semi = input.indexOf(';', amp)
      if (semi === -1) { out += input.slice(amp); break }
      const ref = input.slice(amp + 1, semi)
      k = semi + 1
      if (ref[0] === '#') { const ch = numericRef(ref); out += ch; budget.used += ch.length; continue }
      if (PREDEFINED[ref] !== undefined) { out += PREDEFINED[ref]; budget.used += 1; continue }
      const ent = entities.get(ref)
      if (!ent) continue // unknown entity -> drop
      if (++budget.refs > MAX_REFS) return out // bound total work regardless of output size
      if (!ent.internal) {
        if (!opts.resolveExternalEntities || !ent.uri) continue
        out += expand(resolveExternal(ent.uri), depth + 1)
        continue
      }
      out += expand(ent.value, depth + 1)
    }
    return out
  }

  const parseDoctypeEntities = (subset: string): void => {
    const re = /<!ENTITY\s+(\w+)\s+([^>]*?)>/g
    let m: RegExpExecArray | null
    while ((m = re.exec(subset)) !== null) {
      const name = m[1]!
      const rest = m[2]!.trim()
      const ext = /^(SYSTEM|PUBLIC)\b/i.exec(rest)
      if (ext) {
        const uris = rest.match(/"([^"]*)"|'([^']*)'/g) ?? []
        const last = uris[uris.length - 1]
        const uri = last ? last.slice(1, -1) : ''
        entities.set(name, { internal: false, value: '', uri })
      } else {
        const lit = /^"([^"]*)"|^'([^']*)'/.exec(rest)
        entities.set(name, { internal: true, value: lit ? (lit[1] ?? lit[2] ?? '') : '' })
      }
    }
  }

  const readName = (): string => {
    const s = i
    while (i < n && !/[\s/>=]/.test(src[i]!)) i++
    return src.slice(s, i)
  }
  const skipWs = (): void => { while (i < n && /\s/.test(src[i]!)) i++ }

  const parseElement = (): XmlNode => {
    i++ // consume '<'
    const tag = readName()
    const attrs: Record<string, string> = {}
    while (i < n) {
      skipWs()
      if (src[i] === '/' && src[i + 1] === '>') { i += 2; return { tag, attrs, children: [], text: '' } }
      if (src[i] === '>') { i++; break }
      const aname = readName()
      skipWs()
      let aval = ''
      if (src[i] === '=') {
        i++; skipWs()
        const q = src[i]
        if (q === '"' || q === "'") { i++; const s = i; while (i < n && src[i] !== q) i++; aval = src.slice(s, i); i++ }
        else { const s = i; while (i < n && !/[\s/>]/.test(src[i]!)) i++; aval = src.slice(s, i) }
      }
      attrs[aname] = expand(aval, 0)
    }
    const children: XmlNode[] = []
    let text = ''
    while (i < n) {
      if (src.startsWith('</', i)) { i += 2; readName(); const g = src.indexOf('>', i); i = g === -1 ? n : g + 1; break }
      if (src.startsWith('<!--', i)) { const e = src.indexOf('-->', i); i = e === -1 ? n : e + 3; continue }
      if (src.startsWith('<![CDATA[', i)) { const e = src.indexOf(']]>', i); text += src.slice(i + 9, e === -1 ? n : e); i = e === -1 ? n : e + 3; continue }
      if (src.startsWith('<?', i)) { const e = src.indexOf('?>', i); i = e === -1 ? n : e + 2; continue }
      if (src[i] === '<') { children.push(parseElement()); continue }
      const next = src.indexOf('<', i)
      const raw = src.slice(i, next === -1 ? n : next)
      text += expand(raw, 0)
      i = next === -1 ? n : next
    }
    return { tag, attrs, children, text }
  }

  // Prolog: skip declarations/comments, capture DOCTYPE internal subset, stop at root element.
  while (i < n) {
    skipWs()
    if (src.startsWith('<?', i)) { const e = src.indexOf('?>', i); i = e === -1 ? n : e + 2; continue }
    if (src.startsWith('<!--', i)) { const e = src.indexOf('-->', i); i = e === -1 ? n : e + 3; continue }
    if (src.startsWith('<!DOCTYPE', i)) {
      const bracket = src.indexOf('[', i)
      const gt = src.indexOf('>', i)
      if (bracket !== -1 && (gt === -1 || bracket < gt)) {
        const close = src.indexOf(']', bracket)
        parseDoctypeEntities(src.slice(bracket + 1, close === -1 ? n : close))
        const after = src.indexOf('>', close === -1 ? bracket : close)
        i = after === -1 ? n : after + 1
      } else { i = gt === -1 ? n : gt + 1 }
      continue
    }
    if (src[i] === '<') break
    i++
  }
  if (i >= n) return { tag: '', attrs: {}, children: [], text: '' }
  return parseElement()
}

/** Read a text value by dotted child path (empty path returns the node's own text). */
export function xmlText(node: XmlNode, path: string): string {
  const parts = path.split('.').filter(Boolean)
  let cur: XmlNode | undefined = node
  for (const p of parts) {
    cur = cur?.children.find((c) => c.tag === p)
    if (!cur) return ''
  }
  return cur ? cur.text : ''
}
