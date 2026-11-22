// XML catalog import (hand-written parser so the lab needs no native XML library).
// The `allowDtd: true` configuration models a parser with DTD/external-entity support enabled (planted XXE, hos-10).
import { fetchLoopback, httpError, readBody, sendJson } from './http-util.mjs'
import { VFS, readVirtualUri } from './files.mjs'

class XmlError extends Error {}

const PREDEFINED = { '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"', '&apos;': "'" }
const unquote = s => s.slice(1, -1)

async function resolveSystem(uri) {
  if (/^file:/i.test(uri)) {
    // Virtual lab file system only — real host files are never touched.
    const text = readVirtualUri(uri)
    if (text === null) throw new XmlError(`cannot resolve external entity ${uri}`)
    return text
  }
  if (/^https?:/i.test(uri)) {
    const res = await fetchLoopback(uri, { timeoutMs: 1500, maxBytes: 4096 })
    if (res.blocked) throw new XmlError(res.error)
    return res.body
  }
  throw new XmlError('unsupported external entity scheme')
}

const ENTITY_DECL = /<!ENTITY\s+(%\s+)?([\w.-]+)\s+(?:SYSTEM\s+("[^"]*"|'[^']*')|("[^"]*"|'[^']*'))\s*>/g

function collectEntities(dtd, general, params) {
  for (const m of dtd.matchAll(ENTITY_DECL)) {
    const target = m[1] ? params : general
    target.set(m[2], m[3] ? { system: unquote(m[3]) } : { value: unquote(m[4]) })
  }
}

export async function parseCatalogXml(xml, { allowDtd }) {
  const general = new Map()
  const params = new Map()
  const doctype = /<!DOCTYPE\s+([\w:.-]+)(?:\s+(SYSTEM|PUBLIC)\s+("[^"]*"|'[^']*')(?:\s+("[^"]*"|'[^']*'))?)?\s*(?:\[([\s\S]*?)\]\s*)?>/i.exec(xml)
  let body = xml
  if (doctype) {
    if (!allowDtd) throw new XmlError('DOCTYPE declarations are not allowed (DTD processing disabled)')
    body = xml.replace(doctype[0], '')
    const sysLiteral = doctype[2]?.toUpperCase() === 'PUBLIC' ? doctype[4] : doctype[3]
    let subset = doctype[5] ?? ''
    if (sysLiteral) subset = `${await resolveSystem(unquote(sysLiteral))}\n${subset}`
    collectEntities(subset, general, params)
    // Parameter entity references (%name;) inside the DTD are expanded (external ones are fetched).
    for (const ref of subset.matchAll(/%([\w.-]+);/g)) {
      const def = params.get(ref[1])
      if (!def) continue
      const text = def.system ? await resolveSystem(def.system) : def.value
      collectEntities(text, general, params)
    }
  }

  let expanded = ''
  let last = 0
  for (const m of body.matchAll(/&([\w.-]+);/g)) {
    expanded += body.slice(last, m.index)
    last = m.index + m[0].length
    if (PREDEFINED[m[0]]) {
      expanded += PREDEFINED[m[0]]
      continue
    }
    const def = general.get(m[1])
    if (!def) throw new XmlError(`undefined entity &${m[1]};`)
    expanded += (def.system ? await resolveSystem(def.system) : def.value).slice(0, 2048)
  }
  expanded += body.slice(last)

  const items = []
  for (const m of expanded.matchAll(/<([A-Za-z_][\w:.-]*)>([^<]*)<\/\1>/g)) {
    items.push({ tag: m[1], text: m[2].trim().slice(0, 2048) })
  }
  return items
}

export function xmlImportHandler(ctx, { strict }) {
  return async c => {
    const ctype = String(c.req.headers['content-type'] ?? '')
    if (!/xml/i.test(ctype)) return sendJson(c.res, 415, { error: 'unsupported_media_type', expected: 'application/xml' })
    const raw = await readBody(c.req, 65_536)
    try {
      const items = await parseCatalogXml(raw, { allowDtd: !strict && !ctx.fixed('hos-10') })
      sendJson(c.res, 200, { ok: true, count: items.length, items })
    } catch (err) {
      if (err instanceof XmlError) return sendJson(c.res, 400, { error: 'xml_parse_error', message: err.message })
      throw httpError(400, 'malformed xml')
    }
  }
}

export function register(router, ctx) {
  // hos-10: XML External Entity processing (file:// served from the virtual FS, http(s) limited to loopback).
  router.post('/api/v1/import/xml', xmlImportHandler(ctx, { strict: false }))
}

export { VFS }
