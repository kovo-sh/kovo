// Request body reading + parsing: json, x-www-form-urlencoded, multipart/form-data (basic), xml (raw).
import type { IncomingMessage } from 'node:http'

export type BodyEncoding = 'json' | 'form' | 'multipart' | 'xml'

export const MAX_BODY_BYTES = 256 * 1024 // 256 KiB

export interface ParsedBody {
  body: unknown // parsed representation (object for json/form/multipart, { raw } for xml)
  values: string[] // flattened string leaf values, for taint tracking
  tooLarge: boolean // true if the body exceeded MAX_BODY_BYTES
}

/**
 * Read the raw request body, capping at MAX_BODY_BYTES. Past the cap it sets tooLarge and discards
 * further chunks but keeps draining the stream to end, so the response can be sent without resetting
 * the socket (a destroy() mid-upload surfaces as ECONNRESET on the client).
 */
export function readRawBody(req: IncomingMessage): Promise<{ raw: Buffer; tooLarge: boolean }> {
  return new Promise((resolve, reject) => {
    let chunks: Buffer[] = []
    let size = 0
    let tooLarge = false
    req.on('data', (chunk: Buffer) => {
      if (tooLarge) return
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        tooLarge = true
        chunks = [] // free buffered data; keep draining
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve({ raw: tooLarge ? Buffer.alloc(0) : Buffer.concat(chunks), tooLarge }))
    req.on('error', (err) => (tooLarge ? resolve({ raw: Buffer.alloc(0), tooLarge: true }) : reject(err)))
  })
}

/** Map a raw Content-Type header to one of our encoding families (or undefined). */
export function contentTypeFamily(contentType: string | undefined): BodyEncoding | undefined {
  if (!contentType) return undefined
  const ct = contentType.toLowerCase()
  if (ct.includes('application/json') || ct.endsWith('+json')) return 'json'
  if (ct.includes('application/x-www-form-urlencoded')) return 'form'
  if (ct.includes('multipart/form-data')) return 'multipart'
  if (ct.includes('application/xml') || ct.includes('text/xml') || ct.endsWith('+xml')) return 'xml'
  return undefined
}

function collectStrings(value: unknown, out: string[]): void {
  if (value === null || value === undefined) return
  if (typeof value === 'string') {
    if (value.length > 0) out.push(value)
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out)
  } else if (typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) collectStrings(v, out)
  }
}

function parseForm(text: string): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {}
  for (const pair of text.split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    const rawK = eq < 0 ? pair : pair.slice(0, eq)
    const rawV = eq < 0 ? '' : pair.slice(eq + 1)
    let k: string
    let v: string
    try {
      k = decodeURIComponent(rawK.replace(/\+/g, ' '))
      v = decodeURIComponent(rawV.replace(/\+/g, ' '))
    } catch {
      k = rawK
      v = rawV
    }
    const prev = out[k]
    if (prev === undefined) out[k] = v
    else if (Array.isArray(prev)) prev.push(v)
    else out[k] = [prev, v]
  }
  return out
}

function parseMultipart(raw: Buffer, contentType: string): Record<string, string> {
  const out: Record<string, string> = {}
  const m = contentType.match(/boundary="?([^";]+)"?/i)
  if (!m) return out
  const boundary = `--${m[1]}`
  const text = raw.toString('latin1')
  for (const part of text.split(boundary)) {
    const trimmed = part.replace(/^\r\n/, '')
    if (!trimmed || trimmed === '--' || trimmed === '--\r\n') continue
    const sep = trimmed.indexOf('\r\n\r\n')
    if (sep < 0) continue
    const header = trimmed.slice(0, sep)
    const nameM = header.match(/name="([^"]*)"/i)
    if (!nameM) continue
    let value = trimmed.slice(sep + 4)
    value = value.replace(/\r\n--?$/, '').replace(/\r\n$/, '')
    out[nameM[1]!] = Buffer.from(value, 'latin1').toString('utf8')
  }
  return out
}

/** Parse a raw body according to the declared encoding. Falls back gracefully on malformed input. */
export function parseBody(raw: Buffer, contentType: string | undefined, encoding: BodyEncoding | undefined): ParsedBody {
  const values: string[] = []
  if (raw.length === 0) return { body: encoding === 'xml' ? { raw: '' } : {}, values, tooLarge: false }
  const eff = encoding ?? contentTypeFamily(contentType) ?? 'json'
  try {
    if (eff === 'json') {
      const body = JSON.parse(raw.toString('utf8')) as unknown
      collectStrings(body, values)
      return { body, values, tooLarge: false }
    }
    if (eff === 'form') {
      const body = parseForm(raw.toString('utf8'))
      collectStrings(body, values)
      return { body, values, tooLarge: false }
    }
    if (eff === 'multipart') {
      const body = parseMultipart(raw, contentType ?? '')
      collectStrings(body, values)
      return { body, values, tooLarge: false }
    }
    // xml: raw passthrough (parsing/entity handling is a separate concern in lib/xml.ts)
    const text = raw.toString('utf8')
    values.push(text)
    return { body: { raw: text }, values, tooLarge: false }
  } catch {
    const text = raw.toString('utf8')
    if (text.length > 0) values.push(text)
    return { body: { raw: text }, values, tooLarge: false }
  }
}
