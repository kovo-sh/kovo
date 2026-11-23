// Pure helpers for the HTTP layer (routing match, URL/header parsing, response shaping). Kept out of
// http.ts purely to keep each file small; no I/O, no state.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { HttpResult, Seg, Route } from './http.ts'

export const splitPath = (p: string): string[] => p.split('/').filter((s) => s.length > 0)

export const compile = (path: string): Seg[] =>
  splitPath(path).map((s) => (s.startsWith(':') ? { param: s.slice(1) } : { lit: s }))

export function matchRoute(route: Route, parts: string[]): Record<string, string> | null {
  if (route.segs.length !== parts.length) return null
  const params: Record<string, string> = {}
  for (let i = 0; i < route.segs.length; i++) {
    const seg = route.segs[i]!
    if (seg.param) { try { params[seg.param] = decodeURIComponent(parts[i]!) } catch { params[seg.param] = parts[i]! } }
    else if (seg.lit !== parts[i]) return null
  }
  return params
}

export const isHttpResult = (v: unknown): v is HttpResult =>
  typeof v === 'object' && v !== null && 'status' in v && 'body' in v && 'headers' in v

/**
 * True when a redirect target leaves the app's origin. Resolves the target the way a browser does,
 * after normalising backslashes (browsers treat `\` as `/` for http(s) URLs, so an origin-relative
 * `/\host` target is really `//host`). Any scheme that produces a different/empty host (absolute
 * http(s), protocol-relative, non-http schemes such as javascript:) counts as off-origin.
 */
export function offOrigin(location: string, host: string): boolean {
  try {
    const normalized = location.replace(/\\/g, '/')
    const resolved = new URL(normalized, `http://${host}/`)
    return resolved.host.toLowerCase() !== host.toLowerCase()
  } catch { return false }
}

export const headerStr = (req: IncomingMessage, name: string): string | undefined => {
  const v = req.headers[name.toLowerCase()]
  return v === undefined ? undefined : Array.isArray(v) ? v.join(',') : v
}

export function lowerHeaders(req: IncomingMessage): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(req.headers)) out[k] = Array.isArray(v) ? v.join(',') : v
  return out
}

export function csrfFromBody(body: unknown): string | undefined {
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const v = (body as Record<string, unknown>)['_csrf']
    if (typeof v === 'string') return v
  }
  return undefined
}

export function sameOrigin(req: IncomingMessage, host: string): boolean {
  const src = headerStr(req, 'origin') ?? headerStr(req, 'referer')
  if (!src) return false
  try { return new URL(src).host === host } catch { return false }
}

export const mk = (body: string | Buffer, status: number, ct: string, cookies: string[]): HttpResult => ({
  status, body,
  headers: cookies.length ? { 'content-type': ct, 'set-cookie': cookies } : { 'content-type': ct },
})

export function normalize(ret: unknown, pending: string[]): HttpResult {
  if (isHttpResult(ret)) return ret
  const cookies = pending.slice()
  if (typeof ret === 'string') return mk(ret, 200, 'text/plain; charset=utf-8', cookies)
  if (ret === undefined || ret === null) return { status: 204, headers: cookies.length ? { 'set-cookie': cookies } : {}, body: '' }
  return mk(JSON.stringify(ret), 200, 'application/json; charset=utf-8', cookies)
}

export function send(res: ServerResponse, r: HttpResult): void {
  const headers: Record<string, string | string[]> = {}
  for (const [k, v] of Object.entries(r.headers)) {
    if (v === undefined || (Array.isArray(v) && v.length === 0)) continue
    headers[k] = v
  }
  res.writeHead(r.status, headers)
  res.end(r.body)
}
