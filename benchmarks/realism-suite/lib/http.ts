// Minimal zero-dependency HTTP router shared by every fixture. Intentionally compact:
// path params, query strings, bounded body reads, response helpers and cookies.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { closeServer, listenLoopback, originFor } from './safety.ts'

export interface Ctx {
  req: IncomingMessage
  res: ServerResponse
  method: string
  path: string
  host: string
  query: URLSearchParams
  params: Record<string, string>
  headers: Record<string, string | undefined>
  bodyText: string
}

export type Handler = (ctx: Ctx) => Promise<void> | void

export interface RouteDef {
  method: string
  path: string
  handler: Handler
  meta?: Record<string, unknown>
}

export interface RouteMatch {
  route: RouteDef
  params: Record<string, string>
}

const BODY_LIMIT = 64 * 1024

function splitPath(path: string): string[] {
  return path.split('/').filter((s) => s.length > 0)
}

export class Router {
  readonly routes: RouteDef[] = []
  private readonly buckets = new Map<string, RouteDef[]>()

  add(method: string, path: string, handler: Handler, meta?: Record<string, unknown>): this {
    const route: RouteDef = { method: method.toUpperCase(), path, handler, meta }
    this.routes.push(route)
    const first = splitPath(path)[0] ?? ''
    const key = first.startsWith(':') || first === '*' ? '*' : first.toLowerCase()
    const bucket = this.buckets.get(key)
    if (bucket) bucket.push(route)
    else this.buckets.set(key, [route])
    return this
  }

  get(path: string, handler: Handler, meta?: Record<string, unknown>): this {
    return this.add('GET', path, handler, meta)
  }

  post(path: string, handler: Handler, meta?: Record<string, unknown>): this {
    return this.add('POST', path, handler, meta)
  }

  patch(path: string, handler: Handler, meta?: Record<string, unknown>): this {
    return this.add('PATCH', path, handler, meta)
  }

  put(path: string, handler: Handler, meta?: Record<string, unknown>): this {
    return this.add('PUT', path, handler, meta)
  }

  delete(path: string, handler: Handler, meta?: Record<string, unknown>): this {
    return this.add('DELETE', path, handler, meta)
  }

  match(method: string, path: string): RouteMatch | null {
    const want = method.toUpperCase()
    const segments = splitPath(path)
    const first = (segments[0] ?? '').toLowerCase()
    const candidates = [...(this.buckets.get(first) ?? []), ...(this.buckets.get('*') ?? [])]
    for (const route of candidates) {
      if (route.method !== want && route.method !== 'ANY') continue
      const params = matchSegments(splitPath(route.path), segments)
      if (params) return { route, params }
    }
    return null
  }
}

function matchSegments(pattern: string[], actual: string[]): Record<string, string> | null {
  const params: Record<string, string> = {}
  for (let i = 0; i < pattern.length; i++) {
    const part = pattern[i]
    if (part === '*') {
      params['*'] = actual.slice(i).join('/')
      return params
    }
    if (i >= actual.length) return null
    if (part.startsWith(':')) params[part.slice(1)] = decodeURIComponent(actual[i])
    else if (part !== actual[i]) return null
  }
  return pattern.length === actual.length ? params : null
}

export interface ServeOptions {
  name?: string
  cors?: (ctx: Ctx) => void
  onRequest?: (ctx: Ctx) => void
}

export interface RunningServer {
  name: string
  origin: string
  port: number
  server: Server
  close: () => Promise<void>
}

export function readBody(req: IncomingMessage, limit = BODY_LIMIT): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('body_limit_exceeded'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

export async function serve(router: Router, options: ServeOptions = {}): Promise<RunningServer> {
  const name = options.name ?? 'fixture'
  const server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`)
      const match = router.match(req.method ?? 'GET', url.pathname)
      const ctx: Ctx = {
        req,
        res,
        method: (req.method ?? 'GET').toUpperCase(),
        path: url.pathname,
        host: req.headers.host ?? '',
        query: url.searchParams,
        params: match?.params ?? {},
        headers: req.headers as Record<string, string | undefined>,
        bodyText: '',
      }
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') ctx.bodyText = await readBody(req)
        options.onRequest?.(ctx)
        if (options.cors) options.cors(ctx)
        if (!match) {
          if (req.method === 'OPTIONS') {
            res.statusCode = 204
            res.end()
            return
          }
          sendJson(res, 404, { error: 'not_found', path: url.pathname })
          return
        }
        await match.route.handler(ctx)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        if (!res.headersSent) sendJson(res, message === 'body_limit_exceeded' ? 413 : 500, { error: message })
        else res.end()
      }
    })()
  })
  const port = await listenLoopback(server)
  return {
    name,
    origin: originFor(port),
    port,
    server,
    close: () => closeServer(server),
  }
}

export function sendJson(
  res: ServerResponse,
  status: number,
  value: unknown,
  headers: Record<string, string> = {},
): void {
  const body = JSON.stringify(value)
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v)
  res.end(body)
}

export function sendText(
  res: ServerResponse,
  status: number,
  body: string,
  contentType = 'text/plain; charset=utf-8',
  headers: Record<string, string> = {},
): void {
  res.statusCode = status
  res.setHeader('content-type', contentType)
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v)
  res.end(body)
}

export function sendHtml(res: ServerResponse, status: number, html: string, headers: Record<string, string> = {}): void {
  sendText(res, status, html, 'text/html; charset=utf-8', headers)
}

export function redirect(res: ServerResponse, location: string, status = 302, headers: Record<string, string> = {}): void {
  res.statusCode = status
  res.setHeader('location', location)
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v)
  res.end()
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx < 0) continue
    const name = part.slice(0, idx).trim()
    const value = part.slice(idx + 1).trim()
    if (name) out[name] = decodeURIComponent(value)
  }
  return out
}

export interface CookieOptions {
  httpOnly?: boolean
  sameSite?: 'lax' | 'strict' | 'none'
  path?: string
  maxAge?: number
}

export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`]
  parts.push(`Path=${options.path ?? '/'}`)
  if (options.httpOnly) parts.push('HttpOnly')
  parts.push(`SameSite=${options.sameSite ? options.sameSite[0].toUpperCase() + options.sameSite.slice(1) : 'Lax'}`)
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`)
  return parts.join('; ')
}

export function jsonBody<T = Record<string, unknown>>(ctx: Ctx): T | null {
  if (!ctx.bodyText) return null
  try {
    return JSON.parse(ctx.bodyText) as T
  } catch {
    return null
  }
}

export function bearer(ctx: Ctx): string | null {
  const header = ctx.headers.authorization
  if (!header || !header.startsWith('Bearer ')) return null
  return header.slice('Bearer '.length).trim()
}

export function headerValue(ctx: Ctx, name: string): string | undefined {
  const value = ctx.headers[name.toLowerCase()]
  return Array.isArray(value) ? value[0] : value
}

/** Add an `Access-Control-Allow-*` preflight answer for split-origin fixtures. */
export function allowCors(ctx: Ctx, origin: string, extraHeaders: string[] = ['authorization', 'content-type']): void {
  if (ctx.headers.origin === origin) {
    ctx.res.setHeader('access-control-allow-origin', origin)
    ctx.res.setHeader('access-control-allow-credentials', 'true')
    ctx.res.setHeader('vary', 'origin')
  }
  if (ctx.method === 'OPTIONS') {
    ctx.res.setHeader('access-control-allow-methods', 'GET,POST,PATCH,PUT,DELETE,OPTIONS')
    ctx.res.setHeader('access-control-allow-headers', extraHeaders.join(','))
  }
}
