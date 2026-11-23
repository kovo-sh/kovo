// Stream hub for server-sent build-log events. The neutral HTTP framework returns a single buffered
// response, so SSE connections are dispatched by server.ts before the normal router: this module owns
// the raw socket handshake, route matching and the per-connection session surface.
//
// The session exposes the resolved credential *and* its revocation state so a handler can decide what
// to enforce. Common code rejects revoked tokens; a route module may replace the handler.
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Actor } from '../../../lib/types.ts'

export interface StreamViewer {
  userExt: string
  org: string
  role: string
  persona: string | null
  email: string
}

export interface StreamToken {
  raw: string
  externalId: string | null
  userExt: string | null
  org: string | null
  scopes: string[]
  envScope: string
  revoked: boolean
  signatureValid: boolean
}

export interface StreamSession {
  routeKey: string
  method: string
  path: string
  params: Record<string, string>
  query: Record<string, string | string[]>
  headers: Record<string, string | undefined>
  cookies: Record<string, string>
  actor: Actor
  tenant: string | null
  sessionId: string | null
  viewer: StreamViewer | null
  token: StreamToken | null
  /** True once at least one event was written. */
  readonly opened: boolean
  /** HTTP status used for the handshake (200 unless rejected). */
  readonly status: number
  send(event: string, data: unknown): void
  /** Reject the connection before streaming; sets the HTTP status and closes. */
  reject(status: number, reason: string): void
  close(): void
  onClose(fn: () => void): void
}

export type StreamHandler = (session: StreamSession) => void | Promise<void>

/** Host-visible trace for a connection; keeps the transport module free of host internals. */
export interface StreamTrace {
  routeKey: string
  method: string
  path: string
  params: Record<string, string>
  query: Record<string, string | string[]>
  actor: Actor
  tenant: string | null
  sessionId: string | null
  tokenExt: string | null
  opened(): boolean
  status(): number
}

export interface StreamMatch {
  routeKey: string
  params: Record<string, string>
  handler: StreamHandler
}

export interface StreamHub {
  route(routeKey: string, handler: StreamHandler): void
  has(routeKey: string): boolean
  match(method: string, parts: string[]): StreamMatch | null
}

interface Registered {
  routeKey: string
  method: string
  segs: { lit?: string; param?: string }[]
  handler: StreamHandler
}

export function createStreamHub(routeTable: Record<string, { method: string; path: string }>): StreamHub {
  const registered: Registered[] = []
  return {
    route(routeKey, handler) {
      if (registered.some((r) => r.routeKey === routeKey)) return // first registration wins
      const spec = routeTable[routeKey]
      if (!spec) return
      const segs = spec.path.split('/').filter(Boolean).map((s) =>
        s.startsWith(':') ? { param: s.slice(1) } : { lit: s })
      registered.push({ routeKey, method: spec.method.toUpperCase(), segs, handler })
    },
    has: (routeKey) => registered.some((r) => r.routeKey === routeKey),
    match(method, parts) {
      for (const r of registered) {
        if (r.method !== method.toUpperCase() || r.segs.length !== parts.length) continue
        const params: Record<string, string> = {}
        let ok = true
        for (let i = 0; i < r.segs.length; i++) {
          const seg = r.segs[i]!
          if (seg.param) {
            try { params[seg.param] = decodeURIComponent(parts[i]!) } catch { params[seg.param] = parts[i]! }
          } else if (seg.lit !== parts[i]) { ok = false; break }
        }
        if (ok) return { routeKey: r.routeKey, params, handler: r.handler }
      }
      return null
    },
  }
}

export interface StreamWireOpts {
  req: IncomingMessage
  res: ServerResponse
  routeKey: string
  method: string
  path: string
  params: Record<string, string>
  query: Record<string, string | string[]>
  headers: Record<string, string | undefined>
  cookies: Record<string, string>
  actor: Actor
  tenant: string | null
  sessionId: string | null
  viewer: StreamViewer | null
  token: StreamToken | null
  heartbeatMs?: number
}

/** Create the raw SSE session: headers are flushed lazily on the first event or rejection. */
export function openStream(opts: StreamWireOpts): StreamSession {
  const { req, res } = opts
  let started = false
  let closed = false
  let opened = false
  let status = 200
  const disconnectors: Array<() => void> = []
  let beat: ReturnType<typeof setInterval> | null = null

  const stop = (): void => {
    if (closed) return
    closed = true
    if (beat) clearInterval(beat)
    for (const fn of disconnectors) { try { fn() } catch { /* ignore */ } }
  }

  const begin = (): void => {
    if (started) return
    started = true
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    })
    res.write(': stream open\n\n')
    beat = setInterval(() => {
      if (closed) return
      try { res.write(': keep-alive\n\n') } catch { stop() }
    }, opts.heartbeatMs ?? 5000)
  }

  const session: StreamSession = {
    routeKey: opts.routeKey,
    method: opts.method,
    path: opts.path,
    params: opts.params,
    query: opts.query,
    headers: opts.headers,
    cookies: opts.cookies,
    actor: opts.actor,
    tenant: opts.tenant,
    sessionId: opts.sessionId,
    viewer: opts.viewer,
    token: opts.token,
    get opened() { return opened },
    get status() { return status },
    send(event, data) {
      if (closed) return
      begin()
      opened = true
      try { res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`) } catch { stop() }
    },
    reject(code, reason) {
      if (started) return
      started = true
      closed = true
      status = code
      try {
        res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' })
        res.end(JSON.stringify({ error: reason }))
      } catch { /* ignore */ }
    },
    close() {
      if (closed) return
      stop()
      try { res.end() } catch { /* ignore */ }
    },
    onClose(fn) {
      disconnectors.push(fn)
    },
  }
  req.on('close', stop)
  res.on('close', stop)
  return session
}

export { openStream as openSession }
