// Tiny loopback HTTP framework shared by all benchmark apps: router (:param paths), AsyncLocalStorage
// request context, body parsing, cookies/sessions/CSRF primitives, jailed static/SPA serving, and an
// optional poison-aware response cache. It defines the MonitorSet hook surface but implements NO app
// monitors (apps supply those in truth/monitors.ts). node built-ins only.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Actor, VariantPlan } from './types.ts'
import type { Oracle, RequestCtx } from './oracle.ts'
import { runWithCtx, noteInput, isFromInput } from './oracle.ts'
import type { Db } from './db.ts'
import type { CanaryRegistry } from './canary.ts'
import { assertLocalLabAllowed, listenLoopback, closeServer } from './safety.ts'
import { parseCookies } from './http-cookies.ts'
import { readRawBody, parseBody, contentTypeFamily, type BodyEncoding } from './http-body.ts'
import {
  createSessionStore, createSessionHandle, ensureCsrfToken, csrfTokenValid,
  type SessionHandle, type SessionStore,
} from './http-session.ts'
import { serveStatic } from './http-static.ts'
import { createResponseCache, detectCachePoison, type CacheOpts } from './http-cache.ts'
import {
  compile, matchRoute, splitPath, offOrigin, headerStr, lowerHeaders, csrfFromBody, sameOrigin,
  mk, normalize, send,
} from './http-util.ts'

export interface HttpResult {
  status: number
  headers: Record<string, string | string[]>
  body: string | Buffer
}

// ---- MonitorSet hook surface (apps implement; this layer only invokes) -------------------------
export interface ResponseInspector {
  inspect(ctx: RequestCtx, res: HttpResult, oracle: Oracle): void
}
export interface MonitorSet {
  install?(oracle: Oracle, db: Db): void
  afterRequest?(ctx: RequestCtx, oracle: Oracle, db?: Db): void
  inspectResponse?(ctx: RequestCtx, res: HttpResult, oracle: Oracle): void
}

export interface ResolveHelpers {
  cookies: Record<string, string>
  header(name: string): string | undefined
  query: Record<string, string | string[]>
  method: string; path: string; sessions: SessionStore
  getSession(id: string | null | undefined): unknown
}
export type ResolveActor = (req: IncomingMessage, helpers: ResolveHelpers) =>
  { actor: Actor; tenant: string | null; sessionId: string | null }

export interface ReqCtx {
  method: string
  path: string
  params: Record<string, string>
  query: Record<string, string | string[]>
  body: unknown
  headers: Record<string, string | undefined>
  cookies: Record<string, string>
  actor: Actor
  tenant: string | null
  session: SessionHandle
  sameOrigin: boolean // request Origin/Referer host matches the request host
  csrfValid: boolean // a CSRF token matching the session's issued token was presented
  issueCsrfToken(): string
  setCsrfRejected(): void
  json(obj: unknown, status?: number): HttpResult
  html(markup: string, status?: number): HttpResult
  text(body: string, status?: number): HttpResult
  redirect(location: string, status?: number): HttpResult // off-origin + input-derived => open_redirect
}
export type Handler = (ctx: ReqCtx) => HttpResult | Promise<HttpResult> | unknown
export interface RouteOpts { encoding?: BodyEncoding; cache?: CacheOpts }
export interface CreateHttpAppOpts {
  plan: VariantPlan; oracle: Oracle; monitors?: MonitorSet; canaries?: CanaryRegistry
  resolveActor: ResolveActor; db?: Db; sessionCookie?: string
}
export interface HttpApp {
  route(routeKey: string, handler: Handler, opts?: RouteOpts): HttpApp
  static(uiDir: string): HttpApp
  readonly sessions: SessionStore
  handle(req: IncomingMessage, res: ServerResponse): void
  listen(): Promise<number>
  close(): Promise<void>
  readonly server: Server
}
export interface Seg { lit?: string; param?: string }
export interface Route { routeKey: string; method: string; segs: Seg[]; handler: Handler; opts: RouteOpts }

const SUSPICIOUS = /['"<>;`|]|\$\{|\{\{|\.\.\/|\$\(|<script|javascript:|on\w+=|\bunion\b|\bselect\b/i
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export function createHttpApp(opts: CreateHttpAppOpts): HttpApp {
  const { plan, oracle, monitors, canaries, resolveActor, db } = opts
  const cookieName = opts.sessionCookie ?? 'rb_sid'
  const sessions = createSessionStore()
  const cache = createResponseCache()
  const routes: Route[] = []
  let uiDir: string | null = null
  if (monitors?.install && db) monitors.install(oracle, db)

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const method = (req.method ?? 'GET').toUpperCase()
    const pathname = url.pathname
    const parts = splitPath(pathname)
    const cookies = parseCookies(req.headers.cookie)
    const host = String(req.headers.host ?? '127.0.0.1')
    const query: Record<string, string | string[]> = {}
    for (const key of url.searchParams.keys()) {
      const all = url.searchParams.getAll(key)
      query[key] = all.length > 1 ? all : all[0]!
    }
    let matched: Route | null = null
    let params: Record<string, string> = {}
    for (const r of routes) {
      if (r.method !== method) continue
      const m = matchRoute(r, parts)
      if (m) { matched = r; params = m; break }
    }

    // Unmatched GET -> jailed static file / SPA fallback (the only real-FS read).
    if (!matched && method === 'GET' && uiDir) {
      const sr = serveStatic(uiDir, (req.url ?? '/').split('?')[0]!) // raw path: traversal not yet normalized
      send(res, { status: sr.status, headers: { 'content-type': sr.contentType }, body: sr.body })
      oracle.logRequest({ method, path: pathname, routeKey: null, status: sr.status, actor: 'anonymous', paramNames: [], suspicious: false, spaFallback: sr.spaFallback })
      return
    }

    const encoding = matched?.opts.encoding
    const contentType = req.headers['content-type']
    let body: unknown = {}
    let bodyValues: string[] = []
    let tooLarge = false
    if (BODY_METHODS.has(method)) {
      const read = await readRawBody(req)
      tooLarge = read.tooLarge
      if (!tooLarge) { const pb = parseBody(read.raw, contentType, encoding); body = pb.body; bodyValues = pb.values }
    }
    const ctFamily = contentTypeFamily(contentType)
    const encodingMismatch = !!encoding && !!ctFamily && ctFamily !== encoding
    const meta = { csrfRejected: false, sessionLost: false }
    const helpers: ResolveHelpers = {
      cookies, query, method, path: pathname, sessions,
      header: (n) => headerStr(req, n),
      getSession: (id) => { if (id && !sessions.get(id)) meta.sessionLost = true; return sessions.get(id) },
    }
    const resolved = matched ? resolveActor(req, helpers) : { actor: 'anonymous' as Actor, tenant: null, sessionId: null }
    if (tooLarge) {
      send(res, mk(JSON.stringify({ error: 'payload_too_large' }), 413, 'application/json; charset=utf-8', []))
      oracle.logRequest({ method, path: pathname, routeKey: matched?.routeKey ?? null, status: 413, actor: resolved.actor, contentType, paramNames: [], suspicious: false, expectedEncoding: encoding, encodingMismatch: encodingMismatch || undefined })
      return
    }
    if (!matched) {
      send(res, mk(JSON.stringify({ error: 'not_found' }), 404, 'application/json; charset=utf-8', []))
      oracle.logRequest({ method, path: pathname, routeKey: null, status: 404, actor: resolved.actor, paramNames: [], suspicious: false })
      return
    }
    const route = matched
    const paramNames = new Set<string>(Object.keys(query))
    if (body && typeof body === 'object' && !Array.isArray(body)) for (const k of Object.keys(body as Record<string, unknown>)) paramNames.add(k)
    const ctx: RequestCtx = {
      routeKey: route.routeKey, method, path: pathname, actor: resolved.actor, tenant: resolved.tenant,
      sessionId: resolved.sessionId, inputs: [], inputSet: new Set(), startedAt: Date.now(),
    }

    const out = await runWithCtx(ctx, async (): Promise<{ r: HttpResult; suspicious: boolean }> => {
      let suspicious = false
      const note = (v: string): void => { noteInput(v); if (!suspicious && SUSPICIOUS.test(v)) suspicious = true }
      for (const v of Object.values(query)) (Array.isArray(v) ? v : [v]).forEach((x) => note(String(x)))
      for (const v of bodyValues) note(v)
      for (const v of Object.values(params)) note(v)
      for (const v of Object.values(cookies)) note(v)
      for (const [k, v] of Object.entries(req.headers)) {
        if (k.startsWith('x-') || k === 'referer' || k === 'origin') note(Array.isArray(v) ? v.join(',') : String(v ?? ''))
      }
      const pending: string[] = []
      const holder = { rec: sessions.get(resolved.sessionId) }
      const cacheOpts = route.opts.cache
      const cacheKey = cacheOpts ? cache.keyFor(route.routeKey, pathname, query, lowerHeaders(req), cacheOpts) : null
      let r: HttpResult
      const hit = cacheKey ? cache.get(cacheKey) : undefined
      if (hit) {
        detectCachePoison(oracle, canaries, hit, cacheKey!, resolved.actor, resolved.tenant)
        r = { status: hit.status, headers: { 'content-type': hit.contentType }, body: hit.body }
      } else {
        const session = createSessionHandle(sessions, cookieName, holder, (c) => pending.push(c))
        const reqCtx: ReqCtx = {
          method, path: pathname, params, query, body, cookies, headers: lowerHeaders(req),
          actor: resolved.actor, tenant: resolved.tenant, session,
          sameOrigin: sameOrigin(req, host),
          csrfValid: csrfTokenValid(holder.rec, headerStr(req, 'x-csrf-token') ?? csrfFromBody(body)),
          issueCsrfToken: () => ensureCsrfToken(sessions, holder, cookieName, (c) => pending.push(c)),
          setCsrfRejected: () => { meta.csrfRejected = true },
          json: (o, s = 200) => mk(JSON.stringify(o), s, 'application/json; charset=utf-8', pending.slice()),
          html: (h, s = 200) => mk(h, s, 'text/html; charset=utf-8', pending.slice()),
          text: (t, s = 200) => mk(t, s, 'text/plain; charset=utf-8', pending.slice()),
          redirect(location, s = 302) {
            if (offOrigin(location, host) && isFromInput(location)) oracle.emit('open_redirect', { location }, 'redirect')
            return { status: s, headers: { location, 'set-cookie': pending.slice() }, body: '' }
          },
        }
        try { r = normalize(await route.handler(reqCtx), pending) }
        catch { r = mk(JSON.stringify({ error: 'internal' }), 500, 'application/json; charset=utf-8', pending.slice()) }
        if (cacheKey && r.status >= 200 && r.status < 300) {
          cache.set(cacheKey, {
            status: r.status, body: typeof r.body === 'string' ? r.body : r.body.toString('utf8'),
            contentType: String(r.headers['content-type'] ?? ''), tenant: resolved.tenant, actor: resolved.actor,
            expiresAt: Date.now() + (cacheOpts!.ttlMs ?? 60_000),
          })
        }
      }
      const bodyStr = typeof r.body === 'string' ? r.body : r.body.toString('utf8')
      monitors?.afterRequest?.(ctx, oracle, db)
      canaries?.scanResponse(oracle, bodyStr, resolved.tenant)
      monitors?.inspectResponse?.(ctx, r, oracle)
      return { r, suspicious }
    })
    send(res, out.r)
    oracle.logRequest({
      method, path: pathname, routeKey: route.routeKey, status: out.r.status, actor: resolved.actor, contentType,
      paramNames: [...paramNames], suspicious: out.suspicious,
      csrfRejected: meta.csrfRejected || undefined, sessionLost: meta.sessionLost || undefined,
      expectedEncoding: encoding, encodingMismatch: encodingMismatch || undefined,
    })
  }

  const dispatch = (req: IncomingMessage, res: ServerResponse): void => {
    handle(req, res).catch(() => {
      if (!res.headersSent) send(res, mk(JSON.stringify({ error: 'internal' }), 500, 'application/json; charset=utf-8', []))
    })
  }
  const server = createServer(dispatch)
  const app: HttpApp = {
    route(routeKey, handler, routeOpts = {}) {
      const spec = plan.routes[routeKey]
      if (!spec) throw new Error(`createHttpApp.route: unknown routeKey '${routeKey}'`)
      routes.push({ routeKey, method: spec.method.toUpperCase(), segs: compile(spec.path), handler, opts: routeOpts })
      return app
    },
    static(dir) { uiDir = dir; return app },
    sessions,
    handle: dispatch,
    async listen() { assertLocalLabAllowed(); return listenLoopback(server) },
    close: () => closeServer(server),
    server,
  }
  return app
}
