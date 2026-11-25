import { randomBytes, timingSafeEqual } from 'node:crypto'
import { chmodSync, createReadStream, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { join, resolve } from 'node:path'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { getAppRuntime } from '../src/server/app-runtime.ts'
import type { AppRuntime } from '../src/server/app-runtime.ts'
import { configureGlobalKillSwitch } from '../src/server/kill-switch.ts'
import type { GlobalKillSwitch } from '../src/server/kill-switch.ts'
import { exportRunReceiptBundle } from '../src/server/receipt-export.ts'
import { store, TenantIsolationError } from '../src/server/store.ts'
import type { Store } from '../src/server/store.ts'

const maxBody = 8 * 1024 * 1024
const maxOpsBody = 64 * 1024
const bootstrapParam = 'bootstrap'
const defaultPairingTtlMs = 5 * 60 * 1000
const maxActivePairingTokens = 10
const pairingLinkPath = '/_kovo/auth/pairing-link'
const rotateSessionPath = '/_kovo/auth/rotate-session'
const authStatusPath = '/_kovo/auth/status'
const killSwitchPath = '/api/ops/kill-switch'
const receiptExportPathRegex = /^\/api\/runs\/([A-Za-z0-9_-]{1,128})\/receipts\/export$/

export interface LocalApp {
  fetch(request: Request): Promise<Response> | Response
}

export interface LocalSessionOptions {
  app: LocalApp
  /** Owner-only data directory that holds `local-session` and the per-start `bootstrap` secret. */
  directory: string
  port: number
  /** Optional host-mapped external loopback port (e.g. `KOVO_PORT` in Docker Compose). */
  hostPort?: number
  /** Additional HTTPS origin presented by a deliberately configured local reverse proxy. */
  publicOrigin?: string
  /** TTL for ephemeral device-pairing links in milliseconds (default: 5 minutes). */
  pairingTtlMs?: number
  /** Optional clock override for deterministic expiration tests. */
  now?: () => number
  /** Option 2 M2: optional shared AppRuntime composition root. */
  runtime?: AppRuntime
  /** v7 M4: kill-switch instance exposed at `/api/ops/kill-switch` (defaults to `AppRuntime.killSwitch`). */
  killSwitch?: GlobalKillSwitch
  /** v7 M4: optional Store handle for `/api/runs/:runId/receipts/export` and ops audit logging. */
  store?: Store
}

export interface KovoLocalServer {
  server: Server
  token: string
  bootstrapSecret: string
  bootstrapUrl(origin: string): string
  runtime?: AppRuntime
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

/**
 * The long-lived local session token lives in `<data>/local-session` (owner-only, mode 0600).
 * It is never handed to a request that arrives without an explicit bootstrap handshake.
 */
export function readOrCreateSessionToken(directory: string): string {
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const file = join(directory, 'local-session')
  try {
    writeFileSync(file, randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
  }
  if ((statSync(file).mode & 0o077) !== 0) throw new Error('The local session file must have owner-only permissions.')
  const value = readFileSync(file, 'utf8')
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid local session file.')
  return value
}

/**
 * Atomically rotates the long-lived local session token in `<data>/local-session` (mode 0600).
 * Writes a fresh 0600 temp file and renames it into place so the file is never empty or world-readable.
 */
export function rotateSessionToken(directory: string): string {
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const next = randomBytes(32).toString('hex')
  const file = join(directory, 'local-session')
  const tmp = join(directory, `.local-session.${randomBytes(8).toString('hex')}.tmp`)
  writeFileSync(tmp, next, { flag: 'wx', mode: 0o600 })
  try {
    chmodSync(tmp, 0o600)
    if ((statSync(tmp).mode & 0o077) !== 0) throw new Error('The local session file must have owner-only permissions.')
    renameSync(tmp, file)
  } catch (error) {
    rmSync(tmp, { force: true })
    throw error
  }
  return next
}

/**
 * A fresh, single-use bootstrap secret is written for every server start. The operator opens the
 * printed `?bootstrap=` URL (or reads the owner-only file); the secret is consumed after the first
 * successful handshake. A bare HTTP request from another local process does not obtain a session.
 */
export function readOrCreateBootstrapSecret(directory: string): string {
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const secret = randomBytes(32).toString('hex')
  const file = join(directory, 'bootstrap')
  writeFileSync(file, secret, { mode: 0o600 })
  chmodSync(file, 0o600)
  if ((statSync(file).mode & 0o077) !== 0) throw new Error('The bootstrap file must have owner-only permissions.')
  return secret
}

export function consumeBootstrapSecret(directory: string): void {
  rmSync(join(directory, 'bootstrap'), { force: true })
  rmSync(join(directory, 'bootstrap-url'), { force: true })
}

function isLoopbackOrigin(originUrl: string): boolean {
  try {
    const host = new URL(originUrl).hostname.toLowerCase()
    return host === '127.0.0.1' || host === 'localhost' || host === '[::1]' || host === '::1'
  } catch {
    return false
  }
}

export function isSessionAuthorized(cookieHeader: string | undefined, token: string): boolean {
  const cookies = cookieHeader?.split(';').map(cookie => cookie.trim()) ?? []
  const value = cookies.find(cookie => cookie.startsWith('kovo_local='))?.slice('kovo_local='.length)
  return Boolean(value && value.length === token.length && /^[0-9a-f]+$/.test(value)
    && constantTimeEquals(value, token))
}

export function isBootstrapAuthorized(candidate: string | null | undefined, secret: string): boolean {
  return Boolean(candidate && /^[a-f0-9]{64}$/.test(candidate) && constantTimeEquals(candidate, secret))
}

export function sessionCookie(token: string, origin: string): string {
  return `kovo_local=${token}; Path=/; HttpOnly; SameSite=Strict${origin.startsWith('https:') ? '; Secure' : ''}`
}

function bootstrapNotice(): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Kovo Hunter local session</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"></head>
<body><h1>Kovo Hunter needs a local session</h1>
<p>Open the one-time bootstrap URL printed by the Kovo Hunter server in your terminal, or read
<code>&lt;data-dir&gt;/bootstrap</code> (mode 0600) and open <code>/?bootstrap=&lt;secret&gt;</code>.</p>
<p>A plain request to this server no longer receives an owner session cookie.</p></body></html>`
}

function reject(res: ServerResponse, status: number, message: string) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' }).end(message)
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  }).end(JSON.stringify(body))
}

async function readBoundedJsonBody(req: IncomingMessage, limitBytes = maxOpsBody): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    total += buf.length
    if (total > limitBytes) {
      throw new Error('Request body is too large.')
    }
    chunks.push(buf)
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim()
  if (!raw) return {}
  const parsed = JSON.parse(raw) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Request body must be a JSON object.')
  }
  return parsed as Record<string, unknown>
}

function rejectSession(res: ServerResponse) {
  res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' }).end(bootstrapNotice())
}

const mime: Record<string, string> = {
  js: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  woff2: 'font/woff2',
  svg: 'image/svg+xml',
  png: 'image/png',
}

function allowedOrigins(port: number, publicOrigin?: string, hostPort?: number): Map<string, string> {
  const origins = new Map([
    [`127.0.0.1:${port}`, `http://127.0.0.1:${port}`],
    [`localhost:${port}`, `http://localhost:${port}`],
  ])
  if (hostPort !== undefined && Number.isInteger(hostPort) && hostPort >= 1 && hostPort <= 65535 && hostPort !== port) {
    origins.set(`127.0.0.1:${hostPort}`, `http://127.0.0.1:${hostPort}`)
    origins.set(`localhost:${hostPort}`, `http://localhost:${hostPort}`)
  }
  // A deliberately configured local reverse proxy can present one additional origin.
  if (publicOrigin) {
    const proxy = new URL(publicOrigin)
    if (proxy.protocol !== 'https:' || proxy.origin !== publicOrigin) {
      throw new Error('KOVO_PUBLIC_ORIGIN must be a single HTTPS origin.')
    }
    origins.set(proxy.host, proxy.origin)
  }
  return origins
}

const allowedListenHosts = new Set(['127.0.0.1', '0.0.0.0', '::1', '::'])

function resolveListenHost(rawHost: string | undefined): string {
  const host = rawHost?.trim() || '127.0.0.1'
  if (!allowedListenHosts.has(host)) {
    throw new Error('KOVO_LISTEN_HOST must be 127.0.0.1, 0.0.0.0, ::1, or ::.')
  }
  return host
}

function parseOptionalPort(rawPort: string | undefined): number | undefined {
  const trimmed = rawPort?.trim()
  if (!trimmed) return undefined
  if (!/^\d{1,5}$/.test(trimmed)) {
    throw new Error('KOVO_PORT must be a TCP port between 1 and 65535.')
  }
  const parsed = Number(trimmed)
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error('KOVO_PORT must be a TCP port between 1 and 65535.')
  }
  return parsed
}

/**
 * Build the production local server. Session issuance requires either an existing owner session
 * cookie or a single-use bootstrap secret that is only available to the owner (terminal URL or a
 * mode-0600 file). The application handler is never invoked for an unauthenticated document.
 */
export function createKovoLocalServer(options: LocalSessionOptions): KovoLocalServer {
  const { app, directory, port } = options
  const origins = allowedOrigins(port, options.publicOrigin, options.hostPort)
  const pairingTtlMs = options.pairingTtlMs ?? defaultPairingTtlMs
  const now = options.now ?? Date.now
  const runtime = options.runtime
  const killSwitch = options.killSwitch ?? runtime?.killSwitch ?? getAppRuntime({ dataDir: directory }).killSwitch
  const storeHandle = options.store ?? runtime?.store
  let token = readOrCreateSessionToken(directory)
  const secret = readOrCreateBootstrapSecret(directory)
  let bootstrapConsumed = false
  const pairingTokens = new Map<string, number>()
  const clientRoot = resolve('build/client')
  const publicRoot = resolve('public')

  function prunePairingTokens(currentMs: number): void {
    for (const [candidate, expiresAtMs] of pairingTokens) {
      if (expiresAtMs <= currentMs) pairingTokens.delete(candidate)
    }
  }

  function mintPairingToken(): { token: string; expiresAtMs: number } {
    const currentMs = now()
    prunePairingTokens(currentMs)
    while (pairingTokens.size >= maxActivePairingTokens) {
      const oldest = pairingTokens.keys().next().value
      if (oldest === undefined) break
      pairingTokens.delete(oldest)
    }
    const pairingToken = randomBytes(32).toString('hex')
    const expiresAtMs = currentMs + pairingTtlMs
    pairingTokens.set(pairingToken, expiresAtMs)
    return { token: pairingToken, expiresAtMs }
  }

  function consumePairingToken(candidate: string, currentMs: number): boolean {
    prunePairingTokens(currentMs)
    if (!/^[a-f0-9]{64}$/.test(candidate)) return false
    let matchedKey: string | undefined
    for (const [stored, expiresAtMs] of pairingTokens) {
      if (expiresAtMs > currentMs && constantTimeEquals(candidate, stored)) {
        matchedKey = stored
      }
    }
    if (!matchedKey) return false
    pairingTokens.delete(matchedKey)
    return true
  }

  async function serve(req: IncomingMessage, res: ServerResponse) {
    const origin = origins.get(req.headers.host ?? '')
    const method = req.method ?? 'GET'
    const readOnly = method === 'GET' || method === 'HEAD'
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('Cache-Control', 'no-store')
    if (!origin) return reject(res, 421, 'Unexpected host.')
    const path = new URL(req.url ?? '/', origin)
    if (path.origin !== origin) return reject(res, 421, 'Unexpected request URL.')
    if (!readOnly && req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
    if (readOnly && path.pathname === '/health') return reject(res, 200, 'ok')

    if (readOnly && (path.pathname === '/favicon.svg' || path.pathname === '/favicon-stealth.svg' || /^\/brand\/[A-Za-z0-9._-]+\.svg$/.test(path.pathname))) {
      const relPath = path.pathname.slice(1)
      let file = join(clientRoot, relPath)
      let size: number
      try {
        size = statSync(file).size
      } catch {
        file = join(publicRoot, relPath)
        try {
          size = statSync(file).size
        } catch {
          return reject(res, 404, 'Asset not found.')
        }
      }
      res.writeHead(200, {
        'Content-Type': mime.svg,
        'Content-Length': size,
        'Cache-Control': 'public, max-age=86400',
      })
      if (method === 'HEAD') return res.end()
      await pipeline(createReadStream(file), res)
      return
    }

    if (readOnly && /^\/assets\/[A-Za-z0-9._-]+\.(?:js|css|woff2|svg|png)$/.test(path.pathname)) {
      const file = join(clientRoot, 'assets', path.pathname.split('/').at(-1)!)
      let size: number
      try {
        size = statSync(file).size
      } catch {
        return reject(res, 404, 'Asset not found.')
      }
      const extension = file.split('.').at(-1)!
      res.writeHead(200, {
        'Content-Type': mime[extension], 'Content-Length': size, 'Cache-Control': 'public, max-age=31536000, immutable',
      })
      if (method === 'HEAD') return res.end()
      await pipeline(createReadStream(file), res)
      return
    }

    // Explicit, owner-only bootstrap handshake. Accepts either the per-start secret or an active
    // ephemeral pairing token; both are consumed on first successful handshake (strictly single-use).
    const bootstrapCandidate = path.searchParams.get(bootstrapParam)
    if (method === 'GET' && bootstrapCandidate !== null) {
      const currentMs = now()
      let authorized = false
      if (!bootstrapConsumed && isBootstrapAuthorized(bootstrapCandidate, secret)) {
        bootstrapConsumed = true
        consumeBootstrapSecret(directory)
        authorized = true
      } else if (consumePairingToken(bootstrapCandidate, currentMs)) {
        authorized = true
      }
      if (!authorized) {
        return reject(res, 401, 'Invalid or already consumed bootstrap secret.')
      }
      path.searchParams.delete(bootstrapParam)
      res.setHeader('set-cookie', sessionCookie(token, origin))
      res.writeHead(303, { location: path.pathname + (path.search || '') })
      return res.end()
    }

    const session = isSessionAuthorized(req.headers.cookie, token)
    if (!session) {
      if (req.headers['sec-fetch-site'] === 'cross-site') return reject(res, 403, 'Open Kovo Hunter directly.')
      if (
        path.pathname.startsWith('/_kovo/auth/') ||
        path.pathname.startsWith('/api/ops/') ||
        receiptExportPathRegex.test(path.pathname)
      ) {
        return sendJson(res, 401, { error: 'Local session required.' })
      }
      return rejectSession(res)
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') return reject(res, 403, 'Open Kovo Hunter directly.')
    if (Number(req.headers['content-length'] ?? 0) > maxBody) return reject(res, 413, 'Request body is too large.')

    // v7 M4 Production Ops: global < 2s kill-switch control endpoint.
    if (path.pathname === killSwitchPath) {
      if (method === 'GET' || method === 'HEAD') {
        const queryTenantId = path.searchParams.get('tenantId')?.trim() || null
        const state = killSwitch.status(queryTenantId)
        return sendJson(res, 200, state)
      }
      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      let body: Record<string, unknown>
      try {
        body = await readBoundedJsonBody(req)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Invalid JSON body.'
        return sendJson(res, msg.includes('too large') ? 413 : 400, { error: msg })
      }
      const action = typeof body.action === 'string' ? body.action.toLowerCase() : 'trip'
      if (action !== 'trip' && action !== 'reset') {
        return sendJson(res, 400, { error: 'action must be "trip" or "reset".' })
      }
      const tenantId = typeof body.tenantId === 'string' && body.tenantId.trim() ? body.tenantId.trim() : null
      const state = action === 'trip'
        ? killSwitch.trip({
            reason: typeof body.reason === 'string' && body.reason.trim()
              ? body.reason.trim()
              : 'Operator triggered emergency kill switch via HTTP API.',
            trippedBy: 'operator:http',
            tenantId,
            now: now(),
          })
        : killSwitch.reset({ resetBy: 'operator:http', ...(tenantId ? { tenantId } : {}), now: now() })
      if (storeHandle) {
        try {
          storeHandle.appendTenantAuditLog({
            tenantId: tenantId ?? 'default',
            actor: 'operator:http',
            action: action === 'trip' ? 'ops.kill_switch.tripped' : 'ops.kill_switch.reset',
            resourceKind: 'kill_switch',
            outcome: action === 'trip' ? 'tripped' : 'allowed',
            detail: { reason: state.reason, generation: state.generation, scope: tenantId ? 'tenant' : 'global' },
            now: now(),
          })
        } catch {
          // Never block kill-switch response if audit log write fails.
        }
      }
      return sendJson(res, 200, state)
    }

    // v7 M4 Production Ops: portable signed ProofReceipt bundle export.
    const receiptMatch = receiptExportPathRegex.exec(path.pathname)
    if (receiptMatch) {
      if (method !== 'GET') return reject(res, 405, 'Method not allowed.')
      if (!storeHandle) {
        return sendJson(res, 503, { error: 'Store is not attached to this local server.' })
      }
      const runId = receiptMatch[1]!
      const zdrParam = path.searchParams.get('zdr')
      const zdr = zdrParam === '1' || zdrParam === 'true'
        ? true
        : zdrParam === '0' || zdrParam === 'false'
          ? false
          : undefined
      const tenantId = path.searchParams.get('tenantId')?.trim() || undefined
      try {
        const bundle = exportRunReceiptBundle(storeHandle, runId, {
          ...(zdr !== undefined ? { zdr } : {}),
          ...(tenantId ? { tenantId } : {}),
          actor: 'operator:http',
          now: now(),
        })
        return sendJson(res, 200, bundle, {
          'content-disposition': `attachment; filename="kovo-receipts-${runId.slice(0, 12)}.json"`,
        })
      } catch (err) {
        if (err instanceof TenantIsolationError) {
          return sendJson(res, 403, { error: err.message, code: err.code })
        }
        const message = err instanceof Error ? err.message : 'Unable to export run receipts.'
        if (/unknown run|not found/i.test(message)) {
          return sendJson(res, 404, { error: message })
        }
        return sendJson(res, 500, { error: message })
      }
    }

    // Authenticated local-server session management endpoints (never exposed without an active
    // kovo_local session cookie; mutating endpoints also require exact matching Origin header).
    if (path.pathname === authStatusPath) {
      if (method !== 'GET' && method !== 'HEAD') return reject(res, 405, 'Method not allowed.')
      prunePairingTokens(now())
      const payload = {
        authenticated: true,
        origin,
        loopbackOnly: isLoopbackOrigin(origin),
        publicOriginConfigured: Boolean(options.publicOrigin),
        activePairingLinks: pairingTokens.size,
        pairingTtlSeconds: Math.round(pairingTtlMs / 1000),
      }
      if (method === 'HEAD') {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        }).end()
        return
      }
      return sendJson(res, 200, payload)
    }

    if (path.pathname === pairingLinkPath) {
      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      req.resume()
      const minted = mintPairingToken()
      return sendJson(res, 200, {
        url: `${origin}/?${bootstrapParam}=${minted.token}`,
        expiresAt: new Date(minted.expiresAtMs).toISOString(),
        ttlSeconds: Math.round(pairingTtlMs / 1000),
      })
    }

    if (path.pathname === rotateSessionPath) {
      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      req.resume()
      token = rotateSessionToken(directory)
      pairingTokens.clear()
      bootstrapConsumed = true
      consumeBootstrapSecret(directory)
      res.setHeader('set-cookie', sessionCookie(token, origin))
      return sendJson(res, 200, { rotated: true })
    }

    if (path.pathname.startsWith('/_kovo/auth/')) {
      return reject(res, 404, 'Not found.')
    }

    const headers = new Headers()
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined && !name.startsWith('x-forwarded-') && name !== 'forwarded') {
        for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item)
      }
    }

    const abort = new AbortController()
    const unsubscribeSseRevocation = path.pathname.endsWith('/events')
      ? killSwitch.onSseRevocation(() => {
          if (!abort.signal.aborted) abort.abort()
        })
      : null
    res.once('close', () => {
      unsubscribeSseRevocation?.()
      abort.abort()
    })
    let received = 0
    const limiter = new Transform({
      transform(chunk, _encoding, done) {
        received += chunk.length
        if (received > maxBody) done(new Error('Request body is too large.'))
        else done(null, chunk)
      },
    })
    if (!readOnly) req.pipe(limiter)
    const body = readOnly ? undefined : Readable.toWeb(limiter) as ReadableStream<Uint8Array>
    const request = new Request(path, {
      method, headers, body, signal: abort.signal, ...(body ? { duplex: 'half' } : {}),
    } as RequestInit)
    const response = await app.fetch(request)
    for (const [name, value] of response.headers) {
      if (name !== 'set-cookie') res.setHeader(name, value)
    }
    const cookies = response.headers.getSetCookie()
    if (cookies.length) res.setHeader('set-cookie', cookies)
    res.writeHead(response.status)
    if (!response.body || method === 'HEAD') return res.end()
    await pipeline(Readable.fromWeb(response.body as import('node:stream/web').ReadableStream), res)
  }

  const server = createServer((req, res) => {
    void serve(req, res).catch(() => {
      if (res.destroyed) return
      if (!res.headersSent) reject(res, 500, 'Kovo Hunter could not complete the request.')
      else res.end()
    })
  })

  return {
    server,
    get token() {
      return token
    },
    bootstrapSecret: secret,
    bootstrapUrl: (origin: string) => `${origin}/?${bootstrapParam}=${secret}`,
    ...(runtime ? { runtime } : {}),
  }
}

async function main() {
  const directory = resolve(process.env.KOVO_DATA_DIR ?? '.kovo')
  const port = Number(process.env.PORT ?? 8000)
  const hostPort = parseOptionalPort(process.env.KOVO_PORT)
  const listenHost = resolveListenHost(process.env.KOVO_LISTEN_HOST)
  const killSwitchFilePath = join(directory, 'kill-switch.json')
  const runtime = getAppRuntime({
    dataDir: directory,
    killSwitchFilePath,
  })
  const serverEntry = new URL('../build/server/server.js', import.meta.url).href
  const { default: app, initialize } = await import(serverEntry) as {
    default: LocalApp
    initialize: (options?: { dataDir?: string; killSwitchFilePath?: string }) => AppRuntime | void
  }

  initialize({ dataDir: directory, killSwitchFilePath })

  const sharedStore = store()
  const sharedKillSwitch = configureGlobalKillSwitch({
    filePath: killSwitchFilePath,
  })

  const local = createKovoLocalServer({
    app,
    directory,
    port,
    ...(hostPort !== undefined ? { hostPort } : {}),
    publicOrigin: process.env.KOVO_PUBLIC_ORIGIN || undefined,
    runtime,
    killSwitch: sharedKillSwitch,
    store: sharedStore,
  })

  let shuttingDown = false
  const shutdown = () => {
    if (shuttingDown) return
    shuttingDown = true
    local.server.closeAllConnections?.()
    local.server.close(() => {
      void runtime.dispose().finally(() => process.exit(0))
    })
  }
  process.once('SIGTERM', shutdown)
  process.once('SIGINT', shutdown)

  const externalPort = hostPort ?? port
  const origin = process.env.KOVO_PUBLIC_ORIGIN || `http://127.0.0.1:${externalPort}`
  local.server.listen(port, listenHost, () => {
    const bootstrapFile = join(directory, 'bootstrap-url')
    writeFileSync(bootstrapFile, `${local.bootstrapUrl(`http://127.0.0.1:${externalPort}`)}\n`, { mode: 0o600 })
    chmodSync(bootstrapFile, 0o600)
    console.log(`Kovo Hunter listening on http://${listenHost}:${port}`)
    console.log(`Open Kovo Hunter with the one-time bootstrap URL: ${local.bootstrapUrl(origin)}`)
  })
}

if (import.meta.main) await main()
