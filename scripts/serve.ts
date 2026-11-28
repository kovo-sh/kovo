import { randomBytes, timingSafeEqual } from 'node:crypto'
import { chmodSync, createReadStream, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { join, resolve } from 'node:path'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { assetOriginForEnvironment, isLocalLabEnvEnabled } from '../src/domain.ts'
import { getAppRuntime } from '../src/server/app-runtime.ts'
import type { AppRuntime } from '../src/server/app-runtime.ts'
import {
  BrowserCaptureManager,
  updateBrowserSessionPersonaMeta,
  wwwSiblingOrigin,
} from '../src/server/browser-session-auth.ts'
import type { CaptureKeyInput, CaptureMouseInput } from '../src/server/browser-session-auth.ts'
import { configureGlobalKillSwitch } from '../src/server/kill-switch.ts'
import type { GlobalKillSwitch } from '../src/server/kill-switch.ts'
import {
  clearQaAnomalies,
  isQaAnomaliesEnabled,
  listQaAnomalies,
  QA_ANOMALIES_MAX_ENTRIES,
  qaAnomalyKinds,
  recordQaAnomaly,
} from '../src/server/qa-anomalies.ts'
import type { QaAnomalyKind } from '../src/server/qa-anomalies.ts'
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
const authCaptureStartPath = '/_kovo/auth-capture/start'
const authCapturePersonaConfigPath = '/_kovo/auth-capture/persona-config'
const authCaptureActionRegex = /^\/_kovo\/auth-capture\/([A-Za-z0-9_-]{6,128})\/(stream|input|complete|cancel)$/
const qaAnomaliesPath = '/_kovo/qa/anomalies'
const validQaAnomalyKinds: ReadonlySet<string> = new Set(qaAnomalyKinds)
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
  /** Option 4: optional browser capture manager for `/_kovo/auth-capture/*` interactive login capture. */
  captureManager?: BrowserCaptureManager
  /** Optional request body byte limit override for proxied app requests (defaults to 8 MiB). */
  maxBodyBytes?: number
  /** Optional callback invoked (throttled) when an unauthenticated visit arrives before bootstrap is consumed. */
  onBootstrapRemind?: (origin: string) => void
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

const pinnedOriginFilename = 'pinned-origin'
const bootstrapReminderThrottleMs = 30_000
const bootstrapRateWindowMs = 60_000
const maxFailedBootstrapAttempts = 20
const validHostHeaderRegex = /^[a-z0-9.-]+(?::[0-9]{1,5})?$/i

export function readPinnedOrigin(directory: string): string | undefined {
  const file = join(directory, pinnedOriginFilename)
  let raw: string
  try {
    if ((statSync(file).mode & 0o077) !== 0) return undefined
    raw = readFileSync(file, 'utf8').trim()
  } catch {
    return undefined
  }
  if (!raw) return undefined
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'https:' || parsed.origin !== raw) return undefined
    return parsed.origin
  } catch {
    return undefined
  }
}

export function writePinnedOrigin(directory: string, origin: string): void {
  const parsed = new URL(origin)
  if (parsed.protocol !== 'https:' || parsed.origin !== origin) {
    throw new Error('Pinned origin must be a single HTTPS origin.')
  }
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  const file = join(directory, pinnedOriginFilename)
  const tmp = join(directory, `.${pinnedOriginFilename}.${randomBytes(8).toString('hex')}.tmp`)
  writeFileSync(tmp, `${parsed.origin}\n`, { flag: 'wx', mode: 0o600 })
  try {
    chmodSync(tmp, 0o600)
    if ((statSync(tmp).mode & 0o077) !== 0) throw new Error('The pinned origin file must have owner-only permissions.')
    renameSync(tmp, file)
  } catch (error) {
    rmSync(tmp, { force: true })
    throw error
  }
}

function isHttpsForwardedRequest(req: IncomingMessage): boolean {
  const rawProto = req.headers['x-forwarded-proto']
  const firstProto = (Array.isArray(rawProto) ? rawProto[0] : rawProto ?? '').split(',')[0]?.trim().toLowerCase()
  if (firstProto === 'https') return true
  const rawScheme = req.headers['x-forwarded-scheme']
  const firstScheme = (Array.isArray(rawScheme) ? rawScheme[0] : rawScheme ?? '').split(',')[0]?.trim().toLowerCase()
  if (firstScheme === 'https') return true
  const rawForwarded = req.headers.forwarded
  const firstForwarded = (Array.isArray(rawForwarded) ? rawForwarded[0] : rawForwarded ?? '').split(',')[0] ?? ''
  return /(?:^|[;\s])proto\s*=\s*"?https"?(?:$|[;\s])/i.test(firstForwarded)
}

function isTopLevelDocumentNavigation(req: IncomingMessage): boolean {
  const mode = (Array.isArray(req.headers['sec-fetch-mode']) ? req.headers['sec-fetch-mode'][0] : req.headers['sec-fetch-mode'] ?? '').trim().toLowerCase()
  const dest = (Array.isArray(req.headers['sec-fetch-dest']) ? req.headers['sec-fetch-dest'][0] : req.headers['sec-fetch-dest'] ?? '').trim().toLowerCase()
  return mode === 'navigate' && dest === 'document'
}

function parseHttpsForwardedHost(req: IncomingMessage): { host: string; origin: string } | null {
  if (!isHttpsForwardedRequest(req)) return null
  const rawHost = (req.headers.host ?? '').trim().toLowerCase()
  if (!rawHost || !validHostHeaderRegex.test(rawHost)) return null
  const normalizedHost = rawHost.endsWith(':443') ? rawHost.slice(0, -4) : rawHost
  if (!normalizedHost) return null
  try {
    const parsed = new URL(`https://${normalizedHost}`)
    if (parsed.protocol !== 'https:' || parsed.host !== normalizedHost || isLoopbackOrigin(parsed.origin)) return null
    return { host: parsed.host, origin: parsed.origin }
  } catch {
    return null
  }
}

export function formatBootstrapBanner(options: {
  localUrl: string
  secret: string
  publicOrigin?: string
}): string {
  const lines = [
    '',
    '========================================================================',
    '  Kovo is ready — sign in with your one-time setup link or token',
    '',
    `  Local URL : ${options.localUrl}`,
    `  Token     : ${options.secret}`,
  ]
  if (options.publicOrigin) {
    lines.push(`  Public URL: ${options.publicOrigin}/?${bootstrapParam}=${options.secret}`)
  } else {
    lines.push('')
    lines.push('  Behind an HTTPS proxy (exe.dev, Fly, Tailscale, Caddy)?')
    lines.push('  Open your https://... URL and paste the token above (auto-pins host).')
  }
  lines.push('  Retrieve anytime: docker compose exec kovo cat /data/bootstrap')
  lines.push('========================================================================')
  lines.push('')
  return lines.join('\n')
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

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] ?? ch))
}

function bootstrapNotice(options: { bootstrapActive?: boolean; hostHint?: string } = {}): string {
  const active = options.bootstrapActive !== false
  const hostNote = options.hostHint
    ? `<p class="hint">Signing in will pin <code>${escapeHtml(options.hostHint)}</code> as this Kovo instance's authorized HTTPS origin.</p>`
    : ''
  const subtitle = active
    ? 'Paste the one-time setup token printed in your Kovo terminal to start a local owner session.'
    : 'The startup bootstrap token has already been consumed. Paste an active pairing token, or restart Kovo to generate a fresh one-time token.'
  const cmdHint = active
    ? 'docker compose exec kovo cat /data/bootstrap'
    : 'docker compose restart kovo'
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to Kovo</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
:root{color-scheme:light dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;--bg:#fbfbfa;--card:#fff;--line:#e4e4e7;--field-line:#d4d4d8;--fg:#18181b;--muted:#71717a;--sunk:#f4f4f5;--cta:#18181b;--cta-fg:#fff;--ring:rgba(47,95,223,.35);--ring-soft:rgba(47,95,223,.09);--shadow:0 8px 30px rgba(0,0,0,.06)}
@media(prefers-color-scheme:dark){:root{--bg:#141416;--card:#1c1c20;--line:#2e2e34;--field-line:#3a3a42;--fg:#f4f4f5;--muted:#a1a1aa;--sunk:#121215;--cta:#f4f4f5;--cta-fg:#141416;--ring:rgba(108,147,255,.45);--ring-soft:rgba(108,147,255,.14);--shadow:0 8px 30px rgba(0,0,0,.4)}}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;grid-template-columns:minmax(0,460px);justify-content:center;align-content:center;padding:24px 16px;background:var(--bg);color:var(--fg)}
.card{min-width:0;width:100%;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;box-shadow:var(--shadow)}
@media(max-width:420px){.card{padding:22px 18px}}
h1{margin:0 0 8px;font-size:20px;font-weight:600;color:var(--fg)}
p{margin:0 0 16px;font-size:14px;line-height:1.5;color:var(--muted)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
form{display:flex;flex-direction:column;gap:12px;margin:16px 0}
input{width:100%;min-width:0;padding:10px 12px;font:16px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--fg);background:var(--card);border:1px solid var(--field-line);border-radius:8px}
input::placeholder{color:var(--muted);font-size:14px}
input:focus-visible{outline:none;border-color:transparent;box-shadow:0 0 0 1px var(--ring),0 0 0 3px var(--ring-soft)}
button{padding:10px 14px;font:inherit;font-size:14px;font-weight:600;border:0;border-radius:8px;background:var(--cta);color:var(--cta-fg);cursor:pointer}
button:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
.hint{font-size:13px}
pre{margin:8px 0 0;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--sunk);color:var(--fg);font:12px ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-all}
</style></head><body><main class="card"><h1>Sign in to Kovo</h1><p>${subtitle}</p>${hostNote}<form method="GET" action="/"><input type="password" name="${bootstrapParam}" placeholder="Paste 64-character one-time token" autocomplete="off" spellcheck="false" autofocus required><button type="submit">Sign in</button></form><p class="hint">Missed the terminal banner? Run:</p><pre>${cmdHint}</pre></main></body></html>`
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

const TENANT_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/

class BodyTooLargeError extends Error {
  constructor() {
    super('Request body is too large.')
    this.name = 'BodyTooLargeError'
  }
}

function isBodyTooLargeError(err: unknown): boolean {
  if (err instanceof BodyTooLargeError) return true
  if (err && typeof err === 'object' && 'cause' in err) {
    return (err as { cause?: unknown }).cause instanceof BodyTooLargeError
  }
  return false
}

/**
 * Strict Fetch Metadata (`Sec-Fetch-Site`) control-plane guard:
 * - Mutating requests (`!readOnly`) only permit `same-origin` (or absent for non-browser callers,
 *   which are still bound by exact `Origin` equality). Loose `same-site` / `cross-site` / `none`
 *   are rejected to prevent sibling-subdomain CSRF.
 * - Read-only requests (`GET` / `HEAD`) permit `same-origin`, `none` (direct address-bar navigation),
 *   or absent header, and reject both `same-site` and `cross-site`.
 */
export function isAllowedSecFetchSite(
  rawHeader: string | string[] | undefined,
  readOnly: boolean,
): boolean {
  const first = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader
  if (first === undefined) return true
  const normalized = first.trim().toLowerCase()
  if (!normalized) return true
  if (!readOnly) return normalized === 'same-origin'
  return normalized === 'same-origin' || normalized === 'none'
}

function parseOptionalTenantId(raw: unknown): { ok: true; value: string | null } | { ok: false; error: string } {
  if (raw === undefined || raw === null) return { ok: true, value: null }
  if (typeof raw !== 'string') return { ok: false, error: 'tenantId must be a string.' }
  const trimmed = raw.trim()
  if (!trimmed) return { ok: true, value: null }
  if (!TENANT_ID_RE.test(trimmed)) {
    return { ok: false, error: 'Invalid tenantId format.' }
  }
  return { ok: true, value: trimmed }
}

function shouldReturnJsonAuthError(pathname: string): boolean {
  return (
    pathname.startsWith('/_kovo/auth/')
    || pathname.startsWith('/_kovo/auth-capture')
    || pathname.startsWith('/_kovo/qa/')
    || pathname.startsWith('/api/')
    || pathname.startsWith('/_serverFn/')
    || receiptExportPathRegex.test(pathname)
  )
}

async function readBoundedJsonBody(req: IncomingMessage, limitBytes = maxOpsBody): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let total = 0
  try {
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      total += buf.length
      if (total > limitBytes) {
        req.resume()
        throw new BodyTooLargeError()
      }
      chunks.push(buf)
    }
  } catch (err) {
    if (err instanceof BodyTooLargeError) throw err
    throw new Error('Failed to read request body.')
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim()
  if (!raw) return {}
  const parsed = JSON.parse(raw) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Request body must be a JSON object.')
  }
  return parsed as Record<string, unknown>
}

function rejectSession(res: ServerResponse, options?: { bootstrapActive?: boolean; hostHint?: string }) {
  res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' }).end(bootstrapNotice(options))
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
    origins.set(proxy.host.toLowerCase(), proxy.origin)
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
  const explicitPublicOrigin = Boolean(options.publicOrigin)
  if (!explicitPublicOrigin) {
    const persistedPinned = readPinnedOrigin(directory)
    if (persistedPinned) {
      const parsedPinned = new URL(persistedPinned)
      origins.set(parsedPinned.host.toLowerCase(), parsedPinned.origin)
    }
  }
  const pairingTtlMs = options.pairingTtlMs ?? defaultPairingTtlMs
  const now = options.now ?? Date.now
  const runtime = options.runtime
  const killSwitch = options.killSwitch ?? runtime?.killSwitch ?? getAppRuntime({ dataDir: directory }).killSwitch
  const storeHandle = options.store ?? runtime?.store
  const captureManager = options.captureManager ?? new BrowserCaptureManager()
  const bodyLimit = Math.max(256, Math.floor(options.maxBodyBytes ?? maxBody))
  let token = readOrCreateSessionToken(directory)
  const secret = readOrCreateBootstrapSecret(directory)
  let bootstrapConsumed = false
  let lastBootstrapReminderMs = -Infinity
  const failedBootstrapAttempts: number[] = []
  const pairingTokens = new Map<string, number>()
  const clientRoot = resolve('build/client')
  const publicRoot = resolve('public')

  function pruneFailedBootstrapAttempts(currentMs: number): void {
    const cutoff = currentMs - bootstrapRateWindowMs
    while (failedBootstrapAttempts.length > 0 && failedBootstrapAttempts[0]! <= cutoff) {
      failedBootstrapAttempts.shift()
    }
  }

  function isBootstrapRateLimited(currentMs: number): boolean {
    pruneFailedBootstrapAttempts(currentMs)
    return failedBootstrapAttempts.length >= maxFailedBootstrapAttempts
  }

  function recordFailedBootstrapAttempt(currentMs: number): void {
    pruneFailedBootstrapAttempts(currentMs)
    failedBootstrapAttempts.push(currentMs)
  }

  function maybeRemindBootstrap(targetOrigin: string): void {
    if (bootstrapConsumed || !options.onBootstrapRemind) return
    const currentMs = now()
    if (currentMs - lastBootstrapReminderMs < bootstrapReminderThrottleMs) return
    lastBootstrapReminderMs = currentMs
    options.onBootstrapRemind(targetOrigin)
  }

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
    const hostKey = (req.headers.host ?? '').trim().toLowerCase()
    let origin = origins.get(hostKey)
    if (!origin && hostKey.endsWith(':443')) {
      const candidate = origins.get(hostKey.slice(0, -4))
      if (candidate?.startsWith('https://')) origin = candidate
    }
    const method = req.method ?? 'GET'
    const readOnly = method === 'GET' || method === 'HEAD'
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'no-referrer')
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('Cache-Control', 'no-store')
    if (!origin) {
      // Zero-config TOFU HTTPS host pinning: only active while bootstrap is unconsumed, no explicit
      // KOVO_PUBLIC_ORIGIN is configured, and the request arrived over an HTTPS reverse proxy
      // (X-Forwarded-Proto: https / Forwarded: proto=https). Plain HTTP unknown hosts fail closed with 421.
      const httpsCandidate = !explicitPublicOrigin && !bootstrapConsumed && method === 'GET'
        ? parseHttpsForwardedHost(req)
        : null
      if (!httpsCandidate) return reject(res, 421, 'Unexpected host.')
      const candidateUrl = new URL(req.url ?? '/', httpsCandidate.origin)
      if (candidateUrl.origin !== httpsCandidate.origin) return reject(res, 421, 'Unexpected request URL.')
      const candidateBootstrap = candidateUrl.searchParams.get(bootstrapParam)
      if (candidateBootstrap !== null) {
        const currentMs = now()
        if (isBootstrapRateLimited(currentMs)) {
          return reject(res, 429, 'Too many bootstrap attempts. Try again in a minute.')
        }
        if (!isBootstrapAuthorized(candidateBootstrap, secret)) {
          recordFailedBootstrapAttempt(currentMs)
          return reject(res, 421, 'Unexpected host.')
        }
        writePinnedOrigin(directory, httpsCandidate.origin)
        origins.set(httpsCandidate.host, httpsCandidate.origin)
        origin = httpsCandidate.origin
        bootstrapConsumed = true
        consumeBootstrapSecret(directory)
        candidateUrl.searchParams.delete(bootstrapParam)
        res.setHeader('set-cookie', sessionCookie(token, origin))
        res.writeHead(303, { location: candidateUrl.pathname + (candidateUrl.search || '') })
        return res.end()
      }
      if (
        candidateUrl.pathname === '/'
        && (isAllowedSecFetchSite(req.headers['sec-fetch-site'], true) || isTopLevelDocumentNavigation(req))
      ) {
        maybeRemindBootstrap(httpsCandidate.origin)
        return rejectSession(res, { bootstrapActive: true, hostHint: httpsCandidate.origin })
      }
      return reject(res, 421, 'Unexpected host.')
    }
    const path = new URL(req.url ?? '/', origin)
    if (path.origin !== origin) return reject(res, 421, 'Unexpected request URL.')
    if (!readOnly) {
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      if (!isAllowedSecFetchSite(req.headers['sec-fetch-site'], false)) {
        return reject(res, 403, 'Cross-origin request rejected.')
      }
    }
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
      if (isBootstrapRateLimited(currentMs)) {
        return reject(res, 429, 'Too many bootstrap attempts. Try again in a minute.')
      }
      let authorized = false
      if (!bootstrapConsumed && isBootstrapAuthorized(bootstrapCandidate, secret)) {
        bootstrapConsumed = true
        consumeBootstrapSecret(directory)
        authorized = true
      } else if (consumePairingToken(bootstrapCandidate, currentMs)) {
        authorized = true
      }
      if (!authorized) {
        recordFailedBootstrapAttempt(currentMs)
        return reject(res, 401, 'Invalid or already consumed bootstrap secret.')
      }
      path.searchParams.delete(bootstrapParam)
      res.setHeader('set-cookie', sessionCookie(token, origin))
      res.writeHead(303, { location: path.pathname + (path.search || '') })
      return res.end()
    }

    const session = isSessionAuthorized(req.headers.cookie, token)
    if (!isAllowedSecFetchSite(req.headers['sec-fetch-site'], readOnly)) {
      return reject(res, 403, 'Open Kovo directly.')
    }
    if (!session) {
      if (shouldReturnJsonAuthError(path.pathname)) {
        if (method === 'HEAD') {
          res.writeHead(401, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
            'x-kovo-auth': 'expired',
          }).end()
          return
        }
        return sendJson(res, 401, { error: 'Local session required.', code: 'SESSION_EXPIRED' }, {
          'x-kovo-auth': 'expired',
        })
      }
      if (method === 'HEAD') {
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'x-kovo-auth': 'expired' }).end()
        return
      }
      if (method === 'GET' && path.pathname === '/') maybeRemindBootstrap(origin)
      return rejectSession(res, { bootstrapActive: !bootstrapConsumed })
    }
    if (Number(req.headers['content-length'] ?? 0) > bodyLimit) return reject(res, 413, 'Request body is too large.')

    // v7 M4 Production Ops: global < 2s kill-switch control endpoint.
    if (path.pathname === killSwitchPath) {
      if (method === 'GET' || method === 'HEAD') {
        const tenantCheck = parseOptionalTenantId(path.searchParams.get('tenantId'))
        if (!tenantCheck.ok) return sendJson(res, 400, { error: tenantCheck.error })
        const state = killSwitch.status(tenantCheck.value)
        if (method === 'HEAD') {
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end()
          return
        }
        return sendJson(res, 200, state)
      }
      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      let body: Record<string, unknown>
      try {
        body = await readBoundedJsonBody(req)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Invalid JSON body.'
        return sendJson(res, isBodyTooLargeError(err) || msg.includes('too large') ? 413 : 400, { error: msg })
      }
      const action = typeof body.action === 'string' ? body.action.toLowerCase() : 'trip'
      if (action !== 'trip' && action !== 'reset') {
        return sendJson(res, 400, { error: 'action must be "trip" or "reset".' })
      }
      const tenantCheck = parseOptionalTenantId(body.tenantId)
      if (!tenantCheck.ok) return sendJson(res, 400, { error: tenantCheck.error })
      const tenantId = tenantCheck.value
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
      const tenantCheck = parseOptionalTenantId(path.searchParams.get('tenantId'))
      if (!tenantCheck.ok) return sendJson(res, 400, { error: tenantCheck.error })
      const tenantId = tenantCheck.value ?? undefined
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
        if (isQaAnomaliesEnabled()) {
          recordQaAnomaly({
            kind: 'unexpected_ui_rpc_error',
            routeOrOrigin: path.pathname,
            summary: `Receipt export failed with HTTP 500: ${message}`,
            detail: {
              source: 'serve_receipt_export',
              method,
              statusCode: 500,
            },
          })
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
          'x-kovo-auth': 'ok',
        }).end()
        return
      }
      return sendJson(res, 200, payload, { 'x-kovo-auth': 'ok' })
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

    // Option 4: Universal Interactive Browser Login Capture endpoints (gated by kovo_local session).
    if (path.pathname === authCaptureStartPath) {
      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      let body: Record<string, unknown>
      try {
        body = await readBoundedJsonBody(req)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Invalid JSON body.'
        return sendJson(res, msg.includes('too large') ? 413 : 400, { error: msg })
      }
      const projectId = typeof body.projectId === 'string' ? body.projectId.trim() : ''
      const targetOrigin = typeof body.targetOrigin === 'string' ? body.targetOrigin.trim() : ''
      if (!projectId || !targetOrigin) {
        return sendJson(res, 400, { error: 'projectId and targetOrigin are required.' })
      }
      let allowLocalLab = false
      let projectEnv: 'public' | 'local-lab' = 'public'
      const explicitAllowedOrigins: string[] = Array.isArray(body.allowedOrigins)
        ? body.allowedOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
        : []
      const projectAutoOrigins: string[] = []
      if (storeHandle) {
        try {
          const detail = storeHandle.projectDetail(projectId)
          const proj = detail.project
          projectEnv = proj.environment
          allowLocalLab = proj.environment === 'local-lab' && isLocalLabEnvEnabled()
          projectAutoOrigins.push(
            ...(proj.defaultScope ?? []),
            ...(proj.seeds ?? []),
            ...(detail.assets ?? []).filter(a => !a.thirdParty).map(a => a.origin),
          )
        } catch (err) {
          return sendJson(res, 404, { error: err instanceof Error ? err.message : 'Project not found.' })
        }
      } else if (body.allowLocalLab === true && isLocalLabEnvEnabled()) {
        allowLocalLab = true
        projectEnv = 'local-lab'
      }
      const originPolicy = assetOriginForEnvironment(projectEnv)
      const parsedTarget = originPolicy.safeParse(targetOrigin)
      if (!parsedTarget.success) {
        return sendJson(res, 400, {
          error: parsedTarget.error.issues[0]?.message ?? `targetOrigin is not allowed for this ${projectEnv} project.`,
        })
      }
      const mergedAllowed = new Set<string>([parsedTarget.data])
      const targetSibling = wwwSiblingOrigin(parsedTarget.data)
      if (targetSibling) {
        const parsedSib = originPolicy.safeParse(targetSibling)
        if (parsedSib.success) mergedAllowed.add(parsedSib.data)
      }
      for (const candidate of explicitAllowedOrigins.slice(0, 64)) {
        const parsedCandidate = originPolicy.safeParse(candidate)
        if (!parsedCandidate.success) {
          return sendJson(res, 400, {
            error: parsedCandidate.error.issues[0]?.message ?? `allowedOrigins entry "${candidate}" is not allowed for this ${projectEnv} project.`,
          })
        }
        mergedAllowed.add(parsedCandidate.data)
        const sibling = wwwSiblingOrigin(parsedCandidate.data)
        if (sibling) {
          const parsedSib = originPolicy.safeParse(sibling)
          if (parsedSib.success) mergedAllowed.add(parsedSib.data)
        }
      }
      for (const candidate of projectAutoOrigins) {
        if (mergedAllowed.size >= 64) break
        const parsedCandidate = originPolicy.safeParse(candidate)
        if (!parsedCandidate.success) continue
        mergedAllowed.add(parsedCandidate.data)
        const sibling = wwwSiblingOrigin(parsedCandidate.data)
        if (sibling && mergedAllowed.size < 64) {
          const parsedSib = originPolicy.safeParse(sibling)
          if (parsedSib.success) mergedAllowed.add(parsedSib.data)
        }
      }
      const allowedOrigins = [...mergedAllowed].slice(0, 64)
      const ttlMs = typeof body.ttlMs === 'number' && Number.isFinite(body.ttlMs) ? body.ttlMs : undefined
      try {
        const capture = await captureManager.startCapture({
          projectId,
          targetOrigin: parsedTarget.data,
          allowLocalLab,
          allowedOrigins,
          ...(ttlMs ? { ttlMs } : {}),
        })
        const initialNavErr = capture.lastError()?.trim()
        if (initialNavErr && isQaAnomaliesEnabled()) {
          recordQaAnomaly({
            kind: /proxy.*denied|disallowed|not allowed|blocked/i.test(initialNavErr)
              ? 'interactive_proxy_denied'
              : 'swallowed_nav_error',
            routeOrOrigin: capture.currentUrl() || capture.targetOrigin,
            summary: `Interactive auth-capture nav_error: ${initialNavErr}`,
            detail: {
              source: 'auth_capture_start',
              captureId: capture.id,
              projectId: capture.projectId,
            },
          })
        }
        return sendJson(res, 200, {
          captureId: capture.id,
          projectId: capture.projectId,
          targetOrigin: capture.targetOrigin,
          currentUrl: capture.currentUrl(),
          lastError: capture.lastError(),
          expiresAt: capture.expiresAt,
          viewport: capture.viewport,
        })
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unable to start browser login capture.'
        return sendJson(res, 400, { error: message })
      }
    }

    if (path.pathname === authCapturePersonaConfigPath) {
      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
      let body: Record<string, unknown>
      try {
        body = await readBoundedJsonBody(req)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Invalid JSON body.'
        return sendJson(res, msg.includes('too large') ? 413 : 400, { error: msg })
      }
      const projectId = typeof body.projectId === 'string' ? body.projectId.trim() : ''
      const personaId = typeof body.personaId === 'string' ? body.personaId.trim() : ''
      if (!projectId || !personaId) {
        return sendJson(res, 400, { error: 'projectId and personaId are required.' })
      }
      const verifyOrigin = body.verifyOrigin === null
        ? null
        : typeof body.verifyOrigin === 'string'
          ? body.verifyOrigin.trim()
          : undefined
      const verifyPath = body.verifyPath === null
        ? null
        : typeof body.verifyPath === 'string'
          ? body.verifyPath.trim()
          : undefined
      const idpOrigins = body.idpOrigins === null
        ? null
        : Array.isArray(body.idpOrigins)
          ? body.idpOrigins.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
          : undefined
      try {
        const db = storeHandle ?? store()
        updateBrowserSessionPersonaMeta(db, {
          projectId,
          personaId,
          ...(verifyOrigin !== undefined ? { verifyOrigin } : {}),
          ...(verifyPath !== undefined ? { verifyPath } : {}),
          ...(idpOrigins !== undefined ? { idpOrigins } : {}),
        })
        return sendJson(res, 200, { ok: true })
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Unable to update browser session metadata.'
        return sendJson(res, /not found/i.test(msg) ? 404 : 400, { error: msg })
      }
    }

    const captureMatch = authCaptureActionRegex.exec(path.pathname)
    if (captureMatch) {
      const captureId = captureMatch[1]!
      const action = captureMatch[2]!
      if (action === 'stream') {
        if (method !== 'GET') return reject(res, 405, 'Method not allowed.')
        const capture = captureManager.get(captureId)
        if (!capture) {
          return sendJson(res, 404, { error: 'Capture session not found or expired.' })
        }
        const pollMode = path.searchParams.get('mode') === 'poll' ||
          (req.headers.accept?.includes('application/json') && !req.headers.accept?.includes('text/event-stream'))
        if (pollMode) {
          return sendJson(res, 200, {
            captureId: capture.id,
            state: capture.state,
            url: capture.currentUrl(),
            lastError: capture.lastError(),
            expiresAt: capture.expiresAt,
            viewport: capture.viewport,
            frame: capture.latestFrame(),
          })
        }
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache, no-store, must-revalidate',
          connection: 'keep-alive',
          'x-accel-buffering': 'no',
        })
        const sendEvent = (eventName: string, payload: unknown) => {
          if (res.destroyed || res.writableEnded) return
          res.write(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`)
        }
        sendEvent('init', {
          captureId: capture.id,
          url: capture.currentUrl(),
          lastError: capture.lastError(),
          expiresAt: capture.expiresAt,
          viewport: capture.viewport,
        })
        const unsubscribe = capture.subscribe(ev => {
          if (ev.type === 'frame') sendEvent('frame', ev.frame)
          else if (ev.type === 'url') sendEvent('url', { url: ev.url })
          else if (ev.type === 'error') {
            const msg = ev.message.trim()
            if (msg && isQaAnomaliesEnabled()) {
              recordQaAnomaly({
                kind: /proxy.*denied|disallowed|not allowed|blocked/i.test(msg)
                  ? 'interactive_proxy_denied'
                  : 'swallowed_nav_error',
                routeOrOrigin: ev.url || capture.currentUrl() || capture.targetOrigin,
                summary: `Interactive auth-capture nav_error: ${msg}`,
                detail: {
                  source: 'auth_capture_stream',
                  captureId: capture.id,
                  projectId: capture.projectId,
                },
              })
            }
            sendEvent('nav_error', { message: ev.message, ...(ev.url ? { url: ev.url } : {}) })
          }
          else if (ev.type === 'status') {
            sendEvent('status', { state: ev.state, ...(ev.reason ? { reason: ev.reason } : {}) })
            if (ev.state !== 'active' && !res.writableEnded) res.end()
          }
        })
        const keepalive = setInterval(() => {
          if (!res.destroyed && !res.writableEnded) res.write(': keepalive\n\n')
        }, 15_000)
        keepalive.unref?.()
        res.once('close', () => {
          clearInterval(keepalive)
          unsubscribe()
        })
        return
      }

      if (method !== 'POST') return reject(res, 405, 'Method not allowed.')
      if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')

      if (action === 'cancel') {
        req.resume()
        const canceled = await captureManager.cancel(captureId)
        return sendJson(res, canceled ? 200 : 404, canceled ? { ok: true, canceled: true } : { error: 'Capture session not found or already closed.' })
      }

      if (action === 'complete') {
        req.resume()
        try {
          // Move U2: Keep raw captured BrowserStorageBundle strictly server-side in a single-use
          // project-bound escrow map and return ONLY { captureToken, expiresAt, verifyOrigin, verifyPath, capturedAppOrigins, capturedIdpOrigins, summary } to the UI.
          const escrowed = await captureManager.completeToEscrow(captureId)
          return sendJson(res, 200, {
            ok: true,
            captureToken: escrowed.captureToken,
            expiresAt: escrowed.expiresAt,
            verifyOrigin: escrowed.summary.verifyOrigin,
            verifyPath: escrowed.summary.verifyPath,
            capturedAppOrigins: escrowed.summary.capturedAppOrigins,
            capturedIdpOrigins: escrowed.summary.capturedIdpOrigins,
            summary: escrowed.summary,
          })
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unable to complete capture.'
          return sendJson(res, /not found|already closed|expired/i.test(message) ? 404 : 400, { error: message })
        }
      }

      if (action === 'input') {
        const capture = captureManager.get(captureId)
        if (!capture) {
          req.resume()
          return sendJson(res, 404, { error: 'Capture session not found or expired.' })
        }
        let body: Record<string, unknown>
        try {
          body = await readBoundedJsonBody(req)
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Invalid JSON body.'
          return sendJson(res, msg.includes('too large') ? 413 : 400, { error: msg })
        }
        const kind = typeof body.kind === 'string' ? body.kind : ''
        try {
          if (kind === 'mouse') {
            const type = body.type
            if (type !== 'mousePressed' && type !== 'mouseReleased' && type !== 'mouseMoved' && type !== 'mouseWheel') {
              return sendJson(res, 400, { error: 'Invalid mouse event type.' })
            }
            const input: CaptureMouseInput = {
              type,
              x: typeof body.x === 'number' ? body.x : 0,
              y: typeof body.y === 'number' ? body.y : 0,
              ...(body.button === 'none' || body.button === 'left' || body.button === 'middle' || body.button === 'right'
                ? { button: body.button }
                : {}),
              ...(typeof body.clickCount === 'number' ? { clickCount: body.clickCount } : {}),
              ...(typeof body.deltaX === 'number' ? { deltaX: body.deltaX } : {}),
              ...(typeof body.deltaY === 'number' ? { deltaY: body.deltaY } : {}),
              ...(typeof body.modifiers === 'number' ? { modifiers: body.modifiers } : {}),
            }
            await capture.dispatchMouse(input)
            return sendJson(res, 200, { ok: true, url: capture.currentUrl() })
          }
          if (kind === 'key') {
            const type = body.type
            if (type !== 'keyDown' && type !== 'keyUp' && type !== 'char' && type !== 'insertText') {
              return sendJson(res, 400, { error: 'Invalid key event type.' })
            }
            const input: CaptureKeyInput = {
              type,
              ...(typeof body.key === 'string' ? { key: body.key } : {}),
              ...(typeof body.code === 'string' ? { code: body.code } : {}),
              ...(typeof body.text === 'string' ? { text: body.text } : {}),
              ...(typeof body.windowsVirtualKeyCode === 'number' ? { windowsVirtualKeyCode: body.windowsVirtualKeyCode } : {}),
              ...(typeof body.modifiers === 'number' ? { modifiers: body.modifiers } : {}),
            }
            await capture.dispatchKey(input)
            return sendJson(res, 200, { ok: true, url: capture.currentUrl() })
          }
          if (kind === 'navigate') {
            const navUrl = typeof body.url === 'string' ? body.url.trim() : ''
            if (!navUrl) return sendJson(res, 400, { error: 'url is required for navigate input.' })
            const resNav = await capture.navigate(navUrl)
            return sendJson(res, 200, { ok: true, url: resNav.url })
          }
          return sendJson(res, 400, { error: 'input kind must be "mouse", "key", or "navigate".' })
        } catch (err) {
          return sendJson(res, 400, { error: err instanceof Error ? err.message : 'Input dispatch failed.' })
        }
      }
    }

    if (path.pathname.startsWith('/_kovo/auth-capture')) {
      return reject(res, 404, 'Not found.')
    }

    // Move 4: Opt-in QA Anomaly Recorder endpoint (strictly 404 unless KOVO_QA_ANOMALIES === '1',
    // authenticated with the same kovo_local session + Origin + Sec-Fetch-Site guards above).
    if (path.pathname === qaAnomaliesPath) {
      if (!isQaAnomaliesEnabled()) {
        return sendJson(res, 404, { error: 'Not found.' })
      }
      if (method === 'GET' || method === 'HEAD') {
        const rawKind = path.searchParams.get('kind')?.trim()
        let kind: QaAnomalyKind | undefined
        if (rawKind) {
          if (!validQaAnomalyKinds.has(rawKind)) {
            return sendJson(res, 400, { error: 'Invalid kind filter.' })
          }
          kind = rawKind as QaAnomalyKind
        }
        const rawLimit = path.searchParams.get('limit')?.trim()
        let limit: number | undefined
        if (rawLimit) {
          if (!/^\d+$/.test(rawLimit)) {
            return sendJson(res, 400, { error: 'Invalid limit parameter.' })
          }
          limit = Number(rawLimit)
        }
        const rawSinceTs = path.searchParams.get('sinceTs')?.trim()
        let sinceTs: number | undefined
        if (rawSinceTs) {
          if (!/^\d+$/.test(rawSinceTs)) {
            return sendJson(res, 400, { error: 'Invalid sinceTs parameter.' })
          }
          sinceTs = Number(rawSinceTs)
        }
        if (method === 'HEAD') {
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end()
          return
        }
        const anomalies = listQaAnomalies({
          ...(kind ? { kind } : {}),
          ...(limit !== undefined ? { limit } : {}),
          ...(sinceTs !== undefined ? { sinceTs } : {}),
        })
        return sendJson(res, 200, {
          enabled: true,
          maxEntries: QA_ANOMALIES_MAX_ENTRIES,
          count: anomalies.length,
          anomalies,
        })
      }
      if (method === 'DELETE') {
        if (req.headers.origin !== origin) return reject(res, 403, 'Unexpected origin.')
        req.resume()
        clearQaAnomalies()
        return sendJson(res, 200, { ok: true, cleared: true })
      }
      return reject(res, 405, 'Method not allowed.')
    }

    if (path.pathname.startsWith('/_kovo/qa/')) {
      return reject(res, 404, 'Not found.')
    }

    const headers = new Headers()
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined && !name.startsWith('x-forwarded-') && name !== 'forwarded') {
        for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item)
      }
    }

    const sseRunMatch = /^\/api\/runs\/([A-Za-z0-9_-]{1,128})\/events$/.exec(path.pathname)
    let sseTenantId: string | null = null
    if (sseRunMatch) {
      const sseRunId = sseRunMatch[1]!
      const ctxTenant = runtime?.getRunContext(sseRunId)?.tenantId ?? null
      if (ctxTenant && ctxTenant !== 'default') {
        sseTenantId = ctxTenant
      } else if (storeHandle) {
        try {
          const resolvedTenant = storeHandle.getRunTenant(sseRunId)
          sseTenantId = resolvedTenant && resolvedTenant !== 'default' ? resolvedTenant : null
        } catch {
          sseTenantId = null
        }
      }
      if (killSwitch.isActive(sseTenantId)) {
        return sendJson(res, 503, { error: 'Kill switch active.', code: 'KILL_SWITCH_TRIPPED' })
      }
    }

    const abort = new AbortController()
    const unsubscribeSseRevocation = path.pathname.endsWith('/events')
      ? killSwitch.onSseRevocation(state => {
          if (state.tenantId === null || (sseTenantId !== null && state.tenantId === sseTenantId)) {
            if (!abort.signal.aborted) abort.abort()
          }
        })
      : null
    res.once('close', () => {
      unsubscribeSseRevocation?.()
      abort.abort()
    })
    let received = 0
    let bodyTooLarge = false
    const limiter = new Transform({
      transform(chunk, _encoding, done) {
        received += chunk.length
        if (received > bodyLimit) {
          bodyTooLarge = true
          req.unpipe(limiter)
          req.resume()
          done(new BodyTooLargeError())
        } else {
          done(null, chunk)
        }
      },
    })
    // Prevent unhandled stream 'error' events if chunked uploads exceed bodyLimit or the socket resets.
    limiter.on('error', () => {
      req.unpipe(limiter)
    })
    const onReqError = (err: Error) => {
      req.unpipe(limiter)
      if (!limiter.destroyed) limiter.destroy(err)
    }
    if (!readOnly) {
      req.on('error', onReqError)
      req.pipe(limiter)
    }
    res.once('close', () => {
      req.off('error', onReqError)
      req.unpipe(limiter)
      if (!limiter.destroyed) limiter.destroy()
    })
    const body = readOnly ? undefined : Readable.toWeb(limiter) as ReadableStream<Uint8Array>
    const request = new Request(path, {
      method, headers, body, signal: abort.signal, ...(body ? { duplex: 'half' } : {}),
    } as RequestInit)
    let response: Response
    try {
      response = await app.fetch(request)
    } catch (err) {
      if (bodyTooLarge || isBodyTooLargeError(err)) {
        if (!res.headersSent) return reject(res, 413, 'Request body is too large.')
        return
      }
      throw err
    }
    if (bodyTooLarge) {
      if (!res.headersSent) return reject(res, 413, 'Request body is too large.')
      return
    }
    if (response.status >= 500 && isQaAnomaliesEnabled()) {
      recordQaAnomaly({
        kind: 'unexpected_ui_rpc_error',
        routeOrOrigin: path.pathname,
        summary: `Server responded HTTP ${response.status} for ${method} ${path.pathname}`,
        detail: {
          source: 'serve_app_fetch',
          method,
          statusCode: response.status,
        },
      })
    }
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
    void serve(req, res).catch((err: unknown) => {
      if (isQaAnomaliesEnabled()) {
        const rawUrl = req.url ?? '/'
        const pathnameOnly = rawUrl.split(/[?#]/, 1)[0] || '/'
        const errName = err instanceof Error ? err.name : 'Error'
        const errMsg = err instanceof Error ? err.message : 'Unhandled server error'
        recordQaAnomaly({
          kind: 'unexpected_ui_rpc_error',
          routeOrOrigin: pathnameOnly,
          summary: `Unhandled HTTP 500 on ${req.method ?? 'GET'} ${pathnameOnly}: ${errName}: ${errMsg}`,
          detail: {
            source: 'serve_unhandled_error',
            method: req.method ?? 'GET',
            statusCode: 500,
            errorName: errName,
          },
        })
      }
      if (res.destroyed) return
      if (!res.headersSent) reject(res, 500, 'Kovo could not complete the request.')
      else res.end()
    })
  })
  server.once('close', () => {
    void captureManager.disposeAll()
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

export interface HostHardeningStatus {
  prototypeClean: boolean
  prototypeSealed: boolean
  disableProtoDelete: boolean
  linearRegexpFallback: boolean
  regexpSelfCheckMs: number | null
  warnings: string[]
}

// Use --disable-proto=delete instead of --disable-proto=throw: playwright-core's colors helper assigns
// `builder.__proto__ = proto` in formatCallLog (playwright-core/lib/utilsBundle.js:591), which throws
// ERR_PROTO_ACCESS under --disable-proto=throw while --disable-proto=delete removes Object.prototype.__proto__
// without breaking Playwright error formatting.
const RECOMMENDED_HARDENING_FLAGS =
  '--disable-proto=delete --enable-experimental-regexp-engine-on-excessive-backtracks --regexp-backtracks-before-fallback=10000'

/**
 * Verify that `Object.prototype` has no unexpected enumerable properties (detects pre-existing
 * prototype pollution before serving requests).
 */
export function assertObjectPrototypeIntegrity(): void {
  const pollutedKeys = Object.keys(Object.prototype)
  if (pollutedKeys.length > 0) {
    throw new Error(`Object.prototype integrity check failed: unexpected own enumerable properties [${pollutedKeys.join(', ')}]`)
  }
}

/**
 * R2-C-2 / H-32 process-level hardening and startup self-check:
 * 1. Verifies `Object.prototype` has no unexpected enumerable keys.
 * 2. Seals `Object.prototype` so no new properties can be attached process-wide (while preserving
 *    compatibility with third-party subclasses such as Playwright's SourceMapGenerator).
 * 3. Checks whether `--disable-proto=delete` and `--enable-experimental-regexp-engine-on-excessive-backtracks`
 *    are active and runs a bounded exponential-regex self-check when the linear fallback is enabled.
 */
export function hardenHostProcess(options?: {
  requireFlags?: boolean
  requireLinearRegexp?: boolean
  sealPrototype?: boolean
  quiet?: boolean
}): HostHardeningStatus {
  assertObjectPrototypeIntegrity()

  if (options?.sealPrototype !== false && !Object.isSealed(Object.prototype)) {
    Object.seal(Object.prototype)
  }

  // Under --disable-proto=delete, Node removes `Object.prototype.__proto__` cleanly so `__proto__`
  // reads return undefined and property assignment cannot mutate Object.prototype, while
  // playwright-core/lib/utilsBundle.js:591 (`builder.__proto__ = proto`) does not crash.
  const disableProtoDelete = Object.getOwnPropertyDescriptor(Object.prototype, '__proto__') === undefined

  const nodeOptionsTokens = (process.env.NODE_OPTIONS ?? '').trim().split(/\s+/).filter(Boolean)
  const linearFlagPresent =
    process.execArgv.includes('--enable-experimental-regexp-engine-on-excessive-backtracks')
    || nodeOptionsTokens.includes('--enable-experimental-regexp-engine-on-excessive-backtracks')

  let regexpSelfCheckMs: number | null = null
  let linearRegexpFallback = false
  if (linearFlagPresent) {
    const probeRe = /(a+)+b/
    const t0 = performance.now()
    probeRe.test(`${'a'.repeat(32)}!`)
    regexpSelfCheckMs = Number((performance.now() - t0).toFixed(2))
    linearRegexpFallback = regexpSelfCheckMs < 50
  }

  const warnings: string[] = []
  let linearFailureMessage: string | null = null
  if (!disableProtoDelete) {
    warnings.push(`Node started without --disable-proto=delete (recommended: node ${RECOMMENDED_HARDENING_FLAGS} scripts/serve.ts)`)
  }
  if (!linearRegexpFallback) {
    linearFailureMessage = linearFlagPresent
      ? `Linear regexp fallback self-check exceeded 50 ms (${regexpSelfCheckMs} ms).`
      : `Node requires --enable-experimental-regexp-engine-on-excessive-backtracks to prevent regex backtracking stalls. Launch via "npm start" or: node ${RECOMMENDED_HARDENING_FLAGS} scripts/serve.ts`
    warnings.push(linearFailureMessage)
  }

  const requireFlags = options?.requireFlags ?? process.env.KOVO_REQUIRE_HARDENED_NODE === '1'
  const allowUnhardenedForTest = process.env.KOVO_ALLOW_UNHARDENED_NODE_FOR_TEST === '1'
  // R3-H-11 backstop: linear-regexp fallback is mandatory at startup unless an explicit test opt-out
  // (`KOVO_ALLOW_UNHARDENED_NODE_FOR_TEST=1`) or `requireFlags: false` / `requireLinearRegexp: false` is set.
  const requireLinearRegexp = options?.requireLinearRegexp
    ?? (requireFlags ? true : (options?.requireFlags === false ? false : !allowUnhardenedForTest))

  if (requireFlags && warnings.length > 0) {
    throw new Error(`Host process hardening check failed: ${warnings.join(' | ')}`)
  }
  if (requireLinearRegexp && linearFailureMessage) {
    throw new Error(`Host process hardening check failed: ${linearFailureMessage}`)
  }
  if (!options?.quiet) {
    for (const w of warnings) console.warn(`[kovo:hardening] ${w}`)
  }

  return {
    prototypeClean: true,
    prototypeSealed: Object.isSealed(Object.prototype),
    disableProtoDelete,
    linearRegexpFallback,
    regexpSelfCheckMs,
    warnings,
  }
}

const UNRECOVERABLE_ERROR_CODES = new Set([
  'ERR_OUT_OF_MEMORY',
  'ERR_WORKER_OUT_OF_MEMORY',
  'ENOMEM',
  'ERR_INTERNAL_ASSERTION',
])

const UNCAUGHT_STORM_WINDOW_MS = 10_000
const UNCAUGHT_STORM_LIMIT = 5

export function isUnrecoverableHostError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false
  const code = (err as { code?: unknown }).code
  if (typeof code === 'string' && UNRECOVERABLE_ERROR_CODES.has(code)) return true
  const name = (err as { name?: unknown }).name
  if (name === 'RangeError' && typeof (err as { message?: unknown }).message === 'string') {
    if (/allocation failed|out of memory/i.test((err as { message: string }).message)) return true
  }
  return false
}

export interface HostUncaughtGuardOptions {
  /** Invoked when a fatal/unrecoverable error or uncaught exception storm occurs. */
  onFatal?: (err: unknown, origin: NodeJS.UncaughtExceptionOrigin, reason: string) => void
  /** Structured log sink (defaults to `console.error`). */
  logError?: (line: string) => void
  /** Optional clock override for storm-window testing. */
  now?: () => number
  /** Maximum uncaught exceptions permitted within `stormWindowMs` before tripping fatal shutdown. */
  stormLimit?: number
  /** Sliding window for uncaught exception storm detection (ms). */
  stormWindowMs?: number
}

/**
 * R3-C-1 defense-in-depth process-level `uncaughtException` guard:
 * Logs structured JSON diagnostics rather than letting an isolated socket/parser exception crash
 * all concurrent runs and take the UI offline, while still failing fast cleanly on truly
 * unrecoverable runtime faults (OOM, internal assertion) or an uncaught-exception storm.
 */
export function installHostUncaughtExceptionGuard(options: HostUncaughtGuardOptions = {}): () => void {
  const logError = options.logError ?? (line => console.error(line))
  const now = options.now ?? Date.now
  const stormLimit = Math.max(1, options.stormLimit ?? UNCAUGHT_STORM_LIMIT)
  const stormWindowMs = Math.max(100, options.stormWindowMs ?? UNCAUGHT_STORM_WINDOW_MS)
  const recentTimestamps: number[] = []
  let fatalTriggered = false

  const listener = (err: Error, origin: NodeJS.UncaughtExceptionOrigin) => {
    const ts = now()
    recentTimestamps.push(ts)
    while (recentTimestamps.length > 0 && ts - recentTimestamps[0]! > stormWindowMs) {
      recentTimestamps.shift()
    }
    const unrecoverable = isUnrecoverableHostError(err)
    const storm = recentTimestamps.length >= stormLimit
    const fatal = unrecoverable || storm
    const reason = unrecoverable
      ? 'unrecoverable_runtime_error'
      : (storm ? `uncaught_exception_storm(${recentTimestamps.length}/${stormWindowMs}ms)` : 'isolated_uncaught_exception')

    try {
      logError(JSON.stringify({
        level: 'error',
        event: 'host.uncaught_exception',
        origin,
        fatal,
        reason,
        name: err instanceof Error ? err.name : typeof err,
        code: typeof (err as NodeJS.ErrnoException | undefined)?.code === 'string'
          ? (err as NodeJS.ErrnoException).code
          : null,
        message: (err instanceof Error ? err.message : String(err)).slice(0, 512),
        stack: err instanceof Error && err.stack ? err.stack.split('\n').slice(0, 8).join('\n') : undefined,
        timestamp: new Date(ts).toISOString(),
      }))
    } catch {
      // Never re-throw from the uncaughtException logger.
    }

    if (fatal && !fatalTriggered) {
      fatalTriggered = true
      try {
        options.onFatal?.(err, origin, reason)
      } catch {
        process.exitCode = 1
      }
    }
  }

  process.on('uncaughtException', listener)
  return () => {
    process.off('uncaughtException', listener)
  }
}

async function main() {
  hardenHostProcess()
  const directory = resolve(process.env.KOVO_DATA_DIR ?? '.kovo')
  const port = Number(process.env.PORT ?? 8000)
  const hostPort = parseOptionalPort(process.env.KOVO_PORT)
  const listenHost = resolveListenHost(process.env.KOVO_LISTEN_HOST)
  const killSwitchFilePath = join(directory, 'kill-switch.json')
  const runtime = getAppRuntime({
    dataDir: directory,
    killSwitchFilePath,
    autoRecoverStore: false,
  })
  const serverEntry = new URL('../build/server/server.js', import.meta.url).href
  const { default: app, initialize } = await import(serverEntry) as {
    default: LocalApp
    initialize: (options?: { dataDir?: string; killSwitchFilePath?: string }) => AppRuntime | void
  }

  initialize({ dataDir: directory, killSwitchFilePath })
  await runtime.startupRecover().catch(() => undefined)

  const sharedStore = store()
  const sharedKillSwitch = configureGlobalKillSwitch({
    filePath: killSwitchFilePath,
  })

  const externalPort = hostPort ?? port
  const configuredPublicOrigin = process.env.KOVO_PUBLIC_ORIGIN || undefined
  const localOrigin = `http://127.0.0.1:${externalPort}`
  let bannerRef: (() => string) | undefined

  const local = createKovoLocalServer({
    app,
    directory,
    port,
    ...(hostPort !== undefined ? { hostPort } : {}),
    publicOrigin: configuredPublicOrigin,
    runtime,
    killSwitch: sharedKillSwitch,
    store: sharedStore,
    onBootstrapRemind: () => {
      if (bannerRef) console.log(bannerRef())
    },
  })

  bannerRef = () => formatBootstrapBanner({
    localUrl: local.bootstrapUrl(localOrigin),
    secret: local.bootstrapSecret,
    publicOrigin: configuredPublicOrigin || readPinnedOrigin(directory),
  })

  let shuttingDown = false
  const shutdown = (exitCode = 0) => {
    if (shuttingDown) return
    shuttingDown = true
    process.exitCode = exitCode
    const forceTimer = setTimeout(() => process.exit(exitCode), 5_000)
    forceTimer.unref?.()
    local.server.closeAllConnections?.()
    local.server.close(() => {
      void runtime.dispose().finally(() => process.exit(exitCode))
    })
  }
  installHostUncaughtExceptionGuard({
    onFatal: () => shutdown(1),
  })
  process.once('SIGTERM', () => shutdown(0))
  process.once('SIGINT', () => shutdown(0))

  local.server.listen(port, listenHost, () => {
    const bootstrapFile = join(directory, 'bootstrap-url')
    writeFileSync(bootstrapFile, `${local.bootstrapUrl(localOrigin)}\n`, { mode: 0o600 })
    chmodSync(bootstrapFile, 0o600)
    console.log(`Kovo listening on http://${listenHost}:${port}`)
    console.log(bannerRef!())
  })
}

if (import.meta.main) await main()
