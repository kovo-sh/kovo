import { createHash, createHmac, createPublicKey, randomBytes } from 'node:crypto'
import { lookup, resolve4, resolve6, resolveCname, resolveNs, resolveTxt } from 'node:dns/promises'
import { request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as netConnect } from 'node:net'
import type { Socket as NetSocket } from 'node:net'
import { connect as tlsConnect, TLSSocket } from 'node:tls'
import type { DetailedPeerCertificate } from 'node:tls'
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib'
import ipaddr from 'ipaddr.js'
import { referrerPolicies } from '../domain.ts'
import type { ApprovedEndpointPattern, CapabilityTier, HttpMethod, PreparedObservation } from '../domain.ts'
import { cacheBusterValueRegex, containsDestructivePayload, containsWebshellSignature } from '../replay-spec.ts'
import type { AuthMutation, CsrfBind } from '../replay-spec.ts'
import { computeStateChangeBodyHash, isLocalLabAutoApprovalOrigin } from './approval-judge.ts'
import type { StateChangeApprovalContext } from './approval-judge.ts'
import { scanSecondOrderMarkers } from './canary-broker.ts'
import type { CanaryBroker, SecondOrderStore } from './canary-broker.ts'
import { buildPersonaHeader, personaSecrets } from './persona-vault.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { redact, redactHeaders, scanSecretHeaders, scanSecrets } from './redact.ts'
import type { NamedSecret, SecretMatch } from './redact.ts'
import {
  createHttpTransport,
  extractTlsMetadata,
  RaceBarrier,
  resolveTransportConfig,
  WebSocketSession,
} from './transport.ts'
import type { TransportConfig } from './transport.ts'

export interface PublicObservation extends PreparedObservation {
  origin: string
  finalOrigin: string
  source: 'public response' | 'fixture response' | 'supplied observation'
}

export interface TlsMetadata {
  protocol: string | null
  cipher: string | null
  authorized: boolean
  authorizationError: string | null
  subject: Record<string, string>
  issuer: Record<string, string>
  sans: string[]
  validFrom: string | null
  validTo: string | null
  fingerprint256: string | null
  serialNumber: string | null
  daysUntilExpiry: number | null
  expired: boolean
  hostnameMatchesSan: boolean
  weakProtocol: boolean
}

export interface SetCookieSummary {
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite: string | null
}

export interface BrokerMultipartPart {
  name: string
  filename?: string
  contentType: string
  content: string
}

export interface BrokerHttpRequest {
  origin: string
  method: HttpMethod
  pathAndQuery: string
  headers?: Record<string, string>
  body?: string
  multipartParts?: BrokerMultipartPart[]
  persona?: string
  personaHandle?: string
  personaHeaders?: Record<string, string>
  session?: string
  sessionGroupRole?: 'setup' | 'control' | 'probe' | 'cleanup'
  csrfBind?: CsrfBind
  authMutation?: AuthMutation
  probeClass?: string
  cacheVerify?: boolean
  traceId?: string
  runId?: string
  assignmentId?: string
  scopeRevision?: number
  followRedirects?: boolean
  secrets?: readonly NamedSecret[]
  maxBodyBytes?: number
  timeoutMs?: number
}

export interface BrokerWebsocketRequest {
  origin: string
  pathAndQuery: string
  originHeader?: string
  headers?: Record<string, string>
  persona?: string
  personaHandle?: string
  personaHeaders?: Record<string, string>
  subprotocols?: string[]
  sendMessages?: string[]
  maxFrames?: number
  maxBytes?: number
  timeoutMs?: number
  secrets?: readonly NamedSecret[]
  /**
   * Opt-in turn-aware session script. Requires `BrokerOptions.wsSessionEnabled`; when unset the
   * legacy single-shot probe path runs unchanged.
   */
  turns?: BrokerWebsocketTurn[]
}

export interface BrokerWebsocketTurn {
  /** Text payload to send before awaiting server frames. */
  send?: string
  /** Number of complete server messages to await (continuations reassembled). Defaults to 1. */
  awaitMessages?: number
  timeoutMs?: number
}

export interface BrokerWebsocketFrame {
  direction: 'sent' | 'received'
  opcode: 'text' | 'binary'
  data: string
  bytes: number
  timestamp: number
}

export interface BrokerWebsocketResult {
  origin: string
  pathAndQuery: string
  personaHandle: string | null
  originHeader: string | null
  connected: boolean
  upgradeStatus: number | null
  upgradeHeaders: Record<string, string>
  subprotocol: string | null
  sentFrames: number
  receivedFrames: number
  totalBytes: number
  frames: BrokerWebsocketFrame[]
  closeCode: number | null
  closeReason: string | null
  error: string | null
  durationMs: number
}

export interface BrokerExchangeResult {
  origin: string
  finalOrigin: string
  redirectOrigins: string[]
  /** Path + query of the final hop actually requested (differs from `pathAndQuery` after redirects). */
  finalPathAndQuery?: string
  /** Every redirect target path + query followed during this exchange, in order. */
  redirectPaths?: string[]
  method: string
  pathAndQuery: string
  personaHandle: string | null
  status: number
  mediaType: string
  reqHeaders: Record<string, string>
  respHeaders: Record<string, string>
  setCookies: SetCookieSummary[]
  bodyPreview: string
  body: string
  bodySha256: string
  bodyBytes: number
  bodyTruncated: boolean
  durationMs: number
  /**
   * Redacted structural evidence that secret-shaped values were present in the raw response body
   * or headers before scrubbing. Fingerprints only (no raw values); see `SecretMatch` in
   * `redact.ts`. Probes should treat a non-empty list as "disclosure candidate" and correlate
   * `sha256Prefix` against a locally held secret to prove unauthorized disclosure.
   */
  secretMatches?: SecretMatch[]
  tls?: TlsMetadata
  observation: PublicObservation
}

export interface RaceBurstSummary {
  total: number
  statuses: number[]
  statusCounts: Record<string, number>
  distinctBodies: number
  minDurationMs: number
  maxDurationMs: number
  spreadMs: number
}

export interface BrokerRaceBurstResult {
  results: BrokerExchangeResult[]
  summary: RaceBurstSummary
}

export interface DnsDanglingHint {
  provider: string
  cname: string
}

export interface DnsInspectionResult {
  origin: string
  hostname: string
  a: string[]
  aaaa: string[]
  cname: string[]
  txt: string[]
  ns: string[]
  nxdomain: boolean
  danglingNoIp: boolean
  danglingHints: DnsDanglingHint[]
  durationMs: number
}

export interface TlsInspectionResult {
  origin: string
  hostname: string
  resolvedIp: string
  port: number
  tls: TlsMetadata
  durationMs: number
}

export type RawHttpResponse = {
  status: number
  headers: IncomingHttpHeaders
  body?: string
  bodyBytes?: number
  bodyTruncated?: boolean
  tls?: TlsMetadata
}

export type PublicAddress = { address: string; family: number }
export type Resolver = (host: string) => Promise<PublicAddress[]>
export type Transport = (
  url: URL,
  address: PublicAddress,
  signal: AbortSignal,
  options?: {
    method?: string
    headers?: Record<string, string>
    body?: string
    maxBodyBytes?: number
    readBody?: boolean
    rejectUnauthorized?: boolean
    /** Present only for HTTP/2 race bursts; releases synchronized stream headers. */
    raceBarrier?: RaceBarrier
  },
) => Promise<RawHttpResponse>

export type DnsRecordResolver = (hostname: string, signal: AbortSignal) => Promise<{
  a: string[]
  aaaa: string[]
  cname: string[]
  txt: string[]
  ns: string[]
  nxdomain: boolean
}>

export type TlsInspector = (
  url: URL,
  address: PublicAddress,
  signal: AbortSignal,
) => Promise<TlsMetadata>

export type Grant = {
  origin?: string
  tier?: CapabilityTier
  maxRpsPerOrigin?: number
  allowLocalLab?: boolean
  personas?: ReadonlyMap<string, ResolvedPersona>
  secrets?: readonly NamedSecret[]
  sandboxWriteAllowlist?: ApprovedEndpointPattern[]
  scopeRevision?: number
  /** Explicit operator-approved non-default target ports (e.g. 8080/8443) for authorized staging origins. */
  allowedPorts?: number[]
  storage?: SecondOrderStore
  canaryBroker?: CanaryBroker
  mintCanary?: (purpose: string, origin?: string) => { httpUrl?: string; url?: string } | null
  canRead: (origin: string) => boolean
  /**
   * @deprecated Never consulted for authorization. Tier-3 state changes are always authorized by
   * `isStateChangeApproved`; a path-substring "idempotent POST" predicate must not skip approvals.
   * Retained only for source compatibility with older grant builders.
   */
  isIdempotentPostAllowed?: (origin: string, pathAndQuery: string, body?: string) => boolean
  /**
   * Exact-fingerprint Tier-3 authorization. The optional context carries the bytes/flags of the
   * precise request so auto-approvals cannot be replayed against a different path, persona, body,
   * or multipart/race/rce shape. Callers must not return true without matching that fingerprint.
   */
  isStateChangeApproved?: (
    origin: string,
    method: string,
    pathAndQuery: string,
    context?: StateChangeApprovalContext,
  ) => boolean
  audit: (outcome: 'allowed' | 'denied' | 'observed' | 'circuit_open', origin: string, status?: number) => void
}

export type WebsocketTransport = (
  url: URL,
  address: PublicAddress,
  signal: AbortSignal,
  options: {
    headers: Record<string, string>
    subprotocols?: string[]
    sendMessages: string[]
    maxFrames: number
    maxBytes: number
    timeoutMs: number
    rejectUnauthorized: boolean
  },
) => Promise<{
  connected: boolean
  upgradeStatus: number | null
  upgradeHeaders: Record<string, string>
  subprotocol: string | null
  frames: BrokerWebsocketFrame[]
  closeCode: number | null
  closeReason: string | null
  error: string | null
}>

export type BrokerOptions = {
  resolve?: Resolver
  transport?: Transport
  wsTransport?: WebsocketTransport
  dnsResolver?: DnsRecordResolver
  tlsInspector?: TlsInspector
  source?: PublicObservation['source']
  circuit5xxThreshold?: number
  circuit429Threshold?: number
  circuitWindowMs?: number
  /** Half-open route cooldown in ms (clamped to 15–30s). Defaults to 15s. */
  circuitCooldownMs?: number
  /**
   * Exponential per-origin backoff: first cooldown after a trip, doubled per consecutive trip.
   * `circuitCooldownMs` (the legacy any-trip cooldown) takes precedence for route circuits.
   */
  circuitBackoffBaseMs?: number
  /** Ceiling for the per-origin exponential backoff. Defaults to 30s. */
  circuitBackoffMaxMs?: number
  rejectUnauthorized?: boolean
  storage?: SecondOrderStore
  canaryBroker?: CanaryBroker
  maxJarsPerAssignment?: number
  maxCookiesPerJar?: number
  /** Injectable clock (test-only) used by circuit-breaker accounting. */
  now?: () => number
  /**
   * Layer-1 transport configuration. Merged over `GUARDIAN_HTTP2` / `GUARDIAN_EGRESS_PROXY` /
   * `GUARDIAN_MTLS_*` / `GUARDIAN_USER_AGENT` / `GUARDIAN_AUTHORIZED_HEADERS` (/`GUARDIAN_UA_PROFILE`).
   * Invalid configuration fails closed at construction time.
   */
  transportConfig?: Partial<TransportConfig>
  /** Opt-in turn-aware WebSocket sessions; unset keeps the legacy single-shot probe path. */
  wsSessionEnabled?: boolean
  /**
   * Rate-limited persona re-authentication invoked by the broker on a persona-bound 401.
   * Returning true retries the request once with freshly resolved persona headers.
   */
  reauth?: (personaHandle: string, origin: string) => Promise<boolean | void>
}

const maxPathLength = 8192
const maxRedirects = 8
const defaultMaxBodyBytes = 1024 * 1024
const hardMaxBodyBytes = 2 * 1024 * 1024
const maxMultipartBytes = 256 * 1024
const maxMultipartParts = 16
const defaultWsMaxFrames = 10
const hardWsMaxFrames = 25
const defaultWsMaxBytes = 64 * 1024
const defaultWsTimeoutMs = 10_000
const hardWsTimeoutMs = 20_000
const bodyPreviewLimit = 8192
const defaultRequestTimeoutMs = 30_000
const forbiddenCallerHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|x-guardian-trace-id)$/i
const wsGuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
const sessionHandleRegex = /^[a-z0-9_-]{1,32}$/
const csrfCookieNameRegex = /^(?:xsrf-token|csrf[_-]?token|_csrf|csrf)$/i
const csrfInputNameRegex = /^(?:_csrf|csrf[_-]?token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|_token)$/i
const canaryUrlRegex = /^\/c\/guardian-canary-[a-f0-9]{24}$/i

interface JarCookieEntry {
  key: string
  /** Origin that issued the cookie. Host-only cookies are scoped strictly to it. */
  origin: string
  /** RFC-6265 Domain scope (hostname). Equals the issuing hostname when host-only. */
  domain: string
  hostOnly: boolean
  name: string
  value: string
  path: string
  secure: boolean
  httpOnly: boolean
  sameSite: string | null
  expiresAt?: number
  /** Epoch ms of the most recent Set-Cookie write for this jar entry. */
  setAt: number
  /**
   * Number of Set-Cookie writes observed for this entry inside the current jar.
   * `>= 2` marks an in-jar rotation, which is allowed to supersede a stale
   * Persona Vault cookie (a single colliding write never may — that invariant
   * prevents a target from hijacking the operator-approved credential).
   */
  writeCount: number
}

interface StoredCsrfToken {
  value: string
  sourceKind: 'cookie' | 'meta' | 'hidden_input' | 'json' | 'header' | 'vault_cookie'
  detectedName?: string
  updatedAt: number
}

/** Browser-safe projection of a jar cookie, used to mirror non-HttpOnly cookies into Playwright. */
export interface BrowserMirrorCookie {
  name: string
  value: string
  domain: string
  path: string
  secure: boolean
  httpOnly: boolean
  sameSite: 'Strict' | 'Lax' | 'None'
  expires?: number
}

interface SessionJar {
  jarKey: string
  assignmentKey: string
  runId: string
  assignmentId: string
  role: string
  session: string
  scopeRevision: number
  cookies: Map<string, JarCookieEntry>
  csrfTokens: Map<string, StoredCsrfToken>
  lastUsedAt: number
}

function normalizeCookiePath(rawPath: string | undefined, requestPathname: string): string {
  if (rawPath && rawPath.startsWith('/')) {
    return rawPath.length > 1 && rawPath.endsWith('/') ? rawPath.slice(0, -1) : rawPath
  }
  const idx = requestPathname.lastIndexOf('/')
  if (idx <= 0) return '/'
  return requestPathname.slice(0, idx)
}

function cookiePathMatches(requestPath: string, cookiePath: string): boolean {
  if (cookiePath === '/') return true
  if (requestPath === cookiePath) return true
  const prefix = cookiePath.endsWith('/') ? cookiePath : `${cookiePath}/`
  return requestPath.startsWith(prefix)
}

/** RFC-6265 domain-match: host-only cookies require an exact issuing origin; Domain cookies match subdomains. */
function cookieDomainMatches(entry: JarCookieEntry, url: URL): boolean {
  if (entry.hostOnly) return entry.origin === url.origin
  const host = url.hostname.toLowerCase()
  return host === entry.domain || host.endsWith(`.${entry.domain}`)
}

/** URL-decode double-submit CSRF cookie values (e.g. `XSRF-TOKEN=abc%3D`) defensively. */
function decodeCsrfValue(raw: string): string {
  if (!raw.includes('%')) return raw
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

/** Path prefixes used to key CSRF tokens by `(origin, pathPrefix)` with origin fallback. */
function csrfPathPrefixes(pathname: string): string[] {
  const out: string[] = []
  let cursor = pathname || '/'
  for (;;) {
    out.push(cursor)
    if (cursor === '/' || cursor === '') break
    const idx = cursor.lastIndexOf('/')
    cursor = idx <= 0 ? '/' : cursor.slice(0, idx)
  }
  return out
}

function parseSetCookieHeaderEntries(
  headers: IncomingHttpHeaders,
  requestUrl: URL,
): Array<{ action: 'set' | 'delete'; entry: JarCookieEntry }> {
  const raw = headers['set-cookie']
  if (!raw) return []
  const items = Array.isArray(raw) ? raw : [raw]
  const out: Array<{ action: 'set' | 'delete'; entry: JarCookieEntry }> = []
  const now = Date.now()
  for (const cookieStr of items) {
    const parts = cookieStr.split(';')
    const nameVal = parts[0] ?? ''
    const eqIdx = nameVal.indexOf('=')
    if (eqIdx <= 0) continue
    const name = nameVal.slice(0, eqIdx).trim()
    const value = nameVal.slice(eqIdx + 1).trim()
    if (!name || /[\r\n\0;]/.test(name) || /[\r\n\0]/.test(value)) continue

    let pathAttr: string | undefined
    let domainAttr: string | undefined
    let secure = false
    let httpOnly = false
    let sameSite: string | null = null
    let expiresAt: number | undefined
    let deleteCookie = false

    for (const rawAttr of parts.slice(1)) {
      const attr = rawAttr.trim()
      if (!attr) continue
      const attrEq = attr.indexOf('=')
      const k = (attrEq >= 0 ? attr.slice(0, attrEq) : attr).trim().toLowerCase()
      const v = attrEq >= 0 ? attr.slice(attrEq + 1).trim() : ''
      if (k === 'secure') secure = true
      else if (k === 'httponly') httpOnly = true
      else if (k === 'path') pathAttr = v
      else if (k === 'domain') domainAttr = v.replace(/^\.+/, '').toLowerCase()
      else if (k === 'samesite') sameSite = v || null
      else if (k === 'max-age') {
        const secs = Number(v)
        if (Number.isFinite(secs)) {
          if (secs <= 0) deleteCookie = true
          else expiresAt = now + secs * 1000
        }
      } else if (k === 'expires') {
        const parsedTs = Date.parse(v)
        if (Number.isFinite(parsedTs)) {
          if (parsedTs <= now) deleteCookie = true
          else if (expiresAt === undefined) expiresAt = parsedTs
        }
      }
    }

    if (domainAttr) {
      const host = requestUrl.hostname.toLowerCase()
      if (domainAttr !== host && !host.endsWith(`.${domainAttr}`)) {
        // Reject cross-origin Domain attribute
        continue
      }
      // RFC-6265 §5.3 step 5: reject public-suffix / single-label Domain scopes
      // (e.g. Domain=com). `localhost` stays valid for authorized local labs.
      if (!domainAttr.includes('.') && domainAttr !== 'localhost') continue
    }

    const hostOnly = !domainAttr
    const domain = hostOnly ? requestUrl.hostname.toLowerCase() : domainAttr!
    const path = normalizeCookiePath(pathAttr, requestUrl.pathname)
    // Host-only keys stay scoped to the issuing origin (port included); Domain keys are
    // shared across in-scope subdomains (`app.` <-> `api.`) inside the same session jar.
    const scopeKey = hostOnly ? `host:${requestUrl.origin}` : `domain:${domain}`
    const key = `${scopeKey}\0${path}\0${name}`
    out.push({
      action: deleteCookie ? 'delete' : 'set',
      entry: {
        key,
        origin: requestUrl.origin,
        domain,
        hostOnly,
        name,
        value,
        path,
        secure,
        httpOnly,
        sameSite,
        expiresAt,
        setAt: now,
        writeCount: 0,
      },
    })
  }
  return out
}

function parseCookieHeaderPairs(headerValue: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const part of headerValue.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    const k = trimmed.slice(0, eq).trim()
    const v = trimmed.slice(eq + 1).trim()
    if (k) out.set(k, v)
  }
  return out
}

function extractHtmlAttr(tag: string, attrName: string): string | null {
  const re = new RegExp(`\\b${attrName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')
  const m = re.exec(tag)
  if (!m) return null
  return (m[1] ?? m[2] ?? m[3] ?? '').trim()
}

function extractCsrfFromBody(mediaType: string, body: string): Omit<StoredCsrfToken, 'updatedAt'> | null {
  if (!body) return null
  const lowerMedia = mediaType.toLowerCase()
  const looksHtml = lowerMedia.includes('html') || /^\s*</.test(body)
  if (looksHtml) {
    const metaTags = body.match(/<meta\b[^>]*>/gi) ?? []
    for (const tag of metaTags) {
      const name = extractHtmlAttr(tag, 'name')
      if (name && /^(?:csrf-token|xsrf-token|_csrf|csrf_token)$/i.test(name)) {
        const content = extractHtmlAttr(tag, 'content')
        if (content) {
          return { value: content, sourceKind: 'meta', detectedName: name }
        }
      }
    }
    const inputTags = body.match(/<input\b[^>]*>/gi) ?? []
    for (const tag of inputTags) {
      const name = extractHtmlAttr(tag, 'name')
      const type = extractHtmlAttr(tag, 'type')?.toLowerCase()
      if (name && (csrfInputNameRegex.test(name) || (type === 'hidden' && /csrf|xsrf|token/i.test(name)))) {
        const value = extractHtmlAttr(tag, 'value')
        if (value) {
          return { value, sourceKind: 'hidden_input', detectedName: name }
        }
      }
    }
  }
  const looksJson = lowerMedia.includes('json') || /^\s*\{/.test(body)
  if (looksJson) {
    try {
      const parsed = JSON.parse(body) as unknown
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const rec = parsed as Record<string, unknown>
        const candidateKeys = ['csrfToken', 'csrf_token', 'xsrfToken', 'xsrf_token', '_csrf', 'csrf']
        for (const k of candidateKeys) {
          const v = rec[k]
          if (typeof v === 'string' && v.trim()) {
            return { value: v.trim(), sourceKind: 'json', detectedName: k }
          }
        }
        if (rec.data && typeof rec.data === 'object' && !Array.isArray(rec.data)) {
          const dataRec = rec.data as Record<string, unknown>
          for (const k of candidateKeys) {
            const v = dataRec[k]
            if (typeof v === 'string' && v.trim()) {
              return { value: v.trim(), sourceKind: 'json', detectedName: k }
            }
          }
        }
      }
    } catch {
      // Not valid JSON
    }
  }
  return null
}

function matchesSandboxWriteAllowlist(
  origin: string,
  pathname: string,
  rawPathAndQuery: string,
  patterns: readonly ApprovedEndpointPattern[],
): boolean {
  const rawPathOnly = rawPathAndQuery.split('?')[0] ?? rawPathAndQuery
  if (
    rawPathOnly.includes('..') ||
    /%2e/i.test(rawPathOnly) ||
    /%25/i.test(rawPathOnly) ||
    pathname.includes('..') ||
    /[\r\n\0\\]/.test(rawPathOnly)
  ) {
    return false
  }
  // Iteratively decode up to 3 passes to catch double/triple-encoded path traversal
  let decoded = rawPathOnly
  for (let pass = 0; pass < 3; pass += 1) {
    let next: string
    try {
      next = decodeURIComponent(decoded)
    } catch {
      return false
    }
    if (next.includes('..') || /[\r\n\0\\]/.test(next)) return false
    if (next === decoded) break
    decoded = next
  }
  for (const pattern of patterns) {
    let patOrigin: string
    try {
      patOrigin = new URL(pattern.origin).origin
    } catch {
      continue
    }
    if (patOrigin !== origin) continue
    const patMethod = (pattern.method || 'POST').toUpperCase()
    if (patMethod !== 'POST' && patMethod !== '*') continue

    const rawPat = (pattern.pathPattern || '').trim()
    if (!rawPat || !rawPat.startsWith('/')) continue
    if (rawPat === '/*') return true
    if (rawPat.endsWith('/*')) {
      const prefix = rawPat.slice(0, -2)
      if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return true
    } else if (rawPat.endsWith('*')) {
      const prefix = rawPat.slice(0, -1)
      if (pathname.startsWith(prefix)) return true
    } else if (pathname === rawPat) {
      return true
    }
  }
  return false
}

function decodeJwtSegmentJson(seg: string): Record<string, unknown> | null {
  try {
    const raw = Buffer.from(seg, 'base64url').toString('utf8')
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    return null
  }
}

function encodeJwtJson(obj: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url')
}

const danglingCnameProviders: Array<{ provider: string; cname: RegExp }> = [
  { provider: 'GitHub Pages', cname: /\.github\.io\.?$/i },
  { provider: 'Vercel', cname: /\.(?:vercel-dns\.com|now\.sh)\.?$/i },
  { provider: 'Netlify', cname: /\.netlify\.(?:app|com)\.?$/i },
  { provider: 'AWS S3', cname: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$/i },
  { provider: 'AWS CloudFront', cname: /\.cloudfront\.net\.?$/i },
  { provider: 'Heroku', cname: /\.herokudns\.com\.?$|\.herokuapp\.com\.?$/i },
  { provider: 'Fastly', cname: /\.fastly\.net\.?$/i },
  { provider: 'Fly.io', cname: /\.fly\.dev\.?$/i },
  { provider: 'Cloudflare Pages', cname: /\.pages\.dev\.?$/i },
  { provider: 'Azure', cname: /\.(?:azurewebsites\.net|cloudapp\.net|blob\.core\.windows\.net)\.?$/i },
  { provider: 'Shopify', cname: /\.myshopify\.com\.?$/i },
  { provider: 'Ghost', cname: /\.ghost\.io\.?$/i },
  { provider: 'Surge', cname: /\.surge\.sh\.?$/i },
  { provider: 'Render', cname: /\.onrender\.com\.?$/i },
  { provider: 'Railway', cname: /\.up\.railway\.app\.?$/i },
  { provider: 'Webflow', cname: /\.webflow\.io\.?$|proxy-ssl\.webflow\.com\.?$/i },
]

export class BrokerDenied extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BrokerDenied'
  }
}

export class BrokerCircuitOpen extends Error {
  readonly origin: string
  readonly reason: string
  constructor(origin: string, reason: string) {
    super(`Defensive circuit breaker opened for ${origin}: ${reason}`)
    this.name = 'BrokerCircuitOpen'
    this.origin = origin
    this.reason = reason
  }
}

export class BrokerApprovalRequired extends Error {
  readonly origin: string
  readonly method: string
  readonly pathAndQuery: string
  constructor(origin: string, method: string, pathAndQuery: string) {
    super(`Tier 3 operator approval required for ${method} ${origin}${pathAndQuery}`)
    this.name = 'BrokerApprovalRequired'
    this.origin = origin
    this.method = method
    this.pathAndQuery = pathAndQuery
  }
}

/**
 * Probe classes whose payloads legitimately provoke parser/DB/template errors. A 5xx from these
 * is target evidence, so it must not feed the availability circuit breaker.
 */
const errorInducingProbePattern = /(?:sqli|ssti|xxe|xpath|ldap|nosql|injection|traversal|deserial|template|expression|parser)/i

function isErrorInducingProbe(probeClass: string | undefined): boolean {
  return Boolean(probeClass && errorInducingProbePattern.test(probeClass))
}

function hasDestructiveContent(text: string): boolean {
  if (containsDestructivePayload(text)) return true
  try {
    const decoded = decodeURIComponent(text.replaceAll('+', ' '))
    if (decoded !== text && containsDestructivePayload(decoded)) return true
  } catch {
    // Malformed percent-encoding; still check simple + replacement.
    const plusDecoded = text.replaceAll('+', ' ')
    if (plusDecoded !== text && containsDestructivePayload(plusDecoded)) return true
  }
  return false
}

function allowLocalLab(grant: Grant): boolean {
  return Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
}

export function isPublicAddress({ address }: PublicAddress): boolean {
  try {
    const ip = ipaddr.process(address)
    if (ip.range() !== 'unicast') return false
    return ip.kind() === 'ipv4' || ip.toByteArray()[0] >> 5 === 1
  } catch {
    return false
  }
}

async function withAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason
  let cancel = () => {}
  try {
    const aborted = new Promise<never>((_resolve, reject) => {
      cancel = () => reject(signal.reason)
      signal.addEventListener('abort', cancel, { once: true })
    })
    return await Promise.race([aborted, promise])
  } finally {
    signal.removeEventListener('abort', cancel)
  }
}

function header(headers: IncomingHttpHeaders, key: string): string | undefined {
  const value = headers[key]
  return Array.isArray(value) ? value.join(', ') : value
}

function referrerPolicy(value: string | undefined): PublicObservation['referrerPolicy'] {
  if (value === undefined) return 'absent'
  if (value.includes('"')) return 'unrecognized'
  const tokens = value.split(',').map(token => token.trim())
  return tokens.findLast((token): token is typeof referrerPolicies[number] =>
    referrerPolicies.some(policy => policy === token)) ?? 'unrecognized'
}

function contentSecurityPolicy(headers: IncomingHttpHeaders): PublicObservation['contentSecurityPolicy'] {
  const enforced = header(headers, 'content-security-policy')
  const reportOnly = header(headers, 'content-security-policy-report-only')
  if (enforced !== undefined) return enforced.trim() ? 'enforced' : 'unrecognized'
  if (reportOnly !== undefined) return reportOnly.trim() ? 'report-only' : 'unrecognized'
  return 'absent'
}

function frameProtection(headers: IncomingHttpHeaders): PublicObservation['frameProtection'] {
  const csp = header(headers, 'content-security-policy')
  const xfo = header(headers, 'x-frame-options')
  const frameAncestors = Boolean(csp && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(csp))
  const validXfo = Boolean(xfo && /^(?:deny|sameorigin)\s*$/i.test(xfo.split(',', 1)[0]))
  if (frameAncestors && validXfo) return 'both'
  if (frameAncestors) return 'csp-frame-ancestors'
  if (validXfo) return 'x-frame-options'
  if (xfo !== undefined) return 'unrecognized'
  return 'absent'
}

function serverDisclosure(headers: IncomingHttpHeaders): PublicObservation['serverDisclosure'] {
  if (header(headers, 'x-powered-by')) return 'technology'
  const server = header(headers, 'server')?.trim()
  if (!server) return 'absent'
  return /(?:\d|\/|next|express|php|asp\.net|nginx|apache)/i.test(server) ? 'technology' : 'generic'
}

function corsPolicy(headers: IncomingHttpHeaders, requestOrigin?: string): PublicObservation['corsPolicy'] | undefined {
  const acao = header(headers, 'access-control-allow-origin')?.trim()
  const acac = header(headers, 'access-control-allow-credentials')?.trim().toLowerCase() === 'true'
  if (!acao) return undefined
  if (acao === '*') return 'wildcard'
  if (requestOrigin && acao === requestOrigin) {
    return acac ? 'reflected-origin-with-credentials' : 'reflected-origin'
  }
  return 'restricted'
}

function parseSetCookies(headers: IncomingHttpHeaders): SetCookieSummary[] {
  const raw = headers['set-cookie']
  if (!raw) return []
  const items = Array.isArray(raw) ? raw : [raw]
  return items.slice(0, 32).map(cookie => {
    const parts = cookie.split(';')
    const name = parts[0]?.split('=', 1)[0]?.trim() || 'cookie'
    const attrs = parts.slice(1).map(p => p.trim())
    const secure = attrs.some(a => /^secure$/i.test(a))
    const httpOnly = attrs.some(a => /^httponly$/i.test(a))
    const sameSiteAttr = attrs.find(a => /^samesite=/i.test(a))
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=', 2)[1]?.trim() ?? null : null
    return { name: name.slice(0, 128), secure, httpOnly, sameSite }
  })
}

function sessionCookiePolicy(headers: IncomingHttpHeaders): PublicObservation['sessionCookiePolicy'] | undefined {
  const cookies = parseSetCookies(headers)
  if (!cookies.length) return undefined
  const sessionCookies = cookies.filter(c => /(?:^|\b)(?:sess|sid|auth|token|jwt|__session|__host-)/i.test(c.name))
  if (!sessionCookies.length) return 'none'
  const allSecure = sessionCookies.every(c => c.secure)
  const allHttpOnly = sessionCookies.every(c => c.httpOnly)
  if (allSecure && allHttpOnly) return 'secure-httponly'
  if (allSecure) return 'secure-only'
  return 'insecure'
}

/**
 * Non-default ports are refused on public targets unless the operator explicitly
 * allowlists them (grant.allowedPorts) or exports GUARDIAN_ALLOWED_PORTS=8080,8443.
 * This keeps the port invariant while permitting authorized staging origins.
 */
function operatorApprovedPorts(): number[] {
  const raw = process.env.GUARDIAN_ALLOWED_PORTS
  if (!raw) return []
  const out: number[] = []
  for (const part of raw.split(',')) {
    const n = Number(part.trim())
    if (Number.isInteger(n) && n > 0 && n <= 65535) out.push(n)
  }
  return out
}

function portAllowed(port: string, protocol: string, allowedPorts?: readonly number[]): boolean {
  if (!port) return true
  const defaultPort = protocol === 'https:' ? '443' : '80'
  if (port === defaultPort) return true
  const numeric = Number(port)
  if (!Number.isInteger(numeric)) return false
  return Boolean(allowedPorts?.includes(numeric)) || operatorApprovedPorts().includes(numeric)
}

function safeUrl(url: URL, allowQuery: boolean, localLab: boolean, allowedPorts?: readonly number[]): boolean {
  const validProtocol = url.protocol === 'https:' || (localLab && url.protocol === 'http:')
  if (!validProtocol || url.username || url.password || url.hash) return false
  if (!localLab && !portAllowed(url.port, url.protocol, allowedPorts)) return false
  if (!allowQuery && !localLab && url.search) return false
  const full = url.pathname + url.search
  return full.length <= maxPathLength && !url.pathname.startsWith('//') && !/[\r\n\0]/.test(full)
}

const routeUuidSegment = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const routeNumericSegment = /^\d+$/
const routeLongHexSegment = /^[0-9a-f]{16,}$/i
const routePrefixedIdSegment = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
const routeOpaqueSegment = /^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}$/

/** Stable `(origin, routeTemplate)` circuit key: dynamic path segments collapse to `*`. */
export function routeTemplateForPath(pathname: string): string {
  const segments = (pathname || '/').split('/')
  const templated = segments.map((seg, idx) => {
    if (idx === 0 || seg === '') return seg
    if (
      routeUuidSegment.test(seg) ||
      routeNumericSegment.test(seg) ||
      routeLongHexSegment.test(seg) ||
      routePrefixedIdSegment.test(seg) ||
      routeOpaqueSegment.test(seg)
    ) {
      return '*'
    }
    return seg.toLowerCase()
  })
  return templated.join('/') || '/'
}

function parseRetryAfterSeconds(headers: IncomingHttpHeaders | undefined): number | undefined {
  const raw = headers?.['retry-after']
  const value = Array.isArray(raw) ? raw[0] : raw
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed) return undefined
  const asNumber = Number(trimmed)
  if (Number.isFinite(asNumber) && asNumber >= 0) return Math.min(asNumber, 300)
  const asDate = Date.parse(trimmed)
  if (Number.isFinite(asDate)) return Math.min(Math.max(0, Math.ceil((asDate - Date.now()) / 1000)), 300)
  return undefined
}

function encodeMultipartParts(parts: readonly BrokerMultipartPart[]): { contentType: string; body: string } {
  if (parts.length === 0 || parts.length > maxMultipartParts) {
    throw new BrokerDenied(`multipartParts must contain between 1 and ${maxMultipartParts} parts.`)
  }
  let totalBytes = 0
  for (const part of parts) {
    if (!part.name || /[\r\n\0"]/.test(part.name) || part.name.length > 128) {
      throw new BrokerDenied('Invalid multipart part name.')
    }
    if (part.filename && (/[\r\n\0"]/.test(part.filename) || part.filename.length > 256)) {
      throw new BrokerDenied('Invalid multipart filename.')
    }
    if (!part.contentType || /[\r\n\0]/.test(part.contentType) || part.contentType.length > 128) {
      throw new BrokerDenied('Invalid multipart contentType.')
    }
    const serialized = `${part.name}\n${part.filename ?? ''}\n${part.contentType}\n${part.content}`
    if (hasDestructiveContent(serialized)) {
      throw new BrokerDenied('Multipart upload blocked by Guardian destructive-payload denylist.')
    }
    if (containsWebshellSignature(serialized)) {
      throw new BrokerDenied('Multipart upload blocked by Guardian webshell signature filter.')
    }
    totalBytes += Buffer.byteLength(part.content, 'utf8')
    if (totalBytes > maxMultipartBytes) {
      throw new BrokerDenied(`Multipart upload exceeds Guardian 256 KiB limit (${totalBytes} bytes).`)
    }
  }

  const boundary = `----GuardianBoundary${randomBytes(12).toString('hex')}`
  const chunks: string[] = []
  for (const part of parts) {
    chunks.push(`--${boundary}\r\n`)
    const disposition = part.filename
      ? `Content-Disposition: form-data; name="${part.name}"; filename="${part.filename}"\r\n`
      : `Content-Disposition: form-data; name="${part.name}"\r\n`
    chunks.push(disposition)
    chunks.push(`Content-Type: ${part.contentType}\r\n\r\n`)
    chunks.push(part.content)
    chunks.push('\r\n')
  }
  chunks.push(`--${boundary}--\r\n`)
  return {
    contentType: `multipart/form-data; boundary=${boundary}`,
    body: chunks.join(''),
  }
}

function encodeWsClientFrame(opcode: number, payload: Buffer): Buffer {
  const mask = randomBytes(4)
  const len = payload.length
  let header: Buffer
  if (len < 126) {
    header = Buffer.alloc(2)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 0x80 | len
  } else if (len < 65_536) {
    header = Buffer.alloc(4)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 0x80 | 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 0x80 | (opcode & 0x0f)
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  const masked = Buffer.alloc(len)
  for (let i = 0; i < len; i += 1) {
    masked[i] = payload[i] ^ mask[i & 3]
  }
  return Buffer.concat([header, mask, masked])
}

function defaultWsTransport(
  url: URL,
  address: PublicAddress,
  signal: AbortSignal,
  options: {
    headers: Record<string, string>
    subprotocols?: string[]
    sendMessages: string[]
    maxFrames: number
    maxBytes: number
    timeoutMs: number
    rejectUnauthorized: boolean
  },
): Promise<{
  connected: boolean
  upgradeStatus: number | null
  upgradeHeaders: Record<string, string>
  subprotocol: string | null
  frames: BrokerWebsocketFrame[]
  closeCode: number | null
  closeReason: string | null
  error: string | null
}> {
  return new Promise((resolve) => {
    const isSecure = url.protocol === 'https:'
    const port = url.port ? Number(url.port) : (isSecure ? 443 : 80)
    const wsKey = randomBytes(16).toString('base64')
    const expectedAccept = createHash('sha1').update(wsKey + wsGuid).digest('base64')

    const reqLines = [
      `GET ${url.pathname + url.search} HTTP/1.1`,
      `Host: ${url.host}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${wsKey}`,
      'Sec-WebSocket-Version: 13',
      'User-Agent: Guardian/3 defensive websocket probe',
    ]
    if (options.subprotocols && options.subprotocols.length > 0) {
      reqLines.push(`Sec-WebSocket-Protocol: ${options.subprotocols.join(', ')}`)
    }
    for (const [k, v] of Object.entries(options.headers)) {
      if (/^(?:host|upgrade|connection|sec-websocket-key|sec-websocket-version|sec-websocket-protocol)$/i.test(k)) continue
      reqLines.push(`${k}: ${v}`)
    }
    reqLines.push('', '')

    const frames: BrokerWebsocketFrame[] = []
    let upgradeDone = false
    let connected = false
    let upgradeStatus: number | null = null
    let upgradeHeaders: Record<string, string> = {}
    let subprotocol: string | null = null
    let closeCode: number | null = null
    let closeReason: string | null = null
    let errorMsg: string | null = null
    let receivedCount = 0
    let totalBytes = 0
    let buf: Buffer<ArrayBufferLike> = Buffer.alloc(0)
    let settled = false

    const socket: NetSocket | TLSSocket = isSecure
      ? tlsConnect({
          host: address.address,
          port,
          servername: url.hostname,
          rejectUnauthorized: options.rejectUnauthorized,
        })
      : netConnect({
          host: address.address,
          port,
        })

    const idleTimer = setTimeout(() => {
      finish()
    }, options.timeoutMs)

    let settleWaitTimer: ReturnType<typeof setTimeout> | undefined

    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(idleTimer)
      if (settleWaitTimer) clearTimeout(settleWaitTimer)
      signal.removeEventListener('abort', onAbort)
      try {
        if (connected && !socket.destroyed) {
          socket.write(encodeWsClientFrame(0x8, Buffer.alloc(0)))
        }
      } catch { /* ignore */ }
      socket.destroy()
      resolve({
        connected,
        upgradeStatus,
        upgradeHeaders,
        subprotocol,
        frames,
        closeCode,
        closeReason,
        error: errorMsg,
      })
    }

    const onAbort = () => {
      errorMsg = errorMsg ?? 'WebSocket probe aborted.'
      finish()
    }
    if (signal.aborted) {
      onAbort()
      return
    }
    signal.addEventListener('abort', onAbort, { once: true })

    const sendHandshake = () => {
      socket.write(reqLines.join('\r\n'))
    }

    if (isSecure) {
      socket.once('secureConnect', sendHandshake)
    } else {
      socket.once('connect', sendHandshake)
    }

    const processFrames = () => {
      while (buf.length >= 2) {
        const b0 = buf[0]
        const b1 = buf[1]
        const opcode = b0 & 0x0f
        const masked = (b1 & 0x80) !== 0
        let payloadLen = b1 & 0x7f
        let offset = 2
        if (payloadLen === 126) {
          if (buf.length < 4) return
          payloadLen = buf.readUInt16BE(2)
          offset = 4
        } else if (payloadLen === 127) {
          if (buf.length < 10) return
          const bigLen = buf.readBigUInt64BE(2)
          if (bigLen > BigInt(options.maxBytes)) {
            errorMsg = 'WebSocket frame exceeded byte limit.'
            finish()
            return
          }
          payloadLen = Number(bigLen)
          offset = 10
        }
        const maskBytes = masked ? 4 : 0
        if (buf.length < offset + maskBytes + payloadLen) return
        let payload = buf.subarray(offset + maskBytes, offset + maskBytes + payloadLen)
        if (masked) {
          const maskKey = buf.subarray(offset, offset + 4)
          const unmasked = Buffer.alloc(payloadLen)
          for (let i = 0; i < payloadLen; i += 1) {
            unmasked[i] = payload[i] ^ maskKey[i & 3]
          }
          payload = unmasked
        }
        buf = buf.subarray(offset + maskBytes + payloadLen)

        if (opcode === 0x8) {
          // Close frame
          if (payload.length >= 2) {
            closeCode = payload.readUInt16BE(0)
            closeReason = payload.subarray(2).toString('utf8').slice(0, 256)
          }
          finish()
          return
        }
        if (opcode === 0x9) {
          // Ping -> Pong
          try { socket.write(encodeWsClientFrame(0xa, payload.subarray(0, 125))) } catch { /* ignore */ }
          continue
        }
        if (opcode === 0xa) continue // Pong

        if (opcode === 0x1 || opcode === 0x2 || opcode === 0x0) {
          const remaining = options.maxBytes - totalBytes
          const slice = payload.length > remaining ? payload.subarray(0, Math.max(0, remaining)) : payload
          totalBytes += slice.length
          receivedCount += 1
          frames.push({
            direction: 'received',
            opcode: opcode === 0x2 ? 'binary' : 'text',
            data: opcode === 0x2 ? slice.toString('base64') : slice.toString('utf8'),
            bytes: slice.length,
            timestamp: Date.now(),
          })
          if (receivedCount >= options.maxFrames || totalBytes >= options.maxBytes) {
            finish()
            return
          }
        }
      }
    }

    socket.on('data', (chunk: Buffer) => {
      if (settled) return
      buf = Buffer.concat([buf, chunk])
      if (!upgradeDone) {
        const headerEnd = buf.indexOf('\r\n\r\n')
        if (headerEnd === -1) {
          if (buf.length > 32 * 1024) {
            errorMsg = 'WebSocket upgrade response headers exceeded 32 KiB.'
            finish()
          }
          return
        }
        upgradeDone = true
        const headerText = buf.subarray(0, headerEnd).toString('latin1')
        buf = buf.subarray(headerEnd + 4)
        const lines = headerText.split('\r\n')
        const statusLine = lines[0] ?? ''
        const statusMatch = /^HTTP\/1\.[01]\s+(\d{3})/i.exec(statusLine)
        upgradeStatus = statusMatch ? Number(statusMatch[1]) : null
        const parsedHeaders: Record<string, string> = {}
        for (const line of lines.slice(1)) {
          const colon = line.indexOf(':')
          if (colon <= 0) continue
          const k = line.slice(0, colon).trim().toLowerCase()
          const v = line.slice(colon + 1).trim()
          parsedHeaders[k] = parsedHeaders[k] ? `${parsedHeaders[k]}, ${v}` : v
        }
        upgradeHeaders = parsedHeaders
        subprotocol = parsedHeaders['sec-websocket-protocol'] ?? null

        if (upgradeStatus !== 101 || parsedHeaders['sec-websocket-accept'] !== expectedAccept) {
          connected = false
          if (upgradeStatus === 101) {
            errorMsg = 'Invalid Sec-WebSocket-Accept header during handshake.'
          }
          finish()
          return
        }

        connected = true
        // Send bounded client messages (up to maxFrames and maxBytes)
        for (const msg of options.sendMessages.slice(0, options.maxFrames)) {
          const payload = Buffer.from(msg, 'utf8')
          if (totalBytes + payload.length > options.maxBytes) break
          totalBytes += payload.length
          socket.write(encodeWsClientFrame(0x1, payload))
          frames.push({
            direction: 'sent',
            opcode: 'text',
            data: msg,
            bytes: payload.length,
            timestamp: Date.now(),
          })
        }

        // Wait briefly for server replies even if server keeps socket open
        const waitMs = Math.min(options.timeoutMs, options.sendMessages.length > 0 ? 1200 : 800)
        settleWaitTimer = setTimeout(() => finish(), waitMs)
      }

      if (connected) {
        processFrames()
      }
    })

    socket.once('error', (err) => {
      errorMsg = err.message
      finish()
    })
    socket.once('close', () => {
      finish()
    })
  })
}

function defaultTransport(
  url: URL,
  address: PublicAddress,
  signal: AbortSignal,
  options?: {
    method?: string
    headers?: Record<string, string>
    body?: string
    maxBodyBytes?: number
    readBody?: boolean
    rejectUnauthorized?: boolean
  },
): Promise<RawHttpResponse> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:'
    const port = url.port ? Number(url.port) : (isHttps ? 443 : 80)
    const method = options?.method ?? 'GET'
    const readBody = options?.readBody ?? false
    const cap = Math.min(options?.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes)
    const headers: Record<string, string> = {
      Host: url.host,
      Accept: 'text/html, application/json;q=0.9, */*;q=0.1',
      'Accept-Encoding': 'gzip, deflate, br',
      'User-Agent': 'Guardian/2 defensive evidence review',
      ...(options?.headers ?? {}),
    }
    if (options?.body !== undefined && !headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json'
    }
    if (options?.body !== undefined) {
      headers['Content-Length'] = String(Buffer.byteLength(options.body))
    }

    const onResponse = (res: import('node:http').IncomingMessage) => {
      const tls = res.socket instanceof TLSSocket ? extractTlsMetadata(res.socket, url.hostname) : undefined
      if (!readBody || method === 'HEAD') {
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: '', bodyBytes: 0, bodyTruncated: false, tls })
        res.destroy()
        return
      }
      const encoding = (header(res.headers, 'content-encoding') ?? '').toLowerCase().trim()
      let stream: NodeJS.ReadableStream = res
      let decompressed = false
      if (encoding === 'gzip' || encoding === 'x-gzip') {
        const gunzip = createGunzip()
        res.pipe(gunzip)
        stream = gunzip
        decompressed = true
      } else if (encoding === 'deflate') {
        const inflate = createInflate()
        res.pipe(inflate)
        stream = inflate
        decompressed = true
      } else if (encoding === 'br') {
        const brotli = createBrotliDecompress()
        res.pipe(brotli)
        stream = brotli
        decompressed = true
      }

      const chunks: Buffer[] = []
      let total = 0
      let truncated = false
      let finished = false
      const done = () => {
        if (finished) return
        finished = true
        const responseHeaders: IncomingHttpHeaders = { ...res.headers }
        if (decompressed) {
          delete responseHeaders['content-encoding']
          delete responseHeaders['content-length']
        }
        resolve({
          status: res.statusCode ?? 0,
          headers: responseHeaders,
          body: Buffer.concat(chunks).toString('utf8'),
          bodyBytes: total,
          bodyTruncated: truncated,
          tls,
        })
      }
      stream.on('data', (chunk: Buffer) => {
        if (finished) return
        if (total + chunk.length > cap) {
          const remaining = cap - total
          if (remaining > 0) chunks.push(chunk.subarray(0, remaining))
          total = cap
          truncated = true
          res.destroy()
          done()
          return
        }
        chunks.push(chunk)
        total += chunk.length
      })
      stream.once('end', done)
      stream.once('close', done)
      stream.once('error', err => {
        if (!finished) {
          if (truncated) done()
          else reject(err)
        }
      })
    }

    const req = isHttps
      ? httpsRequest({
          hostname: address.address,
          servername: url.hostname,
          port,
          path: url.pathname + url.search,
          method,
          agent: false,
          rejectUnauthorized: options?.rejectUnauthorized ?? true,
          signal,
          headers,
        }, onResponse)
      : httpRequest({
          hostname: address.address,
          port,
          path: url.pathname + url.search,
          method,
          agent: false,
          signal,
          headers,
        }, onResponse)

    req.once('error', reject)
    if (options?.body !== undefined) req.write(options.body)
    req.end()
  })
}

async function defaultDnsRecordResolver(hostname: string, signal: AbortSignal) {
  const safe = async <T>(fn: () => Promise<T>, fallback: T): Promise<{ value: T; nxdomain: boolean }> => {
    try {
      const value = await withAbort(fn(), signal)
      return { value, nxdomain: false }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code
      return { value: fallback, nxdomain: code === 'ENOTFOUND' || code === 'NXDOMAIN' }
    }
  }
  const [aRes, aaaaRes, cnameRes, txtRes, nsRes] = await Promise.all([
    safe(() => resolve4(hostname), [] as string[]),
    safe(() => resolve6(hostname), [] as string[]),
    safe(() => resolveCname(hostname), [] as string[]),
    safe(() => resolveTxt(hostname), [] as string[][]),
    safe(() => resolveNs(hostname), [] as string[]),
  ])
  const txt = txtRes.value.map(chunks => chunks.join('')).slice(0, 64)
  const hasAny = aRes.value.length > 0 || aaaaRes.value.length > 0 || cnameRes.value.length > 0 || txt.length > 0 || nsRes.value.length > 0
  const nxdomain = !hasAny && (aRes.nxdomain || cnameRes.nxdomain)
  return {
    a: aRes.value.slice(0, 32),
    aaaa: aaaaRes.value.slice(0, 32),
    cname: cnameRes.value.slice(0, 32),
    txt,
    ns: nsRes.value.slice(0, 32),
    nxdomain,
  }
}

function defaultTlsInspector(url: URL, address: PublicAddress, signal: AbortSignal): Promise<TlsMetadata> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason)
      return
    }
    const port = url.port ? Number(url.port) : 443
    // rejectUnauthorized: false ONLY for read-only TLS certificate inspection (zero HTTP bytes sent)
    // so expired, self-signed, or SAN-mismatched certificates can be inspected and reported honestly.
    const socket = tlsConnect({
      host: address.address,
      port,
      servername: url.hostname,
      rejectUnauthorized: false,
    })
    let settled = false
    const finish = (err?: unknown, metadata?: TlsMetadata) => {
      if (settled) return
      settled = true
      signal.removeEventListener('abort', onAbort)
      socket.destroy()
      if (err) reject(err)
      else resolve(metadata!)
    }
    const onAbort = () => finish(signal.reason)
    signal.addEventListener('abort', onAbort, { once: true })
    socket.once('secureConnect', () => {
      try {
        const meta = extractTlsMetadata(socket, url.hostname)
        finish(undefined, meta)
      } catch (err) {
        finish(err)
      }
    })
    socket.once('error', err => finish(err))
  })
}

function observed(
  origin: string,
  url: URL,
  response: RawHttpResponse,
  source: PublicObservation['source'],
  requestOriginHeader?: string,
): PublicObservation {
  const transport = header(response.headers, 'strict-transport-security') ?? ''
  const ages = transport.split(';').filter(directive => /^\s*max-age\s*(?:=|$)/i.test(directive))
  const parsed = ages.length === 1 ? ages[0].match(/^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i) : null
  const maxAge = parsed ? Number(parsed[1] ?? parsed[2]) : NaN
  const rawType = header(response.headers, 'content-type')?.split(';', 1)[0].trim().toLowerCase() ?? ''
  const typeOptions = header(response.headers, 'x-content-type-options')
  const nosniff = typeOptions?.split(',', 1)[0].trim().toLowerCase() === 'nosniff'
  const cors = corsPolicy(response.headers, requestOriginHeader)
  const cookies = sessionCookiePolicy(response.headers)
  return {
    origin,
    finalOrigin: url.origin,
    status: response.status,
    mediaType: /^[a-z0-9.+-]{1,40}\/[a-z0-9.+-]{1,60}$/.test(rawType) ? rawType : 'unknown',
    transportMaxAge: Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : null,
    includeSubDomains: /(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(transport),
    source,
    contentTypeOptions: typeOptions === undefined ? 'absent' : nosniff ? 'nosniff' : 'unrecognized',
    referrerPolicy: referrerPolicy(header(response.headers, 'referrer-policy')),
    contentSecurityPolicy: contentSecurityPolicy(response.headers),
    frameProtection: frameProtection(response.headers),
    serverDisclosure: serverDisclosure(response.headers),
    ...(cors ? { corsPolicy: cors } : {}),
    ...(cookies ? { sessionCookiePolicy: cookies } : {}),
  }
}

function normalizeHeaders(headers: IncomingHttpHeaders | Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue
    out[k.toLowerCase()] = (Array.isArray(v) ? v.join(', ') : String(v)).slice(0, 2048)
  }
  return out
}

function collectSecrets(req: BrokerHttpRequest, grant: Grant): NamedSecret[] {
  const all: NamedSecret[] = []
  if (grant.personas) all.push(...personaSecrets(grant.personas))
  if (grant.secrets) all.push(...grant.secrets)
  if (req.secrets) all.push(...req.secrets)
  return all
}

type OriginHealth = {
  errors5xx: number[]
  errors429: number[]
  openReason?: string
  openUntil?: number
  /** Consecutive trips drive the per-origin exponential backoff. */
  consecutiveOpens: number
  /** Last computed backoff (exposed for tests/diagnostics). */
  backoffMs: number
  /** 5xx observations attributable to our own active injection/parser probes (never trips). */
  probeInduced5xx: number[]
  tokens: number
  lastRefill: number
  inFlight: number
  batchActive: boolean
  /** Adaptive rate cap after 429 pressure; recovers toward the configured cap on healthy responses. */
  adaptiveRps?: number
  retryAfterUntil?: number
}

type RouteHealth = {
  failures: number[]
  openUntil?: number
  cooldownMs: number
  halfOpen: boolean
  consecutiveOpens: number
}

export class RequestBroker {
  private readonly options: BrokerOptions
  private readonly origins = new Map<string, OriginHealth>()
  private readonly routeCircuits = new Map<string, RouteHealth>()
  private readonly sessionJars = new Map<string, SessionJar>()
  private readonly redactedSecrets = new Map<string, NamedSecret>()
  private readonly seenGcbTokens = new Map<string, { probeClass: string; verifyUsed: boolean }>()
  private readonly transportConfig: TransportConfig
  private readonly httpTransport: Transport
  private latestScopeRevision = 0

  constructor(options: BrokerOptions = {}) {
    this.options = options
    this.transportConfig = resolveTransportConfig(process.env, options.transportConfig)
    this.httpTransport = options.transport ?? createHttpTransport(this.transportConfig, defaultTransport)
  }

  /** Non-secret transport summary for diagnostics and tests. */
  getTransportSummary(): {
    http2: boolean
    mode: 'http2' | 'http1'
    proxy: string | null
    mtls: boolean
    authorizedUserAgent: string | null
  } {
    return {
      http2: this.transportConfig.http2,
      mode: this.transportConfig.http2 ? 'http2' : 'http1',
      proxy: this.transportConfig.proxy
        ? `${this.transportConfig.proxy.protocol}//${this.transportConfig.proxy.host}:${this.transportConfig.proxy.port}`
        : null,
      mtls: Boolean(this.transportConfig.mtls),
      authorizedUserAgent: this.transportConfig.headerProfile?.userAgent ?? null,
    }
  }

  closeTransport(): void {
    const transport = this.httpTransport as Transport & { close?: () => void }
    transport.close?.()
  }

  getStorage(): SecondOrderStore | undefined {
    return this.options.storage
  }

  getRegisteredSecrets(): NamedSecret[] {
    return [...this.redactedSecrets.values()]
  }

  private registerSecret(label: string, value: string | undefined) {
    if (!value || value.length < 4) return
    if (this.redactedSecrets.has(value)) return
    if (this.redactedSecrets.size >= 5_000) {
      const oldest = this.redactedSecrets.keys().next().value
      if (oldest !== undefined) this.redactedSecrets.delete(oldest)
    }
    this.redactedSecrets.set(value, { placeholder: `[redacted:${label}]`, value })
  }

  revokeOrigin(origin: string, scopeRevision?: number) {
    let normalized: string
    try {
      normalized = new URL(origin).origin
    } catch {
      normalized = origin
    }
    if (scopeRevision !== undefined && scopeRevision > this.latestScopeRevision) {
      this.latestScopeRevision = scopeRevision
    }
    this.purgeSessionJars(undefined, normalized)
  }

  revokeScope(scopeRevision: number) {
    if (scopeRevision > this.latestScopeRevision) {
      this.latestScopeRevision = scopeRevision
    }
    for (const [key, jar] of this.sessionJars.entries()) {
      if (jar.scopeRevision < scopeRevision) {
        this.sessionJars.delete(key)
      }
    }
  }

  purgeSessionJars(runId?: string, origin?: string) {
    if (!runId && !origin) {
      this.sessionJars.clear()
      return
    }
    for (const [key, jar] of this.sessionJars.entries()) {
      if (runId && jar.runId !== runId) continue
      if (!origin) {
        this.sessionJars.delete(key)
        continue
      }
      let originHost = ''
      try {
        originHost = new URL(origin).hostname.toLowerCase()
      } catch {
        originHost = ''
      }
      for (const [ck, c] of jar.cookies.entries()) {
        const domainScopedToOrigin = !c.hostOnly && originHost !== '' &&
          (c.domain === originHost || originHost.endsWith(`.${c.domain}`))
        if (c.origin === origin || domainScopedToOrigin) jar.cookies.delete(ck)
      }
      for (const tokenKey of [...jar.csrfTokens.keys()]) {
        if (tokenKey.startsWith(`${origin}\0`) || tokenKey === origin) jar.csrfTokens.delete(tokenKey)
      }
    }
  }

  private getOrCreateSessionJar(
    req: BrokerHttpRequest,
    grant: Grant,
  ): SessionJar | undefined {
    if (req.session === undefined) return undefined
    const runId = req.runId ?? 'default'
    const assignmentId = req.assignmentId ?? 'default'
    const role = req.sessionGroupRole ?? 'default'
    const assignmentKey = `${runId}\0${assignmentId}`
    const jarKey = `${assignmentKey}\0${role}\0${req.session}`
    const effectiveRevision = Math.max(this.latestScopeRevision, req.scopeRevision ?? grant.scopeRevision ?? 0)

    const existing = this.sessionJars.get(jarKey)
    if (existing) {
      existing.lastUsedAt = Date.now()
      // Refresh LRU order
      this.sessionJars.delete(jarKey)
      this.sessionJars.set(jarKey, existing)
      return existing
    }

    const maxJars = Math.max(1, Math.min(this.options.maxJarsPerAssignment ?? 12, 12))
    const assignmentJars = [...this.sessionJars.values()].filter(j => j.assignmentKey === assignmentKey)
    if (assignmentJars.length >= maxJars) {
      assignmentJars.sort((a, b) => a.lastUsedAt - b.lastUsedAt)
      const toEvict = assignmentJars.length - maxJars + 1
      for (let i = 0; i < toEvict; i += 1) {
        const victim = assignmentJars[i]
        if (victim) this.sessionJars.delete(victim.jarKey)
      }
    }

    const cookies = new Map<string, JarCookieEntry>()
    const csrfTokens = new Map<string, StoredCsrfToken>()

    // Only `setup` jars may seed `control` or `probe` via deep-clone on first access;
    // `control` and `probe` remain strictly isolated from each other.
    if (role === 'control' || role === 'probe') {
      const setupKey = `${assignmentKey}\0setup\0${req.session}`
      const setupJar = this.sessionJars.get(setupKey)
      if (setupJar) {
        for (const [k, v] of setupJar.cookies.entries()) cookies.set(k, { ...v })
        for (const [k, v] of setupJar.csrfTokens.entries()) csrfTokens.set(k, { ...v })
      }
    }

    const created: SessionJar = {
      jarKey,
      assignmentKey,
      runId,
      assignmentId,
      role,
      session: req.session,
      scopeRevision: effectiveRevision,
      cookies,
      csrfTokens,
      lastUsedAt: Date.now(),
    }
    this.sessionJars.set(jarKey, created)
    return created
  }

  private storeJarCookiesAndCsrf(
    jar: SessionJar,
    url: URL,
    response: RawHttpResponse,
    mediaType: string,
  ) {
    const maxCookies = Math.max(1, Math.min(this.options.maxCookiesPerJar ?? 32, 64))
    const parsedEntries = parseSetCookieHeaderEntries(response.headers, url)
    const csrfPathPrefix = normalizeCookiePath(undefined, url.pathname)
    for (const item of parsedEntries) {
      if (item.action === 'delete') {
        jar.cookies.delete(item.entry.key)
        continue
      }
      const existing = jar.cookies.get(item.entry.key)
      item.entry.writeCount = (existing?.writeCount ?? 0) + 1
      if (existing) {
        jar.cookies.delete(item.entry.key)
      } else if (jar.cookies.size >= maxCookies) {
        while (jar.cookies.size >= maxCookies) {
          const oldest = jar.cookies.keys().next().value
          if (oldest === undefined) break
          jar.cookies.delete(oldest)
        }
      }
      jar.cookies.set(item.entry.key, item.entry)
      this.registerSecret(`jar:${jar.session}:${item.entry.name}`, item.entry.value)

      if (csrfCookieNameRegex.test(item.entry.name) && item.entry.value) {
        jar.csrfTokens.set(`${url.origin}\0${csrfPathPrefix}`, {
          value: decodeCsrfValue(item.entry.value),
          sourceKind: 'cookie',
          detectedName: item.entry.name,
          updatedAt: Date.now(),
        })
      }
    }

    // Response-header CSRF sources (double-submit / Next.js / XSRF variants).
    for (const headerName of ['x-csrf-token', 'x-xsrf-token', 'csrf-token', 'x-csrftoken']) {
      const raw = response.headers[headerName]
      const value = Array.isArray(raw) ? raw[0] : raw
      if (!value || !value.trim()) continue
      const token = decodeCsrfValue(value.trim())
      this.registerSecret(`csrf:${jar.session}:${headerName}`, token)
      jar.csrfTokens.set(`${url.origin}\0${csrfPathPrefix}`, {
        value: token,
        sourceKind: 'header',
        detectedName: headerName,
        updatedAt: Date.now(),
      })
      break
    }

    const bodyCsrf = extractCsrfFromBody(mediaType, response.body ?? '')
    if (bodyCsrf) {
      this.registerSecret(`csrf:${jar.session}:${bodyCsrf.detectedName ?? 'token'}`, bodyCsrf.value)
      jar.csrfTokens.set(`${url.origin}\0${csrfPathPrefix}`, {
        ...bodyCsrf,
        value: decodeCsrfValue(bodyCsrf.value),
        updatedAt: Date.now(),
      })
    }
  }

  /** Look up a CSRF token for a hop: `(origin, pathPrefix)` first, then most-recent origin fallback. */
  private lookupCsrfToken(jar: SessionJar, url: URL): StoredCsrfToken | undefined {
    for (const prefix of csrfPathPrefixes(url.pathname)) {
      const hit = jar.csrfTokens.get(`${url.origin}\0${prefix}`)
      if (hit) return hit
    }
    let latest: StoredCsrfToken | undefined
    for (const [key, token] of jar.csrfTokens.entries()) {
      if (!key.startsWith(`${url.origin}\0`)) continue
      if (!latest || token.updatedAt > latest.updatedAt) latest = token
    }
    return latest
  }

  /** Internal helper for ScopedBrowser: non-HttpOnly jar cookies applicable to `origin` (never logged/serialized). */
  sessionCookiesForBrowser(
    scope: { session?: string; runId?: string; assignmentId?: string; sessionGroupRole?: string },
    origin: string,
  ): BrowserMirrorCookie[] {
    if (!scope.session) return []
    const assignmentKey = `${scope.runId ?? 'default'}\0${scope.assignmentId ?? 'default'}`
    const jarKey = `${assignmentKey}\0${scope.sessionGroupRole ?? 'default'}\0${scope.session}`
    const jar = this.sessionJars.get(jarKey)
    if (!jar) return []
    let parsed: URL
    try {
      parsed = new URL('/', origin)
    } catch {
      return []
    }
    const now = Date.now()
    const out: BrowserMirrorCookie[] = []
    for (const entry of jar.cookies.values()) {
      if (entry.httpOnly) continue
      if (!cookieDomainMatches(entry, parsed)) continue
      if (entry.expiresAt !== undefined && entry.expiresAt <= now) continue
      if (entry.secure && parsed.protocol !== 'https:') continue
      const sameSite = entry.sameSite?.toLowerCase()
      out.push({
        name: entry.name,
        value: entry.value,
        domain: entry.hostOnly ? parsed.hostname : entry.domain,
        path: entry.path,
        secure: entry.secure,
        httpOnly: false,
        sameSite: sameSite === 'strict' ? 'Strict' : sameSite === 'none' ? 'None' : 'Lax',
        ...(entry.expiresAt !== undefined ? { expires: Math.floor(entry.expiresAt / 1000) } : {}),
      })
    }
    return out
  }

  private now(): number {
    return this.options.now ? this.options.now() : Date.now()
  }

  private health(origin: string, capacity = 5): OriginHealth {
    let state = this.origins.get(origin)
    if (!state) {
      state = {
        errors5xx: [],
        errors429: [],
        tokens: capacity,
        lastRefill: this.now(),
        inFlight: 0,
        batchActive: false,
        consecutiveOpens: 0,
        backoffMs: 0,
        probeInduced5xx: [],
      }
      this.origins.set(origin, state)
    }
    return state
  }

  /** Origin-wide circuit (connection resets/timeouts/global 502–504/429 exhaustion). */
  isCircuitOpen(origin: string): boolean {
    const state = this.origins.get(origin)
    if (!state?.openReason) return false
    if (state.openUntil !== undefined && this.now() >= state.openUntil) {
      // Half-open: allow a single recovery probe by clearing the hard block.
      state.openReason = undefined
      state.openUntil = undefined
      state.errors5xx = []
      return false
    }
    return true
  }

  /** Read-only breaker snapshot (tests/diagnostics); never contains request content. */
  getCircuitState(origin: string): {
    open: boolean
    reason: string | null
    openUntil: number | null
    backoffMs: number
    consecutiveOpens: number
    failures5xx: number
    errors429: number
    probeInduced5xx: number
    adaptiveRps: number | null
    retryAfterUntil: number | null
  } {
    const state = this.origins.get(origin)
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? 30_000
    const inWindow = (ts: number) => now - ts < windowMs
    return {
      open: this.isCircuitOpen(origin),
      reason: state?.openReason ?? null,
      openUntil: state?.openUntil ?? null,
      backoffMs: state?.backoffMs ?? 0,
      consecutiveOpens: state?.consecutiveOpens ?? 0,
      failures5xx: state?.errors5xx.filter(inWindow).length ?? 0,
      errors429: state?.errors429.filter(inWindow).length ?? 0,
      probeInduced5xx: state?.probeInduced5xx.filter(inWindow).length ?? 0,
      adaptiveRps: state?.adaptiveRps ?? null,
      retryAfterUntil: state?.retryAfterUntil ?? null,
    }
  }

  /** Route-scoped breaker snapshot (tests/diagnostics). */
  getRouteCircuitState(origin: string, routeTemplate: string): {
    open: boolean
    openUntil: number | null
    cooldownMs: number
    consecutiveOpens: number
    failures: number
  } {
    const route = this.routeCircuits.get(`${origin}\0${routeTemplate}`)
    return {
      open: this.isRouteCircuitOpen(origin, routeTemplate),
      openUntil: route?.openUntil ?? null,
      cooldownMs: route?.cooldownMs ?? 0,
      consecutiveOpens: route?.consecutiveOpens ?? 0,
      failures: route?.failures.length ?? 0,
    }
  }

  /** Route-scoped circuit for ordinary 5xx responses. */
  isRouteCircuitOpen(origin: string, routeTemplate: string): boolean {
    const key = `${origin}\0${routeTemplate}`
    const route = this.routeCircuits.get(key)
    if (!route?.openUntil) return false
    if (this.now() >= route.openUntil) {
      route.halfOpen = true
      route.openUntil = undefined
      return false
    }
    return true
  }

  resetCircuit(origin?: string) {
    if (origin) {
      const h = this.origins.get(origin)
      if (h) {
        h.errors5xx = []
        h.errors429 = []
        h.openReason = undefined
        h.openUntil = undefined
        h.retryAfterUntil = undefined
        h.adaptiveRps = undefined
        h.consecutiveOpens = 0
        h.backoffMs = 0
        h.probeInduced5xx = []
      }
      for (const key of [...this.routeCircuits.keys()]) {
        if (key.startsWith(`${origin}\0`)) this.routeCircuits.delete(key)
      }
    } else {
      this.origins.clear()
      this.routeCircuits.clear()
    }
  }

  /**
   * Per-origin exponential backoff. A first trip waits `base`; each consecutive re-trip doubles
   * the wait up to `max`, after which the circuit half-opens automatically (see `isCircuitOpen`).
   * A successful recovery response resets the sequence to zero.
   */
  private cooldownMs(consecutiveOpens: number): number {
    const base = Math.max(1, this.options.circuitCooldownMs ?? this.options.circuitBackoffBaseMs ?? 1_000)
    const max = Math.max(base, this.options.circuitBackoffMaxMs ?? 30_000)
    const exponent = Math.min(16, Math.max(0, consecutiveOpens - 1))
    return Math.min(max, Math.round(base * 2 ** exponent))
  }

  private assertRouteCircuit(origin: string, routeTemplate: string): void {
    if (!this.isRouteCircuitOpen(origin, routeTemplate)) return
    throw new BrokerCircuitOpen(
      origin,
      `Route ${routeTemplate} tripped its 5xx circuit; half-open retry pending.`,
    )
  }

  private recordRouteStatus(origin: string, routeTemplate: string, status: number, audit: Grant['audit']) {
    const key = `${origin}\0${routeTemplate}`
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? 30_000
    const threshold = this.options.circuit5xxThreshold ?? 5
    let route = this.routeCircuits.get(key)
    if (!route) {
      route = { failures: [], cooldownMs: this.cooldownMs(1), halfOpen: false, consecutiveOpens: 0 }
      this.routeCircuits.set(key, route)
    }
    if (status >= 500 && status <= 599) {
      route.failures = route.failures.filter(ts => now - ts < windowMs)
      route.failures.push(now)
      if (route.halfOpen || route.failures.length >= threshold) {
        route.consecutiveOpens += 1
        route.cooldownMs = this.cooldownMs(route.consecutiveOpens)
        route.openUntil = now + route.cooldownMs
        route.halfOpen = false
        route.failures = []
        audit('circuit_open', origin, status)
        throw new BrokerCircuitOpen(
          origin,
          `Route ${routeTemplate} observed ${threshold}+ HTTP 5xx responses; cooling down ${Math.round(route.cooldownMs / 1000)}s (half-open).`,
        )
      }
    } else if (status < 500) {
      // Healthy response: close a half-open route and decay the failure window.
      route.failures = []
      route.halfOpen = false
      route.consecutiveOpens = 0
    }
  }

  private recordTransportFailure(origin: string, audit: Grant['audit']) {
    const state = this.health(origin)
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? 30_000
    const threshold = this.options.circuit5xxThreshold ?? 5
    state.errors5xx = state.errors5xx.filter(ts => now - ts < windowMs)
    state.errors5xx.push(now)
    if (state.errors5xx.length >= threshold) {
      state.openReason = `Observed ${state.errors5xx.length} connection resets/timeouts within ${Math.round(windowMs / 1000)}s.`
      state.consecutiveOpens += 1
      state.backoffMs = this.cooldownMs(state.consecutiveOpens)
      state.openUntil = now + state.backoffMs
      audit('circuit_open', origin)
      throw new BrokerCircuitOpen(origin, state.openReason)
    }
  }

  private async acquireSlot(
    origin: string,
    maxRps: number,
    signal: AbortSignal,
    bypassConcurrency = false,
    routeTemplate?: string,
  ): Promise<() => void> {
    const configuredRps = Math.max(1, Math.min(20, maxRps))
    const state = this.health(origin, configuredRps)
    if (state.openReason && (!state.openUntil || this.now() < state.openUntil)) {
      throw new BrokerCircuitOpen(origin, state.openReason)
    }
    if (!state.openReason) state.openUntil = undefined
    if (routeTemplate) this.assertRouteCircuit(origin, routeTemplate)

    for (;;) {
      signal.throwIfAborted()
      if (state.openReason && (!state.openUntil || this.now() < state.openUntil)) {
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
      if (routeTemplate) this.assertRouteCircuit(origin, routeTemplate)
      const now = Date.now()
      const rps = Math.max(1, Math.min(configuredRps, state.adaptiveRps ?? configuredRps))
      const elapsedSec = Math.max(0, (now - state.lastRefill) / 1000)
      state.tokens = Math.min(rps, state.tokens + elapsedSec * rps)
      state.lastRefill = now

      const retryAfterWait = state.retryAfterUntil !== undefined ? state.retryAfterUntil - now : 0
      const concurrencyOk = bypassConcurrency || state.inFlight < 2
      if (retryAfterWait <= 0 && concurrencyOk && state.tokens >= 1) {
        state.tokens -= 1
        state.inFlight += 1
        return () => {
          state.inFlight = Math.max(0, state.inFlight - 1)
        }
      }

      const waitMs = retryAfterWait > 0
        ? Math.min(1_000, Math.max(50, retryAfterWait))
        : state.tokens < 1
          ? Math.min(250, Math.max(20, Math.ceil(((1 - state.tokens) / rps) * 1000)))
          : 40
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          signal.removeEventListener('abort', onAbort)
          resolve()
        }, waitMs)
        const onAbort = () => {
          clearTimeout(timer)
          reject(signal.reason)
        }
        signal.addEventListener('abort', onAbort, { once: true })
      })
    }
  }

  private recordStatus(
    origin: string,
    status: number,
    audit: Grant['audit'],
    meta?: {
      routeTemplate?: string
      headers?: IncomingHttpHeaders
      configuredRps?: number
      /** Present on active probe traffic; error-inducing classes are excluded from breaker trips. */
      probeClass?: string
    },
  ) {
    const state = this.health(origin, meta?.configuredRps ?? 5)
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? 30_000
    const threshold5xx = this.options.circuit5xxThreshold ?? 5
    const threshold429 = this.options.circuit429Threshold ?? 8
    state.errors5xx = state.errors5xx.filter(ts => now - ts < windowMs)
    state.errors429 = state.errors429.filter(ts => now - ts < windowMs)
    state.probeInduced5xx = state.probeInduced5xx.filter(ts => now - ts < windowMs)

    // A 5xx produced by our own injection/parser payload is *evidence*, not target
    // unavailability: count it separately so the probe cannot block its own verification.
    if (status >= 500 && status <= 599 && isErrorInducingProbe(meta?.probeClass)) {
      state.probeInduced5xx.push(now)
      return
    }

    if (status === 429) {
      const retryAfter = parseRetryAfterSeconds(meta?.headers)
      if (retryAfter !== undefined && retryAfter > 0) {
        state.retryAfterUntil = now + retryAfter * 1000
      }
      const configured = Math.max(1, meta?.configuredRps ?? 5)
      state.adaptiveRps = Math.max(1, Math.floor((state.adaptiveRps ?? configured) / 2))
      state.errors429.push(now)
      if (state.errors429.length >= threshold429) {
        state.openReason = `Observed ${state.errors429.length} HTTP 429 rate-limit responses within ${Math.round(windowMs / 1000)}s.`
        state.consecutiveOpens += 1
        state.backoffMs = this.cooldownMs(state.consecutiveOpens)
        state.openUntil = now + state.backoffMs
        audit('circuit_open', origin, status)
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
      return
    }

    // Global gateway/availability failures keep origin-wide protection.
    if (status === 502 || status === 503 || status === 504) {
      state.errors5xx.push(now)
      if (state.errors5xx.length >= threshold5xx) {
        state.openReason = `Observed ${state.errors5xx.length} HTTP ${status} responses within ${Math.round(windowMs / 1000)}s.`
        state.consecutiveOpens += 1
        state.backoffMs = this.cooldownMs(state.consecutiveOpens)
        state.openUntil = now + state.backoffMs
        audit('circuit_open', origin, status)
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
      return
    }

    if (status >= 500 && status <= 599) {
      const routeTemplate = meta?.routeTemplate ?? routeTemplateForPath('/')
      this.recordRouteStatus(origin, routeTemplate, status, audit)
      return
    }

    // Healthy response: recover an adaptive RPS cap toward the configured ceiling.
    if (status < 400) {
      // A real success closes the origin breaker and restarts the backoff sequence.
      state.consecutiveOpens = 0
      state.backoffMs = 0
      if (state.openUntil === undefined || now >= state.openUntil) {
        state.openReason = undefined
        state.openUntil = undefined
      }
      const configured = Math.max(1, meta?.configuredRps ?? 5)
      if (state.adaptiveRps !== undefined) {
        state.adaptiveRps = Math.min(configured, state.adaptiveRps + 1)
        if (state.adaptiveRps >= configured) state.adaptiveRps = undefined
      }
      if (state.retryAfterUntil !== undefined && now >= state.retryAfterUntil) state.retryAfterUntil = undefined
    }

    // Any non-5xx response from a route proves half-open recovery for that route only.
    if (status < 500 && meta?.routeTemplate) {
      const route = this.routeCircuits.get(`${origin}\0${meta.routeTemplate}`)
      if (route) {
        route.failures = []
        route.halfOpen = false
        route.consecutiveOpens = 0
        route.openUntil = undefined
      }
    }
  }

  private async resolveAndCheckAddresses(hostname: string, grant: Grant, deadline: AbortSignal, originForAudit: string): Promise<PublicAddress[]> {
    const resolve = this.options.resolve ?? ((host: string) => lookup(host, { all: true, order: 'verbatim' }))
    const addresses = await withAbort(resolve(hostname), deadline)
    deadline.throwIfAborted()
    const localLab = allowLocalLab(grant)
    // Link-local ranges (169.254.0.0/16 incl. cloud metadata, fe80::/10) are never legitimate
    // targets — not even in an authorized local-lab. This guard stays fail-closed regardless of
    // Tier-3 auto-approval or GUARDIAN_ALLOW_LOCAL_LAB.
    const linkLocal = addresses.some(address => {
      try {
        return ipaddr.process(address.address).range() === 'linkLocal'
      } catch {
        return true
      }
    })
    if (addresses.length === 0 || linkLocal || (!localLab && addresses.some(address => !isPublicAddress(address)))) {
      grant.audit('denied', originForAudit)
      throw new BrokerDenied(
        linkLocal
          ? 'The target hostname resolved to a link-local/metadata address; cloud metadata and link-local endpoints are never permitted.'
          : 'The target hostname did not resolve exclusively to public addresses.',
      )
    }
    return addresses
  }

  async readPublicRoot(grant: Grant, signal: AbortSignal): Promise<PublicObservation> {
    if (!grant.origin) throw new BrokerDenied('Grant origin is required for readPublicRoot.')
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live HTTP requests are disabled in Tier 0 (offline prepared mode).')

    const localLab = allowLocalLab(grant)
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    const transport = this.httpTransport
    let url = new URL('/', grant.origin)
    const deny = (message: string): never => {
      grant.audit('denied', url.origin)
      throw new BrokerDenied(message)
    }
    const check = () => {
      deadline.throwIfAborted()
      if (!safeUrl(url, false, localLab, grant.allowedPorts) || !grant.canRead(url.origin)) {
        deny('Destination is outside the current assignment scope.')
      }
    }
    for (let redirect = 0; redirect <= 3; redirect += 1) {
      check()
      const addresses = await this.resolveAndCheckAddresses(url.hostname, grant, deadline, url.origin)
      check()
      const release = await this.acquireSlot(url.origin, grant.maxRpsPerOrigin ?? 5, deadline, false, routeTemplateForPath(url.pathname))
      let response: RawHttpResponse
      try {
        grant.audit('allowed', url.origin)
        response = await transport(url, addresses.find(a => a.family === 4) ?? addresses[0], deadline, {
          readBody: false,
          rejectUnauthorized: this.options.rejectUnauthorized ?? true,
        })
      } finally {
        release()
      }
      check()
      grant.audit('observed', url.origin, response.status)
      this.recordStatus(url.origin, response.status, grant.audit, {
        routeTemplate: routeTemplateForPath(url.pathname),
        headers: response.headers,
        configuredRps: grant.maxRpsPerOrigin ?? 5,
      })
      if (![301, 302, 303, 307, 308].includes(response.status)) {
        return observed(grant.origin, url, response, this.options.source ?? 'public response')
      }
      const location = response.headers.location
      if (!location || redirect === 3) return deny('The public response could not be followed within the redirect limit.')
      try {
        url = new URL(location, url)
      } catch {
        deny('The redirect destination is invalid.')
      }
    }
    return deny('The public response exceeded the redirect limit.')
  }

  private prepareHttpRequest(req: BrokerHttpRequest, grant: Grant, options: { raceBurst?: boolean } = {}): {
    initialOrigin: string
    url: URL
    localLab: boolean
    personaHandle: string | undefined
    resolvedPersonaHeaders: Record<string, string> | undefined
    cleanHeaders: Record<string, string>
    preparedBody: string | undefined
    secrets: NamedSecret[]
    followRedirects: boolean
    hasCompressedBody: boolean
    maxRps: number
    timeoutMs: number
  } {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live HTTP requests are disabled in Tier 0 (offline prepared mode).')

    if (req.session !== undefined && !sessionHandleRegex.test(req.session)) {
      throw new BrokerDenied('Invalid session handle; expected /^[a-z0-9_-]{1,32}$/.')
    }
    const reqScopeRev = req.scopeRevision ?? grant.scopeRevision
    if (reqScopeRev !== undefined) {
      if (reqScopeRev < this.latestScopeRevision) {
        throw new BrokerDenied('Request scopeRevision is stale relative to the current scope revision.')
      }
      if (reqScopeRev > this.latestScopeRevision) {
        this.revokeScope(reqScopeRev)
      }
    }

    const localLab = allowLocalLab(grant)
    let initialOrigin: string
    let url: URL
    try {
      initialOrigin = new URL(req.origin).origin
      url = new URL(req.pathAndQuery, initialOrigin)
    } catch {
      throw new BrokerDenied('Request origin or path is malformed.')
    }

    if (!req.pathAndQuery.startsWith('/') || req.pathAndQuery.startsWith('//') ||
        req.pathAndQuery.length > maxPathLength || /[\r\n\0]/.test(req.pathAndQuery)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Request path is invalid or exceeds Guardian 8 KiB limit.')
    }
    if (url.origin !== initialOrigin) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Request path escaped the requested origin.')
    }
    if (!safeUrl(url, true, localLab, grant.allowedPorts) || !grant.canRead(initialOrigin)) {
      this.purgeSessionJars(undefined, initialOrigin)
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Destination is outside the current assignment scope.')
    }

    if (req.probeClass === 'cache_poison_deception' || req.probeClass === 'cache_differential') {
      const gcb = url.searchParams.get('_gcb')
      if (!gcb || !cacheBusterValueRegex.test(gcb)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Cache probes require a unique ?_gcb=<16-36 hex/uuid> cache-buster query parameter.')
      }
      const seen = this.seenGcbTokens.get(gcb.toLowerCase())
      if (seen) {
        if (req.probeClass === 'cache_differential' && req.cacheVerify === true && !seen.verifyUsed) {
          seen.verifyUsed = true
        } else {
          grant.audit('denied', initialOrigin)
          throw new BrokerDenied('Reusing an already-used _gcb cache-buster token is forbidden.')
        }
      } else {
        if (this.seenGcbTokens.size >= 10_000) {
          const oldest = this.seenGcbTokens.keys().next().value
          if (oldest !== undefined) this.seenGcbTokens.delete(oldest)
        }
        this.seenGcbTokens.set(gcb.toLowerCase(), { probeClass: req.probeClass, verifyUsed: false })
      }
    }

    // Destructive payload denylist check across path (raw + URL-decoded), headers, body, and multipartParts
    const serializedHeaders = Object.entries(req.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')
    if (
      hasDestructiveContent(req.pathAndQuery) ||
      hasDestructiveContent(serializedHeaders) ||
      (req.body !== undefined && hasDestructiveContent(req.body))
    ) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Request blocked by Guardian destructive-payload denylist.')
    }
    if (req.authMutation?.kind === 'kid_inject' && hasDestructiveContent(req.authMutation.value)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('authMutation kid_inject blocked by Guardian destructive-payload denylist.')
    }
    if (req.authMutation?.kind === 'jku_x5u_canary') {
      const candidateUrl = req.authMutation.url ?? req.authMutation.value
      if (candidateUrl && (hasDestructiveContent(candidateUrl) || /[\r\n\0]/.test(candidateUrl))) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('authMutation jku_x5u_canary blocked by Guardian destructive-payload denylist.')
      }
    }

    const hasMultipart = Array.isArray(req.multipartParts) && req.multipartParts.length > 0
    if (hasMultipart && req.body !== undefined) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Specify either body or multipartParts, not both.')
    }

    const personaHandle = req.persona ?? req.personaHandle
    if (req.authMutation) {
      if (tier < 2) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Broker authMutation primitives require Tier 2 or higher.')
      }
      if (!personaHandle) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('authMutation requires an approved persona handle.')
      }
    }

    let resolvedPersonaHeaders: Record<string, string> | undefined
    if (personaHandle) {
      if (tier < 2) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Persona-authenticated requests require Tier 2 or higher.')
      }
      if (grant.personas) {
        const persona = grant.personas.get(personaHandle)
        if (!persona) {
          grant.audit('denied', initialOrigin)
          throw new BrokerDenied(`Persona "${personaHandle}" is not approved for this run.`)
        }
        const injected = buildPersonaHeader(persona, initialOrigin)
        if (!injected) {
          grant.audit('denied', initialOrigin)
          if (!persona.originAllowlist.includes(initialOrigin)) {
            throw new BrokerDenied(`Origin ${initialOrigin} is not in persona "${personaHandle}" originAllowlist.`)
          }
          throw new BrokerDenied(`Persona "${personaHandle}" does not have an active authenticated session yet.`)
        }
        resolvedPersonaHeaders = { ...injected }
      } else if (req.personaHeaders && Object.keys(req.personaHeaders).length > 0) {
        resolvedPersonaHeaders = { ...req.personaHeaders }
      } else {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied(`Persona "${personaHandle}" could not be resolved from run grant.`)
      }
    }

    const isReadOnlyMethod = req.method === 'GET' || req.method === 'HEAD' ||
      (req.method === 'OPTIONS' && (req.body === undefined || req.body === ''))
    const callerContentType = Object.entries(req.headers ?? {})
      .find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? ''
    const callerContentEncoding = Object.entries(req.headers ?? {})
      .find(([k]) => k.toLowerCase() === 'content-encoding')?.[1] ?? ''
    const hasMultipartContentType = /^\s*multipart\//i.test(callerContentType)
    const hasCompressedBody = callerContentEncoding.trim() !== '' && !/^identity$/i.test(callerContentEncoding.trim())
    if (!isReadOnlyMethod || hasMultipart) {
      // The only pre-approval fast path is the explicit Tier-2 sandbox write allowlist (an operator
      // configuration), never a caller-supplied path heuristic. Every other non-GET/HEAD request
      // goes through the exact-fingerprint approval hook.
      const sandboxPostAllowed = !hasMultipart && !hasMultipartContentType &&
        req.method === 'POST' && tier === 2 && (
          grant.sandboxWriteAllowlist !== undefined
            ? matchesSandboxWriteAllowlist(initialOrigin, url.pathname, req.pathAndQuery, grant.sandboxWriteAllowlist)
            : localLab
        )
      if (!sandboxPostAllowed) {
        if (tier < 3) {
          grant.audit('denied', initialOrigin)
          throw new BrokerDenied(
            hasMultipart || hasMultipartContentType
              ? 'Multipart uploads require Tier 3 (approval-gated state validation).'
              : `Method ${req.method} requires Tier 3 (approval-gated state validation).`,
          )
        }
        const approvalContext: StateChangeApprovalContext = {
          personaHandle: personaHandle ?? null,
          body: req.body ?? null,
          bodyHash: computeStateChangeBodyHash(req.body, req.multipartParts),
          hasMultipart: hasMultipart || hasMultipartContentType,
          isRaceBurst: options.raceBurst === true,
          hasCompressedBody,
        }
        const approved = grant.isStateChangeApproved
          ? grant.isStateChangeApproved(initialOrigin, req.method, req.pathAndQuery, approvalContext)
          : localLab
        if (!approved) {
          throw new BrokerApprovalRequired(initialOrigin, req.method, req.pathAndQuery)
        }
      }
    }

    const cleanHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers ?? {})) {
      if (forbiddenCallerHeaders.test(k)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied(`Header "${k}" cannot be set directly; reference an approved persona handle instead.`)
      }
      if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Invalid request header.')
      }
      cleanHeaders[k] = v
    }

    let preparedBody = req.body
    if (hasMultipart) {
      try {
        const encoded = encodeMultipartParts(req.multipartParts!)
        preparedBody = encoded.body
        for (const existingKey of Object.keys(cleanHeaders)) {
          if (existingKey.toLowerCase() === 'content-type') delete cleanHeaders[existingKey]
        }
        cleanHeaders['Content-Type'] = encoded.contentType
      } catch (err) {
        grant.audit('denied', initialOrigin)
        throw err
      }
    }

    const timeoutMs = Math.max(1_000, Math.min(req.timeoutMs ?? defaultRequestTimeoutMs, 60_000))
    const secrets = collectSecrets(req, grant)
    const followRedirects = req.followRedirects ?? true
    const defaultRps = tier === 3 ? 3 : 5
    const maxRps = grant.maxRpsPerOrigin ?? defaultRps

    return {
      initialOrigin,
      url,
      localLab,
      personaHandle,
      resolvedPersonaHeaders,
      cleanHeaders,
      preparedBody,
      secrets,
      followRedirects,
      hasCompressedBody,
      maxRps,
      timeoutMs,
    }
  }

  private async applyAuthMutationIfNeeded(
    prepared: ReturnType<RequestBroker['prepareHttpRequest']>,
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
  ): Promise<void> {
    if (!req.authMutation || !prepared.resolvedPersonaHeaders) return
    const mutation = req.authMutation
    const hdrs = prepared.resolvedPersonaHeaders

    // Locate JWT in Authorization: Bearer <jwt> or Cookie header value
    let jwtSource: { kind: 'header'; key: string } | { kind: 'cookie'; key: string; cookieName: string } | null = null
    let originalJwt = ''
    for (const [k, v] of Object.entries(hdrs)) {
      if (k.toLowerCase() === 'authorization') {
        const m = /^Bearer\s+(\S+)$/i.exec(v.trim())
        if (m && m[1].split('.').length === 3) {
          jwtSource = { kind: 'header', key: k }
          originalJwt = m[1]
          break
        }
      }
    }
    if (!jwtSource) {
      for (const [k, v] of Object.entries(hdrs)) {
        if (k.toLowerCase() === 'cookie') {
          for (const [cName, cVal] of parseCookieHeaderPairs(v).entries()) {
            if (cVal.split('.').length === 3 && cVal.startsWith('eyJ')) {
              jwtSource = { kind: 'cookie', key: k, cookieName: cName }
              originalJwt = cVal
              break
            }
          }
        }
        if (jwtSource) break
      }
    }
    if (!jwtSource || !originalJwt) {
      grant.audit('denied', prepared.initialOrigin)
      throw new BrokerDenied('authMutation requires a persona with a 3-segment JWT credential.')
    }

    const parts = originalJwt.split('.')
    if (parts.length !== 3) {
      grant.audit('denied', prepared.initialOrigin)
      throw new BrokerDenied('Persona credential is not a valid 3-part JWT.')
    }
    const [headerB64, payloadB64, sigB64] = parts
    const header = decodeJwtSegmentJson(headerB64)
    const payload = decodeJwtSegmentJson(payloadB64)
    if (!header || !payload) {
      grant.audit('denied', prepared.initialOrigin)
      throw new BrokerDenied('Persona JWT header or payload could not be decoded.')
    }

    this.registerSecret(`jwt:original:${prepared.personaHandle ?? 'persona'}`, originalJwt)
    this.registerSecret(`jwt:original_hp:${prepared.personaHandle ?? 'persona'}`, `${headerB64}.${payloadB64}`)
    this.registerSecret(`jwt:original_payload:${prepared.personaHandle ?? 'persona'}`, payloadB64)

    let mutatedJwt = originalJwt
    if (mutation.kind === 'alg_none') {
      const nextHeader = { ...header, alg: 'none' }
      mutatedJwt = `${encodeJwtJson(nextHeader)}.${payloadB64}.`
    } else if (mutation.kind === 'strip_signature') {
      mutatedJwt = `${headerB64}.${payloadB64}.`
    } else if (mutation.kind === 'expired_replay') {
      const nowSec = Math.floor(Date.now() / 1000)
      const skew = Math.max(1, Math.min(mutation.skewSeconds ?? 3600, 31_536_000))
      const curExp = typeof payload.exp === 'number' && Number.isFinite(payload.exp) ? payload.exp : nowSec
      const nextPayload = { ...payload, exp: Math.min(curExp, nowSec) - skew }
      mutatedJwt = `${headerB64}.${encodeJwtJson(nextPayload)}.${sigB64}`
    } else if (mutation.kind === 'kid_inject') {
      if (/[\r\n\0]/.test(mutation.value) || hasDestructiveContent(mutation.value)) {
        grant.audit('denied', prepared.initialOrigin)
        throw new BrokerDenied('kid_inject value rejected.')
      }
      const nextHeader = { ...header, kid: mutation.value }
      mutatedJwt = `${encodeJwtJson(nextHeader)}.${payloadB64}.${sigB64}`
    } else if (mutation.kind === 'jku_x5u_canary') {
      const hdrField = mutation.header ?? 'jku'
      let canaryUrl = mutation.url ?? mutation.value
      const cb = this.options.canaryBroker ?? grant.canaryBroker
      if (canaryUrl) {
        if (/[\r\n\0]/.test(canaryUrl) || hasDestructiveContent(canaryUrl)) {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL rejected.')
        }
        let parsedCanary: URL
        try {
          parsedCanary = new URL(canaryUrl)
        } catch {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL is malformed.')
        }
        if (parsedCanary.protocol !== 'http:' && parsedCanary.protocol !== 'https:') {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL must use http: or https: protocol.')
        }
        if (parsedCanary.search || parsedCanary.hash || parsedCanary.username || parsedCanary.password) {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL must not contain query, fragment, or userinfo.')
        }
        if (!canaryUrlRegex.test(parsedCanary.pathname)) {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL must target a Guardian CanaryBroker endpoint.')
        }
        const canaryHost = parsedCanary.hostname.toLowerCase().replace(/^\[|\]$/g, '')
        if (
          canaryHost === '169.254.169.254' ||
          canaryHost === 'metadata.google.internal' ||
          canaryHost === 'metadata.goog' ||
          canaryHost.startsWith('169.254.') ||
          canaryHost.startsWith('fe80:')
        ) {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL cannot target cloud metadata or link-local endpoints.')
        }
        if (ipaddr.isValid(canaryHost)) {
          const range = ipaddr.process(canaryHost).range()
          if (range === 'linkLocal') {
            grant.audit('denied', prepared.initialOrigin)
            throw new BrokerDenied('jku_x5u_canary URL cannot target link-local IP addresses.')
          }
          if (!prepared.localLab && range !== 'unicast') {
            grant.audit('denied', prepared.initialOrigin)
            throw new BrokerDenied('jku_x5u_canary URL cannot target private or loopback IPs on public projects.')
          }
        } else if (
          !prepared.localLab &&
          (canaryHost === 'localhost' || canaryHost.endsWith('.localhost') || canaryHost.endsWith('.local') || canaryHost.endsWith('.internal'))
        ) {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary URL cannot target local/internal hostnames on public projects.')
        }
        if (cb) {
          const info = cb.listenerInfo()
          const allowedOrigins = new Set<string>()
          for (const base of [info.effectiveBaseUrl, info.localBaseUrl, info.publicBaseUrl]) {
            if (base) {
              try { allowedOrigins.add(new URL(base).origin) } catch { /* ignore */ }
            }
          }
          if (allowedOrigins.size > 0 && !allowedOrigins.has(parsedCanary.origin)) {
            grant.audit('denied', prepared.initialOrigin)
            throw new BrokerDenied('jku_x5u_canary URL origin does not match the active Guardian CanaryBroker.')
          }
        }
      } else {
        if (cb) {
          if (!cb.listenerInfo().running) await cb.startListener()
          const minted = cb.mintCanary(
            req.runId ?? 'auth-mutation',
            `jwt-${hdrField}-canary`,
            prepared.initialOrigin,
          )
          canaryUrl = minted.httpUrl
        } else if (grant.mintCanary) {
          const minted = grant.mintCanary(`jwt-${hdrField}-canary`, prepared.initialOrigin)
          canaryUrl = minted?.httpUrl ?? minted?.url
        }
        if (!canaryUrl) {
          grant.audit('denied', prepared.initialOrigin)
          throw new BrokerDenied('jku_x5u_canary requires an explicit CanaryBroker URL or active CanaryBroker.')
        }
      }
      const nextHeader = { ...header, [hdrField]: canaryUrl }
      mutatedJwt = `${encodeJwtJson(nextHeader)}.${payloadB64}.${sigB64}`
    } else if (mutation.kind === 'rs256_to_hs256_jwks') {
      const jwksTarget = mutation.jwksUrl ?? `${prepared.initialOrigin}/.well-known/jwks.json`
      let parsedJwks: URL
      try {
        parsedJwks = new URL(jwksTarget)
      } catch {
        grant.audit('denied', prepared.initialOrigin)
        throw new BrokerDenied('rs256_to_hs256_jwks jwksUrl is malformed.')
      }
      const jwksEx = await this.executeHttp({
        origin: parsedJwks.origin,
        method: 'GET',
        pathAndQuery: parsedJwks.pathname + parsedJwks.search,
        headers: { accept: 'application/json' },
        followRedirects: false,
        runId: req.runId,
        assignmentId: req.assignmentId,
        traceId: req.traceId,
      }, grant, signal)
      if (jwksEx.status < 200 || jwksEx.status >= 300) {
        grant.audit('denied', prepared.initialOrigin)
        throw new BrokerDenied(`Failed to fetch JWKS (${jwksEx.status}) for rs256_to_hs256_jwks.`)
      }
      let keys: Array<Record<string, unknown>> = []
      try {
        const parsed = JSON.parse(jwksEx.body) as { keys?: Array<Record<string, unknown>> }
        if (Array.isArray(parsed.keys)) keys = parsed.keys
      } catch {
        keys = []
      }
      const targetKid = typeof header.kid === 'string' ? header.kid : undefined
      const selectedJwk =
        (targetKid ? keys.find(k => k.kid === targetKid) : undefined) ??
        keys.find(k => k.kty === 'RSA') ??
        keys[0]
      if (!selectedJwk) {
        grant.audit('denied', prepared.initialOrigin)
        throw new BrokerDenied('No usable RSA key found in JWKS for rs256_to_hs256_jwks.')
      }
      let pem: string
      try {
        pem = createPublicKey({ key: selectedJwk as never, format: 'jwk' })
          .export({ type: 'spki', format: 'pem' })
          .toString()
      } catch {
        grant.audit('denied', prepared.initialOrigin)
        throw new BrokerDenied('JWKS key could not be exported as SPKI PEM.')
      }
      const nextHeader = { ...header, alg: 'HS256' }
      const signingInput = `${encodeJwtJson(nextHeader)}.${payloadB64}`
      const hmacSig = createHmac('sha256', pem).update(signingInput).digest('base64url')
      mutatedJwt = `${signingInput}.${hmacSig}`
    } else if (mutation.kind === 'claim_swap') {
      const isUnsigned = String(header.alg ?? '').toLowerCase() === 'none' || sigB64 === ''
      if (!prepared.localLab && !isUnsigned) {
        grant.audit('denied', prepared.initialOrigin)
        throw new BrokerDenied('claim_swap on signed tokens is restricted to local-lab or unsigned tokens.')
      }
      const nextPayload = { ...payload, ...mutation.claims }
      mutatedJwt = `${headerB64}.${encodeJwtJson(nextPayload)}.${sigB64}`
    }

    this.registerSecret(`jwt:mutated:${mutation.kind}`, mutatedJwt)
    const mutatedParts = mutatedJwt.split('.')
    if (mutatedParts.length >= 2 && mutatedParts[0] && mutatedParts[1]) {
      this.registerSecret(`jwt:mutated_hp:${mutation.kind}`, `${mutatedParts[0]}.${mutatedParts[1]}`)
      if (mutatedParts[1] !== payloadB64) {
        this.registerSecret(`jwt:mutated_payload:${mutation.kind}`, mutatedParts[1])
      }
    }
    if (jwtSource.kind === 'header') {
      hdrs[jwtSource.key] = `Bearer ${mutatedJwt}`
    } else {
      const pairs = parseCookieHeaderPairs(hdrs[jwtSource.key] ?? '')
      pairs.set(jwtSource.cookieName, mutatedJwt)
      hdrs[jwtSource.key] = [...pairs.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
    }
  }

  private async executePreparedHttp(
    prepared: ReturnType<RequestBroker['prepareHttpRequest']>,
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
    options: {
      bypassConcurrency: boolean
      preResolvedAddresses?: PublicAddress[]
      reauthAttempted?: boolean
      refreshedPersonaHeaders?: Record<string, string>
      raceBurst?: boolean
      raceBarrier?: RaceBarrier
    },
  ): Promise<BrokerExchangeResult> {
    await this.applyAuthMutationIfNeeded(prepared, req, grant, signal)
    const {
      initialOrigin,
      localLab,
      personaHandle,
      cleanHeaders,
      secrets,
      followRedirects,
      hasCompressedBody,
      maxRps,
      timeoutMs,
    } = prepared
    let personaHeaders = options.refreshedPersonaHeaders ?? prepared.resolvedPersonaHeaders
    let url = new URL(prepared.url.href)
    const jar = this.getOrCreateSessionJar(req, grant)

    const started = Date.now()
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    const transport = this.httpTransport

    const redirectOrigins = new Set<string>([url.origin])
    const redirectPaths: string[] = []
    let activeMethod: BrokerHttpRequest['method'] = req.method
    let activeBody = prepared.preparedBody
    let includePersona = Boolean(personaHeaders && Object.keys(personaHeaders).length > 0)

    const deny = (message: string): never => {
      grant.audit('denied', url.origin)
      throw new BrokerDenied(message)
    }
    const check = () => {
      deadline.throwIfAborted()
      if (!safeUrl(url, true, localLab, grant.allowedPorts) || !grant.canRead(url.origin)) {
        this.purgeSessionJars(undefined, url.origin)
        deny('Destination is outside the current assignment scope.')
      }
    }
    /**
     * 307/308 preserve the method and body. A state-changing redirect therefore needs a fresh
     * exact-fingerprint authorization for the *target* (origin + method + path/query + body):
     * the approval that covered the first path must never be re-sent to a different one. GET/HEAD
     * redirects stay read-only and are followed without another approval.
     */
    const authorizeRedirectTarget = (target: URL, bodyForHop: string | undefined): void => {
      if (activeMethod === 'GET' || activeMethod === 'HEAD' ||
          (activeMethod === 'OPTIONS' && (activeBody === undefined || activeBody === ''))) return
      const targetPathAndQuery = `${target.pathname}${target.search}`
      const multipart = Array.isArray(req.multipartParts) && req.multipartParts.length > 0
      const context: StateChangeApprovalContext = {
        personaHandle: includePersona ? (personaHandle ?? null) : null,
        body: multipart ? null : (bodyForHop ?? null),
        bodyHash: multipart
          ? computeStateChangeBodyHash(req.body, req.multipartParts)
          : computeStateChangeBodyHash(bodyForHop ?? null),
        hasMultipart: multipart,
        isRaceBurst: options.raceBurst === true,
        hasCompressedBody,
      }
      const approved = grant.isStateChangeApproved
        ? grant.isStateChangeApproved(target.origin, activeMethod, targetPathAndQuery, context)
        : localLab
      if (!approved) {
        grant.audit('denied', target.origin)
        throw new BrokerApprovalRequired(target.origin, activeMethod, targetPathAndQuery)
      }
    }

    for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
      check()
      redirectOrigins.add(url.origin)
      const isCrossOriginHop = url.origin !== initialOrigin
      // Hard invariant: NEVER forward persona credentials across cross-origin redirects.
      if (isCrossOriginHop) includePersona = false

      const addresses = redirect === 0 && options.preResolvedAddresses
        ? options.preResolvedAddresses
        : await this.resolveAndCheckAddresses(url.hostname, grant, deadline, url.origin)
      check()

      const outboundHeaders: Record<string, string> = {
        ...cleanHeaders,
      }
      let personaCookieRaw: string | undefined
      if (includePersona && personaHeaders) {
        for (const [k, v] of Object.entries(personaHeaders)) {
          if (k.toLowerCase() === 'cookie') {
            personaCookieRaw = v
          } else {
            outboundHeaders[k] = v
          }
        }
      }

      if (localLab && req.traceId && !/[\r\n\0]/.test(req.traceId)) {
        outboundHeaders['X-Guardian-Trace-Id'] = req.traceId.slice(0, 128)
      }

      // Merge session jar cookies with Persona Vault cookies.
      // Invariant: the Vault credential wins over a colliding jar cookie UNLESS the jar
      // observed a genuine rotation (2+ Set-Cookie writes for that name), in which case
      // the fresh rotated value supersedes the stale vault cookie.
      const mergedCookies = new Map<string, string>()
      const jarCookieByName = new Map<string, JarCookieEntry>()
      if (jar) {
        const now = Date.now()
        for (const entry of jar.cookies.values()) {
          if (!cookieDomainMatches(entry, url)) continue
          if (entry.expiresAt !== undefined && entry.expiresAt <= now) continue
          if (entry.secure && url.protocol !== 'https:') continue
          if (!cookiePathMatches(url.pathname, entry.path)) continue
          const sameSiteLower = entry.sameSite?.toLowerCase()
          if (isCrossOriginHop && sameSiteLower === 'strict') continue
          if (isCrossOriginHop && sameSiteLower === 'lax' && activeMethod !== 'GET' && activeMethod !== 'HEAD') continue
          jarCookieByName.set(entry.name, entry)
        }
      }
      const vaultCookies = personaCookieRaw ? parseCookieHeaderPairs(personaCookieRaw) : new Map<string, string>()
      for (const [name, entry] of jarCookieByName) {
        if (!vaultCookies.has(name) || entry.writeCount > 1) mergedCookies.set(name, entry.value)
      }
      for (const [k, v] of vaultCookies) {
        const jarEntry = jarCookieByName.get(k)
        if (jarEntry && jarEntry.writeCount > 1) continue
        mergedCookies.set(k, v)
      }
      if (mergedCookies.size > 0) {
        outboundHeaders.Cookie = [...mergedCookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
      }

      // Automatic CSRF token binding (same-origin only)
      let hopBody = activeBody
      let hopContentType: string | undefined
      let injectedCsrfHeaderName: string | undefined
      if (jar && req.csrfBind && !isCrossOriginHop) {
        const cfg = req.csrfBind === true ? {} : req.csrfBind
        let csrfToken: StoredCsrfToken | undefined
        if (cfg.cookieName) {
          const nowTs = Date.now()
          for (const entry of jar.cookies.values()) {
            if (
              cookieDomainMatches(entry, url) &&
              entry.name === cfg.cookieName &&
              cookiePathMatches(url.pathname, entry.path) &&
              !(entry.secure && url.protocol !== 'https:') &&
              !(entry.expiresAt !== undefined && entry.expiresAt <= nowTs)
            ) {
              csrfToken = {
                value: decodeCsrfValue(entry.value),
                sourceKind: 'cookie',
                detectedName: entry.name,
                updatedAt: nowTs,
              }
              break
            }
          }
        }
        csrfToken ??= this.lookupCsrfToken(jar, url)
        if (!csrfToken) {
          // Fall back to a double-submit cookie supplied by the Persona Vault.
          for (const [name, value] of vaultCookies) {
            if (!csrfCookieNameRegex.test(name) || !value) continue
            csrfToken = {
              value: decodeCsrfValue(value),
              sourceKind: 'vault_cookie',
              detectedName: name,
              updatedAt: Date.now(),
            }
            break
          }
        }
        if (csrfToken) {
          this.registerSecret(`csrf:${jar.session}:${csrfToken.detectedName ?? 'token'}`, csrfToken.value)
          const headerName = cfg.headerName ?? (
            (csrfToken.sourceKind === 'cookie' || csrfToken.sourceKind === 'vault_cookie') &&
            csrfToken.detectedName?.toLowerCase() === 'xsrf-token'
              ? 'X-XSRF-TOKEN'
              : 'X-CSRF-Token'
          )
          const hasHeaderAlready = Object.keys(outboundHeaders).some(k => k.toLowerCase() === headerName.toLowerCase())
          if (!hasHeaderAlready && !/[\r\n\0]/.test(headerName)) {
            outboundHeaders[headerName] = csrfToken.value
            injectedCsrfHeaderName = headerName.toLowerCase()
          }
          if (activeMethod === 'POST' || activeMethod === 'PUT' || activeMethod === 'PATCH' || activeMethod === 'DELETE') {
            const ct = Object.entries(outboundHeaders)
              .find(([k]) => k.toLowerCase() === 'content-type')?.[1]?.toLowerCase() ?? ''
            if (ct.includes('application/x-www-form-urlencoded')) {
              const fieldName = cfg.fieldName ?? csrfToken.detectedName ?? '_csrf'
              const params = new URLSearchParams(hopBody ?? '')
              if (!params.has(fieldName)) {
                params.set(fieldName, csrfToken.value)
                hopBody = params.toString()
              }
            } else if (ct.includes('application/json') && (cfg.fieldName || csrfToken.sourceKind === 'json')) {
              const fieldName = cfg.fieldName ?? csrfToken.detectedName ?? 'csrfToken'
              try {
                const parsed = hopBody ? JSON.parse(hopBody) as unknown : {}
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                  const rec = parsed as Record<string, unknown>
                  if (!(fieldName in rec)) {
                    rec[fieldName] = csrfToken.value
                    hopBody = JSON.stringify(rec)
                  }
                }
              } catch {
                // Leave malformed JSON body untouched
              }
            } else if (ct.includes('multipart/form-data') && req.multipartParts?.length) {
              // Multipart CSRF injection: re-encode with an extra field part (deterministic boundary).
              const fieldName = cfg.fieldName ?? csrfToken.detectedName ?? '_csrf'
              if (!req.multipartParts.some(part => part.name === fieldName)) {
                const encoded = encodeMultipartParts([
                  ...req.multipartParts,
                  { name: fieldName, contentType: 'text/plain', content: csrfToken.value },
                ])
                hopBody = encoded.body
                hopContentType = encoded.contentType
              }
            }
          }
        }
      }
      if (hopContentType) {
        for (const existingKey of Object.keys(outboundHeaders)) {
          if (existingKey.toLowerCase() === 'content-type') delete outboundHeaders[existingKey]
        }
        outboundHeaders['Content-Type'] = hopContentType
      }

      const hopRouteTemplate = routeTemplateForPath(url.pathname)
      const release = await this.acquireSlot(url.origin, maxRps, deadline, options.bypassConcurrency, hopRouteTemplate)
      let response: RawHttpResponse
      try {
        grant.audit('allowed', url.origin)
        response = await transport(url, addresses.find(a => a.family === 4) ?? addresses[0], deadline, {
          method: activeMethod,
          headers: outboundHeaders,
          body: hopBody,
          maxBodyBytes: Math.min(req.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes),
          readBody: true,
          rejectUnauthorized: this.options.rejectUnauthorized ?? true,
          ...(options.raceBarrier ? { raceBarrier: options.raceBarrier } : {}),
        })
      } catch (err) {
        if (!deadline.aborted) this.recordTransportFailure(url.origin, grant.audit)
        throw err
      } finally {
        release()
      }
      check()
      grant.audit('observed', url.origin, response.status)
      this.recordStatus(url.origin, response.status, grant.audit, {
        routeTemplate: hopRouteTemplate,
        headers: response.headers,
        configuredRps: maxRps,
        probeClass: req.probeClass,
      })

      const requestOriginHeader = cleanHeaders['Origin'] ?? cleanHeaders['origin']
      const obs = observed(initialOrigin, url, response, this.options.source ?? 'public response', requestOriginHeader)
      if (jar) {
        this.storeJarCookiesAndCsrf(jar, url, response, obs.mediaType)
      }

      // 401 auto-refresh: invoke the rate-limited persona re-auth callback once, then retry.
      if (
        response.status === 401 &&
        includePersona &&
        personaHandle &&
        !req.authMutation &&
        !options.reauthAttempted &&
        this.options.reauth &&
        !deadline.aborted
      ) {
        const refreshed = await this.options.reauth(personaHandle, url.origin).catch(() => false)
        if (refreshed !== false) {
          const refreshedPersona = grant.personas?.get(personaHandle)
          const rebuilt = refreshedPersona ? buildPersonaHeader(refreshedPersona, initialOrigin) : null
          return this.executePreparedHttp(prepared, req, grant, signal, {
            ...options,
            reauthAttempted: true,
            ...(rebuilt ? { refreshedPersonaHeaders: rebuilt } : {}),
          })
        }
      }

      if (followRedirects && [301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.location
        if (!location || redirect === maxRedirects) {
          return deny('The response could not be followed within the redirect limit.')
        }
        try {
          url = new URL(location, url)
        } catch {
          return deny('The redirect destination is invalid.')
        }
        // Local-lab containment: Tier-3 auto-approval is bound to the isolated lab origin, so a
        // redirect must never carry it to an external host — even if that host was (mis)scoped.
        if (localLab && !isLocalLabAutoApprovalOrigin(url.origin)) {
          return deny('Local-lab requests may not follow redirects outside the isolated lab network.')
        }
        if (response.status === 301 || response.status === 302 || response.status === 303) {
          activeMethod = 'GET'
          activeBody = undefined
        } else {
          // 307/308 re-send the same method and body. Re-authorize the exact redirect target before
          // a single byte is sent there; fail closed with the target in BrokerApprovalRequired.
          authorizeRedirectTarget(url, hopBody ?? activeBody)
        }
        redirectPaths.push(`${url.pathname}${url.search}`)
        continue
      }

      const rawBody = response.body ?? ''
      const secondOrderStorage = this.options.storage ?? grant.storage
      if (secondOrderStorage && req.runId && rawBody) {
        scanSecondOrderMarkers({
          text: rawBody,
          runId: req.runId,
          assignmentId: req.assignmentId,
          origin: url.origin,
          endpoint: url.pathname + url.search,
          persona: personaHandle ?? null,
          storage: secondOrderStorage,
        })
      }

      const effectiveSecrets: NamedSecret[] = [
        ...secrets,
        ...this.redactedSecrets.values(),
      ]
      // Structural evidence must be captured from the pre-redaction bytes: redaction is correct
      // for logs/LLMs but erases what a disclosure verifier needs. Only bounded fingerprints leave
      // this scope; raw values stay in memory for the duration of the scan.
      const rawResponseHeaders = normalizeHeaders(response.headers)
      const secretMatches = [
        ...scanSecrets(rawBody, { secrets: effectiveSecrets }),
        ...scanSecretHeaders(rawResponseHeaders, { secrets: effectiveSecrets }),
      ]
      const safeBody = redact(rawBody, effectiveSecrets)
      const bodySha256 = createHash('sha256').update(safeBody).digest('hex')
      const scrubbedReqHeaders = redactHeaders(normalizeHeaders(outboundHeaders), effectiveSecrets)
      if (injectedCsrfHeaderName && injectedCsrfHeaderName in scrubbedReqHeaders) {
        scrubbedReqHeaders[injectedCsrfHeaderName] = '[redacted]'
      }
      return {
        origin: initialOrigin,
        finalOrigin: url.origin,
        redirectOrigins: [...redirectOrigins],
        finalPathAndQuery: redact(`${url.pathname}${url.search}`, effectiveSecrets),
        redirectPaths: redirectPaths.map(p => redact(p, effectiveSecrets)),
        method: req.method,
        pathAndQuery: redact(req.pathAndQuery, effectiveSecrets),
        personaHandle: personaHandle ?? null,
        status: response.status,
        mediaType: obs.mediaType,
        reqHeaders: scrubbedReqHeaders,
        respHeaders: redactHeaders(rawResponseHeaders, effectiveSecrets),
        setCookies: parseSetCookies(response.headers),
        bodyPreview: safeBody.slice(0, bodyPreviewLimit),
        body: safeBody,
        bodySha256,
        bodyBytes: response.bodyBytes ?? Buffer.byteLength(rawBody),
        bodyTruncated: Boolean(response.bodyTruncated),
        durationMs: Date.now() - started,
        secretMatches,
        ...(response.tls ? { tls: response.tls } : {}),
        observation: obs,
      }
    }
    return deny('The response exceeded the redirect limit.')
  }

  private async executeHttpInternal(
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
    bypassConcurrency: boolean,
  ): Promise<BrokerExchangeResult> {
    const prepared = this.prepareHttpRequest(req, grant)
    return this.executePreparedHttp(prepared, req, grant, signal, { bypassConcurrency })
  }

  async executeHttp(req: BrokerHttpRequest, grant: Grant, signal: AbortSignal): Promise<BrokerExchangeResult> {
    return this.executeHttpInternal(req, grant, signal, false)
  }

  async executeBatch(reqs: readonly BrokerHttpRequest[], grant: Grant, signal: AbortSignal): Promise<BrokerExchangeResult[]> {
    const tier = grant.tier ?? 1
    if (tier < 2) {
      throw new BrokerDenied('Synchronized parallel batches (executeBatch) require Tier 2 or Tier 3.')
    }
    if (reqs.length < 2 || reqs.length > 10) {
      throw new BrokerDenied('executeBatch requires between 2 and 10 requests.')
    }
    signal.throwIfAborted()

    // Check scope and circuit breakers up-front before firing the synchronized burst.
    const uniqueOrigins = new Set<string>()
    for (const req of reqs) {
      const origin = new URL(req.origin).origin
      if (!grant.canRead(origin)) {
        grant.audit('denied', origin)
        throw new BrokerDenied(`Origin ${origin} is outside the current assignment scope.`)
      }
      const state = this.health(origin, grant.maxRpsPerOrigin ?? 5)
      if (this.isCircuitOpen(origin)) {
        throw new BrokerCircuitOpen(origin, state.openReason ?? 'Origin circuit is open.')
      }
      if (state.batchActive) throw new BrokerDenied(`Another synchronized batch is already running for ${origin}.`)
      uniqueOrigins.add(origin)
    }

    for (const origin of uniqueOrigins) {
      const state = this.health(origin, grant.maxRpsPerOrigin ?? 5)
      state.batchActive = true
      // Ensure the bucket has enough tokens for a synchronized burst of up to reqs.length
      state.tokens = Math.max(state.tokens, reqs.length)
    }
    try {
      return await Promise.all(reqs.map(req => this.executeHttpInternal(req, grant, signal, true)))
    } finally {
      for (const origin of uniqueOrigins) {
        const state = this.origins.get(origin)
        if (state) state.batchActive = false
      }
    }
  }

  async executeRaceBurst(
    requests: readonly BrokerHttpRequest[],
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrokerRaceBurstResult> {
    const tier = grant.tier ?? 1
    if (tier < 2) {
      throw new BrokerDenied('Safe race-condition burst execution (executeRaceBurst) requires Tier 2 or Tier 3.')
    }
    if (!Array.isArray(requests) || requests.length < 2 || requests.length > 10) {
      throw new BrokerDenied('executeRaceBurst requires between 2 and 10 requests.')
    }
    signal.throwIfAborted()

    // 1. Validate every request up-front (scope, destructive payload denylist, Tier 2/3 method rules,
    //    Tier 3 HITL approvals, persona originAllowlist, forbidden headers) before sending any bytes.
    const preparedList = requests.map(req => ({ req, prepared: this.prepareHttpRequest(req, grant, { raceBurst: true }) }))

    const countsByOrigin = new Map<string, number>()
    const hostsToResolve = new Map<string, string>() // hostname -> originForAudit
    for (const { prepared } of preparedList) {
      const origin = prepared.initialOrigin
      const state = this.health(origin, grant.maxRpsPerOrigin ?? (tier === 3 ? 3 : 5))
      if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)
      if (state.batchActive) throw new BrokerDenied(`Another synchronized burst is already running for ${origin}.`)
      countsByOrigin.set(origin, (countsByOrigin.get(origin) ?? 0) + 1)
      if (!hostsToResolve.has(prepared.url.hostname)) {
        hostsToResolve.set(prepared.url.hostname, origin)
      }
    }

    // 2. Synchronize DNS resolution & public-IP checks before releasing the concurrent burst barrier.
    const dnsDeadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    const resolvedByHost = new Map<string, PublicAddress[]>()
    await Promise.all(
      [...hostsToResolve.entries()].map(async ([hostname, origin]) => {
        const addrs = await this.resolveAndCheckAddresses(hostname, grant, dnsDeadline, origin)
        resolvedByHost.set(hostname, addrs)
      }),
    )
    signal.throwIfAborted()

    // 3. Re-check all origins atomically before mutating state, then reserve burst tokens and lock.
    const defaultRps = grant.maxRpsPerOrigin ?? (tier === 3 ? 3 : 5)
    for (const origin of countsByOrigin.keys()) {
      const state = this.health(origin, defaultRps)
      if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)
      if (state.batchActive) throw new BrokerDenied(`Another synchronized burst is already running for ${origin}.`)
    }

    const markedOrigins: string[] = []
    let results: BrokerExchangeResult[]
    try {
      for (const [origin, count] of countsByOrigin) {
        const state = this.health(origin, defaultRps)
        state.batchActive = true
        markedOrigins.push(origin)
        state.tokens = Math.max(state.tokens, count)
      }
      // HTTP/2 bursts share one pooled connection and release every stream header at the same
      // barrier turn (single-packet / last-byte style). The HTTP/1.1 path ignores the barrier.
      const usesNativeHttp2 = this.transportConfig.http2 && this.options.transport === undefined
      const raceBarrier = usesNativeHttp2 ? new RaceBarrier(preparedList.length) : undefined
      results = await Promise.all(
        preparedList.map(({ req, prepared }) =>
          this.executePreparedHttp(prepared, req, grant, signal, {
            bypassConcurrency: true,
            preResolvedAddresses: resolvedByHost.get(prepared.url.hostname),
            raceBurst: true,
            ...(raceBarrier ? { raceBarrier } : {}),
          }),
        ),
      )
    } finally {
      for (const origin of markedOrigins) {
        const state = this.origins.get(origin)
        if (state) state.batchActive = false
      }
    }

    const statuses = results.map(r => r.status)
    const statusCounts: Record<string, number> = {}
    for (const status of statuses) {
      const key = String(status)
      statusCounts[key] = (statusCounts[key] ?? 0) + 1
    }
    const distinctBodies = new Set(results.map(r => r.bodySha256)).size
    const durations = results.map(r => r.durationMs)
    const minDurationMs = durations.length > 0 ? Math.min(...durations) : 0
    const maxDurationMs = durations.length > 0 ? Math.max(...durations) : 0
    const spreadMs = Math.max(0, maxDurationMs - minDurationMs)

    return {
      results,
      summary: {
        total: results.length,
        statuses,
        statusCounts,
        distinctBodies,
        minDurationMs,
        maxDurationMs,
        spreadMs,
      },
    }
  }

  async inspectDns(origin: string, grant: Grant, signal: AbortSignal): Promise<DnsInspectionResult> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live DNS inspection is disabled in Tier 0 (offline prepared mode).')
    const parsed = new URL(origin)
    if (!grant.canRead(parsed.origin)) {
      grant.audit('denied', parsed.origin)
      throw new BrokerDenied('Destination is outside the current assignment scope.')
    }

    const started = Date.now()
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    grant.audit('allowed', parsed.origin)

    const dnsResolver = this.options.dnsResolver ?? defaultDnsRecordResolver
    const records = await dnsResolver(parsed.hostname, deadline)
    deadline.throwIfAborted()

    const danglingHints: DnsDanglingHint[] = []
    for (const cname of records.cname) {
      for (const sig of danglingCnameProviders) {
        if (sig.cname.test(cname)) {
          danglingHints.push({ provider: sig.provider, cname })
        }
      }
    }
    const danglingNoIp = records.cname.length > 0 && records.a.length === 0 && records.aaaa.length === 0
    grant.audit('observed', parsed.origin)

    return {
      origin: parsed.origin,
      hostname: parsed.hostname,
      a: records.a,
      aaaa: records.aaaa,
      cname: records.cname,
      txt: records.txt,
      ns: records.ns,
      nxdomain: records.nxdomain,
      danglingNoIp,
      danglingHints,
      durationMs: Date.now() - started,
    }
  }

  async inspectTls(origin: string, grant: Grant, signal: AbortSignal): Promise<TlsInspectionResult> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live TLS inspection is disabled in Tier 0 (offline prepared mode).')
    const parsed = new URL(origin)
    if (parsed.protocol !== 'https:' || !grant.canRead(parsed.origin)) {
      grant.audit('denied', parsed.origin)
      throw new BrokerDenied('TLS inspection requires an approved HTTPS origin.')
    }

    const started = Date.now()
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    const addresses = await this.resolveAndCheckAddresses(parsed.hostname, grant, deadline, parsed.origin)
    const chosen = addresses.find(a => a.family === 4) ?? addresses[0]
    const inspector = this.options.tlsInspector ?? defaultTlsInspector

    grant.audit('allowed', parsed.origin)
    const tls = await inspector(parsed, chosen, deadline)
    grant.audit('observed', parsed.origin)

    return {
      origin: parsed.origin,
      hostname: parsed.hostname,
      resolvedIp: chosen.address,
      port: parsed.port ? Number(parsed.port) : 443,
      tls,
      durationMs: Date.now() - started,
    }
  }

  async probeWebsocket(
    req: BrokerWebsocketRequest,
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrokerWebsocketResult> {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live WebSocket probing is disabled in Tier 0 (offline prepared mode).')

    const localLab = allowLocalLab(grant)
    let initialOrigin: string
    let url: URL
    try {
      const normalizedOrigin = req.origin.replace(/^wss:\/\//i, 'https://').replace(/^ws:\/\//i, 'http://')
      initialOrigin = new URL(normalizedOrigin).origin
      url = new URL(req.pathAndQuery, initialOrigin)
    } catch {
      throw new BrokerDenied('WebSocket origin or path is malformed.')
    }

    if (
      !req.pathAndQuery.startsWith('/') ||
      req.pathAndQuery.startsWith('//') ||
      req.pathAndQuery.length > maxPathLength ||
      /[\r\n\0]/.test(req.pathAndQuery)
    ) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('WebSocket path is invalid or exceeds Guardian 8 KiB limit.')
    }
    if (url.origin !== initialOrigin || !safeUrl(url, true, localLab, grant.allowedPorts) || !grant.canRead(initialOrigin)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('WebSocket destination is outside the current assignment scope.')
    }

    const sendMessages = (req.sendMessages ?? []).slice(0, hardWsMaxFrames)
    const serializedInputs = [
      req.pathAndQuery,
      req.originHeader ?? '',
      ...Object.entries(req.headers ?? {}).map(([k, v]) => `${k}: ${v}`),
      ...sendMessages,
    ].join('\n')
    if (hasDestructiveContent(serializedInputs)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('WebSocket probe blocked by Guardian destructive-payload denylist.')
    }

    const personaHandle = req.persona ?? req.personaHandle
    let resolvedPersonaHeaders: Record<string, string> | undefined
    if (personaHandle) {
      if (tier < 2) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Persona-authenticated WebSocket probes require Tier 2 or higher.')
      }
      if (grant.personas) {
        const persona = grant.personas.get(personaHandle)
        if (!persona) {
          grant.audit('denied', initialOrigin)
          throw new BrokerDenied(`Persona "${personaHandle}" is not approved for this run.`)
        }
        const injected = buildPersonaHeader(persona, initialOrigin)
        if (!injected) {
          grant.audit('denied', initialOrigin)
          if (!persona.originAllowlist.includes(initialOrigin)) {
            throw new BrokerDenied(`Origin ${initialOrigin} is not in persona "${personaHandle}" originAllowlist.`)
          }
          throw new BrokerDenied(`Persona "${personaHandle}" does not have an active authenticated session yet.`)
        }
        resolvedPersonaHeaders = injected
      } else if (req.personaHeaders && Object.keys(req.personaHeaders).length > 0) {
        resolvedPersonaHeaders = req.personaHeaders
      } else {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied(`Persona "${personaHandle}" could not be resolved from run grant.`)
      }
    }

    const cleanHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(req.headers ?? {})) {
      if (forbiddenCallerHeaders.test(k)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied(`Header "${k}" cannot be set directly; reference an approved persona handle instead.`)
      }
      if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied('Invalid WebSocket request header.')
      }
      cleanHeaders[k] = v
    }
    const effectiveOriginHeader = req.originHeader ?? cleanHeaders.Origin ?? cleanHeaders.origin ?? initialOrigin
    if (/[\r\n\0]/.test(effectiveOriginHeader)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Invalid WebSocket Origin header.')
    }
    cleanHeaders.Origin = effectiveOriginHeader

    const maxFrames = Math.max(1, Math.min(req.maxFrames ?? defaultWsMaxFrames, hardWsMaxFrames))
    const maxBytes = Math.max(1024, Math.min(req.maxBytes ?? defaultWsMaxBytes, defaultWsMaxBytes))
    const timeoutMs = Math.max(500, Math.min(req.timeoutMs ?? defaultWsTimeoutMs, hardWsTimeoutMs))
    const started = Date.now()
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs + 2_000)])
    const secrets: NamedSecret[] = [
      ...(grant.personas ? personaSecrets(grant.personas) : []),
      ...(grant.secrets ?? []),
      ...(req.secrets ?? []),
    ]

    const addresses = await this.resolveAndCheckAddresses(url.hostname, grant, deadline, initialOrigin)
    const chosen = addresses.find(a => a.family === 4) ?? addresses[0]
    const maxRps = grant.maxRpsPerOrigin ?? (tier === 3 ? 3 : 5)
    const release = await this.acquireSlot(initialOrigin, maxRps, deadline)

    const wsTransport = this.options.wsTransport ?? defaultWsTransport
    const sessionMode = Boolean(req.turns?.length) && this.options.wsSessionEnabled === true
    let raw
    try {
      grant.audit('allowed', initialOrigin)
      if (sessionMode) {
        const frames: BrokerWebsocketFrame[] = []
        let connected = false
        let upgradeStatus: number | null = null
        let upgradeHeaders: Record<string, string> = {}
        let subprotocol: string | null = null
        let closeCode: number | null = null
        let closeReason: string | null = null
        let errorMsg: string | null = null
        const session = await WebSocketSession.connect(url, chosen, {
          headers: { ...cleanHeaders, ...(resolvedPersonaHeaders ?? {}) },
          subprotocols: req.subprotocols,
          rejectUnauthorized: this.options.rejectUnauthorized ?? true,
          timeoutMs,
        })
        try {
          upgradeStatus = session.handshake.status
          upgradeHeaders = session.handshake.headers
          subprotocol = session.handshake.subprotocol
          connected = session.handshake.accepted
          if (!connected) {
            errorMsg = `WebSocket upgrade rejected (status ${upgradeStatus}).`
          } else {
            for (const turn of req.turns ?? []) {
              if (frames.length >= maxFrames * 2) break
              if (turn.send !== undefined) {
                await session.sendText(turn.send)
                frames.push({
                  direction: 'sent',
                  opcode: 'text',
                  data: turn.send,
                  bytes: Buffer.byteLength(turn.send),
                  timestamp: Date.now(),
                })
              }
              const wanted = Math.max(0, Math.min(turn.awaitMessages ?? 1, maxFrames * 2 - frames.length))
              for (let i = 0; i < wanted; i += 1) {
                const message = await session.nextMessage(Math.max(100, turn.timeoutMs ?? Math.min(timeoutMs, 5_000)))
                if (!message) break
                frames.push({
                  direction: 'received',
                  opcode: message.opcode,
                  data: message.text,
                  bytes: message.data.length,
                  timestamp: message.timestamp,
                })
              }
            }
          }
        } finally {
          session.close()
        }
        raw = { connected, upgradeStatus, upgradeHeaders, subprotocol, frames, closeCode, closeReason, error: errorMsg }
      } else {
        raw = await wsTransport(url, chosen, deadline, {
          headers: {
            ...cleanHeaders,
            ...(resolvedPersonaHeaders ?? {}),
          },
          subprotocols: req.subprotocols,
          sendMessages: sendMessages.slice(0, maxFrames),
          maxFrames,
          maxBytes,
          timeoutMs,
          rejectUnauthorized: this.options.rejectUnauthorized ?? true,
        })
      }
    } finally {
      release()
    }

    grant.audit('observed', initialOrigin, raw.upgradeStatus ?? undefined)
    if (raw.upgradeStatus !== null) {
      this.recordStatus(initialOrigin, raw.upgradeStatus, grant.audit)
    }

    const safeFrames: BrokerWebsocketFrame[] = raw.frames.slice(0, maxFrames * 2).map(frame => ({
      ...frame,
      data: redact(frame.data, secrets).slice(0, 8192),
    }))
    const sentFrames = safeFrames.filter(f => f.direction === 'sent').length
    const receivedFrames = safeFrames.filter(f => f.direction === 'received').length
    const totalBytes = safeFrames.reduce((sum, f) => sum + f.bytes, 0)

    return {
      origin: initialOrigin,
      pathAndQuery: req.pathAndQuery,
      personaHandle: personaHandle ?? null,
      originHeader: redact(effectiveOriginHeader, secrets),
      connected: raw.connected,
      upgradeStatus: raw.upgradeStatus,
      upgradeHeaders: redactHeaders(normalizeHeaders(raw.upgradeHeaders), secrets),
      subprotocol: raw.subprotocol ? redact(raw.subprotocol, secrets) : null,
      sentFrames,
      receivedFrames,
      totalBytes,
      frames: safeFrames,
      closeCode: raw.closeCode,
      closeReason: raw.closeReason ? redact(raw.closeReason, secrets) : null,
      error: raw.error ? redact(raw.error, secrets) : null,
      durationMs: Date.now() - started,
    }
  }
}


/** Adapts a WebSocket probe result into a BrokerExchangeResult so it can be logged as a `WS` broker exchange. */
export function websocketResultToExchange(result: BrokerWebsocketResult): BrokerExchangeResult {
  const received = result.frames.filter(f => f.direction === 'received').map(f => f.data).join('\n')
  const sent = result.frames.filter(f => f.direction === 'sent').map(f => f.data).join('\n')
  const body = received.slice(0, 64 * 1024)
  const status = result.upgradeStatus ?? 0
  return {
    origin: result.origin,
    finalOrigin: result.origin,
    redirectOrigins: [result.origin],
    finalPathAndQuery: result.pathAndQuery,
    redirectPaths: [],
    method: 'WS',
    pathAndQuery: result.pathAndQuery,
    personaHandle: result.personaHandle,
    status,
    mediaType: 'text/plain',
    reqHeaders: { origin: result.originHeader ?? '', ...(sent ? { 'x-guardian-ws-sent-frames': String(result.sentFrames) } : {}) },
    respHeaders: result.upgradeHeaders,
    setCookies: [],
    bodyPreview: body.slice(0, bodyPreviewLimit),
    body,
    bodySha256: createHash('sha256').update(body).digest('hex'),
    bodyBytes: Buffer.byteLength(body),
    bodyTruncated: received.length > body.length,
    durationMs: result.durationMs,
    observation: {
      origin: result.origin,
      finalOrigin: result.origin,
      status,
      mediaType: 'text/plain',
      transportMaxAge: null,
      includeSubDomains: false,
      source: 'public response',
    },
  }
}
