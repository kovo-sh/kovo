import { createHash } from 'node:crypto'
import { lookup, resolve4, resolve6, resolveCname, resolveNs, resolveTxt } from 'node:dns/promises'
import { request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as tlsConnect, TLSSocket } from 'node:tls'
import type { DetailedPeerCertificate } from 'node:tls'
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib'
import ipaddr from 'ipaddr.js'
import { referrerPolicies } from '../domain.ts'
import type { CapabilityTier, PreparedObservation } from '../domain.ts'
import { containsDestructivePayload } from '../replay-spec.ts'
import { buildPersonaHeader, personaSecrets } from './persona-vault.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { redact, redactHeaders } from './redact.ts'
import type { NamedSecret } from './redact.ts'

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

export interface BrokerHttpRequest {
  origin: string
  method: 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'PATCH'
  pathAndQuery: string
  headers?: Record<string, string>
  body?: string
  persona?: string
  personaHandle?: string
  personaHeaders?: Record<string, string>
  followRedirects?: boolean
  secrets?: readonly NamedSecret[]
  maxBodyBytes?: number
  timeoutMs?: number
}

export interface BrokerExchangeResult {
  origin: string
  finalOrigin: string
  redirectOrigins: string[]
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
  canRead: (origin: string) => boolean
  isIdempotentPostAllowed?: (origin: string, pathAndQuery: string, body?: string) => boolean
  isStateChangeApproved?: (origin: string, method: string, pathAndQuery: string) => boolean
  audit: (outcome: 'allowed' | 'denied' | 'observed' | 'circuit_open', origin: string, status?: number) => void
}

export type BrokerOptions = {
  resolve?: Resolver
  transport?: Transport
  dnsResolver?: DnsRecordResolver
  tlsInspector?: TlsInspector
  source?: PublicObservation['source']
  circuit5xxThreshold?: number
  circuit429Threshold?: number
  circuitWindowMs?: number
  rejectUnauthorized?: boolean
}

const maxPathLength = 8192
const maxRedirects = 8
const defaultMaxBodyBytes = 1024 * 1024
const hardMaxBodyBytes = 2 * 1024 * 1024
const bodyPreviewLimit = 8192
const defaultRequestTimeoutMs = 30_000
const forbiddenCallerHeaders = /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding)$/i

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

function safeUrl(url: URL, allowQuery: boolean, localLab: boolean): boolean {
  const validProtocol = url.protocol === 'https:' || (localLab && url.protocol === 'http:')
  if (!validProtocol || url.username || url.password || url.hash) return false
  if (!allowQuery && !localLab && (url.port || url.search)) return false
  const full = url.pathname + url.search
  return full.length <= maxPathLength && !url.pathname.startsWith('//') && !/[\r\n\0]/.test(full)
}

function certObjectToRecord(obj: unknown): Record<string, string> {
  if (!obj || typeof obj !== 'object') return {}
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v.slice(0, 256)
    else if (Array.isArray(v)) out[k] = v.map(String).join(', ').slice(0, 256)
  }
  return out
}

function hostnameMatchesPattern(hostname: string, pattern: string): boolean {
  const h = hostname.toLowerCase()
  const p = pattern.toLowerCase()
  if (p === h) return true
  if (p.startsWith('*.')) {
    const suffix = p.slice(1) // ".example.com"
    const rest = h.slice(0, -suffix.length)
    return h.endsWith(suffix) && rest.length > 0 && !rest.includes('.')
  }
  return false
}

function extractTlsMetadata(socket: TLSSocket, hostname: string): TlsMetadata {
  const protocol = socket.getProtocol() ?? null
  const cipherObj = socket.getCipher()
  const cipher = cipherObj?.name ?? null
  const cert = socket.getPeerCertificate(false) as DetailedPeerCertificate | Record<string, never>
  const hasCert = Boolean(cert && Object.keys(cert).length > 0)
  const subject = hasCert ? certObjectToRecord(cert.subject) : {}
  const issuer = hasCert ? certObjectToRecord(cert.issuer) : {}
  const rawSans = hasCert && typeof cert.subjectaltname === 'string' ? cert.subjectaltname : ''
  const sans = rawSans
    .split(',')
    .map(entry => entry.trim())
    .filter(Boolean)
    .map(entry => entry.replace(/^(?:DNS|IP Address):/i, '').trim())
    .slice(0, 64)
  const validFrom = hasCert && typeof cert.valid_from === 'string' ? cert.valid_from : null
  const validTo = hasCert && typeof cert.valid_to === 'string' ? cert.valid_to : null
  const expiryMs = validTo ? Date.parse(validTo) : NaN
  const daysUntilExpiry = Number.isFinite(expiryMs)
    ? Math.floor((expiryMs - Date.now()) / (24 * 60 * 60 * 1000))
    : null
  const expired = Number.isFinite(expiryMs) ? expiryMs < Date.now() : false
  const cn = subject.CN
  const hostnameMatchesSan = sans.length > 0
    ? sans.some(san => hostnameMatchesPattern(hostname, san))
    : Boolean(cn && hostnameMatchesPattern(hostname, cn))
  const weakProtocol = Boolean(protocol && /^(?:SSLv|TLSv1(?:\.0|\.1)?$)/i.test(protocol))
  return {
    protocol,
    cipher,
    authorized: Boolean(socket.authorized),
    authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
    subject,
    issuer,
    sans,
    validFrom,
    validTo,
    fingerprint256: hasCert && typeof cert.fingerprint256 === 'string' ? cert.fingerprint256 : null,
    serialNumber: hasCert && typeof cert.serialNumber === 'string' ? cert.serialNumber : null,
    daysUntilExpiry,
    expired,
    hostnameMatchesSan,
    weakProtocol,
  }
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
  tokens: number
  lastRefill: number
  inFlight: number
  batchActive: boolean
}

export class RequestBroker {
  private readonly options: BrokerOptions
  private readonly origins = new Map<string, OriginHealth>()

  constructor(options: BrokerOptions = {}) {
    this.options = options
  }

  private health(origin: string, capacity = 5): OriginHealth {
    let state = this.origins.get(origin)
    if (!state) {
      state = {
        errors5xx: [],
        errors429: [],
        tokens: capacity,
        lastRefill: Date.now(),
        inFlight: 0,
        batchActive: false,
      }
      this.origins.set(origin, state)
    }
    return state
  }

  isCircuitOpen(origin: string): boolean {
    return Boolean(this.origins.get(origin)?.openReason)
  }

  resetCircuit(origin?: string) {
    if (origin) {
      const h = this.origins.get(origin)
      if (h) {
        h.errors5xx = []
        h.errors429 = []
        h.openReason = undefined
      }
    } else {
      this.origins.clear()
    }
  }

  private async acquireSlot(
    origin: string,
    maxRps: number,
    signal: AbortSignal,
    bypassConcurrency = false,
  ): Promise<() => void> {
    const rps = Math.max(1, Math.min(20, maxRps))
    const state = this.health(origin, rps)
    if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)

    for (;;) {
      signal.throwIfAborted()
      if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)
      const now = Date.now()
      const elapsedSec = Math.max(0, (now - state.lastRefill) / 1000)
      state.tokens = Math.min(rps, state.tokens + elapsedSec * rps)
      state.lastRefill = now

      const concurrencyOk = bypassConcurrency || state.inFlight < 2
      if (concurrencyOk && state.tokens >= 1) {
        state.tokens -= 1
        state.inFlight += 1
        return () => {
          state.inFlight = Math.max(0, state.inFlight - 1)
        }
      }

      const waitMs = state.tokens < 1
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

  private recordStatus(origin: string, status: number, audit: Grant['audit']) {
    const state = this.health(origin)
    const now = Date.now()
    const windowMs = this.options.circuitWindowMs ?? 30_000
    const threshold5xx = this.options.circuit5xxThreshold ?? 5
    const threshold429 = this.options.circuit429Threshold ?? 8
    state.errors5xx = state.errors5xx.filter(ts => now - ts < windowMs)
    state.errors429 = state.errors429.filter(ts => now - ts < windowMs)
    if (status >= 500 && status <= 599) {
      state.errors5xx.push(now)
      if (state.errors5xx.length >= threshold5xx) {
        state.openReason = `Observed ${state.errors5xx.length} HTTP 5xx responses within ${Math.round(windowMs / 1000)}s.`
        audit('circuit_open', origin, status)
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
    } else if (status === 429) {
      state.errors429.push(now)
      if (state.errors429.length >= threshold429) {
        state.openReason = `Observed ${state.errors429.length} HTTP 429 rate-limit responses within ${Math.round(windowMs / 1000)}s.`
        audit('circuit_open', origin, status)
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
    }
  }

  private async resolveAndCheckAddresses(hostname: string, grant: Grant, deadline: AbortSignal, originForAudit: string): Promise<PublicAddress[]> {
    const resolve = this.options.resolve ?? ((host: string) => lookup(host, { all: true, order: 'verbatim' }))
    const addresses = await withAbort(resolve(hostname), deadline)
    deadline.throwIfAborted()
    const localLab = allowLocalLab(grant)
    if (addresses.length === 0 || (!localLab && addresses.some(address => !isPublicAddress(address)))) {
      grant.audit('denied', originForAudit)
      throw new BrokerDenied('The target hostname did not resolve exclusively to public addresses.')
    }
    return addresses
  }

  async readPublicRoot(grant: Grant, signal: AbortSignal): Promise<PublicObservation> {
    if (!grant.origin) throw new BrokerDenied('Grant origin is required for readPublicRoot.')
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live HTTP requests are disabled in Tier 0 (offline prepared mode).')

    const localLab = allowLocalLab(grant)
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    const transport = this.options.transport ?? defaultTransport
    let url = new URL('/', grant.origin)
    const deny = (message: string): never => {
      grant.audit('denied', url.origin)
      throw new BrokerDenied(message)
    }
    const check = () => {
      deadline.throwIfAborted()
      if (!safeUrl(url, false, localLab) || !grant.canRead(url.origin)) {
        deny('Destination is outside the current assignment scope.')
      }
    }
    for (let redirect = 0; redirect <= 3; redirect += 1) {
      check()
      const addresses = await this.resolveAndCheckAddresses(url.hostname, grant, deadline, url.origin)
      check()
      const release = await this.acquireSlot(url.origin, grant.maxRpsPerOrigin ?? 5, deadline)
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
      this.recordStatus(url.origin, response.status, grant.audit)
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

  private prepareHttpRequest(req: BrokerHttpRequest, grant: Grant): {
    initialOrigin: string
    url: URL
    localLab: boolean
    personaHandle: string | undefined
    resolvedPersonaHeaders: Record<string, string> | undefined
    cleanHeaders: Record<string, string>
    secrets: NamedSecret[]
    followRedirects: boolean
    maxRps: number
    timeoutMs: number
  } {
    const tier = grant.tier ?? 1
    if (tier === 0) throw new BrokerDenied('Live HTTP requests are disabled in Tier 0 (offline prepared mode).')

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
    if (!safeUrl(url, true, localLab) || !grant.canRead(initialOrigin)) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Destination is outside the current assignment scope.')
    }

    // Destructive payload denylist check across path (raw + URL-decoded), headers, and body
    const serializedHeaders = Object.entries(req.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')
    if (
      hasDestructiveContent(req.pathAndQuery) ||
      hasDestructiveContent(serializedHeaders) ||
      (req.body !== undefined && hasDestructiveContent(req.body))
    ) {
      grant.audit('denied', initialOrigin)
      throw new BrokerDenied('Request blocked by Guardian destructive-payload denylist.')
    }

    const personaHandle = req.persona ?? req.personaHandle
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
          throw new BrokerDenied(`Origin ${initialOrigin} is not in persona "${personaHandle}" originAllowlist.`)
        }
        resolvedPersonaHeaders = injected
      } else if (req.personaHeaders && Object.keys(req.personaHeaders).length > 0) {
        resolvedPersonaHeaders = req.personaHeaders
      } else {
        grant.audit('denied', initialOrigin)
        throw new BrokerDenied(`Persona "${personaHandle}" could not be resolved from run grant.`)
      }
    }

    const isReadOnlyMethod = req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS'
    if (!isReadOnlyMethod) {
      const idempotentPostAllowed = req.method === 'POST' && tier >= 2 &&
        Boolean(grant.isIdempotentPostAllowed?.(initialOrigin, req.pathAndQuery, req.body))
      if (!idempotentPostAllowed) {
        if (tier < 3) {
          grant.audit('denied', initialOrigin)
          throw new BrokerDenied(`Method ${req.method} requires Tier 3 (approval-gated state validation).`)
        }
        if (!grant.isStateChangeApproved?.(initialOrigin, req.method, req.pathAndQuery)) {
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
      secrets,
      followRedirects,
      maxRps,
      timeoutMs,
    }
  }

  private async executePreparedHttp(
    prepared: ReturnType<RequestBroker['prepareHttpRequest']>,
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
    options: { bypassConcurrency: boolean; preResolvedAddresses?: PublicAddress[] },
  ): Promise<BrokerExchangeResult> {
    const {
      initialOrigin,
      localLab,
      personaHandle,
      resolvedPersonaHeaders,
      cleanHeaders,
      secrets,
      followRedirects,
      maxRps,
      timeoutMs,
    } = prepared
    let url = new URL(prepared.url.href)

    const started = Date.now()
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    const transport = this.options.transport ?? defaultTransport

    const redirectOrigins = new Set<string>([url.origin])
    let activeMethod: BrokerHttpRequest['method'] = req.method
    let activeBody = req.body
    let includePersona = Boolean(resolvedPersonaHeaders && Object.keys(resolvedPersonaHeaders).length > 0)

    const deny = (message: string): never => {
      grant.audit('denied', url.origin)
      throw new BrokerDenied(message)
    }
    const check = () => {
      deadline.throwIfAborted()
      if (!safeUrl(url, true, localLab) || !grant.canRead(url.origin)) {
        deny('Destination is outside the current assignment scope.')
      }
    }

    for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
      check()
      redirectOrigins.add(url.origin)
      // Hard invariant: NEVER forward persona credentials across cross-origin redirects.
      if (url.origin !== initialOrigin) includePersona = false

      const addresses = redirect === 0 && options.preResolvedAddresses
        ? options.preResolvedAddresses
        : await this.resolveAndCheckAddresses(url.hostname, grant, deadline, url.origin)
      check()

      const outboundHeaders: Record<string, string> = {
        ...cleanHeaders,
        ...(includePersona ? resolvedPersonaHeaders : {}),
      }

      const release = await this.acquireSlot(url.origin, maxRps, deadline, options.bypassConcurrency)
      let response: RawHttpResponse
      try {
        grant.audit('allowed', url.origin)
        response = await transport(url, addresses.find(a => a.family === 4) ?? addresses[0], deadline, {
          method: activeMethod,
          headers: outboundHeaders,
          body: activeBody,
          maxBodyBytes: Math.min(req.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes),
          readBody: true,
          rejectUnauthorized: this.options.rejectUnauthorized ?? true,
        })
      } finally {
        release()
      }
      check()
      grant.audit('observed', url.origin, response.status)
      this.recordStatus(url.origin, response.status, grant.audit)

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
        if (response.status === 301 || response.status === 302 || response.status === 303) {
          activeMethod = 'GET'
          activeBody = undefined
        }
        continue
      }

      const requestOriginHeader = cleanHeaders['Origin'] ?? cleanHeaders['origin']
      const obs = observed(initialOrigin, url, response, this.options.source ?? 'public response', requestOriginHeader)
      const rawBody = response.body ?? ''
      const safeBody = redact(rawBody, secrets)
      const bodySha256 = createHash('sha256').update(safeBody).digest('hex')
      return {
        origin: initialOrigin,
        finalOrigin: url.origin,
        redirectOrigins: [...redirectOrigins],
        method: req.method,
        pathAndQuery: req.pathAndQuery,
        personaHandle: personaHandle ?? null,
        status: response.status,
        mediaType: obs.mediaType,
        reqHeaders: redactHeaders(normalizeHeaders(outboundHeaders), secrets),
        respHeaders: redactHeaders(normalizeHeaders(response.headers), secrets),
        setCookies: parseSetCookies(response.headers),
        bodyPreview: safeBody.slice(0, bodyPreviewLimit),
        body: safeBody,
        bodySha256,
        bodyBytes: response.bodyBytes ?? Buffer.byteLength(rawBody),
        bodyTruncated: Boolean(response.bodyTruncated),
        durationMs: Date.now() - started,
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
      if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)
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
    const preparedList = requests.map(req => ({ req, prepared: this.prepareHttpRequest(req, grant) }))

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
      results = await Promise.all(
        preparedList.map(({ req, prepared }) =>
          this.executePreparedHttp(prepared, req, grant, signal, {
            bypassConcurrency: true,
            preResolvedAddresses: resolvedByHost.get(prepared.url.hostname),
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
}
