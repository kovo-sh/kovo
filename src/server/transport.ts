/**
 * Layer-1 transport for the RequestBroker.
 *
 * Everything in this module is transport *plumbing* only: the broker keeps sole authority over
 * scope, approvals, redaction, DNS pinning and circuit breakers, and calls these primitives only
 * after a request has passed the same preflight as the legacy HTTP/1.1 path. Nothing here can
 * reach an origin the broker did not already authorize.
 *
 * Capabilities, all opt-in:
 *   - HTTP/2 (h2 / h2c) with per-(origin, pinned-address) connection pooling and an HTTP/1.1
 *     fallback when the peer cannot speak h2.
 *   - A `RaceBarrier` used by `executeRaceBurst` to release synchronized HTTP/2 streams on one
 *     connection (last-byte gating where a body is present).
 *   - Egress through a corporate HTTP(S) CONNECT proxy or a SOCKS5 proxy, mTLS client
 *     certificates, and an authorized User-Agent/header profile.
 *   - A turn-aware WebSocket session helper (awaited frames, continuation reassembly, cookies).
 */
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync, statSync } from 'node:fs'
import { Agent as HttpAgent, request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http'
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https'
import { connect as http2Connect } from 'node:http2'
import type { ClientHttp2Session, ClientHttp2Stream } from 'node:http2'
import { connect as netConnect } from 'node:net'
import type { Socket as NetSocket } from 'node:net'
import { connect as tlsConnect, TLSSocket } from 'node:tls'
import type { DetailedPeerCertificate, ConnectionOptions as TlsConnectionOptions } from 'node:tls'
import type { Duplex } from 'node:stream'
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib'
import ipaddr from 'ipaddr.js'
import type { PublicAddress, RawHttpResponse, TlsMetadata, Transport } from './broker.ts'
import { isMetadataOrLinkLocalAddress } from './egress-gateway.ts'
import { isValidHttpToken, isValidWebsocketSubprotocol } from './request-admission.ts'

// ---------------------------------------------------------------------------
// Configuration (all fail-closed)
// ---------------------------------------------------------------------------

export class TransportConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TransportConfigError'
  }
}

export type EgressProxy = {
  /** Scheme of the proxy listener. `socks5h` resolves the target name at the proxy. */
  protocol: 'http:' | 'https:' | 'socks5:' | 'socks5h:'
  host: string
  port: number
  /** Base64 `Proxy-Authorization` value for HTTP proxies. */
  authorization?: string
  username?: string
  password?: string
}

export type MtlsMaterial = {
  certPath: string
  keyPath: string
  caPath?: string
  cert: string
  key: string
  ca?: string
}

export type HeaderProfile = {
  userAgent?: string
  headers: Record<string, string>
}

export type TransportConfig = {
  http2: boolean
  proxy?: EgressProxy
  mtls?: MtlsMaterial
  headerProfile?: HeaderProfile
  /** Maximum pooled HTTP/2 sessions (LRU-evicted). */
  http2MaxSessions?: number
}

const forbiddenProfileHeaders = /^(?:host|connection|keep-alive|transfer-encoding|upgrade|proxy-connection|proxy-authorization|content-length)$/i
const crlf = /[\r\n\0]/

function canonicalizeUniqueHeaders(headers: Record<string, string>, source: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(headers)) {
    if (!isValidHttpToken(name) || crlf.test(value)) {
      throw new TransportConfigError(`${source} contains an invalid header name or value`)
    }
    const lower = name.toLowerCase()
    if (Object.prototype.hasOwnProperty.call(out, lower)) {
      throw new TransportConfigError(`${source} contains duplicate case-insensitive header ${lower}`)
    }
    out[lower] = value
  }
  return out
}

function assertHeaderValue(name: string, value: string): void {
  if (!isValidHttpToken(name) || crlf.test(value)) {
    throw new TransportConfigError(`header profile entry ${JSON.stringify(name)} contains invalid syntax`)
  }
  if (forbiddenProfileHeaders.test(name)) {
    throw new TransportConfigError(`header profile may not set transport-managed header ${name}`)
  }
}

function parseBooleanFlag(raw: string | undefined, name: string): boolean | undefined {
  if (raw === undefined || raw === '') return undefined
  if (raw === '1' || raw.toLowerCase() === 'true') return true
  if (raw === '0' || raw.toLowerCase() === 'false') return false
  throw new TransportConfigError(`${name} must be 0 or 1 (got ${JSON.stringify(raw)})`)
}

function parseHeaderProfileFile(path: string): HeaderProfile {
  let raw: string
  try {
    if (!statSync(path).isFile()) throw new Error('not a regular file')
    raw = readFileSync(path, 'utf8')
  } catch (err) {
    throw new TransportConfigError(`KOVO_UA_PROFILE could not be read: ${(err as Error).message}`)
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (err) {
    throw new TransportConfigError(`KOVO_UA_PROFILE is not valid JSON: ${(err as Error).message}`)
  }
  return normalizeHeaderProfile(parsed, 'KOVO_UA_PROFILE')
}

function normalizeHeaderProfile(value: unknown, source: string): HeaderProfile {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TransportConfigError(`${source} must be an object`)
  }
  const record = value as Record<string, unknown>
  const profile: HeaderProfile = { headers: {} }
  let headerDisplayNames: Record<string, string> | undefined
  if (record.userAgent !== undefined) {
    if (typeof record.userAgent !== 'string' || record.userAgent.trim() === '') {
      throw new TransportConfigError(`${source}.userAgent must be a non-empty string`)
    }
    if (crlf.test(record.userAgent)) throw new TransportConfigError(`${source}.userAgent contains CR/LF/NUL`)
    profile.userAgent = record.userAgent
  }
  const headers = record.headers === undefined ? {} : record.headers
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TransportConfigError(`${source}.headers must be an object`)
  }
  for (const [name, raw] of Object.entries(headers as Record<string, unknown>)) {
    if (typeof raw !== 'string') throw new TransportConfigError(`${source}.headers.${name} must be a string`)
    assertHeaderValue(name, raw)
    profile.headers[name] = raw
    ;(headerDisplayNames ??= {})[name.toLowerCase()] = name
  }
  // Flat profile files are also accepted (e.g. { "userAgent": "...", "Accept-Language": "en" }).
  for (const [name, raw] of Object.entries(record)) {
    if (name === 'userAgent' || name === 'headers') continue
    if (typeof raw !== 'string') throw new TransportConfigError(`${source}.${name} must be a string`)
    assertHeaderValue(name, raw)
    profile.headers[name] = raw
    ;(headerDisplayNames ??= {})[name.toLowerCase()] = name
  }
  const canonical = canonicalizeUniqueHeaders(profile.headers, source)
  if (headerDisplayNames) {
    for (const [lower, display] of Object.entries(headerDisplayNames)) profile.headers[display] = canonical[lower]!
  }
  return profile
}

function normalizeProxy(raw: string): EgressProxy {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new TransportConfigError('KOVO_EGRESS_PROXY is not a valid URL')
  }
  if (!['http:', 'https:', 'socks5:', 'socks5h:'].includes(url.protocol)) {
    throw new TransportConfigError(`KOVO_EGRESS_PROXY scheme ${url.protocol} is unsupported (http/https/socks5/socks5h only)`)
  }
  if (!url.hostname) throw new TransportConfigError('KOVO_EGRESS_PROXY is missing a host')
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
    throw new TransportConfigError('KOVO_EGRESS_PROXY must not contain a path, query, or fragment')
  }
  const rawHostname = url.hostname.replace(/^\[|\]$/g, '')
  let proxyHost: string
  if (ipaddr.isValid(rawHostname)) {
    const parsed = ipaddr.process(rawHostname)
    if (isMetadataOrLinkLocalAddress(parsed.toString()) || parsed.range() === 'unspecified') {
      throw new TransportConfigError('KOVO_EGRESS_PROXY host is a metadata, link-local, or unspecified address')
    }
    proxyHost = parsed.toNormalizedString()
  } else {
    if (rawHostname.includes(':') || !/^[a-z0-9.-]+$/i.test(rawHostname) || rawHostname.includes('..')) {
      throw new TransportConfigError('KOVO_EGRESS_PROXY host is invalid')
    }
    const hostname = rawHostname.toLowerCase().replace(/\.+$/, '')
    if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') ||
        hostname === 'metadata.google.internal' || hostname.endsWith('.internal')) {
      throw new TransportConfigError('KOVO_EGRESS_PROXY host is a local or metadata-only destination')
    }
    proxyHost = hostname
  }
  const port = url.port ? Number(url.port) : (url.protocol === 'https:' ? 443 : url.protocol === 'http:' ? 80 : 1080)
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new TransportConfigError('KOVO_EGRESS_PROXY has an invalid port')
  }
  const proxy: EgressProxy = { protocol: url.protocol as EgressProxy['protocol'], host: proxyHost, port }
  if (url.username || url.password) {
    let username: string
    let password: string
    try {
      username = decodeURIComponent(url.username)
      password = decodeURIComponent(url.password)
    } catch {
      throw new TransportConfigError('KOVO_EGRESS_PROXY credentials are not valid percent-encoding')
    }
    if (crlf.test(username) || crlf.test(password)) {
      throw new TransportConfigError('KOVO_EGRESS_PROXY credentials contain CR/LF/NUL')
    }
    proxy.username = username
    proxy.password = password
    proxy.authorization = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
  }
  return proxy
}

function loadMtls(env: Record<string, string | undefined>): MtlsMaterial | undefined {
  const certPath = env.KOVO_MTLS_CERT
  const keyPath = env.KOVO_MTLS_KEY
  const caPath = env.KOVO_MTLS_CA
  if (!certPath && !keyPath) {
    if (caPath) throw new TransportConfigError('KOVO_MTLS_CA requires KOVO_MTLS_CERT and KOVO_MTLS_KEY')
    return undefined
  }
  if (!certPath || !keyPath) {
    throw new TransportConfigError('mTLS requires both KOVO_MTLS_CERT and KOVO_MTLS_KEY')
  }
  const read = (path: string, label: string): string => {
    try {
      if (!statSync(path).isFile()) throw new Error('not a regular file')
      const value = readFileSync(path, 'utf8')
      if (value.trim() === '') throw new Error('empty file')
      return value
    } catch (err) {
      throw new TransportConfigError(`${label} could not be read: ${(err as Error).message}`)
    }
  }
  return {
    certPath,
    keyPath,
    ...(caPath ? { caPath } : {}),
    cert: read(certPath, 'KOVO_MTLS_CERT'),
    key: read(keyPath, 'KOVO_MTLS_KEY'),
    ...(caPath ? { ca: read(caPath, 'KOVO_MTLS_CA') } : {}),
  }
}

/**
 * Resolve transport configuration from the environment plus explicit overrides.
 * Invalid configuration throws `TransportConfigError` — never silently downgrades.
 */
export function resolveTransportConfig(
  env: Record<string, string | undefined> = process.env,
  overrides: Partial<TransportConfig> = {},
): TransportConfig {
  const envHttp2 = parseBooleanFlag(env.KOVO_HTTP2, 'KOVO_HTTP2')
  const proxyRaw = env.KOVO_EGRESS_PROXY
  const proxy = proxyRaw ? normalizeProxy(proxyRaw) : undefined
  const mtls = loadMtls(env)

  let headerProfile: HeaderProfile | undefined
  if (env.KOVO_UA_PROFILE) {
    headerProfile = parseHeaderProfileFile(env.KOVO_UA_PROFILE)
  }
  if (env.KOVO_USER_AGENT !== undefined) {
    if (env.KOVO_USER_AGENT.trim() === '') {
      throw new TransportConfigError('KOVO_USER_AGENT must not be empty')
    }
    if (crlf.test(env.KOVO_USER_AGENT)) {
      throw new TransportConfigError('KOVO_USER_AGENT contains CR/LF/NUL')
    }
    headerProfile = { ...(headerProfile ?? { headers: {} }), userAgent: env.KOVO_USER_AGENT }
  }
  if (env.KOVO_AUTHORIZED_HEADERS) {
    let parsed: unknown
    try {
      parsed = JSON.parse(env.KOVO_AUTHORIZED_HEADERS)
    } catch (err) {
      throw new TransportConfigError(`KOVO_AUTHORIZED_HEADERS is not valid JSON: ${(err as Error).message}`)
    }
    const fromEnv = normalizeHeaderProfile(parsed, 'KOVO_AUTHORIZED_HEADERS')
    headerProfile = {
      ...(headerProfile?.userAgent ? { userAgent: headerProfile.userAgent } : {}),
      headers: { ...(headerProfile?.headers ?? {}), ...fromEnv.headers },
    }
    if (!headerProfile.userAgent && fromEnv.userAgent) headerProfile.userAgent = fromEnv.userAgent
  }

  return {
    http2: overrides.http2 ?? envHttp2 ?? false,
    ...(overrides.proxy ?? proxy ? { proxy: overrides.proxy ?? proxy } : {}),
    ...(overrides.mtls ?? mtls ? { mtls: overrides.mtls ?? mtls } : {}),
    ...(overrides.headerProfile ?? headerProfile
      ? { headerProfile: overrides.headerProfile ?? headerProfile }
      : {}),
    ...(overrides.http2MaxSessions !== undefined ? { http2MaxSessions: overrides.http2MaxSessions } : {}),
  }
}

export const defaultUserAgent = 'KovoHunter/2 defensive evidence review'

// ---------------------------------------------------------------------------
// TLS metadata (shared with the broker)
// ---------------------------------------------------------------------------

export function certObjectToRecord(obj: unknown): Record<string, string> {
  if (!obj || typeof obj !== 'object') return {}
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v.slice(0, 256)
    else if (Array.isArray(v)) out[k] = v.map(String).join(', ').slice(0, 256)
  }
  return out
}

export function hostnameMatchesPattern(hostname: string, pattern: string): boolean {
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

export function extractTlsMetadata(socket: TLSSocket, hostname: string): TlsMetadata {
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

// ---------------------------------------------------------------------------
// Race barrier (single-connection synchronized burst)
// ---------------------------------------------------------------------------

/**
 * A one-shot barrier that releases every waiting HTTP/2 stream at the same event-loop turn.
 *
 * The broker creates one per `executeRaceBurst` with `capacity === requests.length`. Every
 * transport call either arrives (h2) or skips (fallback / pre-transport failure). A short
 * watchdog prevents a lost participant from hanging the rest of the burst; the broker's DNS and
 * approval preflight happen *before* this barrier, so the window only covers header emission.
 */
export class RaceBarrier {
  private readonly capacity: number
  private readonly watchdogMs: number
  private arrivals = 0
  private skips = 0
  private isReleased = false
  private resolveAll: (() => void) | undefined
  private readonly promise: Promise<void>
  private watchdog: ReturnType<typeof setTimeout> | undefined
  readonly releasedAt: number[] = []

  constructor(capacity: number, watchdogMs = 1_000) {
    this.capacity = Math.max(1, capacity)
    this.watchdogMs = watchdogMs
    this.promise = new Promise<void>(resolve => {
      this.resolveAll = resolve
    })
    this.watchdog = setTimeout(() => this.release('watchdog'), watchdogMs)
    this.watchdog.unref?.()
  }

  get released(): boolean {
    return this.isReleased
  }

  get participantCount(): number {
    return this.arrivals + this.skips
  }

  /** Wait until the whole burst is assembled, then return in the same turn as every peer. */
  arrive(): Promise<void> {
    if (this.isReleased) return Promise.resolve()
    this.arrivals += 1
    this.maybeRelease()
    return this.promise
  }

  /** A participant that cannot use the gated connection (fallback/error) must not block peers. */
  skip(): void {
    if (this.isReleased) return
    this.skips += 1
    this.maybeRelease()
  }

  private maybeRelease(): void {
    if (this.arrivals + this.skips >= this.capacity) this.release('capacity')
  }

  release(reason: 'capacity' | 'watchdog' | 'manual' = 'manual'): void {
    if (this.isReleased) return
    this.isReleased = true
    if (this.watchdog) clearTimeout(this.watchdog)
    this.watchdog = undefined
    this.releasedAt.push(Date.now())
    void reason
    this.resolveAll?.()
  }
}

// ---------------------------------------------------------------------------
// Proxy / mTLS socket plumbing
// ---------------------------------------------------------------------------

class SocketReader {
  private buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0)
  private pending: (() => void) | undefined
  private ended = false
  private error: Error | undefined

  constructor(socket: NetSocket) {
    socket.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk])
      this.pending?.()
    })
    socket.once('end', () => {
      this.ended = true
      this.pending?.()
    })
    socket.once('close', () => {
      this.ended = true
      this.pending?.()
    })
    socket.once('error', err => {
      this.error = err
      this.pending?.()
    })
  }

  async readExactly(count: number, signal: AbortSignal): Promise<Buffer> {
    while (this.buffer.length < count) {
      this.throwIfFailed(signal)
      if (this.ended) throw new Error('proxy closed the connection during handshake')
      await this.wait(signal)
    }
    const out = this.buffer.subarray(0, count)
    this.buffer = this.buffer.subarray(count)
    return out
  }

  async readUntil(marker: string, maxBytes: number, signal: AbortSignal): Promise<string> {
    for (;;) {
      const idx = this.buffer.indexOf(marker)
      if (idx >= 0) {
        const out = this.buffer.subarray(0, idx + marker.length).toString('latin1')
        this.buffer = this.buffer.subarray(idx + marker.length)
        return out
      }
      if (this.buffer.length > maxBytes) throw new Error('proxy handshake response too large')
      this.throwIfFailed(signal)
      if (this.ended) throw new Error('proxy closed the connection during handshake')
      await this.wait(signal)
    }
  }

  takeBuffered(): Buffer<ArrayBufferLike> {
    const out = this.buffer
    this.buffer = Buffer.alloc(0)
    return out
  }

  private throwIfFailed(signal: AbortSignal): void {
    if (signal.aborted) throw signal.reason ?? new Error('aborted')
    if (this.error) throw this.error
  }

  private wait(signal: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        signal.removeEventListener('abort', onAbort)
        if (this.pending === wake) this.pending = undefined
      }
      const wake = () => {
        cleanup()
        resolve()
      }
      const onAbort = () => {
        cleanup()
        reject(signal.reason ?? new Error('aborted'))
      }
      this.pending = wake
      signal.addEventListener('abort', onAbort, { once: true })
    })
  }
}

function connectTcp(host: string, port: number, signal: AbortSignal): Promise<NetSocket> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host, port })
    const onAbort = () => {
      socket.destroy()
      reject(signal.reason ?? new Error('aborted'))
    }
    if (signal.aborted) return onAbort()
    signal.addEventListener('abort', onAbort, { once: true })
    socket.once('connect', () => {
      signal.removeEventListener('abort', onAbort)
      resolve(socket)
    })
    socket.once('error', err => {
      signal.removeEventListener('abort', onAbort)
      reject(err)
    })
  })
}

async function socks5Tunnel(
  socket: NetSocket,
  target: { host: string; port: number; address?: string },
  proxy: EgressProxy,
  signal: AbortSignal,
): Promise<NetSocket> {
  const reader = new SocketReader(socket)
  const wantsAuth = Boolean(proxy.username || proxy.password)
  socket.write(Buffer.from([0x05, wantsAuth ? 0x02 : 0x01, 0x00, ...(wantsAuth ? [0x02] : [])]))
  const greeting = await reader.readExactly(2, signal)
  if (greeting[0] !== 0x05) throw new Error('SOCKS5 proxy returned an invalid version')
  const method = greeting[1]
  if (method === 0xff) throw new Error('SOCKS5 proxy rejected all authentication methods')
  if (method === 0x02) {
    const user = Buffer.from(proxy.username ?? '', 'utf8')
    const pass = Buffer.from(proxy.password ?? '', 'utf8')
    if (user.length > 255 || pass.length > 255) throw new Error('SOCKS5 credentials are too long')
    socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]))
    const auth = await reader.readExactly(2, signal)
    if (auth[0] !== 0x01 || auth[1] !== 0x00) throw new Error('SOCKS5 proxy authentication failed')
  } else if (method !== 0x00) {
    throw new Error(`SOCKS5 proxy selected unsupported auth method ${method}`)
  }

  const useRemoteDns = proxy.protocol === 'socks5h:'
  let addressBytes: Buffer
  let atyp: number
  if (useRemoteDns) {
    addressBytes = Buffer.from(target.host, 'utf8')
    if (addressBytes.length > 255) throw new Error('SOCKS5 target hostname is too long')
    atyp = 0x03
  } else {
    const literal = target.address ?? target.host
    if (literal.includes(':')) {
      const bare = literal.replace(/^\[|\]$/g, '').split('%', 1)[0]!
      if (!ipaddr.isValid(bare)) throw new Error('invalid IPv6 address')
      const parsed = ipaddr.parse(bare)
      if (parsed.kind() !== 'ipv6') throw new Error('invalid IPv6 address')
      addressBytes = Buffer.from(parsed.toByteArray())
      atyp = 0x04
    } else {
      const parts = literal.split('.').map(p => Number(p))
      if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
        throw new Error('invalid IPv4 address')
      }
      addressBytes = Buffer.from(parts)
      atyp = 0x01
    }
  }
  const portBytes = Buffer.alloc(2)
  portBytes.writeUInt16BE(target.port)
  socket.write(Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, atyp]),
    ...(atyp === 0x03 ? [Buffer.from([addressBytes.length])] : []),
    addressBytes,
    portBytes,
  ]))
  const head = await reader.readExactly(4, signal)
  if (head[0] !== 0x05) throw new Error('SOCKS5 proxy returned an invalid connect reply')
  if (head[1] !== 0x00) throw new Error(`SOCKS5 proxy rejected CONNECT (reply ${head[1]})`)
  const boundAtyp = head[3]
  const boundLen = boundAtyp === 0x01 ? 4 : boundAtyp === 0x04 ? 16 : (await reader.readExactly(1, signal))[0]
  await reader.readExactly(boundLen + 2, signal)
  const buffered = reader.takeBuffered()
  if (buffered.length > 0) socket.unshift(buffered)
  return socket
}

async function httpProxyTunnel(
  socket: NetSocket,
  target: { host: string; port: number },
  proxy: EgressProxy,
  signal: AbortSignal,
): Promise<NetSocket> {
  const reader = new SocketReader(socket)
  const authority = `${target.host}:${target.port}`
  const lines = [
    `CONNECT ${authority} HTTP/1.1`,
    `Host: ${authority}`,
    'Proxy-Connection: keep-alive',
    ...(proxy.authorization ? [`Proxy-Authorization: ${proxy.authorization}`] : []),
    '',
    '',
  ]
  socket.write(lines.join('\r\n'))
  const head = await reader.readUntil('\r\n\r\n', 16 * 1024, signal)
  const statusLine = head.split('\r\n')[0] ?? ''
  const match = /^HTTP\/1\.[01]\s+(\d{3})/.exec(statusLine)
  if (!match) throw new Error('HTTP proxy returned a malformed CONNECT response')
  const status = Number(match[1])
  if (status < 200 || status > 299) throw new Error(`HTTP proxy refused CONNECT (status ${status})`)
  const buffered = reader.takeBuffered()
  if (buffered.length > 0) socket.unshift(buffered)
  return socket
}

function tlsOptions(
  url: URL,
  rejectUnauthorized: boolean,
  mtls: MtlsMaterial | undefined,
  socket?: NetSocket,
): TlsConnectionOptions {
  return {
    ...(socket ? { socket } : { host: url.hostname, port: url.port ? Number(url.port) : 443 }),
    servername: url.hostname,
    rejectUnauthorized,
    ...(mtls ? { cert: mtls.cert, key: mtls.key, ...(mtls.ca ? { ca: mtls.ca } : {}) } : {}),
  }
}

/** Open a raw TCP/TLS stream to `address` (pinned) or through the configured egress proxy. */
async function openStream(
  url: URL,
  address: PublicAddress,
  signal: AbortSignal,
  opts: {
    rejectUnauthorized: boolean
    proxy?: EgressProxy
    mtls?: MtlsMaterial
    alpn?: string[]
  },
): Promise<NetSocket | TLSSocket> {
  const isHttps = url.protocol === 'https:'
  const port = url.port ? Number(url.port) : (isHttps ? 443 : 80)
  const proxy = opts.proxy
  let base: NetSocket

  if (proxy && (proxy.protocol === 'socks5:' || proxy.protocol === 'socks5h:')) {
    base = await connectTcp(proxy.host, proxy.port, signal)
    base = await socks5Tunnel(base, { host: url.hostname.replace(/^\[|\]$/g, ''), port, address: address.address }, proxy, signal)
  } else if (proxy && proxy.protocol === 'http:' && isHttps) {
    base = await connectTcp(proxy.host, proxy.port, signal)
    base = await httpProxyTunnel(base, { host: url.hostname, port }, proxy, signal)
  } else if (proxy && proxy.protocol === 'https:' && isHttps) {
    const raw = await connectTcp(proxy.host, proxy.port, signal)
    const proxyTls = tlsConnect({ ...tlsOptions(new URL(`https://${proxy.host}`), opts.rejectUnauthorized, undefined, raw) })
    await waitForTls(proxyTls, signal)
    base = await httpProxyTunnel(proxyTls, { host: url.hostname, port }, proxy, signal)
  } else if (proxy) {
    // Every configured proxy must carry the traffic; never silently bypass it.
    throw new TransportConfigError(`egress proxy ${proxy.protocol} cannot transport ${url.protocol}:// targets`)
  } else {
    base = await connectTcp(address.address, port, signal)
  }

  if (!isHttps) return base
  const tlsSocket = tlsConnect({
    ...tlsOptions(url, opts.rejectUnauthorized, opts.mtls, base),
    ...(opts.alpn ? { ALPNProtocols: opts.alpn } : {}),
  })
  tlsSocket.setTimeout(0)
  await waitForTls(tlsSocket, signal)
  if (opts.alpn && tlsSocket.alpnProtocol !== 'h2') {
    tlsSocket.destroy()
    throw new H2UnavailableError('peer did not negotiate h2 via ALPN', true)
  }
  return tlsSocket
}

function waitForTls(socket: TLSSocket, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      socket.destroy()
      reject(signal.reason ?? new Error('aborted'))
    }
    if (signal.aborted) return onAbort()
    signal.addEventListener('abort', onAbort, { once: true })
    socket.once('secureConnect', () => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    })
    socket.once('error', err => {
      signal.removeEventListener('abort', onAbort)
      reject(err)
    })
  })
}

// ---------------------------------------------------------------------------
// HTTP/2 transport
// ---------------------------------------------------------------------------

export class H2UnavailableError extends Error {
  readonly safeToRetry: boolean
  constructor(message: string, safeToRetry: boolean) {
    super(message)
    this.name = 'H2UnavailableError'
    this.safeToRetry = safeToRetry
  }
}

type Http2PoolEntry = {
  session: ClientHttp2Session
  key: string
  authority: string
  lastUsed: number
  socket: NetSocket | TLSSocket
}

const h2UnavailableCodes = new Set([
  'ERR_HTTP2_ERROR',
  'ERR_HTTP2_PROTOCOL_ERROR',
  'ERR_HTTP2_STREAM_ERROR',
  'ERR_HTTP2_INVALID_SESSION',
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'ERR_SSL_NO_APPLICATION_PROTOCOL',
])

const hopByHopHeaders = new Set([
  'host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer',
])

function h2Headers(url: URL, method: string, headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {
    ':method': method,
    ':scheme': url.protocol.replace(':', ''),
    ':authority': url.host,
    ':path': `${url.pathname}${url.search}`,
  }
  const normalized = canonicalizeUniqueHeaders(headers, 'HTTP/2 headers')
  for (const [k, v] of Object.entries(normalized)) {
    if (k.startsWith(':') || hopByHopHeaders.has(k)) continue
    // Connection-specific header lists are illegal on HTTP/2.
    out[k] = v
  }
  return out
}

function decompressStream(headers: IncomingHttpHeaders): { stream?: Duplex; decompressed: boolean } {
  const encoding = String(headers['content-encoding'] ?? '').toLowerCase().trim()
  if (encoding === 'gzip' || encoding === 'x-gzip') return { stream: createGunzip(), decompressed: true }
  if (encoding === 'deflate') return { stream: createInflate(), decompressed: true }
  if (encoding === 'br') return { stream: createBrotliDecompress(), decompressed: true }
  return { decompressed: false }
}

/** Extract the response body from an h2 stream, honoring size caps and content-encoding. */
function collectH2Body(
  stream: ClientHttp2Stream,
  headers: IncomingHttpHeaders,
  cap: number,
): Promise<{ body: string; bodyBytes: number; bodyTruncated: boolean; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const decomp = decompressStream(headers)
    if (decomp.stream) stream.pipe(decomp.stream)
    const source: NodeJS.ReadableStream = decomp.stream ?? stream
    const chunks: Buffer[] = []
    let total = 0
    let truncated = false
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      const outHeaders: IncomingHttpHeaders = { ...headers }
      if (decomp.decompressed) {
        delete outHeaders['content-encoding']
        delete outHeaders['content-length']
      }
      resolve({
        body: Buffer.concat(chunks).toString('utf8'),
        bodyBytes: total,
        bodyTruncated: truncated,
        headers: outHeaders,
      })
    }
    source.on('data', (chunk: Buffer) => {
      if (settled) return
      if (total + chunk.length > cap) {
        const remaining = cap - total
        if (remaining > 0) chunks.push(chunk.subarray(0, remaining))
        total = cap
        truncated = true
        try { stream.close(8 /* NGHTTP2_CANCEL */) } catch { /* ignore */ }
        finish()
        return
      }
      chunks.push(chunk)
      total += chunk.length
    })
    source.once('end', finish)
    source.once('error', err => {
      if (!settled && !truncated) reject(err)
      else finish()
    })
    stream.once('error', err => {
      if (!settled && !truncated) reject(err)
      else finish()
    })
    stream.once('aborted', () => {
      if (!settled) reject(new Error('HTTP/2 stream aborted'))
    })
  })
}

export type HttpTransportOptions = {
  method?: string
  headers?: Record<string, string>
  body?: string
  maxBodyBytes?: number
  readBody?: boolean
  rejectUnauthorized?: boolean
  raceBarrier?: RaceBarrier
  /** Internal: force the HTTP/1.1 path (used after an h2 downgrade). */
  forceHttp1?: boolean
}

export type HttpTransport = Transport & {
  close: () => void
  mode: 'http2' | 'http1'
  isHttp2Enabled: () => boolean
}

const defaultMaxBodyBytes = 1024 * 1024
const hardMaxBodyBytes = 2 * 1024 * 1024

/**
 * Build the broker's default transport: HTTP/2 when enabled, with a transparent fallback to the
 * supplied HTTP/1.1 implementation. Scope/approval/redaction all happen in the broker *before*
 * this function is called, so both paths share the exact same preflight.
 */
export function createHttpTransport(config: TransportConfig, fallback: Transport): HttpTransport {
  const sessions = new Map<string, Http2PoolEntry>()
  const unavailable = new Set<string>()
  const maxSessions = Math.max(1, Math.min(config.http2MaxSessions ?? 8, 64))

  const profileAgent = (headers: Record<string, string>) => {
    const merged = canonicalizeUniqueHeaders(headers, 'HTTP headers')
    if (config.headerProfile?.userAgent) merged['user-agent'] = config.headerProfile.userAgent
    for (const [k, v] of Object.entries(config.headerProfile?.headers ?? {})) {
      // Only fill gaps unless the profile explicitly overrides the caller's authorized header.
      if (merged[k] === undefined) merged[k] = v
    }
    return merged
  }

  const evict = () => {
    while (sessions.size > maxSessions) {
      let oldestKey: string | undefined
      let oldest = Infinity
      for (const [key, entry] of sessions) {
        if (entry.lastUsed < oldest) {
          oldest = entry.lastUsed
          oldestKey = key
        }
      }
      if (!oldestKey) break
      const entry = sessions.get(oldestKey)
      sessions.delete(oldestKey)
      try { entry?.session.close() } catch { /* ignore */ }
    }
  }

  const pendingSessions = new Map<string, Promise<ClientHttp2Session>>()

  const openSession = async (
    url: URL,
    address: PublicAddress,
    signal: AbortSignal,
    rejectUnauthorized: boolean,
    key: string,
  ): Promise<ClientHttp2Session> => {
    const socket = await openStream(url, address, signal, {
      rejectUnauthorized,
      ...(config.proxy ? { proxy: config.proxy } : {}),
      ...(config.mtls ? { mtls: config.mtls } : {}),
      ...(url.protocol === 'https:' ? { alpn: ['h2', 'http/1.1'] } : {}),
    })

    const session = http2Connect(url.origin, {
      createConnection: () => socket as NetSocket,
      settings: { enablePush: false },
    })
    const entry: Http2PoolEntry = { session, key, authority: url.origin, lastUsed: Date.now(), socket }
    sessions.set(key, entry)
    evict()

    const forget = () => {
      if (sessions.get(key) === entry) sessions.delete(key)
    }
    session.once('close', forget)
    session.once('error', forget)
    session.once('goaway', forget)

    await new Promise<void>((resolve, reject) => {
      const onAbort = () => reject(signal.reason ?? new Error('aborted'))
      if (signal.aborted) return onAbort()
      signal.addEventListener('abort', onAbort, { once: true })
      session.once('connect', () => {
        signal.removeEventListener('abort', onAbort)
        resolve()
      })
      session.once('error', err => {
        signal.removeEventListener('abort', onAbort)
        reject(err)
      })
    })
    return session
  }

  const getSession = async (
    url: URL,
    address: PublicAddress,
    signal: AbortSignal,
    rejectUnauthorized: boolean,
  ): Promise<ClientHttp2Session> => {
    const key = `${url.origin}\0${address.address}\0${config.proxy ? config.proxy.protocol + config.proxy.host + config.proxy.port : ''}`
    const existing = sessions.get(key)
    if (existing && !existing.session.closed && !existing.session.destroyed) {
      existing.lastUsed = Date.now()
      return existing.session
    }
    if (existing) sessions.delete(key)
    // Single-flight: a synchronized burst must share one connection, not dial once per stream.
    const pending = pendingSessions.get(key)
    if (pending) return pending
    const promise = openSession(url, address, signal, rejectUnauthorized, key)
    pendingSessions.set(key, promise)
    try {
      return await promise
    } finally {
      pendingSessions.delete(key)
    }
  }

  const sendH2 = async (
    url: URL,
    address: PublicAddress,
    signal: AbortSignal,
    options: HttpTransportOptions,
  ): Promise<RawHttpResponse> => {
    const methodName = (options.method ?? 'GET').toUpperCase()
    const session = await getSession(url, address, signal, options.rejectUnauthorized ?? true)
    const headers = canonicalizeUniqueHeaders({ ...(options.headers ?? {}) }, 'HTTP/2 headers')
    if (config.headerProfile?.userAgent && headers['user-agent'] === undefined) {
      headers['user-agent'] = config.headerProfile.userAgent
    }
    for (const [name, value] of Object.entries(config.headerProfile?.headers ?? {})) {
      if (headers[name] === undefined) headers[name] = value
    }
    if (headers['user-agent'] === undefined) headers['user-agent'] = defaultUserAgent
    if (headers.accept === undefined) headers.accept = 'text/html, application/json;q=0.9, */*;q=0.1'
    if (headers['accept-encoding'] === undefined) headers['accept-encoding'] = 'gzip, deflate, br'
    if (options.body !== undefined && headers['content-type'] === undefined) headers['content-type'] = 'application/json'

    const requestHeaders = h2Headers(url, methodName, headers)

    // Every participant waits for the barrier before its HEADERS frame is written, so a race
    // burst arrives on the wire in one event-loop turn on the single pooled connection.
    if (options.raceBarrier) await options.raceBarrier.arrive()
    signal.throwIfAborted()

    return new Promise<RawHttpResponse>((resolve, reject) => {
      let settled = false
      const stream = session.request(requestHeaders, { endStream: false })
      const tls = session.socket instanceof TLSSocket
        ? extractTlsMetadata(session.socket, url.hostname)
        : undefined
      const fail = (err: Error) => {
        if (settled) return
        settled = true
        signal.removeEventListener('abort', onAbort)
        reject(err)
      }
      const onAbort = () => {
        try { stream.close(8) } catch { /* ignore */ }
        fail(signal.reason ?? new Error('aborted'))
      }
      signal.addEventListener('abort', onAbort, { once: true })

      stream.once('response', rawHeaders => {
        const status = Number(rawHeaders[':status'] ?? 0)
        const responseHeaders: IncomingHttpHeaders = {}
        for (const [k, v] of Object.entries(rawHeaders)) {
          if (k.startsWith(':')) continue
          if (k === 'set-cookie') {
            responseHeaders[k] = Array.isArray(v) ? v.map(String) : [String(v)]
          } else {
            responseHeaders[k] = Array.isArray(v) ? v.map(String).join(', ') : String(v)
          }
        }
        const cap = Math.min(options.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes)
        if (!(options.readBody ?? false) || methodName === 'HEAD') {
          settled = true
          signal.removeEventListener('abort', onAbort)
          resolve({ status, headers: responseHeaders, body: '', bodyBytes: 0, bodyTruncated: false, tls })
          try { stream.close(8) } catch { /* ignore */ }
          return
        }
        collectH2Body(stream, responseHeaders, cap).then(result => {
          if (settled) return
          settled = true
          signal.removeEventListener('abort', onAbort)
          resolve({ status, headers: result.headers, body: result.body, bodyBytes: result.bodyBytes, bodyTruncated: result.bodyTruncated, tls })
        }).catch(fail)
      })

      stream.once('error', err => fail(err))
      stream.once('aborted', () => fail(new Error('HTTP/2 stream aborted')))

      if (options.body !== undefined && options.body !== '') {
        stream.write(options.body)
        stream.end()
      } else {
        stream.end()
      }
    })
  }

  const proxyHttp1 = async (
    url: URL,
    address: PublicAddress,
    signal: AbortSignal,
    options: HttpTransportOptions,
  ): Promise<RawHttpResponse> => {
    const proxy = config.proxy
    if (!proxy) throw new Error('proxyHttp1 called without a proxy')
    const isHttps = url.protocol === 'https:'
    const port = url.port ? Number(url.port) : (isHttps ? 443 : 80)
    const methodName = (options.method ?? 'GET').toUpperCase()
    const headers = profileAgent({ ...(options.headers ?? {}) })
    if (headers['user-agent'] === undefined) headers['user-agent'] = defaultUserAgent
    if (headers.accept === undefined) headers.accept = 'text/html, application/json;q=0.9, */*;q=0.1'
    if (headers['accept-encoding'] === undefined) headers['accept-encoding'] = 'gzip, deflate, br'
    if (options.body !== undefined) {
      if (headers['content-type'] === undefined) headers['content-type'] = 'application/json'
      headers['content-length'] = String(Buffer.byteLength(options.body))
    }

    let socket: NetSocket | undefined
    let requestHost = proxy.host
    let requestPort = proxy.port
    let requestPath = `${url.pathname}${url.search}`
    let extraHeaders: Record<string, string> = {}

    if (isHttps) {
      // CONNECT tunnel (HTTP proxy) or SOCKS5 tunnel, then TLS inside it.
      const raw = await connectTcp(proxy.host, proxy.port, signal)
      socket = proxy.protocol === 'socks5:' || proxy.protocol === 'socks5h:'
        ? await socks5Tunnel(raw, { host: url.hostname.replace(/^\[|\]$/g, ''), port, address: address.address }, proxy, signal)
        : await httpProxyTunnel(raw, { host: url.hostname, port }, proxy, signal)
      const tlsSocket = tlsConnect(tlsOptions(url, options.rejectUnauthorized ?? true, config.mtls, socket))
      await waitForTls(tlsSocket, signal)
      socket = tlsSocket
      requestHost = url.hostname
      requestPort = port
      headers.host = url.host
    } else if (proxy.protocol === 'http:') {
      // Plain HTTP through an HTTP proxy: absolute-form request line.
      requestPath = url.href
      headers.host = url.host
      if (proxy.authorization) extraHeaders['proxy-authorization'] = proxy.authorization
    } else if (proxy.protocol === 'https:') {
      // Fail closed: an HTTPS proxy needs a CONNECT tunnel, which we only implement for TLS
      // targets. Silently sending plaintext to the proxy would leak the request outside it.
      throw new TransportConfigError('HTTPS egress proxy requires an https:// target')
    } else {
      const raw = await connectTcp(proxy.host, proxy.port, signal)
      socket = await socks5Tunnel(raw, { host: url.hostname.replace(/^\[|\]$/g, ''), port, address: address.address }, proxy, signal)
      requestHost = address.address
      requestPort = port
      headers.host = url.host
    }

    const useTls = socket instanceof TLSSocket
    const agent = socket
      ? useTls
        ? new HttpsAgent({ keepAlive: false })
        : new HttpAgent({ keepAlive: false })
      : undefined
    if (agent && socket) {
      // Route the single request over the pre-established tunnel.
      ;(agent as unknown as { createConnection: () => NetSocket }).createConnection = () => socket
    }

    const requestOptions = {
      host: requestHost,
      port: requestPort,
      path: requestPath,
      method: methodName,
      headers: { ...headers, ...extraHeaders },
      signal,
      ...(agent ? { agent } : {}),
    }

    return new Promise<RawHttpResponse>((resolve, reject) => {
      const onResponse = (res: IncomingMessage) => {
        const tls = res.socket instanceof TLSSocket ? extractTlsMetadata(res.socket, url.hostname) : undefined
        const cap = Math.min(options.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes)
        if (!(options.readBody ?? false) || methodName === 'HEAD') {
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: '', bodyBytes: 0, bodyTruncated: false, tls })
          res.destroy()
          return
        }
        const decomp = decompressStream(res.headers)
        if (decomp.stream) res.pipe(decomp.stream)
        const source: NodeJS.ReadableStream = decomp.stream ?? res
        const chunks: Buffer[] = []
        let total = 0
        let truncated = false
        let done = false
        const finish = () => {
          if (done) return
          done = true
          const outHeaders: IncomingHttpHeaders = { ...res.headers }
          if (decomp.decompressed) {
            delete outHeaders['content-encoding']
            delete outHeaders['content-length']
          }
          resolve({
            status: res.statusCode ?? 0,
            headers: outHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
            bodyBytes: total,
            bodyTruncated: truncated,
            tls,
          })
        }
        source.on('data', (chunk: Buffer) => {
          if (done) return
          if (total + chunk.length > cap) {
            const remaining = cap - total
            if (remaining > 0) chunks.push(chunk.subarray(0, remaining))
            total = cap
            truncated = true
            res.destroy()
            finish()
            return
          }
          chunks.push(chunk)
          total += chunk.length
        })
        source.once('end', finish)
        source.once('close', finish)
        source.once('error', err => {
          if (!done && !truncated) reject(err)
          else finish()
        })
      }
      const req = useTls
        ? httpsRequest(requestOptions as never, onResponse)
        : httpRequest(requestOptions as never, onResponse)
      req.once('error', reject)
      if (options.body !== undefined) req.write(options.body)
      req.end()
    })
  }

  const transport = (async (
    url: URL,
    address: PublicAddress,
    signal: AbortSignal,
    options: HttpTransportOptions = {},
  ): Promise<RawHttpResponse> => {
    const methodName = (options.method ?? 'GET').toUpperCase()
    const idempotent = methodName === 'GET' || methodName === 'HEAD' || methodName === 'OPTIONS'
    const key = `${url.origin}\0${address.address}`
    const canUseH2 = config.http2 && options.forceHttp1 !== true && !unavailable.has(key) &&
      !(config.proxy && url.protocol === 'http:')

    if (canUseH2) {
      try {
        return await sendH2(url, address, signal, options)
      } catch (err) {
        options.raceBarrier?.skip()
        const code = (err as NodeJS.ErrnoException)?.code ?? ''
        const protocolFailure = err instanceof H2UnavailableError ||
          h2UnavailableCodes.has(code) ||
          /protocol error|NGHTTP2|ALPN/i.test((err as Error).message ?? '')
        if (protocolFailure) unavailable.add(key)
        // Never replay a non-idempotent request whose bytes may already have reached the target.
        const safe = err instanceof H2UnavailableError ? err.safeToRetry : (protocolFailure && (idempotent || !hasStartedH2(err as Error)))
        if (!safe && !idempotent) throw err
        return config.proxy
          ? proxyHttp1(url, address, signal, options)
          : fallback(url, address, signal, { ...options, headers: profileAgent(options.headers ?? {}) })
      }
    }

    // Barrier participants that never touch h2 must release their peers.
    options.raceBarrier?.skip()
    return config.proxy
      ? proxyHttp1(url, address, signal, options)
      : fallback(url, address, signal, { ...options, headers: profileAgent(options.headers ?? {}) })
  }) as unknown as HttpTransport

  transport.close = () => {
    for (const entry of sessions.values()) {
      try { entry.session.close() } catch { /* ignore */ }
    }
    sessions.clear()
  }
  transport.mode = config.http2 ? 'http2' : 'http1'
  transport.isHttp2Enabled = () => config.http2
  return transport
}

/** Conservative check that the failure happened before any request bytes were flushed. */
function hasStartedH2(err: Error): boolean {
  const code = (err as NodeJS.ErrnoException).code ?? ''
  return !(code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH' ||
    code === 'CERT_HAS_EXPIRED' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || code === 'ERR_TLS_CERT_ALTNAME_INVALID')
}

// ---------------------------------------------------------------------------
// WebSocket turn-aware session
// ---------------------------------------------------------------------------

const wsGuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

export type WsSessionOptions = {
  headers?: Record<string, string>
  /** Convenience cookie attachment: appended as a `Cookie` header when no Cookie header is set. */
  cookie?: string
  subprotocols?: string[]
  rejectUnauthorized?: boolean
  timeoutMs?: number
  userAgent?: string
}

export type WsAssembledMessage = {
  opcode: 'text' | 'binary'
  data: Buffer
  text: string
  frames: number
  timestamp: number
}

type ParsedWsFrame = { fin: boolean; opcode: number; payload: Buffer }

function encodeClientFrame(opcode: number, payload: Buffer, fin = true): Buffer {
  const mask = randomBytes(4)
  const len = payload.length
  let header: Buffer
  if (len < 126) {
    header = Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | len])
  } else if (len < 65_536) {
    header = Buffer.alloc(4)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 0x80 | 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  const masked = Buffer.alloc(len)
  for (let i = 0; i < len; i += 1) masked[i] = payload[i]! ^ mask[i % 4]
  return Buffer.concat([header, mask, masked])
}

export class WebSocketSession {
  private readonly socket: NetSocket | TLSSocket
  private buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0)
  private queue: ParsedWsFrame[] = []
  private waiters: Array<() => void> = []
  private closed = false
  private readonly fragments: Buffer[] = []
  private fragmentsOpcode: number | undefined
  readonly handshake: { status: number; headers: Record<string, string>; subprotocol: string | null; accepted: boolean }

  private constructor(
    socket: NetSocket | TLSSocket,
    handshake: WebSocketSession['handshake'],
  ) {
    this.socket = socket
    this.handshake = handshake
    socket.on('data', (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk])
      this.drain()
      this.wake()
    })
    socket.once('close', () => {
      this.closed = true
      this.wake()
    })
    socket.once('error', () => {
      this.closed = true
      this.wake()
    })
  }

  static async connect(url: URL, address: PublicAddress, options: WsSessionOptions = {}): Promise<WebSocketSession> {
    const subprotocols = options.subprotocols ?? []
    if (subprotocols.some(protocol => !isValidWebsocketSubprotocol(protocol))) {
      throw new TransportConfigError('WebSocket subprotocols must be non-empty RFC token values without control characters')
    }
    const isSecure = url.protocol === 'https:'
    const port = url.port ? Number(url.port) : (isSecure ? 443 : 80)
    const key = randomBytes(16).toString('base64')
    const expectedAccept = createHash('sha1').update(key + wsGuid).digest('base64')
    let socket: NetSocket | TLSSocket
    if (isSecure) {
      socket = tlsConnect({
        host: address.address,
        port,
        servername: url.hostname,
        rejectUnauthorized: options.rejectUnauthorized ?? true,
      })
    } else {
      socket = netConnect({ host: address.address, port })
    }

    try {
      await new Promise<void>((resolve, reject) => {
        const event = isSecure ? 'secureConnect' : 'connect'
        socket.once(event, () => resolve())
        socket.once('error', reject)
      })
    } catch (err) {
      socket.destroy()
      throw err
    }

    const headers = canonicalizeUniqueHeaders({
      host: url.host,
      upgrade: 'websocket',
      connection: 'Upgrade',
      'sec-websocket-key': key,
      'sec-websocket-version': '13',
      'user-agent': options.userAgent ?? 'KovoHunter/3 defensive websocket probe',
    }, 'WebSocket headers')
    if (subprotocols.length) headers['sec-websocket-protocol'] = subprotocols.join(', ')
    const callerHeaders = canonicalizeUniqueHeaders(options.headers ?? {}, 'WebSocket headers')
    for (const [k, v] of Object.entries(callerHeaders)) {
      if (/^(?:host|upgrade|connection|sec-websocket-key|sec-websocket-version|sec-websocket-protocol)$/.test(k)) continue
      headers[k] = v
    }
    if (options.cookie && headers.cookie === undefined) {
      if (crlf.test(options.cookie)) throw new TransportConfigError('WebSocket cookie contains CR/LF/NUL')
      headers.cookie = options.cookie
    }
    if (crlf.test(options.userAgent ?? '')) throw new TransportConfigError('WebSocket user agent contains CR/LF/NUL')
    const requestLines = [
      `GET ${url.pathname}${url.search} HTTP/1.1`,
      ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      '',
      '',
    ]
    socket.write(requestLines.join('\r\n'))

    const reader = new SocketReader(socket)
    const deadline = AbortSignal.timeout(options.timeoutMs ?? 10_000)
    let head: string
    try {
      head = await reader.readUntil('\r\n\r\n', 64 * 1024, deadline)
    } catch (err) {
      socket.destroy()
      throw err
    }
    const lines = head.split('\r\n').filter(Boolean)
    const statusMatch = /^HTTP\/1\.[01]\s+(\d{3})/.exec(lines[0] ?? '')
    const status = statusMatch ? Number(statusMatch[1]) : 0
    const responseHeaders: Record<string, string> = {}
    for (const line of lines.slice(1)) {
      const idx = line.indexOf(':')
      if (idx <= 0) continue
      responseHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim()
    }
    const accepted = status === 101 && responseHeaders['sec-websocket-accept'] === expectedAccept
    const leftover = reader.takeBuffered()
    const session = new WebSocketSession(socket, {
      status,
      headers: responseHeaders,
      subprotocol: responseHeaders['sec-websocket-protocol'] ?? null,
      accepted,
    })
    if (leftover.length > 0) {
      session.buffer = leftover
      session.drain()
    }
    if (!accepted) session.close()
    return session
  }

  get isOpen(): boolean {
    return !this.closed && !this.socket.destroyed
  }

  async sendText(text: string): Promise<void> {
    this.writeFrame(0x1, Buffer.from(text, 'utf8'))
  }

  async sendBinary(data: Buffer): Promise<void> {
    this.writeFrame(0x2, data)
  }

  async ping(payload = Buffer.alloc(0)): Promise<void> {
    this.writeFrame(0x9, payload)
  }

  private writeFrame(opcode: number, payload: Buffer): void {
    if (!this.isOpen) throw new Error('WebSocket session is closed')
    this.socket.write(encodeClientFrame(opcode, payload))
  }

  private drain(): void {
    for (;;) {
      const frame = this.takeFrame()
      if (!frame) return
      if (frame.opcode === 0x9) {
        // Ping: answer immediately so the server's idle timers stay satisfied.
        try { this.socket.write(encodeClientFrame(0xA, frame.payload)) } catch { /* ignore */ }
        continue
      }
      if (frame.opcode === 0xA) continue
      if (frame.opcode === 0x8) {
        this.closed = true
        return
      }
      this.queue.push(frame)
    }
  }

  private takeFrame(): ParsedWsFrame | undefined {
    if (this.buffer.length < 2) return undefined
    const first = this.buffer[0]!
    const second = this.buffer[1]!
    const fin = (first & 0x80) !== 0
    const opcode = first & 0x0f
    const masked = (second & 0x80) !== 0
    let length = second & 0x7f
    let offset = 2
    if (length === 126) {
      if (this.buffer.length < 4) return undefined
      length = this.buffer.readUInt16BE(2)
      offset = 4
    } else if (length === 127) {
      if (this.buffer.length < 10) return undefined
      const big = this.buffer.readBigUInt64BE(2)
      if (big > 8n * 1024n * 1024n) throw new Error('WebSocket frame exceeds the session cap')
      length = Number(big)
      offset = 10
    }
    const maskOffset = masked ? 4 : 0
    if (this.buffer.length < offset + maskOffset + length) return undefined
    let payload = this.buffer.subarray(offset + maskOffset, offset + maskOffset + length)
    if (masked) {
      const mask = this.buffer.subarray(offset, offset + 4)
      const unmasked = Buffer.alloc(length)
      for (let i = 0; i < length; i += 1) unmasked[i] = payload[i]! ^ mask[i % 4]!
      payload = unmasked
    }
    this.buffer = this.buffer.subarray(offset + maskOffset + length)
    return { fin, opcode, payload: Buffer.from(payload) }
  }

  private wake(): void {
    const waiters = this.waiters
    this.waiters = []
    for (const wake of waiters) wake()
  }

  private waitForActivity(timeoutMs: number): Promise<boolean> {
    return new Promise(resolve => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter(w => w !== onWake)
        resolve(false)
      }, timeoutMs)
      const onWake = () => {
        clearTimeout(timer)
        resolve(true)
      }
      this.waiters.push(onWake)
    })
  }

  /** Read one raw frame (control frames included), or null on timeout/close. */
  async nextFrame(timeoutMs = 5_000): Promise<ParsedWsFrame | null> {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      while (this.queue.length === 0) {
        const remaining = deadline - Date.now()
        if (this.closed || remaining <= 0) return null
        const active = await this.waitForActivity(remaining)
        if (!active) return null
        this.drain()
      }
      return this.queue.shift() ?? null
    }
  }

  /**
   * Await one complete application message, reassembling continuation frames. Control frames
   * (ping/pong/close) are handled transparently by the drain loop.
   */
  async nextMessage(timeoutMs = 5_000): Promise<WsAssembledMessage | null> {
    const deadline = Date.now() + timeoutMs
    for (;;) {
      const frame = await this.nextFrame(Math.max(1, deadline - Date.now()))
      if (!frame) return null
      if (frame.opcode === 0x0) {
        if (this.fragmentsOpcode === undefined) continue
        this.fragments.push(frame.payload)
        if (!frame.fin) continue
        const data = Buffer.concat(this.fragments)
        const opcode = this.fragmentsOpcode === 0x2 ? 'binary' : 'text'
        this.fragments.length = 0
        this.fragmentsOpcode = undefined
        return { opcode, data, text: data.toString('utf8'), frames: 0, timestamp: Date.now() }
      }
      if (frame.opcode !== 0x1 && frame.opcode !== 0x2) continue
      if (frame.fin) {
        const opcode = frame.opcode === 0x2 ? 'binary' : 'text'
        return { opcode, data: frame.payload, text: frame.payload.toString('utf8'), frames: 1, timestamp: Date.now() }
      }
      this.fragmentsOpcode = frame.opcode
      this.fragments.length = 0
      this.fragments.push(frame.payload)
    }
  }

  async nextJson<T = unknown>(timeoutMs = 5_000): Promise<T | null> {
    const message = await this.nextMessage(timeoutMs)
    if (!message) return null
    try {
      return JSON.parse(message.text) as T
    } catch {
      return null
    }
  }

  close(code = 1000, reason = ''): void {
    if (!this.closed && !this.socket.destroyed) {
      const payload = Buffer.alloc(2 + Buffer.byteLength(reason))
      payload.writeUInt16BE(code, 0)
      payload.write(reason, 2)
      try { this.socket.write(encodeClientFrame(0x8, payload)) } catch { /* ignore */ }
    }
    this.closed = true
    this.socket.destroy()
  }
}
