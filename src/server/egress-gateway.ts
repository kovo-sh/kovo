/**
 * Canonical outbound network egress gateway (`EgressGateway`).
 *
 * Single choke point for target-facing HTTP/1.1 (`egressFetch`), HTTP/2 (`egressHttp2`),
 * and Playwright Chromium host-loopback proxying (`createLoopbackProxy`).
 *
 * Security invariants enforced uniformly across all three paths:
 *  1. Scheme & userinfo validation (`http:`/`https:` only; userinfo always refused).
 *  2. Scope & denylist validation before DNS resolution.
 *  3. Single-resolution pinned DNS (`createPinnedLookup` / pinned-IP socket dial) so a
 *     hostname cannot rebind between check time and connect time; empty DNS always fails closed.
 *  4. IPv4 + IPv6 SSRF classification via `ipaddr.js` (including IPv4-mapped IPv6 unmapping):
 *     - Cloud metadata & link-local (`169.254.0.0/16`, `169.254.169.254`, `169.254.170.2`,
 *       `100.100.100.200`, `fe80::/10`, `fd00:ec2::254`) are ALWAYS refused, even in local-lab.
 *     - Private/ULA/CGNAT/loopback/unspecified/multicast/reserved ranges are refused unless
 *       explicitly permitted by `allowLocalLab`, `allowedPrivateHosts`, or `allowedLoopbackOnlyHosts`.
 *  5. Manual redirect hopping (`redirect: 'manual'`) with per-hop re-validation and bounded
 *     hop count; sensitive headers (`Authorization`, `Cookie`, `Proxy-Authorization`) are
 *     stripped on cross-origin hops.
 *  6. Original `Host` header and TLS SNI (`servername`) preserved when dialing pinned IPs.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { lookup as dnsLookup } from 'node:dns/promises'
import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage, Server as HttpServer, ServerResponse } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as http2Connect, constants as http2Constants } from 'node:http2'
import type { ClientHttp2Session } from 'node:http2'
import { connect as netConnect } from 'node:net'
import type { AddressInfo, Socket as NetSocket } from 'node:net'
import { connect as tlsConnect, TLSSocket } from 'node:tls'
import { pipeline } from 'node:stream'
import type { Duplex } from 'node:stream'
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib'
import ipaddr from 'ipaddr.js'
import { globalKillSwitch, KillSwitchTrippedError } from './kill-switch.ts'
import type { GlobalKillSwitch } from './kill-switch.ts'
import { isIpLiteralHost, normalizeHostname } from './public-suffix.ts'
import { evaluateBrowserScopeRequest } from './scope-policy.ts'
import type { ScopePolicy } from './scope-policy.ts'

// ---------------------------------------------------------------------------
// Error & Classification Types
// ---------------------------------------------------------------------------

export type EgressDenyCode =
  | 'invalid_url'
  | 'scheme_blocked'
  | 'userinfo_blocked'
  | 'host_denied'
  | 'scope_denied'
  | 'dns_empty'
  | 'metadata_blocked'
  | 'private_ip_blocked'
  | 'loopback_blocked'
  | 'redirect_blocked'
  | 'redirect_limit'
  | 'response_too_large'
  | 'proxy_connect_denied'
  | 'proxy_auth_required'
  | 'kill_switch_active'

export class EgressDeniedError extends Error {
  readonly code: EgressDenyCode

  constructor(code: EgressDenyCode, message: string) {
    super(message)
    this.name = 'EgressDeniedError'
    this.code = code
  }
}

/** Coarse address class (compatible with legacy `persona-auth.ts` consumers). */
export type AddressClass = 'public' | 'loopback' | 'blocked'

/** Fine-grained IPv4/IPv6 classification used by `EgressGateway` policy decisions. */
export type DetailedAddressClass =
  | 'public'
  | 'loopback'
  | 'private'
  | 'metadata_or_link_local'
  | 'blocked'

export interface PinnedAddress {
  address: string
  family: 4 | 6
}

export interface EgressPolicy {
  /** Permit loopback and non-metadata private/ULA addresses plus plaintext HTTP for local labs. */
  allowLocalLab?: boolean
  /** Explicit plaintext HTTP override. When omitted, HTTP is allowed only for local-lab or allowlisted loopback. */
  allowHttp?: boolean
  /** Optional origin allowlist (`https://host[:port]`). */
  allowedOrigins?: readonly string[]
  /** Optional dynamic scope gate evaluated for every hop/request before DNS resolution. */
  allowOrigin?: (
    origin: string,
    method: string,
    url: URL,
  ) => boolean | { allowed: boolean; reason?: string }
  /** Hostnames or origins permitted to resolve to loopback/private IPs (metadata/link-local still blocked). */
  allowedPrivateHosts?: readonly string[]
  /** Hostnames or origins permitted to resolve ONLY to loopback (RFC1918/ULA still blocked). */
  allowedLoopbackOnlyHosts?: readonly string[]
  /** Explicit denylist of hostnames or wildcard suffixes (`*.internal.example`). */
  deniedHosts?: readonly string[]
  /** Manual redirect following (default `false` — fail closed / return 3xx directly). */
  followRedirects?: boolean
  /** Bounded redirect hop limit when `followRedirects` is `true` (default 5, max 10). */
  maxRedirects?: number
  /** Per-request timeout in milliseconds (default 15_000). */
  timeoutMs?: number
  /** Maximum response body size in bytes (default 2 MiB). */
  maxResponseBytes?: number
  /** TLS certificate verification (default `true`). */
  rejectUnauthorized?: boolean
  /** Injectable DNS resolver for deterministic testing. */
  resolveHost?: (hostname: string) => Promise<string[]>
  /**
   * Optional pre-resolved addresses for the initial hop (still re-validated against SSRF rules).
   * Redirect hops ALWAYS perform fresh resolution and never reuse this list.
   */
  pinnedAddresses?: readonly string[]
  /** Optional audit callback invoked on every denial. */
  onDenied?: (event: { url: string; origin: string; code: EgressDenyCode; reason: string }) => void
  /** Optional audit callback invoked before dialing a validated pinned address. */
  onAllow?: (event: { url: string; origin: string; pinnedAddress: string }) => void
  /** H-2: Tenant namespace for per-tenant kill-switch checks (`null`/`undefined` checks global switch). */
  tenantId?: string | null
  /** H-2: Optional kill-switch instance (defaults to process-wide `globalKillSwitch`). */
  killSwitch?: GlobalKillSwitch
}

export interface EgressRawHttp1Options<TTls = unknown> {
  method?: string
  headers?: Record<string, string>
  body?: string | Buffer
  maxBodyBytes?: number
  readBody?: boolean
  rejectUnauthorized?: boolean
  signal?: AbortSignal
  /** H-2: Tenant namespace for per-tenant kill-switch checks (`null`/`undefined` checks global switch). */
  tenantId?: string | null
  /** H-2: Optional kill-switch instance (defaults to process-wide `globalKillSwitch`). */
  killSwitch?: GlobalKillSwitch
  /** Optional hook to extract TLS metadata from the underlying `TLSSocket` before the stream ends. */
  extractTls?: (socket: TLSSocket, hostname: string) => TTls
}

export interface EgressRawHttp1Response<TTls = unknown> {
  status: number
  headers: IncomingHttpHeaders
  body: string
  bodyBytes: number
  bodyTruncated: boolean
  tls?: TTls
}

export interface EgressHttp2Init {
  method?: string
  headers?: Record<string, string>
  body?: string | Buffer | Uint8Array | null
  signal?: AbortSignal
}

export interface EgressHttp2Response {
  status: number
  headers: Record<string, string>
  rawHeaders: Record<string, string>
  body: string
  bodyBytes: number
  bodyTruncated: boolean
  pinnedAddress: string
  durationMs: number
}

export interface LoopbackProxyPolicy extends Omit<EgressPolicy, 'allowLocalLab' | 'allowOrigin' | 'allowedOrigins'> {
  /** Static or dynamically evaluated local-lab flag (supports pooled browser contexts). */
  allowLocalLab?: boolean | (() => boolean)
  /** Static or dynamically evaluated origin allowlist. */
  allowedOrigins?: readonly string[] | (() => readonly string[] | undefined)
  /** Optional ScopePolicy enforced on both proxied HTTP requests and CONNECT tunnels. */
  scopePolicy?: ScopePolicy | (() => ScopePolicy | undefined)
  /** Dynamic scope predicate (evaluated per HTTP request and per CONNECT tunnel). */
  allowOrigin?: (
    origin: string,
    method: string,
    url: URL,
  ) => boolean | { allowed: boolean; reason?: string }
  /** Optional CONNECT port predicate (defaults to 443, allowlisted origin ports, or any valid port in local-lab). */
  allowConnectPort?: (port: number, hostname: string) => boolean
  /** Optional hook to inject or strip headers on proxied plain-HTTP requests before forwarding. */
  transformRequestHeaders?: (url: URL, headers: Record<string, string>) => Record<string, string>
  /** Optional hook to inspect or strip headers on proxied plain-HTTP responses before returning to Chromium. */
  transformResponseHeaders?: (url: URL, headers: IncomingHttpHeaders) => IncomingHttpHeaders
  /** Keep the server unref'd so an idle pooled proxy cannot block process exit (default `true`). */
  unref?: boolean
}

export interface LoopbackProxyCredentials {
  readonly username: string
  readonly password: string
}

export interface LoopbackProxyContextBinding {
  readonly credentials: LoopbackProxyCredentials
  readonly authorizationHeader: string
  readonly proxyConfig: { server: string; username: string; password: string }
  updatePolicy(patch: Partial<LoopbackProxyPolicy>): void
  unregister(): void
}

export interface EgressLoopbackProxy {
  readonly url: string
  readonly host: '127.0.0.1'
  readonly port: number
  readonly credentials: LoopbackProxyCredentials
  readonly authorizationHeader: string
  readonly proxyConfig: { server: string; username: string; password: string }
  registerContextPolicy(policy: LoopbackProxyPolicy): LoopbackProxyContextBinding
  updatePolicy(patch: Partial<LoopbackProxyPolicy>): void
  close(): Promise<void>
}

// ---------------------------------------------------------------------------
// Constants & Address Classification (IPv4 + IPv6 via ipaddr.js)
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 15_000
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
const DEFAULT_MAX_REDIRECTS = 5
const HARD_MAX_REDIRECTS = 10

/** Cloud metadata endpoints that are NEVER permitted — even under `allowLocalLab` or `allowedPrivateHosts`. */
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', // AWS / GCP / Azure / DigitalOcean IMDSv1 & v2
  '169.254.170.2',   // AWS ECS task metadata
  '100.100.100.200', // Alibaba Cloud metadata
  'fd00:ec2::254',   // AWS IPv6 IMDS
])

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

const CROSS_ORIGIN_STRIP_HEADERS = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
])

function stripBracketsAndZone(address: string): string {
  const bare = address.trim().replace(/^\[|\]$/g, '')
  const zoneIdx = bare.indexOf('%')
  return zoneIdx >= 0 ? bare.slice(0, zoneIdx) : bare
}

/**
 * Fine-grained IPv4/IPv6 classification using `ipaddr.js`.
 * `ipaddr.process()` automatically unmaps IPv4-mapped IPv6 addresses (`::ffff:169.254.169.254`,
 * `::ffff:127.0.0.1`, `::ffff:10.0.0.1`) so dual-stack smuggling cannot bypass SSRF checks.
 */
export function classifyDetailedAddress(address: string): DetailedAddressClass {
  const bare = stripBracketsAndZone(address)
  if (!bare) return 'blocked'
  if (bare.toLowerCase() === 'localhost') return 'loopback'
  try {
    const ip = ipaddr.process(bare)
    const normalized = ip.toString().toLowerCase()
    if (CLOUD_METADATA_IPS.has(normalized)) return 'metadata_or_link_local'
    const range = ip.range()
    if (range === 'linkLocal') return 'metadata_or_link_local'
    if (range === 'loopback') return 'loopback'
    if (range === 'private' || range === 'uniqueLocal' || range === 'carrierGradeNat') {
      return 'private'
    }
    if (range === 'unicast') {
      // For IPv6, restrict `public` to global unicast `2000::/3` (matching broker.ts:isPublicAddress).
      if (ip.kind() === 'ipv4' || (ip.toByteArray()[0] >> 5) === 1) {
        return 'public'
      }
      return 'blocked'
    }
    return 'blocked'
  } catch {
    return 'blocked'
  }
}

/** Coarse address class (`'public' | 'loopback' | 'blocked'`) compatible with `persona-auth.ts`. */
export function classifyAddress(address: string): AddressClass {
  const detailed = classifyDetailedAddress(address)
  if (detailed === 'public') return 'public'
  if (detailed === 'loopback') return 'loopback'
  return 'blocked'
}

export function isPublicIpAddress(address: string): boolean {
  return classifyDetailedAddress(address) === 'public'
}

export function isMetadataOrLinkLocalAddress(address: string): boolean {
  return classifyDetailedAddress(address) === 'metadata_or_link_local'
}

export function isLoopbackLiteral(host: string): boolean {
  const bare = stripBracketsAndZone(host)
  if (!bare) return false
  if (bare.toLowerCase() === 'localhost') return true
  if (!ipaddr.isValid(bare)) return false
  return ipaddr.process(bare).range() === 'loopback'
}

// ---------------------------------------------------------------------------
// DNS Resolution & Pinned Lookup
// ---------------------------------------------------------------------------

export async function defaultResolveHost(hostname: string): Promise<string[]> {
  const bare = stripBracketsAndZone(hostname)
  if (!bare) return []
  if (isIpLiteralHost(bare)) return [bare]
  if (bare.toLowerCase() === 'localhost') return ['127.0.0.1', '::1']
  try {
    const records = await dnsLookup(bare, { all: true, order: 'verbatim' })
    return records.map(entry => entry.address)
  } catch {
    return []
  }
}

function toPinnedAddresses(addresses: readonly (string | PinnedAddress)[]): PinnedAddress[] {
  const out: PinnedAddress[] = []
  const seen = new Set<string>()
  for (const item of addresses) {
    const raw = typeof item === 'string' ? item : item.address
    const clean = stripBracketsAndZone(raw)
    if (!clean || seen.has(clean)) continue
    let family: 4 | 6 = 4
    if (typeof item !== 'string' && (item.family === 4 || item.family === 6)) {
      family = item.family
    } else if (ipaddr.isValid(clean)) {
      family = ipaddr.parse(clean).kind() === 'ipv6' ? 6 : 4
    }
    seen.add(clean)
    out.push({ address: clean, family })
  }
  return out
}

/**
 * Custom Node `dns.lookup` pinned strictly to the addresses validated for `expectedHost`.
 * Refuses any other hostname and never falls back to the system resolver.
 */
export function createPinnedLookup(
  expectedHost: string,
  addresses: readonly (string | PinnedAddress)[],
): (hostname: string, options: unknown, callback: (...args: unknown[]) => void) => void {
  const host = normalizeHostname(stripBracketsAndZone(expectedHost))
  const pinned = toPinnedAddresses(addresses)
  return (hostname, options, callback) => {
    const asked = normalizeHostname(stripBracketsAndZone(String(hostname)))
    if (!host || !pinned.length || asked !== host) {
      callback(new Error(`Pinned resolver refused ${asked || '<empty>'} (validated host: ${host || '<none>'}).`))
      return
    }
    const opts = (options && typeof options === 'object' ? options : {}) as { family?: number; all?: boolean }
    const wanted = opts.family === 4 || opts.family === 6
      ? pinned.filter(entry => entry.family === opts.family)
      : pinned
    if (!wanted.length) {
      callback(new Error(`Pinned resolver has no address for family ${String(opts.family)} on ${host}.`))
      return
    }
    if (opts.all) {
      callback(null, wanted)
      return
    }
    callback(null, wanted[0]!.address, wanted[0]!.family)
  }
}

// ---------------------------------------------------------------------------
// Policy Evaluation & Pre-Dial Validation
// ---------------------------------------------------------------------------

function normalizeHostEntry(entry: string): string {
  const trimmed = entry.trim()
  if (!trimmed) return ''
  if (trimmed.includes('://')) {
    try {
      return normalizeHostname(stripBracketsAndZone(new URL(trimmed).hostname))
    } catch {
      return ''
    }
  }
  return normalizeHostname(stripBracketsAndZone(trimmed))
}

function matchesHostList(host: string, entries: readonly string[] | undefined): boolean {
  if (!entries || entries.length === 0) return false
  for (const raw of entries) {
    const pattern = raw.trim().toLowerCase()
    if (!pattern) continue
    if (pattern.startsWith('*.')) {
      const suffix = normalizeHostname(pattern.slice(2))
      if (suffix && host !== suffix && host.endsWith(`.${suffix}`)) return true
      continue
    }
    const normalized = normalizeHostEntry(raw)
    if (normalized && host === normalized) return true
  }
  return false
}

function matchesOriginList(origin: string, entries: readonly string[] | undefined): boolean {
  if (!entries || entries.length === 0) return false
  for (const entry of entries) {
    try {
      if (new URL(entry).origin === origin) return true
    } catch {
      // Ignore malformed allowlist entries.
    }
  }
  return false
}

function denyWithAudit(
  policy: EgressPolicy,
  url: string,
  origin: string,
  code: EgressDenyCode,
  reason: string,
): never {
  policy.onDenied?.({ url, origin, code, reason })
  throw new EgressDeniedError(code, reason)
}

/**
 * Validate scheme, userinfo, denylist, origin scope, DNS resolution, and every resolved IP
 * address against `policy`. Returns the pinned address list that MUST be dialed verbatim.
 */
export async function resolveAndValidateHost(
  urlInput: string | URL,
  policy: EgressPolicy = {},
  method = 'GET',
): Promise<{ url: URL; hostname: string; addresses: PinnedAddress[] }> {
  let url: URL
  try {
    url = urlInput instanceof URL ? new URL(urlInput.toString()) : new URL(urlInput)
  } catch {
    denyWithAudit(policy, String(urlInput), '', 'invalid_url', 'Egress destination is not a valid URL.')
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    denyWithAudit(policy, url.href, url.origin, 'scheme_blocked', `Unsupported egress URL scheme ${url.protocol}.`)
  }
  if (url.username || url.password) {
    denyWithAudit(policy, url.href, url.origin, 'userinfo_blocked', 'Egress URL must not contain embedded credentials.')
  }

  const hostname = normalizeHostname(stripBracketsAndZone(url.hostname))
  if (!hostname) {
    denyWithAudit(policy, url.href, url.origin, 'invalid_url', 'Egress URL is missing a valid hostname.')
  }

  if (matchesHostList(hostname, policy.deniedHosts)) {
    denyWithAudit(policy, url.href, url.origin, 'host_denied', `Egress destination host "${hostname}" is denied by policy.`)
  }

  const allowLocalLab = Boolean(policy.allowLocalLab)
  const privateHostAllowed = matchesHostList(hostname, policy.allowedPrivateHosts)
  const loopbackOnlyHostAllowed = matchesHostList(hostname, policy.allowedLoopbackOnlyHosts)
  const exactOriginAllowed = matchesOriginList(url.origin, policy.allowedOrigins)

  // H10-egress: intersect `allowedOrigins` AND `allowOrigin` (never OR) when both are specified.
  if (policy.allowedOrigins !== undefined && !exactOriginAllowed) {
    denyWithAudit(policy, url.href, url.origin, 'scope_denied', `Egress origin "${url.origin}" is outside the allowed origins.`)
  }
  if (policy.allowOrigin) {
    const verdict = policy.allowOrigin(url.origin, method.toUpperCase(), url)
    const allowed = typeof verdict === 'boolean' ? verdict : verdict.allowed
    if (!allowed) {
      const detail = typeof verdict === 'object' && verdict.reason ? verdict.reason : `Egress origin "${url.origin}" is outside scope.`
      denyWithAudit(policy, url.href, url.origin, 'scope_denied', detail)
    }
  }

  const loopbackHost = isLoopbackLiteral(hostname)
  const httpPermitted = policy.allowHttp === true
    || (policy.allowHttp !== false && (allowLocalLab || (loopbackHost && (privateHostAllowed || loopbackOnlyHostAllowed || exactOriginAllowed))))
  if (url.protocol === 'http:' && !httpPermitted) {
    denyWithAudit(policy, url.href, url.origin, 'scheme_blocked', `Plaintext HTTP egress to "${hostname}" is not permitted; use HTTPS.`)
  }

  const rawAddresses = policy.pinnedAddresses && policy.pinnedAddresses.length > 0
    ? [...policy.pinnedAddresses]
    : await (policy.resolveHost ?? defaultResolveHost)(hostname)
  const pinned = toPinnedAddresses(rawAddresses)
  if (pinned.length === 0) {
    denyWithAudit(
      policy,
      url.href,
      url.origin,
      'dns_empty',
      `Egress host "${hostname}" did not resolve; refusing unpinned connection.`,
    )
  }

  for (const entry of pinned) {
    const kind = classifyDetailedAddress(entry.address)
    if (kind === 'metadata_or_link_local') {
      denyWithAudit(
        policy,
        url.href,
        url.origin,
        'metadata_blocked',
        `Egress host "${hostname}" resolved to link-local/cloud-metadata address (${entry.address}); never permitted.`,
      )
    }
    if (kind === 'public') continue
    if (kind === 'loopback') {
      if (allowLocalLab || privateHostAllowed || loopbackOnlyHostAllowed) continue
      denyWithAudit(
        policy,
        url.href,
        url.origin,
        'loopback_blocked',
        `Egress host "${hostname}" resolved to loopback address (${entry.address}) without local-lab or explicit loopback allowlist.`,
      )
    }
    if (kind === 'private') {
      if (allowLocalLab || privateHostAllowed) continue
      denyWithAudit(
        policy,
        url.href,
        url.origin,
        'private_ip_blocked',
        `Egress host "${hostname}" resolved to private/ULA address (${entry.address}); refused by SSRF policy.`,
      )
    }
    denyWithAudit(
      policy,
      url.href,
      url.origin,
      'private_ip_blocked',
      `Egress host "${hostname}" resolved to non-public address (${entry.address}); refused by SSRF policy.`,
    )
  }

  return { url, hostname, addresses: pinned }
}

// ---------------------------------------------------------------------------
// Header / Body Helpers
// ---------------------------------------------------------------------------

let warnedEnvProxy = false
export function warnIfEnvProxyEnabled(): void {
  if (warnedEnvProxy) return
  const setting = process.env.NODE_USE_ENV_PROXY
  if (!setting || setting === '0' || setting.toLowerCase() === 'false') return
  warnedEnvProxy = true
  console.warn(
    'WARNING: NODE_USE_ENV_PROXY is set. Outbound pinned-IP flows are unsupported behind an environment proxy: ' +
    'the proxy re-resolves on Kovo Hunter\'s behalf, so pinned addresses cannot be guaranteed.',
  )
}

function headersToRecord(initHeaders?: HeadersInit): Record<string, string> {
  const record: Record<string, string> = {}
  new Headers(initHeaders).forEach((value, key) => {
    record[key] = value
  })
  return record
}

const RESERVED_PROTO_HEADER_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

const SINGLE_VALUE_HTTP_HEADERS = new Set([
  'age',
  'authorization',
  'content-length',
  'content-type',
  'etag',
  'expires',
  'from',
  'host',
  'if-modified-since',
  'if-unmodified-since',
  'last-modified',
  'location',
  'max-forwards',
  'proxy-authorization',
  'referer',
  'retry-after',
  'server',
  'user-agent',
])

export function isReservedProtoHeaderKey(name: string): boolean {
  return RESERVED_PROTO_HEADER_KEYS.has(name.toLowerCase())
}

/**
 * R3-C-1: Parse Node's flat `IncomingMessage.rawHeaders` array directly into a null-prototype
 * `IncomingHttpHeaders` map, skipping reserved prototype accessor keys (`__proto__`, `constructor`,
 * `prototype`). Never touches Node's lazy `IncomingMessage.headers` getter, which assigns onto a
 * plain object and throws `ERR_PROTO_ACCESS` when an upstream sends a reserved header name.
 */
export function parseRawHeadersNullProto(rawHeaders: readonly string[] | undefined): IncomingHttpHeaders {
  const out = Object.create(null) as IncomingHttpHeaders
  if (!Array.isArray(rawHeaders)) return out
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const lower = String(rawHeaders[i]).toLowerCase()
    if (!lower || RESERVED_PROTO_HEADER_KEYS.has(lower)) continue
    const value = String(rawHeaders[i + 1])
    if (lower === 'set-cookie') {
      const existing = out['set-cookie']
      if (Array.isArray(existing)) existing.push(value)
      else out['set-cookie'] = [value]
    } else if (lower === 'cookie') {
      out.cookie = out.cookie !== undefined ? `${out.cookie}; ${value}` : value
    } else if (SINGLE_VALUE_HTTP_HEADERS.has(lower)) {
      if (out[lower] === undefined) out[lower] = value
    } else {
      const existing = out[lower]
      out[lower] = existing === undefined ? value : `${existing}, ${value}`
    }
  }
  return out
}

export function cloneNullProtoHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const out = Object.create(null) as IncomingHttpHeaders
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue
    if (RESERVED_PROTO_HEADER_KEYS.has(key.toLowerCase())) continue
    out[key] = Array.isArray(value) ? [...value] : value
  }
  return out
}

export function responseHeadersFromRawHeaders(rawHeaders: readonly string[] | undefined): Headers {
  const headers = new Headers()
  if (!Array.isArray(rawHeaders)) return headers
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = String(rawHeaders[i])
    const lower = name.toLowerCase()
    if (!lower || RESERVED_PROTO_HEADER_KEYS.has(lower)) continue
    headers.append(name, String(rawHeaders[i + 1]))
  }
  return headers
}

async function normalizeRequestBody(body: BodyInit | null | undefined): Promise<Buffer | undefined> {
  if (body === undefined || body === null) return undefined
  if (typeof body === 'string') return Buffer.from(body, 'utf8')
  if (Buffer.isBuffer(body)) return body
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength)
  if (body instanceof ArrayBuffer) return Buffer.from(body)
  if (body instanceof URLSearchParams) return Buffer.from(body.toString(), 'utf8')
  if (typeof (body as Blob).arrayBuffer === 'function') {
    return Buffer.from(await (body as Blob).arrayBuffer())
  }
  return Buffer.from(String(body), 'utf8')
}

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308
}

function resolveEgressKillSwitch(
  policy?: { killSwitch?: GlobalKillSwitch; tenantId?: string | null },
): { ks: GlobalKillSwitch; tenantId: string | null } {
  return {
    ks: policy?.killSwitch ?? globalKillSwitch,
    tenantId: policy?.tenantId ?? null,
  }
}

function bindEgressKillSwitchSignal(
  ks: GlobalKillSwitch,
  signal: AbortSignal | null | undefined,
  tenantId: string | null,
): { signal: AbortSignal; release: () => void } {
  return ks.bindSignal(signal ?? new AbortController().signal, tenantId)
}

function createResponseDecompressor(
  rawEncoding: string | string[] | undefined,
): { decoder: Duplex; encoding: string } | null {
  const encoding = (Array.isArray(rawEncoding) ? rawEncoding.join(', ') : (rawEncoding ?? '')).toLowerCase().trim()
  if (encoding === 'gzip' || encoding === 'x-gzip') return { decoder: createGunzip(), encoding }
  if (encoding === 'deflate') return { decoder: createInflate(), encoding }
  if (encoding === 'br') return { decoder: createBrotliDecompress(), encoding }
  return null
}

/**
 * Strip RFC 9110/9113 hop-by-hop headers (plus any header names listed in `Connection` and
 * `:pseudo-headers` / `host`) before sending an HTTP/2 request (`C-1`).
 */
function stripHttp2HopByHopHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const connectionListed = new Set<string>()
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (k.toLowerCase() !== 'connection') continue
    for (const token of v.split(',')) {
      const name = token.trim().toLowerCase()
      if (name) connectionListed.add(name)
    }
  }
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (k.trimStart().startsWith(':')) continue
    const lower = k.toLowerCase()
    if (lower === 'host' || HOP_BY_HOP_HEADERS.has(lower) || connectionListed.has(lower)) continue
    out[lower] = v
  }
  return out
}

// ---------------------------------------------------------------------------
// 1. Canonical HTTP/1.1 Outbound Dialer (`egressFetch`)
// ---------------------------------------------------------------------------

async function dialSinglePinnedHttp1(params: {
  url: URL
  hostname: string
  addresses: readonly PinnedAddress[]
  method: string
  headers: Record<string, string>
  body: Buffer | undefined
  timeoutMs: number
  maxResponseBytes: number
  rejectUnauthorized: boolean
  signal?: AbortSignal
}): Promise<Response> {
  const { url, hostname, addresses, method, headers, body, timeoutMs, maxResponseBytes, rejectUnauthorized, signal } = params
  const reqHeaders: Record<string, string> = { ...headers }
  const hasHostHeader = Object.keys(reqHeaders).some(k => k.toLowerCase() === 'host')
  if (!hasHostHeader) reqHeaders.host = url.host
  if (body && !Object.keys(reqHeaders).some(k => k.toLowerCase() === 'content-length')) {
    reqHeaders['content-length'] = String(body.byteLength)
  }

  const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest
  return await new Promise<Response>((resolve, reject) => {
    let settled = false
    const finish = (err: unknown, value?: Response) => {
      if (settled) return
      settled = true
      signal?.removeEventListener('abort', onAbort)
      if (err) reject(err)
      else resolve(value!)
    }

    const req = requestFn({
      protocol: url.protocol,
      hostname,
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method,
      headers: reqHeaders,
      agent: false,
      lookup: createPinnedLookup(hostname, addresses) as never,
      ...(url.protocol === 'https:'
        ? {
            servername: !isIpLiteralHost(hostname) ? hostname : undefined,
            rejectUnauthorized,
          }
        : {}),
    }, res => {
      try {
        const chunks: Buffer[] = []
        let total = 0
        res.on('data', (chunk: Buffer) => {
          try {
            total += chunk.byteLength
            if (total > maxResponseBytes) {
              const err = new EgressDeniedError(
                'response_too_large',
                `Egress response exceeded the ${maxResponseBytes}-byte size limit.`,
              )
              req.destroy(err)
              finish(err)
              return
            }
            chunks.push(chunk)
          } catch (err) {
            req.destroy()
            finish(err)
          }
        })
        res.on('end', () => {
          try {
            const status = res.statusCode ?? 0
            const responseBody = status === 204 || status === 304 ? null : Buffer.concat(chunks)
            finish(null, new Response(responseBody, {
              status,
              statusText: res.statusMessage ?? '',
              headers: responseHeadersFromRawHeaders(res.rawHeaders),
            }))
          } catch (err) {
            req.destroy()
            finish(err)
          }
        })
        res.on('error', err => finish(err))
        res.once('aborted', () => finish(new Error('Egress HTTP/1.1 response aborted mid-body.')))
        res.once('close', () => {
          if (!settled && !res.complete) {
            finish(new Error('Egress HTTP/1.1 response closed prematurely mid-body.'))
          }
        })
      } catch (err) {
        req.destroy()
        finish(err)
      }
    })

    req.setTimeout(timeoutMs, () => {
      const err = new Error(`Egress request timed out after ${timeoutMs}ms.`)
      req.destroy(err)
      finish(err)
    })
    req.on('error', err => finish(err))

    const onAbort = () => {
      const reason = signal?.reason instanceof Error ? signal.reason : new Error('Egress request aborted.')
      req.destroy(reason)
      finish(reason)
    }
    if (signal?.aborted) {
      onAbort()
      return
    }
    signal?.addEventListener('abort', onAbort, { once: true })
    req.on('close', () => signal?.removeEventListener('abort', onAbort))

    if (body) req.write(body)
    req.end()
  })
}

/**
 * Canonical outbound HTTP/1.1 fetch with single-resolution DNS pinning, IPv4+IPv6 SSRF
 * enforcement, preserved Host + TLS SNI, and manual per-hop redirect re-validation.
 */
export async function egressFetch(
  urlInput: string | URL,
  init: RequestInit = {},
  policy: EgressPolicy = {},
): Promise<Response> {
  warnIfEnvProxyEnabled()
  const { ks, tenantId } = resolveEgressKillSwitch(policy)
  ks.assertAllowed(tenantId)

  const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const maxResponseBytes = Math.max(1024, policy.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
  const rejectUnauthorized = policy.rejectUnauthorized ?? true
  const followRedirects = Boolean(policy.followRedirects && init.redirect !== 'manual')
  const maxRedirects = Math.max(0, Math.min(policy.maxRedirects ?? DEFAULT_MAX_REDIRECTS, HARD_MAX_REDIRECTS))

  let currentUrl = urlInput instanceof URL ? urlInput.toString() : urlInput
  let method = (init.method ?? 'GET').toUpperCase()
  let headers = headersToRecord(init.headers)
  let body = await normalizeRequestBody(init.body)
  const ksBound = bindEgressKillSwitchSignal(ks, init.signal, tenantId)

  try {
    for (let hop = 0; ; hop += 1) {
      ks.assertAllowed(tenantId)
      // Only the initial hop may use caller-supplied `pinnedAddresses`; redirect hops MUST resolve fresh.
      const hopPolicy: EgressPolicy = hop === 0
        ? policy
        : { ...policy, pinnedAddresses: undefined }
      const validated = await resolveAndValidateHost(currentUrl, hopPolicy, method)
      ks.assertAllowed(tenantId)
      policy.onAllow?.({
        url: validated.url.href,
        origin: validated.url.origin,
        pinnedAddress: validated.addresses[0]!.address,
      })

      const response = await dialSinglePinnedHttp1({
        url: validated.url,
        hostname: validated.hostname,
        addresses: validated.addresses,
        method,
        headers,
        body,
        timeoutMs,
        maxResponseBytes,
        rejectUnauthorized,
        signal: ksBound.signal,
      })

      if (!followRedirects || !isRedirectStatus(response.status)) {
        return response
      }

      const location = response.headers.get('location')
      if (!location) return response

      if (hop >= maxRedirects) {
        denyWithAudit(
          policy,
          validated.url.href,
          validated.url.origin,
          'redirect_limit',
          `Egress request exceeded maximum redirect hops (${maxRedirects}).`,
        )
      }

      let nextUrl: URL
      try {
        nextUrl = new URL(location, validated.url)
      } catch {
        denyWithAudit(
          policy,
          validated.url.href,
          validated.url.origin,
          'redirect_blocked',
          'Egress redirect contained a malformed Location header.',
        )
      }

      if (nextUrl.origin !== validated.url.origin) {
        const stripped: Record<string, string> = {}
        for (const [k, v] of Object.entries(headers)) {
          const lower = k.toLowerCase()
          if (CROSS_ORIGIN_STRIP_HEADERS.has(lower) || lower === 'host') continue
          stripped[k] = v
        }
        headers = stripped
      } else {
        // Drop stale Host header so the next hop computes it cleanly.
        const nextHeaders: Record<string, string> = {}
        for (const [k, v] of Object.entries(headers)) {
          if (k.toLowerCase() === 'host') continue
          nextHeaders[k] = v
        }
        headers = nextHeaders
      }

      if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
        method = 'GET'
        body = undefined
        for (const key of Object.keys(headers)) {
          const lower = key.toLowerCase()
          if (lower === 'content-length' || lower === 'content-type') delete headers[key]
        }
      }

      currentUrl = nextUrl.toString()
    }
  } catch (err) {
    if (ksBound.signal.aborted && ksBound.signal.reason instanceof KillSwitchTrippedError) {
      throw ksBound.signal.reason
    }
    if (ks.isActive(tenantId)) ks.assertAllowed(tenantId)
    throw err
  } finally {
    ksBound.release()
  }
}

/**
 * Streaming pinned-IP HTTP/1.1 fetch for SSE / long-lived responses (e.g., LLM providers in `provider.ts`).
 * Resolves DNS once, validates all IPs against SSRF/metadata/scope rules, dials ONLY the pinned IP
 * with preserved `Host` + TLS SNI, refuses redirects when `init.redirect === 'error'`, transparently
 * decompresses gzip/deflate/br, and streams response chunks while enforcing `maxResponseBytes`.
 */
export async function egressFetchStream(
  urlInput: string | URL,
  init: RequestInit = {},
  policy: EgressPolicy = {},
): Promise<Response> {
  warnIfEnvProxyEnabled()
  const { ks, tenantId } = resolveEgressKillSwitch(policy)
  ks.assertAllowed(tenantId)

  const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const maxResponseBytes = Math.max(1024, policy.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
  const rejectUnauthorized = policy.rejectUnauthorized ?? true
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = headersToRecord(init.headers)
  const body = await normalizeRequestBody(init.body)
  const ksBound = bindEgressKillSwitchSignal(ks, init.signal, tenantId)
  const signal = ksBound.signal

  let validated: { url: URL; hostname: string; addresses: PinnedAddress[] }
  try {
    validated = await resolveAndValidateHost(urlInput, policy, method)
    ks.assertAllowed(tenantId)
  } catch (err) {
    ksBound.release()
    throw err
  }
  const pinned = validated.addresses[0]!
  policy.onAllow?.({
    url: validated.url.href,
    origin: validated.url.origin,
    pinnedAddress: pinned.address,
  })

  const reqHeaders: Record<string, string> = { ...headers }
  if (!Object.keys(reqHeaders).some(k => k.toLowerCase() === 'host')) {
    reqHeaders.host = validated.url.host
  }
  if (body && !Object.keys(reqHeaders).some(k => k.toLowerCase() === 'content-length')) {
    reqHeaders['content-length'] = String(body.byteLength)
  }

  const requestFn = validated.url.protocol === 'https:' ? httpsRequest : httpRequest
  return await new Promise<Response>((resolve, reject) => {
    let headersSettled = false
    const finishHeaders = (err: unknown, value?: Response) => {
      if (headersSettled) return
      headersSettled = true
      if (err) {
        signal.removeEventListener('abort', onAbort)
        ksBound.release()
        reject(err)
      } else {
        resolve(value!)
      }
    }

    const req = requestFn({
      protocol: validated.url.protocol,
      hostname: validated.hostname,
      port: validated.url.port || undefined,
      path: `${validated.url.pathname}${validated.url.search}`,
      method,
      headers: reqHeaders,
      agent: false,
      lookup: createPinnedLookup(validated.hostname, validated.addresses) as never,
      ...(validated.url.protocol === 'https:'
        ? {
            servername: !isIpLiteralHost(validated.hostname) ? validated.hostname : undefined,
            rejectUnauthorized,
          }
        : {}),
    }, res => {
      try {
        const status = res.statusCode ?? 0
        if (init.redirect === 'error' && isRedirectStatus(status)) {
          const err = new EgressDeniedError(
            'redirect_blocked',
            `Egress streaming request refused HTTP ${status} redirect.`,
          )
          policy.onDenied?.({
            url: validated.url.href,
            origin: validated.url.origin,
            code: 'redirect_blocked',
            reason: err.message,
          })
          req.destroy(err)
          finishHeaders(err)
          return
        }

        const parsedHeaders = parseRawHeadersNullProto(res.rawHeaders)
        const decomp = createResponseDecompressor(parsedHeaders['content-encoding'])
        const decompressed = decomp !== null
        const source: NodeJS.ReadableStream = decomp ? decomp.decoder : res

        const respHeaders = responseHeadersFromRawHeaders(res.rawHeaders)
        if (decompressed) {
          respHeaders.delete('content-encoding')
          respHeaders.delete('content-length')
        }

        if (status === 204 || status === 304) {
          signal.removeEventListener('abort', onAbort)
          ksBound.release()
          res.resume()
          finishHeaders(null, new Response(null, { status, statusText: res.statusMessage ?? '', headers: respHeaders }))
          return
        }

        let streamClosed = false
        let totalBytes = 0
        const readable = new ReadableStream<Uint8Array>({
          start(controller) {
            const cleanup = () => {
              signal.removeEventListener('abort', onStreamAbort)
              ksBound.release()
            }
            const failStream = (err: unknown) => {
              if (streamClosed) return
              streamClosed = true
              decomp?.decoder.destroy()
              req.destroy()
              try { controller.error(err) } catch { /* ignore */ }
              cleanup()
            }
            const onStreamAbort = () => {
              const reason = signal.reason instanceof Error ? signal.reason : new Error('Egress stream aborted.')
              failStream(reason)
            }
            if (signal.aborted) {
              onStreamAbort()
              return
            }
            signal.removeEventListener('abort', onAbort)
            signal.addEventListener('abort', onStreamAbort, { once: true })

            if (decomp) {
              pipeline(res, decomp.decoder, err => {
                if (err && !streamClosed) failStream(err)
              })
            }

            source.on('data', (chunk: Buffer) => {
              try {
                if (streamClosed) return
                totalBytes += chunk.byteLength
                if (totalBytes > maxResponseBytes) {
                  const err = new EgressDeniedError(
                    'response_too_large',
                    `Egress streaming response exceeded the ${maxResponseBytes}-byte size limit.`,
                  )
                  failStream(err)
                  return
                }
                try {
                  controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength))
                } catch {
                  streamClosed = true
                  decomp?.decoder.destroy()
                  req.destroy()
                  cleanup()
                }
              } catch (err) {
                failStream(err)
              }
            })
            source.once('end', () => {
              try {
                if (streamClosed) return
                streamClosed = true
                try { controller.close() } catch { /* ignore */ }
                cleanup()
              } catch (err) {
                failStream(err)
              }
            })
            source.once('error', err => failStream(err))
            res.once('aborted', () => failStream(new Error('Egress streaming response aborted mid-body.')))
            res.once('close', () => {
              if (!streamClosed && !res.complete) {
                failStream(new Error('Egress streaming response closed prematurely mid-body.'))
              }
            })
            if (source !== res) {
              res.once('error', err => failStream(err))
            }
          },
          cancel() {
            streamClosed = true
            signal.removeEventListener('abort', onAbort)
            decomp?.decoder.destroy()
            req.destroy()
            ksBound.release()
          },
        })

        finishHeaders(null, new Response(readable, {
          status,
          statusText: res.statusMessage ?? '',
          headers: respHeaders,
        }))
      } catch (err) {
        req.destroy()
        finishHeaders(err)
      }
    })

    req.setTimeout(timeoutMs, () => {
      const err = new Error(`Egress streaming request timed out after ${timeoutMs}ms.`)
      req.destroy(err)
      finishHeaders(err)
    })
    req.on('error', err => finishHeaders(err))

    const onAbort = () => {
      const reason = signal.reason instanceof Error ? signal.reason : new Error('Egress streaming request aborted.')
      req.destroy(reason)
      finishHeaders(reason)
    }
    if (signal.aborted) {
      onAbort()
      return
    }
    signal.addEventListener('abort', onAbort, { once: true })

    if (body) req.write(body)
    req.end()
  })
}

/**
 * Canonical pinned-IP HTTP/1.1 raw transport hook for `RequestBroker` (`defaultTransport`).
 *
 * Preserves exact caller header ordering, optional body skipping (`readBody: false` / `HEAD`),
 * transparent gzip/deflate/br decompression via `stream.pipeline` (R2-H-19: truncated compressed
 * bodies always settle cleanly), bounded truncation at `maxBodyBytes`, TLS socket metadata
 * inspection, global/tenant kill-switch enforcement (H-2), and cloud-metadata/link-local refusal.
 */
export async function egressRawHttp1<TTls = unknown>(
  url: URL,
  address: { address: string; family?: number },
  options: EgressRawHttp1Options<TTls> = {},
): Promise<EgressRawHttp1Response<TTls>> {
  warnIfEnvProxyEnabled()
  const { ks, tenantId } = resolveEgressKillSwitch(options)
  ks.assertAllowed(tenantId)

  const pinnedIp = stripBracketsAndZone(address.address)
  if (!pinnedIp || isMetadataOrLinkLocalAddress(pinnedIp)) {
    throw new EgressDeniedError(
      'metadata_blocked',
      `Egress address "${address.address}" is a link-local/cloud-metadata endpoint; never permitted.`,
    )
  }

  const ksBound = bindEgressKillSwitchSignal(ks, options.signal, tenantId)
  const signal = ksBound.signal

  try {
    return await new Promise<EgressRawHttp1Response<TTls>>((resolve, reject) => {
      const isHttps = url.protocol === 'https:'
      const port = url.port ? Number(url.port) : (isHttps ? 443 : 80)
      const method = options.method ?? 'GET'
      const readBody = options.readBody ?? false
      const cap = Math.max(1, options.maxBodyBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
      const headers: Record<string, string> = { ...(options.headers ?? {}) }
      if (!Object.keys(headers).some(k => k.toLowerCase() === 'host')) {
        headers.Host = url.host
      }
      const hostname = stripBracketsAndZone(url.hostname)

      let finished = false
      let activeDecoder: Duplex | null = null
      let activeRes: IncomingMessage | null = null

      const cleanupListeners = () => {
        signal.removeEventListener('abort', onAbort)
      }

      const fail = (err: unknown) => {
        if (finished) return
        finished = true
        cleanupListeners()
        try { activeDecoder?.destroy() } catch { /* ignore */ }
        try { activeRes?.destroy() } catch { /* ignore */ }
        try { req.destroy() } catch { /* ignore */ }
        reject(err)
      }

      const onResponse = (res: IncomingMessage) => {
        try {
          activeRes = res
          const tls = options.extractTls && res.socket instanceof TLSSocket
            ? options.extractTls(res.socket, hostname)
            : undefined
          const parsedHeaders = parseRawHeadersNullProto(res.rawHeaders)
          if (!readBody || method === 'HEAD') {
            if (!finished) {
              finished = true
              cleanupListeners()
              resolve({ status: res.statusCode ?? 0, headers: parsedHeaders, body: '', bodyBytes: 0, bodyTruncated: false, tls })
            }
            res.destroy()
            return
          }

          const decomp = createResponseDecompressor(parsedHeaders['content-encoding'])
          const decompressed = decomp !== null
          activeDecoder = decomp?.decoder ?? null
          const stream: NodeJS.ReadableStream = decomp ? decomp.decoder : res

          const chunks: Buffer[] = []
          let total = 0
          let truncated = false

          const done = () => {
            try {
              if (finished) return
              finished = true
              cleanupListeners()
              const responseHeaders = cloneNullProtoHeaders(parsedHeaders)
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
            } catch (err) {
              fail(err)
            }
          }

          if (decomp) {
            // R2-H-19: `stream.pipeline` guarantees premature EOF / FIN mid-body propagates
            // into the zlib decoder and settles the promise instead of hanging forever.
            pipeline(res, decomp.decoder, err => {
              if (finished) return
              if (err) {
                if (truncated) done()
                else fail(err)
              }
            })
          }

          stream.on('data', (chunk: Buffer) => {
            try {
              if (finished) return
              if (total + chunk.length > cap) {
                const remaining = cap - total
                if (remaining > 0) chunks.push(chunk.subarray(0, remaining))
                total = cap
                truncated = true
                try { decomp?.decoder.destroy() } catch { /* ignore */ }
                res.destroy()
                done()
                return
              }
              chunks.push(chunk)
              total += chunk.length
            } catch (err) {
              fail(err)
            }
          })
          stream.once('end', done)
          stream.once('error', err => {
            if (finished) return
            if (truncated) done()
            else fail(err)
          })
          res.once('aborted', () => {
            if (finished) return
            if (truncated) done()
            else fail(new Error('HTTP/1.1 response aborted mid-body.'))
          })
          res.once('close', () => {
            if (finished) return
            if (truncated) done()
            else if (!res.complete) fail(new Error('HTTP/1.1 response closed prematurely mid-body.'))
          })
        } catch (err) {
          fail(err)
        }
      }

      const family = address.family === 4 || address.family === 6 ? address.family : undefined
      const req = isHttps
        ? httpsRequest({
            hostname: pinnedIp,
            ...(family ? { family } : {}),
            servername: !isIpLiteralHost(hostname) ? hostname : undefined,
            port,
            path: url.pathname + url.search,
            method,
            agent: false,
            rejectUnauthorized: options.rejectUnauthorized ?? true,
            signal,
            headers,
          }, onResponse)
        : httpRequest({
            hostname: pinnedIp,
            ...(family ? { family } : {}),
            port,
            path: url.pathname + url.search,
            method,
            agent: false,
            signal,
            headers,
          }, onResponse)

      const onAbort = () => {
        fail(signal.reason ?? new Error('HTTP/1.1 egress request aborted.'))
      }
      if (signal.aborted) {
        onAbort()
        return
      }
      signal.addEventListener('abort', onAbort, { once: true })

      req.once('error', err => fail(err))
      if (options.body !== undefined) req.write(options.body)
      req.end()
    })
  } catch (err) {
    if (ksBound.signal.aborted && ksBound.signal.reason instanceof KillSwitchTrippedError) {
      throw ksBound.signal.reason
    }
    if (ks.isActive(tenantId)) ks.assertAllowed(tenantId)
    throw err
  } finally {
    ksBound.release()
  }
}

// ---------------------------------------------------------------------------
// 2. Canonical HTTP/2 Outbound Dialer (`egressHttp2`)
// ---------------------------------------------------------------------------

/**
 * Pinned-IP HTTP/2 request helper (used by `RequestBroker.executeHttp2Exchange`).
 * Resolves DNS once, validates all IPs, enforces global/tenant kill-switch (`H-2`), strips
 * hop-by-hop headers (`C-1`), decompresses via `stream.pipeline` (`R2-H-19`), and dials the
 * pinned IP directly via `createConnection` with TLS SNI (`servername`) and `:authority` preserved.
 */
export async function egressHttp2(
  urlInput: string | URL,
  init: EgressHttp2Init = {},
  policy: EgressPolicy = {},
): Promise<EgressHttp2Response> {
  warnIfEnvProxyEnabled()
  const { ks, tenantId } = resolveEgressKillSwitch(policy)
  ks.assertAllowed(tenantId)

  const method = (init.method ?? 'GET').toUpperCase()
  const validated = await resolveAndValidateHost(urlInput, policy, method)
  ks.assertAllowed(tenantId)
  const pinned = validated.addresses.find(a => a.family === 4) ?? validated.addresses[0]!
  policy.onAllow?.({
    url: validated.url.href,
    origin: validated.url.origin,
    pinnedAddress: pinned.address,
  })

  const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const maxResponseBytes = Math.max(1024, policy.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
  const rejectUnauthorized = policy.rejectUnauthorized ?? true
  const isHttps = validated.url.protocol === 'https:'
  const port = validated.url.port ? Number(validated.url.port) : (isHttps ? 443 : 80)

  // C-1: Strip pseudo-headers, `host`, and all RFC 9110/9113 hop-by-hop headers cleanly.
  const reqHeaders = stripHttp2HopByHopHeaders(init.headers)
  const bodyBuf = init.body === undefined || init.body === null
    ? undefined
    : typeof init.body === 'string'
      ? Buffer.from(init.body, 'utf8')
      : Buffer.isBuffer(init.body)
        ? init.body
        : Buffer.from(init.body.buffer, init.body.byteOffset, init.body.byteLength)
  if (bodyBuf && !('content-length' in reqHeaders)) {
    reqHeaders['content-length'] = String(bodyBuf.byteLength)
  }

  const ksBound = bindEgressKillSwitchSignal(ks, init.signal, tenantId)
  const signal = ksBound.signal
  const started = Date.now()
  let activeSocket: Duplex | undefined
  const client: ClientHttp2Session = http2Connect(validated.url.origin, {
    createConnection: () => {
      const tcpSocket = netConnect({
        host: pinned.address,
        port,
        family: pinned.family,
      })
      if (isHttps) {
        const tlsSock = tlsConnect({
          socket: tcpSocket,
          servername: !isIpLiteralHost(validated.hostname) ? validated.hostname : undefined,
          ALPNProtocols: ['h2'],
          rejectUnauthorized,
        })
        activeSocket = tlsSock
        return tlsSock
      }
      activeSocket = tcpSocket
      return tcpSocket
    },
  })

  try {
    signal.throwIfAborted()
    return await new Promise<EgressHttp2Response>((resolve, reject) => {
      let settled = false
      let activeDecoder: Duplex | null = null
      const timer = setTimeout(() => {
        const err = new Error(`HTTP/2 egress request timed out after ${timeoutMs}ms.`)
        activeDecoder?.destroy()
        client.destroy(err)
        activeSocket?.destroy()
        finish(err)
      }, timeoutMs)
      timer.unref?.()

      const finish = (err: unknown, result?: EgressHttp2Response) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        signal.removeEventListener('abort', onAbort)
        if (err) {
          try { activeDecoder?.destroy() } catch { /* ignore */ }
          reject(err)
        } else {
          resolve(result!)
        }
      }

      const onAbort = () => {
        const reason = signal.reason instanceof Error ? signal.reason : new Error('HTTP/2 egress request aborted.')
        activeDecoder?.destroy()
        client.destroy(reason)
        activeSocket?.destroy()
        finish(reason)
      }
      signal.addEventListener('abort', onAbort, { once: true })
      client.once('error', err => finish(err))

      let stream: ReturnType<ClientHttp2Session['request']>
      try {
        stream = client.request({
          ...reqHeaders,
          ':method': method,
          ':path': `${validated.url.pathname}${validated.url.search}`,
          ':authority': validated.url.host,
          ':scheme': isHttps ? 'https' : 'http',
        })
      } catch (err) {
        client.destroy()
        activeSocket?.destroy()
        finish(err)
        return
      }

      let status = 0
      const rawHeaders = Object.create(null) as Record<string, string>
      const chunks: Buffer[] = []
      let rawCaptured = 0
      let captured = 0
      let truncated = false
      let decompressed = false
      let bodyStream: NodeJS.ReadableStream = stream
      let bodyListenersAttached = false

      const attachBodyListeners = (targetStream: NodeJS.ReadableStream) => {
        if (bodyListenersAttached) return
        bodyListenersAttached = true
        targetStream.on('data', (chunk: Buffer) => {
          try {
            if (settled) return
            captured += chunk.length
            if (captured > maxResponseBytes) {
              truncated = true
              activeDecoder?.destroy()
              stream.close(http2Constants.NGHTTP2_CANCEL)
              finish(new EgressDeniedError(
                'response_too_large',
                `HTTP/2 egress response exceeded the ${maxResponseBytes}-byte limit.`,
              ))
              return
            }
            chunks.push(chunk)
          } catch (err) {
            finish(err)
          }
        })
        targetStream.once('error', err => finish(err))
        targetStream.once('end', () => {
          try {
            const body = Buffer.concat(chunks).toString('utf8')
            const outHeaders = Object.create(null) as Record<string, string>
            for (const [k, v] of Object.entries(rawHeaders)) {
              if (!RESERVED_PROTO_HEADER_KEYS.has(k.toLowerCase())) outHeaders[k] = v
            }
            if (decompressed) {
              delete outHeaders['content-encoding']
              delete outHeaders['content-length']
            }
            finish(null, {
              status,
              headers: outHeaders,
              rawHeaders,
              body,
              bodyBytes: captured,
              bodyTruncated: truncated,
              pinnedAddress: pinned.address,
              durationMs: Date.now() - started,
            })
          } catch (err) {
            finish(err)
          }
        })
      }

      stream.on('response', value => {
        try {
          status = Number(value[':status'] ?? 0)
          for (const [k, v] of Object.entries(value)) {
            if (k.startsWith(':') || v === undefined) continue
            const lower = k.toLowerCase()
            if (RESERVED_PROTO_HEADER_KEYS.has(lower)) continue
            rawHeaders[lower] = Array.isArray(v) ? v.join(', ') : String(v)
          }
          const decomp = createResponseDecompressor(rawHeaders['content-encoding'])
          if (decomp) {
            activeDecoder = decomp.decoder
            decompressed = true
            // Also enforce raw compressed byte cap to prevent decompression-bomb DoS.
            stream.on('data', (rawChunk: Buffer) => {
              try {
                rawCaptured += rawChunk.length
                if (rawCaptured > maxResponseBytes) {
                  truncated = true
                  stream.close(http2Constants.NGHTTP2_CANCEL)
                  decomp.decoder.destroy()
                  finish(new EgressDeniedError(
                    'response_too_large',
                    `HTTP/2 egress response exceeded the ${maxResponseBytes}-byte limit.`,
                  ))
                }
              } catch (err) {
                finish(err)
              }
            })
            pipeline(stream, decomp.decoder, err => {
              if (settled) return
              if (err) finish(err)
            })
            bodyStream = decomp.decoder
          }
          attachBodyListeners(bodyStream)
        } catch (err) {
          finish(err)
        }
      })
      stream.once('error', err => finish(err))
      stream.once('aborted', () => finish(new Error('HTTP/2 stream aborted mid-body.')))
      stream.once('close', () => {
        if (!settled && !stream.readableEnded) {
          finish(new Error('HTTP/2 stream closed prematurely mid-body.'))
        }
      })
      stream.end(bodyBuf)
    })
  } catch (err) {
    if (ksBound.signal.aborted && ksBound.signal.reason instanceof KillSwitchTrippedError) {
      throw ksBound.signal.reason
    }
    if (ks.isActive(tenantId)) ks.assertAllowed(tenantId)
    throw err
  } finally {
    ksBound.release()
    try { client.close() } catch { /* ignore */ }
    try {
      if (!client.destroyed) client.destroy()
    } catch { /* ignore */ }
    try { activeSocket?.destroy() } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// 3. Host Loopback HTTP + HTTPS CONNECT Proxy for Chromium (`createLoopbackProxy`)
// ---------------------------------------------------------------------------

function parseConnectAuthority(rawAuthority: string): { hostname: string; port: number; hostHeader: string } | null {
  const trimmed = rawAuthority.trim()
  if (!trimmed || /[\s/@\\]/.test(trimmed)) return null
  if (trimmed.startsWith('[')) {
    const closeBracket = trimmed.indexOf(']')
    if (closeBracket <= 1) return null
    const hostname = trimmed.slice(1, closeBracket)
    const rest = trimmed.slice(closeBracket + 1)
    if (!rest.startsWith(':')) return null
    const port = Number(rest.slice(1))
    if (!Number.isInteger(port) || port < 1 || port > 65_535) return null
    return { hostname, port, hostHeader: `[${hostname}]:${port}` }
  }
  const colonIdx = trimmed.lastIndexOf(':')
  if (colonIdx <= 0) return null
  const hostname = trimmed.slice(0, colonIdx)
  const port = Number(trimmed.slice(colonIdx + 1))
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65_535) return null
  return { hostname, port, hostHeader: `${hostname}:${port}` }
}

function writeProxyErrorResponse(
  res: ServerResponse,
  status: number,
  code: string,
  message: string,
  extraHeaders: Record<string, string> = {},
): void {
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'x-kovo-egress-denied': code,
    connection: 'close',
    ...extraHeaders,
  })
  res.end(message)
}

function writeConnectError(
  socket: Duplex,
  status: number,
  statusText: string,
  code: string,
  extraHeaders: Record<string, string> = {},
): void {
  if (socket.destroyed || !socket.writable) return
  try {
    const extra = Object.entries(extraHeaders).map(([k, v]) => `${k}: ${v}\r\n`).join('')
    socket.end(
      `HTTP/1.1 ${status} ${statusText}\r\n` +
      `X-Kovo-Egress-Denied: ${code}\r\n` +
      extra +
      'Connection: close\r\n\r\n',
    )
  } catch {
    socket.destroy()
  }
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

function mintLoopbackProxyCredentials(): {
  credentials: LoopbackProxyCredentials
  authorizationHeader: string
} {
  const username = `kovo-${randomBytes(8).toString('hex')}`
  const password = randomBytes(24).toString('base64url')
  const authorizationHeader = `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`
  return { credentials: { username, password }, authorizationHeader }
}

function parseBasicProxyAuthorization(rawHeader: string | string[] | undefined): { username: string; password: string } | null {
  const raw = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader
  if (!raw) return null
  const match = /^Basic\s+([A-Za-z0-9+/=_-]+)$/i.exec(raw.trim())
  if (!match?.[1]) return null
  let decoded: string
  try {
    decoded = Buffer.from(match[1], 'base64').toString('utf8')
  } catch {
    return null
  }
  const colonIdx = decoded.indexOf(':')
  if (colonIdx <= 0) return null
  return { username: decoded.slice(0, colonIdx), password: decoded.slice(colonIdx + 1) }
}

function collectAllowedPortsFromPolicy(policy: EgressPolicy, scopePolicy?: ScopePolicy): Set<number> {
  const ports = new Set<number>([443])
  const addOrigins = (origins: readonly string[] | undefined) => {
    for (const raw of origins ?? []) {
      try {
        const parsed = new URL(raw)
        const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80)
        if (Number.isInteger(port) && port >= 1 && port <= 65_535) ports.add(port)
      } catch {
        // Ignore malformed entries.
      }
    }
  }
  addOrigins(policy.allowedOrigins)
  if (scopePolicy) {
    addOrigins(scopePolicy.targetOrigins)
    addOrigins(scopePolicy.authOrigins)
    addOrigins(scopePolicy.assetOrigins)
  }
  return ports
}

function resolveDynamicLoopbackPolicy(state: LoopbackProxyPolicy): {
  egress: EgressPolicy
  scopePolicy?: ScopePolicy
} {
  const allowLocalLab = typeof state.allowLocalLab === 'function' ? state.allowLocalLab() : Boolean(state.allowLocalLab)
  const allowedOrigins = typeof state.allowedOrigins === 'function' ? state.allowedOrigins() : state.allowedOrigins
  const scopePolicy = typeof state.scopePolicy === 'function' ? state.scopePolicy() : state.scopePolicy
  return {
    egress: {
      allowLocalLab,
      ...(state.allowHttp !== undefined ? { allowHttp: state.allowHttp } : {}),
      ...(allowedOrigins !== undefined ? { allowedOrigins } : {}),
      ...(state.allowOrigin ? { allowOrigin: state.allowOrigin } : {}),
      ...(state.allowedPrivateHosts ? { allowedPrivateHosts: state.allowedPrivateHosts } : {}),
      ...(state.allowedLoopbackOnlyHosts ? { allowedLoopbackOnlyHosts: state.allowedLoopbackOnlyHosts } : {}),
      ...(state.deniedHosts ? { deniedHosts: state.deniedHosts } : {}),
      ...(state.timeoutMs !== undefined ? { timeoutMs: state.timeoutMs } : {}),
      ...(state.maxResponseBytes !== undefined ? { maxResponseBytes: state.maxResponseBytes } : {}),
      ...(state.rejectUnauthorized !== undefined ? { rejectUnauthorized: state.rejectUnauthorized } : {}),
      ...(state.resolveHost ? { resolveHost: state.resolveHost } : {}),
      ...(state.onDenied ? { onDenied: state.onDenied } : {}),
      ...(state.onAllow ? { onAllow: state.onAllow } : {}),
      ...(state.tenantId !== undefined ? { tenantId: state.tenantId } : {}),
      ...(state.killSwitch ? { killSwitch: state.killSwitch } : {}),
    },
    ...(scopePolicy ? { scopePolicy } : {}),
  }
}

/**
 * Lightweight host-loopback (`127.0.0.1:0`) HTTP + HTTPS `CONNECT` proxy for Chromium contexts.
 * Requires per-instance (or per-context) random `Proxy-Authorization` credentials, rejecting
 * unauthenticated local connections with `407 Proxy Authentication Required`.
 * Every plain HTTP request and every CONNECT tunnel passes through `resolveAndValidateHost`,
 * `allowConnectPort`, `scopePolicy`, `maxResponseBytes`, and dials ONLY the validated pinned IP.
 */
export async function createLoopbackProxy(initialPolicy: LoopbackProxyPolicy = {}): Promise<EgressLoopbackProxy> {
  const defaultState: LoopbackProxyPolicy = { ...initialPolicy }
  const defaultAuth = mintLoopbackProxyCredentials()
  const contextPolicies = new Map<string, { credentials: LoopbackProxyCredentials; state: LoopbackProxyPolicy }>()
  const activeSockets = new Set<Duplex>()

  const trackSocket = (socket: Duplex) => {
    activeSockets.add(socket)
    socket.once('close', () => activeSockets.delete(socket))
  }

  const authenticate = (req: IncomingMessage): LoopbackProxyPolicy | null => {
    const reqHeaders = parseRawHeadersNullProto(req.rawHeaders)
    const parsed = parseBasicProxyAuthorization(reqHeaders['proxy-authorization'])
    if (!parsed) return null
    if (
      constantTimeStringEqual(parsed.username, defaultAuth.credentials.username) &&
      constantTimeStringEqual(parsed.password, defaultAuth.credentials.password)
    ) {
      return defaultState
    }
    const ctxEntry = contextPolicies.get(parsed.username)
    if (
      ctxEntry &&
      constantTimeStringEqual(parsed.username, ctxEntry.credentials.username) &&
      constantTimeStringEqual(parsed.password, ctxEntry.credentials.password)
    ) {
      return ctxEntry.state
    }
    return null
  }

  const server: HttpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      if (req.socket) trackSocket(req.socket)

      const state = authenticate(req)
      if (!state) {
        defaultState.onDenied?.({
          url: req.url ?? '',
          origin: '',
          code: 'proxy_auth_required',
          reason: 'Loopback proxy rejected unauthenticated request.',
        })
        writeProxyErrorResponse(
          res,
          407,
          'proxy_auth_required',
          'Proxy authentication required.',
          { 'proxy-authenticate': 'Basic realm="Kovo-Egress-Proxy"' },
        )
        return
      }

      const rawUrl = req.url ?? ''
      let targetUrl: URL
      try {
        if (/^https?:\/\//i.test(rawUrl)) {
          targetUrl = new URL(rawUrl)
        } else {
          writeProxyErrorResponse(res, 400, 'invalid_url', 'Proxy requires an absolute http/https URL.')
          return
        }
      } catch {
        writeProxyErrorResponse(res, 400, 'invalid_url', 'Malformed proxy target URL.')
        return
      }

      const method = (req.method ?? 'GET').toUpperCase()
      const { egress: policy, scopePolicy } = resolveDynamicLoopbackPolicy(state)

      const { ks, tenantId } = resolveEgressKillSwitch(policy)
      if (ks.isActive(tenantId)) {
        const ksReason = `Kill switch active for ${tenantId ? `tenant "${tenantId}"` : 'global'} scope.`
        policy.onDenied?.({
          url: targetUrl.href,
          origin: targetUrl.origin,
          code: 'kill_switch_active',
          reason: ksReason,
        })
        writeProxyErrorResponse(res, 403, 'kill_switch_active', ksReason)
        return
      }

      if (scopePolicy) {
        const decision = evaluateBrowserScopeRequest(scopePolicy, {
          origin: targetUrl.origin,
          method,
          pathAndQuery: `${targetUrl.pathname}${targetUrl.search}`,
          redirectHop: true,
        })
        if (!decision.allowed) {
          policy.onDenied?.({
            url: targetUrl.href,
            origin: targetUrl.origin,
            code: 'scope_denied',
            reason: decision.reason,
          })
          writeProxyErrorResponse(res, 403, 'scope_denied', decision.reason)
          return
        }
      }

      let validated: { url: URL; hostname: string; addresses: PinnedAddress[] }
      try {
        validated = await resolveAndValidateHost(targetUrl, policy, method)
      } catch (err) {
        if (err instanceof EgressDeniedError) {
          writeProxyErrorResponse(res, 403, err.code, err.message)
          return
        }
        writeProxyErrorResponse(res, 403, 'scope_denied', 'Egress denied.')
        return
      }

      const pinned = validated.addresses[0]!
      policy.onAllow?.({
        url: validated.url.href,
        origin: validated.url.origin,
        pinnedAddress: pinned.address,
      })

      let forwardHeaders = Object.create(null) as Record<string, string>
      for (const [k, v] of Object.entries(parseRawHeadersNullProto(req.rawHeaders))) {
        if (v === undefined) continue
        const lower = k.toLowerCase()
        if (HOP_BY_HOP_HEADERS.has(lower) || RESERVED_PROTO_HEADER_KEYS.has(lower)) continue
        forwardHeaders[lower] = Array.isArray(v) ? v.join(', ') : v
      }
      forwardHeaders.host = validated.url.host
      if (state.transformRequestHeaders) {
        forwardHeaders = state.transformRequestHeaders(validated.url, forwardHeaders)
      }

      const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
      const maxResponseBytes = Math.max(1024, policy.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
      const requestFn = validated.url.protocol === 'https:' ? httpsRequest : httpRequest
      const upstream = requestFn({
        protocol: validated.url.protocol,
        hostname: validated.hostname,
        port: validated.url.port || undefined,
        path: `${validated.url.pathname}${validated.url.search}`,
        method,
        headers: forwardHeaders,
        agent: false,
        lookup: createPinnedLookup(validated.hostname, validated.addresses) as never,
        ...(validated.url.protocol === 'https:'
          ? {
              servername: !isIpLiteralHost(validated.hostname) ? validated.hostname : undefined,
              rejectUnauthorized: policy.rejectUnauthorized ?? true,
            }
          : {}),
      }, upRes => {
        let abortedLarge = false
        const failUpstream = () => {
          abortedLarge = true
          try { upRes.destroy() } catch { /* ignore */ }
          try { upstream.destroy() } catch { /* ignore */ }
          if (!res.headersSent) {
            writeProxyErrorResponse(res, 502, 'upstream_error', 'Upstream response failed.')
          } else if (!res.destroyed) {
            res.destroy()
          }
        }
        try {
          let respHeaders: IncomingHttpHeaders = parseRawHeadersNullProto(upRes.rawHeaders)
          const rawContentLen = respHeaders['content-length']
          const declaredLen = typeof rawContentLen === 'string' && /^\d+$/.test(rawContentLen.trim())
            ? Number(rawContentLen.trim())
            : NaN
          if (Number.isFinite(declaredLen) && declaredLen > maxResponseBytes) {
            policy.onDenied?.({
              url: validated.url.href,
              origin: validated.url.origin,
              code: 'response_too_large',
              reason: `Proxied response declared Content-Length ${declaredLen} exceeding ${maxResponseBytes}-byte limit.`,
            })
            upRes.destroy()
            writeProxyErrorResponse(
              res,
              502,
              'response_too_large',
              `Proxied response exceeded the ${maxResponseBytes}-byte limit.`,
            )
            return
          }

          for (const h of HOP_BY_HOP_HEADERS) delete respHeaders[h]
          if (state.transformResponseHeaders) {
            respHeaders = state.transformResponseHeaders(validated.url, respHeaders)
          }

          let headersFlushed = false
          let totalReceived = 0

          const flushHeaders = () => {
            if (headersFlushed || res.headersSent) return
            headersFlushed = true
            res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, respHeaders)
          }

          upRes.on('data', (chunk: Buffer) => {
            try {
              if (abortedLarge) return
              totalReceived += chunk.byteLength
              if (totalReceived > maxResponseBytes) {
                abortedLarge = true
                policy.onDenied?.({
                  url: validated.url.href,
                  origin: validated.url.origin,
                  code: 'response_too_large',
                  reason: `Proxied response exceeded the ${maxResponseBytes}-byte limit.`,
                })
                upRes.destroy()
                upstream.destroy()
                if (!res.headersSent) {
                  writeProxyErrorResponse(
                    res,
                    502,
                    'response_too_large',
                    `Proxied response exceeded the ${maxResponseBytes}-byte limit.`,
                  )
                } else {
                  res.destroy()
                }
                return
              }
              flushHeaders()
              if (!res.destroyed) {
                const ok = res.write(chunk)
                if (!ok) {
                  upRes.pause()
                  res.once('drain', () => {
                    if (!abortedLarge && !upRes.destroyed) upRes.resume()
                  })
                }
              }
            } catch {
              failUpstream()
            }
          })
          upRes.once('end', () => {
            try {
              if (abortedLarge) return
              flushHeaders()
              if (!res.destroyed) res.end()
            } catch {
              failUpstream()
            }
          })
          upRes.once('error', () => {
            if (abortedLarge) return
            if (!res.headersSent) {
              writeProxyErrorResponse(res, 502, 'upstream_error', 'Upstream response failed.')
            } else {
              res.destroy()
            }
          })
        } catch {
          failUpstream()
        }
      })

      upstream.setTimeout(timeoutMs, () => {
        upstream.destroy(new Error('Upstream proxy request timed out.'))
      })
      upstream.on('error', () => {
        if (!res.headersSent) {
          writeProxyErrorResponse(res, 502, 'upstream_error', 'Upstream connection failed.')
        } else {
          res.destroy()
        }
      })
      req.on('aborted', () => upstream.destroy())
      req.pipe(upstream)
    })()
  })

  server.on('connect', (req: IncomingMessage, clientSocket: NetSocket, head: Buffer) => {
    void (async () => {
      trackSocket(clientSocket)
      clientSocket.on('error', () => { /* handled via close cleanup */ })

      const state = authenticate(req)
      if (!state) {
        defaultState.onDenied?.({
          url: req.url ?? '',
          origin: '',
          code: 'proxy_auth_required',
          reason: 'Loopback proxy rejected unauthenticated CONNECT request.',
        })
        writeConnectError(
          clientSocket,
          407,
          'Proxy Authentication Required',
          'proxy_auth_required',
          { 'Proxy-Authenticate': 'Basic realm="Kovo-Egress-Proxy"' },
        )
        return
      }

      const parsed = parseConnectAuthority(req.url ?? '')
      if (!parsed) {
        writeConnectError(clientSocket, 400, 'Bad Request', 'invalid_url')
        return
      }

      const { egress: policy, scopePolicy } = resolveDynamicLoopbackPolicy(state)
      const allowLocalLab = Boolean(policy.allowLocalLab)

      const candidateOrigin = parsed.port === 443
        ? `https://${parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname}`
        : `https://${parsed.hostHeader}`

      const { ks, tenantId } = resolveEgressKillSwitch(policy)
      if (ks.isActive(tenantId)) {
        policy.onDenied?.({
          url: candidateOrigin,
          origin: candidateOrigin,
          code: 'kill_switch_active',
          reason: `Kill switch active for ${tenantId ? `tenant "${tenantId}"` : 'global'} scope.`,
        })
        writeConnectError(clientSocket, 403, 'Forbidden', 'kill_switch_active')
        return
      }

      if (state.allowConnectPort) {
        if (!state.allowConnectPort(parsed.port, parsed.hostname)) {
          policy.onDenied?.({
            url: candidateOrigin,
            origin: candidateOrigin,
            code: 'proxy_connect_denied',
            reason: `CONNECT port ${parsed.port} is not permitted.`,
          })
          writeConnectError(clientSocket, 403, 'Forbidden', 'proxy_connect_denied')
          return
        }
      } else if (!allowLocalLab) {
        const defaultPorts = collectAllowedPortsFromPolicy(policy, scopePolicy)
        if (!defaultPorts.has(parsed.port)) {
          policy.onDenied?.({
            url: candidateOrigin,
            origin: candidateOrigin,
            code: 'proxy_connect_denied',
            reason: `CONNECT port ${parsed.port} is not permitted outside local-lab.`,
          })
          writeConnectError(clientSocket, 403, 'Forbidden', 'proxy_connect_denied')
          return
        }
      }

      if (scopePolicy) {
        const checkScope = (o: string): boolean => evaluateBrowserScopeRequest(scopePolicy, {
          origin: o,
          method: 'GET',
          pathAndQuery: '/',
          redirectHop: true,
        }).allowed
        const httpsOk = checkScope(candidateOrigin)
        const httpAltOk = allowLocalLab && checkScope(candidateOrigin.replace(/^https:/i, 'http:'))
        if (!httpsOk && !httpAltOk) {
          policy.onDenied?.({
            url: candidateOrigin,
            origin: candidateOrigin,
            code: 'scope_denied',
            reason: `CONNECT origin "${candidateOrigin}" is denied by ScopePolicy.`,
          })
          writeConnectError(clientSocket, 403, 'Forbidden', 'scope_denied')
          return
        }
      }

      // In local-lab mode, Chromium may tunnel `ws://` via CONNECT to a port allowlisted as `http://`.
      const effectivePolicy: EgressPolicy = allowLocalLab && (policy.allowOrigin || policy.allowedOrigins)
        ? {
            ...policy,
            allowedOrigins: undefined,
            allowOrigin: (origin, method, url) => {
              const checkOne = (o: string): boolean => {
                // H10-egress: intersect allowedOrigins AND allowOrigin when both are set.
                if (policy.allowedOrigins !== undefined && !matchesOriginList(o, policy.allowedOrigins)) {
                  return false
                }
                if (policy.allowOrigin) {
                  const v = policy.allowOrigin(o, method, url)
                  return typeof v === 'boolean' ? v : v.allowed
                }
                return true
              }
              if (checkOne(origin)) return true
              const httpAlt = origin.replace(/^https:/i, 'http:')
              return checkOne(httpAlt)
            },
          }
        : policy

      let validated: { url: URL; hostname: string; addresses: PinnedAddress[] }
      try {
        validated = await resolveAndValidateHost(candidateOrigin, effectivePolicy, 'CONNECT')
      } catch (err) {
        const code = err instanceof EgressDeniedError ? err.code : 'proxy_connect_denied'
        writeConnectError(clientSocket, 403, 'Forbidden', code)
        return
      }

      const pinned = validated.addresses[0]!
      policy.onAllow?.({
        url: validated.url.href,
        origin: validated.url.origin,
        pinnedAddress: pinned.address,
      })

      const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
      const upstream = netConnect({
        host: pinned.address,
        port: parsed.port,
        family: pinned.family,
      })
      trackSocket(upstream)
      upstream.setTimeout(timeoutMs, () => upstream.destroy())

      let established = false
      upstream.once('connect', () => {
        established = true
        if (clientSocket.destroyed) {
          upstream.destroy()
          return
        }
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head && head.length > 0) upstream.write(head)
        upstream.pipe(clientSocket)
        clientSocket.pipe(upstream)
      })
      upstream.on('error', () => {
        if (!established) writeConnectError(clientSocket, 502, 'Bad Gateway', 'upstream_error')
        else clientSocket.destroy()
      })
      clientSocket.on('close', () => upstream.destroy())
      upstream.on('close', () => clientSocket.destroy())
    })()
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve()
    })
  })

  if (defaultState.unref !== false) {
    server.unref()
  }

  const addr = server.address() as AddressInfo
  const url = `http://127.0.0.1:${addr.port}`
  let closed = false

  return {
    url,
    host: '127.0.0.1',
    port: addr.port,
    credentials: defaultAuth.credentials,
    authorizationHeader: defaultAuth.authorizationHeader,
    proxyConfig: {
      server: url,
      username: defaultAuth.credentials.username,
      password: defaultAuth.credentials.password,
    },
    registerContextPolicy(policy: LoopbackProxyPolicy): LoopbackProxyContextBinding {
      const ctxAuth = mintLoopbackProxyCredentials()
      const ctxState: LoopbackProxyPolicy = { ...policy }
      contextPolicies.set(ctxAuth.credentials.username, { credentials: ctxAuth.credentials, state: ctxState })
      return {
        credentials: ctxAuth.credentials,
        authorizationHeader: ctxAuth.authorizationHeader,
        proxyConfig: {
          server: url,
          username: ctxAuth.credentials.username,
          password: ctxAuth.credentials.password,
        },
        updatePolicy(patch: Partial<LoopbackProxyPolicy>): void {
          Object.assign(ctxState, patch)
        },
        unregister(): void {
          contextPolicies.delete(ctxAuth.credentials.username)
        },
      }
    },
    updatePolicy(patch: Partial<LoopbackProxyPolicy>): void {
      Object.assign(defaultState, patch)
    },
    async close(): Promise<void> {
      if (closed) return
      closed = true
      contextPolicies.clear()
      for (const socket of activeSockets) {
        try { socket.destroy() } catch { /* ignore */ }
      }
      activeSockets.clear()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

// ---------------------------------------------------------------------------
// Unified Namespace Export
// ---------------------------------------------------------------------------

export const EgressGateway = {
  egressFetch,
  egressFetchStream,
  egressRawHttp1,
  egressHttp2,
  createLoopbackProxy,
  resolveAndValidateHost,
  createPinnedLookup,
  defaultResolveHost,
  classifyAddress,
  classifyDetailedAddress,
  isPublicIpAddress,
  isLoopbackLiteral,
  isMetadataOrLinkLocalAddress,
  warnIfEnvProxyEnabled,
} as const
