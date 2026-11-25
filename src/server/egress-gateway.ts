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
import { lookup as dnsLookup } from 'node:dns/promises'
import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import type { IncomingHttpHeaders, IncomingMessage, Server as HttpServer, ServerResponse } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as http2Connect, constants as http2Constants } from 'node:http2'
import type { ClientHttp2Session } from 'node:http2'
import { connect as netConnect } from 'node:net'
import type { AddressInfo, Socket as NetSocket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import type { Duplex } from 'node:stream'
import ipaddr from 'ipaddr.js'
import { isIpLiteralHost, normalizeHostname } from './public-suffix.ts'

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

export interface EgressLoopbackProxy {
  readonly url: string
  readonly host: '127.0.0.1'
  readonly port: number
  readonly proxyConfig: { server: string }
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

  if (policy.allowedOrigins !== undefined && !exactOriginAllowed && !policy.allowOrigin) {
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

function responseHeadersFromNode(raw: IncomingHttpHeaders): Headers {
  const headers = new Headers()
  for (const [key, value] of Object.entries(raw)) {
    if (value === undefined) continue
    if (Array.isArray(value)) {
      for (const entry of value) headers.append(key, entry)
    } else {
      headers.set(key, value)
    }
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
      const chunks: Buffer[] = []
      let total = 0
      res.on('data', (chunk: Buffer) => {
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
      })
      res.on('end', () => {
        const status = res.statusCode ?? 0
        const responseBody = status === 204 || status === 304 ? null : Buffer.concat(chunks)
        finish(null, new Response(responseBody, {
          status,
          statusText: res.statusMessage ?? '',
          headers: responseHeadersFromNode(res.headers),
        }))
      })
      res.on('error', err => finish(err))
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

  const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
  const maxResponseBytes = Math.max(1024, policy.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES)
  const rejectUnauthorized = policy.rejectUnauthorized ?? true
  const followRedirects = Boolean(policy.followRedirects && init.redirect !== 'manual')
  const maxRedirects = Math.max(0, Math.min(policy.maxRedirects ?? DEFAULT_MAX_REDIRECTS, HARD_MAX_REDIRECTS))

  let currentUrl = urlInput instanceof URL ? urlInput.toString() : urlInput
  let method = (init.method ?? 'GET').toUpperCase()
  let headers = headersToRecord(init.headers)
  let body = await normalizeRequestBody(init.body)
  const signal = init.signal ?? undefined

  for (let hop = 0; ; hop += 1) {
    // Only the initial hop may use caller-supplied `pinnedAddresses`; redirect hops MUST resolve fresh.
    const hopPolicy: EgressPolicy = hop === 0
      ? policy
      : { ...policy, pinnedAddresses: undefined }
    const validated = await resolveAndValidateHost(currentUrl, hopPolicy, method)
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
      signal,
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
}

// ---------------------------------------------------------------------------
// 2. Canonical HTTP/2 Outbound Dialer (`egressHttp2`)
// ---------------------------------------------------------------------------

/**
 * Pinned-IP HTTP/2 request helper (ready for `verify-rpc.ts` / `broker.ts` adoption).
 * Resolves DNS once, validates all IPs, and dials the pinned IP directly via `createConnection`
 * with TLS SNI (`servername`) and `:authority` preserved.
 */
export async function egressHttp2(
  urlInput: string | URL,
  init: EgressHttp2Init = {},
  policy: EgressPolicy = {},
): Promise<EgressHttp2Response> {
  warnIfEnvProxyEnabled()

  const method = (init.method ?? 'GET').toUpperCase()
  const validated = await resolveAndValidateHost(urlInput, policy, method)
  const pinned = validated.addresses[0]!
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

  const reqHeaders: Record<string, string> = {}
  for (const [k, v] of Object.entries(init.headers ?? {})) {
    if (k.trimStart().startsWith(':')) continue
    reqHeaders[k.toLowerCase()] = v
  }
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

  const started = Date.now()
  const client: ClientHttp2Session = http2Connect(validated.url.origin, {
    createConnection: () => {
      const tcpSocket = netConnect({
        host: pinned.address,
        port,
        family: pinned.family,
      })
      if (isHttps) {
        return tlsConnect({
          socket: tcpSocket,
          servername: !isIpLiteralHost(validated.hostname) ? validated.hostname : undefined,
          ALPNProtocols: ['h2'],
          rejectUnauthorized,
        })
      }
      return tcpSocket
    },
  })

  try {
    init.signal?.throwIfAborted()
    return await new Promise<EgressHttp2Response>((resolve, reject) => {
      let settled = false
      const timer = setTimeout(() => {
        const err = new Error(`HTTP/2 egress request timed out after ${timeoutMs}ms.`)
        client.destroy(err)
        finish(err)
      }, timeoutMs)
      timer.unref?.()

      const finish = (err: unknown, result?: EgressHttp2Response) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        init.signal?.removeEventListener('abort', onAbort)
        if (err) reject(err)
        else resolve(result!)
      }

      const onAbort = () => {
        const reason = init.signal?.reason instanceof Error ? init.signal.reason : new Error('HTTP/2 egress request aborted.')
        client.destroy(reason)
        finish(reason)
      }
      init.signal?.addEventListener('abort', onAbort, { once: true })
      client.once('error', err => finish(err))

      const stream = client.request({
        ...reqHeaders,
        ':method': method,
        ':path': `${validated.url.pathname}${validated.url.search}`,
        ':authority': validated.url.host,
        ':scheme': isHttps ? 'https' : 'http',
      })

      let status = 0
      const rawHeaders: Record<string, string> = {}
      const chunks: Buffer[] = []
      let captured = 0
      let truncated = false

      stream.on('response', value => {
        status = Number(value[':status'] ?? 0)
        for (const [k, v] of Object.entries(value)) {
          if (k.startsWith(':') || v === undefined) continue
          rawHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v)
        }
      })
      stream.on('data', (chunk: Buffer) => {
        captured += chunk.length
        if (captured > maxResponseBytes) {
          truncated = true
          stream.close(http2Constants.NGHTTP2_CANCEL)
          finish(new EgressDeniedError(
            'response_too_large',
            `HTTP/2 egress response exceeded the ${maxResponseBytes}-byte limit.`,
          ))
          return
        }
        chunks.push(chunk)
      })
      stream.once('error', err => finish(err))
      stream.once('end', () => {
        const body = Buffer.concat(chunks).toString('utf8')
        finish(null, {
          status,
          headers: { ...rawHeaders },
          rawHeaders,
          body,
          bodyBytes: captured,
          bodyTruncated: truncated,
          pinnedAddress: pinned.address,
          durationMs: Date.now() - started,
        })
      })
      stream.end(bodyBuf)
    })
  } finally {
    try { client.close() } catch { /* ignore */ }
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

function writeProxyErrorResponse(res: ServerResponse, status: number, code: string, message: string): void {
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'x-kovo-egress-denied': code,
    connection: 'close',
  })
  res.end(message)
}

function writeConnectError(socket: Duplex, status: number, statusText: string, code: string): void {
  if (socket.destroyed || !socket.writable) return
  try {
    socket.end(
      `HTTP/1.1 ${status} ${statusText}\r\n` +
      `X-Kovo-Egress-Denied: ${code}\r\n` +
      'Connection: close\r\n\r\n',
    )
  } catch {
    socket.destroy()
  }
}

function resolveDynamicLoopbackPolicy(state: LoopbackProxyPolicy): EgressPolicy {
  const allowLocalLab = typeof state.allowLocalLab === 'function' ? state.allowLocalLab() : Boolean(state.allowLocalLab)
  const allowedOrigins = typeof state.allowedOrigins === 'function' ? state.allowedOrigins() : state.allowedOrigins
  return {
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
  }
}

/**
 * Lightweight host-loopback (`127.0.0.1:0`) HTTP + HTTPS `CONNECT` proxy for Chromium contexts.
 * Every plain HTTP request and every CONNECT tunnel passes through `resolveAndValidateHost` and
 * dials ONLY the validated pinned IP, enforcing SSRF, cloud-metadata, denylist, and scope rules.
 */
export async function createLoopbackProxy(initialPolicy: LoopbackProxyPolicy = {}): Promise<EgressLoopbackProxy> {
  const state: LoopbackProxyPolicy = { ...initialPolicy }
  const activeSockets = new Set<Duplex>()

  const trackSocket = (socket: Duplex) => {
    activeSockets.add(socket)
    socket.once('close', () => activeSockets.delete(socket))
  }

  const server: HttpServer = createHttpServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      if (req.socket) trackSocket(req.socket)
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
      const policy = resolveDynamicLoopbackPolicy(state)

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

      let forwardHeaders: Record<string, string> = {}
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue
        const lower = k.toLowerCase()
        if (HOP_BY_HOP_HEADERS.has(lower)) continue
        forwardHeaders[lower] = Array.isArray(v) ? v.join(', ') : v
      }
      forwardHeaders.host = validated.url.host
      if (state.transformRequestHeaders) {
        forwardHeaders = state.transformRequestHeaders(validated.url, forwardHeaders)
      }

      const timeoutMs = Math.max(250, policy.timeoutMs ?? DEFAULT_TIMEOUT_MS)
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
        let respHeaders: IncomingHttpHeaders = { ...upRes.headers }
        for (const h of HOP_BY_HOP_HEADERS) delete respHeaders[h]
        if (state.transformResponseHeaders) {
          respHeaders = state.transformResponseHeaders(validated.url, respHeaders)
        }
        res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, respHeaders)
        upRes.pipe(res)
      })

      upstream.setTimeout(timeoutMs, () => {
        upstream.destroy(new Error('Upstream proxy request timed out.'))
      })
      upstream.on('error', () => {
        writeProxyErrorResponse(res, 502, 'upstream_error', 'Upstream connection failed.')
      })
      req.on('aborted', () => upstream.destroy())
      req.pipe(upstream)
    })()
  })

  server.on('connect', (req: IncomingMessage, clientSocket: NetSocket, head: Buffer) => {
    void (async () => {
      trackSocket(clientSocket)
      clientSocket.on('error', () => { /* handled via close cleanup */ })

      const parsed = parseConnectAuthority(req.url ?? '')
      if (!parsed) {
        writeConnectError(clientSocket, 400, 'Bad Request', 'invalid_url')
        return
      }

      const policy = resolveDynamicLoopbackPolicy(state)
      const allowLocalLab = Boolean(policy.allowLocalLab)

      if (state.allowConnectPort && !state.allowConnectPort(parsed.port, parsed.hostname)) {
        policy.onDenied?.({
          url: `https://${parsed.hostHeader}`,
          origin: `https://${parsed.hostHeader}`,
          code: 'proxy_connect_denied',
          reason: `CONNECT port ${parsed.port} is not permitted.`,
        })
        writeConnectError(clientSocket, 403, 'Forbidden', 'proxy_connect_denied')
        return
      }

      // In local-lab mode, Chromium may tunnel `ws://` via CONNECT to a port allowlisted as `http://`.
      const candidateOrigin = parsed.port === 443
        ? `https://${parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname}`
        : `https://${parsed.hostHeader}`
      const effectivePolicy: EgressPolicy = allowLocalLab && (policy.allowOrigin || policy.allowedOrigins)
        ? {
            ...policy,
            allowedOrigins: undefined,
            allowOrigin: (origin, method, url) => {
              const checkOne = (o: string): boolean => {
                if (policy.allowOrigin) {
                  const v = policy.allowOrigin(o, method, url)
                  return typeof v === 'boolean' ? v : v.allowed
                }
                return matchesOriginList(o, policy.allowedOrigins)
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

  if (state.unref !== false) {
    server.unref()
  }

  const addr = server.address() as AddressInfo
  const url = `http://127.0.0.1:${addr.port}`
  let closed = false

  return {
    url,
    host: '127.0.0.1',
    port: addr.port,
    proxyConfig: { server: url },
    updatePolicy(patch: Partial<LoopbackProxyPolicy>): void {
      Object.assign(state, patch)
    },
    async close(): Promise<void> {
      if (closed) return
      closed = true
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
