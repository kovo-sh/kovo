/**
 * HostFactLog — Dual-Plane Immutable Host Custody Log (Option 2, Move 1).
 *
 * Plane 1 (Host Kernel Truth):
 *   Every brokered HTTP/HTTP2/race exchange, OOB callback, browser trace, and async poll
 *   is recorded once as a deeply frozen `HostExchangeFact` carrying pre-redaction request
 *   and response payloads, host-assigned monotonic `seq`, and host-resolved actor/tenant/
 *   ambient-auth/SameSite metadata. Oracles and verification kernels have strictly read-only
 *   access (`getExchange`, `orderedExchanges`) and never mutate stored facts.
 *
 * Plane 2 (Worker Egress View):
 *   Worker-facing projections (`buildWorkerView`) are derived lazily through `EgressSanitizer`
 *   without ever calling `rescrubBodies()` or mutating the host fact plane.
 */
import { createHash, createHmac } from 'node:crypto'
import { createEgressSanitizer, EgressSanitizer, type EgressChannel } from './egress-sanitizer.ts'
import { normalizeRole, parseRoleLabel, type AmbientAuth, type ImpactStep, type RoleName } from './oracle-invariants.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, WireCredentialProvenance } from './broker.ts'
export type { WireCredentialProvenance } from './broker.ts'

declare module './proof-receipt.ts' {
  interface ReceiptTranscriptEntry {
    /** H-14: Broker-observed non-secret wire credential provenance (header/cookie names & auth sources). */
    wireCredentialProvenance?: Readonly<WireCredentialProvenance>
  }
}
import type {
  HostAsyncPollRecord,
  HostBrowserTrace,
  HostCryptoAttestation,
  HostOobEvent,
  HostSignedTranscript,
  HostTranscriptEntry,
} from './composite-receipt.ts'
import type {
  HostMintedExpressionChallenge,
  HostMintedTimingChallenge,
  ReceiptBrowserTrace,
  ReceiptOobEvent,
  ReceiptTranscript,
  ReceiptTranscriptEntry,
  ScriptProofExchange,
} from './proof-receipt.ts'
import type { TranscriptStore, VerifyTranscriptRecord } from './verify-claims.ts'

/** R2-C-9: Vault-scrubbed capability placeholder pattern that MUST NEVER appear in the kernel request plane. */
export const VAULT_SCRUBBED_TOKEN_RE = /\[redacted:cap:[^\]]*\]/i

export function hasVaultScrubbedToken(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.length > 0 && VAULT_SCRUBBED_TOKEN_RE.test(value)
}

export function hasVaultScrubbedRequestPlane(input: {
  pathAndQuery?: string | null
  requestHeaders?: Readonly<Record<string, string>> | null
  rawRequestBody?: string | null
  carrierText?: string | null
}): boolean {
  if (hasVaultScrubbedToken(input.pathAndQuery)) return true
  if (hasVaultScrubbedToken(input.rawRequestBody)) return true
  if (hasVaultScrubbedToken(input.carrierText)) return true
  if (input.requestHeaders) {
    for (const [k, v] of Object.entries(input.requestHeaders)) {
      if (hasVaultScrubbedToken(k) || hasVaultScrubbedToken(v)) return true
    }
  }
  return false
}

export function assertCleanKernelRequestPlane(
  input: {
    exchangeId?: string
    pathAndQuery?: string | null
    requestHeaders?: Readonly<Record<string, string>> | null
    rawRequestBody?: string | null
    carrierText?: string | null
  },
  context = 'HostFactLog',
): void {
  if (hasVaultScrubbedRequestPlane(input)) {
    throw new Error(
      `${context}: kernel request plane${input.exchangeId ? ` for exchange "${input.exchangeId}"` : ''} contains a vault-scrubbed [redacted:cap:...] token; kernel truth must remain pre-redaction.`,
    )
  }
}

/** C-5: Reserved host-owned evidence roles that workers MUST NOT supply directly. */
export const RESERVED_EVIDENCE_ROLES: ReadonlySet<string> = new Set([
  'baseline_read',
  'pre_read',
  'baseline_balance',
  'balance_before',
  'pre_burst_read',
  'post_read',
  'post_burst_read',
  'after_read',
  'balance_after',
  'serial_pre_read',
  'serial_baseline_read',
  'serial_before_read',
  'serial_post_read',
  'serial_after_read',
  'serial_read',
  'serial_balance_after',
  'post_chain_readback',
  'host_capability_op',
  'host_crypto_op',
])

const RESERVED_BURST_OR_SERIAL_ROLE_RE = /^(?:(?:burst|race_burst|concurrent)(?:[_-].*)?|serial(?:_(?:control|mutation|probe|step|request|debit))?(?:_\d+)?)$/i

export function isReservedEvidenceRole(role: string | null | undefined): boolean {
  if (typeof role !== 'string') return false
  const normalized = role.trim().toLowerCase()
  if (!normalized) return false
  return RESERVED_EVIDENCE_ROLES.has(normalized) || RESERVED_BURST_OR_SERIAL_ROLE_RE.test(normalized)
}

/**
 * H-13: Host-only wire credential placement provenance.
 * Records where the host/broker actually attached credentials on the wire (persona auth kind,
 * capability injection targets, session jar cookie names, header names, and mixed-auth status)
 * so ambient auth and SameSite binding are never spoofed by a junk cookie capability on a bearer API.
 */
export interface HostCredentialPlacement {
  readonly personaAuthKind?: 'cookie' | 'bearer' | 'header' | 'none' | null
  readonly capabilityTargets?: readonly ('cookie' | 'bearer' | 'header' | 'query' | 'body')[]
  readonly jarCookieNames?: readonly string[]
  readonly headerNames?: readonly string[]
  readonly authenticatingCookieName?: string | null
  readonly mixed?: boolean
}

export interface HostOobCallbackFact {
  readonly id: string
  readonly callbackId?: string
  readonly canaryId?: string
  readonly token?: string
  readonly targetOrigin?: string | null
  readonly delivered: boolean
  readonly stage?: 'immediate' | 'late'
  readonly receivedAtMs: number
  readonly injectedAtMs?: number
  readonly latencyMs?: number
  readonly emittedCapabilities?: readonly string[]
  readonly observedValueDigests?: readonly string[]
  readonly correlationIds?: readonly string[]
  readonly hostSignature?: string
  readonly callbackSignature?: string
}

export interface HostExchangeFact {
  readonly seq: number
  readonly exchangeId: string
  readonly op?: string
  readonly method: string
  readonly url: string
  readonly origin: string
  readonly pathAndQuery: string
  readonly status: number | null
  readonly requestHeaders: Readonly<Record<string, string>>
  readonly rawRequestBody: string | null
  readonly responseHeaders: Readonly<Record<string, string>>
  readonly rawResponseBody: string | null
  readonly actor: string | null
  readonly actorRole: RoleName | null
  readonly actorRoleLabel?: string | null
  readonly actorTenant: string | null
  readonly ambientAuth: AmbientAuth
  readonly sameSite: string | null
  readonly credentialPlacement?: HostCredentialPlacement
  /** H-14: Broker-observed wire credential provenance (header/cookie names & auth sources, never secret values). */
  readonly wireCredentialProvenance?: Readonly<WireCredentialProvenance>
  readonly setCookieSameSiteByName?: Readonly<Record<string, string | null>>
  readonly raceBatchId?: string | null
  readonly requestPlaneVaultScrubbed?: boolean
  readonly hostExpressionChallenge?: HostMintedExpressionChallenge
  readonly hostTimingChallenge?: HostMintedTimingChallenge
  readonly hostRedirectCanaryHost?: string | null
  readonly oobCallbacks: readonly HostOobCallbackFact[]
  readonly durationMs: number
  readonly startedAt?: number
  readonly endedAt?: number
  readonly timestampMs?: number
  readonly arm?: ImpactStep['arm']
  readonly sessionRole?: string | null
  readonly evidenceRole?: string
  readonly sessionId?: string | null
  readonly consumedCapabilityId?: string | null
  readonly consumedCapabilities?: readonly string[]
  readonly emittedCapabilities?: readonly string[]
  readonly observedResponseDigests?: readonly string[]
  readonly injectedRequestDigests?: readonly string[]
  readonly cryptoAttestations?: readonly HostCryptoAttestation[]
  readonly entityId?: string
  readonly correlationIds?: readonly string[]
  readonly cleanSession?: boolean
  readonly replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
  readonly hostSignature?: string
  readonly carrierText?: string
  readonly secretMatches?: readonly string[]
  readonly artifact?: ScriptProofExchange['artifact']
}

export interface HostExchangeFactInput {
  seq?: number
  exchangeId: string
  op?: string
  method: string
  url?: string
  origin: string
  pathAndQuery: string
  status: number | null
  requestHeaders?: Readonly<Record<string, string>> | null
  rawRequestBody?: string | null
  responseHeaders?: Readonly<Record<string, string>> | null
  rawResponseBody?: string | null
  actor?: string | null
  actorRole?: RoleName | null
  actorRoleLabel?: string | null
  actorTenant?: string | null
  ambientAuth?: AmbientAuth
  sameSite?: string | null
  credentialPlacement?: HostCredentialPlacement
  wireCredentialProvenance?: WireCredentialProvenance
  raceBatchId?: string | null
  hostExpressionChallenge?: HostMintedExpressionChallenge
  hostTimingChallenge?: HostMintedTimingChallenge
  hostRedirectCanaryHost?: string | null
  oobCallbacks?: readonly HostOobCallbackFact[]
  durationMs?: number
  startedAt?: number
  endedAt?: number
  timestampMs?: number
  arm?: ImpactStep['arm']
  sessionRole?: string | null
  evidenceRole?: string
  sessionId?: string | null
  consumedCapabilityId?: string | null
  consumedCapabilities?: readonly string[]
  emittedCapabilities?: readonly string[]
  observedResponseDigests?: readonly string[]
  injectedRequestDigests?: readonly string[]
  cryptoAttestations?: readonly HostCryptoAttestation[]
  entityId?: string
  correlationIds?: readonly string[]
  cleanSession?: boolean
  replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
  hostSignature?: string
  carrierText?: string
  secretMatches?: readonly string[]
  artifact?: ScriptProofExchange['artifact']
}

export interface WorkerExchangeView {
  readonly seq: number
  readonly exchangeId: string
  readonly op?: string
  readonly method: string
  readonly url: string
  readonly origin: string
  readonly pathAndQuery: string
  readonly status: number | null
  readonly requestHeaders: Readonly<Record<string, string>>
  readonly requestBody: string | null
  readonly responseHeaders: Readonly<Record<string, string>>
  readonly responseBody: string | null
  readonly actor: string | null
  readonly actorRole: RoleName | null
  readonly actorTenant: string | null
  readonly durationMs: number
}

export interface HostFactLogOptions {
  sanitizer?: EgressSanitizer
  /** R2-C-9: When true, `recordExchange` throws if the kernel request plane contains `[redacted:cap:...]`. */
  assertCleanRequestPlane?: boolean
  /** H-14: Optional HMAC-SHA256 signing key used to sign host fact entries (including `wireCredentialProvenance`). */
  signingKey?: string
}

function canonicalStringifyForSign(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalStringifyForSign).join(',')}]`
  return `{${Object.entries(value as Record<string, unknown>)
    .filter(([k, v]) => k !== 'hostSignature' && v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalStringifyForSign(v)}`)
    .join(',')}}`
}

function signHostTranscriptEntry(entry: HostTranscriptEntry, signingKey: string): string {
  return createHmac('sha256', signingKey).update(canonicalStringifyForSign(entry), 'utf8').digest('hex')
}

function freezeWireCredentialProvenance(
  prov: WireCredentialProvenance | undefined,
): Readonly<WireCredentialProvenance> | undefined {
  if (!prov) return undefined
  return Object.freeze({
    authenticated: Boolean(prov.authenticated),
    source: prov.source,
    sources: Object.freeze([...prov.sources]) as WireCredentialProvenance['sources'],
    personaHandle: prov.personaHandle ?? null,
    session: prov.session ?? null,
    headerNames: Object.freeze([...prov.headerNames]) as string[],
    cookieNames: Object.freeze([...prov.cookieNames]) as string[],
    vaultCookieNames: Object.freeze([...prov.vaultCookieNames]) as string[],
    jarCookieNames: Object.freeze([...prov.jarCookieNames]) as string[],
    vaultHeaderNames: Object.freeze([...prov.vaultHeaderNames]) as string[],
    callerAuthHeaderNames: Object.freeze([...prov.callerAuthHeaderNames]) as string[],
    authMutated: Boolean(prov.authMutated),
  })
}

function headerLookup(headers: Readonly<Record<string, string>> | null | undefined, name: string): string | null {
  if (!headers) return null
  const wanted = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === wanted && typeof v === 'string' && v.length > 0) return v
  }
  return null
}

function freezeHeaderMap(headers: Readonly<Record<string, string>> | null | undefined): Readonly<Record<string, string>> {
  const copy: Record<string, string> = {}
  if (headers) {
    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === 'string') copy[k] = v
    }
  }
  return Object.freeze(copy)
}

function freezeStringList(values: readonly string[] | undefined): readonly string[] | undefined {
  if (!values) return undefined
  return Object.freeze([...values])
}

function freezeHostEntry(entry: HostTranscriptEntry): HostTranscriptEntry {
  const freeze = (value: unknown): unknown => {
    if (Array.isArray(value)) return Object.freeze(value.map(freeze))
    if (value && typeof value === 'object') {
      for (const child of Object.values(value as Record<string, unknown>)) freeze(child)
      return Object.freeze(value)
    }
    return value
  }
  return freeze(entry) as HostTranscriptEntry
}

function freezeOobFact(ev: HostOobCallbackFact): HostOobCallbackFact {
  return Object.freeze({
    ...ev,
    ...(ev.emittedCapabilities ? { emittedCapabilities: Object.freeze([...ev.emittedCapabilities]) } : {}),
    ...(ev.observedValueDigests ? { observedValueDigests: Object.freeze([...ev.observedValueDigests]) } : {}),
    ...(ev.correlationIds ? { correlationIds: Object.freeze([...ev.correlationIds]) } : {}),
  })
}

function normalizeOriginKey(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase()
  }
}

const AUTH_COOKIE_NAME_RE = /(?:^|[._-])(?:sid|sess|session|sessionid|auth|token|jwt|access|identity|connect\.sid|jsessionid|phpsessid|asp\.net_sessionid)(?:$|[._-])/i
const NON_AUTH_COOKIE_NAME_RE = /^(?:theme|locale|lang|tz|timezone|prefs?|ab_?test|ga|_ga|_gid|csrftoken|csrf[_-]?token|xsrf[_-]?token|_csrf)$/i

export function parseCookieHeaderNames(cookieHeader: string | null | undefined): string[] {
  if (!cookieHeader) return []
  const names: string[] = []
  const seen = new Set<string>()
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    const name = part.slice(0, eq).trim()
    const key = name.toLowerCase()
    if (!name || seen.has(key)) continue
    seen.add(key)
    names.push(name)
  }
  return names
}

function pickAuthenticatingCookieName(
  cookieNames: readonly string[],
  explicitName?: string | null,
): string | null {
  if (explicitName && explicitName.trim()) return explicitName.trim()
  if (cookieNames.length === 0) return null
  const authLike = cookieNames.find(name => AUTH_COOKIE_NAME_RE.test(name))
  if (authLike) return authLike
  const nonCosmetic = cookieNames.find(name => !NON_AUTH_COOKIE_NAME_RE.test(name))
  return nonCosmetic ?? cookieNames[0] ?? null
}

/**
 * H-13: Parse every cookie entry from a `Set-Cookie` header into a lowercase cookie-name ->
 * normalized SameSite (`'Strict' | 'Lax' | 'None' | null`) map without splitting `Expires=` dates.
 */
export function parseSetCookieSameSiteMap(
  headers: Readonly<Record<string, string>> | null | undefined,
): Record<string, string | null> {
  const map: Record<string, string | null> = {}
  if (!headers) return map
  const rawValues: string[] = []
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'set-cookie' && typeof v === 'string' && v.trim()) {
      rawValues.push(v)
    }
  }
  if (rawValues.length === 0) return map
  // Split multiple Set-Cookie entries joined by `\n` or `, ` (never breaking `Expires=Mon, 01 Jan ...`).
  const entries: string[] = []
  for (const raw of rawValues) {
    for (const line of raw.split(/\r?\n/)) {
      const parts = line.split(/,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/)
      for (const part of parts) {
        const trimmed = part.trim()
        if (trimmed) entries.push(trimmed)
      }
    }
  }
  for (const entry of entries) {
    const firstSemi = entry.indexOf(';')
    const nameVal = firstSemi >= 0 ? entry.slice(0, firstSemi) : entry
    const eq = nameVal.indexOf('=')
    if (eq <= 0) continue
    const cookieName = nameVal.slice(0, eq).trim().toLowerCase()
    if (!cookieName) continue
    const attrs = firstSemi >= 0 ? entry.slice(firstSemi + 1) : ''
    const m = /(?:^|;)\s*samesite\s*=\s*(strict|lax|none)\b/i.exec(attrs)
    if (!m?.[1]) {
      map[cookieName] = null
    } else {
      const lower = m[1].toLowerCase()
      map[cookieName] = lower === 'strict' ? 'Strict' : lower === 'lax' ? 'Lax' : 'None'
    }
  }
  return map
}

export function deriveCredentialPlacement(
  headers: Readonly<Record<string, string>> | null | undefined,
  explicit?: HostCredentialPlacement,
  wireProvenance?: Readonly<WireCredentialProvenance>,
): HostCredentialPlacement {
  const authHeader = headerLookup(headers, 'authorization')
  const apiKeyHeader = headerLookup(headers, 'x-api-key')
  const authTokenHeader = headerLookup(headers, 'x-auth-token')
  const cookieHeader = headerLookup(headers, 'cookie')
  const cookieNamesFromHeader = parseCookieHeaderNames(cookieHeader)
  const headerNamesFromHeaders = [
    ...(authHeader ? ['authorization'] : []),
    ...(apiKeyHeader ? ['x-api-key'] : []),
    ...(authTokenHeader ? ['x-auth-token'] : []),
  ]
  const useWireFallback = !explicit && headerNamesFromHeaders.length === 0 && cookieNamesFromHeader.length === 0 && Boolean(wireProvenance)
  const wireCookieNames = useWireFallback ? (wireProvenance?.cookieNames ?? []) : []
  const wireNonCookieAuthHeaders = useWireFallback
    ? (wireProvenance?.headerNames ?? []).filter(
        h => h !== 'cookie' && h !== 'x-csrf-token' && h !== 'x-xsrf-token',
      )
    : []
  const jarCookieNames = explicit?.jarCookieNames?.length
    ? [...explicit.jarCookieNames]
    : cookieNamesFromHeader.length > 0
      ? cookieNamesFromHeader
      : [...wireCookieNames]
  const headerNames = explicit?.headerNames?.length
    ? [...explicit.headerNames]
    : headerNamesFromHeaders.length > 0
      ? headerNamesFromHeaders
      : [...wireNonCookieAuthHeaders]
  const capTargets = explicit?.capabilityTargets ? [...explicit.capabilityTargets] : []

  const hasBearer = explicit?.personaAuthKind === 'bearer'
    || capTargets.includes('bearer')
    || Boolean(authHeader && /^bearer\s+/i.test(authHeader))
  const hasHeaderAuth = explicit?.personaAuthKind === 'header'
    || capTargets.includes('header')
    || Boolean(apiKeyHeader || authTokenHeader || (authHeader && !/^bearer\s+/i.test(authHeader)))
    || wireNonCookieAuthHeaders.length > 0
  const hasCookie = explicit?.personaAuthKind === 'cookie'
    || capTargets.includes('cookie')
    || jarCookieNames.length > 0
    || Boolean(cookieHeader)

  const mixed = explicit?.mixed === true || ((hasBearer || hasHeaderAuth) && hasCookie)
  const personaAuthKind: HostCredentialPlacement['personaAuthKind'] = explicit?.personaAuthKind !== undefined
    ? explicit.personaAuthKind
    : hasBearer
      ? 'bearer'
      : hasHeaderAuth
        ? 'header'
        : hasCookie
          ? 'cookie'
          : 'none'
  const authenticatingCookieName = hasCookie && !mixed
    ? pickAuthenticatingCookieName(jarCookieNames, explicit?.authenticatingCookieName)
    : (explicit?.authenticatingCookieName ?? null)

  return Object.freeze({
    personaAuthKind,
    ...(capTargets.length > 0 ? { capabilityTargets: Object.freeze(capTargets) } : {}),
    ...(jarCookieNames.length > 0 ? { jarCookieNames: Object.freeze(jarCookieNames) } : {}),
    ...(headerNames.length > 0 ? { headerNames: Object.freeze(headerNames) } : {}),
    ...(authenticatingCookieName ? { authenticatingCookieName } : {}),
    mixed,
  })
}

export function deriveAmbientAuthFromHeaders(
  headers: Readonly<Record<string, string>> | null | undefined,
  explicit?: AmbientAuth,
  placement?: HostCredentialPlacement,
): AmbientAuth {
  if (placement) {
    // H-13: Mixed auth (e.g. bearer persona + junk cookie capability) MUST NEVER classify as `cookie`.
    if (placement.mixed) {
      if (placement.personaAuthKind === 'bearer' || placement.capabilityTargets?.includes('bearer') || explicit === 'bearer') return 'bearer'
      const auth = headerLookup(headers, 'authorization')
      if (auth && /^bearer\s+/i.test(auth)) return 'bearer'
      return 'header'
    }
    if (placement.personaAuthKind === 'bearer' || placement.capabilityTargets?.includes('bearer')) return 'bearer'
    if (placement.personaAuthKind === 'header' || placement.capabilityTargets?.includes('header')) {
      return explicit === 'bearer' ? 'bearer' : 'header'
    }
    if (placement.personaAuthKind === 'cookie') return 'cookie'
  }
  if (headers) {
    const auth = headerLookup(headers, 'authorization')
    const xApiKey = headerLookup(headers, 'x-api-key')
    const xAuthToken = headerLookup(headers, 'x-auth-token')
    const cookie = headerLookup(headers, 'cookie')
    if (auth) return /^bearer\s+/i.test(auth) ? 'bearer' : 'header'
    if (xApiKey || xAuthToken) return 'header'
    if (cookie) return 'cookie'
  }
  if (explicit && explicit !== 'unknown') return explicit
  return 'unknown'
}

export function extractSameSiteFromHeaders(
  headers: Readonly<Record<string, string>> | null | undefined,
  authenticatingCookieName?: string | null,
): string | null {
  const byName = parseSetCookieSameSiteMap(headers)
  const keys = Object.keys(byName)
  if (keys.length === 0) return null
  if (authenticatingCookieName && authenticatingCookieName.trim()) {
    const key = authenticatingCookieName.trim().toLowerCase()
    if (key in byName) {
      return byName[key] ?? 'Lax'
    }
    return null
  }
  // Prefer an auth-like cookie if multiple Set-Cookie entries exist; never let a cosmetic cookie win.
  const authKey = keys.find(k => AUTH_COOKIE_NAME_RE.test(k))
    ?? keys.find(k => !NON_AUTH_COOKIE_NAME_RE.test(k))
    ?? keys[0]!
  return byName[authKey] ?? null
}

function safeJsonParse(raw: string | null | undefined): unknown {
  if (typeof raw !== 'string' || !raw.trim()) return undefined
  try {
    return JSON.parse(raw)
  } catch {
    return undefined
  }
}

function buildUrlString(origin: string, pathAndQuery: string, explicitUrl?: string): string {
  if (explicitUrl && explicitUrl.trim()) return explicitUrl.trim()
  const cleanOrigin = origin.replace(/\/+$/, '')
  const pq = pathAndQuery.startsWith('/') ? pathAndQuery : `/${pathAndQuery}`
  return cleanOrigin ? `${cleanOrigin}${pq}` : pq
}

function buildCarrierText(
  method: string,
  pathAndQuery: string,
  requestHeaders: Readonly<Record<string, string>>,
  rawRequestBody: string | null,
): string {
  const parts = [`${method.toUpperCase()} ${pathAndQuery}`]
  if (Object.keys(requestHeaders).length > 0) parts.push(JSON.stringify(requestHeaders))
  if (rawRequestBody) parts.push(rawRequestBody)
  return parts.join('\n')
}

export function parseBodyFromCarrierText(
  carrierText: string | undefined,
  requestHeaders?: Readonly<Record<string, string>> | null,
  rawResponseBody?: string | null,
): string | null {
  if (!carrierText) return null
  const hdrJson = requestHeaders && Object.keys(requestHeaders).length > 0 ? JSON.stringify(requestHeaders) : null
  const respTrim = rawResponseBody?.trim() || null
  const bodyFrom = (text: string): string | null => {
    const content: string[] = []
    for (const line of text.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed) { if (content.length > 0) content.push(''); continue }
      if (content.length === 0 && (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//i.test(trimmed) || trimmed.startsWith('/'))) continue
      if (content.length === 0 && hdrJson && trimmed === hdrJson) continue
      if (content.length === 0 && /^[A-Za-z0-9-]+:\s/.test(trimmed)) continue
      content.push(line)
    }
    const body = content.join('\n').trim()
    return body.length > 0 ? body : null
  }
  // Legacy carriers appended the response after the request. Strip only a complete response
  // suffix when a request body remains; never mistake a response-only carrier for a request.
  if (respTrim) {
    for (const suffix of [respTrim, respTrim.slice(0, 32 * 1024)]) {
      if (!suffix || !carrierText.trimEnd().endsWith(suffix)) continue
      const prefix = carrierText.trimEnd().slice(0, -suffix.length).trimEnd()
      const body = bodyFrom(prefix)
      if (body) return body
      return null
    }
  }
  return bodyFrom(carrierText)
}

export class HostFactLog {
  private readonly exchanges = new Map<string, HostExchangeFact>()
  private readonly signedEntries = new Map<string, HostTranscriptEntry>()
  private readonly oobEvents = new Map<string, HostOobCallbackFact>()
  private readonly browserTraces = new Map<string, HostBrowserTrace>()
  private readonly asyncPolls = new Map<string, HostAsyncPollRecord>()
  private readonly sanitizer: EgressSanitizer
  private readonly assertCleanRequestPlane: boolean
  private readonly signingKey?: string
  private nextSeq = 0

  constructor(options: HostFactLogOptions = {}) {
    this.sanitizer = options.sanitizer ?? createEgressSanitizer()
    this.assertCleanRequestPlane = options.assertCleanRequestPlane === true
    this.signingKey = options.signingKey
  }

  get size(): number {
    return this.exchanges.size
  }

  /** R2-C-9: Assert that recorded kernel request-plane fields never contain vault-scrubbed `[redacted:cap:...]` tokens. */
  assertKernelRequestPlaneClean(exchangeId?: string): void {
    if (exchangeId) {
      const fact = this.exchanges.get(exchangeId)
      if (!fact) return
      assertCleanKernelRequestPlane(fact, 'HostFactLog')
      return
    }
    for (const fact of this.exchanges.values()) {
      assertCleanKernelRequestPlane(fact, 'HostFactLog')
    }
  }

  /** Record one immutable host-observed exchange. Duplicate exchangeIds are rejected (append-only). */
  recordExchange(input: HostExchangeFactInput): Readonly<HostExchangeFact> {
    if (this.exchanges.has(input.exchangeId)) {
      return this.exchanges.get(input.exchangeId)!
    }
    const seq = typeof input.seq === 'number' && Number.isFinite(input.seq)
      ? (this.nextSeq = Math.max(this.nextSeq, input.seq), input.seq)
      : ++this.nextSeq

    const requestHeaders = freezeHeaderMap(input.requestHeaders)
    const responseHeaders = freezeHeaderMap(input.responseHeaders)
    const rawRequestBody = input.rawRequestBody !== undefined && input.rawRequestBody !== null
      ? String(input.rawRequestBody)
      : null
    const rawResponseBody = input.rawResponseBody !== undefined && input.rawResponseBody !== null
      ? String(input.rawResponseBody)
      : null

    const actor = input.actor ?? null
    const roleSource = input.actorRoleLabel ?? actor ?? null
    const parsedLabel = parseRoleLabel(roleSource)
    const actorRole: RoleName | null = input.actorRole ?? parsedLabel.role ?? normalizeRole(actor ?? undefined) ?? null
    const actorTenant: string | null = input.actorTenant ?? parsedLabel.tenant ?? parseRoleLabel(actor ?? null).tenant ?? null
    const wireCredentialProvenance = freezeWireCredentialProvenance(input.wireCredentialProvenance)
    const credentialPlacement = deriveCredentialPlacement(requestHeaders, input.credentialPlacement, wireCredentialProvenance)
    const ambientAuth = deriveAmbientAuthFromHeaders(requestHeaders, input.ambientAuth, credentialPlacement)
    const setCookieMap = parseSetCookieSameSiteMap(responseHeaders)
    const hasSetCookie = Object.keys(setCookieMap).length > 0
    const sameSite = input.sameSite !== undefined
      ? input.sameSite
      : extractSameSiteFromHeaders(responseHeaders, credentialPlacement.authenticatingCookieName)
    const method = (input.method || 'GET').toUpperCase()
    const pathAndQuery = input.pathAndQuery || '/'
    const origin = input.origin || ''
    const url = buildUrlString(origin, pathAndQuery, input.url)
    const carrierText = input.carrierText !== undefined
      ? input.carrierText
      : buildCarrierText(method, pathAndQuery, requestHeaders, rawRequestBody)
    const requestPlaneVaultScrubbed = hasVaultScrubbedRequestPlane({
      pathAndQuery,
      requestHeaders,
      rawRequestBody,
      carrierText,
    })
    if (this.assertCleanRequestPlane && requestPlaneVaultScrubbed) {
      assertCleanKernelRequestPlane(
        { exchangeId: input.exchangeId, pathAndQuery, requestHeaders, rawRequestBody, carrierText },
        'HostFactLog.recordExchange',
      )
    }
    const oobCallbacks = Object.freeze((input.oobCallbacks ?? []).map(freezeOobFact))

    for (const cb of oobCallbacks) {
      if (!this.oobEvents.has(cb.id)) this.oobEvents.set(cb.id, cb)
    }

    const fact: HostExchangeFact = Object.freeze({
      seq,
      exchangeId: input.exchangeId,
      ...(input.op ? { op: input.op } : {}),
      method,
      url,
      origin,
      pathAndQuery,
      status: input.status,
      requestHeaders,
      rawRequestBody,
      responseHeaders,
      rawResponseBody,
      actor,
      actorRole,
      ...(input.actorRoleLabel !== undefined ? { actorRoleLabel: input.actorRoleLabel } : {}),
      actorTenant,
      ambientAuth,
      sameSite,
      credentialPlacement,
      ...(wireCredentialProvenance ? { wireCredentialProvenance } : {}),
      ...(hasSetCookie ? { setCookieSameSiteByName: Object.freeze(setCookieMap) } : {}),
      ...(input.raceBatchId !== undefined ? { raceBatchId: input.raceBatchId } : {}),
      ...(requestPlaneVaultScrubbed ? { requestPlaneVaultScrubbed: true } : {}),
      ...(input.hostExpressionChallenge ? { hostExpressionChallenge: Object.freeze({ ...input.hostExpressionChallenge }) } : {}),
      ...(input.hostTimingChallenge ? { hostTimingChallenge: Object.freeze({ ...input.hostTimingChallenge }) } : {}),
      ...(input.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: input.hostRedirectCanaryHost } : {}),
      oobCallbacks,
      durationMs: Math.max(0, Number.isFinite(input.durationMs ?? 0) ? (input.durationMs ?? 0) : 0),
      ...(input.startedAt !== undefined ? { startedAt: input.startedAt } : {}),
      ...(input.endedAt !== undefined ? { endedAt: input.endedAt } : {}),
      ...(input.timestampMs !== undefined ? { timestampMs: input.timestampMs } : {}),
      ...(input.arm !== undefined ? { arm: input.arm } : {}),
      ...(input.sessionRole !== undefined ? { sessionRole: input.sessionRole } : {}),
      ...(input.evidenceRole !== undefined ? { evidenceRole: input.evidenceRole } : {}),
      ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
      ...(input.consumedCapabilityId !== undefined ? { consumedCapabilityId: input.consumedCapabilityId } : {}),
      ...(input.consumedCapabilities ? { consumedCapabilities: freezeStringList(input.consumedCapabilities) } : {}),
      ...(input.emittedCapabilities ? { emittedCapabilities: freezeStringList(input.emittedCapabilities) } : {}),
      ...(input.observedResponseDigests ? { observedResponseDigests: freezeStringList(input.observedResponseDigests) } : {}),
      ...(input.injectedRequestDigests ? { injectedRequestDigests: freezeStringList(input.injectedRequestDigests) } : {}),
      ...(input.cryptoAttestations
        ? { cryptoAttestations: Object.freeze(input.cryptoAttestations.map(a => Object.freeze({ ...a }))) }
        : {}),
      ...(input.entityId !== undefined ? { entityId: input.entityId } : {}),
      ...(input.correlationIds ? { correlationIds: freezeStringList(input.correlationIds) } : {}),
      ...(input.cleanSession !== undefined ? { cleanSession: input.cleanSession } : {}),
      ...(input.replayAttempt !== undefined ? { replayAttempt: input.replayAttempt } : {}),
      ...(input.hostSignature !== undefined ? { hostSignature: input.hostSignature } : {}),
      carrierText,
      ...(input.secretMatches ? { secretMatches: freezeStringList(input.secretMatches) } : {}),
      ...(input.artifact !== undefined
        ? { artifact: input.artifact ? Object.freeze({ ...input.artifact }) : null }
        : {}),
    })
    this.exchanges.set(fact.exchangeId, fact)
    if (this.signingKey && !fact.hostSignature) {
      const unsignedEntry = this.projectFactToHostEntry(fact)
      const hostSignature = signHostTranscriptEntry(unsignedEntry, this.signingKey)
      const signedFact: HostExchangeFact = Object.freeze({ ...fact, hostSignature })
      this.exchanges.set(signedFact.exchangeId, signedFact)
      this.signedEntries.set(signedFact.exchangeId, freezeHostEntry({ ...unsignedEntry, hostSignature }))
      return signedFact
    }
    return fact
  }

  recordOobEvent(event: HostOobCallbackFact | ReceiptOobEvent | HostOobEvent): Readonly<HostOobCallbackFact> {
    const frozen = freezeOobFact(event)
    if (!this.oobEvents.has(frozen.id)) this.oobEvents.set(frozen.id, frozen)
    return this.oobEvents.get(frozen.id)!
  }

  recordBrowserTrace(trace: ReceiptBrowserTrace | HostBrowserTrace): Readonly<HostBrowserTrace> {
    const frozen: HostBrowserTrace = Object.freeze({
      ...trace,
      ...(trace.sinks ? { sinks: Object.freeze([...trace.sinks]) } : {}),
      ...('emittedCapabilities' in trace && trace.emittedCapabilities ? { emittedCapabilities: Object.freeze([...trace.emittedCapabilities]) } : {}),
      ...('observedValueDigests' in trace && trace.observedValueDigests ? { observedValueDigests: Object.freeze([...trace.observedValueDigests]) } : {}),
      ...('correlationIds' in trace && trace.correlationIds ? { correlationIds: Object.freeze([...trace.correlationIds]) } : {}),
    })
    if (!this.browserTraces.has(frozen.id)) this.browserTraces.set(frozen.id, frozen)
    return this.browserTraces.get(frozen.id)!
  }

  recordAsyncPoll(poll: HostAsyncPollRecord): Readonly<HostAsyncPollRecord> {
    const frozen: HostAsyncPollRecord = Object.freeze({
      ...poll,
      ...(poll.correlationIds ? { correlationIds: Object.freeze([...poll.correlationIds]) } : {}),
      ...(poll.emittedCapabilities ? { emittedCapabilities: Object.freeze([...poll.emittedCapabilities]) } : {}),
      ...(poll.observedValueDigests ? { observedValueDigests: Object.freeze([...poll.observedValueDigests]) } : {}),
    })
    if (!this.asyncPolls.has(frozen.id)) this.asyncPolls.set(frozen.id, frozen)
    return this.asyncPolls.get(frozen.id)!
  }

  /** Strictly read-only lookup of an immutable host fact. */
  getExchange(id: string): Readonly<HostExchangeFact> | undefined {
    return this.exchanges.get(id)
  }

  getOobEvent(id: string): Readonly<HostOobCallbackFact> | undefined {
    return this.oobEvents.get(id)
  }

  getBrowserTrace(id: string): Readonly<HostBrowserTrace> | undefined {
    return this.browserTraces.get(id)
  }

  getAsyncPoll(id: string): Readonly<HostAsyncPollRecord> | undefined {
    return this.asyncPolls.get(id)
  }

  listOobEvents(): readonly Readonly<HostOobCallbackFact>[] {
    return [...this.oobEvents.values()]
  }

  listBrowserTraces(): readonly Readonly<HostBrowserTrace>[] {
    return [...this.browserTraces.values()]
  }

  listAsyncPolls(): readonly Readonly<HostAsyncPollRecord>[] {
    return [...this.asyncPolls.values()]
  }

  /**
   * Return exchanges strictly sorted by host monotonic `seq` (with `startedAt` / `timestampMs`
   * tie-breaker). Worker-supplied ID ordering is NEVER trusted.
   */
  orderedExchanges(ids?: readonly string[]): readonly Readonly<HostExchangeFact>[] {
    const list: HostExchangeFact[] = []
    if (ids) {
      const seen = new Set<string>()
      for (const id of ids) {
        if (seen.has(id)) continue
        seen.add(id)
        const fact = this.exchanges.get(id)
        if (fact) list.push(fact)
      }
    } else {
      for (const fact of this.exchanges.values()) list.push(fact)
    }
    list.sort((a, b) => {
      if (a.seq !== b.seq) return a.seq - b.seq
      const ta = a.startedAt ?? a.timestampMs ?? 0
      const tb = b.startedAt ?? b.timestampMs ?? 0
      return ta - tb
    })
    return Object.freeze(list)
  }

  /**
   * H-13: Derive host-observed SameSite strictly bound to the authenticating cookie.
   * Scans same-origin/actor Set-Cookie headers for that exact cookie name (never letting a
   * cosmetic cookie overwrite it), and defaults unknown SameSite on cookie auth to `'Lax'`
   * (never `'None'`).
   */
  resolveSameSite(exchangeId: string): string | null {
    const fact = this.exchanges.get(exchangeId)
    if (!fact) return null
    const authCookie = fact.credentialPlacement?.authenticatingCookieName?.trim().toLowerCase() ?? null
    if (authCookie) {
      if (fact.setCookieSameSiteByName && authCookie in fact.setCookieSameSiteByName) {
        return fact.setCookieSameSiteByName[authCookie] ?? 'Lax'
      }
      const originKey = normalizeOriginKey(fact.origin)
      for (const item of this.orderedExchanges()) {
        if (originKey && item.origin && normalizeOriginKey(item.origin) !== originKey) continue
        if (fact.actor && item.actor && item.actor !== fact.actor) continue
        if (item.setCookieSameSiteByName && authCookie in item.setCookieSameSiteByName) {
          return item.setCookieSameSiteByName[authCookie] ?? 'Lax'
        }
      }
      if (fact.sameSite) return fact.sameSite
      return fact.ambientAuth === 'cookie' ? 'Lax' : null
    }
    if (fact.sameSite) return fact.sameSite
    const originKey = normalizeOriginKey(fact.origin)
    for (const item of this.orderedExchanges()) {
      if (originKey && item.origin && normalizeOriginKey(item.origin) !== originKey) continue
      if (fact.actor && item.actor && item.actor !== fact.actor) continue
      if (item.sameSite) return item.sameSite
    }
    return fact.ambientAuth === 'cookie' ? 'Lax' : null
  }

  /**
   * Plane-2 projection: derive a scrubbed worker-facing view of a host fact via `EgressSanitizer`.
   * NEVER mutates the stored pre-redaction `HostExchangeFact`.
   */
  buildWorkerView(
    id: string,
    sanitizer: EgressSanitizer = this.sanitizer,
    channel: EgressChannel = 'worker_rpc',
  ): WorkerExchangeView | undefined {
    const fact = this.exchanges.get(id)
    if (!fact) return undefined
    const requestHeaders = Object.freeze(sanitizer.sanitizeHttpHeaders({ ...fact.requestHeaders }, channel))
    const responseHeaders = Object.freeze(sanitizer.sanitizeHttpHeaders({ ...fact.responseHeaders }, channel))
    const requestBody = fact.rawRequestBody !== null ? sanitizer.redactText(fact.rawRequestBody, channel) : null
    const responseBody = fact.rawResponseBody !== null ? sanitizer.redactText(fact.rawResponseBody, channel) : null
    const pathAndQuery = sanitizer.redactText(fact.pathAndQuery, channel)
    const url = sanitizer.redactText(fact.url, channel)
    return Object.freeze({
      seq: fact.seq,
      exchangeId: fact.exchangeId,
      ...(fact.op ? { op: fact.op } : {}),
      method: fact.method,
      url,
      origin: fact.origin,
      pathAndQuery,
      status: fact.status,
      requestHeaders,
      requestBody,
      responseHeaders,
      responseBody,
      actor: fact.actor,
      actorRole: fact.actorRole,
      actorTenant: fact.actorTenant,
      durationMs: fact.durationMs,
    })
  }

  /** Project one host fact onto `ImpactStep` strictly from host-recorded data. */
  toImpactStep(
    exchangeId: string,
    overrides?: { arm?: ImpactStep['arm']; evidenceRole?: string },
  ): ImpactStep | undefined {
    const fact = this.exchanges.get(exchangeId)
    if (!fact) return undefined
    const arm: ImpactStep['arm'] = overrides?.arm
      ?? fact.arm
      ?? (fact.sessionRole === 'control' || fact.sessionRole === 'probe' || fact.sessionRole === 'setup' || fact.sessionRole === 'cleanup'
        ? fact.sessionRole
        : 'setup')
    const json = safeJsonParse(fact.rawResponseBody)
    const requestJson = fact.rawRequestBody !== null
      ? (safeJsonParse(fact.rawRequestBody) ?? fact.rawRequestBody)
      : undefined
    const sameSite = this.resolveSameSite(exchangeId)
    const evidenceRole = overrides?.evidenceRole ?? fact.evidenceRole
    return {
      id: fact.exchangeId,
      arm,
      method: fact.method,
      route: (fact.pathAndQuery || '/').split('?')[0] || '/',
      pathAndQuery: fact.pathAndQuery || '/',
      status: fact.status,
      actor: {
        handle: fact.actor,
        role: fact.actorRole,
        tenant: fact.actorTenant,
        auth: fact.ambientAuth,
        sameSite,
      },
      ...(json !== undefined ? { json } : {}),
      ...(fact.rawResponseBody !== null ? { body: fact.rawResponseBody } : {}),
      ...(requestJson !== undefined ? { requestJson } : {}),
      ...(Object.keys(fact.requestHeaders).length > 0 ? { requestHeaders: { ...fact.requestHeaders } } : {}),
      ...(Object.keys(fact.responseHeaders).length > 0 ? { responseHeaders: { ...fact.responseHeaders } } : {}),
      ...(fact.secretMatches && fact.secretMatches.length > 0 ? { secretMatches: [...fact.secretMatches] } : {}),
      ...(evidenceRole ? { evidenceRole } : {}),
      durationMs: fact.durationMs,
    }
  }

  /** Project the host log onto a `ReceiptTranscript` ordered by host `seq`. */
  toReceiptTranscript(options?: {
    armOverrides?: ReadonlyMap<string, ImpactStep['arm']>
    evidenceRoleOverrides?: ReadonlyMap<string, string>
  }): ReceiptTranscript {
    const entries: ReceiptTranscriptEntry[] = this.orderedExchanges().map(fact => {
      const evidenceRole = options?.evidenceRoleOverrides?.get(fact.exchangeId) ?? fact.evidenceRole ?? fact.sessionRole ?? undefined
      const step = this.toImpactStep(fact.exchangeId, {
        ...(options?.armOverrides?.has(fact.exchangeId) ? { arm: options.armOverrides.get(fact.exchangeId)! } : {}),
        ...(evidenceRole ? { evidenceRole } : {}),
      })!
      return {
        exchangeId: fact.exchangeId,
        step,
        durationMs: fact.durationMs,
        ...(fact.op ? { op: fact.op } : {}),
        seq: fact.seq,
        ...(fact.startedAt !== undefined ? { startedAt: fact.startedAt } : {}),
        ...(fact.endedAt !== undefined ? { endedAt: fact.endedAt } : {}),
        ...(fact.origin ? { origin: fact.origin } : {}),
        ...(fact.consumedCapabilityId !== undefined ? { consumedCapabilityId: fact.consumedCapabilityId } : {}),
        ...(fact.consumedCapabilities ? { consumedCapabilities: [...fact.consumedCapabilities] } : {}),
        ...(fact.sessionId !== undefined ? { sessionId: fact.sessionId } : {}),
        ...(fact.carrierText ? { carrierText: fact.carrierText } : {}),
        ...(evidenceRole ? { evidenceRole } : {}),
        ...(fact.raceBatchId !== undefined ? { raceBatchId: fact.raceBatchId } : {}),
        ...(fact.credentialPlacement ? { credentialPlacement: fact.credentialPlacement } : {}),
        ...(fact.wireCredentialProvenance ? { wireCredentialProvenance: fact.wireCredentialProvenance } : {}),
        ...(fact.requestPlaneVaultScrubbed ? { requestPlaneVaultScrubbed: true } : {}),
        ...(fact.hostExpressionChallenge ? { hostExpressionChallenge: fact.hostExpressionChallenge } : {}),
        ...(fact.hostTimingChallenge ? { hostTimingChallenge: fact.hostTimingChallenge } : {}),
        ...(fact.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: fact.hostRedirectCanaryHost } : {}),
      }
    })
    return {
      entries,
      oobEvents: this.listOobEvents().map(ev => ({ ...ev })),
      browserTraces: this.listBrowserTraces().map(tr => ({ ...tr })),
    }
  }

  private projectFactToHostEntry(
    fact: HostExchangeFact,
    overrides?: { arm?: ImpactStep['arm']; evidenceRole?: string },
  ): HostTranscriptEntry {
    const evidenceRole = overrides?.evidenceRole ?? fact.evidenceRole ?? fact.sessionRole ?? undefined
    const step = this.toImpactStep(fact.exchangeId, {
      ...(overrides?.arm !== undefined ? { arm: overrides.arm } : {}),
      ...(evidenceRole ? { evidenceRole } : {}),
    })!
    const ts = fact.timestampMs ?? fact.startedAt ?? fact.seq
    const observedDigests = fact.observedResponseDigests && fact.observedResponseDigests.length > 0
      ? [...fact.observedResponseDigests]
      : fact.rawResponseBody !== null
        ? [createHash('sha256').update(fact.rawResponseBody, 'utf8').digest('hex')]
        : undefined
    const consumedCaps = fact.consumedCapabilities?.length
      ? [...fact.consumedCapabilities]
      : fact.consumedCapabilityId
        ? [fact.consumedCapabilityId]
        : undefined
    return {
      exchangeId: fact.exchangeId,
      step,
      durationMs: fact.durationMs,
      ...(fact.op ? { op: fact.op } : {}),
      seq: fact.seq,
      ...(fact.startedAt !== undefined ? { startedAt: fact.startedAt } : {}),
      ...(fact.endedAt !== undefined ? { endedAt: fact.endedAt } : {}),
      ...(fact.origin ? { origin: fact.origin } : {}),
      ...(fact.consumedCapabilityId !== undefined ? { consumedCapabilityId: fact.consumedCapabilityId } : {}),
      ...(consumedCaps ? { consumedCapabilities: consumedCaps } : {}),
      ...(fact.sessionId !== undefined ? { sessionId: fact.sessionId } : {}),
      ...(fact.carrierText ? { carrierText: fact.carrierText } : {}),
      ...(evidenceRole ? { evidenceRole } : {}),
      ...(fact.raceBatchId !== undefined ? { raceBatchId: fact.raceBatchId } : {}),
      ...(fact.credentialPlacement ? { credentialPlacement: fact.credentialPlacement } : {}),
      ...(fact.wireCredentialProvenance ? { wireCredentialProvenance: fact.wireCredentialProvenance } : {}),
      ...(fact.requestPlaneVaultScrubbed ? { requestPlaneVaultScrubbed: true } : {}),
      ...(fact.hostExpressionChallenge ? { hostExpressionChallenge: fact.hostExpressionChallenge } : {}),
      ...(fact.hostTimingChallenge ? { hostTimingChallenge: fact.hostTimingChallenge } : {}),
      ...(fact.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: fact.hostRedirectCanaryHost } : {}),
      timestampMs: ts,
      actorPersona: fact.actor,
      ...(fact.actorRoleLabel !== undefined ? { actorRoleLabel: fact.actorRoleLabel } : {}),
      ...(fact.emittedCapabilities ? { emittedCapabilities: [...fact.emittedCapabilities] } : {}),
      ...(observedDigests ? { observedResponseDigests: observedDigests } : {}),
      ...(fact.injectedRequestDigests ? { injectedRequestDigests: [...fact.injectedRequestDigests] } : {}),
      ...(fact.cryptoAttestations ? { cryptoAttestations: fact.cryptoAttestations.map(a => ({ ...a })) } : {}),
      ...(fact.entityId !== undefined ? { entityId: fact.entityId } : {}),
      ...(fact.correlationIds ? { correlationIds: [...fact.correlationIds] } : {}),
      ...(fact.cleanSession !== undefined ? { cleanSession: fact.cleanSession } : {}),
      ...(fact.replayAttempt !== undefined ? { replayAttempt: fact.replayAttempt } : {}),
      ...(fact.hostSignature !== undefined ? { hostSignature: fact.hostSignature } : {}),
    }
  }

  /** Project the host log onto a `HostSignedTranscript` for unified 1-hop / multi-hop verification. */
  toHostSignedTranscript(options?: {
    armOverrides?: ReadonlyMap<string, ImpactStep['arm']>
    evidenceRoleOverrides?: ReadonlyMap<string, string>
    signingKey?: string
  }): HostSignedTranscript {
    const effectiveSigningKey = options?.signingKey ?? this.signingKey
    const entries: HostTranscriptEntry[] = this.orderedExchanges().map(fact => {
      // A signature covers the original signed entry, not a later projection with derived defaults;
      // only project overrides when explicitly requested and different from the signed entry.
      const signed = this.signedEntries.get(fact.exchangeId)
      const armOverride = options?.armOverrides?.get(fact.exchangeId)
      const roleOverride = options?.evidenceRoleOverrides?.get(fact.exchangeId)
      if (signed) {
        const armDiffers = armOverride !== undefined && armOverride !== signed.step.arm
        const roleDiffers = roleOverride !== undefined && roleOverride !== (signed.evidenceRole ?? signed.step.evidenceRole)
        if (!armDiffers && !roleDiffers) return signed
        return {
          ...signed,
          ...(roleDiffers ? { evidenceRole: roleOverride } : {}),
          step: {
            ...signed.step,
            ...(armDiffers ? { arm: armOverride } : {}),
            ...(roleDiffers ? { evidenceRole: roleOverride } : {}),
          },
        }
      }
      const entry = this.projectFactToHostEntry(fact, {
        ...(armOverride !== undefined ? { arm: armOverride } : {}),
        ...(roleOverride !== undefined ? { evidenceRole: roleOverride } : {}),
      })
      if (effectiveSigningKey && !entry.hostSignature) {
        return { ...entry, hostSignature: signHostTranscriptEntry(entry, effectiveSigningKey) }
      }
      return entry
    })
    return {
      entries,
      oobEvents: this.listOobEvents().map(ev => ({ ...ev })),
      browserTraces: this.listBrowserTraces().map(tr => ({ ...tr })),
      asyncPollRecords: this.listAsyncPolls().map(p => ({ ...p })),
    }
  }

  /** Construct an immutable `HostFactLog` from a `ReceiptTranscript` or `HostSignedTranscript`. */
  static fromTranscript(
    transcript: ReceiptTranscript | HostSignedTranscript,
    options?: HostFactLogOptions,
  ): HostFactLog {
    const log = new HostFactLog(options)
    const entries = transcript.entries ?? []
    entries.forEach((rawEntry, index) => {
      const entry = rawEntry as HostTranscriptEntry
      const step = entry.step
      const rawResp = typeof step.body === 'string'
        ? step.body
        : step.json !== undefined
          ? JSON.stringify(step.json)
          : null
      const rawReq = step.requestJson !== undefined
        ? (typeof step.requestJson === 'string' ? step.requestJson : JSON.stringify(step.requestJson))
        : parseBodyFromCarrierText(entry.carrierText, step.requestHeaders ?? null, rawResp)
      log.recordExchange({
        seq: typeof entry.seq === 'number' && Number.isFinite(entry.seq) ? entry.seq : index + 1,
        exchangeId: entry.exchangeId,
        ...(entry.op ? { op: entry.op } : {}),
        method: step.method,
        origin: entry.origin ?? '',
        pathAndQuery: step.pathAndQuery ?? step.route ?? '/',
        status: step.status,
        requestHeaders: step.requestHeaders ?? null,
        rawRequestBody: rawReq,
        responseHeaders: step.responseHeaders ?? null,
        rawResponseBody: rawResp,
        actor: entry.actorPersona !== undefined ? entry.actorPersona : (step.actor.handle ?? null),
        actorRole: step.actor.role ?? null,
        actorRoleLabel: entry.actorRoleLabel ?? null,
        actorTenant: step.actor.tenant ?? null,
        ambientAuth: step.actor.auth,
        ...(step.actor.sameSite !== null && step.actor.sameSite !== undefined ? { sameSite: step.actor.sameSite } : {}),
        ...(entry.credentialPlacement ? { credentialPlacement: entry.credentialPlacement } : {}),
        ...(entry.wireCredentialProvenance ? { wireCredentialProvenance: entry.wireCredentialProvenance } : {}),
        ...(entry.raceBatchId !== undefined ? { raceBatchId: entry.raceBatchId } : {}),
        ...(entry.hostExpressionChallenge ? { hostExpressionChallenge: entry.hostExpressionChallenge } : {}),
        ...(entry.hostTimingChallenge ? { hostTimingChallenge: entry.hostTimingChallenge } : {}),
        ...(entry.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: entry.hostRedirectCanaryHost } : {}),
        durationMs: entry.durationMs ?? step.durationMs ?? 0,
        ...(entry.startedAt !== undefined ? { startedAt: entry.startedAt } : {}),
        ...(entry.endedAt !== undefined ? { endedAt: entry.endedAt } : {}),
        ...(entry.timestampMs !== undefined ? { timestampMs: entry.timestampMs } : {}),
        arm: step.arm,
        ...(entry.evidenceRole ?? step.evidenceRole ? { evidenceRole: entry.evidenceRole ?? step.evidenceRole } : {}),
        ...(entry.sessionId !== undefined ? { sessionId: entry.sessionId } : {}),
        ...(entry.consumedCapabilityId !== undefined ? { consumedCapabilityId: entry.consumedCapabilityId } : {}),
        ...(entry.consumedCapabilities ? { consumedCapabilities: entry.consumedCapabilities } : {}),
        ...(entry.emittedCapabilities ? { emittedCapabilities: entry.emittedCapabilities } : {}),
        ...(entry.observedResponseDigests ? { observedResponseDigests: entry.observedResponseDigests } : {}),
        ...(entry.injectedRequestDigests ? { injectedRequestDigests: entry.injectedRequestDigests } : {}),
        ...(entry.cryptoAttestations ? { cryptoAttestations: entry.cryptoAttestations } : {}),
        ...(entry.entityId !== undefined ? { entityId: entry.entityId } : {}),
        ...(entry.correlationIds ? { correlationIds: entry.correlationIds } : {}),
        ...(entry.cleanSession !== undefined ? { cleanSession: entry.cleanSession } : {}),
        ...(entry.replayAttempt !== undefined ? { replayAttempt: entry.replayAttempt } : {}),
        ...(entry.hostSignature !== undefined ? { hostSignature: entry.hostSignature } : {}),
        ...(entry.carrierText !== undefined ? { carrierText: entry.carrierText } : {}),
        ...(step.secretMatches ? { secretMatches: step.secretMatches } : {}),
      })
      if (entry.hostSignature && !log.signedEntries.has(entry.exchangeId)) {
        log.signedEntries.set(entry.exchangeId, freezeHostEntry(entry))
      }
    })
    for (const oob of transcript.oobEvents ?? []) log.recordOobEvent(oob)
    for (const trace of transcript.browserTraces ?? []) log.recordBrowserTrace(trace)
    if ('asyncPollRecords' in transcript && transcript.asyncPollRecords) {
      for (const poll of transcript.asyncPollRecords) log.recordAsyncPoll(poll)
    }
    return log
  }

  /** Construct an immutable `HostFactLog` from host-recorded `ScriptProofExchange` items. */
  static fromScriptExchanges(
    exchanges: readonly ScriptProofExchange[],
    oobEvents?: readonly ReceiptOobEvent[],
    options?: HostFactLogOptions,
  ): HostFactLog {
    const log = new HostFactLog(options)
    exchanges.forEach((ex, index) => {
      log.recordExchange({
        seq: typeof ex.seq === 'number' && Number.isFinite(ex.seq) ? ex.seq : index + 1,
        exchangeId: ex.exchangeId,
        ...(ex.op ? { op: ex.op } : {}),
        method: ex.method,
        origin: ex.origin,
        pathAndQuery: ex.pathAndQuery,
        status: ex.status,
        requestHeaders: ex.requestHeaders ?? null,
        rawRequestBody: ex.requestBody ?? null,
        responseHeaders: ex.responseHeaders ?? null,
        rawResponseBody: ex.body ?? null,
        actor: ex.personaHandle ?? null,
        actorRoleLabel: ex.actorRoleLabel ?? null,
        ambientAuth: ex.ambientAuth,
        ...(ex.sessionSameSite !== undefined ? { sameSite: ex.sessionSameSite } : {}),
        ...(ex.credentialPlacement ? { credentialPlacement: ex.credentialPlacement } : {}),
        ...(ex.raceBatchId !== undefined ? { raceBatchId: ex.raceBatchId } : {}),
        ...(ex.hostExpressionChallenge ? { hostExpressionChallenge: ex.hostExpressionChallenge } : {}),
        ...(ex.hostTimingChallenge ? { hostTimingChallenge: ex.hostTimingChallenge } : {}),
        ...(ex.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: ex.hostRedirectCanaryHost } : {}),
        durationMs: ex.durationMs ?? 0,
        ...(ex.startedAt !== undefined ? { startedAt: ex.startedAt } : {}),
        ...(ex.endedAt !== undefined ? { endedAt: ex.endedAt } : {}),
        ...(ex.sessionRole !== undefined ? { sessionRole: ex.sessionRole } : {}),
        ...(ex.sessionId !== undefined ? { sessionId: ex.sessionId } : {}),
        ...(ex.consumedCapabilityId !== undefined ? { consumedCapabilityId: ex.consumedCapabilityId } : {}),
        ...(ex.consumedCapabilities ? { consumedCapabilities: ex.consumedCapabilities } : {}),
        ...(ex.artifact !== undefined ? { artifact: ex.artifact } : {}),
      })
    })
    for (const ev of oobEvents ?? []) log.recordOobEvent(ev)
    return log
  }

  /** Construct an immutable `HostFactLog` from a Layer-3 `TranscriptStore` + optional host transcript/raw bodies. */
  static fromTranscriptStore(
    store: TranscriptStore,
    opts?: {
      rawRequestBodies?: ReadonlyMap<string, string>
      rawResponseBodies?: ReadonlyMap<string, string>
      hostTranscript?: HostSignedTranscript | null
      sanitizer?: EgressSanitizer
    },
  ): HostFactLog {
    const log = new HostFactLog({ sanitizer: opts?.sanitizer })
    const hostEntriesById = new Map((opts?.hostTranscript?.entries ?? []).map(e => [e.exchangeId, e]))
    for (const record of store.list() as readonly VerifyTranscriptRecord[]) {
      const hostEntry = hostEntriesById.get(record.exchangeId)
      const req = record.request
      const rawResp = opts?.rawResponseBodies?.get(record.exchangeId)
        ?? hostEntry?.step.body
        ?? (hostEntry?.step.json !== undefined ? JSON.stringify(hostEntry.step.json) : undefined)
        ?? store.body(record.exchangeId)
        ?? null
      const rawReq = opts?.rawRequestBodies?.get(record.exchangeId)
        ?? store.requestBody?.(record.exchangeId)
        ?? (hostEntry?.step.requestJson !== undefined
          ? (typeof hostEntry.step.requestJson === 'string'
            ? hostEntry.step.requestJson
            : JSON.stringify(hostEntry.step.requestJson))
          : parseBodyFromCarrierText(hostEntry?.carrierText, hostEntry?.step.requestHeaders, rawResp))
      const reqExtra = req as (typeof req & {
        kernelPathAndQuery?: string
        rawPathAndQuery?: string
        kernelHeaders?: Record<string, string>
        rawHeaders?: Record<string, string>
        raceBatchId?: string | null
        credentialPlacement?: HostCredentialPlacement
        wireCredentialProvenance?: WireCredentialProvenance
      }) | undefined
      const artExtra = record.artifact as (typeof record.artifact & {
        subscriptionId?: string
        canaryId?: string
        callbackId?: string
        receivedAtMs?: number
        hostSignature?: string
        callbackSignature?: string
      }) | undefined
      const kernelPathAndQuery = reqExtra?.kernelPathAndQuery
        ?? reqExtra?.rawPathAndQuery
        ?? req?.pathAndQuery
        ?? hostEntry?.step.pathAndQuery
        ?? hostEntry?.step.route
        ?? '/'
      const kernelHeaders = reqExtra?.kernelHeaders
        ?? reqExtra?.rawHeaders
        ?? req?.headers
        ?? hostEntry?.step.requestHeaders
        ?? null
      const kernelCarrierText = hostEntry?.carrierText && !hasVaultScrubbedToken(hostEntry.carrierText)
        ? hostEntry.carrierText
        : undefined
      log.recordExchange({
        seq: record.seq,
        exchangeId: record.exchangeId,
        op: record.op,
        method: req?.method ?? hostEntry?.step.method ?? (record.op === 'oob' ? 'OOB' : 'GET'),
        origin: req?.origin ?? hostEntry?.origin ?? '',
        pathAndQuery: kernelPathAndQuery,
        status: record.response?.status ?? hostEntry?.step.status ?? null,
        requestHeaders: kernelHeaders,
        rawRequestBody: rawReq,
        responseHeaders: record.response?.headers ?? hostEntry?.step.responseHeaders ?? null,
        rawResponseBody: rawResp,
        actor: req?.personaHandle ?? hostEntry?.actorPersona ?? hostEntry?.step.actor.handle ?? null,
        actorRole: hostEntry?.step.actor.role ?? null,
        actorRoleLabel: req?.actorRoleLabel ?? hostEntry?.actorRoleLabel ?? null,
        actorTenant: hostEntry?.step.actor.tenant ?? null,
        ambientAuth: hostEntry?.step.actor.auth,
        ...(hostEntry?.step.actor.sameSite !== null && hostEntry?.step.actor.sameSite !== undefined
          ? { sameSite: hostEntry.step.actor.sameSite }
          : {}),
        ...(reqExtra?.credentialPlacement ?? hostEntry?.credentialPlacement
          ? { credentialPlacement: reqExtra?.credentialPlacement ?? hostEntry?.credentialPlacement }
          : {}),
        ...(reqExtra?.wireCredentialProvenance ?? hostEntry?.wireCredentialProvenance
          ? { wireCredentialProvenance: reqExtra?.wireCredentialProvenance ?? hostEntry?.wireCredentialProvenance }
          : {}),
        ...(reqExtra?.raceBatchId ?? hostEntry?.raceBatchId !== undefined
          ? { raceBatchId: reqExtra?.raceBatchId ?? hostEntry?.raceBatchId }
          : {}),
        ...(hostEntry?.hostExpressionChallenge ? { hostExpressionChallenge: hostEntry.hostExpressionChallenge } : {}),
        ...(hostEntry?.hostTimingChallenge ? { hostTimingChallenge: hostEntry.hostTimingChallenge } : {}),
        ...(hostEntry?.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: hostEntry.hostRedirectCanaryHost } : {}),
        durationMs: record.durationMs,
        startedAt: record.startedAt,
        endedAt: record.startedAt + Math.max(0, record.durationMs),
        timestampMs: hostEntry?.timestampMs ?? record.startedAt,
        arm: hostEntry?.step.arm,
        sessionRole: req?.sessionRole ?? null,
        ...(hostEntry?.evidenceRole ? { evidenceRole: hostEntry.evidenceRole } : {}),
        ...(req?.consumedCapabilityId !== undefined ? { consumedCapabilityId: req.consumedCapabilityId } : {}),
        ...(hostEntry?.consumedCapabilities
          ? { consumedCapabilities: hostEntry.consumedCapabilities }
          : req?.consumedCapabilityId
            ? { consumedCapabilities: [req.consumedCapabilityId] }
            : {}),
        ...(hostEntry?.emittedCapabilities
          ? { emittedCapabilities: hostEntry.emittedCapabilities }
          : record.op === 'capability' && typeof record.artifact?.capabilityHandle === 'string' && record.artifact.capabilityHandle
            ? { emittedCapabilities: [record.artifact.capabilityHandle] }
            : {}),
        ...(hostEntry?.observedResponseDigests ? { observedResponseDigests: hostEntry.observedResponseDigests } : {}),
        ...(hostEntry?.injectedRequestDigests ? { injectedRequestDigests: hostEntry.injectedRequestDigests } : {}),
        ...(hostEntry?.cryptoAttestations ? { cryptoAttestations: hostEntry.cryptoAttestations } : {}),
        ...(hostEntry?.entityId ? { entityId: hostEntry.entityId } : {}),
        ...(hostEntry?.correlationIds ? { correlationIds: hostEntry.correlationIds } : {}),
        ...(hostEntry?.cleanSession !== undefined ? { cleanSession: hostEntry.cleanSession } : {}),
        ...(hostEntry?.replayAttempt ? { replayAttempt: hostEntry.replayAttempt } : {}),
        ...(hostEntry?.hostSignature ? { hostSignature: hostEntry.hostSignature } : {}),
        ...(kernelCarrierText ? { carrierText: kernelCarrierText } : {}),
        ...(record.artifact
          ? {
              artifact: {
                kind: record.artifact.kind,
                token: record.artifact.token,
                url: record.artifact.url,
                dnsHost: record.artifact.dnsHost,
                hit: record.artifact.hit,
                ...(artExtra?.subscriptionId ? { subscriptionId: artExtra.subscriptionId } : {}),
                ...(artExtra?.canaryId ? { canaryId: artExtra.canaryId } : {}),
                ...(artExtra?.callbackId ? { callbackId: artExtra.callbackId } : {}),
                ...(artExtra?.receivedAtMs !== undefined ? { receivedAtMs: artExtra.receivedAtMs } : {}),
                ...(artExtra?.hostSignature ? { hostSignature: artExtra.hostSignature } : {}),
                ...(artExtra?.callbackSignature ? { callbackSignature: artExtra.callbackSignature } : {}),
              },
            }
          : {}),
      })
      if (hostEntry?.hostSignature && !log.signedEntries.has(record.exchangeId)) {
        log.signedEntries.set(record.exchangeId, freezeHostEntry(hostEntry))
      }
    }
    for (const oob of opts?.hostTranscript?.oobEvents ?? []) log.recordOobEvent(oob)
    for (const tr of opts?.hostTranscript?.browserTraces ?? []) log.recordBrowserTrace(tr)
    for (const poll of opts?.hostTranscript?.asyncPollRecords ?? []) log.recordAsyncPoll(poll)
    return log
  }

  /** Record a brokered HTTP exchange + its originating request directly into this log. */
  recordBrokerExchange(
    exchangeId: string,
    request: Pick<BrokerHttpRequest, 'origin' | 'method' | 'pathAndQuery' | 'headers' | 'body' | 'persona' | 'session'>,
    exchange: BrokerExchangeResult,
    meta?: {
      arm?: ImpactStep['arm']
      actorRoleLabel?: string | null
      actorRole?: RoleName | null
      actorTenant?: string | null
      evidenceRole?: string
      startedAt?: number
    },
  ): Readonly<HostExchangeFact> {
    return this.recordExchange({
      exchangeId,
      op: 'http',
      method: exchange.method || request.method,
      origin: exchange.origin || request.origin,
      pathAndQuery: exchange.pathAndQuery || request.pathAndQuery,
      status: exchange.status,
      requestHeaders: { ...(request.headers ?? {}), ...(exchange.reqHeaders ?? {}) },
      rawRequestBody: request.body ?? null,
      responseHeaders: exchange.respHeaders ?? null,
      rawResponseBody: exchange.body,
      actor: exchange.personaHandle ?? request.persona ?? null,
      actorRole: meta?.actorRole ?? null,
      actorRoleLabel: meta?.actorRoleLabel ?? null,
      actorTenant: meta?.actorTenant ?? null,
      durationMs: exchange.durationMs,
      ...(meta?.startedAt !== undefined ? { startedAt: meta.startedAt, endedAt: meta.startedAt + exchange.durationMs } : {}),
      ...(meta?.arm ? { arm: meta.arm } : {}),
      ...(meta?.evidenceRole ? { evidenceRole: meta.evidenceRole } : {}),
      ...(request.session ? { sessionId: request.session } : {}),
      ...(exchange.wireCredentialProvenance ? { wireCredentialProvenance: exchange.wireCredentialProvenance } : {}),
      ...(exchange.secretMatches?.length
        ? { secretMatches: exchange.secretMatches.slice(0, 16).map(m => m.sha256Prefix) }
        : {}),
    })
  }
}
