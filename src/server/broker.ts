import { createHash, createHmac, createPublicKey, randomBytes } from 'node:crypto'
import { resolve4, resolve6, resolveCname, resolveNs, resolveTxt } from 'node:dns/promises'
import type { IncomingHttpHeaders } from 'node:http'
import { connect as netConnect } from 'node:net'
import type { Socket as NetSocket } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import type { DetailedPeerCertificate, TLSSocket } from 'node:tls'
import { defaultMaxRpsPerOrigin, referrerPolicies } from '../domain.ts'
import ipaddr from 'ipaddr.js'
import { EgressDeniedError, EgressGateway, isMetadataOrLinkLocalAddress } from './egress-gateway.ts'
import { isIpLiteralHost } from './public-suffix.ts'
import type { ApprovalPolicy, ApprovedEndpointPattern, CapabilityTier, HttpMethod, PreparedObservation } from '../domain.ts'
import { cacheBusterValueRegex, containsWebshellSignature } from '../replay-spec.ts'
import type { CsrfBind } from '../replay-spec.ts'
import { isLocalLabAutoApprovalOrigin } from './approval-judge.ts'
import type { StateChangeApprovalContext } from './approval-judge.ts'
import { scanSecondOrderMarkers } from './canary-broker.ts'
import type { CanaryBroker, SecondOrderStore } from './canary-broker.ts'
import { detectSessionExpiry, scanJwtCandidatesLinear } from './persona-auth.ts'
import { buildPersonaHeader, personaSecrets } from './persona-vault.ts'
import type { ResolvedPersona } from './persona-vault.ts'
import { redact, redactHeaders, scanSecretHeaders, scanSecrets } from './redact.ts'
import type { NamedSecret, SecretMatch } from './redact.ts'
import {
  resolveRunSafetyBudgets,
  RUN_SAFETY_BUDGET_DEFAULTS,
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
} from './run-safety-budgets.ts'
import {
  classifyTargetClass,
  classifyTargetLoadStatus,
  EXTERNAL_APEX_MAX_RPS_CAP,
  EXTERNAL_ORIGIN_MAX_IN_FLIGHT,
  EXTERNAL_ORIGIN_MAX_RPS_CAP,
  isLoopbackOrigin,
  LOOPBACK_ORIGIN_MAX_IN_FLIGHT,
  LOOPBACK_ORIGIN_MAX_RPS_CAP,
  normalizeIpBucketKey,
  PROBE_INDUCED_EXEMPT_HTTP_STATUSES,
  resolveBrokerPerOriginConcurrencyCap,
  resolveBrokerPerOriginRpsCap,
  resolveExternalApexBucketKey,
  resolveExternalApexRpsCap,
  resolveExternalIpConcurrencyCap,
  resolveExternalIpRpsCap,
  resolveTargetLoadPolicy,
  TARGET_LOAD_POLICY_DEFAULTS,
} from './target-load-policy.ts'
import type {
  AggregateBucketKind,
  EffectiveTargetLoadPolicy,
  TargetClass,
  TargetLoadStatusClass,
} from './target-load-policy.ts'
import type { ScopeHook, ScopePolicy } from './scope-policy.ts'
import {
  defaultRequestAdmissionEngine,
  hasDestructiveContent,
  isLocalLabEnabled,
  isSyntheticAuthMutation,
  isValidWebsocketSubprotocol,
  RequestAdmissionEngine,
  resolveSyntheticApiKeyHeaderName,
  SYNTHETIC_INVALID_API_KEY_PREFIX,
  SYNTHETIC_INVALID_BEARER_PREFIX,
  validateCallerHeaders,
} from './request-admission.ts'
import type {
  AdmissionDecision,
  AdmissionRequest,
  BrokerAuthMutation,
  ValidateCallerHeadersOptions,
} from './request-admission.ts'
import { globalKillSwitch, KillSwitchTrippedError } from './kill-switch.ts'
import type { GlobalKillSwitch } from './kill-switch.ts'
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
  authMutation?: BrokerAuthMutation
  probeClass?: string
  cacheVerify?: boolean
  traceId?: string
  runId?: string
  assignmentId?: string
  scopeRevision?: number
  followRedirects?: boolean
  /** v6: explicit staging setup/cleanup hook context (scope-policy). */
  scopeHook?: ScopeHook
  secrets?: readonly NamedSecret[]
  maxBodyBytes?: number
  timeoutMs?: number
  /** Host-only in-process hook delivering pre-redaction response body & headers strictly for host capability sealing. Never exposed on BrokerExchangeResult. */
  onRawResponse?: (raw: { body: string; headers: Record<string, string> }) => void
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

export type WireCredentialSource =
  | 'none'
  | 'persona_vault'
  | 'session_jar'
  | 'caller_self_minted'
  | 'ephemeral_observed'
  | 'persona_and_jar'

/**
 * H-14: Non-secret wire credential provenance emitted by `RequestBroker` so proof-kernel
 * callers can verify true wire authentication (header/cookie names & auth sources only,
 * NEVER secret values).
 */
export interface WireCredentialProvenance {
  /** Whether any authentication header or cookie was transmitted on the wire. */
  authenticated: boolean
  /** Primary auth source summary for the final hop. */
  source: WireCredentialSource
  /** Distinct contributing credential sources on the wire. */
  sources: Array<'persona_vault' | 'session_jar' | 'caller_self_minted' | 'ephemeral_observed' | 'csrf_bind'>
  /** Declared persona handle if persona credentials were transmitted on the final hop. */
  personaHandle: string | null
  /** Session jar label attached to this exchange, if any. */
  session: string | null
  /** Lowercased names of auth-bearing headers actually transmitted on the wire (never values). */
  headerNames: string[]
  /** Sorted names of cookies actually transmitted on the wire (names only, never values). */
  cookieNames: string[]
  /** Sorted names of cookies contributed by the Persona Vault (names only). */
  vaultCookieNames: string[]
  /** Sorted names of cookies contributed by the Session Jar (names only). */
  jarCookieNames: string[]
  /** Lowercased names of headers contributed by the Persona Vault (names only). */
  vaultHeaderNames: string[]
  /** Lowercased names of caller-supplied auth-bearing headers (e.g. self-minted alg:none Bearer). */
  callerAuthHeaderNames: string[]
  /** True when broker `authMutation` mutated the transmitted credential. */
  authMutated: boolean
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
   * H-14: True wire credential provenance (header/cookie names & auth sources, never secret values).
   */
  wireCredentialProvenance?: WireCredentialProvenance
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
    /** H-2: Tenant namespace for per-tenant kill-switch checks. */
    tenantId?: string | null
    /** H-2: Optional kill-switch instance. */
    killSwitch?: GlobalKillSwitch
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

export interface BrokerAuditMeta {
  reason?: string
  method?: string
  path?: string
  persona?: string
}

export type BrokerLoadEventKind =
  | 'broker.target_throttled'
  | 'broker.origin_breaker_open'
  | 'broker.route_breaker_open'
  | 'broker.aggregate_cap_wait'

export interface BrokerLoadEvent {
  kind: BrokerLoadEventKind
  runId: string | null
  origin: string
  targetClass: TargetClass
  status?: number
  statusClass?: TargetLoadStatusClass
  retryAfterSec?: number
  adaptiveRps?: number
  configuredRps?: number
  consecutiveOpens?: number
  backoffMs?: number
  routeTemplate?: string
  bucketKind?: AggregateBucketKind
  bucketKey?: string
  waitMs?: number
  reason: string
  timestamp: number
}

export type Grant = {
  origin?: string
  tier?: CapabilityTier
  maxRpsPerOrigin?: number
  /** Optional live getter for dynamic mid-run RPS updates (survives `{ ...grant }` spreads). */
  getMaxRpsPerOrigin?: () => number
  allowLocalLab?: boolean
  /**
   * R2-16: Optional per-grant `TargetClass` override (`'external' | 'loopback' | 'local_lab'`)
   * forcing load-policy caps (e.g. external caps on loopback fixtures without toggling env-wide
   * `KOVO_ALLOW_LOCAL_LAB`). Takes precedence over `BrokerOptions.targetClassOverride`.
   */
  targetClassOverride?: TargetClass
  personas?: ReadonlyMap<string, ResolvedPersona>
  secrets?: readonly NamedSecret[]
  sandboxWriteAllowlist?: ApprovedEndpointPattern[]
  scopeRevision?: number
  /** Explicit operator-approved non-default target ports (e.g. 8080/8443) for authorized staging origins. */
  allowedPorts?: number[]
  /** H-3: Host-confirmed GraphQL endpoints for read-only GraphQL exceptions. */
  confirmedGraphqlEndpoints?: readonly string[]
  storage?: SecondOrderStore
  canaryBroker?: CanaryBroker
  mintCanary?: (purpose: string, origin?: string) => { httpUrl?: string; url?: string } | null
  canRead: (origin: string) => boolean
  /**
   * v6 Layer-1 three-tier scope + environment contract. When supplied, auth/asset origins are
   * reachable only through their narrow verbs and `prod_readonly`/`staging_isolated` decide
   * mutations without per-request approval. Omitted grants keep legacy v5 behavior exactly.
   */
  scopePolicy?: ScopePolicy
  /** Optional Tier-3 approval policy (`auto_review` | `yolo` | `strict`) when supplied directly. */
  approvalPolicy?: ApprovalPolicy
  /** v7 M4: optional tenant namespace used for tenant-scoped kill-switch checks. */
  tenantId?: string
  /**
   * Durable, route-scoped operator lease (Run approval_leases). A match authorizes the normalized
   * route across probe iterations and replays; it never widens origin scope.
   */
  approvalLeases?: (origin: string, method: string, pathAndQuery: string, personaHandle?: string | null) => boolean
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
  audit: (
    outcome: 'allowed' | 'denied' | 'observed' | 'circuit_open',
    origin: string,
    status?: number,
    meta?: BrokerAuditMeta,
  ) => void
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
  /** Per-run fail-closed cap on dynamically registered redaction secrets (defaults to `resolveRunSafetyBudgets().maxRedactedSecretsPerRun`). */
  maxRedactedSecretsPerRun?: number
  /** Optional planned assignment workload used to scale `RunSafetyBudgets` (including `maxRedactedSecretsPerRun`). */
  maxAssignments?: number
  /** Injectable clock (test-only) used by circuit-breaker accounting. */
  now?: () => number
  /**
   * Layer-1 transport configuration. Merged over `KOVO_HTTP2` / `KOVO_EGRESS_PROXY` /
   * `KOVO_MTLS_*` / `KOVO_USER_AGENT` / `KOVO_AUTHORIZED_HEADERS` (/`KOVO_UA_PROFILE`).
   * Invalid configuration fails closed at construction time.
   */
  transportConfig?: Partial<TransportConfig>
  /** Opt-in turn-aware WebSocket sessions; unset keeps the legacy single-shot probe path. */
  wsSessionEnabled?: boolean
  /**
   * Rate-limited persona re-authentication invoked by the broker on a persona-bound 401.
   * Returning true retries the request once with freshly resolved persona headers.
   */
  reauth?: (personaHandle: string, runId?: string, origin?: string) => Promise<boolean | void>
  /** v7 M4: optional kill-switch instance (defaults to process-wide `globalKillSwitch`). */
  killSwitch?: GlobalKillSwitch
  /** Canonical request admission engine (defaults to `defaultRequestAdmissionEngine`). */
  admissionEngine?: RequestAdmissionEngine
  /** R2-H-19: TTL in ms for per-origin batch/race burst owner locks (defaults to 60_000 ms). */
  batchLockTtlMs?: number
  /** Optional override for the shared external registrable-apex RPS safety ceiling (defaults to `KOVO_EXTERNAL_APEX_MAX_RPS` or `EXTERNAL_APEX_MAX_RPS_CAP`). */
  externalApexMaxRps?: number
  /** R2-16: Optional override for the shared external per-IP aggregate RPS ceiling (defaults to `KOVO_EXTERNAL_IP_MAX_RPS` or 45). */
  externalIpMaxRps?: number
  /** R2-16: Optional override for the shared external per-IP aggregate concurrent in-flight ceiling (defaults to `KOVO_EXTERNAL_IP_MAX_IN_FLIGHT` or 8). */
  externalIpMaxInFlight?: number
  /**
   * R2-16: Optional `TargetClass` override (`'external' | 'loopback' | 'local_lab'`) forcing
   * load-policy enforcement (e.g. external caps on loopback fixtures without toggling env-wide flags).
   */
  targetClassOverride?: TargetClass
  /** R2-16: Structured throttle / breaker / aggregate-cap telemetry callback. */
  onLoadEvent?: (event: BrokerLoadEvent) => void
}

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
const wsGuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
const sessionHandleRegex = /^[a-z0-9_-]{1,32}$/
const csrfCookieNameRegex = /^(?:xsrf-token|csrf[_-]?token|_csrf|csrf)$/i
const csrfInputNameRegex = /^(?:_csrf|csrf[_-]?token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token|_token)$/i
const crossOriginSensitiveHeaders = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-access-token', 'x-session-token',
])
const postToGetContentHeaders = new Set(['content-type', 'content-encoding', 'content-length'])
const canaryUrlRegex = /^\/c\/kovo-canary-[a-f0-9]{24}$/i
/**
 * Cookie names that carry a server-side session handle. Excludes CSRF/tracking names: a stateless
 * double-submit token may legitimately repeat across identities, while a session id may not.
 */
const sessionCookieNameRegex = /^(?![_.-]*(?:csrf|xsrf|_ga|_gid|amplitude|sentry))(?=[^=]*(?:sid|session|sess|jwt|auth|access_token|refresh_token|id_token))[A-Za-z0-9_.-]{1,64}$/i

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
   * Q4: True when this cookie entry was explicitly issued by a server `Set-Cookie` response.
   * Paired with `vaultValueAtWrite` and timestamp checks so the very first server-issued
   * rotation supersedes a stale Persona Vault cookie immediately while untouched Vault seed
   * cookies and fresher post-reauth Vault refreshes win cleanly.
   */
  rotatedFromResponse: boolean
  /** Vault cookie value observed on the request that received this `Set-Cookie`, if any. */
  vaultValueAtWrite?: string
  /** Number of Set-Cookie writes observed for this entry inside the current jar. */
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
  /** Persona that owns every credential in this jar (request-level, never ambient). */
  persona?: string
  scopeRevision: number
  cookies: Map<string, JarCookieEntry>
  csrfTokens: Map<string, StoredCsrfToken>
  /** Active slot-to-secret bindings owned by this jar in `redactedSecretsByRun` for lifecycle-aware release. */
  secretSlots: Map<string, string>
  /** Epoch ms when broker auto-reauth refreshed the owning persona's Vault credential. */
  vaultRefreshedAt?: number
  lastUsedAt: number
}

/**
 * Jar identity: one jar per (worker session, group role, persona, session label).
 *
 * Persona scope is a **request attribute**, never ambient state: `RequestBroker.executeHttp(req)`
 * carries `req.persona` on every call, and the jar it may read or write is derived exclusively from
 * that value. Two personas therefore can never observe each other's Set-Cookie rotations even when
 * a caller passes the same `session` label for both.
 */
function sessionJarKey(assignmentKey: string, role: string, persona: string | undefined, session: string | undefined): string {
  return `${assignmentKey}\0${role}\0${persona ? `p:${persona}` : 'p:'}\0${session ? `s:${session}` : 's:'}`
}

export const DEFAULT_MAX_REDACTED_SECRETS_PER_RUN = RUN_SAFETY_BUDGET_DEFAULTS.maxRedactedSecretsPerRun
export const HARD_MAX_REDACTED_SECRETS_PER_RUN = RUN_SAFETY_BUDGET_HARD_CEILINGS.maxRedactedSecretsPerRun

export interface JarKeyScope {
  runId?: string
  assignmentId?: string
  sessionGroupRole?: string
  persona?: string
  personaHandle?: string
  session?: string
  scopePolicy?: Pick<ScopePolicy, 'runId'>
}

export interface ResolvedJarKey {
  runId: string
  assignmentId: string
  role: string
  persona: string | undefined
  session: string | undefined
  assignmentKey: string
  jarKey: string
}

function normalizeRunKey(runId?: string | null): string {
  const trimmed = typeof runId === 'string' ? runId.trim() : ''
  return trimmed || 'default'
}

/**
 * Single authoritative jar-key resolver shared by HTTP session jars and `sessionCookiesForBrowser()`.
 * Always consults both `req.runId` and `grant?.scopePolicy?.runId` (or `req.scopePolicy?.runId`)
 * so the browser mirror and HTTP transport never disagree.
 */
export function resolveJarKey(
  req: JarKeyScope,
  grant?: Pick<Grant, 'scopePolicy'>,
): ResolvedJarKey {
  const runId = normalizeRunKey(req.runId ?? grant?.scopePolicy?.runId ?? req.scopePolicy?.runId)
  const assignmentId = req.assignmentId ?? 'default'
  const role = req.sessionGroupRole ?? 'default'
  const persona = req.persona ?? req.personaHandle
  const session = req.session
  const assignmentKey = `${runId}\0${assignmentId}`
  const jarKey = sessionJarKey(assignmentKey, role, persona, session)
  return { runId, assignmentId, role, persona, session, assignmentKey, jarKey }
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
        rotatedFromResponse: true,
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

export class RedactionCapacityError extends Error {
  readonly runId: string
  readonly cap: number
  readonly activeCount: number
  constructor(runId: string, cap: number, activeCount: number) {
    super(`Redaction registry capacity (${cap}) exceeded for run "${runId}" (${activeCount} active secrets); failing closed instead of evicting live secrets.`)
    this.name = 'RedactionCapacityError'
    this.runId = runId
    this.cap = cap
    this.activeCount = activeCount
  }
}

/**
 * Probe classes whose payloads legitimately provoke parser/DB/template errors. Only plain
 * 500/501 responses from these are bounded target evidence; origin-down gateway/edge 5xx
 * statuses (`ORIGIN_DOWN_HTTP_STATUSES`) and transport failures are NEVER exempt.
 */
const errorInducingProbePattern = /(?:sqli|ssti|xxe|xpath|ldap|nosql|injection|traversal|deserial|template|expression|parser)/i

function isErrorInducingProbe(probeClass: string | undefined): boolean {
  return Boolean(probeClass && errorInducingProbePattern.test(probeClass))
}

function resolveProbeInduced5xxThreshold(threshold5xx: number): number {
  return Math.max(
    TARGET_LOAD_POLICY_DEFAULTS.minProbeInduced5xxThreshold,
    threshold5xx * TARGET_LOAD_POLICY_DEFAULTS.probeInduced5xxThresholdMultiplier,
  )
}

export function isPublicAddress({ address }: PublicAddress): boolean {
  return EgressGateway.isPublicIpAddress(address)
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

function parseRetryAfterSeconds(headers: IncomingHttpHeaders | undefined, nowMs: number = Date.now()): number | undefined {
  const raw = headers?.['retry-after']
  const value = Array.isArray(raw) ? raw[0] : raw
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed) return undefined
  const maxSec = TARGET_LOAD_POLICY_DEFAULTS.maxRetryAfterSeconds
  const asNumber = Number(trimmed)
  if (Number.isFinite(asNumber) && asNumber >= 0) return Math.min(asNumber, maxSec)
  const asDate = Date.parse(trimmed)
  if (Number.isFinite(asDate)) return Math.min(Math.max(0, Math.ceil((asDate - nowMs) / 1000)), maxSec)
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
      throw new BrokerDenied('Multipart upload blocked by Kovo Hunter destructive-payload denylist.')
    }
    if (containsWebshellSignature(serialized)) {
      throw new BrokerDenied('Multipart upload blocked by Kovo Hunter webshell signature filter.')
    }
    totalBytes += Buffer.byteLength(part.content, 'utf8')
    if (totalBytes > maxMultipartBytes) {
      throw new BrokerDenied(`Multipart upload exceeds Kovo Hunter 256 KiB limit (${totalBytes} bytes).`)
    }
  }

  const boundary = `----KovoBoundary${randomBytes(12).toString('hex')}`
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
      'User-Agent: KovoHunter/3 defensive websocket probe',
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
    tenantId?: string | null
    killSwitch?: GlobalKillSwitch
  },
): Promise<RawHttpResponse> {
  const headers: Record<string, string> = {
    Host: url.host,
    Accept: 'text/html, application/json;q=0.9, */*;q=0.1',
    'Accept-Encoding': 'gzip, deflate, br',
    'User-Agent': 'KovoHunter/2 defensive evidence review',
    ...(options?.headers ?? {}),
  }
  if (options?.body !== undefined && !headers['Content-Type'] && !headers['content-type']) {
    headers['Content-Type'] = 'application/json'
  }
  if (options?.body !== undefined) {
    headers['Content-Length'] = String(Buffer.byteLength(options.body))
  }
  return EgressGateway.egressRawHttp1(url, address, {
    method: options?.method ?? 'GET',
    headers,
    body: options?.body,
    maxBodyBytes: Math.min(options?.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes),
    readBody: options?.readBody ?? false,
    rejectUnauthorized: options?.rejectUnauthorized ?? true,
    signal,
    ...(options?.tenantId !== undefined ? { tenantId: options.tenantId } : {}),
    ...(options?.killSwitch ? { killSwitch: options.killSwitch } : {}),
    extractTls: extractTlsMetadata,
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

function canonicalizeCallerHeaders(
  headers: Record<string, string> | undefined,
  options: ValidateCallerHeadersOptions = {},
): Record<string, string> {
  const checked = validateCallerHeaders(headers, options)
  if (!checked.ok) throw new BrokerDenied(checked.reason)
  return checked.headers
}

function stripRedirectHeaders(
  headers: Record<string, string>,
  crossOrigin: boolean,
  postToGet: boolean,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase()
    if (crossOrigin && crossOriginSensitiveHeaders.has(lower)) continue
    if (postToGet && postToGetContentHeaders.has(lower)) continue
    out[lower] = value
  }
  return out
}

const WIRE_AUTH_HEADER_NAMES = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-session-token',
  'x-csrf-token',
  'x-xsrf-token',
])

const H2_HOP_BY_HOP_HEADERS = new Set([
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

function setHeaderCaseInsensitive(headers: Record<string, string>, key: string, value: string): void {
  const lower = key.toLowerCase()
  for (const existing of Object.keys(headers)) {
    if (existing.toLowerCase() === lower) delete headers[existing]
  }
  headers[key] = value
}

const LOGOUT_PATH_RE = /(?:^|\/)(?:log[-_]?out|sign[-_]?out)(?:\/|$)/i
const PRIVILEGED_PERSONA_RE =
  /(?:^|[^a-z0-9])(?:admin|administrator|owner|root|superadmin|superuser|staff|operator|system|internal|service|moderator|privileged)(?:$|[^a-z0-9])/i
const EPHEMERAL_TOKEN_KEY_RE =
  /^(?:access_?token|auth_?token|id_?token|jwt|jwt_?token|bearer_?token|session_?token|api_?token|token)$/i
const EPHEMERAL_TOKEN_HEADERS = [
  'authorization',
  'x-auth-token',
  'x-access-token',
  'x-jwt-token',
  'x-session-token',
] as const
const MAX_EPHEMERAL_RUNS = 64
const MAX_EPHEMERAL_TOKENS_PER_RUN = 256
const MAX_EPHEMERAL_BODY_SCAN_BYTES = 256 * 1024
const MAX_EPHEMERAL_TEXT_SCAN_BYTES = 64 * 1024

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function isPrivilegedPersona(handle: string | undefined, roleLabel: string | undefined): boolean {
  if (handle && PRIVILEGED_PERSONA_RE.test(handle)) return true
  if (roleLabel && PRIVILEGED_PERSONA_RE.test(roleLabel)) return true
  return false
}

function personaVaultUpdatedAtMs(persona: ResolvedPersona | undefined): number {
  if (!persona) return 0
  return Math.max(
    persona.session?.updatedAt ?? 0,
    persona.sessionMtimeMs ?? 0,
    persona.secretMtimeMs ?? 0,
  )
}

function jarCookieSupersedesVault(
  entry: JarCookieEntry,
  vaultValue: string,
  vaultUpdatedAtMs: number,
  jarVaultRefreshedAtMs: number,
): boolean {
  if (!entry.rotatedFromResponse) return false
  if (entry.value === vaultValue) return false
  if (entry.vaultValueAtWrite !== vaultValue) return false
  if (jarVaultRefreshedAtMs > 0 && entry.setAt < jarVaultRefreshedAtMs) return false
  if (vaultUpdatedAtMs > 0 && Math.floor(vaultUpdatedAtMs) > entry.setAt) return false
  return true
}

function isSignedJwtToken(value: string): boolean {
  if (value.length < 24 || value.length > 8192 || !value.startsWith('eyJ')) return false
  const parts = value.split('.')
  if (parts.length !== 3) return false
  return (
    parts[0]!.length >= 8 &&
    parts[1]!.length >= 8 &&
    parts[2]!.length >= 8 &&
    /^[A-Za-z0-9_-]+$/.test(parts[0]!) &&
    /^[A-Za-z0-9_-]+$/.test(parts[1]!) &&
    /^[A-Za-z0-9_-]+$/.test(parts[2]!)
  )
}

function extractCandidateEphemeralTokens(
  rawHeaders: Record<string, string>,
  rawBody: string,
  mediaType: string,
): string[] {
  const candidates = new Set<string>()
  const push = (raw: string) => {
    if (candidates.size >= 32) return
    const trimmed = raw.trim().replace(/^Bearer\s+/i, '').trim()
    if (trimmed.length < 16 || trimmed.length > 8192 || /[\s\r\n\0]/.test(trimmed)) return
    candidates.add(trimmed)
  }

  for (const name of EPHEMERAL_TOKEN_HEADERS) {
    const val = rawHeaders[name]
    if (val) push(val)
  }

  if (rawBody && rawBody.length <= MAX_EPHEMERAL_BODY_SCAN_BYTES) {
    const lowerMedia = mediaType.toLowerCase()
    const trimmedBody = rawBody.trimStart()
    if (lowerMedia.includes('json') || trimmedBody.startsWith('{') || trimmedBody.startsWith('[')) {
      try {
        const parsed = JSON.parse(rawBody) as unknown
        let visited = 0
        const walk = (node: unknown, depth: number) => {
          if (depth > 6 || visited >= 256 || candidates.size >= 32 || !node) return
          visited += 1
          if (Array.isArray(node)) {
            for (const item of node.slice(0, 64)) walk(item, depth + 1)
            return
          }
          if (typeof node === 'object') {
            for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
              if (candidates.size >= 32) break
              if (typeof v === 'string') {
                if (EPHEMERAL_TOKEN_KEY_RE.test(k) || isSignedJwtToken(v)) {
                  push(v)
                }
              } else if (v && typeof v === 'object') {
                walk(v, depth + 1)
              }
            }
          }
        }
        walk(parsed, 0)
      } catch {
        // Not valid JSON; fall through to linear JWT scan below.
      }
    }
  }

  if (rawBody && candidates.size < 32) {
    const sample = rawBody.length > MAX_EPHEMERAL_TEXT_SCAN_BYTES
      ? rawBody.slice(0, MAX_EPHEMERAL_TEXT_SCAN_BYTES)
      : rawBody
    for (const jwt of scanJwtCandidatesLinear(sample)) {
      if (isSignedJwtToken(jwt)) push(jwt)
      if (candidates.size >= 32) break
    }
  }

  return [...candidates]
}

function buildWireCredentialProvenance(input: {
  outboundHeaders: Record<string, string>
  vaultHeaderNames: readonly string[]
  vaultCookieNames: readonly string[]
  jarCookieNames: readonly string[]
  mergedCookieNames: readonly string[]
  injectedCsrfHeaderName?: string
  personaHandle: string | null
  session: string | null
  authMutated: boolean
  ephemeralObservedAuth?: boolean
}): WireCredentialProvenance {
  const vaultHeaderSet = new Set(input.vaultHeaderNames.map(h => h.toLowerCase()))
  const vaultCookies = [...new Set(input.vaultCookieNames)].sort()
  const jarCookies = [...new Set(input.jarCookieNames)].sort()
  const cookieNames = [...new Set(input.mergedCookieNames)].sort()
  const csrfLower = input.injectedCsrfHeaderName?.toLowerCase()

  const headerNamesSet = new Set<string>()
  const callerAuthSet = new Set<string>()

  for (const key of Object.keys(input.outboundHeaders)) {
    const lower = key.toLowerCase()
    if (lower === 'cookie') {
      if (cookieNames.length > 0) headerNamesSet.add('cookie')
      continue
    }
    if (vaultHeaderSet.has(lower)) {
      headerNamesSet.add(lower)
      continue
    }
    if (csrfLower && lower === csrfLower) {
      headerNamesSet.add(lower)
      continue
    }
    if (WIRE_AUTH_HEADER_NAMES.has(lower)) {
      headerNamesSet.add(lower)
      callerAuthSet.add(lower)
    }
  }

  const vaultHeaders = [...vaultHeaderSet].sort()
  const callerAuthHeaders = [...callerAuthSet].sort()
  const headerNames = [...headerNamesSet].sort()

  const hasPersonaVault = vaultHeaders.length > 0 || vaultCookies.length > 0
  const hasSessionJar = jarCookies.length > 0
  const hasCallerAuth = callerAuthHeaders.length > 0
  const hasEphemeralObserved = hasCallerAuth && input.ephemeralObservedAuth === true && callerAuthSet.has('authorization')

  const sources: WireCredentialProvenance['sources'] = []
  if (hasPersonaVault) sources.push('persona_vault')
  if (hasSessionJar) sources.push('session_jar')
  if (hasEphemeralObserved) {
    sources.push('ephemeral_observed')
  } else if (hasCallerAuth) {
    sources.push('caller_self_minted')
  }
  if (csrfLower && headerNamesSet.has(csrfLower)) sources.push('csrf_bind')

  const source: WireCredentialSource =
    hasPersonaVault && hasSessionJar
      ? 'persona_and_jar'
      : hasPersonaVault
        ? 'persona_vault'
        : hasSessionJar
          ? 'session_jar'
          : hasEphemeralObserved
            ? 'ephemeral_observed'
            : hasCallerAuth
              ? 'caller_self_minted'
              : 'none'

  return {
    authenticated: hasPersonaVault || hasSessionJar || hasCallerAuth,
    source,
    sources,
    personaHandle: hasPersonaVault ? input.personaHandle : null,
    session: input.session,
    headerNames,
    cookieNames,
    vaultCookieNames: vaultCookies,
    jarCookieNames: jarCookies,
    vaultHeaderNames: vaultHeaders,
    callerAuthHeaderNames: callerAuthHeaders,
    authMutated: input.authMutated,
  }
}

function collectSecrets(req: BrokerHttpRequest, grant: Grant): NamedSecret[] {
  const all: NamedSecret[] = []
  if (grant.personas) all.push(...personaSecrets(grant.personas))
  if (grant.secrets) all.push(...grant.secrets)
  if (req.secrets) all.push(...req.secrets)
  return all
}

const MAX_APEX_BUCKETS = TARGET_LOAD_POLICY_DEFAULTS.maxAggregateBuckets
const APEX_BUCKET_IDLE_TTL_MS = TARGET_LOAD_POLICY_DEFAULTS.aggregateBucketIdleTtlMs

export {
  EXTERNAL_APEX_MAX_RPS_CAP,
  EXTERNAL_ORIGIN_MAX_IN_FLIGHT,
  EXTERNAL_ORIGIN_MAX_RPS_CAP,
  isLoopbackOrigin,
  LOOPBACK_ORIGIN_MAX_IN_FLIGHT,
  LOOPBACK_ORIGIN_MAX_RPS_CAP,
}

/**
 * Per-origin concurrent in-flight request ceiling. External origins stay bounded at 4 so remote
 * targets are never hammered; loopback / authorized local-lab origins scale smoothly to 12 workers.
 */
export function brokerPerOriginConcurrencyCap(
  origin: string,
  allowLocalLabOrigin = false,
  env: NodeJS.ProcessEnv = process.env,
  targetClassOverride?: TargetClass,
): number {
  return resolveBrokerPerOriginConcurrencyCap(origin, allowLocalLabOrigin, env, targetClassOverride)
}

/** Per-origin RPS ceiling: polite cap (20) on external hosts, higher ceiling (100) on loopback/local-lab. */
export function brokerPerOriginRpsCap(
  origin: string,
  requestedRps: number,
  allowLocalLabOrigin = false,
  targetClassOverride?: TargetClass,
): number {
  return resolveBrokerPerOriginRpsCap(origin, requestedRps, allowLocalLabOrigin, targetClassOverride)
}

/**
 * Soft aggregate RPS cap shared across all public/external origins under one PSL registrable apex.
 * Configurable via `KOVO_EXTERNAL_APEX_MAX_RPS` (clamped to `[1, 200]`, default `45` req/s).
 */
export function brokerExternalApexRpsCap(
  env: NodeJS.ProcessEnv = process.env,
  overrideRps?: number,
): number {
  return resolveExternalApexRpsCap(env, overrideRps)
}

/**
 * Shared PSL registrable apex key for external origins. Returns null for loopback, authorized
 * local-lab, private-lab, IP-literal, and bare-suffix origins so local targets bypass the external cap.
 */
export function externalApexBucketKey(
  origin: string,
  allowLocalLabOrigin = false,
  targetClassOverride?: TargetClass,
): string | null {
  return resolveExternalApexBucketKey(origin, allowLocalLabOrigin, targetClassOverride)
}

function resolveGrantMaxRps(grant: Grant, fallback: number): number {
  const live = grant.getMaxRpsPerOrigin ? grant.getMaxRpsPerOrigin() : grant.maxRpsPerOrigin
  return typeof live === 'number' && Number.isFinite(live) && live > 0 ? live : fallback
}

type ApexRateBucket = {
  tokens: number
  lastRefill: number
  lastUsed: number
}

type IpAggregateBucket = {
  tokens: number
  lastRefill: number
  lastUsed: number
  inFlight: number
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
  /** R2-H-19: Owner-scoped batch/race lock with TTL so a stalled burst can never leak permanently. */
  batchLock?: { owner: string; expiresAt: number }
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
  private readonly apexBuckets = new Map<string, ApexRateBucket>()
  private readonly activeApexesByRun = new Map<string, Set<string>>()
  private readonly ipBuckets = new Map<string, IpAggregateBucket>()
  private readonly activeIpsByRun = new Map<string, Set<string>>()
  private readonly lastAggregateWaitEventAt = new Map<string, number>()
  private readonly routeCircuits = new Map<string, RouteHealth>()
  private readonly sessionJars = new Map<string, SessionJar>()
  /** Per-run persona-scope mismatch diagnostics (cleared cleanly on `disposeRun`). */
  private readonly personaScopeMismatchesByRun = new Map<string, Array<{ origin: string; expected: string; observed: string; source: string }>>()
  private readonly personaScopeMismatchKeysByRun = new Map<string, Set<string>>()
  /** Per-run map: origin\0cookieName\0valueHash → persona that first presented it (session ownership). */
  private readonly personaSessionOwnersByRun = new Map<string, Map<string, string>>()
  /** Per-run fail-closed redaction registries (never evict live-run secrets; cleared on `disposeRun`). */
  private readonly redactedSecretsByRun = new Map<string, Map<string, NamedSecret>>()
  /** Per-run lifecycle reference counts (`jarRefs` + `pinned`) for registered redaction secrets. */
  private readonly redactedSecretRefsByRun = new Map<string, Map<string, { jarRefs: number; pinned: boolean }>>()
  /** Per-run one-shot high-watermark (>=80%) capacity warning tracker. */
  private readonly redactionCapacityWarnedByRun = new Set<string>()
  /** Per-run flag set if a post-send mutating response overflowed capacity; forces pre-send fail-closed until headroom returns. */
  private readonly redactionCapacitySaturatedByRun = new Set<string>()
  /** Resolved per-run redaction secret cap from `RunSafetyBudgets`. */
  private readonly resolvedMaxRedactedSecretsPerRun: number
  private readonly seenGcbTokens = new Map<string, { probeClass: string; verifyUsed: boolean }>()
  /** Q4: Run-scoped SHA-256 digests of signed/opaque tokens observed in non-privileged in-scope responses (never raw tokens). */
  private readonly ephemeralTokenDigestsByRun = new Map<string, Map<string, { origin: string; observedAt: number }>>()
  private readonly transportConfig: TransportConfig
  private readonly httpTransport: Transport
  private readonly admissionEngine: RequestAdmissionEngine
  private readonly scopeHopAdmissionEngine: RequestAdmissionEngine
  /** Per-run scope revision floor so bumping Run A's scope never invalidates Run B. */
  private readonly latestScopeRevisionByRun = new Map<string, number>()
  private reauthHandler?: BrokerOptions['reauth']

  constructor(options: BrokerOptions = {}) {
    this.options = options
    this.reauthHandler = options.reauth
    const safetyBudgets = resolveRunSafetyBudgets({
      ...(options.maxAssignments !== undefined ? { maxAssignments: options.maxAssignments } : {}),
      ...(options.maxRedactedSecretsPerRun !== undefined
        ? { overrides: { maxRedactedSecretsPerRun: options.maxRedactedSecretsPerRun } }
        : {}),
    })
    this.resolvedMaxRedactedSecretsPerRun = Math.max(
      1,
      Math.min(
        HARD_MAX_REDACTED_SECRETS_PER_RUN,
        safetyBudgets.maxRedactedSecretsPerRun || DEFAULT_MAX_REDACTED_SECRETS_PER_RUN,
      ),
    )
    this.transportConfig = resolveTransportConfig(process.env, options.transportConfig)
    this.httpTransport = options.transport ?? createHttpTransport(this.transportConfig, defaultTransport)
    this.admissionEngine = options.admissionEngine ?? defaultRequestAdmissionEngine
    this.scopeHopAdmissionEngine = new RequestAdmissionEngine({
      scopeHopValidator: (url, redirectHop) => this.validateScopeHop(url, redirectHop),
    })
  }

  getAdmissionEngine(): RequestAdmissionEngine {
    return this.admissionEngine
  }

  /** Attach or replace the broker's persona 401 re-authentication callback. */
  setReauth(reauth: BrokerOptions['reauth']): void {
    this.reauthHandler = reauth
  }

  private getKillSwitch(): GlobalKillSwitch {
    return this.options.killSwitch ?? globalKillSwitch
  }

  private async withKillSwitch<T>(
    signal: AbortSignal,
    grant: Grant,
    fn: (boundSignal: AbortSignal, ks: GlobalKillSwitch) => Promise<T>,
  ): Promise<T> {
    const ks = this.getKillSwitch()
    const tenantId = grant.tenantId ?? null
    const bound = ks.bindSignal(signal, tenantId)
    try {
      return await fn(bound.signal, ks)
    } catch (err) {
      if (bound.signal.aborted && bound.signal.reason instanceof KillSwitchTrippedError) {
        throw bound.signal.reason
      }
      if (ks.isActive(tenantId)) {
        ks.assertAllowed(tenantId)
      }
      throw err
    } finally {
      bound.release()
    }
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

  getRegisteredSecrets(runId?: string): NamedSecret[] {
    if (runId !== undefined) {
      const map = this.redactedSecretsByRun.get(normalizeRunKey(runId))
      return map ? [...map.values()] : []
    }
    const merged = new Map<string, NamedSecret>()
    for (const map of this.redactedSecretsByRun.values()) {
      for (const [value, secret] of map.entries()) {
        if (!merged.has(value)) merged.set(value, secret)
      }
    }
    return [...merged.values()]
  }

  /**
   * Persona-scope mismatches observed on the wire (diagnostics/tests). A mismatch means the
   * exchange cannot have been served the declared persona's scope; it is flagged so no proof can
   * cite it.
   */
  getPersonaScopeMismatches(runId?: string): Array<{ origin: string; expected: string; observed: string; source: string }> {
    if (runId !== undefined) {
      return [...(this.personaScopeMismatchesByRun.get(normalizeRunKey(runId)) ?? [])]
    }
    const out: Array<{ origin: string; expected: string; observed: string; source: string }> = []
    for (const list of this.personaScopeMismatchesByRun.values()) out.push(...list)
    return out
  }

  /**
   * Detect two personas riding one server-side session. The login-minted session cookie is the
   * server's handle on one identity: if a second persona presents the same value for the same origin
   * then at most one of them is served its declared scope. Returns true on a disagreement.
   */
  private notePersonaSessionSharing(input: {
    origin: string
    persona: string
    cookies: ReadonlyMap<string, string>
    runId?: string
    storage?: SecondOrderStore
  }): boolean {
    const runKey = normalizeRunKey(input.runId)
    let owners = this.personaSessionOwnersByRun.get(runKey)
    let shared = false
    for (const [name, value] of input.cookies) {
      if (!sessionCookieNameRegex.test(name) || value.length < 8) continue
      if (!owners) {
        owners = new Map<string, string>()
        this.personaSessionOwnersByRun.set(runKey, owners)
      }
      const key = `${input.origin}\0${name}\0${createHash('sha256').update(value).digest('hex').slice(0, 16)}`
      const owner = owners.get(key)
      if (owner === undefined) {
        if (owners.size >= 4_096) {
          const oldest = owners.keys().next().value
          if (oldest !== undefined) owners.delete(oldest)
        }
        owners.set(key, input.persona)
        continue
      }
      if (owner === input.persona) continue
      shared = true
      this.notePersonaScopeMismatch({
        origin: input.origin,
        expected: input.persona,
        observed: owner,
        source: `vault_session:${name}`,
        runId: runKey,
        ...(input.storage ? { storage: input.storage } : {}),
      })
    }
    return shared
  }

  /**
   * Record a transport-level persona/scope disagreement. Structured event first, then in-memory
   * diagnostics: the caller must treat the exchange as evidence-invalid (never a confirmation).
   */
  private notePersonaScopeMismatch(input: {
    origin: string
    expected: string
    observed: string
    source: string
    runId?: string
    storage?: SecondOrderStore
  }): void {
    const runKey = normalizeRunKey(input.runId)
    const key = `${input.origin}\0${input.expected}\0${input.observed}\0${input.source}`
    let seenKeys = this.personaScopeMismatchKeysByRun.get(runKey)
    if (!seenKeys) {
      seenKeys = new Set<string>()
      this.personaScopeMismatchKeysByRun.set(runKey, seenKeys)
    }
    if (seenKeys.has(key)) return
    seenKeys.add(key)
    let mismatches = this.personaScopeMismatchesByRun.get(runKey)
    if (!mismatches) {
      mismatches = []
      this.personaScopeMismatchesByRun.set(runKey, mismatches)
    }
    mismatches.push({
      origin: input.origin,
      expected: input.expected,
      observed: input.observed,
      source: input.source,
    })
    try {
      const storage = input.storage ?? this.options.storage
      storage?.event?.(
        input.runId && input.runId !== 'default' ? input.runId : null,
        'broker.persona_scope_mismatch',
        `Persona "${input.expected}" presented session state belonging to "${input.observed}"; the exchange is evidence-invalid.`,
        { origin: input.origin, expected: input.expected, observed: input.observed, source: input.source },
      )
    } catch { /* telemetry is best-effort; the exchange is already flagged */ }
  }

  private maxRedactedSecretsPerRun(): number {
    return this.resolvedMaxRedactedSecretsPerRun
  }

  private isMutatingMethod(method: string, body?: string): boolean {
    const upper = method.toUpperCase()
    if (upper === 'GET' || upper === 'HEAD') return false
    if (upper === 'OPTIONS' && (body === undefined || body === '')) return false
    return true
  }

  private emitRedactionCapacityWarningIfNeeded(
    runKey: string,
    activeCount: number,
    cap: number,
    label: string,
    storage?: SecondOrderStore,
  ): void {
    if (cap < 5 || this.redactionCapacityWarnedByRun.has(runKey)) return
    const threshold = Math.ceil(cap * 0.8)
    if (activeCount < threshold) return
    this.redactionCapacityWarnedByRun.add(runKey)
    try {
      const store = storage ?? this.options.storage
      store?.event?.(
        runKey === 'default' ? null : runKey,
        'broker.redaction_capacity_warning',
        `Per-run redaction registry reached ${activeCount}/${cap} active secrets for run "${runKey}".`,
        {
          runId: runKey,
          cap,
          activeCount,
          utilizationPct: Math.round((activeCount / cap) * 100),
          label,
        },
      )
    } catch { /* telemetry is best-effort */ }
  }

  private emitRedactionCapacityExceeded(
    runKey: string,
    activeCount: number,
    cap: number,
    label: string,
    phase: 'pre_send' | 'post_send' | 'post_send_mutating_saturated',
    storage?: SecondOrderStore,
  ): void {
    try {
      const store = storage ?? this.options.storage
      store?.event?.(
        runKey === 'default' ? null : runKey,
        'broker.redaction_capacity_exceeded',
        `Per-run redaction registry cap (${cap}) reached for run "${runKey}"; failing closed instead of evicting live secrets.`,
        {
          runId: runKey,
          cap,
          activeCount,
          label,
          phase,
          degradation: 'redaction_fail_closed',
        },
      )
    } catch { /* telemetry is best-effort; fail-closed error still throws */ }
  }

  /**
   * R4-H-19: Pre-send fail-closed placement guard.
   * Rejects before any wire bytes are sent when the run's redaction registry is already saturated
   * OR when a mutating jar/auth-bound request has zero remaining redaction headroom (preventing
   * post-send `RedactionCapacityError` throws from discarding evidence of mutations already sent).
   */
  private assertRedactionCapacityBeforeSend(
    runKey: string,
    req: BrokerHttpRequest,
    grant: Grant,
    usesRedactionRegistry: boolean,
  ): void {
    if (!usesRedactionRegistry) return
    const runSecrets = this.redactedSecretsByRun.get(runKey)
    const activeCount = runSecrets?.size ?? 0
    const cap = this.maxRedactedSecretsPerRun()
    if (activeCount < cap) {
      this.redactionCapacitySaturatedByRun.delete(runKey)
      return
    }
    const saturated = this.redactionCapacitySaturatedByRun.has(runKey)
    const mutating = this.isMutatingMethod(req.method, req.body)
    if (saturated || mutating) {
      this.emitRedactionCapacityExceeded(
        runKey,
        activeCount,
        cap,
        `pre_send:${req.method}`,
        'pre_send',
        this.options.storage ?? grant.storage,
      )
      throw new RedactionCapacityError(runKey, cap, activeCount)
    }
  }

  private ensureRunRedactionMaps(runKey: string): {
    runSecrets: Map<string, NamedSecret>
    runRefs: Map<string, { jarRefs: number; pinned: boolean }>
  } {
    let runSecrets = this.redactedSecretsByRun.get(runKey)
    if (!runSecrets) {
      runSecrets = new Map<string, NamedSecret>()
      this.redactedSecretsByRun.set(runKey, runSecrets)
    }
    let runRefs = this.redactedSecretRefsByRun.get(runKey)
    if (!runRefs) {
      runRefs = new Map<string, { jarRefs: number; pinned: boolean }>()
      this.redactedSecretRefsByRun.set(runKey, runRefs)
    }
    return { runSecrets, runRefs }
  }

  private registerSecret(
    runId: string,
    label: string,
    value: string | undefined,
    storage?: SecondOrderStore,
  ): void {
    if (!value || value.length < 4) return
    const runKey = normalizeRunKey(runId)
    const { runSecrets, runRefs } = this.ensureRunRedactionMaps(runKey)
    if (runSecrets.has(value)) {
      const existingRef = runRefs.get(value)
      if (existingRef) existingRef.pinned = true
      else runRefs.set(value, { jarRefs: 0, pinned: true })
      return
    }
    const cap = this.maxRedactedSecretsPerRun()
    if (runSecrets.size >= cap) {
      this.emitRedactionCapacityExceeded(runKey, runSecrets.size, cap, label, 'pre_send', storage)
      throw new RedactionCapacityError(runKey, cap, runSecrets.size)
    }
    runSecrets.set(value, { placeholder: `[redacted:${label}]`, value })
    runRefs.set(value, { jarRefs: 0, pinned: true })
    this.emitRedactionCapacityWarningIfNeeded(runKey, runSecrets.size, cap, label, storage)
  }

  private releaseSecretJarRef(runId: string, value: string, retiredSecrets?: NamedSecret[]): void {
    const runKey = normalizeRunKey(runId)
    const runSecrets = this.redactedSecretsByRun.get(runKey)
    const runRefs = this.redactedSecretRefsByRun.get(runKey)
    if (!runSecrets || !runRefs) return
    const existing = runSecrets.get(value)
    if (existing && retiredSecrets) {
      retiredSecrets.push(existing)
    }
    const ref = runRefs.get(value)
    if (!ref) return
    ref.jarRefs = Math.max(0, ref.jarRefs - 1)
    if (ref.jarRefs === 0 && !ref.pinned) {
      runRefs.delete(value)
      runSecrets.delete(value)
      if (runSecrets.size === 0) {
        this.redactedSecretsByRun.delete(runKey)
        this.redactedSecretRefsByRun.delete(runKey)
      }
      if (runSecrets.size < this.maxRedactedSecretsPerRun()) {
        this.redactionCapacitySaturatedByRun.delete(runKey)
      }
    }
  }

  private releaseJarSecretSlot(jar: SessionJar, slotId: string, retiredSecrets?: NamedSecret[]): void {
    const prev = jar.secretSlots.get(slotId)
    if (prev === undefined) return
    jar.secretSlots.delete(slotId)
    this.releaseSecretJarRef(jar.runId, prev, retiredSecrets)
  }

  private releaseAllJarSecrets(jar: SessionJar): void {
    if (jar.secretSlots.size === 0) return
    for (const value of jar.secretSlots.values()) {
      this.releaseSecretJarRef(jar.runId, value)
    }
    jar.secretSlots.clear()
  }

  private deleteSessionJar(jarKey: string): void {
    const jar = this.sessionJars.get(jarKey)
    if (!jar) return
    this.releaseAllJarSecrets(jar)
    this.sessionJars.delete(jarKey)
  }

  /**
   * Lifecycle-aware binding of a jar cookie / CSRF slot to `redactedSecretsByRun`.
   * Replacing an active slot releases the superseded value (unless still referenced by another
   * jar slot or pinned secret) BEFORE checking capacity, so rotating values reuse the active
   * slot cleanly. Returns `false` only when an already-sent mutating response hits genuine cap
   * saturation (recording the value in `transientSecrets` for this response's redaction and
   * tripping `redactionCapacitySaturatedByRun` so the next pre-send fails closed without
   * discarding evidence of the already-sent mutation).
   */
  private bindJarSecretSlot(
    jar: SessionJar,
    slotId: string,
    label: string,
    value: string | undefined,
    opts: {
      storage?: SecondOrderStore
      wasMutating: boolean
      retiredSecrets: NamedSecret[]
      transientSecrets: NamedSecret[]
    },
  ): boolean {
    const prev = jar.secretSlots.get(slotId)
    if (!value || value.length < 4) {
      if (prev !== undefined) this.releaseJarSecretSlot(jar, slotId, opts.retiredSecrets)
      return true
    }
    if (prev === value) return true

    const runKey = normalizeRunKey(jar.runId)
    const cap = this.maxRedactedSecretsPerRun()
    const existingRunSecrets = this.redactedSecretsByRun.get(runKey)
    const existingRunRefs = this.redactedSecretRefsByRun.get(runKey)

    if (existingRunSecrets?.has(value)) {
      if (prev !== undefined) this.releaseJarSecretSlot(jar, slotId, opts.retiredSecrets)
      const ref = existingRunRefs?.get(value)
      if (ref) ref.jarRefs += 1
      else this.ensureRunRedactionMaps(runKey).runRefs.set(value, { jarRefs: 1, pinned: false })
      jar.secretSlots.set(slotId, value)
      return true
    }

    const prevRef = prev !== undefined ? existingRunRefs?.get(prev) : undefined
    const prevWillFree = prev !== undefined && Boolean(prevRef && prevRef.jarRefs <= 1 && !prevRef.pinned)
    const currentSize = existingRunSecrets?.size ?? 0
    const projectedSize = currentSize - (prevWillFree ? 1 : 0)

    if (projectedSize >= cap) {
      if (opts.wasMutating) {
        opts.transientSecrets.push({ placeholder: `[redacted:${label}]`, value })
        this.redactionCapacitySaturatedByRun.add(runKey)
        this.emitRedactionCapacityExceeded(runKey, currentSize, cap, label, 'post_send_mutating_saturated', opts.storage)
        return false
      }
      this.emitRedactionCapacityExceeded(runKey, currentSize, cap, label, 'post_send', opts.storage)
      throw new RedactionCapacityError(runKey, cap, currentSize)
    }

    if (prev !== undefined) {
      this.releaseJarSecretSlot(jar, slotId, opts.retiredSecrets)
    }
    const { runSecrets, runRefs } = this.ensureRunRedactionMaps(runKey)
    runSecrets.set(value, { placeholder: `[redacted:${label}]`, value })
    runRefs.set(value, { jarRefs: 1, pinned: false })
    jar.secretSlots.set(slotId, value)
    this.emitRedactionCapacityWarningIfNeeded(runKey, runSecrets.size, cap, label, opts.storage)
    return true
  }

  resolveJarKey(req: JarKeyScope, grant?: Pick<Grant, 'scopePolicy'>): ResolvedJarKey {
    return resolveJarKey(req, grant)
  }

  private resolveScopeRunKey(
    req?: Pick<BrokerHttpRequest, 'runId'> & { scopePolicy?: Pick<ScopePolicy, 'runId'> },
    grant?: Pick<Grant, 'scopePolicy'>,
  ): string {
    return normalizeRunKey(req?.runId ?? grant?.scopePolicy?.runId ?? req?.scopePolicy?.runId)
  }

  /**
   * Release all per-run broker state (session jars, scope revision floor, persona session
   * ownership/mismatch records, Q4 ephemeral token digests, and per-run redaction secrets).
   */
  disposeRun(runId: string): void {
    const key = normalizeRunKey(runId)
    this.purgeSessionJars(key)
    this.latestScopeRevisionByRun.delete(key)
    this.personaSessionOwnersByRun.delete(key)
    this.personaScopeMismatchesByRun.delete(key)
    this.personaScopeMismatchKeysByRun.delete(key)
    this.ephemeralTokenDigestsByRun.delete(key)
    this.redactedSecretsByRun.delete(key)
    this.redactedSecretRefsByRun.delete(key)
    this.redactionCapacityWarnedByRun.delete(key)
    this.redactionCapacitySaturatedByRun.delete(key)
    const runApexes = this.activeApexesByRun.get(key)
    this.activeApexesByRun.delete(key)
    if (runApexes) {
      for (const apex of runApexes) {
        if (!this.isApexReferencedByAnyRun(apex)) {
          this.apexBuckets.delete(apex)
          this.lastAggregateWaitEventAt.delete(`apex:${apex}`)
        }
      }
    }
    const runIps = this.activeIpsByRun.get(key)
    this.activeIpsByRun.delete(key)
    if (runIps) {
      for (const ipKey of runIps) {
        if (!this.isIpReferencedByAnyRun(ipKey)) {
          const bucket = this.ipBuckets.get(ipKey)
          if (!bucket || bucket.inFlight <= 0) {
            this.ipBuckets.delete(ipKey)
            this.lastAggregateWaitEventAt.delete(`ip:${ipKey}`)
          }
        }
      }
    }
    const now = this.now()
    for (const [apex, bucket] of this.apexBuckets) {
      if (now - bucket.lastUsed >= APEX_BUCKET_IDLE_TTL_MS && !this.isApexReferencedByAnyRun(apex)) {
        this.apexBuckets.delete(apex)
        this.lastAggregateWaitEventAt.delete(`apex:${apex}`)
      }
    }
    for (const [ipKey, bucket] of this.ipBuckets) {
      if (
        bucket.inFlight <= 0 &&
        now - bucket.lastUsed >= APEX_BUCKET_IDLE_TTL_MS &&
        !this.isIpReferencedByAnyRun(ipKey)
      ) {
        this.ipBuckets.delete(ipKey)
        this.lastAggregateWaitEventAt.delete(`ip:${ipKey}`)
      }
    }
  }

  /** Alias for `disposeRun(runId)` to purge all per-run broker state cleanly. */
  purgeRunState(runId: string): void {
    this.disposeRun(runId)
  }

  /** Read-only per-run state counts for diagnostics and disposal verification. */
  getRunStateCounts(runId: string): {
    sessionJars: number
    hasScopeRevision: boolean
    personaSessionOwners: number
    personaScopeMismatches: number
    ephemeralTokenDigests: number
    redactedSecrets: number
  } {
    const key = normalizeRunKey(runId)
    let sessionJars = 0
    for (const jar of this.sessionJars.values()) {
      if (jar.runId === key) sessionJars += 1
    }
    return {
      sessionJars,
      hasScopeRevision: this.latestScopeRevisionByRun.has(key),
      personaSessionOwners: this.personaSessionOwnersByRun.get(key)?.size ?? 0,
      personaScopeMismatches: this.personaScopeMismatchesByRun.get(key)?.length ?? 0,
      ephemeralTokenDigests: this.ephemeralTokenDigestsByRun.get(key)?.size ?? 0,
      redactedSecrets: this.redactedSecretsByRun.get(key)?.size ?? 0,
    }
  }

  revokeOrigin(origin: string, scopeRevision?: number, runId?: string) {
    let normalized: string
    try {
      normalized = new URL(origin).origin
    } catch {
      normalized = origin
    }
    if (scopeRevision !== undefined) {
      const key = normalizeRunKey(runId)
      const prev = this.latestScopeRevisionByRun.get(key) ?? 0
      if (scopeRevision > prev) {
        this.latestScopeRevisionByRun.set(key, scopeRevision)
      }
    }
    this.purgeSessionJars(runId, normalized)
  }

  revokeScope(scopeRevision: number): void
  revokeScope(runId: string, scopeRevision: number): void
  revokeScope(runIdOrRevision: string | number, maybeRevision?: number): void {
    if (typeof runIdOrRevision === 'string') {
      const runId = normalizeRunKey(runIdOrRevision)
      const scopeRevision = maybeRevision ?? 0
      const prev = this.latestScopeRevisionByRun.get(runId) ?? 0
      if (scopeRevision > prev) {
        this.latestScopeRevisionByRun.set(runId, scopeRevision)
      }
      for (const [key, jar] of [...this.sessionJars.entries()]) {
        if (jar.runId === runId && jar.scopeRevision < scopeRevision) {
          this.deleteSessionJar(key)
        }
      }
      return
    }
    // Legacy single-arg signature `revokeScope(scopeRevision)`: updates the `'default'` run
    // floor and evicts stale jars without locking out unrelated named runs.
    const scopeRevision = runIdOrRevision
    const prev = this.latestScopeRevisionByRun.get('default') ?? 0
    if (scopeRevision > prev) {
      this.latestScopeRevisionByRun.set('default', scopeRevision)
    }
    for (const [key, jar] of [...this.sessionJars.entries()]) {
      if (jar.scopeRevision < scopeRevision) {
        this.deleteSessionJar(key)
      }
    }
  }

  purgeSessionJars(runId?: string, origin?: string) {
    const normalizedRunId = runId !== undefined ? normalizeRunKey(runId) : undefined
    if (!normalizedRunId && !origin) {
      for (const jar of this.sessionJars.values()) {
        this.releaseAllJarSecrets(jar)
      }
      this.sessionJars.clear()
      this.ephemeralTokenDigestsByRun.clear()
      return
    }
    if (!origin && normalizedRunId) {
      this.ephemeralTokenDigestsByRun.delete(normalizedRunId)
    } else if (origin) {
      for (const [rKey, tokens] of this.ephemeralTokenDigestsByRun.entries()) {
        if (normalizedRunId && rKey !== normalizedRunId) continue
        for (const [digest, meta] of tokens.entries()) {
          if (meta.origin === origin) tokens.delete(digest)
        }
        if (tokens.size === 0) this.ephemeralTokenDigestsByRun.delete(rKey)
      }
    }
    for (const [key, jar] of [...this.sessionJars.entries()]) {
      if (normalizedRunId && jar.runId !== normalizedRunId) continue
      if (!origin) {
        this.deleteSessionJar(key)
        continue
      }
      let originHost = ''
      try {
        originHost = new URL(origin).hostname.toLowerCase()
      } catch {
        originHost = ''
      }
      for (const [ck, c] of [...jar.cookies.entries()]) {
        const domainScopedToOrigin = !c.hostOnly && originHost !== '' &&
          (c.domain === originHost || originHost.endsWith(`.${c.domain}`))
        if (c.origin === origin || domainScopedToOrigin) {
          this.releaseJarSecretSlot(jar, `cookie:${ck}`)
          jar.cookies.delete(ck)
        }
      }
      for (const tokenKey of [...jar.csrfTokens.keys()]) {
        if (tokenKey.startsWith(`${origin}\0`) || tokenKey === origin) {
          this.releaseJarSecretSlot(jar, `csrf:${tokenKey}`)
          this.releaseJarSecretSlot(jar, `csrf_raw:${tokenKey}`)
          jar.csrfTokens.delete(tokenKey)
        }
      }
    }
  }

  private getOrCreateSessionJar(
    req: BrokerHttpRequest,
    grant: Grant,
  ): SessionJar | undefined {
    // Persona scope is per-request: the jar key carries the persona, so a Set-Cookie rotation is
    // scoped strictly back to the persona that received it.
    const resolved = resolveJarKey(req, grant)
    const { runId, assignmentId, role, persona, assignmentKey, jarKey } = resolved
    // A jar exists only for requests that carry or need session state. Creating one eagerly for
    // every persona read would evict the CSRF/setup jars the probe families rely on.
    if (req.session === undefined && (persona === undefined || req.csrfBind === undefined)) return undefined
    const latestForRun = this.latestScopeRevisionByRun.get(runId) ?? 0
    const effectiveRevision = Math.max(latestForRun, req.scopeRevision ?? grant.scopeRevision ?? 0)

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
        if (victim) this.deleteSessionJar(victim.jarKey)
      }
    }

    const cookies = new Map<string, JarCookieEntry>()
    const csrfTokens = new Map<string, StoredCsrfToken>()
    const secretSlots = new Map<string, string>()

    // Only `setup` jars may seed `control` or `probe` via deep-clone on first access;
    // `control` and `probe` remain strictly isolated from each other.
    if (role === 'control' || role === 'probe') {
      const setupKey = resolveJarKey({ ...req, sessionGroupRole: 'setup' }, grant).jarKey
      const setupJar = this.sessionJars.get(setupKey)
      if (setupJar) {
        for (const [k, v] of setupJar.cookies.entries()) cookies.set(k, { ...v })
        for (const [k, v] of setupJar.csrfTokens.entries()) csrfTokens.set(k, { ...v })
        const runRefs = this.redactedSecretRefsByRun.get(normalizeRunKey(runId))
        for (const [slotId, secretVal] of setupJar.secretSlots.entries()) {
          secretSlots.set(slotId, secretVal)
          const ref = runRefs?.get(secretVal)
          if (ref) ref.jarRefs += 1
        }
      }
    }

    const created: SessionJar = {
      jarKey,
      assignmentKey,
      runId,
      assignmentId,
      role,
      session: req.session ?? persona ?? 'default',
      ...(persona ? { persona } : {}),
      scopeRevision: effectiveRevision,
      cookies,
      csrfTokens,
      secretSlots,
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
    vaultCookiesAtRequest?: ReadonlyMap<string, string>,
    storage?: SecondOrderStore,
    wasMutating = false,
  ): { retiredSecrets: NamedSecret[]; transientSecrets: NamedSecret[] } {
    const retiredSecrets: NamedSecret[] = []
    const transientSecrets: NamedSecret[] = []
    const bindOpts = { storage, wasMutating, retiredSecrets, transientSecrets }
    const maxCookies = Math.max(1, Math.min(this.options.maxCookiesPerJar ?? 32, 64))
    const parsedEntries = parseSetCookieHeaderEntries(response.headers, url)
    const csrfPathPrefix = normalizeCookiePath(undefined, url.pathname)
    const csrfMapKey = `${url.origin}\0${csrfPathPrefix}`

    const evictOldestCsrfIfNeeded = (incomingKey: string) => {
      if (jar.csrfTokens.has(incomingKey)) {
        jar.csrfTokens.delete(incomingKey)
        return
      }
      while (jar.csrfTokens.size >= maxCookies) {
        const oldest = jar.csrfTokens.keys().next().value
        if (oldest === undefined) break
        this.releaseJarSecretSlot(jar, `csrf:${oldest}`, retiredSecrets)
        this.releaseJarSecretSlot(jar, `csrf_raw:${oldest}`, retiredSecrets)
        jar.csrfTokens.delete(oldest)
      }
    }

    for (const item of parsedEntries) {
      const cookieSlot = `cookie:${item.entry.key}`
      if (item.action === 'delete') {
        this.releaseJarSecretSlot(jar, cookieSlot, retiredSecrets)
        jar.cookies.delete(item.entry.key)
        continue
      }
      const existing = jar.cookies.get(item.entry.key)
      if (!existing && jar.cookies.size >= maxCookies) {
        while (jar.cookies.size >= maxCookies) {
          const oldest = jar.cookies.keys().next().value
          if (oldest === undefined) break
          this.releaseJarSecretSlot(jar, `cookie:${oldest}`, retiredSecrets)
          jar.cookies.delete(oldest)
        }
      }
      // Register/replace secret BEFORE persisting cookie so a redaction-cap overflow fails closed.
      const bound = this.bindJarSecretSlot(
        jar,
        cookieSlot,
        `jar:${jar.session}:${item.entry.name}`,
        item.entry.value,
        bindOpts,
      )
      if (!bound) continue
      item.entry.writeCount = (existing?.writeCount ?? 0) + 1
      item.entry.rotatedFromResponse = true
      item.entry.vaultValueAtWrite = vaultCookiesAtRequest?.get(item.entry.name)
      if (existing) {
        jar.cookies.delete(item.entry.key)
      }
      jar.cookies.set(item.entry.key, item.entry)

      if (csrfCookieNameRegex.test(item.entry.name) && item.entry.value) {
        const decodedCsrf = decodeCsrfValue(item.entry.value)
        evictOldestCsrfIfNeeded(csrfMapKey)
        const csrfBound = this.bindJarSecretSlot(
          jar,
          `csrf:${csrfMapKey}`,
          `csrf:${jar.session}:${item.entry.name}`,
          decodedCsrf,
          bindOpts,
        )
        this.releaseJarSecretSlot(jar, `csrf_raw:${csrfMapKey}`, retiredSecrets)
        if (csrfBound) {
          jar.csrfTokens.set(csrfMapKey, {
            value: decodedCsrf,
            sourceKind: 'cookie',
            detectedName: item.entry.name,
            updatedAt: Date.now(),
          })
        }
      }
    }

    // Response-header CSRF sources (double-submit / Next.js / XSRF variants).
    for (const headerName of ['x-csrf-token', 'x-xsrf-token', 'csrf-token', 'x-csrftoken']) {
      const raw = response.headers[headerName]
      const value = Array.isArray(raw) ? raw[0] : raw
      if (!value || !value.trim()) continue
      const token = decodeCsrfValue(value.trim())
      evictOldestCsrfIfNeeded(csrfMapKey)
      const csrfBound = this.bindJarSecretSlot(
        jar,
        `csrf:${csrfMapKey}`,
        `csrf:${jar.session}:${headerName}`,
        token,
        bindOpts,
      )
      this.releaseJarSecretSlot(jar, `csrf_raw:${csrfMapKey}`, retiredSecrets)
      if (csrfBound) {
        jar.csrfTokens.set(csrfMapKey, {
          value: token,
          sourceKind: 'header',
          detectedName: headerName,
          updatedAt: Date.now(),
        })
      }
      break
    }

    const bodyCsrf = extractCsrfFromBody(mediaType, response.body ?? '')
    if (bodyCsrf) {
      const decodedBodyCsrf = decodeCsrfValue(bodyCsrf.value)
      evictOldestCsrfIfNeeded(csrfMapKey)
      const csrfBound = this.bindJarSecretSlot(
        jar,
        `csrf:${csrfMapKey}`,
        `csrf:${jar.session}:${bodyCsrf.detectedName ?? 'token'}`,
        decodedBodyCsrf,
        bindOpts,
      )
      let rawBound = true
      if (bodyCsrf.value !== decodedBodyCsrf) {
        rawBound = this.bindJarSecretSlot(
          jar,
          `csrf_raw:${csrfMapKey}`,
          `csrf:${jar.session}:${bodyCsrf.detectedName ?? 'token'}`,
          bodyCsrf.value,
          bindOpts,
        )
      } else {
        this.releaseJarSecretSlot(jar, `csrf_raw:${csrfMapKey}`, retiredSecrets)
      }
      if (csrfBound && rawBound) {
        jar.csrfTokens.set(csrfMapKey, {
          ...bodyCsrf,
          value: decodedBodyCsrf,
          updatedAt: Date.now(),
        })
      }
    }

    return { retiredSecrets, transientSecrets }
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
    scope: JarKeyScope,
    origin: string,
    grant?: Pick<Grant, 'scopePolicy'>,
  ): BrowserMirrorCookie[] {
    const resolved = resolveJarKey(scope, grant)
    if (!resolved.session && !resolved.persona) return []
    const jar = this.sessionJars.get(resolved.jarKey)
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

  private health(origin: string, capacity = defaultMaxRpsPerOrigin): OriginHealth {
    let state = this.origins.get(origin)
    if (!state) {
      state = {
        errors5xx: [],
        errors429: [],
        tokens: capacity,
        lastRefill: this.now(),
        inFlight: 0,
        consecutiveOpens: 0,
        backoffMs: 0,
        probeInduced5xx: [],
      }
      this.origins.set(origin, state)
    }
    return state
  }

  private resolveTargetClassOverride(grant?: Pick<Grant, 'targetClassOverride'>): TargetClass | undefined {
    return grant?.targetClassOverride ?? this.options.targetClassOverride
  }

  /**
   * R2-16: Resolve a read-only `EffectiveTargetLoadPolicy` snapshot for this broker and optional
   * grant/origin list (reflecting injected `targetClassOverride` and effective aggregate caps).
   */
  resolveEffectiveLoadPolicy(options: {
    origins?: readonly string[]
    grant?: Pick<Grant, 'allowLocalLab' | 'maxRpsPerOrigin' | 'getMaxRpsPerOrigin' | 'targetClassOverride'>
    env?: Readonly<Record<string, string | undefined>>
  } = {}): EffectiveTargetLoadPolicy {
    const grant = options.grant
    const requestedRps = grant
      ? (grant.getMaxRpsPerOrigin ? grant.getMaxRpsPerOrigin() : grant.maxRpsPerOrigin)
      : undefined
    return resolveTargetLoadPolicy({
      env: options.env ?? process.env,
      origins: options.origins,
      allowLocalLab: grant?.allowLocalLab,
      targetClassOverride: this.resolveTargetClassOverride(grant),
      requestedMaxRpsPerOrigin: requestedRps,
      externalApexMaxRps: this.options.externalApexMaxRps,
      externalIpMaxRps: this.options.externalIpMaxRps,
      externalIpMaxInFlight: this.options.externalIpMaxInFlight,
      circuit5xxThreshold: this.options.circuit5xxThreshold,
      circuit429Threshold: this.options.circuit429Threshold,
      circuitWindowMs: this.options.circuitWindowMs,
      circuitBackoffBaseMs: this.options.circuitBackoffBaseMs,
      circuitBackoffMaxMs: this.options.circuitBackoffMaxMs,
    })
  }

  private emitLoadEvent(
    event: Omit<BrokerLoadEvent, 'timestamp'>,
    storage?: SecondOrderStore,
  ): void {
    const fullEvent: BrokerLoadEvent = {
      ...event,
      timestamp: this.now(),
    }
    try {
      this.options.onLoadEvent?.(fullEvent)
    } catch { /* telemetry callback is best-effort */ }
    try {
      const store = storage ?? this.options.storage
      const detail: Record<string, unknown> = {
        origin: fullEvent.origin,
        targetClass: fullEvent.targetClass,
        ...(fullEvent.status !== undefined ? { status: fullEvent.status } : {}),
        ...(fullEvent.statusClass !== undefined ? { statusClass: fullEvent.statusClass } : {}),
        ...(fullEvent.retryAfterSec !== undefined ? { retryAfterSec: fullEvent.retryAfterSec } : {}),
        ...(fullEvent.adaptiveRps !== undefined ? { adaptiveRps: fullEvent.adaptiveRps } : {}),
        ...(fullEvent.configuredRps !== undefined ? { configuredRps: fullEvent.configuredRps } : {}),
        ...(fullEvent.consecutiveOpens !== undefined ? { consecutiveOpens: fullEvent.consecutiveOpens } : {}),
        ...(fullEvent.backoffMs !== undefined ? { backoffMs: fullEvent.backoffMs } : {}),
        ...(fullEvent.routeTemplate !== undefined ? { routeTemplate: fullEvent.routeTemplate } : {}),
        ...(fullEvent.bucketKind !== undefined ? { bucketKind: fullEvent.bucketKind } : {}),
        ...(fullEvent.bucketKey !== undefined ? { bucketKey: fullEvent.bucketKey } : {}),
        ...(fullEvent.waitMs !== undefined ? { waitMs: fullEvent.waitMs } : {}),
      }
      store?.event?.(fullEvent.runId, fullEvent.kind, fullEvent.reason, detail)
    } catch { /* telemetry persistence is best-effort */ }
  }

  private isApexReferencedByAnyRun(apex: string): boolean {
    for (const apexSet of this.activeApexesByRun.values()) {
      if (apexSet.has(apex)) return true
    }
    return false
  }

  private isIpReferencedByAnyRun(ipKey: string): boolean {
    for (const ipSet of this.activeIpsByRun.values()) {
      if (ipSet.has(ipKey)) return true
    }
    return false
  }

  private evictApexBucketsIfNeeded(now: number): void {
    if (this.apexBuckets.size < MAX_APEX_BUCKETS) return
    for (const [apex, bucket] of this.apexBuckets) {
      if (now - bucket.lastUsed >= APEX_BUCKET_IDLE_TTL_MS && !this.isApexReferencedByAnyRun(apex)) {
        this.apexBuckets.delete(apex)
      }
    }
    while (this.apexBuckets.size >= MAX_APEX_BUCKETS) {
      const oldest = this.apexBuckets.keys().next().value
      if (oldest === undefined) break
      this.apexBuckets.delete(oldest)
    }
  }

  private evictIpBucketsIfNeeded(now: number): void {
    if (this.ipBuckets.size < MAX_APEX_BUCKETS) return
    for (const [ipKey, bucket] of this.ipBuckets) {
      if (
        bucket.inFlight <= 0 &&
        now - bucket.lastUsed >= APEX_BUCKET_IDLE_TTL_MS &&
        !this.isIpReferencedByAnyRun(ipKey)
      ) {
        this.ipBuckets.delete(ipKey)
      }
    }
    while (this.ipBuckets.size >= MAX_APEX_BUCKETS) {
      let evicted = false
      for (const [ipKey, bucket] of this.ipBuckets) {
        if (bucket.inFlight <= 0) {
          this.ipBuckets.delete(ipKey)
          evicted = true
          break
        }
      }
      if (!evicted) break
    }
  }

  private apexBucket(apex: string, capacity: number, now: number, runKey?: string): ApexRateBucket {
    let bucket = this.apexBuckets.get(apex)
    if (!bucket) {
      this.evictApexBucketsIfNeeded(now)
      bucket = {
        tokens: capacity,
        lastRefill: now,
        lastUsed: now,
      }
      this.apexBuckets.set(apex, bucket)
    } else {
      this.apexBuckets.delete(apex)
      bucket.lastUsed = now
      this.apexBuckets.set(apex, bucket)
    }
    if (runKey) {
      let runApexes = this.activeApexesByRun.get(runKey)
      if (!runApexes) {
        runApexes = new Set<string>()
        this.activeApexesByRun.set(runKey, runApexes)
      }
      runApexes.add(apex)
    }
    return bucket
  }

  private ipBucket(ipKey: string, capacity: number, now: number, runKey?: string): IpAggregateBucket {
    let bucket = this.ipBuckets.get(ipKey)
    if (!bucket) {
      this.evictIpBucketsIfNeeded(now)
      bucket = {
        tokens: capacity,
        lastRefill: now,
        lastUsed: now,
        inFlight: 0,
      }
      this.ipBuckets.set(ipKey, bucket)
    } else {
      this.ipBuckets.delete(ipKey)
      bucket.lastUsed = now
      this.ipBuckets.set(ipKey, bucket)
    }
    if (runKey) {
      let runIps = this.activeIpsByRun.get(runKey)
      if (!runIps) {
        runIps = new Set<string>()
        this.activeIpsByRun.set(runKey, runIps)
      }
      runIps.add(ipKey)
    }
    return bucket
  }

  /** Read-only count of active external registrable-apex rate buckets (diagnostics/tests). */
  getApexBucketCount(): number {
    return this.apexBuckets.size
  }

  /** Read-only count of active external per-IP aggregate rate/concurrency buckets (diagnostics/tests). */
  getIpBucketCount(): number {
    return this.ipBuckets.size
  }

  /** Read-only aggregate in-flight count for an external IP bucket (diagnostics/tests). */
  getIpInFlight(ipAddress: string): number {
    const key = normalizeIpBucketKey(ipAddress)
    return key ? (this.ipBuckets.get(key)?.inFlight ?? 0) : 0
  }

  private isBatchLockActive(state: OriginHealth, now = this.now()): boolean {
    if (!state.batchLock) return false
    if (state.batchLock.expiresAt <= now) {
      state.batchLock = undefined
      return false
    }
    return true
  }

  private acquireBatchLock(origin: string, defaultRps: number, owner: string, ttlMs: number): void {
    const state = this.health(origin, defaultRps)
    const now = this.now()
    if (this.isBatchLockActive(state, now)) {
      throw new BrokerDenied(`Another synchronized batch is already running for ${origin}.`)
    }
    state.batchLock = { owner, expiresAt: now + Math.max(1, ttlMs) }
  }

  private releaseBatchLock(origin: string, owner: string): void {
    const state = this.origins.get(origin)
    if (state?.batchLock?.owner === owner) {
      state.batchLock = undefined
    }
  }

  /** Read-only per-origin in-flight slot count (diagnostics/tests). */
  getOriginInFlight(origin: string): number {
    return this.origins.get(origin)?.inFlight ?? 0
  }

  /** Read-only per-origin batch lock state respecting owner TTL (diagnostics/tests). */
  isOriginBatchLocked(origin: string): boolean {
    const state = this.origins.get(origin)
    return state ? this.isBatchLockActive(state) : false
  }

  /** Origin-wide circuit (connection resets/timeouts/global 502–504 & 520–526/429 exhaustion). */
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
      this.apexBuckets.clear()
      this.activeApexesByRun.clear()
      this.ipBuckets.clear()
      this.activeIpsByRun.clear()
      this.lastAggregateWaitEventAt.clear()
      this.routeCircuits.clear()
    }
  }

  /**
   * Per-origin exponential backoff. A first trip waits `base`; each consecutive re-trip doubles
   * the wait up to `max`, after which the circuit half-opens automatically (see `isCircuitOpen`).
   * A successful recovery response resets the sequence to zero.
   */
  private cooldownMs(consecutiveOpens: number): number {
    const base = Math.max(
      1,
      this.options.circuitCooldownMs ??
        this.options.circuitBackoffBaseMs ??
        TARGET_LOAD_POLICY_DEFAULTS.circuitBackoffBaseMs,
    )
    const max = Math.max(
      base,
      this.options.circuitBackoffMaxMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitBackoffMaxMs,
    )
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

  private recordRouteStatus(
    origin: string,
    routeTemplate: string,
    status: number,
    audit: Grant['audit'],
    meta?: {
      runId?: string | null
      targetClass?: TargetClass
      storage?: SecondOrderStore
    },
  ) {
    const key = `${origin}\0${routeTemplate}`
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitWindowMs
    const threshold = this.options.circuit5xxThreshold ?? TARGET_LOAD_POLICY_DEFAULTS.circuit5xxThreshold
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
        const reason = `Route ${routeTemplate} observed ${threshold}+ HTTP 5xx responses; cooling down ${Math.round(route.cooldownMs / 1000)}s (half-open).`
        audit('circuit_open', origin, status)
        this.emitLoadEvent(
          {
            kind: 'broker.route_breaker_open',
            runId: meta?.runId ?? null,
            origin,
            targetClass: meta?.targetClass ?? classifyTargetClass(origin),
            status,
            statusClass: classifyTargetLoadStatus(status),
            routeTemplate,
            consecutiveOpens: route.consecutiveOpens,
            backoffMs: route.cooldownMs,
            reason,
          },
          meta?.storage,
        )
        throw new BrokerCircuitOpen(origin, reason)
      }
    } else if (status < 500) {
      // Healthy response: close a half-open route and decay the failure window.
      route.failures = []
      route.halfOpen = false
      route.consecutiveOpens = 0
    }
  }

  private recordTransportFailure(
    origin: string,
    audit: Grant['audit'],
    meta?: {
      runId?: string | null
      targetClass?: TargetClass
      storage?: SecondOrderStore
    },
  ) {
    const state = this.health(origin)
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitWindowMs
    const threshold = this.options.circuit5xxThreshold ?? TARGET_LOAD_POLICY_DEFAULTS.circuit5xxThreshold
    state.errors5xx = state.errors5xx.filter(ts => now - ts < windowMs)
    state.errors5xx.push(now)
    if (state.errors5xx.length >= threshold) {
      state.openReason = `Observed ${state.errors5xx.length} connection resets/timeouts within ${Math.round(windowMs / 1000)}s.`
      state.consecutiveOpens += 1
      state.backoffMs = this.cooldownMs(state.consecutiveOpens)
      state.openUntil = now + state.backoffMs
      audit('circuit_open', origin)
      this.emitLoadEvent(
        {
          kind: 'broker.origin_breaker_open',
          runId: meta?.runId ?? null,
          origin,
          targetClass: meta?.targetClass ?? classifyTargetClass(origin),
          statusClass: 'origin_down',
          consecutiveOpens: state.consecutiveOpens,
          backoffMs: state.backoffMs,
          reason: state.openReason,
        },
        meta?.storage,
      )
      throw new BrokerCircuitOpen(origin, state.openReason)
    }
  }

  private async acquireSlot(
    origin: string,
    maxRps: number | (() => number),
    signal: AbortSignal,
    bypassConcurrency = false,
    routeTemplate?: string,
    localLab = false,
    runKey?: string,
    slotOptions?: {
      resolvedIp?: string
      targetClassOverride?: TargetClass
      storage?: SecondOrderStore
    },
  ): Promise<() => void> {
    const targetClassOverride = slotOptions?.targetClassOverride ?? this.options.targetClassOverride
    const targetClass = classifyTargetClass(origin, {
      allowLocalLab: localLab,
      targetClassOverride,
    })
    const inFlightCap = brokerPerOriginConcurrencyCap(origin, localLab, process.env, targetClassOverride)
    const readConfiguredRps = () =>
      brokerPerOriginRpsCap(
        origin,
        typeof maxRps === 'function' ? maxRps() : maxRps,
        localLab,
        targetClassOverride,
      )
    const apexKey = externalApexBucketKey(origin, localLab, targetClassOverride)
    let fallbackHostIp: string | null = null
    if (!slotOptions?.resolvedIp && targetClass === 'external') {
      try {
        fallbackHostIp = new URL(origin).hostname
      } catch { /* ignore invalid origin */ }
    }
    const ipKey = targetClass === 'external'
      ? normalizeIpBucketKey(slotOptions?.resolvedIp ?? fallbackHostIp)
      : null
    const readApexRps = () => brokerExternalApexRpsCap(process.env, this.options.externalApexMaxRps)
    const readIpRps = () => resolveExternalIpRpsCap(process.env, this.options.externalIpMaxRps)
    const readIpInFlightCap = () => resolveExternalIpConcurrencyCap(process.env, this.options.externalIpMaxInFlight)
    const telemetryRunId = runKey && runKey !== 'default' ? runKey : null
    const state = this.health(origin, readConfiguredRps())
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
      const now = this.now()
      const configuredRps = readConfiguredRps()
      const rps = Math.max(1, Math.min(configuredRps, state.adaptiveRps ?? configuredRps))
      const elapsedSec = Math.max(0, (now - state.lastRefill) / 1000)
      state.tokens = Math.min(rps, state.tokens + elapsedSec * rps)
      state.lastRefill = now

      let apexBucket: ApexRateBucket | undefined
      let apexRps = 0
      if (apexKey) {
        apexRps = readApexRps()
        apexBucket = this.apexBucket(apexKey, apexRps, now, runKey)
        const apexElapsedSec = Math.max(0, (now - apexBucket.lastRefill) / 1000)
        apexBucket.tokens = Math.min(apexRps, apexBucket.tokens + apexElapsedSec * apexRps)
        apexBucket.lastRefill = now
      }

      let ipBucket: IpAggregateBucket | undefined
      let ipRps = 0
      let ipInFlightCap = 0
      if (ipKey) {
        ipRps = readIpRps()
        ipInFlightCap = readIpInFlightCap()
        ipBucket = this.ipBucket(ipKey, ipRps, now, runKey)
        const ipElapsedSec = Math.max(0, (now - ipBucket.lastRefill) / 1000)
        ipBucket.tokens = Math.min(ipRps, ipBucket.tokens + ipElapsedSec * ipRps)
        ipBucket.lastRefill = now
      }

      const retryAfterWait = state.retryAfterUntil !== undefined ? state.retryAfterUntil - now : 0
      const concurrencyOk = bypassConcurrency || state.inFlight < inFlightCap
      const apexTokensOk = !apexBucket || apexBucket.tokens >= 1
      const ipTokensOk = !ipBucket || ipBucket.tokens >= 1
      const ipConcurrencyOk = bypassConcurrency || !ipBucket || ipBucket.inFlight < ipInFlightCap
      if (
        retryAfterWait <= 0 &&
        concurrencyOk &&
        state.tokens >= 1 &&
        apexTokensOk &&
        ipTokensOk &&
        ipConcurrencyOk
      ) {
        state.tokens -= 1
        if (apexBucket) apexBucket.tokens -= 1
        if (ipBucket) {
          ipBucket.tokens -= 1
          ipBucket.inFlight += 1
        }
        state.inFlight += 1
        const acquiredIpBucket = ipBucket
        let released = false
        return () => {
          if (released) return
          released = true
          state.inFlight = Math.max(0, state.inFlight - 1)
          if (acquiredIpBucket) {
            acquiredIpBucket.inFlight = Math.max(0, acquiredIpBucket.inFlight - 1)
          }
        }
      }

      let waitMs = 40
      let aggregateWaitKind: AggregateBucketKind | null = null
      let aggregateWaitKey: string | null = null
      if (retryAfterWait > 0) {
        waitMs = Math.min(1_000, Math.max(50, retryAfterWait))
      } else {
        const originTokenWait = state.tokens < 1
          ? Math.min(250, Math.max(20, Math.ceil(((1 - state.tokens) / rps) * 1000)))
          : 0
        const apexTokenWait = apexBucket && apexBucket.tokens < 1
          ? Math.min(250, Math.max(20, Math.ceil(((1 - apexBucket.tokens) / apexRps) * 1000)))
          : 0
        const ipTokenWait = ipBucket && ipBucket.tokens < 1
          ? Math.min(250, Math.max(20, Math.ceil(((1 - ipBucket.tokens) / ipRps) * 1000)))
          : 0
        const tokenWait = Math.max(originTokenWait, apexTokenWait, ipTokenWait)
        if (tokenWait > 0) waitMs = tokenWait
        if (ipBucket && (!ipTokensOk || !ipConcurrencyOk)) {
          aggregateWaitKind = 'ip'
          aggregateWaitKey = ipKey
        } else if (apexBucket && !apexTokensOk) {
          aggregateWaitKind = 'apex'
          aggregateWaitKey = apexKey
        }
      }
      if (aggregateWaitKind && aggregateWaitKey) {
        const dedupeKey = `${aggregateWaitKind}:${aggregateWaitKey}`
        const lastEmitted = this.lastAggregateWaitEventAt.get(dedupeKey) ?? -Infinity
        if (now - lastEmitted >= 500) {
          this.lastAggregateWaitEventAt.set(dedupeKey, now)
          this.emitLoadEvent(
            {
              kind: 'broker.aggregate_cap_wait',
              runId: telemetryRunId,
              origin,
              targetClass,
              bucketKind: aggregateWaitKind,
              bucketKey: aggregateWaitKey,
              waitMs,
              reason: `Pacing request for ${origin} against shared external ${aggregateWaitKind} bucket "${aggregateWaitKey}" (${waitMs}ms).`,
            },
            slotOptions?.storage,
          )
        }
      }
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
      runId?: string | null
      targetClass?: TargetClass
      storage?: SecondOrderStore
    },
  ) {
    const state = this.health(origin, meta?.configuredRps ?? defaultMaxRpsPerOrigin)
    const now = this.now()
    const windowMs = this.options.circuitWindowMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitWindowMs
    const threshold5xx = this.options.circuit5xxThreshold ?? TARGET_LOAD_POLICY_DEFAULTS.circuit5xxThreshold
    const threshold429 = this.options.circuit429Threshold ?? TARGET_LOAD_POLICY_DEFAULTS.circuit429Threshold
    const targetClass = meta?.targetClass ?? classifyTargetClass(origin, {
      targetClassOverride: this.options.targetClassOverride,
    })
    const statusClass = classifyTargetLoadStatus(status)
    state.errors5xx = state.errors5xx.filter(ts => now - ts < windowMs)
    state.errors429 = state.errors429.filter(ts => now - ts < windowMs)
    state.probeInduced5xx = state.probeInduced5xx.filter(ts => now - ts < windowMs)

    if (statusClass === 'throttled') {
      const retryAfter = parseRetryAfterSeconds(meta?.headers, now)
      if (retryAfter !== undefined && retryAfter > 0) {
        state.retryAfterUntil = now + retryAfter * 1000
      }
      const configured = Math.max(1, meta?.configuredRps ?? defaultMaxRpsPerOrigin)
      state.adaptiveRps = Math.max(1, Math.floor((state.adaptiveRps ?? configured) / 2))
      state.errors429.push(now)
      this.emitLoadEvent(
        {
          kind: 'broker.target_throttled',
          runId: meta?.runId ?? null,
          origin,
          targetClass,
          status,
          statusClass,
          ...(retryAfter !== undefined ? { retryAfterSec: retryAfter } : {}),
          adaptiveRps: state.adaptiveRps,
          configuredRps: configured,
          reason: retryAfter !== undefined && retryAfter > 0
            ? `Target ${origin} returned HTTP ${status} (Retry-After=${retryAfter}s; adaptiveRps=${state.adaptiveRps}/${configured}).`
            : `Target ${origin} returned HTTP ${status} (adaptiveRps=${state.adaptiveRps}/${configured}).`,
        },
        meta?.storage,
      )
      if (state.errors429.length >= threshold429) {
        state.openReason = `Observed ${state.errors429.length} HTTP 429 rate-limit responses within ${Math.round(windowMs / 1000)}s.`
        state.consecutiveOpens += 1
        state.backoffMs = this.cooldownMs(state.consecutiveOpens)
        state.openUntil = now + state.backoffMs
        audit('circuit_open', origin, status)
        this.emitLoadEvent(
          {
            kind: 'broker.origin_breaker_open',
            runId: meta?.runId ?? null,
            origin,
            targetClass,
            status,
            statusClass,
            ...(retryAfter !== undefined ? { retryAfterSec: retryAfter } : {}),
            consecutiveOpens: state.consecutiveOpens,
            backoffMs: state.backoffMs,
            reason: state.openReason,
          },
          meta?.storage,
        )
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
      return
    }

    // Global gateway/availability/edge origin-down failures (502–504 and Cloudflare 520–526)
    // ALWAYS keep origin-wide protection regardless of worker-declared `probeClass` so dead or
    // edge-failing origins trip cleanly even during active injection phases.
    if (statusClass === 'origin_down') {
      state.errors5xx.push(now)
      if (state.errors5xx.length >= threshold5xx) {
        state.openReason = `Observed ${state.errors5xx.length} HTTP ${status} responses within ${Math.round(windowMs / 1000)}s.`
        state.consecutiveOpens += 1
        state.backoffMs = this.cooldownMs(state.consecutiveOpens)
        state.openUntil = now + state.backoffMs
        audit('circuit_open', origin, status)
        this.emitLoadEvent(
          {
            kind: 'broker.origin_breaker_open',
            runId: meta?.runId ?? null,
            origin,
            targetClass,
            status,
            statusClass,
            consecutiveOpens: state.consecutiveOpens,
            backoffMs: state.backoffMs,
            reason: state.openReason,
          },
          meta?.storage,
        )
        throw new BrokerCircuitOpen(origin, state.openReason)
      }
      return
    }

    // Only plain 500/501 responses from error-inducing probes are treated as bounded target
    // evidence — NEVER origin-down statuses (502–504, 520–526) or transport failures. Enforce a
    // bounded per-window cap so sustained 500/501 storms still open the route breaker.
    if (
      statusClass === 'transient' &&
      PROBE_INDUCED_EXEMPT_HTTP_STATUSES.has(status) &&
      isErrorInducingProbe(meta?.probeClass)
    ) {
      const routeTemplate = meta?.routeTemplate ?? routeTemplateForPath('/')
      const key = `${origin}\0${routeTemplate}`
      const existingRoute = this.routeCircuits.get(key)
      const probeInducedThreshold = resolveProbeInduced5xxThreshold(threshold5xx)
      state.probeInduced5xx.push(now)
      if (existingRoute?.halfOpen || state.probeInduced5xx.length >= probeInducedThreshold) {
        const route = existingRoute ?? {
          failures: [],
          cooldownMs: this.cooldownMs(1),
          halfOpen: false,
          consecutiveOpens: 0,
        }
        if (!existingRoute) this.routeCircuits.set(key, route)
        route.consecutiveOpens += 1
        route.cooldownMs = this.cooldownMs(route.consecutiveOpens)
        route.openUntil = now + route.cooldownMs
        route.halfOpen = false
        route.failures = []
        const reason = `Route ${routeTemplate} exceeded probe-induced 5xx budget (${state.probeInduced5xx.length}/${probeInducedThreshold} within ${Math.round(windowMs / 1000)}s); cooling down ${Math.round(route.cooldownMs / 1000)}s (half-open).`
        audit('circuit_open', origin, status)
        this.emitLoadEvent(
          {
            kind: 'broker.route_breaker_open',
            runId: meta?.runId ?? null,
            origin,
            targetClass,
            status,
            statusClass,
            routeTemplate,
            consecutiveOpens: route.consecutiveOpens,
            backoffMs: route.cooldownMs,
            reason,
          },
          meta?.storage,
        )
        throw new BrokerCircuitOpen(origin, reason)
      }
      return
    }

    if (statusClass === 'transient') {
      const routeTemplate = meta?.routeTemplate ?? routeTemplateForPath('/')
      this.recordRouteStatus(origin, routeTemplate, status, audit, {
        runId: meta?.runId ?? null,
        targetClass,
        storage: meta?.storage,
      })
      return
    }

    // Healthy response: recover an adaptive RPS cap toward the configured ceiling.
    if (statusClass === 'healthy') {
      // A real success closes the origin breaker and restarts the backoff sequence.
      state.consecutiveOpens = 0
      state.backoffMs = 0
      if (state.openUntil === undefined || now >= state.openUntil) {
        state.openReason = undefined
        state.openUntil = undefined
      }
      const configured = Math.max(1, meta?.configuredRps ?? defaultMaxRpsPerOrigin)
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

  private collectVaultSecretDigests(req: BrokerHttpRequest, grant: Grant): Set<string> {
    const digests = new Set<string>()
    const addSecret = (raw: string | undefined) => {
      if (!raw || raw.length < 8) return
      digests.add(sha256Hex(raw))
      const stripped = raw.replace(/^Bearer\s+/i, '').trim()
      if (stripped && stripped !== raw && stripped.length >= 8) {
        digests.add(sha256Hex(stripped))
      }
    }
    for (const s of collectSecrets(req, grant)) addSecret(s.value)
    for (const s of this.getRegisteredSecrets(this.resolveScopeRunKey(req, grant))) addSecret(s.value)
    return digests
  }

  private observeEphemeralResponseTokens(input: {
    req: BrokerHttpRequest
    grant: Grant
    url: URL
    status: number
    rawResponseHeaders: Record<string, string>
    rawBody: string
    mediaType: string
    includePersona: boolean
    personaHandle: string | undefined
    effectiveSecrets: readonly NamedSecret[]
  }): void {
    if (input.status < 200 || input.status >= 400) return
    if (input.includePersona && input.personaHandle) {
      const persona = input.grant.personas?.get(input.personaHandle)
      if (isPrivilegedPersona(input.personaHandle, persona?.roleLabel)) return
    }
    const candidates = extractCandidateEphemeralTokens(input.rawResponseHeaders, input.rawBody, input.mediaType)
    if (candidates.length === 0) return

    const vaultDigests = new Set<string>()
    for (const s of input.effectiveSecrets) {
      if (!s.value || s.value.length < 8) continue
      vaultDigests.add(sha256Hex(s.value))
      const stripped = s.value.replace(/^Bearer\s+/i, '').trim()
      if (stripped && stripped !== s.value && stripped.length >= 8) {
        vaultDigests.add(sha256Hex(stripped))
      }
    }

    const runKey = this.resolveScopeRunKey(input.req, input.grant)
    let runTokens = this.ephemeralTokenDigestsByRun.get(runKey)
    if (!runTokens) {
      while (this.ephemeralTokenDigestsByRun.size >= MAX_EPHEMERAL_RUNS) {
        const oldestRun = this.ephemeralTokenDigestsByRun.keys().next().value
        if (oldestRun === undefined) break
        this.ephemeralTokenDigestsByRun.delete(oldestRun)
      }
      runTokens = new Map()
      this.ephemeralTokenDigestsByRun.set(runKey, runTokens)
    } else {
      // Refresh run LRU order
      this.ephemeralTokenDigestsByRun.delete(runKey)
      this.ephemeralTokenDigestsByRun.set(runKey, runTokens)
    }

    const now = Date.now()
    for (const token of candidates) {
      const digest = sha256Hex(token)
      // H-8: Never allow a Vault/pre-seeded persona secret to enter the ephemeral caller channel.
      if (vaultDigests.has(digest)) continue
      if (runTokens.has(digest)) {
        runTokens.delete(digest)
      } else if (runTokens.size >= MAX_EPHEMERAL_TOKENS_PER_RUN) {
        const oldest = runTokens.keys().next().value
        if (oldest !== undefined) runTokens.delete(oldest)
      }
      runTokens.set(digest, { origin: input.url.origin, observedAt: now })
    }
  }

  private isEphemeralTokenAuthorized(
    runKey: string,
    tokenDigestSha256: string,
    req: BrokerHttpRequest,
    grant: Grant,
  ): boolean {
    const runTokens = this.ephemeralTokenDigestsByRun.get(runKey)
    if (!runTokens || !runTokens.has(tokenDigestSha256)) return false
    // H-8 defense-in-depth: refuse even if a Vault secret was added/rotated after observation.
    const vaultDigests = this.collectVaultSecretDigests(req, grant)
    if (vaultDigests.has(tokenDigestSha256)) return false
    return true
  }

  private shouldAutoReauthOnResponse(
    response: RawHttpResponse,
    url: URL,
    personaHandle: string,
    grant: Grant,
  ): boolean {
    const persona = grant.personas?.get(personaHandle)
    const signal = detectSessionExpiry({
      status: response.status,
      headers: response.headers,
      body: response.body,
      requestOrigin: url.origin,
      loginUrl: persona?.loginConfig?.loginUrl ?? null,
    })
    if (!signal.expired) return false
    // Do not auto-reauth an intentional logout/signout redirect back to /login.
    if (
      (signal.reason === 'login_redirect' || signal.reason === 'clerk_signed_out') &&
      LOGOUT_PATH_RE.test(url.pathname)
    ) {
      return false
    }
    return true
  }

  private clearRefreshedJarCookies(
    jar: SessionJar | undefined,
    refreshedHeaders: Record<string, string> | null,
  ): void {
    if (!jar) return
    jar.vaultRefreshedAt = Date.now()
    if (!refreshedHeaders) return
    const cookieHeader = Object.entries(refreshedHeaders).find(([k]) => k.toLowerCase() === 'cookie')?.[1]
    if (!cookieHeader) return
    const refreshedNames = new Set(parseCookieHeaderPairs(cookieHeader).keys())
    for (const [key, entry] of [...jar.cookies.entries()]) {
      if (refreshedNames.has(entry.name)) {
        this.releaseJarSecretSlot(jar, `cookie:${key}`)
        jar.cookies.delete(key)
      }
    }
  }

  private toAdmissionRequest(
    req: BrokerHttpRequest,
    opts: { raceBurst?: boolean; kind?: 'http' | 'http2' } = {},
    grant?: Grant,
  ): AdmissionRequest {
    const kind = opts.kind ?? 'http'
    const stripPseudoHeaders = kind === 'http2'
    const runKey = this.resolveScopeRunKey(req, grant)
    const isAuthorizedEphemeralBearer = grant
      ? (digest: string) => this.isEphemeralTokenAuthorized(runKey, digest, req, grant)
      : undefined
    return {
      kind,
      origin: req.origin,
      method: req.method,
      pathAndQuery: req.pathAndQuery,
      headers: req.headers,
      body: req.body,
      multipartParts: req.multipartParts,
      personaHandle: req.persona ?? req.personaHandle ?? null,
      authMutation: req.authMutation,
      scopeHook: req.scopeHook ?? null,
      stripPseudoHeaders,
      ...(isAuthorizedEphemeralBearer ? { isAuthorizedEphemeralBearer } : {}),
      isRaceBurst: opts.raceBurst === true,
      runId: req.runId,
      assignmentId: req.assignmentId,
    }
  }

  private enforceAdmission(
    decision: AdmissionDecision,
    req: { pathAndQuery: string; persona?: string; secrets?: readonly NamedSecret[]; runId?: string },
    grant: Grant,
  ): asserts decision is AdmissionDecision & { outcome: 'allow'; normalizedOrigin: string; parsedUrl: URL } {
    if (decision.outcome === 'allow') return
    if (decision.outcome === 'require_approval') {
      if (decision.matchedRule === 'tier3_redirect_approval_required' && decision.normalizedOrigin) {
        this.auditDenied(
          grant,
          decision.normalizedOrigin,
          {
            reason: decision.reason,
            method: decision.normalizedMethod,
            path: req.pathAndQuery,
            ...(req.persona ? { persona: req.persona } : {}),
          },
          req.secrets,
          req.runId,
        )
      }
      throw new BrokerApprovalRequired(decision.normalizedOrigin!, decision.normalizedMethod, req.pathAndQuery)
    }
    if (
      decision.normalizedOrigin &&
      (decision.reasonCode === 'out_of_scope' ||
        decision.reasonCode === 'port_not_allowed' ||
        decision.reasonCode === 'protocol_not_allowed')
    ) {
      this.purgeSessionJars(req.runId ?? grant.scopePolicy?.runId ?? undefined, decision.normalizedOrigin)
    }
    if (
      decision.normalizedOrigin &&
      decision.reasonCode !== 'tier_offline' &&
      decision.reasonCode !== 'malformed_origin'
    ) {
      this.auditDenied(
        grant,
        decision.normalizedOrigin,
        {
          reason: decision.reason,
          method: decision.normalizedMethod,
          path: req.pathAndQuery,
          ...(req.persona ? { persona: req.persona } : {}),
        },
        req.secrets,
        req.runId,
      )
    }
    throw new BrokerDenied(decision.reason)
  }

  private auditDenied(
    grant: Grant,
    origin: string,
    meta: BrokerAuditMeta,
    extraSecrets?: readonly NamedSecret[],
    runId?: string,
  ): void {
    const scopeRunKey = this.resolveScopeRunKey(runId ? { runId } : undefined, grant)
    const effectiveSecrets: NamedSecret[] = [
      ...(extraSecrets ?? []),
      ...(grant.personas ? personaSecrets(grant.personas) : []),
      ...(grant.secrets ?? []),
      ...this.getRegisteredSecrets(scopeRunKey),
    ]
    const scrub = (value: string | undefined, maxLen: number): string | undefined => {
      if (typeof value !== 'string') return undefined
      const cleaned = redact(value, effectiveSecrets).replace(/[\r\n\0]+/g, ' ').trim()
      if (!cleaned) return undefined
      return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen)}…` : cleaned
    }
    const cleanMeta: BrokerAuditMeta = {
      ...(meta.reason ? { reason: scrub(meta.reason, 512) } : {}),
      ...(meta.method ? { method: scrub(meta.method, 32) } : {}),
      ...(meta.path ? { path: scrub(meta.path, 512) } : {}),
      ...(meta.persona ? { persona: scrub(meta.persona, 128) } : {}),
    }
    grant.audit('denied', origin, undefined, cleanMeta)
  }

  private validateScopeHop(url: URL, redirectHop: boolean): AdmissionDecision {
    return this.scopeHopAdmissionEngine.admit({
      kind: 'http',
      origin: url.origin,
      method: 'GET',
      pathAndQuery: `${url.pathname}${url.search}`,
      redirectHop,
      checkCallerHeaders: false,
    })
  }

  private async resolveAndCheckAddresses(
    hostname: string,
    grant: Grant,
    deadline: AbortSignal,
    originForAudit: string,
    auditContext?: { method?: string; path?: string; persona?: string; secrets?: readonly NamedSecret[] },
    allowLocalLabOverride?: boolean,
  ): Promise<PublicAddress[]> {
    const localLab = allowLocalLabOverride !== undefined ? allowLocalLabOverride : isLocalLabEnabled(grant)
    const customResolve = this.options.resolve
    const bare = hostname.replace(/^\[|\]$/g, '')
    const validationUrl = `https://${bare.includes(':') ? `[${bare}]` : bare}/`
    try {
      const validated = await withAbort(
        EgressGateway.resolveAndValidateHost(validationUrl, {
          allowLocalLab: localLab,
          ...(customResolve
            ? { resolveHost: async host => (await customResolve(host)).map(a => a.address) }
            : {}),
        }),
        deadline,
      )
      deadline.throwIfAborted()
      return validated.addresses
    } catch (err) {
      if (err instanceof EgressDeniedError) {
        const reason = err.code === 'metadata_blocked'
          ? 'The target hostname resolved to a link-local/metadata address; cloud metadata and link-local endpoints are never permitted.'
          : 'The target hostname did not resolve exclusively to public addresses.'
        this.auditDenied(
          grant,
          originForAudit,
          {
            reason,
            ...(auditContext?.method ? { method: auditContext.method } : {}),
            ...(auditContext?.path ? { path: auditContext.path } : {}),
            ...(auditContext?.persona ? { persona: auditContext.persona } : {}),
          },
          auditContext?.secrets,
        )
        throw new BrokerDenied(reason)
      }
      throw err
    }
  }

  async readPublicRoot(grant: Grant, signal: AbortSignal): Promise<PublicObservation> {
    if (!grant.origin) throw new BrokerDenied('Grant origin is required for readPublicRoot.')
    if (process.env.KOVO_OFFLINE === '1' && !EgressGateway.isLoopbackLiteral(new URL(grant.origin).hostname)) {
      throw new BrokerDenied('Public root discovery is disabled in offline mode for non-loopback origins.')
    }
    const initial = this.admissionEngine.admit({ kind: 'public_root', origin: grant.origin, method: 'GET', pathAndQuery: '/', allowQuery: false }, grant)
    this.enforceAdmission(initial, { pathAndQuery: '/' }, grant)

    const localLab = Boolean(initial.localLab)
    const targetClassOverride = this.resolveTargetClassOverride(grant)
    const scopeRunKey = this.resolveScopeRunKey(undefined, grant)
    const telemetryRunId = scopeRunKey === 'default' ? null : scopeRunKey
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    const transport = this.httpTransport
    let url = new URL('/', grant.origin)
    const deny: (message: string) => never = (message: string): never => {
      this.auditDenied(grant, url.origin, {
        reason: message,
        method: 'GET',
        path: `${url.pathname}${url.search}`,
      })
      throw new BrokerDenied(message)
    }
    let redirect = 0
    const check = () => {
      deadline.throwIfAborted()
      const hop = this.admissionEngine.admitScopeHop(url, grant, {
        allowQuery: false,
        requireTargetRole: true,
      })
      if (!hop.allowed) deny(hop.reason)
    }
    for (redirect = 0; redirect <= 3; redirect += 1) {
      check()
      const addresses = await this.resolveAndCheckAddresses(
        url.hostname,
        grant,
        deadline,
        url.origin,
        {
          method: 'GET',
          path: `${url.pathname}${url.search}`,
        },
        localLab,
      )
      check()
      const chosenAddress = addresses.find(a => a.family === 4) ?? addresses[0]
      const hopTargetClass = classifyTargetClass(url.origin, {
        allowLocalLab: localLab,
        targetClassOverride,
      })
      const release = await this.acquireSlot(
        url.origin,
        () => resolveGrantMaxRps(grant, defaultMaxRpsPerOrigin),
        deadline,
        false,
        routeTemplateForPath(url.pathname),
        localLab,
        scopeRunKey,
        {
          resolvedIp: chosenAddress?.address,
          targetClassOverride,
          storage: grant.storage,
        },
      )
      let response: RawHttpResponse
      try {
        const ks = this.getKillSwitch()
        ks.assertAllowed(grant.tenantId ?? null)
        deadline.throwIfAborted()
        grant.audit('allowed', url.origin)
        response = await withAbort(
          transport(url, chosenAddress, deadline, {
            readBody: false,
            rejectUnauthorized: this.options.rejectUnauthorized ?? true,
            tenantId: grant.tenantId ?? null,
            killSwitch: ks,
          }),
          deadline,
        )
      } finally {
        release()
      }
      check()
      grant.audit('observed', url.origin, response.status)
      this.recordStatus(url.origin, response.status, grant.audit, {
        routeTemplate: routeTemplateForPath(url.pathname),
        headers: response.headers,
        configuredRps: resolveGrantMaxRps(grant, defaultMaxRpsPerOrigin),
        runId: telemetryRunId,
        targetClass: hopTargetClass,
        storage: grant.storage,
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

  private prepareHttpRequest(
    req: BrokerHttpRequest,
    grant: Grant,
    options: { raceBurst?: boolean; preAdmitted?: AdmissionDecision; kind?: 'http' | 'http2' } = {},
  ): {
    initialOrigin: string
    url: URL
    localLab: boolean
    personaHandle: string | undefined
    resolvedPersonaHeaders: Record<string, string> | undefined
    syntheticAuthHeader?: { name: string; value: string }
    cleanHeaders: Record<string, string>
    ephemeralObservedAuth: boolean
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
    const scopeRunId = this.resolveScopeRunKey(req, grant)
    const reqScopeRev = req.scopeRevision ?? grant.scopeRevision
    if (reqScopeRev !== undefined) {
      const latestForRun = this.latestScopeRevisionByRun.get(scopeRunId) ?? 0
      if (reqScopeRev < latestForRun) {
        throw new BrokerDenied('Request scopeRevision is stale relative to the current scope revision.')
      }
      if (reqScopeRev > latestForRun) {
        this.revokeScope(scopeRunId, reqScopeRev)
      }
    }

    const personaHandle = req.persona ?? req.personaHandle
    const usesRedactionRegistry =
      req.session !== undefined ||
      (personaHandle !== undefined && req.csrfBind !== undefined) ||
      Boolean(req.authMutation)
    this.assertRedactionCapacityBeforeSend(scopeRunId, req, grant, usesRedactionRegistry)
    const syntheticAuth = isSyntheticAuthMutation(req.authMutation)
    const admissionReq = this.toAdmissionRequest(req, options, grant)
    const auditCtx = { pathAndQuery: req.pathAndQuery, persona: personaHandle, secrets: req.secrets, runId: req.runId }

    // Pre-flight static admission when persona or cache-buster checks must fail before consuming
    // single-use Tier-3 approval grants.
    let decision = options.preAdmitted
    if (!decision && ((personaHandle && !syntheticAuth) || req.probeClass === 'cache_poison_deception' || req.probeClass === 'cache_differential')) {
      const pre = this.admissionEngine.admit(admissionReq, grant, { evaluateConsumingHooks: false })
      this.enforceAdmission(pre, auditCtx, grant)
      const preOrigin = pre.normalizedOrigin
      const preUrl = pre.parsedUrl
      if (req.probeClass === 'cache_poison_deception' || req.probeClass === 'cache_differential') {
        this.validateCacheBuster(req, preUrl, preOrigin, personaHandle, grant)
      }
      if (personaHandle && !syntheticAuth) {
        this.resolvePersonaHeadersForRequest(req, grant, preOrigin, personaHandle)
      }
    }

    if (!decision) {
      decision = this.admissionEngine.admit(admissionReq, grant)
    }
    this.enforceAdmission(decision, auditCtx, grant)

    const initialOrigin = decision.normalizedOrigin
    const url = decision.parsedUrl
    const localLab = Boolean(decision.localLab)
    const hasCompressedBody = Boolean(decision.classification?.hasCompressedBody)

    if (options.preAdmitted && (req.probeClass === 'cache_poison_deception' || req.probeClass === 'cache_differential')) {
      this.validateCacheBuster(req, url, initialOrigin, personaHandle, grant)
    }
    const resolvedPersonaHeaders = personaHandle && !syntheticAuth
      ? this.resolvePersonaHeadersForRequest(req, grant, initialOrigin, personaHandle)
      : undefined

    const cleanHeaders = {
      ...(decision.normalizedHeaders ?? canonicalizeCallerHeaders(req.headers, {
        allowSelfMintedBearer: true,
        stripPseudoHeaders: options.kind === 'http2',
        ...(admissionReq.isAuthorizedEphemeralBearer
          ? { isAuthorizedEphemeralBearer: admissionReq.isAuthorizedEphemeralBearer }
          : {}),
      })),
    }
    const ephemeralObservedAuth = Boolean(decision.ephemeralObservedAuth)
    const hasMultipart = Array.isArray(req.multipartParts) && req.multipartParts.length > 0
    let preparedBody = req.body
    if (hasMultipart) {
      try {
        const encoded = encodeMultipartParts(req.multipartParts!)
        preparedBody = encoded.body
        for (const existingKey of Object.keys(cleanHeaders)) {
          if (existingKey.toLowerCase() === 'content-type') delete cleanHeaders[existingKey]
        }
        cleanHeaders['content-type'] = encoded.contentType
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err)
        this.auditDenied(
          grant,
          initialOrigin,
          {
            reason,
            method: req.method,
            path: req.pathAndQuery,
            ...(personaHandle ? { persona: personaHandle } : {}),
          },
          req.secrets,
        )
        throw err
      }
    }

    const timeoutMs = Math.max(1_000, Math.min(req.timeoutMs ?? defaultRequestTimeoutMs, 60_000))
    const secrets = collectSecrets(req, grant)
    const followRedirects = req.followRedirects ?? true
    const defaultRps = tier === 3 ? 3 : defaultMaxRpsPerOrigin
    const maxRps = resolveGrantMaxRps(grant, defaultRps)

    return {
      initialOrigin,
      url,
      localLab,
      personaHandle,
      resolvedPersonaHeaders,
      cleanHeaders,
      ephemeralObservedAuth,
      preparedBody,
      secrets,
      followRedirects,
      hasCompressedBody,
      maxRps,
      timeoutMs,
    }
  }

  private validateCacheBuster(
    req: BrokerHttpRequest,
    url: URL,
    initialOrigin: string,
    personaHandle: string | undefined,
    grant: Grant,
  ): void {
    const deny: (reason: string) => never = (reason: string): never => {
      this.auditDenied(
        grant,
        initialOrigin,
        { reason, method: req.method, path: req.pathAndQuery, ...(personaHandle ? { persona: personaHandle } : {}) },
        req.secrets,
      )
      throw new BrokerDenied(reason)
    }
    const gcb = url.searchParams.get('_gcb')
    if (!gcb || !cacheBusterValueRegex.test(gcb)) {
      deny('Cache probes require a unique ?_gcb=<16-36 hex/uuid> cache-buster query parameter.')
    }
    const seen = this.seenGcbTokens.get(gcb.toLowerCase())
    if (seen) {
      if (req.probeClass === 'cache_differential' && req.cacheVerify === true && !seen.verifyUsed) {
        seen.verifyUsed = true
      } else {
        deny('Reusing an already-used _gcb cache-buster token is forbidden.')
      }
    } else {
      if (this.seenGcbTokens.size >= 10_000) {
        const oldest = this.seenGcbTokens.keys().next().value
        if (oldest !== undefined) this.seenGcbTokens.delete(oldest)
      }
      this.seenGcbTokens.set(gcb.toLowerCase(), { probeClass: req.probeClass!, verifyUsed: false })
    }
  }

  private resolvePersonaHeadersForRequest(
    req: Pick<BrokerHttpRequest, 'method' | 'pathAndQuery' | 'personaHeaders' | 'secrets'>,
    grant: Grant,
    initialOrigin: string,
    personaHandle: string,
  ): Record<string, string> {
    const deny: (reason: string) => never = (reason: string): never => {
      this.auditDenied(
        grant,
        initialOrigin,
        { reason, method: req.method, path: req.pathAndQuery, persona: personaHandle },
        req.secrets,
      )
      throw new BrokerDenied(reason)
    }
    if (grant.personas) {
      const persona = grant.personas.get(personaHandle)
      if (!persona) deny(`Persona "${personaHandle}" is not approved for this run.`)
      const injected = buildPersonaHeader(persona, initialOrigin)
      if (!injected) {
        if (!persona.originAllowlist.includes(initialOrigin)) {
          deny(`Origin ${initialOrigin} is not in persona "${personaHandle}" originAllowlist.`)
        }
        deny(`Persona "${personaHandle}" does not have an active authenticated session yet.`)
      }
      return { ...injected }
    }
    if (req.personaHeaders && Object.keys(req.personaHeaders).length > 0) {
      // Persona headers are an approved credential source, not caller headers. They are still
      // canonicalized/validated before transport, but may intentionally carry Authorization/Cookie.
      return { ...req.personaHeaders }
    }
    deny(`Persona "${personaHandle}" could not be resolved from run grant.`)
  }

  private async applyAuthMutationIfNeeded(
    prepared: ReturnType<RequestBroker['prepareHttpRequest']>,
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
  ): Promise<void> {
    if (!req.authMutation) return
    const mutation = req.authMutation
    const deny: (reason: string) => never = (reason: string): never => {
      this.auditDenied(
        grant,
        prepared.initialOrigin,
        {
          reason,
          method: req.method,
          path: req.pathAndQuery,
          ...(prepared.personaHandle ? { persona: prepared.personaHandle } : {}),
        },
        req.secrets,
      )
      throw new BrokerDenied(reason)
    }

    if (isSyntheticAuthMutation(mutation)) {
      const authRunKey = this.resolveScopeRunKey(req, grant)
      const runNonce = createHash('sha256')
        .update(`kovo-synthetic-invalid-auth-probe:v1:${authRunKey}`)
        .digest('hex')
        .slice(0, 16)
      if (mutation.kind === 'synthetic_invalid_bearer') {
        prepared.syntheticAuthHeader = {
          name: 'Authorization',
          value: `Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}${runNonce}`,
        }
      } else {
        const headerName = resolveSyntheticApiKeyHeaderName(mutation.headerName)
        if (!headerName) {
          deny('synthetic_invalid_api_key headerName must be an allowlisted API-key header (X-API-Key, X-Auth-Token, X-Access-Token, or X-Session-Token).')
        }
        prepared.syntheticAuthHeader = {
          name: headerName,
          value: `${SYNTHETIC_INVALID_API_KEY_PREFIX}${runNonce}`,
        }
      }
      // Guarantee zero persona credential leakage and accurate `caller_self_minted` wire provenance.
      prepared.resolvedPersonaHeaders = undefined
      prepared.personaHandle = undefined
      prepared.ephemeralObservedAuth = false
      return
    }

    if (!prepared.resolvedPersonaHeaders) return
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
      deny('authMutation requires a persona with a 3-segment JWT credential.')
    }

    const parts = originalJwt.split('.')
    if (parts.length !== 3) {
      deny('Persona credential is not a valid 3-part JWT.')
    }
    const [headerB64, payloadB64, sigB64] = parts
    const header = decodeJwtSegmentJson(headerB64)
    const payload = decodeJwtSegmentJson(payloadB64)
    if (!header || !payload) {
      deny('Persona JWT header or payload could not be decoded.')
    }

    const authRunKey = this.resolveScopeRunKey(req, grant)
    const authStorage = this.options.storage ?? grant.storage
    this.registerSecret(authRunKey, `jwt:original:${prepared.personaHandle ?? 'persona'}`, originalJwt, authStorage)
    this.registerSecret(authRunKey, `jwt:original_hp:${prepared.personaHandle ?? 'persona'}`, `${headerB64}.${payloadB64}`, authStorage)
    this.registerSecret(authRunKey, `jwt:original_payload:${prepared.personaHandle ?? 'persona'}`, payloadB64, authStorage)

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
        deny('kid_inject value rejected.')
      }
      const nextHeader = { ...header, kid: mutation.value }
      mutatedJwt = `${encodeJwtJson(nextHeader)}.${payloadB64}.${sigB64}`
    } else if (mutation.kind === 'jku_x5u_canary') {
      const hdrField = mutation.header ?? 'jku'
      let canaryUrl = mutation.url ?? mutation.value
      const cb = this.options.canaryBroker ?? grant.canaryBroker
      if (canaryUrl) {
        if (/[\r\n\0]/.test(canaryUrl) || hasDestructiveContent(canaryUrl)) {
          deny('jku_x5u_canary URL rejected.')
        }
        let parsedCanary: URL
        try {
          parsedCanary = new URL(canaryUrl)
        } catch {
          deny('jku_x5u_canary URL is malformed.')
        }
        if (parsedCanary.protocol !== 'http:' && parsedCanary.protocol !== 'https:') {
          deny('jku_x5u_canary URL must use http: or https: protocol.')
        }
        if (parsedCanary.search || parsedCanary.hash || parsedCanary.username || parsedCanary.password) {
          deny('jku_x5u_canary URL must not contain query, fragment, or userinfo.')
        }
        if (!canaryUrlRegex.test(parsedCanary.pathname)) {
          deny('jku_x5u_canary URL must target a Kovo Hunter CanaryBroker endpoint.')
        }
        const canaryHost = parsedCanary.hostname.toLowerCase().replace(/^\[|\]$/g, '')
        const canaryAddrClass = EgressGateway.classifyDetailedAddress(canaryHost)
        if (
          canaryAddrClass === 'metadata_or_link_local' ||
          canaryHost === 'metadata.google.internal' ||
          canaryHost === 'metadata.goog'
        ) {
          deny('jku_x5u_canary URL cannot target cloud metadata or link-local endpoints.')
        }
        if (isIpLiteralHost(canaryHost)) {
          if (!prepared.localLab && canaryAddrClass !== 'public') {
            deny('jku_x5u_canary URL cannot target private or loopback IPs on public projects.')
          }
        } else if (
          !prepared.localLab &&
          (canaryHost === 'localhost' || canaryHost.endsWith('.localhost') || canaryHost.endsWith('.local') || canaryHost.endsWith('.internal'))
        ) {
          deny('jku_x5u_canary URL cannot target local/internal hostnames on public projects.')
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
            deny('jku_x5u_canary URL origin does not match the active Kovo Hunter CanaryBroker.')
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
          deny('jku_x5u_canary requires an explicit CanaryBroker URL or active CanaryBroker.')
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
        deny('rs256_to_hs256_jwks jwksUrl is malformed.')
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
        deny(`Failed to fetch JWKS (${jwksEx.status}) for rs256_to_hs256_jwks.`)
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
        deny('No usable RSA key found in JWKS for rs256_to_hs256_jwks.')
      }
      let pem: string
      try {
        pem = createPublicKey({ key: selectedJwk as never, format: 'jwk' })
          .export({ type: 'spki', format: 'pem' })
          .toString()
      } catch {
        deny('JWKS key could not be exported as SPKI PEM.')
      }
      const nextHeader = { ...header, alg: 'HS256' }
      const signingInput = `${encodeJwtJson(nextHeader)}.${payloadB64}`
      const hmacSig = createHmac('sha256', pem).update(signingInput).digest('base64url')
      mutatedJwt = `${signingInput}.${hmacSig}`
    } else if (mutation.kind === 'claim_swap') {
      const isUnsigned = String(header.alg ?? '').toLowerCase() === 'none' || sigB64 === ''
      if (!prepared.localLab && !isUnsigned) {
        deny('claim_swap on signed tokens is restricted to local-lab or unsigned tokens.')
      }
      const nextPayload = { ...payload, ...mutation.claims }
      mutatedJwt = `${headerB64}.${encodeJwtJson(nextPayload)}.${sigB64}`
    }

    this.registerSecret(authRunKey, `jwt:mutated:${mutation.kind}`, mutatedJwt, authStorage)
    const mutatedParts = mutatedJwt.split('.')
    if (mutatedParts.length >= 2 && mutatedParts[0] && mutatedParts[1]) {
      this.registerSecret(authRunKey, `jwt:mutated_hp:${mutation.kind}`, `${mutatedParts[0]}.${mutatedParts[1]}`, authStorage)
      if (mutatedParts[1] !== payloadB64) {
        this.registerSecret(authRunKey, `jwt:mutated_payload:${mutation.kind}`, mutatedParts[1], authStorage)
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
    return this.withKillSwitch(signal, grant, (boundSignal, ks) =>
      this.executePreparedHttpWithKillSwitch(prepared, req, grant, boundSignal, ks, options),
    )
  }

  private async executePreparedHttpWithKillSwitch(
    prepared: ReturnType<RequestBroker['prepareHttpRequest']>,
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
    ks: GlobalKillSwitch,
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
    const exchangeExtraSecrets: NamedSecret[] = []
    let activeMethod: BrokerHttpRequest['method'] = req.method
    let activeBody = prepared.preparedBody
    let activeHeaders = { ...cleanHeaders }
    let stripSensitiveHeaders = false
    let stripEntityHeaders = false
    let includePersona = Boolean(personaHeaders && Object.keys(personaHeaders).length > 0)

    const defaultRps = (grant.tier ?? 1) === 3 ? 3 : defaultMaxRpsPerOrigin
    const deny: (message: string) => never = (message: string): never => {
      this.auditDenied(
        grant,
        url.origin,
        {
          reason: message,
          method: activeMethod,
          path: `${url.pathname}${url.search}`,
          ...(includePersona && personaHandle ? { persona: personaHandle } : {}),
        },
        req.secrets,
      )
      throw new BrokerDenied(message)
    }
    let redirect = 0
    const check = () => {
      ks.assertAllowed(grant.tenantId ?? null)
      deadline.throwIfAborted()
      const hop = this.admissionEngine.admitScopeHop(url, grant, {
        allowQuery: true,
        redirectHop: redirect > 0,
      })
      if (!hop.allowed) {
        this.purgeSessionJars(req.runId ?? grant.scopePolicy?.runId ?? undefined, url.origin)
        deny(hop.reason)
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
      const hopDecision = this.admissionEngine.admit({
        kind: 'http',
        origin: target.origin,
        method: activeMethod,
        pathAndQuery: targetPathAndQuery,
        headers: activeHeaders,
        normalizedHeaders: activeHeaders,
        checkCallerHeaders: false,
        body: multipart ? undefined : bodyForHop,
        multipartParts: multipart ? req.multipartParts : undefined,
        personaHandle: includePersona ? (personaHandle ?? null) : null,
        scopeHook: req.scopeHook ?? null,
        redirectHop: true,
        isRaceBurst: options.raceBurst === true,
        runId: req.runId,
        assignmentId: req.assignmentId,
      }, grant)
      this.enforceAdmission(
        hopDecision,
        {
          pathAndQuery: targetPathAndQuery,
          ...(includePersona && personaHandle ? { persona: personaHandle } : {}),
          secrets: req.secrets,
          runId: req.runId,
        },
        grant,
      )
    }

    for (redirect = 0; redirect <= maxRedirects; redirect += 1) {
      check()
      redirectOrigins.add(url.origin)
      const isCrossOriginHop = url.origin !== initialOrigin
      // Hard invariant: NEVER forward persona credentials across cross-origin redirects.
      if (isCrossOriginHop) {
        includePersona = false
        stripSensitiveHeaders = true
      }

      const addresses = redirect === 0 && options.preResolvedAddresses
        ? options.preResolvedAddresses
        : await this.resolveAndCheckAddresses(
          url.hostname,
          grant,
          deadline,
          url.origin,
          {
            method: activeMethod,
            path: `${url.pathname}${url.search}`,
            ...(includePersona && personaHandle ? { persona: personaHandle } : {}),
            secrets: req.secrets,
          },
          localLab,
        )
      check()

      const outboundHeaders = stripRedirectHeaders(activeHeaders, stripSensitiveHeaders, stripEntityHeaders)
      let personaCookieRaw: string | undefined
      const vaultHeaderNames: string[] = []
      if (includePersona && personaHeaders) {
        for (const [k, v] of Object.entries(personaHeaders)) {
          if (k.toLowerCase() === 'cookie') {
            personaCookieRaw = v
          } else if (!(stripSensitiveHeaders && crossOriginSensitiveHeaders.has(k.toLowerCase()))) {
            // Preserve canonical persona header casing (e.g. `Authorization`) after case-insensitive deduplication.
            setHeaderCaseInsensitive(outboundHeaders, k, v)
            vaultHeaderNames.push(k.toLowerCase())
          }
        }
      }
      if (prepared.syntheticAuthHeader && !stripSensitiveHeaders) {
        setHeaderCaseInsensitive(
          outboundHeaders,
          prepared.syntheticAuthHeader.name,
          prepared.syntheticAuthHeader.value,
        )
      }

      if (localLab && req.traceId && !/[\r\n\0]/.test(req.traceId)) {
        outboundHeaders['x-kovo-trace-id'] = req.traceId.slice(0, 128)
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
      // A session cookie is the server's handle on one identity. Two different personas presenting
      // the *same* login-minted session cookie are the same server session, so at most one of them
      // can be served its declared scope. Record it, withhold nothing (the credential is the
      // declared persona's own), and mark the exchange evidence-invalid.
      if (personaHandle && vaultCookies.size > 0 &&
        this.notePersonaSessionSharing({
          origin: url.origin,
          persona: personaHandle,
          cookies: vaultCookies,
          runId: this.resolveScopeRunKey(req, grant),
          ...(this.options.storage ?? grant.storage ? { storage: (this.options.storage ?? grant.storage)! } : {}),
        })) {
        // Fail closed: the request would be answered from another persona's session, so both the
        // bytes on the wire and any claim drawn from them belong to the wrong actor. Send nothing.
        deny(`Persona scope mismatch: the credential for "${personaHandle}" is the session of another persona; no request was sent. Re-mint this persona's login before scanning.`)
      }
      const jarCookieNames: string[] = []
      const vaultCookieNames: string[] = []
      const personaUpdatedAtMs = personaVaultUpdatedAtMs(personaHandle ? grant.personas?.get(personaHandle) : undefined)
      const jarVaultRefreshedAtMs = jar?.vaultRefreshedAt ?? 0
      for (const [name, entry] of jarCookieByName) {
        const vaultVal = vaultCookies.get(name)
        if (vaultVal === undefined || jarCookieSupersedesVault(entry, vaultVal, personaUpdatedAtMs, jarVaultRefreshedAtMs)) {
          mergedCookies.set(name, entry.value)
          jarCookieNames.push(name)
        }
      }
      for (const [k, v] of vaultCookies) {
        const jarEntry = jarCookieByName.get(k)
        if (jarEntry && jarCookieSupersedesVault(jarEntry, v, personaUpdatedAtMs, jarVaultRefreshedAtMs)) continue
        mergedCookies.set(k, v)
        vaultCookieNames.push(k)
      }
      if (mergedCookies.size > 0) {
        setHeaderCaseInsensitive(
          outboundHeaders,
          'Cookie',
          [...mergedCookies.entries()].map(([k, v]) => `${k}=${v}`).join('; '),
        )
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
          this.registerSecret(
            jar.runId,
            `csrf:${jar.session}:${csrfToken.detectedName ?? 'token'}`,
            csrfToken.value,
            this.options.storage ?? grant.storage,
          )
          const headerName = cfg.headerName ?? (
            (csrfToken.sourceKind === 'cookie' || csrfToken.sourceKind === 'vault_cookie') &&
            csrfToken.detectedName?.toLowerCase() === 'xsrf-token'
              ? 'X-XSRF-TOKEN'
              : 'X-CSRF-Token'
          )
          const hasHeaderAlready = Object.keys(outboundHeaders).some(k => k.toLowerCase() === headerName.toLowerCase())
          if (!hasHeaderAlready && !/[\r\n\0]/.test(headerName)) {
            outboundHeaders[headerName.toLowerCase()] = csrfToken.value
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
        outboundHeaders['content-type'] = hopContentType
      }

      const wireCredentialProvenance = buildWireCredentialProvenance({
        outboundHeaders,
        vaultHeaderNames,
        vaultCookieNames,
        jarCookieNames,
        mergedCookieNames: [...mergedCookies.keys()],
        injectedCsrfHeaderName,
        personaHandle: includePersona ? (personaHandle ?? null) : null,
        session: jar ? jar.session : null,
        authMutated: Boolean(req.authMutation),
        ephemeralObservedAuth: prepared.ephemeralObservedAuth,
      })

      const hopRouteTemplate = routeTemplateForPath(url.pathname)
      const chosenAddress = addresses.find(a => a.family === 4) ?? addresses[0]
      const targetClassOverride = this.resolveTargetClassOverride(grant)
      const hopTargetClass = classifyTargetClass(url.origin, {
        allowLocalLab: localLab,
        targetClassOverride,
      })
      const scopeRunKey = this.resolveScopeRunKey(req, grant)
      const telemetryRunId = scopeRunKey === 'default' ? null : scopeRunKey
      const release = await this.acquireSlot(
        url.origin,
        () => resolveGrantMaxRps(grant, maxRps || defaultRps),
        deadline,
        options.bypassConcurrency,
        hopRouteTemplate,
        localLab,
        scopeRunKey,
        {
          resolvedIp: chosenAddress?.address,
          targetClassOverride,
          storage: grant.storage,
        },
      )
      let response: RawHttpResponse
      try {
        ks.assertAllowed(grant.tenantId ?? null)
        deadline.throwIfAborted()
        grant.audit('allowed', url.origin)
        // R2-H-19: Wrap transport in `withAbort(deadline)` so a hung transport can never leak slots.
        response = await withAbort(
          transport(url, chosenAddress, deadline, {
            method: activeMethod,
            headers: outboundHeaders,
            body: hopBody,
            maxBodyBytes: Math.min(req.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes),
            readBody: true,
            rejectUnauthorized: this.options.rejectUnauthorized ?? true,
            tenantId: grant.tenantId ?? null,
            killSwitch: ks,
            ...(options.raceBarrier ? { raceBarrier: options.raceBarrier } : {}),
          }),
          deadline,
        )
      } catch (err) {
        // Per-request timeouts abort `deadline` while the run/caller `signal` stays active; count them
        // as origin transport failures so unresponsive origins trip the breaker cleanly. Only skip
        // when the run/caller/kill-switch aborted or tripped.
        if (!signal.aborted && !(err instanceof KillSwitchTrippedError)) {
          this.recordTransportFailure(url.origin, grant.audit, {
            runId: telemetryRunId,
            targetClass: hopTargetClass,
            storage: grant.storage,
          })
        }
        throw err
      } finally {
        release()
      }
      check()
      grant.audit('observed', url.origin, response.status)
      this.recordStatus(url.origin, response.status, grant.audit, {
        routeTemplate: hopRouteTemplate,
        headers: response.headers,
        configuredRps: resolveGrantMaxRps(grant, maxRps || defaultRps),
        probeClass: req.probeClass,
        runId: telemetryRunId,
        targetClass: hopTargetClass,
        storage: grant.storage,
      })

      const requestOriginHeader = cleanHeaders.origin
      const obs = observed(initialOrigin, url, response, this.options.source ?? 'public response', requestOriginHeader)

      // Session-expiry auto-refresh (401, pre-redirect 3xx login redirect, 403 session-expired, Clerk signed-out):
      // invoke the rate-limited persona re-auth callback once, then retry with fresh Vault credentials.
      if (
        includePersona &&
        personaHandle &&
        !req.authMutation &&
        !options.reauthAttempted &&
        this.reauthHandler &&
        !deadline.aborted &&
        this.shouldAutoReauthOnResponse(response, url, personaHandle, grant)
      ) {
        const reauthRunId = req.runId ?? grant.scopePolicy?.runId ?? undefined
        const refreshed = await this.reauthHandler(personaHandle, reauthRunId, url.origin).catch(() => false)
        if (refreshed !== false) {
          const refreshedPersona = grant.personas?.get(personaHandle)
          const rebuilt = refreshedPersona ? buildPersonaHeader(refreshedPersona, initialOrigin) : null
          this.clearRefreshedJarCookies(jar, rebuilt)
          const refreshedPrepared = { ...prepared, secrets: collectSecrets(req, grant) }
          return this.executePreparedHttp(refreshedPrepared, req, grant, signal, {
            ...options,
            reauthAttempted: true,
            ...(rebuilt ? { refreshedPersonaHeaders: rebuilt } : {}),
          })
        }
      }

      if (jar) {
        const jarDelta = this.storeJarCookiesAndCsrf(
          jar,
          url,
          response,
          obs.mediaType,
          vaultCookies,
          this.options.storage ?? grant.storage,
          this.isMutatingMethod(activeMethod, hopBody ?? activeBody),
        )
        exchangeExtraSecrets.push(...jarDelta.retiredSecrets, ...jarDelta.transientSecrets)
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
        const targetOrigin = url.origin
        const nextIsCrossOrigin = targetOrigin !== initialOrigin
        const nextIsPostToGet =
          (response.status === 301 || response.status === 302 || response.status === 303) &&
          activeMethod === 'POST'
        if (response.status === 301 || response.status === 302 || response.status === 303) {
          activeMethod = 'GET'
          activeBody = undefined
        } else {
          // 307/308 re-send the same method and body. Re-authorize the exact redirect target before
          // a single byte is sent there; fail closed with the target in BrokerApprovalRequired.
          authorizeRedirectTarget(url, hopBody ?? activeBody)
        }
        activeHeaders = stripRedirectHeaders(activeHeaders, nextIsCrossOrigin, nextIsPostToGet)
        stripSensitiveHeaders ||= nextIsCrossOrigin
        stripEntityHeaders ||= nextIsPostToGet
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
        ...this.getRegisteredSecrets(this.resolveScopeRunKey(req, grant)),
        ...exchangeExtraSecrets,
      ]
      // Structural evidence must be captured from the pre-redaction bytes: redaction is correct
      // for logs/LLMs but erases what a disclosure verifier needs. Only bounded fingerprints leave
      // this scope; raw values stay in memory for the duration of the scan.
      const rawResponseHeaders = normalizeHeaders(response.headers)
      this.observeEphemeralResponseTokens({
        req,
        grant,
        url,
        status: response.status,
        rawResponseHeaders,
        rawBody,
        mediaType: obs.mediaType,
        includePersona,
        personaHandle,
        effectiveSecrets,
      })
      if (req.onRawResponse) {
        try { req.onRawResponse({ body: rawBody, headers: { ...rawResponseHeaders } }) } catch { /* host hook must never abort exchange */ }
      }
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
        wireCredentialProvenance,
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
    this.getKillSwitch().assertAllowed(grant.tenantId ?? null)
    const prepared = this.prepareHttpRequest(req, grant)
    return this.executePreparedHttp(prepared, req, grant, signal, { bypassConcurrency })
  }

  async executeHttp(req: BrokerHttpRequest, grant: Grant, signal: AbortSignal): Promise<BrokerExchangeResult> {
    return this.executeHttpInternal(req, grant, signal, false)
  }

  /**
   * R2-08: Execute a bounded state-restore/cleanup HTTP request with an independent short
   * timeout signal so an aborted or timed-out caller signal does not prevent target restoration.
   *
   * Target-safety invariant: routes through the exact same `prepareHttpRequest` +
   * `executePreparedHttp` pipeline (ScopePolicy, Tier-3 approval/lease gates, kill-switch,
   * SSRF/DNS pinning, persona allowlists, and audit logging) — NEVER bypasses scope or approval.
   */
  async executeCleanupHttp(
    req: BrokerHttpRequest,
    grant: Grant,
    options: { timeoutMs?: number; bypassConcurrency?: boolean } = {},
  ): Promise<BrokerExchangeResult> {
    const boundedTimeoutMs = Math.max(500, Math.min(options.timeoutMs ?? 5_000, 10_000))
    const cleanupSignal = AbortSignal.timeout(boundedTimeoutMs)
    const cleanupReq: BrokerHttpRequest = {
      ...req,
      sessionGroupRole: req.sessionGroupRole ?? 'cleanup',
      timeoutMs: boundedTimeoutMs,
    }
    return this.executeHttpInternal(cleanupReq, grant, cleanupSignal, options.bypassConcurrency ?? true)
  }

  /**
   * R2-08: Invalidate all broker session jars and session-ownership records for `personaHandle`
   * within `runId`, and attempt to re-mint its session via `reauthHandler` when available.
   * Called when a mutating floor-recipe state restore fails or is denied so drifted session
   * state cannot bleed into subsequent probes.
   */
  async invalidateAndRemintPersonaSession(input: {
    personaHandle: string
    runId?: string
    origin?: string
    grant?: Pick<Grant, 'scopePolicy' | 'personas' | 'storage'>
  }): Promise<{ invalidatedJars: number; reminted: boolean }> {
    const runKey = this.resolveScopeRunKey({ runId: input.runId }, input.grant as Grant | undefined)
    let invalidatedJars = 0
    for (const [key, jar] of [...this.sessionJars.entries()]) {
      if (jar.runId !== runKey) continue
      if (jar.persona !== input.personaHandle) continue
      this.deleteSessionJar(key)
      invalidatedJars += 1
    }
    const owners = this.personaSessionOwnersByRun.get(runKey)
    if (owners) {
      for (const [fp, ownerPersona] of owners.entries()) {
        if (ownerPersona === input.personaHandle) owners.delete(fp)
      }
      if (owners.size === 0) this.personaSessionOwnersByRun.delete(runKey)
    }
    let reminted = false
    if (this.reauthHandler) {
      const reauthRunId = input.runId ?? input.grant?.scopePolicy?.runId ?? undefined
      const refreshed = await this.reauthHandler(input.personaHandle, reauthRunId, input.origin).catch(() => false)
      reminted = refreshed !== false
    }
    return { invalidatedJars, reminted }
  }

  /**
   * R2-08: Emit a structured degradation event when a mutating floor-recipe state restore fails
   * or is denied. Best-effort telemetry: never throws.
   */
  emitRestoreDegradationEvent(input: {
    runId?: string
    grant?: Pick<Grant, 'scopePolicy' | 'storage'>
    detail: Record<string, unknown>
    message: string
  }): void {
    try {
      const runKey = this.resolveScopeRunKey({ runId: input.runId }, input.grant as Grant | undefined)
      const store = input.grant?.storage ?? this.options.storage
      store?.event?.(
        runKey === 'default' ? null : runKey,
        'floor_recipe.restore_degraded',
        input.message,
        {
          runId: runKey,
          degradation: 'floor_recipe_restore_failed',
          ...input.detail,
        },
      )
    } catch {
      // Telemetry is best-effort and must never mask primary execution results.
    }
  }

  /**
   * C-1: Canonical brokered HTTP/2 exchange enforcing kill-switch, RequestAdmissionEngine,
   * pinned DNS + SSRF checks, per-origin slot acquisition & concurrency/RPS caps, circuit breaker,
   * audit logging (`allowed` / `observed`), persona/jar credential binding + `wireCredentialProvenance`
   * (`H-14`), transport proxy/mTLS/UA header policy, and hop-by-hop header stripping.
   */
  async executeHttp2Exchange(
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
    internalOptions: { reauthAttempted?: boolean; refreshedPersonaHeaders?: Record<string, string> } = {},
  ): Promise<BrokerExchangeResult> {
    this.getKillSwitch().assertAllowed(grant.tenantId ?? null)
    const prepared = this.prepareHttpRequest(req, grant, { kind: 'http2' })
    return this.withKillSwitch(signal, grant, async (boundSignal, ks) => {
      await this.applyAuthMutationIfNeeded(prepared, req, grant, boundSignal)
      const {
        initialOrigin,
        localLab,
        personaHandle,
        cleanHeaders,
        secrets,
        maxRps,
        timeoutMs,
      } = prepared
      const url = new URL(prepared.url.href)
      const personaHeaders = internalOptions.refreshedPersonaHeaders ?? prepared.resolvedPersonaHeaders
      const includePersona = Boolean(personaHeaders && Object.keys(personaHeaders).length > 0)
      const jar = this.getOrCreateSessionJar(req, grant)

      const started = Date.now()
      const deadline = AbortSignal.any([boundSignal, AbortSignal.timeout(timeoutMs)])
      const defaultRps = (grant.tier ?? 1) === 3 ? 3 : defaultMaxRpsPerOrigin

      const deny: (message: string) => never = (message: string): never => {
        this.auditDenied(
          grant,
          url.origin,
          {
            reason: message,
            method: req.method,
            path: `${url.pathname}${url.search}`,
            ...(includePersona && personaHandle ? { persona: personaHandle } : {}),
          },
          req.secrets,
        )
        throw new BrokerDenied(message)
      }

      ks.assertAllowed(grant.tenantId ?? null)
      deadline.throwIfAborted()

      const addresses = await this.resolveAndCheckAddresses(
        url.hostname,
        grant,
        deadline,
        url.origin,
        {
          method: req.method,
          path: `${url.pathname}${url.search}`,
          ...(includePersona && personaHandle ? { persona: personaHandle } : {}),
          secrets: req.secrets,
        },
        localLab,
      )

      // Build outbound HTTP/2 headers with transport UA/authorized profile & hop-by-hop stripping.
      const outboundHeaders: Record<string, string> = {}
      const connectionListed = new Set<string>()
      for (const [k, v] of Object.entries(cleanHeaders)) {
        if (k.toLowerCase() === 'connection') {
          for (const token of v.split(',')) {
            const name = token.trim().toLowerCase()
            if (name) connectionListed.add(name)
          }
        }
      }
      for (const [k, v] of Object.entries(cleanHeaders)) {
        if (k.trimStart().startsWith(':')) continue
        const lower = k.toLowerCase()
        if (lower === 'host' || H2_HOP_BY_HOP_HEADERS.has(lower) || connectionListed.has(lower)) continue
        outboundHeaders[lower] = v
      }
      if (this.transportConfig.headerProfile?.userAgent && !('user-agent' in outboundHeaders)) {
        outboundHeaders['user-agent'] = this.transportConfig.headerProfile.userAgent
      }
      for (const [k, v] of Object.entries(this.transportConfig.headerProfile?.headers ?? {})) {
        const lower = k.toLowerCase()
        if (!(lower in outboundHeaders) && !H2_HOP_BY_HOP_HEADERS.has(lower)) {
          outboundHeaders[lower] = v
        }
      }
      if (!('user-agent' in outboundHeaders)) {
        outboundHeaders['user-agent'] = 'KovoHunter/2 defensive evidence review'
      }
      if (!('accept' in outboundHeaders)) {
        outboundHeaders.accept = 'text/html, application/json;q=0.9, */*;q=0.1'
      }
      if (!('accept-encoding' in outboundHeaders)) {
        outboundHeaders['accept-encoding'] = 'gzip, deflate, br'
      }
      if (prepared.preparedBody !== undefined && !('content-type' in outboundHeaders)) {
        outboundHeaders['content-type'] = 'application/json'
      }
      if (localLab && req.traceId && !/[\r\n\0]/.test(req.traceId)) {
        outboundHeaders['x-kovo-trace-id'] = req.traceId.slice(0, 128)
      }

      let personaCookieRaw: string | undefined
      const vaultHeaderNames: string[] = []
      if (includePersona && personaHeaders) {
        for (const [k, v] of Object.entries(personaHeaders)) {
          if (k.toLowerCase() === 'cookie') {
            personaCookieRaw = v
          } else {
            setHeaderCaseInsensitive(outboundHeaders, k, v)
            vaultHeaderNames.push(k.toLowerCase())
          }
        }
      }
      if (prepared.syntheticAuthHeader) {
        outboundHeaders[prepared.syntheticAuthHeader.name.toLowerCase()] = prepared.syntheticAuthHeader.value
      }

      const mergedCookies = new Map<string, string>()
      const jarCookieByName = new Map<string, JarCookieEntry>()
      if (jar) {
        const now = Date.now()
        for (const entry of jar.cookies.values()) {
          if (!cookieDomainMatches(entry, url)) continue
          if (entry.expiresAt !== undefined && entry.expiresAt <= now) continue
          if (entry.secure && url.protocol !== 'https:') continue
          if (!cookiePathMatches(url.pathname, entry.path)) continue
          jarCookieByName.set(entry.name, entry)
        }
      }
      const vaultCookies = personaCookieRaw ? parseCookieHeaderPairs(personaCookieRaw) : new Map<string, string>()
      if (personaHandle && vaultCookies.size > 0 &&
        this.notePersonaSessionSharing({
          origin: url.origin,
          persona: personaHandle,
          cookies: vaultCookies,
          runId: this.resolveScopeRunKey(req, grant),
          ...(this.options.storage ?? grant.storage ? { storage: (this.options.storage ?? grant.storage)! } : {}),
        })) {
        deny(`Persona scope mismatch: the credential for "${personaHandle}" is the session of another persona; no request was sent. Re-mint this persona's login before scanning.`)
      }
      const jarCookieNames: string[] = []
      const vaultCookieNames: string[] = []
      const personaUpdatedAtMs = personaVaultUpdatedAtMs(personaHandle ? grant.personas?.get(personaHandle) : undefined)
      const jarVaultRefreshedAtMs = jar?.vaultRefreshedAt ?? 0
      for (const [name, entry] of jarCookieByName) {
        const vaultVal = vaultCookies.get(name)
        if (vaultVal === undefined || jarCookieSupersedesVault(entry, vaultVal, personaUpdatedAtMs, jarVaultRefreshedAtMs)) {
          mergedCookies.set(name, entry.value)
          jarCookieNames.push(name)
        }
      }
      for (const [k, v] of vaultCookies) {
        const jarEntry = jarCookieByName.get(k)
        if (jarEntry && jarCookieSupersedesVault(jarEntry, v, personaUpdatedAtMs, jarVaultRefreshedAtMs)) continue
        mergedCookies.set(k, v)
        vaultCookieNames.push(k)
      }
      if (mergedCookies.size > 0) {
        setHeaderCaseInsensitive(
          outboundHeaders,
          'Cookie',
          [...mergedCookies.entries()].map(([k, v]) => `${k}=${v}`).join('; '),
        )
      }

      const wireCredentialProvenance = buildWireCredentialProvenance({
        outboundHeaders,
        vaultHeaderNames,
        vaultCookieNames,
        jarCookieNames,
        mergedCookieNames: [...mergedCookies.keys()],
        personaHandle: includePersona ? (personaHandle ?? null) : null,
        session: jar ? jar.session : null,
        authMutated: Boolean(req.authMutation),
        ephemeralObservedAuth: prepared.ephemeralObservedAuth,
      })

      const hopRouteTemplate = routeTemplateForPath(url.pathname)
      const chosenAddress = addresses.find(a => a.family === 4) ?? addresses[0]
      const targetClassOverride = this.resolveTargetClassOverride(grant)
      const hopTargetClass = classifyTargetClass(url.origin, {
        allowLocalLab: localLab,
        targetClassOverride,
      })
      const scopeRunKey = this.resolveScopeRunKey(req, grant)
      const telemetryRunId = scopeRunKey === 'default' ? null : scopeRunKey
      const release = await this.acquireSlot(
        url.origin,
        () => resolveGrantMaxRps(grant, maxRps || defaultRps),
        deadline,
        false,
        hopRouteTemplate,
        localLab,
        scopeRunKey,
        {
          resolvedIp: chosenAddress?.address,
          targetClassOverride,
          storage: grant.storage,
        },
      )

      const maxResponseBytes = Math.min(req.maxBodyBytes ?? defaultMaxBodyBytes, hardMaxBodyBytes)
      let response: RawHttpResponse
      try {
        ks.assertAllowed(grant.tenantId ?? null)
        deadline.throwIfAborted()
        grant.audit('allowed', url.origin)
        if (this.transportConfig.proxy || this.transportConfig.mtls) {
          // Enforce configured egress proxy / mTLS transport instead of dialing directly.
          response = await withAbort(
            this.httpTransport(url, chosenAddress, deadline, {
              method: req.method,
              headers: outboundHeaders,
              body: prepared.preparedBody,
              maxBodyBytes: maxResponseBytes,
              readBody: true,
              rejectUnauthorized: this.options.rejectUnauthorized ?? true,
              tenantId: grant.tenantId ?? null,
              killSwitch: ks,
            }),
            deadline,
          )
        } else {
          const h2 = await withAbort(
            EgressGateway.egressHttp2(
              url,
              {
                method: req.method,
                headers: outboundHeaders,
                body: prepared.preparedBody,
                signal: deadline,
              },
              {
                allowLocalLab: localLab,
                allowedOrigins: [url.origin],
                pinnedAddresses: addresses.map(a => a.address),
                timeoutMs,
                maxResponseBytes,
                rejectUnauthorized: this.options.rejectUnauthorized ?? true,
                tenantId: grant.tenantId ?? null,
                killSwitch: ks,
              },
            ),
            deadline,
          )
          response = {
            status: h2.status,
            headers: h2.headers,
            body: h2.body,
            bodyBytes: h2.bodyBytes,
            bodyTruncated: h2.bodyTruncated,
          }
        }
      } catch (err) {
        if (!boundSignal.aborted && !(err instanceof KillSwitchTrippedError)) {
          this.recordTransportFailure(url.origin, grant.audit, {
            runId: telemetryRunId,
            targetClass: hopTargetClass,
            storage: grant.storage,
          })
        }
        throw err
      } finally {
        release()
      }

      ks.assertAllowed(grant.tenantId ?? null)
      deadline.throwIfAborted()
      grant.audit('observed', url.origin, response.status)
      this.recordStatus(url.origin, response.status, grant.audit, {
        routeTemplate: hopRouteTemplate,
        headers: response.headers,
        configuredRps: resolveGrantMaxRps(grant, maxRps || defaultRps),
        probeClass: req.probeClass,
        runId: telemetryRunId,
        targetClass: hopTargetClass,
        storage: grant.storage,
      })

      const requestOriginHeader = cleanHeaders.origin
      const obs = observed(initialOrigin, url, response, this.options.source ?? 'public response', requestOriginHeader)

      // Session-expiry auto-refresh on HTTP/2: invoke rate-limited persona re-auth once, then retry.
      if (
        includePersona &&
        personaHandle &&
        !req.authMutation &&
        !internalOptions.reauthAttempted &&
        this.reauthHandler &&
        !deadline.aborted &&
        this.shouldAutoReauthOnResponse(response, url, personaHandle, grant)
      ) {
        const reauthRunId = req.runId ?? grant.scopePolicy?.runId ?? undefined
        const refreshed = await this.reauthHandler(personaHandle, reauthRunId, url.origin).catch(() => false)
        if (refreshed !== false) {
          const refreshedPersona = grant.personas?.get(personaHandle)
          const rebuilt = refreshedPersona ? buildPersonaHeader(refreshedPersona, initialOrigin) : null
          this.clearRefreshedJarCookies(jar, rebuilt)
          return this.executeHttp2Exchange(req, grant, signal, {
            reauthAttempted: true,
            ...(rebuilt ? { refreshedPersonaHeaders: rebuilt } : {}),
          })
        }
      }

      const h2ExtraSecrets: NamedSecret[] = []
      if (jar) {
        const jarDelta = this.storeJarCookiesAndCsrf(
          jar,
          url,
          response,
          obs.mediaType,
          vaultCookies,
          this.options.storage ?? grant.storage,
          this.isMutatingMethod(req.method, prepared.preparedBody),
        )
        h2ExtraSecrets.push(...jarDelta.retiredSecrets, ...jarDelta.transientSecrets)
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
        ...this.getRegisteredSecrets(this.resolveScopeRunKey(req, grant)),
        ...h2ExtraSecrets,
      ]
      const rawResponseHeaders = normalizeHeaders(response.headers)
      this.observeEphemeralResponseTokens({
        req,
        grant,
        url,
        status: response.status,
        rawResponseHeaders,
        rawBody,
        mediaType: obs.mediaType,
        includePersona,
        personaHandle,
        effectiveSecrets,
      })
      if (req.onRawResponse) {
        try { req.onRawResponse({ body: rawBody, headers: { ...rawResponseHeaders } }) } catch { /* host hook must never abort exchange */ }
      }
      const secretMatches = [
        ...scanSecrets(rawBody, { secrets: effectiveSecrets }),
        ...scanSecretHeaders(rawResponseHeaders, { secrets: effectiveSecrets }),
      ]
      const safeBody = redact(rawBody, effectiveSecrets)
      const bodySha256 = createHash('sha256').update(safeBody).digest('hex')
      const scrubbedReqHeaders = redactHeaders(normalizeHeaders(outboundHeaders), effectiveSecrets)

      return {
        origin: initialOrigin,
        finalOrigin: url.origin,
        redirectOrigins: [url.origin],
        finalPathAndQuery: redact(`${url.pathname}${url.search}`, effectiveSecrets),
        redirectPaths: [],
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
        wireCredentialProvenance,
        secretMatches,
        ...(response.tls ? { tls: response.tls } : {}),
        observation: obs,
      }
    })
  }

  async executeBatch(reqs: readonly BrokerHttpRequest[], grant: Grant, signal: AbortSignal): Promise<BrokerExchangeResult[]> {
    this.getKillSwitch().assertAllowed(grant.tenantId ?? null)
    signal.throwIfAborted()

    // Check circuit breakers & concurrent batch locks before consuming per-target approvals.
    const uniqueOrigins = new Set<string>()
    for (const req of reqs) {
      let origin: string
      try { origin = new URL(req.origin).origin } catch { continue }
      const state = this.health(origin, resolveGrantMaxRps(grant, 5))
      if (this.isCircuitOpen(origin)) {
        throw new BrokerCircuitOpen(origin, state.openReason ?? 'Origin circuit is open.')
      }
      if (this.isBatchLockActive(state)) throw new BrokerDenied(`Another synchronized batch is already running for ${origin}.`)
      uniqueOrigins.add(origin)
    }

    // H-4: Admit EVERY target individually through RequestAdmissionEngine up-front before releasing
    // any bytes onto the wire, so an unapproved or denied sibling never lets an earlier item send.
    const batchDecision = this.admissionEngine.admitBatch(
      reqs.map(req => this.toAdmissionRequest(req, {}, grant)),
      grant,
      { isRaceBurst: false },
    )
    if (!batchDecision.allowed) {
      const idx = batchDecision.failedIndex
      const failedReq = idx !== null ? reqs[idx] : undefined
      const failedDec = idx !== null ? batchDecision.decisions[batchDecision.decisions.length - 1] : undefined
      if (failedReq && failedDec) {
        this.enforceAdmission(
          failedDec,
          { pathAndQuery: failedReq.pathAndQuery, persona: failedReq.persona ?? failedReq.personaHandle, secrets: failedReq.secrets, runId: failedReq.runId },
          grant,
        )
      }
      throw new BrokerDenied(batchDecision.reason)
    }

    const preparedList = reqs.map((req, idx) => ({
      req,
      prepared: this.prepareHttpRequest(req, grant, { preAdmitted: batchDecision.decisions[idx] }),
    }))

    const lockOwner = `batch:${randomBytes(8).toString('hex')}`
    const maxTimeout = Math.max(0, ...preparedList.map(p => p.prepared.timeoutMs))
    const lockTtlMs = this.options.batchLockTtlMs ?? Math.max(60_000, maxTimeout + 15_000)
    const lockedOrigins: string[] = []
    try {
      for (const origin of uniqueOrigins) {
        const defaultRps = resolveGrantMaxRps(grant, defaultMaxRpsPerOrigin)
        this.acquireBatchLock(origin, defaultRps, lockOwner, lockTtlMs)
        lockedOrigins.push(origin)
        const state = this.health(origin, defaultRps)
        // Ensure the bucket has enough tokens for a synchronized burst of up to reqs.length
        state.tokens = Math.max(state.tokens, reqs.length)
      }
      return await Promise.all(
        preparedList.map(({ req, prepared }) => this.executePreparedHttp(prepared, req, grant, signal, { bypassConcurrency: true })),
      )
    } finally {
      for (const origin of lockedOrigins) {
        this.releaseBatchLock(origin, lockOwner)
      }
    }
  }

  async executeRaceBurst(
    requests: readonly BrokerHttpRequest[],
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrokerRaceBurstResult> {
    this.getKillSwitch().assertAllowed(grant.tenantId ?? null)
    const tier = grant.tier ?? 1
    signal.throwIfAborted()

    // 1. Validate every request up-front through RequestAdmissionEngine (H-4 per-target validation)
    //    before sending any bytes.
    const batchDecision = this.admissionEngine.admitBatch(
      requests.map(req => this.toAdmissionRequest(req, { raceBurst: true }, grant)),
      grant,
      { isRaceBurst: true },
    )
    if (!batchDecision.allowed) {
      const idx = batchDecision.failedIndex
      const failedReq = idx !== null ? requests[idx] : undefined
      const failedDec = idx !== null ? batchDecision.decisions[batchDecision.decisions.length - 1] : undefined
      if (failedReq && failedDec) {
        this.enforceAdmission(
          failedDec,
          { pathAndQuery: failedReq.pathAndQuery, persona: failedReq.persona ?? failedReq.personaHandle, secrets: failedReq.secrets, runId: failedReq.runId },
          grant,
        )
      }
      throw new BrokerDenied(batchDecision.reason)
    }
    const preparedList = requests.map((req, idx) => ({
      req,
      prepared: this.prepareHttpRequest(req, grant, { raceBurst: true, preAdmitted: batchDecision.decisions[idx] }),
    }))

    const countsByOrigin = new Map<string, number>()
    const hostsToResolve = new Map<string, { origin: string; method: string; path: string; persona?: string; secrets?: readonly NamedSecret[] }>()
    for (const { req, prepared } of preparedList) {
      const origin = prepared.initialOrigin
      const state = this.health(origin, resolveGrantMaxRps(grant, tier === 3 ? 3 : defaultMaxRpsPerOrigin))
      if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)
      if (this.isBatchLockActive(state)) throw new BrokerDenied(`Another synchronized burst is already running for ${origin}.`)
      countsByOrigin.set(origin, (countsByOrigin.get(origin) ?? 0) + 1)
      if (!hostsToResolve.has(prepared.url.hostname)) {
        hostsToResolve.set(prepared.url.hostname, {
          origin,
          method: req.method,
          path: req.pathAndQuery,
          persona: prepared.personaHandle,
          secrets: req.secrets,
        })
      }
    }

    // 2. Synchronize DNS resolution & public-IP checks before releasing the concurrent burst barrier.
    const dnsDeadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)])
    const resolvedByHost = new Map<string, PublicAddress[]>()
    await Promise.all(
      [...hostsToResolve.entries()].map(async ([hostname, ctx]) => {
        const addrs = await this.resolveAndCheckAddresses(hostname, grant, dnsDeadline, ctx.origin, {
          method: ctx.method,
          path: ctx.path,
          ...(ctx.persona ? { persona: ctx.persona } : {}),
          secrets: ctx.secrets,
        })
        resolvedByHost.set(hostname, addrs)
      }),
    )
    signal.throwIfAborted()

    // 3. Re-check all origins atomically before mutating state, then reserve burst tokens and owner-TTL lock.
    const defaultRps = resolveGrantMaxRps(grant, tier === 3 ? 3 : defaultMaxRpsPerOrigin)
    for (const origin of countsByOrigin.keys()) {
      const state = this.health(origin, defaultRps)
      if (state.openReason) throw new BrokerCircuitOpen(origin, state.openReason)
      if (this.isBatchLockActive(state)) throw new BrokerDenied(`Another synchronized burst is already running for ${origin}.`)
    }

    const lockOwner = `race:${randomBytes(8).toString('hex')}`
    const maxTimeout = Math.max(0, ...preparedList.map(p => p.prepared.timeoutMs))
    const lockTtlMs = this.options.batchLockTtlMs ?? Math.max(60_000, maxTimeout + 15_000)
    const markedOrigins: string[] = []
    let results: BrokerExchangeResult[]
    try {
      for (const [origin, count] of countsByOrigin) {
        this.acquireBatchLock(origin, defaultRps, lockOwner, lockTtlMs)
        markedOrigins.push(origin)
        const state = this.health(origin, defaultRps)
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
        this.releaseBatchLock(origin, lockOwner)
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
    const decision = this.admissionEngine.admit({ kind: 'dns', origin, method: 'DNS', pathAndQuery: '/' }, grant)
    this.enforceAdmission(decision, { pathAndQuery: '/' }, grant)
    const parsed = decision.parsedUrl
    const offline = process.env.KOVO_OFFLINE === '1'
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '')
    const literal = ipaddr.isValid(hostname) ? ipaddr.process(hostname) : null
    if (offline && literal && isMetadataOrLinkLocalAddress(literal.toString())) {
      throw new BrokerDenied('Metadata and link-local DNS inspection are disabled in offline mode.')
    }
    if (offline && !literal) {
      this.auditDenied(grant, parsed.origin, {
        reason: 'External DNS inspection is disabled in offline mode.',
        method: 'DNS',
        path: '/',
      })
      throw new BrokerDenied('External DNS inspection is disabled in offline mode.')
    }

    const started = Date.now()
    const records = await this.withKillSwitch(signal, grant, async (ksSignal, ks) => {
      const deadline = AbortSignal.any([ksSignal, AbortSignal.timeout(15_000)])
      ks.assertAllowed(grant.tenantId ?? null)
      grant.audit('allowed', parsed.origin)
      const dnsResolver = this.options.dnsResolver ?? defaultDnsRecordResolver
      const resolved = await dnsResolver(parsed.hostname, deadline)
      ks.assertAllowed(grant.tenantId ?? null)
      deadline.throwIfAborted()
      return resolved
    })

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
    const decision = this.admissionEngine.admit({ kind: 'tls', origin, method: 'TLS', pathAndQuery: '/' }, grant)
    this.enforceAdmission(decision, { pathAndQuery: '/' }, grant)
    const parsed = decision.parsedUrl

    const started = Date.now()
    const { chosen, tls } = await this.withKillSwitch(signal, grant, async (ksSignal, ks) => {
      const deadline = AbortSignal.any([ksSignal, AbortSignal.timeout(15_000)])
      const addresses = await this.resolveAndCheckAddresses(parsed.hostname, grant, deadline, parsed.origin, {
        method: 'TLS',
        path: '/',
      })
      const picked = addresses.find(a => a.family === 4) ?? addresses[0]
      const inspector = this.options.tlsInspector ?? defaultTlsInspector

      ks.assertAllowed(grant.tenantId ?? null)
      grant.audit('allowed', parsed.origin)
      const inspected = await inspector(parsed, picked, deadline)
      ks.assertAllowed(grant.tenantId ?? null)
      return { chosen: picked, tls: inspected }
    })
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
    const personaHandle = req.persona ?? req.personaHandle
    const sendMessages = (req.sendMessages ?? []).slice(0, hardWsMaxFrames)
    const turnMessages = (req.turns ?? []).flatMap(turn => turn.send === undefined ? [] : [turn.send])
    const subprotocols = req.subprotocols ?? []
    if (subprotocols.some(protocol => !isValidWebsocketSubprotocol(protocol))) {
      this.auditDenied(grant, req.origin, {
        reason: 'Invalid WebSocket subprotocol offer.',
        method: 'WS',
        path: req.pathAndQuery,
        ...(personaHandle ? { persona: personaHandle } : {}),
      }, req.secrets)
      throw new BrokerDenied('Invalid WebSocket subprotocol offer.')
    }
    if (turnMessages.some(message => hasDestructiveContent(message))) {
      this.auditDenied(grant, req.origin, {
        reason: 'WebSocket turn payload blocked by the destructive denylist.',
        method: 'WS',
        path: req.pathAndQuery,
        ...(personaHandle ? { persona: personaHandle } : {}),
      }, req.secrets)
      throw new BrokerDenied('WebSocket turn payload blocked by the destructive denylist.')
    }
    const decision = this.admissionEngine.admit({
      kind: 'websocket',
      origin: req.origin,
      method: 'WS',
      pathAndQuery: req.pathAndQuery,
      headers: req.headers,
      personaHandle: personaHandle ?? null,
      wsSendMessages: [...sendMessages, ...turnMessages],
      wsOriginHeader: req.originHeader,
      wsSubprotocols: subprotocols,
    }, grant)
    this.enforceAdmission(decision, { pathAndQuery: req.pathAndQuery, persona: personaHandle, secrets: req.secrets }, grant)

    const initialOrigin = decision.normalizedOrigin
    const url = decision.parsedUrl
    const localLab = Boolean(decision.localLab)
    const resolvedPersonaHeaders = personaHandle
      ? canonicalizeCallerHeaders(
          this.resolvePersonaHeadersForRequest(
            { method: 'WS' as HttpMethod, pathAndQuery: req.pathAndQuery, personaHeaders: req.personaHeaders, secrets: req.secrets },
            grant,
            initialOrigin,
            personaHandle,
          ),
          { allowSelfMintedBearer: true },
        )
      : undefined

    const cleanHeaders = { ...(decision.normalizedHeaders ?? canonicalizeCallerHeaders(req.headers, { allowSelfMintedBearer: false })) }
    const effectiveOriginHeader = req.originHeader ?? cleanHeaders.origin ?? initialOrigin
    if (/[\r\n\0]/.test(effectiveOriginHeader)) {
      this.auditDenied(grant, initialOrigin, { reason: 'Invalid WebSocket Origin header.', method: 'WS', path: req.pathAndQuery, ...(personaHandle ? { persona: personaHandle } : {}) }, req.secrets)
      throw new BrokerDenied('Invalid WebSocket Origin header.')
    }
    cleanHeaders.origin = effectiveOriginHeader

    const maxFrames = Math.max(1, Math.min(req.maxFrames ?? defaultWsMaxFrames, hardWsMaxFrames))
    const maxBytes = Math.max(1024, Math.min(req.maxBytes ?? defaultWsMaxBytes, defaultWsMaxBytes))
    const timeoutMs = Math.max(500, Math.min(req.timeoutMs ?? defaultWsTimeoutMs, hardWsTimeoutMs))
    const started = Date.now()
    const ks = this.getKillSwitch()
    const ksBound = ks.bindSignal(signal, grant.tenantId ?? null)
    const deadline = AbortSignal.any([ksBound.signal, AbortSignal.timeout(timeoutMs + 2_000)])
    const secrets: NamedSecret[] = [
      ...(grant.personas ? personaSecrets(grant.personas) : []),
      ...(grant.secrets ?? []),
      ...(req.secrets ?? []),
    ]

    let raw
    const targetClassOverride = this.resolveTargetClassOverride(grant)
    const wsTargetClass = classifyTargetClass(initialOrigin, {
      allowLocalLab: localLab,
      targetClassOverride,
    })
    const wsScopeRunKey = this.resolveScopeRunKey(undefined, grant)
    const wsTelemetryRunId = wsScopeRunKey === 'default' ? null : wsScopeRunKey
    try {
      const addresses = await this.resolveAndCheckAddresses(
        url.hostname,
        grant,
        deadline,
        initialOrigin,
        {
          method: 'WS',
          path: req.pathAndQuery,
          ...(personaHandle ? { persona: personaHandle } : {}),
          secrets: req.secrets,
        },
        localLab,
      )
      const chosen = addresses.find(a => a.family === 4) ?? addresses[0]
      const release = await this.acquireSlot(
        initialOrigin,
        () => resolveGrantMaxRps(grant, tier === 3 ? 3 : defaultMaxRpsPerOrigin),
        deadline,
        false,
        undefined,
        localLab,
        wsScopeRunKey,
        {
          resolvedIp: chosen?.address,
          targetClassOverride,
          storage: grant.storage,
        },
      )

      const wsTransport = this.options.wsTransport ?? defaultWsTransport
      const sessionMode = Boolean(req.turns?.length) && this.options.wsSessionEnabled === true
      try {
        ks.assertAllowed(grant.tenantId ?? null)
        deadline.throwIfAborted()
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
    } catch (err) {
      if (ksBound.signal.aborted && ksBound.signal.reason instanceof KillSwitchTrippedError) {
        throw ksBound.signal.reason
      }
      throw err
    } finally {
      ksBound.release()
    }

    grant.audit('observed', initialOrigin, raw.upgradeStatus ?? undefined)
    if (raw.upgradeStatus !== null) {
      this.recordStatus(initialOrigin, raw.upgradeStatus, grant.audit, {
        runId: wsTelemetryRunId,
        targetClass: wsTargetClass,
        storage: grant.storage,
      })
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
      pathAndQuery: decision.normalizedPath,
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
    reqHeaders: { origin: result.originHeader ?? '', ...(sent ? { 'x-kovo-ws-sent-frames': String(result.sentFrames) } : {}) },
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
