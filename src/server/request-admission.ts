/**
 * Single Canonical RequestAdmissionEngine (Option 2 — Move 3).
 *
 * Pure, stateless (except optional pluggable grant/budget/rate-limit/kill-switch lookup interfaces)
 * admission authority shared by BOTH `RequestBroker` (`broker.ts`) and `VerifyRpcServer`
 * (`verify-rpc.ts`). Consolidates:
 *   a. Target origin/scope + explicit denylist + destructive payload / header checks;
 *   b. Method + GraphQL + JSON-RPC mutation/destructive classification (strict parser from H-3,
 *      never regex-only);
 *   c. Tier (`offline` / `passive` / `supervised` / `autonomous`) + approval policy + `Grant` /
 *      `sandboxWriteAllowlist` / durable lease matching (including H-4 per-target batch validation);
 *   d. Request budget & rate-limit admission hooks.
 */
import { createHash } from 'node:crypto'
import type { ApprovalPolicy, ApprovedEndpointPattern, CapabilityTier } from '../domain.ts'
import { containsDestructivePayload, containsWebshellSignature } from '../replay-spec.ts'
import type { AuthMutation } from '../replay-spec.ts'
import { computeStateChangeBodyHash, detectMultipartRequest, isLocalLabAutoApprovalOrigin } from './approval-judge.ts'
import type { MultipartBodyPart, StateChangeApprovalContext } from './approval-judge.ts'
import { computeApprovalHeadersDigest, normalizeOriginKey } from './approval-pattern.ts'
import {
  canonicalPathAndQuery,
  detectMethodOverride,
  evaluateScopeRequest,
  hasUnsafeAdmissionPath,
  isReadOnlyHttpMethod,
  isRouteDenylisted,
  isVerifiedReadOnlyGraphqlQuery,
  normalizeScopeOrigin,
  originRoleFor,
} from './scope-policy.ts'
import type { EnvironmentMode, ScopeHook, ScopePolicy, ScopeSurface } from './scope-policy.ts'

export const MAX_ADMISSION_PATH_LENGTH = 8192
const MAX_JSONRPC_CLASSIFICATION_CHARS = 64 * 1024
const MAX_JSON_NESTING_DEPTH = 32

/** Internal redirect callback used by the broker to enforce the current effective scope policy. */
export type AdmissionScopeHopValidator = (url: URL, redirectHop: boolean) => AdmissionDecision

export const FORBIDDEN_CALLER_HEADERS =
  /^(?:authorization|proxy-authorization|cookie|host|content-length|transfer-encoding|x-kovo-trace-id)$/i

export type AdmissionTier = 'offline' | 'passive' | 'supervised' | 'autonomous'
export type AdmissionOutcome = 'allow' | 'deny' | 'require_approval'

export type AdmissionRequestKind =
  | 'http'
  | 'http2'
  | 'browser'
  | 'websocket'
  | 'public_root'
  | 'dns'
  | 'tls'

export type AdmissionReasonCode =
  | 'allowed'
  | 'allowed_read_only'
  | 'allowed_graphql_readonly'
  | 'allowed_environment_contract'
  | 'allowed_approval_lease'
  | 'allowed_sandbox_allowlist'
  | 'allowed_state_change_approved'
  | 'allowed_local_lab'
  | 'kill_switch_active'
  | 'tier_offline'
  | 'tier_insufficient'
  | 'malformed_origin'
  | 'malformed_path'
  | 'origin_escape'
  | 'protocol_not_allowed'
  | 'port_not_allowed'
  | 'query_not_allowed'
  | 'out_of_scope'
  | 'origin_role_restricted'
  | 'auth_origin_active_probe'
  | 'asset_origin_active_probe'
  | 'readonly_environment'
  | 'staging_denylist'
  | 'staging_untagged_mutation'
  | 'explicit_denylist'
  | 'destructive_payload'
  | 'webshell_signature'
  | 'forbidden_header'
  | 'invalid_header'
  | 'conflicting_body_multipart'
  | 'persona_required'
  | 'local_lab_redirect_escape'
  | 'approval_required'
  | 'budget_exhausted'
  | 'rate_limited'
  | 'batch_size_invalid'
  | 'missing_grant'

export type RequestMutationKind =
  | 'read_only_http'
  | 'graphql_readonly_query'
  | 'graphql_mutation_or_unverified'
  | 'jsonrpc_read_method'
  | 'jsonrpc_mutation'
  | 'jsonrpc_destructive'
  | 'jsonrpc_malformed'
  | 'http_mutation'
  | 'multipart_upload'
  | 'compressed_mutation'

export interface RequestMutationClassification {
  kind: RequestMutationKind
  /** R2-H-1: Effective HTTP verb including method-override headers and `_method` carriers. */
  effectiveMethod: string
  /** R2-H-1: True when any method-override header or `_method` query/form/JSON field is present. */
  hasMethodOverride: boolean
  /** R3-H-1(b): True when the request body exceeds the 64 KiB deterministic classification window. */
  hasOverCapBody: boolean
  /** R3-H-1(b): True when the request body could not be completely parsed/scanned for method overrides. */
  overrideScanIncomplete: boolean
  /** R3-H-1(b): Authoritative override-risk flag (explicit override, over-cap body, compressed, or unscannable). */
  hasOverrideRisk: boolean
  /** R2-H-1: Override carrier names when `hasMethodOverride` is true. */
  methodOverrideCarriers?: string[]
  isReadOnly: boolean
  isVerifiedGraphqlRead: boolean
  isStateChanging: boolean
  isStructuralMutation: boolean
  hasMultipart: boolean
  hasCompressedBody: boolean
  isJsonRpc: boolean
  jsonRpcMethods?: string[]
}

/** Structural subset of `Grant` required for pure admission evaluation (no circular imports). */
export interface AdmissionGrant {
  origin?: string
  tier?: CapabilityTier | AdmissionTier
  maxRpsPerOrigin?: number
  getMaxRpsPerOrigin?: () => number
  allowLocalLab?: boolean
  sandboxWriteAllowlist?: readonly ApprovedEndpointPattern[]
  allowedPorts?: readonly number[]
  /** H-3: Host-confirmed GraphQL endpoints for read-only GraphQL exceptions. */
  confirmedGraphqlEndpoints?: readonly string[]
  canRead: (origin: string) => boolean
  scopePolicy?: ScopePolicy
  approvalPolicy?: ApprovalPolicy
  tenantId?: string
  storage?: unknown
  approvalLeases?: (origin: string, method: string, pathAndQuery: string) => boolean
  isStateChangeApproved?: (
    origin: string,
    method: string,
    pathAndQuery: string,
    context?: StateChangeApprovalContext,
  ) => boolean
}

export interface AdmissionRequest {
  kind?: AdmissionRequestKind
  origin: string
  method?: string
  pathAndQuery?: string
  headers?: Record<string, string>
  body?: string
  multipartParts?: readonly MultipartBodyPart[]
  personaHandle?: string | null
  authMutation?: AuthMutation
  scopeHook?: ScopeHook | null
  surface?: ScopeSurface
  redirectHop?: boolean
  isRaceBurst?: boolean
  /** Override query allowance (false for passive root discovery). Defaults to true. */
  allowQuery?: boolean
  /** Validate caller-supplied headers against forbidden/control-char rules. Defaults to true. */
  checkCallerHeaders?: boolean
  /** Strip `:`-prefixed HTTP/2 pseudo-headers when validating caller headers. */
  stripPseudoHeaders?: boolean
  /** WebSocket-specific outbound inputs checked against the destructive denylist. */
  wsSendMessages?: readonly string[]
  wsOriginHeader?: string
  wsSubprotocols?: readonly string[]
  /** Canonical lower-case header map produced once by admission validation. */
  normalizedHeaders?: Record<string, string>
  /** Optional semantic or numeric tier override for standalone evaluation. */
  tierOverride?: CapabilityTier | AdmissionTier
  /** H-3: Optional per-request confirmed GraphQL endpoints list. */
  confirmedGraphqlEndpoints?: readonly string[]
  /**
   * Q4: Optional run-scoped predicate returning true ONLY when the exact SHA-256 digest of a
   * caller-supplied `Authorization: Bearer` token was observed in an in-scope non-privileged
   * exchange response during the same run (and is never a Vault secret).
   */
  isAuthorizedEphemeralBearer?: (tokenDigestSha256: string) => boolean
  runId?: string
  assignmentId?: string
}

export interface AdmissionDecision {
  outcome: AdmissionOutcome
  allowed: boolean
  reason: string
  reasonCode: AdmissionReasonCode
  matchedRule: string | null
  effectiveTier: AdmissionTier
  capabilityTier: CapabilityTier
  normalizedMethod: string
  normalizedOrigin: string | null
  normalizedPath: string
  localLab?: boolean
  parsedUrl?: URL
  classification?: RequestMutationClassification
  normalizedHeaders?: Record<string, string>
  /** Q4: True when a caller-supplied Authorization header passed via provenance-bound ephemeral digest match. */
  ephemeralObservedAuth?: boolean
  approvalContext?: StateChangeApprovalContext
  retryAfterMs?: number
}

export interface BatchAdmissionDecision {
  outcome: AdmissionOutcome
  allowed: boolean
  reason: string
  reasonCode: AdmissionReasonCode
  matchedRule: string | null
  effectiveTier: AdmissionTier
  capabilityTier: CapabilityTier
  decisions: AdmissionDecision[]
  failedIndex: number | null
  /** H-4: SHA-256 digest binding the batch admission decision to ALL targets (never target[0] alone). */
  targetsHash?: string
}

export interface AdmissionBudgetContext {
  origin: string
  method: string
  pathAndQuery: string
  effectiveTier: AdmissionTier
  capabilityTier: CapabilityTier
  kind: AdmissionRequestKind
  weight: number
  runId?: string
  assignmentId?: string
}

export interface AdmissionRateLimitContext extends AdmissionBudgetContext {
  maxRpsPerOrigin?: number
}

export type AdmissionHookResult =
  | { allowed: true }
  | { allowed: false; reasonCode?: 'budget_exhausted' | 'rate_limited'; reason: string; retryAfterMs?: number }

export interface AdmissionExplicitDenylist {
  origins?: readonly string[]
  pathPrefixes?: readonly string[]
}

export interface RequestAdmissionEngineOptions {
  grantLookup?: (request: AdmissionRequest) => AdmissionGrant | null | undefined
  budgetCheck?: (ctx: AdmissionBudgetContext) => AdmissionHookResult
  rateLimitCheck?: (ctx: AdmissionRateLimitContext) => AdmissionHookResult
  killSwitchCheck?: (tenantId: string | null) => { active: boolean; reason?: string }
  explicitDenylist?: AdmissionExplicitDenylist
  scopeHopValidator?: AdmissionScopeHopValidator
  env?: NodeJS.ProcessEnv
}

export interface GrantApprovalContext {
  effectivePolicy: ApprovalPolicy | undefined
  liveEnvironmentMode: EnvironmentMode | undefined
  explicitEnvironmentMode: boolean
}

// ---------------------------------------------------------------------------
// Tier conversion helpers
// ---------------------------------------------------------------------------

export function admissionTierToCapabilityTier(tier: CapabilityTier | AdmissionTier | undefined): CapabilityTier {
  if (tier === undefined) return 1
  if (typeof tier === 'number') return tier
  switch (tier) {
    case 'offline': return 0
    case 'passive': return 1
    case 'supervised': return 2
    case 'autonomous': return 3
  }
}

export function capabilityTierToAdmissionTier(tier: CapabilityTier | AdmissionTier | undefined): AdmissionTier {
  const numeric = admissionTierToCapabilityTier(tier)
  switch (numeric) {
    case 0: return 'offline'
    case 1: return 'passive'
    case 2: return 'supervised'
    case 3: return 'autonomous'
  }
}

// ---------------------------------------------------------------------------
// URL, port, origin scope, header & denylist primitives
// ---------------------------------------------------------------------------

export function isLocalLabEnabled(grant: Pick<AdmissionGrant, 'allowLocalLab'>, env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(grant.allowLocalLab && env.KOVO_ALLOW_LOCAL_LAB === '1')
}

export function operatorApprovedPorts(env: NodeJS.ProcessEnv = process.env): number[] {
  const raw = env.KOVO_ALLOWED_PORTS
  if (!raw) return []
  const out: number[] = []
  for (const part of raw.split(',')) {
    const n = Number(part.trim())
    if (Number.isInteger(n) && n > 0 && n <= 65535) out.push(n)
  }
  return out
}

export function isPortAllowed(
  port: string,
  protocol: string,
  allowedPorts?: readonly number[],
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (!port) return true
  const defaultPort = protocol === 'https:' ? '443' : '80'
  if (port === defaultPort) return true
  const numeric = Number(port)
  if (!Number.isInteger(numeric)) return false
  return Boolean(allowedPorts?.includes(numeric)) || operatorApprovedPorts(env).includes(numeric)
}

export function isSafeAdmissionUrl(
  url: URL,
  allowQuery: boolean,
  localLab: boolean,
  allowedPorts?: readonly number[],
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const validProtocol = url.protocol === 'https:' || (localLab && url.protocol === 'http:')
  if (!validProtocol || url.username || url.password || url.hash) return false
  if (!localLab && !isPortAllowed(url.port, url.protocol, allowedPorts, env)) return false
  if (!allowQuery && !localLab && url.search) return false
  const full = url.pathname + url.search
  return canonicalPathAndQuery(full) !== null && !url.pathname.startsWith('//')
}

export function isOriginInGrantScope(
  grant: Pick<AdmissionGrant, 'canRead' | 'scopePolicy'>,
  origin: string,
  effectiveScopePolicy?: ScopePolicy,
): boolean {
  const policy = effectiveScopePolicy ?? grant.scopePolicy
  if (policy) {
    const role = originRoleFor(policy, origin)
    if (!role) return false
    if (role === 'auth' || role === 'asset') return true
  }
  return grant.canRead(origin)
}

export function resolveGrantApprovalContext(grant: Pick<AdmissionGrant, 'approvalPolicy' | 'scopePolicy' | 'storage'>): GrantApprovalContext {
  let effectivePolicy = grant.approvalPolicy
  let liveEnvironmentMode: EnvironmentMode | undefined
  let explicitEnvironmentMode = false
  const runId = grant.scopePolicy?.runId
  const store = grant.storage as {
    run?: (id: string) => { approvalPolicy?: ApprovalPolicy; environmentMode?: EnvironmentMode }
    eventsAfter?: (id: string, after: number, limit?: number) => Array<{ kind: string }>
  } | undefined
  if (runId && store && typeof store.run === 'function') {
    try {
      const liveRun = store.run(runId)
      if (liveRun.approvalPolicy) effectivePolicy = liveRun.approvalPolicy
      if (liveRun.environmentMode) liveEnvironmentMode = liveRun.environmentMode
      if (typeof store.eventsAfter === 'function') {
        explicitEnvironmentMode = store.eventsAfter(runId, 0, 500).some(e => e.kind === 'scope.environment_mode')
      }
    } catch {
      explicitEnvironmentMode = grant.approvalPolicy === undefined
    }
  } else {
    explicitEnvironmentMode = grant.approvalPolicy === undefined
  }
  return { effectivePolicy, liveEnvironmentMode, explicitEnvironmentMode }
}

/**
 * Positive-only self-minted unsigned JWT shape (`alg:none` / signature-bypass probe): a three-segment
 * JWT whose signature segment is empty. Every other caller-set Authorization value stays forbidden.
 */
export function isSelfMintedBearer(name: string, value: string): boolean {
  if (!/^authorization$/i.test(name)) return false
  const match = /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.\s*$/i.exec(value)
  if (!match) return false
  try {
    const header = JSON.parse(Buffer.from(match[1]!, 'base64url').toString('utf8')) as { alg?: unknown }
    return typeof header?.alg === 'string' && /^(?:none|HS256|HS384|HS512|RS256|RS384|RS512|ES256)$/.test(header.alg)
  } catch {
    return false
  }
}

/**
 * Extract the credential token from an `Authorization: Bearer <token>` header and compute its
 * SHA-256 hex digest for provenance-bound ephemeral channel verification. Returns null for
 * non-Bearer, malformed, or implausibly short/long values.
 */
export function extractBearerTokenDigest(
  name: string,
  value: string,
): { token: string; sha256: string } | null {
  if (!/^authorization$/i.test(name)) return null
  const match = /^Bearer\s+([^\s\r\n\0]+)\s*$/i.exec(value.trim())
  if (!match) return null
  const token = match[1]!
  if (token.length < 16 || token.length > 8192) return null
  const sha256 = createHash('sha256').update(token, 'utf8').digest('hex')
  return { token, sha256 }
}

const HTTP_TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
const WS_SUBPROTOCOL_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

/** RFC 7230 token validation shared by caller headers and WebSocket subprotocol offers. */
export function isValidHttpToken(value: string): boolean {
  return value.length > 0 && HTTP_TOKEN_RE.test(value)
}

export function isValidWebsocketSubprotocol(value: string): boolean {
  return value.length > 0 && WS_SUBPROTOCOL_RE.test(value) && !/[\x00-\x20\x7f]/.test(value)
}

export interface ValidateCallerHeadersOptions {
  allowSelfMintedBearer?: boolean
  stripPseudoHeaders?: boolean
  isAuthorizedEphemeralBearer?: (tokenDigestSha256: string) => boolean
}

export function validateCallerHeaders(
  headers: Record<string, string> | undefined,
  options: ValidateCallerHeadersOptions = {},
):
  | { ok: true; headers: Record<string, string>; ephemeralObservedAuth?: boolean }
  | { ok: false; reasonCode: 'forbidden_header' | 'invalid_header'; reason: string } {
  const allowSelfMinted = options.allowSelfMintedBearer ?? true
  const stripPseudo = options.stripPseudoHeaders ?? false
  const normalized: Record<string, string> = {}
  let ephemeralObservedAuth = false
  for (const [k, v] of Object.entries(headers ?? {})) {
    if (stripPseudo && k.trimStart().startsWith(':')) continue
    if (!isValidHttpToken(k) || /[\r\n\0]/.test(v)) {
      return { ok: false, reasonCode: 'invalid_header', reason: 'Invalid request header.' }
    }
    const canonicalName = k.toLowerCase()
    if (Object.prototype.hasOwnProperty.call(normalized, canonicalName)) {
      return {
        ok: false,
        reasonCode: 'invalid_header',
        reason: `Duplicate case-insensitive request header "${canonicalName}".`,
      }
    }
    if (FORBIDDEN_CALLER_HEADERS.test(canonicalName)) {
      const selfMintedOk = allowSelfMinted && isSelfMintedBearer(canonicalName, v)
      let ephemeralOk = false
      if (!selfMintedOk && canonicalName === 'authorization' && options.isAuthorizedEphemeralBearer) {
        const bearer = extractBearerTokenDigest(canonicalName, v)
        if (bearer && options.isAuthorizedEphemeralBearer(bearer.sha256)) {
          ephemeralOk = true
          ephemeralObservedAuth = true
        }
      }
      if (!selfMintedOk && !ephemeralOk) {
        return {
          ok: false,
          reasonCode: 'forbidden_header',
          reason: `Header "${k}" cannot be set directly; reference an approved persona handle instead.`,
        }
      }
    }
    normalized[canonicalName] = v
  }
  return ephemeralObservedAuth
    ? { ok: true, headers: normalized, ephemeralObservedAuth: true }
    : { ok: true, headers: normalized }
}

export function hasDestructiveContent(text: string): boolean {
  if (containsDestructivePayload(text)) return true
  try {
    const decoded = decodeURIComponent(text.replaceAll('+', ' '))
    if (decoded !== text && containsDestructivePayload(decoded)) return true
  } catch {
    const plusDecoded = text.replaceAll('+', ' ')
    if (plusDecoded !== text && containsDestructivePayload(plusDecoded)) return true
  }
  return false
}

export function matchesSandboxWriteAllowlist(
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

// ---------------------------------------------------------------------------
// Strict RFC 8259 JSON-RPC & Mutation Classifier (H-3 parity, never regex-only)
// ---------------------------------------------------------------------------

/**
 * Strict RFC 8259 JSON validator for object or array payloads:
 *  - rejects duplicate keys at every object depth,
 *  - rejects case-insensitive duplicate keys and backslash-escaped keys at envelope depth,
 *  - enforces bounded nesting depth and rejects trailing bytes.
 */
function validateStrictJsonValue(raw: string): boolean {
  const text = raw.trim()
  if (!text || text.length > MAX_JSONRPC_CLASSIFICATION_CHARS) return false
  let i = 0
  const n = text.length

  const skipWs = () => {
    while (i < n) {
      const c = text.charCodeAt(i)
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i += 1
      else break
    }
  }

  const parseString = (): { value: string; hasEscape: boolean } | undefined => {
    if (text[i] !== '"') return undefined
    const start = i
    i += 1
    let hasEscape = false
    while (i < n) {
      const ch = text[i]!
      const code = text.charCodeAt(i)
      if (code < 0x20) return undefined
      if (ch === '\\') {
        hasEscape = true
        i += 1
        if (i >= n) return undefined
        const esc = text[i]!
        if (esc === 'u') {
          if (i + 4 >= n) return undefined
          for (let k = 1; k <= 4; k += 1) {
            if (!/[0-9a-fA-F]/.test(text[i + k]!)) return undefined
          }
          i += 5
        } else if ('"\\/bfnrt'.includes(esc)) {
          i += 1
        } else {
          return undefined
        }
        continue
      }
      if (ch === '"') {
        i += 1
        try {
          const decoded = JSON.parse(text.slice(start, i)) as unknown
          if (typeof decoded !== 'string') return undefined
          return { value: decoded, hasEscape }
        } catch {
          return undefined
        }
      }
      i += 1
    }
    return undefined
  }

  const parseValue = (depth: number, envelopeDepth: boolean): boolean => {
    if (depth > MAX_JSON_NESTING_DEPTH) return false
    skipWs()
    if (i >= n) return false
    const ch = text[i]!
    if (ch === '{') return parseObject(depth, envelopeDepth)
    if (ch === '[') {
      i += 1
      skipWs()
      if (i < n && text[i] === ']') {
        i += 1
        return true
      }
      while (i < n) {
        if (!parseValue(depth + 1, depth === 0)) return false
        skipWs()
        if (i < n && text[i] === ',') {
          i += 1
          continue
        }
        if (i < n && text[i] === ']') {
          i += 1
          return true
        }
        return false
      }
      return false
    }
    if (ch === '"') return parseString() !== undefined
    if (text.startsWith('true', i)) { i += 4; return true }
    if (text.startsWith('false', i)) { i += 5; return true }
    if (text.startsWith('null', i)) { i += 4; return true }
    const numMatch = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i))
    if (!numMatch) return false
    i += numMatch[0].length
    return true
  }

  const parseObject = (depth: number, envelopeDepth: boolean): boolean => {
    if (text[i] !== '{') return false
    i += 1
    skipWs()
    if (i < n && text[i] === '}') {
      i += 1
      return true
    }
    const seenExact = new Set<string>()
    const seenLower = envelopeDepth ? new Set<string>() : undefined
    while (i < n) {
      skipWs()
      const key = parseString()
      if (!key) return false
      if (envelopeDepth && key.hasEscape) return false
      if (seenExact.has(key.value)) return false
      seenExact.add(key.value)
      if (seenLower) {
        const lower = key.value.toLowerCase()
        if (seenLower.has(lower)) return false
        seenLower.add(lower)
      }
      skipWs()
      if (i >= n || text[i] !== ':') return false
      i += 1
      if (!parseValue(depth + 1, false)) return false
      skipWs()
      if (i < n && text[i] === ',') {
        i += 1
        continue
      }
      if (i < n && text[i] === '}') {
        i += 1
        return true
      }
      return false
    }
    return false
  }

  skipWs()
  if (i >= n || (text[i] !== '{' && text[i] !== '[')) return false
  if (!parseValue(0, text[i] === '{')) return false
  skipWs()
  return i === n
}

const JSONRPC_READ_METHOD_RE = /^(?:[a-z][a-z0-9_-]*[./:])?(?:get|list|read|find|fetch|query|search|describe|inspect|show|view|check|ping|health|status|version|info|echo)(?:[A-Z_].*)?$/
const JSONRPC_DESTRUCTIVE_METHOD_RE = /(?:^|[./:_-])(?:delete|destroy|drop|purge|wipe|truncate|remove|revoke|reset|exec|eval|shell|shutdown|kill|nuke)(?:$|[./:_-]|[A-Z])/i

export interface JsonRpcInspection {
  isJsonRpc: boolean
  malformed: boolean
  methods: string[]
  hasDestructiveMethod: boolean
  hasMutationMethod: boolean
  allReadNamed: boolean
}

/**
 * Strictly parses a JSON-RPC 2.0 single or batch payload without regex-only body sniffing.
 * Duplicate keys, escaped envelope keys, mixed batches, or malformed frames fail closed.
 */
export function inspectJsonRpcPayload(
  body: string | null | undefined,
  headers?: Record<string, string>,
): JsonRpcInspection {
  const empty: JsonRpcInspection = {
    isJsonRpc: false,
    malformed: false,
    methods: [],
    hasDestructiveMethod: false,
    hasMutationMethod: false,
    allReadNamed: false,
  }
  const trimmed = (body ?? '').trim()
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return empty

  const contentType = headerLookup(headers, 'content-type').toLowerCase()
  const contentEncoding = headerLookup(headers, 'content-encoding').trim()
  if (contentEncoding && !/^identity$/i.test(contentEncoding)) return empty
  if (contentType && !contentType.includes('json')) return empty

  const looksJsonRpcHint = /"jsonrpc"|"\\u006a/i.test(trimmed)
  if (!validateStrictJsonValue(trimmed)) {
    return looksJsonRpcHint
      ? { ...empty, isJsonRpc: true, malformed: true, hasMutationMethod: true }
      : empty
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    return looksJsonRpcHint
      ? { ...empty, isJsonRpc: true, malformed: true, hasMutationMethod: true }
      : empty
  }

  const items = Array.isArray(parsed) ? parsed : [parsed]
  if (items.length === 0) return empty

  const hasAnyJsonRpcField = items.some(
    item => Boolean(item && typeof item === 'object' && !Array.isArray(item) && 'jsonrpc' in (item as Record<string, unknown>)),
  )
  if (!hasAnyJsonRpcField) return empty

  const methods: string[] = []
  let malformed = false
  let hasDestructiveMethod = false
  let hasMutationMethod = false

  for (const item of items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      malformed = true
      hasMutationMethod = true
      continue
    }
    const rec = item as Record<string, unknown>
    if (rec.jsonrpc !== '2.0' || typeof rec.method !== 'string' || !rec.method.trim()) {
      malformed = true
      hasMutationMethod = true
      continue
    }
    const rpcMethod = rec.method.trim()
    methods.push(rpcMethod)
    if (JSONRPC_DESTRUCTIVE_METHOD_RE.test(rpcMethod)) {
      hasDestructiveMethod = true
      hasMutationMethod = true
    } else if (!JSONRPC_READ_METHOD_RE.test(rpcMethod)) {
      // Fail-closed: unknown JSON-RPC methods are treated as mutating.
      hasMutationMethod = true
    }
  }

  return {
    isJsonRpc: true,
    malformed,
    methods,
    hasDestructiveMethod,
    hasMutationMethod,
    allReadNamed: !malformed && methods.length > 0 && !hasMutationMethod && !hasDestructiveMethod,
  }
}

function headerLookup(headers: Record<string, string> | undefined, name: string): string {
  return headers?.[name.toLowerCase()] ?? ''
}

function isGraphqlPathCandidate(pathAndQuery: string): boolean {
  const pathname = (pathAndQuery.split('?')[0] ?? pathAndQuery).split('#')[0] ?? ''
  const segments = pathname.split('/').filter(Boolean)
  return segments.length > 0 && segments[segments.length - 1]!.toLowerCase() === 'graphql'
}

export function classifyRequestMutation(input: {
  origin?: string
  method: string
  pathAndQuery: string
  body?: string | null
  headers?: Record<string, string>
  multipartParts?: readonly MultipartBodyPart[]
  confirmedGraphqlEndpoints?: readonly string[]
}): RequestMutationClassification {
  const method = (input.method || 'GET').toUpperCase()
  const override = detectMethodOverride({
    method,
    pathAndQuery: input.pathAndQuery,
    headers: input.headers,
    body: input.body ?? null,
  })
  const effectiveMethod = override.effectiveMethod
  const hasMultipartParts = Array.isArray(input.multipartParts) && input.multipartParts.length > 0
  const contentType = headerLookup(input.headers, 'content-type')
  const contentEncoding = headerLookup(input.headers, 'content-encoding').trim()
  const hasMultipartContentType = /^\s*multipart\//i.test(contentType)
  const hasMultipart = hasMultipartParts || hasMultipartContentType
  const hasCompressedBody = contentEncoding !== '' && !/^identity$/i.test(contentEncoding)
  const hasOverCapBody = override.bodyExceedsScanWindow
  const overrideScanIncomplete = override.scanIncomplete
  const hasOverrideRisk = override.hasOverrideRisk || hasCompressedBody
  const isReadOnlyHttp = !hasMultipart && !hasOverrideRisk && isReadOnlyHttpMethod(effectiveMethod, input.body ?? null)
  // R2-H-1 / R3-H-1(b): Treat override carriers, over-cap bodies (>64 KiB), unscannable bodies,
  // effective DELETE verbs, multipart uploads, and compressed bodies as structural mutations so
  // auto_review gates and durable route leases can never be bypassed.
  const isStructuralMutation =
    method === 'DELETE' ||
    effectiveMethod === 'DELETE' ||
    override.hasOverride ||
    hasOverCapBody ||
    overrideScanIncomplete ||
    hasOverrideRisk ||
    hasMultipart ||
    hasCompressedBody
  const overrideMeta = {
    effectiveMethod,
    hasMethodOverride: override.hasOverride,
    hasOverCapBody,
    overrideScanIncomplete,
    hasOverrideRisk,
    ...(override.carriers.length > 0 ? { methodOverrideCarriers: override.carriers } : {}),
  }

  if (isReadOnlyHttp) {
    return {
      kind: 'read_only_http',
      ...overrideMeta,
      isReadOnly: true,
      isVerifiedGraphqlRead: false,
      isStateChanging: false,
      isStructuralMutation: false,
      hasMultipart: false,
      hasCompressedBody,
      isJsonRpc: false,
    }
  }

  if (hasMultipart) {
    return {
      kind: 'multipart_upload',
      ...overrideMeta,
      isReadOnly: false,
      isVerifiedGraphqlRead: false,
      isStateChanging: true,
      isStructuralMutation: true,
      hasMultipart: true,
      hasCompressedBody,
      isJsonRpc: false,
    }
  }

  if (hasCompressedBody) {
    return {
      kind: 'compressed_mutation',
      ...overrideMeta,
      isReadOnly: false,
      isVerifiedGraphqlRead: false,
      isStateChanging: true,
      isStructuralMutation: true,
      hasMultipart: false,
      hasCompressedBody: true,
      isJsonRpc: false,
    }
  }

  if (
    !hasOverrideRisk &&
    method === 'POST' &&
    isVerifiedReadOnlyGraphqlQuery(input.pathAndQuery, input.body ?? null, input.headers, {
      ...(input.confirmedGraphqlEndpoints !== undefined
        ? { confirmedEndpoints: input.confirmedGraphqlEndpoints }
        : {}),
      ...(input.origin ? { origin: input.origin } : {}),
      method: effectiveMethod,
    })
  ) {
    return {
      kind: 'graphql_readonly_query',
      ...overrideMeta,
      isReadOnly: false,
      isVerifiedGraphqlRead: true,
      isStateChanging: false,
      isStructuralMutation: false,
      hasMultipart: false,
      hasCompressedBody: false,
      isJsonRpc: false,
    }
  }

  if (method === 'POST' && isGraphqlPathCandidate(input.pathAndQuery)) {
    return {
      kind: 'graphql_mutation_or_unverified',
      ...overrideMeta,
      isReadOnly: false,
      isVerifiedGraphqlRead: false,
      isStateChanging: true,
      isStructuralMutation,
      hasMultipart: false,
      hasCompressedBody: false,
      isJsonRpc: false,
    }
  }

  const jsonRpc = inspectJsonRpcPayload(input.body ?? null, input.headers)
  if (jsonRpc.isJsonRpc) {
    // Fail-closed: JSON-RPC POSTs remain state-changing at the HTTP/approval boundary so they
    // never bypass prod_readonly or Tier-3 approval hooks, while preserving strict sub-classification.
    const kind: RequestMutationKind = jsonRpc.malformed
      ? 'jsonrpc_malformed'
      : jsonRpc.hasDestructiveMethod
        ? 'jsonrpc_destructive'
        : jsonRpc.hasMutationMethod
          ? 'jsonrpc_mutation'
          : 'jsonrpc_read_method'
    return {
      kind,
      ...overrideMeta,
      isReadOnly: false,
      isVerifiedGraphqlRead: false,
      isStateChanging: true,
      isStructuralMutation: isStructuralMutation || jsonRpc.hasDestructiveMethod,
      hasMultipart: false,
      hasCompressedBody: false,
      isJsonRpc: true,
      jsonRpcMethods: jsonRpc.methods,
    }
  }

  return {
    kind: 'http_mutation',
    ...overrideMeta,
    isReadOnly: false,
    isVerifiedGraphqlRead: false,
    isStateChanging: true,
    isStructuralMutation,
    hasMultipart: false,
    hasCompressedBody: false,
    isJsonRpc: false,
  }
}

/**
 * Single authoritative durable-route-lease eligibility check (`R3-H-1(b)`).
 *
 * Race bursts, compressed bodies, explicit method-override carriers, over-cap bodies (>64 KiB),
 * and bodies whose override scan was incomplete NEVER satisfy a durable POST/route lease under
 * any approval policy.
 */
export function isDurableRouteLeaseEligible(
  classification: Pick<
    RequestMutationClassification,
    'hasCompressedBody' | 'hasMethodOverride' | 'hasOverCapBody' | 'overrideScanIncomplete' | 'hasOverrideRisk'
  >,
  options: { isRaceBurst?: boolean } = {},
): boolean {
  if (options.isRaceBurst === true) return false
  if (classification.hasCompressedBody) return false
  if (classification.hasMethodOverride) return false
  if (classification.hasOverCapBody) return false
  if (classification.overrideScanIncomplete) return false
  if (classification.hasOverrideRisk) return false
  return true
}

// ---------------------------------------------------------------------------
// RequestAdmissionEngine — sole outbound admission authority
// ---------------------------------------------------------------------------

export class RequestAdmissionEngine {
  private readonly options: RequestAdmissionEngineOptions

  constructor(options: RequestAdmissionEngineOptions = {}) {
    this.options = options
  }

  private env(): NodeJS.ProcessEnv {
    return this.options.env ?? process.env
  }

  private checkExplicitDenylist(origin: string, pathAndQuery: string): { matchedRule: string; reason: string } | null {
    const denylist = this.options.explicitDenylist
    if (!denylist) return null
    if (denylist.origins?.length) {
      const normalizedTarget = normalizeScopeOrigin(origin) ?? origin
      for (const denied of denylist.origins) {
        const normDenied = normalizeScopeOrigin(denied) ?? denied
        if (normDenied === normalizedTarget) {
          return {
            matchedRule: `explicit_denylist:origin:${normDenied}`,
            reason: `Origin ${normalizedTarget} is explicitly denylisted.`,
          }
        }
      }
    }
    if (denylist.pathPrefixes?.length) {
      const pseudoPolicy: ScopePolicy = {
        mode: 'staging_isolated',
        targetOrigins: [origin],
        routeDenylist: denylist.pathPrefixes,
      }
      if (isRouteDenylisted(pseudoPolicy, pathAndQuery)) {
        return {
          matchedRule: 'explicit_denylist:path',
          reason: `Route ${pathAndQuery} is explicitly denylisted.`,
        }
      }
    }
    return null
  }

  /**
   * Origin-level admission check (used by VerifyRpcServer `scopeOrigin` & capability URL injection).
   * Enforces protocol (`http:` / `https:`), grant scope (including v6 `scopePolicy` auth/asset
   * roles), and engine-level explicit origin denylists.
   */
  admitOrigin(rawOrigin: string, grantArg?: AdmissionGrant): AdmissionDecision {
    const grant = grantArg ?? this.options.grantLookup?.({ origin: rawOrigin })
    const capabilityTier = admissionTierToCapabilityTier(grant?.tier)
    const effectiveTier = capabilityTierToAdmissionTier(capabilityTier)
    if (!grant) {
      return {
        outcome: 'deny',
        allowed: false,
        reason: 'No admission grant is configured for this request.',
        reasonCode: 'missing_grant',
        matchedRule: 'grant_required',
        effectiveTier,
        capabilityTier,
        normalizedMethod: 'GET',
        normalizedOrigin: null,
        normalizedPath: '/',
      }
    }
    let url: URL
    try {
      url = new URL(rawOrigin)
    } catch {
      return {
        outcome: 'deny',
        allowed: false,
        reason: 'Target origin is malformed.',
        reasonCode: 'malformed_origin',
        matchedRule: 'origin_syntax',
        effectiveTier,
        capabilityTier,
        normalizedMethod: 'GET',
        normalizedOrigin: null,
        normalizedPath: '/',
      }
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return {
        outcome: 'deny',
        allowed: false,
        reason: 'Destination protocol is outside the current assignment scope.',
        reasonCode: 'protocol_not_allowed',
        matchedRule: 'origin_protocol',
        effectiveTier,
        capabilityTier,
        normalizedMethod: 'GET',
        normalizedOrigin: url.origin,
        normalizedPath: '/',
      }
    }
    const denied = this.checkExplicitDenylist(url.origin, '/')
    if (denied) {
      return {
        outcome: 'deny',
        allowed: false,
        reason: denied.reason,
        reasonCode: 'explicit_denylist',
        matchedRule: denied.matchedRule,
        effectiveTier,
        capabilityTier,
        normalizedMethod: 'GET',
        normalizedOrigin: url.origin,
        normalizedPath: '/',
      }
    }
    const approvalMeta = resolveGrantApprovalContext(grant)
    const effectiveScopePolicy: ScopePolicy | undefined = grant.scopePolicy
      ? (approvalMeta.liveEnvironmentMode && approvalMeta.liveEnvironmentMode !== grant.scopePolicy.mode
          ? { ...grant.scopePolicy, mode: approvalMeta.liveEnvironmentMode }
          : grant.scopePolicy)
      : undefined
    if (!isOriginInGrantScope(grant, url.origin, effectiveScopePolicy)) {
      return {
        outcome: 'deny',
        allowed: false,
        reason: 'Destination is outside the current assignment scope.',
        reasonCode: 'out_of_scope',
        matchedRule: 'grant_scope',
        effectiveTier,
        capabilityTier,
        normalizedMethod: 'GET',
        normalizedOrigin: url.origin,
        normalizedPath: '/',
      }
    }
    return {
      outcome: 'allow',
      allowed: true,
      reason: 'Origin is inside the approved scope.',
      reasonCode: 'allowed',
      matchedRule: 'grant_scope',
      effectiveTier,
      capabilityTier,
      normalizedMethod: 'GET',
      normalizedOrigin: url.origin,
      normalizedPath: '/',
      parsedUrl: url,
      localLab: isLocalLabEnabled(grant, this.env()),
    }
  }

  /**
   * Non-consuming URL & scope check for redirect hops and passive root hops.
   */
  admitScopeHop(
    url: URL,
    grant: AdmissionGrant,
    options: { allowQuery?: boolean; requireTargetRole?: boolean; redirectHop?: boolean } = {},
  ): AdmissionDecision {
    const capabilityTier = admissionTierToCapabilityTier(grant.tier)
    const effectiveTier = capabilityTierToAdmissionTier(capabilityTier)
    const localLab = isLocalLabEnabled(grant, this.env())
    const normalizedOrigin = url.origin
    const fail = (reasonCode: AdmissionReasonCode, matchedRule: string, reason: string): AdmissionDecision => ({
      outcome: 'deny',
      allowed: false,
      reason,
      reasonCode,
      matchedRule,
      effectiveTier,
      capabilityTier,
      normalizedMethod: 'GET',
      normalizedOrigin,
      normalizedPath,
      localLab,
      parsedUrl: url,
      normalizedHeaders: {},
    })

    const normalizedPath = `${url.pathname}${url.search}`
    const canonical = canonicalPathAndQuery(normalizedPath)
    if (canonical === null || hasUnsafeAdmissionPath(normalizedPath)) {
      return fail('malformed_path', 'path_syntax', 'Redirect path is not canonical or contains ambiguous path syntax.')
    }
    if (!isSafeAdmissionUrl(url, options.allowQuery ?? true, localLab, grant.allowedPorts, this.env())) {
      return fail('out_of_scope', 'grant_scope', 'Destination is outside the current assignment scope.')
    }
    if (this.checkExplicitDenylist(normalizedOrigin, canonical)) {
      return fail('explicit_denylist', 'explicit_denylist', 'Redirect destination matches an explicit denylist.')
    }

    if (options.redirectHop && localLab && !isLocalLabAutoApprovalOrigin(normalizedOrigin)) {
      return fail(
        'local_lab_redirect_escape',
        'local_lab_containment',
        'Local-lab requests may not follow redirects outside the isolated lab network.',
      )
    }
    const approvalMeta = resolveGrantApprovalContext(grant)
    const effectiveScopePolicy: ScopePolicy | undefined = grant.scopePolicy
      ? (approvalMeta.liveEnvironmentMode && approvalMeta.liveEnvironmentMode !== grant.scopePolicy.mode
          ? { ...grant.scopePolicy, mode: approvalMeta.liveEnvironmentMode }
          : grant.scopePolicy)
      : undefined
    if (options.requireTargetRole && effectiveScopePolicy && originRoleFor(effectiveScopePolicy, normalizedOrigin) !== 'target') {
      return fail(
        'origin_role_restricted',
        'scope_policy:target_role_only',
        'Passive root discovery is only permitted for target origins.',
      )
    }
    if (effectiveScopePolicy) {
      const scopeDecision = evaluateScopeRequest(effectiveScopePolicy, {
        origin: normalizedOrigin,
        method: 'GET',
        pathAndQuery: canonical,
        redirectHop: options.redirectHop,
        surface: 'broker',
      })
      if (!scopeDecision.allowed) {
        const code: AdmissionReasonCode =
          scopeDecision.code === 'out_of_scope' ? 'out_of_scope'
            : scopeDecision.code === 'auth_origin_active_probe' ? 'auth_origin_active_probe'
            : scopeDecision.code === 'asset_origin_active_probe' ? 'asset_origin_active_probe'
            : scopeDecision.code === 'invalid_path' ? 'malformed_path'
            : scopeDecision.code === 'staging_denylist' ? 'staging_denylist'
            : 'out_of_scope'
        return fail(code, `scope_policy:${scopeDecision.code}`, scopeDecision.reason)
      }
      if (isRouteDenylisted(effectiveScopePolicy, canonical)) {
        return fail('staging_denylist', 'scope_policy:staging_denylist',
          'Redirect destination is on the staging denylist.')
      }
    }
    if (!isOriginInGrantScope(grant, normalizedOrigin, effectiveScopePolicy)) {
      return fail('out_of_scope', 'grant_scope', 'Destination is outside the current assignment scope.')
    }
    if (this.options.scopeHopValidator) {
      const validated = this.options.scopeHopValidator(url, options.redirectHop === true)
      if (!validated.allowed) return validated
    }
    if (hasDestructiveContent(canonical)) {
      return fail('destructive_payload', 'denylist:destructive_payload',
        'Redirect destination is blocked by Kovo Hunter destructive-payload denylist.')
    }
    return {
      outcome: 'allow',
      allowed: true,
      reason: 'Redirect hop is inside the approved scope.',
      reasonCode: 'allowed',
      matchedRule: 'grant_scope',
      effectiveTier,
      capabilityTier,
      normalizedMethod: 'GET',
      normalizedOrigin,
      normalizedPath,
      localLab,
      parsedUrl: url,
      normalizedHeaders: {},
    }
  }

  /**
   * Canonical single-request admission decision.
   *
   * Set `evaluateConsumingHooks: false` internally (during batch pre-flight) to run all static
   * checks without consuming single-use approval grants or incrementing lease counters.
   */
  admit(
    request: AdmissionRequest,
    grantArg?: AdmissionGrant,
    internalOptions: { evaluateConsumingHooks?: boolean; budgetWeight?: number } = {},
  ): AdmissionDecision {
    const kind: AdmissionRequestKind = request.kind ?? 'http'
    const normalizedMethod = (
      request.method ??
      (kind === 'dns' ? 'DNS' : kind === 'tls' ? 'TLS' : kind === 'websocket' ? 'WS' : 'GET')
    ).toUpperCase()
    const rawPath = request.pathAndQuery ?? '/'
    const grant = grantArg ?? this.options.grantLookup?.(request)
    const capabilityTier = admissionTierToCapabilityTier(request.tierOverride ?? grant?.tier)
    const effectiveTier = capabilityTierToAdmissionTier(capabilityTier)

    const build = (
      outcome: AdmissionOutcome,
      reasonCode: AdmissionReasonCode,
      matchedRule: string | null,
      reason: string,
      extra: Partial<AdmissionDecision> = {},
    ): AdmissionDecision => ({
      outcome,
      allowed: outcome === 'allow',
      reason,
      reasonCode,
      matchedRule,
      effectiveTier,
      capabilityTier,
      normalizedMethod,
      normalizedOrigin: extra.normalizedOrigin ?? null,
      normalizedPath: extra.normalizedPath ?? rawPath,
      normalizedHeaders: extra.normalizedHeaders,
      ...extra,
    })

    if (!grant) {
      return build('deny', 'missing_grant', 'grant_required', 'No admission grant is configured for this request.')
    }

    if (this.options.killSwitchCheck) {
      const ks = this.options.killSwitchCheck(grant.tenantId ?? null)
      if (ks.active) {
        return build('deny', 'kill_switch_active', 'kill_switch', ks.reason ?? 'Global kill switch is active.')
      }
    }

    // 1. Tier 0 offline gate
    if (capabilityTier === 0) {
      const offlineReason =
        kind === 'dns' ? 'Live DNS inspection is disabled in Tier 0 (offline prepared mode).'
        : kind === 'tls' ? 'Live TLS inspection is disabled in Tier 0 (offline prepared mode).'
        : kind === 'websocket' ? 'Live WebSocket probing is disabled in Tier 0 (offline prepared mode).'
        : 'Live HTTP requests are disabled in Tier 0 (offline prepared mode).'
      return build('deny', 'tier_offline', 'tier:offline', offlineReason)
    }

    const env = this.env()
    const localLab = isLocalLabEnabled(grant, env)

    // 2. Origin & URL parsing + normalization
    let initialOrigin: string
    let url: URL
    try {
      const originInput = kind === 'websocket'
        ? request.origin.replace(/^wss:\/\//i, 'https://').replace(/^ws:\/\//i, 'http://')
        : request.origin
      initialOrigin = new URL(originInput).origin
      url = new URL(rawPath, initialOrigin)
    } catch {
      return build(
        'deny',
        'malformed_origin',
        'origin_syntax',
        kind === 'websocket' ? 'WebSocket origin or path is malformed.' : 'Request origin or path is malformed.',
      )
    }

    const normalizedPath = `${url.pathname}${url.search}`
    const approvalMeta = resolveGrantApprovalContext(grant)
    const effectiveScopePolicy: ScopePolicy | undefined = grant.scopePolicy
      ? (approvalMeta.liveEnvironmentMode && approvalMeta.liveEnvironmentMode !== grant.scopePolicy.mode
          ? { ...grant.scopePolicy, mode: approvalMeta.liveEnvironmentMode }
          : grant.scopePolicy)
      : undefined

    // 3. DNS / TLS / public_root specialized scope checks
    if (kind === 'dns') {
      if (effectiveScopePolicy && originRoleFor(effectiveScopePolicy, initialOrigin) !== 'target') {
        return build('deny', 'origin_role_restricted', 'scope_policy:target_role_only',
          'Passive DNS/TLS inspection is only permitted for target origins.',
          { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
      }
      const denied = this.checkExplicitDenylist(initialOrigin, '/')
      if (denied) {
        return build('deny', 'explicit_denylist', denied.matchedRule, denied.reason,
          { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
      }
      if (!isOriginInGrantScope(grant, initialOrigin, effectiveScopePolicy)) {
        return build('deny', 'out_of_scope', 'grant_scope', 'Destination is outside the current assignment scope.',
          { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
      }
      return build('allow', 'allowed_read_only', 'dns_inspect', 'DNS inspection permitted within scope.',
        { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
    }

    if (kind === 'tls') {
      const denied = this.checkExplicitDenylist(initialOrigin, '/')
      if (denied) {
        return build('deny', 'explicit_denylist', denied.matchedRule, denied.reason,
          { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
      }
      if (url.protocol !== 'https:' || !isOriginInGrantScope(grant, initialOrigin, effectiveScopePolicy) ||
          (effectiveScopePolicy && originRoleFor(effectiveScopePolicy, initialOrigin) !== 'target')) {
        return build('deny', 'out_of_scope', 'tls_https_target_only', 'TLS inspection requires an approved HTTPS origin.',
          { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
      }
      return build('allow', 'allowed_read_only', 'tls_inspect', 'TLS inspection permitted within scope.',
        { normalizedOrigin: initialOrigin, normalizedPath: '/', localLab, parsedUrl: url })
    }

    if (kind === 'public_root') {
      const hop = this.admitScopeHop(url, grant, { allowQuery: request.allowQuery ?? false, requireTargetRole: true })
      if (!hop.allowed) return hop
      return build('allow', 'allowed_read_only', 'public_root', 'Passive root discovery permitted within scope.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders: hop.normalizedHeaders })
    }

    // 4. Path & URL safety + origin scope + explicit denylist
    const rawIsAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawPath)
    if (hasUnsafeAdmissionPath(rawPath)) {
      return build(
        'deny',
        'malformed_path',
        'path_syntax',
        'Request path contains ambiguous dot-segment, separator, or control syntax.',
        { normalizedOrigin: initialOrigin, normalizedPath: rawPath, localLab },
      )
    }
    if (
      (!rawIsAbsolute && !rawPath.startsWith('/')) ||
      rawPath.startsWith('//') ||
      rawPath.length > MAX_ADMISSION_PATH_LENGTH ||
      /[\r\n\0]/.test(rawPath)
    ) {
      return build(
        'deny',
        'malformed_path',
        'path_syntax',
        kind === 'websocket'
          ? 'WebSocket path is invalid or exceeds Kovo Hunter 8 KiB limit.'
          : 'Request path is invalid or exceeds Kovo Hunter 8 KiB limit.',
        { normalizedOrigin: initialOrigin, normalizedPath: rawPath, localLab },
      )
    }
    const canonical = canonicalPathAndQuery(`${url.pathname}${url.search}`)
    if (url.origin !== initialOrigin) {
      return build('deny', 'origin_escape', 'origin_boundary', 'Request path escaped the requested origin.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
    }
    if (canonical === null || hasUnsafeAdmissionPath(canonical) || canonical !== `${url.pathname}${url.search}`) {
      return build('deny', 'malformed_path', 'path_syntax', 'Request path could not be canonicalized safely.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
    }

    const validProtocol = url.protocol === 'https:' || (localLab && url.protocol === 'http:')
    if (!validProtocol || url.username || url.password || url.hash) {
      return build(
        'deny',
        'protocol_not_allowed',
        'url_protocol',
        kind === 'websocket'
          ? 'WebSocket destination is outside the current assignment scope.'
          : 'Destination is outside the current assignment scope.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url },
      )
    }
    if (!localLab && !isPortAllowed(url.port, url.protocol, grant.allowedPorts, env)) {
      return build(
        'deny',
        'port_not_allowed',
        'url_port',
        kind === 'websocket'
          ? 'WebSocket destination is outside the current assignment scope.'
          : 'Destination is outside the current assignment scope.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url },
      )
    }
    if (!isOriginInGrantScope(grant, initialOrigin, effectiveScopePolicy)) {
      return build(
        'deny',
        'out_of_scope',
        'grant_scope',
        kind === 'websocket'
          ? 'WebSocket destination is outside the current assignment scope.'
          : 'Destination is outside the current assignment scope.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url },
      )
    }
    if (kind === 'websocket' && effectiveScopePolicy && originRoleFor(effectiveScopePolicy, initialOrigin) !== 'target') {
      return build('deny', 'origin_role_restricted', 'scope_policy:target_role_only',
        'WebSocket sessions are only permitted for target origins.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
    }
    if (request.redirectHop && localLab && !isLocalLabAutoApprovalOrigin(initialOrigin)) {
      return build('deny', 'local_lab_redirect_escape', 'local_lab_containment',
        'Local-lab requests may not follow redirects outside the isolated lab network.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
    }

    const explicitDenied = this.checkExplicitDenylist(initialOrigin, canonical)
    if (explicitDenied) {
      return build('deny', 'explicit_denylist', explicitDenied.matchedRule, explicitDenied.reason,
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
    }

    // 5. Validate and canonicalize caller headers once. Every later check uses this map.
    let normalizedHeaders = request.normalizedHeaders ?? {}
    let ephemeralObservedAuth = false
    if (request.checkCallerHeaders !== false) {
      const hdrCheck = validateCallerHeaders(request.headers, {
        allowSelfMintedBearer: kind !== 'websocket',
        stripPseudoHeaders: request.stripPseudoHeaders ?? kind === 'http2',
        ...(kind !== 'websocket' && request.isAuthorizedEphemeralBearer
          ? { isAuthorizedEphemeralBearer: request.isAuthorizedEphemeralBearer }
          : {}),
      })
      if (!hdrCheck.ok) {
        return build('deny', hdrCheck.reasonCode, `header:${hdrCheck.reasonCode}`,
          kind === 'websocket' && hdrCheck.reasonCode === 'invalid_header' ? 'Invalid WebSocket request header.' : hdrCheck.reason,
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
      }
      normalizedHeaders = hdrCheck.headers
      ephemeralObservedAuth = Boolean(hdrCheck.ephemeralObservedAuth)
    }
    const serializedHeaders = Object.entries(normalizedHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')
    const wsSubprotocols = request.wsSubprotocols ?? []
    if (kind === 'websocket') {
      if (wsSubprotocols.some(protocol => !isValidWebsocketSubprotocol(protocol))) {
        return build('deny', 'invalid_header', 'header:invalid_websocket_subprotocol',
          'WebSocket subprotocols must be non-empty RFC token values without control characters.',
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
      }
      const wsMessages = [...(request.wsSendMessages ?? []), ...wsSubprotocols]
      const wsText = [canonical, request.wsOriginHeader ?? '', serializedHeaders, ...wsMessages].join('\n')
      if (hasDestructiveContent(wsText)) {
        return build('deny', 'destructive_payload', 'denylist:destructive_payload',
          'WebSocket probe blocked by Kovo Hunter destructive-payload denylist.',
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
      }
      if (request.personaHandle && capabilityTier < 2) {
        return build('deny', 'tier_insufficient', 'tier:persona_requires_supervised',
          'Persona-authenticated WebSocket probes require Tier 2 or higher.',
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
      }
      const hookDenial = this.evaluateBudgetAndRateHooks(request, grant, initialOrigin, normalizedMethod, canonical, effectiveTier, capabilityTier, kind, internalOptions.budgetWeight ?? 1)
      if (hookDenial) return { ...hookDenial, normalizedHeaders, localLab, parsedUrl: url }
      return build('allow', 'allowed', 'websocket_scope', 'WebSocket probe permitted within scope.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
    }

    if (
      hasDestructiveContent(canonical) ||
      hasDestructiveContent(serializedHeaders) ||
      (request.body !== undefined && hasDestructiveContent(request.body))
    ) {
      return build('deny', 'destructive_payload', 'denylist:destructive_payload',
        'Request blocked by Kovo Hunter destructive-payload denylist.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
    }
    if (request.authMutation?.kind === 'kid_inject' && hasDestructiveContent(request.authMutation.value)) {
      return build('deny', 'destructive_payload', 'denylist:auth_mutation_kid',
        'authMutation kid_inject blocked by Kovo Hunter destructive-payload denylist.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
    }
    if (request.authMutation?.kind === 'jku_x5u_canary') {
      const candidateUrl = request.authMutation.url ?? request.authMutation.value
      if (candidateUrl && (hasDestructiveContent(candidateUrl) || /[\r\n\0]/.test(candidateUrl))) {
        return build('deny', 'destructive_payload', 'denylist:auth_mutation_jku',
          'authMutation jku_x5u_canary blocked by Kovo Hunter destructive-payload denylist.',
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
      }
    }

    const hasMultipartParts = Array.isArray(request.multipartParts) && request.multipartParts.length > 0
    if (hasMultipartParts && request.body !== undefined) {
      return build('deny', 'conflicting_body_multipart', 'request:body_multipart_exclusive',
        'Specify either body or multipartParts, not both.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
    }
    if (hasMultipartParts) {
      for (const part of request.multipartParts!) {
        const serialized = `${part.name}\n${part.filename ?? ''}\n${part.contentType ?? ''}\n${part.content}`
        if (hasDestructiveContent(serialized)) {
          return build('deny', 'destructive_payload', 'denylist:multipart_destructive',
            'Multipart upload blocked by Kovo Hunter destructive-payload denylist.',
            { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
        }
        if (containsWebshellSignature(serialized)) {
          return build('deny', 'webshell_signature', 'denylist:multipart_webshell',
            'Multipart upload blocked by Kovo Hunter webshell signature filter.',
            { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, normalizedHeaders })
        }
      }
    }

    // 6. AuthMutation & Persona Tier gate
    if (request.authMutation) {
      if (capabilityTier < 2) {
        return build('deny', 'tier_insufficient', 'tier:auth_mutation_requires_supervised',
          'Broker authMutation primitives require Tier 2 or higher.',
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
      }
      if (!request.personaHandle) {
        return build('deny', 'persona_required', 'auth_mutation:persona_required',
          'authMutation requires an approved persona handle.',
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
      }
    }
    if (request.personaHandle && capabilityTier < 2) {
      return build('deny', 'tier_insufficient', 'tier:persona_requires_supervised',
        'Persona-authenticated requests require Tier 2 or higher.',
        { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url })
    }

    // 7. Strict Method + GraphQL + JSON-RPC mutation classification
    const decisionHeaders = { ...normalizedHeaders }
    const confirmedGraphqlEndpoints =
      request.confirmedGraphqlEndpoints ??
      grant.confirmedGraphqlEndpoints ??
      effectiveScopePolicy?.confirmedGraphqlEndpoints
    const classification = classifyRequestMutation({
      origin: initialOrigin,
      method: normalizedMethod,
      pathAndQuery: canonical,
      body: request.body ?? null,
      headers: normalizedHeaders,
      multipartParts: request.multipartParts,
      ...(confirmedGraphqlEndpoints !== undefined ? { confirmedGraphqlEndpoints } : {}),
    })

    // 8. Budget / rate-limit admission hooks (before consuming any single-use approval grants)
    if (internalOptions.evaluateConsumingHooks !== false) {
      const hookDenial = this.evaluateBudgetAndRateHooks(
        request, grant, initialOrigin, normalizedMethod, canonical, effectiveTier, capabilityTier, kind, internalOptions.budgetWeight ?? 1,
      )
      if (hookDenial) return { ...hookDenial, classification, normalizedHeaders: decisionHeaders, localLab, parsedUrl: url }
    }

    // 9. ScopePolicy + Tier + Approval Policy + Leases + SandboxWriteAllowlist + Exact Grant
    const evaluateConsuming = internalOptions.evaluateConsumingHooks !== false
    let contractApproved = false
    let approvedReasonCode: AdmissionReasonCode = classification.isReadOnly
      ? 'allowed_read_only'
      : classification.isVerifiedGraphqlRead
        ? 'allowed_graphql_readonly'
        : 'allowed'
    let approvedRule = classification.isReadOnly
      ? 'method:read_only'
      : classification.isVerifiedGraphqlRead
        ? 'graphql:verified_readonly'
        : 'grant_scope'

    if (effectiveScopePolicy) {
      const derivedStaging = effectiveScopePolicy.mode === 'staging_isolated' && !approvalMeta.explicitEnvironmentMode
      const scopeDecision = evaluateScopeRequest(effectiveScopePolicy, {
        origin: initialOrigin,
        method: normalizedMethod,
        pathAndQuery: canonical,
        body: request.body ?? null,
        headers: normalizedHeaders,
        ...(confirmedGraphqlEndpoints !== undefined ? { confirmedGraphqlEndpoints } : {}),
        ...(derivedStaging ? { derivedEnvironmentMode: true } : {}),
        redirectHop: request.redirectHop,
        hook: request.scopeHook ?? null,
        surface: request.surface ?? (kind === 'browser' ? 'browser' : 'broker'),
      })
      const contractApplies = effectiveScopePolicy.mode !== 'ephemeral_lab'
      const leaseClassificationEligible = isDurableRouteLeaseEligible(classification, {
        isRaceBurst: request.isRaceBurst === true,
      })
      const checkLease = (): boolean =>
        leaseClassificationEligible &&
        grant.approvalLeases?.(initialOrigin, classification.effectiveMethod, canonical) === true

      const sandboxPostAllowed =
        !classification.hasMultipart &&
        !classification.hasCompressedBody &&
        !classification.hasOverrideRisk &&
        normalizedMethod === 'POST' &&
        capabilityTier === 2 &&
        grant.sandboxWriteAllowlist !== undefined &&
        matchesSandboxWriteAllowlist(initialOrigin, url.pathname, canonical, grant.sandboxWriteAllowlist)

      if (scopeDecision.allowed) {
        if (classification.isReadOnly || classification.isVerifiedGraphqlRead) {
          contractApproved = contractApplies
          approvedReasonCode = classification.isVerifiedGraphqlRead ? 'allowed_graphql_readonly' : 'allowed_read_only'
          approvedRule = classification.isVerifiedGraphqlRead ? 'scope_policy:graphql_readonly' : 'scope_policy:read_only'
        } else if (approvalMeta.explicitEnvironmentMode) {
          // R3-H-1(b): Even on explicit staging_isolated, method-override carriers, over-cap
          // (>64 KiB) bodies, and unscannable bodies MUST escalate through `isStateChangeApproved`
          // (matching `approval-judge.ts`), unless policy is explicitly `yolo`.
          const allowExplicitContract =
            contractApplies &&
            (!classification.hasOverrideRisk || approvalMeta.effectivePolicy === 'yolo')
          contractApproved = allowExplicitContract || (evaluateConsuming && checkLease())
          if (contractApproved) {
            approvedReasonCode = allowExplicitContract ? 'allowed_environment_contract' : 'allowed_approval_lease'
            approvedRule = allowExplicitContract ? `scope_policy:${effectiveScopePolicy.mode}` : 'approval_lease'
          }
        } else if (!contractApplies) {
          contractApproved = evaluateConsuming && checkLease()
          if (contractApproved) {
            approvedReasonCode = 'allowed_approval_lease'
            approvedRule = 'approval_lease'
          }
        } else if (approvalMeta.effectivePolicy === 'yolo') {
          contractApproved = true
          approvedReasonCode = 'allowed_environment_contract'
          approvedRule = 'approval_policy:yolo'
        } else if (approvalMeta.effectivePolicy === 'strict') {
          contractApproved = evaluateConsuming && checkLease()
          if (contractApproved) {
            approvedReasonCode = 'allowed_approval_lease'
            approvedRule = 'approval_lease'
          }
        } else {
          // R3-H-1(a): Derived (non-explicit) staging_isolated under `auto_review` NEVER
          // auto-approves writes via tenant tags (neither headers nor host-injected
          // `stagingProbeTag` / `tagStagingEntityBody` body fields) or hooks. Every non-read-only
          // mutation without an eligible durable operator lease routes through `isStateChangeApproved`.
          contractApproved = evaluateConsuming && checkLease()
          if (contractApproved) {
            approvedReasonCode = 'allowed_approval_lease'
            approvedRule = 'approval_lease'
          }
        }
      } else {
        const leaseEligible =
          contractApplies &&
          leaseClassificationEligible &&
          scopeDecision.code !== 'out_of_scope' &&
          scopeDecision.code !== 'invalid_path' &&
          scopeDecision.code !== 'auth_origin_active_probe' &&
          scopeDecision.code !== 'asset_origin_active_probe'
        const leased = leaseEligible && evaluateConsuming && checkLease()
        if (leased) {
          contractApproved = true
          approvedReasonCode = 'allowed_approval_lease'
          approvedRule = 'approval_lease:override'
        } else if (scopeDecision.code === 'readonly_environment' && sandboxPostAllowed) {
          // Tier-2 project sandboxWriteAllowlist explicitly authorizes this non-multipart POST.
          contractApproved = false
        } else if (
          scopeDecision.code === 'staging_untagged_mutation' &&
          !approvalMeta.explicitEnvironmentMode &&
          capabilityTier >= 3
        ) {
          contractApproved = approvalMeta.effectivePolicy === 'yolo'
          if (contractApproved) {
            approvedReasonCode = 'allowed_environment_contract'
            approvedRule = 'approval_policy:yolo'
          }
        } else if (!evaluateConsuming && leaseEligible && typeof grant.approvalLeases === 'function') {
          // Defer lease evaluation to the consuming phase of admitBatch so static pre-flight
          // doesn't reject a route that an active durable lease authorizes.
          contractApproved = false
        } else {
          const mappedCode: AdmissionReasonCode =
            scopeDecision.code === 'out_of_scope' ? 'out_of_scope'
            : scopeDecision.code === 'auth_origin_active_probe' ? 'auth_origin_active_probe'
            : scopeDecision.code === 'asset_origin_active_probe' ? 'asset_origin_active_probe'
            : scopeDecision.code === 'readonly_environment' ? 'readonly_environment'
            : scopeDecision.code === 'staging_denylist' ? 'staging_denylist'
            : scopeDecision.code === 'staging_untagged_mutation' ? 'staging_untagged_mutation'
            : scopeDecision.code === 'invalid_path' ? 'malformed_path'
            : 'out_of_scope'
          return build('deny', mappedCode, `scope_policy:${scopeDecision.code}`, scopeDecision.reason,
            { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, classification })
        }
      }

      if (contractApproved && !classification.isReadOnly && !classification.isVerifiedGraphqlRead && capabilityTier < 3) {
        return build('deny', 'tier_insufficient', 'tier:mutation_requires_autonomous',
          `Method ${normalizedMethod} requires Tier 3 (approval-gated state validation).`,
          { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, classification })
      }
    }

    if (!contractApproved && (!classification.isReadOnly || classification.hasMultipart)) {
      const sandboxPostAllowed =
        !classification.hasMultipart &&
        !classification.hasCompressedBody &&
        !classification.hasOverrideRisk &&
        normalizedMethod === 'POST' &&
        capabilityTier === 2 &&
        (grant.sandboxWriteAllowlist !== undefined
          ? matchesSandboxWriteAllowlist(initialOrigin, url.pathname, canonical, grant.sandboxWriteAllowlist)
          : localLab)

      if (sandboxPostAllowed) {
        approvedReasonCode = grant.sandboxWriteAllowlist !== undefined ? 'allowed_sandbox_allowlist' : 'allowed_local_lab'
        approvedRule = grant.sandboxWriteAllowlist !== undefined ? 'sandbox_write_allowlist' : 'local_lab:tier2_post'
      } else {
        if (capabilityTier < 3) {
          return build(
            'deny',
            'tier_insufficient',
            classification.hasMultipart ? 'tier:multipart_requires_autonomous' : 'tier:mutation_requires_autonomous',
            classification.hasMultipart
              ? 'Multipart uploads require Tier 3 (approval-gated state validation).'
              : `Method ${classification.effectiveMethod} requires Tier 3 (approval-gated state validation).`,
            { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, classification },
          )
        }
        const multipartKind = detectMultipartRequest({
          headers: decisionHeaders,
          hasMultipart: classification.hasMultipart,
          bodyPreview: hasMultipartParts ? null : (request.body ?? null),
        })
        const approvalContext: StateChangeApprovalContext = {
          personaHandle: request.personaHandle ?? null,
          body: hasMultipartParts ? null : (request.body ?? null),
          bodyHash: computeStateChangeBodyHash(request.body, request.multipartParts),
          headers: decisionHeaders,
          headersDigest: computeApprovalHeadersDigest(decisionHeaders),
          hasMultipart: classification.hasMultipart,
          multipartKind,
          isRaceBurst: request.isRaceBurst === true,
          hasCompressedBody: classification.hasCompressedBody,
          hasMethodOverride: classification.hasMethodOverride,
          effectiveMethod: classification.effectiveMethod,
          ...(request.assignmentId ? { assignmentId: request.assignmentId } : {}),
        }
        if (evaluateConsuming) {
          const approved = grant.isStateChangeApproved
            ? grant.isStateChangeApproved(initialOrigin, normalizedMethod, canonical, approvalContext)
            : localLab
          if (!approved) {
            return build(
              'require_approval',
              'approval_required',
              request.redirectHop ? 'tier3_redirect_approval_required' : 'tier3_approval_required',
              request.redirectHop
                ? `Approval required for state-changing redirect ${classification.effectiveMethod} ${canonical}.`
                : `Tier 3 operator approval required for ${classification.effectiveMethod} ${initialOrigin}${canonical}`,
              { normalizedOrigin: initialOrigin, normalizedPath, localLab, parsedUrl: url, classification, approvalContext },
            )
          }
          approvedReasonCode = grant.isStateChangeApproved ? 'allowed_state_change_approved' : 'allowed_local_lab'
          approvedRule = grant.isStateChangeApproved ? 'grant:is_state_change_approved' : 'local_lab:tier3_default'
        }
      }
    }

    return build('allow', approvedReasonCode, approvedRule, 'Request admitted.', {
      normalizedOrigin: initialOrigin,
      normalizedPath,
      localLab,
      parsedUrl: url,
      classification,
      normalizedHeaders: decisionHeaders,
      ...(ephemeralObservedAuth ? { ephemeralObservedAuth: true } : {}),
    })
  }

  /**
   * H-4 Per-target Batch / Race Burst Admission:
   *   1. Enforces Tier >= 2 (`supervised` / `autonomous`) and 2..10 batch bounds.
   *   2. Phase 1 (non-consuming): runs all static scope/denylist/tier/header/destructive checks
   *      across EVERY item first so a bad sibling never burns an earlier item's single-use grant.
   *   3. Phase 2 (consuming): evaluates EVERY target individually against leases & exact approval
   *      grants — approval of item 0 NEVER authorizes a distinct item 1.
   */
  admitBatch(
    requests: readonly AdmissionRequest[],
    grantArg?: AdmissionGrant,
    options: { isRaceBurst?: boolean; minSize?: number; maxSize?: number } = {},
  ): BatchAdmissionDecision {
    const grant = grantArg ?? (requests[0] ? this.options.grantLookup?.(requests[0]) : undefined)
    const capabilityTier = admissionTierToCapabilityTier(grant?.tier)
    const effectiveTier = capabilityTierToAdmissionTier(capabilityTier)
    const isRace = options.isRaceBurst === true
    const minSize = options.minSize ?? 2
    const maxSize = options.maxSize ?? 10

    if (!grant) {
      return {
        outcome: 'deny',
        allowed: false,
        reason: 'No admission grant is configured for this batch.',
        reasonCode: 'missing_grant',
        matchedRule: 'grant_required',
        effectiveTier,
        capabilityTier,
        decisions: [],
        failedIndex: null,
      }
    }
    if (capabilityTier < 2) {
      return {
        outcome: 'deny',
        allowed: false,
        reason: isRace
          ? 'Safe race-condition burst execution (executeRaceBurst) requires Tier 2 or Tier 3.'
          : 'Synchronized parallel batches (executeBatch) require Tier 2 or Tier 3.',
        reasonCode: 'tier_insufficient',
        matchedRule: 'tier:batch_requires_supervised',
        effectiveTier,
        capabilityTier,
        decisions: [],
        failedIndex: null,
      }
    }
    if (!Array.isArray(requests) || requests.length < minSize || requests.length > maxSize) {
      return {
        outcome: 'deny',
        allowed: false,
        reason: isRace
          ? `executeRaceBurst requires between ${minSize} and ${maxSize} requests.`
          : `executeBatch requires between ${minSize} and ${maxSize} requests.`,
        reasonCode: 'batch_size_invalid',
        matchedRule: 'batch:size_bounds',
        effectiveTier,
        capabilityTier,
        decisions: [],
        failedIndex: null,
      }
    }

    // Phase 1: static non-consuming pre-flight across ALL items in the batch.
    const preflightDecisions: AdmissionDecision[] = []
    for (let i = 0; i < requests.length; i += 1) {
      const pre = this.admit({ ...requests[i]!, isRaceBurst: isRace }, grant, { evaluateConsumingHooks: false })
      preflightDecisions.push(pre)
      if (!pre.allowed) {
        return {
          outcome: pre.outcome,
          allowed: false,
          reason: pre.reason,
          reasonCode: pre.reasonCode,
          matchedRule: pre.matchedRule,
          effectiveTier: pre.effectiveTier,
          capabilityTier: pre.capabilityTier,
          decisions: [pre],
          failedIndex: i,
        }
      }
    }

    const targetsHash = `batch-admit-v1:${createHash('sha256')
      .update(
        JSON.stringify(
          preflightDecisions.map((pre, idx) => {
            const req = requests[idx]!
            return [
              normalizeOriginKey(pre.normalizedOrigin ?? req.origin),
              pre.normalizedMethod,
              pre.classification?.effectiveMethod ?? pre.normalizedMethod,
              pre.normalizedPath,
              req.personaHandle ?? '',
              computeStateChangeBodyHash(req.body ?? null, req.multipartParts) ?? '',
              computeApprovalHeadersDigest(pre.normalizedHeaders ?? req.headers) ?? '',
              Boolean(pre.classification?.hasMultipart),
              Boolean(pre.classification?.hasCompressedBody),
              Boolean(pre.classification?.hasMethodOverride),
              Boolean(pre.classification?.hasOverCapBody),
              Boolean(pre.classification?.hasOverrideRisk),
            ]
          }),
        ),
        'utf8',
      )
      .digest('hex')}`

    // Phase 2: per-target consuming evaluation (H-4: every target evaluated individually).
    const decisions: AdmissionDecision[] = []
    for (let i = 0; i < requests.length; i += 1) {
      const dec = this.admit({ ...requests[i]!, isRaceBurst: isRace }, grant, {
        evaluateConsumingHooks: true,
        budgetWeight: 1,
      })
      decisions.push(dec)
      if (!dec.allowed) {
        return {
          outcome: dec.outcome,
          allowed: false,
          reason: dec.reason,
          reasonCode: dec.reasonCode,
          matchedRule: dec.matchedRule,
          effectiveTier: dec.effectiveTier,
          capabilityTier: dec.capabilityTier,
          decisions,
          failedIndex: i,
          targetsHash,
        }
      }
    }

    return {
      outcome: 'allow',
      allowed: true,
      reason: `All ${decisions.length} batch targets admitted.`,
      reasonCode: 'allowed',
      matchedRule: isRace ? 'batch:race_admitted' : 'batch:admitted',
      effectiveTier,
      capabilityTier,
      decisions,
      failedIndex: null,
      targetsHash,
    }
  }

  private evaluateBudgetAndRateHooks(
    request: AdmissionRequest,
    grant: AdmissionGrant,
    normalizedOrigin: string,
    normalizedMethod: string,
    pathAndQuery: string,
    effectiveTier: AdmissionTier,
    capabilityTier: CapabilityTier,
    kind: AdmissionRequestKind,
    weight: number,
  ): AdmissionDecision | null {
    const budgetCtx: AdmissionBudgetContext = {
      origin: normalizedOrigin,
      method: normalizedMethod,
      pathAndQuery,
      effectiveTier,
      capabilityTier,
      kind,
      weight,
      ...(request.runId ? { runId: request.runId } : {}),
      ...(request.assignmentId ? { assignmentId: request.assignmentId } : {}),
    }
    if (this.options.budgetCheck) {
      const res = this.options.budgetCheck(budgetCtx)
      if (!res.allowed) {
        return {
          outcome: 'deny',
          allowed: false,
          reason: res.reason,
          reasonCode: res.reasonCode ?? 'budget_exhausted',
          matchedRule: 'hook:budget',
          effectiveTier,
          capabilityTier,
          normalizedMethod,
          normalizedOrigin,
          normalizedPath: pathAndQuery,
          ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}),
        }
      }
    }
    if (this.options.rateLimitCheck) {
      const maxRps = grant.getMaxRpsPerOrigin ? grant.getMaxRpsPerOrigin() : grant.maxRpsPerOrigin
      const res = this.options.rateLimitCheck({
        ...budgetCtx,
        ...(maxRps !== undefined ? { maxRpsPerOrigin: maxRps } : {}),
      })
      if (!res.allowed) {
        return {
          outcome: 'deny',
          allowed: false,
          reason: res.reason,
          reasonCode: res.reasonCode ?? 'rate_limited',
          matchedRule: 'hook:rate_limit',
          effectiveTier,
          capabilityTier,
          normalizedMethod,
          normalizedOrigin,
          normalizedPath: pathAndQuery,
          ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}),
        }
      }
    }
    return null
  }
}

export const defaultRequestAdmissionEngine = new RequestAdmissionEngine()
