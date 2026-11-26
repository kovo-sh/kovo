/**
 * Canonicalizes and matches operator-approved endpoint path patterns through the shared scope
 * path primitive, keeping admission, leases, denylists, and approvals on one interpretation.
 */
import { createHash } from 'node:crypto'
import {
  deriveOperatorPrefixPatternFromNormalized,
  evaluateClientApprovalLeaseEligibility,
  HOST_NONDESTRUCTIVE_LEASE_METHOD,
  HOST_NONDESTRUCTIVE_LEASE_PATTERN,
  isConcreteApprovalIdSegment,
  isHighRiskOrExternalMutationPath,
  isHostNonDestructiveLease,
  isNonDestructiveMutationMethod,
  isPrefixApprovalPattern,
  NON_DESTRUCTIVE_MUTATION_METHODS,
} from '../domain.ts'
import type {
  ApprovalLeaseScope,
  ApprovalPathPatternSource,
  ApprovedEndpointPattern,
} from '../domain.ts'
import {
  canonicalPathAndQuery,
  detectMethodOverride,
  isVerifiedReadOnlyGraphqlQuery,
  parseStrictJsonObject,
} from './scope-policy.ts'
import type { EnvironmentMode } from './scope-policy.ts'

export {
  HOST_NONDESTRUCTIVE_LEASE_METHOD,
  HOST_NONDESTRUCTIVE_LEASE_PATTERN,
  isHighRiskOrExternalMutationPath,
  isHostNonDestructiveLease,
  isNonDestructiveMutationMethod,
  isPrefixApprovalPattern,
  NON_DESTRUCTIVE_MUTATION_METHODS,
}
export type { ApprovalPathPatternSource }

const PLACEHOLDER_SEGMENT = /^(?::[A-Za-z0-9_]+|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\])$/

/**
 * True only for genuinely identifier-shaped path segments (numeric, UUID, Mongo id, long hex,
 * prefixed id, or a high-entropy opaque token). A wildcard in an approved endpoint pattern must
 * never match a sibling verb or a literal path word: that is how an approval for
 * `POST /api/items/<id>` used to cover `POST /api/items/delete`.
 */
function isConcreteIdSegment(segment: string): boolean {
  return isConcreteApprovalIdSegment(segment)
}

function isIdLikeSegment(segment: string): boolean {
  return PLACEHOLDER_SEGMENT.test(segment) || isConcreteIdSegment(segment)
}

export interface NormalizeApprovalPathOptions {
  /**
   * Provenance of the input path (SECURITY-REAUDIT 1.3 / R3-H-9 / R4-H-1):
   * - `'card_path'` (default): worker-originated path from an approval card or target request.
   *   Literal `*` and `**` segments are escaped to `%2a` / `%2a%2a` so they match ONLY the exact
   *   literal path segment and never produce a wildcard or prefix glob. Concrete ID segments
   *   (numeric, UUID, Mongo ID, etc.) still generalize to `*`.
   * - `'operator_explicit'`: pattern explicitly authored by a human operator. Preserves `*`
   *   (single ID-shaped segment wildcard), `:id`/`{id}`/`[id]` placeholders, and trailing `**`
   *   (prefix wildcard, requiring at least two fixed non-wildcard prefix segments).
   */
  source?: ApprovalPathPatternSource
}

export interface ApprovalPathGlobInspection {
  /** True when any pathname segment contains a `*` glob metacharacter. */
  hasGlobMetacharacters: boolean
  /** True when any pathname segment is an exact `*` or `**` wildcard segment. */
  hasWildcardSegment: boolean
  /** True when any pathname segment is the `**` prefix-glob segment. */
  hasPrefixGlobSegment: boolean
  /** Offending pathname segments containing `*`, in path order. */
  globSegments: string[]
}

const ORIGIN_PREFIX_RE = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i

/**
 * Inspect a worker-submitted request `pathAndQuery` for glob metacharacters (`*`, `**`) in its
 * pathname segments so approval cards can be flagged before operator review (R3-H-9).
 * Query strings and fragments are excluded because approval patterns operate on pathnames only.
 */
export function inspectApprovalPathGlobs(pathAndQuery: string): ApprovalPathGlobInspection {
  const canonical = canonicalPathAndQuery(pathAndQuery)
  let pathname: string
  if (canonical !== null) {
    pathname = canonical.split('?', 1)[0]!
  } else {
    const trimmed = (pathAndQuery || '').trim()
    const withoutOrigin = ORIGIN_PREFIX_RE.test(trimmed) ? trimmed.replace(ORIGIN_PREFIX_RE, '') : trimmed
    const q = withoutOrigin.indexOf('?')
    const h = withoutOrigin.indexOf('#')
    const cut = q >= 0 && h >= 0 ? Math.min(q, h) : q >= 0 ? q : h
    pathname = cut >= 0 ? withoutOrigin.slice(0, cut) : withoutOrigin
  }

  const globSegments: string[] = []
  let hasWildcardSegment = false
  let hasPrefixGlobSegment = false
  for (const seg of pathname.split('/')) {
    if (!seg) continue
    if (seg.includes('*')) {
      globSegments.push(seg)
      if (seg === '*' || seg === '**') hasWildcardSegment = true
      if (seg === '**') hasPrefixGlobSegment = true
    }
  }
  return {
    hasGlobMetacharacters: globSegments.length > 0,
    hasWildcardSegment,
    hasPrefixGlobSegment,
    globSegments,
  }
}

export function hasApprovalPathGlobMetacharacters(pathAndQuery: string): boolean {
  return inspectApprovalPathGlobs(pathAndQuery).hasGlobMetacharacters
}

export function normalizeOriginKey(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase().replace(/\/+$/, '')
  }
}

/**
 * Canonicalize request headers into a deterministically ordered, lowercased record for approval
 * fingerprinting and batch target grouping (`H-4`).
 */
export function canonicalizeApprovalHeaders(
  headers?: Record<string, string | string[] | undefined>,
): Record<string, string> {
  if (!headers) return {}
  const entries: Array<[string, string]> = []
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue
    const key = rawKey.trim().toLowerCase()
    if (!key) continue
    const value = Array.isArray(rawValue)
      ? rawValue.map(v => v.trim()).join(', ')
      : String(rawValue).trim()
    entries.push([key, value])
  }
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  const out: Record<string, string> = {}
  for (const [k, v] of entries) {
    out[k] = k in out ? `${out[k]}, ${v}` : v
  }
  return out
}

/**
 * Stable SHA-256 digest of canonicalized request headers (`H-4`). Returns `null` when no headers
 * are present so headerless requests have a distinct, explicit digest state.
 */
export function computeApprovalHeadersDigest(
  headers?: Record<string, string | string[] | undefined>,
): string | null {
  const canonical = canonicalizeApprovalHeaders(headers)
  const keys = Object.keys(canonical)
  if (keys.length === 0) return null
  const pairs = keys.map(k => [k, canonical[k]])
  return `hdr:${createHash('sha256').update(JSON.stringify(pairs), 'utf8').digest('hex')}`
}

export function normalizeApprovalPathPattern(
  pathAndQuery: string,
  options?: NormalizeApprovalPathOptions,
): string {
  const source: ApprovalPathPatternSource = options?.source ?? 'card_path'
  const canonical = canonicalPathAndQuery(pathAndQuery)
  if (canonical === null) return ''
  let pathname = canonical.split('?', 1)[0]!
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1)
  }

  const segments = pathname.split('/').map((seg, idx) => {
    if (idx === 0 && seg === '') return ''
    if (!seg) return ''
    if (seg === '*' || seg === '**') {
      if (source === 'operator_explicit') return seg
      // Escape literal worker-submitted glob segments so they match only the exact literal segment
      // and never become an ID wildcard or prefix glob (R3-H-9 / SECURITY-REAUDIT 1.3).
      return seg === '**' ? '%2a%2a' : '%2a'
    }
    if (source === 'operator_explicit' ? isIdLikeSegment(seg) : isConcreteIdSegment(seg)) {
      return '*'
    }
    return seg.toLowerCase()
  })

  return segments.join('/') || '/'
}

/**
 * Derive an explicit operator-authored prefix pattern (e.g. `/api/v1/users/123` -> `/api/v1/**`,
 * `/_actions/courses/redeem` -> `/_actions/courses/**`) from a worker-submitted request path.
 *
 * R3-H-9 / R4-H-1 invariants: returns `null` whenever the card path contains ANY glob
 * metacharacter (`*`), is malformed, has fewer than two concrete fixed prefix segments
 * (rejecting bare `/**` and single-segment `/api/**`), or targets a high-risk prefix base.
 */
export function deriveOperatorPrefixPattern(pathAndQuery: string): string | null {
  if (hasApprovalPathGlobMetacharacters(pathAndQuery)) return null
  const normalized = normalizeApprovalPathPattern(pathAndQuery, { source: 'card_path' })
  if (!normalized) return null
  return deriveOperatorPrefixPatternFromNormalized(normalized, false)
}

// ---------------------------------------------------------------------------
// Single authoritative lease-eligibility predicate (R4-H-1)
//
// Evaluated at match time across ALL THREE `leaseAuthorizes` steps (`route`,
// `prefix`, `host_nondestructive`), `RequestAdmissionEngine`, Judge Stage 1B
// (`approval-judge.ts`), and (via `evaluateClientApprovalLeaseEligibility`) the
// Queue UI so enforcement and operator consent copy can never drift apart.
// ---------------------------------------------------------------------------

const LEASE_BODY_SCAN_CHARS = 64 * 1024

const LEASE_JSONRPC_READ_METHOD_RE =
  /^(?:[a-z][a-z0-9_-]*[./:])?(?:get|list|read|find|fetch|query|search|describe|inspect|show|view|check|ping|health|status|version|info|echo)(?:[A-Z_].*)?$/
const LEASE_JSONRPC_DESTRUCTIVE_METHOD_RE =
  /(?:^|[./:_-])(?:delete|destroy|drop|purge|wipe|truncate|remove|revoke|reset|exec|eval|shell|shutdown|kill|nuke)(?:$|[./:_-]|[A-Z])/i

const LEASE_DESTRUCTIVE_BODY_ACTION_KEYS = new Set([
  'action', 'op', 'operation', 'command', 'cmd', 'method', 'type', 'intent', 'event', 'task', 'mutation',
])

const LEASE_HIGH_RISK_BODY_KEYS = new Set([
  'isadmin', 'is_admin', 'superadmin', 'role', 'roles', 'permission', 'permissions', 'privilege', 'privileges',
  'grantrole', 'grant_role', 'setrole', 'set_role', 'refundamount', 'refund_amount', 'payoutamount', 'payout_amount',
  'wiretransfer', 'wire_transfer', 'deleteaccount', 'delete_account', 'closeaccount', 'close_account',
  'cancelsubscription', 'cancel_subscription', 'revoketoken', 'revoke_token', 'rotatekey', 'rotate_key',
  'webhookurl', 'webhook_url',
])

const LEASE_DESTRUCTIVE_ACTION_TOKENS = new Set([
  'delete', 'destroy', 'drop', 'purge', 'wipe', 'truncate', 'terminate', 'deactivate', 'unregister',
  'unsubscribe', 'remove', 'cancel', 'close', 'reset', 'revoke', 'rotate', 'reissue', 'regenerate',
  'refund', 'charge', 'payout', 'transfer', 'withdraw', 'wire', 'impersonate', 'escalate',
  'broadcast', 'exec', 'eval', 'shell', 'deploy', 'nuke', 'kill', 'shutdown',
])

export type LeaseEligibilityScope = ApprovalLeaseScope | 'any'

export interface LeaseMatchContext {
  origin?: string
  body?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  multipartKind?: 'none' | 'multipart' | 'malformed_multipart'
  isRaceBurst?: boolean
  isRceProof?: boolean
  hasCompressedBody?: boolean
  hasMethodOverride?: boolean
  hasOverCapBody?: boolean
  overrideScanIncomplete?: boolean
  hasOverrideRisk?: boolean
  isStructuralMutation?: boolean
  mutationKind?: string
  effectiveMethod?: string
  hostFloor?: 'low' | 'medium' | 'high'
  riskLevel?: string | null
  environmentMode?: EnvironmentMode | null
  confirmedGraphqlEndpoints?: readonly string[]
  /**
   * Set ONLY by Judge Stage 1B for exact `route` patterns explicitly approved by an operator,
   * preserving exact-route DELETE & well-formed multipart approval while keeping prefix/host strict.
   */
  allowExplicitRouteStructural?: boolean
}

export interface LeaseEligibilityInput extends LeaseMatchContext {
  scope: LeaseEligibilityScope
  method: string
  pathAndQuery: string
  routePattern?: string | null
}

export type LeaseEligibilityCode =
  | 'readonly_environment'
  | 'non_overridable_structural'
  | 'structural_mutation'
  | 'method_not_allowed'
  | 'high_risk_path'
  | 'high_risk_floor'
  | 'worker_glob'
  | 'invalid_prefix_pattern'
  | 'graphql_mutation'
  | 'jsonrpc_mutation'
  | 'body_destructive_mutation'

export interface LeaseEligibilityResult {
  eligible: boolean
  code?: LeaseEligibilityCode
  reason?: string
}

function leaseHeaderLookup(headers: Record<string, string> | undefined, name: string): string {
  if (!headers) return ''
  const lower = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v
  }
  return ''
}

function detectLeaseMultipartKind(input: {
  headers?: Record<string, string>
  hasMultipart?: boolean
  body?: string | null
}): 'none' | 'multipart' | 'malformed_multipart' {
  const contentType = leaseHeaderLookup(input.headers, 'content-type').trim()
  const declared = /^multipart\//i.test(contentType)
  const head = (input.body ?? '').slice(0, LEASE_BODY_SCAN_CHARS)
  const boundaryBody =
    /(?:^|\r?\n)--[-A-Za-z0-9'()+_,./:=?]{1,70}\r?\n/i.test(head) ||
    /content-disposition:\s*form-data/i.test(head)
  if (!input.hasMultipart && !declared && !boundaryBody) return 'none'
  if (declared && !/\bboundary\s*=\s*\S+/i.test(contentType)) return 'malformed_multipart'
  return 'multipart'
}

function isGraphqlPathForLease(pathAndQuery: string): boolean {
  const pathname = (pathAndQuery.split('?')[0] ?? pathAndQuery).split('#')[0] ?? ''
  const segments = pathname.split('/').filter(Boolean)
  return segments.length > 0 && segments[segments.length - 1]!.toLowerCase() === 'graphql'
}

function isGraphqlMutationBodyForLease(
  pathAndQuery: string,
  body: string | null | undefined,
  headers?: Record<string, string>,
  options?: { confirmedEndpoints?: readonly string[]; origin?: string; method?: string },
): boolean {
  const trimmed = (body ?? '').trim()
  const contentType = leaseHeaderLookup(headers, 'content-type').toLowerCase()
  if (isGraphqlPathForLease(pathAndQuery)) {
    return !isVerifiedReadOnlyGraphqlQuery(pathAndQuery, body ?? null, headers, options)
  }
  if (!trimmed || trimmed.length > LEASE_BODY_SCAN_CHARS) return false
  if (contentType.includes('application/graphql')) {
    return !isVerifiedReadOnlyGraphqlQuery(pathAndQuery, body ?? null, headers, options)
  }
  if (trimmed[0] === '{' || trimmed[0] === '[') {
    if (!/"query"\s*:|"operations"\s*:|\\u0071/i.test(trimmed)) return false
    try {
      const parsed = trimmed[0] === '{' ? parseStrictJsonObject(trimmed) : JSON.parse(trimmed)
      if (!parsed) return true
      const items = Array.isArray(parsed) ? parsed : [parsed]
      for (const item of items) {
        if (!item || typeof item !== 'object' || Array.isArray(item)) continue
        const rec = item as Record<string, unknown>
        if (typeof rec.query === 'string') {
          const q = rec.query.trim()
          if (/^\s*(?:mutation|subscription)\b/i.test(q) || /\b(?:mutation|subscription)\s*(?:[A-Za-z_]\w*)?\s*[({]/i.test(q)) {
            return true
          }
        }
      }
    } catch {
      return /"query"\s*:/i.test(trimmed)
    }
  }
  return false
}

function classifyJsonRpcForLease(
  body: string | null | undefined,
  headers?: Record<string, string>,
): 'none' | 'read' | 'mutation' | 'destructive' | 'malformed' {
  const trimmed = (body ?? '').trim()
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[') || trimmed.length > LEASE_BODY_SCAN_CHARS) return 'none'
  const contentType = leaseHeaderLookup(headers, 'content-type').toLowerCase()
  if (contentType && !contentType.includes('json')) return 'none'
  if (!/"jsonrpc"|"\\u006a/i.test(trimmed)) return 'none'
  let parsed: unknown
  try {
    parsed = trimmed[0] === '{' ? parseStrictJsonObject(trimmed) : JSON.parse(trimmed)
    if (parsed === undefined) return 'malformed'
  } catch {
    return 'malformed'
  }
  const items = Array.isArray(parsed) ? parsed : [parsed]
  if (items.length === 0) return 'none'
  if (!items.some(item => Boolean(item && typeof item === 'object' && !Array.isArray(item) && 'jsonrpc' in (item as Record<string, unknown>)))) {
    return 'none'
  }
  let hasMutation = false
  for (const item of items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return 'malformed'
    const rec = item as Record<string, unknown>
    if (rec.jsonrpc !== '2.0' || typeof rec.method !== 'string' || !rec.method.trim()) return 'malformed'
    const rpcMethod = rec.method.trim()
    if (LEASE_JSONRPC_DESTRUCTIVE_METHOD_RE.test(rpcMethod)) return 'destructive'
    if (!LEASE_JSONRPC_READ_METHOD_RE.test(rpcMethod)) hasMutation = true
  }
  return hasMutation ? 'mutation' : 'read'
}

function splitIdentifierTokens(value: string): string[] {
  return value.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
}

function inspectJsonForDestructiveMutation(value: unknown, depth = 0, budget = { steps: 0 }): boolean {
  if (depth > 16 || budget.steps > 512 || value === null || value === undefined) return false
  budget.steps += 1
  if (Array.isArray(value)) {
    for (const item of value) {
      if (inspectJsonForDestructiveMutation(item, depth + 1, budget)) return true
    }
    return false
  }
  if (typeof value === 'object') {
    for (const [rawKey, rawVal] of Object.entries(value as Record<string, unknown>)) {
      const keyNorm = rawKey.trim().toLowerCase()
      if (LEASE_HIGH_RISK_BODY_KEYS.has(keyNorm)) return true
      if (LEASE_DESTRUCTIVE_BODY_ACTION_KEYS.has(keyNorm) && typeof rawVal === 'string') {
        const tokens = splitIdentifierTokens(rawVal)
        if (tokens.some(t => LEASE_DESTRUCTIVE_ACTION_TOKENS.has(t))) return true
      }
      if (inspectJsonForDestructiveMutation(rawVal, depth + 1, budget)) return true
    }
  }
  return false
}

function hasDestructiveBodyMutationForLease(
  body: string | null | undefined,
  headers?: Record<string, string>,
): boolean {
  const trimmed = (body ?? '').trim()
  if (!trimmed || trimmed.length > LEASE_BODY_SCAN_CHARS) return false
  const contentType = leaseHeaderLookup(headers, 'content-type').toLowerCase()
  if (trimmed[0] === '{' || trimmed[0] === '[') {
    try {
      const parsed = trimmed[0] === '{' ? parseStrictJsonObject(trimmed) : JSON.parse(trimmed)
      if (parsed && inspectJsonForDestructiveMutation(parsed)) return true
    } catch {
      // Fall through to form/key-value scan only when non-JSON.
    }
    return false
  }
  if (contentType.includes('application/x-www-form-urlencoded') || trimmed.includes('=')) {
    let params: URLSearchParams
    try {
      params = new URLSearchParams(trimmed)
    } catch {
      return false
    }
    for (const [rawKey, rawVal] of params.entries()) {
      const keyNorm = rawKey.trim().toLowerCase()
      if (LEASE_HIGH_RISK_BODY_KEYS.has(keyNorm)) return true
      if (LEASE_DESTRUCTIVE_BODY_ACTION_KEYS.has(keyNorm)) {
        if (splitIdentifierTokens(rawVal).some(t => LEASE_DESTRUCTIVE_ACTION_TOKENS.has(t))) return true
      }
    }
  }
  return false
}

/**
 * Single authoritative lease-eligibility predicate (R4-H-1).
 *
 * Evaluates whether a request is eligible for durable approval lease / pattern authorization
 * under the requested scope (`'route'`, `'prefix'`, `'host_nondestructive'`, or `'any'` for
 * broker admission pre-check before delegating to `grant.approvalLeases`):
 *   1. NEVER overrides `prod_readonly` (`readonly_environment`) under any scope.
 *   2. NEVER allows non-overridable structural risks (RCE proof, race burst, method-override
 *      carriers, compressed bodies, >64 KiB bodies, unscannable bodies, malformed multipart).
 *   3. Refuses `DELETE`, structural mutations, GraphQL mutations/unverified probes, and
 *      destructive/malformed JSON-RPC payloads (with explicit Stage 1B exact-route opt-in).
 *   4. On `'prefix'`, `'host_nondestructive'`, and `'any'` (broker pre-check): enforces
 *      `isHighRiskOrExternalMutationPath`, `hostFloor !== 'high'`, `POST|PUT|PATCH` only,
 *      no worker globs, >= 2 fixed prefix segments (for `'prefix'`), no JSON-RPC mutations,
 *      and no body-level destructive/privilege mutations.
 */
export function evaluateLeaseEligibility(input: LeaseEligibilityInput): LeaseEligibilityResult {
  const method = (input.method || '').trim().toUpperCase()
  const pathAndQuery = input.pathAndQuery || '/'

  // 1. NEVER allow any approval lease to override `prod_readonly` (`readonly_environment`).
  if (input.environmentMode === 'prod_readonly') {
    return {
      eligible: false,
      code: 'readonly_environment',
      reason: 'Read-only environments (prod_readonly) never permit approval lease overrides.',
    }
  }

  // 2. Universal non-overridable structural invariants (apply across ALL scopes).
  if (input.isRceProof) {
    return { eligible: false, code: 'non_overridable_structural', reason: 'RCE proofs are never eligible for approval leases.' }
  }
  if (input.isRaceBurst) {
    return { eligible: false, code: 'non_overridable_structural', reason: 'Concurrent race bursts are never eligible for approval leases.' }
  }
  const override = detectMethodOverride({
    method: method || 'POST',
    pathAndQuery,
    headers: input.headers,
    body: input.body ?? null,
  })
  const effectiveMethod = (input.effectiveMethod ?? override.effectiveMethod).trim().toUpperCase()
  const contentEncoding = leaseHeaderLookup(input.headers, 'content-encoding').trim()
  const hasCompressed = Boolean(input.hasCompressedBody) || (contentEncoding !== '' && !/^identity$/i.test(contentEncoding))
  const hasOverCap = Boolean(input.hasOverCapBody) || override.bodyExceedsScanWindow || (input.body?.length ?? 0) > LEASE_BODY_SCAN_CHARS
  const scanIncomplete = Boolean(input.overrideScanIncomplete) || override.scanIncomplete
  const hasOverride = Boolean(input.hasMethodOverride) || override.hasOverride
  const hasOverrideRisk = Boolean(input.hasOverrideRisk) || hasOverride || hasOverCap || scanIncomplete || override.hasOverrideRisk || hasCompressed
  const multipartKind = input.multipartKind ?? detectLeaseMultipartKind({
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    body: input.body ?? null,
  })
  if (hasCompressed || hasOverCap || scanIncomplete || hasOverride || hasOverrideRisk || multipartKind === 'malformed_multipart') {
    return {
      eligible: false,
      code: 'non_overridable_structural',
      reason: 'Method-override carriers, compressed/oversized/unscannable bodies, and malformed multipart uploads are never eligible for approval leases.',
    }
  }

  // 3. Structural mutations, GraphQL mutations, and destructive/malformed JSON-RPC.
  const explicitRouteStructural = input.scope === 'route' && input.allowExplicitRouteStructural === true
  const jsonRpc =
    input.mutationKind === 'jsonrpc_destructive' ? 'destructive'
    : input.mutationKind === 'jsonrpc_malformed' ? 'malformed'
    : input.mutationKind === 'jsonrpc_mutation' ? 'mutation'
    : input.mutationKind === 'jsonrpc_read_method' ? 'read'
    : classifyJsonRpcForLease(input.body ?? null, input.headers)

  const graphqlMutation =
    input.mutationKind === 'graphql_mutation_or_unverified' ||
    isGraphqlMutationBodyForLease(pathAndQuery, input.body ?? null, input.headers, {
      ...(input.confirmedGraphqlEndpoints !== undefined ? { confirmedEndpoints: input.confirmedGraphqlEndpoints } : {}),
      ...(input.origin ? { origin: input.origin } : {}),
      method: effectiveMethod,
    })

  if (!explicitRouteStructural) {
    if (
      input.isStructuralMutation === true ||
      method === 'DELETE' ||
      effectiveMethod === 'DELETE' ||
      multipartKind !== 'none' ||
      input.mutationKind === 'multipart_upload' ||
      input.mutationKind === 'compressed_mutation'
    ) {
      return {
        eligible: false,
        code: 'structural_mutation',
        reason: 'DELETE, multipart uploads, and structural mutations are ineligible for durable approval leases.',
      }
    }
    if (jsonRpc === 'destructive' || jsonRpc === 'malformed') {
      return {
        eligible: false,
        code: 'jsonrpc_mutation',
        reason: 'Destructive or malformed JSON-RPC payloads are ineligible for durable approval leases.',
      }
    }
    if (graphqlMutation) {
      return {
        eligible: false,
        code: 'graphql_mutation',
        reason: 'GraphQL mutations and unverified GraphQL requests are ineligible for durable approval leases.',
      }
    }
  }

  if (input.scope === 'route') {
    return { eligible: true }
  }

  // 4. Broad scopes (`prefix`, `host_nondestructive`) and broker admission pre-check (`any`).
  const clientScope: ApprovalLeaseScope = input.scope === 'any' ? 'host_nondestructive' : input.scope
  const clientCheck = evaluateClientApprovalLeaseEligibility({
    scope: clientScope,
    method: effectiveMethod,
    pathAndQuery,
    riskLevel: input.riskLevel,
    environmentMode: input.environmentMode,
    routePattern: input.scope === 'prefix' ? input.routePattern : undefined,
  })
  if (!clientCheck.eligible) {
    const code: LeaseEligibilityCode =
      !isNonDestructiveMutationMethod(effectiveMethod) ? 'method_not_allowed'
      : hasApprovalPathGlobMetacharacters(pathAndQuery) ? 'worker_glob'
      : input.riskLevel === 'high' ? 'high_risk_floor'
      : isHighRiskOrExternalMutationPath(pathAndQuery) ? 'high_risk_path'
      : 'invalid_prefix_pattern'
    return { eligible: false, code, reason: clientCheck.reason }
  }
  if (input.hostFloor === 'high') {
    return {
      eligible: false,
      code: 'high_risk_floor',
      reason: 'High-risk requests must be evaluated by the Safety Judge / human operator and cannot use a lease.',
    }
  }
  if (graphqlMutation) {
    return {
      eligible: false,
      code: 'graphql_mutation',
      reason: 'GraphQL mutations are ineligible for prefix and host leases.',
    }
  }
  if (jsonRpc === 'destructive' || jsonRpc === 'malformed' || jsonRpc === 'mutation') {
    return {
      eligible: false,
      code: 'jsonrpc_mutation',
      reason: 'JSON-RPC mutations and destructive methods are ineligible for prefix and host leases.',
    }
  }
  if (hasDestructiveBodyMutationForLease(input.body ?? null, input.headers)) {
    return {
      eligible: false,
      code: 'body_destructive_mutation',
      reason: 'Body-level destructive or privilege-changing payloads are ineligible for prefix and host leases.',
    }
  }

  return { eligible: true }
}

/**
 * Normalized segment view used for pattern matching. `wildcard` is true only for `*` and for
 * segments that are genuinely identifier-shaped; literals must match exactly (case-insensitively).
 * `**` is reserved for an explicit operator-approved prefix pattern and is only honoured as the
 * final segment with at least two fixed non-wildcard prefix segments (R4-H-1).
 */
interface ApprovalPathSegment {
  value: string
  wildcard: boolean
}

function parseApprovalPathSegments(
  pathAndQuery: string,
  source: ApprovalPathPatternSource,
): ApprovalPathSegment[] {
  const normalized = normalizeApprovalPathPattern(pathAndQuery, { source })
  if (!normalized) return []
  return normalized
    .split('/')
    .filter(Boolean)
    .map(segment => {
      if (segment === '**') return { value: '**', wildcard: false }
      if (segment === '*') return { value: '*', wildcard: true }
      return { value: segment, wildcard: false }
    })
}

/**
 * Parse a stored `ApprovedEndpointPattern.pathPattern` using its provenance `source` (defaulting
 * missing/legacy `source` to `'card_path'`, NEVER `'operator_explicit'`).
 *
 * - In `'card_path'` mode: `**` is NEVER honoured as a prefix glob (escaped to `%2a%2a`),
 *   template placeholders (`:id`, `{id}`) stay literal, and already-normalized single-segment
 *   ID wildcards (`*`, emitted when normalizing `/api/orders/123` -> `/api/orders/*`) remain
 *   ID-only wildcards (matching concrete ID segments only, never sibling verbs or literal `*`).
 * - In `'operator_explicit'` mode: preserves `*`, `:id`/`{id}`/`[id]` -> `*`, and trailing `**`.
 */
function parseStoredPatternSegments(
  pathPattern: string,
  source: ApprovalPathPatternSource,
): ApprovalPathSegment[] {
  if (source === 'operator_explicit') {
    return parseApprovalPathSegments(pathPattern, 'operator_explicit')
  }
  const canonical = canonicalPathAndQuery(pathPattern)
  if (canonical === null) return []
  let pathname = canonical.split('?', 1)[0]!
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1)
  }
  return pathname
    .split('/')
    .filter(Boolean)
    .map(seg => {
      if (seg === '**') return { value: '%2a%2a', wildcard: false }
      if (seg === '*') return { value: '*', wildcard: true }
      if (isConcreteIdSegment(seg)) return { value: '*', wildcard: true }
      return { value: seg.toLowerCase(), wildcard: false }
    })
}

export function matchesApprovedEndpointPattern(
  target: { origin: string; method: string; pathAndQuery: string },
  patterns: readonly (ApprovedEndpointPattern & { source?: ApprovalPathPatternSource })[] | undefined,
  matchContext?: LeaseMatchContext,
): ApprovedEndpointPattern | undefined {
  if (!patterns?.length) return undefined
  const targetOrigin = normalizeOriginKey(target.origin)
  const targetMethod = target.method.toUpperCase()
  const targetNormalized = normalizeApprovalPathPattern(target.pathAndQuery, { source: 'card_path' })
  if (!targetNormalized) return undefined
  const targetSegs = parseApprovalPathSegments(target.pathAndQuery, 'card_path')

  for (const pattern of patterns) {
    if (normalizeOriginKey(pattern.origin) !== targetOrigin) continue
    if (pattern.method.toUpperCase() !== targetMethod) continue
    // R4-H-1: Missing/legacy `source` defaults to `'card_path'` — NEVER `'operator_explicit'`.
    const patternSource: ApprovalPathPatternSource = pattern.source ?? 'card_path'
    const patSegs = parseStoredPatternSegments(pattern.pathPattern, patternSource)
    if (patSegs.length === 0) continue

    const prefixWildcard = patternSource === 'operator_explicit' && patSegs[patSegs.length - 1]!.value === '**'
    // `**` is an explicit operator-approved prefix pattern. It is only valid as the last segment,
    // only when explicitly operator-authored (`source: 'operator_explicit'`), and must carry at
    // least TWO fixed non-wildcard prefix segments (`fixedLength >= 2`).
    if (patSegs.some((seg, i) => seg.value === '**' && i !== patSegs.length - 1)) continue
    const fixedLength = prefixWildcard ? patSegs.length - 1 : patSegs.length
    if (prefixWildcard) {
      if (fixedLength < 2) continue
      if (patSegs.slice(0, fixedLength).some(seg => seg.wildcard)) continue
    }
    if (prefixWildcard ? targetSegs.length < fixedLength : targetSegs.length !== fixedLength) continue

    let matched = true
    for (let i = 0; i < fixedLength; i += 1) {
      const pat = patSegs[i]!
      const seg = targetSegs[i]!
      if (pat.wildcard) {
        // Wildcards (explicit `*`, `:id`, `{id}`, or an ID-like literal normalized to `*`) only
        // cover genuinely identifier-shaped targets. They never cover a sibling verb.
        if (!seg.wildcard) {
          matched = false
          break
        }
      } else if (pat.value !== seg.value) {
        matched = false
        break
      }
    }
    if (!matched) continue

    // R4-H-1: Evaluate the single authoritative lease-eligibility predicate at match time on
    // prefix patterns so high-risk paths, DELETE, GraphQL/JSON-RPC, body-destructive mutations,
    // and prod_readonly are refused even for direct callers of matchesApprovedEndpointPattern.
    if (prefixWildcard) {
      const elig = evaluateLeaseEligibility({
        ...matchContext,
        scope: 'prefix',
        origin: target.origin,
        method: targetMethod,
        pathAndQuery: target.pathAndQuery,
        routePattern: pattern.pathPattern,
      })
      if (!elig.eligible) continue
    }
    return pattern
  }
  return undefined
}
