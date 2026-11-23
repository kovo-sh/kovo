import { createHash } from 'node:crypto'
import { z } from 'zod'
import type { ApprovalPolicy, ApprovedEndpointPattern } from '../domain.ts'
import { resolveProfilePoolForRole } from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { providerPool } from './provider.ts'
import type { UsageCallback } from './provider.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

export type { ApprovalPolicy, ApprovedEndpointPattern }
export type ApprovalPolicyMode = ApprovalPolicy
export type ApprovalDecisionKind = 'approve' | 'escalate_human' | 'deny'
export type ApprovalDecidedBy =
  | 'auto-review:rule'
  | 'auto-review:judge'
  | 'auto-review:local-lab'
  | 'auto-yolo'
  | 'operator'
export type ApprovalRiskLevel = 'low' | 'medium' | 'high'

export type SafetyJudgeLlmCall = (prompt: {
  systemPrompt: string
  userPrompt: string
}) => Promise<string>

export interface Tier3ApprovalInput {
  policy: ApprovalPolicyMode
  origin: string
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  rationale?: string
  bodyPreview?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  isRceProof?: boolean
  isRaceBurst?: boolean
  hasCompressedBody?: boolean
  environment?: 'public' | 'local-lab'
  approvedPatterns?: readonly ApprovedEndpointPattern[]
  llmCall?: SafetyJudgeLlmCall
  profiles?: readonly ResolvedModelProfile[]
  signal?: AbortSignal
  secrets?: readonly NamedSecret[]
  onUsage?: UsageCallback
  offline?: boolean
}

export interface Tier3ApprovalEvaluation {
  decision: ApprovalDecisionKind
  decidedBy: ApprovalDecidedBy
  riskLevel: ApprovalRiskLevel
  reason: string
  usedLlm: boolean
  stage:
    | 'strict'
    | 'yolo'
    | 'approved_pattern'
    | 'local_lab'
    | 'hard_escalation'
    | 'benign_fast_path'
    | 'safety_judge'
    | 'fail_safe'
}

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MONGO_ID_SEGMENT = /^[0-9a-f]{24}$/i
const NUMERIC_SEGMENT = /^\d+$/
const LONG_HEX_SEGMENT = /^[0-9a-f]{16,}$/i
const PREFIXED_ID_SEGMENT = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
const OPAQUE_TOKEN_SEGMENT = /^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}$/
const PLACEHOLDER_SEGMENT = /^(?::[A-Za-z0-9_]+|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\])$/

/**
 * True only for genuinely identifier-shaped path segments (numeric, UUID, Mongo id, long hex,
 * prefixed id, or a high-entropy opaque token). A wildcard in an approved endpoint pattern must
 * never match a sibling verb or a literal path word: that is how an approval for
 * `POST /api/items/<id>` used to cover `POST /api/items/delete`.
 */
function isIdLikeSegment(segment: string): boolean {
  return (
    PLACEHOLDER_SEGMENT.test(segment) ||
    UUID_SEGMENT.test(segment) ||
    MONGO_ID_SEGMENT.test(segment) ||
    NUMERIC_SEGMENT.test(segment) ||
    LONG_HEX_SEGMENT.test(segment) ||
    PREFIXED_ID_SEGMENT.test(segment) ||
    OPAQUE_TOKEN_SEGMENT.test(segment)
  )
}

// Financial / destructive / irreversible state mutations — always escalate regardless of auth
const ALWAYS_HIGH_RISK_PATTERN =
  /(?:^|[^a-z])(billing|stripe|cancel|refund|charge|invoice|void|payout|subscription|trial|delete|destroy|remove|drop|transfer|webhook)(?:$|[^a-z])/i

// Privilege / credential / access-control mutations — escalate conservatively
const AUTH_ADMIN_HIGH_RISK_PATTERN =
  /(?:^|[^a-z])(admin|role|permission|password|reset|revoke)(?:$|[^a-z])/i

// Benign unauthenticated sign-in / auth-check / inference / read-only endpoints
const BENIGN_UNAUTH_ENDPOINT_PATTERN =
  /(?:^|\/)(?:v1\/client\/sign_ins|sign_ins|sign-in|signin|login|auth\/login|auth\/sign-in|auth\/session|auth\/token|oauth\/token|v1\/chat\/completions|v1\/completions|v1\/messages|v1\/responses|api\/chat|api\/completions)(?:\/|$|\?)/i

// Read-only GraphQL or search/filter POST endpoints
const GRAPHQL_PATH_PATTERN = /(?:^|\/)graphql(?:\/|$|\?)/i
const READONLY_SEARCH_PATH_PATTERN =
  /(?:^|\/)(?:search|query|filter|lookup|introspect|validate|check|health|ping)(?:\/|$|\?)/i

const MUTATION_BODY_HINT =
  /(?:^|[^a-z])(mutation|delete|destroy|remove|drop|update|insert|create|write|transfer|refund|charge|cancel)(?:$|[^a-z])/i

// Bounded keyword scan: the full request body is inspected up to this cap instead of only the
// first few KiB, so a destructive/privileged keyword placed past a short prefix is still caught.
export const MAX_KEYWORD_SCAN_CHARS = 64 * 1024

const safetyJudgeResponseSchema = z.object({
  decision: z.enum(['approve', 'escalate_human', 'deny']),
  riskLevel: z.enum(['low', 'medium', 'high']).default('medium'),
  reason: z.string().trim().min(1).max(400),
})

export function normalizeApprovalPathPattern(pathAndQuery: string): string {
  let pathname = (pathAndQuery || '/').trim()
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(pathname)) {
    try {
      pathname = new URL(pathname).pathname || '/'
    } catch {
      // Keep raw string
    }
  }
  const qIdx = pathname.indexOf('?')
  if (qIdx >= 0) pathname = pathname.slice(0, qIdx)
  const hIdx = pathname.indexOf('#')
  if (hIdx >= 0) pathname = pathname.slice(0, hIdx)
  if (!pathname.startsWith('/')) pathname = '/' + pathname
  pathname = pathname.replace(/\/{2,}/g, '/')
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1)
  }

  const segments = pathname.split('/').map((seg, idx) => {
    if (idx === 0 && seg === '') return ''
    if (!seg) return ''
    if (seg === '*' || seg === '**') return seg
    if (isIdLikeSegment(seg)) return '*'
    return seg.toLowerCase()
  })

  return segments.join('/') || '/'
}

/**
 * Normalized segment view used for pattern matching. `wildcard` is true only for `*` and for
 * segments that are genuinely identifier-shaped; literals must match exactly (case-insensitively).
 * `**` is reserved for an explicit operator-approved prefix pattern and is only honoured as the
 * final segment.
 */
interface ApprovalPathSegment {
  value: string
  wildcard: boolean
}

function parseApprovalPathSegments(pathAndQuery: string): ApprovalPathSegment[] {
  const normalized = normalizeApprovalPathPattern(pathAndQuery)
  return normalized
    .split('/')
    .filter(Boolean)
    .map(segment => {
      if (segment === '**') return { value: '**', wildcard: false }
      if (segment === '*') return { value: '*', wildcard: true }
      return { value: segment, wildcard: false }
    })
}

function normalizeOriginKey(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase().replace(/\/+$/, '')
  }
}

function parseIpv4Host(host: string): [number, number, number, number] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (!match) return null
  const octets = match.slice(1).map(Number) as [number, number, number, number]
  if (octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null
  return octets
}

/**
 * Zero-trust origin binding for local-lab auto-approval (invariant: a project labeled
 * `local-lab` must still never auto-approve probes against an external hostname).
 *
 * Accepted: loopback (127.0.0.0/8, localhost, ::1), RFC1918 lab/container subnets
 * (10/8, 172.16/12, 192.168/16), and single-label Docker/LabRunner service aliases
 * such as `app` or `guardian-lab-web-1a2b3c4d5e`.
 *
 * Rejected: public hostnames (`EVIL.example.com`), public IPs, link-local/metadata
 * addresses (169.254.0.0/16, fe80::/10), unspecified/other special-use ranges.
 */
export function isLocalLabAutoApprovalOrigin(origin: string): boolean {
  let url: URL
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(origin) ? origin : `http://${origin}`)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  if (url.username || url.password) return false
  const host = url.hostname.toLowerCase()
  if (!host) return false
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true

  const v4 = parseIpv4Host(host)
  if (v4) {
    const [a, b] = v4
    if (a === 127) return true
    if (a === 10) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    // 169.254.0.0/16 is link-local (cloud metadata); never an authorized lab target.
    return false
  }

  // IPv6 lab containers would be ULA/link-local; only the explicit loopback form is allowed above.
  if (host.includes(':')) return false

  // Single-label hostname: Docker network alias / LabRunner container name. These are only
  // resolvable on the isolated lab network, never a public FQDN.
  return !host.includes('.') && /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/.test(host)
}

export function matchesApprovedEndpointPattern(
  target: { origin: string; method: string; pathAndQuery: string },
  patterns: readonly ApprovedEndpointPattern[] | undefined,
): ApprovedEndpointPattern | undefined {
  if (!patterns?.length) return undefined
  const targetOrigin = normalizeOriginKey(target.origin)
  const targetMethod = target.method.toUpperCase()
  const targetSegs = parseApprovalPathSegments(target.pathAndQuery)

  for (const pattern of patterns) {
    if (normalizeOriginKey(pattern.origin) !== targetOrigin) continue
    if (pattern.method.toUpperCase() !== targetMethod) continue
    const patSegs = parseApprovalPathSegments(pattern.pathPattern)
    if (patSegs.length === 0) continue

    const prefixWildcard = patSegs[patSegs.length - 1]!.value === '**'
    // `**` is an explicit operator-approved prefix pattern. It is only valid as the last segment
    // and only when the operator actually wrote it; a trailing `*` never matches arbitrary depth.
    if (patSegs.some((seg, i) => seg.value === '**' && i !== patSegs.length - 1)) continue
    const fixedLength = prefixWildcard ? patSegs.length - 1 : patSegs.length
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
    if (matched) return pattern
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Exact-fingerprint, single-use Tier-3 approvals
//
// Tier-3 state changes are only auto-authorized for the exact request the operator/judge saw:
// origin, method, exact path + query, persona, body hash, multipart/race/rce flags, and scope
// revision. Automatic decisions are never reused for a different path or a later identical probe:
// the ledger consumes a grant on first use. Segment-prefix matching remains available only for
// explicit operator-approved endpoint patterns (matchesApprovedEndpointPattern).
// ---------------------------------------------------------------------------

export interface StateChangeApprovalContext {
  /** Approved persona handle (null/undefined for unauthenticated requests). */
  personaHandle?: string | null
  /** Raw request body when the caller has it; used to derive the body hash if bodyHash is absent. */
  body?: string | null
  /** SHA-256 body/parts digest as computed by computeStateChangeBodyHash. */
  bodyHash?: string | null
  hasMultipart?: boolean
  isRaceBurst?: boolean
  isRceProof?: boolean
  /** True when the caller declared a non-identity Content-Encoding (gzip/br/deflate/...). */
  hasCompressedBody?: boolean
}

export interface StateChangeFingerprintInput extends StateChangeApprovalContext {
  runId?: string
  origin: string
  method: string
  pathAndQuery: string
  scopeRevision?: number
}

export interface MultipartBodyPart {
  name: string
  filename?: string
  contentType?: string
  content: string
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/**
 * Stable digest of the bytes a Tier-3 state change will send. Multipart requests are hashed from
 * their parts (the wire boundary is random and must not change the fingerprint). Returns null when
 * the request carries no body.
 */
export function computeStateChangeBodyHash(
  body?: string | null,
  multipartParts?: readonly MultipartBodyPart[] | null,
): string | null {
  if (Array.isArray(multipartParts) && multipartParts.length > 0) {
    const canonical = multipartParts.map(part => [
      part.name,
      part.filename ?? '',
      part.contentType ?? '',
      part.content,
    ])
    return `multipart:${sha256Hex(JSON.stringify(canonical))}`
  }
  if (body === undefined || body === null) return null
  return `body:${sha256Hex(String(body))}`
}

export function buildStateChangeFingerprint(input: StateChangeFingerprintInput): string {
  const bodyHash = input.bodyHash ?? computeStateChangeBodyHash(input.body ?? null)
  return JSON.stringify([
    'state-change-v1',
    input.runId ?? '',
    normalizeOriginKey(input.origin),
    input.method.toUpperCase(),
    input.pathAndQuery,
    input.personaHandle ?? '',
    bodyHash ?? '',
    input.scopeRevision ?? null,
    Boolean(input.hasMultipart),
    Boolean(input.isRaceBurst),
    Boolean(input.isRceProof),
  ])
}

export interface StateChangeApprovalGrant {
  expiresAt: number
  approvalId?: string
}

/** Grants are valid only long enough for the broker retry that immediately follows the decision. */
export const STATE_CHANGE_APPROVAL_TTL_MS = 60_000

/** True when a Content-Type header declares multipart (malformed boundary included). */
export function hasDeclaredMultipartContentType(headers: Record<string, string> | undefined): boolean {
  return /^\s*multipart\//i.test(headerLookup(headers, 'content-type') ?? '')
}

/**
 * In-memory, per-Execution ledger of exact Tier-3 grants. A grant is consumed by the first matching
 * state change and never authorizes a second request. Grants are deliberately not persisted: after
 * a restart an unspent approval fails closed and re-escalates.
 */
export class StateChangeApprovalLedger {
  private readonly grants = new Map<string, StateChangeApprovalGrant>()

  grant(input: StateChangeFingerprintInput, options: StateChangeApprovalGrant): string {
    const key = buildStateChangeFingerprint(input)
    this.grants.set(key, options)
    this.prune(options.expiresAt)
    return key
  }

  consume(input: StateChangeFingerprintInput, now = Date.now()): boolean {
    const key = buildStateChangeFingerprint(input)
    const grant = this.grants.get(key)
    if (!grant) return false
    this.grants.delete(key)
    return grant.expiresAt > now
  }

  get size(): number {
    return this.grants.size
  }

  clear(): void {
    this.grants.clear()
  }

  private prune(now: number): void {
    if (this.grants.size <= 2048) return
    for (const [key, grant] of this.grants) {
      if (grant.expiresAt <= now) this.grants.delete(key)
    }
    while (this.grants.size > 2048) {
      const oldest = this.grants.keys().next().value
      if (oldest === undefined) break
      this.grants.delete(oldest)
    }
  }
}

export type StateChangeAuthorizationVia = 'local_lab' | 'operator_pattern' | 'one_shot' | 'none'

/**
 * Single authorization decision for a Tier-3 state change. The broker fast path must call this
 * before skipping the safety judge: `true` means an exact fingerprint (or an explicit operator
 * pattern) already authorizes this precise request; anything else must go through
 * evaluateTier3Approval so hard escalations still apply.
 *
 * `localLabAutoApproval` must be derived by the caller from the project environment, the
 * capability tier, the approval policy, and `isLocalLabAutoApprovalOrigin(origin)`; this helper
 * never infers lab authorization from the origin alone.
 */
export function authorizeStateChange(input: {
  origin: string
  method: string
  pathAndQuery: string
  runId?: string
  scopeRevision?: number
  context?: StateChangeApprovalContext | null
  approvedPatterns?: readonly ApprovedEndpointPattern[]
  ledger?: StateChangeApprovalLedger
  localLabAutoApproval?: boolean
  now?: number
}): { approved: boolean; via: StateChangeAuthorizationVia; pattern?: ApprovedEndpointPattern } {
  if (input.localLabAutoApproval) {
    return { approved: true, via: 'local_lab' }
  }

  const context = input.context
  // Hard escalations are evaluated before patterns: multipart/upload, DELETE, RCE, race bursts,
  // compressed or over-cap bodies, and destructive/privileged keyword payloads can never be
  // pre-authorized by a broad operator pattern. Patterns additionally require the caller to supply
  // the exact request context — a context-less call (e.g. a replay retry that cannot describe the
  // request) fails closed instead of inheriting a pattern grant.
  const hardEscalation = !context || Boolean(detectHardEscalationReason({
    method: input.method.toUpperCase(),
    pathAndQuery: input.pathAndQuery,
    personaHandle: context?.personaHandle,
    bodyPreview: context?.body ?? null,
    hasMultipart: context?.hasMultipart,
    isRceProof: context?.isRceProof,
    hasCompressedBody: context?.hasCompressedBody,
  }))
  if (context && !context.isRaceBurst && !hardEscalation) {
    const pattern = matchesApprovedEndpointPattern(
      { origin: input.origin, method: input.method, pathAndQuery: input.pathAndQuery },
      input.approvedPatterns,
    )
    if (pattern) return { approved: true, via: 'operator_pattern', pattern }
  }

  if (context && input.ledger) {
    const consumed = input.ledger.consume({
      runId: input.runId,
      origin: input.origin,
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      scopeRevision: input.scopeRevision,
      personaHandle: context.personaHandle ?? null,
      bodyHash: context.bodyHash,
      body: context.body,
      hasMultipart: context.hasMultipart,
      isRaceBurst: context.isRaceBurst,
      isRceProof: context.isRceProof,
    }, input.now)
    if (consumed) return { approved: true, via: 'one_shot' }
  }

  return { approved: false, via: 'none' }
}

function extractJsonObject(raw: string): unknown {
  const trimmed = raw.trim()
  const fenced = /```(?:json)?\s*([\s\S]*?)\s*```/i.exec(trimmed)
  const candidate = fenced ? fenced[1].trim() : trimmed
  const start = candidate.indexOf('{')
  const end = candidate.lastIndexOf('}')
  if (start < 0 || end <= start) {
    throw new Error('Safety judge did not return a JSON object.')
  }
  return JSON.parse(candidate.slice(start, end + 1))
}

function headerLookup(headers: Record<string, string> | undefined, name: string): string | undefined {
  if (!headers) return undefined
  const lower = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v
  }
  return undefined
}

function isEmptyOrTrivialBody(body: string | null | undefined): boolean {
  if (!body) return true
  const trimmed = body.trim()
  return trimmed === '' || trimmed === '{}' || trimmed === '[]' || trimmed === 'null'
}

/**
 * Multipart classification derived from the actual request metadata, not only from a caller flag:
 * a declared `multipart/*` Content-Type is enough, a missing boundary is reported as malformed, and
 * a boundary-looking body is also treated as multipart. Callers must never fall back to the benign
 * fast paths for any of these.
 */
export type MultipartRequestKind = 'none' | 'multipart' | 'malformed_multipart'

export function detectMultipartRequest(input: {
  headers?: Record<string, string>
  hasMultipart?: boolean
  bodyPreview?: string | null
}): MultipartRequestKind {
  const contentType = (headerLookup(input.headers, 'content-type') ?? '').trim()
  const declared = /^multipart\//i.test(contentType)
  const boundaryLookingBody = /(?:^|\r?\n)--[-A-Za-z0-9'()+_,./:=?]{1,70}\r?\n/i.test(
    (input.bodyPreview ?? '').slice(0, MAX_KEYWORD_SCAN_CHARS),
  ) || /content-disposition:\s*form-data/i.test((input.bodyPreview ?? '').slice(0, MAX_KEYWORD_SCAN_CHARS))

  if (!input.hasMultipart && !declared && !boundaryLookingBody) return 'none'
  if (declared && !/\bboundary\s*=/i.test(contentType)) return 'malformed_multipart'
  if (declared && !/\bboundary\s*=\s*\S+/i.test(contentType)) return 'malformed_multipart'
  return 'multipart'
}

/**
 * Duplicate-aware top-level key scan. `JSON.parse` is last-wins, so a body with two `query` keys
 * (one mutation, one read-only document) could be classified as benign by Guardian while a target
 * parser executes the other value. Returns `undefined` for malformed JSON.
 */
function topLevelJsonKeys(raw: string): string[] | undefined {
  const text = raw.trim()
  if (!text.startsWith('{')) return undefined
  const keys: string[] = []
  let depth = 0
  let i = 0
  while (i < text.length) {
    const ch = text[i]!
    if (ch === '"') {
      let j = i + 1
      let value = ''
      let closed = false
      while (j < text.length) {
        const c = text[j]!
        if (c === '\\') {
          value += text.slice(j, j + 2)
          j += 2
          continue
        }
        if (c === '"') {
          closed = true
          j += 1
          break
        }
        value += c
        j += 1
      }
      if (!closed) return undefined
      if (depth === 1) {
        let k = j
        while (k < text.length && /\s/.test(text[k]!)) k += 1
        if (text[k] === ':') keys.push(value)
      }
      i = j
      continue
    }
    if (ch === '{' || ch === '[') depth += 1
    else if (ch === '}' || ch === ']') {
      depth -= 1
      if (depth < 0) return undefined
    }
    i += 1
  }
  if (depth !== 0) return undefined
  return keys
}

function hasDuplicateTopLevelJsonKeys(raw: string): boolean {
  const keys = topLevelJsonKeys(raw)
  if (!keys) return false
  return new Set(keys).size !== keys.length
}

function parseJsonObjectBody(body: string | null | undefined): Record<string, unknown> | undefined {
  const trimmed = (body ?? '').trim()
  if (!trimmed.startsWith('{') || !trimmed.endsWith('}')) return undefined
  if (hasDuplicateTopLevelJsonKeys(trimmed)) return undefined
  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined
    return parsed as Record<string, unknown>
  } catch {
    return undefined
  }
}

const GRAPHQL_ENVELOPE_KEYS = new Set(['query', 'operationname', 'variables', 'extensions'])

function isGraphqlReadOnlyQuery(pathAndQuery: string, body: string | null | undefined): boolean {
  const trimmed = (body ?? '').trim()
  if (!trimmed) return false

  // JSON GraphQL envelope: require an exact top-level `query` key (no substring/keyword guessing).
  const envelope = parseJsonObjectBody(trimmed)
  if (envelope) {
    const keys = Object.keys(envelope)
    const hasExactQueryKey = Object.prototype.hasOwnProperty.call(envelope, 'query')
    if (!hasExactQueryKey) return false
    if (!keys.every(key => GRAPHQL_ENVELOPE_KEYS.has(key.toLowerCase()))) return false
    const document = envelope.query
    if (typeof document !== 'string') return false
    if (/\b(?:mutation|subscription)\b/i.test(document)) return false
    return true
  }

  // Raw GraphQL document (application/graphql) only on a GraphQL endpoint; malformed JSON above
  // already returned false, so `{"notquery":1}` can never fall through to this branch.
  if (!trimmed.startsWith('{') && !/^\s*(?:query|fragment)\b/i.test(trimmed)) return false
  if (!GRAPHQL_PATH_PATTERN.test(pathAndQuery)) return false
  if (/\b(?:mutation|subscription)\b/i.test(trimmed)) return false
  return true
}

function isReadOnlySearchPost(pathAndQuery: string, body: string | null | undefined): boolean {
  if (!READONLY_SEARCH_PATH_PATTERN.test(pathAndQuery)) return false
  const trimmed = (body ?? '').trim().slice(0, MAX_KEYWORD_SCAN_CHARS)
  if (!trimmed) return true
  // JSON search bodies must be well-formed and duplicate-key-free, so the exact document the
  // judge classified is the document the target will parse.
  if (trimmed.startsWith('{') && !parseJsonObjectBody(trimmed)) return false
  if (hasDuplicateTopLevelJsonKeys(trimmed)) return false
  return !MUTATION_BODY_HINT.test(trimmed)
}

function detectHardEscalationReason(input: {
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyPreview?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  isRceProof?: boolean
  hasCompressedBody?: boolean
}): string | null {
  if (input.isRceProof) {
    return 'RCE proof-of-execution probe always requires explicit human approval.'
  }
  const contentEncoding = (headerLookup(input.headers, 'content-encoding') ?? '').trim()
  if (input.hasCompressedBody || (contentEncoding && !/^identity$/i.test(contentEncoding))) {
    return 'Compressed (Content-Encoding) request bodies cannot be classified and always require explicit human approval.'
  }
  if ((input.bodyPreview?.length ?? 0) > MAX_KEYWORD_SCAN_CHARS) {
    return `Request body exceeds the ${Math.round(MAX_KEYWORD_SCAN_CHARS / 1024)} KiB classification cap and always requires explicit human approval.`
  }
  const multipartKind = detectMultipartRequest(input)
  if (multipartKind === 'malformed_multipart') {
    return 'Malformed multipart upload (missing or invalid boundary) always requires explicit human approval.'
  }
  if (multipartKind === 'multipart') {
    return 'Multipart file upload probe always requires explicit human approval.'
  }
  if (input.method === 'DELETE') {
    return 'HTTP DELETE requests always require explicit human approval.'
  }

  const actionHeader =
    headerLookup(input.headers, 'next-action') ??
    headerLookup(input.headers, 'x-action') ??
    headerLookup(input.headers, 'soapaction') ??
    ''
  const pathText = input.pathAndQuery
  // Scan the full body (bounded) so keywords placed past a short prefix are still detected.
  const bodyText = (input.bodyPreview ?? '').slice(0, MAX_KEYWORD_SCAN_CHARS)

  const alwaysMatch =
    ALWAYS_HIGH_RISK_PATTERN.exec(pathText) ??
    ALWAYS_HIGH_RISK_PATTERN.exec(actionHeader) ??
    ALWAYS_HIGH_RISK_PATTERN.exec(bodyText)
  if (alwaysMatch) {
    return `High-risk state-mutation keyword "${alwaysMatch[1].toLowerCase()}" detected; escalating to human approval.`
  }

  const isAuthSignInPath = !input.personaHandle && BENIGN_UNAUTH_ENDPOINT_PATTERN.test(pathText)
  const authAdminPathMatch =
    AUTH_ADMIN_HIGH_RISK_PATTERN.exec(pathText) ??
    AUTH_ADMIN_HIGH_RISK_PATTERN.exec(actionHeader)
  if (authAdminPathMatch) {
    return `Sensitive auth/privilege path keyword "${authAdminPathMatch[1].toLowerCase()}" detected; escalating to human approval.`
  }

  const authAdminBodyMatch = AUTH_ADMIN_HIGH_RISK_PATTERN.exec(bodyText)
  if (authAdminBodyMatch) {
    const matchedWord = authAdminBodyMatch[1].toLowerCase()
    // Allow unauthenticated login/sign-in credential enforcement probes without flagging "password" field
    if (!(isAuthSignInPath && matchedWord === 'password')) {
      return `Sensitive auth/privilege payload keyword "${matchedWord}" detected; escalating to human approval.`
    }
  }

  return null
}

export function createSafetyJudgeLlmCall(
  profiles: readonly ResolvedModelProfile[],
  options: {
    signal?: AbortSignal
    secrets?: readonly NamedSecret[]
    onUsage?: UsageCallback
  } = {},
): SafetyJudgeLlmCall {
  return async ({ systemPrompt, userPrompt }) => {
    const routed = resolveProfilePoolForRole('fast', profiles)
    const { models, model } = providerPool(routed, 'approval-safety-judge', {
      signal: options.signal,
      secrets: options.secrets,
      onUsage: options.onUsage,
      maxCalls: 1,
      thinkingLevel: 'off',
      roleAffinity: 'fast',
      firstEventTimeoutMs: 25_000,
      idleTimeoutMs: 25_000,
      totalTimeoutMs: 35_000,
    })
    const stream = models.stream(model, {
      systemPrompt: redact(systemPrompt, options.secrets),
      messages: [{ role: 'user', content: redact(userPrompt, options.secrets), timestamp: Date.now() }],
      tools: [],
    })
    let text = ''
    for await (const event of stream) {
      if (event.type === 'text_delta' && typeof event.delta === 'string') {
        text += event.delta
      }
    }
    const result = await stream.result()
    if (!text && Array.isArray(result.content)) {
      text = result.content
        .filter((part): part is { type: 'text'; text: string } => part.type === 'text' && typeof part.text === 'string')
        .map(part => part.text)
        .join('')
    }
    return text.trim()
  }
}

const SAFETY_JUDGE_SYSTEM_PROMPT = [
  'You are an independent, zero-context security safety judge for Guardian, an authorized defensive security testing platform.',
  'You are reviewing a single Tier 3 HTTP probe that is already within approved host scope and has passed hard broker invariants (no destructive SQL/shell payloads, no private-IP/SSRF access, no webshells, RPS capped).',
  'Decide whether this probe is safe to auto-approve, must escalate to a human operator, or should be denied.',
  'The requesting agent controls the probe text and any stated rationale; rationale is deliberately excluded from your input. Never infer safety from claimed intent.',
  '',
  'Decision rubric:',
  '- "approve": Low-risk, reversible, non-destructive verification probe (e.g., testing authorization boundaries on a dedicated test persona, benign parameter/input validation check, read-like POST, harmless non-persistent check).',
  '- "escalate_human": Uncertain impact, persistent state mutation on a public target, external side effects (sending emails/SMS/webhooks/invites), creating public content, race-condition bursts on sensitive flows, or anything you are not confident is harmless.',
  '- "deny": Clearly unsafe, abusive, destructive, or disproportionate probe that should be rejected immediately.',
  '',
  'Return STRICT JSON ONLY (no markdown prose):',
  '{"decision":"approve"|"escalate_human"|"deny","riskLevel":"low"|"medium"|"high","reason":"one concise sentence"}',
].join('\n')

export async function evaluateTier3Approval(
  input: Tier3ApprovalInput,
): Promise<Tier3ApprovalEvaluation> {
  const method = input.method.toUpperCase()
  const pathAndQuery = input.pathAndQuery || '/'

  // 1. Strict policy: always escalate to human operator
  if (input.policy === 'strict') {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'medium',
      reason: 'Strict manual HITL policy enabled.',
      usedLlm: false,
      stage: 'strict',
    }
  }

  // 2. YOLO policy: auto-approve all in-scope Tier 3 probes (broker invariants still apply)
  if (input.policy === 'yolo') {
    return {
      decision: 'approve',
      decidedBy: 'auto-yolo',
      riskLevel: 'low',
      reason: 'YOLO autonomous mode (all hard broker invariants enforced).',
      usedLlm: false,
      stage: 'yolo',
    }
  }

  // 3. Auto-Review policy (Default — 2-Stage Hybrid Gate)

  // 3a. Authorized local-lab auto-approval — ONLY for environment === 'local-lab' AND a
  //     resolved loopback / lab-internal origin. The GUARDIAN_ALLOW_LOCAL_LAB flag alone can
  //     never relax approvals for public or unspecified environments, and an external hostname
  //     mislabeled as local-lab falls through to the public hard-escalation rules below.
  //     Hard broker invariants (destructive denylist, webshell filter, private-IP/metadata SSRF
  //     guards, RPS/budget caps) stay fully enforced; this gate only replaces the human approval.
  if (input.environment === 'local-lab' && isLocalLabAutoApprovalOrigin(input.origin)) {
    return {
      decision: 'approve',
      decidedBy: 'auto-review:local-lab',
      riskLevel: 'medium',
      reason: 'Authorized local-lab auto-approval for loopback/lab-internal origin (broker destructive-payload, webshell, SSRF metadata and RPS invariants still enforced).',
      usedLlm: false,
      stage: 'local_lab',
    }
  }

  // Stage 1A — Hard Escalation Patterns (ALWAYS escalate to human). These run BEFORE operator
  // pattern matching: a broad pattern can never pre-approve multipart/DELETE/RCE/upload/race
  // probes, compressed or over-cap bodies, or destructive/privileged payload keywords.
  const hardEscalationReason = detectHardEscalationReason({
    method,
    pathAndQuery,
    personaHandle: input.personaHandle,
    bodyPreview: input.bodyPreview,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    isRceProof: input.isRceProof,
    hasCompressedBody: input.hasCompressedBody,
  })
  if (hardEscalationReason) {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'high',
      reason: hardEscalationReason,
      usedLlm: false,
      stage: 'hard_escalation',
    }
  }

  // Stage 1B — Operator-approved endpoint pattern (only after hard escalations passed).
  const matchedPattern = !input.isRceProof && !input.isRaceBurst
    ? matchesApprovedEndpointPattern(
        { origin: input.origin, method, pathAndQuery },
        input.approvedPatterns,
      )
    : undefined
  if (matchedPattern) {
    return {
      decision: 'approve',
      decidedBy: 'auto-review:rule',
      riskLevel: 'low',
      reason: `Matched run-scoped approved endpoint pattern (${matchedPattern.method} ${matchedPattern.pathPattern}).`,
      usedLlm: false,
      stage: 'approved_pattern',
    }
  }

  // Stage 1C — Deterministic Benign Fast-Path (zero LLM cost)
  if (method === 'POST' && !input.isRaceBurst) {
    if (isGraphqlReadOnlyQuery(pathAndQuery, input.bodyPreview)) {
      return {
        decision: 'approve',
        decidedBy: 'auto-review:rule',
        riskLevel: 'low',
        reason: 'Auto-approved read-only GraphQL query/introspection probe.',
        usedLlm: false,
        stage: 'benign_fast_path',
      }
    }

    if (isReadOnlySearchPost(pathAndQuery, input.bodyPreview)) {
      return {
        decision: 'approve',
        decidedBy: 'auto-review:rule',
        riskLevel: 'low',
        reason: 'Auto-approved idempotent read-only search/filter POST probe.',
        usedLlm: false,
        stage: 'benign_fast_path',
      }
    }

    if (!input.personaHandle) {
      if (isEmptyOrTrivialBody(input.bodyPreview)) {
        return {
          decision: 'approve',
          decidedBy: 'auto-review:rule',
          riskLevel: 'low',
          reason: 'Auto-approved unauthenticated empty-body POST auth-enforcement probe.',
          usedLlm: false,
          stage: 'benign_fast_path',
        }
      }
      if (BENIGN_UNAUTH_ENDPOINT_PATTERN.test(pathAndQuery)) {
        return {
          decision: 'approve',
          decidedBy: 'auto-review:rule',
          riskLevel: 'low',
          reason: 'Auto-approved unauthenticated auth/inference boundary POST probe.',
          usedLlm: false,
          stage: 'benign_fast_path',
        }
      }
    }
  }

  // Stage 2 — Independent Zero-Context Safety-Judge LLM
  const isOffline = input.offline ?? (process.env.GUARDIAN_OFFLINE === '1' && !input.llmCall)
  if (isOffline) {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'medium',
      reason: 'Offline mode active; escalating grey-area Tier 3 probe to human operator.',
      usedLlm: false,
      stage: 'fail_safe',
    }
  }

  const llmCall =
    input.llmCall ??
    (input.profiles && input.profiles.length > 0
      ? createSafetyJudgeLlmCall(input.profiles, {
          signal: input.signal,
          secrets: input.secrets,
          onUsage: input.onUsage,
        })
      : undefined)

  if (!llmCall) {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'medium',
      reason: 'No model profile configured for Safety Judge; escalating to human operator.',
      usedLlm: false,
      stage: 'fail_safe',
    }
  }

  const secrets = input.secrets ?? []
  // The agent-controlled rationale is intentionally omitted: an untrusted claim of benign intent
  // must never be able to weaken the judge's independent decision.
  const userPrompt = JSON.stringify(
    {
      environment: input.environment ?? 'public',
      origin: input.origin,
      method,
      pathAndQuery: redact(pathAndQuery, secrets).slice(0, 500),
      personaHandle: input.personaHandle ?? null,
      isRaceBurst: Boolean(input.isRaceBurst),
      bodyPreview: redact((input.bodyPreview ?? '').slice(0, 1200), secrets),
    },
    null,
    2,
  )

  try {
    const raw = await llmCall({
      systemPrompt: SAFETY_JUDGE_SYSTEM_PROMPT,
      userPrompt,
    })
    const parsed = safetyJudgeResponseSchema.parse(extractJsonObject(raw))
    if (parsed.decision === 'approve') {
      return {
        decision: 'approve',
        decidedBy: 'auto-review:judge',
        riskLevel: parsed.riskLevel,
        reason: redact(parsed.reason, secrets),
        usedLlm: true,
        stage: 'safety_judge',
      }
    }
    if (parsed.decision === 'deny') {
      return {
        decision: 'deny',
        decidedBy: 'auto-review:judge',
        riskLevel: parsed.riskLevel,
        reason: redact(parsed.reason, secrets),
        usedLlm: true,
        stage: 'safety_judge',
      }
    }
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: parsed.riskLevel,
      reason: redact(parsed.reason, secrets),
      usedLlm: true,
      stage: 'safety_judge',
    }
  } catch {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'medium',
      reason: 'Safety Judge call failed or returned invalid JSON; failing safe to human approval.',
      usedLlm: true,
      stage: 'fail_safe',
    }
  }
}
