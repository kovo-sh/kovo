import { setTimeout as delay } from 'node:timers/promises'
import { createHash } from 'node:crypto'
import { z } from 'zod'
import { isHighRiskOrExternalMutationPath } from '../domain.ts'
import type { ApprovalPolicy, ApprovedEndpointPattern } from '../domain.ts'
import {
  computeApprovalHeadersDigest,
  evaluateLeaseEligibility,
  isPrefixApprovalPattern,
  matchesApprovedEndpointPattern,
  normalizeOriginKey,
} from './approval-pattern.ts'
import type { LeaseMatchContext } from './approval-pattern.ts'
import { resolveProfilePoolForRole } from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { classifyProviderFailure, providerPool } from './provider.ts'
import type { ProviderFailureKind, UsageCallback } from './provider.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import {
  detectMethodOverride,
  evaluateScopeRequest,
  isReadOnlyHttpMethod,
  isVerifiedReadOnlyGraphqlQuery,
  parseStrictJsonObject,
} from './scope-policy.ts'
import type { EnvironmentMode, ScopeHook } from './scope-policy.ts'

export type { ApprovalPolicy, ApprovedEndpointPattern }
export {
  computeApprovalHeadersDigest,
  matchesApprovedEndpointPattern,
  normalizeApprovalPathPattern,
} from './approval-pattern.ts'
export type ApprovalPolicyMode = ApprovalPolicy
export type ApprovalDecisionKind = 'approve' | 'escalate_human' | 'deny'
export type ApprovalDecidedBy =
  | 'auto-review:rule'
  | 'auto-review:judge'
  | 'auto-review:policy'
  | 'auto-review:local-lab'
  | 'auto-review:environment'
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
  /**
   * Host-derived minimum risk floor computed from request mutation classification
   * (`isStructuralMutation`, `jsonrpc_destructive`, method/body) and domain `HIGH_RISK` tokens.
   * Effective risk is `max(hostFloor, judgeRisk)`; Stage 2 auto_review NEVER auto-approves when
   * `hostFloor > 'low'`.
   */
  hostFloor?: ApprovalRiskLevel
  /** Optional mutation-classification hints passed from RequestAdmissionEngine. */
  isStructuralMutation?: boolean
  mutationKind?: string
  environment?: 'public' | 'local-lab'
  /**
   * v6 environment contract. When supplied, it replaces per-request keyword HITL as the primary
   * decision: `prod_readonly` refuses mutations outright (no popup), `staging_isolated` allows
   * run-tagged tenant mutations / setup-cleanup hooks and denies denylisted routes.
   * Omitted (or `ephemeral_lab`) keeps the legacy approval flow unchanged.
   */
  mode?: EnvironmentMode
  /** Explicit staging setup/cleanup hook context. */
  hook?: ScopeHook | null
  /** Run-scoped synthetic tenant tag (`kovo-qa-<runId>-`). */
  tenantTag?: string | null
  routeDenylist?: readonly string[]
  /** H-3: Host-confirmed GraphQL endpoints (exact match only when supplied). */
  confirmedGraphqlEndpoints?: readonly string[]
  approvedPatterns?: readonly ApprovedEndpointPattern[]
  llmCall?: SafetyJudgeLlmCall
  profiles?: readonly ResolvedModelProfile[]
  signal?: AbortSignal
  secrets?: readonly NamedSecret[]
  onUsage?: UsageCallback
  offline?: boolean
}

export type ApprovalFailSafeReason =
  | 'judge_offline'
  | 'judge_unconfigured'
  | 'judge_provider_rate_limited'
  | 'judge_provider_quota'
  | 'judge_provider_auth'
  | 'judge_provider_server'
  | 'judge_provider_stall'
  | 'judge_provider_stream_drop'
  | 'judge_provider_context_overflow'
  | 'judge_invalid_response'
  | 'judge_provider_unavailable'

export interface Tier3ApprovalEvaluation {
  decision: ApprovalDecisionKind
  decidedBy: ApprovalDecidedBy
  riskLevel: ApprovalRiskLevel
  reason: string
  /** Optional explicit policy explanation when Stage 2 auto_review normalizes a low/medium verdict. */
  policyNote?: string
  /** Raw decision returned by the Stage 2 Safety Judge before host policy normalization. */
  originalJudgeDecision?: ApprovalDecisionKind
  /** Raw riskLevel explicitly returned by the Stage 2 Safety Judge (`null` if omitted or invalid). */
  originalRiskLevel?: ApprovalRiskLevel | null
  /** Effective host-derived risk floor enforced during Stage 2 evaluation. */
  hostFloor?: ApprovalRiskLevel
  usedLlm: boolean
  stage:
    | 'strict'
    | 'yolo'
    | 'environment_contract'
    | 'approved_pattern'
    | 'local_lab'
    | 'hard_escalation'
    | 'benign_fast_path'
    | 'safety_judge'
    | 'fail_safe'
  /** Structured flag distinguishing Safety Judge outage/misconfiguration from normal risk escalation. */
  failSafe?: boolean
  /** Machine-readable fail-safe cause for UI badges, audit records, and reports. */
  failSafeReason?: ApprovalFailSafeReason
  /** Redacted diagnostic summary when the Safety Judge failed safe. */
  failSafeDetail?: string
  /** Number of Stage-2 Safety Judge LLM attempts executed (1 normal, 2 after bounded transient retry). */
  judgeAttempts?: number
}

// v6: keyword escalation ("billing", "delete", "admin", "password", …) is retired. The
// environment contract plus durable operator leases own the safety decision; English words in a
// path or body are not a security boundary and caused approval storms on benign staging routes.

// Benign unauthenticated sign-in / auth-check / inference / read-only endpoints
const BENIGN_UNAUTH_ENDPOINT_PATTERN =
  /(?:^|\/)(?:v1\/client\/sign_ins|sign_ins|sign-in|signin|login|auth\/login|auth\/sign-in|auth\/session|auth\/token|oauth\/token|v1\/chat\/completions|v1\/completions|v1\/messages|v1\/responses|api\/chat|api\/completions)(?:\/|$|\?)/i

// Read-only search/filter POST endpoints
const READONLY_SEARCH_PATH_PATTERN =
  /(?:^|\/)(?:search|query|filter|lookup|introspect|validate|check|health|ping)(?:\/|$|\?)/i

const MUTATION_BODY_HINT =
  /(?:^|[^a-z])(mutation|delete|destroy|remove|drop|update|insert|create|write|transfer|refund|charge|cancel)(?:$|[^a-z])/i

/**
 * Body inspection cap. Kept exported for callers/tests that pin the classification limit: a body
 * larger than this cannot be classified deterministically and is escalated structurally.
 */
export const MAX_KEYWORD_SCAN_CHARS = 64 * 1024

const RISK_LEVEL_RANK: Record<ApprovalRiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
}

function maxApprovalRiskLevel(a: ApprovalRiskLevel, b: ApprovalRiskLevel): ApprovalRiskLevel {
  return RISK_LEVEL_RANK[a] >= RISK_LEVEL_RANK[b] ? a : b
}

// Fail-closed Safety Judge response schema: NO `.default('medium')` on `riskLevel`.
// Missing or invalid `riskLevel` is parsed as `null` (`originalRiskLevel: null`) and escalated
// to effective `'high'` risk so an incomplete model reply can NEVER auto-approve.
const safetyJudgeResponseSchema = z.object({
  decision: z.enum(['approve', 'escalate_human', 'deny']),
  riskLevel: z.unknown().optional(),
  reason: z.string().trim().min(1).max(400),
})

function parseExplicitJudgeRiskLevel(raw: unknown): ApprovalRiskLevel | null {
  return raw === 'low' || raw === 'medium' || raw === 'high' ? raw : null
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
 * such as `app` or `kovo-lab-web-1a2b3c4d5e`.
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
  /** H-4: Caller headers included in canonical digest & structural checks. */
  headers?: Record<string, string>
  /** H-4: Pre-computed canonical headers digest (`computeApprovalHeadersDigest`). */
  headersDigest?: string | null
  hasMultipart?: boolean
  /** H-4: Explicit multipart classification (`none` | `multipart` | `malformed_multipart`). */
  multipartKind?: MultipartRequestKind
  isRaceBurst?: boolean
  isRceProof?: boolean
  /** True when the caller declared a non-identity Content-Encoding (gzip/br/deflate/...). */
  hasCompressedBody?: boolean
  /** R2-H-1: True when a method-override header or `_method` carrier was detected. */
  hasMethodOverride?: boolean
  /** R2-H-1: Effective HTTP verb after accounting for override carriers. */
  effectiveMethod?: string
  /** R2-01: Host-derived minimum risk floor computed from mutation classification + domain HIGH_RISK tokens. */
  hostFloor?: ApprovalRiskLevel
  /** Optional assignment ID binding a grant to a specific worker assignment (`H-4`). */
  assignmentId?: string
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

function hasCompressedContentEncoding(headers: Record<string, string> | undefined): boolean {
  const ce = (headerLookup(headers, 'content-encoding') ?? '').trim()
  return ce !== '' && !/^identity$/i.test(ce)
}

export function buildStateChangeFingerprint(input: StateChangeFingerprintInput): string {
  const bodyHash = input.bodyHash ?? computeStateChangeBodyHash(input.body ?? null)
  const headersDigest = input.headersDigest !== undefined
    ? (input.headersDigest ?? '')
    : (computeApprovalHeadersDigest(input.headers) ?? '')
  const multipartKind: MultipartRequestKind = input.multipartKind ?? detectMultipartRequest({
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    bodyPreview: input.body ?? null,
  })
  const hasCompressed = Boolean(input.hasCompressedBody) || hasCompressedContentEncoding(input.headers)
  const override = detectMethodOverride({
    method: input.method,
    pathAndQuery: input.pathAndQuery,
    headers: input.headers,
    body: input.body ?? null,
  })
  const hasOverride = Boolean(input.hasMethodOverride) || override.hasOverride
  return JSON.stringify([
    'state-change-v2',
    input.runId ?? '',
    normalizeOriginKey(input.origin),
    input.method.toUpperCase(),
    input.pathAndQuery,
    input.personaHandle ?? '',
    bodyHash ?? '',
    input.scopeRevision ?? null,
    Boolean(input.hasMultipart || multipartKind !== 'none'),
    Boolean(input.isRaceBurst),
    Boolean(input.isRceProof),
    headersDigest,
    multipartKind,
    hasCompressed,
    hasOverride,
    input.assignmentId ?? '',
  ])
}

export interface StateChangeApprovalGrant {
  expiresAt: number
  approvalId?: string
  /** Internal flag: true when the grant explicitly bound headers/headersDigest. */
  hasHeadersBinding?: boolean
  /** Internal flag: true when the grant explicitly bound assignmentId. */
  hasAssignmentBinding?: boolean
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
    const hasHeadersBinding = options.hasHeadersBinding ?? (input.headers !== undefined || input.headersDigest !== undefined)
    const hasAssignmentBinding = options.hasAssignmentBinding ?? Boolean(input.assignmentId)
    this.grants.set(key, { ...options, hasHeadersBinding, hasAssignmentBinding })
    this.prune(Date.now())
    return key
  }

  consume(input: StateChangeFingerprintInput, now = Date.now()): boolean {
    const key = buildStateChangeFingerprint(input)
    const exact = this.grants.get(key)
    if (exact) {
      this.grants.delete(key)
      return exact.expiresAt > now
    }
    // Compatibility bridge for legacy callers that granted without forwarding `headers` or
    // `assignmentId`: ONLY matches a grant that explicitly lacked those bindings, and NEVER when
    // the consuming request carries compressed bodies, method overrides, or malformed multipart.
    const hasInputHeaders = input.headers !== undefined || input.headersDigest !== undefined
    const hasInputAssignment = Boolean(input.assignmentId)
    if (hasInputHeaders || hasInputAssignment) {
      const multipartKind = input.multipartKind ?? detectMultipartRequest({
        headers: input.headers,
        hasMultipart: input.hasMultipart,
        bodyPreview: input.body ?? null,
      })
      const hasCompressed = Boolean(input.hasCompressedBody) || hasCompressedContentEncoding(input.headers)
      const override = detectMethodOverride({
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        headers: input.headers,
        body: input.body ?? null,
      })
      if (!hasCompressed && !override.hasOverride && !input.hasMethodOverride && multipartKind !== 'malformed_multipart') {
        const candidates: Array<{ key: string; dropHeaders: boolean; dropAssignment: boolean }> = []
        if (hasInputAssignment) {
          candidates.push({
            key: buildStateChangeFingerprint({ ...input, assignmentId: undefined }),
            dropHeaders: false,
            dropAssignment: true,
          })
        }
        if (hasInputHeaders) {
          candidates.push({
            key: buildStateChangeFingerprint({ ...input, headers: undefined, headersDigest: null }),
            dropHeaders: true,
            dropAssignment: false,
          })
        }
        if (hasInputHeaders && hasInputAssignment) {
          candidates.push({
            key: buildStateChangeFingerprint({ ...input, headers: undefined, headersDigest: null, assignmentId: undefined }),
            dropHeaders: true,
            dropAssignment: true,
          })
        }
        for (const cand of candidates) {
          const legacy = this.grants.get(cand.key)
          if (!legacy) continue
          if (cand.dropHeaders && legacy.hasHeadersBinding !== false) continue
          if (cand.dropAssignment && legacy.hasAssignmentBinding !== false) continue
          this.grants.delete(cand.key)
          return legacy.expiresAt > now
        }
      }
    }
    return false
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
  // Non-overridable structural invariants are ALWAYS evaluated before operator patterns:
  // RCE proof, compressed or over-cap bodies, malformed multipart uploads, race bursts, and
  // context-less calls can never be pre-authorized by a pattern. Once those pass, an explicit
  // operator pattern ("Approve similar") honors the operator's approval on that normalized route,
  // including DELETE and well-formed multipart routes they explicitly approved.
  const nonOverridable = !context || Boolean(detectNonOverridableEscalationReason({
    method: input.method,
    pathAndQuery: input.pathAndQuery,
    bodyPreview: context?.body ?? null,
    headers: context?.headers,
    hasMultipart: context?.hasMultipart,
    isRceProof: context?.isRceProof,
    isRaceBurst: context?.isRaceBurst,
    hasCompressedBody: context?.hasCompressedBody,
    hasMethodOverride: context?.hasMethodOverride,
  }))
  if (context && !context.isRaceBurst && !nonOverridable) {
    const hostFloor = context.hostFloor ?? computeHostApprovalRiskFloor({
      method: input.method,
      pathAndQuery: input.pathAndQuery,
      personaHandle: context.personaHandle ?? null,
      bodyPreview: context.body ?? null,
      headers: context.headers,
      hasMultipart: context.hasMultipart,
      isRceProof: context.isRceProof,
      isRaceBurst: context.isRaceBurst,
      hasCompressedBody: context.hasCompressedBody,
      hasMethodOverride: context.hasMethodOverride,
    })
    const matchContext: LeaseMatchContext = {
      origin: input.origin,
      body: context.body ?? null,
      headers: context.headers,
      hasMultipart: context.hasMultipart,
      multipartKind: context.multipartKind,
      isRceProof: context.isRceProof,
      isRaceBurst: context.isRaceBurst,
      hasCompressedBody: context.hasCompressedBody,
      hasMethodOverride: context.hasMethodOverride,
      effectiveMethod: context.effectiveMethod,
      hostFloor,
      allowExplicitRouteStructural: true,
    }
    const pattern = matchesApprovedEndpointPattern(
      { origin: input.origin, method: input.method, pathAndQuery: input.pathAndQuery },
      input.approvedPatterns,
      matchContext,
    )
    if (pattern) {
      const patternScope = isPrefixApprovalPattern(pattern.pathPattern) ? 'prefix' : 'route'
      const elig = evaluateLeaseEligibility({
        ...matchContext,
        scope: patternScope,
        method: input.method,
        pathAndQuery: input.pathAndQuery,
        routePattern: pattern.pathPattern,
      })
      if (elig.eligible) return { approved: true, via: 'operator_pattern', pattern }
    }
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
      headers: context.headers,
      headersDigest: context.headersDigest,
      hasMultipart: context.hasMultipart,
      multipartKind: context.multipartKind,
      hasCompressedBody: context.hasCompressedBody,
      hasMethodOverride: context.hasMethodOverride,
      isRaceBurst: context.isRaceBurst,
      isRceProof: context.isRceProof,
      assignmentId: context.assignmentId,
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
 * Strict RFC 8259 JSON object parser shared with `scope-policy.ts` (`H-3`): rejects duplicate
 * keys at any depth, escaped top-level keys, case-variant top-level duplicates, and malformed JSON.
 */
function parseJsonObjectBody(body: string | null | undefined): Record<string, unknown> | undefined {
  if (!body) return undefined
  return parseStrictJsonObject(body)
}

function collectDecodedJsonStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 16 || out.length > 512) return
  if (typeof value === 'string') {
    out.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectDecodedJsonStrings(item, out, depth + 1)
    return
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out.push(k)
      collectDecodedJsonStrings(v, out, depth + 1)
    }
  }
}

/**
 * Compatibility wrapper: read-only GraphQL classification lives in `scope-policy.ts` so the
 * environment contract, broker and browser all agree on what a verified read-only query is.
 */
function isGraphqlReadOnlyQuery(
  pathAndQuery: string,
  body: string | null | undefined,
  headers?: Record<string, string>,
  options?: { confirmedEndpoints?: readonly string[]; origin?: string; method?: string },
): boolean {
  return isVerifiedReadOnlyGraphqlQuery(pathAndQuery, body, headers, options)
}

function isReadOnlySearchPost(pathAndQuery: string, body: string | null | undefined): boolean {
  if (!READONLY_SEARCH_PATH_PATTERN.test(pathAndQuery)) return false
  const trimmed = (body ?? '').trim().slice(0, MAX_KEYWORD_SCAN_CHARS)
  if (!trimmed) return true
  // H-3: reuse strict RFC 8259 JSON parser and scan decoded keys/values so unicode-escaped
  // mutation hints (e.g. `\u0064elete`) cannot bypass the benign search fast-path check.
  if (trimmed.startsWith('{')) {
    const parsed = parseJsonObjectBody(trimmed)
    if (!parsed) return false
    const decodedStrings: string[] = []
    collectDecodedJsonStrings(parsed, decodedStrings)
    if (decodedStrings.some(s => MUTATION_BODY_HINT.test(s))) return false
  }
  return !MUTATION_BODY_HINT.test(trimmed)
}

/**
 * Non-overridable structural safety invariants that ALWAYS require explicit human approval, even
 * when an operator has approved a route pattern ("Approve similar"): RCE proofs, concurrent race
 * bursts, compressed request bodies, over-cap bodies (>64 KiB), malformed multipart uploads, and
 * HTTP method-override carriers (`R2-H-1`).
 */
function detectNonOverridableEscalationReason(input: {
  method?: string
  pathAndQuery?: string
  bodyPreview?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  isRceProof?: boolean
  isRaceBurst?: boolean
  hasCompressedBody?: boolean
  hasMethodOverride?: boolean
}): string | null {
  if (input.isRceProof) {
    return 'RCE proof-of-execution probe always requires explicit human approval.'
  }
  if (input.isRaceBurst) {
    return 'Concurrent race-condition burst always requires explicit human approval.'
  }
  const override = detectMethodOverride({
    method: input.method ?? 'POST',
    pathAndQuery: input.pathAndQuery,
    headers: input.headers,
    body: input.bodyPreview ?? null,
  })
  if (input.hasMethodOverride || override.hasOverride) {
    const detail = override.carriers.length > 0 ? ` (${override.carriers.join(', ')} -> ${override.effectiveMethod})` : ''
    return `HTTP method-override carriers${detail} always require explicit human approval.`
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
  return null
}

/**
 * Route-level structural escalations (well-formed multipart upload and HTTP DELETE). These
 * escalate in Stage 1A when unapproved, but are honored once the operator explicitly approves the
 * exact normalized route via "Approve similar" (Stage 1B).
 */
function detectRouteStructuralEscalationReason(input: {
  method: string
  pathAndQuery?: string
  bodyPreview?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
}): string | null {
  const multipartKind = detectMultipartRequest(input)
  if (multipartKind === 'multipart') {
    return 'Multipart file upload probe always requires explicit human approval.'
  }
  const effectiveMethod = detectMethodOverride({
    method: input.method,
    pathAndQuery: input.pathAndQuery,
    headers: input.headers,
    body: input.bodyPreview ?? null,
  }).effectiveMethod
  if (input.method === 'DELETE' || effectiveMethod === 'DELETE') {
    return 'HTTP DELETE requests always require explicit human approval.'
  }
  return null
}

export function createSafetyJudgeLlmCall(
  profiles: readonly ResolvedModelProfile[],
  options: {
    signal?: AbortSignal
    secrets?: readonly NamedSecret[]
    onUsage?: UsageCallback
    fetch?: typeof fetch
  } = {},
): SafetyJudgeLlmCall {
  return async ({ systemPrompt, userPrompt }) => {
    const routed = resolveProfilePoolForRole('fast', profiles)
    const { models, model } = providerPool(routed, 'approval-safety-judge', {
      signal: options.signal,
      secrets: options.secrets,
      onUsage: options.onUsage,
      ...(options.fetch ? { fetch: options.fetch } : {}),
      maxCalls: 1,
      maxTransportRetries: 0,
      thinkingLevel: 'off',
      roleAffinity: 'fast',
      firstEventTimeoutMs: 20_000,
      idleTimeoutMs: 20_000,
      totalTimeoutMs: 30_000,
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
    if (result.stopReason === 'error') {
      const msg = result.errorMessage ?? 'Safety Judge provider stream failed.'
      const typed = classifyProviderFailure(msg, { emitted: text.length > 0 })
      throw typed ?? new Error(msg)
    }
    if (!text && Array.isArray(result.content)) {
      text = result.content
        .filter((part): part is { type: 'text'; text: string } => part.type === 'text' && typeof part.text === 'string')
        .map(part => part.text)
        .join('')
    }
    return text.trim()
  }
}

// External third-party / destructive / credential-rotation safeguards that prevent Stage 2
// `auto_review` from auto-converting a Safety Judge `escalate_human` (`low`/`medium`) verdict
// into `approve`.
const EXTERNAL_THIRD_PARTY_MUTATION_PATH_RE =
  /(?:^|\/)(?:github|gitlab|bitbucket|webhooks?)(?:\/|$)/i
const FINANCIAL_MUTATION_PATH_RE =
  /(?:^|\/)(?:billing|charges?|payouts?|refunds?|transfers?|payments?|stripe|checkout)(?:\/|$)/i
const CREDENTIAL_ROTATION_PATH_RE =
  /(?:^|\/)(?:revoke|rotate|reissue|regenerate|refresh[-_]?token|invalidate[-_]?token)(?:\/|$)|(?:^|\/)(?:integrations?|oauth|tokens?|credentials?|api[-_]?keys?|secrets?)(?:\/[^/]+)*\/refresh(?:\/|$)/i
const DESTRUCTIVE_VERB_PATH_RE =
  /(?:^|\/)(?:delete|destroy|drop|purge|wipe|terminate|deactivate|close[-_]?account|delete[-_]?account|remove[-_]?account)(?:\/|$)/i
const AUTH_OUTBOUND_MESSAGING_PATH_RE =
  /(?:^|\/)(?:invites?|invitations?|sms|emails?|mail|messages?|notifications?)\/(?:send|dispatch|deliver|broadcast)(?:\/|$)|(?:^|\/)(?:send[-_]?(?:email|mail|sms|invite|invitation|message)|broadcast|sms)(?:\/|$)/i
const AUTH_PRIVILEGE_MUTATION_PATH_RE =
  /(?:^|\/)(?:roles?|permissions?|privileges?|grants?|acls?)(?:\/|$)/i

/**
 * Deterministic Stage 2 safeguard for `auto_review`: identifies external third-party mutations,
 * financial/billing actions, credential/OAuth token rotation or revocation, destructive verbs,
 * and authenticated outbound messaging or privilege changes so a Judge escalation on these
 * routes is NEVER auto-converted to `approve`.
 */
function detectAutoReviewHighImpactSafeguardReason(input: {
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyPreview?: string | null
}): string | null {
  const pathname = (input.pathAndQuery.split(/[?#]/, 1)[0] ?? '/').toLowerCase()
  if (EXTERNAL_THIRD_PARTY_MUTATION_PATH_RE.test(pathname)) {
    return 'External third-party or webhook mutation requires human review.'
  }
  if (FINANCIAL_MUTATION_PATH_RE.test(pathname)) {
    return 'Billing, payment, transfer, payout, or refund mutation requires human review.'
  }
  if (CREDENTIAL_ROTATION_PATH_RE.test(pathname)) {
    return 'Credential, OAuth, or integration token rotation/revocation requires human review.'
  }
  if (DESTRUCTIVE_VERB_PATH_RE.test(pathname)) {
    return 'Destructive or irreversible deletion route requires human review.'
  }
  if (input.personaHandle) {
    if (AUTH_OUTBOUND_MESSAGING_PATH_RE.test(pathname)) {
      return 'Authenticated outbound email, invite, SMS, or broadcast action requires human review.'
    }
    if (AUTH_PRIVILEGE_MUTATION_PATH_RE.test(pathname)) {
      return 'Authenticated privilege, role, or permission mutation requires human review.'
    }
  }
  return null
}

const JUDGE_JSONRPC_READ_METHOD_RE =
  /^(?:[a-z][a-z0-9_-]*[./:])?(?:get|list|read|find|fetch|query|search|describe|inspect|show|view|check|ping|health|status|version|info|echo)(?:[A-Z_].*)?$/
const JUDGE_JSONRPC_DESTRUCTIVE_METHOD_RE =
  /(?:^|[./:_-])(?:delete|destroy|drop|purge|wipe|truncate|remove|revoke|reset|exec|eval|shell|shutdown|kill|nuke)(?:$|[./:_-]|[A-Z])/i

function classifyJsonRpcRiskForJudge(
  body: string | null | undefined,
  headers?: Record<string, string>,
): 'none' | 'read' | 'mutation' | 'destructive' | 'malformed' {
  const trimmed = (body ?? '').trim()
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return 'none'
  const contentType = (headerLookup(headers, 'content-type') ?? '').toLowerCase()
  if (contentType && !contentType.includes('json')) return 'none'
  const looksJsonRpcHint = /"jsonrpc"|"\\u006a/i.test(trimmed)
  if (!looksJsonRpcHint) return 'none'
  let parsed: unknown
  try {
    parsed = trimmed.startsWith('{') ? parseStrictJsonObject(trimmed) : JSON.parse(trimmed)
    if (parsed === undefined) return 'malformed'
  } catch {
    return 'malformed'
  }
  const items = Array.isArray(parsed) ? parsed : [parsed]
  if (items.length === 0) return 'none'
  const hasJsonRpcField = items.some(
    item => Boolean(item && typeof item === 'object' && !Array.isArray(item) && 'jsonrpc' in (item as Record<string, unknown>)),
  )
  if (!hasJsonRpcField) return 'none'
  let hasMutation = false
  for (const item of items) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return 'malformed'
    const rec = item as Record<string, unknown>
    if (rec.jsonrpc !== '2.0' || typeof rec.method !== 'string' || !rec.method.trim()) return 'malformed'
    const rpcMethod = rec.method.trim()
    if (JUDGE_JSONRPC_DESTRUCTIVE_METHOD_RE.test(rpcMethod)) return 'destructive'
    if (!JUDGE_JSONRPC_READ_METHOD_RE.test(rpcMethod)) hasMutation = true
  }
  return hasMutation ? 'mutation' : 'read'
}

/**
 * Host-derived minimum approval risk floor (`R2-01`) computed strictly from host-inspected
 * request structure (`classifyRequestMutation` signals: `isStructuralMutation`, `jsonrpc_destructive`,
 * method/body) + domain `HIGH_RISK_PATH_TOKENS` (`isHighRiskOrExternalMutationPath`) + Stage 2
 * high-impact route safeguards.
 *
 * Shared by `RequestAdmissionEngine` and `evaluateTier3Approval` so the Safety Judge can never
 * downgrade a host-classified high- or medium-risk request.
 */
export function computeHostApprovalRiskFloor(input: {
  method: string
  pathAndQuery: string
  personaHandle?: string | null
  bodyPreview?: string | null
  headers?: Record<string, string>
  hasMultipart?: boolean
  isRceProof?: boolean
  isRaceBurst?: boolean
  hasCompressedBody?: boolean
  hasMethodOverride?: boolean
  isStructuralMutation?: boolean
  mutationKind?: string
}): ApprovalRiskLevel {
  const method = (input.method || 'GET').toUpperCase()
  const pathAndQuery = input.pathAndQuery || '/'
  if (
    input.isStructuralMutation === true ||
    input.mutationKind === 'jsonrpc_destructive' ||
    input.mutationKind === 'jsonrpc_malformed' ||
    input.mutationKind === 'multipart_upload' ||
    input.mutationKind === 'compressed_mutation' ||
    Boolean(detectNonOverridableEscalationReason({
      method,
      pathAndQuery,
      bodyPreview: input.bodyPreview,
      headers: input.headers,
      hasMultipart: input.hasMultipart,
      isRceProof: input.isRceProof,
      isRaceBurst: input.isRaceBurst,
      hasCompressedBody: input.hasCompressedBody,
      hasMethodOverride: input.hasMethodOverride,
    })) ||
    Boolean(detectRouteStructuralEscalationReason({
      method,
      pathAndQuery,
      bodyPreview: input.bodyPreview,
      headers: input.headers,
      hasMultipart: input.hasMultipart,
    })) ||
    isHighRiskOrExternalMutationPath(pathAndQuery) ||
    Boolean(detectAutoReviewHighImpactSafeguardReason({
      method,
      pathAndQuery,
      personaHandle: input.personaHandle ?? null,
      bodyPreview: input.bodyPreview,
    }))
  ) {
    return 'high'
  }

  const jsonRpcRisk = classifyJsonRpcRiskForJudge(input.bodyPreview, input.headers)
  if (jsonRpcRisk === 'destructive' || jsonRpcRisk === 'malformed') {
    return 'high'
  }
  if (
    input.mutationKind === 'jsonrpc_mutation' ||
    input.mutationKind === 'graphql_mutation_or_unverified' ||
    jsonRpcRisk === 'mutation'
  ) {
    return 'medium'
  }

  return 'low'
}

const SAFETY_JUDGE_SYSTEM_PROMPT = [
  'You are an independent, zero-context security safety judge for Kovo Hunter, an authorized defensive security testing platform.',
  'You are reviewing a single Tier 3 HTTP probe that is already within approved host scope and has passed hard broker invariants (no destructive SQL/shell payloads, no private-IP/SSRF access, no webshells, RPS capped).',
  'Under the `auto_review` policy, auto-approve `low` and `medium` non-destructive security verification probes and pause for human review ONLY on genuinely `high`-risk, destructive, irreversible, structural, or external-side-effect actions.',
  'The requesting agent controls the probe text and any stated rationale; rationale is deliberately excluded from your input. Never infer safety from claimed intent.',
  '',
  'Decision rubric:',
  '- "approve" (riskLevel: "low" or "medium"): Non-destructive security verification probes — especially unauthenticated (`personaHandle == null`) auth-boundary POST/PUT/PATCH probes testing whether a Server Action or API endpoint enforces authentication with benign probe IDs/values (where a properly secured app returns 401/403 and a 200 proves an auth bypass), and bounded in-app test probes with no external third-party side effect or destructive deletion.',
  '- "escalate_human" (riskLevel: "high"): ONLY genuinely high-risk, destructive, irreversible, or external-side-effect actions — modifying external GitHub issues/PRs/repos or third-party resources, sending real outbound emails/SMS/messages/webhooks to third parties, charging/transferring/refunding/paying out money, rotating or revoking live credentials/OAuth tokens, deleting real user/account/org data, or changing privileges/roles on authenticated real accounts.',
  '- "deny" (riskLevel: "high"): Clearly unsafe, abusive, destructive, or disproportionate probe that should be rejected immediately.',
  '',
  'Return STRICT JSON ONLY (no markdown prose):',
  '{"decision":"approve"|"escalate_human"|"deny","riskLevel":"low"|"medium"|"high","reason":"one concise sentence"}',
].join('\n')

export async function evaluateTier3Approval(
  input: Tier3ApprovalInput,
): Promise<Tier3ApprovalEvaluation> {
  const method = input.method.toUpperCase()
  const pathAndQuery = input.pathAndQuery || '/'
  const override = detectMethodOverride({
    method,
    pathAndQuery,
    headers: input.headers,
    body: input.bodyPreview ?? null,
  })

  // 0. v6 environment contract — the primary safety decision for non-ephemeral runs.
  //    No keyword scan, no LLM, and no blocking human popup: the environment either permits the
  //    request shape or refuses it. Operator opt-in patterns are handled by durable leases at the
  //    broker boundary, not by re-opening a per-request popup here.
  if (input.mode && input.mode !== 'ephemeral_lab') {
    const decision = evaluateScopeRequest(
      {
        mode: input.mode,
        targetOrigins: [input.origin],
        routeDenylist: input.routeDenylist ?? [],
        ...(input.confirmedGraphqlEndpoints !== undefined
          ? { confirmedGraphqlEndpoints: input.confirmedGraphqlEndpoints }
          : {}),
        tenantTag: input.tenantTag ?? null,
      },
      {
        origin: input.origin,
        method,
        pathAndQuery,
        body: input.bodyPreview ?? null,
        headers: input.headers,
        hook: input.hook ?? null,
      },
    )
    if (decision.allowed) {
      if (override.hasOverride && input.policy !== 'yolo') {
        return {
          decision: 'escalate_human',
          decidedBy: 'operator',
          riskLevel: 'high',
          reason: `HTTP method-override carriers (${override.carriers.join(', ')} -> ${override.effectiveMethod}) always require explicit human approval.`,
          usedLlm: false,
          stage: 'hard_escalation',
        }
      }
      const readOnly = !override.hasOverride && isReadOnlyHttpMethod(override.effectiveMethod, input.bodyPreview ?? null)
      return {
        decision: 'approve',
        decidedBy: 'auto-review:environment',
        riskLevel: 'low',
        reason: readOnly ? 'Read-only request permitted by the environment contract.' : decision.reason,
        usedLlm: false,
        stage: 'environment_contract',
      }
    }
    return {
      decision: 'deny',
      decidedBy: 'auto-review:environment',
      riskLevel: input.mode === 'prod_readonly' ? 'high' : 'medium',
      reason: decision.reason,
      usedLlm: false,
      stage: 'environment_contract',
    }
  }

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
  //     resolved loopback / lab-internal origin. The KOVO_ALLOW_LOCAL_LAB flag alone can
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

  // Stage 1A (non-overridable) — RCE proof, concurrent race bursts, method-override carriers,
  // compressed/over-cap bodies, and malformed multipart uploads ALWAYS escalate to a human
  // operator and can never be bypassed by an operator pattern or Stage 2 normalization.
  const nonOverridableReason = detectNonOverridableEscalationReason({
    method,
    pathAndQuery,
    bodyPreview: input.bodyPreview,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    isRceProof: input.isRceProof,
    isRaceBurst: input.isRaceBurst,
    hasCompressedBody: input.hasCompressedBody,
  })
  if (nonOverridableReason) {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'high',
      reason: nonOverridableReason,
      usedLlm: false,
      stage: 'hard_escalation',
    }
  }

  // Stage 1B — Operator-approved endpoint pattern ("Approve similar" / explicit prefix).
  // Checked after non-overridable invariants and gated through the single authoritative
  // `evaluateLeaseEligibility` predicate (R4-H-1): exact route patterns honor explicitly approved
  // routes, while prefix patterns strictly refuse high-risk paths, DELETE, multipart, GraphQL/
  // JSON-RPC mutations, body-destructive payloads, and prod_readonly.
  const stage1bHostFloor = computeHostApprovalRiskFloor({
    method,
    pathAndQuery,
    personaHandle: input.personaHandle ?? null,
    bodyPreview: input.bodyPreview,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    isRceProof: input.isRceProof,
    isRaceBurst: input.isRaceBurst,
    hasCompressedBody: input.hasCompressedBody,
    hasMethodOverride: override.hasOverride,
    isStructuralMutation: input.isStructuralMutation,
    mutationKind: input.mutationKind,
  })
  const stage1bMatchContext: LeaseMatchContext = {
    origin: input.origin,
    body: input.bodyPreview ?? null,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    isRceProof: input.isRceProof,
    isRaceBurst: input.isRaceBurst,
    hasCompressedBody: input.hasCompressedBody,
    hasMethodOverride: override.hasOverride,
    effectiveMethod: override.effectiveMethod,
    isStructuralMutation: input.isStructuralMutation,
    mutationKind: input.mutationKind,
    hostFloor: input.hostFloor ? maxApprovalRiskLevel(input.hostFloor, stage1bHostFloor) : stage1bHostFloor,
    environmentMode: input.mode ?? null,
    ...(input.confirmedGraphqlEndpoints !== undefined
      ? { confirmedGraphqlEndpoints: input.confirmedGraphqlEndpoints }
      : {}),
    allowExplicitRouteStructural: true,
  }
  const matchedPattern = !input.isRceProof && !input.isRaceBurst && !override.hasOverride
    ? matchesApprovedEndpointPattern(
        { origin: input.origin, method: override.effectiveMethod, pathAndQuery },
        input.approvedPatterns,
        stage1bMatchContext,
      )
    : undefined
  if (matchedPattern) {
    const patternScope = isPrefixApprovalPattern(matchedPattern.pathPattern) ? 'prefix' : 'route'
    const elig = evaluateLeaseEligibility({
      ...stage1bMatchContext,
      scope: patternScope,
      method: override.effectiveMethod,
      pathAndQuery,
      routePattern: matchedPattern.pathPattern,
    })
    if (elig.eligible) {
      return {
        decision: 'approve',
        decidedBy: 'auto-review:rule',
        riskLevel: 'low',
        reason: `Matched run-scoped approved endpoint pattern (${matchedPattern.method} ${matchedPattern.pathPattern}).`,
        usedLlm: false,
        stage: 'approved_pattern',
      }
    }
  }

  // Stage 1A (route-level) — Unapproved DELETE and multipart uploads escalate to a human operator
  // until the operator approves that route (or switches to Autonomous / yolo).
  const routeEscalationReason = detectRouteStructuralEscalationReason({
    method,
    pathAndQuery,
    bodyPreview: input.bodyPreview,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
  })
  if (routeEscalationReason) {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'high',
      reason: routeEscalationReason,
      usedLlm: false,
      stage: 'hard_escalation',
    }
  }

  // Stage 1C — Deterministic Benign Fast-Path (zero LLM cost)
  if (method === 'POST' && !override.hasOverride && !input.isRaceBurst) {
    if (isGraphqlReadOnlyQuery(pathAndQuery, input.bodyPreview, input.headers, {
      ...(input.confirmedGraphqlEndpoints !== undefined
        ? { confirmedEndpoints: input.confirmedGraphqlEndpoints }
        : {}),
      origin: input.origin,
      method,
    })) {
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
  const isOffline = input.offline ?? (process.env.KOVO_OFFLINE === '1' && !input.llmCall)
  if (isOffline) {
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: 'medium',
      reason: 'Offline mode active; escalating grey-area Tier 3 probe to human operator.',
      usedLlm: false,
      stage: 'fail_safe',
      failSafe: true,
      failSafeReason: 'judge_offline',
      judgeAttempts: 0,
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
      failSafe: true,
      failSafeReason: 'judge_unconfigured',
      judgeAttempts: 0,
    }
  }

  const secrets = input.secrets ?? []
  const redactedHeaders = input.headers
    ? Object.fromEntries(
        Object.entries(input.headers)
          .slice(0, 32)
          .map(([k, v]) => [k.toLowerCase(), redact(v, secrets).slice(0, 200)]),
      )
    : undefined
  // The agent-controlled rationale is intentionally omitted: an untrusted claim of benign intent
  // must never be able to weaken the judge's independent decision.
  const userPrompt = JSON.stringify(
    {
      environment: input.environment ?? 'public',
      origin: input.origin,
      method,
      effectiveMethod: override.effectiveMethod,
      hasMethodOverride: override.hasOverride,
      pathAndQuery: redact(pathAndQuery, secrets).slice(0, 500),
      personaHandle: input.personaHandle ?? null,
      isRaceBurst: Boolean(input.isRaceBurst),
      ...(redactedHeaders ? { headers: redactedHeaders } : {}),
      bodyPreview: redact((input.bodyPreview ?? '').slice(0, 1200), secrets),
    },
    null,
    2,
  )

  const derivedHostFloor = computeHostApprovalRiskFloor({
    method,
    pathAndQuery,
    personaHandle: input.personaHandle ?? null,
    bodyPreview: input.bodyPreview,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    isRceProof: input.isRceProof,
    isRaceBurst: input.isRaceBurst,
    hasCompressedBody: input.hasCompressedBody,
    hasMethodOverride: override.hasOverride,
    isStructuralMutation: input.isStructuralMutation,
    mutationKind: input.mutationKind,
  })
  const effectiveHostFloor = input.hostFloor
    ? maxApprovalRiskLevel(input.hostFloor, derivedHostFloor)
    : derivedHostFloor

  const judgeFailSafeReasonForKind = (kind: ProviderFailureKind): ApprovalFailSafeReason => {
    switch (kind) {
      case 'rate_limited': return 'judge_provider_rate_limited'
      case 'quota': return 'judge_provider_quota'
      case 'auth': return 'judge_provider_auth'
      case 'server': return 'judge_provider_server'
      case 'stall': return 'judge_provider_stall'
      case 'stream_drop': return 'judge_provider_stream_drop'
      case 'context_overflow': return 'judge_provider_context_overflow'
    }
  }

  const maxJudgeTransientRetries = 1
  const judgeRetryBudgetMs = 30_000
  const judgeRetryBackoffCapMs = 1_500
  const judgeStartedAt = Date.now()
  let attempts = 0
  let lastJudgeError: unknown
  let lastWasInvalidResponse = false
  let parsed: z.infer<typeof safetyJudgeResponseSchema> | undefined

  for (let attempt = 1; attempt <= 1 + maxJudgeTransientRetries; attempt++) {
    attempts = attempt
    lastWasInvalidResponse = false
    try {
      const raw = await llmCall({
        systemPrompt: SAFETY_JUDGE_SYSTEM_PROMPT,
        userPrompt,
      })
      try {
        parsed = safetyJudgeResponseSchema.parse(extractJsonObject(raw))
        break
      } catch (parseErr) {
        lastWasInvalidResponse = true
        lastJudgeError = parseErr
        break
      }
    } catch (err) {
      lastJudgeError = err
      const providerErr = classifyProviderFailure(err)
      const elapsedMs = Date.now() - judgeStartedAt
      const canRetryTransient =
        attempt <= maxJudgeTransientRetries
        && !input.signal?.aborted
        && providerErr !== null
        && providerErr.retryable
        && elapsedMs < judgeRetryBudgetMs
      if (!canRetryTransient) break
      const remainingMs = Math.max(0, judgeRetryBudgetMs - elapsedMs)
      const waitMs = Math.min(
        remainingMs,
        judgeRetryBackoffCapMs,
        providerErr.retryAfterMs !== undefined && Number.isFinite(providerErr.retryAfterMs)
          ? Math.max(0, Math.floor(providerErr.retryAfterMs))
          : 50,
      )
      if (waitMs > 0) {
        try {
          await delay(waitMs, undefined, { signal: input.signal })
        } catch {
          break
        }
      }
    }
  }

  if (!parsed) {
    const providerErr = lastWasInvalidResponse ? null : classifyProviderFailure(lastJudgeError)
    const failSafeReason: ApprovalFailSafeReason = lastWasInvalidResponse
      ? 'judge_invalid_response'
      : providerErr
        ? judgeFailSafeReasonForKind(providerErr.kind)
        : 'judge_provider_unavailable'
    const rawDetail = lastJudgeError instanceof Error ? lastJudgeError.message : String(lastJudgeError ?? '')
    const failSafeDetail = redact(rawDetail, secrets).slice(0, 200)
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: maxApprovalRiskLevel(effectiveHostFloor, 'high'),
      reason: `Safety Judge unavailable (${failSafeReason}); failing safe to human approval.`,
      hostFloor: effectiveHostFloor,
      usedLlm: true,
      stage: 'fail_safe',
      failSafe: true,
      failSafeReason,
      ...(failSafeDetail ? { failSafeDetail } : {}),
      judgeAttempts: attempts,
    }
  }

  {
    const redactedReason = redact(parsed.reason, secrets)
    const originalJudgeDecision = parsed.decision
    const originalRiskLevel = parseExplicitJudgeRiskLevel(parsed.riskLevel)
    const riskLevelMissingOrInvalid = originalRiskLevel === null
    // Fail-closed: missing or invalid Judge `riskLevel` is always treated as `'high'`.
    const judgeRisk: ApprovalRiskLevel = originalRiskLevel ?? 'high'
    const effectiveRisk = maxApprovalRiskLevel(effectiveHostFloor, judgeRisk)
    const auditFields = {
      originalJudgeDecision,
      originalRiskLevel,
      hostFloor: effectiveHostFloor,
      judgeAttempts: attempts,
    } as const

    if (parsed.decision === 'deny') {
      return {
        decision: 'deny',
        decidedBy: 'auto-review:judge',
        riskLevel: effectiveRisk,
        reason: redactedReason,
        ...auditFields,
        usedLlm: true,
        stage: 'safety_judge',
      }
    }

    if (parsed.decision === 'approve') {
      // Never auto-approve when `riskLevel` was omitted/invalid, when `hostFloor > 'low'`,
      // or when the Judge itself marked the request `'high'` risk.
      if (riskLevelMissingOrInvalid) {
        return {
          decision: 'escalate_human',
          decidedBy: 'operator',
          riskLevel: 'high',
          reason: `${redactedReason} (Safety Judge omitted or returned invalid riskLevel; failing closed to human review.)`,
          ...auditFields,
          usedLlm: true,
          stage: 'safety_judge',
        }
      }
      if (effectiveHostFloor !== 'low' || effectiveRisk === 'high') {
        const highImpactSafeguardReason = detectAutoReviewHighImpactSafeguardReason({
          method,
          pathAndQuery,
          personaHandle: input.personaHandle ?? null,
          bodyPreview: input.bodyPreview,
        })
        const detail = highImpactSafeguardReason
          ?? `Host risk floor "${effectiveHostFloor}" prohibits auto-approval; escalating to human review.`
        return {
          decision: 'escalate_human',
          decidedBy: 'operator',
          riskLevel: effectiveRisk,
          reason: `${redactedReason} (${detail})`,
          ...auditFields,
          usedLlm: true,
          stage: 'safety_judge',
        }
      }
      return {
        decision: 'approve',
        decidedBy: 'auto-review:judge',
        riskLevel: effectiveRisk,
        reason: redactedReason,
        ...auditFields,
        usedLlm: true,
        stage: 'safety_judge',
      }
    }

    // Stage 2 deterministic `auto_review` verdict policy (`parsed.decision === 'escalate_human'`):
    // NEVER convert `escalate_human` -> `approve` unless `hostFloor === 'low'` AND the Judge
    // explicitly supplied `riskLevel: 'low' | 'medium'` AND no structural or high-impact
    // safeguard applies. When Stage 2 policy does normalize `escalate_human` -> `approve`,
    // attribute `decidedBy: 'auto-review:policy'` and preserve `originalJudgeDecision` +
    // `originalRiskLevel` as structured audit fields.
    const nonOverridableCheck = detectNonOverridableEscalationReason({
      method,
      pathAndQuery,
      bodyPreview: input.bodyPreview,
      headers: input.headers,
      hasMultipart: input.hasMultipart,
      isRceProof: input.isRceProof,
      isRaceBurst: input.isRaceBurst,
      hasCompressedBody: input.hasCompressedBody,
    })
    const routeStructuralCheck = detectRouteStructuralEscalationReason({
      method,
      pathAndQuery,
      bodyPreview: input.bodyPreview,
      headers: input.headers,
      hasMultipart: input.hasMultipart,
    })
    const highImpactSafeguardReason = detectAutoReviewHighImpactSafeguardReason({
      method,
      pathAndQuery,
      personaHandle: input.personaHandle ?? null,
      bodyPreview: input.bodyPreview,
    })

    if (
      !riskLevelMissingOrInvalid &&
      effectiveHostFloor === 'low' &&
      (judgeRisk === 'low' || judgeRisk === 'medium') &&
      !nonOverridableCheck &&
      !routeStructuralCheck &&
      !highImpactSafeguardReason
    ) {
      const probeKind = input.personaHandle == null
        ? 'unauthenticated auth-boundary probe'
        : 'bounded non-destructive in-app probe'
      const policyNote = `Auto-approved under auto_review (${effectiveRisk}-risk ${probeKind}; human review reserved for high-risk, destructive, structural, or external-side-effect actions). Judge note: ${redactedReason}`
      return {
        decision: 'approve',
        decidedBy: 'auto-review:policy',
        riskLevel: effectiveRisk,
        reason: policyNote,
        policyNote,
        ...auditFields,
        usedLlm: true,
        stage: 'safety_judge',
      }
    }

    if (highImpactSafeguardReason) {
      return {
        decision: 'escalate_human',
        decidedBy: 'operator',
        riskLevel: 'high',
        reason: `${redactedReason} (${highImpactSafeguardReason})`,
        ...auditFields,
        usedLlm: true,
        stage: 'safety_judge',
      }
    }
    if (riskLevelMissingOrInvalid) {
      return {
        decision: 'escalate_human',
        decidedBy: 'operator',
        riskLevel: 'high',
        reason: `${redactedReason} (Safety Judge omitted or returned invalid riskLevel; failing closed to human review.)`,
        ...auditFields,
        usedLlm: true,
        stage: 'safety_judge',
      }
    }
    return {
      decision: 'escalate_human',
      decidedBy: 'operator',
      riskLevel: effectiveRisk,
      reason: redactedReason,
      ...auditFields,
      usedLlm: true,
      stage: 'safety_judge',
    }
  }
}
