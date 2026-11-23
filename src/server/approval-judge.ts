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
    if (seg === '*') return '*'
    if (
      seg.startsWith(':') ||
      (seg.startsWith('{') && seg.endsWith('}')) ||
      (seg.startsWith('[') && seg.endsWith(']')) ||
      UUID_SEGMENT.test(seg) ||
      MONGO_ID_SEGMENT.test(seg) ||
      NUMERIC_SEGMENT.test(seg) ||
      LONG_HEX_SEGMENT.test(seg) ||
      PREFIXED_ID_SEGMENT.test(seg) ||
      OPAQUE_TOKEN_SEGMENT.test(seg)
    ) {
      return '*'
    }
    return seg.toLowerCase()
  })

  return segments.join('/') || '/'
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
  const targetNorm = normalizeApprovalPathPattern(target.pathAndQuery)
  const targetSegs = targetNorm.split('/').filter(Boolean)

  for (const pattern of patterns) {
    if (normalizeOriginKey(pattern.origin) !== targetOrigin) continue
    if (pattern.method.toUpperCase() !== targetMethod) continue
    const patNorm = normalizeApprovalPathPattern(pattern.pathPattern)
    if (patNorm === targetNorm) return pattern
    const patSegs = patNorm.split('/').filter(Boolean)
    if (patSegs.length === targetSegs.length) {
      const matched = patSegs.every((seg, i) => seg === '*' || seg === targetSegs[i])
      if (matched) return pattern
    }
    // Trailing wildcard prefix match (e.g., /api/v1/items/* matches /api/v1/items/123/sub)
    if (patSegs.length > 0 && patSegs[patSegs.length - 1] === '*' && targetSegs.length >= patSegs.length) {
      const prefixMatched = patSegs.slice(0, -1).every((seg, i) => seg === '*' || seg === targetSegs[i])
      if (prefixMatched) return pattern
    }
  }
  return undefined
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

function isGraphqlReadOnlyQuery(pathAndQuery: string, body: string | null | undefined): boolean {
  const trimmed = (body ?? '').trim()
  const looksGraphqlPath = GRAPHQL_PATH_PATTERN.test(pathAndQuery)
  const looksGraphqlBody =
    trimmed.includes('__schema') ||
    trimmed.includes('__type') ||
    trimmed.includes('IntrospectionQuery') ||
    /"query"\s*:/i.test(trimmed)
  if (!looksGraphqlPath && !looksGraphqlBody) return false
  if (/\bmutation\b/i.test(trimmed)) return false
  return true
}

function isReadOnlySearchPost(pathAndQuery: string, body: string | null | undefined): boolean {
  if (!READONLY_SEARCH_PATH_PATTERN.test(pathAndQuery)) return false
  const trimmed = (body ?? '').trim()
  if (!trimmed) return true
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
}): string | null {
  if (input.isRceProof) {
    return 'RCE proof-of-execution probe always requires explicit human approval.'
  }
  if (input.hasMultipart) {
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
  const bodyText = (input.bodyPreview ?? '').slice(0, 4000)

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
  if (input.environment === 'local-lab' && isLocalLabAutoApprovalOrigin(input.origin) && input.method !== 'DELETE' && !input.hasMultipart && !input.isRceProof) {
    return {
      decision: 'approve',
      decidedBy: 'auto-review:local-lab',
      riskLevel: 'medium',
      reason: 'Authorized local-lab auto-approval for loopback/lab-internal origin (broker destructive-payload, webshell, SSRF metadata and RPS invariants still enforced).',
      usedLlm: false,
      stage: 'local_lab',
    }
  }

  // Check operator-approved endpoint pattern (except RCE proof which always escalates unless explicitly approved)
  const matchedPattern = !input.isRceProof
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

  // Stage 1A — Hard Escalation Patterns (ALWAYS escalate to human)
  const hardEscalationReason = detectHardEscalationReason({
    method,
    pathAndQuery,
    personaHandle: input.personaHandle,
    bodyPreview: input.bodyPreview,
    headers: input.headers,
    hasMultipart: input.hasMultipart,
    isRceProof: input.isRceProof,
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

  // Stage 1B — Deterministic Benign Fast-Path (zero LLM cost)
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
  const userPrompt = JSON.stringify(
    {
      environment: input.environment ?? 'public',
      origin: input.origin,
      method,
      pathAndQuery: redact(pathAndQuery, secrets).slice(0, 500),
      personaHandle: input.personaHandle ?? null,
      isRaceBurst: Boolean(input.isRaceBurst),
      bodyPreview: redact((input.bodyPreview ?? '').slice(0, 1200), secrets),
      rationale: redact((input.rationale ?? '').slice(0, 500), secrets),
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
