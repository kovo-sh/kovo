import { createHash } from 'node:crypto'
import { z } from 'zod'
import type { Finding } from '../domain.ts'
import { resolveProfilePoolForRole } from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { providerPool } from './provider.ts'
import type { UsageCallback } from './provider.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

export interface FindingFingerprintInput {
  origin: string
  cwe?: string | null
  category?: string | null
  endpoint?: string | null
  authState?: string | null
  specKind?: string | null
  /** HTTP verb of the probed step. Defaults to `any` so findings without a method never fragment. */
  method?: string | null
  /** Primary injectable/read parameter (query/body/header name). Empty when the route itself is the unit. */
  param?: string | null
}

export interface SpecDedupeFields {
  endpoint: string
  authState: string
  specKind: string
  method: string
  param: string
}

export interface ComputedFindingFingerprint {
  key: string
  hash: string
  normalizedEndpoint: string
}

export interface DedupeCandidate {
  id?: string
  origin: string
  title: string
  cwe?: string | null
  category?: string | null
  severity: Finding['severity']
  endpoint?: string | null
  authState?: string | null
  specKind?: string | null
  method?: string | null
  param?: string | null
  reason?: string
  impact?: string
  remediation?: string
  sourceOrigins?: string[]
  fingerprintHash?: string | null
}

export interface ExistingFindingRef {
  id: string
  origin: string
  title: string
  status: Finding['status'] | 'static_verified'
  cwe?: string | null
  category?: string | null
  severity: Finding['severity']
  endpoint?: string | null
  authState?: string | null
  specKind?: string | null
  method?: string | null
  param?: string | null
  reason?: string
  impact?: string
  remediation?: string
  sourceOrigins?: string[]
  fingerprintHash?: string | null
}

export interface StructuralDuplicateResult {
  isDuplicate: boolean
  duplicateOfId: string | null
  matchedFinding: ExistingFindingRef | null
  fingerprint: ComputedFindingFingerprint
  shouldUpgrade: boolean
  rationale: string
}

export type SemanticDedupeLlmCall = (prompt: {
  systemPrompt: string
  userPrompt: string
}) => Promise<string>

export interface SemanticDuplicateResult {
  isDuplicate: boolean
  duplicateOfId: string | null
  shouldUpgrade: boolean
  rationale: string
  usedLlm: boolean
}

export interface EvaluateSubmissionDedupeParams {
  candidate: DedupeCandidate
  existingFindings: readonly ExistingFindingRef[]
  llmCall?: SemanticDedupeLlmCall
  excludeFindingId?: string
}

export interface SubmissionDedupeDecision {
  action: 'accept' | 'reject_duplicate' | 'upgrade_existing'
  isDuplicate: boolean
  duplicateOfId: string | null
  shouldUpgrade: boolean
  stage: 'none' | 'structural' | 'semantic'
  fingerprintKey: string
  fingerprintHash: string
  normalizedEndpoint: string
  rationale: string
  instruction?: string
}

const SEVERITY_RANK: Record<Finding['severity'], number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const STATUS_PRIORITY: Record<ExistingFindingRef['status'], number> = {
  confirmed: 0,
  static_verified: 1,
  pending: 2,
  inconclusive: 3,
  dismissed: 4,
}

// Origin-wide vulnerability classes where distinct probe paths on the same origin
// typically share a single middleware/edge/server root cause.
const ORIGIN_WIDE_CWES = new Set([
  'CWE-942', // Permissive Cross-domain Policy (CORS)
  'CWE-346', // Origin Validation Error
  'CWE-693', // Protection Mechanism Failure (CSP / security headers)
  'CWE-1021', // Clickjacking / Frame Protection
  'CWE-319', // Cleartext Transmission / HSTS
  'CWE-295', // Improper Certificate Validation / TLS
  'CWE-327', // Broken/Risky Crypto / TLS cipher
  'CWE-614', // Sensitive Cookie without Secure
  'CWE-1004', // Sensitive Cookie without HttpOnly
  'CWE-1275', // Sensitive Cookie SameSite
])

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MONGO_ID_SEGMENT = /^[0-9a-f]{24}$/i
const NUMERIC_SEGMENT = /^\d+$/
const LONG_HEX_SEGMENT = /^[0-9a-f]{16,}$/i
const PREFIXED_ID_SEGMENT = /^[a-z]{2,10}_[a-zA-Z0-9]{8,}$/
const OPAQUE_TOKEN_SEGMENT = /^(?=.*\d)(?=.*[a-zA-Z])[a-zA-Z0-9_-]{14,}$/

export function severityRank(severity: Finding['severity']): number {
  return SEVERITY_RANK[severity] ?? 0
}

export function normalizeOrigin(origin: string): string {
  const trimmed = origin.trim().toLowerCase()
  if (!trimmed) return ''
  try {
    return new URL(trimmed).origin.toLowerCase()
  } catch {
    return trimmed.replace(/\/+$/, '')
  }
}

export function normalizeCwe(cwe?: string | null, category?: string | null): string {
  const cleanCwe = cwe?.trim().toUpperCase()
  if (cleanCwe && /^CWE-\d{1,5}$/.test(cleanCwe)) return cleanCwe
  const digits = cleanCwe?.match(/(\d{1,5})/)
  if (cleanCwe && digits && cleanCwe.includes('CWE')) return `CWE-${digits[1]}`
  const cleanCat = category?.trim().toLowerCase()
  return cleanCat || 'unknown'
}

/**
 * Normalize an endpoint path for fingerprinting. Literal segments are lowercased by default because
 * fingerprints must be host-case-insensitive; callers that build *request* paths (recon) pass
 * `preserveCase` so case-sensitive route segments (Next.js server actions, capitalized REST
 * resources) are not corrupted.
 */
export function normalizeEndpointTemplate(endpoint?: string | null, options?: { preserveCase?: boolean }): string {
  const preserveCase = options?.preserveCase === true
  const raw = (endpoint ?? '').trim()
  if (!raw) return '/'

  let pathname = raw
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      pathname = new URL(raw).pathname || '/'
    } catch {
      pathname = raw
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
    if (seg.startsWith(':') || (seg.startsWith('{') && seg.endsWith('}')) || (seg.startsWith('[') && seg.endsWith(']'))) {
      return ':id'
    }
    if (
      UUID_SEGMENT.test(seg) ||
      MONGO_ID_SEGMENT.test(seg) ||
      NUMERIC_SEGMENT.test(seg) ||
      LONG_HEX_SEGMENT.test(seg) ||
      PREFIXED_ID_SEGMENT.test(seg) ||
      OPAQUE_TOKEN_SEGMENT.test(seg)
    ) {
      return ':id'
    }
    return preserveCase ? seg : seg.toLowerCase()
  })

  const normalized = segments.join('/')
  return normalized || '/'
}

export function computeFindingFingerprint(input: FindingFingerprintInput): ComputedFindingFingerprint {
  const origin = normalizeOrigin(input.origin)
  const cwe = normalizeCwe(input.cwe, input.category)
  const normalizedEndpoint = normalizeEndpointTemplate(input.endpoint)
  const authState = (input.authState?.trim().toLowerCase() || 'anonymous')
  const specKind = (input.specKind?.trim().toLowerCase() || 'http_chain')
  const method = (input.method?.trim().toUpperCase() || 'ANY')
  const param = (input.param?.trim().toLowerCase() || '')
  // `(method, param)` participate in the key so GET vs DELETE BOLA/IDOR on one route and two
  // distinct injectable parameters on one route do not collapse into a single fingerprint.
  const key = `${origin}|${cwe}|${method}|${normalizedEndpoint}|${param}|${authState}|${specKind}`
  const hash = createHash('sha256').update(key).digest('hex')
  return { key, hash, normalizedEndpoint }
}

/** Extract the first parameter name from a pathAndQuery string (`?a=1&b=2` → `a`). */
function firstQueryParam(pathAndQuery: string | undefined | null): string {
  if (!pathAndQuery) return ''
  const qIdx = pathAndQuery.indexOf('?')
  if (qIdx < 0) return ''
  const query = pathAndQuery.slice(qIdx + 1).split('#')[0]
  for (const pair of query.split('&')) {
    const name = pair.split('=')[0]?.trim()
    if (name) return decodeURIComponentSafe(name)
  }
  return ''
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function firstJsonKey(value: unknown): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const key = Object.keys(value as Record<string, unknown>)[0]
  return typeof key === 'string' ? key : ''
}

/** Resolve the primary parameter for a ReplaySpec step (request body → query string). */
function primaryParamForRequest(request: { pathAndQuery?: string; jsonBody?: unknown; textBody?: string } | undefined): string {
  if (!request) return ''
  const jsonKey = firstJsonKey(request.jsonBody)
  if (jsonKey) return jsonKey
  const queryParam = firstQueryParam(request.pathAndQuery)
  if (queryParam) return queryParam
  if (typeof request.textBody === 'string') {
    const formParams = new URLSearchParams(request.textBody)
    const first = [...formParams.keys()][0]
    if (first) return first
  }
  return ''
}

function personaAuthState(personas: readonly (string | undefined)[]): string {
  const unique = [...new Set(personas.filter((p): p is string => Boolean(p && p.trim())))].sort()
  return unique.length ? `persona:${unique.join(',')}` : 'anonymous'
}

export function extractSpecDedupeFields(spec: unknown): SpecDedupeFields {
  if (!spec || typeof spec !== 'object') {
    return { endpoint: '/', authState: 'anonymous', specKind: 'http_chain', method: 'ANY', param: '' }
  }
  const s = spec as Record<string, unknown>
  const specKind = typeof s.kind === 'string' && s.kind.trim() ? s.kind.trim() : 'http_chain'

  if (specKind === 'http_chain' && Array.isArray(s.steps)) {
    const steps = s.steps as Array<{
      role?: string
      request?: { pathAndQuery?: string; persona?: string; method?: string; jsonBody?: unknown; textBody?: string }
    }>
    const probeStep = steps.find(st => st?.role === 'probe') ?? steps[0]
    const endpoint = probeStep?.request?.pathAndQuery ?? '/'
    const authState = personaAuthState(steps.filter(st => st?.role === 'probe').map(st => st?.request?.persona))
    const method = probeStep?.request?.method ?? 'ANY'
    const param = primaryParamForRequest(probeStep?.request)
    return { endpoint, authState, specKind, method, param }
  }

  if (specKind === 'browser_chain' && Array.isArray(s.steps)) {
    const steps = s.steps as Array<{ role?: string; pathAndQuery?: string; persona?: string }>
    const probeStep = steps.find(st => st?.role === 'probe') ?? steps[0]
    const endpoint = probeStep?.pathAndQuery ?? '/'
    const authState = probeStep?.persona ? `persona:${probeStep.persona}` : 'anonymous'
    return {
      endpoint,
      authState,
      specKind,
      method: 'ANY',
      param: firstQueryParam(endpoint),
    }
  }

  if (specKind === 'browser_dom') {
    const endpoint = typeof s.probePath === 'string' ? s.probePath : '/'
    const authState = typeof s.persona === 'string' && s.persona ? `persona:${s.persona}` : 'anonymous'
    return { endpoint, authState, specKind, method: 'ANY', param: firstQueryParam(endpoint) }
  }

  if (specKind === 'race_burst' && Array.isArray(s.burst)) {
    const first = s.burst[0] as { pathAndQuery?: string; persona?: string; method?: string } | undefined
    const endpoint = first?.pathAndQuery ?? '/'
    const authState = first?.persona ? `persona:${first.persona}` : 'anonymous'
    return { endpoint, authState, specKind, method: first?.method ?? 'ANY', param: firstQueryParam(endpoint) }
  }

  if (specKind === 'rce_proof') {
    const probeStep = s.probeStep as { request?: { pathAndQuery?: string; persona?: string; method?: string; jsonBody?: unknown } } | undefined
    const endpoint = probeStep?.request?.pathAndQuery ?? '/'
    const authState = probeStep?.request?.persona ? `persona:${probeStep.request.persona}` : 'anonymous'
    return {
      endpoint,
      authState,
      specKind,
      method: probeStep?.request?.method ?? 'ANY',
      param: primaryParamForRequest(probeStep?.request),
    }
  }

  if (specKind === 'sql_boolean_diff') {
    const probe = (s.probeRequest ?? s.targetRequest ?? s.request) as { pathAndQuery?: string; persona?: string; method?: string } | undefined
    const endpoint = (typeof s.pathAndQuery === 'string' ? s.pathAndQuery : probe?.pathAndQuery) ?? '/'
    const persona = (typeof s.persona === 'string' ? s.persona : probe?.persona)
    const method = (typeof s.method === 'string' ? s.method : probe?.method) ?? 'ANY'
    const param = typeof s.paramName === 'string' ? s.paramName : firstQueryParam(endpoint)
    return { endpoint, authState: persona ? `persona:${persona}` : 'anonymous', specKind, method, param }
  }

  if (specKind === 'sql_time_diff') {
    const endpoint = typeof s.pathAndQuery === 'string' ? s.pathAndQuery : '/'
    const persona = typeof s.persona === 'string' && s.persona
      ? `persona:${s.persona}`
      : typeof s.session === 'string' && s.session ? `session:${s.session}` : 'anonymous'
    const method = typeof s.method === 'string' ? s.method : 'ANY'
    const param = typeof s.paramName === 'string'
      ? s.paramName
      : firstJsonKey(s.jsonBody) || firstQueryParam(endpoint)
    return { endpoint, authState: persona, specKind, method, param }
  }

  if (specKind === 'auth_protocol_proof' && Array.isArray(s.steps)) {
    const steps = s.steps as Array<{
      role?: string
      request?: { pathAndQuery?: string; persona?: string; method?: string; jsonBody?: unknown; authMutation?: { kind?: string } }
    }>
    const probeStep = steps.find(st => st?.role === 'probe') ?? steps[0]
    const endpoint = probeStep?.request?.pathAndQuery ?? '/'
    const authState = personaAuthState(steps.filter(st => st?.role === 'probe').map(st => st?.request?.persona))
    const method = probeStep?.request?.method ?? 'ANY'
    const mutationKind = probeStep?.request?.authMutation?.kind
    const param = mutationKind ? `auth:${mutationKind}` : primaryParamForRequest(probeStep?.request)
    return { endpoint, authState, specKind, method, param }
  }

  if (specKind === 'cache_differential') {
    const endpoint = typeof s.probePath === 'string' ? s.probePath : '/'
    const persona = typeof s.poisonPersona === 'string' && s.poisonPersona
      ? `persona:${s.poisonPersona}`
      : 'anonymous'
    const method = typeof s.method === 'string' ? s.method : 'ANY'
    const headers = s.poisonHeaders && typeof s.poisonHeaders === 'object' && !Array.isArray(s.poisonHeaders)
      ? Object.keys(s.poisonHeaders as Record<string, unknown>).map(k => k.toLowerCase()).sort()
      : []
    const param = headers[0] ?? firstQueryParam(endpoint)
    return { endpoint, authState: persona, specKind, method, param }
  }

  if (specKind === 'ws_chain' && Array.isArray(s.steps)) {
    const steps = s.steps as Array<{ role?: string; pathAndQuery?: string; persona?: string }>
    const probeStep = steps.find(st => st?.role === 'probe') ?? steps[0]
    const endpoint = (typeof s.pathAndQuery === 'string' ? s.pathAndQuery : probeStep?.pathAndQuery) ?? '/'
    const persona = (typeof s.persona === 'string' ? s.persona : probeStep?.persona)
    return { endpoint, authState: persona ? `persona:${persona}` : 'anonymous', specKind, method: 'ANY', param: firstQueryParam(endpoint) }
  }

  if (specKind === 'upload_probe') {
    const uploadReq = (s.uploadRequest ?? s.uploadStep) as { pathAndQuery?: string; persona?: string; method?: string; fieldName?: string; request?: { pathAndQuery?: string; persona?: string; method?: string } } | undefined
    const endpoint = uploadReq?.pathAndQuery ?? uploadReq?.request?.pathAndQuery ?? (typeof s.uploadPath === 'string' ? s.uploadPath : '/')
    const persona = uploadReq?.persona ?? uploadReq?.request?.persona ?? (typeof s.persona === 'string' ? s.persona : undefined)
    const method = uploadReq?.method ?? uploadReq?.request?.method ?? 'ANY'
    const param = typeof uploadReq?.fieldName === 'string' ? uploadReq.fieldName : firstQueryParam(endpoint)
    return { endpoint, authState: persona ? `persona:${persona}` : 'anonymous', specKind, method, param }
  }

  if (specKind === 'static_ast_proof') {
    const repo = typeof s.repo === 'string' ? s.repo : ''
    const file = typeof s.file === 'string' ? s.file : ''
    const endpoint = file ? `/${[repo, file].filter(Boolean).join('/')}` : '/'
    const startLine = typeof s.startLine === 'number' ? String(s.startLine) : ''
    return { endpoint, authState: 'static', specKind, method: 'ANY', param: startLine }
  }

  if (specKind === 'dns_takeover') {
    const endpoint = typeof s.probePath === 'string' ? s.probePath : '/'
    return { endpoint, authState: 'anonymous', specKind, method: 'ANY', param: '' }
  }

  if (specKind === 'tls_audit') {
    // TLS posture is origin-wide by definition; `/` is the correct unit of work here.
    return { endpoint: '/', authState: 'anonymous', specKind, method: 'ANY', param: '' }
  }

  return { endpoint: '/', authState: 'anonymous', specKind, method: 'ANY', param: '' }
}

function activeExistingFindings(
  existingFindings: readonly ExistingFindingRef[],
  excludeId?: string,
): ExistingFindingRef[] {
  return existingFindings.filter(f => f.id !== excludeId && f.status !== 'dismissed')
}

function sortExistingByPrecedence(matches: ExistingFindingRef[]): ExistingFindingRef[] {
  return [...matches].sort((a, b) => {
    const statusDiff = (STATUS_PRIORITY[a.status] ?? 9) - (STATUS_PRIORITY[b.status] ?? 9)
    if (statusDiff !== 0) return statusDiff
    return severityRank(b.severity) - severityRank(a.severity)
  })
}

export function checkStructuralDuplicate(
  candidate: DedupeCandidate,
  existingFindings: readonly ExistingFindingRef[],
  excludeFindingId?: string,
): StructuralDuplicateResult {
  const fingerprint = computeFindingFingerprint({
    origin: candidate.origin,
    cwe: candidate.cwe,
    category: candidate.category,
    endpoint: candidate.endpoint,
    authState: candidate.authState,
    specKind: candidate.specKind,
    method: candidate.method,
    param: candidate.param,
  })
  const candidateHash = candidate.fingerprintHash || fingerprint.hash
  const active = activeExistingFindings(existingFindings, excludeFindingId ?? candidate.id)

  const matches = active.filter(existing => {
    const existingFp = existing.fingerprintHash || computeFindingFingerprint({
      origin: existing.origin,
      cwe: existing.cwe,
      category: existing.category,
      endpoint: existing.endpoint,
      authState: existing.authState,
      specKind: existing.specKind,
      method: existing.method,
      param: existing.param,
    }).hash
    return existingFp === candidateHash || existingFp === fingerprint.hash
  })

  if (!matches.length) {
    return {
      isDuplicate: false,
      duplicateOfId: null,
      matchedFinding: null,
      fingerprint,
      shouldUpgrade: false,
      rationale: 'No structural fingerprint collision found.',
    }
  }

  const best = sortExistingByPrecedence(matches)[0]
  const shouldUpgrade = severityRank(candidate.severity) > severityRank(best.severity)
  return {
    isDuplicate: true,
    duplicateOfId: best.id,
    matchedFinding: best,
    fingerprint,
    shouldUpgrade,
    rationale: shouldUpgrade
      ? `Structural fingerprint matched existing finding ${best.id} (${best.severity} → ${candidate.severity}); upgrade existing finding instead of creating a duplicate.`
      : `Structural fingerprint matched existing finding ${best.id} (${fingerprint.key}).`,
  }
}

export function findNearbyFindings(
  candidate: DedupeCandidate,
  existingFindings: readonly ExistingFindingRef[],
  excludeFindingId?: string,
): ExistingFindingRef[] {
  const active = activeExistingFindings(existingFindings, excludeFindingId ?? candidate.id)
  const candOrigin = normalizeOrigin(candidate.origin)
  const candCat = (candidate.category ?? '').trim().toLowerCase()
  const candCwe = normalizeCwe(candidate.cwe, candidate.category)
  const candSources = new Set([candOrigin, ...(candidate.sourceOrigins ?? []).map(normalizeOrigin)].filter(Boolean))

  const nearby = active.filter(existing => {
    const exOrigin = normalizeOrigin(existing.origin)
    const exCat = (existing.category ?? '').trim().toLowerCase()
    const exCwe = normalizeCwe(existing.cwe, existing.category)
    const sameOrigin = exOrigin === candOrigin
    const sameCategory = Boolean(candCat && exCat && candCat === exCat)
    const sameCwe = candCwe !== 'unknown' && exCwe === candCwe

    if (sameOrigin && (sameCategory || sameCwe)) return true

    const exSources = [exOrigin, ...(existing.sourceOrigins ?? []).map(normalizeOrigin)].filter(Boolean)
    const overlappingSources = exSources.some(src => candSources.has(src))
    if (overlappingSources && (sameCategory || sameCwe)) return true

    return false
  })

  return sortExistingByPrecedence(nearby).slice(0, 12)
}

function tokenize(text: string): Set<string> {
  const stop = new Set(['the', 'and', 'for', 'with', 'from', 'that', 'this', 'via', 'into', 'missing', 'allows', 'endpoint', 'check'])
  const tokens = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .split(/\s+/)
    .filter(tok => tok.length >= 3 && !stop.has(tok))
  return new Set(tokens)
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (!a.size && !b.size) return 0
  let intersection = 0
  for (const tok of a) {
    if (b.has(tok)) intersection++
  }
  const union = a.size + b.size - intersection
  return union === 0 ? 0 : intersection / union
}

function deterministicSemanticFallback(
  candidate: DedupeCandidate,
  nearbyFindings: readonly ExistingFindingRef[],
): SemanticDuplicateResult {
  const candOrigin = normalizeOrigin(candidate.origin)
  const candCwe = normalizeCwe(candidate.cwe, candidate.category)
  const candEndpoint = normalizeEndpointTemplate(candidate.endpoint)
  const candTokens = tokenize(`${candidate.title} ${candidate.reason ?? ''}`)

  for (const existing of nearbyFindings) {
    const exOrigin = normalizeOrigin(existing.origin)
    const exCwe = normalizeCwe(existing.cwe, existing.category)
    const exEndpoint = normalizeEndpointTemplate(existing.endpoint)
    const sameOrigin = candOrigin === exOrigin
    const sameCwe = candCwe !== 'unknown' && candCwe === exCwe
    const sameEndpoint = candEndpoint === exEndpoint
    // Two probes that explicitly name different verbs or different injectable parameters on the
    // same route are distinct attack surfaces (GET vs DELETE BOLA, two injectable params).
    const methodConflict = Boolean(
      candidate.method && existing.method &&
      candidate.method.trim().toUpperCase() !== existing.method.trim().toUpperCase(),
    )
    const paramConflict = Boolean(
      candidate.param && existing.param &&
      candidate.param.trim().toLowerCase() !== existing.param.trim().toLowerCase(),
    )
    const probeConflict = methodConflict || paramConflict
    const shouldUpgrade = severityRank(candidate.severity) > severityRank(existing.severity)

    // Same origin + origin-wide CWE (e.g., CORS / CSP / HSTS / TLS / cookies):
    // collapse duplicate Low/Medium CORS findings on the same host automatically!
    if (sameOrigin && sameCwe && ORIGIN_WIDE_CWES.has(candCwe)) {
      return {
        isDuplicate: true,
        duplicateOfId: existing.id,
        shouldUpgrade,
        rationale: `Deterministic fallback: same origin (${candOrigin}) and origin-wide class ${candCwe} as existing finding ${existing.id}.`,
        usedLlm: false,
      }
    }

    // Same origin + same CWE + same normalized endpoint template (even if authState/specKind differs)
    if (sameOrigin && sameCwe && sameEndpoint && !probeConflict) {
      return {
        isDuplicate: true,
        duplicateOfId: existing.id,
        shouldUpgrade,
        rationale: `Deterministic fallback: same origin (${candOrigin}), ${candCwe}, and normalized endpoint (${candEndpoint}) as existing finding ${existing.id}.`,
        usedLlm: false,
      }
    }

    // Same origin + same CWE + very high title/reason token overlap
    if (sameOrigin && sameCwe && !probeConflict) {
      const exTokens = tokenize(`${existing.title} ${existing.reason ?? ''}`)
      const sim = jaccardSimilarity(candTokens, exTokens)
      if (sim >= 0.6) {
        return {
          isDuplicate: true,
          duplicateOfId: existing.id,
          shouldUpgrade,
          rationale: `Deterministic fallback: same origin and ${candCwe} with high semantic token overlap (${sim.toFixed(2)}) with finding ${existing.id}.`,
          usedLlm: false,
        }
      }
    }
  }

  return {
    isDuplicate: false,
    duplicateOfId: null,
    shouldUpgrade: false,
    rationale: 'Deterministic fallback: distinct root cause or endpoint from nearby findings.',
    usedLlm: false,
  }
}

const semanticJudgeSchema = z.object({
  isDuplicate: z.boolean(),
  duplicateOfId: z.string().nullable(),
  shouldUpgrade: z.boolean().default(false),
  rationale: z.string().min(1).max(1000),
})

function extractJsonObject(raw: string): unknown {
  const trimmed = raw.trim()
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  const candidate = fenceMatch ? fenceMatch[1].trim() : trimmed
  const firstBrace = candidate.indexOf('{')
  const lastBrace = candidate.lastIndexOf('}')
  if (firstBrace === -1 || lastBrace <= firstBrace) {
    throw new Error('No JSON object found in semantic dedupe judge response.')
  }
  return JSON.parse(candidate.slice(firstBrace, lastBrace + 1))
}

export async function judgeSemanticDuplicate(
  candidate: DedupeCandidate,
  nearbyFindings: readonly ExistingFindingRef[],
  llmCall?: SemanticDedupeLlmCall,
): Promise<SemanticDuplicateResult> {
  if (!nearbyFindings.length) {
    return {
      isDuplicate: false,
      duplicateOfId: null,
      shouldUpgrade: false,
      rationale: 'No nearby findings to compare.',
      usedLlm: false,
    }
  }

  if (!llmCall) {
    return deterministicSemanticFallback(candidate, nearbyFindings)
  }

  const systemPrompt = [
    'You are Guardian’s security finding deduplication judge.',
    'Determine whether the CANDIDATE vulnerability shares the SAME underlying root cause and single remediation fix as one of the EXISTING findings.',
    'Rules:',
    '- Return STRICT JSON only with keys: {"isDuplicate": boolean, "duplicateOfId": string | null, "shouldUpgrade": boolean, "rationale": string}.',
    '- Mark isDuplicate=true ONLY if fixing one existing finding fixes the candidate (same root cause, same component/middleware/handler).',
    '- Different endpoints with distinct authorization/injection bugs are NOT duplicates, even if they share a CWE.',
    '- Near-identical origin-level misconfigurations (e.g., two CORS reflections on the same host, one Low and one Medium with credentials) ARE duplicates, and shouldUpgrade=true if the candidate proves higher severity/impact.',
    '- If isDuplicate=false, duplicateOfId MUST be null and shouldUpgrade MUST be false.',
  ].join('\n')

  const userPrompt = JSON.stringify({
    candidate: {
      origin: candidate.origin,
      title: candidate.title,
      cwe: candidate.cwe ?? null,
      category: candidate.category ?? null,
      severity: candidate.severity,
      endpoint: normalizeEndpointTemplate(candidate.endpoint),
      authState: candidate.authState ?? 'anonymous',
      specKind: candidate.specKind ?? 'http_chain',
      method: candidate.method ?? 'ANY',
      param: candidate.param ?? null,
      reason: (candidate.reason ?? '').slice(0, 600),
      impact: (candidate.impact ?? '').slice(0, 400),
      remediation: (candidate.remediation ?? '').slice(0, 400),
    },
    existingFindings: nearbyFindings.map(f => ({
      id: f.id,
      origin: f.origin,
      title: f.title,
      status: f.status,
      cwe: f.cwe ?? null,
      category: f.category ?? null,
      severity: f.severity,
      endpoint: normalizeEndpointTemplate(f.endpoint),
      authState: f.authState ?? 'anonymous',
      specKind: f.specKind ?? 'http_chain',
      method: f.method ?? 'ANY',
      param: f.param ?? null,
      reason: (f.reason ?? '').slice(0, 400),
      remediation: (f.remediation ?? '').slice(0, 300),
    })),
  }, null, 2)

  try {
    const raw = await llmCall({ systemPrompt, userPrompt })
    const parsed = semanticJudgeSchema.parse(extractJsonObject(raw))
    if (!parsed.isDuplicate) {
      return {
        isDuplicate: false,
        duplicateOfId: null,
        shouldUpgrade: false,
        rationale: parsed.rationale,
        usedLlm: true,
      }
    }

    const matched = nearbyFindings.find(f => f.id === parsed.duplicateOfId)
    if (!matched) {
      return deterministicSemanticFallback(candidate, nearbyFindings)
    }

    const higherSeverity = severityRank(candidate.severity) > severityRank(matched.severity)
    return {
      isDuplicate: true,
      duplicateOfId: matched.id,
      shouldUpgrade: parsed.shouldUpgrade || higherSeverity,
      rationale: parsed.rationale,
      usedLlm: true,
    }
  } catch {
    return deterministicSemanticFallback(candidate, nearbyFindings)
  }
}

export async function evaluateSubmissionDedupe(
  params: EvaluateSubmissionDedupeParams,
): Promise<SubmissionDedupeDecision> {
  const excludeId = params.excludeFindingId ?? params.candidate.id
  const structural = checkStructuralDuplicate(params.candidate, params.existingFindings, excludeId)

  if (structural.isDuplicate && structural.duplicateOfId) {
    const action = structural.shouldUpgrade ? 'upgrade_existing' : 'reject_duplicate'
    return {
      action,
      isDuplicate: true,
      duplicateOfId: structural.duplicateOfId,
      shouldUpgrade: structural.shouldUpgrade,
      stage: 'structural',
      fingerprintKey: structural.fingerprint.key,
      fingerprintHash: structural.fingerprint.hash,
      normalizedEndpoint: structural.fingerprint.normalizedEndpoint,
      rationale: structural.rationale,
      instruction: structural.shouldUpgrade
        ? `Duplicate of finding ${structural.duplicateOfId} with higher impact/severity. Call update_proposed_finding("${structural.duplicateOfId}") to upgrade its Replay Spec and severity instead of creating a new finding.`
        : `Duplicate of existing finding ${structural.duplicateOfId} (structural match). Do not re-submit; call update_proposed_finding("${structural.duplicateOfId}") only if you have a stronger Replay Spec or additional chain step.`,
    }
  }

  const nearby = findNearbyFindings(params.candidate, params.existingFindings, excludeId)
  if (nearby.length > 0) {
    const semantic = await judgeSemanticDuplicate(params.candidate, nearby, params.llmCall)
    if (semantic.isDuplicate && semantic.duplicateOfId) {
      const action = semantic.shouldUpgrade ? 'upgrade_existing' : 'reject_duplicate'
      return {
        action,
        isDuplicate: true,
        duplicateOfId: semantic.duplicateOfId,
        shouldUpgrade: semantic.shouldUpgrade,
        stage: 'semantic',
        fingerprintKey: structural.fingerprint.key,
        fingerprintHash: structural.fingerprint.hash,
        normalizedEndpoint: structural.fingerprint.normalizedEndpoint,
        rationale: semantic.rationale,
        instruction: semantic.shouldUpgrade
          ? `Same root cause as finding ${semantic.duplicateOfId}, with higher impact. Call update_proposed_finding("${semantic.duplicateOfId}") to supersede/upgrade it.`
          : `Same root cause as existing finding ${semantic.duplicateOfId}. Do not create a duplicate row; use update_proposed_finding("${semantic.duplicateOfId}") if adding a stronger proof.`,
      }
    }
  }

  return {
    action: 'accept',
    isDuplicate: false,
    duplicateOfId: null,
    shouldUpgrade: false,
    stage: 'none',
    fingerprintKey: structural.fingerprint.key,
    fingerprintHash: structural.fingerprint.hash,
    normalizedEndpoint: structural.fingerprint.normalizedEndpoint,
    rationale: 'Accepted as a distinct finding.',
  }
}

export function createProviderLlmCall(
  profiles: readonly ResolvedModelProfile[],
  options: {
    signal?: AbortSignal
    secrets?: readonly NamedSecret[]
    onUsage?: UsageCallback
    scenario?: string
  } = {},
): SemanticDedupeLlmCall {
  return async ({ systemPrompt, userPrompt }) => {
    const routed = resolveProfilePoolForRole('fast', profiles)
    const { models, model } = providerPool(routed, options.scenario ?? 'dedupe-judge', {
      signal: options.signal,
      secrets: options.secrets,
      onUsage: options.onUsage,
      maxCalls: 2,
      thinkingLevel: 'off',
      roleAffinity: 'fast',
      firstEventTimeoutMs: 30_000,
      idleTimeoutMs: 30_000,
      totalTimeoutMs: 45_000,
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
