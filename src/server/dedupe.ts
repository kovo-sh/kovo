import { z } from 'zod'
import type { Finding } from '../domain.ts'
import { cweFamiliesIntersect, isConcreteCwe } from '../vuln-taxonomy.ts'
import {
  ORIGIN_WIDE_CWE_KEYS,
  computeFindingFingerprint,
  normalizeCwe,
  normalizeEndpointTemplate,
  normalizeHandlerRef,
  normalizeMutatedInput,
  normalizeOrigin,
} from './finding-fingerprint.ts'
import type {
  ComputedFindingFingerprint,
  FindingFingerprintInput,
  MutatedInput,
  MutatedInputKind,
} from './finding-fingerprint.ts'
import { resolveProfilePoolForRole } from './model-settings.ts'
import type { ResolvedModelProfile } from './model-settings.ts'
import { providerOptionsFor } from './provider-runtime-policy.ts'
import { providerPool } from './provider.ts'
import type { TelemetryCallback, UsageCallback } from './provider.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

export {
  ORIGIN_WIDE_CWE_KEYS,
  computeFindingFingerprint,
  isOriginWideCwe,
  normalizeCwe,
  normalizeEndpointTemplate,
  normalizeHandlerRef,
  normalizeMutatedInput,
  normalizeOrigin,
} from './finding-fingerprint.ts'
export type {
  ComputedFindingFingerprint,
  FindingFingerprintInput,
  MutatedInput,
  MutatedInputKind,
} from './finding-fingerprint.ts'

export interface SpecDedupeFields {
  endpoint: string
  authState: string
  specKind: string
  method: string
  param: string
  graphqlField: string
  /** Explicitly mutated input declared by the spec schema (sql/upload/cache/graphql). */
  mutated?: MutatedInput
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
  graphqlField?: string | null
  mutated?: MutatedInput | null
  handler?: string | null
  verifiedEndpoint?: string | null
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
  graphqlField?: string | null
  mutated?: MutatedInput | null
  handler?: string | null
  verifiedEndpoint?: string | null
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

export type SameFindingIdentity = Pick<
  DedupeCandidate,
  'origin' | 'cwe' | 'category' | 'endpoint' | 'method' | 'param' | 'graphqlField' | 'mutated' | 'handler' | 'verifiedEndpoint'
>

export type SameFindingPredicateReason =
  | 'origin_wide_cwe'
  | 'same_surface'
  | 'origin_mismatch'
  | 'cwe_family_conflict'
  | 'endpoint_mismatch'
  | 'method_conflict'
  | 'param_conflict'
  | 'field_conflict'
  | 'mutation_conflict'
  | 'input_location_conflict'
  | 'handler_conflict'

export interface SameFindingPredicateEvaluation {
  allowed: boolean
  reason: SameFindingPredicateReason
  detail: string
}

export interface SemanticDuplicateResult {
  isDuplicate: boolean
  duplicateOfId: string | null
  shouldUpgrade: boolean
  rationale: string
  usedLlm: boolean
  /** Populated when the deterministic veto overrode an LLM `isDuplicate: true` verdict against a distinct sibling. */
  vetoedDuplicateOfId?: string
  /** Structured reason why `sameFindingPredicate` vetoed the LLM duplicate verdict. */
  vetoReason?: SameFindingPredicateReason
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
  /** Existing sibling finding ID when a model duplicate verdict was vetoed by `sameFindingPredicate`. */
  siblingOfId?: string
  /** Structured deterministic veto reason when `siblingOfId` is recorded. */
  vetoReason?: SameFindingPredicateReason
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

/**
 * Extract the first root field/resolver name from a GraphQL operation string. The `/graphql`
 * route is shared by every resolver, so the root field (not the path) is the dedupe unit.
 * Returns an empty string when the payload is not a recognisable GraphQL operation.
 */
export function extractGraphqlRootField(query?: string | null): string {
  if (typeof query !== 'string' || !query.trim()) return ''
  const stripped = query.replace(/#[^\n\r]*/g, ' ')
  const match = stripped.match(
    /^\s*(?:(?:query|mutation|subscription)\b(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\([^)]*\))?\s*)?\{\s*([A-Za-z_][A-Za-z0-9_]*)/,
  )
  return match?.[1]?.toLowerCase() ?? ''
}

export function severityRank(severity: Finding['severity']): number {
  return SEVERITY_RANK[severity] ?? 0
}

/** Fingerprint ignoring any explicit mutation (the deprecated first-key heuristic key). */
function computeLegacyFindingFingerprint(input: FindingFingerprintInput): ComputedFindingFingerprint {
  return computeFindingFingerprint({ ...input, mutated: null })
}

/**
 * Deprecated-heuristic view of a finding for backward compatibility: a param/graphql mutation is
 * projected onto `param`/`graphqlField`, so a v6 finding still matches a v5 row that only carried
 * the first-key heuristic. Header/RPC mutations have no legacy equivalent and return null.
 */
function computeLegacyEquivalentFingerprint(input: FindingFingerprintInput): ComputedFindingFingerprint | null {
  const mutated = normalizeMutatedInput(input.mutated)
  if (!mutated) return computeLegacyFindingFingerprint(input)
  if (mutated.kind !== 'param' && mutated.kind !== 'graphql') return null
  return computeLegacyFindingFingerprint({
    ...input,
    param: mutated.kind === 'param' ? input.param?.trim() || mutated.name : input.param,
    graphqlField: mutated.kind === 'graphql' ? input.graphqlField?.trim() || mutated.name : input.graphqlField,
  })
}

function fingerprintInputFromRef(ref: DedupeCandidate | ExistingFindingRef): FindingFingerprintInput {
  return {
    origin: ref.origin,
    cwe: ref.cwe,
    category: ref.category,
    endpoint: ref.endpoint,
    authState: ref.authState,
    specKind: ref.specKind,
    method: ref.method,
    param: ref.param,
    graphqlField: ref.graphqlField,
    mutated: ref.mutated,
    handler: ref.handler,
    verifiedEndpoint: ref.verifiedEndpoint,
  }
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

/**
 * Map a spec-declared `(paramName, paramLocation)` pair to the dedupe mutation unit. The location
 * decides whether the mutated input is a header, a GraphQL variable, or a body/query parameter.
 */
function declaredParamMutation(paramName: unknown, paramLocation: unknown): MutatedInput | undefined {
  if (typeof paramName !== 'string' || !paramName.trim()) return undefined
  const location = typeof paramLocation === 'string' ? paramLocation.trim().toLowerCase() : ''
  const kind: MutatedInputKind = location === 'header' ? 'header' : location === 'graphql_var' ? 'graphql' : 'param'
  return location ? { kind, name: paramName.trim(), location } : { kind, name: paramName.trim() }
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
    return { endpoint: '/', authState: 'anonymous', specKind: 'http_chain', method: 'ANY', param: '', graphqlField: '' }
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
    const body = probeStep?.request?.jsonBody
    const graphqlQuery = body && typeof body === 'object' && !Array.isArray(body)
      ? (body as Record<string, unknown>).query
      : undefined
    const graphqlField = extractGraphqlRootField(typeof graphqlQuery === 'string' ? graphqlQuery : '')
    return {
      endpoint,
      authState,
      specKind,
      method,
      param: graphqlField ? '' : primaryParamForRequest(probeStep?.request),
      graphqlField,
      ...(graphqlField ? { mutated: { kind: 'graphql' as const, name: graphqlField } } : {}),
    }
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
      graphqlField: '',
    }
  }

  if (specKind === 'browser_dom') {
    const endpoint = typeof s.probePath === 'string' ? s.probePath : '/'
    const authState = typeof s.persona === 'string' && s.persona ? `persona:${s.persona}` : 'anonymous'
    return { endpoint, authState, specKind, method: 'ANY', param: firstQueryParam(endpoint), graphqlField: '' }
  }

  if (specKind === 'race_burst' && Array.isArray(s.burst)) {
    const first = s.burst[0] as { pathAndQuery?: string; persona?: string; method?: string } | undefined
    const endpoint = first?.pathAndQuery ?? '/'
    const authState = first?.persona ? `persona:${first.persona}` : 'anonymous'
    return { endpoint, authState, specKind, method: first?.method ?? 'ANY', param: firstQueryParam(endpoint), graphqlField: '' }
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
      graphqlField: '',
    }
  }

  if (specKind === 'sql_boolean_diff') {
    const probe = (s.probeRequest ?? s.targetRequest ?? s.request) as { pathAndQuery?: string; persona?: string; method?: string } | undefined
    const endpoint = (typeof s.pathAndQuery === 'string' ? s.pathAndQuery : probe?.pathAndQuery) ?? '/'
    const persona = (typeof s.persona === 'string' ? s.persona : probe?.persona)
    const method = (typeof s.method === 'string' ? s.method : probe?.method) ?? 'ANY'
    const param = typeof s.paramName === 'string' ? s.paramName : firstQueryParam(endpoint)
    const mutated = declaredParamMutation(s.paramName, s.paramLocation)
    return { endpoint, authState: persona ? `persona:${persona}` : 'anonymous', specKind, method, param, graphqlField: '', ...(mutated ? { mutated } : {}) }
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
    const mutated = declaredParamMutation(s.paramName, s.paramLocation)
    return { endpoint, authState: persona, specKind, method, param, graphqlField: '', ...(mutated ? { mutated } : {}) }
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
    return { endpoint, authState, specKind, method, param, graphqlField: '' }
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
    const mutated: MutatedInput | undefined = headers[0] ? { kind: 'header', name: headers[0], location: 'header' } : undefined
    return { endpoint, authState: persona, specKind, method, param, graphqlField: '', ...(mutated ? { mutated } : {}) }
  }

  if (specKind === 'ws_chain' && Array.isArray(s.steps)) {
    const steps = s.steps as Array<{ role?: string; pathAndQuery?: string; persona?: string }>
    const probeStep = steps.find(st => st?.role === 'probe') ?? steps[0]
    const endpoint = (typeof s.pathAndQuery === 'string' ? s.pathAndQuery : probeStep?.pathAndQuery) ?? '/'
    const persona = (typeof s.persona === 'string' ? s.persona : probeStep?.persona)
    return { endpoint, authState: persona ? `persona:${persona}` : 'anonymous', specKind, method: 'ANY', param: firstQueryParam(endpoint), graphqlField: '' }
  }

  if (specKind === 'upload_probe') {
    const uploadReq = (s.uploadRequest ?? s.uploadStep) as { pathAndQuery?: string; persona?: string; method?: string; fieldName?: string; request?: { pathAndQuery?: string; persona?: string; method?: string } } | undefined
    const endpoint = uploadReq?.pathAndQuery ?? uploadReq?.request?.pathAndQuery ?? (typeof s.uploadPath === 'string' ? s.uploadPath : '/')
    const persona = uploadReq?.persona ?? uploadReq?.request?.persona ?? (typeof s.persona === 'string' ? s.persona : undefined)
    const method = uploadReq?.method ?? uploadReq?.request?.method ?? 'ANY'
    const param = typeof uploadReq?.fieldName === 'string' ? uploadReq.fieldName : firstQueryParam(endpoint)
    const mutated: MutatedInput | undefined = typeof uploadReq?.fieldName === 'string' && uploadReq.fieldName.trim()
      ? { kind: 'param', name: uploadReq.fieldName.trim(), location: 'form' }
      : undefined
    return { endpoint, authState: persona ? `persona:${persona}` : 'anonymous', specKind, method, param, graphqlField: '', ...(mutated ? { mutated } : {}) }
  }

  if (specKind === 'static_ast_proof') {
    const repo = typeof s.repo === 'string' ? s.repo : ''
    const file = typeof s.file === 'string' ? s.file : ''
    const endpoint = file ? `/${[repo, file].filter(Boolean).join('/')}` : '/'
    const startLine = typeof s.startLine === 'number' ? String(s.startLine) : ''
    return { endpoint, authState: 'static', specKind, method: 'ANY', param: startLine, graphqlField: '' }
  }

  if (specKind === 'dns_takeover') {
    const endpoint = typeof s.probePath === 'string' ? s.probePath : '/'
    return { endpoint, authState: 'anonymous', specKind, method: 'ANY', param: '', graphqlField: '' }
  }

  if (specKind === 'tls_audit') {
    // TLS posture is origin-wide by definition; `/` is the correct unit of work here.
    return { endpoint: '/', authState: 'anonymous', specKind, method: 'ANY', param: '', graphqlField: '' }
  }

  return { endpoint: '/', authState: 'anonymous', specKind, method: 'ANY', param: '', graphqlField: '' }
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
  const fingerprint = computeFindingFingerprint(fingerprintInputFromRef(candidate))
  const candidateHash = candidate.fingerprintHash || fingerprint.hash
  const candidateMutated = fingerprint.mutated
  const candidateHandler = fingerprint.handler
  const active = activeExistingFindings(existingFindings, excludeFindingId ?? candidate.id)

  const matches = active.filter(existing => {
    const existingFp = computeFindingFingerprint(fingerprintInputFromRef(existing))
    const existingHash = existing.fingerprintHash || existingFp.hash
    const hashMatch = existingHash === candidateHash || existingHash === fingerprint.hash
    const existingHandler = existingFp.handler
    const handlerConflict = Boolean(candidateHandler && existingHandler && candidateHandler !== existingHandler)

    // Two explicit mutations are distinct attack surfaces even when a deprecated stored hash
    // collides: never merge two parameters, a header vs a body field, two GraphQL operations or
    // two RPC procedures on one endpoint.
    if (candidateMutated && existingFp.mutated) {
      const sameMutation = candidateMutated.kind === existingFp.mutated.kind
        && candidateMutated.name === existingFp.mutated.name
      return hashMatch && sameMutation && !handlerConflict
    }

    if (hashMatch) return !handlerConflict

    // Backward compatibility with findings fingerprinted before explicit mutations existed: only
    // param/graphql mutations can be projected onto the deprecated first-key heuristic.
    const mutatedSide = candidateMutated ?? existingFp.mutated
    if (mutatedSide && mutatedSide.kind !== 'param' && mutatedSide.kind !== 'graphql') return false

    const candidateLegacy = computeLegacyEquivalentFingerprint(fingerprintInputFromRef(candidate))
    const existingLegacy = computeLegacyEquivalentFingerprint(fingerprintInputFromRef(existing))
    if (!candidateLegacy || !existingLegacy) return false
    return candidateLegacy.hash === existingLegacy.hash
      || candidateLegacy.hash === existingHash
      || existingLegacy.hash === candidateHash
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

function normalizeComparableMethod(method?: string | null): string {
  const normalized = (method ?? '').trim().toUpperCase()
  return normalized && normalized !== 'ANY' ? normalized : ''
}

function implicitMutationKind(ref: Pick<SameFindingIdentity, 'param' | 'graphqlField'>): 'param' | 'graphql' | null {
  if (ref.graphqlField?.trim()) return 'graphql'
  if (ref.param?.trim()) return 'param'
  return null
}

/**
 * Deterministic surface-identity predicate shared by the offline semantic fallback and the hard
 * veto on LLM semantic deduplication verdicts.
 *
 * Returns `{ allowed: true }` ONLY when two findings share the same origin and either:
 *  - belong to the same origin-wide CWE (`ORIGIN_WIDE_CWE_KEYS`, e.g. CORS/CSP/HSTS/TLS/cookies), OR
 *  - target the same normalized route template, compatible HTTP method, compatible input location
 *    and verified handler, with no conflicting parameter name, GraphQL field, or mutation class.
 */
function evaluateSameFindingPredicate(
  candidate: SameFindingIdentity,
  existing: SameFindingIdentity,
): SameFindingPredicateEvaluation {
  const candOrigin = normalizeOrigin(candidate.origin)
  const exOrigin = normalizeOrigin(existing.origin)
  if (!candOrigin || candOrigin !== exOrigin) {
    return {
      allowed: false,
      reason: 'origin_mismatch',
      detail: `origin mismatch (${candOrigin || 'empty'} vs ${exOrigin || 'empty'})`,
    }
  }

  const candCwe = normalizeCwe(candidate.cwe, candidate.category)
  const exCwe = normalizeCwe(existing.cwe, existing.category)
  const sameCwe = candCwe !== 'unknown' && candCwe === exCwe

  // Same origin + same origin-wide CWE (e.g., CORS / CSP / HSTS / TLS / cookies):
  // distinct probe paths or handlers on the same host still collapse into one host-wide finding.
  if (sameCwe && ORIGIN_WIDE_CWE_KEYS.has(candCwe)) {
    return {
      allowed: true,
      reason: 'origin_wide_cwe',
      detail: `same origin (${candOrigin}) and origin-wide class ${candCwe}`,
    }
  }

  // R3-11 CWE-family veto: when both findings carry known concrete CWEs whose families do not
  // intersect (e.g., SQLi CWE-89 vs CMDi CWE-78 or SSTI CWE-1336 sharing `injection-input`, or
  // BOLA CWE-639 vs Mass Assignment CWE-915), never collapse them on the same surface.
  if (isConcreteCwe(candCwe) && isConcreteCwe(exCwe) && !cweFamiliesIntersect(candCwe, exCwe)) {
    return {
      allowed: false,
      reason: 'cwe_family_conflict',
      detail: `CWE family conflict (${candCwe} vs ${exCwe})`,
    }
  }

  const candEndpoint = normalizeEndpointTemplate(candidate.endpoint)
  const exEndpoint = normalizeEndpointTemplate(existing.endpoint)
  if (candEndpoint !== exEndpoint) {
    return {
      allowed: false,
      reason: 'endpoint_mismatch',
      detail: `normalized endpoint mismatch (${candEndpoint} vs ${exEndpoint})`,
    }
  }

  // Two probes that explicitly name different HTTP verbs, parameters, GraphQL fields, mutation
  // classes/locations, or verified handlers are distinct attack surfaces (GET vs DELETE BOLA,
  // two parameters, header vs body field, two resolvers, reverse-proxy microservices).
  const candMethod = normalizeComparableMethod(candidate.method)
  const exMethod = normalizeComparableMethod(existing.method)
  if (candMethod && exMethod && candMethod !== exMethod) {
    return {
      allowed: false,
      reason: 'method_conflict',
      detail: `HTTP method conflict (${candMethod} vs ${exMethod})`,
    }
  }

  const candMutated = normalizeMutatedInput(candidate.mutated)
  const exMutated = normalizeMutatedInput(existing.mutated)
  if (candMutated && exMutated) {
    if (candMutated.kind !== exMutated.kind || candMutated.name !== exMutated.name) {
      return {
        allowed: false,
        reason: 'mutation_conflict',
        detail: `mutated input conflict (${candMutated.kind}:${candMutated.name} vs ${exMutated.kind}:${exMutated.name})`,
      }
    }
    if (candMutated.location && exMutated.location && candMutated.location !== exMutated.location) {
      return {
        allowed: false,
        reason: 'input_location_conflict',
        detail: `input location conflict (${candMutated.location} vs ${exMutated.location})`,
      }
    }
  } else if (candMutated && !exMutated) {
    const exImplicit = implicitMutationKind(existing)
    if (candMutated.kind === 'header' || candMutated.kind === 'rpc' || (exImplicit && candMutated.kind !== exImplicit)) {
      return {
        allowed: false,
        reason: 'mutation_conflict',
        detail: `mutation class conflict (${candMutated.kind}:${candMutated.name} vs ${exImplicit ?? 'unmutated'})`,
      }
    }
  } else if (!candMutated && exMutated) {
    const candImplicit = implicitMutationKind(candidate)
    if (exMutated.kind === 'header' || exMutated.kind === 'rpc' || (candImplicit && exMutated.kind !== candImplicit)) {
      return {
        allowed: false,
        reason: 'mutation_conflict',
        detail: `mutation class conflict (${candImplicit ?? 'unmutated'} vs ${exMutated.kind}:${exMutated.name})`,
      }
    }
  }

  const candParam = (candidate.param ?? '').trim().toLowerCase() || (candMutated?.kind === 'param' ? candMutated.name : '')
  const exParam = (existing.param ?? '').trim().toLowerCase() || (exMutated?.kind === 'param' ? exMutated.name : '')
  if (candParam && exParam && candParam !== exParam) {
    return {
      allowed: false,
      reason: 'param_conflict',
      detail: `parameter conflict (${candParam} vs ${exParam})`,
    }
  }

  const candField = (candidate.graphqlField ?? '').trim().toLowerCase() || (candMutated?.kind === 'graphql' ? candMutated.name : '')
  const exField = (existing.graphqlField ?? '').trim().toLowerCase() || (exMutated?.kind === 'graphql' ? exMutated.name : '')
  if (candField && exField && candField !== exField) {
    return {
      allowed: false,
      reason: 'field_conflict',
      detail: `GraphQL field conflict (${candField} vs ${exField})`,
    }
  }

  const candHandler = normalizeHandlerRef(candidate.handler?.trim() ? candidate.handler : candidate.verifiedEndpoint)
  const exHandler = normalizeHandlerRef(existing.handler?.trim() ? existing.handler : existing.verifiedEndpoint)
  if (candHandler && exHandler && candHandler !== exHandler) {
    return {
      allowed: false,
      reason: 'handler_conflict',
      detail: `verified handler conflict (${candHandler} vs ${exHandler})`,
    }
  }

  return {
    allowed: true,
    reason: 'same_surface',
    detail: `same origin (${candOrigin}), normalized endpoint (${candEndpoint}), and compatible probe surface`,
  }
}

/**
 * Boolean convenience wrapper around `evaluateSameFindingPredicate`: true iff `candidate` and
 * `existing` refer to a mergeable attack surface (or the same origin-wide CWE class).
 */
export function sameFindingPredicate(
  candidate: SameFindingIdentity,
  existing: SameFindingIdentity,
): boolean {
  return evaluateSameFindingPredicate(candidate, existing).allowed
}

function deterministicSemanticFallback(
  candidate: DedupeCandidate,
  nearbyFindings: readonly ExistingFindingRef[],
): SemanticDuplicateResult {
  const candOrigin = normalizeOrigin(candidate.origin)
  const candCwe = normalizeCwe(candidate.cwe, candidate.category)
  const candEndpoint = normalizeEndpointTemplate(candidate.endpoint)

  for (const existing of nearbyFindings) {
    const exCwe = normalizeCwe(existing.cwe, existing.category)
    const sameCwe = candCwe !== 'unknown' && candCwe === exCwe
    if (!sameCwe) continue

    if (!sameFindingPredicate(candidate, existing)) continue

    const shouldUpgrade = severityRank(candidate.severity) > severityRank(existing.severity)

    // Same origin + origin-wide CWE (e.g., CORS / CSP / HSTS / TLS / cookies):
    // collapse duplicate Low/Medium CORS findings on the same host automatically!
    if (ORIGIN_WIDE_CWE_KEYS.has(candCwe)) {
      return {
        isDuplicate: true,
        duplicateOfId: existing.id,
        shouldUpgrade,
        rationale: `Deterministic fallback: same origin (${candOrigin}) and origin-wide class ${candCwe} as existing finding ${existing.id}.`,
        usedLlm: false,
      }
    }

    // Same origin + same CWE + same normalized endpoint template. Cross-endpoint title similarity
    // is deliberately NOT a duplicate signal: two BOLA routes or two resolvers on one host are
    // separate findings even when the prose is near-identical.
    return {
      isDuplicate: true,
      duplicateOfId: existing.id,
      shouldUpgrade,
      rationale: `Deterministic fallback: same origin (${candOrigin}), ${candCwe}, and normalized endpoint (${candEndpoint}) as existing finding ${existing.id}.`,
      usedLlm: false,
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
    'You are Kovo Hunter’s security finding deduplication judge.',
    'Determine whether the CANDIDATE vulnerability shares the SAME underlying root cause and single remediation fix as one of the EXISTING findings.',
    'Rules:',
    '- Return STRICT JSON only with keys: {"isDuplicate": boolean, "duplicateOfId": string | null, "shouldUpgrade": boolean, "rationale": string}.',
    '- Mark isDuplicate=true ONLY if fixing one existing finding fixes the candidate (same root cause, same component/middleware/handler).',
    '- Different endpoints with distinct authorization/injection bugs are NOT duplicates, even if they share a CWE.',
    '- Findings that mutate a different parameter, header, GraphQL operation or RPC procedure on the same endpoint are NOT duplicates.',
    '- Findings with distinct vulnerability classes / CWE families (e.g., SQLi vs command injection vs SSTI vs XXE, or BOLA vs mass assignment) on the same endpoint and parameter are NOT duplicates.',
    '- Findings that resolve to a different verified handler/service path behind a reverse proxy are NOT duplicates.',
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
      graphqlField: candidate.graphqlField ?? null,
      mutated: normalizeMutatedInput(candidate.mutated),
      handler: normalizeHandlerRef(candidate.handler?.trim() ? candidate.handler : candidate.verifiedEndpoint) || null,
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
      graphqlField: f.graphqlField ?? null,
      mutated: normalizeMutatedInput(f.mutated),
      handler: normalizeHandlerRef(f.handler?.trim() ? f.handler : f.verifiedEndpoint) || null,
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

    // Hard deterministic veto: the LLM may ONLY merge a candidate into an existing finding when
    // `sameFindingPredicate` confirms they target the same attack surface (or origin-wide CWE).
    if (!sameFindingPredicate(candidate, matched)) {
      const predicate = evaluateSameFindingPredicate(candidate, matched)
      return {
        isDuplicate: false,
        duplicateOfId: null,
        shouldUpgrade: false,
        rationale: `Deterministic veto overrode LLM duplicate verdict against sibling ${matched.id} (${predicate.reason}: ${predicate.detail}); proceeding to verification.`,
        usedLlm: true,
        vetoedDuplicateOfId: matched.id,
        vetoReason: predicate.reason,
      }
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
  let siblingVeto: { vetoedDuplicateOfId: string; vetoReason: SameFindingPredicateReason; rationale: string } | null = null
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
    if (semantic.vetoedDuplicateOfId && semantic.vetoReason) {
      siblingVeto = {
        vetoedDuplicateOfId: semantic.vetoedDuplicateOfId,
        vetoReason: semantic.vetoReason,
        rationale: semantic.rationale,
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
    rationale: siblingVeto ? siblingVeto.rationale : 'Accepted as a distinct finding.',
    ...(siblingVeto
      ? {
          siblingOfId: siblingVeto.vetoedDuplicateOfId,
          vetoReason: siblingVeto.vetoReason,
        }
      : {}),
  }
}

export function createProviderLlmCall(
  profiles: readonly ResolvedModelProfile[],
  options: {
    runId?: string
    signal?: AbortSignal
    secrets?: readonly NamedSecret[]
    onUsage?: UsageCallback
    onTelemetry?: TelemetryCallback
    scenario?: string
  } = {},
): SemanticDedupeLlmCall {
  return async ({ systemPrompt, userPrompt }) => {
    const routed = resolveProfilePoolForRole('fast', profiles)
    const { models, model } = providerPool(
      routed,
      options.scenario ?? 'dedupe-judge',
      providerOptionsFor(options.runId, 'fast', 'dedupe-judge', {
        profile: routed[0],
        signal: options.signal,
        secrets: options.secrets,
        onUsage: options.onUsage,
        onTelemetry: options.onTelemetry,
        maxCalls: 2,
        thinkingLevel: 'off',
      }),
    )
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
