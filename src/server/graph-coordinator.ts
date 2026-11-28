/**
 * Graph Coordinator — typed chain-hop artifacts, dispatch-plan validation, and the deterministic
 * scheduler guard shared by the World Graph + single-turn LLM planner path
 * (`world-graph.ts` + `llm-planner.ts`).
 *
 * Pure and deterministic: identical inputs produce identical output. Dispatch never performs
 * HTTP — it validates and normalises hypotheses into a plan for Layer 1. Chain hops never carry
 * raw credentials: secrets are represented by `secret:<factId>` or opaque handles.
 */
import type { HopCheckpointBrief } from './frontier-scheduler.ts'


// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------

export type CoordinatorCapability = 'http' | 'browser' | 'oob' | 'race' | 'http2' | 'sast'
export const COORDINATOR_CAPABILITIES: readonly CoordinatorCapability[] = ['http', 'browser', 'oob', 'race', 'http2', 'sast']

/** Minimal projections: store rows and Program Graph data are structurally assignable. */
export interface CoordinatorEndpoint {
  id: string
  origin: string
  method: string
  pathTemplate: string
  source?: string
  authRequirement?: string | null
  ownershipGuard?: string | null
  sinkKinds?: readonly string[]
  testedClasses?: readonly string[]
  coveragePct?: number | null
  riskScore?: number
  roleExclusive?: boolean
  codeLocation?: unknown
}

export interface CoordinatorFact {
  id: string
  origin: string
  kind: string
  summary: string
  data?: Record<string, unknown>
  evidenceIds?: readonly string[]
  exchangeIds?: readonly string[]
  tainted?: boolean
  coldSinceRound?: number | null
  digestId?: string | null
  createdAt?: number
}

export interface CoordinatorFinding {
  id: string
  origin: string
  title: string
  status: string
  severity: string
  reason?: string
  category?: string
  cwe?: string
  confidence?: string
  verification?: string
  runtimeProofGap?: string | null
  findingKind?: string
  evidenceIds?: readonly string[]
  chainFactIds?: readonly string[]
  exchangeIds?: readonly string[]
  /** Adapter hint: the finding is waiting on a durable OOB subscription. */
  pendingOob?: boolean
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

const ROLE_PATH_RE = /\/(?:admin|internal|manage|management|backoffice|staff|console|superuser|root|settings\/roles)(?:\/|$)/i
const ROLE_AUTH_RE = /\b(?:admin|role|rbac|superuser|staff|privileged|tenant[-_ ]?admin)\b/i

function isRoleExclusive(endpoint: CoordinatorEndpoint): boolean {
  return endpoint.roleExclusive === true || ROLE_PATH_RE.test(endpoint.pathTemplate) || ROLE_AUTH_RE.test(endpoint.authRequirement ?? '')
}

// ---------------------------------------------------------------------------
// Shared value helpers
// ---------------------------------------------------------------------------

const str = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null
const num = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) ? value : null
const truncate = (value: string, max: number): string => value.length <= max ? value : `${value.slice(0, max - 1)}…`

function factRound(fact: CoordinatorFact): number | null {
  const data = fact.data ?? {}
  return num(data.roundNo) ?? num(data.round) ?? num(data.plannerRound) ?? num(data.discoveredRound)
}

const PENDING_OOB_RE = /pending[_\s-]?oob|awaiting[_\s-]?(?:oob|callback)/i

/** True when a pending/inconclusive finding is parked on a durable OOB subscription. */
export function isPendingOobFinding(finding: CoordinatorFinding): boolean {
  if (finding.status !== 'pending' && finding.status !== 'inconclusive') return false
  return finding.pendingOob === true
    || PENDING_OOB_RE.test(`${finding.runtimeProofGap ?? ''} ${finding.verification ?? ''} ${finding.reason ?? ''}`)
}

const hostOf = (origin: string): string => origin.replace(/^https?:\/\//, '')

function parseRouteTarget(rawRoute: unknown): { method?: string; endpoint?: string } {
  if (typeof rawRoute !== 'string' || !rawRoute.trim()) return {}
  const trimmed = rawRoute.trim()
  const parts = trimmed.split(/\s+/, 2)
  if (parts.length === 2 && /^[A-Z]+$/i.test(parts[0]!)) {
    return { method: parts[0]!.toUpperCase(), endpoint: parts[1]! }
  }
  return { endpoint: trimmed }
}


// ---------------------------------------------------------------------------
// Chain primitives & typed multi-round ChainHop artifacts (v7 M2)
// ---------------------------------------------------------------------------

type ChainPrimitiveKind =
  | 'leaked_token'
  | 'discovered_id'
  | 'ssrf_internal_reach'
  | 'stored_write'
  | 'weak_jwt'
  | 'admin_route'
  | 'role_transition'
  | 'workflow_state_handle'

export type ChainHopArtifactKind =
  | 'token_ref'
  | 'leaked_id'
  | 'ssrf_redirect_target'
  | 'role_transition'
  | 'workflow_state_handle'
  | 'stored_write_handle'

/**
 * Typed, deterministic chain-hop artifact persisted across coordinator rounds.
 * Never carries raw credentials or secrets: credential material is always represented as an
 * opaque non-secret handle (`secret:<factId>`, `jwt:<factId>`, `finding:<id>`).
 */
export interface ChainHop {
  hopId: string
  roundNo: number
  hopIndex: number
  artifactKind: ChainHopArtifactKind
  /** Non-secret typed handle usable by follow-on round briefs without prompt soup. */
  artifactRef: string
  origin: string
  endpoint?: string
  method?: string
  persona?: string | null
  targetPersona?: string | null
  stateBefore?: string | null
  stateAfter?: string | null
  verified: boolean
  evidenceIds: string[]
  factIds: string[]
  parentHopId?: string | null
  summary: string
}

interface ChainPrimitive {
  kind: ChainPrimitiveKind
  origin: string
  /** Non-secret identity; never a raw credential. */
  value: string
  /** Evidence/fact/endpoint anchors usable as `parentEvidenceIds`. */
  evidenceIds: string[]
  factIds: string[]
  endpointId?: string
  endpoint?: string
  method?: string
  persona?: string | null
  detail: string
}

const PRIMITIVE_RANK: Record<ChainPrimitiveKind, number> = {
  leaked_token: 0,
  weak_jwt: 1,
  discovered_id: 2,
  ssrf_internal_reach: 3,
  stored_write: 4,
  admin_route: 5,
  role_transition: 6,
  workflow_state_handle: 7,
}

const HOP_ARTIFACT_RANK: Record<ChainHopArtifactKind, number> = {
  token_ref: 0,
  leaked_id: 1,
  ssrf_redirect_target: 2,
  role_transition: 3,
  workflow_state_handle: 4,
  stored_write_handle: 5,
}

interface ChainHopSourceInput {
  facts?: readonly CoordinatorFact[]
  findings?: readonly CoordinatorFinding[]
  endpoints?: readonly CoordinatorEndpoint[]
}

const dedupe = (values: readonly string[]): string[] => [...new Set(values.filter(value => typeof value === 'string' && value.length > 0))]
const matches = (text: string, patterns: readonly RegExp[]): boolean => patterns.some(pattern => pattern.test(text))

const RAW_SECRET_REF_RE = /^(?:bearer\s+)?eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$|^(?:sk|pk|ghp|gho|ghs|ghu|ghr|xox[baprs]|AKIA|ASIA)[_-]?[A-Za-z0-9_-]{8,}$/i

function safeArtifactRef(raw: string, fallback: string, artifactKind: ChainHopArtifactKind): string {
  if (artifactKind === 'token_ref') return fallback
  const trimmed = raw.trim()
  if (!trimmed || trimmed === '[redacted]' || RAW_SECRET_REF_RE.test(trimmed)) return fallback
  return truncate(trimmed, 96)
}

function primitiveKindToHopArtifactKind(kind: ChainPrimitiveKind): ChainHopArtifactKind {
  switch (kind) {
    case 'leaked_token':
    case 'weak_jwt':
      return 'token_ref'
    case 'discovered_id':
      return 'leaked_id'
    case 'ssrf_internal_reach':
      return 'ssrf_redirect_target'
    case 'role_transition':
    case 'admin_route':
      return 'role_transition'
    case 'workflow_state_handle':
      return 'workflow_state_handle'
    case 'stored_write':
      return 'stored_write_handle'
  }
}

/** Derive typed chain primitives from one untainted fact (secrets stay opaque `secret:<factId>` handles). */
function pushFactPrimitives(fact: CoordinatorFact, out: ChainPrimitive[]): void {
  if (fact.tainted) return
  const data = fact.data ?? {}
  const subkind = str(data.subkind) ?? ''
  const probeClass = str(data.probeClass) ?? ''
  const text = `${subkind} ${probeClass} ${str(data.kind) ?? ''} ${str(data.artifactKind) ?? ''}`.toLowerCase()
  const endpoint = str(data.endpoint) ?? str(data.path) ?? undefined
  const method = str(data.method)?.toUpperCase()
  const persona = str(data.persona) ?? str(data.personaHandle) ?? str(data.ownerPersona)
  const base = {
    origin: fact.origin, evidenceIds: dedupe([fact.id, ...(fact.evidenceIds ?? [])]), factIds: [fact.id],
    ...(endpoint ? { endpoint } : {}), ...(method ? { method } : {}), ...(persona ? { persona } : {}),
  }
  const resourceId = str(data.resourceId) ?? (typeof data.resourceId === 'number' ? String(data.resourceId) : null)
    ?? str(data.id) ?? (typeof data.id === 'number' ? String(data.id) : null)
  const anomalies = Array.isArray(data.anomalies) ? data.anomalies : []
  const anomalyTypes = anomalies
    .map(anomaly => anomaly && typeof anomaly === 'object' ? str((anomaly as { type?: unknown }).type) ?? '' : '')
    .filter(Boolean).join(' ').toLowerCase()
  const ssrfText = `${text} ${anomalyTypes} ${str(data.internalTarget) ?? ''} ${str(data.redirectTarget) ?? ''}`

  // Rehydrate persisted typed chain_hop facts cleanly onto their primitive kinds, preserving
  // original factIds/evidenceIds and canonical artifactRef so they dedupe with source facts.
  if (subkind === 'chain_hop' || data.kind === 'chain_hop') {
    const hop = (data.hop && typeof data.hop === 'object' ? data.hop : data) as Record<string, unknown>
    const artifactKind = str(hop.artifactKind) as ChainHopArtifactKind | null
    const hopEndpoint = str(hop.endpoint) ?? endpoint
    const hopMethod = str(hop.method)?.toUpperCase() ?? method
    const hopPersona = str(hop.persona) ?? persona
    const hopRef = str(hop.artifactRef) ?? `hop:${fact.id}`
    const origFactIds = Array.isArray(hop.factIds) ? hop.factIds.map(str).filter((v): v is string => v !== null) : []
    const origEvidenceIds = Array.isArray(hop.evidenceIds) ? hop.evidenceIds.map(str).filter((v): v is string => v !== null) : []
    const hopBase = {
      ...base,
      evidenceIds: dedupe([...origEvidenceIds, fact.id, ...(fact.evidenceIds ?? [])]),
      factIds: dedupe([...origFactIds, fact.id]),
      ...(hopEndpoint ? { endpoint: hopEndpoint } : {}),
      ...(hopMethod ? { method: hopMethod } : {}),
      ...(hopPersona ? { persona: hopPersona } : {}),
    }
    if (artifactKind === 'token_ref') {
      const canonicalTokenRef = hopRef.startsWith('secret:') || hopRef.startsWith('jwt:') || hopRef.startsWith('finding:')
        ? hopRef
        : `secret:${origFactIds[0] ?? fact.id}`
      out.push({ ...hopBase, kind: 'leaked_token', value: canonicalTokenRef, detail: truncate(str(hop.summary) ?? 'Persisted token_ref chain hop (value withheld).', 160) })
    } else if (artifactKind === 'leaked_id') {
      out.push({ ...hopBase, kind: 'discovered_id', value: safeArtifactRef(hopRef, `id:${fact.id}`, 'leaked_id'), detail: truncate(str(hop.summary) ?? `Persisted leaked_id hop ${hopRef}.`, 160) })
    } else if (artifactKind === 'ssrf_redirect_target') {
      out.push({ ...hopBase, kind: 'ssrf_internal_reach', value: safeArtifactRef(hopRef, `ssrf:${hopEndpoint ?? fact.id}`, 'ssrf_redirect_target'), detail: truncate(str(hop.summary) ?? `Persisted SSRF/redirect hop at ${hopEndpoint ?? 'target'}.`, 160) })
    } else if (artifactKind === 'role_transition') {
      out.push({ ...hopBase, kind: 'role_transition', value: safeArtifactRef(hopRef, `role:${fact.id}`, 'role_transition'), detail: truncate(str(hop.summary) ?? 'Persisted role transition hop.', 160) })
    } else if (artifactKind === 'workflow_state_handle') {
      out.push({ ...hopBase, kind: 'workflow_state_handle', value: safeArtifactRef(hopRef, `workflow:${fact.id}`, 'workflow_state_handle'), detail: truncate(str(hop.summary) ?? 'Persisted workflow state handle hop.', 160) })
    } else if (artifactKind === 'stored_write_handle') {
      out.push({ ...hopBase, kind: 'stored_write', value: safeArtifactRef(hopRef, `stored:${fact.id}`, 'stored_write_handle'), detail: truncate(str(hop.summary) ?? 'Persisted stored write hop.', 160) })
    }
    return
  }

  if (fact.kind === 'secret' || matches(text, [/leak(?:ed)?[_-]?token/, /token[_-]?leak/, /credential[_-]?leak/, /secret[_-]?exposure/, /api[_-]?key[_-]?(?:exposed|leak)/])) {
    out.push({ ...base, kind: 'leaked_token', value: `secret:${fact.id}`, detail: 'Leaked credential material recorded as a secret fact (value withheld).' })
  }
  if ((fact.kind === 'object_ref' || subkind === 'persona_resource') && resourceId && resourceId !== '[redacted]') {
    out.push({ ...base, kind: 'discovered_id', value: resourceId, detail: `Discovered object identifier ${truncate(resourceId, 48)}${endpoint ? ` at ${endpoint}` : ''}.` })
  }
  if (matches(ssrfText, [/ssrf/, /internal[_-]?(?:reach|fetch|target)/, /oob[_-]?(?:callback|hit)/, /open[_-]?redirect/, /redirect[_-]?target/]) || probeClass.toLowerCase().startsWith('ssrf')) {
    const targetRef = str(data.redirectTarget) ?? str(data.internalTarget) ?? endpoint ?? fact.id
    out.push({ ...base, kind: 'ssrf_internal_reach', value: `ssrf:${truncate(targetRef, 64)}`, detail: `Server-side fetch or redirect pivot reached ${truncate(targetRef, 64)} via ${endpoint ?? 'a recorded sink'}.` })
  }
  if (subkind === 'second_order_surface' || matches(text, [/stored[_-]?(?:xss|write)/, /persistent[_-]?xss/, /second[_-]?order/])) {
    out.push({ ...base, kind: 'stored_write', value: `stored:${str(data.marker) ?? str(data.canaryId) ?? endpoint ?? fact.id}`, detail: `Stateful write persisted and resurfaced${endpoint ? ` at ${endpoint}` : ''}.` })
  }
  if (matches(text, [/jwt/, /jwk/, /alg[_-]?none/, /weak[_-]?(?:jwt|secret)/, /token[_-]?algorithm/])) {
    out.push({ ...base, kind: 'weak_jwt', value: `jwt:${fact.id}`, detail: 'JWT/session weakness recorded (claims and signatures withheld).' })
  }
  if (matches(text, [/admin[_-]?route/, /role[_-]?exclusive/, /privileged[_-]?route/, /auth[_-]?bypass/]) || data.roleExclusive === true) {
    out.push({ ...base, kind: 'admin_route', value: `admin:${endpoint ?? fact.id}`, detail: `Privileged route primitive recorded${endpoint ? ` at ${endpoint}` : ''}.` })
  }
  if (matches(text, [/role[_-]?(?:transition|change|escalat|grant|demot|revok)/, /stale[_-]?privilege/, /impersonat/, /self[_-]?approv/, /invite[_-]?(?:accept|redeem)/, /tenant[_-]?confusion/]) || str(data.roleAfter)) {
    const transition = str(data.roleAfter) ? `${str(data.roleBefore) ?? persona ?? 'member'}->${str(data.roleAfter)}` : (endpoint ?? fact.id)
    out.push({ ...base, kind: 'role_transition', value: `role:${truncate(transition, 64)}`, detail: `Role/privilege transition observed (${truncate(transition, 64)})${endpoint ? ` at ${endpoint}` : ''}.` })
  }
  if (matches(text, [/workflow[_-]?(?:state|handle|transition|bypass)/, /approval[_-]?(?:id|handle|pending)/, /checkout[_-]?(?:state|handle)/, /payout[_-]?handle/, /pipeline[_-]?(?:run|handle)/, /signed[_-]?url/]) || str(data.workflowHandle) || str(data.stateHandle)) {
    const handle = str(data.workflowHandle) ?? str(data.stateHandle) ?? resourceId ?? endpoint ?? fact.id
    out.push({ ...base, kind: 'workflow_state_handle', value: `workflow:${truncate(handle, 64)}`, detail: `Workflow state handle ${truncate(handle, 48)}${str(data.stateAfter) ? ` (state=${str(data.stateAfter)})` : ''}${endpoint ? ` at ${endpoint}` : ''}.` })
  }
  if (fact.kind === 'code_audit_suspect' || subkind === 'code_audit_suspect') {
    const routeOrAction = str(data.routeOrAction) ?? endpoint
    const parsedRoute = parseRouteTarget(routeOrAction)
    const suspectEndpoint = parsedRoute.endpoint ?? endpoint
    const suspectMethod = parsedRoute.method ?? method
    const sinkKind = (str(data.sinkKind) ?? '').toLowerCase()
    const suspectText = `${sinkKind} ${fact.summary} ${str(data.hypothesis) ?? ''} ${routeOrAction ?? ''}`.toLowerCase()
    const suspectKind: ChainPrimitiveKind =
      sinkKind === 'outbound_fetch' || sinkKind === 'redirect' || /\b(?:ssrf|outbound[- ]?fetch|redirect|proxy|render)\b/.test(suspectText)
        ? 'ssrf_internal_reach'
        : sinkKind === 'webhook' || /\b(?:webhook|hmac|signing[- ]?(?:key|secret|salt)|jwt|jwks)\b/.test(suspectText)
          ? 'leaked_token'
          : sinkKind === 'auth_config' || /\b(?:invite|session|oauth|oidc|impersonat|role[- ]?grant|x-forwarded)\b/.test(suspectText)
            ? 'role_transition'
            : /\b(?:export|async|job|queue|settlement|approve|transfer|payout|cache|race|concurren)\b/.test(suspectText)
              ? 'workflow_state_handle'
              : /\b(?:admin|privileged|bfla|missing\s+authz?)\b/.test(suspectText)
                ? 'admin_route'
                : 'discovered_id'
    out.push({
      ...base,
      ...(suspectEndpoint ? { endpoint: suspectEndpoint } : {}),
      ...(suspectMethod ? { method: suspectMethod } : {}),
      kind: suspectKind,
      value: `suspect:${fact.id}`,
      detail: truncate(`Code-audit suspect (${sinkKind || 'sink'}${suspectEndpoint ? ` ${suspectEndpoint}` : ''}): ${fact.summary}`, 160),
    })
  }
}

/** Derive typed chain primitives from one runtime-confirmed finding. */
function pushFindingPrimitives(finding: CoordinatorFinding, out: ChainPrimitive[]): void {
  if (finding.status !== 'confirmed') return
  const text = `${finding.title} ${finding.category ?? ''} ${finding.cwe ?? ''}`.toLowerCase()
  const base = {
    origin: finding.origin, evidenceIds: dedupe([finding.id, ...(finding.evidenceIds ?? []), ...(finding.chainFactIds ?? [])]), factIds: [] as string[],
  }
  const claim = truncate(finding.title, 120)
  if (/leak|expos/.test(text) && /token|credential|secret|api[_-]?key/.test(text)) {
    out.push({ ...base, kind: 'leaked_token', value: `finding:${finding.id}`, detail: 'Confirmed finding reports credential exposure (value withheld).' })
  }
  if (matches(text, [/jwt/, /json web token/, /alg(?:orithm)?[ -]?none/, /weak[ -]?secret/])) {
    out.push({ ...base, kind: 'weak_jwt', value: `finding:${finding.id}`, detail: `Confirmed JWT/session weakness (${claim}).` })
  }
  if (matches(text, [/ssrf/, /server[ -]?side request/, /internal (?:reach|metadata|network)/, /open[ -]?redirect/])) {
    out.push({ ...base, kind: 'ssrf_internal_reach', value: `finding:${finding.id}`, detail: `Confirmed server-side request/redirect reach (${claim}).` })
  }
  if (/stored|persistent|second[ -]?order/.test(text) && /xss|write|inject/.test(text)) {
    out.push({ ...base, kind: 'stored_write', value: `finding:${finding.id}`, detail: `Confirmed persisted write primitive (${claim}).` })
  }
  if (matches(text, [/admin/, /privileged/, /bfla/, /role escalation/])) {
    out.push({ ...base, kind: 'admin_route', value: `finding:${finding.id}`, detail: `Confirmed privileged-surface primitive (${claim}).` })
  }
  if (matches(text, [/idor/, /bola/, /object reference/, /tenant isolation/])) {
    out.push({ ...base, kind: 'discovered_id', value: `finding:${finding.id}`, detail: `Confirmed cross-object access primitive (${claim}).` })
  }
  if (matches(text, [/role escalation/, /privilege escalation/, /revok/, /demot/, /self[ -]?approv/, /impersonat/, /sso.*tenant/])) {
    out.push({ ...base, kind: 'role_transition', value: `finding:${finding.id}`, detail: `Confirmed role/privilege transition (${claim}).` })
  }
  if (matches(text, [/workflow/, /state[ -]?machine/, /approval[ -]?bypass/, /checkout/, /payout/, /race[ -]?condition/, /double[ -]?spend/])) {
    out.push({ ...base, kind: 'workflow_state_handle', value: `finding:${finding.id}`, detail: `Confirmed workflow state primitive (${claim}).` })
  }
}

/** Typed, deduplicated chain primitives from untainted facts, confirmed findings and role-exclusive endpoints. */
function collectChainPrimitives(input: ChainHopSourceInput): ChainPrimitive[] {
  const out: ChainPrimitive[] = []
  for (const fact of input.facts ?? []) pushFactPrimitives(fact, out)
  for (const finding of input.findings ?? []) pushFindingPrimitives(finding, out)
  for (const endpoint of input.endpoints ?? []) {
    if (!isRoleExclusive(endpoint)) continue
    out.push({
      kind: 'admin_route', origin: endpoint.origin, value: `admin:${endpoint.method.toUpperCase()} ${endpoint.pathTemplate}`,
      evidenceIds: [endpoint.id], factIds: [], endpointId: endpoint.id, endpoint: endpoint.pathTemplate,
      method: endpoint.method.toUpperCase(), detail: `Role-exclusive endpoint ${endpoint.method.toUpperCase()} ${endpoint.pathTemplate}.`,
    })
  }

  const unique = new Map<string, ChainPrimitive>()
  for (const primitive of out) {
    const key = `${primitive.kind}\u0000${primitive.origin}\u0000${primitive.value}`
    if (!unique.has(key)) unique.set(key, primitive)
  }
  return [...unique.values()].sort((a, b) =>
    PRIMITIVE_RANK[a.kind] - PRIMITIVE_RANK[b.kind]
    || (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0)
    || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0))
}

/**
 * Extract typed, non-secret `ChainHop` artifacts from untainted facts (including persisted
 * `chain_hop` facts from earlier coordinator rounds), confirmed findings, and endpoints.
 */
export function extractChainHops(
  input: ChainHopSourceInput & { roundNo?: number; priorHops?: readonly ChainHop[] },
): ChainHop[] {
  const defaultRound = Math.max(1, Math.floor(input.roundNo ?? 1))
  const byKey = new Map<string, ChainHop>()
  const upsert = (hop: ChainHop): void => {
    const key = `${hop.artifactKind}\u0000${hop.origin}\u0000${hop.artifactRef}`
    const existing = byKey.get(key)
    if (!existing) {
      byKey.set(key, { ...hop, evidenceIds: dedupe(hop.evidenceIds), factIds: dedupe(hop.factIds) })
      return
    }
    byKey.set(key, {
      ...existing,
      roundNo: Math.min(existing.roundNo, hop.roundNo),
      verified: existing.verified || hop.verified,
      evidenceIds: dedupe([...existing.evidenceIds, ...hop.evidenceIds]),
      factIds: dedupe([...existing.factIds, ...hop.factIds]),
      ...(!existing.endpoint && hop.endpoint ? { endpoint: hop.endpoint } : {}),
      ...(!existing.method && hop.method ? { method: hop.method } : {}),
      ...(!existing.persona && hop.persona ? { persona: hop.persona } : {}),
      ...(!existing.targetPersona && hop.targetPersona ? { targetPersona: hop.targetPersona } : {}),
      ...(!existing.stateBefore && hop.stateBefore ? { stateBefore: hop.stateBefore } : {}),
      ...(!existing.stateAfter && hop.stateAfter ? { stateAfter: hop.stateAfter } : {}),
      ...(!existing.parentHopId && hop.parentHopId ? { parentHopId: hop.parentHopId } : {}),
    })
  }

  for (const prior of input.priorHops ?? []) {
    upsert({
      ...prior,
      artifactRef: safeArtifactRef(prior.artifactRef, `secret:${prior.hopId}`, prior.artifactKind),
    })
  }

  // Rehydrate persisted chain_hop facts directly so round/parentHopId/state metadata survives intact.
  for (const fact of input.facts ?? []) {
    if (fact.tainted) continue
    const data = fact.data ?? {}
    if (data.subkind !== 'chain_hop' && data.kind !== 'chain_hop') continue
    const raw = (data.hop && typeof data.hop === 'object' ? data.hop : data) as Record<string, unknown>
    const artifactKind = str(raw.artifactKind) as ChainHopArtifactKind | null
    if (!artifactKind || !(artifactKind in HOP_ARTIFACT_RANK)) continue
    const roundNo = num(raw.roundNo) ?? factRound(fact) ?? defaultRound
    const hopId = str(raw.hopId) ?? `hop:${artifactKind}:${fact.id}`
    const fallbackRef = artifactKind === 'token_ref' ? `secret:${fact.id}` : `${artifactKind}:${fact.id}`
    const artifactRef = safeArtifactRef(str(raw.artifactRef) ?? fallbackRef, fallbackRef, artifactKind)
    upsert({
      hopId,
      roundNo: Math.max(1, Math.floor(roundNo)),
      hopIndex: Math.max(0, Math.floor(num(raw.hopIndex) ?? 0)),
      artifactKind,
      artifactRef,
      origin: fact.origin,
      ...(str(raw.endpoint) ? { endpoint: str(raw.endpoint)! } : {}),
      ...(str(raw.method) ? { method: str(raw.method)!.toUpperCase() } : {}),
      ...(str(raw.persona) ? { persona: str(raw.persona) } : {}),
      ...(str(raw.targetPersona) ? { targetPersona: str(raw.targetPersona) } : {}),
      ...(str(raw.stateBefore) ? { stateBefore: str(raw.stateBefore) } : {}),
      ...(str(raw.stateAfter) ? { stateAfter: str(raw.stateAfter) } : {}),
      verified: raw.verified === true,
      evidenceIds: dedupe([fact.id, ...(fact.evidenceIds ?? []), ...(Array.isArray(raw.evidenceIds) ? raw.evidenceIds.map(String) : [])]),
      factIds: dedupe([fact.id, ...(Array.isArray(raw.factIds) ? raw.factIds.map(String) : [])]),
      ...(str(raw.parentHopId) ? { parentHopId: str(raw.parentHopId) } : {}),
      summary: truncate(str(raw.summary) ?? fact.summary, 160),
    })
  }

  // Synthesize typed ChainHops from all derived primitives (facts, confirmed findings, endpoints).
  const confirmedFindingIds = new Set((input.findings ?? []).filter(f => f.status === 'confirmed').map(f => f.id))
  const factById = new Map((input.facts ?? []).map(f => [f.id, f]))
  const primitives = collectChainPrimitives(input)
  primitives.forEach((primitive, idx) => {
    const artifactKind = primitiveKindToHopArtifactKind(primitive.kind)
    const primaryFact = primitive.factIds.length ? factById.get(primitive.factIds[0]) : undefined
    const factData = primaryFact?.data ?? {}
    const verified = primitive.evidenceIds.some(id => confirmedFindingIds.has(id)) || factData.verified === true
    const roundNo = (primaryFact ? factRound(primaryFact) : null) ?? defaultRound
    const fallbackRef = artifactKind === 'token_ref'
      ? (primitive.value.startsWith('secret:') || primitive.value.startsWith('jwt:') || primitive.value.startsWith('finding:') ? primitive.value : `secret:${primitive.factIds[0] ?? idx}`)
      : primitive.value
    const artifactRef = safeArtifactRef(primitive.value, fallbackRef, artifactKind)
    const stateBefore = str(factData.stateBefore) ?? str(factData.roleBefore)
    const stateAfter = str(factData.stateAfter) ?? str(factData.roleAfter)
    const targetPersona = str(factData.targetPersona) ?? str(factData.surfacedPersona)
    upsert({
      hopId: `hop:${artifactKind}:${hostOf(primitive.origin)}:${artifactRef.replace(/[^A-Za-z0-9:._-]/g, '_').slice(0, 48)}`,
      roundNo: Math.max(1, Math.floor(roundNo)),
      hopIndex: idx,
      artifactKind,
      artifactRef,
      origin: primitive.origin,
      ...(primitive.endpoint ? { endpoint: primitive.endpoint } : {}),
      ...(primitive.method ? { method: primitive.method } : {}),
      ...(primitive.persona ? { persona: primitive.persona } : {}),
      ...(targetPersona ? { targetPersona } : {}),
      ...(stateBefore ? { stateBefore } : {}),
      ...(stateAfter ? { stateAfter } : {}),
      verified,
      evidenceIds: primitive.evidenceIds,
      factIds: primitive.factIds,
      ...(str(factData.parentHopId) ? { parentHopId: str(factData.parentHopId) } : {}),
      summary: truncate(primitive.detail, 160),
    })
  })

  return [...byKey.values()]
    .sort((a, b) =>
      a.roundNo - b.roundNo
      || Number(b.verified) - Number(a.verified)
      || HOP_ARTIFACT_RANK[a.artifactKind] - HOP_ARTIFACT_RANK[b.artifactKind]
      || (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0)
      || (a.artifactRef < b.artifactRef ? -1 : a.artifactRef > b.artifactRef ? 1 : 0))
    .map((hop, index) => ({ ...hop, hopIndex: index }))
}

/**
 * Compact, deterministic JSON encoding of typed `ChainHop` inputs for follow-on round briefs.
 * Strictly bounded by `maxBytes` and guaranteed free of raw credentials.
 */
export function formatChainHopsBrief(hops: readonly ChainHop[], maxBytes = 640): string {
  const cap = Math.max(128, Math.floor(maxBytes))
  const compact = hops.map(hop => ({
    hop: hop.hopIndex + 1,
    r: hop.roundNo,
    kind: hop.artifactKind,
    ref: safeArtifactRef(hop.artifactRef, `secret:${hop.hopId}`, hop.artifactKind),
    ...(hop.method && hop.endpoint ? { at: `${hop.method} ${truncate(hop.endpoint, 80)}` } : hop.endpoint ? { at: truncate(hop.endpoint, 80) } : {}),
    ...(hop.persona ? { actor: truncate(hop.persona, 32) } : {}),
    ...(hop.targetPersona ? { target: truncate(hop.targetPersona, 32) } : {}),
    ...(hop.stateBefore || hop.stateAfter ? { state: `${hop.stateBefore ?? '*'}->${hop.stateAfter ?? '*'}` } : {}),
    v: hop.verified ? 1 : 0,
  }))
  for (let count = compact.length; count >= 1; count -= 1) {
    const text = JSON.stringify(compact.slice(0, count))
    if (Buffer.byteLength(text, 'utf8') <= cap) return text
  }
  return '[]'
}

// ---------------------------------------------------------------------------
// Dispatch plan validation (no HTTP)
// ---------------------------------------------------------------------------

export interface DispatchStepInput {
  hypothesis: string
  origin?: string
  origins?: readonly string[]
  capabilities?: readonly string[]
  parentEvidenceIds?: readonly string[]
  budgetUsd?: number
  probeClass?: string
  expectedSignal?: string
  skills?: readonly string[]
  priority?: number
  /** Optional typed multi-round hop artifacts feeding follow-on briefs without prompt soup. */
  chainHops?: readonly ChainHop[]
  /** Optional v8 bounded (<= 2 KB) pre-hydrated hop-checkpoint brief for depth >= 2 assignments. */
  checkpointCapId?: string
  checkpointBrief?: HopCheckpointBrief
  checkpointJson?: string
}

export interface DispatchOptions {
  budgetUsd?: number
  approvedOrigins?: readonly string[]
  maxSteps?: number
  allowedCapabilities?: readonly CoordinatorCapability[]
  /** Default true. Hop continuations opt out: their lineage is pinned via `dependsOnStepIds`. */
  requireParentEvidence?: boolean
}

export interface NormalizedDispatchStep {
  id: string
  hypothesis: string
  origins: string[]
  capabilities: CoordinatorCapability[]
  parentEvidenceIds: string[]
  budgetUsd: number
  probeClass?: string
  expectedSignal?: string
  skills: string[]
  priority: number
  chainHops?: ChainHop[]
  checkpointCapId?: string
  checkpointBrief?: HopCheckpointBrief
  checkpointJson?: string
}

export type DispatchRejectionCode =
  | 'empty_hypothesis' | 'missing_origin' | 'invalid_origin' | 'origin_not_approved'
  | 'missing_parent_evidence' | 'unknown_capability' | 'invalid_budget' | 'overspend'
  | 'duplicate_step' | 'step_limit'

export interface DispatchRejection {
  index: number
  code: DispatchRejectionCode
  reason: string
}

export interface DispatchPlan {
  /** Always false: the coordinator never sends HTTP; callers execute the plan via Layer 1. */
  dispatched: false
  plan: NormalizedDispatchStep[]
  rejected: DispatchRejection[]
  totalBudgetUsd: number
  budgetUsd: number | null
  parentEvidenceIds: string[]
}

function normalizeOrigin(value: string): string | null {
  try {
    const url = new URL(value.trim())
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : null
  } catch {
    return null
  }
}

function normalizeCapabilities(capabilities: readonly string[] | undefined, allowed: ReadonlySet<string>): { values: CoordinatorCapability[]; unknown: string[] } {
  const values = new Set<CoordinatorCapability>()
  const unknown: string[] = []
  for (const raw of capabilities ?? []) {
    const capability = raw.trim().toLowerCase()
    if (!capability) continue
    if (!allowed.has(capability)) unknown.push(capability)
    else values.add(capability as CoordinatorCapability)
  }
  return { values: COORDINATOR_CAPABILITIES.filter(capability => values.has(capability)), unknown }
}

/** Validate and normalise investigation hypotheses into a deterministic plan without I/O. */
export function dispatchInvestigations(steps: readonly DispatchStepInput[], options: DispatchOptions = {}): DispatchPlan {
  const allowed = new Set<string>(options.allowedCapabilities ?? COORDINATOR_CAPABILITIES)
  const approved = options.approvedOrigins?.length
    ? new Set(options.approvedOrigins.map(origin => normalizeOrigin(origin) ?? origin))
    : null
  const maxSteps = Math.max(1, Math.floor(options.maxSteps ?? Number.POSITIVE_INFINITY))
  const budgetCap = options.budgetUsd !== undefined && Number.isFinite(options.budgetUsd) && options.budgetUsd >= 0 ? options.budgetUsd : null
  const plan: NormalizedDispatchStep[] = []
  const rejected: DispatchRejection[] = []
  const seen = new Set<string>()
  let totalBudgetUsd = 0

  steps.forEach((step, index) => {
    const reject = (code: DispatchRejectionCode, reason: string): void => { rejected.push({ index, code, reason }) }
    if (plan.length >= maxSteps) return reject('step_limit', `Dispatch plan already reached the ${maxSteps}-step limit.`)
    const hypothesis = (step.hypothesis ?? '').trim()
    if (!hypothesis) return reject('empty_hypothesis', 'Hypothesis text is required.')
    const rawOrigins = [...(step.origins ?? []), ...(step.origin ? [step.origin] : [])]
    if (!rawOrigins.length) return reject('missing_origin', 'At least one target origin is required.')
    const origins: string[] = []
    for (const raw of rawOrigins) {
      const origin = normalizeOrigin(raw)
      if (!origin) return reject('invalid_origin', `Origin is not a valid http(s) origin: ${raw}`)
      if (approved && !approved.has(origin)) return reject('origin_not_approved', `Origin is outside approved scope: ${origin}`)
      if (!origins.includes(origin)) origins.push(origin)
    }
    const parentEvidenceIds = dedupe((step.parentEvidenceIds ?? []).map(value => String(value).trim()))
    if (!parentEvidenceIds.length && options.requireParentEvidence !== false) return reject('missing_parent_evidence', 'Hypothesis must cite at least one parent evidence id.')
    const capabilities = normalizeCapabilities(step.capabilities, allowed)
    if (capabilities.unknown.length) return reject('unknown_capability', `Unknown capability: ${capabilities.unknown.join(', ')}`)
    const stepBudget = step.budgetUsd ?? 0
    if (!Number.isFinite(stepBudget) || stepBudget < 0) return reject('invalid_budget', `Budget must be a non-negative number, received ${String(step.budgetUsd)}`)
    if (budgetCap !== null && totalBudgetUsd + stepBudget > budgetCap + 1e-9) {
      return reject('overspend', `Step budget $${stepBudget} would exceed remaining $${Math.max(0, budgetCap - totalBudgetUsd)}.`)
    }
    const duplicateKey = `${hypothesis.toLowerCase()}\u0000${origins.join(',')}`
    if (seen.has(duplicateKey)) return reject('duplicate_step', 'Duplicate hypothesis/origin pair.')
    seen.add(duplicateKey)
    totalBudgetUsd += stepBudget
      const derivedCapId = step.checkpointCapId?.trim()
        || step.checkpointBrief?.capabilityHandles[step.checkpointBrief.capabilityHandles.length - 1]
        || step.checkpointBrief?.verifiedHops[step.checkpointBrief.verifiedHops.length - 1]?.capId
      plan.push({
      id: `dispatch-${plan.length + 1}`,
      hypothesis, origins, capabilities: capabilities.values, parentEvidenceIds,
      budgetUsd: stepBudget,
      ...(step.probeClass?.trim() ? { probeClass: step.probeClass.trim() } : {}),
      ...(step.expectedSignal?.trim() ? { expectedSignal: step.expectedSignal.trim() } : {}),
      skills: [...new Set((step.skills ?? []).map(skill => skill.trim()).filter(Boolean))].sort(),
      priority: Math.max(0, Math.min(100, Math.round(step.priority ?? 50))),
      ...(step.chainHops?.length
        ? {
            chainHops: step.chainHops.map(hop => ({
              ...hop,
              artifactRef: safeArtifactRef(hop.artifactRef, `secret:${hop.hopId}`, hop.artifactKind),
              evidenceIds: dedupe(hop.evidenceIds),
              factIds: dedupe(hop.factIds),
            })),
          }
        : {}),
      ...(derivedCapId ? { checkpointCapId: derivedCapId } : {}),
      ...(step.checkpointBrief ? { checkpointBrief: step.checkpointBrief } : {}),
      ...(step.checkpointJson ? { checkpointJson: step.checkpointJson } : {}),
    })
  })

  return {
    dispatched: false, plan, rejected,
    totalBudgetUsd: Math.round(totalBudgetUsd * 1e6) / 1e6,
    budgetUsd: budgetCap,
    parentEvidenceIds: dedupe(plan.flatMap(step => step.parentEvidenceIds)),
  }
}

// ---------------------------------------------------------------------------
// Deterministic scheduler guard (K=6 empty-round semantics owned here)
// ---------------------------------------------------------------------------

export const EMPTY_PLANNER_ROUND_LIMIT = 2

export type SchedulerStopReason = 'budget_exhausted' | 'requests_exhausted' | 'wallclock_exhausted' | 'diminishing_returns' | 'coordinator_done'

export interface SchedulerInput {
  budgetExhausted?: boolean
  /** Remaining request allowance; null/undefined means unlimited. */
  requestsLeft?: number | null
  /** Remaining wall-clock budget in milliseconds; null/undefined means unlimited. */
  wallClockLeft?: number | null
  consecutiveEmptyPlannerRounds?: number
  coordinatorDone?: boolean
  /** Durable OOB subscriptions still awaiting a callback; drain before reporting done. */
  pendingOob?: number
}

export interface SchedulerDecision {
  decision: 'continue' | 'stop'
  reason: SchedulerStopReason | 'continue'
  detail: string
}

/** Pure stop/continue guard: budget, requests, wall clock, empty-round cap and OOB drain. */
export function decideNext(input: SchedulerInput): SchedulerDecision {
  const stop = (reason: SchedulerStopReason, detail: string): SchedulerDecision => ({ decision: 'stop', reason, detail })
  if (input.budgetExhausted === true) return stop('budget_exhausted', 'Run budget is exhausted.')
  if (input.requestsLeft !== undefined && input.requestsLeft !== null && input.requestsLeft <= 0) return stop('requests_exhausted', 'No request allowance remains.')
  if (input.wallClockLeft !== undefined && input.wallClockLeft !== null && input.wallClockLeft <= 0) return stop('wallclock_exhausted', 'Wall-clock budget is exhausted.')
  const empty = input.consecutiveEmptyPlannerRounds ?? 0
  if (empty >= EMPTY_PLANNER_ROUND_LIMIT) return stop('diminishing_returns', `${empty} consecutive empty planner rounds (K=${EMPTY_PLANNER_ROUND_LIMIT}).`)
  const pending = input.pendingOob ?? 0
  if (input.coordinatorDone === true && pending === 0) return stop('coordinator_done', 'Coordinator finished and no OOB callbacks are pending.')
  return { decision: 'continue', reason: 'continue', detail: pending > 0 ? `Continuing while ${pending} OOB subscription(s) are pending.` : 'Planner may continue.' }
}

// ---------------------------------------------------------------------------
// Coordinator facade
// ---------------------------------------------------------------------------
