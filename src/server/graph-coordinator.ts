/**
 * Graph Coordinator — v6 Phase 4 / v8 M0-M3 causal coordinator core (plans/v8.md §2 & §5).
 *
 * Exposes five paginated read/dispatch tools, typed chain primitives, and causal multi-hop
 * frontier planning backed by `CapabilityLedger` + `FrontierScheduler` (depth 1..6, exact EVI
 * beam ranking, `capability_only` quarantine enforcement, negative-edge dead-end suppression,
 * and strictly bounded <= 2 KB hop-checkpoint briefs).
 *
 * Pure and deterministic: identical deps + arguments produce identical output. Dispatch never
 * performs HTTP — it validates and normalises hypotheses into a plan for Layer 1.
 * Chain primitives never carry raw credentials: secrets are represented by `secret:<factId>`
 * or opaque `cap:hop_<id>:<slot>` handles.
 */
import {
  ALWAYS_QUARANTINED_KINDS,
  CapabilityLedger,
  computeArtifactDigest,
  type CapabilityKind,
  type CapabilityNode,
  type CapabilitySurface,
  type CausalEdge,
  type CausalEdgeBindingKind,
} from './capability-ledger.ts'
import {
  FrontierScheduler,
  MAX_CHAIN_DEPTH,
  MAX_CHECKPOINT_BRIEF_BYTES,
  MIN_CHAIN_DEPTH,
  buildHopCheckpointBrief,
  clampBeamWidth,
  computeBranchEvi,
  computeNegativeEdgeKey,
  rankAndPruneBeam,
  type FrontierBranch,
  type FrontierTargetSurface,
  type HopCheckpointBrief,
  type NegativeEdgeRecord,
  type VerifiedHopHandle,
} from './frontier-scheduler.ts'

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

export interface CoordinatorProgramRoute {
  id: string
  method: string
  path: string
  file: string
  line: number
  handler: string
  input?: { params?: readonly string[]; query?: readonly string[]; body?: readonly string[] }
  middleware?: readonly string[]
  guards?: readonly string[]
}

export interface CoordinatorProgramGraph {
  repo?: string
  routes: readonly CoordinatorProgramRoute[]
  nodes: ReadonlyArray<{ id: string; kind: string; symbol: string; file: string; line: number; sinkKind?: string }>
  edges: ReadonlyArray<{ fromId: string; toId: string; file?: string; line?: number }>
  warnings?: readonly string[]
}

export interface CoordinatorCommitSignal {
  sha: string
  subject: string
  committedAt?: string
  file: string
  change: 'added' | 'removed' | 'modified'
  sinkKinds?: readonly string[]
  routeTouched?: boolean
  authMiddlewareTouched?: boolean
  securityRelevant?: boolean
  reasons?: readonly string[]
}

export interface CoordinatorApiDependency {
  id?: string
  producerEndpointId?: string
  consumerEndpointId?: string
  producer?: string
  consumer?: string
  producerOrigin?: string
  consumerOrigin?: string
  producerMethod?: string
  consumerMethod?: string
  resourceKey: string
  personaHandle?: string | null
  observedTransitions?: readonly string[]
  testedBola?: boolean
}

/** Complete, untruncated data access (adapters page the store past its default page size). */
export interface CoordinatorDeps {
  listEndpoints(): readonly CoordinatorEndpoint[]
  listFacts(): readonly CoordinatorFact[]
  listFindings(): readonly CoordinatorFinding[]
  listApiDependencies?(): readonly CoordinatorApiDependency[]
  programGraph?(): CoordinatorProgramGraph | null
  commitSignals?(): readonly CoordinatorCommitSignal[]
  approvedOrigins?(): readonly string[]
  /** Optional v8 run-scoped CapabilityLedger backing causal DAG planning & negative-edge pruning. */
  capabilityLedger?(): CapabilityLedger | null
  /** Optional v8 FrontierScheduler backing EVI beam ranking & wave progression. */
  frontierScheduler?(): FrontierScheduler | null
}

export class CoordinatorInputError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'CoordinatorInputError'
    this.code = code
  }
}

// ---------------------------------------------------------------------------
// Stable pagination
// ---------------------------------------------------------------------------

export const DEFAULT_PAGE_LIMIT = 50
export const MAX_PAGE_LIMIT = 500
const CURSOR_RE = /^v1:(\d+)$/

export interface CoordinatorPage<T> {
  items: T[]
  cursor: string | null
  nextCursor: string | null
  limit: number
  total: number
  returned: number
}

function decodeCursor(cursor?: string | null): number {
  if (!cursor) return 0
  const match = CURSOR_RE.exec(cursor)
  if (!match) throw new CoordinatorInputError('invalid_cursor', `Invalid pagination cursor: ${cursor}`)
  return Number(match[1])
}

function resolveLimit(limit: number | undefined, fallback = DEFAULT_PAGE_LIMIT): number {
  if (limit === undefined) return fallback
  if (!Number.isFinite(limit) || limit < 1) throw new CoordinatorInputError('invalid_limit', `limit must be a positive integer, received ${String(limit)}`)
  return Math.min(Math.floor(limit), MAX_PAGE_LIMIT)
}

function pageOf<T>(items: readonly T[], cursor: string | null | undefined, limit: number | undefined): CoordinatorPage<T> {
  const offset = decodeCursor(cursor)
  const size = resolveLimit(limit)
  const slice = items.slice(offset, offset + size)
  const next = offset + slice.length
  return {
    items: slice, cursor: offset === 0 ? null : `v1:${offset}`,
    nextCursor: next < items.length ? `v1:${next}` : null,
    limit: size, total: items.length, returned: slice.length,
  }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

const ROLE_PATH_RE = /\/(?:admin|internal|manage|management|backoffice|staff|console|superuser|root|settings\/roles)(?:\/|$)/i
const ROLE_AUTH_RE = /\b(?:admin|role|rbac|superuser|staff|privileged|tenant[-_ ]?admin)\b/i
const MISSING_AUTH_RE = /^(?:|none|public|unknown|anonymous|unauthenticated)$/i

export function isMissingAuthGuard(endpoint: CoordinatorEndpoint): boolean {
  return MISSING_AUTH_RE.test((endpoint.authRequirement ?? '').trim())
}

export function isRoleExclusive(endpoint: CoordinatorEndpoint): boolean {
  return endpoint.roleExclusive === true || ROLE_PATH_RE.test(endpoint.pathTemplate) || ROLE_AUTH_RE.test(endpoint.authRequirement ?? '')
}

export function isUncoveredEndpoint(endpoint: CoordinatorEndpoint): boolean {
  return (endpoint.testedClasses?.length ?? 0) === 0 && (endpoint.coveragePct ?? 0) <= 0
}

export type NonFloorSemanticClass = 'workflow' | 'business_logic' | 'race' | 'auth_protocol' | 'chain'
export const NON_FLOOR_SEMANTIC_CLASSES: readonly NonFloorSemanticClass[] = [
  'workflow', 'business_logic', 'race', 'auth_protocol', 'chain',
]

const SEMANTIC_MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const WORKFLOW_PATH_RE = /\/(?:checkout|confirm|approve|reject|submit|publish|cancel|refunds?|transitions?|verify|activate|complete|close|escalate|impersonate|invites?)(?:\/|$)/i
const BUSINESS_LOGIC_PATH_RE = /\/(?:carts?|orders?|invoices?|billing|plans?|subscriptions?|prices?|discounts?|coupons?|vouchers?|credits?|quotas?|seats?|limits?|tiers?|payments?)(?:\/|$)/i
const RACE_PATH_RE = /\/(?:redeem|apply|transfers?|withdraw|debit|claims?|reserve|allocate|stock|inventory|balances?|wallets?|gifts?|cards?|coupons?|checkout|pay)(?:\/|$)/i
const AUTH_PROTOCOL_PATH_RE = /\/(?:auth|login|tokens?|jwt|oauth|oidc|saml|sso|sessions?|refresh|mfa|2fa|otp|magic|reset|verify|keys?|webhooks?|reports?|exports?|integrations?)(?:\/|$)/i

/**
 * Pure structural classifier for non-floor semantic classes (`workflow`, `business_logic`, `race`,
 * `auth_protocol`, `chain`) that are under-covered on an endpoint. Returns classes relevant to the
 * endpoint that have not yet been tested, without any benchmark/app literals.
 */
export function classifySemanticEndpointClasses(endpoint: CoordinatorEndpoint): NonFloorSemanticClass[] {
  const method = (endpoint.method || 'GET').toUpperCase()
  const path = endpoint.pathTemplate || ''
  const tested = new Set((endpoint.testedClasses ?? []).map(c => c.toLowerCase()))
  const mutating = SEMANTIC_MUTATING_METHODS.has(method)
  const out: NonFloorSemanticClass[] = []
  if (mutating && WORKFLOW_PATH_RE.test(path) && !tested.has('workflow') && !tested.has('workflow_bypass')) {
    out.push('workflow')
  }
  if (mutating && BUSINESS_LOGIC_PATH_RE.test(path) && !tested.has('business_logic') && !tested.has('price_tampering')) {
    out.push('business_logic')
  }
  if (mutating && RACE_PATH_RE.test(path) && !tested.has('race') && !tested.has('race_burst') && !tested.has('race_condition')) {
    out.push('race')
  }
  if ((AUTH_PROTOCOL_PATH_RE.test(path) || isRoleExclusive(endpoint)) && !tested.has('auth_protocol') && !tested.has('jwt') && !tested.has('jwt_forgery')) {
    out.push('auth_protocol')
  }
  if ((endpoint.sinkKinds?.length ?? 0) > 0 && (endpoint.coveragePct ?? 0) < 100 && !tested.has('chain')) {
    out.push('chain')
  }
  return out
}

export interface PrioritizedSemanticEndpoint {
  endpoint: CoordinatorEndpoint
  semanticClasses: NonFloorSemanticClass[]
  priorityScore: number
}

/**
 * Rank unconfirmed endpoints carrying untested non-floor semantic classes ahead of generic routes
 * already swept by the deterministic floor. Pure and deterministic.
 */
export function prioritizeSemanticEndpoints(
  endpoints: readonly CoordinatorEndpoint[],
  options: { confirmedPaths?: ReadonlySet<string>; limit?: number } = {},
): PrioritizedSemanticEndpoint[] {
  const confirmed = options.confirmedPaths
  const limit = resolveLimit(options.limit, 20)
  const ranked: PrioritizedSemanticEndpoint[] = []
  for (const endpoint of endpoints) {
    if (confirmed?.has(endpoint.pathTemplate)) continue
    const semanticClasses = classifySemanticEndpointClasses(endpoint)
    if (!semanticClasses.length) continue
    const score = (endpoint.riskScore ?? 0) + semanticClasses.length * 15 + (isUncoveredEndpoint(endpoint) ? 10 : 0)
    ranked.push({ endpoint, semanticClasses, priorityScore: score })
  }
  ranked.sort((a, b) =>
    b.priorityScore - a.priorityScore
    || (a.endpoint.coveragePct ?? 0) - (b.endpoint.coveragePct ?? 0)
    || (a.endpoint.id < b.endpoint.id ? -1 : a.endpoint.id > b.endpoint.id ? 1 : 0))
  return ranked.slice(0, limit)
}

export interface QueryEndpointsArgs {
  cursor?: string
  limit?: number
  uncoveredOnly?: boolean
  /** Include endpoints with untested non-floor semantic classes even if another floor class ran. */
  untestedSemanticOnly?: boolean
  hasSink?: boolean
  missingAuthGuard?: boolean
  roleExclusive?: boolean
  pathPrefix?: string
}

/** Paginated endpoint query sorted risk-desc/coverage-asc/id-asc for stable cursors. */
export function queryEndpoints(deps: CoordinatorDeps, args: QueryEndpointsArgs = {}): CoordinatorPage<CoordinatorEndpoint> {
  const prefix = args.pathPrefix?.trim().toLowerCase()
  const filtered = deps.listEndpoints()
    .filter(endpoint => !args.uncoveredOnly || isUncoveredEndpoint(endpoint))
    .filter(endpoint => !args.untestedSemanticOnly || classifySemanticEndpointClasses(endpoint).length > 0)
    .filter(endpoint => !args.hasSink || (endpoint.sinkKinds?.length ?? 0) > 0)
    .filter(endpoint => !args.missingAuthGuard || isMissingAuthGuard(endpoint))
    .filter(endpoint => !args.roleExclusive || isRoleExclusive(endpoint))
    .filter(endpoint => !prefix || endpoint.pathTemplate.toLowerCase().startsWith(prefix))
    .slice()
    .sort((a, b) =>
      (args.untestedSemanticOnly
        ? classifySemanticEndpointClasses(b).length - classifySemanticEndpointClasses(a).length
        : 0)
      || (b.riskScore ?? 0) - (a.riskScore ?? 0)
      || (a.coveragePct ?? 0) - (b.coveragePct ?? 0)
      || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  return pageOf(filtered, args.cursor, args.limit)
}

// ---------------------------------------------------------------------------
// Facts and findings
// ---------------------------------------------------------------------------

const str = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null
const num = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) ? value : null
const truncate = (value: string, max: number): string => value.length <= max ? value : `${value.slice(0, max - 1)}…`

function factTags(fact: CoordinatorFact): string[] {
  const data = fact.data ?? {}
  return [fact.kind, data.kind, data.subkind, data.probeClass].map(str).filter((value): value is string => value !== null)
}

function factPersonas(fact: CoordinatorFact): string[] {
  const data = fact.data ?? {}
  const many = [data.personas, data.visibleToPersonas].flatMap(value => Array.isArray(value) ? value : [])
  return [data.persona, data.personaHandle, data.ownerPersona, data.injectedPersona, ...many]
    .map(str).filter((value): value is string => value !== null).map(value => value.toLowerCase())
}

function factRound(fact: CoordinatorFact): number | null {
  const data = fact.data ?? {}
  return num(data.roundNo) ?? num(data.round) ?? num(data.plannerRound) ?? num(data.discoveredRound)
}

function factHaystack(fact: CoordinatorFact): string {
  let data = ''
  try { data = JSON.stringify(fact.data ?? {}) } catch { /* non-serialisable fact data */ }
  return `${fact.kind} ${fact.origin} ${fact.summary} ${data}`.toLowerCase()
}

const compareFacts = (a: CoordinatorFact, b: CoordinatorFact): number =>
  (b.createdAt ?? 0) - (a.createdAt ?? 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)

export interface QueryFactsArgs {
  cursor?: string
  limit?: number
  kind?: string
  origin?: string
  persona?: string
  sinceRound?: number
  search?: string
}

/**
 * Paginated fact query so early low-severity primitives stay retrievable for late-round chains.
 * `sinceRound` uses the fact's recorded planner round (`data.roundNo`/`round`/`plannerRound`);
 * facts with no recorded round are excluded only when that filter is explicitly requested.
 */
export function queryFacts(deps: CoordinatorDeps, args: QueryFactsArgs = {}): CoordinatorPage<CoordinatorFact> {
  const kind = args.kind?.trim()
  const origin = args.origin?.trim()
  const persona = args.persona?.trim().toLowerCase()
  const search = args.search?.trim().toLowerCase()
  const filtered = deps.listFacts()
    .filter(fact => !fact.tainted)
    .filter(fact => !kind || factTags(fact).includes(kind))
    .filter(fact => !origin || fact.origin === origin)
    .filter(fact => !persona || factPersonas(fact).includes(persona))
    .filter(fact => args.sinceRound === undefined || (factRound(fact) ?? -1) >= args.sinceRound)
    .filter(fact => !search || factHaystack(fact).includes(search))
    .slice()
    .sort(compareFacts)
  return pageOf(filtered, args.cursor, args.limit)
}

export type FindingQueryStatus = 'confirmed' | 'pending_oob' | 'det_lead'

export interface QueryFindingsArgs {
  status: FindingQueryStatus
  limit?: number
}

export interface FindingRef {
  id: string
  source: 'finding' | 'det_lead'
  origin: string
  title: string
  status: string
  severity: string
  category?: string
  cwe?: string
  parentEvidenceIds: string[]
  exchangeIds: string[]
  endpoint?: string
  method?: string
  probeClass?: string
  reason?: string
}

export interface FindingsPage {
  status: FindingQueryStatus
  items: FindingRef[]
  total: number
  returned: number
}

const PENDING_OOB_RE = /pending[_\s-]?oob|awaiting[_\s-]?(?:oob|callback)/i

function isPendingOobFinding(finding: CoordinatorFinding): boolean {
  if (finding.status !== 'pending' && finding.status !== 'inconclusive') return false
  return finding.pendingOob === true
    || PENDING_OOB_RE.test(`${finding.runtimeProofGap ?? ''} ${finding.verification ?? ''} ${finding.reason ?? ''}`)
}

function findingRef(finding: CoordinatorFinding): FindingRef {
  return {
    id: finding.id, source: 'finding', origin: finding.origin, title: finding.title,
    status: finding.status, severity: finding.severity,
    ...(finding.category ? { category: finding.category } : {}),
    ...(finding.cwe ? { cwe: finding.cwe } : {}),
    parentEvidenceIds: [...(finding.evidenceIds ?? [])],
    exchangeIds: [...(finding.exchangeIds ?? [])],
    ...(finding.reason ? { reason: truncate(finding.reason, 200) } : {}),
  }
}

function detLeadRef(fact: CoordinatorFact): FindingRef {
  const data = fact.data ?? {}
  const endpoint = str(data.endpoint)
  const method = str(data.method)
  const probeClass = str(data.probeClass)
  const reason = str(data.reason)
  return {
    id: fact.id, source: 'det_lead', origin: fact.origin, title: truncate(fact.summary, 200),
    status: 'det_lead', severity: 'info',
    parentEvidenceIds: [fact.id, ...(fact.evidenceIds ?? [])],
    exchangeIds: [...(fact.exchangeIds ?? [])],
    ...(endpoint ? { endpoint } : {}),
    ...(method ? { method: method.toUpperCase() } : {}),
    ...(probeClass ? { probeClass } : {}),
    ...(reason ? { reason: truncate(reason, 200) } : {}),
  }
}

/**
 * Query outstanding work: runtime-confirmed findings, findings parked on a durable `pending_oob`
 * subscription, and unproven deterministic leads stored as facts (`data.kind === 'det_lead'`).
 */
export function queryFindings(deps: CoordinatorDeps, args: QueryFindingsArgs): FindingsPage {
  const limit = resolveLimit(args.limit)
  const items = args.status === 'confirmed'
    ? deps.listFindings().filter(finding => finding.status === 'confirmed').map(findingRef)
    : args.status === 'pending_oob'
      ? deps.listFindings().filter(isPendingOobFinding).map(findingRef)
      : deps.listFacts().filter(fact => !fact.tainted && fact.data?.kind === 'det_lead').slice().sort(compareFacts).map(detLeadRef)
  return { status: args.status, items: items.slice(0, limit), total: items.length, returned: Math.min(items.length, limit) }
}

// ---------------------------------------------------------------------------
// Program graph
// ---------------------------------------------------------------------------

export interface QueryProgramGraphArgs {
  routeOrFile?: string
  kind: 'sinks' | 'middleware_diff' | 'git_hotspots'
  limit?: number
}

export interface ProgramSinkItem {
  routeId: string
  method: string
  path: string
  file: string
  line: number
  sinkKind: string
  sinkFile: string
  sinkLine: number
  hops: number
  guards: string[]
  chain: Array<{ symbol: string; file: string; line: number }>
}

export interface MiddlewareDiffItem {
  routeId: string
  method: string
  path: string
  file: string
  line: number
  middleware: string[]
  guards: string[]
  missingGuardFamilies: string[]
}

export interface GitHotspotItem {
  sha: string
  subject: string
  committedAt?: string
  file: string
  change: string
  sinkKinds: string[]
  routeTouched: boolean
  authMiddlewareTouched: boolean
  reasons: string[]
}

export interface ProgramGraphPage<T> {
  kind: QueryProgramGraphArgs['kind']
  items: T[]
  total: number
  returned: number
  note?: string
}

const ADMIN_GUARD_RE = /(?:admin|rbac|role|permission|superuser|staff)/i
const AUTH_GUARD_RE = /(?:auth|authn|authz|jwt|session|passport|requireuser|login|permission|rbac|role|admin|policy|guard|acl|can[A-Z]|security)/i
const TENANT_GUARD_RE = /(?:tenant|org|organization|workspace|account|ownership|owner|scope|belongs)/i
const TENANT_PARAM_RE = /^(?:id|pk|.*_id|.*Id|.*_ids)$/
const ADMIN_PATH_RE = /\/(?:admin|internal|manage|management|backoffice|staff|console|superuser)(?:\/|$)/i

function matchesRouteOrFile(route: CoordinatorProgramRoute, needle?: string): boolean {
  const query = needle?.trim().toLowerCase()
  return !query
    || route.path.toLowerCase().includes(query)
    || route.file.toLowerCase().includes(query)
    || route.handler.toLowerCase().includes(query)
}

/** Local reverse call-graph (route ← handler ← … ← sink) with an explicit depth cap. */
function projectSinkPaths(graph: CoordinatorProgramGraph): ProgramSinkItem[] {
  const maxDepth = 7
  const maxPaths = 500
  const nodeById = new Map(graph.nodes.map(node => [node.id, node]))
  const routeById = new Map(graph.routes.map(route => [route.id, route]))
  const incoming = new Map<string, Array<{ fromId: string; toId: string }>>()
  for (const edge of graph.edges) incoming.set(edge.toId, [...(incoming.get(edge.toId) ?? []), edge])
  const results: ProgramSinkItem[] = []
  const seen = new Set<string>()
  for (const sink of graph.nodes.filter(node => node.kind === 'sink')) {
    const walk = (current: typeof sink, chain: Array<typeof sink>, visited: Set<string>): void => {
      if (results.length >= maxPaths) return
      if (current.kind === 'route') {
        const route = routeById.get(current.id)
        const key = `${current.id}:${sink.id}`
        if (!route || seen.has(key)) return
        seen.add(key)
        const ordered = [...chain].reverse()
        results.push({
          routeId: route.id, method: route.method, path: route.path, file: route.file, line: route.line,
          sinkKind: sink.sinkKind ?? 'other', sinkFile: sink.file, sinkLine: sink.line, hops: ordered.length - 1,
          guards: [...(route.guards ?? [])],
          chain: ordered.map(node => ({ symbol: node.symbol, file: node.file, line: node.line })),
        })
        return
      }
      if (chain.length > maxDepth + 1) return
      for (const edge of incoming.get(current.id) ?? []) {
        const caller = nodeById.get(edge.fromId)
        if (!caller || visited.has(caller.id)) continue
        visited.add(caller.id)
        chain.push(caller)
        walk(caller, chain, visited)
        chain.pop()
        visited.delete(caller.id)
      }
    }
    walk(sink, [sink], new Set([sink.id]))
  }
  return results
}

function middlewareDiff(route: CoordinatorProgramRoute): MiddlewareDiffItem | null {
  const guards = [...(route.guards ?? [])]
  const families = new Set<string>()
  if (!guards.some(guard => AUTH_GUARD_RE.test(guard))) families.add('authentication')
  if ((ADMIN_PATH_RE.test(route.path) || ADMIN_GUARD_RE.test(route.handler)) && !guards.some(guard => ADMIN_GUARD_RE.test(guard))) families.add('admin_rbac')
  const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method.toUpperCase())
  if (mutating && (route.input?.params ?? []).some(param => TENANT_PARAM_RE.test(param)) && !guards.some(guard => TENANT_GUARD_RE.test(guard))) families.add('tenant_scope')
  if (!families.size) return null
  return {
    routeId: route.id, method: route.method, path: route.path, file: route.file, line: route.line,
    middleware: [...(route.middleware ?? [])], guards, missingGuardFamilies: [...families],
  }
}

/** Query code-to-runtime sinks, missing guard chains, or security-relevant commit hotspots. */
export function queryProgramGraph<T extends ProgramSinkItem | MiddlewareDiffItem | GitHotspotItem = ProgramSinkItem>(
  deps: CoordinatorDeps,
  args: QueryProgramGraphArgs,
): ProgramGraphPage<T> {
  const limit = resolveLimit(args.limit)
  const page = (items: T[], note?: string): ProgramGraphPage<T> => ({
    kind: args.kind, items: items.slice(0, limit), total: items.length, returned: Math.min(items.length, limit),
    ...(note ? { note } : {}),
  })

  if (args.kind === 'git_hotspots') {
    const signals = deps.commitSignals?.() ?? []
    const needle = args.routeOrFile?.trim().toLowerCase()
    const items = signals
      .filter(signal => signal.securityRelevant !== false)
      .filter(signal => !needle || signal.file.toLowerCase().includes(needle) || signal.subject.toLowerCase().includes(needle))
      .slice()
      .sort((a, b) => (b.committedAt ?? '').localeCompare(a.committedAt ?? '')
        || (a.sha < b.sha ? -1 : a.sha > b.sha ? 1 : 0)
        || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0))
      .map(signal => ({
        sha: signal.sha, subject: signal.subject, ...(signal.committedAt ? { committedAt: signal.committedAt } : {}),
        file: signal.file, change: signal.change, sinkKinds: [...(signal.sinkKinds ?? [])],
        routeTouched: signal.routeTouched === true, authMiddlewareTouched: signal.authMiddlewareTouched === true,
        reasons: [...(signal.reasons ?? [])],
      })) as T[]
    return page(items, signals.length ? undefined : 'no commit signals supplied')
  }

  const graph = deps.programGraph?.() ?? null
  if (!graph) return page([], 'no program graph available')

  if (args.kind === 'sinks') {
    const streamlined = projectSinkPaths(graph)
      .filter(item => {
        const route = graph.routes.find(candidate => candidate.id === item.routeId)
        return route ? matchesRouteOrFile(route, args.routeOrFile) : !args.routeOrFile
      })
      .sort((a, b) => b.hops - a.hops || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0) || (a.sinkKind < b.sinkKind ? -1 : a.sinkKind > b.sinkKind ? 1 : 0))
    return page(streamlined as T[])
  }

  const diffs = graph.routes
    .filter(route => matchesRouteOrFile(route, args.routeOrFile))
    .map(middlewareDiff)
    .filter((item): item is MiddlewareDiffItem => item !== null)
    .sort((a, b) => b.missingGuardFamilies.length - a.missingGuardFamilies.length || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  return page(diffs as T[])
}

// ---------------------------------------------------------------------------
// Chain primitives & typed multi-round ChainHop artifacts (v7 M2)
// ---------------------------------------------------------------------------

export type ChainPrimitiveKind =
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

export interface ChainPrimitive {
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

export interface DeriveChainPrimitivesInput {
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

/** Derive typed, deduplicated chain tags from untainted facts, confirmed findings and endpoints. */
export function deriveChainPrimitives(input: DeriveChainPrimitivesInput): ChainPrimitive[] {
  const out: ChainPrimitive[] = []

  for (const fact of input.facts ?? []) {
    if (fact.tainted) continue
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
      continue
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

  for (const finding of input.findings ?? []) {
    if (finding.status !== 'confirmed') continue
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
  input: DeriveChainPrimitivesInput & { roundNo?: number; priorHops?: readonly ChainHop[] },
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
  const primitives = deriveChainPrimitives(input)
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
// Explicit chaining round — v8 CapabilityLedger + FrontierScheduler beam planner
// ---------------------------------------------------------------------------

export type ChainScope = 'same_origin' | 'cross_origin'

export interface ChainHypothesis {
  id: string
  scope: ChainScope
  hops: number
  origin: string
  chainOrigins: string[]
  primitiveKinds: ChainPrimitiveKind[]
  parentEvidenceIds: string[]
  title: string
  rationale: string
  probeClasses: string[]
  capabilities: CoordinatorCapability[]
  confidence: number
  entry?: { endpoint: string; method?: string; origin: string }
  target?: { endpoint: string; method?: string; origin: string }
  /** Ordered typed hop inputs feeding follow-on rounds without prompt soup (v7 M2). */
  chainHops?: ChainHop[]
  /** v8 Frontier branch identifier for wave tracking and 2-strike dead-end pruning. */
  branchKey?: string
  /** Exact v8 EVI score computed by `FrontierScheduler`. */
  evi?: number
  /** Ordered CapabilityLedger handle IDs participating in this causal branch. */
  capabilityIds?: string[]
  /** Ordered causal edge binding kinds across hops. */
  edgeBindingKinds?: CausalEdgeBindingKind[]
  /** Strictly bounded (<= 2 KB) pre-hydrated Hop-Checkpoint brief for follow-on workers. */
  checkpointBrief?: HopCheckpointBrief
  /** Serialized UTF-8 JSON of `checkpointBrief` (<= 2048 bytes). */
  checkpointJson?: string
  /** UTF-8 byte length of `checkpointJson`. */
  checkpointBytes?: number
}

export interface PlanChainRoundArgs {
  primitives: readonly ChainPrimitive[]
  endpoints?: readonly CoordinatorEndpoint[]
  /** Typed hops from prior/current rounds to attach onto planned multi-step hypotheses. */
  hops?: readonly ChainHop[]
  /** Runtime producer->consumer API dependency edges (e.g. from `endpointGraphCatalog.apiDependencies`). */
  apiDependencies?: readonly CoordinatorApiDependency[]
  /** False/omitted in grey-box/black-box runs where no repo source is mounted. */
  sourceMounted?: boolean
  /** Maximum chain depth (v8 supports 1..6; defaults to 4). */
  maxHops?: number
  /** Minimum chain depth (defaults to 2 for multi-hop composition; set 1 to include terminal-eligible 1-hop nodes). */
  minHops?: number
  limit?: number
  approvedOrigins?: readonly string[]
  /** Optional v8 CapabilityLedger for causal DAG lineage, quarantine, and negative-edge filtering. */
  capabilityLedger?: CapabilityLedger | null
  /** Optional v8 FrontierScheduler for beam ranking, strike telemetry, and negative-edge sync. */
  frontierScheduler?: FrontierScheduler | null
  /** Beam width B clamped to [8, 16] per plans/v8.md §5. */
  beamWidth?: number
  /** Current wave number for FrontierBranch metadata. */
  waveNo?: number
  /** Maximum UTF-8 byte budget for hop-checkpoint briefs (default 2048 B). */
  maxCheckpointBriefBytes?: number
}

const PROBE_CLASS: Record<ChainPrimitiveKind, string> = {
  leaked_token: 'authz_replay',
  discovered_id: 'bola_idor',
  ssrf_internal_reach: 'ssrf',
  stored_write: 'stored_xss',
  weak_jwt: 'jwt_forgery',
  admin_route: 'auth_bypass',
  role_transition: 'auth_bypass',
  workflow_state_handle: 'workflow_invariant',
}

const AUTHORITY_CAP_KINDS: ReadonlySet<CapabilityKind> = new Set([
  'identity_session', 'scoped_token', 'signing_material', 'signed_artifact_or_url',
])
const PIVOT_CAP_KINDS: ReadonlySet<CapabilityKind> = new Set([
  'internal_reach_handle', 'state_handle', 'write_sink_handle', 'parser_or_cache_primitive',
])
const TARGET_CAP_KINDS: ReadonlySet<CapabilityKind> = new Set([
  'opaque_object_ref', 'policy_asymmetry',
])

const hostOf = (origin: string): string => origin.replace(/^https?:\/\//, '')

function primitiveToCapabilityKind(kind: ChainPrimitiveKind): CapabilityKind {
  switch (kind) {
    case 'leaked_token': return 'scoped_token'
    case 'weak_jwt': return 'signing_material'
    case 'discovered_id': return 'opaque_object_ref'
    case 'ssrf_internal_reach': return 'internal_reach_handle'
    case 'stored_write': return 'write_sink_handle'
    case 'admin_route': return 'policy_asymmetry'
    case 'role_transition': return 'identity_session'
    case 'workflow_state_handle': return 'state_handle'
  }
}

function capabilityKindToPrimitiveKind(kind: CapabilityKind): ChainPrimitiveKind {
  switch (kind) {
    case 'scoped_token':
    case 'signed_artifact_or_url':
      return 'leaked_token'
    case 'signing_material':
      return 'weak_jwt'
    case 'opaque_object_ref':
      return 'discovered_id'
    case 'internal_reach_handle':
      return 'ssrf_internal_reach'
    case 'write_sink_handle':
      return 'stored_write'
    case 'policy_asymmetry':
    case 'parser_or_cache_primitive':
      return 'admin_route'
    case 'identity_session':
      return 'role_transition'
    case 'state_handle':
      return 'workflow_state_handle'
  }
}

function inferSurfaceFromEndpoint(endpoint: string | undefined, kind: ChainPrimitiveKind): CapabilitySurface {
  if (kind === 'stored_write') return 'browser'
  if (kind === 'ssrf_internal_reach') return 'webhook'
  if (kind === 'workflow_state_handle') return 'async_job'
  const path = (endpoint ?? '').toLowerCase()
  if (/\/(?:graphql|gql)(?:\/|$)/.test(path)) return 'graphql'
  if (/\/(?:sse|events|stream)(?:\/|$)/.test(path)) return 'sse'
  if (/\/(?:ws|wss|socket)(?:\/|$)/.test(path)) return 'ws'
  if (/\/(?:oauth|oidc|idp|sso|scim|authorize)(?:\/|$)/.test(path)) return 'idp'
  if (/\/(?:cdn|static|public\/profile|cache)(?:\/|$)/.test(path)) return 'cdn'
  if (/\/(?:storage|buckets?|blobs?|files?|artifacts?|downloads?)(?:\/|$)/.test(path)) return 'storage'
  if (/\/(?:jobs?|workers?|exports?|async)(?:\/|$)/.test(path)) return 'async_job'
  if (/\/(?:webhooks?|callbacks?|hooks?)(?:\/|$)/.test(path)) return 'webhook'
  return 'http'
}

function capabilitySet(kinds: readonly ChainPrimitiveKind[], surfaces: readonly CapabilitySurface[] = []): CoordinatorCapability[] {
  return COORDINATOR_CAPABILITIES.filter(capability =>
    capability === 'http'
    || (capability === 'oob' && (kinds.includes('ssrf_internal_reach') || surfaces.includes('webhook') || surfaces.includes('async_job')))
    || (capability === 'browser' && (kinds.includes('stored_write') || surfaces.includes('browser')))
    || (capability === 'race' && kinds.includes('workflow_state_handle')))
}

function endpointFor(primitive: ChainPrimitive, endpoints: readonly CoordinatorEndpoint[]): CoordinatorEndpoint | undefined {
  return primitive.endpointId
    ? endpoints.find(endpoint => endpoint.id === primitive.endpointId)
    : endpoints.find(endpoint => endpoint.origin === primitive.origin && endpoint.pathTemplate === primitive.endpoint
      && (!primitive.method || endpoint.method.toUpperCase() === primitive.method))
}

function matchHopForPrimitive(primitive: ChainPrimitive, hops: readonly ChainHop[], hopIndex: number): ChainHop {
  const artifactKind = primitiveKindToHopArtifactKind(primitive.kind)
  const matched = hops.find(hop =>
    hop.origin === primitive.origin
    && hop.artifactKind === artifactKind
    && (hop.artifactRef === primitive.value
      || (primitive.factIds.length > 0 && primitive.factIds.some(id => hop.factIds.includes(id)))
      || (primitive.endpoint && hop.endpoint === primitive.endpoint)))
  if (matched) return { ...matched, hopIndex }
  const fallbackRef = artifactKind === 'token_ref'
    ? (primitive.value.startsWith('secret:') || primitive.value.startsWith('jwt:') || primitive.value.startsWith('finding:') ? primitive.value : `secret:${primitive.factIds[0] ?? hopIndex}`)
    : primitive.value
  return {
    hopId: `hop:${artifactKind}:${hostOf(primitive.origin)}:${hopIndex}`,
    roundNo: 1,
    hopIndex,
    artifactKind,
    artifactRef: safeArtifactRef(primitive.value, fallbackRef, artifactKind),
    origin: primitive.origin,
    ...(primitive.endpoint ? { endpoint: primitive.endpoint } : {}),
    ...(primitive.method ? { method: primitive.method } : {}),
    ...(primitive.persona ? { persona: primitive.persona } : {}),
    verified: false,
    evidenceIds: dedupe(primitive.evidenceIds),
    factIds: dedupe(primitive.factIds),
    summary: truncate(primitive.detail, 160),
  }
}

export interface CausalPlanUnit {
  unitId: string
  capId: string
  capKind: CapabilityKind
  primitive: ChainPrimitive
  surface: CapabilitySurface
  tenantScope: string | null
  actorPersona: string
  serviceOrigin: string
  hopReceiptId: string
  verified: boolean
  quarantined: boolean
  terminalEligible: boolean
  targetSurfaceKey: string
  hypothesisClass: string
  endpoint: string
  method: string
}

function sanitizeUnitToken(raw: string): string {
  const clean = raw.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[^A-Za-z0-9]+/, '')
  return (clean || 'u0').slice(0, 48)
}

function inferCausalBinding(from: CausalPlanUnit, to: CausalPlanUnit): CausalEdgeBindingKind {
  if (from.capKind === 'signing_material' || to.capKind === 'signed_artifact_or_url') return 'derived_crypto_binding'
  if (
    from.capKind === 'write_sink_handle'
    || from.capKind === 'internal_reach_handle'
    || to.surface === 'async_job'
    || to.surface === 'webhook'
    || to.surface === 'browser'
    || to.surface === 'sse'
  ) {
    return 'async_pivot_binding'
  }
  if (
    from.capKind === 'state_handle'
    || from.capKind === 'parser_or_cache_primitive'
    || to.capKind === 'state_handle'
    || to.capKind === 'parser_or_cache_primitive'
  ) {
    return 'state_transition_binding'
  }
  return 'value_binding'
}

function parseRouteTarget(rawRoute: unknown): { method?: string; endpoint?: string } {
  if (typeof rawRoute !== 'string' || !rawRoute.trim()) return {}
  const trimmed = rawRoute.trim()
  const parts = trimmed.split(/\s+/, 2)
  if (parts.length === 2 && /^[A-Z]+$/i.test(parts[0]!)) {
    return { method: parts[0]!.toUpperCase(), endpoint: parts[1]! }
  }
  return { endpoint: trimmed }
}

function ledgerNodeToUnit(node: CapabilityNode, fallbackOrigin: string | null): CausalPlanUnit | null {
  const meta = node.metadata ?? {}
  const parsedRoute = parseRouteTarget(meta.targetRoute)
  const endpoint = parsedRoute.endpoint ?? (typeof meta.endpoint === 'string' ? meta.endpoint : `/${node.surface}/${node.kind}`)
  const method = parsedRoute.method ?? (typeof meta.method === 'string' ? meta.method.toUpperCase() : 'POST')
  const origin = /^https?:\/\//i.test(node.serviceOrigin) ? node.serviceOrigin : fallbackOrigin
  if (!origin) return null
  const rawTenant = node.tenantScope?.trim() || null
  const tenantScope = rawTenant && rawTenant !== 'unscoped_hypothesis' ? rawTenant : null
  const primitiveKind = capabilityKindToPrimitiveKind(node.kind)
  const hypothesisClass = typeof meta.hypothesisKind === 'string' && meta.hypothesisKind.trim()
    ? meta.hypothesisKind.trim()
    : PROBE_CLASS[primitiveKind]
  const targetSurfaceKey = typeof meta.targetSurfaceKey === 'string' && meta.targetSurfaceKey.trim()
    ? meta.targetSurfaceKey.trim()
    : `${node.serviceOrigin}|${node.surface}|${endpoint}`
  const quarantined = ALWAYS_QUARANTINED_KINDS.has(node.kind) || node.promotionStatus === 'capability_only'
  const terminalEligible = !ALWAYS_QUARANTINED_KINDS.has(node.kind)
    && node.promotionStatus === 'terminal_eligible'
    && node.terminalImpactOracleVerified
  const detail = node.artifactSummary
    || `Capability ${node.capId} (${node.kind} on ${node.surface}/${node.serviceOrigin})`
  return {
    unitId: `ledger:${node.capId}`,
    capId: node.capId,
    capKind: node.kind,
    primitive: {
      kind: primitiveKind,
      origin,
      value: node.capId,
      evidenceIds: dedupe([node.capId, ...node.parentHopReceiptIds]),
      factIds: typeof meta.factId === 'string' ? [meta.factId] : [],
      endpoint,
      method,
      persona: node.actorPersona,
      detail,
    },
    surface: node.surface,
    tenantScope,
    actorPersona: node.actorPersona,
    serviceOrigin: node.serviceOrigin,
    hopReceiptId: node.parentHopReceiptIds[0] ?? `hop:${sanitizeUnitToken(node.capId)}`,
    verified: node.provenance === 'derived_hop' || node.parentHopReceiptIds.length > 0 || terminalEligible,
    quarantined,
    terminalEligible,
    targetSurfaceKey,
    hypothesisClass,
    endpoint,
    method,
  }
}

function primitiveToUnit(primitive: ChainPrimitive, hops: readonly ChainHop[], ordinal: number): CausalPlanUnit {
  const capKind = primitiveToCapabilityKind(primitive.kind)
  const surface = inferSurfaceFromEndpoint(primitive.endpoint, primitive.kind)
  const matched = matchHopForPrimitive(primitive, hops, ordinal)
  const capId = `cap:hop_prim${ordinal}:${sanitizeUnitToken(primitive.kind)}`
  const endpoint = primitive.endpoint ?? `/${surface}/${primitive.kind}`
  const method = (primitive.method ?? 'POST').toUpperCase()
  const targetSurfaceKey = `${primitive.origin}|${surface}|${endpoint}`
  const hypothesisClass = PROBE_CLASS[primitive.kind]
  const quarantined = ALWAYS_QUARANTINED_KINDS.has(capKind)
  return {
    unitId: `prim:${primitive.kind}:${primitive.origin}:${primitive.value}`,
    capId,
    capKind,
    primitive,
    surface,
    tenantScope: null,
    actorPersona: primitive.persona ?? 'attacker',
    serviceOrigin: primitive.origin,
    hopReceiptId: matched.hopId,
    verified: matched.verified,
    quarantined,
    terminalEligible: !quarantined && matched.verified,
    targetSurfaceKey,
    hypothesisClass,
    endpoint,
    method,
  }
}

export function structuralTransitionFeasibility(
  units: readonly CausalPlanUnit[],
  verifiedEdgeCount: number,
): { feasibilityProb: number; terminalImpactWeight: number; surfaceNovelty: number } {
  const capKinds = units.map(u => u.capKind)
  const distinctSurfaces = new Set(units.map(u => u.surface)).size
  const distinctOrigins = new Set(units.map(u => u.serviceOrigin)).size
  const distinctTenants = new Set(
    units
      .map(u => u.tenantScope)
      .filter((t): t is string => Boolean(t && t !== 'unscoped_hypothesis')),
  ).size
  const hasAuthority = capKinds.some(k => AUTHORITY_CAP_KINDS.has(k))
  const hasPivot = capKinds.some(k => PIVOT_CAP_KINDS.has(k))
  const hasTarget = capKinds.some(k => TARGET_CAP_KINDS.has(k))
  const stagesCovered = Number(hasAuthority) + Number(hasPivot) + Number(hasTarget)
  const verifiedUnits = units.filter(u => u.verified).length

  let feasibility = 0.56
  if (hasAuthority && (hasTarget || hasPivot)) feasibility += 0.16
  else if (hasPivot && hasTarget) feasibility += 0.11
  else if (stagesCovered >= 2) feasibility += 0.08
  feasibility += Math.min(0.16, verifiedEdgeCount * 0.06 + verifiedUnits * 0.03)
  if (units.length >= 2 && units[0]!.capKind === units[units.length - 1]!.capKind && verifiedEdgeCount === 0) {
    feasibility -= 0.12
  }
  const feasibilityProb = Math.max(0.25, Math.min(0.96, Number(feasibility.toFixed(4))))

  let impact = 6.2 + stagesCovered * 0.9
  if (hasAuthority) impact += 0.8
  if (distinctOrigins > 1) impact += 0.6
  if (distinctTenants > 1) impact += 0.6
  if (verifiedEdgeCount > 0) impact += Math.min(1.0, verifiedEdgeCount * 0.35)
  const terminalImpactWeight = Math.min(10, Number(impact.toFixed(4)))

  // Distinct surfaces + cross-service/cross-origin transitions drive v8 SurfaceNovelty.
  const surfaceNovelty = Number((
    1.0
    + Math.max(0, distinctSurfaces - 1) * 0.42
    + (distinctOrigins > 1 ? 0.18 : 0)
    + Math.min(0.35, Math.max(0, units.length - 2) * 0.08)
  ).toFixed(4))

  return { feasibilityProb, terminalImpactWeight, surfaceNovelty }
}

interface PlannedCausalCandidate {
  branch: FrontierBranch
  units: CausalPlanUnit[]
  bindings: CausalEdgeBindingKind[]
  evi: number
  isLedgerDag: boolean
}

function buildCausalBranch(input: {
  units: CausalPlanUnit[]
  bindings: CausalEdgeBindingKind[]
  waveNo: number
  verifiedEdgeCount: number
  attemptsOnBranch: number
}): FrontierBranch {
  const { units, bindings, waveNo, verifiedEdgeCount, attemptsOnBranch } = input
  const tail = units[units.length - 1]!
  const scoring = structuralTransitionFeasibility(units, verifiedEdgeCount)
  const verifiedHops: VerifiedHopHandle[] = units.map((unit, idx) => ({
    hopIndex: idx + 1,
    hopReceiptId: unit.hopReceiptId,
    capabilityId: unit.capId,
    kind: unit.capKind,
    surface: unit.surface,
    serviceOrigin: unit.serviceOrigin,
    tenantScope: unit.tenantScope ?? '',
    actorPersona: unit.actorPersona,
    endpoint: unit.endpoint,
    method: unit.method,
    ...(idx > 0 && bindings[idx - 1] ? { edgeBindingKind: bindings[idx - 1] } : {}),
    summary: truncate(unit.primitive.detail, 120),
  }))
  const nextTarget: FrontierTargetSurface = {
    targetSurfaceKey: tail.targetSurfaceKey,
    surface: tail.surface,
    serviceOrigin: tail.serviceOrigin,
    endpoint: tail.endpoint,
    method: tail.method,
    hypothesisClass: tail.hypothesisClass,
    ...(bindings.length ? { expectedBindingKind: bindings[bindings.length - 1] } : {}),
    ...(tail.tenantScope ? { targetTenantScope: tail.tenantScope } : {}),
    goalSummary: truncate(
      `Verify ${units.length}-hop causal chain reaching ${tail.method} ${tail.endpoint} (${tail.capKind})`,
      160,
    ),
  }
  const branchKey = `b:${units.map(u => sanitizeUnitToken(u.capId)).join('>')}`
  return {
    branchKey,
    depth: units.length,
    verifiedHops,
    nextTarget,
    feasibilityProb: scoring.feasibilityProb,
    terminalImpactWeight: scoring.terminalImpactWeight,
    surfaceNovelty: scoring.surfaceNovelty,
    attemptsOnBranch,
    consecutiveFailedAttempts: attemptsOnBranch,
    lane: 'partial_chain',
    createdWave: waveNo,
    lastUpdatedWave: waveNo,
  }
}

function buildHypothesisFromCausalCandidate(
  candidate: PlannedCausalCandidate,
  endpoints: readonly CoordinatorEndpoint[],
  hops: readonly ChainHop[],
  maxCheckpointBriefBytes: number,
  ordinal: number,
): ChainHypothesis {
  const chain = candidate.units.map(u => u.primitive)
  const kinds = chain.map(primitive => primitive.kind)
  const surfaces = candidate.units.map(u => u.surface)
  const origins = [...new Set(chain.map(primitive => primitive.origin))]
  const scope: ChainScope = origins.length === 1 ? 'same_origin' : 'cross_origin'
  const entry = chain.map(primitive => endpointFor(primitive, endpoints)).find(Boolean)
  const target = [...chain].reverse().map(primitive => endpointFor(primitive, endpoints)).find(Boolean)
  const chainHops = chain.map((primitive, index) => matchHopForPrimitive(primitive, hops, index))
  for (let i = 1; i < chainHops.length; i += 1) {
    if (!chainHops[i]!.parentHopId) chainHops[i] = { ...chainHops[i]!, parentHopId: chainHops[i - 1]!.hopId }
  }
  const { brief, checkpointJson, checkpointBytes } = buildHopCheckpointBrief(
    candidate.branch,
    candidate.evi,
    maxCheckpointBriefBytes,
  )
  // Monotonically project EVI into [0.35, 0.99] confidence for legacy consumers.
  const confidence = Math.round(Math.min(0.99, Math.max(0.35, candidate.evi / (candidate.evi + 3.0))) * 100) / 100
  return {
    id: `chain:${scope}:${kinds.join('>')}:${ordinal}`,
    scope,
    hops: chain.length,
    origin: chain[0]!.origin,
    chainOrigins: origins,
    primitiveKinds: kinds,
    parentEvidenceIds: dedupe(chain.flatMap(primitive => [...primitive.evidenceIds, ...primitive.factIds])),
    title: `${kinds.join(' → ')} chain on ${origins.map(hostOf).join(' → ')}`,
    rationale: `Connect ${chain.map(primitive => primitive.detail).join(' Then ')}`,
    probeClasses: [...new Set(kinds.map(kind => PROBE_CLASS[kind]))].sort(),
    capabilities: capabilitySet(kinds, surfaces),
    confidence,
    ...(entry ? { entry: { endpoint: entry.pathTemplate, method: entry.method, origin: entry.origin } } : {}),
    ...(target ? { target: { endpoint: target.pathTemplate, method: target.method, origin: target.origin } } : {}),
    chainHops,
    branchKey: candidate.branch.branchKey,
    evi: Number(candidate.evi.toFixed(6)),
    capabilityIds: candidate.units.map(u => u.capId),
    edgeBindingKinds: [...candidate.bindings],
    checkpointBrief: brief,
    checkpointJson,
    checkpointBytes,
  }
}

function collectNegativeEdgeState(
  ledger: CapabilityLedger | null | undefined,
  scheduler: FrontierScheduler | null | undefined,
): { prunedKeys: Set<string>; strikeCountByKey: Map<string, number>; records: NegativeEdgeRecord[] } {
  const prunedKeys = new Set<string>()
  const strikeCountByKey = new Map<string, number>()
  const records: NegativeEdgeRecord[] = []
  if (ledger) {
    for (const neg of ledger.listNegativeEdges()) {
      const key = computeNegativeEdgeKey(neg.preconditionCapIds, neg.targetSurfaceKey, neg.hypothesisClass)
      strikeCountByKey.set(key, Math.max(strikeCountByKey.get(key) ?? 0, neg.attemptCount))
      if (neg.pruned || neg.attemptCount >= ledger.pruneStrikeThreshold) {
        prunedKeys.add(key)
        records.push({
          negativeEdgeKey: key,
          branchKey: `ledger:${neg.preconditionKey}`,
          preconditionCapIds: [...neg.preconditionCapIds],
          targetSurfaceKey: neg.targetSurfaceKey,
          hypothesisClass: neg.hypothesisClass,
          reason: neg.reason,
          failedAttempts: neg.attemptCount,
          falsifiedByExchangeIds: [...neg.falsifiedByExchangeIds],
          recordedAtWave: 0,
        })
      }
    }
  }
  if (scheduler) {
    for (const rec of scheduler.exportNegativeEdges()) {
      prunedKeys.add(rec.negativeEdgeKey)
      strikeCountByKey.set(rec.negativeEdgeKey, Math.max(strikeCountByKey.get(rec.negativeEdgeKey) ?? 0, rec.failedAttempts))
    }
  }
  return { prunedKeys, strikeCountByKey, records }
}

function inferRuntimeRoutePrimitiveKind(
  method: string,
  endpoint: string,
  resourceKey = '',
  sinkKinds: readonly string[] = [],
): ChainPrimitiveKind {
  const lower = `${endpoint} ${resourceKey} ${sinkKinds.join(' ')}`.toLowerCase()
  if (sinkKinds.includes('outbound_fetch') || /\/(?:webhooks?|callbacks?|hooks?|render|preview|proxy|fetch|import|redirect)(?:\/|$)/.test(lower)) {
    return 'ssrf_internal_reach'
  }
  if (/\/(?:oauth|oidc|idp|sso|token|jwks|keys?|sign|signing)(?:\/|$)/.test(lower) || /token|jwt|secret|key/.test(resourceKey.toLowerCase())) {
    return 'leaked_token'
  }
  if (/\/(?:invite|impersonate|roles?|grant|session|login|auth)(?:\/|$)/.test(lower)) {
    return 'role_transition'
  }
  if (ROLE_PATH_RE.test(endpoint)) {
    return 'admin_route'
  }
  if (
    SEMANTIC_MUTATING_METHODS.has(method.toUpperCase())
    && (WORKFLOW_PATH_RE.test(endpoint) || BUSINESS_LOGIC_PATH_RE.test(endpoint) || RACE_PATH_RE.test(endpoint) || /\/(?:exports?|jobs?|async|batch|bulk)(?:\/|$)/.test(lower))
  ) {
    return 'workflow_state_handle'
  }
  return 'discovered_id'
}

function makeRuntimePlanUnit(input: {
  origin: string
  method: string
  endpoint: string
  endpointId?: string
  resourceKey?: string
  persona?: string | null
  tenantScope?: string | null
  detail: string
  sinkKinds?: readonly string[]
  unitTag: string
  ordinal: number
}): CausalPlanUnit {
  const method = input.method.toUpperCase()
  const kind = inferRuntimeRoutePrimitiveKind(method, input.endpoint, input.resourceKey, input.sinkKinds)
  const capKind = primitiveToCapabilityKind(kind)
  const surface = inferSurfaceFromEndpoint(input.endpoint, kind)
  const capId = `cap:hop_${sanitizeUnitToken(input.unitTag)}_${input.ordinal}:${sanitizeUnitToken(input.resourceKey || kind)}`
  const primitive: ChainPrimitive = {
    kind,
    origin: input.origin,
    value: input.resourceKey ? `${input.resourceKey}@${input.endpoint}` : `${method} ${input.endpoint}`,
    evidenceIds: [],
    factIds: [],
    ...(input.endpointId ? { endpointId: input.endpointId } : {}),
    endpoint: input.endpoint,
    method,
    ...(input.persona ? { persona: input.persona } : {}),
    detail: input.detail,
  }
  return {
    unitId: `rt:${input.unitTag}:${input.origin}:${method}:${input.endpoint}`,
    capId,
    capKind,
    primitive,
    surface,
    tenantScope: input.tenantScope?.trim() || null,
    actorPersona: input.persona ?? 'attacker',
    serviceOrigin: input.origin,
    hopReceiptId: `hop:${sanitizeUnitToken(input.unitTag)}:${input.ordinal}`,
    verified: false,
    quarantined: ALWAYS_QUARANTINED_KINDS.has(capKind),
    terminalEligible: !ALWAYS_QUARANTINED_KINDS.has(capKind),
    targetSurfaceKey: `${input.origin}|${surface}|${input.endpoint}`,
    hypothesisClass: PROBE_CLASS[kind],
    endpoint: input.endpoint,
    method,
  }
}

function resolveDependencySide(
  endpointId: string | undefined,
  rawRoute: string | undefined,
  explicitOrigin: string | undefined,
  explicitMethod: string | undefined,
  endpointsById: ReadonlyMap<string, CoordinatorEndpoint>,
  endpointsByMethodPath: ReadonlyMap<string, CoordinatorEndpoint>,
  fallbackOrigin: string | null,
): { origin: string; method: string; endpoint: string; endpointId?: string; sinkKinds?: readonly string[] } | null {
  if (endpointId) {
    const found = endpointsById.get(endpointId)
    if (found) {
      return {
        origin: explicitOrigin ?? found.origin,
        method: (explicitMethod ?? found.method).toUpperCase(),
        endpoint: found.pathTemplate,
        endpointId: found.id,
        sinkKinds: found.sinkKinds,
      }
    }
  }
  if (!rawRoute || !rawRoute.trim()) return null
  const parsed = parseRouteTarget(rawRoute)
  const rawEndpoint = parsed.endpoint?.trim()
  if (!rawEndpoint || !rawEndpoint.startsWith('/')) return null
  const method = (explicitMethod ?? parsed.method ?? 'GET').toUpperCase()
  const matched = endpointsByMethodPath.get(`${method} ${rawEndpoint}`)
    ?? endpointsByMethodPath.get(`* ${rawEndpoint}`)
  const origin = explicitOrigin ?? matched?.origin ?? fallbackOrigin
  if (!origin) return null
  return {
    origin,
    method,
    endpoint: rawEndpoint,
    ...(matched?.id ? { endpointId: matched.id } : {}),
    ...(matched?.sinkKinds ? { sinkKinds: matched.sinkKinds } : {}),
  }
}

// ---------------------------------------------------------------------------
// Unified Causal Composite Planner (shared by white-box suspects & grey-box runtime nodes)
// ---------------------------------------------------------------------------

export type CompositeWorkflowRole =
  | 'outbound_fetch'
  | 'signing_webhook'
  | 'info_disclosure'
  | 'auth_session'
  | 'privileged_mutation'
  | 'async_worker'
  | 'cache_permission'
  | 'request_parsing'
  | 'concurrent_settlement'

export interface CompositeWorkflowNode {
  id: string
  origin: string
  serviceScope: string
  endpoint: string
  sinkKind: string
  summary: string
  roles: ReadonlySet<CompositeWorkflowRole>
  fileLoc?: string
  factId?: string
  resourceKey?: string
  explicitSuspect?: boolean
  isApiDep?: boolean
  priorityScore?: number
}

export interface PlannedCompositeWorkflow<T extends CompositeWorkflowNode = CompositeWorkflowNode> {
  key: string
  label: string
  category: string
  hops: T[]
  resourceKey?: string
  priority: number
}

interface CompositeWorkflowRule<T extends CompositeWorkflowNode> {
  key: string
  entry: (c: T) => boolean
  entryFallback?: (c: T) => boolean
  pivot: (c: T) => boolean
  pivotFallback?: (c: T) => boolean
  terminal?: (c: T, pivot: T) => boolean
  terminalFallback?: (c: T, pivot: T) => boolean
  label: (hasTerminal: boolean) => string
  category: (hasTerminal: boolean) => string
  requireDiversity?: boolean
}

function compositeRoleToCapabilityKind(roles: ReadonlySet<CompositeWorkflowRole>): CapabilityKind {
  if (roles.has('outbound_fetch')) return 'internal_reach_handle'
  if (roles.has('signing_webhook')) return 'signing_material'
  if (roles.has('auth_session')) return 'identity_session'
  if (roles.has('cache_permission') || roles.has('request_parsing')) return 'parser_or_cache_primitive'
  if (roles.has('async_worker') || roles.has('privileged_mutation')) return 'write_sink_handle'
  return 'state_handle'
}

function compositeRoleToSurface(roles: ReadonlySet<CompositeWorkflowRole>, endpoint: string): CapabilitySurface {
  if (roles.has('signing_webhook')) return 'webhook'
  if (roles.has('async_worker')) return 'async_job'
  if (roles.has('cache_permission')) return 'cdn'
  return inferSurfaceFromEndpoint(endpoint, 'discovered_id')
}

/**
 * Seed normalized code-audit suspects and runtime API-dependency nodes into `CapabilityLedger`
 * as strictly quarantined (`capability_only`) capability nodes + causal edges so `planChainRound`
 * composes white-box and runtime edges in a single causal DAG.
 */
export function seedCompositeNodesToLedger(
  ledger: CapabilityLedger | null | undefined,
  nodes: readonly CompositeWorkflowNode[],
  depPairs: readonly { prod: CompositeWorkflowNode; cons: CompositeWorkflowNode; resourceKey: string }[] = [],
): number {
  if (!ledger || nodes.length === 0) return 0
  let seeded = 0
  const capIdByNodeId = new Map<string, string>()
  for (const node of nodes.slice(0, 48)) {
    const capKind = compositeRoleToCapabilityKind(node.roles)
    const surface = compositeRoleToSurface(node.roles, node.endpoint)
    const capId = `cap:hop_comp_${sanitizeUnitToken(node.id)}:${sanitizeUnitToken(capKind)}`
    capIdByNodeId.set(node.id, capId)
    if (ledger.getCapability(capId)) continue
    try {
      const parsed = parseRouteTarget(node.endpoint)
      ledger.addCapability({
        capId,
        kind: capKind,
        surface,
        serviceOrigin: node.origin,
        tenantScope: 'unscoped_hypothesis',
        actorPersona: 'attacker',
        provenance: node.explicitSuspect ? 'static_analysis' : 'runtime_discovery',
        promotionStatus: 'capability_only',
        terminalImpactOracleVerified: false,
        artifactDigest: computeArtifactDigest(`${capId}|${node.origin}|${node.endpoint}|${node.sinkKind}`),
        artifactSummary: truncate(node.summary, 160),
        metadata: {
          ...(node.factId ? { factId: node.factId } : {}),
          ...(parsed.endpoint ? { endpoint: parsed.endpoint } : {}),
          ...(parsed.method ? { method: parsed.method } : {}),
          targetRoute: node.endpoint,
          sinkKind: node.sinkKind,
          serviceScope: node.serviceScope,
          roles: [...node.roles],
        },
      })
      seeded += 1
    } catch { /* fail-closed ledger validation */ }
  }
  const nowMs = Date.now()
  for (const pair of depPairs.slice(0, 32)) {
    const prodCapId = capIdByNodeId.get(pair.prod.id)
    const consCapId = capIdByNodeId.get(pair.cons.id)
    if (!prodCapId || !consCapId || prodCapId === consCapId) continue
    try {
      ledger.addCausalEdge({
        edgeId: `edge:dep:${sanitizeUnitToken(pair.prod.id)}:${sanitizeUnitToken(pair.cons.id)}`,
        preconditionCapIds: [prodCapId],
        postconditionCapId: consCapId,
        edgeBindingKind: 'value_binding',
        hopReceiptId: `hop:dep:${sanitizeUnitToken(pair.resourceKey)}`,
        actorContext: { persona: 'attacker', serviceOrigin: pair.cons.origin },
        sourceTimestampMs: nowMs,
        targetTimestampMs: nowMs,
        metadata: { resourceKey: pair.resourceKey },
      })
    } catch { /* ignore duplicate or already-recorded edge */ }
  }
  return seeded
}

/**
 * Unified table-driven causal composite planner shared by white-box code-audit suspect promotion
 * and grey-box runtime composite promotion (replaces duplicated 5-pattern matchers).
 */
export function planCompositeWorkflows<T extends CompositeWorkflowNode>(
  candidates: readonly T[],
  options: {
    maxComposites: number
    mode: 'whitebox' | 'runtime'
    depPairs?: readonly { prod: T; cons: T; resourceKey: string }[]
    ledger?: CapabilityLedger | null
  },
): PlannedCompositeWorkflow<T>[] {
  const maxComposites = Math.max(0, Math.floor(options.maxComposites))
  if (candidates.length < 2 || maxComposites <= 0) return []
  seedCompositeNodesToLedger(options.ledger, candidates, options.depPairs)

  const composites: PlannedCompositeWorkflow<T>[] = []
  const usedInPrior = new Set<string>()
  const emittedIdSets: ReadonlySet<string>[] = []

  const pick = (
    predicate: (c: T) => boolean,
    excludeIds: ReadonlySet<string>,
    anchor?: T,
  ): T | undefined => {
    let best: { c: T; score: number; idx: number } | undefined
    for (let idx = 0; idx < candidates.length; idx += 1) {
      const c = candidates[idx]!
      if (excludeIds.has(c.id) || !predicate(c)) continue
      let score = options.mode === 'runtime' ? (c.priorityScore ?? 50) : 0
      if (!usedInPrior.has(c.id)) score += options.mode === 'runtime' ? 20 : 4
      if (anchor) {
        if (options.mode === 'runtime' && c.origin !== anchor.origin) score += 28
        if (c.serviceScope !== anchor.serviceScope) score += options.mode === 'runtime' ? 10 : 3
        if (c.fileLoc && anchor.fileLoc && c.fileLoc !== anchor.fileLoc) score += 2
        if (c.sinkKind !== anchor.sinkKind) score += options.mode === 'runtime' ? 8 : 2
      }
      if (c.explicitSuspect) score += 1
      if (!best || score > best.score || (score === best.score && idx < best.idx)) {
        best = { c, score, idx }
      }
    }
    return best?.c
  }

  const record = (
    key: string,
    label: string,
    category: string,
    hops: T[],
    resourceKey?: string,
  ): void => {
    if (composites.length >= maxComposites || hops.length < 2) return
    const idSet = new Set(hops.map(h => h.id))
    if (emittedIdSets.some(prev => [...idSet].every(id => prev.has(id)))) return
    emittedIdSets.push(idSet)
    for (const h of hops) usedInPrior.add(h.id)
    composites.push({
      key,
      label,
      category,
      hops,
      ...(resourceKey ? { resourceKey } : {}),
      priority: Math.max(96, 98 - composites.length),
    })
  }

  const rules: CompositeWorkflowRule<T>[] = [
    {
      key: 'outbound_signing_webhook',
      entry: c => c.roles.has('outbound_fetch'),
      pivot: c => c.roles.has('signing_webhook'),
      terminal: c => c.roles.has('privileged_mutation'),
      terminalFallback: c => c.roles.has('auth_session'),
      label: t => t ? 'Outbound/SSRF -> Signing/Webhook -> Terminal Impact' : 'Outbound/SSRF -> Signing/Webhook Pivot',
      category: t => t ? 'broken-access-control' : 'auth-identity',
    },
    {
      key: 'disclosure_auth_mutation',
      entry: c => c.roles.has('info_disclosure') && c.sinkKind !== 'auth_config',
      entryFallback: c => c.roles.has('info_disclosure') || (options.mode === 'runtime' && Boolean(c.isApiDep)),
      pivot: c => c.roles.has('auth_session') && (options.mode === 'whitebox' ? c.sinkKind === 'auth_config' : true),
      pivotFallback: c => c.roles.has('auth_session'),
      terminal: c => c.roles.has('privileged_mutation') || (options.mode === 'runtime' && c.roles.has('async_worker')),
      label: t => t ? 'Disclosure -> Auth/Session -> Privileged Mutation' : 'Disclosure -> Auth/Session Pivot',
      category: () => 'broken-access-control',
    },
    ...(options.mode === 'whitebox'
      ? [
          {
            key: 'cache_permission_async_export',
            entry: (c: T) => c.roles.has('cache_permission'),
            pivot: (c: T) => c.roles.has('async_worker'),
            terminal: (c: T, p: T) => (c.roles.has('privileged_mutation') || c.roles.has('info_disclosure')) && c.id !== p.id,
            label: (t: boolean) => t
              ? 'Cache/Permission -> Async Export/Download -> Terminal Readback'
              : 'Cache/Permission -> Async Export/Download Pivot',
            category: () => 'broken-access-control',
          },
          {
            key: 'request_parsing_concurrent_settlement',
            entry: (c: T) => c.roles.has('request_parsing'),
            pivot: (c: T) => c.roles.has('concurrent_settlement'),
            terminal: (c: T, p: T) => (c.roles.has('privileged_mutation') || c.roles.has('async_worker')) && c.id !== p.id,
            label: (t: boolean) => t
              ? 'Request-Parsing -> Concurrent Settlement -> Terminal Conservation'
              : 'Request-Parsing -> Concurrent Settlement Pivot',
            category: () => 'business-logic',
          },
        ]
      : []),
  ]

  for (const rule of rules) {
    if (composites.length >= maxComposites) break
    const used = new Set<string>()
    const entry = pick(rule.entry, used) ?? (rule.entryFallback ? pick(rule.entryFallback, used) : undefined)
    if (!entry) continue
    used.add(entry.id)
    const pivot = pick(rule.pivot, used, entry) ?? (rule.pivotFallback ? pick(rule.pivotFallback, used, entry) : undefined)
    if (!pivot) continue
    used.add(pivot.id)
    const terminal = rule.terminal
      ? (pick(c => rule.terminal!(c, pivot), used, pivot)
        ?? (rule.terminalFallback ? pick(c => rule.terminalFallback!(c, pivot), used, pivot) : undefined))
      : undefined
    const hops = terminal ? [entry, pivot, terminal] : [entry, pivot]
    record(rule.key, rule.label(Boolean(terminal)), rule.category(Boolean(terminal)), hops)
  }

  // Runtime producer -> consumer API dependency composite
  if (options.mode === 'runtime' && composites.length < maxComposites && (options.depPairs?.length ?? 0) > 0) {
    const rankedDep = [...options.depPairs!].sort((a, b) =>
      Number(b.prod.origin !== b.cons.origin) - Number(a.prod.origin !== a.cons.origin)
      || ((b.prod.priorityScore ?? 50) + (b.cons.priorityScore ?? 50))
        - ((a.prod.priorityScore ?? 50) + (a.cons.priorityScore ?? 50)),
    )[0]!
    const used = new Set<string>([rankedDep.prod.id, rankedDep.cons.id])
    const terminal = pick(
      c => c.origin !== rankedDep.cons.origin || c.roles.has('privileged_mutation') || c.roles.has('async_worker'),
      used,
      rankedDep.cons,
    )
    const hops = terminal ? [rankedDep.prod, rankedDep.cons, terminal] : [rankedDep.prod, rankedDep.cons]
    record(
      'runtime_api_dependency',
      `Producer -> Consumer (${rankedDep.resourceKey})${terminal ? ' -> Cross-Boundary Pivot' : ''}`,
      'broken-access-control',
      hops,
      rankedDep.resourceKey,
    )
  }

  // White-box 2-hop Disclosure/Auth -> Privileged Mutation fallback
  if (options.mode === 'whitebox' && composites.length < maxComposites) {
    const used = new Set<string>()
    const leak = pick(c => c.roles.has('info_disclosure') && c.sinkKind !== 'auth_config', used)
      ?? pick(c => c.roles.has('info_disclosure'), used)
    if (leak) used.add(leak.id)
    const authPivot = !leak
      ? (pick(c => c.roles.has('auth_session') && c.sinkKind === 'auth_config', used)
        ?? pick(c => c.roles.has('auth_session'), used))
      : undefined
    if (authPivot) used.add(authPivot.id)
    const terminal = pick(c => c.roles.has('privileged_mutation'), used, authPivot ?? leak)
    const hops = [leak, authPivot, terminal].filter((h): h is T => Boolean(h))
    const hasCrossBoundaryDiversity = Boolean(leak && terminal)
      || new Set(hops.map(h => h.serviceScope)).size >= 2
      || new Set(hops.map(h => h.sinkKind)).size >= 2
    if (hops.length >= 2 && hasCrossBoundaryDiversity) {
      record(
        'disclosure_or_auth_mutation',
        leak && terminal ? 'Disclosure -> Privileged Cross-Tenant Pivot' : 'Auth/Session -> Privileged Mutation Pivot',
        'broken-access-control',
        hops,
      )
    }
  }

  // General cross-service (whitebox) or cross-origin (runtime) multi-sink fallback
  if (composites.length < maxComposites) {
    const crossReady = options.mode === 'runtime'
      ? new Set(candidates.map(c => c.origin)).size >= 2
      : new Set(candidates.map(c => c.serviceScope)).size >= 2 && new Set(candidates.map(c => c.sinkKind)).size >= 2
    if (crossReady) {
      const used = new Set<string>()
      const first = pick(
        c => c.roles.has('outbound_fetch') || c.roles.has('info_disclosure') || c.roles.has('auth_session') || c.roles.has('async_worker') || c.roles.size > 0,
        used,
      ) ?? pick(() => true, used)
      if (first) {
        used.add(first.id)
        const second = options.mode === 'runtime'
          ? (pick(c => c.origin !== first.origin && (c.roles.size > 0 || c.sinkKind !== first.sinkKind), used, first)
            ?? pick(c => c.origin !== first.origin, used, first))
          : pick(c => c.serviceScope !== first.serviceScope && c.sinkKind !== first.sinkKind, used, first)
        if (second) {
          used.add(second.id)
          const third = options.mode === 'runtime'
            ? (pick(c => c.origin !== first.origin && c.origin !== second.origin, used, second)
              ?? pick(c => c.roles.has('privileged_mutation') || c.roles.has('async_worker'), used, second))
            : pick(c => c.roles.has('privileged_mutation') && c.serviceScope !== second.serviceScope, used, second)
          const hops = third ? [first, second, third] : [first, second]
          const prefix = options.mode === 'runtime' ? 'Cross-Origin' : 'Cross-Service'
          const suffix = options.mode === 'runtime' ? 'Workflow' : 'Pivot'
          record(
            options.mode === 'runtime' ? 'cross_origin_runtime_workflow' : 'cross_service_multi_sink',
            `${prefix} ${first.sinkKind} -> ${second.sinkKind}${third ? ` -> ${third.sinkKind}` : ''} ${suffix}`,
            'broken-access-control',
            hops,
          )
        }
      }
    }
  }

  return composites
}

/**
 * Plan multi-hop causal hypotheses (depth 1..6) using `CapabilityLedger` causal lineage +
 * `FrontierScheduler` EVI-ranked beam search, enforcing `capability_only` quarantine,
 * negative-edge dead-end suppression, and bounded <= 2 KB hop-checkpoint briefs.
 */
export function planChainRound(args: PlanChainRoundArgs): ChainHypothesis[] {
  const maxHops = Math.max(MIN_CHAIN_DEPTH, Math.min(Math.floor(args.maxHops ?? 4), MAX_CHAIN_DEPTH))
  const minHops = Math.max(MIN_CHAIN_DEPTH, Math.min(Math.floor(args.minHops ?? (maxHops === 1 ? 1 : 2)), maxHops))
  const limit = resolveLimit(args.limit, 12)
  const beamWidth = clampBeamWidth(args.beamWidth ?? args.frontierScheduler?.beamWidth)
  const waveNo = Math.max(1, Math.floor(args.waveNo ?? 1))
  const maxBriefBytes = Math.min(MAX_CHECKPOINT_BRIEF_BYTES, Math.max(256, Math.floor(args.maxCheckpointBriefBytes ?? MAX_CHECKPOINT_BRIEF_BYTES)))
  const approved = args.approvedOrigins?.length ? new Set(args.approvedOrigins) : null
  const endpoints = args.endpoints ?? []
  const hops = args.hops ?? []
  const apiDependencies = args.apiDependencies ?? []
  const sourceMounted = args.sourceMounted === true
  const ledger = args.capabilityLedger ?? null
  const scheduler = args.frontierScheduler ?? null

  const { prunedKeys, strikeCountByKey, records } = collectNegativeEdgeState(ledger, scheduler)
  if (scheduler && records.length > 0) scheduler.seedNegativeEdges(records)

  const isPrunedCandidate = (units: readonly CausalPlanUnit[]): { pruned: boolean; attempts: number } => {
    const tail = units[units.length - 1]!
    const allCapIds = units.map(u => u.capId)
    const preCapIds = units.length > 1 ? units.slice(0, -1).map(u => u.capId) : allCapIds
    const keyPre = computeNegativeEdgeKey(preCapIds, tail.targetSurfaceKey, tail.hypothesisClass)
    const keyAll = computeNegativeEdgeKey(allCapIds, tail.targetSurfaceKey, tail.hypothesisClass)
    const pruned =
      prunedKeys.has(keyPre)
      || prunedKeys.has(keyAll)
      || Boolean(ledger?.isBranchPruned(preCapIds, tail.targetSurfaceKey, tail.hypothesisClass))
      || Boolean(ledger?.isBranchPruned(allCapIds, tail.targetSurfaceKey, tail.hypothesisClass))
      || Boolean(scheduler?.hasNegativeEdge(preCapIds, tail.targetSurfaceKey, tail.hypothesisClass))
      || Boolean(scheduler?.hasNegativeEdge(allCapIds, tail.targetSurfaceKey, tail.hypothesisClass))
    const attempts = Math.max(strikeCountByKey.get(keyPre) ?? 0, strikeCountByKey.get(keyAll) ?? 0)
    return { pruned, attempts }
  }

  const filteredPrimitives = args.primitives
    .filter(primitive => !approved || approved.has(primitive.origin))
    .slice()
    .sort((a, b) => PRIMITIVE_RANK[a.kind] - PRIMITIVE_RANK[b.kind]
      || (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0)
      || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0))

  const fallbackOrigin = args.approvedOrigins?.[0] ?? filteredPrimitives[0]?.origin ?? endpoints[0]?.origin ?? null
  const primitiveUnits = filteredPrimitives.map((primitive, idx) => primitiveToUnit(primitive, hops, idx))

  const ledgerNodes = ledger ? ledger.listCapabilities() : []
  const ledgerUnitsByCapId = new Map<string, CausalPlanUnit>()
  for (const node of ledgerNodes) {
    const unit = ledgerNodeToUnit(node, fallbackOrigin)
    if (!unit) continue
    if (approved && /^https?:\/\//i.test(node.serviceOrigin) && !approved.has(node.serviceOrigin)) continue
    ledgerUnitsByCapId.set(node.capId, unit)
  }

  const candidatesByKey = new Map<string, PlannedCausalCandidate>()
  const registerCandidate = (units: CausalPlanUnit[], bindings: CausalEdgeBindingKind[], verifiedEdgeCount: number, isLedgerDag: boolean): void => {
    if (units.length < minHops || units.length > maxHops) return
    // Quarantine enforcement: a single `capability_only` / always-quarantined node is NEVER
    // promoted as a standalone 1-hop hypothesis; it must compose into a multi-hop chain.
    if (units.length === 1 && (units[0]!.quarantined || !units[0]!.terminalEligible)) return
    const check = isPrunedCandidate(units)
    if (check.pruned) return
    const branch = buildCausalBranch({
      units,
      bindings,
      waveNo,
      verifiedEdgeCount,
      attemptsOnBranch: check.attempts,
    })
    const evi = computeBranchEvi(branch)
    const prev = candidatesByKey.get(branch.branchKey)
    if (!prev || evi > prev.evi) {
      candidatesByKey.set(branch.branchKey, { branch, units, bindings, evi, isLedgerDag })
    }
  }

  // 1. Walk explicit CapabilityLedger causal DAG edges (verified depth 1..6 lineage).
  const ledgerEdges: CausalEdge[] = ledger ? ledger.listCausalEdges() : []
  if (ledgerUnitsByCapId.size > 0) {
    const outgoing = new Map<string, CausalEdge[]>()
    const hasIncoming = new Set<string>()
    for (const edge of ledgerEdges) {
      if (edge.postconditionCapId) hasIncoming.add(edge.postconditionCapId)
      for (const preId of edge.preconditionCapIds) {
        const bucket = outgoing.get(preId) ?? []
        bucket.push(edge)
        outgoing.set(preId, bucket)
      }
    }
    const allLedgerUnits = [...ledgerUnitsByCapId.values()]
    const rootUnits = allLedgerUnits.filter(u => !hasIncoming.has(u.capId))
    const startUnits = rootUnits.length > 0 ? rootUnits : allLedgerUnits

    const walkDag = (path: CausalPlanUnit[], bindings: CausalEdgeBindingKind[], verifiedEdges: number): void => {
      registerCandidate(path, bindings, verifiedEdges, true)
      if (path.length >= maxHops) return
      const tip = path[path.length - 1]!
      const visited = new Set(path.map(u => u.capId))
      const nextEdges = outgoing.get(tip.capId) ?? []
      let extendedViaEdge = false
      for (const edge of nextEdges) {
        if (!edge.postconditionCapId || visited.has(edge.postconditionCapId)) continue
        const nextUnit = ledgerUnitsByCapId.get(edge.postconditionCapId)
        if (!nextUnit) continue
        extendedViaEdge = true
        walkDag([...path, nextUnit], [...bindings, edge.edgeBindingKind], verifiedEdges + 1)
      }
      // If a verified DAG path reaches a frontier tip, allow causal extension onto compatible
      // unvisited ledger targets (e.g., synthesized policy_asymmetry / state_handle seeds).
      if (!extendedViaEdge && path.length < maxHops) {
        const extensions: PlannedCausalCandidate[] = []
        for (const nextUnit of allLedgerUnits) {
          if (visited.has(nextUnit.capId)) continue
          if (nextUnit.capKind === tip.capKind && nextUnit.surface === tip.surface) continue
          const nextUnits = [...path, nextUnit]
          const check = isPrunedCandidate(nextUnits)
          if (check.pruned) continue
          const nextBindings = [...bindings, inferCausalBinding(tip, nextUnit)]
          const branch = buildCausalBranch({
            units: nextUnits,
            bindings: nextBindings,
            waveNo,
            verifiedEdgeCount: verifiedEdges,
            attemptsOnBranch: check.attempts,
          })
          extensions.push({ branch, units: nextUnits, bindings: nextBindings, evi: computeBranchEvi(branch), isLedgerDag: true })
        }
        extensions.sort((a, b) => b.evi - a.evi || a.branch.branchKey.localeCompare(b.branch.branchKey))
        for (const ext of extensions.slice(0, Math.min(4, beamWidth))) {
          registerCandidate(ext.units, ext.bindings, verifiedEdges, true)
        }
      }
    }

    for (const root of startUnits) {
      walkDag([root], [], 0)
    }
  }

  // 1b. Seed producer->consumer API dependency chains & cross-origin runtime edges (critical for
  //     grey-box mode where `!sourceMounted`, and additive when mounted source also exists).
  const runtimeUnits: CausalPlanUnit[] = []
  const unitByRouteKey = new Map<string, CausalPlanUnit>()
  for (const unit of [...primitiveUnits, ...ledgerUnitsByCapId.values()]) {
    const key = `${unit.serviceOrigin}|${unit.method.toUpperCase()}|${unit.endpoint}`
    if (!unitByRouteKey.has(key)) unitByRouteKey.set(key, unit)
  }
  const endpointsById = new Map<string, CoordinatorEndpoint>()
  const endpointsByMethodPath = new Map<string, CoordinatorEndpoint>()
  for (const ep of endpoints) {
    if (approved && !approved.has(ep.origin)) continue
    endpointsById.set(ep.id, ep)
    const mk = `${ep.method.toUpperCase()} ${ep.pathTemplate}`
    if (!endpointsByMethodPath.has(mk)) endpointsByMethodPath.set(mk, ep)
    const wk = `* ${ep.pathTemplate}`
    if (!endpointsByMethodPath.has(wk)) endpointsByMethodPath.set(wk, ep)
  }

  let runtimeUnitOrd = 0
  const getOrCreateRuntimeUnit = (spec: {
    origin: string
    method: string
    endpoint: string
    endpointId?: string
    resourceKey?: string
    persona?: string | null
    detail: string
    sinkKinds?: readonly string[]
    unitTag: string
  }): CausalPlanUnit => {
    const key = `${spec.origin}|${spec.method.toUpperCase()}|${spec.endpoint}`
    const existing = unitByRouteKey.get(key)
    if (existing) return existing
    runtimeUnitOrd += 1
    const created = makeRuntimePlanUnit({ ...spec, ordinal: runtimeUnitOrd })
    unitByRouteKey.set(key, created)
    runtimeUnits.push(created)
    return created
  }

  if (apiDependencies.length > 0) {
    const depOutgoing = new Map<string, Array<{ next: CausalPlanUnit; binding: CausalEdgeBindingKind }>>()
    const depIncoming = new Set<string>()
    const depStarts: CausalPlanUnit[] = []
    const depStartSeen = new Set<string>()
    const depByPathPrefix = new Map<string, CausalPlanUnit[]>()

    for (const dep of apiDependencies.slice(0, 64)) {
      const prod = resolveDependencySide(
        dep.producerEndpointId, dep.producer, dep.producerOrigin, dep.producerMethod,
        endpointsById, endpointsByMethodPath, fallbackOrigin,
      )
      const cons = resolveDependencySide(
        dep.consumerEndpointId, dep.consumer, dep.consumerOrigin, dep.consumerMethod,
        endpointsById, endpointsByMethodPath, prod?.origin ?? fallbackOrigin,
      )
      if (!prod || !cons) continue
      if (approved && (!approved.has(prod.origin) || !approved.has(cons.origin))) continue
      if (prod.origin === cons.origin && prod.method === cons.method && prod.endpoint === cons.endpoint) continue

      const prodUnit = getOrCreateRuntimeUnit({
        ...prod,
        resourceKey: dep.resourceKey,
        persona: dep.personaHandle,
        detail: `API dependency producer ${prod.method} ${prod.endpoint} yields resource "${dep.resourceKey}"`,
        unitTag: 'apidep_prod',
      })
      const consUnit = getOrCreateRuntimeUnit({
        ...cons,
        resourceKey: dep.resourceKey,
        persona: dep.personaHandle,
        detail: `API dependency consumer ${cons.method} ${cons.endpoint} consumes resource "${dep.resourceKey}"`,
        unitTag: 'apidep_cons',
      })
      const binding = inferCausalBinding(prodUnit, consUnit)
      const bucket = depOutgoing.get(prodUnit.capId) ?? []
      if (!bucket.some(e => e.next.capId === consUnit.capId)) {
        bucket.push({ next: consUnit, binding })
        depOutgoing.set(prodUnit.capId, bucket)
      }
      depIncoming.add(consUnit.capId)
      if (!depStartSeen.has(prodUnit.capId)) {
        depStartSeen.add(prodUnit.capId)
        depStarts.push(prodUnit)
      }
      const prodPathKey = `${prodUnit.serviceOrigin}|${prodUnit.endpoint}`
      const pList = depByPathPrefix.get(prodPathKey) ?? []
      if (!pList.some(u => u.capId === prodUnit.capId)) {
        pList.push(prodUnit)
        depByPathPrefix.set(prodPathKey, pList)
      }
    }

    const rootDeps = depStarts.filter(u => !depIncoming.has(u.capId))
    const startNodes = rootDeps.length > 0 ? rootDeps : depStarts
    const walkApiDeps = (path: CausalPlanUnit[], bindings: CausalEdgeBindingKind[]): void => {
      if (path.length >= minHops) registerCandidate(path, bindings, path.length - 1, false)
      if (path.length >= maxHops) return
      const tip = path[path.length - 1]!
      const visited = new Set(path.map(u => u.capId))
      const directNext = depOutgoing.get(tip.capId) ?? []
      // Also allow chaining when consumer's path matches another dependency producer's path (different HTTP method).
      const pathAliasProducers = (depByPathPrefix.get(`${tip.serviceOrigin}|${tip.endpoint}`) ?? [])
        .filter(u => u.capId !== tip.capId)
      const aliasNext = pathAliasProducers.flatMap(u => depOutgoing.get(u.capId) ?? [])
      const nextEdges = [...directNext, ...aliasNext]
      let extended = false
      for (const edge of nextEdges.slice(0, 6)) {
        if (visited.has(edge.next.capId)) continue
        extended = true
        walkApiDeps([...path, edge.next], [...bindings, edge.binding])
      }
      // If a dependency path stops short of maxHops and another origin has a ledger/primitive unit,
      // extend across the cross-origin boundary so GB dependency chains reach multi-origin targets.
      if (!extended && path.length < maxHops) {
        const crossOriginTargets = [...ledgerUnitsByCapId.values(), ...primitiveUnits]
          .filter(u => !visited.has(u.capId) && u.serviceOrigin !== tip.serviceOrigin)
          .slice(0, 3)
        for (const target of crossOriginTargets) {
          registerCandidate([...path, target], [...bindings, inferCausalBinding(tip, target)], path.length - 1, false)
        }
      }
    }
    for (const root of startNodes.slice(0, 16)) {
      walkApiDeps([root], [])
    }
  }

  // In grey-box mode (`!sourceMounted`), synthesize cross-origin runtime boundary units when the
  // discovered endpoint surface spans >= 2 approved origins so multi-origin chains seed in Round 1.
  if (!sourceMounted) {
    const runtimeByOrigin = new Map<string, CoordinatorEndpoint[]>()
    for (const ep of endpoints) {
      if (approved && !approved.has(ep.origin)) continue
      if (ep.pathTemplate === '/' || /^\/(?:health|healthz|ready|metrics|favicon)/i.test(ep.pathTemplate)) continue
      const list = runtimeByOrigin.get(ep.origin) ?? []
      list.push(ep)
      runtimeByOrigin.set(ep.origin, list)
    }
    if (runtimeByOrigin.size >= 2) {
      const originSeedUnits: CausalPlanUnit[] = []
      const sortedOrigins = [...runtimeByOrigin.keys()].sort()
      for (const origin of sortedOrigins) {
        const eps = (runtimeByOrigin.get(origin) ?? [])
          .slice()
          .sort((a, b) =>
            ((b.riskScore ?? 50) - (a.riskScore ?? 50))
            || Number(isRoleExclusive(b) || SEMANTIC_MUTATING_METHODS.has(b.method.toUpperCase()))
              - Number(isRoleExclusive(a) || SEMANTIC_MUTATING_METHODS.has(a.method.toUpperCase()))
            || a.pathTemplate.localeCompare(b.pathTemplate))
        let pickedForOrigin = 0
        for (const ep of eps) {
          if (pickedForOrigin >= 3 || originSeedUnits.length >= 12) break
          const kind = inferRuntimeRoutePrimitiveKind(ep.method, ep.pathTemplate, '', ep.sinkKinds)
          const hasSignal = (ep.riskScore ?? 0) >= 65
            || isRoleExclusive(ep)
            || isMissingAuthGuard(ep)
            || kind !== 'discovered_id'
            || classifySemanticEndpointClasses(ep).length > 0
          if (!hasSignal) continue
          const unit = getOrCreateRuntimeUnit({
            origin: ep.origin,
            method: ep.method,
            endpoint: ep.pathTemplate,
            endpointId: ep.id,
            sinkKinds: ep.sinkKinds,
            detail: `Cross-origin runtime surface ${ep.method.toUpperCase()} ${ep.pathTemplate} on ${hostOf(ep.origin)}`,
            unitTag: 'xorigin',
          })
          if (!originSeedUnits.some(u => u.capId === unit.capId)) {
            originSeedUnits.push(unit)
            pickedForOrigin += 1
          }
        }
      }
      // Seed bounded 2-hop and 3-hop cross-origin runtime transitions across distinct origins.
      for (let i = 0; i < originSeedUnits.length; i += 1) {
        const first = originSeedUnits[i]!
        for (let j = i + 1; j < originSeedUnits.length; j += 1) {
          const second = originSeedUnits[j]!
          if (first.serviceOrigin === second.serviceOrigin) continue
          const pairBindings: CausalEdgeBindingKind[] = [inferCausalBinding(first, second)]
          registerCandidate([first, second], pairBindings, 0, false)
          if (maxHops >= 3) {
            const third = originSeedUnits.find((u, k) =>
              k !== i && k !== j
              && u.serviceOrigin !== first.serviceOrigin
              && u.serviceOrigin !== second.serviceOrigin,
            ) ?? originSeedUnits.find((u, k) =>
              k !== i && k !== j
              && u.serviceOrigin !== second.serviceOrigin
              && u.capKind !== second.capKind,
            )
            if (third) {
              registerCandidate(
                [first, second, third],
                [...pairBindings, inferCausalBinding(second, third)],
                0,
                false,
              )
            }
          }
        }
      }
    }
  }

  // 2. Beam-search causal composition across primitives + ledger capability nodes + runtime units (depth up to maxHops <= 6).
  //    Replaces v7's flat lookup tables with bounded EVI beam expansion via `rankAndPruneBeam`.
  const allUnits: CausalPlanUnit[] = [...primitiveUnits]
  const existingCapIds = new Set(allUnits.map(u => u.capId))
  for (const unit of [...ledgerUnitsByCapId.values(), ...runtimeUnits]) {
    if (!existingCapIds.has(unit.capId)) {
      existingCapIds.add(unit.capId)
      allUnits.push(unit)
    }
  }

  if (allUnits.length > 0) {
    // Seed depth-1 frontier states (even quarantined nodes may serve as Hop-1 prefixes for depth >= 2).
    let beamPaths: Array<{ units: CausalPlanUnit[]; bindings: CausalEdgeBindingKind[]; lastIdx: number }> = allUnits.map((unit, idx) => ({
      units: [unit],
      bindings: [],
      lastIdx: idx,
    }))
    if (minHops === 1) {
      for (const seed of beamPaths) registerCandidate(seed.units, [], 0, false)
    }

    for (let depth = 2; depth <= maxHops; depth += 1) {
      const nextByKey = new Map<string, { branch: FrontierBranch; units: CausalPlanUnit[]; bindings: CausalEdgeBindingKind[]; lastIdx: number }>()
      for (const prefix of beamPaths) {
        const usedKinds = new Set(prefix.units.map(u => u.primitive.kind))
        const usedCaps = new Set(prefix.units.map(u => u.capId))
        for (let idx = prefix.lastIdx + 1; idx < allUnits.length; idx += 1) {
          const next = allUnits[idx]!
          if (usedCaps.has(next.capId)) continue
          // Avoid degenerate same-kind primitive pairs unless backed by distinct ledger surfaces,
          // cross-origin transitions, or explicit runtime API dependency edges.
          const isDistinctLedgerSurface = next.unitId.startsWith('ledger:') && prefix.units.every(u => u.surface !== next.surface)
          const isCrossOriginTransition = prefix.units.every(u => u.serviceOrigin !== next.serviceOrigin)
          const isRuntimeDepUnit = next.unitId.startsWith('rt:apidep_')
          if (usedKinds.has(next.primitive.kind) && !isDistinctLedgerSurface && !isCrossOriginTransition && !isRuntimeDepUnit) continue
          const nextUnits = [...prefix.units, next]
          const check = isPrunedCandidate(nextUnits)
          if (check.pruned) continue
          const nextBindings = [...prefix.bindings, inferCausalBinding(prefix.units[prefix.units.length - 1]!, next)]
          const branch = buildCausalBranch({
            units: nextUnits,
            bindings: nextBindings,
            waveNo,
            verifiedEdgeCount: 0,
            attemptsOnBranch: check.attempts,
          })
          if (!nextByKey.has(branch.branchKey)) {
            nextByKey.set(branch.branchKey, { branch, units: nextUnits, bindings: nextBindings, lastIdx: idx })
          }
        }
      }
      if (nextByKey.size === 0) break

      // Bound each depth's active frontier through FrontierScheduler's exact EVI beam ranker.
      const depthBeamLimit = Math.max(beamWidth, Math.min(beamWidth * 2, limit * 2))
      const ranked = rankAndPruneBeam(
        [...nextByKey.values()].map(item => item.branch),
        depthBeamLimit,
        prunedKeys,
      )
      // Also preserve top branches across distinct depths/scopes before capping beam expansion.
      const keptPaths: Array<{ units: CausalPlanUnit[]; bindings: CausalEdgeBindingKind[]; lastIdx: number }> = []
      for (const scored of ranked) {
        const item = nextByKey.get(scored.branch.branchKey)
        if (!item) continue
        registerCandidate(item.units, item.bindings, 0, false)
        keptPaths.push({ units: item.units, bindings: item.bindings, lastIdx: item.lastIdx })
      }
      beamPaths = keptPaths
    }
  }

  // 3. Final EVI-ranked selection with depth diversity (preserving top deep chains & 2-hop baselines).
  const allCandidates = [...candidatesByKey.values()].sort((a, b) =>
    Number(b.isLedgerDag) - Number(a.isLedgerDag)
    || b.evi - a.evi
    || b.units.length - a.units.length
    || Number(new Set(a.units.map(u => u.primitive.origin)).size > 1) - Number(new Set(b.units.map(u => u.primitive.origin)).size > 1)
    || a.branch.branchKey.localeCompare(b.branch.branchKey))

  const selected: PlannedCausalCandidate[] = []
  const selectedKeys = new Set<string>()
  const pick = (candidate: PlannedCausalCandidate): void => {
    if (selected.length >= limit || selectedKeys.has(candidate.branch.branchKey)) return
    selectedKeys.add(candidate.branch.branchKey)
    selected.push(candidate)
  }

  // Reserve at least one top candidate per achievable depth (deepest first) so deep chains
  // (3..6 hops) are never starved out of the top-N frontier slice by shallow 2-hop pairs.
  for (let depth = maxHops; depth >= minHops; depth -= 1) {
    const topForDepth = allCandidates.find(c => c.units.length === depth)
    if (topForDepth) pick(topForDepth)
  }
  for (const candidate of allCandidates) {
    if (selected.length >= limit) break
    pick(candidate)
  }

  if (scheduler) {
    for (const candidate of selected) {
      scheduler.admitBranch(candidate.branch)
    }
  }

  const counters = new Map<string, number>()
  return selected
    .map(candidate => buildHypothesisFromCausalCandidate(candidate, endpoints, hops, maxBriefBytes, 0))
    .sort((a, b) =>
      (b.evi ?? 0) - (a.evi ?? 0)
      || b.confidence - a.confidence
      || b.hops - a.hops
      || Number(a.scope === 'cross_origin') - Number(b.scope === 'cross_origin')
      || (a.title < b.title ? -1 : a.title > b.title ? 1 : 0))
    .slice(0, limit)
    .map(hypothesis => {
      const key = `${hypothesis.scope}:${hypothesis.primitiveKinds.join('>')}`
      const ordinal = (counters.get(key) ?? 0) + 1
      counters.set(key, ordinal)
      return { ...hypothesis, id: `chain:${key}:${ordinal}` }
    })
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
    if (!parentEvidenceIds.length) return reject('missing_parent_evidence', 'Hypothesis must cite at least one parent evidence id.')
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

export interface GraphCoordinatorOptions {
  deps: CoordinatorDeps
  approvedOrigins?: readonly string[]
  budgetUsd?: number
  maxDispatchSteps?: number
  allowedCapabilities?: readonly CoordinatorCapability[]
}

export interface GraphCoordinator {
  queryEndpoints(args?: QueryEndpointsArgs): CoordinatorPage<CoordinatorEndpoint>
  queryProgramGraph(args: QueryProgramGraphArgs): ProgramGraphPage<ProgramSinkItem | MiddlewareDiffItem | GitHotspotItem>
  queryFacts(args?: QueryFactsArgs): CoordinatorPage<CoordinatorFact>
  queryFindings(args: QueryFindingsArgs): FindingsPage
  dispatchInvestigations(steps: readonly DispatchStepInput[], options?: DispatchOptions): DispatchPlan
  deriveChainPrimitives(): ChainPrimitive[]
  extractChainHops(roundNo?: number, priorHops?: readonly ChainHop[]): ChainHop[]
  planChainRound(args?: Partial<Omit<PlanChainRoundArgs, 'primitives'>>): ChainHypothesis[]
  decideNext(input: SchedulerInput): SchedulerDecision
}

/** Bind the pure tools to one run's deps and scope/budget defaults. */
export function createGraphCoordinator(options: GraphCoordinatorOptions): GraphCoordinator {
  const { deps } = options
  const approvedOrigins = (): readonly string[] => options.approvedOrigins ?? deps.approvedOrigins?.() ?? []
  const primitives = (): ChainPrimitive[] => deriveChainPrimitives({
    facts: deps.listFacts(), findings: deps.listFindings(), endpoints: deps.listEndpoints(),
  })
  const chainHops = (roundNo = 1, priorHops: readonly ChainHop[] = []): ChainHop[] => extractChainHops({
    facts: deps.listFacts(), findings: deps.listFindings(), endpoints: deps.listEndpoints(), roundNo, priorHops,
  })
  return {
    queryEndpoints: (args = {}) => queryEndpoints(deps, args),
    queryProgramGraph: args => queryProgramGraph(deps, args),
    queryFacts: (args = {}) => queryFacts(deps, args),
    queryFindings: args => queryFindings(deps, args),
    dispatchInvestigations: (steps, dispatch = {}) => dispatchInvestigations(steps, {
      approvedOrigins: dispatch.approvedOrigins ?? approvedOrigins(),
      budgetUsd: dispatch.budgetUsd ?? options.budgetUsd,
      maxSteps: dispatch.maxSteps ?? options.maxDispatchSteps,
      allowedCapabilities: dispatch.allowedCapabilities ?? options.allowedCapabilities,
    }),
    deriveChainPrimitives: primitives,
    extractChainHops: chainHops,
    planChainRound: args => planChainRound({
      ...args,
      primitives: primitives(),
      hops: args?.hops ?? chainHops(),
      endpoints: args?.endpoints ?? deps.listEndpoints(),
      apiDependencies: args?.apiDependencies ?? deps.listApiDependencies?.(),
      approvedOrigins: args?.approvedOrigins ?? approvedOrigins(),
      capabilityLedger: args?.capabilityLedger !== undefined ? args.capabilityLedger : (deps.capabilityLedger?.() ?? null),
      frontierScheduler: args?.frontierScheduler !== undefined ? args.frontierScheduler : (deps.frontierScheduler?.() ?? null),
    }),
    decideNext,
  }
}
