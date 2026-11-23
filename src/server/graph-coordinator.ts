/**
 * Graph Coordinator — v6 Phase 4 pure coordinator core (plans/better-architecture.md §3.3).
 *
 * Replaces `execution.ts`'s stateless single-shot `runChainPlanner` with five paginated
 * read/dispatch tools, typed chain primitives and an explicit chaining round. The module is
 * standalone (zero imports): data arrives through `CoordinatorDeps`, so wiring can adapt the live
 * store/program graph after v6-delete releases `execution.ts`.
 *
 * Pure and deterministic: identical deps + arguments produce identical output. Dispatch never
 * performs HTTP — it validates and normalises hypotheses into a plan for Layer 1.
 * Chain primitives never carry raw credentials: secrets are represented by `secret:<factId>`.
 */

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

/** Complete, untruncated data access (adapters page the store past its default page size). */
export interface CoordinatorDeps {
  listEndpoints(): readonly CoordinatorEndpoint[]
  listFacts(): readonly CoordinatorFact[]
  listFindings(): readonly CoordinatorFinding[]
  programGraph?(): CoordinatorProgramGraph | null
  commitSignals?(): readonly CoordinatorCommitSignal[]
  approvedOrigins?(): readonly string[]
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

export interface QueryEndpointsArgs {
  cursor?: string
  limit?: number
  uncoveredOnly?: boolean
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
    .filter(endpoint => !args.hasSink || (endpoint.sinkKinds?.length ?? 0) > 0)
    .filter(endpoint => !args.missingAuthGuard || isMissingAuthGuard(endpoint))
    .filter(endpoint => !args.roleExclusive || isRoleExclusive(endpoint))
    .filter(endpoint => !prefix || endpoint.pathTemplate.toLowerCase().startsWith(prefix))
    .slice()
    .sort((a, b) =>
      (b.riskScore ?? 0) - (a.riskScore ?? 0)
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
// Chain primitives
// ---------------------------------------------------------------------------

export type ChainPrimitiveKind = 'leaked_token' | 'discovered_id' | 'ssrf_internal_reach' | 'stored_write' | 'weak_jwt' | 'admin_route'

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
  leaked_token: 0, weak_jwt: 1, discovered_id: 2, ssrf_internal_reach: 3, stored_write: 4, admin_route: 5,
}

export interface DeriveChainPrimitivesInput {
  facts?: readonly CoordinatorFact[]
  findings?: readonly CoordinatorFinding[]
  endpoints?: readonly CoordinatorEndpoint[]
}

const dedupe = (values: readonly string[]): string[] => [...new Set(values.filter(value => typeof value === 'string' && value.length > 0))]
const matches = (text: string, patterns: readonly RegExp[]): boolean => patterns.some(pattern => pattern.test(text))

/** Derive typed, deduplicated chain tags from untainted facts, confirmed findings and endpoints. */
export function deriveChainPrimitives(input: DeriveChainPrimitivesInput): ChainPrimitive[] {
  const out: ChainPrimitive[] = []

  for (const fact of input.facts ?? []) {
    if (fact.tainted) continue
    const data = fact.data ?? {}
    const subkind = str(data.subkind) ?? ''
    const probeClass = str(data.probeClass) ?? ''
    const text = `${subkind} ${probeClass} ${str(data.kind) ?? ''}`.toLowerCase()
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
    const ssrfText = `${text} ${anomalyTypes} ${str(data.internalTarget) ?? ''}`

    if (fact.kind === 'secret' || matches(text, [/leak(?:ed)?[_-]?token/, /token[_-]?leak/, /credential[_-]?leak/, /secret[_-]?exposure/, /api[_-]?key[_-]?(?:exposed|leak)/])) {
      out.push({ ...base, kind: 'leaked_token', value: `secret:${fact.id}`, detail: 'Leaked credential material recorded as a secret fact (value withheld).' })
    }
    if ((fact.kind === 'object_ref' || subkind === 'persona_resource') && resourceId && resourceId !== '[redacted]') {
      out.push({ ...base, kind: 'discovered_id', value: resourceId, detail: `Discovered object identifier ${truncate(resourceId, 48)}${endpoint ? ` at ${endpoint}` : ''}.` })
    }
    if (matches(ssrfText, [/ssrf/, /internal[_-]?(?:reach|fetch|target)/, /oob[_-]?(?:callback|hit)/]) || probeClass.toLowerCase().startsWith('ssrf')) {
      out.push({ ...base, kind: 'ssrf_internal_reach', value: `ssrf:${endpoint ?? fact.id}`, detail: `Server-side fetch reached internal/out-of-band infrastructure via ${endpoint ?? 'a recorded sink'}.` })
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
    if (matches(text, [/ssrf/, /server[ -]?side request/, /internal (?:reach|metadata|network)/])) {
      out.push({ ...base, kind: 'ssrf_internal_reach', value: `finding:${finding.id}`, detail: `Confirmed server-side request reach (${claim}).` })
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

// ---------------------------------------------------------------------------
// Explicit chaining round
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
}

export interface PlanChainRoundArgs {
  primitives: readonly ChainPrimitive[]
  endpoints?: readonly CoordinatorEndpoint[]
  maxHops?: number
  limit?: number
  approvedOrigins?: readonly string[]
}

const PAIR_WEIGHTS: Readonly<Record<string, number>> = {
  'admin_route+leaked_token': 0.86, 'admin_route+weak_jwt': 0.84, 'discovered_id+leaked_token': 0.80,
  'discovered_id+stored_write': 0.78, 'ssrf_internal_reach+stored_write': 0.82, 'admin_route+stored_write': 0.74,
  'discovered_id+admin_route': 0.75, 'leaked_token+ssrf_internal_reach': 0.76, 'discovered_id+weak_jwt': 0.72,
  'admin_route+ssrf_internal_reach': 0.70, 'discovered_id+ssrf_internal_reach': 0.68,
}

const THREE_HOP_SETS: ReadonlySet<string> = new Set([
  'discovered_id+ssrf_internal_reach+stored_write', 'admin_route+discovered_id+leaked_token',
  'admin_route+discovered_id+weak_jwt', 'leaked_token+ssrf_internal_reach+stored_write',
  'admin_route+ssrf_internal_reach+stored_write',
])

const keyOf = (kinds: readonly ChainPrimitiveKind[]): string => [...kinds].sort().join('+')
const PROBE_CLASS: Record<ChainPrimitiveKind, string> = {
  leaked_token: 'authz_replay', discovered_id: 'bola_idor', ssrf_internal_reach: 'ssrf',
  stored_write: 'stored_xss', weak_jwt: 'jwt_forgery', admin_route: 'auth_bypass',
}
const hostOf = (origin: string): string => origin.replace(/^https?:\/\//, '')

function capabilitySet(kinds: readonly ChainPrimitiveKind[]): CoordinatorCapability[] {
  return COORDINATOR_CAPABILITIES.filter(capability =>
    capability === 'http'
    || (capability === 'oob' && kinds.includes('ssrf_internal_reach'))
    || (capability === 'browser' && kinds.includes('stored_write')))
}

function endpointFor(primitive: ChainPrimitive, endpoints: readonly CoordinatorEndpoint[]): CoordinatorEndpoint | undefined {
  return primitive.endpointId
    ? endpoints.find(endpoint => endpoint.id === primitive.endpointId)
    : endpoints.find(endpoint => endpoint.origin === primitive.origin && endpoint.pathTemplate === primitive.endpoint
      && (!primitive.method || endpoint.method.toUpperCase() === primitive.method))
}

function buildHypothesis(scope: ChainScope, chain: readonly ChainPrimitive[], endpoints: readonly CoordinatorEndpoint[], ordinal: number): ChainHypothesis {
  const kinds = chain.map(primitive => primitive.kind)
  const origins = [...new Set(chain.map(primitive => primitive.origin))]
  const entry = chain.map(primitive => endpointFor(primitive, endpoints)).find(Boolean)
  const target = [...chain].reverse().map(primitive => endpointFor(primitive, endpoints)).find(Boolean)
  const base = chain.length === 2
    ? PAIR_WEIGHTS[keyOf(kinds)] ?? 0.55
    : Math.min(PAIR_WEIGHTS[keyOf(kinds.slice(0, 2))] ?? 0.55, PAIR_WEIGHTS[keyOf(kinds.slice(1))] ?? 0.55, 0.9)
  return {
    id: `chain:${scope}:${kinds.join('>')}:${ordinal}`,
    scope, hops: chain.length, origin: chain[0].origin, chainOrigins: origins, primitiveKinds: kinds,
    parentEvidenceIds: dedupe(chain.flatMap(primitive => [...primitive.evidenceIds, ...primitive.factIds])),
    title: `${kinds.join(' → ')} chain on ${origins.map(hostOf).join(' → ')}`,
    rationale: `Connect ${chain.map(primitive => primitive.detail).join(' Then ')}`,
    probeClasses: [...new Set(kinds.map(kind => PROBE_CLASS[kind]))].sort(),
    capabilities: capabilitySet(kinds),
    confidence: Math.round((base - (chain.length - 2) * 0.03) * 100) / 100,
    ...(entry ? { entry: { endpoint: entry.pathTemplate, method: entry.method, origin: entry.origin } } : {}),
    ...(target ? { target: { endpoint: target.pathTemplate, method: target.method, origin: target.origin } } : {}),
  }
}

/**
 * Propose explicit 2–3 hop hypotheses over the full primitive set: same-origin chains pair
 * primitives on one target; cross-origin chains pair a credential/ID from one approved origin
 * with a privileged or stateful surface on another. Every hypothesis carries parent evidence.
 */
export function planChainRound(args: PlanChainRoundArgs): ChainHypothesis[] {
  const maxHops = Math.max(2, Math.min(Math.floor(args.maxHops ?? 3), 3))
  const limit = resolveLimit(args.limit, 12)
  const approved = args.approvedOrigins?.length ? new Set(args.approvedOrigins) : null
  const endpoints = args.endpoints ?? []
  const primitives = args.primitives
    .filter(primitive => !approved || approved.has(primitive.origin))
    .slice()
    .sort((a, b) => PRIMITIVE_RANK[a.kind] - PRIMITIVE_RANK[b.kind]
      || (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0)
      || (a.value < b.value ? -1 : a.value > b.value ? 1 : 0))

  const chains: Array<{ scope: ChainScope; chain: ChainPrimitive[] }> = []
  const push = (chain: ChainPrimitive[]): void => {
    chains.push({ scope: new Set(chain.map(primitive => primitive.origin)).size === 1 ? 'same_origin' : 'cross_origin', chain })
  }
  for (let i = 0; i < primitives.length; i += 1) {
    for (let j = i + 1; j < primitives.length; j += 1) {
      const pair = [primitives[i], primitives[j]]
      if (pair[0].kind === pair[1].kind || !PAIR_WEIGHTS[keyOf(pair.map(primitive => primitive.kind))]) continue
      push(pair)
      if (maxHops < 3) continue
      for (let k = j + 1; k < primitives.length; k += 1) {
        const third = primitives[k]
        const kinds = [...pair.map(primitive => primitive.kind), third.kind]
        if (new Set(kinds).size === 3 && THREE_HOP_SETS.has(keyOf(kinds))) push([...pair, third])
      }
    }
  }

  const counters = new Map<string, number>()
  return chains
    .map(chain => buildHypothesis(chain.scope, chain.chain, endpoints, 0))
    .sort((a, b) => b.confidence - a.confidence
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
    plan.push({
      id: `dispatch-${plan.length + 1}`,
      hypothesis, origins, capabilities: capabilities.values, parentEvidenceIds,
      budgetUsd: stepBudget,
      ...(step.probeClass?.trim() ? { probeClass: step.probeClass.trim() } : {}),
      ...(step.expectedSignal?.trim() ? { expectedSignal: step.expectedSignal.trim() } : {}),
      skills: [...new Set((step.skills ?? []).map(skill => skill.trim()).filter(Boolean))].sort(),
      priority: Math.max(0, Math.min(100, Math.round(step.priority ?? 50))),
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
    planChainRound: args => planChainRound({
      ...args, primitives: primitives(), endpoints: args?.endpoints ?? deps.listEndpoints(),
      approvedOrigins: args?.approvedOrigins ?? approvedOrigins(),
    }),
    decideNext,
  }
}
