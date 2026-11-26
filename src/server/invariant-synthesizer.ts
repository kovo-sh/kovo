/** General Invariant Synthesizer (v8 Layer 2 — White-Box + Runtime Parity). All capabilities stay quarantined as `capability_only`. */
import {
  buildLineIndex,
  extractLineRange,
  lineAtOffset,
  type LineIndex,
  type MonorepoService,
  type ProgramGraph,
  type ProgramNode,
  type ProgramRoute,
  type ProgramSinkKind,
  type ServiceOriginMapping,
} from './program-graph.ts'
import { snapshotSourceFiles, type StaticWorkspaceSnapshot } from './static-workspace-snapshot.ts'
import {
  BATCH_HINT_RE,
  MUTATING_METHOD_RE,
  classifySurface,
  deduplicateHypotheses,
  detectLifecyclePatterns,
  inferEntityName,
  inferRuntimeInvariantHypotheses,
  isPublicOrStaticAssetPath,
  makeHypothesis,
  pushMap,
  scoreToSeverity,
  scrubLiteralValues,
  sortHypotheses,
  stableId,
  clamp01,
  toCapabilityLedgerSeeds,
} from './invariant-runtime-parity.ts'
export {
  buildRuntimeDiscoveryInput,
  classifySurface,
  extractRuntimeCatalogFromFacts,
  inferEntityName,
  inferRuntimeInvariantHypotheses,
  scrubLiteralValues,
  synthesizePostFloorRuntimeInvariants,
  toCapabilityLedgerSeeds,
  type BuildRuntimeDiscoveryInputParams,
  type RuntimeCatalogFactsExtract,
} from './invariant-runtime-parity.ts'

export const ENTITY_LIFECYCLE_SLICE_MAX_BYTES = 1600
export const DEFAULT_SEMANTIC_BUDGET_FRACTION = 0.10
export const MAX_SEMANTIC_BUDGET_FRACTION = 0.10
export const DEFAULT_SLICE_ESTIMATED_COST_USD = 0.02

export type SynthesizerMode = 'white-box' | 'grey-box' | 'black-box'
export type PromotionStatus = 'capability_only' | 'terminal_eligible'
export type GuardDimension = 'auth' | 'tenant_scope' | 'role' | 'revocation'
export type HypothesisSeverity = 'critical' | 'high' | 'medium' | 'low'
export type InvariantHypothesisKind = 'policy_asymmetry' | 'trust_boundary_mismatch' | 'lifecycle_invariant' | 'runtime_surface_asymmetry'
export type CapabilityKind = 'identity_session' | 'scoped_token' | 'signing_material' | 'signed_artifact_or_url' | 'opaque_object_ref' | 'state_handle' | 'write_sink_handle' | 'internal_reach_handle' | 'parser_or_cache_primitive' | 'policy_asymmetry'
export type CapabilitySurface = 'http' | 'graphql' | 'ws' | 'sse' | 'browser' | 'webhook' | 'async_job' | 'idp' | 'cdn' | 'storage'
export type ServiceTier = 'edge_cdn' | 'app_api' | 'idp_oauth' | 'async_worker' | 'internal_service'
export type BoundaryMechanism = 'reverse_proxy' | 'outbound_http' | 'oauth_redirect' | 'webhook_dispatch' | 'async_queue' | 'cache_layer' | 'router_mount'
export type BoundaryRiskClass = 'identity_header_forwarding' | 'tenant_scope_propagation' | 'path_prefix_normalization' | 'body_reparse_differential' | 'cache_key_divergence' | 'cross_boundary_signing'
export type LifecyclePatternKind = 'state_transition' | 'creator_approver_mutation' | 'numeric_balance_billing'
export interface SourceFileInput { path: string; content: string }
export interface InvariantHypothesis {
  id: string; kind: InvariantHypothesisKind; capabilityKind: CapabilityKind; promotionStatus: 'capability_only'; mode: SynthesizerMode
  entity: string; surface: CapabilitySurface; serviceOrigin?: string; targetRoute?: string; severity: HypothesisSeverity; score: number
  summary: string; preconditions: string[]; verificationHint: string; evidence: string[]; location?: { file: string; line: number }
}
export interface CapabilitySeedRecord {
  capId: string; kind: CapabilityKind; promotionStatus: 'capability_only'; provenance: string; tenantScope: string; actorPersona: string
  serviceOrigin: string; surface: CapabilitySurface; temporalState: 'active' | 'pending' | 'revoked' | 'demoted' | 'expired' | 'primed_cache'
  artifactDigest: string; summary: string; metadata: { hypothesisId: string; hypothesisKind: InvariantHypothesisKind; entity: string; mode: SynthesizerMode; score: number; targetRoute?: string }
}
export interface SurfaceHandlerRecord {
  id: string; entity: string; surface: CapabilitySurface; method: string; path: string; handler: string; file: string; line: number
  serviceOrigin?: string; isBatch: boolean; isMutating: boolean; guards: Record<GuardDimension, string[]>; sinks: ProgramSinkKind[]
}
export interface GuardAsymmetryDiff { entity: string; weakerHandler: SurfaceHandlerRecord; strongerHandler: SurfaceHandlerRecord; missingDimensions: GuardDimension[]; crossSurface: boolean; batchVsSingle: boolean; consensusRatio: number; score: number }
export interface EntitySurfaceMatrixEntry { entity: string; surfaces: CapabilitySurface[]; handlers: SurfaceHandlerRecord[]; enforcedDimensionsBySurface: Partial<Record<CapabilitySurface, GuardDimension[]>>; diffs: GuardAsymmetryDiff[] }
export interface GuardAsymmetryMatrixOptions { sourceFiles?: readonly SourceFileInput[]; serviceOrigins?: readonly ServiceOriginMapping[]; extraHandlers?: readonly SurfaceHandlerRecord[]; maxHypotheses?: number }
export interface GuardAsymmetryMatrixResult { matrix: EntitySurfaceMatrixEntry[]; hypotheses: InvariantHypothesis[]; stats: { handlersAnalyzed: number; entitiesGrouped: number; asymmetriesFound: number } }
export interface TrustBoundaryNode { serviceId: string; tier: ServiceTier; root?: string; origin?: string; routeCount: number; surfaces: CapabilitySurface[]; internalOnly: boolean }
export interface TrustBoundaryEdge { id: string; fromService: string; toService: string; fromTier: ServiceTier; toTier: ServiceTier; mechanism: BoundaryMechanism; propagatedArtifacts: string[]; riskClasses: BoundaryRiskClass[]; file: string; line: number; targetPattern?: string }
export interface TrustBoundaryFinding { edgeId: string; fromService: string; toService: string; riskClass: BoundaryRiskClass; severity: HypothesisSeverity; score: number; rationale: string; evidence: string[]; file: string; line: number }
export interface TrustBoundaryGraphOptions { sourceFiles?: readonly SourceFileInput[]; services?: readonly MonorepoService[]; serviceOrigins?: readonly ServiceOriginMapping[]; compose?: string; ingress?: string; maxHypotheses?: number }
export interface TrustBoundaryGraphResult { nodes: TrustBoundaryNode[]; edges: TrustBoundaryEdge[]; findings: TrustBoundaryFinding[]; hypotheses: InvariantHypothesis[]; stats: { servicesMapped: number; edgesMapped: number; flaggedBoundaries: number } }
export interface EntityLifecycleSlice { entity: string; patterns: LifecyclePatternKind[]; handlers: Array<{ method: string; path: string; surface: CapabilitySurface; file: string; line: number; symbol: string }>; dependencies: Array<{ symbol: string; file: string; line: number }>; renderedSlice: string; byteLength: number; truncated: boolean; estimatedCostUsd: number }
export interface SemanticBudgetGuard { totalRunBudgetUsd: number; requestedBudgetFraction: number; enforcedBudgetFraction: number; allocatedBudgetUsd: number; estimatedCostUsd: number; slicesCandidateCount: number; slicesIncluded: number; slicesDropped: number; truncatedByBudget: boolean }
export interface EntityLifecycleSliceOptions { sourceFiles?: readonly SourceFileInput[]; serviceOrigins?: readonly ServiceOriginMapping[]; maxSliceBytes?: number; totalRunBudgetUsd?: number; maxBudgetFraction?: number; estimatedCostPerSliceUsd?: number; maxSlices?: number }
export interface EntityLifecycleSlicesResult { slices: EntityLifecycleSlice[]; hypotheses: InvariantHypothesis[]; budgetGuard: SemanticBudgetGuard }
export interface PersonaSurfaceObservation { persona: string; roleLabel?: string; tenantId?: string; isRevokedOrDemoted?: boolean; surface: CapabilitySurface; serviceOrigin?: string; method: string; path: string; status: number; responseHeaders?: Record<string, string>; bodyKeys?: string[]; isBatch?: boolean }

export interface RuntimeOpenApiOperation {
  method: string; path: string; operationId?: string; security?: Array<Record<string, string[]>>
  authRequirement?: string | null; tags?: readonly string[]; parameters?: string[]; requestBodyKeys?: string[]; serviceOrigin?: string
}
export interface RuntimeGraphqlField { name: string; kind: 'query' | 'mutation' | 'subscription'; args?: string[]; returnType?: string; requiresAuth?: boolean; requiredRole?: string }
export interface RuntimeGraphqlCatalog { endpoint?: string; serviceOrigin?: string; fields: readonly RuntimeGraphqlField[] }
export interface RuntimeSpaRoute { path: string; serviceOrigin?: string; apiCalls?: ReadonlyArray<{ method: string; path: string; surface?: CapabilitySurface; serviceOrigin?: string }>; stateActions?: readonly string[]; requiredRoles?: readonly string[] }
export interface RuntimeApiDependency { producer: string; consumer: string; resourceKey: string; producerOrigin?: string; consumerOrigin?: string; personaHandle?: string | null; observedTransitions?: readonly string[]; testedBola?: boolean }
export interface RuntimeDiscoveryInput {
  mode: 'grey-box' | 'black-box'; personaObservations?: readonly PersonaSurfaceObservation[]; openApiOperations?: readonly RuntimeOpenApiOperation[]
  graphqlCatalog?: RuntimeGraphqlCatalog; graphqlCatalogs?: readonly RuntimeGraphqlCatalog[]; spaRoutes?: readonly RuntimeSpaRoute[]; apiDependencies?: readonly RuntimeApiDependency[]; maxHypotheses?: number
}
export interface RuntimeInvariantParityResult {
  mode: 'grey-box' | 'black-box'; hypotheses: InvariantHypothesis[]; capabilitySeeds: CapabilitySeedRecord[]
  stats: { observationsAnalyzed: number; catalogOpsAnalyzed: number; spaRoutesAnalyzed: number; hypothesesEmitted: number; apiDependenciesAnalyzed?: number }
}

export interface SynthesizeInvariantsInput {
  mode: SynthesizerMode; graph?: ProgramGraph; sourceFiles?: readonly SourceFileInput[]; staticSnapshot?: StaticWorkspaceSnapshot
  services?: readonly MonorepoService[]; serviceOrigins?: readonly ServiceOriginMapping[]; compose?: string; ingress?: string
  runtime?: Omit<RuntimeDiscoveryInput, 'mode'>; totalRunBudgetUsd?: number; maxBudgetFraction?: number; maxSliceBytes?: number; maxHypotheses?: number
}
export interface SynthesizeInvariantsResult { mode: SynthesizerMode; guardMatrix?: GuardAsymmetryMatrixResult; trustBoundaries?: TrustBoundaryGraphResult; lifecycleSlices?: EntityLifecycleSlicesResult; runtimeParity?: RuntimeInvariantParityResult; hypotheses: InvariantHypothesis[]; capabilitySeeds: CapabilitySeedRecord[] }

const AUTH_GUARD_RE = /\b(?:auth(?:enticate|orize|Required|Middleware)?|requireAuth|ensureAuth|verify(?:Jwt|Token|Session|Bearer|Pat|Cookie)|jwtAuth|sessionAuth|passport|loginRequired|isAuthenticated|getSession|currentUser|req\.user|ctx\.user)\b/i
const TENANT_GUARD_RE = /\b(?:tenant|org(?:anization)?|workspace|account|team|project)(?:Scope|Guard|Check|Isolation|Access|Match|Member|Filter|Context)|require(?:Tenant|Org|Workspace|Account)|enforceTenant|scopeBy(?:Tenant|Org|Workspace)|assert(?:Tenant|Org|Workspace)Access|where[^\n]{0,120}(?:tenantId|orgId|workspaceId)\b/i
const ROLE_GUARD_RE = /\b(?:require(?:Admin|Owner|Role|Permission|Scope|Privilege|Approver|Finance)|check(?:Role|Permission|Scope|Rbac|Abac|Policy)|has(?:Role|Permission|Scope)|is(?:Admin|Owner|Staff|Superuser)|authorize(?:Role|Action|Policy)|rbac|abac|allowRoles|guardRole|minRole)\b/i
const REVOCATION_GUARD_RE = /\b(?:revok(?:e|ed|ation)|checkRevok|isRevok|verifyActive(?:Token|Session|Pat|Key|Invite|Grant)?|tokenVersion|sessionVersion|introspect(?:Token)?|notRevoked|ensureActive|checkDemot|liveRoleCheck|validateGrantStatus|blacklist|denylist)\b/i

export function truncateUtf8(text: string, maxBytes: number): { text: string; byteLength: number; truncated: boolean } {
  const safeMax = Math.max(0, Math.floor(maxBytes)), fullBytes = Buffer.byteLength(text, 'utf8')
  if (fullBytes <= safeMax) return { text, byteLength: fullBytes, truncated: false }
  if (safeMax === 0) return { text: '', byteLength: 0, truncated: true }
  const suffix = '\n...[truncated]', suffixBytes = Buffer.byteLength(suffix, 'utf8'), target = safeMax > suffixBytes + 8 ? safeMax - suffixBytes : safeMax
  let lo = 0, hi = text.length
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (Buffer.byteLength(text.slice(0, mid), 'utf8') <= target) lo = mid; else hi = mid - 1 }
  const clipped = safeMax > suffixBytes + 8 ? `${text.slice(0, lo).trimEnd()}${suffix}` : text.slice(0, lo)
  return { text: clipped, byteLength: Buffer.byteLength(clipped, 'utf8'), truncated: true }
}

function classifyGuardDimensions(guards: readonly string[], bodySnippet = ''): Record<GuardDimension, string[]> {
  const out: Record<GuardDimension, string[]> = { auth: [], tenant_scope: [], role: [], revocation: [] }
  const add = (d: GuardDimension, label: string) => { const c = label.trim().slice(0, 64); if (c && !out[d].includes(c)) out[d].push(c) }
  for (const g of guards) {
    if (AUTH_GUARD_RE.test(g)) add('auth', g)
    if (TENANT_GUARD_RE.test(g)) add('tenant_scope', g)
    if (ROLE_GUARD_RE.test(g)) { add('role', g); add('auth', g) }
    if (REVOCATION_GUARD_RE.test(g)) { add('revocation', g); add('auth', g) }
  }
  if (bodySnippet) {
    for (const [d, re] of [['auth', AUTH_GUARD_RE], ['tenant_scope', TENANT_GUARD_RE], ['role', ROLE_GUARD_RE], ['revocation', REVOCATION_GUARD_RE]] as const) {
      const m = re.exec(bodySnippet)
      if (m) add(d, `body:${m[0]}`)
    }
  }
  return out
}

const MAX_WINDOW_EXTRACT_CHARS = 4_096
const MAX_AUX_HANDLERS_PER_FILE = 256
const MAX_OUTBOUND_MATCHES_PER_FILE = 256

interface IndexedSourceFile {
  readonly content: string
  readonly lineIndex: LineIndex
}

function createIndexedSourceLookup(sourceFiles?: readonly SourceFileInput[]): Map<string, IndexedSourceFile> {
  const map = new Map<string, IndexedSourceFile>()
  for (const sf of sourceFiles ?? []) {
    if (!map.has(sf.path)) {
      map.set(sf.path, { content: sf.content, lineIndex: buildLineIndex(sf.content) })
    }
  }
  return map
}

function extractFunctionBodyWindow(
  content: string,
  line: number,
  maxLines = 26,
  lineIndex?: LineIndex,
  anchorOffset?: number,
): string {
  const idx = lineIndex ?? buildLineIndex(content)
  const slice = extractLineRange(content, idx, Math.max(1, line), Math.max(1, line) + maxLines, MAX_WINDOW_EXTRACT_CHARS, anchorOffset)
  if (!slice) return ''
  const lines = slice.split('\n')
  const out: string[] = []
  let depth = 0, sawOpen = false
  for (let i = 0; i < lines.length; i += 1) {
    const l = lines[i]!
    if (i > 0 && !sawOpen && /^[ \t]{0,32}(?:export[ \t]+)?(?:async[ \t]+)?(?:function\b|const[ \t]+\w+[ \t]*=|router\.|app\.)/.test(l)) break
    out.push(l)
    for (let j = 0; j < l.length; j += 1) {
      const ch = l.charCodeAt(j)
      if (ch === 123 /* '{' */) { depth += 1; sawOpen = true }
      else if (ch === 125 /* '}' */) depth -= 1
    }
    if (sawOpen && depth <= 0) break
  }
  return out.join('\n')
}
const extractLineWindow = (
  content: string,
  line: number,
  before = 6,
  after = 14,
  lineIndex?: LineIndex,
  anchorOffset?: number,
): string => {
  const idx = lineIndex ?? buildLineIndex(content)
  return extractLineRange(content, idx, Math.max(1, line - before), Math.max(1, line + after), MAX_WINDOW_EXTRACT_CHARS, anchorOffset)
}
function resolveServiceOriginForFile(file: string, mappings?: readonly ServiceOriginMapping[]): string | undefined {
  if (!mappings?.length) return undefined
  const norm = file.replace(/\\/g, '/')
  let best: ServiceOriginMapping | undefined, bestLen = -1
  for (const m of mappings) {
    const root = (m.root ?? m.service).replace(/\\/g, '/').replace(/\/$/, '')
    if (root && (norm === root || norm.startsWith(`${root}/`) || norm.includes(`/${root}/`)) && root.length > bestLen) { best = m; bestLen = root.length }
  }
  return best?.origin ?? best?.service
}
interface GraphReachabilityIndex {
  readonly nodeById: Map<string, ProgramNode>
  readonly adj: Map<string, string[]>
}
function buildGraphReachabilityIndex(graph: ProgramGraph): GraphReachabilityIndex {
  const nodeById = new Map<string, ProgramNode>()
  for (const n of graph.nodes) nodeById.set(n.id, n)
  const adj = new Map<string, string[]>()
  for (const e of graph.edges) {
    const list = adj.get(e.fromId)
    if (list) list.push(e.toId)
    else adj.set(e.fromId, [e.toId])
  }
  return { nodeById, adj }
}
function collectReachableNodes(index: GraphReachabilityIndex, startId: string, maxDepth = 3): ProgramNode[] {
  const visited = new Set([startId]), queue: Array<{ id: string; depth: number }> = [{ id: startId, depth: 0 }], result: ProgramNode[] = []
  let head = 0
  while (head < queue.length) {
    const cur = queue[head++]!
    if (cur.depth >= maxDepth) continue
    for (const nextId of index.adj.get(cur.id) ?? []) {
      if (visited.has(nextId)) continue
      visited.add(nextId)
      const node = index.nodeById.get(nextId); if (node) result.push(node)
      queue.push({ id: nextId, depth: cur.depth + 1 })
    }
  }
  return result
}
// Analyzer 1 — Entity x Surface Guard-Asymmetry Matrix
function discoverAuxiliarySurfaceHandlers(
  sourceFiles: readonly SourceFileInput[],
  serviceOrigins?: readonly ServiceOriginMapping[],
  indexedFiles?: Map<string, IndexedSourceFile>,
): SurfaceHandlerRecord[] {
  const discovered: SurfaceHandlerRecord[] = []
  const patterns: Array<{ surface: CapabilitySurface; method: string; re: RegExp; nameGroup: number }> = [
    { surface: 'graphql', method: 'RESOLVER', re: /\b(?:(Query|Mutation|Subscription)[ \t]{0,8}:[ \t]{0,8}\{[\s\S]{0,120}?)?([a-z][A-Za-z0-9_]{2,48})[ \t]{0,8}:[ \t]{0,8}(?:async[ \t]{1,8})?\([^)]{0,160}(?:args|ctx|context|parent)[^)]{0,160}\)[ \t]{0,8}(?:=>|\{)/g, nameGroup: 2 },
    { surface: 'async_job', method: 'WORKER', re: /\b(?:registerWorker|processJob|onJob|queue\.process|worker\.on|subscribeTopic|consumeQueue)[ \t]{0,8}\([ \t\r\n]{0,16}['"`]([a-zA-Z0-9._:/-]{2,64})['"`]/g, nameGroup: 1 },
    { surface: 'ws', method: 'WS', re: /\b(?:ws|wss|socket|io)\.on[ \t]{0,8}\([ \t\r\n]{0,16}['"`]([a-zA-Z0-9._:/-]{2,64})['"`]/g, nameGroup: 1 },
  ]
  for (const sf of sourceFiles) {
    const indexed = indexedFiles?.get(sf.path)
    let lineIndex: LineIndex | undefined = indexed?.lineIndex
    let fileMatches = 0
    for (const pat of patterns) {
      if (fileMatches >= MAX_AUX_HANDLERS_PER_FILE) break
      pat.re.lastIndex = 0
      let match: RegExpExecArray | null
      while ((match = pat.re.exec(sf.content)) !== null) {
        if (fileMatches >= MAX_AUX_HANDLERS_PER_FILE) break
        const rawName = match[pat.nameGroup]
        if (!rawName || /^(?:connection|close|error|open|disconnect|ping|pong|end|data|finish)$/.test(rawName)) continue
        if (!lineIndex) lineIndex = buildLineIndex(sf.content)
        const line = lineAtOffset(lineIndex, match.index)
        const snippet = extractFunctionBodyWindow(sf.content, line, 24, lineIndex, match.index)
        const path = `${pat.surface}:${rawName}`
        fileMatches += 1
        discovered.push({
          id: stableId('aux', `${sf.path}:${line}:${path}`),
          entity: inferEntityName(`/${rawName.replace(/[:.]/g, '/')}`, rawName, snippet),
          surface: pat.surface, method: pat.method, path, handler: rawName, file: sf.path, line,
          serviceOrigin: resolveServiceOriginForFile(sf.path, serviceOrigins),
          isBatch: BATCH_HINT_RE.test(rawName) || BATCH_HINT_RE.test(snippet),
          isMutating: pat.surface === 'graphql'
            ? (match[1] === 'Mutation' || /^(?:create|update|delete|approve|revoke|transfer|promote|set|patch|put)/i.test(rawName))
            : MUTATING_METHOD_RE.test(pat.method) || /\b(?:update|insert|delete|write|save|mutate|set)\b/i.test(snippet),
          guards: classifyGuardDimensions([], snippet),
          sinks: /\b(?:select|insert|update|delete|findOne|findMany|query|prisma|knex|db\.)\b/i.test(snippet) ? ['db_query'] : [],
        })
      }
    }
  }
  return discovered
}

/**
 * Group routes and multi-surface handlers by inferred domain entity/resource,
 * diff effective auth, tenant-scope, role, and revocation guards across surfaces,
 * and emit ranked `policy_asymmetry` hypotheses.
 */
export function buildGuardAsymmetryMatrix(
  graph: ProgramGraph,
  options: GuardAsymmetryMatrixOptions = {},
): GuardAsymmetryMatrixResult {
  const indexedFiles = createIndexedSourceLookup(options.sourceFiles)
  const reachability = buildGraphReachabilityIndex(graph)
  const handlers: SurfaceHandlerRecord[] = []
  const seenKeys = new Set<string>()
  const addHandler = (h: SurfaceHandlerRecord) => {
    const key = `${h.method}|${h.path}|${h.file}:${h.line}`
    if (!seenKeys.has(key)) { seenKeys.add(key); handlers.push(h) }
  }

  const orderedRoutes = [...graph.routes].sort(
    (a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method) || a.file.localeCompare(b.file) || a.line - b.line,
  )
  for (const route of orderedRoutes) {
    if (isPublicOrStaticAssetPath(route.path)) continue
    const handlerFile = route.handlerFile ?? route.file
    const handlerLine = route.handlerLine ?? route.line
    const src = indexedFiles.get(handlerFile) ?? indexedFiles.get(route.file)
    const snippet = src ? extractFunctionBodyWindow(src.content, handlerLine, 26, src.lineIndex) : ''
    const reachable = collectReachableNodes(reachability, route.id, 3)
    addHandler({
      id: route.id,
      entity: inferEntityName(route.path, route.handler, `${snippet}\n${reachable.map(n => n.symbol).join(' ')}`),
      surface: classifySurface(route.path, route.method, route.handler, snippet),
      method: route.method.toUpperCase(), path: route.path, handler: route.handler,
      file: handlerFile, line: handlerLine,
      serviceOrigin: resolveServiceOriginForFile(handlerFile, options.serviceOrigins),
      isBatch: BATCH_HINT_RE.test(route.path) || BATCH_HINT_RE.test(route.handler) || route.input.body.some(k => /(?:ids|items|batch|records|entries)$/i.test(k)),
      isMutating: MUTATING_METHOD_RE.test(route.method),
      guards: classifyGuardDimensions([...route.guards, ...route.middleware, ...reachable.flatMap(n => n.guards)], snippet),
      sinks: [...new Set(reachable.map(n => n.sinkKind).filter((s): s is ProgramSinkKind => Boolean(s)))],
    })
  }
  for (const aux of [...discoverAuxiliarySurfaceHandlers(options.sourceFiles ?? [], options.serviceOrigins, indexedFiles), ...(options.extraHandlers ?? [])]) addHandler(aux)

  const byEntity = new Map<string, SurfaceHandlerRecord[]>()
  for (const h of handlers) pushMap(byEntity, h.entity, h)

  const matrix: EntitySurfaceMatrixEntry[] = [], hypotheses: InvariantHypothesis[] = []
  const dims: GuardDimension[] = ['auth', 'tenant_scope', 'role', 'revocation']
  const dimWeight: Record<GuardDimension, number> = { auth: 0.34, tenant_scope: 0.32, revocation: 0.28, role: 0.24 }

  for (const [entity, group] of [...byEntity.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const surfaces = [...new Set(group.map(h => h.surface))].sort()
    const enforcedDimensionsBySurface: Partial<Record<CapabilitySurface, GuardDimension[]>> = {}
    for (const s of surfaces) enforcedDimensionsBySurface[s] = dims.filter(d => group.some(h => h.surface === s && h.guards[d].length > 0))
    const diffs: GuardAsymmetryDiff[] = []
    if (group.length >= 2) {
      const guardedCount = Object.fromEntries(dims.map(d => [d, group.filter(h => h.guards[d].length > 0).length])) as Record<GuardDimension, number>
      // Deduplicate stronger-handler candidates by `(surface, isBatch, isMutating, guardMask)` so
      // comparison stays O(group.length * uniqueProfiles) instead of O(group.length^2) on huge groups.
      const candidateReps: SurfaceHandlerRecord[] = []
      const seenProfile = new Set<string>()
      for (const h of group) {
        const mask = (h.guards.auth.length ? 1 : 0) | (h.guards.tenant_scope.length ? 2 : 0) | (h.guards.role.length ? 4 : 0) | (h.guards.revocation.length ? 8 : 0)
        if (mask === 0) continue
        const prof = `${h.surface}|${h.isBatch ? 1 : 0}|${h.isMutating ? 1 : 0}|${mask}`
        if (!seenProfile.has(prof)) {
          seenProfile.add(prof)
          candidateReps.push(h)
        }
      }
      for (const weaker of group) {
        let bestStronger: SurfaceHandlerRecord | undefined, bestMissing: GuardDimension[] = [], bestStrength = -1
        for (const cand of candidateReps) {
          if (cand.id === weaker.id) continue
          const missing = dims.filter(d => cand.guards[d].length > 0 && weaker.guards[d].length === 0)
          if (!missing.length) continue
          if (cand.surface === weaker.surface && !weaker.isBatch && !weaker.isMutating && cand.isMutating && missing.length === 1 && missing[0] === 'role') continue
          const strength = missing.reduce((a, d) => a + dimWeight[d], 0) + (cand.surface !== weaker.surface ? 0.25 : 0) + (weaker.isBatch && !cand.isBatch ? 0.2 : 0)
          if (strength > bestStrength) { bestStrength = strength; bestStronger = cand; bestMissing = missing }
        }
        if (!bestStronger || !bestMissing.length) continue
        const crossSurface = weaker.surface !== bestStronger.surface, batchVsSingle = weaker.isBatch && !bestStronger.isBatch
        const avgConsensus = bestMissing.reduce((a, d) => a + guardedCount[d] / group.length, 0) / bestMissing.length
        const score = clamp01(0.32 + bestMissing.reduce((a, d) => a + dimWeight[d], 0) * 0.7 + (crossSurface ? 0.16 : 0) + (batchVsSingle ? 0.14 : 0) + (weaker.isMutating ? 0.08 : 0) + (weaker.sinks.length > 0 ? 0.06 : 0) + avgConsensus * 0.08)
        diffs.push({ entity, weakerHandler: weaker, strongerHandler: bestStronger, missingDimensions: bestMissing, crossSurface, batchVsSingle, consensusRatio: Number(avgConsensus.toFixed(3)), score })
        const missingList = bestMissing.join(', ')
        hypotheses.push(makeHypothesis({
          id: stableId('hyp_asym', `${entity}|${weaker.surface}|${weaker.method}|${weaker.path}|${missingList}`),
          kind: 'policy_asymmetry', capabilityKind: 'policy_asymmetry', mode: 'white-box', entity, surface: weaker.surface,
          ...(weaker.serviceOrigin ? { serviceOrigin: weaker.serviceOrigin } : {}), targetRoute: `${weaker.method} ${weaker.path}`, score,
          summary: `Entity "${entity}" surface "${weaker.surface}" (${weaker.method} ${weaker.path}) omits [${missingList}] enforced on sibling "${bestStronger.surface}" (${bestStronger.method} ${bestStronger.path}).`,
          preconditions: [`actor_access_to:${weaker.surface}`, ...bestMissing.map(d => `missing_guard:${d}`)],
          verificationHint: bestMissing.includes('revocation')
            ? `Verify primary surface denies a revoked/demoted credential (401/403), then replay on ${weaker.surface} (${weaker.method} ${weaker.path}).`
            : batchVsSingle
              ? `Submit a mixed batch [ownId, foreignId] to ${weaker.method} ${weaker.path} and compare per-item enforcement against ${bestStronger.method} ${bestStronger.path}.`
              : `Run a denied control on ${bestStronger.method} ${bestStronger.path}, then test the same actor/tenant boundary on ${weaker.surface} (${weaker.method} ${weaker.path}).`,
          evidence: [
            `weaker=${weaker.surface}:${weaker.method} ${weaker.path} @ ${weaker.file}:${weaker.line}`,
            `stronger=${bestStronger.surface}:${bestStronger.method} ${bestStronger.path} @ ${bestStronger.file}:${bestStronger.line}`,
            `missing_dimensions=${missingList}`, `stronger_guards=${bestMissing.flatMap(d => bestStronger!.guards[d]).slice(0, 6).join(',')}`,
          ],
          location: { file: weaker.file, line: weaker.line },
        }))
      }
    }
    matrix.push({ entity, surfaces, handlers: group, enforcedDimensionsBySurface, diffs: diffs.sort((a, b) => b.score - a.score) })
  }
  const limited = sortHypotheses(hypotheses, options.maxHypotheses)
  return { matrix, hypotheses: limited, stats: { handlersAnalyzed: handlers.length, entitiesGrouped: matrix.length, asymmetriesFound: limited.length } }
}

// Analyzer 2 — Cross-Service Trust-Boundary & Token/Header Propagation Graph
const IDENTITY_HEADER_RE = /\b(?:x-forwarded-(?:user|for|host|proto|prefix)|x-(?:user|actor|internal|auth|role|subject|email|identity|delegat)[a-z0-9-]*|authorization|cookie|proxy-authorization)\b/gi
const TENANT_HEADER_RE = /\b(?:x-(?:tenant|org|organization|workspace|account)[a-z0-9-]*|tenantId|orgId|workspaceId|accountId)\b/gi
const PATH_PREFIX_RE = /\b(?:rewrite|stripPrefix|pathRewrite|startsWith\s*\(|redirect_uri|returnTo|nextUrl|callbackUrl|path\.join|path\.resolve|signedUrl|basePath)\b/i
const BODY_REPARSE_RE = /\b(?:JSON\.parse|rawBody|bodyParser|text\(\)|Buffer\.concat|forwardBody|streamBody|parseJson)\b/i
const CACHE_SURFACE_RE = /\b(?:cache-control|x-cache|cache\.set|cache\.get|cacheKey|cdnCache|vary\b|max-age|s-maxage|stale-while-revalidate)\b/i
const SIGNING_SURFACE_RE = /\b(?:createHmac|hmac|jwt\.sign|jwt\.verify|signPayload|verifySignature|x-signature|webhookSignature|crypto\.sign)\b/i
const OUTBOUND_CALL_RE = /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|http\.request|https\.request|proxyRequest|forwardTo|upstreamFetch|dispatchWebhook|enqueueJob|publishEvent|sendToWorker|res\.redirect)[ \t]{0,8}\([ \t]{0,8}([^\n;]{1,180})/g

function classifyServiceTier(name: string, routes: readonly ProgramRoute[], sourceText: string): ServiceTier {
  const lower = name.toLowerCase()
  if (/(?:edge|gateway|proxy|cdn|ingress|nginx|front|portal|router)/.test(lower)) return 'edge_cdn'
  if (/(?:idp|oauth|oidc|sso|auth|iam|identity|scim)/.test(lower)) return 'idp_oauth'
  if (/(?:worker|runner|queue|job|async|relay|webhook|consumer|scheduler|pdf|render|export)/.test(lower)) return 'async_worker'
  if (/(?:internal|private|secret|kms|storage|registry|ledger|vault|billing|treasury|sync)/.test(lower)) return 'internal_service'
  if (/(?:api|app|backend|core|server|web)/.test(lower)) return 'app_api'
  const surfaces = new Set(routes.map(r => classifySurface(r.path, r.method, r.handler)))
  if (surfaces.has('idp') && surfaces.size <= 2) return 'idp_oauth'
  if (surfaces.has('async_job') && !surfaces.has('http')) return 'async_worker'
  return /\b(?:proxyPass|httpProxy|upstream|createProxy|forwardRequest)\b/i.test(sourceText) ? 'edge_cdn' : 'app_api'
}
function inferServiceIdForPath(filePath: string, services: readonly MonorepoService[], serviceOrigins?: readonly ServiceOriginMapping[]): string {
  const norm = filePath.replace(/\\/g, '/')
  for (const s of services) { const r = (s.root ?? s.name).replace(/\\/g, '/').replace(/\/$/, ''); if (r && (norm === r || norm.startsWith(`${r}/`) || norm.includes(`/${r}/`))) return s.name }
  for (const m of serviceOrigins ?? []) { const r = (m.root ?? m.service).replace(/\\/g, '/').replace(/\/$/, ''); if (r && (norm === r || norm.startsWith(`${r}/`) || norm.includes(`/${r}/`))) return m.service }
  return /(?:^|\/)(?:services|apps|packages)\/([a-zA-Z0-9_.-]+)\//.exec(norm)?.[1] ?? (norm.split('/')[0] || 'app')
}
function detectRiskClassesInWindow(windowText: string, mechanism: BoundaryMechanism, fromTier: ServiceTier, toTier: ServiceTier): { risks: BoundaryRiskClass[]; artifacts: string[] } {
  const risks = new Set<BoundaryRiskClass>(), artifacts = new Set<string>()
  for (const h of [...windowText.matchAll(IDENTITY_HEADER_RE)].map(m => m[0].toLowerCase()).slice(0, 4)) {
    artifacts.add(`header:${h}`)
    if (!/\b(?:delete\s+headers|strip(?:Internal)?Headers|sanitizeHeaders|omit\()/i.test(windowText) || fromTier === 'edge_cdn' || toTier === 'internal_service') risks.add('identity_header_forwarding')
  }
  for (const t of [...windowText.matchAll(TENANT_HEADER_RE)].map(m => m[0].toLowerCase()).slice(0, 4)) {
    artifacts.add(`tenant:${t}`)
    if (/\|\|\s*['"`]?[a-z0-9_-]+|default(?:Tenant|Org|Workspace)|\?\?\s*['"`]/i.test(windowText) || fromTier !== toTier) risks.add('tenant_scope_propagation')
  }
  if (PATH_PREFIX_RE.test(windowText) && (mechanism === 'reverse_proxy' || mechanism === 'oauth_redirect' || mechanism === 'router_mount' || toTier === 'internal_service')) { artifacts.add('path_or_redirect_prefix'); risks.add('path_prefix_normalization') }
  if (BODY_REPARSE_RE.test(windowText) && (mechanism === 'reverse_proxy' || fromTier === 'edge_cdn')) { artifacts.add('raw_body_forward'); risks.add('body_reparse_differential') }
  if (CACHE_SURFACE_RE.test(windowText)) {
    artifacts.add('cache_layer')
    if (!/vary[^;\n]{0,200}(?:authorization|cookie)/i.test(windowText) && !/cacheKey[^\n]{0,200}(?:tenantId|orgId|userId)[^\n]{0,200}(?:tenantId|orgId|userId)/i.test(windowText)) risks.add('cache_key_divergence')
  }
  if (SIGNING_SURFACE_RE.test(windowText)) {
    artifacts.add('crypto_signature')
    if (!/\b(?:canonical|tenantId|orgId|scope|audience|aud|targetPath)\b/i.test(windowText) || mechanism === 'webhook_dispatch' || mechanism === 'async_queue' || toTier === 'internal_service') risks.add('cross_boundary_signing')
  }
  return { risks: [...risks], artifacts: [...artifacts] }
}

const BOUNDARY_RISK_META: Record<BoundaryRiskClass, { capKind: CapabilityKind; baseScore: number; hint: string }> = {
  identity_header_forwarding: { capKind: 'scoped_token', baseScore: 0.78, hint: 'Test whether client-supplied or case-variant identity headers survive or overwrite trusted headers across the hop.' },
  tenant_scope_propagation: { capKind: 'policy_asymmetry', baseScore: 0.74, hint: 'Test empty, omitted, or mismatched tenant scope headers/claims across the hop for fail-open fallback.' },
  path_prefix_normalization: { capKind: 'parser_or_cache_primitive', baseScore: 0.72, hint: 'Test sibling prefix overlap, missing trailing slashes, and path/redirect normalization differentials.' },
  body_reparse_differential: { capKind: 'parser_or_cache_primitive', baseScore: 0.80, hint: 'Compare edge validation vs backend interpretation using duplicate keys or structural parser differentials.' },
  cache_key_divergence: { capKind: 'parser_or_cache_primitive', baseScore: 0.77, hint: 'Prime the cache under actor/tenant A and replay the cache key under actor/tenant B to test bleed.' },
  cross_boundary_signing: { capKind: 'signing_material', baseScore: 0.76, hint: 'Verify whether a valid signature minted for tenant/scope B is accepted under tenant/scope A while tampered signatures fail.' },
}

/**
 * Map ingress/edge/CDN -> app/API -> IdP/OAuth -> async workers/internal services
 * from service origins, router mounts, and outbound client calls, flagging trust
 * boundaries where identity headers, tenant scopes, path prefixes, request bodies,
 * caches, or signatures cross tiers.
 */
export function buildTrustBoundaryGraph(
  graph: ProgramGraph,
  options: TrustBoundaryGraphOptions = {},
): TrustBoundaryGraphResult {
  const services = options.services ?? []
  const originsByService = new Map((options.serviceOrigins ?? []).filter(m => m.origin).map(m => [m.service, m.origin!]))
  const routesByService = new Map<string, ProgramRoute[]>()
  const textByService = new Map<string, string>()
  const knownServices = new Set<string>([...services.map(s => s.name), ...(options.serviceOrigins ?? []).map(m => m.service)])

  for (const r of graph.routes) {
    const svc = inferServiceIdForPath(r.file, services, options.serviceOrigins)
    knownServices.add(svc); pushMap(routesByService, svc, r)
  }
  for (const sf of options.sourceFiles ?? []) {
    const svc = inferServiceIdForPath(sf.path, services, options.serviceOrigins)
    knownServices.add(svc)
    const prev = textByService.get(svc) ?? ''
    if (prev.length < 32_000) textByService.set(svc, `${prev}\n${sf.content.slice(0, 8000)}`)
  }
  const composeTargets: Array<{ from: string; to: string; line: number }> = []
  if (options.compose) {
    let curSvc = ''
    options.compose.split('\n').forEach((raw, idx) => {
      const m = /^\s{2}([a-zA-Z0-9_.-]+)\s*:\s*$/.exec(raw)
      if (m) { curSvc = m[1]; knownServices.add(curSvc) }
      if (!curSvc) return
      for (const dep of raw.matchAll(/https?:\/\/([a-zA-Z0-9_.-]+)(?::\d+)?/g)) {
        if (dep[1] !== curSvc && !/^(?:localhost|127\.0\.0\.1)$/.test(dep[1])) { knownServices.add(dep[1]); composeTargets.push({ from: curSvc, to: dep[1], line: idx + 1 }) }
      }
    })
  }
  const nodesMap = new Map<string, TrustBoundaryNode>()
  for (const svc of [...knownServices].sort()) {
    const svcRoutes = routesByService.get(svc) ?? [], svcObj = services.find(s => s.name === svc)
    const tier = classifyServiceTier(svc, svcRoutes, textByService.get(svc) ?? '')
    nodesMap.set(svc, {
      serviceId: svc, tier, ...(svcObj?.root ? { root: svcObj.root } : {}), ...(originsByService.get(svc) ? { origin: originsByService.get(svc) } : {}),
      routeCount: svcRoutes.length, surfaces: [...new Set(svcRoutes.map(r => classifySurface(r.path, r.method, r.handler)))].sort(),
      internalOnly: tier === 'internal_service' || tier === 'async_worker',
    })
  }

  const edges: TrustBoundaryEdge[] = []
  const edgeKeys = new Set<string>()
  const addEdge = (e: TrustBoundaryEdge) => {
    const key = `${e.fromService}->${e.toService}|${e.mechanism}|${e.file}:${e.line}`
    if (!edgeKeys.has(key)) { edgeKeys.add(key); edges.push(e) }
  }

  const resolveTarget = (expr: string, fromSvc: string): { target: string; tier: ServiceTier } | null => {
    const lower = expr.toLowerCase()
    for (const cand of nodesMap.keys()) {
      if (cand === fromSvc) continue
      const tok = cand.toLowerCase().replace(/[^a-z0-9]/g, '')
      if (tok.length >= 2 && (lower.includes(cand.toLowerCase()) || lower.includes(`${tok}_url`) || lower.includes(`${tok}url`) || lower.includes(`${tok}origin`))) {
        return { target: cand, tier: nodesMap.get(cand)!.tier }
      }
    }
    const hostMatch = /https?:\/\/([a-zA-Z0-9_.-]+)(?::\d+)?/.exec(expr)
    if (hostMatch && !/^(?:localhost|127\.0\.0\.1|example\.com)$/.test(hostMatch[1])) {
      const host = hostMatch[1]
      const tier: ServiceTier = /\.internal$|\.local$|^internal/i.test(host) ? 'internal_service' : /(?:idp|oauth|auth|sso)/i.test(host) ? 'idp_oauth' : 'app_api'
      if (!nodesMap.has(host)) nodesMap.set(host, { serviceId: host, tier, routeCount: 0, surfaces: [], internalOnly: tier === 'internal_service' })
      return { target: host, tier }
    }
    return /(?:webhook|callback|targetUrl|remoteUrl|userUrl|destUrl)/i.test(expr) ? { target: 'external_or_internal_target', tier: 'internal_service' } : null
  }

  for (const sf of options.sourceFiles ?? []) {
    const fromSvc = inferServiceIdForPath(sf.path, services, options.serviceOrigins)
    const fromTier = nodesMap.get(fromSvc)?.tier ?? 'app_api'
    let lineIndex: LineIndex | undefined
    let outboundMatches = 0
    OUTBOUND_CALL_RE.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = OUTBOUND_CALL_RE.exec(sf.content)) !== null) {
      if (outboundMatches >= MAX_OUTBOUND_MATCHES_PER_FILE) break
      const callExpr = match[0], argExpr = match[1] ?? ''
      if (!lineIndex) lineIndex = buildLineIndex(sf.content)
      const line = lineAtOffset(lineIndex, match.index)
      const mechanism: BoundaryMechanism = /proxy|forwardTo|upstream/i.test(callExpr) || fromTier === 'edge_cdn' ? 'reverse_proxy'
        : /redirect/i.test(callExpr) ? 'oauth_redirect'
        : /webhook/i.test(callExpr) ? 'webhook_dispatch'
        : /enqueue|publish|sendToWorker/i.test(callExpr) ? 'async_queue' : 'outbound_http'
      const resolved = resolveTarget(argExpr, fromSvc)
      const toService = resolved?.target ?? (mechanism === 'oauth_redirect' ? 'client_redirect_target' : mechanism === 'async_queue' ? 'async_worker_pool' : '')
      if (!toService) continue
      outboundMatches += 1
      const toTier: ServiceTier = resolved?.tier ?? (mechanism === 'async_queue' ? 'async_worker' : 'app_api')
      const { risks, artifacts } = detectRiskClassesInWindow(extractLineWindow(sf.content, line, 10, 14, lineIndex, match.index), mechanism, fromTier, toTier)
      addEdge({
        id: stableId('edge', `${fromSvc}->${toService}|${mechanism}|${sf.path}:${line}`),
        fromService: fromSvc, toService, fromTier, toTier, mechanism,
        propagatedArtifacts: artifacts, riskClasses: risks, file: sf.path, line,
        targetPattern: scrubLiteralValues(argExpr.trim().slice(0, 96)),
      })
    }
    const cacheMatch = CACHE_SURFACE_RE.exec(sf.content)
    if (cacheMatch) {
      if (!lineIndex) lineIndex = buildLineIndex(sf.content)
      const line = lineAtOffset(lineIndex, cacheMatch.index)
      const { risks, artifacts } = detectRiskClassesInWindow(extractLineWindow(sf.content, line, 8, 12, lineIndex, cacheMatch.index), 'cache_layer', fromTier, 'app_api')
      if (risks.includes('cache_key_divergence')) {
        addEdge({ id: stableId('edge_cache', `${fromSvc}|${sf.path}:${line}`), fromService: fromSvc, toService: `${fromSvc}:cache`, fromTier, toTier: fromTier, mechanism: 'cache_layer', propagatedArtifacts: artifacts, riskClasses: risks, file: sf.path, line })
      }
    }
  }

  for (const n of graph.nodes) {
    if (n.kind !== 'sink' || (n.sinkKind !== 'outbound_fetch' && n.sinkKind !== 'redirect')) continue
    const fromSvc = inferServiceIdForPath(n.file, services, options.serviceOrigins), isRedir = n.sinkKind === 'redirect'
    addEdge({
      id: stableId('edge_sink', `${fromSvc}|${n.file}:${n.line}`), fromService: fromSvc,
      toService: isRedir ? 'client_redirect_target' : 'downstream_service', fromTier: nodesMap.get(fromSvc)?.tier ?? 'app_api',
      toTier: isRedir ? 'app_api' : 'internal_service', mechanism: isRedir ? 'oauth_redirect' : 'outbound_http',
      propagatedArtifacts: [n.symbol], riskClasses: [isRedir ? 'path_prefix_normalization' : 'identity_header_forwarding'], file: n.file, line: n.line,
    })
  }
  for (const r of graph.routes) {
    if (r.mountedFrom.length < 2 || !r.handlerFile) continue
    const fromSvc = inferServiceIdForPath(r.file, services, options.serviceOrigins), toSvc = inferServiceIdForPath(r.handlerFile, services, options.serviceOrigins)
    if (fromSvc !== toSvc) addEdge({
      id: stableId('edge_mount', `${fromSvc}->${toSvc}|${r.path}`), fromService: fromSvc, toService: toSvc,
      fromTier: nodesMap.get(fromSvc)?.tier ?? 'edge_cdn', toTier: nodesMap.get(toSvc)?.tier ?? 'app_api',
      mechanism: 'router_mount', propagatedArtifacts: r.mountedFrom.slice(0, 4), riskClasses: ['path_prefix_normalization'], file: r.file, line: r.line, targetPattern: r.path,
    })
  }
  for (const ct of composeTargets) addEdge({
    id: stableId('edge_compose', `${ct.from}->${ct.to}:${ct.line}`), fromService: ct.from, toService: ct.to,
    fromTier: nodesMap.get(ct.from)?.tier ?? 'app_api', toTier: nodesMap.get(ct.to)?.tier ?? 'internal_service',
    mechanism: 'outbound_http', propagatedArtifacts: ['compose_upstream_url'], riskClasses: ['identity_header_forwarding'], file: 'docker-compose.yml', line: ct.line,
  })

  const findings: TrustBoundaryFinding[] = []
  const hypotheses: InvariantHypothesis[] = []
  for (const edge of edges) {
    for (const riskClass of edge.riskClasses) {
      const meta = BOUNDARY_RISK_META[riskClass]
      const score = clamp01(meta.baseScore + (edge.fromTier !== edge.toTier ? 0.08 : 0) + (edge.toTier === 'internal_service' || edge.toTier === 'async_worker' ? 0.06 : 0))
      const rationale = `Boundary ${edge.fromService} (${edge.fromTier}) -> ${edge.toService} (${edge.toTier}) via ${edge.mechanism} exhibits ${riskClass}.`
      const evidence = [
        `boundary=${edge.fromService}->${edge.toService}`, `tiers=${edge.fromTier}->${edge.toTier}`, `mechanism=${edge.mechanism}`,
        ...(edge.propagatedArtifacts.length ? [`artifacts=${edge.propagatedArtifacts.slice(0, 6).join(',')}`] : []),
        ...(edge.targetPattern ? [`target=${edge.targetPattern}`] : []), `at=${edge.file}:${edge.line}`,
      ]
      findings.push({ edgeId: edge.id, fromService: edge.fromService, toService: edge.toService, riskClass, severity: scoreToSeverity(score), score, rationale, evidence, file: edge.file, line: edge.line })
      const surface: CapabilitySurface = edge.mechanism === 'cache_layer' || edge.fromTier === 'edge_cdn' ? 'cdn'
        : edge.mechanism === 'webhook_dispatch' ? 'webhook'
        : edge.mechanism === 'async_queue' || edge.toTier === 'async_worker' ? 'async_job'
        : edge.mechanism === 'oauth_redirect' || edge.toTier === 'idp_oauth' ? 'idp' : 'http'
      hypotheses.push(makeHypothesis({
        id: stableId('hyp_bnd', `${edge.id}|${riskClass}`), kind: 'trust_boundary_mismatch',
        capabilityKind: edge.toTier === 'internal_service' && edge.mechanism === 'outbound_http' ? 'internal_reach_handle' : meta.capKind,
        mode: 'white-box', entity: edge.toService, surface,
        ...(nodesMap.get(edge.fromService)?.origin ? { serviceOrigin: nodesMap.get(edge.fromService)!.origin } : {}),
        ...(edge.targetPattern ? { targetRoute: edge.targetPattern } : {}),
        score, summary: rationale, preconditions: [`boundary_hop:${edge.fromService}->${edge.toService}`, `risk:${riskClass}`],
        verificationHint: meta.hint, evidence, location: { file: edge.file, line: edge.line },
      }))
    }
  }

  const limited = sortHypotheses(hypotheses, options.maxHypotheses)
  return {
    nodes: [...nodesMap.values()].sort((a, b) => a.serviceId.localeCompare(b.serviceId)),
    edges, findings: findings.sort((a, b) => b.score - a.score), hypotheses: limited,
    stats: { servicesMapped: nodesMap.size, edgesMapped: edges.length, flaggedBoundaries: findings.length },
  }
}

// Analyzer 3 — Bounded Entity Lifecycle Semantic Slice Builder
const compactCodeExcerpt = (content: string, line: number, maxLines = 12, lineIndex?: LineIndex): string =>
  scrubLiteralValues(extractFunctionBodyWindow(content, line, maxLines, lineIndex).split('\n').map(l => l.trimEnd()).filter(l => l.trim().length > 0 && !/^\s*\/\//.test(l)).slice(0, maxLines).join('\n'))
export function buildEntityLifecycleSlices(graph: ProgramGraph, options: EntityLifecycleSliceOptions = {}): EntityLifecycleSlicesResult {
  const indexedFiles = createIndexedSourceLookup(options.sourceFiles)
  const reachability = buildGraphReachabilityIndex(graph)
  const maxSliceBytes = Math.min(Math.max(128, Math.floor(options.maxSliceBytes ?? ENTITY_LIFECYCLE_SLICE_MAX_BYTES)), ENTITY_LIFECYCLE_SLICE_MAX_BYTES)
  const totalRunBudgetUsd = Math.max(0, options.totalRunBudgetUsd ?? 5.0), requestedBudgetFraction = Math.max(0, options.maxBudgetFraction ?? DEFAULT_SEMANTIC_BUDGET_FRACTION)
  const enforcedBudgetFraction = Math.min(requestedBudgetFraction, MAX_SEMANTIC_BUDGET_FRACTION), allocatedBudgetUsd = Number((totalRunBudgetUsd * enforcedBudgetFraction).toFixed(6))
  const costPerSlice = Math.max(0.0001, options.estimatedCostPerSliceUsd ?? DEFAULT_SLICE_ESTIMATED_COST_USD), budgetSliceCap = Math.floor((allocatedBudgetUsd + 1e-9) / costPerSlice)
  const hardSliceCap = options.maxSlices !== undefined ? Math.min(options.maxSlices, budgetSliceCap) : budgetSliceCap
  interface ClusterCandidate { entity: string; patterns: Set<LifecyclePatternKind>; priority: number; handlers: Array<{ method: string; path: string; surface: CapabilitySurface; file: string; line: number; symbol: string; excerpt: string; serviceOrigin?: string }>; dependencies: Map<string, { symbol: string; file: string; line: number; excerpt: string }> }
  const clusters = new Map<string, ClusterCandidate>()
  const orderedRoutes = [...graph.routes].sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method) || a.file.localeCompare(b.file) || a.line - b.line)
  for (const route of orderedRoutes) {
    if (isPublicOrStaticAssetPath(route.path)) continue
    const handlerFile = route.handlerFile ?? route.file, handlerLine = route.handlerLine ?? route.line
    const src = indexedFiles.get(handlerFile) ?? indexedFiles.get(route.file)
    const excerpt = src ? compactCodeExcerpt(src.content, handlerLine, 10, src.lineIndex) : `${route.method} ${route.path} -> ${route.handler}`
    const depExcerpts = collectReachableNodes(reachability, route.id, 3)
      .filter(d => d.kind === 'function' || d.kind === 'sink')
      .map(d => {
        const depSrc = indexedFiles.get(d.file)
        return { symbol: d.symbol, file: d.file, line: d.line, excerpt: depSrc ? compactCodeExcerpt(depSrc.content, d.line, 7, depSrc.lineIndex) : `${d.kind}:${d.symbol}` }
      })
    const combined = [route.path, route.handler, route.input.body.join(' '), excerpt, ...depExcerpts.map(d => `${d.symbol} ${d.excerpt}`)].join('\n')
    const patterns = detectLifecyclePatterns(combined)
    if (!patterns.length) continue

    const entity = inferEntityName(route.path, route.handler, combined)
    const cluster: ClusterCandidate = clusters.get(entity) ?? { entity, patterns: new Set<LifecyclePatternKind>(), handlers: [], dependencies: new Map(), priority: 0 }
    for (const p of patterns) cluster.patterns.add(p)
    cluster.handlers.push({
      method: route.method.toUpperCase(), path: route.path, surface: classifySurface(route.path, route.method, route.handler, excerpt),
      file: handlerFile, line: handlerLine, symbol: route.handler, excerpt,
      serviceOrigin: resolveServiceOriginForFile(handlerFile, options.serviceOrigins),
    })
    for (const d of depExcerpts) { const k = `${d.file}:${d.line}:${d.symbol}`; if (!cluster.dependencies.has(k)) cluster.dependencies.set(k, d) }
    cluster.priority = cluster.patterns.size * 0.35 + Math.min(cluster.handlers.length, 4) * 0.12 +
      (cluster.patterns.has('numeric_balance_billing') ? 0.15 : 0) + (cluster.patterns.has('creator_approver_mutation') ? 0.14 : 0) +
      (cluster.dependencies.size > 0 ? 0.08 : 0)
    clusters.set(entity, cluster)
  }

  const ranked = [...clusters.values()].sort((a, b) => b.priority - a.priority || a.entity.localeCompare(b.entity))
  const slices: EntityLifecycleSlice[] = []
  const hypotheses: InvariantHypothesis[] = []

  for (const cand of ranked.slice(0, Math.max(0, hardSliceCap))) {
    const patterns = [...cand.patterns].sort()
    const deps = [...cand.dependencies.values()].slice(0, 6)
    const lines = [`ENTITY: ${cand.entity}`, `PATTERNS: ${patterns.join(', ')}`, `HANDLERS (${cand.handlers.length}):`]
    for (const h of cand.handlers.slice(0, 5)) {
      lines.push(`- ${h.method} ${h.path} [${h.surface}] @ ${h.file}:${h.line} (${h.symbol})`)
      if (h.excerpt) lines.push(`  ${h.excerpt.replace(/\n/g, '\n  ')}`)
    }
    if (deps.length) {
      lines.push(`DEPS (${deps.length}):`)
      for (const d of deps.slice(0, 4)) {
        lines.push(`- ${d.symbol} @ ${d.file}:${d.line}`)
        if (d.excerpt) lines.push(`  ${d.excerpt.replace(/\n/g, '\n  ')}`)
      }
    }
    const bounded = truncateUtf8(lines.join('\n'), maxSliceBytes)
    slices.push({
      entity: cand.entity, patterns,
      handlers: cand.handlers.map(({ method, path, surface, file, line, symbol }) => ({ method, path, surface, file, line, symbol })),
      dependencies: deps.map(({ symbol, file, line }) => ({ symbol, file, line })),
      renderedSlice: bounded.text, byteLength: bounded.byteLength, truncated: bounded.truncated, estimatedCostUsd: costPerSlice,
    })

    const primary = cand.handlers[0]
    const invDesc = [
      cand.patterns.has('state_transition') ? 'preserve state monotonicity and clear stale grants on reopen/demotion' : '',
      cand.patterns.has('creator_approver_mutation') ? 'preserve creator/owner attribution and maker-checker separation' : '',
      cand.patterns.has('numeric_balance_billing') ? 'preserve numeric conservation across multi-step or concurrent billing mutations' : '',
    ].filter(Boolean).join('; ')
    hypotheses.push(makeHypothesis({
      id: stableId('hyp_life', `${cand.entity}|${patterns.join(',')}`), kind: 'lifecycle_invariant', capabilityKind: 'state_handle',
      mode: 'white-box', entity: cand.entity, surface: primary.surface,
      ...(primary.serviceOrigin ? { serviceOrigin: primary.serviceOrigin } : {}),
      targetRoute: `${primary.method} ${primary.path}`, score: 0.45 + Math.min(0.45, cand.priority * 0.55),
      summary: `Entity "${cand.entity}" lifecycle cluster [${patterns.join(', ')}] across ${cand.handlers.length} handler(s): ${invDesc}.`,
      preconditions: [`entity_cluster:${cand.entity}`, ...patterns.map(p => `pattern:${p}`)],
      verificationHint: `Exercise multi-step state sequence across ${cand.handlers.slice(0, 3).map(h => `${h.method} ${h.path}`).join(' -> ')} with an ablation control verifying the terminal action fails without the setup mutation.`,
      evidence: [...cand.handlers.slice(0, 4).map(h => `handler=${h.method} ${h.path} @ ${h.file}:${h.line}`), ...deps.slice(0, 3).map(d => `dep=${d.symbol} @ ${d.file}:${d.line}`), `slice_bytes=${bounded.byteLength}/${maxSliceBytes}`],
      location: { file: primary.file, line: primary.line },
    }))
  }

  return {
    slices, hypotheses: hypotheses.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)),
    budgetGuard: {
      totalRunBudgetUsd, requestedBudgetFraction, enforcedBudgetFraction, allocatedBudgetUsd,
      estimatedCostUsd: Number((slices.length * costPerSlice).toFixed(6)),
      slicesCandidateCount: ranked.length, slicesIncluded: slices.length,
      slicesDropped: Math.max(0, ranked.length - slices.length), truncatedByBudget: ranked.length > budgetSliceCap,
    },
  }
}

// Unified Orchestrator
/** Unified Layer-2 synthesizer entry point across `white-box`, `grey-box`, and `black-box` modes. */
export function synthesizeInvariants(input: SynthesizeInvariantsInput): SynthesizeInvariantsResult {
  const all: InvariantHypothesis[] = [], snap = input.staticSnapshot, graph = input.graph ?? snap?.programGraph
  const sourceFiles = input.sourceFiles ?? (snap ? snapshotSourceFiles(snap) : undefined), compose = input.compose ?? snap?.compose, ingress = input.ingress ?? snap?.ingress
  let guardMatrix: GuardAsymmetryMatrixResult | undefined, trustBoundaries: TrustBoundaryGraphResult | undefined, lifecycleSlices: EntityLifecycleSlicesResult | undefined, runtimeParity: RuntimeInvariantParityResult | undefined
  if (input.mode === 'white-box' && graph) {
    guardMatrix = buildGuardAsymmetryMatrix(graph, { sourceFiles, serviceOrigins: input.serviceOrigins })
    trustBoundaries = buildTrustBoundaryGraph(graph, { sourceFiles, services: input.services, serviceOrigins: input.serviceOrigins, compose, ingress })
    lifecycleSlices = buildEntityLifecycleSlices(graph, { sourceFiles, serviceOrigins: input.serviceOrigins, maxSliceBytes: input.maxSliceBytes, totalRunBudgetUsd: input.totalRunBudgetUsd, maxBudgetFraction: input.maxBudgetFraction })
    all.push(...guardMatrix.hypotheses, ...trustBoundaries.hypotheses, ...lifecycleSlices.hypotheses)
  }
  if (input.runtime) {
    runtimeParity = inferRuntimeInvariantHypotheses({ mode: input.mode === 'black-box' ? 'black-box' : 'grey-box', ...input.runtime })
    all.push(...runtimeParity.hypotheses)
  }
  const hypotheses = input.maxHypotheses ? deduplicateHypotheses(all).slice(0, input.maxHypotheses) : deduplicateHypotheses(all)
  return { mode: input.mode, ...(guardMatrix ? { guardMatrix } : {}), ...(trustBoundaries ? { trustBoundaries } : {}), ...(lifecycleSlices ? { lifecycleSlices } : {}), ...(runtimeParity ? { runtimeParity } : {}), hypotheses, capabilitySeeds: toCapabilityLedgerSeeds(hypotheses) }
}
