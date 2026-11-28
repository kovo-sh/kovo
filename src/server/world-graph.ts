/**
 * Track B Cut 1 — pure-fact World Graph snapshot (zero LLM, read-only).
 *
 * Projects bounded, already-observed run state (discovered endpoints, per-principal broker exchange
 * status outcomes, observed API dependencies, host-verified CapabilityLedger causal edges, untainted
 * worker facts/leads, optional in-memory program-graph controller routes) into a compact, prioritized
 * snapshot, and serializes it under a deterministic UTF-8 byte budget for the single-turn planner.
 */
import { normalizeRouteTemplate } from './route-template.ts'
import type { Run, Store } from './store.ts'

const EXCHANGE_SAMPLE_LIMIT = 250
const API_DEPENDENCY_SAMPLE_LIMIT = 250
const FACT_SAMPLE_LIMIT = 250
const ENDPOINT_SAMPLE_LIMIT = 500
const LEDGER_EDGE_SAMPLE_LIMIT = 64
const GROUP_CAP = 40
const EDGE_CAP = 16
const FACT_CAP = 16
const CODE_ROUTE_CAP = 12
const SAMPLE_TEMPLATE_CAP = 3
const FACT_SUMMARY_MAX = 120
const DEFAULT_BYTE_BUDGET = 4096
const MUTATING_METHODS: ReadonlySet<string> = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const LEAD_SUBKINDS: ReadonlySet<string> = new Set(['det_lead', 'code_audit_suspect', 'lead', 'invariant_hypothesis'])

export type WorldGraphStatusClass = '2xx' | '401' | '403' | 'other'
export type WorldGraphAuthCounts = Record<WorldGraphStatusClass, number>
/** Per-principal status counts keyed by `personaHandle ?? 'anon'`. */
export type WorldGraphAuthMatrix = Record<string, WorldGraphAuthCounts>

export interface WorldGraphEndpointGroup {
  origin: string; prefix: string; methods: string[]; sampleTemplates: string[]; endpointCount: number
  authMatrix: WorldGraphAuthMatrix; authAsymmetric: boolean; mutating: boolean; confirmed: boolean; priority: number
}

export interface WorldGraphCausalEdge {
  id: string; source: 'api_dependency' | 'capability_ledger'; fromOrigin: string; from: string; toOrigin: string; to: string
  resourceKey?: string; crossOrigin: boolean; hostVerified: boolean
}

export interface WorldGraphFact { id: string; origin: string; kind: string; summary: string; route?: string; lead: boolean; confirmed: boolean }
export interface WorldGraphCodeRoute { method: string; path: string; file: string; guards: string[]; sinks: string[] }

export interface WorldGraphTruncation {
  omittedGroups: number; omittedEdges: number; omittedFacts: number; omittedCodeRoutes: number; byteBudget: number; serializedBytes?: number
}

export interface WorldGraphSnapshot {
  version: 1; runId: string; principals: string[]
  groups: WorldGraphEndpointGroup[]; edges: WorldGraphCausalEdge[]; facts: WorldGraphFact[]; codeRoutes: WorldGraphCodeRoute[]
  stats: { endpoints: number; exchangesSampled: number; apiDependencies: number; ledgerEdges: number; factsSeen: number; degraded?: string[] }
  truncation: WorldGraphTruncation
}

export interface WorldGraphEndpointInput { origin: string; method: string; pathTemplate: string }
export interface WorldGraphExchangeInput { origin: string; method: string; pathAndQuery: string; personaHandle: string | null; status: number }
export interface WorldGraphApiDependencyInput {
  id: string; resourceKey: string; testedBola?: boolean
  producerOrigin: string; producerMethod: string; producerPath: string
  consumerOrigin: string; consumerMethod: string; consumerPath: string
}
export interface WorldGraphLedgerEdgeInput { edgeId: string; fromOrigin: string; from: string; toOrigin: string; to: string }
export interface WorldGraphFactInput { id: string; origin: string; kind: string; summary: string; data?: Record<string, unknown> | null }
export interface WorldGraphConfirmedRef { origin?: string | null; method?: string | null; path: string }
/** Structural subset of the coordinator program graph (in-memory only; never walks the filesystem). */
export interface WorldGraphProgramGraphInput {
  routes: ReadonlyArray<{ id: string; method: string; path: string; file: string; guards?: readonly string[] }>
  nodes: ReadonlyArray<{ id: string; kind: string; symbol?: string; sinkKind?: string }>
  edges: ReadonlyArray<{ fromId: string; toId: string }>
}

export interface CollectWorldGraphOptions {
  approvedOrigins?: readonly string[]; confirmedRefs?: readonly WorldGraphConfirmedRef[]
  programGraph?: WorldGraphProgramGraphInput | null; byteBudget?: number
  onWarning?: (stage: string, error: unknown) => void
}

export interface BuildWorldGraphInput extends Omit<CollectWorldGraphOptions, 'onWarning'> {
  runId: string; endpoints: readonly WorldGraphEndpointInput[]; exchanges: readonly WorldGraphExchangeInput[]
  apiDependencies?: readonly WorldGraphApiDependencyInput[]; ledgerEdges?: readonly WorldGraphLedgerEdgeInput[]
  facts?: readonly WorldGraphFactInput[]; degraded?: readonly string[]
}

/** Group key prefix: `/api/v1/<seg>`, `/api/<seg>`, or `/<seg>` (never a path parameter). */
function groupPrefix(template: string): string {
  const segs = template.split('/').filter(Boolean)
  const isParam = (seg: string | undefined) => !seg || seg.startsWith(':') || seg.startsWith('{')
  if (segs[0] === 'api' && /^v\d+$/i.test(segs[1] ?? '') && !isParam(segs[2])) return `/api/${segs[1]}/${segs[2]}`
  if (segs[0] === 'api' && !isParam(segs[1])) return `/api/${segs[1]}`
  return isParam(segs[0]) ? '/' : `/${segs[0]}`
}

function statusClass(status: number): WorldGraphStatusClass {
  if (status >= 200 && status < 300) return '2xx'
  if (status === 401) return '401'
  if (status === 403) return '403'
  return 'other'
}

function isAuthAsymmetric(matrix: WorldGraphAuthMatrix): boolean {
  const principals = Object.keys(matrix)
  if (principals.length < 2) return false
  const allowed = principals.filter(p => matrix[p]!['2xx'] > 0)
  const denied = principals.filter(p => matrix[p]!['401'] + matrix[p]!['403'] > 0)
  if (allowed.some(a => denied.some(d => d !== a))) return true
  const dominant = new Set(principals.map(p => {
    const counts = matrix[p]!
    return (Object.keys(counts) as WorldGraphStatusClass[]).reduce((best, k) => (counts[k] > counts[best] ? k : best), '2xx')
  }))
  return dominant.size > 1
}

function isConfirmedTemplate(origin: string, template: string, refs: readonly WorldGraphConfirmedRef[]): boolean {
  return refs.some(ref => (!ref.origin || ref.origin === origin) && normalizeRouteTemplate(ref.path) === template)
}

function cleanText(text: string, max: number): string {
  const flat = text.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim()
  return flat.length <= max ? flat : `${flat.slice(0, Math.max(0, max - 1)).trimEnd()}…`
}

interface GroupAccumulator { origin: string; prefix: string; methods: Set<string>; templates: string[]; endpointCount: number; matrix: WorldGraphAuthMatrix }

function buildGroups(input: BuildWorldGraphInput, inScope: (origin: string) => boolean): WorldGraphEndpointGroup[] {
  const acc = new Map<string, GroupAccumulator>()
  const touch = (origin: string, template: string, method: string): GroupAccumulator => {
    const prefix = groupPrefix(template)
    const key = `${origin} ${prefix}`
    let group = acc.get(key)
    if (!group) acc.set(key, group = { origin, prefix, methods: new Set(), templates: [], endpointCount: 0, matrix: {} })
    group.methods.add(method.toUpperCase())
    if (!group.templates.includes(template)) group.templates.push(template)
    return group
  }
  for (const ep of input.endpoints) {
    if (!inScope(ep.origin)) continue
    touch(ep.origin, normalizeRouteTemplate(ep.pathTemplate), ep.method).endpointCount += 1
  }
  for (const ex of input.exchanges) {
    if (!inScope(ex.origin)) continue
    const group = touch(ex.origin, normalizeRouteTemplate(ex.pathAndQuery), ex.method)
    const principal = ex.personaHandle?.trim() || 'anon'
    const cell = group.matrix[principal] ??= { '2xx': 0, '401': 0, '403': 0, other: 0 }
    cell[statusClass(ex.status)] += 1
  }
  const refs = input.confirmedRefs ?? []
  return [...acc.values()].map(group => {
    const methods = [...group.methods].sort()
    const mutating = methods.some(m => MUTATING_METHODS.has(m))
    const authAsymmetric = isAuthAsymmetric(group.matrix)
    const confirmed = group.templates.length > 0 && group.templates.every(t => isConfirmedTemplate(group.origin, t, refs))
    // Confirmed groups keep only a residual asymmetry weight so unconfirmed surfaces always lead.
    const priority = (authAsymmetric ? (confirmed ? 10 : 40) : 0) + (confirmed ? 0 : 25) + (mutating ? 20 : 0) +
      Math.min(10, group.endpointCount) + Math.min(5, Object.keys(group.matrix).length)
    const sampleTemplates = [...group.templates]
      .sort((a, b) => Number(isConfirmedTemplate(group.origin, a, refs)) - Number(isConfirmedTemplate(group.origin, b, refs)) || a.localeCompare(b))
      .slice(0, SAMPLE_TEMPLATE_CAP)
    return {
      origin: group.origin, prefix: group.prefix, methods, sampleTemplates, endpointCount: group.endpointCount,
      authMatrix: group.matrix, authAsymmetric, mutating, confirmed, priority,
    }
  }).sort((a, b) => b.priority - a.priority || a.origin.localeCompare(b.origin) || a.prefix.localeCompare(b.prefix))
}

function buildEdges(input: BuildWorldGraphInput, inScope: (origin: string) => boolean): WorldGraphCausalEdge[] {
  const seen = new Set<string>()
  const edges: Array<WorldGraphCausalEdge & { tested: boolean }> = []
  const push = (edge: WorldGraphCausalEdge & { tested: boolean }) => {
    if (!inScope(edge.fromOrigin) && !inScope(edge.toOrigin)) return
    const key = `${edge.fromOrigin}|${edge.from}|${edge.toOrigin}|${edge.to}|${edge.resourceKey ?? ''}`
    if (seen.has(key)) return
    seen.add(key)
    edges.push(edge)
  }
  for (const dep of input.apiDependencies ?? []) {
    push({
      id: dep.id, source: 'api_dependency', fromOrigin: dep.producerOrigin,
      from: `${dep.producerMethod.toUpperCase()} ${normalizeRouteTemplate(dep.producerPath)}`,
      toOrigin: dep.consumerOrigin, to: `${dep.consumerMethod.toUpperCase()} ${normalizeRouteTemplate(dep.consumerPath)}`,
      resourceKey: cleanText(dep.resourceKey, 48), crossOrigin: dep.producerOrigin !== dep.consumerOrigin,
      hostVerified: false, tested: dep.testedBola === true,
    })
  }
  for (const edge of input.ledgerEdges ?? []) {
    push({
      id: edge.edgeId, source: 'capability_ledger', fromOrigin: edge.fromOrigin, from: cleanText(edge.from, 64),
      toOrigin: edge.toOrigin, to: cleanText(edge.to, 64), crossOrigin: edge.fromOrigin !== edge.toOrigin,
      hostVerified: true, tested: false,
    })
  }
  return edges
    .sort((a, b) => Number(b.crossOrigin) - Number(a.crossOrigin) || Number(b.hostVerified) - Number(a.hostVerified) ||
      Number(a.tested) - Number(b.tested) || a.id.localeCompare(b.id))
    .map(({ tested: _tested, ...edge }) => edge)
}

function factRoute(data: Record<string, unknown> | null | undefined): string | undefined {
  for (const key of ['route', 'path', 'endpoint', 'pathTemplate']) {
    const value = data?.[key]
    if (typeof value === 'string' && value.trim().startsWith('/')) return normalizeRouteTemplate(value)
  }
  return undefined
}

function buildFacts(input: BuildWorldGraphInput, inScope: (origin: string) => boolean): WorldGraphFact[] {
  const refs = input.confirmedRefs ?? []
  const ranked = (input.facts ?? []).filter(fact => inScope(fact.origin)).map(fact => {
    const subkind = typeof fact.data?.subkind === 'string' ? fact.data.subkind : typeof fact.data?.kind === 'string' ? fact.data.kind : ''
    const lead = LEAD_SUBKINDS.has(subkind) || fact.kind === 'policy_gap'
    const route = factRoute(fact.data)
    const confirmed = route ? isConfirmedTemplate(fact.origin, route, refs) : false
    const score = (lead ? 30 : 0) + (confirmed ? 0 : 20) + (['auth', 'object_ref', 'cors', 'policy_gap'].includes(fact.kind) ? 10 : 0)
    const out: WorldGraphFact = {
      id: fact.id, origin: fact.origin, kind: subkind || fact.kind, summary: cleanText(fact.summary, FACT_SUMMARY_MAX),
      ...(route ? { route } : {}), lead, confirmed,
    }
    return { out, score }
  })
  return ranked.sort((a, b) => b.score - a.score || a.out.id.localeCompare(b.out.id)).map(r => r.out)
}

function buildCodeRoutes(graph: WorldGraphProgramGraphInput | null | undefined): WorldGraphCodeRoute[] {
  if (!graph) return []
  const sinkNodes = new Map(graph.nodes.filter(n => n.kind === 'sink' || n.sinkKind).map(n => [n.id, n.sinkKind ?? n.symbol ?? n.kind]))
  const sinksByRoute = new Map<string, string[]>()
  for (const edge of graph.edges) {
    const sink = sinkNodes.get(edge.toId)
    if (sink) sinksByRoute.set(edge.fromId, [...new Set([...(sinksByRoute.get(edge.fromId) ?? []), sink])])
  }
  return graph.routes.map(route => {
    const sinks = (sinksByRoute.get(route.id) ?? []).slice(0, 4).map(s => cleanText(s, 32))
    const guards = (route.guards ?? []).filter(g => g.trim()).slice(0, 3).map(g => cleanText(g, 40))
    const method = route.method.toUpperCase()
    const score = (sinks.length && !guards.length ? 30 : sinks.length ? 20 : 0) + (MUTATING_METHODS.has(method) ? 10 : 0)
    return { out: { method, path: normalizeRouteTemplate(route.path), file: cleanText(route.file, 80), guards, sinks }, score }
  }).sort((a, b) => b.score - a.score || a.out.path.localeCompare(b.out.path) || a.out.method.localeCompare(b.out.method))
    .map(r => r.out)
}

/** Pure, deterministic snapshot builder over already-collected facts (no I/O, no LLM). */
export function buildWorldGraphSnapshot(input: BuildWorldGraphInput): WorldGraphSnapshot {
  const approved = new Set(input.approvedOrigins ?? [])
  const inScope = (origin: string) => approved.size === 0 || approved.has(origin)
  const groups = buildGroups(input, inScope)
  const edges = buildEdges(input, inScope)
  const facts = buildFacts(input, inScope)
  const codeRoutes = buildCodeRoutes(input.programGraph)
  const principals = [...new Set(groups.flatMap(g => Object.keys(g.authMatrix)))].sort()
  return {
    version: 1, runId: input.runId, principals, groups: groups.slice(0, GROUP_CAP), edges: edges.slice(0, EDGE_CAP),
    facts: facts.slice(0, FACT_CAP), codeRoutes: codeRoutes.slice(0, CODE_ROUTE_CAP),
    stats: {
      endpoints: input.endpoints.length, exchangesSampled: input.exchanges.length,
      apiDependencies: input.apiDependencies?.length ?? 0, ledgerEdges: input.ledgerEdges?.length ?? 0,
      factsSeen: input.facts?.length ?? 0, ...(input.degraded?.length ? { degraded: [...input.degraded] } : {}),
    },
    truncation: {
      omittedGroups: Math.max(0, groups.length - GROUP_CAP),
      omittedEdges: Math.max(0, edges.length - EDGE_CAP),
      omittedFacts: Math.max(0, facts.length - FACT_CAP),
      omittedCodeRoutes: Math.max(0, codeRoutes.length - CODE_ROUTE_CAP),
      byteBudget: input.byteBudget ?? DEFAULT_BYTE_BUDGET,
    },
  }
}

function stringifyWithBytes(snap: WorldGraphSnapshot): { json: string; bytes: number } {
  let json = JSON.stringify(snap)
  for (let i = 0; i < 4; i += 1) {
    const bytes = Buffer.byteLength(json, 'utf8')
    if (snap.truncation.serializedBytes === bytes) return { json, bytes }
    snap.truncation.serializedBytes = bytes
    json = JSON.stringify(snap)
  }
  return { json, bytes: Buffer.byteLength(json, 'utf8') }
}

type PruneList = 'codeRoutes' | 'facts' | 'edges' | 'groups'
const OMITTED_KEY: Record<PruneList, keyof Omit<WorldGraphTruncation, 'byteBudget' | 'serializedBytes'>> = {
  codeRoutes: 'omittedCodeRoutes', facts: 'omittedFacts', edges: 'omittedEdges', groups: 'omittedGroups',
}

/**
 * Deterministic UTF-8 byte-budget serializer. Ordered pruning ladder: trim sample templates →
 * prune lowest-priority code routes / facts / edges / groups down to floors → tighten summaries →
 * prune each list to zero → drop stats. `truncation.*` counts stay exact on the serialized output.
 */
export function serializeWorldGraph(snapshot: WorldGraphSnapshot, maxBytes = DEFAULT_BYTE_BUDGET): string {
  const snap: WorldGraphSnapshot = structuredClone(snapshot)
  snap.truncation.byteBudget = maxBytes
  delete snap.truncation.serializedBytes
  let current = stringifyWithBytes(snap)
  const fits = () => (current = stringifyWithBytes(snap)).bytes <= maxBytes
  if (current.bytes <= maxBytes) return current.json
  const pruneTo = (list: PruneList, floor: number): boolean => {
    while (snap[list].length > floor) {
      snap[list].pop()
      snap.truncation[OMITTED_KEY[list]] += 1
      if (fits()) return true
    }
    return false
  }
  const ladder: Array<() => boolean> = [
    () => { for (const g of snap.groups) g.sampleTemplates = g.sampleTemplates.slice(0, 1); return fits() },
    () => pruneTo('codeRoutes', 4),
    () => pruneTo('facts', 6),
    () => pruneTo('edges', 6),
    () => pruneTo('groups', 8),
    () => { for (const f of snap.facts) f.summary = cleanText(f.summary, 48); return fits() },
    () => pruneTo('codeRoutes', 0),
    () => pruneTo('facts', 0),
    () => pruneTo('edges', 0),
    () => pruneTo('groups', 0),
    () => { snap.principals = snap.principals.slice(0, 4); delete snap.stats.degraded; return fits() },
  ]
  for (const step of ladder) if (step()) return current.json
  const minimal = JSON.stringify({ version: 1, truncation: snap.truncation })
  return Buffer.byteLength(minimal, 'utf8') <= maxBytes ? minimal : maxBytes >= 2 ? '{}' : ''
}

function readStage<T>(stage: string, fallback: T, degraded: string[], opts: CollectWorldGraphOptions, read: () => T): T {
  try {
    return read()
  } catch (error) {
    degraded.push(stage)
    opts.onWarning?.(stage, error)
    return fallback
  }
}

/**
 * Collect a World Graph snapshot from the store via read-only SELECTs / read-only getters only.
 * Every projection is bounded (`broker_exchanges` / `api_dependencies` / facts `LIMIT 250`).
 */
export function collectWorldGraphFromStore(storage: Store, run: Pick<Run, 'id'>, opts: CollectWorldGraphOptions = {}): WorldGraphSnapshot {
  const degraded: string[] = []
  const endpoints = readStage('endpoints', [] as WorldGraphEndpointInput[], degraded, opts, () =>
    storage.listEndpoints(run.id, { orderBy: 'risk', limit: ENDPOINT_SAMPLE_LIMIT }))
  const exchanges = readStage('broker_exchanges', [] as WorldGraphExchangeInput[], degraded, opts, () =>
    storage.client.prepare(
      `SELECT origin, method, path_and_query AS pathAndQuery, persona_handle AS personaHandle, status
         FROM broker_exchanges WHERE run_id = ? ORDER BY created_at DESC, id ASC LIMIT ${EXCHANGE_SAMPLE_LIMIT}`,
    ).all(run.id) as unknown as WorldGraphExchangeInput[])
  const apiDependencies = readStage('api_dependencies', [] as WorldGraphApiDependencyInput[], degraded, opts, () =>
    (storage.client.prepare(
      `SELECT d.id AS id, d.resource_key AS resourceKey, d.tested_bola AS testedBola,
              p.origin AS producerOrigin, p.method AS producerMethod, p.path_template AS producerPath,
              c.origin AS consumerOrigin, c.method AS consumerMethod, c.path_template AS consumerPath
         FROM api_dependencies d
         JOIN endpoints p ON p.id = d.producer_endpoint_id
         JOIN endpoints c ON c.id = d.consumer_endpoint_id
        WHERE d.run_id = ? ORDER BY d.created_at DESC, d.id ASC LIMIT ${API_DEPENDENCY_SAMPLE_LIMIT}`,
    ).all(run.id) as unknown as Array<WorldGraphApiDependencyInput & { testedBola: number | boolean }>)
      .map(dep => ({ ...dep, testedBola: Boolean(dep.testedBola) })))
  const ledgerEdges = readStage('capability_ledger', [] as WorldGraphLedgerEdgeInput[], degraded, opts, () => {
    const ledger = storage.capabilityLedger(run.id)
    return ledger.listCausalEdges().slice(-LEDGER_EDGE_SAMPLE_LIMIT).flatMap(edge => {
      const post = edge.postconditionCapId ? ledger.getCapability(edge.postconditionCapId) : null
      const fromOrigin = edge.actorContext.serviceOrigin ?? ''
      const toOrigin = post?.serviceOrigin ?? fromOrigin
      if (!fromOrigin || !toOrigin) return []
      return [{
        edgeId: edge.edgeId, fromOrigin, from: `${edge.actorContext.roleLabel ?? edge.actorContext.persona} ${edge.edgeBindingKind}`,
        toOrigin, to: post ? `${post.kind} ${post.surface}` : (edge.terminalImpact ?? 'terminal'),
      }]
    })
  })
  const facts = readStage('facts', [] as WorldGraphFactInput[], degraded, opts, () =>
    storage.listFacts(run.id, { includeTainted: false, limit: FACT_SAMPLE_LIMIT }))
  return buildWorldGraphSnapshot({
    runId: run.id, approvedOrigins: opts.approvedOrigins, endpoints, exchanges, apiDependencies, ledgerEdges, facts,
    confirmedRefs: opts.confirmedRefs, programGraph: opts.programGraph, byteBudget: opts.byteBudget, degraded,
  })
}
