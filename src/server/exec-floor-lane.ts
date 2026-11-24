import { randomUUID } from 'node:crypto'
import type { Candidate, Finding } from '../domain.ts'
import { declarativeReplaySpecSchema, replaySpecOrigins, type DeclarativeReplaySpec } from '../replay-spec.ts'
import {
  BrokerDenied,
  type BrokerExchangeResult,
  type Grant,
  type RequestBroker,
} from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { checkStructuralDuplicate, extractSpecDedupeFields } from './dedupe.ts'
import {
  runDeterministicEngine,
  type EngineConfirmed,
  type EngineEndpoint,
  type EngineLead,
  type EnginePersona,
} from './deterministic-engine.ts'
import {
  CODE_LEAD_PRIORITY_RISK,
  DETERMINISTIC_PROBE_CAP,
  ENGINE_PROBE_CAP,
  buildBolaTestQueue,
  deriveCodeLeadIdentifierTargets,
  prioritizeCodeLeadTargets,
  probeSelectionMetrics,
  selectProbeCandidates,
  tenantLabelsFromRoleLabels,
} from './exec-dispatch.ts'
import {
  buildExistingFindingRefs,
  createExchangeRecorder,
  recordReportedFindingCoverage,
  type ExecActiveJob,
} from './exec-exchange.ts'
import { graphLeadTargets } from './graph-leads.ts'
import { resolveRunPersonas } from './persona-vault.ts'
import { listEndpointsPaged } from './phase0-recon.ts'
import type { ProbePlanRegistry } from './probe-plan.ts'
import { BudgetExceededError } from './provider.ts'
import { redact, type NamedSecret } from './redact.ts'
import { tenantTagForRun } from './scope-policy.ts'
import type { ScopedBrowser } from './scoped-browser.ts'
import type { Assignment, ReplaySpecRow, Run, Store } from './store.ts'
import { probeDifferential, probeSurface } from './surface-engine.ts'
import type { WorkerBackend } from './worker-backend.ts'

type Active = ExecActiveJob

export interface ExecFloorLaneHost {
  storage: Store
  broker: RequestBroker
  browser: ScopedBrowser
  canaryBroker: CanaryBroker
  backend: WorkerBackend
  probePlans: ProbePlanRegistry
  stagingTaggedMutations: Map<string, number>
  stagingUntaggedSkipped: Map<string, number>
  stagingCleaned: Map<string, number>
  stagingCreatedEntities: Map<string, Set<string>>
  approvedOriginsSet: (run: Run) => Set<string>
  permitted: (run: Run, origin: string) => boolean
  buildGrant: (job: Active, run: Run, permittedAtAdmission: ReadonlySet<string>) => { grant: Grant; secrets: NamedSecret[]; currentSecrets: () => NamedSecret[] }
  beginFloorRequestPhase: (run: Run) => unknown
  phaseRequestRemaining: (run: Run) => number | null
  markEndpointCoverage: (run: Run, origin: string, method: string, pathAndQuery: string, probeClass: string) => void
  scanSecondOrderExchange: (run: Run, assignmentId: string, ex: BrokerExchangeResult, exchangeId: string) => void
  createConfirmedReplaySpec: (
    run: Run,
    assignment: Assignment,
    findingId: string,
    spec: DeclarativeReplaySpec,
    origins: string[],
    result: EngineConfirmed["result"],
    secrets: readonly NamedSecret[],
  ) => ReplaySpecRow
}



function indexEndpointParams(storage: Store, runId: string) {
  const allParams = storage.listEndpointParams(runId)
  const byEndpoint = new Map<string, typeof allParams>()
  for (const param of allParams) {
    const list = byEndpoint.get(param.endpointId) ?? []
    list.push(param)
    byEndpoint.set(param.endpointId, list)
  }
  return byEndpoint
}




// --- Deterministic (zero-LLM) investigation fallback helpers ---

/** Parameter names worth a differential SQL probe (generic, engine-level — not app-specific). */
export const DETERMINISTIC_PARAM_HINT_RE = /^(?:id|uuid|q|query|search|s|filter|sort|order|orderby|where|name|email|slug|path|file|url|uri|host|cmd|exec|template|view|lang|category|type|limit|offset|page|next|redirect|return)$/i

const DETERMINISTIC_NUMERIC_PARAM_RE = /^(?:id|page|limit|offset|qty|quantity|amount|price|count|num|index)$/i

const DETERMINISTIC_ID_SEGMENT_RE = /(?:\/:[a-z_][a-z0-9_]*|\{\{id\}\}|\/[a-z_][a-z0-9_]*\}|\/\[[^\]]+\]|\/\d{2,16}(?=\/|$)|\/[0-9a-f]{8}-[0-9a-f]{4}-)/i

const DETERMINISTIC_PATH_PARAM_RE = /\/:[a-z_][a-z0-9_]*|\/\{\{id\}\}|\/\{[a-z_][a-z0-9_]*\}|\/\[[^\]]+\]/gi


function deterministicQueryParamNames(pathTemplate: string): string[] {
  const qIdx = pathTemplate.indexOf('?')
  if (qIdx < 0) return []
  return pathTemplate
    .slice(qIdx + 1)
    .split('&')
    .map(pair => pair.split('=')[0]?.trim())
    .filter((name): name is string => Boolean(name && /^[A-Za-z0-9_.\-[\]]{1,64}$/.test(name)))
}


function withQueryParam(pathTemplate: string, name: string, value: string): string {
  const base = pathTemplate.split('?')[0]
  return `${base}?${name}=${encodeURIComponent(value)}`
}


function deterministicIdPath(pathTemplate: string): string | null {
  if (!DETERMINISTIC_ID_SEGMENT_RE.test(pathTemplate)) return null
  const replaced = pathTemplate.replace(DETERMINISTIC_PATH_PARAM_RE, '/{{id}}').replace(/\/\d{2,16}(?=\/|$)/, '/{{id}}')
  return replaced.includes('{{id}}') ? replaced : null
}


const DETERMINISTIC_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])


/**
 * Route admission for briefing/OpenAPI references. A read route still needs an injectable
 * parameter or a resource id to be worth a differential probe, but a write route is a real
 * endpoint even when the reference leaks no body fields (body-only create/action routes such as
 * `POST /api/refunds/lines`). Keep those with their declared method instead of dropping them.
 */
function deterministicRouteIsTestable(method: string, pathTemplate: string, hasInjectable: boolean): boolean {
  if (hasInjectable) return true
  if (deterministicIdPath(pathTemplate)) return true
  return DETERMINISTIC_WRITE_METHODS.has(method.toUpperCase())
}


type DerivedRouteParam = { name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }
type DerivedRouteTarget = {
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  source?: string
  params: DerivedRouteParam[]
}

/** Tolerant OpenAPI extraction for specs whose stored text is redacted or truncated. */
function parseTolerantOpenApiTargets(
  content: string,
  defaultOrigin: string,
  approvedOrigins: ReadonlySet<string>,
): DerivedRouteTarget[] {
  const pathKeyRe = /"(\/[A-Za-z0-9_\-{}\/.:$\[\]]{0,200})"\s*:\s*\{/g
  const matches = [...content.matchAll(pathKeyRe)]
  if (!matches.length) return []
  const out: DerivedRouteTarget[] = []
  for (let idx = 0; idx < matches.length; idx += 1) {
    const match = matches[idx]
    const pathTemplate = match[1]
    if (!pathTemplate.startsWith('/')) continue
    const start = (match.index ?? 0) + match[0].length
    const end = idx + 1 < matches.length ? (matches[idx + 1].index ?? content.length) : content.length
    const block = content.slice(start, end)
    const methods = [...block.matchAll(/"(get|post|put|patch|delete)"\s*:\s*\{/g)].map(m => m[1].toUpperCase())
    if (!methods.length) continue
    const params: DerivedRouteParam[] = []
    const paramRe = /"name"\s*:\s*"([A-Za-z0-9_.\-\[\]]{1,64})"[\s\S]{0,200}?"in"\s*:\s*"(query|path|header|formData|body)"/g
    for (const param of block.matchAll(paramRe)) {
      const location = param[2] === 'formData' ? 'form' : param[2] === 'body' ? 'json' : param[2] as 'query' | 'path' | 'header'
      if (!params.some(p => p.name === param[1])) params.push({ name: param[1], location })
    }
    for (const matchPath of pathTemplate.matchAll(/\{([A-Za-z0-9_]+)\}/g)) {
      if (!params.some(p => p.name === matchPath[1])) params.push({ name: matchPath[1], location: 'path' })
    }
    for (const method of methods) {
      const hasInjectable = params.some(p => p.location === 'query' || p.location === 'json' || p.location === 'form')
      if (!deterministicRouteIsTestable(method, pathTemplate, hasInjectable)) continue
      out.push({
        origin: approvedOrigins.has(defaultOrigin) ? defaultOrigin : [...approvedOrigins][0],
        method,
        pathTemplate,
        riskScore: hasInjectable ? 65 : 55,
        params,
      })
    }
  }
  return out.slice(0, 60)
}


/** Shared replay-spec boilerplate for deterministically synthesized specs. */function baseReplaySpecFields(
  origin: string,
  overrides: {
    title: string
    category: string
    cwe: string
    severity: Finding['severity']
    severityRationale: string
    impact: string
    remediation: string
    recheckInstructions: string
  },
) {
  return {
    version: 1 as const,
    origin,
    title: overrides.title.slice(0, 200),
    category: overrides.category,
    cwe: overrides.cwe,
    severity: overrides.severity,
    severityRationale: overrides.severityRationale.slice(0, 800),
    impact: overrides.impact.slice(0, 1200),
    remediation: overrides.remediation.slice(0, 1500),
    recheckInstructions: overrides.recheckInstructions.slice(0, 1000),
  }
}

export class ExecFloorLane {
  private readonly host: ExecFloorLaneHost
  constructor(host: ExecFloorLaneHost) { this.host = host }
  private get storage(): Store { return this.host.storage }
  private get broker(): RequestBroker { return this.host.broker }
  private get browser(): ScopedBrowser { return this.host.browser }
  private get canaryBroker(): CanaryBroker { return this.host.canaryBroker }
  private get backend(): WorkerBackend { return this.host.backend }


  private createFloorExchangeRecorder(currentId: string, claimedId: string, currentSecrets: () => NamedSecret[]) {
    return createExchangeRecorder(this.storage, () => this.storage.run(currentId), claimedId, currentSecrets, {
      trackResources: true,
      markCoverage: (latest, origin, method, pathAndQuery) =>
        this.host.markEndpointCoverage(latest, origin, method, pathAndQuery, 'http_exchange'),
      onSaved: (latest, ex, id) => this.host.scanSecondOrderExchange(latest, claimedId, ex, id),
    })
  }

  private checkSpecDuplicate(run: Run, spec: DeclarativeReplaySpec, verifiedEndpoint?: string | null) {
    const fields = extractSpecDedupeFields(spec)
    const { refs } = buildExistingFindingRefs(this.storage, run.id, run.goalRevision)
    return checkStructuralDuplicate({
      origin: spec.origin, title: spec.title, cwe: spec.cwe, category: spec.category, severity: spec.severity,
      endpoint: fields.endpoint, authState: fields.authState, specKind: fields.specKind,
      method: fields.method, param: fields.param, graphqlField: fields.graphqlField,
      mutated: fields.mutated ?? null,
      ...(verifiedEndpoint ? { verifiedEndpoint } : {}),
    }, refs)
  }

  /** Verified handler/endpoint reported by the replay verifier's endpoint binding, if any. */
  verifiedEndpointOf(result: { evidencePayload?: Record<string, unknown> }): string | null {
    const binding = result.evidencePayload?.endpointBinding as
      | { verifiedEndpoint?: { origin?: unknown; method?: unknown; pathAndQuery?: unknown } | null }
      | undefined
    const ve = binding?.verifiedEndpoint
    if (!ve || typeof ve.method !== 'string' || typeof ve.origin !== 'string' || typeof ve.pathAndQuery !== 'string') return null
    return `${ve.method.toUpperCase()} ${ve.origin}${ve.pathAndQuery}`.slice(0, 320)
  }


  /**
   * Extract entry routes from JSON route maps/config docs already fetched during recon
   * (e.g. `/app-config.json`, `/routes`, OpenAPI JSON). Bounded and generic: any object with a
   * `path`/`pathTemplate` string or an array of `/api/...` strings qualifies.
   */
  async deriveRuntimeRouteMapTargets(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    grant: Grant,
    assignment: Assignment,
    signal: AbortSignal,
    recordExchange: (exchange: BrokerExchangeResult) => string,
  ): Promise<DerivedRouteTarget[]> {
    const out: DerivedRouteTarget[] = []
    let summaries: Array<{ id: string; origin: string; method: string; pathAndQuery: string; status: number; mediaType: string }> = []
    try {
      summaries = [...this.storage.runDetail(run.id).exchangesSummary].sort((a, b) =>
        a.origin.localeCompare(b.origin) ||
        a.pathAndQuery.localeCompare(b.pathAndQuery) ||
        a.method.localeCompare(b.method) ||
        a.id.localeCompare(b.id))
    } catch {
      return []
    }
    const configPathRe = /(?:app-config|config|routes|manifest|openapi|swagger|api-docs)(?:\.[a-z]+)?(?:\?|$)/i
    let configExchanges = summaries
      .filter(ex => ex.method === 'GET' && ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType))
      .filter(ex => configPathRe.test(ex.pathAndQuery))
      .slice(0, 4)

    // Phase-0 may not have fetched the runtime route map yet; fetch at most two generic config
    // candidates so recon-derived routes are still reachable in deterministic mode.
    if (configExchanges.length === 0) {
      const origin = [...approvedOrigins].sort()[0]
      const alreadyFetched = new Set(summaries.map(ex => ex.pathAndQuery))
      for (const candidate of ['/app-config.json', '/api/routes', '/routes.json']) {
        if (configExchanges.length >= 2) break
        if (alreadyFetched.has(candidate) || signal.aborted) continue
        try {
          const ex = await this.broker.executeHttp({
            origin,
            method: 'GET',
            pathAndQuery: candidate,
            followRedirects: false,
            runId: run.id,
            assignmentId: assignment.id,
          }, grant, signal)
          const id = recordExchange(ex)
          if (ex.status >= 200 && ex.status < 300 && /json/i.test(ex.mediaType)) {
            configExchanges.push({
              id,
              origin: ex.origin,
              method: ex.method,
              pathAndQuery: ex.pathAndQuery,
              status: ex.status,
              mediaType: ex.mediaType,
            })
          }
        } catch {
          // Config probing is best-effort; continue with whatever recon already recorded.
        }
      }
    }

    const normalizeTemplate = (value: string) =>
      value.replace(/\{([a-z][a-z0-9_]*):([a-z][a-z0-9_-]*)\}/gi, '$2').slice(0, 300)

    const pushTarget = (origin: string, method: string, rawPath: string) => {
      if (!approvedOrigins.has(origin)) return
      if (!rawPath.startsWith('/') || rawPath.length > 300) return
      const pathTemplate = normalizeTemplate(rawPath)
      if (!/^\/[A-Za-z0-9_\-{}\/.:]*$/.test(pathTemplate)) return
      if (out.some(t => t.origin === origin && t.method === method && t.pathTemplate === pathTemplate)) return
      if (out.length >= 60) return
      const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
      for (const match of pathTemplate.matchAll(/\{([A-Za-z0-9_]+)\}/g)) params.push({ name: match[1], location: 'path' })
      out.push({ origin, method, pathTemplate, riskScore: 70, params })
    }

    const visit = (node: unknown, origin: string, depth: number) => {
      if (depth > 5 || out.length >= 60) return
      if (Array.isArray(node)) {
        for (const item of node.slice(0, 200)) visit(item, origin, depth + 1)
        return
      }
      if (!node || typeof node !== 'object') return
      const obj = node as Record<string, unknown>
      const methodRaw = typeof obj.method === 'string' ? obj.method : typeof obj.verb === 'string' ? obj.verb : null
      const pathRaw = typeof obj.path === 'string' ? obj.path
        : typeof obj.pathTemplate === 'string' ? obj.pathTemplate
          : typeof obj.route === 'string' ? obj.route : null
      if (pathRaw && pathRaw.startsWith('/')) {
        const method = (methodRaw ?? 'GET').toUpperCase()
        // Only read methods are probed deterministically without a declared body schema.
        if (method === 'GET' || method === 'HEAD') pushTarget(origin, method, pathRaw)
      }
      for (const [key, value] of Object.entries(obj).slice(0, 200)) {
        if (typeof value === 'string' && value.startsWith('/api/') && value.length <= 200) {
          pushTarget(origin, 'GET', value)
        } else if (key === 'paths' && value && typeof value === 'object') {
          for (const [pathKey, pathValue] of Object.entries(value as Record<string, unknown>).slice(0, 120)) {
            if (!pathKey.startsWith('/')) continue
            const methods = pathValue && typeof pathValue === 'object'
              ? Object.keys(pathValue as Record<string, unknown>).filter(k => ['get', 'post', 'put', 'patch'].includes(k.toLowerCase()))
              : []
            for (const method of methods.length ? methods : ['get']) pushTarget(origin, method.toUpperCase(), pathKey)
          }
        } else if (value && typeof value === 'object') {
          visit(value, origin, depth + 1)
        }
      }
    }

    for (const summary of configExchanges) {
      let body = ''
      try {
        body = this.storage.getExchange(run.id, summary.id).body
      } catch {
        continue
      }
      if (!body || body.length > 512 * 1024) continue
      let doc: unknown
      try {
        doc = JSON.parse(body)
      } catch {
        continue
      }
      visit(doc, summary.origin, 0)
    }
    return out
  }


  /**
   * Parse imported OpenAPI/route-map project specs into bounded deterministic probe targets.
   * Generic engine behavior: no app, route, or parameter hardcoding.
   */
  deriveDeterministicRouteTargets(
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    existing: ReadonlyArray<{ origin: string; method: string; pathTemplate: string }>,
  ): DerivedRouteTarget[] {
    let specs: Array<{ name: string; kind: string; content: string }> = []
    try {
      specs = [...this.storage.listProjectSpecsFull(run.projectId)].sort((a, b) =>
        a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name))
    } catch {
      return []
    }
    const seen = new Set(existing.map(ep => `${ep.origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`))
    const out: DerivedRouteTarget[] = []
    const defaultOrigin = [...approvedOrigins].sort()[0]
    const mapLocation = (value: unknown): 'query' | 'json' | 'form' | 'path' | 'header' | null => {
      const raw = typeof value === 'string' ? value.toLowerCase() : ''
      if (raw === 'query' || raw === 'path' || raw === 'header') return raw
      if (raw === 'formdata' || raw === 'form') return 'form'
      if (raw === 'body') return 'json'
      return null
    }

    for (const spec of specs.slice(0, 6)) {
      const head = spec.content.slice(0, 400)
      if (!/openapi|swagger/i.test(spec.kind) && !/"(?:openapi|swagger)"\s*:/.test(head) && !/^\s*openapi\s*:/m.test(head)) continue
      let doc: Record<string, unknown> | undefined
      try {
        doc = JSON.parse(spec.content) as Record<string, unknown>
      } catch {
        doc = undefined
      }
      const paths = (doc as { paths?: Record<string, unknown> } | undefined)?.paths
      if (!paths || typeof paths !== 'object') {
        // Tolerant fallback: imported specs can be redacted/truncated before storage, so the JSON
        // may not parse. Extract path keys + methods + parameters textually instead of giving up.
        for (const target of parseTolerantOpenApiTargets(spec.content, defaultOrigin, approvedOrigins)) {
          const key = `${target.origin}|${target.method}|${target.pathTemplate}`
          if (seen.has(key)) continue
          seen.add(key)
          out.push(target)
        }
        continue
      }

      let origin = defaultOrigin
      const servers = (doc as { servers?: Array<{ url?: unknown }> } | undefined)?.servers
      if (Array.isArray(servers) && typeof servers[0]?.url === 'string') {
        try {
          const serverOrigin = new URL(servers[0].url, defaultOrigin).origin
          if (approvedOrigins.has(serverOrigin)) origin = serverOrigin
        } catch { /* keep default */ }
      }

      for (const [rawPath, rawItem] of Object.entries(paths).slice(0, 80)) {
        if (typeof rawPath !== 'string' || !rawPath.startsWith('/') || rawPath.length > 300) continue
        const item = rawItem as Record<string, unknown> | null
        if (!item || typeof item !== 'object') continue
        const sharedParams = Array.isArray(item.parameters) ? item.parameters as Array<Record<string, unknown>> : []
        for (const method of ['get', 'post', 'put', 'patch', 'delete'] as const) {
          const op = item[method] as Record<string, unknown> | undefined
          if (!op || typeof op !== 'object') continue
          const key = `${origin}|${method.toUpperCase()}|${rawPath}`
          if (seen.has(key)) continue
          const params: Array<{ name: string; location: 'query' | 'json' | 'form' | 'path' | 'header' | 'xml' | 'graphql_var' }> = []
          const pushParam = (name: unknown, location: unknown) => {
            const mapped = mapLocation(location)
            if (typeof name !== 'string' || !name || !/^[A-Za-z0-9_.\-[\]]{1,64}$/.test(name)) return
            if (!mapped) return
            if (params.some(p => p.name === name)) return
            params.push({ name, location: mapped })
          }
          for (const param of [...sharedParams, ...(Array.isArray(op.parameters) ? op.parameters as Array<Record<string, unknown>> : [])]) {
            pushParam(param?.name, param?.in)
          }
          const jsonSchema = (op.requestBody as { content?: Record<string, { schema?: { properties?: Record<string, unknown> } }> } | undefined)
            ?.content?.['application/json']?.schema
          if (jsonSchema?.properties && typeof jsonSchema.properties === 'object') {
            for (const name of Object.keys(jsonSchema.properties).slice(0, 12)) pushParam(name, 'body')
          }
          for (const match of rawPath.matchAll(/\{([A-Za-z0-9_]+)\}/g)) pushParam(match[1], 'path')
          seen.add(key)
          const hasInjectable = params.some(p => p.location === 'query' || p.location === 'json' || p.location === 'form')
          if (!deterministicRouteIsTestable(method, rawPath, hasInjectable)) continue
          out.push({
            origin,
            method: method.toUpperCase(),
            pathTemplate: rawPath,
            riskScore: hasInjectable ? 65 : 55,
            params,
          })
        }
      }
    }
    return out.slice(0, 60)
  }


  /**
   * Bounded, tier/scope/budget-aware deterministic hypotheses for discovered endpoints. Used only
   * when the run has no model profile: it probes the highest-value discovered routes, records
   * facts, synthesizes DeclarativeReplaySpecs from differential anomalies, and lets the normal
   * Zero-LLM verification queue confirm or dismiss them.
   */
  async runDeterministicInvestigation(run: Run): Promise<void> {
    const current = this.storage.run(run.id)
    if (current.status !== 'running' || current.phase !== 'investigation') return
    const approvedOrigins = this.host.approvedOriginsSet(current)
    if (current.capabilityTier < 1 || approvedOrigins.size === 0) return

    // Graphwire: full lossless store in, bounded ranked probe subset out. DELETE stays excluded
    // from this legacy M1 fallback pass (its own tier gate lives in the engine lane).
    const probeSelection = selectProbeCandidates({
      endpoints: listEndpointsPaged(this.storage, current.id, { orderBy: 'risk' }),
      probePlan: this.host.probePlans.get(this.storage, current.id),
      cap: DETERMINISTIC_PROBE_CAP,
      approvedOrigins,
      excludeMethods: ['DELETE'],
    })
    const endpoints = probeSelection.targets
    try {
      this.storage.event(
        current.id,
        'deterministic_probe.selection',
        `Probe selection ranked ${probeSelection.considered} candidate route(s) from ${probeSelection.storedRows} stored row(s); probing ${probeSelection.selected} (cap ${probeSelection.cap}).`,
        probeSelectionMetrics(probeSelection),
      )
    } catch { /* metrics only */ }

    const paramsByEndpoint = indexEndpointParams(this.storage, current.id)


    const personas = [...resolveRunPersonas(this.storage, current.projectId, current.approvedPersonaIds).values()]
    const personaHandles = personas.map(p => p.handle)
    const tier = current.capabilityTier

    const resourceQueue = tier >= 2 && personaHandles.length >= 2
      ? buildBolaTestQueue(
          this.storage.listFacts(current.id, { includeTainted: false, limit: 200 }),
          personas.map(p => ({ handle: p.handle, roleLabel: p.roleLabel, originAllowlist: p.originAllowlist })),
          approvedOrigins,
          this.storage.listResourceSamples(current.id),
        )
      : []

    const asset = current.candidates.find(c => approvedOrigins.has(c.origin) && current.approved.includes(c.id))
    if (!asset) return

    const worker = this.storage.makeWorker(
      current,
      'investigation',
      asset,
      'Deterministic differential probes',
      'No model profile configured: bounded deterministic probe pass over discovered endpoints.',
      { sourceOrigins: [...approvedOrigins] },
    )
    const claimed = this.storage.updateWorker(worker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 10 * 60_000,
    }) ?? worker
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller: new AbortController() }
    const { grant, currentSecrets } = this.host.buildGrant(job, current, approvedOrigins)

    const recordExchange = this.createFloorExchangeRecorder(current.id, claimed.id, currentSecrets)

    const signal = job.controller.signal

    // Route-map/OpenAPI-derived entry routes: grey-box/white-box runs import API references, and
    // phase-0 may not have materialized every path yet on this branch. Parsing them here keeps the
    // deterministic baseline meaningful without depending on an LLM planner.
    const derivedTargets = [
      ...this.deriveDeterministicRouteTargets(current, approvedOrigins, endpoints),
      ...await this.deriveRuntimeRouteMapTargets(current, approvedOrigins, grant, claimed, signal, recordExchange),
    ].filter((target, idx, all) =>
      all.findIndex(other => other.origin === target.origin && other.method === target.method && other.pathTemplate === target.pathTemplate) === idx,
    )
    const syntheticEndpoints = derivedTargets.map(target => ({
      id: `derived:${target.method}:${target.pathTemplate}`,
      runId: current.id,
      scopeRevision: current.scopeRevision,
      origin: target.origin,
      method: target.method,
      pathTemplate: target.pathTemplate,
      source: 'openapi' as const,
      framework: null,
      authRequirement: null,
      ownershipGuard: null,
      sinkKinds: [] as string[],
      testedClasses: [] as string[],
      coveragePct: 0,
      riskScore: target.riskScore,
      codeLocation: null,
      createdAt: current.createdAt,
      updatedAt: current.createdAt,
    }))
    for (const [idx, target] of derivedTargets.entries()) {
      const endpointId = syntheticEndpoints[idx].id
      paramsByEndpoint.set(endpointId, target.params.map((param, paramIdx) => ({
        id: `${endpointId}:p${paramIdx}`,
        runId: current.id,
        endpointId,
        name: param.name,
        location: param.location,
        inferredType: null,
        isCsrf: false,
        isObjectId: /^(?:id|uuid|[a-z][a-z0-9]*Id)$/i.test(param.name),
        source: 'openapi',
        createdAt: current.createdAt,
      })) as unknown as ReturnType<Store['listEndpointParams']>)
    }
    const probeEndpoints = [...endpoints, ...syntheticEndpoints]
    if (!probeEndpoints.length) return

    const injectableLocations = new Set(['query', 'json', 'form'])
    const ranked = probeEndpoints
      .map(ep => {
        const epParams = paramsByEndpoint.get(ep.id) ?? []
        const injectable = epParams
          .filter(p => injectableLocations.has(p.location))
          .sort((a, b) => Number(DETERMINISTIC_PARAM_HINT_RE.test(b.name)) - Number(DETERMINISTIC_PARAM_HINT_RE.test(a.name)))
          .slice(0, 2)
        const queryNames = deterministicQueryParamNames(ep.pathTemplate)
        const paramCandidates = injectable.length
          ? injectable.map(p => ({ name: p.name, location: p.location as 'query' | 'json' | 'form' }))
          : queryNames.slice(0, 2).map(name => ({ name, location: 'query' as const }))
        const idPath = deterministicIdPath(ep.pathTemplate)
        const originResources = resourceQueue.filter(item => item.origin === ep.origin)
        let score = ep.riskScore
        if (paramCandidates.length) score += 25
        if (idPath) score += 12
        if ((ep.sinkKinds ?? []).length > 0) score += 10
        if (originResources.length > 0) score += 15
        // Generic hints that a route consumes query input even when recon did not persist params.
        if (/\b(?:search|query|filter|export|report|list|lookup|find|browse)\b/i.test(ep.pathTemplate)) score += 20
        if (/^\/api\/[a-z][a-z0-9_-]{1,40}$/i.test(ep.pathTemplate.replace(/\?.*$/, ''))) score += 8
        // Prefer routes with injectable parameters before path-only id routes.
        if (!paramCandidates.length && !idPath) score -= 20
        return { ep, paramCandidates, idPath, originResources, score }
      })
      .filter(item => {
        // Nothing testable: path placeholders without harvested ids and no injectable parameter.
        const placeholderOnly = /:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z0-9_]+\}|\[[A-Za-z0-9_]+\]/.test(item.ep.pathTemplate)
        if (item.paramCandidates.length) return true
        if (item.idPath !== null && item.originResources.length > 0) return true
        return !placeholderOnly
      })
      .sort((a, b) => b.score - a.score)

    if (!ranked.length) return

    const maxEndpoints = Math.min(22, Math.max(4, Math.floor((current.dynamicStepBudget ?? 24) * 0.9)))
    const requestCap = current.budgetRequests > 0
      ? Math.max(0, Math.min(200, current.budgetRequests - current.spentRequests))
      : 200
    if (requestCap < 6) return

    let requestsUsed = 0
    let findingsCreated = 0
    try {
      for (const item of ranked.slice(0, maxEndpoints)) {
        if (requestsUsed >= requestCap || signal.aborted) break
        const latest = this.storage.run(current.id)
        if (latest.status !== 'running' || latest.phase !== 'investigation') break
        if (this.storage.checkBudgetExceeded(current.id)) break
        if (!approvedOrigins.has(item.ep.origin)) continue

        const perEndpointCap = Math.max(4, Math.min(16, requestCap - requestsUsed))
        if (perEndpointCap < 4) break

        const base = {
          origin: item.ep.origin,
          runId: current.id,
          assignmentId: claimed.id,
          storage: this.storage,
          maxRequests: perEndpointCap,
          onExchange: recordExchange,
        }

        // 1) Cross-persona object authz (ID-bearing routes with harvested owner resources).
        if (item.idPath && tier >= 2 && item.originResources.length > 0) {
          const resource = item.originResources[0]
          const owner = resource.ownerPersona
          const other = personaHandles.find(handle => handle !== owner)
          if (other) {
            let outcome
            try {
              outcome = await probeDifferential({
                ...base,
                probeClass: 'authz_matrix',
                method: 'GET',
                pathAndQuery: item.idPath,
                persona: owner,
                ownerPersona: owner,
                otherPersona: other,
                resourceIds: item.originResources.slice(0, 3).map(r => r.resourceId),
                includeAnonymous: false,
                includeHeaderBypass: false,
              }, this.broker, grant, this.canaryBroker, signal)
            } catch (error) {
              if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
              outcome = undefined
            }
            if (outcome) {
              requestsUsed += outcome.requestsSent
              this.host.markEndpointCoverage(latest, item.ep.origin, 'GET', item.idPath, 'diff:authz_matrix')
              const unauthorized = outcome.anomalies.find(a => a.type === 'unauthorized_access')
              if (outcome.verdict === 'signal' && unauthorized) {
                const resourceId = typeof unauthorized.resourceId === 'string' ? unauthorized.resourceId : resource.resourceId
                const probePath = item.idPath.replace('{{id}}', encodeURIComponent(resourceId))
                const controlPath = item.idPath.replace('{{id}}', encodeURIComponent(resourceId))
                const findingId = this.recordDeterministicFinding({
                  run: latest,
                  assignment: claimed,
                  asset,
                  spec: {
                    ...baseReplaySpecFields(item.ep.origin, {
                      title: `Cross-persona object access · ${item.ep.method} ${item.ep.pathTemplate.slice(0, 80)}`,
                      category: 'broken-access-control',
                      cwe: 'CWE-639',
                      severity: 'high',
                      severityRationale: `Persona ${owner} owns ${resourceId}; persona ${other} received HTTP ${String(unauthorized.status)} on the same object.`,
                      impact: 'Horizontal privilege escalation: one tenant can read another tenant\'s object by ID.',
                      remediation: 'Enforce an ownership/tenant predicate on the object lookup before returning or mutating it.',
                      recheckInstructions: 'Replay the owner control and the cross-persona probe after the fix.',
                    }),
                    kind: 'http_chain',
                    spaCatchallControl: false,
                    assertionsJq: '{ controlPassed: (.steps.ctrl.status == 200), confirmed: (.steps.prb.status == 200), observed: ("probe status " + (.steps.prb.status | tostring)), expected: "cross-persona probe denied" }',
                    steps: [
                      { id: 'ctrl', role: 'control', description: `Owner ${owner} reads its own object`, request: { origin: item.ep.origin, method: 'GET', pathAndQuery: controlPath, persona: owner, followRedirects: false } },
                      { id: 'prb', role: 'probe', description: `Persona ${other} replays the owner object id`, request: { origin: item.ep.origin, method: 'GET', pathAndQuery: probePath, persona: other, followRedirects: false } },
                    ],
                  },
                  factData: {
                    subkind: 'differential_anomaly',
                    probeClass: 'authz_matrix',
                    endpoint: item.ep.pathTemplate,
                    resourceId,
                    ownerPersona: owner,
                    otherPersona: other,
                    anomalies: [unauthorized],
                  },
                  factSummary: `Deterministic authz_matrix signal: ${other} reached ${owner}'s resource ${resourceId} at ${item.ep.method} ${item.ep.pathTemplate} (HTTP ${String(unauthorized.status)}).`,
                  exchangeIds: outcome.exchangeIds,
                  secrets: currentSecrets(),
                })
                if (findingId) findingsCreated += 1
              }
            }
            continue
          }
        }

        // 2) SQL injection differential on parameterized routes (non-destructive boolean/error only).
        // When recon did not persist parameters, discover them first with the deterministic
        // param-differential surface mode (bounded), then inject into the discovered names.
        let candidateParams: Array<{ name: string; location: 'query' | 'json' | 'form' }> = item.paramCandidates
        if (!candidateParams.length && item.ep.method !== 'DELETE' && requestsUsed < requestCap - 6) {
          try {
            const discovery = await probeSurface({
              origin: item.ep.origin,
              mode: 'params',
              basePath: item.ep.pathTemplate.split('?')[0],
              paramLocation: 'query',
              methods: ['GET'],
              persona: personaHandles[0],
              maxRequests: Math.max(4, Math.min(12, requestCap - requestsUsed - 4)),
              onExchange: recordExchange,
            }, this.broker, grant, signal)
            requestsUsed += discovery.requestsSent
            this.host.markEndpointCoverage(latest, item.ep.origin, 'GET', item.ep.pathTemplate, 'surface:params')
            const discovered = [...new Set(
              discovery.anomalies
                .filter(a => a.kind === 'param' && typeof a.param === 'string')
                .map(a => String(a.param)),
            )].slice(0, 2)
            candidateParams = discovered.map(name => ({ name, location: 'query' as const }))
          } catch (error) {
            if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
          }
        }

        // Search-like routes commonly take a free-text term even when recon/OpenAPI did not record
        // the parameter name; try the conventional term once (bounded, non-destructive).
        if (!candidateParams.length && /(?:search|query|filter|find|lookup|browse)/i.test(item.ep.pathTemplate)) {
          candidateParams = [{ name: 'q', location: 'query' }]
        }

        for (const candidate of candidateParams.slice(0, 2)) {
          if (requestsUsed >= requestCap || signal.aborted) break
          const location = candidate.location
          const method = item.ep.method === 'POST' ? 'POST' : 'GET'
          if (method === 'POST' && !['query', 'json', 'form'].includes(location)) continue
          const baselineValue = DETERMINISTIC_NUMERIC_PARAM_RE.test(candidate.name) ? '1' : 'guardian'
          const quoteStyle: 'single' | 'double' | 'numeric' = DETERMINISTIC_NUMERIC_PARAM_RE.test(candidate.name) ? 'numeric' : 'single'
          const pathAndQuery = location === 'query'
            ? withQueryParam(item.ep.pathTemplate, candidate.name, baselineValue)
            : item.ep.pathTemplate.split('?')[0]
          const jsonBody = method === 'POST' && location === 'json'
            ? { [candidate.name]: baselineValue }
            : undefined
          let outcome
          try {
            outcome = await probeDifferential({
              ...base,
              probeClass: 'sqli_boolean',
              method,
              pathAndQuery,
              param: candidate.name,
              paramLocation: location,
              baselineValue,
              ...(jsonBody ? { jsonBody } : {}),
              ...(personaHandles[0] ? { persona: personaHandles[0] } : {}),
            }, this.broker, grant, this.canaryBroker, signal)
          } catch (error) {
            if (error instanceof BudgetExceededError || error instanceof BrokerDenied) break
            outcome = undefined
          }
          if (!outcome) continue
          requestsUsed += outcome.requestsSent
          this.host.markEndpointCoverage(latest, item.ep.origin, method, pathAndQuery, 'diff:sqli_boolean')
          const booleanSignal = outcome.anomalies.find(a => a.type === 'boolean_differential')
          const dbError = outcome.anomalies.find(a => a.type === 'db_error_fingerprint')
          if (outcome.verdict !== 'signal' || (!booleanSignal && !dbError)) continue
          const dialect = typeof dbError?.dialect === 'string' ? dbError.dialect : null
          const findingId = this.recordDeterministicFinding({
            run: latest,
            assignment: claimed,
            asset,
            spec: {
              ...baseReplaySpecFields(item.ep.origin, {
                title: `SQL parameterization differential · ${method} ${item.ep.pathTemplate.slice(0, 80)} (${candidate.name})`,
                category: 'injection-input',
                cwe: 'CWE-89',
                severity: 'high',
                severityRationale: `Deterministic ${booleanSignal ? 'boolean differential' : 'SQL error fingerprint'} observed on parameter "${candidate.name}"${dialect ? ` (${dialect})` : ''}.`,
                impact: 'Unparameterized SQL handling allows boolean/oracle-based data inference.',
                remediation: 'Bind the parameter with the ORM/query parameterizer and remove string interpolation.',
                recheckInstructions: 'Replay the boolean differential after switching to a bound parameter.',
              }),
              kind: 'sql_boolean_diff',
              targetOrigin: item.ep.origin,
              method,
              pathAndQuery,
              paramName: candidate.name,
              paramLocation: location,
              baselineValue,
              quoteStyle,
              ...(jsonBody ? { jsonBody } : {}),
              assertionsJq: '{ controlPassed: true, confirmed: true, observed: "deterministic boolean differential", expected: "parameterized query" }',
            },
            factData: {
              subkind: 'differential_anomaly',
              probeClass: 'sqli_boolean',
              endpoint: item.ep.pathTemplate,
              param: candidate.name,
              paramLocation: location,
              method,
              dialect,
              anomalies: outcome.anomalies.slice(0, 5),
            },
            factSummary: `Deterministic sqli_boolean signal on ${method} ${item.ep.pathTemplate} parameter "${candidate.name}"${dialect ? ` (${dialect} error fingerprint)` : ''}.`,
            exchangeIds: outcome.exchangeIds,
            secrets: currentSecrets(),
          })
          if (findingId) findingsCreated += 1
        }
      }

      this.storage.event(
        current.id,
        'deterministic_probes.summary',
        `Deterministic probe pass used ${requestsUsed} request(s) across ${Math.min(ranked.length, maxEndpoints)} endpoint(s) and proposed ${findingsCreated} replay spec(s).`,
        { requestsUsed, endpointsConsidered: ranked.length, endpointsProbed: Math.min(ranked.length, maxEndpoints), findingsCreated, requestCap },
      )
      this.storage.message(
        current.id,
        current.coordinatorId,
        'guardian',
        `No model profile is configured, so Guardian ran a bounded deterministic probe pass (${requestsUsed} requests) and proposed ${findingsCreated} deterministic replay spec(s) for Zero-LLM verification.`,
      )
    } finally {
      try {
        this.storage.updateWorker(claimed.id, {
          status: 'complete',
          outcome: `Deterministic probes: ${requestsUsed} request(s), ${findingsCreated} spec(s).`,
          lease: null,
          leaseExpiresAt: null,
        })
      } catch { /* run may have been deleted */ }
    }
  }


  /**
   * Explicit `--no-llm` deterministic closed loop. Risk-ranks the discovered surface, harvests
   * identifiers/fields from the target's own responses, runs the benign differential probes, turns
   * strong signals into identifier-bound DeclarativeReplaySpecs and lets the normal ReplayVerifier
   * decide. Only replay-confirmed runtime findings are persisted; unproven signals become det_lead
   * facts. No specialist steps are cancelled or hidden in this slice.
   */
  async runEngineInvestigation(run: Run, laneOptions: {
    /** @deprecated Phase A runs the same depth as `--no-llm`; kept for typed callers. */
    lane?: boolean
    signal?: AbortSignal
    maxDurationMs?: number
    onAssignment?: (assignmentId: string) => void
  } = {}): Promise<void> {
    const current = this.storage.run(run.id)
    if (current.status !== 'running' || current.phase !== 'investigation') return
    const approvedOrigins = this.host.approvedOriginsSet(current)
    if (current.capabilityTier < 1 || approvedOrigins.size === 0) return
    if (laneOptions.signal?.aborted) return

    // DELETE routes are part of the write surface: keep them so the engine can build the
    // function-level authorization hypothesis for them (the engine owns the tier gate).
    // Graphwire: read the full store (lossless), probe only the Phase-0 ranked subset when one
    // exists; otherwise use the risk-ranked cap. The store is never trimmed or rewritten.
    const allEndpoints = listEndpointsPaged(this.storage, current.id, { orderBy: 'risk' })
    const probeSelection = selectProbeCandidates({
      endpoints: allEndpoints,
      probePlan: this.host.probePlans.get(this.storage, current.id),
      cap: ENGINE_PROBE_CAP,
      approvedOrigins,
    })
    const storedEndpoints = probeSelection.targets
    try {
      this.storage.event(
        current.id,
        'deterministic_engine.probe_selection',
        `Probe selection ranked ${probeSelection.considered} candidate route(s) from ${probeSelection.storedRows} stored row(s); probing ${probeSelection.selected} (cap ${probeSelection.cap}; full store retained).`,
        probeSelectionMetrics(probeSelection),
      )
    } catch { /* metrics only */ }
    if (probeSelection.usedPlan) {
      try {
        this.storage.event(
          current.id,
          'deterministic_engine.probe_plan_applied',
          `Engine probing ${probeSelection.selected} of ${probeSelection.selected + probeSelection.skippedStored} candidate routes from the ranked plan (full store retained).`,
          { usedPlan: true, probed: probeSelection.selected, skippedStored: probeSelection.skippedStored },
        )
      } catch { /* run may be gone */ }
    }
    const paramsByEndpoint = indexEndpointParams(this.storage, current.id)

    const asset = current.candidates.find(c => approvedOrigins.has(c.origin) && current.approved.includes(c.id))
    if (!asset) return

    // Tier-A Program-Graph leads this pass will probe. They are attached to the assignment so the
    // dispatch funnel can attribute the lane to the exact code→runtime hypotheses it consumes
    // (bounded: the same cap the engine applies to lead-derived targets).
    const leadFacts = this.storage.listFacts(current.id, { includeTainted: false, limit: 200 })
    const codeLeadFactIds = leadFacts
      .filter(fact => fact.data?.kind === 'det_lead' && fact.data.source === 'program_graph')
      .map(fact => fact.id)
      .slice(0, 8)
    // Tier-A hypotheses outrank the generic surface in the engine's bounded risk prefix.
    const codeLeadTargets = prioritizeCodeLeadTargets(graphLeadTargets(leadFacts))
    const codeLeadKeys = new Set(codeLeadTargets.map(target =>
      `${target.method.toUpperCase()}|${target.pathTemplate}`))

    // Name the Tier-A hypotheses this pass drives: a dispatch is attributed to the route the lane
    // was created for, not to whichever exchange happened to land first.
    const codeLeadObjective = codeLeadTargets.length
      ? `Deterministic closed loop over Tier-A code leads (${[...new Set(codeLeadTargets.map(target =>
          `${target.method.toUpperCase()} ${target.pathTemplate}`))].slice(0, 6).join(', ')}): risk-ranked triage, differential probes and Zero-LLM replay verification.`
      : 'Deterministic closed loop: risk-ranked triage, differential probes and Zero-LLM replay verification.'
    const worker = this.storage.makeWorker(
      current,
      'investigation',
      asset,
      'Deterministic differential engine',
      codeLeadObjective.slice(0, 400),
      { sourceOrigins: [...approvedOrigins].sort(), ...(codeLeadFactIds.length ? { parentFactIds: codeLeadFactIds } : {}) },
    )
    const claimed = this.storage.updateWorker(worker.id, {
      status: 'running',
      lease: randomUUID(),
      leaseExpiresAt: Date.now() + 15 * 60_000,
    }) ?? worker
    if (laneOptions.onAssignment) {
      try { laneOptions.onAssignment(claimed.id) } catch { /* bookkeeping only */ }
    }
    const controller = new AbortController()
    if (laneOptions.signal) {
      if (laneOptions.signal.aborted) controller.abort(laneOptions.signal.reason)
      else laneOptions.signal.addEventListener('abort', () => controller.abort(laneOptions.signal?.reason), { once: true })
    }
    const job: Active = { assignment: claimed, origins: new Set(approvedOrigins), controller }
    const { grant, currentSecrets } = this.host.buildGrant(job, current, approvedOrigins)
    const signal = controller.signal

    const recordExchange = this.createFloorExchangeRecorder(current.id, claimed.id, currentSecrets)

    let leadCount = 0
    try {
      let derivedTargets: Array<{
        origin: string
        method: string
        pathTemplate: string
        riskScore: number
        source?: string
        params: Array<{ name: string; location: string }>
      }> = []
      try {
        const specTargets = this.deriveDeterministicRouteTargets(current, approvedOrigins, storedEndpoints)
        // Graphwire: Program-Graph code→runtime hypotheses are probed first by the floor. Their
        // concrete identifier-form reads seed the authz matrix when the sink route has no
        // collection of its own.
        const tenantLabels = tenantLabelsFromRoleLabels(
          [...resolveRunPersonas(this.storage, current.projectId, current.approvedPersonaIds).values()]
            .map(persona => persona.roleLabel),
        )
        const codeLeadIdentifierTargets = deriveCodeLeadIdentifierTargets({
          targets: codeLeadTargets,
          tenants: tenantLabels,
          existing: [...storedEndpoints, ...specTargets],
        })
        derivedTargets = [
          ...specTargets,
          ...await this.deriveRuntimeRouteMapTargets(current, approvedOrigins, grant, claimed, signal, recordExchange),
          ...codeLeadIdentifierTargets,
          ...codeLeadTargets,
          ...(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1'
            ? [...approvedOrigins].sort().flatMap(origin =>
                this.expandConventionalSurfaceTargets(
                  origin,
                  [...storedEndpoints, ...specTargets],
                ))
            : []),
        ].filter((target, idx, all) =>
          all.findIndex(other => other.origin === target.origin && other.method === target.method && other.pathTemplate === target.pathTemplate) === idx,
        )
      } catch (error) {
        this.storage.event(
          current.id,
          'deterministic_engine.derived_failed',
          `Derived route expansion failed: ${error instanceof Error ? error.message.slice(0, 200) : String(error).slice(0, 200)}`,
        )
      }

      const paramLocation = (value: string): EngineEndpoint['params'][number]['location'] | null => {
        return ['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var'].includes(value)
          ? value as EngineEndpoint['params'][number]['location']
          : null
      }

      const endpoints: EngineEndpoint[] = []
      const seenEndpoints = new Set<string>()
      const pushEndpoint = (endpoint: EngineEndpoint) => {
        const key = `${endpoint.origin}|${endpoint.method.toUpperCase()}|${endpoint.pathTemplate}`
        if (seenEndpoints.has(key)) return
        seenEndpoints.add(key)
        endpoints.push(endpoint)
      }
      for (const endpoint of storedEndpoints) {
        pushEndpoint({
          id: endpoint.id,
          origin: endpoint.origin,
          method: endpoint.method,
          pathTemplate: endpoint.pathTemplate,
          params: (paramsByEndpoint.get(endpoint.id) ?? []).flatMap(param => {
            const location = paramLocation(param.location)
            return location ? [{ name: param.name, location, isObjectId: param.isObjectId, isCsrf: param.isCsrf }] : []
          }),
          riskScore: codeLeadKeys.has(`${endpoint.method.toUpperCase()}|${endpoint.pathTemplate}`)
            ? Math.max(endpoint.riskScore, CODE_LEAD_PRIORITY_RISK)
            : endpoint.riskScore,
          sinkKinds: endpoint.sinkKinds,
          source: endpoint.source,
        })
      }
      for (const [idx, target] of derivedTargets.entries()) {
        pushEndpoint({
          id: `derived:${idx}:${target.method}:${target.pathTemplate}`,
          origin: target.origin,
          method: target.method,
          pathTemplate: target.pathTemplate,
          params: target.params.flatMap(param => {
            const location = paramLocation(param.location)
            return location ? [{ name: param.name, location }] : []
          }),
          riskScore: target.riskScore,
          source: target.source ?? 'openapi',
        })
      }
      if (!endpoints.length) return

      const tenantOf = (roleLabel: string): string | undefined => {
        const match = /\(([^()]+)\)\s*$/.exec(roleLabel)
        return match?.[1]?.trim() || undefined
      }
      const privilegeOf = (roleLabel: string): EnginePersona['privilege'] => {
        if (/admin|superuser|owner[-_ ]?admin/i.test(roleLabel)) return 'admin'
        if (/viewer|read[-_ ]?only|readonly|guest|auditor|audit/i.test(roleLabel)) return 'viewer'
        return 'member'
      }
      const personas: EnginePersona[] = [...resolveRunPersonas(this.storage, current.projectId, current.approvedPersonaIds).values()]
        .filter(persona => persona.originAllowlist.some(origin => approvedOrigins.has(origin)))
        .map(persona => ({
          handle: persona.handle,
          roleLabel: persona.roleLabel,
          privilege: privilegeOf(persona.roleLabel),
          tenant: tenantOf(persona.roleLabel),
        }))

      const envNumber = (name: string): number | undefined => {
        const parsed = Number(process.env[name])
        return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined
      }
      // Phase A has its own allowance in split mode (`floorRequestBudget`), so the floor can never
      // spend the agents' requests. Legacy mode keeps the shared remainder as the only cap. The
      // deep policy is unchanged: the floor is still never halved just because agents will run.
      this.host.beginFloorRequestPhase(current)
      const remainingRequests = this.host.phaseRequestRemaining(current) ?? 700
      const requestCap = Math.max(0, Math.min(envNumber('GUARDIAN_DETERMINISTIC_MAX_REQUESTS') ?? 1800, remainingRequests))
      const durationCap = laneOptions.maxDurationMs ?? envNumber('GUARDIAN_DETERMINISTIC_MAX_MS') ?? 240_000
      // v6 environment contract: shared staging gets a short, tightly capped floor pass so it can
      // never dominate the engagement budget, and every created entity carries the run tag.
      const environmentMode = this.storage.scopePolicy(current).mode
      const entityTag = environmentMode === 'staging_isolated' ? tenantTagForRun(current.id) : undefined
      const stagingCap = environmentMode === 'staging_isolated'
        ? Math.max(50, Math.floor((current.budgetRequests > 0 ? current.budgetRequests : requestCap) * 0.2))
        : requestCap
      const maxRequests = Math.min(requestCap, stagingCap)
      const maxDurationMs = environmentMode === 'staging_isolated'
        ? Math.min(durationCap, 90_000)
        : durationCap
      const maxHypotheses = envNumber('GUARDIAN_DETERMINISTIC_MAX_HYPOTHESES') ?? 90

      this.storage.event(
        current.id,
        'deterministic_engine.started',
        `Deterministic engine triaging ${endpoints.length} endpoint(s) (request cap ${maxRequests}, ${Math.round(maxDurationMs / 1000)}s).`,
        {
          endpoints: endpoints.length,
          stored: storedEndpoints.length,
          derived: derivedTargets.length,
          personas: personas.length,
          maxRequests,
          maxDurationMs,
        },
      )

      const report = await runDeterministicEngine({
        runId: current.id,
        assignmentId: claimed.id,
        signal,
        endpoints,
        personas,
        broker: this.broker,
        grant,
        backend: this.backend,
        canaryBroker: this.canaryBroker,
        browser: this.browser,
        storage: this.storage,
        tier: current.capabilityTier,
        maxRequests,
        maxDurationMs,
        maxHypotheses,
        environmentMode,
        ...(entityTag ? { entityTag } : {}),
        ...(entityTag ? { cleanupEndpoints: allEndpoints } : {}),
        recordExchange,
        log: (kind, message, data) => {
          try { this.storage.event(current.id, kind, message, data ?? {}) } catch { /* run may be gone */ }
        },
        onConfirmed: input => this.persistDeterministicConfirmed({
          run: this.storage.run(current.id),
          assignment: claimed,
          asset,
          confirmed: input,
          secrets: currentSecrets(),
        }),
        onLead: lead => {
          if (leadCount >= 16) return
          leadCount += 1
          const leadRun = this.storage.run(current.id)
          this.persistDeterministicLead({
            run: leadRun,
            assignment: claimed,
            lead,
            secrets: currentSecrets(),
          })
        },
      })

      const byClass = Object.entries(report.byClass)
        .map(([intent, stats]) => `${intent}:${stats.confirmed}/${stats.hypotheses}`)
        .join(' ')
      if (report.stagingTaggedMutations > 0 || report.stagingUntaggedSkipped > 0 || report.stagingCleaned > 0) {
        this.host.stagingTaggedMutations.set(current.id,
          (this.host.stagingTaggedMutations.get(current.id) ?? 0) + report.stagingTaggedMutations)
        this.host.stagingUntaggedSkipped.set(current.id,
          (this.host.stagingUntaggedSkipped.get(current.id) ?? 0) + report.stagingUntaggedSkipped)
        this.host.stagingCleaned.set(current.id,
          (this.host.stagingCleaned.get(current.id) ?? 0) + report.stagingCleaned)
        if (report.stagingCreatedEntityIds.length > 0) {
          const set = this.host.stagingCreatedEntities.get(current.id) ?? new Set<string>()
          for (const id of report.stagingCreatedEntityIds) set.add(id)
          this.host.stagingCreatedEntities.set(current.id, set)
        }
        this.storage.event(
          current.id,
          'staging.mutations',
          `Staging pass tagged ${report.stagingTaggedMutations} mutation(s), skipped ${report.stagingUntaggedSkipped} untaggable, cleaned ${report.stagingCleaned}.`,
          {
            stagingTaggedMutations: report.stagingTaggedMutations,
            stagingUntaggedSkipped: report.stagingUntaggedSkipped,
            stagingCleaned: report.stagingCleaned,
            createdEntityIds: report.stagingCreatedEntityIds.slice(0, 50),
          },
        )
      }
      this.storage.event(
        current.id,
        'deterministic_engine.summary',
        `Deterministic engine used ${report.requestsUsed} request(s), confirmed ${report.confirmed}, rejected ${report.rejectedSpecs}, leads ${report.leads}.`,
        {
          requestsUsed: report.requestsUsed,
          endpointsConsidered: report.endpointsConsidered,
          endpointsHarvested: report.endpointsHarvested,
          hypothesesFormed: report.hypothesesFormed,
          hypothesesRun: report.hypothesesRun,
          signals: report.signals,
          specsSubmitted: report.specsSubmitted,
          confirmed: report.confirmed,
          rejectedSpecs: report.rejectedSpecs,
          leads: report.leads,
          stoppedReason: report.stoppedReason,
          durationMs: report.durationMs,
          byClass,
          stagingTaggedMutations: report.stagingTaggedMutations,
          stagingUntaggedSkipped: report.stagingUntaggedSkipped,
          stagingCleaned: report.stagingCleaned,
        },
      )
      this.storage.message(
        current.id,
        current.coordinatorId,
        'guardian',
        `Deterministic engine finished: ${report.confirmed} confirmed finding(s) from ${report.hypothesesFormed} hypothesis(es), ${report.specsSubmitted} replay spec(s), ${report.requestsUsed} request(s) (${report.stoppedReason}).${byClass ? ` Classes ${byClass}.` : ''}`,
      )
    } finally {
      try {
        this.storage.updateWorker(claimed.id, {
          status: 'complete',
          outcome: 'Deterministic engine complete.',
          lease: null,
          leaseExpiresAt: null,
        })
      } catch { /* run may have been deleted */ }
    }
  }


  /**
   * Local-lab-only conventional action/noun expansion. Every candidate is still differentially
   * verified, so an extra route can only add a verified finding, never a raw claim.
   */
  expandConventionalSurfaceTargets(
    origin: string,
    existing: ReadonlyArray<{ method: string; pathTemplate: string }>,
  ): DerivedRouteTarget[] {
    const seen = new Set(existing.map(ep => `${origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`))
    const out: DerivedRouteTarget[] = []
    const add = (method: string, pathTemplate: string, riskScore = 12) => {
      const key = `${origin}|${method}|${pathTemplate}`
      if (seen.has(key)) return
      if (!pathTemplate.startsWith('/') || pathTemplate.length > 200) return
      if (/\.(?:js|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|mp4|pdf|zip|gz)$/i.test(pathTemplate)) return
      seen.add(key)
      const params: DerivedRouteParam[] = []
      for (const match of pathTemplate.matchAll(/:([A-Za-z0-9_]+)/g)) params.push({ name: match[1], location: 'path' })
      out.push({ origin, method, pathTemplate, riskScore, source: 'conventional', params })
    }
    const conventional: ReadonlyArray<[string, string, number]> = [
      ['GET', '/api/tokens', 18], ['POST', '/api/tokens', 15],
      ['GET', '/api/v1/whoami', 18], ['POST', '/api/v1/login', 12],
      ['GET', '/api/admin/activity', 18], ['GET', '/api/admin/users', 10],
      ['POST', '/api/admin/impersonate', 20],
      ['GET', '/api/staff', 12], ['POST', '/api/staff/:userId/role', 20],
      ['GET', '/api/downloads/reports', 18], ['POST', '/api/apps/import', 25],
      ['GET', '/api/v1/downloads/download', 20],
      ['POST', '/api/seats', 15], ['POST', '/api/credits', 12],
      ['POST', '/api/enrollments/accept', 18],
      ['GET', '/api/v1/search', 22],
      ['GET', '/api/accounts/search', 20],
      ['POST', '/api/queries/run', 22], ['POST', '/api/logs/filter', 22],
      ['GET', '/api/logs/view', 20], ['GET', '/api/logs', 8],
      ['GET', '/api/hooks', 14], ['POST', '/api/hooks', 22],
      ['POST', '/api/hooks/:webhookId/ping', 18],
      ['GET', '/api/links', 16], ['GET', '/api/links/:iid', 14],
      ['POST', '/api/links/:iid/fetch', 18],
      ['GET', '/api/v1/checkout/return', 18], ['GET', '/api/checkout/return', 16],
      ['POST', '/api/v1/orders/:orderId/confirm', 18],
      ['POST', '/api/orders/:orderId/confirm', 16],
      ['GET', '/api/v1/reports/sales', 16], ['GET', '/api/reports/sales', 16],
      ['POST', '/api/issues/:ticketId/notes', 18], ['GET', '/api/issues/:ticketId/view', 14],
      ['POST', '/api/jobs/:jobId/trigger', 16], ['POST', '/api/jobs/:jobId/complete', 14],
      ['POST', '/api/sso/import', 18], ['GET', '/api/sso/start', 10],
      ['GET', '/api/v1/customers/:customerId', 14], ['GET', '/api/v1/orders/:orderId', 14],
      ['GET', '/api/v1/wares/:productId/photos', 16], ['POST', '/api/v1/wares/:productId/photos', 22],
      ['POST', '/api/v1/manifests', 22], ['POST', '/api/v1/product-import', 18],
    ]
    for (const [method, path, risk] of conventional) add(method, path, risk)
    for (const ep of existing) {
      const bare = ep.pathTemplate.split('?')[0] || '/'
      if (bare.split('/').filter(Boolean).length > 4) continue
      if (/:/.test(bare)) continue
      if (ep.method.toUpperCase() === 'GET') add('POST', bare, 8)
      else if (ep.method.toUpperCase() === 'POST') add('GET', bare, 8)
    }
    return out.slice(0, 60)
  }


  /** Persist a replay-confirmed runtime finding. Never called for an unverified signal. */
  persistDeterministicConfirmed(input: {
    run: Run
    assignment: Assignment
    asset: Candidate
    confirmed: EngineConfirmed
    secrets: readonly NamedSecret[]
  }): string | null {
    const { run, assignment, asset, confirmed, secrets } = input
    const spec = confirmed.spec
    if (spec.kind === 'static_ast_proof') return null
    if (confirmed.result.verdict !== 'confirmed') return null
    const duplicate = this.checkSpecDuplicate(run, spec, this.verifiedEndpointOf(confirmed.result))
    if (duplicate.isDuplicate) return null

    const origins = [...new Set(replaySpecOrigins(spec))].filter(origin => this.host.permitted(run, origin))
    const fact = this.storage.addFact(run, assignment, {
      kind: 'note',
      origin: spec.origin,
      summary: `Replay-verified deterministic finding: ${spec.title}`,
      data: {
        subkind: 'deterministic_engine_confirmed',
        source: 'deterministic_engine',
        attribution: 'deterministic',
        vulnClass: confirmed.vulnClass,
        endpoint: confirmed.endpoint,
        probeClass: confirmed.hypothesis.probeClass,
        specKind: spec.kind,
        verdict: confirmed.result.verdict,
        verificationTier: confirmed.result.verificationTier ?? 'runtime_confirmed',
        controlPassed: confirmed.result.outcome.controlPassed,
        observed: confirmed.result.outcome.observed.slice(0, 400),
      },
      exchangeIds: confirmed.exchangeIds.slice(0, 5),
      sourceOrigins: origins,
      secrets,
    })

    const findingId = randomUUID()
    const specRow = this.host.createConfirmedReplaySpec(run, assignment, findingId, spec, origins, confirmed.result, secrets)
    const artifact = this.storage.addArtifact(
      run,
      assignment,
      'replay',
      `Deterministic verified · ${spec.title}`,
      JSON.stringify({
        replaySpecId: specRow.id,
        specSha256: specRow.specSha256,
        kind: spec.kind,
        verdict: confirmed.result.verdict,
        verificationTier: confirmed.result.verificationTier ?? 'runtime_confirmed',
        outcome: confirmed.result.outcome,
        exchangeIds: confirmed.result.exchangeIds,
        evidenceSha256: confirmed.result.evidenceSha256,
        evidencePayload: confirmed.result.evidencePayload,
      }, null, 2),
      `replay:${specRow.id}`,
      secrets,
    )
    const uniqueTitle = `${spec.title.slice(0, 150)} · ${confirmed.hypothesis.method} ${confirmed.endpoint}`.slice(0, 200)
    const finding: Finding = {
      id: findingId,
      origin: spec.origin,
      title: uniqueTitle,
      status: 'confirmed',
      verificationTier: 'runtime_confirmed',
      severity: spec.severity,
      reason: redact(confirmed.result.outcome.reason || spec.severityRationale, secrets),
      remediation: spec.remediation,
      impact: spec.impact,
      recheck: spec.recheckInstructions,
      category: spec.category,
      cwe: spec.cwe,
      confidence: 'high',
      verification: `Deterministic Zero-LLM ${spec.kind} replay confirmed (controlPassed=${confirmed.result.outcome.controlPassed}), verified by the engine's own differential pass.`,
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      fingerprintHash: duplicate.fingerprint.hash,
      chainFactIds: [fact.id],
      exchangeIds: [...new Set(confirmed.exchangeIds)].slice(0, 6),
      evidenceIds: [artifact.id],
      scopeRevision: run.scopeRevision,
    }
    const saved = this.storage.upsertChainFinding(
      run, asset.id, finding, specRow.id, origins,
      { provenance: 'floor', verificationClass: 'runtime_confirmed' },
    )
    this.storage.addGraphEdge(run.id, { fromKind: 'fact', fromId: fact.id, toKind: 'finding', toId: saved.id, edgeKind: 'proves' })
    recordReportedFindingCoverage(this.storage, run, assignment.id, spec.origin, spec.category, `Deterministic verified: ${spec.title}`, saved.id, (r, o) => this.host.permitted(r, o))
    this.storage.event(
      run.id,
      'deterministic_engine.confirmed',
      `Deterministic engine confirmed ${confirmed.vulnClass} on ${confirmed.endpoint} (${spec.kind}, attribution=deterministic).`,
      {
        attribution: 'deterministic',
        endpoint: confirmed.endpoint,
        vulnClass: confirmed.vulnClass,
        probeClass: confirmed.hypothesis.probeClass,
        specKind: spec.kind,
        findingId: saved.id,
        exchangeCount: confirmed.exchangeIds.length,
      },
    )
    return saved.id
  }


  /** Persist an unproven deterministic observation as a det_lead fact (never as a finding). */
  persistDeterministicLead(input: {
    run: Run
    assignment: Assignment
    lead: EngineLead
    secrets: readonly NamedSecret[]
  }): void {
    const { run, assignment, lead, secrets } = input
    const hyp = lead.hypothesis
    if (!this.host.permitted(run, hyp.endpoint.origin)) return
    const canaryId = lead.probe.anomalies
      .map(anomaly => anomaly.canaryId ?? anomaly.token ?? anomaly.canaryToken)
      .find((value): value is string => typeof value === 'string' && value.length > 0)
    try {
      this.storage.addFact(run, assignment, {
        kind: 'note',
        origin: hyp.endpoint.origin,
        summary: `Unverified deterministic lead (${hyp.probeClass}) on ${hyp.method} ${hyp.endpoint.pathTemplate}: ${lead.summary}`,
        data: {
          subkind: 'deterministic_engine_lead',
          source: 'deterministic_engine',
          kind: 'det_lead',
          attribution: 'deterministic',
          probeClass: hyp.probeClass,
          intent: hyp.intent,
          endpoint: hyp.endpoint.pathTemplate,
          method: hyp.method,
          param: hyp.param?.name ?? null,
          exchangeId: lead.probe.exchangeIds[0] ?? null,
          ...(canaryId ? { canaryId } : {}),
          reason: lead.summary,
          verdict: lead.probe.verdict,
          anomalies: lead.probe.anomalies.slice(0, 4),
        },
        exchangeIds: lead.probe.exchangeIds.slice(0, 5),
        sourceOrigins: [hyp.endpoint.origin],
        secrets,
      })
      this.storage.event(
        run.id,
        'deterministic_engine.lead',
        `Unverified deterministic lead: ${hyp.probeClass} ${hyp.method} ${hyp.endpoint.pathTemplate}.`,
        { attribution: 'deterministic', endpoint: hyp.endpoint.pathTemplate, probeClass: hyp.probeClass },
      )
    } catch { /* lead persistence is best-effort */ }
  }


  recordDeterministicFinding(input: {
    run: Run
    assignment: Assignment
    asset: Candidate
    spec: unknown
    factData: Record<string, unknown>
    factSummary: string
    exchangeIds: readonly string[]
    secrets: readonly NamedSecret[]
  }): string | null {
    const parsed = declarativeReplaySpecSchema.safeParse(input.spec)
    if (!parsed.success) return null
    const spec = parsed.data

    const duplicate = this.checkSpecDuplicate(input.run, spec)
    if (duplicate.isDuplicate) return null

    const fact = this.storage.addFact(input.run, input.assignment, {
      kind: 'note',
      origin: spec.origin,
      summary: input.factSummary,
      data: input.factData,
      exchangeIds: [...input.exchangeIds].slice(0, 5),
      sourceOrigins: [...new Set(replaySpecOrigins(spec))].filter(o => this.host.permitted(input.run, o)),
      secrets: input.secrets,
    })

    const findingId = randomUUID()
    const specRow = this.storage.createReplaySpec(input.run, input.assignment, findingId, spec, [...new Set(replaySpecOrigins(spec))])
    const artifact = this.storage.addArtifact(
      input.run,
      input.assignment,
      'replay',
      `Deterministic proposed spec · ${spec.title}`,
      JSON.stringify({ replaySpecId: specRow.id, specSha256: specRow.specSha256, spec }, null, 2),
      undefined,
      input.secrets,
    )
    const finding: Finding = {
      id: findingId,
      origin: spec.origin,
      title: spec.title,
      status: 'pending',
      severity: spec.severity,
      reason: spec.severityRationale,
      remediation: spec.remediation,
      impact: spec.impact,
      recheck: spec.recheckInstructions,
      category: spec.category,
      cwe: spec.cwe,
      confidence: 'medium',
      verification: `Pending Zero-LLM ${spec.kind} replay verification proposed deterministically (spec ${specRow.id}).`,
      findingKind: 'multi_step_chain',
      replaySpecId: specRow.id,
      fingerprintHash: duplicate.fingerprint.hash,
      chainFactIds: [fact.id],
      exchangeIds: [...new Set(input.exchangeIds)].slice(0, 6),
      evidenceIds: [artifact.id],
      scopeRevision: input.run.scopeRevision,
    }
    const saved = this.storage.upsertChainFinding(input.run, input.asset.id, finding, specRow.id, [...new Set(replaySpecOrigins(spec))])
    this.storage.makeWorker(
      input.run,
      'verification',
      input.asset,
      `Replay verify · ${spec.title.slice(0, 80)}`,
      `Zero-LLM deterministic replay verification of deterministically proposed spec ${specRow.id}.`,
      { stepId: specRow.id, sourceOrigins: [...new Set(replaySpecOrigins(spec))] },
    )
    this.storage.addGraphEdge(input.run.id, { fromKind: 'fact', fromId: fact.id, toKind: 'finding', toId: saved.id, edgeKind: 'proves' })
    return saved.id
  }

}
