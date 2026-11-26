// Formatting helpers shared by every run view. Pure functions, no React.

export const host = (origin: string | null | undefined) =>
  String(origin ?? '').replace(/^https?:\/\//, '').replace(/\/$/, '')

export const fmtN = (n: number | null | undefined) => (n == null ? '—' : Number(n).toLocaleString('en-US'))
export const fmtUsd = (n: number | null | undefined) => '$' + Number(n || 0).toFixed(2)
export const fmtTok = (n: number) => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? Math.round(n / 1e3) + 'k' : String(n || 0)
export const short = (id: string | null | undefined) => String(id ?? '').slice(0, 8)

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
export const pad = (n: number) => String(n).padStart(2, '0')
export const fmtTime = (ms: number) => { const d = new Date(ms); return pad(d.getHours()) + ':' + pad(d.getMinutes()) }
export const fmtTimeS = (ms: number) => { const d = new Date(ms); return fmtTime(ms) + ':' + pad(d.getSeconds()) }
export const fmtDay = (ms: number) => { const d = new Date(ms); return MON[d.getMonth()] + ' ' + d.getDate() }
export const fmtDate = (ms: number) => fmtDay(ms) + ', ' + fmtTime(ms)
/** Full local date + time for `title` tooltips (e.g. "Nov 22, 2026, 2:15 PM"). */
export const fmtFullDateTime = (ms: number) => {
  if (!Number.isFinite(ms)) return ''
  try {
    return new Date(ms).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })
  } catch {
    return fmtDate(ms)
  }
}
/** Human relative time: `< 24h` -> "Just now" / "8m ago" / "3h ago"; `>= 24h` -> "Nov 22". */
export const fmtAgo = (ms: number, now = Date.now()) => {
  if (!Number.isFinite(ms)) return ''
  const diff = Math.max(0, now - ms)
  if (diff < 60_000) return 'Just now'
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + 'm ago'
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + 'h ago'
  return fmtDay(ms)
}

/** Known URL query params used by run view sub-modes (preserved across selection updates). */
export const RUN_SUBMODE_PARAMS = ['mode', 'version'] as const

/** Read a single URL query param from `window.location.search` (SSR-safe). */
export function readRunUrlParam(key: string): string | null {
  if (typeof window === 'undefined') return null
  return new URLSearchParams(window.location.search).get(key)
}

/** Sync a single URL query param via `history.replaceState` without disturbing TanStack Router state. */
export function syncRunUrlParam(key: string, value: string | null | undefined) {
  if (typeof window === 'undefined') return
  const url = new URL(window.location.href)
  const prev = url.searchParams.get(key)
  if (!value) {
    if (prev === null) return
    url.searchParams.delete(key)
  } else {
    if (prev === value) return
    url.searchParams.set(key, value)
  }
  const next = url.pathname + url.search + url.hash
  window.history.replaceState(window.history.state, '', next)
}

const EVENT_KIND_LABELS: Record<string, string> = {
  'broker.exchange': 'HTTP exchange',
  'broker.allowed': 'Request allowed',
  'broker.denied': 'Request blocked',
  'broker.circuit_open': 'Host rate-limited',
  'broker.route_circuit': 'Route paused',
  'broker.persona_scope_mismatch': 'Test account scope mismatch',
  'worker.started': 'Worker started',
  'worker.complete': 'Worker finished',
  'worker.failed': 'Worker failed',
  'worker.canceled': 'Worker canceled',
  'worker.stall_retry': 'Worker retry',
  'worker.stall_failed': 'Worker stalled',
  'worker.provider_stall': 'Model response stalled',
  'worker.warm_pool_rotated': 'Worker container refreshed',
  'finding.proposed': 'Finding drafted',
  'finding.verified': 'Finding confirmed',
  'finding.updated': 'Finding updated',
  'finding.confirmation_conflict': 'Verification conflict',
  'finding.floor_preserved': 'Verified finding preserved',
  'verification.started': 'Verification started',
  'retest.queued': 'Fix verification queued',
  'retest.complete': 'Fix verification finished',
  'planner.round': 'Planning round',
  'planner.dry_streak': 'Planning stalled',
  'planner.capped_reinvestigations': 'Re-investigation limit reached',
  'planner.ready_steps_stranded': 'Queued steps waiting',
  'chain_step.created': 'Plan step added',
  'chain_step.canceled': 'Plan step canceled',
  'graph.compacted': 'Memory compacted',
  'fact.recorded': 'Fact recorded',
  'evidence.reused': 'Evidence reused',
  'evidence.restricted': 'Evidence restricted',
  'approval.requested': 'Approval requested',
  'approval.decided': 'Approval decided',
  'approval.auto_approved': 'Auto-approved by policy',
  'approval.auto_denied': 'Auto-denied by policy',
  'approval.policy_changed': 'Approval policy updated',
  'approval.pattern_approved': 'Similar requests approved',
  'approval.batch_approved': 'Pending requests approved',
  'approval.lease_granted': 'Approval window granted',
  'approval.lease_revoked': 'Approval window revoked',
  'approval.worker_parked': 'Worker waiting for approval',
  'approval.worker_resumed': 'Worker resumed after approval',
  'run.created': 'Run created',
  'run.paused': 'Run paused',
  'run.resumed': 'Run resumed',
  'run.budget_paused': 'Paused at budget limit',
  'budget.raised': 'Budget updated',
  'scope.approved': 'Scope approved',
  'scope.revoked': 'Scope updated',
  'scope.environment_mode': 'Environment mode set',
  'scope.route_denylist': 'Route blocklist updated',
  'scope.origin_role': 'Host role updated',
  'goal.revised': 'Goal updated',
  'discovery.consented': 'Discovery started',
  'discovery.complete': 'Discovery finished',
  'phase0.stage': 'Recon stage',
  'phase0.discovery': 'Recon discovery summary',
  'phase0.completed': 'Recon completed',
  'phase0.crawl_paged': 'State-graph crawl read',
  'phase0.read_paged': 'Surface store read',
  'phase0.privileged_surface': 'Privileged routes surfaced',
  'phase0.code_slices': 'Code slices attached',
  'phase0.program_graph': 'Program graph extracted',
  'phase0.param_discovery': 'Parameters discovered',
  'phase0.runtime_catalog': 'Runtime catalog built',
  'phase0.probe_plan': 'AST probe plan',
  'phase0.declared_surface': 'Declared API ingested',
  'phase0.truncation': 'Discovery cap reached',
  'threat_model.saved': 'Threat model saved',
  'threat_model.failed': 'Threat model failed',
  'review.planned': 'Review planned',
  'report.partial': 'Partial report saved',
  'report.complete': 'Final report ready',
  'board.message': 'Board message',
  'board.tainted': 'Board message marked outdated',
  'coordinator.message': 'Coordinator message',
  'hint.injected': 'Operator guidance added',
  'asset.candidate': 'Host discovered',
  'surface.probe': 'Surface check',
  'sast.run': 'Code scan',
  'code_audit.started': 'Code review started',
  'code_audit.complete': 'Code review finished',
  'patch.saved': 'Verified patch saved',
  'persona.authenticated': 'Test account signed in',
  'persona.auth_failed': 'Test account sign-in failed',
  'persona.refresh_failed': 'Test account session refresh failed',
  'scheduler.dispatch': 'Worker dispatched',
  'scheduler.queue_drain': 'Queue drained',
  'scheduler.multi_trial': 'Parallel verification',
  'trial.early_stopped': 'Trial stopped early',
  'deterministic_engine.confirmed': 'Automated check confirmed',
  'deterministic_engine.lead': 'Automated lead found',
  'deterministic_engine.summary': 'Automated scan summary',
  'deterministic_lane.started': 'Automated scan started',
  'deterministic_lane.failed': 'Automated scan failed',
  'deterministic_lane.aborting': 'Automated scan stopping',
  'deterministic_lane.metrics': 'Automated scan metrics',
  'deterministic_floor.summary': 'Baseline scan summary',
  'request_budget.phase_started': 'Request budget phase started',
  'request_budget.phase_ended': 'Request budget phase ended',
  'request_budget.floor_settled': 'Baseline budget settled',
  'request_budget.floor_exhausted': 'Baseline budget reached',
  'request_budget.agent_exhausted': 'Agent request budget reached',
  'agentic.assignment_metrics': 'Worker metrics',
  'agent.proof_obligation': 'Verification check',
  'agent.gap_validation': 'Coverage gap check',
  'agent.early_exit': 'Worker finished early',
  'oob.drain_complete': 'Callback check finished',
  'oob.receipt_confirmed': 'Callback verified',
  'proof_gaps.surfaced': 'Coverage gaps noted',
  'second_order_canary.surfaced': 'Delayed signal detected',
  'recovery.completed': 'Run recovered',
  'retention.pruned': 'Old records pruned',
  'staging.teardown': 'Lab teardown',
  'staging.untagged_skipped': 'Untagged route skipped',
  'interrupted': 'Run interrupted',
}

/** Convert raw dotted event keys (`broker.exchange`) into plain-English labels (`HTTP exchange`). */
export function fmtEventKind(kind: string): string {
  const exact = EVENT_KIND_LABELS[kind]
  if (exact) return exact
  const clean = kind.replace(/[._]+/g, ' ').trim()
  return clean ? clean.charAt(0).toUpperCase() + clean.slice(1) : 'Event'
}
/** "+mm:ss" / "h:mm:ss" offset from the run start, used in time columns. */
export const fmtRel = (ms: number, base: number) => {
  let s = Math.max(0, Math.round((ms - base) / 1000))
  const h = Math.floor(s / 3600); s -= h * 3600
  const m = Math.floor(s / 60); s -= m * 60
  return (h ? h + ':' + pad(m) : '+' + pad(m)) + ':' + pad(s)
}
export const fmtDur = (ms: number) => {
  const s = Math.round(ms / 1000)
  if (s < 60) return s + 's'
  const m = Math.floor(s / 60)
  if (m < 60) return m + 'm ' + pad(s % 60) + 's'
  return Math.floor(m / 60) + 'h ' + pad(m % 60) + 'm'
}
export const cap = (s: string | null | undefined) => String(s ?? '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
export const capF = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
export const plural = (n: number, w: string, p?: string) => fmtN(n) + ' ' + (n === 1 ? w : (p ?? w + 's'))
const WORDS = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty']
/** Small numbers as words ("two medium-severity weaknesses"), larger as digits. */
export const words = (n: number) => n < WORDS.length ? WORDS[n] : fmtN(n)
export const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v))

export const firstSentence = (input: string | null | undefined) => {
  const s = String(input ?? '').trim()
  const m = s.match(/^(.{20,150}?[.;:])(\s|$)/)
  let r = m ? m[1] : s.slice(0, 140)
  if (r.length >= 140 && !m) r = r.replace(/\s+\S*$/, '') + '…'
  return r.replace(/[.;:]$/, '')
}

/** Short label for a run in the rail / palette ("Tier 1 Deep Read-Only + Safe…"). */
export function runLabel(goal: string) {
  let g = String(goal || '').replace(/^(perform|conduct|run)\s+an?\s+/i, '').replace(/^strictly defensive,\s*non-destructive\s+/i, '')
  g = g.split(/[.:]/)[0]
  return g.charAt(0).toUpperCase() + g.slice(1)
}

/** Most common apex domain, if at least half the hosts share it (used to dim it in host labels). */
export function sharedApex(hosts: readonly string[]) {
  const cnt = new Map<string, number>()
  for (const h of hosts) {
    const k = h.split('.').slice(-2).join('.')
    cnt.set(k, (cnt.get(k) ?? 0) + 1)
  }
  const best = [...cnt.entries()].sort((a, b) => b[1] - a[1])[0]
  return best && best[1] >= hosts.length / 2 && hosts.length > 1 ? best[0] : null
}

export const isMac = () => typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
export const modKey = () => (isMac() ? '⌘' : 'Ctrl')

/** Body text for display: JSON is pretty-printed, anything else is returned as is; empty → ''. */
export function prettyBody(body: unknown, mediaType = ''): string {
  if (body == null) return ''
  if (typeof body !== 'string') return JSON.stringify(body, null, 2)
  const t = body.trim()
  if (!t) return ''
  if (mediaType.includes('json') || t.startsWith('{') || t.startsWith('[')) {
    try { return JSON.stringify(JSON.parse(t), null, 2) } catch { return body }
  }
  return body
}

// ---------------------------------------------------------------- Round-0 Recon Pipeline derivation (browser-safe)

export type Round0StageKey = 'fingerprint' | 'crawl' | 'templates' | 'auth' | 'ranking'
export type Round0StepStatus = 'done' | 'active' | 'pending'

export interface Round0PipelineStep {
  id: Round0StageKey
  index: number
  label: string
  shortLabel: string
  status: Round0StepStatus
  metric: string | null
}

export interface Round0HostSignal {
  origin: string
  host: string
  endpoints: number
  requests: number
  status401: number
  status403: number
  status5xx: number
  privileged: number
  score: number
}

export interface Round0PipelineState {
  steps: Round0PipelineStep[]
  activeStepIndex: number
  doneSteps: number
  isComplete: boolean
  stageBadge: string
  stageShort: string
  currentOrigin: string | null
  activeDetail: string | null
  counts: {
    endpoints: number
    params: number
    mappedHosts: number
    totalHosts: number
    authGated: number
    privileged: number
    requests: number
    rankedHosts: number
    seededSteps: number
  }
  frameworks: string[]
  hosts: Round0HostSignal[]
}

export interface Round0DerivationInput {
  assignment: {
    id: string
    phase: string
    status: string
    stepId?: string | null
    title?: string | null
    turnsUsed?: number | null
    requestsUsed?: number | null
    sourceOrigins?: readonly string[]
  }
  detail: {
    run: {
      phase: string
      status: string
      phase0CompletedAt?: number | null
      candidates?: readonly { id: string; origin: string }[]
      approved?: readonly string[]
    }
    endpoints?: readonly {
      origin: string
      method: string
      pathTemplate: string
      source?: string | null
      framework?: string | null
      authRequirement?: string | null
    }[]
    endpointParams?: readonly { id?: string }[]
    exchangesSummary?: readonly {
      id: string
      assignmentId?: string | null
      origin: string
      method: string
      pathAndQuery: string
      status: number
    }[]
    threatModel?: {
      entries?: readonly { origin: string; riskTier?: string }[]
    } | null
    chainSteps?: readonly { id: string }[]
    projection?: {
      totals?: {
        endpoints?: number
        endpointParams?: number
        exchanges?: number
      }
    } | null
  }
  events?: readonly {
    kind: string
    message?: string
    detail?: Record<string, unknown> | null
    createdAt?: number
  }[]
}

const ROUND0_PRIV_RE = /(?:^|\/)(?:admin|internal|staff|superuser|console|manage|rbac|audit|moderator|ops)(?:\/|$)/i
const ROUND0_API_RE = /^\/(?:api|rest|graphql|trpc|v\d+)(?:\/|$)/i
const ROUND0_STEP_DEFS: readonly { id: Round0StageKey; label: string; shortLabel: string }[] = [
  { id: 'fingerprint', label: 'Reachability & host fingerprint', shortLabel: 'Fingerprint' },
  { id: 'crawl', label: 'Crawl & state graph', shortLabel: 'Crawl' },
  { id: 'templates', label: 'API template & method probing', shortLabel: 'API probes' },
  { id: 'auth', label: 'Auth & privileged surface detection', shortLabel: 'Auth surface' },
  { id: 'ranking', label: 'Surface ranking & Round-1 worker plan', shortLabel: 'Ranking' },
]

/** Detect the orchestrator Round-0 Threat Model & Surface Ranking worker cleanly. */
export function isRound0ThreatModelWorker(a: {
  phase: string
  stepId?: string | null
  title?: string | null
}): boolean {
  if (a.phase !== 'threat_model' || a.stepId) return false
  return /Round-0|Threat Model/i.test(a.title ?? '')
}

function asNonNegInt(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0
}

/**
 * Pure browser-safe derivation of the Round-0 5-step recon stepper, discovery counters,
 * frameworks, and per-host signal table. Works seamlessly for both live runs emitting
 * `phase0.stage` telemetry AND historical/in-flight runs without `phase0.stage`.
 */
export function deriveRound0PipelineState(input: Round0DerivationInput): Round0PipelineState {
  const { assignment: a, detail, events = [] } = input
  const endpointsList = detail.endpoints ?? []
  const endpointParamsList = detail.endpointParams ?? []
  const allExchanges = detail.exchangesSummary ?? []
  const workerExchanges = allExchanges.filter(e => e.assignmentId === a.id)
  const threatEntries = detail.threatModel?.entries ?? []
  const chainStepsList = detail.chainSteps ?? []

  // Scan phase0.* and threat_model.saved events
  let latestStage: string | null = null
  let latestStageLabel: string | null = null
  let currentOrigin: string | null = null
  let stageHostsDone = 0
  let stageHostsTotal = 0
  let stageEndpoints = 0
  let stageParams = 0
  let stageRequests = 0
  let discoveryEndpoints = 0
  let discoveryParams = 0
  let discoveryRequests = 0
  let hasPhase0Discovery = false
  let hasPhase0Completed = false
  let hasCrawlPaged = false
  let hasTemplateRead = false
  let hasPrivilegedEvent = false
  let hasParamDiscoveryEvent = false
  let hasThreatModelSaved = false
  const frameworksSet = new Set<string>()
  const eventMappedOrigins = new Set<string>()
  const privilegedKeys = new Set<string>()
  const privilegedByOrigin = new Map<string, Set<string>>()

  const noteFramework = (fw: unknown) => {
    if (typeof fw !== 'string') return
    const clean = fw.trim()
    if (clean) frameworksSet.add(clean)
  }

  for (const ev of events) {
    const d = (ev.detail && typeof ev.detail === 'object' ? ev.detail : {}) as Record<string, unknown>
    if (ev.kind === 'phase0.stage') {
      if (typeof d.stage === 'string' && d.stage) latestStage = d.stage
      if (typeof d.label === 'string' && d.label) latestStageLabel = d.label
      else if (ev.message) latestStageLabel = ev.message
      if (typeof d.origin === 'string' && d.origin) {
        currentOrigin = d.origin
        eventMappedOrigins.add(d.origin)
      }
      stageHostsDone = Math.max(stageHostsDone, asNonNegInt(d.hostsDone))
      stageHostsTotal = Math.max(stageHostsTotal, asNonNegInt(d.hostsTotal))
      stageEndpoints = Math.max(stageEndpoints, asNonNegInt(d.endpointsDiscovered))
      stageParams = Math.max(stageParams, asNonNegInt(d.paramsDiscovered))
      stageRequests = Math.max(stageRequests, asNonNegInt(d.requestsUsed))
      if (Array.isArray(d.frameworks)) d.frameworks.forEach(noteFramework)
    } else if (ev.kind === 'phase0.discovery') {
      hasPhase0Discovery = true
      discoveryEndpoints = Math.max(discoveryEndpoints, asNonNegInt(d.endpointsDiscovered))
      discoveryParams = Math.max(discoveryParams, asNonNegInt(d.paramsDiscovered))
      discoveryRequests = Math.max(discoveryRequests, asNonNegInt(d.requestsUsed))
      if (Array.isArray(d.frameworksDetected)) d.frameworksDetected.forEach(noteFramework)
    } else if (ev.kind === 'phase0.completed') {
      hasPhase0Completed = true
    } else if (ev.kind === 'phase0.crawl_paged') {
      hasCrawlPaged = true
      if (typeof d.origin === 'string' && d.origin) eventMappedOrigins.add(d.origin)
    } else if (ev.kind === 'phase0.read_paged') {
      if (typeof d.origin === 'string' && d.origin) eventMappedOrigins.add(d.origin)
      if (d.phase === 'template_api_paths' || d.phase === 'detail_methods') hasTemplateRead = true
    } else if (ev.kind === 'phase0.privileged_surface') {
      hasPrivilegedEvent = true
      const originVal = typeof d.origin === 'string' ? d.origin : ''
      if (Array.isArray(d.routes)) {
        for (const r of d.routes) {
          if (!r || typeof r !== 'object') continue
          const rec = r as Record<string, unknown>
          const m = typeof rec.method === 'string' ? rec.method.toUpperCase() : 'GET'
          const p = typeof rec.pathTemplate === 'string' ? rec.pathTemplate : ''
          if (!p) continue
          const key = `${originVal}|${m} ${p}`
          privilegedKeys.add(key)
          if (originVal) {
            let set = privilegedByOrigin.get(originVal)
            if (!set) { set = new Set(); privilegedByOrigin.set(originVal, set) }
            set.add(`${m} ${p}`)
          }
        }
      }
    } else if (ev.kind === 'phase0.param_discovery') {
      hasParamDiscoveryEvent = true
    } else if (ev.kind === 'threat_model.saved') {
      hasThreatModelSaved = true
    }
  }

  // Per-host signal aggregation
  type HostAcc = {
    origin: string
    endpoints: number
    requests: number
    status401: number
    status403: number
    status5xx: number
    privSet: Set<string>
  }
  const hostMap = new Map<string, HostAcc>()
  const ensureHost = (origin: string): HostAcc => {
    let acc = hostMap.get(origin)
    if (!acc) {
      acc = { origin, endpoints: 0, requests: 0, status401: 0, status403: 0, status5xx: 0, privSet: new Set() }
      hostMap.set(origin, acc)
    }
    return acc
  }

  for (const origin of a.sourceOrigins ?? []) if (origin) ensureHost(origin)
  for (const entry of threatEntries) if (entry.origin) ensureHost(entry.origin)
  for (const origin of eventMappedOrigins) if (origin) ensureHost(origin)

  let apiEndpoints = 0
  for (const ep of endpointsList) {
    if (!ep.origin) continue
    const acc = ensureHost(ep.origin)
    acc.endpoints += 1
    noteFramework(ep.framework)
    const method = (ep.method || 'GET').toUpperCase()
    const path = ep.pathTemplate || '/'
    if (ROUND0_API_RE.test(path) || ep.source === 'openapi' || ep.source === 'graphql' || ep.source === 'surface_probe') {
      apiEndpoints += 1
    }
    const authReq = (ep.authRequirement ?? '').toLowerCase()
    if (ROUND0_PRIV_RE.test(path) || authReq.includes('admin') || authReq.includes('persona:')) {
      const k = `${method} ${path}`
      acc.privSet.add(k)
      privilegedKeys.add(`${ep.origin}|${k}`)
    }
  }

  for (const [origin, set] of privilegedByOrigin) {
    const acc = ensureHost(origin)
    for (const k of set) acc.privSet.add(k)
  }

  let authGated = 0
  for (const ex of workerExchanges) {
    if (!ex.origin) continue
    const acc = ensureHost(ex.origin)
    acc.requests += 1
    if (ex.status === 401) { acc.status401 += 1; authGated += 1 }
    else if (ex.status === 403) { acc.status403 += 1; authGated += 1 }
    else if (ex.status >= 500 && ex.status < 600) acc.status5xx += 1
  }

  const hosts: Round0HostSignal[] = [...hostMap.values()]
    .map(acc => {
      const privileged = acc.privSet.size
      const score = acc.endpoints * 3 + privileged * 4 + (acc.status401 + acc.status403) * 2 + acc.status5xx * 2 + acc.requests
      return {
        origin: acc.origin,
        host: host(acc.origin),
        endpoints: acc.endpoints,
        requests: acc.requests,
        status401: acc.status401,
        status403: acc.status403,
        status5xx: acc.status5xx,
        privileged,
        score,
      }
    })
    .sort((x, y) => y.score - x.score || y.endpoints - x.endpoints || y.requests - x.requests || x.host.localeCompare(y.host))

  const approvedCount = detail.run.approved?.length ?? 0
  const candidateCount = detail.run.candidates?.length ?? 0
  const totalHosts = Math.max(
    a.sourceOrigins?.length ?? 0,
    stageHostsTotal,
    approvedCount || candidateCount,
    hosts.length,
  )

  const endpoints = Math.max(
    asNonNegInt(detail.projection?.totals?.endpoints),
    endpointsList.length,
    stageEndpoints,
    discoveryEndpoints,
  )
  const params = Math.max(
    asNonNegInt(detail.projection?.totals?.endpointParams),
    endpointParamsList.length,
    stageParams,
    discoveryParams,
  )
  const requests = Math.max(
    asNonNegInt(a.requestsUsed),
    workerExchanges.length,
    stageRequests,
    discoveryRequests,
  )
  const privileged = privilegedKeys.size
  const rankedHosts = threatEntries.length
  const seededSteps = chainStepsList.length

  const observedMappedOrigins = new Set<string>(eventMappedOrigins)
  for (const h of hosts) {
    if (h.endpoints > 0 || h.requests > 0) observedMappedOrigins.add(h.origin)
  }
  let mappedHosts = Math.max(observedMappedOrigins.size, stageHostsDone)
  if (totalHosts > 0) mappedHosts = Math.min(totalHosts, mappedHosts)

  const workerDone = a.status === 'complete'
  const workerStopped = a.status === 'failed' || a.status === 'canceled'
  const hasThreatModel = Boolean(detail.threatModel) || hasThreatModelSaved
  const isComplete = workerDone || (hasThreatModel && a.status !== 'running')
  const phase0Done = Boolean(detail.run.phase0CompletedAt) || hasPhase0Discovery || hasPhase0Completed || hasThreatModel

  if (isComplete && totalHosts > 0 && mappedHosts === 0 && rankedHosts > 0) {
    mappedHosts = Math.min(totalHosts, rankedHosts)
  }

  let activeStepIndex = 0
  if (isComplete) {
    activeStepIndex = 4
  } else if (phase0Done) {
    activeStepIndex = 4
  } else if (latestStage) {
    switch (latestStage) {
      case 'static_ast':
        activeStepIndex = 0
        break
      case 'host_fingerprint':
        activeStepIndex = totalHosts > 1 && (mappedHosts > 0 || endpoints > 0 || hasCrawlPaged) ? 1 : 0
        break
      case 'crawl_state_graph':
        activeStepIndex = 1
        break
      case 'api_templates':
        activeStepIndex = 2
        break
      case 'auth_privileged':
      case 'param_discovery':
        activeStepIndex = 3
        break
      default:
        activeStepIndex = endpoints > 0 || hasCrawlPaged ? 1 : 0
        break
    }
  } else {
    // Fallback for historical / already-running runs without phase0.stage telemetry
    if (hasPrivilegedEvent || hasParamDiscoveryEvent) activeStepIndex = 3
    else if (hasTemplateRead) activeStepIndex = 2
    else if (hasCrawlPaged || endpoints > 0 || mappedHosts >= 2 || requests >= 5) activeStepIndex = 1
    else activeStepIndex = 0
  }

  const frameworks = [...frameworksSet].sort((x, y) => x.localeCompare(y))

  const stepMetric = (id: Round0StageKey, status: Round0StepStatus): string | null => {
    switch (id) {
      case 'fingerprint': {
        if (frameworks.length > 0) {
          return frameworks.slice(0, 2).join(', ') + (frameworks.length > 2 ? ` +${frameworks.length - 2}` : '')
        }
        if (totalHosts > 0) return status === 'done' ? `${totalHosts} ${totalHosts === 1 ? 'host' : 'hosts'}` : `${mappedHosts}/${totalHosts} hosts`
        return requests > 0 ? `${fmtN(requests)} req` : null
      }
      case 'crawl': {
        const parts: string[] = []
        if (totalHosts > 0 && (mappedHosts > 0 || status !== 'pending')) parts.push(`${mappedHosts}/${totalHosts} hosts`)
        if (endpoints > 0 || status !== 'pending') parts.push(`${fmtN(endpoints)} ${endpoints === 1 ? 'endpoint' : 'endpoints'}`)
        return parts.length ? parts.join(' · ') : null
      }
      case 'templates': {
        if (params > 0) return `${fmtN(params)} ${params === 1 ? 'param' : 'params'}`
        if (apiEndpoints > 0) return `${fmtN(apiEndpoints)} API ${apiEndpoints === 1 ? 'route' : 'routes'}`
        return status === 'done' ? 'Checked' : null
      }
      case 'auth': {
        if (privileged > 0 && authGated > 0) return `${fmtN(privileged)} priv · ${fmtN(authGated)} 401/403`
        if (privileged > 0) return `${fmtN(privileged)} privileged`
        if (authGated > 0) return `${fmtN(authGated)} 401/403`
        return status === 'done' ? '0 gated' : null
      }
      case 'ranking': {
        const parts: string[] = []
        if (rankedHosts > 0) parts.push(`${fmtN(rankedHosts)} ranked`)
        if (seededSteps > 0) parts.push(`${fmtN(seededSteps)} ${seededSteps === 1 ? 'step' : 'steps'}`)
        return parts.length ? parts.join(' · ') : null
      }
    }
  }

  const steps: Round0PipelineStep[] = ROUND0_STEP_DEFS.map((def, i) => {
    const status: Round0StepStatus = isComplete
      ? 'done'
      : workerStopped
        ? (i < activeStepIndex ? 'done' : 'pending')
        : i < activeStepIndex
          ? 'done'
          : i === activeStepIndex
            ? 'active'
            : 'pending'
    return {
      id: def.id,
      index: i + 1,
      label: def.label,
      shortLabel: def.shortLabel,
      status,
      metric: stepMetric(def.id, status),
    }
  })

  const doneSteps = steps.filter(s => s.status === 'done').length
  const activeStep = steps[activeStepIndex] ?? steps[0]!
  const stageBadge = isComplete
    ? '5/5 · Ranked'
    : workerStopped
      ? `Stopped · ${activeStepIndex + 1}/5`
      : `Stage ${activeStepIndex + 1}/5 · ${activeStep.shortLabel}`
  const stageShort = isComplete
    ? '5/5 Ranked'
    : workerStopped
      ? `${activeStepIndex + 1}/5 Stopped`
      : `${activeStepIndex + 1}/5 ${activeStep.shortLabel}`

  return {
    steps,
    activeStepIndex,
    doneSteps,
    isComplete,
    stageBadge,
    stageShort,
    currentOrigin,
    activeDetail: !isComplete && !workerStopped ? latestStageLabel : null,
    counts: {
      endpoints,
      params,
      mappedHosts,
      totalHosts,
      authGated,
      privileged,
      requests,
      rankedHosts,
      seededSteps,
    },
    frameworks,
    hosts,
  }
}
