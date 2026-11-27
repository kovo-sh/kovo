/**
 * Kovo v4 recall benchmark core: pure, dependency-light helpers shared by the
 * live pipeline (`benchmark-live.ts`) and the CLI/orchestrator (`benchmark-recall.ts`).
 *
 * Nothing in this file talks to the network. It owns the funnel arithmetic, the
 * deterministic failure-bucket attribution, the baseline diff maths and the
 * Markdown report formatter.
 */
import { failureTaxonomyBuckets } from '../src/domain.ts'
import type { BenchmarkFunnel, FailureTaxonomyBucket } from '../src/domain.ts'

export type BenchmarkProfileMode = 'v3-baseline' | 'v4-full'
export type BenchmarkSuiteName = 'xben-25' | 'held-out-saas'

export interface ManifestChallenge {
  id: string
  name?: string
  vulnClass: string
  cwe?: string
  endpoint: string
  method?: string
  param?: string
  encoding?: string
  flagMarker?: string
  expectedReplayKind?: string
  tierRequired?: number
  requiresAuth?: boolean
  requiresCsrf?: boolean
  requiresBrowser?: boolean
  requiresV4Feature?: string
  isDecoy?: boolean
  decoyReason?: string
  patchId?: string
  persona?: string
  [key: string]: unknown
}

export interface BenchmarkManifest {
  challenges: ManifestChallenge[]
  [key: string]: unknown
}

/**
 * Telemetry observed for one manifest entry while the pipeline ran. Scoring-only:
 * the manifest is the answer key used AFTER probing to decide which stages a target reached.
 */
export interface TargetTrace {
  id: string
  isDecoy: boolean
  vulnClass?: string
  surfaceDiscovered: boolean
  hypothesisFormed: boolean
  signalObserved: boolean
  specSubmitted: boolean
  confirmed: boolean
  probeClass?: string | null
  verdict?: string | null
  /** The endpoint/param needs a body encoding the active profile cannot emit. */
  encodingUnsupported?: boolean
  /** A probe or replay request was rejected for a missing/invalid CSRF token. */
  csrfRejected?: boolean
  /** Session/browser state was lost between control and probe steps. */
  contextReset?: boolean
  /** The required capability tier was above what the run was granted. */
  tierBlocked?: boolean
  /** The jq assertion errored or produced invalid output. */
  jqError?: boolean
  /** The probe response matched the SPA/catch-all baseline. */
  spaCatchall?: boolean
  /** The run budget (requests/time) ran out before the target was fully processed. */
  budgetExhausted?: boolean
  /** True when a confirmed claim had no compatible manifest entry (off-manifest over-claim). */
  unmatchedConfirmed?: boolean
  notes?: string[]
}

export type FailureTaxonomy = Record<FailureTaxonomyBucket, number>

export function emptyFailureTaxonomy(): FailureTaxonomy {
  const out = {} as FailureTaxonomy
  for (const bucket of failureTaxonomyBuckets) out[bucket] = 0
  return out
}

export function emptyFunnel(): BenchmarkFunnel {
  return { targetVulns: 0, surfaceDiscovered: 0, hypothesisFormed: 0, signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0 }
}

/** Force the stage flags into a cascade so a later stage can never be true without the earlier ones. */
export function normalizeTrace(trace: TargetTrace): TargetTrace {
  const surfaceDiscovered = trace.surfaceDiscovered
  const hypothesisFormed = surfaceDiscovered && trace.hypothesisFormed
  const signalObserved = hypothesisFormed && trace.signalObserved
  const specSubmitted = signalObserved && trace.specSubmitted
  const confirmed = specSubmitted && trace.confirmed
  return { ...trace, surfaceDiscovered, hypothesisFormed, signalObserved, specSubmitted, confirmed }
}

/** Decoys never enter the recall denominator or the funnel. */
export function buildFunnel(traces: readonly TargetTrace[]): BenchmarkFunnel {
  const funnel = emptyFunnel()
  for (const raw of traces) {
    if (raw.isDecoy) continue
    const t = normalizeTrace(raw)
    funnel.targetVulns += 1
    if (t.surfaceDiscovered) funnel.surfaceDiscovered += 1
    if (t.hypothesisFormed) funnel.hypothesisFormed += 1
    if (t.signalObserved) funnel.signalObserved += 1
    if (t.specSubmitted) funnel.specSubmitted += 1
    if (t.confirmed) funnel.zeroLlmConfirmed += 1
  }
  return funnel
}

export function isMonotonicFunnel(f: BenchmarkFunnel): boolean {
  return f.targetVulns >= f.surfaceDiscovered &&
    f.surfaceDiscovered >= f.hypothesisFormed &&
    f.hypothesisFormed >= f.signalObserved &&
    f.signalObserved >= f.specSubmitted &&
    f.specSubmitted >= f.zeroLlmConfirmed
}

export function assertMonotonicFunnel(f: BenchmarkFunnel): void {
  if (!isMonotonicFunnel(f)) {
    throw new Error(`Benchmark funnel is not monotonic: ${JSON.stringify(f)}`)
  }
}

/**
 * Deterministic failure attribution. Returns null for a confirmed target, otherwise exactly one
 * of the 11 taxonomy buckets, chosen from the earliest funnel stage the target failed to clear.
 */
export function attributeFailureBucket(input: TargetTrace): FailureTaxonomyBucket | null {
  const t = normalizeTrace(input)
  if (t.confirmed) return null
  if (t.budgetExhausted) return 'budget_exhausted'
  if (!t.surfaceDiscovered) return 'surface_miss'
  if (!t.hypothesisFormed) return t.encodingUnsupported ? 'form_encoding_missing' : 'hypothesis_miss'
  if (!t.signalObserved) {
    if (t.csrfRejected) return 'csrf_blocked'
    if (t.contextReset) return 'context_reset'
    if (t.tierBlocked) return 'tier_blocked'
    if (t.encodingUnsupported) return 'form_encoding_missing'
    return 'trigger_miss'
  }
  if (!t.specSubmitted) {
    if (t.tierBlocked) return 'tier_blocked'
    return 'replay_spec_miss'
  }
  // A spec was verified but did not confirm.
  if (t.spaCatchall) return 'spa_catchall_fp'
  if (t.jqError) return 'jq_assertion_bug'
  if (t.csrfRejected) return 'csrf_blocked'
  if (t.contextReset) return 'context_reset'
  if (t.tierBlocked) return 'tier_blocked'
  return 'replay_spec_miss'
}

export function buildFailureTaxonomy(traces: readonly TargetTrace[]): FailureTaxonomy {
  const taxonomy = emptyFailureTaxonomy()
  for (const t of traces) {
    if (t.isDecoy) continue
    const bucket = attributeFailureBucket(t)
    if (bucket) taxonomy[bucket] += 1
  }
  return taxonomy
}

export interface FalsePositiveBreakdown {
  decoyFalsePositives: number
  unmatchedConfirmed: number
  total: number
}

function extraUnmatchedCount(unmatchedConfirmed?: readonly unknown[] | number): number {
  if (typeof unmatchedConfirmed === 'number') {
    return Number.isFinite(unmatchedConfirmed) ? Math.max(0, Math.trunc(unmatchedConfirmed)) : 0
  }
  return Array.isArray(unmatchedConfirmed) ? unmatchedConfirmed.length : 0
}

/** Separate decoy FPs from off-manifest unmatched confirmed claims and sum both. */
export function countFalsePositiveBreakdown(
  traces: readonly TargetTrace[],
  unmatchedConfirmed?: readonly unknown[] | number,
): FalsePositiveBreakdown {
  const decoyFalsePositives = traces.filter(t => t.isDecoy && normalizeTrace(t).confirmed).length
  const traceUnmatched = traces.filter(t => !t.isDecoy && t.unmatchedConfirmed === true && normalizeTrace(t).confirmed).length
  const unmatched = traceUnmatched + extraUnmatchedCount(unmatchedConfirmed)
  return {
    decoyFalsePositives,
    unmatchedConfirmed: unmatched,
    total: decoyFalsePositives + unmatched,
  }
}

/**
 * Decoys that reached `confirmed` plus off-manifest `unmatchedConfirmed` claims count as false
 * positives. Pass `{ includeBreakdown: true }` to inspect decoy vs unmatched counts separately.
 */
export function countFalsePositives(traces: readonly TargetTrace[]): number
export function countFalsePositives(
  traces: readonly TargetTrace[],
  unmatchedConfirmed: readonly unknown[] | number,
): number
export function countFalsePositives(
  traces: readonly TargetTrace[],
  options: { includeBreakdown: true; unmatchedConfirmed?: readonly unknown[] | number },
): FalsePositiveBreakdown
export function countFalsePositives(
  traces: readonly TargetTrace[],
  unmatchedOrOptions?: readonly unknown[] | number | { includeBreakdown?: boolean; unmatchedConfirmed?: readonly unknown[] | number },
): number | FalsePositiveBreakdown {
  if (unmatchedOrOptions && typeof unmatchedOrOptions === 'object' && !Array.isArray(unmatchedOrOptions)) {
    const opts = unmatchedOrOptions as { includeBreakdown?: boolean; unmatchedConfirmed?: readonly unknown[] | number }
    const breakdown = countFalsePositiveBreakdown(traces, opts.unmatchedConfirmed)
    return opts.includeBreakdown ? breakdown : breakdown.total
  }
  return countFalsePositiveBreakdown(traces, unmatchedOrOptions as readonly unknown[] | number | undefined).total
}

// ---------------------------------------------------------------------------
// Orchestration: config knobs, budget maths, safety classification, scheduler
// ---------------------------------------------------------------------------

/** Default request budget in broker audit units (each HTTP exchange is counted twice: allowed + observed). Aligned with v7 M0 6,000-unit floor budget (3,000 HTTP exchanges). */
export const BENCH_MAX_REQUESTS_DEFAULT = 6000
export const BENCH_DEADLINE_MS_DEFAULT = 8 * 60_000
export const BENCH_PROBE_CONCURRENCY_DEFAULT = 4
export const BENCH_PROBE_CONCURRENCY_MAX = 8
export const BENCH_VERIFY_CONCURRENCY_DEFAULT = 2
export const BENCH_VERIFY_CONCURRENCY_MAX = 4
export const BENCH_SLOW_PROBES_MIN = 12
export const BENCH_SLOW_PROBES_MAX = 24

/** Max hypotheses of one probe class per endpoint (first in deterministic plan order wins). */
export const DEFAULT_PER_ENDPOINT_CLASS_CAPS: Readonly<Record<string, number>> = {
  path_traversal_benign: 1,
  auth_protocol_audit: 1,
  cache_poison_deception: 1,
  sqli_time_diff: 3,
  sqli_boolean: 8,
  ssti_math: 3,
  xss_context: 2,
  authz_matrix: 2,
  ssrf_canary: 2,
  xxe_canary: 2,
  mass_assignment: 1,
  workflow_invariant: 1,
  graphql_audit: 1,
}

/**
 * Max hypotheses of one probe class across a run. These bound the classes that otherwise grow
 * with surface size and are the main guard against `budget_exhausted`; the first hypotheses in
 * plan order are kept so stateful writes are never reordered.
 */
export const DEFAULT_PER_CLASS_CAPS: Readonly<Record<string, number>> = {
  path_traversal_benign: 8,
  auth_protocol_audit: 16,
  cache_poison_deception: 5,
  authz_matrix: 16,
  mass_assignment: 8,
  workflow_invariant: 3,
  graphql_audit: 1,
}

export interface BenchmarkClassCaps {
  perEndpoint: Record<string, number>
  perClass: Record<string, number>
}

export interface BenchmarkOrchestrationConfig {
  /** Broker audit units (see BENCH_MAX_REQUESTS_DEFAULT). */
  maxRequests: number
  deadlineMs: number
  probeConcurrency: number
  verifyConcurrency: number
  /** Explicit slow-probe allowance; null = adaptive from candidate count. */
  slowProbes: number | null
  classCaps: BenchmarkClassCaps
}

export interface BenchmarkOrchestrationOverrides {
  maxRequests?: number
  deadlineMs?: number
  probeConcurrency?: number
  verifyConcurrency?: number
  slowProbes?: number
  classCaps?: Partial<BenchmarkClassCaps>
}

type EnvLike = Record<string, string | undefined>

function readInt(raw: string | undefined): number | null {
  if (raw === undefined || raw.trim() === '') return null
  const n = Number(raw)
  return Number.isFinite(n) ? Math.trunc(n) : null
}

function clampInt(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Math.trunc(value)))
}

/** Parse `class=limit,class=limit` overrides; unknown/malformed entries are ignored. */
export function parseClassCapSpec(raw: string | undefined): Record<string, number> {
  const out: Record<string, number> = {}
  if (!raw) return out
  for (const part of raw.split(',')) {
    const [name, limit] = part.split('=').map(s => s.trim())
    const n = readInt(limit)
    if (!name || n === null || n < 0) continue
    out[name] = n
  }
  return out
}

/**
 * Resolve the orchestration knobs from env + explicit overrides (overrides win).
 * Invalid env values fall back to the compatibility defaults rather than aborting a run.
 */
export function resolveBenchOrchestrationConfig(
  env: EnvLike = process.env,
  overrides: BenchmarkOrchestrationOverrides = {},
): BenchmarkOrchestrationConfig {
  const maxRequests = overrides.maxRequests
    ?? readInt(env.KOVO_BENCH_MAX_REQUESTS)
    ?? BENCH_MAX_REQUESTS_DEFAULT
  const deadlineMs = overrides.deadlineMs
    ?? readInt(env.KOVO_BENCH_DEADLINE_MS)
    ?? BENCH_DEADLINE_MS_DEFAULT
  const probeConcurrency = clampInt(
    overrides.probeConcurrency ?? readInt(env.KOVO_BENCH_PROBE_CONCURRENCY) ?? BENCH_PROBE_CONCURRENCY_DEFAULT,
    1,
    BENCH_PROBE_CONCURRENCY_MAX,
  )
  const verifyConcurrency = clampInt(
    overrides.verifyConcurrency ?? readInt(env.KOVO_BENCH_VERIFY_CONCURRENCY) ?? BENCH_VERIFY_CONCURRENCY_DEFAULT,
    1,
    BENCH_VERIFY_CONCURRENCY_MAX,
  )
  const rawSlow = overrides.slowProbes ?? readInt(env.KOVO_BENCH_SLOW_PROBES)
  return {
    maxRequests: Math.max(1, maxRequests),
    deadlineMs: Math.max(1_000, deadlineMs),
    probeConcurrency,
    verifyConcurrency,
    slowProbes: rawSlow === null ? null : clampInt(rawSlow, 0, 64),
    classCaps: {
      perEndpoint: { ...DEFAULT_PER_ENDPOINT_CLASS_CAPS, ...(overrides.classCaps?.perEndpoint ?? parseClassCapSpec(env.KOVO_BENCH_CLASS_ENDPOINT_CAP)) },
      perClass: { ...DEFAULT_PER_CLASS_CAPS, ...(overrides.classCaps?.perClass ?? parseClassCapSpec(env.KOVO_BENCH_CLASS_CAP)) },
    },
  }
}

/**
 * Adaptive blind-SQLi allowance. Explicit values pass through; otherwise scale with the number of
 * candidate parameters and bound to [12, 24] so the expensive probe cannot crowd out the matrix.
 */
export function computeSlowProbeAllowance(candidateCount: number, explicit?: number | null): number {
  if (explicit !== undefined && explicit !== null) return clampInt(explicit, 0, 64)
  return Math.min(BENCH_SLOW_PROBES_MAX, Math.max(BENCH_SLOW_PROBES_MIN, Math.trunc(candidateCount)))
}

const sqlNameHint = /(^|[_-])(q|query|search|term|filter|sort|order|id|uid|name|category|ref|sku|text|body|comment|invoice|email|user|account|host|type|status|page|limit)$/i
const blindSinkHint = /(filter|query|search|where|lookup|analytics|report|metric|stat|term)/i
const sqlPathHint = /(\/api\/|\/search|lookup|query|products|items|orders|accounts?|profile|comments|xm|graphql|login|report|filter|list|\/_actions|server.?action)/i
const lowSignalLocation = new Set(['header', 'cookie', 'path'])

export interface SlowProbeCandidate {
  key: string
  path: string
  param?: string
  location?: string
  method?: string
}

/**
 * Plausibility score for a blind time-based SQLi candidate. Used only to pick which parameters
 * receive the bounded slow budget; execution stays in plan order (writes are never reordered).
 */
export function scoreSlowProbePlausibility(c: SlowProbeCandidate): number {
  let score = 0
  if (sqlPathHint.test(c.path)) score += 3
  if (blindSinkHint.test(c.path)) score += 2
  if (c.param && sqlNameHint.test(c.param)) score += 2
  if (c.param && blindSinkHint.test(c.param)) score += 2
  // Dotted paths (`filter.name`) are blind-SQLi sinks in modern JSON APIs.
  if (c.param?.includes('.')) score += 2
  if (c.path.split('/').filter(Boolean).length >= 2) score += 1
  const loc = c.location ?? ''
  if (loc === 'query' || loc === 'json' || loc === 'form' || loc === 'xml' || loc === 'graphql_var') score += 1
  if (lowSignalLocation.has(loc)) score -= 1
  if ((c.method ?? 'GET').toUpperCase() !== 'GET') score += 0
  return score
}

/**
 * Select at most `allowance` slow-probe keys, highest plausibility first with plan order as the
 * tie-break. The returned set is consumed in original plan order, so writes keep their positions.
 */
export function selectSlowProbeKeys(candidates: readonly SlowProbeCandidate[], allowance: number): Set<string> {
  if (allowance <= 0) return new Set()
  return new Set(
    candidates
      .map((c, index) => ({ c, index, score: scoreSlowProbePlausibility(c) }))
      .sort((a, b) => b.score - a.score || a.index - b.index)
      .slice(0, allowance)
      .map(entry => entry.c.key),
  )
}

export interface ClassCapDrop {
  key: string
  probeClass: string
  path: string
  reason: 'per_class_cap' | 'per_endpoint_cap'
}

export interface ClassCapResult<T> {
  kept: T[]
  dropped: ClassCapDrop[]
}

/**
 * Apply per-endpoint and per-class hypothesis caps in deterministic plan order. Kept hypotheses
 * keep their original relative order; only the tail beyond a cap is dropped.
 */
export function applyBenchmarkClassCaps<T extends { key: string; probeClass: string; endpoint: { path: string }; param?: { name: string }; location?: string; method?: string }>(
  hypotheses: readonly T[],
  caps: BenchmarkClassCaps,
): ClassCapResult<T> {
  // Choose which hypotheses survive a per-class cap by plausibility (high score first, plan order as
  // tie-break), but emit survivors in original plan order so stateful writes are never reordered.
  const allowedByClass = new Map<string, Set<number>>()
  const indicesByClass = new Map<string, number[]>()
  hypotheses.forEach((h, index) => {
    const list = indicesByClass.get(h.probeClass) ?? []
    list.push(index)
    indicesByClass.set(h.probeClass, list)
  })
  for (const [probeClass, indices] of indicesByClass) {
    const cap = caps.perClass[probeClass]
    if (cap === undefined || indices.length <= cap) continue
    const ranked = indices
      .map(index => {
        const h = hypotheses[index]
        return {
          index,
          score: scoreSlowProbePlausibility({
            key: h.key, path: h.endpoint.path,
            ...(h.param ? { param: h.param.name } : {}),
            ...(h.location ? { location: h.location } : {}),
            ...(h.method ? { method: h.method } : {}),
          }),
        }
      })
      .sort((a, b) => b.score - a.score || a.index - b.index)
      .slice(0, Math.max(0, cap))
      .map(entry => entry.index)
    allowedByClass.set(probeClass, new Set(ranked))
  }

  const kept: T[] = []
  const dropped: ClassCapDrop[] = []
  const perEndpoint = new Map<string, number>()
  hypotheses.forEach((h, index) => {
    const allowed = allowedByClass.get(h.probeClass)
    if (allowed && !allowed.has(index)) {
      dropped.push({ key: h.key, probeClass: h.probeClass, path: h.endpoint.path, reason: 'per_class_cap' })
      return
    }
    const endpointKey = `${h.probeClass}|${h.endpoint.path}`
    const endpointCount = perEndpoint.get(endpointKey) ?? 0
    const endpointCap = caps.perEndpoint[h.probeClass]
    if (endpointCap !== undefined && endpointCount >= endpointCap) {
      dropped.push({ key: h.key, probeClass: h.probeClass, path: h.endpoint.path, reason: 'per_endpoint_cap' })
      return
    }
    perEndpoint.set(endpointKey, endpointCount + 1)
    kept.push(h)
  })
  return { kept, dropped }
}

/** Probe classes that are read-only and independent enough to overlap with peers. */
export const PARALLEL_SAFE_PROBE_CLASSES: ReadonlySet<string> = new Set([
  'sqli_boolean',
  'sqli_time_diff',
  'ssti_math',
  'xss_context',
  'path_traversal_benign',
  'authz_matrix',
])

/**
 * Hypotheses whose replay specs are pure reads and may be verified in parallel. Auth/JWT/cache/XSS
 * specs can bind sessions, mutate a lab user's role, or touch shared state, so their replays stay
 * serial even when the probe itself was a read-only GET.
 */
export const BATCH_VERIFY_PROBE_CLASSES: ReadonlySet<string> = new Set([
  'sqli_boolean',
  'sqli_time_diff',
  'ssti_math',
  'path_traversal_benign',
])

export interface ConcurrencySafety {
  parallelSafe: boolean
  /** Why the hypothesis is serialized (empty when parallel-safe). */
  reason: string
}

/**
 * Decide whether one hypothesis may run concurrently with peers.
 *
 * Serialized by rule (documented in `docs/benchmark-orchestration.md`):
 * - any non-GET method (state mutation), second-order plant/read chains;
 * - browser-eligible XSS (one persisted browser session);
 * - canary-callback classes (ssrf/xxe) and cache poisoning (shared cache state);
 * - protocol/write classes (graphql_audit, mass_assignment, workflow_invariant);
 * - CSRF-bound probes (they share a mutating session jar).
 */
export function classifyHypothesisConcurrency(h: {
  probeClass: string
  method: string
  secondOrder?: boolean
  browserEligible?: boolean
  urlDomSink?: boolean
  location?: string
  csrfBound?: boolean
}): ConcurrencySafety {
  if (h.secondOrder) return { parallelSafe: false, reason: 'second_order_write' }
  if (h.browserEligible || h.urlDomSink) return { parallelSafe: false, reason: 'shared_browser' }
  if (h.csrfBound) return { parallelSafe: false, reason: 'csrf_session_jar' }
  if (h.method.toUpperCase() !== 'GET') return { parallelSafe: false, reason: 'stateful_write' }
  if (h.probeClass === 'cache_poison_deception') return { parallelSafe: false, reason: 'shared_cache_state' }
  if (h.probeClass === 'ssrf_canary' || h.probeClass === 'xxe_canary') return { parallelSafe: false, reason: 'canary_callback' }
  if (!PARALLEL_SAFE_PROBE_CLASSES.has(h.probeClass)) return { parallelSafe: false, reason: `class:${h.probeClass}` }
  return { parallelSafe: true, reason: '' }
}

export interface BenchmarkScheduledTask<T> {
  key: string
  /** May overlap with neighbouring parallel-safe tasks. */
  parallelSafe: boolean
  /** Keys that must have completed before this task is allowed to start. */
  dependsOn?: readonly string[]
  run: () => Promise<T>
}

export interface BenchmarkScheduleOptions {
  /** Max concurrently-running parallel-safe tasks (1 = fully serial). */
  concurrency: number
  /** Called as each task starts; lets the caller account for budget deterministically. */
  onStart?: (task: BenchmarkScheduledTask<unknown>) => void
}

/**
 * Deterministic bounded scheduler.
 *
 * - Parallel-safe tasks fill up to `concurrency` slots and may overlap.
 * - A serial task (or one with unmet dependencies) drains every in-flight task first, then runs
 *   alone, so stateful writes never interleave with reads and their order is unchanged.
 * - Results are returned in task order, regardless of completion order, so report ordering is
 *   stable across runs.
 */
export async function runBenchmarkSchedule<T>(
  tasks: readonly BenchmarkScheduledTask<T>[],
  opts: BenchmarkScheduleOptions,
): Promise<T[]> {
  const results = new Array<T>(tasks.length)
  const concurrency = Math.max(1, Math.trunc(opts.concurrency))
  const completed = new Set<string>()
  const inflight = new Set<Promise<void>>()
  const failure: { current: { index: number; error: unknown } | null } = { current: null }
  const drain = async (): Promise<void> => {
    while (inflight.size > 0) {
      await Promise.all([...inflight])
    }
  }
  for (let index = 0; index < tasks.length; index += 1) {
    const task = tasks[index]
    const depsMet = (task.dependsOn ?? []).every(key => completed.has(key))
    if (!task.parallelSafe || concurrency === 1 || !depsMet) {
      await drain()
      opts.onStart?.(task)
      results[index] = await task.run()
      completed.add(task.key)
      continue
    }
    opts.onStart?.(task)
    const promise: Promise<void> = Promise.resolve()
      .then(() => task.run())
      .then(value => { results[index] = value }, error => { failure.current ??= { index, error } })
      .finally(() => { completed.add(task.key); inflight.delete(promise) })
    inflight.add(promise)
    if (inflight.size >= concurrency) await Promise.all([[...inflight][0]])
  }
  await drain()
  if (failure.current) throw failure.current.error
  return results
}

/** Deterministic batch sizes for candidate-spec verification (confirm-on-first preserved). */
export function verificationBatches<T>(items: readonly T[], size: number): T[][] {
  const batch = Math.max(1, Math.trunc(size))
  const out: T[][] = []
  for (let i = 0; i < items.length; i += batch) out.push(items.slice(i, i + batch))
  return out
}

// ---------------------------------------------------------------------------
// Metrics + diff
// ---------------------------------------------------------------------------

export interface BenchmarkMetricsInput {
  targetsTotal: number
  confirmedCount: number
  falsePositiveCount: number
  funnelCounts?: Partial<BenchmarkFunnel> | Record<string, number> | null
  failureTaxonomy?: Partial<Record<string, number>> | null
  totalCostUsd?: number
  gitSha?: string
}

export function safeDivide(numerator: number, denominator: number): number {
  return denominator > 0 && Number.isFinite(numerator / denominator) ? numerator / denominator : 0
}

/** Recall = confirmed / targets. Zero targets yields 0, never NaN. */
export function computeRecall(confirmedCount: number, targetsTotal: number): number {
  return safeDivide(confirmedCount, targetsTotal)
}

/** Precision = confirmed / (confirmed + false positives); undefined (null) when nothing was reported. */
export function computePrecision(confirmedCount: number, falsePositiveCount: number): number | null {
  const reported = confirmedCount + falsePositiveCount
  return reported > 0 ? confirmedCount / reported : null
}

/** Cost per confirmed vuln; null when nothing was confirmed. */
export function computeCostPerVuln(totalCostUsd: number, confirmedCount: number): number | null {
  return confirmedCount > 0 ? (totalCostUsd || 0) / confirmedCount : null
}

export interface BucketDrop {
  bucket: FailureTaxonomyBucket
  before: number
  after: number
  /** Positive = the bucket shrank versus the baseline. */
  drop: number
}

export interface BenchmarkDiff {
  baselineGitSha: string | null
  currentGitSha: string | null
  recall: number
  precision: number | null
  baselineRecall: number | null
  baselinePrecision: number | null
  recallDelta: number | null
  precisionDelta: number | null
  confirmedDelta: number | null
  fpDelta: number | null
  costPerVuln: number | null
  baselineCostPerVuln: number | null
  costPerVulnDelta: number | null
  funnelDeltas: Record<keyof BenchmarkFunnel, number | null>
  bucketDeltas: FailureTaxonomy
  topBucketDrops: BucketDrop[]
  hasBaseline: boolean
}

function readBucketCounts(raw: BenchmarkMetricsInput['failureTaxonomy']): FailureTaxonomy {
  const out = emptyFailureTaxonomy()
  for (const bucket of failureTaxonomyBuckets) {
    const v = raw?.[bucket]
    out[bucket] = typeof v === 'number' && Number.isFinite(v) ? v : 0
  }
  return out
}

function readFunnel(raw: BenchmarkMetricsInput['funnelCounts']): BenchmarkFunnel {
  const f = emptyFunnel()
  const src = (raw ?? {}) as Record<string, unknown>
  for (const key of Object.keys(f) as Array<keyof BenchmarkFunnel>) {
    const v = src[key]
    f[key] = typeof v === 'number' && Number.isFinite(v) ? v : 0
  }
  return f
}

export function computeBenchmarkDiff(
  current: BenchmarkMetricsInput,
  baseline: BenchmarkMetricsInput | null | undefined,
): BenchmarkDiff {
  const recall = computeRecall(current.confirmedCount, current.targetsTotal)
  const precision = computePrecision(current.confirmedCount, current.falsePositiveCount)
  const costPerVuln = computeCostPerVuln(current.totalCostUsd ?? 0, current.confirmedCount)
  const curFunnel = readFunnel(current.funnelCounts)
  const curBuckets = readBucketCounts(current.failureTaxonomy)

  const bucketDeltas = emptyFailureTaxonomy()
  const funnelDeltas = {} as Record<keyof BenchmarkFunnel, number | null>
  for (const key of Object.keys(curFunnel) as Array<keyof BenchmarkFunnel>) funnelDeltas[key] = null

  if (!baseline) {
    return {
      baselineGitSha: null,
      currentGitSha: current.gitSha ?? null,
      recall,
      precision,
      baselineRecall: null,
      baselinePrecision: null,
      recallDelta: null,
      precisionDelta: null,
      confirmedDelta: null,
      fpDelta: null,
      costPerVuln,
      baselineCostPerVuln: null,
      costPerVulnDelta: null,
      funnelDeltas,
      bucketDeltas,
      topBucketDrops: [],
      hasBaseline: false,
    }
  }

  const baseRecall = computeRecall(baseline.confirmedCount, baseline.targetsTotal)
  const basePrecision = computePrecision(baseline.confirmedCount, baseline.falsePositiveCount)
  const baseCost = computeCostPerVuln(baseline.totalCostUsd ?? 0, baseline.confirmedCount)
  const baseFunnel = readFunnel(baseline.funnelCounts)
  const baseBuckets = readBucketCounts(baseline.failureTaxonomy)

  for (const key of Object.keys(curFunnel) as Array<keyof BenchmarkFunnel>) {
    funnelDeltas[key] = curFunnel[key] - baseFunnel[key]
  }
  const drops: BucketDrop[] = []
  for (const bucket of failureTaxonomyBuckets) {
    bucketDeltas[bucket] = curBuckets[bucket] - baseBuckets[bucket]
    drops.push({ bucket, before: baseBuckets[bucket], after: curBuckets[bucket], drop: baseBuckets[bucket] - curBuckets[bucket] })
  }
  const topBucketDrops = drops
    .filter(d => d.drop > 0)
    .sort((a, b) => b.drop - a.drop || a.bucket.localeCompare(b.bucket))
    .slice(0, 5)

  return {
    baselineGitSha: baseline.gitSha ?? null,
    currentGitSha: current.gitSha ?? null,
    recall,
    precision,
    baselineRecall: baseRecall,
    baselinePrecision: basePrecision,
    recallDelta: recall - baseRecall,
    precisionDelta: precision !== null && basePrecision !== null ? precision - basePrecision : null,
    confirmedDelta: current.confirmedCount - baseline.confirmedCount,
    fpDelta: current.falsePositiveCount - baseline.falsePositiveCount,
    costPerVuln,
    baselineCostPerVuln: baseCost,
    costPerVulnDelta: costPerVuln !== null && baseCost !== null ? costPerVuln - baseCost : null,
    funnelDeltas,
    bucketDeltas,
    topBucketDrops,
    hasBaseline: true,
  }
}

// ---------------------------------------------------------------------------
// Result shape + Markdown report
// ---------------------------------------------------------------------------

export interface PerTargetOutcome {
  id: string
  vulnClass: string
  isDecoy: boolean
  outcome: 'confirmed' | FailureTaxonomyBucket | 'decoy_clean' | 'decoy_false_positive'
  probeClass?: string | null
}

/**
 * One isolated patch retest. `id`/`before`/`after`/`fixed` are the stable, report-facing fields;
 * the rest carry the evidence needed to audit a `fixed` claim without re-running anything.
 */
export interface PatchVerificationEntry {
  /** Challenge (vuln) id; kept as the compact identifier used by reports. */
  id: string
  /** Verdict observed before the patch (usually `confirmed`, or `not_confirmed`). */
  before: string
  /** Verdict observed after applying only this patch. */
  after: string
  fixed: boolean
  patchId?: string
  vulnId?: string
  reproducedBefore?: boolean
  fixedAfter?: boolean
  /** Every verdict observed for this target on the patched server, in attempt order. */
  verdicts?: string[]
  /** Unrelated baseline findings replayed on the same patched server. */
  isolationChecked?: number
  isolationPreserved?: number
  isolationLost?: string[]
  notes?: string[]
}

/** Outcome of the single "all patches applied" pass. */
export interface AllPatchesVerification {
  /** Patch ids applied for this pass (deterministically sorted). */
  patchIds: string[]
  /** True when the pass actually ran to completion. */
  attempted: boolean
  /** Baseline-confirmed vulns that still confirmed with every patch applied. */
  stillConfirming: string[]
  /** Vulns confirmed in the all-patches pass that were not confirmed at baseline. */
  newlyConfirming: string[]
  /** Baseline vulns whose only evidence was a spec shared with another target (not patch evidence). */
  ambiguous?: string[]
  /** Baseline-attributed specs replayed against the all-patched server. */
  replayed?: number
  /** Replayed baseline specs that no longer confirmed (dismissed/inconclusive, no transport error). */
  dismissed?: number
  decoyFalsePositivesBefore: number
  decoyFalsePositivesAfter: number
  verdict: 'fixed' | 'regressed' | 'inconclusive'
  notes: string[]
}

export interface PatchVerificationSummary {
  attempted: number
  fixed: number
  reproducedBefore: number
  perPatch: PatchVerificationEntry[]
  skippedReason?: string
  allPatches?: AllPatchesVerification
  decoyFalsePositivesBefore?: number
  decoyFalsePositivesAfter?: number
  durationMs?: number
}

export interface BenchmarkSuiteResult {
  suite: BenchmarkSuiteName | 'all'
  profileMode: BenchmarkProfileMode
  dryRun: boolean
  /** True when the funnel came from the capability model (dry run) instead of live engines. */
  simulated: boolean
  gitSha: string
  baselineSha: string | null
  targetsTotal: number
  decoysTotal: number
  confirmedCount: number
  falsePositiveCount: number
  unmatchedConfirmedCount?: number
  funnelCounts: BenchmarkFunnel
  failureTaxonomy: FailureTaxonomy
  recall: number
  precision: number | null
  totalCostUsd: number
  costPerVuln: number | null
  durationMs: number
  verifierBackend: string | null
  runId: string | null
  perTarget: PerTargetOutcome[]
  diff: BenchmarkDiff | null
  recallDelta: number | null
  precisionDelta: number | null
  confirmedDelta: number | null
  fpDelta: number | null
  costPerVulnDelta: number | null
  bucketDeltas: FailureTaxonomy
  topBucketDrops: BucketDrop[]
  patchVerification?: PatchVerificationSummary | null
  children?: BenchmarkSuiteResult[]
  notes: string[]
}

const pct = (v: number | null): string => (v === null ? 'n/a' : `${(v * 100).toFixed(1)}%`)
const signed = (v: number | null, digits = 0): string =>
  v === null ? 'n/a' : `${v > 0 ? '+' : ''}${digits ? v.toFixed(digits) : String(v)}`
const signedPct = (v: number | null): string => (v === null ? 'n/a' : `${v > 0 ? '+' : ''}${(v * 100).toFixed(1)} pp`)
const usd = (v: number | null): string => (v === null ? 'n/a' : `$${v.toFixed(4)}`)

export function formatBenchmarkMarkdown(result: BenchmarkSuiteResult): string {
  if (result.children?.length && result.suite === 'all') {
    return [
      `# Kovo v4 Recall Benchmark: all suites`,
      '',
      `- Git SHA: \`${result.gitSha}\``,
      `- Baseline SHA: \`${result.baselineSha ?? 'none'}\``,
      '',
      ...result.children.map(child => formatBenchmarkMarkdown(child)),
    ].join('\n')
  }
  const diff = result.diff
  const lines: string[] = []
  lines.push(`# Kovo v4 Recall Benchmark: ${result.suite}`)
  lines.push('')
  lines.push(`- Git SHA: \`${result.gitSha}\``)
  lines.push(`- Baseline SHA: \`${result.baselineSha ?? 'none'}\`${diff && !diff.hasBaseline ? ' (no matching baseline run found)' : ''}`)
  lines.push(`- Profile: \`${result.profileMode}\``)
  lines.push(`- Mode: ${result.dryRun ? '**dry run** (capability model, no live engines)' : 'live engines'}${result.simulated ? ' - simulated figures' : ''}`)
  if (result.verifierBackend) lines.push(`- Verifier backend: \`${result.verifierBackend}\``)
  lines.push(`- Duration: ${result.durationMs} ms`)
  lines.push('')
  lines.push('## Recall / Precision / Delta')
  lines.push('')
  lines.push('| Metric | Current | Baseline | Delta |')
  lines.push('| --- | ---: | ---: | ---: |')
  lines.push(`| Recall | ${pct(result.recall)} | ${pct(diff?.baselineRecall ?? null)} | ${signedPct(diff?.recallDelta ?? null)} |`)
  lines.push(`| Precision | ${pct(result.precision)} | ${pct(diff?.baselinePrecision ?? null)} | ${signedPct(diff?.precisionDelta ?? null)} |`)
  lines.push(`| Confirmed | ${result.confirmedCount}/${result.targetsTotal} | n/a | ${signed(diff?.confirmedDelta ?? null)} |`)
  lines.push(`| False positives (decoys: ${result.decoysTotal}${result.unmatchedConfirmedCount !== undefined ? `, unmatchedConfirmed: ${result.unmatchedConfirmedCount}` : ''}) | ${result.falsePositiveCount} | n/a | ${signed(diff?.fpDelta ?? null)} |`)
  lines.push(`| Cost per vuln | ${usd(result.costPerVuln)} | ${usd(diff?.baselineCostPerVuln ?? null)} | ${signed(diff?.costPerVulnDelta ?? null, 4)} |`)
  lines.push('')
  lines.push('## Funnel')
  lines.push('')
  lines.push('| Stage | Count | Delta vs baseline |')
  lines.push('| --- | ---: | ---: |')
  for (const key of Object.keys(result.funnelCounts) as Array<keyof BenchmarkFunnel>) {
    lines.push(`| ${key} | ${result.funnelCounts[key]} | ${signed(diff?.funnelDeltas[key] ?? null)} |`)
  }
  lines.push('')
  lines.push('## Failure taxonomy')
  lines.push('')
  lines.push('| Bucket | Count | Delta vs baseline |')
  lines.push('| --- | ---: | ---: |')
  for (const bucket of failureTaxonomyBuckets) {
    lines.push(`| ${bucket} | ${result.failureTaxonomy[bucket]} | ${signed(diff?.hasBaseline ? diff.bucketDeltas[bucket] : null)} |`)
  }
  lines.push('')
  lines.push('## Top bucket drops')
  lines.push('')
  if (diff?.topBucketDrops.length) {
    lines.push('| Bucket | Before | After | Drop |')
    lines.push('| --- | ---: | ---: | ---: |')
    for (const d of diff.topBucketDrops) lines.push(`| ${d.bucket} | ${d.before} | ${d.after} | ${d.drop} |`)
  } else {
    lines.push(diff?.hasBaseline ? 'No failure bucket shrank versus the baseline.' : 'No baseline run available, so no bucket drops can be computed.')
  }
  if (result.patchVerification) {
    lines.push('')
    lines.push('## Patch verification (reproduced -> fixed)')
    lines.push('')
    const pv = result.patchVerification
    lines.push(`- Patches attempted: ${pv.attempted}; reproduced before patch: ${pv.reproducedBefore}; fixed after patch: ${pv.fixed}`)
    if (pv.decoyFalsePositivesBefore !== undefined) {
      lines.push(`- Decoy false positives: ${pv.decoyFalsePositivesBefore} before${pv.decoyFalsePositivesAfter === undefined ? '' : `, ${pv.decoyFalsePositivesAfter} after all patches`}`)
    }
    if (pv.skippedReason) lines.push(`- Note: ${pv.skippedReason}`)
    if (pv.perPatch.length) {
      lines.push('')
      lines.push('| Patch | Vuln | Before | After | Fixed | Isolation |')
      lines.push('| --- | --- | --- | --- | --- | --- |')
      for (const p of pv.perPatch) {
        const isolation = !p.reproducedBefore
          ? 'n/a'
          : p.isolationChecked === undefined || p.isolationChecked === 0
            ? 'n/a (no unrelated findings)'
            : `${p.isolationPreserved ?? 0}/${p.isolationChecked} preserved${p.isolationLost?.length ? ` (lost: ${p.isolationLost.join(', ')})` : ''}`
        lines.push(`| ${p.patchId ?? p.id} | ${p.vulnId ?? p.id} | ${p.before} | ${p.after} | ${p.fixed ? 'yes' : 'no'} | ${isolation} |`)
      }
    }
    if (pv.allPatches) {
      const a = pv.allPatches
      lines.push('')
      lines.push(`- All patches applied: **${a.verdict}**${a.attempted ? '' : ' (not run)'}`)
      if (a.replayed !== undefined) lines.push(`  - Baseline specs replayed: ${a.replayed}; dismissed: ${a.dismissed ?? 0}`)
      if (a.stillConfirming.length) lines.push(`  - Still confirming: ${a.stillConfirming.join(', ')}`)
      if (a.newlyConfirming.length) lines.push(`  - Newly confirming: ${a.newlyConfirming.join(', ')}`)
      lines.push(`  - Decoy false positives before/after: ${a.decoyFalsePositivesBefore}/${a.decoyFalsePositivesAfter}`)
      for (const n of a.notes) lines.push(`  - ${n}`)
    }
  }
  if (result.perTarget.length) {
    lines.push('')
    lines.push('## Per-target outcomes')
    lines.push('')
    lines.push('| Target | Class | Outcome | Probe |')
    lines.push('| --- | --- | --- | --- |')
    for (const t of result.perTarget) lines.push(`| ${t.id} | ${t.vulnClass} | ${t.outcome} | ${t.probeClass ?? ''} |`)
  }
  if (result.notes.length) {
    lines.push('')
    lines.push('## Notes')
    lines.push('')
    for (const n of result.notes) lines.push(`- ${n}`)
  }
  lines.push('')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Dry-run capability model
// ---------------------------------------------------------------------------

const v4OnlyFeatures = new Set([
  'cache_differential', 'sqli_time_diff', 'xxe_canary', 'second_order_canary', 'graphql_fuzzer',
  'xss_context', 'auth_protocol_audit', 'mass_assignment',
])
const v3EncodingSet = new Set(['query', 'json'])

/**
 * Deterministic capability model used ONLY by `--dry-run`. It maps manifest requirements to the
 * funnel stage that a given profile would reach, without touching the network. Live runs never
 * call this: they derive every flag from real engine telemetry.
 */
export function simulateTraceFromManifest(c: ManifestChallenge, profile: BenchmarkProfileMode): TargetTrace {
  const base: TargetTrace = {
    id: c.id,
    isDecoy: Boolean(c.isDecoy),
    vulnClass: c.vulnClass,
    surfaceDiscovered: true,
    hypothesisFormed: true,
    signalObserved: true,
    specSubmitted: true,
    confirmed: true,
    probeClass: null,
    notes: ['simulated'],
  }
  if (c.isDecoy) return { ...base, signalObserved: false, specSubmitted: false, confirmed: false }
  if (profile === 'v4-full') return base

  const encoding = c.encoding ?? 'query'
  const feature = c.requiresV4Feature ?? ''
  const segments = c.endpoint.split('/').filter(Boolean)
  if (segments.length > 2 || /[{:]/.test(c.endpoint)) return { ...base, surfaceDiscovered: false, hypothesisFormed: false, signalObserved: false, specSubmitted: false, confirmed: false }
  if (!v3EncodingSet.has(encoding)) return { ...base, hypothesisFormed: false, signalObserved: false, specSubmitted: false, confirmed: false, encodingUnsupported: true }
  if (v4OnlyFeatures.has(feature)) return { ...base, hypothesisFormed: false, signalObserved: false, specSubmitted: false, confirmed: false }
  if (c.requiresCsrf) return { ...base, signalObserved: false, specSubmitted: false, confirmed: false, csrfRejected: true }
  if (c.requiresBrowser || feature === 'persistent_browser' || feature === 'session_jar') {
    return { ...base, signalObserved: false, specSubmitted: false, confirmed: false, contextReset: true }
  }
  if ((c.tierRequired ?? 1) >= 3) return { ...base, signalObserved: false, specSubmitted: false, confirmed: false, tierBlocked: true }
  if (feature === 'jwt_auth_mutation') return { ...base, specSubmitted: false, confirmed: false }
  if (feature === 'inline_verify') return { ...base, confirmed: false, jqError: true }
  return base
}

export function perTargetOutcomes(traces: readonly TargetTrace[]): PerTargetOutcome[] {
  return traces.map(raw => {
    const t = normalizeTrace(raw)
    if (t.isDecoy) {
      return { id: t.id, vulnClass: t.vulnClass ?? 'decoy', isDecoy: true, outcome: t.confirmed ? 'decoy_false_positive' : 'decoy_clean', probeClass: t.probeClass ?? null }
    }
    return { id: t.id, vulnClass: t.vulnClass ?? 'unknown', isDecoy: false, outcome: attributeFailureBucket(t) ?? 'confirmed', probeClass: t.probeClass ?? null }
  })
}
