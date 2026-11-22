/**
 * Guardian v4 recall benchmark core: pure, dependency-light helpers shared by the
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

/** Decoys that reached `confirmed` count as false positives. */
export function countFalsePositives(traces: readonly TargetTrace[]): number {
  return traces.filter(t => t.isDecoy && normalizeTrace(t).confirmed).length
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

export interface PatchVerificationSummary {
  attempted: number
  fixed: number
  reproducedBefore: number
  perPatch: Array<{ id: string; before: string; after: string; fixed: boolean }>
  skippedReason?: string
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
      `# Guardian v4 Recall Benchmark: all suites`,
      '',
      `- Git SHA: \`${result.gitSha}\``,
      `- Baseline SHA: \`${result.baselineSha ?? 'none'}\``,
      '',
      ...result.children.map(child => formatBenchmarkMarkdown(child)),
    ].join('\n')
  }
  const diff = result.diff
  const lines: string[] = []
  lines.push(`# Guardian v4 Recall Benchmark: ${result.suite}`)
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
  lines.push(`| False positives (decoys: ${result.decoysTotal}) | ${result.falsePositiveCount} | n/a | ${signed(diff?.fpDelta ?? null)} |`)
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
    if (pv.skippedReason) lines.push(`- Note: ${pv.skippedReason}`)
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
