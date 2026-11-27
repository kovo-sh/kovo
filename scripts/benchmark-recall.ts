#!/usr/bin/env node
/**
 * Kovo v4 recall benchmark harness (`npm run benchmark:recall`).
 *
 * Runs the stratified XBEN-25 dev suite and/or the Held-Out Modern SaaS Lab against Kovo's
 * own engines, records the 6-stage funnel plus the 11-bucket failure taxonomy in SQLite
 * (`benchmark_runs`), and emits JSON + Markdown diff reports against a baseline run.
 *
 * `--dry-run` never touches the network: it uses a deterministic capability model so the
 * reporting and persistence plumbing can be exercised anywhere. Live runs (the default) are
 * gated behind KOVO_ALLOW_LOCAL_LAB=1 and drive the real engines in `benchmark-live.ts`.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { Store, dataDirectory } from '../src/server/store.ts'
import {
  assertMonotonicFunnel,
  buildFailureTaxonomy,
  buildFunnel,
  computeBenchmarkDiff,
  computeCostPerVuln,
  computePrecision,
  computeRecall,
  countFalsePositives,
  emptyFailureTaxonomy,
  formatBenchmarkMarkdown,
  normalizeTrace,
  perTargetOutcomes,
  simulateTraceFromManifest,
} from './benchmark-core.ts'
import {
  DEFAULT_LEDGER_PATH,
  appendLedgerRow,
  appendPerRunLedgerRow,
  computeBenchmarkVersion,
  computeEffectiveConfig,
  promoteLedgerRows,
  resolveGitState,
} from './bench-ledger.ts'
import { ScorecardReader, buildLedgerRow, ratioOrNull } from './score-primitives.ts'
import type {
  BenchmarkManifest,
  BenchmarkOrchestrationOverrides,
  BenchmarkProfileMode,
  BenchmarkSuiteName,
  BenchmarkSuiteResult,
  PatchVerificationSummary,
  TargetTrace,
} from './benchmark-core.ts'

export {
  attributeFailureBucket,
  buildFailureTaxonomy,
  buildFunnel,
  computeBenchmarkDiff,
  formatBenchmarkMarkdown,
  isMonotonicFunnel,
  simulateTraceFromManifest,
} from './benchmark-core.ts'
export type { BenchmarkDiff, BenchmarkProfileMode, BenchmarkSuiteName, BenchmarkSuiteResult, TargetTrace } from './benchmark-core.ts'

export type BenchmarkSuiteOption = BenchmarkSuiteName | 'saas-lab' | 'all'
export type VerifierBackendChoice = 'auto' | 'docker' | 'local-jq'

export interface BenchmarkServerHandle {
  origin: string
  port: number
  personas: Record<string, { headerName?: string; token?: string; cookie?: string; jwt?: string; role?: string; userId?: string }>
  resetState?: () => void
  close: () => Promise<void>
}
export type BenchmarkServerLauncher = (opts?: { patchedIds?: string[] }) => Promise<BenchmarkServerHandle>

export interface RunBenchmarkOptions {
  suite: BenchmarkSuiteOption
  dryRun?: boolean
  profileMode?: BenchmarkProfileMode
  storage?: Store
  /** Data directory for the benchmark SQLite DB when no `storage` is supplied. */
  dbPath?: string
  baselineSha?: string
  gitSha?: string
  outJson?: string
  outMd?: string
  outDir?: string
  verifyPatches?: boolean
  verifierBackend?: VerifierBackendChoice
  /** Test hooks: replace the on-disk manifest / server launcher for a suite. */
  manifests?: Partial<Record<BenchmarkSuiteName, BenchmarkManifest>>
  launchers?: Partial<Record<BenchmarkSuiteName, BenchmarkServerLauncher>>
  repoRootDir?: string
  /** Wall-clock/request/concurrency knobs for the live pipeline (env supplies the rest). */
  orchestration?: BenchmarkOrchestrationOverrides
  /** Optional custom directory for default per-run ledger JSONL files. */
  ledgerRunsDir?: string
  /** Optional legacy explicit ledger JSONL path. */
  ledgerPath?: string
  /** Optional target ledger path to promote validated per-run rows into. */
  promoteLedgerPath?: string
}

export const benchmarkRepoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

export const suiteManifestRelPaths: Record<BenchmarkSuiteName, string> = {
  'xben-25': 'benchmarks/xben-25/manifest.json',
  'held-out-saas': 'local-lab/held-out-saas/manifest.json',
}

export function normalizeSuiteName(raw: string): BenchmarkSuiteOption {
  const s = raw.trim().toLowerCase()
  if (s === 'saas-lab' || s === 'held-out-saas' || s === 'held-out') return s === 'saas-lab' ? 'saas-lab' : 'held-out-saas'
  if (s === 'xben-25' || s === 'xben') return 'xben-25'
  if (s === 'all') return 'all'
  throw new Error(`Unknown benchmark suite "${raw}". Use xben-25, held-out-saas (alias saas-lab) or all.`)
}

export function resolveSuites(suite: BenchmarkSuiteOption): BenchmarkSuiteName[] {
  if (suite === 'all') return ['xben-25', 'held-out-saas']
  if (suite === 'saas-lab') return ['held-out-saas']
  return [suite]
}

export function loadSuiteManifest(suite: BenchmarkSuiteName, rootDir = benchmarkRepoRoot): BenchmarkManifest {
  const path = resolve(rootDir, suiteManifestRelPaths[suite])
  if (!existsSync(path)) {
    throw new Error(`Benchmark manifest for suite "${suite}" not found at ${path}.`)
  }
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as BenchmarkManifest
  if (!parsed || !Array.isArray(parsed.challenges)) {
    throw new Error(`Benchmark manifest ${path} must contain a "challenges" array.`)
  }
  return parsed
}

export function resolveGitSha(rootDir = benchmarkRepoRoot): string {
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: rootDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || 'unknown'
  } catch {
    return 'unknown'
  }
}

function assertLocalLabGate(dryRun: boolean | undefined) {
  if (!dryRun && process.env.KOVO_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Refusing to execute local-lab benchmarks: set KOVO_ALLOW_LOCAL_LAB=1 (or use --dry-run).')
  }
}

function writeOutput(path: string, content: string) {
  mkdirSync(dirname(resolve(path)), { recursive: true })
  writeFileSync(path, content)
}

function openDefaultStore(dbPath?: string): Store {
  return new Store(resolve(dbPath ?? join(dataDirectory(), 'benchmarks')))
}

export async function verifyHeldOutPatches(args: {
  manifest: BenchmarkManifest
  profileMode?: BenchmarkProfileMode
  launcher?: BenchmarkServerLauncher
  verifierBackend?: VerifierBackendChoice
  repoRootDir?: string
}): Promise<PatchVerificationSummary> {
  const live = await import('./benchmark-live.ts')
  return await live.verifyPatchesLive(args)
}

async function runSingleSuite(suite: BenchmarkSuiteName, opts: RunBenchmarkOptions, storage: Store, gitSha: string): Promise<BenchmarkSuiteResult> {
  const rootDir = opts.repoRootDir ?? benchmarkRepoRoot
  const profileMode: BenchmarkProfileMode = opts.profileMode ?? 'v4-full'
  const manifest = opts.manifests?.[suite] ?? loadSuiteManifest(suite, rootDir)
  const started = Date.now()
  const notes: string[] = []

  let traces: TargetTrace[]
  let unmatchedConfirmed: readonly unknown[] | number = 0
  let totalCostUsd = 0
  let verifierBackend: string | null = null
  let patchVerification: PatchVerificationSummary | null = null

  if (opts.dryRun) {
    traces = manifest.challenges.map(c => simulateTraceFromManifest(c, profileMode))
    notes.push('Dry run: funnel derived from the deterministic capability model, not live engine telemetry.')
    if (opts.verifyPatches) {
      patchVerification = { attempted: 0, fixed: 0, reproducedBefore: 0, perPatch: [], skippedReason: 'Skipped in dry run.' }
    }
  } else {
    const live = await import('./benchmark-live.ts')
    const outcome = await live.runLivePipeline({
      suite,
      manifest,
      profileMode,
      launcher: opts.launchers?.[suite],
      verifierBackend: opts.verifierBackend ?? 'auto',
      repoRootDir: rootDir,
      ...(opts.orchestration ? { orchestration: opts.orchestration } : {}),
    })
    traces = outcome.traces
    unmatchedConfirmed = outcome.unmatchedConfirmed ?? 0
    totalCostUsd = outcome.totalCostUsd
    verifierBackend = outcome.verifierBackend
    notes.push(...outcome.notes)
    if (opts.verifyPatches) {
      if (suite === 'held-out-saas') {
        patchVerification = await live.verifyPatchesLive({
          manifest, profileMode, launcher: opts.launchers?.[suite], verifierBackend: opts.verifierBackend ?? 'auto', repoRootDir: rootDir,
          suite, baseline: outcome,
          ...(opts.orchestration ? { orchestration: opts.orchestration } : {}),
        })
      } else {
        patchVerification = { attempted: 0, fixed: 0, reproducedBefore: 0, perPatch: [], skippedReason: 'Patch verification applies to held-out-saas only.' }
      }
    }
  }

  const normalized = traces.map(normalizeTrace)
  const funnelCounts = buildFunnel(normalized)
  assertMonotonicFunnel(funnelCounts)
  const failureTaxonomy = buildFailureTaxonomy(normalized)
  const fpBreakdown = countFalsePositives(normalized, { includeBreakdown: true, unmatchedConfirmed })
  const falsePositiveCount = fpBreakdown.total
  const targetsTotal = funnelCounts.targetVulns
  const confirmedCount = funnelCounts.zeroLlmConfirmed
  const decoysTotal = normalized.filter(t => t.isDecoy).length
  const durationMs = Date.now() - started

  // Baseline lookup happens before the insert so a run never diffs against itself.
  const priorRows = storage.listBenchmarkRuns(suite, 500)
  const baselineRow = opts.baselineSha
    ? priorRows.find(r => r.gitSha === opts.baselineSha) ?? null
    : priorRows[0] ?? null
  if (opts.baselineSha && !baselineRow) notes.push(`No stored benchmark run found for baseline SHA "${opts.baselineSha}".`)

  const row = storage.insertBenchmarkRun({
    suite,
    gitSha,
    modelRoutingConfig: { profileMode, dryRun: Boolean(opts.dryRun), simulated: Boolean(opts.dryRun), verifierBackend },
    targetsTotal,
    confirmedCount,
    falsePositiveCount,
    funnelCounts,
    failureTaxonomy,
    totalCostUsd,
    durationMs,
  })

  const diff = computeBenchmarkDiff(
    { targetsTotal, confirmedCount, falsePositiveCount, funnelCounts, failureTaxonomy, totalCostUsd, gitSha },
    baselineRow
      ? {
        targetsTotal: baselineRow.targetsTotal,
        confirmedCount: baselineRow.confirmedCount,
        falsePositiveCount: baselineRow.falsePositiveCount,
        funnelCounts: baselineRow.funnelCounts,
        failureTaxonomy: baselineRow.failureTaxonomy,
        totalCostUsd: baselineRow.totalCostUsd,
        gitSha: baselineRow.gitSha,
      }
      : null,
  )

  const recallResult: BenchmarkSuiteResult = {
    suite,
    profileMode,
    dryRun: Boolean(opts.dryRun),
    simulated: Boolean(opts.dryRun),
    gitSha,
    baselineSha: baselineRow?.gitSha ?? opts.baselineSha ?? null,
    targetsTotal,
    decoysTotal,
    confirmedCount,
    falsePositiveCount,
    unmatchedConfirmedCount: fpBreakdown.unmatchedConfirmed,
    funnelCounts,
    failureTaxonomy,
    recall: computeRecall(confirmedCount, targetsTotal),
    precision: ratioOrNull(confirmedCount, confirmedCount + falsePositiveCount),
    totalCostUsd,
    costPerVuln: computeCostPerVuln(totalCostUsd, confirmedCount),
    durationMs,
    verifierBackend,
    runId: row.id,
    perTarget: perTargetOutcomes(normalized),
    diff,
    recallDelta: diff.recallDelta,
    precisionDelta: diff.precisionDelta,
    confirmedDelta: diff.confirmedDelta,
    fpDelta: diff.fpDelta,
    costPerVulnDelta: diff.costPerVulnDelta,
    bucketDeltas: diff.bucketDeltas,
    topBucketDrops: diff.topBucketDrops,
    patchVerification,
    notes,
  }

  // Default per-run ledger writing for live runs (gitignored benchmarks/results/runs/<run-id>.jsonl).
  if (!opts.dryRun || opts.ledgerRunsDir || opts.ledgerPath || opts.promoteLedgerPath) {
    try {
      const { benchmarkVersion } = computeBenchmarkVersion(suite, rootDir)
      const { effectiveConfigHash, effectiveConfig } = computeEffectiveConfig({
        deterministicOnly: true,
        environment: 'local-lab',
        approvalPolicy: 'auto_review',
        wordlistOn: false,
        verifierBackend: verifierBackend ?? opts.verifierBackend ?? 'auto',
        mode: profileMode,
      })
      const gitState = resolveGitState(rootDir)
      const readerCell = ScorecardReader.read({
        app: suite,
        seed: 0,
        mode: profileMode,
        llm: 'deterministic-no-llm',
        targets: targetsTotal,
        confirmed: confirmedCount,
        decoys: decoysTotal,
        decoyFalsePositives: fpBreakdown.decoyFalsePositives,
        unmatchedFalsePositives: fpBreakdown.unmatchedConfirmed,
        totalCostUsd,
        durationMs,
      })
      const siteOutcomes: Record<string, string> = {}
      for (const t of recallResult.perTarget) siteOutcomes[t.id] = t.outcome
      const ledgerRow = buildLedgerRow({
        cell: readerCell,
        suite,
        gitSha,
        dirty: gitState.dirty,
        benchmarkVersion,
        effectiveConfigHash,
        effectiveConfig,
        app: suite,
        split: suite === 'held-out-saas' ? 'held-out' : 'dev',
        mode: profileMode,
        llm: 'deterministic-no-llm',
        seed: 0,
        repeat: 1,
        certifying: false,
        reportable: !opts.dryRun,
        siteOutcomes,
      })
      const appended = appendPerRunLedgerRow(ledgerRow, {
        runId: `recall-${suite}-${row.id}`,
        runsDir: opts.ledgerRunsDir,
        repoRoot: rootDir,
      })
      if (opts.ledgerPath) appendLedgerRow(ledgerRow, opts.ledgerPath, rootDir)
      if (opts.promoteLedgerPath) {
        promoteLedgerRows(appended.path, { targetLedgerPath: opts.promoteLedgerPath, repoRoot: rootDir })
      }
    } catch {
      // Non-fatal in synthetic unit tests with mock repoRootDir missing benchmark dirs.
    }
  }

  return recallResult
}

function aggregateResults(children: BenchmarkSuiteResult[], gitSha: string, opts: RunBenchmarkOptions): BenchmarkSuiteResult {
  const funnelCounts = { targetVulns: 0, surfaceDiscovered: 0, hypothesisFormed: 0, signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0 }
  const failureTaxonomy = emptyFailureTaxonomy()
  let confirmedCount = 0
  let falsePositiveCount = 0
  let unmatchedConfirmedCount = 0
  let decoysTotal = 0
  let totalCostUsd = 0
  let durationMs = 0
  for (const c of children) {
    for (const key of Object.keys(funnelCounts) as Array<keyof typeof funnelCounts>) funnelCounts[key] += c.funnelCounts[key]
    for (const key of Object.keys(failureTaxonomy) as Array<keyof typeof failureTaxonomy>) failureTaxonomy[key] += c.failureTaxonomy[key]
    confirmedCount += c.confirmedCount
    falsePositiveCount += c.falsePositiveCount
    unmatchedConfirmedCount += c.unmatchedConfirmedCount ?? 0
    decoysTotal += c.decoysTotal
    totalCostUsd += c.totalCostUsd
    durationMs += c.durationMs
  }
  const targetsTotal = funnelCounts.targetVulns
  return {
    suite: 'all',
    profileMode: opts.profileMode ?? 'v4-full',
    dryRun: Boolean(opts.dryRun),
    simulated: Boolean(opts.dryRun),
    gitSha,
    baselineSha: opts.baselineSha ?? null,
    targetsTotal,
    decoysTotal,
    confirmedCount,
    falsePositiveCount,
    unmatchedConfirmedCount,
    funnelCounts,
    failureTaxonomy,
    recall: computeRecall(confirmedCount, targetsTotal),
    precision: computePrecision(confirmedCount, falsePositiveCount),
    totalCostUsd,
    costPerVuln: computeCostPerVuln(totalCostUsd, confirmedCount),
    durationMs,
    verifierBackend: children.find(c => c.verifierBackend)?.verifierBackend ?? null,
    runId: null,
    perTarget: children.flatMap(c => c.perTarget),
    diff: null,
    recallDelta: null,
    precisionDelta: null,
    confirmedDelta: null,
    fpDelta: null,
    costPerVulnDelta: null,
    bucketDeltas: emptyFailureTaxonomy(),
    topBucketDrops: [],
    children,
    notes: children.flatMap(c => c.notes),
  }
}

export async function runBenchmarkSuite(opts: RunBenchmarkOptions): Promise<BenchmarkSuiteResult> {
  assertLocalLabGate(opts.dryRun)
  const suites = resolveSuites(normalizeSuiteName(String(opts.suite)))
  const rootDir = opts.repoRootDir ?? benchmarkRepoRoot
  const gitSha = opts.gitSha ?? resolveGitSha(rootDir)
  const ownStore = !opts.storage
  const storage = opts.storage ?? openDefaultStore(opts.dbPath)
  try {
    const children: BenchmarkSuiteResult[] = []
    for (const suite of suites) {
      const child = await runSingleSuite(suite, opts, storage, gitSha)
      children.push(child)
      if (opts.outDir) {
        const stem = join(opts.outDir, `benchmark-${suite}-${child.profileMode}-${gitSha}`)
        writeOutput(`${stem}.json`, JSON.stringify(child, null, 2))
        writeOutput(`${stem}.md`, formatBenchmarkMarkdown(child))
      }
    }
    const result = children.length === 1 && opts.suite !== 'all' ? children[0] : aggregateResults(children, gitSha, opts)
    if (opts.outJson) writeOutput(opts.outJson, JSON.stringify(result, null, 2))
    if (opts.outMd) writeOutput(opts.outMd, formatBenchmarkMarkdown(result))
    return result
  } finally {
    if (ownStore) storage.close()
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export interface BenchmarkCliOptions extends Omit<RunBenchmarkOptions, 'storage' | 'manifests' | 'launchers'> {
  diff: boolean
  help: boolean
}

export function benchmarkCliHelp(): string {
  return [
    'Kovo v4 recall benchmark',
    '',
    'Usage: node scripts/benchmark-recall.ts [options]',
    '',
    '  --suite <xben-25|held-out-saas|saas-lab|all>  Suite to run (default: xben-25)',
    '  --profile-mode <v4-full|v3-baseline>          Capability profile (default: v4-full)',
    '  --baseline-sha <sha>                          Diff against the stored run for this git SHA',
    '  --git-sha <sha>                               SHA label for this run (default: git HEAD)',
    '  --out-json <file>  --out-md <file>            Write the JSON / Markdown report',
    '  --out-dir <dir>                               Write per-suite reports into a directory',
    '  --db <dir>                                    Data directory holding kovo.sqlite for benchmark_runs',
    '  --diff                                        Print the Markdown diff to stdout',
    '  --verify-patches                              held-out-saas: verify reproduced -> fixed patch retests',
    '                                                (20 isolated patches + one all-patches pass)',
    '  --verifier-backend <auto|docker|local-jq>     Zero-LLM verifier backend (default: auto)',
    '  --max-requests <n>                            Broker audit-unit budget (default: 6000, env KOVO_BENCH_MAX_REQUESTS)',
    '  --deadline-ms <n>                             Wall-clock budget for the live pipeline (default: 480000)',
    '  --probe-concurrency <n>                       Parallel read-only hypotheses, 1-8 (default: 4, env KOVO_BENCH_PROBE_CONCURRENCY)',
    '  --verify-concurrency <n>                      Candidate specs verified in parallel, 1-4 (default: 2)',
    '  --slow-probes <n>                             Blind time-based SQLi allowance (default: adaptive 12-24)',
    '  --dry-run                                     Capability-model run, no network',
    '  -h, --help',
    '',
    'Live runs require KOVO_ALLOW_LOCAL_LAB=1.',
    'Orchestration env: KOVO_BENCH_MAX_REQUESTS, KOVO_BENCH_DEADLINE_MS,',
    'KOVO_BENCH_PROBE_CONCURRENCY, KOVO_BENCH_VERIFY_CONCURRENCY, KOVO_BENCH_SLOW_PROBES,',
    'KOVO_BENCH_CLASS_CAP / KOVO_BENCH_CLASS_ENDPOINT_CAP (class=limit,...).',
    'Patch-verification bounds: KOVO_BENCH_PATCH_TIMEOUT_MS (per patch, default 90000),',
    'KOVO_BENCH_ALLPATCH_TIMEOUT_MS (all-patches baseline-spec replay, default 600000),',
    'KOVO_BENCH_PATCH_ISOLATION (unrelated findings replayed per patch, default 4).',
    'KOVO_BENCH_ALLPATCH_FRESH=1 adds an optional fresh all-patches discovery pass;',
    'its findings are reported as newly-confirming, never as patch evidence.',
  ].join('\n')
}

function parseCountArg(flag: string, value: string, min: number, max: number): number {
  const n = Number(value)
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${flag} must be an integer in ${min}..${max}.`)
  return n
}

export function parseBenchmarkCliArgs(argv: readonly string[]): BenchmarkCliOptions {
  const out: BenchmarkCliOptions = { suite: 'xben-25', diff: false, help: false }
  const orchestration: BenchmarkOrchestrationOverrides = {}
  const valueFlags = new Set([
    '--suite', '--profile-mode', '--baseline-sha', '--git-sha', '--out-json', '--out-md', '--out-dir', '--db', '--verifier-backend',
    '--max-requests', '--deadline-ms', '--probe-concurrency', '--verify-concurrency', '--slow-probes',
    '--ledger', '--promote-ledger',
  ])
  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i]
    let inline: string | undefined
    const eq = arg.indexOf('=')
    if (arg.startsWith('--') && eq > 0) {
      inline = arg.slice(eq + 1)
      arg = arg.slice(0, eq)
    }
    if (arg === '--') continue
    if (arg === '-h' || arg === '--help') { out.help = true; continue }
    if (arg === '--dry-run' || arg === '--diff' || arg === '--verify-patches') {
      if (inline !== undefined) throw new Error(`Option ${arg} does not take a value.`)
      if (arg === '--dry-run') out.dryRun = true
      else if (arg === '--diff') out.diff = true
      else out.verifyPatches = true
      continue
    }
    if (!valueFlags.has(arg)) throw new Error(`Unknown benchmark option: ${argv[i]}`)
    const value = inline ?? argv[++i]
    if (value === undefined || value.startsWith('--')) throw new Error(`Option ${arg} requires a value.`)
    switch (arg) {
      case '--suite': out.suite = normalizeSuiteName(value); break
      case '--profile-mode':
        if (value !== 'v3-baseline' && value !== 'v4-full') throw new Error('--profile-mode must be v3-baseline or v4-full.')
        out.profileMode = value
        break
      case '--baseline-sha': out.baselineSha = value; break
      case '--git-sha': out.gitSha = value; break
      case '--out-json': out.outJson = value; break
      case '--out-md': out.outMd = value; break
      case '--out-dir': out.outDir = value; break
      case '--db': out.dbPath = value.endsWith('.sqlite') || value.endsWith('.db') ? dirname(resolve(value)) : value; break
      case '--verifier-backend':
        if (value !== 'auto' && value !== 'docker' && value !== 'local-jq') throw new Error('--verifier-backend must be auto, docker or local-jq.')
        out.verifierBackend = value
        break
      case '--max-requests': orchestration.maxRequests = parseCountArg('--max-requests', value, 1, 1_000_000); break
      case '--deadline-ms': orchestration.deadlineMs = parseCountArg('--deadline-ms', value, 1_000, 24 * 60 * 60_000); break
      case '--probe-concurrency': orchestration.probeConcurrency = parseCountArg('--probe-concurrency', value, 1, 8); break
      case '--verify-concurrency': orchestration.verifyConcurrency = parseCountArg('--verify-concurrency', value, 1, 4); break
      case '--slow-probes': orchestration.slowProbes = parseCountArg('--slow-probes', value, 0, 64); break
      case '--ledger': out.ledgerPath = value || DEFAULT_LEDGER_PATH; break
      case '--promote-ledger': out.promoteLedgerPath = value || DEFAULT_LEDGER_PATH; break
    }
  }
  if (Object.keys(orchestration).length > 0) out.orchestration = orchestration
  return out
}

export async function runBenchmarkCli(argv: readonly string[]): Promise<number> {
  let cli: BenchmarkCliOptions
  try {
    cli = parseBenchmarkCliArgs(argv)
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n\n${benchmarkCliHelp()}\n`)
    return 1
  }
  if (cli.help) {
    process.stdout.write(`${benchmarkCliHelp()}\n`)
    return 0
  }
  try {
    const { diff, help: _help, ...opts } = cli
    const result = await runBenchmarkSuite(opts)
    if (result.verifierBackend === 'local-jq') {
      process.stderr.write('Note: Docker verifier worker unavailable; assertions were evaluated with host jq (verifierBackend=local-jq).\n')
    }
    const summary = [
      `suite=${result.suite} profile=${result.profileMode} git=${result.gitSha} baseline=${result.baselineSha ?? 'none'}`,
      `targets=${result.targetsTotal} confirmed=${result.confirmedCount} falsePositives=${result.falsePositiveCount} recall=${(result.recall * 100).toFixed(1)}%`,
      `funnel=${JSON.stringify(result.funnelCounts)}`,
    ]
    if (result.recallDelta !== null) summary.push(`recallDelta=${(result.recallDelta * 100).toFixed(1)}pp confirmedDelta=${result.confirmedDelta}`)
    if (result.patchVerification) {
      const pv = result.patchVerification
      summary.push(`patches=${pv.attempted} reproducedBefore=${pv.reproducedBefore} fixed=${pv.fixed}${pv.allPatches ? ` allPatches=${pv.allPatches.verdict}` : ''}`)
      if (pv.skippedReason) summary.push(`patchVerificationSkipped=${pv.skippedReason}`)
      const missed = pv.perPatch.filter(p => !p.fixed)
      for (const p of missed) {
        summary.push(`patchMiss ${p.patchId ?? p.id} vuln=${p.vulnId ?? p.id} before=${p.before} after=${p.after}${p.notes?.length ? ` notes=${p.notes.join(' | ')}` : ''}`)
      }
    }
    process.stdout.write(`${summary.join('\n')}\n`)
    if (diff) process.stdout.write(`\n${formatBenchmarkMarkdown(result)}\n`)
    if (opts.outJson) process.stdout.write(`wrote ${opts.outJson}\n`)
    if (opts.outMd) process.stdout.write(`wrote ${opts.outMd}\n`)
    return !result.dryRun && result.falsePositiveCount > 0 ? 2 : 0
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`)
    return 1
  }
}

function isEntrypoint(): boolean {
  const entry = process.argv[1]
  if (!entry) return false
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href || import.meta.url === pathToFileURL(entry).href
  } catch {
    return false
  }
}

if (isEntrypoint()) {
  process.exitCode = await runBenchmarkCli(process.argv.slice(2))
  // Artifacts are flushed; exit deterministically so the process never lingers as an orphan.
  setImmediate(() => process.exit(process.exitCode ?? 0))
}
