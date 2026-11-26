/**
 * Parallel runner for benchmarks/realistic-bench cells (app x seed).
 *
 * Runs each cell in its own child process so the 16-core host is used instead of
 * executing a 9-cell matrix serially. It only reads each cell's structured scorecard
 * JSON and prints aggregate metrics (no raw logs).
 *
 * Usage:
 *   KOVO_ALLOW_LOCAL_LAB=1 node scripts/benchmark-realistic-matrix.ts \
 *     --apps acme-saas,shopflow,opsportal --seeds 42,1,2 --split dev \
 *     --concurrency 9 --out-dir /tmp/rb-matrix
 *
 * Held-out runs additionally need KOVO_RB_HELDOUT_SALT (>=16 chars, never committed).
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { availableParallelism } from 'node:os'
import { resolve } from 'node:path'
import {
  CellReaper, ResourceGuard, cellLabel, envFlagDisabled,
} from './benchmark-parallel.ts'
import {
  DEFAULT_LEDGER_PATH,
  appendLedgerRow,
  appendPerRunLedgerRow,
  computeBenchmarkVersion,
  computeEffectiveConfig,
  promoteLedgerRows,
  resolveGitState,
  type BenchmarkSuiteName,
  type EffectiveConfigSnapshot,
  type LedgerRow,
} from './bench-ledger.ts'
import {
  ScorecardReader,
  buildLedgerRow,
  ratioOrNull,
  type CellReadState,
} from './score-primitives.ts'

interface Cell { app: string; seed: number }
export interface CellResult {
  app: string
  seed: number
  ok: boolean
  exitCode: number | null
  runtimeMs: number
  confirmed: number
  targets: number
  recall: number | null
  precision: number | null
  rawPrecision?: number | null
  strictPrecision?: number | null
  cellState?: CellReadState
  decoyFp: number
  decoys: number
  unmatchedFp: number
  misclassifiedCount?: number
  costUsd: number
  funnel?: Record<string, number>
  error?: string
}

export interface RealisticMatrixTotals {
  status: 'VALID' | 'INVALID'
  cells: number
  ok: number
  failed: number
  confirmed: number
  targets: number
  recall: number | null
  precision: number | null
  decoyFp: number
  decoys: number
  unmatchedFp: number
  costUsd: number
}

type MatrixSuite = 'realistic' | 'xben-25' | 'held-out-saas'

const KNOWN_APPS = ['acme-saas', 'shopflow', 'opsportal'] as const
const KNOWN_SUITES: MatrixSuite[] = ['realistic', 'xben-25', 'held-out-saas']
const DEFAULT_MIN_FREE_MEM_GB = 6
const DEFAULT_MAX_ACTIVE_WORKERS = 16

function parseArgs(argv: readonly string[]): {
  suite: MatrixSuite; apps: string[]; seeds: number[]; split: 'dev' | 'heldout'; concurrency: number
  outDir: string; timeoutMs: number; mode: string; profileMode: string
  maxRequests?: number; probeConcurrency?: number; verifyConcurrency?: number; slowProbes?: number
  minFreeMemGb: number; maxActiveWorkers: number; warmWorkers: boolean
  ledgerPath?: string; promoteLedgerPath?: string
} {
  const out = {
    suite: 'realistic' as MatrixSuite,
    apps: [...KNOWN_APPS] as string[], seeds: [42, 1, 2], split: 'dev' as 'dev' | 'heldout',
    concurrency: Math.min(9, Math.max(1, availableParallelism() - 1)),
    outDir: '/tmp/rb-matrix', timeoutMs: 600_000, mode: 'grey-box', profileMode: 'v4-full',
    maxRequests: undefined as number | undefined,
    probeConcurrency: undefined as number | undefined,
    verifyConcurrency: undefined as number | undefined,
    slowProbes: undefined as number | undefined,
    minFreeMemGb: Number(process.env.KOVO_MATRIX_MIN_FREE_GB) > 0
      ? Number(process.env.KOVO_MATRIX_MIN_FREE_GB) : DEFAULT_MIN_FREE_MEM_GB,
    maxActiveWorkers: Number(process.env.KOVO_MATRIX_MAX_WORKERS) >= 1
      ? Math.floor(Number(process.env.KOVO_MATRIX_MAX_WORKERS)) : DEFAULT_MAX_ACTIVE_WORKERS,
    warmWorkers: !envFlagDisabled(process.env, 'KOVO_WARM_WORKERS'),
    ledgerPath: undefined as string | undefined,
    promoteLedgerPath: undefined as string | undefined,
  }
  const int = (arg: string, value: string, min: number, max: number): number => {
    const n = Number(value)
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${arg} must be an integer in ${min}..${max}`)
    return n
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    const value = argv[i + 1]
    const take = () => { if (value === undefined) throw new Error(`${arg} requires a value`); i += 1; return value }
    switch (arg) {
      case '--suite': {
        const v = take() as MatrixSuite
        if (!KNOWN_SUITES.includes(v)) throw new Error('--suite must be realistic, xben-25 or held-out-saas')
        out.suite = v
        break
      }
      case '--apps': out.apps = take().split(',').map(s => s.trim()).filter(Boolean); break
      case '--seeds': out.seeds = take().split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n)); break
      case '--split': {
        const v = take()
        if (v !== 'dev' && v !== 'heldout') throw new Error('--split must be dev or heldout')
        out.split = v
        break
      }
      case '--concurrency': out.concurrency = Math.max(1, Number(take())); break
      case '--out-dir': out.outDir = take(); break
      case '--timeout-ms': out.timeoutMs = Math.max(1000, Number(take())); break
      case '--mode': out.mode = take(); break
      case '--profile-mode': out.profileMode = take(); break
      case '--max-requests': out.maxRequests = int(arg, take(), 1, 1_000_000); break
      case '--probe-concurrency': out.probeConcurrency = int(arg, take(), 1, 8); break
      case '--verify-concurrency': out.verifyConcurrency = int(arg, take(), 1, 4); break
      case '--slow-probes': out.slowProbes = int(arg, take(), 0, 64); break
      case '--min-free-gb': out.minFreeMemGb = int(arg, take(), 0, 1024); break
      case '--max-workers': out.maxActiveWorkers = int(arg, take(), 1, 256); break
      case '--no-warm-workers': out.warmWorkers = false; break
      case '--ledger': {
        if (value !== undefined && !value.startsWith('--')) {
          out.ledgerPath = take()
        } else {
          out.ledgerPath = DEFAULT_LEDGER_PATH
        }
        break
      }
      case '--promote-ledger': {
        if (value !== undefined && !value.startsWith('--')) {
          out.promoteLedgerPath = take()
        } else {
          out.promoteLedgerPath = DEFAULT_LEDGER_PATH
        }
        break
      }
      case '--help': case '-h':
        console.log('Usage: node scripts/benchmark-realistic-matrix.ts [--suite realistic|xben-25|held-out-saas] [--apps a,b] [--seeds 1,2] [--split dev|heldout] [--concurrency N] [--out-dir DIR] [--timeout-ms N] [--mode grey-box] [--profile-mode v4-full] [--max-requests N] [--probe-concurrency 1-8] [--verify-concurrency 1-4] [--slow-probes N] [--min-free-gb N] [--max-workers N] [--no-warm-workers]')
        process.exit(0)
        break
      default: throw new Error(`Unknown option: ${arg}`)
    }
  }
  if (out.suite === 'realistic') {
    if (out.apps.length === 0) throw new Error('No apps selected')
    if (out.seeds.length === 0) throw new Error('No seeds selected')
  }
  if (out.suite === 'realistic' && out.split === 'heldout' && (process.env.KOVO_RB_HELDOUT_SALT ?? '').length < 16) {
    throw new Error('heldout requires KOVO_RB_HELDOUT_SALT (>=16 chars)')
  }
  return out
}

function readScorecard(file: string): Partial<CellResult> | null {
  if (!existsSync(file)) return null
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const normalized = ScorecardReader.read(raw)
    if (normalized.state === 'failed_inert') return null
    const funnel = (raw.funnel ?? raw.funnelCounts) as Record<string, number> | undefined
    return {
      confirmed: normalized.confirmed,
      targets: normalized.targets,
      recall: normalized.recall,
      precision: normalized.headlinePrecision,
      rawPrecision: normalized.rawPrecision,
      strictPrecision: normalized.strictPrecision,
      cellState: normalized.state,
      decoyFp: normalized.decoyFalsePositives,
      decoys: normalized.decoys,
      unmatchedFp: normalized.unmatchedFalsePositives,
      misclassifiedCount: normalized.misclassifiedCount,
      costUsd: normalized.costUsd,
      funnel: funnel && typeof funnel === 'object' ? funnel : undefined,
    }
  } catch { return null }
}

export function orchestrationEnv(opts: ReturnType<typeof parseArgs>, cell: Cell): Record<string, string> {
  const id = cellLabel(opts.suite === 'realistic' ? `realistic-${cell.app}-seed${cell.seed}` : `${opts.suite}-seed${cell.seed}`)
  const env: Record<string, string> = {
    KOVO_ALLOW_LOCAL_LAB: '1',
    // Cell isolation: stable label + unique data dir + unique run label per cell.
    KOVO_CELL_ID: id,
    KOVO_RUN_LABEL: id,
    KOVO_DATA_DIR: resolve(opts.outDir, 'cells', id, 'data'),
    KOVO_WARM_WORKERS: opts.warmWorkers ? '1' : '0',
  }
  if (opts.maxRequests !== undefined) env.KOVO_BENCH_MAX_REQUESTS = String(opts.maxRequests)
  if (opts.probeConcurrency !== undefined) env.KOVO_BENCH_PROBE_CONCURRENCY = String(opts.probeConcurrency)
  if (opts.verifyConcurrency !== undefined) env.KOVO_BENCH_VERIFY_CONCURRENCY = String(opts.verifyConcurrency)
  if (opts.slowProbes !== undefined) env.KOVO_BENCH_SLOW_PROBES = String(opts.slowProbes)
  return env
}

function runCell(cell: Cell, opts: ReturnType<typeof parseArgs>): Promise<CellResult> {
  const suiteTag = opts.suite === 'realistic' ? cell.app : opts.suite
  const json = resolve(opts.outDir, `${suiteTag}-${cell.seed}.json`)
  const findings = resolve(opts.outDir, `${suiteTag}-${cell.seed}.findings.json`)
  const log = resolve(opts.outDir, `${suiteTag}-${cell.seed}.log`)
  const started = Date.now()
  const args = opts.suite === 'realistic'
    ? [
        'benchmarks/realistic-bench/benchmark-realistic.ts',
        '--app', cell.app, '--seed', String(cell.seed), '--split', opts.split,
        '--profile-mode', opts.profileMode, '--mode', opts.mode,
        '--out-json', json, '--out-findings', findings,
      ]
    : [
        'scripts/benchmark-recall.ts',
        '--suite', opts.suite, '--profile-mode', opts.profileMode,
        '--db', resolve(opts.outDir, `${opts.suite}-db`),
        '--out-json', json, '--out-md', resolve(opts.outDir, `${opts.suite}.md`),
      ]
  return new Promise(resolvePromise => {
    const child = spawn(process.execPath, args, {
      cwd: resolve(import.meta.dirname, '..'),
      env: { ...process.env, ...orchestrationEnv(opts, cell) },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let logText = ''
    const cap = (chunk: Buffer) => { if (logText.length < 20_000) logText += chunk.toString() }
    child.stdout.on('data', cap)
    child.stderr.on('data', cap)
    const timer = setTimeout(() => { child.kill('SIGKILL') }, opts.timeoutMs)
    child.on('error', err => {
      clearTimeout(timer)
      resolvePromise({ app: cell.app, seed: cell.seed, ok: false, exitCode: null, runtimeMs: Date.now() - started, confirmed: 0, targets: 0, recall: null, precision: null, decoyFp: 0, decoys: 0, unmatchedFp: 0, costUsd: 0, error: err.message })
    })
    child.on('close', code => {
      clearTimeout(timer)
      const score = readScorecard(json)
      const firstError = logText.split('\n').find(line => /^error:/i.test(line.trim()))?.slice(0, 180)
      const ok = code === 0 && score !== null
      resolvePromise({
        app: cell.app, seed: cell.seed, ok, exitCode: code,
        runtimeMs: Date.now() - started,
        confirmed: score?.confirmed ?? 0, targets: score?.targets ?? 0,
        recall: ok ? (score?.recall ?? null) : null,
        precision: ok ? (score?.precision ?? null) : null,
        rawPrecision: ok ? (score?.rawPrecision ?? null) : null,
        strictPrecision: ok ? (score?.strictPrecision ?? null) : null,
        cellState: ok ? (score?.cellState ?? 'ok_no_claims') : 'failed_inert',
        decoyFp: score?.decoyFp ?? 0, decoys: score?.decoys ?? 0,
        unmatchedFp: score?.unmatchedFp ?? 0,
        misclassifiedCount: score?.misclassifiedCount ?? 0,
        costUsd: score?.costUsd ?? 0, funnel: score?.funnel,
        ...(code === 0 ? {} : { error: firstError ?? `exit ${code}` }),
      })
    })
  })
}

const fmtPct = (v: number | null): string => (v === null ? 'n/a' : `${(v * 100).toFixed(1)}%`)

export function summarizeMatrix(results: readonly CellResult[]): RealisticMatrixTotals {
  const failed = results.filter(r => !r.ok || r.cellState === 'failed_inert').length
  const status: 'VALID' | 'INVALID' = failed > 0 ? 'INVALID' : 'VALID'
  const confirmed = results.reduce((n, r) => n + r.confirmed, 0)
  const targets = results.reduce((n, r) => n + r.targets, 0)
  const decoyFp = results.reduce((n, r) => n + r.decoyFp, 0)
  const decoys = results.reduce((n, r) => n + r.decoys, 0)
  const unmatchedFp = results.reduce((n, r) => n + r.unmatchedFp, 0)
  const costUsd = results.reduce((n, r) => n + r.costUsd, 0)
  const tpPlusFp = confirmed + decoyFp + unmatchedFp
  return {
    status,
    cells: results.length,
    ok: results.length - failed,
    failed,
    confirmed,
    targets,
    recall: failed > 0 ? null : ratioOrNull(confirmed, targets),
    precision: ratioOrNull(confirmed, tpPlusFp),
    decoyFp,
    decoys,
    unmatchedFp,
    costUsd,
  }
}

export function writeRealisticMatrixLedgerRows(input: {
  results: readonly CellResult[]
  suiteName: BenchmarkSuiteName
  split: 'dev' | 'held-out'
  mode: string
  recordedAt: string
  gitSha: string
  dirty: boolean
  benchmarkVersion: string
  effectiveConfigHash: string
  effectiveConfig?: EffectiveConfigSnapshot
  runId?: string
  runsDir?: string
  ledgerPath?: string
  promoteLedgerPath?: string
  repoRoot?: string
}): { perRunPath: string; rows: LedgerRow[] } {
  const rows: LedgerRow[] = []
  let perRunPath = ''
  const runId = input.runId ?? `realistic-matrix-${input.recordedAt.replace(/[:.]/g, '-')}-${process.pid}`
  for (const r of input.results) {
    const normalized = ScorecardReader.read(
      {
        app: r.app,
        seed: r.seed,
        split: input.split,
        mode: input.mode,
        llm: 'deterministic-no-llm',
        targets: r.targets,
        confirmed: r.confirmed,
        precision: r.precision,
        rawPrecision: r.rawPrecision,
        strictPrecision: r.strictPrecision,
        decoys: r.decoys,
        decoyFalsePositives: r.decoyFp,
        unmatchedFalsePositives: r.unmatchedFp,
        misclassifiedCount: r.misclassifiedCount ?? 0,
        totalCostUsd: r.costUsd,
        durationMs: r.runtimeMs,
      },
      {
        failed: !r.ok || r.cellState === 'failed_inert',
        exitCode: r.exitCode,
        error: r.error,
      },
    )
    const row = buildLedgerRow({
      cell: normalized,
      recordedAt: input.recordedAt,
      suite: input.suiteName,
      gitSha: input.gitSha,
      dirty: input.dirty,
      benchmarkVersion: input.benchmarkVersion,
      effectiveConfigHash: input.effectiveConfigHash,
      effectiveConfig: input.effectiveConfig,
      app: r.app,
      split: input.split,
      mode: input.mode,
      llm: 'deterministic-no-llm',
      seed: r.seed,
      repeat: 1,
      certifying: false,
      reportable: true,
      costUsd: r.costUsd,
      durationMs: r.runtimeMs,
    })
    const appended = appendPerRunLedgerRow(row, {
      runId,
      runsDir: input.runsDir,
      repoRoot: input.repoRoot,
    })
    perRunPath = appended.path
    if (input.ledgerPath) {
      appendLedgerRow(row, input.ledgerPath, input.repoRoot)
    }
    rows.push(row)
  }
  if (input.promoteLedgerPath && perRunPath) {
    promoteLedgerRows(perRunPath, {
      targetLedgerPath: input.promoteLedgerPath,
      repoRoot: input.repoRoot,
    })
  }
  return { perRunPath, rows }
}

export function formatMatrixSummaryLine(input: {
  suite: MatrixSuite
  totals: RealisticMatrixTotals
  concurrency: number
  wallSec: string
  pauseCount: number
  pauses: string
  orphans: number
  outDir: string
}): string {
  const { suite, totals, concurrency, wallSec, pauseCount, pauses, orphans, outDir } = input
  if (totals.status === 'INVALID') {
    return `[matrix] status=INVALID suite=${suite} cells=${totals.cells} failed=${totals.failed} concurrency=${concurrency} wall=${wallSec}s precision=${fmtPct(totals.precision)} decoyFP=${totals.decoyFp} unmatchedFP=${totals.unmatchedFp} cost=$${totals.costUsd.toFixed(3)} pauses=${pauseCount} [${pauses}] orphans=${orphans} out=${outDir}`
  }
  return `[matrix] status=VALID suite=${suite} cells=${totals.cells} failed=${totals.failed} concurrency=${concurrency} wall=${wallSec}s confirmed=${totals.confirmed}/${totals.targets} recall=${fmtPct(totals.recall)} precision=${fmtPct(totals.precision)} decoyFP=${totals.decoyFp} unmatchedFP=${totals.unmatchedFp} cost=$${totals.costUsd.toFixed(3)} pauses=${pauseCount} [${pauses}] orphans=${orphans} out=${outDir}`
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.suite === 'realistic' && opts.split === 'heldout' && !process.env.KOVO_RB_HELDOUT_SALT) {
    console.error('heldout split requires KOVO_RB_HELDOUT_SALT')
    return 2
  }
  mkdirSync(opts.outDir, { recursive: true })
  const cells: Cell[] = []
  if (opts.suite === 'realistic') {
    for (const app of opts.apps) for (const seed of opts.seeds) cells.push({ app, seed })
  } else {
    // Recall suites are deterministic single runs; the seed label is only a report tag.
    cells.push({ app: opts.suite, seed: opts.seeds[0] ?? 42 })
  }

  const cellIds = cells.map(cell => cellLabel(opts.suite === 'realistic' ? `realistic-${cell.app}-seed${cell.seed}` : `${opts.suite}-seed${cell.seed}`))
  const reaper = new CellReaper(cellIds)
  const guard = new ResourceGuard({
    minFreeMemBytes: opts.minFreeMemGb * 1024 ** 3,
    maxActiveWorkers: opts.maxActiveWorkers,
    onPause: event => console.error(`[matrix] paused: ${event.reason} (${(event.memAvailableBytes / 1024 ** 3).toFixed(1)}GiB free, ${event.activeWorkers} workers)`),
    onResume: event => console.error(`[matrix] resumed: ${event.reason} cleared`),
  })
  const startedAt = Date.now()
  const results: CellResult[] = []
  let next = 0
  let orphans = 0
  try {
    reaper.install()
    const workers = Array.from({ length: Math.min(opts.concurrency, cells.length) }, async () => {
      while (next < cells.length) {
        const index = next
        const cell = cells[next]
        next += 1
        await guard.waitForCapacity()
        const result = await runCell(cell, opts)
        results.push(result)
        await reaper.reap(cellIds[index]!)
        const verdict = result.ok
          ? `recall=${result.confirmed}/${result.targets} (${fmtPct(result.recall)}) precision=${fmtPct(result.precision)} decoyFP=${result.decoyFp}/${result.decoys} unmatchedFP=${result.unmatchedFp}`
          : `ERROR ${result.error ?? 'failed'} exit=${result.exitCode}`
        console.log(`[cell] ${cellIds[index]} ${(result.runtimeMs / 1000).toFixed(1)}s ${verdict}`)
      }
    })
    await Promise.all(workers)
    orphans = await reaper.orphans()
  } finally {
    reaper.dispose()
    await reaper.reapAll()
  }

  results.sort((a, b) => a.app.localeCompare(b.app) || a.seed - b.seed)
  const totals = summarizeMatrix(results)
  const suiteName: BenchmarkSuiteName = opts.suite === 'realistic' ? 'realistic-bench' : opts.suite
  const { benchmarkVersion } = computeBenchmarkVersion(suiteName)
  const { effectiveConfigHash, effectiveConfig } = computeEffectiveConfig({
    deterministicOnly: true,
    environment: 'local-lab',
    approvalPolicy: 'auto_review',
    wordlistOn: false,
    mode: opts.mode,
    extra: { profileMode: opts.profileMode },
  })
  const gitState = resolveGitState()
  const recordedAt = new Date().toISOString()
  writeFileSync(
    resolve(opts.outDir, 'matrix-summary.json'),
    `${JSON.stringify({
      recordedAt,
      gitSha: gitState.gitSha,
      dirty: gitState.dirty,
      suite: suiteName,
      benchmarkVersion,
      effectiveConfigHash,
      totals,
      cells: results,
    }, null, 2)}\n`,
    { mode: 0o600 },
  )
  // Default per-run ledger writing (gitignored benchmarks/results/runs/<run-id>.jsonl);
  // promote to committed ledger only via --promote-ledger (or explicit --ledger).
  writeRealisticMatrixLedgerRows({
    results,
    suiteName,
    split: opts.split === 'heldout' ? 'held-out' : 'dev',
    mode: opts.mode,
    recordedAt,
    gitSha: gitState.gitSha,
    dirty: gitState.dirty,
    benchmarkVersion,
    effectiveConfigHash,
    effectiveConfig,
    ledgerPath: opts.ledgerPath,
    promoteLedgerPath: opts.promoteLedgerPath,
  })
  const table = [
    '',
    ['cell'.padEnd(40), 'recall'.padEnd(11), 'prec'.padEnd(7), 'decoy/unmFP'.padEnd(12), 'wall'.padEnd(7), 'cost'.padEnd(8), 'status'].join(' '),
    '-'.repeat(90),
    ...results.map(result => [
      (opts.suite === 'realistic' ? `realistic-${result.app}-seed${result.seed}` : `${opts.suite}-seed${result.seed}`).padEnd(40),
      (result.ok ? `${result.confirmed}/${result.targets}` : 'n/a').padEnd(11),
      fmtPct(result.precision).padEnd(7),
      `${result.decoyFp}/${result.unmatchedFp}`.padEnd(12),
      `${(result.runtimeMs / 1000).toFixed(1)}s`.padEnd(7),
      `$${result.costUsd.toFixed(3)}`.padEnd(8),
      result.ok ? 'ok' : 'FAIL',
    ].join(' ')),
  ].join('\n')
  const pauses = guard.events.length
    ? guard.events.map(e => `${e.reason}@${Math.round(e.at / 1000)}s${e.resumedAt ? `->${Math.round(e.resumedAt / 1000)}s` : '(open)'}`).join(' ')
    : 'none'
  console.log(table)
  console.log(formatMatrixSummaryLine({
    suite: opts.suite,
    totals,
    concurrency: Math.min(opts.concurrency, cells.length),
    wallSec: ((Date.now() - startedAt) / 1000).toFixed(1),
    pauseCount: guard.events.length,
    pauses,
    orphans,
    outDir: opts.outDir,
  }))
  return totals.failed === 0 ? 0 : 1
}

const entry = process.argv[1] ?? ''
if (entry.endsWith('benchmark-realistic-matrix.ts')) {
  main().then(code => {
    process.exitCode = code
    setTimeout(() => process.exit(code), 100)
  }).catch(err => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exitCode = 1
    setTimeout(() => process.exit(1), 100)
  })
}

export { parseArgs, runCell, readScorecard }
