/**
 * Parallel runner for benchmarks/realistic-bench cells (app x seed).
 *
 * Runs each cell in its own child process so the 16-core host is used instead of
 * executing a 9-cell matrix serially. It only reads each cell's structured scorecard
 * JSON and prints aggregate metrics (no raw logs).
 *
 * Usage:
 *   GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-realistic-matrix.ts \
 *     --apps acme-saas,shopflow,opsportal --seeds 42,1,2 --split dev \
 *     --concurrency 9 --out-dir /tmp/rb-matrix
 *
 * Held-out runs additionally need GUARDIAN_RB_HELDOUT_SALT (>=16 chars, never committed).
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { availableParallelism } from 'node:os'
import { resolve } from 'node:path'
import {
  CellReaper, ResourceGuard, cellLabel, envFlagDisabled,
} from './benchmark-parallel.ts'

interface Cell { app: string; seed: number }
interface CellResult {
  app: string
  seed: number
  ok: boolean
  exitCode: number | null
  runtimeMs: number
  confirmed: number
  targets: number
  recall: number
  precision: number
  decoyFp: number
  decoys: number
  unmatchedFp: number
  costUsd: number
  funnel?: Record<string, number>
  error?: string
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
    minFreeMemGb: Number(process.env.GUARDIAN_MATRIX_MIN_FREE_GB) > 0
      ? Number(process.env.GUARDIAN_MATRIX_MIN_FREE_GB) : DEFAULT_MIN_FREE_MEM_GB,
    maxActiveWorkers: Number(process.env.GUARDIAN_MATRIX_MAX_WORKERS) >= 1
      ? Math.floor(Number(process.env.GUARDIAN_MATRIX_MAX_WORKERS)) : DEFAULT_MAX_ACTIVE_WORKERS,
    warmWorkers: !envFlagDisabled(process.env, 'GUARDIAN_WARM_WORKERS'),
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
  if (out.suite === 'realistic' && out.split === 'heldout' && (process.env.GUARDIAN_RB_HELDOUT_SALT ?? '').length < 16) {
    throw new Error('heldout requires GUARDIAN_RB_HELDOUT_SALT (>=16 chars)')
  }
  return out
}

function readScorecard(file: string): Partial<CellResult> | null {
  if (!existsSync(file)) return null
  try {
    const c = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
    // realistic-bench scorecards use `targets`; recall benchmarks use `targetsTotal`/`confirmedCount`.
    const funnel = (c.funnel ?? c.funnelCounts) as Record<string, number> | undefined
    return {
      confirmed: num(c.confirmed ?? c.confirmedCount), targets: num(c.targets ?? c.targetsTotal), recall: num(c.recall),
      precision: num(c.precision), decoyFp: num(c.decoyFalsePositives ?? c.falsePositiveCount), decoys: num(c.decoys ?? c.decoysTotal),
      unmatchedFp: num(c.unmatchedFalsePositives), costUsd: num(c.totalCostUsd),
      funnel: funnel && typeof funnel === 'object' ? funnel : undefined,
    }
  } catch { return null }
}

export function orchestrationEnv(opts: ReturnType<typeof parseArgs>, cell: Cell): Record<string, string> {
  const id = cellLabel(opts.suite === 'realistic' ? `realistic-${cell.app}-seed${cell.seed}` : `${opts.suite}-seed${cell.seed}`)
  const env: Record<string, string> = {
    GUARDIAN_ALLOW_LOCAL_LAB: '1',
    // Cell isolation: stable label + unique data dir + unique run label per cell.
    GUARDIAN_CELL_ID: id,
    GUARDIAN_RUN_LABEL: id,
    GUARDIAN_DATA_DIR: resolve(opts.outDir, 'cells', id, 'data'),
    GUARDIAN_WARM_WORKERS: opts.warmWorkers ? '1' : '0',
  }
  if (opts.maxRequests !== undefined) env.GUARDIAN_BENCH_MAX_REQUESTS = String(opts.maxRequests)
  if (opts.probeConcurrency !== undefined) env.GUARDIAN_BENCH_PROBE_CONCURRENCY = String(opts.probeConcurrency)
  if (opts.verifyConcurrency !== undefined) env.GUARDIAN_BENCH_VERIFY_CONCURRENCY = String(opts.verifyConcurrency)
  if (opts.slowProbes !== undefined) env.GUARDIAN_BENCH_SLOW_PROBES = String(opts.slowProbes)
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
      resolvePromise({ app: cell.app, seed: cell.seed, ok: false, exitCode: null, runtimeMs: Date.now() - started, confirmed: 0, targets: 0, recall: 0, precision: 0, decoyFp: 0, decoys: 0, unmatchedFp: 0, costUsd: 0, error: err.message })
    })
    child.on('close', code => {
      clearTimeout(timer)
      const score = readScorecard(json)
      const firstError = logText.split('\n').find(line => /^error:/i.test(line.trim()))?.slice(0, 180)
      resolvePromise({
        app: cell.app, seed: cell.seed, ok: code === 0 && score !== null, exitCode: code,
        runtimeMs: Date.now() - started,
        confirmed: score?.confirmed ?? 0, targets: score?.targets ?? 0, recall: score?.recall ?? 0,
        precision: score?.precision ?? 0, decoyFp: score?.decoyFp ?? 0, decoys: score?.decoys ?? 0,
        unmatchedFp: score?.unmatchedFp ?? 0, costUsd: score?.costUsd ?? 0, funnel: score?.funnel,
        ...(code === 0 ? {} : { error: firstError ?? `exit ${code}` }),
      })
    })
  })
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.suite === 'realistic' && opts.split === 'heldout' && !process.env.GUARDIAN_RB_HELDOUT_SALT) {
    console.error('heldout split requires GUARDIAN_RB_HELDOUT_SALT')
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
          ? `recall=${result.confirmed}/${result.targets} (${(result.recall * 100).toFixed(1)}%) precision=${(result.precision * 100).toFixed(1)}% decoyFP=${result.decoyFp}/${result.decoys} unmatchedFP=${result.unmatchedFp}`
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
  const totalConfirmed = results.reduce((n, r) => n + r.confirmed, 0)
  const totalTargets = results.reduce((n, r) => n + r.targets, 0)
  const totalDecoyFp = results.reduce((n, r) => n + r.decoyFp, 0)
  const totalUnmatched = results.reduce((n, r) => n + r.unmatchedFp, 0)
  const totalCost = results.reduce((n, r) => n + r.costUsd, 0)
  const failures = results.filter(r => !r.ok).length
  const table = [
    '',
    ['cell'.padEnd(40), 'recall'.padEnd(11), 'prec'.padEnd(7), 'decoy/unmFP'.padEnd(12), 'wall'.padEnd(7), 'cost'.padEnd(8), 'status'].join(' '),
    '-'.repeat(90),
    ...results.map(result => [
      (opts.suite === 'realistic' ? `realistic-${result.app}-seed${result.seed}` : `${opts.suite}-seed${result.seed}`).padEnd(40),
      `${result.confirmed}/${result.targets}`.padEnd(11),
      `${(result.precision * 100).toFixed(1)}%`.padEnd(7),
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
  console.log(`[matrix] suite=${opts.suite} cells=${results.length} failed=${failures} concurrency=${Math.min(opts.concurrency, cells.length)} wall=${((Date.now() - startedAt) / 1000).toFixed(1)}s confirmed=${totalConfirmed}/${totalTargets} recall=${totalTargets ? ((totalConfirmed / totalTargets) * 100).toFixed(1) : '0.0'}% decoyFP=${totalDecoyFp} unmatchedFP=${totalUnmatched} cost=$${totalCost.toFixed(3)} pauses=${guard.events.length} [${pauses}] orphans=${orphans} out=${opts.outDir}`)
  return failures === 0 ? 0 : 1
}

const entry = process.argv[1] ?? ''
if (entry.endsWith('benchmark-realistic-matrix.ts')) {
  main().then(code => { process.exitCode = code }).catch(err => {
    console.error(err instanceof Error ? err.message : String(err))
    process.exitCode = 1
  })
}

export { parseArgs, runCell, readScorecard }
