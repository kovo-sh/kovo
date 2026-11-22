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
  funnel?: Record<string, number>
  error?: string
}

const KNOWN_APPS = ['acme-saas', 'shopflow', 'opsportal'] as const

function parseArgs(argv: readonly string[]): {
  apps: string[]; seeds: number[]; split: 'dev' | 'heldout'; concurrency: number
  outDir: string; timeoutMs: number; mode: string; profileMode: string
} {
  const out = {
    apps: [...KNOWN_APPS] as string[], seeds: [42, 1, 2], split: 'dev' as 'dev' | 'heldout',
    concurrency: Math.min(9, Math.max(1, availableParallelism() - 1)),
    outDir: '/tmp/rb-matrix', timeoutMs: 600_000, mode: 'grey-box', profileMode: 'v4-full',
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    const value = argv[i + 1]
    const take = () => { if (value === undefined) throw new Error(`${arg} requires a value`); i += 1; return value }
    switch (arg) {
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
      case '--help': case '-h':
        console.log('Usage: node scripts/benchmark-realistic-matrix.ts [--apps a,b] [--seeds 1,2] [--split dev|heldout] [--concurrency N] [--out-dir DIR] [--timeout-ms N] [--mode grey-box] [--profile-mode v4-full]')
        process.exit(0)
        break
      default: throw new Error(`Unknown option: ${arg}`)
    }
  }
  if (out.apps.length === 0) throw new Error('No apps selected')
  if (out.seeds.length === 0) throw new Error('No seeds selected')
  if (out.split === 'heldout' && (process.env.GUARDIAN_RB_HELDOUT_SALT ?? '').length < 16) {
    throw new Error('heldout requires GUARDIAN_RB_HELDOUT_SALT (>=16 chars)')
  }
  return out
}

function readScorecard(file: string): Partial<CellResult> | null {
  if (!existsSync(file)) return null
  try {
    const c = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
    return {
      confirmed: num(c.confirmed), targets: num(c.targets), recall: num(c.recall),
      precision: num(c.precision), decoyFp: num(c.decoyFalsePositives), decoys: num(c.decoys),
      unmatchedFp: num(c.unmatchedFalsePositives),
      funnel: (c.funnel && typeof c.funnel === 'object' ? c.funnel : undefined) as Record<string, number> | undefined,
    }
  } catch { return null }
}

function runCell(cell: Cell, opts: ReturnType<typeof parseArgs>): Promise<CellResult> {
  const json = resolve(opts.outDir, `${cell.app}-${cell.seed}.json`)
  const findings = resolve(opts.outDir, `${cell.app}-${cell.seed}.findings.json`)
  const log = resolve(opts.outDir, `${cell.app}-${cell.seed}.log`)
  const started = Date.now()
  const args = [
    'benchmarks/realistic-bench/benchmark-realistic.ts',
    '--app', cell.app, '--seed', String(cell.seed), '--split', opts.split,
    '--profile-mode', opts.profileMode, '--mode', opts.mode,
    '--out-json', json, '--out-findings', findings,
  ]
  return new Promise(resolvePromise => {
    const child = spawn(process.execPath, args, {
      cwd: resolve(import.meta.dirname, '..'),
      env: { ...process.env, GUARDIAN_ALLOW_LOCAL_LAB: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let logText = ''
    const cap = (chunk: Buffer) => { if (logText.length < 20_000) logText += chunk.toString() }
    child.stdout.on('data', cap)
    child.stderr.on('data', cap)
    const timer = setTimeout(() => { child.kill('SIGKILL') }, opts.timeoutMs)
    child.on('error', err => {
      clearTimeout(timer)
      resolvePromise({ app: cell.app, seed: cell.seed, ok: false, exitCode: null, runtimeMs: Date.now() - started, confirmed: 0, targets: 0, recall: 0, precision: 0, decoyFp: 0, decoys: 0, unmatchedFp: 0, error: err.message })
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
        unmatchedFp: score?.unmatchedFp ?? 0, funnel: score?.funnel,
        ...(code === 0 ? {} : { error: firstError ?? `exit ${code}` }),
      })
    })
  })
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2))
  if (opts.split === 'heldout' && !process.env.GUARDIAN_RB_HELDOUT_SALT) {
    console.error('heldout split requires GUARDIAN_RB_HELDOUT_SALT')
    return 2
  }
  mkdirSync(opts.outDir, { recursive: true })
  const cells: Cell[] = []
  for (const app of opts.apps) for (const seed of opts.seeds) cells.push({ app, seed })

  const results: CellResult[] = []
  let next = 0
  const workers = Array.from({ length: Math.min(opts.concurrency, cells.length) }, async () => {
    while (next < cells.length) {
      const cell = cells[next]
      next += 1
      const result = await runCell(cell, opts)
      results.push(result)
      const verdict = result.ok
        ? `recall=${result.confirmed}/${result.targets} (${(result.recall * 100).toFixed(1)}%) precision=${(result.precision * 100).toFixed(1)}% decoyFP=${result.decoyFp}/${result.decoys} unmatchedFP=${result.unmatchedFp} funnel=${JSON.stringify(result.funnel)}`
        : `ERROR ${result.error ?? 'failed'} exit=${result.exitCode}`
      console.log(`[cell] ${result.app} seed=${result.seed} ${(result.runtimeMs / 1000).toFixed(1)}s ${verdict}`)
    }
  })
  await Promise.all(workers)

  results.sort((a, b) => a.app.localeCompare(b.app) || a.seed - b.seed)
  const totalConfirmed = results.reduce((n, r) => n + r.confirmed, 0)
  const totalTargets = results.reduce((n, r) => n + r.targets, 0)
  const totalDecoyFp = results.reduce((n, r) => n + r.decoyFp, 0)
  const totalUnmatched = results.reduce((n, r) => n + r.unmatchedFp, 0)
  const failures = results.filter(r => !r.ok).length
  console.log(`[matrix] cells=${results.length} failed=${failures} confirmed=${totalConfirmed}/${totalTargets} recall=${totalTargets ? ((totalConfirmed / totalTargets) * 100).toFixed(1) : '0.0'}% decoyFP=${totalDecoyFp} unmatchedFP=${totalUnmatched} out=${opts.outDir}`)
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
