/**
 * Agentic benchmark matrix (v5 M6 measurement).
 *
 * Runs app x seed x mode cells in parallel child processes. Every cell gets its own
 * artifact directory and an isolated Guardian data dir initialized from --data-dir, so
 * cells never contend for the source Store lock. Agentic cells require a
 * worker-session-capable verifier (`--verifier docker`); the matrix fails closed when a
 * cell is inert, when worker sessions cannot be opened, or when a preflight/lock error
 * occurs.
 *
 * Only structured scorecard/meta JSON is read back. Raw child output is never printed
 * or persisted; failures are summarized to a single short reason.
 *
 * Usage:
 *   newgrp docker -c 'GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-agentic-matrix.ts \
 *     --apps acme-saas,shopflow,opsportal --seeds 1,1000042 --modes grey-box \
 *     --data-dir /home/omarchy/guardian-data --verifier docker \
 *     --budget-usd 5 --max-duration-ms 1200000 --concurrency 3 \
 *     --out-dir /tmp/agentic-matrix'
 *
 * Held-out seeds (>= 1000000) require GUARDIAN_RB_HELDOUT_SALT (>= 16 chars, never
 * logged or committed). `--smoke` is the CI preset: 90 s wall cap, $0.25 budget.
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  CellReaper, ModelGate, ResourceGuard, cellLabel, defaultMaxInFlightStreams, envFlagDisabled,
  rewriteProfileEndpoints,
} from './benchmark-parallel.ts'
import type { AimdStats } from './benchmark-parallel.ts'
import { prepareIsolatedDataDir } from './benchmark-realistic.ts'

export const MATRIX_KNOWN_APPS = ['acme-saas', 'shopflow', 'opsportal'] as const
export const MATRIX_KNOWN_MODES = ['black-box', 'grey-box', 'white-box'] as const
export const MATRIX_KNOWN_VERIFIERS = ['auto', 'docker', 'local-jq'] as const

export const DEFAULT_MATRIX_BUDGET_USD = 5
export const DEFAULT_MATRIX_MAX_DURATION_MS = 15 * 60_000
export const DEFAULT_MATRIX_CONCURRENCY = 3
export const SMOKE_BUDGET_USD = 0.25
export const SMOKE_MAX_DURATION_MS = 90_000
export const HELDOUT_SEED_FLOOR = 1_000_000
/** RAM watermark: do not launch a new cell below this MemAvailable. */
export const DEFAULT_MIN_FREE_MEM_GB = 6
/** Do not launch a new cell while this many cell-labeled workers are running. */
export const DEFAULT_MAX_ACTIVE_WORKERS = 16

export type MatrixApp = (typeof MATRIX_KNOWN_APPS)[number]
export type MatrixMode = (typeof MATRIX_KNOWN_MODES)[number]
export type MatrixVerifier = (typeof MATRIX_KNOWN_VERIFIERS)[number]

export interface MatrixArgs {
  apps: MatrixApp[]
  seeds: number[]
  modes: MatrixMode[]
  budgetUsd: number
  maxDurationMs: number
  concurrency: number
  outDir: string
  dataDir?: string
  noLlm: boolean
  verifier: MatrixVerifier
  keepDataDirs: boolean
  smoke: boolean
  /** Hard kill for a child process; defaults to maxDurationMs + 5 minutes. */
  childTimeoutMs: number
  /** Pause launching cells below this MemAvailable (default 6 GiB). */
  minFreeMemGb?: number
  /** Pause launching cells at/above this many running cell workers (default 16). */
  maxActiveWorkers?: number
  /** Best-effort warm session container per cell (`GUARDIAN_WARM_WORKERS=0` disables). */
  warmWorkers?: boolean
  /** Route model traffic through the loopback gate (global stream cap + 429 AIMD). */
  modelGate?: boolean
  /** Global concurrent model-stream ceiling across all cells (default 28). */
  maxInFlightStreams?: number
  /** Per-cell prepared data-dir override (gate-routed profiles); keyed by cell label. */
  dataDirOverrides?: Record<string, string>
  help: boolean
}

export interface MatrixCell {
  app: MatrixApp
  seed: number
  mode: MatrixMode
  seedSet: 'dev' | 'held-out'
  label: string
}

export interface AssignmentCounts {
  total: number
  completed: number
  failed: number
  canceled: number
  investigationTotal: number
  investigationCompleted: number
  investigationFailed: number
}

export interface FunnelCounts {
  targetVulns: number
  surfaceDiscovered: number
  hypothesisFormed: number
  signalObserved: number
  specSubmitted: number
  zeroLlmConfirmed: number
}

export interface MatrixCellResult {
  app: MatrixApp
  seed: number
  mode: MatrixMode
  seedSet: 'dev' | 'held-out'
  label: string
  ok: boolean
  exitCode: number | null
  runtimeMs: number
  confirmed: number
  targets: number
  precision: number
  decoyFp: number
  decoys: number
  unmatchedFp: number
  costUsd: number
  wallMs: number
  surface: number
  facts: number
  assignments: AssignmentCounts
  funnel: FunnelCounts
  failureBuckets: Record<string, number>
  inert: boolean
  workerSessions: boolean
  agenticExpected: boolean
  modelMode: 'agentic' | 'deterministic-no-llm' | 'unknown'
  verifierBackend: string
  timedOut: boolean
  terminalStatus: string
  jsonPath: string
  metaPath: string
  /** Short redacted reason only; never raw child output. */
  error?: string
  lockError: boolean
  /** True when the cell failed closed on configuration (inert/worker/lock/profile). */
  configError: boolean
}

export interface MatrixTotals {
  cells: number
  ok: number
  failed: number
  inert: number
  workerSessionFailures: number
  lockErrors: number
  confirmed: number
  targets: number
  precision: number
  decoyFp: number
  decoys: number
  unmatchedFp: number
  costUsd: number
  wallMs: number
  surface: number
  facts: number
  assignmentsCompleted: number
  assignmentsFailed: number
  workerFailureRate: number
  costPerFinding: number | null
  funnel: FunnelCounts
  failureBuckets: Record<string, number>
}

interface RawScorecard {
  confirmed?: unknown
  targets?: unknown
  precision?: unknown
  decoyFalsePositives?: unknown
  decoys?: unknown
  unmatchedFalsePositives?: unknown
  totalCostUsd?: unknown
  funnel?: unknown
  failureBuckets?: unknown
}

interface RawMeta {
  model?: { mode?: unknown } | null
  workerSessions?: unknown
  verifierBackend?: unknown
  inert?: unknown
  endpointsDiscovered?: unknown
  facts?: unknown
  assignments?: unknown
  durationMs?: unknown
  timedOut?: unknown
  terminalStatus?: unknown
}

function fail(message: string): never {
  throw new Error(message)
}

function takeValue(argv: readonly string[], index: number, flag: string): string {
  const value = argv[index + 1]
  if (value === undefined || value.startsWith('--')) fail(`${flag} requires a value`)
  return value
}

function parsePositiveInt(raw: string, flag: string, max = 1_000_000_000): number {
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0 || n > max) fail(`${flag} must be a positive integer <= ${max} (got '${raw}')`)
  return n
}

function parseNumber(raw: string, flag: string, min: number, max: number): number {
  const n = Number(raw)
  if (!Number.isFinite(n) || n < min || n > max) fail(`${flag} must be a number in ${min}..${max} (got '${raw}')`)
  return n
}

function parseList<T extends string>(raw: string, flag: string, known: readonly T[]): T[] {
  const values = raw.split(',').map(s => s.trim()).filter(Boolean)
  if (!values.length) fail(`${flag} requires at least one value`)
  for (const value of values) {
    if (!(known as readonly string[]).includes(value)) fail(`${flag} must be one of ${known.join(', ')} (got '${value}')`)
  }
  return [...new Set(values)] as T[]
}

export function parseMatrixArgs(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
): MatrixArgs {
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const key = arg.slice(2)
    if (!key) fail('empty flag')
    if (argv[i + 1] !== undefined && !argv[i + 1]!.startsWith('--')) {
      flags[key] = argv[i + 1]!
      i += 1
    } else {
      flags[key] = true
    }
  }

  const known = new Set([
    'apps', 'seeds', 'modes', 'budget-usd', 'max-duration-ms', 'concurrency',
    'out-dir', 'data-dir', 'no-llm', 'verifier', 'keep-data-dirs', 'smoke',
    'timeout-ms', 'min-free-gb', 'max-workers', 'no-warm-workers', 'warm-workers',
    'no-model-gate', 'model-gate', 'max-inflight-streams', 'help',
  ])
  for (const key of Object.keys(flags)) if (!known.has(key)) fail(`unknown flag --${key}`)

  const smoke = flags.smoke === true
  const help = flags.help === true

  const stringFlag = (key: string): string | undefined => (typeof flags[key] === 'string' ? flags[key] as string : undefined)
  const boolFlag = (key: string): boolean => flags[key] === true

  if (flags['apps'] === true) fail('--apps requires a value')
  const appsRaw = stringFlag('apps')
  const apps = appsRaw === undefined || appsRaw === 'all'
    ? [...MATRIX_KNOWN_APPS]
    : parseList(appsRaw, '--apps', MATRIX_KNOWN_APPS)

  const seedsRaw = stringFlag('seeds') ?? '1'
  const seeds = [...new Set(seedsRaw.split(',').map(s => s.trim()).filter(Boolean).map(s => {
    const n = Number(s)
    if (!Number.isInteger(n) || n <= 0) fail(`seed '${s}' must be a positive integer`)
    return n
  }))]
  if (!seeds.length) fail('at least one seed is required')

  const modes = stringFlag('modes') === undefined
    ? ['grey-box'] as MatrixMode[]
    : parseList(stringFlag('modes')!, '--modes', MATRIX_KNOWN_MODES)

  const budgetUsd = stringFlag('budget-usd') === undefined
    ? (smoke ? SMOKE_BUDGET_USD : DEFAULT_MATRIX_BUDGET_USD)
    : parseNumber(stringFlag('budget-usd')!, '--budget-usd', 0.01, 500)
  const maxDurationMs = stringFlag('max-duration-ms') === undefined
    ? (smoke ? SMOKE_MAX_DURATION_MS : DEFAULT_MATRIX_MAX_DURATION_MS)
    : parsePositiveInt(stringFlag('max-duration-ms')!, '--max-duration-ms')
  const concurrency = stringFlag('concurrency') === undefined
    ? DEFAULT_MATRIX_CONCURRENCY
    : parsePositiveInt(stringFlag('concurrency')!, '--concurrency', 64)

  const verifierRaw = stringFlag('verifier') ?? (boolFlag('no-llm') ? 'auto' : 'docker')
  if (!(MATRIX_KNOWN_VERIFIERS as readonly string[]).includes(verifierRaw)) {
    fail(`--verifier must be one of ${MATRIX_KNOWN_VERIFIERS.join(', ')} (got '${verifierRaw}')`)
  }

  const outDirRaw = stringFlag('out-dir') ?? '.guardian/agentic-matrix'
  const dataDirRaw = stringFlag('data-dir') ?? env.GUARDIAN_DATA_DIR
  const childTimeoutMs = stringFlag('timeout-ms') === undefined
    ? maxDurationMs + 5 * 60_000
    : parsePositiveInt(stringFlag('timeout-ms')!, '--timeout-ms')
  const minFreeMemGb = stringFlag('min-free-gb') === undefined
    ? (Number(env.GUARDIAN_MATRIX_MIN_FREE_GB) > 0 ? Number(env.GUARDIAN_MATRIX_MIN_FREE_GB) : DEFAULT_MIN_FREE_MEM_GB)
    : parseNumber(stringFlag('min-free-gb')!, '--min-free-gb', 0, 1024)
  const maxActiveWorkers = stringFlag('max-workers') === undefined
    ? (Number(env.GUARDIAN_MATRIX_MAX_WORKERS) >= 1 ? Math.floor(Number(env.GUARDIAN_MATRIX_MAX_WORKERS)) : DEFAULT_MAX_ACTIVE_WORKERS)
    : parsePositiveInt(stringFlag('max-workers')!, '--max-workers', 256)
  const warmWorkers = !boolFlag('no-warm-workers') && !envFlagDisabled(env, 'GUARDIAN_WARM_WORKERS')
  const modelGate = !boolFlag('no-model-gate') && !envFlagDisabled(env, 'GUARDIAN_MODEL_GATE')
  const maxInFlightStreams = stringFlag('max-inflight-streams') === undefined
    ? defaultMaxInFlightStreams(env)
    : parsePositiveInt(stringFlag('max-inflight-streams')!, '--max-inflight-streams', 256)

  const heldOutSeeds = seeds.filter(seed => seed >= HELDOUT_SEED_FLOOR)
  if (heldOutSeeds.length && (env.GUARDIAN_RB_HELDOUT_SALT ?? '').length < 16) {
    fail('held-out seeds (>= 1000000) require GUARDIAN_RB_HELDOUT_SALT (>= 16 chars)')
  }

  return {
    apps,
    seeds,
    modes,
    budgetUsd,
    maxDurationMs,
    concurrency,
    outDir: resolve(outDirRaw),
    ...(dataDirRaw ? { dataDir: resolve(dataDirRaw) } : {}),
    noLlm: boolFlag('no-llm'),
    verifier: verifierRaw as MatrixVerifier,
    keepDataDirs: boolFlag('keep-data-dirs'),
    smoke,
    childTimeoutMs,
    minFreeMemGb,
    maxActiveWorkers,
    warmWorkers,
    modelGate,
    maxInFlightStreams,
    help,
  }
}

/** Stable app -> seed -> mode ordering (the order cells are scheduled in). */
export function buildCells(args: Pick<MatrixArgs, 'apps' | 'seeds' | 'modes'>): MatrixCell[] {
  const cells: MatrixCell[] = []
  for (const app of args.apps) {
    for (const seed of args.seeds) {
      for (const mode of args.modes) {
        cells.push({
          app,
          seed,
          mode,
          seedSet: seed >= HELDOUT_SEED_FLOOR ? 'held-out' : 'dev',
          label: `${app}-seed${seed}-${mode}`,
        })
      }
    }
  }
  return cells
}

export function cellArtifactPaths(outDir: string, cell: MatrixCell): { dir: string; jsonPath: string; metaPath: string } {
  const dir = resolve(outDir, cell.label)
  return {
    dir,
    jsonPath: resolve(dir, `${cell.label}.json`),
    metaPath: resolve(dir, `${cell.label}.meta.json`),
  }
}

function finite(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function readJson<T>(path: string): T | null {
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T
  } catch {
    return null
  }
}

function emptyFunnel(): FunnelCounts {
  return {
    targetVulns: 0, surfaceDiscovered: 0, hypothesisFormed: 0,
    signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0,
  }
}

function readAssignments(raw: unknown): AssignmentCounts {
  const a = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  return {
    total: finite(a.total),
    completed: finite(a.completed),
    failed: finite(a.failed),
    canceled: finite(a.canceled),
    investigationTotal: finite(a.investigationTotal),
    investigationCompleted: finite(a.investigationCompleted),
    investigationFailed: finite(a.investigationFailed),
  }
}

function readFunnel(raw: unknown): FunnelCounts {
  const f = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  return {
    targetVulns: finite(f.targetVulns),
    surfaceDiscovered: finite(f.surfaceDiscovered),
    hypothesisFormed: finite(f.hypothesisFormed),
    signalObserved: finite(f.signalObserved),
    specSubmitted: finite(f.specSubmitted),
    zeroLlmConfirmed: finite(f.zeroLlmConfirmed),
  }
}

function readBuckets(raw: unknown): Record<string, number> {
  const out: Record<string, number> = {}
  if (!raw || typeof raw !== 'object') return out
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const n = finite(value)
    if (n > 0) out[key] = n
  }
  return out
}

/** Extract one short diagnostic line from capped child output (no raw dump kept). */
export function summarizeChildFailure(text: string, exitCode: number | null): { error?: string; lockError: boolean } {
  const lines = text.split('\n').map(line => line.trim()).filter(Boolean)
  const errorLine = lines.find(line => /^error:/i.test(line))
    ?? lines.find(line => /lock|EADDRINUSE|worker session|inert|preflight/i.test(line))
  const error = (errorLine ?? (exitCode === null ? 'process error' : `exit ${exitCode}`))
    .replace(/\s+/g, ' ')
    .slice(0, 200)
  return {
    error,
    lockError: /lock|process-lock|isolate-data-dir|EADDRINUSE/i.test(error),
  }
}

export interface CellRunOutcome {
  exitCode: number | null
  runtimeMs: number
  output: string
}

export type CellExecutor = (cell: MatrixCell, args: MatrixArgs) => Promise<CellRunOutcome>

function childEnv(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return { ...base, GUARDIAN_ALLOW_LOCAL_LAB: '1' }
}

/**
 * Per-cell environment: a stable docker cell label, a cell-private data dir, a unique run
 * label and the warm-worker escape hatch. Cells never share a data dir or a run label.
 */
export function cellEnv(
  cell: MatrixCell,
  args: Pick<MatrixArgs, 'dataDir' | 'outDir' | 'warmWorkers' | 'modelGate' | 'dataDirOverrides'>,
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const id = cellLabel(cell.label)
  const env = childEnv(base)
  env.GUARDIAN_CELL_ID = id
  env.GUARDIAN_RUN_LABEL = id
  env.GUARDIAN_WARM_WORKERS = args.warmWorkers === false ? '0' : '1'
  if (!args.modelGate) env.GUARDIAN_MODEL_GATE = '0'
  if (args.dataDir) {
    env.GUARDIAN_DATA_DIR = args.dataDirOverrides?.[cell.label] ?? resolve(args.outDir, 'data', cell.label)
  }
  return env
}

/** Build the child CLI for one cell (exported for scheduling/plan tests). */
export function cellChildArgs(cell: MatrixCell, args: MatrixArgs): string[] {
  const { dir } = cellArtifactPaths(args.outDir, cell)
  const dataDir = args.dataDirOverrides?.[cell.label] ?? args.dataDir
  const childArgs = [
    'scripts/benchmark-realistic.ts',
    '--app', cell.app,
    '--seed', String(cell.seed),
    '--mode', cell.mode,
    '--budget-usd', String(args.budgetUsd),
    '--max-duration-ms', String(args.maxDurationMs),
    '--out-dir', dir,
    '--verifier', args.verifier,
  ]
  if (cell.seedSet === 'held-out') childArgs.push('--held-out')
  if (args.noLlm) {
    childArgs.push('--no-llm')
  } else if (dataDir) {
    childArgs.push('--data-dir', dataDir, '--isolate-data-dir')
  }
  if (args.keepDataDirs) childArgs.push('--keep-data-dirs')
  return childArgs
}

/** Spawn one benchmark cell; artifacts land in its own directory. */
export const spawnCell: CellExecutor = (cell, args) => {
  const { dir } = cellArtifactPaths(args.outDir, cell)
  const childArgs = cellChildArgs(cell, args)

  return new Promise<CellRunOutcome>((resolvePromise, rejectPromise) => {
    const started = Date.now()
    const child = spawn(process.execPath, childArgs, {
      cwd: resolve(import.meta.dirname, '..'),
      env: cellEnv(cell, args),
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let output = ''
    const cap = (chunk: Buffer): void => {
      if (output.length < 16_000) output += chunk.toString()
    }
    child.stdout.on('data', cap)
    child.stderr.on('data', cap)
    const timer = setTimeout(() => { child.kill('SIGKILL') }, args.childTimeoutMs)
    child.on('error', error => {
      clearTimeout(timer)
      rejectPromise(error)
    })
    child.on('close', code => {
      clearTimeout(timer)
      resolvePromise({ exitCode: code, runtimeMs: Date.now() - started, output })
    })
  })
}

/** Read a cell's scorecard + meta into structured metrics. */
export function collectCellResult(
  cell: MatrixCell,
  args: Pick<MatrixArgs, 'outDir' | 'noLlm'>,
  outcome: CellRunOutcome,
): MatrixCellResult {
  const { jsonPath, metaPath } = cellArtifactPaths(args.outDir, cell)
  const card = readJson<RawScorecard>(jsonPath)
  const meta = readJson<RawMeta>(metaPath)
  const failure = summarizeChildFailure(outcome.output, outcome.exitCode)
  const modelModeRaw = meta?.model?.mode
  const modelMode = modelModeRaw === 'agentic' || modelModeRaw === 'deterministic-no-llm'
    ? modelModeRaw
    : 'unknown'
  const expectedAgentic = !args.noLlm
  const inert = meta?.inert === true
  const workerSessions = meta?.workerSessions === true
  const costUsd = finite(card?.totalCostUsd)
  const confirmed = finite(card?.confirmed)
  const targets = finite(card?.targets)
  const decoyFp = finite(card?.decoyFalsePositives)
  const decoys = finite(card?.decoys)
  const unmatchedFp = finite(card?.unmatchedFalsePositives)
  const surface = finite(meta?.endpointsDiscovered)
  const facts = finite(meta?.facts)
  const assignments = readAssignments(meta?.assignments)
  const wallMs = finite(meta?.durationMs, outcome.runtimeMs)

  const lockError = failure.lockError
  const producedArtifacts = outcome.exitCode === 0 && card !== null
  const missingProfile = expectedAgentic && modelMode === 'deterministic-no-llm'
  const missingMeta = expectedAgentic && meta === null
  const noWorkerSessions = expectedAgentic && meta !== null && !workerSessions
  const configError = inert || lockError
    || (producedArtifacts && (missingProfile || missingMeta || noWorkerSessions))

  let error: string | undefined
  if (!card) error = `scorecard missing (${failure.error ?? 'no artifact'})`
  else if (outcome.exitCode !== 0) error = failure.error
  else if (inert) error = 'inert agentic run (no facts, findings, or completed investigation)'
  else if (missingProfile) error = 'agentic run missing a model profile (deterministic fallback)'
  else if (missingMeta) error = 'cell meta missing (cannot prove worker sessions)'
  else if (noWorkerSessions) error = 'worker sessions unavailable (verifier cannot run agents)'

  const ok = outcome.exitCode === 0 && card !== null && !configError

  return {
    app: cell.app,
    seed: cell.seed,
    mode: cell.mode,
    seedSet: cell.seedSet,
    label: cell.label,
    ok,
    exitCode: outcome.exitCode,
    runtimeMs: outcome.runtimeMs,
    confirmed,
    targets,
    precision: finite(card?.precision),
    decoyFp,
    decoys,
    unmatchedFp,
    costUsd,
    wallMs,
    surface,
    facts,
    assignments,
    funnel: readFunnel(card?.funnel),
    failureBuckets: readBuckets(card?.failureBuckets),
    inert,
    workerSessions,
    agenticExpected: expectedAgentic,
    modelMode,
    verifierBackend: typeof meta?.verifierBackend === 'string' ? meta.verifierBackend : 'unknown',
    timedOut: meta?.timedOut === true,
    terminalStatus: typeof meta?.terminalStatus === 'string' ? meta.terminalStatus : 'unknown',
    jsonPath,
    metaPath,
    ...(error ? { error } : {}),
    lockError,
    configError,
  }
}

export interface MatrixRunHooks {
  /** Called before a cell launches (RAM/worker watermark guard). */
  beforeCell?: (cell: MatrixCell) => Promise<void> | void
  /** Called after a cell completes (cell-labeled reaping). */
  afterCell?: (cell: MatrixCell, result: MatrixCellResult) => Promise<void> | void
}

/** Run cells with bounded concurrency; injectable executor keeps scheduling testable. */
export async function runMatrix(
  args: MatrixArgs,
  execute: CellExecutor = spawnCell,
  hooks: MatrixRunHooks = {},
): Promise<MatrixCellResult[]> {
  const cells = buildCells(args)
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })
  const results: MatrixCellResult[] = []
  let next = 0
  const width = Math.min(args.concurrency, cells.length)
  const worker = async (): Promise<void> => {
    while (next < cells.length) {
      const cell = cells[next]!
      next += 1
      await hooks.beforeCell?.(cell)
      let result: MatrixCellResult
      try {
        const outcome = await execute(cell, args)
        result = collectCellResult(cell, args, outcome)
      } catch (error) {
        result = collectCellResult(cell, args, {
          exitCode: null,
          runtimeMs: 0,
          output: `error: ${error instanceof Error ? error.message : String(error)}`,
        })
      }
      results.push(result)
      try { await hooks.afterCell?.(cell, result) } catch { /* reaping is best-effort */ }
    }
  }
  await Promise.all(Array.from({ length: width }, worker))
  return results.sort((a, b) => a.app.localeCompare(b.app) || a.seed - b.seed || a.mode.localeCompare(b.mode))
}

function sumBuckets(results: readonly MatrixCellResult[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const result of results) {
    for (const [key, count] of Object.entries(result.failureBuckets)) out[key] = (out[key] ?? 0) + count
  }
  return out
}

export function summarizeMatrix(results: readonly MatrixCellResult[]): MatrixTotals {
  const funnel = emptyFunnel()
  for (const result of results) {
    for (const key of Object.keys(funnel) as Array<keyof FunnelCounts>) funnel[key] += result.funnel[key]
  }
  const confirmed = results.reduce((n, r) => n + r.confirmed, 0)
  const decoyFp = results.reduce((n, r) => n + r.decoyFp, 0)
  const unmatchedFp = results.reduce((n, r) => n + r.unmatchedFp, 0)
  const assignmentsCompleted = results.reduce((n, r) => n + r.assignments.investigationCompleted, 0)
  const assignmentsFailed = results.reduce((n, r) => n + r.assignments.investigationFailed, 0)
  const agentic = results.filter(r => r.modelMode !== 'deterministic-no-llm')
  const agenticCompleted = agentic.reduce((n, r) => n + r.assignments.investigationCompleted, 0)
  const agenticFailed = agentic.reduce((n, r) => n + r.assignments.investigationFailed, 0)
  const costUsd = results.reduce((n, r) => n + r.costUsd, 0)
  const tpPlusFp = confirmed + decoyFp + unmatchedFp
  return {
    cells: results.length,
    ok: results.filter(r => r.ok).length,
    failed: results.filter(r => !r.ok).length,
    inert: results.filter(r => r.inert).length,
    workerSessionFailures: results.filter(r => r.agenticExpected && !r.workerSessions).length,
    lockErrors: results.filter(r => r.lockError).length,
    confirmed,
    targets: results.reduce((n, r) => n + r.targets, 0),
    precision: tpPlusFp ? confirmed / tpPlusFp : 1,
    decoyFp,
    decoys: results.reduce((n, r) => n + r.decoys, 0),
    unmatchedFp,
    costUsd,
    wallMs: results.reduce((n, r) => n + r.wallMs, 0),
    surface: results.reduce((n, r) => n + r.surface, 0),
    facts: results.reduce((n, r) => n + r.facts, 0),
    assignmentsCompleted,
    assignmentsFailed,
    workerFailureRate: agenticCompleted + agenticFailed
      ? agenticFailed / (agenticCompleted + agenticFailed)
      : 0,
    costPerFinding: confirmed ? costUsd / confirmed : null,
    funnel,
    failureBuckets: sumBuckets(results),
  }
}

/** Configuration failures are exit 2 (fail closed); ordinary cell failures are exit 1. */
export function matrixExitCode(results: readonly MatrixCellResult[]): number {
  if (results.some(r => r.configError)) return 2
  return results.some(r => !r.ok) ? 1 : 0
}

const pct = (n: number): string => `${(n * 100).toFixed(1)}%`

export function renderMatrixTable(results: readonly MatrixCellResult[]): string {
  const header = [
    'cell'.padEnd(34), 'conf'.padEnd(9), 'prec'.padEnd(7), 'decoyFP'.padEnd(8),
    'unmFP'.padEnd(6), 'cost'.padEnd(8), 'wall'.padEnd(7), 'surf'.padEnd(5),
    'facts'.padEnd(6), 'assign'.padEnd(9), 'inert'.padEnd(6), 'ws'.padEnd(3), 'status',
  ].join(' ')
  const lines = ['', header, '-'.repeat(header.length)]
  for (const r of results) {
    const wall = `${Math.round(r.wallMs / 1000)}s`
    lines.push([
      r.label.padEnd(34),
      `${r.confirmed}/${r.targets}`.padEnd(9),
      pct(r.precision).padEnd(7),
      String(r.decoyFp).padEnd(8),
      String(r.unmatchedFp).padEnd(6),
      `$${r.costUsd.toFixed(3)}`.padEnd(8),
      wall.padEnd(7),
      String(r.surface).padEnd(5),
      String(r.facts).padEnd(6),
      `${r.assignments.investigationCompleted}/${r.assignments.investigationFailed}`.padEnd(9),
      (r.inert ? 'YES' : 'no').padEnd(6),
      (r.workerSessions ? 'yes' : 'no').padEnd(3),
      r.ok ? 'ok' : 'FAIL',
    ].join(' '))
    if (!r.ok) lines.push(`  ! ${r.label}: ${r.error ?? 'failed'}`)
  }
  return lines.join('\n')
}

export function renderMatrixSummary(totals: MatrixTotals): string {
  const costPerFinding = totals.costPerFinding === null ? 'n/a' : `$${totals.costPerFinding.toFixed(3)}`
  return [
    '',
    `TOTAL cells=${totals.cells} ok=${totals.ok} failed=${totals.failed} inert=${totals.inert} `
      + `workerSessionFailures=${totals.workerSessionFailures} lockErrors=${totals.lockErrors}`,
    `confirmed=${totals.confirmed}/${totals.targets} precision=${pct(totals.precision)} `
      + `decoyFP=${totals.decoyFp}/${totals.decoys} unmatchedFP=${totals.unmatchedFp} cost=$${totals.costUsd.toFixed(3)} `
      + `cost/finding=${costPerFinding} wall=${Math.round(totals.wallMs / 1000)}s surface=${totals.surface} facts=${totals.facts}`,
    `assignments completed=${totals.assignmentsCompleted} failed=${totals.assignmentsFailed} `
      + `workerFailureRate=${pct(totals.workerFailureRate)}`,
    `funnel=${JSON.stringify(totals.funnel)}`,
    `failureBuckets=${JSON.stringify(totals.failureBuckets)}`,
  ].join('\n')
}

export const MATRIX_USAGE = `Guardian agentic benchmark matrix (v5 M6)

Usage:
  GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-agentic-matrix.ts [flags]

Flags:
  --apps a,b              ${MATRIX_KNOWN_APPS.join(' | ')} (default: all)
  --seeds 1,1000042       dev (1..9999) and/or held-out (>= 1000000) seeds
  --modes m,...           ${MATRIX_KNOWN_MODES.join(' | ')} (default: grey-box)
  --budget-usd <n>        per-cell USD budget (default: ${DEFAULT_MATRIX_BUDGET_USD})
  --max-duration-ms <n>   per-cell wall cap (default: ${DEFAULT_MATRIX_MAX_DURATION_MS})
  --concurrency <n>       parallel cells (default: ${DEFAULT_MATRIX_CONCURRENCY})
  --out-dir <dir>         matrix artifacts (default: .guardian/agentic-matrix)
  --data-dir <path>       Guardian data dir with an enabled model profile
                          (default: $GUARDIAN_DATA_DIR); each cell gets an isolated copy
  --verifier <kind>       auto | docker | local-jq (default: docker; auto with --no-llm)
  --no-llm                deterministic cells (no model profile)
  --keep-data-dirs        keep per-cell isolated data dirs
  --smoke                 CI preset: ${SMOKE_MAX_DURATION_MS / 1000}s per cell, $${SMOKE_BUDGET_USD} budget
  --timeout-ms <n>        hard child kill (default: max-duration + 5 min)
  --min-free-gb <n>       pause new cells below this MemAvailable (default: ${DEFAULT_MIN_FREE_MEM_GB})
  --max-workers <n>       pause new cells at this many running cell workers (default: ${DEFAULT_MAX_ACTIVE_WORKERS})
  --no-warm-workers       disable the per-cell warm session container pool
  --no-model-gate         bypass the loopback gate (no global stream cap / 429 AIMD)
  --max-inflight-streams  global concurrent model streams (default: 28, env GUARDIAN_MODEL_MAX_STREAMS)
  --help                  show this help

Held-out seeds need GUARDIAN_RB_HELDOUT_SALT (env only; never logged).
Agentic cells need Docker worker access: run under \`newgrp docker -c '<command>'\`.
Each cell gets its own data dir, ephemeral app/canary ports, cell label and run label.
Exit codes: 0 clean, 2 fail-closed configuration/inert/lock, 1 cell failure.
`

/**
 * Prepare a gate-routed source data dir per cell. The child still isolates again from this dir;
 * only enabled profile endpoints change (credentials stay symlinked, never copied).
 */
export function prepareGatedCellDataDirs(args: MatrixArgs, gate: ModelGate): Record<string, string> {
  const overrides: Record<string, string> = {}
  const source = args.dataDir
  if (!source) return overrides
  for (const cell of buildCells(args)) {
    const target = resolve(args.outDir, 'cells', cellLabel(cell.label), 'source')
    prepareIsolatedDataDir({ sourceDataDir: source, targetDir: target })
    rewriteProfileEndpoints(target, endpoint => gate.endpointFor(endpoint))
    overrides[cell.label] = target
  }
  return overrides
}

export interface ParallelStatus {
  gate: AimdStats | null
  gatePort: number | null
  pauses: Array<{ at: number; reason: string; memGiB: number; workers: number; resumedAt?: number }>
  orphans: number
}

export function renderParallelStatus(status: ParallelStatus): string {
  const gate = status.gate
    ? `gate=max${status.gate.limit} peak=${status.gate.peak} queued=${status.gate.queued} `
      + `429=${status.gate.rateLimited} retries=${status.gate.retries}`
    : 'gate=off'
  const pauses = status.pauses.length
    ? status.pauses.map(p => `${p.reason}@${Math.round(p.at / 1000)}s(`
      + `${p.memGiB.toFixed(1)}GiB/${p.workers}w${p.resumedAt ? ` resume@${Math.round(p.resumedAt / 1000)}s` : ',open'})`).join(' ')
    : 'none'
  return `parallel ${gate} pauses=${status.pauses.length} [${pauses}] orphans=${status.orphans}`
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  let args: MatrixArgs
  try {
    args = parseMatrixArgs(argv)
  } catch (error) {
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`)
    return 2
  }
  if (args.help) {
    process.stdout.write(MATRIX_USAGE)
    return 0
  }
  if (!args.noLlm && !args.dataDir) {
    process.stderr.write('error: agentic matrix needs --data-dir (or GUARDIAN_DATA_DIR) with an enabled model profile; use --no-llm for deterministic cells\n')
    return 2
  }
  // Worker sessions need the Docker backend; a model profile + local-jq is inert, so fail fast.
  if (!args.noLlm && args.verifier === 'local-jq') {
    process.stderr.write('error: agentic cells need worker sessions: use --verifier docker (local-jq cannot run agents)\n')
    return 2
  }
  mkdirSync(args.outDir, { recursive: true, mode: 0o700 })
  const started = Date.now()
  let gate: ModelGate | undefined
  const cells = buildCells(args)
  const reaper = new CellReaper(cells.map(cell => cell.label))
  const guard = new ResourceGuard({
    minFreeMemBytes: (args.minFreeMemGb ?? DEFAULT_MIN_FREE_MEM_GB) * 1024 ** 3,
    maxActiveWorkers: args.maxActiveWorkers ?? DEFAULT_MAX_ACTIVE_WORKERS,
    onPause: event => process.stderr.write(
      `[matrix] paused: ${event.reason} (${(event.memAvailableBytes / 1024 ** 3).toFixed(1)}GiB free, `
      + `${event.activeWorkers} workers)\n`,
    ),
    onResume: event => process.stderr.write(`[matrix] resumed: ${event.reason} cleared\n`),
  })
  let orphans = 0
  try {
    if (!args.noLlm && args.modelGate !== false) {
      gate = new ModelGate({ maxInFlightStreams: args.maxInFlightStreams ?? 28 })
      await gate.start()
      args = { ...args, dataDirOverrides: prepareGatedCellDataDirs(args, gate) }
      process.stdout.write(`[matrix] model gate 127.0.0.1:${gate.port} maxInFlight=${gate.stats().limit}\n`)
    }
    reaper.install()
    const results = await runMatrix(args, spawnCell, {
      beforeCell: () => guard.waitForCapacity(),
      afterCell: async cell => { await reaper.reap(cell.label) },
    })
    orphans = await reaper.orphans()
    const totals = summarizeMatrix(results)
    const matrix = {
      generatedAt: new Date().toISOString(),
      wallMs: Date.now() - started,
      args: {
        apps: args.apps, seeds: args.seeds, modes: args.modes, budgetUsd: args.budgetUsd,
        maxDurationMs: args.maxDurationMs, concurrency: args.concurrency, noLlm: args.noLlm,
        verifier: args.verifier, smoke: args.smoke, dataDir: args.dataDir ?? null,
        warmWorkers: args.warmWorkers !== false,
        maxInFlightStreams: args.maxInFlightStreams ?? 28,
        minFreeMemGb: args.minFreeMemGb ?? DEFAULT_MIN_FREE_MEM_GB,
        maxActiveWorkers: args.maxActiveWorkers ?? DEFAULT_MAX_ACTIVE_WORKERS,
      },
      parallel: {
        gate: gate?.stats() ?? null,
        pauses: guard.events,
        orphans,
      },
      totals,
      cells: results,
    }
    const outPath = resolve(args.outDir, 'matrix.json')
    writeFileSync(outPath, `${JSON.stringify(matrix, null, 2)}\n`, { mode: 0o600 })
    process.stdout.write(`[matrix] ${results.length} cell(s) -> ${outPath}\n`)
    process.stdout.write(`${renderMatrixTable(results)}\n${renderMatrixSummary(totals)}\n`)
    process.stdout.write(`${renderParallelStatus({
      gate: gate?.stats() ?? null,
      gatePort: gate?.port ?? null,
      pauses: guard.events.map(event => ({
        at: event.at, reason: event.reason,
        memGiB: event.memAvailableBytes / 1024 ** 3, workers: event.activeWorkers,
        ...(event.resumedAt !== undefined ? { resumedAt: event.resumedAt } : {}),
      })),
      orphans,
    })}\n`)
    return matrixExitCode(results)
  } catch (error) {
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`)
    return 2
  } finally {
    reaper.dispose()
    await reaper.reapAll()
    await gate?.close()
  }
}

const isMain = process.argv[1] ? resolve(process.argv[1]) === fileURLToPath(import.meta.url) : false
if (isMain) {
  main().then(code => { process.exitCode = code }).catch(error => {
    process.stderr.write(`error: ${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
  })
}
