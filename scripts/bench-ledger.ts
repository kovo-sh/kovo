/**
 * Versioned benchmark results ledger & held-out seed hygiene (Item #2 / Gap #3).
 *
 * Provides:
 *  - `computeBenchmarkVersion(suite)` — deterministic SHA-256 content hash over benchmark
 *    apps, truth, grader, and lib directories (for both `realistic-bench` and v8 `multihop-saas`).
 *  - `computeEffectiveConfig(opts)` — deterministic SHA-256 fingerprint over all behavior-changing
 *    `KOVO_*` env vars + `deterministicOnly`, `environment`, `approvalPolicy`, `wordlistOn`,
 *    `proofReceiptMode` (never including secrets, salts, tokens, keys, or host paths).
 *  - `appendLedgerRow(row, ledgerPath)` / `readLedgerRows(ledgerPath)` / `compareLedgerRows(a, b)`
 *    — append-only JSONL ledger at `benchmarks/results/ledger.jsonl` that refuses cross-version
 *    or cross-config comparisons.
 *  - `loadBurnedSeeds()` / `assertNoBurnedSeeds()` / `drawUnburnedHeldoutSeeds()` — enforces the
 *    committed `benchmarks/realistic-bench/BURNED_SEEDS` burn list and draws `n >= 3` fresh
 *    unburned salted seeds for certification runs.
 */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { listSeeds as realisticListSeeds } from '../benchmarks/realistic-bench/generator/seeds.ts'

export const LEDGER_SCHEMA_VERSION = 1 as const
export const DEFAULT_LEDGER_PATH = 'benchmarks/results/ledger.jsonl'
export const BURNED_SEEDS_PATH = 'benchmarks/realistic-bench/BURNED_SEEDS'
export const CERTIFYING_MIN_HELDOUT_SEEDS = 3

export type BenchmarkSuiteName =
  | 'realistic-bench'
  | 'multihop-saas'
  | 'xben-25'
  | 'held-out-saas'
  | 'reason-bench'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

/** Env-var name patterns that may carry secrets/credentials/salts — NEVER fingerprinted or persisted. */
export const SENSITIVE_ENV_KEY_RE =
  /(SALT|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|COOKIE|AUTH_HEADER|PAT|BEARER|PRIVATE)/i

/** Non-behavioral host-path / per-cell ephemeral env vars excluded from EffectiveConfig. */
const NON_BEHAVIORAL_KOVO_ENV_KEYS = new Set([
  'KOVO_DATA_DIR',
  'KOVO_CREDENTIALS_DIR',
  'KOVO_CELL_ID',
  'KOVO_RUN_LABEL',
  'KOVO_OUT_DIR',
  'KOVO_TMPDIR',
  'KOVO_LOG_DIR',
  'KOVO_CACHE_DIR',
  'KOVO_BENCH_DEBUG',
  'KOVO_RB_HELDOUT_SALT',
])

const SKIP_DIRS = new Set(['node_modules', '.git', 'out', 'dist', '.kovo'])

export interface BenchmarkVersionResult {
  suite: BenchmarkSuiteName
  benchmarkVersion: string
  filesHashed: number
  paths: string[]
}

function suiteContentRoots(suite: BenchmarkSuiteName): string[] {
  switch (suite) {
    case 'realistic-bench':
      return [
        'benchmarks/realistic-bench/apps',
        'benchmarks/realistic-bench/truth',
        'benchmarks/realistic-bench/grader',
        'benchmarks/realistic-bench/lib',
      ]
    case 'multihop-saas':
      return [
        'benchmarks/multihop-saas/apps',
        'benchmarks/multihop-saas/truth',
        'benchmarks/multihop-saas/run.ts',
        'benchmarks/multihop-saas/grader',
        'benchmarks/multihop-saas/lib',
      ]
    case 'xben-25':
      return ['benchmarks/xben-25']
    case 'held-out-saas':
      return ['local-lab/held-out-saas']
    case 'reason-bench':
      return ['benchmarks/reason-bench']
  }
}

function collectFilesSorted(targetPath: string, out: string[]): void {
  if (!existsSync(targetPath)) return
  const st = statSync(targetPath)
  if (st.isFile()) {
    out.push(targetPath)
    return
  }
  if (!st.isDirectory()) return
  const entries = readdirSync(targetPath).sort()
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue
    collectFilesSorted(join(targetPath, entry), out)
  }
}

/**
 * Compute a stable SHA-256 content hash for a benchmark suite's immutable specification
 * (apps, truth, grader, lib, and for multihop-saas also `run.ts`).
 */
export function computeBenchmarkVersion(
  suite: BenchmarkSuiteName = 'realistic-bench',
  repoRoot: string = REPO_ROOT,
): BenchmarkVersionResult {
  const roots = suiteContentRoots(suite)
  const files: string[] = []
  for (const rel of roots) {
    collectFilesSorted(resolve(repoRoot, rel), files)
  }
  const uniqueRel = [...new Set(files.map(f => relative(repoRoot, f).split(sep).join('/')))].sort()
  if (uniqueRel.length === 0) {
    throw new Error(`computeBenchmarkVersion(${suite}): no benchmark files found under ${roots.join(', ')}`)
  }
  const hash = createHash('sha256')
  hash.update(`kovo-bench-version:v1:${suite}\0`)
  for (const relPath of uniqueRel) {
    const absPath = resolve(repoRoot, relPath)
    hash.update(relPath)
    hash.update('\0')
    hash.update(readFileSync(absPath))
    hash.update('\0')
  }
  return {
    suite,
    benchmarkVersion: hash.digest('hex'),
    filesHashed: uniqueRel.length,
    paths: uniqueRel,
  }
}

export interface EffectiveConfigInput {
  env?: NodeJS.ProcessEnv
  deterministicOnly?: boolean
  environment?: string
  approvalPolicy?: string
  wordlistOn?: boolean
  proofReceiptMode?: string
  verifierBackend?: string
  mode?: string
  extra?: Record<string, string | number | boolean | null | undefined>
}

export interface EffectiveConfigSnapshot {
  deterministicOnly: boolean
  environment: string
  approvalPolicy: string
  wordlistOn: boolean
  proofReceiptMode: string
  verifierBackend: string
  mode: string
  kovoEnv: Record<string, string>
  extra?: Record<string, string | number | boolean | null>
}

export interface EffectiveConfigResult {
  effectiveConfigHash: string
  effectiveConfig: EffectiveConfigSnapshot
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`).join(',')}}`
}

/**
 * Fingerprint every behavior-changing `KOVO_*` environment variable plus the core execution
 * switches (`deterministicOnly`, `environment`, `approvalPolicy`, `wordlistOn`, `proofReceiptMode`)
 * into a stable SHA-256 `effectiveConfigHash`. Secrets, salts, tokens, and host paths are stripped.
 */
export function computeEffectiveConfig(opts: EffectiveConfigInput = {}): EffectiveConfigResult {
  const env = opts.env ?? process.env
  const kovoEnv: Record<string, string> = {}
  const keys = Object.keys(env).sort()
  for (const key of keys) {
    if (!key.startsWith('KOVO_')) continue
    if (NON_BEHAVIORAL_KOVO_ENV_KEYS.has(key)) continue
    if (SENSITIVE_ENV_KEY_RE.test(key)) continue
    const raw = env[key]
    if (raw === undefined || raw === '') continue
    kovoEnv[key] = raw.trim()
  }

  const proofReceiptRaw = opts.proofReceiptMode ?? env.KOVO_PROOF_RECEIPT
  const proofReceiptMode =
    typeof proofReceiptRaw === 'string' && proofReceiptRaw.trim().length > 0
      ? proofReceiptRaw.trim().toLowerCase()
      : 'strict'

  const cleanExtra: Record<string, string | number | boolean | null> = {}
  if (opts.extra) {
    for (const [k, v] of Object.entries(opts.extra).sort(([a], [b]) => a.localeCompare(b))) {
      if (v === undefined) continue
      if (SENSITIVE_ENV_KEY_RE.test(k)) continue
      cleanExtra[k] = v
    }
  }

  const effectiveConfig: EffectiveConfigSnapshot = {
    deterministicOnly: Boolean(opts.deterministicOnly ?? false),
    environment: (opts.environment ?? 'local-lab').trim(),
    approvalPolicy: (opts.approvalPolicy ?? 'auto_review').trim(),
    wordlistOn: Boolean(opts.wordlistOn ?? false),
    proofReceiptMode,
    verifierBackend: (opts.verifierBackend ?? 'auto').trim(),
    mode: (opts.mode ?? 'grey-box').trim(),
    kovoEnv,
    ...(Object.keys(cleanExtra).length > 0 ? { extra: cleanExtra } : {}),
  }

  const canonical = stableJson(effectiveConfig)
  const effectiveConfigHash = createHash('sha256')
    .update('kovo-effective-config:v1:')
    .update(canonical)
    .digest('hex')

  return { effectiveConfigHash, effectiveConfig }
}

// ---------------------------------------------------------------------------
// Burned held-out seeds & fresh unburned seed drawing
// ---------------------------------------------------------------------------

function resolveRepoPath(p: string, repoRoot: string = REPO_ROOT): string {
  return isAbsolute(p) ? p : resolve(repoRoot, p)
}

/** Parse `benchmarks/realistic-bench/BURNED_SEEDS` into a set of burned integer seeds. */
export function loadBurnedSeeds(burnedPath: string = BURNED_SEEDS_PATH, repoRoot: string = REPO_ROOT): Set<number> {
  const abs = resolveRepoPath(burnedPath, repoRoot)
  if (!existsSync(abs)) return new Set()
  const out = new Set<number>()
  const text = readFileSync(abs, 'utf8')
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim()
    if (!line) continue
    const n = Number(line)
    if (!Number.isInteger(n) || n <= 0) {
      throw new Error(`Invalid burned seed entry '${line}' in ${abs}`)
    }
    out.add(n)
  }
  return out
}

export class BurnedSeedError extends Error {
  readonly burnedSeeds: number[]
  constructor(message: string, burnedSeeds: number[]) {
    super(message)
    this.name = 'BurnedSeedError'
    this.burnedSeeds = burnedSeeds
  }
}

/**
 * Reject burned held-out seeds (e.g. `1000042`) for certification runs.
 * Explicit `allowBurnedDev: true` permits dev-2 debugging and returns `certifying: false`.
 */
export function assertNoBurnedSeeds(
  seeds: readonly number[],
  opts: {
    allowBurnedDev?: boolean
    burnedPath?: string
    repoRoot?: string
    context?: string
  } = {},
): { burned: number[]; certifying: boolean } {
  const burnedSet = loadBurnedSeeds(opts.burnedPath, opts.repoRoot)
  const burned = [...new Set(seeds.filter(s => burnedSet.has(s)))].sort((a, b) => a - b)
  if (burned.length === 0) {
    return { burned: [], certifying: true }
  }
  if (opts.allowBurnedDev) {
    return { burned, certifying: false }
  }
  const prefix = opts.context ? `${opts.context}: ` : ''
  throw new BurnedSeedError(
    `${prefix}refusing burned held-out seed(s) [${burned.join(', ')}] listed in ${BURNED_SEEDS_PATH} `
      + '(demoted to dev-2 only). Draw fresh unburned salted seeds for certification, or pass '
      + '--allow-burned-dev for non-certifying dev-2 debugging.',
    burned,
  )
}

/**
 * Draw `count` fresh unburned salted held-out seeds (`>= 1_000_000`) via `listSeeds`,
 * skipping any seed present in `benchmarks/realistic-bench/BURNED_SEEDS`.
 */
export function drawUnburnedHeldoutSeeds(
  count: number = CERTIFYING_MIN_HELDOUT_SEEDS,
  salt?: string,
  burnedPath: string = BURNED_SEEDS_PATH,
  repoRoot: string = REPO_ROOT,
): number[] {
  if (!Number.isInteger(count) || count < 1) {
    throw new Error(`drawUnburnedHeldoutSeeds: count must be a positive integer (got ${count})`)
  }
  const burned = loadBurnedSeeds(burnedPath, repoRoot)
  let request = count + burned.size + 4
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidates = realisticListSeeds('held-out', request, salt)
    const fresh = candidates.filter(seed => !burned.has(seed))
    if (fresh.length >= count) {
      return fresh.slice(0, count)
    }
    request *= 2
  }
  throw new Error(`drawUnburnedHeldoutSeeds: unable to draw ${count} unburned held-out seeds`)
}

// ---------------------------------------------------------------------------
// Git state & append-only JSONL ledger
// ---------------------------------------------------------------------------

export function resolveGitState(repoRoot: string = REPO_ROOT): { gitSha: string; dirty: boolean } {
  let gitSha = 'unknown'
  let dirty = false
  try {
    gitSha = execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || 'unknown'
  } catch { /* non-git dir */ }
  try {
    const status = execFileSync('git', ['status', '--porcelain', '-uno'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    dirty = status.length > 0
  } catch { /* non-git dir */ }
  return { gitSha, dirty }
}

export interface LedgerRow {
  schemaVersion: typeof LEDGER_SCHEMA_VERSION
  recordedAt: string
  suite: BenchmarkSuiteName
  gitSha: string
  dirty: boolean
  benchmarkVersion: string
  effectiveConfigHash: string
  effectiveConfig?: EffectiveConfigSnapshot
  app: string
  split: 'dev' | 'held-out' | 'sealed'
  mode: string
  llm: 'agentic' | 'deterministic-no-llm'
  seed: number
  repeat: number
  certifying: boolean
  reportable: boolean
  status: 'VALID' | 'INVALID'
  targets: number
  confirmed: number
  recall: number | null
  rawPrecision: number | null
  strictPrecision: number | null
  precision: number | null
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  validUnplantedCount?: number
  costUsd: number
  durationMs?: number
  siteOutcomes?: Record<string, string>
  notes?: string[]
}

export function validateLedgerRow(row: LedgerRow): void {
  if (row.schemaVersion !== LEDGER_SCHEMA_VERSION) {
    throw new Error(`Unsupported ledger schemaVersion: ${String(row.schemaVersion)}`)
  }
  if (!row.suite || typeof row.suite !== 'string') throw new Error('LedgerRow.suite is required')
  if (!row.benchmarkVersion || !/^[0-9a-f]{16,64}$/i.test(row.benchmarkVersion)) {
    throw new Error(`LedgerRow.benchmarkVersion must be a hex hash (got '${String(row.benchmarkVersion)}')`)
  }
  if (!row.effectiveConfigHash || !/^[0-9a-f]{16,64}$/i.test(row.effectiveConfigHash)) {
    throw new Error(`LedgerRow.effectiveConfigHash must be a hex hash (got '${String(row.effectiveConfigHash)}')`)
  }
  if (!row.gitSha || typeof row.gitSha !== 'string') throw new Error('LedgerRow.gitSha is required')
  if (row.status !== 'VALID' && row.status !== 'INVALID') {
    throw new Error(`LedgerRow.status must be 'VALID' or 'INVALID' (got '${String(row.status)}')`)
  }
}

/** Append one validated row to the append-only JSONL ledger (default `benchmarks/results/ledger.jsonl`). */
export function appendLedgerRow(
  row: LedgerRow,
  ledgerPath: string = DEFAULT_LEDGER_PATH,
  repoRoot: string = REPO_ROOT,
): LedgerRow {
  validateLedgerRow(row)
  const abs = resolveRepoPath(ledgerPath, repoRoot)
  mkdirSync(dirname(abs), { recursive: true })
  appendFileSync(abs, `${JSON.stringify(row)}\n`, { encoding: 'utf8', mode: 0o644 })
  return row
}

/** Read all rows from a JSONL ledger file (returns `[]` if missing or empty). */
export function readLedgerRows(
  ledgerPath: string = DEFAULT_LEDGER_PATH,
  repoRoot: string = REPO_ROOT,
): LedgerRow[] {
  const abs = resolveRepoPath(ledgerPath, repoRoot)
  if (!existsSync(abs)) return []
  const raw = readFileSync(abs, 'utf8')
  const rows: LedgerRow[] = []
  const lines = raw.split(/\r?\n/)
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!.trim()
    if (!line || line.startsWith('#')) continue
    let parsed: unknown
    try {
      parsed = JSON.parse(line)
    } catch (err) {
      throw new Error(`Invalid JSON on line ${i + 1} of ${abs}: ${(err as Error).message}`)
    }
    const row = parsed as LedgerRow
    validateLedgerRow(row)
    rows.push(row)
  }
  return rows
}

export class LedgerComparisonError extends Error {
  readonly reason: 'suite_mismatch' | 'benchmark_version_mismatch' | 'effective_config_mismatch' | 'invalid_row'
  constructor(
    reason: 'suite_mismatch' | 'benchmark_version_mismatch' | 'effective_config_mismatch' | 'invalid_row',
    message: string,
  ) {
    super(message)
    this.name = 'LedgerComparisonError'
    this.reason = reason
  }
}

export interface LedgerComparison {
  suite: BenchmarkSuiteName
  benchmarkVersion: string
  effectiveConfigHash: string
  baselineSha: string
  candidateSha: string
  confirmedDelta: number
  targetsDelta: number
  recallDelta: number | null
  rawPrecisionDelta: number | null
  strictPrecisionDelta: number | null
  fpDelta: number
  costDeltaUsd: number
}

/**
 * Compare two ledger rows (baseline `a` -> candidate `b`).
 * Refuses to compare rows across mismatched `suite`, `benchmarkVersion`, or `effectiveConfigHash`,
 * or if either row has `status: 'INVALID'`.
 */
export function compareLedgerRows(a: LedgerRow, b: LedgerRow): LedgerComparison {
  if (a.status === 'INVALID' || b.status === 'INVALID') {
    throw new LedgerComparisonError(
      'invalid_row',
      `Refusing to compare INVALID ledger row(s): a=${a.status} (${a.gitSha}), b=${b.status} (${b.gitSha})`,
    )
  }
  if (a.suite !== b.suite) {
    throw new LedgerComparisonError(
      'suite_mismatch',
      `Refusing to compare rows from different suites: '${a.suite}' vs '${b.suite}'`,
    )
  }
  if (a.benchmarkVersion !== b.benchmarkVersion) {
    throw new LedgerComparisonError(
      'benchmark_version_mismatch',
      `Refusing to compare rows across mismatched benchmarkVersion: ${a.benchmarkVersion.slice(0, 12)} vs ${b.benchmarkVersion.slice(0, 12)}`,
    )
  }
  if (a.effectiveConfigHash !== b.effectiveConfigHash) {
    throw new LedgerComparisonError(
      'effective_config_mismatch',
      `Refusing to compare rows across mismatched effectiveConfigHash: ${a.effectiveConfigHash.slice(0, 12)} vs ${b.effectiveConfigHash.slice(0, 12)}`,
    )
  }

  const aFp = a.decoyFalsePositives + a.unmatchedFalsePositives
  const bFp = b.decoyFalsePositives + b.unmatchedFalsePositives
  return {
    suite: a.suite,
    benchmarkVersion: a.benchmarkVersion,
    effectiveConfigHash: a.effectiveConfigHash,
    baselineSha: a.gitSha,
    candidateSha: b.gitSha,
    confirmedDelta: b.confirmed - a.confirmed,
    targetsDelta: b.targets - a.targets,
    recallDelta: a.recall !== null && b.recall !== null ? b.recall - a.recall : null,
    rawPrecisionDelta:
      a.rawPrecision !== null && b.rawPrecision !== null ? b.rawPrecision - a.rawPrecision : null,
    strictPrecisionDelta:
      a.strictPrecision !== null && b.strictPrecision !== null
        ? b.strictPrecision - a.strictPrecision
        : null,
    fpDelta: bFp - aFp,
    costDeltaUsd: b.costUsd - a.costUsd,
  }
}
