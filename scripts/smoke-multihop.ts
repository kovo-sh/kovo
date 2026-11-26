#!/usr/bin/env node
// Kovo Hunter v8 — Multi-Hop Smoke Battery (Tier 0 + Tier 1).
//
// Tier 0 (< 90 s, $0):
//   Runs `scripts/worker-gate.sh` + v8 unit/chaos test suites
//   (capability-ledger, composite-receipt, derived-custody, oracle-families,
//    invariant-synthesizer, frontier-scheduler).
//
// Tier 1 (~10 min, ~$2, 3 cells):
//   1. Rotating dev archetype slice (`paygrid` | `shipforge` | `nexusiam`)
//      invoking `scripts/benchmark-multihop.ts`.
//   2. Hardened-twin precision trap cell (`--mode hardened-twin-trap`):
//      MUST confirm 0 findings (any confirmation = immediate FAIL).
//   3. Async-pivot / derived-crypto micro-slice.
//
// Defensive QA framing: measures multi-hop causal detection recall, precision,
// and efficiency against synthetic, authorized loopback lab targets only.

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const DEFAULT_DATA_DIR = process.env.KOVO_DATA_DIR || join(homedir(), 'guardian-data')
const DEFAULT_OUT_DIR = join(ROOT, '.kovo/smoke-multihop')

export const SMOKE_MULTIHOP_VERSION = 1
export const DEV_ARCHETYPES = ['paygrid', 'shipforge', 'nexusiam'] as const
export type DevArchetype = typeof DEV_ARCHETYPES[number]
export type ArchetypeSelector = DevArchetype | 'rotate'
export type SmokeTier = 0 | 1
export type SmokeMode = 'grey-box' | 'white-box'
export type CellMode = SmokeMode | 'hardened-twin-trap'

export const DEFAULT_BUDGET_USD_PER_CELL = 2.0
export const DEFAULT_MAX_DURATION_MS = 600_000
export const MAX_DEAD_END_WASTE_RATE = 0.05

export const V8_TIER0_TEST_FILES = [
  'tests/v8-capability-ledger.test.ts',
  'tests/v8-composite-receipt.test.ts',
  'tests/v8-derived-custody.test.ts',
  'tests/v8-oracle-families.test.ts',
  'tests/v8-invariant-synthesizer.test.ts',
  'tests/v8-frontier-scheduler.test.ts',
] as const

export const MICRO_SLICE_DEFAULT_ARCHETYPE: DevArchetype = 'paygrid'
export const MICRO_SLICE_SPEC = 'async-pivot,derived-crypto'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface V8SmokeArgs {
  repoRoot: string
  tier: SmokeTier
  archetype: ArchetypeSelector
  mode: SmokeMode
  budgetUsdPerCell: number
  maxDurationMs: number
  dryRun: boolean
  outDir: string
  dataDir: string
  json: boolean
  baseline?: string
  seed: number
  cellIndex: number
  skipWorkerGate: boolean
  help: boolean
}

export interface HopDepthFunnel {
  h1: number
  h2: number
  h3: number
  h4Plus: number
  finalOracle: number
  compositeReceiptConfirmed: number
}

export interface V8Tier0TestResult {
  file: string
  status: 'pass' | 'fail' | 'not-run'
  wallMs: number
  error?: string
}

export interface V8CellPlan {
  id: string
  kind: 'lift' | 'trap' | 'micro'
  archetype: DevArchetype
  mode: CellMode
  slice?: string
  outDir: string
  budgetUsd: number
  maxDurationMs: number
  command: string
  args: string[]
}

export interface V8CellMetrics {
  id: string
  kind: 'lift' | 'trap' | 'micro'
  archetype: DevArchetype
  mode: CellMode
  slice?: string
  targets: number
  confirmed: number
  precision: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  hopFunnel: HopDepthFunnel
  costUsd: number
  wallMs: number
  crashes: number
  workerFailures: number
  orphans: number
  /** Fraction in [0, 1] of assignments wasted re-probing pruned dead ends (cap <= 0.05). */
  deadEndReprobeWasteRate: number
  completedAssignments: number
  detail?: string
  error?: string
}

export interface V8GateResult {
  id: string
  label: string
  pass: boolean
  observed: string
}

export interface V8SmokeReport {
  version: number
  generatedAt: string
  executionMode: 'run' | 'dry-run'
  gitSha: string
  args: {
    tier: SmokeTier
    archetype: ArchetypeSelector
    resolvedArchetype: DevArchetype
    mode: SmokeMode
    seed: number
    cellIndex: number
    budgetUsdPerCell: number
    maxDurationMs: number
    outDir: string
    baselinePath: string | null
  }
  tier0: {
    workerGate: 'pass' | 'fail' | 'skipped' | 'not-run'
    v8Tests: V8Tier0TestResult[]
    pass: boolean
  }
  plannedCells: V8CellPlan[]
  cells: V8CellMetrics[]
  aggregateHopFunnel: HopDepthFunnel
  gates: V8GateResult[]
  totals: {
    confirmed: number
    trapConfirmed: number
    costUsd: number
    wallMs: number
    cells: number
    crashes: number
    workerFailures: number
    orphans: number
    maxDeadEndReprobeWasteRate: number
  }
  pass: boolean
  notes: string[]
}

export interface V8SmokeBaseline {
  aggregateHopFunnel?: HopDepthFunnelLike
  hopFunnel?: HopDepthFunnelLike
  cells?: Array<Pick<V8CellMetrics, 'id' | 'kind'> & { hopFunnel?: HopDepthFunnelLike }>
}

export interface V8SmokeGateReportInput {
  args?: {
    budgetUsdPerCell?: number
    maxDurationMs?: number
  }
  cells: V8CellMetrics[]
  aggregateHopFunnel?: HopDepthFunnel
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = `Kovo Hunter v8 — Multi-Hop Smoke Battery (defensive QA)

Usage:
  node scripts/smoke-multihop.ts [flags]

Tier 0 (< 90 s, $0):
  Runs scripts/worker-gate.sh + v8 unit/chaos test suites:
    - tests/v8-capability-ledger.test.ts
    - tests/v8-composite-receipt.test.ts
    - tests/v8-derived-custody.test.ts
    - tests/v8-oracle-families.test.ts
    - tests/v8-invariant-synthesizer.test.ts
    - tests/v8-frontier-scheduler.test.ts

Tier 1 (~10 min, ~$2/cell, 3 cells):
  1. archetype-lift      Rotating dev archetype (paygrid | shipforge | nexusiam)
                         via scripts/benchmark-multihop.ts.
  2. hardened-twin-trap  Hardened-twin precision trap (--mode hardened-twin-trap);
                         MUST confirm 0 findings (any confirmation = instant FAIL).
  3. async-crypto-micro  Async-pivot / derived-crypto micro-slice.

Flags:
  --tier <0|1>                     Battery tier to run (default 1; Tier 1 runs Tier 0 first)
  --archetype <paygrid|shipforge|nexusiam|rotate>
                                   Dev archetype or daily rotation (default rotate)
  --mode <grey-box|white-box>      Evaluation mode for lift & micro cells (default grey-box)
  --budget-usd-per-cell <n>        USD cap per Tier-1 cell (default 2.0)
  --max-duration-ms <n>            Wall-clock cap per Tier-1 cell in ms (default 600000)
  --dry-run                        Plan cells & print report; starts ZERO external processes
  --out-dir <path>                 Artifact directory (default .kovo/smoke-multihop)
  --data-dir <path>                Kovo Hunter model profile source dir (default $KOVO_DATA_DIR)
  --baseline <path>                Optional baseline JSON report for hop-funnel non-regression
  --seed <n>                       Deterministic dev seed (default 1)
  --cell-index <n>                 Explicit rotation index (default UTC day-of-year)
  --skip-worker-gate               Skip scripts/worker-gate.sh during Tier 0
  --json                           Emit full structured JSON report to stdout
  --help                           Show this help

Gates (Tier 1):
  - 100% precision on lift/micro cells AND 0 confirmed on hardened-twin trap
  - 0 crashes / worker failures / orphans
  - Hop-Depth Funnel non-regression (H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed)
  - Budget cap (<= $2.00 per cell) and dead-end re-probe waste (<= 5%)

Examples:
  node scripts/smoke-multihop.ts --dry-run
  node scripts/smoke-multihop.ts --dry-run --archetype shipforge --mode white-box --json
  node scripts/smoke-multihop.ts --tier 0
  node scripts/smoke-multihop.ts --tier 1 --archetype rotate --out-dir /tmp/v8-smoke
`

function fail(message: string): never {
  throw new Error(message)
}

function parseRawFlags(argv: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '-h') {
      flags.help = true
      continue
    }
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const body = arg.slice(2)
    if (!body) fail('empty flag')
    const eqIndex = body.indexOf('=')
    if (eqIndex !== -1) {
      const key = body.slice(0, eqIndex)
      const val = body.slice(eqIndex + 1)
      if (!key) fail('empty flag')
      flags[key] = val
      continue
    }
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--') || next === '-h') {
      flags[body] = true
    } else {
      flags[body] = next
      i += 1
    }
  }
  return flags
}

function strFlag(flags: Record<string, string | boolean>, key: string): string | undefined {
  const value = flags[key]
  return typeof value === 'string' ? value : undefined
}

function positiveInt(raw: string | undefined, flag: string, fallback: number): number {
  if (raw === undefined) return fallback
  const n = Number(raw)
  if (!Number.isInteger(n) || n <= 0) fail(`${flag} must be a positive integer (got '${raw}')`)
  return n
}

function nonNegativeInt(raw: string | undefined, flag: string, fallback: number): number {
  if (raw === undefined) return fallback
  const n = Number(raw)
  if (!Number.isInteger(n) || n < 0) fail(`${flag} must be a non-negative integer (got '${raw}')`)
  return n
}

function positiveFloat(raw: string | undefined, flag: string, fallback: number): number {
  if (raw === undefined) return fallback
  const n = Number(raw)
  if (!Number.isFinite(n) || n <= 0) fail(`${flag} must be a positive number (got '${raw}')`)
  return n
}

export function dayOfYearUtc(date: Date = new Date()): number {
  const start = Date.UTC(date.getUTCFullYear(), 0, 0)
  return Math.floor((date.getTime() - start) / 86_400_000)
}

export function resolveArchetype(
  selector: ArchetypeSelector,
  opts: { cellIndex?: number; date?: Date } = {},
): DevArchetype {
  if (selector !== 'rotate') return selector
  if (opts.cellIndex !== undefined && Number.isFinite(opts.cellIndex)) {
    const idx = Math.abs(Math.trunc(opts.cellIndex)) % DEV_ARCHETYPES.length
    return DEV_ARCHETYPES[idx]!
  }
  const day = dayOfYearUtc(opts.date)
  return DEV_ARCHETYPES[Math.abs(day) % DEV_ARCHETYPES.length]!
}

const KNOWN_FLAGS = new Set([
  'tier',
  'archetype',
  'mode',
  'budget-usd-per-cell',
  'max-duration-ms',
  'dry-run',
  'out-dir',
  'data-dir',
  'json',
  'baseline',
  'seed',
  'cell-index',
  'skip-worker-gate',
  'help',
])

export function parseV8SmokeArgs(argv: string[], now: Date = new Date()): V8SmokeArgs {
  const flags = parseRawFlags(argv)
  for (const key of Object.keys(flags)) {
    if (!KNOWN_FLAGS.has(key)) fail(`unknown flag --${key}`)
  }

  const defaultCellIndex = dayOfYearUtc(now)

  if (flags.help === true) {
    return {
      repoRoot: ROOT,
      tier: 1,
      archetype: 'rotate',
      mode: 'grey-box',
      budgetUsdPerCell: DEFAULT_BUDGET_USD_PER_CELL,
      maxDurationMs: DEFAULT_MAX_DURATION_MS,
      dryRun: false,
      outDir: DEFAULT_OUT_DIR,
      dataDir: DEFAULT_DATA_DIR,
      json: false,
      seed: 1,
      cellIndex: defaultCellIndex,
      skipWorkerGate: false,
      help: true,
    }
  }

  const tierRaw = strFlag(flags, 'tier') ?? '1'
  if (tierRaw !== '0' && tierRaw !== '1') {
    fail(`--tier must be 0 or 1 (got '${tierRaw}')`)
  }

  const archetypeRaw = strFlag(flags, 'archetype') ?? 'rotate'
  if (
    archetypeRaw !== 'rotate'
    && archetypeRaw !== 'paygrid'
    && archetypeRaw !== 'shipforge'
    && archetypeRaw !== 'nexusiam'
  ) {
    fail(`--archetype must be paygrid, shipforge, nexusiam, or rotate (got '${archetypeRaw}')`)
  }

  const modeRaw = strFlag(flags, 'mode') ?? 'grey-box'
  if (modeRaw !== 'grey-box' && modeRaw !== 'white-box') {
    fail(`--mode must be grey-box or white-box (got '${modeRaw}')`)
  }

  const outDirRaw = strFlag(flags, 'out-dir') ?? DEFAULT_OUT_DIR
  const outDir = isAbsolute(outDirRaw) ? outDirRaw : resolve(outDirRaw)

  const baselineRaw = strFlag(flags, 'baseline')
  const baseline = baselineRaw
    ? (isAbsolute(baselineRaw) ? baselineRaw : resolve(baselineRaw))
    : undefined

  return {
    repoRoot: ROOT,
    tier: Number(tierRaw) as SmokeTier,
    archetype: archetypeRaw,
    mode: modeRaw,
    budgetUsdPerCell: positiveFloat(strFlag(flags, 'budget-usd-per-cell'), '--budget-usd-per-cell', DEFAULT_BUDGET_USD_PER_CELL),
    maxDurationMs: positiveInt(strFlag(flags, 'max-duration-ms'), '--max-duration-ms', DEFAULT_MAX_DURATION_MS),
    dryRun: flags['dry-run'] === true,
    outDir,
    dataDir: strFlag(flags, 'data-dir') ?? DEFAULT_DATA_DIR,
    json: flags.json === true,
    baseline,
    seed: positiveInt(strFlag(flags, 'seed'), '--seed', 1),
    cellIndex: nonNegativeInt(strFlag(flags, 'cell-index'), '--cell-index', defaultCellIndex),
    skipWorkerGate: flags['skip-worker-gate'] === true,
    help: false,
  }
}

// ---------------------------------------------------------------------------
// Hop-Depth Funnel Helpers
// ---------------------------------------------------------------------------

export function emptyHopFunnel(): HopDepthFunnel {
  return {
    h1: 0,
    h2: 0,
    h3: 0,
    h4Plus: 0,
    finalOracle: 0,
    compositeReceiptConfirmed: 0,
  }
}

export type HopDepthFunnelLike = Partial<HopDepthFunnel> & {
  H1?: number
  H2?: number
  H3?: number
  H4Plus?: number
  FinalOracle?: number
  CompositeReceiptConfirmed?: number
}

export function normalizeHopFunnel(raw?: HopDepthFunnelLike | null): HopDepthFunnel {
  const pick = (a: unknown, b: unknown): number => {
    if (typeof a === 'number' && Number.isFinite(a)) return a
    if (typeof b === 'number' && Number.isFinite(b)) return b
    return 0
  }
  return {
    h1: pick(raw?.h1, raw?.H1),
    h2: pick(raw?.h2, raw?.H2),
    h3: pick(raw?.h3, raw?.H3),
    h4Plus: pick(raw?.h4Plus, raw?.H4Plus),
    finalOracle: pick(raw?.finalOracle, raw?.FinalOracle),
    compositeReceiptConfirmed: pick(raw?.compositeReceiptConfirmed, raw?.CompositeReceiptConfirmed),
  }
}

export function sumHopFunnels(funnels: readonly HopDepthFunnel[]): HopDepthFunnel {
  const total = emptyHopFunnel()
  for (const funnel of funnels) {
    total.h1 += funnel.h1
    total.h2 += funnel.h2
    total.h3 += funnel.h3
    total.h4Plus += funnel.h4Plus
    total.finalOracle += funnel.finalOracle
    total.compositeReceiptConfirmed += funnel.compositeReceiptConfirmed
  }
  return total
}

export function formatHopFunnelLong(funnel: HopDepthFunnel): string {
  return [
    `H1=${funnel.h1}`,
    `H2=${funnel.h2}`,
    `H3=${funnel.h3}`,
    `H4+=${funnel.h4Plus}`,
    `FinalOracle=${funnel.finalOracle}`,
    `CompositeReceiptConfirmed=${funnel.compositeReceiptConfirmed}`,
  ].join(' -> ')
}

export function formatHopFunnelCompact(funnel: HopDepthFunnel): string {
  return `${funnel.h1}/${funnel.h2}/${funnel.h3}/${funnel.h4Plus}/${funnel.finalOracle}/${funnel.compositeReceiptConfirmed}`
}

// ---------------------------------------------------------------------------
// Tier 1 Cell Planning
// ---------------------------------------------------------------------------

export function planTierOneCells(opts: V8SmokeArgs): V8CellPlan[] {
  const resolvedArchetype = resolveArchetype(opts.archetype, { cellIndex: opts.cellIndex })
  const liftOut = join(opts.outDir, 'cells', 'archetype-lift')
  const trapOut = join(opts.outDir, 'cells', 'hardened-twin-trap')
  const microOut = join(opts.outDir, 'cells', 'async-crypto-micro')
  const microArchetype = resolvedArchetype === 'nexusiam' ? MICRO_SLICE_DEFAULT_ARCHETYPE : resolvedArchetype

  return [
    {
      id: 'archetype-lift',
      kind: 'lift',
      archetype: resolvedArchetype,
      mode: opts.mode,
      outDir: liftOut,
      budgetUsd: opts.budgetUsdPerCell,
      maxDurationMs: opts.maxDurationMs,
      command: 'node',
      args: [
        'scripts/benchmark-multihop.ts',
        '--app', resolvedArchetype,
        '--seed', String(opts.seed),
        '--mode', opts.mode,
        '--budget-usd', String(opts.budgetUsdPerCell),
        '--max-duration-ms', String(opts.maxDurationMs),
        '--verifier', 'docker',
        '--out-dir', liftOut,
        '--data-dir', join(liftOut, 'data'),
      ],
    },
    {
      id: 'hardened-twin-trap',
      kind: 'trap',
      archetype: resolvedArchetype,
      mode: 'hardened-twin-trap',
      outDir: trapOut,
      budgetUsd: opts.budgetUsdPerCell,
      maxDurationMs: opts.maxDurationMs,
      command: 'node',
      args: [
        'scripts/benchmark-multihop.ts',
        '--app', resolvedArchetype,
        '--seed', String(opts.seed),
        '--mode', 'hardened-twin-trap',
        '--budget-usd', String(opts.budgetUsdPerCell),
        '--max-duration-ms', String(opts.maxDurationMs),
        '--verifier', 'docker',
        '--out-dir', trapOut,
        '--data-dir', join(trapOut, 'data'),
      ],
    },
    {
      id: 'async-crypto-micro',
      kind: 'micro',
      archetype: microArchetype,
      mode: opts.mode,
      slice: MICRO_SLICE_SPEC,
      outDir: microOut,
      budgetUsd: opts.budgetUsdPerCell,
      maxDurationMs: opts.maxDurationMs,
      command: 'node',
      args: [
        'scripts/benchmark-multihop.ts',
        '--app', microArchetype,
        '--seed', String(opts.seed),
        '--mode', opts.mode,
        '--slice', MICRO_SLICE_SPEC,
        '--budget-usd', String(opts.budgetUsdPerCell),
        '--max-duration-ms', String(opts.maxDurationMs),
        '--verifier', 'docker',
        '--out-dir', microOut,
        '--data-dir', join(microOut, 'data'),
      ],
    },
  ]
}

export function emptyCellMetrics(plan: V8CellPlan, extra: Partial<V8CellMetrics> = {}): V8CellMetrics {
  return {
    id: plan.id,
    kind: plan.kind,
    archetype: plan.archetype,
    mode: plan.mode,
    ...(plan.slice ? { slice: plan.slice } : {}),
    targets: 0,
    confirmed: 0,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    hopFunnel: emptyHopFunnel(),
    costUsd: 0,
    wallMs: 0,
    crashes: 0,
    workerFailures: 0,
    orphans: 0,
    deadEndReprobeWasteRate: 0,
    completedAssignments: 0,
    ...extra,
  }
}

// ---------------------------------------------------------------------------
// Pure Gate Evaluator
// ---------------------------------------------------------------------------

const pct = (value: number | null | undefined): string =>
  value === null || value === undefined || !Number.isFinite(value) ? 'n/a' : `${(value * 100).toFixed(1)}%`

const FUNNEL_STAGES: ReadonlyArray<{ key: keyof HopDepthFunnel; label: string }> = [
  { key: 'h1', label: 'H1' },
  { key: 'h2', label: 'H2' },
  { key: 'h3', label: 'H3' },
  { key: 'h4Plus', label: 'H4+' },
  { key: 'finalOracle', label: 'FinalOracle' },
  { key: 'compositeReceiptConfirmed', label: 'CompositeReceiptConfirmed' },
]

function resolveBaselineFunnel(baseline: V8SmokeBaseline | null | undefined): HopDepthFunnel | null {
  if (!baseline) return null
  if (baseline.aggregateHopFunnel) return normalizeHopFunnel(baseline.aggregateHopFunnel)
  if (baseline.hopFunnel) return normalizeHopFunnel(baseline.hopFunnel)
  if (Array.isArray(baseline.cells) && baseline.cells.length > 0) {
    const relevant = baseline.cells.filter(cell => cell.kind !== 'trap')
    return sumHopFunnels(relevant.map(cell => normalizeHopFunnel(cell.hopFunnel)))
  }
  return null
}

/**
 * Pure, deterministic gate evaluator for the v8 Multi-Hop Smoke Battery.
 *
 * Enforces:
 *   1. 100% precision on lift (and micro) cells (0 decoy/unmatched FPs)
 *   2. 0 confirmed findings on hardened-twin precision trap (any confirmation = instant FAIL)
 *   3. 0 crashes / worker failures / orphans (and zero cell errors)
 *   4. Hop-Depth Funnel non-regression (H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed)
 *   5. Budget cap (<= budgetUsdPerCell, default $2.00/cell)
 *   6. Dead-end re-probe waste (<= 5% per cell)
 */
export function evaluateV8SmokeGates(
  report: V8SmokeGateReportInput,
  baseline?: V8SmokeBaseline | null,
): V8GateResult[] {
  const cells = report.cells ?? []
  const liftCells = cells.filter(cell => cell.kind === 'lift')
  const precisionScopedCells = cells.filter(cell => cell.kind === 'lift' || cell.kind === 'micro')
  const trapCells = cells.filter(cell => cell.kind === 'trap')
  const budgetCap = report.args?.budgetUsdPerCell ?? DEFAULT_BUDGET_USD_PER_CELL

  const gates: V8GateResult[] = []

  // Gate 1: 100% precision on lift (and micro) cells
  const precisionFailures = precisionScopedCells.filter(cell =>
    cell.error !== undefined
    || !Number.isFinite(cell.precision)
    || cell.precision !== 1
    || cell.decoyFalsePositives > 0
    || cell.unmatchedFalsePositives > 0,
  )
  gates.push({
    id: 'precision-lift',
    label: '100% precision on lift cell (0 decoy/unmatched FPs)',
    pass: liftCells.length > 0 && precisionFailures.length === 0,
    observed: liftCells.length === 0
      ? 'no lift cell measured'
      : precisionFailures.length === 0
        ? precisionScopedCells.map(cell => `${cell.id}=${pct(cell.precision)}`).join(', ')
        : `fail: ${precisionFailures.map(cell =>
            `${cell.id}(prec=${pct(cell.precision)},decoyFP=${cell.decoyFalsePositives},unmatchedFP=${cell.unmatchedFalsePositives}${cell.error ? `,err=${cell.error}` : ''})`,
          ).join(', ')}`,
  })

  // Gate 2: Hardened-twin precision trap MUST confirm 0 findings
  const trapConfirmed = trapCells.reduce((sum, cell) => sum + cell.confirmed, 0)
  const trapFp = trapCells.reduce(
    (sum, cell) => sum + cell.decoyFalsePositives + cell.unmatchedFalsePositives,
    0,
  )
  const trapErrors = trapCells.filter(cell => cell.error !== undefined)
  const trapPass = trapCells.length > 0 && trapConfirmed === 0 && trapFp === 0 && trapErrors.length === 0
  gates.push({
    id: 'hardened-twin-trap-zero',
    label: '0 confirmed findings on hardened-twin precision trap',
    pass: trapPass,
    observed: trapCells.length === 0
      ? 'no hardened-twin trap cell measured'
      : trapPass
        ? `0 confirmed across ${trapCells.length} trap cell(s)`
        : `INSTANT FAIL: confirmed=${trapConfirmed}, fp=${trapFp}${trapErrors.length ? `, errors=${trapErrors.map(cell => cell.id).join(',')}` : ''}`,
  })

  // Gate 3: 0 crashes / worker failures / orphans
  const totalCrashes = cells.reduce((sum, cell) => sum + cell.crashes, 0)
  const totalWorkerFailures = cells.reduce((sum, cell) => sum + cell.workerFailures, 0)
  const totalOrphans = cells.reduce((sum, cell) => sum + cell.orphans, 0)
  const erroredCells = cells.filter(cell => cell.error !== undefined)
  const reliabilityPass = cells.length > 0
    && totalCrashes === 0
    && totalWorkerFailures === 0
    && totalOrphans === 0
    && erroredCells.length === 0
  gates.push({
    id: 'zero-crashes-failures-orphans',
    label: '0 crashes / worker failures / orphans',
    pass: reliabilityPass,
    observed: cells.length === 0
      ? 'no cells measured'
      : reliabilityPass
        ? '0 crashes, 0 worker failures, 0 orphans'
        : `crashes=${totalCrashes}, workerFailures=${totalWorkerFailures}, orphans=${totalOrphans}${erroredCells.length ? `, cellErrors=${erroredCells.map(cell => cell.id).join(',')}` : ''}`,
  })

  // Gate 4: Hop-Depth Funnel non-regression
  const observedFunnel = report.aggregateHopFunnel
    ? normalizeHopFunnel(report.aggregateHopFunnel)
    : sumHopFunnels(precisionScopedCells.map(cell => normalizeHopFunnel(cell.hopFunnel)))
  const baselineFunnel = resolveBaselineFunnel(baseline)
  const invalidFunnelStage = FUNNEL_STAGES.find(({ key }) => {
    const val = observedFunnel[key]
    return !Number.isFinite(val) || val < 0
  })
  const twoSideInvalid = observedFunnel.compositeReceiptConfirmed > observedFunnel.finalOracle
  const regressions: string[] = []
  if (baselineFunnel) {
    for (const { key, label } of FUNNEL_STAGES) {
      if (observedFunnel[key] < baselineFunnel[key]) {
        regressions.push(`${label} ${observedFunnel[key]}<${baselineFunnel[key]}`)
      }
    }
  }
  const funnelPass = cells.length > 0 && !invalidFunnelStage && !twoSideInvalid && regressions.length === 0
  gates.push({
    id: 'hop-funnel-non-regression',
    label: 'Hop-Depth Funnel non-regression (H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed)',
    pass: funnelPass,
    observed: cells.length === 0
      ? 'no cells measured'
      : invalidFunnelStage
        ? `invalid stage count: ${invalidFunnelStage.label}`
        : twoSideInvalid
          ? `two-side violation: CompositeReceiptConfirmed (${observedFunnel.compositeReceiptConfirmed}) > FinalOracle (${observedFunnel.finalOracle})`
          : regressions.length > 0
            ? `regression: ${regressions.join(', ')}`
            : baselineFunnel
              ? `ok vs baseline (${formatHopFunnelLong(observedFunnel)})`
              : `no baseline (${formatHopFunnelLong(observedFunnel)})`,
  })

  // Gate 5: Budget cap (<= budgetUsdPerCell per cell)
  const overBudget = cells.filter(cell => !Number.isFinite(cell.costUsd) || cell.costUsd < 0 || cell.costUsd > budgetCap)
  const totalCost = cells.reduce((sum, cell) => sum + (Number.isFinite(cell.costUsd) ? cell.costUsd : 0), 0)
  gates.push({
    id: 'budget-cap',
    label: `budget cap <= $${budgetCap.toFixed(2)} per cell`,
    pass: cells.length > 0 && overBudget.length === 0,
    observed: cells.length === 0
      ? 'no cells measured'
      : overBudget.length === 0
        ? `total $${totalCost.toFixed(4)} (max $${Math.max(...cells.map(cell => cell.costUsd)).toFixed(4)}/cell)`
        : `over cap: ${overBudget.map(cell => `${cell.id}=$${cell.costUsd.toFixed(3)}`).join(', ')}`,
  })

  // Gate 6: Dead-end re-probe waste (<= 5%)
  const highWaste = cells.filter(cell =>
    !Number.isFinite(cell.deadEndReprobeWasteRate)
    || cell.deadEndReprobeWasteRate < 0
    || cell.deadEndReprobeWasteRate > MAX_DEAD_END_WASTE_RATE,
  )
  const maxWaste = cells.length > 0
    ? Math.max(...cells.map(cell => (Number.isFinite(cell.deadEndReprobeWasteRate) ? cell.deadEndReprobeWasteRate : 1)))
    : 0
  gates.push({
    id: 'dead-end-reprobe-waste',
    label: `dead-end re-probe waste <= ${(MAX_DEAD_END_WASTE_RATE * 100).toFixed(0)}%`,
    pass: cells.length > 0 && highWaste.length === 0,
    observed: cells.length === 0
      ? 'no cells measured'
      : highWaste.length === 0
        ? `max ${pct(maxWaste)} across ${cells.length} cell(s)`
        : `over cap: ${highWaste.map(cell => `${cell.id}=${pct(cell.deadEndReprobeWasteRate)}`).join(', ')}`,
  })

  return gates
}

// ---------------------------------------------------------------------------
// Artifact / Structured Telemetry Readers (never dump raw HTTP bodies)
// ---------------------------------------------------------------------------

interface MultihopScorecardLike {
  app?: string
  archetype?: string
  mode?: string
  targets?: number
  totalChains?: number
  chainsTotal?: number
  confirmed?: number
  confirmedChains?: number
  chainsConfirmed?: number
  chainsCompositeConfirmed?: number
  precision?: number
  decoyFalsePositives?: number
  hardenedTwinDecoyFps?: number
  hardenedTwinFalsePositives?: number
  unmatchedFalsePositives?: number
  totalCostUsd?: number
  costUsd?: number
  crashes?: number
  workerFailures?: number
  orphans?: number
  deadEndReprobeWasteRate?: number
  completedAssignments?: number
  hopFunnel?: HopDepthFunnelLike
  funnel?: HopDepthFunnelLike
}

export function readJson<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as T
  } catch {
    return null
  }
}

export function loadBaseline(path: string | undefined): V8SmokeBaseline | null {
  if (!path) return null
  const parsed = readJson<V8SmokeBaseline>(path)
  if (!parsed) fail(`could not read baseline JSON at ${path}`)
  return parsed
}

export function countLogCrashes(text: string): number {
  const patterns = [
    /\brpc\b[^\n]{0,40}\b(?:fail(?:ed|ure)?|error|crash(?:ed|es)?|timeout)\b/gi,
    /\bsandbox\b[^\n]{0,40}\b(?:fail(?:ed|ure)?|error|crash(?:ed|es)?|died)\b/gi,
    /\bworker backend\b[^\n]{0,40}\b(?:fail(?:ed|ure)?|error|unavailable)\b/gi,
  ]
  let count = 0
  for (const pattern of patterns) count += (text.match(pattern) ?? []).length
  return count
}

function readDbSummary(dbPath: string): {
  spentUsd: number
  completedAssignments: number
  failedAssignments: number
  orphanAssignments: number
} {
  if (!existsSync(dbPath)) {
    return { spentUsd: 0, completedAssignments: 0, failedAssignments: 0, orphanAssignments: 0 }
  }
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    const runRow = db.prepare('select spent_usd from runs order by rowid desc limit 1')
      .get() as { spent_usd?: number } | undefined
    const completeRow = db.prepare("select count(*) as n from assignments where status = 'complete'")
      .get() as { n?: number } | undefined
    const failedRow = db.prepare("select count(*) as n from assignments where status = 'failed'")
      .get() as { n?: number } | undefined
    const orphanRow = db.prepare("select count(*) as n from assignments where status in ('running', 'queued')")
      .get() as { n?: number } | undefined
    return {
      spentUsd: Number(runRow?.spent_usd ?? 0),
      completedAssignments: Number(completeRow?.n ?? 0),
      failedAssignments: Number(failedRow?.n ?? 0),
      orphanAssignments: Number(orphanRow?.n ?? 0),
    }
  } catch {
    return { spentUsd: 0, completedAssignments: 0, failedAssignments: 0, orphanAssignments: 0 }
  } finally {
    try { db?.close() } catch { /* best-effort */ }
  }
}

/** Pure filesystem git SHA reader — spawns zero external processes (safe for --dry-run). */
export function readGitShaNoSpawn(repoRoot: string = ROOT): string {
  try {
    const dotGit = join(repoRoot, '.git')
    if (!existsSync(dotGit)) return 'unknown'
    let gitDir = dotGit
    const headOrPointer = readFileSync(dotGit, 'utf8').trim()
    if (headOrPointer.startsWith('gitdir:')) {
      const target = headOrPointer.slice('gitdir:'.length).trim()
      gitDir = isAbsolute(target) ? target : resolve(repoRoot, target)
    }
    const headRaw = readFileSync(join(gitDir, 'HEAD'), 'utf8').trim()
    if (!headRaw.startsWith('ref:')) return headRaw.slice(0, 12) || 'unknown'
    const refPath = headRaw.slice('ref:'.length).trim()
    const directRef = join(gitDir, refPath)
    if (existsSync(directRef)) return readFileSync(directRef, 'utf8').trim().slice(0, 12) || 'unknown'
    // Worktree commondir fallback for packed-refs / shared refs.
    const commonDirFile = join(gitDir, 'commondir')
    const commonDir = existsSync(commonDirFile)
      ? resolve(gitDir, readFileSync(commonDirFile, 'utf8').trim())
      : gitDir
    const sharedRef = join(commonDir, refPath)
    if (existsSync(sharedRef)) return readFileSync(sharedRef, 'utf8').trim().slice(0, 12) || 'unknown'
    const packedPath = join(commonDir, 'packed-refs')
    if (existsSync(packedPath)) {
      for (const line of readFileSync(packedPath, 'utf8').split('\n')) {
        if (!line || line.startsWith('#') || line.startsWith('^')) continue
        const [sha, name] = line.trim().split(/\s+/)
        if (name === refPath && sha) return sha.slice(0, 12)
      }
    }
    return 'unknown'
  } catch {
    return 'unknown'
  }
}

// ---------------------------------------------------------------------------
// Process Execution (ONLY invoked when !opts.dryRun)
// ---------------------------------------------------------------------------

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function dockerUsable(): boolean {
  const probe = spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 10_000 })
  return probe.status === 0
}

interface SpawnOutcome {
  code: number | null
  wallMs: number
  logPath: string
  timedOut: boolean
}

async function spawnLogged(input: {
  command: string
  args: string[]
  cwd: string
  env: NodeJS.ProcessEnv
  logPath: string
  docker: boolean
  killAfterMs: number
}): Promise<SpawnOutcome> {
  mkdirSync(dirname(input.logPath), { recursive: true, mode: 0o700 })
  const started = Date.now()
  const direct = [input.command, ...input.args].map(shellQuote).join(' ')
  const shellCommand = `cd ${shellQuote(input.cwd)} && ${direct}`
  const useNewgrp = input.docker && !dockerUsable()
  const command = useNewgrp ? 'newgrp' : '/bin/bash'
  const args = useNewgrp ? ['docker', '-c', shellCommand] : ['-lc', shellCommand]
  let timedOut = false

  const code = await new Promise<number | null>((resolvePromise) => {
    const child = spawn(command, args, {
      cwd: input.cwd,
      env: input.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    })
    let output = ''
    const cap = 200_000
    const absorb = (chunk: Buffer) => {
      if (output.length < cap) output += chunk.toString('utf8')
    }
    child.stdout.on('data', absorb)
    child.stderr.on('data', absorb)
    const killGroup = (signal: NodeJS.Signals) => {
      try {
        if (child.pid) process.kill(-child.pid, signal)
      } catch {
        try { child.kill(signal) } catch { /* already exited */ }
      }
    }
    let hardKill: ReturnType<typeof setTimeout> | undefined
    const grace = setTimeout(() => {
      timedOut = true
      absorb(Buffer.from('\n[smoke-multihop] hard stop: child exceeded wall budget; terminating process group\n'))
      killGroup('SIGTERM')
      hardKill = setTimeout(() => killGroup('SIGKILL'), 8_000)
    }, input.killAfterMs)
    grace.unref?.()

    child.on('error', (error) => {
      output += `\n[spawn error] ${error.message}\n`
      clearTimeout(grace)
      if (hardKill) clearTimeout(hardKill)
      writeFileSync(input.logPath, output, { mode: 0o600 })
      resolvePromise(127)
    })
    child.on('close', (exitCode) => {
      clearTimeout(grace)
      if (hardKill) clearTimeout(hardKill)
      writeFileSync(input.logPath, output, { mode: 0o600 })
      resolvePromise(exitCode)
    })
  })

  return { code, wallMs: Date.now() - started, logPath: input.logPath, timedOut }
}

// ---------------------------------------------------------------------------
// Tier 0 & Tier 1 Runners
// ---------------------------------------------------------------------------

async function runTierZero(opts: V8SmokeArgs, report: V8SmokeReport): Promise<void> {
  if (opts.dryRun) {
    report.tier0 = {
      workerGate: 'not-run',
      v8Tests: V8_TIER0_TEST_FILES.map(file => ({ file, status: 'not-run', wallMs: 0 })),
      pass: true,
    }
    return
  }

  let allOk = true
  if (opts.skipWorkerGate) {
    report.tier0.workerGate = 'skipped'
  } else {
    const wgResult = await spawnLogged({
      command: 'bash',
      args: ['scripts/worker-gate.sh'],
      cwd: opts.repoRoot,
      env: process.env,
      logPath: join(opts.outDir, 'tier0-worker-gate.log'),
      docker: false,
      killAfterMs: 300_000,
    })
    const ok = wgResult.code === 0 && !wgResult.timedOut
    report.tier0.workerGate = ok ? 'pass' : 'fail'
    if (!ok) {
      allOk = false
      report.notes.push(`Tier 0 worker-gate failed (exit=${wgResult.code ?? 'null'})`)
    }
  }

  const testResults: V8Tier0TestResult[] = []
  for (const file of V8_TIER0_TEST_FILES) {
    const absPath = join(opts.repoRoot, file)
    if (!existsSync(absPath)) {
      testResults.push({ file, status: 'fail', wallMs: 0, error: 'test file missing' })
      allOk = false
      report.notes.push(`Tier 0 missing test file: ${file}`)
      continue
    }
    const slug = file.replace(/[^a-z0-9_.-]+/gi, '-')
    const outcome = await spawnLogged({
      command: process.execPath,
      args: ['--test', file],
      cwd: opts.repoRoot,
      env: process.env,
      logPath: join(opts.outDir, `tier0-${slug}.log`),
      docker: false,
      killAfterMs: 120_000,
    })
    const ok = outcome.code === 0 && !outcome.timedOut
    testResults.push({
      file,
      status: ok ? 'pass' : 'fail',
      wallMs: outcome.wallMs,
      ...(ok ? {} : { error: `exit ${outcome.code ?? 'null'}` }),
    })
    if (!ok) {
      allOk = false
      report.notes.push(`Tier 0 test failed: ${file} (exit=${outcome.code ?? 'null'})`)
    }
  }

  report.tier0.v8Tests = testResults
  report.tier0.pass = allOk
}

function findCellScorecard(plan: V8CellPlan, seed: number): MultihopScorecardLike | null {
  const candidates = [
    join(plan.outDir, `${plan.archetype}-seed${seed}-${plan.mode}.json`),
    join(plan.outDir, `${plan.archetype}-${plan.mode}.json`),
    join(plan.outDir, 'scorecard.json'),
    join(plan.outDir, 'report.json'),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      const parsed = readJson<MultihopScorecardLike>(candidate)
      if (parsed) return parsed
    }
  }
  return null
}

async function runTierOneCell(plan: V8CellPlan, opts: V8SmokeArgs): Promise<V8CellMetrics> {
  mkdirSync(plan.outDir, { recursive: true, mode: 0o700 })
  const harnessPath = join(opts.repoRoot, 'scripts/benchmark-multihop.ts')
  if (!existsSync(harnessPath)) {
    return emptyCellMetrics(plan, {
      error: 'scripts/benchmark-multihop.ts not found in repo',
      detail: 'install/merge v8 multihop harness before running live Tier 1',
    })
  }

  const logPath = join(plan.outDir, 'run.log')
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    KOVO_ALLOW_LOCAL_LAB: '1',
    KOVO_DATA_DIR: opts.dataDir,
  }
  const outcome = await spawnLogged({
    command: plan.command,
    args: plan.args,
    cwd: opts.repoRoot,
    env,
    logPath,
    docker: true,
    killAfterMs: plan.maxDurationMs + 120_000,
  })

  const scorecard = findCellScorecard(plan, opts.seed)
  const dbPath = join(plan.outDir, 'data', 'kovo.sqlite')
  const dbSummary = readDbSummary(dbPath)
  const logText = existsSync(logPath) ? readFileSync(logPath, 'utf8') : ''

  const confirmed = scorecard?.confirmed
    ?? scorecard?.chainsConfirmed
    ?? scorecard?.confirmedChains
    ?? scorecard?.chainsCompositeConfirmed
    ?? 0
  const targets = scorecard?.targets ?? scorecard?.chainsTotal ?? scorecard?.totalChains ?? 0
  const decoyFp = scorecard?.hardenedTwinDecoyFps
    ?? scorecard?.decoyFalsePositives
    ?? scorecard?.hardenedTwinFalsePositives
    ?? 0
  const unmatchedFp = scorecard?.unmatchedFalsePositives ?? 0
  const precision = scorecard?.precision
    ?? (confirmed + decoyFp + unmatchedFp > 0
      ? confirmed / (confirmed + decoyFp + unmatchedFp)
      : (plan.kind === 'trap' ? (confirmed === 0 ? 1 : 0) : 1))
  const hopFunnel = normalizeHopFunnel(scorecard?.hopFunnel ?? scorecard?.funnel)
  const crashes = (scorecard?.crashes ?? 0) + countLogCrashes(logText)
  const workerFailures = scorecard?.workerFailures ?? dbSummary.failedAssignments
  const orphans = scorecard?.orphans ?? dbSummary.orphanAssignments
  const costUsd = scorecard?.totalCostUsd ?? scorecard?.costUsd ?? dbSummary.spentUsd
  const waste = scorecard?.deadEndReprobeWasteRate ?? 0
  const completedAssignments = scorecard?.completedAssignments ?? dbSummary.completedAssignments

  const cellError = outcome.timedOut && !scorecard
    ? `timed out after ${plan.maxDurationMs} ms`
    : (outcome.code !== 0 && !scorecard ? `harness exit ${outcome.code ?? 'null'}` : undefined)

  return {
    id: plan.id,
    kind: plan.kind,
    archetype: plan.archetype,
    mode: plan.mode,
    ...(plan.slice ? { slice: plan.slice } : {}),
    targets,
    confirmed,
    precision,
    decoyFalsePositives: decoyFp,
    unmatchedFalsePositives: unmatchedFp,
    hopFunnel,
    costUsd,
    wallMs: outcome.wallMs,
    crashes,
    workerFailures,
    orphans,
    deadEndReprobeWasteRate: waste,
    completedAssignments,
    ...(cellError ? { error: cellError } : {}),
  }
}

async function runTierOne(
  opts: V8SmokeArgs,
  report: V8SmokeReport,
  baseline: V8SmokeBaseline | null,
): Promise<void> {
  const plans = report.plannedCells
  const cells = await Promise.all(plans.map(plan => runTierOneCell(plan, opts)))
  finalizeTierOneMetrics(report, cells, baseline)
}

function finalizeTierOneMetrics(
  report: V8SmokeReport,
  cells: V8CellMetrics[],
  baseline: V8SmokeBaseline | null,
): void {
  report.cells = cells
  const nonTrapCells = cells.filter(cell => cell.kind !== 'trap')
  report.aggregateHopFunnel = sumHopFunnels(nonTrapCells.map(cell => cell.hopFunnel))
  report.gates = evaluateV8SmokeGates(report, baseline)
  const trapConfirmed = cells
    .filter(cell => cell.kind === 'trap')
    .reduce((sum, cell) => sum + cell.confirmed, 0)
  report.totals = {
    confirmed: nonTrapCells.reduce((sum, cell) => sum + cell.confirmed, 0),
    trapConfirmed,
    costUsd: cells.reduce((sum, cell) => sum + cell.costUsd, 0),
    wallMs: cells.length > 0 ? Math.max(...cells.map(cell => cell.wallMs)) : 0,
    cells: cells.length,
    crashes: cells.reduce((sum, cell) => sum + cell.crashes, 0),
    workerFailures: cells.reduce((sum, cell) => sum + cell.workerFailures, 0),
    orphans: cells.reduce((sum, cell) => sum + cell.orphans, 0),
    maxDeadEndReprobeWasteRate: cells.length > 0
      ? Math.max(...cells.map(cell => cell.deadEndReprobeWasteRate))
      : 0,
  }
  for (const cell of cells) {
    if (cell.error) report.notes.push(`${cell.id}: ${cell.error}`)
  }
}

// ---------------------------------------------------------------------------
// Compact ASCII & Markdown Rendering
// ---------------------------------------------------------------------------

export function renderV8CompactTable(cells: readonly V8CellMetrics[]): string {
  const header = [
    'cell',
    'archetype',
    'mode',
    'conf/tgt',
    'prec',
    'fp(d/u)',
    'funnel(H1/H2/H3/H4+/O/C)',
    'waste',
    'err(c/f/o)',
    'cost',
    'wall',
  ]
  const rows = cells.map(cell => [
    cell.id,
    cell.archetype,
    cell.slice ? `${cell.mode}[${cell.slice}]` : cell.mode,
    `${cell.confirmed}/${cell.targets}`,
    pct(cell.precision),
    `${cell.decoyFalsePositives}/${cell.unmatchedFalsePositives}`,
    formatHopFunnelCompact(cell.hopFunnel),
    pct(cell.deadEndReprobeWasteRate),
    `${cell.crashes}/${cell.workerFailures}/${cell.orphans}`,
    `$${cell.costUsd.toFixed(3)}`,
    `${Math.round(cell.wallMs / 1000)}s`,
  ])
  const widths = header.map((title, i) => Math.max(title.length, ...rows.map(row => (row[i] ?? '').length)))
  const fmt = (row: string[]) => row.map((value, i) => value.padEnd(widths[i]!)).join('  ')
  return [
    fmt(header),
    widths.map(width => '-'.repeat(width)).join('  '),
    ...rows.map(fmt),
  ].join('\n')
}

export function renderV8MarkdownSummary(report: V8SmokeReport): string {
  const lines: string[] = [
    `# Kovo Hunter v8 Multi-Hop Smoke Battery (${report.executionMode})`,
    '',
    `- **Git SHA:** \`${report.gitSha}\``,
    `- **Tier:** \`${report.args.tier}\` | **Archetype:** \`${report.args.resolvedArchetype}\` (selector: \`${report.args.archetype}\`) | **Mode:** \`${report.args.mode}\``,
    `- **Budget Cap:** \`$${report.args.budgetUsdPerCell.toFixed(2)}/cell\` | **Max Duration:** \`${Math.round(report.args.maxDurationMs / 1000)}s/cell\``,
    `- **Tier 0:** worker-gate=\`${report.tier0.workerGate}\`, v8-tests=\`${report.tier0.v8Tests.filter(t => t.status === 'pass').length}/${report.tier0.v8Tests.length}\`, pass=\`${report.tier0.pass}\``,
    '',
  ]

  if (report.cells.length > 0) {
    lines.push('## Tier 1 Cells', '')
    lines.push('| Cell | Archetype | Mode | Confirmed | Precision | FP (decoy/unmatched) | Hop Funnel (H1/H2/H3/H4+/O/C) | Waste | Crashes/Fail/Orph | Cost |')
    lines.push('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')
    for (const cell of report.cells) {
      const modeLabel = cell.slice ? `${cell.mode} (${cell.slice})` : cell.mode
      lines.push(
        `| \`${cell.id}\` | \`${cell.archetype}\` | \`${modeLabel}\` | ${cell.confirmed}/${cell.targets} | ${pct(cell.precision)} | ${cell.decoyFalsePositives}/${cell.unmatchedFalsePositives} | \`${formatHopFunnelCompact(cell.hopFunnel)}\` | ${pct(cell.deadEndReprobeWasteRate)} | ${cell.crashes}/${cell.workerFailures}/${cell.orphans} | $${cell.costUsd.toFixed(3)} |`,
      )
    }
    lines.push('')
    lines.push(`**Aggregate Hop-Depth Funnel:** \`${formatHopFunnelLong(report.aggregateHopFunnel)}\``)
    lines.push('')
  }

  if (report.gates.length > 0) {
    lines.push('## Gates', '')
    lines.push('| Status | Gate | Observed |')
    lines.push('| --- | --- | --- |')
    for (const gate of report.gates) {
      lines.push(`| ${gate.pass ? 'PASS' : 'FAIL'} | \`${gate.id}\` | ${gate.observed} |`)
    }
    lines.push('')
  }

  if (report.notes.length > 0) {
    lines.push('## Notes', '')
    for (const note of report.notes) lines.push(`- ${note}`)
    lines.push('')
  }

  return `${lines.join('\n')}\n`
}

function printTextReport(report: V8SmokeReport): void {
  process.stdout.write(
    `smoke-multihop v${report.version} [${report.executionMode}] git=${report.gitSha} `
    + `tier=${report.args.tier} archetype=${report.args.resolvedArchetype} mode=${report.args.mode}\n`,
  )
  process.stdout.write(
    `tier0: worker-gate=${report.tier0.workerGate} `
    + `v8-tests=${report.tier0.v8Tests.filter(t => t.status === 'pass').length}/${report.tier0.v8Tests.length} `
    + `pass=${report.tier0.pass ? 'PASS' : 'FAIL'}\n`,
  )
  for (const testItem of report.tier0.v8Tests) {
    process.stdout.write(`  ${testItem.status.padEnd(7)}  ${testItem.file}\n`)
  }
  if (report.cells.length > 0) {
    process.stdout.write('\n')
    process.stdout.write(`${renderV8CompactTable(report.cells)}\n`)
    process.stdout.write(`\nhop-funnel: ${formatHopFunnelLong(report.aggregateHopFunnel)}\n`)
  }
  if (report.gates.length > 0) {
    process.stdout.write('\n')
    for (const gate of report.gates) {
      process.stdout.write(`${gate.pass ? 'PASS' : 'FAIL'}  ${gate.id.padEnd(28)} ${gate.observed}\n`)
    }
    process.stdout.write(
      `\ntotals: confirmed=${report.totals.confirmed}, trapConfirmed=${report.totals.trapConfirmed}, `
      + `cost=$${report.totals.costUsd.toFixed(4)}, maxWaste=${pct(report.totals.maxDeadEndReprobeWasteRate)}\n`,
    )
  }
  if (report.notes.length > 0) {
    process.stdout.write('\nnotes:\n')
    for (const note of report.notes) process.stdout.write(`  - ${note}\n`)
  }
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

function buildEmptyReport(opts: V8SmokeArgs, resolvedArchetype: DevArchetype): V8SmokeReport {
  return {
    version: SMOKE_MULTIHOP_VERSION,
    generatedAt: new Date().toISOString(),
    executionMode: opts.dryRun ? 'dry-run' : 'run',
    gitSha: readGitShaNoSpawn(opts.repoRoot),
    args: {
      tier: opts.tier,
      archetype: opts.archetype,
      resolvedArchetype,
      mode: opts.mode,
      seed: opts.seed,
      cellIndex: opts.cellIndex,
      budgetUsdPerCell: opts.budgetUsdPerCell,
      maxDurationMs: opts.maxDurationMs,
      outDir: opts.outDir,
      baselinePath: opts.baseline ?? null,
    },
    tier0: {
      workerGate: 'not-run',
      v8Tests: [],
      pass: false,
    },
    plannedCells: [],
    cells: [],
    aggregateHopFunnel: emptyHopFunnel(),
    gates: [],
    totals: {
      confirmed: 0,
      trapConfirmed: 0,
      costUsd: 0,
      wallMs: 0,
      cells: 0,
      crashes: 0,
      workerFailures: 0,
      orphans: 0,
      maxDeadEndReprobeWasteRate: 0,
    },
    pass: false,
    notes: [],
  }
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const opts = parseV8SmokeArgs(argv)
  if (opts.help) {
    process.stdout.write(USAGE)
    return 0
  }

  const baseline = loadBaseline(opts.baseline)
  const resolvedArchetype = resolveArchetype(opts.archetype, { cellIndex: opts.cellIndex })
  const report = buildEmptyReport(opts, resolvedArchetype)
  report.plannedCells = opts.tier === 1 ? planTierOneCells(opts) : []

  if (opts.dryRun) {
    await runTierZero(opts, report)
    report.cells = report.plannedCells.map(plan => emptyCellMetrics(plan))
    report.aggregateHopFunnel = emptyHopFunnel()
    report.totals.cells = report.cells.length
    report.pass = true
    report.notes.push('dry-run: zero external processes were started')
    if (opts.json) {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
    } else {
      printTextReport(report)
    }
    return 0
  }

  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  mkdirSync(opts.outDir, { recursive: true, mode: 0o700 })

  await runTierZero(opts, report)

  if (opts.tier === 1) {
    await runTierOne(opts, report, baseline)
  }

  const tier0Ok = report.tier0.pass
  const tier1Ok = opts.tier === 0 || (report.gates.length > 0 && report.gates.every(gate => gate.pass))
  report.pass = tier0Ok && tier1Ok

  writeFileSync(
    join(opts.outDir, 'smoke-multihop-report.json'),
    `${JSON.stringify(report, null, 2)}\n`,
    { mode: 0o600 },
  )
  writeFileSync(
    join(opts.outDir, 'smoke-multihop-summary.md'),
    renderV8MarkdownSummary(report),
    { mode: 0o600 },
  )

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  } else {
    printTextReport(report)
  }

  return report.pass ? 0 : 1
}

const invokedDirectly = Boolean(process.argv[1]) && resolve(process.argv[1]!) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  main()
    .then(code => { process.exitCode = code })
    .catch(error => {
      process.stderr.write(`smoke-multihop: ${error instanceof Error ? error.message : String(error)}\n`)
      process.exitCode = 2
    })
}
