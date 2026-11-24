#!/usr/bin/env node
// Guardian v7 — three-tier smoke battery.
//
// Tier 0 (<90 s, $0): worker gate + deterministic replay of past false-positive
// archetypes through the shared Oracle invariants.
// Tier 1 (~6 min, ~$1, four parallel cells): paired agentic lift, a rotating second
// app, a zero-vuln precision trap, and a realism conversion micro-slice.
// Tier 2: the full 3-app + held-out + endurance command, documented only.
//
// Defensive QA framing: this battery measures whether a defensive scanner over-claims
// on synthetic, authorized loopback targets. It never attacks third-party systems.

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { DatabaseSync } from 'node:sqlite'

import {
  assessBusinessLogicImpact,
  assessCsrfImpact,
  assessImpactEvidence,
  assessMassAssignmentImpact,
  assessMfaBypass,
} from '../src/server/oracle-invariants.ts'
import type { ActorIdentity, ImpactInput, ImpactStep } from '../src/server/oracle-invariants.ts'
import { start as startZeroVulnTrap } from '../benchmarks/realism-suite/traps/zero-vuln.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '..')
const CORPUS_PATH = join(ROOT, 'benchmarks/realism-suite/traps/fp-archetypes.json')
const DEFAULT_DATA_DIR = process.env.GUARDIAN_DATA_DIR ?? '/home/omarchy/guardian-data'
const DEFAULT_OUT = join(ROOT, '.guardian/smoke-battery')

export const SMOKE_VERSION = 1
export const LIFT_APPS = ['acme-saas'] as const
export const ROTATION_APPS = ['shopflow', 'opsportal'] as const
export const MICRO_FIXTURES = ['wan-oob', 'staging-concurrency', 'monorepo-whitebox'] as const

export type Tier = 0 | 1 | 2
export type AssessorKind = 'mfa' | 'business_logic' | 'mass_assignment' | 'csrf' | 'authorization' | 'bfla'

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export interface SmokeArgs {
  /** Repository/worktree root used for child processes (calibration varies this). */
  repoRoot: string
  tier: Tier
  dryRun: boolean
  cellIndex: number
  seed: number
  durationSec: number
  trapDurationSec: number
  microDurationSec: number
  outDir: string
  dataDir: string
  snapshotRoot: string
  floorScorecard?: string
  liftBaseline: number
  corpusPath: string
  json: boolean
  calibrate: boolean
  variantsPath?: string
  rerunOnMinusOne: boolean
  skipWorkerGate: boolean
  microFixtures: string[]
  budgetUsdPerCell: number
  help: boolean
}

const usage = `Guardian smoke battery (three tiers, defensive QA)

Usage:
  npm run smoke:agentic -- [flags]
  node scripts/smoke-agentic.ts [flags]

Tier 0 (<90 s, $0):
  scripts/worker-gate.sh (typecheck + contract invariants) and a deterministic
  transcript corpus. The corpus replays six past over-claim archetypes through the
  shared Oracle invariants: 2FA without enrollment, amount:-1 echo, BFLA 2xx-only,
  mass-assignment echo, Bearer CSRF, and a public-route tenant canary. Every
  archetype must be dismissed; if any confirms, Tier 0 exits non-zero.

Tier 1 (~6 min, ~$1, four parallel cells):
  1. paired lift       acme-saas post-floor snapshot, 300 s agentic; reports net-new
                       vs the floor and floor preservation.
  2. rotating app      shopflow or opsportal post-floor snapshot, 300 s; rotates by
                       --cell-index or day of year. Missing snapshot falls back to a
                       cold run and captures a snapshot for next time.
  3. precision trap    hardened zero-vuln target with writable-looking decoys, 240 s;
                       any confirmed vulnerability finding fails the cell.
  4. micro-slice       realism #2 (async OOB), #3 (staging race/write-BOLA), #4
                       (4-hop Tier-A sink); wiring and capability are reported apart.

Tier 2 (documented, not run by default):
  Full 3-app agentic matrix + salted held-out + endurance. Print with --tier 2.

Flags:
  --tier <0|1|2>            default 1 (runs Tier 0 then Tier 1); 2 prints docs only
  --dry-run                 plan cells and evaluate the corpus; no model/worker calls
  --cell-index <n>          rotation index (default 0; date is used when omitted)
  --seed <n>                dev seed for lift/rotation/trap (default 1)
  --duration-sec <n>        lift/rotation budget (default 300)
  --trap-duration-sec <n>   trap budget (default 240)
  --micro-duration-sec <n>  per-fixture micro-slice budget (default 300)
  --out-dir <path>          artifacts (default .guardian/smoke-battery)
  --data-dir <path>         Guardian data dir (default $GUARDIAN_DATA_DIR or
                            /home/omarchy/guardian-data)
  --snapshot-root <path>    post-floor checkpoints (default <out-dir>/snapshots)
  --floor-scorecard <path>  baseline floor scorecard used for net-new/preservation
                            (default <snapshot-root>/baseline/<app>-seed<n>-grey-box.json)
  --lift-baseline <n>       prior agentic net-new baseline (default 0)
  --corpus <path>           archetype corpus JSON (default traps/fp-archetypes.json)
  --micro-fixtures <csv>    micro-slice fixtures (default #2,#3,#4)
  --budget-usd-per-cell <n> USD cap per cell (default 0.80)
  --rerun-on-minus-one      allow net-new = baseline - 1 only if conversion improved;
                            the lift cell is re-run once before the gate is evaluated
  --skip-worker-gate        skip scripts/worker-gate.sh in Tier 0 (not for handoff)
  --json                    emit the full report as JSON on stdout
  --calibrate --variants <json>
                            run Tier 1 against N worktrees/commits and emit CSV for
                            the Spearman study. Variants: [{"label":"a","dir":"..."}]
                            or [{"label":"b","commit":"<sha>"}].
  --help                    show this help

Gates (Tier 1):
  precision 100% on lift/rotation; 0 confirmed on the trap; paired net-new >=
  --lift-baseline (a -1 is allowed once with improved conversion and a rerun);
  conversion drop <= 10pp; 0 RPC/sandbox crashes; p50 assignment <= 90 s (>75 s warns);
  >= 12 completed assignments in the 300 s lift cell; <= $0.80/cell.

Environment:
  GUARDIAN_ALLOW_LOCAL_LAB=1   required for the loopback trap/fixtures
  GUARDIAN_DATA_DIR            model profile source (isolated per cell)
  GUARDIAN_RB_HELDOUT_SALT     required only for the Tier 2 held-out command
  Docker socket                agentic cells run under newgrp docker when needed

Examples:
  npm run smoke:agentic -- --dry-run
  npm run smoke:agentic -- --tier 0
  npm run smoke:agentic -- --tier 1 --out-dir /tmp/smoke
  npm run smoke:agentic -- --tier 2
`

function fail(message: string): never {
  throw new Error(message)
}

function take(argv: string[]): { flags: Record<string, string | boolean> } {
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (!arg.startsWith('--')) fail(`unexpected argument '${arg}'`)
    const key = arg.slice(2)
    if (!key) fail('empty flag')
    const next = argv[i + 1]
    if (next === undefined || next.startsWith('--')) flags[key] = true
    else { flags[key] = next; i += 1 }
  }
  return { flags }
}

function str(flags: Record<string, string | boolean>, key: string): string | undefined {
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

export function parseSmokeArgs(argv: string[], _env: NodeJS.ProcessEnv = process.env): SmokeArgs {
  const { flags } = take(argv)
  const known = new Set([
    'tier', 'dry-run', 'cell-index', 'seed', 'duration-sec', 'trap-duration-sec',
    'micro-duration-sec', 'out-dir', 'data-dir', 'snapshot-root', 'floor-scorecard',
    'lift-baseline', 'corpus', 'json', 'calibrate', 'variants', 'rerun-on-minus-one',
    'skip-worker-gate', 'micro-fixtures', 'budget-usd-per-cell', 'help',
  ])
  for (const key of Object.keys(flags)) if (!known.has(key)) fail(`unknown flag --${key}`)
  if (flags.help === true) {
    return {
      repoRoot: ROOT, tier: 1, dryRun: false, cellIndex: 0, seed: 1, durationSec: 300,
      trapDurationSec: 240, microDurationSec: 300, outDir: DEFAULT_OUT,
      dataDir: DEFAULT_DATA_DIR, snapshotRoot: join(DEFAULT_OUT, 'snapshots'),
      liftBaseline: 0, corpusPath: CORPUS_PATH, json: false, calibrate: false,
      rerunOnMinusOne: false, skipWorkerGate: false, microFixtures: [...MICRO_FIXTURES],
      budgetUsdPerCell: 0.8, help: true,
    }
  }
  const tierRaw = str(flags, 'tier') ?? '1'
  if (tierRaw !== '0' && tierRaw !== '1' && tierRaw !== '2') fail("--tier must be 0, 1 or 2")
  const outDirRaw = str(flags, 'out-dir') ?? DEFAULT_OUT
  const outDir = isAbsolute(outDirRaw) ? outDirRaw : resolve(outDirRaw)
  const snapshotRaw = str(flags, 'snapshot-root')
  const snapshotRoot = snapshotRaw
    ? (isAbsolute(snapshotRaw) ? snapshotRaw : resolve(snapshotRaw))
    : join(outDir, 'snapshots')
  const microRaw = str(flags, 'micro-fixtures')
  const microFixtures = microRaw
    ? microRaw.split(',').map(s => s.trim()).filter(Boolean)
    : [...MICRO_FIXTURES]
  const budget = Number(str(flags, 'budget-usd-per-cell') ?? '0.8')
  if (!Number.isFinite(budget) || budget <= 0) fail('--budget-usd-per-cell must be a positive number')
  const liftBaselineRaw = Number(str(flags, 'lift-baseline') ?? '0')
  if (!Number.isFinite(liftBaselineRaw) || liftBaselineRaw < 0) fail('--lift-baseline must be >= 0')
  const now = new Date()
  const defaultCellIndex = Math.floor((now.getTime() - Date.UTC(now.getUTCFullYear(), 0, 0)) / 86_400_000)
  if (flags.calibrate === true && !str(flags, 'variants')) fail('--calibrate requires --variants <json>')
  return {
    repoRoot: ROOT,
    tier: Number(tierRaw) as Tier,
    dryRun: flags['dry-run'] === true,
    cellIndex: nonNegativeInt(str(flags, 'cell-index'), '--cell-index', defaultCellIndex),
    seed: positiveInt(str(flags, 'seed'), '--seed', 1),
    durationSec: positiveInt(str(flags, 'duration-sec'), '--duration-sec', 300),
    trapDurationSec: positiveInt(str(flags, 'trap-duration-sec'), '--trap-duration-sec', 240),
    microDurationSec: positiveInt(str(flags, 'micro-duration-sec'), '--micro-duration-sec', 300),
    outDir,
    dataDir: str(flags, 'data-dir') ?? DEFAULT_DATA_DIR,
    snapshotRoot,
    floorScorecard: str(flags, 'floor-scorecard'),
    liftBaseline: liftBaselineRaw,
    corpusPath: str(flags, 'corpus') ?? CORPUS_PATH,
    json: flags.json === true,
    calibrate: flags.calibrate === true,
    variantsPath: str(flags, 'variants'),
    rerunOnMinusOne: flags['rerun-on-minus-one'] === true,
    skipWorkerGate: flags['skip-worker-gate'] === true,
    microFixtures,
    budgetUsdPerCell: budget,
    help: false,
  }
}

// ---------------------------------------------------------------------------
// Tier 0 — deterministic archetype corpus
// ---------------------------------------------------------------------------

export interface RawArchetypeStep {
  id: string
  arm: 'control' | 'probe' | 'setup' | 'cleanup'
  method: string
  route?: string
  pathAndQuery?: string
  status: number | null
  actor?: Partial<ActorIdentity>
  json?: unknown
  body?: string
  requestJson?: unknown
  requestHeaders?: Record<string, string> | null
  responseHeaders?: Record<string, string> | null
}

export interface Archetype {
  id: string
  title: string
  assessor: AssessorKind
  expectedDismissal: string
  input: {
    impactClass: ImpactInput['impactClass']
    requiredRole?: string | null
    resourceTenant?: string | null
    targetOrigin?: string | null
    oracleEvents?: string[]
    steps: RawArchetypeStep[]
  }
}

export interface ArchetypeResult {
  id: string
  title: string
  assessor: AssessorKind
  dismissed: boolean
  satisfied: boolean
  reason: string
  expectedDismissal: string
}

function actorOf(raw: Partial<ActorIdentity> | undefined): ActorIdentity {
  return {
    handle: raw?.handle ?? null,
    role: raw?.role ?? null,
    tenant: raw?.tenant ?? null,
    auth: raw?.auth ?? 'unknown',
    sameSite: raw?.sameSite ?? null,
  }
}

export function materializeArchetypeInput(input: Archetype['input']): ImpactInput {
  const steps: ImpactStep[] = input.steps.map(step => ({
    id: step.id,
    arm: step.arm,
    method: step.method.toUpperCase(),
    ...(step.route ? { route: step.route } : {}),
    ...(step.pathAndQuery ? { pathAndQuery: step.pathAndQuery } : {}),
    status: step.status,
    actor: actorOf(step.actor),
    ...(step.json !== undefined ? { json: step.json } : {}),
    ...(step.body !== undefined ? { body: step.body } : {}),
    ...(step.requestJson !== undefined ? { requestJson: step.requestJson } : {}),
    ...(step.requestHeaders ? { requestHeaders: step.requestHeaders } : {}),
    ...(step.responseHeaders ? { responseHeaders: step.responseHeaders } : {}),
  }))
  return {
    impactClass: input.impactClass,
    steps,
    ...(input.requiredRole !== undefined ? { requiredRole: input.requiredRole } : {}),
    ...(input.resourceTenant !== undefined ? { resourceTenant: input.resourceTenant } : {}),
    ...(input.targetOrigin !== undefined ? { targetOrigin: input.targetOrigin } : {}),
    ...(input.oracleEvents !== undefined ? { oracleEvents: input.oracleEvents } : {}),
  }
}

export function evaluateArchetype(archetype: Archetype): ArchetypeResult {
  const input = materializeArchetypeInput(archetype.input)
  let satisfied: boolean
  let reason: string
  switch (archetype.assessor) {
    case 'mfa': {
      const result = assessMfaBypass(input)
      satisfied = result.satisfied
      reason = result.reason
      break
    }
    case 'csrf': {
      const result = assessCsrfImpact(input)
      satisfied = result.satisfied
      reason = result.reason
      break
    }
    case 'mass_assignment': {
      const result = assessMassAssignmentImpact(input)
      satisfied = result.satisfied
      reason = result.reason
      break
    }
    case 'business_logic': {
      const result = assessBusinessLogicImpact(input)
      satisfied = result.satisfied
      reason = result.reason
      break
    }
    case 'authorization':
    case 'bfla': {
      const result = assessImpactEvidence(input)
      satisfied = result.satisfied
      reason = result.reason
      break
    }
    default:
      fail(`unknown archetype assessor '${String((archetype as Archetype).assessor)}'`)
  }
  return {
    id: archetype.id,
    title: archetype.title,
    assessor: archetype.assessor,
    dismissed: satisfied === false,
    satisfied,
    reason,
    expectedDismissal: archetype.expectedDismissal,
  }
}

export function loadCorpus(path: string): Archetype[] {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { archetypes?: Archetype[] }
  if (!Array.isArray(parsed.archetypes) || parsed.archetypes.length === 0) {
    fail(`corpus ${path} has no archetypes`)
  }
  for (const archetype of parsed.archetypes) {
    if (!archetype.id || !archetype.assessor || !archetype.input?.steps?.length) {
      fail(`corpus ${path} has a malformed archetype (need id, assessor, input.steps)`)
    }
  }
  return parsed.archetypes
}

export function runCorpus(path: string): { results: ArchetypeResult[]; pass: boolean } {
  const results = loadCorpus(path).map(evaluateArchetype)
  return { results, pass: results.every(result => result.dismissed) }
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

export function rotateSecondApp(opts: { cellIndex?: number; date?: Date } = {}): typeof ROTATION_APPS[number] {
  const index = opts.cellIndex
  if (index !== undefined && Number.isFinite(index)) {
    return ROTATION_APPS[Math.abs(Math.trunc(index)) % ROTATION_APPS.length]!
  }
  const date = opts.date ?? new Date()
  const start = Date.UTC(date.getUTCFullYear(), 0, 0)
  const dayOfYear = Math.floor((date.getTime() - start) / 86_400_000)
  return ROTATION_APPS[Math.abs(dayOfYear) % ROTATION_APPS.length]!
}

// ---------------------------------------------------------------------------
// Cell metrics / gates
// ---------------------------------------------------------------------------

export interface CellMetrics {
  id: string
  kind: 'lift' | 'rotation' | 'trap' | 'micro'
  app: string
  source: 'snapshot' | 'cold' | 'local'
  targets: number
  confirmed: number
  precision: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  netNew: number | null
  floorConfirmed: number | null
  floorPreserved: number | null
  conversion: number | null
  costUsd: number
  p50AssignmentMs: number | null
  completedAssignments: number
  wallMs: number
  crashes: number
  wiring?: string | null
  capability?: number | null
  detail?: string
  error?: string
}

export interface GateResult {
  id: string
  label: string
  pass: boolean
  observed: string
}

export interface GateInput {
  cells: CellMetrics[]
  liftBaseline: number
  baselineConversion: number | null
  trapConfirmed: number
  rerunExecuted: boolean
  perCellBudgetUsd: number
}

const pct = (value: number | null | undefined): string =>
  value === null || value === undefined || !Number.isFinite(value) ? 'n/a' : `${(value * 100).toFixed(1)}%`

/** Gates are pure so CI fixtures can exercise pass/fail without starting a run. */
export function evaluateGates(input: GateInput): GateResult[] {
  const agentic = input.cells.filter(cell => cell.kind === 'lift' || cell.kind === 'rotation')
  const lift = input.cells.find(cell => cell.kind === 'lift') ?? null
  const gates: GateResult[] = []

  const precisionFailures = agentic.filter(cell =>
    cell.error !== undefined || cell.precision !== 1 || cell.decoyFalsePositives > 0 || cell.unmatchedFalsePositives > 0)
  gates.push({
    id: 'precision-lift',
    label: 'precision 100% on lift/rotation cells',
    pass: agentic.length > 0 && precisionFailures.length === 0,
    observed: agentic.length === 0
      ? 'no lift cells measured'
      : precisionFailures.length === 0
        ? `${agentic.map(cell => `${cell.id}=${pct(cell.precision)}`).join(', ')}`
        : `fail: ${precisionFailures.map(cell => cell.id).join(', ')}`,
  })

  gates.push({
    id: 'trap-zero',
    label: '0 confirmed findings on the zero-vuln trap',
    pass: input.trapConfirmed === 0,
    observed: `${input.trapConfirmed} confirmed`,
  })

  const netNew = lift?.netNew ?? null
  const canAllowMinusOne = input.rerunExecuted
  const netNewPass = netNew !== null && (
    netNew >= input.liftBaseline ||
    (canAllowMinusOne && netNew === input.liftBaseline - 1 &&
      lift !== null && input.baselineConversion !== null &&
      (lift.conversion ?? -1) >= input.baselineConversion)
  )
  gates.push({
    id: 'paired-net-new',
    label: `paired net-new >= baseline (${input.liftBaseline})`,
    pass: netNewPass,
    observed: netNew === null
      ? 'not measured'
      : `${netNew} (${canAllowMinusOne ? '-1 rerun allowance active' : 'no -1 allowance'})`,
  })

  if (input.baselineConversion === null) {
    gates.push({
      id: 'conversion',
      label: 'conversion drop <= 10pp',
      pass: false,
      observed: 'baseline conversion not measured',
    })
  } else {
    const conversion = lift?.conversion ?? null
    gates.push({
      id: 'conversion',
      label: 'conversion drop <= 10pp',
      pass: conversion !== null && conversion >= input.baselineConversion - 0.10,
      observed: conversion === null
        ? 'not measured'
        : `${pct(conversion)} vs baseline ${pct(input.baselineConversion)}`,
    })
  }

  const crashes = input.cells.reduce((sum, cell) => sum + cell.crashes, 0)
  gates.push({
    id: 'crashes',
    label: '0 RPC/sandbox crashes',
    pass: input.cells.length > 0 && crashes === 0 && input.cells.every(cell => cell.error === undefined),
    observed: crashes === 0
      ? (input.cells.some(cell => cell.error !== undefined) ? `cell error: ${input.cells.find(cell => cell.error)!.id}` : '0')
      : String(crashes),
  })

  const p50Warnings = agentic.filter(cell => cell.p50AssignmentMs !== null && cell.p50AssignmentMs > 75_000)
  const p50Failures = agentic.filter(cell => cell.p50AssignmentMs === null || cell.p50AssignmentMs > 90_000)
  gates.push({
    id: 'p50-assignment',
    label: 'p50 assignment <= 90 s (>75 s warns)',
    pass: agentic.length > 0 && p50Failures.length === 0,
    observed: agentic.length === 0
      ? 'not measured'
      : p50Failures.length === 0
        ? `${agentic.map(cell => `${cell.id}=${Math.round((cell.p50AssignmentMs ?? 0) / 1000)}s`).join(', ')}${p50Warnings.length ? ' (warn >75s)' : ''}`
        : `fail: ${p50Failures.map(cell => `${cell.id}=${cell.p50AssignmentMs === null ? 'n/a' : `${Math.round(cell.p50AssignmentMs / 1000)}s`}`).join(', ')}`,
  })

  gates.push({
    id: 'throughput',
    label: '>= 12 completed assignments in 300 s',
    pass: lift !== null && lift.completedAssignments >= 12,
    observed: lift ? `${lift.completedAssignments} completed` : 'not measured',
  })

  const overBudget = input.cells.filter(cell => cell.costUsd > input.perCellBudgetUsd)
  gates.push({
    id: 'cost',
    label: `cost <= $${input.perCellBudgetUsd.toFixed(2)}/cell`,
    pass: input.cells.length > 0 && overBudget.length === 0,
    observed: input.cells.length === 0
      ? 'not measured'
      : overBudget.length === 0
        ? `total $${input.cells.reduce((sum, cell) => sum + cell.costUsd, 0).toFixed(4)}`
        : `over: ${overBudget.map(cell => `${cell.id}=$${cell.costUsd.toFixed(3)}`).join(', ')}`,
  })

  return gates
}

// ---------------------------------------------------------------------------
// Artifact readers (structured only; never dump raw bodies)
// ---------------------------------------------------------------------------

interface ScorecardLike {
  app?: string
  seed?: number
  targets?: number
  confirmed?: number
  precision?: number
  decoyFalsePositives?: number
  unmatchedFalsePositives?: number
  totalCostUsd?: number
  funnel?: { specSubmitted?: number; zeroLlmConfirmed?: number }
  vulns?: Array<{ siteId: string; outcome: string; matchedFindingIds?: string[] }>
}

interface MetaLike {
  durationMs?: number
  resumedFrom?: string | null
  notes?: string[]
  assignments?: { completed?: number }
}

export function readJson<T>(path: string): T | null {
  try { return JSON.parse(readFileSync(path, 'utf8')) as T } catch { return null }
}

export function confirmedSiteIds(card: ScorecardLike | null): string[] {
  return (card?.vulns ?? []).filter(vuln => vuln.outcome === 'confirmed').map(vuln => vuln.siteId)
}

export function preservedSiteIds(card: ScorecardLike | null, baselineIds: string[]): number {
  const matched = new Set(
    (card?.vulns ?? [])
      .filter(vuln => vuln.outcome === 'confirmed' || (vuln.matchedFindingIds?.length ?? 0) > 0)
      .map(vuln => vuln.siteId),
  )
  return baselineIds.filter(id => matched.has(id)).length
}

export function conversionOf(card: ScorecardLike | null): number | null {
  if (!card) return null
  // Prefer overall target conversion (confirmed/targets); fall back to spec conversion when a
  // caller only has funnel counters. The lift gate compares this with the floor baseline.
  if ((card.targets ?? 0) > 0) return (card.confirmed ?? 0) / card.targets!
  if (!card.funnel) return null
  const submitted = card.funnel.specSubmitted ?? 0
  const confirmed = card.funnel.zeroLlmConfirmed ?? 0
  return submitted > 0 ? confirmed / submitted : (confirmed > 0 ? 1 : 0)
}

/** p50 of assignment wall time from worker.started/complete/failed/canceled events. */
export function assignmentP50Ms(dbPath: string): number | null {
  if (!existsSync(dbPath)) return null
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    const rows = db.prepare(
      "select kind, detail, created_at from events where kind in ('worker.started','worker.complete','worker.failed','worker.canceled') order by id asc",
    ).all() as Array<{ kind: string; detail: string; created_at: number }>
    const started = new Map<string, number>()
    const durations: number[] = []
    for (const row of rows) {
      let detail: Record<string, unknown> = {}
      try { detail = JSON.parse(row.detail) as Record<string, unknown> } catch { detail = {} }
      const id = typeof detail.assignmentId === 'string' ? detail.assignmentId : null
      if (!id) continue
      if (row.kind === 'worker.started') started.set(id, Number(row.created_at))
      else {
        const at = started.get(id)
        if (at !== undefined) {
          durations.push(Math.max(0, Number(row.created_at) - at))
          started.delete(id)
        }
      }
    }
    if (durations.length === 0) return null
    durations.sort((a, b) => a - b)
    const mid = Math.floor(durations.length / 2)
    return durations.length % 2 === 0
      ? Math.round((durations[mid - 1]! + durations[mid]!) / 2)
      : durations[mid]!
  } catch {
    return null
  } finally {
    try { db?.close() } catch { /* best-effort */ }
  }
}

export function spentUsd(dbPath: string): number {
  if (!existsSync(dbPath)) return 0
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    const row = db.prepare('select spent_usd from runs order by rowid desc limit 1').get() as { spent_usd?: number } | undefined
    return Number(row?.spent_usd ?? 0)
  } catch {
    return 0
  } finally {
    try { db?.close() } catch { /* best-effort */ }
  }
}

export function countCrashes(text: string): number {
  const patterns = [
    /\brpc\b[^\n]{0,40}\b(?:fail(?:ed|ure)?|error|crash(?:ed|es)?|timeout)\b/gi,
    /\bsandbox\b[^\n]{0,40}\b(?:fail(?:ed|ure)?|error|crash(?:ed|es)?|died)\b/gi,
    /\bworker backend\b[^\n]{0,40}\b(?:fail(?:ed|ure)?|error|unavailable)\b/gi,
  ]
  let count = 0
  for (const pattern of patterns) count += (text.match(pattern) ?? []).length
  return count
}

function readLog(path: string): string {
  try { return readFileSync(path, 'utf8') } catch { return '' }
}

function scorecardPath(outDir: string, app: string, seed: number): string {
  return join(outDir, `${app}-seed${seed}-grey-box.json`)
}

function metaPath(outDir: string, app: string, seed: number): string {
  return join(outDir, `${app}-seed${seed}-grey-box.meta.json`)
}

function snapshotDir(root: string, app: string, seed: number): string {
  return join(root, `${app}-seed${seed}-grey-box`)
}

export function hasSnapshot(dir: string): boolean {
  return existsSync(join(dir, 'snapshot.json'))
}

/**
 * Prefer the checkpoint with the most runtime-confirmed floor findings. The post-floor capture
 * is taken at the boundary and can precede floor confirmations; `planner-round-N` carries them.
 * Falling back to the base directory keeps old single-checkpoint snapshots working.
 */
export function bestSnapshotDir(dir: string): string | null {
  if (!existsSync(dir)) return null
  const runtimeConfirmed = (candidate: string): number => {
    const snapshot = readJson<{ counts?: { runtimeConfirmed?: number } }>(join(candidate, 'snapshot.json'))
    return snapshot?.counts?.runtimeConfirmed ?? 0
  }
  let best: string | null = hasSnapshot(dir) ? dir : null
  let bestCount = best ? runtimeConfirmed(best) : -1
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^planner-round-\d+$/.test(entry.name)) continue
      const candidate = join(dir, entry.name)
      if (!hasSnapshot(candidate)) continue
      const count = runtimeConfirmed(candidate)
      if (count > bestCount) { best = candidate; bestCount = count }
    }
  } catch { /* unreadable directory means no checkpoint */ }
  return best
}

// ---------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function dockerUsable(): boolean {
  const probe = spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 10_000 })
  return probe.status === 0
}

interface RunResult {
  code: number | null
  wallMs: number
  logPath: string
  /** True when the battery's hard stop fired (the child ignored its own budget/teardown). */
  timedOut: boolean
}

async function spawnLogged(input: {
  command: string
  args: string[]
  cwd: string
  env: NodeJS.ProcessEnv
  logPath: string
  docker: boolean
  /** Hard-kill the process group after this wall time. Default: 1 hour. */
  killAfterMs?: number
}): Promise<RunResult> {
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
        try { child.kill(signal) } catch { /* already gone */ }
      }
    }
    let hardKill: ReturnType<typeof setTimeout> | undefined
    const grace = setTimeout(() => {
      timedOut = true
      absorb(Buffer.from('\n[battery] hard stop: child exceeded its wall budget; terminating process group\n'))
      killGroup('SIGTERM')
      hardKill = setTimeout(() => killGroup('SIGKILL'), 8_000)
    }, input.killAfterMs ?? 3_600_000)
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

interface CellPlan {
  id: string
  kind: CellMetrics['kind']
  app: string
  source: 'snapshot' | 'cold' | 'local'
  outDir: string
  args: string[]
  snapshot?: string
  command: string
}

export function planTierOne(opts: SmokeArgs): CellPlan[] {
  const micro = opts.microFixtures.join(',')
  const rotation = rotateSecondApp({ cellIndex: opts.cellIndex })
  const liftSnapshot = bestSnapshotDir(snapshotDir(opts.snapshotRoot, 'acme-saas', opts.seed))
  const rotationSnapshot = bestSnapshotDir(snapshotDir(opts.snapshotRoot, rotation, opts.seed))
  return [
    {
      id: 'lift',
      kind: 'lift',
      app: 'acme-saas',
      source: liftSnapshot ? 'snapshot' : 'cold',
      outDir: join(opts.outDir, 'cells', 'lift'),
      ...(liftSnapshot
        ? { snapshot: liftSnapshot }
        : { snapshot: snapshotDir(opts.snapshotRoot, 'acme-saas', opts.seed) }),
      command: 'node scripts/benchmark-realistic.ts',
      args: ['--app', 'acme-saas'],
    },
    {
      id: 'rotation',
      kind: 'rotation',
      app: rotation,
      source: rotationSnapshot ? 'snapshot' : 'cold',
      outDir: join(opts.outDir, 'cells', 'rotation'),
      ...(rotationSnapshot
        ? { snapshot: rotationSnapshot }
        : { snapshot: snapshotDir(opts.snapshotRoot, rotation, opts.seed) }),
      command: 'node scripts/benchmark-realistic.ts',
      args: ['--app', rotation],
    },
    {
      id: 'trap',
      kind: 'trap',
      app: 'zero-vuln',
      source: 'local',
      outDir: join(opts.outDir, 'cells', 'trap'),
      command: 'node scripts/cli.ts',
      args: ['scan'],
    },
    {
      id: 'micro',
      kind: 'micro',
      app: micro,
      source: 'local',
      outDir: join(opts.outDir, 'cells', 'micro'),
      command: 'node scripts/benchmark-realism.ts',
      args: ['--fixture', micro],
    },
  ]
}

function realisticArgs(plan: CellPlan, opts: SmokeArgs): string[] {
  const durationMs = opts.durationSec * 1000
  return [
    '--app', plan.app,
    '--seed', String(opts.seed),
    '--mode', 'grey-box',
    '--max-duration-ms', String(durationMs),
    '--budget-usd', String(opts.budgetUsdPerCell),
    '--max-rps', '50',
    '--concurrency', '1',
    '--worker-concurrency', '6',
    '--out-dir', plan.outDir,
    '--data-dir', join(plan.outDir, 'data'),
    ...(plan.source === 'snapshot'
      ? ['--resume-snapshot', plan.snapshot!]
      : ['--snapshot-after-floor', plan.snapshot!]),
  ]
}

function baseEnv(opts: SmokeArgs): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GUARDIAN_ALLOW_LOCAL_LAB: '1',
    GUARDIAN_DATA_DIR: opts.dataDir,
    GUARDIAN_RECON_SIBLINGS: '1',
  }
}

async function prepareIsolated(sourceDataDir: string, dataDir: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  try {
    const { prepareIsolatedDataDir } = await import('./benchmark-realistic.ts')
    prepareIsolatedDataDir({ sourceDataDir, targetDir: dataDir })
    return { ok: true }
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) }
  }
}

// ---------------------------------------------------------------------------
// Tier 1 cells
// ---------------------------------------------------------------------------

async function runRealisticCell(plan: CellPlan, opts: SmokeArgs): Promise<CellMetrics> {
  mkdirSync(plan.outDir, { recursive: true, mode: 0o700 })
  const dataDir = join(plan.outDir, 'data')
  const prepared = await prepareIsolated(opts.dataDir, dataDir)
  if (!prepared.ok) {
    return emptyCell(plan, { error: `data dir preflight failed: ${prepared.reason}` })
  }
  const logPath = join(plan.outDir, 'run.log')
  const result = await spawnLogged({
    command: 'node',
    args: ['scripts/benchmark-realistic.ts', ...realisticArgs(plan, opts)],
    cwd: opts.repoRoot,
    env: baseEnv(opts),
    logPath,
    docker: true,
    killAfterMs: opts.durationSec * 1000 + 180_000,
  })
  const card = readJson<ScorecardLike>(scorecardPath(plan.outDir, plan.app, opts.seed))
  const meta = readJson<MetaLike>(metaPath(plan.outDir, plan.app, opts.seed))
  const baselinePath = opts.floorScorecard ?? join(opts.snapshotRoot, 'baseline', `${plan.app}-seed${opts.seed}-grey-box.json`)
  const baseline = plan.kind === 'lift' ? readJson<ScorecardLike>(baselinePath) : null
  const baselineIds = confirmedSiteIds(baseline)
  const confirmed = card?.confirmed ?? 0
  const floorConfirmed = baseline?.confirmed ?? (plan.kind === 'lift' ? opts.liftBaseline : null)
  const netNew = plan.kind === 'lift'
    ? (plan.source === 'snapshot' ? confirmed : Math.max(0, confirmed - (floorConfirmed ?? 0)))
    : (card ? confirmed : null)
  const floorPreserved = plan.kind === 'lift' && baselineIds.length > 0
    ? preservedSiteIds(card, baselineIds)
    : null
  // A resumed scorecard counts only oracle evidence from this process, so effective lift
  // conversion = net-new + preserved floor findings over the cell's targets.
  const effectiveConfirmed = plan.kind === 'lift' && plan.source === 'snapshot'
    ? confirmed + (floorPreserved ?? 0)
    : confirmed
  const conversion = (card?.targets ?? 0) > 0 ? effectiveConfirmed / card!.targets! : conversionOf(card)
  const log = readLog(logPath)
  const dbPath = plan.source === 'snapshot'
    ? join(plan.outDir, 'data', `${plan.app}-seed${opts.seed}-grey-box-resume`, 'guardian.sqlite')
    : join(dataDir, 'guardian.sqlite')
  return {
    id: plan.id,
    kind: plan.kind,
    app: plan.app,
    source: plan.source,
    targets: card?.targets ?? 0,
    confirmed,
    precision: card?.precision ?? 0,
    decoyFalsePositives: card?.decoyFalsePositives ?? 0,
    unmatchedFalsePositives: card?.unmatchedFalsePositives ?? 0,
    netNew,
    floorConfirmed,
    floorPreserved,
    conversion,
    costUsd: card?.totalCostUsd ?? spentUsd(dbPath),
    p50AssignmentMs: assignmentP50Ms(dbPath),
    completedAssignments: meta?.assignments?.completed ?? 0,
    wallMs: meta?.durationMs ?? result.wallMs,
    crashes: countCrashes(`${log}\n${(meta?.notes ?? []).join('\n')}`),
    ...(result.code !== 0 && !card ? { error: `harness exit ${result.code}` } : {}),
  }
}

function emptyCell(plan: CellPlan, extra: Partial<CellMetrics> = {}): CellMetrics {
  return {
    id: plan.id,
    kind: plan.kind,
    app: plan.app,
    source: plan.source,
    targets: 0,
    confirmed: 0,
    precision: 0,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    netNew: null,
    floorConfirmed: null,
    floorPreserved: null,
    conversion: null,
    costUsd: 0,
    p50AssignmentMs: null,
    completedAssignments: 0,
    wallMs: 0,
    crashes: 0,
    ...extra,
  }
}

async function runTrapCell(plan: CellPlan, opts: SmokeArgs): Promise<CellMetrics> {
  mkdirSync(plan.outDir, { recursive: true, mode: 0o700 })
  const dataDir = join(plan.outDir, 'data')
  const prepared = await prepareIsolated(opts.dataDir, dataDir)
  if (!prepared.ok) {
    return emptyCell(plan, { error: `data dir preflight failed: ${prepared.reason}` })
  }
  const trap = await startZeroVulnTrap({ seed: opts.seed })
  const logPath = join(plan.outDir, 'run.log')
  // Hand the CLI owner-held synthetic bearer credentials so the trap's authorized surface is
  // actually exercised. Files are 0600 and live inside the cell artifact dir.
  const personaDir = join(plan.outDir, 'personas')
  mkdirSync(personaDir, { recursive: true, mode: 0o700 })
  const personaArgs: string[] = []
  for (const persona of trap.personas) {
    if (!persona.token) continue
    const credentialPath = join(personaDir, `${persona.id}.json`)
    writeFileSync(credentialPath, `${JSON.stringify({
      secret: persona.token,
      authKind: 'bearer',
      roleLabel: `${persona.role} (${persona.tenant})`,
      canaryMarkers: [],
    }, null, 2)}\n`, { mode: 0o600 })
    personaArgs.push('--persona', `${persona.id}:${credentialPath}`)
  }
  try {
    const result = await spawnLogged({
      command: 'node',
      args: [
        'scripts/cli.ts', 'scan',
        '--origin', trap.origins.app!,
        '--local-lab',
        '--tier', '3',
        ...personaArgs,
        '--budget-usd', String(opts.budgetUsdPerCell),
        '--budget-requests', '3000',
        '--max-rps', '20',
        '--timeout-sec', String(opts.trapDurationSec),
        '--output-dir', plan.outDir,
      ],
      cwd: opts.repoRoot,
      env: baseEnv(opts),
      logPath,
      docker: true,
      killAfterMs: opts.trapDurationSec * 1000 + 60_000,
    })
    const dbPath = join(dataDir, 'guardian.sqlite')
    const counts = confirmedVulnerabilityCounts(dbPath)
    const state = latestRunState(dbPath)
    const log = readLog(logPath)
    // A deliberate budget stop is not a crash. It is acceptable only when the run actually
    // reached investigation; a run that never left threat_model proves nothing about precision.
    const budgetStop = result.timedOut || result.code === 143 || result.code === 1
    const reachedInvestigation = counts.completedAssignments > 0 || counts.confirmed > 0
      || (state !== null && state.phase !== 'threat_model' && state.phase !== 'phase0')
    return {
      id: plan.id,
      kind: 'trap',
      app: plan.app,
      source: 'local',
      targets: 0,
      confirmed: counts.confirmed,
      precision: counts.confirmed === 0 ? 1 : 0,
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
      netNew: 0,
      floorConfirmed: 0,
      floorPreserved: null,
      conversion: null,
      costUsd: spentUsd(dbPath),
      p50AssignmentMs: assignmentP50Ms(dbPath),
      completedAssignments: counts.completedAssignments,
      wallMs: result.wallMs,
      crashes: countCrashes(log),
      capability: counts.confirmed,
      detail: `${counts.confirmed} confirmed, ${counts.advisory} advisory; run ${state?.status ?? 'unknown'}/${state?.phase ?? 'unknown'}${budgetStop ? ' (budget stop)' : ''}`,
      ...(!existsSync(dbPath)
        ? { error: 'trap run persisted no findings DB' }
        : budgetStop
          ? (reachedInvestigation ? {} : { error: `trap never reached investigation (exit ${result.code})` })
          : result.code !== 0 && result.code !== 2
            ? { error: `cli exit ${result.code}` }
            : {}),
    }
  } finally {
    await trap.stop()
  }
}

export function latestRunState(dbPath: string): { status: string; phase: string } | null {
  if (!existsSync(dbPath)) return null
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    const row = db.prepare('select status, phase from runs order by rowid desc limit 1')
      .get() as { status?: string; phase?: string } | undefined
    return row ? { status: String(row.status ?? 'unknown'), phase: String(row.phase ?? 'unknown') } : null
  } catch {
    return null
  } finally {
    try { db?.close() } catch { /* best-effort */ }
  }
}

export function confirmedVulnerabilityCounts(dbPath: string): {
  confirmed: number
  advisory: number
  completedAssignments: number
} {
  if (!existsSync(dbPath)) return { confirmed: 0, advisory: 0, completedAssignments: 0 }
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    const confirmed = db.prepare(
      "select count(*) as n from findings where verification_class = 'runtime_confirmed' "
      + "and finding_kind != 'baseline_check' and superseded_by_finding_id is null",
    ).get() as { n?: number } | undefined
    const advisory = db.prepare(
      "select count(*) as n from findings where verification_class != 'runtime_confirmed' "
      + "and finding_kind != 'baseline_check' and superseded_by_finding_id is null",
    ).get() as { n?: number } | undefined
    const completed = db.prepare(
      "select count(*) as n from assignments where status = 'complete'",
    ).get() as { n?: number } | undefined
    return {
      confirmed: Number(confirmed?.n ?? 0),
      advisory: Number(advisory?.n ?? 0),
      completedAssignments: Number(completed?.n ?? 0),
    }
  } catch {
    return { confirmed: 0, advisory: 0, completedAssignments: 0 }
  } finally {
    try { db?.close() } catch { /* best-effort */ }
  }
}

interface RealismArtifact {
  fixture?: string
  grade?: { submitted?: number; truePositives?: number; falsePositives?: number; precision?: number }
  metrics?: {
    wiring?: { status?: string }
    oob?: { blindSqliConfirmed?: boolean; asyncSsrfConfirmed?: boolean; asyncXxeConfirmed?: boolean; webhookForgeryConfirmed?: boolean }
    staging?: { writeBolaConfirmed?: boolean; raceConfirmed?: boolean; checkoutConfirmed?: boolean }
    monorepo?: { fourHopConfirmations?: number }
  }
}

export function microCapability(fixture: string, artifact: RealismArtifact | null): number {
  if (!artifact) return 0
  if (fixture === 'wan-oob') {
    const oob = artifact.metrics?.oob
    return [oob?.blindSqliConfirmed, oob?.asyncSsrfConfirmed, oob?.asyncXxeConfirmed, oob?.webhookForgeryConfirmed]
      .filter(Boolean).length
  }
  if (fixture === 'staging-concurrency') {
    const staging = artifact.metrics?.staging
    return [staging?.writeBolaConfirmed, staging?.raceConfirmed, staging?.checkoutConfirmed].filter(Boolean).length
  }
  if (fixture === 'monorepo-whitebox') {
    return artifact.metrics?.monorepo?.fourHopConfirmations ?? artifact.grade?.truePositives ?? 0
  }
  return artifact.grade?.truePositives ?? 0
}

async function runMicroCell(plan: CellPlan, opts: SmokeArgs): Promise<CellMetrics> {
  mkdirSync(plan.outDir, { recursive: true, mode: 0o700 })
  const results = await Promise.all(opts.microFixtures.map(async (fixture) => {
    const fixtureOut = join(plan.outDir, fixture)
    mkdirSync(fixtureOut, { recursive: true, mode: 0o700 })
    const dataDir = join(fixtureOut, 'data')
    const prepared = await prepareIsolated(opts.dataDir, dataDir)
    if (!prepared.ok) return { fixture, error: prepared.reason, artifact: null, wallMs: 0, db: '', log: '' }
    const logPath = join(fixtureOut, 'run.log')
    const result = await spawnLogged({
      command: 'node',
      args: [
        'scripts/benchmark-realism.ts',
        '--fixture', fixture,
        '--mode', 'grey-box',
        '--max-duration-ms', String(opts.microDurationSec * 1000),
        '--budget-usd', String(opts.budgetUsdPerCell),
        '--out-dir', fixtureOut,
        '--data-dir', dataDir,
        '--keep-data-dirs',
        '--verifier', 'docker',
      ],
      cwd: opts.repoRoot,
      env: baseEnv(opts),
      logPath,
      docker: true,
      killAfterMs: opts.microDurationSec * 1000 + 150_000,
    })
    return {
      fixture,
      error: undefined as string | undefined,
      artifact: readJson<RealismArtifact>(join(fixtureOut, `${fixture}-grey-box.json`)),
      wallMs: result.wallMs,
      db: join(dataDir, `${fixture}-grey-box`, 'guardian.sqlite'),
      log: readLog(logPath),
    }
  }))
  const details = results.map(result => {
    const wiring = result.artifact?.metrics?.wiring?.status ?? 'unmeasured'
    const capability = microCapability(result.fixture, result.artifact)
    return `${result.fixture}: wiring=${wiring} capability=${capability}${result.error ? ` error=${result.error}` : ''}`
  })
  const wiringPass = results.every(result => result.artifact?.metrics?.wiring?.status === 'pass')
  const submitted = results.reduce((sum, result) => sum + (result.artifact?.grade?.submitted ?? 0), 0)
  const truePositives = results.reduce((sum, result) => sum + (result.artifact?.grade?.truePositives ?? 0), 0)
  const falsePositives = results.reduce((sum, result) => sum + (result.artifact?.grade?.falsePositives ?? 0), 0)
  const precision = submitted > 0 ? truePositives / (truePositives + falsePositives || 1) : 1
  return {
    id: plan.id,
    kind: 'micro',
    app: plan.app,
    source: 'local',
    targets: results.length,
    confirmed: results.reduce((sum, result) => sum + microCapability(result.fixture, result.artifact), 0),
    precision,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: falsePositives,
    netNew: null,
    floorConfirmed: null,
    floorPreserved: null,
    conversion: null,
    costUsd: results.reduce((sum, result) => sum + spentUsd(result.db), 0),
    p50AssignmentMs: (() => {
      const values = results.map(result => assignmentP50Ms(result.db)).filter((value): value is number => value !== null)
      return values.length > 0 ? Math.max(...values) : null
    })(),
    completedAssignments: results.reduce(
      (sum, result) => sum + confirmedVulnerabilityCounts(result.db).completedAssignments, 0,
    ),
    wallMs: Math.max(0, ...results.map(result => result.wallMs)),
    crashes: results.reduce((sum, result) => sum + countCrashes(result.log), 0),
    wiring: wiringPass ? 'pass' : (results.some(result => result.artifact?.metrics?.wiring?.status === 'fail') ? 'fail' : 'unmeasured'),
    capability: results.reduce((sum, result) => sum + microCapability(result.fixture, result.artifact), 0),
    detail: details.join('; '),
  }
}

async function runLiftCellTwice(plan: CellPlan, opts: SmokeArgs): Promise<{ cell: CellMetrics; rerun: boolean }> {
  const first = await runRealisticCell(plan, opts)
  if (!opts.rerunOnMinusOne || first.netNew === null) return { cell: first, rerun: false }
  const baselinePath = opts.floorScorecard ?? join(opts.snapshotRoot, 'baseline', `${plan.app}-seed${opts.seed}-grey-box.json`)
  const baseline = readJson<ScorecardLike>(baselinePath)
  const baselineConversion = conversionOf(baseline)
  const improved = baselineConversion !== null && (first.conversion ?? -1) > baselineConversion
  if (first.netNew === opts.liftBaseline - 1 && improved) {
    // Re-run only the lift cell, into a sibling directory so the first artifact is preserved.
    const rerunPlan: CellPlan = { ...plan, outDir: `${plan.outDir}-rerun` }
    const second = await runRealisticCell(rerunPlan, opts)
    return { cell: second, rerun: true }
  }
  return { cell: first, rerun: false }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

export interface SmokeReport {
  version: number
  generatedAt: string
  mode: 'run' | 'dry-run'
  gitSha: string
  args: Pick<SmokeArgs, 'tier' | 'seed' | 'cellIndex' | 'outDir'>
  tier0: {
    workerGate: 'pass' | 'fail' | 'skipped' | 'not-run'
    corpus: ArchetypeResult[]
    pass: boolean
  }
  cells: CellMetrics[]
  gates: GateResult[]
  totals: {
    confirmed: number
    netNew: number | null
    costUsd: number
    wallMs: number
    cells: number
  }
  notes: string[]
}

function gitSha(): string {
  const result = spawnSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: ROOT, encoding: 'utf8' })
  return result.status === 0 ? result.stdout.trim() : 'unknown'
}

export function renderCompactTable(cells: CellMetrics[]): string {
  const header = ['cell', 'app/source', 'conf/target', 'prec', 'net-new', 'preserved', 'conv', 'p50', 'done', 'cost']
  const rows = cells.map(cell => [
    cell.id,
    `${cell.app}/${cell.source}`,
    `${cell.confirmed}/${cell.targets}`,
    pct(cell.precision),
    cell.netNew === null ? 'n/a' : String(cell.netNew),
    cell.floorPreserved === null ? 'n/a' : `${cell.floorPreserved}/${cell.floorConfirmed ?? '?'}`,
    pct(cell.conversion),
    cell.p50AssignmentMs === null ? 'n/a' : `${Math.round(cell.p50AssignmentMs / 1000)}s`,
    String(cell.completedAssignments),
    `$${cell.costUsd.toFixed(3)}`,
  ])
  const widths = header.map((title, index) => Math.max(title.length, ...rows.map(row => (row[index] ?? '').length)))
  const line = (row: string[]) => row.map((value, index) => value.padEnd(widths[index]!)).join('  ')
  return [line(header), widths.map(width => '-'.repeat(width)).join('  '), ...rows.map(line)].join('\n')
}

export function toCsv(rows: Array<Record<string, string | number | boolean | null>>): string {
  if (rows.length === 0) return ''
  const keys = Object.keys(rows[0]!)
  const escape = (value: string | number | boolean | null | undefined): string => {
    const text = value === null || value === undefined ? '' : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return [keys.join(','), ...rows.map(row => keys.map(key => escape(row[key])).join(','))].join('\n')
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

async function runTierZero(opts: SmokeArgs, report: SmokeReport): Promise<void> {
  const corpus = runCorpus(opts.corpusPath)
  report.tier0.corpus = corpus.results
  let gatePass = corpus.pass
  if (!opts.skipWorkerGate && !opts.dryRun) {
    const logPath = join(opts.outDir, 'tier0-worker-gate.log')
    const result = await spawnLogged({
      command: 'bash', args: ['scripts/worker-gate.sh'], cwd: opts.repoRoot, env: process.env, logPath, docker: false,
      killAfterMs: 1_800_000,
    })
    report.tier0.workerGate = result.code === 0 ? 'pass' : 'fail'
    gatePass = gatePass && result.code === 0
  } else {
    report.tier0.workerGate = opts.dryRun ? 'not-run' : 'skipped'
  }
  report.tier0.pass = gatePass
  if (!corpus.pass) {
    const confirmed = corpus.results.filter(result => !result.dismissed).map(result => `${result.id}: ${result.reason}`)
    report.notes.push(`Tier 0 archetype(s) confirmed (must be dismissed): ${confirmed.join('; ')}`)
  }
}

async function runTierOne(opts: SmokeArgs, report: SmokeReport): Promise<void> {
  const plans = planTierOne(opts)
  const liftPlan = plans.find(plan => plan.kind === 'lift')!
  const rotationPlan = plans.find(plan => plan.kind === 'rotation')!
  const trapPlan = plans.find(plan => plan.kind === 'trap')!
  const microPlan = plans.find(plan => plan.kind === 'micro')!
  const [lift, rotation, trap, micro] = await Promise.all([
    runLiftCellTwice(liftPlan, opts),
    runRealisticCell(rotationPlan, opts),
    runTrapCell(trapPlan, opts),
    runMicroCell(microPlan, opts),
  ])
  report.cells = [lift.cell, rotation, trap, micro]
  const baselinePath = opts.floorScorecard ?? join(opts.snapshotRoot, 'baseline', `acme-saas-seed${opts.seed}-grey-box.json`)
  const baseline = readJson<ScorecardLike>(baselinePath)
  report.gates = evaluateGates({
    cells: report.cells,
    liftBaseline: opts.liftBaseline,
    baselineConversion: conversionOf(baseline),
    trapConfirmed: trap.confirmed,
    rerunExecuted: lift.rerun,
    perCellBudgetUsd: opts.budgetUsdPerCell,
  })
  report.totals = {
    confirmed: report.cells.reduce((sum, cell) => sum + cell.confirmed, 0),
    netNew: lift.cell.netNew,
    costUsd: report.cells.reduce((sum, cell) => sum + cell.costUsd, 0),
    wallMs: Math.max(...report.cells.map(cell => cell.wallMs)),
    cells: report.cells.length,
  }
  for (const cell of report.cells) if (cell.error) report.notes.push(`${cell.id}: ${cell.error}`)
}

export function tierTwoCommand(): string[] {
  return [
    '# Full matrix (all 3 apps, dev seed 1, 15 min/cell, 3 cells in parallel):',
    'GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \\',
    '  newgrp docker -c \'npm run benchmark:realistic -- --app all --seed 1 --mode grey-box \\',
    '    --max-duration-ms 900000 --budget-usd 5 --concurrency 3 --worker-concurrency 6 \\',
    '    --isolate-data-dir --out-dir .guardian/smoke-battery/tier2-dev\'',
    '',
    '# Salted held-out (never commit the salt; seeds >= 1,000,000):',
    'GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_RB_HELDOUT_SALT=... \\',
    '  newgrp docker -c \'npm run benchmark:realistic -- --app all --seeds 1000001,1000002 \\',
    '    --held-out --mode grey-box --max-duration-ms 900000 --concurrency 3 \\',
    '    --isolate-data-dir --out-dir .guardian/smoke-battery/tier2-heldout\'',
    '',
    '# Endurance (45 min, one app, floor+agent split budgets):',
    'GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \\',
    '  newgrp docker -c \'npm run benchmark:realistic -- --app acme-saas --seed 1 \\',
    '    --max-duration-ms 2700000 --budget-usd 10 --out-dir .guardian/smoke-battery/tier2-endurance\'',
    '',
    '# Realism exit gate (all fixtures, wiring + capability):',
    'GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \\',
    '  newgrp docker -c \'npm run benchmark:realism -- --fixture all --verifier docker \\',
    '    --max-duration-ms 600000 --out-dir .guardian/smoke-battery/tier2-realism\'',
  ]
}

async function runCalibration(opts: SmokeArgs): Promise<void> {
  const variantsRaw = JSON.parse(readFileSync(resolve(opts.variantsPath!), 'utf8')) as Array<{
    label: string
    dir?: string
    commit?: string
  }>
  if (!Array.isArray(variantsRaw) || variantsRaw.length === 0) fail('--variants must be a non-empty JSON array')
  const rows: Array<Record<string, string | number | boolean | null>> = []
  const scratch = join(opts.outDir, 'calibration')
  mkdirSync(scratch, { recursive: true, mode: 0o700 })
  for (const variant of variantsRaw) {
    if (!variant.label) fail('every variant needs a label')
    let cwd = variant.dir ? resolve(variant.dir) : ''
    if (!cwd && variant.commit) {
      cwd = join(scratch, `worktree-${variant.label.replace(/[^a-z0-9_.-]+/gi, '-')}`)
      const add = spawnSync('git', ['worktree', 'add', '--detach', cwd, variant.commit], {
        cwd: ROOT, encoding: 'utf8',
      })
      if (add.status !== 0) {
        rows.push({ variant: variant.label, cell: 'all', error: add.stderr.trim().slice(0, 200) })
        continue
      }
    }
    if (!cwd) cwd = ROOT
    const variantOut = join(opts.outDir, 'calibration', variant.label)
    const variantOpts: SmokeArgs = {
      ...opts,
      repoRoot: cwd,
      outDir: variantOut,
      snapshotRoot: join(variantOut, 'snapshots'),
      corpusPath: join(cwd, 'benchmarks/realism-suite/traps/fp-archetypes.json'),
      floorScorecard: undefined,
      dryRun: false,
      calibrate: false,
    }
    const report: SmokeReport = emptyReport(variantOpts, 'run')
    // Tier 1 only; the calibration study wants comparable cells, not a gate rerun.
    try {
      await runTierOne(variantOpts, report)
    } catch (error) {
      report.notes.push(error instanceof Error ? error.message : String(error))
    }
    for (const cell of report.cells) {
      rows.push({
        variant: variant.label,
        cell: cell.id,
        confirmed: cell.confirmed,
        targets: cell.targets,
        precision: cell.precision,
        net_new: cell.netNew,
        floor_preserved: cell.floorPreserved,
        cost_usd: cell.costUsd,
        p50_assignment_ms: cell.p50AssignmentMs,
        completed: cell.completedAssignments,
        wall_ms: cell.wallMs,
        wiring: cell.wiring ?? '',
        capability: cell.capability ?? '',
        error: cell.error ?? '',
      })
    }
  }
  const csvPath = join(opts.outDir, 'calibration.csv')
  writeFileSync(csvPath, `${toCsv(rows)}\n`, { mode: 0o600 })
  process.stdout.write(`calibration CSV: ${csvPath}\n`)
}

function emptyReport(opts: SmokeArgs, mode: 'run' | 'dry-run'): SmokeReport {
  return {
    version: SMOKE_VERSION,
    generatedAt: new Date().toISOString(),
    mode,
    gitSha: gitSha(),
    args: { tier: opts.tier, seed: opts.seed, cellIndex: opts.cellIndex, outDir: opts.outDir },
    tier0: { workerGate: 'not-run', corpus: [], pass: false },
    cells: [],
    gates: [],
    totals: { confirmed: 0, netNew: null, costUsd: 0, wallMs: 0, cells: 0 },
    notes: [],
  }
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const opts = parseSmokeArgs(argv)
  if (opts.help) {
    process.stdout.write(usage)
    return 0
  }
  if (!opts.dryRun) process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
  mkdirSync(opts.outDir, { recursive: true, mode: 0o700 })
  const mode = opts.dryRun ? 'dry-run' : 'run'
  const report = emptyReport(opts, mode)

  if (opts.calibrate) {
    await runCalibration(opts)
    return 0
  }

  if (opts.tier === 2) {
    process.stdout.write(`${tierTwoCommand().join('\n')}\n`)
    return 0
  }

  await runTierZero(opts, report)

  if (opts.dryRun) {
    report.cells = planTierOne(opts).map(plan => emptyCell(plan))
    report.totals = { confirmed: 0, netNew: null, costUsd: 0, wallMs: 0, cells: report.cells.length }
    report.notes.push('dry-run: no model, worker, CLI or fixture runs were started')
    if (!report.tier0.pass) {
      printReport(report, opts)
      return 2
    }
    printReport(report, opts)
    return 0
  }

  if (opts.tier >= 1) await runTierOne(opts, report)

  writeFileSync(join(opts.outDir, 'smoke-report.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 })
  printReport(report, opts)

  const tier0Ok = report.tier0.pass
  const tier1Ok = opts.tier === 0 || (report.gates.length > 0 && report.gates.every(gate => gate.pass))
  return tier0Ok && tier1Ok ? 0 : 1
}

function printReport(report: SmokeReport, opts: SmokeArgs): void {
  if (opts.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
    return
  }
  process.stdout.write(`smoke-battery v${report.version} ${report.mode} git=${report.gitSha}\n`)
  process.stdout.write(`tier0 worker-gate=${report.tier0.workerGate} corpus=${report.tier0.pass ? 'pass' : 'FAIL'}\n`)
  for (const result of report.tier0.corpus) {
    process.stdout.write(`  ${result.dismissed ? 'dismissed' : 'CONFIRMED'}  ${result.id}  (${result.assessor})\n`)
  }
  if (report.cells.length > 0) {
    process.stdout.write('\n')
    process.stdout.write(`${renderCompactTable(report.cells)}\n`)
  }
  if (report.gates.length > 0) {
    process.stdout.write('\n')
    for (const gate of report.gates) {
      process.stdout.write(`${gate.pass ? 'PASS' : 'FAIL'}  ${gate.id.padEnd(18)} ${gate.observed}\n`)
    }
    process.stdout.write(`\ntotal cost: $${report.totals.costUsd.toFixed(4)}; net-new: ${report.totals.netNew ?? 'n/a'}\n`)
  }
  if (report.cells.some(cell => cell.detail)) {
    for (const cell of report.cells) if (cell.detail) process.stdout.write(`  ${cell.id}: ${cell.detail}\n`)
  }
  if (report.notes.length > 0) {
    process.stdout.write('\nnotes:\n')
    for (const note of report.notes) process.stdout.write(`  - ${note}\n`)
  }
}

const invokedDirectly = Boolean(process.argv[1]) && resolve(process.argv[1]!) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  main().then(code => { process.exitCode = code }).catch(error => {
    process.stderr.write(`smoke-battery: ${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 2
  })
}
