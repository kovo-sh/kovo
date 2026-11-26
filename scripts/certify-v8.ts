#!/usr/bin/env node
/**
 * Kovo Hunter v8 — M2 / M3 / M4 Scaling & Certification Scorecard CLI (`scripts/certify-v8.ts`).
 *
 * Pure, deterministic grading and aggregation for Kovo Hunter v8 multi-hop certification per
 * `plans/v8.md` §Milestones (M2, M3, M4):
 *  - Universal Precision Gate: 100.0% worst-run precision (0 hardened-twin decoy FPs,
 *    0 unmatched FPs, 0 OSS clean-control FPs across every single cell/repeat).
 *  - Universal Anti-Heuristic Gate: `multihop-saas --no-llm <= 5%`.
 *  - M2 Gate (`$5/30m`, Dev 12 chains + 9 twins): GB >= 33%, WB >= 50%, WB-GB lift >= +15 pp, 0 twin FPs.
 *  - M3 Gate (Dev scaling matrix `$2/10m`, `$5/30m`, `$15/60m`, n >= 3):
 *    strict monotonic median recall, `$15/60m - $2/10m >= +20 pp`,
 *    depth breakdown at `$15/60m` WB (`3–4 hop >= 60%`, `5–6 hop >= 35%`),
 *    dead-end re-probing waste `<= 5%` of Phase B assignments.
 *  - M4 Full Certification Gate (`$15/60m`, n >= 3):
 *    Dev WB >= 65% / GB >= 45%; Salted Held-Out (`seed >= 1_000_000`) WB >= 55% / GB >= 40%
 *    with `dev -> held-out <= 10 pp`; Sealed `connecthub` blind first run WB >= 50% (0/3 twin FPs)
 *    with `dev -> sealed <= 20 pp` overfitting guard; OSS Multi-Hop Corpus (8 targets + 2 clean
 *    controls): >= 50% sealed recall at 100% precision, >= 80% patch-retest closure, 0 clean-control FPs;
 *    Efficiency floor: >= 0.50 TP/$ (at $5 tier) and >= 1.0 TP/10m (at 30m tier);
 *    v7 regression floor: xben 25/25, held-out-saas 20/20 + 20/20 patches,
 *    reason-bench --no-llm <= 10% & agentic >= 50%, realistic-bench floor spread 0.
 *
 * Defensive QA framing: aggregates structured benchmark telemetry only (never raw HTTP bodies).
 * Zero external npm dependencies (Node 24+ native TypeScript).
 */

import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  DEFAULT_LEDGER_PATH,
  appendLedgerRow,
  appendPerRunLedgerRow,
  computeBenchmarkVersion,
  promoteLedgerRows,
  resolveGitState,
  type LedgerRow,
} from './bench-ledger.ts'
import {
  ScorecardReader,
  buildLedgerRow,
  ratioOrNull,
  type CellReadState,
} from './score-primitives.ts'

// ---------------------------------------------------------------------------
// Constants & Thresholds
// ---------------------------------------------------------------------------

export const V8_CERTIFY_SCHEMA_VERSION = 1 as const
export const EPS = 1e-9

export const MULTIHOP_DEV_APPS = ['paygrid', 'shipforge', 'nexusiam'] as const
export const MULTIHOP_SEALED_APPS = ['connecthub'] as const

export const HOP_DROP_REASONS = [
  'capability_not_extracted',
  'pivot_not_discovered',
  'edge_binding_rejected',
  'replay_failed',
  'budget_exhausted',
  'persona_shortcut_rejected',
  'other',
] as const

export type HopDropReason = typeof HOP_DROP_REASONS[number]
export type V8GateName = 'm2' | 'm3' | 'm4'
export type MultihopMode = 'black-box' | 'grey-box' | 'white-box'
export type MultihopLlmMode = 'agentic' | 'deterministic-no-llm'
export type MultihopSplit = 'dev' | 'held-out' | 'sealed'

export interface TierSpec {
  id: string
  label: string
  budgetUsd: number
  maxDurationMs: number
}

export const SCALING_TIERS = {
  t2_10m: { id: '2_10m', label: '$2/10m', budgetUsd: 2, maxDurationMs: 600_000 },
  t5_30m: { id: '5_30m', label: '$5/30m', budgetUsd: 5, maxDurationMs: 1_800_000 },
  t15_60m: { id: '15_60m', label: '$15/60m', budgetUsd: 15, maxDurationMs: 3_600_000 },
} as const satisfies Record<string, TierSpec>

export const V8_THRESHOLDS = {
  precisionWorstRunMin: 1.0,
  antiHeuristicNoLlmMax: 0.05,
  heldOutSeedMin: 1_000_000,
  minRepeats: 3,
  m2: {
    greyBoxRecallMin: 0.33,
    whiteBoxRecallMin: 0.50,
    whiteBoxLiftOverGreyBoxMin: 0.15,
    expectedDevChains: 12,
    expectedDevTwins: 9,
  },
  m3: {
    scalingLift15Over2Min: 0.20,
    depth3to4RecallMin: 0.60,
    depth5to6RecallMin: 0.35,
    deadEndWasteMax: 0.05,
  },
  m4: {
    devWhiteBoxRecallMin: 0.65,
    devGreyBoxRecallMin: 0.45,
    heldOutWhiteBoxRecallMin: 0.55,
    heldOutGreyBoxRecallMin: 0.40,
    devToHeldOutMaxGap: 0.10,
    sealedWhiteBoxRecallMin: 0.50,
    devToSealedMaxGap: 0.20,
    ossMinTargets: 8,
    ossMinCleanControls: 2,
    ossSealedRecallMin: 0.50,
    ossPatchRetestClosureMin: 0.80,
    efficiencyTpPerDollarMin: 0.50,
    efficiencyTpPer10mMin: 1.0,
    v7XbenMinConfirmed: 25,
    v7HeldOutSaasMinConfirmed: 20,
    v7HeldOutSaasMinPatches: 20,
    v7ReasonNoLlmMax: 0.10,
    v7ReasonAgenticMin: 0.50,
    v7RealisticMaxSpread: 0,
  },
} as const

// ---------------------------------------------------------------------------
// Input & Output Types
// ---------------------------------------------------------------------------

export interface HopDepthFunnel {
  totalChains: number
  H1: number
  H2: number
  H3: number
  H4Plus: number
  FinalOracle: number
  CompositeReceiptConfirmed: number
  dropReasons: Record<HopDropReason, number>
}

export interface HopDepthFunnelLike {
  totalChains?: number
  H1?: number
  H2?: number
  H3?: number
  H4Plus?: number
  FinalOracle?: number
  CompositeReceiptConfirmed?: number
  h1?: number
  h2?: number
  h3?: number
  h4Plus?: number
  h4plus?: number
  finalOracle?: number
  compositeReceiptConfirmed?: number
  receiptConfirmed?: number
  oracleObserved?: number
  twoSideConfirmed?: number
  dropReasons?: Partial<Record<string, number>>
}

export interface DepthTierBucket {
  targets: number
  confirmed: number
  recall: number
}

export interface DepthTierBreakdown {
  hops3to4: DepthTierBucket
  hops5to6: DepthTierBucket
}

export interface MultihopChainVerdictInput {
  chainId: string
  expectedHops: number
  maxHopReached?: number
  oracleObserved?: boolean
  forbiddenShortcutViolation?: boolean
  compositeReceiptConfirmed?: boolean
  twoSideConfirmed: boolean
  replayMode?: 'fresh_clean_replay' | 'one_shot_transcript' | string
  dropReason?: string | null
}

export interface MultihopTwinVerdictInput {
  twinId: string
  baseChainId?: string
  vulnClass?: string
  falsePositive: boolean
  matchedFindingIds?: string[]
  reason?: string
}

export interface FrontierWasteTelemetry {
  deadEndReprobeCount?: number
  totalAssignmentsDispatched?: number
  phaseBAssignments?: number
  deadEndReprobeWasteRate?: number
}

export interface MultihopRunTelemetryLike {
  scheduler?: {
    totalPhaseBAssignments?: number
    deadEndReprobes?: number
    deadEndWastePct?: number
  } | null
}

export interface MultihopCellInput {
  schemaVersion?: number
  status?: 'VALID' | 'INVALID'
  failed?: boolean
  benchmarkVersion?: string
  effectiveConfigHash?: string
  app: string
  sealed?: boolean
  seed: number
  seedSet?: 'dev' | 'held-out'
  mode: MultihopMode | string
  cell?: string
  llm?: MultihopLlmMode | string
  repeatId?: string | number
  repeatIndex?: number
  runId?: string | null
  budgetUsd?: number
  maxDurationMs?: number
  startedAt?: number
  endedAt?: number
  durationMs?: number
  wallMs?: number
  costUsd?: number
  totalCostUsd?: number
  chainsTotal: number
  chainsOracleObserved?: number
  chainsCompositeConfirmed?: number
  chainsConfirmed: number
  recall?: number | null
  precision?: number | null
  hardenedTwinsTotal?: number
  decoys?: number
  hardenedTwinDecoyFps?: number
  decoyFalsePositives?: number
  hardenedTwinFalsePositives?: number
  unmatchedFalsePositives?: number
  unmatchedFindingsDetail?: Array<{
    findingId: string
    status: string
    findingKind: string | null
    verificationTier: string | null
    verificationClass: string | null
    cwe: string | null
    route: string | null
    title: string
  }>
  shortcutViolations?: number
  modeBViolations?: number
  inert?: boolean
  tpPerDollar?: number | null
  tpPer10m?: number | null
  hopFunnel?: HopDepthFunnelLike | null
  depthBreakdown?: {
    hops3to4?: { targets: number; confirmed: number; recall?: number }
    hops5to6?: { targets: number; confirmed: number; recall?: number }
  } | null
  chains?: MultihopChainVerdictInput[]
  hardenedTwins?: MultihopTwinVerdictInput[]
  assignmentsCompleted?: number
  assignmentsTotal?: number
  phaseBAssignments?: number
  totalAssignmentsDispatched?: number
  deadEndReprobeCount?: number
  deadEndReprobeWasteRate?: number
  deadEndWastePct?: number
  frontier?: FrontierWasteTelemetry | null
  telemetry?: MultihopRunTelemetryLike | null
  gitSha?: string
}

export interface NormalizedMultihopCell {
  status: 'VALID' | 'INVALID'
  cellState: CellReadState
  failed: boolean
  benchmarkVersion?: string
  effectiveConfigHash?: string
  app: string
  sealed: boolean
  seed: number
  seedSet: 'dev' | 'held-out'
  split: MultihopSplit
  mode: MultihopMode
  cell: string
  llm: MultihopLlmMode
  repeatId?: string
  runId: string | null
  budgetUsd: number
  maxDurationMs: number
  tierLabel: string
  startedAt: number | null
  durationMs: number
  costUsd: number
  chainsTotal: number
  chainsOracleObserved: number
  chainsCompositeConfirmed: number
  chainsConfirmed: number
  recall: number
  precision: number | null
  rawPrecision: number | null
  strictPrecision: number | null
  hardenedTwinsTotal: number
  hardenedTwinDecoyFps: number
  unmatchedFalsePositives: number
  shortcutViolations: number
  modeBViolations: number
  inert: boolean
  hopFunnel: HopDepthFunnel
  depthBreakdown: DepthTierBreakdown
  chains: MultihopChainVerdictInput[]
  phaseBAssignments: number | null
  deadEndReprobeCount: number | null
  deadEndReprobeWasteRate: number | null
  gitSha?: string
}

export interface OssAnchorResultInput {
  anchorId: string
  project?: string
  split: 'dev' | 'sealed'
  status?: string
  twoSideConfirmed: boolean
  patchRetestStatus?: string
  patchBrokeHopId?: string | null
}

export interface OssCleanControlResultInput {
  controlId: string
  project?: string
  passed?: boolean
  fpCount: number
  unexpectedOracleTriggers?: number
}

export interface OssCorpusInput {
  schemaVersion?: string
  runId?: string
  split?: 'dev' | 'sealed'
  mode?: string
  totalAnchors: number
  tpCount: number
  fnCount?: number
  unmatchedFpCount?: number
  spuriousAnchorFpCount?: number
  cleanControlCount: number
  cleanControlFpCount: number
  totalFpCount?: number
  falsePositives?: number
  recall?: number
  precision?: number
  worstRunPrecision?: number
  patchRetestAttempted?: number
  patchRetestClosed?: number
  patchRetestClosureRate?: number
  tpPerUsd?: number | null
  tpPer10m?: number | null
  hopDepthFunnel?: HopDepthFunnelLike | null
  anchorResults?: OssAnchorResultInput[]
  cleanControlResults?: OssCleanControlResultInput[]
}

export interface NormalizedOssSummary {
  runs: number
  failedRuns: number
  totalAnchors: number
  tpCount: number
  sealedAnchors: number
  sealedTpCount: number
  sealedRecall: number | null
  overallRecall: number
  worstRunPrecision: number | null
  totalFpCount: number
  unmatchedFpCount: number
  spuriousAnchorFpCount: number
  cleanControlCount: number
  cleanControlFpCount: number
  cleanControlUnexpectedOracles: number
  patchRetestAttempted: number
  patchRetestClosed: number
  patchRetestClosureRate: number | null
  tpPerUsd: number | null
  tpPer10m: number | null
  anchorResults: OssAnchorResultInput[]
  cleanControlResults: OssCleanControlResultInput[]
}

export interface V7RegressionFloorInput {
  xben?: {
    confirmed: number
    targets: number
    falsePositives?: number
  }
  heldOutSaas?: {
    confirmed: number
    targets: number
    patchesClosed: number
    patchesTotal: number
    falsePositives?: number
  }
  reasonBench?: {
    noLlmRecall?: number | null
    noLlmConfirmed?: number
    noLlmTargets?: number
    agenticRecall?: number | null
    agenticConfirmed?: number
    agenticTargets?: number
    worstPrecision?: number | null
  }
  realisticBench?: {
    maxFloorSpread?: number | null
    spreadByApp?: Record<string, number | null>
  }
}

export interface NormalizedV7Floor {
  xben: { confirmed: number; targets: number; falsePositives: number } | null
  heldOutSaas: {
    confirmed: number
    targets: number
    patchesClosed: number
    patchesTotal: number
    falsePositives: number
  } | null
  reasonBench: {
    noLlmRecall: number | null
    noLlmConfirmed: number | null
    noLlmTargets: number | null
    agenticRecall: number | null
    agenticConfirmed: number | null
    agenticTargets: number | null
    worstPrecision: number | null
  } | null
  realisticBench: {
    maxFloorSpread: number | null
  } | null
}

export interface CertifyV8Options {
  /** Override git SHA recorded in report metadata. */
  gitSha?: string
  /** Override ISO timestamp recorded in report metadata. */
  generatedAt?: string
  /** Require v7 regression floor in M4 (default true for M4, false for M2/M3). */
  requireV7Floor?: boolean
}

export interface CertifyV8Input {
  gate: V8GateName
  cells: readonly MultihopCellInput[]
  oss?: readonly OssCorpusInput[] | OssCorpusInput | null
  v7Floor?: V7RegressionFloorInput | Record<string, unknown> | null
  options?: CertifyV8Options
}

export interface GateCheckResult {
  id: string
  category:
    | 'precision'
    | 'anti-heuristic'
    | 'recall'
    | 'lift'
    | 'scaling'
    | 'depth'
    | 'waste'
    | 'generalization'
    | 'overfitting'
    | 'oss'
    | 'efficiency'
    | 'v7-floor'
  description: string
  threshold: string
  observed: string
  status: 'PASS' | 'FAIL'
  detail?: string
}

export interface RepeatSummary {
  repeatKey: string
  cells: number
  apps: string[]
  seeds: number[]
  startedAt: number | null
  chainsTotal: number
  chainsConfirmed: number
  recall: number
  hardenedTwinsTotal: number
  hardenedTwinDecoyFps: number
  unmatchedFalsePositives: number
  worstCellPrecision: number | null
  costUsd: number
  durationMs: number
  tpPerDollar: number | null
  tpPer10m: number | null
  depthBreakdown: DepthTierBreakdown
  hopFunnel: HopDepthFunnel
}

export interface ModeSplitSummary {
  split: MultihopSplit
  mode: MultihopMode
  tierLabel: string | null
  repeats: number
  repeatSummaries: RepeatSummary[]
  cells: number
  chainsTotal: number
  chainsConfirmed: number
  medianRecall: number | null
  minRecall: number | null
  maxRecall: number | null
  aggregateRecall: number
  worstRunPrecision: number | null
  hardenedTwinsTotal: number
  hardenedTwinDecoyFps: number
  unmatchedFalsePositives: number
  costUsd: number
  durationMs: number
  tpPerDollar: number | null
  tpPer10m: number | null
  depthBreakdown: {
    hops3to4Targets: number
    hops3to4Confirmed: number
    hops3to4MedianRecall: number | null
    hops5to6Targets: number
    hops5to6Confirmed: number
    hops5to6MedianRecall: number | null
  }
  hopFunnel: HopDepthFunnel
}

export interface ScalingCurvePoint {
  split: MultihopSplit
  mode: MultihopMode
  budgetUsd: number
  maxDurationMs: number
  tierLabel: string
  repeats: number
  cells: number
  chainsTotal: number
  chainsConfirmed: number
  medianRecall: number | null
  minRecall: number | null
  maxRecall: number | null
  hops3to4MedianRecall: number | null
  hops5to6MedianRecall: number | null
  deadEndWasteRate: number | null
  costUsd: number
  durationMs: number
  tpPerDollar: number | null
  tpPer10m: number | null
  hardenedTwinDecoyFps: number
  unmatchedFalsePositives: number
  worstRunPrecision: number | null
}

export interface WasteSummary {
  measuredCells: number
  unmeasuredCells: number
  totalDeadEndReprobes: number
  totalPhaseBAssignments: number
  wasteRate: number | null
  maxCellWasteRate: number | null
}

export interface V8CertificationReport {
  schemaVersion: typeof V8_CERTIFY_SCHEMA_VERSION
  status: 'VALID' | 'INVALID'
  failedCells: number
  benchmarkVersion: string
  effectiveConfigHash: string | null
  gate: V8GateName
  verdict: 'PASS' | 'FAIL'
  generatedAt: string
  gitSha: string
  totalCells: number
  precision: {
    worstRunPrecision: number | null
    worstRunCell: string | null
    totalHardenedTwinDecoyFps: number
    totalUnmatchedFalsePositives: number
    totalOssFalsePositives: number
    totalShortcutViolations: number
    totalModeBViolations: number
    inertAgenticCells: number
    passed: boolean
  }
  antiHeuristic: {
    cells: number
    chainsConfirmed: number
    chainsTotal: number
    recall: number | null
    ceiling: number
    passed: boolean
  }
  modeSummaries: ModeSplitSummary[]
  scalingCurve: ScalingCurvePoint[]
  scalingMonotonic: {
    tiersPresent: boolean
    minRepeatsObserved: number
    recallAt2_10m: number | null
    recallAt5_30m: number | null
    recallAt15_60m: number | null
    strictlyMonotonic: boolean
    lift15Over2: number | null
  }
  generalization: {
    devWhiteBoxMedian: number | null
    devGreyBoxMedian: number | null
    heldOutWhiteBoxMedian: number | null
    heldOutGreyBoxMedian: number | null
    devToHeldOutWbGap: number | null
    devToHeldOutGbGap: number | null
    sealedBlindFirstRunWb: number | null
    sealedTwinFps: number
    devToSealedWbGap: number | null
    overfittingViolation: boolean
  }
  efficiency: {
    tier5Cells: number
    tier5Confirmed: number
    tier5CostUsd: number
    tpPerDollarAt5: number | null
    tier30mCells: number
    tier30mConfirmed: number
    tier30mDurationMs: number
    tpPer10mAt30m: number | null
  }
  waste: WasteSummary
  hopFunnel: HopDepthFunnel
  oss: NormalizedOssSummary | null
  v7Floor: NormalizedV7Floor | null
  checks: GateCheckResult[]
  failedChecks: GateCheckResult[]
  notes: string[]
}

export interface CertifyV8CliArgs {
  gate: V8GateName
  inputs: string[]
  ossPaths: string[]
  v7FloorPath?: string
  outMd?: string
  outJson?: string
  ledgerPath?: string
  promoteLedgerPath?: string
  allowMissingV7Floor: boolean
  help: boolean
}

// ---------------------------------------------------------------------------
// Math & Formatting Helpers
// ---------------------------------------------------------------------------

function finiteNum(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function nonNegNum(value: unknown, fallback = 0): number {
  const n = finiteNum(value, fallback)
  return n < 0 ? 0 : n
}

function optionalNum(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function safeRatio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0
}

export function median(values: readonly number[]): number | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 1
    ? sorted[mid]!
    : (sorted[mid - 1]! + sorted[mid]!) / 2
}

export function formatTierLabel(budgetUsd: number, maxDurationMs: number): string {
  const mins = Math.round(maxDurationMs / 60_000)
  const bStr = Number.isInteger(budgetUsd) ? String(budgetUsd) : budgetUsd.toFixed(2)
  return `$${bStr}/${mins}m`
}

export function matchesTier(
  cell: Pick<NormalizedMultihopCell, 'budgetUsd' | 'maxDurationMs'>,
  tier: TierSpec,
): boolean {
  return (
    Math.abs(cell.budgetUsd - tier.budgetUsd) < 0.01 &&
    Math.abs(cell.maxDurationMs - tier.maxDurationMs) < 1_000
  )
}

function pct(value: number | null): string {
  return value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`
}

function pp(value: number | null): string {
  if (value === null) return 'n/a'
  const sign = value >= 0 ? '+' : ''
  return `${sign}${(value * 100).toFixed(1)} pp`
}

function fixed(value: number | null, digits = 2): string {
  return value === null ? 'n/a' : value.toFixed(digits)
}

function mdTable(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  const lines = [
    `| ${headers.join(' | ')} |`,
    `| ${headers.map(() => '---').join(' | ')} |`,
  ]
  for (const row of rows) {
    lines.push(`| ${row.join(' | ')} |`)
  }
  return lines.join('\n')
}

function resolveGitSha(): string {
  try {
    return (
      execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim() || 'unknown'
    )
  } catch {
    return 'unknown'
  }
}

// ---------------------------------------------------------------------------
// Funnel & Depth Helpers
// ---------------------------------------------------------------------------

export function emptyDropReasons(): Record<HopDropReason, number> {
  return {
    capability_not_extracted: 0,
    pivot_not_discovered: 0,
    edge_binding_rejected: 0,
    replay_failed: 0,
    budget_exhausted: 0,
    persona_shortcut_rejected: 0,
    other: 0,
  }
}

export function emptyHopFunnel(): HopDepthFunnel {
  return {
    totalChains: 0,
    H1: 0,
    H2: 0,
    H3: 0,
    H4Plus: 0,
    FinalOracle: 0,
    CompositeReceiptConfirmed: 0,
    dropReasons: emptyDropReasons(),
  }
}

export function normalizeDropReason(raw: unknown): HopDropReason | null {
  if (typeof raw !== 'string') return null
  const normalized = raw.trim().toLowerCase()
  for (const reason of HOP_DROP_REASONS) {
    if (reason === normalized) return reason
  }
  return normalized.length > 0 ? 'other' : null
}

export function normalizeHopFunnel(
  raw?: HopDepthFunnelLike | null,
  fallback?: { totalChains?: number; oracleObserved?: number; confirmed?: number },
): HopDepthFunnel {
  const dropReasons = emptyDropReasons()
  if (raw?.dropReasons) {
    for (const [k, v] of Object.entries(raw.dropReasons)) {
      const reason = normalizeDropReason(k)
      if (reason && typeof v === 'number' && Number.isFinite(v)) {
        dropReasons[reason] += v
      }
    }
  }
  return {
    totalChains: nonNegNum(raw?.totalChains, fallback?.totalChains ?? 0),
    H1: nonNegNum(raw?.H1 ?? raw?.h1, 0),
    H2: nonNegNum(raw?.H2 ?? raw?.h2, 0),
    H3: nonNegNum(raw?.H3 ?? raw?.h3, 0),
    H4Plus: nonNegNum(raw?.H4Plus ?? raw?.h4Plus ?? raw?.h4plus, 0),
    FinalOracle: nonNegNum(
      raw?.FinalOracle ?? raw?.finalOracle ?? raw?.oracleObserved,
      fallback?.oracleObserved ?? 0,
    ),
    CompositeReceiptConfirmed: nonNegNum(
      raw?.CompositeReceiptConfirmed ??
        raw?.compositeReceiptConfirmed ??
        raw?.receiptConfirmed ??
        raw?.twoSideConfirmed,
      fallback?.confirmed ?? 0,
    ),
    dropReasons,
  }
}

export function buildHopFunnelFromVerdicts(verdicts: readonly MultihopChainVerdictInput[]): HopDepthFunnel {
  const funnel = emptyHopFunnel()
  funnel.totalChains = verdicts.length
  for (const v of verdicts) {
    const reached = finiteNum(v.maxHopReached, v.twoSideConfirmed ? v.expectedHops : 0)
    if (reached >= 1) funnel.H1 += 1
    if (reached >= 2) funnel.H2 += 1
    if (reached >= 3) funnel.H3 += 1
    if (reached >= 4) funnel.H4Plus += 1
    if (v.oracleObserved ?? v.twoSideConfirmed) funnel.FinalOracle += 1
    if (v.twoSideConfirmed) {
      funnel.CompositeReceiptConfirmed += 1
    } else {
      const reason = normalizeDropReason(v.dropReason) ?? 'other'
      funnel.dropReasons[reason] += 1
    }
  }
  return funnel
}

export function aggregateHopFunnels(funnels: readonly HopDepthFunnel[]): HopDepthFunnel {
  const out = emptyHopFunnel()
  for (const f of funnels) {
    out.totalChains += f.totalChains
    out.H1 += f.H1
    out.H2 += f.H2
    out.H3 += f.H3
    out.H4Plus += f.H4Plus
    out.FinalOracle += f.FinalOracle
    out.CompositeReceiptConfirmed += f.CompositeReceiptConfirmed
    for (const reason of HOP_DROP_REASONS) {
      out.dropReasons[reason] += f.dropReasons[reason] ?? 0
    }
  }
  return out
}

export function computeDepthBreakdownFromVerdicts(
  verdicts: readonly MultihopChainVerdictInput[],
): DepthTierBreakdown {
  let t34 = 0
  let c34 = 0
  let t56 = 0
  let c56 = 0
  for (const v of verdicts) {
    if (v.expectedHops >= 5) {
      t56 += 1
      if (v.twoSideConfirmed) c56 += 1
    } else {
      t34 += 1
      if (v.twoSideConfirmed) c34 += 1
    }
  }
  return {
    hops3to4: { targets: t34, confirmed: c34, recall: safeRatio(c34, t34) },
    hops5to6: { targets: t56, confirmed: c56, recall: safeRatio(c56, t56) },
  }
}

// ---------------------------------------------------------------------------
// Normalization & Repeat Grouping
// ---------------------------------------------------------------------------

function normalizeMode(raw: string): MultihopMode {
  const lowered = raw.trim().toLowerCase()
  if (lowered === 'black-box' || lowered === 'grey-box' || lowered === 'white-box') {
    return lowered
  }
  return 'grey-box'
}

function normalizeLlm(raw?: string): MultihopLlmMode {
  if (!raw) return 'agentic'
  const lowered = raw.trim().toLowerCase()
  if (lowered === 'deterministic-no-llm' || lowered === 'no-llm' || lowered === 'floor') {
    return 'deterministic-no-llm'
  }
  return 'agentic'
}

export function normalizeCell(raw: MultihopCellInput): NormalizedMultihopCell {
  const app = String(raw.app)
  const sealed = raw.sealed === true || (MULTIHOP_SEALED_APPS as readonly string[]).includes(app)
  const seed = finiteNum(raw.seed, 0)
  const seedSet: 'dev' | 'held-out' =
    raw.seedSet === 'held-out' || raw.seedSet === 'dev'
      ? raw.seedSet
      : seed >= V8_THRESHOLDS.heldOutSeedMin
        ? 'held-out'
        : 'dev'
  const split: MultihopSplit = sealed ? 'sealed' : seedSet
  const mode = normalizeMode(String(raw.mode ?? 'grey-box'))
  const llm = normalizeLlm(raw.llm)

  const chainsTotal = nonNegNum(raw.chainsTotal, 0)
  const chainsConfirmed = nonNegNum(raw.chainsConfirmed, 0)
  const chainsOracleObserved = nonNegNum(raw.chainsOracleObserved, chainsConfirmed)
  const chainsCompositeConfirmed = nonNegNum(raw.chainsCompositeConfirmed, chainsConfirmed)
  const recall = optionalNum(raw.recall) ?? safeRatio(chainsConfirmed, chainsTotal)

  const hardenedTwinsArr = Array.isArray(raw.hardenedTwins) ? raw.hardenedTwins : []
  const hardenedTwinsTotal = Math.max(
    nonNegNum(raw.hardenedTwinsTotal ?? raw.decoys, 0),
    hardenedTwinsArr.length,
  )
  const twinFpsFromArray = hardenedTwinsArr.filter((t) => t && t.falsePositive === true).length
  const hardenedTwinDecoyFps = Math.max(
    nonNegNum(
      raw.hardenedTwinDecoyFps ?? raw.decoyFalsePositives ?? raw.hardenedTwinFalsePositives,
      0,
    ),
    twinFpsFromArray,
  )
  const unmatchedFalsePositives = nonNegNum(raw.unmatchedFalsePositives, 0)
  const inert = raw.inert === true
  const readerCell = ScorecardReader.read(
    {
      ...raw,
      app,
      seed,
      seedSet,
      split,
      mode,
      llm,
      targets: chainsTotal,
      confirmed: chainsConfirmed,
      decoys: hardenedTwinsTotal,
      decoyFalsePositives: hardenedTwinDecoyFps,
      unmatchedFalsePositives,
    },
    {
      failed: raw.failed === true || raw.status === 'INVALID',
      inert,
    },
  )
  const precision: number | null = readerCell.headlinePrecision
  const rawPrecision: number | null = readerCell.rawPrecision
  const strictPrecision: number | null = readerCell.strictPrecision
  const failed = readerCell.state === 'failed_inert'
  const status: 'VALID' | 'INVALID' = readerCell.status

  const budgetUsd = nonNegNum(raw.budgetUsd, 0)
  const maxDurationMs = nonNegNum(raw.maxDurationMs, 0)
  const durationMs = nonNegNum(raw.durationMs ?? raw.wallMs, 0)
  const costUsd = nonNegNum(raw.costUsd ?? raw.totalCostUsd, 0)

  const chains = Array.isArray(raw.chains) ? raw.chains : []
  const derivedShortcutViolations = chains.filter(
    (ch) => ch && ch.forbiddenShortcutViolation === true,
  ).length
  const derivedModeBViolations = chains.filter(
    (ch) => ch && ch.replayMode === 'one_shot_transcript',
  ).length
  const shortcutViolations = Math.max(
    nonNegNum(raw.shortcutViolations, 0),
    derivedShortcutViolations,
  )
  const modeBViolations = Math.max(nonNegNum(raw.modeBViolations, 0), derivedModeBViolations)
  const hopFunnel = raw.hopFunnel
    ? normalizeHopFunnel(raw.hopFunnel, {
        totalChains: chainsTotal,
        oracleObserved: chainsOracleObserved,
        confirmed: chainsConfirmed,
      })
    : chains.length > 0
      ? buildHopFunnelFromVerdicts(chains)
      : normalizeHopFunnel(null, {
          totalChains: chainsTotal,
          oracleObserved: chainsOracleObserved,
          confirmed: chainsConfirmed,
        })

  let depthBreakdown: DepthTierBreakdown
  if (
    raw.depthBreakdown &&
    ((raw.depthBreakdown.hops3to4?.targets ?? 0) > 0 ||
      (raw.depthBreakdown.hops5to6?.targets ?? 0) > 0)
  ) {
    const t34 = nonNegNum(raw.depthBreakdown.hops3to4?.targets, 0)
    const c34 = nonNegNum(raw.depthBreakdown.hops3to4?.confirmed, 0)
    const t56 = nonNegNum(raw.depthBreakdown.hops5to6?.targets, 0)
    const c56 = nonNegNum(raw.depthBreakdown.hops5to6?.confirmed, 0)
    depthBreakdown = {
      hops3to4: {
        targets: t34,
        confirmed: c34,
        recall: optionalNum(raw.depthBreakdown.hops3to4?.recall) ?? safeRatio(c34, t34),
      },
      hops5to6: {
        targets: t56,
        confirmed: c56,
        recall: optionalNum(raw.depthBreakdown.hops5to6?.recall) ?? safeRatio(c56, t56),
      },
    }
  } else if (chains.length > 0) {
    depthBreakdown = computeDepthBreakdownFromVerdicts(chains)
  } else {
    depthBreakdown = {
      hops3to4: { targets: 0, confirmed: 0, recall: 0 },
      hops5to6: { targets: 0, confirmed: 0, recall: 0 },
    }
  }

  const schedulerTel = raw.telemetry?.scheduler
  const phaseBAssignments = optionalNum(
    raw.phaseBAssignments ??
      raw.frontier?.phaseBAssignments ??
      schedulerTel?.totalPhaseBAssignments ??
      raw.totalAssignmentsDispatched ??
      raw.frontier?.totalAssignmentsDispatched ??
      raw.assignmentsTotal ??
      raw.assignmentsCompleted,
  )
  const deadEndReprobeCount = optionalNum(
    raw.deadEndReprobeCount ??
      raw.frontier?.deadEndReprobeCount ??
      schedulerTel?.deadEndReprobes,
  )
  const rawWastePct = optionalNum(raw.deadEndWastePct ?? schedulerTel?.deadEndWastePct)
  const explicitWasteRate = optionalNum(
    raw.deadEndReprobeWasteRate ??
      raw.frontier?.deadEndReprobeWasteRate ??
      (rawWastePct !== null ? rawWastePct / 100 : undefined),
  )
  const deadEndReprobeWasteRate =
    explicitWasteRate !== null
      ? explicitWasteRate
      : deadEndReprobeCount !== null && phaseBAssignments !== null && phaseBAssignments > 0
        ? deadEndReprobeCount / phaseBAssignments
        : deadEndReprobeCount !== null && deadEndReprobeCount === 0
          ? 0
          : null

  const repeatId =
    raw.repeatId !== undefined
      ? String(raw.repeatId)
      : raw.repeatIndex !== undefined
        ? String(raw.repeatIndex)
        : undefined

  return {
    status,
    cellState: readerCell.state,
    failed,
    ...(raw.benchmarkVersion ? { benchmarkVersion: raw.benchmarkVersion } : {}),
    ...(raw.effectiveConfigHash ? { effectiveConfigHash: raw.effectiveConfigHash } : {}),
    app,
    sealed,
    seed,
    seedSet,
    split,
    mode,
    cell: raw.cell ?? `${app}-seed${seed}-${mode}`,
    llm,
    repeatId,
    runId: raw.runId ?? null,
    budgetUsd,
    maxDurationMs,
    tierLabel: formatTierLabel(budgetUsd, maxDurationMs),
    startedAt: optionalNum(raw.startedAt),
    durationMs,
    costUsd,
    chainsTotal,
    chainsOracleObserved,
    chainsCompositeConfirmed,
    chainsConfirmed,
    recall,
    precision,
    rawPrecision,
    strictPrecision,
    hardenedTwinsTotal,
    hardenedTwinDecoyFps,
    unmatchedFalsePositives,
    shortcutViolations,
    modeBViolations,
    inert,
    hopFunnel,
    depthBreakdown,
    chains,
    phaseBAssignments,
    deadEndReprobeCount,
    deadEndReprobeWasteRate,
    gitSha: raw.gitSha,
  }
}

/**
 * Group homogeneous cells (same split/mode/tier) into independent repeats.
 *  1. If `repeatId` is set on a cell, group directly by `repeat:${repeatId}`.
 *  2. Otherwise, group by `seed` + per-(app, seed) occurrence index so both
 *     multi-seed runs (`seed=1,2,3`) and repeated same-seed runs (`3x seed=42`)
 *     produce clean per-repeat aggregates across all apps in the suite.
 */
export function groupCellsIntoRepeats(cells: readonly NormalizedMultihopCell[]): RepeatSummary[] {
  const buckets = new Map<string, NormalizedMultihopCell[]>()
  const appSeedCounts = new Map<string, number>()

  for (const cell of cells) {
    let key: string
    if (cell.repeatId !== undefined) {
      key = `repeat:${cell.repeatId}`
    } else {
      const appSeedKey = `${cell.app}::${cell.seed}`
      const occ = appSeedCounts.get(appSeedKey) ?? 0
      appSeedCounts.set(appSeedKey, occ + 1)
      key = `seed:${cell.seed}#${occ}`
    }
    const list = buckets.get(key)
    if (list) list.push(cell)
    else buckets.set(key, [cell])
  }

  const summaries: RepeatSummary[] = []
  for (const [repeatKey, group] of buckets.entries()) {
    let chainsTotal = 0
    let chainsConfirmed = 0
    let hardenedTwinsTotal = 0
    let hardenedTwinDecoyFps = 0
    let unmatchedFalsePositives = 0
    let worstCellPrecision: number | null = null
    let costUsd = 0
    let durationMs = 0
    let t34 = 0
    let c34 = 0
    let t56 = 0
    let c56 = 0
    let earliestStart: number | null = null
    const apps = new Set<string>()
    const seeds = new Set<number>()
    const funnels: HopDepthFunnel[] = []

    for (const c of group) {
      chainsTotal += c.chainsTotal
      chainsConfirmed += c.chainsConfirmed
      hardenedTwinsTotal += c.hardenedTwinsTotal
      hardenedTwinDecoyFps += c.hardenedTwinDecoyFps
      unmatchedFalsePositives += c.unmatchedFalsePositives
      if (c.precision !== null) {
        worstCellPrecision =
          worstCellPrecision === null ? c.precision : Math.min(worstCellPrecision, c.precision)
      }
      costUsd += c.costUsd
      durationMs += c.durationMs
      t34 += c.depthBreakdown.hops3to4.targets
      c34 += c.depthBreakdown.hops3to4.confirmed
      t56 += c.depthBreakdown.hops5to6.targets
      c56 += c.depthBreakdown.hops5to6.confirmed
      if (c.startedAt !== null) {
        earliestStart = earliestStart === null ? c.startedAt : Math.min(earliestStart, c.startedAt)
      }
      apps.add(c.app)
      seeds.add(c.seed)
      funnels.push(c.hopFunnel)
    }

    summaries.push({
      repeatKey,
      cells: group.length,
      apps: [...apps].sort(),
      seeds: [...seeds].sort((a, b) => a - b),
      startedAt: earliestStart,
      chainsTotal,
      chainsConfirmed,
      recall: safeRatio(chainsConfirmed, chainsTotal),
      hardenedTwinsTotal,
      hardenedTwinDecoyFps,
      unmatchedFalsePositives,
      worstCellPrecision,
      costUsd,
      durationMs,
      tpPerDollar: costUsd > 0 ? chainsConfirmed / costUsd : null,
      tpPer10m: durationMs > 0 ? chainsConfirmed / (durationMs / 600_000) : null,
      depthBreakdown: {
        hops3to4: { targets: t34, confirmed: c34, recall: safeRatio(c34, t34) },
        hops5to6: { targets: t56, confirmed: c56, recall: safeRatio(c56, t56) },
      },
      hopFunnel: aggregateHopFunnels(funnels),
    })
  }

  return summaries
}

export function summarizeModeSplit(
  cells: readonly NormalizedMultihopCell[],
  split: MultihopSplit,
  mode: MultihopMode,
  tierLabel: string | null = null,
): ModeSplitSummary {
  const repeatSummaries = groupCellsIntoRepeats(cells)
  const recalls = repeatSummaries.map((r) => r.recall)
  const h34Recalls = repeatSummaries
    .filter((r) => r.depthBreakdown.hops3to4.targets > 0)
    .map((r) => r.depthBreakdown.hops3to4.recall)
  const h56Recalls = repeatSummaries
    .filter((r) => r.depthBreakdown.hops5to6.targets > 0)
    .map((r) => r.depthBreakdown.hops5to6.recall)

  let chainsTotal = 0
  let chainsConfirmed = 0
  let hardenedTwinsTotal = 0
  let hardenedTwinDecoyFps = 0
  let unmatchedFalsePositives = 0
  let worstRunPrecision: number | null = null
  let costUsd = 0
  let durationMs = 0
  let t34 = 0
  let c34 = 0
  let t56 = 0
  let c56 = 0
  const funnels: HopDepthFunnel[] = []

  for (const r of repeatSummaries) {
    chainsTotal += r.chainsTotal
    chainsConfirmed += r.chainsConfirmed
    hardenedTwinsTotal += r.hardenedTwinsTotal
    hardenedTwinDecoyFps += r.hardenedTwinDecoyFps
    unmatchedFalsePositives += r.unmatchedFalsePositives
    if (r.worstCellPrecision !== null) {
      worstRunPrecision =
        worstRunPrecision === null
          ? r.worstCellPrecision
          : Math.min(worstRunPrecision, r.worstCellPrecision)
    }
    costUsd += r.costUsd
    durationMs += r.durationMs
    t34 += r.depthBreakdown.hops3to4.targets
    c34 += r.depthBreakdown.hops3to4.confirmed
    t56 += r.depthBreakdown.hops5to6.targets
    c56 += r.depthBreakdown.hops5to6.confirmed
    funnels.push(r.hopFunnel)
  }

  return {
    split,
    mode,
    tierLabel,
    repeats: repeatSummaries.length,
    repeatSummaries,
    cells: cells.length,
    chainsTotal,
    chainsConfirmed,
    medianRecall: median(recalls),
    minRecall: recalls.length > 0 ? Math.min(...recalls) : null,
    maxRecall: recalls.length > 0 ? Math.max(...recalls) : null,
    aggregateRecall: safeRatio(chainsConfirmed, chainsTotal),
    worstRunPrecision: cells.length > 0 ? worstRunPrecision : null,
    hardenedTwinsTotal,
    hardenedTwinDecoyFps,
    unmatchedFalsePositives,
    costUsd,
    durationMs,
    tpPerDollar: costUsd > 0 ? chainsConfirmed / costUsd : null,
    tpPer10m: durationMs > 0 ? chainsConfirmed / (durationMs / 600_000) : null,
    depthBreakdown: {
      hops3to4Targets: t34,
      hops3to4Confirmed: c34,
      hops3to4MedianRecall: median(h34Recalls),
      hops5to6Targets: t56,
      hops5to6Confirmed: c56,
      hops5to6MedianRecall: median(h56Recalls),
    },
    hopFunnel: aggregateHopFunnels(funnels),
  }
}

export function computeWasteSummary(cells: readonly NormalizedMultihopCell[]): WasteSummary {
  let measuredCells = 0
  let unmeasuredCells = 0
  let totalDeadEndReprobes = 0
  let totalPhaseBAssignments = 0
  let weightedRateSum = 0
  let weightSum = 0
  let maxCellWasteRate: number | null = null

  for (const c of cells) {
    const hasCounts =
      c.deadEndReprobeCount !== null && c.phaseBAssignments !== null && c.phaseBAssignments > 0
    if (hasCounts) {
      measuredCells += 1
      totalDeadEndReprobes += c.deadEndReprobeCount!
      totalPhaseBAssignments += c.phaseBAssignments!
      const rate = c.deadEndReprobeCount! / c.phaseBAssignments!
      weightedRateSum += rate * c.phaseBAssignments!
      weightSum += c.phaseBAssignments!
      maxCellWasteRate = maxCellWasteRate === null ? rate : Math.max(maxCellWasteRate, rate)
    } else if (c.deadEndReprobeWasteRate !== null) {
      measuredCells += 1
      const weight =
        c.phaseBAssignments !== null && c.phaseBAssignments > 0
          ? c.phaseBAssignments
          : c.phaseBAssignments === 0 && c.deadEndReprobeWasteRate === 0
            ? 0
            : 1
      weightedRateSum += c.deadEndReprobeWasteRate * weight
      weightSum += weight
      if (c.phaseBAssignments !== null && c.phaseBAssignments > 0) {
        totalPhaseBAssignments += c.phaseBAssignments
        totalDeadEndReprobes += Math.round(c.deadEndReprobeWasteRate * c.phaseBAssignments)
      }
      maxCellWasteRate =
        maxCellWasteRate === null
          ? c.deadEndReprobeWasteRate
          : Math.max(maxCellWasteRate, c.deadEndReprobeWasteRate)
    } else {
      unmeasuredCells += 1
    }
  }

  const wasteRate =
    measuredCells === 0
      ? null
      : weightSum > 0
        ? weightedRateSum / weightSum
        : 0

  return {
    measuredCells,
    unmeasuredCells,
    totalDeadEndReprobes,
    totalPhaseBAssignments,
    wasteRate,
    maxCellWasteRate,
  }
}

export function buildScalingCurve(cells: readonly NormalizedMultihopCell[]): ScalingCurvePoint[] {
  const groups = new Map<string, NormalizedMultihopCell[]>()
  for (const c of cells) {
    if (c.llm !== 'agentic') continue
    const key = `${c.split}::${c.mode}::${c.budgetUsd}::${c.maxDurationMs}`
    const list = groups.get(key)
    if (list) list.push(c)
    else groups.set(key, [c])
  }

  const splitOrder: Record<MultihopSplit, number> = { dev: 0, 'held-out': 1, sealed: 2 }
  const modeOrder: Record<MultihopMode, number> = { 'black-box': 0, 'grey-box': 1, 'white-box': 2 }

  const points: ScalingCurvePoint[] = []
  for (const group of groups.values()) {
    const head = group[0]!
    const summary = summarizeModeSplit(group, head.split, head.mode, head.tierLabel)
    const waste = computeWasteSummary(group)
    points.push({
      split: head.split,
      mode: head.mode,
      budgetUsd: head.budgetUsd,
      maxDurationMs: head.maxDurationMs,
      tierLabel: head.tierLabel,
      repeats: summary.repeats,
      cells: summary.cells,
      chainsTotal: summary.chainsTotal,
      chainsConfirmed: summary.chainsConfirmed,
      medianRecall: summary.medianRecall,
      minRecall: summary.minRecall,
      maxRecall: summary.maxRecall,
      hops3to4MedianRecall: summary.depthBreakdown.hops3to4MedianRecall,
      hops5to6MedianRecall: summary.depthBreakdown.hops5to6MedianRecall,
      deadEndWasteRate: waste.wasteRate,
      costUsd: summary.costUsd,
      durationMs: summary.durationMs,
      tpPerDollar: summary.tpPerDollar,
      tpPer10m: summary.tpPer10m,
      hardenedTwinDecoyFps: summary.hardenedTwinDecoyFps,
      unmatchedFalsePositives: summary.unmatchedFalsePositives,
      worstRunPrecision: summary.worstRunPrecision,
    })
  }

  return points.sort(
    (a, b) =>
      splitOrder[a.split] - splitOrder[b.split] ||
      modeOrder[a.mode] - modeOrder[b.mode] ||
      a.budgetUsd - b.budgetUsd ||
      a.maxDurationMs - b.maxDurationMs,
  )
}

// ---------------------------------------------------------------------------
// OSS & v7 Regression Floor Normalization
// ---------------------------------------------------------------------------

export function normalizeOssInputs(
  rawInputs: readonly OssCorpusInput[] | OssCorpusInput | null | undefined,
): NormalizedOssSummary | null {
  if (!rawInputs) return null
  const list: readonly OssCorpusInput[] = Array.isArray(rawInputs)
    ? rawInputs
    : [rawInputs as OssCorpusInput]
  if (list.length === 0) return null

  let totalAnchors = 0
  let tpCount = 0
  let sealedAnchors = 0
  let sealedTpCount = 0
  let worstRunPrecision: number | null = null
  let failedRuns = 0
  let totalFpCount = 0
  let unmatchedFpCount = 0
  let spuriousAnchorFpCount = 0
  let cleanControlCount = 0
  let cleanControlFpCount = 0
  let cleanControlUnexpectedOracles = 0
  let patchRetestAttempted = 0
  let patchRetestClosed = 0
  let tpPerUsdSum = 0
  let tpPerUsdCount = 0
  let tpPer10mSum = 0
  let tpPer10mCount = 0
  const anchorResults: OssAnchorResultInput[] = []
  const cleanControlResults: OssCleanControlResultInput[] = []

  for (const item of list) {
    const itemAnchors = nonNegNum(item.totalAnchors, 0)
    const itemTp = nonNegNum(item.tpCount, 0)
    totalAnchors += itemAnchors
    tpCount += itemTp

    const unmatched = nonNegNum(item.unmatchedFpCount, 0)
    const spurious = nonNegNum(item.spuriousAnchorFpCount, 0)
    const ccCount = nonNegNum(item.cleanControlCount, item.cleanControlResults?.length ?? 0)
    const ccFpsFromDetail = Array.isArray(item.cleanControlResults)
      ? item.cleanControlResults.reduce((acc, r) => acc + nonNegNum(r.fpCount, 0), 0)
      : 0
    const ccUnexpectedFromDetail = Array.isArray(item.cleanControlResults)
      ? item.cleanControlResults.reduce((acc, r) => acc + nonNegNum(r.unexpectedOracleTriggers, 0), 0)
      : 0
    const ccFps = Math.max(nonNegNum(item.cleanControlFpCount, 0), ccFpsFromDetail)
    const derivedTotalFp = unmatched + spurious + ccFps
    const itemTotalFp = Math.max(
      nonNegNum(item.totalFpCount ?? item.falsePositives, 0),
      derivedTotalFp,
    )

    unmatchedFpCount += unmatched
    spuriousAnchorFpCount += spurious
    cleanControlCount += ccCount
    cleanControlFpCount += ccFps
    cleanControlUnexpectedOracles += ccUnexpectedFromDetail
    totalFpCount += itemTotalFp

    const ossCell = ScorecardReader.read({
      ...(item as unknown as Record<string, unknown>),
      targets: itemAnchors,
      confirmed: itemTp,
      decoyFalsePositives: ccFps,
      unmatchedFalsePositives: Math.max(0, itemTotalFp - ccFps),
    })
    if (ossCell.state === 'failed_inert') {
      failedRuns += 1
    }
    // Fail closed (R2-05): 0 claims -> precision is null, NEVER 1.
    const computedPrec = ratioOrNull(itemTp, itemTp + itemTotalFp)
    const reportedPrec = optionalNum(item.precision)
    const reportedWorstPrec = optionalNum(item.worstRunPrecision)
    if (computedPrec !== null) {
      let itemPrec = computedPrec
      if (reportedPrec !== null) itemPrec = Math.min(itemPrec, reportedPrec)
      if (reportedWorstPrec !== null) itemPrec = Math.min(itemPrec, reportedWorstPrec)
      worstRunPrecision =
        worstRunPrecision === null ? itemPrec : Math.min(worstRunPrecision, itemPrec)
    }

    if (Array.isArray(item.anchorResults) && item.anchorResults.length > 0) {
      for (const a of item.anchorResults) {
        anchorResults.push(a)
        if (a.split === 'sealed') {
          sealedAnchors += 1
          if (a.twoSideConfirmed) sealedTpCount += 1
        }
      }
    } else if (item.split === 'sealed') {
      sealedAnchors += itemAnchors
      sealedTpCount += itemTp
    }

    if (Array.isArray(item.cleanControlResults)) {
      for (const cc of item.cleanControlResults) cleanControlResults.push(cc)
    }

    patchRetestAttempted += nonNegNum(item.patchRetestAttempted, 0)
    patchRetestClosed += nonNegNum(item.patchRetestClosed, 0)

    const tpu = optionalNum(item.tpPerUsd)
    if (tpu !== null) {
      tpPerUsdSum += tpu
      tpPerUsdCount += 1
    }
    const tp10 = optionalNum(item.tpPer10m)
    if (tp10 !== null) {
      tpPer10mSum += tp10
      tpPer10mCount += 1
    }
  }

  const effectivePatchAttempted = Math.max(patchRetestAttempted, tpCount)

  return {
    runs: list.length,
    failedRuns,
    totalAnchors,
    tpCount,
    sealedAnchors,
    sealedTpCount,
    sealedRecall: sealedAnchors > 0 ? safeRatio(sealedTpCount, sealedAnchors) : null,
    overallRecall: safeRatio(tpCount, totalAnchors),
    worstRunPrecision,
    totalFpCount,
    unmatchedFpCount,
    spuriousAnchorFpCount,
    cleanControlCount,
    cleanControlFpCount,
    cleanControlUnexpectedOracles,
    patchRetestAttempted: effectivePatchAttempted,
    patchRetestClosed,
    patchRetestClosureRate:
      effectivePatchAttempted > 0 ? safeRatio(patchRetestClosed, effectivePatchAttempted) : null,
    tpPerUsd: tpPerUsdCount > 0 ? tpPerUsdSum / tpPerUsdCount : null,
    tpPer10m: tpPer10mCount > 0 ? tpPer10mSum / tpPer10mCount : null,
    anchorResults,
    cleanControlResults,
  }
}

export function normalizeV7Floor(raw: unknown): NormalizedV7Floor | null {
  if (!raw || typeof raw !== 'object') return null
  const obj = raw as Record<string, unknown>

  // Support both dedicated `V7RegressionFloorInput` AND `certify-phase1.ts` Certificate shape.
  const rawXben = obj.xben as Record<string, unknown> | undefined
  const xben =
    rawXben && typeof rawXben === 'object'
      ? {
          confirmed: finiteNum(rawXben.confirmed, 0),
          targets: finiteNum(rawXben.targets, 0),
          falsePositives: finiteNum(rawXben.falsePositives, 0),
        }
      : null

  const rawHeldOut = (obj.heldOutSaas ?? obj['held-out-saas']) as Record<string, unknown> | undefined
  const heldOutSaas =
    rawHeldOut && typeof rawHeldOut === 'object'
      ? {
          confirmed: finiteNum(rawHeldOut.confirmed, 0),
          targets: finiteNum(rawHeldOut.targets, 0),
          patchesClosed: finiteNum(rawHeldOut.patchesClosed ?? rawHeldOut.patches, 0),
          patchesTotal: finiteNum(rawHeldOut.patchesTotal ?? rawHeldOut.targets, 0),
          falsePositives: finiteNum(rawHeldOut.falsePositives, 0),
        }
      : null

  const rawReason = (obj.reasonBench ?? obj['reason-bench'] ?? obj.reason) as
    | Record<string, unknown>
    | undefined
  let reasonBench: NormalizedV7Floor['reasonBench'] = null
  if (rawReason && typeof rawReason === 'object') {
    const nestedFloor = rawReason.floor as Record<string, unknown> | undefined
    const nestedAgentic = rawReason.agentic as Record<string, unknown> | undefined
    const noLlmConfirmed = optionalNum(rawReason.noLlmConfirmed ?? nestedFloor?.confirmed)
    const noLlmTargets = optionalNum(rawReason.noLlmTargets ?? nestedFloor?.targets)
    const noLlmRecall =
      optionalNum(rawReason.noLlmRecall ?? nestedFloor?.recall) ??
      (noLlmConfirmed !== null && noLlmTargets !== null && noLlmTargets > 0
        ? noLlmConfirmed / noLlmTargets
        : null)

    const agenticConfirmed = optionalNum(rawReason.agenticConfirmed ?? nestedAgentic?.confirmed)
    const agenticTargets = optionalNum(rawReason.agenticTargets ?? nestedAgentic?.targets)
    const agenticRecall =
      optionalNum(rawReason.agenticRecall ?? nestedAgentic?.recall) ??
      (agenticConfirmed !== null && agenticTargets !== null && agenticTargets > 0
        ? agenticConfirmed / agenticTargets
        : null)

    const worstPrecision = optionalNum(rawReason.worstPrecision ?? nestedAgentic?.worstPrecision)
    reasonBench = {
      noLlmRecall,
      noLlmConfirmed,
      noLlmTargets,
      agenticRecall,
      agenticConfirmed,
      agenticTargets,
      worstPrecision,
    }
  }

  const rawRealistic = (obj.realisticBench ?? obj['realistic-bench']) as
    | Record<string, unknown>
    | undefined
  const rawPhase1Floor = obj.floor as Record<string, unknown> | undefined
  let realisticBench: NormalizedV7Floor['realisticBench'] = null
  if (rawRealistic && typeof rawRealistic === 'object') {
    const direct = optionalNum(rawRealistic.maxFloorSpread)
    if (direct !== null) {
      realisticBench = { maxFloorSpread: direct }
    } else if (rawRealistic.spreadByApp && typeof rawRealistic.spreadByApp === 'object') {
      const vals = Object.values(rawRealistic.spreadByApp as Record<string, unknown>).filter(
        (v): v is number => typeof v === 'number' && Number.isFinite(v),
      )
      realisticBench = { maxFloorSpread: vals.length > 0 ? Math.max(...vals) : null }
    }
  } else if (rawPhase1Floor?.spread && typeof rawPhase1Floor.spread === 'object') {
    const vals = Object.values(rawPhase1Floor.spread as Record<string, unknown>).filter(
      (v): v is number => typeof v === 'number' && Number.isFinite(v),
    )
    realisticBench = { maxFloorSpread: vals.length > 0 ? Math.max(...vals) : null }
  }

  if (!xben && !heldOutSaas && !reasonBench && !realisticBench) return null
  return { xben, heldOutSaas, reasonBench, realisticBench }
}

// ---------------------------------------------------------------------------
// Core Gate Evaluator (M2 / M3 / M4)
// ---------------------------------------------------------------------------

export function evaluateV8Certification(input: CertifyV8Input): V8CertificationReport {
  const gate = input.gate
  const cells = input.cells.map(normalizeCell)
  const oss = normalizeOssInputs(input.oss)
  const v7Floor = normalizeV7Floor(input.v7Floor)
  const requireV7Floor = input.options?.requireV7Floor ?? gate === 'm4'

  const checks: GateCheckResult[] = []
  const notes: string[] = []

  const addCheck = (c: GateCheckResult): void => {
    checks.push(c)
  }

  // ---- 1. Universal Worst-Run Precision Gate (100.0%, 0 FPs across every cell/repeat) ----
  let worstRunPrecision: number | null = null
  let worstRunCell: string | null = null
  let totalHardenedTwinDecoyFps = 0
  let totalUnmatchedFalsePositives = 0
  let totalShortcutViolations = 0
  let totalModeBViolations = 0
  let inertAgenticCells = 0
  let failedCells = 0
  const failedCellLabels: string[] = []
  const integrityOffenders: string[] = []

  for (const c of cells) {
    if (c.failed || c.status === 'INVALID') {
      failedCells += 1
      failedCellLabels.push(c.cell)
    }
    totalHardenedTwinDecoyFps += c.hardenedTwinDecoyFps
    totalUnmatchedFalsePositives += c.unmatchedFalsePositives
    totalShortcutViolations += c.shortcutViolations
    totalModeBViolations += c.modeBViolations
    const isInertAgentic = c.llm === 'agentic' && c.inert
    if (isInertAgentic) inertAgenticCells += 1
    if (c.shortcutViolations > 0 || c.modeBViolations > 0 || isInertAgentic) {
      integrityOffenders.push(
        `${c.cell} (shortcut=${c.shortcutViolations}, modeB=${c.modeBViolations}${isInertAgentic ? ', inert=true' : ''})`,
      )
    }
    if (c.precision !== null) {
      if (
        worstRunPrecision === null ||
        c.precision < worstRunPrecision ||
        (c.precision < 1 - EPS && worstRunCell === null)
      ) {
        worstRunPrecision =
          worstRunPrecision === null ? c.precision : Math.min(worstRunPrecision, c.precision)
        if (c.precision < 1 - EPS) {
          worstRunCell = `${c.cell} (${c.llm}, ${c.tierLabel}${c.repeatId ? `, r=${c.repeatId}` : ''})`
        }
      }
    } else if (
      (c.hardenedTwinDecoyFps > 0 || c.unmatchedFalsePositives > 0) &&
      worstRunCell === null
    ) {
      worstRunCell = `${c.cell} (${c.llm}, ${c.tierLabel})`
    }
  }

  const totalOssFps = oss ? oss.totalFpCount : 0
  if (oss && oss.failedRuns > 0) {
    failedCells += oss.failedRuns
    failedCellLabels.push(`oss-multihop (${oss.failedRuns} failed)`)
  }
  if (
    oss &&
    oss.worstRunPrecision !== null &&
    (worstRunPrecision === null || oss.worstRunPrecision < worstRunPrecision)
  ) {
    worstRunPrecision = oss.worstRunPrecision
    if (oss.worstRunPrecision < 1 - EPS) worstRunCell = 'oss-multihop'
  }

  const reportStatus: 'VALID' | 'INVALID' = failedCells > 0 ? 'INVALID' : 'VALID'
  if (failedCells > 0) {
    addCheck({
      id: 'cell_validity',
      category: 'precision',
      description: 'All benchmark cells valid (0 failed/INVALID cells)',
      threshold: '0 failed cells (status VALID)',
      observed: `INVALID (${failedCells}/${cells.length} failed cell(s))`,
      status: 'FAIL',
      detail: failedCellLabels.slice(0, 5).join(', '),
    })
  }

  const precisionPassed =
    cells.length > 0 &&
    failedCells === 0 &&
    worstRunPrecision !== null &&
    worstRunPrecision >= V8_THRESHOLDS.precisionWorstRunMin - EPS &&
    totalHardenedTwinDecoyFps === 0 &&
    totalUnmatchedFalsePositives === 0 &&
    totalOssFps === 0

  addCheck({
    id: 'precision_worst_run',
    category: 'precision',
    description: 'Worst-run precision 100.0% (0 hardened-twin decoy FPs, 0 unmatched FPs, 0 OSS FPs)',
    threshold: '100.0% (0 FPs across every repeat/cell)',
    observed:
      cells.length === 0
        ? 'no cells'
        : `${pct(worstRunPrecision)} (twinFPs=${totalHardenedTwinDecoyFps}, unmatchedFPs=${totalUnmatchedFalsePositives}, ossFPs=${totalOssFps})`,
    status: precisionPassed ? 'PASS' : 'FAIL',
    detail: worstRunCell ? `worst cell: ${worstRunCell}` : undefined,
  })

  const integrityPassed =
    cells.length > 0 &&
    totalShortcutViolations === 0 &&
    totalModeBViolations === 0 &&
    inertAgenticCells === 0

  addCheck({
    id: 'two_side_replay_integrity',
    category: 'precision',
    description: 'Two-side provenance & Mode-A replay integrity (0 shortcut violations, 0 Mode-B violations, 0 inert agentic cells)',
    threshold: '0 shortcut violations, 0 Mode-B violations, 0 inert cells',
    observed:
      cells.length === 0
        ? 'no cells'
        : `shortcutViolations=${totalShortcutViolations}, modeBViolations=${totalModeBViolations}, inertAgenticCells=${inertAgenticCells}`,
    status: integrityPassed ? 'PASS' : 'FAIL',
    detail: integrityOffenders.length > 0 ? integrityOffenders.slice(0, 5).join('; ') : undefined,
  })

  // ---- 2. Universal Anti-Heuristic Gate (`multihop-saas --no-llm <= 5%`) ----
  const noLlmCells = cells.filter((c) => c.llm === 'deterministic-no-llm')
  const noLlmConfirmed = noLlmCells.reduce((n, c) => n + c.chainsConfirmed, 0)
  const noLlmTotal = noLlmCells.reduce((n, c) => n + c.chainsTotal, 0)
  const noLlmRecall = noLlmTotal > 0 ? safeRatio(noLlmConfirmed, noLlmTotal) : null
  const antiHeuristicPassed =
    noLlmCells.length > 0 &&
    noLlmRecall !== null &&
    noLlmRecall <= V8_THRESHOLDS.antiHeuristicNoLlmMax + EPS

  addCheck({
    id: 'anti_heuristic_no_llm',
    category: 'anti-heuristic',
    description: 'Anti-heuristic ceiling (multihop-saas --no-llm <= 5%)',
    threshold: `<= ${pct(V8_THRESHOLDS.antiHeuristicNoLlmMax)}`,
    observed:
      noLlmRecall === null
        ? 'missing (--no-llm cells required)'
        : `${pct(noLlmRecall)} (${noLlmConfirmed}/${noLlmTotal})`,
    status: antiHeuristicPassed ? 'PASS' : 'FAIL',
  })

  // ---- Helper slices for agentic cells ----
  const agenticCells = cells.filter((c) => c.llm === 'agentic')
  const devAgentic = agenticCells.filter((c) => c.split === 'dev')
  const heldOutAgentic = agenticCells.filter((c) => c.split === 'held-out')
  const sealedAgentic = agenticCells.filter((c) => c.split === 'sealed')

  // Build per-mode summaries (across all agentic cells grouped by split + mode)
  const modeSummaries: ModeSplitSummary[] = []
  const splits: MultihopSplit[] = ['dev', 'held-out', 'sealed']
  const modes: MultihopMode[] = ['black-box', 'grey-box', 'white-box']
  for (const s of splits) {
    for (const m of modes) {
      const slice = agenticCells.filter((c) => c.split === s && c.mode === m)
      if (slice.length > 0) {
        modeSummaries.push(summarizeModeSplit(slice, s, m, null))
      }
    }
  }

  const scalingCurve = buildScalingCurve(agenticCells)
  const hopFunnel = aggregateHopFunnels(agenticCells.map((c) => c.hopFunnel))
  const waste = computeWasteSummary(agenticCells)

  // Scaling curve metrics on Dev White-Box (`$2/10m`, `$5/30m`, `$15/60m`)
  const devWb2 = summarizeModeSplit(
    devAgentic.filter((c) => c.mode === 'white-box' && matchesTier(c, SCALING_TIERS.t2_10m)),
    'dev',
    'white-box',
    SCALING_TIERS.t2_10m.label,
  )
  const devWb5 = summarizeModeSplit(
    devAgentic.filter((c) => c.mode === 'white-box' && matchesTier(c, SCALING_TIERS.t5_30m)),
    'dev',
    'white-box',
    SCALING_TIERS.t5_30m.label,
  )
  const devGb5 = summarizeModeSplit(
    devAgentic.filter((c) => c.mode === 'grey-box' && matchesTier(c, SCALING_TIERS.t5_30m)),
    'dev',
    'grey-box',
    SCALING_TIERS.t5_30m.label,
  )
  const devWb15 = summarizeModeSplit(
    devAgentic.filter((c) => c.mode === 'white-box' && matchesTier(c, SCALING_TIERS.t15_60m)),
    'dev',
    'white-box',
    SCALING_TIERS.t15_60m.label,
  )
  const devGb15 = summarizeModeSplit(
    devAgentic.filter((c) => c.mode === 'grey-box' && matchesTier(c, SCALING_TIERS.t15_60m)),
    'dev',
    'grey-box',
    SCALING_TIERS.t15_60m.label,
  )

  const heldOutWb15Cells = heldOutAgentic.filter(
    (c) => c.mode === 'white-box' && matchesTier(c, SCALING_TIERS.t15_60m),
  )
  const heldOutGb15Cells = heldOutAgentic.filter(
    (c) => c.mode === 'grey-box' && matchesTier(c, SCALING_TIERS.t15_60m),
  )
  const heldOutWb15 = summarizeModeSplit(
    heldOutWb15Cells,
    'held-out',
    'white-box',
    SCALING_TIERS.t15_60m.label,
  )
  const heldOutGb15 = summarizeModeSplit(
    heldOutGb15Cells,
    'held-out',
    'grey-box',
    SCALING_TIERS.t15_60m.label,
  )

  const sealedWb15Cells = sealedAgentic.filter(
    (c) => c.mode === 'white-box' && matchesTier(c, SCALING_TIERS.t15_60m),
  )
  const sealedWbCandidates = sealedWb15Cells.length > 0
    ? sealedWb15Cells
    : sealedAgentic.filter((c) => c.mode === 'white-box')
  const sealedWbSummary = summarizeModeSplit(
    sealedWbCandidates,
    'sealed',
    'white-box',
    sealedWb15Cells.length > 0 ? SCALING_TIERS.t15_60m.label : null,
  )
  // Blind first run: sort repeats by earliest startedAt (non-null timestamps first, preserving order on ties).
  const orderedSealedRepeats = [...sealedWbSummary.repeatSummaries].sort((a, b) => {
    if (a.startedAt !== null && b.startedAt !== null) return a.startedAt - b.startedAt
    if (a.startedAt !== null) return -1
    if (b.startedAt !== null) return 1
    return 0
  })
  const sealedBlindFirstRun = orderedSealedRepeats[0] ?? null

  const isCompleteDevRepeat = (r: RepeatSummary): boolean =>
    MULTIHOP_DEV_APPS.every((app) => r.apps.includes(app)) &&
    r.chainsTotal >= V8_THRESHOLDS.m2.expectedDevChains &&
    r.hardenedTwinsTotal >= V8_THRESHOLDS.m2.expectedDevTwins

  const completeDevRepeats = (summary: ModeSplitSummary): { complete: number; incomplete: number } => {
    let complete = 0
    let incomplete = 0
    for (const r of summary.repeatSummaries) {
      if (isCompleteDevRepeat(r)) complete += 1
      else incomplete += 1
    }
    return { complete, incomplete }
  }

  // Scaling summary
  const devWb2Cov = completeDevRepeats(devWb2)
  const devWb5Cov = completeDevRepeats(devWb5)
  const devWb15Cov = completeDevRepeats(devWb15)
  const tiersPresent = devWb2Cov.complete > 0 && devWb5Cov.complete > 0 && devWb15Cov.complete > 0
  const minRepeatsObserved = Math.min(devWb2Cov.complete, devWb5Cov.complete, devWb15Cov.complete)
  const r2 = devWb2.medianRecall
  const r5 = devWb5.medianRecall
  const r15 = devWb15.medianRecall
  const strictlyMonotonic =
    r2 !== null && r5 !== null && r15 !== null && r5 > r2 + EPS && r15 > r5 + EPS
  const lift15Over2 = r2 !== null && r15 !== null ? r15 - r2 : null

  // Generalization & overfitting summary
  const devToHeldOutWbGap =
    devWb15.medianRecall !== null && heldOutWb15.medianRecall !== null
      ? devWb15.medianRecall - heldOutWb15.medianRecall
      : null
  const devToHeldOutGbGap =
    devGb15.medianRecall !== null && heldOutGb15.medianRecall !== null
      ? devGb15.medianRecall - heldOutGb15.medianRecall
      : null
  const devToSealedWbGap =
    devWb15.medianRecall !== null && sealedBlindFirstRun !== null
      ? devWb15.medianRecall - sealedBlindFirstRun.recall
      : null
  const overfittingViolation =
    devToSealedWbGap !== null && devToSealedWbGap > V8_THRESHOLDS.m4.devToSealedMaxGap + EPS

  // Efficiency metrics ($5 tier for TP/$, 30m tier for TP/10m)
  const devWbAt5 = devAgentic.filter(
    (c) => c.mode === 'white-box' && Math.abs(c.budgetUsd - SCALING_TIERS.t5_30m.budgetUsd) < 0.01,
  )
  const tier5Cells = devWbAt5.length > 0
    ? devWbAt5
    : devAgentic.filter((c) => Math.abs(c.budgetUsd - SCALING_TIERS.t5_30m.budgetUsd) < 0.01)
  const tier5Confirmed = tier5Cells.reduce((n, c) => n + c.chainsConfirmed, 0)
  const tier5CostUsd = tier5Cells.reduce((n, c) => n + c.costUsd, 0)
  const tpPerDollarAt5 = tier5CostUsd > 0 ? tier5Confirmed / tier5CostUsd : null

  const devWbAt30m = devAgentic.filter(
    (c) =>
      c.mode === 'white-box' &&
      Math.abs(c.maxDurationMs - SCALING_TIERS.t5_30m.maxDurationMs) < 1_000,
  )
  const tier30mCells = devWbAt30m.length > 0
    ? devWbAt30m
    : devAgentic.filter(
        (c) => Math.abs(c.maxDurationMs - SCALING_TIERS.t5_30m.maxDurationMs) < 1_000,
      )
  const tier30mConfirmed = tier30mCells.reduce((n, c) => n + c.chainsConfirmed, 0)
  const tier30mDurationMs = tier30mCells.reduce((n, c) => n + c.durationMs, 0)
  const tpPer10mAt30m = tier30mDurationMs > 0 ? tier30mConfirmed / (tier30mDurationMs / 600_000) : null

  // ---- 3. Gate-Specific Checks ----

  if (gate === 'm2') {
    // M2 Gate: $5/30m, Dev 3-archetype (paygrid, shipforge, nexusiam; 12 chains + 9 twins)
    const devGb5Cov = completeDevRepeats(devGb5)
    const m2CoveragePassed =
      devGb5Cov.complete >= 1 &&
      devGb5Cov.incomplete === 0 &&
      devWb5Cov.complete >= 1 &&
      devWb5Cov.incomplete === 0

    addCheck({
      id: 'm2_dev_archetype_coverage',
      category: 'recall',
      description: 'M2 Dev 3-archetype coverage (paygrid, shipforge, nexusiam; 12 chains + 9 twins per repeat)',
      threshold: `all 3 dev apps (>= ${V8_THRESHOLDS.m2.expectedDevChains} chains, >= ${V8_THRESHOLDS.m2.expectedDevTwins} twins) in GB & WB`,
      observed: `GB complete=${devGb5Cov.complete}/${devGb5.repeats}, WB complete=${devWb5Cov.complete}/${devWb5.repeats}`,
      status: m2CoveragePassed ? 'PASS' : 'FAIL',
    })

    const gbRecall = devGb5.medianRecall
    const wbRecall = devWb5.medianRecall
    const wbLift = gbRecall !== null && wbRecall !== null ? wbRecall - gbRecall : null
    const m2TwinFps = devGb5.hardenedTwinDecoyFps + devWb5.hardenedTwinDecoyFps
    const m2TwinsTotal = devGb5.hardenedTwinsTotal + devWb5.hardenedTwinsTotal

    addCheck({
      id: 'm2_greybox_recall',
      category: 'recall',
      description: 'M2 Dev grey-box recall ($5/30m)',
      threshold: `>= ${pct(V8_THRESHOLDS.m2.greyBoxRecallMin)} (>= 4/12)`,
      observed:
        gbRecall === null
          ? 'missing ($5/30m dev grey-box cells)'
          : `${pct(gbRecall)} (${devGb5.chainsConfirmed}/${devGb5.chainsTotal}, n=${devGb5.repeats})`,
      status:
        gbRecall !== null && gbRecall >= V8_THRESHOLDS.m2.greyBoxRecallMin - EPS ? 'PASS' : 'FAIL',
    })

    addCheck({
      id: 'm2_whitebox_recall',
      category: 'recall',
      description: 'M2 Dev white-box recall ($5/30m)',
      threshold: `>= ${pct(V8_THRESHOLDS.m2.whiteBoxRecallMin)} (>= 6/12)`,
      observed:
        wbRecall === null
          ? 'missing ($5/30m dev white-box cells)'
          : `${pct(wbRecall)} (${devWb5.chainsConfirmed}/${devWb5.chainsTotal}, n=${devWb5.repeats})`,
      status:
        wbRecall !== null && wbRecall >= V8_THRESHOLDS.m2.whiteBoxRecallMin - EPS ? 'PASS' : 'FAIL',
    })

    addCheck({
      id: 'm2_whitebox_lift',
      category: 'lift',
      description: 'M2 White-box lift over grey-box ($5/30m)',
      threshold: `>= ${pp(V8_THRESHOLDS.m2.whiteBoxLiftOverGreyBoxMin)}`,
      observed: pp(wbLift),
      status:
        wbLift !== null && wbLift >= V8_THRESHOLDS.m2.whiteBoxLiftOverGreyBoxMin - EPS
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm2_dev_twin_fps',
      category: 'precision',
      description: 'M2 Dev hardened-twin decoy FPs (0/9 twins per repeat)',
      threshold: '0 twin FPs',
      observed: `${m2TwinFps}/${m2TwinsTotal}`,
      status:
        devGb5.cells > 0 && devWb5.cells > 0 && m2TwinsTotal > 0 && m2TwinFps === 0 ? 'PASS' : 'FAIL',
    })
  }

  if (gate === 'm3') {
    // M3 Gate: Dev scaling matrix ($2/10m, $5/30m, $15/60m, n >= 3 complete 3-archetype repeats)
    const m3IncompleteRepeats = devWb2Cov.incomplete + devWb5Cov.incomplete + devWb15Cov.incomplete
    addCheck({
      id: 'm3_repeats_floor',
      category: 'scaling',
      description: 'M3 Scaling matrix coverage ($2/10m, $5/30m, $15/60m with n >= 3 complete 3-archetype repeats each)',
      threshold: `n >= ${V8_THRESHOLDS.minRepeats} complete Dev repeats per tier`,
      observed: `$2/10m: n=${devWb2Cov.complete}/${devWb2.repeats}, $5/30m: n=${devWb5Cov.complete}/${devWb5.repeats}, $15/60m: n=${devWb15Cov.complete}/${devWb15.repeats}`,
      status:
        tiersPresent &&
        minRepeatsObserved >= V8_THRESHOLDS.minRepeats &&
        m3IncompleteRepeats === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm3_monotonic_scaling',
      category: 'scaling',
      description: 'M3 Strict monotonic median recall ($2/10m < $5/30m < $15/60m)',
      threshold: '$2/10m < $5/30m < $15/60m',
      observed: `${pct(r2)} -> ${pct(r5)} -> ${pct(r15)}`,
      status: strictlyMonotonic ? 'PASS' : 'FAIL',
    })

    addCheck({
      id: 'm3_scaling_lift',
      category: 'scaling',
      description: 'M3 Scaling lift ($15/60m - $2/10m >= +20 pp)',
      threshold: `>= ${pp(V8_THRESHOLDS.m3.scalingLift15Over2Min)}`,
      observed: pp(lift15Over2),
      status:
        lift15Over2 !== null && lift15Over2 >= V8_THRESHOLDS.m3.scalingLift15Over2Min - EPS
          ? 'PASS'
          : 'FAIL',
    })

    const h34 = devWb15.depthBreakdown.hops3to4MedianRecall
    const h56 = devWb15.depthBreakdown.hops5to6MedianRecall

    addCheck({
      id: 'm3_depth_3_4_hop',
      category: 'depth',
      description: 'M3 Depth breakdown at $15/60m white-box: 3–4 hop chains',
      threshold: `>= ${pct(V8_THRESHOLDS.m3.depth3to4RecallMin)}`,
      observed:
        h34 === null
          ? 'missing (no 3–4 hop breakdown)'
          : `${pct(h34)} (${devWb15.depthBreakdown.hops3to4Confirmed}/${devWb15.depthBreakdown.hops3to4Targets})`,
      status: h34 !== null && h34 >= V8_THRESHOLDS.m3.depth3to4RecallMin - EPS ? 'PASS' : 'FAIL',
    })

    addCheck({
      id: 'm3_depth_5_6_hop',
      category: 'depth',
      description: 'M3 Depth breakdown at $15/60m white-box: 5–6 hop chains',
      threshold: `>= ${pct(V8_THRESHOLDS.m3.depth5to6RecallMin)}`,
      observed:
        h56 === null
          ? 'missing (no 5–6 hop breakdown)'
          : `${pct(h56)} (${devWb15.depthBreakdown.hops5to6Confirmed}/${devWb15.depthBreakdown.hops5to6Targets})`,
      status: h56 !== null && h56 >= V8_THRESHOLDS.m3.depth5to6RecallMin - EPS ? 'PASS' : 'FAIL',
    })

    const m3Waste = computeWasteSummary(
      devAgentic.filter(
        (c) =>
          matchesTier(c, SCALING_TIERS.t2_10m) ||
          matchesTier(c, SCALING_TIERS.t5_30m) ||
          matchesTier(c, SCALING_TIERS.t15_60m),
      ),
    )

    addCheck({
      id: 'm3_dead_end_waste',
      category: 'waste',
      description: 'M3 Dead-end re-probing waste (<= 5% of Phase B assignments)',
      threshold: `<= ${pct(V8_THRESHOLDS.m3.deadEndWasteMax)}`,
      observed:
        m3Waste.wasteRate === null
          ? 'missing (dead-end waste telemetry required)'
          : `${pct(m3Waste.wasteRate)} (max cell: ${pct(m3Waste.maxCellWasteRate)}, measured=${m3Waste.measuredCells}/${m3Waste.measuredCells + m3Waste.unmeasuredCells})`,
      status:
        m3Waste.wasteRate !== null &&
        m3Waste.unmeasuredCells === 0 &&
        m3Waste.wasteRate <= V8_THRESHOLDS.m3.deadEndWasteMax + EPS
          ? 'PASS'
          : 'FAIL',
    })
  }

  if (gate === 'm4') {
    // 1. Dev ($15/60m, n >= 3 complete 3-archetype repeats)
    const devGb15Cov = completeDevRepeats(devGb15)
    addCheck({
      id: 'm4_dev_repeats',
      category: 'recall',
      description: 'M4 Dev $15/60m repeat count (WB and GB, n >= 3 complete 3-archetype repeats)',
      threshold: `n >= ${V8_THRESHOLDS.minRepeats} complete repeats (WB & GB)`,
      observed: `WB n=${devWb15Cov.complete}/${devWb15.repeats}, GB n=${devGb15Cov.complete}/${devGb15.repeats}`,
      status:
        devWb15Cov.complete >= V8_THRESHOLDS.minRepeats &&
        devWb15Cov.incomplete === 0 &&
        devGb15Cov.complete >= V8_THRESHOLDS.minRepeats &&
        devGb15Cov.incomplete === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_dev_wb_recall',
      category: 'recall',
      description: 'M4 Dev white-box median recall ($15/60m, 0 twin FPs)',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.devWhiteBoxRecallMin)}, 0 twin FPs`,
      observed:
        devWb15.medianRecall === null
          ? 'missing ($15/60m dev WB)'
          : `${pct(devWb15.medianRecall)} (twinFPs=${devWb15.hardenedTwinDecoyFps})`,
      status:
        devWb15.medianRecall !== null &&
        devWb15.medianRecall >= V8_THRESHOLDS.m4.devWhiteBoxRecallMin - EPS &&
        devWb15.hardenedTwinDecoyFps === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_dev_gb_recall',
      category: 'recall',
      description: 'M4 Dev grey-box median recall ($15/60m, 0 twin FPs)',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.devGreyBoxRecallMin)}, 0 twin FPs`,
      observed:
        devGb15.medianRecall === null
          ? 'missing ($15/60m dev GB)'
          : `${pct(devGb15.medianRecall)} (twinFPs=${devGb15.hardenedTwinDecoyFps})`,
      status:
        devGb15.medianRecall !== null &&
        devGb15.medianRecall >= V8_THRESHOLDS.m4.devGreyBoxRecallMin - EPS &&
        devGb15.hardenedTwinDecoyFps === 0
          ? 'PASS'
          : 'FAIL',
    })

    // 2. Salted Held-Out (seed >= 1_000_000, $15/60m, n >= 3 complete 3-archetype repeats)
    const heldOutWb15Cov = completeDevRepeats(heldOutWb15)
    const heldOutGb15Cov = completeDevRepeats(heldOutGb15)
    const invalidHeldOutSeeds = [...heldOutWb15Cells, ...heldOutGb15Cells].filter(
      (c) => c.seed < V8_THRESHOLDS.heldOutSeedMin,
    )

    addCheck({
      id: 'm4_heldout_repeats',
      category: 'generalization',
      description: 'M4 Salted Held-Out $15/60m coverage (seed >= 1_000_000, n >= 3 complete 3-archetype WB & GB)',
      threshold: `n >= ${V8_THRESHOLDS.minRepeats} complete repeats, all seeds >= ${V8_THRESHOLDS.heldOutSeedMin}`,
      observed: `WB n=${heldOutWb15Cov.complete}/${heldOutWb15.repeats}, GB n=${heldOutGb15Cov.complete}/${heldOutGb15.repeats}, invalidSeeds=${invalidHeldOutSeeds.length}`,
      status:
        heldOutWb15Cov.complete >= V8_THRESHOLDS.minRepeats &&
        heldOutWb15Cov.incomplete === 0 &&
        heldOutGb15Cov.complete >= V8_THRESHOLDS.minRepeats &&
        heldOutGb15Cov.incomplete === 0 &&
        invalidHeldOutSeeds.length === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_heldout_wb_recall',
      category: 'generalization',
      description: 'M4 Salted Held-Out white-box median recall ($15/60m, 0 twin FPs)',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.heldOutWhiteBoxRecallMin)}, 0 twin FPs`,
      observed:
        heldOutWb15.medianRecall === null
          ? 'missing ($15/60m held-out WB)'
          : `${pct(heldOutWb15.medianRecall)} (twinFPs=${heldOutWb15.hardenedTwinDecoyFps})`,
      status:
        heldOutWb15.medianRecall !== null &&
        heldOutWb15.medianRecall >= V8_THRESHOLDS.m4.heldOutWhiteBoxRecallMin - EPS &&
        heldOutWb15.hardenedTwinDecoyFps === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_heldout_gb_recall',
      category: 'generalization',
      description: 'M4 Salted Held-Out grey-box median recall ($15/60m, 0 twin FPs)',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.heldOutGreyBoxRecallMin)}, 0 twin FPs`,
      observed:
        heldOutGb15.medianRecall === null
          ? 'missing ($15/60m held-out GB)'
          : `${pct(heldOutGb15.medianRecall)} (twinFPs=${heldOutGb15.hardenedTwinDecoyFps})`,
      status:
        heldOutGb15.medianRecall !== null &&
        heldOutGb15.medianRecall >= V8_THRESHOLDS.m4.heldOutGreyBoxRecallMin - EPS &&
        heldOutGb15.hardenedTwinDecoyFps === 0
          ? 'PASS'
          : 'FAIL',
    })

    const maxDevToHeldOutGap =
      devToHeldOutWbGap !== null && devToHeldOutGbGap !== null
        ? Math.max(devToHeldOutWbGap, devToHeldOutGbGap)
        : devToHeldOutWbGap ?? devToHeldOutGbGap

    addCheck({
      id: 'm4_dev_heldout_gap',
      category: 'generalization',
      description: 'M4 Dev -> Salted Held-Out generalization gap (<= 10 pp)',
      threshold: `<= +10.0 pp (WB & GB)`,
      observed: `WB=${pp(devToHeldOutWbGap)}, GB=${pp(devToHeldOutGbGap)}`,
      status:
        devToHeldOutWbGap !== null &&
        devToHeldOutGbGap !== null &&
        maxDevToHeldOutGap !== null &&
        maxDevToHeldOutGap <= V8_THRESHOLDS.m4.devToHeldOutMaxGap + EPS
          ? 'PASS'
          : 'FAIL',
    })

    // 3. Sealed connecthub blind first run + overfitting guard (> 20 pp drop)
    addCheck({
      id: 'm4_sealed_wb_recall',
      category: 'generalization',
      description: 'M4 Sealed connecthub blind first run white-box (>= 50%, 0/3 twin FPs)',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.sealedWhiteBoxRecallMin)} (>= 2/4), 0/3 twin FPs`,
      observed:
        sealedBlindFirstRun === null
          ? 'missing (sealed connecthub WB run)'
          : `${pct(sealedBlindFirstRun.recall)} (${sealedBlindFirstRun.chainsConfirmed}/${sealedBlindFirstRun.chainsTotal}, twinFPs=${sealedWbSummary.hardenedTwinDecoyFps}/${sealedWbSummary.hardenedTwinsTotal})`,
      status:
        sealedBlindFirstRun !== null &&
        sealedBlindFirstRun.chainsTotal >= 4 &&
        sealedBlindFirstRun.hardenedTwinsTotal >= 3 &&
        sealedBlindFirstRun.recall >= V8_THRESHOLDS.m4.sealedWhiteBoxRecallMin - EPS &&
        sealedWbSummary.hardenedTwinDecoyFps === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_sealed_overfit_guard',
      category: 'overfitting',
      description: 'M4 Anti-overfitting guard: Dev -> Sealed connecthub drop <= 20 pp',
      threshold: '<= +20.0 pp drop (dev WB - sealed blind WB)',
      observed:
        devToSealedWbGap === null
          ? 'missing (dev WB or sealed WB)'
          : `${pp(devToSealedWbGap)}${overfittingViolation ? ' [OVERFITTING VIOLATION]' : ''}`,
      status:
        devToSealedWbGap !== null && !overfittingViolation ? 'PASS' : 'FAIL',
      detail: overfittingViolation
        ? 'Sealed blind recall dropped > 20 pp below dev; stop and remove overfitted heuristics.'
        : undefined,
    })

    if (overfittingViolation) {
      notes.push(
        `OVERFITTING VIOLATION: Dev WB (${pct(devWb15.medianRecall)}) -> Sealed connecthub blind first run (${pct(sealedBlindFirstRun?.recall ?? null)}) dropped ${pp(devToSealedWbGap)} (> 20 pp limit).`,
      )
    }

    // 4. OSS Multi-Hop Corpus (8 targets + 2 clean controls)
    addCheck({
      id: 'm4_oss_corpus_coverage',
      category: 'oss',
      description: 'M4 OSS Multi-Hop Corpus coverage (8 targets + 2 clean controls)',
      threshold: `>= ${V8_THRESHOLDS.m4.ossMinTargets} targets, >= ${V8_THRESHOLDS.m4.ossMinCleanControls} clean controls`,
      observed:
        oss === null
          ? 'missing (--oss report required)'
          : `${oss.totalAnchors} targets (sealed=${oss.sealedAnchors}), ${oss.cleanControlCount} clean controls`,
      status:
        oss !== null &&
        oss.totalAnchors >= V8_THRESHOLDS.m4.ossMinTargets &&
        oss.cleanControlCount >= V8_THRESHOLDS.m4.ossMinCleanControls
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_oss_sealed_recall',
      category: 'oss',
      description: 'M4 OSS sealed recall >= 50% at 100% precision',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.ossSealedRecallMin)} sealed recall, 100.0% precision`,
      observed:
        oss === null
          ? 'missing'
          : `sealed=${pct(oss.sealedRecall)} (${oss.sealedTpCount}/${oss.sealedAnchors}), precision=${pct(oss.worstRunPrecision)} (FPs=${oss.totalFpCount})`,
      status:
        oss !== null &&
        oss.sealedRecall !== null &&
        oss.sealedRecall >= V8_THRESHOLDS.m4.ossSealedRecallMin - EPS &&
        oss.worstRunPrecision !== null &&
        oss.worstRunPrecision >= 1 - EPS &&
        oss.totalFpCount === 0
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_oss_patch_retest',
      category: 'oss',
      description: 'M4 OSS patch-retest closure >= 80%',
      threshold: `>= ${pct(V8_THRESHOLDS.m4.ossPatchRetestClosureMin)}`,
      observed:
        oss === null || oss.patchRetestClosureRate === null
          ? 'missing (patch-retest records required)'
          : `${pct(oss.patchRetestClosureRate)} (${oss.patchRetestClosed}/${oss.patchRetestAttempted})`,
      status:
        oss !== null &&
        oss.patchRetestClosureRate !== null &&
        oss.patchRetestClosureRate >= V8_THRESHOLDS.m4.ossPatchRetestClosureMin - EPS
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_oss_clean_controls',
      category: 'oss',
      description: 'M4 OSS clean patched controls: 0 FPs on both controls',
      threshold: '0 FPs, 0 unexpected oracle triggers',
      observed:
        oss === null
          ? 'missing'
          : `${oss.cleanControlFpCount} FPs, ${oss.cleanControlUnexpectedOracles} unexpected oracles across ${oss.cleanControlCount} controls`,
      status:
        oss !== null &&
        oss.cleanControlCount >= V8_THRESHOLDS.m4.ossMinCleanControls &&
        oss.cleanControlFpCount === 0 &&
        oss.cleanControlUnexpectedOracles === 0
          ? 'PASS'
          : 'FAIL',
    })

    // 5. Efficiency Floor: >= 0.50 TP/$ (at $5 tier) AND >= 1.0 TP/10m (at 30m tier)
    addCheck({
      id: 'm4_efficiency_tp_per_dollar',
      category: 'efficiency',
      description: 'M4 Efficiency floor: >= 0.50 confirmed chains / $1 (at $5 tier)',
      threshold: `>= ${V8_THRESHOLDS.m4.efficiencyTpPerDollarMin.toFixed(2)} TP/$`,
      observed:
        tpPerDollarAt5 === null
          ? 'missing ($5 tier cells with costUsd > 0)'
          : `${tpPerDollarAt5.toFixed(2)} TP/$ (${tier5Confirmed} TP / $${tier5CostUsd.toFixed(2)})`,
      status:
        tpPerDollarAt5 !== null &&
        tpPerDollarAt5 >= V8_THRESHOLDS.m4.efficiencyTpPerDollarMin - EPS
          ? 'PASS'
          : 'FAIL',
    })

    addCheck({
      id: 'm4_efficiency_tp_per_10m',
      category: 'efficiency',
      description: 'M4 Efficiency floor: >= 1.0 confirmed chain / 10m (at 30m tier)',
      threshold: `>= ${V8_THRESHOLDS.m4.efficiencyTpPer10mMin.toFixed(2)} TP/10m`,
      observed:
        tpPer10mAt30m === null
          ? 'missing (30m tier cells with durationMs > 0)'
          : `${tpPer10mAt30m.toFixed(2)} TP/10m (${tier30mConfirmed} TP / ${(tier30mDurationMs / 600_000).toFixed(2)} x10m)`,
      status:
        tpPer10mAt30m !== null &&
        tpPer10mAt30m >= V8_THRESHOLDS.m4.efficiencyTpPer10mMin - EPS
          ? 'PASS'
          : 'FAIL',
    })

    // 6. v7 Regression Floor (required in M4 unless explicitly waived)
    if (requireV7Floor || v7Floor !== null) {
      addCheck({
        id: 'm4_v7_xben',
        category: 'v7-floor',
        description: 'M4 v7 regression floor: xben 25/25',
        threshold: '25/25 (0 FPs)',
        observed:
          v7Floor?.xben == null
            ? 'missing (--v7-floor xben)'
            : `${v7Floor.xben.confirmed}/${v7Floor.xben.targets} (FPs=${v7Floor.xben.falsePositives})`,
        status:
          v7Floor?.xben != null &&
          v7Floor.xben.targets >= V8_THRESHOLDS.m4.v7XbenMinConfirmed &&
          v7Floor.xben.confirmed >= V8_THRESHOLDS.m4.v7XbenMinConfirmed &&
          v7Floor.xben.falsePositives === 0
            ? 'PASS'
            : 'FAIL',
      })

      addCheck({
        id: 'm4_v7_heldout_saas',
        category: 'v7-floor',
        description: 'M4 v7 regression floor: held-out-saas 20/20 + 20/20 patches',
        threshold: '20/20 detections, 20/20 patches (0 FPs)',
        observed:
          v7Floor?.heldOutSaas == null
            ? 'missing (--v7-floor heldOutSaas)'
            : `${v7Floor.heldOutSaas.confirmed}/${v7Floor.heldOutSaas.targets} det, ${v7Floor.heldOutSaas.patchesClosed}/${v7Floor.heldOutSaas.patchesTotal} patches (FPs=${v7Floor.heldOutSaas.falsePositives})`,
        status:
          v7Floor?.heldOutSaas != null &&
          v7Floor.heldOutSaas.targets >= V8_THRESHOLDS.m4.v7HeldOutSaasMinConfirmed &&
          v7Floor.heldOutSaas.confirmed >= V8_THRESHOLDS.m4.v7HeldOutSaasMinConfirmed &&
          v7Floor.heldOutSaas.patchesTotal >= V8_THRESHOLDS.m4.v7HeldOutSaasMinPatches &&
          v7Floor.heldOutSaas.patchesClosed >= V8_THRESHOLDS.m4.v7HeldOutSaasMinPatches &&
          v7Floor.heldOutSaas.falsePositives === 0
            ? 'PASS'
            : 'FAIL',
      })

      const rNoLlm = v7Floor?.reasonBench?.noLlmRecall ?? null
      addCheck({
        id: 'm4_v7_reason_no_llm',
        category: 'v7-floor',
        description: 'M4 v7 regression floor: reason-bench --no-llm <= 10%',
        threshold: `<= ${pct(V8_THRESHOLDS.m4.v7ReasonNoLlmMax)}`,
        observed: rNoLlm === null ? 'missing (--v7-floor reasonBench.noLlmRecall)' : pct(rNoLlm),
        status: rNoLlm !== null && rNoLlm <= V8_THRESHOLDS.m4.v7ReasonNoLlmMax + EPS ? 'PASS' : 'FAIL',
      })

      const rAgentic = v7Floor?.reasonBench?.agenticRecall ?? null
      const rPrec = v7Floor?.reasonBench?.worstPrecision ?? null
      addCheck({
        id: 'm4_v7_reason_agentic',
        category: 'v7-floor',
        description: 'M4 v7 regression floor: reason-bench agentic >= 50%',
        threshold: `>= ${pct(V8_THRESHOLDS.m4.v7ReasonAgenticMin)} (100% precision)`,
        observed:
          rAgentic === null
            ? 'missing (--v7-floor reasonBench.agenticRecall)'
            : `${pct(rAgentic)} (precision=${pct(rPrec)})`,
        status:
          rAgentic !== null &&
          rAgentic >= V8_THRESHOLDS.m4.v7ReasonAgenticMin - EPS &&
          rPrec !== null &&
          rPrec >= 1 - EPS
            ? 'PASS'
            : 'FAIL',
      })

      const spread = v7Floor?.realisticBench?.maxFloorSpread ?? null
      addCheck({
        id: 'm4_v7_realistic_spread',
        category: 'v7-floor',
        description: 'M4 v7 regression floor: realistic-bench floor spread == 0',
        threshold: '0 spread',
        observed: spread === null ? 'missing (--v7-floor realisticBench.maxFloorSpread)' : String(spread),
        status:
          spread !== null &&
          spread >= 0 &&
          spread <= V8_THRESHOLDS.m4.v7RealisticMaxSpread
            ? 'PASS'
            : 'FAIL',
      })
    } else {
      notes.push('v7 regression floor check waived (--allow-missing-v7-floor)')
    }
  }

  const failedChecks = checks.filter((c) => c.status === 'FAIL')
  const verdict: 'PASS' | 'FAIL' =
    reportStatus === 'VALID' && failedChecks.length === 0 ? 'PASS' : 'FAIL'
  const gitSha =
    input.options?.gitSha ??
    cells.find((c) => c.gitSha && c.gitSha !== 'unknown')?.gitSha ??
    resolveGitSha()
  const cellVersions = [...new Set(cells.map((c) => c.benchmarkVersion).filter((v): v is string => Boolean(v)))]
  const benchmarkVersion =
    cellVersions.length === 1
      ? cellVersions[0]!
      : computeBenchmarkVersion('multihop-saas').benchmarkVersion
  const cellConfigs = [...new Set(cells.map((c) => c.effectiveConfigHash).filter((v): v is string => Boolean(v)))]
  const effectiveConfigHash = cellConfigs.length === 1 ? cellConfigs[0]! : null

  return {
    schemaVersion: V8_CERTIFY_SCHEMA_VERSION,
    status: reportStatus,
    failedCells,
    benchmarkVersion,
    effectiveConfigHash,
    gate,
    verdict,
    generatedAt: input.options?.generatedAt ?? new Date().toISOString(),
    gitSha,
    totalCells: cells.length,
    precision: {
      worstRunPrecision: cells.length > 0 ? worstRunPrecision : null,
      worstRunCell,
      totalHardenedTwinDecoyFps,
      totalUnmatchedFalsePositives,
      totalOssFalsePositives: totalOssFps,
      totalShortcutViolations,
      totalModeBViolations,
      inertAgenticCells,
      passed: precisionPassed && integrityPassed,
    },
    antiHeuristic: {
      cells: noLlmCells.length,
      chainsConfirmed: noLlmConfirmed,
      chainsTotal: noLlmTotal,
      recall: noLlmRecall,
      ceiling: V8_THRESHOLDS.antiHeuristicNoLlmMax,
      passed: antiHeuristicPassed,
    },
    modeSummaries,
    scalingCurve,
    scalingMonotonic: {
      tiersPresent,
      minRepeatsObserved,
      recallAt2_10m: r2,
      recallAt5_30m: r5,
      recallAt15_60m: r15,
      strictlyMonotonic,
      lift15Over2,
    },
    generalization: {
      devWhiteBoxMedian: devWb15.medianRecall,
      devGreyBoxMedian: devGb15.medianRecall,
      heldOutWhiteBoxMedian: heldOutWb15.medianRecall,
      heldOutGreyBoxMedian: heldOutGb15.medianRecall,
      devToHeldOutWbGap,
      devToHeldOutGbGap,
      sealedBlindFirstRunWb: sealedBlindFirstRun?.recall ?? null,
      sealedTwinFps: sealedWbSummary.hardenedTwinDecoyFps,
      devToSealedWbGap,
      overfittingViolation,
    },
    efficiency: {
      tier5Cells: tier5Cells.length,
      tier5Confirmed,
      tier5CostUsd,
      tpPerDollarAt5,
      tier30mCells: tier30mCells.length,
      tier30mConfirmed,
      tier30mDurationMs,
      tpPer10mAt30m,
    },
    waste,
    hopFunnel,
    oss,
    v7Floor,
    checks,
    failedChecks,
    notes,
  }
}

// ---------------------------------------------------------------------------
// Markdown (`CALIBRATION-v8.md`) & JSON Renderers
// ---------------------------------------------------------------------------

export function renderCalibrationJson(report: V8CertificationReport): string {
  return `${JSON.stringify(report, null, 2)}\n`
}

export function renderCalibrationMarkdown(report: V8CertificationReport): string {
  const lines: string[] = []
  const gateUpper = report.gate.toUpperCase()

  lines.push(`# Kovo Hunter v8 Calibration & Certification Scorecard (${gateUpper})`)
  lines.push('')
  lines.push(
    `**Verdict:** **${report.verdict}** · **Gate:** \`${gateUpper}\` · **Generated:** ${report.generatedAt} · **Git:** \`${report.gitSha}\``,
  )
  lines.push('')

  if (report.generalization.overfittingViolation) {
    lines.push(
      '> [!WARNING]',
      `> **OVERFITTING VIOLATION DETECTED:** Dev white-box median (${pct(report.generalization.devWhiteBoxMedian)}) dropped **${pp(report.generalization.devToSealedWbGap)}** on sealed \`connecthub\` blind first run (${pct(report.generalization.sealedBlindFirstRunWb)}), exceeding the 20.0 pp anti-overfitting ceiling.`,
      '',
    )
  }

  // ---- Gate Checklist ----
  lines.push(`## ${gateUpper} Gate Checklist (${report.checks.length - report.failedChecks.length}/${report.checks.length} PASS)`)
  lines.push('')
  lines.push(
    mdTable(
      ['Gate ID', 'Category', 'Check', 'Threshold', 'Observed', 'Status'],
      report.checks.map((c) => [
        `\`${c.id}\``,
        c.category,
        c.description,
        c.threshold,
        c.observed,
        c.status === 'PASS' ? '**PASS**' : '**FAIL**',
      ]),
    ),
  )
  lines.push('')

  // ---- Per-Mode Breakdown ----
  lines.push('## Per-Mode Breakdown (`black-box` / `grey-box` / `white-box`)')
  lines.push('')
  if (report.modeSummaries.length === 0) {
    lines.push('_No agentic cells recorded._')
  } else {
    lines.push(
      mdTable(
        [
          'Split',
          'Mode',
          'Repeats',
          'Median Recall',
          'Range',
          'Confirmed',
          'Worst Precision',
          'Twin FPs',
          'Unmatched FPs',
          'TP/$',
          'TP/10m',
        ],
        report.modeSummaries.map((m) => [
          m.split,
          `\`${m.mode}\``,
          String(m.repeats),
          pct(m.medianRecall),
          m.minRecall !== null && m.maxRecall !== null
            ? `${pct(m.minRecall)}–${pct(m.maxRecall)}`
            : 'n/a',
          `${m.chainsConfirmed}/${m.chainsTotal}`,
          pct(m.worstRunPrecision),
          `${m.hardenedTwinDecoyFps}/${m.hardenedTwinsTotal}`,
          String(m.unmatchedFalsePositives),
          fixed(m.tpPerDollar),
          fixed(m.tpPer10m),
        ]),
      ),
    )
  }
  lines.push('')

  // ---- Budget / Duration Scaling Curve ----
  lines.push('## Budget & Duration Scaling Curve (`$2/10m`, `$5/30m`, `$15/60m`)')
  lines.push('')
  if (report.scalingCurve.length === 0) {
    lines.push('_No scaling curve data recorded._')
  } else {
    lines.push(
      mdTable(
        [
          'Split',
          'Mode',
          'Tier',
          'Repeats',
          'Median Recall',
          '3–4 Hop',
          '5–6 Hop',
          'Waste %',
          'TP/$',
          'TP/10m',
          'Twin FPs',
          'Worst Precision',
        ],
        report.scalingCurve.map((p) => [
          p.split,
          `\`${p.mode}\``,
          p.tierLabel,
          String(p.repeats),
          pct(p.medianRecall),
          pct(p.hops3to4MedianRecall),
          pct(p.hops5to6MedianRecall),
          pct(p.deadEndWasteRate),
          fixed(p.tpPerDollar),
          fixed(p.tpPer10m),
          String(p.hardenedTwinDecoyFps),
          pct(p.worstRunPrecision),
        ]),
      ),
    )
    const sm = report.scalingMonotonic
    lines.push('')
    lines.push(
      `Dev white-box scaling curve: \`$2/10m\` **${pct(sm.recallAt2_10m)}** -> \`$5/30m\` **${pct(sm.recallAt5_30m)}** -> \`$15/60m\` **${pct(sm.recallAt15_60m)}** · Strictly monotonic: **${sm.strictlyMonotonic ? 'YES' : 'NO'}** · Lift (\`$15/60m − $2/10m\`): **${pp(sm.lift15Over2)}**`,
    )
  }
  lines.push('')

  // ---- Efficiency & Generalization ----
  lines.push('## Efficiency & Generalization Summary')
  lines.push('')
  lines.push(
    mdTable(
      ['Metric', 'Value', 'Target'],
      [
        ['`TP/$` ($5 tier)', fixed(report.efficiency.tpPerDollarAt5), '>= 0.50'],
        ['`TP/10m` (30m tier)', fixed(report.efficiency.tpPer10mAt30m), '>= 1.00'],
        ['Dead-end re-probing waste', pct(report.waste.wasteRate), '<= 5.0%'],
        ['Dev -> Held-Out gap (WB)', pp(report.generalization.devToHeldOutWbGap), '<= +10.0 pp'],
        ['Dev -> Held-Out gap (GB)', pp(report.generalization.devToHeldOutGbGap), '<= +10.0 pp'],
        [
          'Sealed `connecthub` blind first run (WB)',
          pct(report.generalization.sealedBlindFirstRunWb),
          '>= 50.0% (0/3 twin FPs)',
        ],
        [
          'Dev -> Sealed `connecthub` gap (WB)',
          `${pp(report.generalization.devToSealedWbGap)}${report.generalization.overfittingViolation ? ' (OVERFIT ALARM)' : ''}`,
          '<= +20.0 pp',
        ],
        [
          'Anti-heuristic (`--no-llm`)',
          report.antiHeuristic.recall === null
            ? 'n/a'
            : `${pct(report.antiHeuristic.recall)} (${report.antiHeuristic.chainsConfirmed}/${report.antiHeuristic.chainsTotal})`,
          '<= 5.0%',
        ],
      ],
    ),
  )
  lines.push('')

  // ---- Hop-Depth Funnel & Drop-Reason Breakdown ----
  const f = report.hopFunnel
  lines.push('## Hop-Depth Funnel & Drop-Reason Breakdown')
  lines.push('')
  lines.push(
    `Funnel: \`H1: ${f.H1} -> H2: ${f.H2} -> H3: ${f.H3} -> H4+: ${f.H4Plus} -> FinalOracle: ${f.FinalOracle} -> CompositeReceiptConfirmed: ${f.CompositeReceiptConfirmed}\` (Total chains: ${f.totalChains})`,
  )
  lines.push('')
  lines.push(
    mdTable(
      ['Stage', 'Count', 'Share of Total'],
      [
        ['Total Chains', String(f.totalChains), f.totalChains > 0 ? '100.0%' : 'n/a'],
        ['H1', String(f.H1), pct(f.totalChains > 0 ? f.H1 / f.totalChains : null)],
        ['H2', String(f.H2), pct(f.totalChains > 0 ? f.H2 / f.totalChains : null)],
        ['H3', String(f.H3), pct(f.totalChains > 0 ? f.H3 / f.totalChains : null)],
        ['H4+', String(f.H4Plus), pct(f.totalChains > 0 ? f.H4Plus / f.totalChains : null)],
        [
          'FinalOracle (ChainOracle v2)',
          String(f.FinalOracle),
          pct(f.totalChains > 0 ? f.FinalOracle / f.totalChains : null),
        ],
        [
          'CompositeReceiptConfirmed (Two-Side TP)',
          String(f.CompositeReceiptConfirmed),
          pct(f.totalChains > 0 ? f.CompositeReceiptConfirmed / f.totalChains : null),
        ],
      ],
    ),
  )
  lines.push('')

  const totalDrops = HOP_DROP_REASONS.reduce((acc, r) => acc + (f.dropReasons[r] ?? 0), 0)
  lines.push('### Drop-Reason Breakdown')
  lines.push('')
  lines.push(
    mdTable(
      ['Drop Reason', 'Count', 'Share of Drops'],
      HOP_DROP_REASONS.map((reason) => [
        `\`${reason}\``,
        String(f.dropReasons[reason] ?? 0),
        totalDrops > 0 ? pct((f.dropReasons[reason] ?? 0) / totalDrops) : '0.0%',
      ]),
    ),
  )
  lines.push('')

  // ---- OSS Multi-Hop Corpus ----
  if (report.oss !== null) {
    const o = report.oss
    lines.push('## OSS Multi-Hop Corpus')
    lines.push('')
    lines.push(
      mdTable(
        ['Metric', 'Observed', 'Target'],
        [
          ['Total Anchors', `${o.tpCount}/${o.totalAnchors} (${pct(o.overallRecall)})`, '8 targets'],
          [
            'Sealed Recall',
            `${o.sealedTpCount}/${o.sealedAnchors} (${pct(o.sealedRecall)})`,
            '>= 50.0%',
          ],
          ['Worst-Run Precision', `${pct(o.worstRunPrecision)} (totalFPs=${o.totalFpCount})`, '100.0% (0 FPs)'],
          [
            'Patch-Retest Closure',
            `${o.patchRetestClosed}/${o.patchRetestAttempted} (${pct(o.patchRetestClosureRate)})`,
            '>= 80.0%',
          ],
          [
            'Clean Patched Controls',
            `${o.cleanControlFpCount} FPs across ${o.cleanControlCount} controls`,
            '0 FPs across >= 2 controls',
          ],
          ['TP/$', fixed(o.tpPerUsd), 'informational'],
          ['TP/10m', fixed(o.tpPer10m), 'informational'],
        ],
      ),
    )
    lines.push('')
  }

  // ---- v7 Regression Floor ----
  if (report.v7Floor !== null) {
    const v = report.v7Floor
    lines.push('## v7 Regression Floor')
    lines.push('')
    lines.push(
      mdTable(
        ['Suite', 'Observed', 'Target'],
        [
          [
            'xben',
            v.xben ? `${v.xben.confirmed}/${v.xben.targets} (FPs=${v.xben.falsePositives})` : 'n/a',
            '25/25 (0 FPs)',
          ],
          [
            'held-out-saas',
            v.heldOutSaas
              ? `${v.heldOutSaas.confirmed}/${v.heldOutSaas.targets} det, ${v.heldOutSaas.patchesClosed}/${v.heldOutSaas.patchesTotal} patches`
              : 'n/a',
            '20/20 + 20/20 patches',
          ],
          ['reason-bench (`--no-llm`)', pct(v.reasonBench?.noLlmRecall ?? null), '<= 10.0%'],
          ['reason-bench (agentic)', pct(v.reasonBench?.agenticRecall ?? null), '>= 50.0%'],
          [
            'realistic-bench floor spread',
            v.realisticBench?.maxFloorSpread !== null && v.realisticBench !== null
              ? String(v.realisticBench.maxFloorSpread)
              : 'n/a',
            '0',
          ],
        ],
      ),
    )
    lines.push('')
  }

  if (report.notes.length > 0) {
    lines.push('## Notes')
    lines.push('')
    for (const note of report.notes) {
      lines.push(`- ${note}`)
    }
    lines.push('')
  }

  return `${lines.join('\n')}`
}

// ---------------------------------------------------------------------------
// File Loading (Reports, Meta Artifacts, Directories, OSS, v7 Floor)
// ---------------------------------------------------------------------------

function isCellLike(value: unknown): value is MultihopCellInput {
  if (!value || typeof value !== 'object') return false
  const obj = value as Record<string, unknown>
  return (
    typeof obj.app === 'string' &&
    typeof obj.chainsTotal === 'number' &&
    typeof obj.chainsConfirmed === 'number'
  )
}

function extractCellsFromParsed(parsed: unknown): MultihopCellInput[] {
  if (Array.isArray(parsed)) {
    return parsed.flatMap(extractCellsFromParsed)
  }
  if (!parsed || typeof parsed !== 'object') return []
  const obj = parsed as Record<string, unknown>
  if (Array.isArray(obj.cells)) {
    return obj.cells.filter(isCellLike)
  }
  if (isCellLike(obj)) {
    return [obj]
  }
  return []
}

function parseJsonFile(filePath: string): unknown {
  const raw = readFileSync(filePath, 'utf8')
  try {
    return JSON.parse(raw) as unknown
  } catch (err) {
    throw new Error(`Failed to parse JSON file ${filePath}: ${(err as Error).message}`)
  }
}

function collectJsonFilesFromDir(dirPath: string): string[] {
  const entries = readdirSync(dirPath).sort()
  const reportFile = entries.find((e) => e === 'multihop-report.json')
  if (reportFile) {
    return [join(dirPath, reportFile)]
  }
  const metaFiles = entries.filter((e) => e.endsWith('.meta.json')).map((e) => join(dirPath, e))
  if (metaFiles.length > 0) {
    return metaFiles
  }
  const files: string[] = []
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === '.git') continue
    const full = join(dirPath, entry)
    let st
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) {
      files.push(...collectJsonFilesFromDir(full))
    } else if (entry.endsWith('.json')) {
      files.push(full)
    }
  }
  return files
}

export function loadMultihopInputs(paths: readonly string[]): MultihopCellInput[] {
  const cells: MultihopCellInput[] = []
  for (const rawPath of paths) {
    const abs = resolve(rawPath)
    if (!existsSync(abs)) {
      throw new Error(`Input path does not exist: ${rawPath}`)
    }
    const st = statSync(abs)
    const files = st.isDirectory() ? collectJsonFilesFromDir(abs) : [abs]
    for (const file of files) {
      const parsed = parseJsonFile(file)
      cells.push(...extractCellsFromParsed(parsed))
    }
  }
  return cells
}

function collectOssJsonFilesFromDir(dirPath: string): string[] {
  const entries = readdirSync(dirPath).sort()
  const files: string[] = []
  for (const entry of entries) {
    if (entry === 'node_modules' || entry === '.git') continue
    const full = join(dirPath, entry)
    let st
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) {
      files.push(...collectOssJsonFilesFromDir(full))
    } else if (entry.endsWith('.json')) {
      files.push(full)
    }
  }
  return files
}

export function loadOssInputs(paths: readonly string[]): OssCorpusInput[] {
  const out: OssCorpusInput[] = []
  for (const rawPath of paths) {
    const abs = resolve(rawPath)
    if (!existsSync(abs)) {
      throw new Error(`OSS input path does not exist: ${rawPath}`)
    }
    const st = statSync(abs)
    const files = st.isDirectory() ? collectOssJsonFilesFromDir(abs) : [abs]
    for (const file of files) {
      const parsed = parseJsonFile(file)
      if (Array.isArray(parsed)) {
        for (const item of parsed) out.push(item as OssCorpusInput)
      } else if (parsed && typeof parsed === 'object' && Array.isArray((parsed as Record<string, unknown>).results)) {
        for (const item of (parsed as { results: OssCorpusInput[] }).results) out.push(item)
      } else if (parsed && typeof parsed === 'object') {
        out.push(parsed as OssCorpusInput)
      }
    }
  }
  return out
}

export function loadV7FloorInput(filePath: string): unknown {
  const abs = resolve(filePath)
  if (!existsSync(abs)) {
    throw new Error(`v7 floor path does not exist: ${filePath}`)
  }
  if (statSync(abs).isDirectory()) {
    throw new Error(`v7 floor path is a directory, expected a JSON file: ${filePath}`)
  }
  return parseJsonFile(abs)
}

// ---------------------------------------------------------------------------
// CLI Parsing & Entrypoint
// ---------------------------------------------------------------------------

const USAGE = `Kovo Hunter v8 Scaling & Certification Scorecard CLI

Usage:
  node scripts/certify-v8.ts --gate m2|m3|m4 --inputs <paths...> \\
    [--v7-floor <path>] [--oss <paths...>] \\
    [--out-md CALIBRATION-v8.md] [--out-json <path>] [--allow-missing-v7-floor]

Options:
  --gate <m2|m3|m4>          Milestone certification gate to evaluate (required)
  --inputs <paths...>        One or more multihop report JSONs, *.meta.json files, or directories
  --oss <paths...>           OSS multi-hop grade JSON file(s) or directories from benchmarks/oss-multihop/run.ts
  --v7-floor <path>          v7 regression floor JSON (xben, held-out-saas, reason-bench, realistic-bench)
  --out-md <path>            Write Markdown scorecard (e.g. CALIBRATION-v8.md)
  --out-json <path>          Write structured JSON report
  --allow-missing-v7-floor   Waive the v7 regression floor requirement in M4
  -h, --help                 Show this help message
`

function splitCsvOrTokens(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

export function parseCertifyV8Args(argv: readonly string[]): CertifyV8CliArgs {
  let gate: V8GateName | null = null
  const inputs: string[] = []
  const ossPaths: string[] = []
  let v7FloorPath: string | undefined
  let outMd: string | undefined
  let outJson: string | undefined
  let ledgerPath: string | undefined
  let promoteLedgerPath: string | undefined
  let allowMissingV7Floor = false
  let help = false

  const isFlagToken = (tok: string): boolean => tok.startsWith('--') || tok === '-h'

  for (let i = 0; i < argv.length; i += 1) {
    const rawToken = argv[i]!
    const eqIdx = rawToken.startsWith('--') ? rawToken.indexOf('=') : -1
    const token = eqIdx > 0 ? rawToken.slice(0, eqIdx) : rawToken
    const inlineVal = eqIdx > 0 ? rawToken.slice(eqIdx + 1) : undefined

    if (token === '-h' || token === '--help') {
      help = true
      continue
    }
    if (token === '--allow-missing-v7-floor') {
      allowMissingV7Floor = true
      continue
    }
    if (token === '--gate') {
      const next = inlineVal ?? argv[++i]
      const normalized = next?.toLowerCase()
      if (normalized !== 'm2' && normalized !== 'm3' && normalized !== 'm4') {
        throw new Error(`Invalid --gate value '${next ?? ''}'; expected m2, m3, or m4`)
      }
      gate = normalized
      continue
    }
    if (token === '--inputs' || token === '--input') {
      let consumed = 0
      if (inlineVal !== undefined) {
        inputs.push(...splitCsvOrTokens(inlineVal))
        consumed += 1
      }
      while (i + 1 < argv.length && !isFlagToken(argv[i + 1]!)) {
        inputs.push(...splitCsvOrTokens(argv[++i]!))
        consumed += 1
      }
      if (consumed === 0) throw new Error(`${token} requires at least one path`)
      continue
    }
    if (token === '--oss') {
      let consumed = 0
      if (inlineVal !== undefined) {
        ossPaths.push(...splitCsvOrTokens(inlineVal))
        consumed += 1
      }
      while (i + 1 < argv.length && !isFlagToken(argv[i + 1]!)) {
        ossPaths.push(...splitCsvOrTokens(argv[++i]!))
        consumed += 1
      }
      if (consumed === 0) throw new Error('--oss requires at least one path')
      continue
    }
    if (token === '--v7-floor') {
      const next = inlineVal ?? argv[++i]
      if (!next || isFlagToken(next)) throw new Error('--v7-floor requires a path')
      v7FloorPath = next
      continue
    }
    if (token === '--out-md') {
      const next = inlineVal ?? argv[++i]
      if (!next || isFlagToken(next)) throw new Error('--out-md requires a path')
      outMd = next
      continue
    }
    if (token === '--out-json') {
      const next = inlineVal ?? argv[++i]
      if (!next || isFlagToken(next)) throw new Error('--out-json requires a path')
      outJson = next
      continue
    }
    if (token === '--ledger') {
      const next = inlineVal ?? (argv[i + 1] && !isFlagToken(argv[i + 1]!) ? argv[++i] : undefined)
      ledgerPath = next ?? DEFAULT_LEDGER_PATH
      continue
    }
    if (token === '--promote-ledger') {
      const next = inlineVal ?? (argv[i + 1] && !isFlagToken(argv[i + 1]!) ? argv[++i] : undefined)
      promoteLedgerPath = next ?? DEFAULT_LEDGER_PATH
      continue
    }
    throw new Error(`Unknown CLI argument: ${rawToken}`)
  }

  if (!help) {
    if (!gate) throw new Error('Missing required flag: --gate m2|m3|m4')
    if (inputs.length === 0) throw new Error('Missing required flag: --inputs <paths...>')
  }

  return {
    gate: gate ?? 'm4',
    inputs,
    ossPaths,
    v7FloorPath,
    outMd,
    outJson,
    ledgerPath,
    promoteLedgerPath,
    allowMissingV7Floor,
    help,
  }
}

export function writeV8CertifyLedgerRows(input: {
  cells: readonly MultihopCellInput[]
  report: V8CertificationReport
  runId?: string
  runsDir?: string
  ledgerPath?: string
  promoteLedgerPath?: string
  repoRoot?: string
}): { perRunPath: string; rows: LedgerRow[] } {
  const gitState = resolveGitState(input.repoRoot)
  const normalized = input.cells.map(normalizeCell)
  const rows: LedgerRow[] = []
  let perRunPath = ''
  const runId = input.runId ?? `certify-v8-${input.report.gate}-${input.report.generatedAt.replace(/[:.]/g, '-')}-${process.pid}`
  for (const c of normalized) {
    const readerCell = ScorecardReader.read(
      {
        app: c.app,
        seed: c.seed,
        seedSet: c.seedSet,
        split: c.split,
        mode: c.mode,
        llm: c.llm,
        targets: c.chainsTotal,
        confirmed: c.chainsConfirmed,
        precision: c.precision,
        rawPrecision: c.rawPrecision,
        strictPrecision: c.strictPrecision,
        decoys: c.hardenedTwinsTotal,
        decoyFalsePositives: c.hardenedTwinDecoyFps,
        unmatchedFalsePositives: c.unmatchedFalsePositives,
        costUsd: c.costUsd,
        durationMs: c.durationMs,
      },
      { failed: c.failed || c.status === 'INVALID', inert: c.inert },
    )
    const row = buildLedgerRow({
      cell: readerCell,
      recordedAt: input.report.generatedAt,
      suite: 'multihop-saas',
      gitSha: c.gitSha ?? input.report.gitSha,
      dirty: gitState.dirty,
      benchmarkVersion: c.benchmarkVersion ?? input.report.benchmarkVersion,
      effectiveConfigHash: c.effectiveConfigHash ?? input.report.effectiveConfigHash ?? '0'.repeat(64),
      app: c.app,
      split: c.split,
      mode: c.mode,
      llm: c.llm,
      seed: c.seed,
      repeat: Number(c.repeatId ?? 1) || 1,
      certifying: input.report.verdict === 'PASS' && c.status === 'VALID',
      reportable: true,
      costUsd: c.costUsd,
      durationMs: c.durationMs,
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

export function main(argv: readonly string[] = process.argv.slice(2)): number {
  let args: CertifyV8CliArgs
  try {
    args = parseCertifyV8Args(argv)
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n\n${USAGE}`)
    return 2
  }

  if (args.help) {
    process.stdout.write(USAGE)
    return 0
  }

  let cells: MultihopCellInput[]
  let oss: OssCorpusInput[] | null = null
  let v7Floor: unknown = null

  try {
    cells = loadMultihopInputs(args.inputs)
    if (args.ossPaths.length > 0) {
      oss = loadOssInputs(args.ossPaths)
    }
    if (args.v7FloorPath) {
      v7Floor = loadV7FloorInput(args.v7FloorPath)
    }
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`)
    return 2
  }

  const report = evaluateV8Certification({
    gate: args.gate,
    cells,
    oss,
    v7Floor: v7Floor as V7RegressionFloorInput | null,
    options: {
      requireV7Floor: args.gate === 'm4' && !args.allowMissingV7Floor,
    },
  })

  const md = renderCalibrationMarkdown(report)
  const json = renderCalibrationJson(report)

  if (args.outMd) {
    const absMd = resolve(args.outMd)
    mkdirSync(dirname(absMd), { recursive: true })
    writeFileSync(absMd, md, 'utf8')
  }
  if (args.outJson) {
    const absJson = resolve(args.outJson)
    mkdirSync(dirname(absJson), { recursive: true })
    writeFileSync(absJson, json, 'utf8')
  }
  // Default per-run ledger writing (gitignored benchmarks/results/runs/<run-id>.jsonl);
  // promote to committed ledger via --promote-ledger (or legacy --ledger).
  writeV8CertifyLedgerRows({
    cells,
    report,
    ledgerPath: args.ledgerPath,
    promoteLedgerPath: args.promoteLedgerPath,
  })

  process.stdout.write(
    `[certify-v8] gate=${report.gate} verdict=${report.verdict} ` +
      `checks=${report.checks.length - report.failedChecks.length}/${report.checks.length} ` +
      `worstPrecision=${pct(report.precision.worstRunPrecision)}\n`,
  )
  if (report.failedChecks.length > 0) {
    for (const fc of report.failedChecks) {
      process.stdout.write(`  FAIL ${fc.id}: observed=${fc.observed} (threshold=${fc.threshold})\n`)
    }
  }

  return report.verdict === 'PASS' ? 0 : 1
}

const isDirectEntry =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))

if (isDirectEntry) {
  process.exit(main(process.argv.slice(2)))
}
