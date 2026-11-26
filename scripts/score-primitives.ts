/**
 * Authoritative scoring & ledger-row primitives (`R2-05`, `plans/claude_quality_2.md` §5).
 *
 * Single source of truth for:
 *  - `ratioOrNull(numerator, denominator)` — NEVER defaults `0/0` to `1`.
 *  - `ScorecardReader` — schema-validated reader classifying every benchmark cell strictly into
 *    one of 3 states: `'ok_with_claims' | 'ok_no_claims' | 'failed_inert'`.
 *  - `buildLedgerRow(...)` — single authoritative `LedgerRow` constructor enforcing accurate
 *    `rawPrecision` vs `headlinePrecision`, fail-closed `INVALID` on `failed_inert`, and optional
 *    R2-23/R2-06 fields (`preservationRatio`, `floorConfirmed`, `agenticConfirmed`).
 */
import { existsSync, readFileSync } from 'node:fs'
import {
  LEDGER_SCHEMA_VERSION,
  validateLedgerRow,
  type BenchmarkSuiteName,
  type EffectiveConfigSnapshot,
  type LedgerRow,
} from './bench-ledger.ts'

export type CellReadState = 'ok_with_claims' | 'ok_no_claims' | 'failed_inert'

export type ScorecardSplit = 'dev' | 'held-out' | 'sealed'
export type ScorecardLlmMode = 'agentic' | 'deterministic-no-llm'

export interface ScorecardReadMeta {
  /** Child exit code, if launched via a matrix harness. */
  exitCode?: number | null
  /** Allow specific non-zero exit codes (e.g. exit 3 anti-heuristic gate violation). */
  allowedExitCodes?: readonly number[]
  /** Explicit cell failure flag (timeout, process crash, missing meta). */
  failed?: boolean
  /** Explicit inert flag (e.g. agentic cell produced no worker activity/facts). */
  inert?: boolean
  /** Explicit configuration/preflight failure flag. */
  configError?: boolean
  /** Contract-leaked static-only/advisory claims inside confirmed findings. */
  contractLeaks?: number
  /** Fallback metadata when absent from the scorecard JSON. */
  app?: string
  seed?: number
  split?: ScorecardSplit
  mode?: string
  llm?: ScorecardLlmMode
  durationMs?: number
  costUsd?: number | null
  /** Human-readable failure reason from child logs. */
  error?: string
}

export interface NormalizedScorecardCell {
  state: CellReadState
  status: 'VALID' | 'INVALID'
  valid: boolean
  failed: boolean
  inert: boolean
  reasons: string[]
  app: string
  seed: number
  seedSet: 'dev' | 'held-out'
  split: ScorecardSplit
  mode: string
  llm: ScorecardLlmMode
  targets: number
  confirmed: number
  recall: number | null
  decoys: number
  decoyFalsePositives: number
  unmatchedFalsePositives: number
  misclassifiedCount: number
  contractLeaks: number
  /** Headline precision: TP / (TP + decoyFP + unmatchedFP + contractLeaks), or null on empty/failed. */
  headlinePrecision: number | null
  /** Pre-adjudication strict precision: TP / (TP + decoyFP + unmatchedFP + misclassified + contractLeaks), or null. */
  rawPrecision: number | null
  /** Conservative strict precision (charges misclassifications + contract leaks), or null on empty/failed. */
  strictPrecision: number | null
  /** Observed spend in USD: `0` for `--no-llm` when absent; `null` when agentic cost telemetry is missing. */
  costUsd: number | null
  durationMs: number
  benchmarkVersion: string | null
  effectiveConfigHash: string | null
}

export interface BuildLedgerRowInput {
  /** Normalized scorecard cell (from `ScorecardReader.read(...)`) or raw scorecard object. */
  cell: NormalizedScorecardCell | Record<string, unknown>
  /** Optional read metadata used when `cell` is a raw object. */
  readMeta?: ScorecardReadMeta
  suite: BenchmarkSuiteName
  gitSha: string
  dirty: boolean
  benchmarkVersion: string
  effectiveConfigHash: string
  effectiveConfig?: EffectiveConfigSnapshot
  recordedAt?: string
  app?: string
  split?: ScorecardSplit
  mode?: string
  llm?: ScorecardLlmMode
  seed?: number
  repeat?: number
  certifying?: boolean
  reportable?: boolean
  validUnplantedCount?: number
  costUsd?: number | null
  durationMs?: number
  siteOutcomes?: Record<string, string>
  notes?: string[]
  /** Optional R2-23 / R2-06 preservation & floor-vs-agentic split metrics. */
  preservationRatio?: number | null
  floorConfirmed?: number | null
  agenticConfirmed?: number | null
  exposedHeldoutSeeds?: number[]
}

/**
 * Exact ratio `numerator / denominator`, or `null` whenever `denominator <= 0` or either operand
 * is non-finite. NEVER defaults `0 / 0` to `1`.
 */
export function ratioOrNull(numerator: number, denominator: number): number | null {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) {
    return null
  }
  return numerator / denominator
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function finiteNumberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

/**
 * Resolve honest cost telemetry (R3-09):
 *  - Returns the first finite non-negative cost value when telemetry is present.
 *  - When cost telemetry is absent: returns `0` ONLY for `'deterministic-no-llm'` runs
 *    (which genuinely invoke no LLM), and `null` for `'agentic'` runs — never coercing
 *    missing agentic spend to `0`.
 */
function resolveHonestCostUsd(llm: ScorecardLlmMode, ...candidates: readonly unknown[]): number | null {
  for (const cand of candidates) {
    const n = finiteNumberOrNull(cand)
    if (n !== null) return Math.max(0, n)
  }
  return llm === 'deterministic-no-llm' ? 0 : null
}

function nonNegativeIntOrNull(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null
  return value
}

function clampUnitOrNull(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null
  if (value < 0 || value > 1) return null
  return value
}

function normalizeLlmMode(raw: unknown, fallback: ScorecardLlmMode = 'agentic'): ScorecardLlmMode {
  if (typeof raw !== 'string') return fallback
  const lowered = raw.trim().toLowerCase()
  if (lowered === 'deterministic-no-llm' || lowered === 'deterministic' || lowered === 'no-llm' || lowered === 'floor') {
    return 'deterministic-no-llm'
  }
  if (lowered === 'agentic') return 'agentic'
  return fallback
}

function normalizeSplit(
  rawSplit: unknown,
  rawSeedSet: unknown,
  seed: number,
  sealed: boolean,
  fallback?: ScorecardSplit,
): { seedSet: 'dev' | 'held-out'; split: ScorecardSplit } {
  const seedSet: 'dev' | 'held-out' =
    rawSeedSet === 'held-out' || rawSeedSet === 'heldout' || rawSeedSet === 'heldOut'
      ? 'held-out'
      : rawSeedSet === 'dev'
        ? 'dev'
        : seed >= 1_000_000
          ? 'held-out'
          : 'dev'

  if (sealed || rawSplit === 'sealed') return { seedSet, split: 'sealed' }
  if (rawSplit === 'held-out' || rawSplit === 'heldout') return { seedSet: 'held-out', split: 'held-out' }
  if (rawSplit === 'dev') return { seedSet: 'dev', split: 'dev' }
  if (fallback) return { seedSet, split: fallback }
  return { seedSet, split: seedSet }
}

function isNormalizedScorecardCell(value: unknown): value is NormalizedScorecardCell {
  if (!isRecord(value)) return false
  return (
    (value.state === 'ok_with_claims' || value.state === 'ok_no_claims' || value.state === 'failed_inert') &&
    (value.status === 'VALID' || value.status === 'INVALID') &&
    typeof value.targets === 'number' &&
    typeof value.confirmed === 'number' &&
    'headlinePrecision' in value &&
    'rawPrecision' in value
  )
}

function minPresent(a: number | null, b: number | null): number | null {
  if (a === null) return b
  if (b === null) return a
  return Math.min(a, b)
}

/**
 * Schema-validated scorecard reader shared across realistic-bench, reason-bench, recall,
 * multihop-saas, OSS corpus, matrices, and certification runners.
 *
 * Classifies every cell strictly into one of 3 states:
 *  - `'failed_inert'`: missing/malformed JSON, schema violation, non-zero exit, `status === 'INVALID'`,
 *    `failed === true`, `configError === true`, or `inert === true`. Always produces `status: 'INVALID'`
 *    and `recall: null`, `headlinePrecision: null`, `rawPrecision: null`, `strictPrecision: null`.
 *  - `'ok_no_claims'`: healthy run with 0 confirmed TPs and 0 FP/misclassified/leak claims (e.g., clean
 *    control or anti-heuristic floor run). Produces `status: 'VALID'`, `recall: ratioOrNull(0, targets)`,
 *    and `headlinePrecision: null`, `rawPrecision: null`, `strictPrecision: null` (NEVER `1`).
 *  - `'ok_with_claims'`: healthy run with >= 1 graded claim (TP, FP, misclassified, or leak).
 */
export class ScorecardReader {
  read(raw: unknown, meta: ScorecardReadMeta = {}): NormalizedScorecardCell {
    const reasons: string[] = []
    const allowedExits = new Set<number>([0, ...(meta.allowedExitCodes ?? [])])

    if (meta.exitCode !== undefined && meta.exitCode !== null && !allowedExits.has(meta.exitCode)) {
      reasons.push(`exit_code:${meta.exitCode}`)
    }
    if (meta.failed === true) reasons.push('meta_failed')
    if (meta.configError === true) reasons.push('meta_config_error')
    if (meta.inert === true) reasons.push('meta_inert')
    if (meta.error) reasons.push(meta.error)

    if (!isRecord(raw)) {
      reasons.push('missing_or_malformed_scorecard')
      const seed = meta.seed ?? 0
      const { seedSet, split } = normalizeSplit(meta.split, undefined, seed, false, meta.split)
      const llm = meta.llm ?? 'agentic'
      return {
        state: 'failed_inert',
        status: 'INVALID',
        valid: false,
        failed: true,
        inert: meta.inert === true,
        reasons,
        app: meta.app ?? 'unknown',
        seed,
        seedSet,
        split,
        mode: meta.mode ?? 'grey-box',
        llm,
        targets: 0,
        confirmed: 0,
        recall: null,
        decoys: 0,
        decoyFalsePositives: 0,
        unmatchedFalsePositives: 0,
        misclassifiedCount: 0,
        contractLeaks: Math.max(0, finiteNumberOrNull(meta.contractLeaks) ?? 0),
        headlinePrecision: null,
        rawPrecision: null,
        strictPrecision: null,
        costUsd: resolveHonestCostUsd(llm, meta.costUsd),
        durationMs: Math.max(0, finiteNumberOrNull(meta.durationMs) ?? 0),
        benchmarkVersion: null,
        effectiveConfigHash: null,
      }
    }

    if (raw.failed === true) reasons.push('card_failed')
    if (raw.status === 'INVALID') reasons.push('card_status_invalid')
    const inert = raw.inert === true || meta.inert === true
    if (raw.inert === true && !reasons.includes('meta_inert')) reasons.push('card_inert')

    const app =
      typeof raw.app === 'string' && raw.app.trim().length > 0
        ? raw.app.trim()
        : (meta.app ?? 'unknown')
    const seed = finiteNumberOrNull(raw.seed) ?? meta.seed ?? 0
    const sealed = raw.sealed === true
    const { seedSet, split } = normalizeSplit(raw.split, raw.seedSet, seed, sealed, meta.split)
    const mode =
      typeof raw.mode === 'string' && raw.mode.trim().length > 0
        ? raw.mode.trim()
        : (meta.mode ?? 'grey-box')
    const llm = normalizeLlmMode(raw.llm, meta.llm ?? 'agentic')

    // Extract targets & confirmed across realistic-bench, reason-bench, recall, multihop-saas, and OSS schemas.
    const targetsRaw =
      raw.targets ?? raw.targetsTotal ?? raw.chainsTotal ?? raw.totalAnchors
    const confirmedRaw =
      raw.confirmed ?? raw.confirmedCount ?? raw.chainsConfirmed ?? raw.tpCount

    const targets = nonNegativeIntOrNull(targetsRaw)
    const confirmed = nonNegativeIntOrNull(confirmedRaw)
    if (targets === null) reasons.push('schema_invalid:targets')
    if (confirmed === null) reasons.push('schema_invalid:confirmed')

    // Decoys & hardened twins
    const twinsArr = Array.isArray(raw.hardenedTwins) ? raw.hardenedTwins : []
    const twinFpsFromArr = twinsArr.filter(
      (t): t is Record<string, unknown> => isRecord(t) && t.falsePositive === true,
    ).length
    const decoys = Math.max(
      nonNegativeIntOrNull(raw.decoys ?? raw.decoysTotal ?? raw.hardenedTwinsTotal ?? raw.cleanControlCount) ?? 0,
      twinsArr.length,
    )

    // False positives (decoy/twin + unmatched + OSS clean-control/spurious + contract leaks)
    const decoyFpDirect = nonNegativeIntOrNull(
      raw.decoyFalsePositives ?? raw.hardenedTwinDecoyFps ?? raw.hardenedTwinFalsePositives ?? raw.cleanControlFpCount,
    )
    const decoyFp = Math.max(decoyFpDirect ?? 0, twinFpsFromArr)

    const unmatchedFpDirect = nonNegativeIntOrNull(
      raw.unmatchedFalsePositives ?? raw.unmatchedFpCount ?? raw.unmatchedConfirmedCount,
    )
    const spuriousFp = nonNegativeIntOrNull(raw.spuriousAnchorFpCount) ?? 0
    const combinedFallbackFp =
      decoyFpDirect === null && unmatchedFpDirect === null
        ? (nonNegativeIntOrNull(raw.falsePositiveCount ?? raw.totalFpCount ?? raw.falsePositives) ?? 0)
        : 0

    const effectiveDecoyFp = decoyFpDirect !== null ? decoyFp : (twinFpsFromArr > 0 ? twinFpsFromArr : combinedFallbackFp)
    const effectiveUnmatchedFp = (unmatchedFpDirect ?? 0) + spuriousFp

    // Check if totalFpCount exceeds itemized components (e.g., OSS totalFpCount)
    const declaredTotalFp = nonNegativeIntOrNull(raw.totalFpCount ?? raw.falsePositiveCount ?? raw.falsePositives)
    const itemizedFp = effectiveDecoyFp + effectiveUnmatchedFp
    const extraFp = declaredTotalFp !== null && declaredTotalFp > itemizedFp ? declaredTotalFp - itemizedFp : 0

    const misclassifiedCount = Array.isArray(raw.misclassifiedFindingIds)
      ? raw.misclassifiedFindingIds.length
      : (nonNegativeIntOrNull(raw.misclassifiedCount) ?? 0)

    const contractLeaks = Math.max(
      0,
      nonNegativeIntOrNull(meta.contractLeaks) ?? nonNegativeIntOrNull(raw.contractLeaks) ?? 0,
    )

    const costUsd = resolveHonestCostUsd(llm, raw.totalCostUsd, raw.costUsd, meta.costUsd)
    const durationMs = Math.max(
      0,
      finiteNumberOrNull(raw.durationMs ?? raw.wallMs) ?? meta.durationMs ?? 0,
    )
    const benchmarkVersion =
      typeof raw.benchmarkVersion === 'string' && raw.benchmarkVersion.trim()
        ? raw.benchmarkVersion.trim()
        : null
    const effectiveConfigHash =
      typeof raw.effectiveConfigHash === 'string' && raw.effectiveConfigHash.trim()
        ? raw.effectiveConfigHash.trim()
        : null

    const isFailedOrInert = reasons.length > 0 || inert
    if (isFailedOrInert) {
      return {
        state: 'failed_inert',
        status: 'INVALID',
        valid: false,
        failed: true,
        inert,
        reasons,
        app,
        seed,
        seedSet,
        split,
        mode,
        llm,
        targets: targets ?? 0,
        confirmed: confirmed ?? 0,
        recall: null,
        decoys,
        decoyFalsePositives: effectiveDecoyFp,
        unmatchedFalsePositives: effectiveUnmatchedFp + extraFp,
        misclassifiedCount,
        contractLeaks,
        headlinePrecision: null,
        rawPrecision: null,
        strictPrecision: null,
        costUsd,
        durationMs,
        benchmarkVersion,
        effectiveConfigHash,
      }
    }

    const tp = confirmed!
    const totalTargets = targets!
    const totalHeadlineFp = effectiveDecoyFp + effectiveUnmatchedFp + extraFp + contractLeaks
    const headlineDenom = tp + totalHeadlineFp
    const rawDenom = headlineDenom + misclassifiedCount

    const computedHeadline = ratioOrNull(tp, headlineDenom)
    const computedRaw = ratioOrNull(tp, rawDenom)

    // Never trust a reported precision of 1 when there are 0 claims!
    // When claims exist (denom > 0), take min(reported, computed) so misreported 1.0 never hides FPs
    // while explicitly lower graded precision is preserved.
    const reportedHeadline = clampUnitOrNull(raw.precision)
    const reportedRaw = clampUnitOrNull(raw.rawPrecision)
    const reportedStrict = clampUnitOrNull(raw.strictPrecision)

    const headlinePrecision =
      computedHeadline === null ? null : minPresent(reportedHeadline, computedHeadline)
    const rawPrecision =
      computedRaw === null ? null : minPresent(reportedRaw, computedRaw)
    const strictPrecision =
      computedRaw === null ? null : minPresent(reportedStrict, computedRaw)

    const state: CellReadState = rawDenom > 0 ? 'ok_with_claims' : 'ok_no_claims'
    const recall = ratioOrNull(tp, totalTargets)

    return {
      state,
      status: 'VALID',
      valid: true,
      failed: false,
      inert: false,
      reasons: [],
      app,
      seed,
      seedSet,
      split,
      mode,
      llm,
      targets: totalTargets,
      confirmed: tp,
      recall,
      decoys,
      decoyFalsePositives: effectiveDecoyFp,
      unmatchedFalsePositives: effectiveUnmatchedFp + extraFp,
      misclassifiedCount,
      contractLeaks,
      headlinePrecision,
      rawPrecision,
      strictPrecision,
      costUsd,
      durationMs,
      benchmarkVersion,
      effectiveConfigHash,
    }
  }

  readFile(jsonPath: string, meta: ScorecardReadMeta = {}): NormalizedScorecardCell {
    if (!existsSync(jsonPath)) {
      return this.read(null, { ...meta, error: meta.error ?? `scorecard missing (${jsonPath})` })
    }
    try {
      const parsed = JSON.parse(readFileSync(jsonPath, 'utf8')) as unknown
      return this.read(parsed, meta)
    } catch (err) {
      return this.read(null, {
        ...meta,
        error: meta.error ?? `invalid JSON (${(err as Error).message})`,
      })
    }
  }

  static read(raw: unknown, meta?: ScorecardReadMeta): NormalizedScorecardCell {
    return DEFAULT_READER.read(raw, meta)
  }

  static readFile(jsonPath: string, meta?: ScorecardReadMeta): NormalizedScorecardCell {
    return DEFAULT_READER.readFile(jsonPath, meta)
  }
}

const DEFAULT_READER = new ScorecardReader()

/**
 * Single authoritative constructor for `LedgerRow`.
 *
 * Guarantees:
 *  - `rawPrecision` is always the pre-adjudication strict precision (charging decoy, unmatched,
 *    misclassified, and contract-leak claims) — NEVER blindly copied from headline `precision`.
 *  - `headlinePrecision` and `precision` are `null` on `ok_no_claims` and `failed_inert` (NEVER `1`).
 *  - `status` is `'INVALID'` and `recall` is `null` whenever `cell.state === 'failed_inert'`.
 *  - Validates the produced row via `validateLedgerRow(row)`.
 */
export function buildLedgerRow(input: BuildLedgerRowInput): LedgerRow {
  const cell: NormalizedScorecardCell = isNormalizedScorecardCell(input.cell)
    ? input.cell
    : ScorecardReader.read(input.cell, input.readMeta)

  const isFailed = cell.state === 'failed_inert'
  const status: 'VALID' | 'INVALID' = isFailed ? 'INVALID' : 'VALID'
  const recall = isFailed ? null : cell.recall
  const headlinePrecision = isFailed ? null : cell.headlinePrecision
  const rawPrecision = isFailed ? null : cell.rawPrecision
  const strictPrecision = isFailed ? null : cell.strictPrecision

  const resolvedLlm = input.llm ?? cell.llm
  const resolvedCostUsd: number | null =
    input.costUsd === null
      ? null
      : resolveHonestCostUsd(resolvedLlm, input.costUsd, cell.costUsd)

  const row: LedgerRow = {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    recordedAt: input.recordedAt ?? new Date().toISOString(),
    suite: input.suite,
    gitSha: input.gitSha,
    dirty: input.dirty,
    benchmarkVersion: input.benchmarkVersion,
    effectiveConfigHash: input.effectiveConfigHash,
    ...(input.effectiveConfig ? { effectiveConfig: input.effectiveConfig } : {}),
    app: input.app ?? cell.app,
    split: input.split ?? cell.split,
    mode: input.mode ?? cell.mode,
    llm: resolvedLlm,
    seed: input.seed ?? cell.seed,
    repeat: input.repeat ?? 1,
    certifying: Boolean(input.certifying) && !isFailed,
    reportable: input.reportable ?? true,
    status,
    cellState: cell.state,
    targets: cell.targets,
    confirmed: cell.confirmed,
    recall,
    headlinePrecision,
    rawPrecision,
    strictPrecision,
    precision: headlinePrecision,
    decoyFalsePositives: cell.decoyFalsePositives,
    unmatchedFalsePositives: cell.unmatchedFalsePositives,
    ...(input.validUnplantedCount !== undefined ? { validUnplantedCount: input.validUnplantedCount } : {}),
    costUsd: resolvedCostUsd,
    ...(input.durationMs !== undefined || cell.durationMs > 0
      ? { durationMs: input.durationMs ?? cell.durationMs }
      : {}),
    ...(input.preservationRatio !== undefined ? { preservationRatio: input.preservationRatio } : {}),
    ...(input.floorConfirmed !== undefined ? { floorConfirmed: input.floorConfirmed } : {}),
    ...(input.agenticConfirmed !== undefined ? { agenticConfirmed: input.agenticConfirmed } : {}),
    ...(input.exposedHeldoutSeeds && input.exposedHeldoutSeeds.length > 0
      ? { exposedHeldoutSeeds: [...input.exposedHeldoutSeeds] }
      : {}),
    ...(input.siteOutcomes ? { siteOutcomes: input.siteOutcomes } : {}),
    ...(input.notes && input.notes.length > 0 ? { notes: [...input.notes] } : {}),
  }

  validateLedgerRow(row)
  return row
}
