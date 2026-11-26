/**
 * Unit tests for Kovo Hunter v8 M2/M3/M4 Scaling & Certification Scorecard CLI (`scripts/certify-v8.ts`).
 *
 * Covers:
 *  - M2 PASS & FAIL cases (WB lift < +15 pp, 1 twin FP in 1 of 3 repeats fails worst-run precision,
 *    anti-heuristic --no-llm > 5%, GB/WB recall misses).
 *  - M3 PASS & FAIL cases (non-monotonic scaling, < +20 pp scaling lift, 3-4 hop < 60%,
 *    5-6 hop < 35%, dead-end re-probing waste > 5%, < 3 repeats).
 *  - M4 PASS & FAIL cases (dev -> held-out > 10 pp, dev -> sealed > 20 pp overfitting violation,
 *    invalid held-out seed < 1_000_000, sealed blind-first-run ordering, efficiency floor TP/$ & TP/10m,
 *    OSS clean-control FP, OSS patch-retest < 80%, OSS sealed recall < 50%, v7 regression floor misses,
 *    and full CALIBRATION-v8.md & JSON rendering + CLI exit codes).
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  HOP_DROP_REASONS,
  SCALING_TIERS,
  evaluateV8Certification,
  loadMultihopInputs,
  main,
  median,
  normalizeV7Floor,
  parseCertifyV8Args,
  renderCalibrationJson,
  renderCalibrationMarkdown,
  type MultihopCellInput,
  type MultihopChainVerdictInput,
  type MultihopMode,
  type OssCorpusInput,
  type V7RegressionFloorInput,
} from '../scripts/certify-v8.ts'

const REPO_ROOT = join(import.meta.dirname, '..')
const tempRoot = mkdtempSync(join(tmpdir(), 'kovo-v8-certify-test-'))
process.on('exit', () => rmSync(tempRoot, { recursive: true, force: true }))

// ---------------------------------------------------------------------------
// Synthetic Fixture Builders
// ---------------------------------------------------------------------------

const DEV_APPS = ['paygrid', 'shipforge', 'nexusiam'] as const

interface DevSuiteOptions {
  mode: MultihopMode
  budgetUsd: number
  maxDurationMs: number
  seed: number
  seedSet?: 'dev' | 'held-out'
  repeatId?: string
  /** Confirmed counts across [paygrid, shipforge, nexusiam] (each has 4 chains, 3 twins). */
  confirmedByApp: [number, number, number]
  /** Optional split of 3-4 hop vs 5-6 hop targets/confirmed across the 3 apps. */
  hops3to4ConfirmedByApp?: [number, number, number]
  hops5to6ConfirmedByApp?: [number, number, number]
  twinFpsByApp?: [number, number, number]
  unmatchedFpsByApp?: [number, number, number]
  costUsdPerApp?: number
  durationMsPerApp?: number
  deadEndReprobeCount?: number
  phaseBAssignments?: number
  deadEndReprobeWasteRate?: number
}

function makeChainVerdicts(
  app: string,
  confirmed34: number,
  confirmed56: number,
): MultihopChainVerdictInput[] {
  // Each dev archetype has 4 chains: two 3-4 hop chains and two 5-6 hop chains (total 6 + 6 = 12 across 3 apps).
  const verdicts: MultihopChainVerdictInput[] = []
  for (let i = 0; i < 2; i += 1) {
    const ok = i < confirmed34
    verdicts.push({
      chainId: `${app}-c34-${i + 1}`,
      expectedHops: 4,
      maxHopReached: ok ? 4 : 2,
      oracleObserved: ok,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      dropReason: ok ? null : 'pivot_not_discovered',
    })
  }
  for (let i = 0; i < 2; i += 1) {
    const ok = i < confirmed56
    verdicts.push({
      chainId: `${app}-c56-${i + 1}`,
      expectedHops: 5,
      maxHopReached: ok ? 5 : 3,
      oracleObserved: ok,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      dropReason: ok ? null : 'budget_exhausted',
    })
  }
  return verdicts
}

function makeDevSuiteCells(opts: DevSuiteOptions): MultihopCellInput[] {
  return DEV_APPS.map((app, idx) => {
    const confirmed = opts.confirmedByApp[idx]!
    const c34 = opts.hops3to4ConfirmedByApp ? opts.hops3to4ConfirmedByApp[idx]! : Math.min(2, confirmed)
    const c56 = opts.hops5to6ConfirmedByApp
      ? opts.hops5to6ConfirmedByApp[idx]!
      : Math.max(0, confirmed - c34)
    const twinFp = opts.twinFpsByApp?.[idx] ?? 0
    const unmatchedFp = opts.unmatchedFpsByApp?.[idx] ?? 0
    const totalFps = twinFp + unmatchedFp
    const precision = confirmed + totalFps > 0 ? confirmed / (confirmed + totalFps) : 1
    const chains = makeChainVerdicts(app, c34, c56)

    return {
      schemaVersion: 1,
      app,
      sealed: false,
      seed: opts.seed,
      seedSet: opts.seedSet ?? (opts.seed >= 1_000_000 ? 'held-out' : 'dev'),
      mode: opts.mode,
      llm: 'agentic',
      repeatId: opts.repeatId,
      budgetUsd: opts.budgetUsd,
      maxDurationMs: opts.maxDurationMs,
      costUsd: opts.costUsdPerApp ?? opts.budgetUsd * 0.8,
      durationMs: opts.durationMsPerApp ?? Math.round(opts.maxDurationMs * 0.75),
      chainsTotal: 4,
      chainsOracleObserved: confirmed,
      chainsCompositeConfirmed: confirmed,
      chainsConfirmed: confirmed,
      recall: confirmed / 4,
      precision,
      hardenedTwinsTotal: 3,
      hardenedTwinDecoyFps: twinFp,
      unmatchedFalsePositives: unmatchedFp,
      chains,
      phaseBAssignments: opts.phaseBAssignments ?? 40,
      deadEndReprobeCount: opts.deadEndReprobeCount ?? 1,
      deadEndReprobeWasteRate: opts.deadEndReprobeWasteRate,
      gitSha: 'abc123def456',
    }
  })
}

function makeNoLlmFloorCells(confirmedTotal = 0): MultihopCellInput[] {
  let rem = confirmedTotal
  return DEV_APPS.map((app) => {
    const c = Math.min(4, rem)
    rem -= c
    return {
      schemaVersion: 1,
      app,
      sealed: false,
      seed: 1,
      seedSet: 'dev',
      mode: 'white-box',
      llm: 'deterministic-no-llm',
      budgetUsd: 0,
      maxDurationMs: 300_000,
      costUsd: 0,
      durationMs: 45_000,
      chainsTotal: 4,
      chainsConfirmed: c,
      precision: 1,
      hardenedTwinsTotal: 3,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
    }
  })
}

function makeSealedConnecthubCell(overrides: Partial<MultihopCellInput> = {}): MultihopCellInput {
  const confirmed = overrides.chainsConfirmed ?? 3
  const twinFps = overrides.hardenedTwinDecoyFps ?? 0
  const unmatchedFps = overrides.unmatchedFalsePositives ?? 0
  const totalFps = twinFps + unmatchedFps
  const precision =
    overrides.precision ?? (confirmed + totalFps > 0 ? confirmed / (confirmed + totalFps) : 1)
  return {
    schemaVersion: 1,
    app: 'connecthub',
    sealed: true,
    seed: 9001,
    seedSet: 'dev',
    mode: 'white-box',
    llm: 'agentic',
    budgetUsd: 15,
    maxDurationMs: 3_600_000,
    startedAt: 1_750_000_000_000,
    costUsd: 11.2,
    durationMs: 2_400_000,
    chainsTotal: 4,
    chainsConfirmed: confirmed,
    precision,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: twinFps,
    unmatchedFalsePositives: unmatchedFps,
    chains: makeChainVerdicts('connecthub', Math.min(2, confirmed), Math.max(0, confirmed - 2)),
    phaseBAssignments: 50,
    deadEndReprobeCount: 1,
    ...overrides,
  }
}

function makePassingOssInputs(): OssCorpusInput[] {
  const devResult: OssCorpusInput = {
    schemaVersion: '1.0',
    runId: 'oss-dev-1',
    split: 'dev',
    mode: 'white-box',
    totalAnchors: 4,
    tpCount: 3,
    fnCount: 1,
    unmatchedFpCount: 0,
    spuriousAnchorFpCount: 0,
    cleanControlCount: 0,
    cleanControlFpCount: 0,
    totalFpCount: 0,
    recall: 0.75,
    precision: 1,
    patchRetestAttempted: 3,
    patchRetestClosed: 3,
    patchRetestClosureRate: 1,
    tpPerUsd: 0.75,
    tpPer10m: 1.5,
    anchorResults: [
      { anchorId: 'oss-dev-gitea', split: 'dev', twoSideConfirmed: true, patchRetestStatus: 'closed' },
      { anchorId: 'oss-dev-directus', split: 'dev', twoSideConfirmed: true, patchRetestStatus: 'closed' },
      { anchorId: 'oss-dev-ghost', split: 'dev', twoSideConfirmed: true, patchRetestStatus: 'closed' },
      { anchorId: 'oss-dev-mattermost', split: 'dev', twoSideConfirmed: false, patchRetestStatus: 'not_applicable' },
    ],
  }
  const sealedResult: OssCorpusInput = {
    schemaVersion: '1.0',
    runId: 'oss-sealed-1',
    split: 'sealed',
    mode: 'white-box',
    totalAnchors: 4,
    tpCount: 3,
    fnCount: 1,
    unmatchedFpCount: 0,
    spuriousAnchorFpCount: 0,
    cleanControlCount: 2,
    cleanControlFpCount: 0,
    totalFpCount: 0,
    recall: 0.75,
    precision: 1,
    patchRetestAttempted: 3,
    patchRetestClosed: 2,
    patchRetestClosureRate: 2 / 3,
    tpPerUsd: 0.65,
    tpPer10m: 1.2,
    anchorResults: [
      { anchorId: 'oss-sealed-iam', split: 'sealed', twoSideConfirmed: true, patchRetestStatus: 'closed' },
      { anchorId: 'oss-sealed-ci', split: 'sealed', twoSideConfirmed: true, patchRetestStatus: 'closed' },
      { anchorId: 'oss-sealed-bi', split: 'sealed', twoSideConfirmed: true, patchRetestStatus: 'open_still_reproduces' },
      { anchorId: 'oss-sealed-commerce', split: 'sealed', twoSideConfirmed: false, patchRetestStatus: 'not_applicable' },
    ],
    cleanControlResults: [
      { controlId: 'oss-clean-1', passed: true, fpCount: 0, unexpectedOracleTriggers: 0 },
      { controlId: 'oss-clean-2', passed: true, fpCount: 0, unexpectedOracleTriggers: 0 },
    ],
  }
  // Combined patch-retest closure: 5/6 = 83.3% >= 80%; sealed recall: 3/4 = 75% >= 50%; 8 total anchors + 2 clean controls.
  return [devResult, sealedResult]
}

function makePassingV7Floor(): V7RegressionFloorInput {
  return {
    xben: { confirmed: 25, targets: 25, falsePositives: 0 },
    heldOutSaas: { confirmed: 20, targets: 20, patchesClosed: 20, patchesTotal: 20, falsePositives: 0 },
    reasonBench: { noLlmRecall: 0.08, agenticRecall: 0.56, worstPrecision: 1 },
    realisticBench: { maxFloorSpread: 0 },
  }
}

function makePassingM3Cells(): MultihopCellInput[] {
  const cells: MultihopCellInput[] = [...makeNoLlmFloorCells(0)]
  for (const seed of [1, 2, 3]) {
    // $2/10m: 4/12 = 33.3%
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: SCALING_TIERS.t2_10m.budgetUsd,
        maxDurationMs: SCALING_TIERS.t2_10m.maxDurationMs,
        seed,
        confirmedByApp: [2, 1, 1],
        costUsdPerApp: 1.6,
        durationMsPerApp: 450_000,
        deadEndReprobeCount: 1,
        phaseBAssignments: 30,
      }),
    )
    // $5/30m: 6/12 = 50.0%
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: SCALING_TIERS.t5_30m.budgetUsd,
        maxDurationMs: SCALING_TIERS.t5_30m.maxDurationMs,
        seed,
        confirmedByApp: [2, 2, 2],
        costUsdPerApp: 3.5,
        durationMsPerApp: 1_000_000,
        deadEndReprobeCount: 1,
        phaseBAssignments: 40,
      }),
    )
    // $15/60m: 8/12 = 66.7% (3-4 hop: 5/6 = 83.3% >= 60%, 5-6 hop: 3/6 = 50.0% >= 35%)
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: SCALING_TIERS.t15_60m.budgetUsd,
        maxDurationMs: SCALING_TIERS.t15_60m.maxDurationMs,
        seed,
        confirmedByApp: [3, 3, 2],
        hops3to4ConfirmedByApp: [2, 2, 1],
        hops5to6ConfirmedByApp: [1, 1, 1],
        costUsdPerApp: 10.5,
        durationMsPerApp: 2_500_000,
        deadEndReprobeCount: 1,
        phaseBAssignments: 50,
      }),
    )
  }
  return cells
}

function makePassingM4Cells(): MultihopCellInput[] {
  const cells: MultihopCellInput[] = [...makeNoLlmFloorCells(0)]

  // Dev black-box (for per-mode table completeness)
  cells.push(
    ...makeDevSuiteCells({
      mode: 'black-box',
      budgetUsd: 15,
      maxDurationMs: 3_600_000,
      seed: 1,
      confirmedByApp: [1, 1, 1],
      costUsdPerApp: 9.0,
      durationMsPerApp: 2_000_000,
    }),
  )

  // Dev $2/10m & $5/30m WB (for scaling curve + M4 efficiency floor:
  // at $5/30m: 7 TP / $10.50 = 0.67 TP/$ >= 0.50; 7 TP / (3.0M ms = 5 x 10m) = 1.40 TP/10m >= 1.0)
  for (const seed of [1, 2, 3]) {
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 2,
        maxDurationMs: 600_000,
        seed,
        confirmedByApp: [1, 1, 1],
        costUsdPerApp: 1.5,
        durationMsPerApp: 420_000,
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [3, 2, 2],
        costUsdPerApp: 3.5,
        durationMsPerApp: 1_000_000,
      }),
      // Dev $15/60m WB: 8/12 = 66.7% >= 65%
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [3, 3, 2],
        hops3to4ConfirmedByApp: [2, 2, 1],
        hops5to6ConfirmedByApp: [1, 1, 1],
        costUsdPerApp: 11.0,
        durationMsPerApp: 2_400_000,
      }),
      // Dev $15/60m GB: 6/12 = 50.0% >= 45%
      ...makeDevSuiteCells({
        mode: 'grey-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [2, 2, 2],
        costUsdPerApp: 10.0,
        durationMsPerApp: 2_200_000,
      }),
    )
  }

  // Salted Held-Out (seeds >= 1_000_000), $15/60m, n = 3
  for (const seed of [1_000_001, 1_000_002, 1_000_003]) {
    cells.push(
      // Held-Out WB: 7/12 = 58.3% >= 55% (dev -> held-out gap = 8.3 pp <= 10 pp)
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        seedSet: 'held-out',
        confirmedByApp: [3, 2, 2],
        costUsdPerApp: 11.0,
        durationMsPerApp: 2_500_000,
      }),
      // Held-Out GB: 5/12 = 41.7% >= 40% (dev -> held-out gap = 8.3 pp <= 10 pp)
      ...makeDevSuiteCells({
        mode: 'grey-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        seedSet: 'held-out',
        confirmedByApp: [2, 2, 1],
        costUsdPerApp: 10.0,
        durationMsPerApp: 2_300_000,
      }),
    )
  }

  // Sealed connecthub blind first run: 2/4 = 50.0% >= 50%, gap = 66.7% - 50.0% = 16.7 pp <= 20 pp
  cells.push(makeSealedConnecthubCell({ chainsConfirmed: 2, hardenedTwinDecoyFps: 0 }))

  return cells
}

// ---------------------------------------------------------------------------
// Utility & Parsing Tests
// ---------------------------------------------------------------------------

test('median handles empty, odd, and even arrays accurately', () => {
  assert.equal(median([]), null)
  assert.equal(median([0.5]), 0.5)
  assert.equal(median([0.75, 0.25, 0.5]), 0.5)
  assert.equal(median([0.2, 0.6, 0.4, 0.8]), 0.5)
})

test('CLI arg parser parses multi-token, CSV, and optional flags cleanly', () => {
  const parsed = parseCertifyV8Args([
    '--gate',
    'm4',
    '--inputs',
    'a.json',
    'b.json,c.json',
    '--oss',
    'oss-dev.json',
    'oss-sealed.json',
    '--v7-floor',
    'v7.json',
    '--out-md',
    'CALIBRATION-v8.md',
    '--out-json',
    'out.json',
  ])
  assert.equal(parsed.gate, 'm4')
  assert.deepEqual(parsed.inputs, ['a.json', 'b.json', 'c.json'])
  assert.deepEqual(parsed.ossPaths, ['oss-dev.json', 'oss-sealed.json'])
  assert.equal(parsed.v7FloorPath, 'v7.json')
  assert.equal(parsed.outMd, 'CALIBRATION-v8.md')
  assert.equal(parsed.outJson, 'out.json')

  assert.throws(() => parseCertifyV8Args(['--gate', 'm9', '--inputs', 'a.json']), /Invalid --gate/)
  assert.throws(() => parseCertifyV8Args(['--gate', 'm2']), /Missing required flag: --inputs/)
})

// ---------------------------------------------------------------------------
// M2 Gate Tests (PASS & FAIL)
// ---------------------------------------------------------------------------

test('M2 PASS: Dev $5/30m GB >= 33%, WB >= 50%, WB-GB lift >= +15 pp, 0 twin FPs, --no-llm <= 5%', () => {
  const cells: MultihopCellInput[] = [
    ...makeNoLlmFloorCells(0),
    // GB: 4/12 = 33.3%
    ...makeDevSuiteCells({
      mode: 'grey-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      seed: 1,
      confirmedByApp: [2, 1, 1],
    }),
    // WB: 6/12 = 50.0% -> lift = +16.7 pp >= +15 pp
    ...makeDevSuiteCells({
      mode: 'white-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      seed: 1,
      confirmedByApp: [2, 2, 2],
    }),
  ]

  const report = evaluateV8Certification({ gate: 'm2', cells })
  assert.equal(report.verdict, 'PASS', JSON.stringify(report.failedChecks, null, 2))
  assert.equal(report.precision.worstRunPrecision, 1)
  assert.equal(report.precision.totalHardenedTwinDecoyFps, 0)
  assert.equal(report.antiHeuristic.passed, true)
})

test('M2 FAIL: WB lift over GB < +15 pp fails m2_whitebox_lift', () => {
  const cells: MultihopCellInput[] = [
    ...makeNoLlmFloorCells(0),
    // GB: 5/12 = 41.7%
    ...makeDevSuiteCells({
      mode: 'grey-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      seed: 1,
      confirmedByApp: [2, 2, 1],
    }),
    // WB: 6/12 = 50.0% -> lift = +8.3 pp < +15 pp!
    ...makeDevSuiteCells({
      mode: 'white-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      seed: 1,
      confirmedByApp: [2, 2, 2],
    }),
  ]

  const report = evaluateV8Certification({ gate: 'm2', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm2_whitebox_lift'))
  // GB and WB absolute floors themselves pass
  assert.equal(report.checks.find((c) => c.id === 'm2_greybox_recall')?.status, 'PASS')
  assert.equal(report.checks.find((c) => c.id === 'm2_whitebox_recall')?.status, 'PASS')
})

test('M2 FAIL: 1 hardened-twin decoy FP in 1 of 3 repeats fails worst-run precision (never averaged away)', () => {
  const cells: MultihopCellInput[] = [...makeNoLlmFloorCells(0)]
  for (const seed of [1, 2, 3]) {
    cells.push(
      ...makeDevSuiteCells({
        mode: 'grey-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [2, 1, 1],
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [3, 2, 2],
        // Inject exactly 1 twin FP in repeat 3 on nexusiam only
        twinFpsByApp: seed === 3 ? [0, 0, 1] : [0, 0, 0],
      }),
    )
  }

  const report = evaluateV8Certification({ gate: 'm2', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.precision.passed, false)
  assert.equal(report.precision.totalHardenedTwinDecoyFps, 1)
  assert.ok(report.precision.worstRunPrecision !== null && report.precision.worstRunPrecision < 1)
  assert.ok(report.failedChecks.some((c) => c.id === 'precision_worst_run'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm2_dev_twin_fps'))
})

test('M2 FAIL: anti-heuristic --no-llm > 5% (1/12 = 8.3%) fails anti_heuristic_no_llm', () => {
  const cells: MultihopCellInput[] = [
    ...makeNoLlmFloorCells(1),
    ...makeDevSuiteCells({
      mode: 'grey-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      seed: 1,
      confirmedByApp: [2, 1, 1],
    }),
    ...makeDevSuiteCells({
      mode: 'white-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      seed: 1,
      confirmedByApp: [2, 2, 2],
    }),
  ]

  const report = evaluateV8Certification({ gate: 'm2', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.antiHeuristic.passed, false)
  assert.ok(report.failedChecks.some((c) => c.id === 'anti_heuristic_no_llm'))
})

// ---------------------------------------------------------------------------
// M3 Gate Tests (PASS & FAIL)
// ---------------------------------------------------------------------------

test('M3 PASS: strict monotonic scaling, >= +20 pp lift, depth floors, waste <= 5%, 100% worst precision', () => {
  const cells = makePassingM3Cells()
  const report = evaluateV8Certification({ gate: 'm3', cells })

  assert.equal(report.verdict, 'PASS', JSON.stringify(report.failedChecks, null, 2))
  assert.equal(report.scalingMonotonic.strictlyMonotonic, true)
  assert.equal(report.scalingMonotonic.minRepeatsObserved, 3)
  assert.ok((report.scalingMonotonic.lift15Over2 ?? 0) >= 0.20)
  assert.ok((report.waste.wasteRate ?? 1) <= 0.05)
})

test('M3 FAIL: non-monotonic scaling ($5/30m == $15/60m) fails m3_monotonic_scaling', () => {
  const cells: MultihopCellInput[] = [...makeNoLlmFloorCells(0)]
  for (const seed of [1, 2, 3]) {
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 2,
        maxDurationMs: 600_000,
        seed,
        confirmedByApp: [1, 1, 1], // 25%
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [3, 3, 2], // 66.7%
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [3, 3, 2], // 66.7% (flat, not strictly > $5/30m!)
        hops3to4ConfirmedByApp: [2, 2, 1],
        hops5to6ConfirmedByApp: [1, 1, 1],
      }),
    )
  }

  const report = evaluateV8Certification({ gate: 'm3', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.scalingMonotonic.strictlyMonotonic, false)
  assert.ok(report.failedChecks.some((c) => c.id === 'm3_monotonic_scaling'))
})

test('M3 FAIL: scaling lift < +20 pp fails m3_scaling_lift even when strictly monotonic', () => {
  const cells: MultihopCellInput[] = [...makeNoLlmFloorCells(0)]
  for (const seed of [1, 2, 3]) {
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 2,
        maxDurationMs: 600_000,
        seed,
        confirmedByApp: [2, 2, 2], // 50.0%
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [3, 2, 2], // 58.3%
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [3, 3, 2], // 66.7% -> lift = +16.7 pp < +20 pp
        hops3to4ConfirmedByApp: [2, 2, 1],
        hops5to6ConfirmedByApp: [1, 1, 1],
      }),
    )
  }

  const report = evaluateV8Certification({ gate: 'm3', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.scalingMonotonic.strictlyMonotonic, true)
  assert.ok(report.failedChecks.some((c) => c.id === 'm3_scaling_lift'))
})

test('M3 FAIL: 5–6 hop recall < 35% fails m3_depth_5_6_hop', () => {
  const cells: MultihopCellInput[] = [...makeNoLlmFloorCells(0)]
  for (const seed of [1, 2, 3]) {
    cells.push(
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 2,
        maxDurationMs: 600_000,
        seed,
        confirmedByApp: [1, 1, 1], // 25%
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        seed,
        confirmedByApp: [2, 2, 1], // 41.7%
      }),
      ...makeDevSuiteCells({
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        seed,
        confirmedByApp: [2, 2, 3], // 58.3% overall, 3-4 hop 6/6 = 100%, 5-6 hop 1/6 = 16.7% < 35%!
        hops3to4ConfirmedByApp: [2, 2, 2],
        hops5to6ConfirmedByApp: [0, 0, 1],
      }),
    )
  }

  const report = evaluateV8Certification({ gate: 'm3', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm3_depth_5_6_hop'))
  assert.equal(report.checks.find((c) => c.id === 'm3_depth_3_4_hop')?.status, 'PASS')
})

test('M3 FAIL: dead-end re-probing waste > 5% fails m3_dead_end_waste', () => {
  const cells = makePassingM3Cells().map((c) =>
    c.llm === 'agentic' ? { ...c, deadEndReprobeCount: 4, phaseBAssignments: 50 } : c,
  ) // 8.0% > 5.0%

  const report = evaluateV8Certification({ gate: 'm3', cells })
  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm3_dead_end_waste'))
  assert.ok((report.waste.wasteRate ?? 0) > 0.05)
})

// ---------------------------------------------------------------------------
// M4 Gate Tests (PASS & FAIL)
// ---------------------------------------------------------------------------

test('M4 PASS: full certification (Dev + Salted Held-Out + Sealed + OSS + Efficiency + v7 floor)', () => {
  const report = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss: makePassingOssInputs(),
    v7Floor: makePassingV7Floor(),
    options: { gitSha: 'deadbeef1234', generatedAt: '2026-11-25T00:00:00.000Z' },
  })

  assert.equal(report.verdict, 'PASS', JSON.stringify(report.failedChecks, null, 2))
  assert.equal(report.generalization.overfittingViolation, false)
  assert.equal(report.precision.worstRunPrecision, 1)
  assert.ok((report.efficiency.tpPerDollarAt5 ?? 0) >= 0.5)
  assert.ok((report.efficiency.tpPer10mAt30m ?? 0) >= 1.0)

  // Verify CALIBRATION-v8.md rendering contains all required sections & metrics
  const md = renderCalibrationMarkdown(report)
  assert.match(md, /# Kovo(?: Hunter)? v8 Calibration & Certification Scorecard \(M4\)/)
  assert.match(md, /\*\*Verdict:\*\* \*\*PASS\*\*/)
  assert.match(md, /## M4 Gate Checklist/)
  assert.match(md, /## Per-Mode Breakdown/)
  assert.match(md, /`black-box`/)
  assert.match(md, /`grey-box`/)
  assert.match(md, /`white-box`/)
  assert.match(md, /## Budget & Duration Scaling Curve/)
  assert.match(md, /\$2\/10m/)
  assert.match(md, /\$5\/30m/)
  assert.match(md, /\$15\/60m/)
  assert.match(md, /`TP\/\$`/)
  assert.match(md, /`TP\/10m`/)
  assert.match(md, /## Hop-Depth Funnel & Drop-Reason Breakdown/)
  assert.match(md, /H1: \d+ -> H2: \d+ -> H3: \d+ -> H4\+: \d+ -> FinalOracle: \d+ -> CompositeReceiptConfirmed: \d+/)
  for (const reason of HOP_DROP_REASONS) {
    assert.ok(md.includes(`\`${reason}\``), `missing drop reason ${reason} in markdown`)
  }
  assert.match(md, /## OSS Multi-Hop Corpus/)
  assert.match(md, /## v7 Regression Floor/)
})

test('M4 FAIL: dev -> held-out gap > 10 pp fails m4_dev_heldout_gap even when held-out >= 55%', () => {
  // Dev WB = 9/12 = 75.0%, Held-Out WB = 7/12 = 58.3% -> gap = +16.7 pp > 10 pp!
  const cells = makePassingM4Cells().map((c) => {
    if (c.llm === 'agentic' && !c.sealed && c.seedSet === 'dev' && c.mode === 'white-box' && c.budgetUsd === 15) {
      return { ...c, chainsConfirmed: 3, recall: 0.75 }
    }
    return c
  })
  // Also bump sealed connecthub to 3/4 = 75% so only dev->held-out gap triggers
  const adjusted = cells.map((c) => (c.sealed ? { ...c, chainsConfirmed: 3, recall: 0.75 } : c))

  const report = evaluateV8Certification({
    gate: 'm4',
    cells: adjusted,
    oss: makePassingOssInputs(),
    v7Floor: makePassingV7Floor(),
  })

  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.checks.find((c) => c.id === 'm4_heldout_wb_recall')?.status, 'PASS')
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_dev_heldout_gap'))
})

test('M4 FAIL: dev -> sealed drop > 20 pp triggers OVERFITTING VIOLATION alarm & warning banner', () => {
  // Dev WB = 9/12 = 75.0%, Held-Out WB = 8/12 = 66.7% (gap 8.3 pp <= 10 pp),
  // Sealed connecthub blind first run = 2/4 = 50.0% (>= 50% passes recall floor, BUT 75% - 50% = +25 pp > 20 pp!)
  const cells = makePassingM4Cells().map((c) => {
    if (c.llm === 'agentic' && !c.sealed && c.mode === 'white-box' && c.budgetUsd === 15) {
      if (c.seedSet === 'dev') return { ...c, chainsConfirmed: 3, recall: 0.75 }
      if (c.seedSet === 'held-out') {
        const conf = c.app === 'nexusiam' ? 2 : 3
        return { ...c, chainsConfirmed: conf, recall: conf / 4 }
      }
    }
    return c
  })

  const report = evaluateV8Certification({
    gate: 'm4',
    cells,
    oss: makePassingOssInputs(),
    v7Floor: makePassingV7Floor(),
  })

  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.generalization.overfittingViolation, true)
  assert.equal(report.checks.find((c) => c.id === 'm4_sealed_wb_recall')?.status, 'PASS')
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_sealed_overfit_guard'))

  const md = renderCalibrationMarkdown(report)
  assert.match(md, /OVERFITTING VIOLATION DETECTED/)
})

test('M4 FAIL: sealed connecthub blind first run cannot be overridden by a better second run', () => {
  const cells = [
    ...makePassingM4Cells().filter((c) => !c.sealed),
    // Blind first run (earlier timestamp): 1/4 = 25% -> FAIL
    makeSealedConnecthubCell({
      repeatId: 'blind-run-1',
      startedAt: 1_750_000_000_000,
      chainsConfirmed: 1,
      recall: 0.25,
    }),
    // Second run (later timestamp): 4/4 = 100% -> must NOT override blind first run!
    makeSealedConnecthubCell({
      repeatId: 'run-2',
      startedAt: 1_750_010_000_000,
      chainsConfirmed: 4,
      recall: 1.0,
    }),
  ]

  const report = evaluateV8Certification({
    gate: 'm4',
    cells,
    oss: makePassingOssInputs(),
    v7Floor: makePassingV7Floor(),
  })

  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.generalization.sealedBlindFirstRunWb, 0.25)
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_sealed_wb_recall'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_sealed_overfit_guard'))
})

test('M4 FAIL: efficiency floor misses (TP/$ < 0.50 at $5 tier and TP/10m < 1.0 at 30m tier)', () => {
  const cells = makePassingM4Cells().map((c) => {
    if (c.llm === 'agentic' && !c.sealed && c.budgetUsd === 5 && c.maxDurationMs === 1_800_000) {
      // 3 confirmed across 3 apps (1 each) / $14.40 = 0.21 TP/$ < 0.50; 3 / (5.4M ms = 9 x10m) = 0.33 TP/10m < 1.0
      return { ...c, chainsConfirmed: 1, recall: 0.25, costUsd: 4.8, durationMs: 1_800_000 }
    }
    return c
  })

  const report = evaluateV8Certification({
    gate: 'm4',
    cells,
    oss: makePassingOssInputs(),
    v7Floor: makePassingV7Floor(),
  })

  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_efficiency_tp_per_dollar'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_efficiency_tp_per_10m'))
})

test('M4 FAIL: OSS clean control FP fails both precision_worst_run and m4_oss_clean_controls', () => {
  const oss = makePassingOssInputs()
  oss[1] = {
    ...oss[1]!,
    cleanControlFpCount: 1,
    totalFpCount: 1,
    precision: 3 / 4,
    cleanControlResults: [
      { controlId: 'oss-clean-1', passed: false, fpCount: 1, unexpectedOracleTriggers: 0 },
      { controlId: 'oss-clean-2', passed: true, fpCount: 0, unexpectedOracleTriggers: 0 },
    ],
  }

  const report = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss,
    v7Floor: makePassingV7Floor(),
  })

  assert.equal(report.verdict, 'FAIL')
  assert.equal(report.precision.passed, false)
  assert.equal(report.precision.totalOssFalsePositives, 1)
  assert.ok(report.failedChecks.some((c) => c.id === 'precision_worst_run'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_oss_clean_controls'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_oss_sealed_recall'))
})

test('M4 FAIL: OSS patch-retest closure < 80% fails m4_oss_patch_retest', () => {
  const oss = makePassingOssInputs()
  // 2/3 closed in dev + 2/3 closed in sealed = 4/6 = 66.7% < 80%
  oss[0] = { ...oss[0]!, patchRetestAttempted: 3, patchRetestClosed: 2, patchRetestClosureRate: 2 / 3 }

  const report = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss,
    v7Floor: makePassingV7Floor(),
  })

  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_oss_patch_retest'))
  assert.equal(report.checks.find((c) => c.id === 'm4_oss_clean_controls')?.status, 'PASS')
})

test('M4 FAIL: v7 regression floor misses (xben 24/25, held-out-saas 19/20 patches, reason-bench)', () => {
  const badFloor: V7RegressionFloorInput = {
    xben: { confirmed: 24, targets: 25, falsePositives: 0 },
    heldOutSaas: { confirmed: 20, targets: 20, patchesClosed: 19, patchesTotal: 20, falsePositives: 0 },
    reasonBench: { noLlmRecall: 0.12, agenticRecall: 0.45, worstPrecision: 1 },
    realisticBench: { maxFloorSpread: 1 },
  }

  const report = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss: makePassingOssInputs(),
    v7Floor: badFloor,
  })

  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_v7_xben'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_v7_heldout_saas'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_v7_reason_no_llm'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_v7_reason_agentic'))
  assert.ok(report.failedChecks.some((c) => c.id === 'm4_v7_realistic_spread'))
})

test('normalizeV7Floor extracts reason-bench and realistic-bench spread from certify-phase1 Certificate shape', () => {
  const phase1Like = {
    floor: { spread: { appA: 0, appB: 0 } },
    reason: {
      floor: { confirmed: 1, targets: 12, recall: 1 / 12 },
      agentic: { confirmed: 7, targets: 12, recall: 7 / 12, worstPrecision: 1, cells: 1 },
    },
  }
  const normalized = normalizeV7Floor(phase1Like)
  assert.ok(normalized)
  assert.equal(normalized.realisticBench?.maxFloorSpread, 0)
  assert.ok(Math.abs((normalized.reasonBench?.noLlmRecall ?? 0) - 1 / 12) < 1e-9)
  assert.ok(Math.abs((normalized.reasonBench?.agenticRecall ?? 0) - 7 / 12) < 1e-9)
})

// ---------------------------------------------------------------------------
// End-to-End File Loading & CLI Execution Tests
// ---------------------------------------------------------------------------

test('CLI end-to-end: PASS writes CALIBRATION-v8.md and JSON with exit 0; FAIL exits non-zero', () => {
  const workDir = join(tempRoot, 'cli-e2e')
  const reportDir = join(workDir, 'bench-dir')
  mkdirSync(reportDir, { recursive: true })

  // Write a benchmark-multihop.ts-shaped MultihopReport inside a directory (plus a stale .meta.json
  // that must NOT be double-counted because multihop-report.json takes precedence).
  const m4Cells = makePassingM4Cells()
  writeFileSync(
    join(reportDir, 'multihop-report.json'),
    JSON.stringify({ schemaVersion: 1, cells: m4Cells }, null, 2),
    'utf8',
  )
  writeFileSync(
    join(reportDir, 'paygrid-seed1-white-box.meta.json'),
    JSON.stringify(m4Cells[0], null, 2),
    'utf8',
  )

  const loaded = loadMultihopInputs([reportDir])
  assert.equal(loaded.length, m4Cells.length)

  const ossPath = join(workDir, 'oss.json')
  const v7Path = join(workDir, 'v7-floor.json')
  const outMd = join(workDir, 'CALIBRATION-v8.md')
  const outJson = join(workDir, 'calibration-v8.json')
  writeFileSync(ossPath, JSON.stringify(makePassingOssInputs(), null, 2), 'utf8')
  writeFileSync(v7Path, JSON.stringify(makePassingV7Floor(), null, 2), 'utf8')

  // In-process PASS run
  const exitPass = main([
    '--gate',
    'm4',
    '--inputs',
    reportDir,
    '--oss',
    ossPath,
    '--v7-floor',
    v7Path,
    '--out-md',
    outMd,
    '--out-json',
    outJson,
  ])
  assert.equal(exitPass, 0)
  assert.ok(existsSync(outMd))
  assert.ok(existsSync(outJson))

  const mdContent = readFileSync(outMd, 'utf8')
  const jsonContent = JSON.parse(readFileSync(outJson, 'utf8')) as { verdict: string; gate: string }
  assert.equal(jsonContent.verdict, 'PASS')
  assert.equal(jsonContent.gate, 'm4')
  assert.match(mdContent, /Kovo(?: Hunter)? v8 Calibration & Certification Scorecard \(M4\)/)

  // Verify JSON renderer round-trips cleanly
  const sampleReport = evaluateV8Certification({
    gate: 'm4',
    cells: m4Cells,
    oss: makePassingOssInputs(),
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(JSON.parse(renderCalibrationJson(sampleReport)).verdict, 'PASS')

  // Subprocess CLI FAIL run (missing --oss and --v7-floor on M4 must exit non-zero)
  let failedExitCode = 0
  try {
    execFileSync(
      process.execPath,
      [join(REPO_ROOT, 'scripts/certify-v8.ts'), '--gate', 'm4', '--inputs', reportDir],
      { cwd: REPO_ROOT, encoding: 'utf8', stdio: 'pipe' },
    )
  } catch (err) {
    failedExitCode = (err as { status?: number }).status ?? 0
  }
  assert.equal(failedExitCode, 1)
})
