/**
 * Queue #34 schema-readiness and grading tests for `scripts/certify-v8.ts` (M2 / M3 / M4).
 *
 * Uses realistic `MultihopCellMeta` and `buildMultihopReport()` outputs from
 * `scripts/benchmark-multihop.ts` (and `CertifyOssGradeReport`-shaped OSS scorecards) to verify:
 *  - Compile-time & runtime schema compatibility between `benchmark-multihop.ts` and `certify-v8.ts`
 *  - M2 PASS & FAIL gates (WB >= 50%, GB >= 33%, WB lift >= +15 pp, 3-archetype Dev coverage,
 *    100.0% worst-run precision, 0 decoy/unmatched FPs, 0 shortcut/Mode-B violations, 0 inert cells)
 *  - M3 PASS & FAIL gates (strict monotonic scaling $2/10m < $5/30m < $15/60m, n=3 complete repeats,
 *    >= +20 pp lift, 3–4h >= 60%, 5–6h >= 35%, dead-end waste <= 5% from `telemetry.scheduler`,
 *    no zero-assignment dilution)
 *  - M4 PASS & FAIL gates (Dev + Salted Held-Out + Blind Sealed connecthub + OSS anchors/controls +
 *    v7 regression floor including fail-closed `realisticBench.maxFloorSpread`, CALIBRATION-v8.md)
 *  - Directory/single-file loading resilience (broken symlinks, nested dirs, `--oss` dir, `--flag=val`)
 */

import assert from 'node:assert/strict'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import type {
  DepthTierBreakdown,
  HopDepthFunnel,
  MultihopAppName,
  MultihopCellMeta,
  MultihopChainVerdict,
  MultihopLlmMode,
  MultihopMode,
  MultihopReport,
  MultihopTwinVerdict,
} from '../scripts/benchmark-multihop.ts'
import {
  SCALING_TIERS,
  buildHopFunnelFromVerdicts,
  computeDepthBreakdownFromVerdicts,
  evaluateV8Certification,
  loadMultihopInputs,
  loadOssInputs,
  main,
  parseCertifyV8Args,
  type MultihopCellInput,
  type OssCorpusInput,
  type V7RegressionFloorInput,
} from '../scripts/certify-v8.ts'

const tempRoot = mkdtempSync(join(tmpdir(), 'guardian-v8-q34-certify-'))
process.on('exit', () => rmSync(tempRoot, { recursive: true, force: true }))

const DEV_APPS: readonly MultihopAppName[] = ['paygrid', 'shipforge', 'nexusiam']

// Real hop depths from plans/v8.md (3 apps => 9 chains of 3-4h + 3 chains of 5-6h = 12 chains)
const APP_CHAIN_HOPS: Record<MultihopAppName, readonly number[]> = {
  paygrid: [4, 4, 5, 3],
  shipforge: [5, 4, 4, 3],
  nexusiam: [5, 4, 4, 4],
  connecthub: [4, 5, 4, 5],
}

interface BuildCellOptions {
  app: MultihopAppName
  seed: number
  mode: MultihopMode
  llm?: MultihopLlmMode
  budgetUsd: number
  maxDurationMs: number
  confirmedIndices?: readonly number[]
  twinFpCount?: number
  unmatchedFalsePositives?: number
  shortcutViolationIdx?: number
  modeBViolationIdx?: number
  inert?: boolean
  costUsd?: number
  durationMs?: number
  startedAt?: number
  phaseBAssignments?: number
  deadEndReprobes?: number
  omitTopLevelFrontier?: boolean
}

function makeRealisticCellMeta(opts: BuildCellOptions): MultihopCellMeta {
  const hops = APP_CHAIN_HOPS[opts.app]
  const confirmedSet = new Set(opts.confirmedIndices ?? [])
  const llm: MultihopLlmMode = opts.llm ?? 'agentic'
  const seedSet: 'dev' | 'held-out' = opts.seed >= 1_000_000 ? 'held-out' : 'dev'
  const prefix = opts.app.slice(0, 2).toUpperCase()

  const chains: MultihopChainVerdict[] = hops.map((expectedHops, idx) => {
    const shortcut = opts.shortcutViolationIdx === idx
    const modeB = opts.modeBViolationIdx === idx
    const ok = confirmedSet.has(idx) && !shortcut && !modeB
    return {
      chainId: `${prefix}-C${idx + 1}`,
      expectedHops,
      maxHopReached: ok ? expectedHops : Math.max(1, expectedHops - 2),
      oracleObserved: ok,
      forbiddenShortcutViolation: shortcut,
      compositeReceiptConfirmed: ok,
      twoSideConfirmed: ok,
      replayMode: modeB ? 'one_shot_transcript' : 'fresh_clean_replay',
      dropReason: ok
        ? null
        : shortcut
          ? 'persona_shortcut_rejected'
          : modeB
            ? 'replay_failed'
            : 'pivot_not_discovered',
      matchedFindingIds: ok ? [`finding-${prefix}-${idx + 1}`] : [],
      oracleEventSeqs: ok ? [1, 2, 3] : [1],
      terminalVulnClass: 'authz_escalation',
    }
  })

  const twinFpCount = opts.twinFpCount ?? 0
  const hardenedTwins: MultihopTwinVerdict[] = [1, 2, 3].map((n) => ({
    twinId: `${prefix}-D${n}`,
    baseChainId: `${prefix}-C${n}`,
    vulnClass: 'authz_escalation',
    falsePositive: n <= twinFpCount,
    matchedFindingIds: n <= twinFpCount ? [`fp-twin-${n}`] : [],
  }))

  const chainsTotal = chains.length
  const chainsConfirmed = chains.filter((c) => c.twoSideConfirmed).length
  const unmatchedFalsePositives = opts.unmatchedFalsePositives ?? 0
  const totalFps = twinFpCount + unmatchedFalsePositives
  const precision = chainsConfirmed + totalFps > 0 ? chainsConfirmed / (chainsConfirmed + totalFps) : 1
  const costUsd = opts.costUsd ?? (llm === 'deterministic-no-llm' ? 0 : opts.budgetUsd * 0.7)
  const durationMs = opts.durationMs ?? (llm === 'deterministic-no-llm' ? 30_000 : Math.round(opts.maxDurationMs * 0.5))
  const startedAt = opts.startedAt ?? 1_760_000_000_000
  const phaseBAssignments = opts.phaseBAssignments ?? (llm === 'deterministic-no-llm' ? 0 : 40)
  const deadEndReprobes = opts.deadEndReprobes ?? (llm === 'deterministic-no-llm' ? 0 : 1)
  const deadEndReprobeWasteRate = phaseBAssignments > 0 ? deadEndReprobes / phaseBAssignments : 0
  const deadEndWastePct = Math.round(deadEndReprobeWasteRate * 10_000) / 100
  const eff = {
    tpPerDollar: costUsd > 0 ? chainsConfirmed / costUsd : null,
    tpPer10m: durationMs > 0 ? chainsConfirmed / (durationMs / 600_000) : null,
  }
  const hopFunnel: HopDepthFunnel = buildHopFunnelFromVerdicts(chains)
  const depthBreakdown: DepthTierBreakdown = computeDepthBreakdownFromVerdicts(chains)

  const meta: MultihopCellMeta = {
    schemaVersion: 1,
    app: opts.app,
    sealed: opts.app === 'connecthub',
    seed: opts.seed,
    seedSet,
    mode: opts.mode,
    cell: `${opts.app}-seed${opts.seed}-${opts.mode}`,
    llm,
    origin: 'http://127.0.0.1:41000',
    publicOrigins: ['http://127.0.0.1:41000'],
    loginPath: '/api/auth/login',
    gitSha: 'deadbeef1234',
    model:
      llm === 'agentic'
        ? {
            mode: 'agentic',
            profiles: [
              {
                name: 'OpenRouter DeepSeek V4.1 Flash',
                model: 'deepseek/deepseek-v4.1-flash-1017',
                protocol: 'responses',
              },
            ],
          }
        : { mode: 'deterministic-no-llm', profiles: [] },
    verifierBackend: llm === 'agentic' ? 'docker' : 'local-jq',
    workerSessions: llm === 'agentic',
    workerSessionsDetail: llm === 'agentic' ? 'docker-worker-ok' : 'no-llm',
    dataDirIsolated: true,
    dataDirSource: '/home/omarchy/guardian-data',
    isolatedProfileNames: llm === 'agentic' ? ['OpenRouter DeepSeek V4.1 Flash'] : [],
    dataDirKept: false,
    budgetUsd: opts.budgetUsd,
    maxDurationMs: opts.maxDurationMs,
    startedAt,
    endedAt: startedAt + durationMs,
    durationMs,
    timedOut: false,
    terminalStatus: 'complete',
    terminalPhase: 'complete',
    runId: `run-${opts.app}-${opts.seed}-${opts.mode}`,
    projectId: `proj-${opts.app}`,
    chainsTotal,
    chainsOracleObserved: chainsConfirmed,
    chainsCompositeConfirmed: chainsConfirmed,
    chainsConfirmed,
    oracleOnlyCount: 0,
    receiptOnlyCount: 0,
    shortcutViolations: chains.filter((c) => c.forbiddenShortcutViolation).length,
    modeBViolations: chains.filter((c) => c.replayMode === 'one_shot_transcript').length,
    recall: chainsConfirmed / chainsTotal,
    precision,
    hardenedTwinsTotal: hardenedTwins.length,
    hardenedTwinDecoyFps: twinFpCount,
    unmatchedFalsePositives,
    costUsd,
    tpPerDollar: eff.tpPerDollar,
    tpPer10m: eff.tpPer10m,
    hopFunnel,
    depthBreakdown,
    chains,
    hardenedTwins,
    assignmentsCompleted: phaseBAssignments,
    assignmentsTotal: phaseBAssignments,
    investigationCompleted: phaseBAssignments,
    ...(opts.omitTopLevelFrontier
      ? {}
      : {
          phaseBAssignments,
          deadEndReprobeCount: deadEndReprobes,
          deadEndReprobeWasteRate,
          deadEndWastePct,
          frontier: {
            deadEndReprobeCount: deadEndReprobes,
            totalAssignmentsDispatched: phaseBAssignments,
            phaseBAssignments,
            deadEndReprobeWasteRate,
          },
        }),
    telemetry: {
      phaseTiming: {
        codeAuditMs: opts.mode === 'white-box' ? 5_000 : null,
        floorMs: 4_000,
        phaseBStartMs: 9_000,
        firstChainDispatchMs: 12_000,
        totalWallMs: durationMs,
      },
      scheduler: {
        maxEffectiveConcurrency: 3,
        workersStarted: phaseBAssignments,
        workersCompleted: phaseBAssignments,
        wallClockRotations: 0,
        maxWorkerWallMs: 90_000,
        totalPhaseBAssignments: phaseBAssignments,
        deadEndReprobes,
        deadEndWastePct,
      },
      capabilityLedger: {
        nodesTotal: 12,
        capabilityOnlyCount: 8,
        sealedHandlesCount: 4,
        causalEdgesCount: 6,
        negativeEdgesPrunedCount: 3,
        compositeReceiptsCount: chainsConfirmed,
      },
      v8SdkAdoption: {
        guardianVerifyCalls: 10,
        sealCapabilityCalls: 4,
        hmacSignCalls: 1,
        jwtSignCalls: 1,
        awaitAsyncCalls: 2,
        proveCompositeCalls: chainsConfirmed + 1,
        compositeConfirmed: chainsConfirmed,
        topRejectReasons: [],
      },
    },
    facts: 25,
    findingsPersisted: chainsConfirmed,
    findingsSubmitted: chainsConfirmed,
    compositeReceiptsExtracted: chainsConfirmed,
    endpointsDiscovered: 95,
    requestCount: 300,
    oracleEventCount: chainsConfirmed * 4,
    inert: opts.inert ?? false,
    snapshot: {
      capture: {
        requested: false,
        captured: false,
        directory: null,
        reason: null,
        checkpoints: [],
        primary: null,
      },
      resume: {
        requested: false,
        loaded: false,
        directory: null,
        capturedAt: null,
        ageMs: null,
        skippedMs: 0,
        phase0Skipped: false,
        originsRebound: 0,
        personaSessionsRebound: 0,
        schemaVersion: null,
        gitSha: null,
        seedSet: null,
        heldOutOverride: false,
        incompatibleReason: null,
      },
    },
    resumedFrom: null,
    snapshotSkippedMs: 0,
    notes: [],
    shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
  }

  return meta
}

function makeDevSuiteReportCells(opts: {
  seed: number
  mode: MultihopMode
  budgetUsd: number
  maxDurationMs: number
  confirmedByApp: readonly [readonly number[], readonly number[], readonly number[]]
  llm?: MultihopLlmMode
  costUsd?: number
  durationMs?: number
  phaseBAssignments?: number
  deadEndReprobes?: number
  omitTopLevelFrontier?: boolean
}): MultihopCellMeta[] {
  return DEV_APPS.map((app, i) =>
    makeRealisticCellMeta({
      app,
      seed: opts.seed,
      mode: opts.mode,
      llm: opts.llm,
      budgetUsd: opts.budgetUsd,
      maxDurationMs: opts.maxDurationMs,
      confirmedIndices: opts.confirmedByApp[i]!,
      costUsd: opts.costUsd,
      durationMs: opts.durationMs,
      phaseBAssignments: opts.phaseBAssignments,
      deadEndReprobes: opts.deadEndReprobes,
      omitTopLevelFrontier: opts.omitTopLevelFrontier,
    }),
  )
}

function makePassingM2Cells(): MultihopCellMeta[] {
  return [
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'white-box',
      llm: 'deterministic-no-llm',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[], [], []],
    }),
    // GB: 4/12 = 33.3%
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'grey-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[0, 1], [0], [0]],
    }),
    // WB: 6/12 = 50.0% -> lift = +16.7 pp >= +15 pp
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'white-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[0, 1], [0, 1], [0, 1]],
    }),
  ]
}

function makePassingM3Cells(opts?: { omitTopLevelFrontier?: boolean }): MultihopCellMeta[] {
  const cells: MultihopCellMeta[] = [
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'white-box',
      llm: 'deterministic-no-llm',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[], [], []],
    }),
  ]
  for (const seed of [1, 2, 3]) {
    // $2/10m: 3/12 = 25.0%
    cells.push(
      ...makeDevSuiteReportCells({
        seed,
        mode: 'white-box',
        budgetUsd: SCALING_TIERS.t2_10m.budgetUsd,
        maxDurationMs: SCALING_TIERS.t2_10m.maxDurationMs,
        confirmedByApp: [[0], [1], [1]],
        phaseBAssignments: 25,
        deadEndReprobes: 1,
        omitTopLevelFrontier: opts?.omitTopLevelFrontier,
      }),
    )
    // $5/30m: 6/12 = 50.0%
    cells.push(
      ...makeDevSuiteReportCells({
        seed,
        mode: 'white-box',
        budgetUsd: SCALING_TIERS.t5_30m.budgetUsd,
        maxDurationMs: SCALING_TIERS.t5_30m.maxDurationMs,
        confirmedByApp: [[0, 1], [1, 2], [1, 2]],
        phaseBAssignments: 40,
        deadEndReprobes: 1,
        omitTopLevelFrontier: opts?.omitTopLevelFrontier,
      }),
    )
    // $15/60m: 9/12 = 75.0%
    // 3-4h chains: paygrid idx 0,1,3 (2 confirmed), shipforge idx 1,2,3 (2 confirmed), nexusiam idx 1,2,3 (3 confirmed) => 7/9 = 77.8% >= 60%
    // 5-6h chains: paygrid idx 2 (1 confirmed), shipforge idx 0 (1 confirmed), nexusiam idx 0 (0 confirmed) => 2/3 = 66.7% >= 35%
    cells.push(
      ...makeDevSuiteReportCells({
        seed,
        mode: 'white-box',
        budgetUsd: SCALING_TIERS.t15_60m.budgetUsd,
        maxDurationMs: SCALING_TIERS.t15_60m.maxDurationMs,
        confirmedByApp: [[0, 1, 2], [0, 1, 2], [1, 2, 3]],
        phaseBAssignments: 50,
        deadEndReprobes: 2,
        omitTopLevelFrontier: opts?.omitTopLevelFrontier,
      }),
    )
  }
  return cells
}

function makePassingM4Cells(): MultihopCellMeta[] {
  const cells: MultihopCellMeta[] = [
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'white-box',
      llm: 'deterministic-no-llm',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[], [], []],
    }),
  ]
  for (const seed of [1, 2, 3]) {
    // Dev $5/30m WB for efficiency floor: 7 TP / ($3.5 * 3 = $10.50) = 0.67 TP/$; 7 TP / (3M ms = 5 x 10m) = 1.40 TP/10m
    cells.push(
      ...makeDevSuiteReportCells({
        seed,
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        confirmedByApp: [[0, 1, 2], [0, 1], [0, 1]],
        costUsd: 3.5,
        durationMs: 1_000_000,
      }),
      // Dev $15/60m WB: 8/12 = 66.7% >= 65%
      ...makeDevSuiteReportCells({
        seed,
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        confirmedByApp: [[0, 1, 2], [0, 1, 2], [1, 2]],
        costUsd: 10.5,
        durationMs: 2_400_000,
      }),
      // Dev $15/60m GB: 6/12 = 50.0% >= 45%
      ...makeDevSuiteReportCells({
        seed,
        mode: 'grey-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        confirmedByApp: [[0, 1], [1, 2], [1, 2]],
        costUsd: 9.5,
        durationMs: 2_200_000,
      }),
    )
  }
  for (const seed of [1_000_001, 1_000_002, 1_000_003]) {
    // Salted Held-Out $15/60m WB: 7/12 = 58.3% >= 55% (gap = 8.3 pp <= 10 pp)
    cells.push(
      ...makeDevSuiteReportCells({
        seed,
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        confirmedByApp: [[0, 1, 2], [0, 1], [1, 2]],
        costUsd: 10.5,
        durationMs: 2_500_000,
      }),
      // Salted Held-Out $15/60m GB: 5/12 = 41.7% >= 40% (gap = 8.3 pp <= 10 pp)
      ...makeDevSuiteReportCells({
        seed,
        mode: 'grey-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        confirmedByApp: [[0, 1], [1, 2], [1]],
        costUsd: 9.5,
        durationMs: 2_300_000,
      }),
    )
  }
  // Blind sealed connecthub first run: 2/4 = 50.0% >= 50%, 0/3 twin FPs, gap = 16.7 pp <= 20 pp
  cells.push(
    makeRealisticCellMeta({
      app: 'connecthub',
      seed: 9001,
      mode: 'white-box',
      budgetUsd: 15,
      maxDurationMs: 3_600_000,
      confirmedIndices: [0, 1],
      costUsd: 11.0,
      durationMs: 2_400_000,
      startedAt: 1_760_000_000_000,
    }),
  )
  return cells
}

function makePassingOssReports(): OssCorpusInput[] {
  return [
    {
      schemaVersion: '1.0',
      runId: 'oss-dev-01',
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
      falsePositives: 0,
      recall: 0.75,
      precision: 1,
      worstRunPrecision: 1,
      patchRetestAttempted: 3,
      patchRetestClosed: 3,
      patchRetestClosureRate: 1,
      tpPerUsd: 0.8,
      tpPer10m: 1.5,
      anchorResults: [
        { anchorId: 'oss-dev-1', split: 'dev', twoSideConfirmed: true, patchRetestStatus: 'closed' },
        { anchorId: 'oss-dev-2', split: 'dev', twoSideConfirmed: true, patchRetestStatus: 'closed' },
        { anchorId: 'oss-dev-3', split: 'dev', twoSideConfirmed: true, patchRetestStatus: 'closed' },
        { anchorId: 'oss-dev-4', split: 'dev', twoSideConfirmed: false, patchRetestStatus: 'not_applicable' },
      ],
    },
    {
      schemaVersion: '1.0',
      runId: 'oss-sealed-01',
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
      falsePositives: 0,
      recall: 0.75,
      precision: 1,
      worstRunPrecision: 1,
      patchRetestAttempted: 3,
      patchRetestClosed: 2,
      patchRetestClosureRate: 2 / 3,
      tpPerUsd: 0.7,
      tpPer10m: 1.3,
      anchorResults: [
        { anchorId: 'oss-sealed-1', split: 'sealed', twoSideConfirmed: true, patchRetestStatus: 'closed' },
        { anchorId: 'oss-sealed-2', split: 'sealed', twoSideConfirmed: true, patchRetestStatus: 'closed' },
        { anchorId: 'oss-sealed-3', split: 'sealed', twoSideConfirmed: true, patchRetestStatus: 'open_still_reproduces' },
        { anchorId: 'oss-sealed-4', split: 'sealed', twoSideConfirmed: false, patchRetestStatus: 'not_applicable' },
      ],
      cleanControlResults: [
        { controlId: 'oss-clean-1', passed: true, fpCount: 0, unexpectedOracleTriggers: 0 },
        { controlId: 'oss-clean-2', passed: true, fpCount: 0, unexpectedOracleTriggers: 0 },
      ],
    },
  ]
}

function makePassingV7Floor(): V7RegressionFloorInput {
  return {
    xben: { confirmed: 25, targets: 25, falsePositives: 0 },
    heldOutSaas: { confirmed: 20, targets: 20, patchesClosed: 20, patchesTotal: 20, falsePositives: 0 },
    reasonBench: { noLlmRecall: 0.07, agenticRecall: 0.60, worstPrecision: 1 },
    realisticBench: { maxFloorSpread: 0 },
  }
}

function makeMultihopReportJson(
  cells: MultihopCellMeta[],
  floorCells: MultihopCellMeta[],
  gitSha = 'deadbeef1234',
): string {
  const agg = (list: readonly MultihopCellMeta[]) => {
    const chainsTotal = list.reduce((n, c) => n + c.chainsTotal, 0)
    const chainsConfirmed = list.reduce((n, c) => n + c.chainsConfirmed, 0)
    const hardenedTwinsTotal = list.reduce((n, c) => n + c.hardenedTwinsTotal, 0)
    const hardenedTwinDecoyFps = list.reduce((n, c) => n + c.hardenedTwinDecoyFps, 0)
    const unmatchedFalsePositives = list.reduce((n, c) => n + c.unmatchedFalsePositives, 0)
    const costUsd = list.reduce((n, c) => n + c.costUsd, 0)
    const durationMs = list.reduce((n, c) => n + c.durationMs, 0)
    const worstRunPrecision = list.length ? Math.min(...list.map((c) => c.precision)) : 1
    const allChains = list.flatMap((c) => c.chains)
    const totalFps = hardenedTwinDecoyFps + unmatchedFalsePositives
    return {
      cells: list.length,
      chainsTotal,
      chainsOracleObserved: list.reduce((n, c) => n + c.chainsOracleObserved, 0),
      chainsCompositeConfirmed: list.reduce((n, c) => n + c.chainsCompositeConfirmed, 0),
      chainsConfirmed,
      oracleOnlyCount: 0,
      receiptOnlyCount: 0,
      shortcutViolations: list.reduce((n, c) => n + c.shortcutViolations, 0),
      modeBViolations: list.reduce((n, c) => n + c.modeBViolations, 0),
      recall: chainsTotal > 0 ? chainsConfirmed / chainsTotal : 0,
      precision: chainsConfirmed + totalFps > 0 ? chainsConfirmed / (chainsConfirmed + totalFps) : 1,
      worstRunPrecision,
      hardenedTwinsTotal,
      hardenedTwinDecoyFps,
      unmatchedFalsePositives,
      hardenedTwinGatePassed: hardenedTwinDecoyFps === 0 && unmatchedFalsePositives === 0 && worstRunPrecision >= 1,
      costUsd,
      durationMs,
      tpPerDollar: costUsd > 0 ? chainsConfirmed / costUsd : null,
      tpPer10m: durationMs > 0 ? chainsConfirmed / (durationMs / 600_000) : null,
      hopFunnel: buildHopFunnelFromVerdicts(allChains),
      depthBreakdown: computeDepthBreakdownFromVerdicts(allChains),
      assignmentsCompleted: list.reduce((n, c) => n + c.assignmentsCompleted, 0),
      assignmentsTotal: list.reduce((n, c) => n + c.assignmentsTotal, 0),
    }
  }
  const agenticCells = cells.filter((c) => c.llm === 'agentic')
  const floorRunCells = cells.filter((c) => c.llm === 'deterministic-no-llm')
  const agentic = agg(agenticCells)
  const floorAgg = floorCells.length ? agg(floorCells) : null
  const report: MultihopReport = {
    schemaVersion: 1,
    generatedAt: '2026-11-25T00:00:00.000Z',
    gitSha,
    cells,
    agentic,
    floorRun: floorRunCells.length ? agg(floorRunCells) : null,
    floor: floorAgg
      ? {
          recall: floorAgg.recall,
          confirmed: floorAgg.chainsConfirmed,
          targets: floorAgg.chainsTotal,
          cells: floorAgg.cells,
        }
      : null,
    lift: {
      agenticRecall: agentic.recall,
      floorRecall: floorAgg ? floorAgg.recall : null,
      deltaReasoning: floorAgg && agenticCells.length ? agentic.recall - floorAgg.recall : null,
      costUsd: agentic.costUsd,
      tpPerDollar: agentic.tpPerDollar,
      tpPer10m: agentic.tpPer10m,
    },
    curve: [],
    antiHeuristicGate: floorRunCells.length
      ? {
          ceiling: 0.05,
          recall: agg(floorRunCells).recall,
          confirmed: agg(floorRunCells).chainsConfirmed,
          targets: agg(floorRunCells).chainsTotal,
          passed: agg(floorRunCells).recall <= 0.05,
          chains: [],
        }
      : null,
    hardenedTwinGatePassed: agg(cells).hardenedTwinGatePassed,
    telemetry: null,
    notes: [],
  }
  return `${JSON.stringify(report, null, 2)}\n`
}

// ---------------------------------------------------------------------------
// M2 Schema Readiness & Gate Tests (benchmark-multihop.ts MultihopReport round-trip)
// ---------------------------------------------------------------------------

test('M2 PASS: loads real benchmark-multihop.ts MultihopReport files across split dirs and passes M2 gate', () => {
  const dir = join(tempRoot, 'm2-pass')
  const gbDir = join(dir, 'dev-gb')
  const wbDir = join(dir, 'dev-wb')
  const floorDir = join(dir, 'dev-floor')
  mkdirSync(gbDir, { recursive: true })
  mkdirSync(wbDir, { recursive: true })
  mkdirSync(floorDir, { recursive: true })

  const allCells = makePassingM2Cells()
  const floorCells = allCells.filter((c) => c.llm === 'deterministic-no-llm')
  const gbCells = allCells.filter((c) => c.llm === 'agentic' && c.mode === 'grey-box')
  const wbCells = allCells.filter((c) => c.llm === 'agentic' && c.mode === 'white-box')

  writeFileSync(join(floorDir, 'multihop-report.json'), makeMultihopReportJson(floorCells, floorCells))
  writeFileSync(join(gbDir, 'multihop-report.json'), makeMultihopReportJson(gbCells, floorCells))
  writeFileSync(join(wbDir, 'multihop-report.json'), makeMultihopReportJson(wbCells, floorCells))

  const outMd = join(dir, 'M2-SCORECARD.md')
  const outJson = join(dir, 'm2-scorecard.json')
  const exitCode = main(['--gate=M2', '--inputs', dir, `--out-md=${outMd}`, `--out-json=${outJson}`])
  assert.equal(exitCode, 0)
  assert.ok(existsSync(outMd))
  assert.ok(existsSync(outJson))

  const parsed = JSON.parse(readFileSync(outJson, 'utf8')) as {
    verdict: string
    gate: string
    precision: { worstRunPrecision: number; totalShortcutViolations: number; totalModeBViolations: number; inertAgenticCells: number }
  }
  assert.equal(parsed.verdict, 'PASS')
  assert.equal(parsed.gate, 'm2')
  assert.equal(parsed.precision.worstRunPrecision, 1)
  assert.equal(parsed.precision.totalShortcutViolations, 0)
  assert.equal(parsed.precision.totalModeBViolations, 0)
  assert.equal(parsed.precision.inertAgenticCells, 0)
})

test('M2 FAIL: shortcut violation or Mode-B replay violation fails two_side_replay_integrity', () => {
  // Case A: shortcut violation present in chains[] (even if top-level shortcutViolations is zeroed)
  const shortcutCells: MultihopCellInput[] = makePassingM2Cells().map((c) => {
    if (c.llm === 'agentic' && c.mode === 'white-box' && c.app === 'paygrid') {
      const mutated = makeRealisticCellMeta({
        app: 'paygrid',
        seed: 1,
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        confirmedIndices: [0, 1],
        shortcutViolationIdx: 2,
      })
      return { ...mutated, shortcutViolations: 0 }
    }
    return c
  })
  const shortcutReport = evaluateV8Certification({ gate: 'm2', cells: shortcutCells })
  assert.equal(shortcutReport.verdict, 'FAIL')
  assert.equal(shortcutReport.precision.totalShortcutViolations, 1)
  assert.equal(shortcutReport.precision.passed, false)
  assert.ok(shortcutReport.failedChecks.some((c) => c.id === 'two_side_replay_integrity'))

  // Case B: Mode-B one_shot_transcript violation
  const modeBCells = makePassingM2Cells().map((c) =>
    c.llm === 'agentic' && c.mode === 'white-box' && c.app === 'shipforge'
      ? makeRealisticCellMeta({
          app: 'shipforge',
          seed: 1,
          mode: 'white-box',
          budgetUsd: 5,
          maxDurationMs: 1_800_000,
          confirmedIndices: [0, 1],
          modeBViolationIdx: 3,
        })
      : c,
  )
  const modeBReport = evaluateV8Certification({ gate: 'm2', cells: modeBCells })
  assert.equal(modeBReport.verdict, 'FAIL')
  assert.equal(modeBReport.precision.totalModeBViolations, 1)
  assert.ok(modeBReport.failedChecks.some((c) => c.id === 'two_side_replay_integrity'))
})

test('M2 FAIL: decoy FP in hardenedTwins[] or unmatched FP fails worst-run precision even if reported precision=1.0', () => {
  // Decoy FP hidden inside hardenedTwins[] with misreported precision=1.0 and hardenedTwinDecoyFps=0
  const decoyCells: MultihopCellInput[] = makePassingM2Cells().map((c) => {
    if (c.llm === 'agentic' && c.mode === 'white-box' && c.app === 'nexusiam') {
      const bad = makeRealisticCellMeta({
        app: 'nexusiam',
        seed: 1,
        mode: 'white-box',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        confirmedIndices: [0, 1],
        twinFpCount: 1,
      })
      return { ...bad, hardenedTwinDecoyFps: 0, precision: 1 }
    }
    return c
  })
  const decoyReport = evaluateV8Certification({ gate: 'm2', cells: decoyCells })
  assert.equal(decoyReport.verdict, 'FAIL')
  assert.equal(decoyReport.precision.totalHardenedTwinDecoyFps, 1)
  assert.ok(decoyReport.precision.worstRunPrecision < 1)
  assert.ok(decoyReport.failedChecks.some((c) => c.id === 'precision_worst_run'))
  assert.ok(decoyReport.failedChecks.some((c) => c.id === 'm2_dev_twin_fps'))

  // Unmatched FP
  const unmatchedCells = makePassingM2Cells().map((c) =>
    c.llm === 'agentic' && c.mode === 'grey-box' && c.app === 'paygrid'
      ? makeRealisticCellMeta({
          app: 'paygrid',
          seed: 1,
          mode: 'grey-box',
          budgetUsd: 5,
          maxDurationMs: 1_800_000,
          confirmedIndices: [0, 1],
          unmatchedFalsePositives: 1,
        })
      : c,
  )
  const unmatchedReport = evaluateV8Certification({ gate: 'm2', cells: unmatchedCells })
  assert.equal(unmatchedReport.verdict, 'FAIL')
  assert.equal(unmatchedReport.precision.totalUnmatchedFalsePositives, 1)
  assert.ok(unmatchedReport.precision.worstRunPrecision < 1)
  assert.ok(unmatchedReport.failedChecks.some((c) => c.id === 'precision_worst_run'))
})

test('M2 FAIL: single-archetype Dev subset cannot pass M2 (enforces paygrid + shipforge + nexusiam)', () => {
  const singleAppCells = makePassingM2Cells().filter((c) => c.app === 'paygrid')
  // Boost paygrid WB to 3/4 (75%) and GB to 2/4 (50%) -> lift +25 pp, but missing shipforge & nexusiam
  const boosted = singleAppCells.map((c) =>
    c.llm === 'agentic' && c.mode === 'white-box'
      ? makeRealisticCellMeta({
          app: 'paygrid',
          seed: 1,
          mode: 'white-box',
          budgetUsd: 5,
          maxDurationMs: 1_800_000,
          confirmedIndices: [0, 1, 2],
        })
      : c,
  )
  const report = evaluateV8Certification({ gate: 'm2', cells: boosted })
  assert.equal(report.verdict, 'FAIL')
  assert.ok(report.failedChecks.some((c) => c.id === 'm2_dev_archetype_coverage'))
})

test('M2 FAIL: insufficient WB lift (< +15 pp) and inert agentic cell both fail M2', () => {
  // GB 5/12 (41.7%), WB 6/12 (50.0%) -> +8.3 pp < +15 pp
  const lowLiftCells = [
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'white-box',
      llm: 'deterministic-no-llm',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[], [], []],
    }),
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'grey-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[0, 1], [0, 1], [0]],
    }),
    ...makeDevSuiteReportCells({
      seed: 1,
      mode: 'white-box',
      budgetUsd: 5,
      maxDurationMs: 1_800_000,
      confirmedByApp: [[0, 1], [0, 1], [0, 1]],
    }),
  ]
  const lowLiftReport = evaluateV8Certification({ gate: 'm2', cells: lowLiftCells })
  assert.equal(lowLiftReport.verdict, 'FAIL')
  assert.ok(lowLiftReport.failedChecks.some((c) => c.id === 'm2_whitebox_lift'))

  // Inert agentic cell
  const inertCells = makePassingM2Cells().map((c) =>
    c.llm === 'agentic' && c.mode === 'white-box' && c.app === 'paygrid'
      ? { ...c, inert: true }
      : c,
  )
  const inertReport = evaluateV8Certification({ gate: 'm2', cells: inertCells })
  assert.equal(inertReport.verdict, 'FAIL')
  assert.equal(inertReport.precision.inertAgenticCells, 1)
  assert.ok(inertReport.failedChecks.some((c) => c.id === 'two_side_replay_integrity'))
})

// ---------------------------------------------------------------------------
// M3 Schema Readiness & Scaling Gate Tests
// ---------------------------------------------------------------------------

test('M3 PASS: telemetry.scheduler-only waste fields work and full monotonic matrix passes', () => {
  // Omit top-level frontier / deadEndReprobeCount / phaseBAssignments so certify-v8 must read
  // `telemetry.scheduler` emitted by `benchmark-multihop.ts`.
  const cells = makePassingM3Cells({ omitTopLevelFrontier: true })
  const report = evaluateV8Certification({ gate: 'm3', cells })
  assert.equal(report.verdict, 'PASS', JSON.stringify(report.failedChecks, null, 2))
  assert.equal(report.scalingMonotonic.strictlyMonotonic, true)
  assert.equal(report.scalingMonotonic.minRepeatsObserved, 3)
  assert.ok((report.scalingMonotonic.lift15Over2 ?? 0) >= 0.20)
  assert.equal(report.waste.unmeasuredCells, 0)
  assert.ok((report.waste.wasteRate ?? 1) <= 0.05)
})

test('M3 FAIL: non-monotonic scaling, incomplete Dev repeat, and high telemetry.scheduler waste fail', () => {
  // 1. Non-monotonic ($5/30m > $15/60m)
  const nonMono = makePassingM3Cells().map((c) => {
    if (c.llm === 'agentic' && c.budgetUsd === 15) {
      return makeRealisticCellMeta({
        app: c.app,
        seed: c.seed,
        mode: 'white-box',
        budgetUsd: 15,
        maxDurationMs: 3_600_000,
        confirmedIndices: c.app === 'paygrid' ? [0, 1] : [0], // 4/12 = 33.3% < 50.0% at $5/30m
      })
    }
    return c
  })
  const nonMonoReport = evaluateV8Certification({ gate: 'm3', cells: nonMono })
  assert.equal(nonMonoReport.verdict, 'FAIL')
  assert.equal(nonMonoReport.scalingMonotonic.strictlyMonotonic, false)
  assert.ok(nonMonoReport.failedChecks.some((c) => c.id === 'm3_monotonic_scaling'))

  // 2. Incomplete Dev repeat (drop nexusiam from seed 3 at $15/60m)
  const missingApp = makePassingM3Cells().filter(
    (c) => !(c.llm === 'agentic' && c.budgetUsd === 15 && c.seed === 3 && c.app === 'nexusiam'),
  )
  const missingAppReport = evaluateV8Certification({ gate: 'm3', cells: missingApp })
  assert.equal(missingAppReport.verdict, 'FAIL')
  assert.ok(missingAppReport.failedChecks.some((c) => c.id === 'm3_repeats_floor'))

  // 3. Dead-end waste > 5% read via telemetry.scheduler ONLY (and verify 0-assignment cell cannot dilute it)
  const highWaste = makePassingM3Cells({ omitTopLevelFrontier: true }).map((c) => {
    if (c.llm !== 'agentic') return c
    const isIdle = c.app === 'nexusiam' && c.budgetUsd === 2
    const phaseB = isIdle ? 0 : 20
    const reprobes = isIdle ? 0 : 2 // 10% waste on active cells
    return makeRealisticCellMeta({
      app: c.app,
      seed: c.seed,
      mode: 'white-box',
      budgetUsd: c.budgetUsd,
      maxDurationMs: c.maxDurationMs,
      confirmedIndices: c.chains.flatMap((ch, idx) => (ch.twoSideConfirmed ? [idx] : [])),
      phaseBAssignments: phaseB,
      deadEndReprobes: reprobes,
      omitTopLevelFrontier: true,
    })
  })
  const highWasteReport = evaluateV8Certification({ gate: 'm3', cells: highWaste })
  assert.equal(highWasteReport.verdict, 'FAIL')
  assert.ok(highWasteReport.failedChecks.some((c) => c.id === 'm3_dead_end_waste'))
  assert.ok(Math.abs((highWasteReport.waste.wasteRate ?? 0) - 0.1) < 1e-6)
})

// ---------------------------------------------------------------------------
// M4 Schema Readiness, OSS, v7-Floor Fail-Closed & Loader Resilience Tests
// ---------------------------------------------------------------------------

test('M4 PASS: end-to-end CLI with MultihopReport + OSS directory + v7 floor generates CALIBRATION-v8.md', () => {
  const dir = join(tempRoot, 'm4-pass')
  const runsDir = join(dir, 'runs')
  const ossDir = join(dir, 'oss')
  mkdirSync(join(runsDir, 'batch-all'), { recursive: true })
  mkdirSync(join(runsDir, 'data-with-broken-link'), { recursive: true })
  mkdirSync(ossDir, { recursive: true })

  // Create a dangling credential symlink inside a sibling dir to prove directory traversal never crashes
  symlinkSync('/nonexistent/guardian/cred-file', join(runsDir, 'data-with-broken-link', 'model-key.json'))

  const cells = makePassingM4Cells()
  const floorCells = cells.filter((c) => c.llm === 'deterministic-no-llm')
  const reportJson = makeMultihopReportJson(cells, floorCells)
  writeFileSync(join(runsDir, 'batch-all', 'multihop-report.json'), reportJson, 'utf8')

  const ossReports = makePassingOssReports()
  writeFileSync(join(ossDir, 'oss-dev.json'), JSON.stringify(ossReports[0], null, 2), 'utf8')
  writeFileSync(join(ossDir, 'oss-sealed.json'), JSON.stringify(ossReports[1], null, 2), 'utf8')

  const v7Path = join(dir, 'v7-floor.json')
  writeFileSync(v7Path, JSON.stringify(makePassingV7Floor(), null, 2), 'utf8')

  const outMd = join(dir, 'CALIBRATION-v8.md')
  const outJson = join(dir, 'calibration-v8.json')

  assert.equal(loadMultihopInputs([runsDir]).length, cells.length)
  assert.equal(loadOssInputs([ossDir]).length, 2)

  const exitCode = main([
    '--gate',
    'm4',
    '--inputs',
    runsDir,
    '--oss',
    ossDir,
    '--v7-floor',
    v7Path,
    '--out-md',
    outMd,
    '--out-json',
    outJson,
  ])
  assert.equal(exitCode, 0)

  const md = readFileSync(outMd, 'utf8')
  const json = JSON.parse(readFileSync(outJson, 'utf8')) as { verdict: string; failedChecks: unknown[] }
  assert.equal(json.verdict, 'PASS')
  assert.equal(json.failedChecks.length, 0)
  assert.match(md, /# Guardian v8 Calibration & Certification Scorecard \(M4\)/)
  assert.match(md, /`two_side_replay_integrity`/)
  assert.match(md, /`m4_v7_realistic_spread`/)
})

test('M4 FAIL: missing realisticBench.maxFloorSpread fails closed and unrun OSS patch-retests fail closure gate', () => {
  const floorWithoutRealistic: V7RegressionFloorInput = {
    xben: { confirmed: 25, targets: 25, falsePositives: 0 },
    heldOutSaas: { confirmed: 20, targets: 20, patchesClosed: 20, patchesTotal: 20, falsePositives: 0 },
    reasonBench: { noLlmRecall: 0.07, agenticRecall: 0.60, worstPrecision: 1 },
  }
  const reportMissingRealistic = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss: makePassingOssReports(),
    v7Floor: floorWithoutRealistic,
  })
  assert.equal(reportMissingRealistic.verdict, 'FAIL')
  assert.ok(reportMissingRealistic.failedChecks.some((c) => c.id === 'm4_v7_realistic_spread'))

  // OSS unrun patch retest: 6 total TPs, only 1 attempted & 1 closed -> effective 1/6 = 16.7% < 80%
  const ossUnrunPatch = makePassingOssReports().map((r) => ({
    ...r,
    patchRetestAttempted: r.split === 'dev' ? 1 : 0,
    patchRetestClosed: r.split === 'dev' ? 1 : 0,
    patchRetestClosureRate: 1,
  }))
  const reportUnrunPatch = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss: ossUnrunPatch,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(reportUnrunPatch.verdict, 'FAIL')
  assert.ok(reportUnrunPatch.failedChecks.some((c) => c.id === 'm4_oss_patch_retest'))

  // OSS worstRunPrecision < 1 fails precision_worst_run even if precision=1 and fp counts=0
  const ossBadWorstPrec = makePassingOssReports()
  ossBadWorstPrec[1] = { ...ossBadWorstPrec[1]!, worstRunPrecision: 0.75 }
  const reportBadOssPrec = evaluateV8Certification({
    gate: 'm4',
    cells: makePassingM4Cells(),
    oss: ossBadWorstPrec,
    v7Floor: makePassingV7Floor(),
  })
  assert.equal(reportBadOssPrec.verdict, 'FAIL')
  assert.ok(reportBadOssPrec.failedChecks.some((c) => c.id === 'precision_worst_run'))
})

test('CLI arg parser & error handling: supports --flag=value, stops before -h, rejects bad JSON and dir v7-floor', () => {
  const parsed = parseCertifyV8Args([
    '--gate=M3',
    '--inputs=a.json,b.json',
    '-h',
  ])
  assert.equal(parsed.gate, 'm3')
  assert.deepEqual(parsed.inputs, ['a.json', 'b.json'])
  assert.equal(parsed.help, true)

  const badDir = join(tempRoot, 'bad-json')
  mkdirSync(badDir, { recursive: true })
  const badJsonPath = join(badDir, 'broken.json')
  writeFileSync(badJsonPath, '{ not valid json', 'utf8')
  assert.throws(() => loadMultihopInputs([badJsonPath]), /Failed to parse JSON file/)

  // Passing a directory to --v7-floor returns exit code 2 cleanly (no unhandled EISDIR)
  const validCellsPath = join(badDir, 'valid-m2.json')
  writeFileSync(validCellsPath, JSON.stringify({ cells: makePassingM2Cells() }), 'utf8')
  const exitDirV7 = main(['--gate', 'm4', '--inputs', validCellsPath, '--v7-floor', badDir])
  assert.equal(exitDirV7, 2)
})
