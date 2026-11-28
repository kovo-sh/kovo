/**
 * Track E3 behavioral tests:
 *  - `computeCostPerConfirmed` (zero-confirmed -> null, finite rounding)
 *  - `compactRunTokenTelemetry` (pre-E1 without providerBreakdown & post-E1 with providerBreakdown, top-5 drivers)
 *  - `mergeProviderBreakdowns` & `aggregateMultihopTokenTelemetry` (multi-cell token-weighted cacheHitRate,
 *    Morph Ultra / OpenCode Go / OpenRouter merging, retry/stall waste, top tool-result drivers)
 *  - `aggregateMultihopCells` / `buildMultihopReport` / `renderMultihopReport` (JSON fields + 1-line MD summary)
 *  - `Execution.getRunTokenTelemetry` capture before run disposal vs. null after disposal
 *  - `--smoke` convenience preset + explicit override precedence + 4-tier cadence in `--help`
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'

import {
  DEFAULT_BUDGET_USD,
  DEFAULT_MAX_DURATION_MS,
  SMOKE_BUDGET_USD,
  SMOKE_MAX_DURATION_MS,
  aggregateMultihopCells,
  aggregateMultihopTokenTelemetry,
  buildMultihopReport,
  compactRunTokenTelemetry,
  computeCostPerConfirmed,
  emptyDropReasons,
  formatCostCacheProviderSummaryLine,
  mergeProviderBreakdowns,
  parseMultihopArgs,
  renderMultihopReport,
  usage,
  type MultihopCellMeta,
  type MultihopProviderTelemetry,
  type MultihopTokenTelemetry,
  type RawRunTokenTelemetry,
} from '../scripts/benchmark-multihop.ts'
import { emptySnapshotMeta } from '../scripts/benchmark-realistic.ts'
import { Execution } from '../src/server/execution.ts'
import { Store } from '../src/server/store.ts'
import {
  disposeRunTokenTelemetry,
  recordProviderUsageTelemetry,
  recordToolResultSizeTelemetry,
} from '../src/server/token-telemetry.ts'

function makeCell(overrides: Partial<MultihopCellMeta> = {}): MultihopCellMeta {
  const chainsTotal = overrides.chainsTotal ?? 4
  const chainsConfirmed = overrides.chainsConfirmed ?? 2
  const costUsd = overrides.costUsd ?? 1.5
  return {
    schemaVersion: 1,
    status: 'VALID',
    app: 'paygrid',
    sealed: false,
    seed: 1,
    seedSet: 'dev',
    mode: 'grey-box',
    cell: 'paygrid-seed1-grey-box',
    llm: 'agentic',
    origin: 'http://127.0.0.1:4100',
    publicOrigins: ['http://127.0.0.1:4100'],
    loginPath: '/login',
    gitSha: '98e27554',
    model: {
      mode: 'agentic',
      profiles: [{ name: 'OpenRouter DeepSeek V4.1 Flash', model: 'deepseek/deepseek-v4.1-flash-1017', protocol: 'responses' }],
    },
    verifierBackend: 'docker',
    workerSessions: true,
    workerSessionsDetail: 'docker',
    dataDirIsolated: true,
    dataDirSource: null,
    isolatedProfileNames: [],
    dataDirKept: false,
    budgetUsd: 2,
    maxDurationMs: 600_000,
    startedAt: 1_000,
    endedAt: 601_000,
    durationMs: 600_000,
    timedOut: false,
    terminalStatus: 'completed',
    terminalPhase: 'done',
    runId: 'run-e3-test',
    projectId: 'proj-e3-test',
    chainsTotal,
    chainsOracleObserved: chainsConfirmed,
    chainsCompositeConfirmed: chainsConfirmed,
    chainsConfirmed,
    oracleOnlyCount: 0,
    receiptOnlyCount: 0,
    shortcutViolations: 0,
    modeBViolations: 0,
    recall: chainsTotal > 0 ? chainsConfirmed / chainsTotal : 0,
    precision: chainsConfirmed > 0 ? 1 : null,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: 0,
    unmatchedFalsePositives: 0,
    costUsd,
    costPerConfirmed: computeCostPerConfirmed(costUsd, chainsConfirmed),
    tpPerDollar: costUsd > 0 ? chainsConfirmed / costUsd : null,
    tpPer10m: chainsConfirmed,
    hopFunnel: {
      totalChains: chainsTotal,
      H1: chainsTotal,
      H2: chainsConfirmed,
      H3: chainsConfirmed,
      H4Plus: 0,
      FinalOracle: chainsConfirmed,
      CompositeReceiptConfirmed: chainsConfirmed,
      dropReasons: emptyDropReasons(),
    },
    depthBreakdown: {
      hops3to4: { targets: chainsTotal, confirmed: chainsConfirmed, recall: chainsTotal > 0 ? chainsConfirmed / chainsTotal : 0 },
      hops5to6: { targets: 0, confirmed: 0, recall: 0 },
    },
    chains: [],
    hardenedTwins: [],
    assignmentsCompleted: 6,
    assignmentsTotal: 6,
    investigationCompleted: 6,
    facts: 10,
    findingsPersisted: chainsConfirmed,
    findingsSubmitted: chainsConfirmed,
    compositeReceiptsExtracted: chainsConfirmed,
    endpointsDiscovered: 12,
    requestCount: 40,
    oracleEventCount: 8,
    inert: false,
    snapshot: emptySnapshotMeta(),
    resumedFrom: null,
    snapshotSkippedMs: 0,
    notes: [],
    shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
    ...overrides,
  }
}

function makeRawTelemetry(overrides: Partial<RawRunTokenTelemetry> = {}): RawRunTokenTelemetry {
  return {
    runId: 'run-raw-1',
    inputTokens: 10_000,
    cachedInputTokens: 6_000,
    uncachedInputTokens: 4_000,
    outputTokens: 2_000,
    reasoningTokens: 500,
    cacheHitRate: 0.6,
    totalCostUsd: 0.45,
    retryStallWasteUsd: 0.05,
    providerCalls: 12,
    providerRetries: 2,
    providerStalls: 1,
    truncatedToolCalls: 0,
    wallClockRotations: 0,
    totalToolResultBytes: 120_000,
    toolResultSpills: 2,
    toolResultBytesByTool: {},
    topToolResultDrivers: [
      { toolName: 'request_http', calls: 10, bytes: 50_000, spilledCount: 1 },
      { toolName: 'derive_evidence', calls: 4, bytes: 30_000, spilledCount: 1 },
      { toolName: 'query_facts', calls: 8, bytes: 20_000, spilledCount: 0 },
      { toolName: 'run_script', calls: 6, bytes: 10_000, spilledCount: 0 },
      { toolName: 'read_repo', calls: 3, bytes: 6_000, spilledCount: 0 },
      { toolName: 'list_endpoints', calls: 2, bytes: 4_000, spilledCount: 0 },
    ],
    ...overrides,
  }
}

describe('Track E3: Benchmark cost, cache & per-provider telemetry export', () => {
  it('computes costPerConfirmed accurately and returns null for zero confirmed chains', () => {
    assert.equal(computeCostPerConfirmed(2.5, 0), null)
    assert.equal(computeCostPerConfirmed(0, 0), null)
    assert.equal(computeCostPerConfirmed(3.0, -1), null)
    assert.equal(computeCostPerConfirmed(2.5, 2), 1.25)
    assert.equal(computeCostPerConfirmed(1, 3), 0.3333)
    assert.equal(computeCostPerConfirmed(0, 2), 0)
  })

  it('compacts RunTokenTelemetrySummary both before E1 (no providerBreakdown) and after E1, capping topToolResultDrivers to 5', () => {
    assert.equal(compactRunTokenTelemetry(null), null)
    assert.equal(compactRunTokenTelemetry(undefined), null)

    // Pre-E1 shape: no providerBreakdown field
    const preE1 = compactRunTokenTelemetry(makeRawTelemetry())
    assert.ok(preE1)
    assert.deepEqual(preE1.providerBreakdown, {})
    assert.equal(preE1.cacheHitRate, 0.6)
    assert.equal(preE1.retryStallWasteUsd, 0.05)
    assert.equal(preE1.topToolResultDrivers.length, 5)
    assert.deepEqual(
      preE1.topToolResultDrivers.map(d => d.toolName),
      ['request_http', 'derive_evidence', 'query_facts', 'run_script', 'read_repo'],
    )

    // Post-E1 shape: includes providerBreakdown
    const postE1 = compactRunTokenTelemetry(makeRawTelemetry({
      providerBreakdown: {
        'Morph Ultra': {
          calls: 8,
          retries: 1,
          stalls: 0,
          inputTokens: 7_000,
          cachedInputTokens: 4_900,
          outputTokens: 1_400,
          costUsd: 0.3,
          cacheHitRate: 0.7,
        },
        OpenRouter: {
          calls: 4,
          retries: 1,
          stalls: 1,
          inputTokens: 3_000,
          cachedInputTokens: 1_100,
          outputTokens: 600,
          costUsd: 0.15,
          cacheHitRate: 1_100 / 3_000,
        },
      },
    }))
    assert.ok(postE1)
    assert.equal(postE1.providerBreakdown['Morph Ultra']?.calls, 8)
    assert.equal(postE1.providerBreakdown['Morph Ultra']?.cacheHitRate, 0.7)
    assert.equal(postE1.providerBreakdown.OpenRouter?.stalls, 1)
    assert.ok(Math.abs((postE1.providerBreakdown.OpenRouter?.cacheHitRate ?? 0) - 1_100 / 3_000) < 1e-9)
  })

  it('merges providerBreakdown across Morph Ultra, OpenCode Go, and OpenRouter with token-weighted cacheHitRate', () => {
    const cellA: Record<string, MultihopProviderTelemetry> = {
      'Morph Ultra': {
        calls: 10,
        retries: 1,
        stalls: 0,
        inputTokens: 10_000,
        cachedInputTokens: 8_000,
        outputTokens: 2_000,
        costUsd: 0.4,
        cacheHitRate: 0.8,
      },
      'OpenCode Go': {
        calls: 5,
        retries: 0,
        stalls: 1,
        inputTokens: 4_000,
        cachedInputTokens: 1_000,
        outputTokens: 1_000,
        costUsd: 0.15,
        cacheHitRate: 0.25,
      },
    }
    const cellB: Record<string, MultihopProviderTelemetry> = {
      'Morph Ultra': {
        calls: 20,
        retries: 2,
        stalls: 1,
        inputTokens: 30_000,
        cachedInputTokens: 12_000,
        outputTokens: 6_000,
        costUsd: 1.1,
        cacheHitRate: 0.4,
      },
      OpenRouter: {
        calls: 15,
        retries: 3,
        stalls: 2,
        inputTokens: 20_000,
        cachedInputTokens: 5_000,
        outputTokens: 4_000,
        costUsd: 0.75,
        cacheHitRate: 0.25,
      },
    }

    const merged = mergeProviderBreakdowns([cellA, cellB])
    assert.deepEqual(Object.keys(merged), ['Morph Ultra', 'OpenCode Go', 'OpenRouter'])

    // Morph Ultra: (8,000 + 12,000) / (10,000 + 30,000) = 20,000 / 40,000 = 0.5 (NOT unweighted 0.6!)
    assert.equal(merged['Morph Ultra']!.calls, 30)
    assert.equal(merged['Morph Ultra']!.retries, 3)
    assert.equal(merged['Morph Ultra']!.stalls, 1)
    assert.equal(merged['Morph Ultra']!.inputTokens, 40_000)
    assert.equal(merged['Morph Ultra']!.cachedInputTokens, 20_000)
    assert.equal(merged['Morph Ultra']!.outputTokens, 8_000)
    assert.equal(merged['Morph Ultra']!.costUsd, 1.5)
    assert.equal(merged['Morph Ultra']!.cacheHitRate, 0.5)

    assert.equal(merged['OpenCode Go']!.calls, 5)
    assert.equal(merged['OpenCode Go']!.cacheHitRate, 0.25)

    assert.equal(merged.OpenRouter!.calls, 15)
    assert.equal(merged.OpenRouter!.retries, 3)
    assert.equal(merged.OpenRouter!.stalls, 2)
    assert.equal(merged.OpenRouter!.costUsd, 0.75)
  })

  it('aggregates multi-cell token telemetry, weights cacheHitRate by tokens, and renders 1-line markdown summary', () => {
    const telA: MultihopTokenTelemetry = {
      totalCostUsd: 0.8,
      inputTokens: 10_000,
      cachedInputTokens: 8_000,
      uncachedInputTokens: 2_000,
      outputTokens: 2_000,
      reasoningTokens: 400,
      providerCalls: 10,
      providerRetries: 1,
      providerStalls: 0,
      cacheHitRate: 0.8,
      retryStallWasteUsd: 0.08,
      providerBreakdown: {
        'Morph Ultra': {
          calls: 6,
          retries: 0,
          stalls: 0,
          inputTokens: 6_000,
          cachedInputTokens: 5_400,
          outputTokens: 1_200,
          costUsd: 0.5,
          cacheHitRate: 0.9,
        },
        'OpenCode Go': {
          calls: 4,
          retries: 1,
          stalls: 0,
          inputTokens: 4_000,
          cachedInputTokens: 2_600,
          outputTokens: 800,
          costUsd: 0.3,
          cacheHitRate: 0.65,
        },
      },
      topToolResultDrivers: [
        { toolName: 'request_http', calls: 12, bytes: 40_000, spilledCount: 1 },
        { toolName: 'derive_evidence', calls: 3, bytes: 25_000, spilledCount: 0 },
        { toolName: 'query_facts', calls: 5, bytes: 15_000, spilledCount: 0 },
        { toolName: 'tool_d', calls: 2, bytes: 5_000, spilledCount: 0 },
        { toolName: 'tool_e', calls: 1, bytes: 4_000, spilledCount: 0 },
      ],
    }
    const telB: MultihopTokenTelemetry = {
      totalCostUsd: 2.2,
      inputTokens: 30_000,
      cachedInputTokens: 6_000,
      uncachedInputTokens: 24_000,
      outputTokens: 8_000,
      reasoningTokens: 1_200,
      providerCalls: 30,
      providerRetries: 4,
      providerStalls: 2,
      cacheHitRate: 0.2,
      retryStallWasteUsd: 0.32,
      providerBreakdown: {
        'Morph Ultra': {
          calls: 14,
          retries: 1,
          stalls: 0,
          inputTokens: 14_000,
          cachedInputTokens: 4_600,
          outputTokens: 4_800,
          costUsd: 1.0,
          cacheHitRate: 4_600 / 14_000,
        },
        OpenRouter: {
          calls: 16,
          retries: 3,
          stalls: 2,
          inputTokens: 16_000,
          cachedInputTokens: 1_400,
          outputTokens: 3_200,
          costUsd: 1.2,
          cacheHitRate: 1_400 / 16_000,
        },
      },
      topToolResultDrivers: [
        { toolName: 'request_http', calls: 8, bytes: 35_000, spilledCount: 2 },
        { toolName: 'run_script', calls: 6, bytes: 50_000, spilledCount: 1 },
        { toolName: 'tool_f', calls: 2, bytes: 12_000, spilledCount: 0 },
      ],
    }

    const cell1 = makeCell({
      app: 'paygrid',
      cell: 'paygrid-seed1-grey-box',
      chainsTotal: 4,
      chainsConfirmed: 2,
      costUsd: 0.8,
      costPerConfirmed: computeCostPerConfirmed(0.8, 2),
      cacheHitRate: telA.cacheHitRate,
      retryStallWasteUsd: telA.retryStallWasteUsd,
      providerBreakdown: telA.providerBreakdown,
      topToolResultDrivers: telA.topToolResultDrivers,
      tokenTelemetry: telA,
    })
    const cell2 = makeCell({
      app: 'shipforge',
      cell: 'shipforge-seed1-grey-box',
      chainsTotal: 4,
      chainsConfirmed: 1,
      costUsd: 2.2,
      costPerConfirmed: computeCostPerConfirmed(2.2, 1),
      cacheHitRate: telB.cacheHitRate,
      retryStallWasteUsd: telB.retryStallWasteUsd,
      providerBreakdown: telB.providerBreakdown,
      topToolResultDrivers: telB.topToolResultDrivers,
      tokenTelemetry: telB,
    })

    const agg = aggregateMultihopCells([cell1, cell2])
    assert.equal(agg.costUsd, 3.0)
    assert.equal(agg.costPerConfirmed, 1)
    // Weighted cache hit rate: (8,000 + 6,000) / (10,000 + 30,000) = 14,000 / 40,000 = 0.35 (NOT unweighted 0.50!)
    assert.equal(agg.cacheHitRate, 0.35)
    assert.equal(agg.retryStallWasteUsd, 0.4)
    assert.equal(agg.tokenTelemetry?.providerCalls, 40)
    assert.equal(agg.tokenTelemetry?.providerRetries, 5)
    assert.equal(agg.tokenTelemetry?.providerStalls, 2)
    assert.equal(agg.tokenTelemetry?.reasoningTokens, 1_600)
    assert.deepEqual(
      (agg.topToolResultDrivers ?? []).map(d => [d.toolName, d.bytes]),
      [
        ['request_http', 75_000],
        ['run_script', 50_000],
        ['derive_evidence', 25_000],
        ['query_facts', 15_000],
        ['tool_f', 12_000],
      ],
    )

    const report = buildMultihopReport([cell1, cell2], [], '98e27554')
    assert.equal(report.costPerConfirmed, 1)
    assert.equal(report.cacheHitRate, 0.35)
    assert.equal(report.retryStallWasteUsd, 0.4)
    assert.deepEqual(Object.keys(report.providerBreakdown ?? {}), ['Morph Ultra', 'OpenCode Go', 'OpenRouter'])

    const md = renderMultihopReport(report, 'md')
    const summaryLine = md.split('\n').find(line => line.startsWith('Cost & Cache Summary:'))
    assert.ok(summaryLine, 'multihop-report.md must include a 1-line Cost & Cache Summary')
    assert.ok(summaryLine.includes('cost=$3.0000'))
    assert.ok(summaryLine.includes('$/confirmed=$1.0000'))
    assert.ok(summaryLine.includes('cacheHit=35.0%'))
    assert.ok(summaryLine.includes('retryStallWaste=$0.4000'))
    // Total calls = 20 Morph Ultra (50%), 16 OpenRouter (40%), 4 OpenCode Go (10%)
    // Total tokens = (20k+6k)=26k Morph Ultra (52%), (16k+3.2k)=19.2k OpenRouter (38.4%), (4k+0.8k)=4.8k OpenCode Go (9.6%)
    assert.ok(summaryLine.includes('Morph Ultra (50.0% calls / 52.0% tokens)'))
    assert.ok(summaryLine.includes('OpenRouter (40.0% calls / 38.4% tokens)'))
    assert.ok(summaryLine.includes('OpenCode Go (10.0% calls / 9.6% tokens)'))

    // Zero-confirmed report formats $/confirmed=n/a cleanly
    const zeroConfirmedCell = makeCell({ chainsConfirmed: 0, costUsd: 1.25, tokenTelemetry: null })
    const zeroReport = buildMultihopReport([zeroConfirmedCell], [], '98e27554')
    assert.equal(zeroReport.costPerConfirmed, null)
    assert.equal(aggregateMultihopTokenTelemetry([zeroConfirmedCell]), null)
    const zeroLine = formatCostCacheProviderSummaryLine({
      costUsd: zeroReport.agentic.costUsd,
      costPerConfirmed: zeroReport.costPerConfirmed ?? null,
      cacheHitRate: zeroReport.cacheHitRate ?? null,
      retryStallWasteUsd: zeroReport.retryStallWasteUsd ?? 0,
      providerBreakdown: zeroReport.providerBreakdown,
    })
    assert.ok(zeroLine.includes('$/confirmed=n/a'))
    assert.ok(zeroLine.includes('cacheHit=n/a'))
    assert.ok(zeroLine.includes('providers=none'))
  })

  it('captures Execution.getRunTokenTelemetry(runId) before disposal and observes null after disposal', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'kovo-e3-exec-telemetry-'))
    const store = new Store(join(tempDir, 'kovo.sqlite'))
    const runId = `e3-telemetry-${Date.now()}`
    try {
      const engine = new Execution(store)
      recordProviderUsageTelemetry({
        runId,
        inputTokens: 5_000,
        cachedInputTokens: 3_500,
        outputTokens: 1_000,
        reasoningTokens: 250,
        costUsd: 0.25,
        outcome: 'ok',
      })
      recordProviderUsageTelemetry({
        runId,
        inputTokens: 1_000,
        cachedInputTokens: 0,
        outputTokens: 100,
        costUsd: 0.05,
        outcome: 'stalled',
        stalled: true,
        retried: true,
      })
      recordToolResultSizeTelemetry({
        runId,
        toolName: 'request_http',
        bytes: 18_000,
        spilled: true,
      })

      const beforeDispose = engine.getRunTokenTelemetry(runId)
      assert.ok(beforeDispose, 'telemetry must be readable before teardown/disposal')
      const compact = compactRunTokenTelemetry(beforeDispose)
      assert.ok(compact)
      assert.equal(compact.inputTokens, 6_000)
      assert.equal(compact.cachedInputTokens, 3_500)
      assert.equal(compact.uncachedInputTokens, 2_500)
      assert.equal(compact.outputTokens, 1_100)
      assert.equal(compact.reasoningTokens, 250)
      assert.equal(compact.providerCalls, 2)
      assert.equal(compact.providerRetries, 1)
      assert.equal(compact.providerStalls, 1)
      assert.equal(compact.totalCostUsd, 0.3)
      assert.equal(compact.retryStallWasteUsd, 0.05)
      assert.ok(Math.abs(compact.cacheHitRate - 3_500 / 6_000) < 1e-9)
      assert.deepEqual(compact.topToolResultDrivers, [
        { toolName: 'request_http', calls: 1, bytes: 18_000, spilledCount: 1 },
      ])

      // Simulates teardownCell() disposing run-scoped telemetry
      disposeRunTokenTelemetry(runId)
      assert.equal(engine.getRunTokenTelemetry(runId), null)
    } finally {
      disposeRunTokenTelemetry(runId)
      store.close()
      rmSync(tempDir, { recursive: true, force: true })
    }
  })

  it('parses --smoke preset defaults, honors explicit overrides, and documents the 4-tier cadence in usage', () => {
    // Baseline without --smoke
    const standard = parseMultihopArgs(['--app', 'paygrid'])
    assert.equal(standard.smoke, false)
    assert.equal(standard.budgetUsd, DEFAULT_BUDGET_USD)
    assert.equal(standard.maxDurationMs, DEFAULT_MAX_DURATION_MS)

    // --smoke preset sets 10m duration and $2 budget
    const smokeDefaults = parseMultihopArgs(['--smoke'])
    assert.equal(smokeDefaults.smoke, true)
    assert.equal(smokeDefaults.budgetUsd, SMOKE_BUDGET_USD)
    assert.equal(smokeDefaults.maxDurationMs, SMOKE_MAX_DURATION_MS)
    assert.equal(smokeDefaults.budgetUsd, 2)
    assert.equal(smokeDefaults.maxDurationMs, 10 * 60_000)

    // Slice smoke (--app <app> --smoke)
    const sliceSmoke = parseMultihopArgs(['--app', 'paygrid', '--smoke'])
    assert.equal(sliceSmoke.smoke, true)
    assert.deepEqual(sliceSmoke.apps, ['paygrid'])
    assert.equal(sliceSmoke.budgetUsd, 2)
    assert.equal(sliceSmoke.maxDurationMs, 10 * 60_000)

    // Explicit overrides take precedence over --smoke defaults
    const overrideBoth = parseMultihopArgs(['--smoke', '--duration-min', '20', '--budget-usd', '3.5'])
    assert.equal(overrideBoth.smoke, true)
    assert.equal(overrideBoth.maxDurationMs, 20 * 60_000)
    assert.equal(overrideBoth.budgetUsd, 3.5)

    const overrideMaxMs = parseMultihopArgs(['--smoke', '--max-duration-ms', '15m'])
    assert.equal(overrideMaxMs.smoke, true)
    assert.equal(overrideMaxMs.maxDurationMs, 15 * 60_000)
    assert.equal(overrideMaxMs.budgetUsd, 2)

    // Value attached to boolean --smoke fails fast
    assert.throws(() => parseMultihopArgs(['--smoke=fast']), /--smoke is a boolean flag/)

    // --help usage documents --smoke and the 4-tier iteration cadence
    assert.ok(usage.includes('--smoke'))
    assert.ok(usage.includes('scripts/replay-v8-receipts.ts'))
    assert.ok(usage.includes('--app <app> --smoke'))
    assert.ok(usage.includes('4-Tier Iteration Cadence'))
  })
})
