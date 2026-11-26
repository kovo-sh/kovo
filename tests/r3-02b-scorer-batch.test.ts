/**
 * R3-02 Stream B + Forensic Live-M2 Fixes:
 *  1. Default per-run ledger emission (`appendPerRunLedgerRow` under `KOVO_LEDGER_ROOT`) + `--no-ledger`
 *     escape hatch + `--ledger`/`--promote-ledger` promotion across Execution runners
 *     (`benchmark-realistic.ts`, `benchmark-multihop.ts`, `benchmark-agentic-matrix.ts`).
 *  2. Observed `run.effective_config` enforcement (never fabricating `effectiveConfig` from caller args;
 *     marking rows `INVALID` when observed config is absent).
 *  3. Per-cell teardown isolation (`benchmark-multihop.ts` & `benchmark-reason.ts` NEVER call
 *     process-global `cleanup.runAll()` inside `runCell()` `finally`, so 1 failing cell never tears
 *     down sibling cells).
 *  4. `waitForTerminal` fail-fast when `Execution.isStopped` flips true while a run is non-terminal.
 *  5. `scripts/batch-boundary.sh --dry-run` dirty-tree guard, plan output, and salt non-leakage.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'

import type { Scorecard } from '../benchmarks/realistic-bench/lib/types.ts'
import { VERIFY_RPC_SDK_VERSION } from '../src/server/verify-rpc.ts'
import {
  EffectiveConfigMismatchError,
  computeEffectiveConfig,
  readLedgerRows,
  resolveGitState,
} from '../scripts/bench-ledger.ts'
import {
  MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH,
  parseRealisticArgs,
  resolveObservedEffectiveConfigForRunner,
  waitForTerminal as waitForRealisticTerminal,
  writeRealisticCellLedgerRow,
} from '../scripts/benchmark-realistic.ts'
import {
  createCleanupRegistry as createMultihopCleanupRegistry,
  parseMultihopArgs,
  runCell as runMultihopCell,
  waitForTerminal as waitForMultihopTerminal,
  writeMultihopLedgerRows,
  type MultihopCellMeta,
  type MultihopRuntime,
} from '../scripts/benchmark-multihop.ts'
import {
  waitForTerminal as waitForReasonTerminal,
} from '../scripts/benchmark-reason.ts'
import {
  collectCellResult as collectAgenticCellResult,
  parseMatrixArgs,
  writeAgenticMatrixLedgerRows,
  type MatrixCell,
} from '../scripts/benchmark-agentic-matrix.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
const REPO_ROOT = resolve(import.meta.dirname, '..')
const HEAD_SHA = resolveGitState(REPO_ROOT).gitSha
const HASH_A = 'a'.repeat(64)

function makeTmpDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeObservedConfig(overrides: Partial<Parameters<typeof computeEffectiveConfig>[0]> = {}) {
  return computeEffectiveConfig({
    observed: {
      environment: 'local-lab',
      environmentMode: 'ephemeral_lab',
      tier: 3,
      approvalPolicy: 'auto_review',
      deterministicOnly: true,
      wordlistOn: false,
      proofReceiptMode: 'strict',
      workerImageId: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
      workerSourceHash: '0123456789abcdef0123456789abcdef01234567',
      sdkVersion: VERIFY_RPC_SDK_VERSION,
    },
    deterministicOnly: true,
    environment: 'local-lab',
    approvalPolicy: 'auto_review',
    wordlistOn: false,
    verifierBackend: 'docker',
    mode: 'grey-box',
    env: {},
    ...overrides,
  })
}

function makeSyntheticScorecard(overrides: Partial<Scorecard> = {}): Scorecard {
  return {
    app: 'acme-saas',
    seed: 1,
    seedSet: 'dev',
    mode: 'grey-box',
    targets: 10,
    confirmed: 4,
    recall: 0.4,
    precision: 1,
    strictPrecision: 1,
    decoys: 2,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    totalCostUsd: 0,
    vulns: [
      { siteId: 'site-1', outcome: 'confirmed' } as Scorecard['vulns'][number],
      { siteId: 'site-2', outcome: 'missed' } as Scorecard['vulns'][number],
    ],
    funnel: {
      targetVulns: 10,
      surfaceDiscovered: 12,
      hypothesisFormed: 6,
      signalObserved: 5,
      specSubmitted: 4,
      zeroLlmConfirmed: 4,
    },
    failureBuckets: {} as Scorecard['failureBuckets'],
    ...overrides,
  } as Scorecard
}

function makeMultihopCellMeta(overrides: Partial<MultihopCellMeta> = {}): MultihopCellMeta {
  const cfg = makeObservedConfig()
  return {
    schemaVersion: 1,
    status: 'VALID',
    benchmarkVersion: HASH_A,
    effectiveConfigHash: cfg.effectiveConfigHash,
    effectiveConfig: cfg.effectiveConfig,
    wordlistOn: false,
    reportable: true,
    workerImageId: cfg.effectiveConfig.workerImageId ?? null,
    workerSourceHash: cfg.effectiveConfig.workerSourceHash ?? null,
    sdkVersion: VERIFY_RPC_SDK_VERSION,
    app: 'paygrid',
    sealed: false,
    seed: 1,
    seedSet: 'dev',
    mode: 'white-box',
    cell: 'paygrid-seed1-white-box',
    llm: 'deterministic-no-llm',
    origin: 'http://127.0.0.1:41001',
    publicOrigins: [],
    loginPath: '/api/login',
    gitSha: HEAD_SHA,
    model: { mode: 'deterministic-no-llm', profiles: [] },
    verifierBackend: 'docker',
    workerSessions: true,
    workerSessionsDetail: 'ok',
    dataDirIsolated: true,
    dataDirSource: null,
    isolatedProfileNames: [],
    dataDirKept: false,
    budgetUsd: 5,
    maxDurationMs: 600_000,
    startedAt: 1000,
    endedAt: 11_000,
    durationMs: 10_000,
    timedOut: false,
    terminalStatus: 'complete',
    terminalPhase: 'complete',
    runId: 'run-1',
    projectId: 'proj-1',
    chainsTotal: 4,
    chainsOracleObserved: 0,
    chainsCompositeConfirmed: 0,
    chainsConfirmed: 0,
    oracleOnlyCount: 0,
    receiptOnlyCount: 0,
    shortcutViolations: 0,
    modeBViolations: 0,
    recall: 0,
    precision: null,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: 0,
    unmatchedFalsePositives: 0,
    unmatchedFindingsDetail: [],
    costUsd: 0,
    tpPerDollar: null,
    tpPer10m: 0,
    hopFunnel: {
      totalChains: 4,
      H1: 0,
      H2: 0,
      H3: 0,
      H4Plus: 0,
      FinalOracle: 0,
      CompositeReceiptConfirmed: 0,
      dropReasons: {} as MultihopCellMeta['hopFunnel']['dropReasons'],
    },
    depthBreakdown: {} as MultihopCellMeta['depthBreakdown'],
    chains: [],
    hardenedTwins: [],
    assignmentsCompleted: 0,
    assignmentsTotal: 0,
    investigationCompleted: 0,
    phaseBAssignments: 0,
    deadEndReprobeCount: 0,
    deadEndReprobeWasteRate: 0,
    deadEndWastePct: 0,
    frontier: {
      deadEndReprobeCount: 0,
      totalAssignmentsDispatched: 0,
      phaseBAssignments: 0,
      deadEndReprobeWasteRate: 0,
    },
    telemetry: {} as MultihopCellMeta['telemetry'],
    facts: 0,
    findingsPersisted: 0,
    findingsSubmitted: 0,
    compositeReceiptsExtracted: 0,
    endpointsDiscovered: 5,
    requestCount: 10,
    oracleEventCount: 0,
    inert: false,
    snapshot: {} as MultihopCellMeta['snapshot'],
    resumedFrom: null,
    snapshotSkippedMs: 0,
    notes: [],
    shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
    ...overrides,
  }
}

describe('R3-02b: default per-run ledger emission & observed effective_config enforcement', () => {
  test('1. CLI parsers default per-run ledger ON, accept --no-ledger, and reject --no-ledger + --ledger', () => {
    const rDef = parseRealisticArgs(['--app', 'acme-saas'], {})
    assert.equal(rDef.noLedger, undefined)
    assert.equal(rDef.ledgerPath, undefined)
    assert.equal(parseRealisticArgs(['--app', 'acme-saas', '--no-ledger'], {}).noLedger, true)
    assert.throws(() => parseRealisticArgs(['--no-ledger', '--ledger'], {}), /--no-ledger/)

    const mDef = parseMultihopArgs(['--no-llm'], {})
    assert.equal(mDef.noLedger, undefined)
    assert.equal(parseMultihopArgs(['--no-llm', '--no-ledger'], {}).noLedger, true)
    assert.throws(() => parseMultihopArgs(['--no-ledger', '--promote-ledger'], {}), /--no-ledger/)

    const aDef = parseMatrixArgs(['--no-llm'], {})
    assert.equal(aDef.noLedger, undefined)
    assert.equal(parseMatrixArgs(['--no-llm', '--no-ledger'], {}).noLedger, true)
    assert.throws(() => parseMatrixArgs(['--no-ledger', '--ledger'], {}), /--no-ledger/)
  })

  test('2. resolveObservedEffectiveConfigForRunner never fabricates effectiveConfig when observed is null, and fails closed on mismatch', () => {
    const missing = resolveObservedEffectiveConfigForRunner({
      observed: null,
      deterministicOnly: true,
      wordlistOn: false,
      verifierBackend: 'docker',
      mode: 'grey-box',
    })
    assert.equal(missing.observed, false)
    assert.equal(missing.effectiveConfig, undefined)
    assert.equal(missing.effectiveConfigHash, MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH)

    const valid = resolveObservedEffectiveConfigForRunner({
      observed: {
        environment: 'local-lab',
        approvalPolicy: 'auto_review',
        deterministicOnly: true,
        wordlistOn: false,
        sdkVersion: VERIFY_RPC_SDK_VERSION,
      },
      deterministicOnly: true,
      wordlistOn: false,
      verifierBackend: 'docker',
      mode: 'grey-box',
    })
    assert.equal(valid.observed, true)
    assert.ok(valid.effectiveConfig)
    assert.equal(valid.effectiveConfig.wordlistOn, false)

    assert.throws(
      () => resolveObservedEffectiveConfigForRunner({
        observed: {
          environment: 'local-lab',
          approvalPolicy: 'auto_review',
          deterministicOnly: true,
          wordlistOn: true,
          sdkVersion: VERIFY_RPC_SDK_VERSION,
        },
        deterministicOnly: true,
        wordlistOn: false,
        verifierBackend: 'docker',
        mode: 'grey-box',
      }),
      (err: unknown) => err instanceof EffectiveConfigMismatchError,
    )
  })

  test('3. benchmark-realistic, benchmark-multihop & benchmark-agentic-matrix write per-run ledger rows by default, honor --no-ledger, and mark missing observed effectiveConfig INVALID', (t) => {
    const dir = makeTmpDir(t, 'r3-02b-ledger-')
    const runsDir = join(dir, 'runs')
    const committedLedger = join(dir, 'committed.jsonl')
    const cfg = makeObservedConfig()

    // (a) realistic-bench default per-run write with observed config -> VALID + promotes cleanly
    const rOk = writeRealisticCellLedgerRow({
      scorecard: makeSyntheticScorecard(),
      app: 'acme-saas',
      split: 'dev',
      mode: 'grey-box',
      llm: 'deterministic-no-llm',
      seed: 1,
      recordedAt: '2026-11-26T01:00:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: cfg.effectiveConfigHash,
      effectiveConfig: cfg.effectiveConfig,
      observedEffectiveConfig: true,
      inert: false,
      conventionalWordlist: false,
      durationMs: 4_000,
      runsDir,
      runId: 'r-ok',
      promoteLedgerPath: committedLedger,
    })
    assert.ok(rOk.perRunPath && existsSync(rOk.perRunPath))
    assert.equal(rOk.row?.status, 'VALID')
    assert.equal(rOk.row?.effectiveConfig?.wordlistOn, false)
    assert.equal(readLedgerRows(committedLedger).length, 1)

    // (b) realistic-bench missing observed config -> INVALID, no fabricated effectiveConfig, never promoted
    const rMissing = writeRealisticCellLedgerRow({
      scorecard: makeSyntheticScorecard(),
      app: 'shopflow',
      split: 'dev',
      mode: 'grey-box',
      llm: 'deterministic-no-llm',
      seed: 1,
      recordedAt: '2026-11-26T01:01:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH,
      effectiveConfig: undefined,
      observedEffectiveConfig: false,
      inert: false,
      conventionalWordlist: false,
      durationMs: 4_000,
      runsDir,
      runId: 'r-missing',
      promoteLedgerPath: committedLedger,
    })
    assert.equal(rMissing.row?.status, 'INVALID')
    assert.equal(rMissing.row?.effectiveConfig, undefined)
    assert.equal(rMissing.row?.reportable, false)
    assert.ok(rMissing.row?.notes?.includes('missing_observed_effective_config'))
    assert.equal(readLedgerRows(committedLedger).length, 1, 'INVALID row must NOT be promoted')

    // (c) realistic-bench --no-ledger writes nothing
    const rSuppressed = writeRealisticCellLedgerRow({
      scorecard: makeSyntheticScorecard(),
      app: 'opsportal',
      split: 'dev',
      mode: 'grey-box',
      llm: 'deterministic-no-llm',
      seed: 1,
      recordedAt: '2026-11-26T01:02:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: cfg.effectiveConfigHash,
      effectiveConfig: cfg.effectiveConfig,
      observedEffectiveConfig: true,
      inert: false,
      conventionalWordlist: false,
      durationMs: 4_000,
      noLedger: true,
      runsDir,
      runId: 'r-none',
    })
    assert.equal(rSuppressed.perRunPath, null)
    assert.equal(existsSync(join(runsDir, 'r-none.jsonl')), false)

    // (d) multihop-saas default per-run write: observed -> VALID, missing observed -> INVALID, --no-ledger -> empty
    const mWritten = writeMultihopLedgerRows({
      cells: [
        makeMultihopCellMeta({ app: 'paygrid' }),
        makeMultihopCellMeta({
          app: 'shipforge',
          effectiveConfig: undefined,
          effectiveConfigHash: MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH,
        }),
      ],
      recordedAt: '2026-11-26T01:03:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      runsDir,
      runId: 'm-run',
    })
    assert.ok(existsSync(mWritten.perRunPath))
    const mRows = readLedgerRows(mWritten.perRunPath)
    assert.equal(mRows.length, 2)
    assert.equal(mRows[0]!.status, 'VALID')
    assert.ok(mRows[0]!.effectiveConfig)
    assert.equal(mRows[1]!.status, 'INVALID')
    assert.equal(mRows[1]!.effectiveConfig, undefined)
    assert.ok(mRows[1]!.notes?.includes('missing_observed_effective_config'))

    const mSuppressed = writeMultihopLedgerRows({
      cells: [makeMultihopCellMeta()],
      recordedAt: '2026-11-26T01:04:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      noLedger: true,
      runsDir,
      runId: 'm-none',
    })
    assert.equal(mSuppressed.perRunPath, '')
    assert.equal(existsSync(join(runsDir, 'm-none.jsonl')), false)

    // (e) benchmark-agentic-matrix propagates observed effectiveConfig from meta.json and rejects missing observed config
    const matrixOut = join(dir, 'matrix-out')
    const cellWithObs: MatrixCell = { app: 'acme-saas', seed: 1, mode: 'grey-box', seedSet: 'dev', label: 'acme-saas-seed1-grey-box' }
    const cellNoObs: MatrixCell = { app: 'shopflow', seed: 1, mode: 'grey-box', seedSet: 'dev', label: 'shopflow-seed1-grey-box' }
    mkdirSync(join(matrixOut, cellWithObs.label), { recursive: true })
    mkdirSync(join(matrixOut, cellNoObs.label), { recursive: true })
    writeFileSync(join(matrixOut, cellWithObs.label, `${cellWithObs.label}.json`), JSON.stringify({
      app: 'acme-saas', seed: 1, targets: 10, confirmed: 3, precision: 1, decoyFalsePositives: 0, unmatchedFalsePositives: 0, totalCostUsd: 0,
    }))
    writeFileSync(join(matrixOut, cellWithObs.label, `${cellWithObs.label}.meta.json`), JSON.stringify({
      model: { mode: 'deterministic-no-llm' },
      workerSessions: false,
      inert: false,
      effectiveConfigObserved: true,
      effectiveConfigHash: cfg.effectiveConfigHash,
      effectiveConfig: cfg.effectiveConfig,
      workerImageId: cfg.effectiveConfig.workerImageId,
      workerSourceHash: cfg.effectiveConfig.workerSourceHash,
      sdkVersion: VERIFY_RPC_SDK_VERSION,
    }))
    writeFileSync(join(matrixOut, cellNoObs.label, `${cellNoObs.label}.json`), JSON.stringify({
      app: 'shopflow', seed: 1, targets: 10, confirmed: 2, precision: 1, decoyFalsePositives: 0, unmatchedFalsePositives: 0, totalCostUsd: 0,
    }))
    writeFileSync(join(matrixOut, cellNoObs.label, `${cellNoObs.label}.meta.json`), JSON.stringify({
      model: { mode: 'deterministic-no-llm' },
      workerSessions: false,
      inert: false,
    }))

    const collectedObs = collectAgenticCellResult(cellWithObs, { outDir: matrixOut, noLlm: true }, { exitCode: 0, runtimeMs: 500, output: '' })
    const collectedNoObs = collectAgenticCellResult(cellNoObs, { outDir: matrixOut, noLlm: true }, { exitCode: 0, runtimeMs: 500, output: '' })
    assert.equal(collectedObs.effectiveConfigObserved, true)
    assert.equal(collectedObs.effectiveConfigHash, cfg.effectiveConfigHash)
    assert.equal(collectedNoObs.effectiveConfigObserved, false)

    const aWritten = writeAgenticMatrixLedgerRows({
      results: [collectedObs, collectedNoObs],
      recordedAt: '2026-11-26T01:05:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: MISSING_OBSERVED_EFFECTIVE_CONFIG_HASH,
      certifying: false,
      runsDir,
      runId: 'a-run',
    })
    const aRows = readLedgerRows(aWritten.perRunPath)
    assert.equal(aRows.length, 2)
    assert.equal(aRows[0]!.status, 'VALID')
    assert.equal(aRows[0]!.effectiveConfigHash, cfg.effectiveConfigHash)
    assert.equal(aRows[1]!.status, 'INVALID')
    assert.equal(aRows[1]!.effectiveConfig, undefined)
    assert.ok(aRows[1]!.notes?.includes('missing_observed_effective_config'))

    const aSuppressed = writeAgenticMatrixLedgerRows({
      results: [collectedObs],
      recordedAt: '2026-11-26T01:06:00.000Z',
      gitSha: HEAD_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: cfg.effectiveConfigHash,
      certifying: false,
      noLedger: true,
      runsDir,
      runId: 'a-none',
    })
    assert.equal(aSuppressed.perRunPath, '')
    assert.equal(existsSync(join(runsDir, 'a-none.jsonl')), false)
  })
})

describe('R3-02b: per-cell teardown isolation & waitForTerminal fail-fast', () => {
  test('4. 1 failing cell in benchmark-multihop never tears down concurrent sibling cells (no cleanup.runAll() in cell finally)', async (t) => {
    // (a) Static invariant: neither benchmark-multihop nor benchmark-reason calls cleanup.runAll() inside runCell()
    for (const rel of ['scripts/benchmark-multihop.ts', 'scripts/benchmark-reason.ts']) {
      const src = readFileSync(join(REPO_ROOT, rel), 'utf8')
      const startIdx = src.indexOf('export async function runCell(')
      assert.ok(startIdx > 0, `runCell not found in ${rel}`)
      const endIdx = src.indexOf('\n// -----', startIdx)
      const body = src.slice(startIdx, endIdx > startIdx ? endIdx : startIdx + 25_000)
      const codeOnly = body.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '')
      assert.equal(
        codeOnly.includes('cleanup.runAll('),
        false,
        `${rel} runCell() MUST NEVER call process-global cleanup.runAll()`,
      )
    }

    // (b) Live concurrency isolation test: sibling cell registers cleanup in shared CleanupRegistry;
    // paygrid cell fails after starting its app -> ONLY paygrid stops, sibling cleanup is untouched!
    const outDir = makeTmpDir(t, 'r3-02b-teardown-')
    const sharedCleanup = createMultihopCleanupRegistry()
    let siblingTeardowns = 0
    const unregisterSibling = sharedCleanup.add(async () => {
      siblingTeardowns += 1
    })
    t.after(() => unregisterSibling())

    let failingCellStopped = 0
    const mockRuntime: MultihopRuntime = {
      async startMultihopApp() {
        return {
          app: 'paygrid',
          origin: 'http://127.0.0.1:41001',
          origins: { app: 'http://127.0.0.1:41001' },
          groundTruth: { app: 'paygrid', seed: 1, chains: [], hardenedTwins: [] },
          oracle: { events: () => [], requests: () => [] },
          async stop() {
            failingCellStopped += 1
          },
        }
      },
      briefingFor() {
        throw new Error('simulated mid-cell briefing failure after app boot')
      },
      gradeRun() {
        throw new Error('should not reach gradeRun')
      },
      renderScorecard() {
        return '{}'
      },
      async listSeeds() {
        return { dev: [1] }
      },
    }

    const args = parseMultihopArgs(['--app', 'paygrid', '--seed', '1', '--no-llm', '--verifier', 'local-jq', '--no-ledger', '--out-dir', outDir], {})
    await assert.rejects(
      () => runMultihopCell(args, 'paygrid', 1, mockRuntime, () => {}, sharedCleanup),
      /simulated mid-cell briefing failure/,
    )

    assert.equal(failingCellStopped, 1, 'failing cell MUST tear down its own started app exactly once')
    assert.equal(siblingTeardowns, 0, 'failing cell MUST NEVER invoke sibling cell teardown via cleanup.runAll()')

    // Process-wide emergency cleanup (SIGINT/SIGTERM) still tears down remaining sibling cell cleanly.
    await sharedCleanup.runAll()
    assert.equal(siblingTeardowns, 1, 'process-wide cleanup.runAll() still cleans up surviving sibling cells')
    assert.equal(failingCellStopped, 1, 'failing cell teardown must not double-run after unregisterCleanup()')
  })

  test('5. waitForTerminal fails fast when isEngineStopped() returns true on a non-terminal run, and succeeds when already terminal', async (t) => {
    const { storage } = makeStore(t, 'r3-02b-wait-')
    const { runId } = await setupApprovedRun(storage, { budgetRequests: 300 })
    const farDeadline = Date.now() + 30 * 60_000

    for (const [label, waitFn] of [
      ['benchmark-multihop', waitForMultihopTerminal],
      ['benchmark-realistic', waitForRealisticTerminal],
      ['benchmark-reason', waitForReasonTerminal],
    ] as const) {
      const t0 = Date.now()
      await assert.rejects(
        () => waitFn({
          storage,
          runId,
          deadlineAt: farDeadline,
          isEngineStopped: () => true,
        }),
        /Execution engine stopped unexpectedly/,
        `${label} waitForTerminal must fail fast when engine stops unexpectedly`,
      )
      assert.ok(Date.now() - t0 < 2_000, `${label} waitForTerminal must fail fast (<2s), not spin to deadline`)
    }

    // Once the run reaches a terminal status, isEngineStopped() === true returns cleanly without throwing
    storage.command({ requestId: 'req-stop-terminal', runId, action: 'stop' })
    const res = await waitForMultihopTerminal({
      storage,
      runId,
      deadlineAt: farDeadline,
      isEngineStopped: () => true,
    })
    assert.equal(res.timedOut, false)
    assert.equal(res.status, 'stopped')
  })
})

describe('R3-02b: scripts/batch-boundary.sh orchestration & guards', () => {
  test('6. batch-boundary.sh refuses dirty trees without --allow-dirty, prints full plan on --dry-run, and never leaks held-out salt', (t) => {
    const repoDir = makeTmpDir(t, 'r3-02b-batch-repo-')
    const git = (args: string[]) =>
      execFileSync('git', args, {
        cwd: repoDir,
        encoding: 'utf8',
        env: {
          ...process.env,
          GIT_AUTHOR_NAME: 'Kovo Test',
          GIT_AUTHOR_EMAIL: 'test@kovo.local',
          GIT_COMMITTER_NAME: 'Kovo Test',
          GIT_COMMITTER_EMAIL: 'test@kovo.local',
        },
      }).trim()

    git(['init', '-b', 'main'])
    mkdirSync(join(repoDir, 'scripts'), { recursive: true })
    writeFileSync(join(repoDir, 'scripts/batch-boundary.sh'), readFileSync(join(REPO_ROOT, 'scripts/batch-boundary.sh'), 'utf8'))
    writeFileSync(join(repoDir, 'scripts/render-verification-tables.ts'), '// stub\n')
    git(['add', '.'])
    git(['commit', '-m', 'init'])

    const sentinelSalt = 'super-secret-test-salt-never-print-0123456789abcdef'

    // (a) Clean repo --dry-run succeeds, marks certifying=true, and lists all orchestration steps
    const cleanRes = spawnSync(
      'bash',
      ['scripts/batch-boundary.sh', '--dry-run', '--heldout-seeds', '1000101,1000102,1000103'],
      {
        cwd: repoDir,
        encoding: 'utf8',
        env: { ...process.env, KOVO_RB_HELDOUT_SALT: sentinelSalt },
      },
    )
    assert.equal(cleanRes.status, 0, `expected clean --dry-run PASS: ${cleanRes.stderr}`)
    assert.match(cleanRes.stdout, /certifying:\s+true/)
    assert.match(cleanRes.stdout, /dev --no-llm:/)
    assert.match(cleanRes.stdout, /dev agentic:/)
    assert.match(cleanRes.stdout, /held-out --no-llm:/)
    assert.match(cleanRes.stdout, /held-out agentic:/)
    assert.match(cleanRes.stdout, /promoteLedgerRows:/)
    assert.match(cleanRes.stdout, /regression-floor\.sh/)
    assert.match(cleanRes.stdout, /render-verification-tables\.ts/)
    assert.equal(cleanRes.stdout.includes(sentinelSalt), false, 'held-out salt MUST NEVER appear in stdout')
    assert.equal(cleanRes.stderr.includes(sentinelSalt), false, 'held-out salt MUST NEVER appear in stderr')

    // (b) Dirty tree without --allow-dirty fails closed even under --dry-run
    writeFileSync(join(repoDir, 'dirty.txt'), 'uncommitted\n')
    const dirtyFail = spawnSync(
      'bash',
      ['scripts/batch-boundary.sh', '--dry-run', '--heldout-seeds', '1000101,1000102,1000103'],
      { cwd: repoDir, encoding: 'utf8' },
    )
    assert.notEqual(dirtyFail.status, 0, 'dirty tree without --allow-dirty MUST fail closed')
    assert.match(dirtyFail.stderr, /dirty working tree/)

    // (c) Dirty tree with --allow-dirty succeeds in non-certifying mode
    const dirtyAllowed = spawnSync(
      'bash',
      ['scripts/batch-boundary.sh', '--dry-run', '--allow-dirty', '--heldout-seeds', '1000101,1000102,1000103'],
      { cwd: repoDir, encoding: 'utf8' },
    )
    assert.equal(dirtyAllowed.status, 0, dirtyAllowed.stderr)
    assert.match(dirtyAllowed.stdout, /dirty:\s+true/)
    assert.match(dirtyAllowed.stdout, /certifying:\s+false/)
  })
})
