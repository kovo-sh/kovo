/**
 * R2-05 measurement-layer parity & fail-closed scoring test suite.
 *
 * Feeds `empty`, `failed_inert`, `ok_no_claims`, and `ok_with_claims` cells through EVERY
 * grader, aggregator, and certifier proving:
 *   1. ZERO paths ever return `precision = 1` on empty or failed cells.
 *   2. `failed_inert` ALWAYS yields `status: 'INVALID'` and fails certification.
 *   3. `rawPrecision` vs `headlinePrecision` are strictly distinct when misclassifications exist.
 *   4. Default per-run ledger append writes valid JSONL rows without `--ledger` and explicit
 *      promotion moves only validated rows into the committed ledger idempotently.
 *   5. Held-out seed draws use a separate `'smoke'` HMAC domain and advance certifying draws
 *      strictly past the highest recorded exposed index.
 *   6. `scripts/regression-floor.sh` catches an injected lost TP (`outcome: 'confirmed' -> 'missed'`)
 *      against both JSON and JSONL ledger baselines, and `package.json` `test:boundaries` excludes
 *      quarantined `tests/provider-stream.test.ts`.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ScorecardReader, buildLedgerRow, ratioOrNull } from '../scripts/score-primitives.ts'
import {
  DEFAULT_LEDGER_PATH,
  appendPerRunLedgerRow,
  drawUnburnedHeldoutSeeds,
  drawUnburnedHeldoutSeedsWithMeta,
  loadExposedSeedState,
  promoteLedgerRows,
  readLedgerRows,
  recordExposedHeldoutSeeds,
  resolveGitState,
} from '../scripts/bench-ledger.ts'
import { listSeeds as realisticListSeeds } from '../benchmarks/realistic-bench/generator/seeds.ts'
import { gradeRun as gradeRealisticRun } from '../benchmarks/realistic-bench/grader/score.ts'
import { aggregateScorecards as aggregateRealisticScorecards } from '../benchmarks/realistic-bench/grader/aggregate.ts'
import { gradeRun as gradeReasonRun } from '../benchmarks/reason-bench/grader/score.ts'
import { aggregateScorecards as aggregateReasonScorecards } from '../benchmarks/reason-bench/grader/aggregate.ts'
import {
  readScorecard as readRealisticMatrixScorecard,
  summarizeMatrix as summarizeRealisticMatrix,
  writeRealisticMatrixLedgerRows,
  type CellResult as RealisticMatrixCellResult,
} from '../scripts/benchmark-realistic-matrix.ts'
import {
  collectCellResult as collectAgenticCellResult,
  parseMatrixArgs as parseAgenticMatrixArgs,
  summarizeMatrix as summarizeAgenticMatrix,
  writeAgenticMatrixLedgerRows,
  type MatrixCell,
} from '../scripts/benchmark-agentic-matrix.ts'
import {
  buildRunEvidence,
  evaluateCertification as evaluatePhase1Certification,
  ingestFromDirs as ingestPhase1Dirs,
  writePhase1CertifyLedgerRows,
  type RealismRun,
  type ReasonRun,
  type ScorecardLike,
} from '../scripts/certify-phase1.ts'
import {
  evaluateV8Certification,
  normalizeCell as normalizeV8Cell,
  normalizeOssInputs,
  writeV8CertifyLedgerRows,
  type MultihopCellInput,
} from '../scripts/certify-v8.ts'
import { countFalsePositives } from '../scripts/benchmark-core.ts'
import type { GroundTruth as RealisticGT, GroundTruthEntry as RealisticGTEntry } from '../benchmarks/realistic-bench/lib/types.ts'
import type { GroundTruth as ReasonGT, GroundTruthEntry as ReasonGTEntry } from '../benchmarks/reason-bench/lib/types.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const TEST_GIT_SHA = resolveGitState(REPO_ROOT).gitSha
const TEST_SALT = '0123456789abcdef0123456789abcdef0123456789abcdef'
const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

function makeTmpDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeRealisticEntry(siteId: string, overrides: Partial<RealisticGTEntry> = {}): RealisticGTEntry {
  return {
    siteId,
    title: siteId,
    vulnClass: overrides.vulnClass ?? 'bola',
    cwe: overrides.cwe ?? 'CWE-639',
    severity: overrides.severity ?? 'high',
    endpoints: overrides.endpoints ?? [{ method: 'GET', path: `/api/${siteId}/:id`, routeKey: `${siteId}.get` }],
    triggerEndpoints: overrides.triggerEndpoints ?? [{ method: 'GET', path: `/api/${siteId}/:id`, routeKey: `${siteId}.get` }],
    params: overrides.params ?? ['id'],
    oracle: overrides.oracle ?? { kinds: ['cross_tenant_read'], routeKeys: [`${siteId}.get`] },
    rootCause: overrides.rootCause ?? { file: 'app.ts', symbol: siteId },
  }
}

function makeReasonEntry(siteId: string, overrides: Partial<ReasonGTEntry> = {}): ReasonGTEntry {
  return {
    siteId,
    title: siteId,
    vulnClass: overrides.vulnClass ?? 'business_logic',
    cwe: overrides.cwe ?? 'CWE-840',
    severity: overrides.severity ?? 'high',
    family: overrides.family ?? 'A',
    endpoints: overrides.endpoints ?? [{ method: 'POST', path: `/api/${siteId}`, routeKey: `${siteId}.post` }],
    triggerEndpoints: overrides.triggerEndpoints ?? [{ method: 'POST', path: `/api/${siteId}`, routeKey: `${siteId}.post` }],
    params: overrides.params ?? ['amount'],
    oracle: overrides.oracle ?? { kinds: ['economic_invariant_violation'], routeKeys: [`${siteId}.post`] },
    rootCause: overrides.rootCause ?? { file: 'ledger.ts', symbol: siteId },
  }
}

// ---------------------------------------------------------------------------
// 1. ratioOrNull & ScorecardReader 3-state contract
// ---------------------------------------------------------------------------

describe('R2-05 #1: ratioOrNull & 3-state ScorecardReader', () => {
  test('ratioOrNull never defaults 0/0 or non-finite inputs to 1', () => {
    assert.equal(ratioOrNull(0, 0), null)
    assert.equal(ratioOrNull(5, 0), null)
    assert.equal(ratioOrNull(1, -2), null)
    assert.equal(ratioOrNull(Number.NaN, 5), null)
    assert.equal(ratioOrNull(5, Number.POSITIVE_INFINITY), null)
    assert.equal(ratioOrNull(0, 10), 0)
    assert.equal(ratioOrNull(3, 4), 0.75)
  })

  test('ScorecardReader classifies empty, ok_no_claims, failed_inert, and ok_with_claims strictly', () => {
    // 1) Missing / null / malformed -> failed_inert + INVALID
    const missing = ScorecardReader.read(null)
    assert.equal(missing.state, 'failed_inert')
    assert.equal(missing.status, 'INVALID')
    assert.equal(missing.headlinePrecision, null)
    assert.equal(missing.rawPrecision, null)
    assert.equal(missing.recall, null)

    const schemaBad = ScorecardReader.read({ app: 'acme-saas', precision: 1 })
    assert.equal(schemaBad.state, 'failed_inert')
    assert.equal(schemaBad.status, 'INVALID')
    assert.equal(schemaBad.headlinePrecision, null)

    // 2) Inert / failed cell even with forged precision: 1 -> failed_inert + INVALID + precision null
    const inertCell = ScorecardReader.read(
      { app: 'acme-saas', seed: 1, targets: 20, confirmed: 0, precision: 1, inert: true },
    )
    assert.equal(inertCell.state, 'failed_inert')
    assert.equal(inertCell.status, 'INVALID')
    assert.equal(inertCell.headlinePrecision, null)
    assert.equal(inertCell.rawPrecision, null)
    assert.equal(inertCell.recall, null)

    // 3) ok_no_claims (clean control / 0-claim run even if input falsely says precision: 1)
    const noClaims = ScorecardReader.read(
      { app: 'acme-saas', seed: 1, targets: 20, confirmed: 0, decoyFalsePositives: 0, unmatchedFalsePositives: 0, precision: 1 },
    )
    assert.equal(noClaims.state, 'ok_no_claims')
    assert.equal(noClaims.status, 'VALID')
    assert.equal(noClaims.recall, 0)
    assert.equal(noClaims.headlinePrecision, null, 'ok_no_claims MUST NEVER yield precision 1')
    assert.equal(noClaims.rawPrecision, null)
    assert.equal(noClaims.strictPrecision, null)

    // 4) ok_with_claims with misclassified sibling -> headlinePrecision !== rawPrecision
    const withMisclassified = ScorecardReader.read({
      app: 'acme-saas',
      seed: 1,
      targets: 10,
      confirmed: 2,
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
      misclassifiedFindingIds: ['m-1', 'm-2'],
      precision: 1,
    })
    assert.equal(withMisclassified.state, 'ok_with_claims')
    assert.equal(withMisclassified.status, 'VALID')
    assert.equal(withMisclassified.headlinePrecision, 1)
    assert.equal(withMisclassified.rawPrecision, 0.5, 'rawPrecision MUST charge misclassified claims')
    assert.equal(withMisclassified.strictPrecision, 0.5)
    assert.notEqual(withMisclassified.headlinePrecision, withMisclassified.rawPrecision)
  })
})

// ---------------------------------------------------------------------------
// 2. Graders (realistic-bench & reason-bench) & benchmark-recall
// ---------------------------------------------------------------------------

describe('R2-05 #2: realistic-bench, reason-bench, and benchmark-recall zero precision-1 defaults', () => {
  test('realistic-bench grader and aggregator return null (never 1) on empty claims and keep rawPrecision distinct from headline precision', () => {
    const gt: RealisticGT = {
      schemaVersion: 1,
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      vulns: [
        makeRealisticEntry('v-bola', { vulnClass: 'bola', cwe: 'CWE-639' }),
        makeRealisticEntry('v-bfla', { vulnClass: 'bfla', cwe: 'CWE-285' }),
      ],
      decoys: [],
      chains: [],
    }
    const telemetry = { startedAtMs: 0, endedAtMs: 1000, totalCostUsd: 0.1 }

    const empty = gradeRealisticRun({
      groundTruth: gt,
      findings: [],
      oracleEvents: [],
      requestLog: [],
      telemetry,
      mode: 'grey-box',
    })
    assert.equal(empty.precision, null)
    assert.equal(empty.strictPrecision, null)
    assert.equal(empty.rawPrecision, null)

    const aggEmpty = aggregateRealisticScorecards([empty])
    assert.equal(aggEmpty.precision.mean, null)
    assert.equal(aggEmpty.precision.min, null)
    assert.equal(aggEmpty.precision.max, null)

    // 1 TP on v-bola + 1 runtime-confirmed sibling-misclassified claim (mass_assignment on bfla)
    const gtSibling: RealisticGT = {
      schemaVersion: 1,
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      vulns: [
        makeRealisticEntry('v-bola', { vulnClass: 'bola', cwe: 'CWE-639' }),
        makeRealisticEntry('v-bfla', {
          vulnClass: 'bfla',
          cwe: 'CWE-285',
          endpoints: [{ method: 'POST', path: '/api/admin/roles', routeKey: 'roles.post' }],
          triggerEndpoints: [{ method: 'POST', path: '/api/admin/roles', routeKey: 'roles.post' }],
          oracle: { kinds: ['privilege_escalation'], routeKeys: ['roles.post'] },
        }),
      ],
      decoys: [],
      chains: [],
    }
    const mixed = gradeRealisticRun({
      groundTruth: gtSibling,
      findings: [
        {
          id: 'f-tp',
          title: 'BOLA',
          vulnClass: 'bola',
          cwe: 'CWE-639',
          endpoints: [{ method: 'GET', path: '/api/v-bola/1' }],
          status: 'runtime_confirmed',
          submittedAtMs: 100,
        },
        {
          id: 'f-sibling',
          title: 'Mass assignment on BFLA site',
          vulnClass: 'mass_assignment',
          endpoints: [{ method: 'POST', path: '/api/admin/roles' }],
          status: 'runtime_confirmed',
          submittedAtMs: 120,
        },
      ],
      oracleEvents: [
        {
          seq: 1,
          ts: 50,
          kind: 'cross_tenant_read',
          app: 'acme-saas',
          routeKey: 'v-bola.get',
          method: 'GET',
          path: '/api/v-bola/1',
          actor: 'persona_a',
          detail: {},
        },
      ],
      requestLog: [],
      telemetry,
      mode: 'grey-box',
    })
    assert.equal(mixed.confirmed, 1)
    assert.equal(mixed.misclassifiedFindingIds?.length, 1)
    assert.equal(mixed.precision, 1)
    assert.equal(mixed.strictPrecision, 0.5)
    assert.equal(mixed.rawPrecision, 0.5)
  })

  test('reason-bench grader and aggregator return null (never 1) on empty claims and expose rawPrecision', () => {
    const gt: ReasonGT = {
      schemaVersion: 1,
      app: 'ledgerflow',
      seed: 1,
      seedSet: 'dev',
      vulns: [makeReasonEntry('lf-01')],
      decoys: [makeReasonEntry('lf-d1', {
        endpoints: [{ method: 'POST', path: '/api/decoy', routeKey: 'decoy.post' }],
        triggerEndpoints: [{ method: 'POST', path: '/api/decoy', routeKey: 'decoy.post' }],
        oracle: { kinds: ['economic_invariant_violation'], routeKeys: ['decoy.post'] },
      })],
      chains: [],
    }
    const telemetry = { startedAtMs: 0, endedAtMs: 1000, totalCostUsd: 0.2 }

    const empty = gradeReasonRun({
      groundTruth: gt,
      findings: [],
      oracleEvents: [],
      requestLog: [],
      telemetry,
      mode: 'grey-box',
    })
    assert.equal(empty.precision, null)
    assert.equal(empty.rawPrecision, null)
    const aggEmpty = aggregateReasonScorecards([empty])
    assert.equal(aggEmpty.precision.mean, null)

    const withDecoyFp = gradeReasonRun({
      groundTruth: gt,
      findings: [
        {
          id: 'r-tp',
          title: 'Economic invariant',
          vulnClass: 'business_logic',
          endpoints: [{ method: 'POST', path: '/api/lf-01' }],
          status: 'runtime_confirmed',
          submittedAtMs: 100,
        },
        {
          id: 'r-fp',
          title: 'Decoy claim',
          vulnClass: 'business_logic',
          endpoints: [{ method: 'POST', path: '/api/decoy' }],
          status: 'runtime_confirmed',
          submittedAtMs: 120,
        },
      ],
      oracleEvents: [
        {
          seq: 1,
          ts: 50,
          kind: 'economic_invariant_violation',
          app: 'ledgerflow',
          routeKey: 'lf-01.post',
          method: 'POST',
          path: '/api/lf-01',
          actor: 'member_a',
          detail: {},
        },
      ],
      requestLog: [],
      telemetry,
      mode: 'grey-box',
    })
    assert.equal(withDecoyFp.precision, 0.5)
    assert.equal(withDecoyFp.rawPrecision, 0.5)
  })

  test('benchmark-recall counts unmatchedConfirmed as false positives', () => {
    const traces = [
      { id: 't1', isDecoy: false, surfaceDiscovered: true, hypothesisFormed: true, signalObserved: true, specSubmitted: true, confirmed: true },
      { id: 'd1', isDecoy: true, surfaceDiscovered: true, hypothesisFormed: true, signalObserved: false, specSubmitted: false, confirmed: false },
    ]
    const breakdown = countFalsePositives(traces, {
      includeBreakdown: true,
      unmatchedConfirmed: [{ path: '/api/unlisted', probeClass: 'sqli_boolean', confirmed: true }],
    })
    assert.equal(breakdown.decoyFalsePositives, 0)
    assert.equal(breakdown.unmatchedConfirmed, 1)
    assert.equal(breakdown.total, 1)
  })
})

// ---------------------------------------------------------------------------
// 3. Matrix aggregators, default per-run ledger, and promotion
// ---------------------------------------------------------------------------

describe('R2-05 #3: matrix aggregators, default per-run ledger writing & promotion', () => {
  test('realistic & agentic matrices fail closed via ScorecardReader, keep rawPrecision distinct, and write per-run JSONL by default', (t) => {
    const dir = makeTmpDir(t, 'r205-matrix-')
    const runsDir = join(dir, 'runs')
    const committedLedger = join(dir, 'ledger.jsonl')

    // Realistic matrix readScorecard rejects precision=1 on empty card
    const emptyCardPath = join(dir, 'empty.json')
    writeFileSync(emptyCardPath, JSON.stringify({
      app: 'acme-saas', seed: 1, targets: 20, confirmed: 0, precision: 1, decoyFalsePositives: 0, unmatchedFalsePositives: 0,
    }))
    const parsedEmpty = readRealisticMatrixScorecard(emptyCardPath)
    assert.ok(parsedEmpty)
    assert.equal(parsedEmpty.cellState, 'ok_no_claims')
    assert.equal(parsedEmpty.precision, null)
    assert.equal(parsedEmpty.rawPrecision, null)

    // Realistic matrix readScorecard treats inert/INVALID scorecard as failed (null)
    const inertCardPath = join(dir, 'inert.json')
    writeFileSync(inertCardPath, JSON.stringify({
      app: 'shopflow', seed: 1, targets: 20, confirmed: 0, precision: 1, status: 'INVALID',
    }))
    assert.equal(readRealisticMatrixScorecard(inertCardPath), null)

    // Realistic matrix summary + default per-run ledger writing + promotion
    const realisticCells: RealisticMatrixCellResult[] = [
      {
        app: 'acme-saas', seed: 1, ok: true, exitCode: 0, runtimeMs: 1000,
        confirmed: 2, targets: 10, recall: 0.2, precision: 1, rawPrecision: 0.5, strictPrecision: 0.5,
        cellState: 'ok_with_claims', decoyFp: 0, decoys: 2, unmatchedFp: 0, misclassifiedCount: 2, costUsd: 0.1,
      },
      {
        app: 'shopflow', seed: 1, ok: true, exitCode: 0, runtimeMs: 1000,
        confirmed: 0, targets: 10, recall: 0, precision: null, rawPrecision: null, strictPrecision: null,
        cellState: 'ok_no_claims', decoyFp: 0, decoys: 2, unmatchedFp: 0, costUsd: 0.05,
      },
      {
        app: 'opsportal', seed: 1, ok: false, exitCode: 1, runtimeMs: 500,
        confirmed: 0, targets: 10, recall: null, precision: null, rawPrecision: null, strictPrecision: null,
        cellState: 'failed_inert', decoyFp: 0, decoys: 0, unmatchedFp: 0, costUsd: 0, error: 'crashed',
      },
    ]
    const rTotals = summarizeRealisticMatrix(realisticCells)
    assert.equal(rTotals.status, 'INVALID')
    assert.equal(rTotals.recall, null)

    const rWritten = writeRealisticMatrixLedgerRows({
      results: realisticCells,
      suiteName: 'realistic-bench',
      split: 'dev',
      mode: 'grey-box',
      recordedAt: '2026-11-26T00:00:00.000Z',
      gitSha: TEST_GIT_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: HASH_B,
      runsDir,
      runId: 'realistic-test-run',
    })
    assert.ok(existsSync(rWritten.perRunPath), 'per-run JSONL must be written without --ledger')
    const perRunRows = readLedgerRows(rWritten.perRunPath)
    assert.equal(perRunRows.length, 3)
    assert.equal(perRunRows[0]!.headlinePrecision, 1)
    assert.equal(perRunRows[0]!.rawPrecision, 0.5, 'realistic matrix must NOT copy headline precision into rawPrecision')
    assert.equal(perRunRows[1]!.precision, null, 'ok_no_claims row must have null precision')
    assert.equal(perRunRows[1]!.cellState, 'ok_no_claims')
    assert.equal(perRunRows[2]!.status, 'INVALID')
    assert.equal(perRunRows[2]!.cellState, 'failed_inert')

    // Promote only VALID rows into committed ledger (idempotent on second call)
    const promo1 = promoteLedgerRows(rWritten.perRunPath, { targetLedgerPath: committedLedger })
    assert.equal(promo1.promoted, 2)
    assert.equal(promo1.skippedInvalid, 1)
    const promo2 = promoteLedgerRows(rWritten.perRunPath, { targetLedgerPath: committedLedger })
    assert.equal(promo2.promoted, 0)
    assert.equal(promo2.skippedDuplicate, 2)
    assert.equal(readLedgerRows(committedLedger).length, 2)

    // Agentic matrix collectCellResult: ok_no_claims vs failed_inert vs ok_with_claims
    const agentOutDir = join(dir, 'agentic')
    const cellOk: MatrixCell = { app: 'acme-saas', seed: 1, mode: 'grey-box', seedSet: 'dev', label: 'acme-saas-seed1-grey-box' }
    const cellInert: MatrixCell = { app: 'shopflow', seed: 1, mode: 'grey-box', seedSet: 'dev', label: 'shopflow-seed1-grey-box' }
    mkdirSync(join(agentOutDir, cellOk.label), { recursive: true })
    mkdirSync(join(agentOutDir, cellInert.label), { recursive: true })
    writeFileSync(join(agentOutDir, cellOk.label, `${cellOk.label}.json`), JSON.stringify({
      app: 'acme-saas', seed: 1, targets: 20, confirmed: 0, precision: 1, decoyFalsePositives: 0, unmatchedFalsePositives: 0, totalCostUsd: 0.1,
    }))
    writeFileSync(join(agentOutDir, cellOk.label, `${cellOk.label}.meta.json`), JSON.stringify({
      model: { mode: 'agentic' }, workerSessions: true, inert: false,
    }))
    writeFileSync(join(agentOutDir, cellInert.label, `${cellInert.label}.json`), JSON.stringify({
      app: 'shopflow', seed: 1, targets: 20, confirmed: 0, precision: 1, decoyFalsePositives: 0, unmatchedFalsePositives: 0, totalCostUsd: 0,
    }))
    writeFileSync(join(agentOutDir, cellInert.label, `${cellInert.label}.meta.json`), JSON.stringify({
      model: { mode: 'agentic' }, workerSessions: true, inert: true,
    }))

    const collectedEmpty = collectAgenticCellResult(cellOk, { outDir: agentOutDir, noLlm: false }, { exitCode: 0, runtimeMs: 1000, output: '' })
    assert.equal(collectedEmpty.ok, true)
    assert.equal(collectedEmpty.cellState, 'ok_no_claims')
    assert.equal(collectedEmpty.precision, null)
    assert.equal(collectedEmpty.rawPrecision, null)

    const collectedInert = collectAgenticCellResult(cellInert, { outDir: agentOutDir, noLlm: false }, { exitCode: 0, runtimeMs: 500, output: '' })
    assert.equal(collectedInert.ok, false)
    assert.equal(collectedInert.cellState, 'failed_inert')
    assert.equal(collectedInert.precision, null)

    const aTotals = summarizeAgenticMatrix([collectedEmpty, collectedInert])
    assert.equal(aTotals.status, 'INVALID')
    assert.equal(aTotals.precision, null)

    const aWritten = writeAgenticMatrixLedgerRows({
      results: [collectedEmpty, collectedInert],
      recordedAt: '2026-11-26T00:01:00.000Z',
      gitSha: TEST_GIT_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: HASH_B,
      certifying: false,
      runsDir,
      runId: 'agentic-test-run',
    })
    assert.ok(existsSync(aWritten.perRunPath))
    const aRows = readLedgerRows(aWritten.perRunPath)
    assert.equal(aRows[0]!.cellState, 'ok_no_claims')
    assert.equal(aRows[0]!.precision, null)
    assert.equal(aRows[1]!.status, 'INVALID')
    assert.equal(aRows[1]!.cellState, 'failed_inert')
  })
})

// ---------------------------------------------------------------------------
// 4. Certifiers (certify-phase1 & certify-v8)
// ---------------------------------------------------------------------------

describe('R2-05 #4: certify-phase1 & certify-v8 fail closed on empty/failed cells and expected reason targets', () => {
  test('certify-phase1 never defaults empty precision to 1, marks failed_inert INVALID, and enforces expected reason targets', (t) => {
    const dir = makeTmpDir(t, 'r205-phase1-')
    // Empty scorecard that falsely reports precision: 1
    const emptyCard: ScorecardLike = {
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      mode: 'grey-box',
      targets: 22,
      confirmed: 0,
      recall: 0,
      precision: 1,
      strictPrecision: 1,
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
      vulns: [],
    }
    const ev = buildRunEvidence(emptyCard, null, [])
    assert.equal(ev.cellState, 'ok_no_claims')
    assert.equal(ev.precision, null)
    assert.equal(ev.rawPrecision, null)
    assert.equal(ev.strictPrecision, null)

    // Ingesting a crashed/inert scorecard produces failed_inert
    writeFileSync(join(dir, 'summary.json'), JSON.stringify([
      { ...emptyCard, app: 'acme-saas', inert: true },
    ]))
    const ingested = ingestPhase1Dirs([dir], {})
    assert.equal(ingested.runs.length, 1)
    assert.equal(ingested.runs[0]!.cellState, 'failed_inert')
    assert.equal(ingested.runs[0]!.precision, null)

    // Evaluate certification with failed_inert realism cell -> INVALID + FAIL
    const certFailedRealism = evaluatePhase1Certification(ingested.runs, [], {
      mode: 'from-dir',
      checkMatrix: false,
      generatedAt: '2026-11-26T00:00:00.000Z',
      gitSha: TEST_GIT_SHA,
    })
    assert.equal(certFailedRealism.status, 'INVALID')
    assert.equal(certFailedRealism.failedCells, 1)
    assert.equal(certFailedRealism.verdict, 'FAIL')
    assert.ok(certFailedRealism.criteria.some(c => c.id === 'cell_validity' && c.status === 'FAIL'))
    assert.equal(certFailedRealism.precision.worst, null)

    // Reason-bench: 1 healthy app (14 targets, 7 confirmed) + 1 crashed/missing app ->
    // denominator MUST stay 28 (expected targets), NOT shrink to 14 (which would fake 50% recall!)
    const okRun: RealismRun = {
      id: 'ok-1',
      dir: '/syn',
      file: null,
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      mode: 'grey-box',
      llm: 'agentic',
      targets: 22,
      confirmed: 10,
      recall: 10 / 22,
      precision: 1,
      rawPrecision: 0.5,
      strictPrecision: 0.5,
      cellState: 'ok_with_claims',
      cellConcurrency: 1,
      workerConcurrency: 6,
      incompatibleClassCount: 0,
      misclassifiedFindingIds: ['m1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm10'],
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
      confirmedKeys: Array.from({ length: 10 }, (_, i) => `site:acme-saas|s${i}`),
      floor: { floorConfirmed: 8, floorLeadsConsumed: 4, floorLeadsEmitted: 4, floorLeadsQueued: 4, floorLeadsInvestigated: 4, source: 'synthetic' },
      provenance: { floor: 8, agentOnly: 2, chainFromFloor: 0 },
      provenanceComplete: true,
      provenanceSource: 'synthetic',
      advisories: 0,
      contractLeaks: 0,
      notes: [],
    }
    const partialReason: ReasonRun[] = [{
      source: 'reason-report.json',
      cells: [
        {
          app: 'ledgerflow', seed: 1, mode: 'grey-box', llm: 'agentic',
          targets: 14, confirmed: 7, recall: 0.5, precision: 1,
          cellState: 'ok_with_claims', decoyFalsePositives: 0, unmatchedFalsePositives: 0,
          sites: Array.from({ length: 14 }, (_, i) => ({ siteId: `lf-${i}`, confirmed: i < 7 })),
        },
        {
          app: 'forgecloud', seed: 1, mode: 'grey-box', llm: 'agentic',
          targets: 14, confirmed: 0, recall: null, precision: null,
          cellState: 'failed_inert', failed: true, decoyFalsePositives: 0, unmatchedFalsePositives: 0,
          sites: [],
        },
      ],
    }]
    const certReasonCrash = evaluatePhase1Certification([okRun], partialReason, {
      mode: 'from-dir',
      checkMatrix: false,
      generatedAt: '2026-11-26T00:00:00.000Z',
      gitSha: TEST_GIT_SHA,
    })
    assert.equal(certReasonCrash.status, 'INVALID')
    assert.equal(certReasonCrash.verdict, 'FAIL')
    assert.equal(certReasonCrash.reason.agentic.targets, 28, 'reason denominator must count expected targets, not union of surviving sites')
    assert.equal(certReasonCrash.reason.agentic.recall, null, 'crashed reason cell must suppress recall')
    assert.equal(certReasonCrash.reason.agentic.worstPrecision, null)

    // Phase-1 ledger writer writes per-run JSONL with preservation/floor/agentic fields and distinct rawPrecision
    const runsDir = join(dir, 'runs')
    const written = writePhase1CertifyLedgerRows({
      runs: [okRun],
      certificate: certReasonCrash,
      runsDir,
      runId: 'phase1-test',
    })
    assert.ok(existsSync(written.perRunPath))
    const rows = readLedgerRows(written.perRunPath)
    assert.equal(rows.length, 1)
    assert.equal(rows[0]!.headlinePrecision, 1)
    assert.equal(rows[0]!.rawPrecision, 0.5)
    assert.equal(rows[0]!.floorConfirmed, 8)
    assert.equal(rows[0]!.agenticConfirmed, 2)
  })

  test('certify-v8 eliminates OSS/reason precision-1 defaults, marks failed_inert INVALID, and writes per-run ledger rows', (t) => {
    const dir = makeTmpDir(t, 'r205-v8-')
    // Empty OSS run -> worstRunPrecision MUST be null (never 1!)
    const emptyOss = normalizeOssInputs({
      totalAnchors: 8,
      tpCount: 0,
      cleanControlCount: 2,
      cleanControlFpCount: 0,
      totalFpCount: 0,
    })
    assert.ok(emptyOss)
    assert.equal(emptyOss.worstRunPrecision, null, 'empty OSS run MUST NOT default worstRunPrecision to 1')

    // Inert agentic cell -> failed_inert -> status INVALID, precision null
    const inertV8: MultihopCellInput = {
      app: 'paygrid',
      seed: 1,
      mode: 'white-box',
      llm: 'agentic',
      chainsTotal: 4,
      chainsConfirmed: 0,
      precision: 1,
      inert: true,
      hardenedTwinsTotal: 3,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
    }
    const normInert = normalizeV8Cell(inertV8)
    assert.equal(normInert.cellState, 'failed_inert')
    assert.equal(normInert.status, 'INVALID')
    assert.equal(normInert.precision, null)
    assert.equal(normInert.rawPrecision, null)

    const report = evaluateV8Certification({
      gate: 'm2',
      cells: [inertV8],
      options: { gitSha: TEST_GIT_SHA, generatedAt: '2026-11-26T00:00:00.000Z' },
    })
    assert.equal(report.status, 'INVALID')
    assert.equal(report.verdict, 'FAIL')
    assert.equal(report.precision.worstRunPrecision, null)

    // Default per-run ledger write for certify-v8
    const written = writeV8CertifyLedgerRows({
      cells: [inertV8],
      report,
      runsDir: join(dir, 'runs'),
      runId: 'v8-test',
    })
    assert.ok(existsSync(written.perRunPath))
    const rows = readLedgerRows(written.perRunPath)
    assert.equal(rows.length, 1)
    assert.equal(rows[0]!.status, 'INVALID')
    assert.equal(rows[0]!.cellState, 'failed_inert')
    assert.equal(rows[0]!.precision, null)
    assert.equal(rows[0]!.rawPrecision, null)
  })
})

// ---------------------------------------------------------------------------
// 5. Held-out seed exposure tracking + separate smoke HMAC domain
// ---------------------------------------------------------------------------

describe('R2-05 #5: separate smoke HMAC domain & tracked held-out seed exposure', () => {
  test('smoke HMAC domain is disjoint from certify domain and certifying draws advance strictly past highest exposed index', (t) => {
    const dir = makeTmpDir(t, 'r205-seeds-')
    const exposedPath = join(dir, 'EXPOSED_SEEDS.json')

    const certifyFirst = realisticListSeeds('held-out', 3, TEST_SALT, { domain: 'certify' })
    const smokeFirst = realisticListSeeds('held-out', 3, TEST_SALT, { domain: 'smoke' })
    assert.equal(certifyFirst.length, 3)
    assert.equal(smokeFirst.length, 3)
    for (const s of smokeFirst) {
      assert.ok(!certifyFirst.includes(s), 'smoke domain seed must be disjoint from certify domain')
    }

    // Smoke CLI draws from smoke domain (disjoint from certify)
    const smokeArgs = parseAgenticMatrixArgs(['--held-out', '--smoke'], { KOVO_RB_HELDOUT_SALT: TEST_SALT })
    assert.equal(smokeArgs.seeds.length, 1)
    assert.equal(smokeArgs.seeds[0], smokeFirst[0])

    // First certifying draw starts at index 0 and records exposure (endIndex >= 2)
    const draw1 = drawUnburnedHeldoutSeedsWithMeta(3, TEST_SALT, undefined, REPO_ROOT, {
      domain: 'certify',
      exposedPath,
      recordExposure: true,
      certificateId: 'cert-1',
    })
    assert.equal(draw1.startIndex, 0)
    assert.ok(draw1.endIndex >= 2)
    const state1 = loadExposedSeedState(exposedPath, REPO_ROOT)
    assert.equal(state1.highestIndex, draw1.endIndex)

    // Second certifying draw MUST start strictly after draw1.endIndex with zero seed overlap
    const draw2 = drawUnburnedHeldoutSeedsWithMeta(3, TEST_SALT, undefined, REPO_ROOT, {
      domain: 'certify',
      exposedPath,
      recordExposure: true,
      certificateId: 'cert-2',
    })
    assert.ok(draw2.startIndex > draw1.endIndex, `expected startIndex (${draw2.startIndex}) > prior endIndex (${draw1.endIndex})`)
    for (const s of draw2.seeds) {
      assert.ok(!draw1.seeds.includes(s), `second draw seed ${s} must not repeat first draw`)
    }

    // Manual recordExposedHeldoutSeeds advances drawUnburnedHeldoutSeeds too
    recordExposedHeldoutSeeds(
      { certificateId: 'cert-3', domain: 'certify', startIndex: 20, endIndex: 22, seeds: [1_999_001, 1_999_002, 1_999_003] },
      exposedPath,
      REPO_ROOT,
    )
    const draw3 = drawUnburnedHeldoutSeeds(3, TEST_SALT, undefined, REPO_ROOT, { exposedPath })
    const expectedFrom23 = realisticListSeeds('held-out', 3, TEST_SALT, { startIndex: 23, domain: 'certify' })
    assert.deepEqual(draw3, expectedFrom23)
  })
})

// ---------------------------------------------------------------------------
// 6. regression-floor.sh lost-TP detection & package.json test:boundaries
// ---------------------------------------------------------------------------

describe('R2-05 #6: regression-floor.sh catches injected lost TP & test:boundaries honors quarantine', () => {
  test('regression-floor.sh reads outcome === confirmed (not t.confirmed) and catches an injected lost TP on JSON & ledger baselines', (t) => {
    const dir = makeTmpDir(t, 'r205-floor-')
    const baselineJson = join(dir, 'floor.json')
    const passingActual = join(dir, 'actual-pass.json')
    const regressedActual = join(dir, 'actual-lost-tp.json')
    const legacyFieldOnly = join(dir, 'actual-legacy-confirmed-field.json')
    const ledgerBaseline = join(dir, 'ledger.jsonl')

    writeFileSync(passingActual, JSON.stringify({
      gitSha: 'abc123456789',
      targetsTotal: 2,
      confirmedCount: 2,
      falsePositiveCount: 0,
      perTarget: [
        { id: 'xben-01', vulnClass: 'sqli', isDecoy: false, outcome: 'confirmed' },
        { id: 'xben-02', vulnClass: 'bola', isDecoy: false, outcome: 'confirmed' },
      ],
    }))

    // 1) Initialize baseline via --write-baseline -> MUST populate confirmedIds from outcome === 'confirmed'
    const writeRes = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', baselineJson,
        '--actual-json', passingActual,
        '--write-baseline',
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.equal(writeRes.status, 0, `write-baseline failed: ${writeRes.stderr}\n${writeRes.stdout}`)
    const savedBaseline = JSON.parse(readFileSync(baselineJson, 'utf8')) as {
      suites: { 'xben-25': { confirmedIds: string[] } }
    }
    assert.deepEqual(savedBaseline.suites['xben-25'].confirmedIds, ['xben-01', 'xben-02'])

    // 2) Same passing actual -> PASS
    const passRes = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', baselineJson,
        '--actual-json', passingActual,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.equal(passRes.status, 0, `expected PASS: ${passRes.stderr}\n${passRes.stdout}`)

    // 3) Injected lost TP (xben-02 flipped outcome: 'confirmed' -> 'missed') -> MUST FAIL!
    writeFileSync(regressedActual, JSON.stringify({
      gitSha: 'def123456789',
      targetsTotal: 2,
      confirmedCount: 2, // even if aggregate count were spoofed, per-target lostIds MUST catch xben-02!
      falsePositiveCount: 0,
      perTarget: [
        { id: 'xben-01', vulnClass: 'sqli', isDecoy: false, outcome: 'confirmed' },
        { id: 'xben-02', vulnClass: 'bola', isDecoy: false, outcome: 'missed' },
      ],
    }))
    const failRes = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', baselineJson,
        '--actual-json', regressedActual,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.notEqual(failRes.status, 0, 'injected lost TP MUST fail regression-floor.sh')
    assert.match(failRes.stderr, /lost confirmed TP\(s\): xben-02/)

    // 4) Legacy `confirmed: true` without `outcome: 'confirmed'` is NOT accepted as confirmed
    writeFileSync(legacyFieldOnly, JSON.stringify({
      gitSha: 'def123456789',
      targetsTotal: 2,
      confirmedCount: 2,
      falsePositiveCount: 0,
      perTarget: [
        { id: 'xben-01', vulnClass: 'sqli', isDecoy: false, confirmed: true, outcome: 'missed' },
        { id: 'xben-02', vulnClass: 'bola', isDecoy: false, outcome: 'confirmed' },
      ],
    }))
    const legacyFail = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', baselineJson,
        '--actual-json', legacyFieldOnly,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.notEqual(legacyFail.status, 0, 'legacy t.confirmed field must NOT satisfy outcome === confirmed')
    assert.match(legacyFail.stderr, /lost confirmed TP\(s\): xben-01/)

    // 5) JSONL ledger row baseline works identically
    const ledgerRow = buildLedgerRow({
      cell: ScorecardReader.read({
        app: 'xben-25', seed: 0, targets: 2, confirmed: 2, decoyFalsePositives: 0, unmatchedFalsePositives: 0,
      }),
      suite: 'xben-25',
      gitSha: TEST_GIT_SHA,
      dirty: false,
      benchmarkVersion: HASH_A,
      effectiveConfigHash: HASH_B,
      siteOutcomes: { 'xben-01': 'confirmed', 'xben-02': 'confirmed' },
    })
    appendPerRunLedgerRow(ledgerRow, { runId: 'ledger-baseline', runsDir: dir })
    writeFileSync(ledgerBaseline, `${JSON.stringify(ledgerRow)}\n`)
    const ledgerFail = spawnSync(
      'bash',
      [
        'scripts/regression-floor.sh',
        '--skip-golden', '--skip-boundaries', '--with-xben',
        '--baseline', ledgerBaseline,
        '--actual-json', regressedActual,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
    assert.notEqual(ledgerFail.status, 0, 'JSONL ledger baseline must also catch injected lost TP')
    assert.match(ledgerFail.stderr, /lost confirmed TP\(s\): xben-02/)

    // 6) Committed benchmarks/baselines/floor.json exists & package.json test:boundaries excludes quarantined provider-stream
    assert.ok(existsSync(join(REPO_ROOT, 'benchmarks/baselines/floor.json')))
    const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as { scripts: Record<string, string> }
    assert.ok(pkg.scripts['test:boundaries'])
    assert.equal(
      pkg.scripts['test:boundaries']!.includes('provider-stream.test.ts'),
      false,
      'test:boundaries must not include quarantined red tests/provider-stream.test.ts',
    )
    assert.equal(DEFAULT_LEDGER_PATH, 'benchmarks/results/ledger.jsonl')
  })
})
