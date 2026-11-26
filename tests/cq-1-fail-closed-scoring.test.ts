/**
 * cq-1: Fail-closed measurement & scoring invariants.
 *
 * Covers all five strictly-tightening invariants:
 *  1. `benchmark-realistic.ts`: `conventionalWordlist` default OFF, opt-in `--conventional-wordlist`,
 *     and scorecard `wordlistOn` / `reportable: !wordlistOn` stamping.
 *  2. `benchmark-realistic.ts` `translateFindings` + `benchmarks/realistic-bench/grader/match.ts`:
 *     `vulnClass` from verifying spec probe class, mutated-only params (no inventory widening),
 *     classless findings marked `unmatched_classless`, and `classCompatible` failing closed.
 *  3. `benchmark-realistic-matrix.ts` & `benchmark-agentic-matrix.ts`:
 *     `failed > 0` -> `status: 'INVALID'` + `recall: null` (no valid recall line printed);
 *     `tp + fp === 0` -> `precision: null` (never `1`).
 *  4. `smoke-agentic.ts`:
 *     explicit `--lift-baseline` or pinned `--floor-scorecard` required (else `UNMEASURED`),
 *     no `Math.max(0, ...)` clamp on `netNew`, `outcome === 'confirmed'` required for
 *     `preservedSiteIds`, seed/SHA deterministic `rotateSecondApp`, and `runLiftCellTwice`
 *     reporting both runs while gating on the worse run.
 *  5. `benchmark-score.ts` & `benchmark-core.ts`:
 *     anchored `classCompat` regexes with cross-family leaks removed (`csrf -> sqli/authz/xss`,
 *     `graphql -> authz`, substring leaks), and `unmatchedConfirmed` counted alongside decoy FPs.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import type { GroundTruth, GroundTruthEntry, SubmittedFinding } from '../benchmarks/realistic-bench/lib/types.ts'
import { classCompatible, matchFindingToEntries } from '../benchmarks/realistic-bench/grader/match.ts'
import { gradeRun } from '../benchmarks/realistic-bench/run.ts'
import type { Finding } from '../src/domain.ts'
import {
  buildTelemetry,
  parseRealisticArgs,
  probeClassToVulnClass,
  specMutatedParams,
  translateFindings,
  vulnClassFromSpec,
  withScorecardReportability,
} from '../scripts/benchmark-realistic.ts'
import {
  formatMatrixSummaryLine as formatRealisticMatrixLine,
  summarizeMatrix as summarizeRealisticMatrix,
  type CellResult as RealisticCellResult,
} from '../scripts/benchmark-realistic-matrix.ts'
import {
  collectCellResult,
  renderMatrixSummary,
  summarizeMatrix as summarizeAgenticMatrix,
  type MatrixCell,
  type MatrixCellResult,
} from '../scripts/benchmark-agentic-matrix.ts'
import {
  computeCellAccounting,
  deterministicRotationIndex,
  evaluateGates,
  parseSmokeArgs,
  preservedSiteIds,
  rotateSecondApp,
  runLiftCellTwice,
  selectWorseLiftRun,
  type CellMetrics,
  type GateInput,
} from '../scripts/smoke-agentic.ts'
import {
  compatibleClasses,
  findUnmatchedConfirmedOutcomes,
  scoreChallenge,
  type ScoredOutcome,
} from '../scripts/benchmark-score.ts'
import {
  countFalsePositiveBreakdown,
  countFalsePositives,
  formatBenchmarkMarkdown,
  type BenchmarkSuiteResult,
  type ManifestChallenge,
  type TargetTrace,
} from '../scripts/benchmark-core.ts'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> & { id: string }): Finding {
  return {
    origin: 'http://127.0.0.1:4000',
    title: 'Synthetic finding',
    status: 'confirmed',
    severity: 'high',
    reason: 'Confirmed by differential replay.',
    remediation: 'Validate input.',
    evidenceIds: [],
    scopeRevision: 1,
    findingKind: 'multi_step_chain',
    ...overrides,
  } as Finding
}

function makeGtEntry(overrides: Partial<GroundTruthEntry> & { siteId: string }): GroundTruthEntry {
  return {
    siteId: overrides.siteId,
    title: overrides.title ?? overrides.siteId,
    vulnClass: overrides.vulnClass ?? 'bola',
    cwe: overrides.cwe ?? 'CWE-639',
    severity: overrides.severity ?? 'high',
    endpoints: overrides.endpoints ?? [{ method: 'GET', path: '/api/invoices/:invoiceId', routeKey: 'getInvoice' }],
    triggerEndpoints: overrides.triggerEndpoints ?? overrides.endpoints ?? [{ method: 'GET', path: '/api/invoices/:invoiceId', routeKey: 'getInvoice' }],
    params: overrides.params ?? ['invoiceId'],
    oracle: overrides.oracle ?? { kinds: ['cross_tenant_read'], routeKeys: ['getInvoice'] },
    rootCause: overrides.rootCause ?? { file: 'billing/invoices.ts', symbol: 'getInvoice' },
  }
}

function makeAgenticCellResult(overrides: Partial<MatrixCellResult> = {}): MatrixCellResult {
  return {
    app: 'acme-saas',
    seed: 1,
    mode: 'grey-box',
    seedSet: 'dev',
    label: 'acme-saas-seed1-grey-box',
    ok: true,
    exitCode: 0,
    runtimeMs: 10_000,
    confirmed: 4,
    targets: 20,
    precision: 1,
    decoyFp: 0,
    decoys: 5,
    unmatchedFp: 0,
    costUsd: 0.5,
    wallMs: 10_000,
    surface: 30,
    facts: 20,
    assignments: {
      total: 4, completed: 4, failed: 0, canceled: 0,
      investigationTotal: 4, investigationCompleted: 4, investigationFailed: 0,
    },
    funnel: {
      targetVulns: 20, surfaceDiscovered: 18, hypothesisFormed: 10,
      signalObserved: 6, specSubmitted: 4, zeroLlmConfirmed: 4,
    },
    failureBuckets: {},
    inert: false,
    workerSessions: true,
    agenticExpected: true,
    modelMode: 'agentic',
    verifierBackend: 'docker',
    timedOut: false,
    terminalStatus: 'complete',
    jsonPath: '/tmp/a.json',
    metaPath: '/tmp/a.meta.json',
    lockError: false,
    configError: false,
    ...overrides,
  }
}

function makeSmokeCell(overrides: Partial<CellMetrics> = {}): CellMetrics {
  return {
    id: 'lift',
    kind: 'lift',
    app: 'acme-saas',
    source: 'snapshot',
    targets: 22,
    confirmed: 12,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    netNew: 2,
    floorConfirmed: 10,
    floorPreserved: 10,
    conversion: 12 / 22,
    costUsd: 0.35,
    p50AssignmentMs: 45_000,
    completedAssignments: 14,
    wallMs: 200_000,
    crashes: 0,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// 1. Wordlist default OFF + reportability stamp
// ---------------------------------------------------------------------------

describe('cq-1 #1: conventionalWordlist default OFF and scorecard reportability stamp', () => {
  test('conventionalWordlist defaults OFF and requires explicit --conventional-wordlist opt-in', () => {
    const def = parseRealisticArgs(['--app', 'acme-saas'], {})
    assert.equal(def.conventionalWordlist, false)

    const helpArgs = parseRealisticArgs(['--help'], {})
    assert.equal(helpArgs.conventionalWordlist, false)

    const explicitOff = parseRealisticArgs(['--app', 'acme-saas', '--no-conventional-wordlist'], {})
    assert.equal(explicitOff.conventionalWordlist, false)

    const optIn = parseRealisticArgs(['--app', 'acme-saas', '--conventional-wordlist'], {})
    assert.equal(optIn.conventionalWordlist, true)

    assert.throws(
      () => parseRealisticArgs(['--conventional-wordlist', '--no-conventional-wordlist'], {}),
      /not both/,
    )
  })

  test('withScorecardReportability stamps wordlistOn and reportable = !wordlistOn', () => {
    const reportableCard = withScorecardReportability({ app: 'acme-saas', confirmed: 10 }, false)
    assert.equal(reportableCard.wordlistOn, false)
    assert.equal(reportableCard.reportable, true)

    const inflatedCard = withScorecardReportability({ app: 'acme-saas', confirmed: 19 }, true)
    assert.equal(inflatedCard.wordlistOn, true)
    assert.equal(inflatedCard.reportable, false)
  })
})

// ---------------------------------------------------------------------------
// 2. translateFindings & grader/match.ts fail-closed invariants
// ---------------------------------------------------------------------------

describe('cq-1 #2: translateFindings vulnClass, mutated-only params, and classless fail-closed', () => {
  test('populates vulnClass from verifying spec probe class and prefers confirmed spec', () => {
    assert.equal(probeClassToVulnClass('sqli_boolean'), 'sqli')
    assert.equal(probeClassToVulnClass('authz_matrix'), 'bola')
    assert.equal(probeClassToVulnClass('ssrf_canary'), 'ssrf')
    assert.equal(probeClassToVulnClass('path_traversal_benign'), 'path_traversal')

    const out = translateFindings({
      findings: [makeFinding({ id: 'f1', cwe: undefined })],
      replaySpecs: [
        {
          id: 's-stale',
          findingId: 'f1',
          createdAt: 2000,
          spec: { kind: 'http_chain', probeClass: 'xss_context', steps: [] },
          lastVerificationDiff: { verdict: 'inconclusive' },
        },
        {
          id: 's-confirmed',
          findingId: 'f1',
          createdAt: 1000,
          spec: {
            kind: 'sql_boolean_diff',
            probeClass: 'sqli_boolean',
            method: 'GET',
            pathAndQuery: '/api/items/search?q=1',
            paramName: 'q',
            jsonBody: { q: '1', limit: 25, offset: 0 },
          },
          lastVerificationDiff: { verdict: 'confirmed' },
        },
      ],
      endpoints: [{ id: 'ep1', method: 'GET', pathTemplate: '/api/items/search' }],
      endpointParams: [
        { endpointId: 'ep1', name: 'q' },
        { endpointId: 'ep1', name: 'inventory_only_param_a' },
        { endpointId: 'ep1', name: 'inventory_only_param_b' },
      ],
    })
    assert.equal(out.length, 1)
    assert.equal(out[0]!.vulnClass, 'sqli')
    assert.deepEqual(out[0]!.params, ['q'], 'must include ONLY the verifying spec mutated param, never inventory or unmutated siblings')
    assert.equal(out[0]!.submittedAtMs, 1000)
  })

  test('step-based specs keep only params mutated between control and probe (no inventory widening)', () => {
    const chain = {
      kind: 'http_chain',
      recipe: { recipeId: 'persisted_mutation', args: { vulnClass: 'mass_assignment' } },
      steps: [
        {
          id: 'c1',
          role: 'control',
          request: {
            method: 'PATCH',
            pathAndQuery: '/api/users/1?version=1',
            jsonBody: { displayName: 'Alice', role: 'member' },
          },
        },
        {
          id: 'p1',
          role: 'probe',
          request: {
            method: 'PATCH',
            pathAndQuery: '/api/users/1?version=1',
            jsonBody: { displayName: 'Alice', role: 'admin' },
          },
        },
      ],
    }
    assert.equal(vulnClassFromSpec(chain), 'mass_assignment')
    assert.deepEqual(specMutatedParams(chain), ['role'])

    const out = translateFindings({
      findings: [makeFinding({ id: 'f-ma', cwe: 'CWE-915' })],
      replaySpecs: [{ id: 's1', findingId: 'f-ma', spec: chain, createdAt: 500 }],
      endpoints: [{ id: 'ep1', method: 'PATCH', pathTemplate: '/api/users/:id' }],
      endpointParams: [
        { endpointId: 'ep1', name: 'id' },
        { endpointId: 'ep1', name: 'displayName' },
        { endpointId: 'ep1', name: 'email' },
        { endpointId: 'ep1', name: 'role' },
      ],
    })
    assert.equal(out[0]!.vulnClass, 'mass_assignment')
    assert.deepEqual(out[0]!.params, ['role'])
  })

  test('findings with no CWE and no class are marked unmatched_classless and never wildcard-match', () => {
    const out = translateFindings({
      findings: [makeFinding({ id: 'f-classless', cwe: undefined, category: undefined })],
      replaySpecs: [
        {
          id: 's1',
          findingId: 'f-classless',
          createdAt: 100,
          spec: {
            kind: 'http_chain',
            steps: [
              { id: 'c1', role: 'control', request: { method: 'GET', pathAndQuery: '/api/invoices/1' } },
              { id: 'p1', role: 'probe', request: { method: 'GET', pathAndQuery: '/api/invoices/2' } },
            ],
          },
        },
      ],
    })
    assert.equal(out.length, 1)
    assert.equal(out[0]!.cwe, undefined)
    assert.equal(out[0]!.vulnClass, 'unmatched_classless')

    const entry = makeGtEntry({ siteId: 'acme.invoice-bola', vulnClass: 'bola', cwe: 'CWE-639' })
    // Both explicit unmatched_classless AND completely empty { } fail closed in match.ts.
    assert.equal(classCompatible({}, entry), false)
    assert.equal(classCompatible({ vulnClass: '', cwe: '' }, entry), false)
    assert.equal(classCompatible({ vulnClass: 'unmatched_classless' }, entry), false)
    assert.equal(matchFindingToEntries(out[0]!, [{ entry, isDecoy: false }]), null)

    const gt: GroundTruth = {
      schemaVersion: 1,
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      vulns: [entry],
      decoys: [],
      chains: [],
    }
    const card = gradeRun({
      groundTruth: gt,
      findings: out,
      oracleEvents: [{
        seq: 1, ts: 50, kind: 'cross_tenant_read', app: 'acme-saas',
        routeKey: 'getInvoice', method: 'GET', path: '/api/invoices/2', actor: 'persona_a', detail: {},
      }],
      requestLog: [],
      telemetry: buildTelemetry({ runStartedAt: 1, runEndedAt: 200, spentUsd: 0, budgetUsd: 5, budgetExhausted: false }),
      mode: 'grey-box',
    })
    assert.equal(card.confirmed, 0)
    assert.deepEqual(card.unmatchedFindingIds, ['f-classless'])
    assert.equal(card.unmatchedFalsePositives, 1)
  })
})

// ---------------------------------------------------------------------------
// 3. Matrix summaries fail closed on cell failure and empty precision
// ---------------------------------------------------------------------------

describe('cq-1 #3: realistic & agentic matrix fail-closed status, recall and precision', () => {
  test('realistic matrix emits status INVALID and recall null when any cell fails, without printing recall', () => {
    const cells: RealisticCellResult[] = [
      {
        app: 'acme-saas', seed: 1, ok: true, exitCode: 0, runtimeMs: 1000,
        confirmed: 10, targets: 20, recall: 0.5, precision: 1, decoyFp: 0, decoys: 4, unmatchedFp: 0, costUsd: 0.2,
      },
      {
        app: 'shopflow', seed: 1, ok: false, exitCode: 1, runtimeMs: 500,
        confirmed: 0, targets: 0, recall: null, precision: null, decoyFp: 0, decoys: 0, unmatchedFp: 0, costUsd: 0, error: 'boom',
      },
    ]
    const totals = summarizeRealisticMatrix(cells)
    assert.equal(totals.status, 'INVALID')
    assert.equal(totals.failed, 1)
    assert.equal(totals.recall, null)
    assert.equal(totals.precision, 1)

    const line = formatRealisticMatrixLine({
      suite: 'realistic', totals, concurrency: 2, wallSec: '1.5', pauseCount: 0, pauses: 'none', orphans: 0, outDir: '/tmp/out',
    })
    assert.match(line, /status=INVALID/)
    assert.doesNotMatch(line, /\brecall=/)
    assert.doesNotMatch(line, /\bconfirmed=/)
  })

  test('realistic & agentic matrices return precision null (never 1) when tp + fp === 0', () => {
    const emptyRealistic = summarizeRealisticMatrix([
      {
        app: 'acme-saas', seed: 1, ok: true, exitCode: 0, runtimeMs: 1000,
        confirmed: 0, targets: 20, recall: 0, precision: null, decoyFp: 0, decoys: 4, unmatchedFp: 0, costUsd: 0,
      },
    ])
    assert.equal(emptyRealistic.status, 'VALID')
    assert.equal(emptyRealistic.recall, 0)
    assert.equal(emptyRealistic.precision, null)

    const emptyAgentic = summarizeAgenticMatrix([
      makeAgenticCellResult({ confirmed: 0, decoyFp: 0, unmatchedFp: 0, precision: null }),
    ])
    assert.equal(emptyAgentic.status, 'VALID')
    assert.equal(emptyAgentic.precision, null)
    const emptySummary = renderMatrixSummary(emptyAgentic)
    assert.match(emptySummary, /precision=n\/a/)
    assert.doesNotMatch(emptySummary, /precision=100\.0%/)
  })

  test('agentic matrix emits status INVALID and recall null when failed > 0 and suppresses recall line', () => {
    const totals = summarizeAgenticMatrix([
      makeAgenticCellResult({ ok: true, confirmed: 5, targets: 20 }),
      makeAgenticCellResult({ app: 'shopflow', label: 'shopflow-seed1-grey-box', ok: false, confirmed: 0, targets: 0, precision: null }),
    ])
    assert.equal(totals.status, 'INVALID')
    assert.equal(totals.failed, 1)
    assert.equal(totals.recall, null)
    const summary = renderMatrixSummary(totals)
    assert.match(summary, /status=INVALID/)
    assert.match(summary, /INVALID/)
    assert.doesNotMatch(summary, /\brecall=/)
    assert.doesNotMatch(summary, /confirmed=5\/20/)

    // collectCellResult also returns precision null on missing/failed cell
    const dummyCell: MatrixCell = { app: 'acme-saas', seed: 1, mode: 'grey-box', seedSet: 'dev', label: 'acme-saas-seed1-grey-box' }
    const collected = collectCellResult(dummyCell, { outDir: '/tmp/nonexistent-cq1-dir', noLlm: true }, { exitCode: 1, runtimeMs: 10, output: 'error: failed' })
    assert.equal(collected.ok, false)
    assert.equal(collected.precision, null)
  })
})

// ---------------------------------------------------------------------------
// 4. smoke-agentic.ts fail-closed invariants
// ---------------------------------------------------------------------------

describe('cq-1 #4: smoke-agentic UNMEASURED baseline, no clamp, confirmed preserved, seed rotation, worst-of-two rerun', () => {
  test('liftBaseline defaults to null and missing baseline reports UNMEASURED (never PASS)', () => {
    const parsed = parseSmokeArgs([])
    assert.equal(parsed.liftBaseline, null)

    const input: GateInput = {
      cells: [makeSmokeCell({ netNew: 0 })],
      liftBaseline: null,
      baselineConversion: 0.5,
      hasPinnedBaseline: false,
      trapConfirmed: 0,
      rerunExecuted: false,
      perCellBudgetUsd: 0.8,
    }
    const netNewGate = evaluateGates(input).find(g => g.id === 'paired-net-new')!
    assert.equal(netNewGate.pass, false)
    assert.equal(netNewGate.status, 'UNMEASURED')
    assert.match(netNewGate.observed, /UNMEASURED/)

    // Explicit --lift-baseline OR pinned --floor-scorecard enables strict evaluation
    const withPinned = evaluateGates({ ...input, hasPinnedBaseline: true }).find(g => g.id === 'paired-net-new')!
    assert.equal(withPinned.pass, true)
    assert.equal(withPinned.status, 'PASS')

    const withExplicit = evaluateGates({ ...input, liftBaseline: 3 }).find(g => g.id === 'paired-net-new')!
    assert.equal(withExplicit.pass, false)
    assert.equal(withExplicit.status, 'FAIL')
  })

  test('computeCellAccounting removes Math.max(0, ...) clamp and exposes regressions + null when baseline missing', () => {
    const regressed = computeCellAccounting({
      kind: 'lift',
      source: 'cold',
      card: { targets: 22, confirmed: 8 },
      baseline: { targets: 22, confirmed: 12 },
      liftBaseline: null,
    })
    assert.equal(regressed.netNew, -4, 'regression below floor must stay negative, never clamped to 0')
    assert.equal(regressed.floorConfirmed, 12)

    const noBaseline = computeCellAccounting({
      kind: 'lift',
      source: 'cold',
      card: { targets: 22, confirmed: 10 },
      baseline: null,
      liftBaseline: null,
    })
    assert.equal(noBaseline.floorConfirmed, null)
    assert.equal(noBaseline.netNew, null)
  })

  test('preservedSiteIds requires outcome === confirmed (unconfirmed matchedFindingIds never count)', () => {
    const card = {
      vulns: [
        { siteId: 'site-confirmed', outcome: 'confirmed', matchedFindingIds: ['f1'] },
        { siteId: 'site-unconfirmed', outcome: 'claimed_without_impact', matchedFindingIds: ['f2'] },
        { siteId: 'site-static', outcome: 'static_only', matchedFindingIds: ['f3'] },
        { siteId: 'site-missed', outcome: 'missed', matchedFindingIds: [] },
      ],
    }
    assert.equal(
      preservedSiteIds(card, ['site-confirmed', 'site-unconfirmed', 'site-static', 'site-missed']),
      1,
    )
  })

  test('rotateSecondApp derives deterministically from seed/SHA instead of day-of-year', () => {
    assert.equal(rotateSecondApp({ seed: 1 }), rotateSecondApp({ seed: 1 }))
    assert.notEqual(rotateSecondApp({ seed: 1 }), rotateSecondApp({ seed: 2 }))

    const shaA = rotateSecondApp({ seed: 1, sha: 'abcdef123456' })
    const shaA2 = rotateSecondApp({ seed: 1, sha: 'abcdef123456' })
    assert.equal(shaA, shaA2)
    assert.equal(
      deterministicRotationIndex(42, 'deadbeef0001'),
      deterministicRotationIndex(42, 'deadbeef0001'),
    )
    assert.notEqual(
      deterministicRotationIndex(42, 'deadbeef0001'),
      deterministicRotationIndex(42, 'deadbeef0002'),
    )
  })

  test('runLiftCellTwice reports BOTH runs and gates on the worse run', async () => {
    const run1 = makeSmokeCell({ netNew: 1, conversion: 0.6, confirmed: 13, costUsd: 0.3 })
    const run2 = makeSmokeCell({ netNew: 3, conversion: 0.7, confirmed: 15, costUsd: 0.4 })
    assert.equal(selectWorseLiftRun(run1, run2), run1)
    assert.equal(selectWorseLiftRun(run2, run1), run1)

    // Precision/FP failure is strictly worse than lower netNew
    const fpRun = makeSmokeCell({ netNew: 5, precision: 0.8, unmatchedFalsePositives: 1 })
    assert.equal(selectWorseLiftRun(run1, fpRun), fpRun)

    const calls = [run1, run2]
    let idx = 0
    const opts = parseSmokeArgs(['--lift-baseline', '2', '--rerun-on-minus-one', '--out-dir', '/tmp/cq1-smoke'])
    const outcome = await runLiftCellTwice(
      { id: 'lift', kind: 'lift', app: 'acme-saas', source: 'snapshot', outDir: '/tmp/cq1-smoke/lift', command: 'node', args: [] },
      opts,
      async () => calls[idx++]!,
      { card: { targets: 22, confirmed: 11 }, conversion: 0.5, source: 'floor-scorecard', path: '/tmp/floor.json' },
    )
    assert.equal(outcome.rerun, true)
    assert.equal(outcome.runs.length, 2, 'must report both runs')
    assert.equal(outcome.runs[0], run1)
    assert.equal(outcome.runs[1], run2)
    assert.equal(outcome.cell, run1, 'must gate on the worse run, never cherry-pick the better rerun')

    // And if run2 is worse (e.g. drops to netNew 0), run2 is selected and fails the gate!
    const worseRun2 = makeSmokeCell({ netNew: 0, conversion: 0.4, confirmed: 9 })
    const calls2 = [run1, worseRun2]
    let idx2 = 0
    const outcome2 = await runLiftCellTwice(
      { id: 'lift', kind: 'lift', app: 'acme-saas', source: 'snapshot', outDir: '/tmp/cq1-smoke/lift2', command: 'node', args: [] },
      opts,
      async () => calls2[idx2++]!,
      { card: { targets: 22, confirmed: 11 }, conversion: 0.5, source: 'floor-scorecard', path: '/tmp/floor.json' },
    )
    assert.equal(outcome2.cell, worseRun2)
    const gates = evaluateGates({
      cells: [run1],
      liftRuns: outcome2.runs,
      liftBaseline: 2,
      baselineConversion: 0.5,
      trapConfirmed: 0,
      rerunExecuted: true,
      perCellBudgetUsd: 0.8,
    })
    assert.equal(gates.find(g => g.id === 'paired-net-new')!.pass, false)
  })
})

// ---------------------------------------------------------------------------
// 5. Anchored legacy classCompat & unmatchedConfirmed FP accounting
// ---------------------------------------------------------------------------

describe('cq-1 #5: anchored classCompat and unmatchedConfirmed FP accounting', () => {
  test('classCompat removes cross-family leaks (csrf -> sqli/authz/xss, graphql -> authz) and substring false matches', () => {
    // Cross-family leaks removed
    assert.deepEqual(compatibleClasses('csrf'), ['csrf'])
    assert.ok(!compatibleClasses('csrf')!.includes('sqli_boolean'))
    assert.ok(!compatibleClasses('csrf')!.includes('authz_matrix'))
    assert.ok(!compatibleClasses('csrf')!.includes('xss_context'))

    assert.deepEqual(compatibleClasses('graphql'), ['graphql_audit'])
    assert.ok(!compatibleClasses('graphql')!.includes('authz_matrix'))
    assert.ok(!compatibleClasses('graphql')!.includes('sqli_boolean'))

    // Anchoring blocks substring collisions (`auth` in `authz`, `rce` in `resource`, `dom` in `random`, `race` in `trace`, `time` in `timeout`)
    assert.deepEqual(compatibleClasses('server_action_authz'), ['authz_matrix'])
    assert.equal(compatibleClasses('resource'), null)
    assert.equal(compatibleClasses('random'), null)
    assert.equal(compatibleClasses('trace'), null)
    assert.equal(compatibleClasses('timeout'), null)

    // Legitimate manifest classes remain mapped accurately
    assert.deepEqual(compatibleClasses('sqli_form_csrf'), ['sqli_boolean', 'sqli_time_diff'])
    assert.deepEqual(compatibleClasses('graphql_bola'), ['authz_matrix'])
    assert.deepEqual(compatibleClasses('graphql_sqli'), ['sqli_boolean', 'sqli_time_diff'])
    assert.deepEqual(compatibleClasses('auth_oauth'), ['auth_protocol_audit'])
    assert.deepEqual(compatibleClasses('jwt_alg_none'), ['auth_protocol_audit'])
    assert.deepEqual(compatibleClasses('decoy_sqli'), ['sqli_boolean', 'sqli_time_diff'])

    // scoreChallenge rejects sqli_boolean confirming a csrf manifest entry
    const csrfChallenge: ManifestChallenge = { id: 'c-csrf', vulnClass: 'csrf', endpoint: '/api/transfer' }
    const sqliOutcome: ScoredOutcome = {
      path: '/api/transfer', probeClass: 'sqli_boolean', signal: true, specSubmitted: true, confirmed: true,
      csrfRejected: false, contextReset: false, tierBlocked: false, jqError: false, spaCatchall: false, skippedForBudget: false,
    }
    const trace = scoreChallenge(csrfChallenge, {
      discoveredPaths: ['/api/transfer'],
      outcomes: [sqliOutcome],
      encodingSkipPaths: [],
      budgetSkippedPaths: [],
    })
    assert.equal(trace.confirmed, false)
    assert.equal(trace.hypothesisFormed, false)
  })

  test('findUnmatchedConfirmedOutcomes + countFalsePositives report unmatchedConfirmed alongside decoy FPs', () => {
    const challenges: ManifestChallenge[] = [
      { id: 'v1', vulnClass: 'sqli', endpoint: '/api/search', isDecoy: false },
      { id: 'd1', vulnClass: 'sqli', endpoint: '/api/safe', isDecoy: true },
    ]
    const baseFlags = {
      signal: true, specSubmitted: true, confirmed: true,
      csrfRejected: false, contextReset: false, tierBlocked: false, jqError: false, spaCatchall: false, skippedForBudget: false,
    }
    const outcomes: ScoredOutcome[] = [
      { path: '/api/search', probeClass: 'sqli_boolean', ...baseFlags },
      { path: '/api/safe', probeClass: 'sqli_boolean', ...baseFlags },
      // Off-manifest confirmed claim on an unplanted route
      { path: '/api/unlisted', probeClass: 'xss_context', ...baseFlags },
      // Wrong-class confirmed claim on a manifest route
      { path: '/api/search', probeClass: 'authz_matrix', ...baseFlags },
    ]
    const unmatched = findUnmatchedConfirmedOutcomes(challenges, { outcomes })
    assert.equal(unmatched.length, 2)
    assert.deepEqual(unmatched.map(o => `${o.path}:${o.probeClass}`), [
      '/api/unlisted:xss_context',
      '/api/search:authz_matrix',
    ])

    const traces: TargetTrace[] = [
      { id: 'v1', isDecoy: false, surfaceDiscovered: true, hypothesisFormed: true, signalObserved: true, specSubmitted: true, confirmed: true },
      { id: 'd1', isDecoy: true, surfaceDiscovered: true, hypothesisFormed: true, signalObserved: true, specSubmitted: true, confirmed: true },
      { id: 'u1', isDecoy: false, unmatchedConfirmed: true, surfaceDiscovered: true, hypothesisFormed: true, signalObserved: true, specSubmitted: true, confirmed: true },
    ]
    assert.equal(countFalsePositives(traces), 2)
    assert.equal(countFalsePositives(traces, unmatched), 4)
    const breakdown = countFalsePositives(traces, { includeBreakdown: true, unmatchedConfirmed: unmatched })
    assert.deepEqual(breakdown, { decoyFalsePositives: 1, unmatchedConfirmed: 3, total: 4 })
    assert.deepEqual(countFalsePositiveBreakdown(traces, unmatched), breakdown)

    const md = formatBenchmarkMarkdown({
      suite: 'xben-25',
      profileMode: 'v4-full',
      dryRun: false,
      simulated: false,
      gitSha: 'abc1234',
      baselineSha: null,
      targetsTotal: 1,
      decoysTotal: 1,
      confirmedCount: 1,
      falsePositiveCount: breakdown.total,
      unmatchedConfirmedCount: breakdown.unmatchedConfirmed,
      funnelCounts: { targetVulns: 1, surfaceDiscovered: 1, hypothesisFormed: 1, signalObserved: 1, specSubmitted: 1, zeroLlmConfirmed: 1 },
      failureTaxonomy: {
        surface_miss: 0, hypothesis_miss: 0, form_encoding_missing: 0, csrf_blocked: 0,
        context_reset: 0, tier_blocked: 0, trigger_miss: 0, jq_assertion_bug: 0,
        spa_catchall_fp: 0, replay_spec_miss: 0, budget_exhausted: 0,
      },
      recall: 1,
      precision: 0.2,
      totalCostUsd: 0,
      costPerVuln: 0,
      durationMs: 100,
      verifierBackend: 'local-jq',
      runId: null,
      perTarget: [],
      diff: null,
      recallDelta: null,
      precisionDelta: null,
      confirmedDelta: null,
      fpDelta: null,
      costPerVulnDelta: null,
      bucketDeltas: {
        surface_miss: 0, hypothesis_miss: 0, form_encoding_missing: 0, csrf_blocked: 0,
        context_reset: 0, tier_blocked: 0, trigger_miss: 0, jq_assertion_bug: 0,
        spa_catchall_fp: 0, replay_spec_miss: 0, budget_exhausted: 0,
      },
      topBucketDrops: [],
      notes: [],
    } satisfies BenchmarkSuiteResult)
    assert.match(md, /unmatchedConfirmed: 3/)
  })
})
