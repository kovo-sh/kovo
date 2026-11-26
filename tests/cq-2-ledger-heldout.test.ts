/**
 * cq-2: Versioned results ledger, held-out seed hygiene, rawPrecision/validUnplanted,
 * and Gap #3 v8 multihop-saas / certify-v8 parity.
 */
import assert from 'node:assert/strict'
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import type { GroundTruth, GroundTruthEntry, SubmittedFinding } from '../benchmarks/realistic-bench/lib/types.ts'
import { gradeRun, validateValidUnplantedEvidence } from '../benchmarks/realistic-bench/grader/score.ts'
import type { Finding } from '../src/domain.ts'
import {
  BURNED_SEEDS_PATH,
  BurnedSeedError,
  CERTIFYING_MIN_HELDOUT_SEEDS,
  LEDGER_SCHEMA_VERSION,
  LedgerComparisonError,
  appendLedgerRow,
  assertNoBurnedSeeds,
  compareLedgerRows,
  computeBenchmarkVersion,
  computeEffectiveConfig,
  drawUnburnedHeldoutSeeds,
  loadBurnedSeeds,
  readLedgerRows,
  type LedgerRow,
} from '../scripts/bench-ledger.ts'
import {
  MixedLedgerVersionError,
  renderVerificationDocument,
  renderVerificationTable,
  validateTableRows,
} from '../scripts/render-verification-tables.ts'
import { parseMatrixArgs } from '../scripts/benchmark-agentic-matrix.ts'
import {
  CERTIFY_APPS,
  buildRunPlan,
  evaluateCertification,
  parseCli as parseCertifyPhase1Cli,
  type RealismRun,
} from '../scripts/certify-phase1.ts'
import { emptySnapshotMeta, withScorecardVersion } from '../scripts/benchmark-realistic.ts'
import {
  aggregateMultihopCells,
  buildMultihopReport,
  buildUnmatchedFindingsDetail,
  emptyDropReasons,
  parseMultihopArgs,
  type MultihopCellMeta,
} from '../scripts/benchmark-multihop.ts'
import {
  evaluateV8Certification,
  normalizeCell,
  type MultihopCellInput,
} from '../scripts/certify-v8.ts'

const TEST_SALT = '0123456789abcdef0123456789abcdef0123456789abcdef'

function makeTmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

function makeLedgerRow(overrides: Partial<LedgerRow> = {}): LedgerRow {
  return {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    recordedAt: '2026-11-26T00:00:00.000Z',
    suite: 'realistic-bench',
    gitSha: 'abc123456789',
    dirty: false,
    benchmarkVersion: 'a'.repeat(64),
    effectiveConfigHash: 'b'.repeat(64),
    app: 'acme-saas',
    split: 'dev',
    mode: 'grey-box',
    llm: 'deterministic-no-llm',
    seed: 1,
    repeat: 1,
    certifying: true,
    reportable: true,
    status: 'VALID',
    targets: 22,
    confirmed: 14,
    recall: 14 / 22,
    rawPrecision: 1,
    strictPrecision: 1,
    precision: 1,
    decoyFalsePositives: 0,
    unmatchedFalsePositives: 0,
    validUnplantedCount: 0,
    costUsd: 0.12,
    durationMs: 12_000,
    ...overrides,
  }
}

function makeGtEntry(overrides: Partial<GroundTruthEntry> & { siteId: string }): GroundTruthEntry {
  return {
    siteId: overrides.siteId,
    title: overrides.title ?? overrides.siteId,
    vulnClass: overrides.vulnClass ?? 'bola',
    cwe: overrides.cwe ?? 'CWE-639',
    severity: overrides.severity ?? 'high',
    endpoints: overrides.endpoints ?? [{ method: 'GET', path: '/api/invoices/:id', routeKey: 'invoice.get' }],
    triggerEndpoints: overrides.triggerEndpoints ?? overrides.endpoints ?? [{ method: 'GET', path: '/api/invoices/:id', routeKey: 'invoice.get' }],
    params: overrides.params ?? ['id'],
    oracle: overrides.oracle ?? { kinds: ['cross_tenant_read'], routeKeys: ['invoice.get'] },
    rootCause: overrides.rootCause ?? { file: 'billing/invoices.ts', symbol: 'getInvoice' },
  }
}

function makeMultihopMeta(overrides: Partial<MultihopCellMeta> = {}): MultihopCellMeta {
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
    loginPath: '/api/login',
    gitSha: 'deadbeef1234',
    model: { mode: 'agentic', profiles: [{ name: 'test-model', model: 'deepseek/test', protocol: 'responses' }] },
    verifierBackend: 'docker',
    workerSessions: true,
    workerSessionsDetail: 'ok',
    dataDirIsolated: true,
    dataDirSource: null,
    isolatedProfileNames: ['test-model'],
    dataDirKept: false,
    budgetUsd: 5,
    maxDurationMs: 1_800_000,
    startedAt: 1000,
    endedAt: 61_000,
    durationMs: 60_000,
    timedOut: false,
    terminalStatus: 'complete',
    terminalPhase: 'complete',
    runId: 'run-1',
    projectId: 'proj-1',
    chainsTotal: 4,
    chainsOracleObserved: 2,
    chainsCompositeConfirmed: 2,
    chainsConfirmed: 2,
    oracleOnlyCount: 0,
    receiptOnlyCount: 0,
    shortcutViolations: 0,
    modeBViolations: 0,
    recall: 0.5,
    precision: 1,
    hardenedTwinsTotal: 3,
    hardenedTwinDecoyFps: 0,
    unmatchedFalsePositives: 0,
    costUsd: 1.0,
    tpPerDollar: 2.0,
    tpPer10m: 20.0,
    hopFunnel: {
      totalChains: 4,
      H1: 4,
      H2: 3,
      H3: 2,
      H4Plus: 2,
      FinalOracle: 2,
      CompositeReceiptConfirmed: 2,
      dropReasons: emptyDropReasons(),
    },
    depthBreakdown: {
      hops3to4: { targets: 2, confirmed: 1, recall: 0.5 },
      hops5to6: { targets: 2, confirmed: 1, recall: 0.5 },
    },
    chains: [],
    hardenedTwins: [],
    assignmentsCompleted: 5,
    assignmentsTotal: 5,
    investigationCompleted: 5,
    facts: 10,
    findingsPersisted: 2,
    findingsSubmitted: 2,
    compositeReceiptsExtracted: 2,
    endpointsDiscovered: 12,
    requestCount: 100,
    oracleEventCount: 5,
    inert: false,
    snapshot: emptySnapshotMeta(),
    resumedFrom: null,
    snapshotSkippedMs: 0,
    notes: [],
    shutdown: { engineBusy: 0, appStopped: true, canaryStopped: true },
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// 1. computeBenchmarkVersion & computeEffectiveConfig
// ---------------------------------------------------------------------------

describe('cq-2 #1: computeBenchmarkVersion & computeEffectiveConfig', () => {
  test('computeBenchmarkVersion hashes realistic-bench and multihop-saas deterministically and changes on content edit', (t) => {
    const rb1 = computeBenchmarkVersion('realistic-bench')
    const rb2 = computeBenchmarkVersion('realistic-bench')
    assert.equal(rb1.benchmarkVersion, rb2.benchmarkVersion)
    assert.match(rb1.benchmarkVersion, /^[0-9a-f]{64}$/)
    assert.ok(rb1.filesHashed > 10, 'realistic-bench must hash apps/truth/grader/lib files')

    const mh1 = computeBenchmarkVersion('multihop-saas')
    const mh2 = computeBenchmarkVersion('multihop-saas')
    assert.equal(mh1.benchmarkVersion, mh2.benchmarkVersion)
    assert.match(mh1.benchmarkVersion, /^[0-9a-f]{64}$/)
    assert.notEqual(rb1.benchmarkVersion, mh1.benchmarkVersion)
    assert.ok(mh1.paths.includes('benchmarks/multihop-saas/run.ts'))

    // Modifying a file inside realistic-bench/grader changes the content hash.
    const tmpRoot = makeTmpDir('cq2-benchver-')
    t.after(() => rmSync(tmpRoot, { recursive: true, force: true }))
    cpSync('benchmarks/realistic-bench/grader', join(tmpRoot, 'benchmarks/realistic-bench/grader'), { recursive: true })
    cpSync('benchmarks/realistic-bench/lib', join(tmpRoot, 'benchmarks/realistic-bench/lib'), { recursive: true })
    const before = computeBenchmarkVersion('realistic-bench', tmpRoot)
    writeFileSync(join(tmpRoot, 'benchmarks/realistic-bench/grader/extra-marker.ts'), '// changed\n')
    const after = computeBenchmarkVersion('realistic-bench', tmpRoot)
    assert.notEqual(before.benchmarkVersion, after.benchmarkVersion)
  })

  test('computeEffectiveConfig fingerprints behavioral KOVO_* vars & flags while stripping all secrets', () => {
    const secretSalt = 'SUPER_SECRET_HELDOUT_SALT_NEVER_LEAK_999'
    const secretKey = 'sk-or-v1-supersecretkeyvalue12345'
    const a = computeEffectiveConfig({
      env: {
        KOVO_RECON_SIBLINGS: '1',
        KOVO_PROOF_RECEIPT: 'strict',
        KOVO_RB_HELDOUT_SALT: secretSalt,
        KOVO_OPENROUTER_API_KEY: secretKey,
        KOVO_AUTH_TOKEN: 'bearer-secret-xyz',
        KOVO_DATA_DIR: '/tmp/cell-1',
        UNRELATED_ENV: 'ignored',
      },
      deterministicOnly: false,
      environment: 'local-lab',
      approvalPolicy: 'auto_review',
      wordlistOn: false,
    })
    const b = computeEffectiveConfig({
      env: {
        KOVO_RECON_SIBLINGS: '1',
        KOVO_PROOF_RECEIPT: 'strict',
        KOVO_RB_HELDOUT_SALT: 'DIFFERENT_SALT_VALUE_1234567890',
        KOVO_DATA_DIR: '/tmp/cell-2',
      },
      deterministicOnly: false,
      environment: 'local-lab',
      approvalPolicy: 'auto_review',
      wordlistOn: false,
    })
    // Same behavioral config -> identical hash even when secrets & dataDir differ.
    assert.equal(a.effectiveConfigHash, b.effectiveConfigHash)
    const serialized = JSON.stringify(a)
    assert.ok(!serialized.includes(secretSalt), 'must never include salt')
    assert.ok(!serialized.includes(secretKey), 'must never include API key')
    assert.ok(!serialized.includes('bearer-secret-xyz'), 'must never include token')
    assert.ok(!serialized.includes('KOVO_DATA_DIR'), 'must exclude per-cell path')

    // Changing any behavior-changing switch MUST change effectiveConfigHash.
    const wordlistFlipped = computeEffectiveConfig({
      env: { KOVO_RECON_SIBLINGS: '1', KOVO_PROOF_RECEIPT: 'strict' },
      deterministicOnly: false,
      environment: 'local-lab',
      approvalPolicy: 'auto_review',
      wordlistOn: true,
    })
    assert.notEqual(a.effectiveConfigHash, wordlistFlipped.effectiveConfigHash)

    const detFlipped = computeEffectiveConfig({
      env: { KOVO_RECON_SIBLINGS: '1', KOVO_PROOF_RECEIPT: 'strict' },
      deterministicOnly: true,
      environment: 'local-lab',
      approvalPolicy: 'auto_review',
      wordlistOn: false,
    })
    assert.notEqual(a.effectiveConfigHash, detFlipped.effectiveConfigHash)

    const receiptFlipped = computeEffectiveConfig({
      env: { KOVO_RECON_SIBLINGS: '1' },
      deterministicOnly: false,
      environment: 'local-lab',
      approvalPolicy: 'auto_review',
      wordlistOn: false,
      proofReceiptMode: 'shadow',
    })
    assert.notEqual(a.effectiveConfigHash, receiptFlipped.effectiveConfigHash)

    const stamped = withScorecardVersion({ confirmed: 10 }, {
      benchmarkVersion: 'a'.repeat(64),
      effectiveConfigHash: a.effectiveConfigHash,
    })
    assert.equal(stamped.benchmarkVersion, 'a'.repeat(64))
    assert.equal(stamped.effectiveConfigHash, a.effectiveConfigHash)
  })
})

// ---------------------------------------------------------------------------
// 2. Ledger append, comparison refusal, and table renderer refusal
// ---------------------------------------------------------------------------

describe('cq-2 #2: ledger append, cross-version/config comparison refusal & table rendering', () => {
  test('appendLedgerRow / readLedgerRows round-trip and compareLedgerRows refuses mismatched version/config', (t) => {
    const dir = makeTmpDir('cq2-ledger-')
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const ledgerPath = join(dir, 'ledger.jsonl')

    const base = makeLedgerRow({ gitSha: 'sha-base', confirmed: 12, recall: 12 / 22, costUsd: 0.5 })
    const cand = makeLedgerRow({ gitSha: 'sha-cand', confirmed: 15, recall: 15 / 22, costUsd: 0.7 })
    appendLedgerRow(base, ledgerPath)
    appendLedgerRow(cand, ledgerPath)

    const rows = readLedgerRows(ledgerPath)
    assert.equal(rows.length, 2)

    const cmp = compareLedgerRows(rows[0]!, rows[1]!)
    assert.equal(cmp.confirmedDelta, 3)
    assert.ok(Math.abs((cmp.recallDelta ?? 0) - 3 / 22) < 1e-9)
    assert.ok(Math.abs(cmp.costDeltaUsd - 0.2) < 1e-9)

    // Mismatched benchmarkVersion -> refuse
    const diffVersion = makeLedgerRow({ benchmarkVersion: 'c'.repeat(64) })
    assert.throws(
      () => compareLedgerRows(base, diffVersion),
      (err: unknown) => err instanceof LedgerComparisonError && err.reason === 'benchmark_version_mismatch',
    )

    // Mismatched effectiveConfigHash -> refuse
    const diffConfig = makeLedgerRow({ effectiveConfigHash: 'd'.repeat(64) })
    assert.throws(
      () => compareLedgerRows(base, diffConfig),
      (err: unknown) => err instanceof LedgerComparisonError && err.reason === 'effective_config_mismatch',
    )

    // Mismatched suite -> refuse
    const diffSuite = makeLedgerRow({ suite: 'multihop-saas' })
    assert.throws(
      () => compareLedgerRows(base, diffSuite),
      (err: unknown) => err instanceof LedgerComparisonError && err.reason === 'suite_mismatch',
    )

    // INVALID row -> refuse
    const invalidRow = makeLedgerRow({ status: 'INVALID', recall: null })
    assert.throws(
      () => compareLedgerRows(base, invalidRow),
      (err: unknown) => err instanceof LedgerComparisonError && err.reason === 'invalid_row',
    )
  })

  test('render-verification-tables renders homogeneous tables and FAILS on mixed benchmarkVersion or effectiveConfigHash', () => {
    const r1 = makeLedgerRow({ app: 'acme-saas', confirmed: 14, targets: 22, recall: 14 / 22 })
    const r2 = makeLedgerRow({ app: 'shopflow', confirmed: 13, targets: 19, recall: 13 / 19 })
    const md = renderVerificationTable([r1, r2], { title: 'Dev floor' })
    assert.match(md, /benchmarkVersion=aaaaaaaaaaaa/)
    assert.match(md, /effectiveConfigHash=bbbbbbbbbbbb/)
    assert.match(md, /\*\*27\/41\*\*/)

    const doc = renderVerificationDocument([r1, r2])
    assert.match(doc, /realistic-bench · dev · grey-box · deterministic-no-llm/)

    // Mixing benchmarkVersion in one table MUST throw MixedLedgerVersionError.
    const mixedVer = makeLedgerRow({ app: 'opsportal', benchmarkVersion: 'f'.repeat(64) })
    assert.throws(
      () => validateTableRows([r1, mixedVer], { tableName: 'mixed-ver' }),
      (err: unknown) => err instanceof MixedLedgerVersionError && err.kind === 'benchmarkVersion',
    )
    assert.throws(
      () => renderVerificationDocument([r1, mixedVer]),
      MixedLedgerVersionError,
    )

    // Mixing effectiveConfigHash in one table MUST throw MixedLedgerVersionError.
    const mixedCfg = makeLedgerRow({ app: 'opsportal', effectiveConfigHash: 'e'.repeat(64) })
    assert.throws(
      () => renderVerificationTable([r1, mixedCfg], { title: 'mixed-cfg' }),
      (err: unknown) => err instanceof MixedLedgerVersionError && err.kind === 'effectiveConfigHash',
    )

    // Non-reportable row (e.g. wordlistOn=true) fails closed too.
    const nonReportable = makeLedgerRow({ reportable: false })
    assert.throws(
      () => validateTableRows([r1, nonReportable]),
      (err: unknown) => err instanceof MixedLedgerVersionError && err.kind === 'nonReportableRow',
    )
  })
})

// ---------------------------------------------------------------------------
// 3. BURNED_SEEDS & n >= 3 certifying held-out enforcement
// ---------------------------------------------------------------------------

describe('cq-2 #3: BURNED_SEEDS refusal of 1000042 & n >= 3 fresh salted held-out', () => {
  test('BURNED_SEEDS contains 1000042, assertNoBurnedSeeds refuses it, and drawUnburnedHeldoutSeeds draws >= 3 fresh seeds', () => {
    const burned = loadBurnedSeeds(BURNED_SEEDS_PATH)
    assert.ok(burned.has(1_000_042), '1000042 must be in BURNED_SEEDS')

    assert.throws(
      () => assertNoBurnedSeeds([1_000_042]),
      (err: unknown) => err instanceof BurnedSeedError && err.burnedSeeds.includes(1_000_042),
    )
    const dev2 = assertNoBurnedSeeds([1_000_042], { allowBurnedDev: true })
    assert.deepEqual(dev2.burned, [1_000_042])
    assert.equal(dev2.certifying, false)

    const fresh = drawUnburnedHeldoutSeeds(CERTIFYING_MIN_HELDOUT_SEEDS, TEST_SALT)
    assert.equal(fresh.length, 3)
    assert.equal(new Set(fresh).size, 3)
    for (const s of fresh) {
      assert.ok(s >= 1_000_000)
      assert.ok(!burned.has(s), `drawn seed ${s} must not be burned`)
    }
  })

  test('benchmark-agentic-matrix rejects 1000042 without --allow-burned-dev, draws 3 fresh seeds on --held-out, and marks --smoke non-certifying', () => {
    const env = { KOVO_RB_HELDOUT_SALT: TEST_SALT }

    // Burned seed rejected by default
    assert.throws(
      () => parseMatrixArgs(['--seeds', '1000042'], env),
      /BURNED_SEEDS/,
    )

    // Explicit --allow-burned-dev allowed for dev-2 debugging, stamped non-certifying
    const dev2 = parseMatrixArgs(['--seeds', '1000042', '--allow-burned-dev'], env)
    assert.deepEqual(dev2.seeds, [1_000_042])
    assert.equal(dev2.allowBurnedDev, true)
    assert.equal(dev2.certifying, false)
    assert.match(dev2.nonCertifyingReason ?? '', /burned-dev-seed/)

    // --certify refuses --allow-burned-dev and --smoke
    assert.throws(() => parseMatrixArgs(['--certify', '--allow-burned-dev'], env), /non-certifying/)
    assert.throws(() => parseMatrixArgs(['--certify', '--smoke'], env), /non-certifying/)

    // --held-out / --certify draws >= 3 fresh unburned salted seeds automatically
    const certArgs = parseMatrixArgs(['--held-out', '--certify'], env)
    assert.equal(certArgs.seeds.length, 3)
    assert.equal(certArgs.certifying, true)
    assert.equal(certArgs.nonCertifyingReason, null)
    assert.ok(!certArgs.seeds.includes(1_000_042))

    // --smoke keeps n=1 and is labeled non-certifying
    const smokeHeldout = parseMatrixArgs(['--held-out', '--smoke'], env)
    assert.equal(smokeHeldout.seeds.length, 1)
    assert.equal(smokeHeldout.certifying, false)
    assert.match(smokeHeldout.nonCertifyingReason ?? '', /smoke-tier/)
  })

  test('certify-phase1 rejects 1000042 in parseCli, buildRunPlan & evaluateCertification, and draws >= 3 fresh unburned seeds', () => {
    const env = { KOVO_RB_HELDOUT_SALT: TEST_SALT }

    // parseCli rejects burned seed 1000042
    assert.throws(
      () => parseCertifyPhase1Cli(['--run', '--heldout-seed', '1000042'], env),
      /BURNED_SEEDS/,
    )

    // parseCli with --allow-burned-dev permits 1000042 and stamps certifying=false
    const dev2Cli = parseCertifyPhase1Cli(['--run', '--heldout-seed', '1000042', '--allow-burned-dev'], env)
    assert.equal(dev2Cli.allowBurnedDev, true)
    assert.equal(dev2Cli.certifying, false)
    assert.deepEqual(dev2Cli.heldoutSeeds, [1_000_042])

    // parseCli --run draws >= 3 fresh unburned salted seeds by default
    const certCli = parseCertifyPhase1Cli(['--run'], env)
    assert.equal(certCli.certifying, true)
    assert.ok(certCli.heldoutSeeds && certCli.heldoutSeeds.length >= 3)
    assert.ok(!certCli.heldoutSeeds!.includes(1_000_042))

    // buildRunPlan rejects burned seed 1000042 without allowBurnedDev
    assert.throws(
      () => buildRunPlan({
        outDir: '/tmp/cq2-certify',
        apps: ['acme-saas'],
        devSeed: 1,
        heldoutSeed: 1_000_042,
        devRuns: 1,
        floorHeldoutRuns: 1,
        heldoutRuns: 1,
        dataDir: '/tmp/data',
        verifier: 'docker',
        budgetUsd: 5,
        maxDurationMs: 600_000,
        reasonRuns: 0,
        mode: 'grey-box',
      }),
      /BURNED_SEEDS/,
    )

    // buildRunPlan draws 3 fresh unburned seeds when heldoutSeeds omitted and distributes them across cells
    const plan = buildRunPlan({
      outDir: '/tmp/cq2-certify',
      apps: ['acme-saas'],
      devSeed: 1,
      heldOutSalt: TEST_SALT,
      devRuns: 1,
      floorHeldoutRuns: 3,
      heldoutRuns: 3,
      dataDir: '/tmp/data',
      verifier: 'docker',
      budgetUsd: 5,
      maxDurationMs: 600_000,
      reasonRuns: 0,
      mode: 'grey-box',
    })
    const unifiedHeldoutSeeds = new Set(plan.filter(c => c.kind === 'unified-heldout').map(c => c.seed))
    assert.equal(unifiedHeldoutSeeds.size, 3)
    assert.ok(!unifiedHeldoutSeeds.has(1_000_042))

    // evaluateCertification fails heldout_seed_hygiene on burned seed 1000042
    const burnedRun: RealismRun = {
      id: 'run-burned',
      dir: '/tmp/x',
      file: null,
      app: CERTIFY_APPS[0],
      seed: 1_000_042,
      seedSet: 'held-out',
      mode: 'grey-box',
      llm: 'agentic',
      targets: 22,
      confirmed: 12,
      recall: 12 / 22,
      precision: 1,
      cellConcurrency: 1,
      workerConcurrency: 6,
      strictPrecision: 1,
      incompatibleClassCount: 0,
      misclassifiedFindingIds: [],
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
      confirmedKeys: [],
      floor: { floorConfirmed: 10, floorLeadsConsumed: 5, floorLeadsEmitted: 5, floorLeadsQueued: 5, floorLeadsInvestigated: 5, source: 'synthetic' },
      provenance: { floor: 10, agentOnly: 2, chainFromFloor: 0 },
      provenanceComplete: true,
      provenanceSource: 'synthetic',
      advisories: 0,
      contractLeaks: 0,
      notes: [],
    }
    const cert = evaluateCertification([burnedRun], [], { mode: 'from-dir', checkMatrix: false })
    assert.equal(cert.certifying, false)
    assert.deepEqual(cert.burnedSeedsDetected, [1_000_042])
    const hygieneGate = cert.criteria.find(c => c.id === 'heldout_seed_hygiene')
    assert.ok(hygieneGate)
    assert.equal(hygieneGate.status, 'FAIL')
    assert.equal(cert.verdict, 'FAIL')
  })
})

// ---------------------------------------------------------------------------
// 4. rawPrecision headline vs replay-evidenced validUnplanted side column
// ---------------------------------------------------------------------------

describe('cq-2 #4: grader rawPrecision headline and replay-evidenced validUnplanted side column', () => {
  test('rawPrecision fails closed to null on empty findings and never lets validUnplanted inflate headline precision', () => {
    const vuln = makeGtEntry({ siteId: 'acme.invoice-bola', vulnClass: 'bola', cwe: 'CWE-639' })
    const gt: GroundTruth = {
      schemaVersion: 1,
      app: 'acme-saas',
      seed: 1,
      seedSet: 'dev',
      vulns: [vuln],
      decoys: [],
      chains: [],
    }
    const baseTelemetry = { startedAtMs: 0, endedAtMs: 1000, totalCostUsd: 0.1 }

    // Empty findings -> rawPrecision is null (never 1)
    const emptyCard = gradeRun({
      groundTruth: gt,
      findings: [],
      oracleEvents: [],
      requestLog: [],
      telemetry: baseTelemetry,
      mode: 'grey-box',
    })
    assert.equal(emptyCard.rawPrecision, null)
    assert.deepEqual(emptyCard.validUnplanted, [])
    assert.equal(emptyCard.validUnplantedCount, 0)

    // 1 TP + 1 unmatched finding: even when unmatched has serial-replay evidence and enters
    // validUnplanted side column, rawPrecision & strictPrecision MUST stay 0.5!
    const findings: SubmittedFinding[] = [
      {
        id: 'f-tp',
        title: 'Invoice BOLA',
        vulnClass: 'bola',
        cwe: 'CWE-639',
        endpoints: [{ method: 'GET', path: '/api/invoices/42' }],
        status: 'runtime_confirmed',
        submittedAtMs: 500,
      },
      {
        id: 'f-unplanted-verified',
        title: 'Unplanted real issue',
        vulnClass: 'xss_reflected',
        cwe: 'CWE-79',
        endpoints: [{ method: 'GET', path: '/api/unplanted' }],
        status: 'runtime_confirmed',
        submittedAtMs: 600,
      },
      {
        id: 'f-unplanted-no-replay',
        title: 'Unplanted claim lacking replay evidence',
        vulnClass: 'sqli',
        cwe: 'CWE-89',
        endpoints: [{ method: 'GET', path: '/api/other-unplanted' }],
        status: 'runtime_confirmed',
        submittedAtMs: 700,
      },
    ]

    assert.equal(validateValidUnplantedEvidence(null), false)
    assert.equal(validateValidUnplantedEvidence({ serialReplayVerified: false, receiptHash: '12345678', exchangeCount: 2 }), false)
    assert.equal(validateValidUnplantedEvidence({ serialReplayVerified: true, receiptHash: 'short', exchangeCount: 2 }), false)
    assert.equal(validateValidUnplantedEvidence({ serialReplayVerified: true, receiptHash: 'abcdef012345', exchangeCount: 2 }), true)

    const card = gradeRun(
      {
        groundTruth: gt,
        findings,
        oracleEvents: [
          {
            seq: 1,
            ts: 100,
            kind: 'cross_tenant_read',
            app: 'acme-saas',
            routeKey: 'invoice.get',
            method: 'GET',
            path: '/api/invoices/42',
            actor: 'persona_a',
            detail: {},
          },
        ],
        requestLog: [],
        telemetry: baseTelemetry,
        mode: 'grey-box',
      },
      {
        validUnplantedCandidates: [
          {
            findingId: 'f-unplanted-verified',
            reason: 'Confirmed by serial replay',
            replayEvidence: {
              serialReplayVerified: true,
              receiptHash: 'sha256-deadbeef1234',
              exchangeCount: 3,
            },
          },
          {
            findingId: 'f-unplanted-no-replay',
            reason: 'Hand-waved without replay',
            replayEvidence: null,
          },
        ],
      },
    )

    assert.equal(card.confirmed, 1)
    assert.equal(card.unmatchedFalsePositives, 2)
    assert.equal(card.rawPrecision, 1 / 3, 'rawPrecision MUST charge all unmatched findings even when in validUnplanted')
    assert.equal(card.strictPrecision, 1 / 3, 'strictPrecision MUST stay 1/3')
    assert.equal(card.validUnplantedCount, 1, 'only replay-evidenced candidate enters validUnplanted side column')
    assert.equal(card.validUnplanted[0]!.findingId, 'f-unplanted-verified')
    assert.equal(card.validUnplantedRejected.length, 1)
    assert.equal(card.validUnplantedRejected[0]!.findingId, 'f-unplanted-no-replay')
  })
})

// ---------------------------------------------------------------------------
// 5. Gap #3: v8 benchmark-multihop & certify-v8 parity
// ---------------------------------------------------------------------------

describe('cq-2 #5: Gap #3 v8 benchmark-multihop .meta.json FP detail & fail-closed status/precision', () => {
  test('buildUnmatchedFindingsDetail serializes structured FP summaries with ZERO secrets or raw bodies', () => {
    const secretVal = 'secret-session-cookie-value-999999'
    const findings: Finding[] = [
      {
        id: 'f-confirmed',
        origin: 'http://127.0.0.1:4100',
        title: 'Confirmed chain finding',
        status: 'confirmed',
        severity: 'high',
        cwe: 'CWE-639',
        findingKind: 'multi_step_chain',
        reason: 'confirmed',
        remediation: 'fix',
        evidenceIds: [],
        scopeRevision: 1,
      } as Finding,
      {
        id: 'f-unmatched-fp',
        origin: 'http://127.0.0.1:4100',
        title: `Spurious claim with ${secretVal}`,
        status: 'confirmed',
        severity: 'high',
        cwe: 'CWE-89',
        findingKind: 'single_step',
        verificationTier: 'runtime_confirmed',
        verificationClass: 'sqli',
        reason: 'raw body should never appear',
        remediation: 'fix',
        evidenceIds: [],
        scopeRevision: 1,
      } as unknown as Finding,
      {
        id: 'f-ruled-out',
        origin: 'http://127.0.0.1:4100',
        title: 'Dismissed',
        status: 'dismissed',
        severity: 'low',
        reason: 'dismissed',
        remediation: 'none',
        evidenceIds: [],
        scopeRevision: 1,
      } as Finding,
    ]
    const submitted: SubmittedFinding[] = [
      {
        id: 'f-unmatched-fp',
        title: 'Spurious claim',
        cwe: 'CWE-89',
        vulnClass: 'sqli',
        endpoints: [{ method: 'POST', path: `/api/v1/payments?token=${secretVal}` }],
        status: 'runtime_confirmed',
        submittedAtMs: 200,
      },
    ]

    const detail = buildUnmatchedFindingsDetail({
      findings,
      submitted,
      chains: [
        {
          chainId: 'chain-1',
          expectedHops: 3,
          maxHopReached: 3,
          oracleObserved: true,
          compositeReceiptConfirmed: true,
          twoSideConfirmed: true,
          matchedFindingIds: ['f-confirmed'],
        },
      ],
      secrets: [{ value: secretVal, placeholder: '[redacted-session]' }],
    })

    assert.equal(detail.length, 1, 'confirmed and ruled_out findings are excluded')
    const item = detail[0]!
    assert.equal(item.findingId, 'f-unmatched-fp')
    assert.equal(item.status, 'confirmed')
    assert.equal(item.findingKind, 'single_step')
    assert.equal(item.verificationTier, 'runtime_confirmed')
    assert.equal(item.verificationClass, 'sqli')
    assert.equal(item.cwe, 'CWE-89')
    assert.equal(item.route, 'POST /api/v1/payments', 'query string stripped from route summary')
    assert.ok(!JSON.stringify(item).includes(secretVal), 'must NEVER leak secret values')
    assert.ok(!('reason' in item), 'must NEVER include raw reason/body fields')
  })

  test('benchmark-multihop & certify-v8 enforce precision: null when tp+fp===0 and status: INVALID on failed cells', () => {
    // 1) parseMultihopArgs supports --ledger
    const parsed = parseMultihopArgs(['--no-llm', '--ledger', 'benchmarks/results/ledger.jsonl'], {})
    assert.equal(parsed.ledgerPath, 'benchmarks/results/ledger.jsonl')

    // 2) Empty cell (0 confirmed, 0 FPs) -> precision: null
    const emptyCell = makeMultihopMeta({
      llm: 'deterministic-no-llm',
      chainsConfirmed: 0,
      precision: null,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
    })
    const emptyAgg = aggregateMultihopCells([emptyCell])
    assert.equal(emptyAgg.status, 'VALID')
    assert.equal(emptyAgg.precision, null)
    assert.equal(emptyAgg.worstRunPrecision, null)
    assert.equal(emptyAgg.hardenedTwinGatePassed, true, '0 FPs passes hardened-twin gate even when precision is null')

    // 3) Failed cell -> status: INVALID, recall: null, hardenedTwinGatePassed: false
    const okCell = makeMultihopMeta({ chainsConfirmed: 2, chainsTotal: 4, precision: 1 })
    const invalidAgg = aggregateMultihopCells([okCell], 1)
    assert.equal(invalidAgg.status, 'INVALID')
    assert.equal(invalidAgg.failedCells, 1)
    assert.equal(invalidAgg.recall, null)
    assert.equal(invalidAgg.hardenedTwinGatePassed, false)

    const report = buildMultihopReport([okCell], [], 'deadbeef1234', { failedCells: 1 })
    assert.equal(report.status, 'INVALID')
    assert.equal(report.failedCells, 1)
    assert.equal(report.agentic.recall, null)

    // 4) certify-v8 normalizeCell returns precision: null when tp+fp===0 (even if input claimed precision: 1)
    const emptyV8Input: MultihopCellInput = {
      app: 'paygrid',
      seed: 1,
      mode: 'grey-box',
      llm: 'deterministic-no-llm',
      chainsTotal: 4,
      chainsConfirmed: 0,
      precision: 1,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
    }
    const normEmpty = normalizeCell(emptyV8Input)
    assert.equal(normEmpty.precision, null)
    assert.equal(normEmpty.status, 'VALID')

    // 5) certify-v8 evaluateV8Certification enforces status: INVALID and verdict: FAIL on failed cells
    const failedInput: MultihopCellInput = {
      app: 'paygrid',
      seed: 1,
      mode: 'white-box',
      llm: 'agentic',
      status: 'INVALID',
      failed: true,
      chainsTotal: 4,
      chainsConfirmed: 0,
      precision: null,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
    }
    const v8Cert = evaluateV8Certification({
      gate: 'm2',
      cells: [emptyV8Input, failedInput],
      options: { gitSha: 'deadbeef1234', generatedAt: '2026-11-26T00:00:00.000Z' },
    })
    assert.equal(v8Cert.status, 'INVALID')
    assert.equal(v8Cert.failedCells, 1)
    assert.equal(v8Cert.verdict, 'FAIL')
    assert.equal(v8Cert.precision.worstRunPrecision, null)
    assert.ok(v8Cert.failedChecks.some(c => c.id === 'cell_validity'))
    assert.match(v8Cert.benchmarkVersion, /^[0-9a-f]{64}$/)
  })
})
