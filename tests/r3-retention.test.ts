/**
 * R3-H-16 — StorageMaintenanceController / ArtifactTTL evidence-retention safety tests:
 *  1. Default `AppRuntime` and `StorageMaintenanceController` ship with exchange & artifact TTL OFF
 *     unless the operator explicitly configures `ttlPolicy` or `KOVO_EXCHANGE_TTL_DAYS` /
 *     `KOVO_ARTIFACT_TTL_DAYS`.
 *  2. With explicit retention configured and a terminal run aged past the TTL, a full maintenance
 *     cycle leaves `exportRunReceiptBundle()` byte-for-byte identical (zero lost exchanges, FTS
 *     rows, body blobs, or evidence artifacts cited by findings, single-hop/composite receipts,
 *     retests, facts, or surfaced canaries) while pruning unreferenced aged exchanges & artifacts.
 *  3. All non-terminal runs (`running`, `waiting`, `paused`, `budget_paused`, legacy `queued`, and
 *     in-memory active `RunContext` runs) are completely skipped by TTL pruning and orphan sweeping.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { newProject, newRun } from '../src/domain.ts'
import type { InlineVerifyFeedback } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import { isTerminalRunStatus, purgeExpiredArtifacts } from '../src/server/artifact-ttl.ts'
import { exportRunReceiptBundle, verifyProofReceiptBundle } from '../src/server/receipt-export.ts'
import {
  DEFAULT_MAINTENANCE_TTL_POLICY,
  resolveStorageMaintenancePolicy,
  StorageMaintenanceController,
} from '../src/server/storage-maintenance.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN = 'https://retention.example.test'
const HOUR_MS = 60 * 60_000
const DAY_MS = 24 * HOUR_MS

function makeTempDir(t: test.TestContext, prefix = 'kovo-r3-ret-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeTempStore(t: test.TestContext, prefix = 'kovo-r3-ret-'): { dir: string; store: Store } {
  const dir = makeTempDir(t, prefix)
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
  })
  return { dir, store }
}

function setupApprovedRun(store: Store, name = 'Retention App', origin = ORIGIN) {
  const proj = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [origin],
  }))
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: `Assess ${name}`,
    capabilityTier: 2,
  }))
  store.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
  const discovered = store.run(createdRun.id)
  store.command({
    requestId: randomUUID(),
    runId: createdRun.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 2,
  })
  const run = store.run(createdRun.id)
  const asset = run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'Retention Worker', 'Verify retention invariants')
  return { projectId: proj.id, runId: run.id, run, asset, worker }
}

function sampleSpec(title: string, pathAndQuery: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Authorization boundary differential',
    impact: 'Cross-account data read',
    remediation: 'Enforce ownership checks',
    recheckInstructions: 'Replay owner control and peer probe',
    assertionsJq: '.status == 200',
    spaCatchallControl: false,
    steps: [{
      id: 'probe-1',
      role: 'probe',
      description: 'Read target object',
      request: {
        origin,
        method: 'GET',
        pathAndQuery,
        followRedirects: false,
      },
    }],
  } as unknown as DeclarativeReplaySpec
}

function confirmedFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    controlPassed: true,
    assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
    stepStatuses: [{ id: 'probe-1', role: 'probe', status: 200, bodyLen: 32 }],
    retriesRemaining: 0,
  }
}

function recordEx(
  store: Store,
  runId: string,
  assignmentId: string,
  scopeRevision: number,
  pathAndQuery: string,
  body: string,
) {
  return store.recordExchange({
    runId,
    assignmentId,
    scopeRevision,
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: { accept: 'application/json' },
    respHeaders: { 'content-type': 'application/json' },
    body,
    durationMs: 5,
  })
}

// ============================================================================
// 1. Default-OFF TTL policy on AppRuntime and StorageMaintenanceController
// ============================================================================

test('R3-H-16: AppRuntime and StorageMaintenanceController disable automatic exchange/artifact TTL by default unless explicitly configured', async t => {
  assert.equal(DEFAULT_MAINTENANCE_TTL_POLICY.exchangeTtlMs, 0)
  assert.equal(DEFAULT_MAINTENANCE_TTL_POLICY.artifactTtlMs, 0)
  assert.equal(DEFAULT_MAINTENANCE_TTL_POLICY.tempFileTtlMs, 0)
  assert.equal(DEFAULT_MAINTENANCE_TTL_POLICY.preserveConfirmedEvidence, true)
  assert.equal(DEFAULT_MAINTENANCE_TTL_POLICY.skipActiveRuns, true)

  // Policy resolution: empty/invalid/zero env stays OFF; positive days env enables only configured TTLs; explicit false always wins.
  assert.equal(resolveStorageMaintenancePolicy(undefined, {}), false)
  assert.equal(resolveStorageMaintenancePolicy(undefined, { KOVO_EXCHANGE_TTL_DAYS: '0', KOVO_ARTIFACT_TTL_DAYS: '-7' }), false)
  assert.equal(resolveStorageMaintenancePolicy(undefined, { KOVO_EXCHANGE_TTL_DAYS: 'off', KOVO_ARTIFACT_TTL_DAYS: 'NaN' }), false)
  assert.equal(resolveStorageMaintenancePolicy({}, {}), false)
  assert.equal(resolveStorageMaintenancePolicy(false, { KOVO_EXCHANGE_TTL_DAYS: '7', KOVO_ARTIFACT_TTL_DAYS: '7' }), false)

  const envExchangeOnly = resolveStorageMaintenancePolicy(undefined, { KOVO_EXCHANGE_TTL_DAYS: '30' })
  assert.ok(envExchangeOnly !== false)
  assert.equal(envExchangeOnly.exchangeTtlMs, 30 * DAY_MS)
  assert.equal(envExchangeOnly.artifactTtlMs, 0)
  assert.equal(envExchangeOnly.preserveConfirmedEvidence, true)
  assert.equal(envExchangeOnly.skipActiveRuns, true)

  const envBoth = resolveStorageMaintenancePolicy(undefined, {
    KOVO_EXCHANGE_TTL_DAYS: '21',
    KOVO_ARTIFACT_TTL_DAYS: '45',
  })
  assert.ok(envBoth !== false)
  assert.equal(envBoth.exchangeTtlMs, 21 * DAY_MS)
  assert.equal(envBoth.artifactTtlMs, 45 * DAY_MS)

  // Default AppRuntime (no retention env, no maintenance.ttlPolicy) must NOT prune aged transcripts or artifacts!
  const dir = makeTempDir(t, 'kovo-r3-default-rt-')
  const runtime = createAppRuntime({
    dataDir: dir,
    autoStartMaintenance: false,
    maintenance: { env: {} },
  })
  t.after(async () => {
    if (!runtime.isDisposed) await runtime.dispose()
  })

  const st = runtime.store
  const { runId, run, worker } = setupApprovedRun(st, 'Default Runtime Retention')
  st.updateRun(runId, { status: 'complete' })

  const now = Date.now()
  const oldEx = recordEx(st, runId, worker.id, run.scopeRevision, '/api/old-transcript', '{"keep":"by-default"}')
  const oldArt = st.addArtifact(run, worker, 'observation', 'Old observation', 'keep-artifact-by-default')
  st.flushNow()
  st.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?').run(now - 60 * DAY_MS, oldEx.id)
  st.client.prepare('UPDATE evidence SET created_at = ? WHERE id = ?').run(now - 60 * DAY_MS, oldArt.id)

  assert.equal(runtime.maintenance.effectiveTtlPolicy(), false, 'default AppRuntime must have TTL pruning OFF')
  const report = runtime.maintenance.runMaintenanceCycle({ now })
  assert.deepEqual(report.errors, [])
  assert.equal(report.ttl, null, 'default maintenance cycle must not execute TTL purge')
  assert.equal(st.getExchange(runId, oldEx.id).body, '{"keep":"by-default"}')
  assert.equal(st.artifact(runId, oldArt.id).content, 'keep-artifact-by-default')
})

// ============================================================================
// 2. Receipt export byte-for-byte unchanged after maintenance cycle past TTL
// ============================================================================

test('R3-H-16: exportRunReceiptBundle is byte-for-byte unchanged after full maintenance cycle past explicit TTL while unreferenced rows are pruned', t => {
  const { dir, store } = makeTempStore(t, 'kovo-r3-receipt-export-')
  const { runId, run, asset, worker } = setupApprovedRun(store, 'Receipt Export Retention')
  const now = Date.now()
  const agedTs = now - 30 * DAY_MS
  const fixedExportNow = now + 1000
  const hmacSecret = 'r3-retention-test-signing-secret-0123456789'

  const sharedBlobBody = JSON.stringify({ shared: 'content-addressed-blob', evidence: 'must-survive' })

  // Seed cited exchanges across every protected category + unreferenced aged exchanges (including one sharing a blob!).
  const exUnref1 = recordEx(store, runId, worker.id, run.scopeRevision, '/api/unref/a', '{"unref":"a"}')
  const exUnrefShared = recordEx(store, runId, worker.id, run.scopeRevision, '/api/unref/shared', sharedBlobBody)
  const exFinding = recordEx(store, runId, worker.id, run.scopeRevision, '/api/orders/101', sharedBlobBody)
  const exSingleReceipt = recordEx(store, runId, worker.id, run.scopeRevision, '/api/orders/101?probe=1', '{"order":101,"owner":"alice"}')
  const exCompHop = recordEx(store, runId, worker.id, run.scopeRevision, '/api/chain/hop1', '{"chain":"hop1"}')
  const exCompCtrl = recordEx(store, runId, worker.id, run.scopeRevision, '/api/chain/ctrl', '{"chain":"ctrl"}')
  const exCompReadback = recordEx(store, runId, worker.id, run.scopeRevision, '/api/chain/readback', '{"chain":"readback"}')
  const exRetest = recordEx(store, runId, worker.id, run.scopeRevision, '/api/orders/101?retest=1', '{"retest":"reproduced"}')
  const exFactCol = recordEx(store, runId, worker.id, run.scopeRevision, '/api/fact/col', '{"fact":"col"}')
  const exFactData = recordEx(store, runId, worker.id, run.scopeRevision, '/api/fact/data', '{"fact":"data"}')
  const exCanary = recordEx(store, runId, worker.id, run.scopeRevision, '/api/canary/surface', '{"canary":"hit"}')
  const exUnref2 = recordEx(store, runId, worker.id, run.scopeRevision, '/api/unref/b', '{"unref":"b"}')

  // Seed cited evidence artifacts + unreferenced aged evidence artifact.
  const artUnref = store.addArtifact(run, worker, 'observation', 'Unreferenced aged note', 'prune-this-artifact')
  const artFinding = store.addArtifact(run, worker, 'verification', 'Finding proof note', 'keep-finding-artifact')
  const artProofScript = store.addArtifact(run, worker, 'verification', 'Proof script artifact', 'console.log("proof")')
  const artRetestComposite = store.addArtifact(
    run,
    worker,
    'verification',
    'Composite patch retest',
    JSON.stringify({ kind: 'composite_patch_retest', compositeVerdict: 'fixed', patchBrokeHopId: 'hop_1' }),
  )
  const artFact = store.addArtifact(run, worker, 'observation', 'Fact evidence', 'keep-fact-artifact')

  // 1) Confirmed single-hop finding + ProofReceipt + Retest
  const singleFindingId = randomUUID()
  const singleSpec = store.createReplaySpec(run, worker, singleFindingId, sampleSpec('Confirmed IDOR', '/api/orders/101'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.setReplaySpecProof(runId, singleSpec.id, {
    replaySpecId: singleSpec.id,
    findingId: singleFindingId,
    verdict: 'confirmed',
    runtime: 'ts',
    scriptSha256: 'c'.repeat(64),
    artifactId: artProofScript.id,
    createdAt: agedTs,
    receipt: {
      receipt: {
        vulnClass: 'bola',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/orders/101' },
        exchangeIds: [exSingleReceipt.id, exFinding.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Peer persona read owner order 101',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'bola_cross_owner',
        reason: 'Cross-persona read verified',
        observed: '200 with owner payload',
        expected: '403 denied',
      },
    },
  })
  store.upsertChainFinding(run, asset.id, {
    id: singleFindingId,
    origin: ORIGIN,
    title: 'Confirmed IDOR on /api/orders/101',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Cross-persona order read',
    remediation: 'Enforce owner check',
    evidenceIds: [artFinding.id],
    exchangeIds: [exFinding.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-r3-ret-single',
  }, singleSpec.id, [ORIGIN])

  store.recordRetestRun(
    run,
    singleFindingId,
    singleSpec.id,
    'reproduced',
    'Still reproduces after initial patch',
    [artRetestComposite.id],
    [exRetest.id],
  )

  // 2) Confirmed composite-receipt finding
  const compFindingId = randomUUID()
  const compSpec = store.createReplaySpec(run, worker, compFindingId, sampleSpec('Composite Chain', '/api/chain/hop1'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.client.prepare('UPDATE replay_specs SET proof_receipt = ? WHERE id = ?').run(
    JSON.stringify({
      receipt: {
        vulnClass: 'bola',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/chain/hop1' },
        exchangeIds: [exCompHop.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Multi-hop chain confirmed',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'composite_chain',
        reason: 'Composite chain verified',
        observed: '200',
        expected: '403',
      },
      compositeReceipt: {
        chainId: 'chain-ret-1',
        terminalVulnClass: 'bola',
        hops: [{
          hopId: 'hop_1',
          surface: 'http',
          target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/chain/hop1' },
          exchangeIds: [exCompHop.id],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'Hop 1 cross-tenant read',
        }],
        causalEdges: [],
        terminalImpact: {
          terminalHopId: 'hop_1',
          claimedImpact: 'Unauthorized readback',
          preChainControlExchangeIds: [exCompCtrl.id],
          postChainReadbackExchangeIds: [exCompReadback.id],
        },
      },
      compositeVerification: { confirmed: true },
    }),
    compSpec.id,
  )
  store.upsertChainFinding(run, asset.id, {
    id: compFindingId,
    origin: ORIGIN,
    title: 'Confirmed composite chain',
    status: 'confirmed',
    severity: 'critical',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Composite chain verified',
    remediation: 'Enforce authorization on chain hop',
    evidenceIds: [],
    exchangeIds: [exCompHop.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-r3-ret-comp',
  }, compSpec.id, [ORIGIN])

  // 3) Fact citing exchangeIds + nested data.exchangeId + evidenceIds
  store.addFact(run, worker, {
    kind: 'auth',
    origin: ORIGIN,
    summary: 'Auth boundary fact with cited exchanges & evidence',
    data: { exchangeId: exFactData.id },
    exchangeIds: [exFactCol.id],
    evidenceIds: [artFact.id],
    sourceOrigins: [ORIGIN],
  })

  // 4) Surfaced second-order canary citing exCanary
  store.client.prepare(
    `INSERT INTO second_order_canaries (id, run_id, assignment_id, marker, injected_origin, injected_endpoint, injected_param, surfaced_origin, surfaced_endpoint, surfaced_exchange_id, status, created_at, surfaced_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'surfaced', ?, ?)`,
  ).run(
    randomUUID(),
    runId,
    worker.id,
    `kovo-canary-${randomUUID().slice(0, 8)}`,
    ORIGIN,
    '/api/profile',
    'bio',
    ORIGIN,
    '/api/canary/surface',
    exCanary.id,
    agedTs,
    agedTs,
  )

  // Mark run terminal and backdate ALL seeded exchanges & evidence past the 14-day TTL!
  store.updateRun(runId, { status: 'complete' })
  store.flushNow()
  store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE run_id = ?').run(agedTs, runId)
  store.client.prepare(
    'UPDATE evidence SET created_at = ? WHERE id IN (?, ?, ?, ?, ?)',
  ).run(agedTs, artUnref.id, artFinding.id, artProofScript.id, artRetestComposite.id, artFact.id)

  // Capture receipt bundle BEFORE maintenance cycle.
  const beforeBundle = exportRunReceiptBundle(store, runId, {
    now: fixedExportNow,
    signing: { algorithm: 'hmac-sha256', secret: hmacSecret },
  })
  assert.equal(verifyProofReceiptBundle(beforeBundle, { secret: hmacSecret }).valid, true)
  assert.equal(beforeBundle.payload.records.length, 2)
  assert.ok(beforeBundle.payload.records.some(r => r.transcriptSlices.length >= 2))

  // Run a full StorageMaintenanceController cycle with explicit 14-day retention configured via env!
  const maint = new StorageMaintenanceController({
    store,
    dataDir: dir,
    env: {
      KOVO_EXCHANGE_TTL_DAYS: '14',
      KOVO_ARTIFACT_TTL_DAYS: '14',
    },
    orphanGraceMs: 30 * 60_000,
    now: () => now,
  })
  const policy = maint.effectiveTtlPolicy()
  assert.ok(policy !== false)
  assert.equal(policy.exchangeTtlMs, 14 * DAY_MS)
  assert.equal(policy.artifactTtlMs, 14 * DAY_MS)

  const cycleReport = maint.runMaintenanceCycle({ now })
  assert.deepEqual(cycleReport.errors, [])
  assert.ok(cycleReport.ttl !== null)
  assert.equal(cycleReport.ttl.exchangesDeleted, 3, 'only the 3 unreferenced aged exchanges should be pruned')
  assert.equal(cycleReport.ttl.blobsDeleted, 2, 'shared content-addressed blob referenced by exFinding MUST survive')
  assert.equal(cycleReport.ttl.artifactsDeleted, 1, 'only the 1 unreferenced aged evidence artifact should be pruned')

  // Capture receipt bundle AFTER full maintenance cycle — MUST be byte-for-byte identical!
  const afterBundle = exportRunReceiptBundle(store, runId, {
    now: fixedExportNow,
    signing: { algorithm: 'hmac-sha256', secret: hmacSecret },
  })
  assert.equal(verifyProofReceiptBundle(afterBundle, { secret: hmacSecret }).valid, true)
  assert.equal(afterBundle.payloadSha256, beforeBundle.payloadSha256, 'receipt bundle payloadSha256 must be unchanged after maintenance')
  assert.equal(afterBundle.signature, beforeBundle.signature, 'receipt bundle signature must be unchanged after maintenance')
  assert.equal(
    JSON.stringify(afterBundle),
    JSON.stringify(beforeBundle),
    'receipt export bundle must be byte-for-byte identical after TTL maintenance past expiry',
  )

  // Every protected exchange still has intact DB row, FTS entry, and on-disk body blob.
  for (const ex of [exFinding, exSingleReceipt, exCompHop, exCompCtrl, exCompReadback, exRetest, exFactCol, exFactData, exCanary]) {
    const loaded = store.getExchange(runId, ex.id)
    assert.equal(loaded.body, ex.bodyPreview, `protected exchange ${ex.pathAndQuery} blob must survive`)
    const fts = store.client.prepare('SELECT count(*) AS c FROM broker_exchanges_fts WHERE exchange_id = ?').get(ex.id) as { c: number }
    assert.equal(fts.c, 1, `protected exchange ${ex.pathAndQuery} FTS row must survive`)
  }

  // Every protected evidence artifact still has intact DB row and disk file.
  for (const [art, expectedContent] of [
    [artFinding, 'keep-finding-artifact'],
    [artProofScript, 'console.log("proof")'],
    [artFact, 'keep-fact-artifact'],
  ] as const) {
    assert.equal(store.artifact(runId, art.id).content, expectedContent)
  }
  assert.ok(store.artifact(runId, artRetestComposite.id).content.includes('composite_patch_retest'))

  // Unreferenced aged exchanges and unreferenced artifact were actually pruned.
  for (const ex of [exUnref1, exUnrefShared, exUnref2]) {
    const cnt = store.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE id = ?').get(ex.id) as { c: number }
    assert.equal(cnt.c, 0, `unreferenced exchange ${ex.pathAndQuery} must be pruned`)
  }
  const unrefArtCount = store.client.prepare('SELECT count(*) AS c FROM evidence WHERE id = ?').get(artUnref.id) as { c: number }
  assert.equal(unrefArtCount.c, 0, 'unreferenced aged evidence artifact must be pruned')
})

// ============================================================================
// 3. Non-terminal runs skipped completely; terminal runs pruned when opted in
// ============================================================================

test('R3-H-16: TTL pruning and orphan sweeping skip ALL non-terminal runs (running, waiting, paused, budget_paused, queued) and only prune terminal runs', async t => {
  // Unit-check terminal status classifier
  for (const terminal of ['complete', 'completed', 'stopped', 'failed', 'cancelled', 'canceled']) {
    assert.equal(isTerminalRunStatus(terminal), true, `${terminal} must be classified as terminal`)
  }
  for (const nonTerminal of ['running', 'waiting', 'paused', 'budget_paused', 'queued', 'pending', 'scoping', '', null, undefined]) {
    assert.equal(isTerminalRunStatus(nonTerminal), false, `${String(nonTerminal)} must be classified as non-terminal`)
  }

  const dir = makeTempDir(t, 'kovo-r3-nonterminal-')
  const runtime = createAppRuntime({
    dataDir: dir,
    autoStartMaintenance: false,
    maintenance: {
      ttlPolicy: {
        exchangeTtlMs: 14 * DAY_MS,
        artifactTtlMs: 14 * DAY_MS,
        preserveConfirmedEvidence: true,
      },
      orphanGraceMs: 30 * 60_000,
    },
  })
  t.after(async () => {
    if (!runtime.isDisposed) await runtime.dispose()
  })

  const store = runtime.store
  const now = Date.now()
  const agedTs = now - 30 * DAY_MS

  const nonTerminalCases: Array<{ label: string; dbStatus: string; inMemoryActive?: boolean }> = [
    { label: 'running', dbStatus: 'running' },
    { label: 'waiting', dbStatus: 'waiting' },
    { label: 'paused', dbStatus: 'paused' },
    { label: 'budget_paused', dbStatus: 'budget_paused' },
    { label: 'queued', dbStatus: 'queued' },
    { label: 'in-memory-active-complete', dbStatus: 'complete', inMemoryActive: true },
  ]
  const terminalCases: Array<{ label: string; dbStatus: 'complete' | 'stopped' | 'failed' }> = [
    { label: 'complete', dbStatus: 'complete' },
    { label: 'stopped', dbStatus: 'stopped' },
    { label: 'failed', dbStatus: 'failed' },
  ]

  const seededNonTerminal: Array<{ label: string; runId: string; exId: string; artId: string; scratchFile: string }> = []
  const seededTerminal: Array<{ label: string; runId: string; exId: string; artId: string }> = []

  for (const c of nonTerminalCases) {
    const setup = setupApprovedRun(store, `NonTerm ${c.label}`)
    const ex = recordEx(store, setup.runId, setup.worker.id, setup.run.scopeRevision, `/api/nt/${c.label}`, `{"nt":"${c.label}"}`)
    const art = store.addArtifact(setup.run, setup.worker, 'observation', `NT art ${c.label}`, `nt-content-${c.label}`)
    store.flushNow()
    store.client.prepare('UPDATE runs SET status = ? WHERE id = ?').run(c.dbStatus, setup.runId)
    store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?').run(agedTs, ex.id)
    store.client.prepare('UPDATE evidence SET created_at = ? WHERE id = ?').run(agedTs, art.id)

    const scratchDir = join(dir, 'scratch', `run-${setup.runId}`)
    mkdirSync(scratchDir, { recursive: true })
    const scratchFile = join(scratchDir, 'work.tmp')
    writeFileSync(scratchFile, 'keep-non-terminal-scratch', 'utf8')
    utimesSync(scratchFile, new Date(now - 2 * HOUR_MS), new Date(now - 2 * HOUR_MS))

    if (c.inMemoryActive) {
      runtime.createRunContext(setup.runId)
    }
    seededNonTerminal.push({ label: c.label, runId: setup.runId, exId: ex.id, artId: art.id, scratchFile })
  }

  for (const c of terminalCases) {
    const setup = setupApprovedRun(store, `Term ${c.label}`)
    const ex = recordEx(store, setup.runId, setup.worker.id, setup.run.scopeRevision, `/api/term/${c.label}`, `{"term":"${c.label}"}`)
    const art = store.addArtifact(setup.run, setup.worker, 'observation', `Term art ${c.label}`, `term-content-${c.label}`)
    store.flushNow()
    store.updateRun(setup.runId, { status: c.dbStatus })
    store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?').run(agedTs, ex.id)
    store.client.prepare('UPDATE evidence SET created_at = ? WHERE id = ?').run(agedTs, art.id)
    seededTerminal.push({ label: c.label, runId: setup.runId, exId: ex.id, artId: art.id })
  }

  const report = runtime.maintenance.runMaintenanceCycle({ now })
  assert.deepEqual(report.errors, [])
  assert.ok(report.ttl !== null)
  assert.equal(report.ttl.runsScanned, terminalCases.length, 'only strictly terminal inactive runs may be scanned')
  assert.equal(report.ttl.exchangesDeleted, terminalCases.length)
  assert.equal(report.ttl.artifactsDeleted, terminalCases.length)

  // Every non-terminal run MUST be 100% untouched (exchanges, blobs, artifacts, scratch files).
  for (const item of seededNonTerminal) {
    assert.equal(
      store.getExchange(item.runId, item.exId).body,
      `{"nt":"${item.label}"}`,
      `non-terminal run (${item.label}) exchange MUST NOT be pruned`,
    )
    assert.equal(
      store.artifact(item.runId, item.artId).content,
      `nt-content-${item.label}`,
      `non-terminal run (${item.label}) evidence artifact MUST NOT be pruned`,
    )
    assert.equal(
      existsSync(item.scratchFile),
      true,
      `non-terminal run (${item.label}) scratch file MUST NOT be swept`,
    )
  }

  // Direct purgeExpiredArtifacts targeting a paused or waiting runId must ALSO skip it!
  const pausedItem = seededNonTerminal.find(i => i.label === 'paused')!
  const waitingItem = seededNonTerminal.find(i => i.label === 'waiting')!
  for (const target of [pausedItem, waitingItem]) {
    const directRes = purgeExpiredArtifacts(store, {
      runId: target.runId,
      exchangeTtlMs: DAY_MS,
      artifactTtlMs: DAY_MS,
      now,
    })
    assert.equal(directRes.runsScanned, 0, `direct TTL purge must skip ${target.label} run`)
    assert.equal(directRes.exchangesDeleted, 0)
    assert.equal(directRes.artifactsDeleted, 0)
  }

  // Every terminal run's unreferenced aged exchange & artifact WAS pruned.
  for (const item of seededTerminal) {
    const exCnt = store.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE id = ?').get(item.exId) as { c: number }
    const artCnt = store.client.prepare('SELECT count(*) AS c FROM evidence WHERE id = ?').get(item.artId) as { c: number }
    assert.equal(exCnt.c, 0, `terminal run (${item.label}) unreferenced aged exchange should be pruned`)
    assert.equal(artCnt.c, 0, `terminal run (${item.label}) unreferenced aged artifact should be pruned`)
  }
})
