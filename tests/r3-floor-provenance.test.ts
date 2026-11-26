import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { and, eq } from 'drizzle-orm'
import { newProject, newRun } from '../src/domain.ts'
import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { ExecFloorLane, type ExecFloorLaneHost } from '../src/server/exec-floor-lane.ts'
import * as tables from '../src/server/schema.ts'
import {
  floorEnvelopeTrustForFinding,
  isConfirmedFloorFinding,
  listProtectedExchangeIdsForRun,
} from '../src/server/store-findings.ts'
import { InvariantError, Store } from '../src/server/store.ts'

const ORIGIN = 'https://r3-floor.example.test'
const HOUR_MS = 60 * 60_000

function makeTempStore(t: test.TestContext, prefix = 'kovo-r3-floor-'): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { dir, store }
}

function setupApprovedRun(store: Store, name = 'R3 Floor Provenance App', origin = ORIGIN) {
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
  const worker = store.makeWorker(run, 'investigation', asset, 'R3 Worker', 'Verify floor provenance & retention')
  return { projectId: proj.id, runId: run.id, run, asset, worker }
}

function makeFloorLane(store: Store): ExecFloorLane {
  const hostStub = {
    storage: store,
    permitted: () => true,
  } as unknown as ExecFloorLaneHost
  return new ExecFloorLane(hostStub)
}

function sampleAuthzSpec(pathAndQuery: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: `Cross-persona object access · GET ${pathAndQuery}`,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Owner vs peer differential observed on object read.',
    impact: 'Horizontal cross-account object access.',
    remediation: 'Enforce object ownership checks before returning records.',
    recheckInstructions: 'Replay owner control and cross-persona probe after fix.',
    assertionsJq: '{ controlPassed: (.steps.ctrl.status == 200), confirmed: (.steps.prb.status == 200), observed: "200", expected: "403" }',
    spaCatchallControl: false,
    steps: [
      {
        id: 'ctrl',
        role: 'control',
        description: 'Owner reads own object',
        request: { origin, method: 'GET', pathAndQuery, persona: 'alice', followRedirects: false },
      },
      {
        id: 'prb',
        role: 'probe',
        description: 'Peer replays owner object id',
        request: { origin, method: 'GET', pathAndQuery, persona: 'bob', followRedirects: false },
      },
    ],
  } as unknown as DeclarativeReplaySpec
}

function sampleSqliSpec(pathAndQuery: string, paramName: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'sql_boolean_diff',
    origin,
    targetOrigin: origin,
    title: `SQL parameterization differential · GET ${pathAndQuery} (${paramName})`,
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: `Deterministic boolean differential on parameter "${paramName}".`,
    impact: 'Boolean differential indicates unparameterized query handling.',
    remediation: 'Use parameterized query bindings.',
    recheckInstructions: 'Replay boolean differential control vs variant after fix.',
    method: 'GET',
    pathAndQuery,
    paramName,
    paramLocation: 'query',
    baselineValue: 'kovo',
    quoteStyle: 'single',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "differential", expected: "parameterized" }',
  } as unknown as DeclarativeReplaySpec
}

function feedback(verdict: InlineVerifyFeedback['verdict']): InlineVerifyFeedback {
  return {
    verdict,
    verificationTier: verdict === 'confirmed' ? 'runtime_confirmed' : verdict === 'static_verified' ? 'static_verified' : undefined,
    controlPassed: verdict !== 'inconclusive',
    assertionSummary: { observed: verdict, expected: 'confirmed' },
    stepStatuses: [{ id: 'prb', role: 'probe', status: verdict === 'confirmed' ? 200 : 403, bodyLen: 32 }],
    retriesRemaining: 0,
  }
}

function floorPreservedEvents(store: Store, runId: string) {
  return store.db.select().from(tables.events).where(and(
    eq(tables.events.runId, runId),
    eq(tables.events.kind, 'finding.floor_preserved'),
  )).all()
}

function getFindingRow(store: Store, runId: string, findingId: string) {
  return store.db.select().from(tables.findings).where(and(
    eq(tables.findings.runId, runId),
    eq(tables.findings.id, findingId),
  )).get()
}

function recordTestExchange(
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
    reqHeaders: {},
    respHeaders: {},
    body,
    durationMs: 4,
  })
}

// ============================================================================
// R3-H-14: Pending deterministic proposals must NOT be frozen as provenance:'floor'
// ============================================================================

test('R3-H-14: pending deterministic proposals (authz_matrix & sqli_boolean) transition cleanly on replay confirm, dismiss, and inconclusive', t => {
  const { store } = makeTempStore(t, 'kovo-r3-h14-replay-')
  const { runId, run, asset, worker } = setupApprovedRun(store)
  const lane = makeFloorLane(store)

  // 1) authz_matrix proposal -> replay confirms it via upsertChainFinding (persistReplayConfirmation path)
  const authzId = lane.recordDeterministicFinding({
    run,
    assignment: worker,
    asset,
    spec: sampleAuthzSpec('/api/orders/101'),
    factData: { subkind: 'differential_anomaly', probeClass: 'authz_matrix', endpoint: '/api/orders/{id}' },
    factSummary: 'Deterministic authz_matrix differential on /api/orders/{id}.',
    exchangeIds: ['ex-authz-1'],
    secrets: [],
  })
  assert.ok(authzId, 'authz_matrix proposal should persist')
  const pendingAuthz = getFindingRow(store, runId, authzId)!
  assert.equal(pendingAuthz.finding.status, 'pending')
  assert.notEqual(pendingAuthz.provenance, 'floor', 'pending deterministic proposal must NOT be stamped provenance: floor')
  assert.equal(isConfirmedFloorFinding(pendingAuthz), false)
  assert.equal(floorEnvelopeTrustForFinding(pendingAuthz), 'untrusted')

  // Replay confirms the authz_matrix proposal
  store.recordReplaySpecVerification(runId, pendingAuthz.replaySpecId!, feedback('confirmed'), 'replay confirmed')
  const confirmedAuthz = store.upsertChainFinding(
    run,
    pendingAuthz.assetId,
    {
      ...pendingAuthz.finding,
      status: 'confirmed',
      verificationTier: 'runtime_confirmed',
      confidence: 'high',
      verification: 'Zero-LLM replay confirmed cross-persona access.',
    },
    pendingAuthz.replaySpecId!,
    pendingAuthz.sourceOrigins,
  )
  assert.equal(confirmedAuthz.id, authzId)
  assert.equal(confirmedAuthz.status, 'confirmed')
  assert.equal(getFindingRow(store, runId, authzId)?.finding.status, 'confirmed')
  assert.equal(floorPreservedEvents(store, runId).length, 0, 'pending proposal must never emit floor_preserved')

  // 2) sqli_boolean proposal -> replay dismisses it via updateProposedFinding
  const sqliDismissId = lane.recordDeterministicFinding({
    run,
    assignment: worker,
    asset,
    spec: sampleSqliSpec('/api/search?q=kovo', 'q'),
    factData: { subkind: 'differential_anomaly', probeClass: 'sqli_boolean', endpoint: '/api/search' },
    factSummary: 'Deterministic sqli_boolean signal on /api/search param q.',
    exchangeIds: ['ex-sqli-1'],
    secrets: [],
  })
  assert.ok(sqliDismissId)
  const pendingSqliDismiss = getFindingRow(store, runId, sqliDismissId)!
  assert.equal(pendingSqliDismiss.finding.status, 'pending')
  assert.notEqual(pendingSqliDismiss.provenance, 'floor')

  store.recordReplaySpecVerification(runId, pendingSqliDismiss.replaySpecId!, feedback('dismissed'), 'replay dismissed')
  const dismissedSqli = store.updateProposedFinding(run, sqliDismissId, {
    verificationTier: null,
    finding: {
      status: 'dismissed',
      confidence: 'low',
      verification: 'Replay dismissed boolean differential.',
    },
  })
  assert.equal(dismissedSqli.status, 'dismissed')
  assert.equal(getFindingRow(store, runId, sqliDismissId)?.finding.status, 'dismissed')

  // 3) sqli_boolean proposal -> replay marks it inconclusive via updateProposedFinding
  const sqliInconclusiveId = lane.recordDeterministicFinding({
    run,
    assignment: worker,
    asset,
    spec: sampleSqliSpec('/api/catalog?filter=kovo', 'filter'),
    factData: { subkind: 'differential_anomaly', probeClass: 'sqli_boolean', endpoint: '/api/catalog' },
    factSummary: 'Deterministic sqli_boolean signal on /api/catalog param filter.',
    exchangeIds: ['ex-sqli-2'],
    secrets: [],
  })
  assert.ok(sqliInconclusiveId)
  const pendingSqliInc = getFindingRow(store, runId, sqliInconclusiveId)!
  store.recordReplaySpecVerification(runId, pendingSqliInc.replaySpecId!, feedback('inconclusive'), 'replay inconclusive')
  const inconclusiveSqli = store.updateProposedFinding(run, sqliInconclusiveId, {
    verificationTier: null,
    finding: {
      status: 'inconclusive',
      confidence: 'low',
      verification: 'Replay control did not pass.',
    },
  })
  assert.equal(inconclusiveSqli.status, 'inconclusive')
  assert.equal(getFindingRow(store, runId, sqliInconclusiveId)?.finding.status, 'inconclusive')
  assert.equal(floorPreservedEvents(store, runId).length, 0)
})

test('R3-H-14: agent / kovo_verify confirmation with same structural fingerprint upgrades pending deterministic proposal instead of suppressing as floor_preserved', t => {
  const { store } = makeTempStore(t, 'kovo-r3-h14-agent-upgrade-')
  const { runId, run, asset, worker } = setupApprovedRun(store)
  const lane = makeFloorLane(store)

  // Case A: Pending proposal created by ExecFloorLane.recordDeterministicFinding
  const pendingId = lane.recordDeterministicFinding({
    run,
    assignment: worker,
    asset,
    spec: sampleAuthzSpec('/api/invoices/55'),
    factData: { subkind: 'differential_anomaly', probeClass: 'authz_matrix', endpoint: '/api/invoices/{id}' },
    factSummary: 'Deterministic authz_matrix signal on /api/invoices/{id}.',
    exchangeIds: ['ex-det-55'],
    secrets: [],
  })
  assert.ok(pendingId)
  const pendingRow = getFindingRow(store, runId, pendingId)!
  assert.ok(pendingRow.fingerprintHash, 'deterministic proposal must carry structural fingerprintHash')

  // Agent / kovo_verify proves the same structural fingerprint with a verified ProofReceipt
  const agentFindingId = randomUUID()
  const agentSpec = store.createReplaySpec(run, worker, agentFindingId, sampleAuthzSpec('/api/invoices/55'), [ORIGIN])
  store.setReplaySpecProof(runId, agentSpec.id, {
    replaySpecId: agentSpec.id,
    findingId: agentFindingId,
    verdict: 'confirmed',
    runtime: 'ts',
    scriptSha256: 'a'.repeat(64),
    artifactId: randomUUID(),
    createdAt: Date.now(),
    receipt: {
      receipt: {
        vulnClass: 'bola',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/invoices/55' },
        exchangeIds: ['ex-agent-55-ctrl', 'ex-agent-55-prb'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Peer persona read foreign invoice 55',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'bola_cross_owner',
        reason: 'Cross-persona readback verified.',
        observed: '200 with owner payload',
        expected: '403 denied',
      },
    },
  })

  const upgraded = store.upsertChainFinding(
    run,
    asset.id,
    {
      id: agentFindingId,
      origin: ORIGIN,
      title: 'Agent-verified cross-persona invoice read',
      status: 'confirmed',
      severity: 'high',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'kovo_verify proved cross-tenant invoice readback.',
      remediation: 'Check invoice ownership.',
      evidenceIds: [],
      exchangeIds: ['ex-agent-55-ctrl', 'ex-agent-55-prb'],
      scopeRevision: run.scopeRevision,
      verificationTier: 'runtime_confirmed',
      fingerprintHash: pendingRow.fingerprintHash,
    },
    agentSpec.id,
    [ORIGIN],
    { provenance: 'agent_only', verificationClass: 'runtime_confirmed' },
  )

  assert.equal(upgraded.id, pendingId, 'agent confirmation merges into canonical pending row')
  assert.equal(upgraded.status, 'confirmed', 'pending deterministic proposal upgrades cleanly to confirmed')
  assert.equal(upgraded.replaySpecId, agentSpec.id)
  assert.equal(floorPreservedEvents(store, runId).length, 0, 'must NOT be suppressed as floor_preserved')

  // Case B: Even a legacy DB row stamped { provenance: 'floor' } while status === 'pending' must upgrade & remain dismissible
  const legacyPendingId = randomUUID()
  const legacySpec = store.createReplaySpec(run, worker, legacyPendingId, sampleAuthzSpec('/api/tickets/77'), [ORIGIN])
  store.upsertChainFinding(
    run,
    asset.id,
    {
      id: legacyPendingId,
      origin: ORIGIN,
      title: 'Legacy pending floor row',
      status: 'pending',
      severity: 'medium',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Pending replay',
      remediation: 'Enforce ownership check',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      fingerprintHash: 'fp-legacy-pending-floor',
    },
    legacySpec.id,
    [ORIGIN],
    { provenance: 'floor' },
  )

  const legacyAgentSpec = store.createReplaySpec(run, worker, randomUUID(), sampleAuthzSpec('/api/tickets/77'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed'),
  })
  const upgradedLegacy = store.upsertChainFinding(
    run,
    asset.id,
    {
      id: randomUUID(),
      origin: ORIGIN,
      title: 'Agent confirmation of legacy pending floor row',
      status: 'confirmed',
      severity: 'high',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Verified cross-account access',
      remediation: 'Enforce ownership check',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      verificationTier: 'runtime_confirmed',
      fingerprintHash: 'fp-legacy-pending-floor',
    },
    legacyAgentSpec.id,
    [ORIGIN],
    { provenance: 'agent_only' },
  )
  assert.equal(upgradedLegacy.id, legacyPendingId)
  assert.equal(upgradedLegacy.status, 'confirmed')
  assert.equal(floorPreservedEvents(store, runId).length, 0)

  // Legacy pending floor row can also transition to dismissed cleanly
  const legacyDismissId = randomUUID()
  const legacyDismissSpec = store.createReplaySpec(run, worker, legacyDismissId, sampleAuthzSpec('/api/tickets/88'), [ORIGIN])
  store.upsertChainFinding(
    run,
    asset.id,
    {
      id: legacyDismissId,
      origin: ORIGIN,
      title: 'Legacy pending floor row to dismiss',
      status: 'pending',
      severity: 'medium',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Pending replay',
      remediation: 'Enforce ownership check',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      fingerprintHash: 'fp-legacy-pending-dismiss',
    },
    legacyDismissSpec.id,
    [ORIGIN],
    { provenance: 'floor' },
  )
  const dismissedLegacy = store.updateProposedFinding(run, legacyDismissId, {
    verificationTier: null,
    finding: { status: 'dismissed', confidence: 'low', verification: 'Replay dismissed candidate.' },
  })
  assert.equal(dismissedLegacy.status, 'dismissed')
  assert.equal(floorPreservedEvents(store, runId).length, 0)
})

test('R3-H-14: pending proposals never get backed:true or host_persisted, while confirmed floor rows remain strictly immutable', t => {
  const { store } = makeTempStore(t, 'kovo-r3-h14-guards-')
  const { runId, run, asset, worker } = setupApprovedRun(store)

  // Pending row (even if explicitly tagged provenance: 'floor') MUST NOT get backed:true or host_persisted
  const pendingFloorId = randomUUID()
  const unconfirmedSpec = store.createReplaySpec(run, worker, pendingFloorId, sampleAuthzSpec('/api/docs/9'), [ORIGIN])
  store.upsertChainFinding(
    run,
    asset.id,
    {
      id: pendingFloorId,
      origin: ORIGIN,
      title: 'Pending floor candidate without proof',
      status: 'pending',
      severity: 'high',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Awaiting replay confirmation',
      remediation: 'Check ownership',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      fingerprintHash: 'fp-pending-no-backing',
    },
    unconfirmedSpec.id,
    [ORIGIN],
    { provenance: 'floor' },
  )
  const pendingRow = getFindingRow(store, runId, pendingFloorId)!
  assert.equal(isConfirmedFloorFinding(pendingRow), false)
  assert.equal(floorEnvelopeTrustForFinding(pendingRow), 'untrusted')

  // Direct assertConfirmationEvidence must reject pending floor rows
  assert.throws(
    () => store.assertConfirmationEvidence(runId, {
      findingId: pendingFloorId,
      replaySpecId: unconfirmedSpec.id,
      provenance: 'floor',
    }),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
  )

  // Attempting to promote pending floor row to confirmed WITHOUT confirming spec/receipt must throw
  assert.throws(
    () => store.updateProposedFinding(run, pendingFloorId, {
      finding: { status: 'confirmed', verificationTier: 'runtime_confirmed' },
    }),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
  )
  assert.throws(
    () => store.upsertChainFinding(
      run,
      asset.id,
      {
        id: randomUUID(),
        origin: ORIGIN,
        title: 'Unbacked confirmation attempt',
        status: 'confirmed',
        severity: 'high',
        category: 'broken-access-control',
        cwe: 'CWE-639',
        reason: 'No proof yet',
        remediation: 'Check ownership',
        evidenceIds: [],
        scopeRevision: run.scopeRevision,
        verificationTier: 'runtime_confirmed',
        fingerprintHash: 'fp-pending-no-backing',
      },
      unconfirmedSpec.id,
      [ORIGIN],
      { provenance: 'agent_only' },
    ),
    (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
  )
  assert.equal(getFindingRow(store, runId, pendingFloorId)?.finding.status, 'pending')

  // Now persist a truly CONFIRMED floor row -> gets host_persisted + strict immutability
  const confirmedFloorId = randomUUID()
  const confirmedSpec = store.createReplaySpec(run, worker, confirmedFloorId, sampleAuthzSpec('/api/docs/42'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed'),
  })
  store.upsertChainFinding(
    run,
    asset.id,
    {
      id: confirmedFloorId,
      origin: ORIGIN,
      title: 'Floor-confirmed IDOR on /api/docs/42',
      status: 'confirmed',
      severity: 'high',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Confirmed by deterministic engine replay',
      remediation: 'Enforce document ownership check',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      verificationTier: 'runtime_confirmed',
      fingerprintHash: 'fp-confirmed-floor-immutable',
    },
    confirmedSpec.id,
    [ORIGIN],
    { provenance: 'floor', verificationClass: 'runtime_confirmed' },
  )
  const confirmedRow = getFindingRow(store, runId, confirmedFloorId)!
  assert.equal(isConfirmedFloorFinding(confirmedRow), true)
  assert.equal(floorEnvelopeTrustForFinding(confirmedRow), 'host_persisted')

  // Downgrade via updateProposedFinding must be blocked and logged as finding.floor_preserved
  const afterUpdate = store.updateProposedFinding(run, confirmedFloorId, {
    finding: { status: 'dismissed', severity: 'low', title: 'Should not overwrite' },
  })
  assert.equal(afterUpdate.status, 'confirmed')
  assert.equal(afterUpdate.severity, 'high')
  assert.equal(afterUpdate.title, 'Floor-confirmed IDOR on /api/docs/42')

  // Overwrite via upsertChainFinding (agent_only, same fingerprint) must be blocked
  const afterUpsert = store.upsertChainFinding(
    run,
    asset.id,
    {
      id: randomUUID(),
      origin: ORIGIN,
      title: 'Agent downgrade attempt',
      status: 'confirmed',
      severity: 'low',
      category: 'broken-access-control',
      cwe: 'CWE-639',
      reason: 'Agent attempt',
      remediation: 'Fix',
      evidenceIds: [],
      scopeRevision: run.scopeRevision,
      verificationTier: 'runtime_confirmed',
      fingerprintHash: 'fp-confirmed-floor-immutable',
    },
    confirmedSpec.id,
    [ORIGIN],
    { provenance: 'agent_only' },
  )
  assert.equal(afterUpsert.id, confirmedFloorId)
  assert.equal(afterUpsert.severity, 'high')
  assert.equal(afterUpsert.title, 'Floor-confirmed IDOR on /api/docs/42')
  assert.equal(floorPreservedEvents(store, runId).length, 2)
})

// ============================================================================
// R3-H-16: pruneExchangeRows protects every cited exchange, FTS row, and blob
// ============================================================================

test('R3-H-16: pruneExchanges preserves exchanges (rows, FTS, blobs) cited by findings, receipts, retests, and facts while pruning unreferenced rows', t => {
  const { store } = makeTempStore(t, 'kovo-r3-h16-prune-')
  const { runId, run, asset, worker } = setupApprovedRun(store, 'Retention Protection App')
  const now = Date.now()
  const sharedBody = JSON.stringify({ sharedMarker: 'same-content-addressed-blob', secretRef: 'keep-blob' })

  // Interleave unreferenced exchanges before, between, and after protected exchanges so batchSize=1 exercises cursor scanning!
  const exUnref1 = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/unref/1', '{"unref":1,"token":"delete-me-one"}')
  const exFinding = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/finding/confirmed', sharedBody)
  const exStaticFinding = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/finding/static', '{"static":"keep"}')
  const exSingleReceipt = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/receipt/single', '{"single":"receipt-keep"}')
  const exCompHop = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/composite/hop', '{"comp":"hop-keep"}')
  const exCompControl = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/composite/ctrl', '{"comp":"ctrl-keep"}')
  const exCompReadback = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/composite/readback', '{"comp":"readback-keep"}')
  const exCompModeA = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/composite/mode-a', '{"comp":"mode-a-keep"}')
  const exCompAblation = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/composite/ablation', '{"comp":"ablation-keep"}')
  const exCompOracle = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/composite/oracle', '{"comp":"oracle-keep"}')
  const exRetest = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/retest/1', '{"retest":"keep"}')
  const exFactCol = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/fact/col', '{"fact":"col-keep"}')
  const exFactData = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/fact/data', '{"fact":"data-keep"}')
  const exExplicit = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/explicit/protected', '{"explicit":"caller-keep"}')
  // Unreferenced exchange sharing the exact same body blob as exFinding!
  const exSharedBodyUnref = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/unref/shared-body', sharedBody)
  const exUnref2 = recordTestExchange(store, runId, worker.id, run.scopeRevision, '/api/unref/2', '{"unref":2,"token":"delete-me-two"}')

  store.flushNow()
  // Backdate ALL exchanges well past the 1-hour retention cutoff
  store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE run_id = ?').run(now - 24 * HOUR_MS, runId)

  // 1) Confirmed finding citing exFinding + single-hop ProofReceipt citing exSingleReceipt
  const confirmedId = randomUUID()
  const confirmedSpec = store.createReplaySpec(run, worker, confirmedId, sampleAuthzSpec('/api/finding/confirmed'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed'),
  })
  store.setReplaySpecProof(runId, confirmedSpec.id, {
    replaySpecId: confirmedSpec.id,
    findingId: confirmedId,
    verdict: 'confirmed',
    runtime: 'ts',
    scriptSha256: 'b'.repeat(64),
    artifactId: randomUUID(),
    createdAt: now,
    receipt: {
      receipt: {
        vulnClass: 'bola',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/receipt/single' },
        exchangeIds: [exSingleReceipt.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Confirmed single-hop proof',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'bola_cross_owner',
        reason: 'Verified',
        observed: '200',
        expected: '403',
      },
    },
  })
  store.upsertChainFinding(run, asset.id, {
    id: confirmedId,
    origin: ORIGIN,
    title: 'Confirmed finding with cited exchange',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Confirmed',
    remediation: 'Fix',
    evidenceIds: [],
    exchangeIds: [exFinding.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-r3-h16-confirmed',
  }, confirmedSpec.id, [ORIGIN])

  // 2) Static-verified finding citing exStaticFinding
  const staticId = randomUUID()
  const staticSpec = store.createReplaySpec(run, worker, staticId, sampleAuthzSpec('/api/finding/static'), [ORIGIN])
  store.upsertChainFinding(run, asset.id, {
    id: staticId,
    origin: ORIGIN,
    title: 'Static finding with cited exchange',
    status: 'static_verified',
    severity: 'medium',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Static match',
    remediation: 'Fix',
    evidenceIds: [],
    exchangeIds: [exStaticFinding.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
    fingerprintHash: 'fp-r3-h16-static',
  }, staticSpec.id, [ORIGIN])

  // 3) Replay spec with compositeReceipt citing hops, controls, readback, modeA, ablation, and oracleInput exchanges
  const compFindingId = randomUUID()
  const compSpec = store.createReplaySpec(run, worker, compFindingId, sampleAuthzSpec('/api/composite/hop'), [ORIGIN])
  store.client.prepare('UPDATE replay_specs SET proof_receipt = ? WHERE id = ?').run(
    JSON.stringify({
      compositeReceipt: {
        chainId: 'chain-r3-h16',
        terminalVulnClass: 'economic_conservation',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN }, exchangeIds: [exCompHop.id], oobEventIds: [], browserTraceIds: [], claimedDelta: 'hop 1' },
        ],
        causalEdges: [
          { kind: 'state_transition_binding', fromHopId: 'hop_1', toHopId: 'hop_1', entityId: 'ent-1', ablationExchangeIds: [exCompAblation.id] },
        ],
        terminalImpact: {
          terminalHopId: 'hop_1',
          claimedImpact: 'Balance drift',
          preChainControlExchangeIds: [exCompControl.id],
          postChainReadbackExchangeIds: [exCompReadback.id],
          modeAFailureExchangeId: exCompModeA.id,
          oracleInput: { baselineReadbackExchangeId: exCompOracle.id },
        },
      },
      compositeVerification: { confirmed: true },
    }),
    compSpec.id,
  )

  // 4) Retest run citing exRetest
  store.recordRetestRun(
    run,
    confirmedId,
    confirmedSpec.id,
    'reproduced',
    'Still reproduces',
    [],
    [exRetest.id],
  )

  // 5) Facts citing exFactCol (exchangeIds column) and exFactData (data.exchangeId)
  store.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN,
    summary: 'Fact with exchangeIds column and nested data.exchangeId',
    data: { exchangeId: exFactData.id, subkind: 'deterministic_engine_lead' },
    exchangeIds: [exFactCol.id],
    sourceOrigins: [ORIGIN],
  })

  // Verify helper enumerates every single cited exchange ID and excludes unreferenced ones
  const protectedSet = listProtectedExchangeIdsForRun(store.client, runId)
  const expectedBuiltInProtected = [
    exFinding,
    exStaticFinding,
    exSingleReceipt,
    exCompHop,
    exCompControl,
    exCompReadback,
    exCompModeA,
    exCompAblation,
    exCompOracle,
    exRetest,
    exFactCol,
    exFactData,
  ]
  for (const ex of expectedBuiltInProtected) {
    assert.equal(protectedSet.has(ex.id), true, `listProtectedExchangeIdsForRun must include ${ex.pathAndQuery}`)
  }
  assert.equal(protectedSet.has(exUnref1.id), false)
  assert.equal(protectedSet.has(exUnref2.id), false)
  assert.equal(protectedSet.has(exSharedBodyUnref.id), false)

  // Prune with batchSize: 1 and caller-supplied protectedExchangeIds (exExplicit)
  const pruneRes = store.pruneExchanges({
    runId,
    olderThanMs: HOUR_MS,
    batchSize: 1,
    now,
    protectedExchangeIds: new Set([exExplicit.id]),
  })
  assert.equal(pruneRes.exchanges, 3, 'only the 3 unreferenced old exchanges should be deleted')
  assert.equal(pruneRes.ftsRows, 3, 'only the 3 unreferenced FTS rows should be deleted')
  assert.equal(pruneRes.blobs, 2, 'shared content-addressed blob referenced by exFinding MUST survive')

  // Every protected exchange (built-in + explicit) MUST retain its row, FTS entry, and on-disk body blob!
  for (const ex of [...expectedBuiltInProtected, exExplicit]) {
    const loaded = store.getExchange(runId, ex.id)
    assert.equal(loaded.id, ex.id)
    assert.equal(loaded.body, ex.bodyPreview, `body blob for protected exchange ${ex.pathAndQuery} must remain intact on disk`)
    const ftsHit = store.client.prepare(
      'SELECT count(*) AS c FROM broker_exchanges_fts WHERE exchange_id = ?',
    ).get(ex.id) as { c: number }
    assert.equal(ftsHit.c, 1, `FTS row for protected exchange ${ex.pathAndQuery} must survive pruning`)
  }

  // Unreferenced exchanges MUST be deleted from both broker_exchanges and broker_exchanges_fts
  for (const ex of [exUnref1, exUnref2, exSharedBodyUnref]) {
    const rowHit = store.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE id = ?').get(ex.id) as { c: number }
    const ftsHit = store.client.prepare('SELECT count(*) AS c FROM broker_exchanges_fts WHERE exchange_id = ?').get(ex.id) as { c: number }
    assert.equal(rowHit.c, 0, `unreferenced exchange ${ex.pathAndQuery} should be pruned`)
    assert.equal(ftsHit.c, 0, `unreferenced FTS row ${ex.pathAndQuery} should be pruned`)
  }

  // Explicit ZDR opt-out (`preserveConfirmedEvidence: false`) can prune cited exchanges while still honoring explicit `protectedExchangeIds`
  const zdrRes = store.pruneExchanges({
    runId,
    olderThanMs: HOUR_MS,
    now,
    preserveConfirmedEvidence: false,
    protectedExchangeIds: new Set([exExplicit.id]),
  })
  assert.equal(zdrRes.exchanges, expectedBuiltInProtected.length)
  assert.equal(store.getExchange(runId, exExplicit.id).id, exExplicit.id, 'explicit protectedExchangeIds stays excluded even when preserveConfirmedEvidence is false')
})
