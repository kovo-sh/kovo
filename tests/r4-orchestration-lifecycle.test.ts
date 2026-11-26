/**
 * WS-10 (`R4-H-11`, `R4-H-12`, `R4-H-13`, `R4-H-8`, `R4-H-16`):
 * Fast (<5s) class-level orchestration lifecycle guards.
 *
 * Covers:
 *  1. R4-H-11: Evidence-based per-origin quarantine detector (no single-52x false quarantine,
 *     no global 240-row window scroll, host/Phase-0 probes only, `RunSafetyBudgets` thresholds,
 *     lifetime live-response immunity, and automatic release of `unreachable` & `edge_protected`).
 *  2. R4-H-12: Unified terminal-transition primitive (`reconcileUnavailableOriginSteps`) shared by
 *     origin quarantine and circuit-open; clean restore on unquarantine; shared quarantine-aware
 *     predicate across `anyActive`, `dispatchableReadySteps`, `evaluateDispatchStop`, and
 *     `passOneCoverageFor` so live + quarantined runs advance cleanly to verification.
 *  3. R4-H-13: Exhaustive `STEP_STATUS` terminal parent-status propagation in both `addChainStep`
 *     and `refreshReadyChainSteps`, multi-trial sibling preservation on `turn_capped` lineage,
 *     and run-level stranded-step backstop advancing to verification with structured telemetry.
 *  4. R4-H-8: Explicit `runId` threaded to repo-mounting `openSession` in `execution.ts`.
 *  5. R4-H-16: `exec-recon-planner.ts` invokes `synthesizeInvariantsInWorker` off the host event loop.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  STEP_STATUS,
  chainStepTerminalStatuses,
  isTerminalStepStatus,
  stepBlocksDependent,
  stepKillsDependents,
  stepSatisfiesDependency,
} from '../src/step-status.ts'
import {
  detectQuarantinedOrigins,
  dispatchableReadySteps,
  evaluateDispatchStop,
  hasActiveInvestigationSteps,
  isStepOriginUnavailable,
  permanentlyBlockedStepIds,
  reconcileUnavailableOriginSteps,
} from '../src/server/exec-dispatch.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import { resolveRunSafetyBudgets } from '../src/server/run-safety-budgets.ts'
import { closeSharedUntrustedComputePool } from '../src/server/untrusted-compute-pool.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN_A = 'https://origin-a.r4-ws10.example.invalid'
const ORIGIN_B = 'https://origin-b.r4-ws10.example.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async verifyStaticAst(_aid, req) {
      return {
        verified: false, engine: req.engine, repo: req.repo, file: req.file,
        startLine: req.startLine, endLine: req.endLine, matchedLines: [],
        codeExcerpt: '', matchCount: 0, durationMs: 1,
      }
    },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({
          verified: false, engine: req.engine, repo: req.repo, file: req.file,
          startLine: req.startLine, endLine: req.endLine, matchedLines: [],
          codeExcerpt: '', matchCount: 0, durationMs: 1,
        }),
        close: async () => undefined,
      }
    },
  }
}

function internals(engine: Execution) {
  return engine as unknown as {
    reconPlanner: ExecReconPlanner
    plannerDoneRound: Map<string, number>
    plannerDirty: Set<string>
    tierAFactIds: Set<string>
    driveInvestigation: (run: ReturnType<Execution['storage']['run']>, profiles: readonly unknown[]) => void
    expandEligibleMultiTrialSteps: (run: ReturnType<Execution['storage']['run']>) => void
  }
}

function insertBrokerExchangeRow(
  storage: ReturnType<typeof makeStore>['storage'],
  input: {
    id: string
    runId: string
    assignmentId: string
    origin: string
    pathAndQuery: string
    status: number
    personaHandle?: string | null
    createdAt: number
  },
): void {
  storage.client.prepare(`
    INSERT INTO broker_exchanges (
      id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins,
      method, path_and_query, persona_handle, status, media_type, req_headers, resp_headers,
      body_preview, body_artifact_id, body_sha256, secret_matches, duration_ms, created_at
    ) VALUES (?, ?, ?, 1, ?, ?, '[]', 'GET', ?, ?, ?, 'application/json', '{}', '{}', '', NULL, 'sha256', '[]', 10, ?)
  `).run(
    input.id,
    input.runId,
    input.assignmentId,
    input.origin,
    input.origin,
    input.pathAndQuery,
    input.personaHandle ?? null,
    input.status,
    input.createdAt,
  )
}

// ============================================================================
// 1. R4-H-11: Single-52x, window-scroll, worker-traffic, & budget thresholds
// ============================================================================

test('R4-H-11.1: single 524 alongside 239x200 on sibling origin, single-path 52x, worker traffic, and out-of-window probes NEVER quarantine', () => {
  const now = 1_700_000_000_000
  const budgets = resolveRunSafetyBudgets()
  assert.equal(budgets.originQuarantineMin52xCount, 3)
  assert.equal(budgets.originQuarantineMin401Count, 3)
  assert.equal(budgets.originQuarantineMinDistinctPaths, 2)
  assert.equal(budgets.originQuarantineWindowMs, 300_000)

  // Case A: Exact R4-H-11 repro — 239x200 on Origin A + 1x524 on Origin B (even with a persona).
  const exchangesA = Array.from({ length: 239 }, (_, i) => ({
    origin: ORIGIN_A,
    status: 200,
    pathAndQuery: `/api/item/${i}`,
    createdAt: now - 1000 + i,
    probeSource: 'phase0' as const,
  }))
  const resSingle524 = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_A, ORIGIN_B],
    observedExchanges: [
      ...exchangesA,
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/heavy', createdAt: now, probeSource: 'phase0' },
    ],
    personas: [{ handle: 'alice', originAllowlist: [ORIGIN_A, ORIGIN_B] }],
    nowMs: now,
  })
  assert.equal(resSingle524.quarantinedSet.has(ORIGIN_B), false, 'single 524 must NEVER quarantine origin B')
  assert.deepEqual(resSingle524.activeOrigins, [ORIGIN_A, ORIGIN_B])

  // Case B: 3x524 on a single path fails minDistinctPaths >= 2.
  const resSinglePath = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_B],
    observedExchanges: [
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/slow', createdAt: now - 2000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/slow?attempt=2', createdAt: now - 1000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/slow?attempt=3', createdAt: now, probeSource: 'phase0' },
    ],
    nowMs: now,
  })
  assert.equal(resSinglePath.quarantinedSet.has(ORIGIN_B), false, '524s on only 1 distinct path must not quarantine')

  // Case C: 3x524 across 3 paths from investigation worker traffic (NOT host/Phase-0 probes) NEVER quarantines.
  const resWorkerTraffic = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_B],
    observedExchanges: [
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/a', createdAt: now - 2000, assignmentPhase: 'investigation' },
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/b', createdAt: now - 1000, assignmentPhase: 'investigation' },
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/c', createdAt: now, assignmentPhase: 'investigation' },
    ],
    nowMs: now,
  })
  assert.equal(resWorkerTraffic.quarantinedSet.has(ORIGIN_B), false, 'worker traffic alone must never quarantine an origin')

  // Case D: 3x524 spread wider than originQuarantineWindowMs (300s) NEVER quarantines.
  const resOutsideWindow = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_B],
    observedExchanges: [
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/a', createdAt: now - 700_000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/b', createdAt: now - 350_000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 524, pathAndQuery: '/c', createdAt: now, probeSource: 'phase0' },
    ],
    nowMs: now,
  })
  assert.equal(resOutsideWindow.quarantinedSet.has(ORIGIN_B), false, 'probes outside windowMs must not trigger quarantine')

  // Case E: 3x524 across >=2 distinct paths from Phase-0 host probes within window with zero live responses DOES quarantine.
  const resConfirmedDead = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_B],
    observedExchanges: [
      { origin: ORIGIN_B, status: 525, pathAndQuery: '/', createdAt: now - 2000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 525, pathAndQuery: '/health', createdAt: now - 1000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 525, pathAndQuery: '/api', createdAt: now, probeSource: 'phase0' },
    ],
    nowMs: now,
  })
  assert.equal(resConfirmedDead.quarantined.get(ORIGIN_B)?.reason, 'unreachable')
  assert.equal(resConfirmedDead.quarantined.get(ORIGIN_B)?.source, 'telemetry_52x_dead')

  // Case F: 3x401 across >=2 distinct paths with 0 personas and 0 live responses DOES quarantine as edge_protected,
  // but 2x401 across 2 paths does NOT (< originQuarantineMin401Count=3).
  const resTwo401 = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_B],
    observedExchanges: [
      { origin: ORIGIN_B, status: 401, pathAndQuery: '/', createdAt: now - 1000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 401, pathAndQuery: '/api', createdAt: now, probeSource: 'phase0' },
    ],
    nowMs: now,
  })
  assert.equal(resTwo401.quarantinedSet.has(ORIGIN_B), false, '2x401 is below originQuarantineMin401Count=3')

  const resThree401 = detectQuarantinedOrigins({
    approvedOrigins: [ORIGIN_B],
    observedExchanges: [
      { origin: ORIGIN_B, status: 401, pathAndQuery: '/', createdAt: now - 2000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 401, pathAndQuery: '/api', createdAt: now - 1000, probeSource: 'phase0' },
      { origin: ORIGIN_B, status: 401, pathAndQuery: '/status', createdAt: now, probeSource: 'phase0' },
    ],
    nowMs: now,
  })
  assert.equal(resThree401.quarantined.get(ORIGIN_B)?.reason, 'edge_protected')
})

test('R4-H-11.2: SQLite window-scroll guard — 260 rows on origin A never scroll origin B live 200 out of quarantine evaluation', async t => {
  const { storage } = makeStore(t, 'kovo-r4-h11-window-scroll-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!
  const assetB = run.candidates.find(c => c.origin === ORIGIN_B)!
  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  const phase0Worker = storage.makeWorker(run, 'threat_model', assetB, 'Phase-0 probe', 'Baseline probe', { sourceOrigins: [ORIGIN_A, ORIGIN_B] })
  const baseTs = Date.now() - 60_000

  // Origin B returns an early live 200 at baseTs.
  insertBrokerExchangeRow(storage, {
    id: 'ex-b-live-0',
    runId,
    assignmentId: phase0Worker.id,
    origin: ORIGIN_B,
    pathAndQuery: '/health',
    status: 200,
    createdAt: baseTs,
  })

  // Origin A generates 260 rows (> old global LIMIT 240), pushing Origin B's 200 out of any global 240 window.
  for (let i = 0; i < 260; i += 1) {
    insertBrokerExchangeRow(storage, {
      id: `ex-a-${i}`,
      runId,
      assignmentId: phase0Worker.id,
      origin: ORIGIN_A,
      pathAndQuery: `/api/a/${i}`,
      status: 200,
      createdAt: baseTs + 1000 + i,
    })
  }

  // Later, Origin B gets 3x524 across 3 distinct paths.
  for (let j = 0; j < 3; j += 1) {
    insertBrokerExchangeRow(storage, {
      id: `ex-b-524-${j}`,
      runId,
      assignmentId: phase0Worker.id,
      origin: ORIGIN_B,
      pathAndQuery: `/heavy/${j}`,
      status: 524,
      createdAt: baseTs + 20_000 + j * 1000,
    })
  }

  const quarantined = reconPlanner.getQuarantinedOriginSet(storage.run(runId))
  assert.equal(quarantined.has(ORIGIN_B), false, 'earlier live 200 on origin B must NEVER be scrolled out by 260 rows on origin A')
  assert.equal(quarantined.has(ORIGIN_A), false)
  assert.ok(assetA && assetB)
})

// ============================================================================
// 2. R4-H-11 & R4-H-12: Release on live response + step restoration
// ============================================================================

test('R4-H-11.3 + R4-H-12.1: unreachable origin releases automatically on a later live response and restores quarantined steps', async t => {
  const { storage } = makeStore(t, 'kovo-r4-h11-release-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!
  const assetB = run.candidates.find(c => c.origin === ORIGIN_B)!
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  // Seed a ready step on origin B, a same-origin dependent on origin B, and a cross-origin dependent on live origin A.
  const stepB = storage.addChainStep(run, {
    title: 'Inspect origin B orders',
    hypothesis: 'Check access control on origin B',
    category: 'broken-access-control',
    targetAssetIds: [assetB.id],
    sourceOrigins: [ORIGIN_B],
  })
  const depB = storage.addChainStep(run, {
    title: 'Follow-up origin B export',
    hypothesis: 'Depends on origin B orders step',
    category: 'broken-access-control',
    targetAssetIds: [assetB.id],
    dependsOnStepIds: [stepB.id],
    sourceOrigins: [ORIGIN_B],
  })
  const depCrossOrigin = storage.addChainStep(run, {
    title: 'Cross-origin follow-up on live origin A',
    hypothesis: 'Depends on origin B step but targets live origin A',
    category: 'broken-access-control',
    targetAssetIds: [assetA.id],
    dependsOnStepIds: [stepB.id],
    sourceOrigins: [ORIGIN_A],
  })
  assert.equal(stepB.status, 'ready')
  assert.equal(depB.status, 'pending')
  assert.equal(depCrossOrigin.status, 'pending')

  // Quarantine origin B as `unreachable` from Phase-0.
  reconPlanner.refreshQuarantinedOriginsFromPhase0(storage.run(runId), {
    skippedDeadHosts: [{ origin: ORIGIN_B, reason: '525 TLS handshake failed across 3 paths', requestsUsed: 3 }],
  })
  assert.equal(reconPlanner.getQuarantinedOriginSet(storage.run(runId)).has(ORIGIN_B), true)

  // Same-origin non-running steps transition to `blocked`; cross-origin dependent transitions to `tainted`.
  const whileQuarantined = storage.listChainSteps(runId, run.goalRevision)
  assert.equal(whileQuarantined.find(s => s.id === stepB.id)?.status, 'blocked')
  assert.equal(whileQuarantined.find(s => s.id === depB.id)?.status, 'blocked')
  assert.equal(whileQuarantined.find(s => s.id === depCrossOrigin.id)?.status, 'tainted')

  // Later, a live HTTP 200 arrives for origin B in broker_exchanges.
  const probeWorker = storage.makeWorker(run, 'investigation', assetB, 'Recovery check', 'Check liveness', { sourceOrigins: [ORIGIN_B] })
  insertBrokerExchangeRow(storage, {
    id: 'ex-b-recovered-200',
    runId,
    assignmentId: probeWorker.id,
    origin: ORIGIN_B,
    pathAndQuery: '/health',
    status: 200,
    createdAt: Date.now() + 1000,
  })

  // Calling getQuarantinedOriginSet automatically releases `unreachable` and restores the steps!
  const afterRecovery = reconPlanner.getQuarantinedOriginSet(storage.run(runId))
  assert.equal(afterRecovery.has(ORIGIN_B), false, 'live 200 response must release unreachable quarantine automatically')

  const restoredSteps = storage.listChainSteps(runId, run.goalRevision)
  assert.equal(restoredSteps.find(s => s.id === stepB.id)?.status, 'ready', 'quarantined step must restore to ready')
  assert.equal(restoredSteps.find(s => s.id === depB.id)?.status, 'pending', 'same-origin dependent must restore to pending')
  assert.equal(restoredSteps.find(s => s.id === depCrossOrigin.id)?.status, 'pending', 'cross-origin dependent tainted solely by quarantine must restore to pending')

  const events = storage.eventsAfter(runId, 0, 100)
  assert.ok(events.some(e => e.kind === 'planner.origin_unquarantined'), 'must emit planner.origin_unquarantined telemetry')
  assert.ok(events.some(e => e.kind === 'scheduler.steps_restored_origin_unquarantined'), 'must emit restore telemetry')
})

// ============================================================================
// 3. R4-H-12: Live + quarantined origin with ready step drains to verification
// ============================================================================

test('R4-H-12.2: run with live origin + quarantined origin holding a ready step drains cleanly and advances to verification (zero wedge)', async t => {
  const { storage } = makeStore(t, 'kovo-r4-h12-live-plus-quarantined-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!
  const assetB = run.candidates.find(c => c.origin === ORIGIN_B)!
  storage.updateRun(runId, { phase: 'investigation', status: 'running', roundNo: 2 })

  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => engine.stop())
  const { reconPlanner, plannerDoneRound, plannerDirty, tierAFactIds } = internals(engine)

  // Live origin A completed its step cleanly.
  const stepA = storage.addChainStep(run, {
    title: 'Origin A live check',
    hypothesis: 'Verify origin A endpoint',
    category: 'broken-access-control',
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
  })
  const wA = storage.makeWorker(run, 'investigation', assetA, stepA.title, stepA.hypothesis, { stepId: stepA.id, sourceOrigins: [ORIGIN_A] })
  storage.updateChainStep(stepA.id, { status: 'complete', assignedWorkerId: wA.id })

  // Origin B has a ready step, a pending dependent, AND a Tier-A lead fact — then origin B is quarantined.
  const stepB = storage.addChainStep(run, {
    title: 'Origin B quarantined check',
    hypothesis: 'Verify origin B endpoint',
    category: 'broken-access-control',
    targetAssetIds: [assetB.id],
    sourceOrigins: [ORIGIN_B],
  })
  const stepBChild = storage.addChainStep(run, {
    title: 'Origin B follow-up check',
    hypothesis: 'Depends on origin B check',
    category: 'broken-access-control',
    targetAssetIds: [assetB.id],
    dependsOnStepIds: [stepB.id],
    sourceOrigins: [ORIGIN_B],
  })
  const stepBCrossOriginChild = storage.addChainStep(run, {
    title: 'Origin A follow-up depending on quarantined origin B',
    hypothesis: 'Depends on origin B check',
    category: 'broken-access-control',
    targetAssetIds: [assetA.id],
    dependsOnStepIds: [stepB.id],
    sourceOrigins: [ORIGIN_A],
  })
  reconPlanner.registerStepTargets(runId, stepB.id, [
    { origin: ORIGIN_B, method: 'GET', route: '/api/secret', vulnClass: 'broken-access-control' },
  ])
  const tierAFactB = storage.addFact(run, wA, {
    kind: 'note',
    origin: ORIGIN_B,
    summary: 'Tier-A lead on quarantined origin B',
    data: { subkind: 'det_lead', tier: 'A', method: 'GET', endpoint: '/api/secret' },
  })
  tierAFactIds.add(tierAFactB.id)

  // Quarantine origin B (uniform 401 edge wall with no persona).
  reconPlanner.refreshQuarantinedOriginsFromPhase0(storage.run(runId), {
    edgeProtectedOrigins: [{ origin: ORIGIN_B, reason: 'Cloudflare Access 401 wall', status: 401, requestsUsed: 3 }],
  })

  // Shared predicates must agree BEFORE and AFTER driveInvestigation:
  const unavailable = reconPlanner.unavailableOriginsForRun(storage.run(runId))
  assert.equal(unavailable.has(ORIGIN_B), true)
  assert.equal(isStepOriginUnavailable(stepB, unavailable), true)
  assert.equal(isStepOriginUnavailable(stepA, unavailable), false)

  const stepsNow = storage.listChainSteps(runId, run.goalRevision)
  assert.equal(stepsNow.find(s => s.id === stepB.id)?.status, 'blocked', 'quarantined ready step must become terminal blocked')
  assert.equal(stepsNow.find(s => s.id === stepBChild.id)?.status, 'blocked', 'same-origin quarantined pending step must become terminal blocked')
  assert.equal(stepsNow.find(s => s.id === stepBCrossOriginChild.id)?.status, 'tainted', 'cross-origin dependent of quarantined step must become tainted')
  assert.equal(dispatchableReadySteps(stepsNow, undefined, unavailable).length, 0)
  assert.equal(hasActiveInvestigationSteps(stepsNow, undefined, unavailable), false)

  const coverage = reconPlanner.passOneCoverageFor(storage.run(runId), stepsNow)
  assert.deepEqual(coverage.uncoveredTierAEndpoints, [], 'Tier-A leads on quarantined origins must not block stop')
  assert.deepEqual(coverage.uninvestigatedFirstPassClasses, [], 'quarantined steps must not keep Pass-1 coverage open')

  const stopEval = evaluateDispatchStop({
    decision: 'stop',
    reason: 'coordinator_done',
    remainingReady: dispatchableReadySteps(stepsNow, undefined, unavailable).length,
    freeSlots: 4,
    inFlight: 0,
    uninvestigatedFirstPassClasses: coverage.uninvestigatedFirstPassClasses,
    uncoveredTierAEndpoints: coverage.uncoveredTierAEndpoints,
  })
  assert.equal(stopEval.decision, 'stop', 'evaluateDispatchStop must NOT defer stop on quarantined steps')
  assert.equal(stopEval.deferred, false)

  // Simulate planner stop decision for roundNo=2 and invoke driveInvestigation -> advances to verification!
  plannerDoneRound.set(runId, 2)
  plannerDirty.delete(runId)
  internals(engine).driveInvestigation(storage.run(runId), [{ id: 'stub-profile' }])

  const afterDrive = storage.run(runId)
  assert.equal(afterDrive.phase, 'verification', 'run with live + quarantined origins must advance to verification with zero wedge')

  // Also verify circuit-open steps share the exact same `reconcileUnavailableOriginSteps` primitive.
  const { runId: cbRunId, run: cbRun } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const cbAssetA = cbRun.candidates.find(c => c.origin === ORIGIN_A)!
  const cbAssetB = cbRun.candidates.find(c => c.origin === ORIGIN_B)!
  const cbStep = storage.addChainStep(cbRun, {
    title: 'Circuit-open step',
    hypothesis: 'Check origin A under circuit break',
    targetAssetIds: [cbAssetA.id],
    sourceOrigins: [ORIGIN_A],
  })
  const cbSameOriginDep = storage.addChainStep(cbRun, {
    title: 'Circuit-open same-origin dependent',
    hypothesis: 'Depends on circuit-open step on origin A',
    targetAssetIds: [cbAssetA.id],
    dependsOnStepIds: [cbStep.id],
    sourceOrigins: [ORIGIN_A],
  })
  const cbCrossOriginDep = storage.addChainStep(cbRun, {
    title: 'Circuit-open cross-origin dependent',
    hypothesis: 'Depends on circuit-open step from live origin B',
    targetAssetIds: [cbAssetB.id],
    dependsOnStepIds: [cbStep.id],
    sourceOrigins: [ORIGIN_B],
  })
  const rec = reconcileUnavailableOriginSteps({
    storage,
    run: cbRun,
    circuitOpenOrigins: new Set([ORIGIN_A]),
  })
  assert.deepEqual(rec.blockedForCircuitIds.sort(), [cbStep.id, cbSameOriginDep.id].sort())
  assert.equal(rec.refreshed, true)
  const cbStepsAfter = storage.listChainSteps(cbRunId, cbRun.goalRevision)
  assert.equal(cbStepsAfter.find(s => s.id === cbStep.id)?.status, 'blocked')
  assert.equal(cbStepsAfter.find(s => s.id === cbSameOriginDep.id)?.status, 'blocked')
  assert.equal(cbStepsAfter.find(s => s.id === cbCrossOriginDep.id)?.status, 'tainted')
})

// ============================================================================
// 4. R4-H-13: Exhaustive terminal parent status matrix + multi-trial + backstop
// ============================================================================

test('R4-H-13.1: exhaustive terminal parent status matrix in BOTH addChainStep and refreshReadyChainSteps (zero stranded pending)', async t => {
  const { storage } = makeStore(t, 'kovo-r4-h13-exhaustive-')
  assert.equal(chainStepTerminalStatuses.length, 9, 'all 9 terminal statuses in STEP_STATUS must be covered')

  for (const terminalStatus of chainStepTerminalStatuses) {
    const meta = STEP_STATUS[terminalStatus]
    assert.equal(meta.terminal, true)

    // Path A: Parent already terminal BEFORE child is created via `addChainStep`.
    {
      const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
      const asset = run.candidates.find(c => c.origin === ORIGIN_A)!
      const parent = storage.addChainStep(run, {
        title: `Pre-terminal parent (${terminalStatus})`,
        hypothesis: 'Parent',
        targetAssetIds: [asset.id],
        sourceOrigins: [ORIGIN_A],
      })
      storage.client.prepare('update chain_steps set status = ? where id = ?').run(terminalStatus, parent.id)

      const child = storage.addChainStep(run, {
        title: `Child created after parent=${terminalStatus}`,
        hypothesis: 'Child',
        targetAssetIds: [asset.id],
        dependsOnStepIds: [parent.id],
        sourceOrigins: [ORIGIN_A],
      })
      assert.notEqual(child.status, 'pending', `addChainStep(parent=${terminalStatus}) must NEVER leave child pending`)
      if (stepSatisfiesDependency(terminalStatus)) {
        assert.equal(child.status, 'ready')
      } else if (stepKillsDependents(terminalStatus)) {
        assert.equal(child.status, 'tainted')
      } else {
        assert.equal(stepBlocksDependent(terminalStatus), true)
        assert.equal(child.status, 'blocked')
      }
      assert.equal(storage.listChainSteps(runId, run.goalRevision).some(s => s.status === 'pending'), false)
    }

    // Path B: Child created `pending` while parent is `ready`, then parent transitions to terminalStatus and `refreshReadyChainSteps` runs.
    {
      const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
      const asset = run.candidates.find(c => c.origin === ORIGIN_A)!
      const parent = storage.addChainStep(run, {
        title: `Parent (${terminalStatus})`,
        hypothesis: 'Parent',
        targetAssetIds: [asset.id],
        sourceOrigins: [ORIGIN_A],
      })
      const child = storage.addChainStep(run, {
        title: `Pending child (${terminalStatus})`,
        hypothesis: 'Child',
        targetAssetIds: [asset.id],
        dependsOnStepIds: [parent.id],
        sourceOrigins: [ORIGIN_A],
      })
      assert.equal(child.status, 'pending')
      storage.client.prepare('update chain_steps set status = ? where id = ?').run(terminalStatus, parent.id)

      storage.refreshReadyChainSteps(runId, run.goalRevision)
      const postChild = storage.listChainSteps(runId, run.goalRevision).find(s => s.id === child.id)!
      assert.notEqual(postChild.status, 'pending', `refreshReadyChainSteps(parent=${terminalStatus}) must NEVER leave child pending`)
      if (stepSatisfiesDependency(terminalStatus)) {
        assert.equal(postChild.status, 'ready')
      } else {
        assert.equal(isTerminalStepStatus(postChild.status), true)
        assert.equal(postChild.status, stepKillsDependents(terminalStatus) ? 'tainted' : 'blocked')
      }
    }
  }
})

test('R4-H-13.2: expandEligibleMultiTrialSteps preserves ready status on trial siblings of retry steps with turn_capped parent', async t => {
  const { storage } = makeStore(t, 'kovo-r4-h13-multitrial-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
  const asset = run.candidates.find(c => c.origin === ORIGIN_A)!
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 4, multiTrialEnabled: true })

  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => engine.stop())

  // Parent hit `turn_capped`; explicit retry step is `ready` with `dependsOnStepIds: [parent.id]`.
  const parent = storage.addChainStep(run, {
    title: 'Turn-capped parent step',
    hypothesis: 'Check access control on /api/v1/admin',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN_A],
  })
  storage.updateChainStep(parent.id, { status: 'turn_capped' })

  const retryStep = storage.addChainStep(run, {
    title: 'Turn-capped parent step [retry #1]',
    hypothesis: 'Retry access control check on /api/v1/admin',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: [asset.id],
    skills: ['cq5:retry:1'],
    dependsOnStepIds: [parent.id],
    sourceOrigins: [ORIGIN_A],
  })
  storage.updateChainStep(retryStep.id, { status: 'ready' })

  internals(engine).expandEligibleMultiTrialSteps(storage.run(runId))

  const afterExpand = storage.listChainSteps(runId, run.goalRevision)
  const siblings = afterExpand.filter(s => s.id !== parent.id && s.id !== retryStep.id)
  assert.ok(siblings.length >= 1, 'expected multi-trial expansion to fan out surplus trial sibling')
  for (const sib of siblings) {
    assert.equal(sib.status, 'ready', 'trial sibling of a ready retry step must be ready (never stranded pending/blocked)')
  }
})

test('R4-H-13.3: run-level stranded-step backstop advances to verification and emits structured telemetry instead of wedging', async t => {
  const { storage } = makeStore(t, 'kovo-r4-h13-backstop-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
  const asset = run.candidates.find(c => c.origin === ORIGIN_A)!
  storage.updateRun(runId, { phase: 'investigation', status: 'running', roundNo: 3 })

  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => engine.stop())
  const { plannerDoneRound, plannerDirty } = internals(engine)

  // Construct a mutual dependency cycle A <-> B both stuck in `pending` (0 ready, 0 running, 0 active workers).
  const stepA = storage.addChainStep(run, {
    title: 'Cyclic step A',
    hypothesis: 'Depends on B',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN_A],
  })
  const stepB = storage.addChainStep(run, {
    title: 'Cyclic step B',
    hypothesis: 'Depends on A',
    targetAssetIds: [asset.id],
    dependsOnStepIds: [stepA.id],
    sourceOrigins: [ORIGIN_A],
  })
  storage.client.prepare('update chain_steps set status = ?, depends_on_step_ids = ? where id = ?')
    .run('pending', JSON.stringify([stepB.id]), stepA.id)
  storage.client.prepare('update chain_steps set status = ?, depends_on_step_ids = ? where id = ?')
    .run('pending', JSON.stringify([stepA.id]), stepB.id)

  const preSteps = storage.listChainSteps(runId, run.goalRevision)
  assert.deepEqual(
    permanentlyBlockedStepIds(preSteps).sort(),
    [stepA.id, stepB.id].sort(),
    'cycle A <-> B must be detected as permanently blocked',
  )
  assert.deepEqual(dispatchableReadySteps(preSteps), [])
  assert.equal(hasActiveInvestigationSteps(preSteps), false)

  // Planner already decided stop for roundNo=3; driveInvestigation must trigger the backstop and advance.
  plannerDoneRound.set(runId, 3)
  plannerDirty.delete(runId)
  internals(engine).driveInvestigation(storage.run(runId), [{ id: 'stub-profile' }])

  assert.equal(storage.run(runId).phase, 'verification', 'run-level backstop must advance to verification instead of wedging')
  const backstopEvent = storage.eventsAfter(runId, 0, 100).find(e => e.kind === 'scheduler.stranded_steps_backstop')
  assert.ok(backstopEvent, 'run-level backstop must emit scheduler.stranded_steps_backstop telemetry')
  const detail = backstopEvent.detail as { strandedCount?: number; strandedStepIds?: string[] }
  assert.equal(detail.strandedCount, 2)
  assert.deepEqual((detail.strandedStepIds ?? []).sort(), [stepA.id, stepB.id].sort())
})

// ============================================================================
// 5. R4-H-8 & R4-H-16: Production caller contracts (`runId` & off-host worker)
// ============================================================================

test('R4-H-8 + R4-H-16: execution.ts passes runId to repo-mounting openSession and exec-recon-planner.ts uses synthesizeInvariantsInWorker', async t => {
  t.after(async () => {
    await closeSharedUntrustedComputePool()
  })

  // R4-H-8 static guard: every `backend.openSession(..., { ...reposDir... })` in execution.ts passes `runId`.
  const execSource = readFileSync(resolve('src/server/execution.ts'), 'utf8')
  const openSessionCalls = [...execSource.matchAll(/this\.backend\.openSession\([^)]*\)/g)].map(m => m[0])
  assert.ok(openSessionCalls.length >= 1, 'expected at least one backend.openSession call in execution.ts')
  for (const call of openSessionCalls) {
    if (call.includes('reposDir')) {
      assert.match(call, /\brunId\s*:/, `repo-mounting openSession call must pass explicit runId: ${call}`)
    }
  }

  // R4-H-16 static guard: exec-recon-planner.ts calls `synthesizeInvariantsInWorker`, never synchronous `synthesizeInvariants(`.
  const plannerSource = readFileSync(resolve('src/server/exec-recon-planner.ts'), 'utf8')
  assert.match(plannerSource, /import\s*\{[^}]*\bsynthesizeInvariantsInWorker\b[^}]*\}\s*from\s*['"]\.\/untrusted-compute-pool\.ts['"]/)
  assert.match(plannerSource, /await\s+synthesizeInvariantsInWorker\s*\(/)
  assert.doesNotMatch(plannerSource, /(?<!await\s+)\bsynthesizeInvariants\s*\(\s*\{/, 'exec-recon-planner.ts must not call synchronous synthesizeInvariants on host thread')

  // R4-H-16 live worker-pool execution check through `seedCapabilityLedgerInvariants` in white-box mode.
  const { storage } = makeStore(t, 'kovo-r4-h16-worker-')
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A], tier: 2 })
  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => engine.stop())
  const { reconPlanner } = internals(engine)

  const seeded = await reconPlanner.seedCapabilityLedgerInvariants(run, {
    mode: 'white-box',
    promoteWave1Chains: false,
    sourceFiles: [
      {
        path: 'app/routes/orders.ts',
        content: [
          'import express from "express"',
          'const router = express.Router()',
          'router.get("/api/orders/:id", requireAuth, (req, res) => res.json({ id: req.params.id }))',
          'router.delete("/api/orders/:id", (req, res) => res.json({ deleted: req.params.id }))',
          'export default router',
        ].join('\n'),
      },
    ],
  })
  assert.equal(seeded.mode, 'white-box')
  assert.ok(seeded.synthesis, 'white-box seedCapabilityLedgerInvariants must return synthesis from UntrustedComputePool worker')
})
