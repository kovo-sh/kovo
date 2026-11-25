import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'
import { runCommand } from '../src/domain.ts'
import { StateChangeApprovalLedger } from '../src/server/approval-judge.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  computePlannerBackoffMs,
  Execution,
  PLANNER_BACKOFF_BASE_MS,
  PLANNER_BACKOFF_CAP_MS,
} from '../src/server/execution.ts'
import { GlobalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import { approvalRequests } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDRESS = { address: '93.184.216.34', family: 4 }

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-t1-lifecycle-wedges-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function makeBroker(
  calls: Array<{ method: string; url: string }> = [],
  killSwitch?: GlobalKillSwitch,
): RequestBroker {
  return new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string }) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
    ...(killSwitch ? { killSwitch } : {}),
  })
}

async function waitFor(predicate: () => boolean, timeoutMs = 5_000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

function createApprovedRun(
  storage: Store,
  opts: {
    tier?: 0 | 1 | 2 | 3
    approvalPolicy?: 'auto_review' | 'yolo' | 'strict'
    phase?: 'investigation' | 'verification'
    tenantId?: string
  } = {},
) {
  const project = storage.createProject({
    requestId: randomUUID(),
    name: `T1 Wedges ${randomUUID().slice(0, 6)}`,
    seeds: [APP_ORIGIN],
    environment: 'public',
  })
  if (opts.tenantId) {
    storage.setProjectTenant(project.id, opts.tenantId)
  }
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify Tier 1 lifecycle wedge fixes',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 3,
    ...(opts.approvalPolicy ? { approvalPolicy: opts.approvalPolicy } : {}),
  } as Parameters<Store['createRun']>[0])
  storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = storage.run(runId)
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
  }))
  storage.updateRun(runId, { phase: opts.phase ?? 'investigation', status: 'running' })
  return { projectId: project.id, runId, run: storage.run(runId) }
}

// ---------------------------------------------------------------------------
// 1. H-27: Failed verification workers settle cleanly instead of hanging runs
// ---------------------------------------------------------------------------

test('H-27: a run with a failed verification worker finalizes cleanly instead of hanging', async t => {
  const storage = makeStorage(t)
  const { runId, run } = createApprovedRun(storage, { tier: 2, phase: 'verification' })

  const execution = new Execution(storage, {
    broker: makeBroker(),
    deterministicSweep: false,
  })
  t.after(() => execution.stop())

  // Simulate a live baseline verification worker whose execution throws and transitions to `failed`.
  const priv = execution as unknown as Record<string, any>
  priv.verifier.verifyBaselineJob = async () => {
    throw new Error('simulated verifier container failure')
  }

  execution.wake()

  await waitFor(
    () => {
      const latest = storage.run(runId)
      return latest.status === 'complete' && latest.phase === 'complete'
    },
    5_000,
    'run finalization after failed verification worker',
  )

  const verificationWorkers = storage.workerList(runId).filter(w => w.phase === 'verification')
  assert.equal(verificationWorkers.length, 1, 'failed verification worker must not spawn duplicate replacements')
  assert.equal(verificationWorkers[0]!.status, 'failed')
  assert.equal(storage.run(runId).status, 'complete')
  assert.equal(storage.run(runId).phase, 'complete')
  assert.ok(run.approved.length > 0)
})

// ---------------------------------------------------------------------------
// 2. H-28: Operator-denied and expired Tier-3 approvals do not wedge Execution
// ---------------------------------------------------------------------------

test('H-28: operator-denied Tier-3 approval in investigation settles worker + step and advances run', async t => {
  const storage = makeStorage(t)
  await saveModelProfile({
    name: 'Test Denied Approval Model',
    endpoint: 'https://api.example.test/v1',
    model: 'test-model',
    protocol: 'responses',
    key: 'sk-test-denied-key-123456',
    enabled: true,
    priority: 100,
  }, storage, { skipConnectionCheck: true })
  const { runId, run } = createApprovedRun(storage, {
    tier: 3,
    approvalPolicy: 'strict',
    phase: 'investigation',
  })

  const step1 = storage.addChainStep(run, {
    title: 'Tier-3 state-change verification step',
    hypothesis: 'Test operator-denied Tier-3 approval teardown',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [run.candidates[0]!.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [APP_ORIGIN],
  })
  const dependentStep = storage.addChainStep(run, {
    title: 'Downstream step depending on denied step',
    hypothesis: 'Should become tainted instead of staying pending forever',
    category: 'broken-access-control',
    priority: 50,
    targetAssetIds: [run.candidates[0]!.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [step1.id],
    sourceOrigins: [APP_ORIGIN],
  })

  const worker = storage.makeWorker(run, 'investigation', run.candidates[0], step1.title, step1.hypothesis, {
    stepId: step1.id,
    sourceOrigins: [APP_ORIGIN],
  })
  const claimed = storage.updateWorker(worker.id, {
    status: 'running',
    lease: randomUUID(),
    leaseExpiresAt: Date.now() + 60_000,
  })!
  storage.updateChainStep(step1.id, { status: 'running', assignedWorkerId: claimed.id })

  const execution = new Execution(storage, {
    broker: makeBroker(),
    deterministicSweep: false,
  })
  t.after(() => execution.stop())

  const priv = execution as unknown as Record<string, any>
  priv.reconPlanner.startCoordinator = () => undefined
  // Mark planner done for current round so investigation advances directly once no active steps remain.
  priv.plannerDoneRound.set(runId, storage.run(runId).roundNo)
  // Ensure verification finalizes cleanly when phase transitions.
  priv.verifier.verifyBaselineJob = async (job: { assignment: { id: string } }) => {
    storage.updateWorker(job.assignment.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome: 'ok' })
  }

  const job = { assignment: claimed, origins: new Set([APP_ORIGIN]), controller: new AbortController() }
  priv.active.set(claimed.id, job)

  const approvalPromise: Promise<{ approved: boolean }> = priv.waitForTier3Approval(
    job,
    {
      origin: APP_ORIGIN,
      method: 'DELETE',
      pathAndQuery: '/api/items/42',
      rationale: 'Verify denied approval does not wedge investigation',
      requestPreview: 'DELETE /api/items/42',
      secrets: [],
    },
    job.controller.signal,
  )

  await waitFor(
    () => storage.listApprovalRequests(runId).some(r => r.assignmentId === claimed.id && r.status === 'pending'),
    3_000,
    'pending approval request creation',
  )
  const req = storage.listApprovalRequests(runId).find(r => r.assignmentId === claimed.id)!
  assert.equal(storage.worker(claimed.id).status, 'waiting_approval')

  // Operator denies the Tier-3 request.
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: req.id,
    decision: 'denied',
  }))

  const outcome = await approvalPromise
  assert.equal(outcome.approved, false)

  // Worker and chain step must both be terminal immediately, and downstream step must not wedge pending.
  assert.equal(storage.worker(claimed.id).status, 'failed')
  const updatedStep1 = storage.listChainSteps(runId, run.goalRevision).find(s => s.id === step1.id)!
  assert.equal(updatedStep1.status, 'canceled')

  // Scheduler advances out of investigation instead of wedging forever.
  await waitFor(
    () => storage.run(runId).phase !== 'investigation',
    5_000,
    'run advancing past investigation after denied approval',
  )
  const updatedDependent = storage.listChainSteps(runId, run.goalRevision).find(s => s.id === dependentStep.id)!
  assert.equal(updatedDependent.status, 'tainted', 'dependent step must taint instead of wedging pending')
})

test('H-28: expired Tier-3 approval in verification marks worker failed and finalizes run', async t => {
  const storage = makeStorage(t)
  const { runId, run } = createApprovedRun(storage, {
    tier: 3,
    approvalPolicy: 'strict',
    phase: 'verification',
  })

  // Create a baseline verification worker that parked waiting on an approval request that has now expired.
  const worker = storage.makeWorker(run, 'verification', run.candidates[0], 'Baseline verify · app.example.test', 'Verify baseline', {
    sourceOrigins: [APP_ORIGIN],
  })
  storage.parkWorkerForApproval(run, worker.id)
  const req = storage.createApprovalRequest(run, worker, {
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/99',
    rationale: 'Verify expired approval does not wedge verification',
    requestPreview: 'DELETE /api/items/99',
    riskLevel: 'high',
  })
  // Backdate expiry into the past so the approval is already expired.
  storage.db.update(approvalRequests).set({ expiresAt: Date.now() - 1_000 }).where(eq(approvalRequests.id, req.id)).run()

  const execution = new Execution(storage, {
    broker: makeBroker(),
    deterministicSweep: false,
  })
  t.after(() => execution.stop())

  execution.wake()

  await waitFor(
    () => {
      const latest = storage.run(runId)
      return latest.status === 'complete' && latest.phase === 'complete'
    },
    5_000,
    'verification finalization after expired Tier-3 approval',
  )

  assert.equal(storage.getApprovalRequest(runId, req.id).status, 'expired')
  assert.equal(storage.worker(worker.id).status, 'failed')
  assert.equal(storage.run(runId).status, 'complete')
})

// ---------------------------------------------------------------------------
// 3. H-29: Planner exception exponential backoff + consecutive-error breaker
// ---------------------------------------------------------------------------

test('H-29: computePlannerBackoffMs doubles 500ms -> 1s -> 2s -> 4s -> 8s -> 15s cap', () => {
  assert.equal(PLANNER_BACKOFF_BASE_MS, 500)
  assert.equal(PLANNER_BACKOFF_CAP_MS, 15_000)
  assert.equal(computePlannerBackoffMs(0), 0)
  assert.equal(computePlannerBackoffMs(1), 500)
  assert.equal(computePlannerBackoffMs(2), 1_000)
  assert.equal(computePlannerBackoffMs(3), 2_000)
  assert.equal(computePlannerBackoffMs(4), 4_000)
  assert.equal(computePlannerBackoffMs(5), 8_000)
  assert.equal(computePlannerBackoffMs(6), 15_000)
  assert.equal(computePlannerBackoffMs(10), 15_000)
})

test('H-29: repeated planner exceptions back off exponentially and trip consecutive-error breaker instead of hot-looping', async t => {
  const storage = makeStorage(t)
  await saveModelProfile({
    name: 'Test Outage Model',
    endpoint: 'https://api.example.test/v1',
    model: 'test-model',
    protocol: 'responses',
    key: 'sk-test-outage-key-123456',
    enabled: true,
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  const { runId } = createApprovedRun(storage, { tier: 2, phase: 'investigation' })

  const execution = new Execution(storage, {
    broker: makeBroker(),
    deterministicSweep: false,
    plannerBackoffBaseMs: 80,
    plannerBackoffCapMs: 400,
    plannerMaxConsecutiveErrors: 4,
  })
  t.after(() => execution.stop())

  const priv = execution as unknown as Record<string, any>
  // Prevent the background coordinator from making real network calls during the test.
  priv.reconPlanner.startCoordinator = () => undefined
  priv.verifier.verifyBaselineJob = async (job: { assignment: { id: string } }) => {
    storage.updateWorker(job.assignment.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome: 'ok' })
  }

  const attemptTimestamps: number[] = []
  priv.reconPlanner.runChainPlanner = async () => {
    attemptTimestamps.push(Date.now())
    throw new Error('HTTP 503 upstream provider outage')
  }

  execution.wake()

  await waitFor(
    () => storage.run(runId).phase !== 'investigation',
    5_000,
    'planner circuit breaker advancing run after repeated outages',
  )

  // Must have attempted exactly plannerMaxConsecutiveErrors (4) times, never hot-looping beyond the breaker.
  assert.equal(attemptTimestamps.length, 4, `expected exactly 4 planner attempts before breaker tripped, got ${attemptTimestamps.length}`)

  // Verify exponential backoff events recorded growing delays: 80ms -> 160ms -> 320ms, then circuit_open.
  const events = storage.eventsAfter(runId, 0)
  const errorEvents = events.filter(e => e.kind === 'planner.error')
  const openEvents = events.filter(e => e.kind === 'planner.circuit_open')
  assert.equal(errorEvents.length, 3, 'first 3 failures should record planner.error with backoff')
  assert.equal(openEvents.length, 1, '4th failure must emit planner.circuit_open')
  assert.deepEqual(
    errorEvents.map(e => e.detail?.backoffMs),
    [80, 160, 320],
  )

  // Verify real elapsed wall-clock gaps grew exponentially (not 100ms hot loop).
  const gap1 = attemptTimestamps[1]! - attemptTimestamps[0]!
  const gap2 = attemptTimestamps[2]! - attemptTimestamps[1]!
  const gap3 = attemptTimestamps[3]! - attemptTimestamps[2]!
  assert.ok(gap2 > gap1, `expected gap2 (${gap2}ms) > gap1 (${gap1}ms)`)
  assert.ok(gap3 >= 250, `expected 3rd retry gap (${gap3}ms) to honor ~320ms exponential backoff`)

  // Wait briefly to confirm no extra attempts fire after the breaker trips.
  await new Promise(resolve => setTimeout(resolve, 200))
  assert.equal(attemptTimestamps.length, 4, 'breaker must prevent any further planner retries')
})

test('H-29: transient planner error recovers cleanly and resets consecutive error counter on success', async t => {
  const storage = makeStorage(t)
  await saveModelProfile({
    name: 'Test Transient Model',
    endpoint: 'https://api.example.test/v1',
    model: 'test-model',
    protocol: 'responses',
    key: 'sk-test-transient-key-123456',
    enabled: true,
    priority: 100,
  }, storage, { skipConnectionCheck: true })

  const { runId } = createApprovedRun(storage, { tier: 2, phase: 'investigation' })

  const execution = new Execution(storage, {
    broker: makeBroker(),
    deterministicSweep: false,
    plannerBackoffBaseMs: 60,
    plannerBackoffCapMs: 300,
    plannerMaxConsecutiveErrors: 4,
  })
  t.after(() => execution.stop())

  const priv = execution as unknown as Record<string, any>
  priv.reconPlanner.startCoordinator = () => undefined
  priv.verifier.verifyBaselineJob = async (job: { assignment: { id: string } }) => {
    storage.updateWorker(job.assignment.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome: 'ok' })
  }

  let attempts = 0
  priv.reconPlanner.runChainPlanner = async (run: { id: string; roundNo: number }) => {
    attempts += 1
    if (attempts <= 2) {
      throw new Error('transient 502 gateway timeout')
    }
    const nextRound = run.roundNo + 1
    storage.updateRun(run.id, { roundNo: nextRound })
    priv.plannerDoneRound.set(run.id, nextRound)
  }

  execution.wake()

  await waitFor(
    () => storage.run(runId).status === 'complete',
    5_000,
    'run completing after transient planner recovery',
  )

  assert.equal(attempts, 3)
  assert.equal(priv.plannerErrorState.has(runId), false, 'planner error counter must reset after a successful round')
  assert.equal(storage.eventsAfter(runId, 0).filter(e => e.kind === 'planner.circuit_open').length, 0)
})

// ---------------------------------------------------------------------------
// 4. H-2: Grant.tenantId populated from project.tenantId & matches tenant kill-switch
// ---------------------------------------------------------------------------

test('H-2: Execution.buildGrant populates Grant.tenantId from project.tenantId and enforces tenant kill-switch', async t => {
  const storage = makeStorage(t)
  const ks = new GlobalKillSwitch()
  const calls: Array<{ method: string; url: string }> = []
  const execution = new Execution(storage, {
    broker: makeBroker(calls, ks),
    deterministicSweep: false,
  })
  t.after(() => execution.stop())

  const alpha = createApprovedRun(storage, { tier: 2, tenantId: 'tenant-alpha' })
  const beta = createApprovedRun(storage, { tier: 2, tenantId: 'tenant-beta' })
  const defaultRun = createApprovedRun(storage, { tier: 2 })

  const buildGrantFor = (runId: string): Grant => {
    const run = storage.run(runId)
    const created = storage.makeWorker(run, 'investigation', run.candidates[0], 'Tenant worker', 'Verify tenantId', {
      sourceOrigins: [APP_ORIGIN],
    })
    const assignment = storage.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
    const job = { assignment, origins: new Set([APP_ORIGIN]), controller: new AbortController() }
    const priv = execution as unknown as Record<string, any>
    return (priv.buildGrant(job, run, new Set([APP_ORIGIN])) as { grant: Grant }).grant
  }

  const alphaGrant = buildGrantFor(alpha.runId)
  const betaGrant = buildGrantFor(beta.runId)
  const defaultGrant = buildGrantFor(defaultRun.runId)

  assert.equal(alphaGrant.tenantId, 'tenant-alpha')
  assert.equal(betaGrant.tenantId, 'tenant-beta')
  assert.equal(defaultGrant.tenantId, 'default')

  // Trip kill-switch strictly for tenant-alpha: tenant-alpha must be rejected while tenant-beta still runs!
  ks.trip({ tenantId: 'tenant-alpha', reason: 'Emergency stop for alpha', trippedBy: 'operator' })

  await assert.rejects(
    execution.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/health',
    }, alphaGrant, AbortSignal.timeout(5_000)),
    KillSwitchTrippedError,
    'tenant-alpha kill-switch must block requests using alphaGrant',
  )

  const betaRes = await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/health',
  }, betaGrant, AbortSignal.timeout(5_000))
  assert.equal(betaRes.status, 200)
  assert.equal(calls.length, 1)
})

// ---------------------------------------------------------------------------
// 5. L-19: StateChangeApprovalLedger prunes with Date.now() instead of options.expiresAt
// ---------------------------------------------------------------------------

test('L-19: StateChangeApprovalLedger.grant prunes expired entries with Date.now() and preserves active grants', () => {
  const ledger = new StateChangeApprovalLedger()
  const now = Date.now()

  // Insert 100 expired grants + 1950 active grants (>2048 total) to trigger prune().
  for (let i = 0; i < 100; i += 1) {
    ledger.grant(
      { runId: 'run-prune', origin: APP_ORIGIN, method: 'POST', pathAndQuery: `/expired/${i}` },
      { expiresAt: now - 10_000 },
    )
  }
  for (let i = 0; i < 1950; i += 1) {
    ledger.grant(
      { runId: 'run-prune', origin: APP_ORIGIN, method: 'POST', pathAndQuery: `/active/${i}` },
      { expiresAt: now + 30_000 },
    )
  }

  // Insert one more active grant with a later expiry; before L-19, passing options.expiresAt to prune()
  // evicted both the just-inserted grant and all 1950 active entries with earlier expiresAt!
  const freshTarget = {
    runId: 'run-prune',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/active/newest',
  }
  ledger.grant(freshTarget, { expiresAt: now + 60_000 })

  assert.ok(ledger.size <= 2048, `ledger size (${ledger.size}) must stay bounded at <= 2048`)
  assert.equal(ledger.size, 1951, 'only the 100 expired entries should have been pruned; all 1951 active grants stay')
  assert.equal(
    ledger.consume(freshTarget, now),
    true,
    'newly inserted active grant must not be self-pruned',
  )
  assert.equal(
    ledger.consume({ runId: 'run-prune', origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/active/0' }, now),
    true,
    'existing unexpired grants with earlier expiresAt must not be evicted',
  )
})
