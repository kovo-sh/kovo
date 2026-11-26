process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * WS-14 Regression Tests (`plans/CLAUDE_AUDIT_R2.md`):
 *  - R2-H-17: RunActor.isDisposed includes draining/aborted; spawn() returns `{ started: boolean }`;
 *             rejected spawns roll back `active` and DB claims; kill-switch trip->reset recovers.
 *  - R2-H-18 / H-28: Approval waiter abort cancels card & unparks/terminates worker (H-28b);
 *             approved request with no live waiter reconciles without wedging (H-28c);
 *             verification denial marks finding inconclusive (H-28d);
 *             ownership guard protects replacement worker's step (H-28e).
 *  - H-2: GlobalKillSwitch.reset() clears global only while preserving per-tenant trips;
 *             resetAll() lifts all scopes and audits releasedTenants; monotonic generation merge
 *             prevents concurrent write drop; persistence failure still notifies listeners.
 *  - H-27: Verification worker retries once (bounded attempts=2), marks exhausted pending findings
 *             inconclusive, writes `partial: true` report with explicit gap lines, and lease
 *             watchdog reclaims orphaned expired verification leases.
 *  - R2-H-24: `execution.ts` awaits `buildStaticWorkspaceSnapshotInWorker(...)` with abort/timeout.
 *  - Warm-pool eviction: `Execution.disposeRun(runId)` invokes `backend.evictRunWarmPool(runId)`.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { and, eq } from 'drizzle-orm'
import { runCommand, type Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { GlobalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import { RunActor, type RunTier3ApprovalCoordinator } from '../src/server/run-actor.ts'
import { approvalRequests, findings } from '../src/server/schema.ts'
import { buildStaticWorkspaceSnapshotInWorker } from '../src/server/static-workspace-snapshot.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const ORIGIN_A = 'https://ws14-a.example.test'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-ws14-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => { rmSync(dir, { recursive: true, force: true }) })
  return dir
}

function makeTempStore(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-ws14-store-'): { dir: string; store: Store } {
  const dir = makeTempDir(t, prefix)
  const store = new Store(dir)
  t.after(() => { try { store.close() } catch { /* already closed */ } })
  return { dir, store }
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function stubBackend(onEvictWarmPool?: (runId: string) => void): WorkerBackend {
  return {
    openSession: async () => ({
      stage: async (name: string) => `/work/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async () => ({ repo: 'app', enginesRun: [], engineStatus: {}, findings: [], durationMs: 1 }),
      runScript: async () => ({ runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 }),
      close: async () => undefined,
    }),
    evictRunWarmPool: async (runId: string) => {
      onEvictWarmPool?.(runId)
    },
  } as unknown as WorkerBackend
}

function createApprovedRun(
  store: Store,
  opts: {
    origin?: string
    phase?: 'threat_model' | 'investigation' | 'verification'
    tier?: 0 | 1 | 2 | 3
    approvalPolicy?: 'strict' | 'auto_review' | 'yolo'
    tenantId?: string
  } = {},
) {
  const origin = opts.origin ?? ORIGIN_A
  const project = store.createProject({
    requestId: randomUUID(),
    name: `WS14 Proj ${randomUUID().slice(0, 6)}`,
    seeds: [origin],
    environment: 'public',
  })
  if (opts.tenantId) store.setProjectTenant(project.id, opts.tenantId)
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'WS-14 lifecycle and approval invariants',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 3,
    approvalPolicy: opts.approvalPolicy ?? 'strict',
  } as Parameters<Store['createRun']>[0])
  if (opts.tenantId) store.setRunTenant(runId, opts.tenantId)
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
  }))
  store.updateRun(runId, { phase: opts.phase ?? 'investigation', status: 'running' })
  return { projectId: project.id, runId, run: store.run(runId) }
}

async function waitFor(predicate: () => boolean, timeoutMs = 4_000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 15))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

function seedPendingReplayFinding(store: Store, runId: string, origin = ORIGIN_A) {
  const run = store.run(runId)
  const asset = run.candidates[0]!
  const invWorker = store.makeWorker(run, 'investigation', asset, 'inv-seed', 'seed finding', {
    sourceOrigins: [origin],
  })
  const ex = store.recordExchange({
    runId,
    assignmentId: invWorker.id,
    scopeRevision: run.scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/api/items/1',
    personaHandle: null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"id":1}',
    durationMs: 5,
  })
  const spec: DeclarativeReplaySpec = {
    kind: 'http_assert',
    description: 'Check access control on /api/items/1',
    origin,
    requests: [{
      id: 'r1',
      origin,
      method: 'GET',
      pathAndQuery: '/api/items/1',
      expect: { status: [200] },
    }],
    successCondition: 'r1 status 200',
  } as unknown as DeclarativeReplaySpec
  const findingId = randomUUID()
  const specRow = store.createReplaySpec(run, invWorker, findingId, spec, [origin])
  const finding: Finding = {
    id: findingId,
    origin,
    title: 'Pending chain finding for WS-14 verification test',
    severity: 'high',
    confidence: 'medium',
    status: 'pending',
    reason: 'Proposed access-control issue pending replay verification.',
    remediation: 'Enforce authorization check.',
    evidenceIds: [],
    exchangeIds: [ex.id],
    scopeRevision: run.scopeRevision,
    replaySpecId: specRow.id,
  }
  store.upsertChainFinding(run, asset.id, finding, specRow.id, [origin])
  return { asset, invWorker, specRow, findingId }
}

// ============================================================================
// 1. R2-H-17: RunActor draining/aborted isDisposed, spawn.started=false, rollback & kill-switch recovery
// ============================================================================

test('R2-H-17: RunActor.isDisposed includes draining/aborted and spawn() returns started=false while draining', async t => {
  const { dir } = makeTempStore(t, 'kovo-ws14-r2h17-actor-')
  const runtime = createAppRuntime({ dataDir: dir })
  t.after(() => runtime.dispose())

  const ctx = runtime.createRunContext(`run-drain-${randomUUID().slice(0, 8)}`)
  const actor = new RunActor({ context: ctx, initialState: 'investigating' })
  assert.equal(actor.isDisposed, false)
  assert.equal(actor.isDraining, false)

  let releaseBlocker: () => void = () => {}
  const blocker = actor.spawn('slow-blocker', async () => {
    await new Promise<void>(resolve => { releaseBlocker = resolve })
  })
  assert.equal(blocker.started, true)

  // Begin draining without awaiting completion yet
  const drainPromise = actor.drainAndDispose({ terminalState: 'canceled', reason: 'operator stop', timeoutMs: 2_000 })
  assert.equal(actor.isDraining, true, 'actor.isDraining must become true synchronously on drainAndDispose')
  assert.equal(actor.isDisposed, true, 'actor.isDisposed must include draining state (R2-H-17)')
  assert.equal(ctx.isDraining, true, 'RunContext.isDraining must be true while draining')

  let fnRan = false
  const rejected = actor.spawn('during-drain', async () => { fnRan = true })
  assert.equal(rejected.started, false, 'spawn() during drain must return started=false')
  await rejected.promise
  assert.equal(fnRan, false, 'rejected spawn callback must never execute')

  releaseBlocker()
  await drainPromise

  // Aborted context also marks actor disposed and rejects spawns cleanly
  const ctxAborted = runtime.createRunContext(`run-aborted-${randomUUID().slice(0, 8)}`)
  const actorAborted = new RunActor({ context: ctxAborted, initialState: 'investigating' })
  ctxAborted.abort(new Error('kill-switch abort'))
  assert.equal(actorAborted.isDisposed, true, 'actor.isDisposed must be true when context is aborted')
  let abortedFnRan = false
  const abortedTask = actorAborted.spawn('after-abort', async () => { abortedFnRan = true })
  assert.equal(abortedTask.started, false)
  await abortedTask.promise
  assert.equal(abortedFnRan, false)
  await ctxAborted.dispose()
})

test('R2-H-17 / H-27c: rejected dispatch during drain rolls back active/worker/step claims and trip->reset recovers cleanly', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-ws14-r2h17-exec-')
  const runtime = createAppRuntime({ dataDir: dir, store })
  const exec = new Execution(store, {
    runtime,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(async () => {
    await exec.stop()
    await runtime.dispose()
  })

  // --- Part A: Drain-window verification dispatch rollback (H-27c) ---
  const { runId, run } = createApprovedRun(store, { phase: 'verification' })
  const asset = run.candidates[0]!
  const verWorker = store.makeWorker(run, 'verification', asset, 'Baseline verify', 'verify', {
    sourceOrigins: [ORIGIN_A],
  })
  const priv = exec as unknown as {
    ensureRunActor: (id: string) => RunActor
    active: Map<string, unknown>
    claimAndDispatchWorker: (
      r: typeof run,
      w: typeof verWorker,
      prefix: 'worker' | 'retest',
      label: string,
      work: () => Promise<void>,
      skip: boolean,
    ) => boolean
    startInvestigationStep: (r: typeof run, step: ReturnType<Store['addChainStep']>, profiles: readonly unknown[]) => void
    driveVerification: (r: typeof run) => void
  }

  const actor1 = priv.ensureRunActor(runId)
  let releaseDrain: () => void = () => {}
  actor1.spawn('drain-hold', async () => {
    await new Promise<void>(resolve => { releaseDrain = resolve })
  })
  const disposing = exec.disposeRun(runId, { terminalState: 'canceled', reason: 'stop', timeoutMs: 2_000 })
  assert.equal(actor1.isDisposed, true)

  // Attempt to dispatch verification worker during the drain window
  let workRanDuringDrain = false
  const started = priv.claimAndDispatchWorker(
    store.run(runId),
    verWorker,
    'worker',
    'Verification failed',
    async () => { workRanDuringDrain = true },
    true,
  )
  assert.equal(started, false, 'dispatch during drain must return false')
  assert.equal(workRanDuringDrain, false)
  assert.equal(priv.active.has(verWorker.id), false, 'rejected spawn must roll back Execution.active')
  const rolledBackWorker = store.worker(verWorker.id)
  assert.equal(rolledBackWorker.status, 'queued', 'rejected verification worker claim must roll back to queued')
  assert.equal(rolledBackWorker.lease, null, 'rejected verification worker claim must clear lease')

  // Also test investigation step dispatch rollback while draining
  const step = store.addChainStep(store.run(runId), {
    title: 'Drain-window step',
    hypothesis: 'Must roll back to ready if actor is draining',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [asset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN_A],
  })
  priv.startInvestigationStep(store.run(runId), step, [])
  assert.equal(priv.active.size, 0, 'rejected investigation spawn must not leave orphaned active entries')
  const stepAfter = store.listChainSteps(runId, run.goalRevision).find(s => s.id === step.id)!
  assert.equal(stepAfter.status, 'ready', 'rejected investigation spawn must revert chain step back to ready')
  assert.equal(stepAfter.assignedWorkerId, null, 'rejected investigation spawn must clear assignedWorkerId')

  releaseDrain()
  await disposing

  // --- Part B: Kill-switch trip -> reset -> resume never leaves zombie actor ---
  const { runId: ksRunId } = createApprovedRun(store, { phase: 'investigation', tenantId: 'tenant-ws14' })
  const privKs = exec as unknown as {
    ensureRunActor: (id: string) => RunActor
    spawnRunTask: (id: string, label: string, fn: (signal: AbortSignal) => Promise<void>) => { started: boolean; promise: Promise<void | undefined> }
    driveInvestigation: () => void
  }
  privKs.driveInvestigation = () => {}
  const beforeActor = privKs.ensureRunActor(ksRunId)
  assert.equal(beforeActor.signal.aborted, false)

  runtime.killSwitch.trip({ reason: 'Emergency stop for WS-14 test' })
  assert.equal(beforeActor.signal.aborted, true, 'kill-switch trip must abort active RunActor')
  assert.equal(store.run(ksRunId).status, 'paused', 'kill-switch trip must durably pause active run')

  // Reset global kill switch and resume run
  runtime.killSwitch.reset()
  store.command(runCommand.parse({ requestId: randomUUID(), runId: ksRunId, action: 'resume' }))
  exec.wake()

  await waitFor(() => {
    const cur = exec.getRunActor(ksRunId)
    return Boolean(cur && cur !== beforeActor && !cur.isDisposed && !cur.signal.aborted)
  }, 3_000, 'fresh non-aborted RunActor after kill-switch trip -> reset -> resume')

  let ranAfterReset = false
  const resumedTask = privKs.spawnRunTask(ksRunId, 'post-ks-reset', async signal => {
    assert.equal(signal.aborted, false)
    ranAfterReset = true
  })
  assert.equal(resumedTask.started, true, 'spawnRunTask must start on fresh RunActor after kill-switch reset')
  await resumedTask.promise
  assert.equal(ranAfterReset, true)
})

// ============================================================================
// 2. R2-H-18 / H-28: Approval waiter abort cleanup, approved-no-waiter reconcile, denial & ownership guard
// ============================================================================

test('R2-H-18 / H-28b-e: approval abort cancels card, approved-no-waiter reconciles, denial marks finding inconclusive, ownership guard protects replacement step', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-ws14-r2h18-')
  const runtime = createAppRuntime({ dataDir: dir, store })
  const exec = new Execution(store, {
    runtime,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(async () => {
    await exec.stop()
    await runtime.dispose()
  })

  const priv = exec as unknown as {
    tier3Approvals: RunTier3ApprovalCoordinator
    active: Map<string, { assignment: ReturnType<Store['worker']>; origins: Set<string>; controller: AbortController }>
  }

  // --- H-28b: Aborting approval waiter cancels pending approval card & unparks/terminates worker ---
  const { runId: abortRunId, run: abortRun } = createApprovedRun(store, {
    phase: 'investigation',
    tier: 3,
    approvalPolicy: 'strict',
  })
  const abortAsset = abortRun.candidates[0]!
  const abortStep = store.addChainStep(abortRun, {
    title: 'Tier-3 step that times out waiting',
    hypothesis: 'Session wall clock rotates before operator responds',
    category: 'broken-access-control',
    priority: 90,
    targetAssetIds: [abortAsset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN_A],
  })
  const abortWorker = store.updateWorker(
    store.makeWorker(abortRun, 'investigation', abortAsset, 'abort-worker', 'abort-worker', {
      stepId: abortStep.id,
      sourceOrigins: [ORIGIN_A],
    }).id,
    { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
  )!
  store.updateChainStep(abortStep.id, { status: 'running', assignedWorkerId: abortWorker.id })

  const jobController = new AbortController()
  const sessionController = new AbortController()
  const abortJob = { assignment: abortWorker, origins: new Set([ORIGIN_A]), controller: jobController }
  priv.active.set(abortWorker.id, abortJob)

  const waitPromise = priv.tier3Approvals.waitForTier3Approval(abortJob, {
    origin: ORIGIN_A,
    method: 'DELETE',
    pathAndQuery: '/api/items/99',
    rationale: 'Verify deletion authz',
    requestPreview: 'DELETE /api/items/99',
    secrets: [],
  }, sessionController.signal)

  await waitFor(() => store.listApprovalRequests(abortRunId).some(r => r.status === 'pending'), 2_000, 'pending approval card')
  assert.equal(store.worker(abortWorker.id).status, 'waiting_approval')
  assert.equal(abortJob.assignment.lease, null, 'parking worker must update job.assignment to clear stale lease')

  // Abort session signal (simulating 120s wall-clock rotation)
  sessionController.abort(new Error('session wall clock rotated'))
  await assert.rejects(() => waitPromise, /session wall clock rotated/i)

  const cardsAfterAbort = store.listApprovalRequests(abortRunId)
  assert.equal(cardsAfterAbort.length, 1)
  assert.equal(cardsAfterAbort[0]!.status, 'canceled', 'H-28b: waiter abort must cancel pending approval card')
  const workerAfterAbort = store.worker(abortWorker.id)
  assert.equal(workerAfterAbort.status, 'failed', 'H-28b: waiter abort must terminate parked worker')
  assert.equal(workerAfterAbort.approvalParkedAt, null, 'H-28b: waiter abort must clear approvalParkedAt')
  const stepAfterAbort = store.listChainSteps(abortRunId, abortRun.goalRevision).find(s => s.id === abortStep.id)!
  assert.equal(stepAfterAbort.status, 'canceled', 'H-28b: waiter abort must settle owned running chain step')

  // --- H-28c: Approved approval request with NO live waiter reconciles cleanly (verification & investigation) ---
  const { runId: orphanRunId, run: orphanRun } = createApprovedRun(store, {
    phase: 'verification',
    tier: 3,
    approvalPolicy: 'strict',
  })
  const orphanAsset = orphanRun.candidates[0]!

  // Verification worker parked with an already-approved card and no active waiter
  const orphanVerWorker = store.makeWorker(orphanRun, 'verification', orphanAsset, 'orphan-ver', 'orphan-ver', {
    sourceOrigins: [ORIGIN_A],
  })
  store.parkWorkerForApproval(orphanRun, orphanVerWorker.id)
  const verReq = store.createApprovalRequest(orphanRun, store.worker(orphanVerWorker.id), {
    origin: ORIGIN_A,
    method: 'POST',
    pathAndQuery: '/api/exec',
    rationale: 'Verify PoE',
    requestPreview: 'POST /api/exec',
    riskLevel: 'high',
    policyNote: 'strict',
    secrets: [],
  })
  store.db.update(approvalRequests).set({ status: 'approved', decidedAt: Date.now() })
    .where(eq(approvalRequests.id, verReq.id)).run()

  // Investigation worker parked with an already-approved card and no active waiter
  const orphanStep = store.addChainStep(orphanRun, {
    title: 'Orphaned approved step',
    hypothesis: 'Waiter exited before operator approved',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [orphanAsset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN_A],
  })
  const orphanInvWorker = store.makeWorker(orphanRun, 'investigation', orphanAsset, 'orphan-inv', 'orphan-inv', {
    stepId: orphanStep.id,
    sourceOrigins: [ORIGIN_A],
  })
  store.updateChainStep(orphanStep.id, { status: 'running', assignedWorkerId: orphanInvWorker.id })
  store.parkWorkerForApproval(orphanRun, orphanInvWorker.id)
  const invReq = store.createApprovalRequest(orphanRun, store.worker(orphanInvWorker.id), {
    origin: ORIGIN_A,
    method: 'DELETE',
    pathAndQuery: '/api/records/1',
    rationale: 'Test authz',
    requestPreview: 'DELETE /api/records/1',
    riskLevel: 'high',
    policyNote: 'strict',
    secrets: [],
  })
  store.db.update(approvalRequests).set({ status: 'approved', decidedAt: Date.now() })
    .where(eq(approvalRequests.id, invReq.id)).run()

  priv.tier3Approvals.reconcileSettledApprovalWorkers(store.run(orphanRunId))
  assert.equal(store.worker(orphanVerWorker.id).status, 'queued', 'H-28c: approved verification worker with no waiter must be requeued')
  assert.equal(store.worker(orphanVerWorker.id).approvalParkedAt, null)
  assert.equal(store.worker(orphanInvWorker.id).status, 'canceled', 'H-28c: approved investigation worker with no waiter must be canceled')
  const reconciledStep = store.listChainSteps(orphanRunId, orphanRun.goalRevision).find(s => s.id === orphanStep.id)!
  assert.equal(reconciledStep.status, 'ready', 'H-28c: investigation step owned by orphaned approved worker must reset to ready')
  assert.equal(reconciledStep.assignedWorkerId, null)

  // --- H-28d: Denial on verification worker durably marks pending finding inconclusive ---
  const { runId: denyRunId } = createApprovedRun(store, { phase: 'verification', tier: 3, approvalPolicy: 'strict' })
  const { asset: denyAsset, specRow: denySpec, findingId: denyFindingId } = seedPendingReplayFinding(store, denyRunId)
  const denyRun = store.run(denyRunId)
  const denyVerWorker = store.makeWorker(denyRun, 'verification', denyAsset, 'deny-ver', 'deny-ver', {
    stepId: denySpec.id,
    sourceOrigins: [ORIGIN_A],
  })
  store.parkWorkerForApproval(denyRun, denyVerWorker.id)
  const denyReq = store.createApprovalRequest(denyRun, store.worker(denyVerWorker.id), {
    origin: ORIGIN_A,
    method: 'POST',
    pathAndQuery: '/api/items/1',
    rationale: 'Verify PoE',
    requestPreview: 'POST /api/items/1',
    riskLevel: 'high',
    policyNote: 'strict',
    secrets: [],
  })
  store.db.update(approvalRequests).set({ status: 'denied', decidedAt: Date.now() })
    .where(eq(approvalRequests.id, denyReq.id)).run()

  priv.tier3Approvals.reconcileSettledApprovalWorkers(store.run(denyRunId))
  const denyFindingRow = store.db.select().from(findings)
    .where(and(eq(findings.runId, denyRunId), eq(findings.id, denyFindingId))).get()
  assert.equal(denyFindingRow?.finding.status, 'inconclusive', 'H-28d: denied verification approval must durably mark finding inconclusive')

  // --- H-28e: Late terminate on old worker must NOT overwrite replacement worker's running step ---
  const { runId: ownRunId, run: ownRun } = createApprovedRun(store, { phase: 'investigation', tier: 3 })
  const ownAsset = ownRun.candidates[0]!
  const sharedStep = store.addChainStep(ownRun, {
    title: 'Step reassigned to replacement worker',
    hypothesis: 'Ownership guard must protect worker B',
    category: 'broken-access-control',
    priority: 75,
    targetAssetIds: [ownAsset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN_A],
  })
  const workerA = store.makeWorker(ownRun, 'investigation', ownAsset, 'worker-a', 'old', {
    stepId: sharedStep.id,
    sourceOrigins: [ORIGIN_A],
  })
  const workerB = store.makeWorker(ownRun, 'investigation', ownAsset, 'worker-b', 'replacement', {
    stepId: sharedStep.id,
    sourceOrigins: [ORIGIN_A],
  })
  store.updateChainStep(sharedStep.id, { status: 'running', assignedWorkerId: workerB.id })

  priv.tier3Approvals.terminateApprovalBlockedAssignment(ownRunId, workerA.id, 'expired')
  const protectedStep = store.listChainSteps(ownRunId, ownRun.goalRevision).find(s => s.id === sharedStep.id)!
  assert.equal(protectedStep.status, 'running', 'H-28e: late termination of old worker must keep replacement worker step running')
  assert.equal(protectedStep.assignedWorkerId, workerB.id, 'H-28e: step assignedWorkerId must remain worker B')
})

// ============================================================================
// 3. H-2: KillSwitch reset() vs resetAll(), monotonic generation merge & persistence failure notification
// ============================================================================

test('H-2: GlobalKillSwitch separates reset() vs resetAll(), merges monotonically across instances, and notifies even when persistence fails', t => {
  const dir = makeTempDir(t, 'kovo-ws14-h2-')
  const filePath = join(dir, 'kill-switch.json')
  const dbPath = join(dir, 'kill-switch.sqlite')
  const db1 = new DatabaseSync(dbPath)
  const db2 = new DatabaseSync(dbPath)
  t.after(() => {
    try { db1.close() } catch { /* ignore */ }
    try { db2.close() } catch { /* ignore */ }
  })

  // 1. reset() clears ONLY global scope and preserves per-tenant trips; resetAll() clears all + returns releasedTenants.
  const ks1 = new GlobalKillSwitch({ filePath, db: db1, pollIntervalMs: 0 })
  ks1.trip({ reason: 'Contain tenant A', tenantId: 'tenant-a' })
  ks1.trip({ reason: 'Contain tenant B', tenantId: 'tenant-b' })
  ks1.trip({ reason: 'Global pause' })

  assert.equal(ks1.isActive(), true)
  assert.equal(ks1.isActive('tenant-a'), true)
  assert.equal(ks1.isActive('tenant-b'), true)

  ks1.reset()
  assert.equal(ks1.isActive(), false, 'global reset() must clear global state')
  assert.equal(ks1.isActive('tenant-a'), true, 'global reset() must PRESERVE tenant-a trip (H-2)')
  assert.equal(ks1.isActive('tenant-b'), true, 'global reset() must PRESERVE tenant-b trip (H-2)')

  const allCleared = ks1.resetAll()
  assert.equal(allCleared.active, false)
  assert.deepEqual(allCleared.releasedTenants.sort(), ['tenant-a', 'tenant-b'])
  assert.equal(ks1.isActive('tenant-a'), false)
  assert.equal(ks1.isActive('tenant-b'), false)

  // 2. Monotonic generation merge across sibling instances (concurrent global + tenant trips never drop each other)
  const ksWriterA = new GlobalKillSwitch({ filePath, db: db1, pollIntervalMs: 60_000 })
  const ksWriterB = new GlobalKillSwitch({ filePath, db: db2, pollIntervalMs: 60_000 })

  ksWriterA.trip({ reason: 'Global emergency from A' })
  // Sibling B trips a tenant without having polled A's global trip yet -> must merge, NOT drop global trip!
  ksWriterB.trip({ reason: 'Tenant X trip from B', tenantId: 'tenant-x' })

  assert.equal(ksWriterB.isActive(), true, 'sibling B tenant trip must preserve sibling A global trip')
  assert.equal(ksWriterB.isActive('tenant-x'), true)

  ksWriterA.syncFromExternal(true)
  assert.equal(ksWriterA.isActive(), true, 'sibling A must still have global trip active')
  assert.equal(ksWriterA.isActive('tenant-x'), true, 'sibling A must adopt sibling B tenant-x trip')

  // Simulate a stale concurrent file overwrite with lower globalGeneration=0 + new tenant-y trip
  writeFileSync(filePath, JSON.stringify({
    active: false,
    reason: null,
    trippedBy: null,
    trippedAt: null,
    tenantId: null,
    generation: 1,
    globalGeneration: 0,
    tenants: {
      'tenant-y': {
        active: true,
        reason: 'Concurrent tenant Y',
        trippedBy: 'ops',
        trippedAt: Date.now(),
        tenantId: 'tenant-y',
        generation: 1,
      },
    },
  }))
  ksWriterA.syncFromExternal(true)
  assert.equal(ksWriterA.isActive(), true, 'stale lower-generation global=false must NEVER drop higher-generation global trip')
  assert.equal(ksWriterA.isActive('tenant-y'), true, 'concurrent new tenant-y trip must be merged in')

  // 3. Persistence failure STILL aborts controllers and notifies listeners & SSE revocations
  const brokenPath = join(dir, 'dir-as-file')
  mkdirSync(brokenPath, { recursive: true })
  const ksBroken = new GlobalKillSwitch({ filePath: brokenPath })
  const ctrl = new AbortController()
  ksBroken.registerAbortController(ctrl, null)
  let onChangeFired = false
  let onSseFired = false
  ksBroken.onChange(st => { if (st.active) onChangeFired = true })
  ksBroken.onSseRevocation(st => { if (st.active) onSseFired = true })

  assert.throws(() => ksBroken.trip({ reason: 'Persist failure test' }))
  assert.equal(ctrl.signal.aborted, true, 'controller must abort even when persistence throws')
  assert.ok(ctrl.signal.reason instanceof KillSwitchTrippedError)
  assert.equal(onChangeFired, true, 'onChange listener must fire even when persistence throws')
  assert.equal(onSseFired, true, 'onSseRevocation listener must fire even when persistence throws')
})

// ============================================================================
// 4. H-27: Verification worker bounded retry, inconclusive marking, partial=true + gap line & lease watchdog
// ============================================================================

test('H-27b: failed verification worker retries once, marks finding inconclusive, and finalizes partial=true report with explicit gap line', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-ws14-h27-')
  const runtime = createAppRuntime({ dataDir: dir, store })
  const exec = new Execution(store, {
    runtime,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(async () => {
    await exec.stop()
    await runtime.dispose()
  })

  const { runId } = createApprovedRun(store, { phase: 'verification', tier: 2 })
  const { findingId, specRow } = seedPendingReplayFinding(store, runId)

  let verifyCalls = 0
  const priv = exec as unknown as {
    verifyReplaySpecJob: (job: unknown, specId: string) => Promise<void>
    verifier: { verifyBaselineJob: (job: { assignment: ReturnType<Store['worker']> }) => Promise<void> }
  }
  priv.verifyReplaySpecJob = async () => {
    verifyCalls += 1
    throw new Error(`simulated docker failure #${verifyCalls}`)
  }
  priv.verifier.verifyBaselineJob = async job => {
    store.updateWorker(job.assignment.id, { status: 'complete', outcome: 'Baseline OK', lease: null, leaseExpiresAt: null })
  }

  exec.wake()
  await waitFor(() => store.run(runId).phase === 'complete', 4_000, 'verification completion after bounded retries')

  assert.equal(verifyCalls, 2, 'H-27b: failed verification worker must be retried exactly once (2 total attempts)')
  const verWorkers = store.workerList(runId).filter(w => w.phase === 'verification' && w.stepId === specRow.id)
  assert.equal(verWorkers.length, 1)
  assert.equal(verWorkers[0]!.status, 'failed')
  assert.equal(verWorkers[0]!.attempt, 2)

  const findingRow = store.db.select().from(findings)
    .where(and(eq(findings.runId, runId), eq(findings.id, findingId))).get()
  assert.equal(findingRow?.finding.status, 'inconclusive', 'H-27b: exhausted verification worker must mark pending finding inconclusive')

  const detail = store.runDetail(runId)
  assert.ok(detail.reports.length >= 1, 'final report must be written')
  const latestReport = detail.reports[0]!
  assert.equal(latestReport.partial, true, 'H-27b: report must set partial=true when verification workers failed')
  assert.ok(
    latestReport.body.gaps.some(line => /Verification worker failed.*2 attempts/i.test(line)),
    `H-27b: report.body.gaps must contain explicit failure gap line, got: ${JSON.stringify(latestReport.body.gaps)}`,
  )

  const events = store.eventsAfter(runId, 0)
  assert.ok(events.some(e => e.kind === 'worker.retrying'), 'worker.retrying event must be emitted on first failure')
})

test('H-27 lease watchdog: expired unowned running verification worker is reclaimed and retried', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-ws14-h27-watchdog-')
  const runtime = createAppRuntime({ dataDir: dir, store })
  const exec = new Execution(store, {
    runtime,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(async () => {
    await exec.stop()
    await runtime.dispose()
  })

  const { runId, run } = createApprovedRun(store, { phase: 'verification', tier: 2 })
  const asset = run.candidates[0]!
  const stuck = store.updateWorker(
    store.makeWorker(run, 'verification', asset, 'Baseline verify · stuck', 'verify', {
      sourceOrigins: [ORIGIN_A],
    }).id,
    { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() - 10_000 },
  )!

  let baselineRan = false
  const priv = exec as unknown as {
    verifier: { verifyBaselineJob: (job: { assignment: ReturnType<Store['worker']> }) => Promise<void> }
  }
  priv.verifier.verifyBaselineJob = async job => {
    baselineRan = true
    store.updateWorker(job.assignment.id, { status: 'complete', outcome: 'Recovered OK', lease: null, leaseExpiresAt: null })
  }

  exec.wake()
  await waitFor(() => store.run(runId).phase === 'complete', 4_000, 'recovered run completion')
  assert.equal(baselineRan, true, 'expired verification lease must be reclaimed and retried')
  assert.equal(store.worker(stuck.id).status, 'complete')
})

// ============================================================================
// 5. R2-H-24: Async buildStaticWorkspaceSnapshotInWorker wiring & non-blocking check
// ============================================================================

test('R2-H-24: execution.ts awaits buildStaticWorkspaceSnapshotInWorker with abort/timeout and never calls sync buildStaticWorkspaceSnapshot', async t => {
  const execSrc = readFileSync(join(REPO_ROOT, 'src', 'server', 'execution.ts'), 'utf8')
  assert.match(
    execSrc,
    /import\s*\{[^}]*\bbuildStaticWorkspaceSnapshotInWorker\b[^}]*\}\s*from\s*['"]\.\/static-workspace-snapshot\.ts['"]/,
    'execution.ts must import buildStaticWorkspaceSnapshotInWorker',
  )
  assert.doesNotMatch(
    execSrc,
    /\bbuildStaticWorkspaceSnapshot\s*\(/,
    'execution.ts must NOT call synchronous buildStaticWorkspaceSnapshot(',
  )
  assert.match(
    execSrc,
    /await\s+buildStaticWorkspaceSnapshotInWorker\(\s*reposDir\s*,\s*\{[\s\S]*?signal:\s*controller\.signal[\s\S]*?workerTimeoutMs:/,
    'execution.ts must await buildStaticWorkspaceSnapshotInWorker with signal and workerTimeoutMs',
  )

  const reposDir = makeTempDir(t, 'kovo-ws14-r2h24-repo-')
  mkdirSync(join(reposDir, 'app'), { recursive: true })
  writeFileSync(join(reposDir, 'app', 'routes.ts'), 'export function register(app: any) { app.get("/health", () => "ok") }\n')

  let maxLagMs = 0
  let lastTick = performance.now()
  const probe = setInterval(() => {
    const now = performance.now()
    const lag = now - lastTick - 10
    if (lag > maxLagMs) maxLagMs = lag
    lastTick = now
  }, 10)
  try {
    const ctrl = new AbortController()
    const snapshot = await buildStaticWorkspaceSnapshotInWorker(reposDir, {
      mountedRepos: ['app'],
      signal: ctrl.signal,
      workerTimeoutMs: 5_000,
    })
    assert.ok(snapshot.files.length >= 1)
  } finally {
    clearInterval(probe)
  }
  assert.ok(maxLagMs < 200, `event-loop lag during buildStaticWorkspaceSnapshotInWorker must stay < 200ms (got ${maxLagMs.toFixed(1)}ms)`)
})

// ============================================================================
// 6. Warm-pool eviction wired into Execution.disposeRun
// ============================================================================

test('evictRunWarmPool(runId) is called on Execution.disposeRun with and without an active RunActor', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-ws14-warmpool-')
  const runtime = createAppRuntime({ dataDir: dir, store })
  const evicted: string[] = []
  const exec = new Execution(store, {
    runtime,
    broker: makeBroker(),
    backend: stubBackend(runId => evicted.push(runId)),
    deterministicSweep: false,
  })
  t.after(async () => {
    await exec.stop()
    await runtime.dispose()
  })

  // Case A: Run has an initialized RunActor
  const { runId: runA } = createApprovedRun(store, { phase: 'investigation' })
  ;(exec as unknown as { ensureRunActor: (id: string) => RunActor }).ensureRunActor(runA)
  await exec.disposeRun(runA, { terminalState: 'completed', reason: 'done' })
  assert.deepEqual(evicted, [runA], 'disposeRun with active RunActor must call backend.evictRunWarmPool(runId)')

  // Case B: Run has NO initialized RunActor
  const { runId: runB } = createApprovedRun(store, { phase: 'investigation' })
  await exec.disposeRun(runB, { terminalState: 'canceled', reason: 'direct dispose' })
  assert.deepEqual(evicted, [runA, runB], 'disposeRun without RunActor must also call backend.evictRunWarmPool(runId)')
})
