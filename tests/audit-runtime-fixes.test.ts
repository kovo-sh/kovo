process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * Adversarial Runtime & Concurrency Audit Remediation Tests (#729):
 *  - C1: AppRuntime composition root parity, CanaryBroker attachment, Execution shutdown ordering,
 *        Symbol.for('kovo.execution') singleton across dual ESM/SSR imports.
 *  - C4: deleteRunWithActiveGuard / deleteProjectWithActiveGuard / Execution.deleteRun drain
 *        barrier & fail-closed RunDeleteBusyError (409) when tasks time out.
 *  - H1: RunActor FSM reconciliation on phase jumps, resume-after-stop/fail actor refresh,
 *        and kill-switch pause + hot-loop prevention.
 *  - H2 & H5: Supervised OOB final report / retest / subdomain discovery, timer disposer cleanup,
 *        per-run map eviction, per-run detLeadConsumed isolation, per-run WarmSpecialistController
 *        isolation, CanaryBroker observedSecondOrderSurfaces eviction, and tenant-aware SSE 503 +
 *        kill-switch revocation.
 *  - M1: StoreSession poison-row dead-lettering + priorError recovery, deferred post-commit
 *        emitter notifications (discarded on rollback), and Store constructor lock cleanup.
 *  - M2: GlobalKillSwitch transactional SQLite persist, registerAbortController external sync,
 *        and (mtimeMs, ctimeMs, size, ino) change detection.
 *  - M3: OobRelay post-unsubscribe callback rejection & atomic claim() transaction.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { launchSubdomainDiscoveryInBackground } from '../src/actions.ts'
import { runCommand } from '../src/domain.ts'
import { eventsResponse } from '../src/routes/api.runs.$runId.events.ts'
import {
  createAppRuntime,
  disposeAllAppRuntimes,
  getAppRuntime,
} from '../src/server/app-runtime.ts'
import { WarmSpecialistController } from '../src/server/board-tools.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  CanaryBroker,
  resetSecondOrderSurfaceTracking,
  scanSecondOrderMarkers,
  trackedSecondOrderSurfaceCount,
} from '../src/server/canary-broker.ts'
import { Execution, execution } from '../src/server/execution.ts'
import { GlobalKillSwitch, globalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import { scheduleFinalReport, type FinalizeHost, type OobDrainRelay } from '../src/server/oob-drain.ts'
import { OobRelay } from '../src/server/oob-relay.ts'
import { RunActor } from '../src/server/run-actor.ts'
import {
  deleteProjectWithActiveGuard,
  deleteRunWithActiveGuard,
  RunDeleteBusyError,
  Store,
} from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const ORIGIN_A = 'https://audit-a.example.test'
const ORIGIN_B = 'https://audit-b.example.test'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-audit-rt-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => {
    rmSync(dir, { recursive: true, force: true })
  })
  return dir
}

function makeTempStore(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-audit-store-'): { dir: string; store: Store } {
  const dir = makeTempDir(t, prefix)
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
  })
  return { dir, store }
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function stubBackend(): WorkerBackend {
  return {
    openSession: async () => ({
      stage: async (name: string) => `/work/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async () => ({ repo: 'app', enginesRun: [], engineStatus: {}, findings: [], durationMs: 1 }),
      runScript: async () => ({ runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 }),
      close: async () => undefined,
    }),
  } as unknown as WorkerBackend
}

function createApprovedRun(
  store: Store,
  opts: { origin?: string; phase?: 'threat_model' | 'investigation' | 'verification' | 'complete'; tenantId?: string } = {},
) {
  const origin = opts.origin ?? ORIGIN_A
  const project = store.createProject({
    requestId: randomUUID(),
    name: `AuditProj ${randomUUID().slice(0, 6)}`,
    seeds: [origin],
    environment: 'public',
  })
  if (opts.tenantId) {
    store.setProjectTenant(project.id, opts.tenantId)
  }
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify runtime audit fixes',
    sourceMode: 'public',
    capabilityTier: 2,
  } as Parameters<Store['createRun']>[0])
  if (opts.tenantId) {
    store.setRunTenant(runId, opts.tenantId)
  }
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
  const phase = opts.phase ?? 'investigation'
  store.updateRun(runId, { phase, status: phase === 'complete' ? 'complete' : 'running' })
  return { projectId: project.id, runId, run: store.run(runId) }
}

async function waitFor(predicate: () => boolean, timeoutMs = 3_000, label = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 15))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

// ============================================================================
// C1: AppRuntime composition root parity, CanaryBroker attachment & Execution shutdown
// ============================================================================

test('C1: execution() shares Symbol.for singleton across dual ESM loads, attaches CanaryBroker to existing AppRuntime, and stops BEFORE Store closes', async t => {
  const prevDataDir = process.env.KOVO_DATA_DIR
  const dir = makeTempDir(t, 'kovo-c1-runtime-')
  process.env.KOVO_DATA_DIR = dir
  t.after(async () => {
    await disposeAllAppRuntimes()
    globalKillSwitch.reset()
    if (prevDataDir === undefined) delete process.env.KOVO_DATA_DIR
    else process.env.KOVO_DATA_DIR = prevDataDir
  })

  // 1. Pre-create AppRuntime BEFORE Execution (exactly as scripts/serve.ts does).
  const rt = getAppRuntime({ dataDir: dir })
  assert.equal(rt.hasCanaryBroker(), false)

  // 2. execution() attaches its CanaryBroker onto the existing AppRuntime and is shared across dual imports.
  const exec1 = execution()
  const dualMod = await import(`../src/server/execution.ts?c1dual=${Date.now()}`) as { execution: typeof execution }
  const exec2 = dualMod.execution()
  assert.strictEqual(exec2, exec1, 'dual SSR/ESM module loads must share the exact same Execution instance')
  assert.equal(rt.hasCanaryBroker(), true, 'Execution must attach its CanaryBroker to pre-existing AppRuntime')
  assert.strictEqual(rt.canaryBroker, exec1.canaryBroker)

  // 3. RunContext oob:unsubscribe disposer now unsubscribes Execution's CanaryBroker.
  const { runId: c1RunId } = createApprovedRun(rt.store)
  const ctx = rt.createRunContext(c1RunId)
  const canary = exec1.canaryBroker.mintCanary(ctx.runId, 'c1-probe', ORIGIN_A)
  const sub = exec1.canaryBroker.subscribe({
    runId: ctx.runId,
    assignmentId: 'a-c1',
    canaryId: canary.id,
    token: canary.token,
    artifact: 'art-c1',
  })
  assert.equal(exec1.canaryBroker.oob.subscription(sub.id).status, 'pending')
  await ctx.dispose()
  assert.equal(exec1.canaryBroker.oob.subscription(sub.id).status, 'expired', 'RunContext dispose must unsubscribe Execution.canaryBroker')

  // 4. AppRuntime.dispose() stops Execution cleanly BEFORE closing Store.
  const order: string[] = []
  const origStop = exec1.stop.bind(exec1)
  const origClose = rt.store.close.bind(rt.store)
  exec1.stop = async () => {
    order.push('execution.stop:start')
    await origStop()
    order.push('execution.stop:end')
  }
  rt.store.close = () => {
    order.push('store.close')
    origClose()
  }

  exec1.start()
  const report = await rt.dispose()
  assert.deepEqual(report.errors, [])
  assert.equal(report.storeClosed, true)
  assert.deepEqual(order, ['execution.stop:start', 'execution.stop:end', 'store.close'], 'Execution.stop() must complete BEFORE Store.close()')

  // 5. After dispose, execution() creates a fresh instance rather than returning the stopped one.
  const execFresh = execution()
  assert.notStrictEqual(execFresh, exec1)
})

// ============================================================================
// C4: deleteRunWithActiveGuard & deleteProjectWithActiveGuard drain barrier & fail-closed
// ============================================================================

test('C4: deleteRunWithActiveGuard drains RunActor before SQLite delete and fails closed (409 RunDeleteBusyError) when tasks time out', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-c4-delete-')
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

  const { runId: runOkId } = createApprovedRun(store, { phase: 'investigation' })
  const priv = exec as unknown as { ensureRunActor: (id: string) => RunActor }
  const actorOk = priv.ensureRunActor(runOkId)

  const timeline: string[] = []
  actorOk.spawn('c4-writer', async signal => {
    await new Promise<void>(resolve => {
      signal.addEventListener('abort', () => {
        timeline.push('task-aborted')
        setTimeout(() => {
          timeline.push('task-drained')
          resolve()
        }, 25)
      }, { once: true })
    })
  })

  const origDeleteRun = store.deleteRun.bind(store)
  store.deleteRun = (id: string) => {
    timeline.push(`db-delete:${id}`)
    return origDeleteRun(id)
  }

  const res = await deleteRunWithActiveGuard(store, exec, exec.labRunner, {
    runId: runOkId,
    stopActive: true,
    waitTimeoutMs: 1_500,
  })
  assert.equal(res.deleted, true)
  assert.deepEqual(timeline, ['task-aborted', 'task-drained', `db-delete:${runOkId}`])

  // Fail-closed test: a hanging task that ignores abort MUST cause RunDeleteBusyError (409)
  // and preserve the run row in SQLite instead of hard-deleting under a live writer.
  const { projectId: projBusy, runId: runBusyId } = createApprovedRun(store, { phase: 'investigation' })
  const actorBusy = priv.ensureRunActor(runBusyId)
  let releaseHungTask: () => void = () => {}
  actorBusy.spawn('c4-hung-writer', async () => {
    await new Promise<void>(resolve => { releaseHungTask = resolve })
  })
  t.after(() => { releaseHungTask() })

  await assert.rejects(
    () => deleteRunWithActiveGuard(store, exec, exec.labRunner, {
      runId: runBusyId,
      stopActive: true,
      waitTimeoutMs: 60,
    }),
    (err: unknown) => err instanceof RunDeleteBusyError && err.code === 'RUN_DELETE_BUSY' && err.status === 409,
  )
  // Run MUST still exist in SQLite!
  assert.equal(store.run(runBusyId).id, runBusyId)

  await assert.rejects(
    () => deleteProjectWithActiveGuard(store, exec, exec.labRunner, {
      projectId: projBusy,
      stopActive: true,
      waitTimeoutMs: 60,
    }),
    (err: unknown) => err instanceof RunDeleteBusyError && err.status === 409,
  )
  assert.equal(store.project(projBusy).id, projBusy)
  releaseHungTask()
})

// ============================================================================
// H1: RunActor FSM reconciliation on phase jumps, resume-after-stop, and kill-switch
// ============================================================================

test('H1: RunActor reconciles multi-hop phase jumps, refreshes on resume-after-stop, and pauses without hot-looping on kill-switch', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-h1-fsm-')
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

  // 1. Multi-hop persisted phase jumps reconcile cleanly along legal FSM edges.
  const ctxJump = runtime.createRunContext('run-h1-jump')
  const actorJump = new RunActor({ context: ctxJump, initialState: 'queued' })
  assert.equal(actorJump.reconcileWithPersisted('verifying', 'restore'), 'verifying')
  assert.equal(actorJump.state, 'verifying')
  assert.ok(actorJump.transitions.length >= 2)
  await ctxJump.dispose()

  const ctxJump2 = runtime.createRunContext('run-h1-jump-2')
  const actorJump2 = new RunActor({ context: ctxJump2, initialState: 'investigating' })
  assert.equal(actorJump2.reconcileWithPersisted('completed', 'restore'), 'completed')
  assert.equal(actorJump2.state, 'completed')
  await ctxJump2.dispose()

  // 2. Resume-after-stop refreshes a terminal/draining actor instead of wedging spawnRunTask.
  const { runId } = createApprovedRun(store, { phase: 'investigation', tenantId: 'tenant-h1-a' })
  const priv = exec as unknown as {
    ensureRunActor: (id: string) => RunActor
    spawnRunTask: (runId: string, label: string, fn: (signal: AbortSignal) => Promise<void>) => { promise: Promise<void | undefined> }
    driveInvestigation: () => void
  }
  // Keep investigation parked so we inspect the live resumed RunActor before auto-completion.
  priv.driveInvestigation = () => {}
  const actor1 = priv.ensureRunActor(runId)
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'stop' }))
  exec.wake()
  // Immediately resume while disposal may still be settling.
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' }))
  assert.equal(store.run(runId).status, 'running')
  exec.wake()

  await waitFor(() => {
    const latest = exec.getRunActor(runId)
    return Boolean(latest && latest !== actor1 && !latest.signal.aborted && !latest.isTerminal)
  }, 3_000, 'fresh non-aborted RunActor after resume')

  let ranAfterResume = false
  await priv.spawnRunTask(runId, 'post-resume-check', async signal => {
    assert.equal(signal.aborted, false)
    ranAfterResume = true
  }).promise
  assert.equal(ranAfterResume, true, 'spawnRunTask must execute on fresh actor after stop+resume')

  // Completed runs cannot be resumed.
  const { runId: completeRunId } = createApprovedRun(store, { phase: 'complete' })
  assert.throws(
    () => store.command(runCommand.parse({ requestId: randomUUID(), runId: completeRunId, action: 'resume' })),
    /Completed runs cannot be resumed|not paused or stopped/i,
  )

  // 3. Kill-switch trip pauses matching tenant's SQLite run and prevents wake() hot-loop dispatch.
  const { runId: runTenantB } = createApprovedRun(store, { origin: ORIGIN_B, phase: 'investigation', tenantId: 'tenant-h1-b' })
  let driveCallsWhileTripped = 0
  priv.driveInvestigation = (r?: { id: string }) => {
    if (r?.id === runId) driveCallsWhileTripped += 1
  }
  runtime.killSwitch.trip({ reason: 'H1 tenant-a emergency stop', tenantId: 'tenant-h1-a' })
  assert.equal(store.run(runId).status, 'paused', 'tenant-a run must be paused in SQLite on tenant-a kill-switch trip')
  assert.equal(store.run(runTenantB).status, 'running', 'sibling tenant-b run must remain running')

  // Repeated wake() calls while tripped must NOT dispatch assignments for tenant-a.
  store.updateRun(runId, { status: 'running' })
  exec.wake()
  exec.wake()
  assert.equal(store.run(runId).status, 'paused', 'wake() must re-pause running tenant-a run while kill-switch is active')
  assert.equal(driveCallsWhileTripped, 0, 'wake() must never hot-loop dispatch while kill-switch is active')
})

// ============================================================================
// H2 & H5: Supervision, per-run eviction, detLeadConsumed, WarmSpecialist & SSE
// ============================================================================

test('H2: scheduleFinalReport supervises OOB drain, schedulePlanner does not leak timers, and launchSubdomainDiscoveryInBackground honors abort', async t => {
  const { dir, store } = makeTempStore(t, 'kovo-h2-supervision-')
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

  // 1. scheduleFinalReport routes async OOB drain through host.spawn + signal.
  const { runId, run } = createApprovedRun(store, { phase: 'verification' })
  let spawnedLabel = ''
  let drainedWithSignal = false
  let finalizedRunId = ''
  const relay: OobDrainRelay = { pending: () => [{ id: 'sub-1' }], promoteLate: () => [] }
  const host: FinalizeHost = {
    storage: store,
    relay,
    draining: new Set(),
    lastDrain: new Map(),
    drain: async (_id, signal) => {
      drainedWithSignal = Boolean(signal)
      return { oobDrainMs: 1, promotedLate: 0, remaining: 0 }
    },
    spawn: (label, fn) => {
      spawnedLabel = label
      return (exec as unknown as { ensureRunActor: (id: string) => RunActor }).ensureRunActor(runId).spawn(label, fn)
    },
    onFinalized: id => { finalizedRunId = id },
  }
  scheduleFinalReport(host, run)
  await waitFor(() => finalizedRunId === runId, 2_000, 'supervised final report completion')
  assert.equal(spawnedLabel, 'oob-final-report')
  assert.equal(drainedWithSignal, true)

  // 2. schedulePlanner uses actor.scheduleTimer so firing releases RunContext resource entries (no leak).
  const { runId: plannerRunId } = createApprovedRun(store, { phase: 'investigation' })
  const priv = exec as unknown as {
    ensureRunActor: (id: string) => RunActor
    schedulePlanner: (id: string, delayMs?: number) => void
  }
  const actor = priv.ensureRunActor(plannerRunId)
  const resourcesBefore = (actor.context as unknown as { resources: Map<string, unknown> }).resources.size
  for (let i = 0; i < 4; i += 1) {
    priv.schedulePlanner(plannerRunId, 5)
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  const resourcesAfter = (actor.context as unknown as { resources: Map<string, unknown> }).resources.size
  assert.equal(resourcesAfter, resourcesBefore, 'repeated schedulePlanner firings must not leak RunContext timer disposers')

  // 3. launchSubdomainDiscoveryInBackground honors AbortSignal and writes zero events after abort.
  const { runId: discRunId } = createApprovedRun(store, { phase: 'investigation' })
  const abortCtrl = new AbortController()
  let resolveStarted: () => void = () => {}
  const discoveryStarted = new Promise<void>(resolve => { resolveStarted = resolve })
  let resolveSlow: () => void = () => {}
  const bg = launchSubdomainDiscoveryInBackground(
    store,
    discRunId,
    async () => {
      resolveStarted()
      await new Promise<void>(resolve => { resolveSlow = resolve })
      return {
        skipped: false,
        addedOrigins: ['https://late.example.test'],
        thirdPartyOrigins: [],
        totalCandidates: 1,
        discovery: { discovered: [], queriedApexes: [], skippedOrigins: [], warnings: [] },
      }
    },
    5_000,
    { signal: abortCtrl.signal },
  )
  await discoveryStarted
  abortCtrl.abort(new Error('run disposed'))
  resolveSlow()
  await bg
  const discEvents = store.eventsAfter(discRunId, 0)
  assert.equal(discEvents.some(e => e.kind === 'discovery.subdomains_discovered'), false, 'aborted subdomain discovery must not write events')
})

test('H2 & H5: per-run detLeadConsumed, WarmSpecialistController, CanaryBroker surfaces & per-run maps are isolated and evicted on disposal', async t => {
  resetSecondOrderSurfaceTracking()
  const { dir, store } = makeTempStore(t, 'kovo-h2-h5-isolation-')
  const runtime = createAppRuntime({ dataDir: dir, store })
  const canaryBroker = new CanaryBroker({ storage: store, oobDirectory: dir })
  runtime.attachCanaryBroker(canaryBroker)
  const exec = new Execution(store, {
    runtime,
    canaryBroker,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(async () => {
    await exec.stop()
    await runtime.dispose()
  })

  const runA = createApprovedRun(store, { origin: ORIGIN_A, phase: 'investigation' })
  const runB = createApprovedRun(store, { origin: ORIGIN_B, phase: 'investigation' })

  // 1. Per-run detLeadConsumed isolation
  const workerA = store.updateWorker(
    store.makeWorker(runA.run, 'investigation', runA.run.candidates[0]!, 'floor-a', 'floor-a').id,
    { status: 'running', lease: randomUUID() },
  )!
  const workerB = store.updateWorker(
    store.makeWorker(runB.run, 'investigation', runB.run.candidates[0]!, 'floor-b', 'floor-b').id,
    { status: 'running', lease: randomUUID() },
  )!
  store.addFact(runA.run, workerA, {
    kind: 'note',
    origin: ORIGIN_A,
    summary: 'lead-a',
    data: { kind: 'det_lead', source: 'deterministic_engine', probeClass: 'ssrf_canary', endpoint: '/a/hook', method: 'POST', leadEvidenceKind: 'near_miss', reason: 'url param' },
  })
  store.addFact(runB.run, workerB, {
    kind: 'note',
    origin: ORIGIN_B,
    summary: 'lead-b',
    data: { kind: 'det_lead', source: 'deterministic_engine', probeClass: 'ssrf_canary', endpoint: '/b/hook', method: 'POST', leadEvidenceKind: 'near_miss', reason: 'url param' },
  })

  const priv = exec as unknown as {
    queueDetLeadUpgradeSteps: (run: typeof runA.run, origins: ReadonlySet<string>, budget: number) => number
    recordFloorMetrics: (runId: string, reason: string) => void
    detLeadConsumed: Set<string>
    detLeadConsumedByRun: Map<string, Set<string>>
    dryStreakObserved: Map<string, number>
  }
  assert.equal(priv.queueDetLeadUpgradeSteps(store.run(runA.runId), new Set([ORIGIN_A]), 20), 1)
  assert.equal(priv.detLeadConsumedByRun.get(runA.runId)?.size, 1)
  assert.equal(priv.detLeadConsumedByRun.get(runB.runId)?.size ?? 0, 0, 'Run A consuming a det_lead must NOT mark Run B as consumed')

  priv.recordFloorMetrics(runB.runId, 'isolation-check')
  const summaryB = store.eventsAfter(runB.runId, 0).filter(e => e.kind === 'deterministic_floor.summary').at(-1)
  assert.equal((summaryB?.detail as Record<string, unknown>)?.floorLeadsConsumed, 0, 'Run B floor metrics must report 0 consumed (not Run A count)')

  assert.equal(priv.queueDetLeadUpgradeSteps(store.run(runB.runId), new Set([ORIGIN_B]), 20), 1, 'Run B must still queue its own det_lead upgrade step')

  // 2. Per-run WarmSpecialistController isolation
  const warm = new WarmSpecialistController()
  warm.register('auth', { sessionId: 'sess-a', state: 'waiting' }, runA.runId)
  warm.register('auth', { sessionId: 'sess-b', state: 'waiting' }, runB.runId)
  warm.retire('auth', 'run_complete', runA.runId)
  assert.equal(warm.get('auth', runA.runId)?.state, 'retired')
  assert.equal(warm.get('auth', runB.runId)?.state, 'waiting', 'retiring handle on Run A must not retire handle on Run B')
  assert.equal(warm.get('auth', runB.runId)?.sessionId, 'sess-b')
  warm.evictRun(runA.runId)
  assert.equal(warm.get('auth', runA.runId), undefined)
  assert.equal(warm.get('auth', runB.runId)?.state, 'waiting')

  // 3. CanaryBroker observedSecondOrderSurfaces evicted in unsubscribeRun(runId) without touching sibling run
  const soA = canaryBroker.mintSecondOrderCanary({
    runId: runA.runId,
    assignmentId: workerA.id,
    injectedOrigin: ORIGIN_A,
    injectedEndpoint: '/profile',
    injectedPersona: 'alice',
    storage: store,
  })
  const soB = canaryBroker.mintSecondOrderCanary({
    runId: runB.runId,
    assignmentId: workerB.id,
    injectedOrigin: ORIGIN_B,
    injectedEndpoint: '/profile',
    injectedPersona: 'alice',
    storage: store,
  })
  scanSecondOrderMarkers({
    text: `rendered ${soA.marker}`,
    runId: runA.runId,
    assignmentId: workerA.id,
    origin: ORIGIN_A,
    endpoint: '/admin/audit',
    persona: 'admin',
    storage: store,
  })
  scanSecondOrderMarkers({
    text: `rendered ${soB.marker}`,
    runId: runB.runId,
    assignmentId: workerB.id,
    origin: ORIGIN_B,
    endpoint: '/admin/audit',
    persona: 'admin',
    storage: store,
  })
  assert.equal(trackedSecondOrderSurfaceCount(runA.runId), 1)
  assert.equal(trackedSecondOrderSurfaceCount(runB.runId), 1)

  // 4. Disposing Run A evicts Run A's maps + detLeadConsumed + CanaryBroker surfaces while preserving Run B!
  priv.dryStreakObserved.set(runA.runId, 3)
  priv.dryStreakObserved.set(runB.runId, 2)
  await exec.disposeRun(runA.runId, { terminalState: 'completed', reason: 'done' })
  assert.equal(priv.dryStreakObserved.has(runA.runId), false)
  assert.equal(priv.dryStreakObserved.get(runB.runId), 2)
  assert.equal(priv.detLeadConsumedByRun.has(runA.runId), false)
  assert.equal(priv.detLeadConsumedByRun.get(runB.runId)?.size, 1)
  assert.equal(trackedSecondOrderSurfaceCount(runA.runId), 0, 'unsubscribeRun must evict Run A observedSecondOrderSurfaces')
  assert.equal(trackedSecondOrderSurfaceCount(runB.runId), 1, 'evicting Run A must preserve Run B observedSecondOrderSurfaces')
})

test('H5: eventsResponse returns 503 when kill-switch is tripped and enforces tenant-scoped SSE revocation', async t => {
  const prevDataDir = process.env.KOVO_DATA_DIR
  const dir = makeTempDir(t, 'kovo-h5-sse-')
  process.env.KOVO_DATA_DIR = dir
  t.after(async () => {
    await disposeAllAppRuntimes()
    globalKillSwitch.reset()
    if (prevDataDir === undefined) delete process.env.KOVO_DATA_DIR
    else process.env.KOVO_DATA_DIR = prevDataDir
  })

  const runtime = getAppRuntime({ dataDir: dir })
  const db = runtime.store
  const runA = createApprovedRun(db, { origin: ORIGIN_A, tenantId: 'tenant-sse-a' })
  const runB = createApprovedRun(db, { origin: ORIGIN_B, tenantId: 'tenant-sse-b' })

  const ctrlA = new AbortController()
  const ctrlB = new AbortController()
  t.after(() => { ctrlA.abort(); ctrlB.abort() })

  const resA = eventsResponse(new Request(`http://127.0.0.1/api/runs/${runA.runId}/events`, { signal: ctrlA.signal }), runA.runId)
  const resB = eventsResponse(new Request(`http://127.0.0.1/api/runs/${runB.runId}/events`, { signal: ctrlB.signal }), runB.runId)
  assert.equal(resA.status, 200)
  assert.equal(resB.status, 200)

  const readerA = resA.body!.getReader()
  const readerB = resB.body!.getReader()
  // Read initial retry banner + buffered setup backlog
  await readerA.read()
  await readerB.read()

  const drainUntilClosed = async (reader: ReadableStreamDefaultReader<Uint8Array>, timeoutMs = 1_500): Promise<boolean> => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const next = await Promise.race([
        reader.read(),
        new Promise<'timeout'>(resolve => setTimeout(() => resolve('timeout'), Math.max(10, deadline - Date.now()))),
      ])
      if (next === 'timeout') return false
      if (next.done) return true
    }
    return false
  }

  // Trip Tenant A kill switch -> Stream A closes, Stream B stays open & receives events!
  runtime.killSwitch.trip({ reason: 'Tenant A halt', tenantId: 'tenant-sse-a' })
  assert.equal(await drainUntilClosed(readerA), true, 'Tenant A SSE stream must close immediately on Tenant A kill-switch trip')

  // Reconnect attempt for Tenant A while tripped MUST return 503 (never resume streaming!).
  const reconnectA = eventsResponse(new Request(`http://127.0.0.1/api/runs/${runA.runId}/events`), runA.runId)
  assert.equal(reconnectA.status, 503, 'SSE reconnect for tripped tenant must return 503')

  // Tenant B stream stays open and receives new events!
  db.event(runB.runId, 'test.alive', 'Tenant B still live')
  let sawAlive = false
  const decoder = new TextDecoder()
  for (let i = 0; i < 5; i += 1) {
    const nextB = await Promise.race([
      readerB.read(),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('Stream B stopped receiving events')), 1_500)),
    ])
    assert.equal(nextB.done, false, 'Tenant B SSE stream must remain open when only Tenant A is tripped')
    if (/Tenant B still live/.test(decoder.decode(nextB.value))) {
      sawAlive = true
      break
    }
  }
  assert.equal(sawAlive, true, 'Tenant B must receive live events while Tenant A is tripped')

  // Global trip closes Tenant B and makes reconnect return 503.
  runtime.killSwitch.trip({ reason: 'Global halt' })
  assert.equal(await drainUntilClosed(readerB), true, 'Stream B must close on global kill-switch trip')
  const reconnectB = eventsResponse(new Request(`http://127.0.0.1/api/runs/${runB.runId}/events`), runB.runId)
  assert.equal(reconnectB.status, 503)
})

// ============================================================================
// M1: StoreSession dead-lettering, deferred post-commit events, constructor lock cleanup
// ============================================================================

test('M1: StoreSession dead-letters repeated poison rows, clears priorError on recovery, defers events until COMMIT, and Store releases lock on init failure', async t => {
  const { store } = makeTempStore(t, 'kovo-m1-store-')
  const { runId, run } = createApprovedRun(store)
  const worker = store.makeWorker(run, 'investigation', run.candidates[0]!, 'w-m1', 'w-m1')
  // Drain microtask notifications queued by setup before subscribing.
  await new Promise(resolve => setTimeout(resolve, 10))

  // 1. Pre-commit event emission deferral: rolled-back transaction emits ZERO events; committed tx emits AFTER commit.
  const receivedEvents: string[] = []
  const unsub = store.onRunEvent(runId, ev => { receivedEvents.push(`${ev.kind}:${ev.message}`) })
  t.after(unsub)

  assert.throws(() => {
    store.transaction(() => {
      store.event(runId, 'tx.phantom', 'must never emit')
      store.message(runId, run.coordinatorId, 'kovo', 'phantom message')
      throw new Error('force rollback')
    })
  }, /force rollback/)
  await new Promise(resolve => setTimeout(resolve, 25))
  assert.equal(receivedEvents.length, 0, 'rolled-back transaction must emit zero SSE/event notifications')

  // Nested savepoint rollback discards inner event while outer commit emits outer event.
  store.transaction(() => {
    store.event(runId, 'tx.outer', 'outer committed')
    try {
      store.transaction(() => {
        store.event(runId, 'tx.inner', 'inner rolled back')
        throw new Error('rollback savepoint')
      })
    } catch { /* expected */ }
  })
  await new Promise(resolve => setTimeout(resolve, 25))
  assert.equal(receivedEvents.some(e => e.includes('tx.outer')), true, 'outer committed event must emit after COMMIT')
  assert.equal(receivedEvents.some(e => e.includes('tx.inner')), false, 'rolled-back savepoint event must NOT emit')

  // 2. Poison row isolation & dead-lettering: 1 poison row + 1 healthy row in one batch.
  const rawClient = (store as unknown as { session: { client: { exec: (sql: string) => void } } }).session.client
  rawClient.exec(`
    CREATE TRIGGER test_poison_path BEFORE INSERT ON broker_exchanges
    WHEN NEW.path_and_query = '/poison-row'
    BEGIN
      SELECT RAISE(ABORT, 'poison row constraint');
    END;
  `)

  const recordOne = (pathAndQuery: string) => store.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin: ORIGIN_A,
    finalOrigin: ORIGIN_A,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery,
    personaHandle: null,
    status: 200,
    mediaType: 'text/plain',
    reqHeaders: {},
    respHeaders: {},
    body: 'ok',
    durationMs: 1,
  })

  recordOne('/healthy-1')
  recordOne('/poison-row')
  recordOne('/healthy-2')

  // 1st flush isolates per item: commits both healthy rows immediately, retries poison row once & throws.
  assert.throws(() => store.flushNow(), (err: unknown) => {
    const e = err as { message?: string; cause?: { message?: string } }
    return /poison row constraint/.test(e?.message ?? '') || /poison row constraint/.test(e?.cause?.message ?? '')
  })
  // 2nd flush hits poison retry limit -> dead-letters poison row without head-of-line blocking!
  assert.doesNotThrow(() => store.flushNow())
  assert.equal(store.session.flushNow.length >= 0, true)
  const deadLetters = (store.session as unknown as { getDeadLetterExchanges: () => Array<{ error: string }> }).getDeadLetterExchanges()
  assert.equal(deadLetters.length, 1, 'poison row must be dead-lettered after retry cap')
  assert.match(deadLetters[0]!.error, /poison row constraint/)

  // Unrelated reads & subsequent healthy writes work with zero lingering flushError!
  recordOne('/healthy-3')
  assert.doesNotThrow(() => store.flushNow())
  const paths = (store.client.prepare('SELECT path_and_query FROM broker_exchanges WHERE run_id = ?').all(runId) as Array<{ path_and_query: string }>)
    .map(row => row.path_and_query)
  assert.ok(paths.includes('/healthy-1'))
  assert.ok(paths.includes('/healthy-2'))
  assert.ok(paths.includes('/healthy-3'))
  assert.ok(!paths.includes('/poison-row'))

  // 3. Store constructor lock cleanup on init error.
  const corruptDir = makeTempDir(t, 'kovo-m1-corrupt-')
  writeFileSync(join(corruptDir, 'kovo.sqlite'), 'this is not a valid sqlite database file!', 'utf8')
  assert.throws(() => new Store(corruptDir))
  // Replace corrupt file with empty file -> processLock MUST have been released so reopen succeeds!
  rmSync(join(corruptDir, 'kovo.sqlite'), { force: true })
  const recoveredStore = new Store(corruptDir)
  t.after(() => recoveredStore.close())
  assert.equal(existsSync(join(corruptDir, 'kovo.sqlite')), true)
})

// ============================================================================
// M2: GlobalKillSwitch transactional SQLite persist, stat key, synced registerAbortController
// ============================================================================

test('M2: GlobalKillSwitch persists SQLite atomically, syncs on registerAbortController(), and detects same-ms file updates via (mtimeMs, ctimeMs, size, ino)', async t => {
  const dir = makeTempDir(t, 'kovo-m2-ks-')
  const filePath = join(dir, 'kill-switch.json')
  const dbPath = join(dir, 'ks.sqlite')
  const db1 = new DatabaseSync(dbPath)
  const db2 = new DatabaseSync(dbPath)
  t.after(() => {
    try { db1.close() } catch { /* ignore */ }
    try { db2.close() } catch { /* ignore */ }
  })

  const ksWriter = new GlobalKillSwitch({ filePath, db: db1, pollIntervalMs: 0 })
  const ksReader = new GlobalKillSwitch({ filePath, db: db2, pollIntervalMs: 0 })

  // 1. Atomic SQLite persist with multiple tenants + registerAbortController external sync.
  ksWriter.trip({ reason: 'Tenant A tripped', tenantId: 'tenant-m2-a' })
  ksWriter.trip({ reason: 'Tenant B tripped', tenantId: 'tenant-m2-b' })

  const ctrlA = new AbortController()
  const ctrlC = new AbortController()
  const releaseA = ksReader.registerAbortController(ctrlA, 'tenant-m2-a')
  const releaseC = ksReader.registerAbortController(ctrlC, 'tenant-m2-c')
  t.after(() => { releaseA(); releaseC() })

  assert.equal(ctrlA.signal.aborted, true, 'registerAbortController must syncFromExternal and immediately abort for externally tripped tenant')
  assert.ok(ctrlA.signal.reason instanceof KillSwitchTrippedError)
  assert.equal(ctrlC.signal.aborted, false)

  // 2. Same-millisecond file replacement (identical mtimeMs, different inode/size) is detected!
  const ksFileOnly = new GlobalKillSwitch({ filePath, pollIntervalMs: 0 })
  assert.equal(ksFileOnly.isActive(), false)
  const frozenTime = new Date(1_700_000_000_000)
  utimesSync(filePath, frozenTime, frozenTime)
  ksFileOnly.syncFromExternal(true)
  assert.equal(ksFileOnly.isActive(), false)

  // Replace file via atomic rename with the EXACT SAME mtimeMs!
  const tmpFile = `${filePath}.same-ms.tmp`
  writeFileSync(tmpFile, JSON.stringify({
    active: true,
    reason: 'Same-ms global trip',
    trippedBy: 'ops',
    trippedAt: Date.now(),
    tenantId: null,
    generation: 99,
    tenants: {},
  }))
  utimesSync(tmpFile, frozenTime, frozenTime)
  const { renameSync } = await import('node:fs')
  renameSync(tmpFile, filePath)
  utimesSync(filePath, frozenTime, frozenTime)

  ksFileOnly.syncFromExternal(false)
  assert.equal(ksFileOnly.isActive(), true, 'file stat key (mtimeMs, ctimeMs, size, ino) must detect same-ms replacement')
})

// ============================================================================
// M3: OobRelay post-unsubscribe callback rejection & atomic claim()
// ============================================================================

test('M3: OobRelay rejects late callbacks after unsubscribeRun() and claims atomically without orphaning callbacks', t => {
  const dir = makeTempDir(t, 'kovo-m3-oob-')
  const relay = new OobRelay({ directory: dir })
  t.after(() => relay.close())

  const token = `kovo-canary-${'a'.repeat(24)}`
  relay.registerCanary({ token, canaryId: 'canary-m3-1', runId: 'run-m3-1', assignmentId: 'assign-1' })
  const sub = relay.subscribe({
    runId: 'run-m3-1',
    assignmentId: 'assign-1',
    canaryId: 'canary-m3-1',
    token,
    artifact: 'art-m3-1',
  })
  assert.equal(sub.status, 'pending')

  // Unsubscribe run -> expires pending_oob and deletes oob_bindings.
  const unsub = relay.unsubscribeRun('run-m3-1')
  assert.equal(unsub.expiredSubscriptions, 1)
  assert.equal(unsub.removedBindings, 1)

  // Late callback MUST be rejected (not inserted into oob_callbacks!).
  const lateRec = relay.recordCallback({
    token,
    artifact: 'art-m3-1',
    sourceIp: '203.0.113.10',
    method: 'GET',
    path: `/c/${token}`,
  })
  assert.equal(lateRec.accepted, false, 'post-unsubscribe callback must be rejected')
  if (!lateRec.accepted) {
    assert.equal(lateRec.rejection.reason, 'unknown_token')
  }
  assert.equal(relay.callbacksForToken(token).length, 0, 'rejected post-unsubscribe callback must not be stored in oob_callbacks')

  // Atomic claim(): if subscription was concurrently expired before claim(), callback must NOT be orphaned as claimed!
  const token2 = `kovo-canary-${'b'.repeat(24)}`
  relay.registerCanary({ token: token2, canaryId: 'canary-m3-2', runId: 'run-m3-2', assignmentId: 'assign-2' })
  const sub2 = relay.subscribe({
    runId: 'run-m3-2',
    assignmentId: 'assign-2',
    canaryId: 'canary-m3-2',
    token: token2,
    artifact: 'art-m3-2',
  })
  const cbRec = relay.recordCallback({
    token: token2,
    artifact: 'art-m3-2',
    sourceIp: '203.0.113.20',
    method: 'GET',
    path: `/c/${token2}`,
  })
  assert.equal(cbRec.accepted, true)
  if (!cbRec.accepted) throw new Error('expected accepted')
  const recordedCallback = cbRec.callback

  // Concurrently expire sub2 before claim() executes.
  relay.unsubscribeRun('run-m3-2')
  const claimResult = (relay as unknown as {
    claim: (s: typeof sub2, c: typeof recordedCallback, now: number) => { subscription: { status: string }; callback: { claimedBy: string | null } }
  }).claim(sub2, recordedCallback, Date.now())

  assert.equal(claimResult.subscription.status, 'expired')
  const storedCb = relay.callback(recordedCallback.callbackId)
  assert.equal(storedCb?.claimedBy, null, 'atomic claim() must NOT orphan callback.claimed_by when subscription is no longer pending')
})
