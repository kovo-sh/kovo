process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * Option 2 — Move 5B Tests: Explicit `RunActor` FSM, Structured Per-Run `TaskSupervisor`,
 * `RunContext`/`ContainerSupervisor` Wiring, `M-12` Circuit-Open Propagation, `M-47`/`M-48`
 * Host-Only Control Signal Trust & Pagination, and `M-7` Patch Gate 6 Rollback Isolation.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { runCommand, type Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { Execution } from '../src/server/execution.ts'
import { applyUnifiedDiffToDirectory, getSharedLabRunner, type LabRunner } from '../src/server/lab-runner.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import { generateAndReviewPatch } from '../src/server/patch-workflow.ts'
import {
  HOST_PLANNER_PRODUCER,
  InvalidRunTransitionError,
  RunActor,
  canTransition,
  deriveRunActorState,
  installRunActorRejectionGuard,
  isOrphanedRunAbortError,
  isTrustedHostControlFact,
  sanitizeWorkerFactData,
  type RunActorState,
} from '../src/server/run-actor.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const APP_ORIGIN = 'https://actor-test.example.test'

function makeTempStore(t: { after(fn: () => void): void }): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-run-actor-'))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { dir, store }
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"ok":true}',
    }),
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
  opts: { origin?: string; phase?: 'threat_model' | 'investigation' | 'verification'; tier?: 0 | 1 | 2 | 3 } = {},
) {
  const origin = opts.origin ?? APP_ORIGIN
  const project = store.createProject({
    requestId: randomUUID(),
    name: `RunActor Test ${randomUUID().slice(0, 6)}`,
    seeds: [origin],
    environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify RunActor FSM and supervision invariants',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 2,
  } as Parameters<Store['createRun']>[0])
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
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  assert.ok(predicate(), `Timed out waiting for ${label} after ${timeoutMs}ms`)
}

// ---------------------------------------------------------------------------
// 1. Explicit FSM transition table (valid & rejected transitions)
// ---------------------------------------------------------------------------

test('RunActor FSM enforces valid transition edges and rejects illegal phase/status splits', async t => {
  const { dir } = makeTempStore(t)
  const runtime = createAppRuntime({ dataDir: dir })
  t.after(() => runtime.dispose())

  const ctx = runtime.createRunContext(`run-fsm-${randomUUID().slice(0, 8)}`)
  const actor = new RunActor({ context: ctx, initialState: 'queued' })

  // Valid lifecycle walk
  const validPath: RunActorState[] = [
    'initializing',
    'recon',
    'awaiting_scope',
    'investigating',
    'paused',
    'investigating',
    'verifying',
    'completed',
  ]
  for (const next of validPath) {
    assert.equal(actor.canTransitionTo(next), true, `expected ${actor.state} -> ${next} to be legal`)
    actor.transition(next, `step:${next}`)
    assert.equal(actor.state, next)
  }
  assert.equal(actor.isTerminal, true)
  assert.equal(actor.transitions.length, validPath.length)

  // Terminal states have zero outgoing transitions
  for (const target of ['queued', 'initializing', 'investigating', 'verifying', 'paused', 'stopping', 'failed', 'canceled'] as const) {
    assert.equal(canTransition('completed', target), false)
    assert.equal(canTransition('failed', target), false)
    assert.equal(canTransition('canceled', target), false)
    assert.throws(
      () => actor.transition(target, 'illegal-from-terminal'),
      InvalidRunTransitionError,
    )
  }

  // Illegal skips & self-transitions rejected
  assert.equal(canTransition('queued', 'completed'), false)
  assert.equal(canTransition('queued', 'verifying'), false)
  assert.equal(canTransition('investigating', 'completed'), false)
  assert.equal(canTransition('stopping', 'investigating'), false)
  assert.equal(canTransition('investigating', 'investigating'), false)

  const ctx2 = runtime.createRunContext(`run-fsm-illegal-${randomUUID().slice(0, 8)}`)
  const actor2 = new RunActor({ context: ctx2, initialState: 'investigating' })
  assert.throws(() => actor2.transition('completed', 'skip-verify'), InvalidRunTransitionError)
  assert.throws(() => actor2.transition('investigating', 'self-loop'), InvalidRunTransitionError)
  // syncState is an idempotent no-op for the current state
  assert.equal(actor2.syncState('investigating', 'noop'), 'investigating')

  // Store (status, phase) mapping
  assert.equal(deriveRunActorState({ status: 'waiting', phase: 'consent' }), 'queued')
  assert.equal(deriveRunActorState({ status: 'running', phase: 'discovery' }), 'recon')
  assert.equal(deriveRunActorState({ status: 'waiting', phase: 'review' }), 'awaiting_scope')
  assert.equal(deriveRunActorState({ status: 'running', phase: 'threat_model' }), 'initializing')
  assert.equal(deriveRunActorState({ status: 'running', phase: 'investigation' }), 'investigating')
  assert.equal(deriveRunActorState({ status: 'running', phase: 'verification' }), 'verifying')
  assert.equal(deriveRunActorState({ status: 'paused', phase: 'investigation' }), 'paused')
  assert.equal(deriveRunActorState({ status: 'complete', phase: 'complete' }), 'completed')
  assert.equal(deriveRunActorState({ status: 'failed', phase: 'investigation' }), 'failed')
  assert.equal(deriveRunActorState({ status: 'stopped', phase: 'investigation' }), 'canceled')
})

// ---------------------------------------------------------------------------
// 2. TaskSupervisor abort + drain barrier on stop()/deleteRun(), vault & OOB disposal, M-20
// ---------------------------------------------------------------------------

test('TaskSupervisor aborts and drains all supervised tasks & timers before deleteRun() and stop()', async t => {
  const { dir, store } = makeTempStore(t)
  const runtime = createAppRuntime({ dataDir: dir, store })
  const canaryBroker = new CanaryBroker({ storage: store, oobDirectory: dir })
  runtime.attachCanaryBroker(canaryBroker)
  t.after(async () => {
    await canaryBroker.stop().catch(() => undefined)
    canaryBroker.closeOob()
  })

  const runA = createApprovedRun(store, { phase: 'investigation' })
  const runB = createApprovedRun(store, { phase: 'investigation' })

  // Default labRunner uses shared singleton (M-20)
  const execution = new Execution(store, {
    runtime,
    canaryBroker,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  assert.equal(execution.labRunner, getSharedLabRunner(), 'Execution must default to getSharedLabRunner() (M-20)')

  // Seed capability vaults (RAM + disk) and OOB subscriptions for both runA and runB
  const vaultA = execution.capabilityVaultFor(runA.runId)
  vaultA.seal({ hopReceiptId: 'hop-a', slot: 'tok', rawValue: 'secret-token-value-run-a-123456' })
  const vaultB = execution.capabilityVaultFor(runB.runId)
  vaultB.seal({ hopReceiptId: 'hop-b', slot: 'tok', rawValue: 'secret-token-value-run-b-123456' })

  const vaultFileA = join(dir, 'capability-vaults', `${runA.runId}.json`)
  const vaultFileB = join(dir, 'capability-vaults', `${runB.runId}.json`)
  assert.equal(existsSync(vaultFileA), true)
  assert.equal(existsSync(vaultFileB), true)

  const mintedA = canaryBroker.mintCanary(runA.runId, 'oob-runA', APP_ORIGIN, { storage: store })
  const mintedB = canaryBroker.mintCanary(runB.runId, 'oob-runB', APP_ORIGIN, { storage: store })
  const subA = canaryBroker.subscribe({
    runId: runA.runId,
    assignmentId: 'assign-a',
    canaryId: mintedA.id,
    token: mintedA.token,
    artifact: 'artifact-a',
  })
  const subB = canaryBroker.subscribe({
    runId: runB.runId,
    assignmentId: 'assign-b',
    canaryId: mintedB.id,
    token: mintedB.token,
    artifact: 'artifact-b',
  })
  assert.equal(canaryBroker.oob.subscription(subA.id)?.status, 'pending')
  assert.equal(canaryBroker.oob.subscription(subB.id)?.status, 'pending')

  // Spawn an in-flight supervised task + timer on runA that only settles after receiving abort
  const priv = execution as unknown as {
    ensureRunActor: (runId: string) => RunActor
    capabilityVaults: Map<string, unknown>
  }
  const actorA = priv.ensureRunActor(runA.runId)
  let taskAborted = false
  let taskCleanedUp = false
  let timerFired = false

  actorA.scheduleTimer('never-fire-after-delete', 5_000, () => {
    timerFired = true
  })
  actorA.spawn('long-worker-job', async signal => {
    await new Promise<void>(resolve => {
      signal.addEventListener('abort', () => {
        taskAborted = true
        setTimeout(() => {
          taskCleanedUp = true
          resolve()
        }, 35)
      }, { once: true })
    })
  })
  assert.equal(actorA.activeTaskCount, 1)

  // Execution.deleteRun(runA) MUST abort & drain the task BEFORE returning, evict RAM+disk vault,
  // unsubscribe OOB for runA, dispose RunContext, and leave sibling runB completely intact.
  const del = await execution.deleteRun(runA.runId)
  assert.equal(del.deleted, true)
  assert.equal(taskAborted, true, 'deleteRun must abort supervised tasks')
  assert.equal(taskCleanedUp, true, 'deleteRun must drain supervised tasks to completion before deleting')
  assert.equal(timerFired, false, 'deleteRun must cancel run-scoped timers')
  assert.equal(actorA.state, 'canceled')
  assert.equal(runtime.getRunContext(runA.runId), undefined, 'RunContext for deleted runA must be removed')
  assert.equal(priv.capabilityVaults.has(runA.runId), false, 'runA vault must be evicted from RAM')
  assert.equal(existsSync(vaultFileA), false, 'runA vault file must be evicted from disk')
  assert.equal(canaryBroker.oob.subscription(subA.id)?.status, 'expired', 'runA OOB subscription must be unsubscribed')

  // Sibling runB stays untouched
  assert.equal(priv.capabilityVaults.has(runB.runId), true, 'runB RAM vault must stay intact')
  assert.equal(existsSync(vaultFileB), true, 'runB disk vault must stay intact')
  assert.equal(canaryBroker.oob.subscription(subB.id)?.status, 'pending', 'runB OOB subscription must stay intact')

  // Now stop() drains and disposes runB too
  const actorB = priv.ensureRunActor(runB.runId)
  let runBDrained = false
  actorB.spawn('runb-task', async signal => {
    await new Promise<void>(resolve => {
      signal.addEventListener('abort', () => {
        setTimeout(() => {
          runBDrained = true
          resolve()
        }, 20)
      }, { once: true })
    })
  })
  await execution.stop()
  assert.equal(runBDrained, true, 'Execution.stop() must drain all active RunActor tasks')
  assert.equal(runtime.getRunContext(runB.runId), undefined, 'Execution.stop() must dispose RunContext')
  assert.equal(priv.capabilityVaults.size, 0, 'Execution.stop() must evict RAM capability vaults')
  assert.equal(existsSync(vaultFileB), false, 'Execution.stop() must evict disk capability vaults')
  assert.equal(canaryBroker.oob.subscription(subB.id)?.status, 'expired', 'Execution.stop() must unsubscribe OOB')

  // Idempotent rejection guard helper
  const logged: Array<{ kind: string; isAbort: boolean }> = []
  const uninstall1 = installRunActorRejectionGuard(entry => logged.push(entry))
  const uninstall2 = installRunActorRejectionGuard(entry => logged.push(entry))
  assert.equal(isOrphanedRunAbortError(new DOMException('aborted', 'AbortError')), true)
  assert.equal(isOrphanedRunAbortError(new Error('RunContext "r1" disposed.')), true)
  assert.equal(isOrphanedRunAbortError(new Error('unrelated database crash')), false)
  uninstall1()
  uninstall2()
})

// ---------------------------------------------------------------------------
// 3. M-12: circuit-open blocked steps propagate to pending dependents (zero wedge)
// ---------------------------------------------------------------------------

test('M-12: blocked circuit-open step transitively taints pending dependents and never wedges driveInvestigation', async t => {
  const { dir, store } = makeTempStore(t)
  const runtime = createAppRuntime({ dataDir: dir, store })
  await saveModelProfile({
    name: 'M12 Circuit Model',
    endpoint: 'https://api.example.test/v1',
    model: 'test-model',
    protocol: 'responses',
    key: 'sk-test-m12-key-123456',
    enabled: true,
    priority: 100,
  }, store, { skipConnectionCheck: true })

  const { runId, run } = createApprovedRun(store, { phase: 'investigation', tier: 2 })
  const asset = run.candidates[0]!

  const stepA = store.addChainStep(run, {
    title: 'Step A on circuit-open origin',
    hypothesis: 'Origin circuit breaker opens before dispatch',
    category: 'broken-access-control',
    priority: 90,
    targetAssetIds: [asset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [APP_ORIGIN],
  })
  const stepB = store.addChainStep(run, {
    title: 'Step B depending on Step A',
    hypothesis: 'Must taint when A is blocked',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [asset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [stepA.id],
    sourceOrigins: [APP_ORIGIN],
  })
  const stepC = store.addChainStep(run, {
    title: 'Step C transitively depending on Step B',
    hypothesis: 'Must transitively taint when B is tainted from A',
    category: 'broken-access-control',
    priority: 70,
    targetAssetIds: [asset.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [stepB.id],
    sourceOrigins: [APP_ORIGIN],
  })

  // 1. Direct Store check: refreshReadyChainSteps propagates blocked -> tainted transitively
  store.updateChainStep(stepA.id, { status: 'blocked' })
  store.refreshReadyChainSteps(runId, run.goalRevision)
  const afterDirect = store.listChainSteps(runId, run.goalRevision)
  assert.equal(afterDirect.find(s => s.id === stepB.id)?.status, 'tainted', 'direct dependent of blocked step must taint')
  assert.equal(afterDirect.find(s => s.id === stepC.id)?.status, 'tainted', 'transitive dependent of blocked step must taint')

  // 2. End-to-end Execution.driveInvestigation with live circuit-open broker
  const run2 = createApprovedRun(store, { phase: 'investigation', tier: 2 })
  const asset2 = run2.run.candidates[0]!
  const s1 = store.addChainStep(run2.run, {
    title: 'Ready step on circuit-open origin',
    hypothesis: 'Will become blocked in driveInvestigation',
    category: 'broken-access-control',
    priority: 90,
    targetAssetIds: [asset2.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [APP_ORIGIN],
  })
  const API_ORIGIN = 'https://api.example.test'
  const s2 = store.addChainStep(run2.run, {
    title: 'Pending dependent on same circuit-open origin',
    hypothesis: 'Transitions directly to blocked via reconcileUnavailableOriginSteps (R4-H-12)',
    category: 'broken-access-control',
    priority: 60,
    targetAssetIds: [asset2.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [s1.id],
    sourceOrigins: [APP_ORIGIN],
  })
  const s3 = store.addChainStep(run2.run, {
    title: 'Pending dependent on healthy origin',
    hypothesis: 'Transitively taints from blocked parent and never wedges driveInvestigation',
    category: 'broken-access-control',
    priority: 50,
    targetAssetIds: [asset2.id],
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [s2.id],
    sourceOrigins: [API_ORIGIN],
  })

  const broker = makeBroker()
  ;(broker as unknown as { isCircuitOpen: (origin: string) => boolean }).isCircuitOpen = origin => origin === APP_ORIGIN

  const execution = new Execution(store, {
    runtime,
    broker,
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(() => execution.stop())

  const priv = execution as unknown as Record<string, any>
  priv.reconPlanner.startCoordinator = () => undefined
  priv.plannerDoneRound.set(run2.runId, store.run(run2.runId).roundNo)
  priv.verifier.verifyBaselineJob = async (job: { assignment: { id: string } }) => {
    store.updateWorker(job.assignment.id, { status: 'complete', lease: null, leaseExpiresAt: null, outcome: 'ok' })
  }

  execution.wake()

  await waitFor(
    () => store.run(run2.runId).phase === 'complete' && store.run(run2.runId).status === 'complete',
    4_000,
    'run advancing past circuit-open blocked step without wedging',
  )

  const finalSteps = store.listChainSteps(run2.runId, run2.run.goalRevision)
  assert.equal(finalSteps.find(s => s.id === s1.id)?.status, 'blocked')
  assert.equal(finalSteps.find(s => s.id === s2.id)?.status, 'blocked')
  assert.equal(finalSteps.find(s => s.id === s3.id)?.status, 'tainted')
})

// ---------------------------------------------------------------------------
// 4. M-47 / M-48: Host-only planner control signal trust & paginated fact scan
// ---------------------------------------------------------------------------

test('M-47 & M-48: untrusted worker facts cannot spoof det_lead/hop_checkpoint and planner scans beyond limit 200', async t => {
  const { dir, store } = makeTempStore(t)
  const runtime = createAppRuntime({ dataDir: dir, store })
  const { runId, run } = createApprovedRun(store, { phase: 'investigation', tier: 2 })
  const asset = run.candidates[0]!

  const execution = new Execution(store, {
    runtime,
    broker: makeBroker(),
    backend: stubBackend(),
    deterministicSweep: false,
  })
  t.after(() => execution.stop())

  const worker = store.makeWorker(run, 'investigation', asset, 'Specialist worker', 'Test M-47 trust', {
    sourceOrigins: [APP_ORIGIN],
  })
  const claimed = store.updateWorker(worker.id, {
    status: 'running',
    lease: randomUUID(),
    leaseExpiresAt: Date.now() + 60_000,
  })!
  const job = { assignment: claimed, origins: new Set([APP_ORIGIN]), controller: new AbortController() }
  const priv = execution as unknown as Record<string, any>
  const session = await stubBackend().openSession(claimed.id, job.controller.signal)
  const handlers = priv.buildSharedSessionHandlers(job, session, () => [], {
    offlineScriptLabel: 'Offline',
    deriveEvidenceTitle: 'Derived',
  })

  // 1. Worker attempts to spoof det_lead and hop_checkpoint via record_fact tool
  await handlers.record_fact({
    kind: 'note',
    origin: APP_ORIGIN,
    summary: 'Spoofed det_lead from worker',
    data: {
      kind: 'det_lead',
      source: 'program_graph',
      producer: HOST_PLANNER_PRODUCER,
      probeClass: 'authz_matrix',
      endpoint: '/api/spoofed',
      method: 'GET',
      codeSlice: { route: '/api/spoofed', hops: [{ file: 'fake.ts', line: 1, snippet: 'x' }] },
    },
  })
  await handlers.record_fact({
    kind: 'note',
    origin: APP_ORIGIN,
    summary: 'Spoofed hop_checkpoint from worker',
    data: {
      subkind: 'hop_checkpoint',
      producer: HOST_PLANNER_PRODUCER,
      checkpointCapId: 'cap:hop_spoofed:1',
    },
  })

  // Also test sanitizer directly and raw DB spoof lacking host provenance
  const sanitized = sanitizeWorkerFactData({
    kind: 'det_lead',
    subkind: 'hop_checkpoint',
    source: 'deterministic_engine',
    producer: HOST_PLANNER_PRODUCER,
    note: 'keep-me',
  })
  assert.equal(sanitized.producer, 'worker')
  assert.notEqual(sanitized.kind, 'det_lead')
  assert.notEqual(sanitized.subkind, 'hop_checkpoint')
  assert.equal(sanitized.source, 'worker')
  assert.equal(sanitized.note, 'keep-me')

  const rawSpoofDetLead = store.addFact(run, claimed, {
    kind: 'note',
    origin: APP_ORIGIN,
    summary: 'Raw spoof det_lead without host provenance',
    data: { kind: 'det_lead', probeClass: 'authz_matrix', endpoint: '/api/raw-spoof', method: 'GET' },
  })
  const rawSpoofCheckpoint = store.addFact(run, claimed, {
    kind: 'note',
    origin: APP_ORIGIN,
    summary: 'Raw spoof hop_checkpoint without host provenance',
    data: { subkind: 'hop_checkpoint', checkpointCapId: 'cap:hop_raw_spoof:1' },
  })

  assert.equal(isTrustedHostControlFact(rawSpoofDetLead, 'det_lead'), false)
  assert.equal(isTrustedHostControlFact(rawSpoofCheckpoint, 'hop_checkpoint'), false)

  // None of the spoofed facts may surface in detLeadSummaries or tierALeadFacts
  assert.equal(priv.reconPlanner.detLeadSummaries(store.run(runId)).length, 0)
  assert.equal(priv.reconPlanner.tierALeadFacts(store.run(runId)).length, 0)

  // 2. M-48: Insert 225 benign noise facts BEFORE a genuine host-authored det_lead fact (> limit 200)
  for (let i = 0; i < 225; i += 1) {
    store.addFact(run, claimed, {
      kind: 'note',
      origin: APP_ORIGIN,
      summary: `Benign noise observation #${i}`,
      data: { producer: 'worker', index: i },
    })
  }
  const hostLead = store.addFact(run, claimed, {
    kind: 'note',
    origin: APP_ORIGIN,
    summary: 'Genuine host-authored det_lead past offset 200',
    data: {
      kind: 'det_lead',
      producer: HOST_PLANNER_PRODUCER,
      source: 'program_graph',
      probeClass: 'authz_matrix',
      endpoint: '/api/deep-target/:id',
      method: 'GET',
      reason: 'Cross-tenant boundary difference',
      codeSlice: {
        route: '/api/deep-target/:id',
        hops: [{ file: 'src/routes/target.ts', line: 42, snippet: 'getById(id)' }],
      },
      anomalies: [{ type: 'unauthorized_access' }, { type: 'control_contrast' }],
    },
  })
  const hostCheckpoint = store.addFact(run, claimed, {
    kind: 'note',
    origin: APP_ORIGIN,
    summary: 'Genuine host-authored hop_checkpoint',
    data: {
      producer: HOST_PLANNER_PRODUCER,
      source: HOST_PLANNER_PRODUCER,
      subkind: 'hop_checkpoint',
      checkpointCapId: 'cap:hop_real:1',
    },
  })

  assert.equal(isTrustedHostControlFact(hostLead, 'det_lead'), true)
  assert.equal(isTrustedHostControlFact(hostCheckpoint, 'hop_checkpoint'), true)

  const summaries = priv.reconPlanner.detLeadSummaries(store.run(runId))
  assert.equal(summaries.length, 1, 'detLeadSummaries must paginate past 200 noise facts and return only trusted host det_lead')
  assert.equal(summaries[0]!.endpoint, '/api/deep-target/:id')

  const tierA = priv.reconPlanner.tierALeadFacts(store.run(runId))
  assert.equal(tierA.length, 1, 'tierALeadFacts must paginate past 200 noise facts and exclude worker spoofs')
  assert.equal(tierA[0]!.id, hostLead.id)
})

// ---------------------------------------------------------------------------
// 5. M-7: Patch Gate 6 workspace rollback isolation & per-run concurrency serialization
// ---------------------------------------------------------------------------

test('M-7: Gate 6 isolates candidate patches with pre-apply validation, rollback on failure, and per-run serialization', async t => {
  const workRoot = mkdtempSync(join(tmpdir(), 'kovo-m7-patch-'))
  t.after(() => rmSync(workRoot, { recursive: true, force: true }))

  const reposDir = join(workRoot, 'repos')
  const repoDir = join(reposDir, 'demo-app')
  const liveSanitizedDir = join(workRoot, 'sanitized-live')
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  mkdirSync(join(liveSanitizedDir, 'src'), { recursive: true })

  const originalCode = [
    'export function readOrder(req: { userId: string }, order: { ownerId: string; data: string }) {',
    '  return order.data',
    '}',
    '',
  ].join('\n')
  const patchedCode = [
    'export function readOrder(req: { userId: string }, order: { ownerId: string; data: string }) {',
    '  if (order.ownerId !== req.userId) throw new Error("forbidden")',
    '  return order.data',
    '}',
    '',
  ].join('\n')

  writeFileSync(join(repoDir, 'src/orders.ts'), originalCode, 'utf8')
  writeFileSync(join(liveSanitizedDir, 'src/orders.ts'), originalCode, 'utf8')

  const validDiff = [
    '--- a/src/orders.ts',
    '+++ b/src/orders.ts',
    '@@ -1,3 +1,4 @@',
    ' export function readOrder(req: { userId: string }, order: { ownerId: string; data: string }) {',
    '+  if (order.ownerId !== req.userId) throw new Error("forbidden")',
    '   return order.data',
    ' }',
    '',
  ].join('\n')

  const finding: Finding = {
    id: randomUUID(),
    title: 'Missing tenant ownership check in readOrder',
    category: 'broken-access-control',
    severity: 'high',
    status: 'confirmed',
    cwe: 'CWE-639',
    summary: 'readOrder returns order data without verifying req.userId === order.ownerId.',
    remediation: 'Check ownership before returning order data.',
    evidenceIds: [],
    assetIds: [],
    codeLocations: [{ repo: 'demo-app', file: 'src/orders.ts', startLine: 1, endLine: 3 }],
  } as unknown as Finding

  const dummySpec = {
    version: 1,
    kind: 'http_chain',
    steps: [{
      role: 'control',
      request: { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/orders/1' },
    }],
  } as unknown as DeclarativeReplaySpec

  const dummyGrant: Grant = {
    tier: 2,
    allowLocalLab: true,
    maxRpsPerOrigin: 50,
    canRead: () => true,
    audit: () => undefined,
  }

  const candidatePatch = {
    repo: 'demo-app',
    fixBefore: originalCode,
    fixAfter: patchedCode,
    diff: validDiff,
    rationale: 'Enforce owner check before returning order.',
    codeLocations: [{ repo: 'demo-app', file: 'src/orders.ts', startLine: 1, endLine: 3 }],
    coverageInventory: [{
      file: 'src/orders.ts',
      line: 1,
      symbol: 'readOrder',
      role: 'primary_sink' as const,
      coveredByPatch: true,
      notes: 'Primary read handler',
    }],
    syntaxCheck: { ran: true, passed: true },
  }

  const approveReviewCall = async () => JSON.stringify({
    approved: true,
    callerCompatibility: 'attacker_only',
    gates: [
      { gate: 1, name: 'applicability', passed: true, detail: 'Applies cleanly' },
      { gate: 2, name: 'security_closure', passed: true, detail: 'Closes ownership bypass' },
      { gate: 3, name: 'sibling_coverage', passed: true, detail: 'No sibling bypasses' },
      { gate: 4, name: 'caller_compatibility', passed: true, detail: 'Authorized callers preserved' },
      { gate: 5, name: 'repo_conventions', passed: true, detail: 'Follows repo style' },
    ],
    enforcingLocation: 'src/orders.ts:2',
    reviewNotes: 'Approved statically.',
  })

  // 1. Failing rebuild mutates liveSanitizedDir in place -> M-7 MUST roll back liveSanitizedDir byte-for-byte
  let rebuildCalls = 0
  let inFlightCount = 0
  let maxConcurrentRebuilds = 0
  const mockLabRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      rebuildCalls += 1
      inFlightCount += 1
      maxConcurrentRebuilds = Math.max(maxConcurrentRebuilds, inFlightCount)
      try {
        applyUnifiedDiffToDirectory(liveSanitizedDir, diff)
        assert.equal(
          readFileSync(join(liveSanitizedDir, 'src/orders.ts'), 'utf8'),
          patchedCode,
          'rebuildWithPatch applied candidate diff into workspace during retest',
        )
        await new Promise(resolve => setTimeout(resolve, 40))
        throw new Error('simulated Gate-6 healthcheck failure')
      } finally {
        inFlightCount -= 1
      }
    },
  } as unknown as LabRunner

  const runId = `run-m7-${randomUUID().slice(0, 8)}`
  const [res1, res2] = await Promise.all([
    generateAndReviewPatch({
      runId,
      finding,
      repo: 'demo-app',
      reposDir,
      candidatePatch,
      reviewerLlmCall: approveReviewCall,
      labRetest: {
        labRunner: mockLabRunner,
        runId,
        sanitizedRepoDir: liveSanitizedDir,
        replaySpec: dummySpec,
        broker: makeBroker(),
        backend: stubBackend(),
        grant: dummyGrant,
      },
    }),
    generateAndReviewPatch({
      runId,
      finding,
      repo: 'demo-app',
      reposDir,
      candidatePatch,
      reviewerLlmCall: approveReviewCall,
      labRetest: {
        labRunner: mockLabRunner,
        runId,
        sanitizedRepoDir: liveSanitizedDir,
        replaySpec: dummySpec,
        broker: makeBroker(),
        backend: stubBackend(),
        grant: dummyGrant,
      },
    }),
  ])

  assert.equal(res1.status, 'withheld')
  assert.equal(res2.status, 'withheld')
  assert.equal(rebuildCalls, 2)
  assert.equal(maxConcurrentRebuilds, 1, 'concurrent Gate-6 retests for the same runId must be strictly serialized')
  assert.equal(
    readFileSync(join(liveSanitizedDir, 'src/orders.ts'), 'utf8'),
    originalCode,
    'live sanitizedRepoDir must be rolled back byte-for-byte after Gate-6 failure',
  )

  // 2. Unapplicable diff fails during isolated temp-copy validation BEFORE rebuildWithPatch is ever called
  let badRebuildCalls = 0
  const neverCalledLabRunner = {
    rebuildWithPatch: async () => {
      badRebuildCalls += 1
      throw new Error('must not be called')
    },
  } as unknown as LabRunner

  const staleDiff = [
    '--- a/src/orders.ts',
    '+++ b/src/orders.ts',
    '@@ -1,3 +1,4 @@',
    ' export function nonExistentLine() {',
    '+  return false',
    ' }',
    '',
  ].join('\n')

  // Overwrite liveSanitizedDir with divergent content so dry-run apply against liveSanitizedDir fails
  const divergentLive = 'export function otherSignature() { return null }\n'
  writeFileSync(join(liveSanitizedDir, 'src/orders.ts'), divergentLive, 'utf8')
  const resBad = await generateAndReviewPatch({
    runId,
    finding,
    repo: 'demo-app',
    reposDir,
    candidatePatch: { ...candidatePatch, diff: validDiff },
    reviewerLlmCall: approveReviewCall,
    labRetest: {
      labRunner: neverCalledLabRunner,
      runId,
      sanitizedRepoDir: liveSanitizedDir,
      replaySpec: dummySpec,
      broker: makeBroker(),
      backend: stubBackend(),
      grant: dummyGrant,
    },
  })
  assert.equal(resBad.status, 'withheld')
  assert.equal(badRebuildCalls, 0, 'unapplicable diff must fail in isolated scratch copy before rebuildWithPatch')
  assert.equal(readFileSync(join(liveSanitizedDir, 'src/orders.ts'), 'utf8'), divergentLive)
  assert.ok(staleDiff.length > 0)
})
