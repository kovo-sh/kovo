// @fixes R3-20
/**
 * R3-20 Authoritative Persisted Lifecycle, Pause-Aware Resources,
 * TTL/UI Consistency, Emit-Only Liveness Checker, and Seeded Lifecycle Fuzz (<5s).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import { newProject, newRun, runCommand, type RunStatus } from '../src/domain.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import { purgeExpiredArtifacts } from '../src/server/artifact-ttl.ts'
import type { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { Execution } from '../src/server/execution.ts'
import { LabRunner } from '../src/server/lab-runner.ts'
import {
  checkRunLiveness,
  emitRunLivenessViolations,
  IllegalLifecycleTransitionError,
  LIFECYCLE_TRANSITION_TABLES,
  type RunLivenessSnapshot,
  validateLifecycleTransition,
} from '../src/server/lifecycle.ts'
import { clearQaAnomalies, listQaAnomalies } from '../src/server/qa-anomalies.ts'
import type { RunTier3ApprovalCoordinator } from '../src/server/run-actor.ts'
import {
  canOfferResumeButton,
  canResumeRun,
  canResumeRunStatus,
  isEligibleForArtifactTtlPurge,
  isTerminalRunStatus,
  RUN_STATUSES,
} from '../src/server/run-status.ts'
import { StorageMaintenanceController } from '../src/server/storage-maintenance.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'

const ORIGIN = 'https://lifecycle-fuzz.example.test'

function makeTempDir(t: test.TestContext, prefix = 'kovo-r3-20-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeTempStore(t: test.TestContext, prefix = 'kovo-r3-20-'): { dir: string; store: Store } {
  const dir = makeTempDir(t, prefix)
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
  })
  return { dir, store }
}

function setupApprovedRun(store: Store, name = 'Lifecycle App', phase: 'investigation' | 'threat_model' = 'investigation') {
  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [ORIGIN],
  }))
  const { id: runId } = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: `Verify lifecycle invariants for ${name}`,
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 25,
    budgetRequests: 500,
  }))
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: false,
    capabilityTier: 2,
  }))
  if (phase !== 'threat_model') {
    store.updateRun(runId, { phase })
  }
  const run = store.run(runId)
  const asset = run.candidates[0]!
  return { projectId: project.id, runId, run, asset }
}

function createMulberry32(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function stubBroker(): RequestBroker {
  return {
    send: async () => { throw new Error('stub broker') },
    disposeRun: () => undefined,
    isCircuitOpen: () => false,
    close: () => undefined,
  } as unknown as RequestBroker
}

function makeWarmPoolTrackingBackend() {
  const warmContainersByRun = new Map<string, number>()
  const evictCalls: string[] = []
  const backend: WorkerBackend = {
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
    async evictRunWarmPool(runId: string) {
      evictCalls.push(runId)
      warmContainersByRun.set(runId, 0)
    },
  }
  return { backend, warmContainersByRun, evictCalls }
}

// ============================================================================
// 1. Stopped/Failed = Terminal: Artifact TTL NEVER selects any run UI offers to resume
// ============================================================================

describe('R3-20.1: stopped/failed terminal contract & artifact-ttl vs UI Resume disjointness', () => {
  test('artifact-ttl and storage-maintenance NEVER select any run that canResumeRun() or UI Resume offers to resume', t => {
    const { dir, store } = makeTempStore(t, 'kovo-r3-20-ttl-ui-')
    const baseNow = Date.now()
    const agedTs = baseNow - 3 * 60 * 60_000
    const staleMtimeSec = Math.floor(agedTs / 1000)

    const runsByStatus = new Map<RunStatus, { runId: string; scratchDir: string }>()

    for (const status of RUN_STATUSES) {
      // Predicate-level mathematical disjointness across EVERY canonical RunStatus
      const ttlEligible = isEligibleForArtifactTtlPurge(status)
      const resumable = canResumeRun({ status, phase: 'investigation' })
      const uiOffersResume = canOfferResumeButton({ status, phase: 'investigation' })
      assert.equal(canResumeRunStatus(status), resumable)
      assert.equal(
        ttlEligible && resumable,
        false,
        `status="${status}" cannot be BOTH TTL-purge-eligible and resumable`,
      )
      assert.equal(
        ttlEligible && uiOffersResume,
        false,
        `status="${status}" cannot be BOTH TTL-purge-eligible and offered UI Resume`,
      )

      const { runId, run, asset } = setupApprovedRun(store, `TTL-${status}`)
      const worker = store.makeWorker(run, 'investigation', asset, `w-${status}`, 'Check artifact')
      const ev = store.addArtifact(run, worker, 'observation', `obs-${status}`, JSON.stringify({ status }))
      store.flushNow()
      store.client.prepare('UPDATE evidence SET created_at = ? WHERE id = ?').run(agedTs, ev.id)

      const scratchDir = join(dir, 'scratch', runId)
      mkdirSync(scratchDir, { recursive: true })
      const scratchFile = join(scratchDir, 'temp.txt')
      writeFileSync(scratchFile, `scratch-${status}`)
      utimesSync(scratchFile, staleMtimeSec, staleMtimeSec)
      utimesSync(scratchDir, staleMtimeSec, staleMtimeSec)

      store.client.prepare('UPDATE runs SET status = ? WHERE id = ?').run(status, runId)
      runsByStatus.set(status, { runId, scratchDir })
    }

    // Behavioral verification: artifact-ttl MUST skip every status offered Resume or accepted by resume command
    for (const status of RUN_STATUSES) {
      const { runId } = runsByStatus.get(status)!
      const purge = purgeExpiredArtifacts(store, {
        runId,
        artifactTtlMs: 60_000,
        skipActiveRuns: true,
        preserveConfirmedEvidence: false,
        now: baseNow,
      })
      const resumable = canResumeRun({ status, phase: 'investigation' })
      const uiOffersResume = canOfferResumeButton({ status, phase: 'investigation' })

      if (resumable || uiOffersResume) {
        assert.equal(purge.runsScanned, 0, `artifact-ttl MUST NEVER scan resumable status "${status}"`)
        assert.equal(purge.artifactsDeleted, 0, `artifact-ttl MUST NEVER delete artifacts for resumable status "${status}"`)
      } else if (isTerminalRunStatus(status)) {
        assert.equal(purge.runsScanned, 1, `terminal status "${status}" should be eligible for TTL purge`)
        assert.equal(purge.artifactsDeleted, 1)
        // Terminal runs (`complete`, `stopped`, `failed`) MUST reject `resume`
        assert.throws(
          () => store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' })),
          /cannot be resumed|terminal/i,
          `terminal status "${status}" must reject resume command`,
        )
      }
    }

    // StorageMaintenanceController.sweepOrphans MUST protect every resumable/non-terminal run
    const maint = new StorageMaintenanceController({
      store,
      dataDir: dir,
      ttlPolicy: false,
      orphanGraceMs: 60_000,
      now: () => baseNow,
    })
    maint.sweepOrphans({ graceMs: 60_000, now: baseNow })
    for (const status of RUN_STATUSES) {
      const { scratchDir } = runsByStatus.get(status)!
      if (canResumeRun({ status, phase: 'investigation' }) || canOfferResumeButton({ status, phase: 'investigation' })) {
        assert.equal(existsSync(scratchDir), true, `storage-maintenance MUST protect scratch for resumable status "${status}"`)
      }
    }
  })
})

// ============================================================================
// 2. Preserve In-Flight Investigation Steps on Pause -> Resume & Worker Cancel
// ============================================================================

describe('R3-20.2: preserve in-flight investigation steps across pause -> resume', () => {
  test('pause -> resume with a running investigation step requeues the step to ready instead of canceling or stranding it', t => {
    const { store } = makeTempStore(t, 'kovo-r3-20-pause-step-')
    const { runId, run, asset } = setupApprovedRun(store, 'PauseStep')
    const worker = store.makeWorker(run, 'investigation', asset, 'Investigate /api/items', 'Probe access control')
    const step = store.addChainStep(run, {
      title: 'Test BOLA on /api/items',
      hypothesis: 'Verify tenant isolation on /api/items',
      targetAssetIds: [asset.id],
      skills: ['bola'],
      dependsOnFactIds: [],
      dependsOnStepIds: [],
      sourceOrigins: [ORIGIN],
    })
    store.updateWorker(worker.id, { status: 'running', stepId: step.id, lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 })
    store.updateChainStep(step.id, { status: 'running', assignedWorkerId: worker.id })
    store.updateBoardMemberState(runId, 'coordinator', { state: 'working', activeAssignmentId: worker.id })

    // Pause run
    store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'pause' }))
    assert.equal(store.run(runId).status, 'paused')
    assert.equal(store.worker(worker.id).status, 'paused')
    assert.equal(store.boardMember(runId, 'coordinator')?.state, 'waiting')

    const stepAfterPause = store.listChainSteps(runId, run.goalRevision).find(s => s.id === step.id)!
    assert.equal(stepAfterPause.status, 'ready', 'in-flight investigation step must be requeued to ready on pause')
    assert.equal(stepAfterPause.assignedWorkerId, null)

    // Resume run
    store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' }))
    assert.equal(store.run(runId).status, 'running')
    const stepAfterResume = store.listChainSteps(runId, run.goalRevision).find(s => s.id === step.id)!
    assert.equal(stepAfterResume.status, 'ready', 'in-flight investigation step must remain ready (not canceled/lost) after resume')
    assert.equal(stepAfterResume.assignedWorkerId, null)

    // Verify 0 liveness invariant violations
    const violations = checkRunLiveness({
      run: store.run(runId),
      assignments: store.workerList(runId),
      chainSteps: store.listChainSteps(runId, run.goalRevision),
      boardMembers: store.listBoardMembers(runId),
      approvalRequests: store.listApprovalRequests(runId),
      approvalLeases: store.listApprovalLeases(runId),
    })
    assert.deepEqual(violations, [])
  })

  test('reconcileSettledApprovalWorkers requeues a running step when its worker was canceled by interruption/status change (not operator cancel)', async t => {
    const { dir, store } = makeTempStore(t, 'kovo-r3-20-reconcile-step-')
    const runtime = createAppRuntime({ dataDir: dir, store, maintenance: false, autoStartMaintenance: false })
    const { backend } = makeWarmPoolTrackingBackend()
    const exec = new Execution(store, { runtime, broker: stubBroker(), backend, deterministicSweep: false })
    t.after(async () => {
      await exec.stop()
      await runtime.dispose()
    })

    const { runId, run, asset } = setupApprovedRun(store, 'ReconcileStep')
    const workerInterrupted = store.makeWorker(run, 'investigation', asset, 'Interrupted worker', 'Probe A')
    const stepInterrupted = store.addChainStep(run, {
      title: 'Step A (interrupted)',
      hypothesis: 'Must be requeued to ready',
      targetAssetIds: [asset.id],
      skills: ['sqli'],
      dependsOnFactIds: [],
      dependsOnStepIds: [],
      sourceOrigins: [ORIGIN],
    })
    store.updateWorker(workerInterrupted.id, {
      status: 'canceled',
      stepId: stepInterrupted.id,
      outcome: 'Assignment authorization changed.',
    })
    store.updateChainStep(stepInterrupted.id, { status: 'running', assignedWorkerId: workerInterrupted.id })

    const workerOperatorCanceled = store.makeWorker(run, 'investigation', asset, 'Operator canceled worker', 'Probe B')
    const stepOperatorCanceled = store.addChainStep(run, {
      title: 'Step B (operator canceled)',
      hypothesis: 'Must settle canceled',
      targetAssetIds: [asset.id],
      skills: ['xss'],
      dependsOnFactIds: [],
      dependsOnStepIds: [],
      sourceOrigins: [ORIGIN],
    })
    store.updateWorker(workerOperatorCanceled.id, {
      status: 'canceled',
      stepId: stepOperatorCanceled.id,
      outcome: 'Canceled by operator.',
    })
    store.updateChainStep(stepOperatorCanceled.id, { status: 'running', assignedWorkerId: workerOperatorCanceled.id })

    const priv = exec as unknown as { tier3Approvals: RunTier3ApprovalCoordinator }
    priv.tier3Approvals.reconcileSettledApprovalWorkers(store.run(runId))

    const steps = store.listChainSteps(runId, run.goalRevision)
    const afterA = steps.find(s => s.id === stepInterrupted.id)!
    const afterB = steps.find(s => s.id === stepOperatorCanceled.id)!
    assert.equal(afterA.status, 'ready', 'interrupted worker cancellation must requeue step to ready (preserve work)')
    assert.equal(afterA.assignedWorkerId, null)
    assert.equal(afterB.status, 'canceled', 'explicit operator cancel must still cancel the step')
  })
})

// ============================================================================
// 3. Pause-Aware Resources: Warm Pool Suspends on Pause (== 0), Lab & OOB Held
// ============================================================================

describe('R3-20.3: pause-aware resources (warm pool suspends on pause; lab targets & OOB held)', () => {
  test('pausing a run evicts warm-pool containers to 0 while keeping lab target & OOB subscription held; stop disposes all', async t => {
    const dir = makeTempDir(t, 'kovo-r3-20-resources-')
    const store = new Store(dir)
    const runtime = createAppRuntime({ dataDir: dir, store, maintenance: false, autoStartMaintenance: false })
    const { backend, warmContainersByRun, evictCalls } = makeWarmPoolTrackingBackend()

    const stoppedLabRuns: string[] = []
    const mockLabRunner = {
      stopLabTarget: async (rid: string) => { stoppedLabRuns.push(rid) },
      stopAll: async () => undefined,
      recoverOnStartup: async () => [],
      ensureStartupRecovery: async () => [],
      recoverAll: async () => [],
    } as unknown as LabRunner

    const canaryBroker = new CanaryBroker({ storage: store, oobDirectory: dir })
    runtime.attachCanaryBroker(canaryBroker)
    let oobUnsubscribedCount = 0
    const origUnsub = canaryBroker.unsubscribeRun.bind(canaryBroker)
    canaryBroker.unsubscribeRun = (rid: string) => {
      oobUnsubscribedCount += 1
      return origUnsub(rid)
    }

    const exec = new Execution(store, {
      runtime,
      broker: stubBroker(),
      backend,
      labRunner: mockLabRunner,
      canaryBroker,
      deterministicSweep: false,
    })
    t.after(async () => {
      await exec.stop()
      await runtime.dispose()
    })

    const { runId } = setupApprovedRun(store, 'PauseResources')
    const priv = exec as unknown as {
      ensureRunActor: (id: string) => ReturnType<Execution['getRunActor']>
      startedLabRuns: Set<string>
      driveInvestigation: () => void
    }
    priv.driveInvestigation = () => {}

    const actor = priv.ensureRunActor(runId)!
    assert.ok(actor)
    // Simulate active warm-pool containers, running lab target, and custom pause-aware resource
    warmContainersByRun.set(runId, 2)
    priv.startedLabRuns.add(runId)
    let customSuspended = 0
    let customResumed = 0
    actor.registerResource('custom:ephemeral', {
      holdIn: ['running'],
      suspend: () => { customSuspended += 1 },
      resume: () => { customResumed += 1 },
      dispose: () => undefined,
    })

    // Pause run + wake scheduler
    store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'pause' }))
    exec.wake()
    await actor.context.whenResourcesSettled()

    assert.equal(warmContainersByRun.get(runId), 0, 'warm-pool containers for paused run MUST be 0')
    assert.ok(evictCalls.includes(runId), 'evictRunWarmPool must be invoked on pause')
    assert.equal(customSuspended, 1, 'holdIn: ["running"] resource must suspend on pause')
    assert.ok(actor.context.suspendedResourceNames.includes('warm-pool:evict'))
    assert.equal(stoppedLabRuns.length, 0, 'lab target MUST stay held on pause (preserving seeded state)')
    assert.equal(oobUnsubscribedCount, 0, 'OOB subscription MUST stay held on pause (preserving pending canaries)')

    // Resume run -> custom pause-aware resource resumes
    store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' }))
    exec.wake()
    await actor.context.whenResourcesSettled()
    assert.equal(customResumed, 1, 'suspended pause-aware resource must resume when run returns to running')
    assert.equal(actor.context.suspendedResourceNames.length, 0)

    // Terminal stop -> disposes lab target AND OOB subscription AND warm pool
    store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'stop' }))
    exec.wake()
    await exec.disposeRun(runId)

    assert.equal(warmContainersByRun.get(runId), 0)
    assert.deepEqual(stoppedLabRuns, [runId], 'lab target MUST stop on terminal run state')
    assert.ok(oobUnsubscribedCount >= 1, 'OOB subscription MUST unsubscribe on terminal run state')
  })
})

// ============================================================================
// 4. Transition Tables (Warn-Mode Telemetry + Enforce Mode) & Always-On Liveness
// ============================================================================

describe('R3-20.4: transition tables & always-on emit-only checkRunLiveness', () => {
  test('LIFECYCLE_TRANSITION_TABLES enforces terminal closure in warn and enforce modes', t => {
    // Terminal run states have zero outgoing edges
    assert.equal(LIFECYCLE_TRANSITION_TABLES.run.complete.size, 0)
    assert.equal(LIFECYCLE_TRANSITION_TABLES.run.stopped.size, 0)
    assert.equal(LIFECYCLE_TRANSITION_TABLES.run.failed.size, 0)

    // Warn mode records warning without throwing
    const warnings: Array<{ entity: string; from: string; to: string }> = []
    const warnResult = validateLifecycleTransition('run', 'stopped', 'running', {
      mode: 'warn',
      onWarning: w => warnings.push({ entity: w.entity, from: w.from, to: w.to }),
    })
    assert.equal(warnResult.allowed, false)
    assert.equal(warnings.length, 1)
    assert.deepEqual(warnings[0], { entity: 'run', from: 'stopped', to: 'running' })

    // Enforce mode throws IllegalLifecycleTransitionError
    assert.throws(
      () => validateLifecycleTransition('run', 'stopped', 'running', { mode: 'enforce' }),
      IllegalLifecycleTransitionError,
    )

    // Store emits lifecycle.transition_warning telemetry in warn mode when an illegal transition occurs
    const { store } = makeTempStore(t, 'kovo-r3-20-warn-telemetry-')
    const { runId, run, asset } = setupApprovedRun(store, 'WarnTelemetry')
    const w = store.makeWorker(run, 'investigation', asset, 'W', 'Test')
    store.updateWorker(w.id, { status: 'complete' })
    // Attempting illegal worker transition complete -> running emits warning in warn mode
    store.updateWorker(w.id, { status: 'running' })
    const warnEvents = store.client.prepare(
      "SELECT kind, detail FROM events WHERE run_id = ? AND kind = 'lifecycle.transition_warning'",
    ).all(runId) as Array<{ kind: string; detail: string }>
    assert.ok(warnEvents.length >= 1, 'warn-mode illegal transition must emit lifecycle.transition_warning event')
  })

  test('emitRunLivenessViolations is always-on, emit-only (never mutates DB), and deduplicates across ticks', t => {
    clearQaAnomalies()
    const { store } = makeTempStore(t, 'kovo-r3-20-liveness-emit-')
    const { runId, run, asset } = setupApprovedRun(store, 'LivenessEmit')
    const w = store.makeWorker(run, 'investigation', asset, 'Stranded worker', 'Test')
    const step = store.addChainStep(run, {
      title: 'Stranded step',
      hypothesis: 'Corrupted on terminal run',
      targetAssetIds: [asset.id],
      skills: ['bola'],
      dependsOnFactIds: [],
      dependsOnStepIds: [],
      sourceOrigins: [ORIGIN],
    })
    // Simulate corrupted DB state bypassing co-transitions: terminal run with active worker + running step
    store.client.prepare("UPDATE runs SET status = 'stopped' WHERE id = ?").run(runId)
    store.client.prepare("UPDATE assignments SET status = 'running' WHERE id = ?").run(w.id)
    store.client.prepare("UPDATE chain_steps SET status = 'running', assigned_worker_id = ? WHERE id = ?").run(w.id, step.id)

    const emitted = new Map<string, Set<string>>()
    const events: Array<{ kind: string; code?: unknown }> = []
    const emit = (rid: string, kind: string, msg: string, detail?: Record<string, unknown>) => {
      store.event(rid, kind, msg, detail)
      events.push({ kind, code: detail?.code })
    }

    const first = emitRunLivenessViolations(store, store.run(runId), new Set(), emitted, emit)
    assert.ok(first.length >= 2, 'must detect both terminal_run_active_assignment and terminal_run_running_step')
    assert.ok(first.some(v => v.code === 'terminal_run_active_assignment'))
    assert.ok(first.some(v => v.code === 'terminal_run_running_step'))
    assert.equal(events.filter(e => e.kind === 'run.invariant_violation').length, first.length)

    // Always-on QA anomaly recording (even when KOVO_QA_ANOMALIES is unset)
    const qaHits = listQaAnomalies({ kind: 'run_invariant_violation' })
    assert.ok(qaHits.length >= 2, 'liveness violations must record run_invariant_violation QA anomalies unconditionally')

    // Emit-only invariant: DB rows MUST NOT be auto-repaired/mutated
    assert.equal(store.worker(w.id).status, 'running', 'checkRunLiveness MUST be emit-only (never mutate assignment)')
    assert.equal(
      store.listChainSteps(runId, run.goalRevision).find(s => s.id === step.id)?.status,
      'running',
      'checkRunLiveness MUST be emit-only (never mutate chain step)',
    )

    // Deduplication: second tick emits 0 duplicate events for the same unchanged violations
    const second = emitRunLivenessViolations(store, store.run(runId), new Set(), emitted, emit)
    assert.equal(second.length, 0, 'repeated wake ticks must deduplicate identical liveness violations')
  })
})

// ============================================================================
// 5. Seeded Lifecycle Fuzz (~500 sequences, <5s, 0 invariant violations)
// ============================================================================

describe('R3-20.5: seeded lifecycle fuzz (500 sequences, 0 invariant violations)', () => {
  test('500 seeded multi-step lifecycle sequences maintain liveness and terminal closure with 0 violations', t => {
    const t0 = Date.now()
    const { store } = makeTempStore(t, 'kovo-r3-20-fuzz-')
    const { runId, run: templateRun, asset } = setupApprovedRun(store, 'Fuzz Project')
    const templateCandidatesJson = JSON.stringify(templateRun.candidates)
    const templateApprovedJson = JSON.stringify(templateRun.approved)

    const rng = createMulberry32(0x52333230) // deterministic seed ('R320')
    const SEQUENCES = 500
    let totalOps = 0
    let totalViolations = 0
    const sampleViolations: string[] = []

    const pick = <T>(arr: readonly T[]): T => arr[Math.floor(rng() * arr.length)]!

    // Reuse a single approved run cleanly reset between sequences so Store.recover() scans 1 run
    // (not 50 stale pool runs) and history tables never grow O(N^2) across 500 sequences.
    const delLeases = store.client.prepare('DELETE FROM approval_leases WHERE run_id = ?')
    const delReqs = store.client.prepare('DELETE FROM approval_requests WHERE run_id = ?')
    const delSteps = store.client.prepare('DELETE FROM chain_steps WHERE run_id = ?')
    const delAssg = store.client.prepare('DELETE FROM assignments WHERE run_id = ?')
    const delEvents = store.client.prepare('DELETE FROM events WHERE run_id = ?')
    const delMessages = store.client.prepare('DELETE FROM messages WHERE run_id = ?')
    const delReports = store.client.prepare('DELETE FROM reports WHERE run_id = ?')
    const delOperations = store.client.prepare('DELETE FROM operations')
    const resetBoard = store.client.prepare(
      "UPDATE board_members SET state = 'waiting', active_assignment_id = NULL WHERE run_id = ?",
    )
    const resetRun = store.client.prepare(
      "UPDATE runs SET phase = 'investigation', status = 'running', scope_revision = 1, budget_usd = 10, spent_usd = 0, spent_requests = 0, candidates = ?, approved = ? WHERE id = ?",
    )

    // Pre-prepared read-only snapshot statements over the exact authoritative SQLite tables
    // checked by checkRunLiveness(), avoiding per-op Drizzle query compilation and JSON parsing.
    type RunSnapRow = RunLivenessSnapshot['run'] & { budgetUsd: number; spentUsd: number }
    const readRunSnap = store.client.prepare(
      'SELECT id, status, phase, goal_revision AS goalRevision, budget_usd AS budgetUsd, spent_usd AS spentUsd FROM runs WHERE id = ?',
    )
    const readAssignmentsSnap = store.client.prepare(
      'SELECT id, phase, status, lease_expires_at AS leaseExpiresAt, approval_parked_at AS approvalParkedAt FROM assignments WHERE run_id = ?',
    )
    const readStepsSnap = store.client.prepare(
      'SELECT id, goal_revision AS goalRevision, status, assigned_worker_id AS assignedWorkerId FROM chain_steps WHERE run_id = ? AND goal_revision = ?',
    )
    const readBoardSnap = store.client.prepare(
      'SELECT id, handle, state, active_assignment_id AS activeAssignmentId FROM board_members WHERE run_id = ?',
    )
    const readApprovalsSnap = store.client.prepare(
      'SELECT id, status FROM approval_requests WHERE run_id = ?',
    )
    const readLeasesSnap = store.client.prepare(
      'SELECT id, status FROM approval_leases WHERE run_id = ?',
    )

    for (let seq = 0; seq < SEQUENCES; seq += 1) {
      // Reset run cleanly for a fresh seeded sequence
      store.transaction(() => {
        delLeases.run(runId)
        delReqs.run(runId)
        delSteps.run(runId)
        delAssg.run(runId)
        delEvents.run(runId)
        delMessages.run(runId)
        delReports.run(runId)
        delOperations.run()
        resetBoard.run(runId)
        resetRun.run(templateCandidatesJson, templateApprovedJson, runId)
      }, { behavior: 'immediate' })

      const stepsCount = 4 + Math.floor(rng() * 5) // 4..8 operations per sequence
      const liveHandles = new Set<string>()
      const createdStepIds: string[] = []
      const createdApprovalIds: string[] = []
      let currentSnap = readRunSnap.get(runId) as unknown as RunSnapRow

      for (let op = 0; op < stepsCount; op += 1) {
        totalOps += 1
        const action = pick([
          'spawn_step',
          'pause',
          'budget_pause',
          'resume',
          'raise_budget',
          'approval',
          'complete_step',
          'stop',
          'fail',
          'complete',
          'recover',
        ] as const)

        switch (action) {
          case 'spawn_step': {
            if (currentSnap.status !== 'running') break
            store.transaction(() => {
              const current = store.run(runId)
              const step = store.addChainStep(current, {
                title: `Fuzz step ${seq}-${op}`,
                hypothesis: 'Verify invariants',
                targetAssetIds: [asset.id],
                skills: ['bola'],
                dependsOnFactIds: [],
                dependsOnStepIds: [],
                sourceOrigins: [ORIGIN],
              })
              createdStepIds.push(step.id)
              const w = store.makeWorker(current, 'investigation', asset, `w-${seq}-${op}`, 'Run fuzz step', { stepId: step.id })
              store.updateWorker(w.id, { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 })
              store.updateChainStep(step.id, { status: 'running', assignedWorkerId: w.id })
              store.updateBoardMemberState(runId, 'coordinator', { state: 'working', activeAssignmentId: w.id })
              liveHandles.add(w.id)
            }, { behavior: 'immediate' })
            break
          }
          case 'pause': {
            if (currentSnap.status === 'running') {
              store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'pause' }))
              liveHandles.clear()
            }
            break
          }
          case 'budget_pause': {
            if (currentSnap.status === 'running') {
              store.recordLlmSpend(runId, { usd: currentSnap.budgetUsd + 1, tokens: 100, turns: 1 })
              store.checkBudgetExceeded(runId)
              liveHandles.clear()
            }
            break
          }
          case 'resume': {
            if (isTerminalRunStatus(currentSnap.status)) {
              assert.throws(() => store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' })))
            } else if (currentSnap.status === 'paused') {
              store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'resume' }))
            }
            break
          }
          case 'raise_budget': {
            if (currentSnap.status === 'budget_paused') {
              store.command(runCommand.parse({
                requestId: randomUUID(),
                runId,
                action: 'raise_budget',
                budgetUsd: currentSnap.spentUsd + 15,
                resume: true,
              }))
            }
            break
          }
          case 'approval': {
            if (currentSnap.status === 'running') {
              const hasRunningWorker = (readAssignmentsSnap.all(runId) as unknown as RunLivenessSnapshot['assignments'])
                .some(w => w.status === 'running')
              if (hasRunningWorker) {
                const target = store.workerList(runId).find(w => w.status === 'running')
                if (target) {
                  const req = store.createApprovalRequest(store.run(runId), target, {
                    origin: ORIGIN,
                    method: 'POST',
                    pathAndQuery: `/api/fuzz/${seq}/${op}`,
                    rationale: 'Fuzz state change',
                    requestPreview: '{}',
                    expiresInMs: 60_000,
                  })
                  createdApprovalIds.push(req.id)
                }
              }
            } else if (createdApprovalIds.length > 0 && !isTerminalRunStatus(currentSnap.status)) {
              const id = createdApprovalIds[createdApprovalIds.length - 1]!
              const req = (readApprovalsSnap.all(runId) as unknown as NonNullable<RunLivenessSnapshot['approvalRequests']>)
                .find(r => r.id === id)
              if (req && req.status === 'pending') {
                store.decideApproval(store.run(runId), id, rng() < 0.5 ? 'approved' : 'denied', 'once')
              }
            }
            break
          }
          case 'complete_step': {
            if (currentSnap.status !== 'running') break
            const runningStep = (readStepsSnap.all(runId, currentSnap.goalRevision) as unknown as RunLivenessSnapshot['chainSteps'])
              .find(s => s.status === 'running')
            if (runningStep && runningStep.assignedWorkerId) {
              store.transaction(() => {
                store.updateChainStep(runningStep.id, { status: 'complete', assignedWorkerId: runningStep.assignedWorkerId })
                store.updateWorker(runningStep.assignedWorkerId!, { status: 'complete', lease: null, leaseExpiresAt: null })
                liveHandles.delete(runningStep.assignedWorkerId!)
                const coord = (readBoardSnap.all(runId) as unknown as NonNullable<RunLivenessSnapshot['boardMembers']>)
                  .find(m => m.handle === 'coordinator')
                if (coord?.activeAssignmentId === runningStep.assignedWorkerId) {
                  store.updateBoardMemberState(runId, 'coordinator', { state: 'waiting', activeAssignmentId: null })
                }
              }, { behavior: 'immediate' })
            }
            break
          }
          case 'stop': {
            if (!isTerminalRunStatus(currentSnap.status)) {
              store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'stop' }))
              liveHandles.clear()
            }
            break
          }
          case 'fail': {
            if (!isTerminalRunStatus(currentSnap.status)) {
              store.setStatus(store.run(runId), 'failed')
              liveHandles.clear()
            }
            break
          }
          case 'complete': {
            if (!isTerminalRunStatus(currentSnap.status)) {
              const updated = store.updateRun(runId, { phase: 'complete' })
              store.setStatus(updated, 'complete')
              liveHandles.clear()
            }
            break
          }
          case 'recover': {
            store.recover()
            liveHandles.clear()
            break
          }
        }

        const after = readRunSnap.get(runId) as unknown as RunSnapRow
        currentSnap = after
        const violations = checkRunLiveness({
          run: after,
          assignments: readAssignmentsSnap.all(runId) as unknown as RunLivenessSnapshot['assignments'],
          chainSteps: readStepsSnap.all(runId, after.goalRevision) as unknown as RunLivenessSnapshot['chainSteps'],
          boardMembers: readBoardSnap.all(runId) as unknown as NonNullable<RunLivenessSnapshot['boardMembers']>,
          approvalRequests: readApprovalsSnap.all(runId) as unknown as NonNullable<RunLivenessSnapshot['approvalRequests']>,
          approvalLeases: readLeasesSnap.all(runId) as unknown as NonNullable<RunLivenessSnapshot['approvalLeases']>,
          activeAssignmentIds: liveHandles,
        })
        if (violations.length > 0) {
          totalViolations += violations.length
          if (sampleViolations.length < 10) {
            sampleViolations.push(`seq=${seq} op=${op} action=${action} status=${after.status}: ${violations.map(v => v.code).join(',')}`)
          }
        }
      }
    }

    const elapsedMs = Date.now() - t0
    assert.equal(
      totalViolations,
      0,
      `Expected 0 invariant violations across ${SEQUENCES} sequences (${totalOps} ops), got ${totalViolations}: ${sampleViolations.join('; ')}`,
    )
    assert.ok(totalOps >= SEQUENCES * 4)
    assert.ok(elapsedMs < 5_000, `Expected 500-sequence fuzz suite to finish in <5s, took ${elapsedMs}ms`)
  })
})
