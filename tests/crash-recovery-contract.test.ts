// @fixes R3-20
/**
 * R3-20 Startup Crash-Recovery Contract Matrix (`tests/crash-recovery-contract.test.ts`).
 *
 * Verifies:
 *  1. Exhaustive seeded crash-DB matrix across ALL 7 canonical `RunStatus` values
 *     (`waiting`, `running`, `paused`, `budget_paused`, `stopped`, `failed`, `complete`):
 *       - `AppRuntime.startupRecover()` reconciles persisted SQLite state without prematurely
 *         wiping `lab_containers` in the `Store` constructor,
 *       - hands EVERY reclaimed `lab_containers` row (across ALL 7 statuses!) to
 *         `labRunner.ensureStartupRecovery(store, { persistedContainers })`,
 *       - preserves parked `waiting_approval` assignments on non-terminal runs and permanently
 *         `failed` assignments across all runs,
 *       - requeues non-parked `running` chain steps on non-terminal runs to `ready` and closes
 *         stranded rows on terminal runs (`stopped`, `failed`, `complete`),
 *       - leaves 0 `checkRunLiveness` violations on every recovered run, and is idempotent.
 *  2. Standalone `new Store(dir)` handoff: containers reclaimed during standalone Store construction
 *     are stashed and STILL delivered to `labRunner.ensureStartupRecovery` when `AppRuntime.startupRecover()` runs.
 *  3. `Execution.start()` triggers `AppRuntime.startupRecover({ labRunner })` so web/server boot
 *     reaps crashed lab containers automatically.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import { newProject, newRun, runCommand, type RunStatus } from '../src/domain.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import type { RequestBroker } from '../src/server/broker.ts'
import type { LabRecoveryResult, PersistedLabContainerRef } from '../src/server/container-supervisor.ts'
import { Execution } from '../src/server/execution.ts'
import type { LabRunner } from '../src/server/lab-runner.ts'
import { checkRunLiveness } from '../src/server/lifecycle.ts'
import { isTerminalRunStatus, RUN_STATUSES } from '../src/server/run-status.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'

const ORIGIN = 'https://crash-recovery.example.test'

function makeTempDir(t: test.TestContext, prefix = 'kovo-crash-matrix-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeMockLabRunner() {
  const calls: Array<{
    persistedContainers: PersistedLabContainerRef[]
    includeLiveOwners?: boolean
  }> = []
  const ensureStartupRecovery = async (
    _storage: unknown,
    options: { includeLiveOwners?: boolean; persistedContainers?: ReadonlyArray<PersistedLabContainerRef> } = {},
  ): Promise<LabRecoveryResult[]> => {
    const list = [...(options.persistedContainers ?? [])]
    calls.push({ persistedContainers: list, includeLiveOwners: options.includeLiveOwners })
    return list.map(ref => ({
      runId: ref.runId,
      containersRemoved: 1,
      networksRemoved: 1,
      volumesRemoved: 0,
      tempDirsRemoved: 0,
      recoveredFromRecord: true,
    }))
  }
  const labRunner = {
    recoverOnStartup: ensureStartupRecovery,
    ensureStartupRecovery,
    async recoverAll(): Promise<LabRecoveryResult[]> {
      return []
    },
    async stopLabTarget(): Promise<void> {
      return undefined
    },
    async stopAll(): Promise<void> {
      return undefined
    },
  } as unknown as LabRunner
  return { labRunner, calls }
}

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

function stubBroker(): RequestBroker {
  return {
    send: async () => { throw new Error('stub broker') },
    disposeRun: () => undefined,
    isCircuitOpen: () => false,
    close: () => undefined,
  } as unknown as RequestBroker
}

interface SeededCrashRun {
  status: RunStatus
  runId: string
  runningWorkerId: string
  failedWorkerId: string
  parkedWorkerId: string
  unparkedWaitWorkerId: string
  retestWorkerId?: string
  runningStepId: string
  parkedStepId: string
  expiredApprovalId: string
  liveApprovalId: string
  expiredLeaseId: string
  liveLeaseId: string
  runningContainerName: string
  orphanedContainerName: string
}

describe('R3-20: Crash-Recovery Contract Matrix (all 7 RunStatus values)', () => {
  test('AppRuntime.startupRecover() reconciles every RunStatus and hands all reclaimed lab_containers to labRunner.ensureStartupRecovery', async t => {
    const dir = makeTempDir(t)
    const now = Date.now()
    const seeded = new Map<RunStatus, SeededCrashRun>()

    // 1. Seed crashed DB state across ALL 7 canonical RunStatus values, then close Store cleanly (simulating SIGKILL).
    {
      const seedStore = new Store(dir, { autoRecover: false })
      try {
        const project = seedStore.createProject(newProject.parse({
          requestId: randomUUID(),
          name: 'Crash Matrix Project',
          environment: 'local-lab',
          seeds: [ORIGIN],
        }))

        for (const status of RUN_STATUSES) {
          const { id: runId } = seedStore.createRun(newRun.parse({
            requestId: randomUUID(),
            projectId: project.id,
            goal: `Crash recovery matrix for ${status}`,
            sourceMode: 'public',
            capabilityTier: 2,
            budgetUsd: 20,
            budgetRequests: 500,
          }))
          seedStore.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
          const disc = seedStore.run(runId)
          seedStore.command(runCommand.parse({
            requestId: randomUUID(),
            runId,
            action: 'scope',
            assetIds: disc.candidates.map(c => c.id),
            expectedScopeRevision: disc.scopeRevision,
            consent: true,
            saveProject: false,
            capabilityTier: 2,
          }))
          seedStore.updateRun(runId, { phase: status === 'complete' ? 'complete' : 'investigation' })
          const run = seedStore.run(runId)
          const asset = run.candidates[0]!

          const runningWorker = seedStore.makeWorker(run, 'investigation', asset, `run-${status}`, 'Active worker')
          const failedWorker = seedStore.makeWorker(run, 'investigation', asset, `fail-${status}`, 'Failed worker')
          const parkedWorker = seedStore.makeWorker(run, 'investigation', asset, `park-${status}`, 'Parked approval worker')
          const unparkedWaitWorker = seedStore.makeWorker(run, 'verification', asset, `wait-${status}`, 'Unparked approval worker')

          const runningStep = seedStore.addChainStep(run, {
            title: `Running step ${status}`,
            hypothesis: 'Must requeue or close on recovery',
            targetAssetIds: [asset.id],
            skills: ['bola'],
            dependsOnFactIds: [],
            dependsOnStepIds: [],
            sourceOrigins: [ORIGIN],
          })
          const parkedStep = seedStore.addChainStep(run, {
            title: `Parked step ${status}`,
            hypothesis: 'Attached to parked approval worker',
            targetAssetIds: [asset.id],
            skills: ['sqli'],
            dependsOnFactIds: [],
            dependsOnStepIds: [],
            sourceOrigins: [ORIGIN],
          })

          let retestWorkerId: string | undefined
          if (status === 'complete') {
            const retestWorker = seedStore.makeWorker(run, 'retest', asset, 'Queued retest', 'Verify fix')
            retestWorkerId = retestWorker.id
          }

          const expiredApproval = seedStore.createApprovalRequest(run, unparkedWaitWorker, {
            origin: ORIGIN,
            method: 'POST',
            pathAndQuery: `/api/${status}/expired`,
            rationale: 'Expired before crash',
            requestPreview: '{}',
            expiresInMs: -5_000,
          })
          const liveApproval = seedStore.createApprovalRequest(run, parkedWorker, {
            origin: ORIGIN,
            method: 'POST',
            pathAndQuery: `/api/${status}/live`,
            rationale: 'Unexpired approval at crash',
            requestPreview: '{}',
            expiresInMs: 120_000,
          })

          // Seed one expired active lease and one unexpired active lease
          const expiredLeaseId = randomUUID()
          const liveLeaseId = randomUUID()
          seedStore.client.prepare(
            `INSERT INTO approval_leases (id, run_id, origin, method, route_pattern, scope_revision, lease_scope, status, max_uses, uses, cross_persona, expires_at, created_by, created_at, updated_at)
             VALUES (?, ?, ?, 'POST', '/api/exp', ?, 'route', 'active', 3, 0, 0, ?, 'operator', ?, ?)`,
          ).run(expiredLeaseId, runId, ORIGIN, run.scopeRevision, now - 5_000, now - 10_000, now - 10_000)
          seedStore.client.prepare(
            `INSERT INTO approval_leases (id, run_id, origin, method, route_pattern, scope_revision, lease_scope, status, max_uses, uses, cross_persona, expires_at, created_by, created_at, updated_at)
             VALUES (?, ?, ?, 'POST', '/api/live', ?, 'route', 'active', 3, 0, 0, ?, 'operator', ?, ?)`,
          ).run(liveLeaseId, runId, ORIGIN, run.scopeRevision, now + 120_000, now - 1_000, now - 1_000)

          const runningContainerName = `kovo-lab-run-${status}`
          const orphanedContainerName = `kovo-lab-orphan-${status}`
          seedStore.recordLabContainer({ runId, assignmentId: runningWorker.id, containerName: runningContainerName, imageName: 'lab:1', status: 'running' })
          seedStore.recordLabContainer({ runId, containerName: orphanedContainerName, imageName: 'lab:1', status: 'orphaned' })

          // Force raw crashed statuses directly in SQLite (simulating mid-flight process death)
          seedStore.client.prepare("UPDATE assignments SET status = 'running', step_id = ?, lease = ?, lease_expires_at = ? WHERE id = ?")
            .run(runningStep.id, randomUUID(), now + 30_000, runningWorker.id)
          seedStore.client.prepare("UPDATE assignments SET status = 'failed', outcome = 'exhausted retries' WHERE id = ?")
            .run(failedWorker.id)
          seedStore.client.prepare("UPDATE assignments SET status = 'waiting_approval', approval_parked_at = ?, step_id = ? WHERE id = ?")
            .run(now - 2_000, parkedStep.id, parkedWorker.id)
          seedStore.client.prepare("UPDATE assignments SET status = 'waiting_approval', approval_parked_at = NULL WHERE id = ?")
            .run(unparkedWaitWorker.id)
          seedStore.client.prepare("UPDATE chain_steps SET status = 'running', assigned_worker_id = ? WHERE id = ?")
            .run(runningWorker.id, runningStep.id)
          seedStore.client.prepare("UPDATE chain_steps SET status = 'running', assigned_worker_id = ? WHERE id = ?")
            .run(parkedWorker.id, parkedStep.id)
          seedStore.client.prepare("UPDATE board_members SET state = 'working', active_assignment_id = ? WHERE run_id = ? AND handle = 'coordinator'")
            .run(runningWorker.id, runId)
          seedStore.client.prepare('UPDATE runs SET status = ? WHERE id = ?').run(status, runId)

          seeded.set(status, {
            status,
            runId,
            runningWorkerId: runningWorker.id,
            failedWorkerId: failedWorker.id,
            parkedWorkerId: parkedWorker.id,
            unparkedWaitWorkerId: unparkedWaitWorker.id,
            retestWorkerId,
            runningStepId: runningStep.id,
            parkedStepId: parkedStep.id,
            expiredApprovalId: expiredApproval.id,
            liveApprovalId: liveApproval.id,
            expiredLeaseId,
            liveLeaseId,
            runningContainerName,
            orphanedContainerName,
          })
        }
      } finally {
        seedStore.close()
      }
    }

    // 2. Reopen via AppRuntime with autoRecoverStore: false (Store constructor MUST NOT delete lab_containers before startupRecover!)
    const runtime = createAppRuntime({ dataDir: dir, autoRecoverStore: false, maintenance: false, autoStartMaintenance: false })
    t.after(async () => {
      if (!runtime.isDisposed) await runtime.dispose()
    })

    const storeBeforeRecover = runtime.store
    const preRows = storeBeforeRecover.client.prepare('SELECT count(*) AS c FROM lab_containers').get() as { c: number }
    assert.equal(
      Number(preRows.c),
      RUN_STATUSES.length * 2,
      'AppRuntime.store lazy init must NOT prematurely wipe lab_containers before startupRecover() runs',
    )

    // 3. Execute AppRuntime.startupRecover() with mock LabRunner
    const { labRunner, calls } = makeMockLabRunner()
    const recovery = await runtime.startupRecover({ labRunner, now })

    assert.equal(recovery.alreadyRecovered, false)
    assert.equal(recovery.storeReport.pausedRuns, 1, 'only the running run transitions to paused')
    assert.equal(recovery.reclaimedContainers.length, RUN_STATUSES.length * 2, 'ALL lab_containers across ALL 7 RunStatus values must be reclaimed')
    assert.equal(calls.length, 1, 'labRunner.ensureStartupRecovery must be invoked once')
    assert.equal(calls[0]!.persistedContainers.length, RUN_STATUSES.length * 2, 'all reclaimed containers must be handed to labRunner.ensureStartupRecovery')

    const handedNames = new Set(calls[0]!.persistedContainers.map(c => c.containerName))
    for (const status of RUN_STATUSES) {
      const fx = seeded.get(status)!
      assert.ok(handedNames.has(fx.runningContainerName), `running container for status="${status}" must be handed to LabRunner`)
      assert.ok(handedNames.has(fx.orphanedContainerName), `orphaned container for status="${status}" must be handed to LabRunner`)
      assert.equal(storeBeforeRecover.listLabContainers(fx.runId).length, 0, `lab_containers rows cleared for status="${status}"`)

      const runAfter = storeBeforeRecover.run(fx.runId)
      const expectedStatus: RunStatus = status === 'running' ? 'paused' : status
      assert.equal(runAfter.status, expectedStatus, `post-recovery run status for "${status}"`)

      // Permanently failed assignment is NEVER re-queued
      assert.equal(storeBeforeRecover.worker(fx.failedWorkerId).status, 'failed')

      // Expired approval is always expired (or canceled if terminal closure ran first)
      const expApp = storeBeforeRecover.getApprovalRequest(fx.runId, fx.expiredApprovalId)
      const liveApp = storeBeforeRecover.getApprovalRequest(fx.runId, fx.liveApprovalId)
      const expLease = storeBeforeRecover.listApprovalLeases(fx.runId).find(l => l.id === fx.expiredLeaseId)!
      const liveLease = storeBeforeRecover.listApprovalLeases(fx.runId).find(l => l.id === fx.liveLeaseId)!

      const steps = storeBeforeRecover.listChainSteps(fx.runId, runAfter.goalRevision)
      const runStepAfter = steps.find(s => s.id === fx.runningStepId)!
      const parkStepAfter = steps.find(s => s.id === fx.parkedStepId)!
      const coord = storeBeforeRecover.boardMember(fx.runId, 'coordinator')!

      if (isTerminalRunStatus(status)) {
        assert.equal(storeBeforeRecover.worker(fx.runningWorkerId).status, 'canceled', `terminal "${status}" closes running assignment`)
        assert.equal(storeBeforeRecover.worker(fx.parkedWorkerId).status, 'canceled', `terminal "${status}" closes parked assignment`)
        assert.equal(storeBeforeRecover.worker(fx.unparkedWaitWorkerId).status, 'canceled', `terminal "${status}" closes unparked approval assignment`)
        if (fx.retestWorkerId) {
          assert.equal(storeBeforeRecover.worker(fx.retestWorkerId).status, 'queued', 'complete run preserves queued retest worker')
        }
        assert.equal(runStepAfter.status, 'canceled', `terminal "${status}" closes running chain step`)
        assert.equal(parkStepAfter.status, 'canceled', `terminal "${status}" closes parked chain step`)
        assert.equal(coord.state, 'retired', `terminal "${status}" retires working board member`)
        assert.equal(expApp.status, 'canceled')
        assert.equal(liveApp.status, 'canceled')
        assert.equal(expLease.status, 'revoked')
        assert.equal(liveLease.status, 'revoked')
      } else {
        assert.equal(storeBeforeRecover.worker(fx.runningWorkerId).status, 'queued', `non-terminal "${status}" requeues running assignment`)
        assert.equal(runStepAfter.status, 'ready', `non-terminal "${status}" requeues running step to ready`)
        assert.equal(runStepAfter.assignedWorkerId, null)
        assert.equal(coord.state, 'waiting', `non-terminal "${status}" resets working board member to waiting`)
        assert.equal(coord.activeAssignmentId, null)
        assert.equal(expApp.status, 'expired')
        assert.equal(liveApp.status, 'pending')
        assert.equal(expLease.status, 'expired')
        assert.equal(liveLease.status, 'active')
        if (status === 'running' || status === 'paused' || status === 'budget_paused') {
          assert.equal(storeBeforeRecover.worker(fx.parkedWorkerId).status, 'waiting_approval', `non-terminal "${status}" preserves parked approval worker`)
          assert.equal(storeBeforeRecover.worker(fx.unparkedWaitWorkerId).status, 'queued', `non-terminal "${status}" requeues unparked approval worker`)
          assert.equal(parkStepAfter.status, 'running', `non-terminal "${status}" keeps parked approval step attached`)
        }
      }

      // Every recovered run across ALL 7 statuses MUST have 0 liveness invariant violations
      const violations = checkRunLiveness({
        run: runAfter,
        assignments: storeBeforeRecover.workerList(fx.runId),
        chainSteps: steps,
        boardMembers: storeBeforeRecover.listBoardMembers(fx.runId),
        approvalRequests: storeBeforeRecover.listApprovalRequests(fx.runId),
        approvalLeases: storeBeforeRecover.listApprovalLeases(fx.runId),
      })
      assert.deepEqual(violations, [], `recovered "${status}" run must have 0 liveness violations`)
    }

    // 4. Idempotence: repeated startupRecover({ force: true }) makes 0 mutations
    const second = await runtime.startupRecover({ labRunner, now, force: true })
    assert.equal(second.storeReport.changed, false)
    assert.equal(second.reclaimedContainers.length, 0)
  })

  test('standalone Store(dir) stashes reclaimed lab_containers so AppRuntime.startupRecover() still hands them to LabRunner', async t => {
    const dir = makeTempDir(t, 'kovo-crash-standalone-')
    let runId: string
    {
      const seed = new Store(dir, { autoRecover: false })
      const project = seed.createProject(newProject.parse({
        requestId: randomUUID(), name: 'Standalone', environment: 'local-lab', seeds: [ORIGIN],
      }))
      runId = seed.createRun(newRun.parse({
        requestId: randomUUID(), projectId: project.id, goal: 'Test handoff',
        sourceMode: 'public', capabilityTier: 1, budgetUsd: 5, budgetRequests: 100,
      })).id
      seed.recordLabContainer({ runId, containerName: 'kovo-lab-stashed-1', status: 'running' })
      seed.close()
    }

    // Open standalone Store (auto-recovers by default) and attach to AppRuntime
    const standaloneStore = new Store(dir)
    const runtime = createAppRuntime({ dataDir: dir, store: standaloneStore, maintenance: false, autoStartMaintenance: false })
    t.after(async () => {
      if (!runtime.isDisposed) await runtime.dispose()
    })

    const { labRunner, calls } = makeMockLabRunner()
    const report = await runtime.startupRecover({ labRunner })
    assert.equal(calls.length, 1)
    assert.deepEqual(
      report.reclaimedContainers,
      [{ runId, containerName: 'kovo-lab-stashed-1' }],
      'stashed containers from standalone Store constructor must still reach LabRunner.ensureStartupRecovery',
    )
    assert.deepEqual(calls[0]!.persistedContainers, [{ runId, containerName: 'kovo-lab-stashed-1' }])
  })

  test('Execution.start() hands stashed startup lab containers to LabRunner without re-pausing newly created live runs', async t => {
    const dir = makeTempDir(t, 'kovo-crash-exec-start-')
    let crashedRunId: string
    {
      const seed = new Store(dir, { autoRecover: false })
      const project = seed.createProject(newProject.parse({
        requestId: randomUUID(), name: 'ExecStart', environment: 'local-lab', seeds: [ORIGIN],
      }))
      crashedRunId = seed.createRun(newRun.parse({
        requestId: randomUUID(), projectId: project.id, goal: 'Web startup recovery',
        sourceMode: 'public', capabilityTier: 1, budgetUsd: 5, budgetRequests: 100,
      })).id
      seed.client.prepare("UPDATE runs SET status = 'running' WHERE id = ?").run(crashedRunId)
      seed.recordLabContainer({ runId: crashedRunId, containerName: 'kovo-lab-web-orphan', status: 'running' })
      seed.close()
    }

    const runtime = createAppRuntime({ dataDir: dir, maintenance: false, autoStartMaintenance: false })
    // Store open recovers pre-crash run and stashes kovo-lab-web-orphan; now seed a brand new live run!
    const liveProject = runtime.store.createProject(newProject.parse({
      requestId: randomUUID(), name: 'LiveAfterBoot', environment: 'public', seeds: [ORIGIN],
    }))
    const liveRunId = runtime.store.createRun(newRun.parse({
      requestId: randomUUID(), projectId: liveProject.id, goal: 'Fresh live run',
      sourceMode: 'public', capabilityTier: 1, budgetUsd: 5, budgetRequests: 100,
    })).id
    runtime.store.updateRun(liveRunId, { status: 'running', phase: 'investigation' })

    const { labRunner, calls } = makeMockLabRunner()
    const exec = new Execution(runtime.store, {
      runtime,
      broker: stubBroker(),
      backend: stubBackend(),
      labRunner,
      deterministicSweep: false,
    })
    t.after(async () => {
      await exec.stop()
      await runtime.dispose()
    })

    exec.start()
    const deadline = Date.now() + 2_000
    while (calls.length === 0 && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 15))
    }

    assert.ok(calls.length >= 1, 'Execution.start() must hand stashed lab containers to labRunner')
    assert.ok(
      calls.some(c => c.persistedContainers.some(p => p.containerName === 'kovo-lab-web-orphan')),
      'crashed lab container must be delivered to labRunner.ensureStartupRecovery on Execution.start()',
    )
    assert.equal(runtime.store.run(crashedRunId).status, 'paused', 'pre-crash run stays paused')
    assert.equal(runtime.store.run(liveRunId).status, 'running', 'freshly seeded live run MUST NOT be paused by Execution.start()')
  })
})
