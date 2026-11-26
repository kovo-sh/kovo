// @fixes R3-07
/**
 * R3-07 Assignment Claim Owner, Settlement Reporting & Phase-Agnostic Reaper Tests.
 *
 * Verifies:
 *  1. P0 hotfix (`runSourceFirstCodeAudit`): an `openSession` throw settles the assignment
 *     row as `failed` (clearing lease), emits `code_audit.failed`, removes the entry from
 *     `this.active` and `claimRegistry`, detaches the abort listener, and leaves
 *     `isRunTrackedActive(run.id) === false` so `deleteRun` succeeds cleanly.
 *  2. `settleOrReport` / `settleOrReportAsync`: emits `lifecycle.settlement_failed` on
 *     unexpected failures, suppresses classified known races (`run_not_found`, `store_closed`,
 *     `already_terminal`, `aborted`), and never cascades if the reporter throws.
 *  3. Authoritative `claimAssignment()` / `ClaimHandle` + `run-safety-budgets.ts`:
 *     budgeted lease durations per kind, clamping telemetry (`assignment.lease_clamped`),
 *     `heartbeat()`, idempotent `settle()` with paired chain-step co-transitions,
 *     `[Symbol.dispose]()` / `release()` safety net, and non-clobbering of parked/settled rows.
 *  4. Phase-agnostic orphan reaper (`reapOrphanedRunningAssignments` & `Execution.wake()`):
 *     reclaims orphaned `running` rows across `threat_model`, `investigation`, `verification`,
 *     and `retest` without a live owner handle while NEVER touching `waiting_approval` parked
 *     workers or legitimately long-running sessions holding a live `ClaimHandle`.
 *  5. `scripts/check-empty-catch.ts` AST ratchet passes below the pre-R3-07 baseline,
 *     rejects newly introduced empty catches, and verifies claim-owner discipline.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  BASELINE_EMPTY_CATCH_BY_FILE,
  PRE_R3_07_EMPTY_CATCH_TOTAL,
  runClaimDisciplineCheck,
  runEmptyCatchCheck,
} from '../scripts/check-empty-catch.ts'
import {
  AssignmentClaimRegistry,
  claimAssignment,
  purgeActiveJobsForRun,
  reapOrphanedRunningAssignments,
} from '../src/server/assignment-claim.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  classifyKnownSettlementRace,
  settleOrReport,
  settleOrReportAsync,
} from '../src/server/run-disposers.ts'
import {
  RUN_SAFETY_BUDGET_DEFAULTS,
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
  resolveAssignmentLeaseBudget,
  resolveRunSafetyBudgets,
} from '../src/server/run-safety-budgets.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const ORIGIN = 'https://claim-owner.r3-07.example.invalid'

function fakeProfile(): ResolvedModelProfile {
  return {
    id: 'profile-r3-07',
    name: 'Test Reasoning Profile',
    provider: 'openrouter',
    protocol: 'responses',
    endpoint: 'http://127.0.0.1:1/v1',
    model: 'test-model',
    apiKey: 'sk-test-dummy-key',
    enabled: true,
    role: 'reasoning',
    priority: 1,
    timeoutMs: 10_000,
    maxTokens: 1_024,
  } as unknown as ResolvedModelProfile
}

function makeStubBackend(opts: { openSessionError?: Error } = {}): WorkerBackend {
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
      if (opts.openSessionError) throw opts.openSessionError
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

describe('R3-07 Assignment Claim Owner, Settlement Reporting & Phase-Agnostic Reaper', () => {
  test('P0 hotfix: runSourceFirstCodeAudit openSession throw settles assignment, clears active/handles, and leaves isRunTrackedActive false', async t => {
    const { storage } = makeStore(t, 'kovo-r3-07-hotfix-')
    const repoDir = mkdtempSync(join(tmpdir(), 'kovo-r3-07-repo-'))
    let engine: Execution | undefined
    try {
      const { run } = await setupApprovedRun(storage, { environment: 'public', seeds: [ORIGIN], tier: 1 })
      storage.updateRun(run.id, { phase: 'threat_model', status: 'running', capabilityTier: 1 })
      mkdirSync(join(repoDir, 'app'), { recursive: true })
      writeFileSync(join(repoDir, 'app', 'index.ts'), 'export const ok = true\n', 'utf8')

      engine = new Execution(storage, {
        backend: makeStubBackend({ openSessionError: new Error('docker daemon socket unavailable') }),
      })
      const engAny = engine as unknown as {
        active: Map<string, unknown>
        claimRegistry: AssignmentClaimRegistry
        projectReposMount: (projectId: string) => { reposDir: string; mountedRepos: string[] }
        startDeterministicLane: () => boolean
      }
      engAny.projectReposMount = () => ({ reposDir: repoDir, mountedRepos: ['app'] })
      engAny.startDeterministicLane = () => false

      const parentAbort = new AbortController()
      await assert.rejects(
        () => engine!.runSourceFirstCodeAudit(storage.run(run.id), [], [fakeProfile()], parentAbort.signal),
        err => err instanceof Error && err.message.includes('docker daemon socket unavailable'),
      )

      const workers = storage.workerList(run.id).filter(w => w.title.includes('Source-First Code Audit'))
      assert.equal(workers.length, 1, 'exactly one code audit assignment should exist')
      assert.equal(workers[0]!.status, 'failed', 'assignment row must settle to failed on openSession throw')
      assert.equal(workers[0]!.lease, null, 'lease must be cleared on failure')
      assert.equal(workers[0]!.leaseExpiresAt, null, 'leaseExpiresAt must be cleared on failure')
      assert.ok((workers[0]!.outcome ?? '').includes('docker daemon socket unavailable'))

      const events = storage.eventsAfter(run.id, 0, 200)
      assert.ok(events.some(e => e.kind === 'code_audit.failed'), 'must emit code_audit.failed event')

      assert.equal(engAny.active.size, 0, 'this.active must not leak an entry after openSession throw')
      assert.equal(engAny.claimRegistry.listForRun(run.id).length, 0, 'claimRegistry must not leak a handle')
      assert.equal(engine.isRunTrackedActive(run.id), false, 'isRunTrackedActive must be false so deleteRun never hits RunDeleteBusyError')

      // Aborting parent signal after cleanup must be a clean no-op
      parentAbort.abort(new Error('late abort'))
      const del = await engine.deleteRun(run.id)
      assert.equal(del.deleted, true, 'deleteRun must succeed without RunDeleteBusyError')
    } finally {
      if (engine) await engine.stop()
      rmSync(repoDir, { recursive: true, force: true })
    }
  })

  test('settleOrReport and settleOrReportAsync report unexpected errors and suppress classified known races', async () => {
    const reported: Array<{ runId: string; kind: string; message: string; detail?: Record<string, unknown> }> = []
    const reporter = (runId: string, kind: string, message: string, detail?: Record<string, unknown>) => {
      reported.push({ runId, kind, message, detail })
    }

    assert.equal(classifyKnownSettlementRace(new Error('Run not found.')), 'run_not_found')
    assert.equal(classifyKnownSettlementRace(new Error('database connection is not open')), 'store_closed')
    assert.equal(classifyKnownSettlementRace(new Error('Assignment already terminal')), 'already_terminal')
    const abortErr = new Error('operation cancelled')
    abortErr.name = 'AbortError'
    assert.equal(classifyKnownSettlementRace(abortErr), 'aborted')
    assert.equal(classifyKnownSettlementRace(new Error('SQLITE_BUSY: database is locked')), null)

    const knownRes = settleOrReport('run-1', 'scheduler.queue_drain', () => {
      throw new Error('Run not found.')
    }, reporter)
    assert.equal(knownRes.ok, false)
    assert.equal(knownRes.race, 'run_not_found')
    assert.equal(reported.length, 0, 'known race must not emit noisy lifecycle.settlement_failed')

    const unexpectedRes = settleOrReport('run-1', 'scheduler.queue_drain', () => {
      throw new Error('SQLITE_BUSY: database is locked')
    }, reporter, { step: 'drain' })
    assert.equal(unexpectedRes.ok, false)
    assert.equal(unexpectedRes.race, undefined)
    assert.equal(reported.length, 1)
    assert.equal(reported[0]!.kind, 'lifecycle.settlement_failed')
    assert.equal(reported[0]!.detail?.settlementKind, 'scheduler.queue_drain')

    const asyncRes = await settleOrReportAsync('run-2', 'warm_pool.evict', async () => {
      throw new Error('docker rm timed out')
    }, reporter)
    assert.equal(asyncRes.ok, false)
    assert.equal(reported.length, 2)
    assert.equal(reported[1]!.detail?.settlementKind, 'warm_pool.evict')

    // Failing reporter must never cascade
    const safeRes = settleOrReport('run-3', 'test.fail', () => {
      throw new Error('unexpected write error')
    }, () => { throw new Error('sink exploded') })
    assert.equal(safeRes.ok, false)
  })

  test('claimAssignment enforces run-safety-budgets lease caps, supports heartbeat/settle/dispose, and never clobbers parked rows', async t => {
    const { storage } = makeStore(t, 'kovo-r3-07-claim-')
    const budgets = resolveRunSafetyBudgets()
    assert.equal(budgets.assignmentLeaseMs, RUN_SAFETY_BUDGET_DEFAULTS.assignmentLeaseMs)
    assert.equal(budgets.investigationLeaseMs, RUN_SAFETY_BUDGET_DEFAULTS.investigationLeaseMs)
    assert.equal(budgets.patchRetestLeaseMs, RUN_SAFETY_BUDGET_DEFAULTS.patchRetestLeaseMs)

    const clampedBudget = resolveAssignmentLeaseBudget('code_audit', {
      requestedMs: RUN_SAFETY_BUDGET_HARD_CEILINGS.assignmentLeaseMs * 5,
    })
    assert.equal(clampedBudget.clamped, true)
    assert.equal(clampedBudget.leaseMs, RUN_SAFETY_BUDGET_HARD_CEILINGS.assignmentLeaseMs)

    const { run } = await setupApprovedRun(storage, { environment: 'public', seeds: [ORIGIN], tier: 2 })
    const step = storage.addChainStep(run, {
      title: 'Test step',
      hypothesis: 'Verify claim handle co-transition',
      category: 'broken-access-control',
      priority: 80,
      targetAssetIds: [run.candidates[0]!.id],
      sourceOrigins: [ORIGIN],
      skills: [],
    })
    const worker = storage.makeWorker(run, 'investigation', run.candidates[0], 'Step worker', 'Objective', {
      stepId: step.id,
      sourceOrigins: [ORIGIN],
    })
    const registry = new AssignmentClaimRegistry()

    const claim = claimAssignment(storage, {
      runId: run.id,
      assignmentId: worker.id,
      leaseKind: 'investigation',
      leaseMs: RUN_SAFETY_BUDGET_HARD_CEILINGS.investigationLeaseMs * 3,
      registry,
      afterClaimInTx: c => {
        storage.updateChainStep(step.id, { status: 'running', assignedWorkerId: c.id })
      },
    })!
    assert.ok(claim)
    assert.equal(claim.leaseClamped, true)
    assert.equal(registry.has(worker.id), true)
    assert.ok(storage.eventsAfter(run.id, 0, 200).some(e => e.kind === 'assignment.lease_clamped'))

    const prevExpiry = claim.leaseExpiresAt
    const refreshed = claim.heartbeat(60_000)
    assert.ok(refreshed)
    assert.notEqual(refreshed!.leaseExpiresAt, prevExpiry)

    // Settle with paired chain step co-transition
    const settled = claim.settle({
      status: 'failed',
      outcome: 'injected failure',
      stepStatus: 'ready',
      clearStepWorker: true,
    })
    assert.equal(settled.settled, true)
    assert.equal(registry.has(worker.id), false)
    assert.equal(storage.worker(worker.id).status, 'failed')
    assert.equal(storage.worker(worker.id).lease, null)
    const updatedStep = storage.listChainSteps(run.id, run.goalRevision).find(s => s.id === step.id)!
    assert.equal(updatedStep.status, 'ready')
    assert.equal(updatedStep.assignedWorkerId, null)

    // Idempotent second settle
    assert.equal(claim.settle({ status: 'complete' }).settled, false)

    // Symbol.dispose settles an unsettled claim instead of leaking a running row
    const worker2 = storage.makeWorker(run, 'threat_model', run.candidates[0], 'Dispose worker', 'Objective', {
      sourceOrigins: [ORIGIN],
    })
    {
      using handle2 = claimAssignment(storage, {
        runId: run.id,
        assignmentId: worker2.id,
        leaseKind: 'code_audit',
        registry,
      })!
      assert.equal(registry.has(worker2.id), true)
      assert.equal(storage.worker(worker2.id).status, 'running')
      void handle2
    }
    assert.equal(registry.has(worker2.id), false)
    assert.equal(storage.worker(worker2.id).status, 'failed')
    assert.equal(storage.worker(worker2.id).lease, null)

    // Parked waiting_approval worker must NOT be clobbered by claim.release()
    const worker3 = storage.makeWorker(run, 'investigation', run.candidates[0], 'Parked worker', 'Objective', {
      sourceOrigins: [ORIGIN],
    })
    const claim3 = claimAssignment(storage, { runId: run.id, assignmentId: worker3.id, registry })!
    storage.parkWorkerForApproval(storage.run(run.id), worker3.id)
    claim3.release('should not overwrite parked worker')
    assert.equal(storage.worker(worker3.id).status, 'waiting_approval')

    // resumeParkedWorker goes through budgeted claimAssignment
    const resumed = storage.resumeParkedWorker(storage.run(run.id), worker3.id)
    assert.equal(resumed.status, 'running')
    assert.ok(resumed.lease && resumed.leaseExpiresAt && resumed.leaseExpiresAt > Date.now())
  })

  test('phase-agnostic orphan reaper reclaims running rows without live handles across phases while sparing parked and live-handle sessions', async t => {
    const { storage } = makeStore(t, 'kovo-r3-07-reap-')
    const { run } = await setupApprovedRun(storage, { environment: 'public', seeds: [ORIGIN], tier: 2 })
    const registry = new AssignmentClaimRegistry()

    // (a) Orphaned threat_model row (unexpired lease, no live handle)
    const orphanTm = storage.makeWorker(run, 'threat_model', run.candidates[0], 'Orphan TM', 'Obj', { sourceOrigins: [ORIGIN] })
    const tmClaim = claimAssignment(storage, { runId: run.id, assignmentId: orphanTm.id, leaseKind: 'code_audit' })!
    void tmClaim

    // (b) Orphaned investigation row linked to running step (no live handle)
    const invStep = storage.addChainStep(run, {
      title: 'Orphaned inv step',
      hypothesis: 'H',
      category: 'broken-access-control',
      priority: 70,
      targetAssetIds: [run.candidates[0]!.id],
      sourceOrigins: [ORIGIN],
      skills: [],
    })
    const orphanInv = storage.makeWorker(run, 'investigation', run.candidates[0], 'Orphan Inv', 'Obj', {
      stepId: invStep.id, sourceOrigins: [ORIGIN],
    })
    claimAssignment(storage, {
      runId: run.id, assignmentId: orphanInv.id, leaseKind: 'investigation',
      afterClaimInTx: c => { storage.updateChainStep(invStep.id, { status: 'running', assignedWorkerId: c.id }) },
    })

    // (c) Orphaned verification row (expired lease, no live handle)
    const orphanVer = storage.makeWorker(run, 'verification', run.candidates[0], 'Orphan Ver', 'Obj', { sourceOrigins: [ORIGIN] })
    storage.updateWorker(orphanVer.id, { status: 'running', lease: 'dead-ver-lease', leaseExpiresAt: Date.now() - 5_000 })

    // (d) Parked waiting_approval worker (must NEVER be reaped)
    const parked = storage.makeWorker(run, 'investigation', run.candidates[0], 'Parked Inv', 'Obj', { sourceOrigins: [ORIGIN] })
    storage.parkWorkerForApproval(storage.run(run.id), parked.id)

    // (e) Legitimately long-running worker holding a live ClaimHandle even past leaseExpiresAt (must NEVER be reaped)
    const liveLong = storage.makeWorker(run, 'investigation', run.candidates[0], 'Live Long Inv', 'Obj', { sourceOrigins: [ORIGIN] })
    claimAssignment(storage, { runId: run.id, assignmentId: liveLong.id, leaseKind: 'investigation', registry })
    storage.updateWorker(liveLong.id, { leaseExpiresAt: Date.now() - 60_000 })

    const verCallbackIds: string[] = []
    const result = reapOrphanedRunningAssignments(storage, run, {
      activeAssignmentIds: new Set(),
      activeLeases: registry.activeLeases(),
      claimRegistry: registry,
      onVerificationOrRetestExpired: w => {
        verCallbackIds.push(w.id)
        storage.updateWorker(w.id, { status: 'failed', lease: null, leaseExpiresAt: null, outcome: 'reaped ver' })
      },
    })

    assert.deepEqual(new Set(result.reapedIds), new Set([orphanTm.id, orphanInv.id, orphanVer.id]))
    assert.equal(result.skippedLiveHandle, 1, 'live long-running handle must be spared')
    assert.ok(result.skippedParkedOrNonRunning >= 1, 'parked waiting_approval and completed workers must be spared')

    assert.equal(storage.worker(orphanTm.id).status, 'failed')
    assert.equal(storage.worker(orphanInv.id).status, 'failed')
    const recoveredStep = storage.listChainSteps(run.id, run.goalRevision).find(s => s.id === invStep.id)!
    assert.equal(recoveredStep.status, 'ready', 'orphaned investigation step must co-transition back to ready')
    assert.equal(recoveredStep.assignedWorkerId, null)
    assert.deepEqual(verCallbackIds, [orphanVer.id])

    assert.equal(storage.worker(parked.id).status, 'waiting_approval', 'parked worker must remain untouched')
    assert.equal(storage.worker(liveLong.id).status, 'running', 'live-handle worker must remain untouched')
    assert.ok(storage.eventsAfter(run.id, 0, 200).some(e => e.kind === 'assignment.reaped'))

    // purgeActiveJobsForRun clears both active map and claimRegistry for the run
    const activeMap = new Map([[liveLong.id, { assignment: { runId: run.id }, controller: new AbortController() }]])
    assert.equal(purgeActiveJobsForRun(activeMap, run.id, registry), 1)
    assert.equal(activeMap.size, 0)
    assert.equal(registry.listForRun(run.id).length, 0)
  })

  test('check-empty-catch AST ratchet passes strictly below pre-R3-07 baseline and rejects any new empty catch', () => {
    const live = runEmptyCatchCheck({ rootDir: REPO_ROOT })
    assert.equal(live.ok, true, `expected check-empty-catch PASS, got regressions: ${live.regressions.join('; ')}`)
    assert.ok(
      live.totalEmptyCatches < PRE_R3_07_EMPTY_CATCH_TOTAL,
      `expected live empty catches (${live.totalEmptyCatches}) < pre-R3-07 baseline (${PRE_R3_07_EMPTY_CATCH_TOTAL})`,
    )
    assert.equal(live.countsByFile['src/server/assignment-claim.ts'], 0)
    assert.equal(live.countsByFile['src/server/run-disposers.ts'], 0)

    const tmpRoot = mkdtempSync(join(tmpdir(), 'kovo-empty-catch-'))
    try {
      mkdirSync(join(tmpRoot, 'src', 'server'), { recursive: true })
      writeFileSync(
        join(tmpRoot, 'src', 'server', 'assignment-claim.ts'),
        'export function bad() { try { return 1 } catch { /* silent */ } return 0 }\n',
        'utf8',
      )
      const failed = runEmptyCatchCheck({ rootDir: tmpRoot, baselineByFile: BASELINE_EMPTY_CATCH_BY_FILE })
      assert.equal(failed.ok, false, 'new empty catch in assignment-claim.ts must fail the ratchet')
      assert.equal(failed.regressions.length, 1)
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true })
    }
  })

  test('AST claim-owner discipline guard: 0 raw status:running writes or hard-coded 10/15m lease literals in execution.ts and store-runs.ts', () => {
    const res = runClaimDisciplineCheck(REPO_ROOT)
    assert.equal(res.ok, true, `unexpected claim discipline violations: ${JSON.stringify(res.violations)}`)
    assert.equal(res.filesScanned, 2)
  })
})
