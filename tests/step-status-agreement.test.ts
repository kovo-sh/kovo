/**
 * R2-07: Exhaustive `STEP_STATUS` single-source-of-truth & cross-consumer agreement suite.
 *
 * Verifies:
 * 1. `src/step-status.ts` is pure & browser-safe and covers every `ChainStepStatus` exhaustively.
 * 2. Exhaustive `(parentStatus, childStatus)` property test (all 12 x 12 = 144 pairs):
 *    `store-runs.refreshReadyChainSteps` and `exec-dispatch.permanentlyBlockedStepIds` /
 *    `dispatchableReadySteps` agree 100%, with zero `pending` steps stranded on terminal
 *    non-satisfying dependencies.
 * 3. Transitive multi-hop propagation agreement (`A -> B -> C`) for every blocking status.
 * 4. Retry creation (`maybeRequeueRetryableStep`) re-points pending dependents to the retry step
 *    inside the 1-retry cap & `RunSafetyBudgets`, promotes them on retry completion, and blocks
 *    them cleanly once retry is exhausted.
 * 5. O3 planner deferral gate (`shouldInvokeLlmPlanner` + `dispatchableReadySteps`) never counts
 *    stranded pending steps with terminal non-satisfying parents as dispatchable.
 * 6. `RunActor` reconciler (`reconcileSettledApprovalWorkers`) and `run-snapshot.ts`
 *    (`countDrySteps`) derive typed terminal outcomes from `STEP_STATUS`.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import {
  STEP_STATUS,
  chainStepActiveStatuses,
  chainStepContinuableStatuses,
  chainStepLostWorkStatuses,
  chainStepRetryableStatuses,
  chainStepStatuses,
  chainStepTerminalStatuses,
  getStepStatusMeta,
  isContinuableStepStatus,
  isLostWorkStepStatus,
  isRetryableStepStatus,
  isTerminalStepStatus,
  stepBlocksDependent,
  stepKillsDependents,
  stepSatisfiesDependency,
  type ChainStepStatus,
} from '../src/step-status.ts'
import {
  RETRYABLE_CHAIN_STEP_STATUSES,
  TERMINAL_CHAIN_STEP_STATUSES,
  dispatchableReadySteps,
  isRetryableChainStepStatus,
  isTerminalChainStepStatus,
  permanentlyBlockedStepIds,
  shouldInvokeLlmPlanner,
} from '../src/server/exec-dispatch.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import { captureRunSnapshot } from '../src/server/run-snapshot.ts'
import * as schema from '../src/server/schema.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://r2-07-step-status.example.invalid'

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
    tier3Approvals: {
      reconcileSettledApprovalWorkers: (run: ReturnType<Execution['storage']['run']>) => void
    }
  }
}

// ============================================================================
// 1. Exhaustive STEP_STATUS table invariants & browser-safety
// ============================================================================

test('R2-07.1: STEP_STATUS is browser-safe, exhaustive, and matches schema/exec-dispatch re-exports', () => {
  const source = readFileSync(resolve('src/step-status.ts'), 'utf8')
  assert.doesNotMatch(source, /from ['"]node:/, 'src/step-status.ts must remain pure browser-safe (no node:* imports)')
  assert.doesNotMatch(source, /from ['"]\.\/server\//, 'src/step-status.ts must not import server modules')

  const allStatuses = Object.keys(STEP_STATUS) as ChainStepStatus[]
  assert.equal(allStatuses.length, 12, 'expected all 12 ChainStepStatus values in STEP_STATUS')
  assert.deepEqual([...chainStepStatuses], allStatuses)

  // Active and terminal partition the entire status domain.
  const union = new Set([...chainStepActiveStatuses, ...chainStepTerminalStatuses])
  assert.equal(union.size, allStatuses.length)
  for (const s of chainStepActiveStatuses) {
    assert.equal(chainStepTerminalStatuses.includes(s as never), false)
  }

  // Exact per-class semantic invariants.
  assert.deepEqual(STEP_STATUS.complete, {
    terminal: true,
    retryable: false,
    continuable: true,
    satisfiesDependency: true,
    killsDependents: false,
    lostWork: false,
    glyph: 'complete',
  })

  for (const partial of ['turn_capped', 'nudged_out', 'rotated_partial'] as const) {
    const meta = STEP_STATUS[partial]
    assert.equal(meta.terminal, true, `${partial} must be terminal`)
    assert.equal(meta.continuable, true, `${partial} must be continuable`)
    assert.equal(meta.satisfiesDependency, false, `${partial} must NOT satisfy downstream dependencies`)
    assert.equal(meta.killsDependents, false, `${partial} must keep killsDependents=false so retries can re-point`)
    assert.equal(meta.lostWork, true, `${partial} must count as lostWork`)
    assert.equal(stepBlocksDependent(partial), true, `${partial} must block un-repointed pending dependents`)
  }
  assert.deepEqual([...chainStepRetryableStatuses].sort(), ['nudged_out', 'turn_capped'])
  assert.equal(STEP_STATUS.rotated_partial.retryable, false)

  for (const hardKill of ['blocked', 'tainted', 'canceled', 'model_failure', 'infra_failed'] as const) {
    const meta = STEP_STATUS[hardKill]
    assert.equal(meta.terminal, true, `${hardKill} must be terminal`)
    assert.equal(meta.retryable, false, `${hardKill} must not be retryable`)
    assert.equal(meta.continuable, false, `${hardKill} must not be continuable`)
    assert.equal(meta.satisfiesDependency, false, `${hardKill} must not satisfy dependencies`)
    assert.equal(meta.killsDependents, true, `${hardKill} must kill dependents`)
    assert.equal(meta.lostWork, true, `${hardKill} must count as lostWork`)
    assert.equal(stepBlocksDependent(hardKill), true, `${hardKill} must block pending dependents`)
  }

  for (const active of ['pending', 'ready', 'running'] as const) {
    const meta = STEP_STATUS[active]
    assert.equal(meta.terminal, false)
    assert.equal(meta.retryable, false)
    assert.equal(meta.continuable, false)
    assert.equal(meta.satisfiesDependency, false)
    assert.equal(meta.killsDependents, false)
    assert.equal(meta.lostWork, false)
    assert.equal(stepBlocksDependent(active), false)
  }

  for (const s of allStatuses) {
    const meta = getStepStatusMeta(s)
    assert.ok(meta, `missing metadata for ${s}`)
    assert.ok(meta.glyph.length > 0, `empty glyph for ${s}`)
    assert.equal(isTerminalStepStatus(s), meta.terminal)
    assert.equal(isRetryableStepStatus(s), meta.retryable)
    assert.equal(isContinuableStepStatus(s), meta.continuable)
    assert.equal(stepSatisfiesDependency(s), meta.satisfiesDependency)
    assert.equal(stepKillsDependents(s), meta.killsDependents)
    assert.equal(isLostWorkStepStatus(s), meta.lostWork)
    assert.equal(isTerminalChainStepStatus(s), meta.terminal)
    assert.equal(isRetryableChainStepStatus(s), meta.retryable)
    assert.equal(TERMINAL_CHAIN_STEP_STATUSES.has(s), meta.terminal)
    assert.equal(RETRYABLE_CHAIN_STEP_STATUSES.has(s), meta.retryable)
    assert.equal(chainStepContinuableStatuses.includes(s as never), meta.continuable)
  }

  // Unknown statuses fail closed.
  assert.equal(getStepStatusMeta('unknown_status'), undefined)
  assert.equal(isTerminalStepStatus('unknown_status'), false)
  assert.equal(stepSatisfiesDependency('unknown_status'), false)
  assert.equal(stepBlocksDependent('unknown_status'), false)

  // schema.ts re-exports the exact table and derived lists.
  assert.equal(schema.STEP_STATUS, STEP_STATUS)
  assert.deepEqual([...schema.chainStepStatuses], [...chainStepStatuses])
  assert.deepEqual([...schema.chainStepTerminalStatuses], [...chainStepTerminalStatuses])
  assert.deepEqual([...schema.chainStepRetryableStatuses], [...chainStepRetryableStatuses])
  assert.deepEqual([...schema.chainStepContinuableStatuses], [...chainStepContinuableStatuses])
  assert.deepEqual([...schema.chainStepLostWorkStatuses], [...chainStepLostWorkStatuses])
})

// ============================================================================
// 2. Exhaustive (parentStatus, childStatus) property test (all 144 pairs)
// ============================================================================

test('R2-07.2: store refreshReadyChainSteps and exec-dispatch permanentlyBlockedStepIds agree across ALL (parentStatus, childStatus) pairs', async t => {
  const { storage } = makeStore(t, 'kovo-r2-07-pairs-')
  let pairsChecked = 0

  for (const parentStatus of chainStepStatuses) {
    for (const childStatus of chainStepStatuses) {
      pairsChecked += 1
      const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
      const asset = run.candidates.find(c => run.approved.includes(c.id))!

      const parent = storage.addChainStep(run, {
        title: `Parent (${parentStatus})`,
        hypothesis: 'Parent step hypothesis',
        category: 'broken-access-control',
        targetAssetIds: [asset.id],
        sourceOrigins: [ORIGIN],
      })
      const child = storage.addChainStep(run, {
        title: `Child (${childStatus})`,
        hypothesis: 'Child step hypothesis',
        category: 'broken-access-control',
        targetAssetIds: [asset.id],
        dependsOnStepIds: [parent.id],
        sourceOrigins: [ORIGIN],
      })

      // Set exact target statuses directly so even terminal transitions (e.g. from canceled) are clean.
      storage.client.prepare('update chain_steps set status = ? where id = ?').run(parentStatus, parent.id)
      storage.client.prepare('update chain_steps set status = ? where id = ?').run(childStatus, child.id)

      const preSteps = storage.listChainSteps(runId, run.goalRevision)
      const preBlocked = new Set(permanentlyBlockedStepIds(preSteps))
      const preDispatchable = new Set(dispatchableReadySteps(preSteps).map(s => s.id))

      storage.refreshReadyChainSteps(runId, run.goalRevision)

      const postSteps = storage.listChainSteps(runId, run.goalRevision)
      const postChild = postSteps.find(s => s.id === child.id)!
      const postDispatchable = new Set(dispatchableReadySteps(postSteps).map(s => s.id))

      const label = `pair (${parentStatus} -> ${childStatus})`

      if (childStatus !== 'pending') {
        assert.equal(preBlocked.has(child.id), false, `${label}: non-pending child must not be marked permanently blocked`)
        assert.equal(postChild.status, childStatus, `${label}: refreshReadyChainSteps must not mutate non-pending child`)
        assert.equal(
          preDispatchable.has(child.id),
          childStatus === 'ready',
          `${label}: non-pending child is dispatchable iff ready`,
        )
      } else if (stepBlocksDependent(parentStatus)) {
        // Terminal non-satisfying parent with no retry re-pointing -> permanently blocked / lost!
        assert.equal(preBlocked.has(child.id), true, `${label}: exec-dispatch must mark child permanently blocked`)
        assert.equal(preDispatchable.has(child.id), false, `${label}: exec-dispatch must exclude stranded child`)
        assert.equal(isTerminalStepStatus(postChild.status), true, `${label}: store refresh must resolve child to terminal`)
        assert.equal(isLostWorkStepStatus(postChild.status), true, `${label}: store refresh must count child as lostWork`)
        const expectedStatus = stepKillsDependents(parentStatus) ? 'tainted' : 'blocked'
        assert.equal(postChild.status, expectedStatus, `${label}: store refresh status mismatch`)
        assert.equal(postDispatchable.has(child.id), false, `${label}: post-refresh child must not be dispatchable`)
      } else if (stepSatisfiesDependency(parentStatus)) {
        // Satisfying parent (`complete`) -> promoted to `ready`!
        assert.equal(preBlocked.has(child.id), false, `${label}: satisfied child must not be permanently blocked`)
        assert.equal(preDispatchable.has(child.id), true, `${label}: satisfied child must be dispatchable`)
        assert.equal(postChild.status, 'ready', `${label}: store refresh must promote child to ready`)
        assert.equal(postDispatchable.has(child.id), true, `${label}: post-refresh child must stay dispatchable`)
      } else {
        // Active parent (`pending`, `ready`, `running`) -> stays `pending`!
        assert.equal(preBlocked.has(child.id), false, `${label}: child of active parent must not be permanently blocked`)
        assert.equal(preDispatchable.has(child.id), true, `${label}: child of active parent remains potentially dispatchable`)
        assert.equal(postChild.status, 'pending', `${label}: child of active parent must remain pending`)
        assert.equal(postDispatchable.has(child.id), true, `${label}: post-refresh child of active parent stays dispatchable`)
      }

      // Pre-refresh and post-refresh dispatchable sets MUST agree 100% on every pair.
      assert.deepEqual(
        [...preDispatchable].sort(),
        [...postDispatchable].sort(),
        `${label}: pre- and post-refresh dispatchableReadySteps must agree`,
      )

      // Zero pending steps with a terminal non-satisfying dependency may remain after refresh.
      const postById = new Map(postSteps.map(s => [s.id, s]))
      const strandedPending = postSteps.filter(s =>
        s.status === 'pending' && s.dependsOnStepIds.some(sid => {
          const dep = postById.get(sid)
          return !dep || stepBlocksDependent(dep.status)
        }),
      )
      assert.deepEqual(strandedPending, [], `${label}: zero pending steps may remain on terminal non-satisfying deps`)
    }
  }

  assert.equal(pairsChecked, chainStepStatuses.length * chainStepStatuses.length)
})

// ============================================================================
// 3. Transitive multi-hop propagation agreement (A -> B -> C)
// ============================================================================

test('R2-07.3: transitive chains A -> B -> C agree between permanentlyBlockedStepIds and refreshReadyChainSteps', async t => {
  const { storage } = makeStore(t, 'kovo-r2-07-transitive-')
  const blockingStatuses = chainStepStatuses.filter(stepBlocksDependent)
  assert.equal(blockingStatuses.length, 8, 'all 8 non-complete terminal statuses block un-repointed dependents')

  for (const rootStatus of blockingStatuses) {
    const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
    const asset = run.candidates.find(c => run.approved.includes(c.id))!

    const stepA = storage.addChainStep(run, {
      title: `Root A (${rootStatus})`,
      hypothesis: 'Root step',
      targetAssetIds: [asset.id],
      sourceOrigins: [ORIGIN],
    })
    const stepB = storage.addChainStep(run, {
      title: 'Child B',
      hypothesis: 'Depends on A',
      targetAssetIds: [asset.id],
      dependsOnStepIds: [stepA.id],
      sourceOrigins: [ORIGIN],
    })
    const stepC = storage.addChainStep(run, {
      title: 'Grandchild C',
      hypothesis: 'Depends on B',
      targetAssetIds: [asset.id],
      dependsOnStepIds: [stepB.id],
      sourceOrigins: [ORIGIN],
    })
    storage.client.prepare('update chain_steps set status = ? where id = ?').run(rootStatus, stepA.id)

    const preSteps = storage.listChainSteps(runId, run.goalRevision)
    assert.deepEqual(
      permanentlyBlockedStepIds(preSteps).sort(),
      [stepB.id, stepC.id].sort(),
      `root=${rootStatus}: permanentlyBlockedStepIds must catch transitive dependents B and C`,
    )
    assert.deepEqual(
      dispatchableReadySteps(preSteps),
      [],
      `root=${rootStatus}: dispatchableReadySteps must exclude transitive stranded dependents`,
    )

    storage.refreshReadyChainSteps(runId, run.goalRevision)
    const postSteps = storage.listChainSteps(runId, run.goalRevision)
    const postB = postSteps.find(s => s.id === stepB.id)!
    const postC = postSteps.find(s => s.id === stepC.id)!
    assert.equal(isTerminalStepStatus(postB.status), true, `root=${rootStatus}: B must be terminal`)
    assert.equal(isTerminalStepStatus(postC.status), true, `root=${rootStatus}: C must be terminal`)
    assert.equal(isLostWorkStepStatus(postB.status), true, `root=${rootStatus}: B must be lostWork`)
    assert.equal(isLostWorkStepStatus(postC.status), true, `root=${rootStatus}: C must be lostWork`)
    assert.equal(postSteps.some(s => s.status === 'pending'), false, `root=${rootStatus}: zero pending steps may remain`)
  }
})

// ============================================================================
// 4. Retry creation re-points pending dependents & blocks on retry exhaustion
// ============================================================================

test('R2-07.4: maybeRequeueRetryableStep re-points pending dependents to the retry step and blocks them if retry exhausts', async t => {
  const { storage } = makeStore(t, 'kovo-r2-07-retry-repoint-')

  // Path A: Retry succeeds -> re-pointed dependent promotes to `ready`
  {
    const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
    const asset = run.candidates.find(c => run.approved.includes(c.id))!
    const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
    t.after(() => engine.stop())
    const { reconPlanner } = internals(engine)
    storage.updateRun(runId, { phase: 'investigation', status: 'running', dynamicStepBudget: 12 })

    const parent = storage.addChainStep(run, {
      title: 'Parent check on GET /api/v1/orders/:id',
      hypothesis: 'Verify access control on GET /api/v1/orders/:id',
      category: 'broken-access-control',
      targetAssetIds: [asset.id],
      sourceOrigins: [ORIGIN],
    })
    const dependent = storage.addChainStep(run, {
      title: 'Follow-up check on POST /api/v1/orders/:id/export',
      hypothesis: 'Depends on parent verification',
      category: 'broken-access-control',
      targetAssetIds: [asset.id],
      dependsOnStepIds: [parent.id],
      sourceOrigins: [ORIGIN],
    })
    const grandchild = storage.addChainStep(run, {
      title: 'Final check on GET /api/v1/orders/:id/download',
      hypothesis: 'Depends on follow-up check',
      category: 'broken-access-control',
      targetAssetIds: [asset.id],
      dependsOnStepIds: [dependent.id],
      sourceOrigins: [ORIGIN],
    })
    reconPlanner.registerStepTargets(runId, parent.id, [
      { origin: ORIGIN, method: 'GET', route: '/api/v1/orders/:id', vulnClass: 'broken-access-control' },
    ])
    const w1 = storage.makeWorker(run, 'investigation', asset, parent.title, parent.hypothesis, { stepId: parent.id, sourceOrigins: [ORIGIN] })
    storage.updateChainStep(parent.id, { status: 'turn_capped', assignedWorkerId: w1.id })

    const res = reconPlanner.maybeRequeueRetryableStep({
      run: storage.run(runId),
      step: { ...parent, status: 'turn_capped', assignedWorkerId: w1.id },
      assignment: w1,
      terminalStatus: 'turn_capped',
      targetOrigins: [ORIGIN],
    })
    assert.equal(res.requeued, true)
    assert.ok(res.retryStep)
    assert.equal(res.retryStep.status, 'ready')
    assert.deepEqual(res.retryStep.dependsOnStepIds, [parent.id], 'retry step retains lineage link to original parent')
    assert.deepEqual(res.repointedDependentIds, [dependent.id])

    const afterRequeue = storage.listChainSteps(runId, run.goalRevision)
    const depAfter = afterRequeue.find(s => s.id === dependent.id)!
    assert.deepEqual(depAfter.dependsOnStepIds, [res.retryStep.id], 'pending dependent must be re-pointed to retry step')

    // Refresh while retry is ready -> dependent & grandchild wait cleanly in pending (not tainted/blocked)
    storage.refreshReadyChainSteps(runId, run.goalRevision)
    const duringRetry = storage.listChainSteps(runId, run.goalRevision)
    assert.equal(duringRetry.find(s => s.id === res.retryStep!.id)?.status, 'ready')
    assert.equal(duringRetry.find(s => s.id === dependent.id)?.status, 'pending')
    assert.equal(duringRetry.find(s => s.id === grandchild.id)?.status, 'pending')
    assert.deepEqual(permanentlyBlockedStepIds(duringRetry), [])

    // Retry completes -> dependent promotes to ready!
    storage.updateChainStep(res.retryStep.id, { status: 'complete' })
    storage.refreshReadyChainSteps(runId, run.goalRevision)
    const afterComplete = storage.listChainSteps(runId, run.goalRevision)
    assert.equal(afterComplete.find(s => s.id === dependent.id)?.status, 'ready')
    assert.equal(afterComplete.find(s => s.id === grandchild.id)?.status, 'pending')
  }

  // Path B: Retry ALSO hits turn_capped (retry cap exhausted) -> dependents become blocked/tainted (lostWork)
  {
    const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
    const asset = run.candidates.find(c => run.approved.includes(c.id))!
    const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
    t.after(() => engine.stop())
    const { reconPlanner } = internals(engine)
    storage.updateRun(runId, { phase: 'investigation', status: 'running', dynamicStepBudget: 12 })

    const parent = storage.addChainStep(run, {
      title: 'Parent check on GET /api/v1/tickets/:id',
      hypothesis: 'Verify access control on GET /api/v1/tickets/:id',
      category: 'broken-access-control',
      targetAssetIds: [asset.id],
      sourceOrigins: [ORIGIN],
    })
    const dependent = storage.addChainStep(run, {
      title: 'Follow-up ticket check',
      hypothesis: 'Depends on parent ticket check',
      category: 'broken-access-control',
      targetAssetIds: [asset.id],
      dependsOnStepIds: [parent.id],
      sourceOrigins: [ORIGIN],
    })
    const grandchild = storage.addChainStep(run, {
      title: 'Grandchild ticket check',
      hypothesis: 'Depends on follow-up ticket check',
      category: 'broken-access-control',
      targetAssetIds: [asset.id],
      dependsOnStepIds: [dependent.id],
      sourceOrigins: [ORIGIN],
    })
    const w1 = storage.makeWorker(run, 'investigation', asset, parent.title, parent.hypothesis, { stepId: parent.id, sourceOrigins: [ORIGIN] })
    storage.updateChainStep(parent.id, { status: 'nudged_out', assignedWorkerId: w1.id })

    const retry1 = reconPlanner.maybeRequeueRetryableStep({
      run: storage.run(runId),
      step: { ...parent, status: 'nudged_out', assignedWorkerId: w1.id },
      assignment: w1,
      terminalStatus: 'nudged_out',
      targetOrigins: [ORIGIN],
    })
    assert.equal(retry1.requeued, true)
    const retryStep = retry1.retryStep!

    // Retry itself ends turn_capped; second retry is refused by the 1-retry cap.
    storage.updateChainStep(retryStep.id, { status: 'turn_capped', assignedWorkerId: w1.id })
    const retry2 = reconPlanner.maybeRequeueRetryableStep({
      run: storage.run(runId),
      step: { ...retryStep, status: 'turn_capped', assignedWorkerId: w1.id },
      assignment: w1,
      terminalStatus: 'turn_capped',
      targetOrigins: [ORIGIN],
    })
    assert.equal(retry2.requeued, false)
    assert.equal(retry2.reason, 'already_retry_step')

    const beforeRefresh = storage.listChainSteps(runId, run.goalRevision)
    assert.deepEqual(
      permanentlyBlockedStepIds(beforeRefresh).sort(),
      [dependent.id, grandchild.id].sort(),
      'once retry is exhausted, dispatch must flag both dependent and grandchild as permanently blocked',
    )
    assert.deepEqual(dispatchableReadySteps(beforeRefresh), [], 'zero dispatchable steps remain after retry exhaustion')

    storage.refreshReadyChainSteps(runId, run.goalRevision)
    const afterRefresh = storage.listChainSteps(runId, run.goalRevision)
    assert.equal(afterRefresh.find(s => s.id === dependent.id)?.status, 'blocked')
    assert.equal(afterRefresh.find(s => s.id === grandchild.id)?.status, 'tainted')
    assert.equal(afterRefresh.some(s => s.status === 'pending'), false, 'zero pending steps remain after retry exhaustion')
  }
})

// ============================================================================
// 5. O3 planner deferral gate ignores stranded steps on terminal non-satisfying deps
// ============================================================================

test('R2-07.5: O3 planner deferral gate never defers on stranded pending steps with terminal non-satisfying parents', () => {
  const strandedQueue = [
    { id: 'p-cap', status: 'turn_capped', dependsOnStepIds: [] },
    { id: 'p-nudge', status: 'nudged_out', dependsOnStepIds: [] },
    { id: 'p-rot', status: 'rotated_partial', dependsOnStepIds: [] },
    { id: 'p-model', status: 'model_failure', dependsOnStepIds: [] },
    { id: 'p-infra', status: 'infra_failed', dependsOnStepIds: [] },
    { id: 'c-cap', status: 'pending', dependsOnStepIds: ['p-cap'] },
    { id: 'c-nudge', status: 'pending', dependsOnStepIds: ['p-nudge'] },
    { id: 'c-rot', status: 'pending', dependsOnStepIds: ['p-rot'] },
    { id: 'c-model', status: 'pending', dependsOnStepIds: ['p-model'] },
    { id: 'c-infra', status: 'pending', dependsOnStepIds: ['p-infra'] },
    { id: 'gc-cap', status: 'pending', dependsOnStepIds: ['c-cap'] },
  ]

  const blocked = permanentlyBlockedStepIds(strandedQueue)
  assert.deepEqual(blocked.sort(), ['c-cap', 'c-infra', 'c-model', 'c-nudge', 'c-rot', 'gc-cap'])

  const dispatchable = dispatchableReadySteps(strandedQueue)
  assert.equal(dispatchable.length, 0, 'stranded pending steps must NEVER inflate dispatchableReadySteps')

  const gate = shouldInvokeLlmPlanner({
    roundNo: 2,
    readyStepCount: dispatchable.length,
    activeWorkerCount: 0,
    waveBufferTarget: 4,
    newConfirmedFindings: 0,
    newCrossOriginCapabilities: 0,
    openProofGaps: 0,
    queueEmptyOrDraining: dispatchable.length === 0,
  })
  assert.equal(gate.invokeLlm, true, 'O3 deferral gate must invoke LLM planner rather than deferring on stranded steps')

  // An explicit ready retry/continuation step IS legitimately dispatchable.
  const withReadyRetry = [
    ...strandedQueue,
    { id: 'retry-cap', status: 'ready', dependsOnStepIds: ['p-cap'] },
    { id: 'cont-rot', status: 'ready', dependsOnStepIds: ['p-rot'] },
  ]
  assert.deepEqual(
    dispatchableReadySteps(withReadyRetry).map(s => s.id).sort(),
    ['cont-rot', 'retry-cap'],
  )
})

// ============================================================================
// 6. RunActor reconciler & run-snapshot countDrySteps derive from STEP_STATUS
// ============================================================================

test('R2-07.6: RunActor reconciler produces typed failure statuses, protects terminal steps, and countDrySteps counts all terminal statuses', async t => {
  const { storage } = makeStore(t, 'kovo-r2-07-reconcile-snapshot-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })

  const engine = new Execution(storage, { backend: stubBackend() })
  t.after(() => engine.stop())
  const { tier3Approvals } = internals(engine)

  // (a) Settled worker with model error -> step reconciled to `model_failure`, dependent tainted
  const sModel = storage.addChainStep(run, {
    title: 'Orphaned model-failure step',
    hypothesis: 'Check route A',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  const sModelDep = storage.addChainStep(run, {
    title: 'Dependent of model-failure step',
    hypothesis: 'Check route A follow-up',
    targetAssetIds: [asset.id],
    dependsOnStepIds: [sModel.id],
    sourceOrigins: [ORIGIN],
  })
  const wModel = storage.makeWorker(run, 'investigation', asset, sModel.title, sModel.hypothesis, { stepId: sModel.id, sourceOrigins: [ORIGIN] })
  storage.updateWorker(wModel.id, { status: 'failed', outcome: 'OpenRouter 429 rate limit exceeded' })
  storage.updateChainStep(sModel.id, { status: 'running', assignedWorkerId: wModel.id })

  // (b) Settled worker with infra error -> step reconciled to `infra_failed`
  const sInfra = storage.addChainStep(run, {
    title: 'Orphaned infra-failure step',
    hypothesis: 'Check route B',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  const wInfra = storage.makeWorker(run, 'investigation', asset, sInfra.title, sInfra.hypothesis, { stepId: sInfra.id, sourceOrigins: [ORIGIN] })
  storage.updateWorker(wInfra.id, { status: 'failed', outcome: 'Docker daemon ECONNREFUSED' })
  storage.updateChainStep(sInfra.id, { status: 'running', assignedWorkerId: wInfra.id })

  // (c) Already-terminal typed step (`turn_capped`) must NEVER be overwritten by reconciler
  const sCapped = storage.addChainStep(run, {
    title: 'Already turn_capped step',
    hypothesis: 'Check route C',
    targetAssetIds: [asset.id],
    sourceOrigins: [ORIGIN],
  })
  const wCapped = storage.makeWorker(run, 'investigation', asset, sCapped.title, sCapped.hypothesis, { stepId: sCapped.id, sourceOrigins: [ORIGIN] })
  storage.updateWorker(wCapped.id, { status: 'complete', outcome: 'turn_limit reached' })
  storage.updateChainStep(sCapped.id, { status: 'turn_capped', assignedWorkerId: wCapped.id })

  tier3Approvals.reconcileSettledApprovalWorkers(storage.run(runId))

  const reconciled = storage.listChainSteps(runId, run.goalRevision)
  assert.equal(reconciled.find(s => s.id === sModel.id)?.status, 'model_failure')
  assert.equal(reconciled.find(s => s.id === sModelDep.id)?.status, 'tainted')
  assert.equal(reconciled.find(s => s.id === sInfra.id)?.status, 'infra_failed')
  assert.equal(reconciled.find(s => s.id === sCapped.id)?.status, 'turn_capped')

  // (d) countDrySteps recognizes all typed terminal statuses and stops at any active status
  const { runId: snapRunId, run: snapRun } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const snapAsset = snapRun.candidates.find(c => snapRun.approved.includes(c.id))!
  const sequence: ChainStepStatus[] = [
    'ready', // stops streak here
    'complete',
    'turn_capped',
    'nudged_out',
    'rotated_partial',
    'model_failure',
    'infra_failed',
  ]
  for (const status of sequence) {
    const st = storage.addChainStep(snapRun, {
      title: `Dry step (${status})`,
      hypothesis: 'Snapshot dry-streak check',
      targetAssetIds: [snapAsset.id],
      sourceOrigins: [ORIGIN],
    })
    storage.client.prepare('update chain_steps set status = ? where id = ?').run(status, st.id)
  }
  const snapDir = mkdtempSync(join(tmpdir(), 'kovo-r2-07-snap-'))
  t.after(() => rmSync(snapDir, { recursive: true, force: true }))
  const captured = captureRunSnapshot({
    storage,
    snapshotDir: snapDir,
    checkpoint: 'planner-round',
    gitSha: 'r2-07-test',
    target: {
      app: 'test-app',
      seed: 42,
      seedSet: 'dev',
      mode: 'agentic',
      origin: ORIGIN,
      loginPath: null,
      canaryBaseUrls: [],
      projectId: snapRun.projectId,
      runId: snapRunId,
    },
  })
  assert.equal(
    captured.snapshot.coordinator.k6DryStreak,
    6,
    'countDrySteps must count all trailing terminal statuses derived from STEP_STATUS and stop at active status',
  )
})
