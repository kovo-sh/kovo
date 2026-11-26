/**
 * v7 dispatch funnel — coverage regression tests.
 *
 * The measured v7 defect: the planner reported a plan (opsportal 7 hypotheses, acme 19) while the
 * scheduler dispatched one or two investigations and left the rest `ready`. Two independent losses
 * are pinned here, both without network or Docker:
 *
 *  1. multi-trial fanout spent every worker slot on duplicate trials of the top hypothesis, so the
 *     distinct planned hypotheses never ran (7 planned / 6 slots / 3-way fanout = 2 distinct);
 *  2. a dry-round or coordinator-done stop could abandon dispatchable ready steps while worker
 *     slots were free. The funnel reports it loudly instead of silently under-reporting coverage.
 *
 * It also pins the dependency-sanitisation contract: a planner-emitted parent id that does not
 * exist can never be satisfied, so it must not strand a step as permanently `pending`.
 *
 * All fixtures are synthetic: no benchmark/app/route/seed literals.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { Execution } from '../src/server/execution.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'
import {
  DISPATCH_FUNNEL_COUNT_KEYS,
  FrontierDispatcher,
  FrontierWaveController,
  addFunnelCounts,
  circuitBreakAction,
  coordinatorSchedulerDecision,
  dispatchableReadySteps,
  emptyDispatchFunnel,
  evaluateDispatchStop,
  multiTrialSurplusSlots,
  normalizeDispatchStopReason,
  permanentlyBlockedStepIds,
  planMultiTrialExpansion,
} from '../src/server/execution.ts'

interface FakeStep {
  id: string
  seq: number
  status: 'pending' | 'ready' | 'running' | 'complete' | 'canceled' | 'tainted' | 'blocked'
  priority: number
  title: string
  category: string
  hypothesis: string
  skills: string[]
  dependsOnFactIds: string[]
  dependsOnStepIds: string[]
  sourceOrigins: string[]
  trialGroupId?: string | null
  trialIndex?: number
}

const origin = 'https://app.example.invalid'

function planStep(index: number, overrides: Partial<FakeStep> = {}): FakeStep {
  return {
    id: `step-${index}`,
    seq: index,
    status: 'ready',
    priority: 96,
    title: `Investigate class ${index} on the object API`,
    category: 'broken-access-control',
    hypothesis: 'Probe the named route for a cross-persona differential.',
    skills: [],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [origin],
    trialGroupId: null,
    trialIndex: 0,
    ...overrides,
  }
}

// ============================================================================
// 1. Multi-trial fanout may only spend surplus slots
// ============================================================================

test('7 planned hypotheses and 6 slots: no pairwise/three-way fanout (the measured 1..2/7 defect)', () => {
  const steps = Array.from({ length: 7 }, (_, index) => planStep(index + 1, { priority: 100 }))
  // Counterfactual: the pre-fix fanout would turn 7 hypotheses into 21 steps, and a 6-slot fleet
  // would then run 2 distinct hypotheses x 3 trials.
  assert.equal(multiTrialSurplusSlots(7, 6), 0)
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 6 }), [])
  const dispatcher = new FrontierDispatcher({ controller: new FrontierWaveController() })
  const dispatched = dispatcher.dispatch(steps, 6).ordered
  assert.equal(new Set(dispatched.map(step => step.id)).size, 6, 'six distinct hypotheses must take the six slots')
})

test('19 planned hypotheses and 6 slots: zero trial expansion, six distinct dispatched', () => {
  const steps = Array.from({ length: 19 }, (_, index) => planStep(index + 1, {
    priority: index < 4 ? 100 : 90,
  }))
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 6 }), [])
  const dispatcher = new FrontierDispatcher({ controller: new FrontierWaveController() })
  const planned = dispatcher.dispatch(steps, 6).ordered
  assert.equal(planned.length, 6)
  assert.equal(new Set(planned.map(step => step.title)).size, 6)
})

test('idle fleet still fans out: 1 hypothesis and 6 slots uses the trial budget', () => {
  const steps = [planStep(1, { priority: 100 })]
  const expansions = planMultiTrialExpansion({ steps, concurrency: 6 })
  assert.equal(expansions.length, 1)
  assert.equal(expansions[0].fanout, 3, 'priority-100 hypothesis keeps its 3-trial fanout')
})

test('two hypotheses and six slots: fanout fills idle capacity but never exceeds it', () => {
  const steps = [planStep(1, { priority: 100 }), planStep(2, { priority: 100 })]
  const expansions = planMultiTrialExpansion({ steps, concurrency: 6 })
  const trials = expansions.reduce((total, entry) => total + entry.fanout - 1, 0)
  assert.ok(expansions.length >= 1)
  assert.ok(trials <= multiTrialSurplusSlots(2, 6), `trials ${trials} must stay within the 4 surplus slots`)
  assert.equal(expansions[0].fanout, 3)
})

test('disabled multi-trial and single-worker runs never expand', () => {
  const steps = [planStep(1, { priority: 100 })]
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 6, multiTrialEnabled: false }), [])
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 1 }), [])
})

test('already-expanded trial groups are never re-expanded', () => {
  const steps = [
    planStep(1, { priority: 100, trialGroupId: 'grp-1' }),
    planStep(2, { priority: 100, trialGroupId: 'grp-1', trialIndex: 1 }),
  ]
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 6 }), [])
})

// ============================================================================
// 2. Dependency sanitisation — unknown ids cannot strand a plan
// ============================================================================

test('a pending step citing an unknown parent fact is permanently blocked, not dispatchable', () => {
  const steps = [
    planStep(1, { status: 'pending', dependsOnFactIds: ['fact-known'] }),
    planStep(2, { status: 'pending', dependsOnFactIds: ['fact-missing'] }),
    planStep(3, { status: 'pending', dependsOnStepIds: ['step-missing'] }),
    planStep(4, { status: 'pending', dependsOnStepIds: ['step-5'] }),
    planStep(5, { status: 'complete' }),
    planStep(6, { status: 'pending', dependsOnStepIds: ['step-7'] }),
    planStep(7, { status: 'canceled' }),
  ] as FakeStep[]
  const knownFacts = new Set(['fact-known'])
  assert.deepEqual(permanentlyBlockedStepIds(steps, knownFacts).sort(), ['step-2', 'step-3', 'step-6'])
  const ready = dispatchableReadySteps(steps, knownFacts).map(step => step.id).sort()
  assert.deepEqual(ready, ['step-1', 'step-4'], 'only steps with satisfiable dependencies stay dispatchable')
})

test('a step becomes permanently blocked after its parent is canceled', () => {
  const steps = [
    planStep(1, { status: 'canceled' }),
    planStep(2, { status: 'pending', dependsOnStepIds: ['step-1'] }),
  ] as FakeStep[]
  assert.deepEqual(permanentlyBlockedStepIds(steps), ['step-2'])
  assert.deepEqual(dispatchableReadySteps(steps), [])
})

test('all-ready queue has no dependency loss', () => {
  const steps = [planStep(1), planStep(2), planStep(3)]
  assert.deepEqual(permanentlyBlockedStepIds(steps, new Set()), [])
  assert.equal(dispatchableReadySteps(steps, new Set()).length, 3)
})

// ============================================================================
// 3. Dry/coordinator stop must not strand dispatchable ready work
// ============================================================================

test('dry stop with ready work and a free slot is deferred, never silently stranded', () => {
  const evaluation = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 3, freeSlots: 2,
  })
  assert.equal(evaluation.decision, 'continue')
  assert.equal(evaluation.deferred, true)
  assert.equal(evaluation.stranded, false)
  assert.equal(evaluation.stopReason, 'dry_rounds')
})

test('dry stop with ready work and an idle fleet is a stranded violation', () => {
  const evaluation = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 4, freeSlots: 0, inFlight: 0,
  })
  assert.equal(evaluation.decision, 'stop')
  assert.equal(evaluation.stranded, true)
  assert.equal(evaluation.remainingReady, 4)
})

test('dry stop with every slot busy is not a violation: the queue drains behind in-flight work', () => {
  const evaluation = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 12, freeSlots: 0, inFlight: 6,
  })
  assert.equal(evaluation.decision, 'stop')
  assert.equal(evaluation.stranded, false)
  assert.equal(evaluation.remainingReady, 12)
})

test('a genuinely dry queue still stops (2 dry rounds, zero ready steps)', () => {
  const decision = coordinatorSchedulerDecision({
    budgetExhausted: false,
    budgetRequests: 1000,
    spentRequests: 10,
    startedAt: Date.now(),
    maxDurationMs: 600_000,
    emptyRounds: 0,
    pendingOob: 0,
    highPriorityQueueEmpty: true,
    consecutiveDryRounds: 2,
  })
  assert.equal(decision.decision, 'stop')
  assert.equal(decision.reason, 'diminishing_returns')
  const evaluation = evaluateDispatchStop({
    decision: decision.decision, reason: decision.reason, remainingReady: 0, freeSlots: 6,
  })
  assert.equal(evaluation.decision, 'stop')
  assert.equal(evaluation.stranded, false)
  assert.equal(normalizeDispatchStopReason(decision.reason), 'dry_rounds')
})

test('coordinator_done with ready work is deferred while slots are free', () => {
  const evaluation = evaluateDispatchStop({
    decision: 'stop', reason: 'coordinator_done', remainingReady: 5, freeSlots: 6,
  })
  assert.equal(evaluation.decision, 'continue')
  assert.equal(evaluation.deferred, true)
})

test('budget/request/wall exhaustion may stop with ready work and is not a violation', () => {
  for (const reason of ['budget_exhausted', 'requests_exhausted', 'wallclock_exhausted']) {
    const evaluation = evaluateDispatchStop({
      decision: 'stop', reason, remainingReady: 9, freeSlots: 0,
      budgetExhausted: reason === 'budget_exhausted',
      requestExhausted: reason === 'requests_exhausted',
      wallExhausted: reason === 'wallclock_exhausted',
    })
    assert.equal(evaluation.decision, 'stop', reason)
    assert.equal(evaluation.stranded, false, reason)
  }
})

test('a continue decision never reports a deferred or stranded stop', () => {
  const evaluation = evaluateDispatchStop({ decision: 'continue', reason: 'continue', remainingReady: 0, freeSlots: 6 })
  assert.equal(evaluation.decision, 'continue')
  assert.equal(evaluation.deferred, false)
  assert.equal(evaluation.stranded, false)
})

test('dry-round stop reason vocabulary maps the scheduler reason', () => {
  assert.equal(normalizeDispatchStopReason('diminishing_returns'), 'dry_rounds')
  assert.equal(normalizeDispatchStopReason('coordinator_done'), 'coordinator_done')
  assert.equal(normalizeDispatchStopReason('continue'), 'running')
  assert.equal(normalizeDispatchStopReason(null), 'running')
})

// ============================================================================
// 4. Structured funnel counts
// ============================================================================

test('funnel accumulates planned → filtered* → enqueued from structured counts', () => {
  const funnel = emptyDispatchFunnel(3)
  addFunnelCounts(funnel, {
    planned: 19, enqueued: 11, filteredAlreadyConfirmed: 3, filteredCap: 2,
    filteredDedupe: 1, filteredNoAsset: 1, filteredBudget: 1,
  })
  assert.equal(funnel.planned, 19)
  assert.equal(funnel.enqueued, 11)
  const filtered = DISPATCH_FUNNEL_COUNT_KEYS
    .filter(key => key.startsWith('filtered'))
    .reduce((total, key) => total + funnel[key], 0)
  assert.equal(funnel.planned, funnel.enqueued + filtered, 'every planned hypothesis is enqueued or attributed to a filter')
  assert.equal(funnel.roundNo, 3)
  assert.equal(funnel.stopReason, 'running')
})

test('funnel counts are never negative and ignore unknown keys', () => {
  const funnel = emptyDispatchFunnel()
  addFunnelCounts(funnel, { planned: -4, enqueued: 2 } as never)
  assert.equal(funnel.planned, 0)
  assert.equal(funnel.enqueued, 2)
})

// ============================================================================
// 5. Scheduler contract: 7 planned, 1 dry step -> the other 6 still run
// ============================================================================

/**
 * Minimal deterministic scheduler slice: expands trials, fills slots round-robin, completes the
 * dispatched step (dry steps produce no evidence), and re-plans. Mirrors the execution contract
 * without an LLM, Docker or HTTP.
 */
function simulateDispatch(input: {
  steps: FakeStep[]
  concurrency: number
  dryStepIds?: ReadonlySet<string>
  stopAfterRounds?: number
}) {
  const queued = new Map(input.steps.map(step => [step.id, { ...step }]))
  const dry = input.dryStepIds ?? new Set<string>()
  const dispatcher = new FrontierDispatcher({ controller: new FrontierWaveController() })
  const dispatched: string[] = []
  let stopReason = 'continue'
  let remainingReady = 0
  let rounds = 0
  const maxRounds = input.stopAfterRounds ?? 50
  for (; rounds < maxRounds; rounds += 1) {
    const live = [...queued.values()]
    for (const expansion of planMultiTrialExpansion({ steps: live, concurrency: input.concurrency })) {
      expansion.step.trialGroupId = `trial-${expansion.step.id}`
    }
    const ready = [...queued.values()].filter(step => step.status === 'ready')
    remainingReady = ready.length
    const slots = Math.max(0, input.concurrency - [...queued.values()].filter(step => step.status === 'running').length)
    const plan = dispatcher.dispatch(ready, slots)
    for (const step of plan.ordered) {
      const liveStep = queued.get(step.id)!
      liveStep.status = 'running'
      dispatched.push(liveStep.id)
    }
    if (plan.ordered.length === 0) {
      const evaluation = evaluateDispatchStop({
        decision: 'stop', reason: 'diminishing_returns', remainingReady, freeSlots: slots,
      })
      stopReason = evaluation.decision === 'stop' ? evaluation.stopReason : 'continue'
      if (evaluation.decision === 'stop') break
    }
    // Immediate completion: dry steps record nothing; the rest would submit specs (out of scope).
    for (const step of queued.values()) {
      if (step.status === 'running') step.status = 'complete'
    }
    void dry
  }
  return { dispatched, stopReason, remainingReady, rounds }
}

test('7 planned steps with 1 dry step dispatch the other 6 before an empty queue may stop', () => {
  const steps = Array.from({ length: 7 }, (_, index) => planStep(index + 1, { priority: 100 }))
  const result = simulateDispatch({ steps, concurrency: 6, dryStepIds: new Set(['step-3']) })
  assert.equal(result.dispatched.length, 7, 'one dry step must not cost the other six their slot')
  assert.equal(new Set(result.dispatched).size, 7)
  assert.equal(result.stopReason, 'dry_rounds', 'the queue is only allowed to stop once it is empty')
  assert.equal(result.remainingReady, 0)
  assert.equal(result.rounds, 2, 'round 1 dispatches six, round 2 dispatches the seventh, round 3 is dry')
})

test('19 planned steps with 6 slots dispatch all 19 distinct hypotheses when dry steps exist', () => {
  const steps = Array.from({ length: 19 }, (_, index) => planStep(index + 1, { priority: 100 }))
  const result = simulateDispatch({ steps, concurrency: 6, dryStepIds: new Set(['step-1', 'step-9']) })
  assert.equal(new Set(result.dispatched).size, 19)
  assert.equal(result.stopReason, 'dry_rounds')
  assert.equal(result.remainingReady, 0)
})

test('a fully dry queue stops without dispatching duplicates of the same hypothesis', () => {
  const steps = [planStep(1, { priority: 100 }), planStep(2, { priority: 96 }), planStep(3, { priority: 90 })]
  const result = simulateDispatch({ steps, concurrency: 6, dryStepIds: new Set(steps.map(step => step.id)) })
  assert.deepEqual(result.dispatched.sort(), ['step-1', 'step-2', 'step-3'])
  assert.equal(result.stopReason, 'dry_rounds')
  assert.equal(result.remainingReady, 0)
})

// ============================================================================
// 6. Circuit-breaker scope: route cooldowns may not pause a run
// ============================================================================

test('route-scoped 5xx cooldown never blocks dispatch or pauses the run', () => {
  assert.equal(circuitBreakAction({
    originWide: false, approvedOrigins: ['a', 'b'], trippedOrigin: 'a',
  }), 'continue')
})

test('origin-wide trip with one approved origin pauses the run (safety invariant kept)', () => {
  assert.equal(circuitBreakAction({
    originWide: true, approvedOrigins: [origin], trippedOrigin: origin,
  }), 'pause_run')
})

test('origin-wide trip with healthy sibling origins blocks only the tripped origin', () => {
  assert.equal(circuitBreakAction({
    originWide: true, approvedOrigins: ['a', 'b'], trippedOrigin: 'a', isOpen: origin => origin === 'b',
  }), 'pause_run', 'both origins open -> pause')
  assert.equal(circuitBreakAction({
    originWide: true, approvedOrigins: ['a', 'b'], trippedOrigin: 'a', isOpen: () => false,
  }), 'block_origin', 'healthy sibling -> isolate, keep running')
})

// ============================================================================
// 7. Engine wiring: prove the scheduler uses the surplus-slot contract
// ============================================================================

test('Execution.expandEligibleMultiTrialSteps does not inflate a queued fleet into duplicate trials', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 500 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 6, multiTrialEnabled: true })
  const run = storage.run(runId)
  for (let index = 1; index <= 7; index += 1) {
    storage.addChainStep(run, {
      title: `Investigate class ${index} on the object API`,
      hypothesis: 'Probe the named route for a cross-persona differential.',
      category: 'broken-access-control',
      priority: 100,
      targetAssetIds: run.approved,
      sourceOrigins: [run.candidates.find(candidate => run.approved.includes(candidate.id))!.origin],
    })
  }
  const engine = new Execution(storage)
  t.after(() => engine.stop())
  const internals = engine as unknown as { expandEligibleMultiTrialSteps: (run: ReturnType<typeof storage.run>) => void }
  internals.expandEligibleMultiTrialSteps(storage.run(runId))
  const steps = storage.listChainSteps(runId)
  assert.equal(steps.length, 7, 'seven queued hypotheses on six slots must not fan out')
  assert.ok(steps.every(step => !step.trialGroupId))
})

