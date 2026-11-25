/**
 * Phase-B throughput (check-in #8 follow-up): assignment wall p50/p90, not just recall.
 *
 * The measurement at K=6 was 16 assignments, 10 complete / 6 paused, Phase B 310 s, median
 * assignment ~150 s. These tests pin the contract that turns a slot over faster without weakening
 * the funnel:
 *
 *  1. a standalone step gets a short wall cap and a tight turn budget;
 *  2. only a chain that cites upstream evidence keeps the long cap;
 *  3. the settlement nudge still fires at N-2 for every budget;
 *  4. a clean session is returned to the warm pool and reused (one container launch, three
 *     assignments), and `/tmp` is reset between assignments;
 *  5. a paused assignment is requeued when its slot frees instead of starving;
 *  6. provider-stall turns are counted (p50/p90), and one retry is allowed.
 *
 * Fixtures are generic/synthetic: no benchmark/app/route/seed literals.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { settlementNudgeTurnFor } from '../src/server/agent-session.ts'
import {
  CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS,
  CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS,
  MAX_PROVIDER_STALL_RETRIES,
  PROVIDER_STALL_TURN_MS,
  SINGLE_STEP_ASSIGNMENT_MAX_TURNS,
  SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS,
  percentile,
  planAssignmentBudget,
  providerStallAbortMs,
  requeueInterruptedAssignments,
  shouldRetryStalledAssignment,
  singleStepWallClockMs,
  summarizeTurnLatencies,
} from '../src/server/execution.ts'
import {
  WARM_SCRATCH_RESET_COMMAND,
  WarmWorkerPool,
} from '../src/server/worker-backend.ts'
import type { DockerRunner } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const origin = 'https://app.example.invalid'

// ============================================================================
// 1. Assignment budget: single-step cap, chain exemption
// ============================================================================

test('budget: a standalone step gets a 90–120 s cap and a tight turn budget', () => {
  const budget = planAssignmentBudget({
    routes: ['/api/items/:id'],
    parentEvidenceIds: [],
    dependsOnStepIds: [],
    baseMaxTurns: 25,
    baseWallClockMs: 160_000,
  })
  assert.equal(budget.kind, 'single_step')
  assert.equal(budget.maxTurns, SINGLE_STEP_ASSIGNMENT_MAX_TURNS)
  assert.ok(budget.maxTurns <= 18, `single-step turns must stay bounded (got ${budget.maxTurns})`)
  assert.equal(budget.wallClockMs, SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)
  assert.ok(budget.wallClockMs >= 90_000, 'cap must leave room for a real proof attempt')
  assert.ok(budget.wallClockMs <= 120_000, 'cap must turn the slot over inside ~120 s')
  assert.ok(PROVIDER_STALL_TURN_MS < budget.wallClockMs)
})

test('budget: breadth without parent evidence is still a standalone step', () => {
  const wide = planAssignmentBudget({
    routes: ['/a', '/b', '/c', '/d', '/e'],
    parentEvidenceIds: [],
    dependsOnStepIds: [],
    baseMaxTurns: 30,
    baseWallClockMs: 160_000,
  })
  assert.equal(wide.kind, 'single_step')
  assert.equal(wide.maxTurns, SINGLE_STEP_ASSIGNMENT_MAX_TURNS)
  assert.equal(wide.wallClockMs, SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)
})

test('budget: a chain with parent evidence keeps the long cap', () => {
  const chain = planAssignmentBudget({
    routes: ['/api/items/:id', '/api/items/:id/history'],
    parentEvidenceIds: ['fact-upstream'],
    dependsOnStepIds: [],
    baseMaxTurns: 25,
    baseWallClockMs: 160_000,
  })
  assert.equal(chain.kind, 'chain')
  assert.ok(chain.maxTurns >= 18, `chain turns must stay generous (got ${chain.maxTurns})`)
  assert.ok(chain.wallClockMs >= CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS)
  assert.ok(chain.wallClockMs <= CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS)
  assert.ok(chain.wallClockMs > SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS + 20_000)
  assert.ok(chain.maxTurns > SINGLE_STEP_ASSIGNMENT_MAX_TURNS)
})

test('budget: a step dependency also exempts a chain', () => {
  const chain = planAssignmentBudget({
    routes: [],
    parentEvidenceIds: [],
    dependsOnStepIds: ['step-parent'],
    baseMaxTurns: 25,
    baseWallClockMs: 140_000,
  })
  assert.equal(chain.kind, 'chain')
})

test('budget: the settlement nudge still fires at N-2 for every budget', () => {
  for (const budget of [
    planAssignmentBudget({ routes: ['/a'], parentEvidenceIds: [], dependsOnStepIds: [], baseMaxTurns: 25, baseWallClockMs: 160_000 }),
    planAssignmentBudget({ routes: ['/a'], parentEvidenceIds: ['fact-1'], dependsOnStepIds: [], baseMaxTurns: 30, baseWallClockMs: 160_000 }),
    planAssignmentBudget({ routes: ['/a'], parentEvidenceIds: [], dependsOnStepIds: [], baseMaxTurns: 8, baseWallClockMs: 60_000 }),
  ]) {
    assert.ok(budget.maxTurns >= 4)
    assert.equal(budget.settlementTurn, settlementNudgeTurnFor(budget.maxTurns))
    assert.equal(budget.settlementTurn, budget.maxTurns - 2)
  }
})

test('budget: the single-step wall override stays inside the turnover window', () => {
  assert.equal(singleStepWallClockMs({} as NodeJS.ProcessEnv), SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)
  assert.equal(singleStepWallClockMs({ KOVO_SINGLE_STEP_WALL_CLOCK_MS: '78000' } as NodeJS.ProcessEnv), 78_000)
  assert.equal(singleStepWallClockMs({ KOVO_SINGLE_STEP_WALL_CLOCK_MS: '5000' } as NodeJS.ProcessEnv), 30_000)
  assert.equal(singleStepWallClockMs({ KOVO_SINGLE_STEP_WALL_CLOCK_MS: '900000' } as NodeJS.ProcessEnv), 120_000)
})

// ============================================================================
// 2. Provider-stall accounting
// ============================================================================

test('stall: per-turn latencies expose p50/p90 and count turns over the flag threshold', () => {
  const summary = summarizeTurnLatencies([3_000, 5_000, 12_000, 45_000, 2_400])
  assert.equal(summary.samples, 5)
  assert.equal(summary.p50, 5_000)
  assert.equal(summary.p90, 45_000)
  assert.equal(summary.stallTurns, 2, 'only turns over the 10 s flag threshold are stalls')
  assert.equal(summary.stallMs, PROVIDER_STALL_TURN_MS)
  assert.deepEqual(summarizeTurnLatencies([]), { samples: 0, p50: 0, p90: 0, stallTurns: 0, stallMs: PROVIDER_STALL_TURN_MS })
})

test('stall: nearest-rank percentile clamps without inventing samples', () => {
  assert.equal(percentile([], 50), 0)
  assert.equal(percentile([10], 90), 10)
  assert.equal(percentile([10, 20, 30, 40], 50), 20)
  assert.equal(percentile([10, 20, 30, 40], 90), 40)
})

test('stall: the abort threshold scales with the median but never below the floor', () => {
  // No trusted baseline yet: a cold prompt gets the longer cold threshold.
  assert.equal(providerStallAbortMs(0, 0), 90_000)
  assert.equal(providerStallAbortMs(2_000, 2), 90_000)
  assert.equal(providerStallAbortMs(2_000, 3), 45_000)
  assert.equal(providerStallAbortMs(10_000, 3), 45_000)
  assert.equal(providerStallAbortMs(13_000, 5), 52_000)
  assert.equal(providerStallAbortMs(60_000, 8), 75_000, 'ceiling: never wait more than the ceiling')
})

test('stall: exactly one retry is allowed', () => {
  assert.equal(MAX_PROVIDER_STALL_RETRIES, 1)
  assert.equal(shouldRetryStalledAssignment(0), true)
  assert.equal(shouldRetryStalledAssignment(1), false)
  assert.equal(shouldRetryStalledAssignment(3), false)
})

// ============================================================================
// 3. Warm container reuse
// ============================================================================

function stubPoolDocker() {
  const calls: string[][] = []
  const runner: DockerRunner = async (args) => {
    calls.push(args)
    if (args[0] === 'container' && args[1] === 'create') return 'created'
    if (args[0] === 'container' && args[1] === 'inspect') return 'exited'
    return ''
  }
  const creates = () => calls.filter(call => call[0] === 'container' && call[1] === 'create').length
  return { calls, runner, creates }
}

test('warm pool: three assignments reuse one container (one launch, two reuses)', async () => {
  const { runner, creates } = stubPoolDocker()
  const pool = new WarmWorkerPool({
    cell: 'cell-a',
    image: 'kovo-worker:v4',
    dockerRunner: runner,
    runLabel: 'run-a',
    capacity: 1,
  })
  const signal = new AbortController().signal
  const names: string[] = []
  for (let i = 0; i < 3; i += 1) {
    const name = await pool.take(signal)
    assert.ok(name, `assignment ${i + 1} must get a container`)
    names.push(name!)
    assert.equal(await pool.release(name!), true, 'a cleanly stopped container returns to the pool')
  }
  assert.equal(creates(), 1, 'three assignments must never pay three cold creates')
  assert.equal(new Set(names).size, 1, 'the same container serves all three assignments')
  assert.equal(pool.stats.created, 1)
  assert.equal(pool.stats.reused, 2)
  assert.equal(pool.stats.returned, 3)
  await pool.close()
})

test('warm pool: a two-slot pool serves many assignments with two launches', async () => {
  const { runner, creates } = stubPoolDocker()
  const pool = new WarmWorkerPool({
    cell: 'cell-slots',
    image: 'kovo-worker:v4',
    dockerRunner: runner,
    runLabel: 'run-slots',
    capacity: 2,
  })
  const signal = new AbortController().signal
  for (let i = 0; i < 5; i += 1) {
    const name = await pool.take(signal)
    assert.ok(name)
    assert.equal(await pool.release(name!), true)
  }
  assert.equal(creates(), 2, 'launches must be bounded by slot count, not assignment count')
  assert.equal(pool.stats.created, 2)
  assert.equal(pool.stats.reused, 3)
  await pool.close()
})

test('warm pool: a container that is still running is removed, never parked', async () => {
  const calls: string[][] = []
  const runner: DockerRunner = async (args) => {
    calls.push(args)
    if (args[1] === 'create') return 'created'
    if (args[1] === 'inspect') return 'running'
    return ''
  }
  const pool = new WarmWorkerPool({ cell: 'cell-b', image: 'img', dockerRunner: runner, runLabel: 'run-b', capacity: 1 })
  const name = await pool.take(new AbortController().signal)
  assert.ok(name)
  assert.equal(await pool.release(name!), false)
  assert.ok(calls.some(call => call[1] === 'rm'), 'a non-stopped container is force-removed')
  await pool.close()
})

test('warm pool: the reset command touches only container scratch', () => {
  assert.match(WARM_SCRATCH_RESET_COMMAND, /\/tmp/)
  assert.doesNotMatch(WARM_SCRATCH_RESET_COMMAND, /\/repos|\/kovo-rpc|\/kovo-ipc/)
  assert.match(WARM_SCRATCH_RESET_COMMAND, /rm -rf/)
})

// ============================================================================
// 4. Queue drain: paused assignment resumes when a slot frees
// ============================================================================

test('queue drain: a paused running step is requeued and its dead assignment retired', async t => {
  const { storage } = makeStore(t)
  const { runId, assetIds } = await setupApprovedRun(storage)
  const run = storage.run(runId)
  const step = storage.addChainStep(run, {
    title: 'Investigate items resource',
    hypothesis: 'Probe the named route for a differential.',
    targetAssetIds: assetIds,
    sourceOrigins: [origin],
  })
  storage.updateChainStep(step.id, { status: 'running' })
  const worker = storage.makeWorker(run, 'investigation', undefined, step.title, step.hypothesis, { stepId: step.id })
  storage.updateWorker(worker.id, { status: 'paused' })

  const recovered = requeueInterruptedAssignments(storage, run)
  assert.equal(recovered, 1, 'the paused assignment is drained exactly once')

  const after = storage.listChainSteps(runId).find(s => s.id === step.id)!
  assert.equal(after.status, 'ready', 'the step is dispatchable again')
  assert.equal(after.assignedWorkerId, null, 'the dead assignment no longer owns the step')
  assert.equal(storage.worker(worker.id).status, 'canceled')

  const drained = storage.eventsAfter(runId, 0, 50).filter(event => event.kind === 'worker.requeued')
  assert.equal(drained.length, 1)
  assert.equal(drained[0].detail?.stepId, step.id)

  // Idempotent: a second drain finds nothing to recover and does not double-count.
  assert.equal(requeueInterruptedAssignments(storage, run), 0)
})

test('queue drain: a live running assignment is not stolen by the drain', async t => {
  const { storage } = makeStore(t)
  const { runId, assetIds } = await setupApprovedRun(storage)
  const run = storage.run(runId)
  const step = storage.addChainStep(run, {
    title: 'Investigate live resource',
    hypothesis: 'Probe the named route.',
    targetAssetIds: assetIds,
    sourceOrigins: [origin],
  })
  storage.updateChainStep(step.id, { status: 'running' })
  const worker = storage.makeWorker(run, 'investigation', undefined, step.title, step.hypothesis, { stepId: step.id })
  storage.updateWorker(worker.id, { status: 'running' })
  assert.equal(requeueInterruptedAssignments(storage, run), 0)
  assert.equal(storage.worker(worker.id).status, 'running')
})
