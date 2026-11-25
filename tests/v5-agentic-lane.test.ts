/**
 * v5.1 Slice 3 — concurrent deterministic lane + agentic value-add contracts.
 *
 * These tests pin the invariants from plans/ROADMAP-v5.md:
 *  - default OFF means zero lane traffic;
 *  - a pre-Phase-0 seeded step set skips the lane (unless deterministicSweep === 'always');
 *  - the lane is a sibling task (dispatch is never blocked, no specialist semaphore slot);
 *  - dynamicStepBudget is never written by the lane and K=6 is never reset by engine facts;
 *  - multi-trial early stop and step statuses are untouched;
 *  - aborting the lane settles before Phase 3 (verification) is committed;
 *  - typed proof handlers compile + verify through the inline verifier and return repair blocks;
 *  - tracing is off by default and emits checkpoint/planner/lifecycle records when enabled.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import { readTrace } from '../src/server/agent-trace.ts'
import { proveAuthzReadDiff, validateProofInput } from '../src/server/proof-tools.ts'
import { verifierRepairFeedback, withVerifierRepairFeedback } from '../src/server/agent-session.ts'
import {
  computeDynamicStepBudget,
  countConsecutiveDrySteps,
  diminishingReturnsDryThreshold,
  Execution,
  resolveDeterministicSweepMode,
} from '../src/server/execution.ts'
import type { ChainStep, Run } from '../src/server/store.ts'
import type { CompiledProof } from '../src/server/proof-tools.ts'
import { makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

type LaneOptions = {
  lane?: boolean
  signal?: AbortSignal
  maxDurationMs?: number
  onAssignment?: (assignmentId: string) => void
}

type Internals = {
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  startDeterministicLane: (run: Run, profiles: readonly unknown[]) => void
  advanceToVerification: (run: Run) => void
  runEngineInvestigation: (run: Run, opts?: LaneOptions) => Promise<void>
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
  cancelSiblingTrialsOnConfirmation: (run: Run, winningStepId: string | null, findingId?: string) => void
  ensureRunTrace: (run: Run, profiles?: readonly unknown[]) => { dir: string; closeTrace: () => unknown } | null
  traceLifecycle: (runId: string, kind: 'lane_start' | 'lane_end' | 'checkpoint' | 'verdict' | 'abort', payload?: Record<string, unknown>) => void
  tracePlannerDecision: (runId: string, payload: Record<string, unknown>) => void
  notifyCheckpoint: (runId: string, checkpoint: 'phase0' | 'deterministic-lane' | 'post-floor' | 'planner-round') => void
  specialistWallClockMs: (maxTurns: number) => number
  alreadyConfirmedRefs: (run: Run, limit?: number) => Array<{ path: string; method?: string | null; cwe?: string | null }>
  detLeadSummaries: (run: Run) => Array<{ probeClass: string }>
  assignmentBriefForStep: (input: Record<string, unknown>) => string | undefined
  executeInlineVerification: (input: Record<string, unknown>) => Promise<unknown>
  buildGrant: (job: unknown, run: Run, origins: ReadonlySet<string>) => { grant: unknown; currentSecrets: () => unknown[] }
  prePhase0SeededSteps: Map<string, boolean>
  agenticLaneJobs: Map<string, { controller: AbortController; assignmentId: string }>
  agenticLaneAssignmentIds: Set<string>
  deterministicLaneDeadlineMs: () => number
}

function internals(execution: Execution): Internals {
  return execution as unknown as Internals
}

function laneKey(run: Run): string {
  return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
}

async function startRun(t: Parameters<typeof makeStore>[0], opts: { concurrency?: number } = {}) {
  const { dir, storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 500 })
  if (opts.concurrency !== undefined) {
    storage.client.prepare('UPDATE runs SET worker_concurrency = ? WHERE id = ?').run(opts.concurrency, runId)
  }
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { dir, storage, runId }
}

function addStep(storage: ReturnType<typeof makeStore>['storage'], run: Run, overrides: Partial<Parameters<typeof storage.addChainStep>[1]> = {}): ChainStep {
  const assetIds = run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.id)
  const origin = run.candidates.find(c => run.approved.includes(c.id))?.origin ?? 'http://127.0.0.1:9'
  const step = storage.addChainStep(run, {
    title: overrides.title ?? 'BOLA matrix probe',
    hypothesis: overrides.hypothesis ?? 'Cross-persona read differential on the invoice route.',
    category: overrides.category ?? 'broken-access-control',
    priority: overrides.priority ?? 60,
    targetAssetIds: overrides.targetAssetIds ?? assetIds,
    sourceOrigins: overrides.sourceOrigins ?? [origin],
    ...overrides,
  })
  storage.updateChainStep(step.id, { status: 'ready' })
  return step
}

/** Lane stub: records start and resolves only when the lane signal aborts (or after `settleAfterAbortMs`). */
function stubLane(execution: Execution, settleAfterAbortMs = 0) {
  const calls: Array<{ maxDurationMs?: number; signal?: AbortSignal; settledAt?: number }> = []
  let dispatchedBeforeLaneSettled = false
  internals(execution).runEngineInvestigation = async (_run, opts = {}) => {
    const call: { maxDurationMs?: number; signal?: AbortSignal; settledAt?: number } = {
      maxDurationMs: opts.maxDurationMs,
      signal: opts.signal,
    }
    calls.push(call)
    opts.onAssignment?.('lane-assignment')
    await new Promise<void>(resolve => {
      const settle = () => {
        if (settleAfterAbortMs > 0) setTimeout(resolve, settleAfterAbortMs)
        else resolve()
      }
      if (opts.signal?.aborted) settle()
      else opts.signal?.addEventListener('abort', settle, { once: true })
    })
    call.settledAt = Date.now()
    if (!dispatchedBeforeLaneSettled) dispatchedBeforeLaneSettled = true
  }
  return { calls, wasDispatchBeforeLaneSettled: () => dispatchedBeforeLaneSettled }
}

test('deterministicSweep resolves from option/env and defaults OFF', () => {
  assert.equal(resolveDeterministicSweepMode(undefined, {}), 'off')
  assert.equal(resolveDeterministicSweepMode(false, {}), 'off')
  assert.equal(resolveDeterministicSweepMode(true, {}), 'on')
  assert.equal(resolveDeterministicSweepMode('always', {}), 'always')
  assert.equal(resolveDeterministicSweepMode(undefined, { KOVO_DETERMINISTIC_SWEEP: '1' }), 'on')
  assert.equal(resolveDeterministicSweepMode(undefined, { KOVO_DETERMINISTIC_SWEEP: 'always' }), 'always')
  assert.equal(resolveDeterministicSweepMode(undefined, { KOVO_DETERMINISTIC_SWEEP: '0' }), 'off')
})

test('flag OFF: zero lane traffic and no lane events', async (t) => {
  const { storage, runId } = await startRun(t, { concurrency: 2 })
  const run = storage.run(runId)
  const execution = new Execution(storage, { deterministicSweep: false })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  const dispatched: string[] = []
  internals(execution).startInvestigationStep = (_r, step) => { dispatched.push(step.id) }
  const lane = stubLane(execution)

  addStep(storage, run)
  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])

  assert.equal(lane.calls.length, 0, 'flag OFF must never start the lane')
  assert.equal(internals(execution).agenticLaneJobs.size, 0)
  assert.equal(dispatched.length, 1, 'specialist dispatch still happens with the flag OFF')
  assert.equal(storage.eventsAfter(runId, 0).filter(e => e.kind.startsWith('deterministic_lane.')).length, 0)
})

test('seeded pre-Phase-0 steps skip the lane; "always" bypasses the guard', async (t) => {
  const { storage, runId } = await startRun(t, { concurrency: 2 })
  const run = storage.run(runId)
  addStep(storage, run)

  const guarded = new Execution(storage, { deterministicSweep: true })
  t.after(() => guarded.stop())
  internals(guarded).prePhase0SeededSteps.set(laneKey(run), true)
  internals(guarded).startInvestigationStep = () => undefined
  const guardedLane = stubLane(guarded)
  internals(guarded).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(guardedLane.calls.length, 0, 'pre-seeded steps must suppress the lane')

  const forced = new Execution(storage, { deterministicSweep: 'always' })
  t.after(() => forced.stop())
  internals(forced).prePhase0SeededSteps.set(laneKey(run), true)
  internals(forced).startInvestigationStep = () => undefined
  const forcedLane = stubLane(forced)
  internals(forced).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(forcedLane.calls.length, 1, '"always" is the explicit operator override')
  internals(forced).advanceToVerification(storage.run(runId))
  await delay(20)
})

test('missing pre-Phase-0 record is conservative: lane skipped on resumed runs', async (t) => {
  const { storage, runId } = await startRun(t, { concurrency: 2 })
  const run = storage.run(runId)
  addStep(storage, run)
  const execution = new Execution(storage, { deterministicSweep: true })
  t.after(() => execution.stop())
  internals(execution).startInvestigationStep = () => undefined
  const lane = stubLane(execution)
  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(lane.calls.length, 0)
})

test('flag ON: Phase A runs first (sequential) and gates specialist dispatch', async (t) => {
  const { storage, runId } = await startRun(t, { concurrency: 2 })
  const run = storage.run(runId)
  addStep(storage, run)
  const execution = new Execution(storage, { deterministicSweep: true, maxDurationMs: 600_000 })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  const dispatched: string[] = []
  internals(execution).startInvestigationStep = (_r, step) => { dispatched.push(step.id) }
  const lane = stubLane(execution)
  const deadline = internals(execution).deterministicLaneDeadlineMs()

  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])

  assert.equal(lane.calls.length, 1)
  assert.equal(dispatched.length, 0, 'agents wait for the phase-A floor to settle')
  assert.equal(lane.calls[0].maxDurationMs, deadline, 'Phase A deadline = min(180 s, 28% × maxDurationMs)')
  assert.equal(deadline, 168_000)
  // Zero chain-step cancellation and no confirmed-route hiding.
  const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  assert.ok(steps.every(step => step.status !== 'canceled'), 'the floor must not cancel specialist steps')

  await internals(execution).advanceToVerification(storage.run(runId))
  await delay(20)
  assert.ok(lane.calls[0].settledAt, 'floor abort settled before finalize')
})

test('lane never writes dynamicStepBudget and aborting it settles before Phase 3', async (t) => {
  const { storage, runId } = await startRun(t, { concurrency: 2 })
  const run = storage.run(runId)
  addStep(storage, run)
  storage.updateRunDynamicStepBudget(runId, 77)
  const computedBefore = computeDynamicStepBudget(storage, runId)
  const execution = new Execution(storage, { deterministicSweep: true })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  internals(execution).startInvestigationStep = () => undefined
  const lane = stubLane(execution, 60)

  internals(execution).startDeterministicLane(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(lane.calls.length, 1)
  assert.equal(storage.run(runId).dynamicStepBudget, 77, 'lane must never write dynamicStepBudget')
  assert.equal(computeDynamicStepBudget(storage, runId), computedBefore)

  const pending = internals(execution).advanceToVerification
  assert.equal(typeof pending, 'function')
  internals(execution).advanceToVerification(storage.run(runId))
  await delay(20)
  assert.equal(storage.run(runId).phase, 'investigation', 'Phase 3 must wait for the lane to settle')
  await delay(120)
  assert.ok(['verification', 'complete'].includes(storage.run(runId).phase), 'finalize commits after the lane settles')
  assert.ok(lane.calls[0].settledAt, 'abort settled before the verification phase committed')
  const kinds = storage.eventsAfter(runId, 0).map(e => e.kind)
  assert.ok(kinds.indexOf('deterministic_lane.aborting') >= 0)
  assert.ok(kinds.indexOf('verification.started') > kinds.indexOf('deterministic_lane.aborting'))
})

test('K=6 dry-streak still halts and engine facts never reset it', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  const assignment = storage.makeWorker(run, 'investigation', run.candidates[0], 'lane worker', 'lane worker')
  const claimed = storage.updateWorker(assignment.id, { status: 'running', lease: randomUUID() })!
  for (let i = 0; i < diminishingReturnsDryThreshold; i += 1) {
    const step = addStep(storage, run, { title: `Dry step ${i}`, category: 'misconfig-exposure' })
    storage.updateChainStep(step.id, { status: 'complete', assignedWorkerId: claimed.id })
  }
  // A deterministic fact attributed to the lane worker would previously count as productivity.
  storage.addFact(run, claimed, {
    kind: 'note',
    origin: run.candidates[0].origin,
    summary: 'Engine lead',
    data: { kind: 'det_lead', source: 'deterministic_engine', probeClass: 'authz_matrix', endpoint: '/api/x', method: 'GET' },
  })
  const current = storage.run(runId)
  assert.equal(
    countConsecutiveDrySteps(storage, current),
    diminishingReturnsDryThreshold,
    'engine facts must not reset the K=6 streak (default call)',
  )
  assert.equal(countConsecutiveDrySteps(storage, current, new Set([claimed.id])), diminishingReturnsDryThreshold)

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(current), true)
  internals(execution).startInvestigationStep = () => undefined
  ;(internals(execution) as unknown as Record<string, unknown>).schedulePlanner = () => undefined
  const lane = stubLane(execution)
  internals(execution).driveInvestigation(current, [{ id: 'profile', model: 'mock' }])
  assert.equal(lane.calls.length, 0, 'seeded guard also applies to the dry-streak case')
  await delay(10)
  assert.equal(storage.run(runId).phase, 'investigation', 'a dry streak never kills the sweep in v6')
  const kinds = storage.eventsAfter(runId, 0).map(e => e.kind)
  assert.ok(kinds.includes('planner.dry_streak'))
  assert.ok(!kinds.includes('planner.diminishing_returns'))
})

test('multi-trial fanout/early-stop machinery is untouched by the lane', async (t) => {
  const { storage, runId } = await startRun(t, { concurrency: 3 })
  const run = storage.run(runId)
  addStep(storage, run, { title: 'Crown-jewel authz probe', priority: 95 })
  const execution = new Execution(storage, { deterministicSweep: true })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)
  internals(execution).startInvestigationStep = () => undefined
  stubLane(execution)

  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  const afterFanout = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  const trials = afterFanout.filter(step => step.trialGroupId)
  assert.equal(trials.length, 2, 'priority >= 88 still fans out to 2 trials before the lane starts')
  const group = trials[0].trialGroupId

  // Early stop still cancels the sibling when the winner confirms.
  internals(execution).cancelSiblingTrialsOnConfirmation(storage.run(runId), trials[0].id, 'finding-winner')
  const finalSteps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  const losing = finalSteps.find(step => step.trialGroupId === group && step.id !== trials[0].id)
  assert.equal(losing?.status, 'canceled')
  await internals(execution).advanceToVerification(storage.run(runId))
})

test('proof handler compiles a typed spec and verification failures carry repair blocks', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  // Invalid input is rejected before the handler is called (compiler validation).
  const invalid = validateProofInput('prove_authz_read_diff', { origin })
  assert.equal(invalid.ok, false)
  if (!invalid.ok) {
    assert.ok(invalid.errors.length > 0)
    assert.ok(invalid.errors.every(error => typeof error.fix === 'string' && error.fix.length > 0))
  }

  const proof: CompiledProof = proveAuthzReadDiff({
    origin,
    ownerPersona: 'owner',
    attackerPersona: 'attacker',
    endpoint: '/api/invoices/{resourceId}',
    resourceId: 'inv_9f3c2b71',
    identifierPath: 'data.id',
  })
  assert.equal(proof.spec.kind, 'http_chain')

  // The retired `submitProofSpec` compiler path is gone (M0 Cut 1); verification feedback is now
  // surfaced by `withVerifierRepairFeedback`, which must attach a structured repair block to a
  // failing outcome and must leave a confirmed outcome byte-identical.
  const feedback: InlineVerifyFeedback = {
    verdict: 'inconclusive',
    controlPassed: false,
    assertionSummary: { observed: 'probe missing identifier', expected: 'attacker denied', reason: 'identifier not echoed' },
    stepStatuses: [{ id: 'probe', role: 'probe', status: 200, bodyLen: 12 }],
    retriesRemaining: 2,
  }
  const failing = withVerifierRepairFeedback({
    findingId: 'finding-proof-1',
    replaySpecId: 'spec-1',
    status: 'inconclusive',
    ...feedback,
  }) as Record<string, unknown>
  const repair = verifierRepairFeedback(failing)
  assert.ok(repair, 'failed verification must return a structured repair block')
  assert.equal(repair!.failedRule, 'verdict:inconclusive')
  assert.ok(typeof repair!.suggestedFix === 'string' && String(repair!.suggestedFix).length > 0)

  const confirmed = { findingId: 'finding-proof-2', status: 'confirmed', verdict: 'confirmed', controlPassed: true }
  assert.deepEqual(withVerifierRepairFeedback(confirmed), confirmed)
})

test('occurred context builders: confirmed refs, leads and <=1.5 KB assignment brief', async (t) => {
  const { storage, runId } = await startRun(t)
  const run = storage.run(runId)
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const assignment = storage.makeWorker(run, 'investigation', run.candidates[0], 'ctx', 'ctx')
  const claimed = storage.updateWorker(assignment.id, { status: 'running', lease: randomUUID() })!
  storage.addFact(run, claimed, {
    kind: 'note',
    origin,
    summary: 'lead',
    data: { kind: 'det_lead', source: 'deterministic_engine', probeClass: 'authz_matrix', endpoint: '/api/invoices/:id', method: 'GET' },
  })
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const leads = internals(execution).detLeadSummaries(storage.run(runId))
  assert.equal(leads[0]?.probeClass, 'authz_matrix')

  const step = addStep(storage, storage.run(runId))
  const brief = internals(execution).assignmentBriefForStep({
    run: storage.run(runId),
    step,
    targetOrigins: [origin],
    personas: [{ handle: 'owner', roleLabel: 'customer' }],
    parentFacts: [],
    confirmed: [],
    detLeads: leads,
    maxTurns: 9,
  })
  assert.ok(brief)
  assert.ok(Buffer.byteLength(brief!, 'utf8') <= 1536)
  assert.ok(brief!.includes(origin))

  assert.equal(internals(execution).specialistWallClockMs(9), 80_000)
  assert.ok(internals(execution).specialistWallClockMs(30) <= 160_000)
})

test('tracing is OFF by default and emits lifecycle/planner/checkpoint records when enabled', async (t) => {
  const { storage, runId } = await startRun(t)
  const cleanEnv = { KOVO_TRACE: undefined, KOVO_TRACE_DIR: undefined, KOVO_TRACE_ROOT: undefined }

  await withEnv(cleanEnv, () => {
    const execution = new Execution(storage)
    t.after(() => execution.stop())
    assert.equal(internals(execution).ensureRunTrace(storage.run(runId)), null, 'trace is off by default')
  })

  const traceRoot = mkdtempSync(join(tmpdir(), 'kovo-trace-'))
  await withEnv({ KOVO_TRACE: '1', KOVO_TRACE_ROOT: traceRoot }, () => {
    const execution = new Execution(storage)
    t.after(() => execution.stop())
    const trace = internals(execution).ensureRunTrace(storage.run(runId), [{ model: 'mock-model' }])
    assert.ok(trace)
    internals(execution).traceLifecycle(runId, 'lane_start', { deadlineMs: 240_000 })
    internals(execution).tracePlannerDecision(runId, {
      roundIdx: 1, factsCount: 12, detLeadsCount: 3, alreadyConfirmedCount: 2,
      spawnedSteps: 1, k6DryStreak: 0, dynamicStepBudget: 40, durationMs: 12, costUsd: 0.001,
    })
    internals(execution).notifyCheckpoint(runId, 'post-floor')
    trace!.closeTrace()

    const read = readTrace(trace!.dir)
    assert.equal(read.issues.length, 0)
    assert.ok(read.events.some(event => event.type === 'lifecycle' && event.kind === 'lane_start'))
    assert.ok(read.events.some(event => event.type === 'lifecycle' && event.kind === 'checkpoint'))
    assert.ok(read.events.some(event => event.type === 'planner_decision'))
    assert.equal(read.manifest?.model, 'mock-model')
  })
})
