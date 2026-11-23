/**
 * v6 Phase-B starvation fix: split the single shared request budget into a Phase-A (deterministic
 * floor) allowance and a Phase-B (agentic investigation) allowance.
 *
 * The measured failure: at K=6 the stale hardcoded 2,000-request run budget was spent by the floor
 * alone (~1,500-1,800), leaving ~10-25 requests per agentic assignment. These tests pin:
 *  - duration-scaled defaults (600 s → 6k/25k/31k, 45 min → 12k/100k/112k) and explicit overrides;
 *  - `--budget-requests` / `--max-rps` plumbing (the old 2,000 literal is gone);
 *  - phase accounting (no borrowing in either direction);
 *  - a floor that exhausts its own allowance never stops the agent phase;
 *  - an exhausted agent allowance stops dispatch and ends as `agent_budget_exhausted`, not as a
 *    generic wall-clock stop;
 *  - meta/summary ingestion of both budgets and their measured consumption;
 *  - the legacy single-budget path (no split options/env) is unchanged.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  DEFAULT_AGENT_REQUEST_BUDGET,
  DEFAULT_FLOOR_REQUEST_BUDGET,
  DEFAULT_MAX_RPS,
  defaultRequestBudgets,
  parseRealisticArgs,
  summarizeRequestBudgets,
} from '../scripts/benchmark-realistic.ts'
import {
  Execution,
  resolvePhaseRequestBudgets,
} from '../src/server/execution.ts'
import type { ChainStep, Run } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

type PhaseInternals = {
  beginFloorRequestPhase: (run: Run) => { floorBudget: number; agentBudget: number } | null
  beginAgentRequestPhase: (run: Run) => { floorBudget: number; agentBudget: number } | null
  settleFloorRequestPhase: (runId: string, reason: string) => void
  phaseRequestRemaining: (run: Run) => number | null
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
  recordFloorMetrics: (runId: string, reason: string) => void
}

function internals(execution: Execution): PhaseInternals {
  return execution as unknown as PhaseInternals
}

function withSpend(storage: ReturnType<typeof makeStore>['storage'], runId: string, spentRequests: number): Run {
  storage.updateRun(runId, { spentRequests })
  return storage.run(runId)
}

// ---------------------------------------------------------------------------------------------
// Duration-scaled defaults / flags / env
// ---------------------------------------------------------------------------------------------

test('budget split: defaults scale 600 s → 6k/25k/31k and 45 min → 12k/100k/112k', () => {
  assert.equal(DEFAULT_FLOOR_REQUEST_BUDGET, 6_000)
  assert.equal(DEFAULT_AGENT_REQUEST_BUDGET, 25_000)

  assert.deepEqual(defaultRequestBudgets(600_000), { floor: 6_000, agent: 25_000, total: 31_000 })
  assert.deepEqual(defaultRequestBudgets(2_700_000), { floor: 12_000, agent: 100_000, total: 112_000 })

  const short = parseRealisticArgs(['--max-duration-ms', '600000'], {})
  assert.equal(short.floorRequestBudget, 6_000)
  assert.equal(short.agentRequestBudget, 25_000)
  assert.equal(short.totalRequestBudget, 31_000)
  assert.equal(short.budgetUsd, 5, '600 s agentic default is $5')
  assert.equal(short.maxRps, 50, 'lab rate cap is 50 RPS by default')

  const long = parseRealisticArgs(['--max-duration-ms', '2700000'], {})
  assert.equal(long.floorRequestBudget, 12_000)
  assert.equal(long.agentRequestBudget, 100_000)
  assert.equal(long.totalRequestBudget, 112_000)
  assert.equal(long.budgetUsd, 10, '45 min default is $10')
})

test('budget split: explicit flags and env override the scaled defaults', () => {
  const flags = parseRealisticArgs([
    '--max-duration-ms', '600000',
    '--floor-request-budget', '900',
    '--agent-request-budget', '2400',
    '--budget-requests', '3300',
  ], {})
  assert.equal(flags.floorRequestBudget, 900)
  assert.equal(flags.agentRequestBudget, 2_400)
  assert.equal(flags.totalRequestBudget, 3_300)

  const alias = parseRealisticArgs([
    '--floor-request-budget', '900',
    '--agent-request-budget', '2400',
    '--total-request-budget', '5000',
  ], {})
  assert.equal(alias.totalRequestBudget, 5_000, '--total-request-budget stays as an alias')

  assert.throws(() => parseRealisticArgs([
    '--budget-requests', '5000', '--total-request-budget', '4000',
  ], {}), /either --budget-requests or --total-request-budget/)

  const env = parseRealisticArgs([], {
    GUARDIAN_FLOOR_REQUEST_BUDGET: '700',
    GUARDIAN_AGENT_REQUEST_BUDGET: '2100',
    GUARDIAN_TOTAL_REQUEST_BUDGET: '3000',
  })
  assert.equal(env.floorRequestBudget, 700)
  assert.equal(env.agentRequestBudget, 2_100)
  assert.equal(env.totalRequestBudget, 3_000)

  const flagWins = parseRealisticArgs(['--agent-request-budget', '1500'], {
    GUARDIAN_AGENT_REQUEST_BUDGET: '2100',
  })
  assert.equal(flagWins.agentRequestBudget, 1_500)
})

test('budget split: --max-rps plumbs a hard rate cap (flag > env > default)', () => {
  assert.equal(DEFAULT_MAX_RPS, 50)
  assert.equal(parseRealisticArgs([], {}).maxRps, 50)
  assert.equal(parseRealisticArgs(['--max-rps', '40'], {}).maxRps, 40)
  assert.equal(parseRealisticArgs([], { GUARDIAN_MAX_RPS: '35' }).maxRps, 35)
  assert.equal(parseRealisticArgs(['--max-rps', '20'], { GUARDIAN_MAX_RPS: '35' }).maxRps, 20)
  assert.throws(() => parseRealisticArgs(['--max-rps', '0'], {}), /--max-rps/)
  assert.throws(() => parseRealisticArgs(['--max-rps', '500'], {}), /--max-rps/)
})

test('budget split: the stale hardcoded 2,000 run budget is gone from the harness', () => {
  const source = readFileSync(new URL('../scripts/benchmark-realistic.ts', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /budgetRequests:\s*2_?000\b/, 'no stale 2,000 request budget literal')
  const runBudgets = source.match(/budgetRequests:\s*args\.totalRequestBudget/g) ?? []
  assert.equal(runBudgets.length, 2, 'createRun and scope both use the configurable total')
})

test('budget split: invalid values fail fast', () => {
  assert.throws(() => parseRealisticArgs(['--floor-request-budget', '0'], {}), /--floor-request-budget/)
  assert.throws(() => parseRealisticArgs(['--agent-request-budget', '-1'], {}), /--agent-request-budget/)
  assert.throws(() => parseRealisticArgs(['--budget-requests', 'nope'], {}), /--budget-requests/)
  assert.throws(
    () => parseRealisticArgs([], { GUARDIAN_TOTAL_REQUEST_BUDGET: 'nope' }),
    /--budget-requests/,
  )
})

test('budget split: engine resolver is opt-in (legacy path stays off without options/env)', () => {
  assert.equal(resolvePhaseRequestBudgets({}, {}), null)
  assert.deepEqual(
    resolvePhaseRequestBudgets({ floorRequestBudget: 10, agentRequestBudget: 20 }, {}),
    { floor: 10, agent: 20 },
  )
  assert.deepEqual(
    resolvePhaseRequestBudgets({}, { GUARDIAN_AGENT_REQUEST_BUDGET: '25' }),
    { floor: DEFAULT_FLOOR_REQUEST_BUDGET, agent: 25 },
    'a single configured phase fills the other with its default',
  )
})

// ---------------------------------------------------------------------------------------------
// Phase accounting: no borrowing in either direction
// ---------------------------------------------------------------------------------------------

test('budget split: floor exhaustion freezes Phase A and leaves Phase B its full allowance', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 31_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage, { floorRequestBudget: 6_000, agentRequestBudget: 25_000 })
  t.after(() => execution.stop())
  const phase = internals(execution)

  phase.beginFloorRequestPhase(storage.run(runId))
  withSpend(storage, runId, 6_000)
  phase.settleFloorRequestPhase(runId, 'test')

  assert.equal(
    phase.phaseRequestRemaining(storage.run(runId)),
    25_000,
    'Phase B keeps its full allowance even though Phase A is fully exhausted',
  )
})

test('budget split: Phase B cannot borrow unused Phase-A allowance', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 31_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage, { floorRequestBudget: 10_000, agentRequestBudget: 500 })
  t.after(() => execution.stop())
  const phase = internals(execution)

  phase.beginFloorRequestPhase(storage.run(runId))
  withSpend(storage, runId, 10) // floor used only 10 of its 10,000 requests
  phase.settleFloorRequestPhase(runId, 'test')
  assert.equal(phase.phaseRequestRemaining(storage.run(runId)), 500, 'agent allowance is not the leftover')

  withSpend(storage, runId, 510) // 500 agent requests are gone
  assert.equal(phase.phaseRequestRemaining(storage.run(runId)), 0)
})

// ---------------------------------------------------------------------------------------------
// Phase B honoring: dispatch stops only on the agent allowance
// ---------------------------------------------------------------------------------------------

function addReadyStep(storage: ReturnType<typeof makeStore>['storage'], run: Run): ChainStep {
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const assetIds = run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.id)
  const step = storage.addChainStep(run, {
    title: 'Route authorization differential',
    hypothesis: 'Cross-persona read differential on the named route.',
    category: 'broken-access-control',
    priority: 60,
    targetAssetIds: assetIds,
    sourceOrigins: [origin],
  } as never)
  storage.updateChainStep(step.id, { status: 'ready' })
  return storage.listChainSteps(run.id, run.goalRevision).find(candidate => candidate.id === step.id)!
}

test('budget split: exhausted floor does not stop agent dispatch', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 31_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  addReadyStep(storage, storage.run(runId))

  const execution = new Execution(storage, {
    floorRequestBudget: 6_000,
    agentRequestBudget: 25_000,
    deterministicSweep: false,
  })
  t.after(() => execution.stop())
  const phase = internals(execution)
  const dispatched: string[] = []
  phase.startInvestigationStep = (_run, step) => { dispatched.push(step.id) }

  // Simulate a floor that spent its whole allowance before Phase B begins.
  phase.beginFloorRequestPhase(storage.run(runId))
  withSpend(storage, runId, 6_000)
  phase.settleFloorRequestPhase(runId, 'test')

  phase.driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(dispatched.length, 1, 'agent dispatch proceeds with its own allowance intact')
  assert.equal(storage.run(runId).phase, 'investigation')
})

test('budget split: agent cap stops dispatch and ends as agent_budget_exhausted', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 31_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  addReadyStep(storage, storage.run(runId))

  const execution = new Execution(storage, {
    floorRequestBudget: 6_000,
    agentRequestBudget: 50,
    deterministicSweep: false,
  })
  t.after(() => execution.stop())
  const phase = internals(execution)
  const dispatched: string[] = []
  phase.startInvestigationStep = (_run, step) => { dispatched.push(step.id) }

  // No floor lane: Phase B adopts the run at its baseline.
  phase.driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(dispatched.length, 1, 'the first assignment is dispatched')

  // Spend the entire agent allowance while a ready step remains.
  withSpend(storage, runId, 100)
  phase.driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])

  assert.equal(dispatched.length, 1, 'no further dispatch once the agent allowance is gone')
  assert.equal(storage.run(runId).phase, 'verification', 'phase hands off honestly instead of waiting for the wall clock')

  const exhausted = storage.eventsAfter(runId, 0, 500).filter(event => event.kind === 'request_budget.agent_exhausted')
  assert.equal(exhausted.length, 1, 'agent exhaustion is reported exactly once')
  const detail = exhausted[0]!.detail as Record<string, unknown>
  assert.equal(detail.reason, 'agent_budget_exhausted')
  assert.equal(detail.agentRequestBudget, 50)

  const summary = storage.eventsAfter(runId, 0, 500)
    .filter(event => event.kind === 'deterministic_floor.summary').at(-1)
  assert.ok(summary, 'phase 3 records the floor summary')
  const summaryDetail = summary!.detail as Record<string, unknown>
  assert.equal(summaryDetail.terminationReason, 'agent_budget_exhausted')
  assert.equal(summaryDetail.agentRequestBudget, 50)
  assert.equal(summaryDetail.agentBudgetExhausted, true)
  assert.equal(summaryDetail.floorRequestBudget, 6_000)
  assert.equal(typeof summaryDetail.floorRequests, 'number')
  assert.equal(typeof summaryDetail.agentRequests, 'number')
})

// ---------------------------------------------------------------------------------------------
// Legacy single-budget path
// ---------------------------------------------------------------------------------------------

test('budget split: legacy single-budget path reports one shared allowance', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 2_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const phase = internals(execution)

  assert.equal(phase.beginFloorRequestPhase(storage.run(runId)), null, 'no split state in legacy mode')
  withSpend(storage, runId, 750)
  assert.equal(phase.phaseRequestRemaining(storage.run(runId)), 1_250, 'legacy is one shared remainder')

  phase.recordFloorMetrics(runId, 'test')
  const legacy = storage.eventsAfter(runId, 0, 500)
    .filter(event => event.kind === 'deterministic_floor.summary').at(-1)
  assert.ok(legacy)
  const detail = legacy!.detail as Record<string, unknown>
  assert.equal(detail.requestBudgetMode, 'single')
  assert.equal(detail.floorRequestBudget, null)
  assert.equal(detail.agentRequestBudget, null)
  assert.equal(detail.totalRequestBudget, 2_000)
})

// ---------------------------------------------------------------------------------------------
// Ingested telemetry (meta / certify-facing shape)
// ---------------------------------------------------------------------------------------------

test('budget split: meta ingestion reports both budgets and measured consumption', () => {
  const events = [
    { kind: 'request_budget.phase_started', detail: { floorRequestBudget: 6_000, agentRequestBudget: 25_000 } },
    { kind: 'deterministic_engine.summary', detail: { requestsUsed: 1_500, confirmed: 9 } },
    { kind: 'request_budget.floor_settled', detail: { floorRequests: 1_640, floorBudgetExhausted: false } },
    { kind: 'request_budget.phase_ended', detail: { agentRequests: 24_995, agentBudgetExhausted: true } },
    { kind: 'request_budget.agent_exhausted', detail: { reason: 'agent_budget_exhausted', agentRequests: 25_000 } },
  ]
  const meta = summarizeRequestBudgets({
    events,
    spentRequests: 26_640,
    floorRequestBudget: 6_000,
    agentRequestBudget: 25_000,
    totalRequestBudget: 31_000,
  })
  assert.equal(meta.mode, 'split')
  assert.equal(meta.floorRequests, 1_640, 'settled measured delta wins over the engine-reported sum')
  assert.equal(meta.floorRequestBudget, 6_000)
  assert.equal(meta.agentRequests, 25_000)
  assert.equal(meta.agentRequestBudget, 25_000)
  assert.equal(meta.totalRequestBudget, 31_000)
  assert.equal(meta.totalRequests, 26_640)
  assert.equal(meta.agentBudgetExhausted, true)
  assert.equal(meta.terminationReason, 'agent_budget_exhausted')
})

test('budget split: wall-stopped Phase B ingests its spend from the floor settle event', () => {
  const meta = summarizeRequestBudgets({
    events: [
      { kind: 'request_budget.floor_settled', detail: { floorRequests: 1_242, spentRequestsAtSettle: 1_300 } },
    ],
    spentRequests: 2_396,
    floorRequestBudget: 6_000,
    agentRequestBudget: 25_000,
    totalRequestBudget: 31_000,
  })
  assert.equal(meta.mode, 'split')
  assert.equal(meta.floorRequests, 1_242)
  assert.equal(meta.agentRequests, 1_096, 'no phase_ended event yet, so the settle delta is used')
  assert.equal(meta.agentBudgetExhausted, false)
  assert.equal(meta.terminationReason, null)
})

test('budget split: legacy artifacts without phase events still ingest the engine-reported floor', () => {
  const meta = summarizeRequestBudgets({
    events: [{ kind: 'deterministic_engine.summary', detail: { requestsUsed: 1_161 } }],
    spentRequests: 1_900,
  })
  assert.equal(meta.mode, 'single')
  assert.equal(meta.floorRequests, 1_161)
  assert.equal(meta.agentRequests, null, 'legacy events cannot attribute Phase-B spend')
  assert.equal(meta.floorRequestBudget, null)
})
