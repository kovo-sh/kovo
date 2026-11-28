/**
 * v6 Phase 4 coordinator wiring tests (plans/better-architecture.md §3.3), updated for Track B Cut 2.
 *
 * The tool-equipped paginated coordinator session and heuristic chain-round synthesizer are retired
 * in favour of the World Graph + single-turn planner; what remains verified here: the lossy
 * `ColdGraphCompactor` / `CrossHostSynthesizer` stay deleted, dispatch validation preserves ordered
 * parent evidence, and the deterministic `decideNext()` guard owns termination (budget / requests /
 * wall clock / K=2 empty rounds / done + pending OOB).
 */
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  EMPTY_PLANNER_ROUND_LIMIT,
  decideNext,
  dispatchInvestigations,
  type DispatchStepInput,
} from '../src/server/graph-coordinator.ts'
import {
  collectAllPages,
  coordinatorSchedulerDecision,
} from '../src/server/execution.ts'

test('a 2-hop chain fixture produces two ordered dispatches', () => {
  const order = ['https://app.local', 'https://admin.local']
  const steps: DispatchStepInput[] = [
    {
      hypothesis: 'leaked_token → admin_route chain — Replay the leaked credential against the role-exclusive route.',
      origins: order, capabilities: ['http'], parentEvidenceIds: ['fact-secret', 'ep-admin'],
      probeClass: 'authz_replay', skills: ['chain:leaked_token', 'chain:admin_route'], priority: 86,
    },
    {
      hypothesis: 'discovered_id → stored_write chain — Persist the marker then read it as another principal.',
      origins: ['https://app.local'], capabilities: ['http', 'browser'], parentEvidenceIds: ['fact-object', 'fact-stored'],
      probeClass: 'bola_idor', skills: ['chain:discovered_id', 'chain:stored_write'], priority: 78,
    },
  ]
  const plan = dispatchInvestigations(steps, { approvedOrigins: order, maxSteps: 2 })
  assert.deepEqual(plan.plan.map(step => step.id), ['dispatch-1', 'dispatch-2'])
  assert.deepEqual(plan.plan.map(step => step.origins), [order, ['https://app.local']])
  const dispatch = plan.plan[0]
  assert.deepEqual(dispatch.parentEvidenceIds, ['fact-secret', 'ep-admin'], 'ordered parent evidence is preserved')
  assert.deepEqual(dispatch.capabilities, ['http'])
  assert.ok(plan.plan.every(step => step.parentEvidenceIds.length > 0), 'every dispatch cites parent evidence')
})

test('deterministic scheduler stops on budget, requests, wall clock, K=2 empty rounds, and done+pending_oob', () => {
  const now = Date.now()
  const base = { budgetExhausted: false, budgetRequests: 100, spentRequests: 10, startedAt: now, maxDurationMs: 60_000 }
  const wallBase = { ...base, startedAt: now - 61_000 }

  assert.equal(coordinatorSchedulerDecision({ ...base, budgetExhausted: true }).reason, 'budget_exhausted')
  assert.equal(coordinatorSchedulerDecision({ ...base, spentRequests: 100 }).reason, 'requests_exhausted')
  assert.equal(coordinatorSchedulerDecision(wallBase).reason, 'wallclock_exhausted')
  assert.equal(coordinatorSchedulerDecision({ ...base, emptyRounds: EMPTY_PLANNER_ROUND_LIMIT }).reason, 'diminishing_returns')
  assert.equal(coordinatorSchedulerDecision({ ...base, emptyRounds: EMPTY_PLANNER_ROUND_LIMIT - 1 }).decision, 'continue')
  assert.equal(coordinatorSchedulerDecision({ ...base, coordinatorDone: true, pendingOob: 2 }).decision, 'continue')
  assert.equal(coordinatorSchedulerDecision({ ...base, coordinatorDone: true, pendingOob: 0 }).reason, 'coordinator_done')
  assert.equal(coordinatorSchedulerDecision(base).decision, 'continue')
})

test('K=6 halt semantics are preserved by decideNext diminishing returns (K=2), not an in-LLM stop', () => {
  assert.equal(EMPTY_PLANNER_ROUND_LIMIT, 2)
  assert.equal(decideNext({ consecutiveEmptyPlannerRounds: 1 }).decision, 'continue')
  assert.equal(decideNext({ consecutiveEmptyPlannerRounds: 2 }).reason, 'diminishing_returns')
  const source = readFileSync(new URL('../src/server/execution.ts', import.meta.url), 'utf8')
  assert.ok(!/consecutiveDrySteps\s*>=/.test(source), 'no duplicated in-LLM dry-streak stop')
})

test('ColdGraphCompactor, CrossHostSynthesizer and the heuristic chain-round synthesizer are deleted from the tree', () => {
  assert.equal(existsSync(new URL('../src/server/compactor.ts', import.meta.url)), false)
  const source = readFileSync(new URL('../src/server/execution.ts', import.meta.url), 'utf8')
  assert.ok(!source.includes('ColdGraphCompactor'), 'compactor symbol removed')
  assert.ok(!source.includes('CrossHostSynthesizer'), 'cross-host synthesizer removed')
  assert.ok(!source.includes('runCrossHostSynthesizer'), 'cross-host call site removed')
  assert.ok(source.includes('decideNext'), 'deterministic scheduler guard is wired')
  assert.ok(!source.includes('chainHypothesisDispatchSteps'), 'legacy chain-round dispatch is retired')
  assert.ok(!source.includes('dispatchChainRound'), 'legacy chain-round wrapper is retired')
  const collect = collectAllPages((offset, limit) => Array.from({ length: Math.max(0, 1200 - offset) }, (_, i) => offset + i).slice(0, limit), 500)
  assert.equal(collect.length, 1200)
})
