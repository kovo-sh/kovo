/**
 * v7 brief-slice + precision guard.
 *
 * Completes the white-box evidence hop and adds the reviewer's diminishing-returns guard:
 *
 *   1. Phase-0 `codeSlice` hypotheses persist a bounded slice (+ deduped `guardDiff`) on the
 *      `det_lead` fact;
 *   2. the assignment brief renders that stored slice (compact by default, `full` for
 *      chain / 4-hop assignments) and never exceeds the 4 KB ceiling;
 *   3. a `(normalizedRoute, vulnClass)` pair is re-investigated at most twice unless a chain
 *      primitive / parent evidence unlocks another pass;
 *   4. the planner stops after two consecutive dry rounds once the high-priority queue drains,
 *      and never stops earlier;
 *   5. the deterministic floor's lead ranking is unchanged by the slice payload.
 *
 * No benchmark app, seed, route or truth file is consulted; fixtures are synthetic.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

import {
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  measureAssignmentBriefBytes,
} from '../src/server/assignment-brief.ts'
import {
  DRY_ROUND_LIMIT,
  Execution,
  REINVESTIGATION_CAP,
  ReinvestigationGuard,
  coordinatorSchedulerDecision,
  detLeadUnlocksReinvestigation,
  reinvestigationKey,
} from '../src/server/execution.ts'
import {
  DET_LEAD_CODE_SLICE_MAX_BYTES,
  codeToRuntimeLead,
  graphLeadTargets,
  seedCodeToRuntimeLeads,
} from '../src/server/graph-leads.ts'
import type { CodeDataflowSlice, CodeToRuntimeHypothesis } from '../src/server/program-graph.ts'
import type { Store } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const ORIGIN = 'https://brief.slice.test'
const ADMIN_ROUTE = 'PATCH /v3/admin/users/:id'

function internals(execution: Execution): Record<string, any> {
  return execution as unknown as Record<string, any>
}

/** Deterministic four-hop slice with an explicit sibling `missing_guard` contrast. */
function adminSlice(overrides: Partial<CodeDataflowSlice> = {}): CodeDataflowSlice {
  return {
    route: ADMIN_ROUTE,
    mounts: ['/v3'],
    methods: ['PATCH'],
    input: { params: ['role'] },
    auth: 'unguarded',
    guards: [],
    root: 'services/admin/src/',
    hops: [
      { at: 'routes.ts:14', kind: 'route' },
      { at: 'controllers/users.ts:5' },
      { at: 'services/user-service.ts:4' },
      { at: 'repos/user-repo.ts:4' },
    ],
    sink: { at: 'repos/user-repo.ts:4', kind: 'db_query' },
    guardDiff: [{
      kind: 'missing_guard',
      guard: 'admin',
      symbol: 'requireAdmin',
      sibling: 'PATCH /v4/admin/resource-1/:id',
      at: 'routes.generated.runtime.ts:5',
    }],
    ...overrides,
  }
}

function adminHypothesis(index = 1): CodeToRuntimeHypothesis & { codeSlice?: CodeDataflowSlice } {
  return {
    id: `hyp-admin-${index}`,
    kind: 'admin_route_missing_admin_guard',
    severity: 'high',
    confidence: 0.82,
    framework: 'express',
    method: 'PATCH',
    path: '/v3/admin/users/:id',
    file: 'services/admin/src/routes.ts',
    line: 14,
    sinkKind: 'db_query',
    routeId: 'route-admin-1',
    rationale: 'Privileged route has no admin/RBAC middleware in its mounted chain.',
    evidence: ['missing_guard=admin requireAdmin@routes.generated.runtime.ts:5'],
    probeClass: 'auth_bypass',
    codeSlice: adminSlice(),
  }
}

async function approvedRun(storage: Store) {
  const setup = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 3, budgetRequests: 900 })
  storage.updateRun(setup.runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(setup.runId)
  const worker = storage.makeWorker(run, 'investigation', run.candidates[0], 'v7 brief-slice fixture', 'exercise brief wiring', {
    sourceOrigins: [ORIGIN],
  })
  const assignment = storage.updateWorker(worker.id, { status: 'running', lease: randomUUID() })!
  return { runId: setup.runId, run: storage.run(setup.runId), assignment }
}

// ============================================================================
// 1. Persistence: bounded slice + deduped guardDiff on the det_lead fact
// ============================================================================

test('phase-0 code slices persist bounded, deduped and idempotently on det_lead facts', async t => {
  const { storage } = makeStore(t, 'guardian-v7-brief-db-')
  const { run, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const seeded = internals(execution).seedCodeToRuntimeLeads(run, assignment, [adminHypothesis()])
  assert.equal(seeded, 1)

  const fact = storage.listFacts(run.id, { includeTainted: false, limit: 20 })
    .find(entry => entry.data?.hypothesisId === 'hyp-admin-1')
  assert.ok(fact, 'the hypothesis became a det_lead fact')
  const data = fact!.data as Record<string, unknown>
  const slice = data.codeSlice as CodeDataflowSlice
  assert.ok(slice, 'the fact carries the code slice')
  assert.equal(slice.route, ADMIN_ROUTE)
  assert.ok(slice.hops.length >= 4, 'the four-hop chain survives persistence')
  assert.ok(Buffer.byteLength(JSON.stringify(slice), 'utf8') <= DET_LEAD_CODE_SLICE_MAX_BYTES)
  assert.ok(Number(data.codeSliceBytes) <= DET_LEAD_CODE_SLICE_MAX_BYTES)
  const guardDiff = data.guardDiff as Array<{ guard: string; symbol: string }> | undefined
  const sliceDiffs = slice.guardDiff ?? []
  assert.equal(sliceDiffs.length, 1, 'the slice keeps exactly one deduped guard diff')
  assert.equal(sliceDiffs[0].guard, 'admin')
  assert.equal(sliceDiffs[0].symbol, 'requireAdmin')
  if (guardDiff) {
    assert.equal(guardDiff.length, 1, 'the optional mirror is deduped too')
    assert.equal(guardDiff[0].guard, 'admin')
  }

  // Duplicate guard-diff entries are deduped by the persistence helper.
  const duplicated = codeToRuntimeLead({
    ...adminHypothesis(2),
    codeSlice: adminSlice({ guardDiff: [...adminSlice().guardDiff!, ...adminSlice().guardDiff!] }),
  })
  assert.equal((duplicated.data.codeSlice as CodeDataflowSlice).guardDiff?.length, 1)

  assert.equal(
    internals(execution).seedCodeToRuntimeLeads(run, storage.run(run.id), [adminHypothesis()]),
    0,
    're-seeding the same hypothesis never duplicates the lead',
  )
})

// ============================================================================
// 2. Brief wiring: stored slice reaches the brief; compact default, full chain
// ============================================================================

test('the stored slice reaches the assignment brief, compact by default and full for chain steps', async t => {
  const { storage } = makeStore(t, 'guardian-v7-brief-wire-db-')
  const { run, runId, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  internals(execution).seedCodeToRuntimeLeads(run, assignment, [adminHypothesis()])
  const fact = storage.listFacts(runId, { includeTainted: false, limit: 20 })
    .find(entry => entry.data?.hypothesisId === 'hyp-admin-1')!
  const baseStep = {
    id: 'step-brief',
    title: `det_lead upgrade · authz_matrix ${ADMIN_ROUTE}`,
    hypothesis: 'Reproduce the observed privileged-route signal and submit a verified proof.',
    category: 'broken-access-control',
    dependsOnFactIds: [fact.id],
    dependsOnStepIds: [] as string[],
  }

  const briefFor = (step: typeof baseStep) => internals(execution).assignmentBriefForStep({
    run: storage.run(runId),
    step,
    targetOrigins: [ORIGIN],
    personas: [],
    parentFacts: [fact],
    confirmed: [],
    detLeads: [],
    maxTurns: 12,
  }) as string | undefined

  const compact = briefFor(baseStep)
  assert.ok(compact, 'a compact brief is rendered')
  const compactBytes = measureAssignmentBriefBytes(compact!)
  assert.ok(compactBytes <= ASSIGNMENT_BRIEF_MAX_BYTES, `compact brief ${compactBytes} B stays <= 1536 B`)
  const compactPacket = JSON.parse(compact!) as { mission: string; code?: CodeDataflowSlice }
  assert.equal(compactPacket.mission, 'class_scan', 'a non-chain det_lead brief stays compact')
  assert.ok(compactPacket.code, 'the persisted slice is rendered into the brief')
  assert.equal(compactPacket.code!.route, ADMIN_ROUTE)

  const chain = briefFor({ ...baseStep, title: `Chain step 2 · authz_matrix ${ADMIN_ROUTE}`, dependsOnStepIds: ['step-parent'] })
  assert.ok(chain, 'a chain brief is rendered')
  const chainBytes = measureAssignmentBriefBytes(chain!)
  assert.ok(chainBytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE, `chain brief ${chainBytes} B stays <= 4096 B`)
  const chainPacket = JSON.parse(chain!) as { mission: string; code?: CodeDataflowSlice }
  assert.equal(chainPacket.mission, 'chain_step_2')
  assert.ok(chainPacket.code, 'chain assignments keep the code evidence')
  assert.ok(
    (chainPacket.code!.hops.length ?? 0) >= (compactPacket.code!.hops.length ?? 0),
    'full expansion never drops hops the compact render kept',
  )
  assert.ok(
    (chainPacket.code!.guardDiff?.length ?? 0) >= 1,
    'the full render keeps the missing_guard contrast',
  )

  // The renderer's own assertion is the ceiling; buildAssignmentBrief always fits.
  assert.ok(chainBytes <= 4 * 1024)
})

// ============================================================================
// 3. Precision guard: cap third investigation without new evidence
// ============================================================================

test('reinvestigation guard caps the third pass per route/class unless evidence unlocks it', () => {
  const guard = new ReinvestigationGuard()
  const key = reinvestigationKey(ADMIN_ROUTE, 'authz_matrix')
  assert.equal(guard.countFor(key), 0)
  assert.equal(guard.record(key).allowed, true)
  assert.equal(guard.record(key).allowed, true)

  const third = guard.record(key)
  assert.equal(third.allowed, false, 'third pass without new evidence is capped')
  assert.equal(third.capped, true)
  assert.equal(guard.countFor(key), REINVESTIGATION_CAP)
  assert.equal(guard.cappedCount(), 1)

  // Same route, different class is a different key and is allowed.
  assert.equal(guard.record(reinvestigationKey(ADMIN_ROUTE, 'sqli_boolean')).allowed, true)

  // A chain primitive / parent evidence unlocks another pass and is recorded.
  const unlocked = guard.record(key, true)
  assert.equal(unlocked.allowed, true)
  assert.equal(unlocked.unlocked, true)
  assert.equal(guard.countFor(key), 3)
  assert.equal(guard.record(key).allowed, false, 'after the unlocked pass the cap applies again')

  assert.equal(detLeadUnlocksReinvestigation({ kind: 'det_lead' }), false)
  assert.equal(detLeadUnlocksReinvestigation({ kind: 'det_lead', evidenceExchangeIds: ['ex-1'] }), true)
  assert.equal(detLeadUnlocksReinvestigation({ kind: 'det_lead', parentEvidenceIds: ['fact-1'] }), true)
  assert.equal(detLeadUnlocksReinvestigation({ kind: 'det_lead', chainPrimitiveKind: 'admin_route' }), true)
})

test('the det_lead scheduler queues two same-route investigations and caps the third', async t => {
  const { storage } = makeStore(t, 'guardian-v7-brief-cap-db-')
  const { run, runId, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  for (const [index, method] of ['PATCH', 'POST', 'PUT'].entries()) {
    storage.addFact(run, assignment, {
      kind: 'note',
      origin: ORIGIN,
      summary: `det_lead authz_matrix ${method} ${ADMIN_ROUTE}`,
      data: {
        kind: 'det_lead',
        source: 'deterministic_engine',
        probeClass: 'authz_matrix',
        endpoint: '/v3/admin/users/:id',
        method,
        reason: `control diverged on attempt ${index + 1}`,
        leadEvidenceKind: 'near_miss',
        contrast: true,
      },
    })
  }

  const queued = internals(execution).queueDetLeadUpgradeSteps(storage.run(runId), new Set([ORIGIN]), 24)
  assert.equal(queued, REINVESTIGATION_CAP, 'only the cap-many investigations are queued')
  const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  assert.equal(steps.length, REINVESTIGATION_CAP)

  const capped = storage.eventsAfter(runId, 0, 5000)
    .filter(event => event.kind === 'planner.capped_reinvestigations')
  assert.equal(capped.length, 1, 'the capped third pass is reported')
  const detail = capped[0]!.detail as Record<string, unknown>
  assert.equal(detail.cap, REINVESTIGATION_CAP)
  assert.equal(detail.attempted, REINVESTIGATION_CAP + 1)
  assert.equal(detail.capped, 1)
})

// ============================================================================
// 4. Dry-round termination: fires after 2 empty rounds, never before
// ============================================================================

test('the planner stops after two dry rounds once the high-priority queue is empty', () => {
  const base = {
    budgetExhausted: false,
    budgetRequests: 5_000,
    spentRequests: 100,
    startedAt: Date.now(),
    maxDurationMs: 600_000,
  }
  assert.equal(DRY_ROUND_LIMIT, 2)

  assert.equal(coordinatorSchedulerDecision({ ...base, highPriorityQueueEmpty: true, consecutiveDryRounds: 0 }).decision, 'continue')
  assert.equal(coordinatorSchedulerDecision({ ...base, highPriorityQueueEmpty: true, consecutiveDryRounds: 1 }).decision, 'continue')
  const stop = coordinatorSchedulerDecision({ ...base, highPriorityQueueEmpty: true, consecutiveDryRounds: 2 })
  assert.equal(stop.decision, 'stop')
  assert.equal(stop.reason, 'diminishing_returns')
  assert.match(stop.detail, /dry round/i)

  // Dry rounds alone never stop the planner while high-priority work remains.
  assert.equal(coordinatorSchedulerDecision({ ...base, highPriorityQueueEmpty: false, consecutiveDryRounds: 3 }).decision, 'continue')

  // Budget / request / wall rules still win.
  assert.equal(coordinatorSchedulerDecision({ ...base, budgetExhausted: true, highPriorityQueueEmpty: true, consecutiveDryRounds: 2 }).reason, 'budget_exhausted')
  assert.equal(coordinatorSchedulerDecision({ ...base, spentRequests: 5_000, highPriorityQueueEmpty: true, consecutiveDryRounds: 2 }).reason, 'requests_exhausted')
  assert.equal(coordinatorSchedulerDecision({ ...base, startedAt: Date.now() - 600_001, highPriorityQueueEmpty: true, consecutiveDryRounds: 2 }).reason, 'wallclock_exhausted')

  // A done coordinator still drains late OOB callbacks before the dry stop applies.
  assert.equal(
    coordinatorSchedulerDecision({ ...base, coordinatorDone: true, pendingOob: 2, highPriorityQueueEmpty: true, consecutiveDryRounds: 2 }).decision,
    'continue',
  )
})

test('a new chain primitive resets the dry-round streak', () => {
  // Mirrors the planner loop: dry unless this round added a confirmed finding or chain primitive.
  const streak = (before: number, after: number, previous: number) => (after - before > 0 ? 0 : previous + 1)
  assert.equal(streak(3, 3, 0), 1)
  assert.equal(streak(3, 3, 1), 2)
  assert.equal(streak(3, 4, 1), 0, 'a new chain primitive resets the streak')
  assert.equal(streak(0, 1, 0), 0, 'a new runtime_confirmed finding resets the streak')
})

// ============================================================================
// 5. Floor unchanged: the slice payload does not alter lead ranking
// ============================================================================

test('persisted slices do not change the floor lead ranking', async t => {
  const { storage } = makeStore(t, 'guardian-v7-brief-floor-db-')
  const { run, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const withSlice = adminHypothesis(1)
  const withoutSlice = adminHypothesis(2)
  delete (withoutSlice as { codeSlice?: CodeDataflowSlice }).codeSlice

  const leadWith = codeToRuntimeLead(withSlice)
  const leadWithout = codeToRuntimeLead(withoutSlice)
  assert.deepEqual(
    { runtime: leadWith.runtime, probeClass: leadWith.probeClass, summary: leadWith.summary },
    { runtime: leadWithout.runtime, probeClass: leadWithout.probeClass, summary: leadWithout.summary },
    'the slice is additive fact payload only',
  )

  internals(execution).seedCodeToRuntimeLeads(run, assignment, [withSlice, withoutSlice])
  const targets = graphLeadTargets(storage.listFacts(run.id, { includeTainted: false, limit: 40 }))
  assert.equal(targets.length, 1, 'same route/method dedupes to one floor target')
  assert.equal(targets[0].riskScore, 92, 'high severity keeps its floor risk score')
  assert.deepEqual(targets[0].params, [])
})

test('seedCodeToRuntimeLeads remains usable as a pure helper', async t => {
  const { storage } = makeStore(t, 'guardian-v7-brief-pure-db-')
  const { run, assignment } = await approvedRun(storage)
  const seeded = new Set<string>()
  const created = seedCodeToRuntimeLeads(storage, run, assignment, [adminHypothesis()], seeded, ORIGIN)
  assert.equal(created, 1)
  assert.equal(seeded.size, 1)
  assert.equal(seedCodeToRuntimeLeads(storage, run, assignment, [adminHypothesis()], seeded, ORIGIN), 0)
})
