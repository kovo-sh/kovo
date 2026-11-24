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
  GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
  GUARDIAN_VERIFY_SPEC_SHAPE,
  formatReplaySpecValidationIssues,
  guardianVerifyHelperGuidance,
  guardianVerifyPromptHint,
} from '../src/server/agent-session.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { findings as findingsTable } from '../src/server/schema.ts'
import { eq } from 'drizzle-orm'
import { classesCompatible } from '../benchmarks/realism-suite/lib/grade.ts'
import { classCompatible } from '../benchmarks/realistic-bench/grader/match.ts'
import {
  CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS,
  CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS,
  DRY_ROUND_LIMIT,
  Execution,
  MULTI_STEP_ASSIGNMENT_MAX_TURNS,
  MULTI_STEP_ASSIGNMENT_MIN_TURNS,
  PROVIDER_STALL_ABORT_FLOOR_MS,
  REINVESTIGATION_CAP,
  ReinvestigationGuard,
  SINGLE_STEP_ASSIGNMENT_MAX_TURNS,
  SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS,
  coordinatorSchedulerDecision,
  detLeadUnlocksReinvestigation,
  isMultiStepAssignment,
  planAssignmentBudget,
  providerStallAbortMs,
  reinvestigationKey,
  shouldRetryStalledAssignment,
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
    maxTurns: 18,
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

// ============================================================================
// 6. Spec-shape first-try guidance + exact repair feedback
// ============================================================================

test('guardian_verify guidance carries the required DeclarativeReplaySpec shape', () => {
  const hint = guardianVerifyPromptHint()
  assert.ok(hint.includes(GUARDIAN_VERIFY_SPEC_SHAPE))
  for (const required of ['severityRationale', 'steps[]', 'description', 'request{origin', 'request.persona']) {
    assert.ok(hint.includes(required), `prompt hint names ${required}`)
  }
  const guidance = guardianVerifyHelperGuidance()
  assert.ok(guidance.includes('severityRationale'))
  assert.ok(
    Buffer.byteLength(guidance, 'utf8') <= GUARDIAN_VERIFY_HELPER_GUIDANCE_MAX_BYTES,
    'helper guidance stays inside its prompt budget',
  )
})

test('schema rejection names the exact missing field and repeats the required shape', () => {
  const parsed = declarativeReplaySpecSchema.safeParse({
    version: 1,
    origin: ORIGIN,
    title: 'Missing severity rationale',
    category: 'injection',
    cwe: 'CWE-89',
    severity: 'high',
  })
  assert.equal(parsed.success, false)
  const text = formatReplaySpecValidationIssues(parsed.error!.issues)
  assert.match(text, /Missing required field\(s\): .*spec\.severityRationale/, 'the missing top-level field is named')
  assert.match(text, /spec\.steps/, 'the missing steps array is named')
  assert.ok(text.includes('Required shape: '), 'the repair turn repeats the full shape')
  assert.ok(text.includes('severityRationale'))

  // Step-level fields are named too (description / request.origin).
  const stepParsed = declarativeReplaySpecSchema.safeParse({
    version: 1,
    origin: ORIGIN,
    title: 'Step shape',
    category: 'injection',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'Differential evidence shows injection.',
    impact: 'An attacker can read rows.',
    remediation: 'Parameterize the query.',
    recheckInstructions: 'Replay the same probe.',
    assertionsJq: '.probe.status == 200',
    steps: [{ id: 'probe', role: 'probe', request: { method: 'GET', pathAndQuery: '/api/items/1' } }],
  })
  assert.equal(stepParsed.success, false)
  const stepText = formatReplaySpecValidationIssues(stepParsed.error!.issues)
  assert.match(stepText, /spec\.steps\.0\.description: missing required field/)
  assert.match(stepText, /spec\.steps\.0\.request\.origin: missing required field/)
})

// ============================================================================
// 7. Turn cap: single-step is 18 (raised from 12 after the held-out turn-limit audit); race/multi-step/chain get 20–30
// ============================================================================

test('race and multi-step assignments get 20–30 turns; single-step stays bounded at 18', () => {
  const single = planAssignmentBudget({
    routes: ['/api/items/:id'],
    parentEvidenceIds: [],
    dependsOnStepIds: [],
    baseMaxTurns: 25,
    baseWallClockMs: 160_000,
  })
  assert.equal(single.kind, 'single_step')
  assert.equal(single.maxTurns, SINGLE_STEP_ASSIGNMENT_MAX_TURNS)
  assert.equal(single.wallClockMs, SINGLE_STEP_ASSIGNMENT_WALL_CLOCK_MS)

  const race = planAssignmentBudget({
    routes: ['/api/orders/:id'],
    parentEvidenceIds: [],
    dependsOnStepIds: [],
    multiStep: true,
    baseMaxTurns: 25,
    baseWallClockMs: 160_000,
  })
  assert.equal(race.kind, 'chain', 'multi-step keeps the long wall cap')
  assert.ok(race.maxTurns >= MULTI_STEP_ASSIGNMENT_MIN_TURNS && race.maxTurns <= MULTI_STEP_ASSIGNMENT_MAX_TURNS)
  assert.ok(race.maxTurns >= 20, 'a 20–29 turn race worker is no longer truncated at 12')
  assert.ok(race.wallClockMs >= CHAIN_ASSIGNMENT_MIN_WALL_CLOCK_MS)
  assert.ok(race.wallClockMs <= CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS)
  assert.equal(race.settlementTurn, race.maxTurns - 2)

  const chain = planAssignmentBudget({
    routes: ['/a', '/b'],
    parentEvidenceIds: ['fact-1'],
    dependsOnStepIds: [],
    baseMaxTurns: 40,
    baseWallClockMs: 200_000,
  })
  assert.equal(chain.kind, 'chain')
  assert.ok(chain.maxTurns >= 20 && chain.maxTurns <= 34)
  assert.ok(chain.wallClockMs <= CHAIN_ASSIGNMENT_MAX_WALL_CLOCK_MS)

  assert.equal(isMultiStepAssignment({ skills: ['bola-idor-race'] }), true)
  assert.equal(isMultiStepAssignment({
    title: 'det_lead upgrade · authz_matrix PATCH /v3/admin/users/:id',
    skills: ['bola-idor-race', 'false-positive-elimination'],
  }), false)
  assert.equal(isMultiStepAssignment({ title: 'Cross-persona BOLA/IDOR matrix' }), true)
  assert.equal(isMultiStepAssignment({ title: 'det_lead upgrade · authz_matrix PATCH /v3/admin/users/:id', category: 'broken-access-control' }), false)
  assert.equal(
    isMultiStepAssignment({
      title: 'det_lead upgrade · sqli_boolean POST /api/orders/:id',
      hypothesis: 'Reproduce it and chain it into a higher-impact finding.',
      category: 'injection',
      skills: ['injection-sqli-nosqli', 'false-positive-elimination'],
    }),
    false,
    'det_lead prose mentioning "chain" is still a single-step assignment',
  )
})

// ============================================================================
// 8. Provider-stall watchdog: one bounded requeue + exposed metrics
// ============================================================================

test('the stall watchdog retries once and exposes providerStallTurns/Retries', async t => {
  assert.equal(shouldRetryStalledAssignment(0), true)
  assert.equal(shouldRetryStalledAssignment(1), false, 'one requeue only')
  assert.equal(shouldRetryStalledAssignment(2), false)
  assert.equal(providerStallAbortMs(0, 0), 90_000, 'cold streams get the long floor')
  assert.ok(providerStallAbortMs(2_000, 10) >= PROVIDER_STALL_ABORT_FLOOR_MS)

  const { storage } = makeStore(t, 'guardian-v7-brief-stall-db-')
  const { runId } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  internals(execution).providerStallTurnsByRun.set(runId, 3)
  internals(execution).providerStallRetriesByRun.set(runId, 1)
  internals(execution).recordAssignmentMetrics(runId, 'test')
  const metrics = execution.getAssignmentThroughput(runId)
  assert.ok(metrics, 'throughput metrics are readable')
  assert.equal(metrics!.providerStallTurns, 3)
  assert.equal(metrics!.providerStallRetries, 1)
  const event = storage.eventsAfter(runId, 0, 500).find(e => e.kind === 'agentic.assignment_metrics')
  assert.ok(event, 'metrics are mirrored into a run event')
  assert.equal((event!.detail as Record<string, unknown>).providerStallRetries, 1)
})

// ============================================================================
// 9. Receipt findings carry the canonical vulnClass (Realism #2 audit)
// ============================================================================

test('async SSRF/XXE receipt findings use the canonical category and match truth', async t => {
  const { storage } = makeStore(t, 'guardian-v7-receipt-category-db-')
  const { run, runId, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const carrier = storage.recordExchange({
    runId,
    assignmentId: assignment.id,
    scopeRevision: run.scopeRevision,
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method: 'POST',
    pathAndQuery: '/api/preview',
    personaHandle: 'anonymous',
    status: 200,
    mediaType: 'text/plain',
    reqHeaders: {},
    respHeaders: {},
    body: 'ok',
    durationMs: 5,
  })

  const cases = [
    { vulnClass: 'ssrf' as const, cwe: 'CWE-918', truthClass: 'ssrf_internal_fetch', family: 'ssrf' },
    { vulnClass: 'xxe' as const, cwe: 'CWE-611', truthClass: 'xxe_callback', family: 'xxe' },
  ] as const
  for (const entry of cases) {
    const persisted = internals(execution).persistReceiptFinding(storage.run(runId), {
      vulnClass: entry.vulnClass,
      origin: ORIGIN,
      param: 'url',
      carrier,
      receipt: { oobEventIds: [`evt-${entry.vulnClass}`] },
      verification: {
        confirmed: true,
        vulnClass: entry.vulnClass,
        rule: 'oob',
        reason: 'canary callback observed after the response',
        observed: 'callback',
        expected: 'callback',
      },
      subscriptionId: `sub-${entry.vulnClass}`,
    })
    assert.equal(persisted, true, `${entry.vulnClass} receipt becomes a confirmed finding`)

    const finding = storage.db.select().from(findingsTable)
      .where(eq(findingsTable.runId, runId)).all()
      .map(row => row.finding)
      .find(row => row.cwe === entry.cwe)
    assert.ok(finding, `${entry.vulnClass} finding is persisted`)
    assert.equal(finding!.category, entry.vulnClass, 'category is the canonical vulnClass, not an OWASP bucket')
    assert.equal(finding!.cwe, entry.cwe, 'CWE is unchanged')
    assert.equal(finding!.verificationTier, 'runtime_confirmed')

    // Both graders see the canonical category as compatible with the truth class.
    assert.equal(classesCompatible(entry.truthClass, finding!.category), true)
    assert.equal(classCompatible(
      { vulnClass: entry.vulnClass, cwe: finding!.cwe },
      { vulnClass: entry.family, cwe: entry.cwe },
    ), true)
  }
})
