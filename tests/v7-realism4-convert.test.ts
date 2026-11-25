/**
 * v7 Realism #4 — Tier-A 4-hop dispatch and proof grounding.
 *
 * Pins the in-lease conversion contract without a benchmark app, seed or truth file:
 *
 *   1. Program-Graph code-lead routes outrank generic schema-typed routes for the engine's bounded
 *      risk prefix (`prioritizeCodeLeadTargets`);
 *   2. a code-lead object route with no readable collection derives a bounded, deterministic set of
 *      concrete identifier-form reads from the target's own tenant labels
 *      (`deriveCodeLeadIdentifierTargets`) so the authz matrix has a real object to bind to;
 *   3. the assignment brief renders one explicit proof obligation (exact mounted route, parameter
 *      names, middleware verdict, sink expression, hop chain) inside the 4 KB ceiling and drops it
 *      — never the code evidence — under a tight cap;
 *   4. the deterministic-engine lane assignment carries the Program-Graph lead facts it consumes,
 *      so dispatch attribution is the hypothesis link, not a lucky route hit.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

import {
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBrief,
  measureAssignmentBriefBytes,
} from '../src/server/assignment-brief.ts'
import {
  CODE_LEAD_IDENTIFIER_FORMS_PER_ROUTE,
  CODE_LEAD_PRIORITY_RISK,
  Execution,
  TIER_A_STEP_PRIORITY,
  deriveCodeLeadIdentifierTargets,
  detLeadEvidenceGate,
  evaluateDispatchStop,
  passOneCoverage,
  planRoundRobinDispatch,
  prioritizeCodeLeadTargets,
  tenantLabelsFromRoleLabels,
} from '../src/server/execution.ts'
import { seedCodeToRuntimeLeads } from '../src/server/graph-leads.ts'
import { httpChainReplaySpecSchema } from '../src/replay-spec.ts'
import type { EngineHypothesis } from '../src/server/deterministic-engine.ts'
import { codeToRuntimeLead } from '../src/server/graph-leads.ts'
import type { CodeDataflowSlice, CodeToRuntimeHypothesis } from '../src/server/program-graph.ts'
import type { Store } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const ORIGIN = 'https://realism4.convert.test'
const ADMIN_ROUTE = 'PATCH /v3/admin/users/:id'

async function approvedRun(storage: Store) {
  const setup = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 3, budgetRequests: 900 })
  storage.updateRun(setup.runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(setup.runId)
  const worker = storage.makeWorker(run, 'investigation', run.candidates[0], 'v7 realism4 fixture', 'exercise 4-hop conversion', {
    sourceOrigins: [ORIGIN],
  })
  const assignment = storage.updateWorker(worker.id, { status: 'running', lease: randomUUID() })!
  return { runId: setup.runId, run: storage.run(setup.runId), assignment }
}

function internals(execution: Execution): Record<string, any> {
  return execution as unknown as Record<string, any>
}

function lead(
  method: string,
  pathTemplate: string,
  riskScore = 83,
): { origin: string; method: string; pathTemplate: string; riskScore: number; params: Array<{ name: string; location: string }> } {
  return { origin: ORIGIN, method, pathTemplate, riskScore, params: [] }
}

function adminSlice(): CodeDataflowSlice {
  return {
    route: ADMIN_ROUTE,
    mounts: ['/v3'],
    methods: ['PATCH'],
    input: { body: ['role'] },
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
  }
}

function adminHypothesis(): CodeToRuntimeHypothesis & { codeSlice?: CodeDataflowSlice } {
  return {
    id: 'hyp-realism4-admin',
    kind: 'admin_route_missing_admin_guard',
    severity: 'high',
    confidence: 0.82,
    framework: 'express',
    method: 'PATCH',
    path: '/v3/admin/users/:id',
    file: 'services/admin/src/routes.ts',
    line: 14,
    sinkKind: 'db_query',
    routeId: 'route-realism4-admin',
    rationale: 'Privileged route has no admin/RBAC middleware in its mounted chain.',
    evidence: ['missing_guard=admin requireAdmin@routes.generated.runtime.ts:5'],
    probeClass: 'auth_bypass',
    codeSlice: adminSlice(),
  }
}

// ============================================================================
// 1. Tier-A ordering: code leads outrank the generic surface
// ============================================================================

test('code-lead routes are raised above the generic risk prefix without mutating input', () => {
  const billing = lead('GET', '/v2/billing/invoices/:id', 88)
  const report = lead('GET', '/v2/reports/export', 80)
  const alreadyHigh = lead('PATCH', '/v3/admin/users/:id', 300)
  const input = [billing, report, alreadyHigh]

  const prioritized = prioritizeCodeLeadTargets(input)

  assert.equal(prioritized[2], alreadyHigh, 'a route already above the floor keeps its identity')
  assert.equal(prioritized[0]!.riskScore, CODE_LEAD_PRIORITY_RISK)
  assert.equal(prioritized[1]!.riskScore, CODE_LEAD_PRIORITY_RISK)
  assert.equal(billing.riskScore, 88, 'input objects are never mutated')
  assert.equal(prioritized[0]!.pathTemplate, billing.pathTemplate)
  assert.equal(prioritized[0]!.method, 'GET')
})

// ============================================================================
// 2. Identifier-form reads for a collection-less object route
// ============================================================================

test('identifier-form targets are bounded, GET-only, tenant-derived and deduped', () => {
  const targets = [
    lead('GET', '/v2/billing/invoices/:id', CODE_LEAD_PRIORITY_RISK),
    lead('GET', '/v2/reports/export', CODE_LEAD_PRIORITY_RISK),
    lead('PATCH', '/v3/admin/users/:id', CODE_LEAD_PRIORITY_RISK),
  ]
  const derived = deriveCodeLeadIdentifierTargets({
    targets,
    tenants: ['tenant-alpha', 'tenant-beta'],
    existing: [{ origin: ORIGIN, method: 'GET', pathTemplate: '/v2/health' }],
  })

  assert.equal(derived.length, CODE_LEAD_IDENTIFIER_FORMS_PER_ROUTE, 'one bounded form set per object route')
  assert.deepEqual(derived.map(target => target.pathTemplate), [
    '/v2/billing/invoices/inv-alpha-1',
    '/v2/billing/invoices/inv-alpha-2',
  ])
  assert.ok(derived.every(target => target.method === 'GET'), 'only benign reads are derived')
  assert.ok(derived.every(target => target.riskScore === CODE_LEAD_PRIORITY_RISK))
  assert.ok(derived.every(target => target.source === 'program_graph'))
  assert.ok(derived.every(target => target.params.length === 0), 'derived reads add no inferred params')

  const deduped = deriveCodeLeadIdentifierTargets({
    targets,
    tenants: ['tenant-alpha', 'tenant-beta'],
    existing: [derived[0]!],
  })
  assert.deepEqual(deduped.map(target => target.pathTemplate), ['/v2/billing/invoices/inv-alpha-2'])

  assert.equal(deriveCodeLeadIdentifierTargets({ targets, tenants: [], existing: [] }).length, 0)
  assert.equal(deriveCodeLeadIdentifierTargets({ targets, tenants: ['tenant-alpha'], existing: [], perRoute: 0 }).length, 0)
})

test('tenant labels are parsed from declared persona role labels', () => {
  assert.deepEqual(
    tenantLabelsFromRoleLabels([
      'member (tenant-alpha)',
      'admin (tenant-alpha)',
      'member (tenant-beta)',
      'service (no-tenant-label)',
      'member',
    ]),
    ['no-tenant-label', 'tenant-alpha', 'tenant-beta'],
  )
})

// ============================================================================
// 3. Brief proof obligation
// ============================================================================

test('the brief renders one explicit proof obligation inside the 4 KB ceiling', () => {
  const text = buildAssignmentBrief({
    missionKind: 'class_scan',
    origin: ORIGIN,
    routes: [{ method: 'PATCH', path: '/v3/admin/users/:id', params: ['id'] }],
    codeSlice: adminSlice(),
    proofObligation: {
      route: ADMIN_ROUTE,
      params: ['id', 'role'],
      auth: 'unguarded',
      sink: 'db_query@repos/user-repo.ts:4',
      chain: 'routes.ts:14→controllers/users.ts:5→services/user-service.ts:4→repos/user-repo.ts:4',
    },
    codeExpansion: 'full',
  })
  assert.ok(measureAssignmentBriefBytes(text) <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const packet = JSON.parse(text) as {
    proofObligation?: { route: string; params?: string[]; auth?: string; sink?: string; chain?: string }
    code?: CodeDataflowSlice
  }
  assert.equal(packet.proofObligation?.route, ADMIN_ROUTE, 'route keeps method + mounted path')
  assert.deepEqual(packet.proofObligation?.params, ['id', 'role'])
  assert.equal(packet.proofObligation?.auth, 'unguarded')
  assert.equal(packet.proofObligation?.sink, 'db_query@repos/user-repo.ts:4')
  assert.match(packet.proofObligation?.chain ?? '', /user-repo\.ts:4$/)
  assert.equal(packet.code?.route, ADMIN_ROUTE)
})

test('a tight cap drops the proof obligation, never the code evidence', () => {
  const text = buildAssignmentBrief({
    missionKind: 'class_scan',
    origin: ORIGIN,
    routes: [{ method: 'PATCH', path: '/v3/admin/users/:id', params: ['id'] }],
    codeSlice: adminSlice(),
    proofObligation: {
      route: ADMIN_ROUTE,
      params: ['id', 'role'],
      auth: 'unguarded',
      sink: 'db_query@repos/user-repo.ts:4',
      chain: 'routes.ts:14→controllers/users.ts:5→services/user-service.ts:4→repos/user-repo.ts:4',
    },
  }, 700)
  const packet = JSON.parse(text) as { proofObligation?: unknown; code?: CodeDataflowSlice }
  assert.ok(measureAssignmentBriefBytes(text) <= 900)
  assert.equal(packet.proofObligation, undefined)
  assert.equal(packet.code?.route, ADMIN_ROUTE, 'the dataflow slice survives the reduction ladder')
})

test('assignmentBriefForStep grounds a code-slice step in the exact route and sink chain', async t => {
  const { storage } = makeStore(t, 'kovo-v7-realism4-brief-')
  const { run, runId, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  internals(execution).seedCodeToRuntimeLeads(run, assignment, [adminHypothesis()])
  const fact = storage.listFacts(runId, { includeTainted: false, limit: 20 })
    .find(entry => entry.data?.hypothesisId === 'hyp-realism4-admin')!

  const brief = internals(execution).assignmentBriefForStep({
    run: storage.run(runId),
    step: {
      id: 'step-realism4',
      title: `det_lead upgrade · authz_matrix ${ADMIN_ROUTE}`,
      hypothesis: 'Reproduce the privileged-route signal and submit a verified proof.',
      category: 'broken-access-control',
      dependsOnFactIds: [fact.id],
      dependsOnStepIds: [] as string[],
    },
    targetOrigins: [ORIGIN],
    personas: [
      { handle: 'mono-alice', roleLabel: 'member (tenant-alpha)' },
      { handle: 'mono-bob', roleLabel: 'member (tenant-beta)' },
    ],
    parentFacts: [fact],
    confirmed: [],
    detLeads: [],
    maxTurns: 18,
  }) as string | undefined

  assert.ok(brief, 'the brief is rendered')
  assert.ok(measureAssignmentBriefBytes(brief!) <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const packet = JSON.parse(brief!) as {
    proofObligation?: {
      route: string; params?: string[]; auth?: string; sink?: string; chain?: string
      controlPersona?: string; variantPersona?: string; deliverable?: string
    }
  }
  assert.equal(packet.proofObligation?.route, ADMIN_ROUTE)
  assert.deepEqual(packet.proofObligation?.params, ['role'])
  assert.equal(packet.proofObligation?.auth, 'unguarded')
  assert.match(packet.proofObligation?.sink ?? '', /^db_query@.*user-repo\.ts/)
  assert.match(packet.proofObligation?.chain ?? '', /controllers\/users\.ts:5/)
  assert.equal(packet.proofObligation?.controlPersona, 'mono-alice')
  assert.equal(packet.proofObligation?.variantPersona, 'mono-bob', 'variant prefers another tenant')
  assert.match(packet.proofObligation?.deliverable ?? '', /kovo_verify\(prove_persisted_mutation\)/)
  assert.match(packet.proofObligation?.deliverable ?? '', /proofGapReason/)
})

// ============================================================================
// 4. Dispatch attribution
// ============================================================================

test('the engine lane assignment carries the Program-Graph lead facts it consumes', () => {
  // The attribution contract is the fact-id list the lane attaches before dispatch; this pins the
  // shape the funnel reads (`assignments.parent_fact_ids` → `det_lead` route).
  const leadData = codeToRuntimeLead(adminHypothesis()).data
  assert.equal(leadData.kind, 'det_lead')
  assert.equal(leadData.source, 'program_graph')
  assert.equal(leadData.method, 'PATCH')
  assert.equal(leadData.endpoint, '/v3/admin/users/:id')
})

// ============================================================================
// 5. Canonical proof synthesis (fallbacks retired)
// ============================================================================
// The two bounded fallback shapes (`buildCodeLeadCrossTenantProof`,
// `buildCodeLeadSqlErrorProof`) were deleted once `synthesizeEngineSpecs` rendered both signals
// canonically: the identity-scoped GET rule and the fingerprint-bound SQL error chain are pinned in
// `tests/v7-spec-authz.test.ts`, and the monorepo-whitebox 4-hop funnel confirms 3/3 through the
// product `Execution` path with no fallback.

// ============================================================================
// 6. Round-1 Tier-A seeding + dry-round guard + stop telemetry
// ============================================================================

test('a Program-Graph code slice is admissible lead evidence; a slice-less lead is not', () => {
  const admitted = detLeadEvidenceGate({
    kind: 'det_lead',
    source: 'program_graph',
    probeClass: 'authz_matrix',
    endpoint: '/v2/billing/invoices/:id',
    method: 'GET',
    codeSlice: { route: 'GET /v2/billing/invoices/:id', hops: [{ at: 'routes.ts:1' }] },
  })
  assert.equal(admitted.admitted, true)
  assert.equal(admitted.reason, 'code_dataflow_slice')
  assert.equal(detLeadEvidenceGate({ kind: 'det_lead', source: 'program_graph', probeClass: 'authz_matrix' }).admitted, false)
  assert.equal(detLeadEvidenceGate({ kind: 'det_lead', source: 'deterministic_engine', probeClass: 'authz_matrix' }).admitted, false)
})

test('Tier-A leads are dispatched before generic work and exempt from the generic lead cap', () => {
  const step = (id: string, priority: number, seq: number, kind: 'lead' | 'tier-a' = 'lead') => ({
    id, priority, seq,
    title: kind === 'tier-a' ? `Tier-A code lead · authz_matrix ${id}` : `det_lead upgrade · ${id}`,
    category: 'misconfig-exposure',
    hypothesis: '', skills: [], dependsOnFactIds: [], dependsOnStepIds: [], sourceOrigins: [],
  })
  const genericLead = step('generic-lead', 90, 1)
  const tierA1 = step('tier-a-1', TIER_A_STEP_PRIORITY, 2, 'tier-a')
  const tierA2 = step('tier-a-2', TIER_A_STEP_PRIORITY, 3, 'tier-a')
  const tierA3 = step('tier-a-3', TIER_A_STEP_PRIORITY, 4, 'tier-a')
  const route = { ...step('route-1', 60, 5), title: 'route probe /api/orders', category: 'broken-access-control' }

  const plan = planRoundRobinDispatch(
    [route, genericLead, tierA3, tierA1, tierA2],
    5,
    { leadCap: 1, activeLeadCount: 0, tierALeadIds: new Set(['tier-a-1', 'tier-a-2', 'tier-a-3']) },
  )
  const ids = plan.ordered.map(entry => entry.id)
  assert.deepEqual(ids.slice(0, 3), ['tier-a-1', 'tier-a-2', 'tier-a-3'], 'every Tier-A slice takes a first slot')
  assert.ok(ids.includes('route-1'), 'the remaining slot still goes to route breadth')
})

test('Pass-1 coverage distinguishes a drained queue from uninvestigated first-pass work', () => {
  const coverage = passOneCoverage({
    tierAEndpoints: ['GET /v2/reports/export', 'PATCH /v3/admin/users/:id'],
    steps: [
      { id: 'a', dispatchable: false, dispatched: true, routes: ['/v2/reports/export'], keys: ['/v2/reports/export\u0000sqli'] },
      { id: 'b', dispatchable: true, dispatched: false, routes: ['/v3/admin/users/:id'], keys: ['/v3/admin/users/:id\u0000authz'] },
      { id: 'c', dispatchable: true, dispatched: false, routes: ['/api/orders'], keys: ['/api/orders\u0000authz'] },
    ],
  })
  assert.deepEqual(coverage.uncoveredTierAEndpoints, ['PATCH /v3/admin/users/:id'])
  assert.deepEqual(coverage.uninvestigatedFirstPassClasses.sort(), ['/api/orders\u0000authz', '/v3/admin/users/:id\u0000authz'])
})

test('a dry-round stop is deferred while first-pass or Tier-A work remains; exhaustion still stops', () => {
  const deferred = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 0, freeSlots: 0, inFlight: 0,
    uninvestigatedFirstPassClasses: ['/api/orders\u0000authz'],
  })
  assert.equal(deferred.decision, 'continue')
  assert.equal(deferred.deferred, true)

  const tierA = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 0, freeSlots: 0, inFlight: 0,
    uncoveredTierAEndpoints: ['GET /v2/reports/export'],
  })
  assert.equal(tierA.decision, 'continue')

  const exhausted = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 2, freeSlots: 1, inFlight: 0,
    requestExhausted: true, uninvestigatedFirstPassClasses: ['/api/orders\u0000authz'],
  })
  assert.equal(exhausted.decision, 'stop', 'request/wall/budget exhaustion still terminates the run')

  const drained = evaluateDispatchStop({
    decision: 'stop', reason: 'diminishing_returns', remainingReady: 0, freeSlots: 3, inFlight: 0,
  })
  assert.equal(drained.decision, 'stop')
})

test('Tier-A leads seed as ready Round-1 steps without runtime contrast evidence and idempotently', async t => {
  const { storage } = makeStore(t, 'kovo-v7-realism4-tier-a-')
  const { run, assignment } = await approvedRun(storage)
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const hypotheses = [
    adminHypothesis(),
    { ...adminHypothesis(), id: 'hyp-realism4-billing', kind: 'tenant_param_without_scope', method: 'GET', path: '/v2/billing/invoices/:id', probeClass: 'bola_bfla' },
    { ...adminHypothesis(), id: 'hyp-realism4-report', kind: 'sql_concat_sink', method: 'GET', path: '/v2/reports/export', probeClass: 'injection' },
  ] as CodeToRuntimeHypothesis[]
  assert.equal(seedCodeToRuntimeLeads(storage, run, assignment, hypotheses, new Set(), ORIGIN), 3)

  const created = internals(execution).queueTierALeadSteps(storage.run(run.id), new Set([ORIGIN]), 50)
  assert.equal(created, 3, 'all three Tier-A leads are seeded')
  const steps = storage.listChainSteps(run.id, run.goalRevision)
    .filter(step => internals(execution).tierAStepIds.has(step.id))
  assert.equal(steps.length, 3)
  assert.ok(steps.every(step => step.status === 'ready'))
  assert.ok(steps.every(step => step.priority === TIER_A_STEP_PRIORITY))
  assert.ok(internals(execution).tierAFactIds.size >= 3)

  assert.equal(internals(execution).queueTierALeadSteps(storage.run(run.id), new Set([ORIGIN]), 50), 0, 're-seeding is idempotent')
})

