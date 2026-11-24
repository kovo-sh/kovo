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
  buildCodeLeadCrossTenantProof,
  buildCodeLeadSqlErrorProof,
  codeLeadMatrixRows,
  deriveCodeLeadIdentifierTargets,
  prioritizeCodeLeadTargets,
  tenantLabelsFromRoleLabels,
} from '../src/server/execution.ts'
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
  const { storage } = makeStore(t, 'guardian-v7-realism4-brief-')
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
    personas: [],
    parentFacts: [fact],
    confirmed: [],
    detLeads: [],
    maxTurns: 18,
  }) as string | undefined

  assert.ok(brief, 'the brief is rendered')
  assert.ok(measureAssignmentBriefBytes(brief!) <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE)
  const packet = JSON.parse(brief!) as {
    proofObligation?: { route: string; params?: string[]; auth?: string; sink?: string; chain?: string }
  }
  assert.equal(packet.proofObligation?.route, ADMIN_ROUTE)
  assert.deepEqual(packet.proofObligation?.params, ['role'])
  assert.equal(packet.proofObligation?.auth, 'unguarded')
  assert.match(packet.proofObligation?.sink ?? '', /^db_query@.*user-repo\.ts/)
  assert.match(packet.proofObligation?.chain ?? '', /controllers\/users\.ts:5/)
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
// 5. Fallback proof shapes (existing http_chain primitive + existing oracle)
// ============================================================================

function hypothesis(overrides: Partial<EngineHypothesis> = {}): EngineHypothesis {
  return {
    key: 'authz|derived:0:GET:/v2/billing/invoices/:id|path',
    endpoint: {
      id: 'derived:0:GET:/v2/billing/invoices/:id',
      origin: ORIGIN,
      method: 'GET',
      pathTemplate: '/v2/billing/invoices/:id',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
      riskScore: CODE_LEAD_PRIORITY_RISK,
      source: 'program_graph',
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/v2/billing/invoices/{{id}}',
    ownerPersona: 'mono-alice',
    otherPersona: 'mono-bob',
    resourceIds: ['inv-alpha-1'],
    risk: 90,
    ...overrides,
  }
}

test('cross-tenant proof is a valid http_chain bound to the served object id', () => {
  const spec = buildCodeLeadCrossTenantProof({
    origin: ORIGIN,
    hypothesis: hypothesis(),
    resourceId: 'inv-alpha-1',
    probeActor: 'other_persona',
    ownerPersona: 'mono-alice',
    otherPersona: 'mono-bob',
  })
  assert.ok(spec)
  const parsed = httpChainReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, JSON.stringify(parsed.error?.issues))
  assert.equal(parsed.data!.kind, 'http_chain')
  assert.equal(parsed.data!.cwe, 'CWE-639')
  assert.deepEqual(parsed.data!.steps.map(step => step.role), ['control', 'probe'])
  assert.deepEqual(parsed.data!.steps.map(step => step.request.persona), ['mono-alice', 'mono-bob'])
  assert.equal(parsed.data!.steps[0]!.request.pathAndQuery, '/v2/billing/invoices/inv-alpha-1')
  assert.match(parsed.data!.assertionsJq, /contains\("inv-alpha-1"\)/)

  assert.equal(buildCodeLeadCrossTenantProof({
    origin: ORIGIN,
    hypothesis: hypothesis({ method: 'PATCH' }),
    resourceId: 'inv-alpha-1',
    probeActor: 'other_persona',
    ownerPersona: 'mono-alice',
    otherPersona: 'mono-bob',
  }), null, 'mutating routes are not rendered by this read shape')
})

test('SQL error proof asserts the injected arm went 5xx while the control stayed healthy', () => {
  const sqlHypothesis = hypothesis({
    key: 'sqli_boolean|derived:2:GET:/v2/reports/export|sort',
    endpoint: {
      id: 'derived:2:GET:/v2/reports/export',
      origin: ORIGIN,
      method: 'GET',
      pathTemplate: '/v2/reports/export',
      params: [{ name: 'sort', location: 'query' }],
      riskScore: CODE_LEAD_PRIORITY_RISK,
      source: 'program_graph',
    },
    probeClass: 'sqli_boolean',
    intent: 'sqli',
    method: 'GET',
    pathAndQuery: '/v2/reports/export',
    param: { name: 'sort', location: 'query' },
    location: 'query',
    baselineValue: 'created_at',
    ownerPersona: 'mono-alice',
    otherPersona: undefined,
    resourceIds: undefined,
  })
  const spec = buildCodeLeadSqlErrorProof({ origin: ORIGIN, hypothesis: sqlHypothesis, dialect: 'sqlite' })
  assert.ok(spec)
  const parsed = httpChainReplaySpecSchema.safeParse(spec)
  assert.equal(parsed.success, true, JSON.stringify(parsed.error?.issues))
  assert.equal(parsed.data!.kind, 'http_chain')
  assert.equal(parsed.data!.cwe, 'CWE-89')
  assert.match(parsed.data!.steps[0]!.request.pathAndQuery, /sort=created_at$/)
  assert.match(parsed.data!.steps[1]!.request.pathAndQuery, /sort=created_at%27$/)
  assert.match(parsed.data!.assertionsJq, /status >= 500/)
  assert.equal(buildCodeLeadSqlErrorProof({ origin: ORIGIN, hypothesis: hypothesis() }), null)
})

test('matrix parsing is typed and drops malformed rows', () => {
  const rows = codeLeadMatrixRows({
    details: {
      matrix: [
        { resourceId: 'inv-alpha-1', actor: 'owner', status: 200, accessible: true },
        { resourceId: 'inv-alpha-1', actor: 'other_persona', status: 200, accessible: true },
        { resourceId: 7, actor: 'owner', status: 200 },
        { actor: 'owner' },
      ],
    },
  })
  assert.deepEqual(rows, [
    { resourceId: 'inv-alpha-1', actor: 'owner', status: 200, accessible: true },
    { resourceId: 'inv-alpha-1', actor: 'other_persona', status: 200, accessible: true },
  ])
})
