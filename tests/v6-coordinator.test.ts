import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  EMPTY_PLANNER_ROUND_LIMIT,
  createGraphCoordinator,
  decideNext,
  deriveChainPrimitives,
  dispatchInvestigations,
  isMissingAuthGuard,
  isRoleExclusive,
  isUncoveredEndpoint,
  planChainRound,
  queryEndpoints,
  queryFacts,
  queryFindings,
  queryProgramGraph,
} from '../src/server/graph-coordinator.ts'
import type {
  ChainPrimitive,
  CoordinatorCommitSignal,
  CoordinatorDeps,
  CoordinatorEndpoint,
  CoordinatorFact,
  CoordinatorFinding,
  CoordinatorProgramGraph,
  DeriveChainPrimitivesInput,
  GitHotspotItem,
  MiddlewareDiffItem,
  ProgramSinkItem,
} from '../src/server/graph-coordinator.ts'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function endpoint(index: number, overrides: Partial<CoordinatorEndpoint> = {}): CoordinatorEndpoint {
  return {
    id: `ep-${String(index).padStart(5, '0')}`,
    origin: index % 2 === 0 ? 'https://app.local' : 'https://api.local',
    method: index % 3 === 0 ? 'POST' : 'GET',
    pathTemplate: `/r/${index}`,
    source: 'crawl',
    authRequirement: index % 7 === 0 ? null : 'session',
    ownershipGuard: index % 11 === 0 ? null : 'tenant',
    sinkKinds: index % 4 === 0 ? ['db_query'] : [],
    testedClasses: index % 5 === 0 ? [] : ['sqli'],
    coveragePct: index % 5 === 0 ? null : 100,
    riskScore: index % 100,
    ...overrides,
  }
}

function fact(index: number, overrides: Partial<CoordinatorFact> = {}): CoordinatorFact {
  return {
    id: `fact-${String(index).padStart(5, '0')}`,
    origin: index % 2 === 0 ? 'https://app.local' : 'https://api.local',
    kind: index % 6 === 0 ? 'secret' : 'note',
    summary: `fact ${index}`,
    data: { roundNo: Math.floor(index / 10) },
    evidenceIds: [`ev-${index}`],
    exchangeIds: [],
    tainted: false,
    createdAt: 1_000 + index,
    ...overrides,
  }
}

function finding(index: number, overrides: Partial<CoordinatorFinding> = {}): CoordinatorFinding {
  return {
    id: `finding-${index}`,
    origin: 'https://app.local',
    title: `finding ${index}`,
    status: 'confirmed',
    severity: 'high',
    reason: 'reason',
    category: 'broken-access-control',
    evidenceIds: [`ev-${index}`],
    ...overrides,
  }
}

function deps(input: {
  endpoints?: readonly CoordinatorEndpoint[]
  facts?: readonly CoordinatorFact[]
  findings?: readonly CoordinatorFinding[]
  graph?: CoordinatorProgramGraph | null
  commits?: readonly CoordinatorCommitSignal[]
}): CoordinatorDeps {
  return {
    listEndpoints: () => input.endpoints ?? [],
    listFacts: () => input.facts ?? [],
    listFindings: () => input.findings ?? [],
    programGraph: () => input.graph ?? null,
    ...(input.commits ? { commitSignals: () => input.commits! } : {}),
  }
}

function collectEndpoints(d: CoordinatorDeps, limit: number) {
  const pages: Array<ReturnType<typeof queryEndpoints>> = []
  let cursor: string | undefined
  do {
    const page = queryEndpoints(d, { limit, cursor })
    pages.push(page)
    cursor = page.nextCursor ?? undefined
    if (pages.length > 100) throw new Error('pagination did not terminate')
  } while (cursor)
  return pages
}

// ---------------------------------------------------------------------------
// 1. Endpoint pagination and filters
// ---------------------------------------------------------------------------

test('endpoint pagination is stable and never truncates 2,500 endpoints', () => {
  const endpoints = Array.from({ length: 2500 }, (_, index) => endpoint(index))
  const d = deps({ endpoints })
  const pages = collectEndpoints(d, 250)
  const ids = pages.flatMap(page => page.items.map(item => item.id))

  assert.equal(pages.length, 10)
  assert.equal(ids.length, 2500)
  assert.equal(new Set(ids).size, 2500)
  assert.equal(pages[0].total, 2500)
  assert.equal(pages.at(-1)!.nextCursor, null)
  assert.equal(pages[0].cursor, null)
  for (const page of pages) assert.equal(page.limit, 250)

  // A cursor addresses the same slice across repeated calls (stable ordering).
  const first = queryEndpoints(d, { limit: 100, cursor: 'v1:100' })
  const again = queryEndpoints(d, { limit: 100, cursor: 'v1:100' })
  assert.deepEqual(first.items.map(item => item.id), again.items.map(item => item.id))

  assert.throws(() => queryEndpoints(d, { cursor: 'bogus' }), /Invalid pagination cursor/)
  assert.throws(() => queryEndpoints(d, { limit: 0 }), /limit must be a positive integer/)
})

test('endpoint filters cover sink, missing auth guard, role exclusivity, coverage and prefix', () => {
  const endpoints: CoordinatorEndpoint[] = [
    endpoint(1, { id: 'open-admin', pathTemplate: '/admin/users', authRequirement: null, sinkKinds: [], testedClasses: [], coveragePct: null, riskScore: 95, roleExclusive: true }),
    endpoint(2, { id: 'public-api', pathTemplate: '/api/v1/health', authRequirement: 'public', sinkKinds: ['db_query'], testedClasses: ['sqli'], coveragePct: 100, riskScore: 20 }),
    endpoint(3, { id: 'guarded', pathTemplate: '/api/v1/orders', authRequirement: 'session', sinkKinds: ['outbound_fetch'], testedClasses: [], coveragePct: 0, riskScore: 70 }),
    endpoint(4, { id: 'other', pathTemplate: '/docs', authRequirement: 'session', sinkKinds: [], testedClasses: ['xss'], coveragePct: 100, riskScore: 5 }),
  ]
  const d = deps({ endpoints })

  assert.deepEqual(queryEndpoints(d, { hasSink: true }).items.map(item => item.id), ['guarded', 'public-api'])
  assert.deepEqual(queryEndpoints(d, { missingAuthGuard: true }).items.map(item => item.id), ['open-admin', 'public-api'])
  assert.deepEqual(queryEndpoints(d, { roleExclusive: true }).items.map(item => item.id), ['open-admin'])
  assert.deepEqual(queryEndpoints(d, { uncoveredOnly: true }).items.map(item => item.id), ['open-admin', 'guarded'])
  assert.deepEqual(queryEndpoints(d, { pathPrefix: '/api/v1' }).items.map(item => item.id), ['guarded', 'public-api'])

  assert.equal(isUncoveredEndpoint(endpoints[2]), true)
  assert.equal(isUncoveredEndpoint(endpoints[3]), false)
  assert.equal(isMissingAuthGuard(endpoints[1]), true)
  assert.equal(isRoleExclusive(endpoints[0]), true)
  assert.equal(isRoleExclusive(endpoint(5, { pathTemplate: '/profile' })), false)

  // Combined filters intersect rather than union.
  assert.deepEqual(
    queryEndpoints(d, { pathPrefix: '/api', hasSink: true, uncoveredOnly: true }).items.map(item => item.id),
    ['guarded'],
  )
})

// ---------------------------------------------------------------------------
// 2. Facts and findings paging
// ---------------------------------------------------------------------------

test('facts paginate across the whole store and honour kind/origin/persona/round/search', () => {
  const facts = Array.from({ length: 120 }, (_, index) => fact(index, {
    data: {
      roundNo: Math.floor(index / 10),
      persona: index % 3 === 0 ? 'alice' : 'bob',
      subkind: index % 10 === 0 ? 'persona_resource' : 'observation',
    },
  }))
  facts.push(fact(999, { tainted: true, summary: 'tainted leaky observation' }))
  const d = deps({ facts })

  const pages: Array<ReturnType<typeof queryFacts>> = []
  let cursor: string | undefined
  do {
    const page = queryFacts(d, { limit: 40, cursor })
    pages.push(page)
    cursor = page.nextCursor ?? undefined
    if (pages.length > 10) throw new Error('facts pagination did not terminate')
  } while (cursor)
  const ids = pages.flatMap(page => page.items.map(item => item.id))
  assert.equal(ids.length, 120, 'tainted facts stay excluded and nothing is lost')
  assert.equal(new Set(ids).size, 120)
  assert.equal(pages[0].total, 120)

  assert.equal(queryFacts(d, { kind: 'secret', limit: 500 }).total, 20)
  assert.equal(queryFacts(d, { kind: 'persona_resource', limit: 500 }).total, 12)
  assert.equal(queryFacts(d, { origin: 'https://api.local', limit: 500 }).total, 60)
  assert.equal(queryFacts(d, { persona: 'alice', limit: 500 }).total, 40)
  assert.equal(queryFacts(d, { sinceRound: 10, limit: 500 }).total, 20)
  assert.equal(queryFacts(d, { search: 'fact 11', limit: 500 }).total, 11)
  assert.equal(queryFacts(d, { search: 'tainted', limit: 500 }).total, 0)
})

test('findings query separates confirmed, pending_oob and det_lead work', () => {
  const findings: CoordinatorFinding[] = [
    finding(1, { title: 'Confirmed IDOR' }),
    finding(2, { title: 'Confirmed SSRF', category: 'injection-input' }),
    finding(3, { title: 'Pending SSRF callback', status: 'pending', pendingOob: true }),
    finding(4, { title: 'Pending XSS callback', status: 'pending', runtimeProofGap: 'awaiting pending_oob subscription' }),
    finding(5, { title: 'Dismissed', status: 'dismissed', pendingOob: true }),
  ]
  const facts: CoordinatorFact[] = [
    fact(1, { data: { kind: 'det_lead', probeClass: 'sqli_boolean', endpoint: '/search', method: 'get', reason: 'boolean differential' } }),
    fact(2, { data: { kind: 'det_lead', probeClass: 'ssrf', endpoint: '/fetch' } }),
    fact(3, { data: { kind: 'det_lead' }, tainted: true }),
    fact(4, { data: { subkind: 'observation' } }),
  ]
  const d = deps({ findings, facts })

  const confirmed = queryFindings(d, { status: 'confirmed' })
  assert.equal(confirmed.total, 2)
  assert.deepEqual(confirmed.items.map(item => item.id), ['finding-1', 'finding-2'])

  const pending = queryFindings(d, { status: 'pending_oob' })
  assert.equal(pending.total, 2)
  assert.deepEqual(pending.items.map(item => item.id), ['finding-3', 'finding-4'])

  const leads = queryFindings(d, { status: 'det_lead', limit: 1 })
  assert.equal(leads.total, 2)
  assert.equal(leads.items.length, 1)
  assert.equal(leads.items[0].source, 'det_lead')
  assert.equal(leads.items[0].probeClass, 'ssrf')
  const sqliLead = queryFindings(d, { status: 'det_lead' }).items.find(item => item.probeClass === 'sqli_boolean')
  assert.ok(sqliLead)
  assert.equal(sqliLead.endpoint, '/search')
  assert.equal(sqliLead.method, 'GET')
  assert.ok(sqliLead.parentEvidenceIds.includes(sqliLead.id))
})

// ---------------------------------------------------------------------------
// 3. Program graph queries
// ---------------------------------------------------------------------------

test('program graph query projects sinks, middleware gaps and git hotspots', () => {
  const graph: CoordinatorProgramGraph = {
    routes: [
      {
        id: 'route-orders', method: 'POST', path: '/api/orders/:id', file: 'src/orders.ts', line: 10, handler: 'listOrders',
        input: { params: ['id'] }, middleware: ['json'], guards: [],
      },
      {
        id: 'route-admin', method: 'POST', path: '/admin/users', file: 'src/admin.ts', line: 20, handler: 'createUser',
        input: { body: ['email'] }, middleware: ['json', 'requireAdmin'], guards: ['requireAdmin'],
      },
    ],
    nodes: [
      { id: 'route-orders', kind: 'route', symbol: 'GET /api/orders/:id', file: 'src/orders.ts', line: 10 },
      { id: 'svc-orders', kind: 'function', symbol: 'loadOrders', file: 'src/orders.ts', line: 40 },
      { id: 'sink-orders', kind: 'sink', symbol: 'db.query', file: 'src/orders.ts', line: 55, sinkKind: 'db_query' },
      { id: 'route-admin', kind: 'route', symbol: 'POST /admin/users', file: 'src/admin.ts', line: 20 },
      { id: 'sink-admin', kind: 'sink', symbol: 'res.send', file: 'src/admin.ts', line: 30, sinkKind: 'template' },
    ],
    edges: [
      { fromId: 'route-orders', toId: 'svc-orders', file: 'src/orders.ts', line: 12 },
      { fromId: 'svc-orders', toId: 'sink-orders', file: 'src/orders.ts', line: 54 },
      { fromId: 'route-admin', toId: 'sink-admin', file: 'src/admin.ts', line: 22 },
    ],
  }
  const commits: readonly CoordinatorCommitSignal[] = [
    {
      sha: 'abc123', subject: 'orders query', committedAt: '2026-11-20T10:00:00Z', file: 'src/orders.ts',
      change: 'modified', sinkKinds: ['db_query'], routeTouched: true, authMiddlewareTouched: false,
      securityRelevant: true, reasons: ['touches sink(s): db_query'],
    },
    {
      sha: 'def456', subject: 'docs', committedAt: '2026-11-21T10:00:00Z', file: 'docs/readme.md',
      change: 'modified', sinkKinds: [], routeTouched: false, authMiddlewareTouched: false,
      securityRelevant: false, reasons: [],
    },
  ]
  const d = deps({ graph, commits })

  const sinks = queryProgramGraph<ProgramSinkItem>(d, { kind: 'sinks', routeOrFile: 'orders' })
  assert.equal(sinks.total, 1)
  assert.equal(sinks.items[0].sinkKind, 'db_query')
  assert.equal(sinks.items[0].hops, 2)

  const middleware = queryProgramGraph<MiddlewareDiffItem>(d, { kind: 'middleware_diff' })
  assert.equal(middleware.total, 1)
  const diff = middleware.items[0]
  assert.equal(diff.routeId, 'route-orders')
  assert.deepEqual(diff.missingGuardFamilies.sort(), ['authentication', 'tenant_scope'])

  const hotspots = queryProgramGraph<GitHotspotItem>(d, { kind: 'git_hotspots', routeOrFile: 'orders' })
  assert.equal(hotspots.total, 1)
  assert.equal(hotspots.items[0].sha, 'abc123')

  const missing = queryProgramGraph(deps({}), { kind: 'sinks' })
  assert.equal(missing.total, 0)
  assert.equal(missing.note, 'no program graph available')
})

// ---------------------------------------------------------------------------
// 4. Chain primitives
// ---------------------------------------------------------------------------

function primitiveFixture(): DeriveChainPrimitivesInput {
  return {
    facts: [
      fact(1, {
        kind: 'secret',
        summary: 'leaked bearer tok_live_supersecret_9f3a in bundle',
        data: { subkind: 'leaked_token', endpoint: '/static/app.js' },
      }),
      fact(2, {
        kind: 'object_ref',
        summary: 'account sample',
        data: { resourceId: 1042, endpoint: '/api/invoices/1042', method: 'get', persona: 'alice' },
      }),
      fact(3, {
        kind: 'note',
        summary: 'second order surface reached',
        data: { subkind: 'second_order_surface', marker: 'gx-abc', endpoint: '/admin/notes' },
      }),
      fact(4, {
        kind: 'auth',
        summary: 'jwt accepts alg none',
        data: { subkind: 'jwt_alg_none', endpoint: '/api/session' },
      }),
      fact(5, {
        kind: 'note',
        summary: 'blind fetch callback observed',
        data: { kind: 'det_lead', probeClass: 'ssrf', endpoint: '/api/import', anomalies: [{ type: 'ssrf_callback' }] },
      }),
    ],
    findings: [
      finding(1, { title: 'IDOR exposes tenant invoices', category: 'broken-access-control', cwe: 'CWE-639' }),
      finding(2, { title: 'Confirmed leaked credential in public bundle', category: 'auth-identity', cwe: 'CWE-200' }),
    ],
    endpoints: [
      endpoint(1, { id: 'admin-users', pathTemplate: '/admin/users', authRequirement: 'admin', roleExclusive: true }),
      endpoint(2, { id: 'plain', pathTemplate: '/profile', authRequirement: 'session' }),
    ],
  }
}

test('chain primitive extraction derives all typed tags without leaking secrets', () => {
  const fixture = primitiveFixture()
  const primitives = deriveChainPrimitives(fixture)
  const kinds = new Set(primitives.map(primitive => primitive.kind))
  for (const kind of ['leaked_token', 'discovered_id', 'ssrf_internal_reach', 'stored_write', 'weak_jwt', 'admin_route'] as const) {
    assert.ok(kinds.has(kind), `missing primitive kind ${kind}`)
  }

  const discovered = primitives.find(primitive => primitive.kind === 'discovered_id' && primitive.value === '1042')
  assert.ok(discovered)
  assert.equal(discovered.endpoint, '/api/invoices/1042')
  assert.equal(discovered.method, 'GET')
  assert.equal(discovered.persona, 'alice')

  const admin = primitives.find(primitive => primitive.kind === 'admin_route' && primitive.endpointId === 'admin-users')
  assert.ok(admin)
  assert.deepEqual(admin.evidenceIds, ['admin-users'])

  const serialized = JSON.stringify(primitives)
  assert.ok(!serialized.includes('tok_live_supersecret_9f3a'), 'raw token must never appear in primitives')
  assert.ok(!/eyJ[A-Za-z0-9_-]{8,}\./.test(serialized), 'raw JWT must never appear in primitives')
  assert.ok(primitives.filter(primitive => primitive.kind === 'leaked_token').every(primitive => primitive.value.startsWith('secret:') || primitive.value.startsWith('finding:')))

  // Tainted facts are ignored entirely.
  const tainted = deriveChainPrimitives({ facts: [fact(9, { kind: 'secret', tainted: true, data: { subkind: 'leaked_token' } })] })
  assert.equal(tainted.length, 0)
})

// ---------------------------------------------------------------------------
// 5. Explicit chaining round
// ---------------------------------------------------------------------------

function primitive(overrides: Partial<ChainPrimitive> & Pick<ChainPrimitive, 'kind' | 'origin' | 'value'>): ChainPrimitive {
  return {
    evidenceIds: [`ev-${overrides.kind}-${overrides.value}`],
    factIds: [`fact-${overrides.kind}-${overrides.value}`],
    detail: `${overrides.kind} primitive`,
    ...overrides,
  }
}

test('chaining round proposes same-origin and cross-origin hypotheses with parent evidence', () => {
  const primitives: ChainPrimitive[] = [
    primitive({ kind: 'leaked_token', origin: 'https://app.local', value: 'secret:fact-1', factIds: ['fact-secret'], evidenceIds: ['ev-secret'] }),
    primitive({ kind: 'admin_route', origin: 'https://app.local', value: 'admin:GET /admin/users', endpointId: 'admin-users', endpoint: '/admin/users', method: 'GET', evidenceIds: ['admin-users'] }),
    primitive({ kind: 'discovered_id', origin: 'https://api.local', value: '1042', endpoint: '/api/invoices/1042', evidenceIds: ['ev-id'] }),
    primitive({ kind: 'stored_write', origin: 'https://api.local', value: 'stored:gx-abc', evidenceIds: ['ev-stored'] }),
    primitive({ kind: 'ssrf_internal_reach', origin: 'https://api.local', value: 'ssrf:/api/import', evidenceIds: ['ev-ssrf'] }),
  ]
  const endpoints: CoordinatorEndpoint[] = [
    endpoint(1, { id: 'admin-users', origin: 'https://app.local', pathTemplate: '/admin/users', method: 'GET' }),
    endpoint(2, { id: 'invoice', origin: 'https://api.local', pathTemplate: '/api/invoices/1042', method: 'GET' }),
  ]

  const hypotheses = planChainRound({ primitives, endpoints, approvedOrigins: ['https://app.local', 'https://api.local'] })
  const sameOrigin = hypotheses.filter(hypothesis => hypothesis.scope === 'same_origin' && hypothesis.hops === 2)
  const crossOrigin = hypotheses.filter(hypothesis => hypothesis.scope === 'cross_origin' && hypothesis.hops === 2)

  assert.ok(sameOrigin.length >= 1)
  assert.ok(crossOrigin.length >= 1)
  const tokenAdmin = hypotheses.find(hypothesis =>
    hypothesis.scope === 'same_origin' && hypothesis.primitiveKinds.includes('leaked_token') && hypothesis.primitiveKinds.includes('admin_route'))
  assert.ok(tokenAdmin, 'leaked token + admin route should form a same-origin chain')
  assert.equal(tokenAdmin.hops, 2)
  assert.ok(tokenAdmin.parentEvidenceIds.includes('fact-secret'))
  assert.ok(tokenAdmin.parentEvidenceIds.includes('admin-users'))
  assert.ok(tokenAdmin.capabilities.includes('http'))

  const cross = crossOrigin.find(hypothesis =>
    hypothesis.primitiveKinds.includes('leaked_token') && hypothesis.primitiveKinds.includes('discovered_id'))
  assert.ok(cross, 'token on app.local + id on api.local should form a cross-origin chain')
  assert.deepEqual(cross.chainOrigins.sort(), ['https://api.local', 'https://app.local'])
  assert.ok(cross.parentEvidenceIds.length >= 2)

  const threeHop = planChainRound({ primitives, endpoints, maxHops: 3 })
    .find(hypothesis => hypothesis.hops === 3)
  assert.ok(threeHop, 'a 2–3 hop round should propose extension chains')
  assert.ok(threeHop.primitiveKinds.includes('stored_write'))
  assert.ok(threeHop.capabilities.includes('browser'))
  assert.ok(threeHop.capabilities.includes('oob'))

  assert.equal(planChainRound({ primitives, maxHops: 2 }).every(hypothesis => hypothesis.hops === 2), true)
  assert.equal(planChainRound({ primitives, approvedOrigins: ['https://app.local'] })
    .every(hypothesis => hypothesis.chainOrigins.every(origin => origin === 'https://app.local')), true)

  // Deterministic output for identical input.
  assert.deepEqual(
    planChainRound({ primitives, endpoints }).map(hypothesis => hypothesis.id),
    planChainRound({ primitives, endpoints }).map(hypothesis => hypothesis.id),
  )
})

// ---------------------------------------------------------------------------
// 6. Dispatch validation
// ---------------------------------------------------------------------------

test('dispatch validation rejects unknown capabilities and overspend, and normalises the plan', () => {
  const valid = {
    hypothesis: 'Replay leaked token against /admin/users',
    origins: ['https://app.local'],
    capabilities: ['http', 'browser'],
    parentEvidenceIds: ['fact-secret', 'admin-users'],
    budgetUsd: 0.4,
    probeClass: 'authz_replay',
    priority: 140,
  }

  const plan = dispatchInvestigations([valid], {
    budgetUsd: 1,
    approvedOrigins: ['https://app.local'],
  })
  assert.equal(plan.dispatched, false)
  assert.equal(plan.plan.length, 1)
  assert.equal(plan.plan[0].id, 'dispatch-1')
  assert.deepEqual(plan.plan[0].origins, ['https://app.local'])
  assert.deepEqual(plan.plan[0].capabilities, ['http', 'browser'])
  assert.equal(plan.plan[0].priority, 100)
  assert.equal(plan.totalBudgetUsd, 0.4)
  assert.deepEqual(plan.parentEvidenceIds, ['fact-secret', 'admin-users'])

  const unknown = dispatchInvestigations([
    { ...valid, capabilities: ['http', 'quantum'] },
  ])
  assert.equal(unknown.plan.length, 0)
  assert.equal(unknown.rejected[0].code, 'unknown_capability')

  const overspend = dispatchInvestigations([
    valid,
    { ...valid, hypothesis: 'Second step', budgetUsd: 0.9 },
  ], { budgetUsd: 1 })
  assert.equal(overspend.plan.length, 1)
  assert.equal(overspend.rejected[0].code, 'overspend')
  assert.equal(overspend.totalBudgetUsd, 0.4)

  assert.equal(dispatchInvestigations([{ ...valid, parentEvidenceIds: [] }]).rejected[0].code, 'missing_parent_evidence')
  assert.equal(dispatchInvestigations([{ ...valid, origins: ['https://evil.example'] }], {
    approvedOrigins: ['https://app.local'],
  }).rejected[0].code, 'origin_not_approved')
  assert.equal(dispatchInvestigations([{ ...valid, origins: ['not-a-url'] }]).rejected[0].code, 'invalid_origin')
  assert.equal(dispatchInvestigations([{ ...valid, budgetUsd: -1 }]).rejected[0].code, 'invalid_budget')
  assert.equal(dispatchInvestigations([{ ...valid, hypothesis: '  ' }]).rejected[0].code, 'empty_hypothesis')
  assert.equal(dispatchInvestigations([{ ...valid, origins: [] }]).rejected[0].code, 'missing_origin')

  const duplicate = dispatchInvestigations([valid, { ...valid, parentEvidenceIds: ['other'] }])
  assert.equal(duplicate.plan.length, 1)
  assert.equal(duplicate.rejected[0].code, 'duplicate_step')

  const capped = dispatchInvestigations([
    valid,
    { ...valid, hypothesis: 'Second step' },
    { ...valid, hypothesis: 'Third step' },
  ], { maxSteps: 2 })
  assert.equal(capped.plan.length, 2)
  assert.equal(capped.rejected[0].code, 'step_limit')
})

// ---------------------------------------------------------------------------
// 7. Scheduler guard
// ---------------------------------------------------------------------------

test('scheduler stops on budget, request, wall-clock, empty rounds and done+pending OOB', () => {
  assert.equal(decideNext({}).decision, 'continue')
  assert.equal(decideNext({ requestsLeft: 10, wallClockLeft: 60_000, coordinatorDone: false }).decision, 'continue')

  assert.deepEqual(
    { decision: decideNext({ budgetExhausted: true }).decision, reason: decideNext({ budgetExhausted: true }).reason },
    { decision: 'stop', reason: 'budget_exhausted' },
  )
  assert.equal(decideNext({ budgetExhausted: true, requestsLeft: 5 }).reason, 'budget_exhausted')
  assert.equal(decideNext({ requestsLeft: 0 }).reason, 'requests_exhausted')
  assert.equal(decideNext({ requestsLeft: 3 }).decision, 'continue')
  assert.equal(decideNext({ wallClockLeft: 0 }).reason, 'wallclock_exhausted')
  assert.equal(decideNext({ wallClockLeft: 1 }).decision, 'continue')

  const below = decideNext({ consecutiveEmptyPlannerRounds: EMPTY_PLANNER_ROUND_LIMIT - 1 })
  assert.equal(below.decision, 'continue')
  const atLimit = decideNext({ consecutiveEmptyPlannerRounds: EMPTY_PLANNER_ROUND_LIMIT })
  assert.equal(atLimit.decision, 'stop')
  assert.equal(atLimit.reason, 'diminishing_returns')
  assert.equal(EMPTY_PLANNER_ROUND_LIMIT, 2)

  assert.equal(decideNext({ coordinatorDone: true }).reason, 'coordinator_done')
  assert.equal(decideNext({ coordinatorDone: true, pendingOob: 1 }).decision, 'continue')
  assert.equal(decideNext({ coordinatorDone: false, pendingOob: 0 }).decision, 'continue')
  assert.equal(decideNext({ coordinatorDone: true, pendingOob: 0, requestsLeft: 0 }).reason, 'requests_exhausted')

  // Stop decisions carry a stable, human-readable reason.
  assert.match(atLimit.detail, /K=2/)
})

// ---------------------------------------------------------------------------
// 8. Coordinator facade
// ---------------------------------------------------------------------------

test('createGraphCoordinator binds tools, primitives, chain rounds and scope defaults', () => {
  const endpoints: CoordinatorEndpoint[] = [
    endpoint(1, { id: 'admin-users', origin: 'https://app.local', pathTemplate: '/admin/users', authRequirement: 'admin', roleExclusive: true }),
  ]
  const facts: CoordinatorFact[] = [
    fact(1, { origin: 'https://app.local', kind: 'secret', data: { subkind: 'leaked_token' } }),
  ]
  const coordinator = createGraphCoordinator({
    deps: deps({ endpoints, facts }),
    approvedOrigins: ['https://app.local'],
    budgetUsd: 0.5,
    maxDispatchSteps: 1,
  })

  assert.equal(coordinator.queryEndpoints({ roleExclusive: true }).total, 1)
  assert.equal(coordinator.queryFacts({ kind: 'leaked_token' }).total, 1)
  const primitives = coordinator.deriveChainPrimitives()
  assert.ok(primitives.some(item => item.kind === 'leaked_token'))
  const hypotheses = coordinator.planChainRound()
  assert.ok(hypotheses.length >= 1)
  assert.ok(hypotheses.every(hypothesis => hypothesis.chainOrigins.every(origin => origin === 'https://app.local')))

  const dispatch = coordinator.dispatchInvestigations([{
    hypothesis: 'Replay leaked token on admin route', origins: ['https://app.local'], parentEvidenceIds: ['fact-00001'],
  }])
  assert.equal(dispatch.plan.length, 1)
  assert.equal(dispatch.plan[0].budgetUsd, 0)

  const outOfScope = coordinator.dispatchInvestigations([{
    hypothesis: 'Other origin', origins: ['https://evil.example'], parentEvidenceIds: ['fact-00001'],
  }])
  assert.equal(outOfScope.rejected[0].code, 'origin_not_approved')

  assert.equal(coordinator.decideNext({ pendingOob: 1, coordinatorDone: true }).decision, 'continue')
})

// ---------------------------------------------------------------------------
// 9. Structural guarantees
// ---------------------------------------------------------------------------

test('coordinator module never imports execution.ts (no cycle) or other server monoliths', () => {
  const source = readFileSync(new URL('../src/server/graph-coordinator.ts', import.meta.url), 'utf8')
  assert.ok(!/from\s+['"][^'"]*execution\.ts['"]/.test(source), 'must not import execution.ts')
  assert.ok(!/from\s+['"][^'"]*store\.ts['"]/.test(source), 'must not import store.ts')
  assert.ok(!/from\s+['"][^'"]*agent-session\.ts['"]/.test(source), 'must not import agent-session.ts')
  assert.ok(!/from\s+['"][^'"]*program-graph\.ts['"]/.test(source), 'stays standalone (graph passed via deps)')
  assert.ok(!/from\s+['"]/.test(source), 'zero runtime/type imports')
})
