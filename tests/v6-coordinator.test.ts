import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  EMPTY_PLANNER_ROUND_LIMIT,
  decideNext,
  dispatchInvestigations,
  extractChainHops,
  isPendingOobFinding,
} from '../src/server/graph-coordinator.ts'
import type {
  CoordinatorEndpoint,
  CoordinatorFact,
  CoordinatorFinding,
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

// ---------------------------------------------------------------------------
// 1. Pending OOB classification
// ---------------------------------------------------------------------------

test('isPendingOobFinding only flags pending/inconclusive findings parked on an OOB subscription', () => {
  const findings: CoordinatorFinding[] = [
    finding(1, { title: 'Confirmed IDOR' }),
    finding(3, { title: 'Pending SSRF callback', status: 'pending', pendingOob: true }),
    finding(4, { title: 'Pending XSS callback', status: 'pending', runtimeProofGap: 'awaiting pending_oob subscription' }),
    finding(5, { title: 'Dismissed', status: 'dismissed', pendingOob: true }),
    finding(6, { title: 'Inconclusive callback', status: 'inconclusive', verification: 'awaiting callback' }),
    finding(7, { title: 'Plain pending', status: 'pending' }),
  ]
  assert.deepEqual(findings.filter(isPendingOobFinding).map(item => item.id), ['finding-3', 'finding-4', 'finding-6'])
})

// ---------------------------------------------------------------------------
// 2. Typed chain hops
// ---------------------------------------------------------------------------

function hopFixture(): { facts: CoordinatorFact[]; findings: CoordinatorFinding[]; endpoints: CoordinatorEndpoint[] } {
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

test('extractChainHops derives typed hop artifacts from facts, findings and endpoints without leaking secrets', () => {
  const hops = extractChainHops(hopFixture())
  const kinds = new Set(hops.map(hop => hop.artifactKind))
  for (const kind of ['token_ref', 'leaked_id', 'ssrf_redirect_target', 'stored_write_handle', 'role_transition'] as const) {
    assert.ok(kinds.has(kind), `missing hop artifact kind ${kind}`)
  }

  const discovered = hops.find(hop => hop.artifactKind === 'leaked_id' && hop.artifactRef === '1042')
  assert.ok(discovered)
  assert.equal(discovered.endpoint, '/api/invoices/1042')
  assert.equal(discovered.method, 'GET')
  assert.equal(discovered.persona, 'alice')

  const admin = hops.find(hop => hop.artifactKind === 'role_transition' && hop.evidenceIds.includes('admin-users'))
  assert.ok(admin)
  assert.equal(admin.endpoint, '/admin/users')

  const serialized = JSON.stringify(hops)
  assert.ok(!serialized.includes('tok_live_supersecret_9f3a'), 'raw token must never appear in hops')
  assert.ok(!/eyJ[A-Za-z0-9_-]{8,}\./.test(serialized), 'raw JWT must never appear in hops')
  assert.ok(hops.filter(hop => hop.artifactKind === 'token_ref').every(hop => /^(?:secret|jwt|finding):/.test(hop.artifactRef)))
  assert.deepEqual(hops.map(hop => hop.hopIndex), hops.map((_, index) => index))
  assert.deepEqual(extractChainHops(hopFixture()), hops, 'deterministic for identical input')

  // Tainted facts are ignored entirely.
  assert.equal(extractChainHops({ facts: [fact(9, { kind: 'secret', tainted: true, data: { subkind: 'leaked_token' } })] }).length, 0)
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
// 9. Structural guarantees
// ---------------------------------------------------------------------------

test('coordinator module never imports execution.ts (no cycle) or other server monoliths', () => {
  const source = readFileSync(new URL('../src/server/graph-coordinator.ts', import.meta.url), 'utf8')
  assert.ok(!/from\s+['"][^'"]*execution\.ts['"]/.test(source), 'must not import execution.ts')
  assert.ok(!/from\s+['"][^'"]*store\.ts['"]/.test(source), 'must not import store.ts')
  assert.ok(!/from\s+['"][^'"]*agent-session\.ts['"]/.test(source), 'must not import agent-session.ts')
  assert.ok(!/from\s+['"][^'"]*program-graph\.ts['"]/.test(source), 'stays standalone (graph passed via deps)')
  const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map(m => m[1])
  assert.ok(
    imports.every(spec => spec === './frontier-scheduler.ts'),
    `only the pure frontier-scheduler type module is allowed, got: ${imports.join(', ')}`,
  )
})
