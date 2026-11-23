/**
 * v6 Phase 4 coordinator wiring tests (plans/better-architecture.md §3.3).
 *
 * Verifies the atomic swap: a tool-equipped, paginated coordinator session replaces the
 * snapshot `runChainPlanner`; the lossy `ColdGraphCompactor` / `CrossHostSynthesizer` are gone;
 * chain rounds dispatch parent-evidenced hypotheses; and the deterministic `decideNext()` guard
 * owns termination (budget / requests / wall clock / K=2 empty rounds / done + pending OOB).
 */
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  EMPTY_PLANNER_ROUND_LIMIT,
  createGraphCoordinator,
  decideNext,
  planChainRound,
} from '../src/server/graph-coordinator.ts'
import type {
  ChainHypothesis,
  ChainPrimitive,
  CoordinatorDeps,
  CoordinatorEndpoint,
  CoordinatorFact,
  CoordinatorFinding,
} from '../src/server/graph-coordinator.ts'
import { buildWorkerTools } from '../src/server/agent-session.ts'
import type { Run } from '../src/server/store.ts'
import {
  Execution,
  chainHypothesisDispatchSteps,
  collectAllPages,
  coordinatorPlannerHandlers,
  coordinatorSchedulerDecision,
} from '../src/server/execution.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const ENDPOINT_COUNT = 640
const FACT_COUNT = 260

function endpoint(index: number, overrides: Partial<CoordinatorEndpoint> = {}): CoordinatorEndpoint {
  return {
    id: `ep-${String(index).padStart(5, '0')}`,
    origin: index % 3 === 0 ? 'https://admin.local' : 'https://app.local',
    method: index % 4 === 0 ? 'POST' : 'GET',
    pathTemplate: `/api/r/${index}`,
    source: 'repo_ast',
    authRequirement: index % 5 === 0 ? null : 'session',
    ownershipGuard: index % 7 === 0 ? null : 'tenant',
    sinkKinds: index % 6 === 0 ? ['db_query'] : [],
    testedClasses: index % 2 === 0 ? [] : ['sqli'],
    coveragePct: index % 2 === 0 ? null : 100,
    riskScore: index % 100,
    codeLocation: { repo: 'app', file: `src/routes/r${index}.ts`, startLine: index + 1 },
    ...overrides,
  }
}

function fact(index: number, overrides: Partial<CoordinatorFact> = {}): CoordinatorFact {
  return {
    id: `fact-${String(index).padStart(5, '0')}`,
    origin: index % 2 === 0 ? 'https://app.local' : 'https://api.local',
    kind: 'note',
    summary: `fact ${index}`,
    data: { roundNo: Math.floor(index / 20), subkind: index % 3 === 0 ? 'probe' : undefined },
    evidenceIds: [`ev-${index}`],
    exchangeIds: [],
    tainted: false,
    createdAt: 10_000 + index,
    ...overrides,
  }
}

function fixtureDeps(): CoordinatorDeps {
  const endpoints = Array.from({ length: ENDPOINT_COUNT }, (_, index) => endpoint(index))
  const facts = Array.from({ length: FACT_COUNT }, (_, index) => fact(index))
  const findings: CoordinatorFinding[] = [{
    id: 'finding-1', origin: 'https://app.local', title: 'confirmed idor on /api/orders',
    status: 'confirmed', severity: 'high', category: 'broken-access-control', evidenceIds: ['ev-1'],
  }]
  return {
    listEndpoints: () => endpoints,
    listFacts: () => facts,
    listFindings: () => findings,
    approvedOrigins: () => ['https://app.local', 'https://api.local', 'https://admin.local'],
  }
}

async function drain<T extends { nextCursor: string | null }>(
  fetchPage: (cursor?: string) => Promise<T>,
): Promise<T[]> {
  const pages: T[] = []
  let cursor: string | undefined
  for (;;) {
    const page = await fetchPage(cursor)
    pages.push(page)
    if (!page.nextCursor) return pages
    cursor = page.nextCursor
  }
}

test('planner session is equipped with the five paginated coordinator tools', () => {
  const coordinator = createGraphCoordinator({ deps: fixtureDeps() })
  const handlers = coordinatorPlannerHandlers({ coordinator })
  assert.deepEqual(
    Object.keys(handlers).sort(),
    ['dispatch_investigations', 'query_endpoints', 'query_facts', 'query_findings', 'query_program_graph'],
  )
  const toolNames = buildWorkerTools(handlers, value => value, new AbortController().signal, 64 * 1024, () => undefined)
    .map(tool => tool.name)
  for (const name of Object.keys(handlers)) {
    assert.ok(toolNames.includes(name), `planner must receive ${name}`)
  }
  // Investigator tool sets must not silently inherit coordinator-only read tools.
  assert.ok(!toolNames.includes('board_post'), 'planner session exposes only supplied handlers')
  const bare = buildWorkerTools({}, value => value, new AbortController().signal, 64 * 1024, () => undefined)
    .map(tool => tool.name)
  for (const name of Object.keys(handlers)) {
    assert.ok(!bare.includes(name), `${name} is registered only when its handler exists`)
  }
})

test('>500 endpoints and >200 facts are fully reachable across ≤25-row pages', async () => {
  const coordinator = createGraphCoordinator({ deps: fixtureDeps() })
  const handlers = coordinatorPlannerHandlers({ coordinator })

  const endpointPages = await drain(async cursor => (await handlers.query_endpoints!({ cursor }, new AbortController().signal)) as {
    items: Array<{ id: string }>; nextCursor: string | null; total: number
  })
  const endpointIds = new Set(endpointPages.flatMap(page => page.items.map(item => item.id)))
  assert.equal(endpointIds.size, ENDPOINT_COUNT)
  assert.equal(endpointPages[0].total, ENDPOINT_COUNT)
  for (const page of endpointPages) assert.ok(page.items.length <= 25, 'pages stay context-safe')

  const factPages = await drain(async cursor => (await handlers.query_facts!({ cursor, origin: '*' }, new AbortController().signal)) as {
    items: Array<{ id: string; origin: string }>; nextCursor: string | null
  })
  const factIds = new Set(factPages.flatMap(page => page.items.map(item => item.id)))
  assert.equal(factIds.size, FACT_COUNT)
  const origins = new Set(factPages.flatMap(page => page.items.map(item => item.origin)))
  assert.ok(origins.size >= 2, "origin '*' spans every approved origin for cross-host chaining")
  for (const page of factPages) assert.ok(page.items.length <= 25)
})

test('chain round dispatches parent-evidenced hypotheses with capability bundles', async () => {
  const endpoints: CoordinatorEndpoint[] = [
    endpoint(1, { id: 'ep-admin', origin: 'https://admin.local', method: 'GET', pathTemplate: '/admin/users', roleExclusive: true }),
  ]
  const primitives: ChainPrimitive[] = [
    {
      kind: 'leaked_token', origin: 'https://app.local', value: 'secret:fact-secret',
      evidenceIds: ['fact-secret', 'ev-secret'], factIds: ['fact-secret'], endpoint: '/api/token', method: 'GET',
      detail: 'Leaked credential material recorded as a secret fact (value withheld).',
    },
    {
      kind: 'admin_route', origin: 'https://admin.local', value: 'admin:/admin/users',
      evidenceIds: ['ep-admin'], factIds: [], endpointId: 'ep-admin', endpoint: '/admin/users', method: 'GET',
      detail: 'Role-exclusive endpoint GET /admin/users.',
    },
  ]
  const hypotheses = planChainRound({
    primitives, endpoints, limit: 2,
    approvedOrigins: ['https://app.local', 'https://admin.local'],
  })
  assert.ok(hypotheses.length >= 1)
  const crossOrigin = hypotheses.find(hypothesis => hypothesis.scope === 'cross_origin')
  assert.ok(crossOrigin, 'cross-origin chaining survives the synthesizer deletion')
  assert.ok(crossOrigin!.parentEvidenceIds.includes('fact-secret'))
  assert.ok(crossOrigin!.capabilities.includes('http'))

  const dispatched: Array<{ plan: string[]; parents: string[]; skills: string[] }> = []
  const coordinator = createGraphCoordinator({
    deps: {
      listEndpoints: () => endpoints,
      listFacts: () => [],
      listFindings: () => [],
      approvedOrigins: () => ['https://app.local', 'https://admin.local'],
    },
  })
  const handlers = coordinatorPlannerHandlers({
    coordinator,
    onDispatch: plan => dispatched.push({
      plan: plan.plan.map(step => step.id),
      parents: plan.parentEvidenceIds,
      skills: plan.plan.flatMap(step => step.skills),
    }),
  })
  const plan = await handlers.dispatch_investigations!({
    steps: chainHypothesisDispatchSteps(hypotheses),
    maxSteps: 2,
  }, new AbortController().signal) as { plan: Array<{ parentEvidenceIds: string[]; skills: string[] }> }
  assert.ok(plan.plan.length >= 1)
  assert.ok(plan.plan.every(step => step.parentEvidenceIds.length > 0), 'every dispatch cites parent evidence')
  assert.ok(plan.plan.some(step => step.skills.some(skill => skill === 'chain:leaked_token' || skill === 'chain:admin_route')))
  assert.equal(dispatched.length, 1)
})

test('a 2-hop chain fixture produces two ordered dispatches', () => {
  const hypotheses: ChainHypothesis[] = [
    {
      id: 'chain:h1', scope: 'cross_origin', hops: 2, origin: 'https://app.local',
      chainOrigins: ['https://app.local', 'https://admin.local'], primitiveKinds: ['leaked_token', 'admin_route'],
      parentEvidenceIds: ['fact-secret', 'ep-admin'], title: 'leaked_token → admin_route chain',
      rationale: 'Replay the leaked credential against the role-exclusive route.', probeClasses: ['authz_replay', 'auth_bypass'],
      capabilities: ['http'], confidence: 0.86,
    },
    {
      id: 'chain:h2', scope: 'same_origin', hops: 2, origin: 'https://app.local',
      chainOrigins: ['https://app.local'], primitiveKinds: ['discovered_id', 'stored_write'],
      parentEvidenceIds: ['fact-object', 'fact-stored'], title: 'discovered_id → stored_write chain',
      rationale: 'Persist the marker then read it as another principal.', probeClasses: ['bola_idor', 'stored_xss'],
      capabilities: ['http', 'browser'], confidence: 0.78,
    },
  ]
  const steps = chainHypothesisDispatchSteps(hypotheses)
  assert.equal(steps.length, 2)
  const order = ['https://app.local', 'https://admin.local']
  const plan = createGraphCoordinator({
    deps: { listEndpoints: () => [], listFacts: () => [], listFindings: () => [], approvedOrigins: () => order },
  }).dispatchInvestigations(steps, { approvedOrigins: order, maxSteps: 2 })
  assert.deepEqual(plan.plan.map(step => step.id), ['dispatch-1', 'dispatch-2'])
  assert.deepEqual(plan.plan.map(step => step.origins), [order, ['https://app.local']])
  const dispatch = plan.plan[0]
  assert.deepEqual(dispatch.parentEvidenceIds, ['fact-secret', 'ep-admin'], 'ordered parent evidence is preserved')
  assert.deepEqual(dispatch.capabilities, ['http'])
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

test('ColdGraphCompactor and CrossHostSynthesizer are deleted from the tree', () => {
  assert.equal(existsSync(new URL('../src/server/compactor.ts', import.meta.url)), false)
  const source = readFileSync(new URL('../src/server/execution.ts', import.meta.url), 'utf8')
  assert.ok(!source.includes('ColdGraphCompactor'), 'compactor symbol removed')
  assert.ok(!source.includes('CrossHostSynthesizer'), 'cross-host synthesizer removed')
  assert.ok(!source.includes('runCrossHostSynthesizer'), 'cross-host call site removed')
  assert.ok(source.includes('decideNext'), 'deterministic scheduler guard is wired')
  assert.ok(source.includes('chainHypothesisDispatchSteps'), 'chain round is wired')
  const collect = collectAllPages((offset, limit) => Array.from({ length: Math.max(0, 1200 - offset) }, (_, i) => offset + i).slice(0, limit), 500)
  assert.equal(collect.length, 1200)
})

test('chain round over a real store persists ordered parent-evidenced dispatches', async t => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 500 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  let run = storage.run(runId)
  const origin = run.candidates[0]!.origin
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'recon', 'recon')
  storage.updateWorker(worker.id, { status: 'complete' })

  const endpoint = storage.upsertEndpoint({
    runId, scopeRevision: run.scopeRevision, origin, method: 'GET', pathTemplate: '/admin/users',
    source: 'repo_ast', authRequirement: 'admin', sinkKinds: ['db_query'],
    codeLocation: { repo: 'app', file: 'src/admin.ts', startLine: 10, endLine: 12 },
  })
  const secret = storage.addFact(run, worker, {
    kind: 'secret', origin, summary: 'API token exposed in a client bundle.',
    data: { endpoint: '/admin/users', method: 'GET', roundNo: 1 },
  })
  run = storage.run(runId)

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const internal = execution as unknown as {
    coordinatorDeps: (run: Run) => CoordinatorDeps
    dispatchChainRound: (run: Run, coordinator: ReturnType<typeof createGraphCoordinator>, budget: number, factIds: ReadonlySet<string>) => number
  }
  const deps = internal.coordinatorDeps(run)
  assert.ok(deps.programGraph?.(), 'persisted code locations expose a program graph')
  const coordinator = createGraphCoordinator({ deps, approvedOrigins: deps.approvedOrigins?.() ?? [] })
  assert.ok(endpoint.id)
  const factIds = new Set(deps.listFacts().map(item => item.id))
  assert.ok(factIds.has(secret.id))
  const added = internal.dispatchChainRound(run, coordinator, 24, factIds)
  assert.ok(added >= 1, 'chain round dispatches at least one hypothesis')
  const steps = storage.listChainSteps(runId, run.goalRevision)
  const chainStep = steps.find(step => step.skills.some(skill => skill.startsWith('chain:')))
  assert.ok(chainStep, 'dispatched step carries chain primitive tags')
  assert.ok(chainStep!.dependsOnFactIds.includes(secret.id), 'dispatch cites the parent fact')
  assert.ok(chainStep!.sourceOrigins.includes(origin))
})
