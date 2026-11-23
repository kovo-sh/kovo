/**
 * v6 determinism contract: identical inputs produce the identical probe plan/confirmation set.
 *
 * The floor is measured by repeating the same cell and comparing confirmed site ids; at the unit
 * level that reduces to canonical ordering:
 *  - endpoint ranking / phase-0 plan selection / variant collapse are total orders that never
 *    inherit store row order (SQLite breaks risk ties on random row ids);
 *  - persona pairs and harvested object ids are canonical, so probe payloads are byte-identical;
 *  - `det_lead` upgrade selection is severity/identity ordered, not fact-row ordered;
 *  - Phase A runs the same deep engine policy as `--no-llm`, sequentially before agents;
 *  - a floor lead emitted is always either consumed or provably already confirmed.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import { Execution, selectRankedProbeTargets } from '../src/server/execution.ts'
import type { ChainStep, Run } from '../src/server/store.ts'
import {
  collapseRouteVariants,
  enumerateHypotheses,
  rankEndpoints,
  rankEngineParams,
} from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint, EngineParam } from '../src/server/deterministic-engine.ts'
import { graphLeadTargets } from '../src/server/graph-leads.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

type LaneOptions = { signal?: AbortSignal; maxDurationMs?: number; onAssignment?: (assignmentId: string) => void }

type Internals = {
  driveInvestigation: (run: Run, profiles: readonly unknown[]) => void
  startInvestigationStep: (run: Run, step: ChainStep, profiles: readonly unknown[]) => void
  runEngineInvestigation: (run: Run, opts?: LaneOptions) => Promise<void>
  queueDetLeadUpgradeSteps: (run: Run, origins: ReadonlySet<string>, budget: number) => number
  recordFloorMetrics: (runId: string, reason: string) => void
  deterministicLaneDeadlineMs: () => number
  detLeadConsumed: Set<string>
  prePhase0SeededSteps: Map<string, boolean>
}

function internals(execution: Execution): Internals {
  return execution as unknown as Internals
}

function laneKey(run: Run): string {
  return `${run.id}:${run.goalRevision}:${run.scopeRevision}`
}

function endpoint(overrides: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'id' | 'method' | 'pathTemplate'>): EngineEndpoint {
  return {
    origin: 'http://127.0.0.1:4100',
    params: [],
    riskScore: 40,
    ...overrides,
  }
}

function permutations<T>(items: readonly T[]): T[][] {
  return [[...items], [...items].reverse(), [...items].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))]
}

test('endpoint ranking is a total order independent of store arrival order', () => {
  const endpoints: EngineEndpoint[] = [
    endpoint({ id: 'e1', method: 'GET', pathTemplate: '/api/invoices' }),
    endpoint({ id: 'e2', method: 'POST', pathTemplate: '/api/invoices' }),
    endpoint({ id: 'e3', method: 'GET', pathTemplate: '/api/invoices' }),
    endpoint({ id: 'e4', method: 'DELETE', pathTemplate: '/api/invoices' }),
    endpoint({ id: 'e5', method: 'GET', pathTemplate: '/api/orders' }),
  ]
  const keys = permutations(endpoints).map(order =>
    rankEndpoints(order).map(ep => `${ep.origin}|${ep.method.toUpperCase()}|${ep.pathTemplate}`))
  assert.deepEqual(keys[1], keys[0])
  assert.deepEqual(keys[2], keys[0])
  assert.equal(keys[0].length, endpoints.length, 'no endpoint is dropped by ranking')
})

test('phase-0 probe-plan selection and route collapse never depend on input order', () => {
  const endpoints: EngineEndpoint[] = [
    endpoint({ id: 'a', method: 'GET', pathTemplate: '/api/items', riskScore: 50 }),
    endpoint({ id: 'b', method: 'POST', pathTemplate: '/api/items', riskScore: 50 }),
    endpoint({ id: 'c', method: 'GET', pathTemplate: '/api/items/:id', riskScore: 50 }),
    endpoint({ id: 'd', method: 'GET', pathTemplate: '/api/items/:itemId', riskScore: 50 }),
    endpoint({ id: 'e', method: 'GET', pathTemplate: '/api/users/:id', riskScore: 50 }),
  ]
  const plan = { totalRoutes: 5, sample: ['GET /api/items', 'GET /api/users/:id'] }
  const selected = permutations(endpoints).map(order =>
    selectRankedProbeTargets(order, plan, { cap: 3 }).targets.map(ep => `${ep.method} ${ep.pathTemplate}`))
  assert.deepEqual(selected[1], selected[0])
  assert.deepEqual(selected[2], selected[0])
  assert.deepEqual(selected[0].slice(0, 2), ['GET /api/items', 'GET /api/users/:id'])

  const collapsed = permutations(endpoints).map(order =>
    collapseRouteVariants(order).map(ep => `${ep.method} ${ep.pathTemplate}`).sort())
  assert.deepEqual(collapsed[1], collapsed[0])
  assert.deepEqual(collapsed[2], collapsed[0])
})

test('enumeration, persona pairs and harvested ids are canonical', () => {
  const endpoints: EngineEndpoint[] = [
    endpoint({
      id: 'ep-invoice',
      method: 'GET',
      pathTemplate: '/api/invoices/:id',
      riskScore: 55,
      params: [{ name: 'id', location: 'path', declaredType: 'integer' }],
    }),
    endpoint({
      id: 'ep-search',
      method: 'GET',
      pathTemplate: '/api/search',
      riskScore: 45,
      params: [
        { name: 'q', location: 'query', declaredType: 'string' },
        { name: 'sort', location: 'query', declaredType: 'string' },
      ],
    }),
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['ep-invoice', {
      ownerIds: ['10', '2', '7'],
      otherIds: ['11', '3'],
      fields: ['id', 'total', 'status'],
      values: { total: ['42'], status: ['paid'] },
      otherValues: {},
      seedValues: ['invoice'],
      activeQueryParams: [],
      viewerIds: ['12', '4'],
    }],
    ['ep-search', {
      ownerIds: [],
      otherIds: [],
      fields: [],
      values: {},
      otherValues: {},
      seedValues: [],
      activeQueryParams: ['q'],
      viewerIds: [],
    }],
  ])
  const personas = [
    { handle: 'zara', roleLabel: 'member (beta)', privilege: 'member' as const, tenant: 'beta' },
    { handle: 'alice', roleLabel: 'member (acme)', privilege: 'member' as const, tenant: 'acme' },
    { handle: 'bob', roleLabel: 'viewer (acme)', privilege: 'viewer' as const, tenant: 'acme' },
    { handle: 'root', roleLabel: 'admin', privilege: 'admin' as const },
  ]
  const run = (order: readonly EngineEndpoint[], harvestOrder: EndpointHarvest[]) => enumerateHypotheses(
    rankEndpoints(collapseRouteVariants(order)),
    new Map([
      ['ep-invoice', harvestOrder[0]!],
      ['ep-search', harvestOrder[1]!],
    ]),
    { tier: 3, personas: [...personas].reverse() },
  ).map(hyp => ({
    key: hyp.key,
    probeClass: hyp.probeClass,
    path: hyp.pathAndQuery,
    owner: hyp.ownerPersona ?? null,
    other: hyp.otherPersona ?? null,
    ids: hyp.resourceIds ?? [],
  }))

  const a = run(endpoints, [...harvests.values()])
  const b = run([...endpoints].reverse(), [...harvests.values()])
  assert.deepEqual(b, a, 'permuted endpoint order produces the identical hypothesis set')
  assert.ok(a.length > 0)
  assert.ok(a.some(hyp => hyp.ids.length > 0), 'object-level hypotheses carry harvested ids')
})

test('parameter ranking is stable on equal scores', () => {
  const params: EngineParam[] = [
    { name: 'zeta', location: 'query', declaredType: 'string' },
    { name: 'alpha', location: 'query', declaredType: 'string' },
    { name: 'beta', location: 'query', declaredType: 'string' },
  ]
  const a = rankEngineParams(params).map(item => item.param.name)
  const b = rankEngineParams([...params].reverse()).map(item => item.param.name)
  assert.deepEqual(a, ['alpha', 'beta', 'zeta'])
  assert.deepEqual(b, a)
})

test('program-graph leads are severity/identity ordered, not fact-row ordered', () => {
  const facts = [
    { origin: 'http://b.example', data: { kind: 'det_lead', source: 'program_graph', method: 'GET', endpoint: '/b', severity: 'medium' } },
    { origin: 'http://a.example', data: { kind: 'det_lead', source: 'program_graph', method: 'POST', endpoint: '/z', severity: 'critical' } },
    { origin: 'http://a.example', data: { kind: 'det_lead', source: 'program_graph', method: 'GET', endpoint: '/a', severity: 'high' } },
  ]
  const a = graphLeadTargets(facts).map(target => `${target.method} ${target.origin}${target.pathTemplate}`)
  const b = graphLeadTargets([...facts].reverse()).map(target => `${target.method} ${target.origin}${target.pathTemplate}`)
  assert.deepEqual(a, ['POST http://a.example/z', 'GET http://a.example/a', 'GET http://b.example/b'])
  assert.deepEqual(b, a)
})

test('Phase A runs the deep floor sequentially before any agent dispatch', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 5_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const assetIds = run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.id)
  const step = storage.addChainStep(run, {
    title: 'BOLA matrix probe',
    hypothesis: 'Cross-persona read differential on the invoice route.',
    category: 'broken-access-control',
    priority: 60,
    targetAssetIds: assetIds,
    sourceOrigins: [origin],
  } as never)
  storage.updateChainStep(step.id, { status: 'ready' })

  const execution = new Execution(storage, { deterministicSweep: true, maxDurationMs: 600_000 })
  t.after(() => execution.stop())
  internals(execution).prePhase0SeededSteps.set(laneKey(run), false)

  let releaseFloor: () => void = () => undefined
  const floor = new Promise<void>(resolve => { releaseFloor = resolve })
  const floorCalls: Array<{ maxDurationMs?: number }> = []
  internals(execution).runEngineInvestigation = async (_run, opts = {}) => {
    floorCalls.push({ maxDurationMs: opts.maxDurationMs })
    await floor
  }
  const dispatched: string[] = []
  internals(execution).startInvestigationStep = (_run, chainStep) => { dispatched.push(chainStep.id) }

  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(floorCalls.length, 1, 'floor starts first')
  assert.equal(floorCalls[0].maxDurationMs, 168_000, 'Phase A cap = min(180 s, 28% of wall)')
  assert.equal(dispatched.length, 0, 'no agent dispatch while the floor is in flight')

  releaseFloor()
  await delay(20)
  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])
  assert.equal(dispatched.length, 1, 'agents dispatch only after Phase A settles')
})

test('floor lead invariant: emitted det_lead facts are consumed into upgrade steps', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 2_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const origin = run.candidates.find(c => run.approved.includes(c.id))!.origin
  const assignment = storage.makeWorker(run, 'investigation', run.candidates[0], 'floor', 'floor')
  const claimed = storage.updateWorker(assignment.id, { status: 'running', lease: randomUUID() })!

  for (const [endpoint, method, probeClass] of [
    ['/api/relay', 'POST', 'ssrf_canary'],
    ['/api/search', 'GET', 'sqli_boolean'],
    ['/api/render', 'POST', 'ssti_math'],
  ] as const) {
    storage.addFact(run, claimed, {
      kind: 'note',
      origin,
      summary: `Unverified deterministic lead (${probeClass})`,
      data: { kind: 'det_lead', source: 'deterministic_engine', probeClass, endpoint, method, reason: 'differential' },
    })
    storage.event(runId, 'deterministic_engine.lead', `lead ${probeClass}`, { endpoint, probeClass })
  }

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const created = internals(execution).queueDetLeadUpgradeSteps(
    storage.run(runId),
    new Set([origin]),
    Math.max(10, storage.listChainSteps(runId, run.goalRevision).length + 10),
  )
  assert.ok(created > 0, 'floor leads become prioritized upgrade assignments')
  assert.ok(internals(execution).detLeadConsumed.size > 0)

  internals(execution).recordFloorMetrics(runId, 'test')
  const summary = storage.eventsAfter(runId, 0).filter(event => event.kind === 'deterministic_floor.summary').at(-1)
  assert.ok(summary, 'final deterministic_floor.summary is emitted')
  const detail = summary!.detail as Record<string, unknown>
  for (const key of [
    'floorConfirmed', 'floorStandaloneExpected', 'preservationRatio', 'agenticConfirmed',
    'floorLeadsEmitted', 'floorLeadsConsumed', 'laneWallMs', 'floorRequests', 'phaseTimings',
  ]) {
    assert.ok(key in detail, `summary exposes ${key}`)
  }
  assert.equal(detail.floorLeadsEmitted, 3)
  assert.ok(Number(detail.floorLeadsConsumed) > 0, 'emitted leads are consumed, not stranded')
})

test('floor summary metrics survive event-log pagination (deep floor emits >3k events)', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 2_000 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  for (let i = 0; i < 3_500; i += 1) storage.event(runId, 'deterministic_engine.probe', `probe ${i}`, { i })
  storage.event(runId, 'deterministic_engine.summary', 'floor summary', { requestsUsed: 1_161, confirmed: 9, stoppedReason: 'complete' })
  storage.event(runId, 'deterministic_engine.lead', 'lead', { endpoint: '/api/x' })

  internals(execution).recordFloorMetrics(runId, 'phase3')
  const summary = storage.eventsAfter(runId, 0, 5_000).filter(event => event.kind === 'deterministic_floor.summary').at(-1)
  assert.ok(summary, 'summary emitted after a >3k-event floor')
  const detail = summary!.detail as Record<string, unknown>
  assert.equal(detail.floorRequests, 1_161)
  assert.equal(detail.floorStandaloneExpected, 9)
  assert.equal(detail.floorLeadsEmitted, 1)
})
