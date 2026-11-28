/**
 * Track B Cut 1 — pure-fact World Graph + lightweight closed-loop planner (behavioral tests only).
 *
 * Covers: deterministic <= 4 KB serialization with exact truncation accounting on a 500-endpoint app,
 * per-principal auth-matrix prioritization and edge/fact caps, compact program-graph controller
 * summary, bounded read-only store collection, mock-provider single-turn parsing with structured
 * parse errors, and the zero-provider-call `$0` / `--no-llm` deterministic floor.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import {
  buildDeterministicFallbackPlan,
  decidePlannerAnswer,
  planWithWorldGraph,
  plannerResponseSchema,
} from '../src/server/llm-planner.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import {
  buildWorldGraphSnapshot,
  collectWorldGraphFromStore,
  serializeWorldGraph,
  type BuildWorldGraphInput,
  type WorldGraphExchangeInput,
  type WorldGraphSnapshot,
} from '../src/server/world-graph.ts'
import { makeStore, setupApprovedRun, startMockLlmServer } from './v4-tier-helpers.ts'

// Loopback mock model endpoints are plaintext HTTP; allow them exactly like the other planner suites.
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN_A = 'https://app.example.test'
const ORIGIN_B = 'https://api.example.test'

function exchange(path: string, personaHandle: string | null, status: number, method = 'GET', origin = ORIGIN_A): WorldGraphExchangeInput {
  return { origin, method, pathAndQuery: path, personaHandle, status }
}

/** Digit-free route segment (`normalizeRouteTemplate` collapses digit-bearing segments to `:id`). */
function word(i: number): string {
  return `res${String(i).padStart(3, '0').replace(/\d/g, d => 'abcdefghij'[Number(d)]!)}`
}

function mockProfile(endpoint: string, overrides: Partial<ResolvedModelProfile> = {}): ResolvedModelProfile {
  return {
    id: 'wg-mock-profile', name: 'World Graph Mock', endpoint, model: 'mock-wg', protocol: 'responses', key: 'sk-test-world-graph',
    priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'off', roleAffinity: 'tactical',
    inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0, healthState: 'closed', cooldownUntil: null, lastError: null,
    ...overrides,
  }
}

/** Synthetic 500-endpoint app: 100 resource prefixes x 5 routes, plus edges/facts/code routes. */
function largeAppInput(): BuildWorldGraphInput {
  const endpoints: BuildWorldGraphInput['endpoints'][number][] = []
  const exchanges: WorldGraphExchangeInput[] = []
  for (let r = 0; r < 100; r += 1) {
    const base = `/api/v1/${word(r)}-with-a-long-descriptive-name`
    for (const [method, suffix] of [['GET', ''], ['GET', '/{id}'], ['POST', ''], ['PATCH', '/{id}'], ['DELETE', '/{id}']] as const) {
      endpoints.push({ origin: ORIGIN_A, method, pathTemplate: `${base}${suffix}` })
    }
    exchanges.push(exchange(`${base}/${1000 + r}`, 'alice', 200), exchange(`${base}/${1000 + r}`, null, r % 2 ? 401 : 200))
  }
  return {
    runId: 'run-large', approvedOrigins: [ORIGIN_A, ORIGIN_B], endpoints, exchanges,
    apiDependencies: Array.from({ length: 40 }, (_, i) => ({
      id: `dep-${i}`, resourceKey: `resource_${i}_identifier`, producerOrigin: ORIGIN_A, producerMethod: 'POST',
      producerPath: `/api/v1/resource-${i}/create`, consumerOrigin: i % 2 ? ORIGIN_B : ORIGIN_A, consumerMethod: 'GET', consumerPath: `/v2/items/${i}`,
    })),
    facts: Array.from({ length: 60 }, (_, i) => ({
      id: `fact-${String(i).padStart(2, '0')}`, origin: ORIGIN_A, kind: i % 3 ? 'note' : 'policy_gap',
      summary: `Observed structured response field difference number ${i} `.repeat(6), data: { route: `/api/v1/resource-${i}` },
    })),
    programGraph: {
      routes: Array.from({ length: 30 }, (_, i) => ({ id: `r${i}`, method: 'POST', path: `/api/v1/controller-${i}`, file: `services/api/controller-${i}.ts`, guards: i % 2 ? ['requireAuth'] : [] })),
      nodes: Array.from({ length: 30 }, (_, i) => ({ id: `s${i}`, kind: 'sink', symbol: 'db.query', sinkKind: 'sql' })),
      edges: Array.from({ length: 30 }, (_, i) => ({ fromId: `r${i}`, toId: `s${i}` })),
    },
  }
}

test('500-endpoint app serializes strictly <= 4096 UTF-8 bytes with exact truncation accounting', () => {
  const input = largeAppInput()
  const snapshot = buildWorldGraphSnapshot(input)
  assert.equal(snapshot.groups.length + snapshot.truncation.omittedGroups, 100, 'build-time group cap accounts for every prefix group')
  const json = serializeWorldGraph(snapshot, 4096)
  assert.ok(Buffer.byteLength(json, 'utf8') <= 4096, `serialized ${Buffer.byteLength(json, 'utf8')} bytes`)
  const parsed = JSON.parse(json) as WorldGraphSnapshot
  assert.equal(parsed.truncation.byteBudget, 4096)
  assert.equal(parsed.truncation.serializedBytes, Buffer.byteLength(json, 'utf8'), 'serializedBytes is the exact output size')
  assert.equal(parsed.groups.length + parsed.truncation.omittedGroups, 100)
  assert.equal(parsed.edges.length + parsed.truncation.omittedEdges, 40)
  assert.equal(parsed.facts.length + parsed.truncation.omittedFacts, 60)
  assert.equal(parsed.codeRoutes.length + parsed.truncation.omittedCodeRoutes, 30)
  assert.ok(parsed.groups.length >= 1, 'highest-priority groups survive pruning')
  assert.equal(serializeWorldGraph(snapshot, 4096), json, 'serialization is deterministic')
  assert.equal(snapshot.truncation.serializedBytes, undefined, 'input snapshot is not mutated')

  // Multi-byte summaries still respect the UTF-8 byte budget (not the UTF-16 length).
  const wide = buildWorldGraphSnapshot({ ...input, facts: input.facts!.map(f => ({ ...f, summary: '観測されたレスポンス差分 '.repeat(20) })) })
  const wideJson = serializeWorldGraph(wide, 2048)
  assert.ok(Buffer.byteLength(wideJson, 'utf8') <= 2048)
  const wideParsed = JSON.parse(wideJson) as WorldGraphSnapshot
  assert.equal(wideParsed.facts.length + wideParsed.truncation.omittedFacts, 60)
})

test('per-principal auth matrix ranks auth-asymmetric / mutating / unconfirmed groups first and caps edges/facts', () => {
  const snapshot = buildWorldGraphSnapshot({
    runId: 'run-matrix',
    endpoints: [
      { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/v1/catalog' },
      { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/v1/reports/{id}' },
      { origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/v1/orders' },
      { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/v1/orders/{id}' },
      { origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/v1/invoices/{id}' },
      { origin: ORIGIN_A, method: 'GET', pathTemplate: '/health' },
    ],
    exchanges: [
      exchange('/api/v1/orders/41', 'alice', 200), exchange('/api/v1/orders/41', 'bob', 403), exchange('/api/v1/orders/41', null, 401),
      exchange('/api/v1/orders', 'alice', 201, 'POST'), exchange('/api/v1/orders', 'bob', 500, 'POST'),
      exchange('/api/v1/catalog', 'alice', 200), exchange('/api/v1/catalog', 'bob', 200), exchange('/api/v1/catalog', null, 200),
      exchange('/api/v1/reports/9', 'alice', 200), exchange('/api/v1/reports/9', null, 401),
      exchange('/api/v1/invoices/7', 'alice', 200), exchange('/api/v1/invoices/7', 'bob', 200),
    ],
    confirmedRefs: [{ origin: ORIGIN_A, method: 'GET', path: '/api/v1/reports/123' }],
    apiDependencies: Array.from({ length: 24 }, (_, i) => ({
      id: `dep-${String(i).padStart(2, '0')}`, resourceKey: `order_id_${i}`, producerOrigin: ORIGIN_A, producerMethod: 'POST', producerPath: `/api/v1/orders/${i}`,
      consumerOrigin: i < 3 ? ORIGIN_B : ORIGIN_A, consumerMethod: 'GET', consumerPath: `/v2/fulfil/${i}`,
    })),
    ledgerEdges: [{ edgeId: 'edge-ledger-1', fromOrigin: ORIGIN_A, from: 'member value_binding', toOrigin: ORIGIN_B, to: 'scoped_token http' }],
    facts: Array.from({ length: 30 }, (_, i) => ({
      id: `fact-${String(i).padStart(2, '0')}`, origin: ORIGIN_A, kind: 'note', summary: `Observed field ${i} ${'x'.repeat(300)}`,
      data: i === 29 ? { subkind: 'det_lead', route: '/api/v1/orders/5' } : {},
    })),
  })
  const orders = snapshot.groups.find(g => g.prefix === '/api/v1/orders')!
  assert.deepEqual(orders.authMatrix.alice, { '2xx': 2, '401': 0, '403': 0, other: 0 })
  assert.deepEqual(orders.authMatrix.bob, { '2xx': 0, '401': 0, '403': 1, other: 1 })
  assert.deepEqual(orders.authMatrix.anon, { '2xx': 0, '401': 1, '403': 0, other: 0 }, "null persona keys as 'anon'")
  assert.equal(orders.authAsymmetric, true)
  assert.equal(orders.mutating, true)
  assert.deepEqual(orders.methods, ['GET', 'POST'])
  assert.equal(snapshot.groups[0]!.prefix, '/api/v1/orders', 'asymmetric + mutating + unconfirmed group ranks first')

  const rank = (prefix: string) => snapshot.groups.findIndex(g => g.prefix === prefix)
  const catalog = snapshot.groups[rank('/api/v1/catalog')]!
  assert.equal(catalog.authAsymmetric, false, 'uniform 2xx across principals is symmetric')
  const reports = snapshot.groups[rank('/api/v1/reports')]!
  assert.equal(reports.confirmed, true, 'fully confirmed group is flagged')
  assert.ok(rank('/api/v1/invoices') < rank('/api/v1/reports') && rank('/api/v1/catalog') < rank('/api/v1/reports'),
    'unconfirmed read-only groups outrank an already-confirmed group')
  assert.equal(rank('/api/v1/reports'), snapshot.groups.length - 1, 'confirmed group ranks last')
  assert.ok(snapshot.groups.every(g => g.sampleTemplates.length <= 3))

  assert.equal(snapshot.edges.length, 16)
  assert.equal(snapshot.truncation.omittedEdges, 25 - 16)
  assert.ok(snapshot.edges.slice(0, 4).every(e => e.crossOrigin), 'cross-origin edges first')
  assert.equal(snapshot.edges[0]!.hostVerified, true, 'host-verified cross-origin ledger edge leads')
  assert.equal(snapshot.facts.length, 16)
  assert.equal(snapshot.truncation.omittedFacts, 14)
  assert.equal(snapshot.facts[0]!.id, 'fact-29', 'unconfirmed lead fact ranks first')
  assert.equal(snapshot.facts[0]!.lead, true)
  assert.ok(snapshot.facts.every(f => f.summary.length <= 120), 'fact summaries truncated to <= 120 chars')
})

test('compact program-graph controller summary keeps <= 12 routes with guards/sinks, unguarded sinks first', () => {
  const base: BuildWorldGraphInput = { runId: 'run-code', endpoints: [], exchanges: [] }
  assert.deepEqual(buildWorldGraphSnapshot(base).codeRoutes, [], 'no program graph -> no code routes')
  const snapshot = buildWorldGraphSnapshot({
    ...base,
    programGraph: {
      routes: Array.from({ length: 20 }, (_, i) => ({
        id: `route-${i}`, method: i % 2 ? 'get' : 'post', path: `/api/v1/widgets/${word(i)}`, file: `src/controllers/widgets-${i}.ts`,
        guards: i < 10 ? ['requireSession', 'ownsWidget'] : [],
      })),
      nodes: [{ id: 'sink-a', kind: 'sink', sinkKind: 'sql' }, { id: 'sink-b', kind: 'sink', sinkKind: 'fetch' }, { id: 'mw', kind: 'middleware' }],
      edges: [{ fromId: 'route-12', toId: 'sink-a' }, { fromId: 'route-12', toId: 'sink-b' }, { fromId: 'route-3', toId: 'sink-a' }, { fromId: 'route-4', toId: 'mw' }],
    },
  })
  assert.equal(snapshot.codeRoutes.length, 12)
  assert.equal(snapshot.truncation.omittedCodeRoutes, 8)
  assert.deepEqual(snapshot.codeRoutes[0], { method: 'POST', path: `/api/v1/widgets/${word(12)}`, file: 'src/controllers/widgets-12.ts', guards: [], sinks: ['sql', 'fetch'] })
  assert.deepEqual(snapshot.codeRoutes[1]!.sinks, ['sql'])
  assert.deepEqual(snapshot.codeRoutes[1]!.guards, ['requireSession', 'ownsWidget'])
})

test('collectWorldGraphFromStore is read-only and bounds the broker_exchanges projection to 250 rows', async (t) => {
  const { storage } = makeStore(t, 'kovo-world-graph-')
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], environment: 'public' })
  const asset = run.candidates.find(c => c.origin === ORIGIN_A)!
  const worker = storage.makeWorker(run, 'investigation', asset, 'World graph seed', 'Seed observations', { sourceOrigins: [ORIGIN_A, ORIGIN_B] })
  const producer = storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/v1/orders', source: 'openapi', riskScore: 90 })
  storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/v1/orders/{id}', source: 'openapi' })
  const consumer = storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: ORIGIN_B, method: 'GET', pathTemplate: '/v2/shipments/{id}', source: 'spa_crawl' })
  storage.recordApiDependency({ runId, producerEndpointId: producer.id, consumerEndpointId: consumer.id, resourceKey: 'order_id' })
  for (let i = 0; i < 300; i += 1) {
    storage.recordExchange({
      runId, assignmentId: worker.id, scopeRevision: run.scopeRevision, origin: ORIGIN_A, finalOrigin: ORIGIN_A, redirectOrigins: [],
      method: 'GET', pathAndQuery: `/api/v1/orders/${i}`, personaHandle: i % 2 ? null : 'alice', status: i % 2 ? 401 : 200,
      mediaType: 'application/json', reqHeaders: {}, respHeaders: {}, body: '', durationMs: 1,
    })
  }
  const lead = storage.addFact(run, worker, { kind: 'policy_gap', origin: ORIGIN_A, summary: 'Order detail returns 200 for the owner and 401 anonymously.', data: { route: '/api/v1/orders/7' } })
  const ledger = storage.capabilityLedger(runId)
  const capA = formatDerivedCapabilityHandle('wg_1', 'session')
  const capB = formatDerivedCapabilityHandle('wg_2', 'token')
  ledger.addCapability({ capId: capA, kind: 'identity_session', provenance: 'attacker_seed', tenantScope: 'org_a', actorPersona: 'alice', serviceOrigin: ORIGIN_A, surface: 'http', artifactDigest: 'a'.repeat(64), artifactSummary: 'seed session', createdAtMs: 1000 })
  ledger.addCapability({ capId: capB, kind: 'scoped_token', provenance: 'derived_hop', tenantScope: 'org_a', actorPersona: 'alice', serviceOrigin: ORIGIN_B, surface: 'http', artifactDigest: 'b'.repeat(64), artifactSummary: 'derived token', createdAtMs: 1100 })
  ledger.addCausalEdge({ preconditionCapIds: [capA], actorContext: { persona: 'alice', serviceOrigin: ORIGIN_A }, hopReceiptId: 'rcpt-wg-1', edgeBindingKind: 'value_binding', postconditionCapId: capB, sourceTimestampMs: 1000, targetTimestampMs: 1100 })

  const prepared: string[] = []
  const client = storage.client
  const originalPrepare = client.prepare.bind(client)
  client.prepare = ((sql: string) => { prepared.push(sql); return originalPrepare(sql) }) as typeof client.prepare
  const changesBefore = (originalPrepare('SELECT total_changes() AS n').get() as { n: number }).n
  const warnings: string[] = []
  let snapshot: WorldGraphSnapshot
  try {
    snapshot = collectWorldGraphFromStore(storage, storage.run(runId), { approvedOrigins: [ORIGIN_A, ORIGIN_B], onWarning: stage => warnings.push(stage) })
  } finally {
    client.prepare = originalPrepare
  }
  const changesAfter = (originalPrepare('SELECT total_changes() AS n').get() as { n: number }).n
  assert.equal(changesAfter, changesBefore, 'collection performs zero DB writes')
  assert.ok(prepared.every(sql => !/^\s*(?:INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql)), 'only read-only statements are prepared')
  assert.ok(prepared.some(sql => /FROM broker_exchanges[\s\S]*LIMIT 250/.test(sql)), 'broker_exchanges projection is LIMIT 250')
  assert.deepEqual(warnings, [])
  assert.equal(snapshot.stats.exchangesSampled, 250)
  const orders = snapshot.groups.find(g => g.origin === ORIGIN_A && g.prefix === '/api/v1/orders')!
  assert.equal(orders.authMatrix.alice!['2xx'] + orders.authMatrix.anon!['401'], 250)
  assert.equal(orders.authAsymmetric, true)
  assert.ok(snapshot.edges.some(e => e.source === 'api_dependency' && e.crossOrigin && e.toOrigin === ORIGIN_B && e.resourceKey === 'order_id'))
  assert.ok(snapshot.edges.some(e => e.source === 'capability_ledger' && e.hostVerified && e.crossOrigin))
  assert.ok(snapshot.facts.some(f => f.id === lead.id && f.lead && f.route === '/api/v1/orders/:id'))
})

test('mock-provider single turn parses valid JSON into typed proposals and returns structured parse errors without throwing', async (t) => {
  const snapshot = buildWorldGraphSnapshot({ runId: 'run-llm', endpoints: [{ origin: ORIGIN_A, method: 'POST', pathTemplate: '/api/v1/orders' }], exchanges: [] })
  const answers = [
    '```json\n' + JSON.stringify({
      summary: 'Verify order boundary.', done: false, cancelStepIds: [],
      newSteps: [
        { title: 'Order boundary', hypothesis: 'Verify POST /api/v1/orders access boundary per principal.', category: 'broken-access-control', priority: 85, origins: [ORIGIN_A], skills: ['access-control-bola-bfla'], dependsOnFactIds: [], dependsOnStepIds: [] },
        { title: 'Second', hypothesis: 'Second hypothesis.', origins: [ORIGIN_A] },
        { title: 'Third', hypothesis: 'Third hypothesis.', origins: [ORIGIN_A] },
      ],
    }) + '\n```',
    'NOT_VALID_JSON {{{ broken',
    JSON.stringify({ newSteps: [{ title: '', hypothesis: 'x', origins: [] }] }),
  ]
  const llm = await startMockLlmServer(t, (_call, idx) => ({ type: 'text', text: answers[idx] ?? '{}' }))
  const base = { runId: 'run-llm', goal: 'Verify authorization boundaries', roundNo: 2, snapshot, approvedOrigins: [ORIGIN_A], profiles: [mockProfile(llm.endpoint)], remainingStepCap: 2 }

  const ok = await planWithWorldGraph(base)
  assert.equal(ok.mode, 'llm')
  assert.equal(ok.parseError, null)
  assert.equal(ok.providerCalls, 1)
  assert.equal(ok.newSteps.length, 2, 'proposals respect remainingStepCap')
  assert.equal(ok.droppedSteps, 1)
  assert.deepEqual(ok.newSteps[0]!.skills, ['access-control-bola-bfla'])
  assert.equal(ok.newSteps[1]!.category, 'misconfig-exposure', 'schema defaults applied')
  assert.deepEqual(ok.newSteps[1]!.dependsOnFactIds, [])
  assert.equal(llm.calls.length, 1)
  const sentInput = JSON.stringify(llm.calls[0]!.body.input)
  assert.ok(sentInput.includes('WORLD_GRAPH=') && sentInput.includes('newSteps') && sentInput.includes('cancelStepIds'))
  assert.deepEqual(llm.calls[0]!.body.tools ?? [], [], 'single tool-free turn')

  const badJson = await planWithWorldGraph(base)
  assert.equal(badJson.parseError?.stage, 'json')
  assert.deepEqual(badJson.newSteps, [])
  assert.equal(badJson.usedFallback, false)
  assert.ok(badJson.rawLength > 0)

  const badSchema = await planWithWorldGraph(base)
  assert.equal(badSchema.parseError?.stage, 'schema')
  assert.match(badSchema.parseError!.message, /newSteps\.0\./)
  assert.deepEqual(badSchema.newSteps, [])

  const unreachable = await planWithWorldGraph({ ...base, profiles: [mockProfile('http://127.0.0.1:9/v1')] })
  assert.equal(unreachable.parseError?.stage, 'provider')
  assert.deepEqual(unreachable.newSteps, [])

  const parsed = decidePlannerAnswer(JSON.stringify({ newSteps: [] }), 4)
  assert.equal(parsed.parseError, null)
  assert.equal(plannerResponseSchema.safeParse({ newSteps: [{ title: 't', hypothesis: 'h', origins: [ORIGIN_A] }] }).success, true)
})

test('$0 / --no-llm deterministic floor makes zero provider calls and synthesizes bounded proposals', async (t) => {
  const llm = await startMockLlmServer(t, () => ({ type: 'text', text: '{}' }))
  const snapshot = buildWorldGraphSnapshot({
    runId: 'run-floor', approvedOrigins: [ORIGIN_A, ORIGIN_B],
    endpoints: [{ origin: ORIGIN_A, method: 'GET', pathTemplate: '/api/v1/catalog' }],
    exchanges: [
      exchange('/api/v1/orders/4', 'alice', 200), exchange('/api/v1/orders/4', null, 401),
      exchange('/api/v1/payouts/2', 'alice', 200, 'PATCH'), exchange('/api/v1/payouts/2', 'bob', 403, 'PATCH'),
      exchange('/api/v1/catalog', 'alice', 200), exchange('/api/v1/catalog', null, 200),
    ],
    facts: [
      { id: 'lead-1', origin: ORIGIN_A, kind: 'note', summary: 'Deterministic lead on export route.', data: { subkind: 'det_lead', route: '/api/v1/exports/9' } },
      { id: 'note-1', origin: ORIGIN_A, kind: 'note', summary: 'Plain observation without a route.' },
    ],
    apiDependencies: [{ id: 'dep-x', resourceKey: 'payout_id', producerOrigin: ORIGIN_A, producerMethod: 'POST', producerPath: '/api/v1/payouts', consumerOrigin: ORIGIN_B, consumerMethod: 'GET', consumerPath: '/v2/ledger/{id}' }],
  })
  const base = { runId: 'run-floor', goal: 'Verify boundaries', roundNo: 1, snapshot, approvedOrigins: [ORIGIN_A, ORIGIN_B], remainingStepCap: 10 }

  for (const variant of [
    { profiles: [] as ResolvedModelProfile[] },
    { profiles: [mockProfile(llm.endpoint, { enabled: false })] },
    { profiles: [mockProfile(llm.endpoint)], noLlm: true },
  ]) {
    const plan = await planWithWorldGraph({ ...base, ...variant })
    assert.equal(plan.mode, 'deterministic-fallback')
    assert.equal(plan.usedFallback, true)
    assert.equal(plan.providerCalls, 0)
    assert.equal(plan.parseError, null)
    assert.equal(plan.newSteps.length, 4, 'two asymmetric groups + one lead + one cross-origin edge')
    assert.ok(plan.newSteps.every(step => plannerResponseSchema.shape.newSteps.safeParse([step]).success), 'proposals satisfy the shared contract')
  }
  assert.equal(llm.calls.length, 0, 'zero provider calls on the $0 floor')

  const steps = buildDeterministicFallbackPlan({ snapshot, approvedOrigins: [ORIGIN_A, ORIGIN_B], remainingStepCap: 10 })
  assert.ok(steps.some(s => s.category === 'broken-access-control' && s.hypothesis.includes('/api/v1/payouts/:id') && s.priority === 88))
  assert.ok(steps.some(s => s.dependsOnFactIds.includes('lead-1') && s.hypothesis.includes('/api/v1/exports/:id')))
  assert.ok(steps.some(s => s.skills.includes('cross-host-chaining') && s.origins[0] === ORIGIN_B))
  assert.ok(!steps.some(s => s.title.includes('/api/v1/catalog')), 'symmetric groups produce no proposals')
  assert.ok(!steps.some(s => s.dependsOnFactIds.includes('note-1')), 'route-less non-lead facts produce no proposals')

  assert.equal(buildDeterministicFallbackPlan({ snapshot, approvedOrigins: [ORIGIN_A, ORIGIN_B], remainingStepCap: 2 }).length, 2)
  assert.equal(buildDeterministicFallbackPlan({ snapshot, approvedOrigins: [ORIGIN_A], remainingStepCap: 10, maxNewSteps: 3 }).length, 3)
  assert.deepEqual(buildDeterministicFallbackPlan({ snapshot, approvedOrigins: [ORIGIN_A, ORIGIN_B], remainingStepCap: 0 }), [])
  const onlyA = buildDeterministicFallbackPlan({ snapshot, approvedOrigins: [ORIGIN_A], remainingStepCap: 10 })
  assert.ok(onlyA.every(s => s.origins.every(o => o === ORIGIN_A)), 'proposals stay inside approved origins')
})
