/**
 * Capability misses: the four named held-out gaps and the general primitives that close them.
 *
 * No benchmark literals, no Docker: every case is a fake surface + fake broker.
 *  - JWT token-boundary routes must rank inside the engine's 120-route prefix and form an
 *    `auth_protocol` hypothesis even when the cookie session is rejected.
 *  - Race conversion probes must form in any disposable environment (never `prod_readonly`),
 *    resolve the addressed object id, read the conserved value through a read-only family readback,
 *    and burst an amount the conserved value can actually fund.
 *  - Race confirmation still requires the HTTP/2 barrier, full acknowledgement and an under-debit,
 *    with a serial control that debits everything.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  classifyRaceMode,
  endpointRiskScore,
  engineTriagePrefix,
  enumerateHypotheses,
  probeRaceDoubleSpend,
  shouldScheduleTimingFollowUp,
} from '../src/server/deterministic-engine.ts'
import type {
  DeterministicEngineInput,
  EndpointHarvest,
  EngineEndpoint,
  EngineHypothesis,
  EnginePersona,
} from '../src/server/deterministic-engine.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { baseFields } from '../src/server/deterministic-specs.ts'

const origin = 'http://127.0.0.1:4100'

const personas: EnginePersona[] = [
  { handle: 'owner', roleLabel: 'owner (store)', privilege: 'admin', tenant: 'store-a' },
  { handle: 'viewer', roleLabel: 'viewer (store)', privilege: 'viewer', tenant: 'store-a' },
]

function endpoint(over: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'method' | 'pathTemplate'>): EngineEndpoint {
  return {
    id: `${over.method}:${over.pathTemplate}`,
    origin,
    params: [],
    riskScore: 40,
    ...over,
  }
}

function harvest(over: Partial<EndpointHarvest> = {}): EndpointHarvest {
  return {
    ownerIds: [],
    otherIds: [],
    fields: [],
    values: {},
    otherValues: {},
    seedValues: [],
    activeQueryParams: [],
    ...over,
  }
}

function raceHypothesis(surface: EngineEndpoint[], harvests: Map<string, EndpointHarvest>, mode: 'ephemeral_lab' | 'staging_isolated' | 'prod_readonly') {
  const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas, environmentMode: mode })
  return hypotheses.find(candidate => candidate.raceBurst === true)
}

// ---------------------------------------------------------------------------
// Ranking: a token-boundary read must survive the engine's route prefix
// ---------------------------------------------------------------------------

describe('capability-misses: token-boundary ranking', () => {
  test('a reporting/integration read outranks generated route noise', () => {
    const report = endpoint({ method: 'GET', pathTemplate: '/api/v1/reports/sales', riskScore: 40 })
    const generated = endpoint({ method: 'GET', pathTemplate: '/v4/things', riskScore: 40 })
    const generatedDeep = endpoint({ method: 'GET', pathTemplate: '/v4/storefront/widgets/list', riskScore: 40 })
    assert.ok(endpointRiskScore(report) > endpointRiskScore(generated), 'reporting read must outrank a bare generated route')
    assert.ok(endpointRiskScore(report) > endpointRiskScore(generatedDeep), 'reporting read must outrank a deep generated route')
  })

  test('a 401 reporting read still forms an auth_protocol hypothesis', () => {
    // The harvest is empty because the route rejects the cookie session; the token-boundary shape is
    // the evidence, plus the owner persona whose scope supplies the forged claims.
    const surface = [endpoint({ method: 'GET', pathTemplate: '/api/v1/reports/sales', riskScore: 60 })]
    const hypotheses = enumerateHypotheses(surface, new Map(), { tier: 3, personas, environmentMode: 'ephemeral_lab' })
    const jwt = hypotheses.find(candidate => candidate.intent === 'auth_protocol')
    assert.ok(jwt, 'expected an auth_protocol hypothesis on a reporting read')
    assert.equal(jwt!.method, 'GET')
    assert.equal(jwt!.endpoint.pathTemplate, '/api/v1/reports/sales')
  })

  test('an unrelated read does not form an auth_protocol hypothesis', () => {
    const surface = [endpoint({ method: 'GET', pathTemplate: '/api/v1/widgets', riskScore: 60 })]
    const hypotheses = enumerateHypotheses(surface, new Map(), { tier: 3, personas, environmentMode: 'ephemeral_lab' })
    assert.equal(hypotheses.filter(candidate => candidate.intent === 'auth_protocol').length, 0)
  })
})

// ---------------------------------------------------------------------------
// Race hypothesis formation: disposable environments only
// ---------------------------------------------------------------------------

describe('capability-misses: race conversion environment', () => {
  const surface = [
    endpoint({ method: 'GET', pathTemplate: '/giftcards', riskScore: 45 }),
    endpoint({ method: 'POST', pathTemplate: '/giftcards/:id/redeem', riskScore: 70, params: [{ name: 'amount', location: 'json' }] }),
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['GET:/giftcards', harvest({ otherIds: ['card-1'], fields: ['amount'], values: { amount: ['1'] } })],
  ])

  test('forms in an ephemeral lab and carries id + readback evidence', () => {
    const hyp = raceHypothesis(surface, harvests, 'ephemeral_lab')
    assert.ok(hyp, 'expected a race hypothesis in an ephemeral lab')
    assert.deepEqual(hyp!.resourceIds, ['card-1'])
    assert.equal(hyp!.readbackPath, '/giftcards')
  })

  test('forms in staging', () => {
    assert.ok(raceHypothesis(surface, harvests, 'staging_isolated'), 'expected a race hypothesis in staging')
  })

  test('never forms in a production read-only engagement', () => {
    assert.equal(raceHypothesis(surface, harvests, 'prod_readonly'), undefined)
  })
})

// ---------------------------------------------------------------------------
// Race probe: id resolution, read-only baseline, full-value burst, under-debit
// ---------------------------------------------------------------------------

interface FakeState {
  balance: number
  serialDebits: number
  posts: string[]
  gets: string[]
}

function raceHypothesisFor(): EngineHypothesis {
  return {
    key: 'race_burst|POST:/giftcards/:id/redeem',
    endpoint: endpoint({ method: 'POST', pathTemplate: '/giftcards/:id/redeem', riskScore: 70 }),
    probeClass: 'workflow_invariant',
    intent: 'race',
    method: 'POST',
    pathAndQuery: '/giftcards/{{id}}/redeem',
    ownerPersona: 'owner',
    raceBurst: true,
    resourceIds: ['card-1'],
    readbackPath: '/giftcards',
    jsonBody: { amount: '1' },
    risk: 80,
  }
}

function fakeInput(state: FakeState, behaviour: 'racy' | 'correct' | 'no-id' | 'no-amount'): DeterministicEngineInput {
  const exchange = (method: string, path: string, body: string, status: number, json: unknown) => ({
    status,
    method,
    pathAndQuery: path,
    requestBody: body,
    body: typeof json === 'string' ? json : JSON.stringify(json),
    headers: {},
    durationMs: 1,
    bytes: 1,
  }) as never

  const broker = {
    httpTransport: { isHttp2Enabled: () => true },
    executeHttp: async (req: { method: string; pathAndQuery: string; body?: string }) => {
      const method = req.method.toUpperCase()
      if (method === 'GET') {
        state.gets.push(req.pathAndQuery)
        if (behaviour === 'no-id') return exchange('GET', req.pathAndQuery, '', 200, [{ balance: state.balance }])
        return exchange('GET', req.pathAndQuery, '', 200, [{ id: 'card-1', balance: state.balance }])
      }
      state.posts.push(req.pathAndQuery)
      if (state.posts.length > 64) throw new Error('runaway probe')
      const amount = behaviour === 'no-amount' ? 0 : Number((JSON.parse(req.body ?? '{}') as { amount?: number }).amount ?? 0)
      if (amount === 0) return exchange('POST', req.pathAndQuery, req.body ?? '', 200, { balance: state.balance })
      if (state.balance < amount) return exchange('POST', req.pathAndQuery, req.body ?? '', 409, { error: 'insufficient' })
      state.balance -= amount
      state.serialDebits += 1
      return exchange('POST', req.pathAndQuery, req.body ?? '', 200, { balance: state.balance, redeem: amount })
    },
    executeRaceBurst: async (requests: Array<{ method: string; pathAndQuery: string; body: string }>) => {
      const amount = Number((JSON.parse(requests[0]?.body ?? '{}') as { amount?: number }).amount ?? 0)
      // Racy service: every request is acknowledged, but the conserved value is debited once.
      const debit = behaviour === 'racy' ? 1 : requests.length
      if (behaviour === 'racy') state.balance -= amount
      else state.balance -= amount * requests.length
      const shared = state.balance + (behaviour === 'racy' ? amount * (requests.length - 1) : 0)
      return {
        summary: { spreadMs: 2, statusCounts: { '200': requests.length } },
        results: requests.map(req => exchange('POST', req.pathAndQuery, req.body, 200, { balance: shared, redeem: amount })),
      }
    },
  } as unknown as DeterministicEngineInput['broker']

  return {
    runId: 'run-race',
    assignmentId: 'asg-race',
    signal: new AbortController().signal,
    endpoints: [endpoint({ method: 'POST', pathTemplate: '/giftcards/:id/redeem', riskScore: 70 })],
    personas,
    broker,
    grant: {} as never,
    backend: {} as never,
    tier: 3,
    environmentMode: 'ephemeral_lab',
  } as unknown as DeterministicEngineInput
}

describe('capability-misses: race probe shape', () => {
  test('resolves the id, reads the conserved value, bursts a fundable amount and confirms an under-debit', async () => {
    const state: FakeState = { balance: 16, serialDebits: 0, posts: [], gets: [] }
    const result = await probeRaceDoubleSpend(raceHypothesisFor(), fakeInput(state, 'racy'), () => undefined)
    assert.equal(result.verdict, 'signal', result.summary)
    const anomaly = result.anomalies?.find(item => item.type === 'race_double_spend')
    assert.ok(anomaly, 'expected a race_double_spend anomaly')
    assert.equal(anomaly!.amount, 2, 'burst amount is the largest value the burst and the serial control can each fund (16 / 8)')
    assert.ok(state.gets.length >= 2, 'baseline and post-burst reads must be GETs, not mutating probes')
    assert.ok(state.posts.every(path => path === '/giftcards/card-1/redeem'), 'the placeholder must be substituted')
  })

  test('a correct service debits every acknowledged request and never confirms', async () => {
    const state: FakeState = { balance: 16, serialDebits: 0, posts: [], gets: [] }
    const result = await probeRaceDoubleSpend(raceHypothesisFor(), fakeInput(state, 'correct'), () => undefined)
    assert.notEqual(result.verdict, 'signal', result.summary)
  })

  test('an unresolvable object id never mutates anything', async () => {
    const hypothesis = { ...raceHypothesisFor(), resourceIds: undefined }
    const state: FakeState = { balance: 8, serialDebits: 0, posts: [], gets: [] }
    const result = await probeRaceDoubleSpend(hypothesis, fakeInput(state, 'no-id'), () => undefined)
    assert.notEqual(result.verdict, 'signal', result.summary)
    assert.equal(state.posts.length, 0, 'no mutation may be sent without a resolved object id')
  })

  test('a route with no numeric request field refuses to claim a race', async () => {
    const state: FakeState = { balance: 8, serialDebits: 0, posts: [], gets: [] }
    const hypothesis = { ...raceHypothesisFor(), jsonBody: {} }
    const result = await probeRaceDoubleSpend(hypothesis, fakeInput(state, 'no-amount'), () => undefined)
    assert.notEqual(result.verdict, 'signal', result.summary)
    assert.match(result.summary, /numeric request field|amount/i)
  })
})

// ---------------------------------------------------------------------------
// Race mode contract
// ---------------------------------------------------------------------------

describe('capability-misses: race mode', () => {
  test('requires HTTP/2, one shared pre-state and a tight spread', () => {
    assert.equal(classifyRaceMode({ http2Enabled: true, spreadMs: 2, observedBalances: [6, 6, 6, 6] }), 'h2-single-packet')
    assert.equal(classifyRaceMode({ http2Enabled: false, spreadMs: 2, observedBalances: [6, 6, 6, 6] }), 'fallback')
    assert.equal(classifyRaceMode({ http2Enabled: true, spreadMs: 40, observedBalances: [6, 6, 6, 6] }), 'fallback')
    assert.equal(classifyRaceMode({ http2Enabled: true, spreadMs: 2, observedBalances: [8, 6, 6, 6] }), 'fallback')
  })
})

// ---------------------------------------------------------------------------
// Header transport: a verifier-minted token is the only Authorization a spec may carry
// ---------------------------------------------------------------------------

describe('capability-misses: minted bearer headers', () => {
  const spec = (headers: Record<string, string>) => ({
    ...baseFields('https://target.example.com', 'JWT signature verification bypass', 'CWE-347', 'jwt', 'high', '{ confirmed: true }'),
    kind: 'auth_protocol_proof' as const,
    protocol: 'jwt' as const,
    tokenMints: [{ name: 'jwt_unsigned', header: { alg: 'none' }, payload: { sub: 'owner' }, signature: 'none' as const }],
    steps: [{
      id: 'c1',
      role: 'control' as const,
      description: 'declared-algorithm token with an invalid signature is rejected',
      request: { origin: 'https://target.example.com', method: 'GET' as const, pathAndQuery: '/api/v1/reports/sales' },
    }, {
      id: 'p1',
      role: 'probe' as const,
      description: 'unsigned token',
      request: { origin: 'https://target.example.com', method: 'GET' as const, pathAndQuery: '/api/v1/reports/sales', headers },
    }],
  })

  test('accepts a verifier-minted bearer reference', () => {
    assert.equal(declarativeReplaySpecSchema.safeParse(spec({ Authorization: 'Bearer {{jwt_unsigned}}' })).success, true)
  })

  test('rejects a literal token and a cookie header', () => {
    assert.equal(declarativeReplaySpecSchema.safeParse(spec({ Authorization: 'Bearer eyJhbGciOiJub25lIn0.e30.' })).success, false)
    assert.equal(declarativeReplaySpecSchema.safeParse(spec({ Cookie: 'session=abc' })).success, false)
  })
})

// ---------------------------------------------------------------------------
// Funnel fixes: auth_protocol ranking, admin-only race readback, conserved ranking, timing hook
// ---------------------------------------------------------------------------

import { wiredRecipeForSpecKind } from '../src/server/floor-recipes.ts'
import { planFloorRecipe } from '../src/server/floor-recipe-engine.ts'
import { synthSqlTime } from '../src/server/deterministic-specs.ts'

describe('capability-misses: token-boundary selection', () => {
  test('a cookie-denied read outranks cookie-200 credential routes', () => {
    const denied = endpoint({ method: 'GET', pathTemplate: '/api/v1/reports/sales', riskScore: 45 })
    const cookieOk = endpoint({ method: 'GET', pathTemplate: '/api/v1/tokens/:credId', riskScore: 75 })
    const surface = [denied, cookieOk]
    const harvests = new Map<string, EndpointHarvest>([
      [denied.id, harvest({ ownerReadStatus: 401 })],
      [cookieOk.id, harvest({ ownerReadStatus: 200 })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas, environmentMode: 'ephemeral_lab' })
    const auth = hypotheses.filter(candidate => candidate.intent === 'auth_protocol')
    assert.ok(auth.length >= 2, 'both token-shaped routes form an auth_protocol hypothesis')
    assert.equal(auth[0]!.endpoint.pathTemplate, '/api/v1/reports/sales', 'the cookie-denied read must rank first')
  })
})

describe('capability-misses: race conversion ranking', () => {
  test('checkout/cart conserved writes outrank speculative refund routes', () => {
    const surface = [
      endpoint({ method: 'POST', pathTemplate: '/api/v1/refunds/approve', riskScore: 60, params: [{ name: 'id', location: 'json' }] }),
      endpoint({ method: 'POST', pathTemplate: '/api/v1/bags/:cartId/checkout', riskScore: 65, params: [{ name: 'quantity', location: 'json' }] }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['POST:/api/v1/bags/:cartId/checkout', harvest({ otherIds: ['cart-1'], fields: ['quantity'], values: { quantity: ['1'] } })],
    ])
    const races = enumerateHypotheses(surface, harvests, { tier: 3, personas, environmentMode: 'ephemeral_lab' })
      .filter(candidate => candidate.raceBurst)
    assert.ok(races.length >= 2, 'both money-shaped writes form a race hypothesis')
    assert.equal(races[0]!.endpoint.pathTemplate, '/api/v1/bags/:cartId/checkout', 'the conserved-resource write must rank first')
  })
})

describe('capability-misses: admin-only race readback', () => {
  test('an owner 403 on the collection does not abort the proof; an admin read provides the baseline', async () => {
    const personasWithAdmin: EnginePersona[] = [
      ...personas,
      { handle: 'admin', roleLabel: 'admin (store)', privilege: 'admin', tenant: 'store-a' },
    ]
    const state = { balance: 16 }
    const hypothesis = {
      ...raceHypothesisFor(),
      ownerPersona: 'owner',
    }
    const broker = {
      httpTransport: { isHttp2Enabled: () => true },
      executeHttp: async (req: { method: string; pathAndQuery: string; body?: string; persona?: string }) => {
        const asExchange = (status: number, json: unknown) => ({
          status, method: req.method, pathAndQuery: req.pathAndQuery, body: JSON.stringify(json), headers: {}, durationMs: 1, bytes: 1,
        }) as never
        if (req.method.toUpperCase() === 'GET') {
          // The collection is admin-only; the item route is readable by its owner.
          if (req.pathAndQuery === '/giftcards' && req.persona !== 'admin') return asExchange(403, { error: 'forbidden' })
          if (req.pathAndQuery === '/giftcards' && req.persona === 'admin') return asExchange(200, [{ id: 'card-1', balance: state.balance }])
          if (req.pathAndQuery.startsWith('/giftcards/card-1') && req.persona === 'owner') return asExchange(200, { id: 'card-1', balance: state.balance })
          return asExchange(404, {})
        }
        const amount = Number((JSON.parse(req.body ?? '{}') as { amount?: number }).amount ?? 0)
        if (amount === 0) return asExchange(200, { balance: state.balance })
        if (state.balance < amount) return asExchange(409, { error: 'insufficient' })
        state.balance -= amount
        return asExchange(200, { balance: state.balance, redeem: amount })
      },
      executeRaceBurst: async (requests: Array<{ method: string; pathAndQuery: string; body: string }>) => {
        const amount = Number((JSON.parse(requests[0]?.body ?? '{}') as { amount?: number }).amount ?? 0)
        state.balance -= amount // racy: one debit for every acknowledgement
        const shared = state.balance + amount * (requests.length - 1)
        return {
          summary: { spreadMs: 2, statusCounts: { '200': requests.length } },
          results: requests.map(req => ({
            status: 200, method: req.method, pathAndQuery: req.pathAndQuery, body: JSON.stringify({ balance: shared, redeem: amount }), headers: {}, durationMs: 1, bytes: 1,
          }) as never),
        }
      },
    } as unknown as DeterministicEngineInput['broker']
    const input = {
      runId: 'run-race-admin',
      assignmentId: 'asg-race-admin',
      signal: new AbortController().signal,
      endpoints: [endpoint({ method: 'POST', pathTemplate: '/giftcards/:id/redeem', riskScore: 70 })],
      personas: personasWithAdmin,
      broker,
      grant: {} as never,
      backend: {} as never,
      tier: 3,
      environmentMode: 'ephemeral_lab',
    } as unknown as DeterministicEngineInput
    const result = await probeRaceDoubleSpend(hypothesis as never, input, () => undefined)
    assert.equal(result.verdict, 'signal', result.summary)
  })
})

describe('capability-misses: blind SQLi timing follow-up', () => {
  test('a timing probe emits a spec that is wired to the timing recipe', () => {
    const hyp = {
      key: 'sqli_boolean|x|q',
      endpoint: { id: 'GET:/api/v1/catalog/search', origin: 'http://127.0.0.1:4100', method: 'GET', pathTemplate: '/api/v1/catalog/search', params: [], riskScore: 50 },
      probeClass: 'sqli_boolean',
      intent: 'sqli',
      method: 'GET',
      pathAndQuery: '/api/v1/catalog/search?q=1',
      param: { name: 'q', location: 'query' },
      location: 'query',
      baselineValue: 'widgets',
      risk: 60,
    } as never
    const result = {
      verdict: 'signal',
      summary: 'timing',
      anomalies: [{ type: 'sql_time_differential', dialect: 'sqlite', delayMs: 2500, controlPassed: true }],
      details: {},
      requestsSent: 8,
      exchangeIds: [],
      durationMs: 1,
    } as never
    const specs = synthSqlTime(hyp, result)
    assert.equal(specs.length, 1)
    assert.equal(specs[0]!.kind, 'sql_time_diff')
    assert.equal(wiredRecipeForSpecKind('sql_time_diff', 'sqli'), 'boolean_or_timing')
    const plan = planFloorRecipe({ hypothesis: hyp, probe: result, specKind: 'sql_time_diff', vulnClass: 'sqli', personas })
    assert.ok(plan)
    assert.equal(plan!.recipeId, 'boolean_or_timing')
    const args = plan!.args as { mode?: string; receiptClass?: string; probePathAndQuery?: string }
    assert.equal(args.mode, 'timing')
    assert.equal(args.receiptClass, 'blind_sqli')
    assert.match(String(args.probePathAndQuery), /BLOB/i)
  })
})

// ---------------------------------------------------------------------------
// Regression shapes from the bench-verifier findings
// ---------------------------------------------------------------------------

describe('capability-misses: declared-surface triage prefix', () => {
  test('a declared reporting read survives a wall of generated wordlist routes', () => {
    const generated = Array.from({ length: 200 }, (_, index) =>
      endpoint({ method: 'GET', pathTemplate: `/v4/generated/${index}/items`, riskScore: 95, source: 'conventional' }))
    const declared = endpoint({ method: 'GET', pathTemplate: '/api/v1/reports/sales', riskScore: 45, source: 'openapi' })
    const prefix = engineTriagePrefix([...generated, declared], 120)
    assert.equal(prefix.length, 120)
    assert.ok(prefix.some(item => item.pathTemplate === '/api/v1/reports/sales'), 'declared route must be inside the prefix')
    assert.deepEqual(engineTriagePrefix([...generated, declared], 120).map(item => item.id), prefix.map(item => item.id))
  })

  test('a declared checkout write survives the same generated wall', () => {
    const generated = Array.from({ length: 200 }, (_, index) =>
      endpoint({ method: 'POST', pathTemplate: `/v4/generated/${index}/actions`, riskScore: 95, source: 'conventional' }))
    const checkout = endpoint({ method: 'POST', pathTemplate: '/api/v1/bags/:cartId/checkout', riskScore: 65, source: 'openapi' })
    const prefix = engineTriagePrefix([...generated, checkout], 120)
    assert.ok(prefix.some(item => item.pathTemplate === '/api/v1/bags/:cartId/checkout'))
  })
})

describe('capability-misses: blind-sink follow-up predicate', () => {
  test('empty-row boolean arms schedule a timing follow-up', () => {
    assert.equal(shouldScheduleTimingFollowUp({
      probeClass: 'sqli_boolean',
      verdict: 'inconclusive',
      summary: 'Every boolean arm returned no rows; the operand could not be grounded through this sink.',
      hasParam: true,
      location: 'query',
    }), true)
  })

  test('a URL/XXE/import carrier does not consume the single follow-up', () => {
    const base = { probeClass: 'sqli_boolean', verdict: 'no_signal' as const, summary: '', hasParam: true, location: 'query' as const }
    assert.equal(shouldScheduleTimingFollowUp({ ...base, paramShape: 'url' }), false)
    assert.equal(shouldScheduleTimingFollowUp({ ...base, routePath: '/v1/integrations/webhook-test' }), false)
    assert.equal(shouldScheduleTimingFollowUp({ ...base, routePath: '/v1/catalog/search', paramShape: 'text' }), true)
  })

  test('a signal, a non-sqli class, or a non-text location does not', () => {
    assert.equal(shouldScheduleTimingFollowUp({ probeClass: 'sqli_boolean', verdict: 'signal', summary: '', hasParam: true, location: 'query' }), false)
    assert.equal(shouldScheduleTimingFollowUp({ probeClass: 'ssti_math', verdict: 'no_signal', summary: '', hasParam: true, location: 'query' }), false)
    assert.equal(shouldScheduleTimingFollowUp({ probeClass: 'sqli_boolean', verdict: 'no_signal', summary: '', hasParam: true, location: 'header' }), false)
    assert.equal(shouldScheduleTimingFollowUp({ probeClass: 'sqli_boolean', verdict: 'no_signal', summary: '', hasParam: false, location: 'query' }), false)
  })
})

describe('capability-misses: gift-card redemption shape', () => {
  test('the amount field comes from declared route params when the row exposes only balance', async () => {
    const state = { balance: 5000 }
    const posted: Array<Record<string, unknown>> = []
    const hypothesis = {
      ...raceHypothesisFor(),
      endpoint: endpoint({
        method: 'POST',
        pathTemplate: '/api/v1/store-credit/:creditId/redeem',
        riskScore: 70,
        params: [{ name: 'amount', location: 'json' }],
      }),
      pathAndQuery: '/api/v1/store-credit/{{id}}/redeem',
      jsonBody: { external_id: 'gc-1', code: 'GC-1', balance: '5000' },
      resourceIds: ['gc-1'],
      readbackPath: '/api/v1/store-credit/gc-1',
    }
    const broker = {
      httpTransport: { isHttp2Enabled: () => true },
      executeHttp: async (req: { method: string; pathAndQuery: string; body?: string }) => {
        const ex = (status: number, json: unknown) => ({ status, method: req.method, pathAndQuery: req.pathAndQuery, body: JSON.stringify(json), headers: {}, durationMs: 1, bytes: 1 }) as never
        if (req.method.toUpperCase() === 'GET') {
          if (req.pathAndQuery === '/api/v1/store-credit/gc-1') return ex(200, { external_id: 'gc-1', code: 'GC-1', balance: state.balance })
          return ex(404, {})
        }
        const body = JSON.parse(req.body ?? '{}') as Record<string, unknown>
        posted.push(body)
        const amount = Number(body.amount ?? 0)
        if (amount === 0) return ex(200, { ok: true, remaining: state.balance })
        if (amount > state.balance) return ex(409, { error: 'insufficient_balance', balance: state.balance })
        state.balance -= amount
        return ex(200, { ok: true, redeemed: amount, remaining: state.balance })
      },
      executeRaceBurst: async (requests: Array<{ method: string; pathAndQuery: string; body: string }>) => {
        const amount = Number((JSON.parse(requests[0]?.body ?? '{}') as { amount?: number }).amount ?? 0)
        state.balance -= amount
        const shared = state.balance + amount * (requests.length - 1)
        return {
          summary: { spreadMs: 2, statusCounts: { '200': requests.length } },
          results: requests.map(req => ({ status: 200, method: req.method, pathAndQuery: req.pathAndQuery, body: JSON.stringify({ ok: true, redeemed: amount, remaining: shared }), headers: {}, durationMs: 1, bytes: 1 }) as never),
        }
      },
    } as unknown as DeterministicEngineInput['broker']
    const input = {
      runId: 'run-giftcard',
      assignmentId: 'asg-giftcard',
      signal: new AbortController().signal,
      endpoints: [hypothesis.endpoint],
      personas,
      broker,
      grant: {} as never,
      backend: {} as never,
      tier: 3,
      environmentMode: 'ephemeral_lab',
    } as unknown as DeterministicEngineInput
    const result = await probeRaceDoubleSpend(hypothesis as never, input, () => undefined)
    assert.equal(result.verdict, 'signal', result.summary)
    assert.ok(posted.every(body => 'amount' in body), 'the declared amount field must be the request field')
    assert.ok(posted.every(body => !('external_id' in body || 'code' in body || 'balance' in body)), 'harvested row fields must not leak into the request body')
  })
})

describe('capability-misses: inventory checkout shape', () => {
  test('the race targets the referenced product stock, not the cart row', () => {
    const surface = [
      endpoint({ method: 'GET', pathTemplate: '/api/v1/products', riskScore: 50 }),
      endpoint({ method: 'GET', pathTemplate: '/api/v1/products/:id', riskScore: 55 }),
      endpoint({
        method: 'POST',
        pathTemplate: '/api/v1/bags/:cartId/checkout',
        riskScore: 65,
        params: [{ name: 'productId', location: 'json' }, { name: 'itemQty', location: 'json' }],
      }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['GET:/api/v1/products', harvest({ otherIds: ['prod-1'], fields: ['stock'], values: { stock: ['10'] } })],
    ])
    const race = enumerateHypotheses(surface, harvests, { tier: 3, personas, environmentMode: 'ephemeral_lab' })
      .find(candidate => candidate.raceBurst)
    assert.ok(race, 'checkout forms a race hypothesis')
    assert.equal(race!.readbackPath, '/api/v1/products/:id', 'readback must be the referenced product detail')
    assert.equal((race!.jsonBody as Record<string, unknown>).productId, 'prod-1')
  })

  test('the burst reads product stock and debits it once against four acknowledgements', async () => {
    const state = { stock: 100 }
    const posted: Array<Record<string, unknown>> = []
    const hypothesis: EngineHypothesis = {
      key: 'race_burst|POST:/api/v1/bags/:cartId/checkout',
      endpoint: endpoint({
        method: 'POST',
        pathTemplate: '/api/v1/bags/:cartId/checkout',
        riskScore: 65,
        params: [{ name: 'productId', location: 'json' }, { name: 'itemQty', location: 'json' }],
      }),
      probeClass: 'workflow_invariant',
      intent: 'race',
      method: 'POST',
      pathAndQuery: '/api/v1/bags/{{id}}/checkout',
      ownerPersona: 'owner',
      raceBurst: true,
      resourceIds: ['cart-1'],
      readbackPath: '/api/v1/products/:id',
      jsonBody: { productId: 'prod-1', itemQty: '1' },
      risk: 85,
    }
    const broker = {
      httpTransport: { isHttp2Enabled: () => true },
      executeHttp: async (req: { method: string; pathAndQuery: string; body?: string }) => {
        const ex = (status: number, json: unknown) => ({ status, method: req.method, pathAndQuery: req.pathAndQuery, body: JSON.stringify(json), headers: {}, durationMs: 1, bytes: 1 }) as never
        if (req.method.toUpperCase() === 'GET') return ex(200, { id: 'prod-1', stock: state.stock })
        const body = JSON.parse(req.body ?? '{}') as Record<string, unknown>
        posted.push(body)
        const qty = Number(body.itemQty ?? 0)
        if (qty === 0) return ex(200, { stock: state.stock })
        if (qty > state.stock) return ex(409, { error: 'out_of_stock', stock: state.stock })
        state.stock -= qty
        return ex(201, { id: 'ord-1', reserved: qty })
      },
      executeRaceBurst: async (requests: Array<{ method: string; pathAndQuery: string; body: string }>) => {
        const qty = Number((JSON.parse(requests[0]?.body ?? '{}') as { itemQty?: number }).itemQty ?? 0)
        state.stock -= qty // racy: one reservation for every acknowledgement
        const shared = state.stock + qty * (requests.length - 1)
        return {
          summary: { spreadMs: 2, statusCounts: { '201': requests.length } },
          results: requests.map(req => ({ status: 201, method: req.method, pathAndQuery: req.pathAndQuery, body: JSON.stringify({ id: 'ord-1', reserved: qty, stock: shared }), headers: {}, durationMs: 1, bytes: 1 }) as never),
        }
      },
    } as unknown as DeterministicEngineInput['broker']
    const input = {
      runId: 'run-inventory',
      assignmentId: 'asg-inventory',
      signal: new AbortController().signal,
      endpoints: [hypothesis.endpoint],
      personas,
      broker,
      grant: {} as never,
      backend: {} as never,
      tier: 3,
      environmentMode: 'ephemeral_lab',
    } as unknown as DeterministicEngineInput
    const result = await probeRaceDoubleSpend(hypothesis as never, input, () => undefined)
    assert.equal(result.verdict, 'signal', result.summary)
    assert.ok(posted.every(body => 'productId' in body && 'itemQty' in body), 'the referenced product and quantity must be sent')
  })
})

describe('capability-misses: JWT control transport', () => {
  test('the control token is self-minted (empty signature) yet still rejected by the target', async () => {
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    const seen: string[] = []
    const { diffAuthProtocolAudit } = await import('../src/server/probes/jwt.ts')
    const ctx = {
      req: {
        probeClass: 'auth_protocol_audit',
        origin: 'http://127.0.0.1:4100',
        pathAndQuery: '/api/v1/reports/sales',
        method: 'GET',
        identityClaims: { tenant: 'store-a', store: 'store-a', sub: 'owner' },
      },
      origin: 'http://127.0.0.1:4100',
      runner: {} as never,
      notes: [],
      anomalies: [] as Array<Record<string, unknown>>,
      send: async (req: { headers?: Record<string, string> }) => {
        const token = (req.headers?.Authorization ?? '').replace(/^Bearer\s+/i, '')
        seen.push(token)
        const [header] = token.split('.')
        const alg = JSON.parse(Buffer.from(header ?? '', 'base64url').toString('utf8')).alg
        const sig = token.split('.')[2] ?? ''
        // Fixture semantics: an empty signature is invalid for HS256; alg:none is accepted and
        // returns a data-bearing report.
        if (alg === 'HS256' || sig !== '') return { status: 401, body: '{"error":"unauthorized"}', headers: {}, durationMs: 1 } as never
        return { status: 200, body: '{"store":"store-a","report":{"orders":3,"gross":100}}', headers: {}, durationMs: 1 } as never
      },
    } as never
    const outcome = await diffAuthProtocolAudit(ctx, undefined, { allowLocalLab: true, tier: 3 } as never)
    assert.equal(outcome.verdict, 'signal', outcome.summary)
    assert.ok(seen.length >= 2)
    assert.ok(seen.every(token => token.split('.').length === 3 && (token.split('.')[2] ?? '') === ''), 'all tokens must be empty-signature')
  })
})
