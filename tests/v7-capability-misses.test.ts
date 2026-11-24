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
  enumerateHypotheses,
  probeRaceDoubleSpend,
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
