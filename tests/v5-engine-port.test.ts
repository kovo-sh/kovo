/**
 * v5 engine-port: in-product deterministic closed loop.
 *
 * Covers pure surface ranking/inference/enumeration, identifier-bound replay-spec synthesis,
 * verified-only persistence, lead emission for unproven signals, hide-confirmed matching and the
 * disable guard. Probe/verifier dependencies are injected so no network or worker backend is needed.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import type { BrokerExchangeResult, RequestBroker, Grant } from '../src/server/broker.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import {
  deterministicEngineEnabled,
  endpointClassPairKey,
  endpointRiskScore,
  enumerateHypotheses,
  inferEndpointParams,
  isStaticOrBaselinePath,
  rankEndpoints,
  runDeterministicEngine,
  stepCoveredByConfirmedPairs,
} from '../src/server/deterministic-engine.ts'
import type {
  DeterministicEngineInput, EndpointHarvest, EngineEndpoint, EngineHypothesis, EnginePersona,
} from '../src/server/deterministic-engine.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

// scopedAssetOrigin accepts loopback origins only when local-lab mode is enabled.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const personas: EnginePersona[] = [
  { handle: 'persona-a', roleLabel: 'owner (f6e944)', privilege: 'member', tenant: 'f6e944' },
  { handle: 'persona-b', roleLabel: 'owner (19837b)', privilege: 'member', tenant: '19837b' },
  { handle: 'admin', roleLabel: 'admin (f6e944)', privilege: 'admin', tenant: 'f6e944' },
  { handle: 'viewer', roleLabel: 'viewer (f6e944)', privilege: 'viewer', tenant: 'f6e944' },
]

function endpoint(over: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'method' | 'pathTemplate'>): EngineEndpoint {
  return {
    id: `${over.method}:${over.pathTemplate}`,
    origin: 'http://127.0.0.1:4100',
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

function authzSignal(id: string): DifferentialResult {
  return {
    probeClass: 'authz_matrix',
    origin: 'http://127.0.0.1:4100',
    pathAndQuery: '/api/invoices/{{id}}',
    verdict: 'signal',
    summary: 'cross-tenant read',
    anomalies: [{ type: 'unauthorized_access', resourceId: id, actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 1 }],
    details: {
      matrix: [
        { resourceId: id, actor: 'owner', status: 200, bodyBytes: 64, bodySha256: 'aaa', accessible: true },
        { resourceId: id, actor: 'other_persona', status: 200, bodyBytes: 64, similarityToOwner: 1, accessible: true },
      ],
    },
    requestsSent: 6,
    exchangeIds: ['ex-1'],
    stoppedReason: null,
    notes: [],
    durationMs: 5,
  }
}

describe('deterministic engine surface ranking and inference', () => {
  test('static assets and baselines are excluded from triage', () => {
    assert.equal(isStaticOrBaselinePath('/app.js'), true)
    assert.equal(isStaticOrBaselinePath('/health'), true)
    assert.equal(isStaticOrBaselinePath('/api/invoices/:invoiceId'), false)

    const ranked = rankEndpoints([
      endpoint({ method: 'GET', pathTemplate: '/styles/app.css' }),
      endpoint({ method: 'GET', pathTemplate: '/health' }),
      endpoint({ method: 'GET', pathTemplate: '/api/search/spaces' }),
      endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId' }),
    ])
    assert.deepEqual(ranked.map(item => item.pathTemplate).sort(), ['/api/invoices/:invoiceId', '/api/search/spaces'].sort())
  })

  test('dynamic, injectable and sensitive routes outrank plain lists', () => {
    const dynamic = endpointRiskScore(endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId' }))
    const search = endpointRiskScore(endpoint({ method: 'GET', pathTemplate: '/api/search/spaces' }))
    const plain = endpointRiskScore(endpoint({ method: 'GET', pathTemplate: '/api/me' }))
    assert.ok(dynamic > plain)
    assert.ok(search > plain)
  })

  test('parameter names are inferred from route semantics', () => {
    const search = inferEndpointParams(endpoint({ method: 'GET', pathTemplate: '/api/search/spaces' }))
    assert.ok(search.some(param => param.name === 'q' && param.location === 'query'))

    const avatar = inferEndpointParams(endpoint({ method: 'PUT', pathTemplate: '/api/people/:personId/avatar' }))
    assert.ok(avatar.some(param => param.name === 'avatarUrl' && param.location === 'json'))

    const download = inferEndpointParams(endpoint({ method: 'GET', pathTemplate: '/api/download/assets' }))
    assert.ok(download.some(param => param.name === 'file' && param.location === 'query'))
  })
})

describe('deterministic hypothesis enumeration', () => {
  const surface = [
    endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId' }),
    endpoint({ method: 'GET', pathTemplate: '/api/search/spaces' }),
    endpoint({ method: 'GET', pathTemplate: '/api/download/assets' }),
    endpoint({ method: 'POST', pathTemplate: '/api/apps/import' }),
    endpoint({ method: 'POST', pathTemplate: '/api/graphql' }),
    endpoint({ method: 'GET', pathTemplate: '/api/v1/downloads/download' }),
  ]

  test('object-level authz keeps the {{id}} binding and harvested ids', () => {
    const harvests = new Map<string, EndpointHarvest>([
      ['GET:/api/invoices/:invoiceId', harvest({ ownerIds: ['inv_1'], otherIds: ['inv_2'], fields: ['id', 'amount'] })],
      ['GET:/api/search/spaces', harvest({ ownerIds: ['prj_1'] })],
      ['POST:/api/graphql', harvest({ ownerIds: ['acct_1'] })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, { tier: 2, personas })
    const authz = hypotheses.find(hyp => hyp.probeClass === 'authz_matrix' && hyp.endpoint.pathTemplate === '/api/invoices/:invoiceId')
    assert.ok(authz)
    assert.equal(authz.pathAndQuery, '/api/invoices/{{id}}')
    assert.equal(authz.ownerPersona, 'persona-a')
    assert.equal(authz.otherPersona, 'persona-b')
    assert.ok(authz.resourceIds?.includes('inv_1'))
  })

  test('search, traversal, XXE, GraphQL and redirect hypotheses are formed generically', () => {
    const harvests = new Map<string, EndpointHarvest>([
      ['GET:/api/search/spaces', harvest({ seedValues: ['Roadmap'] })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, { tier: 2, personas })
    assert.ok(hypotheses.some(hyp => hyp.probeClass === 'sqli_boolean' && hyp.endpoint.pathTemplate === '/api/search/spaces'))
    assert.ok(hypotheses.some(hyp => hyp.probeClass === 'path_traversal_benign' && hyp.endpoint.pathTemplate === '/api/download/assets'))
    assert.ok(hypotheses.some(hyp => hyp.probeClass === 'xxe_canary' && hyp.endpoint.pathTemplate === '/api/apps/import'))
    assert.ok(hypotheses.some(hyp => hyp.probeClass === 'graphql_audit'))
    assert.ok(hypotheses.some(hyp => hyp.probeClass === 'open_redirect_differential'))
  })

  test('a disabled class list forms no hypotheses for excluded intents', () => {
    const harvests = new Map<string, EndpointHarvest>([
      ['GET:/api/invoices/:invoiceId', harvest({ ownerIds: ['inv_1'] })],
    ])
    const hypotheses = enumerateHypotheses(surface, harvests, {
      tier: 2, personas, classes: new Set(['authz']),
    })
    assert.ok(hypotheses.length > 0)
    assert.ok(hypotheses.every(hyp => hyp.intent === 'authz'))
  })
})

describe('deterministic replay spec synthesis', () => {
  const authzHypothesis: EngineHypothesis = {
    key: 'authz|invoices',
    endpoint: endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId' }),
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/api/invoices/{{id}}',
    ownerPersona: 'persona-a',
    otherPersona: 'persona-b',
    risk: 90,
  }

  test('authz spec is schema-valid and identifier-bound to a bogus negative control', () => {
    const specs = synthesizeEngineSpecs(authzHypothesis, authzSignal('inv_1'))
    assert.equal(specs.length, 1)
    const parsed = declarativeReplaySpecSchema.safeParse(specs[0].spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.issues[0]?.message)
    const steps = (specs[0].spec.steps as Array<{ id: string; role: string; expectedStatus?: number[]; request: { pathAndQuery: string; persona?: string } }>)
    const control = steps.find(step => step.id === 'c2')
    const owner = steps.find(step => step.id === 'c1')
    const probe = steps.find(step => step.id === 'p1')
    assert.ok(control && owner && probe)
    assert.equal(control.request.pathAndQuery, '/api/invoices/inv_gx9000001')
    assert.notEqual(control.request.pathAndQuery, owner.request.pathAndQuery)
    assert.deepEqual(control.expectedStatus, [400, 401, 403, 404, 405, 409, 410, 422])
    assert.equal(owner.request.pathAndQuery, '/api/invoices/inv_1')
    assert.equal(probe.request.pathAndQuery, '/api/invoices/inv_1')
    assert.equal(owner.request.persona, 'persona-a')
    assert.equal(probe.request.persona, 'persona-b')
  })

  test('an unproven signal yields no spec', () => {
    const dismissed: DifferentialResult = { ...authzSignal('inv_1'), verdict: 'no_signal', anomalies: [], details: {} }
    assert.deepEqual(synthesizeEngineSpecs(authzHypothesis, dismissed), [])
  })

  test('SQLi boolean spec binds the observed parameter and location', () => {
    const hyp: EngineHypothesis = {
      key: 'sqli|search',
      endpoint: endpoint({ method: 'GET', pathTemplate: '/api/search/spaces' }),
      probeClass: 'sqli_boolean',
      intent: 'sqli',
      method: 'GET',
      pathAndQuery: '/api/search/spaces',
      param: { name: 'q', location: 'query' },
      location: 'query',
      baselineValue: 'Roadmap',
      ownerPersona: 'persona-a',
      risk: 80,
    }
    const signal: DifferentialResult = {
      ...authzSignal('x'),
      probeClass: 'sqli_boolean',
      pathAndQuery: '/api/search/spaces',
      anomalies: [{ type: 'boolean_differential', style: 'single_quote' }],
      details: {},
    }
    const specs = synthesizeEngineSpecs(hyp, signal)
    assert.ok(specs.length >= 1)
    const parsed = declarativeReplaySpecSchema.safeParse(specs[0].spec)
    assert.equal(parsed.success, true)
    assert.equal((specs[0].spec as { paramName?: string }).paramName, 'q')
    assert.equal((specs[0].spec as { paramLocation?: string }).paramLocation, 'query')
    assert.equal((specs[0].spec as { baselineValue?: string }).baselineValue, 'Roadmap')
  })
})

// ---------------------------------------------------------------------------------------------
// Orchestrator: verified-only persistence, leads and the disable guard
// ---------------------------------------------------------------------------------------------

function fakeExchange(req: { origin: string; method: string; pathAndQuery: string; persona?: string }): BrokerExchangeResult {
  const other = req.persona === 'persona-b'
  const body = req.pathAndQuery.includes('/api/invoices/')
    ? JSON.stringify({ id: other ? 'inv_2' : 'inv_1', amount: 10, tenant_id: other ? '19837b' : 'f6e944' })
    : JSON.stringify({ items: [{ id: other ? 'inv_2' : 'inv_1', name: 'Invoice', tenant_id: other ? '19837b' : 'f6e944' }] })
  return {
    origin: req.origin,
    finalOrigin: req.origin,
    redirectOrigins: [],
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    personaHandle: req.persona ?? null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body,
    bodyPreview: body.slice(0, 200),
    bodyBytes: body.length,
    bodySha256: `sha-${body.length}`,
    durationMs: 2,
    secretMatches: [],
    setCookies: [],
  } as unknown as BrokerExchangeResult
}

function baseInput(over: Partial<DeterministicEngineInput> = {}): DeterministicEngineInput {
  const endpoints = [
    endpoint({ method: 'GET', pathTemplate: '/api/invoices' }),
    endpoint({ method: 'GET', pathTemplate: '/api/invoices/:invoiceId' }),
  ]
  const broker = {
    executeHttp: async (req: { origin: string; method: string; pathAndQuery: string; persona?: string }) => fakeExchange(req),
  } as unknown as RequestBroker
  return {
    runId: 'run-engine-test',
    assignmentId: 'asg-engine-test',
    signal: new AbortController().signal,
    endpoints,
    personas,
    broker,
    grant: { tier: 2, personas: [], secrets: [], canRead: () => true, audit: () => {} } as unknown as Grant,
    backend: {} as WorkerBackend,
    tier: 2,
    maxRequests: 120,
    maxDurationMs: 20_000,
    probe: async (req) => req.probeClass === 'authz_matrix' && req.pathAndQuery === '/api/invoices/{{id}}'
      ? authzSignal('inv_1')
      : { ...authzSignal('x'), probeClass: req.probeClass, verdict: 'no_signal', anomalies: [], details: {}, exchangeIds: [] },
    verify: async () => ({
      verdict: 'dismissed',
      outcome: { confirmed: false, controlPassed: true, observed: 'denied', expected: 'non-owner denied' },
      exchangeIds: ['verify-1'],
      exchanges: [],
      evidencePayload: {},
      evidenceSha256: 'sha',
    }),
    onConfirmed: () => 'finding-1',
    ...over,
  }
}

describe('deterministic engine orchestrator', () => {
  test('dismissed replay results never reach the persistence callback', async () => {
    const confirmed: string[] = []
    const leads: string[] = []
    const report = await runDeterministicEngine(baseInput({
      onConfirmed: input => { confirmed.push(input.vulnClass); return 'x' },
      onLead: lead => { leads.push(lead.hypothesis.probeClass) },
    }))
    assert.equal(report.confirmed, 0)
    assert.deepEqual(confirmed, [])
    assert.ok(report.specsSubmitted > 0)
    assert.ok(report.rejectedSpecs > 0)
    assert.ok(report.leads > 0)
    assert.ok(leads.includes('authz_matrix'))
  })

  test('only a confirmed replay reaches the persistence callback', async () => {
    const confirmed: Array<{ vulnClass: string; endpoint: string; status: string }> = []
    const report = await runDeterministicEngine(baseInput({
      verify: async params => ({
        verdict: (params.spec as { kind: string }).kind === 'http_chain' ? 'confirmed' : 'dismissed',
        verificationTier: 'runtime_confirmed',
        outcome: { confirmed: true, controlPassed: true, observed: 'cross-tenant body', expected: 'non-owner denied' },
        exchangeIds: ['verify-1'],
        exchanges: [],
        evidencePayload: {},
        evidenceSha256: 'sha',
      }) as never,
      onConfirmed: input => {
        confirmed.push({ vulnClass: input.vulnClass, endpoint: input.endpoint, status: input.result.verdict })
        return 'finding-1'
      },
    }))
    assert.equal(report.confirmed, 1, JSON.stringify(report))
    assert.equal(confirmed.length, 1)
    assert.equal(confirmed[0].vulnClass, 'bola')
    assert.equal(confirmed[0].endpoint, '/api/invoices/:invoiceId')
    assert.equal(confirmed[0].status, 'confirmed')
    assert.deepEqual(report.confirmedPairs, [{ endpoint: '/api/invoices/:invoiceId', vulnClass: 'bola' }])
  })

  test('the disable env keeps the engine inert', async () => {
    const previous = process.env.GUARDIAN_DETERMINISTIC_ENGINE
    process.env.GUARDIAN_DETERMINISTIC_ENGINE = '0'
    try {
      assert.equal(deterministicEngineEnabled(), false)
      let persisted = 0
      const report = await runDeterministicEngine(baseInput({ onConfirmed: () => { persisted += 1; return 'x' } }))
      assert.equal(report.stoppedReason, 'disabled')
      assert.equal(persisted, 0)
    } finally {
      if (previous === undefined) delete process.env.GUARDIAN_DETERMINISTIC_ENGINE
      else process.env.GUARDIAN_DETERMINISTIC_ENGINE = previous
    }
    assert.equal(deterministicEngineEnabled(), true)
  })

  test('request cap stops before unbounded probing', async () => {
    const report = await runDeterministicEngine(baseInput({ maxRequests: 1 }))
    assert.equal(report.stoppedReason, 'budget')
    assert.equal(report.confirmed, 0)
  })
})

describe('hide-confirmed endpoint/class matching', () => {
  test('the same endpoint and class family is hidden from specialists', () => {
    const pairs = [endpointClassPairKey('/api/invoices/:invoiceId', 'bola')]
    assert.equal(stepCoveredByConfirmedPairs('Object-level IDOR/BOLA on /api/invoices cross-tenant read', pairs), true)
    assert.equal(stepCoveredByConfirmedPairs('SQL injection on /api/invoices search parameter', pairs), false)
    assert.equal(stepCoveredByConfirmedPairs('Reflected XSS on /api/search/spaces', pairs), false)
  })
})
