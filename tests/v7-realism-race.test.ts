/**
 * v7 M1 capability contracts for realism #3 (staging-concurrency).
 *
 * The unit surface here is the conversion logic that turns a wired observation into a confirmed
 * capability: identifier-form discovery, client-price workflow proofs, synchronized state-changing
 * bursts, and the field-bound cross-actor write proof. Network behaviour is covered by the realism
 * fixture run; these tests pin the pure plan/spec shapes so a regression is caught in seconds.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  classifyRaceMode,
  enumerateHypotheses,
  identifierFormsForRoute,
} from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint } from '../src/server/deterministic-engine.ts'
import {
  synthesizeEngineSpecs,
  vulnClassOfSpec,
} from '../src/server/deterministic-specs.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

const origin = 'http://127.0.0.1:4100'
const h2Origin = 'http://127.0.0.1:4200'

function emptyHarvest(overrides: Partial<EndpointHarvest> = {}): EndpointHarvest {
  return {
    ownerIds: [],
    otherIds: [],
    fields: [],
    values: {},
    otherValues: {},
    seedValues: [],
    activeQueryParams: [],
    viewerIds: [],
    rowIds: {},
    ...overrides,
  }
}

function diffSignal(anomalies: Array<Record<string, unknown>>, details: Record<string, unknown> = {}): DifferentialResult {
  return {
    probeClass: 'workflow_invariant',
    origin,
    pathAndQuery: '/',
    verdict: 'signal',
    summary: 'test signal',
    anomalies,
    details,
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 0,
  }
}

test('identifier forms discover the tenant-scoped object id used by the staging fixture', () => {
  const forms = identifierFormsForRoute('/v1/invoices/{id}', ['tenant-alpha', 'tenant-beta'])
  assert.equal(forms[0], 'inv-alpha-1', 'first candidate is the server-issued owner object id')
  assert.ok(forms.includes('inv-beta-1'), 'the peer tenant form is enumerated too')
  assert.ok(forms.length <= 12, 'enumeration stays bounded')
  assert.deepEqual(identifierFormsForRoute('/v1/health', ['tenant-alpha']), [], 'routes without an object id enumerate nothing')
})

test('race mode is only single-packet when HTTP/2 and the barrier-observed state agree', () => {
  assert.equal(classifyRaceMode({ http2Enabled: true, spreadMs: 2, observedBalances: [1000, 1000, 1000, 1000] }), 'h2-single-packet')
  assert.equal(classifyRaceMode({ http2Enabled: false, spreadMs: 2, observedBalances: [1000, 1000] }), 'fallback')
  assert.equal(classifyRaceMode({ http2Enabled: true, spreadMs: 40, observedBalances: [1000, 1000] }), 'fallback')
  assert.equal(classifyRaceMode({ http2Enabled: true, spreadMs: 1, observedBalances: [1000, 999] }), 'fallback')
})

test('staging surface forms write-BOLA, price-trust and race-burst hypotheses', () => {
  const endpoints: EngineEndpoint[] = [
    { id: 'ep-invoice-read', origin, method: 'GET', pathTemplate: '/v1/invoices/{id}', params: [{ name: 'id', location: 'path' }], source: 'openapi' },
    { id: 'ep-invoice-write', origin, method: 'PATCH', pathTemplate: '/v1/invoices/{id}', params: [{ name: 'id', location: 'path' }], source: 'openapi' },
    { id: 'ep-checkout-start', origin, method: 'POST', pathTemplate: '/v1/checkout/start', params: [], source: 'openapi' },
    { id: 'ep-checkout-pay', origin, method: 'POST', pathTemplate: '/v1/checkout/pay', params: [], source: 'openapi' },
    { id: 'ep-transfers', origin, method: 'POST', pathTemplate: '/v2/transfers', params: [], source: 'openapi' },
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['ep-invoice-write', emptyHarvest({
      ownerIds: ['inv-alpha-1'],
      fields: ['id', 'tenant', 'total'],
      values: { id: ['inv-alpha-1'], tenant: ['tenant-alpha'], total: ['100'] },
    })],
    ['ep-invoice-read', emptyHarvest({ ownerIds: ['inv-alpha-1'] })],
  ])
  const personas = [
    { handle: 'alice', roleLabel: 'member (tenant-alpha)', privilege: 'member' as const, tenant: 'tenant-alpha' },
    { handle: 'bob', roleLabel: 'member (tenant-beta)', privilege: 'member' as const, tenant: 'tenant-beta' },
  ]
  const hybrids = enumerateHypotheses(endpoints, harvests, { tier: 3, personas, environmentMode: 'staging_isolated' })
  const byKey = new Map(hybrids.map(hyp => [hyp.key, hyp]))

  const authz = byKey.get('authz|ep-invoice-write|path')
  assert.ok(authz, 'mutating object route forms an authorization hypothesis')
  assert.equal(authz!.readbackPath, '/v1/invoices/{{id}}', 'a separate readback route is bound')
  assert.deepEqual(authz!.resourceIds, ['inv-alpha-1'])

  const price = byKey.get('price_trust|ep-checkout-pay')
  assert.ok(price, 'terminal money route forms a client-price workflow hypothesis')
  assert.equal(price!.flowCreatePath, '/v1/checkout/start')
  assert.equal(price!.intent, 'workflow')

  const race = byKey.get('race_burst|ep-transfers')
  assert.ok(race, 'state-changing money route forms a synchronized burst hypothesis')
  assert.equal(race!.intent, 'race')
  assert.equal(race!.raceBurst, true)

  // Disposable environments form the conversion probes; only a production read-only engagement
  // refuses them. The benchmark's isolated lab is `ephemeral_lab`, which is exactly where a race or
  // price-trust proof is legitimate — gating on `staging_isolated` alone made those classes
  // unreachable on the held-out matrix.
  const ephemeral = enumerateHypotheses(endpoints, harvests, { tier: 3, personas, environmentMode: 'ephemeral_lab' })
  assert.equal(ephemeral.some(hyp => hyp.priceTrust || hyp.raceBurst), true)
  const prod = enumerateHypotheses(endpoints, harvests, { tier: 3, personas, environmentMode: 'prod_readonly' })
  assert.equal(prod.some(hyp => hyp.priceTrust || hyp.raceBurst), false)
})

test('price-trust proof names the caller price field and replays the terminal transition', () => {
  const hyp: EngineHypothesis = {
    key: 'price_trust|ep-checkout-pay',
    endpoint: { id: 'ep-checkout-pay', origin, method: 'POST', pathTemplate: '/v1/checkout/pay', params: [] },
    probeClass: 'workflow_invariant',
    intent: 'workflow',
    method: 'POST',
    pathAndQuery: '/v1/checkout/pay',
    ownerPersona: 'alice',
    priceTrust: true,
    flowCreatePath: '/v1/checkout/start',
    headers: { 'x-kovo-run-id': 'run-1' },
    risk: 60,
  }
  const result = diffSignal([{
    type: 'price_tampering',
    path: '/v1/checkout/pay',
    idField: 'cartId',
    resourceId: 'kovo-qa-run-1-cart-1',
    priceField: 'unitPrice',
    serverPrice: 249,
    tamperedPrice: 1,
    chargedField: 'total',
    controlStatus: 200,
    probeStatus: 200,
    repeatStatus: 200,
    repeatAccepted: true,
  }])
  const specs = synthesizeEngineSpecs(hyp, result)
  assert.equal(specs.length, 1)
  const spec = specs[0]!
  assert.equal(spec.vulnClass, 'price_tampering')
  assert.equal(spec.kind, 'http_chain')
  const body = spec.spec as {
    category: string
    cwe: string
    assertionsJq: string
    steps: Array<{ id: string; request: { method: string; pathAndQuery: string; jsonBody: Record<string, unknown>; headers?: Record<string, string> } }>
  }
  assert.equal(body.category, 'price_tampering')
  assert.equal(body.cwe, 'CWE-472')
  assert.deepEqual(body.steps.map(step => step.id), ['c1', 'p1', 'p2'])
  for (const step of body.steps) {
    assert.equal(step.request.method, 'POST')
    assert.equal(step.request.pathAndQuery, '/v1/checkout/pay')
    assert.equal(step.request.jsonBody.cartId, 'kovo-qa-run-1-cart-1')
    assert.equal(step.request.headers?.['x-kovo-run-id'], 'run-1', 'staging write steps carry the run tag')
  }
  assert.equal(body.steps[0]!.request.jsonBody.unitPrice, 249, 'control pays the server price')
  assert.equal(body.steps[1]!.request.jsonBody.unitPrice, 1, 'probe pays the caller price')
  assert.deepEqual(body.steps[1]!.request.jsonBody, body.steps[2]!.request.jsonBody, 'terminal transition replay is identical')
  assert.match(body.assertionsJq, /\.steps\.c1\.json\.total/)
  assert.match(body.assertionsJq, /249/)
  assert.equal(vulnClassOfSpec(spec.spec), 'price_tampering')
})

test('race proof asserts acknowledged transfers against a single balance debit', () => {
  const hyp: EngineHypothesis = {
    key: 'race_burst|ep-transfers',
    endpoint: { id: 'ep-transfers', origin, method: 'POST', pathTemplate: '/v2/transfers', params: [] },
    probeClass: 'workflow_invariant',
    intent: 'race',
    method: 'POST',
    pathAndQuery: '/v2/transfers',
    ownerPersona: 'alice',
    raceBurst: true,
    headers: { 'x-kovo-run-id': 'run-1' },
    risk: 70,
  }
  const result = diffSignal([{
    type: 'race_double_spend',
    path: '/v2/transfers',
    raceOrigin: h2Origin,
    amountField: 'amount',
    balanceField: 'observedBalance',
    transferredField: 'transferred',
    amount: 1,
    burstSize: 4,
    burstAcks: 4,
    burstTransferred: 4,
    preBalance: 1000,
    postBalance: 999,
    burstDebit: 1,
    serialAcks: 4,
    serialDebit: 4,
    raceMode: 'h2-single-packet',
  }])
  const specs = synthesizeEngineSpecs(hyp, result)
  assert.equal(specs.length, 1)
  const spec = specs[0]!
  assert.equal(spec.kind, 'race_burst')
  assert.equal(spec.vulnClass, 'race_double_spend')
  const body = spec.spec as {
    origin: string
    category: string
    cwe: string
    assertionsJq: string
    setupSteps: Array<{ id: string; extract?: Array<{ varName: string; selector: string }> }>
    burst: Array<{ origin: string; method: string; pathAndQuery: string; jsonBody: Record<string, unknown>; headers?: Record<string, string> }>
    postCheckStep: { id: string }
  }
  assert.equal(body.origin, h2Origin, 'the proof names the origin that actually served the burst')
  assert.equal(body.category, 'race_double_spend')
  assert.equal(body.cwe, 'CWE-362')
  assert.equal(body.setupSteps[0]!.extract?.[0]?.selector, 'observedBalance')
  assert.equal(body.burst.length, 4)
  for (const request of body.burst) {
    assert.equal(request.origin, h2Origin)
    assert.equal(request.method, 'POST')
    assert.equal(request.pathAndQuery, '/v2/transfers')
    assert.equal(request.jsonBody.amount, 1)
    assert.equal(request.headers?.['x-kovo-run-id'], 'run-1')
  }
  assert.equal(body.postCheckStep.id, 'post')
  assert.match(body.assertionsJq, /\.setup\[0\]\.json\.observedBalance/)
  assert.match(body.assertionsJq, /\.postCheck\.json\.observedBalance/)
  assert.match(body.assertionsJq, /== 4/)
  assert.equal(vulnClassOfSpec(spec.spec), 'race_double_spend')
})

test('write-BOLA replay binds the exact mutated field to a fresh non-idempotent value', () => {
  const hyp: EngineHypothesis = {
    key: 'authz|ep-invoice-write|path',
    endpoint: { id: 'ep-invoice-write', origin, method: 'PATCH', pathTemplate: '/v1/invoices/{id}', params: [] },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'PATCH',
    pathAndQuery: '/v1/invoices/{{id}}',
    ownerPersona: 'alice',
    otherPersona: 'bob',
    resourceIds: ['inv-alpha-1'],
    readbackPath: '/v1/invoices/{{id}}',
    jsonBody: { total: 100 },
    headers: { 'x-kovo-run-id': 'run-1' },
    risk: 80,
  }
  const result: DifferentialResult = {
    probeClass: 'authz_matrix',
    origin,
    pathAndQuery: '/v1/invoices/{{id}}',
    verdict: 'signal',
    summary: 'cross-actor write',
    anomalies: [{
      type: 'unauthorized_access',
      resourceId: 'inv-alpha-1',
      actor: 'other_persona',
      method: 'PATCH',
      status: 200,
      similarityToOwner: 1,
      bodyTemplate: { total: 100 },
    }],
    details: {
      matrix: [
        { resourceId: 'inv-alpha-1', actor: 'owner', status: 200, bodyBytes: 60, accessible: true },
        { resourceId: 'inv-alpha-1', actor: 'other_persona', status: 200, bodyBytes: 60, accessible: true, similarityToOwner: 1 },
      ],
    },
    requestsSent: 0,
    exchangeIds: [],
    stoppedReason: null,
    notes: [],
    durationMs: 0,
  }
  const specs = synthesizeEngineSpecs(hyp, result)
  assert.equal(specs.length, 1)
  const spec = specs[0]!
  assert.equal(spec.vulnClass, 'bola')
  const body = spec.spec as {
    category: string
    assertionsJq: string
    steps: Array<{ id: string; role: string; request: { method: string; pathAndQuery: string; jsonBody?: Record<string, unknown>; headers?: Record<string, string> } }>
  }
  assert.equal(body.category, 'cross_tenant_write')
  assert.deepEqual(body.steps.map(step => step.id), ['w1', 'c2', 'c3', 'c1', 'p1', 'p2'])
  const baseline = body.steps[0]!.request.jsonBody!.total as number
  const probe = body.steps[4]!.request.jsonBody!.total as number
  assert.equal(typeof baseline, 'number', 'baseline value keeps its numeric JSON type')
  assert.equal(typeof probe, 'number', 'probe value keeps its numeric JSON type')
  assert.equal(probe, 100, 'the probe writes the observed mutation value')
  assert.notEqual(probe, baseline, 'the baseline write makes the probe delta non-idempotent')
  assert.match(body.assertionsJq, /\["total"\]/, 'the assertion names the mutated field')
  assert.match(body.assertionsJq, new RegExp(`== ${probe}\\b`), 'the assertion binds the exact non-idempotent probe value')
  assert.match(body.assertionsJq, new RegExp(`== ${baseline}\\b`), 'the assertion binds the control baseline value')
  assert.equal(body.steps[4]!.request.headers?.['x-kovo-run-id'], 'run-1', 'the cross-actor write carries the staging tag')
  assert.equal(body.steps[4]!.request.pathAndQuery, '/v1/invoices/inv-alpha-1')
})

test('hypothesis enumeration is stable across input order', () => {
  const endpoints: EngineEndpoint[] = [
    { id: 'a', origin, method: 'POST', pathTemplate: '/v1/checkout/start', params: [] },
    { id: 'b', origin, method: 'POST', pathTemplate: '/v1/checkout/pay', params: [] },
    { id: 'c', origin, method: 'POST', pathTemplate: '/v2/transfers', params: [] },
  ]
  const personas = [
    { handle: 'alice', roleLabel: 'member (tenant-alpha)', privilege: 'member' as const, tenant: 'tenant-alpha' },
    { handle: 'bob', roleLabel: 'member (tenant-beta)', privilege: 'member' as const, tenant: 'tenant-beta' },
  ]
  const harvests = new Map<string, EndpointHarvest>([
    ['a', emptyHarvest()], ['b', emptyHarvest()], ['c', emptyHarvest()],
  ])
  const forward = enumerateHypotheses(endpoints, harvests, { tier: 3, personas, environmentMode: 'staging_isolated' }).map(hyp => hyp.key)
  const reverse = enumerateHypotheses([...endpoints].reverse(), new Map([...harvests.entries()].reverse()), { tier: 3, personas, environmentMode: 'staging_isolated' }).map(hyp => hyp.key)
  assert.deepEqual(reverse, forward)
})
