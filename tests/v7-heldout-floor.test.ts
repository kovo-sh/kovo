// v7 held-out floor regress: four engine-side defects that cost salted held-out targets without
// touching the verification gates.
//
//  1. A differential probe dropped its class on the way to the broker, so a payload-induced 5xx was
//     charged to the availability circuit and could pause a healthy run.
//  2. A template/command hypothesis was formed for a numeric/money body field; the payload could
//     never render and the target's validator answered with 5xx.
//  3. An XXE hypothesis required a wire XML sample, so a document-import route whose declared
//     surface ships no sample was never probed.
//  4. A mutating probe on an identity-assumption route (impersonation) could persist a foreign
//     scope on the instrument's own session, which silently turned later reads into other-tenant
//     reads.
//
// Fixtures are synthetic shapes only: no benchmark app or route literal appears here.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import {
  buildIdentityProfiles,
  enumerateHypotheses,
  IDENTITY_ASSUMPTION_ROUTE_RE,
  isIdentityAssignmentField,
  withoutIdentityFields,
} from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint, EnginePersona } from '../src/server/deterministic-engine.ts'

const ORIGIN = 'http://fixture.invalid'
const PERSONAS: EnginePersona[] = [
  { handle: 'admin', roleLabel: 'admin (acme)', privilege: 'admin', tenant: 'acme' },
  { handle: 'owner_a', roleLabel: 'owner (acme)', privilege: 'member', tenant: 'acme' },
  { handle: 'owner_b', roleLabel: 'owner (globex)', privilege: 'member', tenant: 'globex' },
  { handle: 'viewer', roleLabel: 'viewer (acme)', privilege: 'viewer', tenant: 'acme' },
]

function harvestOf(over: Partial<EndpointHarvest> = {}): EndpointHarvest {
  return {
    ownerIds: [], otherIds: [], fields: [], values: {}, otherValues: {},
    seedValues: [], activeQueryParams: [], viewerIds: [], rowIds: {}, ...over,
  }
}

// ---------------------------------------------------------------------------
// 1. The differential class reaches the broker request
// ---------------------------------------------------------------------------

function fakeExchange(req: Record<string, unknown>): BrokerExchangeResult {
  return {
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method: String(req.method ?? 'GET'),
    pathAndQuery: String(req.pathAndQuery ?? '/'),
    personaHandle: (req.persona as string | undefined) ?? null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    setCookies: [],
    bodyPreview: '{"ok":true}',
    body: '{"ok":true}',
    bodySha256: '0'.repeat(64),
    bodyBytes: 11,
    bodyTruncated: false,
    durationMs: 1,
    observation: {
      origin: ORIGIN, finalOrigin: ORIGIN, source: 'supplied observation',
    } as BrokerExchangeResult['observation'],
  } as BrokerExchangeResult
}

test('held-out floor: a differential probe carries its class into the brokered request', async () => {
  const seen: Array<string | undefined> = []
  const broker = {
    executeHttp: async (req: Record<string, unknown>) => {
      seen.push(req.probeClass as string | undefined)
      return fakeExchange(req)
    },
  } as unknown as RequestBroker
  const grant: Grant = {
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    canRead: origin => origin === ORIGIN,
    audit: () => undefined,
  }
  const result = await probeDifferential(
    {
      origin: ORIGIN,
      pathAndQuery: '/api/items?q=guardian',
      method: 'GET',
      probeClass: 'sqli_boolean',
      param: 'q',
      paramLocation: 'query',
      maxRequests: 3,
    },
    broker,
    grant,
    undefined,
    new AbortController().signal,
  )
  assert.ok(result.requestsSent >= 2, `expected at least two differential requests, got ${result.requestsSent}`)
  assert.deepEqual([...new Set(seen)], ['sqli_boolean'],
    'every differential exchange must name its class, so an injection 5xx is evidence rather than unavailability')
})

// ---------------------------------------------------------------------------
// 2. Template/command hypotheses need a free-text carrier
// ---------------------------------------------------------------------------

test('held-out floor: no template hypothesis for a numeric/money body field', () => {
  const endpoint: EngineEndpoint = {
    id: 'POST:/api/render-docs', origin: ORIGIN, method: 'POST', pathTemplate: '/api/render-docs',
    params: [
      { name: 'amount', location: 'json' },
      { name: 'title', location: 'json' },
    ],
  }
  const harvests = new Map<string, EndpointHarvest>([
    [endpoint.id, harvestOf({ fields: ['amount', 'title'], values: { amount: ['1200'], title: ['Q3'] } })],
  ])
  const hypotheses = enumerateHypotheses([endpoint], harvests, { tier: 3, personas: PERSONAS })
  const sstiParams = hypotheses.filter(hyp => hyp.intent === 'ssti').map(hyp => hyp.param?.name)
  // `amount` is a validator-owned number: an arithmetic expression can never render there and the
  // target answers with a 5xx. `title` is a real free-text carrier and stays eligible.
  assert.ok(!sstiParams.includes('amount'), `numeric field must not be templated: ${sstiParams.join(',')}`)
  assert.ok(sstiParams.includes('title'), `free-text field must stay eligible: ${sstiParams.join(',')}`)
})

// ---------------------------------------------------------------------------
// 3. A document-import route is XXE-eligible without a wire XML sample
// ---------------------------------------------------------------------------

test('held-out floor: an import-shaped POST forms an XXE hypothesis without a wire sample', () => {
  const importRoute: EngineEndpoint = {
    id: 'POST:/api/feeds/import', origin: ORIGIN, method: 'POST', pathTemplate: '/api/feeds/import',
    params: [],
  }
  const urlRoute: EngineEndpoint = {
    id: 'POST:/api/hooks', origin: ORIGIN, method: 'POST', pathTemplate: '/api/hooks',
    params: [{ name: 'callbackUrl', location: 'json' }],
  }
  const harvests = new Map<string, EndpointHarvest>([
    [importRoute.id, harvestOf()],
    [urlRoute.id, harvestOf({ fields: ['callbackUrl'], values: { callbackUrl: ['http://example.test/'] } })],
  ])
  const hypotheses = enumerateHypotheses([importRoute, urlRoute], harvests, { tier: 3, personas: PERSONAS })
  const xxe = hypotheses.filter(hyp => hyp.probeClass === 'xxe_canary')
  assert.equal(xxe.length, 1, 'exactly the document-import route is XXE-eligible')
  assert.equal(xxe[0]!.endpoint.pathTemplate, '/api/feeds/import')
  // A URL-consuming route is structurally excluded: its body carries a fetch target, not a document.
  assert.ok(!hypotheses.some(hyp => hyp.probeClass === 'xxe_canary' && hyp.endpoint.pathTemplate === '/api/hooks'))
})

// ---------------------------------------------------------------------------
// 4. Identity-assumption routes never receive a scope selector from a probe
// ---------------------------------------------------------------------------

test('held-out floor: identity-assumption routes are recognised and scope fields are stripped', () => {
  assert.equal(IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/admin/assume-role'), true)
  assert.equal(IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/v1/admin/act-as'), true)
  assert.equal(IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/switch-tenant'), true)
  assert.equal(IDENTITY_ASSUMPTION_ROUTE_RE.test('/api/admin/people'), false)

  assert.equal(isIdentityAssignmentField('store'), true)
  assert.equal(isIdentityAssignmentField('tenantId'), true)
  assert.equal(isIdentityAssignmentField('isAdmin'), true)
  assert.equal(isIdentityAssignmentField('displayName'), false)
  assert.deepEqual(withoutIdentityFields({ store: 'globex', role: 'admin', name: 'x', nested: { org: 'b', note: 'n' } }),
    { name: 'x', nested: { note: 'n' } })
})

test('held-out floor: an impersonation route gets no mass-assignment recipe and no foreign scope body', () => {
  const impersonate: EngineEndpoint = {
    id: 'POST:/api/admin/assume-role', origin: ORIGIN, method: 'POST', pathTemplate: '/api/admin/assume-role',
    params: [],
  }
  const collection: EngineEndpoint = {
    id: 'GET:/api/customers', origin: ORIGIN, method: 'GET', pathTemplate: '/api/customers', params: [],
  }
  const harvests = new Map<string, EndpointHarvest>([
    [impersonate.id, harvestOf({ fields: ['store', 'name'], values: { store: ['globex'], name: ['v'] } })],
    [collection.id, harvestOf({ fields: ['store', 'name'], values: { store: ['globex'], name: ['v'] } })],
  ])
  const hypotheses = enumerateHypotheses([impersonate, collection], harvests, { tier: 3, personas: PERSONAS })
  const impersonateMass = hypotheses.filter(hyp => hyp.probeClass === 'mass_assignment' &&
    hyp.endpoint.pathTemplate === '/api/admin/assume-role')
  assert.equal(impersonateMass.length, 0, 'a scope-write probe must not run on a session-scoping route')

  const authz = hypotheses.find(hyp => hyp.intent === 'authz' && hyp.endpoint.pathTemplate === '/api/admin/assume-role')
  assert.ok(authz, 'the access-control probe still runs on the impersonation route')
  assert.equal(Object.hasOwn(authz!.jsonBody ?? {}, 'store'), false,
    'the access probe must not carry a scope selector that the server would persist on the operator session')
})

test('held-out floor: identity profiles still bind scope values for the replay (not the probe)', () => {
  const actAs: EngineEndpoint = {
    id: 'POST:/api/admin/act-as', origin: ORIGIN, method: 'POST', pathTemplate: '/api/admin/act-as', params: [],
  }
  const identity: EngineEndpoint = { id: 'GET:/api/session', origin: ORIGIN, method: 'GET', pathTemplate: '/api/session', params: [] }
  const harvests = new Map<string, EndpointHarvest>([
    [actAs.id, harvestOf({ fields: ['store'], values: { store: ['acme'] } })],
    [identity.id, harvestOf({
      values: { store: ['acme'] }, otherValues: { store: ['globex'] }, viewerValues: { store: ['acme'] },
    })],
  ])
  const hypotheses = enumerateHypotheses([actAs, identity], harvests, {
    tier: 3,
    personas: PERSONAS,
    identityProfiles: buildIdentityProfiles([actAs, identity], harvests),
  })
  const self = hypotheses.find(hyp => hyp.key.startsWith('authz-self|'))
  assert.ok(self, 'a self-state variant exists')
  // The replay still proves the scope change (target value) and can restore the baseline.
  assert.deepEqual(self!.functionState?.bindings, [{ field: 'store', value: 'globex' }])
  assert.deepEqual(self!.functionState?.reset, [{ field: 'store', value: 'acme' }])
  // The live probe writes no scope selector at all: even the actor's "own" value would rewrite the
  // session on an identity-assumption route, and a stale own binding must never re-scope it.
  assert.equal(Object.hasOwn(self!.jsonBody ?? {}, 'store'), false,
    'the live probe must not persist any scope value on the operator session')
})
