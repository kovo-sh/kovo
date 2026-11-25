/**
 * Tier-2 oracle soundness regressions (C-6, C-7, C-8, H-16, H-17, H-19).
 *
 * Authorized local differential fixtures only. These tests pin host-verified evidence requirements;
 * they never treat model-declared labels, reflected input, transport noise, or a lost control as a
 * confirmed vulnerability or a verified fix.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  assessBooleanDifferential,
  assessBoundary,
  assessBusinessLogicImpact,
  assessInjectionImpact,
  assessStatusOnlyDivergence,
  type ActorIdentity,
  type BooleanDifferentialRound,
  type ImpactStep,
} from '../src/server/oracle-invariants.ts'
import { browserSessionSeam, retestPersistedRecipe } from '../src/server/floor-recipe-engine.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult } from '../src/server/broker.ts'
import type { BrowserVisitResult, ScopedBrowser } from '../src/server/scoped-browser.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const owner: ActorIdentity = { handle: 'owner', role: 'owner', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const admin: ActorIdentity = { handle: 'admin', role: 'admin', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const viewer: ActorIdentity = { handle: 'viewer', role: 'viewer', tenant: 'acme', auth: 'cookie', sameSite: 'Lax' }
const foreignOwner: ActorIdentity = { handle: 'foreign-owner', role: 'owner', tenant: 'globex', auth: 'cookie', sameSite: 'Lax' }

function step(overrides: Partial<ImpactStep> = {}): ImpactStep {
  return {
    id: overrides.id ?? 'step',
    arm: overrides.arm ?? 'probe',
    method: overrides.method ?? 'POST',
    route: overrides.route ?? '/api/orders/1',
    status: overrides.status ?? 200,
    actor: overrides.actor ?? viewer,
    ...overrides,
  }
}

test('C-6: declared role/tenant labels alone never confirm business-logic impact', () => {
  const labelsOnly = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    requiredRole: 'admin',
    resourceTenant: 'globex',
    steps: [step({ requestJson: { status: 'paid' }, json: { ok: true } })],
  })
  assert.equal(labelsOnly.satisfied, false, labelsOnly.reason)
  assert.equal(labelsOnly.evidence.boundary, false)

  const entitledSelfService = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    requiredRole: 'admin',
    resourceTenant: 'globex',
    steps: [
      step({ id: 'before', arm: 'control', method: 'GET', actor: owner, json: { id: 1, status: 'draft' } }),
      step({ id: 'write', actor: owner, method: 'PATCH', requestJson: { status: 'paid' }, json: { ok: true } }),
      step({ id: 'after', arm: 'control', method: 'GET', actor: owner, json: { id: 1, status: 'paid' } }),
    ],
  })
  assert.equal(entitledSelfService.satisfied, false, entitledSelfService.reason)
  assert.equal(entitledSelfService.evidence.boundary, false)
})

test('C-6: host-recorded denial or entitled cross-tenant read supplies the boundary', () => {
  const denied = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    steps: [
      step({ id: 'deny', arm: 'control', actor: admin, status: 403 }),
      step({ id: 'write', requestJson: { status: 'paid' }, json: { ok: true } }),
    ],
  })
  assert.equal(denied.satisfied, true, denied.reason)
  assert.equal(denied.evidence.boundary, true)

  const entitledRead = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    resourceTenant: 'globex',
    steps: [
      step({ id: 'entitled', arm: 'control', method: 'GET', actor: foreignOwner, json: { id: 1, status: 'draft' } }),
      step({ id: 'write', requestJson: { status: 'paid' }, json: { ok: true } }),
    ],
  })
  assert.equal(entitledRead.satisfied, true, entitledRead.reason)
  assert.equal(entitledRead.evidence.boundary, true)
})

test('C-6: attributable persisted protected state remains positive evidence', () => {
  const persisted = assessBusinessLogicImpact({
    impactClass: 'business_logic',
    steps: [
      step({ id: 'before', arm: 'control', method: 'GET', actor: owner, json: { id: 1, balance: 100 } }),
      step({ id: 'write', actor: owner, method: 'PATCH', requestJson: { balance: 999 }, json: { ok: true } }),
      step({ id: 'after', arm: 'control', method: 'GET', actor: owner, json: { id: 1, balance: 999 } }),
    ],
  })
  assert.equal(persisted.satisfied, true, persisted.reason)
  assert.ok(persisted.evidence.protectedFields.includes('balance'))
})

function booleanRounds(controlValue: string, probeValue: string): BooleanDifferentialRound[] {
  return [0, 1].map(() => ({
    control: {
      status: 200,
      method: 'POST',
      pathAndQuery: '/api/search',
      requestJson: { q: controlValue },
      json: { count: 2, results: [{ id: 1 }, { id: 2 }] },
    },
    probe: {
      status: 200,
      method: 'POST',
      pathAndQuery: '/api/search',
      requestJson: { q: probeValue },
      json: { count: 0, results: [] },
    },
  }))
}

test('C-7: opposite literal predicates with a stable structural delta confirm', () => {
  const assessment = assessBooleanDifferential({ rounds: booleanRounds('7919=7919', '7919=7920'), param: 'q' })
  assert.equal(assessment.satisfied, true, assessment.reason)
  assert.equal(assessment.evidence.predicateContrast, true)
  assert.equal(assessment.evidence.controlStable, true)
  assert.equal(assessment.evidence.probeStable, true)
})

test('C-7: arbitrary two-value and same-truth differences do not confirm', () => {
  const arbitrary = assessBooleanDifferential({ rounds: booleanRounds('red', 'blue'), param: 'q' })
  assert.equal(arbitrary.satisfied, false, arbitrary.reason)
  assert.match(arbitrary.reason, /opposite, recognisable boolean predicates/i)

  const sameTruth = assessBooleanDifferential({ rounds: booleanRounds('1=1', '2=2'), param: 'q' })
  assert.equal(sameTruth.satisfied, false, sameTruth.reason)
  assert.match(sameTruth.reason, /opposite, recognisable boolean predicates/i)
})

test('C-7: the third status arm must be the false predicate counterpart', () => {
  const benign = step({ id: 'benign', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?sku=item' })
  const tautology = step({ id: 'true', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?sku=1%3D1' })
  const contradiction = step({ id: 'false', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?sku=1%3D2', status: 403 })
  const positive = assessInjectionImpact({
    impactClass: 'injection',
    steps: [benign, tautology, contradiction],
    injection: { family: 'sqli', statusBoolean: { benign, tautology, contradiction } },
  })
  assert.equal(positive.satisfied, true, positive.reason)

  const anotherTrue = step({ id: 'another-true', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?sku=2%3D2', status: 403 })
  const negative = assessInjectionImpact({
    impactClass: 'injection',
    steps: [benign, tautology, anotherTrue],
    injection: { family: 'sqli', statusBoolean: { benign, tautology, contradiction: anotherTrue } },
  })
  assert.equal(negative.satisfied, false, negative.reason)
})

function browserVisit(overrides: Partial<BrowserVisitResult> = {}): BrowserVisitResult {
  return {
    origin: 'http://127.0.0.1:4399',
    finalUrl: 'http://127.0.0.1:4399/portal',
    title: 'Portal',
    status: 200,
    domSnippet: '<div></div>',
    links: [],
    forms: [],
    xhrRequests: [],
    blockedOrigins: [],
    consoleMessages: [],
    postMessageListeners: { count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false },
    cookieNames: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    canaryCheck: { token: null, triggered: false, detail: null },
    domSinkTraces: [],
    exchangeIds: [],
    exchanges: [],
    durationMs: 1,
    ...overrides,
  }
}

async function runBrowserSeam(visits: BrowserVisitResult[], canaryToken: string) {
  const browser = { async runBrowserSession() { return visits } } as unknown as ScopedBrowser
  const seam = browserSessionSeam({
    browser,
    grant: {} as never,
    signal: AbortSignal.timeout(1_000),
    origin: 'http://127.0.0.1:4399',
  })
  return seam({
    origin: 'http://127.0.0.1:4399',
    steps: [{ role: 'probe', action: 'navigate', pathAndQuery: '/portal' }],
    canaryToken,
    actor: { handle: 'anonymous' },
  })
}

test('C-8: DOM execution requires an execution effect, not a sink substring or inert marker', async () => {
  const token = 'kovo-dom-execution-proof'

  const inertSink = await runBrowserSeam([browserVisit({
    domSinkTraces: [{ sink: 'innerHTML', preview: token, containsCanary: true, timestamp: 1 }],
  })], token)
  assert.equal(inertSink?.sinkHit, false)
  assert.deepEqual(inertSink?.traces, [])

  const inertMarker = await runBrowserSeam([browserVisit({
    domSnippet: `<div data-kovo-canary="${token}"></div>`,
    canaryCheck: { token, triggered: true, detail: 'Unescaped canary element/attribute observed in rendered DOM.' },
  })], token)
  assert.equal(inertMarker?.sinkHit, false)

  const serverTitle = await runBrowserSeam([browserVisit({
    title: token,
    exchanges: [{ body: `<html><head><title>${token}</title></head><body></body></html>` } as BrokerExchangeResult],
  })], token)
  assert.equal(serverTitle?.sinkHit, false)
})

test('C-8: verifier-owned execution effects confirm and cite sink corroboration', async () => {
  const token = 'kovo-dom-execution-proof'

  const changedTitle = await runBrowserSeam([browserVisit({
    title: token,
    exchanges: [{ body: '<html><head><title>Portal</title></head><body></body></html>' } as BrokerExchangeResult],
  })], token)
  assert.equal(changedTitle?.sinkHit, true)
  assert.deepEqual(changedTitle?.traces[0]?.sinks, ['canary:title'])

  const globalFlag = await runBrowserSeam([browserVisit({
    canaryCheck: { token, triggered: true, detail: 'DOM execution canary flag observed on window.' },
  })], token)
  assert.equal(globalFlag?.sinkHit, true)
  assert.deepEqual(globalFlag?.traces[0]?.sinks, ['canary:executed'])

  const corroborated = await runBrowserSeam([browserVisit({
    title: token,
    domSinkTraces: [{ sink: 'innerHTML', preview: token, containsCanary: true, timestamp: 1 }],
  })], token)
  assert.equal(corroborated?.sinkHit, true)
  assert.deepEqual(corroborated?.traces[0]?.sinks, ['dom_xss:innerHTML', 'canary:title'])
})

test('H-16: echoed request tokens cannot manufacture an injection fingerprint', () => {
  const control = step({ id: 'control', arm: 'control', method: 'GET', route: '/api/search', status: 200, json: { results: [] } })
  const echoed = step({
    id: 'echoed',
    method: 'GET',
    route: '/api/search',
    pathAndQuery: '/api/search?q=SQLITE_ERROR',
    status: 400,
    body: '{"error":"invalid input: SQLITE_ERROR"}',
    json: { error: 'invalid input: SQLITE_ERROR' },
  })
  const assessment = assessInjectionImpact({ impactClass: 'injection', steps: [control, echoed], injection: { family: 'sqli' } })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.equal(assessStatusOnlyDivergence([control, echoed]).fingerprint, null)

  const echoedJson = step({
    id: 'echoed-json',
    method: 'POST',
    route: '/api/search',
    status: 400,
    requestJson: { q: 'PostgreSQL' },
    body: '{"error":"invalid input: PostgreSQL"}',
    json: { error: 'invalid input: PostgreSQL' },
  })
  const jsonEcho = assessInjectionImpact({ impactClass: 'injection', steps: [control, echoedJson], injection: { family: 'sqli' } })
  assert.equal(jsonEcho.satisfied, false, jsonEcho.reason)

  const genuine = step({
    id: 'genuine',
    method: 'GET',
    route: '/api/search',
    pathAndQuery: '/api/search?q=benign',
    status: 500,
    body: 'SQLITE_ERROR: near "x": syntax error',
  })
  const positive = assessInjectionImpact({ impactClass: 'injection', steps: [control, genuine], injection: { family: 'sqli' } })
  assert.equal(positive.satisfied, true, positive.reason)
  assert.equal((positive.evidence?.fingerprint as { label?: string } | null)?.label, 'sqlite')
})

test('H-17: per-request query/body/header noise is not an access differential', () => {
  const noise = assessBoundary({
    impactClass: 'authorization',
    boundaryClass: 'access',
    expectControlDenied: false,
    steps: [
      step({
        id: 'control', arm: 'control', method: 'GET', route: '/api/items',
        pathAndQuery: '/api/items?id=1&nonce=first', requestHeaders: { 'X-Request-ID': 'first' },
        requestJson: { id: 1, requestId: 'first' }, json: { id: 1 },
      }),
      step({
        id: 'probe', method: 'GET', route: '/api/items',
        pathAndQuery: '/api/items?nonce=second&id=1', requestHeaders: { 'X-Request-ID': 'second' },
        requestJson: { requestId: 'second', id: 1 }, json: { id: 1 },
      }),
    ],
  })
  assert.equal(noise.satisfied, false, noise.reason)
  assert.equal(noise.evidence.requestDifferential, false)
})

test('H-17: meaningful actor and precondition differentials still confirm', () => {
  const actorDifferential = assessBoundary({
    impactClass: 'bfla',
    boundaryClass: 'access',
    requiredRole: 'admin',
    expectControlDenied: false,
    steps: [
      step({ id: 'control', arm: 'control', method: 'GET', actor: admin, route: '/api/admin/activity', json: { rows: [] } }),
      step({ id: 'probe', method: 'GET', actor: viewer, route: '/api/admin/activity', json: { rows: [] } }),
    ],
  })
  assert.equal(actorDifferential.satisfied, true, actorDifferential.reason)
  assert.equal(actorDifferential.arm, 'actor_differential')

  const preconditionDifferential = assessBoundary({
    impactClass: 'authorization',
    boundaryClass: 'access',
    expectControlDenied: false,
    steps: [
      step({ id: 'control', arm: 'control', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?scope=own', json: { id: 1 } }),
      step({ id: 'probe', method: 'GET', route: '/api/items', pathAndQuery: '/api/items?scope=other', json: { id: 2 } }),
    ],
  })
  assert.equal(preconditionDifferential.satisfied, true, preconditionDifferential.reason)
  assert.equal(preconditionDifferential.evidence.requestDifferential, true)
})

test('H-17: an owner persona cannot be the denied control for role escalation', () => {
  const assessment = assessBoundary({
    impactClass: 'bfla',
    boundaryClass: 'access',
    requiredRole: 'admin',
    expectControlDenied: true,
    steps: [
      step({ id: 'owner-deny', arm: 'control', method: 'GET', actor: owner, route: '/api/admin/activity', status: 403 }),
      step({ id: 'admin-probe', method: 'GET', actor: admin, route: '/api/admin/activity', json: { rows: [] } }),
    ],
  })
  assert.equal(assessment.satisfied, false, assessment.reason)
  assert.equal(assessment.controlDenied, false)
})

test('H-17: owner denial remains valid evidence for a cross-tenant object boundary', () => {
  const assessment = assessBoundary({
    impactClass: 'authorization',
    boundaryClass: 'access',
    requiredRole: 'owner',
    resourceTenant: 'globex',
    expectControlDenied: true,
    steps: [
      step({ id: 'entitled', arm: 'control', method: 'GET', actor: foreignOwner, route: '/api/items/1', json: { id: 1 } }),
      step({ id: 'owner-deny', arm: 'control', method: 'GET', actor: foreignOwner, route: '/api/items/1', status: 404 }),
      step({ id: 'probe', method: 'GET', actor: viewer, route: '/api/items/1', json: { id: 1 } }),
    ],
  })
  assert.equal(assessment.satisfied, true, assessment.reason)
  assert.equal(assessment.arm, 'control_denied')
})

const retestOrigin = 'http://127.0.0.1:4399'
const floorOwner = { handle: 'owner', role: 'owner' as const, tenant: 'acme' }
const floorViewer = { handle: 'viewer', role: 'viewer' as const, tenant: 'acme' }
const accessEnvelope = {
  recipeId: 'access_boundary' as const,
  args: {
    origin: retestOrigin,
    method: 'GET',
    pathAndQuery: '/api/items/1',
    vulnClass: 'bola',
    owner: floorOwner,
    probe: floorViewer,
    denied: floorViewer,
  },
}

function retestGrant() {
  const personas = new Map(['owner', 'viewer'].map(handle => [handle, {
    handle,
    roleLabel: handle === 'owner' ? 'Owner (acme)' : 'Viewer (acme)',
    authKind: 'bearer' as const,
    originAllowlist: [retestOrigin],
    secret: `t2-${handle}-credential`,
    session: { headerName: 'Authorization', headerType: 'Bearer', value: `t2-${handle}-credential` },
  }]))
  return makeLabGrant(retestOrigin, { tier: 3, personas: personas as never })
}

async function retestWithStatuses(statuses: readonly number[]) {
  let index = 0
  const broker = new RequestBroker({
    transport: async () => {
      const status = statuses[index++] ?? 500
      return {
        status,
        headers: { 'content-type': 'application/json' },
        body: status >= 200 && status < 300 ? '{"id":1}' : '{"error":"denied"}',
      }
    },
  })
  return retestPersistedRecipe({
    envelope: accessEnvelope,
    specKind: 'http_chain',
    vulnClass: 'bola',
    endpoint: '/api/items/1',
    origin: retestOrigin,
    broker,
    grant: retestGrant(),
    signal: AbortSignal.timeout(5_000),
  })
}

test('H-19: failed entitled controls map to inconclusive, never fixed', async () => {
  for (const statuses of [[500, 403, 200], [401, 403, 200], [200, 500, 200]] as const) {
    const result = await retestWithStatuses(statuses)
    assert.equal(result.verdict, 'inconclusive', `${statuses.join('/')}: ${result.replay.outcome.reason ?? 'no reason'}`)
    assert.equal(result.replay.verdict, 'inconclusive')
    assert.equal(result.replay.outcome.controlPassed, false)
  }
})

test('H-19: a healthy denied control observing a denied probe remains fixed', async () => {
  const result = await retestWithStatuses([200, 401, 403])
  assert.equal(result.verdict, 'fixed', result.replay.outcome.reason ?? 'no reason')
})

test('H-19: network failure and missing browser trace are inconclusive', async () => {
  const networkBroker = new RequestBroker({ transport: async () => { throw new Error('connection reset') } })
  const network = await retestPersistedRecipe({
    envelope: accessEnvelope,
    specKind: 'http_chain',
    vulnClass: 'bola',
    endpoint: '/api/items/1',
    origin: retestOrigin,
    broker: networkBroker,
    grant: retestGrant(),
    signal: AbortSignal.timeout(5_000),
  })
  assert.equal(network.verdict, 'inconclusive', network.replay.outcome.reason ?? 'no reason')

  const browserEnvelope = {
    recipeId: 'browser_sink' as const,
    args: { origin: retestOrigin, method: 'GET', pathAndQuery: '/portal', vulnClass: 'dom_xss', actor: { handle: 'anonymous' } },
  }
  const missingTrace = await retestPersistedRecipe({
    envelope: browserEnvelope,
    specKind: 'browser_chain',
    vulnClass: 'dom_xss',
    endpoint: '/portal',
    origin: retestOrigin,
    broker: new RequestBroker(),
    grant: retestGrant(),
    signal: AbortSignal.timeout(5_000),
    browserTrace: () => null,
  })
  assert.equal(missingTrace.verdict, 'inconclusive', missingTrace.replay.outcome.reason ?? 'no reason')

  const emptyTrace = await retestPersistedRecipe({
    envelope: browserEnvelope,
    specKind: 'browser_chain',
    vulnClass: 'dom_xss',
    endpoint: '/portal',
    origin: retestOrigin,
    broker: new RequestBroker(),
    grant: retestGrant(),
    signal: AbortSignal.timeout(5_000),
    browserTrace: () => ({ id: 'trace-empty', origin: retestOrigin, sinks: [] }),
  })
  assert.equal(emptyTrace.verdict, 'fixed', emptyTrace.replay.outcome.reason ?? 'no reason')
})
