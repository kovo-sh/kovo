/**
 * Authz readback hints: the deterministic engine must name the separate GET that observes a mutating
 * authorization proof, plus the role a role-exclusive function requires.
 *
 * The synthesizer (`deterministic-specs.synthAuthz`) accepts `readbackPath`/`readbackPersona`/
 * `authzRequiredRole`; without them a mutating proof either invents a non-reading path or falls back
 * to the mutation echo (which the verifier correctly rejects). These tests pin the generic inference:
 * route shape + harvested identifiers only, no app, route, seed or benchmark literals.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { enumerateHypotheses } from '../src/server/deterministic-engine.ts'
import type { EndpointHarvest, EngineEndpoint, EnginePersona } from '../src/server/deterministic-engine.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/surface-engine.ts'

const personas: EnginePersona[] = [
  { handle: 'member-a', roleLabel: 'member (t1)', privilege: 'member', tenant: 't1' },
  { handle: 'member-b', roleLabel: 'member (t2)', privilege: 'member', tenant: 't2' },
  { handle: 'viewer', roleLabel: 'viewer (t1)', privilege: 'viewer', tenant: 't1' },
  { handle: 'admin', roleLabel: 'admin (t1)', privilege: 'admin', tenant: 't1' },
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

function authzHypothesis(
  surface: EngineEndpoint[],
  harvests: Map<string, EndpointHarvest>,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  pathTemplate: string,
) {
  const hypotheses = enumerateHypotheses(surface, harvests, { tier: 3, personas })
  const hyp = hypotheses.find(candidate =>
    candidate.intent === 'authz' &&
    candidate.probeClass === 'authz_matrix' &&
    candidate.method === method &&
    candidate.endpoint.pathTemplate === pathTemplate)
  assert.ok(hyp, `expected a mutating authz hypothesis on ${method} ${pathTemplate}`)
  return hyp
}

describe('object-route readback hints', () => {
  test('a mutating authz hypothesis on an object route reads its detail, not the action verb', () => {
    const surface = [
      endpoint({ method: 'PATCH', pathTemplate: '/api/admin/members/:memberId/role' }),
      endpoint({ method: 'GET', pathTemplate: '/api/admin/members/:memberId' }),
      endpoint({ method: 'GET', pathTemplate: '/api/members/:memberId' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/admin/members/:memberId/role', harvest({ ownerIds: ['m-1', 'm-2'], otherIds: ['m-9'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'PATCH', '/api/admin/members/:memberId/role')

    assert.equal(hyp.pathAndQuery, '/api/admin/members/{{id}}/role')
    assert.equal(hyp.readbackPath, '/api/admin/members/{{id}}')
    // The read is a real detail readback, never the mutating path itself.
    assert.notEqual(hyp.readbackPath, hyp.pathAndQuery)
    assert.equal(hyp.readbackPersona, undefined, 'the privileged control actor reads the object back')
    // A role-exclusive route outranks the probe persona, so the vertical claim is declared.
    assert.equal(hyp.authzRequiredRole, 'admin')
    assert.equal(hyp.ownerPersona, 'admin')
  })

  test('a sibling detail of the same record family reads back an elevated delete', () => {
    const surface = [
      endpoint({ method: 'DELETE', pathTemplate: '/api/admin/people/:personId' }),
      endpoint({ method: 'GET', pathTemplate: '/api/people/:personId' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['DELETE:/api/admin/people/:personId', harvest({ ownerIds: ['p-1'], otherIds: ['p-2'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'DELETE', '/api/admin/people/:personId')
    assert.equal(hyp.readbackPath, '/api/people/{{id}}')
  })

  test('an object-detail mutation defaults to its own detail readback before identity fallback', () => {
    const surface = [
      endpoint({ method: 'PATCH', pathTemplate: '/api/account/:accountId' }),
      endpoint({ method: 'GET', pathTemplate: '/api/me' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/account/:accountId', harvest({ ownerIds: ['a-1'], otherIds: ['a-2'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'PATCH', '/api/account/:accountId')
    assert.equal(hyp.readbackPath, '/api/account/{{id}}')
    assert.equal(hyp.readbackPersona, undefined)
  })

  test('an action-verb mutation without a detail read or identity route has no invented readback', () => {
    const surface = [
      endpoint({ method: 'PATCH', pathTemplate: '/api/admin/notes/:noteId/archive' }),
      endpoint({ method: 'GET', pathTemplate: '/api/health' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/admin/notes/:noteId/archive', harvest({ ownerIds: ['n-1'], otherIds: ['n-2'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'PATCH', '/api/admin/notes/:noteId/archive')
    assert.equal(hyp.readbackPath, undefined)
  })
})

describe('function-route readback hints', () => {
  test('a function-level mutation reads an observable sibling collection, not its own echo', () => {
    const surface = [
      endpoint({ method: 'POST', pathTemplate: '/api/admin/feature-flags' }),
      endpoint({ method: 'GET', pathTemplate: '/api/feature-flags' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['POST:/api/admin/feature-flags', harvest({ ownerIds: ['f-1'], otherIds: ['f-2'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'POST', '/api/admin/feature-flags')
    assert.equal(hyp.functionLevel, true)
    assert.equal(hyp.readbackPath, '/api/feature-flags')
    assert.notEqual(hyp.readbackPath, hyp.pathAndQuery)
    assert.equal(hyp.authzRequiredRole, 'admin')
  })

  test('an unrelated collection is not adopted as the readback', () => {
    const surface = [
      endpoint({ method: 'POST', pathTemplate: '/api/admin/impersonate' }),
      endpoint({ method: 'GET', pathTemplate: '/api/billing/plans' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['POST:/api/admin/impersonate', harvest({ ownerIds: ['u-1'], otherIds: ['u-2'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'POST', '/api/admin/impersonate')
    assert.equal(hyp.readbackPath, undefined)
  })
})

describe('readback hints feed the mutating authz spec', () => {
  test('the synthesized chain reads the hint route before and after the mutation', () => {
    const surface = [
      endpoint({ method: 'PATCH', pathTemplate: '/api/admin/members/:memberId/role' }),
      endpoint({ method: 'GET', pathTemplate: '/api/admin/members/:memberId' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/admin/members/:memberId/role', harvest({ ownerIds: ['m-1'], otherIds: ['m-9'] })],
    ])
    const hyp = authzHypothesis(surface, harvests, 'PATCH', '/api/admin/members/:memberId/role')
    const result: DifferentialResult = {
      probeClass: 'authz_matrix',
      origin: 'http://127.0.0.1:4100',
      pathAndQuery: hyp.pathAndQuery,
      verdict: 'signal',
      summary: 'cross-actor mutation accepted',
      anomalies: [{ type: 'unauthorized_access', resourceId: 'm-1', actor: 'other_persona', method: 'PATCH', status: 200 }],
      details: {},
      requestsSent: 3,
      exchangeIds: [],
      stoppedReason: null,
      notes: [],
      durationMs: 3,
    }
    const [spec] = synthesizeEngineSpecs(hyp, result)
    assert.ok(spec, 'a mutating authz spec is synthesized from the hint')
    const steps = spec.spec.steps as Array<{ id: string; role: string; request: { method: string; pathAndQuery: string } }>
    const preRead = steps.find(step => step.id === 'c1')
    const postRead = steps.find(step => step.id === 'p2')
    const bogusRead = steps.find(step => step.id === 'c3')
    assert.equal(preRead?.request.method, 'GET')
    assert.equal(preRead?.request.pathAndQuery, '/api/admin/members/m-1')
    assert.equal(postRead?.request.method, 'GET')
    assert.equal(postRead?.request.pathAndQuery, '/api/admin/members/m-1')
    assert.equal(bogusRead?.request.method, 'GET')
    const mutation = steps.find(step => step.id === 'p1')
    assert.equal(mutation?.request.pathAndQuery, '/api/admin/members/m-1/role')
    assert.equal(spec.spec.requiredRole, 'admin')
  })
})

describe('determinism', () => {
  test('readback inference is independent of surface order', () => {
    const forward = [
      endpoint({ method: 'PATCH', pathTemplate: '/api/members/:memberId' }),
      endpoint({ method: 'GET', pathTemplate: '/api/members/:memberId' }),
      endpoint({ method: 'GET', pathTemplate: '/api/members' }),
    ]
    const harvests = new Map<string, EndpointHarvest>([
      ['PATCH:/api/members/:memberId', harvest({ ownerIds: ['m-1'], otherIds: ['m-2'] })],
    ])
    const a = authzHypothesis(forward, harvests, 'PATCH', '/api/members/:memberId')
    const b = authzHypothesis([...forward].reverse(), harvests, 'PATCH', '/api/members/:memberId')
    assert.equal(a.readbackPath, '/api/members/{{id}}')
    assert.deepEqual(a, b)
  })
})
