/**
 * v7 — canonical spec synthesis for the two Realism #4 4-hop signals.
 *
 * Pins the replacement rules that retire the two bounded fallback proof shapes in `execution.ts`:
 *
 *   1. An object-authorization GET proves *same addressed object*, not byte-identical bodies: the
 *      victim identifier must appear in the probe body while per-actor echoes (`actor`) differ.
 *      The publicness veto and the bogus-id negative control stay in force.
 *   2. A structural SQL error is a real signal, but only when the failing arm carries a
 *      dialect/engine fingerprint matched to the injected construct; a bare 5xx is still rejected.
 *   3. A privileged function mutation proves a persisted entitlement change: the control arm
 *      restores a non-privileged baseline for the granted field, a separate readback shows the
 *      escalated value, and a bogus-id mutation acknowledged with 2xx is only admissible when the
 *      same bogus identifier reads back absent.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  assessAuthorizationImpact,
  assessStatusOnlyDivergence,
} from '../src/server/oracle-invariants.ts'
import type { ActorIdentity, ImpactStep } from '../src/server/oracle-invariants.ts'
import { buildSqlErrorChain, synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import type { EngineHypothesis } from '../src/server/deterministic-specs.ts'
import type { DifferentialResult } from '../src/server/probes/context.ts'
import {
  assessHttpChainProofStrength,
  classifyHttpChainAssertion,
} from '../src/server/replay-verifier.ts'
import { httpChainReplaySpecSchema } from '../src/replay-spec.ts'

const ORIGIN = 'https://spec-authz.test'

function authzResult(overrides: {
  method?: 'GET' | 'PATCH'
  functionLevel?: boolean
  resourceId?: string
  matrix?: Array<Record<string, unknown>>
  anomalies?: Array<Record<string, unknown>>
} = {}): DifferentialResult {
  const resourceId = overrides.resourceId ?? 'inv-alpha-1'
  const method = overrides.method ?? 'GET'
  const matrix = overrides.matrix ?? [
    { resourceId, actor: 'owner', status: 200, bodyBytes: 120, bodySha256: 'a'.repeat(64), accessible: true },
    { resourceId, actor: 'other_persona', status: 200, bodyBytes: 118, bodySha256: 'b'.repeat(64), similarityToOwner: 0.9, accessible: true },
    { resourceId, actor: 'anonymous', status: 401, accessible: false },
  ]
  return {
    probeClass: 'authz_matrix',
    origin: ORIGIN,
    pathAndQuery: '/',
    verdict: 'signal',
    summary: 'matrix',
    anomalies: overrides.anomalies ?? [{
      type: 'unauthorized_access',
      resourceId,
      actor: 'other_persona',
      method,
      status: 200,
      similarityToOwner: 0.9,
      functionLevel: overrides.functionLevel === true,
      ...(overrides.method === 'PATCH' ? { bodyTemplate: { role: 'admin', grant: 'admin', level: 'admin' } } : {}),
    }],
    details: { matrix, suggestedReplayKind: 'http_chain' },
    requestsSent: 4,
    exchangeIds: ['ex-1'],
    stoppedReason: null,
    notes: [],
    durationMs: 5,
  }
}

function getReadHypothesis(): EngineHypothesis {
  return {
    key: 'authz|invoices',
    endpoint: {
      id: 'derived:0:GET:/v2/billing/invoices/:id',
      origin: ORIGIN,
      method: 'GET',
      pathTemplate: '/v2/billing/invoices/:id',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/v2/billing/invoices/{{id}}',
    ownerPersona: 'mono-alice',
    otherPersona: 'mono-bob',
    resourceIds: ['inv-alpha-1'],
    risk: 90,
  }
}

function privilegedPatchHypothesis(): EngineHypothesis {
  return {
    key: 'authz|admin-users',
    endpoint: {
      id: 'declared:0:PATCH:/v3/admin/users/:id',
      origin: ORIGIN,
      method: 'PATCH',
      pathTemplate: '/v3/admin/users/:id',
      params: [{ name: 'id', location: 'path', isObjectId: true }],
    },
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'PATCH',
    pathAndQuery: '/v3/admin/users/{{id}}',
    ownerPersona: 'mono-admin',
    otherPersona: 'mono-alice',
    resourceIds: ['mono-bob'],
    authzRequiredRole: 'admin',
    readbackPath: '/v3/admin/users/{{id}}',
    csrfBind: true,
    jsonBody: { role: 'admin', grant: 'admin', level: 'admin' },
    risk: 120,
  }
}

function actor(handle: string, role: ActorIdentity['role'], tenant: string): ActorIdentity {
  return { handle, role, tenant, auth: 'cookie', sameSite: null }
}

function step(overrides: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    actor: actor('mono-alice', 'member', 'tenant-alpha'),
    ...overrides,
  }
}

// ============================================================================
// 1. GET object authorization — identity-scoped, not body-identical
// ============================================================================

test('GET authz proof binds the served object identity and admits an actor echo', () => {
  const [candidate] = synthesizeEngineSpecs(getReadHypothesis(), authzResult())
  assert.ok(candidate)
  assert.equal(candidate.kind, 'http_chain')
  assert.equal(candidate.vulnClass, 'bola')
  const spec = httpChainReplaySpecSchema.parse(candidate.spec)
  assert.equal(spec.category, 'idor')
  // The victim object's identifier is asserted in the non-owner response...
  assert.match(spec.assertionsJq, /\.steps\.p1\.body \| contains\("inv-alpha-1"\)/)
  // ...and the bogus-id negative control is still part of the proof.
  assert.deepEqual(spec.steps.map(item => item.id), ['c2', 'c1', 'p1'])
  assert.deepEqual(spec.steps[0]!.expectedStatus, [400, 401, 403, 404, 405, 409, 410, 422])
  assert.equal(classifyHttpChainAssertion(spec.assertionsJq), 'content_bound')

  // Control served the object, probe served the same object but echoed the probe actor instead.
  const ownerBody = JSON.stringify({ invoice: { id: 'inv-alpha-1', total: 100 }, actor: 'mono-alice' })
  const probeBody = JSON.stringify({ invoice: { id: 'inv-alpha-1', total: 100 }, actor: 'mono-bob' })
  const snapshots = [
    { index: 0, id: 'c2', role: 'control', method: 'GET', route: '/v2/billing/invoices/mono-gx9000001', pathAndQuery: '/v2/billing/invoices/mono-gx9000001', actor: 'mono-alice', status: 404, body: '{"error":"not_found"}', bodyBytes: 20, mediaType: 'application/json', json: { error: 'not_found' }, secretMatches: 0 },
    { index: 1, id: 'c1', role: 'control', method: 'GET', route: '/v2/billing/invoices/inv-alpha-1', pathAndQuery: '/v2/billing/invoices/inv-alpha-1', actor: 'mono-alice', status: 200, body: ownerBody, bodyBytes: ownerBody.length, mediaType: 'application/json', json: JSON.parse(ownerBody), secretMatches: 0 },
    { index: 2, id: 'p1', role: 'probe', method: 'GET', route: '/v2/billing/invoices/inv-alpha-1', pathAndQuery: '/v2/billing/invoices/inv-alpha-1', actor: 'mono-bob', status: 200, body: probeBody, bodyBytes: probeBody.length, mediaType: 'application/json', json: JSON.parse(probeBody), secretMatches: 0 },
  ]
  const strength = assessHttpChainProofStrength(spec, snapshots)
  assert.equal(strength.satisfied, true, strength.reason)
  assert.equal(strength.differential, 'cross_actor_access')
})

test('GET authz proof still vetoes a public payload shared with an anonymous caller', () => {
  const shared = 'c'.repeat(64)
  const result = authzResult({
    matrix: [
      { resourceId: 'inv-alpha-1', actor: 'owner', status: 200, bodyBytes: 90, bodySha256: shared, accessible: true },
      { resourceId: 'inv-alpha-1', actor: 'other_persona', status: 200, bodyBytes: 90, bodySha256: shared, similarityToOwner: 0.99, accessible: true },
      { resourceId: 'inv-alpha-1', actor: 'anonymous', status: 200, bodyBytes: 90, bodySha256: shared, similarityToOwner: 0.99, accessible: true },
    ],
  })
  assert.deepEqual(synthesizeEngineSpecs(getReadHypothesis(), result), [], 'publicness veto stays in force')
})

// ============================================================================
// 2. Structural SQL error — 5xx only with a construct-matched fingerprint
// ============================================================================

function sqlResult(dialect?: string): DifferentialResult {
  return {
    probeClass: 'sqli_boolean',
    origin: ORIGIN,
    pathAndQuery: '/v2/reports/export?sort=',
    verdict: 'signal',
    summary: 'sql error',
    anomalies: dialect ? [{ type: 'db_error_fingerprint', dialect }] : [],
    details: { baselineValue: 'created_at', dbErrorDialect: dialect ?? null },
    requestsSent: 6,
    exchangeIds: ['ex-2'],
    stoppedReason: null,
    notes: [],
    durationMs: 9,
  }
}

function sqlHypothesis(): EngineHypothesis {
  return {
    key: 'sqli_boolean|reports',
    endpoint: {
      id: 'derived:2:GET:/v2/reports/export',
      origin: ORIGIN,
      method: 'GET',
      pathTemplate: '/v2/reports/export',
      params: [{ name: 'sort', location: 'query' }],
    },
    probeClass: 'sqli_boolean',
    intent: 'sqli',
    method: 'GET',
    pathAndQuery: '/v2/reports/export',
    param: { name: 'sort', location: 'query' },
    location: 'query',
    baselineValue: 'created_at',
    ownerPersona: 'mono-alice',
    risk: 90,
  }
}

test('structural SQL error renders a fingerprint-bound http_chain error proof', () => {
  const candidates = synthesizeEngineSpecs(sqlHypothesis(), sqlResult('sqlite'))
  assert.ok(candidates.length > 1, 'boolean shapes remain as bounded backups')
  const [candidate] = candidates
  assert.equal(candidate!.kind, 'http_chain')
  assert.equal(candidate!.vulnClass, 'sqli')
  const spec = httpChainReplaySpecSchema.parse(candidate!.spec)
  assert.equal(spec.cwe, 'CWE-89')
  assert.equal(spec.category, 'sqli')
  assert.deepEqual(spec.steps.map(item => item.role), ['control', 'probe'])
  assert.match(spec.steps[0]!.request.pathAndQuery, /sort=created_at$/)
  assert.match(spec.steps[1]!.request.pathAndQuery, /sort=created_at%27$/)
  assert.match(spec.assertionsJq, /status >= 500/)
  assert.match(spec.assertionsJq, /sqlite_error/)
  assert.equal(classifyHttpChainAssertion(spec.assertionsJq), 'content_bound')
})

test('a bare 5xx without a construct fingerprint is never rendered or confirmed', () => {
  // No dialect observed: no error proof is synthesised (only the boolean backups remain).
  assert.equal(buildSqlErrorChain(sqlHypothesis(), sqlResult()), null)
  assert.ok(synthesizeEngineSpecs(sqlHypothesis(), sqlResult()).every(item => item.kind !== 'http_chain'))
  // An unrecognised dialect label is not a fingerprint either.
  assert.equal(buildSqlErrorChain(sqlHypothesis(), { ...sqlResult(), anomalies: [{ type: 'db_error_fingerprint', dialect: 'unknown-db' }] }), null)

  // Universal status-only ban: the same 200 -> 500 pair is proof only with a fingerprint.
  const control = step({ id: 'c1', arm: 'control', method: 'GET', status: 200, json: { rows: ['a'] }, body: '{"rows":["a"]}' })
  const bareProbe = step({
    id: 'p1', arm: 'probe', method: 'GET', status: 500,
    json: { error: 'Internal Server Error' }, body: '{"error":"Internal Server Error"}',
  })
  assert.equal(assessStatusOnlyDivergence([control, bareProbe]).statusOnly, true)
  const fingerprinted = step({
    id: 'p1', arm: 'probe', method: 'GET', status: 500,
    json: { error: 'SQLITE_ERROR: near "\'": syntax error' },
    body: '{"error":"SQLITE_ERROR: near \\"\'\\": syntax error"}',
  })
  assert.equal(assessStatusOnlyDivergence([control, fingerprinted]).statusOnly, false)
})

// ============================================================================
// 3. Privileged function mutation — persisted escalation, bounded negative control
// ============================================================================

test('privileged role grant replays as a demote-then-escalate persisted delta', () => {
  const result = authzResult({
    method: 'PATCH',
    resourceId: 'mono-bob',
    matrix: [
      { resourceId: 'mono-bob', actor: 'owner', status: 200, bodyBytes: 60, accessible: true },
      { resourceId: 'mono-bob', actor: 'other_persona', status: 200, bodyBytes: 60, similarityToOwner: 0.9, accessible: true },
      { resourceId: 'mono-bob', actor: 'anonymous', status: 401, accessible: false },
    ],
  })
  const [candidate] = synthesizeEngineSpecs(privilegedPatchHypothesis(), result)
  assert.ok(candidate)
  assert.equal(candidate.kind, 'http_chain')
  assert.equal(candidate.vulnClass, 'bfla', 'privileged function write is a vertical class')
  const spec = httpChainReplaySpecSchema.parse(candidate.spec)
  assert.equal(spec.category, 'bfla')
  assert.equal(spec.requiredRole, 'admin')
  assert.deepEqual(spec.expectedImpactEvents, ['privilege_escalation'])
  assert.deepEqual(spec.steps.map(item => item.id), ['w1', 'c2', 'c3', 'c1', 'p1', 'p2'])

  const [baseline, bogusMutation, bogusRead, before, probe, after] = spec.steps
  assert.equal(bogusMutation!.request.method, 'PATCH')
  assert.match(bogusMutation!.request.pathAndQuery, /^\/v3\/admin\/users\/mono-gx9000001$/)
  assert.equal(bogusRead!.request.method, 'GET')
  assert.equal(bogusRead!.request.pathAndQuery, '/v3/admin/users/mono-gx9000001')
  assert.deepEqual(bogusRead!.expectedStatus, [404, 410])
  // Control restores a non-privileged value of the exact field the probe elevates.
  assert.deepEqual((baseline!.request as { jsonBody?: Record<string, unknown> }).jsonBody, { role: 'member', grant: 'admin', level: 'admin' })
  assert.deepEqual((probe!.request as { jsonBody?: Record<string, unknown> }).jsonBody, { role: 'admin', grant: 'admin', level: 'admin' })
  assert.equal(before!.request.persona, 'mono-admin')
  assert.equal(probe!.request.persona, 'mono-alice')
  assert.equal(after!.request.pathAndQuery, '/v3/admin/users/mono-bob')
  assert.match(spec.assertionsJq, /\.steps\.c3\.status == 404/)
  assert.match(spec.assertionsJq, /\.steps\.p2\.json \| if type == "object" then \.\["role"\] else null end\) == "admin"/)
  assert.match(spec.assertionsJq, /\.steps\.c1\.json \| if type == "object" then \.\["role"\] else null end\) == "member"/)
  assert.equal(classifyHttpChainAssertion(spec.assertionsJq), 'content_bound')

  // The oracle accepts the recorded evidence: member actor, required admin, role change persisted.
  const owner = actor('mono-admin', 'admin', 'tenant-alpha')
  const member = actor('mono-alice', 'member', 'tenant-alpha')
  const impactSteps: ImpactStep[] = [
    step({ id: 'c2', arm: 'control', method: 'PATCH', route: '/v3/admin/users/mono-gx9000001', status: 200, actor: owner, json: { user: { id: 'mono-gx9000001', role: 'member' } } }),
    step({ id: 'c3', arm: 'control', method: 'GET', route: '/v3/admin/users/mono-gx9000001', status: 404, actor: owner, json: { error: 'not_found' } }),
    step({ id: 'w1', arm: 'control', method: 'PATCH', route: '/v3/admin/users/mono-bob', status: 200, actor: owner, json: { user: { id: 'mono-bob', role: 'member' } } }),
    step({ id: 'c1', arm: 'control', method: 'GET', route: '/v3/admin/users/mono-bob', status: 200, actor: owner, json: { id: 'mono-bob', role: 'member', tenant: 'tenant-beta' } }),
    step({ id: 'p1', arm: 'probe', method: 'PATCH', route: '/v3/admin/users/mono-bob', status: 200, actor: member, json: { user: { id: 'mono-bob', role: 'admin' } }, requestJson: { role: 'admin' } }),
    step({ id: 'p2', arm: 'control', method: 'GET', route: '/v3/admin/users/mono-bob', status: 200, actor: owner, json: { id: 'mono-bob', role: 'admin', tenant: 'tenant-beta' } }),
  ]
  const assessment = assessAuthorizationImpact({
    impactClass: 'bfla',
    steps: impactSteps,
    requiredRole: 'admin',
    oracleEvents: ['privilege_escalation'],
    targetOrigin: ORIGIN,
  })
  assert.equal(assessment.satisfied, true, assessment.reason)
  assert.equal(assessment.evidence.roleDifferential, true)
  assert.equal(assessment.evidence.persisted, true)
  assert.ok(assessment.evidence.changedFields.includes('role'))
})

test('a bogus identifier that is also served is not a valid negative control', () => {
  const [candidate] = synthesizeEngineSpecs(privilegedPatchHypothesis(), authzResult({ method: 'PATCH', resourceId: 'mono-bob' }))
  assert.ok(candidate)
  const spec = httpChainReplaySpecSchema.parse(candidate.spec)
  // The control is only admissible through the readback: a 4xx mutation OR a 2xx whose same-id
  // readback is absent. A served bogus object therefore cannot satisfy it.
  assert.match(spec.assertionsJq, /\.steps\.c2\.status >= 400/)
  assert.match(spec.assertionsJq, /\.steps\.c3\.status == 404/)
  assert.ok(!/\.steps\.c3\.status >= 200/.test(spec.assertionsJq))
})

test('the probe matrix body stays benign while the replay applies the required entitlement', () => {
  // The matrix reports the body the surface published (role=member). Escalating every listed
  // record would be destructive and would also hide the replay delta; the replay itself sets the
  // declared required role on the field the body already carries.
  const result = authzResult({
    method: 'PATCH',
    resourceId: 'mono-bob',
    anomalies: [{
      type: 'unauthorized_access',
      resourceId: 'mono-bob',
      actor: 'other_persona',
      method: 'PATCH',
      status: 200,
      similarityToOwner: 0.9,
      bodyTemplate: { id: 'mono-bob', email: 'bob@example.test', tenant: 'tenant-beta', role: 'member' },
    }],
  })
  const [candidate] = synthesizeEngineSpecs(privilegedPatchHypothesis(), result)
  assert.ok(candidate)
  const spec = httpChainReplaySpecSchema.parse(candidate.spec)
  assert.equal(spec.category, 'bfla')
  const [baseline, bogusMutation, bogusRead, before, probe, after] = spec.steps
  assert.equal((baseline!.request as { jsonBody?: Record<string, unknown> }).jsonBody!.role, 'member')
  assert.equal((probe!.request as { jsonBody?: Record<string, unknown> }).jsonBody!.role, 'admin')
  assert.equal((before!.request as { jsonBody?: Record<string, unknown> }).jsonBody, undefined, 'readback is a GET')
  assert.equal(after!.request.method, 'GET')
  assert.equal(bogusMutation!.request.method, 'PATCH')
  assert.deepEqual(bogusRead!.expectedStatus, [404, 410])
  assert.match(spec.assertionsJq, /\.steps\.p2\.json \| if type == "object" then \.\["role"\] else null end\) == "admin"/)
})

test('a route without a privilege field in its body is not rewritten', () => {
  const result = authzResult({
    method: 'PATCH',
    resourceId: 'mono-bob',
    anomalies: [{
      type: 'unauthorized_access',
      resourceId: 'mono-bob',
      actor: 'other_persona',
      method: 'PATCH',
      status: 200,
      bodyTemplate: { title: 'quarterly report' },
    }],
  })
  const [candidate] = synthesizeEngineSpecs(privilegedPatchHypothesis(), result)
  assert.ok(candidate)
  const spec = httpChainReplaySpecSchema.parse(candidate.spec)
  assert.deepEqual(spec.steps.map(item => item.id), ['w1', 'c2', 'c3', 'c1', 'p1', 'p2'])
  assert.equal((spec.steps[4]!.request as { jsonBody?: Record<string, unknown> }).jsonBody!.title, 'quarterly report')
})
