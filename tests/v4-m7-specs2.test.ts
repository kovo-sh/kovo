/**
 * M7 round 2 (post-merge): authz identifier-binding precision, NoSQL operator injection, and the
 * v5 M3 synthesis contracts that await their probe anomaly shapes.
 *
 * The race / command-injection / traversal / step-skip / GraphQL-BOLA builders are owned by the
 * merged heldout2 implementation and locked by tests/v4-m7-heldout2.test.ts; this file does not
 * duplicate them.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { describe, test } from 'node:test'

// scopedAssetOrigin accepts loopback http origins only under the local-lab gate.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { synthesizeSpec, synthesizeSpecs } from '../scripts/benchmark-specs.ts'
import type { DiscoveredEndpoint, Hypothesis, HypothesisOutcome, ProbeEnv, ProfileCaps } from '../scripts/benchmark-probes.ts'

const caps: ProfileCaps = {
  mode: 'v4-full',
  phase0Recon: true,
  locations: new Set(['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var']),
  newProbeClasses: true,
  sessionAndCsrf: true,
  authMutation: true,
  timeDiff: true,
  inlineRetries: 2,
  tier: 3,
}

function env(over: Partial<ProbeEnv> = {}): ProbeEnv {
  return {
    origin: 'http://127.0.0.1:41000',
    broker: {} as ProbeEnv['broker'],
    grant: {} as ProbeEnv['grant'],
    storage: {} as ProbeEnv['storage'],
    runId: 'run-test',
    signal: AbortSignal.timeout(5_000),
    caps,
    owner: 'persona_a',
    other: 'persona_b',
    jwtPersona: 'persona_a',
    personaUserIds: ['u-1', 'u-2'],
    session: 'bench',
    slowProbesLeft: 10,
    ...over,
  } as ProbeEnv
}

function endpoint(over: Partial<DiscoveredEndpoint> = {}): DiscoveredEndpoint {
  return {
    method: 'GET',
    path: '/api/items',
    params: [{ name: 'q', location: 'query', isObjectId: false, isCsrf: false }],
    source: 'openapi',
    ...over,
  }
}

function hypothesis(over: Partial<Hypothesis> = {}): Hypothesis {
  const ep = over.endpoint ?? endpoint()
  const param = over.param ?? ep.params[0]
  return {
    key: 'k',
    endpoint: ep,
    probeClass: 'sqli_boolean',
    param,
    location: (param?.location ?? 'query') as Hypothesis['location'],
    method: 'GET',
    ...over,
  }
}

function outcome(over: Partial<HypothesisOutcome> = {}): HypothesisOutcome {
  return {
    hyp: hypothesis(),
    verdict: 'signal',
    anomalies: [],
    details: {},
    csrfRejected: false,
    contextReset: false,
    tierBlocked: false,
    requests: 3,
    ...over,
  }
}

function expectSpec(o: HypothesisOutcome, kind: string, e = env()) {
  const built = synthesizeSpec(o, e)
  assert.ok(built, `expected a ${kind} spec`)
  assert.equal(built.kind, kind)
  const parsed = declarativeReplaySpecSchema.safeParse(built.spec)
  assert.equal(parsed.success, true, parsed.success ? '' : JSON.stringify(parsed.error.issues))
  return built
}

function jq<T = { confirmed?: boolean; controlPassed?: boolean }>(program: string, payload: unknown): T {
  const out = execFileSync('jq', ['-c', program], { input: JSON.stringify(payload), encoding: 'utf8' })
  return JSON.parse(out) as T
}

const invoiceEndpoint = endpoint({
  path: '/api/v1/invoices/{id}',
  params: [{ name: 'id', location: 'path', isObjectId: true, isCsrf: false }],
})

function matrixOutcome(over: Partial<HypothesisOutcome> = {}, rows: Array<Record<string, unknown>> = [
  { resourceId: 'inv-1001', actor: 'owner', status: 200, bodyBytes: 80, bodySha256: 'sha-owner', accessible: true },
  { resourceId: 'inv-1001', actor: 'other_persona', status: 200, bodyBytes: 92, bodySha256: 'sha-other', similarityToOwner: 1, accessible: true },
  { resourceId: 'inv-1001', actor: 'anonymous', status: 403, bodyBytes: 12, accessible: false },
]): HypothesisOutcome {
  return outcome({
    hyp: hypothesis({ endpoint: invoiceEndpoint, probeClass: 'authz_matrix', param: undefined, location: undefined }),
    anomalies: [{ type: 'unauthorized_access', resourceId: 'inv-1001', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 1 }],
    details: { matrix: rows },
    ...over,
  })
}

describe('M7.2 authz synthesis: identifier binding', () => {
  test('genuine cross-tenant read gets owner, bogus-id and non-owner steps', () => {
    const built = expectSpec(matrixOutcome(), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; role: string; request: { pathAndQuery: string } }>
    assert.equal(steps.length, 3)
    assert.deepEqual(steps.map(s => s.id), ['c2', 'c1', 'p1'])
    assert.match(steps[0].request.pathAndQuery, /inv-gx9000001/)
    assert.notEqual(steps[0].request.pathAndQuery, steps[1].request.pathAndQuery)
    assert.match(String(built.spec.assertionsJq), /\.steps\.c2\.status/)
  })

  test('bogus id returning the owner session object is not confirming', () => {
    const built = expectSpec(matrixOutcome(), 'http_chain')
    const ownerBody = JSON.stringify({ id: 'inv-1001', memo: 'owner only' })
    const equivalent = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
        c2: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
        p1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
      },
    })
    assert.equal(equivalent.confirmed, false)
    assert.equal(equivalent.controlPassed, false)
  })

  test('a rejected nonexistent identifier plus owner-equivalent non-owner body confirms', () => {
    const built = expectSpec(matrixOutcome(), 'http_chain')
    const ownerBody = JSON.stringify({ id: 'inv-1001', memo: 'owner only' })
    const genuine = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
        c2: { status: 404, body: '{"error":"not found"}', json: { error: 'not found' } },
        p1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
      },
    })
    assert.equal(genuine.confirmed, true)
    assert.equal(genuine.controlPassed, true)
  })

  test('owner lookup failure refuses to synthesize', () => {
    const rows = [
      { resourceId: 'inv-1001', actor: 'owner', status: 404, bodyBytes: 20, accessible: false },
      { resourceId: 'inv-1001', actor: 'other_persona', status: 200, bodyBytes: 92, similarityToOwner: 1, accessible: true },
    ]
    assert.equal(synthesizeSpec(matrixOutcome({}, rows), env()), null)
  })

  test('empty owner acknowledgement does not prove object access', () => {
    const rows = [
      { resourceId: 'inv-1001', actor: 'owner', status: 200, bodyBytes: 0, accessible: true },
      { resourceId: 'inv-1001', actor: 'other_persona', status: 200, bodyBytes: 0, similarityToOwner: 1, accessible: true },
    ]
    assert.equal(synthesizeSpec(matrixOutcome({}, rows), env()), null)
  })

  test('anonymous-readable identical resource is treated as public', () => {
    const rows = [
      { resourceId: 'inv-1001', actor: 'owner', status: 200, bodyBytes: 80, bodySha256: 'sha-owner', accessible: true },
      { resourceId: 'inv-1001', actor: 'other_persona', status: 200, bodyBytes: 80, bodySha256: 'sha-owner', similarityToOwner: 1, accessible: true },
      { resourceId: 'inv-1001', actor: 'anonymous', status: 200, bodyBytes: 80, bodySha256: 'sha-owner', similarityToOwner: 1, accessible: true },
    ]
    assert.equal(synthesizeSpec(matrixOutcome({}, rows), env()), null)
  })

  test('mutating BFLA keeps the object negative control and body template', () => {
    const ep = endpoint({
      method: 'POST',
      path: '/api/admin/users/{id}/promote',
      params: [{ name: 'id', location: 'path', isObjectId: true, isCsrf: false }],
    })
    const rows = [
      { resourceId: 'u-1001', actor: 'owner', status: 200, bodyBytes: 70, accessible: true },
      { resourceId: 'u-1001', actor: 'other_persona', status: 200, bodyBytes: 70, similarityToOwner: 1, accessible: true },
    ]
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{ type: 'unauthorized_access', resourceId: 'u-1001', actor: 'other_persona', method: 'POST', status: 200, bodyTemplate: { note: 'promote' } }],
      details: { matrix: rows },
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { jsonBody?: Record<string, unknown> } }>
    assert.equal(steps[0].request.jsonBody?.note, 'promote')
    const body = JSON.stringify({ ok: true, user: 'u-1001', role: 'admin' })
    const confirmed = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body, json: { ok: true, user: 'u-1001', role: 'admin' } },
        c2: { status: 404, body: '{"error":"user not found"}', json: { error: 'user not found' } },
        p1: { status: 200, body, json: { ok: true, user: 'u-1001', role: 'admin' } },
      },
    })
    assert.equal(confirmed.confirmed, true)
  })

  test('function-level BFLA uses the observed function body without an id control', () => {
    const ep = endpoint({ method: 'POST', path: '/api/v1/admin/orgs', params: [] })
    const rows = [
      { resourceId: '', actor: 'owner', status: 200, bodyBytes: 60, accessible: true },
      { resourceId: '', actor: 'other_persona', status: 200, bodyBytes: 60, similarityToOwner: 1, accessible: true },
    ]
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{ type: 'unauthorized_access', resourceId: '', actor: 'other_persona', method: 'POST', status: 200, functionLevel: true, bodyTemplate: ['acme', 'guardian'] }],
      details: { matrix: rows },
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { pathAndQuery: string; jsonBody?: unknown } }>
    assert.deepEqual(steps.map(s => s.id), ['c1', 'p1'])
    assert.equal(steps[0].request.pathAndQuery, '/api/v1/admin/orgs')
    assert.deepEqual(steps[0].request.jsonBody, ['acme', 'guardian'])

    const trivial = rows.map(row => ({ ...row, bodyBytes: 10 }))
    assert.equal(synthesizeSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{ type: 'unauthorized_access', resourceId: '', actor: 'other_persona', method: 'POST', status: 200, functionLevel: true }],
      details: { matrix: trivial },
    }), env()), null)
  })

  test('an outcome without the actor matrix still carries a sentinel negative control', () => {
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: invoiceEndpoint, probeClass: 'authz_matrix', param: undefined, location: undefined }),
      anomalies: [{ type: 'unauthorized_access', resourceId: 'inv-1001', actor: 'other_persona', method: 'GET', status: 200 }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { pathAndQuery: string } }>
    assert.deepEqual(steps.map(s => s.id), ['c2', 'c1', 'p1'])
    assert.match(steps[0].request.pathAndQuery, /guardian-none-/)
  })
})

describe('M7.2 NoSQL operator injection synthesis', () => {
  const nosqlHyp = () => hypothesis({
    endpoint: endpoint({ path: '/api/users', params: [{ name: 'q', location: 'query', isObjectId: false, isCsrf: false }] }),
    probeClass: 'nosqli_type',
    location: 'query',
  })

  test('$ne divergence with a neutral-object control becomes a three-step chain', () => {
    const built = expectSpec(outcome({
      hyp: nosqlHyp(),
      anomalies: [{ type: 'operator_type_divergence', operator: 'ne', status: 200 }],
      details: { neutralMatchesBase: true },
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ request: { pathAndQuery: string } }>
    assert.equal(steps.length, 3)
    assert.match(steps[2].request.pathAndQuery, /%24ne/)
    const hit = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body: '{"users":[{"name":"guardian"}]}', json: { users: [{ name: 'guardian' }] } },
        c2: { status: 200, body: '{"users":[{"name":"guardian"}]}', json: { users: [{ name: 'guardian' }] } },
        p1: { status: 200, body: '{"users":[{"name":"a"},{"name":"b"}]}', json: { users: [{ name: 'a' }, { name: 'b' }] } },
      },
    })
    assert.equal(hit.confirmed, true)
  })

  test('missing neutral-object control or unknown operator refuses to synthesize', () => {
    const base = outcome({
      hyp: nosqlHyp(),
      anomalies: [{ type: 'operator_type_divergence', operator: 'ne', status: 200 }],
      details: { neutralMatchesBase: false },
    })
    assert.equal(synthesizeSpec(base, env()), null)
    assert.equal(synthesizeSpec({ ...base, details: { neutralMatchesBase: true }, anomalies: [{ type: 'operator_type_divergence', operator: 'regex', status: 200 }] }, env()), null)
  })
})

describe('v5 M3 contracts (awaiting probe shapes)', () => {
  test('CSRF state change: token-bound control, tokenless probe, read-back', () => {
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: endpoint({ method: 'PATCH', path: '/api/v1/profile', params: [] }), probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'PATCH' }),
      anomalies: [{
        type: 'csrf_state_change', path: '/api/v1/profile', method: 'PATCH', bodyField: 'displayName',
        controlValue: 'guardian-control', expectedValue: 'guardian-probe', readPath: '/api/v1/profile', stateField: 'displayName',
      }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { method: string; csrfBind?: boolean; jsonBody?: Record<string, unknown> } }>
    assert.deepEqual(steps.map(s => s.id), ['c1', 'p1', 'p2'])
    assert.equal(steps[0].request.csrfBind, true)
    assert.equal(steps[1].request.csrfBind, undefined)
    const hit = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200 },
        p1: { status: 200 },
        p2: { status: 200, json: { displayName: 'guardian-probe' } },
      },
    })
    assert.equal(hit.confirmed, true)
    const untouched = jq(String(built.spec.assertionsJq), {
      steps: { c1: { status: 200 }, p1: { status: 403 }, p2: { status: 200, json: { displayName: 'guardian-control' } } },
    })
    assert.equal(untouched.confirmed, false)
  })

  test('webhook signature bypass: tampered control rejected, unsigned delivery accepted', () => {
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: endpoint({ method: 'POST', path: '/webhooks/events', params: [] }), probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{
        type: 'webhook_signature_bypass', path: '/webhooks/events', headerName: 'X-Signature',
        body: { event: 'invoice.paid' }, readPath: '/api/v1/orders/1', stateField: 'status', expectedValue: 'paid',
      }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { headers?: Record<string, string>; jsonBody?: Record<string, unknown> } }>
    assert.equal(steps[0].request.headers?.['X-Signature'], 'guardian-invalid-signature')
    assert.equal(steps[1].request.headers?.['X-Signature'], undefined)
    const hit = jq(String(built.spec.assertionsJq), {
      steps: { c1: { status: 401 }, p1: { status: 200 }, p2: { status: 200, json: { status: 'paid' } } },
    })
    assert.equal(hit.confirmed, true)
  })

  test('open redirect: observed external target is replayed against a benign control', () => {
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: endpoint({ path: '/sso/start', params: [{ name: 'next', location: 'query', isObjectId: false, isCsrf: false }] }), probeClass: 'authz_matrix', param: { name: 'next', location: 'query', isObjectId: false, isCsrf: false }, location: 'query' }),
      anomalies: [{ type: 'open_redirect_differential', payload: 'https://evil.invalid/cb', location: 'https://evil.invalid/cb' }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ request: { pathAndQuery: string } }>
    assert.match(steps[0].request.pathAndQuery, /guardian-control\.invalid/)
    assert.match(steps[1].request.pathAndQuery, /evil\.invalid/)
    const hit = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, headers: {} },
        p1: { status: 302, headers: { location: 'https://evil.invalid/cb' } },
      },
    })
    assert.equal(hit.confirmed, true)
    const noRedirect = jq(String(built.spec.assertionsJq), { steps: { c1: { status: 200, headers: {} }, p1: { status: 200, headers: {} } } })
    assert.equal(noRedirect.confirmed, false)
  })

  test('write-path BOLA: cross-tenant write, owner read-back and cleanup', () => {
    const ep = endpoint({
      method: 'PATCH',
      path: '/api/v1/documents/{id}',
      params: [{ name: 'id', location: 'path', isObjectId: true, isCsrf: false }],
    })
    const built = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'PATCH' }),
      anomalies: [{
        type: 'write_path_bola', resourceId: 'doc-1001', path: '/api/v1/documents/{id}', method: 'PATCH',
        writeBody: { title: 'pwned' }, readPath: '/api/v1/documents/{id}', stateField: 'title',
        expectedValue: 'pwned', cleanupBody: { title: 'original' },
      }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; role: string; request: { pathAndQuery: string; jsonBody?: Record<string, unknown> } }>
    assert.deepEqual(steps.map(s => s.id), ['c1', 'p1', 'p2', 'z1'])
    assert.equal(steps[1].request.pathAndQuery, '/api/v1/documents/doc-1001')
    assert.equal(steps[3].role, 'cleanup')
    const hit = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, json: { title: 'original' } },
        p1: { status: 200 },
        p2: { status: 200, json: { title: 'pwned' } },
      },
    })
    assert.equal(hit.confirmed, true)
    const notPersisted = jq(String(built.spec.assertionsJq), {
      steps: { c1: { status: 200, json: { title: 'original' } }, p1: { status: 200 }, p2: { status: 200, json: { title: 'original' } } },
    })
    assert.equal(notPersisted.confirmed, false)
  })

  test('M3 contracts refuse partial evidence', () => {
    const base = { hyp: hypothesis({ probeClass: 'authz_matrix', param: undefined, location: undefined }), details: {} }
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'csrf_state_change', path: '/x' }] }), env()), null)
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'webhook_signature_bypass', path: '/x', headerName: 'X-Sig' }] }), env()), null)
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'open_redirect_differential', payload: 'https://evil.invalid' }] }), env()), null)
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'write_path_bola', resourceId: 'x' }] }), env()), null)
  })
})

describe('M7.2 robustness', () => {
  test('path traversal normalization evidence stays unsynthesized', () => {
    const o = outcome({
      hyp: hypothesis({ endpoint: endpoint({ path: '/api/files/download', params: [{ name: 'name', location: 'query', isObjectId: false, isCsrf: false }] }), probeClass: 'path_traversal_benign', param: undefined, location: undefined }),
      anomalies: [{ type: 'path_normalization_differential', variant: 'encoded_dots', status: 200 }],
    })
    assert.equal(synthesizeSpec(o, env()), null)
  })

  test('a malformed anomaly never leaks an exception', () => {
    const cyclic: Record<string, unknown> = { type: 'workflow_step_skip', fromState: 'a', toState: 'b', path: '/x', status: 200 }
    cyclic.self = cyclic
    assert.doesNotThrow(() => synthesizeSpecs(outcome({ anomalies: [cyclic] }), env()))
    assert.deepEqual(synthesizeSpecs(outcome({ anomalies: [{ type: 'workflow_step_skip', fromState: 'a', toState: 'b', path: '/x', status: 200, jsonBody: { n: 1n } }] }), env()), [])
  })

  test('non-signal outcomes never synthesize', () => {
    const o = outcome({
      verdict: 'inconclusive',
      hyp: hypothesis({ probeClass: 'race_burst' }),
      anomalies: [{ type: 'race_double_spend', path: '/x', producerPath: '/y', param: 'code', consumeBody: {} }],
    })
    assert.deepEqual(synthesizeSpecs(o, env()), [])
  })
})
