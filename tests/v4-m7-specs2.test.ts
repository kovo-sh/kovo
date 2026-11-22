/**
 * M7 round 2: synthesis for the remaining anomaly classes plus authz identifier-binding guards.
 *
 * Every fixture mirrors an anomaly the surface-engine probe can emit. Specs are evaluated with the
 * same jq expressions the Zero-LLM verifier runs, so a "bogus id returns the owner's own object"
 * response is proven non-confirming rather than merely asserted in prose.
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

function matrixOutcome(over: Partial<HypothesisOutcome> = {}, rows = [
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
  test('genuine cross-tenant read gets an owner, bogus-id and non-owner step', () => {
    const built = expectSpec(matrixOutcome(), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; role: string; request: { pathAndQuery: string } }>
    assert.equal(steps.length, 3)
    assert.deepEqual(steps.map(s => s.id), ['c1', 'n1', 'p1'])
    assert.match(steps[1].request.pathAndQuery, /inv-gx9000001/)
    assert.notEqual(steps[0].request.pathAndQuery, steps[1].request.pathAndQuery)
    assert.match(String(built.spec.assertionsJq), /\.steps\.n1\.status/)
  })

  test('bogus id returning the owner session object is not confirming', () => {
    const built = expectSpec(matrixOutcome(), 'http_chain')
    const ownerBody = JSON.stringify({ id: 'inv-1001', memo: 'owner only' })
    const equivalent = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
        n1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
        p1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
      },
    })
    assert.equal(equivalent.confirmed, false)
    assert.equal(equivalent.controlPassed, false)
  })

  test('a missing identifier (404) plus identical non-owner body confirms', () => {
    const built = expectSpec(matrixOutcome(), 'http_chain')
    const ownerBody = JSON.stringify({ id: 'inv-1001', memo: 'owner only' })
    const genuine = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body: ownerBody, json: { id: 'inv-1001', memo: 'owner only' } },
        n1: { status: 404, body: '{"error":"not found"}', json: { error: 'not found' } },
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

  test('mutating BFLA needs a non-trivial object and a rejected bogus id', () => {
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
      anomalies: [{ type: 'unauthorized_access', resourceId: 'u-1001', actor: 'other_persona', method: 'POST', status: 200 }],
      details: { matrix: rows },
    }), 'http_chain')
    const body = JSON.stringify({ ok: true, user: 'u-1001', role: 'admin' })
    const confirmed = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, body, json: { ok: true, user: 'u-1001', role: 'admin' } },
        n1: { status: 404, body: '{"error":"user not found"}', json: { error: 'user not found' } },
        p1: { status: 200, body, json: { ok: true, user: 'u-1001', role: 'admin' } },
      },
    })
    assert.equal(confirmed.confirmed, true)

    const trivial = rows.map(row => ({ ...row, bodyBytes: 10 }))
    assert.equal(synthesizeSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'authz_matrix', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{ type: 'unauthorized_access', resourceId: 'u-1001', actor: 'other_persona', method: 'POST', status: 200 }],
      details: { matrix: trivial },
    }), env()), null)
  })
})

describe('M7.2 race_burst synthesis', () => {
  const raceHyp = () => hypothesis({
    endpoint: endpoint({ method: 'POST', path: '/api/coupon/redeem', params: [] }),
    probeClass: 'workflow_invariant',
    param: undefined,
    location: undefined,
    method: 'POST',
  })

  function raceOutcome(anomaly: Record<string, unknown> = {}): HypothesisOutcome {
    return outcome({
      hyp: raceHyp(),
      anomalies: [{
        type: 'race_condition_differential', path: '/api/coupon/redeem', method: 'POST',
        attempts: 5, successes: 3, allowed: 1, readPath: '/api/wallet', jsonBody: { code: 'SAVE50' }, ...anomaly,
      }],
    })
  }

  test('a real double-spend differential becomes a control/burst/post-check race_burst', () => {
    const built = expectSpec(raceOutcome(), 'race_burst')
    assert.equal(built.spec.kind, 'race_burst')
    const burst = built.spec.burst as Array<{ method: string; pathAndQuery: string; jsonBody?: Record<string, unknown> }>
    assert.equal(burst.length, 5)
    assert.equal(burst[0].method, 'POST')
    assert.equal(burst[0].pathAndQuery, '/api/coupon/redeem')
    assert.equal(burst[0].jsonBody?.code, 'SAVE50')
    const control = built.spec.controlStep as { request: { pathAndQuery: string } }
    const post = built.spec.postCheckStep as { request: { pathAndQuery: string } }
    assert.equal(control.request.pathAndQuery, '/api/wallet')
    assert.equal(post.request.pathAndQuery, '/api/wallet')
    assert.match(String(built.spec.assertionsJq), /\.burst\.summary\.statuses/)
  })

  test('the burst assertion requires multiple 2xx responses and a changed state', () => {
    const built = expectSpec(raceOutcome(), 'race_burst')
    const payload = (statuses: number[], before: string, after: string) => ({
      burst: { summary: { statuses, total: statuses.length } },
      steps: {
        c1: { status: 200, body: before },
        c2: { status: 200, body: after },
      },
    })
    const hit = jq(String(built.spec.assertionsJq), payload([200, 200, 409, 409, 409], '{"balance":100}', '{"balance":0}'))
    assert.equal(hit.confirmed, true)
    const noStateChange = jq(String(built.spec.assertionsJq), payload([200, 200, 409, 409, 409], '{"balance":100}', '{"balance":100}'))
    assert.equal(noStateChange.confirmed, false)
    const singleSuccess = jq(String(built.spec.assertionsJq), payload([200, 409, 409, 409, 409], '{"balance":100}', '{"balance":50}'))
    assert.equal(singleSuccess.confirmed, false)
  })

  test('weak or incomplete race evidence refuses to synthesize', () => {
    assert.equal(synthesizeSpec(raceOutcome({ readPath: undefined }), env()), null)
    assert.equal(synthesizeSpec(raceOutcome({ successes: 1 }), env()), null)
    assert.equal(synthesizeSpec(raceOutcome({ attempts: 1 }), env()), null)
    assert.equal(synthesizeSpec(raceOutcome({ allowed: 3, successes: 3 }), env()), null)
    assert.equal(synthesizeSpec(outcome({ hyp: raceHyp(), anomalies: [{ type: 'db_error_fingerprint', dialect: 'sqlite' }] }), env()), null)
  })
})

describe('M7.2 command-injection rce_proof synthesis', () => {
  const cmdHyp = () => hypothesis({
    endpoint: endpoint({ path: '/api/diagnostics/ping', params: [{ name: 'host', location: 'query', isObjectId: false, isCsrf: false }] }),
    probeClass: 'ssti_math',
    location: 'query',
  })

  function cmdOutcome(anomaly: Record<string, unknown>): HypothesisOutcome {
    return outcome({ hyp: cmdHyp(), anomalies: [{ type: 'command_injection_differential', ...anomaly }] })
  }

  test('split-echo evidence produces nonce halves joined only by shell concatenation', () => {
    const built = expectSpec(cmdOutcome({ proofMode: 'split_echo', outputReflected: true }), 'rce_proof')
    assert.equal(built.spec.proofMode, 'split_echo')
    const serialized = JSON.stringify(built.spec.probeStep)
    assert.ok(serialized.includes('{{nonce_part1}}'))
    assert.ok(serialized.includes('{{nonce_part2}}'))
    assert.ok(!serialized.includes('{{nonce_part1}}{{nonce_part2}}'))
  })

  test('dynamic-math evidence uses the verifier nonces with a sub-shell wrapper', () => {
    const built = expectSpec(cmdOutcome({ proofMode: 'dynamic_math', wrapper: 'subshell', outputReflected: true }), 'rce_proof')
    assert.equal(built.spec.proofMode, 'dynamic_math')
    const serialized = JSON.stringify(built.spec.probeStep)
    assert.ok(serialized.includes('{{nonce_a}}'))
    assert.ok(serialized.includes('{{nonce_b}}'))
    assert.ok(serialized.includes('$('))
  })

  test('out-of-band evidence keeps the canary placeholder', () => {
    const built = expectSpec(cmdOutcome({ canaryTriggered: true }), 'rce_proof')
    assert.equal(built.spec.proofMode, 'oob_canary')
    assert.match(JSON.stringify(built.spec.probeStep), /\{\{canary_(?:url|dns_host)\}\}/)
  })

  test('observed URL encoding is applied to literal shell syntax only', () => {
    const built = expectSpec(cmdOutcome({ proofMode: 'dynamic_math', wrapper: 'semicolon', encoding: 'url', outputReflected: true }), 'rce_proof')
    const path = String((built.spec.probeStep as { request: { pathAndQuery: string } }).request.pathAndQuery)
    assert.match(path, /%3B/)
    assert.match(path, /\{\{nonce_a\}\}/)
    assert.ok(!path.includes('%7B%7B'))
  })

  test('command evidence without an execution oracle refuses to synthesize', () => {
    assert.equal(synthesizeSpec(cmdOutcome({ wrapper: 'semicolon' }), env()), null)
    assert.equal(synthesizeSpec(outcome({
      hyp: cmdHyp(),
      anomalies: [{ type: 'command_injection_differential', proofMode: 'made_up', wrapper: 'semicolon' }],
    }), env()), null)
  })
})

describe('M7.2 workflow step-skip synthesis', () => {
  test('step-skip state evidence becomes a transition http_chain with a state assertion', () => {
    const built = expectSpec(outcome({
      hyp: hypothesis({
        endpoint: endpoint({ method: 'POST', path: '/api/orders/{id}/refund', params: [{ name: 'id', location: 'path', isObjectId: true, isCsrf: false }] }),
        probeClass: 'workflow_invariant', param: undefined, location: undefined, method: 'POST',
      }),
      anomalies: [{ type: 'workflow_step_skip', fromState: 'draft', toState: 'refunded', path: '/api/orders/555/refund', status: 200 }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { method: string; pathAndQuery: string; jsonBody?: unknown } }>
    assert.equal(steps.length, 2)
    assert.equal(steps[1].request.method, 'POST')
    assert.equal(steps[1].request.pathAndQuery, '/api/orders/555/refund')
    assert.match(String(built.spec.assertionsJq), /refunded/)
    const hit = jq(String(built.spec.assertionsJq), { steps: { c1: { status: 200 }, p1: { status: 200, json: { state: 'REFUNDED' } } } })
    assert.equal(hit.confirmed, true)
    const wrong = jq(String(built.spec.assertionsJq), { steps: { c1: { status: 200 }, p1: { status: 200, json: { state: 'draft' } } } })
    assert.equal(wrong.confirmed, false)
  })

  test('step-skip evidence without a target state refuses to synthesize', () => {
    const base = {
      hyp: hypothesis({ probeClass: 'workflow_invariant', param: undefined, location: undefined, method: 'POST' }),
      details: {},
    }
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'workflow_step_skip', fromState: 'draft', path: '/x', status: 200 }] }), env()), null)
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'workflow_step_skip', fromState: 'draft', toState: 'draft', path: '/x', status: 200 }] }), env()), null)
    assert.equal(synthesizeSpec(outcome({ ...base, anomalies: [{ type: 'workflow_step_skip', fromState: 'draft', toState: 'refunded', path: '/x', status: 500 }] }), env()), null)
  })
})

describe('M7.2 GraphQL nested BOLA and alias batching', () => {
  const gqlHyp = () => hypothesis({
    endpoint: endpoint({ method: 'POST', path: '/graphql', params: [] }),
    probeClass: 'graphql_audit', param: undefined, location: undefined, method: 'POST',
  })

  test('nested resolver evidence asserts the non-owner receives the owner data', () => {
    const built = expectSpec(outcome({
      hyp: gqlHyp(),
      anomalies: [{ type: 'graphql_nested_bola', field: 'user', nestedPath: ['invoices', 'memo'] }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ request: { jsonBody?: { query?: string } } }>
    assert.match(String(steps[1].request.jsonBody?.query), /user\{invoices\{memo\}\}/)
    assert.match(String(built.spec.assertionsJq), /data == \.steps\.c1\.json\.data/)
    const same = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, json: { data: { user: { invoices: [{ memo: 'x' }] } } } },
        p1: { status: 200, json: { data: { user: { invoices: [{ memo: 'x' }] } } } },
      },
    })
    assert.equal(same.confirmed, true)
    const different = jq(String(built.spec.assertionsJq), {
      steps: {
        c1: { status: 200, json: { data: { user: { invoices: [{ memo: 'x' }] } } } },
        p1: { status: 200, json: { data: { user: { invoices: [{ memo: 'y' }] } } } },
      },
    })
    assert.equal(different.confirmed, false)
  })

  test('alias batching combined with cross-persona evidence yields a second alias-chain candidate', () => {
    const specs = synthesizeSpecs(outcome({
      hyp: gqlHyp(),
      anomalies: [
        { type: 'graphql_nested_bola', field: 'user', nestedPath: ['invoices', 'memo'] },
        { type: 'alias_batching_allowed', aliases: 3 },
      ],
    }), env())
    assert.equal(specs.length, 2)
    assert.match(String((specs[1].spec.assertionsJq)), /alias keys/)
    const steps = specs[1].spec.steps as Array<{ request: { jsonBody?: { query?: string } } }>
    assert.match(String(steps[1].request.jsonBody?.query), /a0:user/)
    assert.match(String(steps[1].request.jsonBody?.query), /a2:user/)
    const hit = jq(String(specs[1].spec.assertionsJq), {
      steps: {
        c1: { status: 200, json: { data: { user: { invoices: [{ memo: 'x' }] } } } },
        p1: { status: 200, json: { data: { a0: { invoices: [{ memo: 'x' }] }, a1: { invoices: [{ memo: 'x' }] }, a2: { invoices: [{ memo: 'x' }] } } } },
      },
    })
    assert.equal(hit.confirmed, true)
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
      hyp: hypothesis({ probeClass: 'ssti_math' }),
      anomalies: [{ type: 'command_injection_differential', proofMode: 'split_echo', outputReflected: true }],
    })
    assert.deepEqual(synthesizeSpecs(o, env()), [])
  })
})
