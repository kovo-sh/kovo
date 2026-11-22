/**
 * M7 recall hill-climbing: replay-spec synthesis coverage.
 *
 * Each fixture mirrors an anomaly observed by the real surface-engine probes. The tests assert
 * that synthesis turns every exploitable anomaly class into a schema-valid spec (and refuses
 * to synthesize from evidence that is too weak), without consulting any benchmark manifest.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

// scopedAssetOrigin accepts loopback http origins only under the local-lab gate.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { synthesizeSpec } from '../scripts/benchmark-specs.ts'
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
  return { built, parsed: parsed.success ? parsed.data : null }
}

describe('M7 spec synthesis: SQL injection classes', () => {
  test('boolean differential replays the observed style as sql_boolean_diff', () => {
    const { built } = expectSpec(outcome({
      anomalies: [{ type: 'boolean_differential', style: 'or_branch' }],
    }), 'sql_boolean_diff')
    assert.equal(built.spec.kind, 'sql_boolean_diff')
    assert.equal(built.spec.paramName, 'q')
    assert.match(String(built.spec.valueTemplate), /\{\{sql_expr\}\}/)
  })

  test('db_error_fingerprint synthesizes a data-independent boolean differential', () => {
    const ep = endpoint({
      method: 'POST',
      path: '/search/form',
      params: [{ name: 'q', location: 'form', isObjectId: false, isCsrf: false }],
    })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'sqli_boolean', location: 'form', method: 'POST' }),
      anomalies: [{ type: 'db_error_fingerprint', dialect: 'sqlite' }],
    }), 'sql_boolean_diff')
    assert.equal(built.spec.paramLocation, 'form')
    assert.match(String(built.spec.baselineValue), /OR 1=1/)
    assert.match(String(built.spec.valueTemplate), /\{\{sql_expr\}\}/)
  })

  test('db_error_fingerprint on a header parameter keeps the observed location', () => {
    const ep = endpoint({
      params: [{ name: 'X-Tracking-Id', location: 'header', isObjectId: false, isCsrf: false }],
    })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, location: 'header' }),
      anomalies: [{ type: 'db_error_fingerprint', dialect: 'sqlite' }],
    }), 'sql_boolean_diff')
    assert.equal(built.spec.paramLocation, 'header')
    assert.equal(built.spec.paramName, 'X-Tracking-Id')
  })

  test('sql_time_differential maps to the typed sql_time_diff schema', () => {
    const ep = endpoint({ params: [{ name: 'ref', location: 'query', isObjectId: false, isCsrf: false }] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'sqli_time_diff', location: 'query' }),
      anomalies: [{ type: 'sql_time_differential', dialect: 'mysql', style: 'single_quote', delayMs: 1500, probeMedianMs: 1503 }],
    }), 'sql_time_diff')
    assert.equal(built.spec.dialect, 'mysql')
    assert.equal(built.spec.delayMs, 1500)
    assert.equal(built.spec.paramName, 'ref')
  })

  test('unknown SQL dialect or missing param refuses to synthesize', () => {
    const time = outcome({
      hyp: hypothesis({ probeClass: 'sqli_time_diff', location: 'query' }),
      anomalies: [{ type: 'sql_time_differential', dialect: 'oracle', style: 'single_quote' }],
    })
    assert.equal(synthesizeSpec(time, env()), null)
    const noParam = outcome({ hyp: hypothesis({ param: undefined, location: undefined }), anomalies: [{ type: 'db_error_fingerprint' }] })
    assert.equal(synthesizeSpec(noParam, env()), null)
  })
})

describe('M7 spec synthesis: authz, GraphQL, SSRF, JWT', () => {
  test('unauthorized_access still builds the cross-actor http_chain', () => {
    const ep = endpoint({ path: '/api/orders/{id}', params: [{ name: 'id', location: 'path', isObjectId: true, isCsrf: false }] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'authz_matrix', param: undefined, location: undefined }),
      anomalies: [{ type: 'unauthorized_access', resourceId: '1002', actor: 'other_persona', method: 'GET', status: 200 }],
    }), 'http_chain')
    assert.equal((built.spec.steps as unknown[]).length, 2)
  })

  test('graphql introspection becomes a schema-exposure http_chain', () => {
    const ep = endpoint({ method: 'POST', path: '/graphql', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'graphql_audit', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{ type: 'introspection_enabled' }, { type: 'alias_batching_allowed', aliases: 4 }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ request: { jsonBody?: { query?: string } } }>
    assert.match(String(steps[1].request.jsonBody?.query), /__schema/)
  })

  test('SSRF canary builds a control/probe http_chain with the verified canary placeholder', () => {
    const ep = endpoint({ path: '/api/fetch', params: [{ name: 'url', location: 'query', isObjectId: false, isCsrf: false }] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'ssrf_canary', location: 'query' }),
      anomalies: [{ type: 'canary_callback', param: 'url', variant: 'http', protocol: 'http' }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ request: { pathAndQuery: string } }>
    assert.match(steps[0].request.pathAndQuery, /url=http/)
    assert.match(steps[1].request.pathAndQuery, /url=\{\{canary_url\}\}/)
  })

  test('JWT mutation bypass builds auth_protocol_proof with a schema-valid authMutation', () => {
    const ep = endpoint({ path: '/api/jwt/profile', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'auth_protocol_audit', param: undefined, location: undefined }),
      anomalies: [{ type: 'jwt_auth_mutation_bypass', mutation: 'alg_none', status: 200 }],
    }), 'auth_protocol_proof')
    const steps = built.spec.steps as Array<{ request: { authMutation?: { kind: string } } }>
    assert.equal(steps.at(-1)?.request.authMutation?.kind, 'alg_none')
  })

  test('jku canary bypass omits the URL so the verifier mints a fresh canary', () => {
    const ep = endpoint({ path: '/api/jwt/jku-profile', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'auth_protocol_audit', param: undefined, location: undefined }),
      anomalies: [{ type: 'jwt_jku_x5u_oob_canary', mutation: 'jku_x5u_canary', canaryTriggered: true }],
    }), 'auth_protocol_proof')
    const steps = built.spec.steps as Array<{ request: { authMutation?: { kind: string; url?: string } } }>
    assert.equal(steps.at(-1)?.request.authMutation?.kind, 'jku_x5u_canary')
    assert.equal(steps.at(-1)?.request.authMutation?.url, undefined)
  })

  test('unknown JWT mutation or missing persona refuses to synthesize', () => {
    const ep = endpoint({ path: '/api/jwt/profile', params: [] })
    const unknown = outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'auth_protocol_audit', param: undefined, location: undefined }),
      anomalies: [{ type: 'jwt_auth_mutation_bypass', mutation: 'made_up', status: 200 }],
    })
    assert.equal(synthesizeSpec(unknown, env()), null)
    assert.equal(synthesizeSpec({ ...unknown, anomalies: [{ type: 'jwt_auth_mutation_bypass', mutation: 'alg_none' }] }, env({ jwtPersona: undefined, owner: undefined })), null)
  })
})

describe('M7 spec synthesis: state-changing classes', () => {
  test('mass assignment proves a low->high field transition after write + re-read', () => {
    const ep = endpoint({ method: 'PATCH', path: '/api/profile', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'mass_assignment', param: undefined, location: undefined, method: 'PATCH' }),
      anomalies: [{ type: 'mass_assignment', field: 'role', writeStatus: 200, persisted: true }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ id: string; request: { method: string; jsonBody?: Record<string, unknown> } }>
    assert.equal(steps[0].request.jsonBody?.role, 'user')
    assert.equal(steps[2].request.jsonBody?.role, 'admin')
    assert.match(String(built.spec.assertionsJq), /role/)
  })

  test('mass assignment with an unsafe field name refuses to synthesize', () => {
    const ep = endpoint({ method: 'PATCH', path: '/api/profile', params: [] })
    for (const field of ['role;drop', 'a"b', '']) {
      const o = outcome({
        hyp: hypothesis({ endpoint: ep, probeClass: 'mass_assignment', param: undefined, location: undefined, method: 'PATCH' }),
        anomalies: [{ type: 'mass_assignment', field, persisted: true }],
      })
      assert.equal(synthesizeSpec(o, env()), null, field)
    }
  })

  test('cache poisoning becomes a cache_differential with distinct cache busters', () => {
    const ep = endpoint({ path: '/cache/banner', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'cache_poison_deception', param: undefined, location: undefined }),
      anomalies: [{ type: 'cache_poisoning', header: 'X-Forwarded-Host', probeGcb: 'abc', cacheHit: true, markerPersisted: true }],
    }), 'cache_differential')
    assert.equal(built.spec.mode, 'poison')
    assert.match(String(built.spec.controlPath), /\{\{control_gcb\}\}/)
    assert.match(String(built.spec.probePath), /\{\{probe_gcb\}\}/)
  })

  test('workflow quantity invariant builds a control/probe http_chain', () => {
    const ep = endpoint({ method: 'POST', path: '/api/checkout/orders', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'workflow_invariant', param: undefined, location: undefined, method: 'POST' }),
      anomalies: [{ type: 'workflow_quantity_invariant', field: 'qty', value: -1, status: 200 }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ request: { jsonBody?: Record<string, unknown> } }>
    assert.equal(steps[0].request.jsonBody?.qty, 1)
    assert.equal(steps[1].request.jsonBody?.qty, -1)
  })

  test('path normalization differential alone is not synthesized', () => {
    const ep = endpoint({ path: '/api/files/download', params: [{ name: 'name', location: 'query', isObjectId: false, isCsrf: false }] })
    const o = outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'path_traversal_benign', param: undefined, location: undefined }),
      anomalies: [{ type: 'path_normalization_differential', variant: 'encoded_slash', status: 200 }],
    })
    assert.equal(synthesizeSpec(o, env()), null)
  })

  test('a non-signal verdict never synthesizes, even with anomaly-shaped details', () => {
    const o = outcome({
      verdict: 'no_signal',
      anomalies: [{ type: 'db_error_fingerprint', dialect: 'sqlite' }],
    })
    assert.equal(synthesizeSpec(o, env()), null)
  })
})

describe('M7 spec synthesis: browser/web anomaly classes', () => {
  test('second_order_xss plants a marker and asserts it unencoded on the read route', () => {
    const ep = endpoint({
      method: 'POST',
      path: '/api/comments',
      params: [{ name: 'body', location: 'json', isObjectId: false, isCsrf: false }],
    })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'xss_context', location: 'json', method: 'POST' }),
      anomalies: [{
        type: 'second_order_xss', plantPath: '/api/comments', plantParam: 'body', plantLocation: 'json',
        readPath: '/comments', context: 'html_body', unencodedChars: ['"', "'", '<', '>'], mediaType: 'text/html',
      }],
    }), 'http_chain')
    const steps = built.spec.steps as Array<{ role: string; request: { method: string; pathAndQuery: string; jsonBody?: Record<string, unknown> } }>
    assert.equal(steps.length, 3)
    assert.equal(steps[1].request.method, 'POST')
    assert.match(String(steps[1].request.jsonBody?.body), /^gxss[0-9a-f]+/)
    assert.match(String(built.spec.assertionsJq), /contains\("gxss/)
    assert.equal(steps[2].request.pathAndQuery, '/comments')
  })

  test('dom_xss_sink becomes a control/probe browser_chain with fill and click actions', () => {
    const ep = endpoint({ path: '/wizard', params: [{ name: 'display-name', location: 'query', isObjectId: false, isCsrf: false }] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'xss_context', location: 'query' }),
      anomalies: [{
        type: 'dom_xss_sink', path: '/wizard', sink: 'innerHTML',
        actions: ['fill #display-name', 'click #continue', 'click #preview'], canaryTriggered: true,
      }],
    }), 'browser_chain')
    const steps = built.spec.steps as Array<{ id: string; role: string; action?: string; selector?: string }>
    assert.equal(steps[0].role, 'control')
    assert.ok(steps.some(s => s.action === 'fill' && s.selector === '#display-name'))
    assert.ok(steps.some(s => s.action === 'click' && s.selector === '#continue'))
    assert.ok(steps.at(-1)?.action === 'dom_xss_sink_hook')
    assert.match(String(built.spec.assertionsJq), /containsCanary/)
  })

  test('reflected xss_context with unencoded markup becomes an executable browser_chain', () => {
    const ep = endpoint({ path: '/search', params: [{ name: 'q', location: 'query', isObjectId: false, isCsrf: false }] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'xss_context', location: 'query' }),
      anomalies: [{ type: 'xss_context', context: 'html_body', unencodedChars: ['"', "'", '<', '>'] }],
    }), 'browser_chain')
    const steps = built.spec.steps as Array<{ request?: unknown; pathAndQuery: string }>
    assert.match(String(steps[1].pathAndQuery), /%3Cimg/)
    assert.match(String(steps[1].pathAndQuery), /canary_token/)
    assert.match(String(built.spec.assertionsJq), /canaryToken/)
  })

  test('oauth redirect differential without a corpus seed is rebuilt from the observed Location', () => {
    const ep = endpoint({ path: '/oauth/authorize', params: [] })
    const { built } = expectSpec(outcome({
      hyp: hypothesis({ endpoint: ep, probeClass: 'auth_protocol_audit', param: undefined, location: undefined }),
      anomalies: [{
        type: 'oauth_redirect_differential', variant: 'userinfo_at', status: 302,
        location: 'https://app.client.test@evil.invalid/cb?code=abc',
      }],
    }), 'auth_protocol_proof')
    const steps = built.spec.steps as Array<{ role: string; request: { pathAndQuery: string } }>
    assert.equal(built.spec.protocol, 'oauth')
    assert.match(String(steps[0].request.pathAndQuery), /unrelated-control/)
    assert.match(String(steps[1].request.pathAndQuery), /app\.client\.test%40evil\.invalid/)
  })
})
