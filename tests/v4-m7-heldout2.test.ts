/**
 * M7 held-out climb (second stream): route-map discovery, spec encoding, and attribution.
 *
 * Covers the generic additions:
 *  - SPA config/route-map expansion and JS router-table harvesting (endpoints + params)
 *  - case-preserving request path normalization (Next.js server actions)
 *  - nested JSON request-field extraction (dotted parameter names)
 *  - traversal / command-injection / race spec synthesis and schema validity
 *  - ambiguous patch attribution is reported but never counted as fixed or regressed
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

import { normalizeEndpointTemplate } from '../src/server/dedupe.ts'
import { harvestJsRequestParams, harvestJsRouteTable, harvestRouteMapDocument } from '../src/server/phase0-recon.ts'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { synthesizeSpecs } from '../scripts/benchmark-specs.ts'
import { siblingValue } from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint, Hypothesis, HypothesisOutcome, ProbeEnv, ProfileCaps } from '../scripts/benchmark-probes.ts'
import { verifyPatchesLive } from '../scripts/benchmark-live.ts'
import type { ConfirmedFinding, PatchReplayResult, PatchVerificationHooks } from '../scripts/benchmark-live.ts'
import type { BenchmarkManifest, PatchVerificationSummary } from '../scripts/benchmark-core.ts'
import { withEnv } from './v4-tier-helpers.ts'

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
    personaUserIds: ['user-1001', 'user-1002'],
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
    probeClass: 'path_traversal_benign',
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

function firstSpec(o: HypothesisOutcome, e = env()) {
  const specs = synthesizeSpecs(o, e)
  assert.ok(specs.length > 0, 'expected at least one synthesized spec')
  assert.equal(declarativeReplaySpecSchema.safeParse(specs[0].spec).success, true)
  return specs[0]
}

describe('M7 held-out2: route-map discovery', () => {
  test('expands path-keyed method tables, operation arrays and route lists', () => {
    const doc = {
      api: {
        '/v1/orders': { get: { parameters: [{ name: 'status', in: 'query' }] }, post: { body: { sku: 'string' } } },
        '/v1/orders/{id}': { get: { parameters: [{ name: 'id', in: 'path' }] } },
      },
      routes: ['/dashboard', '/settings/profile'],
      endpoints: [
        { path: '/v1/reports/{id}/export', method: 'POST', params: ['format'] },
        { route: '/v1/whoami', verb: 'GET' },
      ],
    }
    const entries = harvestRouteMapDocument(doc)
    const keys = entries.map(e => `${e.method} ${e.path}`)
    assert.ok(keys.includes('GET /v1/orders'))
    assert.ok(keys.includes('POST /v1/orders'))
    assert.ok(keys.includes('GET /v1/orders/{id}'))
    assert.ok(keys.includes('GET /dashboard'))
    assert.ok(keys.includes('GET /settings/profile'))
    assert.ok(keys.includes('POST /v1/reports/{id}/export'))
    assert.ok(keys.includes('GET /v1/whoami'))

    const ordersGet = entries.find(e => e.method === 'GET' && e.path === '/v1/orders')
    assert.deepEqual(ordersGet?.params, [{ name: 'status', location: 'query' }])
    const ordersPost = entries.find(e => e.method === 'POST' && e.path === '/v1/orders')
    assert.deepEqual(ordersPost?.params, [{ name: 'sku', location: 'json' }])
    const detail = entries.find(e => e.path === '/v1/orders/{id}')
    assert.deepEqual(detail?.params, [{ name: 'id', location: 'path' }])
  })

  test('ignores non-route JSON and bounds output', () => {
    assert.deepEqual(harvestRouteMapDocument({ keys: [{ kty: 'RSA', kid: 'x' }], issuer: 'https://x' }), [])
    const big = { routes: Array.from({ length: 500 }, (_, i) => `/r/${i}`) }
    assert.ok(harvestRouteMapDocument(big, 50).length <= 50)
  })

  test('harvests client router tables and navigation literals from bundles', () => {
    const js = `
      const routes = {
        '/dashboard': { component: Dashboard },
        "/settings/:id": { component: Settings },
      }
      const next = [{ path: '/reports/:id', component: Report }]
      router.push('/admin/users')
      navigate("/onboarding")
      const notRoute = '/static/logo.svg'
    `
    const paths = harvestJsRouteTable(js)
    for (const p of ['/dashboard', '/settings/:id', '/reports/:id', '/admin/users', '/onboarding']) {
      assert.ok(paths.includes(p), `expected ${p} in ${paths.join(',')}`)
    }
  })

  test('extracts nested dotted JSON body parameters', () => {
    const specs = harvestJsRequestParams(`
      export function track(name) {
        return fetch('/api/analytics/query', { method: 'POST', body: JSON.stringify({ filter: { name }, page: 1 }) })
      }
    `)
    assert.equal(specs.length, 1)
    const names = specs[0].params.map(p => p.name)
    assert.ok(names.includes('filter.name'))
    assert.ok(names.includes('page'))
    assert.ok(!names.includes('name'), 'bare nested leaf should not be probed at top level')
  })

  test('preserves case for request paths but lowercases fingerprints', () => {
    assert.equal(normalizeEndpointTemplate('/_actions/updateOrgPlan', { preserveCase: true }), '/_actions/updateOrgPlan')
    assert.equal(normalizeEndpointTemplate('/_actions/updateOrgPlan'), '/_actions/updateorgplan')
  })
})

describe('M7 held-out2: value synthesis and spec encoding', () => {
  test('sibling values are format-aware and prefer observed identifiers', () => {
    const corpusEnv = env({ corpus: { all: 'href="/app/projects/p_acme_1/activity"', json: [{ role: 'member' }] } })
    assert.equal(siblingValue('projectId', corpusEnv), 'p_acme_1')
    assert.equal(siblingValue('email', corpusEnv), 'kovo@example.test')
    assert.equal(siblingValue('qty', corpusEnv), 1)
    assert.equal(siblingValue('marketingOptIn', corpusEnv), true)
    assert.equal(siblingValue('role', corpusEnv), 'member')
  })

  test('traversal synthesis follows the observed payload encoding', () => {
    const o = outcome({
      hyp: hypothesis({ probeClass: 'path_traversal_benign', param: { name: 'name', location: 'query', isObjectId: false, isCsrf: false } }),
      anomalies: [{ type: 'path_traversal_escape', param: 'name', location: 'query', payload: '..%2fprivate%2fsecret.txt', oracle: 'content_differential', contentNeedle: 'confidential' }],
    })
    const spec = firstSpec(o)
    assert.equal(spec.kind, 'http_chain')
    const steps = (spec.spec as { steps: Array<{ request: { pathAndQuery: string } }> }).steps
    assert.equal(steps.length, 2)
    assert.notEqual(steps[0].request.pathAndQuery, steps[1].request.pathAndQuery)
  })

  test('command injection proof uses split echo nonces that never appear assembled', () => {
    const o = outcome({
      hyp: hypothesis({ probeClass: 'command_injection', param: { name: 'host', location: 'query', isObjectId: false, isCsrf: false } }),
      anomalies: [{ type: 'command_executed', variant: 'semicolon_echo', baseValue: '127.0.0.1', nonce: 'gnnonce123' }],
    })
    const spec = firstSpec(o)
    assert.equal(spec.kind, 'rce_proof')
    assert.equal((spec.spec as { proofMode?: string }).proofMode, 'split_echo')
    const serialized = JSON.stringify((spec.spec as { probeStep: unknown }).probeStep)
    assert.ok(serialized.includes('{{nonce_part1}}'))
    assert.ok(serialized.includes('{{nonce_part2}}'))
    assert.ok(!serialized.includes('{{nonce_part1}}{{nonce_part2}}'))
  })

  test('race synthesis emits a synchronized burst with a producer control', () => {
    const o = outcome({
      hyp: hypothesis({
        probeClass: 'race_burst', method: 'POST',
        endpoint: endpoint({ method: 'POST', path: '/api/credits/redeem', params: [{ name: 'code', location: 'json', isObjectId: false, isCsrf: false }] }),
        param: { name: 'code', location: 'json', isObjectId: false, isCsrf: false },
      }),
      anomalies: [{
        type: 'race_double_spend', path: '/api/credits/redeem', producerPath: '/api/credits/vouchers',
        param: 'code', consumeBody: { code: '{{code}}' }, successes: 3, parentPath: '/api/credits',
      }],
    })
    const spec = firstSpec(o)
    assert.equal(spec.kind, 'race_burst')
    const burst = (spec.spec as { burst: unknown[] }).burst
    assert.equal(burst.length, 4)
    const control = (spec.spec as { controlStep?: { extract?: Array<{ varName: string }> } }).controlStep
    assert.equal(control?.extract?.[0]?.varName, 'code')
  })
})

describe('M7 held-out2: ambiguous patch attribution', () => {
  const manifest: BenchmarkManifest = {
    challenges: [
      { id: 'hos-02', vulnClass: 'graphql_bola', endpoint: '/graphql', method: 'POST', param: 'q', patchId: 'hos-02' },
      { id: 'hos-09', vulnClass: 'graphql_sqli', endpoint: '/graphql', method: 'POST', param: 'q', patchId: 'hos-09' },
      { id: 'hos-01', vulnClass: 'bola', endpoint: '/api/invoices/{id}', method: 'GET', param: 'id', patchId: 'hos-01' },
    ] as BenchmarkManifest['challenges'],
  }
  const sharedSpec = { kind: 'http_chain', origin: 'http://127.0.0.1:1', steps: [] }
  const findings: ConfirmedFinding[] = [
    { id: 'hos-01', isDecoy: false, path: '/api/invoices/{id}', probeClass: 'authz_matrix', spec: { ...sharedSpec, title: 'invoice' } },
    { id: 'hos-02', isDecoy: false, path: '/graphql', probeClass: 'sqli_boolean', spec: { ...sharedSpec, title: 'shared' } },
    { id: 'hos-09', isDecoy: false, path: '/graphql', probeClass: 'sqli_boolean', spec: { ...sharedSpec, title: 'shared' }, ambiguousAttribution: true },
  ]
  const hooks: PatchVerificationHooks = {
    runFull: async patchedIds => ({ findings: patchedIds.length === 0 ? findings : [], notes: [] }),
    replayAll: async ({ findings: batch }) => {
      const out = new Map<string, PatchReplayResult>()
      for (const f of batch) out.set(f.id, { verdict: 'dismissed', verdicts: ['dismissed'] })
      return out
    },
  }

  test('ambiguous findings are excluded from patch fixed/regressed evidence', async () => {
    const summary: PatchVerificationSummary = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest, hooks, patchTimeoutMs: 2_000, baseline: { findings },
    }))
    const ambiguous = summary.perPatch.find(p => p.id === 'hos-09')
    assert.equal(ambiguous?.before, 'confirmed_ambiguous')
    assert.equal(ambiguous?.fixed, false)
    assert.equal(ambiguous?.reproducedBefore, false)
    const concrete = summary.perPatch.find(p => p.id === 'hos-01')
    assert.equal(concrete?.fixed, true)
    assert.deepEqual(summary.allPatches?.ambiguous, ['hos-09'])
    assert.deepEqual(summary.allPatches?.newlyConfirming, [])
    assert.equal(summary.allPatches?.verdict, 'fixed')
  })
})
