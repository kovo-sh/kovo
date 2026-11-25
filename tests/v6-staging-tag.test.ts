/**
 * v6 staging_isolated tagging contract.
 *
 * Defensive QA framing: the scope policy already refuses untagged staging mutations. These tests
 * pin that probe generation (not the policy) carries the run tag, that an untaggable mutation is
 * skipped locally instead of being refused by the broker, and that the fixture's run-scoped cleanup
 * hook removes tagged entities while leaving pre-existing owner rows untouched.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  buildProbeRequest,
  cleanupStagedEntities,
  probeHypothesisMutates,
  runDeterministicEngine,
  stagingCleanupTarget,
  stagingProbeTag,
  tagStagingEntityBody,
  tagStagingEntityForm,
} from '../src/server/deterministic-engine.ts'
import type { EngineHypothesis } from '../src/server/deterministic-engine.ts'
import { evaluateScopeRequest, tenantTagForRun } from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'

const origin = 'https://staging.example.com'
const runId = 'run-stag-1'
const tenantTag = tenantTagForRun(runId)
const publicAddress = { address: '93.184.216.34', family: 4 as const }

function stagingPolicy(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'staging_isolated',
    targetOrigins: [origin],
    routeDenylist: [],
    tenantTag,
    runId,
    ...overrides,
  }
}

function endpoint(method: string, pathTemplate: string) {
  return { id: `${method}:${pathTemplate}`, origin, method, pathTemplate, params: [], riskScore: 80, source: 'openapi' as const }
}

function postHypothesis(pathAndQuery: string, jsonBody: Record<string, unknown>): EngineHypothesis {
  return {
    key: `mass_assignment|${pathAndQuery}`,
    endpoint: endpoint('POST', pathAndQuery),
    probeClass: 'mass_assignment',
    intent: 'mass_assignment',
    method: 'POST',
    pathAndQuery,
    jsonBody,
    risk: 80,
  }
}

test('v6 staging-tag: mutating probe carries the run tag on values and headers, and is authorized', () => {
  const hyp = postHypothesis('/v1/checkout/start', { name: 'cart', title: 'probe', total: 249 })
  assert.equal(probeHypothesisMutates(hyp), true)

  const staging = stagingProbeTag({
    environmentMode: 'staging_isolated',
    entityTag: tenantTag,
    runId,
    method: hyp.method,
    probeClass: hyp.probeClass,
    pathAndQuery: hyp.pathAndQuery,
    mutates: probeHypothesisMutates(hyp),
    jsonBody: hyp.jsonBody,
  })
  assert.equal(staging.action, 'tag')
  assert.equal(staging.headers?.['x-kovo-run-id'], runId)
  assert.equal(staging.headers?.['x-kovo-tenant-tag'], tenantTag)
  assert.equal(staging.jsonBody?.name, `${tenantTag}cart`)
  assert.equal(staging.jsonBody?.title, `${tenantTag}probe`)
  assert.equal(staging.jsonBody?.total, 249, 'numeric prices are never rewritten')

  // The tagged request passes the unchanged scope policy; the same body without the tag is refused.
  const request = buildProbeRequest(hyp, 20, { runId, assignmentId: 'asg-1' }, staging)
  const allowed = evaluateScopeRequest(stagingPolicy(), {
    origin,
    method: 'POST',
    pathAndQuery: request.pathAndQuery,
    body: JSON.stringify(request.jsonBody),
    headers: request.headers,
  })
  assert.equal(allowed.allowed, true, allowed.reason)
  assert.equal(allowed.code, 'allowed')

  const untagged = evaluateScopeRequest(stagingPolicy(), {
    origin,
    method: 'POST',
    pathAndQuery: request.pathAndQuery,
    body: JSON.stringify(hyp.jsonBody),
  })
  assert.equal(untagged.allowed, false)
  assert.equal(untagged.code, 'staging_untagged_mutation', 'safety is unchanged: untagged writes stay refused')
})

test('v6 staging-tag: read-only probes and non-staging modes are never tagged', () => {
  const getHyp: EngineHypothesis = {
    key: 'authz|invoices',
    endpoint: endpoint('GET', '/v1/invoices/:id'),
    probeClass: 'authz_matrix',
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/v1/invoices/{{id}}',
    resourceIds: ['inv-alpha-1'],
    risk: 90,
  }
  assert.equal(probeHypothesisMutates(getHyp), false)
  const readOnly = stagingProbeTag({
    environmentMode: 'staging_isolated',
    entityTag: tenantTag,
    runId,
    method: getHyp.method,
    probeClass: getHyp.probeClass,
    pathAndQuery: getHyp.pathAndQuery,
    mutates: probeHypothesisMutates(getHyp),
  })
  assert.equal(readOnly.action, 'none')
  assert.equal(readOnly.reason, 'read_only')

  for (const mode of ['prod_readonly', 'ephemeral_lab'] as const) {
    const staging = stagingProbeTag({
      environmentMode: mode,
      entityTag: null,
      runId,
      method: 'POST',
      probeClass: 'mass_assignment',
      pathAndQuery: '/v1/checkout/start',
      jsonBody: { name: 'cart' },
    })
    assert.equal(staging.action, 'none')
    assert.equal(staging.reason, 'not_staging')
  }
})

test('v6 staging-tag: an untaggable identity mutation is skipped instead of reaching the policy', () => {
  for (const path of ['/login', '/api/session/token', '/accounts/password/reset']) {
    const staging = stagingProbeTag({
      environmentMode: 'staging_isolated',
      entityTag: tenantTag,
      runId,
      method: 'POST',
      probeClass: 'auth_protocol_audit',
      pathAndQuery: path,
      mutates: true,
    })
    assert.equal(staging.action, 'skip', `${path} must be skipped`)
    assert.equal(staging.reason, 'pre_existing_identity')
  }

  // Missing run tag is also untaggable in staging: skip, never send an untagged mutation.
  const missing = stagingProbeTag({
    environmentMode: 'staging_isolated',
    entityTag: null,
    runId: null,
    method: 'POST',
    probeClass: 'mass_assignment',
    pathAndQuery: '/v1/checkout/start',
    mutates: true,
  })
  assert.equal(missing.action, 'skip')
  assert.equal(missing.reason, 'missing_tag')

  // The engine's counter records the skip; the uploaded body is not silently sent untagged.
  const hyp = postHypothesis('/login', { email: 'alice@staging.example.invalid' })
  const request = buildProbeRequest(hyp, 10, { runId: '', assignmentId: 'asg-1' })
  assert.equal(request.headers, undefined, 'a skipped mutation builds no tag headers')
})

test('v6 prod_readonly still refuses staging writes and ephemeral remains open', () => {
  const readonly = evaluateScopeRequest(
    stagingPolicy({ mode: 'prod_readonly', tenantTag: null }),
    { origin, method: 'POST', pathAndQuery: '/v1/checkout/start', body: JSON.stringify({ name: `${tenantTag}cart` }), headers: { 'x-kovo-tenant-tag': tenantTag } },
  )
  assert.equal(readonly.allowed, false)
  assert.equal(readonly.code, 'readonly_environment')

  const ephemeral = evaluateScopeRequest(
    { mode: 'ephemeral_lab', targetOrigins: [origin], routeDenylist: [] },
    { origin, method: 'POST', pathAndQuery: '/v1/checkout/start', body: JSON.stringify({ name: 'cart' }) },
  )
  assert.equal(ephemeral.allowed, true)
  assert.equal(ephemeral.code, 'allowed')
})

test('v6 staging-tag: entity taggers touch only benign string fields', () => {
  const json = tagStagingEntityBody(
    { name: 'n', email: 'a@example.invalid', memo: 'm', slug: 's', total: 3, id: 'inv-alpha-1', password: 'p' },
    tenantTag,
  )
  assert.equal(json.name, `${tenantTag}n`)
  assert.equal(json.email, `${tenantTag}a@example.invalid`)
  assert.equal(json.memo, `${tenantTag}m`)
  assert.equal(json.slug, `${tenantTag}s`)
  assert.equal(json.total, 3)
  assert.equal(json.id, 'inv-alpha-1', 'pre-existing owner-row identifiers are never rewritten')
  assert.equal(json.password, 'p')

  const form = tagStagingEntityForm({ name: 'n', price: '100' }, tenantTag)
  assert.equal(form.name, `${tenantTag}n`)
  assert.equal(form.price, '100')
})

test('v6 staging-tag: engine counts tagged vs skipped mutations and never sends the skipped probe', async () => {
  const captured: Array<{ pathAndQuery: string; headers?: Record<string, string>; jsonBody?: Record<string, unknown> }> = []
  const report = await runDeterministicEngine({
    runId,
    assignmentId: 'asg-1',
    signal: new AbortController().signal,
    endpoints: [
      endpoint('POST', '/api/admin/orders'),
      endpoint('POST', '/api/admin/login'),
    ],
    personas: [],
    broker: {} as never,
    grant: { tier: 3, canRead: () => true, audit: () => {}, scopePolicy: stagingPolicy() } as Grant,
    backend: {} as never,
    tier: 3,
    maxRequests: 20,
    maxDurationMs: 10_000,
    environmentMode: 'staging_isolated',
    entityTag: tenantTag,
    probe: async req => {
      captured.push({ pathAndQuery: req.pathAndQuery, headers: req.headers, jsonBody: req.jsonBody })
      return {
        probeClass: req.probeClass,
        origin: req.origin,
        pathAndQuery: req.pathAndQuery,
        verdict: 'no_signal',
        summary: 'no signal',
        anomalies: [],
        details: {},
        requestsSent: 1,
        exchangeIds: [],
        stoppedReason: null,
        notes: [],
        durationMs: 1,
      } as never
    },
    onConfirmed: () => null,
  })
  assert.ok(report.stagingTaggedMutations >= 1, 'the create-shaped mutation is tagged')
  assert.equal(report.stagingUntaggedSkipped, 1, 'the login mutation is skipped locally')
  assert.equal(captured.some(req => /\/login$/.test(req.pathAndQuery)), false, 'skipped probe never reaches the probe layer')
  const orders = captured.find(req => req.pathAndQuery === '/api/admin/orders')
  assert.ok(orders)
  assert.equal(orders!.headers?.['x-kovo-tenant-tag'], tenantTag)
  assert.equal(orders!.headers?.['x-kovo-run-id'], runId)
})

test('v6 staging-tag: cleanup falls back to the next in-scope origin when the label is mis-mapped', async () => {
  const h2Origin = 'https://h2.staging.example.com'
  const entities = new Set([`${tenantTag}cart-9`])
  const hits: string[] = []
  const broker = new RequestBroker({
    resolve: async () => [publicAddress],
    transport: async (url: URL) => {
      hits.push(url.origin)
      if (url.origin === h2Origin) {
        return { status: 404, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'not_found' }) }
      }
      let removed = 0
      for (const id of [...entities]) {
        if (id.startsWith(`${tenantTag}`)) { entities.delete(id); removed += 1 }
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ removed, restored: 0 }) }
    },
  })
  const grant: Grant = {
    tier: 3,
    canRead: () => true,
    scopePolicy: stagingPolicy({ targetOrigins: [origin, h2Origin] }),
    audit: () => {},
  }
  const cleaned = await cleanupStagedEntities({
    endpoints: [
      { origin: h2Origin, method: 'POST', pathTemplate: '/__staging__/cleanup' },
      { origin, method: 'GET', pathTemplate: '/v1/health' },
    ],
    runId,
    broker,
    grant,
    signal: new AbortController().signal,
  })
  assert.equal(cleaned, 1)
  assert.deepEqual(hits, [h2Origin, origin], 'teardown retries the hook on the real app origin')
  assert.equal(entities.size, 0)
})

test('v6 staging-tag: run-scoped cleanup hook removes tagged entities only', async () => {
  const cleanupPath = '/__staging__/cleanup'
  const entities = new Set([
    'inv-alpha-1',
    `${tenantTag}cart-1`,
    `${tenantTag}order-2`,
  ])
  const calls: Array<{ method: string; url: string; body: string }> = []
  const broker = new RequestBroker({
    resolve: async () => [publicAddress],
    transport: async (url: URL, _address, _signal, options) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href, body: options?.body ?? '' })
      const queryRunId = url.searchParams.get('runId') ?? ''
      let removed = 0
      for (const id of [...entities]) {
        if (id.startsWith(`kovo-qa-${queryRunId}-`)) {
          entities.delete(id)
          removed += 1
        }
      }
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ runId: queryRunId, removed, restored: 0, remaining: [] }),
      }
    },
  })
  const grant: Grant = {
    tier: 3,
    canRead: value => value === origin,
    scopePolicy: stagingPolicy(),
    audit: () => {},
  }

  assert.deepEqual(stagingCleanupTarget([endpoint('POST', cleanupPath)], runId), {
    origin,
    pathAndQuery: `${cleanupPath}?runId=${runId}`,
  })
  assert.equal(stagingCleanupTarget([endpoint('GET', cleanupPath)], runId), null, 'cleanup hook must be POST')

  const cleaned = await cleanupStagedEntities({
    endpoints: [{ origin, method: 'POST', pathTemplate: cleanupPath }],
    runId,
    broker,
    grant,
    signal: new AbortController().signal,
  })
  assert.equal(cleaned, 2, 'both tagged entities are reported removed')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].method, 'POST')
  assert.equal(new URL(calls[0].url).searchParams.get('runId'), runId)
  assert.deepEqual([...entities], ['inv-alpha-1'], 'pre-existing owner row survives cleanup')
})
