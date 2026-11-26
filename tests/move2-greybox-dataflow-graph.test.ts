/**
 * Move 2: Live Grey-Box Dynamic Capability & Data-Flow Graph + 404-Only `surface_probe` Ghost Filter.
 *
 * Fast class-level guard covering (Docker-free, real SQLite WAL `Store`, zero benchmark literals):
 *  1. 404/405-only `surface_probe` ghost route exclusion in both `buildRuntimeDiscoveryInput` and
 *     `synthesizeRuntimeCompositeWave1Steps` (preventing bogus `hyp_cat_asym` / `hyp_cat_role_asym`
 *     / `hyp_cat_life` ghost hypotheses while preserving OpenAPI/SPA-evidenced & live routes).
 *  2. Secret-free structural response signal harvesting in `resource-harvest.ts`
 *     (`await_async`, `hmac_sign`, `lifecycle_state`, `signed_url`) without ever leaking raw secret
 *     values, preserving `RESOURCE_SECRET_VALUE_RE`.
 *  3. Cycle-safe OpenAPI `#/components/schemas/...` `$ref` response-property & live HTTP header
 *     harvesting in `buildRuntimeDiscoveryInput` and `phase0-recon.ts`, synthesizing cross-route
 *     `produces -> consumes` edges across disjoint path prefixes plus `runtime_api_dependencies` facts.
 *  4. Typed edge classification & Wave-1 prioritization for `await_async`, `hmac_sign`, and
 *     `create -> rebind -> finalize` lifecycle chains in `inferRuntimeInvariantHypotheses` and
 *     `synthesizeRuntimeCompositeWave1Steps`.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import { synthesizeRuntimeCompositeWave1Steps } from '../src/server/exec-dispatch.ts'
import {
  buildRuntimeDiscoveryInput,
  classifyRuntimeDependencyEdgeKind,
  extractRuntimeCatalogFromFacts,
  filterGhostSurfaceProbeEndpoints,
  inferRuntimeInvariantHypotheses,
} from '../src/server/invariant-runtime-parity.ts'
import { runPhase0Recon } from '../src/server/phase0-recon.ts'
import {
  classifyStructuralFieldEdgeKind,
  extractResourceRefsFromExchange,
  extractResponseStructuralSignals,
  isOpaqueResourceId,
} from '../src/server/resource-harvest.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const APP_ORIGIN = 'https://portal.example.invalid'
const API_ORIGIN = 'https://api.example.invalid'
const HOOK_ORIGIN = 'https://hooks.example.invalid'

// ============================================================================
// 1. 404/405-only `surface_probe` ghost filtering
// ============================================================================

test('buildRuntimeDiscoveryInput & filterGhostSurfaceProbeEndpoints exclude 404/405-only surface_probe ghosts while keeping live and OpenAPI/SPA-evidenced routes', () => {
  const endpoints = [
    { origin: API_ORIGIN, method: 'GET', pathTemplate: '/api/v1/orders/:id', authRequirement: 'bearerAuth', source: 'spa_crawl' },
    { origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/orders/ghost-batch', authRequirement: 'none', source: 'surface_probe' },
    { origin: API_ORIGIN, method: 'DELETE', pathTemplate: '/api/v1/orders/ghost-admin', authRequirement: 'none', source: 'surface_probe' },
    { origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/orders/live-probe', authRequirement: 'none', source: 'surface_probe' },
    { origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/orders/openapi-backed', authRequirement: 'none', source: 'surface_probe' },
  ]
  const brokerExchanges = [
    { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orders/42', status: 200, personaHandle: 'member_a' },
    { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders/ghost-batch', status: 404, personaHandle: 'member_a' },
    { origin: API_ORIGIN, method: 'DELETE', pathAndQuery: '/api/v1/orders/ghost-admin', status: 405, personaHandle: 'member_a' },
    { origin: API_ORIGIN, method: 'DELETE', pathAndQuery: '/api/v1/orders/ghost-admin', status: 404, personaHandle: 'admin_a' },
    { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders/live-probe', status: 404, personaHandle: 'anonymous' },
    { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders/live-probe', status: 403, personaHandle: 'member_a' },
    { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orders/openapi-backed', status: 404, personaHandle: 'anonymous' },
  ]
  const openApiSpec = {
    kind: 'openapi',
    origin: API_ORIGIN,
    content: JSON.stringify({
      openapi: '3.0.3',
      paths: {
        '/api/v1/orders/openapi-backed': { post: { operationId: 'openapiBacked', security: [], responses: { '200': { description: 'ok' } } } },
      },
    }),
  }

  const directFiltered = filterGhostSurfaceProbeEndpoints(endpoints, brokerExchanges)
  assert.equal(directFiltered.some(e => e.pathTemplate === '/api/v1/orders/ghost-batch'), false)
  assert.equal(directFiltered.some(e => e.pathTemplate === '/api/v1/orders/ghost-admin'), false)
  assert.equal(directFiltered.some(e => e.pathTemplate === '/api/v1/orders/live-probe'), true)

  const input = buildRuntimeDiscoveryInput({
    approvedOrigins: new Set([API_ORIGIN]),
    endpoints,
    specs: [openApiSpec],
    brokerExchanges,
  })
  const paths = new Set((input.openApiOperations ?? []).map(o => o.path))
  assert.equal(paths.has('/api/v1/orders/ghost-batch'), false, '404-only surface_probe ghost must be excluded')
  assert.equal(paths.has('/api/v1/orders/ghost-admin'), false, '404/405-only surface_probe ghost must be excluded')
  assert.equal(paths.has('/api/v1/orders/live-probe'), true, 'surface_probe with a non-404/405 live response (403) must stay')
  assert.equal(paths.has('/api/v1/orders/openapi-backed'), true, 'OpenAPI-evidenced route must stay even if anon probe returned 404')

  const parity = inferRuntimeInvariantHypotheses({ mode: 'grey-box', ...input })
  assert.equal(
    parity.hypotheses.some(h => h.targetRoute?.includes('ghost-batch') || h.targetRoute?.includes('ghost-admin')),
    false,
    'filtered ghost routes must never emit hyp_cat_asym / hyp_cat_role_asym / hyp_cat_life hypotheses',
  )
})

// ============================================================================
// 2. Secret-free structural signal extraction (`resource-harvest.ts`)
// ============================================================================

test('extractResponseStructuralSignals classifies await_async, hmac_sign, signed_url, and lifecycle_state without ever returning raw secret values', () => {
  const jwtLike = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEiLCJyb2xlIjoiYWRtaW4ifQ.sigvalue123456'
  const rawSecret = 'whsec_test_never_leak_this_raw_secret_value_998877'
  assert.equal(isOpaqueResourceId(jwtLike), false, 'RESOURCE_SECRET_VALUE_RE must keep rejecting JWT values')

  const signals = extractResponseStructuralSignals({
    status: 202,
    pathAndQuery: '/api/v1/reports/generate',
    mediaType: 'application/json',
    respHeaders: {
      'X-Job-Id': 'job_8821',
      'X-Hub-Signature-256': `sha256=${rawSecret}`,
      'X-Request-Token': jwtLike,
      Location: '/api/v1/jobs/job_8821/status',
    },
    body: JSON.stringify({
      exportId: 'exp_4412',
      statusUrl: '/api/v1/exports/exp_4412/status',
      webhookSecret: rawSecret,
      downloadToken: jwtLike,
      orderId: 'ord_7711',
      approvalStatus: 'pending',
    }),
  })

  const serialized = JSON.stringify(signals)
  assert.equal(serialized.includes(rawSecret), false, 'raw secret value must NEVER appear in structural signals')
  assert.equal(serialized.includes(jwtLike), false, 'JWT value must NEVER appear in structural signals')
  assert.equal(serialized.includes('job_8821'), false, 'raw header value must NEVER appear in structural signals')

  assert.ok(signals.some(s => s.field === 'status:202' && s.edgeKind === 'await_async'))
  assert.ok(signals.some(s => s.field === 'x-job-id' && s.source === 'header' && s.edgeKind === 'await_async'))
  assert.ok(signals.some(s => s.field === 'location' && s.source === 'header' && s.edgeKind === 'await_async'))
  assert.ok(signals.some(s => s.field === 'x-hub-signature-256' && s.source === 'header' && s.edgeKind === 'hmac_sign'))
  assert.ok(signals.some(s => s.field === 'x-request-token' && s.source === 'header' && s.edgeKind === 'signed_url'))
  assert.ok(signals.some(s => s.field === 'exportId' && s.source === 'json' && s.edgeKind === 'await_async'))
  assert.ok(signals.some(s => s.field === 'statusUrl' && s.source === 'json' && s.edgeKind === 'await_async'))
  assert.ok(signals.some(s => s.field === 'webhookSecret' && s.source === 'json' && s.edgeKind === 'hmac_sign'))
  assert.ok(signals.some(s => s.field === 'downloadToken' && s.source === 'json' && s.edgeKind === 'signed_url'))
  assert.ok(signals.some(s => s.field === 'orderId' && s.source === 'json' && s.edgeKind === 'lifecycle_state'))
  assert.equal(classifyStructuralFieldEdgeKind(jwtLike, 'json'), null)

  // Verify extractResourceRefsFromExchange still rejects secrets while extracting opaque IDs
  const refs = extractResourceRefsFromExchange({
    origin: API_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/reports/generate',
    status: 202,
    mediaType: 'application/json',
    body: JSON.stringify({ orderId: 'ord_7711', tokenId: jwtLike }),
  })
  assert.ok(refs.some(r => r.resourceId === 'ord_7711'))
  assert.equal(refs.some(r => r.resourceId === jwtLike), false)
})

// ============================================================================
// 3. OpenAPI `$ref` response schemas (with cycle protection) + live headers
//    -> dynamic `produces -> consumes` edges across disjoint prefixes
// ============================================================================

test('buildRuntimeDiscoveryInput resolves cyclic OpenAPI $ref responses and live response headers into cross-route produces -> consumes edges', () => {
  const openApiSpec = {
    kind: 'openapi',
    origin: API_ORIGIN,
    content: JSON.stringify({
      openapi: '3.0.3',
      components: {
        schemas: {
          CyclicNode: {
            type: 'object',
            properties: {
              exportTaskId: { type: 'string' },
              parent: { $ref: '#/components/schemas/CyclicNode' },
            },
          },
          WebhookProvisionResp: {
            type: 'object',
            properties: {
              signingSecret: { type: 'string' },
              endpointId: { type: 'string' },
            },
          },
        },
      },
      paths: {
        '/api/v1/reports/run': {
          post: {
            operationId: 'startReportRun',
            responses: {
              '202': {
                description: 'accepted',
                headers: { 'X-Task-Id': { schema: { type: 'string' } } },
                content: { 'application/json': { schema: { $ref: '#/components/schemas/CyclicNode' } } },
              },
            },
          },
        },
        '/api/v1/poll/{exportTaskId}': {
          get: {
            operationId: 'pollReportResult',
            parameters: [{ name: 'exportTaskId', in: 'path', required: true }],
            responses: { '200': { description: 'ok' } },
          },
        },
        '/api/v1/integrations/provision': {
          post: {
            operationId: 'provisionIntegration',
            responses: {
              '201': {
                description: 'created',
                content: { 'application/json': { schema: { $ref: '#/components/schemas/WebhookProvisionResp' } } },
              },
            },
          },
        },
        '/api/v1/webhooks/receiver': {
          post: {
            operationId: 'receiveWebhookEvent',
            parameters: [{ name: 'x-signature', in: 'header' }],
            responses: { '200': { description: 'ok' } },
          },
        },
      },
    }),
  }

  const input = buildRuntimeDiscoveryInput({
    approvedOrigins: new Set([API_ORIGIN]),
    specs: [openApiSpec],
    brokerExchanges: [
      {
        origin: API_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/integrations/provision',
        status: 201,
        personaHandle: 'member_a',
        respHeaders: { 'X-Signature': 'sha256=do_not_expose_raw_hmac' },
      },
    ],
  })

  const deps = input.apiDependencies ?? []
  assert.ok(
    deps.some(d => d.producer === 'POST /api/v1/reports/run' && d.consumer === 'GET /api/v1/poll/{exportTaskId}' && d.resourceKey === 'exportTaskId'),
    `expected cross-prefix OpenAPI $ref produces->consumes edge for exportTaskId, got ${JSON.stringify(deps)}`,
  )
  assert.ok(
    deps.some(d => d.producer === 'POST /api/v1/integrations/provision' && d.consumer === 'POST /api/v1/webhooks/receiver' && (d.resourceKey === 'signingSecret' || d.resourceKey === 'x-signature')),
    `expected hmac_sign produces->consumes edge to webhook receiver, got ${JSON.stringify(deps)}`,
  )
  assert.equal(JSON.stringify(deps).includes('do_not_expose_raw_hmac'), false, 'raw header value must not leak into synthesized dependencies')

  const parity = inferRuntimeInvariantHypotheses({ mode: 'grey-box', ...input })
  assert.ok(
    parity.hypotheses.some(h => h.preconditions.includes('edge_kind:await_async') && h.verificationHint.includes('ctx.await_async')),
    'await_async dependency must emit prioritized await_async hypothesis & directive',
  )
  assert.ok(
    parity.hypotheses.some(h => h.preconditions.includes('edge_kind:hmac_sign') && h.capabilityKind === 'signing_material' && h.verificationHint.includes('ctx.hmac_sign')),
    'hmac_sign dependency must emit prioritized signing_material hypothesis & ctx.hmac_sign directive',
  )
})

// ============================================================================
// 4. Phase-0 recon live JSON/header harvesting -> cross-route api_dependencies
//    + persisted `runtime_api_dependencies` catalog fact
// ============================================================================

test('runPhase0Recon harvests live 2xx/202 JSON keys and headers into cross-route api_dependencies and persists runtime_api_dependencies fact', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [APP_ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const reconWorker = storage.makeWorker(run, 'threat_model', asset, 'Phase-0 Recon', 'Map surface', {
    sourceOrigins: [APP_ORIGIN],
  })

  const rawWebhookSecret = 'whsec_live_secret_value_never_store_55667788'
  const openApiPayload = JSON.stringify({
    openapi: '3.0.3',
    paths: {
      '/api/v1/reports/trigger': {
        get: { operationId: 'triggerReport', responses: { '202': { description: 'queued' } } },
      },
      '/api/v1/status/{exportJobId}': {
        get: {
          operationId: 'getExportStatus',
          parameters: [{ name: 'exportJobId', in: 'path', required: true }],
          responses: { '200': { description: 'ok' } },
        },
      },
      '/api/v1/integrations/keys': {
        get: { operationId: 'getIntegrationKey', responses: { '200': { description: 'ok' } } },
      },
      '/api/v1/callbacks/events': {
        post: { operationId: 'ingestCallback', responses: { '200': { description: 'ok' } } },
      },
      '/api/v1/transfers': {
        post: { operationId: 'createTransfer', responses: { '201': { description: 'created' } } },
      },
      '/api/v1/transfers/{transferId}': {
        patch: { operationId: 'rebindTransfer', responses: { '200': { description: 'updated' } } },
      },
      '/api/v1/transfers/{transferId}/finalize': {
        post: { operationId: 'finalizeTransfer', responses: { '200': { description: 'settled' } } },
      },
    },
  })

  const makeEx = (
    method: string,
    pathAndQuery: string,
    status: number,
    mediaType: string,
    body: string,
    extraHeaders: Record<string, string> = {},
  ): BrokerExchangeResult => ({
    origin: APP_ORIGIN,
    finalOrigin: APP_ORIGIN,
    redirectOrigins: [],
    method,
    pathAndQuery,
    reqHeaders: {},
    status,
    respHeaders: { 'content-type': mediaType, ...extraHeaders },
    setCookies: [],
    mediaType,
    body,
    bodyPreview: body.slice(0, 256),
    bodyBytes: Buffer.byteLength(body, 'utf8'),
    bodyTruncated: false,
    bodySha256: '0'.repeat(64),
    durationMs: 2,
    personaHandle: null,
    observation: {
      origin: APP_ORIGIN,
      finalOrigin: APP_ORIGIN,
      status,
      headers: { 'content-type': mediaType, ...extraHeaders },
      setCookies: [],
      bodyPreview: body.slice(0, 256),
      bodyBytes: Buffer.byteLength(body, 'utf8'),
    },
  } as unknown as BrokerExchangeResult)

  const fakeBroker = {
    async executeHttp(req: { method?: string; pathAndQuery: string }): Promise<BrokerExchangeResult> {
      const m = (req.method ?? 'GET').toUpperCase()
      const p = req.pathAndQuery
      if (p === '/') {
        return makeEx(m, p, 200, 'text/html', '<html><body><a href="/api/v1/reports/trigger">Run</a><a href="/api/v1/integrations/keys">Keys</a></body></html>')
      }
      if (p === '/openapi.json') return makeEx(m, p, 200, 'application/json', openApiPayload)
      if (p === '/api/v1/reports/trigger') {
        return makeEx(m, p, 202, 'application/json', JSON.stringify({ exportJobId: 'job_4401', statusUrl: '/api/v1/status/job_4401' }), { 'x-job-id': 'job_4401' })
      }
      if (p === '/api/v1/integrations/keys') {
        return makeEx(m, p, 200, 'application/json', JSON.stringify({ webhookSecret: rawWebhookSecret }), { 'x-signature': 'sha256=deadbeef' })
      }
      return makeEx(m, p, 404, 'text/plain', 'not found')
    },
  } as unknown as RequestBroker

  const fakeGrant = { canRead: () => true, canWrite: () => true, personas: new Map() } as unknown as Grant

  await runPhase0Recon({
    storage,
    runId,
    scopeRevision: run.scopeRevision,
    tier: 2,
    origins: [APP_ORIGIN],
    budgetRequests: 600,
    broker: fakeBroker,
    grant: fakeGrant,
    signal: new AbortController().signal,
    assignmentId: reconWorker.id,
  })

  const facts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
  assert.equal(JSON.stringify(facts).includes(rawWebhookSecret), false, 'raw webhook secret must never persist into facts')

  const extracted = extractRuntimeCatalogFromFacts(facts, new Set([APP_ORIGIN]))
  assert.ok(extracted.apiDependencies.length >= 3, `expected cross-route + lifecycle apiDependencies fact, got ${JSON.stringify(extracted.apiDependencies)}`)
  assert.ok(
    extracted.apiDependencies.some(d => d.producer.includes('/api/v1/reports/trigger') && d.consumer.includes('/api/v1/status/{exportJobId}') && d.resourceKey === 'exportJobId'),
    `expected cross-prefix exportJobId edge, got ${JSON.stringify(extracted.apiDependencies)}`,
  )
  assert.ok(
    extracted.apiDependencies.some(d => d.producer.includes('/api/v1/integrations/keys') && d.consumer.includes('/api/v1/callbacks/events')),
    `expected hmac_sign edge to /api/v1/callbacks/events, got ${JSON.stringify(extracted.apiDependencies)}`,
  )
  assert.ok(
    extracted.apiDependencies.some(d => d.producer.includes('/api/v1/transfers') && d.consumer.includes('/finalize')),
    `expected create->rebind->finalize lifecycle edge, got ${JSON.stringify(extracted.apiDependencies)}`,
  )
})

// ============================================================================
// 5. Typed edge classification & Wave-1 prioritization
//    (`await_async`, `hmac_sign`, `create -> rebind -> finalize`) + ghost filter
// ============================================================================

test('inferRuntimeInvariantHypotheses and synthesizeRuntimeCompositeWave1Steps prioritize await_async, hmac_sign, and create->rebind->finalize while excluding 404 surface_probe ghosts', async (t) => {
  assert.equal(
    classifyRuntimeDependencyEdgeKind({ producer: 'POST /api/v1/jobs', consumer: 'GET /api/v1/status/:jobId', resourceKey: 'jobId' }),
    'await_async',
  )
  assert.equal(
    classifyRuntimeDependencyEdgeKind({ producer: 'GET /api/v1/hooks/config', consumer: 'POST /api/v1/webhooks/receive', resourceKey: 'webhookSecret' }),
    'hmac_sign',
  )
  assert.equal(
    classifyRuntimeDependencyEdgeKind({ producer: 'POST /api/v1/drafts', consumer: 'PATCH /api/v1/drafts/:id', resourceKey: 'draftId' }),
    'lifecycle_chain',
  )

  const parity = inferRuntimeInvariantHypotheses({
    mode: 'grey-box',
    apiDependencies: [
      { producer: 'GET /api/v1/items', consumer: 'GET /api/v1/items/:itemId', resourceKey: 'itemId', producerOrigin: API_ORIGIN, consumerOrigin: API_ORIGIN },
      { producer: 'POST /api/v1/exports', consumer: 'GET /api/v1/poll/:exportId', resourceKey: 'exportId', producerOrigin: APP_ORIGIN, consumerOrigin: API_ORIGIN, observedTransitions: ['edge_kind:await_async'] },
      { producer: 'POST /api/v1/keys', consumer: 'POST /api/v1/webhooks/ingest', resourceKey: 'signingSecret', producerOrigin: API_ORIGIN, consumerOrigin: HOOK_ORIGIN, observedTransitions: ['edge_kind:hmac_sign'] },
      { producer: 'POST /api/v1/payouts', consumer: 'PATCH /api/v1/payouts/:payoutId', resourceKey: 'payoutId', producerOrigin: API_ORIGIN, consumerOrigin: API_ORIGIN },
      { producer: 'PATCH /api/v1/payouts/:payoutId', consumer: 'POST /api/v1/payouts/:payoutId/finalize', resourceKey: 'payoutId', producerOrigin: API_ORIGIN, consumerOrigin: API_ORIGIN },
    ],
  })

  const genericHyp = parity.hypotheses.find(h => h.preconditions.includes('api_dependency:itemId'))
  const asyncHyp = parity.hypotheses.find(h => h.preconditions.includes('edge_kind:await_async'))
  const hmacHyp = parity.hypotheses.find(h => h.preconditions.includes('edge_kind:hmac_sign'))
  const lifeChainHyp = parity.hypotheses.find(h => h.preconditions.includes('workflow:create_rebind_finalize'))

  assert.ok(asyncHyp && hmacHyp && lifeChainHyp, 'all three priority workflow families must emit hypotheses')
  assert.ok(hmacHyp.score > (genericHyp?.score ?? 0), 'hmac_sign must outrank generic single-hop dependency')
  assert.ok(asyncHyp.score > (genericHyp?.score ?? 0), 'await_async must outrank generic single-hop dependency')
  assert.ok(lifeChainHyp.score > (genericHyp?.score ?? 0), 'create->rebind->finalize must outrank generic single-hop dependency')
  assert.match(lifeChainHyp.verificationHint, /ctx\.prove_composite/)

  // Wave-1 composite synthesis: ghost 404 surface_probe endpoint must be excluded, typed edges prioritized.
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [APP_ORIGIN, API_ORIGIN, HOOK_ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => c.origin === APP_ORIGIN)!
  const worker = storage.makeWorker(run, 'threat_model', asset, 'Recon', 'Map', { sourceOrigins: [APP_ORIGIN, API_ORIGIN, HOOK_ORIGIN] })

  storage.client.prepare(`
    INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'ex-ghost-404', runId, worker.id, run.scopeRevision, API_ORIGIN, API_ORIGIN, '[]',
    'POST', '/api/v1/ghost-admin/impersonate', 404, 'text/plain', 'member_a', '{}', '{}', '', 'e3b0', 2, Date.now(),
  )

  const ghostEp = storage.upsertEndpoint({
    runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/ghost-admin/impersonate',
    authRequirement: 'none', riskScore: 99, source: 'surface_probe',
  })
  const liveCreate = storage.upsertEndpoint({
    runId, scopeRevision: run.scopeRevision, origin: APP_ORIGIN, method: 'POST', pathTemplate: '/api/v1/payouts',
    authRequirement: 'bearerAuth', riskScore: 80, source: 'openapi',
  })
  const liveRebind = storage.upsertEndpoint({
    runId, scopeRevision: run.scopeRevision, origin: APP_ORIGIN, method: 'PATCH', pathTemplate: '/api/v1/payouts/:id',
    authRequirement: 'bearerAuth', riskScore: 82, source: 'openapi',
  })
  const liveFinalize = storage.upsertEndpoint({
    runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/payouts/:id/finalize',
    authRequirement: 'bearerAuth', riskScore: 85, source: 'openapi',
  })

  const steps = synthesizeRuntimeCompositeWave1Steps(storage, run, {
    sourceMounted: false,
    endpoints: [ghostEp, liveCreate, liveRebind, liveFinalize],
    apiDependencies: [
      { producer: 'POST /api/v1/exports/start', consumer: 'GET /api/v1/poll/:exportId', resourceKey: 'exportId', producerOrigin: APP_ORIGIN, consumerOrigin: API_ORIGIN },
      { producer: 'GET /api/v1/webhooks/secret', consumer: 'POST /api/v1/webhooks/ingest', resourceKey: 'webhookSecret', producerOrigin: API_ORIGIN, consumerOrigin: HOOK_ORIGIN },
    ],
  })

  assert.ok(steps.length >= 1, 'must synthesize Wave-1 composite steps from prioritized runtime edges')
  for (const step of steps) {
    assert.equal(step.hypothesis.includes('/api/v1/ghost-admin/impersonate'), false, '404-only surface_probe ghost endpoint must never enter Wave-1 composite steps')
  }
  assert.ok(
    steps.some(s => s.hypothesis.includes('ctx.hmac_sign') || s.hypothesis.includes('ctx.await_async')),
    `expected Wave-1 composite step to carry typed workflow directives, got ${JSON.stringify(steps.map(s => s.hypothesis))}`,
  )
})

// ============================================================================
// 6. Anti-Contamination Gate
// ============================================================================

test('src/server/ and src/skills/ remain 100% free of benchmark contamination literals', () => {
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `unexpected contamination hits: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
