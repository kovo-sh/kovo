/**
 * Grey-Box Runtime Invariant Synthesis, API-Dependency Multi-Hop Planning & Wave-1 Dispatch Tests.
 *
 * Proves (Docker-free, real SQLite WAL `Store`, zero benchmark contamination):
 *  1. `phase0-recon.ts`:
 *     - `parseOpenApiDoc` preserves document-level default `security`, operation-level `security`
 *       overrides (`[]` -> `'none'`), role-scoped `security`, `operationId`, `requestBodyKeys`,
 *       and OpenAPI auth extension/header hints on both stored `EndpointRow.authRequirement` and
 *       returned `operations`.
 *     - `extractRuntimeSpaRoutesFromJs`, `extractRuntimeGraphqlFieldsFromJs`,
 *       `buildRuntimeGraphqlCatalogFromSchema`, and `runPhase0Recon` emit structured
 *       `RuntimeSpaRoute[]`, `RuntimeGraphqlCatalog`, and `RuntimeOpenApiOperation[]` summary facts
 *       (`runtime_spa_routes`, `runtime_graphql_catalog`, `runtime_openapi_catalog`).
 *  2. `invariant-synthesizer.ts`:
 *     - `inferRuntimeInvariantHypotheses` cleanly consumes OpenAPI `security` (policy & role-tier
 *       asymmetry), `spaRoutes` (client-role gating, lifecycle actions, cross-origin calls),
 *       `graphqlCatalog`/`graphqlCatalogs`, and producer->consumer `apiDependencies` (same-origin,
 *       3-stage transitive chains, and cross-origin edges).
 *     - `extractRuntimeCatalogFromFacts`, `buildRuntimeDiscoveryInput`, and
 *       `synthesizePostFloorRuntimeInvariants` support both pre-floor and incremental post-floor runs.
 *  3. `graph-coordinator.ts`:
 *     - `planChainRound` seeds multi-stage chain hypotheses from producer->consumer `apiDependencies`
 *       and multi-origin runtime edges when `sourceMounted: false` (grey-box mode), and
 *       `createGraphCoordinator` forwards `deps.listApiDependencies()`.
 *  4. `exec-dispatch.ts`:
 *     - `isGenericWave1BoundaryChainStep` / `chainLaneDispatchRank` do NOT demote grey-box Wave-1
 *       chains backed by runtime producer->consumer dependencies, cross-origin transitions, or
 *       multi-persona differential observations (Rank 0), while still demoting bare single-origin
 *       heuristic stubs (Rank 2).
 *     - `synthesizeRuntimeCompositeWave1Steps` synthesizes up to 2 cross-origin composite Wave-1
 *       workflow steps matching WB's 3-5 stage shape when `sourceMounted: false`, is idempotent,
 *       and returns `[]` when `sourceMounted: true`.
 *  5. Anti-contamination: `scanSourceTreeForContamination` reports 0 hits across `src/server/` & `src/skills/`.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import {
  MAX_SYNTHESIZED_RUNTIME_COMPOSITE_STEPS,
  chainLaneDispatchRank,
  classifyDispatchLane,
  hasRuntimeBackedChainEvidence,
  isGenericWave1BoundaryChainStep,
  isHighSignalSourceOrPlannerChainStep,
  isMultiHopChainStep,
  planRoundRobinDispatch,
  synthesizeRuntimeCompositeWave1Steps,
  type DispatchLaneStep,
} from '../src/server/exec-dispatch.ts'
import {
  createGraphCoordinator,
  planChainRound,
  type CoordinatorApiDependency,
  type CoordinatorEndpoint,
} from '../src/server/graph-coordinator.ts'
import {
  buildRuntimeDiscoveryInput,
  extractRuntimeCatalogFromFacts,
  inferRuntimeInvariantHypotheses,
  synthesizePostFloorRuntimeInvariants,
} from '../src/server/invariant-synthesizer.ts'
import {
  buildRuntimeGraphqlCatalogFromSchema,
  extractRuntimeGraphqlFieldsFromJs,
  extractRuntimeSpaRoutesFromJs,
  parseOpenApiDoc,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import { parseGraphqlIntrospection } from '../src/server/probes/graphql.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const APP_ORIGIN = 'https://portal.example.invalid'
const API_ORIGIN = 'https://api.example.invalid'
const IDP_ORIGIN = 'https://auth.example.invalid'

// ============================================================================
// 1. OpenAPI security/operationId preservation & Phase-0 runtime catalog facts
// ============================================================================

test('parseOpenApiDoc preserves document-level default security, operation overrides, operationId, and auth hints', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [API_ORIGIN], tier: 2 })

  const openApiDoc = {
    openapi: '3.0.3',
    info: { title: 'Synthetic Billing API', version: '1.0.0' },
    security: [{ bearerAuth: [] }],
    paths: {
      '/api/v1/invoices/{invoiceId}': {
        get: {
          operationId: 'getInvoiceById',
          tags: ['invoices'],
          responses: { '200': { description: 'ok' } },
        },
        delete: {
          operationId: 'deleteInvoiceAdmin',
          security: [{ oauth2: ['admin:write'] }],
          responses: { '204': { description: 'deleted' } },
        },
      },
      '/api/v1/invoices/batch': {
        post: {
          operationId: 'batchExportInvoices',
          security: [],
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    invoiceIds: { type: 'array', items: { type: 'string' } },
                    amount: { type: 'number' },
                  },
                },
              },
            },
          },
          responses: { '200': { description: 'ok' } },
        },
      },
      '/api/v1/webhooks/dispatch': {
        post: {
          operationId: 'dispatchWebhook',
          'x-required-roles': ['ops_admin'],
          responses: { '202': { description: 'queued' } },
        },
      },
    },
  }

  const parsed = parseOpenApiDoc(
    JSON.stringify(openApiDoc),
    API_ORIGIN,
    storage,
    runId,
    run.scopeRevision,
    new Set(),
    new Set(),
  )

  assert.equal(parsed.endpoints, 4)

  const getOp = parsed.operations.find(o => o.method === 'GET' && o.pathTemplate === '/api/v1/invoices/{invoiceId}')
  const delOp = parsed.operations.find(o => o.method === 'DELETE' && o.pathTemplate === '/api/v1/invoices/{invoiceId}')
  const batchOp = parsed.operations.find(o => o.method === 'POST' && o.pathTemplate === '/api/v1/invoices/batch')
  assert.ok(getOp && delOp && batchOp)

  assert.equal(getOp.operationId, 'getInvoiceById')
  assert.deepEqual(getOp.security, [{ bearerAuth: [] }])
  assert.equal(getOp.authRequirement, 'bearerAuth')

  assert.equal(delOp.operationId, 'deleteInvoiceAdmin')
  assert.deepEqual(delOp.security, [{ oauth2: ['admin:write'] }])
  assert.equal(delOp.authRequirement, 'oauth2:admin:write')

  assert.equal(batchOp.operationId, 'batchExportInvoices')
  assert.deepEqual(batchOp.security, [])
  assert.equal(batchOp.authRequirement, 'none')
  assert.ok(batchOp.requestBodyKeys?.includes('invoiceIds'))

  const stored = storage.listEndpoints(runId, { origin: API_ORIGIN })
  const storedGet = stored.find(e => e.method === 'GET' && e.pathTemplate === '/api/v1/invoices/{invoiceId}')
  const storedDel = stored.find(e => e.method === 'DELETE' && e.pathTemplate === '/api/v1/invoices/{invoiceId}')
  const storedBatch = stored.find(e => e.method === 'POST' && e.pathTemplate === '/api/v1/invoices/batch')
  assert.equal(storedGet?.authRequirement, 'bearerAuth')
  assert.equal(storedDel?.authRequirement, 'oauth2:admin:write')
  assert.equal(storedBatch?.authRequirement, 'none')

  // Feeding parsed OpenAPI metadata into inferRuntimeInvariantHypotheses must immediately synthesize
  // policy-asymmetry hypotheses (unauthenticated batch export vs authenticated sibling).
  const parity = inferRuntimeInvariantHypotheses({
    mode: 'grey-box',
    openApiOperations: parsed.operations.map(o => ({
      method: o.method,
      path: o.pathTemplate,
      serviceOrigin: API_ORIGIN,
      operationId: o.operationId,
      security: o.security,
      authRequirement: o.authRequirement,
      requestBodyKeys: o.requestBodyKeys,
      parameters: o.parameters,
    })),
  })
  assert.ok(
    parity.hypotheses.some(h => h.kind === 'policy_asymmetry' && h.targetRoute?.includes('/api/v1/invoices/batch')),
    'OpenAPI security: [] override must emit policy_asymmetry hypothesis for unauthenticated batch op',
  )
})

test('Phase-0 recon emits structured SPA route, GraphQL catalog, and OpenAPI catalog facts for InvariantSynthesizer', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [APP_ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const reconWorker = storage.makeWorker(run, 'threat_model', asset, 'Phase-0 Recon', 'Map runtime surface', {
    sourceOrigins: [APP_ORIGIN],
  })

  // Unit-check JS & GraphQL helpers directly first.
  const bundleJs = `
    const routes = [
      { path: '/admin/approvals', requiredRoles: ['admin', 'finance'] },
      { path: '/billing/transfers', requiredRoles: ['member'] },
    ];
    async function approveTransfer(id) {
      return fetch('/api/v1/transfers/' + id + '/approve', { method: 'POST', body: JSON.stringify({ amount: 100 }) });
    }
  `
  const extractedSpa = extractRuntimeSpaRoutesFromJs(
    bundleJs,
    {
      routes: [{ path: '/admin/approvals' }, { path: '/billing/transfers' }],
      adminPaths: ['/admin/approvals'],
      httpCalls: [{ url: '/api/v1/transfers/:id/approve', method: 'POST', bodyKeys: ['amount'] }],
    },
    APP_ORIGIN,
  )
  assert.ok(extractedSpa.length >= 2)
  assert.ok(extractedSpa.some(r => r.path === '/admin/approvals' && (r.requiredRoles?.includes('admin') ?? false)))

  const jsGqlFields = extractRuntimeGraphqlFieldsFromJs([
    { kind: 'mutation', name: 'ApprovePayout', fields: ['approvePayout'], preview: 'mutation ApprovePayout($payoutId: ID!) { approvePayout(payoutId: $payoutId) { id } }' },
  ])
  assert.equal(jsGqlFields.length, 1)
  assert.equal(jsGqlFields[0]!.name, 'approvePayout')
  assert.deepEqual(jsGqlFields[0]!.args, ['payoutId'])

  const gqlSchema = parseGraphqlIntrospection({
    queryType: { name: 'Query' },
    mutationType: { name: 'Mutation' },
    types: [
      {
        name: 'Query',
        kind: 'OBJECT',
        fields: [{ name: 'orders', args: [{ name: 'tenantId', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'Order' } }],
      },
      {
        name: 'Mutation',
        kind: 'OBJECT',
        fields: [{ name: 'approveOrder', args: [{ name: 'orderId', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'Order' } }],
      },
    ],
  })
  const gqlCatalog = buildRuntimeGraphqlCatalogFromSchema(gqlSchema, '/graphql', APP_ORIGIN)
  assert.equal(gqlCatalog.fields.length, 2)
  assert.ok(gqlCatalog.fields.some(f => f.kind === 'mutation' && f.name === 'approveOrder' && f.requiredRole === 'admin'))

  // Run full runPhase0Recon against a deterministic synthetic broker serving HTML + JS bundle + OpenAPI + GraphQL introspection.
  const openApiPayload = JSON.stringify({
    openapi: '3.0.3',
    security: [{ bearerAuth: [] }],
    paths: {
      '/api/v1/orders': { get: { operationId: 'listOrders', responses: { '200': { description: 'ok' } } } },
      '/api/v1/orders/{orderId}/approve': {
        post: { operationId: 'approveOrder', security: [], responses: { '200': { description: 'ok' } } },
      },
    },
  })
  const introspectionPayload = JSON.stringify({
    data: {
      __schema: {
        queryType: { name: 'Query' },
        mutationType: { name: 'Mutation' },
        types: [
          {
            name: 'Query',
            kind: 'OBJECT',
            fields: [{ name: 'orderSummary', args: [{ name: 'orderId', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'Order' } }],
          },
          {
            name: 'Mutation',
            kind: 'OBJECT',
            fields: [{ name: 'approveOrder', args: [{ name: 'orderId', type: { kind: 'SCALAR', name: 'ID' } }], type: { kind: 'OBJECT', name: 'Order' } }],
          },
        ],
      },
    },
  })

  const makeEx = (method: string, pathAndQuery: string, status: number, mediaType: string, body: string): BrokerExchangeResult => ({
    origin: APP_ORIGIN,
    finalOrigin: APP_ORIGIN,
    redirectOrigins: [],
    method,
    pathAndQuery,
    reqHeaders: {},
    status,
    respHeaders: { 'content-type': mediaType },
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
      headers: { 'content-type': mediaType },
      setCookies: [],
      bodyPreview: body.slice(0, 256),
      bodyBytes: Buffer.byteLength(body, 'utf8'),
    },
  } as unknown as BrokerExchangeResult)

  const fakeBroker = {
    async executeHttp(req: { method?: string; pathAndQuery: string; body?: string }): Promise<BrokerExchangeResult> {
      const p = req.pathAndQuery
      const m = (req.method ?? 'GET').toUpperCase()
      if (p === '/') {
        return makeEx(m, p, 200, 'text/html', '<html><body><script src="/assets/app.js"></script><a href="/admin/approvals">Approvals</a></body></html>')
      }
      if (p === '/assets/app.js') {
        return makeEx(m, p, 200, 'application/javascript', bundleJs)
      }
      if (p === '/openapi.json') {
        return makeEx(m, p, 200, 'application/json', openApiPayload)
      }
      if (p === '/graphql' && m === 'POST') {
        return makeEx(m, p, 200, 'application/json', introspectionPayload)
      }
      if (p === '/graphql' && m === 'GET') {
        return makeEx(m, p, 200, 'application/json', '{"data":{}}')
      }
      return makeEx(m, p, 404, 'text/plain', 'not found')
    },
  } as unknown as RequestBroker

  const fakeGrant = {
    canRead: () => true,
    canWrite: () => true,
    personas: new Map(),
  } as unknown as Grant

  const recon = await runPhase0Recon({
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

  assert.ok((recon.runtimeSpaRoutes?.length ?? 0) >= 1, 'Phase-0 recon must return structured runtimeSpaRoutes')
  assert.ok((recon.runtimeGraphqlCatalogs?.length ?? 0) >= 1, 'Phase-0 recon must return structured runtimeGraphqlCatalogs')
  assert.ok((recon.runtimeOpenApiOperations?.length ?? 0) >= 2, 'Phase-0 recon must return structured runtimeOpenApiOperations')

  const facts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
  const extracted = extractRuntimeCatalogFromFacts(facts, new Set([APP_ORIGIN]))
  assert.ok(extracted.spaRoutes.length >= 1, 'runtime_spa_routes fact must be persisted and extractable')
  assert.ok(extracted.graphqlCatalog && extracted.graphqlCatalog.fields.length >= 2, 'runtime_graphql_catalog fact must be persisted and extractable')
  assert.ok(extracted.openApiOperations.length >= 2, 'runtime_openapi_catalog fact must be persisted and extractable')
})

// ============================================================================
// 2. InvariantSynthesizer runtime parity + post-floor helper
// ============================================================================

test('inferRuntimeInvariantHypotheses & synthesizePostFloorRuntimeInvariants consume spaRoutes, graphqlCatalog, OpenAPI security, and apiDependencies', () => {
  const preFloor = synthesizePostFloorRuntimeInvariants({
    mode: 'grey-box',
    approvedOrigins: new Set([APP_ORIGIN, API_ORIGIN]),
    endpoints: [
      { origin: API_ORIGIN, method: 'GET', pathTemplate: '/api/v1/payouts/:id', authRequirement: 'bearerAuth' },
      { origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/payouts/batch', authRequirement: 'none' },
    ],
    graphqlCatalog: {
      endpoint: '/graphql',
      serviceOrigin: API_ORIGIN,
      fields: [
        { name: 'payouts', kind: 'query', args: ['tenantId'], returnType: 'Payout', requiresAuth: true },
        { name: 'batchApprovePayouts', kind: 'mutation', args: ['ids'], returnType: 'Payout', requiresAuth: false },
      ],
    },
    spaRoutes: [
      {
        path: '/admin/payouts',
        serviceOrigin: APP_ORIGIN,
        requiredRoles: ['admin'],
        stateActions: ['approve', 'release'],
        apiCalls: [{ method: 'POST', path: '/api/v1/payouts/:id/approve', serviceOrigin: API_ORIGIN }],
      },
    ],
    apiDependencies: [
      {
        producer: 'POST /api/v1/orders',
        consumer: 'GET /api/v1/orders/:orderId',
        resourceKey: 'orderId',
        producerOrigin: APP_ORIGIN,
        consumerOrigin: API_ORIGIN,
        testedBola: false,
      },
      {
        producer: 'GET /api/v1/orders/:orderId',
        consumer: 'POST /api/v1/orders/:orderId/approve',
        resourceKey: 'orderId',
        producerOrigin: API_ORIGIN,
        consumerOrigin: API_ORIGIN,
        testedBola: false,
      },
    ],
  })

  assert.ok(preFloor.runtimeParity.stats.spaRoutesAnalyzed === 1)
  assert.ok(preFloor.runtimeParity.stats.apiDependenciesAnalyzed === 2)
  assert.ok(preFloor.hypotheses.some(h => h.surface === 'graphql' && h.kind === 'policy_asymmetry'), 'GraphQL unauthed batch mutation must emit policy_asymmetry')
  assert.ok(preFloor.hypotheses.some(h => h.preconditions.some(p => p.startsWith('spa_route:/admin/payouts'))), 'SPA route must emit hypothesis')
  assert.ok(preFloor.hypotheses.some(h => h.preconditions.includes('api_dependency:orderId') && h.preconditions.includes('multi_hop_dependency')), '3-stage transitive API dependency chain must emit multi-hop hypothesis')

  // Simulate post-Phase-A-floor re-synthesis with new multi-persona broker_exchanges differential.
  const preIds = new Set(preFloor.hypotheses.map(h => h.id))
  const postFloor = synthesizePostFloorRuntimeInvariants({
    mode: 'grey-box',
    approvedOrigins: new Set([APP_ORIGIN, API_ORIGIN]),
    existingHypothesisIds: preIds,
    endpoints: [
      { origin: API_ORIGIN, method: 'GET', pathTemplate: '/api/v1/payouts/:id', authRequirement: 'bearerAuth' },
      { origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/payouts/batch', authRequirement: 'none' },
    ],
    brokerExchanges: [
      { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/v1/reports/42', status: 403, personaHandle: 'member_a' },
      { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/reports/batch', status: 200, personaHandle: 'member_a' },
    ],
  })

  assert.ok(postFloor.newHypotheses.length >= 1, 'post-floor re-run must emit incremental new hypotheses from floor exchanges')
  assert.ok(
    postFloor.newHypotheses.some(h => h.kind === 'runtime_surface_asymmetry' && h.targetRoute === 'POST /api/v1/reports/batch'),
    'post-floor multi-persona batch skew must surface incrementally',
  )
  assert.ok(
    postFloor.newHypotheses.every(h => !preIds.has(h.id)),
    'incremental post-floor set must exclude already-seeded pre-floor hypothesis IDs',
  )
})

// ============================================================================
// 3. graph-coordinator.ts grey-box API dependency & cross-origin planning
// ============================================================================

test('planChainRound seeds multi-stage chains from apiDependencies and cross-origin runtime edges when sourceMounted is false', () => {
  const endpoints: CoordinatorEndpoint[] = [
    { id: 'ep-1', origin: IDP_ORIGIN, method: 'POST', pathTemplate: '/oauth/token', riskScore: 88, authRequirement: 'none' },
    { id: 'ep-2', origin: APP_ORIGIN, method: 'POST', pathTemplate: '/api/v1/exports', riskScore: 84, authRequirement: 'bearerAuth' },
    { id: 'ep-3', origin: API_ORIGIN, method: 'GET', pathTemplate: '/api/v1/exports/:exportId/download', riskScore: 90, authRequirement: 'bearerAuth' },
    { id: 'ep-4', origin: API_ORIGIN, method: 'POST', pathTemplate: '/api/v1/exports/:exportId/approve', riskScore: 92, authRequirement: 'role:admin' },
  ]
  const apiDependencies: CoordinatorApiDependency[] = [
    {
      producerEndpointId: 'ep-2',
      consumerEndpointId: 'ep-3',
      resourceKey: 'exportId',
      producerOrigin: APP_ORIGIN,
      consumerOrigin: API_ORIGIN,
    },
    {
      producerEndpointId: 'ep-3',
      consumerEndpointId: 'ep-4',
      resourceKey: 'exportId',
      producerOrigin: API_ORIGIN,
      consumerOrigin: API_ORIGIN,
    },
  ]

  // Even with ZERO pre-existing primitives and `!sourceMounted`, planChainRound must synthesize
  // multi-stage (depth >= 3) and cross-origin chain hypotheses!
  const directPlan = planChainRound({
    primitives: [],
    endpoints,
    apiDependencies,
    approvedOrigins: [IDP_ORIGIN, APP_ORIGIN, API_ORIGIN],
    sourceMounted: false,
    maxHops: 4,
    limit: 10,
  })
  assert.ok(directPlan.length >= 2, 'grey-box planChainRound must emit multi-hop hypotheses from apiDependencies & cross-origin endpoints')
  assert.ok(directPlan.some(h => h.hops >= 3), 'must synthesize >= 3-hop chain hypotheses in grey-box mode')
  assert.ok(directPlan.some(h => h.scope === 'cross_origin' && h.chainOrigins.length >= 2), 'must synthesize cross-origin chain hypotheses')

  // Also verify createGraphCoordinator forwards `deps.listApiDependencies()`.
  const coordinator = createGraphCoordinator({
    deps: {
      listEndpoints: () => endpoints,
      listFacts: () => [],
      listFindings: () => [],
      listApiDependencies: () => apiDependencies,
    },
    approvedOrigins: [IDP_ORIGIN, APP_ORIGIN, API_ORIGIN],
  })
  const facadePlan = coordinator.planChainRound({ sourceMounted: false, maxHops: 4, limit: 8 })
  assert.ok(facadePlan.length >= 2)
  assert.ok(facadePlan.some(h => h.scope === 'cross_origin'))
})

// ============================================================================
// 4. exec-dispatch.ts non-demotion & generic GB cross-origin composite Wave-1
// ============================================================================

test('isGenericWave1BoundaryChainStep and chainLaneDispatchRank preserve Rank 0 for dependency/cross-origin/persona-diff GB Wave-1 chains while still demoting bare stubs', () => {
  const bareStub: DispatchLaneStep = {
    id: 'bare-stub',
    seq: 1,
    priority: 96,
    title: 'Wave-1 chain · Cross-service boundary chain (downstream_service/http)',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=inv-1] [cap=cap:hop_synth:edge] Multi-hop invariant chain',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [APP_ORIGIN],
    trialIndex: 0,
  }
  const depBackedGbWave1: DispatchLaneStep = {
    id: 'gb-dep-wave1',
    seq: 2,
    priority: 92,
    title: 'Wave-1 chain · Entity lifecycle chain (order/http) · POST /api/v1/orders/:id/approve',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=hyp_dep_1] Producer POST /api/v1/orders -> Consumer POST /api/v1/orders/:id/approve. Preconditions: api_dependency:orderId.',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [API_ORIGIN],
    trialIndex: 0,
  }
  const crossOriginGbWave1: DispatchLaneStep = {
    id: 'gb-xorigin-wave1',
    seq: 3,
    priority: 91,
    title: 'Wave-1 chain · Cross-service boundary chain (export/http) · POST /api/v1/exports',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=3] [lane=chain] [inv_hyp=hyp_xo_1] Multi-hop invariant chain across origins.',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [APP_ORIGIN, API_ORIGIN],
    trialIndex: 0,
  }
  const personaDiffGbWave1: DispatchLaneStep = {
    id: 'gb-persona-diff-wave1',
    seq: 4,
    priority: 90,
    title: 'Wave-1 chain · Cross-surface policy chain (report/http) · POST /api/v1/reports/batch',
    category: 'broken-access-control',
    hypothesis: '[chain_hops=2] [lane=chain] [inv_hyp=hyp_rt_asym_1] Multi-hop invariant chain (grey-box runtime_surface_asymmetry): Persona "member_a" is denied (403) on http (GET /api/v1/reports/1) but succeeds (200) on http (POST /api/v1/reports/batch).',
    skills: ['multihop-chains', 'chain-primitives'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [API_ORIGIN],
    trialIndex: 0,
  }

  assert.equal(hasRuntimeBackedChainEvidence(bareStub), false)
  assert.equal(isGenericWave1BoundaryChainStep(bareStub), true)
  assert.equal(chainLaneDispatchRank(bareStub), 2)

  for (const step of [depBackedGbWave1, crossOriginGbWave1, personaDiffGbWave1]) {
    assert.equal(hasRuntimeBackedChainEvidence(step), true, `${step.id} must be recognized as runtime-backed`)
    assert.equal(isGenericWave1BoundaryChainStep(step), false, `${step.id} must NOT be demoted as a generic Wave-1 stub`)
    assert.equal(isHighSignalSourceOrPlannerChainStep(step), true, `${step.id} must qualify as high-signal chain`)
    assert.equal(chainLaneDispatchRank(step), 0, `${step.id} must receive Rank 0 dispatch priority`)
  }

  const plan = planRoundRobinDispatch([bareStub, personaDiffGbWave1, crossOriginGbWave1, depBackedGbWave1], 4)
  assert.equal(plan.ordered[3]!.id, 'bare-stub', 'bare heuristic stub must sort behind all runtime-backed GB Wave-1 chains')
})

test('synthesizeRuntimeCompositeWave1Steps builds up to 2 cross-origin composite Wave-1 workflows when !sourceMounted and skips when sourceMounted', async (t) => {
  const { storage } = makeStore(t)
  const { run } = await setupApprovedRun(storage, { seeds: [APP_ORIGIN, API_ORIGIN, IDP_ORIGIN], tier: 2 })
  const assetApp = run.candidates.find(c => c.origin === APP_ORIGIN)!
  const assetApi = run.candidates.find(c => c.origin === API_ORIGIN)!
  const worker = storage.makeWorker(run, 'threat_model', assetApp, 'Recon', 'Map', {
    sourceOrigins: [APP_ORIGIN, API_ORIGIN, IDP_ORIGIN],
  })

  const factSsrf = storage.addFact(run, worker, {
    kind: 'endpoint',
    origin: APP_ORIGIN,
    summary: 'Outbound render preview endpoint POST /api/v1/render/preview follows redirects to internal webhook signer.',
    data: { endpoint: '/api/v1/render/preview', method: 'POST' },
    sourceOrigins: [APP_ORIGIN],
  })
  const factWebhook = storage.addFact(run, worker, {
    kind: 'endpoint',
    origin: API_ORIGIN,
    summary: 'Webhook signing endpoint POST /api/v1/webhooks/sign generates HMAC signatures for billing callbacks.',
    data: { endpoint: '/api/v1/webhooks/sign', method: 'POST' },
    sourceOrigins: [API_ORIGIN],
  })
  const factInvite = storage.addFact(run, worker, {
    kind: 'auth',
    origin: IDP_ORIGIN,
    summary: 'Invite exchange POST /oauth/invite/accept mints cross-tenant session token.',
    data: { endpoint: '/oauth/invite/accept', method: 'POST' },
    sourceOrigins: [IDP_ORIGIN],
  })
  const factExport = storage.addFact(run, worker, {
    kind: 'endpoint',
    origin: assetApi.origin,
    summary: 'Async batch export POST /api/v1/billing/export mutates and exports tenant ledger.',
    data: { endpoint: '/api/v1/billing/export', method: 'POST' },
    sourceOrigins: [API_ORIGIN],
  })

  // When sourceMounted is true, runtime grey-box composite synthesis must stay a no-op (WB uses code-audit composites).
  const wbNoop = synthesizeRuntimeCompositeWave1Steps(storage, run, {
    sourceMounted: true,
    facts: [factSsrf, factWebhook, factInvite, factExport],
  })
  assert.equal(wbNoop.length, 0)

  const gbComposites = synthesizeRuntimeCompositeWave1Steps(storage, run, {
    sourceMounted: false,
    facts: [factSsrf, factWebhook, factInvite, factExport],
    apiDependencies: [
      {
        producer: 'POST /oauth/invite/accept',
        consumer: 'POST /api/v1/billing/export',
        resourceKey: 'sessionToken',
        producerOrigin: IDP_ORIGIN,
        consumerOrigin: API_ORIGIN,
      },
    ],
  })

  assert.equal(gbComposites.length, MAX_SYNTHESIZED_RUNTIME_COMPOSITE_STEPS)
  for (const step of gbComposites) {
    assert.ok(step.title.startsWith('Runtime composite chain ·'))
    assert.match(step.hypothesis, /Composite workflow \([3-5] stages\):/)
    assert.match(step.hypothesis, /Hop 1 \/ Stage 1/)
    assert.match(step.hypothesis, /ctx\.seal_capability/)
    assert.match(step.hypothesis, /ctx\.prove_composite/)
    assert.ok(step.sourceOrigins.length >= 2, 'synthesized GB composite must span >= 2 origins when available')
    assert.equal(isMultiHopChainStep(step), true)
    assert.equal(classifyDispatchLane(step), 'chain')
    assert.equal(isGenericWave1BoundaryChainStep(step), false)
    assert.equal(isHighSignalSourceOrPlannerChainStep(step), true)
    assert.equal(chainLaneDispatchRank(step), 0)
  }

  // Idempotency check: re-running must not duplicate existing composite titles.
  const secondRun = synthesizeRuntimeCompositeWave1Steps(storage, run, {
    sourceMounted: false,
    facts: [factSsrf, factWebhook, factInvite, factExport],
  })
  assert.equal(secondRun.length, 0)
})

// ============================================================================
// 5. Anti-Contamination Gate
// ============================================================================

test('src/server/ and src/skills/ contain zero v8 benchmark contamination tokens', () => {
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `unexpected contamination hits: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
