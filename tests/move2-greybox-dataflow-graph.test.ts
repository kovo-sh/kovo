/**
 * Move 2: Live Grey-Box Structural Signal Harvesting & Phase-0 Cross-Route API Dependencies.
 *
 * Fast class-level guard covering (Docker-free, real SQLite WAL `Store`, zero benchmark literals):
 *  1. Secret-free structural response signal harvesting in `resource-harvest.ts`
 *     (`await_async`, `hmac_sign`, `lifecycle_state`, `signed_url`) without ever leaking raw secret
 *     values, preserving `RESOURCE_SECRET_VALUE_RE`.
 *  2. Live HTTP JSON/header harvesting in `phase0-recon.ts`, synthesizing cross-route
 *     `produces -> consumes` edges across disjoint path prefixes plus `runtime_api_dependencies` facts.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
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

// ============================================================================
// 1. Secret-free structural signal extraction (`resource-harvest.ts`)
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
// 2. Phase-0 recon live JSON/header harvesting -> cross-route api_dependencies
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

  const extracted = {
    apiDependencies: facts
      .filter(f => f.origin === APP_ORIGIN && f.data?.subkind === 'runtime_api_dependencies' && Array.isArray(f.data?.apiDependencies))
      .flatMap(f => f.data!.apiDependencies as Array<{ producer: string; consumer: string; resourceKey: string }>),
  }
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
// 3. Anti-Contamination Gate
// ============================================================================

test('src/server/ and src/skills/ remain 100% free of benchmark contamination literals', () => {
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `unexpected contamination hits: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
