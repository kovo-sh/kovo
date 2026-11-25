/**
 * v5 surface-filter invariants (parity fix #1, execution.ts half).
 *
 * The deterministic `--no-llm` lane must not discard real write endpoints that the
 * briefing/OpenAPI reference declares without a path parameter:
 *   - body-only write routes (`POST /api/refunds/lines`) keep their declared method;
 *   - DELETE/PUT/PATCH routes are derived when the reference declares them;
 *   - paramless GET routes still need an injectable/id to be worth a probe;
 *   - routes that already exist in the stored surface are not duplicated.
 *
 * Nothing here is app-specific: the fixtures are generic route shapes.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'

import { Execution } from '../src/server/execution.ts'
import { Store } from '../src/server/store.ts'
import type { Run } from '../src/server/store.ts'
import { makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:9'

interface DerivedTarget {
  origin: string
  method: string
  pathTemplate: string
  riskScore: number
  params: Array<{ name: string; location: string }>
}

type SurfaceInternals = {
  deriveDeterministicRouteTargets: (
    run: Run,
    approvedOrigins: ReadonlySet<string>,
    existing: ReadonlyArray<{ origin: string; method: string; pathTemplate: string }>,
  ) => DerivedTarget[]
  runEngineInvestigation: (run: Run) => Promise<void>
}

function internals(execution: Execution): SurfaceInternals {
  return execution as unknown as SurfaceInternals
}

function importSpec(storage: Store, projectId: string, content: string) {
  storage.importProjectSpec({
    requestId: randomUUID(),
    projectId,
    name: 'surface-filter-api.json',
    kind: 'openapi',
    origin,
    content,
  })
}

function derive(
  execution: Execution,
  run: Run,
  existing: Array<{ origin: string; method: string; pathTemplate: string }> = [],
): DerivedTarget[] {
  return internals(execution).deriveDeterministicRouteTargets(run, new Set([origin]), existing)
}

const methodPath = (target: DerivedTarget) => `${target.method} ${target.pathTemplate}`

test('derives body-only write routes with their declared method instead of dropping them', async (t) => {
  const { storage } = makeStore(t)
  const { runId, projectId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  importSpec(storage, projectId, JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/api/admin/impersonate': { post: { parameters: [] } },
      '/api/refunds/lines': { post: { parameters: [] } },
      '/api/reports/export': { put: { parameters: [] }, patch: { parameters: [] } },
      '/api/admin/people/{personId}': { delete: { parameters: [] } },
      '/api/health': { get: { parameters: [] } },
    },
  }))

  const execution = new Execution(storage, { deterministicOnly: true })
  const targets = derive(execution, storage.run(runId))
  const keys = new Set(targets.map(methodPath))

  assert.ok(keys.has('POST /api/admin/impersonate'), 'body-only privileged write must reach the engine')
  assert.ok(keys.has('POST /api/refunds/lines'), 'body-only collection write must reach the engine')
  assert.ok(keys.has('PUT /api/reports/export'), 'declared PUT without params must be derived')
  assert.ok(keys.has('PATCH /api/reports/export'), 'declared PATCH without params must be derived')
  assert.ok(keys.has('DELETE /api/admin/people/{personId}'), 'declared DELETE must be derived')
  assert.equal(keys.has('GET /api/health'), false, 'a paramless GET is still not worth a probe')

  const post = targets.find(target => methodPath(target) === 'POST /api/refunds/lines')
  assert.equal(post?.method, 'POST', 'the declared method is preserved (never coerced to GET)')
})

test('keeps write routes without a trailing id but drops paramless reads', async (t) => {
  const { storage } = makeStore(t)
  const { runId, projectId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  importSpec(storage, projectId, JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/api/jobs/run': { post: { parameters: [] } },
      '/api/status': { get: { parameters: [] } },
      '/api/search': { get: { parameters: [{ name: 'q', in: 'query' }] } },
    },
  }))

  const execution = new Execution(storage, { deterministicOnly: true })
  const targets = derive(execution, storage.run(runId))
  const keys = new Set(targets.map(methodPath))

  assert.ok(keys.has('POST /api/jobs/run'))
  assert.ok(keys.has('GET /api/search'), 'an injectable GET keeps working')
  assert.equal(keys.has('GET /api/status'), false)
})

test('does not duplicate endpoints that already exist in the stored surface', async (t) => {
  const { storage } = makeStore(t)
  const { runId, projectId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  importSpec(storage, projectId, JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/api/admin/impersonate': { post: { parameters: [] } },
      '/api/admin/people/{personId}': { delete: { parameters: [] } },
    },
  }))

  const execution = new Execution(storage, { deterministicOnly: true })
  const targets = derive(execution, storage.run(runId), [
    { origin, method: 'POST', pathTemplate: '/api/admin/impersonate' },
    { origin, method: 'DELETE', pathTemplate: '/api/admin/people/{personId}' },
  ])

  assert.equal(targets.filter(target => methodPath(target) === 'POST /api/admin/impersonate').length, 0)
  assert.equal(targets.filter(target => methodPath(target) === 'DELETE /api/admin/people/{personId}').length, 0)
})

test('tolerant parser accepts method + path without params or a trailing id', async (t) => {
  const { storage } = makeStore(t)
  const { runId, projectId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  // Truncated/redacted reference: JSON.parse fails, so the textual fallback handles it.
  importSpec(storage, projectId, [
    '{"openapi":"3.1.0","paths":{',
    '"/api/admin/impersonate":{"post":{"parameters":[]}},',
    '"/api/refunds/lines":{"post":{"parameters":[]}},',
    '"/api/admin/people/{personId}":{"delete":{"parameters":[]}},',
    '"/api/health":{"get":{"parameters":[]}}',
    '}}<truncated',
  ].join(''))

  const execution = new Execution(storage, { deterministicOnly: true })
  const targets = derive(execution, storage.run(runId))
  const keys = new Set(targets.map(methodPath))

  assert.ok(keys.has('POST /api/admin/impersonate'))
  assert.ok(keys.has('POST /api/refunds/lines'))
  assert.ok(keys.has('DELETE /api/admin/people/{personId}'))
  assert.equal(keys.has('GET /api/health'), false)
})

test('stored DELETE routes reach the engine surface instead of being filtered out', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 100 })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  storage.upsertEndpoint({
    runId, origin, method: 'DELETE', pathTemplate: '/api/admin/people/:personId', source: 'surface_probe', riskScore: 90,
  })
  storage.upsertEndpoint({
    runId, origin, method: 'GET', pathTemplate: '/api/invoices', source: 'surface_probe', riskScore: 70,
  })

  const execution = new Execution(storage, { deterministicOnly: true })
  await withEnv({ KOVO_DETERMINISTIC_ENGINE: '0' }, () =>
    internals(execution).runEngineInvestigation(storage.run(runId)),
  )

  const started = storage.eventsAfter(runId, 0).find(event => event.kind === 'deterministic_engine.started')
  assert.ok(started, 'the engine surface must be assembled before the disabled engine returns')
  assert.equal(started!.detail?.stored, 2, 'the DELETE route is part of the stored write surface')
})
