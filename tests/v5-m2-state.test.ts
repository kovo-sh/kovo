import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { ResourceSampleRow } from '../src/server/store.ts'
import {
  buildBolaTestQueue,
  extractPersonaResourcesFromExchange,
  instantiateConsumerEndpoints,
} from '../src/server/execution.ts'
import { extractResourceRefsFromExchange, isOpaqueResourceId } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const origin = 'https://app.example.test'

function refsFor(pathAndQuery: string, body = '', extra: Partial<{
  mediaType: string
  status: number
  personaHandle: string | null
  respHeaders: Record<string, string>
}> = {}) {
  return extractResourceRefsFromExchange({
    origin,
    method: 'GET',
    pathAndQuery,
    status: extra.status ?? 200,
    mediaType: extra.mediaType ?? 'application/json',
    body,
    ...(extra.personaHandle !== undefined ? { personaHandle: extra.personaHandle } : {}),
    ...(extra.respHeaders ? { respHeaders: extra.respHeaders } : {}),
  })
}

test('resource extractor recognizes every modern opaque-ID shape', () => {
  const shapes: Array<[string, string]> = [
    ['/api/orders/7', '7'],
    ['/api/orders/507f1f77bcf86cd799439011', '507f1f77bcf86cd799439011'],
    ['/api/orders/01ARZ3NDEKTSV4RRFFQ69G5FAV', '01ARZ3NDEKTSV4RRFFQ69G5FAV'],
    ['/api/orders/V1StGXR8_Z5jdHi6B-myT', 'V1StGXR8_Z5jdHi6B-myT'],
    ['/api/orders/k9J2mQ', 'k9J2mQ'],
    ['/api/orders/4f8f6e7a-6f0b-4d2f-8a5a-7c4b1b2c3d4e', '4f8f6e7a-6f0b-4d2f-8a5a-7c4b1b2c3d4e'],
  ]
  for (const [path, id] of shapes) {
    const refs = refsFor(path)
    assert.ok(refs.some(ref => ref.resourceId === id), `Expected ${id} from ${path}: ${JSON.stringify(refs)}`)
    assert.ok(isOpaqueResourceId(id), `Expected ${id} to classify as an opaque id`)
  }
})

test('resource extractor follows HTML anchors and Location headers on 201/302', () => {
  const html = refsFor('/dashboard', '<html><a href="/api/invoices/42">Invoice</a><a href="https://evil.invalid/x/9">x</a></html>', {
    mediaType: 'text/html',
  })
  assert.ok(html.some(ref => ref.resourceId === '42' && ref.field === 'href:invoices'))

  const created = refsFor('/api/orders', '', {
    status: 201,
    respHeaders: { Location: '/api/shipments/77' },
  })
  assert.ok(created.some(ref => ref.resourceId === '77' && ref.field === 'location:shipments'))

  const redirected = refsFor('/api/orders', '', {
    status: 302,
    respHeaders: { location: `${origin}/api/shipments/88` },
  })
  assert.ok(redirected.some(ref => ref.resourceId === '88' && ref.field === 'location:shipments'))
})

test('resource extractor walks arbitrary GraphQL response depths', () => {
  const deep = { data: { viewer: { orgs: [{ teams: [{ projects: [{ invoices: [{ invoiceId: 'inv_deep_01' }] }] }] }] } } }
  const refs = refsFor('/graphql', JSON.stringify(deep), { personaHandle: 'user_a' })
  assert.ok(refs.some(ref => ref.resourceId === 'inv_deep_01' && ref.field === 'invoiceId'))
})

test('unauthenticated JSON and HTML responses still yield harvestable IDs', () => {
  const jsonRefs = extractPersonaResourcesFromExchange({
    origin,
    method: 'GET',
    pathAndQuery: '/api/public/orders/9',
    status: 200,
    mediaType: 'application/json',
    body: JSON.stringify({ id: 9, orderId: 'ord_public_1' }),
  })
  assert.ok(jsonRefs.some(ref => ref.resourceId === '9'))
  assert.ok(jsonRefs.some(ref => ref.resourceId === 'ord_public_1'))

  const htmlRefs = extractResourceRefsFromExchange({
    origin,
    method: 'GET',
    pathAndQuery: '/public',
    status: 200,
    mediaType: 'text/html',
    body: '<a href="/api/receipts/RCPT_123">receipt</a>',
  })
  assert.ok(htmlRefs.some(ref => ref.resourceId === 'RCPT_123'))
})

test('credential-shaped values are never harvested or persisted raw', async t => {
  const secret = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart'
  const refs = extractResourceRefsFromExchange({
    origin,
    method: 'GET',
    pathAndQuery: '/api/me',
    status: 200,
    mediaType: 'application/json',
    body: JSON.stringify({ accessTokenId: secret, sessionId: 'another-secret-token-value' }),
  })
  assert.ok(!refs.some(ref => ref.resourceId === secret))

  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage)
  const sample = storage.recordResourceSample({
    runId,
    ownerPersona: 'user_a',
    resourceKey: 'apiKeyId',
    resourceId: 'sk-or-v1-0123456789abcdef0123456789abcdef',
    origin,
    endpoint: '/api/me',
    method: 'GET',
  })
  assert.equal(sample?.resourceId, '[redacted]')
  assert.ok(!JSON.stringify(storage.listResourceSamples(runId)).includes('sk-or-v1-0123456789abcdef'))
})

test('noteEndpointProbe drives real coveragePct from distinct tested classes', async t => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage)
  const ep = storage.upsertEndpoint({
    runId, scopeRevision: 1, origin, method: 'GET', pathTemplate: '/api/invoices/:id', source: 'spa_crawl', coveragePct: 0,
  })
  const first = storage.noteEndpointProbe({
    runId, scopeRevision: 1, origin, method: 'GET', pathAndQuery: '/api/invoices/42', testedClass: 'diff:authz_matrix',
  })
  assert.equal(first?.id, ep.id)
  assert.equal(first?.coveragePct, 25)
  assert.deepEqual(first?.testedClasses, ['diff:authz_matrix'])

  const second = storage.noteEndpointProbe({
    runId, scopeRevision: 1, origin, method: 'GET', pathAndQuery: '/api/invoices/43', testedClass: 'replay:http_chain',
  })
  assert.equal(second?.coveragePct, 50)
  assert.deepEqual(new Set(second?.testedClasses), new Set(['diff:authz_matrix', 'replay:http_chain']))

  const repeat = storage.noteEndpointProbe({
    runId, scopeRevision: 1, origin, method: 'GET', pathAndQuery: '/api/invoices/44', testedClass: 'diff:authz_matrix',
  })
  assert.equal(repeat?.coveragePct, 50, 'Re-testing the same class must not inflate coverage')

  const rows = storage.listEndpoints(runId, { origin })
  assert.equal(rows.length, 1, 'Concrete ids must normalize onto one route template')
})

test('trackExchangeResources persists redacted samples and producer→consumer edges', async t => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, {
    seeds: [origin],
    personas: [{ handle: 'user_a', roleLabel: 'A', authKind: 'bearer', secret: 'test-token-value-123' }],
  })
  storage.upsertEndpoint({
    runId, scopeRevision: 1, origin, method: 'GET', pathTemplate: '/api/orders/:id', source: 'spa_crawl',
  })
  const refs = storage.trackExchangeResources({
    runId,
    scopeRevision: 1,
    exchange: {
      origin,
      method: 'POST',
      pathAndQuery: '/api/orders',
      personaHandle: 'user_a',
      status: 201,
      mediaType: 'application/json',
      body: JSON.stringify({ orderId: 'ord_9911' }),
      respHeaders: { Location: `/api/orders/ord_9911` },
    },
    source: 'surface_probe',
  })
  assert.ok(refs.some(ref => ref.resourceId === 'ord_9911'))
  const samples = storage.listResourceSamples(runId)
  assert.ok(samples.some(sample => sample.ownerPersona === 'user_a' && sample.resourceKey === 'orderId' && sample.resourceId === 'ord_9911'))
  const deps = storage.listApiDependencies(runId)
  assert.ok(deps.some(dep => dep.resourceKey === 'orderId' && dep.sampleResourceIdHash?.startsWith('sha256:')))
  assert.ok(!deps.some(dep => dep.sampleResourceIdHash === 'ord_9911'), 'Raw ids never enter api_dependencies')
})

function sample(overrides: Partial<ResourceSampleRow>): ResourceSampleRow {
  const now = Date.now()
  return {
    id: `sample-${Math.random().toString(16).slice(2)}`,
    runId: 'run-1',
    ownerPersona: 'user_a',
    resourceKey: 'invoiceId',
    resourceId: '42',
    origin,
    endpoint: '/api/invoices/42',
    method: 'GET',
    mediaType: 'application/json',
    authenticated: true,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  }
}

test('BOLA queue instantiates bounded GET/PUT/PATCH/DELETE consumer item endpoints', () => {
  const personas = [
    { handle: 'user_a', originAllowlist: [origin] },
    { handle: 'user_b', originAllowlist: [origin] },
  ]
  const queue = buildBolaTestQueue([], personas, new Set([origin]), [
    sample({}),
    sample({ resourceKey: 'projectId', resourceId: 'proj_abc', endpoint: '/api/projects' }),
  ])
  assert.equal(queue.length, 2)
  const invoice = queue.find(item => item.resourceKey === 'invoiceId')
  assert.ok(invoice)
  assert.deepEqual(invoice.testAsPersonas, ['user_b', 'anonymous'])
  assert.deepEqual(new Set(invoice.variants.map(v => v.method)), new Set(['GET', 'PUT', 'PATCH', 'DELETE']))
  assert.equal(invoice.variants.find(v => v.method === 'GET')?.endpoint, '/api/invoices/42')
  assert.equal(invoice.variants.find(v => v.method === 'DELETE')?.destructive, true)
  assert.equal(invoice.variants.find(v => v.method === 'DELETE')?.requiresTier, 3)

  const project = queue.find(item => item.resourceKey === 'projectId')
  assert.ok(project)
  assert.equal(project.variants.find(v => v.method === 'GET')?.endpoint, '/api/projects/proj_abc')
  assert.equal(instantiateConsumerEndpoints('/api/orders/:id', '9')[0]?.endpoint, '/api/orders/9')
})

test('BOLA queue keeps a bounded per-resource-type budget', () => {
  const personas = [
    { handle: 'user_a', originAllowlist: [origin] },
    { handle: 'user_b', originAllowlist: [origin] },
  ]
  const samples = Array.from({ length: 14 }, (_v, idx) => sample({
    resourceKey: 'invoiceId',
    resourceId: String(idx + 1),
    endpoint: `/api/invoices/${idx + 1}`,
  }))
  const queue = buildBolaTestQueue([], personas, new Set([origin]), samples)
  assert.equal(queue.length, 8, 'Per-type budget caps runaway item loops')
})

test('anonymous-owned leaked IDs can be replayed by authenticated personas', () => {
  const personas = [
    { handle: 'user_a', originAllowlist: [origin] },
    { handle: 'user_b', originAllowlist: [origin] },
  ]
  const queue = buildBolaTestQueue([], personas, new Set([origin]), [
    sample({ ownerPersona: 'anonymous', authenticated: false }),
  ])
  assert.equal(queue.length, 1)
  assert.deepEqual(new Set(queue[0]?.testAsPersonas), new Set(['user_a', 'user_b']))
  assert.equal(queue[0]?.variants.length, 4)
})
