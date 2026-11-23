/**
 * v6 Phase 1: accurate dedupe keyed on the **explicitly mutated input** + verified handler.
 *
 * v5 keyed findings on `Object.keys(jsonBody)[0]`, so a proof that mutated `ownerId` could collide
 * with a different proof that mutated `id`, and reverse-proxy front paths collapsed findings that
 * resolve to different microservice handlers. The v6 key is
 *
 *   (origin, endpoint, method, mutated.kind+name, cwe)   [endpoint includes the verified handler]
 *
 * with the deprecated first-key heuristic kept only as a fallback when a finding carries no
 * explicit mutation.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import {
  checkStructuralDuplicate,
  computeFindingFingerprint,
  evaluateSubmissionDedupe,
  extractSpecDedupeFields,
  normalizeHandlerRef,
  normalizeMutatedInput,
} from '../src/server/dedupe.ts'
import type { DedupeCandidate, ExistingFindingRef, MutatedInput } from '../src/server/dedupe.ts'

const origin = 'https://app.northstar.example'

function candidate(over: Partial<DedupeCandidate>): DedupeCandidate {
  return {
    origin,
    title: 'Injection finding',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    ...over,
  }
}

function existing(id: string, over: Partial<ExistingFindingRef>): ExistingFindingRef {
  return {
    id,
    origin,
    title: 'Injection finding',
    status: 'confirmed',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    ...over,
  }
}

function mutation(kind: MutatedInput['kind'], name: string, location?: string): MutatedInput {
  return location ? { kind, name, location } : { kind, name }
}

describe('mutated-input structural key', () => {
  test('key encodes origin, endpoint, method, mutation kind+name and CWE', () => {
    const fp = computeFindingFingerprint({
      origin,
      cwe: 'CWE-639',
      endpoint: '/api/invoices/123',
      method: 'get',
      mutated: mutation('param', 'ownerId', 'query'),
    })
    assert.equal(fp.normalizedEndpoint, '/api/invoices/:id')
    assert.equal(fp.key, `${origin}|/api/invoices/:id|GET|mutated:param:ownerid|CWE-639`)
    assert.equal(fp.mutatedSource, 'explicit')
    assert.deepEqual(fp.mutated, { kind: 'param', name: 'ownerid', location: 'query' })
  })

  test('same mutation is the same fingerprint across personas/spec kinds', () => {
    const a = computeFindingFingerprint({
      origin, cwe: 'CWE-89', endpoint: '/search', method: 'GET', mutated: mutation('param', 'q'),
      authState: 'persona:a', specKind: 'sql_boolean_diff',
    })
    const b = computeFindingFingerprint({
      origin, cwe: 'CWE-89', endpoint: '/search', method: 'GET', mutated: mutation('param', 'q'),
      authState: 'persona:b', specKind: 'browser_chain',
    })
    assert.equal(a.hash, b.hash)
  })

  test('two parameters on one endpoint stay distinct', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: candidate({ endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'ownerId') }),
      existingFindings: [existing('f-id', { endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'id') })],
    })
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.action, 'accept')
  })

  test('the same parameter on different endpoints stays distinct', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: candidate({ endpoint: '/api/orders/1', method: 'GET', mutated: mutation('param', 'id') }),
      existingFindings: [existing('f-invoices', { endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'id') })],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('a header mutation never merges with a body parameter of the same name', async () => {
    const header = mutation('header', 'x-tenant-id')
    const bodyParam = mutation('param', 'x-tenant-id', 'json')
    const headerFp = computeFindingFingerprint({ origin, cwe: 'CWE-639', endpoint: '/api/me', method: 'GET', mutated: header })
    const paramFp = computeFindingFingerprint({ origin, cwe: 'CWE-639', endpoint: '/api/me', method: 'GET', mutated: bodyParam })
    assert.notEqual(headerFp.hash, paramFp.hash)

    const decision = await evaluateSubmissionDedupe({
      candidate: candidate({ endpoint: '/api/me', method: 'GET', mutated: header }),
      existingFindings: [existing('f-param', { endpoint: '/api/me', method: 'GET', mutated: bodyParam })],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('two GraphQL operations on POST /graphql stay distinct', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: candidate({ endpoint: '/graphql', method: 'POST', mutated: mutation('graphql', 'updateOrder') }),
      existingFindings: [existing('f-invoice', { endpoint: '/graphql', method: 'POST', mutated: mutation('graphql', 'invoice') })],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('two RPC procedures on one endpoint stay distinct', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: candidate({ endpoint: '/rpc', method: 'POST', mutated: mutation('rpc', 'admin.deleteUser') }),
      existingFindings: [existing('f-get', { endpoint: '/rpc', method: 'POST', mutated: mutation('rpc', 'user.get') })],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('an identical mutation still dedupes structurally', () => {
    const decision = checkStructuralDuplicate(
      candidate({ endpoint: '/rpc', method: 'POST', mutated: mutation('rpc', 'user.get') }),
      [existing('f-rpc', { endpoint: '/rpc', method: 'POST', mutated: mutation('rpc', 'user.get') })],
    )
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.duplicateOfId, 'f-rpc')
    assert.equal(decision.fingerprint.mutatedSource, 'explicit')
  })
})

describe('verified handler identity (reverse proxy)', () => {
  test('different handlers behind one public path stay distinct', () => {
    const front = candidate({ endpoint: '/api/orders/1', method: 'GET', handler: '/svc-orders/orders/:id', mutated: mutation('param', 'id') })
    const other = existing('f-billing', { endpoint: '/api/orders/1', method: 'GET', handler: '/svc-billing/orders/:id', mutated: mutation('param', 'id') })
    const decision = checkStructuralDuplicate(front, [other])
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.fingerprint.handler, '/svc-orders/orders/:id')
  })

  test('a handler difference also blocks the semantic fallback', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: candidate({ endpoint: '/api/orders/1', method: 'GET', handler: '/svc-orders/orders/:id' }),
      existingFindings: [existing('f-billing', { endpoint: '/api/orders/1', method: 'GET', verifiedEndpoint: 'GET https://app.northstar.example/svc-billing/orders/:id' })],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('the same handler and mutation dedupes', () => {
    const decision = checkStructuralDuplicate(
      candidate({ endpoint: '/api/orders/1', method: 'GET', handler: '/svc-orders/orders/:id', mutated: mutation('param', 'id') }),
      [existing('f-orders', { endpoint: '/api/orders/999', method: 'GET', handler: '/svc-orders/orders/:id', mutated: mutation('param', 'id') })],
    )
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.duplicateOfId, 'f-orders')
  })

  test('handler normalization accepts bare paths, URLs and METHOD-prefixed refs', () => {
    assert.equal(normalizeHandlerRef('/svc-orders/Orders/1'), '/svc-orders/orders/:id')
    assert.equal(normalizeHandlerRef('https://app.northstar.example/svc-orders/orders/1'), '/svc-orders/orders/:id')
    assert.equal(normalizeHandlerRef('GET /svc-orders/orders/1'), '/svc-orders/orders/:id')
    assert.equal(normalizeHandlerRef(''), '')
  })
})

describe('deprecated first-key fallback', () => {
  test('legacy keys are byte-identical when no mutation is present', () => {
    const fp = computeFindingFingerprint({
      origin, cwe: 'CWE-639', endpoint: 'https://app.northstar.example/api/invoices/123', method: 'get', param: 'id',
      authState: 'persona:a', specKind: 'http_chain',
    })
    assert.equal(fp.key, `${origin}|/api/invoices/:id|GET|id|CWE-639`)
    assert.equal(fp.mutatedSource, 'legacy')
    assert.equal(fp.mutated, null)

    const gql = computeFindingFingerprint({ origin, cwe: 'CWE-639', endpoint: '/graphql', method: 'POST', graphqlField: 'Invoice' })
    assert.equal(gql.key, `${origin}|/graphql|POST|gql:invoice|CWE-639`)
  })

  test('http_chain specs without an explicit mutation keep the first-key heuristic', () => {
    const fields = extractSpecDedupeFields({
      kind: 'http_chain',
      steps: [{ role: 'probe', request: { method: 'POST', pathAndQuery: '/api/prefs', persona: 'p', jsonBody: { theme: 'dark', locale: 'en' } } }],
    })
    assert.equal(fields.mutated, undefined)
    assert.equal(fields.param, 'theme')
  })

  test('a v5 finding without mutated data still matches the same explicit mutation', () => {
    const decision = checkStructuralDuplicate(
      candidate({ endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'id') }),
      [existing('f-v5', { endpoint: '/api/invoices/1', method: 'GET', param: 'id' })],
    )
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.duplicateOfId, 'f-v5')
  })

  test('a stored legacy fingerprintHash still matches a formerly-written finding', () => {
    const legacyHash = computeFindingFingerprint({
      origin, cwe: 'CWE-639', endpoint: '/api/invoices/1', method: 'GET', param: 'id',
    }).hash
    const decision = checkStructuralDuplicate(
      candidate({ endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'id') }),
      [existing('f-stored', { endpoint: '/api/invoices/1', method: 'GET', fingerprintHash: legacyHash })],
    )
    assert.equal(decision.isDuplicate, true)
  })

  test('a header mutation never falls back onto a legacy first-key collision', () => {
    const decision = checkStructuralDuplicate(
      candidate({ endpoint: '/api/prefs', method: 'POST', mutated: mutation('header', 'x-tenant') }),
      [existing('f-v5', { endpoint: '/api/prefs', method: 'POST', param: 'x-tenant' })],
    )
    assert.equal(decision.isDuplicate, false)
  })

  test('a colliding stored legacy hash never merges two different explicit mutations', () => {
    const collision = computeFindingFingerprint({
      origin, cwe: 'CWE-639', endpoint: '/api/invoices/1', method: 'GET', param: 'id',
    }).hash
    const decision = checkStructuralDuplicate(
      candidate({ endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'id'), fingerprintHash: collision }),
      [existing('f-owner', { endpoint: '/api/invoices/1', method: 'GET', mutated: mutation('param', 'ownerId'), fingerprintHash: collision })],
    )
    assert.equal(decision.isDuplicate, false)
  })
})

describe('spec-declared mutations', () => {
  test('sql specs declare param, header and graphql-var mutations', () => {
    const body = extractSpecDedupeFields({
      kind: 'sql_boolean_diff', targetOrigin: origin, method: 'POST', pathAndQuery: '/api/search', paramName: 'filter.name', paramLocation: 'json',
    })
    assert.deepEqual(body.mutated, { kind: 'param', name: 'filter.name', location: 'json' })

    const header = extractSpecDedupeFields({
      kind: 'sql_time_diff', targetOrigin: origin, method: 'GET', pathAndQuery: '/api/search', paramName: 'X-Filter', paramLocation: 'header',
    })
    assert.deepEqual(header.mutated, { kind: 'header', name: 'X-Filter', location: 'header' })

    const gqlVar = extractSpecDedupeFields({
      kind: 'sql_boolean_diff', targetOrigin: origin, method: 'POST', pathAndQuery: '/graphql', paramName: 'id', paramLocation: 'graphql_var',
    })
    assert.deepEqual(gqlVar.mutated, { kind: 'graphql', name: 'id', location: 'graphql_var' })
  })

  test('graphql, cache and upload specs declare their mutated input', () => {
    const gql = extractSpecDedupeFields({
      kind: 'http_chain',
      steps: [{ role: 'probe', request: { method: 'POST', pathAndQuery: '/graphql', persona: 'p', jsonBody: { query: 'query Order($id: ID) { order(id: $id) { id } }' } } }],
    })
    assert.deepEqual(gql.mutated, { kind: 'graphql', name: 'order' })

    const cache = extractSpecDedupeFields({
      kind: 'cache_differential', probePath: '/api/page', method: 'GET', poisonHeaders: { 'X-Forwarded-Host': 'evil.example' },
    })
    assert.deepEqual(cache.mutated, { kind: 'header', name: 'x-forwarded-host', location: 'header' })

    const upload = extractSpecDedupeFields({
      kind: 'upload_probe', uploadRequest: { pathAndQuery: '/api/upload', method: 'POST', fieldName: 'avatar' },
    })
    assert.deepEqual(upload.mutated, { kind: 'param', name: 'avatar', location: 'form' })
  })

  test('two sql params on one endpoint stay distinct', async () => {
    const byName = extractSpecDedupeFields({
      kind: 'sql_boolean_diff', targetOrigin: origin, method: 'GET', pathAndQuery: '/api/search', paramName: 'authorName', paramLocation: 'query',
    })
    const byTag = extractSpecDedupeFields({
      kind: 'sql_boolean_diff', targetOrigin: origin, method: 'GET', pathAndQuery: '/api/search', paramName: 'tag', paramLocation: 'query',
    })
    const decision = await evaluateSubmissionDedupe({
      candidate: { ...candidate({ cwe: 'CWE-89', category: 'injection' }), ...byTag },
      existingFindings: [{ ...existing('f-name', { cwe: 'CWE-89', category: 'injection' }), ...byName }],
    })
    assert.equal(decision.isDuplicate, false)
  })
})

describe('origin-wide classes keep collapsing', () => {
  test('CORS reflections on different paths still collapse per host', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: { origin, title: 'CORS on /b', cwe: 'CWE-942', category: 'cors-client-side', severity: 'low', endpoint: '/b' },
      existingFindings: [{ id: 'f-cors', origin, title: 'CORS on /a', status: 'confirmed', cwe: 'CWE-942', category: 'cors-client-side', severity: 'medium', endpoint: '/a' }],
    })
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.duplicateOfId, 'f-cors')
  })

  test('origin-wide collapse ignores handler differences by design', async () => {
    const decision = await evaluateSubmissionDedupe({
      candidate: { origin, title: 'CORS on /b', cwe: 'CWE-942', category: 'cors-client-side', severity: 'low', endpoint: '/b', handler: '/svc-b' },
      existingFindings: [{ id: 'f-cors', origin, title: 'CORS on /a', status: 'confirmed', cwe: 'CWE-942', category: 'cors-client-side', severity: 'medium', endpoint: '/a', handler: '/svc-a' }],
    })
    assert.equal(decision.isDuplicate, true)
  })
})

describe('mutated input normalization', () => {
  test('rejects empty/unknown mutations and lowercases case-insensitive kinds', () => {
    assert.equal(normalizeMutatedInput(null), null)
    assert.equal(normalizeMutatedInput({ kind: 'param', name: '  ' }), null)
    assert.deepEqual(normalizeMutatedInput({ kind: 'header', name: 'X-Tenant-Id' }), { kind: 'header', name: 'x-tenant-id' })
    assert.deepEqual(normalizeMutatedInput({ kind: 'rpc', name: 'Admin.GetUser' }), { kind: 'rpc', name: 'Admin.GetUser' })
  })
})
