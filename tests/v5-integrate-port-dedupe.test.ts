/**
 * v5 integrate-port Slice 1: structural dedupe key `(origin, endpoint, method, param/resolver, cwe)`.
 *
 * The engine finds several vulnerabilities on one host. Dedupe must keep distinct attack surfaces
 * (routes, verbs, parameters, GraphQL resolvers) separate while still collapsing genuine
 * origin-wide classes (CORS/CSP/HSTS/TLS/cookies).
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import type { Finding } from '../src/domain.ts'
import { chainFindingDedupKey, deduplicateChainFindings } from '../src/report-summary.ts'
import {
  checkStructuralDuplicate,
  computeFindingFingerprint,
  evaluateSubmissionDedupe,
  extractGraphqlRootField,
  extractSpecDedupeFields,
} from '../src/server/dedupe.ts'
import type { DedupeCandidate, ExistingFindingRef } from '../src/server/dedupe.ts'
import { Store } from '../src/server/store.ts'
import { randomUUID } from 'node:crypto'

const origin = 'https://app.northstar.example'

function httpChainSpec(pathAndQuery: string, method = 'GET', jsonBody?: unknown) {
  return {
    kind: 'http_chain',
    origin,
    title: 'Object-level authorization',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    severityRationale: 'Cross-tenant read.',
    remediation: 'Enforce per-object ownership checks.',
    impact: 'Cross-tenant data exposure.',
    steps: [
      {
        id: 'c1', role: 'control', request: { method, pathAndQuery, persona: 'persona-a' },
      },
      {
        id: 'p1', role: 'probe', request: { method, pathAndQuery, persona: 'persona-b', ...(jsonBody ? { jsonBody } : {}) },
      },
    ],
  }
}

function gqlSpec(field: string) {
  return httpChainSpec('/graphql', 'POST', { query: `query { ${field}(id: "1") { id } }` })
}

function candidateFromSpec(spec: unknown): DedupeCandidate {
  return { origin, title: 'Object-level authorization', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', ...extractSpecDedupeFields(spec) }
}

function existingFromSpec(id: string, spec: unknown): ExistingFindingRef {
  const fields = extractSpecDedupeFields(spec)
  return {
    id,
    origin,
    title: 'Object-level authorization',
    status: 'confirmed',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    ...fields,
  }
}

describe('structural dedupe key', () => {
  test('fingerprint encodes origin, endpoint, method, parameter and CWE only', () => {
    const fp = computeFindingFingerprint({
      origin, cwe: 'CWE-639', endpoint: 'https://app.northstar.example/api/invoices/123', method: 'get', param: 'id',
      authState: 'persona:a', specKind: 'http_chain',
    })
    assert.equal(fp.normalizedEndpoint, '/api/invoices/:id')
    assert.equal(fp.key, `${origin}|/api/invoices/:id|GET|id|CWE-639`)
    const sameRootCauseOtherPersona = computeFindingFingerprint({
      origin, cwe: 'CWE-639', endpoint: '/api/invoices/999', method: 'GET', param: 'id',
      authState: 'persona:b', specKind: 'browser_chain',
    })
    assert.equal(sameRootCauseOtherPersona.hash, fp.hash)
  })

  test('two BOLA routes on one host stay distinct', async () => {
    const invoices = httpChainSpec('/api/invoices/1')
    const orders = httpChainSpec('/api/orders/1')
    const decision = await evaluateSubmissionDedupe({
      candidate: candidateFromSpec(orders),
      existingFindings: [existingFromSpec('f-invoices', invoices)],
    })
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.action, 'accept')
  })

  test('GET and DELETE on the same route stay distinct', async () => {
    const get = httpChainSpec('/api/invoices/1', 'GET')
    const del = httpChainSpec('/api/invoices/1', 'DELETE')
    const decision = await evaluateSubmissionDedupe({
      candidate: candidateFromSpec(del),
      existingFindings: [existingFromSpec('f-get', get)],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('two parameters on one route stay distinct', async () => {
    const byId = httpChainSpec('/api/invoices?id=1')
    const byOwner = httpChainSpec('/api/invoices?ownerId=2')
    assert.equal(extractSpecDedupeFields(byId).param, 'id')
    assert.equal(extractSpecDedupeFields(byOwner).param, 'ownerId')
    const decision = await evaluateSubmissionDedupe({
      candidate: candidateFromSpec(byOwner),
      existingFindings: [existingFromSpec('f-id', byId)],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('two GraphQL resolvers on POST /graphql stay distinct', async () => {
    const invoice = gqlSpec('invoice')
    const order = gqlSpec('order')
    assert.equal(extractSpecDedupeFields(invoice).graphqlField, 'invoice')
    assert.equal(extractGraphqlRootField('mutation UpdateOrder($x: ID) { updateOrder(id: $x) { id } }'), 'updateorder')
    const decision = await evaluateSubmissionDedupe({
      candidate: candidateFromSpec(order),
      existingFindings: [existingFromSpec('f-invoice', invoice)],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('the same endpoint and method is still a structural duplicate', async () => {
    const a = httpChainSpec('/api/invoices/1')
    const b = httpChainSpec('/api/invoices/2')
    const decision = await evaluateSubmissionDedupe({
      candidate: candidateFromSpec(b),
      existingFindings: [existingFromSpec('f-a', a)],
    })
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.action, 'reject_duplicate')
    assert.equal(decision.duplicateOfId, 'f-a')
  })

  test('cross-endpoint title similarity never merges non-origin-wide classes', async () => {
    const invoices = httpChainSpec('/api/invoices/1')
    const decision = await evaluateSubmissionDedupe({
      candidate: { ...candidateFromSpec(httpChainSpec('/api/orders/1')), title: 'Object-level authorization' },
      existingFindings: [existingFromSpec('f-invoices', invoices)],
    })
    assert.equal(decision.isDuplicate, false)
  })

  test('origin-wide CORS findings still collapse on the same host', async () => {
    const corsA = { kind: 'http_chain', origin, title: 'CORS reflection on /a', cwe: 'CWE-942', category: 'cors-client-side', severity: 'medium' }
    const corsB = { kind: 'http_chain', origin, title: 'CORS reflection on /b', cwe: 'CWE-942', category: 'cors-client-side', severity: 'low' }
    const decision = await evaluateSubmissionDedupe({
      candidate: candidateFromSpec(corsB),
      existingFindings: [existingFromSpec('f-cors', corsA)],
    })
    assert.equal(decision.isDuplicate, true)
  })
})

describe('store chain dedupe', () => {
  test('distinct fingerprints stay distinct rows; origin-wide classes still collapse', t => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-integrate-dedupe-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())

    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: 'dedupe', seeds: [origin], environment: 'public',
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(), projectId, goal: 'dedupe', sourceMode: 'public',
      capabilityTier: 2, budgetUsd: 1, budgetRequests: 10, maxRpsPerOrigin: 10, workerConcurrency: 1, workerMaxTurns: 5,
    })
    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const discovered = storage.run(runId)
    storage.command({
      requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0,
      assetIds: discovered.candidates.map(c => c.id), consent: true,
    })
    const run = storage.run(runId)
    const asset = run.candidates[0]

    const finding = (over: Partial<Finding>): Finding => ({
      id: randomUUID(),
      origin,
      title: 'Object-level authorization',
      status: 'confirmed',
      severity: 'high',
      reason: 'Cross-tenant read.',
      remediation: 'Check ownership.',
      evidenceIds: ['ev-1'],
      scopeRevision: 1,
      findingKind: 'multi_step_chain',
      cwe: 'CWE-639',
      category: 'broken-access-control',
      ...over,
    })

    const invoicesHash = computeFindingFingerprint({ origin, cwe: 'CWE-639', endpoint: '/api/invoices/1', method: 'GET', param: 'id' }).hash
    const ordersHash = computeFindingFingerprint({ origin, cwe: 'CWE-639', endpoint: '/api/orders/1', method: 'GET', param: 'id' }).hash
    const invoices = storage.upsertChainFinding(run, asset.id, finding({ fingerprintHash: invoicesHash }), 'spec-1', [origin])
    const orders = storage.upsertChainFinding(run, asset.id, finding({ fingerprintHash: ordersHash }), 'spec-2', [origin])
    assert.notEqual(orders.id, invoices.id, 'two BOLA routes must remain distinct rows')

    const corsHashA = computeFindingFingerprint({ origin, cwe: 'CWE-942', endpoint: '/a' }).hash
    const corsHashB = computeFindingFingerprint({ origin, cwe: 'CWE-942', endpoint: '/b' }).hash
    const corsA = storage.upsertChainFinding(run, asset.id, finding({
      fingerprintHash: corsHashA, cwe: 'CWE-942', category: 'cors-client-side', title: 'CORS on /a',
    }), 'spec-3', [origin])
    const corsB = storage.upsertChainFinding(run, asset.id, finding({
      fingerprintHash: corsHashB, cwe: 'CWE-942', category: 'cors-client-side', title: 'CORS on /b', status: 'pending',
    }), 'spec-4', [origin])
    assert.equal(corsB.id, corsA.id, 'origin-wide CORS findings collapse on one host')

    const chainRows = storage.runDetail(runId).findings.filter(f => f.findingKind === 'multi_step_chain')
    assert.equal(chainRows.length, 3)
  })
})

describe('report-level chain dedupe', () => {
  test('fingerprints separate routes; origin-wide classes collapse', () => {
    const base: Finding = {
      id: 'f1', origin, title: 'Object-level authorization', status: 'confirmed', severity: 'high',
      reason: 'r', remediation: 'r', evidenceIds: ['e'], scopeRevision: 1, findingKind: 'multi_step_chain', cwe: 'CWE-639',
    }
    const distinct = deduplicateChainFindings([
      { ...base, id: 'f1', fingerprintHash: 'hash-a' },
      { ...base, id: 'f2', fingerprintHash: 'hash-b' },
    ])
    assert.equal(distinct.length, 2)

    const corsA: Finding = { ...base, id: 'c1', cwe: 'CWE-942', title: 'CORS /a' }
    const corsB: Finding = { ...base, id: 'c2', cwe: 'CWE-942', title: 'CORS /b' }
    assert.equal(chainFindingDedupKey(corsA), chainFindingDedupKey(corsB))
    assert.equal(deduplicateChainFindings([corsA, corsB]).length, 1)
  })

  test('structural duplicate checks stay quiet for distinct verbs and resolvers', () => {
    const decision = checkStructuralDuplicate(
      { origin, title: 'BOLA', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/graphql', method: 'POST', graphqlField: 'order' },
      [{ id: 'x', origin, title: 'BOLA', status: 'confirmed', cwe: 'CWE-639', category: 'broken-access-control', severity: 'high', endpoint: '/graphql', method: 'POST', graphqlField: 'invoice' }],
    )
    assert.equal(decision.isDuplicate, false)
  })
})
