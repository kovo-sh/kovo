/**
 * R2-10: Deterministic veto on LLM semantic dedupe + single browser-safe `src/finding-keys.ts`.
 *
 * Ensures an LLM semantic dedupe judge returning `isDuplicate: true` can NEVER drop a distinct
 * finding before verification when `sameFindingPredicate(candidate, existing)` rejects the merge
 * (distinct route template, HTTP method, parameter name, GraphQL field, mutation class, input
 * location, verified handler, or origin).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, test } from 'node:test'

import { ORIGIN_WIDE_CWE_KEYS, isOriginWideCwe, normalizeCwe } from '../src/finding-keys.ts'
import * as reportSummary from '../src/report-summary.ts'
import * as dedupe from '../src/server/dedupe.ts'
import {
  evaluateSubmissionDedupe,
  judgeSemanticDuplicate,
  sameFindingPredicate,
} from '../src/server/dedupe.ts'
import type { DedupeCandidate, ExistingFindingRef, MutatedInput, SemanticDedupeLlmCall } from '../src/server/dedupe.ts'
import * as findingFingerprint from '../src/server/finding-fingerprint.ts'

const origin = 'https://app.northstar.example'

function bolaCandidate(over: Partial<DedupeCandidate>): DedupeCandidate {
  return {
    origin,
    title: 'Cross-tenant object access',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    method: 'GET',
    ...over,
  }
}

function bolaExisting(id: string, over: Partial<ExistingFindingRef>): ExistingFindingRef {
  return {
    id,
    origin,
    title: 'Cross-tenant object access',
    status: 'confirmed',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    method: 'GET',
    ...over,
  }
}

function alwaysDuplicateLlm(duplicateOfId: string, shouldUpgrade = false): SemanticDedupeLlmCall {
  return async () => JSON.stringify({
    isDuplicate: true,
    duplicateOfId,
    shouldUpgrade,
    rationale: `Model claims candidate is a duplicate of ${duplicateOfId}.`,
  })
}

function mutation(kind: MutatedInput['kind'], name: string, location?: string): MutatedInput {
  return location ? { kind, name, location } : { kind, name }
}

describe('R2-10: LLM semantic dedupe deterministic veto', () => {
  test('two distinct-endpoint BOLA candidates on the same origin both proceed to verification even when LLM says isDuplicate=true', async () => {
    const existingOrders = bolaExisting('f-orders-bola', {
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
    })
    const candidateInvoices = bolaCandidate({
      endpoint: '/api/v1/invoices/2002',
      method: 'GET',
      param: 'id',
    })

    // First candidate (orders) against empty store proceeds to verification.
    const firstDecision = await evaluateSubmissionDedupe({
      candidate: bolaCandidate({ endpoint: '/api/v1/orders/1001', method: 'GET', param: 'id' }),
      existingFindings: [],
      llmCall: alwaysDuplicateLlm('f-orders-bola'),
    })
    assert.equal(firstDecision.action, 'accept')
    assert.equal(firstDecision.isDuplicate, false)

    // Second candidate (invoices) triggers LLM returning isDuplicate=true against orders,
    // which MUST be vetoed deterministically so BOTH reach verification.
    let llmCalls = 0
    const secondDecision = await evaluateSubmissionDedupe({
      candidate: candidateInvoices,
      existingFindings: [existingOrders],
      llmCall: async prompt => {
        llmCalls += 1
        return alwaysDuplicateLlm('f-orders-bola')(prompt)
      },
    })

    assert.equal(llmCalls, 1, 'LLM semantic judge was invoked on nearby same-origin BOLA')
    assert.equal(secondDecision.action, 'accept')
    assert.equal(secondDecision.isDuplicate, false)
    assert.equal(secondDecision.duplicateOfId, null)
    assert.equal(secondDecision.siblingOfId, 'f-orders-bola')
    assert.equal(secondDecision.vetoReason, 'endpoint_mismatch')
    assert.match(secondDecision.rationale, /veto/i)
    assert.match(secondDecision.rationale, /f-orders-bola/)
  })

  test('same-endpoint different-param candidate is vetoed and preserved when LLM says isDuplicate=true', async () => {
    const existing = bolaExisting('f-param-id', {
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
    })
    const candidate = bolaCandidate({
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'ownerId',
    })

    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: alwaysDuplicateLlm('f-param-id'),
    })
    assert.equal(decision.action, 'accept')
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.siblingOfId, 'f-param-id')
    assert.equal(decision.vetoReason, 'param_conflict')
  })

  test('same-endpoint different-method candidate (GET vs DELETE) is vetoed and preserved when LLM says isDuplicate=true', async () => {
    const existing = bolaExisting('f-get-order', {
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
    })
    const candidate = bolaCandidate({
      endpoint: '/api/v1/orders/1001',
      method: 'DELETE',
      param: 'id',
    })

    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: alwaysDuplicateLlm('f-get-order'),
    })
    assert.equal(decision.action, 'accept')
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.siblingOfId, 'f-get-order')
    assert.equal(decision.vetoReason, 'method_conflict')
  })

  test('same-endpoint different-mutation class (header vs param), different mutation name, and different input location are vetoed', async () => {
    // 1. Different mutation class (header vs body param with same name)
    const headerVsParam = await evaluateSubmissionDedupe({
      candidate: bolaCandidate({
        endpoint: '/api/v1/account',
        method: 'POST',
        mutated: mutation('header', 'x-tenant-id', 'header'),
      }),
      existingFindings: [
        bolaExisting('f-body-tenant', {
          endpoint: '/api/v1/account',
          method: 'POST',
          mutated: mutation('param', 'x-tenant-id', 'json'),
        }),
      ],
      llmCall: alwaysDuplicateLlm('f-body-tenant'),
    })
    assert.equal(headerVsParam.action, 'accept')
    assert.equal(headerVsParam.isDuplicate, false)
    assert.equal(headerVsParam.siblingOfId, 'f-body-tenant')
    assert.equal(headerVsParam.vetoReason, 'mutation_conflict')

    // 2. Different GraphQL operation on POST /graphql
    const gqlDifferentField = await evaluateSubmissionDedupe({
      candidate: bolaCandidate({
        endpoint: '/graphql',
        method: 'POST',
        graphqlField: 'updateInvoice',
        mutated: mutation('graphql', 'updateInvoice'),
      }),
      existingFindings: [
        bolaExisting('f-gql-order', {
          endpoint: '/graphql',
          method: 'POST',
          graphqlField: 'order',
          mutated: mutation('graphql', 'order'),
        }),
      ],
      llmCall: alwaysDuplicateLlm('f-gql-order'),
    })
    assert.equal(gqlDifferentField.action, 'accept')
    assert.equal(gqlDifferentField.isDuplicate, false)
    assert.equal(gqlDifferentField.siblingOfId, 'f-gql-order')
    assert.equal(gqlDifferentField.vetoReason, 'mutation_conflict')

    // 3. Same param name on same endpoint, different input location (query vs json body)
    const queryVsJson = await judgeSemanticDuplicate(
      bolaCandidate({
        endpoint: '/api/v1/orders/1001',
        method: 'POST',
        mutated: mutation('param', 'ownerId', 'query'),
      }),
      [
        bolaExisting('f-json-owner', {
          endpoint: '/api/v1/orders/1001',
          method: 'POST',
          mutated: mutation('param', 'ownerId', 'json'),
        }),
      ],
      alwaysDuplicateLlm('f-json-owner'),
    )
    assert.equal(queryVsJson.isDuplicate, false)
    assert.equal(queryVsJson.usedLlm, true)
    assert.equal(queryVsJson.vetoedDuplicateOfId, 'f-json-owner')
    assert.equal(queryVsJson.vetoReason, 'input_location_conflict')

    // 4. Different RPC procedures on /rpc
    const rpcConflict = await evaluateSubmissionDedupe({
      candidate: bolaCandidate({
        endpoint: '/rpc',
        method: 'POST',
        mutated: mutation('rpc', 'admin.deleteUser'),
      }),
      existingFindings: [
        bolaExisting('f-rpc-get', {
          endpoint: '/rpc',
          method: 'POST',
          mutated: mutation('rpc', 'user.get'),
        }),
      ],
      llmCall: alwaysDuplicateLlm('f-rpc-get'),
    })
    assert.equal(rpcConflict.action, 'accept')
    assert.equal(rpcConflict.isDuplicate, false)
    assert.equal(rpcConflict.vetoReason, 'mutation_conflict')
  })

  test('same-endpoint different verified handler is vetoed when LLM says isDuplicate=true', async () => {
    const existing = bolaExisting('f-svc-orders', {
      endpoint: '/api/v1/items/1001',
      method: 'GET',
      param: 'id',
      handler: '/svc-orders/items/:id',
    })
    const candidate = bolaCandidate({
      endpoint: '/api/v1/items/2002',
      method: 'GET',
      param: 'id',
      handler: '/svc-billing/items/:id',
    })

    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: alwaysDuplicateLlm('f-svc-orders'),
    })
    assert.equal(decision.action, 'accept')
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.siblingOfId, 'f-svc-orders')
    assert.equal(decision.vetoReason, 'handler_conflict')
  })

  test('cross-origin finding pulled into nearby set via sourceOrigins is vetoed when LLM says isDuplicate=true', async () => {
    const existing = bolaExisting('f-other-origin', {
      origin: 'https://api.northstar.example',
      sourceOrigins: [origin],
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
    })
    const candidate = bolaCandidate({
      origin,
      sourceOrigins: ['https://api.northstar.example'],
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
    })

    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: alwaysDuplicateLlm('f-other-origin'),
    })
    assert.equal(decision.action, 'accept')
    assert.equal(decision.isDuplicate, false)
    assert.equal(decision.siblingOfId, 'f-other-origin')
    assert.equal(decision.vetoReason, 'origin_mismatch')
  })

  test('true duplicate (same origin, method, route template, param, handler) with LLM isDuplicate=true still dedupes cleanly', async () => {
    // Different CWE aliases for the same broken-access-control bug on the exact same surface
    // bypass structural fingerprint dedupe and reach the LLM semantic judge.
    const existing = bolaExisting('f-orders-confirmed', {
      cwe: 'CWE-639',
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
      handler: '/svc-orders/orders/:id',
      severity: 'high',
    })
    const candidate = bolaCandidate({
      cwe: 'CWE-284',
      endpoint: '/api/v1/orders/9999',
      method: 'GET',
      param: 'id',
      handler: '/svc-orders/orders/:id',
      severity: 'high',
    })

    assert.equal(sameFindingPredicate(candidate, existing), true)

    let llmCalls = 0
    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: async prompt => {
        llmCalls += 1
        return alwaysDuplicateLlm('f-orders-confirmed')(prompt)
      },
    })
    assert.equal(llmCalls, 1)
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.action, 'reject_duplicate')
    assert.equal(decision.stage, 'semantic')
    assert.equal(decision.duplicateOfId, 'f-orders-confirmed')
    assert.equal(decision.siblingOfId, undefined)
    assert.equal(decision.vetoReason, undefined)

    // Higher-severity true duplicate still upgrades cleanly.
    const upgradeDecision = await evaluateSubmissionDedupe({
      candidate: { ...candidate, severity: 'critical' },
      existingFindings: [existing],
      llmCall: alwaysDuplicateLlm('f-orders-confirmed', true),
    })
    assert.equal(upgradeDecision.isDuplicate, true)
    assert.equal(upgradeDecision.action, 'upgrade_existing')
    assert.equal(upgradeDecision.stage, 'semantic')
    assert.equal(upgradeDecision.duplicateOfId, 'f-orders-confirmed')
  })

  test('structural/fingerprint duplicates still dedupe at structural stage without invoking LLM', async () => {
    const existing = bolaExisting('f-orders-struct', {
      endpoint: '/api/v1/orders/1001',
      method: 'GET',
      param: 'id',
      handler: '/svc-orders/orders/:id',
    })
    const candidate = bolaCandidate({
      endpoint: '/api/v1/orders/4242',
      method: 'GET',
      param: 'id',
      handler: '/svc-orders/orders/:id',
    })

    let llmCalls = 0
    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: async () => {
        llmCalls += 1
        return JSON.stringify({ isDuplicate: false, duplicateOfId: null, shouldUpgrade: false, rationale: 'unused' })
      },
    })
    assert.equal(llmCalls, 0)
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.action, 'reject_duplicate')
    assert.equal(decision.stage, 'structural')
    assert.equal(decision.duplicateOfId, 'f-orders-struct')
  })

  test('origin-wide CWEs (CORS on different paths/handlers) pass sameFindingPredicate and collapse under LLM dedupe', async () => {
    const existing: ExistingFindingRef = {
      id: 'f-cors-root',
      origin,
      title: 'CORS reflection on /api/a',
      status: 'confirmed',
      cwe: 'CWE-942',
      category: 'cors-client-side',
      severity: 'low',
      endpoint: '/api/a',
      handler: '/svc-a',
    }
    const candidate: DedupeCandidate = {
      origin,
      title: 'Credentialed CORS reflection on /api/b',
      cwe: 'CWE-942',
      category: 'cors-client-side',
      severity: 'medium',
      endpoint: '/api/b',
      handler: '/svc-b',
    }

    assert.equal(sameFindingPredicate(candidate, existing), true)

    const decision = await evaluateSubmissionDedupe({
      candidate,
      existingFindings: [existing],
      llmCall: alwaysDuplicateLlm('f-cors-root', true),
    })
    assert.equal(decision.isDuplicate, true)
    assert.equal(decision.action, 'upgrade_existing')
    assert.equal(decision.stage, 'semantic')
    assert.equal(decision.duplicateOfId, 'f-cors-root')
  })

  test('sameFindingPredicate treats wildcard ANY method as non-conflicting while rejecting explicit verb mismatch', async () => {
    const getFinding = bolaExisting('f-get', { endpoint: '/api/v1/orders/1', method: 'GET', param: 'id' })
    const anyFinding = bolaCandidate({ endpoint: '/api/v1/orders/2', method: 'ANY', param: 'id' })
    const postFinding = bolaCandidate({ endpoint: '/api/v1/orders/2', method: 'POST', param: 'id' })

    assert.equal(sameFindingPredicate(anyFinding, getFinding), true)
    assert.equal(sameFindingPredicate(postFinding, getFinding), false)

    const vetoed = await judgeSemanticDuplicate(postFinding, [getFinding], alwaysDuplicateLlm('f-get'))
    assert.equal(vetoed.isDuplicate, false)
    assert.equal(vetoed.vetoReason, 'method_conflict')
  })
})

describe('R2-10: shared browser-safe ORIGIN_WIDE_CWE_KEYS module', () => {
  test('finding-fingerprint.ts, dedupe.ts, and report-summary.ts share the exact same ORIGIN_WIDE_CWE_KEYS reference', () => {
    assert.strictEqual(findingFingerprint.ORIGIN_WIDE_CWE_KEYS, ORIGIN_WIDE_CWE_KEYS)
    assert.strictEqual(dedupe.ORIGIN_WIDE_CWE_KEYS, ORIGIN_WIDE_CWE_KEYS)
    assert.strictEqual(reportSummary.ORIGIN_WIDE_CWE_KEYS, ORIGIN_WIDE_CWE_KEYS)

    assert.strictEqual(findingFingerprint.isOriginWideCwe, isOriginWideCwe)
    assert.strictEqual(findingFingerprint.normalizeCwe, normalizeCwe)
    assert.strictEqual(dedupe.isOriginWideCwe, isOriginWideCwe)
    assert.strictEqual(dedupe.normalizeCwe, normalizeCwe)

    assert.equal(ORIGIN_WIDE_CWE_KEYS.has('CWE-942'), true)
    assert.equal(ORIGIN_WIDE_CWE_KEYS.has('CWE-639'), false)
    assert.equal(isOriginWideCwe('cwe-942'), true)
    assert.equal(isOriginWideCwe('CWE-639'), false)
  })

  test('src/finding-keys.ts is browser-safe with zero node:* or server imports', () => {
    const src = readFileSync(resolve('src/finding-keys.ts'), 'utf8')
    assert.doesNotMatch(src, /from\s+['"]node:/, 'src/finding-keys.ts must not import node:* builtins')
    assert.doesNotMatch(src, /from\s+['"][^'"]*server\//, 'src/finding-keys.ts must not import src/server/* modules')
  })
})
