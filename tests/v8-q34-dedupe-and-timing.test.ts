/**
 * v8 Queue #34 Stream 2 Regression Tests:
 *  1. Finding dedupe normalization (`finding-fingerprint.ts`):
 *     - Redacted capability placeholders (`[redacted]`, `[redacted:...]`, percent-encoded) and
 *       generic prefixed/underscore/hyphenated runtime IDs normalize to `:id`.
 *     - Normal static route segments (`settle-race`, `v1`, `v2`, `api_keys`, `webhook_events`,
 *       `health-check`, `user-profile`, `api_v1`, `api-v2`, `oauth2-callback`) stay intact.
 *     - Equivalent findings differing only by runtime ID vs redacted placeholder yield identical
 *       fingerprints and collapse under `checkStructuralDuplicate`.
 *  2. Multi-hop wall-clock budget & signal expansion (`exec-dispatch.ts` + `agent-prompts.ts`):
 *     - Edge / prefix / startsWith / proxy / cross-tenant / cross-service / async / signed-URL /
 *       readiness / cache / composite / tenant-boundary steps qualify for `isMultiHopChainStep`,
 *       270s–300s wall-clock cap, `chain` lane, and `multiHopDirectives`.
 *     - Standalone single-route sweeps and `det_lead` upgrades stay at 120s and omit
 *       `multiHopDirectives`.
 *  3. Chain scope discipline (`agent-prompts.ts`):
 *     - `multiHopDirectives.scopeAnchor` emits a crisp 2-line scope-anchor directive keeping
 *       workers anchored to their assigned chain/suspect endpoints and off unrelated confirmed routes.
 */
import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  matchesMultiHopStepSignal,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import {
  checkStructuralDuplicate,
  computeFindingFingerprint,
  normalizeEndpointTemplate,
  normalizeHandlerRef,
} from '../src/server/dedupe.ts'
import {
  classifyDispatchLane,
  isMultiHopChainStep,
  isMultiStepAssignment,
  planAssignmentBudget,
  resolveWorkerSettlementMs,
  resolveWorkerWallClockMs,
  type DispatchLaneStep,
} from '../src/server/exec-dispatch.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const ORIGIN = 'https://qa-target.example.invalid'

function makeStep(overrides: Partial<DispatchLaneStep> & { title: string; hypothesis: string }): DispatchLaneStep {
  return {
    id: 'step-q34',
    seq: 1,
    priority: 90,
    category: 'broken-access-control',
    skills: ['bola-idor-race'],
    dependsOnStepIds: [],
    dependsOnFactIds: [],
    sourceOrigins: [ORIGIN],
    ...overrides,
  }
}

test('Q34.1: normalizeEndpointTemplate collapses redacted placeholders and generic runtime IDs while preserving static route words', () => {
  // Positive cases: redacted placeholders, capability handles, prefixed/underscore/hyphenated runtime IDs.
  const positiveCases: Array<[string, string]> = [
    ['/v1/orders/[redacted:cap:hop_1:order_id]/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/[redacted]/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/%5Bredacted%3Acap%3Ahop_1%3Aorder_id%5D/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/%5Bredacted%5D/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/cap:hop_1:order_id/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/mh_ord_9_5ed534/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/job_export_38_c4f8e5/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/ord_123/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/ord_a1b2/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/inv-9001/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/orders/ord-a1b2/settle-race', '/v1/orders/:id/settle-race'],
    ['/v1/exports/export-job-38-c4f8e5/download', '/v1/exports/:id/download'],
    ['/v1/users/usr_01H9ZK8X2M/profile', '/v1/users/:id/profile'],
    ['/v1/files/export-[redacted:cap:hop_2:file_id].csv', '/v1/files/:id'],
  ]
  for (const [input, expected] of positiveCases) {
    assert.equal(normalizeEndpointTemplate(input), expected, `expected ${input} -> ${expected}`)
  }

  // Negative cases: normal static kebab/snake/version route words MUST NOT collapse to `:id`.
  const staticRoutes = [
    '/v1/orders/settle-race',
    '/v2/api_keys/rotate',
    '/v1/user-profile/settings',
    '/v1/webhook_events/health-check',
    '/api_v1/credit_cards',
    '/api-v2/oauth2-callback',
    '/_actions/updateorgplan',
    '/svc-orders/svc-billing/status',
  ]
  for (const route of staticRoutes) {
    assert.equal(normalizeEndpointTemplate(route), route, `static route ${route} must not collapse to :id`)
  }
  assert.equal(
    normalizeEndpointTemplate('/_actions/updateOrgPlan', { preserveCase: true }),
    '/_actions/updateOrgPlan',
  )
})

test('Q34.2: findings on the same parameterized route with redacted vs prefixed runtime IDs share one fingerprint and deduplicate', () => {
  const variants = [
    '/v1/orders/[redacted:cap:hop_1:order_id]/settle-race',
    '/v1/orders/[redacted]/settle-race',
    '/v1/orders/mh_ord_9_5ed534/settle-race',
    '/v1/orders/mh_ord_12_a9b1c2/settle-race',
    '/v1/orders/job_export_38_c4f8e5/settle-race',
  ]

  const fingerprints = variants.map(endpoint =>
    computeFindingFingerprint({
      origin: ORIGIN,
      cwe: 'CWE-362',
      category: 'economic_conservation',
      method: 'POST',
      endpoint,
      verifiedEndpoint: `POST ${ORIGIN}${endpoint}`,
    }),
  )

  for (let i = 0; i < fingerprints.length; i += 1) {
    assert.equal(fingerprints[i]!.normalizedEndpoint, '/v1/orders/:id/settle-race')
    assert.equal(fingerprints[i]!.handler, '/v1/orders/:id/settle-race')
    assert.equal(fingerprints[i]!.key, fingerprints[0]!.key, `variant ${i} must share fingerprint key`)
    assert.equal(fingerprints[i]!.hash, fingerprints[0]!.hash, `variant ${i} must share fingerprint hash`)
  }

  // Handler ref normalization agrees on both redacted and runtime-ID paths.
  assert.equal(
    normalizeHandlerRef('POST /v1/orders/[redacted:cap:hop_1:order_id]/settle-race'),
    normalizeHandlerRef('POST /v1/orders/mh_ord_9_5ed534/settle-race'),
  )

  // Structural dedupe collapses subsequent variants onto the first persisted finding.
  const firstExisting = {
    id: 'f-1',
    origin: ORIGIN,
    title: 'Concurrent settlement conservation violation',
    status: 'confirmed' as const,
    cwe: 'CWE-362',
    category: 'economic_conservation',
    severity: 'high' as const,
    method: 'POST',
    endpoint: variants[0],
    verifiedEndpoint: `POST ${ORIGIN}${variants[0]}`,
  }
  for (const endpoint of variants.slice(1)) {
    const decision = checkStructuralDuplicate(
      {
        origin: ORIGIN,
        title: 'Concurrent settlement conservation violation',
        cwe: 'CWE-362',
        category: 'economic_conservation',
        severity: 'high',
        method: 'POST',
        endpoint,
        verifiedEndpoint: `POST ${ORIGIN}${endpoint}`,
      },
      [firstExisting],
    )
    assert.equal(decision.isDuplicate, true, `expected ${endpoint} to dedupe against ${variants[0]}`)
    assert.equal(decision.duplicateOfId, 'f-1')
  }

  // Distinct routes or HTTP methods still remain distinct findings.
  const diffMethod = computeFindingFingerprint({
    origin: ORIGIN,
    cwe: 'CWE-362',
    method: 'GET',
    endpoint: '/v1/orders/mh_ord_9_5ed534/settle-race',
  })
  const diffRoute = computeFindingFingerprint({
    origin: ORIGIN,
    cwe: 'CWE-362',
    method: 'POST',
    endpoint: '/v1/orders/mh_ord_9_5ed534/cancel-race',
  })
  assert.notEqual(diffMethod.hash, fingerprints[0]!.hash)
  assert.notEqual(diffRoute.hash, fingerprints[0]!.hash)
})

test('Q34.3: edge/prefix/proxy/cross-tenant/async/cache/composite steps get 270s-300s multi-hop wall-clock budget and multiHopDirectives', () => {
  const multiHopCases: Array<{ label: string; step: DispatchLaneStep }> = [
    {
      label: 'Q33 edge startsWith prefix bypass regression',
      step: makeStep({
        title: 'Edge startsWith prefix bypass · GET /files/export/:tenant/:file cross-tenant readback',
        hypothesis: 'Verify whether prefix matching at the gateway allows accessing another tenant export.',
      }),
    },
    {
      label: 'Proxy routing confusion',
      step: makeStep({
        title: 'Reverse proxy path normalization mismatch',
        hypothesis: 'Test differential path routing between ingress and backend.',
      }),
    },
    {
      label: 'Cross-service boundary verification',
      step: makeStep({
        title: 'Cross-service auth header forwarding audit',
        hypothesis: 'Check whether internal headers are trusted across service hops.',
      }),
    },
    {
      label: 'Async export signed URL flow',
      step: makeStep({
        title: 'Async export signed URL tenant boundary check',
        hypothesis: 'Trigger job export, poll readiness, and fetch generated signed URL.',
      }),
    },
    {
      label: 'Readiness probe & cache poisoning',
      step: makeStep({
        title: 'Cache key scoping and readiness state verification',
        hypothesis: 'Prime shared cache entry and verify subsequent cross-actor readback.',
      }),
    },
    {
      label: 'Composite verification title',
      step: makeStep({
        title: 'Composite verification of delegated approval state',
        hypothesis: 'Verify multi-step state transition across endpoints.',
      }),
    },
    {
      label: 'Tenant-boundary title',
      step: makeStep({
        title: 'Tenant-boundary isolation check on export jobs',
        hypothesis: 'Verify tenant isolation across job creation and download.',
      }),
    },
  ]

  for (const { label, step } of multiHopCases) {
    assert.equal(matchesMultiHopStepSignal(step), true, `${label}: matchesMultiHopStepSignal must be true`)
    assert.equal(isMultiHopChainStep(step), true, `${label}: isMultiHopChainStep must be true`)
    assert.equal(isMultiStepAssignment(step), true, `${label}: isMultiStepAssignment must be true`)
    assert.equal(classifyDispatchLane(step), 'chain', `${label}: must route to chain lane`)
    assert.equal(resolveWorkerWallClockMs(step, 900_000), 210_000, `${label}: 15m run must get 210s wall-clock cap`)
    assert.equal(resolveWorkerWallClockMs(step, 1_800_000), 210_000, `${label}: 30m run must get 210s wall-clock cap`)
    assert.equal(resolveWorkerWallClockMs(step, undefined), 210_000, `${label}: default run must get 210s wall-clock`)

    const budget = planAssignmentBudget({
      routes: ['/files/export/:id/:id'],
      parentEvidenceIds: [],
      dependsOnStepIds: [],
      multiHopChain: isMultiHopChainStep(step),
      runDurationMs: 900_000,
      baseMaxTurns: 30,
      baseWallClockMs: 120_000,
    })
    assert.equal(budget.kind, 'chain')
    assert.equal(budget.wallClockMs, 210_000)
    assert.equal(budget.wallClockSettlementMs, resolveWorkerSettlementMs(210_000, true))

    const prompt = JSON.parse(workerInvestigationPrompt({
      goal: 'Verify cross-boundary invariant',
      step: {
        id: step.id,
        title: step.title,
        hypothesis: step.hypothesis ?? '',
        category: step.category ?? 'broken-access-control',
        skills: step.skills ?? [],
      },
      origins: [ORIGIN],
      capabilityTier: 2,
      maxTurns: 30,
    })) as { multiHopDirectives?: Record<string, string> }
    assert.ok(prompt.multiHopDirectives, `${label}: must include multiHopDirectives`)
  }

  // Standalone single-route sweeps and det_lead upgrades must stay at 120s and omit multiHopDirectives.
  const singleRouteCases: Array<{ label: string; step: DispatchLaneStep }> = [
    {
      label: 'Single-route access sweep',
      step: makeStep({
        title: 'Single-route access sweep',
        hypothesis: 'Verify GET /api/v1/items/:id authorization matrix.',
        skills: ['bola-bfla'],
      }),
    },
    {
      label: 'Single-endpoint header check',
      step: makeStep({
        title: 'Single-endpoint header check',
        hypothesis: 'Check response policy on /api/v1/health.',
        category: 'misconfig-exposure',
        skills: ['false-positive-elimination'],
      }),
    },
    {
      label: 'det_lead upgrade mentioning cache path',
      step: makeStep({
        title: 'det_lead upgrade · /api/v1/cache-status',
        hypothesis: 'Verify single-endpoint header response.',
        skills: ['false-positive-elimination'],
      }),
    },
  ]

  for (const { label, step } of singleRouteCases) {
    assert.equal(matchesMultiHopStepSignal(step), false, `${label}: must stay single-route`)
    assert.equal(isMultiHopChainStep(step), false, `${label}: isMultiHopChainStep must be false`)
    assert.equal(resolveWorkerWallClockMs(step, 900_000), 120_000, `${label}: must keep 120s wall-clock`)

    const prompt = JSON.parse(workerInvestigationPrompt({
      goal: 'Verify single route',
      step: {
        id: step.id,
        title: step.title,
        hypothesis: step.hypothesis ?? '',
        category: step.category ?? 'broken-access-control',
        skills: step.skills ?? [],
      },
      origins: [ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
    })) as { multiHopDirectives?: Record<string, string> }
    assert.equal(prompt.multiHopDirectives, undefined, `${label}: must omit multiHopDirectives`)
  }
})

test('Q34.4: multiHopDirectives includes crisp 2-line scopeAnchor rule and repo passes anti-contamination lint', () => {
  const prompt = JSON.parse(workerInvestigationPrompt({
    goal: 'Verify assigned composite chain',
    step: {
      id: 'step-q34-scope',
      title: 'Edge startsWith prefix bypass · GET /files/export/:tenant/:file cross-tenant',
      hypothesis: 'Test gateway prefix matching and cross-tenant export download.',
      category: 'broken-access-control',
      skills: ['bola-idor-race'],
    },
    origins: [ORIGIN],
    capabilityTier: 2,
    maxTurns: 30,
  })) as { multiHopDirectives?: { scopeAnchor?: string } }

  const scopeAnchor = prompt.multiHopDirectives?.scopeAnchor
  assert.ok(scopeAnchor, 'multiHopDirectives.scopeAnchor must be present')
  const lines = scopeAnchor.split('\n').filter(line => line.trim().length > 0)
  assert.equal(lines.length, 2, `scopeAnchor must be a crisp 2-line rule, got ${lines.length} lines`)
  assert.match(scopeAnchor, /anchored to your assigned chain\/suspect endpoints/i)
  assert.match(scopeAnchor, /pivot across hops of THAT hypothesis/i)
  assert.match(scopeAnchor, /do not spend turns re-confirming an unrelated endpoint/i)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
  assert.equal(scan.hits.length, 0)
})
