/**
 * v8 planner dedupe — zero-recall-loss redundant planner suppression tests.
 *
 * Covers every positive suppression AND every negative zero-recall-loss invariant across:
 *   1. `alreadyConfirmedRefs` exposure of host-verified `CompositeProofReceipt` hop/terminal routes;
 *   2. `queueSecondOrderSurfaceSteps` skipping routes already covered by a verified composite receipt
 *      while NEVER skipping for single-hop-only findings;
 *   3. `persistDispatchPlan`, `applyPlannerNewSteps` (`parsedPlanner.data.newSteps`), and
 *      `queueTierALeadSteps` skipping duplicate `(origin, normalizedRoute, classFamily)` already
 *      confirmed or currently in-flight (`pending` / `ready` / `running`, excluding `trialIndex > 0`);
 *   4. Strict zero-recall-loss invariants: different vuln class allowed, different origin allowed,
 *      completed/canceled non-confirmed steps do not block, multi-trial siblings (`trialIndex > 0`)
 *      and Hop-Continuations (`checkpointCapId` / `dependsOnStepIds`) NEVER suppressed, multi-hop
 *      chain steps (`routes.length >= 2`) NEVER suppressed unless ALL tuples are composite-confirmed
 *      or in-flight, and `dynamicStepBudget` untouched.
 *
 * All fixtures are 100% synthetic (no benchmark/app/route/seed literals).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { test } from 'node:test'
import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { Execution, emptyDispatchFunnel } from '../src/server/execution.ts'
import {
  CHECKPOINT_CAP_SKILL_PREFIX,
  buildConfirmedTupleKeySets,
  buildInFlightTupleKeys,
  normalizeConfirmedRouteTemplate,
  plannerDedupeTupleKey,
  type ExecReconPlanner,
  type PlannerConfirmedRef,
} from '../src/server/exec-recon-planner.ts'
import type { DispatchPlan } from '../src/server/graph-coordinator.ts'
import type { ReplayProofReceiptRow } from '../src/server/schema.ts'
import type { Assignment, Run, Store } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const ORIGIN_A = 'https://alpha.example.invalid'
const ORIGIN_B = 'https://beta.example.invalid'

function plannerOf(execution: Execution): ExecReconPlanner {
  return (execution as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

function makeWorker(storage: Store, run: Run, origin = ORIGIN_A): Assignment {
  const asset = run.candidates.find(c => c.origin === origin) ?? run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'planner-dedupe-test', 'test worker', {
    sourceOrigins: [origin],
  })
  return storage.updateWorker(worker.id, { status: 'running', lease: randomUUID() })!
}

function addConfirmedFindingWithSpec(input: {
  storage: Store
  run: Run
  worker: Assignment
  origin: string
  endpoint: string
  method?: string
  category: Finding['category']
  cwe?: string
  title?: string
  proofReceipt?: Record<string, unknown> | null
}): string {
  const findingId = `fnd-${randomUUID().slice(0, 8)}`
  const method = input.method ?? 'GET'
  const asset = input.run.candidates.find(c => c.origin === input.origin) ?? input.run.candidates[0]!
  const spec = {
    kind: 'http_chain',
    title: input.title ?? `Confirmed ${input.category} on ${input.endpoint}`,
    category: input.category,
    cwe: input.cwe ?? 'CWE-639',
    severity: 'high',
    severityRationale: 'Verified differential proof.',
    impact: 'Unauthorized cross-tenant access.',
    remediation: 'Enforce strict tenant authorization checks.',
    recheckInstructions: 'Replay the control vs. probe differential.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [{
      id: 'probe',
      role: 'probe',
      description: 'Probe step',
      expectedStatus: 200,
      request: { origin: input.origin, method, pathAndQuery: input.endpoint, followRedirects: false },
    }],
  } as unknown as DeclarativeReplaySpec
  const specRow = input.storage.createReplaySpec(
    input.run,
    input.worker,
    findingId,
    spec,
    [input.origin],
    {
      initialAttemptCount: 1,
      verifiedInline: true,
      lastVerificationDiff: {
        verdict: 'confirmed',
        controlPassed: true,
        assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
        stepStatuses: [{ id: 'probe', role: 'probe', status: 200, bodyLen: 42 }],
        retriesRemaining: 0,
      },
      ...(input.proofReceipt
        ? {
            proof: {
              replaySpecId: '',
              findingId,
              verdict: 'confirmed',
              runtime: 'ts',
              scriptSha256: 'a'.repeat(64),
              artifactId: `art-${randomUUID().slice(0, 8)}`,
              receipt: input.proofReceipt as unknown as ReplayProofReceiptRow,
              createdAt: Date.now(),
            },
          }
        : {}),
    },
  )
  const finding: Finding = {
    id: findingId,
    title: input.title ?? `Confirmed ${input.category} on ${input.endpoint}`,
    severity: 'high',
    category: input.category,
    cwe: input.cwe ?? 'CWE-639',
    origin: input.origin,
    status: 'confirmed',
    reason: `Verified finding at ${method} ${input.endpoint}`,
    remediation: 'Enforce strict tenant authorization checks.',
    evidenceIds: [],
    replaySpecId: specRow.id,
    scopeRevision: input.run.scopeRevision,
    confidence: 'high',
    verification: 'Zero-LLM http_chain inline replay verdict: confirmed',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
  }
  const saved = input.storage.upsertChainFinding(input.run, asset.id, finding, specRow.id, [input.origin])
  assert.equal(saved.status, 'confirmed', 'fixture finding must persist as confirmed')
  return findingId
}

function makeCompositeProofReceipt(input: {
  origin: string
  hops: Array<{ hopId: string; origin?: string; method?: string; pathAndQuery: string; param?: string }>
  terminalHopId?: string
  terminalVulnClass?: string
  terminalEndpoint?: string
  verifiedMode?: 'confirmed_true' | 'ok_true' | 'confirmed_false' | 'ok_false'
}): Record<string, unknown> {
  const terminalHopId = input.terminalHopId ?? input.hops[input.hops.length - 1]!.hopId
  const terminalHop = input.hops.find(h => h.hopId === terminalHopId) ?? input.hops[input.hops.length - 1]!
  const mode = input.verifiedMode ?? 'confirmed_true'
  const verified = mode === 'confirmed_true' || mode === 'ok_true'
  const verification = mode === 'ok_true' || mode === 'ok_false'
    ? { ok: verified, vulnClass: input.terminalVulnClass ?? 'cross_tenant_chain' }
    : {
        confirmed: verified,
        vulnClass: input.terminalVulnClass ?? 'cross_tenant_chain',
        rule: 'composite:fresh_clean_replay',
        reason: verified ? 'verified' : 'rejected',
        observed: '2-hop composite',
        expected: 'verified composite',
      }
  return {
    receipt: {
      vulnClass: input.terminalVulnClass ?? 'cross_tenant_chain',
      target: {
        origin: terminalHop.origin ?? input.origin,
        method: terminalHop.method ?? 'GET',
        pathAndQuery: terminalHop.pathAndQuery,
      },
      exchangeIds: ['ex-1', 'ex-2'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Multi-hop chain proven.',
    },
    verification,
    compositeReceipt: {
      chainId: `chain-${randomUUID().slice(0, 8)}`,
      terminalVulnClass: input.terminalVulnClass ?? 'cross_tenant_chain',
      hops: input.hops.map(h => ({
        hopId: h.hopId,
        surface: 'http',
        target: {
          origin: h.origin ?? input.origin,
          ...(h.method ? { method: h.method } : {}),
          pathAndQuery: h.pathAndQuery,
          ...(h.param ? { param: h.param } : {}),
        },
        exchangeIds: ['ex-1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Hop ${h.hopId}`,
        producedCapabilities: [],
        consumedCapabilities: [],
      })),
      causalEdges: [],
      terminalImpact: {
        terminalHopId,
        claimedImpact: 'Cross-tenant impact proven.',
        preChainControlExchangeIds: [],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    ...(mode === 'confirmed_true' || mode === 'confirmed_false'
      ? {
          compositeVerification: {
            confirmed: verified,
            chainId: 'chain-1',
            terminalVulnClass: input.terminalVulnClass ?? 'cross_tenant_chain',
            replayMode: 'fresh_clean_replay',
            modeBVerified: verified,
            hopCount: input.hops.length,
            verifiedEdges: [],
            reason: verified ? 'ok' : 'failed',
            ...(input.terminalEndpoint ? { terminalEndpoint: input.terminalEndpoint } : {}),
          },
        }
      : {}),
  }
}

// ============================================================================
// 1. alreadyConfirmedRefs exposes verified CompositeProofReceipt hop/terminal routes
// ============================================================================

test('alreadyConfirmedRefs exposes verified CompositeProofReceipt hop & terminal endpoints with hasCompositeReceipt=true', async (t) => {
  const { storage } = makeStore(t, 'guardian-v8-dedupe-comp-')
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const run = storage.run(runId)
  const worker = makeWorker(storage, run, ORIGIN_A)

  // 1a. Verified composite receipt (compositeVerification.confirmed === true) with 2 hops + terminalEndpoint
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/exports/exp_101',
    method: 'GET',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    proofReceipt: makeCompositeProofReceipt({
      origin: ORIGIN_A,
      hops: [
        { hopId: 'hop_1', origin: ORIGIN_A, method: 'POST', pathAndQuery: '/api/v1/notes/note_42', param: 'body' },
        { hopId: 'hop_2', origin: ORIGIN_B, method: 'GET', pathAndQuery: '/api/v1/render/rpt_77?view=full' },
      ],
      terminalHopId: 'hop_2',
      terminalEndpoint: 'GET /api/v1/downloads/dl_88',
      verifiedMode: 'confirmed_true',
    }),
  })

  // 1b. Verified composite receipt via `verification.ok === true`
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/webhooks/wh_55',
    method: 'POST',
    category: 'cors-client-side',
    cwe: 'CWE-79',
    proofReceipt: makeCompositeProofReceipt({
      origin: ORIGIN_A,
      hops: [
        { hopId: 'hop_a', origin: ORIGIN_A, method: 'POST', pathAndQuery: '/api/v1/comments/cmt_12' },
        { hopId: 'hop_b', origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/v1/preview/prv_19' },
      ],
      verifiedMode: 'ok_true',
    }),
  })

  // 1c. Unverified composite receipt (confirmed === false) -> MUST NOT set hasCompositeReceipt or leak hops
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/unverified/uv_1',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: makeCompositeProofReceipt({
      origin: ORIGIN_A,
      hops: [
        { hopId: 'hop_u1', origin: ORIGIN_A, method: 'POST', pathAndQuery: '/api/v1/unverified-hop/uh_9' },
      ],
      verifiedMode: 'confirmed_false',
    }),
  })

  // 1d. Plain single-hop finding -> MUST NOT set hasCompositeReceipt
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/single/s_100',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: null,
  })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const refs = plannerOf(execution).alreadyConfirmedRefs(storage.run(runId), 100)

  const compRoutes = buildConfirmedTupleKeySets(refs).compositeRoutes
  assert.ok(compRoutes.has(`${ORIGIN_A}\u0000/api/v1/notes/:id`), 'hop 1 normalized route must be exposed as composite')
  assert.ok(compRoutes.has(`${ORIGIN_B}\u0000/api/v1/render/:id`), 'cross-origin hop 2 normalized route must be exposed as composite')
  assert.ok(compRoutes.has(`${ORIGIN_B}\u0000/api/v1/downloads/:id`), 'terminalEndpoint must be exposed as composite')
  assert.ok(compRoutes.has(`${ORIGIN_A}\u0000/api/v1/comments/:id`), 'verification.ok===true hop must be exposed as composite')
  assert.ok(compRoutes.has(`${ORIGIN_A}\u0000/api/v1/preview/:id`), 'verification.ok===true terminal hop must be exposed as composite')

  assert.equal(compRoutes.has(`${ORIGIN_A}\u0000/api/v1/unverified/:id`), false, 'unverified composite must NOT mark route as composite')
  assert.equal(compRoutes.has(`${ORIGIN_A}\u0000/api/v1/unverified-hop/:id`), false, 'unverified composite hops must NOT leak')
  assert.equal(compRoutes.has(`${ORIGIN_A}\u0000/api/v1/single/:id`), false, 'single-hop finding must NOT set hasCompositeReceipt')

  const singleRef = refs.find(r => normalizeConfirmedRouteTemplate(r.path) === '/api/v1/single/:id')
  assert.ok(singleRef, 'single-hop finding is still exposed in alreadyConfirmedRefs')
  assert.equal(singleRef.hasCompositeReceipt, undefined)
})

// ============================================================================
// 2. Second-order canary verification suppression (composite-only, NEVER single-hop)
// ============================================================================

test('queueSecondOrderSurfaceSteps skips routes with verified CompositeProofReceipt but NEVER skips single-hop-only routes', async (t) => {
  const { storage } = makeStore(t, 'guardian-v8-dedupe-2nd-')
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const run = storage.run(runId)
  const worker = makeWorker(storage, run, ORIGIN_A)

  // Confirmed composite on ORIGIN_A /api/v1/tickets/:id (concrete tkt_101)
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/tickets/tkt_101',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: makeCompositeProofReceipt({
      origin: ORIGIN_A,
      hops: [
        { hopId: 'h1', origin: ORIGIN_A, method: 'POST', pathAndQuery: '/api/v1/tickets/tkt_101/comments' },
        { hopId: 'h2', origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/v1/tickets/tkt_101' },
      ],
      verifiedMode: 'confirmed_true',
    }),
  })

  // Single-hop non-composite finding on ORIGIN_A /api/v1/profiles/:id (concrete usr_11)
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/profiles/usr_11',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: null,
  })

  const fCompositeDup = storage.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN_A,
    summary: 'Second-order canary resurfaced on composite-confirmed ticket route',
    data: {
      subkind: 'second_order_surface',
      marker: 'canary_comp_1',
      surfacedOrigin: ORIGIN_A,
      surfacedEndpoint: '/api/v1/tickets/tkt_999',
      surfacedMediaType: 'text/html',
      crossPersona: true,
    },
  })
  const fSingleHopRoute = storage.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN_A,
    summary: 'Second-order canary resurfaced on single-hop-only profile route',
    data: {
      subkind: 'second_order_surface',
      marker: 'canary_single_2',
      surfacedOrigin: ORIGIN_A,
      surfacedEndpoint: '/api/v1/profiles/usr_88',
      surfacedMediaType: 'text/html',
      crossPersona: true,
    },
  })
  const fOtherOrigin = storage.addFact(run, worker, {
    kind: 'note',
    origin: ORIGIN_B,
    summary: 'Second-order canary resurfaced on different origin with same path',
    data: {
      subkind: 'second_order_surface',
      marker: 'canary_originb_3',
      surfacedOrigin: ORIGIN_B,
      surfacedEndpoint: '/api/v1/tickets/tkt_555',
      surfacedMediaType: 'text/html',
      crossPersona: true,
    },
  })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const planner = plannerOf(execution)
  const confirmed = planner.alreadyConfirmedRefs(storage.run(runId), 100)
  const funnel = emptyDispatchFunnel(1)

  const enqueued = planner.queueSecondOrderSurfaceSteps(
    storage.run(runId),
    new Set([ORIGIN_A, ORIGIN_B]),
    [fCompositeDup, fSingleHopRoute, fOtherOrigin],
    storage.listChainSteps(runId, run.goalRevision),
    confirmed,
    10,
    funnel,
  )

  assert.equal(enqueued, 2, 'only composite-confirmed (same origin+route) is skipped; single-hop & other-origin enqueue')
  assert.equal(funnel.planned, 3)
  assert.equal(funnel.enqueued, 2)
  assert.equal(funnel.filteredAlreadyConfirmed, 1)

  const steps = storage.listChainSteps(runId, run.goalRevision)
  assert.equal(steps.some(s => s.title.includes('canary_comp_1')), false, 'composite-confirmed second-order step skipped')
  assert.equal(steps.some(s => s.title.includes('canary_single_2')), true, 'single-hop-only route MUST NOT suppress second-order')
  assert.equal(steps.some(s => s.title.includes('canary_originb_3')), true, 'different origin MUST NOT be suppressed')
})

// ============================================================================
// 3. persistDispatchPlan tuple dedupe + ALL zero-recall-loss invariants
// ============================================================================

test('persistDispatchPlan suppresses duplicate (origin, normalizedRoute, classFamily) confirmed/in-flight while preserving every zero-recall-loss invariant', async (t) => {
  const { storage } = makeStore(t, 'guardian-v8-dedupe-persist-')
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const run = storage.run(runId)
  const worker = makeWorker(storage, run, ORIGIN_A)
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!

  // Single-hop confirmed: (ORIGIN_A, /api/v1/invoices/:id, authz)
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/invoices/inv_100',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: null,
  })
  // Single-hop confirmed: (ORIGIN_A, /api/v1/tokens/:id, authz)
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/tokens/tok_10',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: null,
  })
  // Composite confirmed: (ORIGIN_A, /api/v1/stage-a/:id, authz) + (ORIGIN_A, /api/v1/stage-b/:id, authz)
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/stage-b/sb_1',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: makeCompositeProofReceipt({
      origin: ORIGIN_A,
      hops: [
        { hopId: 's1', origin: ORIGIN_A, method: 'POST', pathAndQuery: '/api/v1/stage-a/sa_1' },
        { hopId: 's2', origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/v1/stage-b/sb_1' },
      ],
      verifiedMode: 'confirmed_true',
    }),
  })

  // Existing in-flight step (status='running', trialIndex=0): (ORIGIN_A, /api/v1/orders/:id, authz)
  const inflightStep = storage.addChainStep(run, {
    title: 'Initial order isolation audit',
    hypothesis: 'Check cross-tenant read on GET /api/v1/orders/ord_11.',
    category: 'broken-access-control',
    priority: 85,
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
  })
  storage.updateChainStep(inflightStep.id, { status: 'running' })

  // Existing completed (non-confirmed) step: (ORIGIN_A, /api/v1/shipments/:id, authz) -> MUST NOT block!
  const completedStep = storage.addChainStep(run, {
    title: 'Prior shipment attempt',
    hypothesis: 'Test cross-tenant read on GET /api/v1/shipments/shp_11.',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
  })
  storage.updateChainStep(completedStep.id, { status: 'complete' })

  // Existing multi-trial sibling ONLY (trialIndex=1, status='running'): (ORIGIN_A, /api/v1/ledgers/:id, authz) -> MUST NOT block!
  const trialSibling = storage.addChainStep(run, {
    title: 'Ledger trial sibling',
    hypothesis: 'Trial sibling probing GET /api/v1/ledgers/ldg_11.',
    category: 'broken-access-control',
    priority: 80,
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
    trialGroupId: 'tg-1',
    trialIndex: 1,
  })
  storage.updateChainStep(trialSibling.id, { status: 'running' })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const planner = plannerOf(execution)

  const plan: DispatchPlan = {
    dispatched: false,
    totalBudgetUsd: 5,
    budgetUsd: 5,
    parentEvidenceIds: [],
    rejected: [],
    plan: [
      // (A) SUPPRESSED (already_confirmed): same (ORIGIN_A, /api/v1/invoices/:id, authz), different title & concrete ID
      {
        id: 'p1',
        hypothesis: 'Alternative phrasing: verify BOLA on GET /api/v1/invoices/inv_999 for cross-tenant leak.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['bola-idor-race'],
        priority: 80,
        budgetUsd: 0.5,
      },
      // (B) ALLOWED (different vuln class on already-confirmed route): stored_xss -> cors-client-side != authz
      {
        id: 'p2',
        hypothesis: 'Probe stored XSS rendering on GET /api/v1/invoices/inv_999.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'stored_xss',
        skills: ['client-side-xss-postmessage'],
        priority: 82,
        budgetUsd: 0.5,
      },
      // (C) ALLOWED (different origin on already-confirmed route+class): ORIGIN_B
      {
        id: 'p3',
        hypothesis: 'Check tenant isolation on beta origin GET /api/v1/invoices/inv_202.',
        origins: [ORIGIN_B],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['bola-idor-race'],
        priority: 80,
        budgetUsd: 0.5,
      },
      // (D) SUPPRESSED (in_flight): same (ORIGIN_A, /api/v1/orders/:id, authz), different title
      {
        id: 'p4',
        hypothesis: 'Redundant order authorization check on GET /api/v1/orders/ord_888.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['bola-idor-race'],
        priority: 85,
        budgetUsd: 0.5,
      },
      // (E) ALLOWED (different vuln class on in-flight route): ssrf -> injection-input != authz
      {
        id: 'p5',
        hypothesis: 'Probe SSRF fetch sink on POST /api/v1/orders/ord_888.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'ssrf',
        skills: ['oob-ssrf-browser-chain'],
        priority: 84,
        budgetUsd: 0.5,
      },
      // (F) ALLOWED (prior step is complete, not confirmed, not in-flight)
      {
        id: 'p6',
        hypothesis: 'Retry shipment authorization probe on GET /api/v1/shipments/shp_99.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['bola-idor-race'],
        priority: 79,
        budgetUsd: 0.5,
      },
      // (G) ALLOWED (only trialIndex > 0 sibling is running -> excluded from in-flight dedupe set)
      {
        id: 'p7',
        hypothesis: 'Primary ledger authorization check on GET /api/v1/ledgers/ldg_42.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['bola-idor-race'],
        priority: 78,
        budgetUsd: 0.5,
      },
      // (H) ALLOWED (Hop-Continuation with checkpointCapId on confirmed+in-flight route)
      {
        id: 'p8',
        hypothesis: 'Continue checkpointed chain on GET /api/v1/stage-b/sb_1.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['multihop-chains'],
        priority: 95,
        budgetUsd: 0.5,
        checkpointCapId: 'cap:hop_1:sealed_tok',
      },
      // (I) ALLOWED (multi-hop chain naming 2 single-hop-confirmed routes -> NOT composite-confirmed!)
      {
        id: 'p9',
        hypothesis: 'Chain GET /api/v1/tokens/tok_10 into GET /api/v1/invoices/inv_100 for escalation.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['multihop-chains'],
        priority: 90,
        budgetUsd: 0.5,
      },
      // (J) ALLOWED (multi-hop chain with 1 composite-confirmed route + 1 novel route)
      {
        id: 'p10',
        hypothesis: 'Chain POST /api/v1/stage-a/sa_1 into GET /api/v1/novel-vault/v_7.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['multihop-chains'],
        priority: 90,
        budgetUsd: 0.5,
      },
      // (K) SUPPRESSED (already_confirmed): multi-hop chain where ALL tuples are composite-confirmed
      {
        id: 'p11',
        hypothesis: 'Repeat composite chain POST /api/v1/stage-a/sa_99 to GET /api/v1/stage-b/sb_99.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['multihop-chains'],
        priority: 90,
        budgetUsd: 0.5,
      },
      // (L) SUPPRESSED (in_flight): multi-hop chain where 1 route is composite-confirmed + 1 is in-flight
      {
        id: 'p12',
        hypothesis: 'Duplicate active chain POST /api/v1/stage-a/sa_42 into GET /api/v1/orders/ord_42.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['multihop-chains'],
        priority: 90,
        budgetUsd: 0.5,
      },
      // (M) SUPPRESSED (in_flight within same batch): duplicates (F) enqueued earlier in this same DispatchPlan
      {
        id: 'p13',
        hypothesis: 'Second distinct-title shipment authz step on GET /api/v1/shipments/shp_100.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['bola-idor-race'],
        priority: 75,
        budgetUsd: 0.5,
      },
    ],
  }

  const counts = planner.persistDispatchPlan(storage.run(runId), plan, new Set())
  assert.equal(counts.planned, 13)
  assert.equal(counts.enqueued, 8, 'B, C, E, F, G, H, I, J must enqueue')
  assert.equal(counts.filteredAlreadyConfirmed, 2, 'A and K must be filteredAlreadyConfirmed')
  assert.equal(counts.filteredDedupe, 3, 'D, L, and M must be filteredDedupe (in-flight)')
  assert.equal(counts.filteredNoAsset, 0)

  // Also verify Hop-Continuation via `dependsOnStepIds` is NEVER suppressed even when route is composite-confirmed
  const contCounts = planner.persistDispatchPlan(
    storage.run(runId),
    {
      dispatched: false,
      totalBudgetUsd: 1,
      budgetUsd: 1,
      parentEvidenceIds: [],
      rejected: [],
      plan: [{
        id: 'cont-1',
        hypothesis: 'Hop continuation [continuation #1] on GET /api/v1/stage-b/sb_1.',
        origins: [ORIGIN_A],
        capabilities: ['http'],
        parentEvidenceIds: [],
        probeClass: 'authz_replay',
        skills: ['multihop-chains'],
        priority: 95,
        budgetUsd: 0.5,
      }],
    },
    new Set(),
    new Set(),
    { dependsOnStepIds: [inflightStep.id], preservePriority: true },
  )
  assert.equal(contCounts.enqueued, 1, 'Hop-Continuation with dependsOnStepIds MUST NEVER be suppressed')

  // Verify `classifyDuplicatePlannedStep` NEVER suppresses a `trialIndex > 0` candidate
  const confirmed = planner.alreadyConfirmedRefs(storage.run(runId), 100)
  const inFlight = buildInFlightTupleKeys(storage.listChainSteps(runId, run.goalRevision))
  assert.equal(
    planner.classifyDuplicatePlannedStep({
      title: 'Trial sibling',
      hypothesis: 'Repeat GET /api/v1/stage-b/sb_1 in trial 2.',
      category: 'broken-access-control',
      origins: [ORIGIN_A],
      trialIndex: 1,
    }, confirmed, inFlight),
    null,
    'multi-trial sibling (trialIndex > 0) MUST NEVER be suppressed',
  )
})

// ============================================================================
// 4. applyPlannerNewSteps (`parsedPlanner.data.newSteps`) tuple dedupe & invariants
// ============================================================================

test('applyPlannerNewSteps suppresses confirmed/in-flight tuples with exact funnel accounting and preserves zero-recall-loss invariants', async (t) => {
  const { storage } = makeStore(t, 'guardian-v8-dedupe-newsteps-')
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const run = storage.run(runId)
  const worker = makeWorker(storage, run, ORIGIN_A)
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!

  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/accounts/acc_10',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: null,
  })
  const activeStep = storage.addChainStep(run, {
    title: 'Active billing audit',
    hypothesis: 'Test cross-tenant access on GET /api/v1/billing/bil_7.',
    category: 'broken-access-control',
    priority: 85,
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
  })
  storage.updateChainStep(activeStep.id, { status: 'ready' })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const planner = plannerOf(execution)
  const funnel = emptyDispatchFunnel(2)

  const enqueued = planner.applyPlannerNewSteps({
    run: storage.run(runId),
    approvedOrigins: new Set([ORIGIN_A, ORIGIN_B]),
    existingSteps: storage.listChainSteps(runId, run.goalRevision),
    dynamicStepBudget: 40,
    factIds: new Set(),
    detLeadFactIds: new Set(),
    funnel,
    newSteps: [
      // Suppressed: confirmed (ORIGIN_A, /api/v1/accounts/:id, authz)
      {
        title: 'Re-test account IDOR',
        hypothesis: 'Check IDOR on GET /api/v1/accounts/acc_99.',
        category: 'broken-access-control',
        priority: 80,
        origins: [ORIGIN_A],
        skills: ['bola-idor-race'],
        dependsOnFactIds: [],
        dependsOnStepIds: [],
      },
      // Allowed: different class (`injection-input` -> sqli) on confirmed account route
      {
        title: 'SQLi on accounts filter',
        hypothesis: 'Probe SQLi differential on GET /api/v1/accounts/acc_99.',
        category: 'injection-input',
        priority: 80,
        origins: [ORIGIN_A],
        skills: ['injection-sqli-nosqli'],
        dependsOnFactIds: [],
        dependsOnStepIds: [],
      },
      // Suppressed: in-flight (ORIGIN_A, /api/v1/billing/:id, authz)
      {
        title: 'Duplicate billing BOLA',
        hypothesis: 'Verify BOLA on GET /api/v1/billing/bil_42.',
        category: 'broken-access-control',
        priority: 80,
        origins: [ORIGIN_A],
        skills: ['bola-idor-race'],
        dependsOnFactIds: [],
        dependsOnStepIds: [],
      },
      // Allowed: Hop-Continuation via checkpoint_cap skill on in-flight billing route
      {
        title: 'Continue billing hop chain',
        hypothesis: 'Continue sealed hop on GET /api/v1/billing/bil_42.',
        category: 'broken-access-control',
        priority: 95,
        origins: [ORIGIN_A],
        skills: ['multihop-chains', `${CHECKPOINT_CAP_SKILL_PREFIX}cap:hop_2:sealed_bill`],
        dependsOnFactIds: [],
        dependsOnStepIds: [],
      },
      // Allowed: multi-hop with 1 in-flight route + 1 novel route
      {
        title: 'Multi-hop billing to payout',
        hypothesis: 'Chain GET /api/v1/billing/bil_42 into POST /api/v1/payouts/pay_1.',
        category: 'broken-access-control',
        priority: 90,
        origins: [ORIGIN_A],
        skills: ['multihop-chains'],
        dependsOnFactIds: [],
        dependsOnStepIds: [],
      },
      // Allowed: novel route
      {
        title: 'Novel settings check',
        hypothesis: 'Test access control on PATCH /api/v1/settings/cfg_5.',
        category: 'broken-access-control',
        priority: 75,
        origins: [ORIGIN_A],
        skills: ['bola-idor-race'],
        dependsOnFactIds: [],
        dependsOnStepIds: [],
      },
    ],
  })

  assert.equal(enqueued, 4)
  assert.equal(funnel.planned, 6)
  assert.equal(funnel.enqueued, 4)
  assert.equal(funnel.filteredAlreadyConfirmed, 1)
  assert.equal(funnel.filteredDedupe, 1)
  assert.equal(
    funnel.planned,
    funnel.enqueued + funnel.filteredAlreadyConfirmed + funnel.filteredDedupe + funnel.filteredBudget + funnel.filteredCap + funnel.filteredNoAsset,
    'dispatch funnel accounting must remain exact',
  )
})

// ============================================================================
// 5. queueTierALeadSteps tuple dedupe + zero-recall-loss invariants
// ============================================================================

test('queueTierALeadSteps skips already-confirmed and in-flight (origin, normalizedRoute, classFamily) leads while seeding novel classes and routes', async (t) => {
  const { storage } = makeStore(t, 'guardian-v8-dedupe-tiera-')
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_A, ORIGIN_B], tier: 2 })
  const run = storage.run(runId)
  const worker = makeWorker(storage, run, ORIGIN_A)
  const assetA = run.candidates.find(c => c.origin === ORIGIN_A)!

  // Confirmed (ORIGIN_A, /api/v1/projects/:id, authz)
  addConfirmedFindingWithSpec({
    storage,
    run,
    worker,
    origin: ORIGIN_A,
    endpoint: '/api/v1/projects/prj_10',
    method: 'GET',
    category: 'broken-access-control',
    proofReceipt: null,
  })
  // In-flight (status='pending', trialIndex=0) (ORIGIN_A, /api/v1/records/:id, sqli)
  storage.addChainStep(run, {
    title: 'In-flight records SQLi',
    hypothesis: 'Test SQLi on GET /api/v1/records/rec_10.',
    category: 'injection-input',
    priority: 85,
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
  })
  // Only trialIndex > 0 sibling in-flight on (ORIGIN_A, /api/v1/audits/:id, authz) -> MUST NOT block!
  const auditSibling = storage.addChainStep(run, {
    title: 'Audit sibling',
    hypothesis: 'Sibling trial on GET /api/v1/audits/aud_1.',
    category: 'broken-access-control',
    priority: 85,
    targetAssetIds: [assetA.id],
    sourceOrigins: [ORIGIN_A],
    trialGroupId: 'tg-audit',
    trialIndex: 1,
  })
  storage.updateChainStep(auditSibling.id, { status: 'running' })

  const addTierAFact = (origin: string, method: string, endpoint: string, probeClass: string) =>
    storage.addFact(run, worker, {
      kind: 'note',
      origin,
      summary: `Tier-A ${probeClass} on ${method} ${endpoint}`,
      data: {
        kind: 'det_lead',
        source: 'program_graph',
        policyDiff: true,
        probeClass,
        method,
        endpoint,
        reason: `static slice for ${probeClass} on ${endpoint}`,
      },
    })

  // 1. SKIPPED: confirmed (ORIGIN_A, /api/v1/projects/:id, authz)
  addTierAFact(ORIGIN_A, 'GET', '/api/v1/projects/prj_99', 'authz_matrix')
  // 2. SEEDED: DIFFERENT class (`sqli_boolean` -> sqli) on confirmed projects route
  addTierAFact(ORIGIN_A, 'GET', '/api/v1/projects/prj_99', 'sqli_boolean')
  // 3. SEEDED: DIFFERENT origin (ORIGIN_B) on confirmed projects route+class
  addTierAFact(ORIGIN_B, 'GET', '/api/v1/projects/prj_99', 'authz_matrix')
  // 4. SKIPPED: in-flight (ORIGIN_A, /api/v1/records/:id, sqli)
  addTierAFact(ORIGIN_A, 'POST', '/api/v1/records/rec_77', 'sqli_boolean')
  // 5. SEEDED: DIFFERENT class (`authz_matrix` -> authz) on in-flight records route
  addTierAFact(ORIGIN_A, 'GET', '/api/v1/records/rec_77', 'authz_matrix')
  // 6. SEEDED: only trialIndex > 0 sibling is active on audits route
  addTierAFact(ORIGIN_A, 'GET', '/api/v1/audits/aud_2', 'authz_matrix')

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const seeded = plannerOf(execution).queueTierALeadSteps(
    storage.run(runId),
    new Set([ORIGIN_A, ORIGIN_B]),
    40,
    { sourceMounted: true },
  )

  assert.equal(seeded, 4, 'must skip confirmed & in-flight duplicates while seeding all 4 novel/different-class/different-origin/trial-only leads')
  const seededTitles = storage.listChainSteps(runId, run.goalRevision)
    .filter(s => s.title.startsWith('Tier-A code lead'))
    .map(s => `${s.sourceOrigins[0]}|${s.title}`)
  assert.equal(seededTitles.some(t => t.includes(`${ORIGIN_A}|`) && t.includes('authz_matrix') && t.includes('/projects/')), false)
  assert.equal(seededTitles.some(t => t.includes(`${ORIGIN_A}|`) && t.includes('sqli_boolean') && t.includes('/records/')), false)
  assert.equal(seededTitles.some(t => t.includes(`${ORIGIN_A}|`) && t.includes('sqli_boolean') && t.includes('/projects/')), true)
  assert.equal(seededTitles.some(t => t.includes(`${ORIGIN_B}|`) && t.includes('authz_matrix') && t.includes('/projects/')), true)
  assert.equal(seededTitles.some(t => t.includes(`${ORIGIN_A}|`) && t.includes('authz_matrix') && t.includes('/records/')), true)
  assert.equal(seededTitles.some(t => t.includes(`${ORIGIN_A}|`) && t.includes('authz_matrix') && t.includes('/audits/')), true)
})

// ============================================================================
// 6. Pure key normalization sanity check
// ============================================================================

test('plannerDedupeTupleKey normalizes concrete IDs and category families cleanly', () => {
  assert.equal(
    plannerDedupeTupleKey(ORIGIN_A, '/api/v1/orders/ord_123?expand=items', 'broken-access-control'),
    `${ORIGIN_A}\u0000/api/v1/orders/:id\u0000authz`,
  )
  assert.equal(
    plannerDedupeTupleKey(ORIGIN_A, '/api/v1/orders/ord_456', 'bola'),
    `${ORIGIN_A}\u0000/api/v1/orders/:id\u0000authz`,
  )
  assert.notEqual(
    plannerDedupeTupleKey(ORIGIN_A, '/api/v1/orders/ord_123', 'broken-access-control'),
    plannerDedupeTupleKey(ORIGIN_A, '/api/v1/orders/ord_123', 'injection-input'),
  )
  assert.equal(plannerDedupeTupleKey(ORIGIN_A, '/', 'broken-access-control'), null)
  const emptyConfirmed: PlannerConfirmedRef[] = []
  assert.equal(buildConfirmedTupleKeySets(emptyConfirmed).all.size, 0)
})
