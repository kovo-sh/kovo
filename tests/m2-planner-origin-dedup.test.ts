/**
 * M2 R5 Planner Origin Affinity, Confirmed-Step Dedup, Flat Stem Balance, and Wave-1 Floor Tests.
 *
 * Covers (100% generic synthetic fixtures — zero app/route/persona hardcoding):
 *  1. Single-monorepo & partial-mount multi-origin route affinity (`resolveRepoOriginAffinity`
 *     Pass 2 + `promoteInvariantHypothesesToWave1ChainSteps` route-level matching ahead of
 *     whole-repo binding + cross-service sibling active origin preservation).
 *  2. Multi-origin / multi-hop / authz-alias confirmed-step dedup suppression
 *     (`canonicalPlannerDedupeFamily` + `plannerDedupeTupleKey` + `classifyDuplicatePlannedStep`
 *     + `applyPlannerNewSteps`) without suppressing distinct unconfirmed routes, unrelated
 *     non-authz classes, different origins, or hop-continuations/trials.
 *  3. Flat `src/<service>*` service-stem bucket splitting (`selectBalancedRepoSourceCandidates`),
 *     route-verified per-origin Wave-1 coverage floor at `>= whiteBoxCapPriority` that is NOT
 *     satisfied merely by listing an origin without probing routes on it, and per-origin grey-box
 *     fallback seeding with recorded API dependencies (`buildWave1UncoveredOriginFallbackSteps`).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { describe, test } from 'node:test'
import { classifyHostTier } from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  WHITEBOX_BLACKBOX_CAP_PRIORITY,
  computeHostTiers,
  confirmedCategoryFamily,
} from '../src/server/exec-dispatch.ts'
import {
  buildWave1UncoveredOriginFallbackSteps,
  canonicalPlannerDedupeFamily,
  selectBalancedRepoSourceCandidates,
} from '../src/server/exec-recon-multiorigin.ts'
import {
  CHECKPOINT_CAP_SKILL_PREFIX,
  plannerDedupeTupleKey,
  resolveRepoOriginAffinity,
  type ExecReconPlanner,
  type PlannerConfirmedRef,
} from '../src/server/exec-recon-planner.ts'
import { Execution, emptyDispatchFunnel } from '../src/server/execution.ts'
import type { InvariantHypothesis, SynthesizeInvariantsResult } from '../src/server/invariant-synthesizer.ts'
import type { ReplayProofReceiptRow } from '../src/server/schema.ts'
import type { Assignment, Run, Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const API_ORIGIN = 'https://core-api.synth.invalid'
const EDGE_ORIGIN = 'https://edge-gw.synth.invalid'
const PORTAL_ORIGIN = 'https://portal-ui.synth.invalid'
const AUTH_ORIGIN = 'https://idp-auth.synth.invalid'

function stubBackend(): WorkerBackend {
  return {
    name: 'stub-m2-r5-planner-dedup',
    async run() {
      return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} }
    },
  } as unknown as WorkerBackend
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function plannerOf(execution: Execution): ExecReconPlanner {
  return (execution as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

function makeHyp(overrides: Partial<InvariantHypothesis> & { id: string }): InvariantHypothesis {
  return {
    kind: 'policy_asymmetry',
    capabilityKind: 'policy_asymmetry',
    promotionStatus: 'capability_only',
    mode: 'white-box',
    entity: 'resource',
    surface: 'http',
    severity: 'high',
    score: 0.88,
    summary: `Differential authorization check on ${overrides.targetRoute ?? '/api/v1/items'}`,
    preconditions: ['two tenants'],
    verificationHint: 'Compare control vs variant responses',
    evidence: [],
    ...overrides,
  }
}

function makeWorker(storage: Store, run: Run, origin = API_ORIGIN): Assignment {
  const asset = run.candidates.find(c => c.origin === origin) ?? run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'm2-r5-dedup', 'test worker', {
    sourceOrigins: [origin],
  })
  return storage.updateWorker(worker.id, { status: 'running', lease: randomUUID() })!
}

function addConfirmedCompositeFinding(input: {
  storage: Store
  run: Run
  worker: Assignment
  origin: string
  endpoint: string
  category: Finding['category']
  terminalVulnClass?: string
  hops?: Array<{ hopId: string; origin?: string; method?: string; pathAndQuery: string }>
}): string {
  const findingId = `fnd-${randomUUID().slice(0, 8)}`
  const asset = input.run.candidates.find(c => c.origin === input.origin) ?? input.run.candidates[0]!
  const hops = input.hops ?? [
    { hopId: 'h1', origin: input.origin, method: 'POST', pathAndQuery: '/api/v1/prep/p_1' },
    { hopId: 'h2', origin: input.origin, method: 'GET', pathAndQuery: input.endpoint },
  ]
  const termHop = hops[hops.length - 1]!
  const spec = {
    kind: 'http_chain',
    title: `Confirmed ${input.category} on ${input.endpoint}`,
    category: input.category,
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Verified differential proof.',
    impact: 'Cross-tenant disclosure.',
    remediation: 'Enforce strict tenant authorization checks.',
    recheckInstructions: 'Replay control vs probe differential.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [{
      id: 'probe',
      role: 'probe',
      description: 'Probe step',
      expectedStatus: 200,
      request: { origin: input.origin, method: 'GET', pathAndQuery: input.endpoint, followRedirects: false },
    }],
  } as unknown as DeclarativeReplaySpec
  const receipt = {
    receipt: {
      vulnClass: input.terminalVulnClass ?? 'broken_access_control',
      target: { origin: termHop.origin ?? input.origin, method: termHop.method ?? 'GET', pathAndQuery: termHop.pathAndQuery },
      exchangeIds: ['ex-1', 'ex-2'],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Composite chain verified.',
    },
    verification: { confirmed: true, vulnClass: input.terminalVulnClass ?? 'broken_access_control', rule: 'composite:fresh_clean_replay' },
    compositeReceipt: {
      chainId: `chain-${randomUUID().slice(0, 8)}`,
      terminalVulnClass: input.terminalVulnClass ?? 'broken_access_control',
      hops: hops.map(h => ({
        hopId: h.hopId,
        surface: 'http',
        target: { origin: h.origin ?? input.origin, method: h.method ?? 'GET', pathAndQuery: h.pathAndQuery },
        exchangeIds: ['ex-1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Hop ${h.hopId}`,
        producedCapabilities: [],
        consumedCapabilities: [],
      })),
      causalEdges: [],
      terminalImpact: {
        terminalHopId: termHop.hopId,
        claimedImpact: 'Unauthorized readback verified.',
        preChainControlExchangeIds: [],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    },
    compositeVerification: {
      confirmed: true,
      chainId: 'chain-verified',
      terminalVulnClass: input.terminalVulnClass ?? 'broken_access_control',
      replayMode: 'fresh_clean_replay',
      modeBVerified: true,
      hopCount: hops.length,
      verifiedEdges: [],
      reason: 'ok',
    },
  }
  const specRow = input.storage.createReplaySpec(input.run, input.worker, findingId, spec, [input.origin], {
    initialAttemptCount: 1,
    verifiedInline: true,
    proof: {
      replaySpecId: '',
      findingId,
      verdict: 'confirmed',
      runtime: 'ts',
      scriptSha256: 'b'.repeat(64),
      artifactId: `art-${randomUUID().slice(0, 8)}`,
      receipt: receipt as unknown as ReplayProofReceiptRow,
      createdAt: Date.now(),
    },
  })
  const finding: Finding = {
    id: findingId,
    title: `Confirmed ${input.category} on ${input.endpoint}`,
    severity: 'high',
    category: input.category,
    cwe: 'CWE-639',
    origin: input.origin,
    status: 'confirmed',
    reason: `Verified finding on ${input.endpoint}`,
    remediation: 'Enforce tenant authorization.',
    evidenceIds: [],
    replaySpecId: specRow.id,
    scopeRevision: input.run.scopeRevision,
    confidence: 'high',
    verification: 'Zero-LLM inline replay verdict: confirmed',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
  }
  input.storage.upsertChainFinding(input.run, asset.id, finding, specRow.id, [input.origin])
  return findingId
}

describe('1. Multi-origin single-monorepo route affinity & cross-service sibling preservation', () => {
  test('resolveRepoOriginAffinity Pass 2 does NOT bind a single monorepo serving N origins to the highest-overlap origin', () => {
    const origins = [API_ORIGIN, EDGE_ORIGIN, PORTAL_ORIGIN]
    const singleMono = resolveRepoOriginAffinity({
      approvedOrigins: origins,
      repos: [{
        repo: '/repos/unified-monorepo',
        declaredRoutes: [
          '/api/v1/orders/:id',
          '/api/v1/billing/:id',
          '/api/v1/workspaces/:id',
          '/edge/webhooks/deliver',
          '/portal/dashboard',
        ],
      }],
      liveEndpoints: [
        { origin: API_ORIGIN, pathTemplate: '/api/v1/orders/1', status: 200 },
        { origin: API_ORIGIN, pathTemplate: '/api/v1/billing/2', status: 200 },
        { origin: API_ORIGIN, pathTemplate: '/api/v1/workspaces/3', status: 200 },
        { origin: EDGE_ORIGIN, pathTemplate: '/edge/webhooks/deliver', status: 200 },
      ],
    })
    assert.equal(singleMono.length, 1)
    assert.equal(singleMono[0]!.confidence, 'unmapped', 'single monorepo serving 3 origins must not whole-repo bind to 1 origin in Pass 2')
    assert.equal(singleMono[0]!.origin, undefined)

    // Partial mount (2 repos < 3 origins): repo spanning 2 live origins stays unmapped while single-origin repo still binds.
    const partialMount = resolveRepoOriginAffinity({
      approvedOrigins: origins,
      repos: [
        {
          repo: 'multi-svc-bundle',
          declaredRoutes: ['/api/v1/orders/:id', '/api/v1/billing/:id', '/edge/webhooks/deliver'],
        },
        {
          repo: 'portal-only-svc',
          declaredRoutes: ['/portal/dashboard', '/portal/profile'],
        },
      ],
      liveEndpoints: [
        { origin: API_ORIGIN, pathTemplate: '/api/v1/orders/1', status: 200 },
        { origin: API_ORIGIN, pathTemplate: '/api/v1/billing/2', status: 200 },
        { origin: EDGE_ORIGIN, pathTemplate: '/edge/webhooks/deliver', status: 200 },
        { origin: PORTAL_ORIGIN, pathTemplate: '/portal/dashboard', status: 200 },
      ],
    })
    const byRepo = new Map(partialMount.map(m => [m.repo, m]))
    assert.equal(byRepo.get('multi-svc-bundle')?.confidence, 'unmapped', 'partial-mount repo matching >=2 live origins must stay unmapped')
    assert.equal(byRepo.get('portal-only-svc')?.origin, PORTAL_ORIGIN, 'single-origin-only repo in partial mount still binds cleanly')
  })

  test('promoteInvariantHypothesesToWave1ChainSteps routes single-monorepo hypotheses by live route/fuzzy prefix without starving sibling origins and preserves siblings on cross-service chains', async (t) => {
    const origins = [API_ORIGIN, EDGE_ORIGIN, PORTAL_ORIGIN]
    const { storage } = makeStore(t, 'kovo-m2-r5-monorepo-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = plannerOf(exec)

    // API origin has many live routes; edge & portal each have distinct routes.
    for (const [origin, method, path, risk] of [
      [API_ORIGIN, 'GET', '/api/v1/orders/:id', 92],
      [API_ORIGIN, 'POST', '/api/v1/invoices/:id/approve', 90],
      [API_ORIGIN, 'GET', '/api/v1/tenants/:id/members', 88],
      [EDGE_ORIGIN, 'POST', '/edge/webhooks/deliver', 94],
      [EDGE_ORIGIN, 'GET', '/edge/downloads/:id', 86],
      [PORTAL_ORIGIN, 'POST', '/portal/exports/:id/trigger', 84],
    ] as const) {
      storage.upsertEndpoint({
        runId,
        scopeRevision: run.scopeRevision,
        origin,
        method,
        pathTemplate: path,
        riskScore: risk,
        source: 'spa_crawl',
      })
    }

    const synthesis: SynthesizeInvariantsResult = {
      mode: 'white-box',
      hypotheses: [
        makeHyp({
          id: 'hyp_edge_live',
          entity: 'webhook',
          targetRoute: 'POST /edge/webhooks/deliver',
          location: { file: 'unified-monorepo/src/edge-service.ts', line: 24 },
          summary: 'Webhook delivery endpoint skips signature verification',
        }),
        makeHyp({
          id: 'hyp_portal_fuzzy',
          entity: 'export',
          targetRoute: 'POST /portal/exports',
          location: { file: 'unified-monorepo/src/portal-service.ts', line: 41 },
          summary: 'Portal export route lacks tenant ownership check',
        }),
        makeHyp({
          id: 'hyp_api_live',
          entity: 'order',
          targetRoute: 'GET /api/v1/orders/:id',
          location: { file: 'unified-monorepo/src/api-service.ts', line: 18 },
          summary: 'Order fetch allows cross-tenant object read',
        }),
        makeHyp({
          id: 'hyp_cross_service',
          kind: 'trust_boundary_mismatch',
          entity: 'boundary',
          targetRoute: 'POST /edge/webhooks/deliver',
          location: { file: 'unified-monorepo/src/edge-service.ts', line: 70 },
          summary: 'Forwarded service token trusted across boundary without audience validation',
        }),
      ],
      capabilitySeeds: [],
    }

    // Even if a coarse precomputed whole-repo mapping points the monorepo at API_ORIGIN,
    // route-level liveOriginsByRoute + shared-monorepo guard must still bind edge & portal cleanly.
    const createdIds = planner.promoteInvariantHypothesesToWave1ChainSteps(storage.run(runId), synthesis, {
      mountedRepos: ['/repos/unified-monorepo'],
      repoOriginMappings: [{
        repo: '/repos/unified-monorepo',
        root: 'unified-monorepo',
        origin: API_ORIGIN,
        confidence: 'live_route',
        score: 98,
        evidence: ['coarse whole-repo live_route binding to api'],
      }],
      maxSteps: 6,
    })

    assert.equal(createdIds.length, 4, 'all 4 monorepo hypotheses must be promoted')
    const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
    const edgeStep = steps.find(s => s.hypothesis.includes('hyp_edge_live'))!
    const portalStep = steps.find(s => s.hypothesis.includes('hyp_portal_fuzzy'))!
    const apiStep = steps.find(s => s.hypothesis.includes('hyp_api_live'))!
    const crossStep = steps.find(s => s.hypothesis.includes('hyp_cross_service'))!

    assert.deepEqual(edgeStep.sourceOrigins, [EDGE_ORIGIN], 'edge route must bind to EDGE_ORIGIN, not API_ORIGIN')
    assert.deepEqual(portalStep.sourceOrigins, [PORTAL_ORIGIN], 'portal fuzzy route must bind to PORTAL_ORIGIN, not API_ORIGIN')
    assert.deepEqual(apiStep.sourceOrigins, [API_ORIGIN], 'api route must bind to API_ORIGIN')
    assert.equal(crossStep.sourceOrigins[0], EDGE_ORIGIN, 'cross-service chain keeps matched route origin primary')
    assert.deepEqual(
      new Set(crossStep.sourceOrigins),
      new Set(origins),
      'cross-service trust_boundary_mismatch must preserve all sibling active origins',
    )
  })
})

describe('2. Multi-origin / multi-hop / authz-alias confirmed-step dedup suppression', () => {
  test('canonicalPlannerDedupeFamily unifies all authz aliases without colliding with non-authz classes', () => {
    const authzAliases = [
      'bola',
      'bfla',
      'idor',
      'broken-access-control',
      'broken_access_control',
      'dual_tenant_abac',
      'cross_tenant_read',
      'cross_tenant_write',
      'cross_tenant_chain',
      'rbac_bypass',
      'privilege_escalation',
      'auth_bypass',
    ]
    for (const alias of authzAliases) {
      assert.equal(
        canonicalPlannerDedupeFamily(alias, confirmedCategoryFamily),
        'authz',
        `authz alias "${alias}" must normalize to "authz"`,
      )
      assert.equal(
        plannerDedupeTupleKey(API_ORIGIN, '/api/v1/vault/obj_42', alias),
        `${API_ORIGIN}\u0000/api/v1/vault/:id\u0000authz`,
      )
    }

    for (const nonAuthz of ['injection-input', 'sqli_boolean', 'cors-client-side', 'stored_xss', 'ssrf', 'misconfig-exposure', 'auth-identity']) {
      assert.notEqual(
        canonicalPlannerDedupeFamily(nonAuthz, confirmedCategoryFamily),
        'authz',
        `non-authz class "${nonAuthz}" must remain distinct from "authz"`,
      )
    }
  })

  test('classifyDuplicatePlannedStep and applyPlannerNewSteps suppress multi-origin/multi-hop/cross-alias repeats of composite-confirmed terminal routes while allowing distinct routes and non-authz classes', async (t) => {
    const { storage } = makeStore(t, 'kovo-m2-r5-dedup-')
    const { runId } = await setupApprovedRun(storage, { seeds: [API_ORIGIN, EDGE_ORIGIN], tier: 2 })
    const run = storage.run(runId)
    const worker = makeWorker(storage, run, API_ORIGIN)

    addConfirmedCompositeFinding({
      storage,
      run,
      worker,
      origin: API_ORIGIN,
      endpoint: '/api/v1/records/rec_101',
      category: 'broken-access-control',
      terminalVulnClass: 'broken_access_control',
      hops: [
        { hopId: 'h1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/api/v1/sessions/init' },
        { hopId: 'h2', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/v1/records/rec_101' },
      ],
    })

    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = plannerOf(exec)
    const confirmed: PlannerConfirmedRef[] = [
      ...planner.alreadyConfirmedRefs(storage.run(runId), 100),
      // Also test untyped composite receipt (empty probeClass -> only in compositeRoutes).
      { origin: EDGE_ORIGIN, path: '/edge/artifacts/art_7', hasCompositeReceipt: true },
    ]

    // 1. Multi-origin single-route with authz aliases -> SUPPRESSED
    for (const alias of ['bola', 'broken_access_control', 'dual_tenant_abac', 'bfla', 'idor', 'cross_tenant_read']) {
      assert.equal(
        planner.classifyDuplicatePlannedStep({
          title: `Re-verify ${alias} on records`,
          hypothesis: `Check ${alias} read on GET /api/v1/records/rec_999.`,
          category: alias,
          origins: [API_ORIGIN, EDGE_ORIGIN],
        }, confirmed),
        'already_confirmed',
        `multi-origin repeat with alias "${alias}" must be suppressed`,
      )
    }

    // 2. Multi-origin multi-hop whose terminal route is already composite-confirmed -> SUPPRESSED
    assert.equal(
      planner.classifyDuplicatePlannedStep({
        title: 'Multi-hop cross-origin retry on records',
        hypothesis: 'Use POST /edge/token/exchange then fetch GET /api/v1/records/rec_555.',
        category: 'dual_tenant_abac',
        origins: [EDGE_ORIGIN, API_ORIGIN],
      }, confirmed),
      'already_confirmed',
      'multi-origin multi-hop targeting already-confirmed terminal route must be suppressed',
    )

    // 3. Untyped composite route on EDGE_ORIGIN with multi-origin step -> SUPPRESSED
    assert.equal(
      planner.classifyDuplicatePlannedStep({
        title: 'Repeat untyped edge artifact chain',
        hypothesis: 'Chain POST /api/v1/bootstrap into GET /edge/artifacts/art_99.',
        category: 'cross_tenant_read',
        origins: [API_ORIGIN, EDGE_ORIGIN],
      }, confirmed),
      'already_confirmed',
      'untyped composite-confirmed terminal route on matching origin must be suppressed',
    )

    // 4. ALLOWED: genuinely distinct unconfirmed terminal route on the SAME origin
    assert.equal(
      planner.classifyDuplicatePlannedStep({
        title: 'Novel terminal target on same origin',
        hypothesis: 'Pivot from GET /api/v1/records/rec_101 into GET /api/v1/exports/exp_42.',
        category: 'bola',
        origins: [API_ORIGIN, EDGE_ORIGIN],
      }, confirmed),
      null,
      'genuinely distinct unconfirmed terminal route must NOT be suppressed',
    )

    // 5. ALLOWED: non-authz unrelated class on the SAME composite-confirmed route
    for (const nonAuthz of ['injection-input', 'cors-client-side', 'ssrf']) {
      assert.equal(
        planner.classifyDuplicatePlannedStep({
          title: `Probe ${nonAuthz} on records`,
          hypothesis: `Chain POST /edge/token/exchange into GET /api/v1/records/rec_555 for ${nonAuthz}.`,
          category: nonAuthz,
          origins: [API_ORIGIN, EDGE_ORIGIN],
        }, confirmed),
        null,
        `non-authz unrelated class "${nonAuthz}" on confirmed authz route must NOT be suppressed`,
      )
    }

    // 6. ALLOWED: different unconfirmed origin alone
    assert.equal(
      planner.classifyDuplicatePlannedStep({
        title: 'Check records on edge origin only',
        hypothesis: 'Verify BOLA on GET /api/v1/records/rec_555.',
        category: 'bola',
        origins: [EDGE_ORIGIN],
      }, confirmed),
      null,
      'different unconfirmed origin alone must NOT be suppressed',
    )

    // 7. ALLOWED: Hop-Continuation & trialIndex > 0 sibling NEVER suppressed
    assert.equal(
      planner.classifyDuplicatePlannedStep({
        title: 'Continuation on confirmed records',
        hypothesis: 'Continue chain on GET /api/v1/records/rec_555.',
        category: 'bola',
        origins: [API_ORIGIN, EDGE_ORIGIN],
        skills: [`${CHECKPOINT_CAP_SKILL_PREFIX}cap:hop_1:sealed_tok`],
      }, confirmed),
      null,
      'hop continuation must never be suppressed',
    )
    assert.equal(
      planner.classifyDuplicatePlannedStep({
        title: 'Trial sibling on confirmed records',
        hypothesis: 'Retry GET /api/v1/records/rec_555.',
        category: 'bola',
        origins: [API_ORIGIN, EDGE_ORIGIN],
        trialIndex: 1,
      }, confirmed),
      null,
      'multi-trial sibling (trialIndex > 0) must never be suppressed',
    )

    // 8. End-to-end funnel check via applyPlannerNewSteps
    const funnel = emptyDispatchFunnel(2)
    const enqueued = planner.applyPlannerNewSteps({
      run: storage.run(runId),
      approvedOrigins: new Set([API_ORIGIN, EDGE_ORIGIN]),
      existingSteps: storage.listChainSteps(runId, run.goalRevision),
      dynamicStepBudget: 30,
      factIds: new Set(),
      detLeadFactIds: new Set(),
      funnel,
      newSteps: [
        {
          title: 'Multi-origin ABAC retry',
          hypothesis: 'Setup via POST /edge/session then read GET /api/v1/records/rec_777.',
          category: 'dual_tenant_abac',
          priority: 90,
          origins: [EDGE_ORIGIN, API_ORIGIN],
          skills: ['bola-idor-race'],
          dependsOnFactIds: [],
          dependsOnStepIds: [],
        },
        {
          title: 'Distinct target route on API',
          hypothesis: 'Test BOLA on GET /api/v1/invoices/inv_88.',
          category: 'bola',
          priority: 85,
          origins: [API_ORIGIN],
          skills: ['bola-idor-race'],
          dependsOnFactIds: [],
          dependsOnStepIds: [],
        },
        {
          title: 'SQLi on confirmed records route',
          hypothesis: 'Test SQLi differential on GET /api/v1/records/rec_777.',
          category: 'injection-input',
          priority: 84,
          origins: [API_ORIGIN, EDGE_ORIGIN],
          skills: ['injection-sqli-nosqli'],
          dependsOnFactIds: [],
          dependsOnStepIds: [],
        },
      ],
    })
    assert.equal(enqueued, 2, 'only distinct target route + non-authz class should enqueue')
    assert.equal(funnel.filteredAlreadyConfirmed, 1)
  })
})

describe('3. Flat src/<service>* branch splitting, route-verified Wave-1 floor & per-origin grey-box fallback', () => {
  test('selectBalancedRepoSourceCandidates splits flat src/<stem>.ts files by service stem while keeping nested service subdirs grouped', () => {
    const candidates: Array<{ full: string; relPath: string; depth: number }> = []
    // 30 flat files under src/service-a* (would starve service-b & service-c if collapsed to "src")
    candidates.push({ full: '/r/src/service-a.ts', relPath: 'src/service-a.ts', depth: 1 })
    candidates.push({ full: '/r/src/service-a-routes.ts', relPath: 'src/service-a-routes.ts', depth: 1 })
    candidates.push({ full: '/r/src/service-a-handlers.ts', relPath: 'src/service-a-handlers.ts', depth: 1 })
    for (let i = 1; i <= 25; i += 1) {
      const name = `src/service-a_${String(i).padStart(2, '0')}.ts`
      candidates.push({ full: `/r/${name}`, relPath: name, depth: 1 })
    }
    // Flat sibling services
    candidates.push({ full: '/r/src/service-b.ts', relPath: 'src/service-b.ts', depth: 1 })
    candidates.push({ full: '/r/src/service-b-routes.ts', relPath: 'src/service-b-routes.ts', depth: 1 })
    candidates.push({ full: '/r/src/service-c.ts', relPath: 'src/service-c.ts', depth: 1 })
    // Nested service subdirs
    candidates.push({ full: '/r/src/billing/routes.ts', relPath: 'src/billing/routes.ts', depth: 2 })
    candidates.push({ full: '/r/src/billing/handlers.ts', relPath: 'src/billing/handlers.ts', depth: 2 })

    const picked = selectBalancedRepoSourceCandidates(candidates, 8)
    assert.equal(picked.length, 8)
    const rels = new Set(picked.map(p => p.relPath))
    const serviceACount = [...rels].filter(r => r.startsWith('src/service-a')).length
    assert.ok(serviceACount >= 2 && serviceACount <= 3, `service-a bucket must get fair share (2-3), got ${serviceACount}`)
    assert.ok(rels.has('src/service-b.ts') || rels.has('src/service-b-routes.ts'), 'flat src/service-b* must NOT be starved by src/service-a*')
    assert.ok(rels.has('src/service-c.ts'), 'flat src/service-c.ts must NOT be starved by src/service-a*')
    assert.ok(rels.has('src/billing/routes.ts'), 'nested src/billing/* must remain grouped as a distinct branch')
  })

  test('buildWave1UncoveredOriginFallbackSteps enforces route-verified coverage floor at >= whiteBoxCapPriority', () => {
    const entries = [
      { origin: API_ORIGIN, riskTier: 'high' as const, surfaceTags: ['api'], rationale: 'core api' },
      { origin: EDGE_ORIGIN, riskTier: 'high' as const, surfaceTags: ['upload'], rationale: 'edge gw' },
      { origin: PORTAL_ORIGIN, riskTier: 'medium' as const, surfaceTags: ['auth'], rationale: 'portal' },
    ]
    const hostTiers = computeHostTiers([API_ORIGIN, EDGE_ORIGIN, PORTAL_ORIGIN], entries)
    const discoveredEndpoints = [
      { origin: API_ORIGIN, method: 'GET', pathTemplate: '/api/v1/orders/:id', riskScore: 92 },
      { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/edge/webhooks/deliver', riskScore: 94 },
      { origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/edge/files/:id', riskScore: 86 },
      { origin: PORTAL_ORIGIN, method: 'POST', pathTemplate: '/portal/invites/accept', riskScore: 88 },
    ]

    // Existing step lists EDGE_ORIGIN & PORTAL_ORIGIN as origins, BUT only probes API_ORIGIN's route!
    const resUncovered = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps: [{
        status: 'ready',
        sourceOrigins: [EDGE_ORIGIN, API_ORIGIN, PORTAL_ORIGIN],
        title: 'Source audit on orders',
        hypothesis: 'Probe cross-tenant read on GET /api/v1/orders/:id across services.',
      }],
      discoveredEndpointOrigins: new Set([API_ORIGIN, EDGE_ORIGIN, PORTAL_ORIGIN]),
      discoveredEndpoints,
      finalHostTiers: hostTiers,
      sourceMounted: true,
      codeAuditStepsCreated: 3,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
    })

    assert.equal(resUncovered.uncoveredAddedCount, 2, 'EDGE_ORIGIN and PORTAL_ORIGIN must NOT be marked covered by a step that only probes API routes')
    const edgeFloor = resUncovered.seededSteps.find(s => s.origins[0] === EDGE_ORIGIN)
    const portalFloor = resUncovered.seededSteps.find(s => s.origins[0] === PORTAL_ORIGIN)
    const apiFloor = resUncovered.seededSteps.find(s => s.origins[0] === API_ORIGIN)
    assert.ok(edgeFloor, 'EDGE_ORIGIN must receive a Wave-1 route-verified coverage floor step')
    assert.ok(portalFloor, 'PORTAL_ORIGIN must receive a Wave-1 route-verified coverage floor step')
    assert.equal(apiFloor, undefined, 'API_ORIGIN already has a route-verified step probing /api/v1/orders/:id')
    assert.ok(
      edgeFloor.priority >= WHITEBOX_BLACKBOX_CAP_PRIORITY,
      `route-verified floor priority (${edgeFloor.priority}) must NOT drop below whiteBoxCapPriority (${WHITEBOX_BLACKBOX_CAP_PRIORITY})`,
    )
    assert.ok(
      portalFloor.priority >= WHITEBOX_BLACKBOX_CAP_PRIORITY,
      `route-verified floor priority (${portalFloor.priority}) must NOT drop below whiteBoxCapPriority (${WHITEBOX_BLACKBOX_CAP_PRIORITY})`,
    )
    assert.ok(edgeFloor.hypothesis.includes('/edge/webhooks/deliver'), 'floor step must cite concrete discovered routes on EDGE_ORIGIN')

    // Once a step actually probes routes on EDGE_ORIGIN, EDGE_ORIGIN IS satisfied.
    const resCovered = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps: [
        {
          status: 'ready',
          sourceOrigins: [API_ORIGIN],
          title: 'Orders audit',
          hypothesis: 'Probe GET /api/v1/orders/:id.',
        },
        {
          status: 'ready',
          sourceOrigins: [EDGE_ORIGIN],
          title: 'Edge webhook audit',
          hypothesis: 'Probe POST /edge/webhooks/deliver.',
        },
        {
          status: 'ready',
          sourceOrigins: [PORTAL_ORIGIN],
          title: 'Portal invite audit',
          hypothesis: 'Probe POST /portal/invites/accept.',
        },
      ],
      discoveredEndpointOrigins: new Set([API_ORIGIN, EDGE_ORIGIN, PORTAL_ORIGIN]),
      discoveredEndpoints,
      finalHostTiers: hostTiers,
      sourceMounted: true,
      codeAuditStepsCreated: 3,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
    })
    assert.equal(resCovered.uncoveredAddedCount, 0, 'all 3 origins have route-verified coverage so no extra fallback steps should be added')
  })

  test('store-backed grey-box runs with recorded API dependencies (0 live 2xx exchanges) still seed per-origin uncovered fallback steps', async (t) => {
    const origins = [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN]
    const { storage } = makeStore(t, 'kovo-m2-r5-prefloor-gb-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: origins, tier: 2 })

    // Seed spec-only endpoints + apiDependencies across 3 origins with ZERO broker_exchanges (pre-floor state).
    const ep1 = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: AUTH_ORIGIN, method: 'POST',
      pathTemplate: '/oauth/token', riskScore: 92, source: 'openapi',
    })
    const ep2 = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST',
      pathTemplate: '/api/v1/exports/create', riskScore: 95, source: 'openapi',
    })
    const ep3 = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'GET',
      pathTemplate: '/edge/downloads/:id', riskScore: 90, source: 'openapi',
    })
    const ep4 = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST',
      pathTemplate: '/api/v1/invites/send', riskScore: 88, source: 'openapi',
    })
    const ep5 = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: AUTH_ORIGIN, method: 'POST',
      pathTemplate: '/oauth/invite/accept', riskScore: 87, source: 'openapi',
    })
    const ep6 = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'POST',
      pathTemplate: '/edge/files/upload', riskScore: 86, source: 'openapi',
    })
    storage.recordApiDependency({
      runId, producerEndpointId: ep1.id, consumerEndpointId: ep2.id, resourceKey: 'access_token',
    })
    storage.recordApiDependency({
      runId, producerEndpointId: ep2.id, consumerEndpointId: ep3.id, resourceKey: 'download_url',
    })
    storage.recordApiDependency({
      runId, producerEndpointId: ep4.id, consumerEndpointId: ep5.id, resourceKey: 'invite_token',
    })
    storage.recordApiDependency({
      runId, producerEndpointId: ep5.id, consumerEndpointId: ep6.id, resourceKey: 'session_token',
    })

    const entries = [
      { origin: AUTH_ORIGIN, riskTier: 'high' as const, surfaceTags: ['auth'], rationale: 'auth' },
      { origin: API_ORIGIN, riskTier: 'high' as const, surfaceTags: ['api'], rationale: 'api' },
      { origin: EDGE_ORIGIN, riskTier: 'high' as const, surfaceTags: ['upload'], rationale: 'edge' },
    ]
    const hostTiers = computeHostTiers(origins, entries)
    const res = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps: [],
      discoveredEndpointOrigins: new Set(origins),
      finalHostTiers: hostTiers,
      sourceMounted: false,
      codeAuditStepsCreated: 0,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
      storage,
      run: storage.run(runId),
    })

    const originFallbackSteps = res.seededSteps.filter(s => s.title.startsWith('Surface & chain investigation'))
    assert.deepEqual(
      new Set(originFallbackSteps.map(s => s.origins[0])),
      new Set(origins),
      'store-backed producer/consumer dependencies must NOT suppress per-origin uncovered fallback steps for any active origin',
    )
    for (const step of originFallbackSteps) {
      assert.ok(
        step.priority >= WHITEBOX_BLACKBOX_CAP_PRIORITY,
        `per-origin route-verified fallback priority (${step.priority}) must stay >= whiteBoxCapPriority`,
      )
    }
  })
})
