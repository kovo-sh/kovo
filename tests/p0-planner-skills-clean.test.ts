/**
 * Phase 0 Non-Kernel Cleanup Regression Suite (`tests/p0-planner-skills-clean.test.ts`).
 *
 * Verifies:
 *  1. `planCompositeWorkflows` uses generic dependency/causal graph chaining (zero hardcoded
 *     4-archetype benchmark recipes) and `classifySemanticEndpointClasses` uses structural signals.
 *  2. `gb-dataflow-synthesizer.ts` & `capability-consumer-frontier.ts` match strictly on structural
 *     runtime signals (no speculative non-live token fabrication, no prefix/host-role tables, no
 *     multiTenant -> basePersona actor rewrite) and strictly bound `persistValueFlowCausalEdges`
 *     both by `slotBudget > 0` and per-run cap (`MAX_VALUEFLOW_EDGES_PER_RUN <= 60`, fixing R10
 *     3,087-edge spam).
 *  3. `invariant-runtime-parity.ts` removes `facets` from `WRAPPER_SEG_RE` and fintech verb-noun
 *     ladders while retaining structural OpenAPI/guard/ghost-route analyzers.
 *  4. `exec-recon-planner.ts` has zero `billingz` literals and neutral `HOP_CONTINUATION_DIRECTIVE`.
 *  5. `src/skills/multihop-chains.md` is crisp (~40 lines) and free of lab/oracle-schema dumps.
 *  6. `scripts/check-v8-contamination.ts` blocks structural lab-artifact regressions across
 *     `src/server/**` and `src/skills/**` while passing cleanly on the repository.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  formatContaminationReport,
  scanSourceTreeForContamination,
} from '../scripts/check-v8-contamination.ts'
import {
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import { rankCapabilityConsumerPairs } from '../src/server/capability-consumer-frontier.ts'
import { HOP_CONTINUATION_DIRECTIVE } from '../src/server/exec-recon-planner.ts'
import {
  MAX_VALUEFLOW_EDGES_PER_RUN,
  refreshGreyBoxValueFlowSteps,
  synthesizeGreyBoxDataflowGraph,
} from '../src/server/gb-dataflow-synthesizer.ts'
import {
  classifySemanticEndpointClasses,
  planCompositeWorkflows,
  type CompositeWorkflowNode,
} from '../src/server/graph-coordinator.ts'
import {
  classifyRuntimeDependencyEdgeKind,
  inferEntityName,
} from '../src/server/invariant-runtime-parity.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import { loadSkill } from '../src/server/skills.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

describe('Phase 0 planner, frontier, dataflow, skills & contamination cleanup', () => {
  test('1. planCompositeWorkflows chains arbitrary dependency edges without hardcoded 4-archetype keys', () => {
    const nodes: CompositeWorkflowNode[] = [
      {
        id: 'n-produce',
        origin: 'https://svc-a.example',
        serviceScope: 'svc-a',
        endpoint: 'POST /api/v1/widgets',
        sinkKind: 'producer',
        summary: 'Creates widget handle',
        roles: new Set(['info_disclosure']),
        resourceKey: 'widget_id',
        priorityScore: 85,
      },
      {
        id: 'n-mid',
        origin: 'https://svc-b.example',
        serviceScope: 'svc-b',
        endpoint: 'PATCH /api/v1/widgets/:id',
        sinkKind: 'transformer',
        summary: 'Updates widget target',
        roles: new Set(['auth_session']),
        resourceKey: 'widget_id',
        priorityScore: 88,
      },
      {
        id: 'n-sink',
        origin: 'https://svc-c.example',
        serviceScope: 'svc-c',
        endpoint: 'POST /api/v1/widgets/:id/execute',
        sinkKind: 'executor',
        summary: 'Executes widget operation',
        roles: new Set(['privileged_mutation']),
        priorityScore: 92,
      },
    ]

    const planned = planCompositeWorkflows(nodes, {
      maxComposites: 3,
      mode: 'runtime',
      depPairs: [
        { prod: nodes[0]!, cons: nodes[1]!, resourceKey: 'widget_id' },
        { prod: nodes[1]!, cons: nodes[2]!, resourceKey: 'widget_id' },
      ],
    })

    assert.ok(planned.length >= 1, 'must synthesize a graph chain from depPairs')
    assert.deepEqual(
      planned[0]!.hops.map(h => h.id),
      ['n-produce', 'n-mid', 'n-sink'],
      'must chain transitive dependency edges A -> B -> C generically',
    )
    const bannedKeys = new Set([
      'outbound_signing_webhook',
      'disclosure_auth_mutation',
      'cache_permission_async_export',
      'request_parsing_concurrent_settlement',
    ])
    for (const c of planned) {
      assert.equal(bannedKeys.has(c.key), false, `hardcoded recipe key ${c.key} must not be emitted`)
    }

    // Structural semantic classification: parameterized mutation qualifies; generic GET report does not.
    assert.ok(classifySemanticEndpointClasses({
      id: 'e-mut',
      origin: 'https://svc-a.example',
      method: 'POST',
      pathTemplate: '/api/v1/widgets/:id/trigger',
      riskScore: 82,
    }).includes('race'))
    assert.deepEqual(classifySemanticEndpointClasses({
      id: 'e-report',
      origin: 'https://svc-a.example',
      method: 'GET',
      pathTemplate: '/api/v1/reports/sales',
      riskScore: 60,
    }), [])
  })

  test('2. gb-dataflow-synthesizer does not fabricate speculative non-live tokens and enforces strict per-run & slotBudget edge caps (R10 fix)', async (t) => {
    // Spec-only endpoints with zero live exchanges and zero apiDependencies must NOT fabricate speculative edges.
    const specOnly = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: ['https://api.clean.invalid', 'https://edge.clean.invalid'],
      endpoints: [
        { id: 'e1', origin: 'https://api.clean.invalid', method: 'POST', pathTemplate: '/v1/tokens', riskScore: 80 },
        { id: 'e2', origin: 'https://edge.clean.invalid', method: 'POST', pathTemplate: '/v1/admin/apply', authRequirement: 'bearer', riskScore: 90 },
      ],
      brokerExchanges: [],
    })
    assert.equal(specOnly.edgeCount, 0, 'must not fabricate speculative edges without live runtime exchanges or apiDependencies')
    assert.equal(specOnly.chains.length, 0)

    // R10 regression: repeated watermark ticks with many routes must stay <= MAX_VALUEFLOW_EDGES_PER_RUN
    // and emit 0 edges once slotBudget is exhausted.
    assert.ok(MAX_VALUEFLOW_EDGES_PER_RUN >= 40 && MAX_VALUEFLOW_EDGES_PER_RUN <= 60)
    const { storage } = makeStore(t, 'kovo-p0-vf-cap-')
    const originA = 'https://api.cap-test.invalid'
    const originB = 'https://worker.cap-test.invalid'
    const { runId, run } = await setupApprovedRun(storage, { seeds: [originA, originB], tier: 2 })
    const persona = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId: run.projectId,
      handle: 'member_a',
      roleLabel: 'member',
      originAllowlist: [originA, originB],
      authKind: 'bearer',
      secret: 'tok-cap-test-member',
      canaryMarkers: [],
    })
    storage.updateRun(runId, { approvedPersonaIds: [persona.id] })
    const freshRun = storage.run(runId)
    const assetA = freshRun.candidates.find(c => c.origin === originA)!
    const worker = storage.makeWorker(freshRun, 'investigation', assetA, 'Cap test', 'Probe', {
      sourceOrigins: [originA, originB],
    })

    // Seed 30 distinct producer/consumer pairs with exact param matches across multiple ticks.
    for (let i = 0; i < 30; i += 1) {
      const prodEp = storage.upsertEndpoint({
        runId,
        scopeRevision: freshRun.scopeRevision,
        origin: originA,
        method: 'POST',
        pathTemplate: `/v1/batch${i}/jobs`,
        riskScore: 80,
        source: 'openapi',
      })
      const consEp = storage.upsertEndpoint({
        runId,
        scopeRevision: freshRun.scopeRevision,
        origin: originB,
        method: 'GET',
        pathTemplate: `/v1/batch${i}/jobs/:job_id`,
        riskScore: 85,
        source: 'openapi',
      })
      void prodEp
      storage.upsertEndpointParam({
        runId,
        endpointId: consEp.id,
        name: `job_${i}_id`,
        location: 'path',
        inferredType: 'string',
        isObjectId: true,
        source: 'openapi',
      })
    }

    const insertEx = (id: string, pathAndQuery: string, bodyObj: Record<string, unknown>, createdAt: number) => {
      storage.client.prepare(`
        INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, runId, worker.id, freshRun.scopeRevision, originA, originA, '[]',
        'POST', pathAndQuery, 202, 'application/json', 'member_a',
        '{}', '{}', JSON.stringify(bodyObj), id.padEnd(64, 'b').slice(0, 64), 5, createdAt,
      )
    }

    // Drive 15 successive watermark ticks (previously this could spam 15 * 24 = 360+ edges even with 0 slots!).
    for (let tick = 0; tick < 15; tick += 1) {
      insertEx(`ex-cap-${tick}-a`, `/v1/batch${tick}/jobs`, { [`job_${tick}_id`]: `id-${tick}` }, 10_000 + tick * 100)
      insertEx(`ex-cap-${tick}-b`, `/v1/batch${tick + 15}/jobs`, { [`job_${tick + 15}_id`]: `id-${tick + 15}` }, 10_050 + tick * 100)
      refreshGreyBoxValueFlowSteps(storage, freshRun, {
        activeOrigins: new Set([originA, originB]),
        sourceMounted: false,
        llmMode: 'agentic',
        maxPerRound: 2,
        maxTotalSteps: 4,
      })
    }

    const totalVfEdges = storage.capabilityLedger(runId).listCausalEdges().filter(
      e => e.edgeId.startsWith('edge_vf_') || e.metadata?.source === 'gb_valueflow',
    ).length
    assert.ok(totalVfEdges > 0, 'must persist valid high-confidence edges when slotBudget > 0')
    assert.ok(totalVfEdges <= MAX_VALUEFLOW_EDGES_PER_RUN, `expected <= ${MAX_VALUEFLOW_EDGES_PER_RUN} edges, got ${totalVfEdges}`)

    // With maxTotalSteps already filled (slotBudget === 0), a new watermark tick MUST persist 0 edges.
    insertEx('ex-cap-after-full', '/v1/batch0/jobs', { job_0_id: 'id-after-full' }, 99_999)
    const afterFull = refreshGreyBoxValueFlowSteps(storage, freshRun, {
      activeOrigins: new Set([originA, originB]),
      sourceMounted: false,
      llmMode: 'agentic',
      maxPerRound: 2,
      maxTotalSteps: 4,
    })
    assert.equal(afterFull.steps.length, 0)
    assert.equal(afterFull.edgesPersisted, 0, 'must persist 0 edges when slotBudget === 0')
  })

  test('3. capability-consumer-frontier preserves owning multiTenant persona without basePersona rewrite', () => {
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: ['https://api.mt.invalid', 'https://hooks.mt.invalid'],
      capabilities: [
        {
          capId: 'cap:hop_h1:signing_key',
          origin: 'https://api.mt.invalid',
          producerEndpoint: '/v1/integrations',
          producerMethod: 'GET',
          actingPersona: 'dual_member',
          ledgerKind: 'signing_material',
          secretKind: 'hmac_key',
          fieldName: 'signing_key',
          provenance: 'runtime_discovery',
        },
      ],
      endpoints: [
        { origin: 'https://hooks.mt.invalid', method: 'POST', pathTemplate: '/v1/ingest', sinkKinds: ['webhook_hmac'], riskScore: 90 },
      ],
      observedResponses: [
        {
          origin: 'https://hooks.mt.invalid',
          method: 'POST',
          pathAndQuery: '/v1/ingest',
          status: 401,
          personaHandle: 'dual_member',
          bodyPreview: JSON.stringify({ error: 'invalid hmac signature' }),
        },
      ],
      personas: [
        { handle: 'owner_a', roleLabel: 'owner' },
        { handle: 'member_a', roleLabel: 'member' },
        { handle: 'dual_member', roleLabel: 'memberships=admin:org_a,viewer:org_b' },
      ],
    })
    assert.equal(pairs.length, 1)
    assert.equal(pairs[0]!.capability.actingPersona, 'dual_member', 'must not rewrite owning multiTenant persona to basePersona')
  })

  test('4. invariant-runtime-parity keeps facets as entity noun and classifies lifecycle chains structurally', () => {
    assert.equal(inferEntityName('/api/v1/facets'), 'facet', 'facets must no longer be stripped by WRAPPER_SEG_RE')
    assert.equal(
      classifyRuntimeDependencyEdgeKind({
        producer: 'POST /api/v1/things',
        consumer: 'PATCH /api/v1/things/:id',
        resourceKey: 'thing_id',
      }),
      'lifecycle_chain',
    )
    assert.equal(
      classifyRuntimeDependencyEdgeKind({
        producer: 'GET /api/v1/things',
        consumer: 'GET /api/v1/things/:id/settle',
        resourceKey: 'thing_id',
      }),
      'generic',
      'non-mutating GET with fintech word settle must not be classified via hardcoded verb ladder',
    )
  })

  test('5. exec-recon-planner, multihop-chains.md, and agent-prompts.ts are trimmed and domain-general', () => {
    const directiveLower = HOP_CONTINUATION_DIRECTIVE.toLowerCase()
    for (const forbidden of ['hops 3', 'hmac_sign', 'jwt_sign', 'await_async']) {
      assert.equal(directiveLower.includes(forbidden), false, `HOP_CONTINUATION_DIRECTIVE must stay neutral (found ${forbidden})`)
    }

    const skill = loadSkill('multihop-chains')
    assert.ok(skill, 'multihop-chains skill must load')
    const skillText = skill.content
    const skillLines = skillText.trimEnd().split('\n').length
    assert.ok(skillLines <= 50, `multihop-chains.md must be trimmed to ~40 lines, got ${skillLines}`)
    const skillLower = skillText.toLowerCase()
    for (const forbidden of ['service-meta', 'webhooks/trigger', 'hardened-twin', 'fast_lab', 'dual_tenant_abac', 'economic_conservation', 'balance_minting']) {
      assert.equal(skillLower.includes(forbidden), false, `multihop-chains.md must not include ${forbidden}`)
    }

    for (const forbidden of ['dual_tenant_abac', 'economic_conservation', 'N >= 5']) {
      assert.equal(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.includes(forbidden), false, `agent-prompts pattern must not include ${forbidden}`)
    }
    const promptJson = workerInvestigationPrompt({
      goal: 'Verify multi-hop flow',
      step: { id: 'step-1', title: 'Chain step', hypothesis: '[chain_hops=2] Test flow', category: 'broken-access-control', skills: ['multihop-chains'] },
      origins: ['https://app.example'],
      capabilityTier: 2,
      maxTurns: 10,
    })
    assert.equal(promptJson.includes('dual_tenant_abac'), false)
    assert.equal(promptJson.includes('economic_conservation'), false)
  })

  test('6. check-v8-contamination.ts blocks structural lab-artifact regressions and passes on repo', () => {
    const repoResult = scanSourceTreeForContamination(REPO_ROOT)
    assert.equal(repoResult.ok, true, formatContaminationReport(repoResult))

    const dir = mkdtempSync(join(tmpdir(), 'kovo-p0-contam-'))
    try {
      mkdirSync(join(dir, 'src', 'server'), { recursive: true })
      mkdirSync(join(dir, 'src', 'skills'), { recursive: true })
      writeFileSync(
        join(dir, 'src', 'server', 'regression.ts'),
        [
          'const a = "fast_lab"',
          'const b = "dual_org_cache_bleed"',
          'const c = "nfkc-collision"',
          'const d = "split_refund_ledger_break"',
          'const e = "billingz"',
          'const f = "whsec_12345"',
          'const g = "xfer_999"',
          'const h = "hardened_twin"',
          'const i = "rbs_secret_abc"',
        ].join('\n'),
        'utf8',
      )
      const res = scanSourceTreeForContamination(dir)
      assert.equal(res.ok, false)
      assert.equal(res.hits.length, 9, `expected 9 structural lab-artifact hits, got ${res.hits.length}`)
      for (const tok of [
        'fast_lab', 'dual_org_cache_bleed', 'nfkc-collision', 'split_refund_ledger_break',
        'billingz', 'whsec_', 'xfer_', 'hardened_twin', 'rbs_',
      ]) {
        assert.ok(
          res.hits.some(h => h.token === tok && h.category === 'structural_lab_artifact'),
          `missing contamination detection for ${tok}`,
        )
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
