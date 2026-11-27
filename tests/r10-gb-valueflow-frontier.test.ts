/**
 * R10 Move 2 Regression Suite:
 *  1. Unblocking `CapabilityConsumerFrontier` for live `http`+`record_fact` `runtimeObserved`
 *     hops in Grey-Box while strictly excluding static/hypothetical projections and `--no-llm`.
 *  2. Continuous Round-2+ Grey-Box value-flow refresh + `CapabilityLedger.addCausalEdge`
 *     (`value_binding`) persistence with watermark advancement, deduplication, and zero `--no-llm`
 *     side effects.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { describe, test } from 'node:test'
import {
  hasAgenticSealedCapabilities,
  isAgenticRuntimeCapabilityNode,
  isAgenticSealedCapabilityNode,
  materializeCapabilityConsumerFrontierSteps,
} from '../src/server/capability-consumer-frontier.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import {
  materializeGreyBoxDataflowWave1Steps,
  refreshGreyBoxValueFlowSteps,
} from '../src/server/gb-dataflow-synthesizer.ts'
import { createGraphCoordinator } from '../src/server/graph-coordinator.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const API_ORIGIN = 'https://core-api.r10-vf.invalid'
const EDGE_ORIGIN = 'https://edge-hooks.r10-vf.invalid'
const FILES_ORIGIN = 'https://files-store.r10-vf.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
  } as unknown as WorkerBackend
}

function plannerOf(engine: Execution): ExecReconPlanner {
  return (engine as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

function insertExchange(
  storage: ReturnType<typeof makeStore>['storage'],
  input: {
    id: string
    runId: string
    assignmentId: string
    scopeRevision: number
    origin: string
    method: string
    pathAndQuery: string
    status: number
    personaHandle?: string
    respHeaders?: Record<string, string>
    bodyPreview?: string
    createdAt?: number
  },
): void {
  storage.client.prepare(`
    INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    input.id,
    input.runId,
    input.assignmentId,
    input.scopeRevision,
    input.origin,
    input.origin,
    '[]',
    input.method,
    input.pathAndQuery,
    input.status,
    'application/json',
    input.personaHandle ?? 'member_a',
    '{}',
    JSON.stringify(input.respHeaders ?? {}),
    input.bodyPreview ?? '{}',
    input.id.padEnd(64, 'a').slice(0, 64),
    4,
    input.createdAt ?? Date.now(),
  )
}

describe('R10 Move 2: runtimeObserved CapabilityConsumerFrontier & Round-2+ GB value-flow synthesis', () => {
  test('1. live agentic runtimeObserved hops enter CapabilityConsumerFrontier while static/hypothetical projections and --no-llm stay strictly excluded', async (t) => {
    const setupScenario = async (llmMode: 'agentic' | 'deterministic-no-llm') => {
      const { storage } = makeStore(t, `kovo-r10-frontier-${llmMode}-`)
      const { runId, run } = await setupApprovedRun(storage, {
        seeds: [API_ORIGIN, EDGE_ORIGIN],
        tier: 2,
      })
      const pMember = createProjectPersona(storage, {
        requestId: randomUUID(),
        projectId: run.projectId,
        handle: 'member_a',
        roleLabel: 'member',
        originAllowlist: [API_ORIGIN, EDGE_ORIGIN],
        authKind: 'bearer',
        secret: 'tok-r10-member-a',
        canaryMarkers: [],
      })
      const pOwner = createProjectPersona(storage, {
        requestId: randomUUID(),
        projectId: run.projectId,
        handle: 'owner_a',
        roleLabel: 'owner',
        originAllowlist: [API_ORIGIN, EDGE_ORIGIN],
        authKind: 'bearer',
        secret: 'tok-r10-owner-a',
        canaryMarkers: [],
      })
      storage.updateRun(runId, { approvedPersonaIds: [pOwner.id, pMember.id] })
      const freshRun = storage.run(runId)
      const assetApi = freshRun.candidates.find(c => c.origin === API_ORIGIN)!
      const worker = storage.makeWorker(freshRun, 'investigation', assetApi, 'R10 probe', 'Probe', {
        sourceOrigins: [API_ORIGIN, EDGE_ORIGIN],
      })

      // Discovered consumers across origins (including 401 signature rejection & sibling :id/<verb>)
      storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 92, source: 'spa_crawl', sinkKinds: ['webhook_hmac'] })
      storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/approve', riskScore: 90, source: 'openapi' })
      storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/admin/internal/audit', authRequirement: 'admin', riskScore: 95, source: 'repo_ast' })

      insertExchange(storage, {
        id: 'r10-ex-401',
        runId,
        assignmentId: worker.id,
        scopeRevision: freshRun.scopeRevision,
        origin: EDGE_ORIGIN,
        method: 'POST',
        pathAndQuery: '/v1/webhooks/ingest',
        status: 401,
        personaHandle: 'member_a',
        bodyPreview: JSON.stringify({ error: 'invalid hmac signature header' }),
        createdAt: 1_000,
      })
      insertExchange(storage, {
        id: 'r10-ex-200-sig',
        runId,
        assignmentId: worker.id,
        scopeRevision: freshRun.scopeRevision,
        origin: API_ORIGIN,
        method: 'GET',
        pathAndQuery: '/v1/integrations/hooks',
        status: 200,
        personaHandle: 'member_a',
        bodyPreview: JSON.stringify({ webhook_secret: 'opaque_placeholder_val' }),
        createdAt: 1_010,
      })
      insertExchange(storage, {
        id: 'r10-ex-200-ord',
        runId,
        assignmentId: worker.id,
        scopeRevision: freshRun.scopeRevision,
        origin: API_ORIGIN,
        method: 'GET',
        pathAndQuery: '/v1/orders/ord_884422',
        status: 200,
        personaHandle: 'member_a',
        bodyPreview: JSON.stringify({ order_id: 'ord_884422' }),
        createdAt: 1_020,
      })

      // Static/hypothetical & deterministic floor facts (must NOT become runtimeObserved!)
      const staticSuspect = storage.addFact(freshRun, worker, {
        kind: 'note',
        origin: API_ORIGIN,
        summary: 'Static AST suspect on webhook route',
        data: { subkind: 'code_audit_suspect', source: 'static_analysis', sinkKind: 'webhook', routeOrAction: 'POST /v1/webhooks/ingest' },
      })
      const floorLead = storage.addFact(freshRun, worker, {
        kind: 'object_ref',
        origin: API_ORIGIN,
        summary: 'Deterministic floor observation',
        data: { subkind: 'det_lead', source: 'deterministic_floor', resourceId: 'flr_111', endpoint: '/v1/floor/items' },
      })

      // Live agentic http + record_fact observations (NOT kovo_verify seal_capability!)
      const liveSecretFact = storage.addFact(freshRun, worker, {
        kind: 'secret',
        origin: API_ORIGIN,
        summary: 'Observed webhook signing secret on integration hooks endpoint',
        data: { endpoint: '/v1/integrations/hooks', method: 'GET', fieldName: 'webhook_secret', secretKind: 'hmac_key', persona: 'member_a' },
        exchangeIds: ['r10-ex-200-sig'],
      })
      const liveOrderFact = storage.addFact(freshRun, worker, {
        kind: 'object_ref',
        origin: API_ORIGIN,
        summary: 'Observed order resource identifier from live response',
        data: { subkind: 'persona_resource', resourceId: 'ord_884422', endpoint: '/v1/orders/ord_884422', method: 'GET', fieldName: 'order_id', persona: 'member_a' },
        exchangeIds: ['r10-ex-200-ord'],
      })

      const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
      t.after(() => engine.stop())
      const planner = plannerOf(engine)
      const coordinator = createGraphCoordinator({
        deps: planner.coordinatorDeps(storage.run(runId)),
        approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      })
      const dispatched = planner.dispatchChainRound(
        storage.run(runId),
        coordinator,
        40,
        new Set([staticSuspect.id, floorLead.id, liveSecretFact.id, liveOrderFact.id]),
        undefined,
        { sourceMounted: false, apiDependencies: [], llmMode },
      )
      return { storage, runId, planner, coordinator, dispatched }
    }

    // (a) --no-llm run: 0 runtimeObserved nodes, 0 frontier steps
    const noLlm = await setupScenario('deterministic-no-llm')
    const noLlmLedger = noLlm.storage.capabilityLedger(noLlm.runId)
    assert.equal(noLlmLedger.listCapabilities().filter(isAgenticRuntimeCapabilityNode).length, 0, '--no-llm must never mark hops runtimeObserved')
    assert.equal(hasAgenticSealedCapabilities(noLlmLedger, { llmMode: 'deterministic-no-llm' }), false)
    const noLlmFrontierSteps = noLlm.storage.listChainSteps(noLlm.runId, noLlm.storage.run(noLlm.runId).goalRevision)
      .filter(s => s.title.startsWith('Capability frontier ·'))
    assert.equal(noLlmFrontierSteps.length, 0, '--no-llm must emit strictly 0 CapabilityConsumerFrontier steps')
    assert.equal(noLlmLedger.listCausalEdges().length, 0, '--no-llm must persist 0 causal edges')

    // (b) Agentic run: live hops are marked runtimeObserved=true and pair with consumer routes!
    const agentic = await setupScenario('agentic')
    const ledger = agentic.storage.capabilityLedger(agentic.runId)
    const allCaps = ledger.listCapabilities()
    const runtimeCaps = allCaps.filter(isAgenticRuntimeCapabilityNode)
    const staticOrUnscoped = allCaps.filter(n => n.tenantScope === 'unscoped_hypothesis')

    assert.ok(runtimeCaps.length >= 2, `expected >= 2 runtimeObserved capability hops, got ${runtimeCaps.length}`)
    assert.ok(runtimeCaps.every(n => n.metadata.runtimeObserved === true && isAgenticSealedCapabilityNode(n)))
    assert.ok(staticOrUnscoped.length >= 1, 'static/hypothetical/endpoint-only hops must remain unscoped_hypothesis')
    assert.ok(staticOrUnscoped.every(n => !isAgenticRuntimeCapabilityNode(n) && !isAgenticSealedCapabilityNode(n)), 'static/unscoped hops must stay excluded from frontier')

    const frontierSteps = agentic.storage.listChainSteps(agentic.runId, agentic.storage.run(agentic.runId).goalRevision)
      .filter(s => s.title.startsWith('Capability frontier ·'))
    assert.ok(frontierSteps.length >= 2, `expected >= 2 frontier steps from live runtimeObserved hops, got ${frontierSteps.length}`)
    assert.ok(
      frontierSteps.some(s =>
        s.hypothesis.includes('[cap_frontier=derive_signature]')
        && s.hypothesis.includes('/v1/webhooks/ingest')
        && s.hypothesis.includes('hmac_sign')
        && s.hypothesis.includes('seal_capability')
        && s.hypothesis.includes('[acting_persona=member_a]')),
      `expected signing_secret hop paired with 401 webhook consumer, got: ${frontierSteps.map(s => s.hypothesis).join('\n')}`,
    )
    assert.ok(
      frontierSteps.some(s =>
        s.hypothesis.includes('[cap_frontier=consume_entity_id]')
        && s.hypothesis.includes('/v1/orders/:id/approve')
        && s.hypothesis.includes('[acting_persona=member_a]')),
      `expected order_id hop paired with sibling :id/approve consumer, got: ${frontierSteps.map(s => s.hypothesis).join('\n')}`,
    )

    // Repeat dispatchChainRound is idempotent and --no-llm materializeCapabilityConsumerFrontierSteps still returns 0
    assert.equal(
      materializeCapabilityConsumerFrontierSteps(agentic.storage, agentic.storage.run(agentic.runId), {
        activeOrigins: new Set([API_ORIGIN, EDGE_ORIGIN]),
        llmMode: 'deterministic-no-llm',
      }).length,
      0,
    )
    const beforeCount = frontierSteps.length
    agentic.planner.dispatchChainRound(agentic.storage.run(agentic.runId), agentic.coordinator, 40, new Set(), undefined, {
      sourceMounted: false,
      apiDependencies: [],
      llmMode: 'agentic',
    })
    const afterCount = agentic.storage.listChainSteps(agentic.runId, agentic.storage.run(agentic.runId).goalRevision)
      .filter(s => s.title.startsWith('Capability frontier ·')).length
    assert.equal(afterCount, beforeCount, 'repeat dispatchChainRound must not duplicate frontier steps')
  })

  test('2. Round-2+ continuous GB value-flow refresh picks up new 2xx exchanges & facts after Wave 1, persists value_binding edges, deduplicates, and leaves --no-llm untouched', async (t) => {
    const { storage } = makeStore(t, 'kovo-r10-valueflow-')
    const { runId, run } = await setupApprovedRun(storage, {
      seeds: [API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN],
      tier: 2,
    })
    const activeOrigins = new Set([API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN])
    const pMember = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId: run.projectId,
      handle: 'member_a',
      roleLabel: 'member',
      originAllowlist: [API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN],
      authKind: 'bearer',
      secret: 'tok-vf-member-a',
      canaryMarkers: [],
    })
    storage.updateRun(runId, { approvedPersonaIds: [pMember.id], roundNo: 2 })
    const freshRun = storage.run(runId)
    const assetApi = freshRun.candidates.find(c => c.origin === API_ORIGIN)!
    const worker = storage.makeWorker(freshRun, 'investigation', assetApi, 'Wave-2 worker', 'Probe', {
      sourceOrigins: [API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN],
    })

    // Saturate the Wave-1 GB dataflow cap (6 live steps already exist!)
    for (let i = 0; i < 6; i += 1) {
      const s = storage.addChainStep(freshRun, {
        title: `GB dataflow chain (2-hop) · wave1-slot-${i} (entity_id)`,
        hypothesis: `[chain_hops=2] [lane=chain] [dataflow_source=live] Pre-existing Wave-1 step ${i}`,
        category: 'broken-access-control',
        priority: 92,
        targetAssetIds: [assetApi.id],
        skills: ['multihop-chains'],
        sourceOrigins: [API_ORIGIN, EDGE_ORIGIN],
      })
      storage.updateChainStep(s.id, { status: 'ready' })
    }

    // Discovered consumer endpoints across all 3 origins
    storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/deployments/:id/promote', riskScore: 90, source: 'openapi' })
    storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/artifacts/:id/download', riskScore: 88, source: 'openapi' })
    storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 94, source: 'spa_crawl', sinkKinds: ['webhook_hmac'] })
    storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/exports/:id/result', riskScore: 86, source: 'openapi' })

    // Round-2 2xx exchange yielding concrete deployment_id + cross-origin signed artifact URL
    insertExchange(storage, {
      id: 'vf-ex-r2-dep',
      runId,
      assignmentId: worker.id,
      scopeRevision: freshRun.scopeRevision,
      origin: API_ORIGIN,
      method: 'POST',
      pathAndQuery: '/v1/deployments',
      status: 201,
      personaHandle: 'member_a',
      bodyPreview: JSON.stringify({
        deployment_id: 'dep_991122',
        artifact_url: `${FILES_ORIGIN}/v1/artifacts/dep_991122/download?sig=opaque_sig_placeholder`,
      }),
      createdAt: 20_000,
    })

    // Strictly 0 steps & 0 ledger writes under --no-llm
    const noLlmRes = refreshGreyBoxValueFlowSteps(storage, storage.run(runId), {
      activeOrigins,
      sourceMounted: false,
      llmMode: 'deterministic-no-llm',
    })
    assert.equal(noLlmRes.steps.length, 0)
    assert.equal(noLlmRes.edgesPersisted, 0)
    assert.equal(storage.capabilityLedger(runId).listCausalEdges().length, 0, '--no-llm must persist 0 causal edges')

    // Round 2 agentic refresh via materializeGreyBoxDataflowWave1Steps runs even though Wave-1 has 6 live steps!
    const r2Steps = materializeGreyBoxDataflowWave1Steps(storage, storage.run(runId), {
      activeOrigins,
      sourceMounted: false,
      maxSteps: 6,
      llmMode: 'agentic',
    })
    const r2VfSteps = r2Steps.filter(s => s.title.startsWith('GB value-flow ('))
    assert.ok(r2VfSteps.length >= 2, `expected >= 2 Round-2 value-flow steps despite Wave-1 cap=6, got ${r2VfSteps.length}`)
    assert.ok(r2VfSteps.some(s => s.hypothesis.includes('/v1/deployments/:id/promote')))
    assert.ok(r2VfSteps.some(s => s.hypothesis.includes('/v1/artifacts/:id/download')))

    const ledger = storage.capabilityLedger(runId)
    const r2Edges = ledger.listCausalEdges({ edgeBindingKind: 'value_binding' })
    assert.ok(r2Edges.length >= 2, `expected >= 2 persisted value_binding causal edges, got ${r2Edges.length}`)
    assert.ok(r2Edges.every(e => e.bindingDigest && /^[a-f0-9]{64}$/.test(e.bindingDigest)), 'every value_binding edge must carry a 64-char SHA-256 bindingDigest')

    // Consumer target nodes must NOT masquerade as producer capabilities in CapabilityConsumerFrontier
    const targetNodes = ledger.listCapabilities().filter(n => n.metadata.consumerTarget === true)
    assert.ok(targetNodes.length >= 2)
    assert.ok(targetNodes.every(n => !isAgenticSealedCapabilityNode(n)), 'consumer target nodes must be excluded from producer frontier')

    // Unchanged watermark -> strict no-op (0 new steps, 0 new edges)
    const repeatRes = refreshGreyBoxValueFlowSteps(storage, storage.run(runId), {
      activeOrigins,
      sourceMounted: false,
      llmMode: 'agentic',
    })
    assert.equal(repeatRes.watermarkChanged, false)
    assert.equal(repeatRes.steps.length, 0)
    assert.equal(repeatRes.edgesPersisted, 0)

    // Mark Round-2 steps complete so active queue slots open for Round 3, then arrive new Round-3 2xx exchange + agentic fact!
    for (const s of r2VfSteps) storage.updateChainStep(s.id, { status: 'complete' })
    storage.updateRun(runId, { roundNo: 3 })
    insertExchange(storage, {
      id: 'vf-ex-r3-401',
      runId,
      assignmentId: worker.id,
      scopeRevision: freshRun.scopeRevision,
      origin: EDGE_ORIGIN,
      method: 'POST',
      pathAndQuery: '/v1/webhooks/ingest',
      status: 401,
      personaHandle: 'member_a',
      bodyPreview: JSON.stringify({ error: 'missing hmac signature' }),
      createdAt: 30_000,
    })
    insertExchange(storage, {
      id: 'vf-ex-r3-sig',
      runId,
      assignmentId: worker.id,
      scopeRevision: freshRun.scopeRevision,
      origin: API_ORIGIN,
      method: 'GET',
      pathAndQuery: '/v1/hooks/settings',
      status: 200,
      personaHandle: 'member_a',
      bodyPreview: JSON.stringify({ webhook_secret: 'whsec_r3_placeholder_value_99' }),
      createdAt: 30_010,
    })
    const r3Fact = storage.addFact(storage.run(runId), worker, {
      kind: 'object_ref',
      origin: API_ORIGIN,
      summary: 'Observed async export job identifier from live response',
      data: { endpoint: '/v1/exports', method: 'POST', export_id: 'exp_778899', persona: 'member_a' },
      exchangeIds: ['vf-ex-r3-sig'],
    })

    const r3Res = refreshGreyBoxValueFlowSteps(storage, storage.run(runId), {
      activeOrigins,
      sourceMounted: false,
      llmMode: 'agentic',
    })
    assert.equal(r3Res.watermarkChanged, true, 'new Round-3 exchange & fact must advance watermark')
    assert.ok(r3Res.edgesPersisted >= 2, `expected >= 2 new Round-3 value_binding edges, got ${r3Res.edgesPersisted}`)
    assert.ok(r3Res.steps.length >= 2, `expected >= 2 new Round-3 follow-on steps, got ${r3Res.steps.length}`)
    assert.ok(r3Res.steps.some(s => s.hypothesis.includes('/v1/webhooks/ingest') && s.hypothesis.includes('hmac_sign')))
    assert.ok(r3Res.steps.some(s => s.hypothesis.includes('/v1/exports/:id/result') && s.dependsOnFactIds.includes(r3Fact.id)))

    // Deduplication: Round-2 chains must NOT be duplicated in Round 3!
    const allSteps = storage.listChainSteps(runId, freshRun.goalRevision).filter(s => s.title.startsWith('GB value-flow ('))
    const titles = allSteps.map(s => s.title.trim().toLowerCase())
    assert.equal(new Set(titles).size, titles.length, 'value-flow step titles must be strictly unique across rounds')

    // Zero raw secret material persisted in CapabilityLedger
    const serializedLedger = JSON.stringify({ caps: ledger.listCapabilities(), edges: ledger.listCausalEdges() })
    assert.ok(!serializedLedger.includes('whsec_r3_placeholder_value_99'), 'raw secret values must never be persisted into CapabilityLedger')
  })

  test('3. ExecReconPlanner.syncPostFloorRuntimeInvariants triggers Round-2+ GB value-flow refresh and persists causal edges when model profile is enabled', async (t) => {
    const { storage } = makeStore(t, 'kovo-r10-planner-sync-')
    const { runId, run } = await setupApprovedRun(storage, {
      seeds: [API_ORIGIN, FILES_ORIGIN],
      tier: 2,
    })
    const activeOrigins = new Set([API_ORIGIN, FILES_ORIGIN])
    // Enable a model profile so ExecReconPlanner resolves llmMode = 'agentic'
    await saveModelProfile({
      name: 'Synth Agentic',
      endpoint: 'https://model.synth.invalid/v1',
      model: 'synth-flash',
      protocol: 'responses',
      key: 'sk-synth-r10-test',
      priority: 100,
      enabled: true,
      contextWindow: 128_000,
      maxTokens: 4096,
      thinkingLevel: 'medium',
      roleAffinity: 'tactical',
      inputCostPerMtok: 0,
      cachedInputCostPerMtok: 0,
      outputCostPerMtok: 0,
    }, storage, { skipConnectionCheck: true })
    storage.updateRun(runId, { roundNo: 2 })
    const freshRun = storage.run(runId)
    const assetApi = freshRun.candidates.find(c => c.origin === API_ORIGIN)!
    const worker = storage.makeWorker(freshRun, 'investigation', assetApi, 'R2 worker', 'Probe', {
      sourceOrigins: [API_ORIGIN, FILES_ORIGIN],
    })
    storage.upsertEndpoint({ runId, scopeRevision: freshRun.scopeRevision, origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/exports/:id/download', riskScore: 90, source: 'openapi' })
    insertExchange(storage, {
      id: 'sync-ex-r2',
      runId,
      assignmentId: worker.id,
      scopeRevision: freshRun.scopeRevision,
      origin: API_ORIGIN,
      method: 'POST',
      pathAndQuery: '/v1/exports',
      status: 202,
      personaHandle: 'member_a',
      bodyPreview: JSON.stringify({ export_id: 'exp_445566', download_url: `${FILES_ORIGIN}/v1/exports/exp_445566/download` }),
      createdAt: 40_000,
    })

    const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
    t.after(() => engine.stop())
    const planner = plannerOf(engine)
    const res = planner.syncPostFloorRuntimeInvariants(storage.run(runId), activeOrigins, { sourceMounted: false })
    assert.ok(res.wave1StepsCreated >= 1, `expected >= 1 step created by Round-2 syncPostFloorRuntimeInvariants, got ${res.wave1StepsCreated}`)
    const edges = storage.capabilityLedger(runId).listCausalEdges({ edgeBindingKind: 'value_binding' })
    assert.ok(edges.length >= 1, `expected >= 1 persisted value_binding causal edge, got ${edges.length}`)
  })
})
