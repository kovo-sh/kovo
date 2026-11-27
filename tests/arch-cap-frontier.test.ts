/**
 * Behavioral & Wiring Tests for Generic Capability-Consumer Frontier (Move A).
 *
 * Proves (100% synthetic generic fixtures — zero app/route/persona hardcoding):
 *  1. `rankCapabilityConsumerPairs` pairs a `signing_secret` with a `401` signature-rejecting
 *     `POST` endpoint as top-ranked `derive_signature` affordance (with `hmac_sign`/`jwt_sign`
 *     and clean denied-control guidance).
 *  2. Pairs a `credential_token` with `403` privileged endpoints on the base persona as
 *     high-priority `pivot_with_credential` affordance across approved origins.
 *  3. Pairs an `entity_or_job_id` with sibling `:id/<verb>` endpoints (`rebind`, `approve`,
 *     `trace`, `result`, `deliveries`, `archive`, `content`) as `consume_entity_id` affordance.
 *  4. Pairs a `signed_or_download_url` with download/export/file routes as `redeem_signed_url`.
 *  5. Prunes already-falsified negative edges (both explicit `(capabilityKind, origin, method,
 *     route)` tuples and SQLite `CapabilityLedger` pruned negative edges).
 *  6. Strictly preserves owning non-elevated `actingPersona` and NEVER substitutes an elevated
 *     shortcut persona (`admin` / `owner`).
 *  7. Emits strictly 0 pairs / 0 steps in `--no-llm` (`llmMode: 'deterministic-no-llm'`) runs,
 *     empty-capability runs, and synthetic/floor-seed-only runs.
 *  8. End-to-end wiring through `materializeCapabilityConsumerFrontierSteps`,
 *     `materializeGreyBoxDataflowWave1Steps`, and `ExecReconPlanner.dispatchChainRound` with
 *     strict deduplication, idempotency, and per-wave capping (<= 6 steps).
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import {
  buildCapabilityFrontierStepDraft,
  classifyCapabilityShape,
  hasAgenticSealedCapabilities,
  isAgenticSealedCapabilityNode,
  materializeCapabilityConsumerFrontierSteps,
  rankCapabilityConsumerPairs,
} from '../src/server/capability-consumer-frontier.ts'
import {
  computeArtifactDigest,
  formatDerivedCapabilityHandle,
} from '../src/server/capability-ledger.ts'
import {
  chainLaneDispatchRank,
  classifyDispatchLane,
  hasRuntimeBackedChainEvidence,
  hasSealedHopCapability,
  isGenericWave1BoundaryChainStep,
  isMultiHopChainStep,
} from '../src/server/exec-dispatch.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import { materializeGreyBoxDataflowWave1Steps } from '../src/server/gb-dataflow-synthesizer.ts'
import { createGraphCoordinator } from '../src/server/graph-coordinator.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const API_ORIGIN = 'https://core-api.synth-frontier.invalid'
const EDGE_ORIGIN = 'https://edge-hooks.synth-frontier.invalid'
const FILES_ORIGIN = 'https://files-store.synth-frontier.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
  } as unknown as WorkerBackend
}

function plannerOf(engine: Execution): ExecReconPlanner {
  return (engine as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

describe('Generic Capability-Consumer Frontier Matcher', () => {
  test('ranks signing_secret + 401 signature-rejecting POST endpoint #1 as derive_signature with hmac_sign/jwt_sign guidance', () => {
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_h1:webhook_secret',
          origin: API_ORIGIN,
          producerEndpoint: '/v1/integrations/config',
          producerMethod: 'GET',
          actingPersona: 'member_a',
          ledgerKind: 'signing_material',
          secretKind: 'hmac_key',
          fieldName: 'webhook_secret',
          summary: 'Sealed signing material from integration settings',
          provenance: 'runtime_discovery',
        },
      ],
      endpoints: [
        { origin: API_ORIGIN, method: 'GET', pathTemplate: '/v1/integrations/config', riskScore: 60 },
        { origin: API_ORIGIN, method: 'GET', pathTemplate: '/v1/profile', riskScore: 50 },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 88, sinkKinds: ['webhook_hmac'] },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/events/notify', riskScore: 76 },
      ],
      observedResponses: [
        {
          origin: EDGE_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/webhooks/ingest',
          status: 401,
          personaHandle: 'member_a',
          bodyPreview: JSON.stringify({ error: 'invalid X-Webhook-Signature HMAC digest' }),
        },
      ],
      personas: [
        { handle: 'admin_root', roleLabel: 'admin' },
        { handle: 'member_a', roleLabel: 'member' },
      ],
    })

    assert.ok(pairs.length >= 1, 'must produce at least one derive_signature pair')
    const top = pairs[0]!
    assert.equal(top.affordance, 'derive_signature')
    assert.equal(top.capability.shapeKind, 'signing_secret')
    assert.equal(top.capability.actingPersona, 'member_a', 'must preserve owning actingPersona, never elevate to admin_root')
    assert.equal(top.consumer.origin, EDGE_ORIGIN)
    assert.equal(top.consumer.method, 'POST')
    assert.equal(top.consumer.normPath, '/v1/webhooks/ingest')
    assert.equal(top.consumer.hasSignatureRejection, true)
    assert.equal(top.crossOrigin, true)
    assert.ok(top.nextHopInstruction.includes('hmac_sign'), 'instruction must direct worker to hmac_sign')
    assert.ok(top.nextHopInstruction.includes('jwt_sign'), 'instruction must mention jwt_sign scheme option')
    assert.ok(top.nextHopInstruction.includes('denied control'), 'instruction must require a clean denied control')

    const draft = buildCapabilityFrontierStepDraft(top, 0)
    assert.equal(draft.actingPersona, 'member_a')
    assert.ok(draft.priority >= 96)
    assert.ok(draft.skills.includes('checkpoint_cap:cap:hop_h1:webhook_secret'))
    const dispatchShape = { id: 'cf-1', seq: 1, ...draft, sourceOrigins: draft.origins }
    assert.equal(isMultiHopChainStep(dispatchShape), true)
    assert.equal(classifyDispatchLane(dispatchShape), 'chain')
    assert.equal(hasRuntimeBackedChainEvidence(dispatchShape), true)
    assert.equal(hasSealedHopCapability(dispatchShape), true)
    assert.equal(isGenericWave1BoundaryChainStep(dispatchShape), false)
    assert.equal(chainLaneDispatchRank(dispatchShape), 0)
  })

  test('pairs credential_token with 403 privileged endpoints on base persona as pivot_with_credential', () => {
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_h2:scim_token',
          origin: API_ORIGIN,
          producerEndpoint: '/v1/directory/bootstrap',
          producerMethod: 'GET',
          actingPersona: 'viewer_b',
          ledgerKind: 'scoped_token',
          secretKind: 'bearer_token',
          fieldName: 'scim_token',
          provenance: 'derived_hop',
        },
      ],
      endpoints: [
        { origin: API_ORIGIN, method: 'GET', pathTemplate: '/v1/public/catalog', authRequirement: 'none', riskScore: 30 },
        { origin: API_ORIGIN, method: 'PATCH', pathTemplate: '/v1/admin/roles/:id/sync', authRequirement: 'bearerAuth', riskScore: 92 },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/vault/secrets/approve', authRequirement: 'bearerAuth', riskScore: 94 },
      ],
      observedResponses: [
        {
          origin: EDGE_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/vault/secrets/approve',
          status: 403,
          personaHandle: 'viewer_b',
          bodyPreview: JSON.stringify({ error: 'forbidden: requires elevated scope' }),
        },
      ],
      personas: [
        { handle: 'owner_admin', roleLabel: 'owner' },
        { handle: 'viewer_b', roleLabel: 'viewer' },
      ],
    })

    assert.ok(pairs.length >= 2)
    const top = pairs[0]!
    assert.equal(top.affordance, 'pivot_with_credential')
    assert.equal(top.capability.shapeKind, 'credential_token')
    assert.equal(top.capability.actingPersona, 'viewer_b')
    assert.equal(top.consumer.origin, EDGE_ORIGIN)
    assert.equal(top.consumer.normPath, '/v1/vault/secrets/approve')
    assert.deepEqual(top.consumer.observedDeniedStatuses, [403])
    assert.ok(pairs.some(p => p.consumer.normPath === '/v1/admin/roles/:id/sync' && p.affordance === 'pivot_with_credential'))
  })

  test('pairs entity_or_job_id with sibling :id/<verb> routes and signed_or_download_url with download/export routes', () => {
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, FILES_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_h3:payout_id',
          origin: API_ORIGIN,
          producerEndpoint: '/v1/payouts',
          producerMethod: 'POST',
          actingPersona: 'member_a',
          ledgerKind: 'opaque_object_ref',
          fieldName: 'payout_id',
          valueHint: 'pay_9f8e7d6c',
          provenance: 'runtime_discovery',
        },
        {
          capId: 'cap:hop_h4:export_signed_url',
          origin: API_ORIGIN,
          producerEndpoint: '/v1/exports/:id/result',
          producerMethod: 'GET',
          actingPersona: 'member_a',
          ledgerKind: 'signed_artifact_or_url',
          secretKind: 'signed_url',
          fieldName: 'download_url',
          targetOrigin: FILES_ORIGIN,
          targetPath: '/v1/artifacts/:id/download',
          provenance: 'derived_hop',
        },
      ],
      endpoints: [
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/payouts', riskScore: 70 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/payouts/:payoutId/approve', riskScore: 90 },
        { origin: API_ORIGIN, method: 'GET', pathTemplate: '/v1/payouts/:payoutId/trace', riskScore: 84 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/payouts/:payoutId/rebind', riskScore: 88 },
        { origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/artifacts/:id/download', riskScore: 86 },
        { origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/docs/:id/content', riskScore: 80 },
      ],
      personas: [{ handle: 'member_a', roleLabel: 'member' }],
    })

    const entityPairs = pairs.filter(p => p.affordance === 'consume_entity_id')
    assert.ok(entityPairs.length >= 2, `expected sibling :id/<verb> entity matches, got ${entityPairs.length}`)
    assert.ok(entityPairs.every(p => p.capability.actingPersona === 'member_a'))
    assert.ok(entityPairs.some(p => p.consumer.normPath === '/v1/payouts/:id/approve'))
    assert.ok(entityPairs.some(p => p.consumer.normPath === '/v1/payouts/:id/rebind'))
    // Producer exact route must never be matched as its own consumer
    assert.ok(!entityPairs.some(p => p.consumer.method === 'POST' && p.consumer.normPath === '/v1/payouts'))

    const urlPairs = pairs.filter(p => p.affordance === 'redeem_signed_url')
    assert.ok(urlPairs.length >= 1)
    assert.equal(urlPairs[0]!.consumer.origin, FILES_ORIGIN)
    assert.equal(urlPairs[0]!.consumer.normPath, '/v1/artifacts/:id/download')
  })

  test('prunes falsified negative edges cleanly and never elevates actingPersona', () => {
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_h5:hmac_salt',
          origin: API_ORIGIN,
          actingPersona: 'admin_shortcut', // elevated persona must NEVER be emitted as actingPersona!
          derivedFromAttackerPersona: 'member_low',
          ledgerKind: 'signing_material',
          fieldName: 'hmac_salt',
          provenance: 'derived_hop',
        },
        {
          capId: 'cap:hop_h6:order_id',
          origin: API_ORIGIN,
          actingPersona: 'member_low',
          ledgerKind: 'state_handle',
          fieldName: 'order_id',
          provenance: 'runtime_discovery',
        },
      ],
      endpoints: [
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 90 },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/callback', riskScore: 88 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/deliveries', riskScore: 86 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/archive', riskScore: 85 },
      ],
      observedResponses: [
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/ingest', status: 401, bodyPreview: 'bad signature' },
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/callback', status: 401, bodyPreview: 'bad signature' },
      ],
      negativeEdges: [
        // Direct failed tuple pruning signing_secret on /v1/webhooks/ingest
        { capabilityKind: 'signing_secret', origin: EDGE_ORIGIN, method: 'POST', route: '/v1/webhooks/ingest' },
        // Ledger-style pruned negative edge pruning cap:hop_h6:order_id on /v1/orders/:id/deliveries
        {
          preconditionCapIds: ['cap:hop_h6:order_id'],
          targetSurfaceKey: `${API_ORIGIN}|POST|/v1/orders/ord_123/deliveries`,
          hypothesisClass: 'consume_entity_id',
          pruned: true,
          attemptCount: 2,
        },
        // Non-pruned single-strike edge (attemptCount: 1, pruned: false) must NOT prune /v1/orders/:id/archive yet
        {
          preconditionCapIds: ['cap:hop_h6:order_id'],
          targetSurfaceKey: `${API_ORIGIN}|POST|/v1/orders/:id/archive`,
          hypothesisClass: 'consume_entity_id',
          pruned: false,
          attemptCount: 1,
        },
      ],
      personas: [
        { handle: 'admin_shortcut', roleLabel: 'admin' },
        { handle: 'member_low', roleLabel: 'member' },
      ],
    })

    assert.ok(!pairs.some(p => p.consumer.normPath === '/v1/webhooks/ingest'), 'pruned signing_secret tuple must be excluded')
    assert.ok(!pairs.some(p => p.consumer.normPath === '/v1/orders/:id/deliveries'), 'pruned ledger negative edge must be excluded')
    assert.ok(pairs.some(p => p.consumer.normPath === '/v1/webhooks/callback' && p.affordance === 'derive_signature'), 'non-pruned sibling webhook route must remain')
    assert.ok(pairs.some(p => p.consumer.normPath === '/v1/orders/:id/archive' && p.affordance === 'consume_entity_id'), 'unpruned 1-strike edge must remain')
    for (const p of pairs) {
      assert.equal(p.capability.actingPersona, 'member_low', 'elevated shortcut persona must never be emitted')
    }
  })

  test('emits strictly 0 pairs in --no-llm, empty-capability, and synthetic-seed-only inputs', () => {
    const baseEndpoints = [
      { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 95 },
      { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/sync', riskScore: 95 },
    ]
    const validCap = {
      capId: 'cap:hop_h1:hmac_key',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'signing_material' as const,
      fieldName: 'hmac_key',
      provenance: 'runtime_discovery',
    }

    // 1. deterministic-no-llm -> 0 pairs
    const noLlm = rankCapabilityConsumerPairs({
      llmMode: 'deterministic-no-llm',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [validCap],
      endpoints: baseEndpoints,
    })
    assert.equal(noLlm.length, 0)

    // 2. Empty capabilities -> 0 pairs
    const empty = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [],
      endpoints: baseEndpoints,
    })
    assert.equal(empty.length, 0)

    // 3. Synthetic / static / floor / seed capabilities -> 0 pairs
    const nonAgentic = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [
        { ...validCap, capId: 'cap:hop_synth:inv_1', provenance: 'runtime_discovery' },
        { ...validCap, capId: 'cap:hop_seed_member:session', provenance: 'attacker_seed' },
        { ...validCap, capId: 'cap:hop_f1:hmac_key', provenance: 'floor_observation' },
        { ...validCap, capId: 'cap:hop_s1:hmac_key', provenance: 'static_analysis' },
      ],
      endpoints: baseEndpoints,
    })
    assert.equal(nonAgentic.length, 0)
    assert.equal(classifyCapabilityShape(validCap), 'signing_secret')
  })

  test('store-backed materialization, dispatchChainRound, and materializeGreyBoxDataflowWave1Steps wire cleanly, honor --no-llm, prune ledger negative edges, and stay idempotent', async (t) => {
    const { storage } = makeStore(t, 'kovo-arch-cap-frontier-')
    const { runId, run } = await setupApprovedRun(storage, {
      seeds: [API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN],
      tier: 2,
    })
    const activeOrigins = new Set([API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN])
    const assetApi = run.candidates.find(c => c.origin === API_ORIGIN)!
    const worker = storage.makeWorker(run, 'investigation', assetApi, 'Wave-1 worker', 'Initial probe', {
      sourceOrigins: [API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN],
    })

    // Seed discovered endpoints across approved origins
    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 92, source: 'spa_crawl', sinkKinds: ['webhook_hmac'] })
    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/deliver', riskScore: 86, source: 'spa_crawl' })
    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/vault/sync', authRequirement: 'bearerAuth', riskScore: 94, source: 'openapi' })
    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/projects/:id/rebind', authRequirement: 'bearerAuth', riskScore: 90, source: 'openapi' })
    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/exports/:id/download', riskScore: 88, source: 'openapi' })

    // Record 401 signature rejection on /v1/webhooks/ingest and 403 on /v1/admin/vault/sync
    storage.client.prepare(`
      INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'cf-ex-401', runId, worker.id, run.scopeRevision, EDGE_ORIGIN, EDGE_ORIGIN, '[]',
      'POST', '/v1/webhooks/ingest', 401, 'application/json', 'member_a', '{}', '{}',
      JSON.stringify({ error: 'missing or invalid hmac signature' }), 'a'.repeat(64), 4, Date.now(),
    )
    storage.client.prepare(`
      INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'cf-ex-403', runId, worker.id, run.scopeRevision, API_ORIGIN, API_ORIGIN, '[]',
      'POST', '/v1/admin/vault/sync', 403, 'application/json', 'member_a', '{}', '{}',
      JSON.stringify({ error: 'forbidden' }), 'b'.repeat(64), 4, Date.now() + 1,
    )

    const ledger = storage.capabilityLedger(runId)
    // Pre-floor synthetic seed ONLY -> hasAgenticSealedCapabilities MUST be false and materialize 0 steps!
    const synthCap = formatDerivedCapabilityHandle('synth', 'policy_1')
    ledger.addCapability({
      capId: synthCap,
      kind: 'policy_asymmetry',
      provenance: 'runtime_discovery',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: API_ORIGIN,
      surface: 'http',
      artifactDigest: computeArtifactDigest('synth-only'),
      artifactSummary: 'Synthetic seed',
      metadata: { hypothesisId: 'inv-1' },
      createdAtMs: 1000,
    })
    assert.equal(isAgenticSealedCapabilityNode(ledger.getCapability(synthCap)!), false)
    assert.equal(hasAgenticSealedCapabilities(ledger), false)
    assert.equal(
      materializeCapabilityConsumerFrontierSteps(storage, storage.run(runId), { activeOrigins }).length,
      0,
      'synthetic-seed-only ledger must materialize 0 frontier steps',
    )

    // Now seal real agentic capabilities in CapabilityLedger
    const hmacCap = formatDerivedCapabilityHandle('h10', 'webhook_secret')
    const tokenCap = formatDerivedCapabilityHandle('h11', 'api_token')
    const projCap = formatDerivedCapabilityHandle('h12', 'project_id')
    ledger.addCapability({
      capId: hmacCap,
      kind: 'signing_material',
      provenance: 'runtime_discovery',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: API_ORIGIN,
      surface: 'http',
      artifactDigest: computeArtifactDigest('hmac-cap'),
      artifactSummary: 'Sealed hmac_key slot webhook_secret',
      metadata: { slot: 'webhook_secret', secretKind: 'hmac_key', endpoint: '/v1/integrations/config', method: 'GET' },
      createdAtMs: 2000,
    })
    ledger.addCapability({
      capId: tokenCap,
      kind: 'scoped_token',
      provenance: 'derived_hop',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: API_ORIGIN,
      surface: 'http',
      artifactDigest: computeArtifactDigest('tok-cap'),
      artifactSummary: 'Sealed bearer_token slot api_token',
      metadata: { slot: 'api_token', secretKind: 'bearer_token' },
      createdAtMs: 2010,
    })
    ledger.addCapability({
      capId: projCap,
      kind: 'opaque_object_ref',
      provenance: 'runtime_discovery',
      tenantScope: 'org_a',
      actorPersona: 'member_a',
      serviceOrigin: API_ORIGIN,
      surface: 'http',
      artifactDigest: computeArtifactDigest('proj-cap'),
      artifactSummary: 'Sealed project_id handle',
      metadata: { slot: 'project_id', endpoint: '/v1/projects', method: 'POST' },
      createdAtMs: 2020,
    })
    // Prune /v1/webhooks/deliver via 2-strike ledger negative edge
    ledger.recordNegativeEdge({
      preconditionCapIds: [hmacCap],
      targetSurfaceKey: `${EDGE_ORIGIN}|POST|/v1/webhooks/deliver`,
      hypothesisClass: 'derive_signature',
      falsifiedByExchangeIds: ['cf-ex-neg-1', 'cf-ex-neg-2'],
      reason: 'invariant_enforced_hardened',
      forcePrune: true,
    })

    assert.equal(hasAgenticSealedCapabilities(ledger), true)

    // deterministic-no-llm MUST STILL materialize 0 steps even with agentic capabilities present
    const noLlmSteps = materializeCapabilityConsumerFrontierSteps(storage, storage.run(runId), {
      activeOrigins,
      llmMode: 'deterministic-no-llm',
    })
    assert.equal(noLlmSteps.length, 0)

    // Wire via ExecReconPlanner.dispatchChainRound
    const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
    t.after(() => engine.stop())
    const planner = plannerOf(engine)
    const coordinator = createGraphCoordinator({
      deps: planner.coordinatorDeps(storage.run(runId)),
      approvedOrigins: [...activeOrigins],
    })

    // dispatchChainRound with deterministic-no-llm emits 0 capability frontier steps
    planner.dispatchChainRound(storage.run(runId), coordinator, 24, new Set(), undefined, {
      sourceMounted: false,
      hops: [],
      apiDependencies: [],
      llmMode: 'deterministic-no-llm',
    })
    const frontierAfterNoLlm = storage.listChainSteps(runId, run.goalRevision)
      .filter(s => s.title.startsWith('Capability frontier ·'))
    assert.equal(frontierAfterNoLlm.length, 0, 'deterministic-no-llm dispatchChainRound must emit 0 capability frontier steps')

    // dispatchChainRound in agentic mode materializes frontier steps even when planChainRound has 0 hops
    const agenticDispatched = planner.dispatchChainRound(storage.run(runId), coordinator, 40, new Set(), undefined, {
      sourceMounted: false,
      hops: [],
      apiDependencies: [],
      llmMode: 'agentic',
    })
    assert.ok(agenticDispatched >= 2, `expected >= 2 dispatched steps in agentic mode, got ${agenticDispatched}`)

    const steps = storage.listChainSteps(runId, run.goalRevision)
    const frontierSteps = steps.filter(s => s.title.startsWith('Capability frontier ·'))
    assert.ok(frontierSteps.length >= 2 && frontierSteps.length <= 6, `expected 2..6 frontier steps, got ${frontierSteps.length}`)
    assert.ok(frontierSteps.every(s => s.status === 'ready'))
    assert.ok(frontierSteps.every(s => s.hypothesis.includes('[acting_persona=member_a]')))
    assert.ok(frontierSteps.some(s => s.hypothesis.includes('[cap_frontier=derive_signature]') && s.hypothesis.includes('/v1/webhooks/ingest') && s.hypothesis.includes('hmac_sign')))
    assert.ok(frontierSteps.some(s => s.hypothesis.includes('[cap_frontier=pivot_with_credential]') && s.hypothesis.includes('/v1/admin/vault/sync')))
    assert.ok(frontierSteps.some(s => s.hypothesis.includes('[cap_frontier=consume_entity_id]') && s.hypothesis.includes('/v1/projects/:id/rebind')))
    assert.ok(!frontierSteps.some(s => s.hypothesis.includes('/v1/webhooks/deliver')), 'pruned ledger negative edge must not be materialized')

    // Re-running dispatchChainRound & materializeGreyBoxDataflowWave1Steps is strictly idempotent (no duplicate frontier steps)
    const beforeRepeatFrontierCount = frontierSteps.length
    planner.dispatchChainRound(storage.run(runId), coordinator, 40, new Set(), undefined, {
      sourceMounted: false,
      hops: [],
      apiDependencies: [],
      llmMode: 'agentic',
    })
    const afterRepeatFrontierCount = storage.listChainSteps(runId, run.goalRevision)
      .filter(s => s.title.startsWith('Capability frontier ·')).length
    assert.equal(afterRepeatFrontierCount, beforeRepeatFrontierCount, 'repeat dispatchChainRound with unchanged capabilities must not duplicate frontier steps')

    const gbRepeat = materializeGreyBoxDataflowWave1Steps(storage, storage.run(runId), {
      activeOrigins,
      sourceMounted: false,
      llmMode: 'agentic',
    })
    assert.equal(
      gbRepeat.filter(s => s.title.startsWith('Capability frontier ·')).length,
      0,
      'gb-dataflow-synthesizer wave materialization must not duplicate already-materialized frontier steps',
    )
  })
})
