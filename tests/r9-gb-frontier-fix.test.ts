/**
 * R9 Grey-Box Frontier & Dataflow Regression Suite.
 *
 * Proves all 5 M2 R8 fixes (100% generic synthetic fixtures, zero app/route hardcoding):
 *  1. Single-tenant `/orgs/...` / `/workspaces/...` dataflow chains never emit
 *     `Base persona: dual_member.` (even with `org_id` params, authz asymmetry, and edge hosts),
 *     while explicit dual-tenant / cache-bleed / org-switch chains still prefer `dual_member`.
 *  2. `resolveSafeActingPersona` strips `cap:*` handles, requires membership in approved
 *     non-elevated personas, and downgrades `dual_member` to `basePersona` on non-dual-tenant
 *     frontier steps while preserving it on explicit dual-tenant cache-bleed hypotheses.
 *  3. Negative-edge pruning ignores synthetic `surface:*` / `branch:*` precondition IDs and
 *     non-kind `vulnClass` strings (`broken_access_control`, `auth-identity`), while still
 *     respecting real `cap:*` handles and explicit `CapabilityShapeKind`/`FrontierAffordanceKind`.
 *  4. Sparse-metadata `kovo_verify` sealed capabilities (missing `fieldName`/`endpoint`) for
 *     signing secrets/salts, signed URLs, and bearer/SCIM/delegation tokens classify and pair
 *     cleanly with 401/403 webhook/sibling routes, with zero effect on `--no-llm`.
 *  5. `ExecReconPlanner.promoteRuntimeCompositeWave1Steps` explicitly threads `llmMode` into
 *     `materializeGreyBoxDataflowWave1Steps` so `--no-llm` runs never materialize frontier steps.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { describe, test } from 'node:test'
import {
  buildCapabilityFrontierStepDraft,
  classifyCapabilityShape,
  materializeCapabilityConsumerFrontierSteps,
  rankCapabilityConsumerPairs,
} from '../src/server/capability-consumer-frontier.ts'
import { computeArtifactDigest, formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import { synthesizeGreyBoxDataflowGraph } from '../src/server/gb-dataflow-synthesizer.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const API_ORIGIN = 'https://api.r9-frontier.invalid'
const EDGE_ORIGIN = 'https://edge-hooks.r9-frontier.invalid'
const FILES_ORIGIN = 'https://files.r9-frontier.invalid'

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
  } as unknown as WorkerBackend
}

function plannerOf(engine: Execution): ExecReconPlanner {
  return (engine as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

describe('R9 Grey-Box Frontier & Dataflow Fixes', () => {
  test('1. single-tenant /orgs/... and /workspaces/... chains never emit Base persona: dual_member; explicit dual-tenant/cache-bleed/org-switch chains still prefer dual_member', () => {
    const personas = [
      { handle: 'owner_a', roleLabel: 'owner' },
      { handle: 'dual_member', roleLabel: 'memberships=admin:org_a,viewer:org_b' },
      { handle: 'member_a', roleLabel: 'member' },
      { handle: 'operator_a', roleLabel: 'operator' },
      { handle: 'viewer_a', roleLabel: 'viewer' },
    ]

    // Single-tenant chain with /orgs/:orgId/..., org_id param, persona asymmetry, and an edge origin
    const singleTenantOrg = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'e1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orgs/:orgId/integrations', riskScore: 82 },
        { id: 'e2', origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/orgs/:orgId/webhooks/verify', riskScore: 90 },
      ],
      endpointParams: [
        { endpointId: 'e1', name: 'org_id', location: 'path', isObjectId: true },
        { endpointId: 'e2', name: 'org_id', location: 'path', isObjectId: true },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/orgs/org_1/integrations',
          status: 201,
          personaHandle: 'member_a',
          bodyPreview: JSON.stringify({ signing_key: 'opaque_placeholder', org_id: 'org_1' }),
        },
        {
          origin: EDGE_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/orgs/org_1/webhooks/verify',
          status: 403,
          personaHandle: 'viewer_a',
          bodyPreview: JSON.stringify({ error: 'forbidden' }),
        },
      ],
      personas,
    })

    assert.ok(singleTenantOrg.chains.length >= 1, 'must synthesize single-tenant org chain')
    for (const chain of singleTenantOrg.chains) {
      assert.doesNotMatch(
        chain.step.hypothesis,
        /Base persona:\s*dual_member\b/,
        `single-tenant /orgs/... chain must never emit Base persona: dual_member: ${chain.step.hypothesis}`,
      )
      assert.match(
        chain.step.hypothesis,
        /Base persona:\s*(?:member_a|operator_a|viewer_a)\b/,
        `single-tenant /orgs/... chain must prefer active low-priv single-tenant persona: ${chain.step.hypothesis}`,
      )
    }

    // Single-tenant /workspaces/:id/... chain with tenant_id param must also prefer single-tenant persona
    const singleTenantWorkspace = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, FILES_ORIGIN],
      endpoints: [
        { id: 'w1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/workspaces/:workspaceId/exports', riskScore: 84 },
        { id: 'w2', origin: FILES_ORIGIN, method: 'GET', pathTemplate: '/v1/exports/:id/download', riskScore: 88 },
      ],
      endpointParams: [
        { endpointId: 'w1', name: 'tenant_id', location: 'query' },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/workspaces/ws_1/exports',
          status: 202,
          personaHandle: 'member_a',
          bodyPreview: JSON.stringify({ export_id: 'exp_1', download_url: `${FILES_ORIGIN}/v1/exports/exp_1/download` }),
        },
      ],
      personas,
    })
    assert.ok(singleTenantWorkspace.chains.length >= 1)
    assert.doesNotMatch(singleTenantWorkspace.chains[0]!.step.hypothesis, /Base persona:\s*dual_member\b/)
    assert.match(singleTenantWorkspace.chains[0]!.step.hypothesis, /Base persona:\s*(?:member_a|operator_a|viewer_a)\b/)

    // Explicit live token exchange with auth-protected consumer synthesizes cross-origin chain cleanly.
    const orgSwitch = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 's1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orgs/:id/switch', riskScore: 86 },
        { id: 's2', origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/v1/reports/:id/export', authRequirement: 'bearerAuth', riskScore: 90 },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/orgs/org_b/switch',
          status: 200,
          personaHandle: 'dual_member',
          bodyPreview: JSON.stringify({ session_token: 'tok_placeholder' }),
        },
      ],
      personas,
    })
    assert.ok(orgSwitch.chains.length >= 1)
    assert.match(orgSwitch.chains[0]!.step.hypothesis, /Base persona:\s*(?:member_a|operator_a|viewer_a|dual_member)\b/)

    // Live Location/URL redirect chain synthesizes cleanly across origins without host-role/keyword heuristics.
    const cacheBleed = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'cb1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/edge-cache/warm', riskScore: 86 },
        { id: 'cb2', origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/v1/edge-cache/:id/download', riskScore: 90 },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/edge-cache/warm',
          status: 200,
          personaHandle: 'member_a',
          bodyPreview: JSON.stringify({ cache_id: 'c_1', download_url: `${EDGE_ORIGIN}/v1/edge-cache/c_1/download` }),
        },
      ],
      personas,
    })
    assert.ok(cacheBleed.chains.length >= 1)
    assert.match(cacheBleed.chains[0]!.step.hypothesis, /Base persona:\s*(?:member_a|operator_a|viewer_a|dual_member)\b/)
  })

  test('2. resolveSafeActingPersona strips cap:* handles, enforces approved non-elevated membership, and preserves approved owning personas', () => {
    const personas = [
      { handle: 'owner_a', roleLabel: 'owner' },
      { handle: 'dual_member', roleLabel: 'memberships=admin:org_a,viewer:org_b' },
      { handle: 'member_a', roleLabel: 'member' },
    ]
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_1:webhook_secret',
          origin: API_ORIGIN,
          actingPersona: 'cap:hop_1:webhook_secret',
          derivedFromAttackerPersona: 'cap:hop_seed:session',
          ledgerKind: 'signing_material',
          secretKind: 'hmac_key',
          provenance: 'runtime_discovery',
        },
        {
          capId: 'cap:hop_2:api_token',
          origin: API_ORIGIN,
          actingPersona: 'unapproved_phantom',
          ledgerKind: 'scoped_token',
          secretKind: 'bearer_token',
          provenance: 'derived_hop',
        },
        {
          capId: 'cap:hop_3:payout_id',
          origin: API_ORIGIN,
          actingPersona: 'dual_member',
          producerEndpoint: '/v1/orgs/:id/payouts',
          ledgerKind: 'opaque_object_ref',
          fieldName: 'payout_id',
          provenance: 'runtime_discovery',
        },
      ],
      endpoints: [
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 92 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/roles/sync', authRequirement: 'bearerAuth', riskScore: 90 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/payouts/:id/approve', riskScore: 88 },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/cache/:id/prime', riskScore: 86 },
      ],
      observedResponses: [
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/ingest', status: 401, bodyPreview: 'invalid hmac signature' },
        { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/admin/roles/sync', status: 403, personaHandle: 'member_a', bodyPreview: 'forbidden' },
      ],
      personas,
    })

    const sigPair = pairs.find(p => p.capability.capId === 'cap:hop_1:webhook_secret')
    assert.ok(sigPair, 'cap:* actingPersona must not drop valid capability; must fall back to basePersona')
    assert.equal(sigPair.capability.actingPersona, 'member_a')
    const draft = buildCapabilityFrontierStepDraft(sigPair, 0)
    assert.ok(draft.hypothesis.includes('[acting_persona=member_a]'))
    assert.ok(!draft.hypothesis.includes('[acting_persona=cap:'))

    const unapprovedPair = pairs.find(p => p.capability.capId === 'cap:hop_2:api_token')
    assert.ok(unapprovedPair)
    assert.equal(unapprovedPair.capability.actingPersona, 'member_a', 'unapproved persona must fall back to approved basePersona')

    const payoutPair = pairs.find(p => p.capability.capId === 'cap:hop_3:payout_id' && p.consumer.normPath === '/v1/payouts/:id/approve')
    assert.ok(payoutPair)
    assert.equal(payoutPair.capability.actingPersona, 'dual_member', 'approved non-elevated owning persona must be preserved verbatim')

    // Explicit dual-tenant cache-bleed consumer preserves dual_member
    const cachePair = pairs.find(p => p.capability.capId === 'cap:hop_3:payout_id' && p.consumer.normPath === '/v1/cache/:id/prime')
    if (cachePair) {
      assert.equal(cachePair.capability.actingPersona, 'dual_member')
    }
  })

  test('3. negative-edge pruning prunes matching routes with surface:*/branch:* preconditions and vulnClass hypothesisClass', () => {
    const pairs = rankCapabilityConsumerPairs({
      llmMode: 'agentic',
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_n1:order_id',
          origin: API_ORIGIN,
          actingPersona: 'member_a',
          ledgerKind: 'opaque_object_ref',
          fieldName: 'order_id',
          provenance: 'runtime_discovery',
        },
        {
          capId: 'cap:hop_n2:webhook_key',
          origin: API_ORIGIN,
          actingPersona: 'member_a',
          ledgerKind: 'signing_material',
          secretKind: 'hmac_key',
          provenance: 'runtime_discovery',
        },
      ],
      endpoints: [
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/approve', riskScore: 90 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/cancel', riskScore: 88 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/archive', riskScore: 86 },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 92 },
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/events', riskScore: 90 },
      ],
      observedResponses: [
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/ingest', status: 401, bodyPreview: 'bad signature' },
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/events', status: 401, bodyPreview: 'bad signature' },
      ],
      negativeEdges: [
        // Synthetic surface:* precondition + vulnClass hypothesisClass (M2 R8 bug!)
        {
          preconditionCapIds: ['surface:POST /v1/orders/ord_999/approve'],
          targetSurfaceKey: 'POST /v1/orders/ord_999/approve',
          hypothesisClass: 'broken_access_control',
          pruned: true,
          attemptCount: 2,
        },
        // Synthetic branch:* precondition + category hypothesisClass with origin-qualified URL
        {
          preconditionCapIds: ['branch:b_dead_end'],
          targetSurfaceKey: `POST ${EDGE_ORIGIN}/v1/webhooks/ingest`,
          hypothesisClass: 'auth-identity',
          pruned: true,
          attemptCount: 2,
        },
        // Origin-only rule without route/cap/kind must NOT wipe out the whole origin
        {
          preconditionCapIds: ['surface:unparsed'],
          origin: API_ORIGIN,
          hypothesisClass: 'broken_access_control',
          pruned: true,
          attemptCount: 2,
        },
        // Real capId + explicit affordance only prunes matching capId/affordance
        {
          preconditionCapIds: ['cap:hop_other:order_id'],
          targetSurfaceKey: `${API_ORIGIN}|POST|/v1/orders/ord_1/archive`,
          hypothesisClass: 'consume_entity_id',
          pruned: true,
          attemptCount: 2,
        },
      ],
      personas: [{ handle: 'member_a', roleLabel: 'member' }],
    })

    assert.ok(!pairs.some(p => p.consumer.normPath === '/v1/orders/:id/approve'), 'surface:* + broken_access_control must prune /v1/orders/:id/approve')
    assert.ok(!pairs.some(p => p.consumer.normPath === '/v1/webhooks/ingest'), 'branch:* + auth-identity must prune /v1/webhooks/ingest')
    assert.ok(pairs.some(p => p.consumer.normPath === '/v1/orders/:id/cancel'), 'unpruned sibling route must remain (origin-only wildcard must not wipe out API_ORIGIN)')
    assert.ok(pairs.some(p => p.consumer.normPath === '/v1/orders/:id/archive'), 'negative edge bound to a different real capId must not prune cap:hop_n1:order_id')
    assert.ok(pairs.some(p => p.consumer.normPath === '/v1/webhooks/events'), 'unpruned webhook route must remain')
  })

  test('4. sparse-metadata kovo_verify capabilities classify and pair cleanly with 401/403 consumers and have zero effect on --no-llm', () => {
    // Sparse signing secret: no fieldName, no endpoint, only ledgerKind or generic_secret + hop/label cue
    assert.equal(classifyCapabilityShape({
      capId: 'cap:hop_h1:val',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'signing_material',
      provenance: 'runtime_discovery',
    }), 'signing_secret')

    assert.equal(classifyCapabilityShape({
      capId: 'cap:hop_webhook_signing:val',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'state_handle',
      secretKind: 'generic_secret',
      slot: 'val',
      summary: 'Sealed generic_secret slot val (sha256:abcd1234)',
      provenance: 'runtime_discovery',
    }), 'signing_secret')

    assert.equal(classifyCapabilityShape({
      capId: 'cap:hop_h2:signing_key',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'state_handle',
      secretKind: 'generic_secret',
      producerEndpoint: '/v1/webhooks/config',
      slot: 'signing_key',
      provenance: 'runtime_discovery',
    }), 'signing_secret')

    // Sparse signed URL via ledgerKind or sourceHopId
    assert.equal(classifyCapabilityShape({
      capId: 'cap:hop_h3:u1',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'signed_artifact_or_url',
      provenance: 'runtime_discovery',
    }), 'signed_or_download_url')

    // Sparse SCIM / delegation token via sourceHopId / label
    assert.equal(classifyCapabilityShape({
      capId: 'cap:hop_h4:v1',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'state_handle',
      secretKind: 'generic_secret',
      sourceHopId: 'scim_delegation_exchange',
      slot: 'v1',
      provenance: 'derived_hop',
    }), 'credential_token')

    // Ordinary entity ID sealed with generic_secret must NOT misclassify as signing_secret
    assert.equal(classifyCapabilityShape({
      capId: 'cap:hop_h5:order_id',
      origin: API_ORIGIN,
      actingPersona: 'member_a',
      ledgerKind: 'state_handle',
      secretKind: 'generic_secret',
      slot: 'order_id',
      summary: 'Sealed generic_secret slot order_id (sha256:ef012345)',
      provenance: 'runtime_discovery',
    }), 'entity_or_job_id')

    const sparseInput = {
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN, FILES_ORIGIN],
      capabilities: [
        {
          capId: 'cap:hop_h10:raw',
          origin: API_ORIGIN,
          actingPersona: 'member_a',
          ledgerKind: 'signing_material' as const,
          secretKind: 'signing_salt',
          slot: 'raw',
          summary: 'Sealed signing_salt slot raw (sha256:1234abcd)',
          provenance: 'runtime_discovery',
        },
        {
          capId: 'cap:hop_h11:raw',
          origin: API_ORIGIN,
          actingPersona: 'member_a',
          ledgerKind: 'scoped_token' as const,
          secretKind: 'bearer_token',
          label: 'delegation',
          slot: 'raw',
          provenance: 'derived_hop',
        },
      ],
      endpoints: [
        { origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 92 },
        { origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/scim/sync', authRequirement: 'bearerAuth', riskScore: 90 },
      ],
      observedResponses: [
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/ingest', status: 401, bodyPreview: 'missing signature' },
        { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/admin/scim/sync', status: 403, personaHandle: 'member_a', bodyPreview: 'forbidden' },
      ],
      personas: [{ handle: 'member_a', roleLabel: 'member' }],
    }

    const agenticPairs = rankCapabilityConsumerPairs({ ...sparseInput, llmMode: 'agentic' })
    assert.ok(agenticPairs.some(p => p.affordance === 'derive_signature' && p.consumer.normPath === '/v1/webhooks/ingest'))
    assert.ok(agenticPairs.some(p => p.affordance === 'pivot_with_credential' && p.consumer.normPath === '/v1/admin/scim/sync'))

    const noLlmPairs = rankCapabilityConsumerPairs({ ...sparseInput, llmMode: 'deterministic-no-llm' })
    assert.equal(noLlmPairs.length, 0, '--no-llm must emit strictly 0 pairs')
  })

  test('5. ExecReconPlanner.promoteRuntimeCompositeWave1Steps passes llmMode so --no-llm emits 0 capability frontier steps and store ledger pruning works end-to-end', async (t) => {
    const { storage } = makeStore(t, 'kovo-r9-gb-frontier-')
    const { runId, run } = await setupApprovedRun(storage, {
      seeds: [API_ORIGIN, EDGE_ORIGIN],
      tier: 2,
    })
    const activeOrigins = new Set([API_ORIGIN, EDGE_ORIGIN])

    // Add approved personas including dual_member and member_a
    const pMember = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId: run.projectId,
      handle: 'member_a',
      roleLabel: 'member',
      originAllowlist: [API_ORIGIN, EDGE_ORIGIN],
      authKind: 'bearer',
      secret: 'tok-member-a-test',
      canaryMarkers: [],
    })
    const pDual = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId: run.projectId,
      handle: 'dual_member',
      roleLabel: 'memberships=admin:org_a,viewer:org_b',
      originAllowlist: [API_ORIGIN, EDGE_ORIGIN],
      authKind: 'bearer',
      secret: 'tok-dual-member-test',
      canaryMarkers: [],
    })
    storage.updateRun(runId, { approvedPersonaIds: [pDual.id, pMember.id] })

    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/ingest', riskScore: 92, source: 'spa_crawl' })
    storage.upsertEndpoint({ runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/webhooks/pruned', riskScore: 90, source: 'spa_crawl' })

    const assetApi = run.candidates.find(c => c.origin === API_ORIGIN)!
    const worker = storage.makeWorker(run, 'investigation', assetApi, 'Probe', 'Initial', { sourceOrigins: [API_ORIGIN, EDGE_ORIGIN] })
    for (const [idx, path] of ['/v1/webhooks/ingest', '/v1/webhooks/pruned'].entries()) {
      storage.client.prepare(`
        INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        `r9-ex-${idx}`, runId, worker.id, run.scopeRevision, EDGE_ORIGIN, EDGE_ORIGIN, '[]',
        'POST', path, 401, 'application/json', 'member_a', '{}', '{}',
        JSON.stringify({ error: 'invalid signature' }), String(idx).repeat(64).slice(0, 64), 3, Date.now() + idx,
      )
    }

    const ledger = storage.capabilityLedger(runId)
    const sparseCap = formatDerivedCapabilityHandle('webhook_salt', 'v1')
    ledger.addCapability({
      capId: sparseCap,
      kind: 'signing_material',
      provenance: 'runtime_discovery',
      tenantScope: 'org_a',
      actorPersona: sparseCap, // buggy cap:* actorPersona persisted in ledger
      serviceOrigin: API_ORIGIN,
      surface: 'http',
      artifactDigest: computeArtifactDigest('r9-sparse-salt'),
      artifactSummary: 'Sealed signing_salt slot v1 (sha256:abcd)',
      metadata: { slot: 'v1', secretKind: 'signing_salt' },
      createdAtMs: 1000,
    })
    ledger.recordNegativeEdge({
      preconditionCapIds: ['surface:POST /v1/webhooks/pruned'],
      targetSurfaceKey: 'POST /v1/webhooks/pruned',
      hypothesisClass: 'broken_access_control',
      falsifiedByExchangeIds: ['r9-neg-1', 'r9-neg-2'],
      reason: 'control_blocked_cleanly',
      forcePrune: true,
    })

    // With 0 enabled model profiles (--no-llm), promoteRuntimeCompositeWave1Steps must emit 0 capability frontier steps
    const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
    t.after(() => engine.stop())
    const planner = plannerOf(engine)
    ;(planner as unknown as {
      promoteRuntimeCompositeWave1Steps: (r: typeof run, origins: ReadonlySet<string>) => number
    }).promoteRuntimeCompositeWave1Steps(storage.run(runId), activeOrigins)

    const frontierAfterNoLlm = storage.listChainSteps(runId, run.goalRevision)
      .filter(s => s.title.startsWith('Capability frontier ·'))
    assert.equal(frontierAfterNoLlm.length, 0, 'promoteRuntimeCompositeWave1Steps must pass llmMode=deterministic-no-llm when no model profiles exist')

    // In agentic mode, materializeCapabilityConsumerFrontierSteps strips cap:* actingPersona and prunes surface:*/vulnClass edge
    const created = materializeCapabilityConsumerFrontierSteps(storage, storage.run(runId), {
      activeOrigins,
      llmMode: 'agentic',
    })
    assert.equal(created.length, 1, 'must materialize only the unpruned /v1/webhooks/ingest frontier step')
    assert.ok(created[0]!.hypothesis.includes('/v1/webhooks/ingest'))
    assert.ok(created[0]!.hypothesis.includes('[acting_persona=member_a]'), `must fall back from cap:* to member_a: ${created[0]!.hypothesis}`)
    assert.ok(!created[0]!.hypothesis.includes('[acting_persona=cap:'))
  })
})
