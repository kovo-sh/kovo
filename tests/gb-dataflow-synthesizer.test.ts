import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { classifyHostTier } from '../src/server/agent-session.ts'
import {
  WHITEBOX_BLACKBOX_CAP_PRIORITY,
  chainLaneDispatchRank,
  classifyDispatchLane,
  computeHostTiers,
  hasRuntimeBackedChainEvidence,
  isGenericWave1BoundaryChainStep,
  isMultiHopChainStep,
} from '../src/server/exec-dispatch.ts'
import { buildWave1UncoveredOriginFallbackSteps } from '../src/server/exec-recon-multiorigin.ts'
import {
  materializeGreyBoxDataflowWave1Steps,
  synthesizeGreyBoxDataflowGraph,
  synthesizeGreyBoxDataflowStepsFromStore,
} from '../src/server/gb-dataflow-synthesizer.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const AUTH_ORIGIN = 'https://auth.synth-saas.example'
const API_ORIGIN = 'https://api.synth-saas.example'
const EDGE_ORIGIN = 'https://files.synth-saas.example'

describe('Phase-0 Grey-Box Producer->Consumer Cross-Origin Dataflow Synthesizer', () => {
  test('synthesizes 3-hop cross-origin invite/token -> token exchange -> protected resource mutation chain', () => {
    const t0 = performance.now()
    const res = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'ep-inv', origin: AUTH_ORIGIN, method: 'POST', pathTemplate: '/oauth2/invites', riskScore: 80 },
        { id: 'ep-exch', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/auth/exchange', riskScore: 85 },
        { id: 'ep-mut', origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/secrets/:id/revoke', authRequirement: 'bearerAuth', riskScore: 92 },
        { id: 'ep-health', origin: API_ORIGIN, method: 'GET', pathTemplate: '/healthz', riskScore: 10 },
      ],
      endpointParams: [
        { endpointId: 'ep-exch', name: 'invite_token', location: 'body', inferredType: 'string' },
        { endpointId: 'ep-mut', name: 'id', location: 'path', inferredType: 'string', isObjectId: true },
      ],
      brokerExchanges: [
        {
          origin: AUTH_ORIGIN,
          method: 'POST',
          pathAndQuery: '/oauth2/invites',
          status: 201,
          personaHandle: 'admin_a',
          bodyPreview: JSON.stringify({ invite_token: 'inv_sample_1', workspace_id: 'ws_1' }),
        },
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/auth/exchange',
          status: 200,
          personaHandle: 'member_b',
          bodyPreview: JSON.stringify({ access_token: 'tok_sample_2', expires_in: 3600 }),
        },
      ],
      personas: [
        { handle: 'admin_a', roleLabel: 'admin' },
        { handle: 'member_b', roleLabel: 'member' },
      ],
    })
    const elapsedMs = performance.now() - t0

    assert.ok(elapsedMs < 50, `expected <50ms deterministic synthesis, got ${elapsedMs.toFixed(1)}ms`)
    assert.ok(res.chains.length >= 1, 'must synthesize at least one multi-hop cross-origin chain')

    const top = res.chains[0]!
    assert.equal(top.hops.length, 3, 'top chain must be the 3-hop cross-origin invite -> exchange -> secret mutation chain')
    assert.deepEqual(top.origins, [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN])
    assert.deepEqual(top.hops.map(h => `${h.method} ${h.pathTemplate}`), [
      'POST /oauth2/invites',
      'POST /v1/auth/exchange',
      'POST /v1/secrets/:id/revoke',
    ])
    assert.ok(top.fields.includes('invite_token'))
    assert.ok(top.fields.includes('access_token'))
    assert.ok(top.step.hypothesis.includes('[chain_hops=3]'))
    assert.ok(top.step.hypothesis.includes('[lane=chain]'))
    assert.ok(top.step.hypothesis.includes('admin_a') && top.step.hypothesis.includes('member_b'))

    // Verify dispatch lane & runtime-backed evidence contracts
    const dispatchShape = { id: 'gb-df-1', seq: 1, ...top.step, sourceOrigins: top.step.origins }
    assert.equal(isMultiHopChainStep(dispatchShape), true)
    assert.equal(classifyDispatchLane(dispatchShape), 'chain')
    assert.equal(hasRuntimeBackedChainEvidence(dispatchShape), true)
    assert.equal(isGenericWave1BoundaryChainStep(dispatchShape), false)
    assert.equal(chainLaneDispatchRank(dispatchShape), 0)
  })

  test('synthesizes 3-hop async job 202 -> signed URL -> download chain across origins', () => {
    const res = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'ep-create-export', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/exports', riskScore: 80 },
        { id: 'ep-export-url', origin: API_ORIGIN, method: 'GET', pathTemplate: '/v1/exports/:exportId/url', riskScore: 84 },
        { id: 'ep-download', origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/v1/artifacts/:id/download', riskScore: 88 },
      ],
      endpointParams: [
        { endpointId: 'ep-export-url', name: 'exportId', location: 'path', isObjectId: true },
        { endpointId: 'ep-download', name: 'id', location: 'path', isObjectId: true },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/exports',
          status: 202,
          personaHandle: 'member_a',
          bodyPreview: JSON.stringify({ export_id: 'exp_99', status: 'queued' }),
        },
        {
          origin: API_ORIGIN,
          method: 'GET',
          pathAndQuery: '/v1/exports/exp_99/url',
          status: 200,
          personaHandle: 'member_a',
          bodyPreview: JSON.stringify({ download_url: `${EDGE_ORIGIN}/v1/artifacts/art_77/download` }),
        },
      ],
      personas: [{ handle: 'member_a', roleLabel: 'member' }],
    })

    assert.ok(res.chains.length >= 1, 'must synthesize async job -> signed URL -> download chain')
    const top = res.chains[0]!
    assert.equal(top.hops.length, 3)
    assert.equal(top.has202, true, 'must flag 202 async job signal')
    assert.deepEqual(top.origins, [API_ORIGIN, EDGE_ORIGIN])
    assert.ok(top.kinds.includes('async_job_or_export'))
    assert.ok(top.kinds.includes('signed_url_or_location'))
    assert.equal(top.step.category, 'upload-storage')
    assert.ok(top.step.hypothesis.includes('export_id'))
    assert.ok(top.step.hypothesis.includes('download_url'))
  })

  test('boosts chains with multi-persona response asymmetry (200 vs 403) ahead of symmetric chains', () => {
    const res = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        // Symmetric order chain
        { id: 'ep-ord-create', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders', riskScore: 70 },
        { id: 'ep-ord-approve', origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:orderId/approve', riskScore: 75 },
        // Asymmetric payout chain (200 for admin_a, 403 for member_b, plus sibling 200)
        { id: 'ep-pay-create', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/payouts', riskScore: 70 },
        { id: 'ep-pay-settle', origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/payouts/:payoutId/settle', riskScore: 75 },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/orders',
          status: 201,
          personaHandle: 'admin_a',
          bodyPreview: JSON.stringify({ order_id: 'ord_1' }),
        },
        {
          origin: EDGE_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/orders/ord_1/approve',
          status: 200,
          personaHandle: 'admin_a',
          bodyPreview: JSON.stringify({ ok: true }),
        },
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/payouts',
          status: 201,
          personaHandle: 'admin_a',
          bodyPreview: JSON.stringify({ payout_id: 'pay_1' }),
        },
        {
          origin: EDGE_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/payouts/pay_1/settle',
          status: 200,
          personaHandle: 'admin_a',
          bodyPreview: JSON.stringify({ ok: true }),
        },
        {
          origin: EDGE_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/payouts/pay_1/settle',
          status: 403,
          personaHandle: 'member_b',
          bodyPreview: JSON.stringify({ error: 'forbidden' }),
        },
      ],
      personas: [
        { handle: 'admin_a', roleLabel: 'admin' },
        { handle: 'member_b', roleLabel: 'member' },
      ],
    })

    assert.ok(res.chains.length >= 2)
    assert.equal(res.chains[0]!.hasPersonaAsymmetry, true, 'asymmetric payout chain must rank #1')
    assert.ok(res.chains[0]!.fields.includes('payout_id'))
    assert.ok(res.chains[0]!.step.hypothesis.includes('[persona_diff:'))
    assert.ok(res.chains[0]!.step.skills.includes('authz-differential'))
    assert.ok(res.chains[0]!.score > res.chains[1]!.score, 'asymmetry must yield strictly higher score')
  })

  test('extracts Location redirect headers and Set-Cookie names without leaking secret values', () => {
    const res = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      endpoints: [
        { id: 'ep-sso', origin: AUTH_ORIGIN, method: 'GET', pathTemplate: '/sso/start', riskScore: 80 },
        { id: 'ep-cb', origin: API_ORIGIN, method: 'GET', pathTemplate: '/auth/callback', riskScore: 82 },
        { id: 'ep-admin', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/settings/sync', authRequirement: 'session', riskScore: 90 },
      ],
      brokerExchanges: [
        {
          origin: AUTH_ORIGIN,
          method: 'GET',
          pathAndQuery: '/sso/start',
          status: 302,
          personaHandle: 'member_a',
          respHeaders: JSON.stringify({
            Location: `${API_ORIGIN}/auth/callback?code=opaque_secret_value_999`,
            'Set-Cookie': 'session_id=topsecret_cookie_val_888; HttpOnly; Secure',
          }),
          bodyPreview: '',
        },
      ],
    })

    assert.ok(res.chains.length >= 1)
    const allHypText = res.steps.map(s => `${s.title} ${s.hypothesis}`).join('\n')
    assert.ok(!allHypText.includes('opaque_secret_value_999'), 'must never leak query token values')
    assert.ok(!allHypText.includes('topsecret_cookie_val_888'), 'must never leak cookie values')
    assert.ok(res.chains.some(c => c.fields.includes('Location') || c.fields.includes('session_id')))
  })

  test('handles truncated JSON previews, sibling-route asymmetry, and caps output at 6 diverse chains', () => {
    const res = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'ep-doc-create', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/docs', riskScore: 72 },
        { id: 'ep-doc-read', origin: API_ORIGIN, method: 'GET', pathTemplate: '/v1/docs/:id', riskScore: 74 },
        { id: 'ep-doc-content', origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/v1/docs/:id/content', riskScore: 80 },
      ],
      brokerExchanges: [
        {
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/docs',
          status: 201,
          personaHandle: 'member_b',
          bodyPreview: '{"doc_id":"doc_1","nested":{"download_url":"https://files.synth-saas.example/v1/docs/doc_1/content","trunc',
        },
        {
          origin: API_ORIGIN,
          method: 'GET',
          pathAndQuery: '/v1/docs/doc_1',
          status: 403,
          personaHandle: 'member_b',
          bodyPreview: '{"error":"forbidden"}',
        },
      ],
      personas: [{ handle: 'member_b', roleLabel: 'member' }],
    })

    assert.ok(res.chains.length >= 1)
    assert.ok(res.steps.length <= 6)
    assert.ok(res.chains[0]!.fields.some(f => f === 'doc_id' || f === 'download_url'))
    assert.equal(res.chains[0]!.hasPersonaAsymmetry, true, 'sibling 403 vs 201 on doc noun must flag persona asymmetry')
  })

  test('zero firing when mountedRepos.length > 0 or sourceMounted is true, and graceful empty output on 0 exchanges/endpoints', () => {
    const wbByFlag = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      sourceMounted: true,
      endpoints: [
        { id: 'ep1', origin: AUTH_ORIGIN, method: 'POST', pathTemplate: '/oauth/token' },
        { id: 'ep2', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/users/:id/revoke', authRequirement: 'bearer' },
      ],
    })
    assert.deepEqual(wbByFlag.steps, [])
    assert.equal(wbByFlag.chains.length, 0)

    const wbByRepos = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      mountedRepos: ['/repos/backend'],
      endpoints: [
        { id: 'ep1', origin: AUTH_ORIGIN, method: 'POST', pathTemplate: '/oauth/token' },
        { id: 'ep2', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/admin/users/:id/revoke', authRequirement: 'bearer' },
      ],
    })
    assert.deepEqual(wbByRepos.steps, [])

    const empty = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      endpoints: [],
      brokerExchanges: [],
    })
    assert.deepEqual(empty.steps, [])
    assert.equal(empty.nodeCount, 0)
    assert.equal(empty.edgeCount, 0)
  })

  test('store-backed synthesis + buildWave1UncoveredOriginFallbackSteps + idempotent materialization wire cleanly in grey-box and stay silent in white-box', async (t) => {
    const { storage } = makeStore(t, 'kovo-gb-df-')
    const { runId, run } = await setupApprovedRun(storage, {
      seeds: [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN],
      tier: 2,
    })
    const assetAuth = run.candidates.find(c => c.origin === AUTH_ORIGIN)!
    const worker = storage.makeWorker(run, 'threat_model', assetAuth, 'Phase 0', 'Recon', {
      sourceOrigins: [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN],
    })

    const epInv = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: AUTH_ORIGIN, method: 'POST',
      pathTemplate: '/oauth/invites', riskScore: 82, source: 'spa_crawl',
    })
    const epExch = storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: API_ORIGIN, method: 'POST',
      pathTemplate: '/v1/tokens/exchange', riskScore: 86, source: 'openapi',
    })
    storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: EDGE_ORIGIN, method: 'POST',
      pathTemplate: '/v1/docs/:id/export', authRequirement: 'bearerAuth', riskScore: 90, source: 'openapi',
    })
    storage.recordApiDependency({
      runId, producerEndpointId: epInv.id, consumerEndpointId: epExch.id, resourceKey: 'invite_code',
    })
    storage.client.prepare(`
      INSERT INTO broker_exchanges (id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins, method, path_and_query, status, media_type, persona_handle, req_headers, resp_headers, body_preview, body_sha256, duration_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'gb-df-ex-1', runId, worker.id, run.scopeRevision, API_ORIGIN, API_ORIGIN, '[]',
      'POST', '/v1/tokens/exchange', 200, 'application/json', 'member_a', '{}', '{}',
      JSON.stringify({ access_token: 'tok_placeholder' }), 'abc123', 4, Date.now(),
    )

    const freshRun = storage.run(runId)
    const activeOrigins = new Set([AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN])

    // White-box store call returns empty
    assert.deepEqual(
      synthesizeGreyBoxDataflowStepsFromStore(storage, freshRun, { activeOrigins, sourceMounted: true }),
      [],
    )

    // Grey-box fallback wiring injects ranked multi-hop dataflow steps
    const entries = [
      { origin: AUTH_ORIGIN, riskTier: 'high' as const, surfaceTags: ['auth'], rationale: 'auth' },
      { origin: API_ORIGIN, riskTier: 'high' as const, surfaceTags: ['api'], rationale: 'api' },
      { origin: EDGE_ORIGIN, riskTier: 'high' as const, surfaceTags: ['upload'], rationale: 'edge' },
    ]
    const hostTiers = computeHostTiers([...activeOrigins], entries)
    const gbFallback = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps: [],
      discoveredEndpointOrigins: activeOrigins,
      finalHostTiers: hostTiers,
      sourceMounted: false,
      codeAuditStepsCreated: 0,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
      storage,
      run: freshRun,
      activeOrigins,
    })
    assert.ok(gbFallback.seededSteps.some(s => s.title.startsWith('GB dataflow chain (')), 'Grey-Box fallback must prepend synthesized dataflow chain steps')
    assert.ok(gbFallback.uncoveredAddedCount >= 1)

    // White-box fallback wiring does NOT inject GB dataflow steps
    const wbFallback = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps: [{ status: 'ready', sourceOrigins: [AUTH_ORIGIN] }],
      discoveredEndpointOrigins: activeOrigins,
      finalHostTiers: hostTiers,
      sourceMounted: true,
      codeAuditStepsCreated: 2,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
      storage,
      run: freshRun,
      activeOrigins,
    })
    assert.equal(wbFallback.seededSteps.filter(s => s.title.startsWith('GB dataflow chain (')).length, 0)

    // Post-floor materialization persists ready steps and is idempotent on repeat
    const first = materializeGreyBoxDataflowWave1Steps(storage, freshRun, { activeOrigins, sourceMounted: false })
    assert.ok(first.length >= 1)
    assert.ok(first.every(s => s.status === 'ready' && s.sourceOrigins.length >= 2))
    const repeat = materializeGreyBoxDataflowWave1Steps(storage, freshRun, { activeOrigins, sourceMounted: false })
    assert.equal(repeat.length, 0, 'repeat materialization with unchanged state must be idempotent')
  })
})
