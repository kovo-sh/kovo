import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import type { IntentCompletion, WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import { buildAssignmentBriefPacket, classifyPersonaPrivilege } from '../src/server/assignment-brief.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { publicPersonasFromGrant } from '../src/server/exec-exchange.ts'
import { sortPersonasLowPrivFirst } from '../src/server/exec-recon-planner.ts'
import {
  buildConsolidatedExploiterToolset,
  buildExploiterUserPrompt,
} from '../src/server/exploiter-tools.ts'
import { synthesizeGreyBoxDataflowGraph } from '../src/server/gb-dataflow-synthesizer.ts'
import {
  extractSiblingVerbCandidates,
  probeSiblingVerbCandidates,
} from '../src/server/phase0-sibling-verbs.ts'
import type { RecordedRequestExchange } from '../src/server/trace-proof-compiler.ts'
import {
  makeLabGrant,
  makeStore,
  setupApprovedRun,
  startHttpFixture,
  withEnv,
} from './v4-tier-helpers.ts'

const API_ORIGIN = 'https://api.m2r7-lab.example'
const EDGE_ORIGIN = 'https://edge.m2r7-lab.example'
const AUTH_ORIGIN = 'https://auth.m2r7-lab.example'

function extractText(res: { output?: Array<{ type: string; text?: string }> }): string {
  return (res.output ?? []).map(p => p.text ?? '').join('\n')
}

function makeDummyHandlers(overrides?: Partial<WorkerToolHandlers>): WorkerToolHandlers {
  return {
    request_http: async () => ({ exchangeId: 'ex-1', status: 200, bodySha256: 'abc', bodyPreview: '{}' }),
    request_http_batch: async () => ({ count: 1, results: [] }),
    request_http_race: async args => ({ count: args.requests.length, results: [] }),
    browser_visit: async () => ({ status: 200 }),
    browser_session: async () => ({ ok: true }),
    crawl_state_graph: async () => ({ pages: [] }),
    probe_websocket: async () => ({ frames: [] }),
    probe_surface: async () => ({ hits: [] }),
    probe_differential: async () => ({ anomalies: [] }),
    run_safe_templates: async () => ({ matches: [] }),
    inspect_dns: async () => ({ records: [] }),
    inspect_tls: async () => ({ valid: true }),
    mint_canary: async () => ({ token: 'tok-1' }),
    check_canary: async () => ({ hits: [] }),
    mint_second_order_canary: async () => ({ marker: 'gn2o_1' }),
    list_second_order_canaries: async () => ({ items: [] }),
    run_offline_script: async args => ({ runtime: args.runtime, stdout: 'ok' }),
    derive_evidence: async args => ({ command: args.command, stdout: 'sliced' }),
    analyze_artifact: async args => ({ tool: args.tool, findings: [] }),
    run_sast_scan: async args => ({ repo: args.repo, engines: args.engines, findings: [] }),
    search_exchanges: async () => ({ items: [] }),
    get_exchange: async args => ({ id: args.exchangeId, status: 200 }),
    search_facts: async () => ({ items: [] }),
    read_peer_trace: async () => ({ turns: [] }),
    query_cves: async args => ({ package: args.package, cves: [] }),
    record_fact: async args => ({ recorded: true, kind: args.kind }),
    suggest_candidate_host: async args => ({ suggested: true, origin: args.origin }),
    complete_intent: async c => ({ ok: true, status: c.status }),
    ...overrides,
  }
}

describe('M2 R7 Fix 1: revoked_stale persona ranking and active low-priv primacy across all persona selectors', () => {
  test('classifyPersonaPrivilege ranks revoked/demoted/stale handles as revoked_stale (rank 3) strictly behind active low (0), standard (1), and multi_tenant (2)', () => {
    for (const [handle, role] of [
      ['revoked_or_demoted', 'revoked member'],
      ['demoted_user', 'demoted'],
      ['disabled_acct', 'disabled user'],
      ['suspended_member', 'suspended'],
      ['former_admin', 'former admin'],
      ['expired_session', 'expired token'],
    ] as const) {
      const cls = classifyPersonaPrivilege(handle, role)
      assert.equal(cls.tier, 'revoked_stale', `${handle} must be revoked_stale`)
      assert.equal(cls.revokedStale, true)
      assert.equal(cls.elevated, false)
      assert.equal(cls.multiTenant, false)
      assert.equal(cls.rank, 3)
    }

    const low = classifyPersonaPrivilege('viewer_a', 'viewer')
    const member = classifyPersonaPrivilege('member_a', 'member')
    const standard = classifyPersonaPrivilege('manager_a', 'manager')
    const multiTenant = classifyPersonaPrivilege('dual_user', 'memberships=admin:org_a,viewer:org_b')
    const revoked = classifyPersonaPrivilege('revoked_or_demoted', 'revoked member')
    const elevatedNonAdmin = classifyPersonaPrivilege('mod_ops', 'moderator')
    const elevatedAdmin = classifyPersonaPrivilege('owner_a', 'owner')

    assert.equal(low.rank, 0)
    assert.equal(member.rank, 0)
    assert.equal(standard.rank, 1)
    assert.equal(multiTenant.rank, 2)
    assert.equal(revoked.rank, 3)
    assert.equal(elevatedNonAdmin.rank, 4)
    assert.equal(elevatedAdmin.rank, 5)
    assert.equal(low.revokedStale, false)
    assert.equal(standard.revokedStale, false)
    assert.equal(multiTenant.revokedStale, false)
    assert.equal(elevatedAdmin.revokedStale, false)
  })

  test('assignment-brief, exec-exchange, exec-recon-planner, and exploiter-tools place active low-priv personas ahead of revoked_or_demoted and preserve configIndex ASC', () => {
    const grantPersonas = new Map([
      ['owner_a', { handle: 'owner_a', roleLabel: 'owner', originAllowlist: [API_ORIGIN] }],
      ['revoked_or_demoted', { handle: 'revoked_or_demoted', roleLabel: 'revoked member', originAllowlist: [API_ORIGIN] }],
      ['dual_actor', { handle: 'dual_actor', roleLabel: 'memberships=admin:org_a,viewer:org_b', originAllowlist: [API_ORIGIN] }],
      ['viewer_z', { handle: 'viewer_z', roleLabel: 'viewer', originAllowlist: [API_ORIGIN] }],
      ['member_a', { handle: 'member_a', roleLabel: 'member', originAllowlist: [API_ORIGIN] }],
      ['editor_a', { handle: 'editor_a', roleLabel: 'editor', originAllowlist: [API_ORIGIN] }],
    ])

    // 1. publicPersonasFromGrant preserves configIndex from grant insertion order
    const pub = publicPersonasFromGrant({ personas: grantPersonas })
    assert.deepEqual(pub.map(p => [p.handle, p.configIndex]), [
      ['owner_a', 0],
      ['revoked_or_demoted', 1],
      ['dual_actor', 2],
      ['viewer_z', 3],
      ['member_a', 4],
      ['editor_a', 5],
    ])

    // 2. sortPersonasLowPrivFirst routes through classifyPersonaPrivilege + configIndex ASC (never alphabetical)
    const sorted = sortPersonasLowPrivFirst(pub)
    assert.deepEqual(sorted.map(p => p.handle), [
      'viewer_z',
      'member_a',
      'editor_a',
      'dual_actor',
      'revoked_or_demoted',
      'owner_a',
    ])

    // 3. assignment-brief renders revokedStale flag and puts active low-priv first in configured order
    const brief = JSON.parse(buildAssignmentBriefPacket({
      missionKind: 'multihop_chain',
      origin: API_ORIGIN,
      routes: [{ method: 'GET', path: '/v1/orders', riskScore: 80 }],
      personas: pub.map(p => ({ handle: p.handle, role: p.roleLabel, configIndex: p.configIndex })),
    }).text) as { personas: Array<{ handle: string; roleTier: string; revokedStale?: boolean; multiTenant?: boolean; elevated?: boolean }> }
    assert.deepEqual(brief.personas.map(p => p.handle), [
      'viewer_z',
      'member_a',
      'editor_a',
      'dual_actor',
      'revoked_or_demoted',
      'owner_a',
    ])
    const revokedBrief = brief.personas.find(p => p.handle === 'revoked_or_demoted')!
    assert.equal(revokedBrief.roleTier, 'revoked_stale')
    assert.equal(revokedBrief.revokedStale, true)

    // 4. buildExploiterUserPrompt partitions revoked_or_demoted OUT of attackerBase into revokedStalePersonas
    const userPrompt = JSON.parse(buildExploiterUserPrompt({
      goal: 'Verify tenant boundaries',
      step: { id: 's1', title: 'Authz check', hypothesis: 'Cross-tenant read', category: 'broken-access-control' },
      origins: [API_ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
      personas: sorted,
    })) as {
      primaryAttackerBasePersona?: string
      attackerBasePersonas: { primary?: string; personas: Array<{ handle: string }> }
      multiTenantBasePersonas?: { instruction: string; personas: Array<{ handle: string }> }
      revokedStalePersonas?: { instruction: string; personas: Array<{ handle: string; roleTier: string; revokedStale: boolean }> }
      elevatedReferencePersonas?: { personas: Array<{ handle: string }> }
    }

    assert.equal(userPrompt.primaryAttackerBasePersona, 'viewer_z')
    assert.equal(userPrompt.attackerBasePersonas.primary, 'viewer_z')
    assert.deepEqual(userPrompt.attackerBasePersonas.personas.map(p => p.handle), ['viewer_z', 'member_a', 'editor_a'])
    assert.deepEqual(userPrompt.multiTenantBasePersonas?.personas.map(p => p.handle), ['dual_actor'])
    assert.deepEqual(userPrompt.revokedStalePersonas?.personas.map(p => p.handle), ['revoked_or_demoted'])
    assert.equal(userPrompt.revokedStalePersonas?.personas[0]?.roleTier, 'revoked_stale')
    assert.equal(userPrompt.revokedStalePersonas?.personas[0]?.revokedStale, true)
    assert.match(userPrompt.revokedStalePersonas?.instruction ?? '', /ONLY for stale-session \/ revocation-bypass checks/i)
    assert.deepEqual(userPrompt.elevatedReferencePersonas?.personas.map(p => p.handle), ['owner_a'])
  })

  test('gb-dataflow-synthesizer never chooses revoked_or_demoted as basePersona and uses multiTenant only when preferMultiTenant is true', () => {
    const personas = [
      { handle: 'owner_a', roleLabel: 'owner' },
      { handle: 'revoked_or_demoted', roleLabel: 'revoked member' },
      { handle: 'dual_actor', roleLabel: 'memberships=admin:org_a,viewer:org_b' },
      { handle: 'viewer_z', roleLabel: 'viewer' },
      { handle: 'member_a', roleLabel: 'member' },
    ]

    // Non-dual-tenant chain picks active non-revoked low-priv persona (viewer_z, configured before member_a)
    const regularRes = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      endpoints: [
        { id: 'r1', origin: AUTH_ORIGIN, method: 'POST', pathTemplate: '/oauth/invites', riskScore: 80 },
        { id: 'r2', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/invites/redeem', riskScore: 85 },
      ],
      brokerExchanges: [
        { origin: AUTH_ORIGIN, method: 'POST', pathAndQuery: '/oauth/invites', status: 201, personaHandle: 'revoked_or_demoted', bodyPreview: JSON.stringify({ invite_token: 'inv_1' }) },
      ],
      personas,
    })
    assert.ok(regularRes.chains.length >= 1)
    assert.match(regularRes.chains[0]!.step.hypothesis, /Base persona:\s*viewer_z\b/)
    assert.doesNotMatch(regularRes.chains[0]!.step.hypothesis, /Base persona:\s*revoked_or_demoted\b/)

    // Non-dual-tenant chain with NO active single-tenant low-priv persona does NOT fall back to revoked_or_demoted or dual_actor
    const noActiveLowRes = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      endpoints: [
        { id: 'n1', origin: AUTH_ORIGIN, method: 'POST', pathTemplate: '/oauth/invites', riskScore: 80 },
        { id: 'n2', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/invites/redeem', riskScore: 85 },
      ],
      brokerExchanges: [
        { origin: AUTH_ORIGIN, method: 'POST', pathAndQuery: '/oauth/invites', status: 201, personaHandle: 'revoked_or_demoted', bodyPreview: JSON.stringify({ invite_token: 'inv_2' }) },
      ],
      personas: [
        { handle: 'owner_a', roleLabel: 'owner' },
        { handle: 'revoked_or_demoted', roleLabel: 'revoked member' },
        { handle: 'dual_actor', roleLabel: 'memberships=admin:org_a,viewer:org_b' },
      ],
    })
    assert.ok(noActiveLowRes.chains.length >= 1)
    assert.doesNotMatch(noActiveLowRes.chains[0]!.step.hypothesis, /Base persona:/)

    // Cache-bleed / dual-tenant chain picks dual_actor (multiTenant) over revoked_or_demoted
    const cacheRes = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'c1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/cache/prime', riskScore: 80 },
        { id: 'c2', origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/v1/cache/:id/export', riskScore: 86 },
      ],
      brokerExchanges: [
        { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/cache/prime', status: 200, personaHandle: 'revoked_or_demoted', bodyPreview: JSON.stringify({ cache_id: 'c_1' }) },
      ],
      personas,
    })
    assert.ok(cacheRes.chains.length >= 1)
    assert.match(cacheRes.chains[0]!.step.hypothesis, /Base persona:\s*dual_actor\b/)
  })

  test('phase0-sibling-verbs skips revoked_or_demoted and admin, selecting active low-priv persona in configured order', async (t: TestContext) => {
    const authHeaders: Array<string | undefined> = []
    const fx = await startHttpFixture(t, (req, _body, res) => {
      authHeaders.push(typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined)
      if (req.url === '/api/payouts/456/rebind' && req.method === 'OPTIONS') {
        res.statusCode = 204
        res.setHeader('Allow', 'PATCH')
        res.end()
        return
      }
      res.statusCode = 404
      res.end()
    })

    const { storage } = makeStore(t, 'kovo-m2-r7-sibling-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 200 })
    const broker = new RequestBroker({ rejectUnauthorized: false })
    const grant: Grant = {
      ...makeLabGrant(fx.origin),
      personas: new Map([
        ['admin_a', {
          id: 'p-admin', handle: 'admin_a', roleLabel: 'admin', privilege: 'admin' as const,
          originAllowlist: [fx.origin], authKind: 'bearer' as const, headerName: null, secret: 'admin-token', canaryMarkers: [],
        }],
        ['revoked_or_demoted', {
          id: 'p-revoked', handle: 'revoked_or_demoted', roleLabel: 'revoked member', privilege: 'member' as const,
          originAllowlist: [fx.origin], authKind: 'bearer' as const, headerName: null, secret: 'revoked-token', canaryMarkers: [],
        }],
        ['viewer_z', {
          id: 'p-viewer-z', handle: 'viewer_z', roleLabel: 'viewer', privilege: 'member' as const,
          originAllowlist: [fx.origin], authKind: 'bearer' as const, headerName: null, secret: 'viewer-z-token', canaryMarkers: [],
        }],
        ['viewer_a', {
          id: 'p-viewer-a', handle: 'viewer_a', roleLabel: 'viewer', privilege: 'member' as const,
          originAllowlist: [fx.origin], authKind: 'bearer' as const, headerName: null, secret: 'viewer-a-token', canaryMarkers: [],
        }],
      ]),
    }

    const candidates = extractSiblingVerbCandidates({
      endpoints: [
        { origin: fx.origin, method: 'PATCH', path: '/api/orders/123/rebind' },
        { origin: fx.origin, method: 'POST', path: '/api/payouts/456/approve' },
      ],
    })

    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => probeSiblingVerbCandidates({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      broker,
      grant,
      signal: AbortSignal.timeout(10_000),
      candidates,
      personas: ['admin_a', 'revoked_or_demoted', 'viewer_a', 'viewer_z'],
    }))

    assert.ok(authHeaders.length > 0)
    assert.ok(
      authHeaders.every(h => h === 'Bearer viewer-z-token'),
      `expected configured active viewer_z token (never revoked_or_demoted or alphabetical viewer_a), got: ${authHeaders.join(', ')}`,
    )

    // When ONLY revoked_or_demoted + admin exist, fall back to unauthenticated (never use revoked or admin token)
    const revokedOnlyHeaders: Array<string | undefined> = []
    const fx2 = await startHttpFixture(t, (req, _body, res) => {
      revokedOnlyHeaders.push(typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined)
      res.statusCode = 404
      res.end()
    })
    const { runId: runId2, run: run2 } = await setupApprovedRun(storage, { seeds: [fx2.origin], budgetRequests: 200 })
    const grantRevokedOnly: Grant = {
      ...makeLabGrant(fx2.origin),
      personas: new Map([
        ['admin_a', {
          id: 'p-admin2', handle: 'admin_a', roleLabel: 'admin', privilege: 'admin' as const,
          originAllowlist: [fx2.origin], authKind: 'bearer' as const, headerName: null, secret: 'admin-token', canaryMarkers: [],
        }],
        ['revoked_or_demoted', {
          id: 'p-revoked2', handle: 'revoked_or_demoted', roleLabel: 'revoked member', privilege: 'member' as const,
          originAllowlist: [fx2.origin], authKind: 'bearer' as const, headerName: null, secret: 'revoked-token', canaryMarkers: [],
        }],
      ]),
    }
    const cands2 = extractSiblingVerbCandidates({
      endpoints: [
        { origin: fx2.origin, method: 'PATCH', path: '/api/orders/123/rebind' },
        { origin: fx2.origin, method: 'POST', path: '/api/payouts/456/approve' },
      ],
    })
    await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => probeSiblingVerbCandidates({
      storage,
      runId: runId2,
      scopeRevision: run2.scopeRevision,
      broker,
      grant: grantRevokedOnly,
      signal: AbortSignal.timeout(10_000),
      candidates: cands2,
      personas: ['admin_a', 'revoked_or_demoted'],
    }))
    assert.ok(revokedOnlyHeaders.length > 0)
    assert.ok(revokedOnlyHeaders.every(h => h === undefined), `revoked/admin token must never be used: ${revokedOnlyHeaders.join(', ')}`)
  })
})

describe('M2 R7 Fix 2: bounded economic/race escalation gate in complete_intent and tightened race burst detection', () => {
  test('complete_intent blocks ONCE with economic_race_escalation_required after mutating confirmation without race, then allows cleanly after http(mode="race")', async () => {
    const completions: IntentCompletion[] = []
    const recorded = new Map<string, RecordedRequestExchange>([
      // 4 concurrent GETs within 50ms MUST NOT falsely count as a mutating race burst!
      ['get-1', { exchangeId: 'get-1', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/orders', persona: 'member_a', status: 200, responseJson: { items: [] }, timestampMs: 100 }],
      ['get-2', { exchangeId: 'get-2', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/orders', persona: 'member_a', status: 200, responseJson: { items: [] }, timestampMs: 110 }],
      ['get-3', { exchangeId: 'get-3', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/orders', persona: 'member_a', status: 200, responseJson: { items: [] }, timestampMs: 120 }],
      ['get-4', { exchangeId: 'get-4', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/orders', persona: 'member_a', status: 200, responseJson: { items: [] }, timestampMs: 130 }],
      // 4 sequential POSTs spanning 300ms (> 250ms) MUST NOT count as a concurrent race burst!
      ['slow-1', { exchangeId: 'slow-1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', persona: 'member_a', status: 201, responseJson: { orderId: 'o1' }, timestampMs: 1000 }],
      ['slow-2', { exchangeId: 'slow-2', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', persona: 'member_a', status: 201, responseJson: { orderId: 'o2' }, timestampMs: 1100 }],
      ['slow-3', { exchangeId: 'slow-3', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', persona: 'member_a', status: 201, responseJson: { orderId: 'o3' }, timestampMs: 1200 }],
      ['slow-4', { exchangeId: 'slow-4', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', persona: 'member_a', status: 201, responseJson: { orderId: 'o4' }, timestampMs: 1300 }],
      // 3-hop mutating chain ending in GET readback terminal
      ['hop-1', { exchangeId: 'hop-1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', persona: 'member_a', status: 201, requestJson: { amount: 100 }, responseJson: { orderId: 'ord_9' }, timestampMs: 3000 }],
      ['hop-2', { exchangeId: 'hop-2', origin: API_ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_9/rebind', persona: 'member_a', status: 200, requestJson: { targetId: 'acct_b' }, responseJson: { ok: true }, timestampMs: 4000 }],
      ['hop-3', { exchangeId: 'hop-3', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/orders/ord_9', persona: 'member_a', status: 200, responseJson: { orderId: 'ord_9', balance: 500 }, timestampMs: 5000 }],
    ])

    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-r7-gate',
      assignmentId: 'asg-r7-gate',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: c => { completions.push(c) },
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-r7-1' }),
    })

    const submit = tools.find(t => t.name === 'submit_exploit_trace')!
    const httpTool = tools.find(t => t.name === 'http')!
    const complete = tools.find(t => t.name === 'complete_intent')!

    // 1. Confirm 3-hop mutating chain ending in GET readback -> MUST trigger mutating_economic_variant_check
    const subRes = JSON.parse(extractText(await submit.execute({
      title: 'Order rebind mutating chain verified via readback',
      vulnClass: 'broken_access_control',
      exchangeIds: ['hop-1', 'hop-2', 'hop-3'],
      terminalExchangeId: 'hop-3',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(subRes.confirmed, true)
    assert.equal(subRes.keepChaining, true)
    assert.equal(subRes.escalationReason, 'mutating_economic_variant_check')

    // 2. Calling complete_intent without running race -> BLOCKED ONCE with economic_race_escalation_required
    const blockedRaw = await complete.execute({
      status: 'proved',
      summary: 'Confirmed order rebind.',
    }, {} as never, { abortSignal: new AbortController().signal } as never)
    assert.equal(blockedRaw.isError, true)
    const blocked = JSON.parse(extractText(blockedRaw)) as Record<string, unknown>
    assert.equal(blocked.ok, false)
    assert.equal(blocked.blocked, true)
    assert.equal(blocked.reason, 'economic_race_escalation_required')
    assert.match(String(blocked.message), /N >= 5/i)
    assert.equal(completions.length, 0, 'onCompleteIntent must not fire when blocked')

    // 3. Worker runs http(mode="race") with N = 5 parallel calls
    await httpTool.execute({
      mode: 'race',
      requests: Array.from({ length: 5 }, () => ({
        origin: API_ORIGIN,
        method: 'POST',
        pathAndQuery: '/v1/orders/ord_9/settle',
        persona: 'member_a',
      })),
    }, {} as never, { abortSignal: new AbortController().signal } as never)

    // 4. Subsequent complete_intent succeeds cleanly
    const doneRaw = await complete.execute({
      status: 'proved',
      summary: 'Confirmed order rebind and tested concurrent settlement race.',
    }, {} as never, { abortSignal: new AbortController().signal } as never) as { isError?: boolean; control?: { terminate?: boolean }; output?: Array<{ type: string; text?: string }> }
    assert.notEqual(doneRaw.isError, true)
    assert.equal(doneRaw.control?.terminate, true)
    assert.equal(completions.length, 1)
  })

  test('complete_intent escalation gate is strictly bounded (never loops even without a race call) and respects remaining budget', async () => {
    const completions: IntentCompletion[] = []
    const recorded = new Map<string, RecordedRequestExchange>([
      ['m1', { exchangeId: 'm1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts', persona: 'member_a', status: 201, responseJson: { payoutId: 'p1' }, timestampMs: 1000 }],
    ])

    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-r7-noloop',
      assignmentId: 'asg-r7-noloop',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: c => { completions.push(c) },
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-r7-noloop' }),
    })

    const submit = tools.find(t => t.name === 'submit_exploit_trace')!
    const complete = tools.find(t => t.name === 'complete_intent')!

    await submit.execute({
      title: 'Sequential payout mutation',
      vulnClass: 'economic_conservation',
      exchangeIds: ['m1'],
      terminalExchangeId: 'm1',
    }, {} as never, { abortSignal: new AbortController().signal } as never)

    // First complete_intent -> blocked once
    const first = await complete.execute({ status: 'proved', summary: 'Done 1' }, {} as never, { abortSignal: new AbortController().signal } as never)
    assert.equal(first.isError, true)
    assert.equal((JSON.parse(extractText(first)) as Record<string, unknown>).reason, 'economic_race_escalation_required')
    assert.equal(completions.length, 0)

    // Second complete_intent without running race -> allowed (escalationGateConsumed prevents looping!)
    const second = await complete.execute({ status: 'proved', summary: 'Done 2' }, {} as never, { abortSignal: new AbortController().signal } as never) as { isError?: boolean; control?: { terminate?: boolean } }
    assert.notEqual(second.isError, true)
    assert.equal(second.control?.terminate, true)
    assert.equal(completions.length, 1)

    // Separate session with exhausted budget -> complete_intent is NOT blocked
    const exhaustedCompletions: IntentCompletion[] = []
    const exhaustedTools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-r7-budget',
      assignmentId: 'asg-r7-budget',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      hasRemainingBudget: () => false,
      onCompleteIntent: c => { exhaustedCompletions.push(c) },
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-r7-budget' }),
    })
    await exhaustedTools.find(t => t.name === 'submit_exploit_trace')!.execute({
      title: 'Budget-exhausted payout',
      vulnClass: 'economic_conservation',
      exchangeIds: ['m1'],
      terminalExchangeId: 'm1',
    }, {} as never, { abortSignal: new AbortController().signal } as never)
    const noBlock = await exhaustedTools.find(t => t.name === 'complete_intent')!.execute({
      status: 'proved',
      summary: 'Budget exhausted, closing cleanly.',
    }, {} as never, { abortSignal: new AbortController().signal } as never) as { isError?: boolean; control?: { terminate?: boolean } }
    assert.notEqual(noBlock.isError, true)
    assert.equal(noBlock.control?.terminate, true)
    assert.equal(exhaustedCompletions.length, 1)
  })

  test('4 concurrent mutating POST/DELETE exchanges within 250ms OR kovo_verify ch.race attempt satisfy raceBurstAttempted without blocking complete_intent', async () => {
    // 1. 4 concurrent POST exchanges within 200ms (<= 250ms) -> race burst detected -> no gate block
    const fastMutating = new Map<string, RecordedRequestExchange>([
      ['r1', { exchangeId: 'r1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/settle', persona: 'member_a', status: 200, timestampMs: 5000 }],
      ['r2', { exchangeId: 'r2', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/settle', persona: 'member_a', status: 200, timestampMs: 5060 }],
      ['r3', { exchangeId: 'r3', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/settle', persona: 'member_a', status: 200, timestampMs: 5120 }],
      ['r4', { exchangeId: 'r4', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/settle', persona: 'member_a', status: 200, timestampMs: 5180 }],
    ])
    const completions1: IntentCompletion[] = []
    const tools1 = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-r7-burst',
      assignmentId: 'asg-r7-burst',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: fastMutating,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: c => { completions1.push(c) },
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-r7-burst' }),
    })
    const sub1 = JSON.parse(extractText(await tools1.find(t => t.name === 'submit_exploit_trace')!.execute({
      title: 'Concurrent payout burst',
      vulnClass: 'economic_conservation',
      exchangeIds: ['r1'],
      terminalExchangeId: 'r1',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(sub1.keepChaining, undefined)
    const done1 = await tools1.find(t => t.name === 'complete_intent')!.execute({ status: 'proved', summary: 'Already raced.' }, {} as never, { abortSignal: new AbortController().signal } as never) as { isError?: boolean; control?: { terminate?: boolean } }
    assert.notEqual(done1.isError, true)
    assert.equal(done1.control?.terminate, true)
    assert.equal(completions1.length, 1)

    // 2. Direct kovo_verify confirms sequential mutating script -> worker then tries ch.race (even unconfirmed on hardened twin) -> complete_intent succeeds without blocking
    const seqRec = new Map<string, RecordedRequestExchange>([
      ['k1', { exchangeId: 'k1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/transfers', persona: 'member_a', status: 200, timestampMs: 100 }],
    ])
    let kvCall = 0
    const completions2: IntentCompletion[] = []
    const tools2 = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers({
        kovo_verify: async () => {
          kvCall += 1
          if (kvCall === 1) {
            return { confirmed: true, findingId: 'f-kv-seq', compositeReceipt: { chainId: 'c1', terminalVulnClass: 'economic_conservation', hopCount: 3, confirmed: true } }
          }
          return { confirmed: false, reason: 'hardened_no_overcredit' }
        },
      }),
      runId: 'run-r7-kv',
      assignmentId: 'asg-r7-kv',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: seqRec,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: c => { completions2.push(c) },
      runKovoVerify: async () => ({ confirmed: true }),
    })
    const kv = tools2.find(t => t.name === 'kovo_verify')!
    const kv1 = JSON.parse(extractText(await kv.execute({
      title: 'Sequential transfer mutation',
      script: 'const ch = ctx.chain("c1", "economic_conservation"); await ch.step("POST /v1/transfers", { method: "POST" }); return await ch.prove({ claimedImpact: "mutation" })',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(kv1.keepChaining, true)
    assert.equal(kv1.escalationReason, 'mutating_economic_variant_check')

    // Worker runs ch.race attempt in kovo_verify (returns confirmed: false because target was hardened)
    await kv.execute({
      title: 'Concurrent transfer race check',
      script: 'const ch = ctx.chain("c2", "economic_conservation"); await ch.race({ request: { path: "/v1/transfers", method: "POST" }, count: 6 }); return await ch.prove({ claimedImpact: "race" })',
    }, {} as never, { abortSignal: new AbortController().signal } as never)

    const done2 = await tools2.find(t => t.name === 'complete_intent')!.execute({ status: 'proved', summary: 'Confirmed sequential; race ruled out.' }, {} as never, { abortSignal: new AbortController().signal } as never) as { isError?: boolean; control?: { terminate?: boolean } }
    assert.notEqual(done2.isError, true)
    assert.equal(done2.control?.terminate, true)
    assert.equal(completions2.length, 1)
  })
})
