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

describe('Phase 0 cleanup: complete_intent completes cleanly after mutating confirmation without forced race escalation gate', () => {
  test('complete_intent succeeds on first call after confirmed mutating finding (submit_exploit_trace or kovo_verify) without blocking for N>=5 race', async () => {
    const completions: IntentCompletion[] = []
    const recorded = new Map<string, RecordedRequestExchange>([
      ['hop-1', { exchangeId: 'hop-1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', persona: 'member_a', status: 201, requestJson: { amount: 100 }, responseJson: { orderId: 'ord_9' }, timestampMs: 3000 }],
      ['hop-2', { exchangeId: 'hop-2', origin: API_ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_9/rebind', persona: 'member_a', status: 200, requestJson: { targetId: 'acct_b' }, responseJson: { ok: true }, timestampMs: 4000 }],
      ['hop-3', { exchangeId: 'hop-3', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/orders/ord_9', persona: 'member_a', status: 200, responseJson: { orderId: 'ord_9', balance: 500 }, timestampMs: 5000 }],
    ])

    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-r7-no-gate',
      assignmentId: 'asg-r7-no-gate',
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
    const complete = tools.find(t => t.name === 'complete_intent')!

    const subRes = JSON.parse(extractText(await submit.execute({
      title: 'Order rebind mutating chain verified via readback',
      vulnClass: 'broken_access_control',
      exchangeIds: ['hop-1', 'hop-2', 'hop-3'],
      terminalExchangeId: 'hop-3',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(subRes.confirmed, true)
    assert.equal(subRes.keepChaining, undefined)

    const doneRaw = await complete.execute({
      status: 'proved',
      summary: 'Confirmed order rebind.',
    }, {} as never, { abortSignal: new AbortController().signal } as never) as { isError?: boolean; control?: { terminate?: boolean } }
    assert.notEqual(doneRaw.isError, true)
    assert.equal(doneRaw.control?.terminate, true)
    assert.equal(completions.length, 1)
  })
})
