import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN, type WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import { buildAssignmentBriefPacket, classifyPersonaPrivilege } from '../src/server/assignment-brief.ts'
import {
  buildConsolidatedExploiterToolset,
  buildExploiterSystemPrompt,
  buildExploiterUserPrompt,
} from '../src/server/exploiter-tools.ts'
import { synthesizeGreyBoxDataflowGraph } from '../src/server/gb-dataflow-synthesizer.ts'
import type { RecordedRequestExchange } from '../src/server/trace-proof-compiler.ts'

const API_ORIGIN = 'https://api.m2r6-lab.example'
const EDGE_ORIGIN = 'https://edge.m2r6-lab.example'
const AUTH_ORIGIN = 'https://auth.m2r6-lab.example'

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

describe('M2 R6 Fix 1: multi-tenant persona classification, prompt separation, hop-1 allowance & synthesizer preference', () => {
  test('classifyPersonaPrivilege classifies multi-tenant personas as multi_tenant (elevated: false, multiTenant: true) while keeping single-tenant elevated strictly elevated', () => {
    const membershipsMixed = classifyPersonaPrivilege('alice_cross', 'memberships=admin:org_a,viewer:org_b')
    assert.equal(membershipsMixed.tier, 'multi_tenant')
    assert.equal(membershipsMixed.elevated, false)
    assert.equal(membershipsMixed.multiTenant, true)

    const bracketMulti = classifyPersonaPrivilege('bob_shared', 'admin [org_alpha], member [org_beta]')
    assert.equal(bracketMulti.tier, 'multi_tenant')
    assert.equal(bracketMulti.elevated, false)
    assert.equal(bracketMulti.multiTenant, true)

    const dualToken = classifyPersonaPrivilege('dual_user', 'dual tenant')
    assert.equal(dualToken.tier, 'multi_tenant')
    assert.equal(dualToken.elevated, false)
    assert.equal(dualToken.multiTenant, true)

    // Multi-tenant where ALL memberships are admin/owner stays globally elevated
    const allAdminMulti = classifyPersonaPrivilege('global_ops', 'memberships=owner:org_a,admin:org_b')
    assert.equal(allAdminMulti.tier, 'elevated')
    assert.equal(allAdminMulti.elevated, true)
    assert.equal(allAdminMulti.multiTenant, false)

    // Single-tenant elevated roles remain strictly elevated
    for (const [handle, role] of [
      ['owner_a', 'owner'],
      ['admin_a', 'admin'],
      ['root_sys', 'superuser'],
      ['ops_root', 'root'],
      ['ci_bot', 'bot'],
      ['svc_sync', 'service'],
      ['mod_a', 'moderator'],
    ] as const) {
      const cls = classifyPersonaPrivilege(handle, role)
      assert.equal(cls.tier, 'elevated', `${handle}/${role} must stay elevated`)
      assert.equal(cls.elevated, true)
      assert.equal(cls.multiTenant, false)
    }

    // Standard low-priv roles remain low and non-multiTenant
    const low = classifyPersonaPrivilege('member_a', 'member')
    assert.equal(low.tier, 'low')
    assert.equal(low.elevated, false)
    assert.equal(low.multiTenant, false)
  })

  test('assignment-brief preserves long memberships=... role classification before truncating display string', () => {
    const packet = buildAssignmentBriefPacket({
      missionKind: 'multihop_chain',
      origin: API_ORIGIN,
      routes: [{ method: 'GET', path: '/api/v1/cache/items', riskScore: 80 }],
      personas: [
        { handle: 'owner_a', role: 'owner' },
        { handle: 'shared_actor', role: 'memberships=admin:org_alpha_long,viewer:org_beta_long' },
        { handle: 'member_a', role: 'member' },
      ],
    })
    const parsed = JSON.parse(packet.text) as {
      personas: Array<{ handle: string; roleTier: string; multiTenant?: boolean; elevated?: boolean }>
    }
    assert.deepEqual(parsed.personas.map(p => p.handle), ['member_a', 'shared_actor', 'owner_a'])
    assert.equal(parsed.personas[1]!.roleTier, 'multi_tenant')
    assert.equal(parsed.personas[1]!.multiTenant, true)
    assert.equal(parsed.personas[1]!.elevated, undefined)
    assert.equal(parsed.personas[2]!.elevated, true)
  })

  test('buildExploiterUserPrompt lists multiTenantBasePersonas clearly and checkElevatedHop1Precheck allows them on hop 1', async () => {
    const userPrompt = JSON.parse(buildExploiterUserPrompt({
      goal: 'Verify cross-tenant cache isolation',
      step: { id: 's1', title: 'Cache bleed check', hypothesis: 'Cross-tenant cache read', category: 'broken-access-control' },
      origins: [API_ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
      personas: [
        { handle: 'owner_a', roleLabel: 'owner', originAllowlist: [API_ORIGIN] },
        { handle: 'shared_actor', roleLabel: 'memberships=admin:org_a,viewer:org_b', originAllowlist: [API_ORIGIN] },
        { handle: 'member_a', roleLabel: 'member', originAllowlist: [API_ORIGIN] },
      ],
    })) as {
      primaryAttackerBasePersona?: string
      attackerBasePersonas: { personas: Array<{ handle: string }> }
      multiTenantBasePersonas?: { instruction: string; personas: Array<{ handle: string; roleTier: string; multiTenant: boolean }> }
      elevatedReferencePersonas?: { personas: Array<{ handle: string }> }
    }

    assert.equal(userPrompt.primaryAttackerBasePersona, 'member_a')
    assert.deepEqual(userPrompt.attackerBasePersonas.personas.map(p => p.handle), ['member_a'])
    assert.deepEqual(userPrompt.multiTenantBasePersonas?.personas.map(p => p.handle), ['shared_actor'])
    assert.match(userPrompt.multiTenantBasePersonas?.instruction ?? '', /Multi-Tenant Base Personas — use for cross-tenant \/ cache-bleed \/ dual-tenant ABAC chains!/i)
    assert.deepEqual(userPrompt.elevatedReferencePersonas?.personas.map(p => p.handle), ['owner_a'])

    const recorded = new Map<string, RecordedRequestExchange>([
      ['ex-mt', {
        exchangeId: 'ex-mt', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/v1/cache/report',
        persona: 'shared_actor', status: 200, responseJson: { rows: 5 }, timestampMs: 100,
      }],
      ['ex-owner', {
        exchangeId: 'ex-owner', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/v1/cache/report',
        persona: 'owner_a', status: 200, responseJson: { rows: 5 }, timestampMs: 100,
      }],
    ])
    let verifyCalls = 0
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-mt-hop1',
      assignmentId: 'asg-mt-hop1',
      publicOrigins: [API_ORIGIN],
      personasPub: [
        { handle: 'owner_a', role: 'owner' },
        { handle: 'shared_actor', role: 'memberships=admin:org_a,viewer:org_b' },
        { handle: 'member_a', role: 'member' },
      ],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => { verifyCalls += 1; return { confirmed: true, findingId: 'f-mt' } },
    })
    const submit = tools.find(t => t.name === 'submit_exploit_trace')!

    const ownerRes = JSON.parse(extractText(await submit.execute({
      title: 'Owner hop 1 blocked', vulnClass: 'dual_tenant_abac', exchangeIds: ['ex-owner'], terminalExchangeId: 'ex-owner',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(ownerRes.rejectedBy, 'elevated_hop1_persona')
    assert.equal(verifyCalls, 0)

    const mtRes = JSON.parse(extractText(await submit.execute({
      title: 'Multi-tenant hop 1 allowed', vulnClass: 'dual_tenant_abac', exchangeIds: ['ex-mt'], terminalExchangeId: 'ex-mt',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(mtRes.confirmed, true)
    assert.equal(verifyCalls, 1)
  })

  test('gb-dataflow-synthesizer prefers multiTenant persona on cache-bleed/dual-tenant chains and standard low-priv persona otherwise', () => {
    const personas = [
      { handle: 'owner_a', roleLabel: 'owner' },
      { handle: 'member_a', roleLabel: 'member' },
      { handle: 'shared_actor', roleLabel: 'memberships=admin:org_a,viewer:org_b' },
    ]
    const cacheRes = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'c1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/cache/prime', riskScore: 80 },
        { id: 'c2', origin: EDGE_ORIGIN, method: 'GET', pathTemplate: '/v1/cache/:id/export', riskScore: 86 },
      ],
      brokerExchanges: [
        { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/cache/prime', status: 200, personaHandle: 'member_a', bodyPreview: JSON.stringify({ cache_id: 'c_1' }) },
      ],
      personas,
    })
    assert.ok(cacheRes.chains.length >= 1)
    assert.match(cacheRes.chains[0]!.step.hypothesis, /Base persona:\s*shared_actor\b/)
    assert.match(cacheRes.chains[0]!.step.hypothesis, /Relevant personas:\s*shared_actor\b/)

    const regularRes = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [AUTH_ORIGIN, API_ORIGIN],
      endpoints: [
        { id: 'r1', origin: AUTH_ORIGIN, method: 'POST', pathTemplate: '/oauth/invites', riskScore: 80 },
        { id: 'r2', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/invites/redeem', riskScore: 85 },
      ],
      brokerExchanges: [
        { origin: AUTH_ORIGIN, method: 'POST', pathAndQuery: '/oauth/invites', status: 201, personaHandle: 'owner_a', bodyPreview: JSON.stringify({ invite_token: 'inv_1' }) },
      ],
      personas,
    })
    assert.ok(regularRes.chains.length >= 1)
    assert.match(regularRes.chains[0]!.step.hypothesis, /Base persona:\s*member_a\b/)
  })
})

describe('M2 R6 Fix 2: configured-order primary low-priv tie-breaking and single-actor continuity', () => {
  test('assignment-brief, exploiter user/system prompt, and gb-dataflow-synthesizer preserve configIndex ASC within same tier over alphabetical or harvestedIds/observation frequency', () => {
    // 1. assignment-brief: member_z configured at index 0 with 0 harvestedIds beats member_a at index 1 with 3 harvestedIds
    const brief = JSON.parse(buildAssignmentBriefPacket({
      missionKind: 'multihop_chain',
      origin: API_ORIGIN,
      routes: [{ method: 'GET', path: '/api/v1/items', riskScore: 80 }],
      personas: [
        { handle: 'owner_a', role: 'owner', harvestedIds: ['o1', 'o2', 'o3', 'o4'] },
        { handle: 'member_z', role: 'member', harvestedIds: [] },
        { handle: 'member_a', role: 'member', harvestedIds: ['i1', 'i2', 'i3'] },
      ],
    }).text) as { personas: Array<{ handle: string }> }
    assert.deepEqual(brief.personas.map(p => p.handle), ['member_z', 'member_a', 'owner_a'])

    // 2. exploiter prompt: primaryAttackerBasePersona is first configured low-priv persona & instructs single-actor continuity
    const sys = buildExploiterSystemPrompt({ hasMountedRepos: false, allowWebSearch: false })
    assert.match(sys, /primaryAttackerBasePersona/i)
    assert.match(sys, /single-actor continuity/i)

    const user = JSON.parse(buildExploiterUserPrompt({
      goal: 'Verify tenant boundaries',
      step: { id: 's1', title: 'BOLA check', hypothesis: 'Cross-tenant read', category: 'broken-access-control' },
      origins: [API_ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
      personas: [
        { handle: 'owner_a', roleLabel: 'owner', originAllowlist: [API_ORIGIN] },
        { handle: 'member_z', roleLabel: 'member', originAllowlist: [API_ORIGIN] },
        { handle: 'member_a', roleLabel: 'member', originAllowlist: [API_ORIGIN] },
      ],
    })) as {
      primaryAttackerBasePersona: string
      attackerBasePersonas: { primary: string; instruction: string; personas: Array<{ handle: string }> }
    }
    assert.equal(user.primaryAttackerBasePersona, 'member_z')
    assert.equal(user.attackerBasePersonas.primary, 'member_z')
    assert.deepEqual(user.attackerBasePersonas.personas.map(p => p.handle), ['member_z', 'member_a'])
    assert.match(user.attackerBasePersonas.instruction, /single-actor continuity/i)

    // 3. gb-dataflow-synthesizer: member_a configured at index 0 beats member_b even when member_b dominates Phase-0 observations,
    //    and member_z configured before member_a wins over alphabetical member_a!
    const synthRes = synthesizeGreyBoxDataflowGraph({
      approvedOrigins: [API_ORIGIN, EDGE_ORIGIN],
      endpoints: [
        { id: 'e1', origin: API_ORIGIN, method: 'POST', pathTemplate: '/v1/orders', riskScore: 80 },
        { id: 'e2', origin: EDGE_ORIGIN, method: 'POST', pathTemplate: '/v1/orders/:id/approve', riskScore: 85 },
      ],
      brokerExchanges: [
        { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders', status: 201, personaHandle: 'member_b', bodyPreview: JSON.stringify({ order_id: 'ord_1' }) },
        { origin: EDGE_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_1/approve', status: 200, personaHandle: 'member_b', bodyPreview: JSON.stringify({ ok: true }) },
      ],
      personas: [
        { handle: 'member_z', roleLabel: 'member' },
        { handle: 'member_a', roleLabel: 'member' },
        { handle: 'member_b', roleLabel: 'member' },
      ],
    })
    assert.ok(synthRes.chains.length >= 1)
    assert.match(synthRes.chains[0]!.step.hypothesis, /Base persona:\s*member_z\b/)
    assert.match(synthRes.chains[0]!.step.hypothesis, /Relevant personas:\s*member_z, member_a, member_b\b/)
  })
})

describe('M2 R6 Fix 3: mutating/economic deeper variant continuation (bounded, no looping)', () => {
  test('submit_exploit_trace attaches keepChaining + escalationGuidance on shallow sequential economic_conservation confirmation, does not loop on repeat, and skips when race already ran', async () => {
    const seqRecorded = new Map<string, RecordedRequestExchange>([
      ['ex-1', { exchangeId: 'ex-1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/wallets/w1/credit', persona: 'member_a', status: 200, requestJson: { amount: 10 }, responseJson: { creditId: 'cr_1', balance: 110 }, timestampMs: 1000 }],
      ['ex-2', { exchangeId: 'ex-2', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/wallets/w1/credit', persona: 'member_a', status: 200, requestJson: { amount: 10 }, responseJson: { creditId: 'cr_2', balance: 120 }, timestampMs: 3300 }],
      ['ex-3', { exchangeId: 'ex-3', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/wallets/w1/payout', persona: 'member_a', status: 200, requestJson: { creditId: 'cr_2', amount: 120 }, responseJson: { payoutId: 'po_1', status: 'paid' }, timestampMs: 5600 }],
    ])
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-econ-cont',
      assignmentId: 'asg-econ-cont',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: seqRecorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-econ-1' }),
    })
    const submit = tools.find(t => t.name === 'submit_exploit_trace')!

    const first = JSON.parse(extractText(await submit.execute({
      title: 'Sequential wallet payout over-credit',
      vulnClass: 'economic_conservation',
      exchangeIds: ['ex-1', 'ex-2', 'ex-3'],
      terminalExchangeId: 'ex-3',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(first.confirmed, true)
    assert.equal(first.keepChaining, true)
    assert.equal(first.escalationReason, 'mutating_economic_variant_check')
    assert.match(String(first.escalationGuidance), /numeric boundary \/ cap/i)
    assert.match(String(first.escalationGuidance), /N >= 5/i)

    // Second confirmation in the same session MUST NOT loop keepChaining
    const second = JSON.parse(extractText(await submit.execute({
      title: 'Follow-up wallet payout check',
      vulnClass: 'economic_conservation',
      exchangeIds: ['ex-1', 'ex-2', 'ex-3'],
      terminalExchangeId: 'ex-3',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(second.confirmed, true)
    assert.equal(second.keepChaining, undefined, 'must not loop keepChaining once mutating escalation was already prompted')

    // Separate session where http(mode="race") with >=4 parallel calls ALREADY ran -> NO keepChaining
    const racedTools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-econ-raced',
      assignmentId: 'asg-econ-raced',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: seqRecorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-econ-race' }),
    })
    const httpTool = racedTools.find(t => t.name === 'http')!
    await httpTool.execute({
      mode: 'race',
      requests: Array.from({ length: 5 }, () => ({ origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/wallets/w1/payout', persona: 'member_a' })),
    }, {} as never, { abortSignal: new AbortController().signal } as never)
    const submitRaced = racedTools.find(t => t.name === 'submit_exploit_trace')!
    const racedRes = JSON.parse(extractText(await submitRaced.execute({
      title: 'Raced wallet payout check',
      vulnClass: 'economic_conservation',
      exchangeIds: ['ex-1', 'ex-2', 'ex-3'],
      terminalExchangeId: 'ex-3',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(racedRes.confirmed, true)
    assert.equal(racedRes.keepChaining, undefined, 'must not attach keepChaining once a concurrent race burst was already exercised')
  })

  test('direct kovo_verify attaches bounded mutating/economic keepChaining when no race op ran, skips when ch.race ran, and agent-prompts documents the rule', async () => {
    const recorded = new Map<string, RecordedRequestExchange>([
      ['p1', { exchangeId: 'p1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/transfers', persona: 'member_a', status: 200, timestampMs: 100 }],
    ])
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers({
        kovo_verify: async () => ({
          confirmed: true,
          findingId: 'f-kv-1',
          compositeReceipt: { chainId: 'c1', terminalVulnClass: 'economic_conservation', hopCount: 3, confirmed: true },
        }),
      }),
      runId: 'run-kv-cont',
      assignmentId: 'asg-kv-cont',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: true }),
    })
    const kv = tools.find(t => t.name === 'kovo_verify')!

    const noRaceRes = JSON.parse(extractText(await kv.execute({
      title: 'Sequential transfer logic confirmation',
      script: 'const ch = ctx.chain("c1", "economic_conservation"); await ch.step("POST /v1/transfers", { method: "POST" }); return await ch.prove({ claimedImpact: "overcredit" })',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(noRaceRes.confirmed, true)
    assert.equal(noRaceRes.keepChaining, true)
    assert.equal(noRaceRes.escalationReason, 'mutating_economic_variant_check')

    // Bounded on repeat
    const repeatRes = JSON.parse(extractText(await kv.execute({
      title: 'Second confirmation',
      script: 'const ch = ctx.chain("c2", "economic_conservation"); await ch.step("POST /v1/transfers", { method: "POST" }); return await ch.prove({ claimedImpact: "overcredit" })',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(repeatRes.confirmed, true)
    assert.equal(repeatRes.keepChaining, undefined)

    // Fresh session with ch.race(...) in script -> NO keepChaining
    const toolsWithRace = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers({
        kovo_verify: async () => ({
          confirmed: true,
          findingId: 'f-kv-race',
          compositeReceipt: { chainId: 'c3', terminalVulnClass: 'economic_conservation', hopCount: 3, confirmed: true },
        }),
      }),
      runId: 'run-kv-race',
      assignmentId: 'asg-kv-race',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: true }),
    })
    const kvRace = toolsWithRace.find(t => t.name === 'kovo_verify')!
    const withRaceRes = JSON.parse(extractText(await kvRace.execute({
      title: 'Concurrent race transfer confirmation',
      script: 'const ch = ctx.chain("c3", "economic_conservation"); await ch.race({ request: { path: "/v1/transfers", method: "POST" }, count: 6 }); return await ch.prove({ claimedImpact: "race overcredit" })',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(withRaceRes.confirmed, true)
    assert.equal(withRaceRes.keepChaining, undefined)

    // Verify agent-prompts.ts contract carries numeric boundary + concurrent race N >= 5 guidance within line/length caps
    assert.match(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN, /numeric boundary\/cap/i)
    assert.match(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN, /concurrent `race` \(`N >= 5`/i)
    assert.ok(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.split('\n').length <= 6)
    assert.ok(KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN.length <= 2000)
  })
})

describe('M2 R6 Fix 4: shallow 1-2 hop capability-grant continuation', () => {
  test('returns keepChaining + downstream chaining guidance on shallow 1-2 hop redeem/resolve token grant and signed-URL fetch, without firing on deep read-only terminals or looping', async () => {
    const recorded = new Map<string, RecordedRequestExchange>([
      ['inv-1', {
        exchangeId: 'inv-1', origin: AUTH_ORIGIN, method: 'POST', pathAndQuery: '/v1/invites/lookup',
        persona: 'member_a', status: 200, responseJson: { invite_code: 'inv_abc123' }, timestampMs: 100,
      }],
      ['inv-2', {
        exchangeId: 'inv-2', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/invites/redeem',
        persona: 'member_a', status: 200, requestJson: { invite_code: 'inv_abc123' },
        responseJson: { token: 'tok_minted_xyz', role: 'admin', tenant: 'org_b' }, timestampMs: 200,
      }],
      ['url-1', {
        exchangeId: 'url-1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/exports/presign',
        persona: 'member_a', status: 200, responseJson: { signed_url: `${EDGE_ORIGIN}/v1/exports/exp_9/download?sig=deadbeef1234` }, timestampMs: 300,
      }],
      ['url-2', {
        exchangeId: 'url-2', origin: EDGE_ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/exp_9/download?sig=deadbeef1234',
        persona: 'member_a', status: 200, responseBody: 'id,data\n1,secret\n', timestampMs: 400,
      }],
      ['deep-1', {
        exchangeId: 'deep-1', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/projects',
        persona: 'member_a', status: 200, responseJson: { projectId: 'prj_9' }, timestampMs: 500,
      }],
      ['deep-2', {
        exchangeId: 'deep-2', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/projects/prj_9/records',
        persona: 'member_a', status: 200, responseJson: { recordId: 'rec_9' }, timestampMs: 600,
      }],
      ['deep-3', {
        exchangeId: 'deep-3', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/records/rec_9',
        persona: 'member_a', status: 200, responseJson: { owner: 'org_b', secretValue: 'classified' }, timestampMs: 700,
      }],
    ])

    const makeSubmit = () => buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-cap-cont',
      assignmentId: 'asg-cap-cont',
      publicOrigins: [AUTH_ORIGIN, API_ORIGIN, EDGE_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-cap-1' }),
    }).find(t => t.name === 'submit_exploit_trace')!

    // 1. Shallow 2-hop POST .../redeem returning { token, role, tenant } -> keepChaining + downstream consumer guidance
    const submitRedeem = makeSubmit()
    const redeemRes = JSON.parse(extractText(await submitRedeem.execute({
      title: 'Cross-tenant invite redeem grants token',
      vulnClass: 'privilege_escalation',
      exchangeIds: ['inv-1', 'inv-2'],
      terminalExchangeId: 'inv-2',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(redeemRes.confirmed, true)
    assert.equal(redeemRes.keepChaining, true)
    assert.equal(redeemRes.escalationReason, 'shallow_capability_grant')
    assert.match(String(redeemRes.escalationGuidance), /downstream consumer routes/i)
    assert.match(String(redeemRes.escalationGuidance), /approve, rebind, payout, vault, transfer/i)

    // Repeat shallow capability-grant in the same session does NOT loop shallow_capability_grant
    const repeatCapRes = JSON.parse(extractText(await submitRedeem.execute({
      title: 'Signed URL fetch in same session',
      vulnClass: 'cross_tenant_export',
      exchangeIds: ['url-1', 'url-2'],
      terminalExchangeId: 'url-2',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(repeatCapRes.confirmed, true)
    assert.equal(repeatCapRes.keepChaining, undefined)

    // 2. Fresh session: shallow 2-hop signed-URL fetch -> keepChaining + downstream consumer guidance
    const submitSignedUrl = makeSubmit()
    const urlRes = JSON.parse(extractText(await submitSignedUrl.execute({
      title: 'Cross-tenant signed URL download',
      vulnClass: 'cross_tenant_export',
      exchangeIds: ['url-1', 'url-2'],
      terminalExchangeId: 'url-2',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(urlRes.confirmed, true)
    assert.equal(urlRes.keepChaining, true)
    assert.equal(urlRes.escalationReason, 'shallow_capability_grant')

    // 3. Fresh session: deep 3-hop read-only GET terminal -> NO keepChaining
    const submitDeep = makeSubmit()
    const deepRes = JSON.parse(extractText(await submitDeep.execute({
      title: 'Deep 3-hop cross-tenant read',
      vulnClass: 'bola',
      exchangeIds: ['deep-1', 'deep-2', 'deep-3'],
      terminalExchangeId: 'deep-3',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(deepRes.confirmed, true)
    assert.equal(deepRes.keepChaining, undefined)
  })
})
