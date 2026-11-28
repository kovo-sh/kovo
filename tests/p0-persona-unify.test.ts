import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import type { WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import {
  buildAssignmentBriefPacket,
  buildMultiHopProofContract,
  classifyPersonaPrivilege as classifyFromBrief,
  isMultiHopBriefInput,
} from '../src/server/assignment-brief.ts'
import {
  buildConsolidatedExploiterToolset,
  resolveExploiterActingPersona,
} from '../src/server/exploiter-tools.ts'
import { classifyPersonaMetadata, classifyPersonaPrivilege } from '../src/server/persona-privilege.ts'
import {
  compileTraceToKovoVerifyScript,
  type RecordedRequestExchange,
} from '../src/server/trace-proof-compiler.ts'

const API_ORIGIN = 'https://api.saas.example'

function makeDummyHandlers(overrides?: Partial<WorkerToolHandlers>): WorkerToolHandlers {
  return {
    request_http: async () => ({ exchangeId: 'ex-1', status: 200, bodySha256: 'abc', bodyPreview: '{}' }),
    request_http_batch: async args => ({ count: args.requests.length, results: args.requests.map((_, i) => ({ exchangeId: `ex-b-${i}`, status: 200 })) }),
    request_http_race: async args => ({ count: args.requests.length, results: args.requests.map((_, i) => ({ exchangeId: `ex-r-${i}`, status: 200 })) }),
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

describe('Phase 0 persona-privilege unification & overfitting cleanup', () => {
  test('classifyPersonaMetadata prefers explicit structured config fields over handle substrings and never parses _a/_b or dual regexes', () => {
    assert.equal(classifyFromBrief, classifyPersonaPrivilege)

    // Real-world SaaS handles that old regexes misclassified
    const botFreeWithRole = classifyPersonaMetadata({ handle: 'support_bot_free', role: 'member', tenant: 'acme' })
    assert.equal(botFreeWithRole.privilege, 'low')
    assert.equal(botFreeWithRole.elevated, false)
    assert.deepEqual(botFreeWithRole.tenants, ['acme'])

    const botFreeNoRole = classifyPersonaMetadata({ handle: 'support_bot_free' })
    assert.equal(botFreeNoRole.privilege, 'low')
    assert.equal(botFreeNoRole.elevated, false)
    assert.deepEqual(botFreeNoRole.tenants, [])

    const realEmail = classifyPersonaMetadata({ handle: 'alice@dyad.sh', privilege: 'member', tenantRef: 'org-dyad' })
    assert.equal(realEmail.privilege, 'low')
    assert.equal(realEmail.elevated, false)
    assert.deepEqual(realEmail.tenants, ['org_dyad'])

    // Explicit privilege always beats handle keywords
    const explicitLowOverride = classifyPersonaMetadata({ handle: 'owner_test_sandbox', privilege: 'viewer', tenant: 'sandbox' })
    assert.equal(explicitLowOverride.privilege, 'low')
    assert.equal(explicitLowOverride.elevated, false)

    const explicitElevated = classifyPersonaMetadata({ handle: 'qa_user_1', privilege: 'admin', tenant: 'corp' })
    assert.equal(explicitElevated.privilege, 'elevated')
    assert.equal(explicitElevated.elevated, true)
    assert.deepEqual(explicitElevated.tenants, ['corp'])

    const explicitRevoked = classifyPersonaMetadata({ handle: 'alice', privilege: 'revoked', tenant: 'corp' })
    assert.equal(explicitRevoked.privilege, 'revoked')
    assert.equal(explicitRevoked.revokedStale, true)
    assert.equal(explicitRevoked.elevated, false)

    // No single-letter _a/_b suffix tenant parsing and no bare `dual` handle regex
    const suffixed = classifyPersonaMetadata({ handle: 'member_a', role: 'member' })
    assert.deepEqual(suffixed.tenants, [])

    const bareDual = classifyPersonaMetadata({ handle: 'dual_monitor_qa', role: 'member' })
    assert.equal(bareDual.privilege, 'low')
    assert.equal(bareDual.multiTenant, false)
    assert.deepEqual(bareDual.tenants, [])

    // Structured memberships produce multiTenant + normalized tenants list
    const multiMixed = classifyPersonaMetadata({
      handle: 'cross_user',
      memberships: [
        { tenant: 'tenant-alpha', role: 'admin' },
        { tenant: 'tenant-beta', role: 'viewer' },
      ],
    })
    assert.equal(multiMixed.privilege, 'low')
    assert.equal(multiMixed.multiTenant, true)
    assert.equal(multiMixed.elevated, false)
    assert.deepEqual(multiMixed.tenants, ['tenant_alpha', 'tenant_beta'])

    const multiAllAdmin = classifyPersonaMetadata({
      handle: 'global_ops',
      memberships: { 'tenant-alpha': 'owner', 'tenant-beta': 'admin' },
    })
    assert.equal(multiAllAdmin.privilege, 'elevated')
    assert.equal(multiAllAdmin.elevated, true)
    assert.equal(multiAllAdmin.multiTenant, false)
    assert.deepEqual(multiAllAdmin.tenants, ['tenant_alpha', 'tenant_beta'])
  })

  test('assignment-brief avoids 2-origin DSL flooding, fast_lab, hardenedTwinRule, and signal-regex helperPatterns', () => {
    // 2-subdomain SaaS running class_scan must NOT auto-trigger multiHopProofContract DSL flooding
    assert.equal(
      isMultiHopBriefInput({
        missionKind: 'class_scan',
        publicOrigins: ['https://app.saas.example', 'https://api.saas.example'],
      }),
      false,
    )
    const twoSubdomainBrief = JSON.parse(
      buildAssignmentBriefPacket({
        missionKind: 'class_scan',
        origin: 'https://app.saas.example',
        publicOrigins: ['https://app.saas.example', 'https://api.saas.example'],
        routes: [
          { origin: 'https://app.saas.example', method: 'GET', path: '/dashboard' },
          { origin: 'https://api.saas.example', method: 'GET', path: '/v1/items' },
        ],
      }).text,
    ) as { multiHopProofContract?: unknown }
    assert.equal(twoSubdomainBrief.multiHopProofContract, undefined)

    // Explicit multihop_chain contract stays clean without fast_lab, hardenedTwinRule, or helperPatterns
    const fullContract = buildMultiHopProofContract(false, {
      missionKind: 'multihop_chain',
      origin: API_ORIGIN,
      routes: [{ method: 'POST', path: '/api/webhooks/hmac/jobs/export' }],
    })
    const compactContract = buildMultiHopProofContract(true, {
      missionKind: 'multihop_chain',
      origin: API_ORIGIN,
      routes: [{ method: 'POST', path: '/api/webhooks/hmac/jobs/export' }],
    })
    assert.equal('hardenedTwinRule' in fullContract, false)
    assert.equal('helperPatterns' in fullContract, false)
    assert.equal('hardenedTwinRule' in compactContract, false)
    assert.equal('helperPatterns' in compactContract, false)
    assert.equal(JSON.stringify(fullContract).includes('fast_lab'), false)
    assert.equal(JSON.stringify(compactContract).includes('fast_lab'), false)
  })

  test('trace-proof-compiler uses ctx.await_async instead of 400ms setTimeout and avoids benchmark chain aliases / DUAL_PERSONA_RE', () => {
    const jobId = 'job_async_99112233'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'a1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/v1/jobs',
        persona: 'alice',
        status: 202,
        responseJson: { jobId },
        timestampMs: 100,
      },
      {
        exchangeId: 'a_poll',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}/status`,
        persona: 'alice',
        status: 200,
        responseJson: { status: 'ready' },
        timestampMs: 200,
      },
      {
        exchangeId: 'a2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}/result`,
        persona: 'alice',
        status: 200,
        responseJson: { rows: 3 },
        timestampMs: 300,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Async job cross-tenant read',
        vulnClass: 'broken_access_control',
        exchangeIds: ['a1', 'a_poll', 'a2'],
        terminalExchangeId: 'a2',
        attackerPersona: 'alice',
      },
      exchanges,
      personaMetadata: [{ handle: 'alice', privilege: 'member', tenant: 'acme' }],
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.script, /setTimeout/)
    assert.match(compiled.script, /ctx\.await_async\(/)
    assert.match(compiled.script, /triggerExchangeId:\s*step_1\.exchangeId/)
    assert.match(compiled.script, /jsonPath:\s*"\$\.status"/)
    assert.match(compiled.script, /equals:\s*"ready"/)
    assert.doesNotMatch(compiled.script, /fast_lab/)

    // When a 202 step has no recorded poll exchange, do not emit any hardcoded setTimeout
    const compiledNoPoll = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Async job without poll exchange',
        vulnClass: 'broken_access_control',
        exchangeIds: ['a1', 'a2'],
        terminalExchangeId: 'a2',
        attackerPersona: 'alice',
      },
      exchanges: [exchanges[0]!, exchanges[2]!],
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiledNoPoll.ok, true)
    assert.doesNotMatch(compiledNoPoll.script!, /setTimeout/)
    assert.doesNotMatch(compiledNoPoll.script!, /ctx\.await_async\(/)

    // Unrecognized benchmark alias settlement_forgery falls back generically instead of forged_settlement
    const aliasCheck = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Settlement check',
        vulnClass: 'settlement_forgery',
        exchangeIds: ['a2'],
        terminalExchangeId: 'a2',
      },
      exchanges: [exchanges[2]!],
      runOrigin: 'https://app.example.test',
    })
    assert.equal(aliasCheck.ok, true)
    assert.equal(aliasCheck.terminalVulnClass, 'broken_access_control')

    // Handle containing "dual" without structured multi-tenant metadata is treated as ordinary low-priv persona
    const dualHandleTrace: RecordedRequestExchange[] = [
      { exchangeId: 'dh1', origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/items/1', persona: 'dual_qa_user', status: 200, responseJson: { ok: true }, timestampMs: 10 },
    ]
    const dualCompiled = compileTraceToKovoVerifyScript({
      submission: { title: 'Standard read', vulnClass: 'bola', exchangeIds: ['dh1'], terminalExchangeId: 'dh1' },
      exchanges: dualHandleTrace,
      allowedPersonas: ['dual_qa_user', 'viewer_other'],
      runOrigin: 'https://app.example.test',
    })
    assert.equal(dualCompiled.ok, true)
    assert.match(dualCompiled.script!, /as:\s*"dual_qa_user"/)
  })

  test('exploiter-tools allows switching across non-elevated personas, blocks elevated personas, and never forces race/path-regex complete_intent gates', async () => {
    const personas = [
      { handle: 'alice', roleLabel: 'member', tenant: 'org_one', originAllowlist: [API_ORIGIN] },
      { handle: 'bob', roleLabel: 'member', tenant: 'org_two', originAllowlist: [API_ORIGIN] },
      { handle: 'support_bot_free', roleLabel: 'member', tenant: 'org_three', originAllowlist: [API_ORIGIN] },
      { handle: 'admin_corp', roleLabel: 'owner', tenant: 'org_one', originAllowlist: [API_ORIGIN] },
    ]
    // No implicit attackerBase[0] -> attackerBase[1] swap when no tenant is named in invite flow
    assert.equal(
      resolveExploiterActingPersona({
        personas,
        step: { title: 'Invite flow', hypothesis: 'Probe /invites/resolve endpoint', category: 'auth' },
      }),
      'alice',
    )

    const recorded = new Map<string, RecordedRequestExchange>([
      ['m1', { exchangeId: 'm1', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/1/refund', persona: 'bob', status: 200, responseJson: { ok: true }, timestampMs: 100 }],
    ])
    let completed = 0
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-p0-behav',
      assignmentId: 'asg-p0-behav',
      publicOrigins: [API_ORIGIN],
      personasPub: personas.map(p => ({ handle: p.handle, role: p.roleLabel, tenant: p.tenant })),
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => { completed += 1 },
      runKovoVerify: async () => ({ confirmed: true, findingId: 'f-p0-1' }),
    })

    const httpTool = tools.find(t => t.name === 'http')!
    const bobRes = await httpTool.execute(
      { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/items', persona: 'bob' },
      {} as never,
      { abortSignal: new AbortController().signal } as never,
    ) as { isError?: boolean }
    assert.equal(bobRes.isError, undefined, 'any non-elevated persona must be allowed on purpose="attacker"')

    const botFreeRes = await httpTool.execute(
      { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/items', persona: 'support_bot_free' },
      {} as never,
      { abortSignal: new AbortController().signal } as never,
    ) as { isError?: boolean }
    assert.equal(botFreeRes.isError, undefined, 'real handle support_bot_free with role=member must not be falsely banned')

    const adminRes = await httpTool.execute(
      { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/items', persona: 'admin_corp' },
      {} as never,
      { abortSignal: new AbortController().signal } as never,
    ) as { isError?: boolean; output: Array<{ text?: string }> }
    assert.equal(adminRes.isError, true, 'elevated persona must be blocked on purpose="attacker"')
    assert.match(adminRes.output.map(o => o.text ?? '').join('\n'), /elevated_persona_violation/)

    // Confirmed mutating finding completes immediately on first complete_intent call without forced N>=5 race gate
    const submitTool = tools.find(t => t.name === 'submit_exploit_trace')!
    await submitTool.execute(
      { title: 'Refund mutation', vulnClass: 'economic_conservation', exchangeIds: ['m1'], terminalExchangeId: 'm1' },
      {} as never,
      { abortSignal: new AbortController().signal } as never,
    )
    const completeTool = tools.find(t => t.name === 'complete_intent')!
    const doneRes = await completeTool.execute(
      { status: 'proved', summary: 'Confirmed refund mutation' },
      {} as never,
      { abortSignal: new AbortController().signal } as never,
    ) as { isError?: boolean }
    assert.equal(doneRes.isError, undefined)
    assert.equal(completed, 1)
  })
})
