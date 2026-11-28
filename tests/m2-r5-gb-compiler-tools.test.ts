import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { Script } from 'node:vm'
import type { WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import { buildAssignmentBriefPacket, classifyPersonaPrivilege } from '../src/server/assignment-brief.ts'
import {
  buildConsolidatedExploiterToolset,
  buildExploiterSystemPrompt,
  buildExploiterUserPrompt,
} from '../src/server/exploiter-tools.ts'
import {
  compileTraceToKovoVerifyScript,
  type RecordedRequestExchange,
} from '../src/server/trace-proof-compiler.ts'
import { canonicalNonAuthQuery } from '../src/server/v8-oracle-hydrate.ts'

const API_ORIGIN = 'https://api.m2r5-lab.example'
const EDGE_ORIGIN = 'https://files.m2r5-lab.example'

function extractText(res: { output?: Array<{ type: string; text?: string }> }): string {
  return (res.output ?? []).map(p => p.text ?? '').join('\n')
}

function makeDummyHandlers(): WorkerToolHandlers {
  return {
    request_http: async () => ({ exchangeId: 'ex-1', status: 200, bodySha256: 'abc', bodyPreview: '{}' }),
    request_http_batch: async () => ({ count: 1, results: [] }),
    request_http_race: async () => ({ count: 2, results: [] }),
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
  }
}

function loadCompiledScript(script: string): (ctx: Record<string, unknown>) => Promise<unknown> {
  const rewritten = script.replace(/^export default\s+/, 'return ')
  new Script(`(function(){ ${rewritten} })`)
  return (new Function(rewritten) as () => (ctx: Record<string, unknown>) => Promise<unknown>)()
}

describe('M2 R5: trace-proof-compiler fixes', () => {
  test('bindLeafValue always returns sealed handle expression and never sends %5Bredacted%3Acap under Layer-1 redaction', async () => {
    const jobId = 'job_exp_445566'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 't1',
        origin: API_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/exports',
        persona: 'member_a',
        status: 202,
        responseJson: { jobId },
        timestampMs: 100,
      },
      {
        exchangeId: 't2',
        origin: API_ORIGIN,
        method: 'POST',
        pathAndQuery: `/api/v1/exports/${jobId}/download?ref=${jobId}`,
        persona: 'member_a',
        requestJson: { targetJobId: jobId },
        status: 200,
        responseJson: { rows: 42 },
        timestampMs: 200,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Export job sealed handle binding',
        vulnClass: 'dual_tenant_abac',
        exchangeIds: ['t1', 't2'],
        terminalExchangeId: 't2',
        attackerPersona: 'member_a',
      },
      exchanges,
      runOrigin: API_ORIGIN,
    })
    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.script, /encodeURIComponent\(String\(v_/, 'must not URL-encode a sealed field variable')
    assert.match(compiled.script, /ch\.seal\(step_1,/)

    // Execute with a mock context that actively simulates Layer-1 redaction upon ch.seal()
    const sentPaths: string[] = []
    const sentBodies: unknown[] = []
    const responses = [
      { status: 403, json: { error: 'denied' } }, // control
      { status: 202, json: { jobId: 'job_live_999111' } }, // step_1
      { status: 200, json: { rows: 42 } }, // step_2
    ]
    let idx = 0
    const mockCtx = {
      chain() {
        const self = {
          control(target: string) {
            sentPaths.push(String(target))
            const r = responses[idx++]!
            return Promise.resolve({ exchangeId: `ex_${idx}`, status: r.status, json: r.json })
          },
          step(target: string, opts: { body?: unknown } = {}) {
            sentPaths.push(String(target))
            sentBodies.push(opts.body)
            const r = responses[idx++]!
            return Promise.resolve({ exchangeId: `ex_${idx}`, status: r.status, json: r.json })
          },
          seal(ex: { json?: Record<string, unknown> }, sel: { slot: string; jsonPath?: string }) {
            const handle = `cap:hop_step_1:${sel.slot}`
            // Simulate Layer-1 redaction mutating the sealed response field!
            if (ex.json && sel.jsonPath && sel.jsonPath in ex.json) {
              ex.json[sel.jsonPath] = `[redacted:${handle}]`
            }
            return Promise.resolve(handle)
          },
          edge() { return self },
          prove() { return Promise.resolve({ confirmed: true, reason: 'ok' }) },
        }
        return self
      },
      result(r: unknown) { return r },
    }
    await loadCompiledScript(compiled.script)(mockCtx)

    assert.equal(sentPaths[2], '/api/v1/exports/cap:hop_step_1:cap_1/download?ref=cap:hop_step_1:cap_1')
    assert.deepEqual(sentBodies[1], { targetJobId: 'cap:hop_step_1:cap_1' })
    for (const p of sentPaths) {
      assert.doesNotMatch(p, /%5Bredacted%3Acap|\[redacted:cap/i, 'wire path must never carry Layer-1 redacted placeholder')
    }
  })

  test('sanitizeControlPath replaces signature query keys with 0000000000000000 while stripping non-signature auth keys and preserving non-auth parity', async () => {
    const cases: Array<{ key: string; realSig: string; includeJwt?: boolean; checkHydrateParity: boolean }> = [
      { key: 'sig', realSig: 'realsig_abcdef123456', checkHydrateParity: true },
      { key: 'signature', realSig: 'realsignature_99887766', checkHydrateParity: true },
      { key: 'hmac', realSig: 'realhmac_1122334455', checkHydrateParity: true },
      { key: 'X-Amz-Signature', realSig: 'realamzsig_fedcba9876', includeJwt: true, checkHydrateParity: false },
    ]
    for (const { key, realSig, includeJwt, checkHydrateParity } of cases) {
      const terminalPq = `/v1/files/download?tenant=org_a&job=j_1&${key}=${realSig}&token=tok_strip_me${includeJwt ? '&jwt=jwt_strip_me' : ''}&access_token=at_strip_me&expires=999999`
      const exchanges: RecordedRequestExchange[] = [
        {
          exchangeId: 's1',
          origin: API_ORIGIN,
          method: 'POST',
          pathAndQuery: '/v1/exports/sign',
          persona: 'member_b',
          status: 200,
          responseJson: { signedUrl: `${EDGE_ORIGIN}${terminalPq}` },
          timestampMs: 100,
        },
        {
          exchangeId: 's2',
          origin: EDGE_ORIGIN,
          method: 'GET',
          pathAndQuery: terminalPq,
          persona: 'member_b',
          status: 200,
          responseBody: 'secret,1\n',
          timestampMs: 200,
        },
      ]
      const compiled = compileTraceToKovoVerifyScript({
        submission: {
          title: `Signed download control invalidates ${key}`,
          vulnClass: 'dual_tenant_abac',
          exchangeIds: ['s1', 's2'],
          terminalExchangeId: 's2',
          attackerPersona: 'member_b',
        },
        exchanges,
        runOrigin: API_ORIGIN,
      })
      assert.equal(compiled.ok, true)
      assert.ok(compiled.script)
      assert.doesNotMatch(compiled.script, new RegExp(realSig), `real ${key} must never leak into compiled script`)
      assert.doesNotMatch(compiled.script, /tok_strip_me|jwt_strip_me|at_strip_me|expires=999999/)
      const expectedCtrlPath = `/v1/files/download?tenant=org_a&job=j_1&${key}=0000000000000000`
      assert.ok(compiled.script.includes(expectedCtrlPath), `expected control path "${expectedCtrlPath}" in script`)
      if (checkHydrateParity) {
        assert.equal(canonicalNonAuthQuery(expectedCtrlPath), canonicalNonAuthQuery(terminalPq))
      }
    }
  })
})

describe('M2 R5: assignment-brief & exploiter-tools persona ordering, precheck, and balanced repo listing', () => {
  test('assignment-brief sorts low-priv personas in configured order before multi-tenant and elevated owner/admin/bot/service personas even when elevated personas have more harvestedIds', () => {
    const packet = buildAssignmentBriefPacket({
      missionKind: 'multihop_chain',
      origin: API_ORIGIN,
      routes: [{ method: 'GET', path: '/api/v1/records', riskScore: 80 }],
      personas: [
        { handle: 'owner_a', role: 'owner', harvestedIds: ['id1', 'id2', 'id3', 'id4', 'id5'] },
        { handle: 'admin_a', role: 'admin', harvestedIds: ['id1', 'id2', 'id3', 'id4'] },
        { handle: 'dual_member', role: 'member [org_a], member [org_b]', harvestedIds: ['id1', 'id2', 'id3'] },
        { handle: 'sync_bot', role: 'service', harvestedIds: ['id1', 'id2'] },
        { handle: 'member_b', role: 'member', harvestedIds: [] },
        { handle: 'viewer_c', role: 'viewer', harvestedIds: ['id9'] },
      ],
    })
    const parsed = JSON.parse(packet.text) as {
      personas: Array<{ handle: string; roleTier: string; elevated?: boolean; multiTenant?: boolean; harvestedIds?: string[] }>
    }
    const handles = parsed.personas.map(p => p.handle)
    assert.deepEqual(handles.slice(0, 2), ['member_b', 'viewer_c'], 'low-priv personas must come first in configured order before multi-tenant and elevated personas')
    assert.equal(parsed.personas[0]!.roleTier, 'low')
    assert.equal(parsed.personas[0]!.elevated, undefined)
    assert.equal(parsed.personas[2]!.handle, 'dual_member')
    assert.equal(parsed.personas[2]!.roleTier, 'multi_tenant')
    assert.equal(parsed.personas[2]!.multiTenant, true)
    assert.equal(parsed.personas[2]!.elevated, undefined)
    for (const elev of parsed.personas.slice(3)) {
      assert.equal(elev.roleTier, 'elevated', `${elev.handle} must be tagged roleTier=elevated`)
      assert.equal(elev.elevated, true, `${elev.handle} must be tagged elevated=true`)
    }
    assert.equal(classifyPersonaPrivilege('moderator_x', 'moderator').elevated, true)
    assert.equal(classifyPersonaPrivilege('root_ops', 'superuser').elevated, true)
  })

  test('buildExploiterUserPrompt and buildExploiterSystemPrompt separate low-priv base, multi-tenant base, and elevated reference personas and reinforce same-actor control baseline', () => {
    const sys = buildExploiterSystemPrompt({ hasMountedRepos: false, allowWebSearch: false })
    assert.match(sys, /attackerBasePersonas/)
    assert.match(sys, /multiTenantBasePersonas/)
    assert.match(sys, /elevatedReferencePersonas/)
    assert.match(sys, /same base attacker persona/i)
    assert.match(sys, /bola.*bfla.*broken_access_control.*dual_tenant_abac/i)

    const user = JSON.parse(buildExploiterUserPrompt({
      goal: 'Verify cross-tenant boundaries',
      step: { id: 's1', title: 'Authz check', hypothesis: 'Check boundaries', category: 'broken-access-control' },
      origins: [API_ORIGIN],
      capabilityTier: 2,
      maxTurns: 15,
      personas: [
        { handle: 'owner_a', roleLabel: 'owner', originAllowlist: [API_ORIGIN] },
        { handle: 'dual_member', roleLabel: 'memberships=admin:org_a,viewer:org_b', originAllowlist: [API_ORIGIN] },
        { handle: 'svc_worker', roleLabel: 'service', originAllowlist: [API_ORIGIN] },
        { handle: 'member_b', roleLabel: 'member', originAllowlist: [API_ORIGIN] },
      ],
    })) as {
      primaryAttackerBasePersona?: string
      attackerBasePersonas: { instruction: string; primary?: string; personas: Array<{ handle: string }> }
      multiTenantBasePersonas?: { instruction: string; personas: Array<{ handle: string }> }
      elevatedReferencePersonas: { instruction: string; personas: Array<{ handle: string }> }
      personas: Array<{ handle: string }>
    }

    assert.equal(user.primaryAttackerBasePersona, 'member_b')
    assert.equal(user.attackerBasePersonas.primary, 'member_b')
    assert.deepEqual(user.attackerBasePersonas.personas.map(p => p.handle), ['member_b'])
    assert.match(user.attackerBasePersonas.instruction, /START ALL CHAINS HERE/i)
    assert.match(user.attackerBasePersonas.instruction, /exact same base attacker persona/i)
    assert.deepEqual(user.multiTenantBasePersonas?.personas.map(p => p.handle), ['dual_member'])
    assert.match(user.multiTenantBasePersonas?.instruction ?? '', /Multi-Tenant Base Personas/i)
    assert.deepEqual(
      user.elevatedReferencePersonas.personas.map(p => p.handle).sort(),
      ['owner_a', 'svc_worker'],
    )
    assert.match(user.elevatedReferencePersonas.instruction, /NEVER use as hop-1 attacker base/i)
    assert.equal(user.personas[0]!.handle, 'member_b', 'personas array must also place lowest-priv persona first')
  })

  test('runSubmitExploitTrace precheck rejects elevated hop-1 base personas when low-priv personas exist, allows multi-tenant personas, and allows elevated when only elevated exist', async () => {
    const makeEx = (id: string, persona: string): RecordedRequestExchange => ({
      exchangeId: id,
      origin: API_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/v1/admin/data',
      persona,
      status: 200,
      responseJson: { rows: 10 },
      timestampMs: 100,
    })

    const recorded = new Map<string, RecordedRequestExchange>([
      ['ex-owner', makeEx('ex-owner', 'owner_a')],
      ['ex-dual', makeEx('ex-dual', 'dual_member')],
      ['ex-role-admin', makeEx('ex-role-admin', 'alice_ops')],
      ['ex-low', makeEx('ex-low', 'member_b')],
    ])

    let verifyCalls = 0
    const mixedTools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-priv',
      assignmentId: 'asg-priv',
      publicOrigins: [API_ORIGIN],
      personasPub: [
        { handle: 'owner_a', role: 'owner' },
        { handle: 'dual_member', role: 'member [org_a], member [org_b]' },
        { handle: 'alice_ops', role: 'admin' },
        { handle: 'member_b', role: 'member' },
      ],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => { verifyCalls += 1; return { confirmed: true, findingId: 'f-1' } },
    })
    const submitMixed = mixedTools.find(t => t.name === 'submit_exploit_trace')!

    for (const badId of ['ex-owner', 'ex-role-admin']) {
      const res = JSON.parse(extractText(await submitMixed.execute({
        title: 'Elevated shortcut attempt',
        vulnClass: 'bfla',
        exchangeIds: [badId],
        terminalExchangeId: badId,
      }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
      assert.equal(res.ok, false)
      assert.equal(res.stage, 'precheck')
      assert.equal(res.rejectedBy, 'elevated_hop1_persona')
      assert.match(String(res.message), /member_b/)
    }
    assert.equal(verifyCalls, 0, 'elevated hop-1 precheck must fail fast before verifier runs')

    // Multi-tenant hop 1 passes precheck and reaches verifier
    const dualRes = JSON.parse(extractText(await submitMixed.execute({
      title: 'Multi-tenant base check',
      vulnClass: 'dual_tenant_abac',
      exchangeIds: ['ex-dual'],
      terminalExchangeId: 'ex-dual',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(dualRes.confirmed, true)
    assert.equal(verifyCalls, 1)

    // Low-priv hop 1 passes precheck and reaches verifier
    const okRes = JSON.parse(extractText(await submitMixed.execute({
      title: 'Low-priv base check',
      vulnClass: 'bfla',
      exchangeIds: ['ex-low'],
      terminalExchangeId: 'ex-low',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(okRes.confirmed, true)
    assert.equal(verifyCalls, 2)

    // When ONLY elevated personas exist in personasPub, precheck allows them through
    let elevatedOnlyVerifyCalls = 0
    const elevatedOnlyTools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-elev-only',
      assignmentId: 'asg-elev-only',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'owner_a', role: 'owner' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => { elevatedOnlyVerifyCalls += 1; return { confirmed: true, findingId: 'f-2' } },
    })
    const submitElevOnly = elevatedOnlyTools.find(t => t.name === 'submit_exploit_trace')!
    const elevOnlyRes = JSON.parse(extractText(await submitElevOnly.execute({
      title: 'Elevated-only run',
      vulnClass: 'bfla',
      exchangeIds: ['ex-owner'],
      terminalExchangeId: 'ex-owner',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as Record<string, unknown>
    assert.equal(elevOnlyRes.confirmed, true)
    assert.equal(elevatedOnlyVerifyCalls, 1)
  })

  test('listRepoFilesHost uses balanced per-service file ordering so early services and docs do not starve later services', async t => {
    const reposDir = mkdtempSync(join(tmpdir(), 'kovo-m2r5-balanced-'))
    t.after(() => rmSync(reposDir, { recursive: true, force: true }))
    // Single mounted monorepo with 3 services + noisy docs/tests
    mkdirSync(join(reposDir, 'monorepo', 'docs'), { recursive: true })
    mkdirSync(join(reposDir, 'monorepo', 'services', 'alpha', 'src'), { recursive: true })
    mkdirSync(join(reposDir, 'monorepo', 'services', 'beta', 'src'), { recursive: true })
    mkdirSync(join(reposDir, 'monorepo', 'services', 'gamma', 'src'), { recursive: true })
    for (let i = 0; i < 20; i += 1) {
      writeFileSync(join(reposDir, 'monorepo', 'docs', `guide-${String(i).padStart(2, '0')}.md`), '# doc\n', 'utf8')
      writeFileSync(join(reposDir, 'monorepo', 'services', 'alpha', 'src', `handler-${String(i).padStart(2, '0')}.ts`), 'export {}\n', 'utf8')
    }
    writeFileSync(join(reposDir, 'monorepo', 'services', 'beta', 'src', 'server.ts'), 'export {}\n', 'utf8')
    writeFileSync(join(reposDir, 'monorepo', 'services', 'gamma', 'src', 'routes.ts'), 'export {}\n', 'utf8')

    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-repo-bal',
      assignmentId: 'asg-repo-bal',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_b', role: 'member' }],
      recordedExchanges: new Map(),
      hasMountedRepos: true,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      specSubmission: { reposDir },
      runKovoVerify: async () => ({ confirmed: false }),
    })
    const repoTool = tools.find(tool => tool.name === 'repo')!
    const listRes = JSON.parse(extractText(await repoTool.execute(
      { action: 'list', maxFiles: 6 },
      {} as never,
      { abortSignal: new AbortController().signal } as never,
    ))) as { available: boolean; count: number; truncated: boolean; files: string[] }

    assert.equal(listRes.available, true)
    assert.equal(listRes.count, 6)
    assert.equal(listRes.truncated, true)
    assert.ok(listRes.files.some(f => f.includes('/services/alpha/')), 'must include alpha service files')
    assert.ok(listRes.files.some(f => f.includes('/services/beta/src/server.ts')), 'must include beta service without starvation')
    assert.ok(listRes.files.some(f => f.includes('/services/gamma/src/routes.ts')), 'must include gamma service without starvation')
    assert.equal(listRes.files.some(f => f.includes('/docs/')), false, 'deprioritized docs must not crowd out runtime source files')
  })
})
