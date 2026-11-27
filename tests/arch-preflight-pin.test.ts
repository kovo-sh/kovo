import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test, type TestContext } from 'node:test'
import type { WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import { SpecSubmissionTracker } from '../src/server/agent-session.ts'
import {
  buildConsolidatedExploiterToolset,
  buildExploiterUserPrompt,
  prepareDecoupledExploiterSession,
  resolveExploiterActingPersona,
  type PreflightNegativeEdge,
} from '../src/server/exploiter-tools.ts'
import type { RecordedRequestExchange } from '../src/server/trace-proof-compiler.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

const API_ORIGIN = 'https://api.preflight-guard.example'
const AUTH_ORIGIN = 'https://auth.preflight-guard.example'
const SAMPLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEiLCJyb2xlIjoiYWRtaW4ifQ.sigVal9876543210abcd'
const SAMPLE_OPAQUE_TOKEN = 'tok_live_explor_9f8e7d6c5b4a3210'

function extractText(res: { output?: Array<{ type: string; text?: string }> }): string {
  return (res.output ?? []).map(p => p.text ?? '').join('\n')
}

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

async function withMockVerifyRpc(
  t: TestContext,
  handler: (op: string, args: Record<string, unknown>) => unknown,
): Promise<{ ctx: VerifyContext; rpcOps: string[] }> {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-verify-preflight-'))
  const socketPath = join(dir, 'verify.sock')
  const tokenFile = join(dir, 'token')
  const contextFile = join(dir, 'context.json')
  writeFileSync(tokenFile, 'test-rpc-token', 'utf8')
  writeFileSync(contextFile, JSON.stringify({
    nonce: 'nonce-preflight-1',
    runId: 'run-preflight-1',
    targetOrigins: [API_ORIGIN],
    sdkVersion: 'kovo_verify/v8',
  }), 'utf8')

  const rpcOps: string[] = []
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', chunk => { raw += chunk })
    req.on('end', () => {
      try {
        const parsed = JSON.parse(raw) as { op: string; args: Record<string, unknown> }
        rpcOps.push(parsed.op)
        const result = handler(parsed.op, parsed.args)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, result }))
      } catch (err) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }))
      }
    })
  })
  await new Promise<void>(resolve => server.listen(socketPath, resolve))

  const prev = {
    socket: process.env.KOVO_RPC_SOCKET,
    token: process.env.KOVO_RPC_TOKEN_FILE,
    ctx: process.env.KOVO_RPC_CONTEXT_FILE,
    nonce: process.env.KOVO_VERIFY_NONCE,
  }
  process.env.KOVO_RPC_SOCKET = socketPath
  process.env.KOVO_RPC_TOKEN_FILE = tokenFile
  process.env.KOVO_RPC_CONTEXT_FILE = contextFile
  process.env.KOVO_VERIFY_NONCE = 'nonce-preflight-1'

  t.after(async () => {
    if (prev.socket === undefined) delete process.env.KOVO_RPC_SOCKET
    else process.env.KOVO_RPC_SOCKET = prev.socket
    if (prev.token === undefined) delete process.env.KOVO_RPC_TOKEN_FILE
    else process.env.KOVO_RPC_TOKEN_FILE = prev.token
    if (prev.ctx === undefined) delete process.env.KOVO_RPC_CONTEXT_FILE
    else process.env.KOVO_RPC_CONTEXT_FILE = prev.ctx
    if (prev.nonce === undefined) delete process.env.KOVO_VERIFY_NONCE
    else process.env.KOVO_VERIFY_NONCE = prev.nonce
    await new Promise<void>(resolve => server.close(() => resolve()))
    rmSync(dir, { recursive: true, force: true })
  })

  return { ctx: new VerifyContext(), rpcOps }
}

describe('Move 1b: Enforced actingPersona pin and purpose controls in exploiter request layer', () => {
  const personas = [
    { handle: 'owner_a', roleLabel: 'owner', originAllowlist: [API_ORIGIN] },
    { handle: 'member_a', roleLabel: 'member', originAllowlist: [API_ORIGIN] },
    { handle: 'member_b', roleLabel: 'member', originAllowlist: [API_ORIGIN] },
    { handle: 'dual_member', roleLabel: 'memberships=admin:org_a,viewer:org_b', originAllowlist: [API_ORIGIN] },
    { handle: 'revoked_user', roleLabel: 'revoked member', originAllowlist: [API_ORIGIN] },
  ]

  test('resolveExploiterActingPersona pins primaryAttackerBasePersona by default and multiTenantBase[0] ONLY on dual-tenant / cross-org privilege-bleed hypotheses', () => {
    const standard = resolveExploiterActingPersona({
      personas,
      step: { title: 'BOLA check', hypothesis: 'Access another tenant invoice via ID enumeration', category: 'broken-access-control' },
    })
    assert.equal(standard, 'member_a')

    const dualTenant = resolveExploiterActingPersona({
      personas,
      step: { title: 'Cache bleed check', hypothesis: 'Dual-tenant cross-org privilege bleed across cached responses', category: 'dual_tenant_abac' },
    })
    assert.equal(dualTenant, 'dual_member')

    const promptStandard = JSON.parse(buildExploiterUserPrompt({
      goal: 'Verify tenant isolation',
      step: { id: 's1', title: 'BOLA', hypothesis: 'Read victim record', category: 'bola' },
      origins: [API_ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
      personas,
    })) as { actingPersona?: string; primaryAttackerBasePersona?: string }
    assert.equal(promptStandard.actingPersona, 'member_a')
    assert.equal(promptStandard.primaryAttackerBasePersona, 'member_a')

    const promptDual = JSON.parse(buildExploiterUserPrompt({
      goal: 'Verify tenant isolation',
      step: { id: 's2', title: 'Dual-tenant ABAC', hypothesis: 'Test dual_tenant_abac cache bleed', category: 'dual_tenant_abac' },
      origins: [API_ORIGIN],
      capabilityTier: 2,
      maxTurns: 12,
      personas,
    })) as { actingPersona?: string }
    assert.equal(promptDual.actingPersona, 'dual_member')
  })

  test('20-call run-scale mixed sequence: enforces actingPersona pin, allows cap: handles, control arm tagging, read-only victim_setup, and blocks mutating victim_setup', async () => {
    const sentRequests: Array<{ mode: 'single' | 'batch' | 'race'; method: string; path: string; persona?: string }> = []
    const tracker = new SpecSubmissionTracker()
    const mintedCaps = new Set(['cap:hop_1:derived_tok'])

    const session = prepareDecoupledExploiterSession({
      handlers: makeDummyHandlers({
        request_http: async req => {
          sentRequests.push({ mode: 'single', method: req.method, path: req.pathAndQuery, persona: req.persona })
          return { exchangeId: `ex-s-${sentRequests.length}`, status: 200, bodySha256: 'h1', bodyPreview: '{}' }
        },
        request_http_batch: async args => {
          for (const r of args.requests) sentRequests.push({ mode: 'batch', method: r.method, path: r.pathAndQuery, persona: r.persona })
          return { count: args.requests.length, results: args.requests.map((_, i) => ({ exchangeId: `ex-b-${i}`, status: 200 })) }
        },
        request_http_race: async args => {
          for (const r of args.requests) sentRequests.push({ mode: 'race', method: r.method, path: r.pathAndQuery, persona: r.persona })
          return { count: args.requests.length, results: args.requests.map((_, i) => ({ exchangeId: `ex-r-${i}`, status: 200 })) }
        },
      }),
      storage: { listEndpoints: () => [], getExchange: () => { throw new Error('missing') } },
      runId: 'run-pin-20',
      assignmentId: 'asg-pin-20',
      publicOrigins: [API_ORIGIN],
      personasPub: personas,
      isSessionCapabilityHandle: h => mintedCaps.has(h),
      recordedExchanges: new Map(),
      mountedRepos: [],
      userPromptInput: {
        goal: 'Verify tenant boundaries',
        step: { id: 's-pin', title: 'Standard chain', hypothesis: 'Probe horizontal access', category: 'bola' },
        origins: [API_ORIGIN],
        capabilityTier: 2,
        maxTurns: 15,
        personas,
      },
      runKovoVerify: async () => ({ confirmed: false }),
      proofWriterDeps: { profiles: [] },
      onProofConfirmed: () => undefined,
      onToolExecuted: () => undefined,
    })

    const tools = session.overrideTools({
      scrubbers: { scrubForDisplay: v => v, scrubExact: v => v },
      signal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      specSubmission: { tracker },
    })
    const httpTool = tools.find(t => t.name === 'http')!
    const call = (args: Record<string, unknown>) =>
      httpTool.execute(args, {} as never, { abortSignal: new AbortController().signal } as never) as Promise<{
        isError?: boolean; output: Array<{ type: string; text?: string }>
      }>

    const sequence: Array<{
      label: string
      args: Record<string, unknown>
      expectError?: RegExp
      expectControlTag?: boolean
    }> = [
      // 1-3: pinned attacker allowed (single, batch, race)
      { label: 'pinned single', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/items/1', persona: 'member_a' } },
      { label: 'pinned explicit attacker', args: { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/items', persona: 'member_a', purpose: 'attacker' } },
      { label: 'pinned batch', args: { mode: 'batch', requests: [{ origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/a', persona: 'member_a' }, { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/b', persona: 'member_a' }] } },
      // 4-8: non-pinned personas blocked on attacker arm in <1ms
      { label: 'block member_b', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/items/2', persona: 'member_b' }, expectError: /persona_pin_violation.*actingPersona "member_a"/ },
      { label: 'block dual_member', args: { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/cache/prime', persona: 'dual_member' }, expectError: /persona_pin_violation.*actingPersona "member_a"/ },
      { label: 'block owner_a', args: { origin: API_ORIGIN, method: 'DELETE', pathAndQuery: '/v1/items/9', persona: 'owner_a' }, expectError: /persona_pin_violation.*actingPersona "member_a"/ },
      { label: 'block batch with member_b', args: { mode: 'batch', requests: [{ origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/ok', persona: 'member_a' }, { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/bad', persona: 'member_b' }] }, expectError: /persona_pin_violation/ },
      { label: 'block race with dual_member', args: { mode: 'race', requests: [{ origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/pay', persona: 'dual_member' }, { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/pay', persona: 'dual_member' }] }, expectError: /persona_pin_violation/ },
      // 9-10: derived cap: handle allowed if session-minted, blocked if unknown
      { label: 'allow minted cap:', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/vault', persona: 'cap:hop_1:derived_tok' } },
      { label: 'block unminted cap:', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/vault', persona: 'cap:hop_9:forged' }, expectError: /persona_pin_violation/ },
      // 11-13: purpose="control" allowed & tagged cleanly as control arm
      { label: 'control same actor', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/admin/secret', persona: 'member_a', purpose: 'control' }, expectControlTag: true },
      { label: 'control alt actor', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/admin/secret', persona: 'member_b', purpose: 'control' }, expectControlTag: true },
      { label: 'control batch', args: { mode: 'batch', purpose: 'control', requests: [{ origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/ctrl1', persona: 'member_a' }] }, expectControlTag: true },
      // 14-15: purpose="victim_setup" allows read-only GET/HEAD for other personas
      { label: 'victim_setup GET owner_a', args: { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/org-b/records', persona: 'owner_a', purpose: 'victim_setup' } },
      { label: 'victim_setup HEAD member_b', args: { origin: API_ORIGIN, method: 'HEAD', pathAndQuery: '/v1/org-b/records/7', persona: 'member_b', purpose: 'victim_setup' } },
      // 16-19: purpose="victim_setup" blocks ALL mutating methods (POST/PATCH/PUT/DELETE)
      { label: 'victim_setup POST blocked', args: { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/org-b/records', persona: 'owner_a', purpose: 'victim_setup' }, expectError: /victim_setup_readonly_violation/ },
      { label: 'victim_setup PATCH blocked', args: { origin: API_ORIGIN, method: 'PATCH', pathAndQuery: '/v1/org-b/records/7', persona: 'member_b', purpose: 'victim_setup' }, expectError: /victim_setup_readonly_violation/ },
      { label: 'victim_setup PUT blocked', args: { origin: API_ORIGIN, method: 'PUT', pathAndQuery: '/v1/org-b/records/7', persona: 'dual_member', purpose: 'victim_setup' }, expectError: /victim_setup_readonly_violation/ },
      { label: 'victim_setup DELETE batch blocked', args: { mode: 'batch', purpose: 'victim_setup', requests: [{ origin: API_ORIGIN, method: 'DELETE', pathAndQuery: '/v1/org-b/records/7', persona: 'owner_a' }] }, expectError: /victim_setup_readonly_violation/ },
      // 20: pinned race succeeds
      { label: 'pinned race', args: { mode: 'race', requests: [{ origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/redeem', persona: 'member_a' }, { origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/redeem', persona: 'member_a' }] } },
    ]
    assert.equal(sequence.length, 20)

    const allowedNonPinnedPaths = new Set(['/v1/admin/secret', '/v1/org-b/records', '/v1/org-b/records/7'])
    for (const step of sequence) {
      const t0 = performance.now()
      const res = await call(step.args)
      const elapsedMs = performance.now() - t0
      const text = extractText(res)
      if (step.expectError) {
        assert.equal(res.isError, true, `${step.label} must return isError=true`)
        assert.match(text, step.expectError, `${step.label} error mismatch: ${text}`)
        assert.ok(elapsedMs < 15, `${step.label} must reject locally in <15ms (got ${elapsedMs.toFixed(2)}ms)`)
      } else {
        assert.equal(res.isError, undefined, `${step.label} unexpectedly failed: ${text}`)
        if (step.expectControlTag) {
          const parsed = JSON.parse(text) as { arm?: string; purpose?: string }
          assert.equal(parsed.arm, 'control', `${step.label} must tag arm="control"`)
          assert.equal(parsed.purpose, 'control', `${step.label} must tag purpose="control"`)
        }
      }
    }

    // Zero unauthorized non-attacker-persona exchanges ever hit the broker!
    const rogueAttackerCalls = sentRequests.filter(r =>
      r.persona
      && r.persona !== 'member_a'
      && !r.persona.startsWith('cap:')
      && !allowedNonPinnedPaths.has(r.path),
    )
    assert.deepEqual(rogueAttackerCalls, [], '0 unauthorized non-pinned attacker exchanges must reach broker')
    assert.ok(sentRequests.some(r => r.persona === 'cap:hop_1:derived_tok'), 'session cap: handle must pass through')
  })
})

describe('Move B: <1ms Pre-Flight Rejection, Negative-Edge Recording, and Literal Token Carry-Over Guard', () => {
  test('submit_exploit_trace rejects non-2xx terminals in <5ms with 0 runKovoVerify calls and records negative edges', async () => {
    const recorded = new Map<string, RecordedRequestExchange>([
      ['ex-401', { exchangeId: 'ex-401', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/admin/keys?org=b', persona: 'member_a', status: 401, timestampMs: 100 }],
      ['ex-403', { exchangeId: 'ex-403', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/9/approve', persona: 'member_a', status: 403, timestampMs: 110 }],
      ['ex-404', { exchangeId: 'ex-404', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/99', persona: 'member_a', status: 404, timestampMs: 120 }],
      ['ex-500', { exchangeId: 'ex-500', origin: API_ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/settle', persona: 'member_a', status: 500, timestampMs: 130 }],
    ])
    const negEdges: PreflightNegativeEdge[] = []
    let verifyCalls = 0
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-neg',
      assignmentId: 'asg-neg',
      publicOrigins: [API_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      recordNegativeEdge: edge => { negEdges.push(edge) },
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => { verifyCalls += 1; return { confirmed: true } },
    })
    const submit = tools.find(t => t.name === 'submit_exploit_trace')!

    for (const [id, status, expectedPath, expectedReason] of [
      ['ex-401', 401, '/v1/admin/keys', 'control_blocked_cleanly'],
      ['ex-403', 403, '/v1/payouts/9/approve', 'control_blocked_cleanly'],
      ['ex-404', 404, '/v1/exports/99', 'control_blocked_cleanly'],
      ['ex-500', 500, '/v1/webhooks/settle', 'terminal_non_2xx'],
    ] as const) {
      const t0 = performance.now()
      const out = JSON.parse(extractText(await submit.execute({
        title: `Attempt ${id}`, vulnClass: 'bfla', exchangeIds: [id], terminalExchangeId: id,
      }, {} as never, { abortSignal: new AbortController().signal } as never))) as {
        ok: boolean; confirmed: boolean; rejectedBy: string; negativeEdge?: PreflightNegativeEdge
      }
      const elapsedMs = performance.now() - t0
      assert.ok(elapsedMs < 5, `${id} must reject in <5ms (got ${elapsedMs.toFixed(2)}ms)`)
      assert.equal(out.ok, false)
      assert.equal(out.confirmed, false)
      assert.equal(out.rejectedBy, 'terminal_exchange_not_succeeding')
      assert.deepEqual(out.negativeEdge, {
        origin: API_ORIGIN,
        method: recorded.get(id)!.method,
        path: expectedPath,
        status,
        reason: expectedReason,
      })
    }
    assert.equal(verifyCalls, 0, '0 Docker/runKovoVerify calls on non-2xx terminals')
    assert.equal(negEdges.length, 4, 'recordNegativeEdge callback must receive all 4 negative edges')
  })

  test('direct kovo_verify tool short-circuits non-2xx terminal routes and literal token carry-over in <5ms with 0 Docker calls', async () => {
    const recorded = new Map<string, RecordedRequestExchange>([
      ['ex-mint', {
        exchangeId: 'ex-mint', origin: AUTH_ORIGIN, method: 'POST', pathAndQuery: '/oauth/token',
        persona: 'member_a', status: 200, responseBody: JSON.stringify({ access_token: SAMPLE_JWT }),
        responseJson: { access_token: SAMPLE_JWT }, timestampMs: 100,
      }],
      ['ex-denied', {
        exchangeId: 'ex-denied', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/admin/ledger',
        persona: 'member_a', status: 403, responseBody: '{"error":"forbidden"}', timestampMs: 120,
      }],
      ['ex-ok', {
        exchangeId: 'ex-ok', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/vault/data',
        persona: 'member_a', status: 200, responseBody: '{"secret":"ok"}', timestampMs: 140,
      }],
    ])
    const negEdges: PreflightNegativeEdge[] = []
    let dockerVerifyCalls = 0
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers({
        kovo_verify: async () => {
          dockerVerifyCalls += 1
          return { confirmed: true, findingId: 'f-ok' }
        },
      }),
      runId: 'run-kv-pre',
      assignmentId: 'asg-kv-pre',
      publicOrigins: [API_ORIGIN, AUTH_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      recordNegativeEdge: edge => { negEdges.push(edge) },
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => { dockerVerifyCalls += 1; return { confirmed: true } },
    })
    const kvTool = tools.find(t => t.name === 'kovo_verify')!

    // 1. Non-2xx terminal route (only 403 recorded, 0 2xx) -> rejected in <5ms, 0 Docker calls, negative edge recorded
    const t0 = performance.now()
    const non2xxRes = JSON.parse(extractText(await kvTool.execute({
      title: 'Doomed 403 admin ledger',
      script: `const ch = ctx.chain('c1', 'bfla'); await ch.step('GET /v1/admin/ledger', { as: 'member_a' }); return await ch.prove({ claimedImpact: 'read ledger' })`,
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as {
      ok: boolean; confirmed: boolean; rejectedBy: string; negativeEdge?: PreflightNegativeEdge
    }
    assert.ok(performance.now() - t0 < 5)
    assert.equal(non2xxRes.ok, false)
    assert.equal(non2xxRes.rejectedBy, 'terminal_exchange_not_succeeding')
    assert.equal(non2xxRes.negativeEdge?.status, 403)
    assert.equal(non2xxRes.negativeEdge?.path, '/v1/admin/ledger')
    assert.equal(dockerVerifyCalls, 0)
    assert.equal(negEdges.length, 1)

    // 2. Literal token carry-over in kovo_verify script (pastes SAMPLE_JWT from ex-mint instead of ch.seal) -> rejected in <5ms, 0 Docker calls
    const t1 = performance.now()
    const carryRes = JSON.parse(extractText(await kvTool.execute({
      title: 'Stale exploration JWT carry-over',
      script: `const ch = ctx.chain('c2', 'privilege_escalation'); await ch.step('POST /oauth/token', { as: 'member_a' }); await ch.step('GET /v1/vault/data', { headers: { Authorization: 'Bearer ${SAMPLE_JWT}' } }); return await ch.prove({ claimedImpact: 'vault read' })`,
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as {
      ok: boolean; confirmed: boolean; rejectedBy: string; error?: string
    }
    assert.ok(performance.now() - t1 < 5)
    assert.equal(carryRes.ok, false)
    assert.equal(carryRes.rejectedBy, 'literal_token_carryover')
    assert.match(carryRes.error ?? '', /ch\.seal\(\.\.\.\).*cap: handle/i)
    assert.equal(dockerVerifyCalls, 0)

    // 3. Clean script using ch.seal + cap: handle on 2xx route passes pre-flight and invokes verifier
    const okRes = JSON.parse(extractText(await kvTool.execute({
      title: 'Proper sealed replay',
      script: `const ch = ctx.chain('c3', 'privilege_escalation'); const h1 = await ch.step('POST /oauth/token', { as: 'member_a' }); const cap = await ch.seal(h1, 'access_token'); await ch.step('GET /v1/vault/data', { capability: cap }); return await ch.prove({ claimedImpact: 'vault read' })`,
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as { confirmed: boolean }
    assert.equal(okRes.confirmed, true)
    assert.equal(dockerVerifyCalls, 1)
  })

  test('submit_exploit_trace catches literal token carry-over from unincluded exploration exchange in <5ms with 0 runKovoVerify calls', async () => {
    const recorded = new Map<string, RecordedRequestExchange>([
      ['ex-explore-mint', {
        exchangeId: 'ex-explore-mint', origin: AUTH_ORIGIN, method: 'POST', pathAndQuery: '/oauth/mint',
        persona: 'member_a', status: 200, responseJson: { access_token: SAMPLE_OPAQUE_TOKEN },
        responseBody: JSON.stringify({ access_token: SAMPLE_OPAQUE_TOKEN }), timestampMs: 100,
      }],
      ['ex-term-carry', {
        exchangeId: 'ex-term-carry', origin: API_ORIGIN, method: 'GET', pathAndQuery: '/v1/secret-records',
        persona: 'member_a', requestHeaders: { authorization: `Bearer ${SAMPLE_OPAQUE_TOKEN}` },
        status: 200, responseJson: { rows: 3 }, responseBody: '{"rows":3}', timestampMs: 150,
      }],
    ])
    let verifyCalls = 0
    const tools = buildConsolidatedExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-carry',
      assignmentId: 'asg-carry',
      publicOrigins: [API_ORIGIN, AUTH_ORIGIN],
      personasPub: [{ handle: 'member_a', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => { verifyCalls += 1; return { confirmed: true } },
    })
    const submit = tools.find(t => t.name === 'submit_exploit_trace')!

    // Submitting ONLY ex-term-carry (carrying stale exploration literal from ex-explore-mint) fails fast in <5ms!
    const t0 = performance.now()
    const bad = JSON.parse(extractText(await submit.execute({
      title: 'Carry-over without mint hop', vulnClass: 'privilege_escalation',
      exchangeIds: ['ex-term-carry'], terminalExchangeId: 'ex-term-carry',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as {
      ok: boolean; confirmed: boolean; rejectedBy: string; message?: string
    }
    assert.ok(performance.now() - t0 < 5)
    assert.equal(bad.ok, false)
    assert.equal(bad.rejectedBy, 'literal_token_carryover')
    assert.match(bad.message ?? '', /ch\.seal\(\.\.\.\)/)
    assert.equal(verifyCalls, 0)

    // Including ex-explore-mint lets trace-proof-compiler compile into ch.seal(...) + cap handle cleanly!
    const good = JSON.parse(extractText(await submit.execute({
      title: 'Complete two-hop chain', vulnClass: 'privilege_escalation',
      exchangeIds: ['ex-explore-mint', 'ex-term-carry'], terminalExchangeId: 'ex-term-carry',
    }, {} as never, { abortSignal: new AbortController().signal } as never))) as { confirmed: boolean }
    assert.equal(good.confirmed, true)
    assert.equal(verifyCalls, 1)
  })

  test('worker/kovo_verify/kovo_verify.ts stays <= 800 LOC and short-circuits non-2xx terminals and literal token carry-over before composite.verify RPC', async (t: TestContext) => {
    const sdkSrc = readFileSync(join(process.cwd(), 'worker/kovo_verify/kovo_verify.ts'), 'utf8')
    const sdkLoc = sdkSrc.trimEnd().split('\n').length
    assert.ok(sdkLoc <= 800, `worker/kovo_verify/kovo_verify.ts must be <= 800 LOC, got ${sdkLoc}`)
    assert.equal(/\bnew\s+RegExp\s*\(/.test(sdkSrc), false, 'kovo_verify.ts must not use new RegExp()')

    let seq = 0
    const { ctx, rpcOps } = await withMockVerifyRpc(t, (op, args) => {
      if (op === 'http.send' || op === 'http') {
        seq += 1
        const path = String(args.path ?? '/')
        if (path === '/v1/denied') {
          return { exchangeId: `ex-${seq}`, status: 403, method: 'GET', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body: '{"error":"denied"}', bodyPreview: '{"error":"denied"}', bodyBytes: 18, bodySha256: 's1', durationMs: 2, personaHandle: 'member_a' }
        }
        if (path === '/v1/mint') {
          const body = JSON.stringify({ access_token: SAMPLE_JWT })
          return { exchangeId: `ex-${seq}`, status: 200, method: 'POST', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body, bodyPreview: body, bodyBytes: body.length, bodySha256: 's2', durationMs: 2, personaHandle: 'member_a' }
        }
        return { exchangeId: `ex-${seq}`, status: 200, method: 'GET', pathAndQuery: path, mediaType: 'application/json', headers: { 'content-type': 'application/json' }, body: '{"ok":true}', bodyPreview: '{"ok":true}', bodyBytes: 11, bodySha256: 's3', durationMs: 2, personaHandle: 'member_a', ...(args.capability ? { consumedCapabilityId: String(args.capability) } : {}) }
      }
      if (op === 'capability.seal') {
        return { handle: 'cap:hop_1:tok', meta: {}, exchangeId: String(args.exchangeId), sealExchangeId: 'ex-seal-1', scrubbedPreview: '<redacted>' }
      }
      if (op === 'composite.verify') {
        return { confirmed: true, ok: true, verified: true, chainId: 'c-ok', terminalVulnClass: 'bfla', replayMode: 'fresh_clean_replay', modeBVerified: true, hopCount: 2, verifiedEdges: [], reason: 'confirmed' }
      }
      throw new Error(`Unexpected op ${op}`)
    })

    // 1. Non-2xx terminal in ChainBuilder.prove short-circuits BEFORE composite.verify RPC
    const ch403 = ctx.chain('c-403', 'bfla')
    const denied = await ch403.step('GET /v1/denied', { as: 'member_a' })
    const res403 = await ch403.prove({ terminalExchange: denied, claimedImpact: 'read denied' })
    assert.equal(res403.confirmed, false)
    assert.equal(res403.failedStage, 'preflight')
    assert.equal(res403.rejectedBy, 'terminal_exchange_not_succeeding')
    assert.equal((res403.evidence as { negativeEdge?: { status?: number; path?: string } })?.negativeEdge?.status, 403)
    assert.equal(rpcOps.includes('composite.verify'), false, 'must NOT call composite.verify RPC on non-2xx terminal')
    assert.equal(ctx.claims.length, 0, 'failed preflight must not poison ctx.claims')
    assert.equal(ctx.effectiveClaims().length, 1, 'failed preflight must surface fallback claim via effectiveClaims()')

    // 2. Multi-hop literal token carry-over without ch.seal short-circuits BEFORE composite.verify RPC
    const chCarry = ctx.chain('c-carry', 'privilege_escalation')
    const h1 = await chCarry.step('POST /v1/mint', { as: 'member_a' })
    const rawTok = (h1.json as { access_token: string }).access_token
    await chCarry.step('GET /v1/vault', { headers: { Authorization: `Bearer ${rawTok}` } })
    const resCarry = await chCarry.prove({ claimedImpact: 'vault read with raw literal' })
    assert.equal(resCarry.confirmed, false)
    assert.equal(resCarry.failedStage, 'preflight')
    assert.equal(resCarry.rejectedBy, 'literal_token_carryover')
    assert.match(resCarry.reason, /ch\.seal\(\.\.\.\).*cap: handle/i)
    assert.equal(rpcOps.includes('composite.verify'), false, 'must NOT call composite.verify RPC on literal token carry-over')

    // 3. Proper ch.seal + cap: handle passes pre-flight and calls composite.verify RPC!
    const chGood = ctx.chain('c-good', 'privilege_escalation')
    const g1 = await chGood.step('POST /v1/mint', { as: 'member_a' })
    const cap = await chGood.seal(g1, 'access_token')
    await chGood.step('GET /v1/vault', { capability: cap })
    const resGood = await chGood.prove({ claimedImpact: 'vault read via sealed cap' })
    assert.equal(resGood.confirmed, true)
    assert.equal(rpcOps.filter(op => op === 'composite.verify').length, 1)
  })
})
