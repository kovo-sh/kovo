/**
 * Behavioral tests for Option D Code Mode / PTC Exploiter wiring (`src/server/ptc-exploiter.ts`,
 * `src/server/exploiter-tools.ts`, `src/server/exec-worker-runner.ts`, `scripts/benchmark-multihop.ts`).
 */
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { buildMultihopCellEnv } from '../scripts/benchmark-multihop.ts'
import { resolveObservedEffectiveConfigForRunner } from '../scripts/benchmark-realistic.ts'
import type { WorkerToolHandlers } from '../src/server/agent-prompts.ts'
import { SpecSubmissionTracker } from '../src/server/agent-session.ts'
import type { BrokerExchangeResult } from '../src/server/broker.ts'
import {
  buildBrokeredTransportHandlers,
  type ExecBrokeredTransportHost,
} from '../src/server/exec-brokered-transport.ts'
import { type ExploiterRunStorage } from '../src/server/exploiter-tools.ts'
import {
  buildPtcExploiterSystemPrompt,
  buildPtcExploiterToolset,
  createPtcExploiterDispatch,
  isDecoupledOrPtcExploiterEnabled,
  isExploiterPtcEnabled,
  prepareExploiterSession,
} from '../src/server/ptc-exploiter.ts'
import { PtcRpcServer, readPtcClientSource } from '../src/server/ptc-rpc.ts'
import type { RecordedRequestExchange } from '../src/server/trace-proof-compiler.ts'
import { runPtcScript } from '../worker/bridge.ts'

function extractText(res: { output?: Array<{ type: string; text?: string }> }): string {
  return (res.output ?? []).map(p => p.text ?? '').join('\n')
}

function makeTempDir(t: test.TestContext, prefix = 'kovo-ptc-wire-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeDummyHandlers(): WorkerToolHandlers {
  return {
    request_http: async args => ({
      exchangeId: 'ex-1', status: 200, origin: args.origin, method: args.method, pathAndQuery: args.pathAndQuery,
      bodySha256: 'abc', bodyPreview: '{"ok":true}',
    }),
    request_http_batch: async args => ({ count: args.requests.length, results: [] }),
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
    search_repo: async args => ({ query: args.query, matches: [] }),
    read_repo_file: async args => ({ path: args.path, content: 'line1' }),
    record_fact: async args => ({ recorded: true, kind: args.kind }),
    suggest_candidate_host: async args => ({ suggested: true, origin: args.origin }),
    complete_intent: async c => ({ ok: true, status: c.status }),
  }
}

function makeFakeStorage(): ExploiterRunStorage {
  return {
    listEndpoints: () => [
      { origin: 'http://app.local', method: 'POST', pathTemplate: '/api/mint', riskScore: 95, source: 'crawl' } as never,
      { origin: 'http://api.local', method: 'GET', pathTemplate: '/api/records/1', riskScore: 90, source: 'crawl' } as never,
    ],
    getExchange: () => { throw new Error('not found') },
  }
}

test('PTC toolset exposes strictly 3 tools (allowWebSearch=false) and 4 tools (allowWebSearch=true) + feature flags', () => {
  const mk = (allowWebSearch: boolean) =>
    buildPtcExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-1',
      assignmentId: 'asg-1',
      publicOrigins: ['http://app.local', 'http://api.local'],
      personasPub: [{ handle: 'member_b', role: 'member' }],
      recordedExchanges: new Map(),
      hasMountedRepos: false,
      allowWebSearch,
      scrub: v => v,
      rootSignal: new AbortController().signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: false }),
      ptcRpc: { resetCallBudget: () => undefined },
      ptcExec: async () => ({ ok: true, result: null, stdout: '', stderr: '', exitCode: 0, durationMs: 1 }),
    })

  const noWeb = mk(false).map(t => t.name)
  const withWeb = mk(true).map(t => t.name)

  assert.deepEqual(noWeb, ['execute_code', 'submit_exploit_trace', 'complete_intent'])
  assert.deepEqual(withWeb, ['execute_code', 'submit_exploit_trace', 'web_search', 'complete_intent'])
  for (const names of [noWeb, withWeb]) {
    for (const excluded of ['kovo_verify', 'http', 'browser', 'sandbox_exec', 'board_post', 'board_read', 'record_coverage']) {
      assert.equal(names.includes(excluded), false, `PTC toolset must not expose ${excluded}`)
    }
  }

  assert.equal(isExploiterPtcEnabled({ KOVO_EXPLOITER_PTC: '1' }), true)
  assert.equal(isExploiterPtcEnabled({ KOVO_EXPLOITER_PTC: '0' }), false)
  assert.equal(isExploiterPtcEnabled({}), false)
  assert.equal(isDecoupledOrPtcExploiterEnabled({ KOVO_EXPLOITER_PTC: '1' }), true)
  assert.equal(isDecoupledOrPtcExploiterEnabled({ KOVO_DECOUPLED_PROOF_PIPELINE: '1' }), true)
  assert.equal(isDecoupledOrPtcExploiterEnabled({}), false)
})

test('PTC system prompt is < 2200 chars, includes kovo.* API + example, and omits verification DSL and benchmark literals', () => {
  for (const opts of [
    { hasMountedRepos: false, allowWebSearch: false },
    { hasMountedRepos: true, allowWebSearch: true },
  ]) {
    const prompt = buildPtcExploiterSystemPrompt(opts)
    assert.ok(prompt.length < 2200, `Expected PTC prompt < 2200 chars, got ${prompt.length}`)
    assert.ok(prompt.includes('kovo.searchRun'))
    assert.ok(prompt.includes('kovo.http'))
    assert.ok(prompt.includes('submit_exploit_trace'))
    assert.ok(prompt.includes('complete_intent'))
    assert.equal(prompt.includes('kovo.repo'), Boolean(opts.hasMountedRepos))
    assert.equal(prompt.includes('web_search'), Boolean(opts.allowWebSearch))
    for (const forbidden of ['kovo_verify', 'prove_composite', 'causalEdges', 'oracleInput', 'seal_capability', 'paygrid', 'shipforge', 'nexusiam', 'connecthub']) {
      assert.equal(prompt.toLowerCase().includes(forbidden.toLowerCase()), false, `PTC prompt must not include ${forbidden}`)
    }
  }
})

test('execute_code dispatches kovo.searchRun/http/race via PtcRpcServer -> brokered handlers -> lossless capture -> submit_exploit_trace -> Stage 2a', async t => {
  const hostDir = makeTempDir(t, 'kovo-ptc-e2e-')
  const recordedExchanges = new Map<string, RecordedRequestExchange>()
  let seq = 0
  const mintedToken = 'tok_live_secret_9876543210abcdef'
  const mkRes = (origin: string, method: string, path: string, body: string, persona?: string): BrokerExchangeResult => ({
    origin, finalOrigin: origin, redirectOrigins: [], method, pathAndQuery: path, personaHandle: persona ?? null,
    status: 200, mediaType: 'application/json',
    reqHeaders: { 'content-type': 'application/json' },
    respHeaders: { 'content-type': 'application/json' },
    setCookies: [], bodyPreview: body, body, bodySha256: `sha-${seq}`,
    bodyBytes: Buffer.byteLength(body), bodyTruncated: false, durationMs: 4,
    observation: {} as BrokerExchangeResult['observation'],
  })

  const fakeRun = { id: 'run-ptc', scopeRevision: 1, capabilityTier: 2, budgetRequests: 100, spentRequests: 0 } as never
  const host = {
    storage: {
      checkBudgetExceeded: () => false,
      scopePolicy: () => ({ mode: 'ephemeral_lab' as const }),
      recordExchange: () => ({ id: `ex-${++seq}` }),
    },
    broker: {
      executeHttp: async (req: { origin: string; method: string; pathAndQuery: string; persona?: string }) => {
        if (req.pathAndQuery === '/api/mint') {
          return mkRes(req.origin, req.method, req.pathAndQuery, JSON.stringify({ accessToken: mintedToken }), req.persona)
        }
        return mkRes(req.origin, req.method, req.pathAndQuery, JSON.stringify({ owner: 'victim_org', recordId: '1', flag: 'secret_row_data' }), req.persona)
      },
      executeBatch: async () => [mkRes('http://app.local', 'GET', '/api/health', '{"ok":true}')],
      executeRaceBurst: async () => ({
        summary: { ok: 2 },
        results: [mkRes('http://api.local', 'POST', '/api/redeem', '{"credited":50}', 'member_b')],
      }),
    },
    check: () => fakeRun,
    markEndpointCoverage: () => undefined,
    scanSecondOrderExchange: () => undefined,
    stageAgentRaceBurst: (_r: string, _g: unknown, _m: unknown, _t: unknown, reqs: unknown[]) => reqs,
    executeApprovedRaceBurst: async (_j: unknown, _r: unknown, _g: unknown, _s: unknown, opts: { execute: () => Promise<unknown> }) => opts.execute(),
    executeApprovedBatch: async (_j: unknown, _r: unknown, _g: unknown, _s: unknown, opts: { execute: () => Promise<unknown> }) => opts.execute(),
    stagingCreatedEntities: new Map(),
  } as unknown as ExecBrokeredTransportHost

  const transport = buildBrokeredTransportHandlers(host, {
    job: { assignment: { id: 'asg-ptc' } } as never,
    step: { title: 'ptc-chain' } as never,
    session: { stage: async () => '/evidence/ex.json' } as never,
    grant: {} as never,
    currentSecrets: () => [{ value: mintedToken, placeholder: '[redacted-token]' }],
    boardTools: { noteEvidence: () => undefined },
    sharedHandlers: {} as never,
    trackPersonaResources: () => undefined,
    prepareBudgetedProbe: (() => ({})) as never,
    stageJsonArtifact: (async () => ({ evidenceId: 'ev-1', stagedPath: null })) as never,
    onExchangeRecorded: ex => { recordedExchanges.set(ex.exchangeId, ex) },
  })
  const handlers: WorkerToolHandlers = { ...makeDummyHandlers(), ...transport }

  const verifiedScripts: string[] = []
  let confirmedTitle = ''
  const clientCode = readPtcClientSource()
  const tracker = new SpecSubmissionTracker()
  const prepared = await prepareExploiterSession({
    handlers,
    storage: makeFakeStorage(),
    runId: 'run-ptc',
    assignmentId: 'asg-ptc',
    runAllowWebSearch: false,
    publicOrigins: ['http://app.local', 'http://api.local'],
    personasPub: [{ handle: 'member_b', roleLabel: 'member', originAllowlist: ['http://app.local', 'http://api.local'] }],
    recordedExchanges,
    mountedRepos: [],
    userPromptInput: {
      goal: 'Verify cross-origin access boundary',
      step: { id: 's-1', title: 'PTC chain', hypothesis: 'Token mint pivots to cross-origin record', category: 'A01:2021' },
      origins: ['http://app.local'], publicOrigins: ['http://app.local', 'http://api.local'],
      capabilityTier: 2, maxTurns: 12,
    },
    runKovoVerify: async ({ script }) => {
      verifiedScripts.push(script)
      return { confirmed: true, findingId: 'find-ptc-1' }
    },
    proofWriterDeps: {} as never,
    onProofConfirmed: info => { confirmedTitle = info.title },
    onToolExecuted: () => undefined,
    env: { KOVO_EXPLOITER_PTC: '1' },
    workerSession: {
      ptcHostDir: hostDir,
      ptcExec: async req => runPtcScript(
        { code: req.code, clientCode, timeoutMs: req.timeoutMs, maxOutputBytes: req.maxOutputBytes },
        hostDir,
        { KOVO_PTC_SOCKET: join(hostDir, 'ptc.sock'), KOVO_PTC_TOKEN_FILE: join(hostDir, 'token') },
      ),
    },
  })
  t.after(() => prepared.close?.())

  assert.equal(prepared.mode, 'ptc')
  assert.ok(prepared.ptcRpc)
  assert.equal(existsSync(prepared.ptcRpc.socketPath), true)
  assert.equal(existsSync(prepared.ptcRpc.tokenPath), true)

  const rootAbort = new AbortController()
  const tools = prepared.session.overrideTools({
    scrubbers: {
      scrubForDisplay: v => v.split(mintedToken).join('[redacted-token]'),
      scrubExact: v => v,
    },
    signal: rootAbort.signal,
    inlineLimit: 24_000,
    onCompleteIntent: () => undefined,
    specSubmission: { tracker },
  })
  assert.deepEqual(tools.map(tool => tool.name), ['execute_code', 'submit_exploit_trace', 'complete_intent'])

  const execTool = tools.find(tool => tool.name === 'execute_code')!
  const submitTool = tools.find(tool => tool.name === 'submit_exploit_trace')!

  const execRes = await execTool.execute({
    code: `
      const eps = await kovo.searchRun({ target: 'endpoints', limit: 20 })
      const hop1 = await kovo.http('POST', '/api/mint', { origin: 'http://app.local', as: 'member_b', body: { scope: 'export' } }) as any
      const parsed = JSON.parse(hop1.bodyPreview)
      const hop2 = await kovo.http('GET', '/api/records/1', {
        origin: 'http://api.local',
        headers: { Authorization: 'Bearer ' + parsed.accessToken },
      }) as any
      const burst = await kovo.race([
        { origin: 'http://api.local', method: 'POST', pathAndQuery: '/api/redeem', as: 'member_b', body: { code: 'c1' } },
      ]) as any
      console.log('debug token=' + parsed.accessToken)
      return {
        endpointCount: eps.count,
        exchanges: [hop1.exchangeId, hop2.exchangeId],
        leakedPreview: parsed.accessToken,
        raceOk: burst.summary?.ok ?? 0,
      }
    `,
  }, {} as never, { abortSignal: rootAbort.signal } as never)

  const execText = extractText(execRes)
  assert.equal(execRes.isError, undefined, `execute_code failed: ${execText}`)
  assert.equal(execText.includes(mintedToken), false, 'execute_code output must mask live secrets')
  const execJson = JSON.parse(execText) as { ok: boolean; result: { endpointCount: number; exchanges: string[]; raceOk: number }; stdout: string }
  assert.equal(execJson.ok, true)
  assert.equal(execJson.result.endpointCount, 2)
  assert.deepEqual(execJson.result.exchanges, ['ex-1', 'ex-2'])
  assert.equal(execJson.result.raceOk, 2)

  // Lossless capture preserved unredacted body in recordedExchanges for Stage 2a compiler.
  assert.equal(recordedExchanges.get('ex-1')?.responseBody?.includes(mintedToken), true)
  assert.equal(recordedExchanges.get('ex-2')?.origin, 'http://api.local')
  assert.ok(recordedExchanges.has('ex-3'), 'kovo.race must also capture lossless RecordedRequestExchange')

  // Grey-box assignment must reject kovo.repo at the RPC server allowlist.
  const repoDeniedRes = await execTool.execute({
    code: `
      try {
        await kovo.repo({ action: 'search', query: 'secret' })
        return { denied: false }
      } catch (err) {
        return { denied: true, message: err instanceof Error ? err.message : String(err) }
      }
    `,
  }, {} as never, { abortSignal: rootAbort.signal } as never)
  const repoDenied = JSON.parse(extractText(repoDeniedRes)) as { ok: boolean; result: { denied: boolean; message: string } }
  assert.equal(repoDenied.ok, true)
  assert.equal(repoDenied.result.denied, true)
  assert.match(repoDenied.result.message, /Disallowed PTC RPC operation/i)

  // Feed captured exchanges into submit_exploit_trace -> Stage 2a deterministic compiler -> runKovoVerify.
  const submitRes = await submitTool.execute({
    title: 'Cross-origin token pivot to victim record',
    vulnClass: 'bola',
    exchangeIds: ['ex-1', 'ex-2'],
    terminalExchangeId: 'ex-2',
    attackerPersona: 'member_b',
    reproNotes: 'Minted token on app.local then fetched victim record on api.local.',
  }, {} as never, { abortSignal: rootAbort.signal } as never)
  const submitJson = JSON.parse(extractText(submitRes)) as { confirmed: boolean; compiledBy: string; findingId?: string }
  assert.equal(submitJson.confirmed, true)
  assert.equal(submitJson.compiledBy, 'deterministic')
  assert.equal(submitJson.findingId, 'find-ptc-1')
  assert.equal(confirmedTitle, 'Cross-origin token pivot to victim record')
  assert.equal(verifiedScripts.length, 1)
  assert.ok(verifiedScripts[0]!.includes('/api/mint'))
  assert.ok(verifiedScripts[0]!.includes('/api/records/1'))

  // Clean close unlinks socket & token while preserving hostDir.
  await prepared.close?.()
  assert.equal(existsSync(prepared.ptcRpc.socketPath), false)
  assert.equal(existsSync(prepared.ptcRpc.tokenPath), false)
  assert.equal(existsSync(hostDir), true)
})

test('execute_code resets PtcRpcServer call budget per invocation and closes cleanly in finally; non-Docker falls back to consolidated tools', async t => {
  const hostDir = makeTempDir(t, 'kovo-ptc-budget-')
  const rootAbort = new AbortController()
  const baseOpts = {
    handlers: makeDummyHandlers(),
    storage: makeFakeStorage(),
    runId: 'run-budget',
    assignmentId: 'asg-budget',
    publicOrigins: ['http://app.local'],
    personasPub: [{ handle: 'member_b', role: 'member' }],
    recordedExchanges: new Map<string, RecordedRequestExchange>(),
    hasMountedRepos: false,
    allowWebSearch: false,
    scrub: (v: string) => v,
    rootSignal: rootAbort.signal,
    inlineLimit: 16_384,
    onCompleteIntent: () => undefined,
    runKovoVerify: async () => ({ confirmed: false }),
  }

  const ptcRpc = new PtcRpcServer({
    hostDir,
    maxCallsPerExec: 2,
    dispatch: createPtcExploiterDispatch(baseOpts),
  })
  await ptcRpc.start()
  const clientCode = readPtcClientSource()
  try {
    const tools = buildPtcExploiterToolset({
      ...baseOpts,
      ptcRpc,
      ptcExec: async req => runPtcScript(
        { code: req.code, clientCode, timeoutMs: req.timeoutMs, maxOutputBytes: req.maxOutputBytes },
        hostDir,
        { KOVO_PTC_SOCKET: ptcRpc.socketPath, KOVO_PTC_TOKEN_FILE: ptcRpc.tokenPath },
      ),
    })
    const execTool = tools.find(tool => tool.name === 'execute_code')!

    // First execute_code uses 2/2 calls (hits budget ceiling cleanly).
    const first = JSON.parse(extractText(await execTool.execute({
      code: `
        await kovo.http('GET', '/a', { as: 'member_b' })
        await kovo.http('GET', '/b', { as: 'member_b' })
        let limited = false
        try { await kovo.http('GET', '/c', { as: 'member_b' }) } catch { limited = true }
        return { limited }
      `,
    }, {} as never, { abortSignal: rootAbort.signal } as never))) as { ok: boolean; result: { limited: boolean } }
    assert.equal(first.ok, true)
    assert.equal(first.result.limited, true)
    assert.equal(ptcRpc.callsUsed, 2)

    // Second execute_code must reset call budget and succeed for 2 fresh calls.
    const second = JSON.parse(extractText(await execTool.execute({
      code: `
        const r1 = await kovo.http('GET', '/d', { as: 'member_b' }) as any
        const r2 = await kovo.http('GET', '/e', { as: 'member_b' }) as any
        return { statuses: [r1.status, r2.status] }
      `,
    }, {} as never, { abortSignal: rootAbort.signal } as never))) as { ok: boolean; result: { statuses: number[] } }
    assert.equal(second.ok, true)
    assert.deepEqual(second.result.statuses, [200, 200])
    assert.equal(ptcRpc.callsUsed, 2)
  } finally {
    await ptcRpc.close()
  }
  assert.equal(existsSync(ptcRpc.socketPath), false)
  assert.equal(existsSync(ptcRpc.tokenPath), false)

  // Non-Docker session (no ptcExec / ptcHostDir) falls back gracefully to consolidated JSON tools.
  const fallback = await prepareExploiterSession({
    handlers: makeDummyHandlers(),
    storage: makeFakeStorage(),
    runId: 'run-fallback',
    assignmentId: 'asg-fallback',
    runAllowWebSearch: false,
    publicOrigins: ['http://app.local'],
    personasPub: [{ handle: 'member_b', roleLabel: 'member', originAllowlist: ['http://app.local'] }],
    recordedExchanges: new Map(),
    mountedRepos: [],
    userPromptInput: {
      goal: 'Fallback test',
      step: { id: 's-fb', title: 'Fallback', hypothesis: 'Non-docker fallback', category: 'A01:2021' },
      origins: ['http://app.local'], capabilityTier: 2, maxTurns: 8,
    },
    runKovoVerify: async () => ({ confirmed: false }),
    proofWriterDeps: {} as never,
    onProofConfirmed: () => undefined,
    onToolExecuted: () => undefined,
    env: { KOVO_EXPLOITER_PTC: '1' },
    workerSession: {},
  })
  assert.equal(fallback.mode, 'consolidated')
  assert.equal(fallback.ptcRpc, undefined)
  const fallbackTools = fallback.session.overrideTools({
    scrubbers: { scrubForDisplay: v => v, scrubExact: v => v },
    signal: rootAbort.signal,
    inlineLimit: 16_384,
    onCompleteIntent: () => undefined,
    specSubmission: {},
  })
  assert.equal(fallbackTools.length, 11)
  assert.equal(fallbackTools.some(tool => tool.name === 'http'), true)
  assert.equal(fallbackTools.some(tool => tool.name === 'execute_code'), false)
})

test('benchmark-multihop forwards KOVO_EXPLOITER_PTC and tracks it in effectiveConfigHash', () => {
  const envBase = buildMultihopCellEnv({})
  const envPtc = buildMultihopCellEnv({ KOVO_DECOUPLED_PROOF_PIPELINE: '1', KOVO_EXPLOITER_PTC: '1' })
  assert.equal(envBase.KOVO_BENCH_MODE, '1')
  assert.equal(envBase.KOVO_EXPLOITER_PTC, undefined)
  assert.equal(envPtc.KOVO_BENCH_MODE, '1')
  assert.equal(envPtc.KOVO_DECOUPLED_PROOF_PIPELINE, '1')
  assert.equal(envPtc.KOVO_EXPLOITER_PTC, '1')

  const common = {
    observed: {
      environment: 'local-lab',
      environmentMode: 'ephemeral_lab',
      tier: 3,
      approvalPolicy: 'auto_review',
      deterministicOnly: false,
      wordlistOn: false,
      proofReceiptMode: 'strict',
    },
    deterministicOnly: false,
    environment: 'local-lab',
    approvalPolicy: 'auto_review',
    verifierBackend: 'docker',
    mode: 'grey-box',
  }
  const cfgBase = resolveObservedEffectiveConfigForRunner({ ...common, env: envBase, extra: { allowWebSearch: false } })
  const cfgPtc = resolveObservedEffectiveConfigForRunner({
    ...common,
    env: envPtc,
    extra: { allowWebSearch: false, decoupledProofPipeline: '1', exploiterPtc: '1' },
  })
  assert.equal(cfgPtc.effectiveConfig?.kovoEnv.KOVO_EXPLOITER_PTC, '1')
  assert.notEqual(cfgBase.effectiveConfigHash, cfgPtc.effectiveConfigHash)
})

test('submit_exploit_trace skips Stage 2b Proof-Writer and returns keepChaining guidance on intermediate-capability rejection', async () => {
  let proofWriterCalls = 0
  const recorded = new Map<string, RecordedRequestExchange>([
    ['ex-stub', {
      exchangeId: 'ex-stub',
      origin: 'http://app.local',
      method: 'POST',
      pathAndQuery: '/api/exports',
      persona: 'member_b',
      requestHeaders: { 'content-type': 'application/json' },
      requestBody: '{"scope":"all"}',
      status: 201,
      mediaType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: '{"jobId":"job-42","downloadUrl":"/api/exports/job-42/download"}',
      responseJson: { jobId: 'job-42', downloadUrl: '/api/exports/job-42/download' },
      timestampMs: Date.now(),
    }],
  ])

  const cases = [
    { rejectedBy: 'terminal_impact_unproven', reason: 'stub_only', detail: 'No terminal readback observed.' },
    { rejectedBy: 'oracle', reason: 'insufficient_impact', detail: 'Trace only minted a signed URL / job/export handle (intermediate capability).' },
  ]

  for (const verifyRejection of cases) {
    const rootAbort = new AbortController()
    const tools = buildPtcExploiterToolset({
      handlers: makeDummyHandlers(),
      runId: 'run-stub',
      assignmentId: 'asg-stub',
      publicOrigins: ['http://app.local'],
      personasPub: [{ handle: 'member_b', role: 'member' }],
      recordedExchanges: recorded,
      hasMountedRepos: false,
      allowWebSearch: false,
      scrub: v => v,
      rootSignal: rootAbort.signal,
      inlineLimit: 16_384,
      onCompleteIntent: () => undefined,
      runKovoVerify: async () => ({ confirmed: false, ...verifyRejection }),
      proofWriterDeps: {
        profiles: [{ id: 'p-1', name: 'Stub', provider: 'openai', model: 'gpt-4o-mini', baseUrl: 'http://127.0.0.1:1', apiKey: 'k' } as never],
        beforeCall: () => { proofWriterCalls += 1; throw new Error('Stage 2b Proof-Writer must not be invoked on intermediate-capability rejections') },
      },
      ptcRpc: { resetCallBudget: () => undefined },
      ptcExec: async () => ({ ok: true, result: null, stdout: '', stderr: '', exitCode: 0, durationMs: 1 }),
    })
    const submitTool = tools.find(tool => tool.name === 'submit_exploit_trace')!
    const res = JSON.parse(extractText(await submitTool.execute({
      title: 'Export job handle created',
      vulnClass: 'bola',
      exchangeIds: ['ex-stub'],
      terminalExchangeId: 'ex-stub',
      attackerPersona: 'member_b',
    }, {} as never, { abortSignal: rootAbort.signal } as never))) as {
      confirmed: boolean
      compiledBy: string
      keepChaining?: boolean
      guidance?: string
    }
    assert.equal(res.confirmed, false)
    assert.equal(res.compiledBy, 'deterministic')
    assert.equal(res.keepChaining, true)
    assert.ok(res.guidance?.includes('intermediate capability'))
    assert.ok(res.guidance?.includes('submit_exploit_trace'))
  }
  assert.equal(proofWriterCalls, 0, 'Stage 2b Proof-Writer must be skipped for intermediate-capability rejections')
})

