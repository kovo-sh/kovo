import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { Script } from 'node:vm'
import {
  compileTraceToKovoVerifyScript,
  type ExploitTraceSubmission,
  type RecordedRequestExchange,
} from '../src/server/trace-proof-compiler.ts'

/**
 * Validate that a compiled `export default async function (ctx) { ... }` script is
 * syntactically valid JS/TS and executes cleanly against a mock `kovo_verify` context.
 */
function loadCompiledEntrypoint(script: string): (ctx: Record<string, unknown>) => Promise<unknown> {
  assert.ok(Buffer.byteLength(script, 'utf8') <= 64 * 1024, 'Compiled script must be <= 64 KiB')
  assert.match(script, /^export default async function \(ctx\)/, 'Must export default async function (ctx)')
  const rewritten = script.replace(/^export default\s+/, 'return ')
  // Parse syntax via V8 Script compiler to catch any syntax/escaping errors deterministically.
  new Script(`(function(){ ${rewritten} })`)
  const factory = new Function(rewritten) as () => (ctx: Record<string, unknown>) => Promise<unknown>
  return factory()
}

interface MockCallLog {
  chainArgs: Array<[string, string]>
  controls: string[]
  controlInsideHop: boolean
  readbacks: string[]
  hops: string[]
  edges: Array<Record<string, unknown>>
  stateTransitions: Array<Record<string, unknown>>
  httpCalls: Array<{ target: unknown; opts: Record<string, unknown> }>
  sealCalls: Array<Record<string, unknown>>
  proveArgs: Array<Record<string, unknown>>
}

function createMockCtx(responses: Array<{ status?: number; json?: unknown; headers?: Record<string, string> }>) {
  const log: MockCallLog = {
    chainArgs: [], controls: [], controlInsideHop: false, readbacks: [], hops: [], edges: [], stateTransitions: [], httpCalls: [], sealCalls: [], proveArgs: [],
  }
  let exCounter = 0
  let capCounter = 0
  let hopDepth = 0
  const sendMockHttp = async (target: unknown, opts: Record<string, unknown> = {}, detached = false) => {
    const idx = exCounter
    exCounter += 1
    if (!detached && (opts.arm === 'control' || opts.role === 'control') && hopDepth > 0) log.controlInsideHop = true
    log.httpCalls.push({ target, opts })
    const spec = responses[idx] ?? { status: 200, json: {} }
    return {
      exchangeId: `ex_${exCounter}`,
      status: spec.status ?? 200,
      json: spec.json ?? null,
      headers: spec.headers ?? {},
      body: spec.json ? JSON.stringify(spec.json) : '',
    }
  }
  const ctx = {
    chain(chainId: string, terminalVulnClass: string) {
      log.chainArgs.push([chainId, terminalVulnClass])
      const self = {
        control(targetOrRef: unknown, opts?: Record<string, unknown>) {
          if (targetOrRef && typeof targetOrRef === 'object' && 'exchangeId' in (targetOrRef as Record<string, unknown>)) {
            if (hopDepth > 0) log.controlInsideHop = true
            log.controls.push(String((targetOrRef as { exchangeId: string }).exchangeId))
            return self
          }
          if (hopDepth > 0) log.controlInsideHop = true
          return sendMockHttp(targetOrRef, { ...(opts ?? {}), arm: 'control', role: 'control' }, true).then(ex => {
            log.controls.push(ex.exchangeId)
            return ex
          })
        },
        readback(targetOrRef: unknown, opts?: Record<string, unknown>) {
          if (targetOrRef && typeof targetOrRef === 'object' && 'exchangeId' in (targetOrRef as Record<string, unknown>)) {
            log.readbacks.push(String((targetOrRef as { exchangeId: string }).exchangeId))
            return self
          }
          return sendMockHttp(targetOrRef, { ...(opts ?? {}), arm: 'control', role: 'control' }, true).then(ex => {
            log.readbacks.push(ex.exchangeId)
            return ex
          })
        },
        edge(e: Record<string, unknown>) { log.edges.push(e); return self },
        stateTransition(e: Record<string, unknown>) { log.stateTransitions.push(e); return self },
        async step(target: unknown, opts: Record<string, unknown> = {}) {
          const { hopId, claimedDelta: _cd, ...httpOpts } = opts
          const resolvedHopId = typeof hopId === 'string' && hopId.trim() ? hopId.trim() : `hop_${log.hops.length + 1}`
          log.hops.push(resolvedHopId)
          hopDepth += 1
          try { return await sendMockHttp(target, httpOpts) } finally { hopDepth -= 1 }
        },
        async seal(exchange: { exchangeId: string } | string, selector: Record<string, unknown>) {
          capCounter += 1
          const exchangeId = typeof exchange === 'string' ? exchange : exchange?.exchangeId
          assert.equal(typeof exchangeId, 'string', 'ch.seal must receive an exchange or exchangeId')
          assert.equal(typeof selector.slot, 'string', 'ch.seal must receive non-empty slot')
          const input = { ...selector, exchangeId }
          log.sealCalls.push(input)
          return `cap:hop_${capCounter}:${String(selector.slot)}`
        },
        async hop(hopId: string, _meta: unknown, fn: () => Promise<unknown>) {
          log.hops.push(hopId)
          hopDepth += 1
          try { return await fn() } finally { hopDepth -= 1 }
        },
        async prove(opts: Record<string, unknown>) {
          log.proveArgs.push(opts)
          return { confirmed: true, reason: 'mock_confirmed' }
        },
      }
      return self
    },
    async http_send(target: unknown, opts: Record<string, unknown> = {}) {
      return sendMockHttp(target, opts)
    },
    async seal_capability(input: Record<string, unknown>) {
      capCounter += 1
      log.sealCalls.push(input)
      assert.equal(typeof input.exchangeId, 'string', 'seal_capability must receive single object with exchangeId')
      assert.equal(typeof input.slot, 'string', 'seal_capability must receive non-empty slot')
      return { handle: `cap:hop_${capCounter}:${String(input.slot)}`, exchangeId: String(input.exchangeId) }
    },
    result(input: Record<string, unknown>) {
      return { sdk: 'kovo_verify.ts', ...input, claims: [{ kind: 'composite_receipt' }] }
    },
  }
  return { ctx, log }
}

/** Verify DAG reachability (mirrors composite-receipt validateDagTopology: 0 orphan hops). */
function assertAllHopsReachTerminal(hops: string[], edges: Array<Record<string, unknown>>, terminalHopId: string): void {
  const revAdj = new Map<string, string[]>(hops.map(h => [h, []]))
  for (const e of edges) {
    const from = String(e.fromHopId ?? ''), to = String(e.toHopId ?? '')
    assert.ok(revAdj.has(from) && revAdj.has(to), `Edge ${from}->${to} references unknown hop`)
    assert.notEqual(from, to, `Edge self-loop on ${from}`)
    revAdj.get(to)!.push(from)
  }
  const seen = new Set<string>([terminalHopId])
  const queue = [terminalHopId]
  while (queue.length > 0) {
    for (const prev of revAdj.get(queue.shift()!) ?? []) {
      if (!seen.has(prev)) { seen.add(prev); queue.push(prev) }
    }
  }
  const orphans = hops.filter(h => !seen.has(h))
  assert.deepEqual(orphans, [], `Expected 0 orphan hops reaching ${terminalHopId}, found: ${orphans.join(', ')}`)
}

describe('optd-trace-compiler: compileTraceToKovoVerifyScript', () => {
  it('compiles a 3-hop bearer-token escalation chain with synthesized control and header hygiene', async () => {
    const tok1 = 'eyJhbGciOiJIUzI1NiJ9.stageOneTokenPayload9911.sigA1B2C3'
    const tok2 = 'eyJhbGciOiJIUzI1NiJ9.elevatedAdminPayload8822.sigX9Y8Z7'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'rec_1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/tokens/exchange',
        persona: 'member_a',
        requestHeaders: {
          Host: 'app.example.test',
          'Content-Length': '28',
          Connection: 'keep-alive',
          'Transfer-Encoding': 'chunked',
          'Accept-Encoding': 'gzip, deflate',
          Authorization: 'Bearer ambient_stale_token_should_strip',
          Cookie: 'ambient_sid=strip_me',
          'X-Client-Mode': 'cli',
        },
        requestJson: { scope: 'elevated' },
        status: 200,
        responseJson: { data: { accessToken: tok1 } },
        timestampMs: 1000,
      },
      {
        exchangeId: 'rec_2',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/delegation/mint',
        persona: 'member_a',
        requestHeaders: {
          Host: 'app.example.test',
          Authorization: `Bearer ${tok1}`,
          'Content-Type': 'application/json',
        },
        requestJson: { targetRole: 'admin' },
        status: 200,
        responseJson: { minted: { bearer: tok2 } },
        timestampMs: 2000,
      },
      {
        exchangeId: 'rec_3',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/admin/secrets',
        persona: 'member_a',
        requestHeaders: {
          Host: 'app.example.test',
          Authorization: `Bearer ${tok2}`,
          'Accept-Encoding': 'br',
        },
        status: 200,
        responseJson: { secretCount: 4 },
        timestampMs: 3000,
      },
    ]

    const submission: ExploitTraceSubmission = {
      title: 'Three-hop bearer escalation to admin secrets',
      vulnClass: 'privilege_escalation',
      exchangeIds: ['rec_1', 'rec_2', 'rec_3'],
      terminalExchangeId: 'rec_3',
      attackerPersona: 'member_a',
    }

    const compiled = compileTraceToKovoVerifyScript({
      submission,
      exchanges,
      allowedPersonas: ['member_a', 'admin_b'],
      runOrigin: 'https://app.example.test',
    })

    assert.equal(compiled.ok, true)
    assert.equal(compiled.terminalVulnClass, 'privilege_escalation')
    assert.equal(compiled.controlSynthesized, true)
    assert.equal(compiled.uncompilableReasons.length, 0)
    assert.ok(compiled.script)

    // Verify taint bindings
    assert.deepEqual(
      compiled.inferredBindings.map(b => ({ fromStep: b.fromStep, toStep: b.toStep, kind: b.kind, selector: b.selector, target: b.target })),
      [
        { fromStep: 1, toStep: 2, kind: 'seal', selector: 'data.accessToken', target: 'header:authorization:bearer' },
        { fromStep: 2, toStep: 3, kind: 'seal', selector: 'minted.bearer', target: 'header:authorization:bearer' },
      ],
    )

    // Header hygiene & ChainBuilder v2 syntax: no hop-by-hop headers, raw tokens, legacy ch.hop, ctx.seal_capability, or .handle
    assert.doesNotMatch(compiled.script, /"Host"|"Content-Length"|"Connection"|"Transfer-Encoding"|"Accept-Encoding"/i)
    assert.doesNotMatch(compiled.script, /ambient_stale_token_should_strip|ambient_sid/)
    assert.doesNotMatch(compiled.script, new RegExp(tok1.replace(/\./g, '\\.')))
    assert.doesNotMatch(compiled.script, new RegExp(tok2.replace(/\./g, '\\.')))
    assert.match(compiled.script, /"X-Client-Mode":\s*"cli"/)
    assert.match(compiled.script, /ch\.step\(/)
    assert.match(compiled.script, /ch\.seal\(/)
    assert.doesNotMatch(compiled.script, /ch\.hop\(/)
    assert.doesNotMatch(compiled.script, /ctx\.seal_capability\(/)
    assert.doesNotMatch(compiled.script, /\.handle\b/)

    // Execute generated script against mock VerifyContext
    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 403, json: { error: 'forbidden' } }, // synthesized control
      { status: 200, json: { data: { accessToken: 'fresh_t1' } } },
      { status: 200, json: { minted: { bearer: 'fresh_t2' } } },
      { status: 200, json: { secretCount: 4 } },
    ])
    const res = await fn(ctx) as { title: string }
    assert.equal(res.title, submission.title)
    assert.deepEqual(log.hops, ['step_1', 'step_2', 'step_3'])
    assert.equal(log.controls.length, 1)
    assert.equal(log.httpCalls[0]!.target, '/api/admin/secrets')
    assert.equal(log.httpCalls[0]!.opts.as, 'member_a')
    assert.equal(log.httpCalls[0]!.opts.arm, 'control')
    assert.equal(log.httpCalls[0]!.opts.session, 'ctrl_clean')

    // Step 2 & Step 3 must inject bearer capability AND omit `as`
    assert.deepEqual(log.httpCalls[2]!.opts.capability, { handle: 'cap:hop_1:cap_1', target: 'bearer' })
    assert.equal(log.httpCalls[2]!.opts.as, undefined)
    assert.deepEqual(log.httpCalls[3]!.opts.capability, { handle: 'cap:hop_2:cap_2', target: 'bearer' })
    assert.equal(log.httpCalls[3]!.opts.as, undefined)
    assert.equal(log.sealCalls.length, 2)
    assert.equal(log.sealCalls[0]!.jsonPath, 'data.accessToken')
    assert.equal(log.sealCalls[0]!.kind, 'bearer_token')
    assert.equal(log.sealCalls[1]!.jsonPath, 'minted.bearer')
  })

  it('compiles locationQuery with followRedirects: false, url capability injection, and Set-Cookie capability binding', async () => {
    const authCode = 'oauth_code_9f8e7d6c5b4a3210'
    const sessionCookie = 'sess_opaque_a1b2c3d4e5f6g7h8'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'o1',
        origin: 'https://idp.example.test',
        method: 'GET',
        pathAndQuery: '/oauth/authorize?client_id=web',
        persona: 'user_a',
        status: 302,
        responseHeaders: {
          Location: `https://app.example.test/callback?code=${authCode}&state=ok`,
        },
        timestampMs: 100,
      },
      {
        exchangeId: 'o2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/callback?code=${authCode}&mode=silent`,
        persona: 'user_a',
        status: 200,
        setCookies: [`app_sid=${sessionCookie}; Path=/; HttpOnly`],
        timestampMs: 200,
      },
      {
        exchangeId: 'o3',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/tenant/export',
        requestHeaders: {
          Cookie: `app_sid=${sessionCookie}`,
        },
        status: 200,
        responseJson: { records: 12 },
        timestampMs: 300,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Redirect code to session cookie cross-tenant export',
        vulnClass: 'cross_tenant_data_access',
        exchangeIds: ['o1', 'o2', 'o3'],
        attackerPersona: 'user_a',
      },
      exchanges,
      runOrigin: 'https://app.example.test',
    })

    assert.equal(compiled.ok, true)
    assert.equal(compiled.terminalVulnClass, 'dual_tenant_abac')
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.script, new RegExp(authCode))
    assert.doesNotMatch(compiled.script, new RegExp(sessionCookie))

    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 403 },
      { status: 302, headers: { location: 'https://app.example.test/callback?code=fresh_code' } },
      { status: 200 },
      { status: 200, json: { records: 12 } },
    ])
    await fn(ctx)

    // Multi-origin step 1 passes explicit origin and followRedirects: false
    assert.deepEqual(log.httpCalls[1]!.target, { origin: 'https://idp.example.test', path: '/oauth/authorize?client_id=web' })
    assert.equal(log.httpCalls[1]!.opts.followRedirects, false)
    assert.equal(log.sealCalls[0]!.locationQuery, 'code')

    // Step 2 injects code via target: 'url', queryParam: 'code' and strips literal code from query
    assert.equal(log.httpCalls[2]!.target, '/callback?mode=silent')
    assert.deepEqual(log.httpCalls[2]!.opts.capability, { handle: 'cap:hop_1:cap_1', target: 'url', queryParam: 'code' })
    assert.equal(log.sealCalls[1]!.setCookie, 'app_sid')
    assert.equal(log.sealCalls[1]!.kind, 'cookie')

    // Step 3 injects cookie capability and omits `as`
    assert.deepEqual(log.httpCalls[3]!.opts.capability, { handle: 'cap:hop_2:cap_2', target: 'cookie', cookieName: 'app_sid' })
    assert.equal(log.httpCalls[3]!.opts.as, undefined)
  })

  it('binds dynamic JSON IDs into path segments and request bodies and places control after read-only lookup', async () => {
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'd1',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/orders',
        persona: 'analyst_a',
        status: 200,
        responseJson: { items: [{ id: 'order_847291' }] },
        timestampMs: 100,
      },
      {
        exchangeId: 'd2',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/orders/order_847291/approve?ref=order_847291',
        persona: 'analyst_a',
        requestJson: { orderId: 'order_847291', email: 'newuser@example.test' },
        status: 200,
        responseJson: { approved: true },
        timestampMs: 200,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Dynamic order approval',
        vulnClass: 'forged_settlement',
        exchangeIds: ['d1', 'd2'],
      },
      exchanges,
      runOrigin: 'https://app.example.test',
    })

    assert.equal(compiled.ok, true)
    assert.equal(compiled.terminalVulnClass, 'forged_settlement')
    assert.equal(compiled.controlSynthesized, true)
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.script, /order_847291/)
    assert.ok(compiled.inferredBindings.some(b => b.kind === 'var' && b.selector === 'items[0].id' && b.target === 'path'))
    assert.ok(compiled.inferredBindings.some(b => b.kind === 'var' && b.selector === 'items[0].id' && b.target === 'query:ref'))
    assert.ok(compiled.inferredBindings.some(b => b.kind === 'var' && b.selector === 'items[0].id' && b.target === 'body:orderId'))
    assert.ok(compiled.warnings.some(w => /read-only hop/i.test(w)))
    assert.ok(compiled.warnings.some(w => /unique-creation field/i.test(w)))

    // Execute with a DIFFERENT dynamic order ID to prove Attempt 2 replay works without hardcoded IDs!
    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 200, json: { items: [{ id: 'order_999999' }] } }, // step_1 read-only lookup
      { status: 403, json: { error: 'denied' } }, // control placed after step_1 with fresh ID!
      { status: 200, json: { approved: true } }, // step_2 terminal
    ])
    await fn(ctx)

    assert.equal(log.httpCalls[0]!.target, '/api/orders')
    assert.equal(log.httpCalls[1]!.target, '/api/orders/order_999999/approve?ref=order_999999')
    assert.equal(log.httpCalls[1]!.opts.arm, 'control')
    assert.equal(log.httpCalls[1]!.opts.role, 'control')
    assert.equal(log.httpCalls[1]!.opts.session, 'ctrl_clean')
    assert.equal(log.controlInsideHop, false)
    assert.deepEqual(log.httpCalls[1]!.opts.body, { orderId: 'order_999999', email: 'newuser@example.test' })
    assert.equal(log.httpCalls[2]!.target, '/api/orders/order_999999/approve?ref=order_999999')
    // Dynamic >=6-char JSON ID must STILL be sealed & wired via explicit value_binding edge!
    assert.equal(log.sealCalls.length, 1)
    assert.equal(log.sealCalls[0]!.jsonPath, 'items[0].id')
    assert.deepEqual(log.edges, [{ kind: 'value_binding', fromHopId: 'step_1', toHopId: 'step_2', capabilityHandle: 'cap:hop_1:cap_1' }])
    assertAllHopsReachTerminal(log.hops, log.edges, 'step_2')
  })

  it('supports custom header sealing, explicit control/readback, vulnClass normalization, and uncompilable inputs', async () => {
    const apiKey = 'ak_live_998877665544332211'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'ctrl_0',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/billing/ledger',
        persona: 'viewer_a',
        status: 403,
        timestampMs: 50,
      },
      {
        exchangeId: 'h1',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/keys/peek',
        persona: 'viewer_a',
        status: 200,
        responseHeaders: { 'X-Internal-Key': apiKey },
        timestampMs: 100,
      },
      {
        exchangeId: 'h2',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/billing/ledger',
        requestHeaders: { 'X-Api-Key': apiKey },
        requestJson: { credit: 500 },
        status: 200,
        timestampMs: 200,
      },
      {
        exchangeId: 'rb_1',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: '/api/billing/ledger',
        persona: 'viewer_a',
        status: 200,
        responseJson: { balance: 1500 },
        timestampMs: 300,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Header capability ledger overcredit',
        vulnClass: 'ledger_overcredit',
        oracleFamily: 'economic_conservation',
        exchangeIds: ['ctrl_0', 'h1', 'h2', 'rb_1'],
        controlExchangeId: 'ctrl_0',
        terminalExchangeId: 'h2',
        readbackExchangeId: 'rb_1',
      },
      exchanges,
      runOrigin: 'https://app.example.test',
    })

    assert.equal(compiled.ok, true)
    assert.equal(compiled.controlSynthesized, false)
    assert.equal(compiled.terminalVulnClass, 'ledger_overcredit')
    assert.ok(compiled.script)

    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 403 },
      { status: 200, headers: { 'x-internal-key': 'fresh_key' } },
      { status: 200 },
      { status: 200, json: { balance: 1500 } },
    ])
    await fn(ctx)

    assert.equal(log.controls.length, 1)
    assert.equal(log.readbacks.length, 1)
    assert.equal(log.sealCalls[0]!.header, 'X-Internal-Key')
    assert.deepEqual(log.httpCalls[2]!.opts.capability, { handle: 'cap:hop_1:cap_1', target: 'header', headerName: 'X-Api-Key' })
    assert.equal(log.proveArgs[0]!.oracleFamily, 'economic_conservation')

    // Multi-hop cross_tenant_read -> dual_tenant_abac
    const multiTenant = compileTraceToKovoVerifyScript({
      submission: { title: 'Cross tenant read', vulnClass: 'cross_tenant_read', exchangeIds: ['h1', 'h2'] },
      exchanges,
    })
    assert.equal(multiTenant.terminalVulnClass, 'dual_tenant_abac')

    // Unrecognized vulnClass still produces draft script with warning
    const unknownCls = compileTraceToKovoVerifyScript({
      submission: { title: 'Weird finding', vulnClass: 'custom_made_up_bug', exchangeIds: ['h1'] },
      exchanges,
    })
    assert.equal(unknownCls.ok, true)
    assert.equal(unknownCls.terminalVulnClass, 'broken_access_control')
    assert.ok(unknownCls.warnings.some(w => /Unrecognized vulnClass/i.test(w)))

    // Empty exchanges -> ok: false
    const empty = compileTraceToKovoVerifyScript({
      submission: { title: 'Empty', vulnClass: 'broken_access_control', exchangeIds: [] },
      exchanges: [],
    })
    assert.equal(empty.ok, false)
    assert.equal(empty.script, undefined)
    assert.ok(empty.uncompilableReasons.length > 0)

    // Missing terminal exchange -> ok: false
    const missingTerm = compileTraceToKovoVerifyScript({
      submission: { title: 'Missing terminal', vulnClass: 'broken_access_control', exchangeIds: ['h1'], terminalExchangeId: 'nope' },
      exchanges,
    })
    assert.equal(missingTerm.ok, false)
    assert.equal(missingTerm.script, undefined)
    assert.ok(missingTerm.uncompilableReasons[0]!.includes('nope'))
  })

  it('compiles a 4-hop POST -> GET job -> GET url -> GET download chain with sealed value_binding edges on every hop and 0 orphans', async () => {
    const jobId = 'job_exp_884422'
    const sig = '9f8e7d6c5b4a3210fedcba98'
    const signedUrl = `https://storage.example.test/files/export/org_a/report.csv?tenant=org_a&sig=${sig}&job=${jobId}`

    const baseExchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'e1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/v1/orgs/org_a/exports',
        persona: 'member_a',
        status: 202,
        responseJson: { jobId, tenant: 'org_a' },
        timestampMs: 100,
      },
      {
        exchangeId: 'e2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}`,
        persona: 'member_a',
        status: 200,
        responseJson: { job: { id: jobId, status: 'completed' } },
        timestampMs: 200,
      },
      {
        exchangeId: 'e3',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/exports/${jobId}/url`,
        persona: 'member_a',
        status: 200,
        responseJson: { jobId, signedUrl },
        timestampMs: 300,
      },
      {
        exchangeId: 'e4',
        origin: 'https://storage.example.test',
        method: 'GET',
        pathAndQuery: `/files/export/org_a/report.csv?tenant=org_a&sig=${sig}&job=${jobId}`,
        persona: 'member_a',
        status: 200,
        responseBody: 'acct,balance\n1,9999\n',
        timestampMs: 400,
      },
    ]

    // Variant A: exact signedUrl download (step_1 -> step_2 -> step_3 -> step_4)
    const compiledExact = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Four-hop async export signed url download',
        vulnClass: 'cross_tenant_data_access',
        exchangeIds: ['e1', 'e2', 'e3', 'e4'],
        terminalExchangeId: 'e4',
        attackerPersona: 'member_a',
      },
      exchanges: baseExchanges,
      runOrigin: 'https://app.example.test',
    })

    assert.equal(compiledExact.ok, true)
    assert.ok(compiledExact.script)
    assert.doesNotMatch(compiledExact.script, new RegExp(jobId))
    assert.doesNotMatch(compiledExact.script, new RegExp(sig))

    const fnExact = loadCompiledEntrypoint(compiledExact.script)
    const { ctx: ctxExact, log: logExact } = createMockCtx([
      { status: 403, json: { error: 'denied' } }, // clean synthesized control
      { status: 202, json: { jobId: 'job_live_556677' } },
      { status: 200, json: { job: { id: '[redacted:cap:hop_1:cap_1]', status: 'completed' } } },
      { status: 200, json: { jobId: '[redacted:cap:hop_1:cap_1]', signedUrl: 'https://storage.example.test/files/export/org_a/report.csv?sig=liveSig998877665544' } },
      { status: 200, json: { ok: true } },
    ])
    await fnExact(ctxExact)

    assert.deepEqual(logExact.hops, ['step_1', 'step_2', 'step_3', 'step_4'])
    assert.equal(logExact.controlInsideHop, false)
    assert.equal(logExact.httpCalls[0]!.opts.arm, 'control')
    assert.equal(logExact.httpCalls[0]!.opts.role, 'control')
    assert.equal(logExact.httpCalls[0]!.opts.session, 'ctrl_clean')
    // step_3 must use cap_2 string handle directly (NOT redacted ex.json.job.id or cap_2.handle!)
    assert.match(String(logExact.httpCalls[3]!.target), /cap:hop_2:cap_2/)
    // step_4 must consume signed_url via `{ origin, path: cap_3 }` with NO leading '/'
    assert.deepEqual(logExact.httpCalls[4]!.target, { origin: 'https://storage.example.test', path: 'cap:hop_3:cap_3' })
    assert.equal(logExact.sealCalls.length, 3)
    assert.equal(logExact.sealCalls[2]!.kind, 'signed_url')
    assert.deepEqual(
      logExact.edges.map(e => `${e.fromHopId}->${e.toHopId}:${e.kind}`),
      ['step_1->step_2:value_binding', 'step_2->step_3:value_binding', 'step_3->step_4:value_binding'],
    )
    assertAllHopsReachTerminal(logExact.hops, logExact.edges, 'step_4')

    // Variant B: path-tampered download reusing ?sig= from step_3's signedUrl
    const tamperedExchanges: RecordedRequestExchange[] = [
      ...baseExchanges.slice(0, 3),
      {
        exchangeId: 'e4_tamper',
        origin: 'https://storage.example.test',
        method: 'GET',
        pathAndQuery: `/files/export/org_b/treasury.csv?tenant=org_a&sig=${sig}&job=${jobId}`,
        persona: 'member_a',
        status: 200,
        responseBody: 'secret,42\n',
        timestampMs: 400,
      },
    ]
    const compiledTamper = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Four-hop async export path tamper',
        vulnClass: 'cross_tenant_data_access',
        exchangeIds: ['e1', 'e2', 'e3', 'e4_tamper'],
        terminalExchangeId: 'e4_tamper',
        attackerPersona: 'member_a',
      },
      exchanges: tamperedExchanges,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiledTamper.ok, true)
    assert.ok(compiledTamper.script)
    assert.doesNotMatch(compiledTamper.script, new RegExp(sig))

    const fnTamper = loadCompiledEntrypoint(compiledTamper.script)
    const { ctx: ctxTamper, log: logTamper } = createMockCtx([
      { status: 403 },
      { status: 202, json: { jobId: 'job_live_556677' } },
      { status: 200, json: { job: { id: '[redacted:cap:hop_1:cap_1]' } } },
      { status: 200, json: { jobId: '[redacted:cap:hop_1:cap_1]', signedUrl: 'https://storage.example.test/files/export/org_a/report.csv?tenant=org_a&sig=liveSig998877665544&job=[redacted:cap:hop_1:cap_1]' } },
      { status: 200 },
    ])
    await fnTamper(ctxTamper)

    assert.deepEqual(logTamper.hops, ['step_1', 'step_2', 'step_3', 'step_4'])
    assert.equal(logTamper.controlInsideHop, false)
    assert.ok(logTamper.sealCalls.some(c => c.value === 'liveSig998877665544'), 'step_3 must extract and seal live sig from signedUrl')
    assert.deepEqual(
      logTamper.edges.map(e => `${e.fromHopId}->${e.toHopId}:${e.kind}`),
      ['step_1->step_2:value_binding', 'step_2->step_3:value_binding', 'step_3->step_4:value_binding'],
    )
    assertAllHopsReachTerminal(logTamper.hops, logTamper.edges, 'step_4')
  })

  it('prunes unlinked read-only recon exchanges and handles short numeric IDs and mutating state transitions without fabricating unrelated edges', async () => {
    // 1) Unlinked read-only recon exchange is pruned with warning
    const reconTrace: RecordedRequestExchange[] = [
      { exchangeId: 'r_me', origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/me', persona: 'user_a', status: 200, responseJson: { user: 'alice' }, timestampMs: 10 },
      { exchangeId: 'r_1', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/api/items', persona: 'user_a', status: 201, responseJson: { id: 42 }, timestampMs: 20 },
      { exchangeId: 'r_dead', origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/items/42/status', persona: 'user_a', status: 200, responseJson: { ready: true }, timestampMs: 30 },
      { exchangeId: 'r_2', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/api/items/42/approve', persona: 'user_a', status: 200, responseJson: { approved: true }, timestampMs: 40 },
    ]
    const compiledShort = compileTraceToKovoVerifyScript({
      submission: { title: 'Short numeric id with recon pruning', vulnClass: 'forged_settlement', exchangeIds: ['r_me', 'r_1', 'r_dead', 'r_2'], terminalExchangeId: 'r_2' },
      exchanges: reconTrace,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiledShort.ok, true)
    assert.ok(compiledShort.script)
    assert.ok(compiledShort.warnings.some(w => /pruned unlinked read-only recon exchange "r_me"/i.test(w)))
    assert.ok(compiledShort.warnings.some(w => /pruned unlinked read-only recon exchange "r_dead"/i.test(w)))

    const fnShort = loadCompiledEntrypoint(compiledShort.script)
    const { ctx: ctxShort, log: logShort } = createMockCtx([
      { status: 403 },
      { status: 201, json: { id: 99 } }, // Attempt 2 fresh numeric ID!
      { status: 200, json: { approved: true } },
    ])
    await fnShort(ctxShort)
    assert.deepEqual(logShort.hops, ['step_1', 'step_2'])
    assert.equal(logShort.httpCalls[2]!.target, '/api/items/99/approve')
    assert.equal(logShort.edges.length, 1)
    assert.equal(logShort.edges[0]!.kind, 'value_binding')
    assert.match(String(logShort.edges[0]!.valueDigest), /^[0-9a-f]{64}$/)
    assertAllHopsReachTerminal(logShort.hops, logShort.edges, 'step_2')

    // 2) Sequential mutating steps sharing a concrete entity get stateTransition; unrelated steps get 0 fabricated edges
    const mutTrace: RecordedRequestExchange[] = [
      { exchangeId: 'm1', origin: 'https://app.example.test', method: 'PATCH', pathAndQuery: '/api/orders/ord_101/rebind', persona: 'user_a', requestJson: { beneficiary: 'attacker' }, status: 200, responseJson: { ok: true }, timestampMs: 10 },
      { exchangeId: 'm2', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/api/orders/ord_101/settle', persona: 'user_a', status: 200, responseJson: { settled: true }, timestampMs: 20 },
    ]
    const compiledMut = compileTraceToKovoVerifyScript({
      submission: { title: 'Order rebind then settle', vulnClass: 'forged_settlement', exchangeIds: ['m1', 'm2'], terminalExchangeId: 'm2' },
      exchanges: mutTrace,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiledMut.ok, true)
    assert.ok(compiledMut.script)
    const fnMut = loadCompiledEntrypoint(compiledMut.script)
    const { ctx: ctxMut, log: logMut } = createMockCtx([{ status: 403 }, { status: 200, json: { ok: true } }, { status: 200, json: { settled: true } }])
    await fnMut(ctxMut)
    assert.equal(logMut.controlInsideHop, false)
    assert.equal(logMut.stateTransitions.length, 1)
    assert.equal(logMut.stateTransitions[0]!.fromHopId, 'step_1')
    assert.equal(logMut.stateTransitions[0]!.toHopId, 'step_2')
    assert.equal(logMut.stateTransitions[0]!.entityId, 'ord_101')
    assertAllHopsReachTerminal(logMut.hops, logMut.stateTransitions, 'step_2')

    // 3) Unrelated mutating + terminal steps MUST prune orphan mutating hop (keeping terminal alone, 0 fabricated edges, 0 orphans)
    const unrelated: RecordedRequestExchange[] = [
      { exchangeId: 'u1', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/api/alpha', persona: 'user_a', status: 200, responseJson: { ok: true }, timestampMs: 10 },
      { exchangeId: 'u2', origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/beta', persona: 'user_a', status: 200, responseJson: { ok: true }, timestampMs: 20 },
    ]
    const compiledUnrel = compileTraceToKovoVerifyScript({
      submission: { title: 'Unrelated hops', vulnClass: 'broken_access_control', exchangeIds: ['u1', 'u2'], terminalExchangeId: 'u2' },
      exchanges: unrelated,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiledUnrel.ok, true)
    assert.ok(compiledUnrel.warnings.some(w => /pruned unreachable exchange "u1"/i.test(w)))
    const { ctx: ctxUnrel, log: logUnrel } = createMockCtx([{ status: 403 }, { status: 200 }])
    await loadCompiledEntrypoint(compiledUnrel.script!)(ctxUnrel)
    assert.deepEqual(logUnrel.hops, ['step_1'])
    assert.equal(logUnrel.httpCalls[1]!.target, '/api/beta')
    assert.equal(logUnrel.edges.length, 0)
    assert.equal(logUnrel.stateTransitions.length, 0)
    assertAllHopsReachTerminal(logUnrel.hops, [...logUnrel.edges, ...logUnrel.stateTransitions], 'step_1')
  })

  it('seals relative signed_url / download keys as kind="signed_url" and emits path: cap_k without leading /', async () => {
    const relDownload = '/api/files/export/download?token=dl_tok_9876543210abcdef'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 's1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/exports',
        persona: 'member_a',
        status: 200,
        responseJson: { downloadHref: relDownload },
        timestampMs: 100,
      },
      {
        exchangeId: 's2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: relDownload,
        persona: 'member_a',
        status: 200,
        responseJson: { rows: 50 },
        timestampMs: 200,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: { title: 'Relative signed URL export', vulnClass: 'cross_tenant_read', exchangeIds: ['s1', 's2'], terminalExchangeId: 's2' },
      exchanges,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.doesNotMatch(compiled.script, /\.handle\b/)
    assert.match(compiled.script, /kind:\s*"signed_url"/)
    assert.match(compiled.script, /path:\s*cap_1\b/)

    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 403 },
      { status: 200, json: { downloadHref: '/api/files/export/download?token=live_fresh_tok' } },
      { status: 200, json: { rows: 50 } },
    ])
    await fn(ctx)

    assert.equal(log.sealCalls.length, 1)
    assert.equal(log.sealCalls[0]!.kind, 'signed_url')
    assert.equal(log.sealCalls[0]!.jsonPath, 'downloadHref')
    // Target is `{ path: "cap:hop_1:cap_1" }` with NO leading '/'
    assert.deepEqual(log.httpCalls[2]!.target, { path: 'cap:hop_1:cap_1' })
    assert.deepEqual(log.edges, [{ kind: 'value_binding', fromHopId: 'step_1', toHopId: 'step_2', capabilityHandle: 'cap:hop_1:cap_1' }])
    assertAllHopsReachTerminal(log.hops, log.edges, 'step_2')
  })

  it('prunes unreachable mutating dead branches via backward reachability and links mutating hops via idx>=1 path, query, and nested JSON entities', async () => {
    // Dead branch: p_dead (POST) -> g_dead (GET) has an edge p_dead->g_dead, but neither reaches terminal!
    // Genuine chain: m_nested (POST nested JSON body entity) -> m_query (PATCH query entity) -> m_path (POST idx=1 path entity, terminal)
    const exchanges: RecordedRequestExchange[] = [
      { exchangeId: 'p_dead', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/api/drafts', persona: 'member_a', status: 201, responseJson: { draftId: 'draft_555111' }, timestampMs: 10 },
      { exchangeId: 'g_dead', origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/api/drafts/draft_555111', persona: 'member_a', status: 200, responseJson: { ok: true }, timestampMs: 20 },
      { exchangeId: 'm_nested', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/api/policies', persona: 'member_a', requestJson: { target: { account_id: 'acct_9042' } }, status: 200, responseJson: { updated: true }, timestampMs: 30 },
      { exchangeId: 'm_query', origin: 'https://app.example.test', method: 'PATCH', pathAndQuery: '/api/payouts?account_id=acct_9042', persona: 'member_a', requestJson: { mode: 'instant' }, status: 200, responseJson: { ok: true }, timestampMs: 40 },
      { exchangeId: 'm_term', origin: 'https://app.example.test', method: 'POST', pathAndQuery: '/acct_9042/settle', persona: 'member_a', status: 200, responseJson: { settled: true }, timestampMs: 50 },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Backward reachability and expanded entity extraction',
        vulnClass: 'forged_settlement',
        exchangeIds: ['p_dead', 'g_dead', 'm_nested', 'm_query', 'm_term'],
        terminalExchangeId: 'm_term',
      },
      exchanges,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.ok(compiled.warnings.some(w => /pruned unreachable exchange "p_dead"/i.test(w)))
    assert.ok(compiled.warnings.some(w => /pruned unlinked read-only recon exchange "g_dead"/i.test(w)))

    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 403 },
      { status: 200, json: { updated: true } },
      { status: 200, json: { ok: true } },
      { status: 200, json: { settled: true } },
    ])
    await fn(ctx)

    assert.deepEqual(log.hops, ['step_1', 'step_2', 'step_3'])
    assert.equal(log.stateTransitions.length, 2)
    assert.deepEqual(
      log.stateTransitions.map(e => `${e.fromHopId}->${e.toHopId}:${e.entityId}`),
      ['step_1->step_2:acct_9042', 'step_2->step_3:acct_9042'],
    )
    assertAllHopsReachTerminal(log.hops, [...log.edges, ...log.stateTransitions], 'step_3')
  })

  it('emits an async wait (and detached setup poll if pruned) after a 202 hop before downstream consumption', async () => {
    const jobId = 'job_async_774411'
    const exchanges: RecordedRequestExchange[] = [
      {
        exchangeId: 'a1',
        origin: 'https://app.example.test',
        method: 'POST',
        pathAndQuery: '/api/v1/renders',
        persona: 'member_a',
        status: 202,
        responseJson: { jobId },
        timestampMs: 100,
      },
      {
        // Pure-status GET poll that does NOT echo jobId -> pruned from DAG hops, emitted as detached setup poll after wait
        exchangeId: 'a_poll',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}/status`,
        persona: 'member_a',
        status: 200,
        responseJson: { status: 'ready' },
        timestampMs: 200,
      },
      {
        exchangeId: 'a2',
        origin: 'https://app.example.test',
        method: 'GET',
        pathAndQuery: `/api/v1/jobs/${jobId}/trace`,
        persona: 'member_a',
        status: 200,
        responseJson: { leakedSecret: 'secret_val_99887766' },
        timestampMs: 300,
      },
    ]

    const compiled = compileTraceToKovoVerifyScript({
      submission: {
        title: 'Async 202 render job trace consumption',
        vulnClass: 'dual_tenant_abac',
        exchangeIds: ['a1', 'a_poll', 'a2'],
        terminalExchangeId: 'a2',
        attackerPersona: 'member_a',
      },
      exchanges,
      runOrigin: 'https://app.example.test',
    })
    assert.equal(compiled.ok, true)
    assert.ok(compiled.script)
    assert.match(compiled.script, /if \(step_1\.status === 202\) await new Promise\(\(r\) => setTimeout\(r, \d+\)\)/)
    assert.match(compiled.script, /if \(step_1\.status === 202\) await ctx\.http_send\(/)
    assert.match(compiled.script, /role:\s*"setup"/)

    const fn = loadCompiledEntrypoint(compiled.script)
    const { ctx, log } = createMockCtx([
      { status: 403 }, // synthesized control
      { status: 202, json: { jobId: 'job_live_991122' } }, // step_1
      { status: 200, json: { status: 'ready' } }, // detached setup poll
      { status: 200, json: { leakedSecret: 'secret_live_1122' } }, // step_2
    ])
    const t0 = Date.now()
    await fn(ctx)
    assert.ok(Date.now() - t0 >= 350, 'Expected compiled script to wait after 202 before downstream consumption')
    assert.deepEqual(log.hops, ['step_1', 'step_2'])
    assert.equal(log.httpCalls[2]!.target, '/api/v1/jobs/job_live_991122/status')
    assert.equal(log.httpCalls[2]!.opts.role, 'setup')
    assert.equal(log.httpCalls[3]!.target, '/api/v1/jobs/job_live_991122/trace')
    assertAllHopsReachTerminal(log.hops, log.edges, 'step_2')
  })
})
