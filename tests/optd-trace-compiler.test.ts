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
  readbacks: string[]
  hops: string[]
  httpCalls: Array<{ target: unknown; opts: Record<string, unknown> }>
  sealCalls: Array<Record<string, unknown>>
  proveArgs: Array<Record<string, unknown>>
}

function createMockCtx(responses: Array<{ status?: number; json?: unknown; headers?: Record<string, string> }>) {
  const log: MockCallLog = {
    chainArgs: [], controls: [], readbacks: [], hops: [], httpCalls: [], sealCalls: [], proveArgs: [],
  }
  let exCounter = 0
  let capCounter = 0
  const ctx = {
    chain(chainId: string, terminalVulnClass: string) {
      log.chainArgs.push([chainId, terminalVulnClass])
      return {
        control(ref: { exchangeId: string }) { log.controls.push(ref.exchangeId); return this },
        readback(ref: { exchangeId: string }) { log.readbacks.push(ref.exchangeId); return this },
        async hop(hopId: string, _meta: unknown, fn: () => Promise<unknown>) {
          log.hops.push(hopId)
          return fn()
        },
        async prove(opts: Record<string, unknown>) {
          log.proveArgs.push(opts)
          return { confirmed: true, reason: 'mock_confirmed' }
        },
      }
    },
    async http_send(target: unknown, opts: Record<string, unknown> = {}) {
      const idx = exCounter
      exCounter += 1
      log.httpCalls.push({ target, opts })
      const spec = responses[idx] ?? { status: 200, json: {} }
      return {
        exchangeId: `ex_${exCounter}`,
        status: spec.status ?? 200,
        json: spec.json ?? null,
        headers: spec.headers ?? {},
        body: spec.json ? JSON.stringify(spec.json) : '',
      }
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

    // Header hygiene: no hop-by-hop headers or raw tokens in compiled output
    assert.doesNotMatch(compiled.script, /"Host"|"Content-Length"|"Connection"|"Transfer-Encoding"|"Accept-Encoding"/i)
    assert.doesNotMatch(compiled.script, /ambient_stale_token_should_strip|ambient_sid/)
    assert.doesNotMatch(compiled.script, new RegExp(tok1.replace(/\./g, '\\.')))
    assert.doesNotMatch(compiled.script, new RegExp(tok2.replace(/\./g, '\\.')))
    assert.match(compiled.script, /"X-Client-Mode":\s*"cli"/)

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
    assert.deepEqual(log.httpCalls[1]!.opts.body, { orderId: 'order_999999', email: 'newuser@example.test' })
    assert.equal(log.httpCalls[2]!.target, '/api/orders/order_999999/approve?ref=order_999999')
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
})
