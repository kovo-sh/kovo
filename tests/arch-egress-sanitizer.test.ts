/**
 * Architectural regression tests for the Single Typed Egress Boundary + Raw Kernel Truth + Opaque Handles:
 *   - C-3: `capability.seal` rejects 1-char / short regex/value oracle probes, caps per-exchange seals,
 *     never exposes raw `sha256` / `sha256Prefix` digests to workers (in seal response, transcript.get,
 *     or crypto.* responses), and verifies `value` selectors against sanitized worker-visible content only.
 *   - H-9: Sealing a capability does NOT rewrite raw kernel `TranscriptStore` bytes or corrupt
 *     `buildHostSignedTranscript()` JSON, while worker-facing RPC and LLM/UI egress DO mask it.
 *   - H-10: Sealed capability handles are strictly immutable; re-sealing an existing handle cannot
 *     overwrite its underlying value or forge `value_binding` causal edges.
 *   - H-8: Browser tool result fields (`forms`, `cookieNames`, `localStorageKeys`, `sessionStorageKeys`,
 *     `domSnippet`, `title`, `consoleMessages`, `xhrRequests`, `webSockets`, `exchanges` headers)
 *     scrub vault/persona/jar secrets & sensitive headers uniformly via `EgressSanitizer`.
 *   - M-13 / M-14 + H-25: Exact-value redaction covers raw, URL-encoded (upper/lower/form), base64
 *     (padded/unpadded/URL-encoded), base64url, JSON-escaped, PHP slash-escaped, and HTML-entity forms;
 *     `personaSecrets` registers >= 8 char cookies; M-13 vendor keys & JSON-quoted headers scrub cleanly
 *     without corrupting JSON or mangling model tool-call code (`llm_tool_args`).
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { createServer, request as httpRequest } from 'node:http'
import { createServer as createH2Server, type ServerHttp2Stream } from 'node:http2'
import type { AddressInfo } from 'node:net'
import test from 'node:test'

import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { DerivedCapabilityVault, DerivedCustodyError } from '../src/server/derived-custody.ts'
import {
  EgressSanitizer,
  createEgressSanitizer,
  redactSecrets,
  sanitizeHttpHeaders,
} from '../src/server/egress-sanitizer.ts'
import { personaSecrets, type ResolvedPersona } from '../src/server/persona-vault.ts'
import { redactExactSecrets, sanitizeProviderValue } from '../src/server/provider-stream.ts'
import { redact, redactHeaders, type NamedSecret } from '../src/server/redact.ts'
import { ScopedBrowser, type PlaywrightBrowserLike } from '../src/server/scoped-browser.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface RpcResponse {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResponse> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(Buffer.from(chunk)))
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcResponse) } catch (err) { reject(err) }
      })
    })
    req.once('error', reject)
    req.end(payload)
  })
}

function makeGrant(origin: string, extra: Partial<Grant> = {}): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    ...extra,
  }
}

// ============================================================================
// C-3: Kill capability.seal byte oracle, rate-limit per exchange, hide raw digests
// ============================================================================

test('C-3: capability.seal rejects 1-char/short regex & value oracles, enforces per-exchange rate limit, and hides sha256/sha256Prefix', async (t) => {
  const HIDDEN_SECRET = 'sec_live_hidden_998877665544'
  const HIDDEN_COOKIE = 'ck_session_secret_44332211'
  const VISIBLE_ORDER = 'ord_visible_alpha_7788'
  const SHORT_LEGIT_TOKEN = 'tok987' // 6 chars — valid for structured jsonPath selector

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/leak') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `sid=${HIDDEN_COOKIE}; Path=/; HttpOnly`,
      })
      res.end(JSON.stringify({
        token: HIDDEN_SECRET,
        orderRef: VISIBLE_ORDER,
        shortToken: SHORT_LEGIT_TOKEN,
        tiny: 'a',
        repeat: 'aaaaaaaaaa',
      }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(resolve => target.close(() => resolve())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin),
    runId: 'run-c3-oracle',
    assignmentId: 'assign-c3',
    targetOrigins: [origin],
    maxSealsPerExchange: 8,
  })
  await rpcServer.start()
  t.after(() => rpcServer.close())

  const ex = await rpcCall(rpcServer, 'http.send', { path: '/api/leak', method: 'GET', sessionGroupRole: 'probe' })
  assert.equal(ex.ok, true)
  const exchangeId = (ex.result as { exchangeId: string }).exchangeId

  // 1) 1-char regex byte oracle MUST be rejected
  const regex1Char = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oracle_r1', regex: '"token":"(.)',
  })
  assert.equal(regex1Char.ok, false)
  assert.match(regex1Char.error ?? '', /minimum length/i)

  // 2) Short (< 8 char) regex prefix oracle MUST be rejected
  const regexShort = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oracle_r5', regex: '"token":"(.{5})',
  })
  assert.equal(regexShort.ok, false)
  assert.match(regexShort.error ?? '', /minimum length/i)

  // 3) 1-char value oracle AND hidden-secret value membership oracle MUST be rejected
  const value1Char = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oracle_v1', value: 's',
  })
  assert.equal(value1Char.ok, false)
  const valueHiddenCookie = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oracle_ck', value: HIDDEN_COOKIE,
  })
  assert.equal(valueHiddenCookie.ok, false, 'value selector must not probe hidden Set-Cookie bytes')
  const valueHiddenToken = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oracle_tok', value: HIDDEN_SECRET,
  })
  assert.equal(valueHiddenToken.ok, false, 'value selector must not probe redacted token bytes')

  // 4) Trivial repeated-character value MUST be rejected
  const repeated = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'oracle_rep', jsonPath: '$.repeat',
  })
  assert.equal(repeated.ok, false)
  assert.match(repeated.error ?? '', /repeated-character/i)

  // 5) Legitimate seals (hidden token via jsonPath, short 6-char token via jsonPath) SUCCEED
  //    AND MUST return NO sha256 / sha256Prefix of the raw secret!
  const sealedSecret = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'api_tok', jsonPath: '$.token', kind: 'api_token',
  })
  assert.equal(sealedSecret.ok, true, sealedSecret.error ?? 'expected valid jsonPath seal to pass')
  const secretOut = sealedSecret.result as {
    handle: string
    meta: Record<string, unknown>
    sealExchangeId: string
  }
  assert.equal(secretOut.handle, 'cap:hop_1:api_tok')
  assert.equal('sha256' in secretOut.meta, false, 'worker meta must NOT contain sha256')
  assert.equal('sha256Prefix' in secretOut.meta, false, 'worker meta must NOT contain sha256Prefix')
  assert.equal(secretOut.meta.kind, 'api_token')

  const rawDigest = createHash('sha256').update(HIDDEN_SECRET, 'utf8').digest('hex')
  const rawPrefix = rawDigest.slice(0, 12)
  assert.equal(JSON.stringify(sealedSecret).includes(rawDigest), false, 'raw sha256 must never appear in seal response')
  assert.equal(JSON.stringify(sealedSecret).includes(rawPrefix), false, 'raw sha256Prefix must never appear in seal response')
  assert.equal(JSON.stringify(sealedSecret).includes(HIDDEN_SECRET), false, 'raw secret must never appear in seal response')

  // Transcript readback of sealExchangeId also must NOT expose raw secret sha256!
  const sealTx = await rpcCall(rpcServer, 'transcript', { action: 'get', exchangeId: secretOut.sealExchangeId })
  assert.equal(sealTx.ok, true)
  assert.equal(JSON.stringify(sealTx).includes(rawDigest), false, 'transcript.get of sealExchangeId must not leak raw sha256')
  assert.equal(JSON.stringify(sealTx).includes(rawPrefix), false, 'transcript.get of sealExchangeId must not leak raw sha256Prefix')

  // Host-internal vault STILL retains sha256 for host verification
  assert.equal(rpcServer.capabilityVault.getMeta(secretOut.handle)?.sha256, rawDigest)

  // Legitimate 6-char structured token still passes
  const shortLegit = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'short_tok', jsonPath: '$.shortToken',
  })
  assert.equal(shortLegit.ok, true, shortLegit.error ?? '6-char structured token should pass')

  // 6) Per-exchange rate limit (maxSealsPerExchange: 8 already reached) blocks the 9th attempt
  const rateLimited = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId, hopReceiptId: '1', slot: 'over_cap', value: VISIBLE_ORDER,
  })
  assert.equal(rateLimited.ok, false)
  assert.match(rateLimited.error ?? '', /rate limit exceeded/i)

  // 7) crypto.hmacSign and crypto.jwtSign also hide raw secret digests from workers
  const hmacRes = await rpcCall(rpcServer, 'crypto.hmacSign', {
    secretHandle: secretOut.handle, payload: 'signed-msg', alg: 'sha256',
  })
  assert.equal(hmacRes.ok, true)
  assert.equal(JSON.stringify(hmacRes).includes(rawDigest), false, 'crypto.hmacSign must not leak sourceSecretDigest')
  const jwtRes = await rpcCall(rpcServer, 'crypto.jwtSign', {
    secretHandle: secretOut.handle, claims: { sub: 'u1' }, alg: 'HS256', hopReceiptId: '2', slot: 'minted_jwt',
  })
  assert.equal(jwtRes.ok, true)
  assert.equal(JSON.stringify(jwtRes).includes(rawDigest), false, 'crypto.jwtSign must not leak sourceSecretDigest')
})

// ============================================================================
// H-9: Raw Host-Kernel Truth — sealing NEVER rewrites TranscriptStore bytes
// ============================================================================

test('H-9: sealing a token does NOT rewrite raw kernel TranscriptStore bytes, while worker/LLM egress DOES mask it', async (t) => {
  const ORDER_TOKEN = 'ord_kernel_truth_88776655'
  const TENANT_ID = 'org_alpha_owned_tenant'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/order') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ tenant: TENANT_ID, orderId: ORDER_TOKEN, status: 'open' }))
      return
    }
    if (url.pathname === '/api/followup') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ tenant: TENANT_ID, echoedOrder: ORDER_TOKEN, ok: true }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(resolve => target.close(() => resolve())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin),
    runId: 'run-h9-kernel',
    assignmentId: 'assign-h9',
    targetOrigins: [origin],
  })
  await rpcServer.start()
  t.after(() => rpcServer.close())

  const ex1 = await rpcCall(rpcServer, 'http.send', { path: '/api/order', method: 'GET', sessionGroupRole: 'probe' })
  assert.equal(ex1.ok, true)
  const ex1Id = (ex1.result as { exchangeId: string }).exchangeId
  const kernelBeforeSeal = rpcServer.transcript.body(ex1Id)
  assert.ok(kernelBeforeSeal && kernelBeforeSeal.includes(ORDER_TOKEN) && kernelBeforeSeal.includes(TENANT_ID))

  // Seal both ORDER_TOKEN and TENANT_ID
  const sealOrder = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId: ex1Id, hopReceiptId: '1', slot: 'order_ref', jsonPath: '$.orderId',
  })
  assert.equal(sealOrder.ok, true)
  const sealTenant = await rpcCall(rpcServer, 'capability.seal', {
    exchangeId: ex1Id, hopReceiptId: '1', slot: 'tenant_ref', jsonPath: '$.tenant',
  })
  assert.equal(sealTenant.ok, true)

  // 1) Kernel TranscriptStore body MUST remain 100% unmodified after sealing!
  const kernelAfterSeal = rpcServer.transcript.body(ex1Id)
  assert.equal(kernelAfterSeal, kernelBeforeSeal, 'TranscriptStore body must NOT be rewritten by capability.seal')

  // 2) Subsequent exchange in TranscriptStore MUST also retain unmodified host-internal bytes!
  const ex2 = await rpcCall(rpcServer, 'http.send', { path: '/api/followup', method: 'GET', sessionGroupRole: 'probe' })
  assert.equal(ex2.ok, true)
  const ex2Res = ex2.result as { exchangeId: string; body: string }
  const kernelEx2 = rpcServer.transcript.body(ex2Res.exchangeId) ?? ''
  assert.equal(kernelEx2.includes(ORDER_TOKEN), true, 'subsequent TranscriptStore body must keep raw ORDER_TOKEN')
  assert.equal(kernelEx2.includes(TENANT_ID), true, 'subsequent TranscriptStore body must keep raw TENANT_ID')

  // 3) Host-internal buildHostSignedTranscript() sees valid, unmodified JSON for both exchanges!
  const hostTranscript = rpcServer.buildHostSignedTranscript()
  const entry1 = (hostTranscript.entries ?? []).find(e => e.exchangeId === ex1Id)
  const entry2 = (hostTranscript.entries ?? []).find(e => e.exchangeId === ex2Res.exchangeId)
  assert.deepEqual(entry1?.step.json, { tenant: TENANT_ID, orderId: ORDER_TOKEN, status: 'open' })
  assert.deepEqual(entry2?.step.json, { tenant: TENANT_ID, echoedOrder: ORDER_TOKEN, ok: true })

  // 4) Worker-facing RPC egress (http.send, transcript.get, capability.seal preview) DOES mask both sealed values!
  assert.equal(ex2Res.body.includes(ORDER_TOKEN), false, 'worker http.send egress must mask sealed ORDER_TOKEN')
  assert.equal(ex2Res.body.includes(TENANT_ID), false, 'worker http.send egress must mask sealed TENANT_ID')
  const txGet1 = await rpcCall(rpcServer, 'transcript', { action: 'get', exchangeId: ex1Id })
  assert.equal(txGet1.ok, true)
  assert.equal(JSON.stringify(txGet1).includes(ORDER_TOKEN), false, 'worker transcript.get must mask sealed ORDER_TOKEN')
  assert.equal(JSON.stringify(txGet1).includes(TENANT_ID), false, 'worker transcript.get must mask sealed TENANT_ID')
  assert.equal(JSON.stringify(sealOrder).includes(ORDER_TOKEN), false, 'seal scrubbedPreview must mask sealed ORDER_TOKEN')

  // 5) LLM/UI EgressSanitizer with the vault masks both values cleanly
  const llmEgress = createEgressSanitizer({ capabilityVaults: [rpcServer.capabilityVault] })
  const llmText = llmEgress.redactText(`Summary: tenant=${TENANT_ID} order=${ORDER_TOKEN}`, 'llm_context')
  assert.equal(llmText.includes(ORDER_TOKEN), false)
  assert.equal(llmText.includes(TENANT_ID), false)
})

// ============================================================================
// H-10: Immutable Sealed Capability Handles — prevent overwrite & value_binding forgery
// ============================================================================

test('H-10: re-sealing an existing handle cannot overwrite its secret value or forge value_binding', async (t) => {
  // 1) Direct vault immutability (active AND after revoke)
  const vault = new DerivedCapabilityVault({ runId: 'run-h10-vault' })
  const original = vault.seal({ hopReceiptId: '1', slot: 'tok', rawValue: 'secret_alpha_11111111' })
  assert.throws(
    () => vault.seal({ hopReceiptId: '1', slot: 'tok', rawValue: 'secret_forged_22222222' }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'HANDLE_IMMUTABLE',
  )
  assert.equal(vault.getMeta(original.handle)?.sha256, original.sha256, 'original handle digest must stay untouched')

  vault.revoke(original.handle)
  assert.throws(
    () => vault.seal({ hopReceiptId: '1', slot: 'tok', rawValue: 'secret_post_revoke_3333' }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'HANDLE_IMMUTABLE',
    'revoked handle name must remain permanently immutable',
  )

  // 2) RPC-level overwrite & value_binding forgery attempt fails closed
  const HOP1_VAL = 'hop1_benign_token_11223344'
  const HOP2_VAL = 'hop2_privileged_secret_55667788'
  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.writeHead(200, { 'content-type': 'application/json' })
    if (url.pathname === '/api/hop1') {
      res.end(JSON.stringify({ token: HOP1_VAL }))
      return
    }
    if (url.pathname === '/api/hop2') {
      res.end(JSON.stringify({ token: HOP2_VAL }))
      return
    }
    res.end(JSON.stringify({ auth: req.headers.authorization ?? null }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(resolve => target.close(() => resolve())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const sharedVault = new DerivedCapabilityVault({ runId: 'run-h10-rpc' })
  const rpc1 = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin),
    runId: 'run-h10-rpc',
    assignmentId: 'assign-h10-1',
    targetOrigins: [origin],
    capabilityVault: sharedVault,
  })
  await rpc1.start()
  t.after(() => rpc1.close())

  const h1 = await rpcCall(rpc1, 'http.send', { path: '/api/hop1', method: 'GET', sessionGroupRole: 'probe' })
  const h2 = await rpcCall(rpc1, 'http.send', { path: '/api/hop2', method: 'GET', sessionGroupRole: 'probe' })
  const h1Id = (h1.result as { exchangeId: string }).exchangeId
  const h2Id = (h2.result as { exchangeId: string }).exchangeId

  const firstSeal = await rpcCall(rpc1, 'capability.seal', {
    exchangeId: h1Id, hopReceiptId: '1', slot: 'session_tok', jsonPath: '$.token', kind: 'bearer_token',
  })
  assert.equal(firstSeal.ok, true)
  const handle = (firstSeal.result as { handle: string }).handle
  const originalDigest = sharedVault.getMeta(handle)!.sha256

  // Attacker attempts to overwrite cap:hop_1:session_tok with HOP2_VAL from h2
  const overwriteSeal = await rpcCall(rpc1, 'capability.seal', {
    exchangeId: h2Id, hopReceiptId: '1', slot: 'session_tok', jsonPath: '$.token', kind: 'bearer_token',
  })
  assert.equal(overwriteSeal.ok, false, 'duplicate handle re-seal in same session must fail closed')
  assert.match(overwriteSeal.error ?? '', /immutable|already sealed/i)
  assert.equal(sharedVault.getMeta(handle)?.sha256, originalDigest, 'underlying secret must NOT be overwritten')

  // Host transcript provenance: h2 must NOT have cap:hop_1:session_tok in emittedCapabilities
  const hostTx = rpc1.buildHostSignedTranscript()
  const h2Entry = (hostTx.entries ?? []).find(e => e.exchangeId === h2Id)
  assert.equal(h2Entry?.emittedCapabilities?.includes(handle) ?? false, false)

  // crypto.jwtSign also cannot overwrite cap:hop_1:session_tok
  const jwtOverwrite = await rpcCall(rpc1, 'crypto.jwtSign', {
    secretHandle: handle, claims: { role: 'admin' }, alg: 'HS256', hopReceiptId: '1', slot: 'session_tok',
  })
  assert.equal(jwtOverwrite.ok, false, 'crypto.jwtSign must not overwrite existing handle')
  assert.equal(sharedVault.getMeta(handle)?.sha256, originalDigest)

  // Cross-attempt (Attempt 2) on shared run vault mints a distinct versioned handle instead of overwriting Attempt 1
  const rpc2 = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin),
    runId: 'run-h10-rpc',
    assignmentId: 'assign-h10-2',
    targetOrigins: [origin],
    capabilityVault: sharedVault,
  })
  await rpc2.start()
  t.after(() => rpc2.close())
  const h2Attempt2 = await rpcCall(rpc2, 'http.send', { path: '/api/hop2', method: 'GET', sessionGroupRole: 'probe' })
  const h2Attempt2Id = (h2Attempt2.result as { exchangeId: string }).exchangeId
  const attempt2Seal = await rpcCall(rpc2, 'capability.seal', {
    exchangeId: h2Attempt2Id, hopReceiptId: '1', slot: 'session_tok', jsonPath: '$.token', kind: 'bearer_token',
  })
  assert.equal(attempt2Seal.ok, true, attempt2Seal.error ?? 'Attempt 2 on shared vault should version cleanly')
  const attempt2Handle = (attempt2Seal.result as { handle: string }).handle
  assert.notEqual(attempt2Handle, handle, 'Attempt 2 must mint a distinct handle, never overwrite Attempt 1')
  assert.equal(sharedVault.getMeta(handle)?.sha256, originalDigest, 'Attempt 1 handle remains immutable')
})

// ============================================================================
// H-8: Uniform Browser Egress Sanitization & Structural Header Stripping (H1/H2/Browser)
// ============================================================================

test('H-8: Browser results scrub vault/jar secrets across ALL fields and strip sensitive headers uniformly across HTTP/1, HTTP/2, and Browser', async (t) => {
  const VAULT_SECRET = 'vault_browser_secret_987654321'
  const JAR_COOKIE = 'jar_cookie_secret_1122334455'
  const CANARY_TOKEN = 'kovo-dom-canary-benign-42'

  const target = createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'set-cookie': `app_sid=${JAR_COOKIE}; Path=/`,
      'authorization': `Bearer ${VAULT_SECRET}`,
      'x-auth-token': 'raw_x_auth_token_998877',
      'x-api-key': 'raw_x_api_key_665544',
      'proxy-authorization': 'Basic c2VjcmV0OnBhc3M=',
      'x-csrf-token': 'raw_csrf_token_332211',
      'x-visible-header': 'ok-visible',
    })
    res.end(`<html><title>Leaked ${VAULT_SECRET}</title><body><p>${JAR_COOKIE}</p></body></html>`)
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(resolve => target.close(() => resolve())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  // Mock Playwright browser that returns unredacted secrets in EVERY BrowserVisitResult field
  // (simulating an XSS payload exfiltrating persona/jar secrets into forms, storage keys, cookieNames, console, etc.)
  const mockLaunch = async (): Promise<PlaywrightBrowserLike> => ({
    newContext: async () => {
      let routeHandler: ((route: unknown) => Promise<void> | void) | null = null
      const consoleListeners: Array<(msg: { type(): string; text(): string }) => void> = []
      return {
        addInitScript: async () => {},
        addCookies: async () => {},
        route: async (_pattern, handler) => { routeHandler = handler as (route: unknown) => Promise<void> | void },
        routeWebSocket: async () => {},
        newPage: async () => ({
          on(event, listener) {
            if (event === 'console') consoleListeners.push(listener as (msg: { type(): string; text(): string }) => void)
          },
          goto: async (url: string) => {
            if (routeHandler) {
              await routeHandler({
                request: () => ({
                  url: () => url,
                  method: () => 'GET',
                  headers: () => ({}),
                  postData: () => null,
                  resourceType: () => 'document',
                }),
                abort: async () => {},
                fulfill: async () => {},
              })
            }
            for (const fn of consoleListeners) {
              fn({ type: () => 'error', text: () => `console leak: ${VAULT_SECRET} ${JAR_COOKIE}` })
            }
            return { status: () => 200 }
          },
          waitForTimeout: async () => {},
          url: () => `${origin}/home?leak=${encodeURIComponent(VAULT_SECRET)}`,
          title: async () => `Dashboard ${VAULT_SECRET} ${JAR_COOKIE}`,
          evaluate: (async () => ({
            domHtml: `<div>${VAULT_SECRET} ${JAR_COOKIE}</div>`,
            links: [`/next?t=${VAULT_SECRET}`, `/other?c=${JAR_COOKIE}`],
            forms: [{
              action: `/submit?leak=${VAULT_SECRET}`,
              method: 'POST',
              inputNames: [`field_${JAR_COOKIE}`, `tok_${VAULT_SECRET}`],
            }],
            cookieNames: [`app_sid`, `exfil_${VAULT_SECRET}`, `ck_${JAR_COOKIE}`],
            localStorageKeys: [`ls_${VAULT_SECRET}`, `ls_${JAR_COOKIE}`],
            sessionStorageKeys: [`ss_${VAULT_SECRET}`, `ss_${JAR_COOKIE}`],
            postMessageListeners: {
              count: 1,
              hasOnMessage: true,
              handlers: [{ preview: `fn(${VAULT_SECRET})`, checksOrigin: false }],
              observedEvents: 1,
              canaryHandledWithoutOriginCheck: false,
            },
            canaryTriggered: true,
            canaryDetail: `Canary detail leaked ${VAULT_SECRET}`,
            sinkTraces: [{ sink: 'innerHTML', preview: `sink=${JAR_COOKIE}`, containsCanary: true, timestamp: Date.now() }],
            selectorResult: { selector: '#app', matched: true, count: 1, textPreview: `sel=${VAULT_SECRET}` },
            fetchResult: {
              url: `${origin}/api?s=${VAULT_SECRET}`,
              origin,
              method: 'GET',
              credentials: 'include',
              ok: true,
              status: 200,
              contentType: 'application/json',
              bodyPreview: `{"leaked":"${JAR_COOKIE}"}`,
              bodyBytes: 32,
              error: null,
            },
          })) as unknown as <T>() => Promise<T>,
          close: async () => {},
        }),
        close: async () => {},
      }
    },
    close: async () => {},
  })

  const broker = new RequestBroker()
  const browser = new ScopedBrowser(broker, { launchBrowser: mockLaunch })
  const secrets: NamedSecret[] = [{ value: VAULT_SECRET, placeholder: '[persona:alice:secret]' }]
  const result = await browser.visitPage(
    {
      origin,
      pathAndQuery: '/home',
      session: 'sess-h8',
      canaryToken: CANARY_TOKEN,
      secrets,
    },
    makeGrant(origin, { secrets }),
    AbortSignal.timeout(10_000),
  )

  const serialized = JSON.stringify(result)
  for (const needle of [
    VAULT_SECRET,
    encodeURIComponent(VAULT_SECRET),
    JAR_COOKIE,
    'raw_x_auth_token_998877',
    'raw_x_api_key_665544',
    'c2VjcmV0OnBhc3M=',
    'raw_csrf_token_332211',
  ]) {
    assert.equal(serialized.includes(needle), false, `BrowserVisitResult leaked secret/header: ${needle}`)
  }

  // Verify specific previously-unredacted fields (H-8) were scrubbed
  assert.equal(result.forms[0]!.action.includes(VAULT_SECRET), false)
  assert.equal(result.forms[0]!.inputNames.join(',').includes(JAR_COOKIE), false)
  assert.equal(result.cookieNames.join(',').includes(VAULT_SECRET), false)
  assert.equal(result.localStorageKeys.join(',').includes(VAULT_SECRET), false)
  assert.equal(result.sessionStorageKeys.join(',').includes(JAR_COOKIE), false)
  // Benign canary token is preserved intact
  assert.equal(result.canaryCheck.token, CANARY_TOKEN)
  // Exchange headers stripped uniformly
  assert.equal(result.exchanges[0]!.respHeaders['set-cookie'], '[redacted]')
  assert.equal(result.exchanges[0]!.respHeaders['authorization'], '[redacted]')
  assert.equal(result.exchanges[0]!.respHeaders['x-auth-token'], '[redacted]')
  assert.equal(result.exchanges[0]!.respHeaders['x-api-key'], '[redacted]')
  assert.equal(result.exchanges[0]!.respHeaders['proxy-authorization'], '[redacted]')
  assert.equal(result.exchanges[0]!.respHeaders['x-csrf-token'], '[redacted]')
  assert.equal(result.exchanges[0]!.respHeaders['x-visible-header'], 'ok-visible')

  // Uniform structural header stripping parity across HTTP/1 (`redactHeaders`), HTTP/2, and EgressSanitizer
  const sampleHeaders = {
    Authorization: `Bearer ${VAULT_SECRET}`,
    Cookie: `sid=${JAR_COOKIE}`,
    'Set-Cookie': `sid=${JAR_COOKIE}; HttpOnly`,
    'X-Auth-Token': 'raw_x_auth_token_998877',
    'X-API-Key': 'raw_x_api_key_665544',
    'Proxy-Authorization': 'Basic c2VjcmV0OnBhc3M=',
    'X-CSRF-Token': 'raw_csrf_token_332211',
    'X-Session-Token': 'raw_session_tok_1122',
    'X-Visible': 'keep-me',
  }
  const h1Stripped = redactHeaders(sampleHeaders, secrets)
  const egressStripped = sanitizeHttpHeaders(sampleHeaders, secrets)
  assert.deepEqual(h1Stripped, egressStripped, 'HTTP/1 redactHeaders and EgressSanitizer.sanitizeHttpHeaders must agree identically')
  for (const k of ['Authorization', 'Cookie', 'Set-Cookie', 'X-Auth-Token', 'X-API-Key', 'Proxy-Authorization', 'X-CSRF-Token', 'X-Session-Token']) {
    assert.equal(egressStripped[k], '[redacted]', `${k} must be stripped to [redacted]`)
  }
  assert.equal(egressStripped['X-Visible'], 'keep-me')

  // HTTP/2 parity check via VerifyRpcServer
  const h2Server = createH2Server()
  h2Server.on('stream', (stream: ServerHttp2Stream) => {
    stream.respond({
      ':status': 200,
      'content-type': 'application/json',
      'set-cookie': `sid=${JAR_COOKIE}; HttpOnly`,
      authorization: `Bearer ${VAULT_SECRET}`,
      'x-auth-token': 'raw_x_auth_token_998877',
      'x-api-key': 'raw_x_api_key_665544',
      'proxy-authorization': 'Basic c2VjcmV0OnBhc3M=',
      'x-csrf-token': 'raw_csrf_token_332211',
      'x-session-token': 'raw_session_tok_1122',
      'x-visible': 'keep-me',
    })
    stream.end(JSON.stringify({ ok: true }))
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const h2Origin = `http://127.0.0.1:${(h2Server.address() as AddressInfo).port}`
  t.after(() => new Promise<void>(resolve => h2Server.close(() => resolve())))
  const h2Rpc = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(h2Origin, { secrets }),
    runId: 'run-h8-h2',
    assignmentId: 'assign-h8-h2',
    targetOrigins: [h2Origin],
  })
  await h2Rpc.start()
  t.after(() => h2Rpc.close())
  const h2Res = await rpcCall(h2Rpc, 'http2', { origin: h2Origin, method: 'GET', path: '/h2' })
  assert.equal(h2Res.ok, true, h2Res.error ?? 'h2 failed')
  const h2Headers = (h2Res.result as { headers: Record<string, string> }).headers
  for (const k of ['set-cookie', 'authorization', 'x-auth-token', 'x-api-key', 'proxy-authorization', 'x-csrf-token', 'x-session-token']) {
    assert.equal(h2Headers[k], '[redacted]', `HTTP/2 header ${k} must be stripped to [redacted]`)
  }
  assert.equal(h2Headers['x-visible'], 'keep-me')
})

// ============================================================================
// M-13 / M-14 + H-25: Encodings, cookie registration, vendor/JSON redaction, and tool-arg preservation
// ============================================================================

test('M-13/M-14 + H-25: EgressSanitizer scrubs raw/URL/base64/base64url/JSON/HTML encodings without mangling tool-call code', () => {
  const SECRET = 's3cr3t/val+with=chars&"quote\' 99'
  const SHORT_COOKIE = 'sid98765432' // 11 chars (previously missed by >= 16 cookie threshold!)
  const PROVIDER_KEY = 'inert-provider-key-m14-55667788'

  // M-14: personaSecrets() registers 8..15 char individual cookies too
  const personas = new Map<string, ResolvedPersona>([[
    'alice',
    {
      id: 'p1',
      handle: 'alice',
      roleLabel: 'member',
      originAllowlist: ['https://app.example'],
      authKind: 'cookie',
      headerName: null,
      secret: `theme=dark; sid=${SHORT_COOKIE}`,
      canaryMarkers: [],
    },
  ]])
  const registered = personaSecrets(personas)
  assert.ok(registered.some(s => s.value === SHORT_COOKIE), 'personaSecrets must register >= 8 char cookie values')

  const vault = new DerivedCapabilityVault({ runId: 'run-m14' })
  const CAP_SECRET = 'derived/cap+token=12345678'
  vault.seal({ hopReceiptId: '1', slot: 'cap_tok', rawValue: CAP_SECRET })

  const sanitizer = new EgressSanitizer({
    providerKey: PROVIDER_KEY,
    secrets: [{ value: SECRET, placeholder: '[persona:vault:secret]' }, ...registered],
    capabilityVaults: [vault],
  })

  const variants = [
    SECRET,
    encodeURIComponent(SECRET),
    encodeURIComponent(SECRET).replace(/%[0-9A-F]{2}/g, m => m.toLowerCase()),
    encodeURIComponent(SECRET).replaceAll('%20', '+'),
    Buffer.from(SECRET, 'utf8').toString('base64'),
    Buffer.from(SECRET, 'utf8').toString('base64').replace(/=+$/, ''),
    Buffer.from(SECRET, 'utf8').toString('base64url'),
    JSON.stringify(SECRET).slice(1, -1),
    SECRET.replaceAll('/', '\\/'),
    SECRET.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll("'", '&#39;'),
    SHORT_COOKIE,
    CAP_SECRET,
    encodeURIComponent(CAP_SECRET),
    Buffer.from(CAP_SECRET, 'utf8').toString('base64'),
    Buffer.from(CAP_SECRET, 'utf8').toString('base64url'),
    PROVIDER_KEY,
  ]

  const payload = variants.map((v, i) => `v${i}=${v}`).join('\n')
  const scrubbedExact = sanitizer.redactSecrets(payload)
  for (const variant of variants) {
    assert.equal(scrubbedExact.includes(variant), false, `Exact secret variant leaked: ${variant}`)
  }

  // Standalone redactSecrets() helper matches identically
  const standalone = redactSecrets(`b64url=${Buffer.from(SECRET, 'utf8').toString('base64url')}`, [{ value: SECRET, placeholder: '[p]' }])
  assert.equal(standalone, 'b64url=[p]')

  // H-25: Tool-call arguments & verification code MUST NOT be mangled by keyword heuristics
  const toolCode = [
    "const password = 'probe-password-123';",
    "const token = res.headers['x-csrf-token'];",
    "const secret = 'probe-secret-xyz';",
    "const authorization = 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.';",
  ].join('\n')
  assert.equal(sanitizer.redactText(toolCode, 'llm_tool_args'), toolCode)
  assert.equal(redactExactSecrets(toolCode, PROVIDER_KEY, registered), toolCode)

  const toolCallValue = sanitizeProviderValue(
    {
      type: 'function_call',
      name: 'kovo_verify',
      arguments: JSON.stringify({
        script: toolCode,
        token: 'gn_canary_benign_001',
        leakedSecret: Buffer.from(SECRET, 'utf8').toString('base64url'),
        leakedCookie: SHORT_COOKIE,
        leakedProvider: PROVIDER_KEY,
      }),
    },
    PROVIDER_KEY,
    undefined,
    [{ value: SECRET, placeholder: '[persona:vault:secret]' }, ...registered],
  ) as { arguments: string }
  const parsedArgs = JSON.parse(toolCallValue.arguments) as Record<string, string>
  assert.equal(parsedArgs.script, toolCode, 'H-25: script code must pass through unmodified')
  assert.equal(parsedArgs.token, 'gn_canary_benign_001', 'H-25: benign canary token must pass through unmodified')
  assert.equal(parsedArgs.leakedSecret, '[persona:vault:secret]')
  assert.equal(parsedArgs.leakedCookie, '[persona:alice:secret]')
  assert.equal(parsedArgs.leakedProvider, '[redacted]')

  // M-13: Heuristic redact() catches vendor keys, Rails secret_key_base, and JSON-quoted headers while keeping valid JSON
  const jsonLeak = JSON.stringify({
    Authorization: 'Bearer raw_json_header_bearer_1234',
    Cookie: 'sid=raw_json_cookie_5678',
    secret_key_base: 'rails_master_secret_key_base_9999',
    aws: 'AKIAIOSFODNN7EXAMPLE',
    stripe: 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWx',
    nullable_token: null,
    token_count: 4,
  })
  const redactedJson = JSON.parse(redact(jsonLeak)) as Record<string, unknown>
  assert.equal(redactedJson.Authorization, '[redacted]')
  assert.equal(redactedJson.Cookie, '[redacted]')
  assert.equal(redactedJson.secret_key_base, '[redacted]')
  assert.equal(redactedJson.aws, '[redacted]')
  assert.equal(redactedJson.stripe, '[redacted]')
  assert.equal(redactedJson.nullable_token, null, 'nullable_token must stay null')
  assert.equal(redactedJson.token_count, 4, 'token_count must stay 4')
})
