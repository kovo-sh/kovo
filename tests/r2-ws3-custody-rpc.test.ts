/**
 * WS-3 / Move B Regression Suite — Blind Handle-Only Secret Custody & Kernel Truth Plane
 *
 * Covers:
 *  - C-3:    capability.seal kills raw-byte regex oracle, collapses misses/validation failures
 *            into constant-shape error, enforces run-scoped budget across VerifyRpcServer instances,
 *            and derives meta.kind strictly from validated structural args.
 *  - R2-C-4: crypto.hmacSign returns an opaque sealed derived capability handle (matching jwtSign),
 *            never leaks raw HMAC or digests, injects genuinely on the wire, enforces key entropy
 *            floor & seal budget, and allows raw output only for explicit non-secret literalKey.
 *  - R2-H-4: Redact FULL raw body BEFORE slicing/truncating in capability.seal & exchangeView
 *            (across both 1024-byte and 512 KiB boundaries).
 *  - R2-C-3: composite.verify run-scoped budget, coarse confirmed/rejected worker diagnostics
 *            (byte-identical for matching vs non-matching correlation guesses), and no raw-leaf
 *            correlation binding in recordRequestProvenance.
 *  - R2-C-9: Kernel request plane (pathAndQuery, requestHeaders, rawRequestBody, carrierText) uses
 *            kernel-only sanitization with ZERO [redacted:cap:...] tokens while worker views mask.
 *  - R2-H-8: Capability-injected Authorization/Cookie stamps the real source-capability handle,
 *            role, and tenant provenance on HostFactLog instead of the base persona handle.
 *  - R2-H-22: DooD verify-RPC scratch dir staging under KOVO_CONTAINER_SCRATCH_DIR (never /dev/shm)
 *             and compatibility with resolveDoodMountArg.
 *  - R2-H-27: Oversized/malformed RPC op never interpolated into error message.
 */
import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  DerivedCapabilityVault,
  resetRunCustodyBudgets,
  resolveVerifyRpcScratchRoot,
} from '../src/server/derived-custody.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { resolveDoodMountArg } from '../src/server/worker-backend.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface RpcResp {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(
  server: VerifyRpcServer,
  op: string,
  args: Record<string, unknown> = {},
): Promise<RpcResp> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, (res) => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolve(JSON.parse(data) as RpcResp) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

function makePersona(handle: string, roleLabel: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: handle,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret,
    canaryMarkers: [],
    session: { headerType: 'bearer', value: secret, adapterUsed: 'static' },
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[] = [], secrets: Array<{ value: string; placeholder: string }> = []): Grant {
  const personaMap = new Map(personas.map(p => [p.handle, p]))
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: personaMap,
    secrets,
  }
}

test('C-3: capability.seal kills regex oracle, collapses misses to constant error, enforces run budget across servers, and derives kind only from args', async (t) => {
  const runId = 'run-ws3-c3-oracle'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const HIDDEN_SECRET = 'sec_live_alpha_9911223344'
  const COOKIE_SHAPED = 'sid=abcd9876efgh5432'
  const PLAIN_TOKEN = 'plain_tok_9876efgh5432'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/data') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `auth_ck=${HIDDEN_SECRET}; Path=/; HttpOnly`,
        'x-api-token': 'hdr_tok_776655443322',
      })
      res.end(JSON.stringify({
        secret: HIDDEN_SECRET,
        cookieShaped: COOKIE_SHAPED,
        plainVal: PLAIN_TOKEN,
        tooShort: 'ab',
        repeated: 'aaaaaaaaaaaa',
        nested: { a: 1 },
      }))
      return
    }
    if (url.pathname === '/api/text') {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(`raw secret=${HIDDEN_SECRET}`)
      return
    }
    res.writeHead(404)
    res.end('nope')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [], [{ value: HIDDEN_SECRET, placeholder: '[redacted:target_secret]' }])
  const rpc1 = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a1', targetOrigins: [origin],
    maxSealsPerRun: 14, maxSealsPerEndpoint: 14, maxSealsPerExchange: 20,
  })
  const rpc2 = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a2', targetOrigins: [origin],
    maxSealsPerRun: 14, maxSealsPerEndpoint: 14, maxSealsPerExchange: 20,
  })
  await rpc1.start()
  await rpc2.start()
  t.after(() => Promise.all([rpc1.close(), rpc2.close()]))

  const exJson = await rpcCall(rpc1, 'http.send', { path: '/api/data', method: 'GET' })
  assert.equal(exJson.ok, true)
  const exJsonId = (exJson.result as { exchangeId: string }).exchangeId
  const exText = await rpcCall(rpc1, 'http.send', { path: '/api/text', method: 'GET' })
  assert.equal(exText.ok, true)
  const exTextId = (exText.result as { exchangeId: string }).exchangeId

  // 1) Regex selector produces byte-identical constant error for true vs false lookahead predicates
  const regexTrue = await rpcCall(rpc1, 'capability.seal', {
    exchangeId: exJsonId, hopReceiptId: '1', slot: 'rx_t', regex: '(?="secret":"sec_)"plainVal":"([^"]+)"',
  })
  const regexFalse = await rpcCall(rpc1, 'capability.seal', {
    exchangeId: exJsonId, hopReceiptId: '1', slot: 'rx_f', regex: '(?="secret":"zzz_)"plainVal":"([^"]+)"',
  })
  assert.equal(regexTrue.ok, false)
  assert.equal(regexFalse.ok, false)
  assert.equal(regexTrue.error, regexFalse.error, 'true and false regex predicates must produce byte-identical errors')

  // 2) All extraction & validation misses collapse to the EXACT same constant-shape error
  const missPath = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm1', jsonPath: '$.doesNotExist' })
  const missNonJson = await rpcCall(rpc1, 'capability.seal', { exchangeId: exTextId, hopReceiptId: '1', slot: 'm2', jsonPath: '$.secret' })
  const missShort = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm3', jsonPath: '$.tooShort' })
  const missRepeat = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm4', jsonPath: '$.repeated' })
  const missObject = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm5', jsonPath: '$.nested' })
  const missHeader = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm6', header: 'x-missing' })
  const missCookie = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm7', cookie: 'missing_ck' })
  const missHiddenVal = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'm8', value: HIDDEN_SECRET })
  const errors = [regexTrue, regexFalse, missPath, missNonJson, missShort, missRepeat, missObject, missHeader, missCookie, missHiddenVal].map(r => r.error)
  assert.equal(new Set(errors).size, 1, `all extraction misses must share one constant error, got: ${JSON.stringify([...new Set(errors)])}`)

  // 3) meta.kind is derived strictly from structural args (NEVER rawValue shape)
  const sealCookieShaped = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'k1', jsonPath: '$.cookieShaped' })
  const sealPlain = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'k2', jsonPath: '$.plainVal' })
  const sealCookieSel = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'k3', cookie: 'auth_ck' })
  const sealHdrSel = await rpcCall(rpc1, 'capability.seal', { exchangeId: exJsonId, hopReceiptId: '1', slot: 'k4', header: 'x-api-token' })
  assert.equal(sealCookieShaped.ok, true)
  assert.equal(sealPlain.ok, true)
  assert.equal(sealCookieSel.ok, true)
  assert.equal(sealHdrSel.ok, true)
  assert.equal((sealCookieShaped.result as { meta: { kind: string } }).meta.kind, 'generic_secret', 'rawValue matching cookie=val must NOT flip kind to cookie')
  assert.equal((sealPlain.result as { meta: { kind: string } }).meta.kind, 'generic_secret')
  assert.equal((sealCookieSel.result as { meta: { kind: string } }).meta.kind, 'cookie')
  assert.equal((sealHdrSel.result as { meta: { kind: string } }).meta.kind, 'header_secret')

  // 4) Run-scoped seal budget (14 total already consumed on rpc1!) trips immediately on rpc2 even with a separate vault
  const exRpc2 = await rpcCall(rpc2, 'http.send', { path: '/api/data', method: 'GET' })
  assert.equal(exRpc2.ok, true)
  const overBudget = await rpcCall(rpc2, 'capability.seal', {
    exchangeId: (exRpc2.result as { exchangeId: string }).exchangeId, hopReceiptId: '2', slot: 'over', jsonPath: '$.secret',
  })
  assert.equal(overBudget.ok, false)
  assert.match(overBudget.error ?? '', /budget exceeded/i)
})

test('R2-C-4: crypto.hmacSign returns opaque derived handle (no raw signature/digest), injects validly on wire, enforces entropy & budget, allows non-secret literalKey', async (t) => {
  const runId = 'run-ws3-r2c4-hmac'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const SIGNING_KEY = 'hmac_secret_key_998877665544'
  const PERSONA_TOK = 'persona_bearer_tok_1122334455'
  const PAYLOAD = '{"event":"settle","amount":500}'
  const EXPECTED_SIG = createHmac('sha256', SIGNING_KEY).update(PAYLOAD).digest('hex')
  const EXPECTED_SIG_DIGEST = createHash('sha256').update(EXPECTED_SIG).digest('hex')
  let observedWireSig = ''

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/key') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ signingKey: SIGNING_KEY }))
      return
    }
    if (url.pathname === '/api/webhook') {
      observedWireSig = String(req.headers['x-webhook-signature'] ?? '')
      res.writeHead(observedWireSig === EXPECTED_SIG ? 200 : 403, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ accepted: observedWireSig === EXPECTED_SIG }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const vault = new DerivedCapabilityVault({ runId })
  const weakMeta = vault.seal({ hopReceiptId: 'weak', slot: 'k', rawValue: 'abc123', kind: 'hmac_key' })
  const grant = makeGrant(origin, [makePersona('member_a', 'member (acme)', PERSONA_TOK, origin)])
  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a-hmac', targetOrigins: [origin],
    capabilityVault: vault, maxSealsPerRun: 5,
  })
  await rpc.start()
  t.after(() => rpc.close())

  const keyEx = await rpcCall(rpc, 'http.send', { path: '/api/key', method: 'GET' })
  const keyExId = (keyEx.result as { exchangeId: string }).exchangeId
  const sealed = await rpcCall(rpc, 'capability.seal', {
    exchangeId: keyExId, hopReceiptId: '1', slot: 'hmac_key', jsonPath: '$.signingKey', kind: 'hmac_key',
  })
  assert.equal(sealed.ok, true)
  const keyHandle = (sealed.result as { handle: string }).handle

  // 1) Low-entropy sealed key rejected by entropy floor (consumes budget #2)
  const weakRes = await rpcCall(rpc, 'crypto.hmacSign', { secretHandle: weakMeta.handle, payload: PAYLOAD, alg: 'sha256' })
  assert.equal(weakRes.ok, false)
  assert.match(weakRes.error ?? '', /entropy/i)

  // 2) Valid sealed key returns opaque derivedHandle, NEVER raw signature or signatureDigest (consumes budget #3)
  const hmacRes = await rpcCall(rpc, 'crypto.hmacSign', {
    secretHandle: keyHandle, payload: PAYLOAD, alg: 'sha256', encoding: 'hex', hopReceiptId: '2', slot: 'sig',
  })
  assert.equal(hmacRes.ok, true, hmacRes.error ?? '')
  const hmacOut = hmacRes.result as Record<string, unknown>
  assert.equal(hmacOut.derivedHandle, 'cap:hop_2:sig')
  assert.equal(hmacOut.handle, 'cap:hop_2:sig')
  assert.equal('signature' in hmacOut, false, 'sealed crypto.hmacSign must NEVER return raw signature')
  const serialized = JSON.stringify(hmacOut)
  assert.equal(serialized.includes(EXPECTED_SIG), false, 'raw HMAC signature must never leak in response')
  assert.equal(serialized.includes(EXPECTED_SIG_DIGEST), false, 'signatureDigest must never leak in response')
  assert.equal(serialized.includes(SIGNING_KEY), false, 'raw signing key must never leak in response')

  // Transcript readback must also hide raw signature & signatureDigest
  const txGet = await rpcCall(rpc, 'transcript', { action: 'get', exchangeId: String(hmacOut.exchangeId) })
  assert.equal(txGet.ok, true)
  assert.equal(JSON.stringify(txGet.result).includes(EXPECTED_SIG), false)
  assert.equal(JSON.stringify(txGet.result).includes(EXPECTED_SIG_DIGEST), false)

  // 3) Injecting derivedHandle into outbound HTTP request sends real HMAC on wire & attests crypto derivation
  const webhookRes = await rpcCall(rpc, 'http.send', {
    path: '/api/webhook',
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-webhook-signature': String(hmacOut.derivedHandle) },
    body: PAYLOAD,
  })
  assert.equal(webhookRes.ok, true, webhookRes.error ?? '')
  const webhookOut = webhookRes.result as { status: number; derivedFromCapabilityIds?: string[]; consumedCapabilities?: string[] }
  assert.equal(webhookOut.status, 200)
  assert.equal(observedWireSig, EXPECTED_SIG)
  assert.deepEqual(webhookOut.derivedFromCapabilityIds, [keyHandle])
  assert.ok(webhookOut.consumedCapabilities?.includes('cap:hop_2:sig'))

  // 4) Non-secret worker literalKey returns raw signature (consumes budget #4)
  const litKey = 'public-worker-literal-key-42'
  const litRes = await rpcCall(rpc, 'crypto.hmacSign', { literalKey: litKey, payload: PAYLOAD, alg: 'sha256', encoding: 'hex' })
  assert.equal(litRes.ok, true, litRes.error ?? '')
  assert.equal((litRes.result as { signature: string }).signature, createHmac('sha256', litKey).update(PAYLOAD).digest('hex'))
  assert.equal((litRes.result as { literalKeyUsed: boolean }).literalKeyUsed, true)

  // 5) Secret value passed as literalKey is rejected (consumes budget #5)
  const leakLitRes = await rpcCall(rpc, 'crypto.hmacSign', { literalKey: PERSONA_TOK, payload: PAYLOAD, alg: 'sha256' })
  assert.equal(leakLitRes.ok, false)
  assert.match(leakLitRes.error ?? '', /rejected literalKey/i)

  // 6) Budget exhausted (5/5 used) blocks next crypto.hmacSign call
  const overBudget = await rpcCall(rpc, 'crypto.hmacSign', { secretHandle: keyHandle, payload: PAYLOAD, alg: 'sha256' })
  assert.equal(overBudget.ok, false)
  assert.match(overBudget.error ?? '', /budget exceeded/i)
})

test('R2-H-4: capability.seal and exchangeView redact FULL raw text before slicing across 1024-byte and 512 KiB boundaries', async (t) => {
  const runId = 'run-ws3-r2h4-preview'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const SECRET_1K = 'sec_boundary_1024_XYZZY9876'
  const SECRET_512K = 'sec_boundary_512k_QWERTY1234'
  // Place SECRET_1K so its first half is before byte 1024 and second half is after byte 1024.
  const prefix1k = 'A'.repeat(1000)
  const padTo512k = 'B'.repeat(512 * 1024 - 1080)
  const payloadObj = {
    pad1: prefix1k,
    leak1k: SECRET_1K,
    pad2: padTo512k,
    leak512k: SECRET_512K,
    ok: 'visible_token_12345678',
  }
  const rawJson = JSON.stringify(payloadObj)
  const idx1k = rawJson.indexOf(SECRET_1K)
  const idx512k = rawJson.indexOf(SECRET_512K)
  assert.ok(idx1k < 1024 && idx1k + SECRET_1K.length > 1024, `expected SECRET_1K to cross byte 1024 (idx=${idx1k})`)
  assert.ok(idx512k < 512 * 1024 && idx512k + SECRET_512K.length > 512 * 1024, `expected SECRET_512K to cross 512 KiB (idx=${idx512k})`)

  const target = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(rawJson)
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [], [
    { value: SECRET_1K, placeholder: '[redacted:s1k]' },
    { value: SECRET_512K, placeholder: '[redacted:s512k]' },
  ])
  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant, runId, assignmentId: 'a-h4', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  const ex = await rpcCall(rpc, 'http.send', { path: '/api/big', method: 'GET' })
  assert.equal(ex.ok, true)
  const exRes = ex.result as { exchangeId: string; body: string; bodyPreview: string }
  // Neither full secret nor its prefix (first 8 chars) may appear in exchangeView body or bodyPreview!
  assert.equal(exRes.body.includes(SECRET_1K.slice(0, 8)), false, 'exchangeView.body leaked SECRET_1K prefix')
  assert.equal(exRes.body.includes(SECRET_512K.slice(0, 8)), false, 'exchangeView.body leaked SECRET_512K prefix across 512 KiB slice')
  assert.equal(exRes.bodyPreview.includes(SECRET_1K.slice(0, 8)), false, 'exchangeView.bodyPreview leaked SECRET_1K prefix')

  const seal = await rpcCall(rpc, 'capability.seal', {
    exchangeId: exRes.exchangeId, hopReceiptId: '1', slot: 'benign', jsonPath: '$.ok',
  })
  assert.equal(seal.ok, true)
  const sealJson = JSON.stringify(seal.result)
  assert.equal(sealJson.includes(SECRET_1K.slice(0, 8)), false, 'capability.seal scrubbedPreview leaked SECRET_1K prefix across byte 1024')
  assert.equal(sealJson.includes(SECRET_512K.slice(0, 8)), false, 'capability.seal scrubbedPreview leaked SECRET_512K prefix')
})

test('R2-C-3: composite.verify enforces run budget, returns coarse rejected diagnostics (no leaf oracle), and ignores hidden-secret correlationIds', async (t) => {
  const runId = 'run-ws3-r2c3-comp'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const HIDDEN_LEAF = 'priv_secret_leaf_44556677'
  const target = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ secret: HIDDEN_LEAF, status: 'ok' }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [], [{ value: HIDDEN_LEAF, placeholder: '[redacted:leaf]' }])
  const rpc1 = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a-c3-1', targetOrigins: [origin], maxCompositeVerifiesPerRun: 3,
  })
  const rpc2 = new VerifyRpcServer({
    broker: new RequestBroker(), grant, runId, assignmentId: 'a-c3-2', targetOrigins: [origin], maxCompositeVerifiesPerRun: 3,
  })
  await rpc1.start()
  await rpc2.start()
  t.after(() => Promise.all([rpc1.close(), rpc2.close()]))

  // Worker tries to bind hidden secret leaf via correlationId arg on http.send
  const ex1 = await rpcCall(rpc1, 'http.send', { path: '/api/h1', method: 'GET', correlationId: 'priv_secret' })
  const ex2 = await rpcCall(rpc1, 'http.send', { path: '/api/h2', method: 'GET', correlationId: 'priv_secret' })
  const id1 = (ex1.result as { exchangeId: string }).exchangeId
  const id2 = (ex2.result as { exchangeId: string }).exchangeId

  // Host transcript must NOT record hidden-secret correlationId
  const hostEntry1 = rpc1.buildHostSignedTranscript().entries?.find(e => e.exchangeId === id1)
  assert.equal(hostEntry1?.correlationIds?.includes('priv_secret') ?? false, false, 'hidden secret must not bind into correlationIds')

  const makeGuessReceipt = (guess: string) => ({
    chainId: 'chain-oracle-probe',
    terminalVulnClass: 'auth_bypass',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/api/h1' }, exchangeIds: [id1], claimedDelta: 'Trigger hop.' },
      { hopId: 'hop_2', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/api/h2' }, exchangeIds: [id2], claimedDelta: 'Readback hop.' },
    ],
    causalEdges: [{ kind: 'async_pivot_binding', fromHopId: 'hop_1', toHopId: 'hop_2', correlationId: guess, channel: 'async_job' }],
    terminalImpact: { terminalHopId: 'hop_2', claimedImpact: 'Probe guess.' },
    replayMode: 'fresh_clean_replay',
  })

  // Correct first-char guess vs wrong first-char guess MUST return identical coarse diagnostics!
  const vHit = await rpcCall(rpc1, 'composite.verify', { receipt: makeGuessReceipt('p') })
  const vMiss = await rpcCall(rpc1, 'composite.verify', { receipt: makeGuessReceipt('z') })
  assert.equal(vHit.ok, true)
  assert.equal(vMiss.ok, true)
  const rHit = vHit.result as Record<string, unknown>
  const rMiss = vMiss.result as Record<string, unknown>
  assert.equal(rHit.confirmed, false)
  assert.equal(rMiss.confirmed, false)
  assert.equal(rHit.status, 'rejected')
  assert.equal(rMiss.status, 'rejected')
  assert.equal(rHit.reason, 'composite_verification_rejected')
  assert.equal(rMiss.reason, 'composite_verification_rejected')
  assert.equal('failedStage' in rHit, false, 'RPC response must not expose failedStage')
  assert.equal('verifiedEdges' in rHit, false, 'RPC response must not expose verifiedEdges')
  assert.equal('failedStage' in rMiss, false)
  assert.equal('verifiedEdges' in rMiss, false)

  // Strip verificationId and echoed receipt (which contains the caller's own guess) and compare coarse shape
  const stripCallerFields = (r: Record<string, unknown>) => {
    const { verificationId: _v, claim: _c, ...rest } = r
    return rest
  }
  assert.deepEqual(stripCallerFields(rHit), stripCallerFields(rMiss), 'coarse verdict must be identical for hit vs miss guess')

  // 3rd call succeeds within budget; 4th call on rpc2 (same runId!) trips run budget
  const v3 = await rpcCall(rpc2, 'composite.verify', { receipt: makeGuessReceipt('x') })
  assert.equal(v3.ok, true)
  const v4 = await rpcCall(rpc2, 'composite.verify', { receipt: makeGuessReceipt('y') })
  assert.equal(v4.ok, false)
  assert.match(v4.error ?? '', /budget exceeded/i)
})

test('R2-C-9: kernel request plane (pathAndQuery, requestHeaders, carrierText) stays kernel-only without [redacted:cap:...], while worker views mask', async (t) => {
  const runId = 'run-ws3-r2c9-kernel'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const MARKER = 'marker_reflected_ssti_884422'
  const PERSONA_SEC = 'persona_real_secret_77665544'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/seed') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ marker: MARKER }))
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ echoed: url.searchParams.get('q') ?? '', hdr: req.headers['x-probe'] ?? '' }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [makePersona('alice', 'member (acme)', PERSONA_SEC, origin)])
  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant, runId, assignmentId: 'a-c9', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // 1) Seal the reflected marker M
  const seedEx = await rpcCall(rpc, 'http.send', { path: '/api/seed', method: 'GET', persona: 'alice' })
  const seedId = (seedEx.result as { exchangeId: string }).exchangeId
  const sealRes = await rpcCall(rpc, 'capability.seal', { exchangeId: seedId, hopReceiptId: '1', slot: 'marker', jsonPath: '$.marker' })
  assert.equal(sealRes.ok, true)
  const capHandle = (sealRes.result as { handle: string }).handle

  // 2) Send a request carrying literal M (and another interpolating capHandle) in path, header, and body
  const literalEx = await rpcCall(rpc, 'http.send', {
    path: `/api/echo?q=${MARKER}`,
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-probe': MARKER },
    body: JSON.stringify({ input: MARKER }),
    persona: 'alice',
  })
  assert.equal(literalEx.ok, true)
  const literalOut = literalEx.result as { exchangeId: string; pathAndQuery: string; body: string }

  const inlineEx = await rpcCall(rpc, 'http.send', {
    path: `/api/echo?q=${capHandle}`,
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-probe': capHandle },
    body: JSON.stringify({ input: capHandle }),
    persona: 'alice',
  })
  assert.equal(inlineEx.ok, true)
  const inlineOut = inlineEx.result as { exchangeId: string; pathAndQuery: string; body: string }

  // Worker-facing views MUST mask M
  assert.equal(literalOut.pathAndQuery.includes(MARKER), false, 'worker exchangeView.pathAndQuery must mask sealed M')
  assert.equal(literalOut.body.includes(MARKER), false, 'worker exchangeView.body must mask sealed M')
  assert.equal(inlineOut.pathAndQuery.includes(MARKER), false, 'worker inline exchangeView.pathAndQuery must mask sealed M')
  const txGet = await rpcCall(rpc, 'transcript', { action: 'get', exchangeId: literalOut.exchangeId })
  assert.equal(JSON.stringify(txGet.result).includes(MARKER), false, 'worker transcript.get must mask sealed M')

  // Kernel truth plane (HostFactLog + buildHostSignedTranscript + fromTranscriptStore) MUST retain M and ZERO [redacted:cap:...]!
  const factLog = rpc.buildHostFactLog()
  const storeFactLog = HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: rpc.buildHostSignedTranscript() })
  for (const log of [factLog, storeFactLog]) {
    for (const exId of [literalOut.exchangeId, inlineOut.exchangeId]) {
      const fact = log.getExchange(exId)
      assert.ok(fact, `expected HostExchangeFact for ${exId}`)
      assert.equal(fact.pathAndQuery.includes(MARKER), true, `kernel pathAndQuery must retain M for ${exId}`)
      assert.equal(fact.pathAndQuery.includes('[redacted:cap:'), false, 'kernel pathAndQuery must NEVER contain [redacted:cap:...')
      assert.equal(fact.requestHeaders['x-probe'], MARKER, `kernel requestHeaders must retain M for ${exId}`)
      assert.equal(JSON.stringify(fact.requestHeaders).includes('[redacted:cap:'), false, 'kernel requestHeaders must NEVER contain [redacted:cap:...')
      assert.equal((fact.carrierText ?? '').includes(MARKER), true, `kernel carrierText must retain M for ${exId}`)
      assert.equal((fact.carrierText ?? '').includes('[redacted:cap:'), false, 'kernel carrierText must NEVER contain [redacted:cap:...')
      assert.equal((fact.rawRequestBody ?? '').includes(MARKER), true, `kernel rawRequestBody must retain M for ${exId}`)
      assert.equal((fact.rawRequestBody ?? '').includes(PERSONA_SEC), false, 'persona secret must never appear in kernel request body')
    }
  }
})

test('R2-H-8: capability-injected Authorization/Cookie stamps source-capability handle, role, and tenant provenance instead of base persona', async (t) => {
  const runId = 'run-ws3-r2h8-provenance'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const ADMIN_SESSION_TOK = 'adm_session_secret_99887766'
  const ADMIN_COOKIE_VAL = 'adm_cookie_secret_55443322'
  let seenAuth = ''
  let seenCookie = ''

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/api/admin/rotate') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `admin_sid=${ADMIN_COOKIE_VAL}; Path=/; HttpOnly`,
      })
      res.end(JSON.stringify({ sessionToken: ADMIN_SESSION_TOK }))
      return
    }
    if (url.pathname === '/api/admin/action') {
      seenAuth = String(req.headers.authorization ?? '')
      seenCookie = String(req.headers.cookie ?? '')
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, privileged: true }))
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const grant = makeGrant(origin, [
    makePersona('admin_a', 'admin (acme)', 'tok-admin-acme-1111', origin),
    makePersona('member_b', 'member (beta)', 'tok-member-beta-2222', origin),
  ])
  const rpc = new VerifyRpcServer({ broker: new RequestBroker(), grant, runId, assignmentId: 'a-h8', targetOrigins: [origin] })
  await rpc.start()
  t.after(() => rpc.close())

  // 1) Admin exchange emits a rolling bearer token & session cookie
  const admEx = await rpcCall(rpc, 'http.send', { path: '/api/admin/rotate', method: 'POST', persona: 'admin_a', sessionGroupRole: 'setup' })
  assert.equal(admEx.ok, true)
  const admExId = (admEx.result as { exchangeId: string }).exchangeId

  const sealTok = await rpcCall(rpc, 'capability.seal', {
    exchangeId: admExId, hopReceiptId: '1', slot: 'adm_tok', jsonPath: '$.sessionToken', kind: 'bearer_token',
  })
  const sealCk = await rpcCall(rpc, 'capability.seal', {
    exchangeId: admExId, hopReceiptId: '1', slot: 'adm_ck', cookie: 'admin_sid',
  })
  assert.equal(sealTok.ok, true)
  assert.equal(sealCk.ok, true)
  const tokHandle = (sealTok.result as { handle: string }).handle
  const ckHandle = (sealCk.result as { handle: string }).handle

  // 2) Worker attempts to disguise admin bearer capability under `persona: 'member_b'` (explicit capability arg)
  const probeExplicit = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/action', method: 'POST', persona: 'member_b', capability: { handle: tokHandle, target: 'bearer' }, sessionGroupRole: 'probe',
  })
  assert.equal(probeExplicit.ok, true)
  assert.equal(seenAuth, `Bearer ${ADMIN_SESSION_TOK}`)
  const explicitId = (probeExplicit.result as { exchangeId: string }).exchangeId

  // 3) Worker attempts to disguise admin cookie capability under `persona: 'member_b'` (inline Cookie header)
  const probeCookie = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/action', method: 'POST', persona: 'member_b', headers: { Cookie: `admin_sid=${ckHandle}` }, sessionGroupRole: 'probe',
  })
  assert.equal(probeCookie.ok, true)
  assert.ok(seenCookie.includes(`admin_sid=${ADMIN_COOKIE_VAL}`))
  const cookieId = (probeCookie.result as { exchangeId: string }).exchangeId

  // 4) Derived JWT minted from admin capability inherits admin (acme) provenance when injected
  const mintedJwt = await rpcCall(rpc, 'crypto.jwtSign', {
    secretHandle: tokHandle, claims: { sub: 'escalated' }, alg: 'HS256', hopReceiptId: '2', slot: 'adm_jwt',
  })
  assert.equal(mintedJwt.ok, true)
  const jwtHandle = (mintedJwt.result as { derivedHandle: string }).derivedHandle
  const probeJwt = await rpcCall(rpc, 'http.send', {
    path: '/api/admin/action', method: 'POST', persona: 'member_b', capability: jwtHandle, sessionGroupRole: 'probe',
  })
  assert.equal(probeJwt.ok, true)
  const jwtId = (probeJwt.result as { exchangeId: string }).exchangeId

  // Inspect HostFactLog: every capability-injected auth exchange MUST stamp the capability handle + admin (acme) provenance!
  const factLog = rpc.buildHostFactLog()
  const fExplicit = factLog.getExchange(explicitId)!
  assert.equal(fExplicit.actor, tokHandle, 'must record capability handle, never base member_b')
  assert.equal(fExplicit.actorRole, 'admin', 'must stamp source-capability role (admin)')
  assert.equal(fExplicit.actorTenant, 'acme', 'must stamp source-capability tenant (acme)')
  assert.equal(fExplicit.actorRoleLabel, 'admin (acme)')
  assert.equal(fExplicit.ambientAuth, 'bearer')
  assert.equal(JSON.stringify(fExplicit.requestHeaders).includes('[redacted:cap:'), false)

  const fCookie = factLog.getExchange(cookieId)!
  assert.equal(fCookie.actor, ckHandle, 'must record cookie capability handle, never base member_b')
  assert.equal(fCookie.actorRole, 'admin')
  assert.equal(fCookie.actorTenant, 'acme')
  assert.equal(fCookie.actorRoleLabel, 'admin (acme)')
  assert.equal(fCookie.ambientAuth, 'cookie')

  const fJwt = factLog.getExchange(jwtId)!
  assert.equal(fJwt.actor, jwtHandle, 'must record derived JWT handle, never base member_b')
  assert.equal(fJwt.actorRole, 'admin', 'derived JWT must inherit source admin role provenance')
  assert.equal(fJwt.actorTenant, 'acme', 'derived JWT must inherit source acme tenant provenance')
})

test('R2-H-22 & R2-H-27: DooD scratch dir mounts cleanly via resolveDoodMountArg and oversized op is not echoed', async (t) => {
  const scratchRoot = mkdtempSync(join(tmpdir(), 'kovo-ws3-dood-'))
  t.after(() => rmSync(scratchRoot, { recursive: true, force: true }))

  const prevContainer = process.env.KOVO_CONTAINER_SCRATCH_DIR
  const prevVolume = process.env.KOVO_WORKER_SCRATCH_VOLUME
  const prevHost = process.env.KOVO_HOST_SCRATCH_DIR
  t.after(() => {
    if (prevContainer === undefined) delete process.env.KOVO_CONTAINER_SCRATCH_DIR
    else process.env.KOVO_CONTAINER_SCRATCH_DIR = prevContainer
    if (prevVolume === undefined) delete process.env.KOVO_WORKER_SCRATCH_VOLUME
    else process.env.KOVO_WORKER_SCRATCH_VOLUME = prevVolume
    if (prevHost === undefined) delete process.env.KOVO_HOST_SCRATCH_DIR
    else process.env.KOVO_HOST_SCRATCH_DIR = prevHost
  })

  // 1) Pure helper resolves '/scratch' default when DooD volume/host env is set without explicit container scratch
  assert.equal(resolveVerifyRpcScratchRoot({ KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch' }), '/scratch')
  assert.equal(resolveVerifyRpcScratchRoot({ KOVO_HOST_SCRATCH_DIR: '/var/lib/kovo/scratch' }), '/scratch')
  assert.equal(resolveVerifyRpcScratchRoot({}), null)
  assert.throws(() => resolveVerifyRpcScratchRoot({ KOVO_CONTAINER_SCRATCH_DIR: '/' }), /must not be root/)
  assert.throws(() => resolveVerifyRpcScratchRoot({ KOVO_CONTAINER_SCRATCH_DIR: '../escape' }), /Invalid KOVO_CONTAINER_SCRATCH_DIR/)

  // 2) Live VerifyRpcServer stages socket dir inside KOVO_CONTAINER_SCRATCH_DIR (never /dev/shm) and passes resolveDoodMountArg
  process.env.KOVO_CONTAINER_SCRATCH_DIR = scratchRoot
  process.env.KOVO_WORKER_SCRATCH_VOLUME = 'kovo_worker_scratch'
  delete process.env.KOVO_HOST_SCRATCH_DIR

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(), grant: makeGrant('http://127.0.0.1:9999'),
    runId: 'run-ws3-dood', assignmentId: 'a-dood', targetOrigins: ['http://127.0.0.1:9999'],
  })
  await rpc.start()
  t.after(() => rpc.close())

  assert.equal(dirname(rpc.hostDir), scratchRoot)
  assert.equal(rpc.hostDir.startsWith('/dev/shm'), false, 'DooD RPC hostDir must NEVER be under /dev/shm')
  const mountArg = resolveDoodMountArg(rpc.hostDir, '/kovo-rpc', { env: process.env })
  assert.match(mountArg, /^type=volume,source=kovo_worker_scratch,target=\/kovo-rpc,volume-subpath=kovo-verify-rpc-/)

  // 3) R2-H-27: Oversized untrusted `op` with repeated PEM markers fails fast without echoing raw `op`
  const hugeOp = '-----BEGIN RSA PRIVATE KEY-----\n'.repeat(2000)
  const badOpRes = await rpcCall(rpc, hugeOp, {})
  assert.equal(badOpRes.ok, false)
  assert.equal(badOpRes.error, 'Unsupported verification RPC operation: <invalid>')
})
