/**
 * Queue #29 regression suite: encapsulated vault auto-binding of literal sealed values.
 *
 *  1. `DerivedCapabilityVault.matchSealedHandlesInRequest` returns only `{ handleId, rawDigest }`
 *     (raw values never leave the vault) and skips short/trivial, expired, run-mismatched and
 *     origin-incompatible entries.
 *  2. `http.send`, `http2`, `race` (every burst exchange) and `async.awaitResult` attest
 *     `consumedCapabilities` + `injectedRequestDigests` when a worker sends the literal sealed
 *     value instead of a `cap:...` placeholder, so `value_binding` verifies.
 *  3. A literal derived JWT (sealed by `crypto.jwtSign`) passed in a header also attests
 *     `derived_crypto_binding`.
 *  4. Control: without a seal, literal values never produce consumed capabilities.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { createServer as createH2Server, type ServerHttp2Stream } from 'node:http2'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORDER_ID = 'ord_7Kq2xZ9mVb41'
const SIGNING_SECRET = 'autobind-signing-key-5566778899'

async function rpcCall(socketPath: string, token: string, nonce: string, op: string, args: Record<string, unknown>): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return await new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath, path: '/rpc', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), [VERIFY_RPC_HEADER]: token, [VERIFY_NONCE_HEADER]: nonce },
    }, (res) => {
      const chunks: Buffer[] = []
      res.on('data', c => chunks.push(Buffer.from(c)))
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) } catch (err) { reject(err) } })
    })
    req.on('error', reject)
    req.end(payload)
  })
}

function makeGrant(origin: string): Grant {
  return {
    canRead: (o: string) => { try { return new URL(o).origin === origin } catch { return o === origin } },
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    audit: () => undefined,
  }
}

async function startFixture() {
  const settled = new Set<string>()
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const send = (status: number, value: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(value))
      }
      if (url.pathname === '/api/orders' && req.method === 'POST') {
        return send(201, { order_id: ORDER_ID, code: 'ab12', state: 'approved', signingKey: SIGNING_SECRET })
      }
      const receipt = /^\/api\/orders\/([^/]+)\/receipt$/.exec(url.pathname)
      if (receipt) {
        const id = decodeURIComponent(receipt[1]!)
        return id === ORDER_ID ? send(200, { id, amountCents: 125000, payee: 'acct-foreign' }) : send(403, { error: 'forbidden' })
      }
      if (url.pathname === '/api/settle' && req.method === 'POST') {
        let parsed: { order_id?: string } = {}
        try { parsed = JSON.parse(body) } catch { /* ignore */ }
        const id = parsed.order_id ?? ''
        if (id !== ORDER_ID) return send(404, { error: 'not_found' })
        // Deliberately racy: first two arrivals both settle.
        if (settled.size >= 2) return send(409, { error: 'already_settled' })
        settled.add(`${settled.size}`)
        return send(200, { settled: true, id })
      }
      if (url.pathname === '/api/status') {
        return send(200, { id: url.searchParams.get('id'), state: 'done', ready: true })
      }
      if (url.pathname === '/api/signed') {
        const sig = String(req.headers['x-signature'] ?? '')
        return send(sig.length > 10 ? 200 : 401, { ok: sig.length > 10 })
      }
      return send(200, { ok: true })
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address() as { port: number }
  return { server, origin: `http://127.0.0.1:${addr.port}` }
}

async function startRpc(origin: string, runId: string, nowFn?: () => number) {
  const hostDir = mkdtempSync(join(tmpdir(), 'kovo-q29-'))
  const vault = new DerivedCapabilityVault({ runId, ...(nowFn ? { now: nowFn } : {}) })
  const rpc = new VerifyRpcServer({
    runId, assignmentId: 'assign-q29', broker: new RequestBroker(), grant: makeGrant(origin),
    targetOrigins: [origin], hostDir, capabilityVault: vault,
  })
  await rpc.start()
  const call = (op: string, args: Record<string, unknown>) => rpcCall(rpc.socketPath, rpc.token, rpc.nonce, op, args)
  const close = async () => { await rpc.close(); rmSync(hostDir, { recursive: true, force: true }) }
  return { rpc, vault, call, close }
}

test('vault.matchSealedHandlesInRequest returns only handle/digest and honors expiry, run, origin and triviality filters', () => {
  let nowMs = 1_700_000_000_000
  const vault = new DerivedCapabilityVault({ runId: 'run-q29-unit', now: () => nowMs })
  const longMeta = vault.seal({ hopReceiptId: '1', slot: 'order_id', rawValue: ORDER_ID })
  vault.seal({ hopReceiptId: '1', slot: 'short', rawValue: 'ab12' })
  vault.seal({ hopReceiptId: '1', slot: 'trivial', rawValue: 'approved' })
  vault.seal({ hopReceiptId: '1', slot: 'repeat', rawValue: '0000000000' })
  const scoped = vault.seal({ hopReceiptId: '1', slot: 'scoped', rawValue: 'scoped-value-123456', allowedOrigins: ['https://a.example'] })
  const spaced = vault.seal({ hopReceiptId: '1', slot: 'spaced', rawValue: 'has space & amp 99' })
  vault.seal({ hopReceiptId: '1', slot: 'expiring', rawValue: 'expiring-value-778899', ttlMs: 1000 })

  const parts = [
    `/api/orders/${ORDER_ID}/receipt?q=ab12&s=approved&z=0000000000`,
    `x=${encodeURIComponent('has space & amp 99')}`,
    '{"v":"scoped-value-123456","e":"expiring-value-778899"}',
  ]
  const hits = vault.matchSealedHandlesInRequest({ runId: 'run-q29-unit', targetOrigin: 'http://127.0.0.1:1', parts })
  assert.deepEqual(hits.map(h => h.handleId).sort(), [longMeta.handle, spaced.handle, 'cap:hop_1:expiring'].sort())
  for (const h of hits) assert.deepEqual(Object.keys(h).sort(), ['handleId', 'rawDigest'])
  assert.equal(hits.find(h => h.handleId === longMeta.handle)!.rawDigest, longMeta.sha256)
  const serialized = JSON.stringify(hits)
  assert.equal(serialized.includes(ORDER_ID), false, 'raw values must never leave the vault')

  // Origin-compatible scoped entry matches only for its allowed origin.
  const scopedHits = vault.matchSealedHandlesInRequest({ targetOrigin: 'https://a.example', parts })
  assert.ok(scopedHits.some(h => h.handleId === scoped.handle))
  assert.equal(vault.matchSealedHandlesInRequest({ parts }).some(h => h.handleId === scoped.handle), false)

  // Expiry, run mismatch, minLength override.
  nowMs += 5000
  assert.equal(vault.matchSealedHandlesInRequest({ parts }).some(h => h.handleId === 'cap:hop_1:expiring'), false)
  assert.deepEqual(vault.matchSealedHandlesInRequest({ runId: 'other-run', parts }), [])
  assert.deepEqual(vault.matchSealedHandlesInRequest({ parts: [] }), [])
  assert.equal(vault.matchSealedHandlesInRequest({ parts, minLength: 64 }).length, 0)
})

test('literal sealed order_id auto-binds on http.send, race (every burst exchange) and async.awaitResult; value_binding verifies', async () => {
  const { server, origin } = await startFixture()
  const { rpc, call, close } = await startRpc(origin, 'run-q29-autobind')
  try {
    // Control: literal value with NO seal never yields consumed capabilities.
    const pre = await call('http.send', { method: 'GET', path: `/api/orders/${ORDER_ID}/receipt`, sessionGroupRole: 'probe' })
    assert.equal(pre.ok, true, pre.error ?? "")
    assert.equal((pre.result as { consumedCapabilities?: string[] }).consumedCapabilities, undefined)

    const ctrl = await call('http.send', { method: 'GET', path: '/api/orders/ord_unknown_0000/receipt', sessionGroupRole: 'control' })
    assert.equal((ctrl.result as { status: number }).status, 403)
    const ctrlId = (ctrl.result as { exchangeId: string }).exchangeId

    const create = await call('http.send', { method: 'POST', path: '/api/orders', body: '{}', headers: { 'content-type': 'application/json' }, sessionGroupRole: 'probe' })
    assert.equal(create.ok, true, create.error ?? "")
    const createId = (create.result as { exchangeId: string }).exchangeId
    const seal = await call('capability.seal', { exchangeId: createId, hopReceiptId: '1', slot: 'order_id', jsonPath: '$.order_id' })
    assert.equal(seal.ok, true, seal.error ?? "")
    const orderHandle = (seal.result as { handle: string }).handle
    assert.equal(orderHandle, 'cap:hop_1:order_id')
    const shortSeal = await call('capability.seal', { exchangeId: createId, hopReceiptId: '1', slot: 'code', jsonPath: '$.code' })
    assert.equal(shortSeal.ok, true, shortSeal.error ?? "")

    // http.send with LITERAL order_id in path (+ short sealed value in query, which must not bind).
    const term = await call('http.send', { method: 'GET', path: `/api/orders/${ORDER_ID}/receipt?code=ab12`, sessionGroupRole: 'probe' })
    assert.equal(term.ok, true, term.error ?? "")
    const termOut = term.result as { exchangeId: string; status: number; consumedCapabilities?: string[]; body: string }
    assert.equal(termOut.status, 200)
    assert.deepEqual(termOut.consumedCapabilities, [orderHandle])
    assert.equal(termOut.body.includes(ORDER_ID), false, 'echoed sealed value must remain scrubbed')

    // race with LITERAL order_id in every body.
    const raceReqs = Array.from({ length: 6 }, () => ({ method: 'POST', path: '/api/settle', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ order_id: ORDER_ID }) }))
    const race = await call('race', { requests: raceReqs })
    assert.equal(race.ok, true, race.error ?? "")
    const raceResults = (race.result as { results: Array<{ exchangeId: string; status: number; consumedCapabilities?: string[] }> }).results
    assert.equal(raceResults.length, 6)
    assert.equal(raceResults.filter(r => r.status === 200).length, 2)
    assert.equal(raceResults.filter(r => r.status === 409).length, 4)
    for (const r of raceResults) assert.deepEqual(r.consumedCapabilities, [orderHandle])

    // prove.race also surfaces per-exchange consumedCapabilities.
    const proveRace = await call('prove.race', { requests: raceReqs.slice(0, 2) })
    assert.equal(proveRace.ok, true, proveRace.error ?? "")
    const proveEx = (proveRace.result as { exchanges: Array<{ consumedCapabilities?: string[] }> }).exchanges
    assert.equal(proveEx.length, 2)
    for (const ex of proveEx) assert.deepEqual(ex.consumedCapabilities, [orderHandle])

    // async.awaitResult with LITERAL value in query.
    const poll = await call('async.awaitResult', {
      pollRequest: { method: 'GET', path: `/api/status?id=${ORDER_ID}` },
      matchPredicate: { status: 200 },
      timeoutMs: 2000, intervalMs: 50, maxAttempts: 5,
    })
    assert.equal(poll.ok, true, poll.error ?? "")
    const pollOut = poll.result as { exchange: { consumedCapabilities?: string[] } }
    assert.deepEqual(pollOut.exchange.consumedCapabilities, [orderHandle])

    // Host-signed transcript records consumedCapabilities + injectedRequestDigests on every burst exchange.
    const transcript = rpc.buildHostSignedTranscript()
    const byId = new Map((transcript.entries ?? []).map(e => [e.exchangeId, e]))
    const preEntry = byId.get((pre.result as { exchangeId: string }).exchangeId)!
    assert.equal(preEntry.consumedCapabilities, undefined)
    for (const id of [termOut.exchangeId, ...raceResults.map(r => r.exchangeId)]) {
      const entry = byId.get(id)!
      assert.deepEqual(entry.consumedCapabilities, [orderHandle])
      assert.ok((entry.injectedRequestDigests ?? []).length > 0)
    }

    // value_binding Hop 1 (order created) -> Hop 2 (race settle burst).
    const raceReceipt = await call('composite.verify', {
      receipt: {
        chainId: 'chain-q29-race-binding',
        terminalVulnClass: 'race_double_spend',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/orders' }, exchangeIds: [createId], producedCapabilities: [orderHandle], claimedDelta: 'Created order and sealed order_id.' },
          { hopId: 'hop_2', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/settle' }, exchangeIds: raceResults.map(r => r.exchangeId), consumedCapabilities: [orderHandle], claimedDelta: 'Concurrent settle burst on the same order.' },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: orderHandle }],
        terminalImpact: { terminalHopId: 'hop_2', summary: 'Order settled twice.', terminalExchangeId: raceResults.find(r => r.status === 200)!.exchangeId, preChainControlExchangeIds: [ctrlId] },
        replayMode: 'fresh_clean_replay',
      },
    })
    assert.equal(raceReceipt.ok, true, raceReceipt.error ?? "")
    const raceVerdict = raceReceipt.result as { failedStage?: string; reason: string; verifiedEdges: Array<{ kind: string; verified: boolean }> }
    assert.notEqual(raceVerdict.failedStage, 'edge_binding', raceVerdict.reason)
    assert.equal(raceVerdict.verifiedEdges.find(e => e.kind === 'value_binding')?.verified, true, raceVerdict.reason)

    // Full confirmation on the http.send path.
    const httpReceipt = await call('composite.verify', {
      receipt: {
        chainId: 'chain-q29-http-binding',
        terminalVulnClass: 'dual_tenant_abac',
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/orders' }, exchangeIds: [createId], producedCapabilities: [orderHandle], claimedDelta: 'Sealed order_id.' },
          { hopId: 'hop_2', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/api/orders/x/receipt' }, exchangeIds: [termOut.exchangeId], consumedCapabilities: [orderHandle], claimedDelta: 'Read receipt with literal order_id.' },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: orderHandle }],
        terminalImpact: { terminalHopId: 'hop_2', summary: 'Foreign receipt exposed.', terminalExchangeId: termOut.exchangeId, preChainControlExchangeIds: [ctrlId] },
        replayMode: 'fresh_clean_replay',
      },
    })
    assert.equal(httpReceipt.ok, true, httpReceipt.error ?? "")
    const httpVerdict = httpReceipt.result as { failedStage?: string; reason: string; verifiedEdges: Array<{ kind: string; verified: boolean }> }
    assert.notEqual(httpVerdict.failedStage, 'edge_binding', httpVerdict.reason)
    assert.equal(httpVerdict.verifiedEdges.find(e => e.kind === 'value_binding')?.verified, true, httpVerdict.reason)
  } finally {
    await close()
    server.closeAllConnections()
    server.close()
  }
})

test('literal derived JWT and HMAC signature in headers attest derived_crypto_binding via the merged consumed list', async () => {
  const { server, origin } = await startFixture()
  const { call, close } = await startRpc(origin, 'run-q29-crypto')
  try {
    const create = await call('http.send', { method: 'POST', path: '/api/orders', body: '{}', headers: { 'content-type': 'application/json' } })
    const createId = (create.result as { exchangeId: string }).exchangeId
    const seal = await call('capability.seal', { exchangeId: createId, hopReceiptId: '1', slot: 'sign_key', jsonPath: '$.signingKey', kind: 'hmac_key' })
    assert.equal(seal.ok, true, seal.error ?? "")
    const signHandle = (seal.result as { handle: string }).handle

    const jwt = await call('crypto.jwtSign', { secretHandle: signHandle, claims: { sub: 'svc' }, alg: 'HS256', hopReceiptId: '2', slot: 'svc_jwt' })
    assert.equal(jwt.ok, true, jwt.error ?? "")
    const jwtHandle = (jwt.result as { derivedHandle: string }).derivedHandle
    // Derived JWT handle in a custom header: merged consumed list drives jwt crypto attestation.
    const viaInline = await call('http.send', { method: 'GET', path: '/api/signed', headers: { 'X-Signature': jwtHandle } })
    assert.equal(viaInline.ok, true, viaInline.error ?? "")

    const hmac = await call('crypto.hmacSign', { secretHandle: signHandle, payload: 'GET /api/signed', alg: 'sha256', encoding: 'hex' })
    assert.equal(hmac.ok, true, hmac.error ?? "")
    const signature = (hmac.result as { signature: string }).signature
    const signed = await call('http.send', { method: 'GET', path: '/api/signed', headers: { 'X-Signature': signature } })
    assert.equal(signed.ok, true, signed.error ?? "")
    const out = signed.result as { status: number; derivedFromCapabilityIds?: string[] }
    assert.equal(out.status, 200)
    assert.deepEqual(out.derivedFromCapabilityIds, [signHandle])

    const viaOut = viaInline.result as { consumedCapabilities?: string[]; derivedFromCapabilityIds?: string[] }
    assert.deepEqual(viaOut.consumedCapabilities, [jwtHandle])
    assert.deepEqual(viaOut.derivedFromCapabilityIds, [signHandle])
  } finally {
    await close()
    server.closeAllConnections()
    server.close()
  }
})

test('http2 path applies capability resolution and literal auto-binding', async () => {
  const h2 = createH2Server()
  h2.on('stream', (stream: ServerHttp2Stream, headers) => {
    const path = String(headers[':path'] ?? '/')
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ path, ok: true }))
  })
  h2.listen(0, '127.0.0.1')
  await once(h2, 'listening')
  const origin = `http://127.0.0.1:${(h2.address() as { port: number }).port}`
  const { rpc, vault, call, close } = await startRpc(origin, 'run-q29-h2')
  try {
    const meta = vault.seal({ hopReceiptId: '1', slot: 'order_id', rawValue: ORDER_ID })
    const res = await call('http2', { method: 'GET', path: `/api/orders/${ORDER_ID}` })
    assert.equal(res.ok, true, res.error ?? "")
    const out = res.result as { exchangeId: string; consumedCapabilities?: string[]; body: string }
    assert.deepEqual(out.consumedCapabilities, [meta.handle])
    assert.equal(out.body.includes(ORDER_ID), false)
    const inline = await call('http2', { method: 'GET', path: `/api/orders/${meta.handle}` })
    assert.equal(inline.ok, true, inline.error ?? "")
    assert.deepEqual((inline.result as { consumedCapabilities?: string[] }).consumedCapabilities, [meta.handle])
    const entry = (rpc.buildHostSignedTranscript().entries ?? []).find(e => e.exchangeId === out.exchangeId)!
    assert.deepEqual(entry.consumedCapabilities, [meta.handle])
  } finally {
    await close()
    h2.close()
  }
})

test('LOC ceilings and anti-contamination hold', () => {
  for (const f of ['src/server/verify-rpc.ts', 'src/server/verify-prove-handlers.ts']) {
    const loc = readFileSync(join(REPO_ROOT, f), 'utf8').trimEnd().split('\n').length
    assert.ok(loc <= 2300, `${f} is ${loc} LOC (ceiling <= 2300)`)
  }
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected benchmark contamination: ${JSON.stringify(scan.hits)}`)
})
