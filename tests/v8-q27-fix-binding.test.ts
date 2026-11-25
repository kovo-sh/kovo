/**
 * Queue #27 Defect #2 Regression Suite:
 *  1. Inline `cap:...` placeholder resolution across URL path, query (raw & URL-encoded),
 *     Authorization / Cookie / custom headers, and JSON / string body in `VerifyRpcServer`.
 *  2. Security invariants preserved on inline handles: expiry, origin-scope, unknown/revoked
 *     rejection, and untouched broker rejection of non-capability Authorization/Cookie headers.
 *  3. Multi-handle `consumedCapabilities` deduplication + `detectCryptoAttestationsForRequest`
 *     across ALL consumed handles (not just the first) so derived JWT/HMAC handles always emit
 *     `cryptoAttestations` and satisfy `composite.verify` (`value_binding` / `derived_crypto_binding`).
 *  4. `capability.seal` kind alias normalization (`signing_material`, `secret_key`, etc.).
 *  5. Actionable `edge_binding` failure messages in `composite-receipt.ts` including `fromHopId`,
 *     `toHopId`, cited `exchangeIds`, and a 1-line fix hint.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SIGNING_KEY = 'q27-fix-binding-unit-test-signing-key-0123456789'

interface RecordedReq {
  method: string
  url: string
  headers: Record<string, string | string[] | undefined>
  body: string
}

async function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return await new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        socketPath,
        path: '/rpc',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
          [VERIFY_RPC_HEADER]: token,
          [VERIFY_NONCE_HEADER]: nonce,
        },
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(Buffer.from(c)))
        res.on('end', () => {
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) }
          catch (err) { reject(err) }
        })
      },
    )
    req.on('error', reject)
    req.end(payload)
  })
}

function makeGrant(origin: string): Grant {
  return {
    canRead: (o: string) => {
      try { return new URL(o).origin === origin } catch { return o === origin }
    },
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    audit: () => undefined,
  }
}

async function startFixtureServer() {
  const received: RecordedReq[] = []
  const secrets = {
    pathToken: 'path-secret-99887766',
    queryToken: 'qry-secret-55443322',
    clientTag: 'hdr-alpha-112233',
    cookieVal: 'sess-cookie-44556677',
    signingKey: 'hmac-signing-key-88776655',
    bodyToken: 'body-tok-"quoted"\\slash',
    signedPath: '/api/download/secret-report?sig=sig-abc12345',
  }

  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      const url = req.url ?? '/'
      received.push({ method: req.method ?? 'GET', url, headers: { ...req.headers }, body })

      if (url === '/api/bootstrap') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify(secrets))
        return
      }
      if (url === '/api/vault/export') {
        const auth = String(req.headers.authorization ?? '')
        const apiKey = String(req.headers['x-api-key'] ?? '')
        if (auth.startsWith('Bearer eyJ') && apiKey === secrets.clientTag) {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({
            tenantId: 'tenant_a',
            records: [{ id: 'rec-1', ownerEmail: 'cfo@tenant-a.test', amountCents: 420000 }],
            echoAuth: auth,
          }))
          return
        }
        res.writeHead(403, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'forbidden' }))
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        ok: true,
        url,
        auth: req.headers.authorization ?? null,
        cookie: req.headers.cookie ?? null,
        apiKey: req.headers['x-api-key'] ?? null,
        custom: req.headers['x-custom'] ?? null,
        body,
      }))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address() as { port: number }
  const origin = `http://127.0.0.1:${addr.port}`
  return { server, origin, received, secrets }
}

test('inline cap:... handles resolve across path, query, Authorization, Cookie, custom headers, and JSON body with full attestation & redaction', async () => {
  const { server, origin, received, secrets } = await startFixtureServer()
  const hostDir = mkdtempSync(join(tmpdir(), 'guardian-q27-'))
  let nowMs = 1_700_000_000_000
  const vault = new DerivedCapabilityVault({ runId: 'run-q27-inline', now: () => nowMs })
  const broker = new RequestBroker()
  const rpc = new VerifyRpcServer({
    runId: 'run-q27-inline',
    assignmentId: 'assign-q27',
    broker,
    grant: makeGrant(origin),
    targetOrigins: [origin],
    hostDir,
    capabilityVault: vault,
  })
  await rpc.start()

  try {
    const call = (op: string, args: Record<string, unknown>) =>
      rpcCall(rpc.socketPath, rpc.token, rpc.nonce, op, args)

    // Bootstrap exchange leaking secrets
    const boot = await call('http.send', { path: '/api/bootstrap', method: 'GET', sessionGroupRole: 'probe' })
    assert.equal(boot.ok, true)
    const bootExId = (boot.result as { exchangeId: string }).exchangeId

    // Seal secrets using exact kinds AND kind aliases (`signing_material`, `secret_key`, `opaque_token`, `unknown_alias`)
    const sealPath = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'path_tok', jsonPath: '$.pathToken', kind: 'opaque_token' })
    assert.equal(sealPath.ok, true, sealPath.error ?? 'sealPath failed')
    assert.equal((sealPath.result as { meta: { kind: string } }).meta.kind, 'api_token')
    const pathHandle = (sealPath.result as { handle: string }).handle

    const sealQuery = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'qry_tok', jsonPath: '$.queryToken', kind: 'unknown_custom_kind' })
    assert.equal(sealQuery.ok, true)
    assert.equal((sealQuery.result as { meta: { kind: string } }).meta.kind, 'generic_secret')
    const queryHandle = (sealQuery.result as { handle: string }).handle

    const sealKey = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'api_key', jsonPath: '$.clientTag', kind: 'secret_key' })
    assert.equal(sealKey.ok, true)
    assert.equal((sealKey.result as { meta: { kind: string } }).meta.kind, 'hmac_key')
    const keyHandle = (sealKey.result as { handle: string }).handle

    const sealCookie = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'sess', jsonPath: '$.cookieVal', kind: 'session_cookie' })
    assert.equal(sealCookie.ok, true)
    assert.equal((sealCookie.result as { meta: { kind: string } }).meta.kind, 'cookie')
    const cookieHandle = (sealCookie.result as { handle: string }).handle

    const sealSign = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'sign_key', jsonPath: '$.signingKey', kind: 'signing_material' })
    assert.equal(sealSign.ok, true)
    assert.equal((sealSign.result as { meta: { kind: string } }).meta.kind, 'hmac_key')
    const signHandle = (sealSign.result as { handle: string }).handle

    const sealBody = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'body_tok', jsonPath: '$.bodyToken', kind: 'generic_secret' })
    assert.equal(sealBody.ok, true)
    const bodyHandle = (sealBody.result as { handle: string }).handle

    const sealSignedPath = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'dl_path', jsonPath: '$.signedPath', kind: 'signed_url' })
    assert.equal(sealSignedPath.ok, true)
    const signedPathHandle = (sealSignedPath.result as { handle: string }).handle

    // Non-string kind still rejects
    const badKind = await call('capability.seal', { exchangeId: bootExId, hopReceiptId: '1', slot: 'bad', jsonPath: '$.clientTag', kind: 42 })
    assert.equal(badKind.ok, false)

    // Mint a derived JWT behind cap:hop_2:admin_jwt
    const jwtRes = await call('crypto.jwtSign', {
      secretHandle: signHandle,
      claims: { sub: 'svc-admin', role: 'admin' },
      alg: 'HS256',
      hopReceiptId: '2',
      slot: 'admin_jwt',
    })
    assert.equal(jwtRes.ok, true)
    const jwtHandle = (jwtRes.result as { derivedHandle: string }).derivedHandle
    assert.equal(jwtHandle, 'cap:hop_2:admin_jwt')

    // 1) Inline handles in path, query (raw + URL-encoded), custom header, Cookie, and JSON body (with special JSON chars!)
    const multiRes = await call('http.send', {
      method: 'POST',
      path: `/api/items/${pathHandle}?q=${encodeURIComponent(queryHandle)}&scope=cap:read`,
      headers: {
        'content-type': 'application/json',
        'x-api-key': keyHandle,
        'x-custom': `prefix-${keyHandle}-cap:admin`,
        Cookie: `theme=dark; sid=${cookieHandle}`,
      },
      body: JSON.stringify({ token: bodyHandle, jwt: jwtHandle, literalScope: 'cap:write' }),
      sessionGroupRole: 'probe',
    })
    assert.equal(multiRes.ok, true, multiRes.error ?? 'multiRes failed')
    const multiOut = multiRes.result as {
      exchangeId: string
      status: number
      consumedCapabilityId?: string
      consumedCapabilities?: string[]
      derivedFromCapabilityIds?: string[]
      body: string
    }
    assert.equal(multiOut.status, 200)

    // Verify server received ACTUAL resolved raw secrets (never literal cap:hop_... handles)
    const lastReq = received[received.length - 1]!
    assert.equal(lastReq.url, `/api/items/${secrets.pathToken}?q=${encodeURIComponent(secrets.queryToken)}&scope=cap:read`)
    assert.equal(lastReq.headers['x-api-key'], secrets.clientTag)
    assert.equal(lastReq.headers['x-custom'], `prefix-${secrets.clientTag}-cap:admin`)
    assert.equal(lastReq.headers.cookie, `theme=dark; sid=${secrets.cookieVal}`)
    const parsedReqBody = JSON.parse(lastReq.body) as { token: string; jwt: string; literalScope: string }
    assert.equal(parsedReqBody.token, secrets.bodyToken)
    assert.ok(parsedReqBody.jwt.startsWith('eyJ'), 'derived JWT handle in body must resolve to actual JWT')
    assert.equal(parsedReqBody.literalScope, 'cap:write', 'ordinary cap:write text must not be modified')

    // Verify echoed raw secrets are redacted in response view
    assert.equal(multiOut.body.includes(secrets.pathToken), false)
    assert.equal(multiOut.body.includes(secrets.clientTag), false)
    assert.equal(multiOut.body.includes(secrets.cookieVal), false)

    // Verify ALL 5 distinct handles are deduplicated in consumedCapabilities AND derived JWT emitted cryptoAttestations!
    assert.deepEqual(
      [...(multiOut.consumedCapabilities ?? [])].sort(),
      [bodyHandle, cookieHandle, jwtHandle, keyHandle, pathHandle, queryHandle].sort(),
    )
    assert.deepEqual(multiOut.derivedFromCapabilityIds, [signHandle])

    // 2) Exact signed path handle passed directly as `path`
    const signedPathRes = await call('http.send', {
      method: 'GET',
      path: signedPathHandle,
      sessionGroupRole: 'probe',
    })
    assert.equal(signedPathRes.ok, true, signedPathRes.error ?? 'signedPathRes failed')
    assert.equal(received[received.length - 1]!.url, secrets.signedPath)

    // 3) Control arm (403) + Terminal probe using inline `Authorization: Bearer cap:hop_2:admin_jwt` + `X-Api-Key: cap:hop_1:api_key`
    const ctrlRes = await call('http.send', {
      method: 'GET',
      path: '/api/vault/export',
      sessionGroupRole: 'control',
    })
    assert.equal(ctrlRes.ok, true)
    const ctrlExId = (ctrlRes.result as { exchangeId: string }).exchangeId
    assert.equal((ctrlRes.result as { status: number }).status, 403)

    const termRes = await call('http.send', {
      method: 'GET',
      path: '/api/vault/export',
      headers: {
        'X-Api-Key': keyHandle,
        Authorization: `Bearer ${jwtHandle}`,
      },
      sessionGroupRole: 'probe',
    })
    assert.equal(termRes.ok, true, termRes.error ?? 'termRes failed')
    const termOut = termRes.result as { exchangeId: string; status: number; body: string; consumedCapabilities?: string[]; derivedFromCapabilityIds?: string[] }
    assert.equal(termOut.status, 200)
    assert.equal(termOut.body.includes('eyJ'), false, 'echoed derived JWT must be scrubbed')
    assert.deepEqual([...(termOut.consumedCapabilities ?? [])].sort(), [jwtHandle, keyHandle].sort())
    assert.deepEqual(termOut.derivedFromCapabilityIds, [signHandle])

    // Verify full CompositeProofReceipt passes BOTH value_binding AND derived_crypto_binding!
    const compositeRes = await call('composite.verify', {
      receipt: {
        chainId: 'chain-q27-inline-binding',
        terminalVulnClass: 'dual_tenant_abac',
        hops: [
          {
            hopId: 'hop_1',
            surface: 'http',
            target: { origin, method: 'GET', pathAndQuery: '/api/bootstrap' },
            exchangeIds: [bootExId],
            producedCapabilities: [keyHandle, signHandle],
            claimedDelta: 'Leaked API key and HMAC signing material.',
          },
          {
            hopId: 'hop_2',
            surface: 'http',
            target: { origin, method: 'GET', pathAndQuery: '/api/vault/export' },
            exchangeIds: [termOut.exchangeId],
            consumedCapabilities: [keyHandle, jwtHandle],
            claimedDelta: 'Used inline X-Api-Key + derived Authorization Bearer JWT to export tenant_a records.',
          },
        ],
        causalEdges: [
          { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: keyHandle },
          { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: signHandle, derivedCapabilityId: jwtHandle, alg: 'HS256' },
        ],
        terminalImpact: {
          terminalHopId: 'hop_2',
          summary: 'Inline capability handles and derived JWT exposed tenant_a vault records.',
          terminalExchangeId: termOut.exchangeId,
          preChainControlExchangeIds: [ctrlExId],
        },
        replayMode: 'fresh_clean_replay',
      },
    })
    assert.equal(compositeRes.ok, true, compositeRes.error ?? 'compositeRes failed')
    const verdict = compositeRes.result as { confirmed: boolean; reason: string }
    assert.equal(verdict.confirmed, true, verdict.reason)

    // 4) Security invariants on inline handles:
    // (a) Raw caller Authorization / Cookie WITHOUT a capability handle is STILL denied by broker
    const rawAuthRes = await call('http.send', {
      method: 'GET',
      path: '/api/vault/export',
      headers: { Authorization: 'Bearer forged-raw-secret' },
    })
    assert.equal(rawAuthRes.ok, false)
    assert.match(rawAuthRes.error ?? '', /cannot be set directly/i)

    const rawCookieRes = await call('http.send', {
      method: 'GET',
      path: '/api/vault/export',
      headers: { Cookie: 'sid=forged-raw-cookie' },
    })
    assert.equal(rawCookieRes.ok, false)
    assert.match(rawCookieRes.error ?? '', /cannot be set directly/i)

    // (b) Unknown handle inline rejects
    const unknownRes = await call('http.send', {
      method: 'GET',
      path: '/api/items/cap:hop_999:missing',
    })
    assert.equal(unknownRes.ok, false)
    assert.match(unknownRes.error ?? '', /unknown or revoked/i)

    // (c) Origin-scoped handle used against disallowed origin rejects
    const scopedSeal = await call('capability.seal', {
      exchangeId: bootExId,
      hopReceiptId: '1',
      slot: 'scoped_key',
      jsonPath: '$.clientTag',
      allowedOrigins: ['https://other-origin.example'],
    })
    assert.equal(scopedSeal.ok, true)
    const scopedHandle = (scopedSeal.result as { handle: string }).handle
    const badOriginRes = await call('http.send', {
      method: 'GET',
      path: '/api/vault/export',
      headers: { 'X-Api-Key': scopedHandle },
    })
    assert.equal(badOriginRes.ok, false)
    assert.match(badOriginRes.error ?? '', /not allowed for origin/i)

    // (d) Expired handle inline rejects
    const expSeal = await call('capability.seal', {
      exchangeId: bootExId,
      hopReceiptId: '1',
      slot: 'exp_key',
      jsonPath: '$.clientTag',
      ttlMs: 1000,
    })
    assert.equal(expSeal.ok, true)
    const expHandle = (expSeal.result as { handle: string }).handle
    nowMs += 2000
    const expRes = await call('http.send', {
      method: 'POST',
      path: '/api/echo',
      body: JSON.stringify({ key: expHandle }),
    })
    assert.equal(expRes.ok, false)
    assert.match(expRes.error ?? '', /expired/i)
  } finally {
    await rpc.close()
    server.close()
    rmSync(hostDir, { recursive: true, force: true })
  }
})

test('composite-receipt edge_binding failures include fromHopId, toHopId, cited exchangeIds, and actionable Fix hint', () => {
  const makeEntry = (
    exchangeId: string,
    opts: {
      arm: 'control' | 'probe'
      method: string
      pathAndQuery: string
      status: number
      timestampMs: number
      emittedCapabilities?: string[]
    },
  ): HostTranscriptEntry => {
    const entry: HostTranscriptEntry = {
      exchangeId,
      timestampMs: opts.timestampMs,
      actorPersona: 'member_b',
      actorRoleLabel: 'member (tenant_b)',
      cleanSession: true,
      ...(opts.emittedCapabilities ? { emittedCapabilities: opts.emittedCapabilities } : {}),
      step: {
        id: exchangeId,
        arm: opts.arm,
        method: opts.method,
        route: opts.pathAndQuery.split('?')[0]!,
        pathAndQuery: opts.pathAndQuery,
        status: opts.status,
        actor: { handle: 'member_b', role: 'member', tenant: 'tenant_b', auth: 'bearer', sameSite: null },
      },
    }
    return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
  }

  const cap = 'cap:hop_1:tok'
  const transcript: HostSignedTranscript = {
    entries: [
      makeEntry('ex-ctrl', { arm: 'control', method: 'GET', pathAndQuery: '/api/target', status: 403, timestampMs: 500 }),
      makeEntry('ex-h1', { arm: 'probe', method: 'GET', pathAndQuery: '/api/leak', status: 200, timestampMs: 1000, emittedCapabilities: [cap] }),
      makeEntry('ex-h2', { arm: 'probe', method: 'GET', pathAndQuery: '/api/target', status: 200, timestampMs: 1100 }),
    ],
  }

  // value_binding failure
  const vb = verifyCompositeReceipt({
    chainId: 'chain-vb-fail',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_leak', surface: 'http', target: { origin: 'https://a.test', method: 'GET', pathAndQuery: '/api/leak' }, exchangeIds: ['ex-h1'], claimedDelta: 'leak' },
      { hopId: 'hop_use', surface: 'http', target: { origin: 'https://a.test', method: 'GET', pathAndQuery: '/api/target' }, exchangeIds: ['ex-h2'], claimedDelta: 'use' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_leak', toHopId: 'hop_use', capabilityHandle: cap }],
    terminalImpact: { terminalHopId: 'hop_use', summary: 'impact', terminalExchangeId: 'ex-h2', preChainControlExchangeIds: ['ex-ctrl'] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { signingKey: SIGNING_KEY })
  assert.equal(vb.confirmed, false)
  assert.equal(vb.failedStage, 'edge_binding')
  assert.match(vb.reason, /hop_leak->hop_use/)
  assert.match(vb.reason, /ex-h1/)
  assert.match(vb.reason, /ex-h2/)
  assert.match(vb.reason, /Fix:.*consumedCapabilities/i)

  // derived_crypto_binding failure
  const dcb = verifyCompositeReceipt({
    chainId: 'chain-dcb-fail',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_key', surface: 'http', target: { origin: 'https://a.test', method: 'GET', pathAndQuery: '/api/leak' }, exchangeIds: ['ex-h1'], claimedDelta: 'key' },
      { hopId: 'hop_signed', surface: 'http', target: { origin: 'https://a.test', method: 'GET', pathAndQuery: '/api/target' }, exchangeIds: ['ex-h2'], claimedDelta: 'signed' },
    ],
    causalEdges: [{ kind: 'derived_crypto_binding', fromHopId: 'hop_key', toHopId: 'hop_signed', sourceCapabilityId: cap }],
    terminalImpact: { terminalHopId: 'hop_signed', summary: 'impact', terminalExchangeId: 'ex-h2', preChainControlExchangeIds: ['ex-ctrl'] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { signingKey: SIGNING_KEY })
  assert.equal(dcb.confirmed, false)
  assert.equal(dcb.failedStage, 'edge_binding')
  assert.match(dcb.reason, /hop_key->hop_signed/)
  assert.match(dcb.reason, /ex-h1/)
  assert.match(dcb.reason, /ex-h2/)
  assert.match(dcb.reason, /Fix:.*cryptoAttestations/i)

  // Ensure sha256Hex import is exercised and LOC ceilings / anti-contamination hold
  assert.equal(sha256Hex('ok').length, 64)
  const compositeLoc = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8').trimEnd().split('\n').length
  const verifyRpcLoc = readFileSync(join(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8').trimEnd().split('\n').length
  assert.ok(compositeLoc <= 750, `composite-receipt.ts is ${compositeLoc} LOC (ceiling <= 750)`)
  assert.ok(verifyRpcLoc <= 2300, `verify-rpc.ts is ${verifyRpcLoc} LOC (ceiling <= 2300)`)
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected benchmark contamination: ${JSON.stringify(scan.hits)}`)
})
