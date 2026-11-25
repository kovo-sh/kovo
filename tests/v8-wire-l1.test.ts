/**
 * v8 M0/M1 Layer-1 Engine Wiring end-to-end integration tests.
 *
 * Proves (zero Docker, pure loopback HTTP + real VerifyRpcServer + real RequestBroker):
 *   1. Multi-hop derived custody flow: Hop 1 leaks a signing salt -> `capability.seal` returns
 *      `cap:hop_1:salt` (raw salt scrubbed from preview & transcript) -> Hop 2 calls
 *      `crypto.hmacSign` + `crypto.jwtSign` (sealing minted JWT without leaking raw token) ->
 *      Hop 3 calls `http.send({ capability })` (host-side injection + scrubbing) ->
 *      `composite.verify` confirms the 3-hop `CompositeProofReceipt` at 100% precision with
 *      zero raw secret leakage.
 *   2. Fail-closed rejections: unverified secret sealing, privileged-persona shortcutting
 *      (`owner_a` in probe hop), and forged/missing edges.
 *   3. Bounded `async.awaitResult` poll-convergence with monotonic timestamps + `async_pivot_binding`.
 *   4. Unified `proof-receipt.ts` re-exports (`verifyReceipt`, `singleReceiptToComposite`,
 *      `verifyCompositeReceipt`, `verifyReceiptUnified`) with 1-hop backward compatibility.
 *   5. Unified `oracle-invariants.ts` re-exports of `evaluateV8OracleFamily` across all 6 families.
 *   6. TypeScript (`kovo_verify.ts`) SDK helpers
 *      (`seal_capability`, `hmac_sign`, `jwt_sign`, `await_async`, `prove_composite`,
 *      `http_send`/`request` with `capability=`) end-to-end against a live `VerifyRpcServer`.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHmac } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  evaluateV8OracleFamily,
} from '../src/server/oracle-invariants.ts'
import type { HostSignedRecord } from '../src/server/oracle-invariants.ts'
import {
  signHostRecord,
  singleReceiptToComposite,
  verifyCompositeReceipt,
} from '../src/server/composite-receipt.ts'
import type { HostSignedTranscript } from '../src/server/composite-receipt.ts'
import {
  buildProofReceipt,
  verifyReceipt,
} from '../src/server/proof-receipt.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VERIFY_RPC_TOKEN_NAME,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const execFileAsync = promisify(execFile)
const REPO_ROOT = resolve(new URL('..', import.meta.url).pathname)
const SDK_DIR = join(REPO_ROOT, 'worker', 'kovo_verify')

const RAW_SIGNING_SALT = 's_v8_wire_l1_hmac_salt_9f8e7d6c5b4a'

function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string })
        } catch (err) {
          rejectPromise(err)
        }
      })
    })
    req.on('error', rejectPromise)
    req.end(payload)
  })
}

function makePersona(handle: string, roleLabel: string, token: string, origin: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret: token,
    canaryMarkers: [],
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[]): Grant {
  const map = new Map(personas.map(p => [p.handle, p]))
  return {
    canRead: (candidate: string) => {
      try { return new URL(candidate).origin === origin } catch { return false }
    },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: map,
  }
}

function verifyHs256Jwt(authHeader: string, secret: string): Record<string, unknown> | null {
  const match = /^Bearer\s+([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/i.exec(authHeader.trim())
  if (!match) return null
  const signingInput = `${match[1]}.${match[2]}`
  const expectedSig = createHmac('sha256', secret).update(signingInput, 'utf8').digest('base64url')
  if (expectedSig !== match[3]) return null
  try {
    return JSON.parse(Buffer.from(match[2]!, 'base64url').toString('utf8')) as Record<string, unknown>
  } catch {
    return null
  }
}

async function startMultiHopFixture(): Promise<{
  origin: string
  resetAsyncCounter: () => void
  close: () => Promise<void>
}> {
  let asyncPolls = 0
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    res.setHeader('content-type', 'application/json')

    // Hop 1: member_b reads a debug config endpoint that leaks a signing salt.
    if (url.pathname === '/api/debug/runtime-meta' && req.method === 'GET') {
      if (auth !== 'Bearer tok-member-beta' && auth !== 'Bearer tok-owner-acme') {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({
        service: 'settlement-gateway',
        signing_salt: RAW_SIGNING_SALT,
        note: `active-salt=${RAW_SIGNING_SALT}`,
      }))
      return
    }

    // Hop 2: signed webhook settlement endpoint requiring HMAC-SHA256(body, RAW_SIGNING_SALT).
    if (url.pathname === '/api/webhooks/settle' && req.method === 'POST') {
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        const providedSig = String(req.headers['x-webhook-signature'] ?? '')
        const expectedSig = createHmac('sha256', RAW_SIGNING_SALT).update(body, 'utf8').digest('hex')
        if (!providedSig || providedSig !== expectedSig) {
          res.statusCode = 403
          res.end(JSON.stringify({ error: 'invalid webhook signature' }))
          return
        }
        res.statusCode = 200
        res.end(JSON.stringify({ settled: true, status: 'disbursed', jobId: 'job-async-42' }))
      })
      return
    }

    // Hop 3: privileged vault export endpoint accepting either owner_a OR a valid HS256 JWT signed with RAW_SIGNING_SALT.
    if (url.pathname === '/api/vault/export' && req.method === 'GET') {
      if (auth === 'Bearer tok-owner-acme') {
        res.statusCode = 200
        res.end(JSON.stringify({ tenant: 'acme', classification: 'restricted', records: 12 }))
        return
      }
      const jwtClaims = verifyHs256Jwt(auth, RAW_SIGNING_SALT)
      if (jwtClaims && jwtClaims.scope === 'vault:export') {
        res.statusCode = 200
        // Deliberately echo Authorization header back to prove Layer 1 scrubs the derived JWT!
        res.end(JSON.stringify({
          tenant: 'acme',
          classification: 'restricted',
          records: 12,
          echoAuth: auth,
          echoSalt: RAW_SIGNING_SALT,
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }

    // Async convergence endpoints: POST /api/jobs/trigger -> GET /api/jobs/job-async-42 (ready on 3rd poll).
    if (url.pathname === '/api/jobs/trigger' && req.method === 'POST') {
      asyncPolls = 0
      res.statusCode = 202
      res.end(JSON.stringify({ accepted: true, jobId: 'job-async-42' }))
      return
    }
    if (url.pathname === '/api/jobs/job-async-42' && req.method === 'GET') {
      asyncPolls += 1
      if (asyncPolls < 3) {
        res.statusCode = 202
        res.end(JSON.stringify({ jobId: 'job-async-42', state: 'queued', poll: asyncPolls }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({ jobId: 'job-async-42', state: 'completed', output: 'exported_ok', poll: asyncPolls }))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not found' }))
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  assert.ok(addr && typeof addr === 'object')
  const origin = `http://127.0.0.1:${addr.port}`
  return {
    origin,
    resetAsyncCounter: () => { asyncPolls = 0 },
    close: () => new Promise<void>(resolveClose => server.close(() => resolveClose())),
  }
}

test('End-to-end loopback VerifyRpcServer: Hop 1 seal -> Hop 2 hmacSign + jwtSign -> Hop 3 capability inject -> composite.verify with zero secret leakage', async (t) => {
  const fixture = await startMultiHopFixture()
  t.after(() => fixture.close())

  const broker = new RequestBroker()
  const grant = makeGrant(fixture.origin, [
    makePersona('member_b', 'member (beta)', 'tok-member-beta', fixture.origin),
    makePersona('owner_a', 'owner (acme)', 'tok-owner-acme', fixture.origin),
  ])
  const rpcServer = new VerifyRpcServer({
    broker,
    grant,
    runId: 'run-v8-e2e-01',
    assignmentId: 'assign-v8-01',
    targetOrigins: [fixture.origin],
    compositeVerifyOptions: {
      attackerPersonas: ['member_b'],
      forbiddenShortcutPersonas: ['owner_a'],
    },
  })
  await rpcServer.start()
  t.after(() => rpcServer.close())

  const call = (op: string, args: Record<string, unknown>) =>
    rpcCall(rpcServer.socketPath, rpcServer.token, rpcServer.nonce, op, args)

  // Pre-chain denied control on terminal vault route as member_b
  const ctrlRes = await call('http.send', {
    path: '/api/vault/export',
    method: 'GET',
    persona: 'member_b',
    sessionGroupRole: 'control',
  })
  assert.equal(ctrlRes.ok, true)
  const ctrlEx = ctrlRes.result as { exchangeId: string; status: number }
  assert.equal(ctrlEx.status, 403)

  // Hop 1: member_b reads debug metadata leaking the signing salt
  const hop1Res = await call('http.send', {
    path: '/api/debug/runtime-meta',
    method: 'GET',
    persona: 'member_b',
    sessionGroupRole: 'probe',
  })
  assert.equal(hop1Res.ok, true)
  const hop1Ex = hop1Res.result as { exchangeId: string; status: number }
  assert.equal(hop1Ex.status, 200)

  // Seal the leaked salt behind cap:hop_1:salt
  const sealRes = await call('capability.seal', {
    exchangeId: hop1Ex.exchangeId,
    hopReceiptId: '1',
    slot: 'salt',
    jsonPath: '$.signing_salt',
    kind: 'signing_salt',
  })
  assert.equal(sealRes.ok, true)
  const sealed = sealRes.result as { handle: string; scrubbedPreview: string; meta: Record<string, unknown> }
  assert.equal(sealed.handle, 'cap:hop_1:salt')
  assert.equal(sealed.scrubbedPreview.includes(RAW_SIGNING_SALT), false, 'raw salt must be scrubbed from preview')
  assert.equal(JSON.stringify(sealed).includes(RAW_SIGNING_SALT), false, 'raw salt must never appear in seal response')
  assert.equal((rpcServer.transcript.body(hop1Ex.exchangeId) ?? '').includes(RAW_SIGNING_SALT), false, 'transcript body must be retroactively scrubbed')
  assert.equal(rpcServer.transcript.verifySignatures(), true, 'transcript signatures must remain valid after rescrubbing')

  // Transcript RPC readback must also have the raw salt scrubbed
  const txGet = await call('transcript', { action: 'get', exchangeId: hop1Ex.exchangeId })
  assert.equal(txGet.ok, true)
  assert.equal(JSON.stringify(txGet.result).includes(RAW_SIGNING_SALT), false)

  // Sealing an unverified/fabricated value not observed in the exchange must fail closed
  const badSeal = await call('capability.seal', {
    exchangeId: hop1Ex.exchangeId,
    hopReceiptId: '1',
    slot: 'fake',
    value: 'fabricated-secret-not-in-response',
  })
  assert.equal(badSeal.ok, false)

  // Hop 2A: crypto.hmacSign using cap:hop_1:salt + send signed webhook request
  const webhookPayload = JSON.stringify({ amount: 500, tenant: 'acme' })
  const hmacRes = await call('crypto.hmacSign', {
    secretHandle: 'cap:hop_1:salt',
    payload: webhookPayload,
    alg: 'sha256',
  })
  assert.equal(hmacRes.ok, true)
  const hmacOut = hmacRes.result as { exchangeId: string; signature: string; attestation: { derivedFromCapabilityId: string } }
  assert.equal(hmacOut.attestation.derivedFromCapabilityId, 'cap:hop_1:salt')
  assert.equal(JSON.stringify(hmacOut).includes(RAW_SIGNING_SALT), false)

  const hop2WebhookRes = await call('http.send', {
    path: '/api/webhooks/settle',
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-webhook-signature': hmacOut.signature },
    body: webhookPayload,
    sessionGroupRole: 'probe',
  })
  assert.equal(hop2WebhookRes.ok, true)
  const hop2WebhookEx = hop2WebhookRes.result as { exchangeId: string; status: number; derivedFromCapabilityIds?: string[] }
  assert.equal(hop2WebhookEx.status, 200)
  assert.deepEqual(hop2WebhookEx.derivedFromCapabilityIds, ['cap:hop_1:salt'])

  // Hop 2B: crypto.jwtSign using cap:hop_1:salt -> seals minted JWT behind cap:hop_2:admin_jwt (never leaks raw JWT)
  const jwtRes = await call('crypto.jwtSign', {
    secretHandle: 'cap:hop_1:salt',
    claims: { sub: 'worker-svc', scope: 'vault:export' },
    alg: 'HS256',
    hopReceiptId: '2',
    slot: 'admin_jwt',
  })
  assert.equal(jwtRes.ok, true)
  const jwtOut = jwtRes.result as { exchangeId: string; derivedHandle: string; attestation: { derivedFromCapabilityId: string } }
  assert.equal(jwtOut.derivedHandle, 'cap:hop_2:admin_jwt')
  assert.equal(jwtOut.attestation.derivedFromCapabilityId, 'cap:hop_1:salt')
  assert.equal('token' in jwtOut, false, 'raw JWT must not be exposed to worker')
  assert.equal(JSON.stringify(jwtOut).includes(RAW_SIGNING_SALT), false)

  // Hop 3: http.send with { capability: 'cap:hop_2:admin_jwt' } injects Authorization host-side and scrubs echoed secret
  const hop3Res = await call('http.send', {
    path: '/api/vault/export',
    method: 'GET',
    capability: 'cap:hop_2:admin_jwt',
    sessionGroupRole: 'probe',
  })
  assert.equal(hop3Res.ok, true)
  const hop3Ex = hop3Res.result as {
    exchangeId: string
    status: number
    body: string
    bodyPreview: string
    consumedCapabilityId?: string
    derivedFromCapabilityIds?: string[]
  }
  assert.equal(hop3Ex.status, 200)
  assert.equal(hop3Ex.consumedCapabilityId, 'cap:hop_2:admin_jwt')
  assert.deepEqual(hop3Ex.derivedFromCapabilityIds, ['cap:hop_1:salt'])
  assert.equal(hop3Ex.body.includes(RAW_SIGNING_SALT), false, 'raw salt echoed by target must be scrubbed')
  assert.equal(hop3Ex.body.includes('[redacted:cap:hop_2:admin_jwt]'), true, 'echoed derived JWT must be redacted with handle')
  assert.equal(hop3Ex.bodyPreview.includes(RAW_SIGNING_SALT), false)

  // Submit 3-hop CompositeProofReceipt via composite.verify RPC:
  // hop_1 (leak salt) --[derived_crypto_binding]--> hop_2 (hmac webhook + jwt mint) --[value_binding]--> hop_3 (vault export via derived JWT)
  const compositeReceipt = {
    chainId: 'chain-v8-e2e-salt-to-vault',
    terminalVulnClass: 'auth_bypass',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: fixture.origin, method: 'GET', pathAndQuery: '/api/debug/runtime-meta' },
        exchangeIds: [hop1Ex.exchangeId],
        producedCapabilities: ['cap:hop_1:salt'],
        claimedDelta: 'Member leaked internal signing salt from runtime metadata.',
      },
      {
        hopId: 'hop_2',
        surface: 'webhook',
        target: { origin: fixture.origin, method: 'POST', pathAndQuery: '/api/webhooks/settle' },
        exchangeIds: [hop2WebhookEx.exchangeId, jwtOut.exchangeId],
        producedCapabilities: ['cap:hop_2:admin_jwt'],
        claimedDelta: 'Signed settlement webhook with HMAC and minted HS256 admin JWT from leaked salt.',
      },
      {
        hopId: 'hop_3',
        surface: 'http',
        target: { origin: fixture.origin, method: 'GET', pathAndQuery: '/api/vault/export' },
        exchangeIds: [hop3Ex.exchangeId],
        consumedCapabilities: ['cap:hop_2:admin_jwt'],
        claimedDelta: 'Exported restricted tenant vault using derived HS256 JWT.',
      },
    ],
    causalEdges: [
      {
        kind: 'derived_crypto_binding',
        fromHopId: 'hop_1',
        toHopId: 'hop_2',
        sourceCapabilityId: 'cap:hop_1:salt',
        alg: 'sha256',
      },
      {
        kind: 'value_binding',
        fromHopId: 'hop_2',
        toHopId: 'hop_3',
        capabilityHandle: 'cap:hop_2:admin_jwt',
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      claimedImpact: 'Unauthorized restricted vault export via salt leak -> derived crypto -> JWT injection.',
      preChainControlExchangeIds: [ctrlEx.exchangeId],
      postChainReadbackExchangeIds: [hop3Ex.exchangeId],
    },
    replayMode: 'fresh_clean_replay',
  }

  const verifyRes = await call('composite.verify', { receipt: compositeReceipt })
  assert.equal(verifyRes.ok, true)
  const verdict = verifyRes.result as {
    confirmed: boolean
    hopCount: number
    verifiedEdges: Array<{ kind: string; verified: boolean }>
    reason: string
  }
  assert.equal(verdict.confirmed, true, `Expected confirmed composite receipt, got: ${verdict.reason}`)
  assert.equal(verdict.hopCount, 3)
  assert.equal(verdict.verifiedEdges.length, 2)
  assert.equal(verdict.verifiedEdges.every(e => e.verified), true)
  assert.equal(JSON.stringify(verdict).includes(RAW_SIGNING_SALT), false)

  // Privileged-shortcut rejection: using pre-seeded owner_a in a probe hop MUST be rejected!
  const shortcutRes = await call('http.send', {
    path: '/api/vault/export',
    method: 'GET',
    persona: 'owner_a',
    sessionGroupRole: 'probe',
  })
  assert.equal(shortcutRes.ok, true)
  const shortcutEx = shortcutRes.result as { exchangeId: string; status: number }
  assert.equal(shortcutEx.status, 200)

  const shortcutReceipt = {
    ...compositeReceipt,
    chainId: 'chain-v8-shortcut-attempt',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: fixture.origin, method: 'GET', pathAndQuery: '/api/vault/export' },
        exchangeIds: [shortcutEx.exchangeId],
        claimedDelta: 'Privileged owner_a directly accessed vault export.',
      },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      claimedImpact: 'Attempted shortcut via pre-seeded owner_a.',
    },
  }
  const shortcutVerdictRes = await call('composite.verify', {
    receipt: shortcutReceipt,
    // Attempt to weaken host options via RPC args (must be ignored by host!)
    attackerPersonas: ['owner_a'],
    forbiddenShortcutPersonas: [],
  })
  assert.equal(shortcutVerdictRes.ok, true)
  const shortcutVerdict = shortcutVerdictRes.result as { confirmed: boolean; failedStage?: string }
  assert.equal(shortcutVerdict.confirmed, false)
  assert.equal(shortcutVerdict.failedStage, 'attacker_provenance')
})

test('async.awaitResult poll-convergence over loopback VerifyRpcServer verifies async_pivot_binding', async (t) => {
  const fixture = await startMultiHopFixture()
  t.after(() => fixture.close())

  const broker = new RequestBroker()
  const grant = makeGrant(fixture.origin, [
    makePersona('member_b', 'member (beta)', 'tok-member-beta', fixture.origin),
  ])
  const rpcServer = new VerifyRpcServer({
    broker,
    grant,
    runId: 'run-v8-async-01',
    assignmentId: 'assign-v8-async',
    targetOrigins: [fixture.origin],
  })
  await rpcServer.start()
  t.after(() => rpcServer.close())

  const call = (op: string, args: Record<string, unknown>) =>
    rpcCall(rpcServer.socketPath, rpcServer.token, rpcServer.nonce, op, args)

  const triggerRes = await call('http.send', {
    path: '/api/jobs/trigger',
    method: 'POST',
    persona: 'member_b',
    sessionGroupRole: 'probe',
    correlationId: 'job-async-42',
  })
  assert.equal(triggerRes.ok, true)
  const triggerEx = triggerRes.result as { exchangeId: string; status: number }
  assert.equal(triggerEx.status, 202)

  const asyncRes = await call('async.awaitResult', {
    pollRequest: {
      path: '/api/jobs/job-async-42',
      method: 'GET',
      persona: 'member_b',
      sessionGroupRole: 'probe',
    },
    matchPredicate: { status: 200, jsonPath: '$.state', equals: 'completed' },
    profile: 'fast_lab',
    timeoutMs: 3_000,
    intervalMs: 25,
    triggerExchangeId: triggerEx.exchangeId,
    correlationId: 'job-async-42',
  })
  assert.equal(asyncRes.ok, true)
  const awaited = asyncRes.result as {
    pollRecordId: string
    converged: boolean
    status: string
    exchangeId: string
    evidence: { attempts: number; tTriggerMs: number; tObservedMs: number }
  }
  assert.equal(awaited.converged, true)
  assert.equal(awaited.status, 'converged')
  assert.equal(awaited.evidence.attempts, 3)
  assert.ok(awaited.evidence.tObservedMs >= awaited.evidence.tTriggerMs)

  const asyncReceipt = {
    chainId: 'chain-async-pivot-1',
    terminalVulnClass: 'business_logic',
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin: fixture.origin, method: 'POST', pathAndQuery: '/api/jobs/trigger' },
        exchangeIds: [triggerEx.exchangeId],
        claimedDelta: 'Triggered background export job.',
      },
      {
        hopId: 'hop_2',
        surface: 'async_job',
        target: { origin: fixture.origin, method: 'GET', pathAndQuery: '/api/jobs/job-async-42' },
        exchangeIds: [awaited.exchangeId],
        claimedDelta: 'Async job completed with exported output.',
      },
    ],
    causalEdges: [
      {
        kind: 'async_pivot_binding',
        fromHopId: 'hop_1',
        toHopId: 'hop_2',
        correlationId: 'job-async-42',
        channel: 'poll_convergence',
        pollRecordId: awaited.pollRecordId,
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Async job completed after trigger.',
    },
  }

  const verifyRes = await call('composite.verify', { receipt: asyncReceipt })
  assert.equal(verifyRes.ok, true)
  const verdict = verifyRes.result as { confirmed: boolean; reason: string; verifiedEdges: Array<{ kind: string; verified: boolean }> }
  assert.equal(verdict.confirmed, true, verdict.reason)
  assert.equal(verdict.verifiedEdges[0]?.kind, 'async_pivot_binding')
  assert.equal(verdict.verifiedEdges[0]?.verified, true)
})

test('proof-receipt.ts unified re-exports preserve 1-hop backward compatibility & zero TDZ', () => {
  const origin = 'http://127.0.0.1:4100'
  const signingKey = 'unit-test-signing-key-01'
  const receipt = buildProofReceipt({
    vulnClass: 'bola',
    target: { origin, method: 'GET', pathAndQuery: '/api/invoices/inv-99' },
    exchangeIds: ['ex-ctrl', 'ex-probe'],
    claimedDelta: 'Member in beta read acme invoice inv-99.',
    resourceTenant: 'acme',
  })

  const rawEntries: HostSignedTranscript['entries'] = [
    {
      exchangeId: 'ex-ctrl',
      timestampMs: 1_700_000_000_100,
      actorPersona: 'viewer_beta',
      actorRoleLabel: 'viewer (beta)',
      cleanSession: true,
      step: {
        id: 'ex-ctrl',
        arm: 'control',
        method: 'GET',
        route: '/api/invoices/inv-99',
        pathAndQuery: '/api/invoices/inv-99',
        status: 403,
        actor: { handle: 'viewer_beta', role: 'viewer', tenant: 'beta', auth: 'bearer', sameSite: null },
        json: { error: 'forbidden' },
        body: '{"error":"forbidden"}',
      },
    },
    {
      exchangeId: 'ex-probe',
      timestampMs: 1_700_000_000_200,
      actorPersona: 'member_beta',
      actorRoleLabel: 'member (beta)',
      cleanSession: true,
      step: {
        id: 'ex-probe',
        arm: 'probe',
        method: 'GET',
        route: '/api/invoices/inv-99',
        pathAndQuery: '/api/invoices/inv-99',
        status: 200,
        actor: { handle: 'member_beta', role: 'member', tenant: 'beta', auth: 'bearer', sameSite: null },
        json: { id: 'inv-99', tenant_id: 'acme', owner_email: 'ceo@acme.test', total_cents: 9500 },
        body: '{"id":"inv-99","tenant_id":"acme","owner_email":"ceo@acme.test","total_cents":9500}',
      },
    },
  ]
  const signedTranscript: HostSignedTranscript = {
    entries: rawEntries.map(e => ({ ...e, hostSignature: signHostRecord(e, signingKey) })),
  }

  // 1-hop v7 API
  const v7 = verifyReceipt(receipt, signedTranscript)
  assert.equal(v7.confirmed, true)

  // Wrapped 1-hop DAG via singleReceiptToComposite + verifyCompositeReceipt
  const wrapped = singleReceiptToComposite(receipt)
  assert.equal(wrapped.hops.length, 1)
  const v8 = verifyCompositeReceipt(wrapped, signedTranscript, { signingKey })
  assert.equal(v8.confirmed, true)
  assert.equal(v8.hopCount, 1)
})

test('oracle-invariants.ts re-exports evaluateV8OracleFamily for all 6 v8 families', () => {
  const rec = (id: string, ts: number, status: number, extra: Partial<HostSignedRecord> = {}): HostSignedRecord => ({
    id,
    hostSignature: 'sig-1234567890abcdef',
    timestampMs: ts,
    status,
    ...extra,
  })

  // 1. dual_tenant_abac
  const d1 = evaluateV8OracleFamily('dual_tenant_abac', {
    mode: 'cross_org_transfer',
    actor: { actorId: 'dual_member', rolesByTenant: { org_a: 'viewer', org_b: 'admin' } },
    sourceTenantId: 'org_a',
    destTenantId: 'org_b',
    entityId: 'proj-7',
    transferRecord: rec('t1', 1000, 200),
    postTransferReadback: rec('t2', 1100, 200),
    observedOwnerTenantId: 'org_b',
  })
  assert.equal(d1.satisfied, true)

  // 2. temporal_revocation
  const d2 = evaluateV8OracleFamily('temporal_revocation', {
    credentialKind: 'pat',
    credentialHandle: 'cap:hop_1:pat',
    primarySurface: 'http',
    secondarySurface: 'sse',
    revocationEvent: rec('r1', 1000, 200),
    primaryDeniedCheck: rec('r2', 1100, 401, { capabilityHandle: 'cap:hop_1:pat', route: '/api/me' }),
    secondarySuccess: rec('r3', 1200, 200, { capabilityHandle: 'cap:hop_1:pat', route: '/events/stream', json: { secretEvent: 'x' } }),
  })
  assert.equal(d2.satisfied, true)

  // 3. economic_conservation
  const d3 = evaluateV8OracleFamily('economic_conservation', {
    equation: 'over_refund',
    baselineReadback: rec('e1', 1000, 200),
    actions: [rec('e2', 1100, 200)],
    finalReadback: rec('e3', 1200, 200),
    paidAmount: 100,
    refundedAmounts: [80, 60],
  })
  assert.equal(d3.satisfied, true)

  // 4. cryptographic_scope_replay
  const d4 = evaluateV8OracleFamily('cryptographic_scope_replay', {
    tamperedSignatureControl: rec('c1', 1000, 401, { route: '/webhooks/in', artifactDigest: 'bad-sig-digest' }),
    sourceValidIssuance: rec('c2', 1100, 200, { artifactDigest: 'valid-sig-digest' }),
    replayedAcceptance: rec('c3', 1200, 200, { route: '/webhooks/in', artifactDigest: 'valid-sig-digest', json: { applied: true } }),
    sourceTenant: 'tenant_b',
    sourceScope: 'billing',
    targetTenant: 'tenant_a',
    targetScope: 'billing',
  })
  assert.equal(d4.satisfied, true)

  // 5. parser_cache_differential
  const d5 = evaluateV8OracleFamily('parser_cache_differential', {
    mode: 'parser_differential',
    differentialKind: 'duplicate_json_key',
    differentialFeature: 'duplicate_amount_key',
    canonicalValue: '{"amount":10000}',
    variantValue: '{"amount":1,"amount":10000}',
    impactKind: 'read',
    cleanControl: rec('p1', 1000, 403),
    differentialProbe: rec('p2', 1100, 200, { json: { record: 'sensitive' } }),
  })
  assert.equal(d5.satisfied, true)

  // 6. cross_surface_pivot
  const d6 = evaluateV8OracleFamily('cross_surface_pivot', {
    attackerOriginPersona: { actorId: 'member_b', role: 'member', tenantId: 'beta' },
    preChainControlDenied: rec('x0', 900, 403),
    hops: [
      { surface: 'http', role: 'trigger_write', record: rec('x1', 1000, 200, { actorId: 'member_b', capabilityHandle: 'cap:hop_1:tok' }), emittedArtifactDigest: 'dig-1' },
      { surface: 'browser', role: 'terminal_impact', record: rec('x2', 1100, 200), bindingKind: 'value_binding', consumedArtifactDigest: 'cap:hop_1:tok' },
    ],
    terminalImpact: { kind: 'privileged_read', verified: true, impactDigest: 'impact-dig-1' },
  })
  assert.equal(d6.satisfied, true)
})

test('worker/kovo_verify TS SDK helpers work end-to-end against VerifyRpcServer', async (t) => {
  const fixture = await startMultiHopFixture()
  t.after(() => fixture.close())

  const broker = new RequestBroker()
  const grant = makeGrant(fixture.origin, [
    makePersona('member_b', 'member (beta)', 'tok-member-beta', fixture.origin),
  ])
  const rpcServer = new VerifyRpcServer({
    broker,
    grant,
    runId: 'run-v8-sdk-01',
    assignmentId: 'assign-v8-sdk',
    targetOrigins: [fixture.origin],
  })
  await rpcServer.start()
  t.after(() => rpcServer.close())

  const workDir = mkdtempSync(join(tmpdir(), 'kovo-v8-sdk-test-'))
  t.after(() => rmSync(workDir, { recursive: true, force: true }))

  const env = {
    ...process.env,
    [VERIFY_RPC_SOCKET_ENV]: rpcServer.socketPath,
    [VERIFY_RPC_TOKEN_ENV]: join(rpcServer.hostDir, VERIFY_RPC_TOKEN_NAME),
    [VERIFY_RPC_CONTEXT_ENV]: join(rpcServer.hostDir, VERIFY_RPC_CONTEXT_NAME),
    [VERIFY_NONCE_ENV]: rpcServer.nonce,
  }

  // 1. TypeScript SDK test script
  const tsScriptPath = join(workDir, 'verify_ts.ts')
  writeFileSync(tsScriptPath, `
import assert from 'node:assert/strict'
import { VerifyContext } from ${JSON.stringify(join(SDK_DIR, 'kovo_verify.ts'))}

const ctx = new VerifyContext()
const h1 = await ctx.http_send('/api/debug/runtime-meta', { as: 'member_b', role: 'probe' })
const sealed = await ctx.seal_capability({ exchange: h1, hopReceiptId: 'ts1', slot: 'salt', jsonPath: '$.signing_salt', kind: 'signing_salt' })
assert.equal(sealed.handle, 'cap:hop_ts1:salt')
const hmac = await ctx.hmac_sign({ secretHandle: sealed.handle, payload: '{"ok":1}', alg: 'sha256' })
const h2 = await ctx.request('/api/webhooks/settle', { method: 'POST', headers: { 'x-webhook-signature': hmac.signature }, body: '{"ok":1}', role: 'probe' })
assert.equal(h2.status, 200)
const jwt = await ctx.jwt_sign({ secretHandle: sealed.handle, claims: { scope: 'vault:export' }, alg: 'HS256', hopReceiptId: 'ts2', slot: 'jwt' })
const h3 = await ctx.http_send('/api/vault/export', { capability: jwt.derivedHandle, role: 'probe' })
assert.equal(h3.status, 200)
assert.equal(h3.consumedCapabilityId, jwt.derivedHandle)

const trig = await ctx.http_send('/api/jobs/trigger', { method: 'POST', as: 'member_b', role: 'probe', correlationIds: ['job-async-42'] })
const pol = await ctx.await_async({
  pollRequest: { path: '/api/jobs/job-async-42', as: 'member_b', role: 'probe' },
  matchPredicate: { status: 200, jsonPath: '$.state', equals: 'completed' },
  timeoutMs: 3000,
  intervalMs: 20,
  triggerExchangeId: trig.exchangeId,
  correlationId: 'job-async-42',
})
assert.equal(pol.converged, true)

const verdict = await ctx.prove_composite({
  chainId: 'sdk-ts-chain',
  terminalVulnClass: 'auth_bypass',
  hops: [
    { hopId: 'hop_1', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/debug/runtime-meta' }, exchangeIds: [h1.exchangeId], claimedDelta: 'Leaked salt.' },
    { hopId: 'hop_2', surface: 'webhook', target: { origin: ctx.targetOrigin, method: 'POST', pathAndQuery: '/api/webhooks/settle' }, exchangeIds: [h2.exchangeId, jwt.exchangeId], claimedDelta: 'Derived HMAC + JWT.' },
    { hopId: 'hop_3', surface: 'http', target: { origin: ctx.targetOrigin, method: 'GET', pathAndQuery: '/api/vault/export' }, exchangeIds: [h3.exchangeId], claimedDelta: 'Vault export via derived JWT.' },
  ],
  causalEdges: [
    { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: sealed.handle, alg: 'sha256' },
    { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: jwt.derivedHandle },
  ],
  terminalImpact: { terminalHopId: 'hop_3', claimedImpact: 'TS SDK composite confirmed.' },
})
assert.equal(verdict.confirmed, true, verdict.reason)
console.log('TS_SDK_OK')
`)
  const tsRun = await execFileAsync(process.execPath, [tsScriptPath], { env, timeout: 15_000 })
  assert.match(tsRun.stdout, /TS_SDK_OK/)
})
