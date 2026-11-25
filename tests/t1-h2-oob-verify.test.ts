/**
 * Tier-1 verification RPC regression suite (CLAUDE_AUDIT C-1, H-7, H-20 verify-rpc half):
 *  - C-1: Caller `:`-prefixed HTTP/2 pseudo-headers are stripped and cannot override
 *    `:method`, `:path`, `:authority`, or `:scheme`.
 *  - C-1: Scope, protocol, scopePolicy, and killSwitch authorization are enforced fail-closed
 *    before opening `h2Connect`.
 *  - H-7: HTTP/2 response `Set-Cookie`, `Authorization`, and sensitive session headers are
 *    redacted via `redactHeaders` before returning to the worker or entering the transcript.
 *  - H-20: OOB `subscribe` uses an empty artifact filter by default (never `artifact: exchangeId`)
 *    and binds the real canary id so real `CanaryBroker` + `OobRelay` callbacks match and promote.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { request as httpRequest } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { IncomingHttpHeaders, ServerHttp2Stream } from 'node:http2'
import type { AddressInfo } from 'node:net'
import test from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { GlobalKillSwitch, globalKillSwitch } from '../src/server/kill-switch.ts'
import { evaluateClaims, VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER, VerifyRpcServer } from '../src/server/verify-rpc.ts'
import type { VerifyClaim } from '../src/server/verify-rpc.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

interface RpcResponse {
  ok: boolean
  result?: unknown
  error?: string
}

interface CapturedH2Request {
  method: string | undefined
  path: string | undefined
  authority: string | undefined
  scheme: string | undefined
  headers: IncomingHttpHeaders
}

function rpc(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResponse> {
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

async function startH2Fixture(
  onStream: (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => void,
): Promise<{ origin: string; host: string; close: () => Promise<void> }> {
  const sessions = new Set<import('node:http2').ServerHttp2Session>()
  const server = createH2Server()
  server.on('session', session => {
    sessions.add(session)
    session.once('close', () => sessions.delete(session))
  })
  server.on('stream', onStream)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  const host = `127.0.0.1:${port}`
  return {
    origin: `http://${host}`,
    host,
    close: async () => {
      for (const session of sessions) session.destroy()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

function makeGrant(allowedOrigins: readonly string[], overrides: Partial<Grant> = {}): Grant {
  const allowed = new Set(allowedOrigins)
  return {
    canRead: origin => allowed.has(origin),
    audit: () => undefined,
    allowLocalLab: true,
    tier: 1,
    isStateChangeApproved: () => false,
    ...overrides,
  }
}

test('C-1: caller :-prefixed HTTP/2 headers are stripped and cannot override pseudo-headers', async () => {
  const captured: CapturedH2Request[] = []
  const fixture = await startH2Fixture((stream, headers) => {
    captured.push({
      method: typeof headers[':method'] === 'string' ? headers[':method'] : undefined,
      path: typeof headers[':path'] === 'string' ? headers[':path'] : undefined,
      authority: typeof headers[':authority'] === 'string' ? headers[':authority'] : undefined,
      scheme: typeof headers[':scheme'] === 'string' ? headers[':scheme'] : undefined,
      headers: { ...headers },
    })
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ ok: true, method: headers[':method'], path: headers[':path'] }))
  })

  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant([fixture.origin], { tier: 1, isStateChangeApproved: () => false }),
    runId: 't1-h2-pseudo',
    assignmentId: 'assign-pseudo',
    targetOrigins: [fixture.origin],
  })
  await rpcServer.start()
  try {
    const res = await rpc(rpcServer, 'http2', {
      origin: fixture.origin,
      method: 'GET',
      path: '/safe-read?probe=1',
      headers: {
        ':method': 'DELETE',
        ':path': '/admin/destroy',
        ':authority': 'evil.example',
        ':scheme': 'https',
        ' :method': 'POST',
        'x-probe-tag': 'benign-check',
      },
    })
    assert.equal(res.ok, true, res.error ?? 'expected safe GET http2 call to succeed')
    assert.equal(captured.length, 1)
    assert.equal(captured[0]!.method, 'GET')
    assert.equal(captured[0]!.path, '/safe-read?probe=1')
    assert.equal(captured[0]!.authority, fixture.host)
    assert.equal(captured[0]!.scheme, 'http')
    assert.equal(captured[0]!.headers['x-probe-tag'], 'benign-check')

    const result = res.result as { exchangeId: string; status: number }
    const record = rpcServer.transcript.get(result.exchangeId)
    assert.ok(record, 'transcript record must exist')
    assert.equal(record.request?.method, 'GET')
    assert.equal(record.request?.pathAndQuery, '/safe-read?probe=1')
    for (const key of Object.keys(record.request?.headers ?? {})) {
      assert.equal(key.trimStart().startsWith(':'), false, `pseudo-header ${key} leaked into transcript`)
    }
  } finally {
    await rpcServer.close()
    await fixture.close()
  }
})

test('H-7: HTTP/2 response Set-Cookie, Authorization, and session headers are redacted before returning to worker', async () => {
  const rawSetCookie = 'connect.sid=s%3Aopaque_h2_session_cookie_99887766; Path=/; HttpOnly'
  const rawAuth = 'Bearer opaque_h2_resp_auth_token_11223344'
  const rawAuthToken = 'opaque_h2_x_auth_secret_55667788'
  const rawApiKey = 'opaque_h2_api_key_aabbccdd'
  const rawCsrf = 'opaque_h2_csrf_tok_eeff0011'
  const fixture = await startH2Fixture(stream => {
    stream.respond({
      ':status': 200,
      'content-type': 'application/json',
      'set-cookie': rawSetCookie,
      authorization: rawAuth,
      'x-auth-token': rawAuthToken,
      'x-api-key': rawApiKey,
      'x-csrf-token': rawCsrf,
      'x-harmless': 'visible-check-value',
    })
    stream.end(JSON.stringify({ ok: true }))
  })

  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant([fixture.origin]),
    runId: 't1-h7-redact',
    assignmentId: 'assign-redact',
    targetOrigins: [fixture.origin],
  })
  await rpcServer.start()
  try {
    const res = await rpc(rpcServer, 'http2', { origin: fixture.origin, method: 'GET', path: '/session' })
    assert.equal(res.ok, true, res.error ?? 'expected http2 exchange to succeed')
    const out = res.result as { exchangeId: string; headers: Record<string, string> }
    assert.equal(out.headers['set-cookie'], '[redacted]')
    assert.equal(out.headers.authorization, '[redacted]')
    assert.equal(out.headers['x-auth-token'], '[redacted]')
    assert.equal(out.headers['x-api-key'], '[redacted]')
    assert.equal(out.headers['x-csrf-token'], '[redacted]')
    assert.equal(out.headers['x-harmless'], 'visible-check-value')

    const serialized = JSON.stringify(res)
    const transcriptRecord = rpcServer.transcript.get(out.exchangeId)
    const serializedRecord = JSON.stringify(transcriptRecord)
    for (const secret of [
      'opaque_h2_session_cookie_99887766',
      'opaque_h2_resp_auth_token_11223344',
      rawAuthToken,
      rawApiKey,
      rawCsrf,
    ]) {
      assert.equal(serialized.includes(secret), false, `worker response leaked ${secret}`)
      assert.equal(serializedRecord.includes(secret), false, `transcript leaked ${secret}`)
    }
    assert.equal(transcriptRecord?.response?.headers['set-cookie'], '[redacted]')
  } finally {
    await rpcServer.close()
    await fixture.close()
  }
})

test('C-1: out-of-scope origin, non-http(s) scheme, scopePolicy, and tripped killSwitch reject HTTP/2 before h2Connect', async () => {
  let inScopeHits = 0
  let outOfScopeHits = 0
  const inScope = await startH2Fixture(stream => {
    inScopeHits += 1
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ ok: true }))
  })
  const outOfScope = await startH2Fixture(stream => {
    outOfScopeHits += 1
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ leaked: true }))
  })

  const customKillSwitch = new GlobalKillSwitch()
  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker({ killSwitch: customKillSwitch }),
    grant: makeGrant([inScope.origin], {
      tier: 3,
      isStateChangeApproved: () => true,
      scopePolicy: {
        mode: 'prod_readonly',
        targetOrigins: [inScope.origin],
      },
    }),
    runId: 't1-h2-authz',
    assignmentId: 'assign-authz',
    targetOrigins: [inScope.origin],
  })
  await rpcServer.start()
  try {
    // 1. Out-of-scope origin must fail closed before opening h2Connect
    const oos = await rpc(rpcServer, 'http2', { origin: outOfScope.origin, method: 'GET', path: '/secret' })
    assert.equal(oos.ok, false)
    assert.match(oos.error ?? '', /scope|outside/i)
    assert.equal(outOfScopeHits, 0, 'out-of-scope h2 server must receive zero streams')

    // 2. Non-http/https scheme must fail closed
    for (const badOrigin of ['ftp://127.0.0.1:21', 'file:///etc/passwd', 'ws://127.0.0.1:8080']) {
      const bad = await rpc(rpcServer, 'http2', { origin: badOrigin, method: 'GET', path: '/' })
      assert.equal(bad.ok, false, `${badOrigin} must be rejected`)
      assert.match(bad.error ?? '', /scope|protocol|outside|malformed/i)
    }

    // 3. scopePolicy (prod_readonly) rejects state-changing HTTP/2 before h2Connect
    const deniedMut = await rpc(rpcServer, 'http2', { origin: inScope.origin, method: 'POST', path: '/mutate', body: '{"x":1}' })
    assert.equal(deniedMut.ok, false)
    assert.match(deniedMut.error ?? '', /prod_readonly|state-changing|refuses/i)
    assert.equal(inScopeHits, 0, 'prod_readonly denied POST must never hit h2 server')

    // 4. Broker killSwitch tripped rejects in-scope GET before h2Connect
    customKillSwitch.trip({ reason: 'operator emergency halt' })
    const killed = await rpc(rpcServer, 'http2', { origin: inScope.origin, method: 'GET', path: '/ok' })
    assert.equal(killed.ok, false)
    assert.match(killed.error ?? '', /kill switch/i)
    assert.equal(inScopeHits, 0, 'tripped killSwitch must block h2Connect')
    const lastEntry = rpcServer.transcript.list().at(-1)
    assert.equal(lastEntry?.errorCode, 'denied')

    // 5. After resetting custom killSwitch, in-scope GET succeeds; globalKillSwitch also blocks when no custom switch is set
    customKillSwitch.reset()
    const allowed = await rpc(rpcServer, 'http2', { origin: inScope.origin, method: 'GET', path: '/ok' })
    assert.equal(allowed.ok, true, allowed.error ?? 'expected GET to succeed after reset')
    assert.equal(inScopeHits, 1)

    const globalServer = new VerifyRpcServer({
      broker: new RequestBroker(),
      grant: makeGrant([inScope.origin]),
      runId: 't1-h2-global-ks',
      assignmentId: 'assign-global-ks',
      targetOrigins: [inScope.origin],
    })
    await globalServer.start()
    try {
      globalKillSwitch.trip({ reason: 'global halt test' })
      const globalBlocked = await rpc(globalServer, 'http2', { origin: inScope.origin, method: 'GET', path: '/ok' })
      assert.equal(globalBlocked.ok, false)
      assert.match(globalBlocked.error ?? '', /kill switch/i)
      assert.equal(inScopeHits, 1, 'global killSwitch must block h2Connect')
    } finally {
      globalKillSwitch.reset()
      await globalServer.close()
    }
  } finally {
    await rpcServer.close()
    await inScope.close()
    await outOfScope.close()
  }
})

test('H-20: real CanaryBroker + OobRelay callbacks match and promote without artifact: exchangeId mismatch', async () => {
  const canary = new CanaryBroker()
  await canary.startLocalListener()
  const runId = `t1-oob-${randomUUID().slice(0, 8)}`
  const rpcServer = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(['http://127.0.0.1:1']),
    runId,
    assignmentId: 'assign-oob',
    targetOrigins: ['http://127.0.0.1:1'],
    canary,
  })
  await rpcServer.start()
  try {
    // 1. Direct oob mint -> subscribe (passing exchangeId as prove.oob does) -> real HTTP callback without artifact header/query -> wait
    const mintRes = await rpc(rpcServer, 'oob', { action: 'mint', label: 'ssrf-direct' })
    assert.equal(mintRes.ok, true, mintRes.error ?? 'oob mint failed')
    const minted = mintRes.result as { exchangeId: string; token: string; url: string; canaryId?: string }
    assert.ok(minted.canaryId, 'mint should return real canaryId when broker provides it')

    const subRes = await rpc(rpcServer, 'oob', {
      action: 'subscribe',
      token: minted.token,
      exchangeId: minted.exchangeId,
      immediateMs: 500,
    })
    assert.equal(subRes.ok, true, subRes.error ?? 'oob subscribe failed')
    const sub = subRes.result as { subscriptionId: string; createdAt: number }

    const storedSub = canary.oob.pending(runId).find(item => item.id === sub.subscriptionId)
    assert.ok(storedSub, 'pending_oob subscription must exist in OobRelay')
    assert.equal(storedSub.artifact, '', 'subscription artifact must be empty by default, never exchangeId')
    assert.equal(storedSub.canaryId, minted.canaryId, 'subscription must bind the real canaryId')

    // Deliver a real HTTP callback to the minted URL (no ?g_art= or x-kovo-artifact header)
    const cbRes = await fetch(minted.url)
    assert.equal(cbRes.status, 200)

    const waitRes = await rpc(rpcServer, 'oob', {
      action: 'wait',
      token: minted.token,
      subscriptionId: sub.subscriptionId,
      subscriptionCreatedAt: sub.createdAt,
      immediateMs: 500,
      timeoutMs: 1_500,
    })
    assert.equal(waitRes.ok, true, waitRes.error ?? 'oob wait failed')
    const waited = waitRes.result as { hit: boolean; promoted: boolean }
    assert.equal(waited.hit, true, 'real callback must match pending_oob subscription')
    assert.equal(waited.promoted, true, 'pending_oob subscription must promote on real callback')
    assert.equal(canary.oob.rejections().length, 0, 'real callback must not be rejected with artifact_missing')

    // 2. Full prove.oob start -> real callback -> prove.oob finish
    const startRes = await rpc(rpcServer, 'prove.oob', { phase: 'start', token: 'ssrf-prove', immediateMs: 500 })
    assert.equal(startRes.ok, true, startRes.error ?? 'prove.oob start failed')
    const started = startRes.result as {
      handle: { exchangeId: string; token: string; url: string; dnsHost: string }
      subscription: { subscriptionId: string; createdAt: number; status: string }
    }
    const cb2 = await fetch(started.handle.url)
    assert.equal(cb2.status, 200)

    const finishRes = await rpc(rpcServer, 'prove.oob', {
      phase: 'finish',
      handle: started.handle,
      subscription: started.subscription,
      immediateMs: 500,
      timeoutMs: 1_500,
    })
    assert.equal(finishRes.ok, true, finishRes.error ?? 'prove.oob finish failed')
    const proof = finishRes.result as { ok: boolean; confirmed: boolean; hit: boolean; promoted: boolean; missingEvidence: string[]; claim: VerifyClaim }
    assert.equal(proof.ok, true, `prove.oob failed: ${proof.missingEvidence.join(',')}`)
    assert.equal(proof.confirmed, true)
    assert.equal(proof.hit, true)
    assert.equal(proof.promoted, true)
    assert.deepEqual(proof.missingEvidence, [])
    assert.equal(canary.oob.rejections().length, 0, 'OobRelay must have zero artifact rejections')

    const oracle = evaluateClaims(rpcServer.transcript, [proof.claim], { canary })
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
  } finally {
    await rpcServer.close()
    await canary.stop()
    canary.closeOob()
  }
})
