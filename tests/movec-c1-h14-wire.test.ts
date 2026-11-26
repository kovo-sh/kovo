/**
 * Move C Final Cross-File Wiring Regression Suite (`C-1` + `H-14` + `WS-20`)
 *
 * Covers:
 *  - C-1: `VerifyRpcServer.handleHttp2` routes strictly through `RequestBroker.executeHttp2Exchange`,
 *         enforcing per-origin slot acquisition/release, audit events (`allowed`/`observed`),
 *         hop-by-hop & pseudo-header stripping, headerProfile injection, and defensive circuit breaker.
 *  - H-14: `wireCredentialProvenance` emitted by `RequestBroker.executeHttp` and
 *         `RequestBroker.executeHttp2Exchange` is forwarded into `HostFactLog` entries and
 *         cryptographically signed into host fact records (`hostSignature`) so proof oracles can
 *         verify wire-observed `headerNames`, `cookieNames`, and `sources` without raw secret leakage.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import {
  createServer as createH2Server,
  type IncomingHttpHeaders as H2IncomingHeaders,
  type ServerHttp2Session,
  type ServerHttp2Stream,
} from 'node:http2'
import type { AddressInfo } from 'node:net'
import test from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import { verifyHostRecordSignature } from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'

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
    }, res => {
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
    id: `persona-${handle}`,
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

function makeGrant(
  origins: string[],
  overrides: Partial<Grant> = {},
): Grant {
  const allowed = new Set(origins)
  return {
    origin: origins[0],
    tier: 2,
    allowLocalLab: true,
    maxRpsPerOrigin: 20,
    canRead: o => { try { return allowed.has(new URL(o).origin) } catch { return allowed.has(o) } },
    audit: () => undefined,
    ...overrides,
  }
}

test('C-1: VerifyRpcServer http2 flows through RequestBroker.executeHttp2Exchange enforcing slots, audit, header policy, and circuit breaker', async t => {
  const sessions = new Set<ServerHttp2Session>()
  const seenHeaders: H2IncomingHeaders[] = []
  let force429 = false
  let serverHits = 0

  const h2Server = createH2Server()
  h2Server.on('session', s => {
    sessions.add(s)
    s.once('close', () => sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream, headers: H2IncomingHeaders) => {
    serverHits += 1
    seenHeaders.push({ ...headers })
    const status = force429 ? 429 : 200
    stream.respond({ ':status': status, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ ok: !force429, path: headers[':path'] }))
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const port = (h2Server.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`
  t.after(async () => {
    for (const s of sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  const auditEvents: Array<{ outcome: string; origin: string; status?: number }> = []
  const broker = new RequestBroker({
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
    circuit429Threshold: 2,
    transportConfig: {
      headerProfile: {
        userAgent: 'KovoC1WireAgent/1.0',
        headers: { 'x-kovo-qa': 'wire-check' },
      },
    },
  })
  t.after(() => broker.closeTransport())

  let brokerH2Calls = 0
  const origExecuteH2 = broker.executeHttp2Exchange.bind(broker)
  broker.executeHttp2Exchange = async (
    req: BrokerHttpRequest,
    grant: Grant,
    signal: AbortSignal,
  ): Promise<BrokerExchangeResult> => {
    brokerH2Calls += 1
    return origExecuteH2(req, grant, signal)
  }

  const grant = makeGrant([origin], {
    audit: (outcome, o, status) => auditEvents.push({ outcome, origin: o, status }),
  })
  const rpc = new VerifyRpcServer({
    broker,
    grant,
    runId: 'run-movec-c1-h2',
    assignmentId: 'assign-c1-h2',
    targetOrigins: [origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  // 1. Happy path: routes through executeHttp2Exchange, strips hop-by-hop + pseudo-headers, injects headerProfile, audits allowed+observed, releases slot.
  const okRes = await rpcCall(rpc, 'http2', {
    origin,
    method: 'GET',
    path: '/v2/health',
    headers: {
      ':method': 'DELETE',
      ':path': '/forbidden',
      Connection: 'keep-alive, x-hop-drop',
      'Keep-Alive': 'timeout=5',
      'x-hop-drop': 'gone',
      'x-trace-tag': 'c1-ok',
    },
  })
  assert.equal(okRes.ok, true, okRes.error ?? 'expected http2 RPC to succeed')
  assert.equal(brokerH2Calls, 1, 'VerifyRpcServer.handleHttp2 must invoke RequestBroker.executeHttp2Exchange')
  assert.equal(broker.getOriginInFlight(origin), 0, 'Broker per-origin slot must be released after HTTP/2 exchange')

  const result = okRes.result as { exchangeId: string; status: number; protocol: string }
  assert.equal(result.status, 200)
  assert.equal(result.protocol, 'h2')

  assert.equal(seenHeaders.length, 1)
  assert.equal(seenHeaders[0]![':method'], 'GET')
  assert.equal(seenHeaders[0]![':path'], '/v2/health')
  assert.equal(seenHeaders[0]!['user-agent'], 'KovoC1WireAgent/1.0')
  assert.equal(seenHeaders[0]!['x-kovo-qa'], 'wire-check')
  assert.equal(seenHeaders[0]!['x-trace-tag'], 'c1-ok')
  assert.equal(seenHeaders[0]!.connection, undefined)
  assert.equal(seenHeaders[0]!['keep-alive'], undefined)
  assert.equal(seenHeaders[0]!['x-hop-drop'], undefined)

  assert.ok(auditEvents.some(e => e.outcome === 'allowed' && e.origin === origin))
  assert.ok(auditEvents.some(e => e.outcome === 'observed' && e.origin === origin && e.status === 200))

  // 2. Repeated 429s trip RequestBroker circuit breaker and fail fast without dialing H2 server again.
  force429 = true
  const r1 = await rpcCall(rpc, 'http2', { origin, method: 'GET', path: '/v2/rate-1' })
  assert.equal(r1.ok, true)
  const r2 = await rpcCall(rpc, 'http2', { origin, method: 'GET', path: '/v2/rate-2' })
  assert.equal(r2.ok, false)
  assert.match(r2.error ?? '', /circuit|429/i)
  assert.equal(broker.isCircuitOpen(origin), true)

  const hitsWhenOpened = serverHits
  const r3 = await rpcCall(rpc, 'http2', { origin, method: 'GET', path: '/v2/rate-3' })
  assert.equal(r3.ok, false)
  assert.match(r3.error ?? '', /circuit/i)
  assert.equal(serverHits, hitsWhenOpened, 'Open circuit breaker must block subsequent HTTP/2 RPC calls before hitting target')
  assert.equal(broker.getOriginInFlight(origin), 0)
})

test('H-14: wireCredentialProvenance from HTTP/1.1 and HTTP/2 flows into HostFactLog and is cryptographically signed', async t => {
  const SECRET_TOKEN = 'sk-h14-wire-secret-token-77889900'
  const JAR_COOKIE_VAL = 'h14-jar-cookie-val-aabbccdd'

  // Local HTTP/1.1 fixture
  const h1Server = createHttpServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/login') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `sid=${JAR_COOKIE_VAL}; Path=/; HttpOnly`,
      })
      res.end(JSON.stringify({ loggedIn: true }))
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ path: url.pathname, authed: Boolean(req.headers.authorization || req.headers.cookie) }))
  })
  h1Server.listen(0, '127.0.0.1')
  await once(h1Server, 'listening')
  const h1Origin = `http://127.0.0.1:${(h1Server.address() as AddressInfo).port}`
  t.after(async () => {
    h1Server.closeAllConnections()
    await new Promise<void>(resolve => h1Server.close(() => resolve()))
  })

  // Local HTTP/2 fixture
  const h2Sessions = new Set<ServerHttp2Session>()
  const h2Server = createH2Server()
  h2Server.on('session', s => {
    h2Sessions.add(s)
    s.once('close', () => h2Sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream, headers: H2IncomingHeaders) => {
    const path = String(headers[':path'] ?? '/')
    if (path === '/h2-login') {
      stream.respond({
        ':status': 200,
        'content-type': 'application/json',
        'set-cookie': `h2sid=${JAR_COOKIE_VAL}; Path=/; HttpOnly`,
      })
      stream.end(JSON.stringify({ loggedIn: true }))
      return
    }
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ path, authed: Boolean(headers.authorization || headers.cookie) }))
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const h2Origin = `http://127.0.0.1:${(h2Server.address() as AddressInfo).port}`
  t.after(async () => {
    for (const s of h2Sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  const broker = new RequestBroker({
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
  })
  t.after(() => broker.closeTransport())

  const alice: ResolvedPersona = {
    ...makePersona('alice', 'member:tenant-a', SECRET_TOKEN, h1Origin),
    originAllowlist: [h1Origin, h2Origin],
  }
  const grant = makeGrant([h1Origin, h2Origin], {
    personas: new Map([['alice', alice]]),
    secrets: [{ value: SECRET_TOKEN, placeholder: '[persona:alice:secret]' }],
  })

  const rpc = new VerifyRpcServer({
    broker,
    grant,
    runId: 'run-movec-h14-wire',
    assignmentId: 'assign-h14-wire',
    targetOrigins: [h1Origin, h2Origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  // 1. Unauthenticated HTTP/1.1 exchange
  const unauthH1 = await rpcCall(rpc, 'http', { origin: h1Origin, method: 'GET', path: '/public' })
  assert.equal(unauthH1.ok, true, unauthH1.error ?? 'unauth http failed')
  const unauthH1Id = (unauthH1.result as { exchangeId: string }).exchangeId

  // 2. Persona + session jar HTTP/1.1 exchange
  const loginH1 = await rpcCall(rpc, 'http', { origin: h1Origin, method: 'GET', path: '/login', persona: 'alice', session: 'jar1' })
  assert.equal(loginH1.ok, true, loginH1.error ?? 'login http failed')
  const authH1 = await rpcCall(rpc, 'http', { origin: h1Origin, method: 'GET', path: '/me', persona: 'alice', session: 'jar1' })
  assert.equal(authH1.ok, true, authH1.error ?? 'authed http failed')
  const authH1Id = (authH1.result as { exchangeId: string }).exchangeId

  // 3. Persona + session jar HTTP/2 exchange
  const loginH2 = await rpcCall(rpc, 'http2', { origin: h2Origin, method: 'GET', path: '/h2-login', persona: 'alice', session: 'jar2' })
  assert.equal(loginH2.ok, true, loginH2.error ?? 'login http2 failed')
  const authH2 = await rpcCall(rpc, 'http2', { origin: h2Origin, method: 'GET', path: '/h2-me', persona: 'alice', session: 'jar2' })
  assert.equal(authH2.ok, true, authH2.error ?? 'authed http2 failed')
  const authH2Id = (authH2.result as { exchangeId: string }).exchangeId

  // Inspect HostSignedTranscript and HostFactLog
  const signedTranscript = rpc.buildHostSignedTranscript()
  const factLog = rpc.buildHostFactLog()
  const storeFactLog = HostFactLog.fromTranscriptStore(rpc.transcript, { hostTranscript: signedTranscript })

  // Verify unauthenticated fact
  const unauthFact = factLog.getExchange(unauthH1Id)!
  assert.ok(unauthFact.wireCredentialProvenance)
  assert.equal(unauthFact.wireCredentialProvenance.authenticated, false)
  assert.equal(unauthFact.wireCredentialProvenance.source, 'none')
  assert.deepEqual(unauthFact.wireCredentialProvenance.headerNames, [])
  assert.deepEqual(unauthFact.wireCredentialProvenance.cookieNames, [])
  assert.deepEqual(unauthFact.wireCredentialProvenance.sources, [])

  // Verify HTTP/1.1 and HTTP/2 authenticated facts on BOTH HostFactLog paths
  for (const [id, expectedCookie, expectedSession] of [
    [authH1Id, 'sid', 'jar1'],
    [authH2Id, 'h2sid', 'jar2'],
  ] as const) {
    for (const log of [factLog, storeFactLog]) {
      const fact = log.getExchange(id)!
      assert.ok(fact, `fact ${id} must exist`)
      assert.ok(fact.hostSignature, `fact ${id} must carry hostSignature`)
      const wp = fact.wireCredentialProvenance
      assert.ok(wp, `fact ${id} must carry wireCredentialProvenance`)
      assert.equal(wp.authenticated, true)
      assert.equal(wp.source, 'persona_and_jar')
      assert.deepEqual(wp.sources, ['persona_vault', 'session_jar'])
      assert.equal(wp.personaHandle, 'alice')
      assert.equal(wp.session, expectedSession)
      assert.deepEqual(wp.headerNames, ['authorization', 'cookie'])
      assert.deepEqual(wp.cookieNames, [expectedCookie])
      assert.deepEqual(wp.vaultHeaderNames, ['authorization'])
      assert.deepEqual(wp.jarCookieNames, [expectedCookie])

      // Deeply frozen and zero raw secret/cookie leakage
      assert.equal(Object.isFrozen(wp), true)
      assert.equal(Object.isFrozen(wp.headerNames), true)
      assert.equal(Object.isFrozen(wp.cookieNames), true)
      assert.equal(Object.isFrozen(wp.sources), true)
      const serialized = JSON.stringify(wp)
      assert.equal(serialized.includes(SECRET_TOKEN), false)
      assert.equal(serialized.includes(JAR_COOKIE_VAL), false)

      // Mixed bearer/header + cookie auth must never misclassify ambientAuth as 'cookie'
      assert.notEqual(fact.ambientAuth, 'cookie')
      assert.equal(fact.credentialPlacement?.mixed, true)
    }

    // Cryptographic signature verification: valid as-is, FAILS if any wireCredentialProvenance field is tampered!
    const projectedEntry = factLog.toHostSignedTranscript().entries!.find(e => e.exchangeId === id)!
    assert.ok(projectedEntry.wireCredentialProvenance)
    assert.equal(rpc.verifyHostSignature(projectedEntry), true, `original signed entry ${id} must verify`)

    const tamperedHeaders = {
      ...projectedEntry,
      wireCredentialProvenance: {
        ...projectedEntry.wireCredentialProvenance!,
        headerNames: ['cookie'],
      },
    }
    const tamperedCookies = {
      ...projectedEntry,
      wireCredentialProvenance: {
        ...projectedEntry.wireCredentialProvenance!,
        cookieNames: ['forged_sid'],
      },
    }
    const tamperedSources = {
      ...projectedEntry,
      wireCredentialProvenance: {
        ...projectedEntry.wireCredentialProvenance!,
        sources: ['session_jar' as const],
      },
    }
    assert.equal(rpc.verifyHostSignature(tamperedHeaders), false, 'tampering headerNames must invalidate hostSignature')
    assert.equal(rpc.verifyHostSignature(tamperedCookies), false, 'tampering cookieNames must invalidate hostSignature')
    assert.equal(rpc.verifyHostSignature(tamperedSources), false, 'tampering sources must invalidate hostSignature')
  }
})

test('H-14: HostFactLog.recordBrokerExchange signs wireCredentialProvenance directly when signingKey is configured', async t => {
  const SIGNING_KEY = 'test-host-fact-log-h14-signing-key-0123456789abcdef'
  const SECRET = 'sk-direct-broker-secret-44556677'
  const ORIGIN = 'https://app.example'

  const broker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"ok":true}',
    }),
  })
  t.after(() => broker.closeTransport())

  const persona = makePersona('bob', 'admin:tenant-b', SECRET, ORIGIN)
  const grant = makeGrant([ORIGIN], {
    allowLocalLab: false,
    personas: new Map([['bob', persona]]),
    secrets: [{ value: SECRET, placeholder: '[persona:bob:secret]' }],
  })

  const req: BrokerHttpRequest = { origin: ORIGIN, method: 'GET', pathAndQuery: '/admin/stats', persona: 'bob' }
  const ex = await broker.executeHttp(req, grant, AbortSignal.timeout(5_000))

  const log = new HostFactLog({ signingKey: SIGNING_KEY })
  const fact = log.recordBrokerExchange('ex-direct-1', req, ex, { actorRoleLabel: 'admin:tenant-b' })

  assert.ok(fact.hostSignature, 'recordBrokerExchange with signingKey must sign the fact')
  assert.ok(fact.wireCredentialProvenance)
  assert.equal(fact.wireCredentialProvenance.authenticated, true)
  assert.deepEqual(fact.wireCredentialProvenance.headerNames, ['authorization'])
  assert.deepEqual(fact.wireCredentialProvenance.cookieNames, [])
  assert.deepEqual(fact.wireCredentialProvenance.sources, ['persona_vault'])
  assert.equal(JSON.stringify(fact.wireCredentialProvenance).includes(SECRET), false)

  const signedEntry = log.toHostSignedTranscript().entries![0]!
  assert.equal(verifyHostRecordSignature(signedEntry, SIGNING_KEY), true)

  const forgedEntry = {
    ...signedEntry,
    wireCredentialProvenance: {
      ...signedEntry.wireCredentialProvenance!,
      sources: ['caller_self_minted' as const],
    },
  }
  assert.equal(verifyHostRecordSignature(forgedEntry, SIGNING_KEY), false)
})
