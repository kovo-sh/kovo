import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { ServerResponse } from 'node:http'
import http2 from 'node:http2'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  BrokerApprovalRequired,
  BrokerCircuitOpen,
  BrokerDenied,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import {
  resolveTransportConfig,
  TransportConfigError,
  WebSocketSession,
} from '../src/server/transport.ts'

// ============================================================================
// v6 Phase 3 Layer-1 transport
//
// Covers: HTTP/2 round trip + pooling + fallback, single-connection race bursts,
// error-safe circuit breakers (probe-induced 5xx vs transport/429, exponential
// backoff recovery), fail-closed proxy/mTLS/UA configuration, WebSocket message
// assembly, and unchanged approval/scope enforcement on the h2 path.
// ============================================================================

const localAddr: PublicAddress = { address: '127.0.0.1', family: 4 }
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

function labGrant(origin: string, overrides: Partial<Grant> = {}): Grant {
  return {
    origin,
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 50,
    canRead: candidate => candidate === origin,
    audit: () => {},
    ...overrides,
  }
}

async function listen(server: { listen: (port: number, host: string) => unknown }, host = '127.0.0.1'): Promise<number> {
  server.listen(0, host)
  await new Promise<void>(resolve => (server as unknown as NodeJS.EventEmitter).once('listening', () => resolve()))
  const address = (server as unknown as { address: () => { port: number } }).address()
  return address.port
}

type H2Fixture = {
  origin: string
  paths: string[]
  bodies: string[]
  methods: string[]
  userAgents: string[]
  requestHeaders: Array<Record<string, string | string[] | undefined>>
  receiveTimestamps: number[]
  sessions: () => number
  close: () => Promise<void>
}

async function h2Fixture(): Promise<H2Fixture> {
  const paths: string[] = []
  const bodies: string[] = []
  const methods: string[] = []
  const userAgents: string[] = []
  const requestHeaders: Array<Record<string, string | string[] | undefined>> = []
  const receiveTimestamps: number[] = []
  let sessionCount = 0
  const activeSessions: http2.ServerHttp2Session[] = []
  const server = http2.createServer()
  server.on('session', session => {
    sessionCount += 1
    activeSessions.push(session)
    session.once('close', () => {
      const idx = activeSessions.indexOf(session)
      if (idx >= 0) activeSessions.splice(idx, 1)
    })
  })
  server.on('stream', (stream: http2.ServerHttp2Stream, headers: http2.IncomingHttpHeaders) => {
    receiveTimestamps.push(Date.now())
    paths.push(String(headers[':path'] ?? ''))
    methods.push(String(headers[':method'] ?? ''))
    userAgents.push(String(headers['user-agent'] ?? ''))
    requestHeaders.push(headers)
    const chunks: Buffer[] = []
    stream.on('data', chunk => chunks.push(Buffer.from(chunk)))
    stream.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      bodies.push(body)
      stream.respond({ ':status': 200, 'content-type': 'text/plain', 'x-served-by': 'h2-fixture' })
      stream.end(`h2:${headers[':method']} ${headers[':path']} ${body}`.trim())
    })
  })
  const port = await listen(server)
  return {
    origin: `http://127.0.0.1:${port}`,
    paths,
    bodies,
    methods,
    userAgents,
    requestHeaders,
    receiveTimestamps,
    sessions: () => sessionCount,
    close: () => new Promise<void>(resolve => {
      for (const session of activeSessions.splice(0)) {
        try { session.destroy() } catch { /* ignore */ }
      }
      server.close(() => resolve())
    }),
  }
}

type H1Fixture = {
  origin: string
  requests: Array<{ method: string; url: string; body: string; headers: Record<string, string | string[] | undefined> }>
  close: () => Promise<void>
}

async function h1Fixture(): Promise<H1Fixture> {
  const requests: H1Fixture['requests'] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.from(chunk)))
    req.on('end', () => {
      requests.push({
        method: req.method ?? '',
        url: req.url ?? '',
        body: Buffer.concat(chunks).toString('utf8'),
        headers: req.headers,
      })
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('h1-ok')
    })
  })
  const port = await listen(server)
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

// ---------------------------------------------------------------------------
// 1. Configuration is fail-closed
// ---------------------------------------------------------------------------

test('v6 transport: HTTP/2, proxy, mTLS and header-profile configuration fail closed', async t => {
  assert.equal(resolveTransportConfig({}).http2, false)
  assert.equal(resolveTransportConfig({ KOVO_HTTP2: '1' }).http2, true)
  assert.equal(resolveTransportConfig({ KOVO_HTTP2: '0' }).http2, false)
  assert.throws(() => resolveTransportConfig({ KOVO_HTTP2: 'yes' }), TransportConfigError)

  assert.throws(() => resolveTransportConfig({ KOVO_EGRESS_PROXY: 'ftp://proxy.example' }), TransportConfigError)
  assert.throws(() => resolveTransportConfig({ KOVO_EGRESS_PROXY: 'not a url' }), TransportConfigError)
  assert.throws(() => resolveTransportConfig({ KOVO_EGRESS_PROXY: 'http://' }), TransportConfigError)
  const proxy = resolveTransportConfig({ KOVO_EGRESS_PROXY: 'socks5h://user:pass@proxy.example:1081' })
  assert.equal(proxy.proxy?.protocol, 'socks5h:')
  assert.equal(proxy.proxy?.port, 1081)
  assert.ok(proxy.proxy?.authorization?.startsWith('Basic '))

  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-mtls-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const keyPath = join(dir, 'client.key')
  const certPath = join(dir, 'client.crt')
  writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { mode: 0o600 })
  writeFileSync(certPath, '-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n')

  assert.throws(() => resolveTransportConfig({ KOVO_MTLS_CERT: certPath }), TransportConfigError)
  assert.throws(() => resolveTransportConfig({ KOVO_MTLS_KEY: keyPath }), TransportConfigError)
  assert.throws(
    () => resolveTransportConfig({ KOVO_MTLS_CERT: join(dir, 'missing.crt'), KOVO_MTLS_KEY: keyPath }),
    TransportConfigError,
  )
  const mtls = resolveTransportConfig({ KOVO_MTLS_CERT: certPath, KOVO_MTLS_KEY: keyPath })
  assert.equal(mtls.mtls?.certPath, certPath)
  assert.match(mtls.mtls?.key ?? '', /BEGIN PRIVATE KEY/)

  assert.throws(() => resolveTransportConfig({ KOVO_AUTHORIZED_HEADERS: '{bad json' }), TransportConfigError)
  assert.throws(
    () => resolveTransportConfig({ KOVO_AUTHORIZED_HEADERS: JSON.stringify({ Host: 'evil.example' }) }),
    TransportConfigError,
  )
  assert.throws(
    () => resolveTransportConfig({ KOVO_AUTHORIZED_HEADERS: JSON.stringify({ 'X-Test': 'a\r\nInjected: 1' }) }),
    TransportConfigError,
  )
  const profile = resolveTransportConfig({
    KOVO_USER_AGENT: 'Authorized-Scanner/1.0',
    KOVO_AUTHORIZED_HEADERS: JSON.stringify({ 'Accept-Language': 'en-US' }),
  })
  assert.equal(profile.headerProfile?.userAgent, 'Authorized-Scanner/1.0')
  assert.equal(profile.headerProfile?.headers['Accept-Language'], 'en-US')

  // Broker construction must fail closed on a bad environment, not silently downgrade.
  await withEnv({ KOVO_EGRESS_PROXY: 'http://proxy.example:3128' }, () => {
    const valid = new RequestBroker({ resolve: async () => [localAddr] })
    assert.match(valid.getTransportSummary().proxy ?? '', /^http:\/\/proxy\.example:3128$/)
    valid.closeTransport()
  })
  await withEnv({ KOVO_EGRESS_PROXY: 'ftp://proxy.example' }, () => {
    assert.throws(() => new RequestBroker({ resolve: async () => [localAddr] }), TransportConfigError)
  })
})

// ---------------------------------------------------------------------------
// 2. HTTP/2 round trip, pooling and HTTP/1.1 fallback
// ---------------------------------------------------------------------------

test('v6 transport: HTTP/2 GET/POST round trip reuses one pooled session; HTTP/1.1 fallback works', async t => {
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const h2 = await h2Fixture()
    t.after(() => h2.close())
    const broker = new RequestBroker({
      resolve: async () => [localAddr],
      transportConfig: { http2: true },
    })
    t.after(() => broker.closeTransport())
    const grant = labGrant(h2.origin)
    const signal = AbortSignal.timeout(10_000)

    const first = await broker.executeHttp({ origin: h2.origin, method: 'GET', pathAndQuery: '/one' }, grant, signal)
    const second = await broker.executeHttp(
      { origin: h2.origin, method: 'POST', pathAndQuery: '/two', body: '{"a":1}', headers: { 'Content-Type': 'application/json' } },
      grant,
      signal,
    )
    assert.equal(first.status, 200)
    assert.match(first.body, /h2:GET \/one/)
    assert.equal(first.respHeaders['x-served-by'], 'h2-fixture')
    assert.equal(second.status, 200)
    assert.match(second.body, /h2:POST \/two \{"a":1\}/)
    assert.equal(h2.sessions(), 1, 'sequential requests must reuse the pooled HTTP/2 session')
    assert.deepEqual(h2.methods, ['GET', 'POST'])
    assert.equal(broker.getTransportSummary().mode, 'http2')

    // A plain HTTP/1.1 peer cannot speak h2: the broker must transparently fall back.
    const h1 = await h1Fixture()
    t.after(() => h1.close())
    const fallbackBroker = new RequestBroker({
      resolve: async () => [localAddr],
      transportConfig: { http2: true },
    })
    t.after(() => fallbackBroker.closeTransport())
    const h1Grant = labGrant(h1.origin)
    const viaFallback = await fallbackBroker.executeHttp(
      { origin: h1.origin, method: 'GET', pathAndQuery: '/legacy?x=1' },
      h1Grant,
      signal,
    )
    assert.equal(viaFallback.status, 200)
    assert.equal(viaFallback.body, 'h1-ok')
    assert.equal(h1.requests.length, 1)
    assert.equal(h1.requests[0].url, '/legacy?x=1')
    assert.equal(fallbackBroker.getTransportSummary().http2, true, 'fallback must not disable the configured mode')
    const again = await fallbackBroker.executeHttp({ origin: h1.origin, method: 'GET', pathAndQuery: '/again' }, h1Grant, signal)
    assert.equal(again.status, 200, 'the downgraded origin keeps working on later requests')
    assert.equal(fallbackBroker.getTransportSummary().http2, true)
  })
})

test('v6 transport: configured authorized User-Agent replaces the hardcoded default only when set', async t => {
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const h2 = await h2Fixture()
    t.after(() => h2.close())
    const profile = resolveTransportConfig({
      KOVO_USER_AGENT: 'Authorized-Scanner/9.1',
      KOVO_AUTHORIZED_HEADERS: JSON.stringify({ 'X-Scope-Approval': 'run-42' }),
    })
    const broker = new RequestBroker({
      resolve: async () => [localAddr],
      transportConfig: { http2: true, headerProfile: profile.headerProfile },
    })
    t.after(() => broker.closeTransport())
    const grant = labGrant(h2.origin)
    await broker.executeHttp({ origin: h2.origin, method: 'GET', pathAndQuery: '/' }, grant, AbortSignal.timeout(10_000))
    assert.equal(h2.userAgents[0], 'Authorized-Scanner/9.1')
    assert.equal(h2.requestHeaders[0]['x-scope-approval'], 'run-42')

    const defaultBroker = new RequestBroker({ resolve: async () => [localAddr], transportConfig: { http2: true } })
    t.after(() => defaultBroker.closeTransport())
    await defaultBroker.executeHttp({ origin: h2.origin, method: 'GET', pathAndQuery: '/default' }, grant, AbortSignal.timeout(10_000))
    assert.match(h2.userAgents[1] ?? '', /^Kovo(?:Hunter)?\//, 'unconfigured runs keep the defensive default UA')
  })
})

test('v6 transport: opt-in egress proxy carries requests and never silently bypasses', async t => {
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const seen: Array<{ path?: string; host?: string; proxyAuth?: string }> = []
    const proxy = createServer((req, res) => {
      seen.push({
        path: req.url,
        host: String(req.headers.host ?? ''),
        proxyAuth: typeof req.headers['proxy-authorization'] === 'string' ? req.headers['proxy-authorization'] : undefined,
      })
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('via-proxy')
    })
    const proxyPort = await listen(proxy)
    t.after(() => new Promise<void>(resolve => {
      proxy.closeAllConnections()
      proxy.close(() => resolve())
    }))

    const h1 = await h1Fixture()
    t.after(() => h1.close())

    const config = resolveTransportConfig({
      KOVO_EGRESS_PROXY: `http://user:pass@127.0.0.1:${proxyPort}`,
    })
    const broker = new RequestBroker({
      resolve: async () => [localAddr],
      transportConfig: { http2: true, proxy: config.proxy },
    })
    t.after(() => broker.closeTransport())
    const result = await broker.executeHttp(
      { origin: h1.origin, method: 'GET', pathAndQuery: '/proxied?a=1' },
      labGrant(h1.origin),
      AbortSignal.timeout(10_000),
    )
    assert.equal(result.status, 200)
    assert.equal(result.body, 'via-proxy')
    assert.equal(h1.requests.length, 0, 'egress must not bypass the configured proxy')
    assert.equal(seen.length, 1)
    assert.equal(seen[0].path, `${h1.origin}/proxied?a=1`, 'plain HTTP through a proxy uses absolute-form')
    assert.equal(seen[0].host, new URL(h1.origin).host)
    assert.match(seen[0].proxyAuth ?? '', /^Basic /)

    // An HTTPS proxy cannot carry a plaintext target; fail closed instead of bypassing it.
    const httpsProxyBroker = new RequestBroker({
      resolve: async () => [localAddr],
      transportConfig: { http2: false, proxy: resolveTransportConfig({ KOVO_EGRESS_PROXY: 'https://127.0.0.1:9' }).proxy },
    })
    t.after(() => httpsProxyBroker.closeTransport())
    await assert.rejects(
      httpsProxyBroker.executeHttp(
        { origin: h1.origin, method: 'GET', pathAndQuery: '/leak' },
        labGrant(h1.origin),
        AbortSignal.timeout(10_000),
      ),
      TransportConfigError,
    )
    assert.equal(h1.requests.length, 0)
  })
})

// ---------------------------------------------------------------------------
// 3. Single-connection synchronized race burst
// ---------------------------------------------------------------------------

test('v6 transport: HTTP/2 race burst uses one connection and releases stream headers together', async t => {
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const h2 = await h2Fixture()
    t.after(() => h2.close())
    const broker = new RequestBroker({ resolve: async () => [localAddr], transportConfig: { http2: true } })
    t.after(() => broker.closeTransport())
    const grant = labGrant(h2.origin, { tier: 2 })
    const requests = Array.from({ length: 5 }, (_, i) => ({
      origin: h2.origin,
      method: 'GET' as const,
      pathAndQuery: `/race/${i}`,
    }))
    const burst = await broker.executeRaceBurst(requests, grant, AbortSignal.timeout(10_000))

    assert.equal(burst.summary.total, 5)
    assert.deepEqual(burst.summary.statusCounts, { 200: 5 })
    assert.equal(h2.sessions(), 1, 'a synchronized burst must share a single HTTP/2 connection')
    assert.equal(h2.receiveTimestamps.length, 5)
    const spread = Math.max(...h2.receiveTimestamps) - Math.min(...h2.receiveTimestamps)
    // Structural assertion: one connection, all five HEADERS released inside one barrier turn.
    assert.ok(spread <= 100, `expected sub-100ms server arrival spread, got ${spread}ms`)
    assert.equal(burst.results.every(result => result.status === 200), true)
  })
})

// ---------------------------------------------------------------------------
// 4. Error-safe circuit breakers
// ---------------------------------------------------------------------------

test('v6 transport: bounded plain 500 under error-inducing probe is evidence while 502, transport errors, and 429s trip the breaker', async t => {
  let clock = 1_000_000
  let mode: 'probe5xx' | 'transport' | '429' | 'ok' = 'probe5xx'
  const broker = new RequestBroker({
    now: () => clock,
    circuit5xxThreshold: 2,
    circuit429Threshold: 2,
    circuitBackoffBaseMs: 100,
    resolve: async () => [publicAddr],
    transport: async url => {
      if (mode === 'probe5xx') {
        return url.pathname.includes('gateway')
          ? { status: 502, headers: {}, body: 'bad gateway' }
          : { status: 500, headers: {}, body: 'parser error' }
      }
      if (mode === '429') return { status: 429, headers: {}, body: 'slow down' }
      if (mode === 'transport') throw Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })
      return { status: 200, headers: {}, body: 'ok' }
    },
  })
  const origin = 'https://app.v6circuit.example'
  const grant = labGrant(origin, { allowLocalLab: false, canRead: o => o === origin, tier: 2 })
  const signal = AbortSignal.timeout(5_000)

  // Bounded plain 500 responses under an error-inducing probeClass stay evidence without tripping.
  for (let i = 0; i < 4; i += 1) {
    const result = await broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: `/crash/${i}`, probeClass: 'sqli_boolean' },
      grant,
      signal,
    )
    assert.equal(result.status, 500, 'bounded plain 500 is returned as evidence, never masked')
  }
  let state = broker.getCircuitState(origin)
  assert.equal(state.open, false)
  assert.equal(broker.isRouteCircuitOpen(origin, '/crash/*'), false)
  assert.equal(state.probeInduced5xx, 4, 'plain probe-induced 500s are accounted separately')
  assert.equal(state.failures5xx, 0)

  // Origin-down gateway status (502) is NEVER exempt, even under an injection probeClass.
  const firstGateway = await broker.executeHttp(
    { origin, method: 'GET', pathAndQuery: '/gateway', probeClass: 'ssti_math' },
    grant,
    signal,
  )
  assert.equal(firstGateway.status, 502)
  assert.equal(broker.getCircuitState(origin).failures5xx, 1, '502 must count against origin-down failures5xx')
  await assert.rejects(
    broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: '/gateway', probeClass: 'ssti_math' },
      grant,
      signal,
    ),
    (err: unknown) => err instanceof BrokerCircuitOpen,
    '502 burst under injection probeClass MUST open the origin breaker',
  )
  assert.equal(broker.isCircuitOpen(origin), true)
  state = broker.getCircuitState(origin)
  assert.equal(state.probeInduced5xx, 4, '502 must never be classified as probeInduced5xx')
  assert.equal(state.failures5xx, 2)

  // Recover from the 502 origin trip before exercising transport-failure and 429 trips.
  clock += state.backoffMs + 1
  mode = 'ok'
  const after502 = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/health' }, grant, signal)
  assert.equal(after502.status, 200)
  // Advance past the 30s accounting window so prior 502s do not carry over into transport checks.
  clock += 31_000

  // A transport failure is real unavailability and must trip the origin breaker.
  mode = 'transport'
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/net', probeClass: 'sqli_boolean' }, grant, signal),
  )
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/net2', probeClass: 'sqli_boolean' }, grant, signal),
    (err: unknown) => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(origin), true)
  state = broker.getCircuitState(origin)
  assert.ok(state.backoffMs >= 100)
  assert.equal(state.consecutiveOpens, 1)

  // Backoff recovers automatically: after the window a healthy probe closes the breaker.
  clock += state.backoffMs + 1
  assert.equal(broker.isCircuitOpen(origin), false, 'breaker half-opens automatically after backoff')
  mode = 'ok'
  const recovered = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/net3' }, grant, signal)
  assert.equal(recovered.status, 200)
  state = broker.getCircuitState(origin)
  assert.equal(state.open, false)
  assert.equal(state.consecutiveOpens, 0)
  assert.equal(state.backoffMs, 0)

  // 429 pressure still trips (and still trips during an active probe).
  mode = '429'
  await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/limit1', probeClass: 'sqli_boolean' }, grant, signal)
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/limit2', probeClass: 'sqli_boolean' }, grant, signal),
    (err: unknown) => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(origin), true)
})

test('v6 transport: per-origin exponential backoff doubles on consecutive trips and recovers', async t => {
  let clock = 5_000_000
  let failing = true
  const broker = new RequestBroker({
    now: () => clock,
    circuit5xxThreshold: 1,
    circuitBackoffBaseMs: 100,
    circuitBackoffMaxMs: 400,
    resolve: async () => [publicAddr],
    transport: async () => (failing
      ? { status: 503, headers: {}, body: 'down' }
      : { status: 200, headers: {}, body: 'ok' }),
  })
  const origin = 'https://app.v6backoff.example'
  const grant = labGrant(origin, { allowLocalLab: false, canRead: o => o === origin, tier: 2 })
  const signal = AbortSignal.timeout(5_000)
  const trip = async () => {
    clock += 1
    await assert.rejects(
      broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/x' }, grant, signal),
      (err: unknown) => err instanceof BrokerCircuitOpen,
    )
    const state = broker.getCircuitState(origin)
    assert.equal(state.open, true)
    return state
  }

  const first = await trip()
  assert.equal(first.backoffMs, 100)
  clock += first.backoffMs
  const second = await trip()
  assert.equal(second.backoffMs, 200, 'second consecutive trip doubles the backoff')
  clock += second.backoffMs
  const third = await trip()
  assert.equal(third.backoffMs, 400, 'third trip doubles again')
  clock += third.backoffMs
  const fourth = await trip()
  assert.equal(fourth.backoffMs, 400, 'backoff is capped at circuitBackoffMaxMs')

  // Automatic recovery once a request succeeds.
  clock += fourth.backoffMs
  failing = false
  const ok = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/x' }, grant, signal)
  assert.equal(ok.status, 200)
  const recovered = broker.getCircuitState(origin)
  assert.equal(recovered.open, false)
  assert.equal(recovered.consecutiveOpens, 0)
})

test('v6 transport: circuit state is exposed per origin and per route for diagnostics', async () => {
  let clock = 9_000_000
  const broker = new RequestBroker({
    now: () => clock,
    circuit5xxThreshold: 2,
    circuitCooldownMs: 1_000,
    resolve: async () => [publicAddr],
    transport: async url => (url.pathname.startsWith('/crash')
      ? { status: 500, headers: {}, body: 'boom' }
      : { status: 200, headers: {}, body: 'ok' }),
  })
  const origin = 'https://app.v6state.example'
  const grant = labGrant(origin, { allowLocalLab: false, canRead: o => o === origin, tier: 2 })
  const signal = AbortSignal.timeout(5_000)
  await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/crash/1' }, grant, signal)
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/crash/2' }, grant, signal),
    (err: unknown) => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(origin), false, 'route 5xx must not open the origin-wide breaker')
  const route = broker.getRouteCircuitState(origin, '/crash/*')
  assert.equal(route.open, true)
  assert.equal(route.consecutiveOpens, 1)
  assert.ok(route.openUntil !== null)
  clock += 1_000
  assert.equal(broker.getRouteCircuitState(origin, '/crash/*').open, false)
  const sibling = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/healthy' }, grant, signal)
  assert.equal(sibling.status, 200)
})

// ---------------------------------------------------------------------------
// 5. Scope and exact approvals still run before the h2 transport
// ---------------------------------------------------------------------------

test('v6 transport: h2 path keeps scope denial, per-instance approvals and race-burst approvals', async t => {
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const h2 = await h2Fixture()
    t.after(() => h2.close())
    const broker = new RequestBroker({ resolve: async () => [localAddr], transportConfig: { http2: true } })
    t.after(() => broker.closeTransport())
    const signal = AbortSignal.timeout(10_000)

    const scoped = labGrant(h2.origin, { canRead: () => false })
    await assert.rejects(
      broker.executeHttp({ origin: h2.origin, method: 'GET', pathAndQuery: '/scope' }, scoped, signal),
      BrokerDenied,
    )

    const approvals: Array<{ method: string; path: string; race: boolean | undefined }> = []
    const gate = labGrant(h2.origin, {
      isStateChangeApproved: (_origin, method, path, context) => {
        approvals.push({ method, path, race: context?.isRaceBurst })
        return false
      },
    })
    await assert.rejects(
      broker.executeHttp({ origin: h2.origin, method: 'POST', pathAndQuery: '/write', body: '{"v":1}' }, gate, signal),
      BrokerApprovalRequired,
    )
    await assert.rejects(
      broker.executeRaceBurst([
        { origin: h2.origin, method: 'POST', pathAndQuery: '/burst', body: '{"v":1}' },
        { origin: h2.origin, method: 'POST', pathAndQuery: '/burst', body: '{"v":1}' },
      ], gate, signal),
      BrokerApprovalRequired,
    )
    assert.equal(h2.paths.length, 0, 'no bytes may reach the target without exact approval')
    assert.equal(approvals.length, 2)
    assert.equal(approvals[1].race, true, 'race-burst approvals are fingerprinted as such')

    const ok = await broker.executeRaceBurst([
      { origin: h2.origin, method: 'POST', pathAndQuery: '/burst', body: '{"v":1}' },
      { origin: h2.origin, method: 'POST', pathAndQuery: '/burst', body: '{"v":1}' },
    ], labGrant(h2.origin, { isStateChangeApproved: () => true }), signal)
    assert.equal(ok.summary.statusCounts['200'], 2)
  })
})

// ---------------------------------------------------------------------------
// 6. WebSocket turn-aware session helper
// ---------------------------------------------------------------------------

function wsServerFrame(opcode: number, payload: Buffer, fin = true): Buffer {
  const len = payload.length
  const header = len < 126
    ? Buffer.from([(fin ? 0x80 : 0) | opcode, len])
    : Buffer.from([(fin ? 0x80 : 0) | opcode, 126, (len >> 8) & 0xff, len & 0xff])
  return Buffer.concat([header, payload])
}

test('v6 transport: WebSocket session awaits frames, reassembles continuations and attaches cookies', async t => {
  const seen: { cookie?: string; path?: string } = {}
  const upgradeSockets: Array<import('node:stream').Duplex> = []
  const server = createServer()
  server.on('upgrade', (req, socket) => {
    upgradeSockets.push(socket)
    socket.on('error', () => {})
    seen.cookie = req.headers.cookie
    seen.path = req.url
    const key = req.headers['sec-websocket-key'] ?? ''
    const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    )
    // One logical text message split across continuations, with an interleaved ping.
    socket.write(wsServerFrame(0x1, Buffer.from('hel'), false))
    socket.write(wsServerFrame(0x9, Buffer.from('ping')))
    socket.write(wsServerFrame(0x0, Buffer.from('lo '), false))
    socket.write(wsServerFrame(0x0, Buffer.from('world'), true))
    socket.write(wsServerFrame(0x1, Buffer.from('{"next":true}'), true))
  })
  const port = await listen(server)
  t.after(() => new Promise<void>(resolve => {
    for (const socket of upgradeSockets.splice(0)) socket.destroy()
    server.closeAllConnections()
    server.close(() => resolve())
  }))

  const session = await WebSocketSession.connect(
    new URL(`ws://127.0.0.1:${port}/socket`),
    localAddr,
    { cookie: 'sid=v6-session', headers: { Origin: `http://127.0.0.1:${port}` }, timeoutMs: 5_000 },
  )
  t.after(() => session.close())
  assert.equal(session.handshake.accepted, true)
  assert.equal(session.handshake.status, 101)
  assert.equal(seen.cookie, 'sid=v6-session')
  assert.equal(seen.path, '/socket')

  const message = await session.nextMessage(5_000)
  assert.ok(message)
  assert.equal(message.opcode, 'text')
  assert.equal(message.text, 'hello world', 'continuation frames must be reassembled in order')

  const json = await session.nextJson<{ next: boolean }>(5_000)
  assert.deepEqual(json, { next: true })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    // Opt-in broker wiring: turns are ignored unless wsSessionEnabled is set.
    const brokerDefault = new RequestBroker({ resolve: async () => [localAddr], transportConfig: { http2: false } })
    const brokerOptIn = new RequestBroker({
      resolve: async () => [localAddr],
      transportConfig: { http2: false },
      wsSessionEnabled: true,
    })
    t.after(() => { brokerDefault.closeTransport(); brokerOptIn.closeTransport() })
    const grant = labGrant(`http://127.0.0.1:${port}`)
    // Without opt-in the legacy probe path runs (and simply sees the handshake + no turns).
    const legacy = await brokerDefault.probeWebsocket(
      { origin: `ws://127.0.0.1:${port}`, pathAndQuery: '/socket', turns: [{ send: 'hi', awaitMessages: 1 }] },
      grant,
      AbortSignal.timeout(10_000),
    )
    assert.equal(legacy.connected, true)
    // With opt-in the turn-aware session path runs.
    const optIn = await brokerOptIn.probeWebsocket(
      { origin: `ws://127.0.0.1:${port}`, pathAndQuery: '/socket', turns: [{ awaitMessages: 1 }] },
      grant,
      AbortSignal.timeout(10_000),
    )
    assert.equal(optIn.connected, true)
    assert.ok(optIn.receivedFrames >= 1)
    assert.match(optIn.frames.find(frame => frame.direction === 'received')?.data ?? '', /hello world/)
  })
})
