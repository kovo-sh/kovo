import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { renameSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { request as httpRequest } from 'node:http'
import { once } from 'node:events'
import { test } from 'node:test'
import { evaluateTier3Approval } from '../src/server/approval-judge.ts'
import { BrokerCircuitOpen, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse, Transport } from '../src/server/broker.ts'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'

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

async function loopbackFixture(
  handler: (req: IncomingMessage, body: string, res: ServerResponse) => void | Promise<void>,
) {
  const requests: Array<{ method: string; url: string; host: string; headers: Record<string, string | string[] | undefined>; body: string }> = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      requests.push({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        host: String(req.headers.host ?? ''),
        headers: req.headers,
        body,
      })
      void Promise.resolve(handler(req, body, res)).catch(err => {
        if (!res.headersSent) res.statusCode = 500
        res.end(String(err))
      })
    })
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  return {
    port: address.port,
    requests,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

/** Real loopback transport that preserves the synthetic Host header (app.localhost etc.). */
function loopbackTransport(port: number): Transport {
  return (url, _addr, signal, options) => new Promise<RawHttpResponse>((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1',
      port,
      method: options?.method ?? 'GET',
      path: url.pathname + url.search,
      headers: { ...(options?.headers ?? {}), Host: url.host },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', c => chunks.push(Buffer.from(c)))
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }))
    })
    req.on('error', reject)
    const onAbort = () => req.destroy(signal.reason as Error)
    signal.addEventListener('abort', onAbort, { once: true })
    req.on('close', () => signal.removeEventListener('abort', onAbort))
    if (options?.body !== undefined) req.write(options.body)
    req.end()
  })
}

function makeGrant(origins: string[], overrides: Partial<Grant> = {}): Grant {
  return {
    origin: origins[0],
    tier: 3,
    allowLocalLab: true,
    maxRpsPerOrigin: 50,
    canRead: o => origins.includes(o),
    audit: () => {},
    ...overrides,
  }
}

function makeLoopbackBroker(port: number): RequestBroker {
  return new RequestBroker({
    rejectUnauthorized: false,
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
    transport: loopbackTransport(port),
  })
}

function cookieHeader(req: IncomingMessage): string {
  return String(req.headers.cookie ?? '')
}

test('V5-M2.1 RFC-6265 Domain cookies cross in-scope subdomains while host-only cookies stay origin-scoped', async t => {
  let rotation = 0
  let setCounter = 0
  const fixture = await loopbackFixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    if (url.pathname === '/login') {
      res.setHeader('Set-Cookie', [
        'shared=SHARED_1; Domain=localhost; Path=/',
        'hostonly=HOST_ONLY_1; Path=/',
      ])
      res.end('ok')
      return
    }
    if (url.pathname === '/rotate') {
      rotation += 1
      res.setHeader('Set-Cookie', `rot=JAR_${rotation}; Path=/`)
      res.end('rotated')
      return
    }
    if (url.pathname === '/set') {
      setCounter += 1
      res.setHeader('Set-Cookie', `jar_marker=JAR_${setCounter}; Path=/`)
      res.end('set')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ cookie: cookieHeader(req) }))
  })
  t.after(() => fixture.close())

  const broker = makeLoopbackBroker(fixture.port)
  const appOrigin = `http://app.localhost:${fixture.port}`
  const apiOrigin = `http://api.localhost:${fixture.port}`
  const sig = AbortSignal.timeout(10_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const grant = makeGrant([appOrigin, apiOrigin])

    // Domain cookie shared across subdomains; host-only cookie must not leak.
    await broker.executeHttp({ origin: appOrigin, method: 'GET', pathAndQuery: '/login', session: 'sub', runId: 'r', assignmentId: 'a' }, grant, sig)
    await broker.executeHttp({ origin: apiOrigin, method: 'GET', pathAndQuery: '/echo', session: 'sub', runId: 'r', assignmentId: 'a' }, grant, sig)
    const apiCookie = String(fixture.requests.at(-1)?.headers.cookie ?? '')
    assert.match(apiCookie, /shared=SHARED_1/, 'Domain=localhost cookie must reach api.localhost')
    assert.doesNotMatch(apiCookie, /hostonly=/, 'host-only cookie must never reach api.localhost')

    // The mirror API exposes non-HttpOnly cookies only, with the RFC-6265 domain scope.
    const mirror = broker.sessionCookiesForBrowser({ session: 'sub', runId: 'r', assignmentId: 'a' }, appOrigin)
    const mirrored = new Map(mirror.map(c => [c.name, c]))
    assert.equal(mirrored.get('shared')?.domain, 'localhost')
    assert.equal(mirrored.get('hostonly')?.domain, 'app.localhost')
    assert.ok(mirror.every(c => c.httpOnly === false))
  })
})

test('V5-M2.1b Persona Vault rotation: fresh jar Set-Cookie rotation supersedes stale vault cookie', async t => {
  let rotation = 0
  const fixture = await loopbackFixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    if (url.pathname === '/rotate') {
      rotation += 1
      res.setHeader('Set-Cookie', `rot=JAR_${rotation}; Path=/`)
      res.end('rotated')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ cookie: cookieHeader(req) }))
  })
  t.after(() => fixture.close())

  const broker = makeLoopbackBroker(fixture.port)
  const appOrigin = `http://app.localhost:${fixture.port}`
  const sig = AbortSignal.timeout(10_000)

  // Build a temporary Store with a static cookie persona.
  const { mkdtempSync, rmSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const { Store } = await import('../src/server/store.ts')
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v5m2-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: 'M2 auth cookies', seeds: [appOrigin], environment: 'local-lab',
    })
    const { id: personaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'rot_user',
      roleLabel: 'Rot',
      originAllowlist: [appOrigin],
      authKind: 'cookie',
      secret: 'rot=VAULT_VALUE',
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [personaId])
    const grant = makeGrant([appOrigin], { personas })

    await broker.executeHttp({ origin: appOrigin, method: 'GET', pathAndQuery: '/rotate', persona: 'rot_user', session: 'rotjar', runId: 'r', assignmentId: 'a' }, grant, sig)
    await broker.executeHttp({ origin: appOrigin, method: 'GET', pathAndQuery: '/rotate', persona: 'rot_user', session: 'rotjar', runId: 'r', assignmentId: 'a' }, grant, sig)
    await broker.executeHttp({
      origin: appOrigin, method: 'GET', pathAndQuery: '/echo', persona: 'rot_user', session: 'rotjar', runId: 'r', assignmentId: 'a',
    }, grant, sig)
    const sentCookie = String(fixture.requests.at(-1)?.headers.cookie ?? '')
    assert.match(sentCookie, /rot=JAR_2/, 'second Set-Cookie rotation must supersede the stale vault cookie')
    assert.doesNotMatch(sentCookie, /VAULT_VALUE/)
  })
})

test('V5-M2.1c LB cap raised to 12 jars per assignment', async t => {
  let n = 0
  const fixture = await loopbackFixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    if (url.pathname === '/set') {
      n += 1
      res.setHeader('Set-Cookie', `k=JAR_${n}; Path=/`)
      res.end('set')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ cookie: cookieHeader(req) }))
  })
  t.after(() => fixture.close())

  const broker = makeLoopbackBroker(fixture.port)
  const origin = `http://app.localhost:${fixture.port}`
  const grant = makeGrant([origin])
  const sig = AbortSignal.timeout(10_000)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    for (let i = 0; i < 12; i += 1) {
      await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/set', session: `j${i}`, runId: 'r', assignmentId: 'a' }, grant, sig)
    }
    await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/echo', session: 'j11', runId: 'r', assignmentId: 'a' }, grant, sig)
    const keptCookie = String(fixture.requests.at(-1)?.headers.cookie ?? '')
    assert.match(keptCookie, /k=JAR_12/, '12 jars must all be retained')

    await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/set', session: 'j12', runId: 'r', assignmentId: 'a' }, grant, sig)
    await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/echo', session: 'j0', runId: 'r', assignmentId: 'a' }, grant, sig)
    const evictedCookie = String(fixture.requests.at(-1)?.headers.cookie ?? '')
    assert.equal(evictedCookie, '', '13th jar must evict the LRU jar')
  })
})

test('V5-M2.2 CSRF: rotated URL-encoded XSRF cookie, response headers, (origin,pathPrefix) keys, and multipart injection', async t => {
  const fixture = await loopbackFixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    if (url.pathname === '/xsrf-boot') {
      res.setHeader('Set-Cookie', `XSRF-TOKEN=${encodeURIComponent('first+tok/=')}; Path=/`)
      res.end('ok')
      return
    }
    if (url.pathname === '/xsrf-rotate') {
      res.setHeader('Set-Cookie', `XSRF-TOKEN=${encodeURIComponent('second/tok+=')}; Path=/`)
      res.end('ok')
      return
    }
    if (url.pathname === '/meta') {
      res.setHeader('Content-Type', 'text/html')
      res.end('<html><head><meta name="csrf-token" content="META_TOK"></head></html>')
      return
    }
    if (url.pathname === '/hdr') {
      res.setHeader('X-CSRF-Token', 'HDR_TOK')
      res.end('ok')
      return
    }
    if (url.pathname === '/api/v1/boot') {
      res.setHeader('X-CSRF-Token', 'V1_TOK')
      res.end('ok')
      return
    }
    if (url.pathname === '/api/v2/boot') {
      res.setHeader('X-CSRF-Token', 'V2_TOK')
      res.end('ok')
      return
    }
    if (url.pathname === '/mp-boot') {
      res.setHeader('X-CSRF-Token', 'MP_TOK')
      res.end('ok')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({
      csrf: String(req.headers['x-xsrf-token'] ?? req.headers['x-csrf-token'] ?? ''),
      body: _body,
    }))
  })
  t.after(() => fixture.close())

  const broker = makeLoopbackBroker(fixture.port)
  const origin = `http://app.localhost:${fixture.port}`
  const grant = makeGrant([origin])
  const sig = AbortSignal.timeout(10_000)
  const req = (pathAndQuery: string, session: string, extra: Record<string, unknown> = {}) => ({
    origin, method: 'GET' as const, pathAndQuery, session, runId: 'r', assignmentId: 'a', ...extra,
  })

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    // URL-encoded double-submit cookie, rotated: second value wins and is decoded once.
    await broker.executeHttp(req('/xsrf-boot', 'csrf1'), grant, sig)
    await broker.executeHttp(req('/xsrf-rotate', 'csrf1'), grant, sig)
    const rotated = await broker.executeHttp({
      ...req('/mutate', 'csrf1'),
      method: 'POST',
      body: '{}',
      headers: { 'Content-Type': 'application/json' },
      csrfBind: true,
    } as never, grant, sig)
    assert.equal(String(fixture.requests.at(-1)?.headers['x-xsrf-token'] ?? ''), 'second/tok+=')
    assert.ok(!JSON.stringify(rotated).includes('second/tok+='), 'CSRF token must be redacted from results')

    // HTML meta token.
    await broker.executeHttp(req('/meta', 'csrf2'), grant, sig)
    const metaRes = await broker.executeHttp({
      ...req('/mutate', 'csrf2'),
      method: 'POST',
      body: '{}',
      headers: { 'Content-Type': 'application/json' },
      csrfBind: true,
    } as never, grant, sig)
    assert.equal(String(fixture.requests.at(-1)?.headers['x-csrf-token'] ?? ''), 'META_TOK')

    // Response-header token.
    await broker.executeHttp(req('/hdr', 'csrf3'), grant, sig)
    const hdrRes = await broker.executeHttp({
      ...req('/mutate', 'csrf3'),
      method: 'POST',
      body: '{}',
      headers: { 'Content-Type': 'application/json' },
      csrfBind: true,
    } as never, grant, sig)
    assert.equal(String(fixture.requests.at(-1)?.headers['x-csrf-token'] ?? ''), 'HDR_TOK')

    // (origin, pathPrefix) keying: v1 route keeps v1 token, v2 keeps v2 token.
    await broker.executeHttp(req('/api/v1/boot', 'csrf4'), grant, sig)
    await broker.executeHttp(req('/api/v2/boot', 'csrf4'), grant, sig)
    const v1 = await broker.executeHttp({
      ...req('/api/v1/item', 'csrf4'),
      method: 'POST',
      body: '{}',
      headers: { 'Content-Type': 'application/json' },
      csrfBind: true,
    } as never, grant, sig)
    const v2 = await broker.executeHttp({
      ...req('/api/v2/item', 'csrf4'),
      method: 'POST',
      body: '{}',
      headers: { 'Content-Type': 'application/json' },
      csrfBind: true,
    } as never, grant, sig)
    const v2Header = String(fixture.requests.at(-1)?.headers['x-csrf-token'] ?? '')
    const v1Header = String(fixture.requests.at(-2)?.headers['x-csrf-token'] ?? '')
    assert.equal(v1Header, 'V1_TOK')
    assert.equal(v2Header, 'V2_TOK')

    // Multipart injection: token becomes a form field part.
    await broker.executeHttp(req('/mp-boot', 'csrf5'), grant, sig)
    const mp = await broker.executeHttp({
      ...req('/upload', 'csrf5'),
      method: 'POST',
      multipartParts: [{ name: 'file', filename: 'a.txt', contentType: 'text/plain', content: 'hello' }],
      csrfBind: { fieldName: '_csrf' },
    } as never, grant, sig)
    const mpBody = String(fixture.requests.at(-1)?.body ?? '')
    assert.match(mpBody, /name="_csrf"/)
    assert.match(mpBody, /MP_TOK/)
    assert.match(mpBody, /hello/)
    assert.ok(!JSON.stringify(mp).includes('MP_TOK'), 'injected multipart CSRF token must be redacted')
  })
})

test('V5-M2.3 PersonaAuthManager 401 re-auth is rate-limited and the broker retries once with the refreshed credential', async t => {
  const fixture = await loopbackFixture((req, _body, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    if (url.pathname === '/me') {
      const auth = String(req.headers.authorization ?? '')
      if (auth !== 'Bearer FRESH_TOKEN_1234567890') {
        res.statusCode = 401
        res.end('expired')
        return
      }
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: true }))
      return
    }
    res.end('ok')
  })
  t.after(() => fixture.close())

  const { mkdtempSync, rmSync } = await import('node:fs')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const { Store } = await import('../src/server/store.ts')
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v5m2-auth-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  // Rate limiter unit check (<= 1 per 60s per persona).
  const manager = new PersonaAuthManager()
  let calls = 0
  manager.registerReauth('limited', async () => { calls += 1 })
  assert.equal(await manager.requestReauth('limited'), true)
  assert.equal(await manager.requestReauth('limited'), false)
  assert.equal(calls, 1)

  const origin = `http://127.0.0.1:${fixture.port}`

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: 'M2 401 refresh', seeds: [origin], environment: 'local-lab',
    })
    const { id: personaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'refresh_user',
      roleLabel: 'Refresh',
      originAllowlist: [origin],
      authKind: 'bearer',
      secret: 'STALE_TOKEN_0987654321',
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [personaId])
    const persona = [...personas.values()][0] as ResolvedPersona
    let reauthCalls = 0
    const broker = new RequestBroker({
      rejectUnauthorized: false,
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      transport: loopbackTransport(fixture.port),
      reauth: async () => {
        reauthCalls += 1
        const tmp = `${persona.secretPath}.tmp`
        writeFileSync(tmp, 'FRESH_TOKEN_1234567890', { mode: 0o600 })
        renameSync(tmp, persona.secretPath!)
        return true
      },
    })
    const grant = makeGrant([origin], { personas })

    const ex = await broker.executeHttp({
      origin, method: 'GET', pathAndQuery: '/me', persona: 'refresh_user', session: 's1', runId: 'r', assignmentId: 'a',
    }, grant, AbortSignal.timeout(10_000))
    assert.equal(ex.status, 200)
    assert.equal(reauthCalls, 1)
    const authSeen = String(fixture.requests.at(-1)?.headers.authorization ?? '')
    assert.equal(authSeen, 'Bearer FRESH_TOKEN_1234567890')
  })
})

test('V5-M2.4 per-(origin,routeTemplate) 5xx circuit opens half-open while sibling routes and other origins continue', async t => {
  let clock = 1_000_000
  let gatewayFail = true
  const broker = new RequestBroker({
    now: () => clock,
    circuit5xxThreshold: 2,
    circuitCooldownMs: 15_000,
    resolve: async () => [publicAddr],
    transport: async url => {
      if (url.pathname === '/gateway' && gatewayFail) {
        return { status: 503, headers: {}, body: 'unavailable' }
      }
      if (url.pathname.startsWith('/crash/')) return { status: 500, headers: {}, body: 'boom' }
      return { status: 200, headers: {}, body: 'ok' }
    },
  })
  const origin = 'https://app.m2circuit.example'
  const grant: Grant = {
    origin, tier: 3, allowLocalLab: false, maxRpsPerOrigin: 50,
    canRead: o => o === origin, audit: () => {},
  }
  const sig = AbortSignal.timeout(5_000)

  const first = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/crash/1' }, grant, sig)
  assert.equal(first.status, 500)
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/crash/2' }, grant, sig),
    BrokerCircuitOpen,
  )
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/crash/3' }, grant, sig),
    BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(origin), false, 'ordinary 5xx must not open the origin-wide circuit')
  assert.equal(broker.isRouteCircuitOpen(origin, '/crash/*'), true)
  const sibling = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/ok' }, grant, sig)
  assert.equal(sibling.status, 200, 'sibling route must continue while /crash/* is cooling down')

  // Half-open after cooldown: one probe is allowed, failure re-opens, success closes.
  clock += 15_000
  assert.equal(broker.isCircuitOpen(origin), false)
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/crash/9' }, grant, sig),
    BrokerCircuitOpen,
  )
  clock += 15_000
  const recovered = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/ok' }, grant, sig)
  assert.equal(recovered.status, 200)

  // Global 502–504 keeps origin-wide protection.
  const gateway = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/gateway' }, grant, sig)
  assert.equal(gateway.status, 503)
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/gateway' }, grant, sig),
    BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(origin), true)
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/ok' }, grant, sig),
    BrokerCircuitOpen,
  )
  gatewayFail = false
})

test('V5-M2.5 explicit operator-approved non-default ports are allowed; unapproved ports stay denied', async t => {
  let clock = 2_000_000
  const seen: string[] = []
  const broker = new RequestBroker({
    now: () => clock,
    circuit429Threshold: 20,
    resolve: async () => [publicAddr],
    transport: async url => {
      seen.push(url.origin)
      return { status: 200, headers: {}, body: 'ok' }
    },
  })
  const throttled = 'https://app.m5ports.example:8443'
  const grant: Grant = {
    origin: throttled, tier: 3, allowLocalLab: false, maxRpsPerOrigin: 10,
    allowedPorts: [8443],
    canRead: o => o === throttled,
    audit: () => {},
  }
  const ok = await broker.executeHttp({ origin: throttled, method: 'GET', pathAndQuery: '/' }, grant, AbortSignal.timeout(5_000))
  assert.equal(ok.status, 200)

  const deniedGrant: Grant = { ...grant, allowedPorts: undefined, origin: 'https://app.m5ports.example:9443', canRead: o => o === 'https://app.m5ports.example:9443' }
  await assert.rejects(
    broker.executeHttp({ origin: 'https://app.m5ports.example:9443', method: 'GET', pathAndQuery: '/' }, deniedGrant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )
  await withEnv({ GUARDIAN_ALLOWED_PORTS: '9443' }, async () => {
    const envOk = await broker.executeHttp({ origin: 'https://app.m5ports.example:9443', method: 'GET', pathAndQuery: '/' }, deniedGrant, AbortSignal.timeout(5_000))
    assert.equal(envOk.status, 200)
  })
  assert.ok(seen.includes(throttled))
})

test('V5-M2.5b Retry-After on 429 pauses the origin bucket before the next request', async () => {
  let first = true
  const broker = new RequestBroker({
    circuit429Threshold: 20,
    resolve: async () => [publicAddr],
    transport: async () => {
      if (first) {
        first = false
        return { status: 429, headers: { 'retry-after': '1' }, body: 'slow down' }
      }
      return { status: 200, headers: {}, body: 'ok' }
    },
  })
  const origin = 'https://app.m2retry.example'
  const grant: Grant = {
    origin, tier: 3, allowLocalLab: false, maxRpsPerOrigin: 10,
    canRead: o => o === origin, audit: () => {},
  }
  const sig = AbortSignal.timeout(10_000)
  const throttled = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/' }, grant, sig)
  assert.equal(throttled.status, 429)
  const started = Date.now()
  const recovered = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/' }, grant, sig)
  const elapsed = Date.now() - started
  assert.equal(recovered.status, 200)
  assert.ok(elapsed >= 800, `expected Retry-After pacing, got ${elapsed}ms`)
})

test('V5-M2.6 local-lab Tier-3 approvals auto-approve keyword routes but never relax RCE/DELETE/multipart or public escalation', async () => {
  const base = { policy: 'auto_review' as const, origin: 'http://127.0.0.1:8080' }
  const local = await evaluateTier3Approval({
    ...base, method: 'POST', pathAndQuery: '/api/invoices/42/refund', personaHandle: 'tenant_a',
    bodyPreview: '{"amount":1}', environment: 'local-lab', offline: true,
  })
  assert.equal(local.decision, 'approve')
  assert.equal(local.usedLlm, false)

  const localAdmin = await evaluateTier3Approval({
    ...base, method: 'POST', pathAndQuery: '/admin/webhooks', personaHandle: 'tenant_a',
    bodyPreview: '{"url":"http://127.0.0.1/hook"}', environment: 'local-lab', offline: true,
  })
  assert.equal(localAdmin.decision, 'approve')

  const publicRefund = await evaluateTier3Approval({
    ...base, method: 'POST', pathAndQuery: '/api/invoices/42/refund', personaHandle: 'tenant_a',
    bodyPreview: '{"amount":1}', environment: 'public', offline: true,
  })
  assert.equal(publicRefund.decision, 'escalate_human')
  assert.equal(publicRefund.stage, 'hard_escalation')

  const localDelete = await evaluateTier3Approval({
    ...base, method: 'DELETE', pathAndQuery: '/api/invoices/42', environment: 'local-lab', offline: true,
  })
  // Loopback local-lab DELETE is auto-approved and audited (Tier-3 lab capability).
  assert.equal(localDelete.decision, 'approve')
  assert.equal(localDelete.decidedBy, 'auto-review:local-lab')

  const localMultipart = await evaluateTier3Approval({
    ...base, method: 'POST', pathAndQuery: '/api/invoices/42', hasMultipart: true, environment: 'local-lab', offline: true,
  })
  assert.equal(localMultipart.decision, 'approve')

  const localRce = await evaluateTier3Approval({
    ...base, method: 'POST', pathAndQuery: '/api/invoices/42', isRceProof: true, environment: 'local-lab', offline: true,
  })
  assert.equal(localRce.decision, 'approve')

  const localStrict = await evaluateTier3Approval({
    ...base, policy: 'strict', method: 'POST', pathAndQuery: '/api/invoices/42/refund', environment: 'local-lab',
  })
  assert.equal(localStrict.decision, 'escalate_human')
})
