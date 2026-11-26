/** Regression coverage for audit #730 admission, broker, and transport findings. */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { createServer as createTcpServer } from 'node:net'
import test from 'node:test'
import { matchesApprovedEndpointPattern, normalizeApprovalPathPattern } from '../src/server/approval-pattern.ts'
import { BrokerApprovalRequired, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse, Transport } from '../src/server/broker.ts'
import { RequestAdmissionEngine, validateCallerHeaders } from '../src/server/request-admission.ts'
import type { AdmissionGrant } from '../src/server/request-admission.ts'
import { evaluateScopeRequest, isRouteDenylisted, routePatternForPath } from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import {
  createHttpTransport,
  resolveTransportConfig,
  TransportConfigError,
  WebSocketSession,
} from '../src/server/transport.ts'

const APP_ORIGIN = 'https://app.example.test'
const IDP_ORIGIN = 'https://idp.example.test'
const PUBLIC_ADDRESS: PublicAddress = { address: '93.184.216.34', family: 4 }

type SeenRequest = {
  method: string
  path: string
  headers: Record<string, string>
  body: string | undefined
}

function admissionGrant(overrides: Partial<AdmissionGrant> = {}): AdmissionGrant {
  return {
    tier: 3,
    canRead: origin => origin === APP_ORIGIN || origin === IDP_ORIGIN,
    ...overrides,
  }
}

function brokerGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: APP_ORIGIN,
    tier: 3,
    canRead: origin => origin === APP_ORIGIN || origin === IDP_ORIGIN,
    audit: () => {},
    ...overrides,
  }
}

function scopePolicy(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'prod_readonly',
    targetOrigins: [APP_ORIGIN],
    authOrigins: [IDP_ORIGIN],
    routeDenylist: ['/blocked'],
    ...overrides,
  }
}

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const previous: Record<string, string | undefined> = {}
  for (const [key, value] of Object.entries(vars)) {
    previous[key] = process.env[key]
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
  try {
    return await fn()
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

async function listen(server: ReturnType<typeof createServer> | ReturnType<typeof createTcpServer>): Promise<number> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  return (server.address() as AddressInfo).port
}

async function closeServer(server: ReturnType<typeof createServer> | ReturnType<typeof createTcpServer>): Promise<void> {
  if ('closeAllConnections' in server) server.closeAllConnections()
  await new Promise<void>(resolve => server.close(() => resolve()))
}

// ---------------------------------------------------------------------------
// C1: one canonical path interpretation for admission, scope, leases, approvals
// ---------------------------------------------------------------------------

test('C1: ambiguous path spellings fail closed at admission, scope, denylist, and approval boundaries', () => {
  const engine = new RequestAdmissionEngine({ env: {} })
  const ambiguousPaths = [
    '/safe/../blocked',
    '/safe/%2e%2e/blocked',
    '/safe/%2E%2E/blocked',
    '/safe%2f..%2fblocked',
    '/safe%5c..%5cblocked',
    '/safe\\..\\blocked',
    '/safe/..\\blocked',
  ]
  for (const pathAndQuery of ambiguousPaths) {
    const decision = engine.admit({ origin: APP_ORIGIN, method: 'GET', pathAndQuery }, admissionGrant())
    assert.equal(decision.allowed, false, pathAndQuery)
    assert.equal(decision.reasonCode, 'malformed_path', pathAndQuery)
    assert.equal(routePatternForPath(pathAndQuery), '', pathAndQuery)
    assert.equal(normalizeApprovalPathPattern(pathAndQuery), '', pathAndQuery)
    assert.equal(evaluateScopeRequest(scopePolicy(), {
      origin: APP_ORIGIN, method: 'POST', pathAndQuery, body: '{}',
    }).allowed, false, `${pathAndQuery}: ${decision.reason}`)
    assert.equal(matchesApprovedEndpointPattern({
      origin: APP_ORIGIN, method: 'POST', pathAndQuery,
    }, [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/safe/**' }]), undefined, pathAndQuery)
  }
  assert.equal(engine.admit({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/safe/./item',
  }, admissionGrant()).allowed, true)
})

test('C1: denylist, scope, budget, lease, and exact approval all receive pathname + search', () => {
  const contexts: Array<{ source: string; pathAndQuery: string }> = []
  const policy = scopePolicy({ mode: 'ephemeral_lab', routeDenylist: ['/blocked'] })
  const grant = admissionGrant({
    scopePolicy: policy,
    approvalLeases: (_origin, _method, pathAndQuery) => {
      contexts.push({ source: 'lease', pathAndQuery })
      return false
    },
    isStateChangeApproved: (_origin, _method, pathAndQuery) => {
      contexts.push({ source: 'approval', pathAndQuery })
      return false
    },
  })
  const engine = new RequestAdmissionEngine({
    env: {},
    budgetCheck: ctx => {
      contexts.push({ source: 'budget', pathAndQuery: ctx.pathAndQuery })
      return { allowed: true }
    },
    rateLimitCheck: ctx => {
      contexts.push({ source: 'rate', pathAndQuery: ctx.pathAndQuery })
      return { allowed: true }
    },
  })

  const canonical = '/api/items/123?view=full&next=/home'
  const decision = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: `${APP_ORIGIN}${canonical}`,
    body: '{}',
  }, grant)
  assert.equal(decision.outcome, 'require_approval')
  assert.equal(decision.normalizedPath, canonical)
  assert.ok(contexts.length >= 4)
  assert.ok(contexts.every(ctx => ctx.pathAndQuery === canonical), JSON.stringify(contexts))
  assert.deepEqual(new Set(contexts.map(ctx => ctx.source)), new Set(['budget', 'rate', 'lease', 'approval']))

  assert.equal(isRouteDenylisted(policy, `${APP_ORIGIN}/blocked?x=1`), true)
  assert.equal(isRouteDenylisted(policy, '/safe/%2e%2e/blocked'), true)
  assert.equal(routePatternForPath('/API/Items/123?x=1'), '/api/items/*')
  assert.equal(routePatternForPath(`${APP_ORIGIN}/API/Items/123?x=1`), '/api/items/*')
})

// ---------------------------------------------------------------------------
// C2: duplicate header names cannot select different admission and wire values
// ---------------------------------------------------------------------------

test('C2: caller header validation rejects case-variant duplicates and returns one canonical map', async () => {
  const duplicateHeaders: Array<Record<string, string>> = [
    { 'Content-Type': 'text/plain', 'content-type': 'application/json' },
    { 'Content-Encoding': 'identity', 'content-encoding': 'gzip' },
    { 'X-Probe': 'control', 'x-probe': 'variant' },
  ]
  for (const headers of duplicateHeaders) {
    const checked = validateCallerHeaders(headers)
    assert.equal(checked.ok, false)
    if (!checked.ok) assert.equal(checked.reasonCode, 'invalid_header')
    const decision = new RequestAdmissionEngine({ env: {} }).admit({
      origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/', headers,
    }, admissionGrant())
    assert.equal(decision.reasonCode, 'invalid_header')
  }

  const checked = validateCallerHeaders({ 'Content-Type': 'application/json', 'X-Probe': 'control' })
  assert.equal(checked.ok, true)
  if (checked.ok) assert.deepEqual(checked.headers, { 'content-type': 'application/json', 'x-probe': 'control' })

  const unsignedHeader = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')
  const unsignedPayload = Buffer.from(JSON.stringify({ sub: 'audit-control' })).toString('base64url')
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (_url, _address, _signal, options) => {
      assert.equal(options?.headers?.authorization, `Bearer ${unsignedHeader}.${unsignedPayload}.`)
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
    },
  })
  try {
    await broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/self-minted-control',
      headers: { Authorization: `Bearer ${unsignedHeader}.${unsignedPayload}.` },
    }, brokerGrant(), AbortSignal.timeout(5_000))
  } finally {
    broker.closeTransport()
  }

  const engine = new RequestAdmissionEngine({ env: {} })
  const decision = engine.admit({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/',
    headers: { 'Content-Type': 'application/json', 'content-encoding': 'identity' },
  }, admissionGrant())
  assert.equal(decision.outcome, 'allow')
  assert.deepEqual(decision.normalizedHeaders, { 'content-type': 'application/json', 'content-encoding': 'identity' })
  assert.equal(decision.classification?.hasCompressedBody, false)
})

// ---------------------------------------------------------------------------
// H6: WebSocket subprotocol tokens and every scripted turn are checked
// ---------------------------------------------------------------------------

test('H6: WebSocket subprotocol offers reject CRLF, controls, separators, and invalid token chars', async () => {
  const invalid = ['chat\r\nInjected: yes', 'chat\n', 'chat\r', 'chat\0', 'chat\u000b', 'chat\u007f', 'chat, other', 'chat other', 'chat/other', '(chat)', '']
  for (const subprotocol of invalid) {
    const decision = new RequestAdmissionEngine({ env: {} }).admit({
      kind: 'websocket', origin: APP_ORIGIN, pathAndQuery: '/socket', wsSubprotocols: [subprotocol],
    }, admissionGrant())
    assert.equal(decision.allowed, false, JSON.stringify(subprotocol))
    assert.equal(decision.reasonCode, 'invalid_header')

    let transportCalled = false
    const broker = new RequestBroker({
      resolve: async () => [PUBLIC_ADDRESS],
      wsTransport: async () => {
        transportCalled = true
        throw new Error('must not be called')
      },
    })
    try {
      await assert.rejects(broker.probeWebsocket({
        origin: APP_ORIGIN, pathAndQuery: '/socket', subprotocols: [subprotocol],
      }, brokerGrant(), AbortSignal.timeout(2_000)), BrokerDenied)
      assert.equal(transportCalled, false)
    } finally {
      broker.closeTransport()
    }
  }

  const accepted = new RequestAdmissionEngine({ env: {} }).admit({
    kind: 'websocket', origin: APP_ORIGIN, pathAndQuery: '/socket', wsSubprotocols: ['chat.1', 'superchat'],
  }, admissionGrant())
  assert.equal(accepted.allowed, true)

  await assert.rejects(WebSocketSession.connect(new URL(`${APP_ORIGIN}/socket`), PUBLIC_ADDRESS, {
    subprotocols: ['chat\r\nInjected: yes'],
  }), TransportConfigError)
})

test('H6: WebSocket turn payloads cannot bypass the destructive denylist in either session mode', async () => {
  const deniedPayload = 'mkfs /dev/audit-canary'
  let transportCalled = false
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    wsTransport: async () => {
      transportCalled = true
      return {
        connected: true, upgradeStatus: 101, upgradeHeaders: {}, subprotocol: null,
        frames: [], closeCode: null, closeReason: null, error: null,
      }
    },
  })
  try {
    for (const wsSessionEnabled of [false, true]) {
      const scoped = new RequestBroker({
        resolve: async () => [PUBLIC_ADDRESS],
        wsSessionEnabled,
        wsTransport: async () => {
          transportCalled = true
          throw new Error('must not be called')
        },
      })
      try {
        await assert.rejects(scoped.probeWebsocket({
          origin: APP_ORIGIN,
          pathAndQuery: '/socket',
          turns: [{ send: 'benign greeting' }, { send: deniedPayload, awaitMessages: 0 }],
        }, brokerGrant(), AbortSignal.timeout(2_000)), BrokerDenied)
      } finally {
        scoped.closeTransport()
      }
    }
    assert.equal(transportCalled, false)
  } finally {
    broker.closeTransport()
  }
})

// ---------------------------------------------------------------------------
// H10: redirect scope/containment, destructive targets, and credential stripping
// ---------------------------------------------------------------------------

test('H10: redirect-hop admission enforces scope roles, route denylist, destructive URLs, and local-lab containment', async () => {
  const engine = new RequestAdmissionEngine({ env: {}, explicitDenylist: { pathPrefixes: ['/explicit'] } })
  const grant = admissionGrant({ scopePolicy: scopePolicy({ mode: 'staging_isolated' }) })
  const blocked = [
    { url: new URL(`${APP_ORIGIN}/blocked`), code: 'staging_denylist' },
    { url: new URL(`${APP_ORIGIN}/explicit`), code: 'explicit_denylist' },
    { url: new URL(`${APP_ORIGIN}/safe%252f..%252fblocked`), code: 'malformed_path' },
    { url: new URL('https://outside.example.test/'), code: 'out_of_scope' },
  ]
  for (const { url, code } of blocked) {
    const decision = engine.admitScopeHop(url, grant, { redirectHop: true })
    assert.equal(decision.allowed, false, url.href)
    assert.equal(decision.reasonCode, code, url.href)
  }
  assert.equal(engine.admitScopeHop(new URL(`${IDP_ORIGIN}/oauth/authorize`), grant, { redirectHop: true }).allowed, true)
  assert.equal(engine.admitScopeHop(new URL(`${IDP_ORIGIN}/admin`), grant).reasonCode, 'auth_origin_active_probe')

  const destructive = new RequestAdmissionEngine({ env: {} }).admitScopeHop(
    new URL(`${APP_ORIGIN}/169.254.169.254/latest/meta-data/`), admissionGrant(), { redirectHop: true },
  )
  assert.equal(destructive.allowed, false)
  assert.equal(destructive.reasonCode, 'destructive_payload')

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const local = new RequestAdmissionEngine({ env: process.env })
    const labGrant = admissionGrant({ allowLocalLab: true, canRead: () => true })
    const escape = local.admitScopeHop(new URL(APP_ORIGIN), labGrant, { redirectHop: true })
    assert.equal(escape.reasonCode, 'local_lab_redirect_escape')
    assert.equal(local.admitScopeHop(new URL('http://127.0.0.1:8080/'), labGrant, { redirectHop: true }).allowed, true)
  })
})

test('H10: cross-origin redirects strip caller and persona auth headers and POST-to-GET strips entity headers', async t => {
  const seen: Array<{ origin: string; request: SeenRequest }> = []
  let appPort = 0
  let idpPort = 0
  const app = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.from(chunk)))
    req.on('end', () => {
      seen.push({ origin: 'app', request: {
        method: req.method ?? '', path: req.url ?? '',
        headers: req.headers as Record<string, string>, body: Buffer.concat(chunks).toString('utf8'),
      } })
      if (req.url?.startsWith('/cross')) {
        res.writeHead(302, { location: `http://127.0.0.1:${idpPort}/landing` })
        res.end()
      } else if (req.url?.startsWith('/rewrite')) {
        res.writeHead(303, { location: '/landing' })
        res.end()
      } else {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('ok')
      }
    })
  })
  const idp = createServer((req, res) => {
    seen.push({ origin: 'idp', request: {
      method: req.method ?? '', path: req.url ?? '', headers: req.headers as Record<string, string>, body: '',
    } })
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  appPort = await listen(app)
  idpPort = await listen(idp)
  t.after(async () => { await closeServer(app); await closeServer(idp) })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({ resolve: async () => [{ address: '127.0.0.1', family: 4 }] })
    t.after(() => broker.closeTransport())
    const grant: Grant = {
      tier: 3,
      allowLocalLab: true,
      canRead: () => true,
      scopePolicy: scopePolicy({
        mode: 'ephemeral_lab',
        targetOrigins: [`http://127.0.0.1:${appPort}`],
        authOrigins: [`http://127.0.0.1:${idpPort}`],
      }),
      audit: () => {},
    }
    const result = await broker.executeHttp({
      origin: grant.scopePolicy!.targetOrigins[0]!,
      method: 'GET',
      pathAndQuery: '/cross',
      followRedirects: true,
      headers: {
        'X-API-Key': 'caller-api-canary',
        'X-Auth-Token': 'caller-auth-canary',
        'X-Keep': 'benign-control',
      },
      persona: 'audit_persona',
      personaHeaders: {
        Authorization: 'Bearer persona-canary',
        Cookie: 'persona=canary',
        'X-API-Key': 'persona-api-canary',
        'X-Auth-Token': 'persona-auth-canary',
      },
    }, grant, AbortSignal.timeout(5_000))
    assert.equal(result.finalOrigin, grant.scopePolicy!.authOrigins![0])
    const target = seen.find(entry => entry.origin === 'idp')!.request
    for (const name of ['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token']) {
      assert.equal(target.headers[name], undefined, name)
    }
    assert.equal(target.headers['x-keep'], 'benign-control')

    seen.length = 0
    const rewritten = await broker.executeHttp({
      origin: grant.scopePolicy!.targetOrigins[0]!,
      method: 'POST',
      pathAndQuery: '/rewrite',
      followRedirects: true,
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'identity',
        'X-Keep': 'benign-control',
      },
      body: '{}',
    }, grant, AbortSignal.timeout(5_000))
    assert.equal(rewritten.method, 'POST')
    assert.deepEqual(seen.map(entry => entry.request.method), ['POST', 'GET'])
    const landing = seen[1]!.request
    assert.equal(landing.body, '')
    assert.equal(landing.headers['content-type'], undefined)
    assert.equal(landing.headers['content-encoding'], undefined)
    assert.equal(landing.headers['content-length'], undefined)
    assert.equal(landing.headers['x-keep'], 'benign-control')
  })
})

test('H10: redirect scope and destructive denylist failures are audited before any target bytes are sent', async () => {
  const calls: string[] = []
  const denied: Array<{ outcome: string; origin: string; reason?: string }> = []
  const transport: Transport = async url => {
    calls.push(url.href)
    if (url.pathname === '/redirect') return { status: 302, headers: { location: '/blocked' }, body: '' }
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  }
  const broker = new RequestBroker({ resolve: async () => [PUBLIC_ADDRESS], transport })
  try {
    const grant: Grant = {
      tier: 3,
      canRead: () => true,
      scopePolicy: scopePolicy({ mode: 'staging_isolated' }),
      audit: (outcome, origin, _status, meta) => denied.push({ outcome, origin, reason: meta?.reason }),
    }
    await assert.rejects(broker.executeHttp({
      origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/redirect', followRedirects: true,
    }, grant, AbortSignal.timeout(5_000)), BrokerDenied)
    assert.deepEqual(calls, [`${APP_ORIGIN}/redirect`])
    assert.ok(denied.some(entry => entry.outcome === 'denied' && entry.reason?.includes('denylist')))
  } finally {
    broker.closeTransport()
  }

  calls.length = 0
  const outside = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async url => {
      calls.push(url.href)
      return url.pathname === '/redirect'
        ? { status: 302, headers: { location: 'https://outside.example.test/' }, body: '' }
        : { status: 200, headers: {}, body: 'ok' }
    },
  })
  try {
    const grant = brokerGrant({ scopePolicy: scopePolicy() })
    await assert.rejects(outside.executeHttp({
      origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/redirect', followRedirects: true,
    }, grant, AbortSignal.timeout(5_000)), BrokerDenied)
    assert.deepEqual(calls, [`${APP_ORIGIN}/redirect`])
  } finally {
    outside.closeTransport()
  }
})

test('H10: 307/308 redirects still require exact approval for the new path after header canonicalization', async () => {
  const approvals: string[] = []
  const calls: string[] = []
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async url => {
      calls.push(url.href)
      return url.pathname === '/start'
        ? { status: 307, headers: { location: '/target' }, body: '' }
        : { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
    },
  })
  try {
    const grant = brokerGrant({
      scopePolicy: scopePolicy({ mode: 'ephemeral_lab' }),
      isStateChangeApproved: (_origin, _method, pathAndQuery) => {
        approvals.push(pathAndQuery)
        return true
      },
    })
    await assert.rejects(broker.executeHttp({
      origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/start', body: '{}',
      headers: { 'Content-Type': 'application/json' },
    }, { ...grant, isStateChangeApproved: () => false }, AbortSignal.timeout(5_000)), BrokerApprovalRequired)
    assert.deepEqual(calls, [])

    const result = await broker.executeHttp({
      origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/start', body: '{}',
      headers: { 'Content-Type': 'application/json' },
    }, grant, AbortSignal.timeout(5_000))
    assert.equal(result.finalPathAndQuery, '/target')
    assert.deepEqual(approvals, ['/start', '/target'])
  } finally {
    broker.closeTransport()
  }
})

// ---------------------------------------------------------------------------
// M11: offline DNS, proxy host validation, and SOCKS5 IPv6 serialization
// ---------------------------------------------------------------------------

test('M11: inspectDns refuses external DNS offline while literal inspection remains available', async () => {
  await withEnv({ KOVO_OFFLINE: '1' }, async () => {
    let dnsCalls = 0
    const broker = new RequestBroker({
      dnsResolver: async () => {
        dnsCalls += 1
        return { a: [], aaaa: [], cname: [], txt: [], ns: [], nxdomain: true }
      },
    })
    try {
      const grant = brokerGrant()
      await assert.rejects(broker.inspectDns(APP_ORIGIN, grant, AbortSignal.timeout(2_000)), BrokerDenied)
      assert.equal(dnsCalls, 0)
      const literal = await broker.inspectDns('https://93.184.216.34', brokerGrant({ canRead: () => true }), AbortSignal.timeout(2_000))
      assert.equal(literal.hostname, '93.184.216.34')
      assert.equal(dnsCalls, 1)
      await assert.rejects(broker.inspectDns('http://169.254.169.254', {
        ...grant, allowLocalLab: true,
      }, AbortSignal.timeout(2_000)), BrokerDenied)
      assert.equal(dnsCalls, 1)
    } finally {
      broker.closeTransport()
    }
  })
})

test('M11: egress proxy configuration rejects metadata and malformed hosts and accepts valid IPv6', () => {
  for (const raw of [
    'http://169.254.169.254:3128',
    'http://[fd00:ec2::254]:3128',
    'http://[::]:3128',
    'http://metadata.google.internal:3128',
    'http://proxy.internal:3128',
    'http://localhost:3128',
    'http://bad_host.example:3128',
    'http://proxy.example/path',
    'http://user:%ZZ@proxy.example:3128',
  ]) {
    assert.throws(() => resolveTransportConfig({ KOVO_EGRESS_PROXY: raw }), TransportConfigError, raw)
  }
  const proxy = resolveTransportConfig({ KOVO_EGRESS_PROXY: 'socks5h://[2001:4860:4860::8888]:1080' }).proxy
  assert.equal(proxy?.host, '2001:4860:4860:0:0:0:0:8888')
  assert.equal(proxy?.port, 1080)
})

test('M11: SOCKS5 tunnel serializes compressed and expanded IPv6 targets as 16 bytes', async t => {
  const sockets = new Set<import('node:net').Socket>()
  const handshakes: Array<{ connect: Buffer }> = []
  const server = createTcpServer(socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.on('error', () => {})
    let buffer = Buffer.alloc(0)
    let phase: 'greeting' | 'connect' | 'http' = 'greeting'
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk])
      if (phase === 'http') {
        if (buffer.includes('\r\n\r\n')) {
          buffer = Buffer.alloc(0)
          socket.end('ok')
        }
        return
      }
      for (;;) {
        if (phase === 'greeting' && buffer.length >= 3) {
          buffer = buffer.subarray(3)
          phase = 'connect'
          socket.write(Buffer.from([0x05, 0x00]))
          continue
        }
        if (phase === 'connect' && buffer.length >= 22) {
          handshakes.push({ connect: buffer.subarray(0, 22) })
          buffer = buffer.subarray(22)
          phase = 'http'
          socket.write(Buffer.concat([
            Buffer.from([0x05, 0x00, 0x00, 0x04]),
            Buffer.from('20010db8000000000000000000000001', 'hex'),
            Buffer.from([0x1f, 0x90]),
          ]))
          setImmediate(() => socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'))
          continue
        }
        return
      }
    })
  })
  const port = await listen(server)
  t.after(async () => {
    for (const socket of sockets) socket.destroy()
    await closeServer(server)
  })

  const config = resolveTransportConfig({}, { proxy: {
    protocol: 'socks5:', host: '127.0.0.1', port,
  } })
  for (const address of ['2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001']) {
    const transport = createHttpTransport(config, async () => {
      throw new Error('direct fallback must not run')
    })
    try {
      const response: RawHttpResponse = await transport(
        new URL('http://[2001:db8::1]/'),
        { address, family: 6 },
        AbortSignal.timeout(5_000),
        { readBody: true, method: 'GET' },
      )
      assert.equal(response.status, 200)
      assert.equal(response.body, 'ok')
      const connect = handshakes.at(-1)!.connect
      assert.equal(connect[0], 0x05)
      assert.equal(connect[1], 0x01)
      assert.equal(connect[3], 0x04)
      assert.deepEqual(connect.subarray(4, 20), Buffer.from('20010db8000000000000000000000001', 'hex'))
      handshakes.length = 0
    } finally {
      transport.close()
    }
  }
})

test('M11: the WebSocket upgrade writer rejects injected subprotocols before opening a socket', async () => {
  const sockets = new Set<import('node:net').Socket>()
  const server = createTcpServer(socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })
  const port = await listen(server)
  try {
    await assert.rejects(WebSocketSession.connect(new URL(`http://127.0.0.1:${port}/socket`), {
      address: '127.0.0.1', family: 4,
    }, { subprotocols: ['chat\r\nX-Injected: yes'] }), TransportConfigError)
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(sockets.size, 0)
  } finally {
    for (const socket of sockets) socket.destroy()
    await closeServer(server)
  }
})
