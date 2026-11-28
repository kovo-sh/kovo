/**
 * Phase-0 floor-clean behavioral suite.
 *
 * Proves the `$0` deterministic lane is driven strictly by the discovered surface:
 *  1. Surface derivation only consumes observed/imported documents and never issues speculative
 *     requests to a hardcoded route catalog.
 *  2. The deterministic engine probes only the discovered endpoints it was given (a route flagged
 *     as a conventional-wordlist entry is ignored by default).
 *  3. The cleaned probe families (authz, xxe, traversal, jwt, mass-assignment) still detect generic
 *     issues on generic discovered endpoints, with generic OS / vendor-format oracles instead of
 *     fixture-specific paths, canary grammars or env toggles.
 *
 * Everything runs against an in-process `node:http` server on loopback.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { describe, test } from 'node:test'

import type { Grant } from '../src/server/broker.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { Store } from '../src/server/store.ts'
import { ExecFloorLane } from '../src/server/exec-floor-lane.ts'
import type { ExecFloorLaneHost } from '../src/server/exec-floor-lane.ts'
import {
  conventionalWordlistEnabled,
  engineWordlistSurface,
  runDeterministicEngine,
} from '../src/server/deterministic-engine.ts'
import type { EngineEndpoint, EnginePersona } from '../src/server/deterministic-engine.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

// Loopback targets are only reachable in local-lab mode; nothing here depends on lab fixtures.
process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const DISCOVERED_ROUTE = '/svc/items'
const DISCOVERED_SEARCH = '/svc/search'
const VENDOR_KEY = 'AKIAABCDEFGHIJKLMNOP'

interface RecordedRequest {
  method: string
  pathname: string
  search: string
  body: string
}

interface TestServer {
  origin: string
  requests: RecordedRequest[]
  state: { role: string }
  close: () => Promise<void>
}

async function startTestServer(): Promise<TestServer> {
  const requests: RecordedRequest[] = []
  const state = { role: 'member' }
  const readBody = async (req: IncomingMessage): Promise<string> => {
    const chunks: Buffer[] = []
    for await (const chunk of req) chunks.push(Buffer.from(chunk))
    return Buffer.concat(chunks).toString('utf8')
  }
  const json = (res: ServerResponse, status: number, payload: unknown) => {
    const body = JSON.stringify(payload)
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
    res.end(body)
  }
  const text = (res: ServerResponse, status: number, body: string) => {
    res.writeHead(status, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body) })
    res.end(body)
  }

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const body = await readBody(req)
    requests.push({ method: req.method ?? 'GET', pathname: url.pathname, search: url.search, body })
    const method = req.method ?? 'GET'

    // Generic object read: the known id resolves, a random sibling id does not (selectivity gate).
    if (method === 'GET' && url.pathname === `${DISCOVERED_ROUTE}/item_1`) {
      json(res, 200, { id: 'item_1', tenant: 't1', name: 'Item' })
      return
    }
    if (method === 'GET' && url.pathname.startsWith(`${DISCOVERED_ROUTE}/`)) {
      json(res, 404, { error: 'not_found' })
      return
    }

    // Generic file download with a real jail escape for the standard passwd oracle.
    if (method === 'GET' && url.pathname === '/svc/download') {
      const value = url.searchParams.get('file') ?? ''
      if (value.includes('etc/passwd')) {
        text(res, 200, 'root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n')
        return
      }
      if (value.startsWith('kovo-none') || value.includes('kovo-none')) {
        text(res, 404, '')
        return
      }
      text(res, 200, 'readme contents\n')
      return
    }

    // Generic credential surface: unauthenticated reads are denied, credential-shaped values are
    // masked behind the compact view and revealed to the entitled caller.
    if (method === 'GET' && url.pathname === '/svc/keys') {
      if (!req.headers.authorization) {
        json(res, 401, { error: 'unauthorized' })
        return
      }
      const reveal = url.searchParams.get('reveal')
      if (reveal === '0') {
        json(res, 200, { apiKey: '****', provider: 'cloud' })
        return
      }
      json(res, 200, { apiKey: VENDOR_KEY, provider: 'cloud' })
      return
    }

    // Generic boolean/error SQL sink: a quote in the term produces a database error fingerprint.
    if (method === 'GET' && url.pathname === DISCOVERED_SEARCH) {
      const term = url.searchParams.get('q') ?? ''
      if (term.includes("'")) {
        text(res, 500, 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version')
        return
      }
      json(res, 200, { results: term ? [{ id: 'r1', term }] : [] })
      return
    }

    // Generic object read/write used by mass assignment.
    if (url.pathname === '/svc/profile') {
      if (method === 'POST') {
        let token = ''
        try { token = String((JSON.parse(body) as { token?: unknown }).token ?? '') } catch { token = '' }
        const header = token.split('.')[0]
        let alg = ''
        try { alg = String((JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as { alg?: unknown }).alg ?? '') } catch { alg = '' }
        if (alg === 'none') {
          json(res, 200, { data: { id: 'user-1', name: 'Self' }, ok: true })
          return
        }
        json(res, 401, { error: 'invalid_signature' })
        return
      }
      if (method === 'PATCH' || method === 'PUT') {
        try {
          const parsed = JSON.parse(body) as Record<string, unknown>
          if (typeof parsed.role === 'string') state.role = parsed.role
        } catch { /* ignore malformed body */ }
        json(res, 200, { ok: true })
        return
      }
      json(res, 200, { id: 'user-1', name: 'Self', role: state.role })
      return
    }

    // XXE in-band oracle: a resolved standard OS entity surfaces its content.
    if (method === 'POST' && url.pathname === '/svc/xml') {
      if (body.includes('file:///etc/passwd')) {
        text(res, 200, 'root:x:0:0:root:/root:/bin/sh\n')
        return
      }
      text(res, 200, 'ok')
      return
    }

    json(res, 404, { error: 'not_found' })
  }

  const server: Server = createServer((req, res) => {
    void handler(req, res)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  return {
    origin,
    requests,
    state,
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  }
}

function makeGrant(origin: string, extra: Partial<Grant> = {}): Grant {
  return {
    canRead: candidate => {
      try { return new URL(candidate).origin === origin } catch { return candidate === origin }
    },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    ...extra,
  }
}

function persona(handle: string, origin: string, privilege: 'admin' | 'viewer' | 'member'): ResolvedPersona {
  return {
    id: `p-${handle}`,
    handle,
    roleLabel: `${privilege} (t1)`,
    tenantRef: 't1',
    privilege,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret: `test-token-${handle}`,
    canaryMarkers: [],
  }
}

describe('floor lane surface derivation is discovered-only', () => {
  test('route maps and imported specs derive targets without speculative catalog requests', async t => {
    const server = await startTestServer()
    t.after(() => server.close())

    const observedRouteMapPath = '/svc/routes.json'
    const specPaths = {
      [`${DISCOVERED_SEARCH}`]: {
        get: { parameters: [{ name: 'q', in: 'query' }] },
      },
      '/svc/widgets/{widgetId}': {
        get: { parameters: [{ name: 'widgetId', in: 'path' }] },
      },
    }
    const storage = {
      runDetail: () => ({
        exchangesSummary: [{
          id: 'ex-route-map',
          origin: server.origin,
          method: 'GET',
          pathAndQuery: observedRouteMapPath,
          status: 200,
          mediaType: 'application/json',
        }],
      }),
      getExchange: () => ({
        body: JSON.stringify({ routes: [{ path: DISCOVERED_ROUTE, method: 'GET' }] }),
      }),
      listProjectSpecsFull: () => [{
        name: 'custom-api.json',
        kind: 'openapi',
        content: JSON.stringify({ openapi: '3.0.0', servers: [{ url: server.origin }], paths: specPaths }),
      }],
    } as unknown as Store
    const lane = new ExecFloorLane({ storage } as unknown as ExecFloorLaneHost)
    const approvedOrigins = new Set([server.origin])
    const run = { id: 'run-floor-clean', projectId: 'project-floor-clean' }

    const runtimeTargets = await lane.deriveRuntimeRouteMapTargets(
      run as never,
      approvedOrigins,
      {} as never,
      {} as never,
      new AbortController().signal,
      () => 'recorded',
    )
    const specTargets = lane.deriveDeterministicRouteTargets(run as never, approvedOrigins, [])

    assert.deepEqual(
      [...new Set(runtimeTargets.map(target => target.pathTemplate))].sort(),
      [DISCOVERED_ROUTE],
      'runtime route maps must only contribute routes present in the observed document',
    )
    assert.ok(
      specTargets.some(target => target.pathTemplate === DISCOVERED_SEARCH && target.params.some(p => p.name === 'q')),
      `imported OpenAPI spec should yield the discovered search route, got ${JSON.stringify(specTargets.map(target => target.pathTemplate))}`,
    )
    // Every derived target belongs to the custom discovered namespace; no catalog route was added.
    for (const target of [...runtimeTargets, ...specTargets]) {
      assert.ok(target.pathTemplate.startsWith('/svc/'), `unexpected derived route ${target.pathTemplate}`)
    }
    assert.equal(server.requests.length, 0, 'surface derivation must not issue speculative HTTP requests')
  })
})

describe('deterministic engine probes only the discovered surface', () => {
  test('conventional-wordlist entries are inert by default and requests stay on discovered routes', async t => {
    const server = await startTestServer()
    t.after(() => server.close())
    assert.equal(conventionalWordlistEnabled({}), false)

    const discovered: EngineEndpoint = {
      id: `GET:${DISCOVERED_SEARCH}`,
      origin: server.origin,
      method: 'GET',
      pathTemplate: DISCOVERED_SEARCH,
      params: [{ name: 'q', location: 'query' }],
      riskScore: 80,
      source: 'openapi',
    }
    const conventional: EngineEndpoint = {
      ...discovered,
      id: 'GET:/catalog/wordlist-only',
      pathTemplate: '/catalog/wordlist-only',
      source: 'conventional',
    }
    const filtered = engineWordlistSurface([discovered, conventional], false)
    assert.deepEqual(filtered.map(endpoint => endpoint.pathTemplate), [DISCOVERED_SEARCH])

    const personas: EnginePersona[] = [{ handle: 'persona-a', roleLabel: 'member (t1)', privilege: 'member', tenant: 't1' }]
    const resolvedPersonas = new Map([['persona-a', persona('persona-a', server.origin, 'member')]])
    const confirmed: string[] = []
    const report = await runDeterministicEngine({
      runId: 'run-floor-clean-engine',
      assignmentId: 'asg-floor-clean-engine',
      signal: new AbortController().signal,
      endpoints: [discovered, conventional],
      personas,
      broker: new RequestBroker(),
      grant: makeGrant(server.origin, { personas: resolvedPersonas }),
      backend: {} as WorkerBackend,
      tier: 1,
      maxRequests: 40,
      maxDurationMs: 8_000,
      verify: async () => ({
        verdict: 'confirmed',
        outcome: { confirmed: true, controlPassed: true, observed: 'database error differential', expected: 'parameterized query' },
        exchangeIds: ['verify-1'],
        exchanges: [],
        evidencePayload: {},
        evidenceSha256: 'sha',
      }),
      onConfirmed: input => {
        confirmed.push(input.vulnClass)
        return 'finding-1'
      },
    })

    assert.ok(report.requestsUsed > 0, 'the engine should probe the discovered endpoint')
    assert.ok(report.hypothesesFormed > 0, 'the engine should form hypotheses from the discovered surface')
    assert.ok(report.signals > 0, 'the generic SQL error sink should produce a signal')
    assert.ok(confirmed.length > 0, 'a verified signal should reach the persistence callback')
    assert.ok(
      server.requests.every(request => request.pathname === DISCOVERED_SEARCH),
      `engine requests left the discovered surface: ${JSON.stringify([...new Set(server.requests.map(request => request.pathname))])}`,
    )
  })
})

describe('cleaned probe families detect generic issues on generic endpoints', () => {
  test('authz matrix confirms a cross-actor object read and a generic vendor-format credential leak', async t => {
    const server = await startTestServer()
    t.after(() => server.close())
    const broker = new RequestBroker()
    const grant = makeGrant(server.origin, {
      personas: new Map([
        ['persona-a', persona('persona-a', server.origin, 'member')],
        ['persona-b', persona('persona-b', server.origin, 'member')],
      ]),
    })
    const signal = new AbortController().signal

    const bola = await probeDifferential({
      probeClass: 'authz_matrix',
      origin: server.origin,
      method: 'GET',
      pathAndQuery: `${DISCOVERED_ROUTE}/{{id}}`,
      resourceIds: ['item_1'],
      ownerPersona: 'persona-a',
      otherPersona: 'persona-b',
      includeAnonymous: false,
      includeHeaderBypass: false,
      maxRequests: 24,
    }, broker, grant, undefined, signal)
    assert.equal(bola.verdict, 'signal')
    assert.ok(bola.anomalies.some(anomaly => anomaly.type === 'unauthorized_access'))

    const personas = new Map([
      ['admin', persona('admin', server.origin, 'admin')],
      ['viewer', persona('viewer', server.origin, 'viewer')],
    ])
    const disclosure = await probeDifferential({
      probeClass: 'authz_matrix',
      origin: server.origin,
      method: 'GET',
      pathAndQuery: '/svc/keys',
      ownerPersona: 'admin',
      viewerPersona: 'viewer',
      secretScan: true,
      includeAnonymous: true,
      includeHeaderBypass: false,
      maxRequests: 24,
    }, broker, makeGrant(server.origin, { personas }), undefined, signal)
    assert.equal(disclosure.verdict, 'signal', JSON.stringify(disclosure.details))
    const secret = disclosure.anomalies.find(anomaly => anomaly.type === 'secret_disclosed')
    assert.ok(secret, `expected a credential disclosure anomaly, got ${JSON.stringify(disclosure.anomalies)}`)
    assert.match(String(secret.secretPattern ?? ''), /AKIA/, 'the observed credential shape should be evidence-bound')
  })

  test('traversal confirms a standard passwd jail escape and never leaves generic OS oracles', async t => {
    const server = await startTestServer()
    t.after(() => server.close())
    const result = await probeDifferential({
      probeClass: 'path_traversal_benign',
      origin: server.origin,
      method: 'GET',
      pathAndQuery: '/svc/download?file=readme.txt',
      param: 'file',
      paramLocation: 'query',
      baselineValue: 'readme.txt',
      maxRequests: 30,
    }, new RequestBroker(), makeGrant(server.origin), undefined, new AbortController().signal)

    assert.equal(result.verdict, 'signal')
    assert.ok(result.anomalies.some(anomaly => anomaly.type === 'path_traversal_escape'))
    const traversalTargets = server.requests
      .filter(request => request.pathname === '/svc/download')
      .map(request => new URL(`http://127.0.0.1${request.search}`).searchParams.get('file') ?? '')
      .filter(Boolean)
    assert.ok(traversalTargets.length > 0)
    // Generic OS files or in-jail relative names only: no application-specific VFS layout is assumed.
    for (const target of traversalTargets) {
      assert.ok(
        target.includes('etc/passwd') || target.includes('etc/hostname') || target.includes('etc/os-release') ||
          target.includes('etc/hosts') || target.includes('secret.txt') || target.includes('flag.txt') ||
          target.includes('.env') || target.includes('config.json') || target.includes('readme.txt') ||
          target.includes('kovo-none'),
        `unexpected traversal oracle ${target}`,
      )
    }
  })

  test('xxe resolves a standard OS entity in-band using generic content markers', async t => {
    const server = await startTestServer()
    t.after(() => server.close())
    const canary = new CanaryBroker({})
    t.after(() => canary.stopListener())

    const result = await probeDifferential({
      probeClass: 'xxe_canary',
      origin: server.origin,
      method: 'POST',
      pathAndQuery: '/svc/xml',
      waitMs: 500,
      maxRequests: 12,
    }, new RequestBroker(), makeGrant(server.origin), canary, new AbortController().signal)

    assert.equal(result.verdict, 'signal')
    assert.ok(result.anomalies.some(anomaly => anomaly.type === 'xxe_entity_resolved_inband'))
    const entities = server.requests
      .map(request => /SYSTEM "(file:\/\/[^"]+)"/.exec(request.body)?.[1] ?? '')
      .filter(Boolean)
    assert.ok(entities.includes('file:///etc/passwd'))
    for (const entity of entities) {
      assert.ok(
        entity === 'file:///etc/passwd' || entity === 'file:///proc/self/environ' || entity === 'file:///etc/hostname',
        `unexpected in-band entity ${entity}`,
      )
    }
  })

  test('jwt audit detects an alg:none body-token forgery from discovered claims', async t => {
    const server = await startTestServer()
    t.after(() => server.close())
    const result = await probeDifferential({
      probeClass: 'auth_protocol_audit',
      origin: server.origin,
      method: 'POST',
      pathAndQuery: '/svc/profile',
      tokenFields: ['token'],
      identityClaims: { sub: 'user-1' },
      maxRequests: 12,
    }, new RequestBroker(), makeGrant(server.origin), undefined, new AbortController().signal)

    assert.equal(result.verdict, 'signal')
    assert.ok(result.anomalies.some(anomaly => anomaly.type === 'jwt_body_token_bypass'))
  })

  test('mass assignment detects a persisted privileged field on a generic profile route', async t => {
    const server = await startTestServer()
    t.after(() => server.close())
    const result = await probeDifferential({
      probeClass: 'mass_assignment',
      origin: server.origin,
      method: 'PATCH',
      pathAndQuery: '/svc/profile',
      paramLocation: 'json',
      candidateFields: ['role'],
      maxRequests: 12,
    }, new RequestBroker(), makeGrant(server.origin), undefined, new AbortController().signal)

    assert.equal(result.verdict, 'signal')
    assert.ok(result.anomalies.some(anomaly => anomaly.type === 'mass_assignment' && anomaly.field === 'role'))
  })
})
