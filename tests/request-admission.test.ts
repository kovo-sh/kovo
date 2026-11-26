import assert from 'node:assert/strict'
import { request as httpRequest } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { IncomingHttpHeaders, ServerHttp2Stream } from 'node:http2'
import type { AddressInfo } from 'node:net'
import test from 'node:test'
import {
  BrokerApprovalRequired,
  BrokerDenied,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  admissionTierToCapabilityTier,
  capabilityTierToAdmissionTier,
  classifyRequestMutation,
  inspectJsonRpcPayload,
  matchesSandboxWriteAllowlist,
  RequestAdmissionEngine,
} from '../src/server/request-admission.ts'
import type { AdmissionGrant } from '../src/server/request-admission.ts'
import { tenantTagForRun } from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'

const APP_ORIGIN = 'https://app.example.com'
const IDP_ORIGIN = 'https://idp.example.com'
const CDN_ORIGIN = 'https://cdn.example.com'
const EVIL_ORIGIN = 'https://evil.example.net'
const PUBLIC_ADDR = { address: '93.184.216.34', family: 4 }

function makeScope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'prod_readonly',
    targetOrigins: [APP_ORIGIN],
    authOrigins: [IDP_ORIGIN],
    assetOrigins: [CDN_ORIGIN],
    routeDenylist: ['/billing/charge'],
    tenantTag: tenantTagForRun('run-adm-1'),
    ...overrides,
  }
}

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: APP_ORIGIN,
    tier: 3,
    allowLocalLab: false,
    canRead: origin => origin === APP_ORIGIN,
    audit: () => {},
    ...overrides,
  }
}

interface RpcResponse {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResponse> {
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
): Promise<{ origin: string; close: () => Promise<void> }> {
  const sessions = new Set<import('node:http2').ServerHttp2Session>()
  const server = createH2Server()
  server.on('session', session => {
    sessions.add(session)
    session.once('close', () => sessions.delete(session))
  })
  server.on('stream', onStream)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = (server.address() as AddressInfo).port
  return {
    origin: `http://127.0.0.1:${port}`,
    close: async () => {
      for (const session of sessions) session.destroy()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

// ============================================================================
// 1. Scope, Origin Roles, Ports, Explicit Denylist & Destructive Payload Guards
// ============================================================================

test('RequestAdmissionEngine enforces scope, origin roles, ports, explicit denylist, and destructive payloads', () => {
  const engine = new RequestAdmissionEngine({
    explicitDenylist: {
      origins: ['https://blocked.example.com'],
      pathPrefixes: ['/internal/admin'],
    },
    env: {},
  })

  const grant = makeGrant({
    canRead: origin => origin === APP_ORIGIN || origin === 'https://blocked.example.com' || origin === 'https://app.example.com:8443',
    scopePolicy: makeScope({
      mode: 'staging_isolated',
      targetOrigins: [APP_ORIGIN, 'https://blocked.example.com', 'https://app.example.com:8443'],
    }),
  })

  // Out-of-scope origin denied
  const oos = engine.admit({ origin: EVIL_ORIGIN, method: 'GET', pathAndQuery: '/' }, grant)
  assert.equal(oos.outcome, 'deny')
  assert.equal(oos.reasonCode, 'out_of_scope')
  assert.equal(oos.normalizedOrigin, EVIL_ORIGIN)
  assert.equal(oos.normalizedMethod, 'GET')

  // Non-default port rejected unless in allowedPorts or KOVO_ALLOWED_PORTS
  const badPort = engine.admit({ origin: 'https://app.example.com:8443', method: 'GET', pathAndQuery: '/ok' }, grant)
  assert.equal(badPort.outcome, 'deny')
  assert.equal(badPort.reasonCode, 'port_not_allowed')

  const okPort = engine.admit(
    { origin: 'https://app.example.com:8443', method: 'GET', pathAndQuery: '/ok' },
    { ...grant, allowedPorts: [8443] },
  )
  assert.equal(okPort.outcome, 'allow')
  assert.equal(okPort.normalizedOrigin, 'https://app.example.com:8443')

  // Explicit origin & path denylists override everything (even GET)
  const deniedOrigin = engine.admit({ origin: 'https://blocked.example.com', method: 'GET', pathAndQuery: '/health' }, grant)
  assert.equal(deniedOrigin.outcome, 'deny')
  assert.equal(deniedOrigin.reasonCode, 'explicit_denylist')

  const deniedPath = engine.admit({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/internal/admin/users' }, grant)
  assert.equal(deniedPath.outcome, 'deny')
  assert.equal(deniedPath.reasonCode, 'explicit_denylist')

  // Auth & asset origin role enforcement
  const idpProbe = engine.admit({ origin: IDP_ORIGIN, method: 'GET', pathAndQuery: '/admin' }, grant)
  assert.equal(idpProbe.outcome, 'deny')
  assert.equal(idpProbe.reasonCode, 'auth_origin_active_probe')

  const idpRedirect = engine.admit({ origin: IDP_ORIGIN, method: 'GET', pathAndQuery: '/oauth/authorize', redirectHop: true }, grant)
  assert.equal(idpRedirect.outcome, 'allow')

  const cdnActive = engine.admit({ origin: CDN_ORIGIN, method: 'GET', pathAndQuery: '/bundle.js' }, grant)
  assert.equal(cdnActive.outcome, 'deny')
  assert.equal(cdnActive.reasonCode, 'asset_origin_active_probe')

  const cdnBrowser = engine.admit({ kind: 'browser', origin: CDN_ORIGIN, method: 'GET', pathAndQuery: '/bundle.js', surface: 'browser' }, grant)
  assert.equal(cdnBrowser.outcome, 'allow')

  // Staging routeDenylist rejects tagged mutation
  const tag = tenantTagForRun('run-adm-1')
  const stagingDeny = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/billing/charge',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tenant: `${tag}1` }),
  }, grant)
  assert.equal(stagingDeny.outcome, 'deny')
  assert.equal(stagingDeny.reasonCode, 'staging_denylist')

  // Forbidden caller header rejected; self-minted unsigned alg:none JWT permitted
  const badAuth = engine.admit({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/me',
    headers: { Authorization: 'Bearer real-credential-value' },
  }, grant)
  assert.equal(badAuth.outcome, 'deny')
  assert.equal(badAuth.reasonCode, 'forbidden_header')

  const unsignedHdr = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
  const unsignedPay = Buffer.from(JSON.stringify({ sub: 'probe' })).toString('base64url')
  const selfMinted = engine.admit({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/me',
    headers: { Authorization: `Bearer ${unsignedHdr}.${unsignedPay}.` },
  }, grant)
  assert.equal(selfMinted.outcome, 'allow')
})

// ============================================================================
// 2. Strict GraphQL (H-3) & JSON-RPC Mutation/Destructive Classification
// ============================================================================

test('RequestAdmissionEngine classifies GraphQL (H-3) and JSON-RPC strictly without regex bypasses', () => {
  const engine = new RequestAdmissionEngine({ env: {} })
  const prodGrant = makeGrant({ scopePolicy: makeScope({ mode: 'prod_readonly' }) })

  // Genuine GraphQL read-only query allowed in prod_readonly
  const gqlRead = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/graphql',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'query Viewer { viewer { id } }', operationName: 'Viewer', variables: {} }),
  }, prodGrant)
  assert.equal(gqlRead.outcome, 'allow')
  assert.equal(gqlRead.reasonCode, 'allowed_graphql_readonly')
  assert.equal(gqlRead.classification?.kind, 'graphql_readonly_query')

  // H-3 bypass attempts fail closed
  const bypassCases = [
    { path: '/api/users/delete', body: JSON.stringify({ query: 'query { ok }' }) },
    { path: '/graphql', body: '{"query":"query { x }","\\u0071uery":"mutation { del }"}' },
    { path: '/graphql', body: '{"query":"mutation { del }","query":"query { x }"}' },
    { path: '/graphql', body: JSON.stringify({ query: 'query Safe { viewer { id } } mutation Evil { nuke { ok } }', operationName: 'Safe' }) },
    { path: '/graphql', body: JSON.stringify({ query: 'query { a: viewer { id } }' }) },
    { path: '/graphql', body: JSON.stringify({ query: 'query { ok }', extensions: { persistedQuery: { version: 1 } } }) },
  ]
  for (const tc of bypassCases) {
    const dec = engine.admit({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: tc.path,
      headers: { 'Content-Type': 'application/json' },
      body: tc.body,
    }, prodGrant)
    assert.equal(dec.outcome, 'deny', `Expected deny for ${tc.path} ${tc.body}`)
    assert.equal(dec.reasonCode, 'readonly_environment')
  }

  // Strict JSON-RPC inspection: single, batch, destructive, duplicate/escaped keys
  const rpcRead = inspectJsonRpcPayload(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'users.getProfile', params: { id: 1 } }))
  assert.equal(rpcRead.isJsonRpc, true)
  assert.equal(rpcRead.allReadNamed, true)
  assert.equal(rpcRead.hasDestructiveMethod, false)

  const rpcDestructive = inspectJsonRpcPayload(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'users.deleteAccount', params: { id: 1 } }))
  assert.equal(rpcDestructive.isJsonRpc, true)
  assert.equal(rpcDestructive.hasDestructiveMethod, true)

  const rpcMixedBatch = inspectJsonRpcPayload(JSON.stringify([
    { jsonrpc: '2.0', id: 1, method: 'system.ping' },
    { jsonrpc: '2.0', id: 2, method: 'orders.purgeAll' },
  ]))
  assert.equal(rpcMixedBatch.isJsonRpc, true)
  assert.equal(rpcMixedBatch.hasDestructiveMethod, true)
  assert.deepEqual(rpcMixedBatch.methods, ['system.ping', 'orders.purgeAll'])

  // Escaped key or duplicate method key in JSON-RPC fails closed as malformed
  const rpcSmuggled = inspectJsonRpcPayload('{"jsonrpc":"2.0","method":"users.get","\\u006dethod":"users.delete"}')
  assert.equal(rpcSmuggled.isJsonRpc, true)
  assert.equal(rpcSmuggled.malformed, true)
  assert.equal(rpcSmuggled.hasMutationMethod, true)

  const rpcClassDestructive = classifyRequestMutation({
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'admin.dropTable' }),
  })
  assert.equal(rpcClassDestructive.kind, 'jsonrpc_destructive')
  assert.equal(rpcClassDestructive.isStateChanging, true)
  assert.equal(rpcClassDestructive.isStructuralMutation, true)

  // Fail-closed: even read-named JSON-RPC POST must NOT bypass prod_readonly or Tier-3 approval
  const rpcInProd = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/rpc',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'users.getProfile' }),
  }, prodGrant)
  assert.equal(rpcInProd.outcome, 'deny')
  assert.equal(rpcInProd.reasonCode, 'readonly_environment')
})

// ============================================================================
// 3. Tier (offline/passive/supervised/autonomous) + Policy + Allowlist + Leases + Hooks
// ============================================================================

test('RequestAdmissionEngine enforces Tier 0/1/2/3, sandboxWriteAllowlist, durable leases, and budget/rate hooks', () => {
  assert.equal(capabilityTierToAdmissionTier(0), 'offline')
  assert.equal(capabilityTierToAdmissionTier(1), 'passive')
  assert.equal(capabilityTierToAdmissionTier(2), 'supervised')
  assert.equal(capabilityTierToAdmissionTier(3), 'autonomous')
  assert.equal(admissionTierToCapabilityTier('supervised'), 2)

  const engine = new RequestAdmissionEngine({ env: {} })

  // Tier 0 offline denies everything
  const t0 = engine.admit({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/' }, makeGrant({ tier: 0 }))
  assert.equal(t0.outcome, 'deny')
  assert.equal(t0.reasonCode, 'tier_offline')
  assert.equal(t0.effectiveTier, 'offline')

  // Tier 1 passive allows anonymous GET, denies persona auth and POST
  const t1Grant = makeGrant({ tier: 1 })
  assert.equal(engine.admit({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/items' }, t1Grant).outcome, 'allow')
  assert.equal(engine.admit({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/items', personaHandle: 'user_a' }, t1Grant).reasonCode, 'tier_insufficient')
  assert.equal(engine.admit({ origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/items', body: '{}' }, t1Grant).reasonCode, 'tier_insufficient')

  // Tier 2 supervised: sandboxWriteAllowlist permits matching POST, blocks traversal & DELETE
  const allowlist = [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/api/safe/*' }]
  const t2Grant = makeGrant({ tier: 2, sandboxWriteAllowlist: allowlist })
  assert.equal(matchesSandboxWriteAllowlist(APP_ORIGIN, '/api/safe/item', '/api/safe/item', allowlist), true)
  assert.equal(matchesSandboxWriteAllowlist(APP_ORIGIN, '/api/safe/item', '/api/safe/%252e%252e/admin', allowlist), false)

  const t2Allowed = engine.admit({ origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/safe/item', body: '{"a":1}' }, t2Grant)
  assert.equal(t2Allowed.outcome, 'allow')
  assert.equal(t2Allowed.effectiveTier, 'supervised')
  assert.equal(t2Allowed.reasonCode, 'allowed_sandbox_allowlist')

  const t2Blocked = engine.admit({ origin: APP_ORIGIN, method: 'DELETE', pathAndQuery: '/api/safe/item' }, t2Grant)
  assert.equal(t2Blocked.outcome, 'deny')
  assert.equal(t2Blocked.reasonCode, 'tier_insufficient')

  // Tier 3 autonomous: exact approval hook -> require_approval vs allow
  const t3Unapproved = engine.admit(
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items', body: '{"x":1}' },
    makeGrant({ tier: 3, isStateChangeApproved: () => false }),
  )
  assert.equal(t3Unapproved.outcome, 'require_approval')
  assert.equal(t3Unapproved.reasonCode, 'approval_required')
  assert.equal(t3Unapproved.effectiveTier, 'autonomous')
  assert.ok(t3Unapproved.approvalContext?.bodyHash)

  // R4-H-1: Durable leases NEVER override prod_readonly (readonly_environment), compressed bodies, or race bursts.
  const prodLeasedGrant = makeGrant({
    tier: 3,
    scopePolicy: makeScope({ mode: 'prod_readonly' }),
    isStateChangeApproved: () => false,
    approvalLeases: (o, m, p) => o === APP_ORIGIN && m === 'POST' && p.startsWith('/api/items/'),
  })
  const prodLeasedDenied = engine.admit({ origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items/42', body: '{"x":1}' }, prodLeasedGrant)
  assert.equal(prodLeasedDenied.outcome, 'deny')
  assert.equal(prodLeasedDenied.reasonCode, 'readonly_environment')

  const leasedCompressed = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    headers: { 'Content-Encoding': 'gzip' },
    body: 'compressed',
  }, prodLeasedGrant)
  assert.equal(leasedCompressed.outcome, 'deny')
  assert.equal(leasedCompressed.reasonCode, 'readonly_environment')

  const leasedRace = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    body: '{"x":1}',
    isRaceBurst: true,
  }, prodLeasedGrant)
  assert.equal(leasedRace.outcome, 'deny')
  assert.equal(leasedRace.reasonCode, 'readonly_environment')

  // In staging_isolated, an eligible durable route lease still authorizes the leased non-high-risk route.
  const stagingLeasedGrant = makeGrant({
    tier: 3,
    scopePolicy: makeScope({ mode: 'staging_isolated' }),
    approvalPolicy: 'auto_review',
    isStateChangeApproved: () => false,
    approvalLeases: (o, m, p) => o === APP_ORIGIN && m === 'POST' && p.startsWith('/api/items/'),
  })
  const leasedOk = engine.admit({ origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items/42', body: '{"x":1}' }, stagingLeasedGrant)
  assert.equal(leasedOk.outcome, 'allow')
  assert.equal(leasedOk.reasonCode, 'allowed_approval_lease')

  // Budget & rate-limit hooks run BEFORE consuming single-use approval grants
  let approvalCalls = 0
  const hookedGrant: AdmissionGrant = makeGrant({
    tier: 3,
    isStateChangeApproved: () => {
      approvalCalls += 1
      return true
    },
  })
  const budgetEngine = new RequestAdmissionEngine({
    env: {},
    grantLookup: () => hookedGrant,
    budgetCheck: () => ({ allowed: false, reason: 'Request budget exhausted for run.' }),
  })
  const overBudget = budgetEngine.admit({ origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items', body: '{}' })
  assert.equal(overBudget.outcome, 'deny')
  assert.equal(overBudget.reasonCode, 'budget_exhausted')
  assert.equal(approvalCalls, 0, 'budget denial must not consume single-use approval grants')

  const rateEngine = new RequestAdmissionEngine({
    env: {},
    rateLimitCheck: () => ({ allowed: false, reasonCode: 'rate_limited', reason: 'Per-origin RPS exceeded.', retryAfterMs: 250 }),
  })
  const rateLimited = rateEngine.admit({ origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items', body: '{}' }, hookedGrant)
  assert.equal(rateLimited.outcome, 'deny')
  assert.equal(rateLimited.reasonCode, 'rate_limited')
  assert.equal(rateLimited.retryAfterMs, 250)
  assert.equal(approvalCalls, 0, 'rate-limit denial must not consume single-use approval grants')
})

// ============================================================================
// 4. H-4 Per-Target Batch / Race Burst Validation
// ============================================================================

test('H-4 admitBatch evaluates every target individually and never burns grants when a sibling fails static checks', () => {
  const engine = new RequestAdmissionEngine({ env: {} })

  // A: Mixed batch [benign POST /search (approved), unapproved DELETE /api/users/1] -> fails closed on index 1
  const approvedPaths = new Set(['POST /search'])
  const seenTargets: string[] = []
  const grant = makeGrant({
    tier: 3,
    isStateChangeApproved: (_origin, method, path) => {
      const key = `${method} ${path}`
      seenTargets.push(key)
      return approvedPaths.has(key)
    },
  })

  const mixed = engine.admitBatch([
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/search', body: '{"q":"ok"}' },
    { origin: APP_ORIGIN, method: 'DELETE', pathAndQuery: '/api/users/1' },
  ], grant)
  assert.equal(mixed.outcome, 'require_approval')
  assert.equal(mixed.reasonCode, 'approval_required')
  assert.equal(mixed.failedIndex, 1)
  assert.deepEqual(seenTargets, ['POST /search', 'DELETE /api/users/1'])

  // B: Sibling #2 out-of-scope fails in static Phase 1 BEFORE consuming item #1's single-use grant!
  let singleUseConsumed = 0
  const singleUseGrant = makeGrant({
    tier: 3,
    isStateChangeApproved: () => {
      singleUseConsumed += 1
      return true
    },
  })
  const staticFail = engine.admitBatch([
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/search', body: '{"q":"ok"}' },
    { origin: EVIL_ORIGIN, method: 'GET', pathAndQuery: '/leak' },
  ], singleUseGrant)
  assert.equal(staticFail.outcome, 'deny')
  assert.equal(staticFail.reasonCode, 'out_of_scope')
  assert.equal(staticFail.failedIndex, 1)
  assert.equal(singleUseConsumed, 0, 'static pre-flight failure must not burn earlier sibling single-use grants')

  // C: Tier 1 batch rejected; batch size bounds enforced
  assert.equal(engine.admitBatch([
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a' },
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b' },
  ], makeGrant({ tier: 1 })).reasonCode, 'tier_insufficient')
  assert.equal(engine.admitBatch([{ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a' }], grant).reasonCode, 'batch_size_invalid')
})

// ============================================================================
// 5. Parity Between broker.ts and verify-rpc.ts (+ Actionable Role Diagnostic)
// ============================================================================

test('broker.ts and verify-rpc.ts share RequestAdmissionEngine with identical decisions across HTTP, HTTP/2, and browser', async () => {
  const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'

  let h2Hits = 0
  const h2Fixture = await startH2Fixture(stream => {
    h2Hits += 1
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end('{"ok":true}')
  })

  let httpHits = 0
  const sharedEngine = new RequestAdmissionEngine({
    explicitDenylist: { pathPrefixes: ['/explicitly-denied'] },
  })
  const broker = new RequestBroker({
    admissionEngine: sharedEngine,
    resolve: async host => (host === '127.0.0.1' ? [{ address: '127.0.0.1', family: 4 }] : [PUBLIC_ADDR]),
    transport: async () => {
      httpHits += 1
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })

  const tag = tenantTagForRun('run-parity-1')
  const parityGrant: Grant = {
    origin: h2Fixture.origin,
    tier: 3,
    allowLocalLab: true,
    allowedPorts: [Number(new URL(h2Fixture.origin).port)],
    canRead: o => o === h2Fixture.origin,
    scopePolicy: {
      mode: 'prod_readonly',
      targetOrigins: [h2Fixture.origin],
      routeDenylist: ['/billing/charge'],
      tenantTag: tag,
    },
    isStateChangeApproved: () => false,
    approvalLeases: (o, m, p) => o === h2Fixture.origin && m === 'POST' && p.startsWith('/leased/'),
    audit: () => {},
  }

  let browserHits = 0
  const rpcServer = new VerifyRpcServer({
    broker,
    grant: parityGrant,
    runId: 'run-parity-1',
    assignmentId: 'assign-parity-1',
    targetOrigins: [h2Fixture.origin],
    browser: {
      async open(req) {
        browserHits += 1
        return { status: 200, url: req.url, html: '<html><body>ok</body></html>' }
      },
    },
  })
  await rpcServer.start()

  try {
    // 1. VerifyRpcServer actionable role diagnostic includes setup|control|probe|cleanup
    const badRole = await rpcCall(rpcServer, 'http', { path: '/ok', sessionGroupRole: 'invalid_arm' })
    assert.equal(badRole.ok, false)
    assert.match(badRole.error ?? '', /Invalid session group role/)
    assert.match(badRole.error ?? '', /setup\|control\|probe\|cleanup/)

    // 2. Explicit denylist blocks broker.executeHttp, verify-rpc http, verify-rpc http2, AND verify-rpc browser identically
    await assert.rejects(
      broker.executeHttp({ origin: h2Fixture.origin, method: 'GET', pathAndQuery: '/explicitly-denied/secret' }, parityGrant, AbortSignal.timeout(5_000)),
      (err: unknown) => err instanceof BrokerDenied && /explicitly denylisted/i.test(err.message),
    )
    const rpcHttpDenied = await rpcCall(rpcServer, 'http', { origin: h2Fixture.origin, method: 'GET', path: '/explicitly-denied/secret' })
    assert.equal(rpcHttpDenied.ok, false)
    assert.match(rpcHttpDenied.error ?? '', /explicitly denylisted/i)

    const rpcH2Denied = await rpcCall(rpcServer, 'http2', { origin: h2Fixture.origin, method: 'GET', path: '/explicitly-denied/secret' })
    assert.equal(rpcH2Denied.ok, false)
    assert.match(rpcH2Denied.error ?? '', /explicitly denylisted/i)

    const rpcBrowserDenied = await rpcCall(rpcServer, 'browser', { origin: h2Fixture.origin, path: '/explicitly-denied/secret' })
    assert.equal(rpcBrowserDenied.ok, false)
    assert.match(rpcBrowserDenied.error ?? '', /explicitly denylisted/i)

    // 3. Verified read-only GraphQL query permitted on BOTH broker.executeHttp AND verify-rpc http2 under prod_readonly
    const gqlReadBody = JSON.stringify({ query: 'query Viewer { viewer { id } }', operationName: 'Viewer' })
    const brokerGql = await broker.executeHttp({
      origin: h2Fixture.origin,
      method: 'POST',
      pathAndQuery: '/graphql',
      headers: { 'Content-Type': 'application/json' },
      body: gqlReadBody,
    }, parityGrant, AbortSignal.timeout(5_000))
    assert.equal(brokerGql.status, 200)

    const h2Gql = await rpcCall(rpcServer, 'http2', {
      origin: h2Fixture.origin,
      method: 'POST',
      path: '/graphql',
      headers: { 'Content-Type': 'application/json' },
      body: gqlReadBody,
    })
    assert.equal(h2Gql.ok, true, h2Gql.error ?? 'expected verified read-only GraphQL on HTTP/2 to succeed')

    // 4. R4-H-1: Durable approval lease NEVER overrides prod_readonly on EITHER broker.executeHttp OR verify-rpc http2!
    await assert.rejects(
      broker.executeHttp({
        origin: h2Fixture.origin,
        method: 'POST',
        pathAndQuery: '/leased/42',
        headers: { 'Content-Type': 'application/json' },
        body: '{"ok":true}',
      }, parityGrant, AbortSignal.timeout(5_000)),
      (err: unknown) => err instanceof BrokerDenied && /prod_readonly/.test(err.message),
    )

    const h2Leased = await rpcCall(rpcServer, 'http2', {
      origin: h2Fixture.origin,
      method: 'POST',
      path: '/leased/42',
      headers: { 'Content-Type': 'application/json' },
      body: '{"ok":true}',
    })
    assert.equal(h2Leased.ok, false, 'prod_readonly must refuse leased route on HTTP/2 with broker parity')
    assert.match(h2Leased.error ?? '', /prod_readonly/i)

    // 5. Unleased mutation in prod_readonly denied on BOTH broker.executeHttp AND verify-rpc http2
    await assert.rejects(
      broker.executeHttp({
        origin: h2Fixture.origin,
        method: 'POST',
        pathAndQuery: '/api/items',
        headers: { 'Content-Type': 'application/json' },
        body: '{"name":"x"}',
      }, parityGrant, AbortSignal.timeout(5_000)),
      (err: unknown) => err instanceof BrokerDenied && /prod_readonly/.test(err.message),
    )
    const h2Unleased = await rpcCall(rpcServer, 'http2', {
      origin: h2Fixture.origin,
      method: 'POST',
      path: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"x"}',
    })
    assert.equal(h2Unleased.ok, false)
    assert.match(h2Unleased.error ?? '', /prod_readonly/)

    // 6. Browser in-scope GET succeeds
    const rpcBrowserOk = await rpcCall(rpcServer, 'browser', { origin: h2Fixture.origin, path: '/home' })
    assert.equal(rpcBrowserOk.ok, true, rpcBrowserOk.error ?? 'expected in-scope browser GET to succeed')
    assert.equal(browserHits, 1)
    assert.equal(httpHits, 1)
    assert.equal(h2Hits, 1)

    // 7. Ephemeral lab Tier 3 unapproved POST raises BrokerApprovalRequired on broker and approval error on verify-rpc http2
    const ephemeralGrant: Grant = {
      ...parityGrant,
      scopePolicy: { mode: 'ephemeral_lab', targetOrigins: [h2Fixture.origin] },
      approvalLeases: undefined,
      isStateChangeApproved: () => false,
    }
    await assert.rejects(
      broker.executeHttp({
        origin: h2Fixture.origin,
        method: 'POST',
        pathAndQuery: '/api/items',
        body: '{"x":1}',
      }, ephemeralGrant, AbortSignal.timeout(5_000)),
      BrokerApprovalRequired,
    )
  } finally {
    await rpcServer.close()
    await h2Fixture.close()
    if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
  }
})
