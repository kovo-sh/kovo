/**
 * Move C Part 1 (`WS-8` + `WS-10`) regression suite:
 *  - R2-H-1: Method-override effective verb detection, structural classification, derived staging tag isolation.
 *  - H-3: Confirmed GraphQL endpoints, override denial, strict Content-Type, strict JSON reuse in judge.
 *  - H-4: Canonical headers digest in fingerprints/grouping, batch target-list hash binding, per-target audit trails.
 *  - R2-H-19: Truncated compressed HTTP/1.1 settlement + slot release, withAbort transport bound, batchLock owner TTL.
 *  - C-1: RequestBroker.executeHttp2Exchange slot/circuit/audit/UA/proxy controls & hop-by-hop stripping in egressHttp2.
 *  - H-14: Broker wireCredentialProvenance (names & sources only, zero secret leakage).
 *  - H-2: EgressGateway global & per-tenant GlobalKillSwitch enforcement.
 */
import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { IncomingHttpHeaders as H2IncomingHeaders, ServerHttp2Session, ServerHttp2Stream } from 'node:http2'
import { createServer as createTcpServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import test from 'node:test'
import { gzipSync } from 'node:zlib'
import {
  authorizeStateChange,
  buildStateChangeFingerprint,
  evaluateTier3Approval,
  StateChangeApprovalLedger,
} from '../src/server/approval-judge.ts'
import { computeApprovalHeadersDigest } from '../src/server/approval-pattern.ts'
import {
  BrokerCircuitOpen,
  BrokerDenied,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { EgressGateway } from '../src/server/egress-gateway.ts'
import { GlobalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  classifyRequestMutation,
  RequestAdmissionEngine,
} from '../src/server/request-admission.ts'
import type { AdmissionGrant } from '../src/server/request-admission.ts'
import {
  detectMethodOverride,
  evaluateScopeRequest,
  isVerifiedReadOnlyGraphqlQuery,
  requestCarriesTenantTag,
  tenantTagForRun,
} from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import type { Run } from '../src/server/store.ts'
import {
  bindBatchApprovalDecision,
  planTier3ApprovalTargets,
  registerBatchStateChangeGrants,
  registerStateChangeGrant,
  verifyBatchApprovalBinding,
} from '../src/server/tier3-approval.ts'
import type { BatchTargetAuditEntry, BurstApprovalInstances } from '../src/server/tier3-approval.ts'

const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeScope(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'prod_readonly',
    targetOrigins: [APP_ORIGIN],
    routeDenylist: ['/billing/charge'],
    tenantTag: tenantTagForRun('run-movec-1'),
    runId: 'run-movec-1',
    ...overrides,
  }
}

function makeAdmissionGrant(overrides: Partial<AdmissionGrant> = {}): AdmissionGrant {
  return {
    origin: APP_ORIGIN,
    tier: 3,
    allowLocalLab: false,
    canRead: origin => origin === APP_ORIGIN,
    ...overrides,
  }
}

function makeBrokerGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: APP_ORIGIN,
    tier: 3,
    allowLocalLab: false,
    canRead: origin => origin === APP_ORIGIN,
    audit: () => {},
    ...overrides,
  }
}

function makeFakeRun(overrides: Partial<Run> = {}): Run {
  return {
    id: 'run-movec-1',
    projectId: 'proj-1',
    scopeRevision: 2,
    approvalPolicy: 'auto_review',
    ...overrides,
  } as Run
}

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
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

// ============================================================================
// 1. R2-H-1: Method overrides & derived staging_isolated tag isolation
// ============================================================================

test('R2-H-1: effective HTTP verb detects override headers and _method query/form/JSON carriers', () => {
  const cases: Array<{
    label: string
    input: { method: string; pathAndQuery: string; headers?: Record<string, string>; body?: string }
    expectedVerb: string
    expectedCarrier: string
  }> = [
    {
      label: 'X-HTTP-Method-Override header',
      input: { method: 'POST', pathAndQuery: '/api/items/42', headers: { 'X-HTTP-Method-Override': 'DELETE' } },
      expectedVerb: 'DELETE',
      expectedCarrier: 'header:x-http-method-override',
    },
    {
      label: 'X-HTTP-Method header',
      input: { method: 'POST', pathAndQuery: '/api/items/42', headers: { 'x-http-method': 'delete' } },
      expectedVerb: 'DELETE',
      expectedCarrier: 'header:x-http-method',
    },
    {
      label: 'X-Method-Override header',
      input: { method: 'POST', pathAndQuery: '/api/items/42', headers: { 'X-Method-Override': 'PUT' } },
      expectedVerb: 'PUT',
      expectedCarrier: 'header:x-method-override',
    },
    {
      label: '_method query param',
      input: { method: 'POST', pathAndQuery: '/api/items/42?_method=DELETE' },
      expectedVerb: 'DELETE',
      expectedCarrier: 'query:_method',
    },
    {
      label: '_method form-urlencoded body',
      input: {
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'name=test&_method=DELETE',
      },
      expectedVerb: 'DELETE',
      expectedCarrier: 'form:_method',
    },
    {
      label: '_method JSON body',
      input: {
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ _method: 'DELETE', id: 42 }),
      },
      expectedVerb: 'DELETE',
      expectedCarrier: 'json:_method',
    },
  ]

  for (const tc of cases) {
    const det = detectMethodOverride(tc.input)
    assert.equal(det.hasOverride, true, tc.label)
    assert.equal(det.effectiveMethod, tc.expectedVerb, tc.label)
    assert.ok(det.carriers.includes(tc.expectedCarrier), `${tc.label}: ${det.carriers.join(',')}`)

    const cls = classifyRequestMutation(tc.input)
    assert.equal(cls.hasMethodOverride, true, tc.label)
    assert.equal(cls.effectiveMethod, tc.expectedVerb, tc.label)
    assert.equal(cls.isStructuralMutation, true, `${tc.label} must be structural`)
    assert.equal(cls.isReadOnly, false, tc.label)
  }

  // Even a GET carrying X-HTTP-Method-Override: DELETE is NOT read-only
  const getOverride = classifyRequestMutation({
    method: 'GET',
    pathAndQuery: '/api/items/42',
    headers: { 'x-http-method-override': 'DELETE' },
  })
  assert.equal(getOverride.isReadOnly, false)
  assert.equal(getOverride.isStructuralMutation, true)
  assert.equal(getOverride.effectiveMethod, 'DELETE')
})

test('R2-H-1: derived staging_isolated never auto-approves override carriers or host-injected run-tag headers alone', async () => {
  const tag = tenantTagForRun('run-r2h1')
  const scope = makeScope({ mode: 'staging_isolated', tenantTag: tag, runId: 'run-r2h1' })

  // Host-injected x-kovo-tenant-tag header alone does NOT prove tenant isolation on derived staging runs
  assert.equal(
    requestCarriesTenantTag(
      {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: { 'x-kovo-tenant-tag': tag, 'x-kovo-run-id': 'run-r2h1' },
        body: '{"status":"archived"}',
      },
      tag,
      { ignoreHostInjectedHeaders: true },
    ),
    false,
  )
  assert.equal(
    evaluateScopeRequest(
      { ...scope, derivedEnvironmentMode: true },
      {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/items/42',
        headers: { 'x-kovo-tenant-tag': tag, 'x-kovo-run-id': 'run-r2h1' },
        body: '{"status":"archived"}',
      },
    ).allowed,
    false,
  )
  // Real target-visible tag in path/body DOES satisfy requestCarriesTenantTag
  assert.equal(
    requestCarriesTenantTag(
      {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: `/api/items?tenant=${tag}1`,
        body: '{"name":"ok"}',
      },
      tag,
    ),
    true,
  )

  const engine = new RequestAdmissionEngine({ env: {} })
  // Derived staging_isolated (approvalPolicy present -> explicitEnvironmentMode=false)
  const derivedGrant = makeAdmissionGrant({
    scopePolicy: scope,
    approvalPolicy: 'auto_review',
    isStateChangeApproved: () => false,
  })

  // 1. Host-injected tag header alone MUST escalate (require_approval), not auto-approve
  const hostTagOnly = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/42',
      headers: { 'x-kovo-tenant-tag': tag, 'content-type': 'application/json' },
      body: '{"name":"live-user-record"}',
    },
    derivedGrant,
  )
  assert.equal(hostTagOnly.outcome, 'require_approval')
  assert.equal(hostTagOnly.reasonCode, 'approval_required')

  // 2. Even WITH a path tenant tag, POST + X-HTTP-Method-Override: DELETE MUST escalate!
  const overrideHeader = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/items/42?tenant=${tag}1`,
      headers: { 'X-HTTP-Method-Override': 'DELETE', 'content-type': 'application/json' },
      body: '{}',
    },
    derivedGrant,
  )
  assert.equal(overrideHeader.outcome, 'require_approval')
  assert.equal(overrideHeader.classification?.isStructuralMutation, true)
  assert.equal(overrideHeader.classification?.effectiveMethod, 'DELETE')

  // 3. Even WITH a path tenant tag, POST + _method=DELETE form field MUST escalate!
  const overrideForm = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/items/42?tenant=${tag}1`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: '_method=DELETE',
    },
    derivedGrant,
  )
  assert.equal(overrideForm.outcome, 'require_approval')

  // 4. An operator POST pattern MUST NEVER authorize a POST carrying X-HTTP-Method-Override: DELETE
  const postPattern = [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/api/items/*' }]
  const judgeVerdict = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    headers: { 'X-HTTP-Method-Override': 'DELETE' },
    approvedPatterns: postPattern,
    offline: true,
  })
  assert.equal(judgeVerdict.decision, 'escalate_human')
  assert.equal(judgeVerdict.stage, 'hard_escalation')

  const authVerdict = authorizeStateChange({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/42',
    context: {
      headers: { 'x-http-method-override': 'DELETE' },
      hasMethodOverride: true,
    },
    approvedPatterns: postPattern,
  })
  assert.equal(authVerdict.approved, false)
})

// ============================================================================
// 2. H-3: Confirmed GraphQL endpoints, override denial, strict JSON in judge
// ============================================================================

test('H-3: GraphQL read-only requires confirmed endpoints, denies method overrides & loose media types, and judge reuses strict JSON', async () => {
  const readQuery = JSON.stringify({ query: 'query Viewer { viewer { id } }' })

  // 1. When confirmedGraphqlEndpoints is empty, even `/graphql` is denied
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql', readQuery, { 'content-type': 'application/json' }, {
      confirmedEndpoints: [],
      origin: APP_ORIGIN,
    }),
    false,
  )

  // 2. When confirmedGraphqlEndpoints lists `/custom/gql`, `/custom/gql` is allowed while `/graphql` is denied
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/custom/gql', readQuery, { 'content-type': 'application/json' }, {
      confirmedEndpoints: ['/custom/gql'],
      origin: APP_ORIGIN,
    }),
    true,
  )
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql', readQuery, { 'content-type': 'application/json' }, {
      confirmedEndpoints: ['/custom/gql'],
      origin: APP_ORIGIN,
    }),
    false,
  )

  // 3. Arbitrary REST parameter path ending in `/graphql` is denied even without confirmedEndpoints
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/api/users/graphql', readQuery, { 'content-type': 'application/json' }),
    false,
  )
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/items/graphql', readQuery, { 'content-type': 'application/json' }),
    false,
  )

  // 4. Method overrides on GraphQL reads are ALWAYS denied
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql', readQuery, {
      'content-type': 'application/json',
      'X-HTTP-Method-Override': 'DELETE',
    }, { confirmedEndpoints: ['/graphql'] }),
    false,
  )
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql?_method=DELETE', readQuery, {
      'content-type': 'application/json',
    }, { confirmedEndpoints: ['/graphql'] }),
    false,
  )

  // 5. Strict Content-Type (no substring bypass like `text/plain; hint=json`) & duplicate content-type denied
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql', readQuery, { 'content-type': 'text/plain; x=json' }),
    false,
  )
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql', 'query { ok }', { 'content-type': 'text/plain; application/graphql' }),
    false,
  )
  assert.equal(
    isVerifiedReadOnlyGraphqlQuery('/graphql', readQuery, {
      'Content-Type': 'application/json',
      'content-type': 'text/plain',
    }),
    false,
  )

  // 6. ScopePolicy & RequestAdmissionEngine enforce confirmedGraphqlEndpoints
  const strictScope = makeScope({ mode: 'prod_readonly', confirmedGraphqlEndpoints: ['/v2/gql'] })
  assert.equal(
    evaluateScopeRequest(strictScope, {
      origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/graphql', headers: { 'content-type': 'application/json' }, body: readQuery,
    }).allowed,
    false,
  )
  assert.equal(
    evaluateScopeRequest(strictScope, {
      origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/v2/gql', headers: { 'content-type': 'application/json' }, body: readQuery,
    }).allowed,
    true,
  )
  const engine = new RequestAdmissionEngine({ env: {} })
  const dupHdr = engine.admit({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/v2/gql',
    headers: { 'Content-Type': 'application/json', 'content-type': 'text/plain' },
    body: readQuery,
  }, makeAdmissionGrant({ scopePolicy: strictScope }))
  assert.equal(dupHdr.outcome, 'deny')
  assert.equal(dupHdr.reasonCode, 'invalid_header')

  // 7. Judge reuses strict JSON validator: escaped mutation hint & duplicate keys escalate instead of benign fast-path
  const escapedSearch = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/search',
    headers: { 'content-type': 'application/json' },
    bodyPreview: '{"action":"\\u0064elete","q":"users"}',
    offline: true,
  })
  assert.equal(escapedSearch.decision, 'escalate_human')

  const dupKeySearch = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/search',
    headers: { 'content-type': 'application/json' },
    bodyPreview: '{"q":"safe","q":"also-safe"}',
    offline: true,
  })
  assert.equal(dupKeySearch.decision, 'escalate_human')
})

// ============================================================================
// 3. H-4: Headers digest in fingerprint/groupKeyOf, batch targetsHash & per-target audit
// ============================================================================

test('H-4: headers digest & multipartKind bind fingerprints/groups, and batch binding hashes ALL targets with per-target audit', () => {
  // 1. Canonical headers digest is case- and order-insensitive, but distinct on different values
  assert.equal(
    computeApprovalHeadersDigest({ 'X-Role': 'viewer', 'Content-Type': 'application/json' }),
    computeApprovalHeadersDigest({ 'content-type': 'application/json', 'x-role': 'viewer' }),
  )
  assert.notEqual(
    computeApprovalHeadersDigest({ 'x-role': 'viewer' }),
    computeApprovalHeadersDigest({ 'x-role': 'admin' }),
  )

  const fpA = buildStateChangeFingerprint({
    runId: 'r1', origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items',
    headers: { 'x-role': 'viewer' }, body: '{"a":1}',
  })
  const fpB = buildStateChangeFingerprint({
    runId: 'r1', origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items',
    headers: { 'x-role': 'admin' }, body: '{"a":1}',
  })
  assert.notEqual(fpA, fpB)

  // Ledger grant bound to headers refuses consumption with mutated headers
  const ledger = new StateChangeApprovalLedger()
  const burst: BurstApprovalInstances = new Map()
  const run = makeFakeRun()
  registerStateChangeGrant(ledger, burst, run, {
    origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items',
    headers: { 'x-role': 'viewer' }, bodyPreview: '{"a":1}',
  })
  assert.equal(
    ledger.consume({
      runId: run.id, origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items',
      scopeRevision: run.scopeRevision, headers: { 'x-role': 'admin' }, body: '{"a":1}',
    }),
    false,
  )
  assert.equal(
    ledger.consume({
      runId: run.id, origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items',
      scopeRevision: run.scopeRevision, headers: { 'X-Role': 'viewer' }, body: '{"a":1}',
    }),
    true,
  )

  // 2. Grouping separates plain vs compressed AND well-formed vs malformed multipart
  const splitPlan = planTier3ApprovalTargets(run, [
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/upload', headers: { 'content-type': 'multipart/form-data; boundary=abc' }, body: 'ok' },
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/upload', headers: { 'content-type': 'multipart/form-data' }, body: 'ok' },
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items', headers: { 'content-type': 'application/json' }, body: '{"a":1}' },
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/items', headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: '{"a":1}' },
  ])
  assert.equal(splitPlan.targets.length, 4)
  assert.equal(splitPlan.targets[0]!.multipartKind, 'multipart')
  assert.equal(splitPlan.targets[1]!.multipartKind, 'malformed_multipart')

  // Operator pattern must NOT approve malformed multipart when headers are passed in context
  const uploadPattern = [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/upload' }]
  assert.equal(
    authorizeStateChange({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/upload',
      context: { headers: { 'content-type': 'multipart/form-data' }, hasMultipart: true },
      approvedPatterns: uploadPattern,
    }).approved,
    false,
  )

  // 3. Batch decision binding hashes ALL targets (never target[0] alone) and audits per target
  const batchPlanA = planTier3ApprovalTargets(run, [
    { origin: APP_ORIGIN, method: 'DELETE', pathAndQuery: '/api/items/1', headers: { 'x-tag': 'a' } },
    { origin: APP_ORIGIN, method: 'DELETE', pathAndQuery: '/api/items/2', headers: { 'x-tag': 'b' } },
  ])
  const batchPlanTampered = planTier3ApprovalTargets(run, [
    { origin: APP_ORIGIN, method: 'DELETE', pathAndQuery: '/api/items/1', headers: { 'x-tag': 'a' } },
    { origin: APP_ORIGIN, method: 'DELETE', pathAndQuery: '/api/items/999', headers: { 'x-tag': 'b' } },
  ])
  assert.notEqual(batchPlanA.targetsHash, batchPlanTampered.targetsHash)

  const binding = bindBatchApprovalDecision(batchPlanA, {
    approvalId: 'apr-batch-1',
    runId: run.id,
    assignmentId: 'asg-1',
    decision: 'approved',
    decidedBy: 'operator',
  })
  assert.equal(binding.auditEntries.length, 2)
  assert.equal(binding.auditEntries[0]!.pathAndQuery, '/api/items/1')
  assert.equal(binding.auditEntries[1]!.pathAndQuery, '/api/items/2')
  assert.equal(verifyBatchApprovalBinding(binding, batchPlanA.targets), true)
  assert.equal(verifyBatchApprovalBinding(binding, batchPlanTampered.targets), false)

  // Tampered sibling fails closed before registering any grant
  assert.throws(
    () => registerBatchStateChangeGrants(ledger, burst, run, batchPlanTampered.targets, binding),
    /binding mismatch/i,
  )

  // Legitimate binding emits per-target audit rows & grants every target
  const audited: BatchTargetAuditEntry[] = []
  registerBatchStateChangeGrants(ledger, burst, run, batchPlanA.targets, binding, {
    onAudit: entry => audited.push(entry),
  })
  assert.equal(audited.length, 2)
  assert.deepEqual(audited.map(a => a.pathAndQuery), ['/api/items/1', '/api/items/2'])
})

// ============================================================================
// 4. R2-H-19: Truncated gzip HTTP/1.1 settles & releases slot; batchLock TTL
// ============================================================================

test('R2-H-19: truncated gzip HTTP/1.1 response settles cleanly and releases per-origin slot', async t => {
  const fullGzip = gzipSync(Buffer.from('hello world '.repeat(200), 'utf8'))
  const partialGzip = fullGzip.subarray(0, Math.floor(fullGzip.length / 2))
  let requestCount = 0

  const tcpServer = createTcpServer(socket => {
    socket.once('data', () => {
      requestCount += 1
      if (requestCount === 1) {
        // Send headers promising full gzip length + partial gzip bytes, then clean FIN mid-body!
        const head =
          'HTTP/1.1 200 OK\r\n' +
          'Content-Type: text/plain\r\n' +
          'Content-Encoding: gzip\r\n' +
          `Content-Length: ${fullGzip.length}\r\n` +
          'Connection: close\r\n\r\n'
        socket.write(Buffer.concat([Buffer.from(head, 'utf8'), partialGzip]))
        socket.end()
      } else {
        const body = 'recovered-ok'
        const resp =
          'HTTP/1.1 200 OK\r\n' +
          'Content-Type: text/plain\r\n' +
          `Content-Length: ${Buffer.byteLength(body)}\r\n` +
          'Connection: close\r\n\r\n' +
          body
        socket.end(resp)
      }
    })
  })
  await new Promise<void>(resolve => tcpServer.listen(0, '127.0.0.1', resolve))
  const port = (tcpServer.address() as AddressInfo).port
  t.after(async () => {
    await new Promise<void>(resolve => tcpServer.close(() => resolve()))
  })

  const origin = `http://127.0.0.1:${port}`
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      transportConfig: { http2: false },
    })
    t.after(() => broker.closeTransport())
    const grant = makeBrokerGrant({
      origin,
      tier: 2,
      allowLocalLab: true,
      canRead: o => o === origin,
    })

    const started = Date.now()
    await assert.rejects(
      broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/truncated-gzip', timeoutMs: 3_000 }, grant, AbortSignal.timeout(3_000)),
      /premature|aborted|unexpected end|closed/i,
    )
    const elapsed = Date.now() - started
    assert.ok(elapsed < 2_000, `truncated gzip must settle immediately instead of hanging (took ${elapsed}ms)`)
    assert.equal(broker.getOriginInFlight(origin), 0, 'in-flight slot must be released after truncated gzip')

    // Subsequent request on the same origin succeeds cleanly!
    const ok = await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/healthy' }, grant, AbortSignal.timeout(3_000))
    assert.equal(ok.status, 200)
    assert.equal(ok.body, 'recovered-ok')
    assert.equal(broker.getOriginInFlight(origin), 0)
  })
})

test('R2-H-19: hung transport respects withAbort(deadline) and batchLock owner TTL prevents permanent cross-run wedge', async t => {
  let fakeNow = 10_000
  let releaseFirstBatch!: () => void
  let callIndex = 0

  const broker = new RequestBroker({
    now: () => fakeNow,
    batchLockTtlMs: 500,
    resolve: async () => [PUBLIC_ADDR],
    transport: async (_url, _addr, signal) => {
      callIndex += 1
      if (callIndex === 1) {
        // Deliberately ignore signal to prove broker wraps transport in withAbort(deadline)
        return await new Promise(() => {})
      }
      if (callIndex === 2 || callIndex === 3) {
        await new Promise<void>(resolve => {
          releaseFirstBatch = resolve
          signal.addEventListener('abort', () => resolve(), { once: true })
        })
        return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'slow' }
      }
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'fast' }
    },
  })
  t.after(() => broker.closeTransport())
  const grant = makeBrokerGrant({ tier: 2 })

  // 1. Hung transport settles at abort deadline and releases slot
  const ctrl = new AbortController()
  setTimeout(() => ctrl.abort(new Error('deadline-fired')), 50)
  await assert.rejects(
    broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/hang', timeoutMs: 1_000 }, grant, ctrl.signal),
    /deadline-fired/,
  )
  assert.equal(broker.getOriginInFlight(APP_ORIGIN), 0)

  // 2. Batch lock held by stalled owner rejects overlap while active, expires after TTL,
  //    and late release from stalled owner never clears a newer owner's lock.
  const stalledPromise = broker.executeBatch(
    [
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b1' },
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b2' },
    ],
    grant,
    AbortSignal.timeout(5_000),
  )
  await new Promise(r => setTimeout(r, 20))
  assert.equal(broker.isOriginBatchLocked(APP_ORIGIN), true)

  await assert.rejects(
    broker.executeBatch(
      [
        { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b3' },
        { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b4' },
      ],
      grant,
      AbortSignal.timeout(5_000),
    ),
    BrokerDenied,
  )

  // Advance clock past TTL -> lock expires automatically; new batch succeeds!
  fakeNow += 600
  assert.equal(broker.isOriginBatchLocked(APP_ORIGIN), false)
  const freshRes = await broker.executeBatch(
    [
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b5' },
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b6' },
    ],
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(freshRes.length, 2)
  assert.equal(freshRes[0]!.body, 'fast')

  // Unblock stalled batch so it finishes cleanly
  releaseFirstBatch()
  await stalledPromise.catch(() => {})
  assert.equal(broker.isOriginBatchLocked(APP_ORIGIN), false)
})

// ============================================================================
// 5. C-1 & H-14: RequestBroker.executeHttp2Exchange & wireCredentialProvenance
// ============================================================================

test('C-1: RequestBroker.executeHttp2Exchange enforces slots, audit, UA profile, hop-by-hop stripping, and 429 circuit breaker', async t => {
  const sessions = new Set<ServerHttp2Session>()
  const seenHeaders: Array<H2IncomingHeaders> = []
  let activeStreams = 0
  let peakStreams = 0
  let force429 = false

  const h2Server = createH2Server()
  h2Server.on('session', s => {
    sessions.add(s)
    s.once('close', () => sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream, headers: H2IncomingHeaders) => {
    seenHeaders.push({ ...headers })
    activeStreams += 1
    peakStreams = Math.max(peakStreams, activeStreams)
    setTimeout(() => {
      activeStreams -= 1
      const status = force429 ? 429 : 200
      stream.respond({ ':status': status, 'content-type': 'application/json' })
      stream.end(JSON.stringify({ ok: !force429, path: headers[':path'] }))
    }, 30)
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const port = (h2Server.address() as AddressInfo).port
  t.after(async () => {
    for (const s of sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  const origin = `http://127.0.0.1:${port}`
  const auditEvents: Array<{ outcome: string; status?: number }> = []

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const broker = new RequestBroker({
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      circuit429Threshold: 2,
      transportConfig: {
        headerProfile: {
          userAgent: 'KovoAuthorizedScanner/9.9',
          headers: { 'x-authorized-scanner': 'kovo-qa' },
        },
      },
    })
    t.after(() => broker.closeTransport())

    const grant = makeBrokerGrant({
      origin,
      tier: 2,
      allowLocalLab: true,
      maxRpsPerOrigin: 10,
      canRead: o => o === origin,
      audit: (outcome, _origin, status) => auditEvents.push({ outcome, status }),
    })

    // 1. Strips hop-by-hop headers (connection, keep-alive, upgrade) & pseudo-header overrides; injects UA profile
    const res = await broker.executeHttp2Exchange(
      {
        origin,
        method: 'GET',
        pathAndQuery: '/v2/ping',
        headers: {
          ':method': 'DELETE',
          ':path': '/evil',
          Connection: 'keep-alive, x-custom-hop',
          'Keep-Alive': 'timeout=5',
          'x-custom-hop': 'strip-me',
          'x-keep-me': 'yes',
        },
      },
      grant,
      AbortSignal.timeout(5_000),
    )
    assert.equal(res.status, 200)
    assert.equal(seenHeaders.length, 1)
    assert.equal(seenHeaders[0]![':method'], 'GET')
    assert.equal(seenHeaders[0]![':path'], '/v2/ping')
    assert.equal(seenHeaders[0]!['user-agent'], 'KovoAuthorizedScanner/9.9')
    assert.equal(seenHeaders[0]!['x-authorized-scanner'], 'kovo-qa')
    assert.equal(seenHeaders[0]!['x-keep-me'], 'yes')
    assert.equal(seenHeaders[0]!.connection, undefined)
    assert.equal(seenHeaders[0]!['keep-alive'], undefined)
    assert.equal(seenHeaders[0]!['x-custom-hop'], undefined)

    // Audit recorded both allowed and observed
    assert.ok(auditEvents.some(e => e.outcome === 'allowed'))
    assert.ok(auditEvents.some(e => e.outcome === 'observed' && e.status === 200))
    assert.equal(broker.getOriginInFlight(origin), 0)

    // 2. Repeated 429s open the circuit breaker, rejecting subsequent executeHttp2Exchange calls with BrokerCircuitOpen
    force429 = true
    await broker.executeHttp2Exchange({ origin, method: 'GET', pathAndQuery: '/v2/rate-1' }, grant, AbortSignal.timeout(5_000))
    await assert.rejects(
      broker.executeHttp2Exchange({ origin, method: 'GET', pathAndQuery: '/v2/rate-2' }, grant, AbortSignal.timeout(5_000)),
      BrokerCircuitOpen,
    )
    await assert.rejects(
      broker.executeHttp2Exchange({ origin, method: 'GET', pathAndQuery: '/v2/rate-3' }, grant, AbortSignal.timeout(5_000)),
      BrokerCircuitOpen,
    )
    assert.equal(broker.getOriginInFlight(origin), 0)
  })
})

test('H-14: broker exchanges return wireCredentialProvenance with names/sources only and zero raw secret leakage', async t => {
  const secretToken = 'sk-super-secret-persona-token-987654321'
  const jarCookieVal = 'jar-secret-cookie-value-abcdef'
  const seenWireHeaders: Array<Record<string, string>> = []

  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (url, _addr, _sig, opts) => {
      seenWireHeaders.push({ ...(opts?.headers ?? {}) })
      if (url.pathname === '/login') {
        return {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'set-cookie': [`sid=${jarCookieVal}; Path=/; HttpOnly`],
          },
          body: '{"ok":true}',
        }
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"me":"alice"}' }
    },
  })
  t.after(() => broker.closeTransport())

  const persona: ResolvedPersona = {
    id: 'p-alice',
    handle: 'alice',
    roleLabel: 'member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'bearer',
    headerName: null,
    secret: secretToken,
    canaryMarkers: [],
  }
  const grant = makeBrokerGrant({
    tier: 2,
    personas: new Map([['alice', persona]]),
  })

  // 1. Unauthenticated exchange
  const unauth = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/public' },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(unauth.wireCredentialProvenance?.authenticated, false)
  assert.equal(unauth.wireCredentialProvenance?.source, 'none')
  assert.deepEqual(unauth.wireCredentialProvenance?.headerNames, [])
  assert.deepEqual(unauth.wireCredentialProvenance?.cookieNames, [])

  // 2. Populate session jar via /login, then send persona + jar exchange
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/login', persona: 'alice', session: 'sess1' },
    grant,
    AbortSignal.timeout(5_000),
  )
  const authed = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/me', persona: 'alice', session: 'sess1' },
    grant,
    AbortSignal.timeout(5_000),
  )
  const prov = authed.wireCredentialProvenance!
  assert.equal(prov.authenticated, true)
  assert.equal(prov.source, 'persona_and_jar')
  assert.deepEqual(prov.sources, ['persona_vault', 'session_jar'])
  assert.equal(prov.personaHandle, 'alice')
  assert.equal(prov.session, 'sess1')
  assert.deepEqual(prov.vaultHeaderNames, ['authorization'])
  assert.deepEqual(prov.jarCookieNames, ['sid'])
  assert.deepEqual(prov.cookieNames, ['sid'])
  assert.deepEqual(prov.headerNames, ['authorization', 'cookie'])

  // Zero raw secret values may ever appear inside wireCredentialProvenance
  const serializedProv = JSON.stringify(prov)
  assert.equal(serializedProv.includes(secretToken), false)
  assert.equal(serializedProv.includes(jarCookieVal), false)

  // Verify #840/#842 canonical casing preserved on outboundHeaders for persona Authorization & merged Cookie
  const lastWire = seenWireHeaders[seenWireHeaders.length - 1]!
  assert.equal(lastWire.Authorization, `Bearer ${secretToken}`)
  assert.equal(lastWire.Cookie, `sid=${jarCookieVal}`)

  // 3. Self-minted alg:none Bearer reports caller_self_minted
  const hdr = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
  const pay = Buffer.from(JSON.stringify({ sub: 'probe' })).toString('base64url')
  const selfMinted = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/me', headers: { Authorization: `Bearer ${hdr}.${pay}.` } },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(selfMinted.wireCredentialProvenance?.authenticated, true)
  assert.equal(selfMinted.wireCredentialProvenance?.source, 'caller_self_minted')
  assert.deepEqual(selfMinted.wireCredentialProvenance?.callerAuthHeaderNames, ['authorization'])
})

// ============================================================================
// 6. H-2: EgressGateway global and per-tenant GlobalKillSwitch enforcement
// ============================================================================

test('H-2: EgressGateway.egress* entrypoints enforce global and per-tenant GlobalKillSwitch checks', async t => {
  let httpHits = 0
  const httpServer = createHttpServer((_req, res) => {
    httpHits += 1
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve))
  const httpPort = (httpServer.address() as AddressInfo).port
  t.after(async () => {
    httpServer.closeAllConnections()
    await new Promise<void>(resolve => httpServer.close(() => resolve()))
  })

  const h2Sessions = new Set<ServerHttp2Session>()
  let h2Hits = 0
  const h2Server = createH2Server()
  h2Server.on('session', s => {
    h2Sessions.add(s)
    s.once('close', () => h2Sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream) => {
    h2Hits += 1
    stream.respond({ ':status': 200, 'content-type': 'text/plain' })
    stream.end('h2-ok')
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const h2Port = (h2Server.address() as AddressInfo).port
  t.after(async () => {
    for (const s of h2Sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  const ks = new GlobalKillSwitch()
  const httpUrl = `http://127.0.0.1:${httpPort}/ping`
  const h2Url = `http://127.0.0.1:${h2Port}/ping`

  // Trip tenant-a ONLY
  ks.trip({ reason: 'tenant-a emergency stop', tenantId: 'tenant-a' })

  // Tenant-a is rejected across ALL EgressGateway.egress* entrypoints with ZERO hits
  await assert.rejects(
    EgressGateway.egressFetch(httpUrl, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-a' }),
    KillSwitchTrippedError,
  )
  await assert.rejects(
    EgressGateway.egressFetchStream(httpUrl, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-a' }),
    KillSwitchTrippedError,
  )
  await assert.rejects(
    EgressGateway.egressRawHttp1(new URL(httpUrl), { address: '127.0.0.1', family: 4 }, {
      readBody: true, killSwitch: ks, tenantId: 'tenant-a',
    }),
    KillSwitchTrippedError,
  )
  await assert.rejects(
    EgressGateway.egressHttp2(h2Url, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-a' }),
    KillSwitchTrippedError,
  )
  assert.equal(httpHits, 0)
  assert.equal(h2Hits, 0)

  // Tenant-b remains unaffected while only tenant-a is tripped
  const okFetch = await EgressGateway.egressFetch(httpUrl, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-b' })
  assert.equal(okFetch.status, 200)
  const okStream = await EgressGateway.egressFetchStream(httpUrl, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-b' })
  assert.equal(await okStream.text(), 'ok')
  const okRaw = await EgressGateway.egressRawHttp1(new URL(httpUrl), { address: '127.0.0.1', family: 4 }, {
    readBody: true, killSwitch: ks, tenantId: 'tenant-b',
  })
  assert.equal(okRaw.status, 200)
  const okH2 = await EgressGateway.egressHttp2(h2Url, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-b' })
  assert.equal(okH2.status, 200)
  assert.equal(httpHits, 3)
  assert.equal(h2Hits, 1)

  // Loopback proxy enforces tenant kill switch (returns 403 kill_switch_active)
  const proxy = await EgressGateway.createLoopbackProxy({
    allowLocalLab: true,
    killSwitch: ks,
    tenantId: 'tenant-a',
  })
  t.after(() => proxy.close())
  const proxyStatus = await new Promise<{ status: number; denied?: string }>((resolve, reject) => {
    const req = createTcpServer // unused; use http.request directly via proxy socket
    void req
    import('node:http').then(({ request }) => {
      const r = request({
        host: proxy.host,
        port: proxy.port,
        method: 'GET',
        path: httpUrl,
        headers: { 'proxy-authorization': proxy.authorizationHeader },
      }, res => {
        res.resume()
        res.once('end', () => resolve({
          status: res.statusCode ?? 0,
          denied: String(res.headers['x-kovo-egress-denied'] ?? ''),
        }))
      })
      r.once('error', reject)
      r.end()
    }).catch(reject)
  })
  assert.equal(proxyStatus.status, 403)
  assert.equal(proxyStatus.denied, 'kill_switch_active')
  assert.equal(httpHits, 3)

  // Global trip blocks tenant-b too
  ks.trip({ reason: 'global emergency stop' })
  await assert.rejects(
    EgressGateway.egressFetch(httpUrl, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-b' }),
    KillSwitchTrippedError,
  )
  await assert.rejects(
    EgressGateway.egressHttp2(h2Url, {}, { allowLocalLab: true, killSwitch: ks, tenantId: 'tenant-b' }),
    KillSwitchTrippedError,
  )
  assert.equal(httpHits, 3)
  assert.equal(h2Hits, 1)
})
