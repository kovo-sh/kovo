import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import type { Finding } from '../src/domain.ts'
import {
  authorizeStateChange,
  computeStateChangeBodyHash,
  evaluateTier3Approval,
  StateChangeApprovalLedger,
} from '../src/server/approval-judge.ts'
import {
  BrokerApprovalRequired,
  BrokerDenied,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { classifyBrowserHttpRequest } from '../src/server/scoped-browser.ts'
import {
  evaluateScopeRequest,
  isRouteDenylisted,
  isVerifiedReadOnlyGraphqlQuery,
  originRoleFor,
  routePatternForPath,
  tenantTagForRun,
} from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

// ============================================================================
// v6 Phase 2 Layer-1: three-tier origin scope, environment contracts and durable
// route-scoped approval leases.
//
// Defensive QA framing: differential probes are authorized only inside the declared
// scope/environment contract; benign IdP/CDN infrastructure hops are provenance,
// never evidence-bearing targets.
// ============================================================================

const appOrigin = 'https://app.example.com'
const idpOrigin = 'https://idp.example.com'
const cdnOrigin = 'https://cdn.example.com'
const publicAddress = { address: '93.184.216.34', family: 4 }

function policy(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'prod_readonly',
    targetOrigins: [appOrigin],
    authOrigins: [idpOrigin],
    assetOrigins: [cdnOrigin],
    routeDenylist: [],
    tenantTag: tenantTagForRun('run-scope-1'),
    ...overrides,
  }
}

function grantFor(scope: ScopePolicy, overrides: Partial<Grant> = {}): Grant {
  return {
    tier: 3,
    canRead: origin => scope.targetOrigins.includes(origin),
    scopePolicy: scope,
    audit: () => {},
    ...overrides,
  }
}

function transportStub(calls: Array<{ method: string; url: string }>) {
  return async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string }) => {
    calls.push({ method: options?.method ?? 'GET', url: url.href })
    if (url.hostname === new URL(appOrigin).hostname && url.pathname === '/login') {
      return {
        status: 302,
        headers: { location: `${idpOrigin}/oauth/authorize?client_id=kovo` },
        body: '',
      }
    }
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  }
}

function brokerFor(calls: Array<{ method: string; url: string }>): RequestBroker {
  return new RequestBroker({
    resolve: async () => [publicAddress],
    transport: transportStub(calls),
  })
}

function makeStorage(t: { after(fn: () => void): void }): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-scope-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

// ---------------------------------------------------------------------------
// 1. Origin roles
// ---------------------------------------------------------------------------

test('v6 scope: role model classifies target/auth/asset origins and refuses active probes', () => {
  const scope = policy()
  assert.equal(originRoleFor(scope, appOrigin), 'target')
  assert.equal(originRoleFor(scope, idpOrigin), 'auth')
  assert.equal(originRoleFor(scope, cdnOrigin), 'asset')
  assert.equal(originRoleFor(scope, 'https://evil.example'), null)

  // Active probing of the IdP is refused; redirect transit and token exchange are the only verbs.
  const idpProbe = evaluateScopeRequest(scope, { origin: idpOrigin, method: 'GET', pathAndQuery: '/admin' })
  assert.equal(idpProbe.allowed, false)
  assert.equal(idpProbe.code, 'auth_origin_active_probe')

  const idpRedirect = evaluateScopeRequest(scope, {
    origin: idpOrigin, method: 'GET', pathAndQuery: '/oauth/authorize?client_id=kovo', redirectHop: true,
  })
  assert.equal(idpRedirect.allowed, true)

  const tokenExchange = evaluateScopeRequest(scope, {
    origin: idpOrigin,
    method: 'POST',
    pathAndQuery: '/oauth/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=authorization_code&code=abc',
  })
  assert.equal(tokenExchange.allowed, true, 'OAuth token exchange stays available')
  const idpBypass = evaluateScopeRequest(scope, {
    origin: idpOrigin, method: 'POST', pathAndQuery: '/admin/users', body: '{"role":"admin"}',
  })
  assert.equal(idpBypass.allowed, false)

  // CDN: browser passive GET only; the broker cannot actively probe it.
  assert.equal(evaluateScopeRequest(scope, { origin: cdnOrigin, method: 'GET', pathAndQuery: '/app.js', surface: 'browser' }).allowed, true)
  const cdnActive = evaluateScopeRequest(scope, { origin: cdnOrigin, method: 'GET', pathAndQuery: '/app.js' })
  assert.equal(cdnActive.allowed, false)
  assert.equal(cdnActive.code, 'asset_origin_active_probe')
  const cdnPost = evaluateScopeRequest(scope, { origin: cdnOrigin, method: 'POST', pathAndQuery: '/upload', surface: 'browser' })
  assert.equal(cdnPost.allowed, false)
})

test('v6 scope: prod_readonly blocks mutations but permits verified read-only GraphQL', () => {
  const scope = policy()
  assert.equal(evaluateScopeRequest(scope, { origin: appOrigin, method: 'GET', pathAndQuery: '/items' }).allowed, true)
  const mutation = evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'POST', pathAndQuery: '/api/items', body: '{"name":"x"}',
  })
  assert.equal(mutation.allowed, false)
  assert.equal(mutation.code, 'readonly_environment')

  const queryBody = '{"query":"query Viewer { viewer { id } }","variables":{}}'
  assert.equal(isVerifiedReadOnlyGraphqlQuery('/graphql', queryBody), true)
  assert.equal(evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'POST', pathAndQuery: '/graphql', body: queryBody,
  }).allowed, true)
  assert.equal(evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'POST', pathAndQuery: '/graphql', body: '{"query":"mutation { nuke }"}',
  }).allowed, false)
})

test('v6 scope: staging_isolated requires the run tenant tag or setup/cleanup, and honours the denylist', () => {
  const tag = 'kovo-qa-run-scope-1-'
  const scope = policy({ mode: 'staging_isolated', tenantTag: tag, routeDenylist: ['/billing/charge'] })
  const untagged = evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'POST', pathAndQuery: '/api/items', body: '{"name":"x"}',
  })
  assert.equal(untagged.allowed, false)
  assert.equal(untagged.code, 'staging_untagged_mutation')

  const tagged = evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'POST', pathAndQuery: `/api/items?tenant=${tag}abc`, body: '{"name":"x"}',
  })
  assert.equal(tagged.allowed, true)

  const hook = evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'DELETE', pathAndQuery: '/api/items/1', hook: 'cleanup',
  })
  assert.equal(hook.allowed, true)

  const denied = evaluateScopeRequest(scope, {
    origin: appOrigin, method: 'POST', pathAndQuery: '/billing/charge', body: `{"tenant":"${tag}x"}`,
  })
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, 'staging_denylist')
  assert.equal(isRouteDenylisted(scope, '/billing/charge/retry'), true)
  assert.equal(isRouteDenylisted(scope, '/billing'), false)
})

// ---------------------------------------------------------------------------
// 2. Broker enforcement
// ---------------------------------------------------------------------------

test('v6 scope: broker refuses a prod_readonly mutation without ever opening an approval popup', async () => {
  const calls: Array<{ method: string; url: string }> = []
  const broker = brokerFor(calls)
  let approvalConsulted = false
  const grant = grantFor(policy(), {
    isStateChangeApproved: () => {
      approvalConsulted = true
      return false
    },
  })
  await assert.rejects(
    broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"x"}',
    }, grant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /prod_readonly/.test(error.message),
  )
  assert.equal(approvalConsulted, false, 'prod_readonly must not invoke the approval flow')
  assert.equal(calls.length, 0, 'no request may leave the broker')
  assert.equal(broker.isCircuitOpen(appOrigin), false, 'a scope refusal must not trip the target breaker')
})

test('v6 scope: broker allows a run-tagged staging mutation and refuses a denylisted route', async () => {
  const calls: Array<{ method: string; url: string }> = []
  const broker = brokerFor(calls)
  const tag = 'kovo-qa-run-scope-1-'
  const grant = grantFor(policy({
    mode: 'staging_isolated',
    tenantTag: tag,
    routeDenylist: ['/billing/charge'],
  }))
  const result = await broker.executeHttp({
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: `/api/items?tenant=${tag}abc`,
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"synthetic"}',
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(result.status, 200)
  assert.equal(calls.length, 1)

  await assert.rejects(
    broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/billing/charge',
      headers: { 'Content-Type': 'application/json' },
      body: `{"tenant":"${tag}abc"}`,
    }, grant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /denylist/.test(error.message),
  )
  assert.equal(calls.length, 1, 'denylisted route never reaches the wire')
})

test('v6 scope: broker follows an IdP redirect permitted only by the auth role', async () => {
  const calls: Array<{ method: string; url: string }> = []
  const broker = brokerFor(calls)
  const grant = grantFor(policy(), {
    // The v5 allowlist only knows the target; the auth role is what permits the IdP hop.
    canRead: origin => origin === appOrigin,
  })
  const result = await broker.executeHttp({
    origin: appOrigin,
    method: 'GET',
    pathAndQuery: '/login',
    followRedirects: true,
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(result.finalOrigin, idpOrigin)
  assert.deepEqual(new Set(result.redirectOrigins), new Set([appOrigin, idpOrigin]))
  assert.equal(calls.length, 2)

  // The same active probe to the IdP (not a redirect hop) is refused.
  await assert.rejects(
    broker.executeHttp({ origin: idpOrigin, method: 'GET', pathAndQuery: '/admin' }, grant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /IdP|authentication/i.test(error.message),
  )
})

test('v6 scope: the pooled browser uses the same scope-policy classifier', () => {
  const scope = policy()
  const decide = (method: string, url: string) => classifyBrowserHttpRequest({
    method, url, tier: 3, canRead: origin => origin === appOrigin, allowLocalLab: false, scopePolicy: scope,
  })
  assert.equal(decide('GET', `${appOrigin}/app`).allowed, true)
  const mutation = decide('POST', `${appOrigin}/api/items`)
  assert.equal(mutation.allowed, false)
  assert.equal(mutation.reason, 'readonly_environment')
  const asset = decide('GET', `${cdnOrigin}/chunks/app.js`)
  assert.equal(asset.allowed, true)
  assert.equal(asset.assetHydration, true)
  assert.equal(decide('POST', `${cdnOrigin}/upload`).allowed, false)
  assert.equal(decide('GET', `${idpOrigin}/oauth/authorize`).allowed, true, 'IdP navigation is redirect transit')
})

test('v6 scope: ephemeral_lab keeps the legacy approval flow unchanged', async () => {
  const broker = brokerFor([])
  const grant = grantFor(policy({ mode: 'ephemeral_lab' }), {
    isStateChangeApproved: () => false,
  })
  await assert.rejects(
    broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"x"}',
    }, grant, AbortSignal.timeout(5_000)),
    BrokerApprovalRequired,
  )
})

test('v6 scope: durable route lease is scoped, survives iterations/replay, and overrides prod_readonly denial', async t => {
  const { storage } = makeStorage(t)
  const { runId, run, assetIds } = await setupApprovedRun(storage, {
    seeds: [appOrigin], tier: 3, environment: 'public',
  })
  void assetIds
  storage.setEnvironmentMode(storage.run(runId), 'prod_readonly')
  const lease = storage.grantApprovalLease(storage.run(runId), {
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/items/12345',
  })
  assert.equal(routePatternForPath('/api/items/12345'), '/api/items/*')
  assert.equal(lease.routePattern, '/api/items/*')

  const leaseCheck = (o: string, m: string, p: string) => storage.leaseAuthorizes(runId, o, m, p)
  const broker = brokerFor([])
  const grant = grantFor(policy(), { isStateChangeApproved: () => false, approvalLeases: leaseCheck })

  for (const id of ['11111', '22222', '33333']) {
    const result = await broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: `/api/items/${id}`,
      headers: { 'Content-Type': 'application/json' },
      body: `{"name":"iteration-${id}"}`,
    }, grant, AbortSignal.timeout(5_000))
    assert.equal(result.status, 200)
  }
  assert.equal(storage.listApprovalLeases(runId, 'active')[0]?.uses, 3, 'lease usage is audited')

  // Independent replay through a fresh broker/grant still matches the same durable lease.
  const replayGrant = grantFor(policy(), { isStateChangeApproved: () => false, approvalLeases: leaseCheck })
  const replay = await brokerFor([]).executeHttp({
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/items/99999',
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"replay"}',
  }, replayGrant, AbortSignal.timeout(5_000))
  assert.equal(replay.status, 200)

  // A different route on the same origin is not covered by the route-scoped lease.
  await assert.rejects(
    broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/admin/roles',
      headers: { 'Content-Type': 'application/json' },
      body: '{"role":"admin"}',
    }, grant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /prod_readonly/.test(error.message),
  )
  assert.ok(run.id === runId)
})

// ---------------------------------------------------------------------------
// 3. Provenance through benign infrastructure hops
// ---------------------------------------------------------------------------

test('v6 scope: a target finding survives IdP redirect + CDN asset hops', async t => {
  const { storage } = makeStorage(t)
  const { runId, assetIds } = await setupApprovedRun(storage, {
    seeds: [appOrigin], tier: 3, environment: 'public',
  })
  const run = storage.run(runId)
  storage.updateRun(runId, { authOrigins: [idpOrigin], assetOrigins: [cdnOrigin] })
  const assetId = assetIds[0]!
  const worker = storage.makeWorker(storage.run(runId), 'investigation', run.candidates.find(c => c.id === assetId), 'Provenance', 'Verify finding provenance')
  const artifact = storage.addArtifact(storage.run(runId), worker, 'replay', 'Proof', '{}')

  const finding = {
    id: randomUUID(),
    origin: appOrigin,
    title: 'Cross-tenant object read after SSO',
    status: 'confirmed',
    severity: 'high',
    reason: 'Synthetic differential probe confirmed unauthorized read.',
    remediation: 'Enforce tenant ownership check.',
    evidenceIds: [artifact.id],
    exchangeIds: [randomUUID()],
    scopeRevision: run.scopeRevision,
  } as unknown as Finding

  storage.upsertChainFinding(storage.run(runId), assetId, finding, randomUUID(), [appOrigin, idpOrigin, cdnOrigin])
  const reportId = storage.writeReport(storage.run(runId), true)
  const report = storage.runDetail(runId).reports.find(row => row.id === reportId)
  assert.ok(report, 'report exists')
  assert.ok(
    report!.body.findings.some(item => item.id === finding.id),
    'IdP/CDN hops must not drop a valid target finding',
  )

  // Control: a truly unapproved origin still invalidates provenance.
  const rogue = { ...finding, id: randomUUID(), title: 'Rogue hop' } as unknown as Finding
  storage.upsertChainFinding(storage.run(runId), assetId, rogue, randomUUID(), [appOrigin, 'https://rogue.example'])
  const report2 = storage.writeReport(storage.run(runId), true)
  const body2 = storage.runDetail(runId).reports.find(row => row.id === report2)!.body
  assert.equal(body2.findings.some(item => item.id === rogue.id), false)
})

test('v6 scope: benign hops never taint board posts or revoke workers', async t => {
  const { storage } = makeStorage(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  storage.updateRun(runId, { authOrigins: [idpOrigin], assetOrigins: [cdnOrigin] })
  const post = storage.postBoardMessage(storage.run(runId), {
    authorHandle: 'coordinator',
    authorRole: 'coordinator',
    kind: 'verdict',
    body: 'Target finding survived the OIDC redirect.',
    sourceOrigins: [appOrigin, idpOrigin, cdnOrigin],
  })
  const taint = storage.taintBoardMessagesForRevokedOrigins(runId, new Set([appOrigin]))
  assert.equal(taint.taintedMessageIds.includes(post.id), false)
})

// ---------------------------------------------------------------------------
// 4. Environment contract at the judge + non-blocking parking + legacy migration
// ---------------------------------------------------------------------------

test('v6 scope: approval judge follows the environment contract and never escalates for prod_readonly', async () => {
  const blocked = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/items',
    bodyPreview: '{"name":"x"}',
    mode: 'prod_readonly',
  })
  assert.equal(blocked.decision, 'deny')
  assert.equal(blocked.stage, 'environment_contract')
  assert.equal(blocked.usedLlm, false)

  const tagged = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/items',
    bodyPreview: '{"tenant":"kovo-qa-run-scope-1-x"}',
    mode: 'staging_isolated',
    tenantTag: 'kovo-qa-run-scope-1-',
  })
  assert.equal(tagged.decision, 'approve')
  assert.equal(tagged.stage, 'environment_contract')

  const denylisted = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/billing/charge',
    bodyPreview: '{"tenant":"kovo-qa-run-scope-1-x"}',
    mode: 'staging_isolated',
    tenantTag: 'kovo-qa-run-scope-1-',
    routeDenylist: ['/billing/charge'],
  })
  assert.equal(denylisted.decision, 'deny')
})

test('v6 scope: awaiting_approval parks with the slot released and persists across reopen', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-park-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  let storage = new Store(dir)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  const run = storage.run(runId)
  const worker = storage.makeWorker(run, 'investigation', run.candidates[0], 'Park', 'Park me')
  const originalLease = worker.lease

  const parked = storage.parkWorkerForApproval(run, worker.id)
  assert.equal(parked.status, 'waiting_approval')
  assert.equal(parked.lease, null)
  assert.equal(parked.leaseExpiresAt, null)
  assert.ok(parked.approvalParkedAt)
  assert.equal(storage.parkedWorkerCount(runId), 1)
  storage.close()

  storage = new Store(dir)
  t.after(() => storage.close())
  const reopened = storage.worker(worker.id)
  assert.equal(reopened.status, 'waiting_approval')
  assert.equal(reopened.lease, null)
  assert.equal(reopened.approvalParkedAt, parked.approvalParkedAt)

  const resumed = storage.resumeParkedWorker(storage.run(runId), worker.id)
  assert.equal(resumed.status, 'running')
  assert.equal(resumed.approvalParkedAt, null)
  assert.ok(resumed.lease && resumed.lease !== originalLease, 'resume issues a fresh slot lease')
})

test('v6 scope: operator approval grants a durable route lease (not a 60 s body hash)', async t => {
  const { storage } = makeStorage(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  const run = storage.run(runId)
  const worker = storage.makeWorker(run, 'investigation', run.candidates[0], 'Approval', 'Review me')
  const request = storage.createApprovalRequest(storage.run(runId), worker, {
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/items/7',
    rationale: 'Operator opted into this sensitive route.',
    requestPreview: 'POST /api/items/7',
  })
  storage.decideApproval(storage.run(runId), request.id, 'approved')
  const leases = storage.listApprovalLeases(runId, 'active')
  assert.equal(leases.length, 1)
  assert.equal(leases[0]!.routePattern, '/api/items/*')
  assert.equal(storage.leaseAuthorizes(runId, appOrigin, 'POST', '/api/items/8'), true)
  assert.equal(storage.leaseAuthorizes(runId, appOrigin, 'POST', '/api/items/9'), true, 'durable across iterations')
  assert.equal(storage.leaseAuthorizes(runId, appOrigin, 'DELETE', '/api/items/9'), false)
  assert.equal(storage.leaseAuthorizes(runId, appOrigin, 'POST', '/api/orders/9'), false)
})

test('v6 scope: legacy approved allowlist migrates into targetOrigins on reopen', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-legacy-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const first = new Store(dir)
  const { runId } = await setupApprovedRun(first, { seeds: [appOrigin], tier: 3, environment: 'public' })
  first.close()

  const storage = new Store(dir)
  t.after(() => storage.close())
  const scope = storage.scopePolicy(runId)
  assert.deepEqual(scope.targetOrigins, [appOrigin], 'legacy allowlist remains the target tier')
  assert.deepEqual(scope.authOrigins, [])
  assert.deepEqual(scope.assetOrigins, [])
  assert.equal(scope.mode, 'prod_readonly')
})

test('v6 scope: exact single-use ledger semantics are unchanged for opted-in patterns', () => {
  const ledger = new StateChangeApprovalLedger()
  const fingerprint = {
    runId: 'run-1',
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/items/1',
    personaHandle: 'user_a',
    bodyHash: computeStateChangeBodyHash('{"name":"x"}'),
    hasMultipart: false,
    isRaceBurst: false,
    isRceProof: false,
    scopeRevision: 1,
  }
  ledger.grant(fingerprint, { expiresAt: Date.now() + 60_000, approvalId: 'approval-1' })
  assert.equal(ledger.consume(fingerprint), true)
  assert.equal(ledger.consume(fingerprint), false, 'single-use grants stay single-use')
  assert.equal(ledger.consume({ ...fingerprint, pathAndQuery: '/api/items/2' }), false)
  assert.equal(authorizeStateChange({
    ...fingerprint,
    approvedPatterns: [],
    ledger,
  }).approved, false)
})
