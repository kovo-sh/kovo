import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { runCommand } from '../src/domain.ts'
import { BrokerApprovalRequired, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, Transport } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import {
  evaluateScopeRequest,
  isVerifiedReadOnlyGraphqlQuery,
  tenantTagForRun,
} from '../src/server/scope-policy.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment } from '../src/server/store.ts'
import { planTier3ApprovalTargets } from '../src/server/tier3-approval.ts'
import { setupApprovedRun, startHttpFixture } from './v4-tier-helpers.ts'

// ============================================================================
// CLAUDE_AUDIT Tier 2 — H-3 (GraphQL read-only & JSON key parity) + H-4
// (Batch/race approval smuggling prevention)
// ============================================================================

const APP_ORIGIN = 'https://app.example.com'
const PUBLIC_ADDRESS = { address: '93.184.216.34', family: 4 }

function makeScopePolicy(overrides: Partial<ScopePolicy> = {}): ScopePolicy {
  return {
    mode: 'prod_readonly',
    targetOrigins: [APP_ORIGIN],
    authOrigins: [],
    assetOrigins: [],
    routeDenylist: [],
    tenantTag: tenantTagForRun('run-t2-sec'),
    ...overrides,
  }
}

function makeRecordingBroker(calls: Array<{ method: string; url: string }>): RequestBroker {
  return new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string }) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
}

function makeScopeGrant(scope: ScopePolicy): Grant {
  return {
    tier: 3,
    canRead: origin => scope.targetOrigins.includes(origin),
    scopePolicy: scope,
    audit: () => {},
  }
}

function fixtureTransport(): Transport {
  return (url, _address, signal, options) => new Promise((resolve, reject) => {
    const req = httpRequest(url, { method: options?.method ?? 'GET', headers: options?.headers }, res => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(Buffer.from(chunk)))
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }))
    })
    req.on('error', reject)
    const onAbort = () => req.destroy(new Error('aborted'))
    signal.addEventListener('abort', onAbort, { once: true })
    req.on('close', () => signal.removeEventListener('abort', onAbort))
    if (options?.body !== undefined) req.write(options.body)
    req.end()
  })
}

async function waitForPendingCard(storage: Store, runId: string, timeoutMs = 8_000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const card = storage.listApprovalRequests(runId, 'pending')[0]
    if (card) return card
    await delay(20)
  }
  throw new Error('Timed out waiting for a Tier-3 approval card')
}

async function makeExecutionHarness(
  t: Parameters<typeof startHttpFixture>[0],
  opts: { environment?: 'public' | 'local-lab'; approvalPolicy?: 'auto_review' | 'strict' | 'yolo' } = {},
) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-t2-broker-approvals-'))
  const storage = new Store(dir)
  const fixture = await startHttpFixture(t, (_req, _body, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end('{"ok":true}')
  })
  const environment = opts.environment ?? 'public'
  const previousAllowLab = process.env.KOVO_ALLOW_LOCAL_LAB
  if (environment === 'local-lab') process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  else delete process.env.KOVO_ALLOW_LOCAL_LAB

  // Use a virtual public origin so public-target auto_review rules apply while the custom
  // transport forwards directly to the local HTTP fixture.
  const targetOrigin = environment === 'public' ? APP_ORIGIN : fixture.origin
  const transportToFixture: Transport = (url, address, signal, options) => {
    const rewritten = new URL(`${url.pathname}${url.search}`, fixture.origin)
    return fixtureTransport()(rewritten, address, signal, options)
  }
  const publicBroker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: transportToFixture,
  })
  const execWithBroker = new Execution(storage, { broker: publicBroker })
  t.after(async () => {
    await execWithBroker.stop()
    storage.close()
    rmSync(dir, { recursive: true, force: true })
    if (previousAllowLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = previousAllowLab
  })

  const { runId } = await setupApprovedRun(storage, {
    seeds: [targetOrigin],
    tier: 3,
    environment,
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  if (opts.approvalPolicy) {
    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'set_approval_policy',
      approvalPolicy: opts.approvalPolicy,
    }))
  }
  const run = storage.run(runId)
  const created = storage.makeWorker(
    run,
    'investigation',
    undefined,
    'T2 approvals verification',
    'Verify per-target Tier-3 approval evaluation',
    { sourceOrigins: [targetOrigin] },
  )
  storage.updateWorker(created.id, { status: 'running' })
  const assignment = storage.worker(created.id) as Assignment
  const job = { assignment, origins: new Set([targetOrigin]), controller: new AbortController() }
  const priv = execWithBroker as unknown as Record<string, any>
  // Keep this unit harness deterministic: don't spin up background recon/floor probes on resume.
  priv.scheduleWake = () => undefined
  const { grant } = priv.buildGrant(job, storage.run(runId), new Set([targetOrigin])) as { grant: Grant }
  const signal = () => AbortSignal.timeout(15_000)

  return {
    storage,
    execution: execWithBroker,
    priv,
    fixture,
    targetOrigin,
    runId,
    job,
    grant,
    broker: publicBroker,
    signal,
  }
}

// ---------------------------------------------------------------------------
// H-3: Non-GraphQL POST with GraphQL-shaped JSON is NOT read-only
// ---------------------------------------------------------------------------

test('H-3: non-GraphQL POST with { query: "query { ok }" } is NOT read-only in prod_readonly or staging', async () => {
  const prodScope = makeScopePolicy({ mode: 'prod_readonly' })
  const stagingScope = makeScopePolicy({ mode: 'staging_isolated' })
  const gqlShapedBody = JSON.stringify({ query: 'query { ok }' })

  const nonGraphqlPaths = [
    '/api/users/delete',
    '/api/items',
    '/api/search',
    '/api/users/delete?next=/graphql',
    '/graphql/delete',
    '/graphql/../admin/delete',
    '/graphql/%2e%2e/admin/delete',
  ]

  for (const pathAndQuery of nonGraphqlPaths) {
    assert.equal(
      isVerifiedReadOnlyGraphqlQuery(pathAndQuery, gqlShapedBody, { 'Content-Type': 'application/json' }),
      false,
      `${pathAndQuery} must NOT be classified as a read-only GraphQL route`,
    )
    assert.equal(
      isVerifiedReadOnlyGraphqlQuery(pathAndQuery, 'query { ok }', { 'Content-Type': 'application/graphql' }),
      false,
      `${pathAndQuery} with spoofed application/graphql header must NOT bypass route check`,
    )

    const prodDecision = evaluateScopeRequest(prodScope, {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery,
      headers: { 'Content-Type': 'application/json' },
      body: gqlShapedBody,
    })
    assert.equal(prodDecision.allowed, false, `prod_readonly must refuse POST ${pathAndQuery}`)
    assert.equal(prodDecision.code, 'readonly_environment')

    const stagingDecision = evaluateScopeRequest(stagingScope, {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery,
      headers: { 'Content-Type': 'application/json' },
      body: gqlShapedBody,
    })
    assert.equal(stagingDecision.allowed, false, `staging_isolated must refuse untagged POST ${pathAndQuery}`)
    assert.equal(stagingDecision.code, 'staging_untagged_mutation')
  }

  // End-to-end through RequestBroker under prod_readonly: blocked before hitting wire
  const calls: Array<{ method: string; url: string }> = []
  const broker = makeRecordingBroker(calls)
  const grant = makeScopeGrant(prodScope)

  await assert.rejects(
    broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/users/delete',
      headers: { 'Content-Type': 'application/json' },
      body: gqlShapedBody,
    }, grant, AbortSignal.timeout(5_000)),
    (err: unknown) => err instanceof BrokerDenied && /prod_readonly/.test(err.message),
  )
  assert.equal(calls.length, 0, 'blocked non-GraphQL POST must never hit the wire')

  // Contrast: genuine GraphQL endpoints with a strict read-only query ARE permitted
  for (const validPath of ['/graphql', '/api/graphql', '/v1/graphql?op=Viewer']) {
    const res = await broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: validPath,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'query Viewer { viewer { id } }', operationName: 'Viewer', variables: {} }),
    }, grant, AbortSignal.timeout(5_000))
    assert.equal(res.status, 200)
  }
  assert.equal(calls.length, 3)
})

// ---------------------------------------------------------------------------
// H-3: Escaped/duplicate JSON key smuggling, multi-op, & alias tricks fail closed
// ---------------------------------------------------------------------------

test('H-3: escaped/duplicate GraphQL JSON keys, multi-operation smuggling, and alias tricks fail closed', async () => {
  const prodScope = makeScopePolicy({ mode: 'prod_readonly' })
  const calls: Array<{ method: string; url: string }> = []
  const broker = makeRecordingBroker(calls)
  const grant = makeScopeGrant(prodScope)

  const bypassBodies: Array<{ label: string; body: string; headers?: Record<string, string> }> = [
    {
      label: 'unicode-escaped second query key with mutation',
      body: '{"query":"query { x }","\\u0071uery":"mutation { del }"}',
    },
    {
      label: 'unicode-escaped first query key with mutation (first-key-wins parity attack)',
      body: '{"\\u0071uery":"mutation { del }","query":"query { x }"}',
    },
    {
      label: 'sole unicode-escaped query key',
      body: '{"\\u0071uery":"query { ok }"}',
    },
    {
      label: 'duplicate exact query key (mutation first, query last)',
      body: '{"query":"mutation { del }","query":"query { x }"}',
    },
    {
      label: 'duplicate exact query key (query first, mutation last)',
      body: '{"query":"query { x }","query":"mutation { del }"}',
    },
    {
      label: 'case-variant duplicate query key',
      body: '{"query":"query { x }","Query":"mutation { del }"}',
    },
    {
      label: 'nested duplicate key in variables',
      body: '{"query":"query($id: ID!) { user(id: $id) { id } }","variables":{"id":"1","id":"2"}}',
    },
    {
      label: 'multi-operation smuggling (query + mutation)',
      body: JSON.stringify({ query: 'query Safe { viewer { id } } mutation Evil { deleteAll { ok } }', operationName: 'Safe' }),
    },
    {
      label: 'multi-operation smuggling (two queries)',
      body: JSON.stringify({ query: 'query A { viewer { id } } query B { secrets { value } }', operationName: 'A' }),
    },
    {
      label: 'subscription operation',
      body: JSON.stringify({ query: 'subscription { auditEvents { id } }' }),
    },
    {
      label: 'field alias trick',
      body: JSON.stringify({ query: 'query { a: viewer { id } }' }),
    },
    {
      label: 'alias batching amplification',
      body: JSON.stringify({ query: '{ a1: viewer { id } a2: viewer { id } }' }),
    },
    {
      label: 'operation-keyword alias confusion',
      body: JSON.stringify({ query: 'query: mutation { deleteAll }' }),
    },
    {
      label: 'operation named mutation',
      body: JSON.stringify({ query: 'query mutation { viewer { id } }' }),
    },
    {
      label: 'non-GraphQL arbitrary string inside query key',
      body: JSON.stringify({ query: 'delete all users' }),
    },
    {
      label: 'mismatched operationName',
      body: JSON.stringify({ query: 'query Viewer { viewer { id } }', operationName: 'AdminDelete' }),
    },
    {
      label: 'persistedQuery APQ extension smuggling',
      body: JSON.stringify({
        query: 'query { ok }',
        extensions: { persistedQuery: { version: 1, sha256Hash: 'deadbeef' } },
      }),
    },
    {
      label: 'compressed Content-Encoding on GraphQL route',
      body: JSON.stringify({ query: 'query { ok }' }),
      headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
    },
    {
      label: 'raw GraphQL multi-op smuggling via application/graphql',
      body: 'query Safe { viewer { id } }\nmutation Evil { nuke }',
      headers: { 'Content-Type': 'application/graphql' },
    },
  ]

  for (const tc of bypassBodies) {
    const headers = tc.headers ?? { 'Content-Type': 'application/json' }
    assert.equal(
      isVerifiedReadOnlyGraphqlQuery('/graphql', tc.body, headers),
      false,
      `${tc.label} must fail closed (NOT read-only)`,
    )
    const decision = evaluateScopeRequest(prodScope, {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/graphql',
      headers,
      body: tc.body,
    })
    assert.equal(decision.allowed, false, `prod_readonly must refuse: ${tc.label}`)
    assert.equal(decision.code, 'readonly_environment')

    await assert.rejects(
      broker.executeHttp({
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/graphql',
        headers,
        body: tc.body,
      }, grant, AbortSignal.timeout(5_000)),
      (err: unknown) => err instanceof BrokerDenied && /prod_readonly/.test(err.message),
      `broker must deny in prod_readonly: ${tc.label}`,
    )
  }
  assert.equal(calls.length, 0, 'none of the smuggled GraphQL requests may reach the wire')

  // Control: valid fragment-using read-only query still works cleanly
  const fragmentQuery = JSON.stringify({
    query: 'query Viewer { viewer { ...UserFields } } fragment UserFields on User { id email }',
    operationName: 'Viewer',
  })
  assert.equal(isVerifiedReadOnlyGraphqlQuery('/graphql', fragmentQuery, { 'Content-Type': 'application/json' }), true)
  const ok = await broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    headers: { 'Content-Type': 'application/json' },
    body: fragmentQuery,
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(ok.status, 200)
  assert.equal(calls.length, 1)
})

// ---------------------------------------------------------------------------
// H-4: Batch approval evaluates EVERY distinct target individually; never
// lets a benign primary request smuggle a destructive sibling DELETE.
// ---------------------------------------------------------------------------

test('H-4: batch [benign POST /search, destructive DELETE /api/users/1] evaluates BOTH targets and never lets /search authorize DELETE', async t => {
  const h = await makeExecutionHarness(t, { environment: 'public', approvalPolicy: 'auto_review' })
  const run = h.storage.run(h.runId)
  const scopeRevision = run.scopeRevision

  const batchRequests = [
    {
      origin: h.targetOrigin,
      method: 'POST' as const,
      pathAndQuery: '/search',
      headers: { 'Content-Type': 'application/json' },
      body: '{"q":"widgets"}',
      runId: h.runId,
      assignmentId: h.job.assignment.id,
      scopeRevision,
    },
    {
      origin: h.targetOrigin,
      method: 'DELETE' as const,
      pathAndQuery: '/api/users/1',
      runId: h.runId,
      assignmentId: h.job.assignment.id,
      scopeRevision,
    },
  ]

  // 1. planTier3ApprovalTargets exposes BOTH distinct targets with full metadata
  const plan = planTier3ApprovalTargets(run, batchRequests)
  assert.equal(plan.targets.length, 2, 'batch with two distinct targets must produce two approval targets')
  assert.equal(plan.targets[0]!.method, 'POST')
  assert.equal(plan.targets[0]!.pathAndQuery, '/search')
  assert.equal(plan.targets[0]!.bodyPreview, '{"q":"widgets"}')
  assert.equal(plan.targets[1]!.method, 'DELETE')
  assert.equal(plan.targets[1]!.pathAndQuery, '/api/users/1')

  // 2. Execute batch under auto_review:
  //    - POST /search takes benign_fast_path (auto-approved),
  //    - DELETE /api/users/1 MUST still be individually evaluated and escalate to human!
  const pendingDenied = h.priv.executeApprovedBatch(h.job, batchRequests, h.grant, h.signal(), {
    stepTitle: 'H-4 mixed batch deny check',
    secrets: [],
  })

  const deleteCard = await waitForPendingCard(h.storage, h.runId)
  assert.equal(deleteCard.method, 'DELETE', 'HITL card must explicitly identify the DELETE target')
  assert.equal(deleteCard.pathAndQuery, '/api/users/1', 'HITL card must explicitly identify /api/users/1')

  // While DELETE is pending, approval of /search has NOT authorized DELETE /api/users/1 and ZERO requests hit the wire!
  assert.equal(
    h.grant.isStateChangeApproved!(h.targetOrigin, 'DELETE', '/api/users/1', {
      personaHandle: null, body: null, hasMultipart: false, isRaceBurst: false,
    }),
    false,
    'approval of benign /search must NEVER authorize DELETE /api/users/1',
  )
  assert.equal(h.fixture.requests.length, 0, 'no batch item may hit the wire while a sibling is unapproved')

  // Verify audit trail recorded BOTH evaluations: POST /search (approved) + DELETE /api/users/1 (pending)
  const recordsBeforeDeny = h.storage.listApprovalRequests(h.runId)
  assert.ok(
    recordsBeforeDeny.some(r => r.method === 'POST' && r.pathAndQuery === '/search' && r.status === 'approved'),
    'benign POST /search was evaluated individually',
  )
  assert.ok(
    recordsBeforeDeny.some(r => r.method === 'DELETE' && r.pathAndQuery === '/api/users/1' && r.status === 'pending'),
    'destructive DELETE /api/users/1 was evaluated individually and escalated',
  )

  // Denying DELETE rejects the whole batch with BrokerDenied and sends ZERO wire bytes
  h.storage.decideApproval(h.storage.run(h.runId), deleteCard.id, 'denied')
  await assert.rejects(pendingDenied, BrokerDenied)
  assert.equal(h.fixture.requests.length, 0, 'denied batch must send zero requests on the wire')
  // Deferred grant must NOT leave a dangling single-use grant for POST /search
  assert.equal(
    h.grant.isStateChangeApproved!(h.targetOrigin, 'POST', '/search', {
      personaHandle: null, body: '{"q":"widgets"}', hasMultipart: false, isRaceBurst: false,
    }),
    false,
    'aborted batch must not leave a dangling grant for the benign sibling',
  )
})

test('H-4: direct waitForTier3Approval refuses unjudged additionalApprovalTargets', async t => {
  const h = await makeExecutionHarness(t, { environment: 'public', approvalPolicy: 'auto_review' })
  const decision = await h.priv.waitForTier3Approval(h.job, {
    origin: h.targetOrigin,
    method: 'POST',
    pathAndQuery: '/search',
    rationale: 'Attempt to smuggle DELETE via additionalApprovalTargets',
    requestPreview: 'POST /search',
    bodyPreview: '{"q":"ok"}',
    additionalApprovalTargets: [{
      origin: h.targetOrigin,
      method: 'DELETE',
      pathAndQuery: '/api/users/1',
      instances: 1,
    }],
    secrets: [],
  }, h.signal())
  assert.equal(decision.approved, false, 'non-empty additionalApprovalTargets must fail closed')
  assert.equal(
    h.grant.isStateChangeApproved!(h.targetOrigin, 'DELETE', '/api/users/1', {
      personaHandle: null, body: null, hasMultipart: false,
    }),
    false,
    'smuggled DELETE target must never receive a grant',
  )
})

test('H-4: approving DELETE in a mixed batch authorizes both items once; identical 4-way race burst still needs only 1 approval', async t => {
  // Part A: Mixed batch succeeds once the operator explicitly approves the escalated DELETE card
  const mixed = await makeExecutionHarness(t, { environment: 'public', approvalPolicy: 'auto_review' })
  const mixedScopeRev = mixed.storage.run(mixed.runId).scopeRevision
  const mixedRequests = [
    {
      origin: mixed.targetOrigin,
      method: 'POST' as const,
      pathAndQuery: '/search',
      headers: { 'Content-Type': 'application/json' },
      body: '{"q":"widgets"}',
      runId: mixed.runId,
      assignmentId: mixed.job.assignment.id,
      scopeRevision: mixedScopeRev,
    },
    {
      origin: mixed.targetOrigin,
      method: 'DELETE' as const,
      pathAndQuery: '/api/users/1',
      runId: mixed.runId,
      assignmentId: mixed.job.assignment.id,
      scopeRevision: mixedScopeRev,
    },
  ]

  const pendingMixed = mixed.priv.executeApprovedBatch(mixed.job, mixedRequests, mixed.grant, mixed.signal(), {
    stepTitle: 'H-4 mixed batch approve check',
    secrets: [],
  })
  const mixedDeleteCard = await waitForPendingCard(mixed.storage, mixed.runId)
  assert.equal(mixedDeleteCard.method, 'DELETE')
  assert.equal(mixedDeleteCard.pathAndQuery, '/api/users/1')
  mixed.storage.decideApproval(mixed.storage.run(mixed.runId), mixedDeleteCard.id, 'approved')
  const mixedResults = await pendingMixed
  assert.equal(mixedResults.length, 2)
  assert.deepEqual(
    mixed.fixture.requests.map(r => `${r.method} ${r.url}`).sort(),
    ['DELETE /api/users/1', 'POST /search'],
  )

  // Part B: Identical 4-way race burst on one route still needs ONLY 1 approval!
  const burst = await makeExecutionHarness(t, { environment: 'public', approvalPolicy: 'strict' })
  const burstRun = burst.storage.run(burst.runId)
  const raceBody = '{"coupon":"SPRING4X"}'
  const raceRequests = Array.from({ length: 4 }, () => ({
    origin: burst.targetOrigin,
    method: 'POST' as const,
    pathAndQuery: '/api/redeem',
    headers: { 'Content-Type': 'application/json' },
    body: raceBody,
    runId: burst.runId,
    assignmentId: burst.job.assignment.id,
    scopeRevision: burstRun.scopeRevision,
  }))

  const racePlan = planTier3ApprovalTargets(burstRun, raceRequests, { isRaceBurst: true })
  assert.equal(racePlan.targets.length, 1, '4 identical race clones must collapse to 1 approval target')
  assert.equal(racePlan.targets[0]!.instances, 4)

  const pendingBurst = burst.priv.executeApprovedRaceBurst(burst.job, raceRequests, burst.grant, burst.signal(), {
    stepTitle: 'H-4 4-way identical race burst',
    secrets: [],
  })
  const burstCard = await waitForPendingCard(burst.storage, burst.runId)
  await delay(100)
  assert.equal(
    burst.storage.listApprovalRequests(burst.runId, 'pending').length,
    1,
    'identical 4-way race burst must raise only 1 approval card',
  )
  burst.storage.decideApproval(burst.storage.run(burst.runId), burstCard.id, 'approved')

  const burstResult = await pendingBurst
  assert.equal(burstResult.summary.total, 4)
  assert.equal(burst.fixture.requests.length, 4, 'all 4 race clones must execute after the single approval')
  assert.equal(burst.storage.listApprovalRequests(burst.runId).length, 1, 'exactly 1 approval decision for the 4-way burst')

  // All 4 burst instances were consumed by the 4-way burst; the exact burst ledger has 0 left.
  assert.equal(
    burst.grant.isStateChangeApproved!(burst.targetOrigin, 'POST', '/api/redeem', {
      personaHandle: null,
      body: raceBody,
      hasMultipart: false,
      isRaceBurst: true,
    }),
    false,
    '5th clone after 4-way burst exhaustion must have no remaining burst instance in the ledger',
  )

  // Part C: Heterogeneous race burst [POST /search, DELETE /api/users/1] MUST evaluate BOTH targets
  const heteroRace = await makeExecutionHarness(t, { environment: 'public', approvalPolicy: 'auto_review' })
  const heteroRev = heteroRace.storage.run(heteroRace.runId).scopeRevision
  const heteroRaceReqs = [
    {
      origin: heteroRace.targetOrigin,
      method: 'POST' as const,
      pathAndQuery: '/search',
      headers: { 'Content-Type': 'application/json' },
      body: '{"q":"race"}',
      runId: heteroRace.runId,
      assignmentId: heteroRace.job.assignment.id,
      scopeRevision: heteroRev,
    },
    {
      origin: heteroRace.targetOrigin,
      method: 'DELETE' as const,
      pathAndQuery: '/api/users/1',
      runId: heteroRace.runId,
      assignmentId: heteroRace.job.assignment.id,
      scopeRevision: heteroRev,
    },
  ]
  const pendingHetero = heteroRace.priv.executeApprovedRaceBurst(heteroRace.job, heteroRaceReqs, heteroRace.grant, heteroRace.signal(), {
    stepTitle: 'H-4 heterogeneous race burst',
    secrets: [],
  })
  const heteroCard1 = await waitForPendingCard(heteroRace.storage, heteroRace.runId)
  // Under auto_review, race bursts do NOT take the benign fast path, so POST /search escalates first;
  // approving POST /search must NOT authorize DELETE /api/users/1 — DELETE must raise its own card!
  assert.equal(heteroCard1.method, 'POST')
  assert.equal(heteroCard1.pathAndQuery, '/search')
  heteroRace.storage.decideApproval(heteroRace.storage.run(heteroRace.runId), heteroCard1.id, 'approved')

  const heteroCard2 = await waitForPendingCard(heteroRace.storage, heteroRace.runId)
  assert.equal(heteroCard2.method, 'DELETE', 'approving /search in a race burst must still escalate sibling DELETE')
  assert.equal(heteroCard2.pathAndQuery, '/api/users/1')
  heteroRace.storage.decideApproval(heteroRace.storage.run(heteroRace.runId), heteroCard2.id, 'denied')
  await assert.rejects(pendingHetero, BrokerDenied)
  assert.equal(heteroRace.fixture.requests.length, 0, 'denied heterogeneous race burst must send zero bytes')
})
