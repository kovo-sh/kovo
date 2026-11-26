/**
 * Regression suite for R3-H-9 (SECURITY-REAUDIT 1.3 invariant):
 * Worker-submitted glob segments (`*`, `**`) on approval cards must never become wildcards or
 * prefix globs via `normalizeApprovalPathPattern` or `approveSimilarEndpoint`.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { newRun, runCommand } from '../src/domain.ts'
import { authorizeStateChange } from '../src/server/approval-judge.ts'
import {
  hasApprovalPathGlobMetacharacters,
  inspectApprovalPathGlobs,
  matchesApprovedEndpointPattern,
  normalizeApprovalPathPattern,
} from '../src/server/approval-pattern.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN = 'https://app.example.test'

function makeStore(t: test.TestContext): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-approval-glob-'))
  const store = new Store(join(dir, 'kovo.db'))
  t.after(() => {
    store.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return store
}

function setupApprovedRun(store: Store) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Glob Approval Test',
    environment: 'public',
    seeds: [ORIGIN],
  })
  const created = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify R3-H-9 glob isolation',
    sourceMode: 'public',
    capabilityTier: 3,
    approvalPolicy: 'strict',
  }))
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId: created.id,
    action: 'discover',
    consent: true,
  }))
  const discovered = store.run(created.id)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId: discovered.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    capabilityTier: 3,
    approvalPolicy: 'strict',
  }))
  store.updateRun(discovered.id, { phase: 'investigation', status: 'running' })
  const approvedRun = store.run(discovered.id)
  const worker = store.makeWorker(approvedRun, 'investigation', approvedRun.candidates[0], 'Glob test worker', 'Check approval glob handling')
  return { runId: discovered.id, run: approvedRun, worker }
}

test('R3-H-9: card_path normalization (default) escapes literal * and ** segments so they never produce wildcards or prefix globs', () => {
  assert.equal(normalizeApprovalPathPattern('/api/**'), '/api/%2a%2a')
  assert.equal(normalizeApprovalPathPattern('/api/**', { source: 'card_path' }), '/api/%2a%2a')
  assert.equal(normalizeApprovalPathPattern('/**'), '/%2a%2a')
  assert.equal(normalizeApprovalPathPattern('/**?probe=1'), '/%2a%2a')
  assert.equal(normalizeApprovalPathPattern('/api/*/users'), '/api/%2a/users')
  assert.equal(normalizeApprovalPathPattern('/api/items/*'), '/api/items/%2a')
  assert.equal(normalizeApprovalPathPattern('/api/**/'), '/api/%2a%2a')
  assert.equal(normalizeApprovalPathPattern(`${ORIGIN}/api/**?x=1`), '/api/%2a%2a')

  // Worker-supplied template placeholders also stay literal in card_path mode.
  assert.equal(normalizeApprovalPathPattern('/api/orders/:id'), '/api/orders/:id')
  assert.equal(normalizeApprovalPathPattern('/api/orders/{id}'), '/api/orders/{id}')

  // Each card-derived glob pattern matches ONLY its exact literal path and never unrelated endpoints.
  const cases = [
    {
      cardPath: '/api/**',
      exact: '/api/**',
      rejected: ['/api/admin/users/delete', '/api/users', '/api/123', '/api', '/'],
    },
    {
      cardPath: '/**',
      exact: '/**',
      rejected: ['/api/admin/users/delete', '/admin', '/items/123', '/'],
    },
    {
      cardPath: '/api/*/users',
      exact: '/api/*/users',
      rejected: ['/api/123/users', '/api/admin/users', '/api/admin/users/delete', '/api/users'],
    },
    {
      cardPath: '/api/items/*',
      exact: '/api/items/*',
      rejected: ['/api/items/123', '/api/items/delete', '/api/items/123/settings'],
    },
  ]

  for (const tc of cases) {
    const pathPattern = normalizeApprovalPathPattern(tc.cardPath, { source: 'card_path' })
    const patterns = [{ origin: ORIGIN, method: 'POST', pathPattern }]
    assert.ok(
      matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: tc.exact }, patterns),
      `card-derived pattern for ${tc.cardPath} must still match exact literal ${tc.exact}`,
    )
    for (const candidate of tc.rejected) {
      assert.equal(
        matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: candidate }, patterns),
        undefined,
        `card-derived pattern for ${tc.cardPath} (${pathPattern}) must NOT match ${candidate}`,
      )
    }
  }
})

test('R3-H-9: explicit operator_explicit opt-in honors ** prefix globs (requiring >= 2 fixed segments and non-high-risk targets) and rejects bare /**', () => {
  const operatorPrefix = normalizeApprovalPathPattern('/api/v1/**', { source: 'operator_explicit' })
  assert.equal(operatorPrefix, '/api/v1/**')
  const patterns = [{ origin: ORIGIN, method: 'POST', pathPattern: operatorPrefix, source: 'operator_explicit' as const }]

  assert.ok(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/items/123' }, patterns))
  assert.equal(
    matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/admin/users/delete' }, patterns),
    undefined,
    'R4-H-1: prefix patterns must refuse high-risk targets at match time',
  )
  assert.equal(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/other/v1/items/123' }, patterns), undefined)

  // Missing `source` defaults to `card_path` (never `operator_explicit`), and single-segment `/api/**` is rejected.
  assert.equal(
    matchesApprovedEndpointPattern(
      { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/items/123' },
      [{ origin: ORIGIN, method: 'POST', pathPattern: '/api/v1/**' }],
    ),
    undefined,
  )
  assert.equal(
    matchesApprovedEndpointPattern(
      { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/items/123' },
      [{ origin: ORIGIN, method: 'POST', pathPattern: '/api/**', source: 'operator_explicit' }],
    ),
    undefined,
  )

  // Explicit operator single-segment wildcard and placeholders work only on ID-shaped targets.
  const operatorPlaceholder = normalizeApprovalPathPattern('/api/orders/:id', { source: 'operator_explicit' })
  assert.equal(operatorPlaceholder, '/api/orders/*')
  const orderPatterns = [{ origin: ORIGIN, method: 'POST', pathPattern: operatorPlaceholder }]
  assert.ok(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/456' }, orderPatterns))
  assert.equal(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/delete' }, orderPatterns), undefined)

  // Defense-in-depth: a bare root `/**` (fixedLength 0) never matches arbitrary paths even if passed directly,
  // and a pattern explicitly tagged `source: 'card_path'` never acts as a prefix glob even un-normalized.
  assert.equal(
    matchesApprovedEndpointPattern(
      { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/admin/users/delete' },
      [{ origin: ORIGIN, method: 'POST', pathPattern: '/**' }],
    ),
    undefined,
  )
  assert.equal(
    matchesApprovedEndpointPattern(
      { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/admin/users/delete' },
      [{ origin: ORIGIN, method: 'POST', pathPattern: '/api/**', source: 'card_path' }],
    ),
    undefined,
  )
})

test('R3-H-9: ordinary numeric/UUID ID path normalization continues to work cleanly in card_path mode', () => {
  const numericPattern = normalizeApprovalPathPattern('/api/orders/123', { source: 'card_path' })
  assert.equal(numericPattern, '/api/orders/*')

  const uuidPattern = normalizeApprovalPathPattern('/api/orders/550e8400-e29b-41d4-a716-446655440000/items?page=2')
  assert.equal(uuidPattern, '/api/orders/*/items')

  const patterns = [{ origin: ORIGIN, method: 'POST', pathPattern: numericPattern }]
  assert.ok(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/456' }, patterns))
  assert.ok(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/550e8400-e29b-41d4-a716-446655440000' }, patterns))
  assert.equal(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/delete' }, patterns), undefined)
  assert.equal(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/*' }, patterns), undefined)
  assert.equal(matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/123/cancel' }, patterns), undefined)
})

test('R3-H-9: inspectApprovalPathGlobs and hasApprovalPathGlobMetacharacters flag worker-submitted glob paths', () => {
  const prefixGlob = inspectApprovalPathGlobs('/api/**?debug=1')
  assert.equal(prefixGlob.hasGlobMetacharacters, true)
  assert.equal(prefixGlob.hasWildcardSegment, true)
  assert.equal(prefixGlob.hasPrefixGlobSegment, true)
  assert.deepEqual(prefixGlob.globSegments, ['**'])

  const singleGlob = inspectApprovalPathGlobs('/api/*/users')
  assert.equal(singleGlob.hasGlobMetacharacters, true)
  assert.equal(singleGlob.hasWildcardSegment, true)
  assert.equal(singleGlob.hasPrefixGlobSegment, false)
  assert.deepEqual(singleGlob.globSegments, ['*'])

  const partialGlob = inspectApprovalPathGlobs('/api/item*all')
  assert.equal(partialGlob.hasGlobMetacharacters, true)
  assert.equal(partialGlob.hasWildcardSegment, false)
  assert.equal(partialGlob.hasPrefixGlobSegment, false)
  assert.deepEqual(partialGlob.globSegments, ['item*all'])

  assert.equal(hasApprovalPathGlobMetacharacters('/**'), true)
  assert.equal(hasApprovalPathGlobMetacharacters(`${ORIGIN}/api/**?x=1`), true)
  assert.equal(hasApprovalPathGlobMetacharacters('/safe/../**'), true)
  assert.equal(hasApprovalPathGlobMetacharacters('/api/orders/123'), false)
  assert.equal(hasApprovalPathGlobMetacharacters('/api/search?q=**'), false)
})

test('R3-H-9: approveSimilarEndpoint on /api/**, /**, and /api/*/users flags cards, never bulk-approves unrelated cards, and restricts leases/authorization to exact literal paths', t => {
  for (const globPath of ['/api/**', '/**', '/api/*/users']) {
    const store = makeStore(t)
    const { runId, run, worker } = setupApprovedRun(store)

    const globCard = store.createApprovalRequest(run, worker, {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: globPath,
      rationale: 'Worker submitted glob path',
      requestPreview: `POST ${globPath}`,
      riskLevel: 'low',
    })

    // Card must be flagged upon creation: riskLevel escalated to high + warning in policyNote + event metadata.
    assert.equal(globCard.riskLevel, 'high', `${globPath} card must escalate riskLevel to high`)
    assert.match(globCard.policyNote ?? '', /glob metacharacters/i, `${globPath} card must include glob warning`)
    const requestedEvents = store.eventsAfter(runId, 0).filter(e => e.kind === 'approval.requested')
    const globEvent = requestedEvents.find(e => e.detail?.approvalId === globCard.id)
    assert.equal(globEvent?.detail?.containsGlobMetacharacters, true)

    // Queue unrelated pending cards and one exact-literal duplicate.
    const adminDeleteCard = store.createApprovalRequest(store.run(runId), worker, {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/admin/users/delete',
      rationale: 'Unrelated deep admin POST',
      requestPreview: 'POST /api/admin/users/delete',
      riskLevel: 'high',
    })
    const siblingUserCard = store.createApprovalRequest(store.run(runId), worker, {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/123/users',
      rationale: 'Unrelated ID path POST',
      requestPreview: 'POST /api/123/users',
      riskLevel: 'medium',
    })
    const exactDuplicateCard = store.createApprovalRequest(store.run(runId), worker, {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: `${globPath}?retry=1`,
      rationale: 'Exact same literal glob path',
      requestPreview: `POST ${globPath}`,
      riskLevel: 'medium',
    })

    // Operator clicks "Approve similar" on the glob card.
    store.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'approve_similar_endpoint',
      approvalId: globCard.id,
    }))

    const updatedRun = store.run(runId)
    assert.equal(updatedRun.approvedEndpointPatterns.length, 1)
    const storedPattern = updatedRun.approvedEndpointPatterns[0]!
    assert.equal(storedPattern.pathPattern.includes('*'), false, `stored pattern for ${globPath} must not contain unescaped *`)

    // Unrelated queued cards MUST remain pending; only the exact literal duplicate is auto-approved.
    assert.equal(store.getApprovalRequest(runId, adminDeleteCard.id).status, 'pending')
    assert.equal(store.getApprovalRequest(runId, siblingUserCard.id).status, 'pending')
    assert.equal(store.getApprovalRequest(runId, exactDuplicateCard.id).status, 'approved')

    // authorizeStateChange with stored approvedEndpointPatterns must reject unrelated deep POSTs
    // and match only the exact literal path.
    const authUnrelated = authorizeStateChange({
      runId,
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/admin/users/delete',
      scopeRevision: updatedRun.scopeRevision,
      context: { personaHandle: 'user_a', hasMultipart: false, isRceProof: false },
      approvedPatterns: updatedRun.approvedEndpointPatterns,
      leaseAuthorizes: store.approvalLeaseAuthorizer(runId),
    })
    assert.equal(authUnrelated.approved, false, `stored pattern for ${globPath} must not authorize /api/admin/users/delete`)

    const authExact = authorizeStateChange({
      runId,
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: globPath,
      scopeRevision: updatedRun.scopeRevision,
      context: { personaHandle: null, hasMultipart: false, isRceProof: false },
      approvedPatterns: updatedRun.approvedEndpointPatterns,
      leaseAuthorizes: store.approvalLeaseAuthorizer(runId),
    })
    assert.equal(authExact.approved, true)
    assert.equal(authExact.via, 'operator_pattern')

    // Durable route lease must likewise reject unrelated paths and authorize only the exact literal glob path.
    assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/admin/users/delete'), false)
    assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/123/users'), false)
    assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', globPath), true)
  }
})

test('R3-H-9: approveSimilarEndpoint preserves ID similarity for ordinary paths and decideApproval isolates literal * cards', t => {
  const store = makeStore(t)
  const { runId, run, worker } = setupApprovedRun(store)

  const order123 = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders/123',
    rationale: 'Order probe',
    requestPreview: 'POST /api/orders/123',
    riskLevel: 'medium',
  })
  assert.equal(order123.riskLevel, 'medium')
  assert.equal(order123.policyNote, null)

  const order456 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders/456',
    rationale: 'Sibling ID order probe',
    requestPreview: 'POST /api/orders/456',
    riskLevel: 'medium',
  })
  const orderDelete = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders/delete',
    rationale: 'Sibling verb probe',
    requestPreview: 'POST /api/orders/delete',
    riskLevel: 'high',
  })
  const orderLiteralStar = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders/*',
    rationale: 'Literal asterisk probe',
    requestPreview: 'POST /api/orders/*',
    riskLevel: 'low',
  })

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'approve_similar_endpoint',
    approvalId: order123.id,
  }))

  assert.equal(store.run(runId).approvedEndpointPatterns[0]?.pathPattern, '/api/orders/*')
  assert.equal(store.getApprovalRequest(runId, order456.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, orderDelete.id).status, 'pending')
  assert.equal(store.getApprovalRequest(runId, orderLiteralStar.id).status, 'pending')

  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/789'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/delete'), false)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/*'), false)

  // Single-card approval on a literal `*` path must NOT grant an ID-wildcard lease.
  const itemStar = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PUT',
    pathAndQuery: '/api/items/*',
    rationale: 'Literal star PUT',
    requestPreview: 'PUT /api/items/*',
  })
  store.decideApproval(store.run(runId), itemStar.id, 'approved')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PUT', '/api/items/123'), false)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PUT', '/api/items/*'), true)
})
