/**
 * Fast class-level security guard for R4-H-1 (Single Authoritative Lease-Eligibility Predicate):
 *
 * Eliminates the admission/approval dual path by proving ONE canonical `evaluateLeaseEligibility`
 * predicate is enforced at match time across:
 *   - All 3 `leaseAuthorizes` steps (`route`, `prefix`, `host_nondestructive`),
 *   - `RequestAdmissionEngine` (`checkLease` -> routes high-risk/GraphQL/JSON-RPC/body-destructive
 *     to `isStateChangeApproved` / Safety Judge),
 *   - Judge Stage 1B (`evaluateTier3Approval` & `authorizeStateChange`),
 *   - Two-segment prefix derivation & validation (`deriveOperatorPrefixPattern` / `deriveApprovalPrefixPattern`),
 *   - Explicit `source` persistence on stored patterns & fail-closed `'card_path'` default on missing `source`,
 *   - Strict non-override of `readonly_environment` (`prod_readonly`) by any approval lease.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  deriveApprovalPrefixPattern,
  eligibleApprovalPrefixPattern,
  evaluateClientApprovalLeaseEligibility,
  HOST_NONDESTRUCTIVE_LEASE_METHOD,
  HOST_NONDESTRUCTIVE_LEASE_PATTERN,
  isPrefixApprovalPattern,
  newRun,
  runCommand,
} from '../src/domain.ts'
import { authorizeStateChange, evaluateTier3Approval } from '../src/server/approval-judge.ts'
import {
  deriveOperatorPrefixPattern,
  evaluateLeaseEligibility,
  matchesApprovedEndpointPattern,
} from '../src/server/approval-pattern.ts'
import { RequestAdmissionEngine } from '../src/server/request-admission.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN = 'https://app.r4-h1.example'

function makeStore(t: test.TestContext): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r4-approval-leases-'))
  const store = new Store(join(dir, 'kovo.db'))
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return store
}

function setupTier3Run(store: Store) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: `R4-H-1 Leases ${randomUUID().slice(0, 6)}`,
    environment: 'public',
    seeds: [ORIGIN],
  })
  const created = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify R4-H-1 single lease-eligibility predicate',
    sourceMode: 'public',
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
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
    approvalPolicy: 'auto_review',
  }))
  store.updateRun(discovered.id, { phase: 'investigation', status: 'running' })
  const approvedRun = store.run(discovered.id)
  const worker = store.makeWorker(
    approvedRun,
    'investigation',
    approvedRun.candidates[0],
    'R4-H-1 worker',
    'Verify lease eligibility',
    { sourceOrigins: [ORIGIN] },
  )
  return { runId: discovered.id, run: approvedRun, worker }
}

test('R4-H-1: prefix derivation requires at least two fixed non-high-risk prefix segments (rejects /api/** and /_actions/**)', () => {
  // Single-segment prefixes MUST be rejected.
  for (const singleSeg of [
    '/',
    '/login',
    '/api/notes',
    '/api/emails?page=2',
    '/_actions/redeemReferralAwardAction',
    '/api/123/items',
    '/api/**',
    '/**',
    '/api/admin/users/42',
    '/api/billing/invoices/9',
  ]) {
    assert.equal(deriveOperatorPrefixPattern(singleSeg), null, `deriveOperatorPrefixPattern(${singleSeg}) must be null`)
    assert.equal(deriveApprovalPrefixPattern(singleSeg), null, `deriveApprovalPrefixPattern(${singleSeg}) must be null`)
  }

  // Two-segment non-high-risk prefixes succeed.
  assert.equal(deriveOperatorPrefixPattern('/api/v1/notes/123'), '/api/v1/**')
  assert.equal(deriveApprovalPrefixPattern('/api/v1/notes/123'), '/api/v1/**')
  assert.equal(deriveOperatorPrefixPattern('/api/orders/123'), '/api/orders/**')
  assert.equal(deriveApprovalPrefixPattern('/_actions/courses/redeem'), '/_actions/courses/**')

  // isPrefixApprovalPattern strictly requires >= 2 concrete fixed segments.
  assert.equal(isPrefixApprovalPattern('/api/v1/**'), true)
  assert.equal(isPrefixApprovalPattern('/api/orders/**'), true)
  assert.equal(isPrefixApprovalPattern('/api/**'), false)
  assert.equal(isPrefixApprovalPattern('/_actions/**'), false)
  assert.equal(isPrefixApprovalPattern('/**'), false)
  assert.equal(isPrefixApprovalPattern('/api/*/**'), false)

  // High-risk card under a benign 2-segment prefix is ineligible for prefix approval in UI/domain helper too.
  assert.equal(
    eligibleApprovalPrefixPattern({ method: 'POST', pathAndQuery: '/api/v1/billing/refund', riskLevel: 'low' }),
    null,
  )
  assert.equal(
    eligibleApprovalPrefixPattern({ method: 'POST', pathAndQuery: '/api/v1/notes/create', riskLevel: 'medium' }),
    '/api/v1/**',
  )
  assert.equal(
    evaluateClientApprovalLeaseEligibility({
      scope: 'prefix',
      method: 'POST',
      pathAndQuery: '/api/v1/notes/create',
      environmentMode: 'prod_readonly',
    }).eligible,
    false,
  )
})

test('R4-H-1: active prefix OR host lease refuses high-risk paths, GraphQL mutations, JSON-RPC mutations, and body-destructive payloads, calling isStateChangeApproved / Judge', async t => {
  for (const leaseMode of ['prefix', 'host_nondestructive'] as const) {
    const store = makeStore(t)
    const { runId, run, worker } = setupTier3Run(store)

    // Approve a single benign 3-segment notes POST card with either prefix (/api/v1/**) or host_nondestructive.
    const benignCard = store.createApprovalRequest(run, worker, {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/v1/notes/create',
      personaHandle: 'qa_member',
      rationale: 'Benign notes POST',
      requestPreview: '{"title":"qa"}',
      riskLevel: 'low',
    })
    store.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'decide_approval',
      approvalId: benignCard.id,
      decision: 'approved',
      scope: leaseMode,
      crossPersona: true,
    }))

    // Verify stored pattern carries explicit `source` for prefix scope.
    if (leaseMode === 'prefix') {
      const storedPatterns = store.run(runId).approvedEndpointPatterns
      assert.equal(storedPatterns.length, 1)
      assert.equal(storedPatterns[0]!.pathPattern, '/api/v1/**')
      assert.equal(storedPatterns[0]!.source, 'operator_explicit')
    }

    const engine = new RequestAdmissionEngine()
    const counters = { judgeHookCalls: 0 }
    const grant = {
      tier: 3 as const,
      canRead: (o: string) => o === ORIGIN,
      scopePolicy: store.scopePolicy(runId),
      approvalPolicy: 'auto_review' as const,
      approvalLeases: store.approvalLeaseAuthorizer(runId),
      isStateChangeApproved: () => {
        counters.judgeHookCalls += 1
        return false
      },
    }

    // Control: benign POST under /api/v1/ IS auto-authorized by the active lease with 0 judge calls.
    const control = engine.admit({
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/v1/notes/update',
      personaHandle: 'qa_member',
      headers: { 'Content-Type': 'application/json' },
      body: '{"title":"updated"}',
    }, grant)
    assert.equal(control.allowed, true, `${leaseMode}: benign sibling POST must be allowed by lease`)
    assert.equal(control.reasonCode, 'allowed_approval_lease')
    assert.equal(counters.judgeHookCalls, 0)

    // 1. High-risk paths (admin, role, billing, refund, delete, emails, account-close, order-cancel)
    //    MUST NOT be auto-authorized by prefix OR host lease and MUST call isStateChangeApproved.
    const highRiskPaths = [
      '/api/v1/admin/settings',
      '/api/v1/users/role',
      '/api/v1/billing/plan',
      '/api/v1/orders/refund',
      '/api/v1/items/delete',
      '/api/v1/emails/send',
      '/api/v1/account-close',
      '/api/v1/order-cancel',
    ]
    for (const path of highRiskPaths) {
      assert.equal(
        store.leaseAuthorizes(runId, ORIGIN, 'POST', path, 'qa_member'),
        false,
        `${leaseMode}: leaseAuthorizes must refuse high-risk path ${path}`,
      )
      const beforeCalls: number = counters.judgeHookCalls
      const dec = engine.admit({
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: path,
        personaHandle: 'qa_member',
        headers: { 'Content-Type': 'application/json' },
        body: '{"ok":true}',
      }, grant)
      assert.equal(dec.allowed, false, `${leaseMode}: admission must refuse lease bypass on ${path}`)
      assert.equal(dec.reasonCode, 'approval_required')
      assert.equal(counters.judgeHookCalls, beforeCalls + 1, `${leaseMode}: ${path} MUST call isStateChangeApproved / Judge`)
    }

    // 2. GraphQL mutation (both on /api/v1/graphql and generic /api/v1/gql) MUST call Judge.
    const gqlCases = [
      { path: '/api/v1/graphql', body: JSON.stringify({ query: 'mutation { updateAccount(id: 1) { ok } }' }) },
      { path: '/api/v1/gql', body: JSON.stringify({ query: 'mutation Drop { deleteItem(id: 1) { ok } }' }) },
    ]
    for (const tc of gqlCases) {
      assert.equal(
        store.leaseAuthorizes(runId, ORIGIN, 'POST', tc.path, 'qa_member', {
          body: tc.body,
          headers: { 'content-type': 'application/json' },
        }),
        false,
        `${leaseMode}: leaseAuthorizes must refuse GraphQL mutation at ${tc.path}`,
      )
      const beforeCalls: number = counters.judgeHookCalls
      const dec = engine.admit({
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: tc.path,
        personaHandle: 'qa_member',
        headers: { 'Content-Type': 'application/json' },
        body: tc.body,
      }, grant)
      assert.equal(dec.allowed, false, `${leaseMode}: GraphQL mutation at ${tc.path} must not bypass Judge`)
      assert.equal(dec.reasonCode, 'approval_required')
      assert.equal(counters.judgeHookCalls, beforeCalls + 1, `${leaseMode}: GraphQL mutation at ${tc.path} MUST call Judge`)
    }

    // 3. JSON-RPC destructive AND JSON-RPC non-read mutations MUST call Judge.
    const rpcCases = [
      { label: 'destructive', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'users.deleteAll', params: {} }) },
      { label: 'mutation', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'account.setTier', params: { tier: 'enterprise' } }) },
    ]
    for (const tc of rpcCases) {
      assert.equal(
        store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/v1/rpc', 'qa_member', {
          body: tc.body,
          headers: { 'content-type': 'application/json' },
        }),
        false,
        `${leaseMode}: leaseAuthorizes must refuse JSON-RPC ${tc.label}`,
      )
      const beforeCalls: number = counters.judgeHookCalls
      const dec = engine.admit({
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/rpc',
        personaHandle: 'qa_member',
        headers: { 'Content-Type': 'application/json' },
        body: tc.body,
      }, grant)
      assert.equal(dec.allowed, false, `${leaseMode}: JSON-RPC ${tc.label} must not bypass Judge`)
      assert.equal(dec.reasonCode, 'approval_required')
      assert.equal(counters.judgeHookCalls, beforeCalls + 1, `${leaseMode}: JSON-RPC ${tc.label} MUST call Judge`)
    }

    // 4. Body-level destructive / privilege mutation on a benign-looking path MUST call Judge.
    const bodyDestructiveCases = [
      JSON.stringify({ action: 'delete_user', id: 42 }),
      JSON.stringify({ operation: 'refund', amount: 100 }),
      JSON.stringify({ role: 'admin', userId: 7 }),
    ]
    for (const body of bodyDestructiveCases) {
      const beforeCalls: number = counters.judgeHookCalls
      const dec = engine.admit({
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/actions/dispatch',
        personaHandle: 'qa_member',
        headers: { 'Content-Type': 'application/json' },
        body,
      }, grant)
      assert.equal(dec.allowed, false, `${leaseMode}: body-destructive payload ${body} must not bypass Judge`)
      assert.equal(dec.reasonCode, 'approval_required')
      assert.equal(counters.judgeHookCalls, beforeCalls + 1, `${leaseMode}: body-destructive payload MUST call Judge`)
    }

    // 5. Judge Stage 1B itself enforces the exact same predicate on stored prefix patterns.
    if (leaseMode === 'prefix') {
      const patterns = store.run(runId).approvedEndpointPatterns
      let llmCalls = 0
      const llmCall = async () => {
        llmCalls += 1
        return JSON.stringify({ decision: 'escalate_human', riskLevel: 'high', reason: 'High risk' })
      }
      const judgeAdmin = await evaluateTier3Approval({
        policy: 'auto_review',
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/admin/roles',
        personaHandle: 'qa_member',
        bodyPreview: '{"ok":true}',
        approvedPatterns: patterns,
        llmCall,
      })
      assert.equal(judgeAdmin.decision, 'escalate_human', 'Stage 1B must NOT approve high-risk path via prefix pattern')
      assert.notEqual(judgeAdmin.stage, 'approved_pattern')
      assert.equal(llmCalls, 1, 'High-risk path under prefix pattern must reach Safety Judge')

      const judgeGql = await evaluateTier3Approval({
        policy: 'auto_review',
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/graphql',
        personaHandle: 'qa_member',
        headers: { 'content-type': 'application/json' },
        bodyPreview: JSON.stringify({ query: 'mutation { wipeAll { ok } }' }),
        approvedPatterns: patterns,
        llmCall,
      })
      assert.equal(judgeGql.decision, 'escalate_human', 'Stage 1B must NOT approve GraphQL mutation via prefix pattern')
      assert.notEqual(judgeGql.stage, 'approved_pattern')
      assert.equal(llmCalls, 2, 'GraphQL mutation under prefix pattern must reach Safety Judge')

      const authAdmin = authorizeStateChange({
        runId,
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/billing/refund',
        scopeRevision: store.run(runId).scopeRevision,
        context: { personaHandle: 'qa_member', body: '{"amount":10}' },
        approvedPatterns: patterns,
      })
      assert.equal(authAdmin.approved, false, 'authorizeStateChange must reject high-risk path on prefix pattern')
    }
  }
})

test('R4-H-1: prod_readonly (readonly_environment) is NEVER overridden by route, prefix, or host approval leases', t => {
  const store = makeStore(t)
  const { runId, run } = setupTier3Run(store)

  // Grant all 3 lease scopes BEFORE switching to prod_readonly.
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/notes/42',
    leaseScope: 'route',
    crossPersona: true,
  })
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/**',
    source: 'operator_explicit',
    leaseScope: 'prefix',
    crossPersona: true,
  })
  store.grantApprovalLease(run, {
    origin: ORIGIN,
    method: HOST_NONDESTRUCTIVE_LEASE_METHOD,
    pathAndQuery: HOST_NONDESTRUCTIVE_LEASE_PATTERN,
    leaseScope: 'host_nondestructive',
    crossPersona: true,
  })

  // Switch run to prod_readonly.
  store.setEnvironmentMode(store.run(runId), 'prod_readonly')

  // Direct predicate, store.leaseAuthorizes, and RequestAdmissionEngine MUST ALL refuse.
  for (const scope of ['route', 'prefix', 'host_nondestructive', 'any'] as const) {
    const elig = evaluateLeaseEligibility({
      scope,
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/v1/notes/42',
      routePattern: scope === 'prefix' ? '/api/v1/**' : undefined,
      environmentMode: 'prod_readonly',
    })
    assert.equal(elig.eligible, false, `evaluateLeaseEligibility(${scope}) must refuse prod_readonly`)
    assert.equal(elig.code, 'readonly_environment')
  }

  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/v1/notes/42'), false)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/v1/notes/new'), false)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/profile'), false)

  const engine = new RequestAdmissionEngine()
  let leaseCallbackCalls = 0
  const prodGrant = {
    tier: 3 as const,
    canRead: (o: string) => o === ORIGIN,
    scopePolicy: store.scopePolicy(runId),
    approvalPolicy: 'auto_review' as const,
    approvalLeases: (o: string, m: string, p: string, ph?: string | null) => {
      leaseCallbackCalls += 1
      return store.leaseAuthorizes(runId, o, m, p, ph)
    },
    isStateChangeApproved: () => true,
  }

  for (const path of ['/api/v1/notes/42', '/api/v1/notes/new', '/api/profile']) {
    const dec = engine.admit({
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: path,
      headers: { 'Content-Type': 'application/json' },
      body: '{"ok":true}',
    }, prodGrant)
    assert.equal(dec.allowed, false, `prod_readonly MUST refuse ${path} even with active leases`)
    assert.equal(dec.reasonCode, 'readonly_environment')
  }
  assert.equal(leaseCallbackCalls, 0, 'prod_readonly must never invoke or consume approval leases')
})

test('R4-H-1: stored patterns persist explicit source and missing/legacy source defaults to card_path (never operator_explicit)', t => {
  // Missing `source` on a `/**` pattern MUST default to `'card_path'` and NEVER act as a prefix glob!
  const missingSourcePrefix = [{ origin: ORIGIN, method: 'POST', pathPattern: '/api/v1/**' }]
  assert.equal(
    matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/notes/create' }, missingSourcePrefix),
    undefined,
    'pattern with missing source must default to card_path and never act as ** prefix wildcard',
  )
  assert.equal(
    matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/items/42' }, missingSourcePrefix),
    undefined,
  )

  // Explicit `source: 'operator_explicit'` with >= 2 fixed segments matches benign child paths only.
  const explicitPrefix = [{ origin: ORIGIN, method: 'POST', pathPattern: '/api/v1/**', source: 'operator_explicit' as const }]
  assert.ok(
    matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/notes/create' }, explicitPrefix),
  )
  assert.equal(
    matchesApprovedEndpointPattern({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/admin/roles' }, explicitPrefix),
    undefined,
    'explicit prefix pattern must still reject high-risk paths at match time',
  )

  // Store persists explicit `source` for both `route` (`card_path`) and `prefix` (`operator_explicit`).
  const store = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)
  const routeCard = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/v1/notes/12',
    rationale: 'Route card',
    requestPreview: '{"text":"a"}',
    riskLevel: 'low',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: routeCard.id,
    decision: 'approved',
    scope: 'route',
  }))
  const prefixCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/v1/notes/create',
    rationale: 'Prefix card',
    requestPreview: '{"text":"b"}',
    riskLevel: 'low',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: prefixCard.id,
    decision: 'approved',
    scope: 'prefix',
  }))

  const patterns = store.run(runId).approvedEndpointPatterns
  const routePat = patterns.find(p => p.method === 'PATCH')
  const prefixPat = patterns.find(p => p.method === 'POST')
  assert.equal(routePat?.source, 'card_path', 'stored route pattern must persist explicit source=card_path')
  assert.equal(prefixPat?.source, 'operator_explicit', 'stored prefix pattern must persist explicit source=operator_explicit')
})
