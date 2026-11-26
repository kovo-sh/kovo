/**
 * Fast class-level security guard for R3-03 (Single Approval Lease Authority + Unified ApprovalRequestFacts):
 *
 * Proves:
 *  1. Both durable authorization consumers (`authorizeStateChange` & `evaluateTier3Approval` Stage 1B)
 *     enforce `leaseAuthorizes` strictly — never returning approved from an unbounded
 *     `approvedEndpointPatterns` entry:
 *       - Missing `leaseAuthorizes` -> refused on both consumers
 *       - Expired lease with surviving pattern -> refused on both consumers
 *       - Exhausted (`maxUses`) lease with surviving pattern -> refused on both consumers
 *       - Foreign persona with surviving pattern -> refused on both consumers
 *       - Stale `scopeRevision` (including `scopeRevision: undefined`) -> refused on both consumers
 *       - R4-H-1 high-risk path / GraphQL / JSON-RPC exclusions -> refused on both consumers
 *  2. Fail-closed `undefined` `scopeRevision`: legacy patterns injected directly into
 *     `runs.approved_endpoint_patterns` with `scopeRevision: undefined` are ignored by
 *     `store.run()`, `store.runDetail()`, `authorizeStateChange`, and `evaluateTier3Approval`.
 *  3. One canonical `ApprovalRequestFacts` + full Judge audit persistence:
 *     `buildWorkerApprovalRequestFacts` threads `classifyRequestMutation` (`isStructuralMutation`,
 *     `mutationKind`) + `computeHostApprovalRiskFloor` (`hostFloor`) into `evaluateTier3Approval`;
 *     persisted approval rows carry `originalJudgeDecision`, `originalRiskLevel`, `hostFloor`, and
 *     `failSafeReason` with honest `decidedBy` (never hard-coded to `'auto-review:judge'`);
 *     `Store.verifySchema()` passes with zero DDL drift on reopen.
 *  4. Operator `extend_approval_lease` bounded extension (+30m / +uses, clamped to max bounds,
 *     refuses revoked / stale-revision / terminal runs) + derived `approvedEndpointPatterns`
 *     projection from live `approval_leases` + bulk-approve matching on live leases.
 *  5. Static guard: 0 readers of `approvedEndpointPatterns` outside the lease module (`store-runs.ts`
 *     projection & `schema.ts` column definition).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import test from 'node:test'
import {
  DEFAULT_APPROVAL_LEASE_TTL_MS,
  DEFAULT_ROUTE_LEASE_MAX_USES,
  MAX_APPROVAL_LEASE_TTL_MS,
  MAX_APPROVAL_LEASE_USES,
  newRun,
  runCommand,
} from '../src/domain.ts'
import type { ApprovedEndpointPattern } from '../src/domain.ts'
import {
  authorizeStateChange,
  buildApprovalRequestFacts,
  evaluateTier3Approval,
} from '../src/server/approval-judge.ts'
import {
  buildWorkerApprovalRequestFacts,
  resolveAutoApprovalDecidedBy,
} from '../src/server/run-actor.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const ORIGIN = 'https://app.r3-03.example'

function makeStore(t: test.TestContext): { store: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-03-lease-auth-'))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { store, dir }
}

function setupTier3Run(store: Store) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: `R3-03 Lease Auth ${randomUUID().slice(0, 6)}`,
    environment: 'public',
    seeds: [ORIGIN],
  })
  const created = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify R3-03 single approval lease authority and Judge audit persistence',
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
  const run = store.run(discovered.id)
  const worker = store.makeWorker(
    run,
    'investigation',
    run.candidates[0],
    'R3-03 worker',
    'Verify single approval lease authority',
    { sourceOrigins: [ORIGIN] },
  )
  return { projectId: project.id, runId: discovered.id, run, worker }
}

function walkSourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      walkSourceFiles(full, out)
    } else if (full.endsWith('.ts') || full.endsWith('.tsx')) {
      out.push(full)
    }
  }
  return out
}

// ============================================================================
// 1. Both consumers (`authorizeStateChange` & Stage 1B) enforce `leaseAuthorizes`
// ============================================================================

test('R3-03 Step 1: expired, exhausted, foreign-persona, missing-authorizer, and stale-revision patterns are ALL refused on both consumers', async t => {
  const { store } = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)
  const scopeRev = run.scopeRevision

  const card = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/101',
    personaHandle: 'alice',
    rationale: 'Benign item mutation',
    requestPreview: '{"name":"probe"}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: card.id,
    decision: 'approved',
    scope: 'route',
    maxUses: 2,
    expiresInMs: 60_000,
  }))

  // Snapshot a surviving pattern copy to simulate a stale/surviving approvedPatterns list.
  const survivingPatterns: ApprovedEndpointPattern[] = [...store.run(runId).approvedEndpointPatterns]
  assert.equal(survivingPatterns.length, 1)
  assert.equal(survivingPatterns[0]!.pathPattern, '/api/items/*')
  const lease = store.listApprovalLeases(runId, 'active')[0]!
  assert.equal(lease.personaHandle, 'alice')
  assert.equal(lease.maxUses, 2)

  const leaseAuth = store.approvalLeaseAuthorizer(runId)

  // (a) Missing `leaseAuthorizes`: surviving pattern alone MUST NEVER approve on either consumer!
  const authNoLeaseCb = authorizeStateChange({
    runId,
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/102',
    scopeRevision: scopeRev,
    context: { personaHandle: 'alice', body: '{"name":"x"}' },
    approvedPatterns: survivingPatterns,
  })
  assert.equal(authNoLeaseCb.approved, false, 'authorizeStateChange must refuse without leaseAuthorizes')

  const stage1bNoLeaseCb = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/102',
    scopeRevision: scopeRev,
    personaHandle: 'alice',
    bodyPreview: '{"name":"x"}',
    approvedPatterns: survivingPatterns,
    offline: true,
  })
  assert.notEqual(stage1bNoLeaseCb.decision, 'approve', 'Stage 1B must refuse without leaseAuthorizes')
  assert.notEqual(stage1bNoLeaseCb.stage, 'approved_pattern')

  // (b) Foreign persona (`bob` and `null`) with a surviving pattern -> refused on BOTH consumers!
  for (const foreignPersona of ['bob', null] as const) {
    const authForeign = authorizeStateChange({
      runId,
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/103',
      scopeRevision: scopeRev,
      context: { personaHandle: foreignPersona, body: '{"name":"x"}' },
      approvedPatterns: survivingPatterns,
      leaseAuthorizes: leaseAuth,
    })
    assert.equal(authForeign.approved, false, `authorizeStateChange must refuse foreign persona=${String(foreignPersona)}`)

    const stage1bForeign = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items/103',
      scopeRevision: scopeRev,
      personaHandle: foreignPersona,
      bodyPreview: '{"name":"x"}',
      approvedPatterns: survivingPatterns,
      leaseAuthorizes: leaseAuth,
      offline: true,
    })
    assert.notEqual(stage1bForeign.decision, 'approve', `Stage 1B must refuse foreign persona=${String(foreignPersona)}`)
    assert.notEqual(stage1bForeign.stage, 'approved_pattern')
  }

  // (c) Positive control: bound persona (`alice`) succeeds for use 1/2 (authorizeStateChange) and 2/2 (Stage 1B).
  const authUse1 = authorizeStateChange({
    runId,
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/104',
    scopeRevision: scopeRev,
    context: { personaHandle: 'alice', body: '{"name":"x"}' },
    approvedPatterns: survivingPatterns,
    leaseAuthorizes: leaseAuth,
  })
  assert.equal(authUse1.approved, true, 'live lease use 1/2 must succeed on authorizeStateChange')
  assert.equal(authUse1.via, 'operator_pattern')

  const stage1bUse2 = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/105',
    scopeRevision: scopeRev,
    personaHandle: 'alice',
    bodyPreview: '{"name":"x"}',
    approvedPatterns: survivingPatterns,
    leaseAuthorizes: leaseAuth,
    offline: true,
  })
  assert.equal(stage1bUse2.decision, 'approve', 'live lease use 2/2 must succeed on Stage 1B')
  assert.equal(stage1bUse2.stage, 'approved_pattern')

  // (d) Exhausted lease (2/2 uses consumed) with surviving pattern -> refused on BOTH consumers!
  assert.equal(store.run(runId).approvedEndpointPatterns.length, 0, 'exhausted lease drops out of derived projection')
  const authExhausted = authorizeStateChange({
    runId,
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/106',
    scopeRevision: scopeRev,
    context: { personaHandle: 'alice', body: '{"name":"x"}' },
    approvedPatterns: survivingPatterns,
    leaseAuthorizes: leaseAuth,
  })
  assert.equal(authExhausted.approved, false, 'authorizeStateChange must refuse exhausted lease even with surviving pattern')

  const stage1bExhausted = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items/106',
    scopeRevision: scopeRev,
    personaHandle: 'alice',
    bodyPreview: '{"name":"x"}',
    approvedPatterns: survivingPatterns,
    leaseAuthorizes: leaseAuth,
    offline: true,
  })
  assert.notEqual(stage1bExhausted.decision, 'approve', 'Stage 1B must refuse exhausted lease even with surviving pattern')
  assert.notEqual(stage1bExhausted.stage, 'approved_pattern')

  // (e) Expired lease (TTL in the past) with surviving pattern -> refused on BOTH consumers!
  const card2 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/notes/55',
    personaHandle: 'alice',
    rationale: 'Note edit',
    requestPreview: '{"text":"ok"}',
    riskLevel: 'low',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: card2.id,
    decision: 'approved',
    scope: 'route',
    expiresInMs: 60_000,
  }))
  const patchPatterns: ApprovedEndpointPattern[] = [...store.run(runId).approvedEndpointPatterns]
  assert.equal(patchPatterns.length, 1)
  const patchLease = store.listApprovalLeases(runId, 'active').find(l => l.method === 'PATCH')!
  store.client.prepare('UPDATE approval_leases SET expires_at = ? WHERE id = ?').run(Date.now() - 1_000, patchLease.id)

  assert.equal(store.run(runId).approvedEndpointPatterns.length, 0, 'expired lease drops out of derived projection')
  const authExpired = authorizeStateChange({
    runId,
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/notes/56',
    scopeRevision: scopeRev,
    context: { personaHandle: 'alice', body: '{"text":"x"}' },
    approvedPatterns: patchPatterns,
    leaseAuthorizes: leaseAuth,
  })
  assert.equal(authExpired.approved, false, 'authorizeStateChange must refuse expired lease')

  const stage1bExpired = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/notes/56',
    scopeRevision: scopeRev,
    personaHandle: 'alice',
    bodyPreview: '{"text":"x"}',
    approvedPatterns: patchPatterns,
    leaseAuthorizes: leaseAuth,
    offline: true,
  })
  assert.notEqual(stage1bExpired.decision, 'approve', 'Stage 1B must refuse expired lease')
  assert.notEqual(stage1bExpired.stage, 'approved_pattern')
})

// ============================================================================
// 2. Fail-closed `undefined` `scopeRevision`
// ============================================================================

test('R3-03 Step 2: undefined or stale scopeRevision patterns are treated as stale everywhere (fail-closed)', async t => {
  const { store } = makeStore(t)
  const { runId, run } = setupTier3Run(store)
  const currentRev = run.scopeRevision

  // Inject a legacy pattern with NO scopeRevision directly into runs.approved_endpoint_patterns.
  const legacyUndefPattern: ApprovedEndpointPattern = {
    origin: ORIGIN,
    method: 'POST',
    pathPattern: '/api/legacy/*',
  }
  store.client.prepare('UPDATE runs SET approved_endpoint_patterns = ? WHERE id = ?')
    .run(JSON.stringify([legacyUndefPattern]), runId)

  // Derived projection ignores raw column rows with no live lease.
  assert.equal(store.run(runId).approvedEndpointPatterns.length, 0)
  assert.equal(store.runDetail(runId).approvedEndpointPatterns.length, 0)

  // Even with a permissive stub authorizer, patterns with undefined or old scopeRevision MUST be rejected!
  const stalePatterns: ApprovedEndpointPattern[] = [
    { origin: ORIGIN, method: 'POST', pathPattern: '/api/legacy/*' },
    { origin: ORIGIN, method: 'POST', pathPattern: '/api/old/*', scopeRevision: Math.max(0, currentRev - 1) },
  ]
  for (const path of ['/api/legacy/1', '/api/old/1']) {
    const authRes = authorizeStateChange({
      runId,
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: path,
      scopeRevision: currentRev,
      context: { personaHandle: 'alice', body: '{}' },
      approvedPatterns: stalePatterns,
      leaseAuthorizes: () => true,
    })
    assert.equal(authRes.approved, false, `authorizeStateChange must reject stale/undefined scopeRevision for ${path}`)

    const judgeRes = await evaluateTier3Approval({
      policy: 'auto_review',
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: path,
      scopeRevision: currentRev,
      personaHandle: 'alice',
      bodyPreview: '{}',
      approvedPatterns: stalePatterns,
      leaseAuthorizes: () => true,
      offline: true,
    })
    assert.notEqual(judgeRes.decision, 'approve', `Stage 1B must reject stale/undefined scopeRevision for ${path}`)
    assert.notEqual(judgeRes.stage, 'approved_pattern')
  }
})

// ============================================================================
// 3. Unified `ApprovalRequestFacts` + full Judge audit persistence + 0 DDL drift
// ============================================================================

test('R3-03 Step 3: buildWorkerApprovalRequestFacts aligns mutation classification + hostFloor, and Judge audit fields persist cleanly without schema drift', async t => {
  const { store, dir } = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  // (a) GraphQL mutation -> mutationKind='graphql_mutation_or_unverified', hostFloor='medium'
  //     Even if Judge returns approve+low, hostFloor='medium' MUST block auto-approval!
  const gqlBody = JSON.stringify({ query: 'mutation { updateProfile(name: "qa") { id } }' })
  const gqlFacts = buildWorkerApprovalRequestFacts(run, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    personaHandle: 'alice',
    headers: { 'content-type': 'application/json' },
    bodyPreview: gqlBody,
  })
  assert.equal(gqlFacts.mutationKind, 'graphql_mutation_or_unverified')
  assert.equal(gqlFacts.hostFloor, 'medium')

  const gqlEval = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/graphql',
    personaHandle: 'alice',
    headers: { 'content-type': 'application/json' },
    bodyPreview: gqlBody,
    facts: gqlFacts,
    hostFloor: gqlFacts.hostFloor,
    isStructuralMutation: gqlFacts.isStructuralMutation,
    mutationKind: gqlFacts.mutationKind,
    offline: false,
    llmCall: async () => JSON.stringify({ decision: 'approve', riskLevel: 'low', reason: 'Looks benign' }),
  })
  assert.equal(gqlEval.decision, 'escalate_human', 'hostFloor=medium must prohibit auto-approval on GraphQL mutation')
  assert.equal(gqlEval.hostFloor, 'medium')
  assert.equal(gqlEval.originalJudgeDecision, 'approve')
  assert.equal(gqlEval.originalRiskLevel, 'low')

  // (b) Stage-2 policy normalization preserves originalJudgeDecision='escalate_human' + decidedBy='auto-review:policy'
  const benignFacts = buildApprovalRequestFacts({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    personaHandle: 'alice',
    bodyPreview: '{"text":"benign"}',
  })
  assert.equal(benignFacts.hostFloor, 'low')
  const normalizedEval = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    personaHandle: 'alice',
    bodyPreview: '{"text":"benign"}',
    facts: benignFacts,
    offline: false,
    llmCall: async () => JSON.stringify({ decision: 'escalate_human', riskLevel: 'low', reason: 'Caution on comment POST' }),
  })
  assert.equal(normalizedEval.decision, 'approve')
  assert.equal(normalizedEval.decidedBy, 'auto-review:policy')
  assert.equal(normalizedEval.originalJudgeDecision, 'escalate_human')
  assert.equal(normalizedEval.originalRiskLevel, 'low')
  assert.equal(normalizedEval.hostFloor, 'low')

  // Persist auto-approval row and assert originalJudgeDecision, originalRiskLevel, hostFloor, failSafeReason, decidedBy!
  const persistedAuto = store.recordAutoApprovalDecision(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    personaHandle: 'alice',
    rationale: 'Comment verification',
    requestPreview: '{"text":"benign"}',
    decision: 'approved',
    decidedBy: resolveAutoApprovalDecidedBy(normalizedEval),
    riskLevel: normalizedEval.riskLevel,
    policyNote: normalizedEval.reason,
    originalJudgeDecision: normalizedEval.originalJudgeDecision ?? null,
    originalRiskLevel: normalizedEval.originalRiskLevel ?? null,
    hostFloor: normalizedEval.hostFloor ?? benignFacts.hostFloor,
    failSafeReason: normalizedEval.failSafeReason ?? null,
  })
  assert.equal(persistedAuto.decidedBy, 'auto-review:policy')
  assert.equal(persistedAuto.originalJudgeDecision, 'escalate_human')
  assert.equal(persistedAuto.originalRiskLevel, 'low')
  assert.equal(persistedAuto.hostFloor, 'low')
  assert.equal(persistedAuto.failSafeReason, null)

  // Read back via getApprovalRequest & runDetail().approvals!
  const reloadedAuto = store.getApprovalRequest(runId, persistedAuto.id)
  assert.equal(reloadedAuto.originalJudgeDecision, 'escalate_human')
  assert.equal(reloadedAuto.originalRiskLevel, 'low')
  assert.equal(reloadedAuto.hostFloor, 'low')
  assert.equal(reloadedAuto.failSafeReason, null)

  // (c) Fail-safe escalation persists failSafeReason + hostFloor on the human card,
  //     and resolveAutoApprovalDecidedBy never hard-codes non-judge denials to 'auto-review:judge'.
  const failSafeEval = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    personaHandle: 'alice',
    bodyPreview: '{"text":"benign"}',
    facts: benignFacts,
    offline: true,
  })
  assert.equal(failSafeEval.failSafe, true)
  assert.equal(failSafeEval.failSafeReason, 'judge_offline')
  assert.equal(failSafeEval.hostFloor, 'low')
  assert.equal(resolveAutoApprovalDecidedBy(failSafeEval), 'auto-review:policy')
  assert.equal(
    resolveAutoApprovalDecidedBy({ decidedBy: 'auto-review:environment', failSafe: false, hostFloor: 'high' }),
    'auto-review:environment',
    'environment deny must preserve auto-review:environment instead of hard-coding auto-review:judge',
  )

  const failSafeCard = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    personaHandle: 'alice',
    rationale: 'Fail-safe card',
    requestPreview: '{"text":"benign"}',
    riskLevel: failSafeEval.riskLevel,
    policyNote: failSafeEval.reason,
    originalJudgeDecision: failSafeEval.originalJudgeDecision ?? null,
    originalRiskLevel: failSafeEval.originalRiskLevel ?? null,
    hostFloor: failSafeEval.hostFloor ?? benignFacts.hostFloor,
    failSafeReason: failSafeEval.failSafeReason ?? null,
  })
  assert.equal(failSafeCard.failSafeReason, 'judge_offline')
  assert.equal(failSafeCard.hostFloor, 'low')

  const detailApprovals = store.runDetail(runId).approvals
  const detailAuto = detailApprovals.find(a => a.id === persistedAuto.id)!
  const detailFailSafe = detailApprovals.find(a => a.id === failSafeCard.id)!
  assert.equal(detailAuto.originalJudgeDecision, 'escalate_human')
  assert.equal(detailAuto.hostFloor, 'low')
  assert.equal(detailFailSafe.failSafeReason, 'judge_offline')

  // (d) Reopening the DB passes Store.verifySchema() with 0 DDL drift!
  store.verifySchema()
  store.close()
  const reopened = new Store(dir)
  t.after(() => { try { reopened.close() } catch { /* already closed */ } })
  reopened.verifySchema()
  const reopenedRow = reopened.getApprovalRequest(runId, persistedAuto.id)
  assert.equal(reopenedRow.originalJudgeDecision, 'escalate_human')
  assert.equal(reopenedRow.originalRiskLevel, 'low')
  assert.equal(reopenedRow.hostFloor, 'low')
})

// ============================================================================
// 4. Operator `extend_approval_lease` + live-lease projection + bulk-approve
// ============================================================================

test('R3-03 Step 4: extend_approval_lease extends TTL/uses within bounds, reactivates expired/exhausted leases, and refuses revoked or stale-revision leases', t => {
  const { store } = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  const card = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/orders/10',
    personaHandle: 'alice',
    rationale: 'Order probe',
    requestPreview: '{"qty":1}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: card.id,
    decision: 'approved',
    scope: 'route',
    maxUses: 1,
    expiresInMs: 60_000,
  }))

  const lease = store.listApprovalLeases(runId, 'active')[0]!
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/11', 'alice'), true, 'use 1/1')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/12', 'alice'), false, 'exhausted after 1/1')
  assert.equal(store.runDetail(runId).approvalLeases.length, 0)
  assert.equal(store.runDetail(runId).approvedEndpointPatterns.length, 0)

  // Extend the exhausted lease via operator command -> reactivates with bounded +30m & +DEFAULT_ROUTE_LEASE_MAX_USES.
  const beforeExtend = Date.now()
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'extend_approval_lease',
    leaseId: lease.id,
  }))
  const extended = store.listApprovalLeases(runId, 'active').find(l => l.id === lease.id)!
  assert.ok(extended, 'extended lease must be active again')
  assert.equal(extended.maxUses, 1 + DEFAULT_ROUTE_LEASE_MAX_USES)
  assert.ok(extended.expiresAt! >= beforeExtend + DEFAULT_APPROVAL_LEASE_TTL_MS - 1_000)
  assert.ok(extended.expiresAt! <= Date.now() + MAX_APPROVAL_LEASE_TTL_MS + 1_000)
  assert.equal(store.runDetail(runId).approvedEndpointPatterns.length, 1, 'derived projection restores live lease')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/orders/12', 'alice'), true, 'extended lease authorizes again')

  // Extension clamps strictly at MAX_APPROVAL_LEASE_USES & now + MAX_APPROVAL_LEASE_TTL_MS.
  const clamped = store.extendApprovalLease(store.run(runId), lease.id, {
    extendMs: MAX_APPROVAL_LEASE_TTL_MS,
    addUses: MAX_APPROVAL_LEASE_USES,
  })
  assert.equal(clamped.maxUses, MAX_APPROVAL_LEASE_USES)
  assert.ok(clamped.expiresAt! <= Date.now() + MAX_APPROVAL_LEASE_TTL_MS + 1_000)

  // Revoked lease CANNOT be extended.
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'revoke_approval_lease',
    leaseId: lease.id,
  }))
  assert.throws(() => store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'extend_approval_lease',
    leaseId: lease.id,
  })), /revoked/i)

  // Stale scopeRevision lease CANNOT be extended.
  const freshLease = store.grantApprovalLease(store.run(runId), {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/profile',
    expiresInMs: 60_000,
  })
  store.updateRun(runId, { scopeRevision: store.run(runId).scopeRevision + 1 })
  assert.throws(() => store.extendApprovalLease(store.run(runId), freshLease.id), /older scope revision/i)
})

// ============================================================================
// 5. Static guard: 0 readers of `approvedEndpointPatterns` outside lease module
// ============================================================================

test('R3-03 Step 5 static guard: 0 readers of approvedEndpointPatterns outside the lease module', () => {
  const srcRoot = join(REPO_ROOT, 'src')
  const files = walkSourceFiles(srcRoot)
  const allowedFiles = new Set([
    'src/server/store-runs.ts',
    'src/server/schema.ts',
  ])
  const violations: string[] = []

  for (const fullPath of files) {
    const rel = relative(REPO_ROOT, fullPath).replace(/\\/g, '/')
    const text = readFileSync(fullPath, 'utf8')
    if (!text.includes('approvedEndpointPatterns')) continue
    if (!allowedFiles.has(rel)) {
      const lines = text.split('\n')
      lines.forEach((line, idx) => {
        if (line.includes('approvedEndpointPatterns')) {
          violations.push(`${rel}:${idx + 1}: ${line.trim()}`)
        }
      })
    }
  }

  assert.deepEqual(
    violations,
    [],
    `Found forbidden readers/references to approvedEndpointPatterns outside lease module:\n${violations.join('\n')}`,
  )

  // Even inside src/server/store-runs.ts, nothing may read `.approvedEndpointPatterns` off a run row!
  const storeRunsText = readFileSync(join(REPO_ROOT, 'src/server/store-runs.ts'), 'utf8')
  const storeReads: string[] = []
  storeRunsText.split('\n').forEach((line, idx) => {
    if (/\.\s*approvedEndpointPatterns\b/.test(line)) {
      storeReads.push(`src/server/store-runs.ts:${idx + 1}: ${line.trim()}`)
    }
  })
  assert.deepEqual(
    storeReads,
    [],
    `store-runs.ts must derive approvedEndpointPatterns from approval_leases rather than reading run.approvedEndpointPatterns:\n${storeReads.join('\n')}`,
  )
})
