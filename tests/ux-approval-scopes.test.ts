import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it, test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import {
  approvalRouteDedupeKey,
  defaultPrimaryApprovalScope,
  deriveApprovalPrefixPattern,
  eligibleApprovalPrefixPattern,
  HOST_NONDESTRUCTIVE_LEASE_METHOD,
  HOST_NONDESTRUCTIVE_LEASE_PATTERN,
  isHighRiskOrExternalMutationPath,
  isHostNonDestructiveEligibleCard,
  isHostNonDestructiveLease,
  isPrefixApprovalPattern,
  newRun,
  runCommand,
} from '../src/domain.ts'
import { StateChangeApprovalLedger, authorizeStateChange } from '../src/server/approval-judge.ts'
import {
  deriveOperatorPrefixPattern,
  matchesApprovedEndpointPattern,
  normalizeApprovalPathPattern,
} from '../src/server/approval-pattern.ts'
import { RequestAdmissionEngine } from '../src/server/request-admission.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN = 'https://academy.dyad.sh'
const OTHER_ORIGIN = 'https://docs.dyad.sh'

function makeStore(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-approval-scopes-'))
  const store = new Store(join(dir, 'kovo.db'))
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return store
}

function setupTier3Run(store: Store, origins: string[] = [ORIGIN, OTHER_ORIGIN]) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: `Approval Scopes ${randomUUID().slice(0, 6)}`,
    environment: 'public',
    seeds: origins,
  })
  const created = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify explicit scoped approval actions, deduped queue, and lease safety invariants',
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
    'Scoped approval test worker',
    'Exercise scoped approvals',
    { sourceOrigins: origins },
  )
  return { projectId: project.id, runId: discovered.id, run: approvedRun, worker }
}

// ---------------------------------------------------------------------------
// 1. Unit tests for pure prefix / dedupe / host-safety primitives
// ---------------------------------------------------------------------------

test('deriveOperatorPrefixPattern & deriveApprovalPrefixPattern derive concrete >=2-segment prefixes and reject single-segment, bare /**, and worker globs', () => {
  assert.equal(deriveOperatorPrefixPattern('/_actions/courses/redeemReferralAwardAction'), '/_actions/courses/**')
  assert.equal(deriveApprovalPrefixPattern('/_actions/courses/redeemReferralAwardAction'), '/_actions/courses/**')
  assert.equal(deriveOperatorPrefixPattern('/api/v1/users/123'), '/api/v1/**')
  assert.equal(deriveApprovalPrefixPattern('/api/v1/users/123'), '/api/v1/**')
  assert.equal(deriveOperatorPrefixPattern('/api/orders/123'), '/api/orders/**')

  // Bare root, single-segment prefixes (/api/**, /_actions/**), ID-leading paths, high-risk prefix bases, and worker globs MUST return null
  for (const bad of ['/', '/login', '/_actions/redeemReferralAwardAction', '/api/emails?page=2', '/123/items', '/api/123/items', '/api/**', '/**', '/api/*/users', '/api/item*all']) {
    assert.equal(deriveOperatorPrefixPattern(bad), null, `deriveOperatorPrefixPattern(${bad}) must be null`)
    assert.equal(deriveApprovalPrefixPattern(bad), null, `deriveApprovalPrefixPattern(${bad}) must be null`)
  }

  assert.equal(isPrefixApprovalPattern('/_actions/courses/**'), true)
  assert.equal(isPrefixApprovalPattern('/_actions/**'), false)
  assert.equal(isPrefixApprovalPattern('/api/**'), false)
  assert.equal(isPrefixApprovalPattern('/**'), false)
  assert.equal(isPrefixApprovalPattern('/api/orders/*'), false)
})

test('high-risk path classification, default primary scope, and dedupe keys enforce safety invariants', () => {
  assert.equal(isHighRiskOrExternalMutationPath('/_actions/redeemReferralAwardAction'), false)
  assert.equal(isHighRiskOrExternalMutationPath('/api/items/42'), false)
  assert.equal(isHighRiskOrExternalMutationPath('/api/profile'), false)

  for (const risky of [
    '/api/billing/charge',
    '/api/users/delete',
    '/api/admin/roles',
    '/api/webhooks/trigger',
    '/api/uploads/avatar',
    '/api/emails/send',
    '/api/**',
  ]) {
    assert.equal(isHighRiskOrExternalMutationPath(risky), true, `${risky} must be flagged high-risk/external`)
  }

  assert.equal(defaultPrimaryApprovalScope({ method: 'POST', riskLevel: 'medium' }), 'route')
  assert.equal(defaultPrimaryApprovalScope({ method: 'POST', riskLevel: 'high' }), 'once')
  assert.equal(defaultPrimaryApprovalScope({ method: 'DELETE', riskLevel: 'low' }), 'once')

  assert.equal(eligibleApprovalPrefixPattern({ method: 'POST', pathAndQuery: '/_actions/courses/redeemReferralAwardAction', riskLevel: 'medium' }), '/_actions/courses/**')
  assert.equal(eligibleApprovalPrefixPattern({ method: 'POST', pathAndQuery: '/_actions/redeemReferralAwardAction', riskLevel: 'medium' }), null)
  assert.equal(eligibleApprovalPrefixPattern({ method: 'DELETE', pathAndQuery: '/api/items/42', riskLevel: 'medium' }), null)
  assert.equal(eligibleApprovalPrefixPattern({ method: 'POST', pathAndQuery: '/_actions/courses/redeem', riskLevel: 'high' }), null)

  assert.equal(isHostNonDestructiveEligibleCard({ method: 'POST', pathAndQuery: '/_actions/redeemReferralAwardAction', riskLevel: 'medium' }), true)
  assert.equal(isHostNonDestructiveEligibleCard({ method: 'DELETE', pathAndQuery: '/api/items/42', riskLevel: 'low' }), false)
  assert.equal(isHostNonDestructiveEligibleCard({ method: 'POST', pathAndQuery: '/api/items/42', riskLevel: 'high' }), false)
  assert.equal(isHostNonDestructiveEligibleCard({ method: 'POST', pathAndQuery: '/api/billing/charge', riskLevel: 'low' }), false)

  assert.equal(
    approvalRouteDedupeKey({ origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/123?a=1' }),
    approvalRouteDedupeKey({ origin: ORIGIN, method: 'post', pathAndQuery: '/api/orders/456/?b=2' }),
  )
})

// ---------------------------------------------------------------------------
// 2. Store & security invariant tests for all 4 scopes
// ---------------------------------------------------------------------------

test('scope=once approves ONLY the exact card, mints NO lease and NO pattern, and leaves duplicate cards pending', t => {
  const store = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  const card1 = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction',
    rationale: 'Differential verification probe 1',
    requestPreview: '{"code":"ref1"}',
    riskLevel: 'medium',
  })
  const card2 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction?retry=1',
    rationale: 'Differential verification probe 2',
    requestPreview: '{"code":"ref2"}',
    riskLevel: 'medium',
  })

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: card1.id,
    decision: 'approved',
    scope: 'once',
  }))

  assert.equal(store.getApprovalRequest(runId, card1.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, card2.id).status, 'pending', 'once must NOT bulk-approve duplicate cards')
  assert.equal(store.listApprovalLeases(runId, 'active').length, 0, 'once must NOT grant a durable lease')
  assert.equal(store.run(runId).approvedEndpointPatterns.length, 0, 'once must NOT add approvedEndpointPatterns')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/_actions/redeemReferralAwardAction'), false)

  // Verify the 60s one-shot exact-fingerprint ledger authorizes exactly one call and rejects a second.
  const ledger = new StateChangeApprovalLedger()
  const fp = {
    runId,
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction',
    scopeRevision: store.run(runId).scopeRevision,
    body: '{"code":"ref1"}',
  }
  ledger.grant(fp, { expiresAt: Date.now() + 60_000, approvalId: card1.id })
  const first = authorizeStateChange({
    ...fp,
    context: { body: fp.body },
    approvedPatterns: store.run(runId).approvedEndpointPatterns,
    ledger,
  })
  const second = authorizeStateChange({
    ...fp,
    context: { body: fp.body },
    approvedPatterns: store.run(runId).approvedEndpointPatterns,
    ledger,
  })
  assert.equal(first.approved, true)
  assert.equal(first.via, 'one_shot')
  assert.equal(second.approved, false, 'one-shot grant must be single-use')
})

test('scope=route creates route lease + approved pattern + bulk-approves matching pending cards (and scope=route deny resolves duplicates)', t => {
  const store = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  const dup1 = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction',
    rationale: 'Action probe 1',
    requestPreview: '{"n":1}',
    riskLevel: 'medium',
  })
  const dup2 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction?attempt=2',
    rationale: 'Action probe 2',
    requestPreview: '{"n":2}',
    riskLevel: 'medium',
  })
  const otherAction = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/submitQuiz',
    rationale: 'Different action',
    requestPreview: '{"q":1}',
    riskLevel: 'low',
  })

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: dup1.id,
    decision: 'approved',
    scope: 'route',
  }))

  assert.equal(store.getApprovalRequest(runId, dup1.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, dup2.id).status, 'approved', 'route scope must bulk-approve matching pending cards')
  assert.equal(store.getApprovalRequest(runId, otherAction.id).status, 'pending', 'route scope must leave sibling routes pending')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/_actions/redeemReferralAwardAction'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/_actions/submitQuiz'), false)
  assert.equal(store.run(runId).approvedEndpointPatterns.length, 1)
  assert.equal(store.run(runId).approvedEndpointPatterns[0]!.pathPattern, '/_actions/redeemreferralawardaction')

  // Denying with scope=route denies matching duplicate pending cards on that route cleanly.
  const deny1 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/orders/123',
    rationale: 'Order patch 1',
    requestPreview: '{"qty":1}',
    riskLevel: 'medium',
  })
  const deny2 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/orders/456',
    rationale: 'Order patch 2',
    requestPreview: '{"qty":2}',
    riskLevel: 'medium',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: deny1.id,
    decision: 'denied',
    scope: 'route',
  }))
  assert.equal(store.getApprovalRequest(runId, deny1.id).status, 'denied')
  assert.equal(store.getApprovalRequest(runId, deny2.id).status, 'denied')
  assert.equal(store.getApprovalRequest(runId, otherAction.id).status, 'pending')
})

test('scope=prefix uses operator_explicit >=2-segment prefix, bulk-approves non-high cards, and enforces R3-H-9/R4-H-1 bare /** & single-segment & worker-glob rejection', t => {
  const store = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  const action1 = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/courses/redeemReferralAwardAction',
    rationale: 'Action 1',
    requestPreview: '{"a":1}',
    riskLevel: 'medium',
  })
  const action2 = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/courses/submitQuiz',
    rationale: 'Action 2',
    requestPreview: '{"a":2}',
    riskLevel: 'low',
  })
  const highRiskAction = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/courses/resetWorkspace',
    rationale: 'High-risk action under same prefix',
    requestPreview: '{"reset":true}',
    riskLevel: 'high',
  })
  const outsidePrefix = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    rationale: 'Outside prefix',
    requestPreview: '{"x":1}',
    riskLevel: 'low',
  })

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: action1.id,
    decision: 'approved',
    scope: 'prefix',
  }))

  assert.equal(store.getApprovalRequest(runId, action1.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, action2.id).status, 'approved', 'prefix bulk-approves non-high cards under /_actions/courses/**')
  assert.equal(store.getApprovalRequest(runId, highRiskAction.id).status, 'pending', 'prefix MUST keep high-risk cards pending')
  assert.equal(store.getApprovalRequest(runId, outsidePrefix.id).status, 'pending', 'prefix MUST NOT resolve paths outside prefix')

  const leases = store.listApprovalLeases(runId, 'active')
  assert.equal(leases.length, 1)
  assert.equal(leases[0]!.routePattern, '/_actions/courses/**')
  assert.equal(store.run(runId).approvedEndpointPatterns[0]?.pathPattern, '/_actions/courses/**')
  assert.equal(store.run(runId).approvedEndpointPatterns[0]?.source, 'operator_explicit')

  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/_actions/courses/anotherAction'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/_actions/courses/nested/deep'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'DELETE', '/_actions/courses/anotherAction'), false, 'prefix lease is method-bound')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/items'), false)

  // R3-H-9 / R4-H-1: worker-glob cards, bare /**, single-segment paths, DELETE, and high-risk cards MUST reject scope=prefix
  const globCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/**',
    rationale: 'Worker glob attempt',
    requestPreview: '{}',
    riskLevel: 'low',
  })
  assert.throws(() => store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: globCard.id,
    decision: 'approved',
    scope: 'prefix',
  })), /high-risk|glob/i)

  const rootSegCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/submit',
    rationale: 'Single segment path',
    requestPreview: '{}',
    riskLevel: 'low',
  })
  assert.throws(() => store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: rootSegCard.id,
    decision: 'approved',
    scope: 'prefix',
  })), /two concrete fixed prefix segments|bare \/\*\*/i)

  const deleteCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/42',
    rationale: 'Delete probe',
    requestPreview: '',
    riskLevel: 'medium',
  })
  assert.throws(() => store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: deleteCard.id,
    decision: 'approved',
    scope: 'prefix',
  })), /DELETE/i)

  // Direct bare /** grant attempt must also throw.
  assert.throws(() => store.runsRepo.grantApprovalLease(store.run(runId), {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/**',
    source: 'operator_explicit',
    leaseScope: 'prefix',
  }), /Bare \/\*\*/i)
})

test('scope=host_nondestructive covers POST/PUT/PATCH on origin, refuses DELETE/high-risk/external/other-origin, obeys R3-H-1 admission, and revokes cleanly', t => {
  const store = makeStore(t)
  const { runId, run, worker } = setupTier3Run(store)

  const postCard = store.createApprovalRequest(run, worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/_actions/redeemReferralAwardAction',
    rationale: 'Benign POST action',
    requestPreview: '{"id":1}',
    riskLevel: 'medium',
  })
  const patchCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/profile',
    rationale: 'Benign PATCH',
    requestPreview: '{"bio":"qa"}',
    riskLevel: 'low',
  })
  const deleteCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/42',
    rationale: 'Destructive DELETE',
    requestPreview: '',
    riskLevel: 'low',
  })
  const highRiskCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/settings',
    rationale: 'High risk card',
    requestPreview: '{"flag":true}',
    riskLevel: 'high',
  })
  const billingCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/billing/charge',
    rationale: 'Billing external mutation',
    requestPreview: '{"amount":100}',
    riskLevel: 'low',
  })
  const otherOriginCard = store.createApprovalRequest(store.run(runId), worker, {
    origin: OTHER_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/comments',
    rationale: 'Different host',
    requestPreview: '{"text":"hi"}',
    riskLevel: 'low',
  })

  // Granting host_nondestructive from DELETE, high-risk, or billing card MUST be refused
  for (const forbidden of [deleteCard, highRiskCard, billingCard]) {
    assert.throws(() => store.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'decide_approval',
      approvalId: forbidden.id,
      decision: 'approved',
      scope: 'host_nondestructive',
    })))
  }

  // Grant host_nondestructive from benign POST card
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'decide_approval',
    approvalId: postCard.id,
    decision: 'approved',
    scope: 'host_nondestructive',
  }))

  // Bulk-approval checks
  assert.equal(store.getApprovalRequest(runId, postCard.id).status, 'approved')
  assert.equal(store.getApprovalRequest(runId, patchCard.id).status, 'approved', 'host lease bulk-approves low/medium non-destructive cards on same origin')
  assert.equal(store.getApprovalRequest(runId, deleteCard.id).status, 'pending', 'host lease NEVER approves DELETE')
  assert.equal(store.getApprovalRequest(runId, highRiskCard.id).status, 'pending', 'host lease NEVER approves high-risk cards')
  assert.equal(store.getApprovalRequest(runId, billingCard.id).status, 'pending', 'host lease NEVER approves billing/external-mutation routes')
  assert.equal(store.getApprovalRequest(runId, otherOriginCard.id).status, 'pending', 'host lease NEVER crosses origins')

  // Lease row & pattern isolation checks
  const detail = store.runDetail(runId)
  assert.equal(detail.approvalLeases.length, 1)
  const hostLease = detail.approvalLeases[0]!
  assert.equal(isHostNonDestructiveLease(hostLease), true)
  assert.equal(hostLease.method, HOST_NONDESTRUCTIVE_LEASE_METHOD)
  assert.equal(hostLease.routePattern, HOST_NONDESTRUCTIVE_LEASE_PATTERN)
  assert.equal(detail.approvedEndpointPatterns.length, 0, 'host lease must NOT inject bare /** into approvedEndpointPatterns')

  // leaseAuthorizes checks
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/items'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PUT', '/api/items/42'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/profile'), true)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'DELETE', '/api/items/42'), false, 'host lease MUST refuse DELETE')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/billing/charge'), false, 'host lease MUST refuse billing')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/users/delete'), false, 'host lease MUST refuse delete path')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/admin/roles'), false, 'host lease MUST refuse admin path')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/webhooks/send'), false, 'host lease MUST refuse webhooks')
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/uploads/avatar'), false, 'host lease MUST refuse uploads')
  assert.equal(store.leaseAuthorizes(runId, OTHER_ORIGIN, 'POST', '/api/items'), false, 'host lease MUST NOT cover other origin')

  // R3-H-1 / R2-H-1 RequestAdmissionEngine invariants: host lease NEVER bypasses method override,
  // compressed body, >64 KiB body, multipart upload, race burst, denylist, or out-of-scope!
  store.setRouteDenylist(store.run(runId), ['/api/forbidden'])
  const engine = new RequestAdmissionEngine()
  const grant = {
    tier: 3 as const,
    canRead: (o: string) => o === ORIGIN,
    scopePolicy: store.scopePolicy(runId),
    approvalPolicy: 'auto_review' as const,
    approvalLeases: store.approvalLeaseAuthorizer(runId),
    isStateChangeApproved: () => false,
  }

  // Benign POST on approved host IS allowed by host lease
  const benignDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"ok"}',
  }, grant)
  assert.equal(benignDecision.allowed, true)
  assert.equal(benignDecision.reasonCode, 'allowed_approval_lease')

  // Method override -> escalated (approval_required), never bypassed by host lease
  const overrideDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'application/json', 'X-HTTP-Method-Override': 'DELETE' },
    body: '{"name":"override"}',
  }, grant)
  assert.equal(overrideDecision.allowed, false)

  // Compressed body -> never bypassed by host lease
  const compressedDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' },
    body: 'compressed-bytes',
  }, grant)
  assert.equal(compressedDecision.allowed, false)

  // Oversized >64 KiB body -> never bypassed by host lease
  const oversizedDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'application/json' },
    body: 'a'.repeat(70_000),
  }, grant)
  assert.equal(oversizedDecision.allowed, false)

  // Multipart upload -> never bypassed by host lease
  const multipartDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'multipart/form-data; boundary=abc' },
    body: '--abc\r\nContent-Disposition: form-data; name="file"\r\n\r\nhi\r\n--abc--',
  }, grant)
  assert.equal(multipartDecision.allowed, false)

  // Race burst -> never bypassed by host lease
  const raceDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'application/json' },
    body: '{"race":1}',
    isRaceBurst: true,
  }, grant)
  assert.equal(raceDecision.allowed, false)

  // Denylisted route -> denied even with host lease
  const denylistDecision = engine.admit({
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/forbidden/step',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  }, grant)
  assert.equal(denylistDecision.allowed, false)

  // 1-click revoke immediately ends host lease authorization
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'revoke_approval_lease',
    leaseId: hostLease.id,
  }))
  assert.equal(store.runDetail(runId).approvalLeases.length, 0)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'POST', '/api/items'), false)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PUT', '/api/items/42'), false)
  assert.equal(store.leaseAuthorizes(runId, ORIGIN, 'PATCH', '/api/profile'), false)
})

// ---------------------------------------------------------------------------
// 3. Real Playwright E2E + DOM geometry QA (1280x720 & 1440x900)
// ---------------------------------------------------------------------------

const SYSTEM_CHROMIUM_CANDIDATES = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
]

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  let pw: PlaywrightModule | null = null
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') {
        pw = loaded as PlaywrightModule
        break
      }
    } catch { /* try next */ }
  }
  if (!pw) return null
  const bundled = (() => {
    try { return pw.chromium.executablePath() } catch { return '' }
  })()
  if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) return { pw, executablePath: candidate }
  }
  return null
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

function ensureBuilt(): void {
  const serverEntry = resolve('build/server/server.js')
  const clientDir = resolve('build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'pipe' })
}

async function startHardenedKovoServer(dataDir: string) {
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const child: ChildProcess = spawn(
    process.execPath,
    [
      '--disable-proto=delete',
      '--enable-experimental-regexp-engine-on-excessive-backtracks',
      '--regexp-backtracks-before-fallback=10000',
      'scripts/serve.ts',
    ],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        PORT: String(port),
        KOVO_DATA_DIR: dataDir,
        KOVO_ALLOW_LOCAL_LAB: '1',
        KOVO_ALLOW_LOCAL_MODEL: '1',
        KOVO_OFFLINE: '1',
        KOVO_PUBLIC_ORIGIN: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  child.stdout?.on('data', c => { output += String(c) })
  child.stderr?.on('data', c => { output += String(c) })

  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      const timedOut = await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])
      if (timedOut && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
  }

  let healthy = false
  for (let i = 0; i < 150; i += 1) {
    if (child.exitCode !== null) break
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })
      if (res.ok) { healthy = true; break }
    } catch { /* retry */ }
    await delay(70)
  }
  if (!healthy) {
    await stop()
    throw new Error(`Hardened scripts/serve.ts failed to start on ${origin}.\n${output}`)
  }

  let bootstrapSecret = ''
  for (let i = 0; i < 40 && !bootstrapSecret; i += 1) {
    try { bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
  }
  if (!bootstrapSecret) {
    await stop()
    throw new Error(`Bootstrap secret was not written in ${dataDir}.\n${output}`)
  }
  return { origin, bootstrapSecret, stop, getOutput: () => output }
}

async function assertActionBarGeometry(page: Page, viewportLabel: string) {
  const geom = await page.evaluate(() => {
    const vw = window.innerWidth
    const vh = window.innerHeight
    const bar = document.querySelector<HTMLElement>('[data-testid="approval-action-bar"]')
    const blast = document.querySelector<HTMLElement>('[data-testid="approval-blast-radius"]')
    if (!bar || !blast) return { ok: false, reason: 'Missing action bar or blast-radius preview' }

    const barRect = bar.getBoundingClientRect()
    const barOverflowX = bar.scrollWidth > bar.clientWidth + 1
    const blastOverflowX = blast.scrollWidth > blast.clientWidth + 2 && getComputedStyle(blast).textOverflow !== 'ellipsis'
    const buttons = [...bar.querySelectorAll<HTMLButtonElement>('button')].filter(b => b.offsetParent !== null)
    const rects = buttons.map(b => {
      const r = b.getBoundingClientRect()
      return {
        label: (b.textContent ?? '').trim(),
        testId: b.dataset.testid ?? '',
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
        width: r.width,
        height: r.height,
        clippedY: b.scrollHeight > b.clientHeight + 2,
        outOfViewport: r.bottom > vh + 1 || r.right > vw + 1 || r.left < -1 || r.top < -1,
      }
    })

    const overlaps: string[] = []
    for (let i = 0; i < rects.length; i += 1) {
      for (let j = i + 1; j < rects.length; j += 1) {
        const a = rects[i]!
        const b = rects[j]!
        const separated = a.right <= b.left + 1 || b.right <= a.left + 1 || a.bottom <= b.top + 1 || b.bottom <= a.top + 1
        if (!separated) overlaps.push(`${a.label} overlaps ${b.label}`)
      }
    }

    const rootOverflowX = document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
    return {
      ok: true,
      barRect: { top: barRect.top, bottom: barRect.bottom, left: barRect.left, right: barRect.right },
      barOverflowX,
      blastOverflowX,
      rootOverflowX,
      overlaps,
      rects,
    }
  })

  assert.equal(geom.ok, true, `${viewportLabel}: ${'reason' in geom ? geom.reason : 'geometry check failed'}`)
  if (!geom.ok) return
  assert.equal(geom.rootOverflowX, false, `${viewportLabel}: page must have zero horizontal overflow`)
  assert.equal(geom.barOverflowX, false, `${viewportLabel}: approval action bar must have zero horizontal overflow`)
  assert.deepEqual(geom.overlaps, [], `${viewportLabel}: sibling action buttons must not overlap`)
  assert.ok(geom.rects.length >= 5, `${viewportLabel}: expected scoped approval buttons to be visible`)
  for (const r of geom.rects) {
    assert.equal(r.outOfViewport, false, `${viewportLabel}: button "${r.label}" must be visible inside viewport above the fold`)
    assert.equal(r.clippedY, false, `${viewportLabel}: button "${r.label}" must not clip text vertically`)
  }
}

describe('Playwright E2E — Deduped Queue, Scoped Approvals, Blast-Radius Preview & Leases Popover', { timeout: 90_000 }, () => {
  let skipReason: string | null = null
  let dataDir = ''
  let runId = ''
  let dup1Id = ''
  let dup2Id = ''
  let server: Awaited<ReturnType<typeof startHardenedKovoServer>> | undefined
  let browser: Browser | undefined
  let context: BrowserContext | undefined
  let page: Page | undefined
  const pageErrors: string[] = []

  before(async () => {
    const pwEnv = await loadPlaywright()
    if (!pwEnv) {
      skipReason = 'Playwright or Chromium binary unavailable'
      return
    }
    ensureBuilt()
    dataDir = await mkdtemp(join(tmpdir(), 'kovo-e2e-approval-scopes-'))

    // Seed project, paused Tier-3 run, worker, and active prefix + host leases before server boot.
    let scopeRevision = 1
    let workerId = ''
    const seedStore = new Store(dataDir)
    try {
      const { runId: seededRunId, run, worker } = setupTier3Run(seedStore, [ORIGIN, OTHER_ORIGIN])
      runId = seededRunId
      scopeRevision = run.scopeRevision
      workerId = worker.id
      // Keep run paused so background workers do not mutate our deterministic approval fixtures.
      seedStore.updateRun(runId, { status: 'paused' })

      // Seed one 2-segment prefix lease + one host non-destructive lease so LeasesPopover displays both.
      seedStore.runsRepo.grantApprovalLease(seedStore.run(runId), {
        origin: ORIGIN,
        method: 'POST',
        pathAndQuery: '/api/v1/**',
        source: 'operator_explicit',
        leaseScope: 'prefix',
        createdBy: 'operator',
      })
      seedStore.runsRepo.grantApprovalLease(seedStore.run(runId), {
        origin: OTHER_ORIGIN,
        method: HOST_NONDESTRUCTIVE_LEASE_METHOD,
        pathAndQuery: HOST_NONDESTRUCTIVE_LEASE_PATTERN,
        leaseScope: 'host_nondestructive',
        createdBy: 'operator',
      })
    } finally {
      seedStore.close()
    }

    server = await startHardenedKovoServer(dataDir)

    // Insert pending approval cards AFTER server boot recovery so they stay live & pending in Queue.
    const now = Date.now()
    const expiresAt = now + 30 * 60_000
    dup1Id = randomUUID()
    dup2Id = randomUUID()
    const quizId = randomUUID()
    const deleteId = randomUUID()
    const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
    try {
      db.exec('PRAGMA busy_timeout = 5000;')
      const insert = db.prepare(`
        INSERT INTO approval_requests (
          id, run_id, assignment_id, scope_revision, origin, method, path_and_query,
          persona_handle, rationale, request_preview, status, decided_by, decided_at,
          policy_note, risk_level, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL, ?, ?, ?)
      `)
      insert.run(
        dup1Id, runId, workerId, scopeRevision, ORIGIN, 'POST', '/_actions/courses/redeemReferralAwardAction',
        'qa_member', 'Verify referral award action authorization boundary with benign control payload.',
        JSON.stringify({
          method: 'POST',
          origin: ORIGIN,
          pathAndQuery: '/_actions/courses/redeemReferralAwardAction',
          headers: { 'content-type': 'application/json' },
          bodyPreview: { referralCode: 'qa-canary-01' },
        }),
        'medium', expiresAt, now - 4_000,
      )
      insert.run(
        dup2Id, runId, workerId, scopeRevision, ORIGIN, 'POST', '/_actions/courses/redeemReferralAwardAction?variant=2',
        'qa_member', 'Verify referral award action idempotency with alternate benign control payload.',
        JSON.stringify({
          method: 'POST',
          origin: ORIGIN,
          pathAndQuery: '/_actions/courses/redeemReferralAwardAction?variant=2',
          headers: { 'content-type': 'application/json' },
          bodyPreview: { referralCode: 'qa-canary-02' },
        }),
        'medium', expiresAt, now - 3_000,
      )
      insert.run(
        quizId, runId, workerId, scopeRevision, ORIGIN, 'POST', '/_actions/courses/submitQuiz',
        'qa_member', 'Verify quiz submission endpoint access controls.',
        JSON.stringify({
          method: 'POST',
          origin: ORIGIN,
          pathAndQuery: '/_actions/courses/submitQuiz',
          headers: { 'content-type': 'application/json' },
          bodyPreview: { quizId: 'intro-1', answers: ['a'] },
        }),
        'low', expiresAt, now - 2_000,
      )
      insert.run(
        deleteId, runId, workerId, scopeRevision, ORIGIN, 'DELETE', '/api/items/42',
        'qa_member', 'Verify DELETE authorization on item 42.',
        JSON.stringify({
          method: 'DELETE',
          origin: ORIGIN,
          pathAndQuery: '/api/items/42',
        }),
        'high', expiresAt, now - 1_000,
      )
    } finally {
      db.close()
    }

    browser = await pwEnv.pw.chromium.launch({
      headless: true,
      executablePath: pwEnv.executablePath,
      args: ['--no-sandbox'],
    })
    context = await browser.newContext({ viewport: { width: 1280, height: 720 } })
    page = await context.newPage()
    page.on('pageerror', err => { pageErrors.push(err instanceof Error ? err.message : String(err)) })
  })

  after(async () => {
    if (context) await context.close().catch(() => {})
    if (browser) await browser.close().catch(() => {})
    if (server) await server.stop().catch(() => {})
    if (dataDir) await rm(dataDir, { recursive: true, force: true }).catch(() => {})
  })

  it('renders deduped ×2 badge, blast-radius preview, scoped actions with clean geometry at 1280×720 & 1440×900, and revocable leases', async t => {
    if (skipReason || !page || !server) {
      t.skip(skipReason ?? 'Playwright unavailable')
      return
    }

    // Authenticate via single-use bootstrap secret, then open Queue view for the seeded run.
    await page.goto(`${server.origin}/?bootstrap=${encodeURIComponent(server.bootstrapSecret)}`, {
      waitUntil: 'domcontentloaded',
    })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
    await page.goto(`${server.origin}/runs/${runId}?view=queue`, { waitUntil: 'domcontentloaded' })

    // Verify deduped ×2 badge on the duplicate POST /_actions/redeemReferralAwardAction row.
    const dedupeBadge = page.getByTestId('queue-dedupe-badge')
    try {
      await dedupeBadge.waitFor({ state: 'visible', timeout: 15_000 })
    } catch (err) {
      const bodyText = await page.evaluate(() => document.body.innerText.slice(0, 600)).catch(() => '')
      throw new Error(`queue-dedupe-badge not visible at ${page.url()} (pageErrors=${JSON.stringify(pageErrors)}): ${bodyText}\nserver:\n${server.getOutput().slice(-800)}`, { cause: err })
    }
    assert.equal((await dedupeBadge.textContent())?.trim(), '×2')

    // Verify blast-radius preview & scoped buttons on the selected medium-risk POST row.
    const blastRadius = page.getByTestId('approval-blast-radius')
    await blastRadius.waitFor({ state: 'visible', timeout: 10_000 })
    const defaultBlast = (await blastRadius.textContent()) ?? ''
    assert.match(defaultBlast, /Approve route: POST \/_actions\/courses\/redeemreferralawardaction/i)
    assert.match(defaultBlast, /also resolves 2 pending cards/i)

    await page.getByTestId('approval-btn-route').waitFor({ state: 'visible' })
    await page.getByTestId('approval-btn-once').waitFor({ state: 'visible' })
    await page.getByTestId('approval-btn-prefix').waitFor({ state: 'visible' })
    await page.getByTestId('approval-btn-host').waitFor({ state: 'visible' })
    await page.getByTestId('approval-btn-deny').waitFor({ state: 'visible' })
    assert.match((await page.getByTestId('approval-btn-prefix').textContent()) ?? '', /Prefix \(\/_actions\/courses\/\*\*\)/)

    // Geometry check + optional screenshot at 1280×720
    await assertActionBarGeometry(page, '1280x720')
    const shotDir = process.env.KOVO_APPROVAL_SCREENSHOT_DIR
    if (shotDir) {
      mkdirSync(shotDir, { recursive: true })
      await page.screenshot({ path: join(shotDir, 'queue-approvals-1280x720.png') })
    }

    // Geometry check + optional screenshot at 1440×900
    await page.setViewportSize({ width: 1440, height: 900 })
    await page.waitForTimeout(150)
    await assertActionBarGeometry(page, '1440x900')
    if (shotDir) {
      await page.screenshot({ path: join(shotDir, 'queue-approvals-1440x900.png') })
    }

    // Hovering scope buttons updates the 1-line blast-radius preview interactively.
    await page.getByTestId('approval-btn-once').hover()
    assert.match((await blastRadius.textContent()) ?? '', /Approve once:.*no lease/i)
    await page.getByTestId('approval-btn-prefix').hover()
    assert.match((await blastRadius.textContent()) ?? '', /Approve prefix: POST \/_actions\/courses\/\*\*.*3 pending cards/i)
    await page.getByTestId('approval-btn-host').hover()
    assert.match((await blastRadius.textContent()) ?? '', /Approve host: POST\/PUT\/PATCH on academy\.dyad\.sh/i)

    // Selecting the high-risk DELETE card switches primary CTA to "Approve once" and hides Prefix & Host!
    const deleteRow = page.locator('[data-id^="ap:"]', { hasText: 'DELETE' }).first()
    await deleteRow.click()
    assert.match((await page.getByTestId('approval-btn-once').textContent()) ?? '', /Approve once/i)
    assert.equal(await page.getByTestId('approval-btn-prefix').count(), 0, 'Prefix button must be hidden on DELETE/high-risk')
    assert.equal(await page.getByTestId('approval-btn-host').count(), 0, 'Host button must be hidden on DELETE/high-risk')
    assert.match((await blastRadius.textContent()) ?? '', /Approve once: DELETE \/api\/items\/\*/i)

    // Switch back to the deduped ×2 POST row and click "Approve route" -> resolves BOTH pending cards!
    const dupRow = page.locator('[data-id^="ap:"]', { hasText: 'redeemReferralAwardAction' }).first()
    await dupRow.click()
    await page.getByTestId('approval-btn-route').click()
    await page.waitForFunction(
      () => !document.querySelector('[data-testid="queue-dedupe-badge"]'),
      null,
      { timeout: 10_000 },
    )

    // Open header Approval leases popover and verify Prefix + HOST leases display & revoke in 1 click.
    await page.locator('button[data-rl-btn]', { hasText: 'Leases' }).click()
    const leasesList = page.getByTestId('approval-leases-list')
    await leasesList.waitFor({ state: 'visible', timeout: 10_000 })
    const hostLeaseItem = leasesList.locator('[data-lease-scope="host_nondestructive"]')
    const prefixLeaseItem = leasesList.locator('[data-lease-scope="prefix"]')
    await hostLeaseItem.waitFor({ state: 'visible' })
    await prefixLeaseItem.waitFor({ state: 'visible' })
    assert.match((await hostLeaseItem.textContent()) ?? '', /HOST.*docs\.dyad\.sh/i)
    assert.match((await prefixLeaseItem.textContent()) ?? '', /POST.*Prefix.*\/api\/v1\/\*\*/i)

    // 1-click revoke of host lease
    await hostLeaseItem.getByRole('button', { name: /Revoke/i }).click()
    await hostLeaseItem.waitFor({ state: 'detached', timeout: 10_000 })

    // Verify both duplicate approval rows settled as approved and host lease was revoked in SQLite.
    const verifyDb = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
    try {
      verifyDb.exec('PRAGMA busy_timeout = 5000;')
      const statusOf = (approvalId: string) =>
        (verifyDb.prepare('SELECT status FROM approval_requests WHERE id = ?').get(approvalId) as { status?: string } | undefined)?.status
      assert.equal(statusOf(dup1Id), 'approved')
      assert.equal(statusOf(dup2Id), 'approved')
      const activeHostLeases = (verifyDb.prepare(
        `SELECT count(*) AS c FROM approval_leases WHERE run_id = ? AND origin = ? AND method = ? AND status = 'active'`,
      ).get(runId, OTHER_ORIGIN, HOST_NONDESTRUCTIVE_LEASE_METHOD) as { c?: number } | undefined)?.c ?? 0
      assert.equal(activeHostLeases, 0, 'revoked host lease must no longer be active')
    } finally {
      verifyDb.close()
    }

    assert.deepEqual(pageErrors, [], 'Zero uncaught page errors expected')
  })
})
