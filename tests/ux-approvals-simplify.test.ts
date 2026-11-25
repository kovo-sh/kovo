import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { runCommand } from '../src/domain.ts'
import {
  authorizeStateChange,
  evaluateTier3Approval,
  MAX_KEYWORD_SCAN_CHARS,
} from '../src/server/approval-judge.ts'
import { BrokerApprovalRequired, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { Store } from '../src/server/store.ts'

const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDRESS = { address: '93.184.216.34', family: 4 }

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-approvals-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function makeBroker(calls: Array<{ method: string; url: string }>): RequestBroker {
  return new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string }) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
}

function createPublicRun(
  storage: Store,
  opts: {
    tier: 0 | 1 | 2 | 3
    approvalPolicy?: 'auto_review' | 'yolo' | 'strict'
    sandboxWriteAllowlist?: Array<{ origin: string; method: string; pathPattern: string }>
  },
) {
  const project = storage.createProject({
    requestId: randomUUID(),
    name: `UX Approvals ${randomUUID().slice(0, 6)}`,
    seeds: [APP_ORIGIN],
    environment: 'public',
    ...(opts.sandboxWriteAllowlist ? { sandboxWriteAllowlist: opts.sandboxWriteAllowlist } : {}),
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify simplified Tier + Approval Policy behavior',
    sourceMode: opts.tier === 0 ? 'prepared' : 'public',
    capabilityTier: opts.tier,
    ...(opts.approvalPolicy ? { approvalPolicy: opts.approvalPolicy } : {}),
  } as Parameters<Store['createRun']>[0])
  return { projectId: project.id, runId }
}

function approveScopeForRun(
  storage: Store,
  runId: string,
  overrides: { capabilityTier?: 0 | 1 | 2 | 3; approvalPolicy?: 'auto_review' | 'yolo' | 'strict' } = {},
) {
  storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = storage.run(runId)
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    ...overrides,
  }))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  return storage.run(runId)
}

function buildExecutionGrant(execution: Execution, storage: Store, runId: string): Grant {
  const run = storage.run(runId)
  const created = storage.makeWorker(run, 'investigation', run.candidates[0], 'Approvals worker', 'Verify broker gate', {
    sourceOrigins: [APP_ORIGIN],
  })
  const assignment = storage.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
  const job = { assignment, origins: new Set([APP_ORIGIN]), controller: new AbortController() }
  const priv = execution as unknown as Record<string, any>
  return (priv.buildGrant(job, run, new Set([APP_ORIGIN])) as { grant: Grant }).grant
}

// ---------------------------------------------------------------------------
// 1. Default environmentMode derivation & explicit lock preservation
// ---------------------------------------------------------------------------

test('Tier 0/1/2 public runs remain prod_readonly and refuse writes', async t => {
  const storage = makeStorage(t)
  for (const tier of [0, 1, 2] as const) {
    const { runId } = createPublicRun(storage, { tier })
    assert.equal(storage.run(runId).environmentMode, 'prod_readonly', `Tier ${tier} public run must default to prod_readonly`)
    assert.equal(storage.scopePolicy(runId).mode, 'prod_readonly')
  }

  // Tier 2 public run still blocks state-changing POST with BrokerDenied
  const { runId } = createPublicRun(storage, { tier: 2 })
  approveScopeForRun(storage, runId)
  const calls: Array<{ method: string; url: string }> = []
  const execution = new Execution(storage, { broker: makeBroker(calls) })
  t.after(() => execution.stop())
  const grant = buildExecutionGrant(execution, storage, runId)

  await assert.rejects(
    execution.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"blocked"}',
    }, grant, AbortSignal.timeout(5_000)),
    (err: unknown) => err instanceof BrokerDenied && /prod_readonly/.test(err.message),
  )
  assert.equal(calls.length, 0)
})

test('Tier 3 (createRun, setScope upgrade, or setApprovalPolicy yolo) derives staging_isolated unless explicitly locked', t => {
  const storage = makeStorage(t)

  // A. createRun with Tier 3 -> staging_isolated
  const t3 = createPublicRun(storage, { tier: 3, approvalPolicy: 'auto_review' })
  assert.equal(storage.run(t3.runId).environmentMode, 'staging_isolated')
  assert.equal(storage.scopePolicy(t3.runId).mode, 'staging_isolated')

  // B. createRun with Tier 1 -> prod_readonly; upgrading via setScope to Tier 3 -> staging_isolated
  const upgraded = createPublicRun(storage, { tier: 1 })
  assert.equal(storage.run(upgraded.runId).environmentMode, 'prod_readonly')
  approveScopeForRun(storage, upgraded.runId, { capabilityTier: 3, approvalPolicy: 'auto_review' })
  assert.equal(storage.run(upgraded.runId).environmentMode, 'staging_isolated')

  // C. Switching approvalPolicy to yolo unlocks staging_isolated
  const switched = createPublicRun(storage, { tier: 2 })
  assert.equal(storage.run(switched.runId).environmentMode, 'prod_readonly')
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId: switched.runId,
    action: 'set_approval_policy',
    approvalPolicy: 'yolo',
  }))
  assert.equal(storage.run(switched.runId).environmentMode, 'staging_isolated')

  // D. Explicit setEnvironmentMode(run, 'prod_readonly') lock is NEVER overridden by setScope or yolo switch
  const locked = createPublicRun(storage, { tier: 1 })
  storage.setEnvironmentMode(storage.run(locked.runId), 'prod_readonly')
  approveScopeForRun(storage, locked.runId, { capabilityTier: 3, approvalPolicy: 'yolo' })
  assert.equal(storage.run(locked.runId).environmentMode, 'prod_readonly', 'explicit prod_readonly lock survives setScope')
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId: locked.runId,
    action: 'set_approval_policy',
    approvalPolicy: 'yolo',
  }))
  assert.equal(storage.run(locked.runId).environmentMode, 'prod_readonly', 'explicit prod_readonly lock survives setApprovalPolicy(yolo)')
})

// ---------------------------------------------------------------------------
// 2. Broker enforcement: Tier 3 + approvalPolicy flows cleanly without silent prod_readonly blocks
// ---------------------------------------------------------------------------

test('Tier 3 + yolo (Autonomous) runs proceed without silent prod_readonly or untagged-staging blocks, while keeping hard boundaries', async t => {
  const storage = makeStorage(t)
  const { runId } = createPublicRun(storage, { tier: 3, approvalPolicy: 'yolo' })
  approveScopeForRun(storage, runId)
  storage.setRouteDenylist(storage.run(runId), ['/billing/charge'])

  const calls: Array<{ method: string; url: string }> = []
  const execution = new Execution(storage, { broker: makeBroker(calls) })
  t.after(() => execution.stop())
  const grant = buildExecutionGrant(execution, storage, runId)

  // Untagged POST succeeds cleanly in Tier 3 + yolo
  const postRes = await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/items',
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"probe"}',
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(postRes.status, 200)

  // DELETE also succeeds cleanly in Tier 3 + yolo
  const delRes = await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/42',
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(delRes.status, 200)
  assert.equal(calls.length, 2)

  // Hard scope boundaries (routeDenylist & out-of-scope) STILL block with BrokerDenied
  await assert.rejects(
    execution.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/billing/charge',
      headers: { 'Content-Type': 'application/json' },
      body: '{"amount":1}',
    }, grant, AbortSignal.timeout(5_000)),
    (err: unknown) => err instanceof BrokerDenied && /denylist/.test(err.message),
  )
  assert.equal(calls.length, 2)
})

test('Tier 3 + strict asks every write, and Tier 3 + auto_review escalates unapproved DELETE/multipart', async t => {
  const storage = makeStorage(t)

  // Strict: even a run-tagged POST raises BrokerApprovalRequired (never silent BrokerDenied)
  const strictRun = createPublicRun(storage, { tier: 3, approvalPolicy: 'strict' })
  approveScopeForRun(storage, strictRun.runId)
  const strictTag = storage.scopePolicy(strictRun.runId).tenantTag!
  const strictCalls: Array<{ method: string; url: string }> = []
  const strictExec = new Execution(storage, { broker: makeBroker(strictCalls) })
  t.after(() => strictExec.stop())
  const strictGrant = buildExecutionGrant(strictExec, storage, strictRun.runId)

  await assert.rejects(
    strictExec.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: `/api/items?tenant=${strictTag}1`,
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"x"}',
    }, strictGrant, AbortSignal.timeout(5_000)),
    BrokerApprovalRequired,
    'strict policy must prompt on every write',
  )
  assert.equal(strictCalls.length, 0)

  // Auto-Review: tagged non-structural POST auto-approves; DELETE escalates via BrokerApprovalRequired
  const autoRun = createPublicRun(storage, { tier: 3, approvalPolicy: 'auto_review' })
  approveScopeForRun(storage, autoRun.runId)
  const autoTag = storage.scopePolicy(autoRun.runId).tenantTag!
  const autoCalls: Array<{ method: string; url: string }> = []
  const autoExec = new Execution(storage, { broker: makeBroker(autoCalls) })
  t.after(() => autoExec.stop())
  const autoGrant = buildExecutionGrant(autoExec, storage, autoRun.runId)

  const safePost = await autoExec.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: `/api/items?tenant=${autoTag}1`,
    headers: { 'Content-Type': 'application/json' },
    body: '{"name":"safe"}',
  }, autoGrant, AbortSignal.timeout(5_000))
  assert.equal(safePost.status, 200)
  assert.equal(autoCalls.length, 1)

  await assert.rejects(
    autoExec.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'DELETE',
      pathAndQuery: `/api/items/42?tenant=${autoTag}1`,
    }, autoGrant, AbortSignal.timeout(5_000)),
    BrokerApprovalRequired,
    'unapproved DELETE must still escalate in auto_review',
  )
  assert.equal(autoCalls.length, 1)
})

// ---------------------------------------------------------------------------
// 3. "Approve similar" suppresses repeat DELETE/multipart prompts while keeping isRceProof hard-escalated
// ---------------------------------------------------------------------------

test('Approve similar suppresses repeat prompts on approved DELETE and multipart routes while isRceProof ALWAYS escalates', async () => {
  const deletePattern = [{ origin: APP_ORIGIN, method: 'DELETE', pathPattern: '/api/items/*' }]
  const uploadPattern = [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/api/uploads/*' }]

  // Unapproved DELETE and multipart still escalate in Stage 1A
  const unapprovedDel = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/42',
    offline: true,
  })
  assert.equal(unapprovedDel.decision, 'escalate_human')
  assert.equal(unapprovedDel.stage, 'hard_escalation')

  const unapprovedUpload = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/uploads/10',
    hasMultipart: true,
    offline: true,
  })
  assert.equal(unapprovedUpload.decision, 'escalate_human')
  assert.equal(unapprovedUpload.stage, 'hard_escalation')

  // Approved DELETE pattern suppresses repeat prompts on sibling IDs (both evaluateTier3Approval & authorizeStateChange)
  const approvedDel = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/999',
    approvedPatterns: deletePattern,
    offline: true,
  })
  assert.equal(approvedDel.decision, 'approve')
  assert.equal(approvedDel.stage, 'approved_pattern')

  const authDel = authorizeStateChange({
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/999',
    context: { personaHandle: 'user_a', hasMultipart: false, isRceProof: false },
    approvedPatterns: deletePattern,
  })
  assert.equal(authDel.approved, true)
  assert.equal(authDel.via, 'operator_pattern')

  // Approved multipart route suppresses repeat prompts on well-formed multipart uploads on that route
  const approvedUpload = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/uploads/20',
    hasMultipart: true,
    headers: { 'Content-Type': 'multipart/form-data; boundary=testbound' },
    approvedPatterns: uploadPattern,
    offline: true,
  })
  assert.equal(approvedUpload.decision, 'approve')
  assert.equal(approvedUpload.stage, 'approved_pattern')

  const authUpload = authorizeStateChange({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/uploads/20',
    context: { personaHandle: 'user_a', hasMultipart: true, isRceProof: false },
    approvedPatterns: uploadPattern,
  })
  assert.equal(authUpload.approved, true)
  assert.equal(authUpload.via, 'operator_pattern')

  // NON-NEGOTIABLE INVARIANT: isRceProof ALWAYS escalates to human even with an exact matching pattern!
  const rceWithPattern = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/999',
    isRceProof: true,
    approvedPatterns: deletePattern,
    offline: true,
  })
  assert.equal(rceWithPattern.decision, 'escalate_human')
  assert.equal(rceWithPattern.stage, 'hard_escalation')

  const authRce = authorizeStateChange({
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/999',
    context: { personaHandle: 'user_a', isRceProof: true },
    approvedPatterns: deletePattern,
  })
  assert.equal(authRce.approved, false)

  // Non-overridable structural invariants (malformed multipart, compressed, oversized >64KiB, race burst) still escalate!
  const malformedUpload = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/uploads/20',
    headers: { 'Content-Type': 'multipart/form-data' },
    approvedPatterns: uploadPattern,
    offline: true,
  })
  assert.equal(malformedUpload.decision, 'escalate_human')
  assert.equal(malformedUpload.stage, 'hard_escalation')

  const compressed = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/uploads/20',
    hasCompressedBody: true,
    approvedPatterns: uploadPattern,
    offline: true,
  })
  assert.equal(compressed.decision, 'escalate_human')
  assert.equal(compressed.stage, 'hard_escalation')

  const oversized = await evaluateTier3Approval({
    policy: 'auto_review',
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/uploads/20',
    bodyPreview: 'a'.repeat(MAX_KEYWORD_SCAN_CHARS + 1),
    approvedPatterns: uploadPattern,
    offline: true,
  })
  assert.equal(oversized.decision, 'escalate_human')
  assert.equal(oversized.stage, 'hard_escalation')
})

test('approveSimilarEndpoint creates consistent approved pattern + durable lease matching trailing-slash & ID variants', async t => {
  const storage = makeStorage(t)
  const { runId } = createPublicRun(storage, { tier: 3, approvalPolicy: 'auto_review' })
  const run = approveScopeForRun(storage, runId)
  const worker = storage.makeWorker(run, 'investigation', run.candidates[0], 'Delete probe', 'Test approve similar')
  const card = storage.createApprovalRequest(run, worker, {
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/12345?dryRun=1',
    rationale: 'Verify DELETE authorization',
    requestPreview: 'DELETE /api/items/12345',
    riskLevel: 'high',
  })

  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'approve_similar_endpoint',
    approvalId: card.id,
  }))

  // Durable lease matches numeric IDs, UUIDs, Mongo IDs, query variants, and trailing slashes
  assert.equal(storage.leaseAuthorizes(runId, APP_ORIGIN, 'DELETE', '/api/items/67890'), true)
  assert.equal(storage.leaseAuthorizes(runId, APP_ORIGIN, 'DELETE', '/api/items/67890/'), true)
  assert.equal(storage.leaseAuthorizes(runId, APP_ORIGIN, 'DELETE', '/api/items/507f1f77bcf86cd799439011?v=2'), true)
  // Different method or sibling literal verb never matches
  assert.equal(storage.leaseAuthorizes(runId, APP_ORIGIN, 'POST', '/api/items/67890'), false)
  assert.equal(storage.leaseAuthorizes(runId, APP_ORIGIN, 'DELETE', '/api/items/purge'), false)

  // End-to-end through broker: subsequent DELETE variants execute with zero new prompts
  const calls: Array<{ method: string; url: string }> = []
  const execution = new Execution(storage, { broker: makeBroker(calls) })
  t.after(() => execution.stop())
  const grant = buildExecutionGrant(execution, storage, runId)

  const res = await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'DELETE',
    pathAndQuery: '/api/items/67890/',
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(res.status, 200)
  assert.equal(calls.length, 1)
})
