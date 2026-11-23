import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { runCommand } from '../src/domain.ts'
import { BrokerApprovalRequired, RequestBroker } from '../src/server/broker.ts'
import type { Grant, Transport } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment } from '../src/server/store.ts'
import { setupApprovedRun, startHttpFixture } from './v4-tier-helpers.ts'

// ============================================================================
// Exec approvals — legitimate Tier-3 flows under the exact single-use ledger
//
// The ledger binds a grant to the exact request fingerprint (run, origin, method,
// path+query, persona, body hash, multipart/race/rce flags, scope revision) and is
// single-use per instance. These tests pin the two flows that broke after that
// hardening:
//   1. identical N-way race bursts (one single-use instance per request, never a
//      shared grant and never a fresh approval card after the first consume);
//   2. synchronized batches (one approval card for the whole batch, retry once the
//      per-instance grants exist, no per-item card spam).
// Exactness is preserved: a different body/persona/path and a replayed instance
// still escalate.
// ============================================================================

/** Transport that dials the loopback fixture while policy resolution reports a public IP. */
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

async function makeHarness(t: Parameters<typeof startHttpFixture>[0]) {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-exec-approvals-'))
  const storage = new Store(dir)
  // Local-lab project (so the broker may dial the loopback fixture). GUARDIAN_ALLOW_LOCAL_LAB
  // enables the broker's loopback transport but every test below uses the strict policy, which
  // disables local-lab auto-approval: the exact single-use ledger must authorize each request.
  const previousAllowLab = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

  const fixture = await startHttpFixture(t, (_req, _body, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end('{"ok":true}')
  })
  const broker = new RequestBroker({
    // The fixture is loopback; policy resolution reports a public address and the transport dials
    // the fixture directly (same shape as makeVirtualPublicBroker).
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: fixtureTransport(),
  })
  const execution = new Execution(storage, { broker })
  t.after(async () => {
    await execution.stop()
    storage.close()
    rmSync(dir, { recursive: true, force: true })
    if (previousAllowLab === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = previousAllowLab
  })
  const { runId } = await setupApprovedRun(storage, {
    seeds: [fixture.origin],
    tier: 3,
    environment: 'local-lab',
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const created = storage.makeWorker(
    run, 'investigation', undefined, 'Exec approvals', 'Verify exact Tier-3 approvals',
    { sourceOrigins: [fixture.origin] },
  )
  storage.updateWorker(created.id, { status: 'running' })
  const assignment = storage.worker(created.id) as Assignment
  const job = { assignment, origins: new Set([fixture.origin]), controller: new AbortController() }
  const priv = execution as unknown as Record<string, any>
  const { grant } = priv.buildGrant(job, storage.run(runId), new Set([fixture.origin])) as { grant: Grant }
  const approve = grant.isStateChangeApproved!
  const setPolicy = (approvalPolicy: 'yolo' | 'strict' | 'auto_review') => {
    storage.command(runCommand.parse({
      requestId: randomUUID(),
      runId,
      action: 'set_approval_policy',
      approvalPolicy,
    }))
  }
  const signal = () => AbortSignal.timeout(15_000)
  return { dir, storage, execution, priv, fixture, runId, job, grant, approve, broker, setPolicy, signal }
}

// ---------------------------------------------------------------------------
// 1. Identical race burst: one single-use instance per request
// ---------------------------------------------------------------------------

test('race burst: a 3x identical burst registers exactly 3 single-use instances', async t => {
  const h = await makeHarness(t)
  h.setPolicy('strict')

  const body = '{"amount":1}'
  const context = { personaHandle: null, body, hasMultipart: false, isRaceBurst: true, isRceProof: false }
  const requests = Array.from({ length: 3 }, () => ({
    origin: h.fixture.origin,
    method: 'POST' as const,
    pathAndQuery: '/api/redeem',
    headers: { 'Content-Type': 'application/json' },
    body,
  }))

  const plan = h.priv.planTier3Approval(h.storage.run(h.runId), requests, { isRaceBurst: true })
  assert.equal(plan.primary.approvalInstances, 3, 'identical burst requests share one fingerprint with 3 instances')
  assert.equal(plan.additional.length, 0)

  const pending = h.priv.waitForTier3Approval(h.job, {
    origin: plan.primary.origin,
    method: plan.primary.method,
    pathAndQuery: plan.primary.pathAndQuery,
    personaHandle: plan.primary.personaHandle,
    rationale: 'Identical 3x race burst regression probe',
    requestPreview: 'POST /api/redeem x3 (synchronized)',
    bodyPreview: plan.primary.bodyPreview,
    bodyHash: plan.primary.bodyHash,
    headers: plan.primary.headers,
    hasMultipart: plan.primary.hasMultipart,
    isRaceBurst: true,
    approvalInstances: plan.primary.approvalInstances,
    additionalApprovalTargets: plan.additional,
    secrets: [],
  }, h.signal())
  const card = await waitForPendingCard(h.storage, h.runId)
  h.storage.decideApproval(h.storage.run(h.runId), card.id, 'approved')
  assert.equal((await pending).approved, true)

  // Exactness is preserved: a different body or persona never inherits a burst instance.
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/redeem', {
    ...context, body: '{"amount":2}',
  }), false, 'different body must escalate')
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/redeem', {
    ...context, personaHandle: 'user_a',
  }), false, 'different persona must escalate')

  // Exactly three instances are authorized, one per request.
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/redeem', context), true)
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/redeem', context), true)
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/redeem', context), true)
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/redeem', context), false,
    'a 4th identical request has no grant left and must escalate')
  assert.equal(h.storage.listApprovalRequests(h.runId).length, 1, 'one decision covers the whole burst')
})

test('race burst: a legitimate 3x burst completes after one approval card (no re-approval loop)', async t => {
  const h = await makeHarness(t)
  h.setPolicy('strict')

  const body = '{"coupon":"SPRING"}'
  const requests = Array.from({ length: 3 }, () => ({
    origin: h.fixture.origin,
    method: 'POST' as const,
    pathAndQuery: '/api/redeem',
    headers: { 'Content-Type': 'application/json' },
    body,
    runId: h.runId,
    assignmentId: h.job.assignment.id,
    scopeRevision: h.storage.run(h.runId).scopeRevision,
  }))

  const pending = h.priv.executeApprovedRaceBurst(h.job, requests, h.grant, h.signal(), {
    stepTitle: 'race burst regression',
    secrets: [],
  })
  const card = await waitForPendingCard(h.storage, h.runId)
  await delay(150)
  assert.equal(h.storage.listApprovalRequests(h.runId, 'pending').length, 1, 'the burst raises exactly one card')
  h.storage.decideApproval(h.storage.run(h.runId), card.id, 'approved')

  const burst = await pending
  assert.equal(burst.summary.total, 3)
  assert.equal(h.fixture.requests.length, 3, 'every burst instance reached the target exactly once')
  assert.equal(h.storage.listApprovalRequests(h.runId).length, 1, 'the retry must not raise a second card')

  // All three instances were consumed by the burst; a further identical burst escalates.
  await assert.rejects(
    h.broker.executeRaceBurst(requests.slice(0, 2), h.grant, h.signal()),
    BrokerApprovalRequired,
    'a 4th request without a grant must fail',
  )
})

// ---------------------------------------------------------------------------
// 2. Synchronized batch: one card, retry every authorized item
// ---------------------------------------------------------------------------

test('batch: one approval card covers two approved items and the batch succeeds', async t => {
  const h = await makeHarness(t)
  h.setPolicy('strict')

  const scopeRevision = h.storage.run(h.runId).scopeRevision
  const requests = [
    {
      origin: h.fixture.origin, method: 'POST' as const, pathAndQuery: '/api/items/1',
      headers: { 'Content-Type': 'application/json' }, body: '{"value":1}',
      runId: h.runId, assignmentId: h.job.assignment.id, scopeRevision,
    },
    {
      origin: h.fixture.origin, method: 'POST' as const, pathAndQuery: '/api/items/2',
      headers: { 'Content-Type': 'application/json' }, body: '{"value":2}',
      runId: h.runId, assignmentId: h.job.assignment.id, scopeRevision,
    },
  ]

  const pending = h.priv.executeApprovedBatch(h.job, requests, h.grant, h.signal(), {
    stepTitle: 'batch regression',
    secrets: [],
  })
  const card = await waitForPendingCard(h.storage, h.runId)
  // No per-item spam: the batch raises exactly one card with per-item previews.
  await delay(150)
  assert.equal(h.storage.listApprovalRequests(h.runId, 'pending').length, 1)
  assert.match(card.requestPreview, /\/api\/items\/1/)
  assert.match(card.requestPreview, /\/api\/items\/2/)
  h.storage.decideApproval(h.storage.run(h.runId), card.id, 'approved')

  const results = await pending
  assert.equal(results.length, 2)
  assert.deepEqual(
    h.fixture.requests.map(request => request.url).sort(),
    ['/api/items/1', '/api/items/2'],
    'each authorized batch item is sent exactly once',
  )
  assert.equal(h.storage.listApprovalRequests(h.runId).length, 1, 'one card for the whole batch')

  // Replaying a consumed instance fails closed.
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/items/1', {
    personaHandle: null, body: '{"value":1}', hasMultipart: false,
  }), false, 'a replayed batch instance must escalate')
})

test('batch: an item whose grant was already consumed still succeeds on the batch retry', async t => {
  const h = await makeHarness(t)
  h.setPolicy('strict')

  const scopeRevision = h.storage.run(h.runId).scopeRevision
  const requests = [
    {
      origin: h.fixture.origin, method: 'POST' as const, pathAndQuery: '/api/orders/1',
      headers: { 'Content-Type': 'application/json' }, body: '{"state":"open"}',
      runId: h.runId, assignmentId: h.job.assignment.id, scopeRevision,
    },
    {
      origin: h.fixture.origin, method: 'POST' as const, pathAndQuery: '/api/orders/2',
      headers: { 'Content-Type': 'application/json' }, body: '{"state":"open"}',
      runId: h.runId, assignmentId: h.job.assignment.id, scopeRevision,
    },
  ]

  // Authorize only the first item beforehand, then consume its grant exactly as a rejected batch
  // attempt would. The batch decision must register a fresh instance for it so the retry does not
  // fail closed on the already-consumed grant.
  const firstPlan = h.priv.planTier3Approval(h.storage.run(h.runId), requests.slice(0, 1))
  const preDecisionPromise = h.priv.waitForTier3Approval(h.job, {
    origin: firstPlan.primary.origin,
    method: firstPlan.primary.method,
    pathAndQuery: firstPlan.primary.pathAndQuery,
    personaHandle: firstPlan.primary.personaHandle,
    rationale: 'Pre-authorize only the first batch item',
    requestPreview: 'POST /api/orders/1',
    bodyPreview: firstPlan.primary.bodyPreview,
    bodyHash: firstPlan.primary.bodyHash,
    headers: firstPlan.primary.headers,
    hasMultipart: firstPlan.primary.hasMultipart,
    secrets: [],
  }, h.signal())
  const preCard = await waitForPendingCard(h.storage, h.runId)
  h.storage.decideApproval(h.storage.run(h.runId), preCard.id, 'approved')
  assert.equal((await preDecisionPromise).approved, true)
  assert.equal(h.approve(h.fixture.origin, 'POST', '/api/orders/1', {
    personaHandle: null, body: '{"state":"open"}', hasMultipart: false,
  }), true, 'the pre-authorized grant is consumed by the first attempt')
  assert.equal(h.fixture.requests.length, 0, 'a rejected batch attempt must not send bytes')

  const pending = h.priv.executeApprovedBatch(h.job, requests, h.grant, h.signal(), {
    stepTitle: 'partial batch regression',
    secrets: [],
  })
  const batchCard = await waitForPendingCard(h.storage, h.runId)
  h.storage.decideApproval(h.storage.run(h.runId), batchCard.id, 'approved')
  const results = await pending
  assert.equal(results.length, 2)
  assert.deepEqual(
    h.fixture.requests.map(request => request.url).sort(),
    ['/api/orders/1', '/api/orders/2'],
  )
})
