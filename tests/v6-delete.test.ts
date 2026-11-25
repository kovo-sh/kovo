/**
 * v6 Phase-4 deletion stream: the two reviewer-approved v5 gates are gone.
 *
 *  - per-request keyword escalation storms and synchronous approval coroutines;
 *  - the K=6 consecutive-dry-step global kill.
 *
 * Pins the replacements:
 *  - `prod_readonly` / `staging_isolated` environment contracts decide mutations with zero
 *    approval popups and zero blocking waits;
 *  - an operator opt-in (`strict`) parks the worker, releases the slot, and resumes on a durable
 *    route-scoped lease while the exact single-use ledger stays authoritative;
 *  - a dry streak is telemetry, never a halt; termination is budget/round completion;
 *  - the report waits for late async OOB callbacks with a bounded drain (fake clock);
 *  - per-worker composite session clones keep a floor logout from poisoning an agentic worker.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'

import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  Execution,
  OOB_DRAIN_POLL_MS,
  resolveOobDrainMs,
  selectRankedProbeTargets,
} from '../src/server/execution.ts'
import type { CodeToRuntimeHypothesis } from '../src/server/program-graph.ts'
import {
  buildPersonaHeader,
  createProjectPersona,
  resolveRunPersonas,
  writePersonaSessionFile,
} from '../src/server/persona-vault.ts'
import type { MintedPersonaSession } from '../src/server/persona-vault.ts'
import { tenantTagForRun } from '../src/server/scope-policy.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

const appOrigin = 'https://app.example.test'
const publicAddress = { address: '93.184.216.34', family: 4 }

type RecordedCall = { method: string; url: string; headers: Record<string, string> }

function internals(execution: Execution): Record<string, any> {
  return execution as unknown as Record<string, any>
}

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-delete-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

/** A live investigation run whose candidate/profile setup is already approved. */
async function activeRun(storage: Store, seeds: string[] = [appOrigin]) {
  const { runId, run } = await setupApprovedRun(storage, { seeds, tier: 3, environment: 'public' })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { runId, run: storage.run(runId) }
}

function recordingBroker(calls: RecordedCall[]): RequestBroker {
  return new RequestBroker({
    resolve: async () => [publicAddress],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string; headers?: Record<string, string> }) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href, headers: options?.headers ?? {} })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{}' }
    },
  })
}

async function runningJob(storage: Store, run: ReturnType<Store['run']>, title = 'v6 delete worker') {
  const created = storage.makeWorker(run, 'investigation', run.candidates[0], title, 'exercise the v6 gate', {
    sourceOrigins: [appOrigin],
  })
  const assignment = storage.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
  return { assignment, job: { assignment, origins: new Set([appOrigin]), controller: new AbortController() } }
}

// ---------------------------------------------------------------------------
// 1. Environment contracts: zero mutations, zero popups, zero blocking waits
// ---------------------------------------------------------------------------

test('v6 delete: prod_readonly sends zero mutating requests and opens zero approval popups', async t => {
  const storage = makeStorage(t)
  const calls: RecordedCall[] = []
  const { runId, run: initial } = await activeRun(storage)
  storage.setEnvironmentMode(initial, 'prod_readonly')
  const run = storage.run(runId)
  const execution = new Execution(storage, { broker: recordingBroker(calls) })
  t.after(() => execution.stop())

  const { job } = await runningJob(storage, run)
  const { grant } = internals(execution).buildGrant(job, run, new Set([appOrigin])) as { grant: Grant }

  let approvalsConsulted = 0
  const original = grant.isStateChangeApproved!.bind(grant)
  grant.isStateChangeApproved = (...args: Parameters<NonNullable<Grant['isStateChangeApproved']>>) => {
    approvalsConsulted += 1
    return original(...args)
  }
  let blockingWaits = 0
  internals(execution).waitForTier3Approval = async () => {
    blockingWaits += 1
    return { approved: true }
  }

  await assert.rejects(
    execution.broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"x"}',
    }, grant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /prod_readonly/.test(error.message),
  )
  assert.equal(calls.length, 0, 'a prod_readonly mutation must never reach the wire')
  assert.equal(approvalsConsulted, 0, 'the contract decides, not the approval ledger')
  assert.equal(blockingWaits, 0, 'no blocking approval coroutine may be started')
  assert.equal(storage.listApprovalRequests(runId).length, 0, 'zero approval popups')
  assert.equal(storage.parkedWorkerCount(runId), 0, 'zero parked workers')

  // Reads remain allowed through the same grant.
  const read = await execution.broker.executeHttp({ origin: appOrigin, method: 'GET', pathAndQuery: '/api/items' }, grant, AbortSignal.timeout(5_000))
  assert.equal(read.status, 200)
  assert.equal(calls.length, 1)
})

test('v6 delete: staging_isolated mutations run with zero blocking waits and zero popups', async t => {
  const storage = makeStorage(t)
  const calls: RecordedCall[] = []
  const { runId, run: initial } = await activeRun(storage)
  storage.setEnvironmentMode(initial, 'staging_isolated')
  const run = storage.run(runId)
  const tag = tenantTagForRun(runId)
  assert.equal(tag, storage.scopePolicy(run).tenantTag)

  const execution = new Execution(storage, { broker: recordingBroker(calls) })
  t.after(() => execution.stop())
  const { job } = await runningJob(storage, run)
  const { grant } = internals(execution).buildGrant(job, run, new Set([appOrigin])) as { grant: Grant }

  let blockingWaits = 0
  internals(execution).waitForTier3Approval = async () => {
    blockingWaits += 1
    return { approved: true }
  }

  const result = await execution.broker.executeHttp({
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: `/api/items?tenant=${tag}abc`,
    headers: { 'Content-Type': 'application/json' },
    body: `{"tenant":"${tag}abc"}`,
  }, grant, AbortSignal.timeout(5_000))
  assert.equal(result.status, 200)
  assert.equal(calls.length, 1, 'the run-tagged staging mutation is authorized by the contract')

  await assert.rejects(
    execution.broker.executeHttp({
      origin: appOrigin,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"untagged"}',
    }, grant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /staging_isolated/.test(error.message),
  )
  assert.equal(calls.length, 1, 'an untagged staging mutation never reaches the wire')
  assert.equal(blockingWaits, 0)
  assert.equal(storage.listApprovalRequests(runId).length, 0)
  assert.equal(internals(execution).pendingTier3ApprovalKeys.size, 0)
})

// ---------------------------------------------------------------------------
// 2. Operator opt-in HITL: park, release the slot, resume on the durable lease
// ---------------------------------------------------------------------------

test('v6 delete: opt-in HITL parks, releases the slot, and resumes on a durable lease', async t => {
  const storage = makeStorage(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  storage.command({ requestId: randomUUID(), runId, action: 'set_approval_policy', approvalPolicy: 'strict' })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const run = storage.run(runId)
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const { job } = await runningJob(storage, run)
  internals(execution).active.set(job.assignment.id, job)
  const { grant } = internals(execution).buildGrant(job, run, new Set([appOrigin])) as { grant: Grant }

  const body = '{"title":"probe"}'
  const context = { personaHandle: null, body, hasMultipart: false }
  const pending = internals(execution).waitForTier3Approval(job, {
    origin: appOrigin,
    method: 'POST',
    pathAndQuery: '/api/notes/7',
    rationale: 'Operator opt-in route HITL',
    requestPreview: `POST ${appOrigin}/api/notes/7`,
    bodyPreview: body,
    headers: { 'Content-Type': 'application/json' },
    secrets: [],
  }, AbortSignal.timeout(10_000))

  let cardId: string | undefined
  for (let attempt = 0; attempt < 100 && !cardId; attempt += 1) {
    cardId = storage.listApprovalRequests(runId, 'pending')[0]?.id
    if (!cardId) await delay(20)
  }
  assert.ok(cardId, 'the opt-in route raises exactly one operator card')
  // The slot is released while the coroutine is suspended; other work can be scheduled.
  assert.equal(storage.worker(job.assignment.id).status, 'waiting_approval')
  assert.equal(storage.worker(job.assignment.id).lease, null)
  assert.equal(internals(execution).active.has(job.assignment.id), false, 'the worker slot is released')
  assert.equal(storage.parkedWorkerCount(runId), 1)

  storage.decideApproval(storage.run(runId), cardId, 'approved')
  const decision = await pending
  assert.equal(decision.approved, true)
  assert.equal(storage.worker(job.assignment.id).status, 'running', 'the parked worker resumes on approval')
  assert.ok(storage.worker(job.assignment.id).lease, 'the resumed worker gets a fresh lease')

  // The durable route-scoped lease authorizes sibling ids; the exact ledger stays single-use.
  assert.equal(storage.leaseAuthorizes(runId, appOrigin, 'POST', '/api/notes/8'), true)
  assert.equal(grant.isStateChangeApproved!(appOrigin, 'POST', '/api/notes/7', context), true)
  assert.equal(grant.isStateChangeApproved!(appOrigin, 'POST', '/api/notes/7', context), false)
  assert.equal(storage.listApprovalRequests(runId).length, 1, 'one decision, no re-approval storm')
})

// ---------------------------------------------------------------------------
// 3. The K=6 global kill is gone
// ---------------------------------------------------------------------------

async function addCompleteSteps(storage: Store, run: ReturnType<Store['run']>, count: number) {
  const steps = []
  for (let i = 0; i < count; i += 1) {
    const step = storage.addChainStep(run, {
      title: `Dry step ${i}`,
      hypothesis: 'no new fact',
      category: 'misconfig-exposure',
      priority: 50,
      targetAssetIds: run.candidates.map(c => c.id),
    })
    storage.updateChainStep(step.id, { status: 'complete' })
    steps.push(step)
  }
  return steps
}

test('v6 delete: a dry streak never kills the sweep while leads remain', async t => {
  const storage = makeStorage(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const current = storage.run(runId)
  await addCompleteSteps(storage, current, 6)
  const lead = storage.addChainStep(current, {
    title: 'Crown-jewel authz lead',
    hypothesis: 'differential authorization on the lead route',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: current.candidates.map(c => c.id),
  })

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  internals(execution).startInvestigationStep = () => undefined
  internals(execution).schedulePlanner = () => undefined
  internals(execution).driveInvestigation(storage.run(runId), [{ id: 'profile', model: 'mock' }])

  assert.equal(storage.run(runId).phase, 'investigation', 'the lead keeps the sweep alive')
  assert.ok(storage.listChainSteps(runId).some(s => s.id === lead.id), 'the lead step is still queued')
  const kinds = storage.eventsAfter(runId, 0).map(e => e.kind)
  assert.ok(!kinds.includes('planner.diminishing_returns'), 'the retired kill event must not fire')
})

test('v6 delete: the run still completes on coordinator round completion', async t => {
  const storage = makeStorage(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const current = storage.run(runId)
  await addCompleteSteps(storage, current, 6)

  const execution = new Execution(storage)
  t.after(() => execution.stop())
  internals(execution).startInvestigationStep = () => undefined
  internals(execution).schedulePlanner = () => undefined
  // Coordinator declared completion for this round: no work left -> finalize even after a dry streak.
  internals(execution).plannerDoneRound.set(runId, current.roundNo)
  internals(execution).driveInvestigation(current, [{ id: 'profile', model: 'mock' }])

  assert.ok(['verification', 'complete'].includes(storage.run(runId).phase), 'round completion still ends the phase')
  const kinds = storage.eventsAfter(runId, 0).map(e => e.kind)
  assert.ok(kinds.includes('planner.dry_streak'), 'the dry streak is recorded as telemetry only')
})

// ---------------------------------------------------------------------------
// 4. pending_oob drain before the report
// ---------------------------------------------------------------------------

test('v6 delete: late OOB callbacks are promoted by a bounded drain and recorded in meta', async t => {
  const storage = makeStorage(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const token = 'gn2o_' + 'abcdef12'
  const canary = internals(execution).canaryBroker as { subscribe: Function; recordCallback: Function; pending: Function }
  canary.subscribe({
    runId,
    assignmentId: 'floor-worker',
    canaryId: 'canary-late-1',
    token,
    artifact: '',
    allowlist: ['127.0.0.1'],
  })
  assert.equal(canary.pending(runId).length, 1)

  let clock = 0
  let recorded = false
  const sleep = async (ms: number) => {
    clock += ms
    if (!recorded) {
      recorded = true
      // The target's background worker fires 20 s after the response.
      canary.recordCallback({
        token,
        canaryId: 'canary-late-1',
        sourceIp: '127.0.0.1',
        method: 'GET',
        path: '/oob',
        receivedAt: Date.now() + 20_000,
      })
    }
  }
  const result = await execution.drainPendingOob(runId, {
    graceMs: 5_000,
    pollMs: OOB_DRAIN_POLL_MS,
    now: () => clock,
    sleep,
  })
  assert.equal(result.promotedLate, 1, 'the late callback is promoted before finalizing')
  assert.equal(result.remaining, 0)
  assert.ok(result.oobDrainMs >= 1_000, 'the drain waited for the callback window')
  assert.deepEqual(execution.getLastOobDrain(runId), result)

  const drainEvent = storage.eventsAfter(runId, 0).find(e => e.kind === 'oob.drain_complete')
  assert.ok(drainEvent, 'drain metrics are recorded')
  assert.equal(drainEvent!.detail.oobDrainMs, result.oobDrainMs)
  assert.equal(drainEvent!.detail.promotedLate, 1)
})

test('v6 delete: finalization drains pending OOB before writeReport()', async t => {
  const storage = makeStorage(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  storage.updateRun(runId, { phase: 'verification', status: 'running' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const canary = internals(execution).canaryBroker as { subscribe: Function }
  canary.subscribe({
    runId, assignmentId: 'floor-worker', canaryId: 'canary-final', token: 'gn2o_12345678',
    artifact: '', allowlist: ['127.0.0.1'],
  })

  const order: string[] = []
  internals(execution).drainPendingOob = async () => {
    order.push('drain')
    return { oobDrainMs: 12, promotedLate: 1, remaining: 0 }
  }
  const originalWrite = storage.writeReport.bind(storage)
  storage.writeReport = ((run: Parameters<typeof storage.writeReport>[0], partial: boolean) => {
    order.push('report')
    return originalWrite(run, partial)
  }) as typeof storage.writeReport

  internals(execution).scheduleFinalReport(storage.run(runId))
  for (let i = 0; i < 50 && !order.includes('report'); i += 1) await delay(10)
  assert.deepEqual(order, ['drain', 'report'], 'the report is written only after the drain')
  assert.equal(storage.run(runId).status, 'complete')
  assert.equal(storage.run(runId).phase, 'complete')
})

test('v6 delete: OOB drain grace is bounded and configurable', () => {
  assert.equal(resolveOobDrainMs({} as NodeJS.ProcessEnv), 45_000)
  assert.equal(resolveOobDrainMs({ KOVO_OOB_DRAIN_MS: '1500' } as NodeJS.ProcessEnv), 1_500)
  assert.equal(resolveOobDrainMs({ KOVO_OOB_DRAIN_MS: 'nope' } as NodeJS.ProcessEnv), 45_000)
  assert.equal(resolveOobDrainMs({ KOVO_OOB_DRAIN_MS: '999999999' } as NodeJS.ProcessEnv), 600_000)
})

// ---------------------------------------------------------------------------
// 5. Per-worker session clones: floor logout cannot poison an agentic worker
// ---------------------------------------------------------------------------

function bundleSession(origin: string): MintedPersonaSession {
  const host = new URL(origin).hostname
  return {
    headerType: 'cookie',
    value: 'app_sid=app-cookie-value-1234567890',
    adapterUsed: 'form',
    bundle: {
      v: 2,
      cookies: [{ name: 'app_sid', value: 'app-cookie-value-1234567890', domain: host, path: '/', httpOnly: true }],
      headers: { 'X-Tenant-Id': 'tenant-42' },
    },
  }
}

async function loginPersonaRun(storage: Store, origin: string) {
  const project = storage.createProject({
    requestId: randomUUID(),
    name: `v6 delete auth ${randomUUID().slice(0, 8)}`,
    seeds: [origin],
    environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'user_a',
    roleLabel: 'User A',
    originAllowlist: [origin],
    authKind: 'login',
    loginConfig: { adapter: 'form', email: 'user-a@example.test' },
    secret: 'V6DeletePassword!42',
    canaryMarkers: [],
  })
  const run = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify v6 session isolation',
    sourceMode: 'public',
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
    approvedPersonaIds: [persona.id],
    budgetUsd: 25,
    budgetRequests: 1000,
    maxRpsPerOrigin: 20,
    workerConcurrency: 4,
    workerMaxTurns: 40,
    multiTrialEnabled: true,
  } as unknown as Parameters<Store['createRun']>[0])
  storage.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
  const detail = storage.runDetail(run.id)
  storage.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: detail.run.candidates.map(c => c.id),
    consent: true,
    approvedPersonaIds: [persona.id],
  })
  storage.updateRun(run.id, { phase: 'investigation', status: 'running' })
  const refreshed = storage.run(run.id)
  const session = bundleSession(origin)
  const resolved = resolveRunPersonas(storage, project.id, [persona.id]).get('user_a')
  assert.ok(resolved?.sessionPath)
  writePersonaSessionFile(resolved!.sessionPath!, session)
  return { projectId: project.id, runId: run.id, run: refreshed, personaId: persona.id, session, handle: 'user_a' }
}

test('v6 delete: a floor logout/rotation does not 401 an agentic worker', async t => {
  const storage = makeStorage(t)
  const calls: RecordedCall[] = []
  const fixture = await loginPersonaRun(storage, appOrigin)
  const execution = new Execution(storage, { broker: recordingBroker(calls) })
  t.after(() => execution.stop())
  execution.personaAuth.registerSession(fixture.handle, {
    session: fixture.session,
    allowlist: [appOrigin],
    refresh: async () => fixture.session,
  })

  const run = storage.run(fixture.runId)
  const { job: floorJob } = await runningJob(storage, run, 'deterministic floor pass')
  const { job: agentJob } = await runningJob(storage, run, 'agentic specialist')
  const { grant: floorGrant } = internals(execution).buildGrant(floorJob, run, new Set([appOrigin])) as { grant: Grant }
  const { grant: agentGrant } = internals(execution).buildGrant(agentJob, run, new Set([appOrigin])) as { grant: Grant }

  const floorPersona = floorGrant.personas!.get(fixture.handle)
  const agentPersona = agentGrant.personas!.get(fixture.handle)
  assert.ok(floorPersona && agentPersona)
  assert.notEqual(floorPersona, agentPersona, 'each worker gets its own clone-backed view')
  assert.ok(buildPersonaHeader(agentPersona!, appOrigin)?.Cookie?.includes('app-cookie-value'))

  // The floor lane's logout probe invalidates only its own clone.
  assert.equal(execution.logoutWorkerSession(floorJob.assignment.id), 1)
  assert.equal(buildPersonaHeader(floorPersona!, appOrigin), null, 'the floor clone is logged out')
  assert.ok(
    buildPersonaHeader(agentPersona!, appOrigin)?.Cookie?.includes('app-cookie-value'),
    'the agentic worker keeps a valid credential',
  )
  assert.equal(execution.personaAuth.sessions.refreshCount(fixture.handle), 0, 'a local logout never refreshes upstream')

  // The agentic worker still reaches the target with its cookie; the floor worker sends no bytes.
  const agentResult = await execution.broker.executeHttp({
    origin: appOrigin,
    method: 'GET',
    pathAndQuery: '/api/me',
    persona: fixture.handle,
  }, agentGrant, AbortSignal.timeout(5_000))
  assert.equal(agentResult.status, 200)
  assert.equal(calls.length, 1)
  assert.ok(calls[0]!.headers.Cookie?.includes('app-cookie-value'))

  await assert.rejects(
    execution.broker.executeHttp({
      origin: appOrigin,
      method: 'GET',
      pathAndQuery: '/api/me',
      persona: fixture.handle,
    }, floorGrant, AbortSignal.timeout(5_000)),
    (error: unknown) => error instanceof BrokerDenied && /authenticated session/i.test(error.message),
  )
  assert.equal(calls.length, 1, 'the logged-out floor clone never reaches the wire')
})

// ---------------------------------------------------------------------------
// 6. Graphwire: ranked probe plan bounds engine breadth, never the store
// ---------------------------------------------------------------------------

test('v6 delete: a 2,500-route surface probes a bounded ranked subset and keeps every stored route', async t => {
  const storage = makeStorage(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  for (let i = 0; i < 2_500; i += 1) {
    storage.upsertEndpoint({
      runId,
      origin: appOrigin,
      method: 'GET',
      pathTemplate: `/api/v${i % 7}/items/${i}`,
      source: 'openapi',
      riskScore: i % 100,
    })
  }
  const stored = storage.listEndpoints(runId, { limit: 5_000 })
  assert.equal(stored.length, 2_500, 'the endpoint store is lossless')

  // Ranked plan: tier A/B routes first, sampled long-tail representatives (bounded for transport).
  const prioritized = stored
    .filter(ep => ep.riskScore >= 90)
    .slice(0, 12)
    .map(ep => `${ep.method} ${ep.pathTemplate}`)
  const plan = {
    totalRoutes: 2_500,
    priority: 6,
    schemaTyped: 34,
    longTail: 2_460,
    clusters: 120,
    representatives: 24,
    probeSubset: 64,
    sample: prioritized,
  }
  const ranked = selectRankedProbeTargets(stored, plan, { cap: 220 })
  assert.equal(ranked.usedPlan, true)
  assert.equal(ranked.probed, 220, 'probe breadth stays bounded at the engine cap')
  assert.ok(ranked.probed < stored.length, 'probe breadth is bounded well below the surface')
  assert.ok(ranked.skippedStored >= 2_280, 'unsampled clusters stay in the store for later rounds')
  assert.deepEqual(
    ranked.targets.slice(0, prioritized.length).map(ep => `${ep.method} ${ep.pathTemplate}`),
    prioritized,
    'the plan order is honored first',
  )
  assert.equal(storage.listEndpoints(runId, { limit: 5_000 }).length, 2_500, 'nothing is deleted by probing')

  // A plan-only consumer probes exactly the reported ranked sample.
  const planOnly = selectRankedProbeTargets(stored, plan, { cap: 220, planOnly: true })
  assert.equal(planOnly.probed, prioritized.length)

  // No plan (recon unavailable/resumed/local-lab): risk-ranked cap, still lossless.
  const fallback = selectRankedProbeTargets(stored, null, { cap: 220 })
  assert.equal(fallback.usedPlan, false)
  assert.equal(fallback.targets.length, 220)
  assert.ok(fallback.targets[0]!.riskScore! >= fallback.targets.at(-1)!.riskScore!, 'fallback is risk-ranked')
  assert.equal(storage.listEndpoints(runId, { limit: 5_000 }).length, 2_500)
})

test('v6 delete: Program-Graph code→runtime hypotheses become prioritized det_lead facts', async t => {
  const storage = makeStorage(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [appOrigin], tier: 3, environment: 'public' })
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const current = storage.run(runId)
  const execution = new Execution(storage)
  t.after(() => execution.stop())
  const { assignment } = await runningJob(storage, current, 'phase-0 graph lead seeding')

  const hypotheses: CodeToRuntimeHypothesis[] = [
    {
      id: 'hyp-sqli-1',
      kind: 'unauthenticated_sink',
      severity: 'high',
      confidence: 0.92,
      framework: 'express',
      method: 'POST',
      path: '/api/orders/:id',
      file: 'src/routes/orders.ts',
      line: 42,
      sinkKind: 'db_query',
      rationale: 'Route reaches a raw SQL sink without a tenant guard.',
      evidence: ['src/routes/orders.ts:42'],
      probeClass: 'injection',
    },
    {
      id: 'hyp-authz-1',
      kind: 'admin_route_missing_admin_guard',
      severity: 'critical',
      confidence: 0.81,
      framework: 'express',
      method: 'GET',
      path: '/api/admin/users',
      file: 'src/routes/admin.ts',
      line: 17,
      rationale: 'Admin route has no admin middleware in the mount chain.',
      evidence: ['src/routes/admin.ts:17'],
      probeClass: 'auth_bypass',
    },
    {
      id: 'hyp-code-only',
      kind: 'recent_diff_touches_sink',
      severity: 'medium',
      confidence: 0.4,
      framework: 'express',
      file: 'src/lib/util.ts',
      line: 5,
      rationale: 'No runtime route binding.',
      evidence: [],
      probeClass: 'code_review',
    },
  ]

  const created = internals(execution).seedCodeToRuntimeLeads(current, assignment, hypotheses)
  assert.equal(created, 2, 'only routes with a runtime binding become lane leads')

  const facts = storage.listFacts(runId, { includeTainted: false, limit: 20 })
  const sqli = facts.find(f => f.data?.hypothesisId === 'hyp-sqli-1')
  const authz = facts.find(f => f.data?.hypothesisId === 'hyp-authz-1')
  assert.ok(sqli && authz)
  assert.equal(sqli!.data.kind, 'det_lead')
  assert.equal(sqli!.data.source, 'program_graph')
  assert.equal(sqli!.data.probeClass, 'sqli_boolean', 'injection maps to the SQLi probe family')
  assert.equal(sqli!.data.method, 'POST')
  assert.equal(authz!.data.probeClass, 'authz_matrix', 'auth_bypass maps to the authz matrix')

  // Idempotent: re-running recon never duplicates leads.
  assert.equal(internals(execution).seedCodeToRuntimeLeads(current, assignment, hypotheses), 0)

  // The existing det_lead funnel consumes them as prioritized upgrade assignments.
  const queued = internals(execution).queueDetLeadUpgradeSteps(storage.run(runId), new Set([appOrigin]), 24)
  assert.equal(queued, 2)
  const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
  assert.ok(steps.every(step => step.priority === 88), 'graph leads enter the prioritized det_lead queue')
})
