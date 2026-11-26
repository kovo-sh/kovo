/**
 * P2 #7 Regression & Unit Tests — Exclude Provider-Stall / Retry Wait Time from Worker
 * Wall-Clock Rotation & Extend Verify Grace:
 *  1. Pure unit tests for `computeEffectiveWorkerElapsedMs` and
 *     `computeEffectiveWorkerElapsedBreakdown` (deducts approval pause + bounded
 *     `providerStallWaitMs`, enforces finite `maxStallCreditMs` cap, never infinite).
 *  2. Pure unit tests for `computeWorkerWallClockPlan` and `resolveWorkerVerifyGrace`
 *     (grants expanded +60s verify grace when worker entered `kovo_verify` or holds a live
 *     sealed capability / active `hop_checkpoint`, strictly clamped by finite `2x` hard cap).
 *  3. Pure unit tests for `ProviderStallWaitTracker` (distinguishes retry/backoff and stream
 *     stall timeout waits from active token streaming; live getter includes in-flight backoff).
 *  4. Integration tests with mock stalled/retrying provider:
 *     - Transient HTTP 429 retry/backoff wait does NOT prematurely rotate a worker after 1–3 turns.
 *     - Genuinely over-ceiling stalled worker still terminates cleanly at the finite `2x` hard cap
 *       with structured `providerStallWaitMs` and `verifyGraceApplied` telemetry.
 *     - Worker with active `kovo_verify` / `hop_checkpoint` receives expanded bounded verify grace
 *       and emits `verifyGraceApplied: true` on bounded rotation.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import { runCommand } from '../src/domain.ts'
import { ProviderStallWaitTracker, runAgentSession } from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { AssignmentBudget } from '../src/server/exec-dispatch.ts'
import type { ExecActiveJob } from '../src/server/exec-exchange.ts'
import {
  DEFAULT_VERIFY_GRACE_MAX_MS,
  DEFAULT_VERIFY_GRACE_MIN_MS,
  EXPANDED_VERIFY_GRACE_MS,
  ExecWorkerRunner,
  computeEffectiveWorkerElapsedBreakdown,
  computeEffectiveWorkerElapsedMs,
  computeWorkerWallClockPlan,
  resolveWorkerVerifyGrace,
} from '../src/server/exec-worker-runner.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const ORIGIN = 'https://stall-wallclock.example.test'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-stall-wc-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeProfile(overrides: Partial<ResolvedModelProfile> & {
  id: string
  endpoint: string
  key: string
}): ResolvedModelProfile {
  return {
    name: overrides.id,
    model: 'stall-wc-test-model',
    protocol: 'responses',
    enabled: true,
    priority: 100,
    contextWindow: 128_000,
    maxTokens: 4096,
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
    ...overrides,
  }
}

function sse(events: Array<{ type: string } & Record<string, unknown>>): string {
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

function responsesToolCallTurn(callId: string, name: string, args: Record<string, unknown>): string {
  const rawArgs = JSON.stringify(args)
  const fcId = `fc_${callId}`
  const item = {
    type: 'function_call',
    id: fcId,
    call_id: callId,
    name,
    arguments: rawArgs,
    status: 'completed',
  }
  return sse([
    { type: 'response.created', response: { id: `resp_${callId}`, status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, arguments: '', status: 'in_progress' } },
    { type: 'response.function_call_arguments.delta', output_index: 0, item_id: fcId, delta: rawArgs },
    { type: 'response.function_call_arguments.done', output_index: 0, item_id: fcId, name, arguments: rawArgs },
    { type: 'response.output_item.done', output_index: 0, item },
    {
      type: 'response.completed',
      response: {
        id: `resp_${callId}`,
        status: 'completed',
        output: [item],
        usage: { input_tokens: 60, output_tokens: 30 },
      },
    },
  ])
}

function setupApprovedTestRun(store: Store, name = 'Stall WallClock Test') {
  const project = store.createProject({
    requestId: randomUUID(),
    name,
    seeds: [ORIGIN],
    environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify stall-credit wall-clock rotation and verify grace',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 500,
    maxRpsPerOrigin: 10,
    workerConcurrency: 2,
    workerMaxTurns: 10,
  })
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
  }))
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { project, runId, run: store.run(runId) }
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function makeStubBackend(): WorkerBackend {
  return {
    workerImage: 'kovo-worker:stall-test',
    run: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
    verifyStaticAst: async () => ({
      verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
      matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
    }),
    openSession: async () => ({
      stage: async name => `/evidence/${name}`,
      exec: async () => ({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async req => ({ repo: req.repo, enginesRun: req.engines, engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
      runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
      verifyStaticAst: async () => ({
        verified: false, engine: 'ast-grep', repo: '.', file: 'a.ts', startLine: 1, endLine: 1,
        matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
      }),
      close: async () => undefined,
    }),
  }
}

// ============================================================================
// 1. Pure unit tests: computeEffectiveWorkerElapsedMs & breakdown
// ============================================================================

describe('P2 #7.1: computeEffectiveWorkerElapsedMs pure math & finite caps', () => {
  test('deducts both approvalPausedMs and bounded providerStallWaitMs', () => {
    const effective = computeEffectiveWorkerElapsedMs({
      wallElapsedMs: 120_000,
      approvalPausedMs: 20_000,
      providerStallWaitMs: 35_000,
      maxStallCreditMs: 90_000,
    })
    assert.equal(effective, 65_000)

    const breakdown = computeEffectiveWorkerElapsedBreakdown({
      wallElapsedMs: 120_000,
      approvalPausedMs: 20_000,
      providerStallWaitMs: 35_000,
      maxStallCreditMs: 90_000,
    })
    assert.deepEqual(breakdown, {
      wallElapsedMs: 120_000,
      approvalPausedMs: 20_000,
      providerStallWaitMs: 35_000,
      creditedStallWaitMs: 35_000,
      activeElapsedMs: 100_000,
      effectiveElapsedMs: 65_000,
    })
  })

  test('enforces finite maxStallCreditMs cap (prevents infinite hang)', () => {
    // Base budget = 90s, maxStallCreditMs = 90s -> hard active ceiling = 180s (2x base).
    // Even if providerStallWaitMs is 500s, credit is strictly capped at 90s.
    const breakdown = computeEffectiveWorkerElapsedBreakdown({
      wallElapsedMs: 185_000,
      approvalPausedMs: 0,
      providerStallWaitMs: 500_000,
      maxStallCreditMs: 90_000,
    })
    assert.equal(breakdown.creditedStallWaitMs, 90_000)
    assert.equal(breakdown.effectiveElapsedMs, 95_000, 'at 185s active, effective elapsed >= 90s base budget triggers rotation')

    // Non-finite maxStallCreditMs (Infinity / NaN) must fail-safe to 0 credit rather than allowing infinite extension.
    assert.equal(
      computeEffectiveWorkerElapsedMs({
        wallElapsedMs: 100_000,
        approvalPausedMs: 0,
        providerStallWaitMs: 80_000,
        maxStallCreditMs: Number.POSITIVE_INFINITY,
      }),
      100_000,
      'Infinity maxStallCreditMs must clamp safely to 0 credit',
    )
    assert.equal(
      computeEffectiveWorkerElapsedMs({
        wallElapsedMs: 100_000,
        approvalPausedMs: Number.NaN,
        providerStallWaitMs: 50_000,
        maxStallCreditMs: Number.NaN,
      }),
      100_000,
    )
  })

  test('never returns negative elapsed time when deductions exceed wallElapsedMs', () => {
    assert.equal(
      computeEffectiveWorkerElapsedMs({
        wallElapsedMs: 10_000,
        approvalPausedMs: 15_000,
        providerStallWaitMs: 20_000,
        maxStallCreditMs: 90_000,
      }),
      0,
    )
    assert.equal(
      computeEffectiveWorkerElapsedMs({
        wallElapsedMs: -500,
        approvalPausedMs: -100,
        providerStallWaitMs: -200,
        maxStallCreditMs: 10_000,
      }),
      0,
    )
  })
})

// ============================================================================
// 2. Pure unit tests: expanded verify grace & hard ceiling enforcement
// ============================================================================

describe('P2 #7.2: computeWorkerWallClockPlan & resolveWorkerVerifyGrace', () => {
  test('computeWorkerWallClockPlan sets finite 2x hard wall-clock ceiling and +60s expanded verify grace', () => {
    const plan = computeWorkerWallClockPlan({ wallClockMs: 90_000, isMultiHop: false })
    assert.equal(plan.remainingBudgetMs, 90_000)
    assert.equal(plan.maxStallCreditMs, 90_000)
    assert.equal(plan.hardWallClockCeilingMs, 180_000)
    assert.equal(plan.expandedVerifyGraceMs, EXPANDED_VERIFY_GRACE_MS)
    assert.ok(plan.verifyGraceMs >= DEFAULT_VERIFY_GRACE_MIN_MS && plan.verifyGraceMs <= DEFAULT_VERIFY_GRACE_MAX_MS)
  })

  test('grants expanded +60s verify grace for kovo_verify, live sealed capability, or hop_checkpoint', () => {
    const plan = computeWorkerWallClockPlan({ wallClockMs: 90_000, isMultiHop: false })

    const inKovoVerify = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 90_000,
      inFlightProofCall: false,
      enteredKovoVerify: true,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(inKovoVerify.verifyGraceApplied, true)
    assert.equal(inKovoVerify.reason, 'expanded_verify')
    assert.equal(inKovoVerify.graceMs, 60_000)

    const withSealedCap = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 90_000,
      inFlightProofCall: false,
      enteredKovoVerify: false,
      hasLiveSealedCapability: true,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(withSealedCap.verifyGraceApplied, true)
    assert.equal(withSealedCap.reason, 'expanded_verify')
    assert.equal(withSealedCap.graceMs, 60_000)

    const withHopCheckpoint = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 90_000,
      inFlightProofCall: false,
      enteredKovoVerify: false,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: true,
      inSettlementStream: false,
    })
    assert.equal(withHopCheckpoint.verifyGraceApplied, true)
    assert.equal(withHopCheckpoint.reason, 'expanded_verify')
    assert.equal(withHopCheckpoint.graceMs, 60_000)
  })

  test('clamps expanded verify grace to remaining hard ceiling headroom and returns 0 at hard cap', () => {
    const plan = computeWorkerWallClockPlan({ wallClockMs: 90_000, isMultiHop: false })

    // Stall credit already moved soft expiration to 150s -> only 30s left before 180s hard cap.
    const clamped = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 150_000,
      inFlightProofCall: true,
      enteredKovoVerify: true,
      hasLiveSealedCapability: true,
      hasHopCheckpoint: true,
      inSettlementStream: false,
    })
    assert.equal(clamped.verifyGraceApplied, true)
    assert.equal(clamped.graceMs, 30_000, 'grace must be clamped by remaining hard ceiling headroom')
    assert.equal(clamped.hardCeilingRemainingMs, 30_000)

    // At hard ceiling (180s), zero grace is granted regardless of proof state.
    const atHardCap = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 180_000,
      inFlightProofCall: true,
      enteredKovoVerify: true,
      hasLiveSealedCapability: true,
      hasHopCheckpoint: true,
      inSettlementStream: true,
    })
    assert.equal(atHardCap.verifyGraceApplied, false)
    assert.equal(atHardCap.graceMs, 0)
    assert.equal(atHardCap.reason, 'none')
  })

  test('grants no verify grace when worker is not in proof, checkpoint, or settlement stream', () => {
    const plan = computeWorkerWallClockPlan({ wallClockMs: 90_000, isMultiHop: false })
    const none = resolveWorkerVerifyGrace({
      plan,
      sessionActiveElapsedMs: 90_000,
      inFlightProofCall: false,
      enteredKovoVerify: false,
      hasLiveSealedCapability: false,
      hasHopCheckpoint: false,
      inSettlementStream: false,
    })
    assert.equal(none.verifyGraceApplied, false)
    assert.equal(none.graceMs, 0)
    assert.equal(none.reason, 'none')
  })
})

// ============================================================================
// 3. Pure unit tests: ProviderStallWaitTracker
// ============================================================================

describe('P2 #7.3: ProviderStallWaitTracker accuracy', () => {
  test('accumulates 0ms on healthy turns, captures 429/5xx retry backoff, and isolates stream stall wait', () => {
    let fakeNow = 1_000
    const tracker = new ProviderStallWaitTracker(() => fakeNow)

    // Turn 1: healthy turn (100ms TTFT + 400ms streaming) -> 0ms stall wait.
    tracker.onCallStart()
    fakeNow += 100
    tracker.onStreamActivity()
    fakeNow += 400
    tracker.onStreamActivity()
    tracker.onCallEnd()
    assert.equal(tracker.getProviderStallWaitMs(), 0, 'healthy turn must record 0ms stall wait')

    // Turn 2: HTTP 429 after 50ms -> 350ms backoff -> attempt 2 succeeds after 40ms TTFT + 200ms streaming.
    tracker.onCallStart()
    fakeNow += 50
    tracker.onRetryOrStall('retried')
    // Mid-backoff live check:
    fakeNow += 200
    assert.equal(tracker.getProviderStallWaitMs(), 250, 'live getter must include in-progress retry wait')
    fakeNow += 150
    // Attempt 2 starts in providerPool (flushes failed attempt + 350ms backoff = 400ms)
    tracker.onCallStart()
    assert.equal(tracker.getProviderStallWaitMs(), 400)
    fakeNow += 40
    tracker.onStreamActivity()
    fakeNow += 200
    tracker.onCallEnd()
    assert.equal(tracker.getProviderStallWaitMs(), 400, 'active streaming must not inflate stall wait')

    // Turn 3: Streams actively for 300ms, then hangs 5_000ms until stream stall timeout fires.
    tracker.onCallStart()
    fakeNow += 300
    tracker.onStreamActivity()
    fakeNow += 5_000
    tracker.onRetryOrStall('stalled')
    tracker.onCallEnd()
    assert.equal(tracker.getProviderStallWaitMs(), 5_400, 'stream stall must exclude prior 300ms active streaming')
  })
})

// ============================================================================
// 4. Integration tests: transient stall survival, hard cap, & verify grace
// ============================================================================

describe('P2 #7.4: Integration tests with mock stalled/retrying provider', () => {
  test('transient HTTP 429 retry wait does NOT prematurely rotate a multi-turn worker in ExecWorkerRunner', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-stall-survive-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    const exec = new Execution(store, { broker: makeBroker(), backend: makeStubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())

    let requestCount = 0
    let logicalTurn = 0
    // On 2-vCPU CI runners, widen the mock 429 stall + base budget proportionally so event-loop
    // jitter and pre-session setup cannot push active turn time past the base budget or hard cap,
    // while keeping total wall > baseWallClockMs (proving stall credit prevented rotation).
    const first429DelayMs = process.env.CI ? 1_300 : 350
    const baseWallClockMs = process.env.CI ? 2_000 : 1_150
    const server = createServer((req, res) => {
      req.resume()
      requestCount += 1
      // First request delays first429DelayMs and returns HTTP 429 -> total retry/backoff stall wait!
      if (requestCount === 1) {
        setTimeout(() => {
          if (!res.writableEnded) {
            res.writeHead(429, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: { message: 'rate limit exceeded, retry later' } }))
          }
        }, first429DelayMs)
        return
      }
      logicalTurn += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (logicalTurn === 1 || logicalTurn === 2) {
        // Two active exploration turns (~220ms each) before turn 3 completes (~120ms).
        setTimeout(() => {
          res.end(responsesToolCallTurn(`call_ev_${logicalTurn}`, 'derive_evidence', {
            command: `echo turn-${logicalTurn}`,
          }))
        }, 220)
        return
      }
      setTimeout(() => {
        res.end(responsesToolCallTurn('call_done', 'complete_intent', {
          status: 'ruled_out',
          summary: 'Completed 3 active turns after transient 429 provider backoff.',
        }))
      }, 120)
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port
    const profile = makeProfile({ id: 'p-stall-survive', endpoint: `http://127.0.0.1:${port}`, key: 'sk-stall-survive-1234' })

    const { runId, run } = setupApprovedTestRun(store, 'Stall Survival Project')
    const asset = run.candidates[0]!
    const step = store.addChainStep(run, {
      title: 'Investigate route under transient 429',
      hypothesis: 'Check /api/orders with transient provider retry',
      category: 'broken-access-control',
      priority: 85,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
    })
    const worker = store.updateWorker(
      store.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
        stepId: step.id,
        sourceOrigins: [ORIGIN],
      }).id,
      { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
    )!
    const job: ExecActiveJob = { assignment: worker, origins: new Set([ORIGIN]), controller: new AbortController() }
    const priv = exec as unknown as {
      workerRunner: ExecWorkerRunner
      active: Map<string, ExecActiveJob>
    }
    priv.active.set(worker.id, job)

    // Base wallClockMs = 1150ms local (2000ms CI). The 429 failed attempt + backoff + 3 active turns
    // takes > baseWallClockMs wall (which WOULD prematurely rotate without stall-wait deduction), while
    // effective active time (~560ms + overhead) < baseWallClockMs and well below the 2x hard cap!
    const startedAt = Date.now()
    const budget: AssignmentBudget = { kind: 'single_step', maxTurns: 6, wallClockMs: baseWallClockMs, settlementTurn: 5 }
    await priv.workerRunner.runInvestigationWorker(job, step, [ORIGIN], [profile], budget)
    priv.active.delete(worker.id)
    const wallElapsedMs = Date.now() - startedAt

    assert.ok(wallElapsedMs > baseWallClockMs, `expected wall duration > ${baseWallClockMs}ms base budget (proving stall credit prevented rotation), got ${wallElapsedMs}ms`)
    assert.equal(logicalTurn, 3, 'worker must execute all 3 turns instead of rotating prematurely after 429 retry')
    const updatedStep = store.listChainSteps(runId, run.goalRevision).find(s => s.id === step.id)
    assert.equal(updatedStep?.status, 'complete', 'step must complete cleanly after transient stall credit')
    const rotatedEvents = store.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.wall_clock_rotated')
    assert.equal(rotatedEvents.length, 0, 'zero premature wall_clock_rotated events when stall credit covers 429 wait')
  })

  test('genuinely over-ceiling stalled worker terminates cleanly at finite 2x hard cap with telemetry', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-stall-hardcap-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    const exec = new Execution(store, { broker: makeBroker(), backend: makeStubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())

    // Always returns 429 after 40ms -> providerPool backs off 350ms + 700ms (> 2x wallClockMs=280ms hard cap!).
    const server = createServer((req, res) => {
      req.resume()
      setTimeout(() => {
        if (!res.writableEnded) {
          res.writeHead(429, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: { message: 'rate limit exceeded' } }))
        }
      }, 40)
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port
    const profile = makeProfile({ id: 'p-stall-hardcap', endpoint: `http://127.0.0.1:${port}`, key: 'sk-stall-cap-1234' })

    const { runId, run } = setupApprovedTestRun(store, 'Stall Hard Cap Project')
    const asset = run.candidates[0]!
    const step = store.addChainStep(run, {
      title: 'Over-ceiling stalled worker',
      hypothesis: 'Check /api/stalled-forever',
      category: 'broken-access-control',
      priority: 80,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
    })
    const worker = store.updateWorker(
      store.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
        stepId: step.id,
        sourceOrigins: [ORIGIN],
      }).id,
      { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
    )!
    const job: ExecActiveJob = { assignment: worker, origins: new Set([ORIGIN]), controller: new AbortController() }
    const priv = exec as unknown as {
      workerRunner: ExecWorkerRunner
      active: Map<string, ExecActiveJob>
    }
    priv.active.set(worker.id, job)

    const startedAt = Date.now()
    const budget: AssignmentBudget = { kind: 'single_step', maxTurns: 6, wallClockMs: 350, settlementTurn: 5 }
    await priv.workerRunner.runInvestigationWorker(job, step, [ORIGIN], [profile], budget)
    priv.active.delete(worker.id)
    const wallElapsedMs = Date.now() - startedAt

    // Must NOT hang past 2x hard cap (700ms) + teardown jitter.
    const hardCapMaxElapsedMs = process.env.CI ? 3_500 : 1_600
    assert.ok(wallElapsedMs >= 500, `expected stall credit to delay rotation past base 350ms, rotated at ${wallElapsedMs}ms`)
    assert.ok(wallElapsedMs < hardCapMaxElapsedMs, `expected hard cap rotation near 2x base (700ms), took ${wallElapsedMs}ms`)

    const rotatedEvents = store.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.wall_clock_rotated')
    assert.equal(rotatedEvents.length, 1, 'expected exactly one worker.wall_clock_rotated event at hard cap')
    const detail = rotatedEvents[0]!.detail as {
      providerStallWaitMs?: number
      creditedStallWaitMs?: number
      hardWallClockCeilingMs?: number
      verifyGraceApplied?: boolean
    }
    assert.ok((detail.providerStallWaitMs ?? 0) > 200, `expected providerStallWaitMs > 200, got ${detail.providerStallWaitMs}`)
    assert.ok((detail.creditedStallWaitMs ?? 0) > 0, `expected creditedStallWaitMs > 0, got ${detail.creditedStallWaitMs}`)
    assert.ok((detail.hardWallClockCeilingMs ?? 0) <= 700, `expected hardWallClockCeilingMs <= 700, got ${detail.hardWallClockCeilingMs}`)
    assert.equal(detail.verifyGraceApplied, false)
  })

  test('runAgentSession tracks providerStallWaitMs live via onSessionReady and avoids premature rotation', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-session-stall-')
    let reqs = 0
    let turns = 0
    const server = createServer((req, res) => {
      req.resume()
      reqs += 1
      if (reqs <= 2) {
        // Two transient 503 responses -> 100ms + 200ms = 300ms backoff wait.
        res.writeHead(503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { message: 'upstream temporarily unavailable' } }))
        return
      }
      turns += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (turns === 1) {
        setTimeout(() => {
          res.end(responsesToolCallTurn('c_t1', 'derive_evidence', { command: 'echo ok' }))
        }, 100)
        return
      }
      setTimeout(() => {
        res.end(responsesToolCallTurn('c_t2', 'complete_intent', {
          status: 'ruled_out',
          summary: 'Finished cleanly after 503 retries.',
        }))
      }, 100)
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port

    let liveGetter: (() => number) | undefined
    const stallEvents: Array<{ providerStallWaitMs: number; kind: string }> = []
    const result = await runAgentSession({
      directory: dir,
      sessionId: 'sess-stall-live',
      requestId: 'req-stall-live',
      profiles: [makeProfile({ id: 'p-live', endpoint: `http://127.0.0.1:${port}`, key: 'sk-live-stall-1234' })],
      scenario: 'worker-investigation',
      prompt: 'Run quick check and complete.',
      signal: AbortSignal.timeout(process.env.CI ? 15_000 : 5_000),
      maxTurns: 4,
      wallClockMs: process.env.CI ? 1_200 : 650,
      providerTransportRetryBaseMs: 180,
      onSessionReady: handle => { liveGetter = () => handle.getProviderStallWaitMs() },
      onProviderStallWait: info => stallEvents.push(info),
      handlers: {
        derive_evidence: async () => ({ exitCode: 0, stdout: 'ok', stderr: '' }),
        complete_intent: async c => c,
      },
    })

    assert.equal(result.status, 'completed')
    assert.ok(liveGetter, 'onSessionReady must supply live getProviderStallWaitMs getter')
    assert.ok((result.providerStallWaitMs ?? 0) >= 450, `expected providerStallWaitMs >= 450ms, got ${result.providerStallWaitMs}`)
    assert.equal(liveGetter!(), result.providerStallWaitMs)
    assert.ok(stallEvents.length >= 2, `expected >= 2 stall wait callbacks, got ${stallEvents.length}`)
  })

  test('ExecWorkerRunner applies expanded verify grace for active hop_checkpoint and emits verifyGraceApplied telemetry', async t => {
    const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
    process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
    t.after(() => {
      if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
    })

    const dir = makeTempDir(t, 'kovo-hop-grace-')
    const store = new Store(dir)
    t.after(() => { try { store.close() } catch { /* ignore */ } })

    const exec = new Execution(store, { broker: makeBroker(), backend: makeStubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())

    // Turn 1 hangs so worker hits soft deadline at ~200ms while holding an active hop_checkpoint,
    // triggering expanded_verify grace (~100ms for 200ms budget) before rotating cleanly!
    const server = createServer((req, res) => {
      req.resume()
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      // Intentionally keep stream open to exercise bounded expanded verify-grace expiration.
    }).listen(0, '127.0.0.1')
    await once(server, 'listening')
    t.after(async () => {
      server.closeAllConnections()
      await new Promise<void>(resolve => server.close(() => resolve()))
    })
    const port = (server.address() as AddressInfo).port
    const profile = makeProfile({ id: 'p-hop-grace', endpoint: `http://127.0.0.1:${port}`, key: 'sk-hop-grace-1234' })

    const { runId, run } = setupApprovedTestRun(store, 'Hop Checkpoint Grace Project')
    const asset = run.candidates[0]!
    const step = store.addChainStep(run, {
      title: 'Continue hopCheckpoint proof',
      hypothesis: 'Use sealed handle cap:hop_token_1 to finish proof',
      category: 'broken-access-control',
      priority: 90,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
    })
    const worker = store.updateWorker(
      store.makeWorker(run, 'investigation', asset, step.title, step.hypothesis, {
        stepId: step.id,
        sourceOrigins: [ORIGIN],
      }).id,
      { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 },
    )!
    const job: ExecActiveJob = { assignment: worker, origins: new Set([ORIGIN]), controller: new AbortController() }
    const priv = exec as unknown as {
      workerRunner: ExecWorkerRunner
      active: Map<string, ExecActiveJob>
      assignmentBriefForStep: (...args: unknown[]) => string
    }
    priv.active.set(worker.id, job)
    const origBrief = priv.assignmentBriefForStep.bind(exec)
    priv.assignmentBriefForStep = (...args: unknown[]) => `${origBrief(...args)}\nhopCheckpoint: cap:hop_token_1`

    const startedAt = Date.now()
    const budget: AssignmentBudget = { kind: 'chain', maxTurns: 6, wallClockMs: 300, settlementTurn: 5 }
    await priv.workerRunner.runInvestigationWorker(job, step, [ORIGIN], [profile], budget)
    priv.active.delete(worker.id)
    const elapsedMs = Date.now() - startedAt

    // Base 300ms + expanded verify grace (~150ms) -> ~450ms (strictly bounded, never hangs).
    const graceMaxElapsedMs = process.env.CI ? 6_000 : 3_000
    assert.ok(elapsedMs >= 380, `expected expanded verify grace to extend past base 300ms, rotated at ${elapsedMs}ms`)
    assert.ok(elapsedMs < graceMaxElapsedMs, `expected bounded rotation after expanded verify grace, took ${elapsedMs}ms`)

    const rotatedEvents = store.eventsAfter(runId, 0, 200).filter(e => e.kind === 'worker.wall_clock_rotated')
    assert.equal(rotatedEvents.length, 1)
    const detail = rotatedEvents[0]!.detail as {
      verifyGraceApplied?: boolean
      verifyGraceReason?: string
      providerStallWaitMs?: number
      graceUsedMs?: number
    }
    assert.equal(detail.verifyGraceApplied, true)
    assert.equal(detail.verifyGraceReason, 'expanded_verify')
    assert.equal(detail.providerStallWaitMs, 0)
    assert.ok((detail.graceUsedMs ?? 0) >= 80, `expected graceUsedMs >= 80, got ${detail.graceUsedMs}`)
  })
})
