/**
 * v8 Phase-B dynamic AIMD concurrency (ceiling 12) & concurrency-12 safety rails tests.
 *
 * Covers:
 *  1. Host hardware cap auto-computation (CPU & available RAM) + budget wind-down.
 *  2. PhaseBConcurrencyController AIMD ramp-up (+2 per clean window/completions up to 12),
 *     immediate multiplicative decrease (max(2, floor(cur/2))) on LLM 429, target 429/503/timeout
 *     spikes, container spawn failures/slow spawn latency, and explicit env/CLI override precedence.
 *  3. Fair 12-slot dispatch scheduling & zero duplicate assignment dispatch (pure + live Execution).
 *  4. SQLite WAL + busy_timeout >= 10_000ms rail + withBusyRetry + 12-writer concurrent stress.
 *  5. Broker loopback concurrency cap (12 in-flight on loopback, polite 2 in-flight on external).
 *  6. LabRunner bounded memory/CPU/PIDs limits & zero-orphan container cleanup on failure/stop.
 */
import assert from 'node:assert/strict'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  EXTERNAL_ORIGIN_MAX_IN_FLIGHT,
  LOOPBACK_ORIGIN_MAX_IN_FLIGHT,
  RequestBroker,
  brokerPerOriginConcurrencyCap,
  brokerPerOriginRpsCap,
  isLoopbackOrigin,
  type Grant,
  type Transport,
} from '../src/server/broker.ts'
import {
  DET_LEAD_CONCURRENT_CAP,
  Execution,
  PHASE_B_AIMD_MAX_CEILING,
  PHASE_B_AIMD_WARM_START,
  PhaseBConcurrencyController,
  computeBudgetPhaseBConcurrencyCap,
  computeHostPhaseBConcurrencyCap,
  parseEnvPhaseBConcurrencyOverride,
  planRoundRobinDispatch,
  type DispatchLaneStep,
} from '../src/server/execution.ts'
import {
  DEFAULT_LAB_MEMORY_LIMIT,
  LabRunner,
  resolveLabServiceResourceLimits,
  type DockerRunner,
  type LabContainerStore,
} from '../src/server/lab-runner.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import {
  HIGH_CONCURRENCY_SQLITE_BUSY_TIMEOUT_MS,
  withBusyRetry,
} from '../src/server/store-session.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const GiB = 1024 ** 3
const ORIGIN = 'https://target.example.invalid'

function makeStep(id: string, overrides: Partial<DispatchLaneStep> = {}): DispatchLaneStep {
  return {
    id,
    seq: Number(id.replace(/\D+/g, '')) || 1,
    priority: 80,
    title: `Route sweep ${id}`,
    category: 'broken-access-control',
    hypothesis: `Verify authorization boundaries on GET /api/v1/items/${id}.`,
    skills: ['bola-bfla'],
    dependsOnFactIds: [],
    dependsOnStepIds: [],
    sourceOrigins: [ORIGIN],
    trialIndex: 0,
    ...overrides,
  }
}

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
        close: async () => undefined,
      }
    },
    async verifyStaticAst(_aid, req) {
      return { verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  }
}

async function startFastMockLlm(
  t: { after: (fn: () => void | Promise<void>) => void },
  delayMs = 40,
): Promise<{ endpoint: string; getPeakConcurrent: () => number; getTotalCalls: () => number }> {
  let active = 0
  let peak = 0
  let total = 0
  const timers = new Set<NodeJS.Timeout>()
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => {
      active += 1
      total += 1
      if (active > peak) peak = active
      const idx = total
      const timer = setTimeout(() => {
        timers.delete(timer)
        active = Math.max(0, active - 1)
        if (res.destroyed || res.writableEnded) return
        res.statusCode = 200
        res.setHeader('Content-Type', 'text/event-stream')
        res.setHeader('Cache-Control', 'no-cache')
        const itemId = `item_${idx}`
        const responseId = `resp_${idx}`
        const argsJson = JSON.stringify({ status: 'ruled_out', summary: `Verified step ${idx}.` })
        const emit = (event: string, data: Record<string, unknown>) => {
          res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        }
        emit('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
        emit('response.output_item.added', {
          type: 'response.output_item.added',
          output_index: 0,
          item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: `c_${idx}`, name: 'complete_intent', arguments: '' },
        })
        emit('response.function_call_arguments.done', {
          type: 'response.function_call_arguments.done',
          output_index: 0,
          item_id: itemId,
          name: 'complete_intent',
          arguments: argsJson,
        })
        emit('response.output_item.done', {
          type: 'response.output_item.done',
          output_index: 0,
          item: { id: itemId, type: 'function_call', status: 'completed', call_id: `c_${idx}`, name: 'complete_intent', arguments: argsJson },
        })
        emit('response.completed', {
          type: 'response.completed',
          response: {
            id: responseId,
            status: 'completed',
            output: [{ id: itemId, type: 'function_call', status: 'completed', call_id: `c_${idx}`, name: 'complete_intent', arguments: argsJson }],
            usage: { input_tokens: 60, output_tokens: 20, total_tokens: 80, input_tokens_details: { cached_tokens: 0 } },
          },
        })
        res.write('data: [DONE]\n\n')
        res.end()
      }, delayMs)
      timer.unref?.()
      timers.add(timer)
      res.on('close', () => {
        if (timers.delete(timer)) {
          clearTimeout(timer)
          active = Math.max(0, active - 1)
        }
      })
    })
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    for (const timer of timers) clearTimeout(timer)
    timers.clear()
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })
  return {
    endpoint: `http://127.0.0.1:${port}/v1`,
    getPeakConcurrent: () => peak,
    getTotalCalls: () => total,
  }
}

// ============================================================================
// 1. Hardware Cap & Budget Cap Helpers
// ============================================================================

test('computeHostPhaseBConcurrencyCap derives ceiling 12 on 16c/11GiB and scales down on smaller hosts', () => {
  assert.equal(PHASE_B_AIMD_MAX_CEILING, 12)
  assert.equal(PHASE_B_AIMD_WARM_START, 6)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 16, availMemBytes: 11 * GiB }), 12)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 32, availMemBytes: 64 * GiB }), 12)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 8, availMemBytes: 16 * GiB }), 6)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 16, availMemBytes: 4.5 * GiB }), 6)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 4, availMemBytes: 16 * GiB }), 3)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 2, availMemBytes: 1 * GiB }), 2)
})

test('computeBudgetPhaseBConcurrencyCap winds down smoothly as remaining USD shrinks', () => {
  assert.equal(computeBudgetPhaseBConcurrencyCap(undefined), Number.POSITIVE_INFINITY)
  assert.equal(computeBudgetPhaseBConcurrencyCap(5.0), 33)
  assert.equal(computeBudgetPhaseBConcurrencyCap(0.90), 6)
  assert.equal(computeBudgetPhaseBConcurrencyCap(0.60), 4)
  assert.equal(computeBudgetPhaseBConcurrencyCap(0.30), 2)
  assert.equal(computeBudgetPhaseBConcurrencyCap(0.10), 1)
  assert.equal(computeBudgetPhaseBConcurrencyCap(0), 1)
})

// ============================================================================
// 2. Dynamic AIMD Controller: Ramp-Up, 429/503 Backoff, Budget Wind-Down, Override
// ============================================================================

test('PhaseBConcurrencyController starts warm at 6 and additively ramps (+2) up to ceiling 12', () => {
  let nowMs = 100_000
  const ctrl = new PhaseBConcurrencyController({
    cpuCount: 16,
    availMemBytes: 11 * GiB,
    now: () => nowMs,
  })
  assert.equal(ctrl.hardwareCap, 12)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 6)

  // Clean 18s window with a clean completion -> +2 (6 -> 8)
  ctrl.recordCleanCompletion({ spawnLatencyMs: 900, remainingBudgetUsd: 5.0 })
  nowMs += 18_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 8)

  // Clean completions threshold (3 completions) -> +2 (8 -> 10)
  ctrl.recordCleanCompletion({ spawnLatencyMs: 800, remainingBudgetUsd: 5.0 })
  ctrl.recordCleanCompletion({ spawnLatencyMs: 700, remainingBudgetUsd: 5.0 })
  assert.equal(ctrl.recordCleanCompletion({ spawnLatencyMs: 850, remainingBudgetUsd: 5.0 }), 10)

  // Another clean 18s window -> +2 (10 -> 12, capped at hardwareCap 12)
  ctrl.recordCleanCompletion({ spawnLatencyMs: 1_000, remainingBudgetUsd: 5.0 })
  nowMs += 18_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 12)

  // Further clean windows stay capped at 12
  ctrl.recordCleanCompletion({ spawnLatencyMs: 500, remainingBudgetUsd: 5.0 })
  nowMs += 20_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 12)
  assert.equal(ctrl.snapshot(5.0).increases, 3)
})

test('PhaseBConcurrencyController multiplicatively decreases immediately on LLM 429, target 429/503/timeout, and container pressure', () => {
  let nowMs = 50_000
  const ctrl = new PhaseBConcurrencyController({
    cpuCount: 16,
    availMemBytes: 11 * GiB,
    warmStart: 12,
    now: () => nowMs,
  })
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 12)

  // LLM 429 -> 12 -> 6
  assert.equal(ctrl.recordPressure('llm_429'), 6)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 6)

  // Target 503 spike (3 errors) -> 6 -> 3
  ctrl.recordTargetOutcome(200)
  ctrl.recordTargetOutcome(503)
  ctrl.recordTargetOutcome(503)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 6)
  ctrl.recordTargetOutcome(503)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 3)

  // High container spawn latency (>8s) -> 3 -> 2 (floor)
  assert.equal(ctrl.recordCleanCompletion({ spawnLatencyMs: 9_500, remainingBudgetUsd: 5.0 }), 2)
  // Another pressure stays at floor 2
  assert.equal(ctrl.recordPressure('container_spawn_error'), 2)
  assert.equal(ctrl.snapshot(5.0).decreases, 3)

  // Recovery after pressure clears: clean window ramps back 2 -> 4 -> 6
  ctrl.recordCleanCompletion({ spawnLatencyMs: 600, remainingBudgetUsd: 5.0 })
  nowMs += 18_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 4)
  ctrl.recordCleanCompletion({ spawnLatencyMs: 600, remainingBudgetUsd: 5.0 })
  nowMs += 18_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 6)
})

test('PhaseBConcurrencyController winds down smoothly on low remaining budget and honors explicit env/CLI overrides', () => {
  const ctrl = new PhaseBConcurrencyController({
    cpuCount: 16,
    availMemBytes: 11 * GiB,
    warmStart: 12,
  })
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 3.0 }), 12)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 0.60 }), 4)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 0.30 }), 2)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 0.10 }), 1)

  // Explicit env override always wins (even on low RAM, pressure, or small budget)
  assert.equal(parseEnvPhaseBConcurrencyOverride({ KOVO_PHASE_B_CONCURRENCY: '12' }), 12)
  assert.equal(parseEnvPhaseBConcurrencyOverride({ KOVO_WORKER_CONCURRENCY: '9' }), 9)
  assert.equal(parseEnvPhaseBConcurrencyOverride({}), undefined)

  const envPinned = new PhaseBConcurrencyController({
    cpuCount: 4,
    availMemBytes: 2 * GiB,
    env: { KOVO_PHASE_B_CONCURRENCY: '10' },
  })
  assert.equal(envPinned.getEffectiveConcurrency({ remainingBudgetUsd: 0.10 }), 10)
  assert.equal(envPinned.recordPressure('llm_429'), 10)
  assert.equal(envPinned.getEffectiveConcurrency({ remainingBudgetUsd: 0.10 }), 10)

  const cliPinned = new PhaseBConcurrencyController({
    cpuCount: 16,
    availMemBytes: 11 * GiB,
    explicitOverride: 4,
  })
  assert.equal(cliPinned.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 4)
  assert.equal(cliPinned.recordPressure('target_503'), 4)
})

// ============================================================================
// 3. 12-Slot Fair Dispatch Scheduling & Zero Duplicate Dispatch
// ============================================================================

test('planRoundRobinDispatch fills all 12 slots fairly without starving chains or double-dispatching duplicate step IDs', () => {
  const steps: DispatchLaneStep[] = [
    ...Array.from({ length: 6 }, (_, i) => makeStep(`chain-${i + 1}`, {
      seq: i + 1,
      priority: 90 - i,
      title: `Multi-hop boundary chain ${i + 1}`,
      hypothesis: `Pivot derived token across services [chain_hops=h1->h2->h3]`,
      skills: ['chain:state_handle', 'multihop-chains'],
    })),
    ...Array.from({ length: 4 }, (_, i) => makeStep(`lead-${i + 1}`, {
      seq: 10 + i,
      priority: 95 - i,
      title: `det_lead upgrade · /api/v1/resource/${i + 1}`,
    })),
    ...Array.from({ length: 6 }, (_, i) => makeStep(`route-${i + 1}`, {
      seq: 20 + i,
      priority: 85 - i,
    })),
  ]
  // Inject duplicate step entries defensively to prove dedupe guarantees unique dispatch across 12 slots.
  const withDupes = [...steps, steps[0]!, steps[1]!, steps[6]!]
  const plan = planRoundRobinDispatch(withDupes, 12, { leadCap: DET_LEAD_CONCURRENT_CAP })

  assert.equal(plan.ordered.length, 12, 'must fill all 12 slots immediately')
  assert.equal(new Set(plan.ordered.map(s => s.id)).size, 12, 'zero duplicate step IDs across 12 slots')
  assert.equal(plan.selectedByLane.chain, 6, 'all 6 multi-hop chain steps claim dedicated frontier slots')
  assert.ok(plan.selectedByLane.lead >= 2, 'det_lead lane receives its fair share')
  assert.ok(plan.selectedByLane.route >= 4, 'route lane fills remaining slots')
})

test('Live Execution dispatches 12 unique concurrent specialists on Wave 1 with zero duplicates and raises SQLite busy_timeout >= 10s', async (t) => {
  const llm = await startFastMockLlm(t, 80)
  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'Conc12-Mock',
    endpoint: llm.endpoint,
    model: 'mock-conc12',
    protocol: 'responses',
    key: 'sk-mock-conc12-1234',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, {
    seeds: [ORIGIN],
    budgetUsd: 5,
    budgetRequests: 5000,
    maxRpsPerOrigin: 30,
  })
  for (let i = 1; i <= 6; i += 1) {
    storage.addChainStep(run, {
      title: `Multi-hop capability chain ${i}`,
      hypothesis: `Advance verified checkpoint across boundary [chain_hops=h1->h2->h3]`,
      category: 'broken-access-control',
      priority: 92 - i,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
      skills: ['chain:state_handle', 'multihop-chains'],
    })
  }
  for (let i = 1; i <= 10; i += 1) {
    storage.addChainStep(run, {
      title: `Route authorization check ${i}`,
      hypothesis: `Verify access controls on GET /api/v1/records/${i}.`,
      category: 'broken-access-control',
      priority: 85 - i,
      targetAssetIds: run.approved,
      sourceOrigins: [ORIGIN],
      skills: ['bola-bfla'],
    })
  }
  storage.updateRun(runId, {
    phase: 'investigation',
    status: 'running',
    workerConcurrency: 12,
    multiTrialEnabled: false,
  })

  const engine = new Execution(storage, {
    backend: stubBackend(),
    deterministicSweep: false,
    workerConcurrencyOverride: 12,
  })
  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 5_000
    while (Date.now() < deadline) {
      const done = storage.listChainSteps(runId, run.goalRevision).filter(s => s.status === 'complete').length
      if (done >= 16) break
      await new Promise(r => setTimeout(r, 25))
    }
    await stopExecution(engine as never)
  })

  // Verify SQLite WAL + busy_timeout >= 10_000ms rail was applied on Execution.start()
  const busy = storage.client.prepare('PRAGMA busy_timeout').get() as { timeout: number }
  const journal = storage.client.prepare('PRAGMA journal_mode').get() as { journal_mode: string }
  assert.equal(String(journal.journal_mode).toLowerCase(), 'wal')
  assert.ok(Number(busy.timeout) >= 10_000, `expected busy_timeout >= 10000ms, got ${busy.timeout}`)

  const dispatchEvents = storage.eventsAfter(runId, 0, 200).filter(e => e.kind === 'scheduler.dispatch')
  assert.ok(dispatchEvents.length >= 1, 'expected scheduler.dispatch event')
  const wave1 = dispatchEvents[0]!.detail as {
    slots: number
    effectiveConcurrency: number
    dispatched: number
    stepIds: string[]
    selectedByLane: Record<string, number>
  }
  assert.equal(wave1.effectiveConcurrency, 12)
  assert.equal(wave1.dispatched, 12, 'Wave 1 must fill all 12 slots immediately')
  assert.equal(new Set(wave1.stepIds).size, 12, 'Wave 1 must dispatch 12 distinct step IDs')
  assert.equal(wave1.selectedByLane.chain, 6, 'all 6 multi-hop chains must launch in Wave 1')
  assert.ok(llm.getPeakConcurrent() >= 8, `expected high live parallelism on mock LLM, got peak=${llm.getPeakConcurrent()}`)

  // Every step must be assigned to at most one investigation worker (no duplicate dispatch)
  const assignments = storage.workerList(runId).filter(w => w.phase === 'investigation')
  const assignedStepIds = assignments.map(w => w.stepId).filter((id): id is string => Boolean(id))
  assert.equal(assignedStepIds.length, 16)
  assert.equal(new Set(assignedStepIds).size, 16, 'zero duplicate assignment dispatches across 12 slots')
})

// ============================================================================
// 4. SQLite busy_timeout & Concurrent 12-Worker Write Contention Rail
// ============================================================================

test('StoreSession ensures WAL + busy_timeout >= 10s, retries SQLITE_BUSY, and survives 12 concurrent writers', async (t) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN] })

  const pragmas = storage.session.ensureHighConcurrencyPragmas()
  assert.equal(pragmas.journalMode, 'wal')
  assert.equal(pragmas.busyTimeoutMs, HIGH_CONCURRENCY_SQLITE_BUSY_TIMEOUT_MS)
  assert.ok(pragmas.busyTimeoutMs >= 10_000)

  // Verify withBusyRetry recovers from transient SQLITE_BUSY errors
  let attempts = 0
  const recovered = withBusyRetry(() => {
    attempts += 1
    if (attempts < 3) throw new Error('SQLITE_BUSY: database is locked')
    return 'ok'
  }, 5, 1)
  assert.equal(recovered, 'ok')
  assert.equal(attempts, 3)

  // 12 concurrent asynchronous writers performing events + transactions
  await Promise.all(
    Array.from({ length: 12 }, (_, workerIdx) =>
      Promise.resolve().then(async () => {
        for (let i = 0; i < 15; i += 1) {
          storage.session.event(runId, 'concurrency.probe', `worker ${workerIdx} tick ${i}`, { workerIdx, i })
          if (i % 5 === 0) {
            storage.session.transaction(() => {
              storage.session.event(runId, 'concurrency.tx', `worker ${workerIdx} tx ${i}`, { workerIdx, i })
            }, { behavior: 'immediate' })
          }
          if (i % 4 === 0) await new Promise(r => setImmediate(r))
        }
      }),
    ),
  )

  const probeEvents = storage.eventsAfter(runId, 0, 500).filter(e => e.kind === 'concurrency.probe')
  const txEvents = storage.eventsAfter(runId, 0, 500).filter(e => e.kind === 'concurrency.tx')
  assert.equal(probeEvents.length, 180)
  assert.equal(txEvents.length, 36)
})

// ============================================================================
// 5. Broker Per-Origin Loopback Concurrency Rail (12 Loopback vs 2 External)
// ============================================================================

test('RequestBroker allows 12 concurrent in-flight requests on loopback while capping external origins at 2', async () => {
  assert.equal(isLoopbackOrigin('http://127.0.0.1:8080'), true)
  assert.equal(isLoopbackOrigin('http://localhost:3000'), true)
  assert.equal(isLoopbackOrigin('http://[::1]:8080'), true)
  assert.equal(isLoopbackOrigin('https://external.example.invalid'), false)

  assert.equal(brokerPerOriginConcurrencyCap('http://127.0.0.1:8080'), LOOPBACK_ORIGIN_MAX_IN_FLIGHT)
  assert.equal(brokerPerOriginConcurrencyCap('https://external.example.invalid'), EXTERNAL_ORIGIN_MAX_IN_FLIGHT)
  assert.equal(brokerPerOriginRpsCap('http://127.0.0.1:8080', 60), 60)
  assert.equal(brokerPerOriginRpsCap('https://external.example.invalid', 60), 20)

  // Measure real concurrent in-flight peak on loopback origin (target: 12 simultaneously)
  let localActive = 0
  let localPeak = 0
  let releaseAllLocal!: () => void
  const localGate = new Promise<void>(resolve => { releaseAllLocal = resolve })
  const localTransport: Transport = async () => {
    localActive += 1
    if (localActive > localPeak) localPeak = localActive
    if (localActive >= 12) releaseAllLocal()
    await Promise.race([localGate, new Promise(r => setTimeout(r, 400))])
    localActive -= 1
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  }
  const localOrigin = 'http://127.0.0.1:18080'
  const localBroker = new RequestBroker({
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
    transport: localTransport,
  })
  const localGrant: Grant = {
    origin: localOrigin,
    tier: 1,
    maxRpsPerOrigin: 30,
    allowLocalLab: true,
    canRead: o => o === localOrigin,
    audit: () => undefined,
  }
  const localResults = await Promise.all(
    Array.from({ length: 12 }, (_, i) =>
      localBroker.executeHttp({ origin: localOrigin, method: 'GET', pathAndQuery: `/api/item/${i}` }, localGrant, AbortSignal.timeout(5_000)),
    ),
  )
  assert.equal(localResults.length, 12)
  assert.equal(localPeak, 12, `expected all 12 loopback requests in-flight concurrently, got peak=${localPeak}`)

  // Verify external origin remains strictly capped at 2 concurrent in-flight
  let extActive = 0
  let extPeak = 0
  const extTransport: Transport = async () => {
    extActive += 1
    if (extActive > extPeak) extPeak = extActive
    await new Promise(r => setTimeout(r, 45))
    extActive -= 1
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  }
  const extOrigin = 'https://external.example.invalid'
  const extBroker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: extTransport,
  })
  const extGrant: Grant = {
    origin: extOrigin,
    tier: 1,
    maxRpsPerOrigin: 20,
    allowLocalLab: false,
    canRead: o => o === extOrigin,
    audit: () => undefined,
  }
  await Promise.all(
    Array.from({ length: 6 }, (_, i) =>
      extBroker.executeHttp({ origin: extOrigin, method: 'GET', pathAndQuery: `/ext/${i}` }, extGrant, AbortSignal.timeout(5_000)),
    ),
  )
  assert.equal(extPeak, 2, `external origin must remain capped at 2 in-flight, got peak=${extPeak}`)
})

// ============================================================================
// 6. LabRunner Memory Bounds & Zero-Orphan Container Cleanup Rail
// ============================================================================

test('LabRunner bounds container memory/CPU/PIDs limits and sweeps orphans cleanly on failed start', async (t) => {
  // Resource bounds
  assert.deepEqual(resolveLabServiceResourceLimits({}, {}), {
    memoryLimit: DEFAULT_LAB_MEMORY_LIMIT,
    cpus: '1.0',
    pidsLimit: 128,
  })
  assert.deepEqual(
    resolveLabServiceResourceLimits({ memoryLimit: '   ', cpus: '', pidsLimit: 0 }, {}),
    { memoryLimit: '512m', cpus: '1.0', pidsLimit: 128 },
  )
  assert.deepEqual(
    resolveLabServiceResourceLimits({ memoryLimit: '16g', cpus: '12', pidsLimit: 9999 }, {}),
    { memoryLimit: '2048m', cpus: '4.0', pidsLimit: 512 },
  )

  // Failed-start cleanup removes tracked container rows and falls back to per-id orphan removal
  const repoDir = mkdtempSync(join(tmpdir(), 'kovo-lab-conc12-repo-'))
  const stateDir = mkdtempSync(join(tmpdir(), 'kovo-lab-conc12-state-'))
  t.after(() => {
    rmSync(repoDir, { recursive: true, force: true })
    rmSync(stateDir, { recursive: true, force: true })
  })
  writeFileSync(join(repoDir, 'server.js'), 'console.log("ok")\n')

  const removedContainers: string[] = []
  const trackedRows = new Map<string, string>()
  const fakeStore: LabContainerStore & { deleteLabContainer: (runId: string, name: string) => void } = {
    recordLabContainer(input) { trackedRows.set(input.containerName, input.status ?? 'running') },
    markLabContainerOrphaned(_runId, name) { trackedRows.set(name, 'orphaned') },
    deleteLabContainer(_runId, name) { trackedRows.delete(name) },
    listLabContainers() { return [...trackedRows.entries()].map(([containerName, status]) => ({ containerName, status })) },
  }

  let runCount = 0
  const docker: DockerRunner = async (args) => {
    if (args[0] === 'network' && args[1] === 'create') return 'net-123\n'
    if (args[0] === 'run') {
      runCount += 1
      if (runCount === 1) return 'cid-app-1\n'
      throw new Error('simulated proxy start failure')
    }
    if (args[0] === 'inspect' && args[2] === '{{.Id}}') return 'a1b2c3d4e5f6a1b2c3d4e5f6\n'
    if (args[0] === 'inspect') return '172.18.0.2\n'
    if (args[0] === 'ps' && args[1] === '-aq') return 'orphan-1 orphan-2\n'
    if (args[0] === 'container' && args[1] === 'rm') {
      const targets = args.slice(3)
      // Simulate batch rm failing once so per-id fallback is exercised
      if (targets.length > 1) throw new Error('batch rm conflict')
      for (const target of targets) removedContainers.push(target)
      return ''
    }
    return ''
  }

  const runner = new LabRunner({ docker, stateDir })
  await assert.rejects(
    () => runner.startLabTarget({
      runId: 'run-conc12-cleanup',
      environment: 'local-lab',
      repoDir,
      labConfig: { startCommand: 'node server.js', memoryLimit: '8g' },
      storage: fakeStore as never,
    }),
    /simulated proxy start failure/,
  )

  assert.equal(trackedRows.size, 0, 'all tracked container rows must be cleared after failed-start cleanup')
  assert.ok(removedContainers.includes('orphan-1'), 'per-id fallback must remove orphan-1')
  assert.ok(removedContainers.includes('orphan-2'), 'per-id fallback must remove orphan-2')
})
