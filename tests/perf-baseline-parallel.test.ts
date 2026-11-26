/**
 * Option C — Parallel baseline capture regression tests (`src/server/exec-recon-planner.ts`):
 * 1. `resolveBaselineCaptureConcurrency` defaults to 6 and clamps `KOVO_BASELINE_CAPTURE_CONCURRENCY` to `[1, 12]`.
 * 2. 6 uncached baseline captures (~80ms each) execute concurrently in `< 2.5x` single-host latency (not `6x` serial),
 *    while Phase-0 in-memory cached roots AND DB-persisted `GET /` roots issue 0 extra HTTP requests.
 * 3. Deterministic ordering of observations, artifacts, and `broker_exchanges` even when later hosts finish first.
 * 4. Per-host timeout / `AbortSignal` / `BrokerDenied` failures never block sibling baseline captures, and parent
 *    `AbortSignal` aborts cleanly cancel in-flight fetches without leaving workers stuck in `running`.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { describe, test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { responseCheckIds } from '../src/domain.ts'
import {
  BrokerDenied,
  RequestBroker,
  type BrokerExchangeResult,
  type BrokerHttpRequest,
  type Grant,
} from '../src/server/broker.ts'
import { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution } from '../src/server/execution.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function stubBackend(): WorkerBackend {
  return {
    name: 'stub-perf-baseline-parallel',
    async run() {
      throw new Error('stub backend must not be invoked')
    },
  } as unknown as WorkerBackend
}

function getPlanner(execution: Execution): ExecReconPlanner {
  return (execution as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

function makeGrant(origins: readonly string[], tier: 0 | 1 | 2 | 3 = 2): Grant {
  const allowed = new Set(origins)
  return {
    tier,
    allowLocalLab: true,
    secrets: [],
    canRead: (origin: string) => allowed.has(origin),
    audit: () => undefined,
  }
}

function makeExchange(origin: string, serverHeader = 'nginx'): BrokerExchangeResult {
  const body = `<html><body>ok ${origin}</body></html>`
  return {
    origin,
    finalOrigin: origin,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/',
    personaHandle: null,
    status: 200,
    mediaType: 'text/html',
    reqHeaders: {},
    respHeaders: {
      'content-type': 'text/html',
      server: serverHeader,
      'x-content-type-options': 'nosniff',
    },
    setCookies: [],
    bodyPreview: body,
    body,
    bodySha256: createHash('sha256').update(body).digest('hex'),
    bodyBytes: Buffer.byteLength(body),
    bodyTruncated: false,
    durationMs: 25,
    secretMatches: [],
    observation: {
      origin,
      finalOrigin: origin,
      status: 200,
      mediaType: 'text/html',
      transportMaxAge: 31536000,
      includeSubDomains: true,
      source: 'public response',
      contentTypeOptions: 'nosniff',
      referrerPolicy: 'strict-origin-when-cross-origin',
      contentSecurityPolicy: 'enforced',
      frameProtection: 'both',
      serverDisclosure: 'generic',
    },
  }
}

describe('resolveBaselineCaptureConcurrency', () => {
  test('defaults to 6 and clamps KOVO_BASELINE_CAPTURE_CONCURRENCY to [1, 12]', () => {
    assert.equal(ExecReconPlanner.BASELINE_CAPTURE_CONCURRENCY, 6)
    assert.equal(ExecReconPlanner.BASELINE_CAPTURE_MIN_CONCURRENCY, 1)
    assert.equal(ExecReconPlanner.BASELINE_CAPTURE_MAX_CONCURRENCY, 12)
    assert.equal(ExecReconPlanner.BASELINE_CAPTURE_TIMEOUT_MS, 8_000)

    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({}), 6)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '' }), 6)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '   ' }), 6)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: 'nope' }), 6)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '0' }), 1)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '-5' }), 1)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '1' }), 1)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '4.9' }), 4)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '12' }), 12)
    assert.equal(ExecReconPlanner.resolveBaselineCaptureConcurrency({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '99' }), 12)
  })
})

describe('parallel baseline capture in ExecReconPlanner', () => {
  test('runs 6 uncached hosts concurrently (< 2.5x single-host latency), issues 0 extra HTTP requests for Phase-0/DB cached hosts, and preserves deterministic order', async t => {
    const { storage } = makeStore(t)
    const cachedPhase0Origin = 'https://cached-phase0.example.invalid'
    const cachedDbOrigin = 'https://cached-db.example.invalid'
    const uncachedOrigins = Array.from({ length: 6 }, (_, i) => `https://uncached-${i}.example.invalid`)
    const allOrigins = [cachedPhase0Origin, ...uncachedOrigins, cachedDbOrigin]

    const { run } = await setupApprovedRun(storage, {
      seeds: allOrigins,
      environment: 'local-lab',
      tier: 2,
    })

    // Pre-populate a DB GET / row for `cachedDbOrigin`
    const seedWorker = storage.makeWorker(run, 'threat_model', run.candidates[0], 'Phase0 seed', 'Seed', {
      sourceOrigins: [cachedDbOrigin],
    })
    storage.recordExchange({
      runId: run.id,
      assignmentId: seedWorker.id,
      scopeRevision: run.scopeRevision,
      origin: cachedDbOrigin,
      finalOrigin: cachedDbOrigin,
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/',
      status: 200,
      mediaType: 'text/html',
      reqHeaders: {},
      respHeaders: { 'content-type': 'text/html', server: 'cached-db-srv', 'x-content-type-options': 'nosniff' },
      body: '<html>cached db</html>',
      durationMs: 5,
      secretMatches: [],
      secrets: [],
    })

    // Reverse latencies (host 0 slowest ~95ms, host 5 fastest ~70ms) so completion order != approvedAssets order
    const latencyByOrigin = new Map<string, number>([
      [uncachedOrigins[0]!, 95],
      [uncachedOrigins[1]!, 90],
      [uncachedOrigins[2]!, 85],
      [uncachedOrigins[3]!, 80],
      [uncachedOrigins[4]!, 75],
      [uncachedOrigins[5]!, 70],
    ])
    const maxSingleHostMs = 95

    let inFlight = 0
    let maxInFlight = 0
    const requestedOrigins: string[] = []
    const observedTimeouts: number[] = []

    const broker = new RequestBroker()
    broker.executeHttp = async (req: BrokerHttpRequest, _grant: Grant, signal: AbortSignal) => {
      requestedOrigins.push(req.origin)
      if (req.timeoutMs !== undefined) observedTimeouts.push(req.timeoutMs)
      inFlight += 1
      maxInFlight = Math.max(maxInFlight, inFlight)
      try {
        const waitMs = latencyByOrigin.get(req.origin) ?? 80
        await delay(waitMs, undefined, { signal })
        return makeExchange(req.origin, `srv-${req.origin}`)
      } finally {
        inFlight -= 1
      }
    }

    const execution = new Execution(storage, { broker, backend: stubBackend() })
    const planner = getPlanner(execution)

    const freshRun = storage.run(run.id)
    const approvedAssets = freshRun.candidates.filter(c => freshRun.approved.includes(c.id))
    const expectedOrder = approvedAssets.map(a => a.origin)
    const expectedUncachedOrder = expectedOrder.filter(o => o !== cachedPhase0Origin && o !== cachedDbOrigin)
    const tmWorker = storage.makeWorker(freshRun, 'threat_model', approvedAssets[0], 'TM', 'TM', {
      sourceOrigins: allOrigins,
    })
    const claimed = storage.updateWorker(tmWorker.id, { status: 'running', lease: 'lease-1' })!
    const controller = new AbortController()
    const job = { assignment: claimed, origins: new Set(allOrigins), controller }
    ;(execution as unknown as { active: Map<string, unknown> }).active.set(claimed.id, job)

    const phase0RootExchanges = new Map<string, BrokerExchangeResult>([
      [cachedPhase0Origin, makeExchange(cachedPhase0Origin, 'cached-phase0-srv')],
    ])
    const grant = makeGrant(allOrigins, freshRun.capabilityTier)

    await withEnv({ KOVO_BASELINE_CAPTURE_CONCURRENCY: undefined }, async () => {
      const started = performance.now()
      const observations = await planner.captureBaselineObservations({
        run: freshRun,
        approvedAssets,
        claimed,
        job,
        grant,
        secrets: [],
        phase0RootExchanges,
        signal: controller.signal,
        selectedChecks: responseCheckIds,
      })
      const elapsedMs = performance.now() - started

      // Concurrency proof: 6 uncached hosts ran concurrently in < 2.5x single-host time (not ~6x serial ~495ms)
      assert.equal(maxInFlight, 6, `expected all 6 uncached hosts in flight simultaneously, got ${maxInFlight}`)
      assert.ok(
        elapsedMs < maxSingleHostMs * 2.5,
        `expected concurrent baseline capture (< ${maxSingleHostMs * 2.5}ms), took ${elapsedMs.toFixed(1)}ms`,
      )

      // Zero extra HTTP requests for cached Phase-0 and DB hosts
      assert.equal(requestedOrigins.length, 6)
      assert.ok(!requestedOrigins.includes(cachedPhase0Origin), 'Phase-0 cached host must issue 0 HTTP requests')
      assert.ok(!requestedOrigins.includes(cachedDbOrigin), 'DB cached host must issue 0 HTTP requests')

      // Bounded 8_000ms timeout used for uncached root fetches
      assert.deepEqual(observedTimeouts, Array(6).fill(ExecReconPlanner.BASELINE_CAPTURE_TIMEOUT_MS))

      // Deterministic ordering matches approvedAssets despite reversed HTTP completion times
      assert.deepEqual(
        observations.map(o => o.origin),
        expectedOrder,
        'observations must preserve exact approvedAssets order',
      )

      // Observation artifacts persisted in deterministic approvedAssets order
      const artifactRows = storage.client.prepare(
        `SELECT id FROM evidence WHERE run_id = ? AND kind = 'observation' ORDER BY rowid ASC`,
      ).all(freshRun.id) as Array<{ id: string }>
      assert.equal(artifactRows.length, expectedOrder.length)
      const artifactOrigins = artifactRows.map(row => {
        const content = storage.artifact(freshRun.id, row.id).content
        return (JSON.parse(content) as { observation: { origin: string } | null }).observation?.origin
      })
      assert.deepEqual(artifactOrigins, expectedOrder, 'observation artifacts must be persisted in approvedAssets order')

      // Recorded fresh broker_exchanges (excluding the pre-seeded DB row) persisted in exact uncached order
      const recordedExchanges = storage.client.prepare(
        `SELECT origin, assignment_id AS assignmentId FROM broker_exchanges
         WHERE run_id = ? AND assignment_id != ?
         ORDER BY rowid ASC`,
      ).all(freshRun.id, seedWorker.id) as Array<{ origin: string; assignmentId: string }>
      assert.deepEqual(
        recordedExchanges.map(r => r.origin),
        expectedUncachedOrder,
        'recorded baseline broker_exchanges must be persisted in deterministic approvedAssets order',
      )

      // Every baseline capture worker completed cleanly
      const baselineWorkers = storage.workerList(freshRun.id).filter(w => w.title.startsWith('Baseline capture · '))
      assert.equal(baselineWorkers.length, allOrigins.length)
      for (const w of baselineWorkers) {
        assert.equal(w.status, 'complete')
        assert.equal(w.lease, null)
      }
    })
  })

  test('runThreatModel executes baseline capture concurrently with KOVO_BASELINE_CAPTURE_CONCURRENCY respected and 0 HTTP calls for DB-cached hosts', async t => {
    const { storage } = makeStore(t)
    const cachedOrigin = 'https://tm-cached.example.invalid'
    const uncachedOrigins = Array.from({ length: 6 }, (_, i) => `https://tm-host-${i}.example.invalid`)
    const allOrigins = [cachedOrigin, ...uncachedOrigins]

    const { run } = await setupApprovedRun(storage, {
      seeds: allOrigins,
      environment: 'local-lab',
      tier: 2,
    })

    // Mark Phase-0 complete and seed the DB root exchange for cachedOrigin
    storage.updateRunPhase0Completed(run.id, Date.now())
    const seedWorker = storage.makeWorker(run, 'threat_model', run.candidates[0], 'Phase0 cached seed', 'Seed', {
      sourceOrigins: [cachedOrigin],
    })
    storage.recordExchange({
      runId: run.id,
      assignmentId: seedWorker.id,
      scopeRevision: run.scopeRevision,
      origin: cachedOrigin,
      finalOrigin: cachedOrigin,
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: '/',
      status: 200,
      mediaType: 'text/html',
      reqHeaders: {},
      respHeaders: { 'content-type': 'text/html', server: 'cached-srv' },
      body: '<html>ok</html>',
      durationMs: 4,
      secretMatches: [],
      secrets: [],
    })

    let inFlight = 0
    let maxInFlight = 0
    const requested: string[] = []
    const timeouts: number[] = []
    const singleHostMs = 80

    const broker = new RequestBroker()
    broker.executeHttp = async (req: BrokerHttpRequest, _grant: Grant, signal: AbortSignal) => {
      requested.push(req.origin)
      if (req.timeoutMs !== undefined) timeouts.push(req.timeoutMs)
      inFlight += 1
      maxInFlight = Math.max(maxInFlight, inFlight)
      try {
        await delay(singleHostMs, undefined, { signal })
        return makeExchange(req.origin)
      } finally {
        inFlight -= 1
      }
    }

    const execution = new Execution(storage, { broker, backend: stubBackend() })
    const planner = getPlanner(execution)
    const controller = new AbortController()
    const freshRun = storage.run(run.id)
    const task = {
      controller,
      goalRevision: freshRun.goalRevision,
      scopeRevision: freshRun.scopeRevision,
    }
    ;(execution as unknown as { plannerTasks: Map<string, unknown> }).plannerTasks.set(freshRun.id, task)

    await withEnv({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '6' }, async () => {
      const started = performance.now()
      await planner.runThreatModel(freshRun, [], task)
      const elapsedMs = performance.now() - started

      assert.equal(maxInFlight, 6)
      assert.ok(
        elapsedMs < singleHostMs * 2.5 + 200,
        `expected runThreatModel baseline capture to run concurrently, took ${elapsedMs.toFixed(1)}ms`,
      )
      assert.equal(requested.length, 6)
      assert.ok(!requested.includes(cachedOrigin))
      assert.deepEqual(timeouts, Array(6).fill(ExecReconPlanner.BASELINE_CAPTURE_TIMEOUT_MS))
      assert.equal(storage.run(freshRun.id).phase, 'investigation')
    })
  })

  test('honors KOVO_BASELINE_CAPTURE_CONCURRENCY upper bound', async t => {
    const { storage } = makeStore(t)
    const origins = Array.from({ length: 6 }, (_, i) => `https://cap-${i}.example.invalid`)
    const { run } = await setupApprovedRun(storage, {
      seeds: origins,
      environment: 'local-lab',
      tier: 2,
    })

    let inFlight = 0
    let maxInFlight = 0
    const broker = new RequestBroker()
    broker.executeHttp = async (req: BrokerHttpRequest, _grant: Grant, signal: AbortSignal) => {
      inFlight += 1
      maxInFlight = Math.max(maxInFlight, inFlight)
      try {
        await delay(30, undefined, { signal })
        return makeExchange(req.origin)
      } finally {
        inFlight -= 1
      }
    }

    const execution = new Execution(storage, { broker, backend: stubBackend() })
    const planner = getPlanner(execution)
    const freshRun = storage.run(run.id)
    const approvedAssets = freshRun.candidates.filter(c => freshRun.approved.includes(c.id))
    const tmWorker = storage.makeWorker(freshRun, 'threat_model', approvedAssets[0], 'TM', 'TM', {
      sourceOrigins: origins,
    })
    const claimed = storage.updateWorker(tmWorker.id, { status: 'running', lease: 'lease-cap' })!
    const controller = new AbortController()
    const job = { assignment: claimed, origins: new Set(origins), controller }
    ;(execution as unknown as { active: Map<string, unknown> }).active.set(claimed.id, job)
    const grant = makeGrant(origins, freshRun.capabilityTier)

    await withEnv({ KOVO_BASELINE_CAPTURE_CONCURRENCY: '2' }, async () => {
      const observations = await planner.captureBaselineObservations({
        run: freshRun,
        approvedAssets,
        claimed,
        job,
        grant,
        secrets: [],
        phase0RootExchanges: new Map(),
        signal: controller.signal,
        selectedChecks: responseCheckIds,
      })
      assert.equal(maxInFlight, 2, `expected max in-flight capped at 2, got ${maxInFlight}`)
      assert.deepEqual(observations.map(o => o.origin), origins)
    })
  })

  test('per-host timeout, AbortError, and BrokerDenied on individual hosts never block sibling captures', async t => {
    const { storage } = makeStore(t)
    const hangingOrigin = 'https://hang-timeout.example.invalid'
    const abortOrigin = 'https://abort-error.example.invalid'
    const deniedOrigin = 'https://denied.example.invalid'
    const okOrigins = [
      'https://sibling-0.example.invalid',
      'https://sibling-1.example.invalid',
      'https://sibling-2.example.invalid',
    ]
    const allOrigins = [hangingOrigin, abortOrigin, deniedOrigin, ...okOrigins]

    const { run } = await setupApprovedRun(storage, {
      seeds: allOrigins,
      environment: 'local-lab',
      tier: 2,
    })

    const siblingDoneAt = new Map<string, number>()
    let hangingSignalAborted = false
    let startTs = 0

    const broker = new RequestBroker()
    broker.executeHttp = async (req: BrokerHttpRequest, _grant: Grant, signal: AbortSignal) => {
      if (req.origin === hangingOrigin) {
        // Hang until per-host timeout signal aborts
        await new Promise<never>((_resolve, reject) => {
          const onAbort = () => {
            hangingSignalAborted = true
            reject(signal.reason ?? new DOMException('Aborted', 'AbortError'))
          }
          if (signal.aborted) onAbort()
          else signal.addEventListener('abort', onAbort, { once: true })
        })
      }
      if (req.origin === abortOrigin) {
        await delay(15)
        throw new DOMException('Request aborted', 'AbortError')
      }
      if (req.origin === deniedOrigin) {
        await delay(10)
        throw new BrokerDenied('Origin denied by test policy')
      }
      await delay(35, undefined, { signal })
      siblingDoneAt.set(req.origin, performance.now() - startTs)
      return makeExchange(req.origin)
    }

    const execution = new Execution(storage, { broker, backend: stubBackend() })
    const planner = getPlanner(execution)
    const freshRun = storage.run(run.id)
    const approvedAssets = freshRun.candidates.filter(c => freshRun.approved.includes(c.id))
    const expectedOrder = approvedAssets.map(a => a.origin)
    const tmWorker = storage.makeWorker(freshRun, 'threat_model', approvedAssets[0], 'TM', 'TM', {
      sourceOrigins: allOrigins,
    })
    const claimed = storage.updateWorker(tmWorker.id, { status: 'running', lease: 'lease-err' })!
    const controller = new AbortController()
    const job = { assignment: claimed, origins: new Set(allOrigins), controller }
    ;(execution as unknown as { active: Map<string, unknown> }).active.set(claimed.id, job)
    const grant = makeGrant(allOrigins, freshRun.capabilityTier)

    const timeoutMs = 160
    startTs = performance.now()
    const observations = await planner.captureBaselineObservations({
      run: freshRun,
      approvedAssets,
      claimed,
      job,
      grant,
      secrets: [],
      phase0RootExchanges: new Map(),
      signal: controller.signal,
      selectedChecks: responseCheckIds,
      timeoutMs,
    })
    const totalMs = performance.now() - startTs

    // Parent controller was NOT aborted by the single-host timeout
    assert.equal(controller.signal.aborted, false)
    assert.equal(hangingSignalAborted, true, 'hanging host must be aborted by per-host timeout signal')
    assert.ok(totalMs < timeoutMs * 2.5, `expected bounded completion near ${timeoutMs}ms, took ${totalMs.toFixed(1)}ms`)

    // Sibling captures completed rapidly BEFORE the hanging host timed out
    for (const ok of okOrigins) {
      const doneMs = siblingDoneAt.get(ok)
      assert.ok(doneMs !== undefined && doneMs < timeoutMs, `sibling ${ok} should finish before hanging host timeout (${doneMs}ms vs ${timeoutMs}ms)`)
    }

    // Deterministic order + exact error/success observations
    assert.deepEqual(observations.map(o => o.origin), expectedOrder)
    const obsByOrigin = new Map(observations.map(o => [String(o.origin), o]))
    assert.equal(obsByOrigin.get(hangingOrigin)!.error, 'The approved public response could not be read.')
    assert.equal(obsByOrigin.get(abortOrigin)!.error, 'The approved public response could not be read.')
    assert.equal(obsByOrigin.get(deniedOrigin)!.error, 'Origin denied by test policy')
    for (const ok of okOrigins) {
      assert.equal(obsByOrigin.get(ok)!.status, 200)
      assert.equal(typeof obsByOrigin.get(ok)!.exchangeId, 'string')
    }

    // All 6 workers finalized cleanly
    const baselineWorkers = storage.workerList(freshRun.id).filter(w => w.title.startsWith('Baseline capture · '))
    assert.equal(baselineWorkers.length, allOrigins.length)
    assert.ok(baselineWorkers.every(w => w.status === 'complete' && w.lease === null))
  })

  test('parent AbortSignal cancels in-flight baseline captures, skips remaining queued hosts, and leaves no dangling running workers', async t => {
    const { storage } = makeStore(t)
    const origins = Array.from({ length: 6 }, (_, i) => `https://parent-abort-${i}.example.invalid`)
    const { run } = await setupApprovedRun(storage, {
      seeds: origins,
      environment: 'local-lab',
      tier: 2,
    })

    const startedOrigins: string[] = []
    const broker = new RequestBroker()
    broker.executeHttp = async (req: BrokerHttpRequest, _grant: Grant, signal: AbortSignal) => {
      startedOrigins.push(req.origin)
      await delay(5_000, undefined, { signal })
      return makeExchange(req.origin)
    }

    const execution = new Execution(storage, { broker, backend: stubBackend() })
    const planner = getPlanner(execution)
    const freshRun = storage.run(run.id)
    const approvedAssets = freshRun.candidates.filter(c => freshRun.approved.includes(c.id))
    const tmWorker = storage.makeWorker(freshRun, 'threat_model', approvedAssets[0], 'TM', 'TM', {
      sourceOrigins: origins,
    })
    const claimed = storage.updateWorker(tmWorker.id, { status: 'running', lease: 'lease-abort' })!
    const controller = new AbortController()
    const job = { assignment: claimed, origins: new Set(origins), controller }
    ;(execution as unknown as { active: Map<string, unknown> }).active.set(claimed.id, job)
    const grant = makeGrant(origins, freshRun.capabilityTier)

    const abortTimer = setTimeout(() => controller.abort(new DOMException('Run stopped', 'AbortError')), 40)
    const startedAt = performance.now()
    try {
      await planner.captureBaselineObservations({
        run: freshRun,
        approvedAssets,
        claimed,
        job,
        grant,
        secrets: [],
        phase0RootExchanges: new Map(),
        signal: controller.signal,
        selectedChecks: responseCheckIds,
        concurrency: 2,
      })
    } finally {
      clearTimeout(abortTimer)
    }
    const elapsedMs = performance.now() - startedAt

    assert.ok(elapsedMs < 500, `expected immediate cancellation on parent abort, took ${elapsedMs.toFixed(1)}ms`)
    assert.equal(startedOrigins.length, 2, 'only the first 2 concurrent slots should have started before abort')

    const baselineWorkers = storage.workerList(freshRun.id).filter(w => w.title.startsWith('Baseline capture · '))
    assert.equal(baselineWorkers.length, 2)
    assert.ok(
      baselineWorkers.every(w => w.status === 'complete' && w.lease === null),
      'started workers must be finalized cleanly on abort',
    )
  })
})
