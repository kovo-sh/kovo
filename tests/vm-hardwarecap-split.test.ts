/**
 * A4 #2 + Phase-0 cleanup unit tests:
 *  1. Decoupled I/O-bound LLM worker `hardwareCap` vs CPU/RAM-bound Docker verify cap.
 *  2. `DockerVerifySemaphore` + `LinuxWorkerBackend` verification concurrency bounding.
 *  3. Phase-0 unexpanded JS template literal route filtering (`${...}`, `$%7B...%7D`, `%24%7B...%7D`, backticks).
 *  4. Generic structural collection/member grouping (no domain-specific lifecycle verb regexes).
 */
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import type { ChildProcess } from 'node:child_process'
import { test } from 'node:test'

import {
  PHASE_B_AIMD_MAX_CEILING,
  PHASE_B_AIMD_WARM_START,
  PhaseBConcurrencyController,
  computeHostPhaseBConcurrencyCap,
  parseEnvPhaseBConcurrencyOverride,
} from '../src/server/exec-dispatch.ts'
import {
  DOCKER_VERIFY_MAX_CEILING,
  DockerVerifySemaphore,
  LinuxWorkerBackend,
  computeDockerVerifyHardwareCap,
} from '../src/server/worker-backend.ts'
import {
  extractRuntimeSpaRoutesFromJs,
  hasUnexpandedJsTemplateArtifact,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from '../src/server/broker.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const GiB = 1024 ** 3
const ORIGIN = 'https://app.example.invalid'

function fakeSessionProcess(): ChildProcess {
  const proc = new EventEmitter() as ChildProcess
  const stdin = new PassThrough()
  const stdout = new PassThrough()
  const stderr = new PassThrough()
  ;(proc as unknown as { stdin: PassThrough; stdout: PassThrough; stderr: PassThrough; kill: () => boolean }).stdin = stdin
  ;(proc as unknown as { stdout: PassThrough }).stdout = stdout
  ;(proc as unknown as { stderr: PassThrough }).stderr = stderr
  ;(proc as unknown as { kill: () => boolean }).kill = () => {
    proc.emit('close', 0)
    return true
  }
  return proc
}

// ============================================================================
// 1. Decoupled LLM Worker Cap vs Docker Verify Cap
// ============================================================================

test('2-vCPU / 3.8 GiB VM yields llmWorkerHardwareCap >= 6 while dockerVerifyHardwareCap is 2', () => {
  // Exact kovo-test-1 VM geometry (total 3.8 GiB, typical free MemAvailable 2.8 GiB).
  const llmTotal = computeHostPhaseBConcurrencyCap({ cpuCount: 2, availMemBytes: 3.8 * GiB })
  const llmFree = computeHostPhaseBConcurrencyCap({ cpuCount: 2, availMemBytes: 2.8 * GiB })
  assert.ok(llmTotal >= 6, `expected llmWorkerHardwareCap >= 6 on 2c/3.8GiB, got ${llmTotal}`)
  assert.ok(llmFree >= 6, `expected llmWorkerHardwareCap >= 6 on 2c/2.8GiB avail, got ${llmFree}`)
  assert.equal(new PhaseBConcurrencyController({ cpuCount: 2, availMemBytes: 3.8 * GiB }).llmWorkerHardwareCap, llmTotal)

  const dockerTotal = computeDockerVerifyHardwareCap({ cpuCount: 2, availMemBytes: 3.8 * GiB, env: {} })
  const dockerFree = computeDockerVerifyHardwareCap({ cpuCount: 2, availMemBytes: 2.8 * GiB, env: {} })
  assert.equal(dockerTotal, 2, '2-vCPU / 3.8 GiB must bound concurrent Docker verify containers to 2')
  assert.equal(dockerFree, 2, '2-vCPU / 2.8 GiB avail must bound concurrent Docker verify containers to 2')

  // Scaling across smaller & larger hosts
  assert.equal(computeDockerVerifyHardwareCap({ cpuCount: 1, availMemBytes: 4 * GiB, env: {} }), 1)
  assert.equal(computeDockerVerifyHardwareCap({ cpuCount: 4, availMemBytes: 1.5 * GiB, env: {} }), 1)
  assert.equal(computeDockerVerifyHardwareCap({ cpuCount: 4, availMemBytes: 8 * GiB, env: {} }), 4)
  assert.equal(computeDockerVerifyHardwareCap({ cpuCount: 16, availMemBytes: 32 * GiB, env: {} }), DOCKER_VERIFY_MAX_CEILING)
  assert.equal(computeDockerVerifyHardwareCap({ cpuCount: 2, availMemBytes: 3.8 * GiB, env: { KOVO_DOCKER_VERIFY_CONCURRENCY: '3' } }), 3)

  // Low-RAM OOM guard still clamps LLM workers on severely constrained 1 GiB hosts
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 2, availMemBytes: 1 * GiB }), 2)
  assert.equal(computeHostPhaseBConcurrencyCap({ cpuCount: 4, availMemBytes: 8 * GiB }), PHASE_B_AIMD_MAX_CEILING)
})

test('PhaseBConcurrencyController starts warm at 6 on 2c/3.8GiB, backs off on real pressure, and honors KOVO_WORKER_CONCURRENCY', () => {
  let nowMs = 10_000
  const ctrl = new PhaseBConcurrencyController({
    cpuCount: 2,
    availMemBytes: 3.8 * GiB,
    now: () => nowMs,
  })
  assert.equal(ctrl.hardwareCap, 6)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), Math.min(PHASE_B_AIMD_WARM_START, 6))

  // Real LLM 429 pressure triggers multiplicative decrease: 6 -> 3
  assert.equal(ctrl.recordPressure('llm_429'), 3)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 3)

  // Target 503 spike backs off further: 3 -> 2 (floor)
  ctrl.recordTargetOutcome(503)
  ctrl.recordTargetOutcome(503)
  ctrl.recordTargetOutcome(503)
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 2)

  // Recovery after clean window: 2 -> 4 -> 6
  ctrl.recordCleanCompletion({ spawnLatencyMs: 500, remainingBudgetUsd: 5.0 })
  nowMs += 18_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 4)
  ctrl.recordCleanCompletion({ spawnLatencyMs: 500, remainingBudgetUsd: 5.0 })
  nowMs += 18_000
  assert.equal(ctrl.getEffectiveConcurrency({ remainingBudgetUsd: 5.0 }), 6)

  // Explicit KOVO_WORKER_CONCURRENCY override always wins
  assert.equal(parseEnvPhaseBConcurrencyOverride({ KOVO_WORKER_CONCURRENCY: '8' }), 8)
  const pinned = new PhaseBConcurrencyController({
    cpuCount: 2,
    availMemBytes: 3.8 * GiB,
    env: { KOVO_WORKER_CONCURRENCY: '8' },
  })
  assert.equal(pinned.getEffectiveConcurrency({ remainingBudgetUsd: 0.1 }), 8)
  assert.equal(pinned.recordPressure('llm_429'), 8)
})

// ============================================================================
// 2. Bounded Docker Verification Semaphore (Unit + LinuxWorkerBackend)
// ============================================================================

test('DockerVerifySemaphore bounds 6 concurrent tasks to 2 active, preserves FIFO, and handles abort cleanly', async () => {
  const sem = new DockerVerifySemaphore(2)
  let inFlight = 0
  let maxObserved = 0
  const startedOrder: number[] = []
  const releases: Array<() => void> = []

  const tasks = [1, 2, 3, 4, 5, 6].map(async id => {
    const release = await sem.acquire()
    startedOrder.push(id)
    inFlight += 1
    maxObserved = Math.max(maxObserved, inFlight)
    await new Promise<void>(resolve => {
      releases.push(() => {
        inFlight -= 1
        release()
        release() // idempotent double-release must not corrupt permits
        resolve()
      })
    })
  })

  await new Promise(r => setTimeout(r, 15))
  assert.equal(sem.activeCount, 2)
  assert.equal(sem.queuedCount, 4)
  assert.equal(maxObserved, 2)

  // Queued aborting waiter must reject cleanly without leaking a permit
  const ac = new AbortController()
  const abortedAcquire = sem.acquire(ac.signal)
  assert.equal(sem.queuedCount, 5)
  ac.abort(new Error('cancelled-waiter'))
  await assert.rejects(abortedAcquire, /cancelled-waiter/)
  assert.equal(sem.queuedCount, 4)

  // Drain all 6 tasks two at a time
  while (startedOrder.length < 6 || releases.length > 0) {
    const next = releases.shift()
    if (next) next()
    await new Promise(r => setTimeout(r, 5))
  }
  await Promise.all(tasks)

  assert.equal(maxObserved, 2)
  assert.equal(sem.peakActiveCount, 2)
  assert.equal(sem.activeCount, 0)
  assert.equal(sem.queuedCount, 0)
  assert.deepEqual(startedOrder, [1, 2, 3, 4, 5, 6])
})

test('LinuxWorkerBackend bounds 6 concurrent verification sessions to dockerVerifyHardwareCap=2 while releasing on close', async (t) => {
  const prevWarm = process.env.KOVO_WARM_WORKERS
  process.env.KOVO_WARM_WORKERS = '0'
  const rpcDirs = Array.from({ length: 6 }, (_, i) => mkdtempSync(join(tmpdir(), `kovo-verify-sem-${i}-`)))
  t.after(() => {
    for (const d of rpcDirs) { try { rmSync(d, { recursive: true, force: true }) } catch { /* ignore */ } }
  })
  try {
    let activeSpawns = 0
    let peakSpawns = 0
    const backend = new LinuxWorkerBackend({
      maxConcurrentVerifyContainers: 2,
      dockerRunner: async (args) => {
        if (args[0] === 'image' && args[1] === 'inspect') return '[]'
        if (args[0] === 'container' && args[1] === 'ls') return ''
        return ''
      },
      sessionSpawner: () => {
        activeSpawns += 1
        peakSpawns = Math.max(peakSpawns, activeSpawns)
        const proc = fakeSessionProcess()
        proc.once('close', () => { activeSpawns = Math.max(0, activeSpawns - 1) })
        return proc
      },
    })
    assert.equal(backend.dockerVerifyHardwareCap, 2)

    const sessions = await Promise.all(
      rpcDirs.map(async (rpcDir, idx) => {
        const ac = new AbortController()
        const sess = await backend.openSession(`verify-slot-${idx}`, ac.signal, {
          rpcMountDir: rpcDir,
        })
        await new Promise(r => setTimeout(r, 25))
        await sess.close()
        return sess
      }),
    )
    assert.equal(sessions.length, 6)
    assert.equal(peakSpawns, 2, `expected peak concurrent verify containers <= 2, got ${peakSpawns}`)
    assert.equal(backend.verifySemaphoreStats.peakActiveCount, 2)
    assert.equal(backend.verifySemaphoreStats.activeCount, 0)
    assert.equal(backend.verifySemaphoreStats.queuedCount, 0)

    // Verify cold-create failure still releases permit cleanly (no leak)
    await assert.rejects(
      backend.openSession('verify-missing-dir', new AbortController().signal, { rpcMountDir: join(rpcDirs[0]!, 'does-not-exist') }),
      /Verification RPC mount path does not exist/,
    )
    assert.equal(backend.verifySemaphoreStats.activeCount, 0)
    await backend.close()
  } finally {
    if (prevWarm === undefined) delete process.env.KOVO_WARM_WORKERS
    else process.env.KOVO_WARM_WORKERS = prevWarm
  }
})

// ============================================================================
// 3. Phase-0 Unexpanded JS Template Literal Route Filtering
// ============================================================================

test('hasUnexpandedJsTemplateArtifact rejects raw/encoded JS template expressions while preserving valid route templates', () => {
  for (const bad of [
    '/api/${e}',
    '/api/${user.id}/profile',
    '/api/$%7Be%7D',
    '/api/$%7bitem.id%7d/edit',
    '/api/%24%7Be%7D',
    '/api/%24%7bfoo%7d',
    '/api/%24{e}',
    '/api/` + id',
    '/api/%60items%60',
  ]) {
    assert.equal(hasUnexpandedJsTemplateArtifact(bad), true, `expected rejection for ${bad}`)
  }

  for (const good of [
    '/api/v1/items/:id',
    '/api/v1/items/{itemId}',
    '/api/v1/items/[id]',
    '/api/v1/items/<int:id>',
    '/api/$metadata',
    '/api/$batch',
    '/api/v1/widgets',
  ]) {
    assert.equal(hasUnexpandedJsTemplateArtifact(good), false, `expected valid route to pass: ${good}`)
  }
})

test('extractRuntimeSpaRoutesFromJs filters unexpanded JS template literals and derives stateActions structurally', () => {
  const routes = extractRuntimeSpaRoutesFromJs(
    `fetch('/api/v1/widgets/123/qux', { method: 'POST' })`,
    {
      routes: [{ path: '/widgets' }, { path: '/api/${e}' }, { path: '/api/$%7Be%7D' }],
      apiPaths: ['/api/${e}', '/api/$%7Be%7D', '/api/%24%7Be%7D', '/api/v1/widgets'],
      httpCalls: [
        { url: '/api/${e}', method: 'GET' },
        { url: '/api/$%7Be%7D', method: 'GET' },
        { url: 'https://app.example.invalid/api/%24%7Be%7D', method: 'POST' },
        { url: '/api/v1/widgets/:widgetId/qux', method: 'POST' },
      ],
    },
    ORIGIN,
  )
  assert.ok(routes.length >= 1)
  const serialized = JSON.stringify(routes)
  assert.equal(serialized.includes('${'), false, 'raw ${...} must not enter SPA routes')
  assert.equal(serialized.toLowerCase().includes('$%7b'), false, 'encoded $%7B must not enter SPA routes')
  assert.equal(serialized.toLowerCase().includes('%24%7b'), false, 'encoded %24%7B must not enter SPA routes')
  const widgetRoute = routes.find(r => r.path === '/widgets')
  assert.ok(widgetRoute?.stateActions?.includes('qux'), 'structural tail segment of mutating API call must populate stateActions without domain regex')
})

// ============================================================================
// 4. Generic Structural Collection/Member Grouping + End-to-End Phase-0 Filter
// ============================================================================

test('runPhase0Recon filters JS template artifacts and groups generic structural collection/member mutators without domain verbs', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => c.origin === ORIGIN)!
  const worker = storage.makeWorker(run, 'threat_model', asset, 'Recon', 'Map', { sourceOrigins: [ORIGIN] })

  const openApiPayload = JSON.stringify({
    openapi: '3.0.3',
    paths: {
      '/api/v1/widgets': {
        post: { operationId: 'createWidget', responses: { '201': { description: 'created' } } },
      },
      '/api/v1/widgets/{widgetId}': {
        patch: { operationId: 'mutateWidget', responses: { '200': { description: 'mutated' } } },
      },
      '/api/v1/widgets/{widgetId}/qux': {
        post: { operationId: 'quxWidget', responses: { '200': { description: 'done' } } },
      },
      '/api/${e}': {
        get: { operationId: 'badTemplate', responses: { '200': { description: 'bad' } } },
      },
    },
  })

  const bundleJs = `
    export async function run(e) {
      await fetch('/api/\${e}');
      await fetch('/api/$%7Be%7D');
      await fetch('/api/%24%7Be%7D');
      await fetch('/api/v1/catalog');
    }
  `

  const makeEx = (method: string, pathAndQuery: string, status: number, mediaType: string, body: string): BrokerExchangeResult => ({
    origin: ORIGIN, finalOrigin: ORIGIN, redirectOrigins: [], method, pathAndQuery,
    reqHeaders: {}, status, respHeaders: { 'content-type': mediaType }, setCookies: [],
    mediaType, body, bodyPreview: body.slice(0, 256), bodyBytes: Buffer.byteLength(body, 'utf8'),
    bodyTruncated: false, bodySha256: '0'.repeat(64), durationMs: 2, personaHandle: null,
    observation: { origin: ORIGIN, finalOrigin: ORIGIN, status, headers: { 'content-type': mediaType }, setCookies: [], bodyPreview: body.slice(0, 256), bodyBytes: Buffer.byteLength(body, 'utf8') },
  } as unknown as BrokerExchangeResult)

  const fakeBroker = {
    async executeHttp(req: { method?: string; pathAndQuery: string }): Promise<BrokerExchangeResult> {
      const m = (req.method ?? 'GET').toUpperCase()
      const p = req.pathAndQuery
      if (p === '/') return makeEx(m, p, 200, 'text/html', '<html><body><script src="/assets/app.js"></script><a href="/api/${e}">bad</a><a href="/api/$%7Be%7D">bad2</a></body></html>')
      if (p === '/assets/app.js') return makeEx(m, p, 200, 'application/javascript', bundleJs)
      if (p === '/openapi.json') return makeEx(m, p, 200, 'application/json', openApiPayload)
      return makeEx(m, p, 404, 'text/plain', 'not found')
    },
  } as unknown as RequestBroker

  await runPhase0Recon({
    storage, runId, scopeRevision: run.scopeRevision, tier: 2, origins: [ORIGIN],
    budgetRequests: 300, broker: fakeBroker,
    grant: { canRead: () => true, canWrite: () => true, personas: new Map() } as unknown as Grant,
    signal: new AbortController().signal, assignmentId: worker.id,
  })

  const endpoints = storage.listEndpoints(runId, { limit: 200 })
  for (const ep of endpoints) {
    assert.equal(hasUnexpandedJsTemplateArtifact(ep.pathTemplate), false, `template artifact leaked into endpoints: ${ep.method} ${ep.pathTemplate}`)
  }
  assert.ok(endpoints.some(ep => ep.pathTemplate === '/api/v1/widgets' && ep.method === 'POST'))

  // Generic structural collection -> member -> sub-route grouping emits edges for non-fintech `widgets` + `qux`
  const facts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
  const catalog = {
    apiDependencies: facts
      .filter(f => f.origin === ORIGIN && f.data?.subkind === 'runtime_api_dependencies' && Array.isArray(f.data?.apiDependencies))
      .flatMap(f => f.data!.apiDependencies as Array<{ producer: string; consumer: string }>),
  }
  assert.ok(
    catalog.apiDependencies.some(d => d.producer.includes('/api/v1/widgets') && d.consumer.includes('/api/v1/widgets/{widgetId}') && !d.consumer.includes('/qux')),
    `expected structural collection->member edge on widgets, got ${JSON.stringify(catalog.apiDependencies)}`,
  )
  assert.ok(
    catalog.apiDependencies.some(d => d.producer.includes('/api/v1/widgets/{widgetId}') && d.consumer.includes('/api/v1/widgets/{widgetId}/qux')),
    `expected structural member->subroute edge on widgets/qux, got ${JSON.stringify(catalog.apiDependencies)}`,
  )
})
