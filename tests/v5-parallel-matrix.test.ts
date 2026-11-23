/**
 * v5 M6 parallel-matrix throughput: stream semaphore/AIMD, RAM watermark guard, cell isolation,
 * cell-labeled reaping, warm-pool fallback and compact summary aggregation.
 *
 * Everything here is deterministic: the model gate uses a fake transport, the resource guard uses
 * an injected memory probe, and docker is a stub. A separate Docker-gated integration test lives
 * in the matrix runners' validation run, not in this file.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer, request } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, describe, test } from 'node:test'

import {
  AimdLimiter, CellReaper, ModelGate, ResourceGuard, Semaphore, cellLabel, defaultMaxInFlightStreams,
  parseRetryAfter, readMemAvailableBytes, rewriteProfileEndpoints,
} from '../scripts/benchmark-parallel.ts'
import { WarmWorkerPool, workerContainerCreateArgs } from '../src/server/worker-backend.ts'
import {
  cellChildArgs, cellEnv, parseMatrixArgs, renderParallelStatus, summarizeMatrix,
} from '../scripts/benchmark-agentic-matrix.ts'
import type { MatrixArgs, MatrixCell, MatrixCellResult } from '../scripts/benchmark-agentic-matrix.ts'
import { orchestrationEnv } from '../scripts/benchmark-realistic-matrix.ts'

const tempDirs: string[] = []
function tempDir(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `guardian-parallel-${label}-`))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

function cell(over: Partial<MatrixCell> = {}): MatrixCell {
  const base: MatrixCell = {
    app: 'acme-saas', seed: 42, mode: 'grey-box', seedSet: 'dev',
    label: 'acme-saas-seed42-grey-box',
  }
  return { ...base, ...over }
}

function matrixArgs(over: Partial<MatrixArgs> = {}): MatrixArgs {
  return {
    apps: ['acme-saas'], seeds: [42], modes: ['grey-box'], budgetUsd: 5,
    maxDurationMs: 1_200_000, concurrency: 3, outDir: '/tmp/parallel-matrix-test',
    dataDir: '/tmp/guardian-data', noLlm: false, verifier: 'docker',
    keepDataDirs: false, smoke: false, childTimeoutMs: 1_500_000, help: false,
    ...over,
  }
}

describe('semaphore', () => {
  test('caps in-flight permits and admits FIFO waiters', async () => {
    const sem = new Semaphore(2)
    assert.equal(sem.limit, 2)
    const releaseA = await sem.acquire()
    const releaseB = await sem.acquire()
    assert.equal(sem.inFlight, 2)
    let third = false
    const pending = sem.acquire().then(release => { third = true; return release })
    await Promise.resolve()
    assert.equal(third, false, 'third acquire must queue while at the cap')
    assert.equal(sem.queued, 1)
    releaseA()
    const releaseC = await pending
    assert.equal(third, true)
    assert.equal(sem.inFlight, 2)
    assert.equal(sem.peak, 2)
    releaseB()
    releaseC()
    assert.equal(sem.inFlight, 0)
  })

  test('shrinking the limit does not over-admit and release wakes the queue', async () => {
    const sem = new Semaphore(4)
    const held = [await sem.acquire(), await sem.acquire(), await sem.acquire()]
    sem.setLimit(1)
    let admitted = false
    const pending = sem.acquire().then(release => { admitted = true; return release })
    await Promise.resolve()
    assert.equal(admitted, false)
    held.forEach(release => release())
    const release = await pending
    assert.equal(admitted, true)
    assert.equal(sem.inFlight, 1)
    release()
  })

  test('aborted waiters reject without leaking a slot', async () => {
    const sem = new Semaphore(1)
    const release = await sem.acquire()
    const controller = new AbortController()
    const pending = sem.acquire(controller.signal)
    controller.abort()
    await assert.rejects(pending, /aborted/i)
    assert.equal(sem.queued, 0)
    release()
    assert.equal(sem.inFlight, 0)
  })
})

describe('AIMD limiter and 429 backoff', () => {
  test('parseRetryAfter honours seconds and HTTP dates with a ceiling', () => {
    const now = Date.parse('2026-11-22T00:00:00Z')
    assert.equal(parseRetryAfter('2', now), 2_000)
    assert.equal(parseRetryAfter('0.25', now), 250)
    assert.equal(parseRetryAfter('Sun, 22 Nov 2026 00:00:03 GMT', now), 3_000)
    assert.equal(parseRetryAfter('120', now), 30_000)
    assert.equal(parseRetryAfter(null, now, 500), 500)
    assert.equal(parseRetryAfter('garbage', now, 700), 700)
  })

  test('429 shrinks the ceiling, records Retry-After and recovers additively', async () => {
    const sleeps: number[] = []
    let clock = 1_000
    const limiter = new AimdLimiter({
      maxInFlight: 20, minInFlight: 4, increaseEvery: 2,
      now: () => clock,
      sleep: async ms => { sleeps.push(ms); clock += ms },
    })
    limiter.onRateLimited(250)
    assert.equal(limiter.stats().limit, 14)
    assert.equal(limiter.stats().decreases, 1)
    assert.equal(limiter.cooldownRemainingMs, 250)
    const release = await limiter.acquire()
    assert.deepEqual(sleeps, [250], 'acquisition waits out Retry-After')
    release()
    limiter.onSuccess()
    limiter.onSuccess()
    assert.equal(limiter.stats().limit, 15)
    assert.equal(limiter.stats().increases, 1)
  })
})

describe('model gate', () => {
  test('honours 429 Retry-After, retries the same request and caps live streams', async () => {
    const delays: number[] = []
    let clock = 0
    let calls = 0
    const fetchImpl = (async () => {
      calls += 1
      if (calls === 1) {
        return new Response('rate limited', { status: 429, headers: { 'retry-after': '0.05' } })
      }
      return new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } })
    }) as typeof fetch
    const gate = new ModelGate({
      maxInFlightStreams: 8, fetchImpl,
      now: () => clock,
      sleep: async ms => { delays.push(ms); clock += ms },
    })
    const response = await gate.forward('https://example.invalid/v1/responses', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: Buffer.from('{}'),
    })
    assert.equal(response.status, 200)
    assert.equal(await response.text(), 'ok')
    assert.deepEqual(delays, [50])
    const stats = gate.stats()
    assert.equal(calls, 2)
    assert.equal(stats.retries, 1)
    assert.equal(stats.rateLimited, 1)
    assert.equal(stats.limit, 5) // floor(8 * 0.7)
    assert.equal(stats.inFlight, 0, 'permit released after the stream is consumed')
  })

  test('releases the permit when the transport throws', async () => {
    let calls = 0
    const gate = new ModelGate({
      maxInFlightStreams: 2,
      fetchImpl: (async () => { calls += 1; throw new Error('socket closed') }) as typeof fetch,
    })
    await assert.rejects(() => gate.forward('https://example.invalid/x', {
      method: 'POST', headers: {}, body: Buffer.from('{}'),
    }), /socket closed/)
    assert.equal(gate.stats().inFlight, 0)
    assert.equal(calls, 1)
  })

  test('holds the permit until the response body is read, then releases exactly once', async () => {
    const gate = new ModelGate({
      maxInFlightStreams: 1,
      fetchImpl: (async () => new Response(new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('a'))
          controller.close()
        },
      }), { status: 200 })) as typeof fetch,
    })
    const response = await gate.forward('https://example.invalid/x', { method: 'POST', headers: {}, body: Buffer.from('{}') })
    assert.equal(gate.stats().inFlight, 1)
    assert.equal(await response.text(), 'a')
    assert.equal(gate.stats().inFlight, 0)
  })

  test('proxies a real loopback upstream and routes the profile endpoint through the gate', async () => {
    const upstream = createServer((req, res) => {
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        res.end(`data: ${req.url}:${body.length}\n\n`)
      })
    })
    await new Promise<void>(resolve => upstream.listen(0, '127.0.0.1', resolve))
    const upstreamPort = (upstream.address() as AddressInfo).port
    const gate = new ModelGate({ maxInFlightStreams: 4 })
    await gate.start()
    try {
      const endpoint = gate.endpointFor(`http://127.0.0.1:${upstreamPort}/v1`)
      assert.match(endpoint, /^http:\/\/127\.0\.0\.1:\d+\/g\//)
      const response = await fetch(`${endpoint}/responses`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"x":1}',
      })
      assert.equal(response.status, 200)
      assert.match(await response.text(), /\/v1\/responses:7/)
      assert.equal(gate.stats().inFlight, 0)
    } finally {
      await gate.close()
      await new Promise<void>(resolve => upstream.close(() => resolve()))
    }
  })

  test('aborted downstream cancels the upstream stream and releases the permit', async () => {
    const upstream = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      const timer = setInterval(() => res.write('data: x\n\n'), 20)
      req.on('close', () => { clearInterval(timer); res.end() })
    })
    await new Promise<void>(resolve => upstream.listen(0, '127.0.0.1', resolve))
    const upstreamPort = (upstream.address() as AddressInfo).port
    const gate = new ModelGate({ maxInFlightStreams: 2 })
    await gate.start()
    try {
      const endpoint = gate.endpointFor(`http://127.0.0.1:${upstreamPort}/v1`)
      await new Promise<void>((resolve, reject) => {
        const req = request(`${endpoint}/responses`, { method: 'POST', headers: { 'content-type': 'application/json' } }, response => {
          response.once('data', () => { req.destroy(); resolve() })
        })
        req.once('error', error => { if (!/socket hang up|ECONNRESET/.test(String(error))) reject(error) })
        req.end('{}')
      })
      for (let i = 0; i < 50 && gate.stats().inFlight > 0; i += 1) {
        await new Promise(resolve => setTimeout(resolve, 20))
      }
      assert.equal(gate.stats().inFlight, 0, 'permit released after downstream abort')
      await Promise.race([
        gate.close(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('gate.close hung')), 2_000)),
      ])
    } finally {
      await upstream.close()
    }
  })

  test('caps concurrent streams at maxInFlightStreams across callers', async () => {
    const pending: Array<{ id: number; run: () => void }> = []
    let fetchId = 0
    const fetchImpl = (async () => new Promise<Response>(resolve => {
      const id = ++fetchId
      pending.push({ id, run: () => resolve(new Response('ok', { status: 200 })) })
    })) as typeof fetch
    const gate = new ModelGate({ maxInFlightStreams: 2, fetchImpl })
    const request = () => gate.forward('https://example.invalid/x', { method: 'POST', headers: {}, body: Buffer.from('{}') })
    const first = request()
    const second = request()
    const third = request()
    const waitFor = async (predicate: () => boolean) => {
      for (let i = 0; i < 40 && !predicate(); i += 1) await new Promise(resolve => setTimeout(resolve, 5))
    }
    await waitFor(() => pending.length >= 2)
    assert.equal(pending.length, 2, 'only two requests reach the transport')
    assert.equal(gate.stats().inFlight, 2)
    assert.equal(gate.stats().queued, 1, 'third request queues, never drops')
    pending.shift()!.run()
    const firstResponse = await first
    await firstResponse.text()
    await waitFor(() => pending.length >= 2)
    assert.equal(pending.length, 2, 'queued request is admitted after a permit frees')
    pending.shift()!.run()
    pending.shift()!.run()
    const [secondResponse, thirdResponse] = await Promise.all([second, third])
    await Promise.all([secondResponse.text(), thirdResponse.text()])
    assert.equal(gate.stats().peak, 2)
    assert.equal(gate.stats().inFlight, 0)
  })

  test('two gates bind distinct ephemeral loopback ports', async () => {
    const a = new ModelGate({ maxInFlightStreams: 4 })
    const b = new ModelGate({ maxInFlightStreams: 4 })
    await a.start(); await b.start()
    try {
      assert.notEqual(a.port, b.port)
      assert.notEqual(a.endpointFor('https://one.invalid/v1'), b.endpointFor('https://one.invalid/v1'))
    } finally { await a.close(); await b.close() }
  })
})

describe('resource watermark guard', () => {
  test('pauses on low RAM and resumes when memory recovers', async () => {
    const snapshots = [
      { memAvailableBytes: 2 * 1024 ** 3, activeWorkers: 2 },
      { memAvailableBytes: 3 * 1024 ** 3, activeWorkers: 2 },
      { memAvailableBytes: 12 * 1024 ** 3, activeWorkers: 2 },
    ]
    const pauses: string[] = []
    const resumes: string[] = []
    const guard = new ResourceGuard({
      minFreeMemBytes: 6 * 1024 ** 3,
      maxActiveWorkers: 16,
      probe: () => snapshots.shift()!,
      sleep: async () => undefined,
      now: () => 1_700_000_000_000,
      onPause: event => pauses.push(event.reason),
      onResume: event => resumes.push(event.reason),
    })
    await guard.waitForCapacity()
    assert.deepEqual(pauses, ['ram'])
    assert.deepEqual(resumes, ['ram'])
    assert.equal(guard.events.length, 1)
    assert.ok(guard.events[0]!.resumedAt !== undefined)
    assert.equal(guard.paused, false)
  })

  test('pauses on worker saturation, and only once per episode', async () => {
    let calls = 0
    const guard = new ResourceGuard({
      minFreeMemBytes: 0,
      maxActiveWorkers: 16,
      probe: () => {
        calls += 1
        return { memAvailableBytes: 32 * 1024 ** 3, activeWorkers: calls <= 3 ? 16 : 15 }
      },
      sleep: async () => undefined,
    })
    await guard.waitForCapacity()
    assert.equal(guard.events.length, 1)
    assert.equal(guard.events[0]!.reason, 'workers')
    assert.equal(calls, 4)
  })

  test('readMemAvailableBytes returns a positive byte count', () => {
    const bytes = readMemAvailableBytes()
    assert.ok(bytes > 0)
  })
})

describe('cell isolation', () => {
  test('agentic cells get unique data dirs, labels and run labels', () => {
    const args = matrixArgs({
      apps: ['acme-saas', 'shopflow'], seeds: [42], modes: ['grey-box'], modelGate: true,
    })
    const a = cellEnv(cell(), args)
    const b = cellEnv(cell({ app: 'shopflow', label: 'shopflow-seed42-grey-box' }), args)
    assert.notEqual(a.GUARDIAN_DATA_DIR, b.GUARDIAN_DATA_DIR)
    assert.notEqual(a.GUARDIAN_CELL_ID, b.GUARDIAN_CELL_ID)
    assert.match(a.GUARDIAN_DATA_DIR!, /data\/acme-saas-seed42-grey-box$/)
    assert.equal(a.GUARDIAN_RUN_LABEL, a.GUARDIAN_CELL_ID)
    assert.equal(a.GUARDIAN_WARM_WORKERS, '1')
    assert.equal(cellEnv(cell(), { ...args, warmWorkers: false }).GUARDIAN_WARM_WORKERS, '0')
  })

  test('prepared per-cell data dir override replaces the shared --data-dir', () => {
    const args = matrixArgs({
      dataDirOverrides: { 'acme-saas-seed42-grey-box': '/tmp/cells/a/source' },
    })
    const argv = cellChildArgs(cell(), args)
    const at = argv.indexOf('--data-dir')
    assert.equal(argv[at + 1], '/tmp/cells/a/source')
    assert.ok(argv.includes('--isolate-data-dir'))
  })

  test('realistic matrix cells get unique cell ids and data dirs', () => {
    const opts = {
      suite: 'realistic' as const, apps: ['acme-saas'], seeds: [42], split: 'dev' as const,
      concurrency: 2, outDir: '/tmp/rb-matrix-iso', timeoutMs: 1_000, mode: 'grey-box',
      profileMode: 'v4-full', minFreeMemGb: 6, maxActiveWorkers: 16, warmWorkers: true,
    }
    const a = orchestrationEnv(opts, { app: 'acme-saas', seed: 42 })
    const b = orchestrationEnv(opts, { app: 'shopflow', seed: 42 })
    assert.notEqual(a.GUARDIAN_CELL_ID, b.GUARDIAN_CELL_ID)
    assert.notEqual(a.GUARDIAN_DATA_DIR, b.GUARDIAN_DATA_DIR)
    assert.equal(a.GUARDIAN_ALLOW_LOCAL_LAB, '1')
  })

  test('cellLabel yields a docker-safe, collapsed label', () => {
    assert.equal(cellLabel('acme/saas seed 42'), 'acme-saas-seed-42')
    assert.equal(cellLabel('***'), 'cell')
    assert.ok(cellLabel('x'.repeat(200)).length <= 63)
  })

  test('rewriteProfileEndpoints routes only enabled profiles through the gate', () => {
    const dir = tempDir('profiles')
    const db = new DatabaseSync(join(dir, 'guardian.sqlite'))
    db.exec('create table model_profiles (id text primary key, endpoint text, enabled integer, updated_at integer)')
    db.prepare('insert into model_profiles values (?,?,?,?)').run('on', 'https://openrouter.ai/api/v1', 1, 0)
    db.prepare('insert into model_profiles values (?,?,?,?)').run('off', 'https://disabled.invalid/v1', 0, 0)
    db.close()
    const result = rewriteProfileEndpoints(dir, endpoint => `http://127.0.0.1:9999/g/${Buffer.from(endpoint).toString('base64url')}`)
    assert.equal(result.updated, 1)
    assert.deepEqual(result.endpoints, ['https://openrouter.ai/api/v1'])
    const check = new DatabaseSync(join(dir, 'guardian.sqlite'), { readOnly: true })
    const rows = check.prepare('select id, endpoint from model_profiles order by id').all() as Array<{ id: string; endpoint: string }>
    check.close()
    assert.match(rows.find(row => row.id === 'on')!.endpoint, /^http:\/\/127\.0\.0\.1:9999\/g\//)
    assert.equal(rows.find(row => row.id === 'off')!.endpoint, 'https://disabled.invalid/v1')
  })
})

describe('cell-labeled reaper', () => {
  test('removes only containers from its own cell labels', async () => {
    const queries: string[] = []
    const removals: string[][] = []
    const live = new Set(['id-a', 'id-b'])
    const docker = async (args: string[]) => {
      if (args[0] === 'ps') {
        const filter = args.find(arg => arg.startsWith('label=dev.guardian.cell='))!
        queries.push(filter)
        const id = filter.endsWith('cell-a') ? 'id-a' : filter.endsWith('cell-b') ? 'id-b' : ''
        return live.has(id) ? id : ''
      }
      if (args[0] === 'rm') {
        removals.push(args.slice(2))
        for (const id of args.slice(2)) live.delete(id)
        return ''
      }
      return ''
    }
    const reaper = new CellReaper(['cell-a', 'cell-b'], { dockerRunner: docker })
    assert.equal(await reaper.reap('foreign'), 0, 'foreign labels are never queried')
    assert.equal(queries.length, 0)
    assert.equal(await reaper.reap('cell-a'), 1)
    assert.deepEqual(removals, [['id-a']])
    assert.equal(await reaper.reapAll(), 1)
    assert.deepEqual(removals.slice(1).sort(), [['id-b']])
    assert.ok(queries.every(query => query.startsWith('label=dev.guardian.cell=')))
  })

  test('orphans() lists only owned labels', async () => {
    const docker = async (args: string[]) => {
      if (args[0] === 'ps') return args.some(arg => arg.endsWith('cell-a')) ? 'id-a' : ''
      return ''
    }
    const reaper = new CellReaper(['cell-a'], { dockerRunner: docker })
    assert.equal(await reaper.orphans(), 1)
  })
})

describe('warm worker pool', () => {
  const dockerArgs: string[][] = []
  const runner = async (args: string[]) => { dockerArgs.push(args); return '' }

  test('pre-creates one labeled session container with the hardened flags intact', async () => {
    dockerArgs.length = 0
    const pool = new WarmWorkerPool({
      cell: 'cell-a', image: 'guardian-worker:v4', dockerRunner: runner, runLabel: 'cell-a',
    })
    const name = await pool.warm()
    assert.ok(name && name.startsWith('guardian-'))
    assert.equal(pool.state, 'ready')
    const create = dockerArgs.find(args => args[0] === 'container' && args[1] === 'create')!
    for (const flag of ['--network', '--user', '--read-only', '--cap-drop', '--security-opt']) {
      assert.ok(create.includes(flag), `missing ${flag}`)
    }
    assert.ok(create.includes('dev.guardian.cell=cell-a'))
    assert.ok(create.includes('dev.guardian.warm=1'))
    assert.ok(create.includes('--session'))
    const taken = await pool.take(new AbortController().signal)
    assert.equal(taken, name)
    await pool.close()
  })

  test('falls back to cold create when the image is unavailable', async () => {
    const pool = new WarmWorkerPool({
      cell: 'cell-b', image: 'missing:v0', runLabel: 'cell-b',
      dockerRunner: async () => { throw new Error('Unable to find image missing:v0 locally') },
    })
    assert.equal(await pool.warm(), null)
    assert.equal(pool.state, 'disabled')
    assert.equal(await pool.take(new AbortController().signal), null)
    assert.equal(pool.stats.failures, 1)
  })

  test('does not hand out a container for mismatched session options', async () => {
    const pool = new WarmWorkerPool({
      cell: 'cell-c', image: 'guardian-worker:v4', dockerRunner: runner, runLabel: 'cell-c',
    })
    await pool.warm()
    const taken = await pool.take(new AbortController().signal, { memoryMb: 4096, reposDir: '/tmp' })
    assert.equal(taken, null)
    await pool.close()
  })

  test('container builder keeps security flags and adds the cell label', () => {
    const args = workerContainerCreateArgs({
      image: 'guardian-worker:v4', name: 'guardian-test', assignmentId: 'a',
      runLabel: 'run', cell: 'cell-z',
    })
    assert.ok(args.includes('--read-only'))
    assert.ok(args.includes('--cap-drop') && args.includes('ALL'))
    assert.ok(args.includes('--security-opt') && args.includes('no-new-privileges'))
    assert.ok(args.includes('--user') && args.includes('10001:10001'))
    assert.ok(args.includes('dev.guardian.cell=cell-z'))
  })
})

describe('matrix summary', () => {
  function result(over: Partial<MatrixCellResult> = {}): MatrixCellResult {
    return {
      app: 'acme-saas', seed: 42, mode: 'grey-box', seedSet: 'dev',
      label: 'acme-saas-seed42-grey-box', ok: true, exitCode: 0, runtimeMs: 60_000,
      confirmed: 3, targets: 10, precision: 1, decoyFp: 0, decoys: 2, unmatchedFp: 0,
      costUsd: 0.2, wallMs: 55_000, surface: 5, facts: 4,
      assignments: {
        total: 2, completed: 2, failed: 0, canceled: 0,
        investigationTotal: 2, investigationCompleted: 2, investigationFailed: 0,
      },
      funnel: {
        targetVulns: 10, surfaceDiscovered: 5, hypothesisFormed: 4,
        signalObserved: 3, specSubmitted: 3, zeroLlmConfirmed: 3,
      },
      failureBuckets: { timeout: 1 }, inert: false, workerSessions: true,
      agenticExpected: true, modelMode: 'agentic', verifierBackend: 'docker',
      timedOut: false, terminalStatus: 'complete', jsonPath: '/tmp/x.json', metaPath: '/tmp/x.meta.json',
      lockError: false, configError: false,
      ...over,
    }
  }

  test('aggregates cells with distinct isolation labels', () => {
    const totals = summarizeMatrix([
      result(),
      result({
        label: 'shopflow-seed42-grey-box', app: 'shopflow', confirmed: 1, targets: 5,
        costUsd: 0.1, wallMs: 45_000, decoys: 1, decoyFp: 0, unmatchedFp: 1,
        assignments: { total: 1, completed: 1, failed: 0, canceled: 0, investigationTotal: 1, investigationCompleted: 1, investigationFailed: 0 },
      }),
    ])
    assert.equal(totals.cells, 2)
    assert.equal(totals.confirmed, 4)
    assert.equal(totals.targets, 15)
    assert.equal(totals.unmatchedFp, 1)
    assert.ok(Math.abs(totals.costUsd - 0.3) < 1e-9)
    assert.equal(totals.wallMs, 100_000)
  })

  test('parallel status reports gate, pauses and orphans', () => {
    const line = renderParallelStatus({
      gate: { limit: 19, inFlight: 2, queued: 1, peak: 28, rateLimited: 3, retries: 2, decreases: 1, increases: 0 },
      gatePort: 1234,
      pauses: [{ at: 5_000, reason: 'ram', memGiB: 4.2, workers: 6, resumedAt: 9_000 }],
      orphans: 0,
    })
    assert.match(line, /gate=max19 peak=28 queued=1 429=3 retries=2/)
    assert.match(line, /pauses=1 \[ram@5s\(4\.2GiB\/6w resume@9s\)\]/)
    assert.match(line, /orphans=0/)
  })
})

describe('CLI defaults', () => {
  test('agentic matrix defaults enable gate, warm workers and watermarks', () => {
    const args = parseMatrixArgs(['--apps', 'acme-saas', '--seeds', '42', '--data-dir', '/tmp/gd'], {
      GUARDIAN_RB_HELDOUT_SALT: 'a'.repeat(48),
    } as NodeJS.ProcessEnv)
    assert.equal(args.modelGate, true)
    assert.equal(args.warmWorkers, true)
    assert.equal(args.maxInFlightStreams, 28)
    assert.equal(args.minFreeMemGb, 6)
    assert.equal(args.maxActiveWorkers, 16)
  })

  test('escape hatches disable the gate and warm pool', () => {
    const args = parseMatrixArgs(
      ['--apps', 'acme-saas', '--seeds', '42', '--data-dir', '/tmp/gd', '--no-warm-workers', '--no-model-gate'],
      {} as NodeJS.ProcessEnv,
    )
    assert.equal(args.warmWorkers, false)
    assert.equal(args.modelGate, false)
    const envArgs = parseMatrixArgs(['--apps', 'acme-saas', '--seeds', '42', '--data-dir', '/tmp/gd'], {
      GUARDIAN_WARM_WORKERS: '0', GUARDIAN_MODEL_GATE: '0',
    } as NodeJS.ProcessEnv)
    assert.equal(envArgs.warmWorkers, false)
    assert.equal(envArgs.modelGate, false)
  })

  test('per-cell env marks the cell for the worker backend label', () => {
    const env = cellEnv(cell(), matrixArgs())
    assert.equal(env.GUARDIAN_CELL_ID, 'acme-saas-seed42-grey-box')
    assert.equal(env.GUARDIAN_ALLOW_LOCAL_LAB, '1')
  })

  test('global stream cap is env-overridable and clamped', () => {
    assert.equal(defaultMaxInFlightStreams({} as NodeJS.ProcessEnv), 28)
    assert.equal(defaultMaxInFlightStreams({ GUARDIAN_MODEL_MAX_STREAMS: '12' } as NodeJS.ProcessEnv), 12)
    assert.equal(defaultMaxInFlightStreams({ GUARDIAN_MODEL_MAX_STREAMS: '0' } as NodeJS.ProcessEnv), 28)
    assert.equal(defaultMaxInFlightStreams({ GUARDIAN_MODEL_MAX_STREAMS: '9999' } as NodeJS.ProcessEnv), 256)
  })
})
