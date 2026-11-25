/**
 * Option 2 Move 5A — Bounded `UntrustedComputePool` (`worker_threads`) & Unified `ContainerSupervisor`.
 *
 * Covers:
 *   1. `parseComposeInWorker` & `runUntrustedTask` inside bounded V8 `resourceLimits` workers
 *   2. Synchronous `parseCompose` compatibility & `ComposeParseError` preservation across IPC
 *   3. Hard wall-clock `timeoutMs` -> `worker.terminate()` on infinite loops while main event loop
 *      remains responsive, plus bounded concurrency & queue-full backpressure
 *   4. `ContainerSupervisor` owner-PID labeling, live-PID protection, `recoverAll()` orphan Docker
 *      reaping (keeping SQLite rows `'orphaned'` if Docker `rm` fails), and shared supervisor/runner
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'
import { ComposeParseError, parseCompose, parseComposeDocument } from '../src/server/compose-parse.ts'
import {
  ContainerSupervisor,
  LAB_OWNER_PID_LABEL,
  getSharedContainerSupervisor,
} from '../src/server/container-supervisor.ts'
import { LAB_LABELS, LabRunner, getSharedLabRunner } from '../src/server/lab-runner.ts'
import type { DockerRunner, LabContainerStore } from '../src/server/lab-runner.ts'
import type { Store } from '../src/server/store.ts'
import {
  DEFAULT_WORKER_RESOURCE_LIMITS,
  UntrustedComputePool,
  UntrustedComputeQueueFullError,
  UntrustedComputeTimeoutError,
  getSharedUntrustedComputePool,
  parseComposeInWorker,
  runUntrustedTask,
} from '../src/server/untrusted-compute-pool.ts'

test('parseComposeInWorker parses valid compose YAML in worker_threads and preserves ComposeParseError', async t => {
  t.after(async () => {
    await getSharedUntrustedComputePool().close()
  })

  const yaml = [
    'x-base: &base_env',
    '  LOG_LEVEL: ${LOG_LEVEL:-info}',
    'services:',
    '  db:',
    '    image: postgres:16',
    '  app:',
    '    image: node:24-bookworm-slim',
    '    expose:',
    '      - "8080"',
    '    depends_on:',
    '      - db',
    '    environment:',
    '      <<: *base_env',
    '      PORT: "8080"',
    '    healthcheck:',
    '      test: ["CMD", "curl", "-f", "http://127.0.0.1:8080/healthz"]',
  ].join('\n')

  const syncDoc = parseCompose(yaml, { env: {} })
  const workerDoc = await parseComposeInWorker(yaml, { env: {}, timeoutMs: 5_000 })
  assert.deepEqual(workerDoc, syncDoc)
  assert.equal(workerDoc.services.length, 2)
  assert.equal(workerDoc.services[1].normalized.environment?.LOG_LEVEL, 'info')

  // Host process.env must never leak into the worker even if passed directly.
  const prevLeakTest = process.env.KOVO_TEST_HOST_SECRET
  process.env.KOVO_TEST_HOST_SECRET = 'do-not-leak'
  try {
    await assert.rejects(
      () => parseComposeInWorker(
        'services:\n  app:\n    image: node:24\n    command: ${KOVO_TEST_HOST_SECRET}\n',
        { env: process.env as Record<string, string | undefined> },
      ),
      err => err instanceof ComposeParseError && /KOVO_TEST_HOST_SECRET/.test(err.message),
    )
  } finally {
    if (prevLeakTest === undefined) delete process.env.KOVO_TEST_HOST_SECRET
    else process.env.KOVO_TEST_HOST_SECRET = prevLeakTest
  }

  // Verify ComposeParseError lineNumber is preserved across worker IPC.
  await assert.rejects(
    () => parseComposeInWorker('services:\n\tbad: true\n'),
    err => err instanceof ComposeParseError && err.lineNumber === 2,
  )

  // Generic runUntrustedTask kinds work cleanly too.
  const parsedJson = await runUntrustedTask<{ ok: boolean }>('parse_json', { text: '{"ok":true}' })
  assert.deepEqual(parsedJson, { ok: true })
  const parsedEnv = await runUntrustedTask<Record<string, string>>('parse_compose_env', {
    content: '# comment\nPORT=8080\nHOST="127.0.0.1"\n',
  })
  assert.deepEqual(parsedEnv, { PORT: '8080', HOST: '127.0.0.1' })
  assert.equal(typeof parseComposeDocument, 'function')
})

test('UntrustedComputePool terminates infinite/pathological worker tasks on timeoutMs while main event loop stays responsive', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-compute-pool-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const testWorkerPath = join(dir, 'adversarial-worker.mjs')
  writeFileSync(
    testWorkerPath,
    [
      "import { parentPort } from 'node:worker_threads'",
      "parentPort.on('message', msg => {",
      "  if (msg.kind === 'spin') {",
      '    while (true) {}',
      '  }',
      "  if (msg.kind === 'slow_ok') {",
      '    setTimeout(() => parentPort.postMessage({ id: msg.id, ok: true, result: msg.payload }), 60)',
      '    return',
      '  }',
      "  parentPort.postMessage({ id: msg.id, ok: true, result: { echoed: msg.payload } })",
      '})',
    ].join('\n'),
  )

  const pool = new UntrustedComputePool({
    maxConcurrency: 1,
    maxQueueSize: 1,
    defaultTimeoutMs: 120,
    resourceLimits: {
      maxOldGenerationSizeMb: 32,
      maxYoungGenerationSizeMb: 8,
      stackSizeMb: 2,
    },
    workerEntry: pathToFileURL(testWorkerPath),
  })
  t.after(() => pool.close())

  assert.equal(DEFAULT_WORKER_RESOURCE_LIMITS.maxOldGenerationSizeMb, 64)
  assert.equal(DEFAULT_WORKER_RESOURCE_LIMITS.maxYoungGenerationSizeMb, 16)

  // Prove main thread event loop keeps ticking smoothly while worker spins infinitely.
  let mainThreadTicks = 0
  const tickTimer = setInterval(() => {
    mainThreadTicks += 1
  }, 10)
  const startedAt = Date.now()
  try {
    await assert.rejects(
      () => pool.run('spin', {}, { timeoutMs: 100 }),
      err => err instanceof UntrustedComputeTimeoutError && err.timeoutMs === 100,
    )
  } finally {
    clearInterval(tickTimer)
  }
  const elapsedMs = Date.now() - startedAt
  assert.ok(elapsedMs < 1_500, `hard wall-clock termination should finish quickly, took ${elapsedMs}ms`)
  assert.ok(mainThreadTicks >= 3, `main thread event loop must remain responsive (ticks=${mainThreadTicks})`)

  // Pool must recover with a fresh replacement worker after termination.
  const afterRecovery = await pool.run<{ echoed: string }>('echo', 'healthy-again', { timeoutMs: 2_000 })
  assert.deepEqual(afterRecovery, { echoed: 'healthy-again' })

  // Bounded concurrency (1) + bounded queue (1): 3rd simultaneous task hits backpressure immediately.
  const first = pool.run('slow_ok', 'one', { timeoutMs: 2_000 })
  const second = pool.run('slow_ok', 'two', { timeoutMs: 2_000 })
  await assert.rejects(
    () => pool.run('slow_ok', 'three', { timeoutMs: 2_000 }),
    err => err instanceof UntrustedComputeQueueFullError && err.maxQueueSize === 1,
  )
  assert.deepEqual(await Promise.all([first, second]), ['one', 'two'])
})

test('ContainerSupervisor tracks owner-PID labels, skips live sibling PIDs, and reaps orphans on recoverAll', async t => {
  const workspace = mkdtempSync(join(tmpdir(), 'kovo-supervisor-'))
  t.after(() => rmSync(workspace, { recursive: true, force: true }))
  const stateDir = join(workspace, 'state')
  const repoDir = join(workspace, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), "require('http').createServer((_q, r) => r.end('ok')).listen(8080)\n")

  const live = new Map<string, { id: string; runId: string; ownerPid?: string }>()
  const removedContainers: string[] = []
  let failRmFor = new Set<string>()
  const servers: Array<{ close: (cb: () => void) => void }> = []
  let seq = 0

  const docker: DockerRunner = async args => {
    if (args[0] === 'network' || args[0] === 'volume' || args[0] === 'build' || args[0] === 'exec') return ''
    if (args[0] === 'run') {
      const name = args[args.indexOf('--name') + 1]
      if (name.includes('-proxy-')) {
        const mountArg = args.find(arg => arg.startsWith('type=bind,source=')) ?? ''
        const dir = mountArg.slice('type=bind,source='.length, mountArg.indexOf(',target='))
        const server = createServer(socket => {
          socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'))
          socket.on('error', () => undefined)
        })
        await new Promise<void>(resolvePromise => server.listen(join(dir, 'proxy.sock'), resolvePromise))
        servers.push(server)
      }
      seq += 1
      let runId = ''
      let ownerPid: string | undefined
      for (let i = 0; i < args.length; i += 1) {
        if (args[i] === '--label') {
          const val = args[i + 1] ?? ''
          if (val.startsWith(`${LAB_LABELS.run}=`)) runId = val.slice(LAB_LABELS.run.length + 1)
          if (val.startsWith(`${LAB_OWNER_PID_LABEL}=`)) ownerPid = val.slice(LAB_OWNER_PID_LABEL.length + 1)
        }
      }
      live.set(name, { id: `c${String(seq).padStart(11, '0')}`, runId, ownerPid })
      return ''
    }
    if (args[0] === 'ps' && args[1] === '-aq') {
      const filter = args.find(a => a.startsWith('label=')) ?? ''
      if (filter === `label=${LAB_LABELS.lab}=1`) {
        return [...live.keys()].join('\n')
      }
      if (filter.startsWith(`label=${LAB_LABELS.run}=`)) {
        const targetRun = filter.slice(`label=${LAB_LABELS.run}=`.length)
        return [...live.entries()].filter(([, v]) => v.runId === targetRun).map(([k]) => k).join('\n')
      }
      return ''
    }
    if (args[0] === 'inspect') {
      const format = args[2] ?? ''
      if (format.includes(LAB_OWNER_PID_LABEL)) {
        const targets = args.slice(3)
        return targets
          .map(name => {
            const entry = live.get(name)
            return entry ? `${entry.runId}\t${entry.ownerPid ?? ''}` : ''
          })
          .filter(Boolean)
          .join('\n')
      }
      const name = args[args.length - 1]
      const entry = live.get(name)
      if (!entry) throw new Error(`Error: No such container: ${name}`)
      if (format === '{{.Id}}') return entry.id
      if (format.includes('NetworkSettings')) return '172.18.0.10'
      if (format.includes('Labels')) return entry.runId
      return 'running exit=0'
    }
    if (args[0] === 'container' && args[1] === 'rm') {
      const targets = args.slice(3)
      for (const target of targets) {
        if (failRmFor.has(target)) throw new Error(`simulated rm failure for ${target}`)
        live.delete(target)
        removedContainers.push(target)
      }
      return ''
    }
    return ''
  }

  t.after(async () => {
    await Promise.all(servers.map(s => new Promise<void>(r => s.close(() => r()))))
  })

  const rows = new Map<string, { runId: string; containerName: string; status: string }>()
  const store: LabContainerStore & {
    deleteLabContainer: (runId: string, containerName: string) => void
    listOrphanedLabContainers: () => Array<{ runId: string; containerName: string; status: string }>
  } = {
    recordLabContainer(input) {
      rows.set(`${input.runId}/${input.containerName}`, {
        runId: input.runId,
        containerName: input.containerName,
        status: input.status ?? 'running',
      })
    },
    markLabContainerOrphaned(runId, containerName) {
      const row = rows.get(`${runId}/${containerName}`)
      if (row) row.status = 'orphaned'
    },
    listLabContainers(runId) {
      return [...rows.values()].filter(r => r.runId === runId)
    },
    listOrphanedLabContainers() {
      return [...rows.values()].filter(r => r.status === 'orphaned')
    },
    deleteLabContainer(runId, containerName) {
      rows.delete(`${runId}/${containerName}`)
    },
  }

  const supervisor = new ContainerSupervisor({
    docker,
    stateDir,
    ownerPid: 4242,
    isPidAlive: pid => pid === 7777, // 7777 is alive sibling; 9999 is dead crashed PID
  })

  // Seed: 1 dead-PID orphan, 1 live-sibling container, and 1 SQLite-only orphaned container.
  live.set('kovo-lab-dead-orphan', { id: 'c000000000991', runId: 'run-dead-pid', ownerPid: '9999' })
  store.recordLabContainer({ runId: 'run-dead-pid', containerName: 'kovo-lab-dead-orphan', status: 'orphaned' })

  live.set('kovo-lab-live-sibling', { id: 'c000000000992', runId: 'run-live-sibling', ownerPid: '7777' })
  live.set('kovo-lab-store-orphan', { id: 'c000000000993', runId: 'run-store-orphan', ownerPid: '9999' })
  store.recordLabContainer({ runId: 'run-store-orphan', containerName: 'kovo-lab-store-orphan', status: 'orphaned' })

  // If rm fails on kovo-lab-store-orphan, recoverAll must keep its SQLite row as 'orphaned'.
  failRmFor.add('kovo-lab-store-orphan')
  const firstPass = await supervisor.recoverAll(store)
  assert.ok(firstPass.some(r => r.runId === 'run-dead-pid' && r.containersRemoved >= 1))
  assert.equal(live.has('kovo-lab-dead-orphan'), false, 'dead-PID orphan must be reaped')
  assert.equal(store.listLabContainers('run-dead-pid').length, 0, 'reaped dead-PID row is deleted')
  assert.equal(live.has('kovo-lab-live-sibling'), true, 'live sibling PID container must NOT be touched')
  assert.equal(live.has('kovo-lab-store-orphan'), true, 'failed rm leaves container live')
  assert.equal(store.listLabContainers('run-store-orphan')[0]?.status, 'orphaned', 'failed rm preserves orphaned SQLite row')

  // Once Docker rm succeeds on retry, recoverAll reaps the remaining orphan and clears its row.
  failRmFor.clear()
  const secondPass = await supervisor.recoverAll(store)
  assert.ok(secondPass.some(r => r.runId === 'run-store-orphan' && r.containersRemoved >= 1))
  assert.equal(live.has('kovo-lab-store-orphan'), false)
  assert.equal(store.listLabContainers('run-store-orphan').length, 0)

  // LabRunner started with the supervisor stamps dev.kovo.owner-pid onto launched containers.
  const prevAllow = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try {
    const runner = new LabRunner({ supervisor })
    const handle = await runner.startLabTarget({
      runId: 'run-supervised-1',
      environment: 'local-lab',
      repoDir,
      storage: store as unknown as Store,
      labConfig: {
        enabled: true,
        image: 'node:24-bookworm-slim',
        startCommand: 'node /app/server.js',
        internalPort: 8080,
        healthPath: '/health',
        healthTimeoutMs: 5_000,
      },
      signal: AbortSignal.timeout(15_000),
    })
    assert.equal(live.get(handle.containerName)?.ownerPid, '4242')
    assert.ok(supervisor.hasActiveRun('run-supervised-1'))
    await runner.stopLabTarget('run-supervised-1')
    assert.equal(supervisor.hasActiveRun('run-supervised-1'), false)
    assert.ok(removedContainers.includes(handle.containerName))
  } finally {
    if (prevAllow === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevAllow
  }
})

test('Shared LabRunner/ContainerSupervisor singleton & CLI M-20 single-runner wiring', () => {
  const supA = getSharedContainerSupervisor()
  const supB = getSharedContainerSupervisor()
  assert.strictEqual(supA, supB)

  const runnerA = getSharedLabRunner()
  const runnerB = getSharedLabRunner()
  const defaultRunner = new LabRunner()
  assert.strictEqual(runnerA, runnerB)
  assert.strictEqual(runnerA.supervisor, supA)
  assert.strictEqual(defaultRunner.supervisor, supA)

  const cliSrc = readFileSync(resolve(import.meta.dirname, '../scripts/cli.ts'), 'utf8')
  assert.match(cliSrc, /getSharedLabRunner\(\)/, 'CLI must use shared LabRunner')
  assert.match(cliSrc, /new Execution\(storage,\s*\{\s*labRunner\s*\}\)/, 'CLI must pass labRunner into Execution (M-20)')
  assert.match(cliSrc, /labRunner\.recoverAll\(storage\)/, 'CLI must reap orphaned lab containers on startup (M-6)')
})
