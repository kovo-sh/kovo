/**
 * Regression suite for Compute/Lab/Planner architecture audit findings (C2, H3, H4, M-3a):
 *   - C2: LabRunner uses parseComposeInWorker() ParsedComposeDocument directly; never re-parses
 *         raw YAML on the main thread or interpolates host process.env secrets.
 *   - H3: UntrustedComputePool enforces payload size, timeout, and process.env stripping, and
 *         Phase-0 / snapshot / JS / HTML / OpenAPI / ProgramGraph async entrypoints route through it.
 *   - H4: ContainerSupervisor.recoverAll() skips mid-boot runs (inFlightBootIds), inspects active/
 *         orphaned SQLite & persisted container refs before wiping, and exposes recoverOnStartup().
 *   - M-3a: ExecReconPlanner.clearRunState() evicts all 14 per-run Maps/Sets and
 *           enqueueHopContinuationOnRotation() hoists paged listFacts() past 500 facts.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { ComposeParseError } from '../src/server/compose-parse.ts'
import { ContainerSupervisor, LAB_OWNER_PID_LABEL } from '../src/server/container-supervisor.ts'
import { ExecReconPlanner, type ExecReconPlannerHost } from '../src/server/exec-recon-planner.ts'
import { LAB_LABELS, LabRunner } from '../src/server/lab-runner.ts'
import type { DockerRunner, LabContainerStore } from '../src/server/lab-runner.ts'
import { parseAndSanitizeComposeYaml, resolveLabStackServices } from '../src/server/lab-proxy.ts'
import { extractRepoProgramGraphInWorker, runPhase0Recon } from '../src/server/phase0-recon.ts'
import { buildStaticWorkspaceSnapshotInWorker } from '../src/server/static-workspace-snapshot.ts'
import type { Store } from '../src/server/store.ts'
import {
  UntrustedComputePayloadTooLargeError,
  UntrustedComputePool,
  UntrustedComputeTimeoutError,
  closeSharedUntrustedComputePool,
  extractHtmlLinksAndScriptsInWorker,
  extractProgramGraphInWorker,
  jsHarvestInWorker,
  parseComposeInWorker,
  parseJsonOrYamlInWorker,
  runUntrustedTask,
} from '../src/server/untrusted-compute-pool.ts'
import type { Grant, RequestBroker } from '../src/server/broker.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function createFakeLabDocker(options: {
  onRun?: (name: string, args: string[]) => Promise<void> | void
} = {}) {
  const live = new Map<string, { id: string; runId: string; ownerPid?: string }>()
  const removedContainers: string[] = []
  const servers: Array<{ close: (cb: () => void) => void }> = []
  let seq = 0

  const docker: DockerRunner = async args => {
    if (args[0] === 'network' || args[0] === 'volume' || args[0] === 'build' || args[0] === 'exec') return ''
    if (args[0] === 'run') {
      const name = args[args.indexOf('--name') + 1] ?? ''
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
      if (options.onRun) await options.onRun(name, args)
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
      const name = args[args.length - 1] ?? ''
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
        live.delete(target)
        removedContainers.push(target)
      }
      return ''
    }
    return ''
  }

  return {
    docker,
    live,
    removedContainers,
    async close() {
      await Promise.all(servers.map(s => new Promise<void>(r => s.close(() => r()))))
    },
  }
}

// ============================================================================
// C2: Compose worker isolation & no main-thread process.env interpolation
// ============================================================================

test('C2: LabRunner consumes worker-parsed Compose document and never interpolates host process.env', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-c2-lab-'))
  const stateDir = join(dir, 'state')
  const repoDir = join(dir, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), 'require("http").createServer((_, r) => r.end("ok")).listen(8080)\n')

  const fake = createFakeLabDocker()
  t.after(async () => {
    await fake.close()
    await closeSharedUntrustedComputePool()
    rmSync(dir, { recursive: true, force: true })
  })

  const prevAllow = process.env.KOVO_ALLOW_LOCAL_LAB
  const prevSecret = process.env.KOVO_AUDIT_C2_HOST_SECRET
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  process.env.KOVO_AUDIT_C2_HOST_SECRET = 'top-secret-host-token'

  try {
    // 1. parseAndSanitizeComposeYaml never defaults to or forwards process.env
    assert.throws(
      () => parseAndSanitizeComposeYaml('services:\n  app:\n    image: node:24\n    environment:\n      LEAK: ${KOVO_AUDIT_C2_HOST_SECRET}\n'),
      err => err instanceof ComposeParseError && /KOVO_AUDIT_C2_HOST_SECRET/.test(err.message),
    )
    assert.throws(
      () => parseAndSanitizeComposeYaml(
        'services:\n  app:\n    image: node:24\n    environment:\n      LEAK: ${KOVO_AUDIT_C2_HOST_SECRET}\n',
        { env: process.env as Record<string, string | undefined> },
      ),
      err => err instanceof ComposeParseError && /KOVO_AUDIT_C2_HOST_SECRET/.test(err.message),
    )

    // 2. resolveLabStackServices accepts ParsedComposeDocument directly without composeYaml
    const workerDoc = await parseComposeInWorker(
      'services:\n  app:\n    image: node:24-bookworm-slim\n    expose: ["8080"]\n    environment:\n      SAFE_FALLBACK: ${KOVO_AUDIT_C2_HOST_SECRET:-safe-default}\n',
    )
    const stack = resolveLabStackServices({ labConfig: { enabled: true }, composeDocument: workerDoc })
    assert.equal(stack.primaryService.name, 'app')
    assert.equal(stack.primaryService.env?.SAFE_FALLBACK, 'safe-default')

    // 3. LabRunner.startLabTarget fails closed on ${HOST_SECRET} instead of interpolating process.env
    writeFileSync(
      join(repoDir, 'docker-compose.leak.yml'),
      'services:\n  app:\n    image: node:24-bookworm-slim\n    environment:\n      LEAK: ${KOVO_AUDIT_C2_HOST_SECRET}\n',
    )
    const runner = new LabRunner({ docker: fake.docker, stateDir })
    await assert.rejects(
      () => runner.startLabTarget({
        runId: 'run-c2-leak',
        environment: 'local-lab',
        repoDir,
        labConfig: { enabled: true, dockerComposeFile: 'docker-compose.leak.yml' },
      }),
      err => err instanceof ComposeParseError && /KOVO_AUDIT_C2_HOST_SECRET/.test(err.message),
    )

    // 4. LabRunner.startLabTarget uses the worker-parsed doc with default fallback (never process.env)
    let capturedRunArgs: string[] = []
    const inspectRunner = new LabRunner({
      docker: async args => {
        if (args[0] === 'run' && !String(args[args.indexOf('--name') + 1] ?? '').includes('-proxy-')) {
          capturedRunArgs = args
        }
        return fake.docker(args)
      },
      stateDir,
    })
    writeFileSync(
      join(repoDir, 'docker-compose.safe.yml'),
      'services:\n  app:\n    image: node:24-bookworm-slim\n    expose: ["8080"]\n    environment:\n      APP_TOKEN: ${KOVO_AUDIT_C2_HOST_SECRET:-safe-fallback}\n',
    )
    const handle = await inspectRunner.startLabTarget({
      runId: 'run-c2-safe',
      environment: 'local-lab',
      repoDir,
      labConfig: { enabled: true, dockerComposeFile: 'docker-compose.safe.yml', healthTimeoutMs: 5_000 },
      signal: AbortSignal.timeout(15_000),
    })
    assert.ok(capturedRunArgs.includes('APP_TOKEN=safe-fallback'))
    assert.equal(capturedRunArgs.some(arg => arg.includes('top-secret-host-token')), false)
    await inspectRunner.stopLabTarget('run-c2-safe')
    assert.ok(handle.containerName)

    // 5. Structural check: lab-runner.ts forwards composeDocument, not composeYaml, to resolveLabStackServices
    const labRunnerSrc = readFileSync(resolve(import.meta.dirname, '../src/server/lab-runner.ts'), 'utf8')
    assert.match(labRunnerSrc, /resolveLabStackServices\(\{[\s\S]*composeDocument/)
    assert.doesNotMatch(labRunnerSrc, /resolveLabStackServices\(\{[\s\S]*composeYaml/)
  } finally {
    if (prevAllow === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevAllow
    if (prevSecret === undefined) delete process.env.KOVO_AUDIT_C2_HOST_SECRET
    else process.env.KOVO_AUDIT_C2_HOST_SECRET = prevSecret
  }
})

// ============================================================================
// H3: UntrustedComputePool size/env/timeout isolation + async Phase-0 wiring
// ============================================================================

test('H3: UntrustedComputePool enforces payload limits, strips process.env, and powers async Phase-0 parsers', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-h3-pool-'))
  t.after(async () => {
    await closeSharedUntrustedComputePool()
    rmSync(dir, { recursive: true, force: true })
  })

  // 1. Payload size limit fails closed before queuing/spawning worker
  const tinyPool = new UntrustedComputePool({ maxConcurrency: 1, maxPayloadBytes: 2048 })
  t.after(() => tinyPool.close())
  await assert.rejects(
    () => tinyPool.run('parse_json', { text: 'x'.repeat(4096) }),
    err => err instanceof UntrustedComputePayloadTooLargeError && err.maxBytes === 2048,
  )

  // 2. Worker isolate receives stripped env (host process.env secrets absent)
  const envProbeWorker = join(dir, 'env-probe.mjs')
  writeFileSync(
    envProbeWorker,
    [
      "import { parentPort } from 'node:worker_threads'",
      "parentPort.on('message', msg => {",
      "  parentPort.postMessage({ id: msg.id, ok: true, result: { keys: Object.keys(process.env), leaked: process.env.KOVO_AUDIT_H3_SECRET ?? null } })",
      '})',
    ].join('\n'),
  )
  const prevSecret = process.env.KOVO_AUDIT_H3_SECRET
  process.env.KOVO_AUDIT_H3_SECRET = 'secret-h3-value'
  const envPool = new UntrustedComputePool({ maxConcurrency: 1, workerEntry: envProbeWorker })
  t.after(() => envPool.close())
  try {
    const probed = await envPool.run<{ keys: string[]; leaked: string | null }>('probe', {})
    assert.equal(probed.leaked, null)
    assert.equal(probed.keys.includes('KOVO_AUDIT_H3_SECRET'), false)
  } finally {
    if (prevSecret === undefined) delete process.env.KOVO_AUDIT_H3_SECRET
    else process.env.KOVO_AUDIT_H3_SECRET = prevSecret
  }

  // 3. Timeout termination keeps event loop responsive
  const spinWorker = join(dir, 'spin-worker.mjs')
  writeFileSync(
    spinWorker,
    "import { parentPort } from 'node:worker_threads'; parentPort.on('message', () => { while (true) {} })",
  )
  const timeoutPool = new UntrustedComputePool({ maxConcurrency: 1, defaultTimeoutMs: 60, workerEntry: spinWorker })
  t.after(() => timeoutPool.close())
  await assert.rejects(
    () => timeoutPool.run('spin', {}),
    err => err instanceof UntrustedComputeTimeoutError,
  )

  // 4. Shared worker entry handles parse_json_or_yaml, extract_html, js_harvest, extract_program_graph
  const yamlDoc = await parseJsonOrYamlInWorker('openapi: 3.0.3\npaths:\n  /items:\n    get:\n      summary: List items\n') as Record<string, unknown>
  assert.equal(yamlDoc.openapi, '3.0.3')

  const htmlSurface = await extractHtmlLinksAndScriptsInWorker(
    '<html><body><a href="/dashboard">Dash</a><script src="/app.js"></script><form method="POST" action="/api/login"><input name="email"></form></body></html>',
    'https://app.example.invalid',
  )
  assert.deepEqual(htmlSurface.links, ['/dashboard'])
  assert.deepEqual(htmlSurface.scripts, ['/app.js'])
  assert.equal(htmlSurface.forms[0]?.action, '/api/login')

  const jsOut = await jsHarvestInWorker("fetch('/api/orders', { method: 'POST', body: JSON.stringify({ sku: 1 }) })", 'https://app.example.invalid/app.js') as {
    apiPaths?: string[]
    httpCalls?: Array<{ url?: string; method?: string }>
  }
  assert.ok((jsOut.apiPaths ?? []).includes('/api/orders') || (jsOut.httpCalls ?? []).some(c => c.url === '/api/orders'))

  const repoDir = join(dir, 'repo')
  mkdirSync(join(repoDir, 'acme', 'api'), { recursive: true })
  writeFileSync(
    join(repoDir, 'acme', 'api', 'server.js'),
    "const express = require('express'); const app = express(); app.get('/api/health', (req, res) => res.json({ ok: true }));\n",
  )
  const graph = await extractProgramGraphInWorker({
    files: [{ path: 'acme/api/server.js', content: readFileSync(join(repoDir, 'acme', 'api', 'server.js'), 'utf8') }],
    repo: 'acme/api',
  })
  assert.ok(graph.routes.some(r => r.path === '/api/health'))

  const snap = await buildStaticWorkspaceSnapshotInWorker(repoDir, { mountedRepos: ['acme/api'] })
  assert.ok(snap.programGraph.routes.some(r => r.path === '/api/health'))
  const extracted = await extractRepoProgramGraphInWorker({
    reposDir: repoDir,
    origins: ['https://app.example.invalid'],
  })
  assert.ok(extracted?.routes.some(r => r.pathTemplate === '/api/health'))

  // 5. Full async runPhase0Recon executes HTML/JS/OpenAPI/ProgramGraph through UntrustedComputePool
  const { storage: store } = makeStore(t)
  const { run } = await setupApprovedRun(store, { seeds: ['https://app.example.invalid'], tier: 1, environment: 'public' })
  let exSeq = 0
  const makeEx = (pathAndQuery: string, status: number, mediaType: string, body: string) => {
    exSeq += 1
    return {
      id: `ex-${exSeq}`,
      exchangeId: `ex-${exSeq}`,
      origin: 'https://app.example.invalid',
      method: 'GET',
      pathAndQuery,
      status,
      mediaType,
      respHeaders: { 'content-type': mediaType },
      body,
      bodyPreview: body.slice(0, 512),
      bodySha256: '0'.repeat(64),
      truncated: false,
      elapsedMs: 1,
      redirectChain: [],
      personaHandle: null,
    }
  }
  const fakeBroker = {
    async executeHttp(req: { pathAndQuery: string }) {
      const path = req.pathAndQuery.split('?')[0]
      if (path === '/') {
        return makeEx(
          req.pathAndQuery,
          200,
          'text/html',
          '<html><script src="/bundle.js"></script><a href="/orders">Orders</a></html>',
        )
      }
      if (path === '/bundle.js') {
        return makeEx(
          req.pathAndQuery,
          200,
          'application/javascript',
          "fetch('/api/widgets', { method: 'POST', body: JSON.stringify({ title: 'x' }) });",
        )
      }
      if (path === '/openapi.json') {
        return makeEx(
          req.pathAndQuery,
          200,
          'application/json',
          JSON.stringify({ openapi: '3.0.3', paths: { '/api/reports': { get: { responses: { '200': { description: 'ok' } } } } } }),
        )
      }
      return makeEx(req.pathAndQuery, 404, 'text/plain', 'not found')
    },
  } as unknown as RequestBroker
  const grant = { canRead: () => true } as unknown as Grant

  const phase0 = await runPhase0Recon({
    storage: store,
    runId: run.id,
    scopeRevision: run.scopeRevision,
    tier: 1,
    origins: ['https://app.example.invalid'],
    budgetRequests: 600,
    reposDir: repoDir,
    broker: fakeBroker,
    grant,
    signal: AbortSignal.timeout(15_000),
  })
  assert.ok(phase0.endpointsDiscovered >= 3)
  const persisted = store.listEndpoints(run.id, { limit: 100 }).map(e => `${e.method} ${e.pathTemplate}`)
  assert.ok(persisted.includes('GET /api/health'))
  assert.ok(persisted.includes('GET /api/reports'))
  assert.ok(persisted.includes('GET /api/widgets') || persisted.includes('POST /api/widgets'))
  await assert.rejects(() => runUntrustedTask('parse_json', { text: 'x'.repeat(5 * 1024 * 1024) }), UntrustedComputePayloadTooLargeError)
})

// ============================================================================
// H4: Mid-boot protection (inFlightBootIds), pre-wipe inspection & startup hook
// ============================================================================

test('H4: recoverAll() & recoverOnStartup() skip mid-boot runs while reaping crashed/persisted orphans', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-h4-sup-'))
  const stateDir = join(dir, 'state')
  const repoDir = join(dir, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), 'require("http").createServer((_, r) => r.end("ok")).listen(8080)\n')

  let releaseProxyRun: (() => void) | undefined
  let proxyPauseEntered: (() => void) | undefined
  const proxyPaused = new Promise<void>(resolvePromise => { proxyPauseEntered = resolvePromise })

  const fake = createFakeLabDocker({
    async onRun(name) {
      if (name.includes('-proxy-')) {
        proxyPauseEntered?.()
        await new Promise<void>(resolvePromise => { releaseProxyRun = resolvePromise })
      }
    },
  })
  t.after(async () => {
    releaseProxyRun?.()
    await fake.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const { storage: store } = makeStore(t)
  const { run: bootRun } = await setupApprovedRun(store, { seeds: ['https://boot.example.invalid'], environment: 'public' })
  const { run: orphanRun } = await setupApprovedRun(store, { seeds: ['https://orphan.example.invalid'], environment: 'public' })

  const supervisor = new ContainerSupervisor({
    docker: fake.docker,
    stateDir,
    ownerPid: 5150,
    isPidAlive: () => false,
  })
  const runner = new LabRunner({ supervisor })

  // Seed a crashed orphan from a dead PID with a 'running' row in real SQLite Store
  fake.live.set('kovo-lab-crashed-app', { id: 'c000000000881', runId: orphanRun.id, ownerPid: '99999' })
  store.recordLabContainer({ runId: orphanRun.id, containerName: 'kovo-lab-crashed-app', status: 'running' })

  const prevAllow = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try {
    // Launch bootRun and pause mid-boot right after primary container launch + proxy start
    const bootPromise = runner.startLabTarget({
      runId: bootRun.id,
      environment: 'local-lab',
      repoDir,
      storage: store,
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

    await proxyPaused
    assert.equal(supervisor.isBooting(bootRun.id), true)
    assert.equal(supervisor.hasActiveRun(bootRun.id), false)
    const bootContainers = store.listLabContainers(bootRun.id).map(r => r.containerName)
    assert.ok(bootContainers.length >= 1, 'primary container row already recorded mid-boot')

    // Concurrent recoverOnStartup() / recoverAll() must reap orphanRun but leave bootRun untouched
    const [r1, r2] = await Promise.all([
      runner.recoverOnStartup(store as unknown as LabContainerStore),
      runner.recoverOnStartup(store as unknown as LabContainerStore),
    ])
    assert.strictEqual(r1, r2, 'concurrent startup recovery calls must coalesce cleanly')
    assert.equal(fake.live.has('kovo-lab-crashed-app'), false, 'crashed orphan container must be reaped')
    assert.equal(store.listLabContainers(orphanRun.id).length, 0, 'reaped orphan row cleared from SQLite')
    for (const cname of bootContainers) {
      assert.equal(fake.live.has(cname), true, `mid-boot container ${cname} must NOT be reaped`)
    }
    assert.equal(store.listLabContainers(bootRun.id).length, bootContainers.length)

    // Resume boot and verify it completes cleanly and clears inFlightBootIds
    releaseProxyRun?.()
    const handle = await bootPromise
    assert.equal(supervisor.isBooting(bootRun.id), false)
    assert.equal(supervisor.hasActiveRun(bootRun.id), true)
    assert.ok(handle.containerName)
    await runner.stopLabTarget(bootRun.id)

    // Pre-collected persistedContainers can still be reaped even if SQLite rows were wiped
    fake.live.set('kovo-lab-prewiped-1', { id: 'c000000000882', runId: 'run-prewiped', ownerPid: '99999' })
    const preWipedResults = await runner.recoverAll(store as unknown as LabContainerStore, {
      persistedContainers: [{ runId: 'run-prewiped', containerName: 'kovo-lab-prewiped-1' }],
    })
    assert.ok(preWipedResults.some(r => r.runId === 'run-prewiped' && r.containersRemoved >= 1))
    assert.equal(fake.live.has('kovo-lab-prewiped-1'), false)
  } finally {
    if (prevAllow === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevAllow
  }
})

// ============================================================================
// M-3a: ExecReconPlanner.clearRunState() + hoisted >500-fact continuation dedup
// ============================================================================

test('M-3a: ExecReconPlanner.clearRunState() evicts all per-run maps and continuation dedup handles >500 facts in one hoisted pass', async t => {
  const { storage: store } = makeStore(t)
  const { run: run1 } = await setupApprovedRun(store, { seeds: ['https://m3a-one.example.invalid'], environment: 'public' })
  const asset1 = run1.candidates[0]!
  const { run: run2 } = await setupApprovedRun(store, { seeds: ['https://m3a-two.example.invalid'], environment: 'public' })

  const host: ExecReconPlannerHost = {
    storage: store,
    browser: {} as ExecReconPlannerHost['browser'],
    broker: {} as ExecReconPlannerHost['broker'],
    backend: {} as ExecReconPlannerHost['backend'],
    labRunner: {} as ExecReconPlannerHost['labRunner'],
    canaryBroker: {} as ExecReconPlannerHost['canaryBroker'],
    maxDurationMs: 60_000,
    active: new Map(),
    coordinator: new Map(),
    probePlans: new Map() as unknown as ExecReconPlannerHost['probePlans'],
    startedLabRuns: new Set(),
    startedLabHandles: new Map(),
    prePhase0SeededSteps: new Map(),
    plannerDoneRound: new Map(),
    dispatchFunnels: new Map(),
    detLeadConsumed: new Set(),
    tierAStepIds: new Set(),
    tierAFactIds: new Set(),
    approvedOriginsSet: r => new Set(r.candidates.filter(c => r.approved.includes(c.id)).map(c => c.origin)),
    authorize: () => true,
    currentCoordinator: () => true,
    buildGrant: () => ({ grant: {} as Grant, secrets: [], currentSecrets: () => [] }),
    projectReposMount: () => ({ mountedRepos: [] }),
    deterministicLaneKey: r => r.id,
    notifyCheckpoint: () => undefined,
    seedCodeToRuntimeLeads: () => 0,
    correlateSpecDependencies: async () => undefined,
    runSourceFirstCodeAudit: async () => ({ suspects: [], stepsCreated: [] }),
    baselineFinding: () => undefined,
    saveBaselineFinding: () => undefined,
    completeWorker: () => undefined,
    expandEligibleMultiTrialSteps: () => undefined,
    endpointGraphCatalog: () => ({ endpointParams: [], apiDependencies: [] }),
    noteDryStreak: () => undefined,
    reinvestigationGuardFor: () => ({ record: () => ({ allowed: true, count: 1, limit: 5 }) }) as never,
    highPriorityQueueEmpty: () => true,
    noteCappedReinvestigation: () => undefined,
    recordDispatchFunnel: () => undefined,
    noteStrandedReadySteps: () => undefined,
    tracePlannerDecision: () => undefined,
    codeSliceForAssignment: () => undefined,
    shouldCoordinatorAnswer: () => false,
    resetBoardHops: () => undefined,
  }

  const planner = new ExecReconPlanner(host)

  // 1. Seed 550 filler facts, then add a hop_checkpoint fact past the 500-fact mark
  const adminWorker = store.makeWorker(run1, 'investigation', asset1, 'recon', 'recon', { sourceOrigins: [asset1.origin] })
  const fillerIds: string[] = []
  for (let i = 0; i < 550; i += 1) {
    const f = store.addFact(run1, adminWorker, {
      origin: asset1.origin,
      kind: 'note',
      summary: `filler-${i}`,
      data: { idx: i },
    })
    fillerIds.push(f.id)
  }

  const sealedHandle = 'cap:hop_gt500:derived_token'
  store.capabilityLedger(run1.id).addCapability({
    capId: sealedHandle,
    kind: 'identity_session',
    provenance: 'derived_hop',
    tenantScope: 'org_a',
    actorPersona: 'user_a',
    serviceOrigin: asset1.origin,
    surface: 'http',
    artifactDigest: 'a'.repeat(64),
    artifactSummary: 'Hop 1 derived token',
    createdAtMs: 1000,
  })
  const cpFact = store.addFact(run1, adminWorker, {
    origin: asset1.origin,
    kind: 'note',
    summary: 'hop checkpoint past 500 facts',
    data: {
      source: 'host:planner',
      subkind: 'hop_checkpoint',
      checkpointCapId: sealedHandle,
      checkpointBrief: {
        schema: 'v8.hop_checkpoint.v1',
        branchKey: 'branch-500',
        depth: 1,
        targetHop: 3,
        mode: 'pivot',
        evi: 1,
        verifiedHops: [],
        capabilityHandles: [sealedHandle],
        nextGoal: {
          targetSurfaceKey: `${asset1.origin}|http|/admin`,
          surface: 'http',
          service: asset1.origin,
          endpoint: '/admin',
          hypothesisClass: 'authz',
          goal: 'Pivot',
        },
        doNotRediscover: true,
      },
    },
  })

  const rootStep = store.addChainStep(run1, {
    title: 'Root chain step',
    hypothesis: 'Test chain',
    category: 'authz',
    priority: 90,
    targetAssetIds: [asset1.id],
    skills: ['multihop-chains'],
    dependsOnFactIds: [],
    sourceOrigins: [asset1.origin],
  })
  const contStep = store.addChainStep(run1, {
    title: 'Root chain step [continuation #1]',
    hypothesis: 'Continue chain',
    category: 'authz',
    priority: 90,
    targetAssetIds: [asset1.id],
    skills: ['multihop-chains', 'chain_continuation:1'],
    dependsOnFactIds: [fillerIds[0]!, fillerIds[1]!, fillerIds[2]!, fillerIds[3]!, cpFact.id],
    dependsOnStepIds: [rootStep.id],
    sourceOrigins: [asset1.origin],
  })
  const contWorker = store.makeWorker(run1, 'investigation', asset1, contStep.title, contStep.hypothesis, {
    stepId: contStep.id,
    sourceOrigins: [asset1.origin],
  })

  let listFactsCalls = 0
  const origListFacts = store.listFacts.bind(store)
  store.listFacts = ((...args: Parameters<Store['listFacts']>) => {
    listFactsCalls += 1
    return origListFacts(...args)
  }) as Store['listFacts']

  const dedupResult = planner.enqueueHopContinuationOnRotation({
    run: store.run(run1.id),
    step: contStep,
    assignment: contWorker,
    targetOrigins: [asset1.origin],
    confirmed: false,
    partialSummary: '[partial] Re-observed inherited handle',
    recordedFacts: [],
    recordedExchanges: [],
    sealedCapHandles: [sealedHandle],
    trigger: 'sealed_handle_exit',
  })
  store.listFacts = origListFacts

  assert.equal(dedupResult.enqueued, false)
  assert.equal(dedupResult.reason, 'duplicate_sealed_handles', 'must find checkpoint fact beyond 500 facts')
  assert.ok(listFactsCalls <= 2, `expected hoisted paging (<=2 calls for 551 facts), got ${listFactsCalls}`)

  // 2. Populate all 14 per-run Maps/Sets on planner for run1 AND run2, then verify clearRunState(run1.id)
  planner.frontierControllerFor(run1.id)
  planner.frontierControllerFor(run2.id)
  const priv = planner as unknown as {
    plannerEmptyRounds: Map<string, number>
    plannerDryRounds: Map<string, number>
    plannerCompletedAtLastRound: Map<string, number>
    plannerEvidenceFrontier: Map<string, { confirmed: number; primitives: number }>
    frontierControllers: Map<string, unknown>
    persistedStepCheckpoints: Map<string, unknown>
    invariantsSeededRuns: Set<string>
    wave1InvariantChainsPromoted: Set<string>
    emittedSealedHandleSets: Map<string, Set<string>>
    plannerSeenCausalEdges: Map<string, Set<string>>
    detLeadStepKeys: Set<string>
    detLeadGateRejected: Set<string>
    cappedLeadReported: Set<string>
    tierAStepKeys: Set<string>
    stepIdsByRun: Map<string, Set<string>>
  }
  priv.plannerEmptyRounds.set(run1.id, 1)
  priv.plannerDryRounds.set(run1.id, 1)
  priv.plannerCompletedAtLastRound.set(run1.id, 1)
  priv.plannerEvidenceFrontier.set(run1.id, { confirmed: 0, primitives: 0 })
  priv.invariantsSeededRuns.add(run1.id)
  priv.wave1InvariantChainsPromoted.add(run1.id)
  priv.emittedSealedHandleSets.set(`${run1.id}:${rootStep.id}`, new Set(['sig1']))
  priv.plannerSeenCausalEdges.set(run1.id, new Set(['edge1']))
  priv.detLeadStepKeys.add(`${run1.id}\0GET /a|authz`)
  priv.detLeadGateRejected.add(`${run1.id}\0f1`)
  priv.cappedLeadReported.add(`${run1.id}\0f2`)
  priv.tierAStepKeys.add(`${run1.id}\0GET /b|authz`)
  priv.persistedStepCheckpoints.set('step-run1', { checkpointCapId: sealedHandle })
  priv.stepIdsByRun.set(run1.id, new Set(['step-run1']))

  priv.plannerEmptyRounds.set(run2.id, 2)
  priv.persistedStepCheckpoints.set('step-run2', { checkpointCapId: 'cap:hop_r2:1' })
  priv.stepIdsByRun.set(run2.id, new Set(['step-run2']))

  planner.clearRunState(run1.id)

  assert.equal(priv.plannerEmptyRounds.has(run1.id), false)
  assert.equal(priv.plannerDryRounds.has(run1.id), false)
  assert.equal(priv.plannerCompletedAtLastRound.has(run1.id), false)
  assert.equal(priv.plannerEvidenceFrontier.has(run1.id), false)
  assert.equal(priv.frontierControllers.has(run1.id), false)
  assert.equal(priv.persistedStepCheckpoints.has('step-run1'), false)
  assert.equal(priv.invariantsSeededRuns.has(run1.id), false)
  assert.equal(priv.wave1InvariantChainsPromoted.has(run1.id), false)
  assert.equal(priv.emittedSealedHandleSets.has(`${run1.id}:${rootStep.id}`), false)
  assert.equal(priv.plannerSeenCausalEdges.has(run1.id), false)
  assert.equal(priv.detLeadStepKeys.has(`${run1.id}\0GET /a|authz`), false)
  assert.equal(priv.detLeadGateRejected.has(`${run1.id}\0f1`), false)
  assert.equal(priv.cappedLeadReported.has(`${run1.id}\0f2`), false)
  assert.equal(priv.tierAStepKeys.has(`${run1.id}\0GET /b|authz`), false)

  // run2 state must stay intact
  assert.equal(priv.frontierControllers.has(run2.id), true)
  assert.equal(priv.plannerEmptyRounds.get(run2.id), 2)
  assert.equal(priv.persistedStepCheckpoints.has('step-run2'), true)

  // Terminal run transition automatically triggers clearRunState via lifecycle subscription
  store.command({ requestId: randomUUID(), runId: run2.id, action: 'stop' })
  await new Promise(resolvePromise => setTimeout(resolvePromise, 25))
  assert.equal(priv.frontierControllers.has(run2.id), false)
  assert.equal(priv.plannerEmptyRounds.has(run2.id), false)
  assert.equal(priv.persistedStepCheckpoints.has('step-run2'), false)
})
