import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { createKovoLocalServer } from '../scripts/serve.ts'
import {
  AppRuntime,
  assertValidRunId,
  createAppRuntime,
  disposeAllAppRuntimes,
  getAppRuntime,
  GlobalKillSwitch,
  globalKillSwitch,
  InvalidRunIdError,
  KillSwitchTrippedError,
  RunContext,
  store as runtimeStore,
} from '../src/server/app-runtime.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { OobRelay } from '../src/server/oob-relay.ts'
import { store as legacyStore } from '../src/server/store.ts'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-app-runtime-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => {
    rmSync(dir, { recursive: true, force: true })
  })
  return dir
}

async function availablePort(): Promise<number> {
  const probe = createServer().listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const address = probe.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate port')
  await new Promise<void>(r => probe.close(() => r()))
  return address.port
}

// ============================================================================
// 1. RunContext non-empty & non-'default' runId invariant
// ============================================================================

test('RunContext & assertValidRunId enforce non-empty, non-"default" runId invariant', async t => {
  const dir = makeTempDir(t)
  const runtime = createAppRuntime({ dataDir: dir })
  t.after(() => runtime.dispose())

  for (const invalid of ['', '   ', 'default', 'DEFAULT', '  DeFaUlT  ', null, undefined, 42]) {
    assert.throws(
      () => assertValidRunId(invalid, 'test'),
      InvalidRunIdError,
      `assertValidRunId must reject ${JSON.stringify(invalid)}`,
    )
    assert.throws(
      () => new RunContext({ runId: invalid as unknown as string }),
      InvalidRunIdError,
      `new RunContext() must reject ${JSON.stringify(invalid)}`,
    )
    assert.throws(
      () => runtime.createRunContext(invalid as unknown as string),
      InvalidRunIdError,
      `AppRuntime.createRunContext() must reject ${JSON.stringify(invalid)}`,
    )
  }

  assert.equal(runtime.getRunContext('default'), undefined)
  assert.equal(runtime.getRunContext(''), undefined)
  assert.throws(() => runtime.requireRunContext('default'), InvalidRunIdError)
  assert.throws(() => runtime.requireRunContext('run-missing'), /RunContext not found/)

  const ctx = runtime.createRunContext('  run-alpha-01  ')
  assert.equal(ctx.runId, 'run-alpha-01')
  assert.strictEqual(runtime.getRunContext('run-alpha-01'), ctx)
  assert.strictEqual(runtime.requireRunContext('run-alpha-01'), ctx)
  assert.deepEqual(runtime.activeRunIds(), ['run-alpha-01'])

  // Duplicate active runId registration is rejected.
  assert.throws(() => runtime.createRunContext('run-alpha-01'), /already exists/)
})

// ============================================================================
// 2. Active GlobalKillSwitch.trigger() -> RunContext abort + SSE revocation
// ============================================================================

test('GlobalKillSwitch.trigger() immediately aborts all active RunContexts, global signal, subscribe listeners, and SSE revocation callbacks', async t => {
  const dir = makeTempDir(t)
  const runtime = createAppRuntime({ dataDir: dir })
  t.after(() => runtime.dispose())

  const ctxA = runtime.createRunContext('run-ks-a', { tenantId: 'tenant-1' })
  const ctxB = runtime.createRunContext('run-ks-b', { tenantId: 'tenant-2' })
  const ctxC = runtime.createRunContext('run-ks-c')

  assert.equal(runtime.killSwitch.isActive(), false)
  assert.equal(runtime.killSwitch.signal.aborted, false)
  assert.equal(ctxA.signal.aborted, false)
  assert.equal(ctxB.signal.aborted, false)
  assert.equal(ctxC.signal.aborted, false)

  const stateEvents: Array<{ active: boolean; tenantId: string | null; reason: string | null }> = []
  const sseRevocations: Array<{ subscriber: string; tenantId: string | null; reason: string | null }> = []

  const unsubState = runtime.killSwitch.subscribe(state => {
    stateEvents.push({ active: state.active, tenantId: state.tenantId, reason: state.reason })
  })
  const unsubSse1 = runtime.registerSseRevocation(state => {
    sseRevocations.push({ subscriber: 'sse-1', tenantId: state.tenantId, reason: state.reason })
  })
  const unsubSseThrow = runtime.registerSseRevocation(() => {
    throw new Error('simulated broken SSE writer')
  })
  const unsubSse2 = runtime.registerSseRevocation(state => {
    sseRevocations.push({ subscriber: 'sse-2', tenantId: state.tenantId, reason: state.reason })
  })
  t.after(() => {
    unsubState()
    unsubSse1()
    unsubSseThrow()
    unsubSse2()
  })

  // Tenant-scoped trigger aborts ONLY tenant-1's RunContext and leaves tenant-2 / global intact.
  runtime.killSwitch.trigger({ reason: 'Tenant 1 emergency halt', tenantId: 'tenant-1' })
  assert.equal(runtime.killSwitch.isActive(), false)
  assert.equal(runtime.killSwitch.isActive('tenant-1'), true)
  assert.equal(runtime.killSwitch.signal.aborted, false)
  assert.equal(ctxA.signal.aborted, true)
  assert.ok(ctxA.signal.reason instanceof KillSwitchTrippedError)
  assert.equal(ctxB.signal.aborted, false)
  assert.equal(ctxC.signal.aborted, false)
  assert.equal(sseRevocations.filter(r => r.tenantId === 'tenant-1').length, 2)

  // Global trigger with string reason aborts ALL remaining active RunContexts + global signal + both healthy SSE callbacks.
  const globalSignalBefore = runtime.killSwitch.signal
  runtime.killSwitch.trigger('Global emergency stop')
  assert.equal(runtime.killSwitch.isActive(), true)
  assert.equal(globalSignalBefore.aborted, true)
  assert.equal(runtime.killSwitch.signal.aborted, true)
  assert.ok(runtime.killSwitch.signal.reason instanceof KillSwitchTrippedError)
  assert.equal(ctxB.signal.aborted, true)
  assert.equal(ctxC.signal.aborted, true)
  assert.ok(ctxB.signal.reason instanceof KillSwitchTrippedError)
  assert.ok(ctxC.signal.reason instanceof KillSwitchTrippedError)
  assert.throws(() => ctxC.throwIfAborted(), KillSwitchTrippedError)
  assert.equal(sseRevocations.filter(r => r.tenantId === null).length, 2)
  assert.equal(sseRevocations.at(-1)?.reason, 'Global emergency stop')

  // New RunContext created while kill switch is active is immediately aborted on construction.
  const ctxLate = runtime.createRunContext('run-ks-late')
  assert.equal(ctxLate.signal.aborted, true)
  assert.ok(ctxLate.signal.reason instanceof KillSwitchTrippedError)

  // Resetting global kill switch restores inactive state and provides a fresh non-aborted signal.
  runtime.killSwitch.reset()
  assert.equal(runtime.killSwitch.isActive(), false)
  assert.equal(runtime.killSwitch.signal.aborted, false)
  assert.notStrictEqual(runtime.killSwitch.signal, globalSignalBefore)
  assert.equal(stateEvents.at(-1)?.active, false)

  const ctxAfterReset = runtime.createRunContext('run-ks-after-reset')
  assert.equal(ctxAfterReset.signal.aborted, false)
})

test('serve.ts /api/ops/kill-switch revokes active SSE /events requests bound through AppRuntime', async t => {
  const dir = makeTempDir(t, 'kovo-serve-sse-')
  const runtime = createAppRuntime({ dataDir: join(dir, 'data') })
  t.after(() => runtime.dispose())

  const port = await availablePort()
  let sseAborted = false
  let resolveSseConnected: (() => void) | null = null
  const sseConnected = new Promise<void>(r => { resolveSseConnected = r })
  let resolveSseClosed: (() => void) | null = null
  const sseClosed = new Promise<void>(r => { resolveSseClosed = r })

  const local = createKovoLocalServer({
    app: {
      fetch(request) {
        const url = new URL(request.url)
        if (url.pathname.endsWith('/events')) {
          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new TextEncoder().encode('retry: 700\n\n'))
              resolveSseConnected?.()
              request.signal.addEventListener('abort', () => {
                sseAborted = true
                try { controller.close() } catch { /* ignore */ }
                resolveSseClosed?.()
              }, { once: true })
            },
          })
          return new Response(stream, {
            headers: { 'content-type': 'text/event-stream' },
          })
        }
        return new Response('ok')
      },
    },
    directory: join(dir, 'srv'),
    port,
    runtime,
  })
  assert.strictEqual(local.runtime, runtime)
  local.server.listen(port, '127.0.0.1')
  await once(local.server, 'listening')
  t.after(async () => {
    local.server.closeAllConnections()
    await new Promise<void>(r => local.server.close(() => r()))
  })

  const baseUrl = `http://127.0.0.1:${port}`
  const boot = await fetch(local.bootstrapUrl(baseUrl), { redirect: 'manual' })
  assert.equal(boot.status, 303)
  const cookie = (boot.headers.get('set-cookie') ?? '').split(';')[0]!

  const runCtx = runtime.createRunContext('run-sse-live')
  const sseResponse = await fetch(`${baseUrl}/api/runs/${runCtx.runId}/events`, {
    headers: { cookie },
  })
  assert.equal(sseResponse.status, 200)
  await sseConnected

  // Trip via HTTP API -> aborts both RunContext and live SSE request immediately.
  const tripRes = await fetch(`${baseUrl}/api/ops/kill-switch`, {
    method: 'POST',
    headers: { cookie, origin: baseUrl, 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'trip', reason: 'Revoke SSE & active runs' }),
  })
  assert.equal(tripRes.status, 200)

  await Promise.race([sseClosed, new Promise((_, rej) => setTimeout(() => rej(new Error('SSE did not close')), 2_000))])
  assert.equal(sseAborted, true, 'SSE stream request signal must abort immediately on kill-switch trip')
  assert.equal(runCtx.signal.aborted, true, 'AppRuntime RunContext must abort immediately on kill-switch trip')
  await sseResponse.body?.cancel().catch(() => undefined)
})

// ============================================================================
// 3. RunContext.drainAndDispose() fault-tolerant resource cleanup & task draining
// ============================================================================

test('RunContext.drainAndDispose() drains tracked tasks, runs all disposers via Promise.allSettled even if one throws, and removes itself from AppRuntime.runs', async t => {
  const dir = makeTempDir(t)
  const runtime = createAppRuntime({ dataDir: dir })
  t.after(() => runtime.dispose())

  const ctx = runtime.createRunContext('run-dispose-01')
  const cleaned: string[] = []

  // Register a real timer, a vault disposer, a sync-throwing disposer, an async-rejecting disposer, and a browser disposer.
  let timerFired = false
  const timer = setTimeout(() => { timerFired = true }, 60_000)
  ctx.registerTimer('heartbeat-timer', timer)
  ctx.registerResource('vault:evict', () => { cleaned.push('vault') })
  ctx.registerResource('broken:sync', () => {
    cleaned.push('broken-sync-attempted')
    throw new Error('sync disposer failure')
  })
  ctx.registerResource('broken:async', async () => {
    cleaned.push('broken-async-attempted')
    throw new Error('async disposer failure')
  })
  ctx.registerResource('browser:close', async () => {
    await new Promise<void>(r => setTimeout(r, 10))
    cleaned.push('browser')
  })

  // Track three async tasks: one resolves cleanly on abort, one rejects on abort, one hangs past drain timeout.
  let gracefulTaskFinished = false
  const gracefulTask = ctx.trackTask('worker-graceful', new Promise<string>(resolve => {
    ctx.signal.addEventListener('abort', () => {
      setTimeout(() => {
        gracefulTaskFinished = true
        resolve('drained')
      }, 15)
    }, { once: true })
  }))

  const failingTask = ctx.trackTask('worker-failing', new Promise<void>((_, reject) => {
    ctx.signal.addEventListener('abort', () => {
      setTimeout(() => reject(new Error('task cancelled')), 10)
    }, { once: true })
  }))
  // Attach caller catch handler to verify no unhandled rejection occurs.
  void failingTask.catch(() => undefined)

  const hangingTask = ctx.trackTask('worker-hanging', new Promise<void>(() => {
    // Intentionally never settles to verify bounded drain timeout.
  }))
  void hangingTask

  assert.equal(ctx.activeTaskCount, 3)

  const report = await ctx.drainAndDispose(80)
  assert.equal(await gracefulTask, 'drained')
  assert.equal(gracefulTaskFinished, true)
  assert.equal(report.runId, 'run-dispose-01')
  assert.equal(report.aborted, true)
  assert.equal(report.alreadyDisposed, false)
  assert.equal(report.tasksTotal, 3)
  assert.equal(report.tasksDrained, 2)
  assert.equal(report.tasksTimedOut, 1)
  assert.equal(timerFired, false)

  // Every single disposer ran despite the sync + async failures.
  assert.ok(cleaned.includes('vault'))
  assert.ok(cleaned.includes('browser'))
  assert.ok(cleaned.includes('broken-sync-attempted'))
  assert.ok(cleaned.includes('broken-async-attempted'))
  assert.equal(report.resourceErrors.length, 2)
  assert.deepEqual(
    report.resourceErrors.map(e => e.name).sort(),
    ['broken:async', 'broken:sync'],
  )
  assert.equal(ctx.isDisposed, true)
  assert.equal(runtime.runs.has('run-dispose-01'), false)
  assert.equal(runtime.getRunContext('run-dispose-01'), undefined)

  // Idempotent second call does not re-run disposers.
  const prevCleanedLen = cleaned.length
  const second = await ctx.drainAndDispose(50)
  assert.equal(second.alreadyDisposed, true)
  assert.equal(cleaned.length, prevCleanedLen)

  // Late resource registration on a disposed RunContext invokes cleanup immediately best-effort.
  let lateDisposed = false
  ctx.registerResource('late-resource', () => { lateDisposed = true })
  assert.equal(lateDisposed, true)
})

// ============================================================================
// 4. AppRuntime lazy Store, SSR/ESM singleton parity, and graceful dispose()
// ============================================================================

test('getAppRuntime() shares one AppRuntime/Store/GlobalKillSwitch across dual module loads and dispose() shuts down cleanly', async t => {
  const prevDataDir = process.env.KOVO_DATA_DIR
  const dir = makeTempDir(t, 'kovo-shared-runtime-')
  process.env.KOVO_DATA_DIR = dir
  t.after(async () => {
    await disposeAllAppRuntimes()
    globalKillSwitch.reset()
    if (prevDataDir === undefined) delete process.env.KOVO_DATA_DIR
    else process.env.KOVO_DATA_DIR = prevDataDir
  })

  const rt1 = getAppRuntime()
  assert.equal(rt1.dataDir, resolve(dir))
  assert.equal(rt1.hasStore(), false, 'AppRuntime.store must initialize lazily')

  // Simulate Vite SSR bundle + Node ESM dual load of app-runtime.ts.
  const dualMod = await import(`../src/server/app-runtime.ts?dual=${Date.now()}`) as {
    getAppRuntime: typeof getAppRuntime
  }
  const rt2 = dualMod.getAppRuntime()
  assert.strictEqual(rt2, rt1, 'dual ESM/SSR imports must resolve to the exact same AppRuntime')
  assert.strictEqual(rt1.killSwitch, globalKillSwitch, 'default AppRuntime must share globalKillSwitch')

  // Accessing store lazily opens ONE shared Store identical to store() and legacy store().
  const s1 = rt1.store
  assert.equal(rt1.hasStore(), true)
  assert.strictEqual(rt2.store, s1)
  assert.strictEqual(runtimeStore(), s1)
  assert.strictEqual(legacyStore(), s1)

  // Attach active run + OOB relay and verify graceful AppRuntime.dispose().
  const ctx = rt1.createRunContext('run-shutdown-01')
  const relay = rt1.oob
  const token = `kovo-canary-${'a'.repeat(24)}`
  relay.registerCanary({ token, canaryId: 'c-shutdown', runId: ctx.runId })
  relay.subscribe({ runId: ctx.runId, assignmentId: 'a-1', canaryId: 'c-shutdown', token, artifact: 'art-1' })
  assert.equal(relay.pending(ctx.runId).length, 1)

  const report = await rt1.dispose()
  assert.equal(report.runsDisposed, 1)
  assert.equal(report.oobClosed, true)
  assert.equal(report.storeClosed, true)
  assert.deepEqual(report.errors, [])
  assert.equal(rt1.isDisposed, true)
  assert.equal(rt1.runs.size, 0)
  assert.throws(() => rt1.store, /disposed/)

  // Calling getAppRuntime() after dispose() constructs a fresh, live runtime cleanly.
  const rtFresh = getAppRuntime()
  assert.notStrictEqual(rtFresh, rt1)
  assert.equal(rtFresh.isDisposed, false)
  assert.ok(rtFresh instanceof AppRuntime)
})

// ============================================================================
// 5. OOB explicit runId enforcement & concurrent multi-run OOB isolation
// ============================================================================

test('OOB relay & CanaryBroker forbid empty/"default" runId and enforce concurrent multi-run isolation + RunContext unsubscribeRun()', async t => {
  const dir = makeTempDir(t, 'kovo-oob-isolation-')
  const runtime = createAppRuntime({ dataDir: dir })
  t.after(() => runtime.dispose())

  const broker = new CanaryBroker({ oobDirectory: dir })
  runtime.attachCanaryBroker(broker)
  const relay = broker.oob
  assert.ok(relay instanceof OobRelay)

  const sampleToken = `kovo-canary-${'c'.repeat(24)}`
  for (const badRunId of ['', '   ', 'default', 'DEFAULT']) {
    assert.throws(
      () => broker.mintCanary(badRunId, 'ssrf-probe'),
      InvalidRunIdError,
      `CanaryBroker.mintCanary must reject "${badRunId}"`,
    )
    assert.throws(
      () => broker.mintSecondOrderCanary({ runId: badRunId }),
      InvalidRunIdError,
      `CanaryBroker.mintSecondOrderCanary must reject "${badRunId}"`,
    )
    assert.throws(
      () => relay.registerCanary({ token: sampleToken, canaryId: 'cid', runId: badRunId }),
      InvalidRunIdError,
      `OobRelay.registerCanary must reject "${badRunId}"`,
    )
    assert.throws(
      () => relay.subscribe({ runId: badRunId, assignmentId: 'a1', canaryId: 'cid', token: sampleToken, artifact: 'art' }),
      InvalidRunIdError,
      `OobRelay.subscribe must reject "${badRunId}"`,
    )
  }

  // Two concurrent runs sharing the same AppRuntime & CanaryBroker/OobRelay.
  const ctxA = runtime.createRunContext('run-oob-alpha')
  const ctxB = runtime.createRunContext('run-oob-beta')

  const canaryA = broker.mintCanary(ctxA.runId, 'webhook-a', 'https://alpha.example.test')
  const canaryB = broker.mintCanary(ctxB.runId, 'webhook-b', 'https://beta.example.test')
  const soA = broker.mintSecondOrderCanary({ runId: ctxA.runId, assignmentId: 'assign-a' })
  const soB = broker.mintSecondOrderCanary({ runId: ctxB.runId, assignmentId: 'assign-b' })
  assert.equal(soA.runId, ctxA.runId)
  assert.equal(soB.runId, ctxB.runId)

  const subA = broker.subscribe({
    runId: ctxA.runId,
    assignmentId: 'assign-a',
    canaryId: canaryA.id,
    token: canaryA.token,
    artifact: 'ex-alpha-1',
    immediateMs: 0,
  })
  const subB = broker.subscribe({
    runId: ctxB.runId,
    assignmentId: 'assign-b',
    canaryId: canaryB.id,
    token: canaryB.token,
    artifact: 'ex-beta-1',
    immediateMs: 0,
  })
  assert.equal(subA.status, 'pending')
  assert.equal(subB.status, 'pending')
  assert.equal(broker.pending(ctxA.runId).length, 1)
  assert.equal(broker.pending(ctxB.runId).length, 1)

  // Deliver callback for runA: visible to runA, completely invisible to runB!
  broker.recordCallback(canaryA.token, {
    method: 'POST',
    path: `/c/${canaryA.token}`,
    remoteIp: '203.0.113.10',
    artifact: 'ex-alpha-1',
  })

  const checkAFromA = broker.checkCanary(canaryA.token, { runId: ctxA.runId })
  const checkAFromB = broker.checkCanary(canaryA.token, { runId: ctxB.runId })
  assert.equal(checkAFromA.hit, true)
  assert.equal(checkAFromB.found, false, 'runB must never see runA canary')
  assert.equal(checkAFromB.hit, false, 'runB must never see runA hits')
  assert.equal(relay.check({ token: canaryA.token, runId: ctxA.runId }).matched, true)
  assert.equal(relay.check({ token: canaryA.token, runId: ctxB.runId }).matched, false)

  // Disposing ctxA triggers automatic OOB unsubscribeRun(ctxA.runId) WITHOUT touching ctxB!
  const disposeA = await ctxA.dispose()
  assert.deepEqual(disposeA.resourceErrors, [])
  assert.equal(broker.pending(ctxA.runId).length, 0, 'runA pending subscriptions must be expired on dispose')
  assert.equal(broker.checkCanary(canaryA.token, { runId: ctxA.runId }).found, false, 'runA in-memory canary must be evicted')

  // runB remains completely intact and promotes its late callback cleanly!
  assert.equal(broker.pending(ctxB.runId).length, 1, 'disposing runA must leave runB subscriptions intact')
  const cbB = relay.recordCallback({
    token: canaryB.token,
    artifact: 'ex-beta-1',
    sourceIp: '203.0.113.20',
    method: 'POST',
    path: '/hook-beta',
  })
  assert.equal(cbB.accepted, true)
  const promotedB = broker.promoteLate({ runId: ctxB.runId })
  assert.equal(promotedB.length, 1)
  assert.equal(promotedB[0]!.subscription.runId, ctxB.runId)
  assert.equal(promotedB[0]!.subscription.status, 'promoted')

  // Cleanly dispose runB too.
  await ctxB.dispose()
  assert.equal(runtime.runs.size, 0)
  assert.equal(new GlobalKillSwitch().isActive(), false)
})
