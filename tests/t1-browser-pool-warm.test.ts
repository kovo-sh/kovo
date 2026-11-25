/**
 * Tier 1 regression tests for CLAUDE_AUDIT H-24, H-30, and H-31:
 *   - H-24: ScopedBrowser pooled context binds a mutable per-checkout activeGrant (HTTP + WS).
 *   - H-30: Deleting a run mid-OOB-drain or mid-finalize never emits an unhandled rejection,
 *           while genuine unexpected storage bugs are not swallowed.
 *   - H-31: Warm-pool & worker containers carry kovo.owner_pid + kovo.pool_instance labels and
 *           removeStaleCreated()/removeInactive() never reap containers owned by a live PID.
 */
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test, type TestContext } from 'node:test'

import { BrokerDenied, type BrokerExchangeResult, type BrokerHttpRequest, type Grant, type RequestBroker } from '../src/server/broker.ts'
import {
  commitFinalReport,
  drainPendingOob,
  isDeletedRunRaceError,
  isOobDrainActive,
  scheduleFinalReport,
  type FinalizeHost,
  type FinalizeStore,
  type OobDrainRelay,
  type OobDrainResult,
} from '../src/server/oob-drain.ts'
import { ScopedBrowser, type PlaywrightBrowserLike, type PlaywrightCdpSession } from '../src/server/scoped-browser.ts'
import { deleteRunWithActiveGuard, type Run } from '../src/server/store.ts'
import {
  LinuxWorkerBackend,
  WORKER_OWNER_PID_LABEL,
  WORKER_POOL_INSTANCE_LABEL,
  WarmWorkerPool,
  isOwnerPidAlive,
  workerContainerCreateArgs,
  type DockerRunner,
} from '../src/server/worker-backend.ts'
import { makeLabGrant, makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

// ============================================================================
// H-24: ScopedBrowser pooled context mutable per-checkout activeGrant
// ============================================================================

type FakeRequestSpec = {
  url: string
  method?: string
  resourceType?: string
  body?: string | null
  headers?: Record<string, string>
}

class FakeCdp implements PlaywrightCdpSession {
  async send(): Promise<unknown> { return undefined }
  on(): void { /* no-op */ }
  async detach(): Promise<void> { /* no-op */ }
}

class FakeWebSocketRoute {
  readonly targetUrl: string
  closedWith: { code?: number; reason?: string } | null = null
  connected = false
  constructor(url: string) { this.targetUrl = url }
  url(): string { return this.targetUrl }
  async close(options?: { code?: number; reason?: string }): Promise<void> {
    this.closedWith = options ?? {}
  }
  async connectToServer(): Promise<void> {
    this.connected = true
  }
}

class FakeRoute {
  private readonly spec: FakeRequestSpec
  private readonly context: FakeContext
  constructor(spec: FakeRequestSpec, context: FakeContext) {
    this.spec = spec
    this.context = context
  }
  request() {
    return {
      url: () => this.spec.url,
      method: () => this.spec.method ?? 'GET',
      headers: () => this.spec.headers ?? {},
      postData: () => this.spec.body ?? null,
      resourceType: () => this.spec.resourceType ?? 'document',
    }
  }
  async abort(errorCode?: string): Promise<void> {
    this.context.aborted.push({ url: this.spec.url, errorCode: errorCode ?? null })
  }
  async fulfill(response: { status?: number; contentType?: string; body?: string | Buffer }): Promise<void> {
    this.context.fulfilled.push({ url: this.spec.url, status: response.status })
  }
}

class FakePage {
  urlValue = 'about:blank'
  private readonly context: FakeContext
  private readonly onGoto?: (ctx: FakeContext, url: string) => Promise<void> | void
  constructor(context: FakeContext, onGoto?: (ctx: FakeContext, url: string) => Promise<void> | void) {
    this.context = context
    this.onGoto = onGoto
  }
  on(): void { /* no-op */ }
  async goto(url: string): Promise<{ status(): number }> {
    this.urlValue = url
    if (this.context.routeHandler) {
      await this.context.routeHandler(new FakeRoute({ url, method: 'GET', resourceType: 'document' }, this.context))
    }
    if (this.onGoto) await this.onGoto(this.context, url)
    const lastFulfilled = this.context.fulfilled.at(-1)
    const status = lastFulfilled && lastFulfilled.url === url ? (lastFulfilled.status ?? 200) : 0
    return { status: () => status }
  }
  async waitForTimeout(): Promise<void> { /* no-op */ }
  async waitForLoadState(): Promise<void> { /* no-op */ }
  url(): string { return this.urlValue }
  async title(): Promise<string> { return 'h24-fixture' }
  async evaluate<T>(fn: (...args: unknown[]) => T): Promise<T> {
    const src = fn.toString()
    if (src.includes('MutationObserver')) return undefined as T
    return {
      domHtml: '<html><body>ok</body></html>',
      links: [],
      forms: [],
      cookieNames: [],
      localStorageKeys: [],
      sessionStorageKeys: [],
      postMessageListeners: {
        count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false,
      },
    } as T
  }
  async close(): Promise<void> { /* no-op */ }
}

class FakeContext {
  readonly fulfilled: Array<{ url: string; status?: number }> = []
  readonly aborted: Array<{ url: string; errorCode: string | null }> = []
  routeHandler: ((route: FakeRoute) => Promise<void> | void) | null = null
  wsHandler: ((ws: FakeWebSocketRoute) => Promise<void> | void) | null = null
  private readonly onGoto?: (ctx: FakeContext, url: string) => Promise<void> | void
  constructor(onGoto?: (ctx: FakeContext, url: string) => Promise<void> | void) {
    this.onGoto = onGoto
  }
  async addInitScript(): Promise<void> { /* no-op */ }
  async addCookies(): Promise<void> { /* no-op */ }
  async route(_pattern: string, handler: (route: FakeRoute) => Promise<void> | void): Promise<void> {
    this.routeHandler = handler
  }
  async routeWebSocket(_pattern: string, handler: (ws: FakeWebSocketRoute) => Promise<void> | void): Promise<void> {
    this.wsHandler = handler
  }
  async newPage(): Promise<FakePage> { return new FakePage(this, this.onGoto) }
  async newCDPSession(): Promise<FakeCdp> { return new FakeCdp() }
  async close(): Promise<void> { /* no-op */ }
}

class FakeBrowser {
  readonly contexts: FakeContext[] = []
  onGoto?: (ctx: FakeContext, url: string) => Promise<void> | void
  async newContext(): Promise<FakeContext> {
    const ctx = new FakeContext((c, u) => this.onGoto?.(c, u))
    this.contexts.push(ctx)
    return ctx
  }
  async close(): Promise<void> { /* no-op */ }
  asPlaywright(): PlaywrightBrowserLike { return this as unknown as PlaywrightBrowserLike }
}

function fakeExchange(req: BrokerHttpRequest): BrokerExchangeResult {
  return {
    origin: req.origin,
    finalOrigin: req.origin,
    redirectOrigins: [req.origin],
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    personaHandle: req.persona ?? null,
    status: 200,
    mediaType: 'text/html',
    reqHeaders: {},
    respHeaders: {},
    setCookies: [],
    bodyPreview: '',
    body: '<html><body>ok</body></html>',
    bodySha256: '0'.repeat(64),
    bodyBytes: 26,
    bodyTruncated: false,
    durationMs: 1,
    observation: { source: 'fixture response' },
  } as unknown as BrokerExchangeResult
}

describe('H-24: pooled browser context activeGrant lifecycle', () => {
  test('reused pooled context switches to Assignment 2 grant after Assignment 1 grant is revoked (HTTP + WS)', async (t: TestContext) => {
    const originA = 'https://app-a.fixture.test'
    const originB = 'https://app-b.fixture.test'

    let grant1Revoked = false
    const seenGrants: Array<{ path: string; grantId: string }> = []
    const grant1Checks: string[] = []
    const grant2Checks: string[] = []

    const grant1 = Object.assign(
      makeLabGrant(originA, {
        tier: 3,
        allowLocalLab: false,
        canRead: (o: string) => {
          grant1Checks.push(o)
          return !grant1Revoked && o === originA
        },
      }),
      { __grantId: 'grant-1' },
    )
    const grant2 = Object.assign(
      makeLabGrant(originB, {
        tier: 3,
        allowLocalLab: false,
        canRead: (o: string) => {
          grant2Checks.push(o)
          return o === originB || o === originA
        },
      }),
      { __grantId: 'grant-2' },
    )

    const broker = {
      executeHttp: async (req: BrokerHttpRequest, grant: Grant) => {
        const gid = (grant as Grant & { __grantId?: string }).__grantId ?? 'unknown'
        seenGrants.push({ path: req.pathAndQuery, grantId: gid })
        if (gid === 'grant-1' && grant1Revoked) {
          throw new BrokerDenied('Stale grant-1 was revoked after Assignment 1')
        }
        return fakeExchange(req)
      },
      sessionCookiesForBrowser: () => [],
      getRegisteredSecrets: () => [],
      getStorage: () => undefined,
    } as unknown as RequestBroker

    const fake = new FakeBrowser()
    const wsResults: Array<{ phase: string; connected: boolean; closedCode?: number }> = []
    fake.onGoto = async (ctx, url) => {
      if (!ctx.wsHandler) return
      const wsUrl = url.includes('page-1') ? 'wss://app-a.fixture.test/ws' : 'wss://app-b.fixture.test/ws'
      const ws = new FakeWebSocketRoute(wsUrl)
      await ctx.wsHandler(ws)
      wsResults.push({
        phase: url.includes('page-1') ? 'asgn-1' : 'asgn-2',
        connected: ws.connected,
        closedCode: ws.closedWith?.code,
      })
    }

    const browser = new ScopedBrowser(broker, { launchBrowser: async () => fake.asPlaywright() })
    t.after(() => browser.close())

    // Assignment 1 creates and checks out the pooled context with grant1.
    const [r1] = await browser.visitPages(
      [{ origin: originA, pathAndQuery: '/page-1', runId: 'run-h24', persona: 'admin', assignmentId: 'asgn-1' }],
      grant1,
      AbortSignal.timeout(10_000),
    )
    assert.equal(r1.status, 200)
    assert.equal(r1.exchanges.length, 1)
    assert.equal(browser.getPoolStats().contextsCreated, 1)

    // Revoke grant1 (simulating Assignment 1 finishing and its grant expiring/revoking).
    grant1Revoked = true
    const grant1ChecksAfterAsgn1 = grant1Checks.length

    // Assignment 2 reuses the EXACT SAME pooled context (same runId + persona) with grant2.
    const [r2] = await browser.visitPages(
      [{ origin: originB, pathAndQuery: '/page-2', runId: 'run-h24', persona: 'admin', assignmentId: 'asgn-2' }],
      grant2,
      AbortSignal.timeout(10_000),
    )
    assert.equal(browser.getPoolStats().contextsCreated, 1, 'pooled context must be reused across assignments')
    assert.equal(r2.status, 200, 'Assignment 2 must succeed using grant2 instead of failing on revoked grant1')
    assert.equal(r2.exchanges.length, 1)
    assert.deepEqual(seenGrants, [
      { path: '/page-1', grantId: 'grant-1' },
      { path: '/page-2', grantId: 'grant-2' },
    ])
    assert.equal(grant1Checks.length, grant1ChecksAfterAsgn1, 'revoked grant1 must not be consulted during Assignment 2')
    assert.ok(grant2Checks.includes(originB), 'live grant2 must be consulted during Assignment 2')
    assert.deepEqual(wsResults, [
      { phase: 'asgn-1', connected: true, closedCode: undefined },
      { phase: 'asgn-2', connected: true, closedCode: undefined },
    ], 'WebSocket guard must also read the live activeGrant on each assignment')

    // After release (no active checkout), stray HTTP and WS requests must fail closed.
    const ctx = fake.contexts[0]!
    const abortedBefore = ctx.aborted.length
    await ctx.routeHandler!(new FakeRoute({ url: `${originB}/stray`, method: 'GET' }, ctx))
    assert.equal(ctx.aborted.length, abortedBefore + 1, 'stray HTTP request after release must be aborted fail-closed')
    const strayWs = new FakeWebSocketRoute('wss://app-b.fixture.test/stray')
    await ctx.wsHandler!(strayWs)
    assert.equal(strayWs.connected, false, 'stray WS upgrade after release must fail closed')
    assert.equal(strayWs.closedWith?.code, 1008)
  })
})

// ============================================================================
// H-30: Run deletion mid-OOB-drain / mid-finalize without unhandled rejections
// ============================================================================

function waitMicrotasks(ms = 30): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

describe('H-30: run deletion mid-OOB-drain / finalize safety', () => {
  test('deleting a run mid-OOB-drain emits zero unhandled rejections and clears drain state', async (t: TestContext) => {
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => { unhandled.push(reason) }
    process.on('unhandledRejection', onUnhandled)
    t.after(() => process.off('unhandledRejection', onUnhandled))

    const { storage } = makeStore(t, 'kovo-h30-delete-mid-drain-')
    const { runId } = await setupApprovedRun(storage, { seeds: ['https://h30.fixture.test'], tier: 3, environment: 'public' })
    storage.updateRun(runId, { phase: 'verification', status: 'running' })
    const run = storage.run(runId)

    let resolveDrain!: (res: OobDrainResult) => void
    const drainPromise = new Promise<OobDrainResult>(resolve => { resolveDrain = resolve })
    const errors: unknown[] = []

    const host: FinalizeHost = {
      storage,
      relay: {
        pending: () => [{ id: 'sub-1' }],
        promoteLate: () => [],
      },
      draining: new Set(),
      lastDrain: new Map(),
      drain: () => drainPromise,
      onError: err => errors.push(err),
    }

    scheduleFinalReport(host, run)
    assert.equal(host.draining.has(runId), true)
    assert.equal(isOobDrainActive(runId), true)

    // Delete the run while OOB drain is still in flight.
    const deleted = storage.deleteRun(runId)
    assert.equal(deleted.deleted, true)

    // Resolve the deferred drain AFTER the run row is gone.
    resolveDrain({ oobDrainMs: 25, promotedLate: 0, remaining: 1 })
    await waitMicrotasks(40)

    assert.equal(unhandled.length, 0, 'deleting a run mid-OOB-drain must never emit unhandledRejection')
    assert.equal(errors.length, 0, 'deleted-run race must not surface as an unexpected storage error')
    assert.equal(host.draining.has(runId), false, 'draining lock must be released')
    assert.equal(host.lastDrain.has(runId), false, 'lastDrain entry for deleted run must be cleared')
    assert.equal(isOobDrainActive(runId), false)
  })

  test('deleteRunWithActiveGuard refuses active drain without stopActive and cancels drain promptly with stopActive', async (t: TestContext) => {
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => { unhandled.push(reason) }
    process.on('unhandledRejection', onUnhandled)
    t.after(() => process.off('unhandledRejection', onUnhandled))

    const { storage } = makeStore(t, 'kovo-h30-guard-drain-')
    const { runId } = await setupApprovedRun(storage, { seeds: ['https://h30-guard.fixture.test'], tier: 3, environment: 'public' })
    storage.updateRun(runId, { phase: 'verification', status: 'running' })
    const run = storage.run(runId)

    const relay: OobDrainRelay = {
      pending: () => [{ id: 'sub-long' }],
      promoteLate: () => [],
    }
    const host: FinalizeHost = {
      storage,
      relay,
      draining: new Set(),
      lastDrain: new Map(),
      drain: id => drainPendingOob(relay, id, { graceMs: 30_000, pollMs: 5_000 }),
    }
    scheduleFinalReport(host, run)
    assert.equal(isOobDrainActive(runId), true)

    const mockExec = { wake: () => {}, getLabTargetHandle: () => undefined }
    const mockLab = { getTarget: () => undefined, stopLabTarget: async () => undefined }

    // Without stopActive, active/draining run cannot be deleted.
    await assert.rejects(
      () => deleteRunWithActiveGuard(storage, mockExec, mockLab, { runId }),
      /currently active/i,
    )

    // With stopActive, delete cancels the 30s drain promptly and deletes the run with zero unhandled rejections.
    const started = Date.now()
    const res = await deleteRunWithActiveGuard(storage, mockExec, mockLab, {
      runId,
      stopActive: true,
      waitTimeoutMs: 2_000,
    })
    const elapsedMs = Date.now() - started
    await waitMicrotasks(40)

    assert.equal(res.deleted, true)
    assert.ok(elapsedMs < 1_500, `expected OOB drain cancellation to complete promptly, took ${elapsedMs} ms`)
    assert.equal(unhandled.length, 0, 'Stop & Delete during OOB drain must emit zero unhandled rejections')
    assert.equal(host.draining.has(runId), false)
    assert.equal(isOobDrainActive(runId), false)
  })

  test('FOREIGN KEY race mid-finalize is ignored while genuine unexpected storage bugs are NOT swallowed', async (t: TestContext) => {
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => { unhandled.push(reason) }
    process.on('unhandledRejection', onUnhandled)
    t.after(() => process.off('unhandledRejection', onUnhandled))

    const fakeRun = {
      id: 'run-fk-race',
      status: 'running',
      phase: 'verification',
      coordinatorId: 'coord-1',
    } as Run

    // 1. FOREIGN KEY constraint failure during async finalize -> benign deleted-run race.
    const fkErrors: unknown[] = []
    const fkStore: FinalizeStore = {
      run: () => fakeRun,
      transaction: fn => fn(),
      updateRun: () => ({ ...fakeRun, phase: 'complete', status: 'complete' }),
      writeReport: () => 'report',
      message: () => {
        const err = Object.assign(new Error('FOREIGN KEY constraint failed'), { code: 'SQLITE_CONSTRAINT_FOREIGNKEY' })
        throw err
      },
    }
    const fkHost: FinalizeHost = {
      storage: fkStore,
      relay: { pending: () => [{ id: 's1' }], promoteLate: () => [] },
      draining: new Set(),
      lastDrain: new Map(),
      drain: async () => ({ oobDrainMs: 1, promotedLate: 0, remaining: 0 }),
      onError: err => fkErrors.push(err),
    }
    scheduleFinalReport(fkHost, fakeRun)
    await waitMicrotasks(30)
    assert.equal(unhandled.length, 0)
    assert.equal(fkErrors.length, 0, 'FOREIGN KEY deleted-run race must be ignored cleanly')
    assert.equal(fkHost.draining.has(fakeRun.id), false)

    // 2. Genuine unexpected storage error (e.g. disk I/O error) must NOT be swallowed.
    const ioErr = Object.assign(new Error('SQLITE_IOERR: disk I/O error'), { code: 'SQLITE_IOERR' })
    assert.equal(isDeletedRunRaceError(ioErr), false)
    assert.equal(isDeletedRunRaceError(new Error('Run not found.')), true)
    assert.equal(isDeletedRunRaceError(Object.assign(new Error('FOREIGN KEY constraint failed'), { code: 'SQLITE_CONSTRAINT_FOREIGNKEY' })), true)

    const brokenStore: FinalizeStore = {
      run: () => fakeRun,
      transaction: fn => fn(),
      updateRun: () => { throw ioErr },
      writeReport: () => 'report',
      message: () => undefined,
    }
    const observedErrors: unknown[] = []
    const brokenHost: FinalizeHost = {
      storage: brokenStore,
      relay: { pending: () => [{ id: 's1' }], promoteLate: () => [] },
      draining: new Set(),
      lastDrain: new Map(),
      drain: async () => ({ oobDrainMs: 1, promotedLate: 0, remaining: 0 }),
      onError: err => observedErrors.push(err),
    }

    // Sync commitFinalReport rethrows genuine storage bugs.
    assert.throws(() => commitFinalReport(brokenHost, fakeRun), /SQLITE_IOERR/)

    // Async scheduleFinalReport surfaces genuine storage bugs to onError (not silently swallowed).
    scheduleFinalReport(brokenHost, fakeRun)
    await waitMicrotasks(30)
    assert.equal(observedErrors.length, 1, 'genuine unexpected storage error must be surfaced')
    assert.equal(observedErrors[0], ioErr)
    assert.equal(unhandled.length, 0)
  })
})

// ============================================================================
// H-31: Warm-pool owner PID label + PID-safe removeStaleCreated / removeInactive
// ============================================================================

async function getGuaranteedDeadPid(): Promise<number> {
  const child = spawn(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore' })
  const pid = child.pid!
  await new Promise<void>(resolve => child.once('exit', () => resolve()))
  return pid
}

describe('H-31: warm-pool owner PID attribution and stale sweep isolation', () => {
  test('WarmWorkerPool and workerContainerCreateArgs stamp kovo.owner_pid and kovo.pool_instance', async () => {
    const dockerCalls: string[][] = []
    const runner: DockerRunner = async args => {
      dockerCalls.push([...args])
      return ''
    }

    const directArgs = workerContainerCreateArgs({
      image: 'kovo-worker:v4',
      name: `kovo-${randomUUID()}`,
      assignmentId: 'asgn-labels',
      runLabel: 'run-labels',
      poolInstanceId: 'pool-inst-1',
    })
    assert.ok(directArgs.includes(`${WORKER_OWNER_PID_LABEL}=${process.pid}`))
    assert.ok(directArgs.includes(`${WORKER_POOL_INSTANCE_LABEL}=pool-inst-1`))

    const pool = new WarmWorkerPool({
      cell: 'cell-h31',
      image: 'kovo-worker:v4',
      dockerRunner: runner,
      runLabel: 'run-h31',
      capacity: 1,
    })
    try {
      const warmed = await pool.warm()
      assert.ok(warmed)
      const createCall = dockerCalls.find(args => args[0] === 'container' && args[1] === 'create')!
      assert.ok(createCall, 'WarmWorkerPool.warm() must invoke docker container create')
      assert.ok(createCall.includes(`${WORKER_OWNER_PID_LABEL}=${process.pid}`), 'warm container must carry owner PID label')
      assert.ok(createCall.includes(`${WORKER_POOL_INSTANCE_LABEL}=${pool.instanceId}`), 'warm container must carry pool instance ID label')
    } finally {
      await pool.close()
    }
  })

  test('removeStaleCreated() skips containers with live PID, sweeps dead PID, and applies grace threshold to unlabelled containers', async () => {
    const deadPid = await getGuaranteedDeadPid()
    assert.equal(isOwnerPidAlive(process.pid), true, 'current process PID must be reported alive')
    assert.equal(isOwnerPidAlive(deadPid), false, 'exited child PID must be reported dead (ESRCH)')

    const now = Date.now()
    const liveOldId = '1'.repeat(64)
    const liveOldName = `kovo-${randomUUID()}`
    const deadOldId = '2'.repeat(64)
    const deadOldName = `kovo-${randomUUID()}`
    const deadFreshId = '3'.repeat(64)
    const deadFreshName = `kovo-${randomUUID()}`
    const unlabelledOldId = '4'.repeat(64)
    const unlabelledOldName = `kovo-${randomUUID()}`
    const unlabelledFreshId = '5'.repeat(64)
    const unlabelledFreshName = `kovo-${randomUUID()}`

    const lsRows = [
      // Aged idle warm container owned by a LIVE parallel process -> MUST BE SKIPPED!
      `${liveOldId}\t${liveOldName}\t${now - 10 * 60_000}\t2026-11-25 00:00:00 +0000 UTC\t${process.pid}\tpool-live-peer`,
      // Aged container owned by a DEAD process -> MUST BE SWEPT!
      `${deadOldId}\t${deadOldName}\t${now - 10 * 60_000}\t2026-11-25 00:00:00 +0000 UTC\t${deadPid}\tpool-dead-old`,
      // Recent container owned by a DEAD process -> MUST BE SWEPT!
      `${deadFreshId}\t${deadFreshName}\t${now - 2_000}\t2026-11-25 00:00:00 +0000 UTC\t${deadPid}\tpool-dead-fresh`,
      // Legacy unlabelled aged container -> MUST BE SWEPT!
      `${unlabelledOldId}\t${unlabelledOldName}\t${now - 10 * 60_000}\t2026-11-25 00:00:00 +0000 UTC\t\t`,
      // Legacy unlabelled fresh container (within grace window) -> MUST BE SKIPPED!
      `${unlabelledFreshId}\t${unlabelledFreshName}\t${now - 1_000}\t2026-11-25 00:00:00 +0000 UTC\t\t`,
    ].join('\n')

    const removedIds: string[] = []
    let sawOwnerPidFormat = false
    const runner: DockerRunner = async args => {
      if (args[0] === 'container' && args[1] === 'ls') {
        const formatArg = args[args.indexOf('--format') + 1] ?? ''
        if (formatArg.includes(WORKER_OWNER_PID_LABEL)) sawOwnerPidFormat = true
        return lsRows
      }
      if (args[0] === 'container' && args[1] === 'rm') {
        const forceIdx = args.indexOf('--force')
        removedIds.push(...args.slice(forceIdx + 1))
        return ''
      }
      return ''
    }

    const backend = new LinuxWorkerBackend({ dockerRunner: runner, staleCreatedMs: 120_000 })
    await backend.reclaimInactive()

    assert.equal(sawOwnerPidFormat, true, 'removeStaleCreated must query kovo.owner_pid label from Docker')
    assert.ok(!removedIds.includes(liveOldId), 'live-PID idle warm container must NEVER be swept even when older than grace window')
    assert.ok(removedIds.includes(deadOldId), 'aged dead-PID container must be swept')
    assert.ok(removedIds.includes(deadFreshId), 'dead-PID container must be swept even when recently created')
    assert.ok(removedIds.includes(unlabelledOldId), 'aged unlabelled container must be swept')
    assert.ok(!removedIds.includes(unlabelledFreshId), 'fresh unlabelled container within grace threshold must be spared')
  })

  test('removeInactive(owner) spares containers labeled with a live sibling PID while reaping dead-PID and unlabelled orphans', async (t: TestContext) => {
    const wsDir = mkdtempSync(join(tmpdir(), 'kovo-h31-ws-'))
    t.after(() => rmSync(wsDir, { recursive: true, force: true }))
    const deadPid = await getGuaranteedDeadPid()

    const liveSiblingId = 'a'.repeat(64)
    const liveSiblingName = `kovo-${randomUUID()}`
    const deadOrphanId = 'b'.repeat(64)
    const deadOrphanName = `kovo-${randomUUID()}`
    const legacyOrphanId = 'c'.repeat(64)
    const legacyOrphanName = `kovo-${randomUUID()}`
    const now = Date.now()

    const removedIds: string[] = []
    const runner: DockerRunner = async args => {
      if (args[0] === 'container' && args[1] === 'ls') {
        const hasWorkspaceFilter = args.some(a => a.startsWith('label=dev.kovo.workspace='))
        if (!hasWorkspaceFilter) return ''
        return [
          `${liveSiblingId}\t${liveSiblingName}\t${now - 60_000}\t2026-11-25 00:00:00 +0000 UTC\tother-session-1\t${process.pid}`,
          `${deadOrphanId}\t${deadOrphanName}\t${now - 60_000}\t2026-11-25 00:00:00 +0000 UTC\tother-session-2\t${deadPid}`,
          `${legacyOrphanId}\t${legacyOrphanName}\t${now - 60_000}\t2026-11-25 00:00:00 +0000 UTC\tother-session-3\t`,
        ].join('\n')
      }
      if (args[0] === 'container' && args[1] === 'rm') {
        const forceIdx = args.indexOf('--force')
        removedIds.push(...args.slice(forceIdx + 1))
        return ''
      }
      return ''
    }

    const backend = new LinuxWorkerBackend({
      workspace: { id: 'ws-h31', directory: wsDir },
      dockerRunner: runner,
    })
    t.after(() => backend.closeWarmPool())
    await backend.reclaimInactive()

    assert.ok(!removedIds.includes(liveSiblingId), 'live sibling PID container in same workspace must be spared')
    assert.ok(removedIds.includes(deadOrphanId), 'dead-PID container in same workspace must be reaped')
    assert.ok(removedIds.includes(legacyOrphanId), 'unlabelled orphan in same workspace must be reaped')
  })
})
