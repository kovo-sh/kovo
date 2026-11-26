/**
 * Systemic Quality Move Q3 regression suite:
 *   1. OOB Relay `pruneCallbacks()` self-poisoning fix: separate claimed vs. unclaimed caps/TTLs,
 *      and zero eviction of unclaimed callbacks matching active `pending_oob` subscriptions.
 *   2. `oob-drain.ts` structured error diagnostics & explicit report coverage gaps on relay/SQLite
 *      failures (no silent swallowing as `0` in `drainPendingOob` or `scheduleFinalReport`).
 *   3. Headless Browser Pool resilience in `scoped-browser.ts`:
 *      - Crash lockout recovery (`disconnected` event + `isConnected()` check + atomic relaunch).
 *      - Cross-origin SPA credential attachment for allowlisted in-scope sibling origins with
 *        zero leakage to non-allowlisted, third-party, or passive asset origins.
 *      - Bounded semaphore wait/backpressure replacing silent LRU eviction bypass.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { eq } from 'drizzle-orm'

import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'
import {
  buildOobDrainCoverageGap,
  drainPendingOob,
  scheduleFinalReport,
  type FinalizeHost,
  type OobDrainRelay,
} from '../src/server/oob-drain.ts'
import { OobRelay } from '../src/server/oob-relay.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { reports } from '../src/server/schema.ts'
import {
  ScopedBrowser,
  resolvePersonaForBrowserRequest,
  type PlaywrightBrowserLike,
  type PlaywrightCdpSession,
} from '../src/server/scoped-browser.ts'
import { Store } from '../src/server/store.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTempStore(t: TestContext, prefix: string): Store {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* ignore */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return store
}

async function createVerificationRun(store: Store, origin: string) {
  const { runId } = await setupApprovedRun(store, { seeds: [origin], tier: 3, environment: 'public' })
  store.updateRun(runId, { phase: 'verification', status: 'running' })
  return store.run(runId)
}

function makeCanaryToken(index: number): string {
  return `gn2o_${index.toString(16).padStart(12, '0')}`
}

function fakeExchange(req: BrokerHttpRequest, status = 200, body = '<html><body>ok</body></html>'): BrokerExchangeResult {
  return {
    origin: req.origin,
    finalOrigin: req.origin,
    redirectOrigins: [req.origin],
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    personaHandle: req.persona ?? null,
    status,
    mediaType: 'text/html',
    reqHeaders: req.headers ?? {},
    respHeaders: { 'content-type': 'text/html; charset=utf-8' },
    setCookies: [],
    bodyPreview: '',
    body,
    bodySha256: '0'.repeat(64),
    bodyBytes: Buffer.byteLength(body),
    bodyTruncated: false,
    durationMs: 1,
    observation: { source: 'q3-fixture' },
  } as unknown as BrokerExchangeResult
}

function makeFakeBroker(
  handler?: (req: BrokerHttpRequest) => Promise<BrokerExchangeResult> | BrokerExchangeResult,
): RequestBroker {
  return {
    getRegisteredSecrets: () => [],
    getStorage: () => undefined,
    sessionCookiesForBrowser: () => [],
    executeHttp: async (req: BrokerHttpRequest) => (handler ? await handler(req) : fakeExchange(req)),
  } as unknown as RequestBroker
}

class FakeCdp implements PlaywrightCdpSession {
  async send(): Promise<unknown> { return undefined }
  on(): void { /* no-op */ }
  async detach(): Promise<void> { /* no-op */ }
}

class FakeRoute {
  readonly reqUrl: string
  readonly reqMethod: string
  readonly reqResourceType: string
  readonly reqHeaders: Record<string, string>
  private readonly ctx: FakeContext
  constructor(
    ctx: FakeContext,
    spec: { url: string; method?: string; resourceType?: string; headers?: Record<string, string> },
  ) {
    this.ctx = ctx
    this.reqUrl = spec.url
    this.reqMethod = spec.method ?? 'GET'
    this.reqResourceType = spec.resourceType ?? 'document'
    this.reqHeaders = spec.headers ?? {}
  }
  request() {
    return {
      url: () => this.reqUrl,
      method: () => this.reqMethod,
      headers: () => this.reqHeaders,
      postData: () => null,
      resourceType: () => this.reqResourceType,
    }
  }
  async abort(errorCode?: string): Promise<void> {
    this.ctx.aborted.push({ url: this.reqUrl, errorCode: errorCode ?? null })
  }
  async fulfill(response: { status?: number }): Promise<void> {
    this.ctx.fulfilled.push({ url: this.reqUrl, status: response.status })
  }
}

interface FakeBrowserHooks {
  onNewContext?: (ctx: FakeContext) => Promise<void> | void
  onGoto?: (page: FakePage, url: string) => Promise<void> | void
}

class FakePage {
  urlValue = 'about:blank'
  closed = false
  readonly ctx: FakeContext
  private readonly hooks: FakeBrowserHooks

  constructor(ctx: FakeContext, hooks: FakeBrowserHooks) {
    this.ctx = ctx
    this.hooks = hooks
  }

  on(): void { /* no-op */ }
  async exposeBinding(): Promise<void> { /* no-op */ }

  async triggerSubrequest(spec: {
    url: string
    method?: string
    resourceType?: string
    headers?: Record<string, string>
  }): Promise<void> {
    if (!this.ctx.routeHandler) return
    await this.ctx.routeHandler(new FakeRoute(this.ctx, spec))
  }

  async goto(url: string): Promise<{ status(): number }> {
    if (this.closed || this.ctx.closed || !this.ctx.browser.connected) {
      throw new Error('Target page, context or browser has been closed')
    }
    this.urlValue = url
    if (this.ctx.routeHandler) {
      await this.ctx.routeHandler(new FakeRoute(this.ctx, { url, method: 'GET', resourceType: 'document' }))
    }
    if (this.hooks.onGoto) {
      await this.hooks.onGoto(this, url)
    }
    if (this.closed || this.ctx.closed || !this.ctx.browser.connected) {
      throw new Error('Target page, context or browser has been closed mid-navigation')
    }
    const last = this.ctx.fulfilled.at(-1)
    return { status: () => (last && last.url === url ? (last.status ?? 200) : 200) }
  }

  async waitForTimeout(): Promise<void> { /* no-op */ }
  async waitForLoadState(): Promise<void> { /* no-op */ }
  url(): string { return this.urlValue }
  async title(): Promise<string> { return 'q3-fixture' }

  async evaluate<T>(fn: (...args: unknown[]) => T): Promise<T> {
    if (this.closed || this.ctx.closed || !this.ctx.browser.connected) {
      throw new Error('Target page, context or browser has been closed')
    }
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
      canaryTriggered: false,
      canaryDetail: null,
      sinkTraces: [],
      selectorResult: null,
      fetchResult: null,
    } as unknown as T
  }

  async close(): Promise<void> { this.closed = true }
}

class FakeContext {
  closed = false
  routeHandler: ((route: FakeRoute) => Promise<void> | void) | null = null
  readonly aborted: Array<{ url: string; errorCode: string | null }> = []
  readonly fulfilled: Array<{ url: string; status: number | undefined }> = []
  readonly pages: FakePage[] = []
  readonly browser: FakeBrowser
  private readonly hooks: FakeBrowserHooks

  constructor(browser: FakeBrowser, hooks: FakeBrowserHooks) {
    this.browser = browser
    this.hooks = hooks
  }

  async addInitScript(): Promise<void> { /* no-op */ }
  async addCookies(): Promise<void> { /* no-op */ }
  async setExtraHTTPHeaders(): Promise<void> { /* no-op */ }
  async route(_pattern: string, handler: (route: FakeRoute) => Promise<void> | void): Promise<void> {
    this.routeHandler = handler
  }
  async routeWebSocket(): Promise<void> { /* no-op */ }
  async newPage(): Promise<FakePage> {
    if (this.closed || !this.browser.connected) throw new Error('Browser context is closed')
    const page = new FakePage(this, this.hooks)
    this.pages.push(page)
    return page
  }
  async newCDPSession(): Promise<PlaywrightCdpSession> { return new FakeCdp() }
  async close(): Promise<void> {
    this.closed = true
    for (const p of this.pages) p.closed = true
  }
}

class FakeBrowser {
  connected = true
  closed = false
  readonly contexts: FakeContext[] = []
  private readonly disconnectListeners = new Set<() => void>()
  private readonly hooks: FakeBrowserHooks

  constructor(hooks: FakeBrowserHooks = {}) {
    this.hooks = hooks
  }

  /** Simulate a Chromium crash, optionally firing the Playwright `disconnected` event. */
  simulateCrash(emitEvent = true): void {
    this.connected = false
    for (const ctx of this.contexts) {
      ctx.closed = true
      for (const page of ctx.pages) page.closed = true
    }
    if (emitEvent) {
      for (const listener of [...this.disconnectListeners]) {
        listener()
      }
    }
  }

  asPlaywright(): PlaywrightBrowserLike {
    return {
      isConnected: () => this.connected,
      on: (_event: 'disconnected', listener: () => void) => {
        this.disconnectListeners.add(listener)
      },
      off: (_event: 'disconnected', listener: () => void) => {
        this.disconnectListeners.delete(listener)
      },
      newContext: async () => {
        if (!this.connected) throw new Error('Target page, context or browser has been closed')
        const ctx = new FakeContext(this, this.hooks)
        this.contexts.push(ctx)
        await this.hooks.onNewContext?.(ctx)
        return ctx as unknown as Awaited<ReturnType<PlaywrightBrowserLike['newContext']>>
      },
      close: async () => {
        this.closed = true
        this.connected = false
        for (const ctx of this.contexts) await ctx.close()
      },
    }
  }
}

// ---------------------------------------------------------------------------
// 1. OOB Relay `pruneCallbacks()` self-poisoning fix
// ---------------------------------------------------------------------------

describe('Q3-1: OobRelay pruneCallbacks() retention isolation & active pending_oob protection', () => {
  test('historical claimed callbacks at/above cap never evict newly accepted live unclaimed callbacks', (t: TestContext) => {
    let now = 1_000_000
    const relay = new OobRelay({
      now: () => now,
      allowlist: ['127.0.0.1'],
      maxClaimedCallbacks: 5,
      maxUnclaimedCallbacks: 5,
      claimedCallbackTtlMs: 0,
      unclaimedCallbackTtlMs: 0,
    })
    t.after(() => relay.close())

    // Accumulate 12 historical claimed callbacks (> maxClaimedCallbacks = 5).
    for (let i = 1; i <= 12; i += 1) {
      now += 100
      const token = makeCanaryToken(i)
      relay.subscribe({
        runId: 'run-hist',
        assignmentId: 'a-hist',
        canaryId: `c-hist-${i}`,
        token,
        artifact: '',
        allowlist: ['127.0.0.1'],
      })
      const rec = relay.recordCallback({
        token,
        sourceIp: '127.0.0.1',
        method: 'GET',
        path: `/hist/${i}`,
      })
      assert.equal(rec.accepted, true)
      const promoted = relay.promoteLate({ runId: 'run-hist', now })
      assert.equal(promoted.length, 1)
    }

    // Historical claimed rows must be bounded to maxClaimedCallbacks (5), oldest pruned first.
    const statusBeforeLive = relay.status()
    assert.equal(statusBeforeLive.delivered, 5, 'historical claimed rows must be pruned to maxClaimedCallbacks')

    // Now record a brand-new live unclaimed callback for an active subscription.
    now += 100
    const liveToken = makeCanaryToken(999)
    relay.subscribe({
      runId: 'run-live',
      assignmentId: 'a-live',
      canaryId: 'c-live-999',
      token: liveToken,
      artifact: '',
      allowlist: ['127.0.0.1'],
    })
    const liveRec = relay.recordCallback({
      token: liveToken,
      sourceIp: '127.0.0.1',
      method: 'GET',
      path: '/live',
    })
    assert.equal(liveRec.accepted, true)
    assert.ok(liveRec.callback, 'live callback must be returned')

    // Verify the live callback was NOT immediately self-poisoned/deleted!
    const persisted = relay.callback(liveRec.callback!.callbackId)
    assert.ok(persisted, 'live unclaimed callback MUST remain persisted after pruneCallbacks()')
    assert.equal(persisted!.claimedBy, null)

    const promoted = relay.promoteLate({ runId: 'run-live', now })
    assert.equal(promoted.length, 1, 'live callback must promote cleanly via promoteLate()')
    assert.equal(promoted[0]!.callback.callbackId, liveRec.callback!.callbackId)
  })

  test('never evicts unclaimed callbacks matching an active pending_oob subscription even above unclaimed cap or TTL', (t: TestContext) => {
    let now = 5_000_000
    const relay = new OobRelay({
      now: () => now,
      allowlist: ['127.0.0.1'],
      maxClaimedCallbacks: 10,
      maxUnclaimedCallbacks: 2,
      claimedCallbackTtlMs: 10_000,
      unclaimedCallbackTtlMs: 1_000,
    })
    t.after(() => relay.close())

    // Create 4 active pending_oob subscriptions (more than maxUnclaimedCallbacks = 2) and record callbacks for each.
    const activeIds: string[] = []
    for (let i = 1; i <= 4; i += 1) {
      now += 10
      const token = makeCanaryToken(100 + i)
      relay.subscribe({
        runId: 'run-active',
        assignmentId: 'a-active',
        canaryId: `c-active-${i}`,
        token,
        artifact: '',
        windowMs: 600_000,
        allowlist: ['127.0.0.1'],
      })
      const rec = relay.recordCallback({ token, sourceIp: '127.0.0.1', method: 'GET', path: `/active/${i}` })
      assert.equal(rec.accepted, true)
      activeIds.push(rec.callback!.callbackId)
    }

    // Create 3 orphaned unclaimed callbacks (bound via registerCanary, NO active pending_oob subscription).
    const orphanIds: string[] = []
    for (let i = 1; i <= 3; i += 1) {
      now += 10
      const token = makeCanaryToken(200 + i)
      relay.registerCanary({ runId: 'run-orphan', canaryId: `c-orphan-${i}`, token })
      const rec = relay.recordCallback({ token, sourceIp: '127.0.0.1', method: 'GET', path: `/orphan/${i}` })
      assert.equal(rec.accepted, true)
      orphanIds.push(rec.callback!.callbackId)
    }

    // Advance past unclaimedCallbackTtlMs (1_000 ms) and trigger another callback to run pruneCallbacks().
    now += 5_000
    const triggerToken = makeCanaryToken(299)
    relay.registerCanary({ runId: 'run-orphan', canaryId: 'c-orphan-trigger', token: triggerToken })
    const triggerRec = relay.recordCallback({ token: triggerToken, sourceIp: '127.0.0.1', method: 'GET', path: '/trigger' })
    assert.equal(triggerRec.accepted, true)

    // Every single active pending_oob callback MUST still exist!
    for (const id of activeIds) {
      assert.ok(relay.callback(id), `active pending_oob callback ${id} must NEVER be evicted`)
    }
    // Just-accepted callback must also remain persisted.
    assert.ok(relay.callback(triggerRec.callback!.callbackId), 'just-accepted callback must never be self-deleted')
    // Stale orphaned unclaimed callbacks without pending_oob subscriptions MUST be pruned.
    for (const id of orphanIds) {
      assert.equal(relay.callback(id), null, `stale orphaned unclaimed callback ${id} should be evicted`)
    }

    // All 4 active callbacks still promote cleanly!
    const promotions = relay.promoteLate({ runId: 'run-active', now })
    assert.equal(promotions.length, 4)
  })

  test('claimedCallbackTtlMs prunes expired historical claimed rows without affecting recent claimed rows', (t: TestContext) => {
    let now = 10_000_000
    const relay = new OobRelay({
      now: () => now,
      allowlist: ['127.0.0.1'],
      maxClaimedCallbacks: 100,
      maxUnclaimedCallbacks: 100,
      claimedCallbackTtlMs: 5_000,
      unclaimedCallbackTtlMs: 0,
    })
    t.after(() => relay.close())

    const oldToken = makeCanaryToken(301)
    relay.subscribe({ runId: 'run-ttl', assignmentId: 'a1', canaryId: 'c-old', token: oldToken, artifact: '', allowlist: ['127.0.0.1'] })
    const oldRec = relay.recordCallback({ token: oldToken, sourceIp: '127.0.0.1', method: 'GET', path: '/old' })
    assert.equal(oldRec.accepted, true)
    assert.equal(relay.promoteLate({ runId: 'run-ttl', now }).length, 1)

    // Advance past claimedCallbackTtlMs (5_000 ms) and claim a new callback.
    now += 10_000
    const freshToken = makeCanaryToken(302)
    relay.subscribe({ runId: 'run-ttl', assignmentId: 'a1', canaryId: 'c-fresh', token: freshToken, artifact: '', allowlist: ['127.0.0.1'] })
    const freshRec = relay.recordCallback({ token: freshToken, sourceIp: '127.0.0.1', method: 'GET', path: '/fresh' })
    assert.equal(freshRec.accepted, true)
    assert.equal(relay.promoteLate({ runId: 'run-ttl', now }).length, 1)

    assert.equal(relay.callback(oldRec.callback!.callbackId), null, 'expired claimed row must be pruned by TTL')
    assert.ok(relay.callback(freshRec.callback!.callbackId), 'fresh claimed row must be retained')
  })
})

// ---------------------------------------------------------------------------
// 2. `oob-drain.ts` structured error diagnostics & explicit coverage gaps
// ---------------------------------------------------------------------------

describe('Q3-2: oob-drain.ts surfaces relay/SQLite errors as explicit coverage gaps', () => {
  test('drainPendingOob surfaces promoteLate() and pending() SQLite errors instead of silently returning 0', async () => {
    const dbErr = Object.assign(new Error('SQLITE_CORRUPT: database disk image is malformed'), { code: 'SQLITE_CORRUPT' })
    const observed: unknown[] = []
    const brokenRelay: OobDrainRelay = {
      promoteLate: () => { throw dbErr },
      pending: () => { throw dbErr },
    }

    const result = await drainPendingOob(brokenRelay, 'run-broken-drain', {
      graceMs: 2_000,
      pollMs: 50,
      onError: err => observed.push(err),
    })

    assert.equal(result.degraded, true, 'drain result must be flagged degraded on relay/SQLite failure')
    assert.ok(Array.isArray(result.errors) && result.errors.length >= 2, 'both promote_late and pending_check errors must be captured')
    assert.equal(result.errors![0]!.phase, 'promote_late')
    assert.equal(result.errors![0]!.code, 'SQLITE_CORRUPT')
    assert.equal(result.errors![1]!.phase, 'pending_check')
    assert.ok(result.coverageGap && /OOB callback drain degraded/i.test(result.coverageGap))
    assert.equal(observed.length, 2, 'onError observer must be called for relay/SQLite errors')
  })

  test('scheduleFinalReport records explicit coverage gap and partial report when preflight pending() throws', async (t: TestContext) => {
    const store = makeTempStore(t, 'kovo-q3-drain-preflight-')
    const run = await createVerificationRun(store, 'https://q3-preflight.fixture.test')
    const relayErr = Object.assign(new Error('SQLITE_IOERR: disk I/O error'), { code: 'SQLITE_IOERR' })
    const observed: unknown[] = []
    let finalizedId = ''

    const host: FinalizeHost = {
      storage: store,
      relay: {
        pending: () => { throw relayErr },
        promoteLate: () => [],
      },
      draining: new Set(),
      lastDrain: new Map(),
      onError: err => observed.push(err),
      onFinalized: id => { finalizedId = id },
    }

    scheduleFinalReport(host, run)

    assert.equal(finalizedId, run.id)
    assert.equal(observed.length, 1, 'preflight pending() error must be reported to onError')
    const drainMeta = host.lastDrain.get(run.id)
    assert.ok(drainMeta?.degraded, 'lastDrain must record degraded state on preflight relay error')
    assert.equal(drainMeta?.errors?.[0]?.phase, 'preflight_pending')
    assert.ok(drainMeta?.coverageGap)

    const reportRows = store.db.select().from(reports).where(eq(reports.runId, run.id)).all()
    assert.equal(reportRows.length, 1)
    assert.equal(reportRows[0]!.partial, true, 'report must be marked partial when OOB preflight fails')
    const gaps = Array.isArray(reportRows[0]!.body?.gaps) ? reportRows[0]!.body.gaps : []
    assert.ok(
      gaps.some((g: string) => /OOB callback drain degraded/i.test(g) && /SQLITE_IOERR/.test(g)),
      `expected explicit OOB drain coverage gap in report.body.gaps, got: ${JSON.stringify(gaps)}`,
    )
  })

  test('scheduleFinalReport records explicit coverage gap when async drain rejects with relay error', async (t: TestContext) => {
    const store = makeTempStore(t, 'kovo-q3-drain-async-')
    const run = await createVerificationRun(store, 'https://q3-async.fixture.test')
    const relayErr = Object.assign(new Error('SQLITE_BUSY: database is locked'), { code: 'SQLITE_BUSY' })
    const observed: unknown[] = []
    let resolveFinalized!: () => void
    const finalizedPromise = new Promise<void>(r => { resolveFinalized = r })

    const host: FinalizeHost = {
      storage: store,
      relay: {
        pending: () => [{ id: 'sub-pending' }],
        promoteLate: () => { throw relayErr },
      },
      draining: new Set(),
      lastDrain: new Map(),
      drain: async () => { throw relayErr },
      onError: err => observed.push(err),
      onFinalized: () => resolveFinalized(),
    }

    scheduleFinalReport(host, run)
    await finalizedPromise

    assert.equal(observed.length, 1)
    const drainMeta = host.lastDrain.get(run.id)
    assert.equal(drainMeta?.degraded, true)
    assert.equal(drainMeta?.errors?.[0]?.phase, 'drain')
    assert.equal(drainMeta?.remaining, 1)

    const reportRows = store.db.select().from(reports).where(eq(reports.runId, run.id)).all()
    assert.equal(reportRows.length, 1)
    assert.equal(reportRows[0]!.partial, true)
    const gaps = Array.isArray(reportRows[0]!.body?.gaps) ? reportRows[0]!.body.gaps : []
    assert.ok(
      gaps.some((g: string) => /OOB callback drain degraded/i.test(g) && /SQLITE_BUSY/.test(g)),
      `expected explicit async drain coverage gap, got: ${JSON.stringify(gaps)}`,
    )
    assert.ok(buildOobDrainCoverageGap(drainMeta!.errors!).includes('SQLITE_BUSY'))
  })
})

// ---------------------------------------------------------------------------
// 3. Headless Browser Pool crash recovery, cross-origin SPA auth, backpressure
// ---------------------------------------------------------------------------

describe('Q3-3A: ScopedBrowser pool Chromium crash recovery', () => {
  test('restarts pool atomically when Chromium emits disconnected event', async (t: TestContext) => {
    const launched: FakeBrowser[] = []
    const browser = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => {
        const fb = new FakeBrowser()
        launched.push(fb)
        return fb.asPlaywright()
      },
    })
    t.after(() => browser.close())

    const origin = 'https://crash-event.fixture.test'
    const grant = makeLabGrant(origin, { tier: 2, allowLocalLab: false })

    const [r1] = await browser.visitPages(
      [{ origin, pathAndQuery: '/page-1', runId: 'run-crash-1', persona: 'admin' }],
      grant,
      AbortSignal.timeout(10_000),
    )
    assert.equal(r1?.status, 200)
    assert.equal(launched.length, 1)
    assert.equal(browser.getPoolStats().launches, 1)
    assert.equal(browser.getPoolStats().activeContexts, 1)

    // Simulate Chromium OOM/crash firing the Playwright disconnected event.
    launched[0]!.simulateCrash(true)
    assert.equal(browser.getPoolStats().activeContexts, 0, 'disconnect handler must reset pooled contexts atomically')
    assert.equal(browser.getRunActiveLeases('run-crash-1'), 0)

    // Next visit MUST cleanly relaunch Chromium and succeed without crash lockout.
    const [r2] = await browser.visitPages(
      [{ origin, pathAndQuery: '/page-2', runId: 'run-crash-1', persona: 'admin' }],
      grant,
      AbortSignal.timeout(10_000),
    )
    assert.equal(r2?.status, 200)
    assert.equal(launched.length, 2, 'crashed Chromium must trigger atomic relaunch')
    assert.equal(browser.getPoolStats().launches, 2)
    assert.equal(browser.getPoolStats().activeContexts, 1)
  })

  test('detects dead browser via isConnected() === false even without disconnected event', async (t: TestContext) => {
    const launched: FakeBrowser[] = []
    const browser = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => {
        const fb = new FakeBrowser()
        launched.push(fb)
        return fb.asPlaywright()
      },
    })
    t.after(() => browser.close())

    const origin = 'https://crash-silent.fixture.test'
    const grant = makeLabGrant(origin, { tier: 2, allowLocalLab: false })

    await browser.visitPages([{ origin, pathAndQuery: '/a', runId: 'run-silent' }], grant, AbortSignal.timeout(10_000))
    assert.equal(launched.length, 1)

    // Crash silently without emitting 'disconnected'.
    launched[0]!.simulateCrash(false)

    const [res] = await browser.visitPages(
      [{ origin, pathAndQuery: '/b', runId: 'run-silent' }],
      grant,
      AbortSignal.timeout(10_000),
    )
    assert.equal(res?.status, 200)
    assert.equal(launched.length, 2, 'isConnected() check must detect silent crash and relaunch')
    assert.equal(browser.getPoolStats().launches, 2)
  })
})

describe('Q3-3B: Cross-origin SPA persona credential attachment with zero leakage', () => {
  test('resolvePersonaForBrowserRequest attaches persona for allowlisted sibling API and refuses unauthorized origins', () => {
    const appOrigin = 'https://app.acme.fixture.test'
    const apiOrigin = 'https://api.acme.fixture.test'
    const otherInScope = 'https://billing.acme.fixture.test'
    const thirdParty = 'https://evil.other.fixture.test'

    const adminPersona: ResolvedPersona = {
      id: 'p-admin',
      handle: 'admin',
      roleLabel: 'Admin',
      originAllowlist: [appOrigin, apiOrigin],
      authKind: 'bearer',
      headerName: 'Authorization',
      secret: 'secret-token-value',
      canaryMarkers: [],
    }
    const grant: Pick<Grant, 'canRead' | 'personas'> = {
      canRead: o => o === appOrigin || o === apiOrigin || o === otherInScope,
      personas: new Map([['admin', adminPersona]]),
    }

    // 1. Same-origin request -> attached
    assert.equal(
      resolvePersonaForBrowserRequest({
        persona: 'admin',
        pageOrigin: appOrigin,
        targetOrigin: appOrigin,
        grant,
        assetHydration: false,
        resourceType: 'fetch',
        requestHeaders: {},
      }),
      'admin',
    )

    // 2. Cross-origin SPA XHR/fetch to allowlisted sibling API origin -> attached!
    assert.equal(
      resolvePersonaForBrowserRequest({
        persona: 'admin',
        pageOrigin: appOrigin,
        targetOrigin: apiOrigin,
        grant,
        assetHydration: false,
        resourceType: 'fetch',
        requestHeaders: { 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site' },
      }),
      'admin',
    )

    // 3. Cross-origin request to in-scope origin NOT in persona.originAllowlist -> REFUSED!
    assert.equal(
      resolvePersonaForBrowserRequest({
        persona: 'admin',
        pageOrigin: appOrigin,
        targetOrigin: otherInScope,
        grant,
        assetHydration: false,
        resourceType: 'fetch',
        requestHeaders: { cookie: 'sid=1', 'sec-fetch-site': 'same-site' },
      }),
      undefined,
    )

    // 4. Cross-origin request to out-of-scope third-party origin -> REFUSED!
    assert.equal(
      resolvePersonaForBrowserRequest({
        persona: 'admin',
        pageOrigin: appOrigin,
        targetOrigin: thirdParty,
        grant,
        assetHydration: false,
        resourceType: 'fetch',
        requestHeaders: { cookie: 'sid=1' },
      }),
      undefined,
    )

    // 5. Passive asset hydration -> REFUSED even if origin is allowlisted!
    assert.equal(
      resolvePersonaForBrowserRequest({
        persona: 'admin',
        pageOrigin: appOrigin,
        targetOrigin: apiOrigin,
        grant,
        assetHydration: true,
        resourceType: 'script',
        requestHeaders: {},
      }),
      undefined,
    )

    // 6. Explicit validatedFetch with credentials: 'omit' -> REFUSED!
    assert.equal(
      resolvePersonaForBrowserRequest({
        persona: 'admin',
        pageOrigin: appOrigin,
        targetOrigin: apiOrigin,
        grant,
        assetHydration: false,
        resourceType: 'fetch',
        requestHeaders: {},
        validatedFetch: { origin: apiOrigin, credentials: 'omit' },
      }),
      undefined,
    )
  })

  test('pooled visitPages attaches persona to allowlisted sibling API subrequests and never leaks to non-allowlisted or third-party origins', async (t: TestContext) => {
    const appOrigin = 'https://app.spa.fixture.test'
    const apiOrigin = 'https://api.spa.fixture.test'
    const otherInScope = 'https://unauthed.spa.fixture.test'
    const evilOrigin = 'https://evil.outside.fixture.test'

    const seenBrokerCalls: Array<{ origin: string; path: string; persona: string | undefined }> = []
    const broker = makeFakeBroker(req => {
      seenBrokerCalls.push({ origin: req.origin, path: req.pathAndQuery, persona: req.persona })
      return fakeExchange(req)
    })

    const fake = new FakeBrowser({
      onGoto: async (page) => {
        // SPA calls its allowlisted sibling API origin
        await page.triggerSubrequest({
          url: `${apiOrigin}/v1/me`,
          method: 'GET',
          resourceType: 'fetch',
          headers: { 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site' },
        })
        // SPA calls an in-scope origin NOT in persona.originAllowlist
        await page.triggerSubrequest({
          url: `${otherInScope}/v1/public`,
          method: 'GET',
          resourceType: 'fetch',
          headers: { 'sec-fetch-mode': 'cors' },
        })
        // SPA attempts a third-party out-of-scope request (must be aborted before broker)
        await page.triggerSubrequest({
          url: `${evilOrigin}/exfil`,
          method: 'GET',
          resourceType: 'fetch',
          headers: { 'sec-fetch-mode': 'cors' },
        })
      },
    })

    const browser = new ScopedBrowser(broker, { launchBrowser: async () => fake.asPlaywright() })
    t.after(() => browser.close())

    const adminPersona: ResolvedPersona = {
      id: 'p-spa-admin',
      handle: 'admin',
      roleLabel: 'Admin',
      originAllowlist: [appOrigin, apiOrigin],
      authKind: 'bearer',
      headerName: 'Authorization',
      secret: 'spa-admin-bearer-secret-99',
      canaryMarkers: [],
    }
    const grant: Grant = {
      canRead: o => o === appOrigin || o === apiOrigin || o === otherInScope,
      audit: () => undefined,
      allowLocalLab: false,
      tier: 2,
      personas: new Map([['admin', adminPersona]]),
    }

    const [res] = await browser.visitPages(
      [{ origin: appOrigin, pathAndQuery: '/', runId: 'run-spa', persona: 'admin' }],
      grant,
      AbortSignal.timeout(10_000),
    )

    assert.equal(res?.status, 200)
    const docCall = seenBrokerCalls.find(c => c.origin === appOrigin)
    const apiCall = seenBrokerCalls.find(c => c.origin === apiOrigin)
    const otherCall = seenBrokerCalls.find(c => c.origin === otherInScope)
    const evilCall = seenBrokerCalls.find(c => c.origin === evilOrigin)

    assert.equal(docCall?.persona, 'admin', 'same-origin document must carry persona')
    assert.equal(apiCall?.persona, 'admin', 'allowlisted sibling API origin must carry persona (no credential stripping)')
    assert.equal(otherCall?.persona, undefined, 'in-scope origin outside persona.originAllowlist must NOT receive persona')
    assert.equal(evilCall, undefined, 'third-party out-of-scope origin must be aborted before broker')
    assert.ok(res!.blockedOrigins.includes(evilOrigin), 'third-party origin must be recorded in blockedOrigins')
  })
})

describe('Q3-3C: ScopedBrowser pool bounded semaphore backpressure', () => {
  test('waits for an active slot to release instead of leaking unbounded contexts, and times out cleanly when saturated', async (t: TestContext) => {
    const origins = [
      'https://cap-1.fixture.test',
      'https://cap-2.fixture.test',
      'https://cap-3.fixture.test',
      'https://cap-4.fixture.test',
    ]

    let ready1!: () => void
    const pReady1 = new Promise<void>(r => { ready1 = r })
    let release1!: () => void
    const pGate1 = new Promise<void>(r => { release1 = r })

    let ready2!: () => void
    const pReady2 = new Promise<void>(r => { ready2 = r })
    let release2!: () => void
    const pGate2 = new Promise<void>(r => { release2 = r })

    let maxSimultaneousOpen = 0
    const fake = new FakeBrowser({
      onNewContext: () => {
        const openNow = fake.contexts.filter(c => !c.closed).length
        maxSimultaneousOpen = Math.max(maxSimultaneousOpen, openNow)
      },
      onGoto: async (_page, url) => {
        if (url.includes('cap-1.fixture.test')) { ready1(); await pGate1 }
        if (url.includes('cap-2.fixture.test')) { ready2(); await pGate2 }
      },
    })

    const browser = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => fake.asPlaywright(),
      maxPooledContexts: 2,
      maxActiveContexts: 2,
      poolAcquireTimeoutMs: 250,
    })
    t.after(() => browser.close())

    // Fill both active slots (2/2).
    const v1 = browser.visitPages(
      [{ origin: origins[0]!, pathAndQuery: '/', runId: 'run-cap-1' }],
      makeLabGrant(origins[0]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    const v2 = browser.visitPages(
      [{ origin: origins[1]!, pathAndQuery: '/', runId: 'run-cap-2' }],
      makeLabGrant(origins[1]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    await Promise.all([pReady1, pReady2])
    assert.equal(maxSimultaneousOpen, 2)

    // 1. While both slots remain held past poolAcquireTimeoutMs (250 ms), visit #3 times out cleanly
    //    WITHOUT evicting active contexts 0/1 and WITHOUT creating a 3rd simultaneous context!
    await assert.rejects(
      () => browser.visitPages(
        [{ origin: origins[2]!, pathAndQuery: '/', runId: 'run-cap-3' }],
        makeLabGrant(origins[2]!, { tier: 2, allowLocalLab: false }),
        AbortSignal.timeout(10_000),
      ),
      /pool capacity exhausted/i,
    )
    assert.equal(fake.contexts[0]!.closed, false, 'active context 1 must never be evicted under backpressure')
    assert.equal(fake.contexts[1]!.closed, false, 'active context 2 must never be evicted under backpressure')
    assert.equal(maxSimultaneousOpen, 2, 'simultaneous open contexts must never exceed maxActiveContexts')

    // 2. Start visit #4 while saturated, then release slot 1 before timeout -> visit #4 wakes,
    //    evicts now-idle slot 1, and completes cleanly!
    const v4 = browser.visitPages(
      [{ origin: origins[3]!, pathAndQuery: '/', runId: 'run-cap-4' }],
      makeLabGrant(origins[3]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    setTimeout(() => { release1() }, 40)

    const [res1, res4] = await Promise.all([v1, v4])
    assert.equal(res1[0]?.status, 200)
    assert.equal(res4[0]?.status, 200)
    assert.equal(fake.contexts[0]!.closed, true, 'released idle context 1 must be evicted to admit waiting visit #4')
    assert.equal(fake.contexts[1]!.closed, false, 'still-active context 2 must remain untouched')
    assert.equal(maxSimultaneousOpen, 2, 'simultaneous open contexts must stay bounded at 2 throughout')

    release2()
    const [res2] = await v2
    assert.equal(res2?.status, 200)
  })

  test('thundering herd of concurrent distinct origins never exceeds hard active context cap', async (t: TestContext) => {
    let maxSimultaneousOpen = 0
    const fake = new FakeBrowser({
      onNewContext: async () => {
        await new Promise(r => setTimeout(r, 15))
        const openNow = fake.contexts.filter(c => !c.closed).length
        maxSimultaneousOpen = Math.max(maxSimultaneousOpen, openNow)
      },
      onGoto: async () => {
        await new Promise(r => setTimeout(r, 25))
      },
    })

    const browser = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => fake.asPlaywright(),
      maxPooledContexts: 2,
      maxActiveContexts: 2,
      poolAcquireTimeoutMs: 5_000,
    })
    t.after(() => browser.close())

    const visits = Array.from({ length: 6 }, (_, i) => {
      const origin = `https://herd-${i}.fixture.test`
      return browser.visitPages(
        [{ origin, pathAndQuery: '/', runId: `run-herd-${i}`, persona: `p${i}` }],
        makeLabGrant(origin, { tier: 2, allowLocalLab: false }),
        AbortSignal.timeout(10_000),
      )
    })

    const results = await Promise.all(visits)
    assert.equal(results.length, 6)
    for (const [res] of results) assert.equal(res?.status, 200)
    assert.ok(maxSimultaneousOpen <= 2, `expected <= 2 simultaneous open contexts, observed ${maxSimultaneousOpen}`)
  })
})
