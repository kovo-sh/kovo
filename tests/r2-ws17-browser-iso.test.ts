/**
 * WS-17 regression suite for R2-H-20 / H-24, C-8, and H-8 in `src/server/scoped-browser.ts`:
 *   - R2-H-20 / H-24: Per-run leased browser pool (concurrent runs never close each other's active
 *     contexts, `releaseRun(runId)` closes only that run's contexts, LRU skips active entries,
 *     concurrent first use dedupes context creation + serializes via per-runtime lease, and crawl
 *     failures propagate cleanly instead of being swallowed).
 *   - C-8: Host-minted isolated-world callback attestation via `page.exposeBinding` (accepts valid
 *     host-minted nonces, rejects unattested title/console/global/DOM sentinels and cross-origin
 *     frames, and never maps unverified `executedSentinels` into `trace.sinks`).
 *   - H-8: SPA-compatible HttpOnly cookie & `Authorization` wire placeholder substitution inside
 *     the loopback proxy strictly for allowlisted origins, zero off-origin leaks, while preserving
 *     client-readable SPA JS tokens (`localStorage` and non-HttpOnly SDK cookies).
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer as createHttpServer, request as nodeHttpRequest } from 'node:http'
import type { IncomingHttpHeaders, RequestListener } from 'node:http'
import type { AddressInfo } from 'node:net'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import { BrokerDenied } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'
import {
  BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX,
  BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX,
  BrowserWirePlaceholderVault,
  KOVO_EXECUTION_ATTESTATION_BINDING,
  ScopedBrowser,
  buildVerifiedTraceSinks,
  createHostExecutionAttestor,
  mintExecutionAttestationNonce,
} from '../src/server/scoped-browser.ts'
import type {
  BrowserSessionBundle,
  PlaywrightBindingSource,
  PlaywrightBrowserLike,
  PlaywrightCdpSession,
} from '../src/server/scoped-browser.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

// ---------------------------------------------------------------------------
// Helpers & Fakes
// ---------------------------------------------------------------------------

type BindingFn = (source: PlaywrightBindingSource, ...args: unknown[]) => unknown

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

class FakePage {
  urlValue = 'about:blank'
  titleValue = 'ws17-fixture'
  closed = false
  readonly bindings = new Map<string, BindingFn>()
  readonly ctx: FakeContext
  private readonly hooks: FakeBrowserHooks

  constructor(ctx: FakeContext, hooks: FakeBrowserHooks) {
    this.ctx = ctx
    this.hooks = hooks
  }

  on(): void { /* no-op */ }

  async exposeBinding(name: string, callback: BindingFn): Promise<void> {
    if (this.bindings.has(name)) {
      throw new Error(`Function "${name}" has been already registered`)
    }
    this.bindings.set(name, callback)
  }

  invokeBinding(name: string, source: PlaywrightBindingSource, ...args: unknown[]): unknown {
    const fn = this.bindings.get(name)
    if (!fn) throw new Error(`Binding "${name}" not registered`)
    return fn(source, ...args)
  }

  async goto(url: string): Promise<{ status(): number }> {
    if (this.closed || this.ctx.closed) {
      throw new Error('Target page, context or browser has been closed')
    }
    this.urlValue = url
    if (this.ctx.routeHandler) {
      await this.ctx.routeHandler(new FakeRoute(this.ctx, { url, method: 'GET', resourceType: 'document' }))
    }
    if (this.hooks.onGoto) {
      await this.hooks.onGoto(this, url)
    }
    if (this.closed || this.ctx.closed) {
      throw new Error('Target page, context or browser has been closed mid-navigation')
    }
    const lastFulfilled = this.ctx.fulfilled.at(-1)
    const status = lastFulfilled && lastFulfilled.url === url ? (lastFulfilled.status ?? 200) : 0
    return { status: () => status }
  }

  async waitForTimeout(): Promise<void> { /* no-op */ }
  async waitForLoadState(): Promise<void> { /* no-op */ }
  url(): string { return this.urlValue }
  async title(): Promise<string> { return this.titleValue }

  async evaluate<T>(fn: (...args: unknown[]) => T): Promise<T> {
    if (this.closed || this.ctx.closed) {
      throw new Error('Target page, context or browser has been closed')
    }
    const src = fn.toString()
    if (src.includes('MutationObserver')) return undefined as T
    const override = this.hooks.snapshotOverride?.(this)
    return {
      domHtml: override?.domHtml ?? '<html><body>ok</body></html>',
      links: [],
      forms: [],
      cookieNames: [],
      localStorageKeys: override?.localStorageKeys ?? [],
      sessionStorageKeys: [],
      postMessageListeners: {
        count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false,
      },
      canaryTriggered: false,
      canaryDetail: null,
      sinkTraces: override?.sinkTraces ?? [],
      selectorResult: null,
      fetchResult: null,
    } as T
  }

  async close(): Promise<void> {
    this.closed = true
  }
}

class FakeContext {
  readonly id: number
  readonly options: Record<string, unknown>
  readonly initScripts: string[] = []
  readonly cookies: Array<Record<string, unknown>> = []
  readonly extraHeaders: Record<string, string> = {}
  readonly fulfilled: Array<{ url: string; status?: number }> = []
  readonly aborted: Array<{ url: string; errorCode: string | null }> = []
  readonly pages: FakePage[] = []
  closed = false
  routeHandler: ((route: FakeRoute) => Promise<void> | void) | null = null
  private readonly hooks: FakeBrowserHooks

  constructor(id: number, options: Record<string, unknown>, hooks: FakeBrowserHooks) {
    this.id = id
    this.options = options
    this.hooks = hooks
  }

  async addInitScript(script: string | (() => void)): Promise<void> {
    this.initScripts.push(typeof script === 'string' ? script : script.toString())
  }
  async addCookies(cookies: Array<Record<string, unknown>>): Promise<void> {
    for (const c of cookies) this.cookies.push({ ...c })
  }
  async setExtraHTTPHeaders(headers: Record<string, string>): Promise<void> {
    Object.assign(this.extraHeaders, headers)
  }
  async route(_pattern: string, handler: (route: FakeRoute) => Promise<void> | void): Promise<void> {
    this.routeHandler = handler
  }
  async routeWebSocket(): Promise<void> { /* no-op */ }
  async newPage(): Promise<FakePage> {
    const page = new FakePage(this, this.hooks)
    this.pages.push(page)
    return page
  }
  async newCDPSession(): Promise<FakeCdp> { return new FakeCdp() }
  async close(): Promise<void> { this.closed = true }
}

interface FakeBrowserHooks {
  onGoto?: (page: FakePage, url: string) => Promise<void> | void
  onNewContext?: (ctx: FakeContext) => Promise<void> | void
  snapshotOverride?: (page: FakePage) => {
    domHtml?: string
    localStorageKeys?: string[]
    sinkTraces?: Array<{ sink: string; preview: string; containsCanary: boolean; timestamp: number }>
  }
}

class FakeBrowser {
  readonly contexts: FakeContext[] = []
  readonly hooks: FakeBrowserHooks
  closed = false
  constructor(hooks: FakeBrowserHooks = {}) {
    this.hooks = hooks
  }
  async newContext(options: Record<string, unknown> = {}): Promise<FakeContext> {
    const ctx = new FakeContext(this.contexts.length + 1, options, this.hooks)
    this.contexts.push(ctx)
    if (this.hooks.onNewContext) await this.hooks.onNewContext(ctx)
    return ctx
  }
  async close(): Promise<void> { this.closed = true }
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
    observation: { source: 'ws17-fixture' },
  } as unknown as BrokerExchangeResult
}

function makeFakeBroker(
  handler?: (req: BrokerHttpRequest, grant: Grant) => Promise<BrokerExchangeResult> | BrokerExchangeResult,
): RequestBroker {
  return {
    executeHttp: async (req: BrokerHttpRequest, grant: Grant) =>
      handler ? await handler(req, grant) : fakeExchange(req),
    sessionCookiesForBrowser: () => [],
    getRegisteredSecrets: () => [],
    getStorage: () => undefined,
  } as unknown as RequestBroker
}

async function startEchoServer(
  t: TestContext,
): Promise<{ port: number; received: Array<{ path: string; headers: IncomingHttpHeaders }> }> {
  const received: Array<{ path: string; headers: IncomingHttpHeaders }> = []
  const listener: RequestListener = (req, res) => {
    received.push({ path: req.url ?? '/', headers: { ...req.headers } })
    req.resume()
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, cookie: req.headers.cookie ?? null, authorization: req.headers.authorization ?? null }))
  }
  const server = createHttpServer(listener)
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(r => {
    server.closeAllConnections?.()
    server.close(() => r())
  }))
  return { port: (server.address() as AddressInfo).port, received }
}

function sendProxyHttpRequest(
  proxyPort: number,
  targetUrl: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  return new Promise((resolvePromise, reject) => {
    const req = nodeHttpRequest({
      host: '127.0.0.1',
      port: proxyPort,
      path: targetUrl,
      method: 'GET',
      headers,
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', chunk => chunks.push(Buffer.from(chunk)))
      res.on('end', () => resolvePromise({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.once('error', reject)
    req.end()
  })
}

function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`
}

// ---------------------------------------------------------------------------
// 1. R2-H-20 / H-24: Per-run leased browser pool
// ---------------------------------------------------------------------------

describe('WS-17 R2-H-20 / H-24: per-run leased browser pool', () => {
  test('concurrent Run A and Run B visits never close each other, and releaseRun(runA) closes only Run A contexts', async (t: TestContext) => {
    const originA = 'https://tenant-a.fixture.test'
    const originB = 'https://tenant-b.fixture.test'

    let runAActive!: () => void
    const runAReady = new Promise<void>(resolve => { runAActive = resolve })
    let releaseRunAVisit!: () => void
    const runAGate = new Promise<void>(resolve => { releaseRunAVisit = resolve })

    const fake = new FakeBrowser({
      onGoto: async (_page, url) => {
        if (url.includes('tenant-a.fixture.test/hold')) {
          runAActive()
          await runAGate
        }
      },
    })

    const browser = new ScopedBrowser(makeFakeBroker(), { launchBrowser: async () => fake.asPlaywright() })
    t.after(() => browser.close())

    const grantA = makeLabGrant(originA, { tier: 2, allowLocalLab: false })
    const grantB = makeLabGrant(originB, { tier: 2, allowLocalLab: false })

    // Start Run A and hold it active mid-visit.
    const visitAPromise = browser.visitPages(
      [{ origin: originA, pathAndQuery: '/hold', runId: 'run-a', persona: 'admin' }],
      grantA,
      AbortSignal.timeout(10_000),
    )
    await runAReady
    assert.equal(browser.getRunActiveLeases('run-a'), 1, 'Run A must hold an active lease while in flight')

    // While Run A is active, Run B runs and completes on its own context.
    const [resB] = await browser.visitPages(
      [{ origin: originB, pathAndQuery: '/dashboard', runId: 'run-b', persona: 'viewer' }],
      grantB,
      AbortSignal.timeout(10_000),
    )
    assert.equal(resB?.status, 200)
    assert.equal(fake.contexts.length, 2)
    const ctxA = fake.contexts[0]!
    const ctxB = fake.contexts[1]!
    assert.equal(ctxA.closed, false, 'Run B visit MUST NEVER close Run A active context')
    assert.equal(ctxA.pages[0]!.closed, false, 'Run B visit MUST NEVER close Run A active page')
    assert.equal(browser.getRunActiveLeases('run-a'), 1)
    assert.equal(browser.getRunActiveLeases('run-b'), 0)

    // Calling releaseRun('run-a') while Run A is still active must NOT kill it mid-visit;
    // it defers closure until Run A's active lease completes.
    const immediateClosed = await browser.releaseRun('run-a')
    assert.equal(immediateClosed, 0, 'releaseRun must not tear down an in-flight leased context mid-visit')
    assert.equal(ctxA.closed, false, 'in-flight Run A context must stay open until its visit finishes')
    assert.equal(ctxB.closed, false, 'Run B context must remain untouched')

    // Now finish Run A's visit -> Run A completes cleanly AND closes automatically on release.
    releaseRunAVisit()
    const [resA] = await visitAPromise
    assert.equal(resA?.status, 200, 'Run A visit must complete cleanly without being destroyed by Run B')
    assert.equal(browser.getRunActiveLeases('run-a'), 0)
    assert.equal(ctxA.closed, true, 'Run A context must close cleanly once its deferred release completes')
    assert.equal(ctxB.closed, false, 'Run B context must still be open after Run A disposal')
    assert.equal(browser.getPoolStats().activeContexts, 1)

    // Now start another Run A visit (idle after completion) and verify direct releaseRun('run-a') closes ONLY Run A.
    await browser.visitPages(
      [{ origin: originA, pathAndQuery: '/done', runId: 'run-a', persona: 'admin' }],
      grantA,
      AbortSignal.timeout(10_000),
    )
    assert.equal(browser.getPoolStats().activeContexts, 2)
    const ctxA2 = fake.contexts[2]!
    const closedA = await browser.releaseRun('run-a')
    assert.equal(closedA, 1)
    assert.equal(ctxA2.closed, true, 'releaseRun(run-a) must close idle Run A context')
    assert.equal(ctxB.closed, false, 'releaseRun(run-a) must NOT close Run B context')
    assert.equal(browser.getPoolStats().activeContexts, 1)
  })

  test('automatic LRU eviction strictly skips active entries (active > 0) and only evicts idle entries', async (t: TestContext) => {
    const origins = [
      'https://lru-1.fixture.test',
      'https://lru-2.fixture.test',
      'https://lru-3.fixture.test',
      'https://lru-4.fixture.test',
    ]
    let ready1!: () => void
    const pReady1 = new Promise<void>(r => { ready1 = r })
    let release1!: () => void
    const pGate1 = new Promise<void>(r => { release1 = r })

    let ready2!: () => void
    const pReady2 = new Promise<void>(r => { ready2 = r })
    let release2!: () => void
    const pGate2 = new Promise<void>(r => { release2 = r })

    const fake = new FakeBrowser({
      onGoto: async (_page, url) => {
        if (url.includes('lru-1.fixture.test')) { ready1(); await pGate1 }
        if (url.includes('lru-2.fixture.test')) { ready2(); await pGate2 }
      },
    })

    const browser = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => fake.asPlaywright(),
      maxPooledContexts: 2,
    })
    t.after(() => browser.close())

    const v1 = browser.visitPages(
      [{ origin: origins[0]!, pathAndQuery: '/', runId: 'run-1' }],
      makeLabGrant(origins[0]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    const v2 = browser.visitPages(
      [{ origin: origins[1]!, pathAndQuery: '/', runId: 'run-2' }],
      makeLabGrant(origins[1]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    await Promise.all([pReady1, pReady2])

    // Both pooled slots are active (size == maxPooledContexts == 2). Run 3 MUST NOT evict either active context.
    await browser.visitPages(
      [{ origin: origins[2]!, pathAndQuery: '/', runId: 'run-3' }],
      makeLabGrant(origins[2]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    assert.equal(fake.contexts[0]!.closed, false, 'active context 1 must NEVER be LRU-evicted')
    assert.equal(fake.contexts[1]!.closed, false, 'active context 2 must NEVER be LRU-evicted')

    // Release context 2 (now idle) while context 1 stays active; creating context 4 must evict idle entries only.
    release2()
    await v2
    await browser.visitPages(
      [{ origin: origins[3]!, pathAndQuery: '/', runId: 'run-4' }],
      makeLabGrant(origins[3]!, { tier: 2, allowLocalLab: false }),
      AbortSignal.timeout(10_000),
    )
    assert.equal(fake.contexts[0]!.closed, false, 'active context 1 must still be spared by LRU eviction')
    assert.ok(
      fake.contexts[1]!.closed || fake.contexts[2]!.closed,
      'idle contexts must be reclaimed by LRU eviction once active === 0',
    )

    release1()
    const [res1] = await v1
    assert.equal(res1?.status, 200)
  })

  test('concurrent same-key first use creates 1 context, serializes visits via lease, and propagates crawl failures', async (t: TestContext) => {
    const origin = 'https://serial.fixture.test'
    let inFlight = 0
    let maxConcurrent = 0
    const order: string[] = []
    const seenAssignments: Array<{ path: string; assignmentId?: string }> = []

    const broker = makeFakeBroker(async req => {
      seenAssignments.push({ path: req.pathAndQuery, assignmentId: req.assignmentId })
      if (req.pathAndQuery === '/denied') {
        throw new BrokerDenied('Explicit broker denial for /denied')
      }
      return fakeExchange(req)
    })

    const fake = new FakeBrowser({
      onNewContext: async () => {
        // Yield across microtasks/timers to expose any concurrent first-use race.
        await new Promise(resolve => setTimeout(resolve, 20))
      },
      onGoto: async (_page, url) => {
        inFlight += 1
        maxConcurrent = Math.max(maxConcurrent, inFlight)
        order.push(`start:${new URL(url).pathname}`)
        await new Promise(resolve => setTimeout(resolve, 25))
        order.push(`end:${new URL(url).pathname}`)
        inFlight -= 1
      },
    })

    const browser = new ScopedBrowser(broker, { launchBrowser: async () => fake.asPlaywright() })
    t.after(() => browser.close())

    const grant = makeLabGrant(origin, { tier: 2, allowLocalLab: false })
    const [res1, res2] = await Promise.all([
      browser.visitPages([{ origin, pathAndQuery: '/first', runId: 'run-serial', persona: 'admin', assignmentId: 'a-1' }], grant, AbortSignal.timeout(10_000)),
      browser.visitPages([{ origin, pathAndQuery: '/second', runId: 'run-serial', persona: 'admin', assignmentId: 'a-2' }], grant, AbortSignal.timeout(10_000)),
    ])

    assert.equal(browser.getPoolStats().contextsCreated, 1, 'concurrent first use must create exactly 1 BrowserContext')
    assert.equal(maxConcurrent, 1, 'per-runtime lease must serialize concurrent visits on the same context')
    assert.equal(res1[0]?.status, 200)
    assert.equal(res2[0]?.status, 200)
    assert.deepEqual(
      seenAssignments.sort((a, b) => a.path.localeCompare(b.path)),
      [
        { path: '/first', assignmentId: 'a-1' },
        { path: '/second', assignmentId: 'a-2' },
      ],
    )
    assert.equal(order[0]!.replace('start:', ''), order[1]!.replace('end:', ''), 'first leased visit must finish before second starts')
    assert.equal(browser.getRunActiveLeases('run-serial'), 0)

    // Crawl failure propagation: BrokerDenied on primary navigation must reject cleanly (never swallowed)
    // and release the lease so subsequent visits succeed.
    await assert.rejects(
      () => browser.visitPages(
        [{ origin, pathAndQuery: '/denied', runId: 'run-serial', persona: 'admin', assignmentId: 'a-fail' }],
        grant,
        AbortSignal.timeout(10_000),
      ),
      /Explicit broker denial for \/denied/,
    )
    assert.equal(browser.getRunActiveLeases('run-serial'), 0, 'failed visit must still release its runtime lease')

    const [recovered] = await browser.visitPages(
      [{ origin, pathAndQuery: '/after-error', runId: 'run-serial', persona: 'admin', assignmentId: 'a-ok' }],
      grant,
      AbortSignal.timeout(10_000),
    )
    assert.equal(recovered?.status, 200)
  })
})

// ---------------------------------------------------------------------------
// 2. C-8: Host-minted isolated-world callback attestation
// ---------------------------------------------------------------------------

describe('WS-17 C-8: host-minted isolated-world callback attestation', () => {
  test('accepts valid host-minted exposeBinding nonce and rejects unattested title/global/marker/cross-origin sentinels', async (t: TestContext) => {
    const origin = 'https://xss-target.fixture.test'
    const canaryToken = 'kovo-canary-sentinel-42'

    // 1) Unattested page: forges title, DOM marker, DOM sink trace, wrong binding nonce, AND cross-origin frame call.
    const forgedNonce = mintExecutionAttestationNonce()
    const validNonce = mintExecutionAttestationNonce()
    assert.notEqual(forgedNonce, validNonce, 'host nonces must be random per probe')

    const forgedFake = new FakeBrowser({
      onGoto: (page) => {
        page.titleValue = canaryToken
        // Wrong nonce attempt -> rejected
        const wrong = page.invokeBinding(
          KOVO_EXECUTION_ATTESTATION_BINDING,
          { frame: { url: () => `${origin}/page` } },
          'forged-wrong-nonce-0000',
          'dom_xss:innerHTML',
        ) as { attested: boolean }
        assert.equal(wrong.attested, false)

        // Right nonce from cross-origin frame -> rejected
        const crossOrigin = page.invokeBinding(
          KOVO_EXECUTION_ATTESTATION_BINDING,
          { frame: { url: () => 'https://evil-iframe.fixture.test/embed' } },
          forgedNonce,
          'dom_xss:eval',
        ) as { attested: boolean }
        assert.equal(crossOrigin.attested, false)
      },
      snapshotOverride: () => ({
        domHtml: `<html><head><title>${canaryToken}</title></head><body><div data-kovo-canary="${canaryToken}"></div></body></html>`,
        sinkTraces: [{ sink: 'innerHTML', preview: canaryToken, containsCanary: true, timestamp: Date.now() }],
      }),
    })

    const browser1 = new ScopedBrowser(makeFakeBroker(), { launchBrowser: async () => forgedFake.asPlaywright() })
    t.after(() => browser1.close())
    const grant = makeLabGrant(origin, { tier: 2, allowLocalLab: false })

    const forgedVisit = await browser1.visitPage({
      origin,
      pathAndQuery: '/search?q=test',
      canaryToken,
      attestationNonce: forgedNonce,
      checkKind: 'dom_xss',
      enableSinkHook: true,
    }, grant, AbortSignal.timeout(10_000))

    assert.equal(forgedVisit.attestation?.verified, false)
    assert.equal(forgedVisit.attestation?.rejectedAttempts, 2)
    assert.equal(forgedVisit.canaryCheck.triggered, false, 'unattested title/marker/sink/wrong-nonce must NOT trigger canaryCheck')
    assert.equal(forgedVisit.canaryCheck.attested, false)
    assert.deepEqual(forgedVisit.attestedSinks, [], 'unattested visit must produce zero attestedSinks')

    // 2) Valid host-minted binding callback from the target origin -> verified!
    const validFake = new FakeBrowser({
      onGoto: (page) => {
        const res = page.invokeBinding(
          KOVO_EXECUTION_ATTESTATION_BINDING,
          { frame: { url: () => `${origin}/search?q=probe` } },
          validNonce,
          'dom_xss:eval',
        ) as { attested: boolean }
        assert.equal(res.attested, true)
      },
    })

    const browser2 = new ScopedBrowser(makeFakeBroker(), { launchBrowser: async () => validFake.asPlaywright() })
    t.after(() => browser2.close())

    const validVisit = await browser2.visitPage({
      origin,
      pathAndQuery: '/search?q=probe',
      canaryToken,
      attestationNonce: validNonce,
      checkKind: 'dom_xss',
    }, grant, AbortSignal.timeout(10_000))

    assert.equal(validVisit.attestation?.verified, true)
    assert.equal(validVisit.attestation?.callbackCount, 1)
    assert.equal(validVisit.attestation?.frameOrigin, origin)
    assert.equal(validVisit.canaryCheck.triggered, true)
    assert.equal(validVisit.canaryCheck.attested, true)
    assert.deepEqual(validVisit.attestedSinks, ['dom_xss:eval'])
  })

  test('buildVerifiedTraceSinks never maps unverified executedSentinels into trace.sinks, and runBrowserSession rotates nonces per step', async (t: TestContext) => {
    const attestor = createHostExecutionAttestor({ expectedOrigin: 'https://app.fixture.test' })

    // Before host binding verification: arbitrary sentinels / title / sink traces produce ZERO sinks.
    const unverifiedSinks = buildVerifiedTraceSinks({
      attestation: attestor.snapshot(),
      executedSentinels: ['alert:1', 'title:canary', `exec:${attestor.nonce}`],
      title: 'canary',
      domSinkTraces: [{ sink: 'innerHTML', preview: 'canary', containsCanary: true, timestamp: 1 }],
    })
    assert.deepEqual(unverifiedSinks, [], 'unverified attestation must never map sentinels into trace.sinks')

    // After valid host binding verification: only binding-attested tags and nonce-matched sentinels enter sinks.
    const call = attestor.handleBindingCall(
      { frame: { url: () => 'https://app.fixture.test/view' } },
      attestor.nonce,
      'binding:dom_exec',
    )
    assert.equal(call.attested, true)
    const verifiedSinks = buildVerifiedTraceSinks({
      attestation: attestor.snapshot(),
      executedSentinels: ['alert:unverified', 'console:spoof', `exec:${attestor.nonce}`],
    })
    assert.deepEqual(verifiedSinks, ['binding:dom_exec', 'sentinel:exec'])
    assert.ok(!verifiedSinks.some(s => s.includes('alert') || s.includes('console')))

    // Multi-step runBrowserSession with reusePage=true mints distinct nonces per step.
    const origin = 'https://session-xss.fixture.test'
    const nonceStep1 = mintExecutionAttestationNonce()
    const nonceStep2 = mintExecutionAttestationNonce()
    let stepIndex = 0
    const fake = new FakeBrowser({
      onGoto: (page) => {
        stepIndex += 1
        if (stepIndex === 2) {
          // Attempting to replay Step 1's nonce during Step 2 MUST be rejected!
          const replay = page.invokeBinding(
            KOVO_EXECUTION_ATTESTATION_BINDING,
            { frame: { url: () => `${origin}/probe` } },
            nonceStep1,
            'dom_xss:replay',
          ) as { attested: boolean }
          assert.equal(replay.attested, false, 'previous step nonce must not satisfy a subsequent step')
        }
      },
    })
    const browser = new ScopedBrowser(makeFakeBroker(), { launchBrowser: async () => fake.asPlaywright() })
    t.after(() => browser.close())
    const grant = makeLabGrant(origin, { tier: 2, allowLocalLab: false })

    const results = await browser.runBrowserSession([
      { id: 'c1', role: 'control', origin, pathAndQuery: '/control', attestationNonce: nonceStep1 },
      { id: 'p1', role: 'probe', origin, pathAndQuery: '/probe', reusePage: true, attestationNonce: nonceStep2 },
    ], grant, AbortSignal.timeout(10_000))

    assert.equal(results.length, 2)
    assert.equal(results[0]!.attestation?.nonce, nonceStep1)
    assert.equal(results[1]!.attestation?.nonce, nonceStep2)
    assert.equal(results[1]!.attestation?.verified, false)
    assert.equal(results[1]!.attestation?.rejectedAttempts, 1)
    assert.equal(results[1]!.canaryCheck.triggered, false)
  })
})

// ---------------------------------------------------------------------------
// 3. H-8: SPA-compatible HttpOnly cookie & Authorization wire placeholder support
// ---------------------------------------------------------------------------

describe('WS-17 H-8: SPA-compatible HttpOnly cookie and Authorization wire placeholder substitution', () => {
  test('BrowserWirePlaceholderVault swaps HttpOnly cookies & Authorization strictly on allowlisted origins and preserves SPA JS tokens', () => {
    const allowedOrigin = 'https://spa.fixture.test'
    const offOrigin = 'https://offsite.fixture.test'
    const vault = new BrowserWirePlaceholderVault()

    const bundle: BrowserSessionBundle = {
      cookies: [
        {
          name: 'sid',
          value: 'real-httponly-session-secret-xyz',
          domain: 'spa.fixture.test',
          path: '/',
          secure: true,
          httpOnly: true,
        },
        {
          name: 'xsrf_sdk',
          value: 'client-readable-xsrf-token',
          domain: 'spa.fixture.test',
          path: '/',
          secure: true,
          httpOnly: false,
        },
      ],
      headers: {
        Authorization: 'Bearer real-wire-jwt-secret-abc',
      },
      localStorage: {
        spa_access_token: 'spa-rotatable-client-jwt',
      },
    }

    const prepared = vault.prepareSeedBundle(bundle, allowedOrigin, [allowedOrigin])
    const sidCookie = prepared.cookies.find(c => c.name === 'sid')!
    const xsrfCookie = prepared.cookies.find(c => c.name === 'xsrf_sdk')!

    assert.ok(sidCookie.value.startsWith(BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX), 'HttpOnly cookie must use opaque placeholder in browser')
    assert.notEqual(sidCookie.value, 'real-httponly-session-secret-xyz')
    assert.equal(xsrfCookie.value, 'client-readable-xsrf-token', 'non-HttpOnly SDK cookie must stay readable for SPA JS')

    const authPlaceholder = prepared.placeholderHeaders.authorization!
    assert.ok(authPlaceholder.startsWith(`Bearer ${BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX}`), 'Authorization header must use opaque placeholder preserving scheme')
    assert.ok(!authPlaceholder.includes('real-wire-jwt-secret-abc'))

    // Allowlisted origin -> real HttpOnly cookie and real Authorization header swapped on the wire!
    const onOriginHeaders = vault.substituteWireHeaders(new URL(`${allowedOrigin}/api/profile`), {
      cookie: `sid=${sidCookie.value}; xsrf_sdk=${xsrfCookie.value}`,
      authorization: authPlaceholder,
    })
    assert.equal(onOriginHeaders.cookie, 'sid=real-httponly-session-secret-xyz; xsrf_sdk=client-readable-xsrf-token')
    assert.equal(onOriginHeaders.authorization, 'Bearer real-wire-jwt-secret-abc')

    // Off-origin host -> real secrets NEVER swapped AND placeholders stripped fail-closed; non-HttpOnly preserved.
    const offOriginHeaders = vault.substituteWireHeaders(new URL(`${offOrigin}/collect`), {
      cookie: `sid=${sidCookie.value}; xsrf_sdk=${xsrfCookie.value}`,
      authorization: authPlaceholder,
      'x-exfil': `${sidCookie.value}|${authPlaceholder}`,
    })
    assert.equal(offOriginHeaders.cookie, 'xsrf_sdk=client-readable-xsrf-token')
    assert.equal(offOriginHeaders.authorization, undefined, 'off-origin placeholder Authorization must be stripped')
    assert.ok(!JSON.stringify(offOriginHeaders).includes('real-httponly-session-secret-xyz'))
    assert.ok(!JSON.stringify(offOriginHeaders).includes('real-wire-jwt-secret-abc'))
    assert.ok(!String(offOriginHeaders['x-exfil']).includes(sidCookie.value))

    // SPA-rotated client Authorization header (non-placeholder) passes through untouched!
    const rotatedHeaders = vault.substituteWireHeaders(new URL(`${allowedOrigin}/api/refresh`), {
      authorization: 'Bearer spa-rotated-fresh-jwt',
    })
    assert.equal(rotatedHeaders.authorization, 'Bearer spa-rotated-fresh-jwt')
  })

  test('loopback proxy swaps HttpOnly cookie & Authorization placeholders strictly for allowlisted origins end-to-end', async (t: TestContext) => {
    const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
    process.env.KOVO_ALLOW_LOCAL_LAB = '1'
    t.after(() => {
      if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
      else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
    })

    const allowedSrv = await startEchoServer(t)
    const offSrv = await startEchoServer(t)
    const allowedOrigin = `http://allowed.fixture.test:${allowedSrv.port}`
    const offOrigin = `http://off.fixture.test:${offSrv.port}`

    const captured: { proxyConfig: { server: string; username: string; password: string } | null } = {
      proxyConfig: null,
    }
    let hydratedCookies: Array<Record<string, unknown>> = []
    let hydratedExtraHeaders: Record<string, string> = {}
    let hydratedInitScripts: string[] = []
    let visitActive!: () => void
    const visitReady = new Promise<void>(r => { visitActive = r })
    let releaseVisit!: () => void
    const visitGate = new Promise<void>(r => { releaseVisit = r })

    const fake = new FakeBrowser({
      onNewContext: (ctx) => {
        captured.proxyConfig = ctx.options.proxy as { server: string; username: string; password: string }
      },
      onGoto: async (page) => {
        hydratedCookies = [...page.ctx.cookies]
        hydratedExtraHeaders = { ...page.ctx.extraHeaders }
        hydratedInitScripts = [...page.ctx.initScripts]
        visitActive()
        await visitGate
      },
    })

    const browser = new ScopedBrowser(makeFakeBroker(), {
      launchBrowser: async () => fake.asPlaywright(),
      proxyResolveHost: async () => ['127.0.0.1'],
    })
    t.after(() => browser.close())

    // Grant permits reading BOTH origins (simulating a multi-origin app scope), while the session
    // bundle is strictly scoped to `allowedOrigin` ONLY — so `offOrigin` must NEVER receive swapped secrets!
    const grant: Grant = {
      canRead: o => o === allowedOrigin || o === offOrigin,
      audit: () => undefined,
      allowLocalLab: true,
      tier: 2,
    }

    const bundle: BrowserSessionBundle = {
      cookies: [
        {
          name: 'session_id',
          value: 'wire-secret-httponly-token-777',
          domain: 'allowed.fixture.test',
          path: '/',
          secure: false,
          httpOnly: true,
        },
        {
          name: 'sdk_csrf',
          value: 'spa-readable-csrf-token-555',
          domain: 'allowed.fixture.test',
          path: '/',
          secure: false,
          httpOnly: false,
        },
      ],
      localStorage: {
        spa_token: 'spa-localstorage-token-333',
      },
      headers: {
        Authorization: 'Bearer wire-secret-bearer-token-999',
      },
    }

    const visitPromise = browser.visitPages(
      [{ origin: allowedOrigin, pathAndQuery: '/app', runId: 'run-h8', persona: 'admin', sessionBundle: bundle }],
      grant,
      AbortSignal.timeout(15_000),
    )
    await visitReady

    assert.ok(captured.proxyConfig, 'pooled context must receive per-context loopback proxy config')
    const proxyConfig = captured.proxyConfig!
    const sidInBrowser = hydratedCookies.find(c => c.name === 'session_id')
    const csrfInBrowser = hydratedCookies.find(c => c.name === 'sdk_csrf')
    assert.ok(sidInBrowser, 'HttpOnly cookie must be hydrated into context')
    assert.equal(sidInBrowser!.httpOnly, true)
    assert.ok(
      String(sidInBrowser!.value).startsWith(BROWSER_HTTPONLY_COOKIE_PLACEHOLDER_PREFIX),
      'browser context must hold opaque placeholder instead of raw HttpOnly cookie value',
    )
    assert.notEqual(sidInBrowser!.value, 'wire-secret-httponly-token-777')
    assert.equal(csrfInBrowser?.value, 'spa-readable-csrf-token-555', 'non-HttpOnly SDK cookie value must be preserved')
    assert.ok(
      hydratedInitScripts.join('\n').includes('spa-localstorage-token-333'),
      'localStorage SPA JS token must be preserved',
    )

    const authInBrowser = hydratedExtraHeaders.Authorization
    assert.ok(authInBrowser, 'Authorization placeholder must be attached to browser context')
    assert.ok(
      authInBrowser!.startsWith(`Bearer ${BROWSER_AUTH_HEADER_PLACEHOLDER_PREFIX}`),
      'browser context must hold opaque Authorization placeholder instead of raw Bearer secret',
    )
    assert.ok(!authInBrowser!.includes('wire-secret-bearer-token-999'))

    const proxyPort = Number(new URL(proxyConfig!.server).port)
    const proxyAuth = basicAuthHeader(proxyConfig!.username, proxyConfig!.password)

    // 1) Request through loopback proxy to allowlisted origin -> HttpOnly cookie & Authorization swapped on wire!
    const allowedRes = await sendProxyHttpRequest(proxyPort, `${allowedOrigin}/api/me`, {
      'proxy-authorization': proxyAuth,
      cookie: `session_id=${String(sidInBrowser!.value)}; sdk_csrf=spa-readable-csrf-token-555`,
      authorization: authInBrowser!,
    })
    assert.equal(allowedRes.status, 200)
    assert.equal(allowedSrv.received.length, 1)
    assert.equal(
      allowedSrv.received[0]!.headers.cookie,
      'session_id=wire-secret-httponly-token-777; sdk_csrf=spa-readable-csrf-token-555',
      'loopback proxy must substitute HttpOnly cookie placeholder with real value on allowlisted origin',
    )
    assert.equal(
      allowedSrv.received[0]!.headers.authorization,
      'Bearer wire-secret-bearer-token-999',
      'loopback proxy must substitute Authorization placeholder with real value on allowlisted origin',
    )

    // 2) Request through loopback proxy to off-origin host -> real secrets NEVER swapped and placeholders stripped!
    const offRes = await sendProxyHttpRequest(proxyPort, `${offOrigin}/api/leak`, {
      'proxy-authorization': proxyAuth,
      cookie: `session_id=${String(sidInBrowser!.value)}; sdk_csrf=spa-readable-csrf-token-555`,
      authorization: authInBrowser!,
    })
    assert.equal(offRes.status, 200)
    assert.equal(offSrv.received.length, 1)
    assert.equal(
      offSrv.received[0]!.headers.cookie,
      'sdk_csrf=spa-readable-csrf-token-555',
      'off-origin host must NEVER receive real HttpOnly secret or its placeholder',
    )
    assert.equal(
      offSrv.received[0]!.headers.authorization,
      undefined,
      'off-origin host must NEVER receive real Authorization secret or its placeholder',
    )
    assert.ok(!String(offSrv.received[0]!.headers.cookie ?? '').includes('wire-secret-httponly-token-777'))
    assert.ok(!String(offSrv.received[0]!.headers.cookie ?? '').includes(String(sidInBrowser!.value)))

    releaseVisit()
    const [visitRes] = await visitPromise
    assert.equal(visitRes?.status, 200)
  })
})
