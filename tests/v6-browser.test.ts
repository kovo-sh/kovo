/**
 * v6 Phase 2 Layer-1 SPA runtime tests.
 *
 * Covers pooled per-persona Playwright contexts, HttpOnly cookie + web-storage hydration,
 * passive asset-origin hydration, CDP WebSocket observation, multi-persona union discovery with
 * privileged route surfacing, per-origin soft-404 calibration, and read-only GraphQL/RPC POST
 * classification below Tier 3.
 *
 * Fixtures are synthetic; no benchmark challenge literals are asserted.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import type { RequestBroker } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  classifyBrowserHttpRequest,
  isAssetOriginAllowed,
  isReadOnlyGraphqlOperation,
  isReadOnlyRpcOperation,
  ScopedBrowser,
} from '../src/server/scoped-browser.ts'
import type {
  BrowserSeedCookie,
  BrowserSessionBundle,
  PlaywrightBrowserLike,
  PlaywrightCdpSession,
  ScopedBrowserOptions,
} from '../src/server/scoped-browser.ts'
import {
  crawlStateGraph,
  isPrivilegedPathTemplate,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { ScopedBrowser as ScopedBrowserType } from '../src/server/scoped-browser.ts'
import {
  makeLabGrant, makeStore, setupApprovedRun,
} from './v4-tier-helpers.ts'

// ---------------------------------------------------------------------------------------------
// Fakes: a Playwright-shaped browser that records context/page/route behaviour without Chromium.
// ---------------------------------------------------------------------------------------------

type FakeRequestSpec = {
  url: string
  method?: string
  resourceType?: string
  body?: string | null
  headers?: Record<string, string>
}

type FakeFulfill = { url: string; status?: number; contentType?: string; body?: string | Buffer }

class FakeCdp implements PlaywrightCdpSession {
  readonly sent: string[] = []
  private readonly listeners = new Map<string, Array<(payload: Record<string, unknown>) => void>>()
  async send(method: string): Promise<unknown> { this.sent.push(method); return undefined }
  on(event: string, listener: (payload: Record<string, unknown>) => void): void {
    const list = this.listeners.get(event) ?? []
    list.push(listener)
    this.listeners.set(event, list)
  }
  emit(event: string, payload: Record<string, unknown>): void {
    for (const listener of this.listeners.get(event) ?? []) listener(payload)
  }
  async detach(): Promise<void> { /* no-op */ }
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
  async fulfill(response: FakeFulfill): Promise<void> {
    this.context.fulfilled.push(response)
  }
}

class FakePage {
  urlValue = 'about:blank'
  closed = false
  readonly runtime: FakeRuntime
  private readonly context: FakeContext
  constructor(runtime: FakeRuntime, context: FakeContext) {
    this.runtime = runtime
    this.context = context
  }
  on(): void { /* console listeners are not exercised */ }
  async goto(url: string, _options?: unknown): Promise<{ status(): number }> {
    this.urlValue = url
    await this.runtime.dispatch(this.context, { url, method: 'GET', resourceType: 'document' })
    for (const extra of this.runtime.extraRequests) await this.runtime.dispatch(this.context, extra)
    if (this.runtime.onGoto) await this.runtime.onGoto(this)
    return { status: () => 200 }
  }
  async waitForTimeout(_ms: number): Promise<void> {
    this.runtime.timeoutCalls += 1
  }
  async waitForLoadState(state?: string): Promise<void> {
    this.runtime.loadStateCalls.push(state ?? 'load')
  }
  url(): string { return this.urlValue }
  async title(): Promise<string> { return 'fixture' }
  async evaluate<T, A = undefined>(fn: (arg: A) => T | Promise<T>, _arg?: A): Promise<T> {
    const source = fn.toString()
    if (source.includes('MutationObserver')) return undefined as T
    if (source.includes('role="tab"')) return [] as unknown as T
    return this.runtime.snapshot() as T
  }
  async click(selector: string): Promise<void> {
    this.runtime.clicks.push(selector)
  }
  async close(): Promise<void> { this.closed = true }
}

class FakeContext {
  readonly initScripts: string[] = []
  readonly cookies: Array<Record<string, unknown>> = []
  readonly fulfilled: FakeFulfill[] = []
  readonly aborted: Array<{ url: string; errorCode: string | null }> = []
  readonly pages: FakePage[] = []
  readonly runtime: FakeRuntime
  closed = false
  routeHandler: ((route: FakeRoute) => Promise<void> | void) | null = null
  constructor(runtime: FakeRuntime) {
    this.runtime = runtime
  }
  async addInitScript(script: string | (() => void)): Promise<void> {
    this.initScripts.push(typeof script === 'string' ? script : script.toString())
  }
  async addCookies(cookies: Array<Record<string, unknown>>): Promise<void> {
    for (const cookie of cookies) this.cookies.push({ ...cookie })
  }
  async route(_pattern: string, handler: (route: FakeRoute) => Promise<void> | void): Promise<void> {
    this.routeHandler = handler
  }
  async routeWebSocket(): Promise<void> { /* scope guard installed */ }
  async newPage(): Promise<FakePage> {
    const page = new FakePage(this.runtime, this)
    this.pages.push(page)
    this.runtime.pages.push(page)
    return page
  }
  async newCDPSession(): Promise<FakeCdp> {
    this.runtime.cdp = new FakeCdp()
    return this.runtime.cdp
  }
  async close(): Promise<void> { this.closed = true }
}

class FakeRuntime {
  readonly contexts: FakeContext[] = []
  readonly pages: FakePage[] = []
  readonly loadStateCalls: string[] = []
  readonly clicks: string[] = []
  readonly browser: FakeBrowser
  timeoutCalls = 0
  extraRequests: FakeRequestSpec[] = []
  cdp: FakeCdp | null = null
  onGoto: ((page: FakePage) => void | Promise<void>) | null = null
  domHtml = '<html><body><div id="app">fixture</div></body></html>'
  links: string[] = []
  localStorageKeys: string[] = []
  sessionStorageKeys: string[] = []
  constructor(browser: FakeBrowser) {
    this.browser = browser
  }
  async dispatch(context: FakeContext, spec: FakeRequestSpec): Promise<void> {
    if (!context.routeHandler) return
    await context.routeHandler(new FakeRoute(spec, context))
  }
  snapshot() {
    return {
      domHtml: this.domHtml,
      links: this.links,
      forms: [],
      cookieNames: [],
      localStorageKeys: this.localStorageKeys,
      sessionStorageKeys: this.sessionStorageKeys,
      postMessageListeners: {
        count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false,
      },
    }
  }
}

class FakeBrowser {
  readonly runtime = new FakeRuntime(this)
  closed = false
  async newContext(): Promise<FakeContext> {
    const context = new FakeContext(this.runtime)
    this.runtime.contexts.push(context)
    return context
  }
  async close(): Promise<void> { this.closed = true }
  asPlaywright(): PlaywrightBrowserLike {
    return this as unknown as PlaywrightBrowserLike
  }
}

function fakeExchange(req: BrokerHttpRequest, overrides: Partial<BrokerExchangeResult> = {}): BrokerExchangeResult {
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
    bodyBytes: 10,
    bodyTruncated: false,
    durationMs: 1,
    observation: { source: 'fixture response' },
    ...overrides,
  } as BrokerExchangeResult
}

function makeFakeBroker(handler?: (req: BrokerHttpRequest) => BrokerExchangeResult) {
  const executed: BrokerHttpRequest[] = []
  const broker = {
    executeHttp: async (req: BrokerHttpRequest) => {
      executed.push(req)
      return handler ? handler(req) : fakeExchange(req)
    },
    sessionCookiesForBrowser: () => [],
    getRegisteredSecrets: () => [],
    getStorage: () => undefined,
  } as unknown as RequestBroker
  return { broker, executed }
}

const appOrigin = 'https://app.fixture.test'
const cdnOrigin = 'https://cdn.fixture.test'
const evilOrigin = 'https://evil.fixture.test'

function baseGrant(overrides: Partial<Grant> = {}): Grant {
  return makeLabGrant(appOrigin, { tier: 3, allowLocalLab: true, ...overrides })
}

async function withBrowser(
  t: TestContext,
  input: { broker: RequestBroker } & ScopedBrowserOptions = { broker: makeFakeBroker().broker },
): Promise<{ browser: ScopedBrowser; fake: FakeBrowser; launches: () => number }> {
  const fake = new FakeBrowser()
  let launches = 0
  const { broker, ...options } = input
  const browser = new ScopedBrowser(broker, {
    launchBrowser: async () => {
      launches += 1
      return fake.asPlaywright()
    },
    ...options,
  })
  t.after(() => browser.close())
  return { browser, fake, launches: () => launches }
}

// ---------------------------------------------------------------------------------------------
// 1. Pooled contexts
// ---------------------------------------------------------------------------------------------

describe('v6 browser: pooled per-persona contexts', () => {
  test('reuses one Chromium and one context per persona across navigations', async (t: TestContext) => {
    const { broker, executed } = makeFakeBroker()
    const { browser, fake, launches } = await withBrowser(t, { broker })

    const results = await browser.visitPages([
      { origin: appOrigin, pathAndQuery: '/' },
      { origin: appOrigin, pathAndQuery: '/dashboard', persona: 'admin' },
      { origin: appOrigin, pathAndQuery: '/reports', persona: 'admin' },
      { origin: appOrigin, pathAndQuery: '/profile', persona: 'viewer' },
    ], baseGrant(), AbortSignal.timeout(30_000))

    assert.equal(results.length, 4)
    assert.equal(launches(), 1, 'one Chromium launch for the whole run')
    assert.equal(fake.runtime.contexts.length, 3, 'one BrowserContext per persona (plus anonymous)')
    assert.equal(fake.runtime.pages.length, 3, 'pages are reused, not recreated per visit')
    assert.ok(fake.runtime.loadStateCalls.filter(state => state === 'networkidle').length >= 4,
      'each visit waits for network-idle instead of a fixed 120 ms sleep')
    assert.equal(fake.runtime.timeoutCalls, 0, 'no fixed settle sleeps when network-idle is available')
    assert.equal(executed.filter(req => req.origin === appOrigin).length, 4, 'every navigation stays broker-proxied')

    assert.equal(browser.getPoolStats().launches, 1)
    assert.equal(browser.getPoolStats().activeContexts, 3)

    await browser.close()
    assert.equal(fake.closed, true, 'Chromium is closed by cleanup')
    assert.ok(fake.runtime.contexts.every(context => context.closed), 'no pooled context survives cleanup')
    assert.equal(browser.getPoolStats().activeContexts, 0)
    assert.equal(browser.getPoolStats().contextsClosed, 3)
  })

  test('hydrates HttpOnly cookies and localStorage/sessionStorage into the persona context', async (t: TestContext) => {
    const { broker } = makeFakeBroker()
    const { browser, fake } = await withBrowser(t, { broker })
    fake.runtime.localStorageKeys = ['guardian_session', 'tenant']
    fake.runtime.sessionStorageKeys = ['step']
    const cookie: BrowserSeedCookie = {
      name: 'sid', value: 'fixture-session-value', domain: 'app.fixture.test', path: '/',
      secure: true, httpOnly: true, sameSite: 'Lax',
    }
    const bundle: BrowserSessionBundle = {
      cookies: [cookie],
      localStorage: { guardian_session: 'local-fixture-value', tenant: 't1' },
      sessionStorage: { step: '2' },
    }

    const [visit] = await browser.visitPages([
      { origin: appOrigin, pathAndQuery: '/admin', persona: 'admin', sessionBundle: bundle },
    ], baseGrant(), AbortSignal.timeout(30_000))

    const context = fake.runtime.contexts[0]!
    assert.equal(context.cookies.length, 1)
    assert.equal(context.cookies[0]!.name, 'sid')
    assert.equal(context.cookies[0]!.httpOnly, true, 'HttpOnly cookies survive hydration')
    assert.equal(context.cookies[0]!.sameSite, 'Lax')
    const initScript = context.initScripts.join('\n')
    assert.ok(initScript.includes('guardian_session'), 'localStorage seed key is installed')
    assert.ok(initScript.includes('tenant'), 'localStorage seed values are installed')
    assert.ok(initScript.includes('step'), 'sessionStorage seed key is installed')
    assert.deepEqual(visit.localStorageKeys, ['guardian_session', 'tenant'])
    assert.deepEqual(visit.sessionStorageKeys, ['step'])
  })

  test('seeds pooled contexts from the v6-auth persona browser attachment (HttpOnly + storage)', async (t: TestContext) => {
    const { chmodSync } = await import('node:fs')
    const dir = mkdtempSync(join(tmpdir(), 'guardian-v6-attach-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const sessionPath = join(dir, 'session.json')
    writeFileSync(sessionPath, JSON.stringify({
      headerType: 'cookie',
      value: 'legacy-cookie-value',
      adapterUsed: 'manual',
      bundle: {
        cookies: [{
          name: '__session', value: 'vault-cookie-value', domain: 'app.fixture.test', path: '/',
          httpOnly: true, secure: true,
        }],
        storage: { localStorage: { vaultKey: 'vault-value' }, sessionStorage: { vaultStep: '1' } },
      },
    }), 'utf8')
    chmodSync(sessionPath, 0o600)
    const persona: ResolvedPersona = {
      id: 'persona-admin',
      handle: 'admin',
      roleLabel: 'Admin',
      originAllowlist: [appOrigin],
      authKind: 'login',
      headerName: null,
      secret: 'legacy-cookie-value',
      canaryMarkers: [],
      sessionPath,
    }

    const { broker } = makeFakeBroker()
    const { browser, fake } = await withBrowser(t, { broker })
    fake.runtime.localStorageKeys = ['vaultKey']
    fake.runtime.sessionStorageKeys = ['vaultStep']

    const [visit] = await browser.visitPages([
      { origin: appOrigin, pathAndQuery: '/admin', persona: 'admin' },
    ], baseGrant({ personas: new Map([['admin', persona]]) }), AbortSignal.timeout(30_000))

    const context = fake.runtime.contexts[0]!
    assert.equal(context.cookies.length, 1, 'vault attachment contributes Playwright-ready cookies')
    assert.equal(context.cookies[0]!.name, '__session')
    assert.equal(context.cookies[0]!.httpOnly, true, 'HttpOnly is preserved from the vault attachment')
    assert.ok(context.initScripts.join('\n').includes('vaultKey'), 'vault storage hydration script is installed')
    assert.deepEqual(visit.sessionStorageKeys, ['vaultStep'])
  })
})

// ---------------------------------------------------------------------------------------------
// 2. Asset origins
// ---------------------------------------------------------------------------------------------

describe('v6 browser: passive asset origins', () => {
  test('allows allowlisted CDN GET hydration and blocks unknown hosts while active probing stays scoped', async (t: TestContext) => {
    const { broker, executed } = makeFakeBroker()
    const { browser, fake } = await withBrowser(t, { broker, assetOrigins: [cdnOrigin] })
    fake.runtime.extraRequests = [
      { url: `${cdnOrigin}/app.js`, method: 'GET', resourceType: 'script' },
      { url: `${evilOrigin}/tracker.js`, method: 'GET', resourceType: 'script' },
      { url: `${cdnOrigin}/api/mutate`, method: 'POST', resourceType: 'fetch', body: '{"op":"write"}' },
    ]

    const [visit] = await browser.visitPages([
      { origin: appOrigin, pathAndQuery: '/' },
    ], baseGrant(), AbortSignal.timeout(30_000))

    const executedOrigins = executed.map(req => `${req.method} ${req.origin}`)
    assert.ok(executedOrigins.includes(`GET ${cdnOrigin}`), 'CDN asset GET is hydrated through the broker')
    assert.ok(!executedOrigins.some(entry => entry.includes(evilOrigin)), 'off-allowlist host never reaches the broker')
    assert.ok(!executedOrigins.some(entry => entry === `POST ${cdnOrigin}`), 'asset origins never carry active probes')
    assert.ok(visit.blockedOrigins.includes(evilOrigin), 'off-allowlist origin is recorded as blocked')
    // The CDN POST probe is refused; the GET hydration is the only allowed asset interaction.
    assert.ok(visit.allRequests?.some(rec => rec.origin === cdnOrigin && rec.resourceType === 'script'),
      'passive hydration is recorded for discovery')
    assert.ok(visit.exchanges.every(ex => ex.origin === appOrigin), 'only target-origin traffic is discovery scope')
    // Asset hydration must not become an exchange (and therefore not consume probe budget).
    assert.equal(visit.exchanges.length, 1)
  })

  test('asset origin matcher fails closed on unknown hosts and wildcard-all patterns', () => {
    assert.equal(isAssetOriginAllowed(cdnOrigin, { origins: ['https://cdn.fixture.test'] }), true)
    assert.equal(isAssetOriginAllowed('https://static.fixture.test', { origins: ['*.fixture.test'] }), true)
    assert.equal(isAssetOriginAllowed('https://fixture.test', { origins: ['*.fixture.test'] }), false)
    assert.equal(isAssetOriginAllowed(cdnOrigin, { origins: ['*'] }), false)
    assert.equal(isAssetOriginAllowed('ftp://cdn.fixture.test', { origins: ['cdn.fixture.test'] }), false)
    assert.equal(isAssetOriginAllowed(evilOrigin, { origins: [cdnOrigin] }), false)
    assert.equal(isAssetOriginAllowed(evilOrigin, undefined), false)
  })
})

// ---------------------------------------------------------------------------------------------
// 3. WebSocket capture + interactive traversal
// ---------------------------------------------------------------------------------------------

describe('v6 browser: WebSocket discovery', () => {
  test('captures CDP Network.webSocket* events and merges them into discovery', async (t: TestContext) => {
    const { broker } = makeFakeBroker()
    const { browser, fake } = await withBrowser(t, { broker })
    fake.runtime.onGoto = () => {
      const cdp = fake.runtime.cdp
      assert.ok(cdp, 'CDP session attached to the pooled page')
      cdp.emit('Network.webSocketCreated', { requestId: 'ws-1', url: 'wss://app.fixture.test/socket' })
      cdp.emit('Network.webSocketWillSendHandshakeRequest', {
        requestId: 'ws-1', request: { headers: { 'Sec-WebSocket-Protocol': 'graphql-ws' } },
      })
      cdp.emit('Network.webSocketHandshakeResponseReceived', { requestId: 'ws-1', response: { status: 101 } })
      cdp.emit('Network.webSocketFrameReceived', { requestId: 'ws-1', response: { opcode: 1, payloadData: '{"type":"welcome"}' } })
      cdp.emit('Network.webSocketFrameSent', { requestId: 'ws-1', response: { opcode: 1, payloadData: '{"type":"subscribe"}' } })
    }

    const [visit] = await browser.visitPages([
      { origin: appOrigin, pathAndQuery: '/realtime' },
    ], baseGrant(), AbortSignal.timeout(30_000))

    assert.ok(visit.webSockets && visit.webSockets.length === 1, 'socket observed through CDP')
    const socket = visit.webSockets![0]!
    assert.equal(socket.origin, appOrigin)
    assert.equal(socket.handshakeStatus, 101)
    assert.equal(socket.protocol, 'graphql-ws')
    assert.equal(socket.frameCount, 2)
    assert.deepEqual(socket.frames.map(frame => frame.direction), ['received', 'sent'])
    assert.ok(visit.allRequests?.some(rec => rec.resourceType === 'websocket' && rec.origin === appOrigin),
      'socket is merged into discovery request records')
    assert.ok(fake.runtime.cdp!.sent.includes('Network.enable'), 'CDP Network domain enabled')
  })

  test('interactive traversal clicks non-destructive affordances only and never submits forms', async (t: TestContext) => {
    const { broker } = makeFakeBroker()
    const { browser, fake } = await withBrowser(t, { broker })
    // Candidate collection is stubbed to two safe tabs by the fake evaluate detector; clicks record.
    const [visit] = await browser.visitPages([
      {
        origin: appOrigin,
        pathAndQuery: '/dashboard',
        interactiveTraversal: { maxClicks: 3 },
      },
    ], baseGrant(), AbortSignal.timeout(30_000))
    assert.ok(visit.interactiveTraversal, 'traversal summary present')
    assert.equal(visit.interactiveTraversal!.readOnlyMode, true, 'read-only mode is the default')
    assert.equal(fake.runtime.clicks.length, 0, 'fake candidate list is empty: nothing is clicked blindly')
  })
})

// ---------------------------------------------------------------------------------------------
// 4. Multi-persona union discovery + privileged surfacing
// ---------------------------------------------------------------------------------------------

describe('v6 browser: multi-persona union', () => {
  function visitFixture(origin: string, pathAndQuery: string, links: string[]) {
    return {
      origin,
      finalUrl: `${origin}${pathAndQuery}`,
      title: 'fixture',
      status: 200,
      domSnippet: '<html><body>fixture</body></html>',
      links,
      forms: [],
      xhrRequests: [],
      allRequests: [],
      blockedOrigins: [],
      consoleMessages: [],
      postMessageListeners: { count: 0, hasOnMessage: false, handlers: [], observedEvents: 0, canaryHandledWithoutOriginCheck: false },
      cookieNames: [],
      localStorageKeys: [],
      sessionStorageKeys: [],
      canaryCheck: { token: null, triggered: false, detail: null },
      domSinkTraces: [],
      exchangeIds: [],
      exchanges: [],
      durationMs: 1,
    }
  }

  test('crawls every persona and surfaces an admin-only route immediately', async (t: TestContext) => {
    const { storage } = makeStore(t, 'guardian-v6-union-')
    const origin = appOrigin
    const { runId, run } = await setupApprovedRun(storage, { seeds: [origin], budgetRequests: 900 })
    const visited: Array<{ persona?: string; path: string }> = []
    const browser = {
      visitPage: async (req: { persona?: string; pathAndQuery: string }) => {
        visited.push({ persona: req.persona, path: req.pathAndQuery })
        if (req.persona === 'admin' && req.pathAndQuery === '/') {
          return visitFixture(origin, '/', ['/dashboard', '/admin/audit'])
        }
        if (req.persona === 'admin' && req.pathAndQuery === '/admin/audit') {
          return visitFixture(origin, '/admin/audit', [])
        }
        return visitFixture(origin, req.pathAndQuery, ['/dashboard'])
      },
    } as unknown as ScopedBrowserType

    const result = await crawlStateGraph({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      origin,
      personas: ['admin', 'viewer'],
      maxPages: 8,
      maxDepth: 2,
      browser,
      grant: baseGrant(),
      signal: AbortSignal.timeout(20_000),
    })

    assert.ok(visited.some(entry => entry.persona === 'admin'), 'admin persona was crawled')
    assert.ok(visited.some(entry => entry.persona === 'viewer'), 'viewer persona was crawled, not just persona[0]')
    assert.deepEqual(result.visibleToPersonas?.['GET /admin/audit'], ['admin'],
      'admin-only route is tagged with its visible persona union')
    assert.ok(result.privilegedEndpoints?.some(entry =>
      entry.pathTemplate === '/admin/audit' && entry.reason.includes('privileged_path')),
    'privileged route surfaced immediately')
    const endpoint = storage.listEndpoints(runId, { origin }).find(ep => ep.method === 'GET' && ep.pathTemplate === '/admin/audit')
    assert.ok(endpoint, 'admin-only endpoint recorded by the union crawl')
    assert.equal(endpoint.authRequirement, 'persona:admin')
    assert.ok(isPrivilegedPathTemplate('/admin/audit'))
    assert.ok(!isPrivilegedPathTemplate('/dashboard'))
  })
})

// ---------------------------------------------------------------------------------------------
// 5. Per-origin soft-404 calibration
// ---------------------------------------------------------------------------------------------

describe('v6 browser: per-origin soft-404 calibration', () => {
  test('calibrates with several unmatched nested paths and still records real JSON surface', async (t: TestContext) => {
    const { storage } = makeStore(t, 'guardian-v6-soft404-')
    const origin = appOrigin
    const setup = await setupApprovedRun(storage, {
      seeds: [origin],
      budgetRequests: 900,
      personas: [{ handle: 'admin', roleLabel: 'Admin', authKind: 'bearer', secret: 'fixture-admin-token' }],
    })
    const shell = '<html><body><div id="app">Loading…</div><script src="/app.js"></script></body></html>'
    const requested: string[] = []
    const { broker } = makeFakeBroker(req => {
      requested.push(req.pathAndQuery)
      if (req.pathAndQuery === '/') {
        return fakeExchange(req, {
          body: shell.replace('</body>', '<a href="/admin/audit">Audit</a></body>'),
        })
      }
      if (req.pathAndQuery.startsWith('/admin/audit')) {
        return fakeExchange(req, {
          mediaType: 'application/json',
          body: JSON.stringify({ items: [], meta: { total: 0 } }),
        })
      }
      return fakeExchange(req, { body: shell })
    })
    const grant = makeLabGrant(origin, {
      tier: 2,
      personas: setup.personaMap,
      canRead: (o: string) => o === origin,
    })

    const result = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 2,
      origins: [origin],
      budgetRequests: 900,
      personas: ['admin'],
      broker,
      grant,
      signal: AbortSignal.timeout(20_000),
    })

    const calibrationProbes = requested.filter(path => path.includes('.guardian-cal-'))
    assert.ok(calibrationProbes.length >= 3, `expected several unmatched calibration paths, saw ${calibrationProbes.join(',')}`)
    assert.ok(new Set(calibrationProbes.map(path => path.split('?')[0])).size >= 3, 'calibration probes use distinct nested paths')
    assert.ok((result.soft404Rejected ?? 0) >= 1, 'SPA catch-all responses are rejected')
    const endpoints = storage.listEndpoints(setup.runId, { origin })
    assert.ok(endpoints.some(ep => ep.pathTemplate === '/admin/audit' && ep.method === 'GET'),
      'real JSON admin route survives calibration')
    assert.ok(!endpoints.some(ep => ep.pathTemplate === '/ghost-page'), 'no catch-all route leaks in')
    assert.ok(result.visibleToPersonas?.['GET /']?.includes('admin'), 'root visibility includes the authenticated persona')
    assert.ok(result.privilegedEndpoints?.some(entry => entry.pathTemplate === '/admin/audit'),
      'admin route surfaced as privileged from the persona union')
  })
})

// ---------------------------------------------------------------------------------------------
// 6. Read-only GraphQL/RPC POST below Tier 3
// ---------------------------------------------------------------------------------------------

describe('v6 browser: read-only GraphQL/RPC POST', () => {
  test('classifies query-only GraphQL POST as read-only below Tier 3', () => {
    const readOnly = classifyBrowserHttpRequest({
      method: 'POST',
      url: `${appOrigin}/graphql`,
      body: JSON.stringify({ query: 'query Viewer { viewer { id email } }', operationName: 'Viewer' }),
      tier: 1,
      canRead: origin => origin === appOrigin,
      allowLocalLab: false,
    })
    assert.equal(readOnly.allowed, true)
    assert.equal(readOnly.readOnlyGraphql, true)

    const anonymousSelection = classifyBrowserHttpRequest({
      method: 'POST',
      url: `${appOrigin}/graphql`,
      body: '{"query":"{ viewer { id } }"}',
      tier: 2,
      canRead: origin => origin === appOrigin,
      allowLocalLab: false,
    })
    assert.equal(anonymousSelection.allowed, true)
    assert.equal(anonymousSelection.readOnlyGraphql, true)

    const mutationBelowTier2 = classifyBrowserHttpRequest({
      method: 'POST',
      url: `${appOrigin}/graphql`,
      body: JSON.stringify({ query: 'mutation DeleteUser { deleteUser(id: 1) { ok } }' }),
      tier: 1,
      canRead: origin => origin === appOrigin,
      allowLocalLab: false,
    })
    assert.equal(mutationBelowTier2.allowed, false)
    assert.equal(mutationBelowTier2.reason, 'tier_too_low')

    const mutationAtTier2 = classifyBrowserHttpRequest({
      method: 'POST',
      url: `${appOrigin}/graphql`,
      body: JSON.stringify({ query: 'mutation DeleteUser { deleteUser(id: 1) { ok } }' }),
      tier: 2,
      canRead: origin => origin === appOrigin,
      allowLocalLab: false,
    })
    assert.equal(mutationAtTier2.allowed, true, 'Tier-2 sandbox POST remains allowed (existing contract)')
    assert.equal(mutationAtTier2.readOnlyGraphql, false, 'mutation is not reported as a read-only operation')

    const mutationAtTier3 = classifyBrowserHttpRequest({
      method: 'POST',
      url: `${appOrigin}/graphql`,
      body: JSON.stringify({ query: 'mutation DeleteUser { deleteUser(id: 1) { ok } }' }),
      tier: 3,
      canRead: origin => origin === appOrigin,
      allowLocalLab: false,
    })
    assert.equal(mutationAtTier3.allowed, true)
    assert.equal(mutationAtTier3.readOnlyGraphql, false)
  })

  test('does not classify mutation keywords inside string literals or JSON-RPC writes as read-only', () => {
    assert.equal(isReadOnlyGraphqlOperation('{"query":"query Q { t(text: \\"mutation Delete\\") { id } }"}'), true)
    assert.equal(isReadOnlyGraphqlOperation('{"query":"subscription S { onEvent { id } }"}'), false)
    assert.equal(isReadOnlyGraphqlOperation('{"mutation":"DeleteUser","variables":{}}'), false)
    assert.equal(isReadOnlyGraphqlOperation('[{"query":"query A { a }"},{"query":"mutation B { b }"}]'), false)
    assert.equal(isReadOnlyRpcOperation('{"jsonrpc":"2.0","method":"users.list","params":{}}'), true)
    assert.equal(isReadOnlyRpcOperation('{"jsonrpc":"2.0","method":"users.delete","params":{}}'), false)
    assert.equal(isReadOnlyRpcOperation('{"method":"billing.charge","id":1}'), false)
  })
})
