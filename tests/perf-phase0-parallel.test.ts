/**
 * Option C Part 2 regression tests:
 * - Adaptive multi-host `computeAdaptivePhase0PerOriginCap` scaling across 1, 5, 10, 27, 50 hosts
 * - Bounded multi-host concurrency in `runPhase0Recon` (6 delayed origins finish in < 2.5x single-origin time)
 * - Fast-fail dead/525 and transport-timeout hosts (<= 5 requests, skip templates & Playwright, sibling healthy hosts unaffected)
 * - Parallel Playwright `crawlStateGraph` bounded by browser semaphore + automatic skip on non-HTML hosts
 * - `surface-engine.ts` forwards explicit bounded `timeoutMs <= 12_000` on template probes
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from '../src/server/broker.ts'
import {
  computeAdaptivePhase0PerOriginCap,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { BrowserVisitResult, ScopedBrowser } from '../src/server/scoped-browser.ts'
import { runSafeTemplates, surfaceProbeTimeoutMs } from '../src/server/surface-engine.ts'
import { makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

function makeMultiOriginGrant(origins: readonly string[], tier: 0 | 1 | 2 = 2): Grant {
  const allowed = new Set(origins.map(o => new URL(o).origin))
  return {
    runId: 'test-run',
    scopeRevision: 1,
    tier,
    allowLocalLab: true,
    canRead(origin: string) {
      try { return allowed.has(new URL(origin).origin) } catch { return false }
    },
    canWrite(origin: string) {
      try { return allowed.has(new URL(origin).origin) } catch { return false }
    },
    canUseAuth() { return true },
    audit() { /* noop */ },
  } as unknown as Grant
}

function makeExchange(
  req: BrokerHttpRequest,
  status: number,
  mediaType: string,
  body: string,
  seq: number,
): BrokerExchangeResult {
  return {
    id: `ex-${seq}`,
    origin: req.origin,
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    status,
    mediaType,
    respHeaders: { 'content-type': mediaType },
    reqHeaders: req.headers ?? {},
    body,
    bodyPreview: body.slice(0, 512),
    bodySha256: '0'.repeat(64),
    truncated: false,
    elapsedMs: 1,
    redirectPaths: [],
    redirectOrigins: [req.origin],
    finalOrigin: req.origin,
    finalPathAndQuery: req.pathAndQuery,
    personaHandle: req.persona ?? null,
    createdAt: Date.now(),
  } as unknown as BrokerExchangeResult
}

describe('Option C Part 2: Adaptive budget scaling & concurrency helpers', () => {
  test('computeAdaptivePhase0PerOriginCap scales smoothly across 1, 5, 10, 27, 50 hosts and honors explicitCap', () => {
    // 1–5 hosts: full depth (150 at default 1000 budget, up to 250 when runBudget is large)
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 1, runBudget: 1000 }), 150)
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 5, runBudget: 1000 }), 150)
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 1, runBudget: 3000 }), 250)
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 5, runBudget: 3000 }), 250)

    // 6–15 hosts: tapers smoothly into 100–120
    const cap6 = computeAdaptivePhase0PerOriginCap({ hostCount: 6, runBudget: 5000 })
    const cap10 = computeAdaptivePhase0PerOriginCap({ hostCount: 10, runBudget: 5000 })
    const cap15 = computeAdaptivePhase0PerOriginCap({ hostCount: 15, runBudget: 5000 })
    assert.ok(cap6 >= 100 && cap6 <= 120, `expected 6-host cap in [100,120], got ${cap6}`)
    assert.ok(cap10 >= 100 && cap10 <= 120, `expected 10-host cap in [100,120], got ${cap10}`)
    assert.ok(cap15 >= 100 && cap15 <= 120, `expected 15-host cap in [100,120], got ${cap15}`)
    assert.ok(cap6 >= cap10 && cap10 >= cap15, '6..15 taper must be monotonically non-increasing')

    // 16+ hosts (including 27 and 50): tapers smoothly into 65–80
    const cap16 = computeAdaptivePhase0PerOriginCap({ hostCount: 16, runBudget: 10_000 })
    const cap27 = computeAdaptivePhase0PerOriginCap({ hostCount: 27, runBudget: 10_000 })
    const cap50 = computeAdaptivePhase0PerOriginCap({ hostCount: 50, runBudget: 10_000 })
    assert.ok(cap16 >= 65 && cap16 <= 80, `expected 16-host cap in [65,80], got ${cap16}`)
    assert.ok(cap27 >= 65 && cap27 <= 80, `expected 27-host cap in [65,80], got ${cap27}`)
    assert.ok(cap50 >= 65 && cap50 <= 80, `expected 50-host cap in [65,80], got ${cap50}`)
    assert.ok(cap15 >= cap16 && cap16 >= cap27 && cap27 >= cap50, 'taper must be monotonically non-increasing across all host counts')

    // Tight runBudget still constrains cap below host ceiling
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 27, runBudget: 100 }), 15)

    // Explicit caller override always wins
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 27, runBudget: 10_000, explicitCap: 180 }), 180)
    assert.equal(computeAdaptivePhase0PerOriginCap({ hostCount: 1, runBudget: 100, explicitCap: 42 }), 42)
  })
})

describe('Option C Part 2: Parallel multi-host Phase-0 recon', () => {
  test('6 delayed mock origins execute in parallel (< 2.5x single-origin time) with accurate hostsDone telemetry', async t => {
    const origins = Array.from({ length: 6 }, (_, i) => `https://svc-${i + 1}.parallel.test`)
    const DELAY_MS = 80
    const makeDelayedBroker = () => {
      let seq = 0
      let inFlight = 0
      let maxInFlight = 0
      const broker = {
        async executeHttp(req: BrokerHttpRequest) {
          seq += 1
          inFlight += 1
          if (inFlight > maxInFlight) maxInFlight = inFlight
          try {
            await delay(DELAY_MS)
            if (req.pathAndQuery === '/') {
              return makeExchange(req, 200, 'text/html', '<html><body><a href="/api/ping">ping</a></body></html>', seq)
            }
            if (req.pathAndQuery === '/api/ping') {
              return makeExchange(req, 200, 'application/json', JSON.stringify({ ok: true }), seq)
            }
            return makeExchange(req, 404, 'text/plain', 'not found', seq)
          } finally {
            inFlight -= 1
          }
        },
      } as unknown as RequestBroker
      return { broker, getMaxInFlight: () => maxInFlight }
    }

    // Baseline single-origin timing with tight cap (8 reqs/origin) so each host executes a fixed probe set
    const { storage: singleStore } = makeStore(t, 'kovo-perf-single-')
    const singleSetup = await setupApprovedRun(singleStore, { seeds: [origins[0]!], tier: 2 })
    const singleBroker = makeDelayedBroker()
    const singleStart = performance.now()
    await runPhase0Recon({
      storage: singleStore,
      runId: singleSetup.runId,
      scopeRevision: singleSetup.run.scopeRevision,
      tier: 2,
      origins: [origins[0]!],
      perOriginCap: 8,
      broker: singleBroker.broker,
      grant: makeMultiOriginGrant([origins[0]!], 2),
      signal: AbortSignal.timeout(15_000),
    })
    const singleMs = performance.now() - singleStart

    // 6-origin concurrent run with the exact same perOriginCap
    const { storage: multiStore } = makeStore(t, 'kovo-perf-multi-')
    const multiSetup = await setupApprovedRun(multiStore, { seeds: origins, tier: 2 })
    const multiBroker = makeDelayedBroker()
    const multiStart = performance.now()
    const multiRes = await runPhase0Recon({
      storage: multiStore,
      runId: multiSetup.runId,
      scopeRevision: multiSetup.run.scopeRevision,
      tier: 2,
      origins,
      perOriginCap: 8,
      broker: multiBroker.broker,
      grant: makeMultiOriginGrant(origins, 2),
      signal: AbortSignal.timeout(15_000),
    })
    const multiMs = performance.now() - multiStart

    assert.ok(
      multiBroker.getMaxInFlight() >= 4,
      `expected true concurrent in-flight requests across 6 origins (got peak ${multiBroker.getMaxInFlight()})`,
    )
    assert.ok(
      multiMs < singleMs * 2.5,
      `expected 6 parallel origins (${Math.round(multiMs)}ms) to finish in < 2.5x single-origin time (${Math.round(singleMs)}ms)`,
    )
    assert.equal(multiRes.perOriginCap, 8)
    assert.ok(multiRes.endpointsDiscovered >= 6, 'all 6 origins should record their discovered endpoints')

    const stageEvents = multiStore.eventsAfter(multiSetup.runId, 0, 500)
      .filter(ev => ev.kind === 'phase0.stage')
      .map(ev => ev.detail as { hostsDone?: number; hostsTotal?: number })
    assert.ok(stageEvents.length > 0, 'expected phase0.stage telemetry events')
    assert.ok(
      stageEvents.some(d => d.hostsDone === 6 && d.hostsTotal === 6),
      'expected phase0.stage to reach hostsDone=6, hostsTotal=6',
    )
  })
})

describe('Option C Part 2: Fast-fail dead/525 hosts & browser concurrency', () => {
  test('525 and timeout origins halt in <= 5 requests and skip templates & Playwright while healthy sibling completes', async t => {
    const dead525Origin = 'https://dead-tls.example.test'
    const deadTimeoutOrigin = 'https://dead-timeout.example.test'
    const healthyOrigin = 'https://healthy-app.example.test'
    const origins = [dead525Origin, deadTimeoutOrigin, healthyOrigin]

    const requestsByOrigin = new Map<string, string[]>()
    let seq = 0
    const fakeBroker = {
      async executeHttp(req: BrokerHttpRequest) {
        seq += 1
        const list = requestsByOrigin.get(req.origin) ?? []
        list.push(req.pathAndQuery)
        requestsByOrigin.set(req.origin, list)

        if (req.origin === dead525Origin) {
          return makeExchange(req, 525, 'text/html', '<html><body>SSL Handshake Failed</body></html>', seq)
        }
        if (req.origin === deadTimeoutOrigin) {
          throw new Error('Request timeout after 8000ms')
        }
        if (req.pathAndQuery === '/') {
          return makeExchange(
            req,
            200,
            'text/html',
            '<html><body><a href="/api/orders">orders</a><script src="/app.js"></script></body></html>',
            seq,
          )
        }
        if (req.pathAndQuery === '/app.js') {
          return makeExchange(req, 200, 'application/javascript', 'fetch("/api/orders");', seq)
        }
        if (req.pathAndQuery === '/api/orders') {
          return makeExchange(req, 200, 'application/json', JSON.stringify({ items: [{ id: 1 }] }), seq)
        }
        return makeExchange(req, 404, 'text/plain', 'not found', seq)
      },
    } as unknown as RequestBroker

    const browserVisitedOrigins: string[] = []
    const fakeBrowser = {
      async visitPage(req: { origin: string; pathAndQuery: string }): Promise<BrowserVisitResult> {
        browserVisitedOrigins.push(req.origin)
        return {
          origin: req.origin,
          pathAndQuery: req.pathAndQuery,
          finalUrl: `${req.origin}${req.pathAndQuery}`,
          title: 'Healthy App',
          links: [],
          forms: [],
          xhrRequests: [],
          allRequests: [],
          exchanges: [],
          localStorageKeys: [],
          sessionStorageKeys: [],
          postMessageListeners: { count: 0, hasOnMessage: false },
          domSnippet: '<html><body><h1>Healthy</h1></body></html>',
        } as unknown as BrowserVisitResult
      },
    } as unknown as ScopedBrowser

    const { storage } = makeStore(t, 'kovo-perf-dead-')
    const setup = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    const res = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 2,
      origins,
      perOriginCap: 40,
      broker: fakeBroker,
      browser: fakeBrowser,
      grant: makeMultiOriginGrant(origins, 2),
      signal: AbortSignal.timeout(15_000),
    })

    const dead525Reqs = requestsByOrigin.get(dead525Origin) ?? []
    const deadTimeoutReqs = requestsByOrigin.get(deadTimeoutOrigin) ?? []
    const healthyReqs = requestsByOrigin.get(healthyOrigin) ?? []

    assert.ok(dead525Reqs.length > 0 && dead525Reqs.length <= 5, `expected 525 origin to halt in <= 5 reqs, got ${dead525Reqs.length}`)
    assert.ok(deadTimeoutReqs.length > 0 && deadTimeoutReqs.length <= 5, `expected timeout origin to halt in <= 5 reqs, got ${deadTimeoutReqs.length}`)
    assert.ok(healthyReqs.length > 5, `expected healthy sibling to run full recon, got ${healthyReqs.length} reqs`)

    // Playwright must ONLY run on the healthy HTML origin, never on dead/525 origins
    assert.deepEqual([...new Set(browserVisitedOrigins)], [healthyOrigin])

    // Structured skippedDeadHosts accounting & phase0.stage telemetry
    assert.equal(res.skippedDeadHosts?.length, 2)
    assert.ok(res.skippedDeadHosts?.some(h => h.origin === dead525Origin && h.reason === 'origin_down_http_525'))
    assert.ok(res.skippedDeadHosts?.some(h => h.origin === deadTimeoutOrigin && h.reason === 'transport_timeout'))

    const stageEvents = storage.eventsAfter(setup.runId, 0, 500).filter(ev => ev.kind === 'phase0.stage')
    const deadSkipEvents = stageEvents.filter(ev => (ev.detail as { skippedDeadHost?: boolean }).skippedDeadHost === true)
    assert.equal(deadSkipEvents.length, 2, 'expected phase0.stage dead-host skip events for both dead origins')

    // Healthy sibling endpoints were persisted normally
    const healthyEndpoints = storage.listEndpoints(setup.runId, { origin: healthyOrigin, limit: 100 })
    assert.ok(healthyEndpoints.some(ep => ep.pathTemplate === '/api/orders'))
  })

  test('Playwright crawlStateGraph runs in parallel up to browser semaphore cap and skips JSON-only hosts', async t => {
    const htmlOrigins = [
      'https://spa-1.example.test',
      'https://spa-2.example.test',
      'https://spa-3.example.test',
      'https://spa-4.example.test',
    ]
    const jsonOnlyOrigin = 'https://json-api.example.test'
    const origins = [...htmlOrigins, jsonOnlyOrigin]

    let seq = 0
    const fakeBroker = {
      async executeHttp(req: BrokerHttpRequest) {
        seq += 1
        if (req.origin === jsonOnlyOrigin) {
          if (req.pathAndQuery === '/') {
            return makeExchange(req, 200, 'application/json', JSON.stringify({ service: 'api', ok: true }), seq)
          }
          return makeExchange(req, 404, 'application/json', JSON.stringify({ error: 'not_found' }), seq)
        }
        if (req.pathAndQuery === '/') {
          return makeExchange(req, 200, 'text/html', '<html><body><div id="app">SPA</div></body></html>', seq)
        }
        return makeExchange(req, 404, 'text/plain', 'not found', seq)
      },
    } as unknown as RequestBroker

    let activeVisits = 0
    let peakConcurrentVisits = 0
    const visitedOrigins = new Set<string>()
    const fakeBrowser = {
      async visitPage(req: { origin: string; pathAndQuery: string }): Promise<BrowserVisitResult> {
        activeVisits += 1
        if (activeVisits > peakConcurrentVisits) peakConcurrentVisits = activeVisits
        visitedOrigins.add(req.origin)
        try {
          await delay(60)
          return {
            origin: req.origin,
            pathAndQuery: req.pathAndQuery,
            finalUrl: `${req.origin}${req.pathAndQuery}`,
            title: 'SPA',
            links: [],
            forms: [],
            xhrRequests: [],
            allRequests: [],
            exchanges: [],
            localStorageKeys: [],
            sessionStorageKeys: [],
            postMessageListeners: { count: 0, hasOnMessage: false },
            domSnippet: '<html><body><div id="app">SPA</div></body></html>',
          } as unknown as BrowserVisitResult
        } finally {
          activeVisits -= 1
        }
      },
    } as unknown as ScopedBrowser

    const { storage } = makeStore(t, 'kovo-perf-browser-')
    const setup = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 2,
      origins,
      perOriginCap: 40,
      broker: fakeBroker,
      browser: fakeBrowser,
      grant: makeMultiOriginGrant(origins, 2),
      signal: AbortSignal.timeout(15_000),
    })

    // JSON-only host had 0 HTML pages -> Playwright automatically skipped
    assert.equal(visitedOrigins.has(jsonOnlyOrigin), false, 'JSON-only origin with 0 HTML pages must skip Playwright')
    for (const origin of htmlOrigins) {
      assert.equal(visitedOrigins.has(origin), true, `HTML origin ${origin} should be crawled by Playwright`)
    }
    assert.ok(
      peakConcurrentVisits >= 2 && peakConcurrentVisits <= 3,
      `expected parallel Playwright visits bounded in [2, 3], got ${peakConcurrentVisits}`,
    )

    // Verify KOVO_PHASE0_BROWSER_CONCURRENCY=2 clamps peak browser concurrency to <= 2
    activeVisits = 0
    peakConcurrentVisits = 0
    visitedOrigins.clear()
    const { storage: storage2 } = makeStore(t, 'kovo-perf-browser-env-')
    const setup2 = await setupApprovedRun(storage2, { seeds: origins, tier: 2 })
    await withEnv({ KOVO_PHASE0_BROWSER_CONCURRENCY: '2' }, () => runPhase0Recon({
      storage: storage2,
      runId: setup2.runId,
      scopeRevision: setup2.run.scopeRevision,
      tier: 2,
      origins,
      perOriginCap: 40,
      broker: fakeBroker,
      browser: fakeBrowser,
      grant: makeMultiOriginGrant(origins, 2),
      signal: AbortSignal.timeout(15_000),
    }))
    assert.equal(visitedOrigins.has(jsonOnlyOrigin), false)
    assert.equal(peakConcurrentVisits, 2, `expected KOVO_PHASE0_BROWSER_CONCURRENCY=2 to cap peak visits at 2, got ${peakConcurrentVisits}`)
  })
})

describe('Option C Part 2: surface-engine bounded template probe timeoutMs', () => {
  test('runSafeTemplates forwards an explicit bounded timeoutMs <= 12_000 on every broker request', async () => {
    const origin = 'https://tpl-timeout.example.test'
    const observedTimeouts: Array<number | undefined> = []
    let seq = 0
    const spyBroker = {
      async executeHttp(req: BrokerHttpRequest) {
        seq += 1
        observedTimeouts.push(req.timeoutMs)
        return makeExchange(req, 404, 'text/plain', 'not found', seq)
      },
    } as unknown as RequestBroker

    assert.ok(surfaceProbeTimeoutMs > 0 && surfaceProbeTimeoutMs <= 12_000)

    const res = await runSafeTemplates(
      {
        origin,
        maxTemplates: 4,
        maxRequests: 8,
      },
      spyBroker,
      makeMultiOriginGrant([origin], 2),
      undefined,
      AbortSignal.timeout(10_000),
    )

    assert.ok(res.requestsSent >= 3, `expected calibration + template requests, got ${res.requestsSent}`)
    assert.equal(observedTimeouts.length, res.requestsSent)
    for (const timeoutMs of observedTimeouts) {
      assert.equal(typeof timeoutMs, 'number', 'every surface-engine probe must pass an explicit numeric timeoutMs')
      assert.ok(
        timeoutMs! > 0 && timeoutMs! <= 12_000,
        `expected bounded timeoutMs <= 12_000, got ${timeoutMs}`,
      )
    }
  })
})
