/**
 * Guardian v7 — `crawlStateGraph` route lookups must page past the store's default 500-row view.
 *
 * Regression for the state-graph crawl finding: `runPhase0Recon` planning reads were paged, but
 * the crawl still resolved intercepted-query, Next-Action and persona-union routes through
 * `listEndpoints(runId, { origin })`, which the store caps at 500 rows. On a 6,000-route surface a
 * tail-ranked route that an exchange or a privileged persona touched was invisible, so its query
 * parameters, Next-Action header schema and privileged auth/risk tagging were silently dropped.
 * Every crawl lookup now resolves through one `listEndpointsPaged` index in the store's stable
 * (risk, coverage, id) order and reports a `phase0.crawl_paged` metric with `truncated: false`.
 *
 * Fixtures are synthetic; no benchmark challenge literals appear in engine-facing assertions.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import type { BrokerExchangeResult } from '../src/server/broker.ts'
import { crawlStateGraph, listEndpointsPaged } from '../src/server/phase0-recon.ts'
import type { PagedReadMetric } from '../src/server/phase0-recon.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import type { Store } from '../src/server/store.ts'
import { makeLabGrant, makeStore, setupApprovedRun, withEnv } from './v4-tier-helpers.ts'

const ORIGIN = 'https://crawl.fixture.test'
const FILLER_COUNT = 6000
/** Tail route: risk 0, so it ranks far past the store's default 500-row page. */
const TAIL_PATH = '/api/v7/crawl/tail'
/** A second tail route reached only through a Next-Action header. */
const ACTION_PATH = '/api/v7/crawl/actions'

type CrawlSurface = {
  runId: string
  storage: Store
  result: Awaited<ReturnType<typeof crawlStateGraph>>
  metric: PagedReadMetric
}

/** Seed the full stored surface; `reverse` flips insert arrival order for the determinism check. */
function seedSurface(
  storage: Store,
  runId: string,
  options: { reverse?: boolean } = {},
): void {
  const indexes = Array.from({ length: FILLER_COUNT }, (_unused, index) => index)
  if (options.reverse) indexes.reverse()
  storage.transaction(() => {
    for (const index of indexes) {
      storage.upsertEndpoint({
        runId,
        origin: ORIGIN,
        method: 'GET',
        pathTemplate: `/api/v7/crawl/s${index}`,
        source: 'spa_crawl',
        riskScore: 50 + (index % 50),
      })
    }
    storage.upsertEndpoint({
      runId, origin: ORIGIN, method: 'POST', pathTemplate: TAIL_PATH, source: 'spa_crawl', riskScore: 0,
    })
    storage.upsertEndpoint({
      runId, origin: ORIGIN, method: 'POST', pathTemplate: ACTION_PATH, source: 'spa_crawl', riskScore: 0,
    })
  })
}

function exchange(
  method: string,
  pathAndQuery: string,
  reqHeaders: Record<string, string> = {},
): BrokerExchangeResult {
  return {
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method,
    pathAndQuery,
    personaHandle: null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders,
    respHeaders: {},
    setCookies: [],
    bodyPreview: '{}',
    body: '{}',
    bodySha256: '',
    bodyBytes: 2,
    bodyTruncated: false,
    durationMs: 1,
  } as unknown as BrokerExchangeResult
}

/** Minimal scoped-browser stub: one page whose only discovery output is broker exchanges. */
function makeCrawlBrowser(exchanges: BrokerExchangeResult[]): ScopedBrowser {
  const visit = {
    origin: ORIGIN,
    finalUrl: `${ORIGIN}/`,
    title: 'fixture',
    status: 200,
    domSnippet: '<html><body><div id="app">Loading…</div></body></html>',
    links: [],
    forms: [],
    xhrRequests: [],
    allRequests: [],
    blockedOrigins: [],
    consoleMessages: [],
    postMessageListeners: {
      count: 0,
      hasOnMessage: false,
      handlers: [],
      observedEvents: 0,
      canaryHandledWithoutOriginCheck: false,
    },
    cookieNames: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    canaryCheck: { token: null, triggered: false, detail: null },
    domSinkTraces: [],
    exchangeIds: [],
    exchanges,
    durationMs: 1,
  }
  return { visitPage: async () => visit } as unknown as ScopedBrowser
}

async function crawlSurface(
  t: TestContext,
  label: string,
  options: { reverse?: boolean } = {},
): Promise<CrawlSurface> {
  const { storage } = makeStore(t, `guardian-v7-crawl-paging-${label}-`)
  const setup = await setupApprovedRun(storage, { seeds: [ORIGIN], budgetRequests: 900 })
  seedSurface(storage, setup.runId, options)
  const result = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
    crawlStateGraph({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      origin: ORIGIN,
      maxPages: 2,
      maxDepth: 0,
      browser: makeCrawlBrowser([
        // Intercepted query string on a tail-ranked route: only a full-surface lookup finds it.
        exchange('POST', `${TAIL_PATH}?filter=active&sort=desc`),
        // Next-Action call on another tail-ranked route.
        exchange('POST', ACTION_PATH, { 'next-action': 'act-v7-fixture' }),
      ]),
      grant: makeLabGrant(ORIGIN),
      signal: AbortSignal.timeout(60_000),
    }),
  )
  const events = storage.eventsAfter(setup.runId, 0, 20_000)
    .filter(event => event.kind === 'phase0.crawl_paged')
  assert.equal(events.length, 1, 'the crawl reports one paged-read metric for its origin')
  const metric = events[0]!.detail as PagedReadMetric
  return { runId: setup.runId, storage, result, metric }
}

describe('v7 crawl state-graph: full-surface paged lookups', () => {
  test('6,000-route crawl sees the whole surface and resolves tail-ranked routes', async (t: TestContext) => {
    const { runId, storage, result, metric } = await crawlSurface(t, 'surface')

    // The regression: a default read truncates, the paged read (and the crawl index) do not.
    assert.equal(storage.listEndpoints(runId, { origin: ORIGIN }).length, 500,
      'the unpaged read is the 500-row default the regression is about')
    const full = listEndpointsPaged(storage, runId, { origin: ORIGIN })
    assert.ok(full.length >= FILLER_COUNT, `paged read sees the whole surface (${full.length})`)
    for (const index of [0, 1, 2999, FILLER_COUNT - 1]) {
      assert.ok(full.some(endpoint => endpoint.pathTemplate === `/api/v7/crawl/s${index}`),
        `filler route s${index} survives the crawl`)
    }

    // Both call sites resolved their tail-ranked route from the full paged index.
    const tail = full.find(endpoint => endpoint.method === 'POST' && endpoint.pathTemplate === TAIL_PATH)
    assert.ok(tail, 'tail-ranked exchanged route is stored')
    const tailParams = storage.listEndpointParams(runId)
      .filter(param => param.endpointId === tail.id)
      .map(param => `${param.name}@${param.location}`)
      .sort()
    assert.deepEqual(tailParams, ['filter@query', 'sort@query'],
      'intercepted query params were attached to the tail-ranked route')

    const action = full.find(endpoint => endpoint.method === 'POST' && endpoint.pathTemplate === ACTION_PATH)
    assert.ok(action, 'Next-Action route is stored')
    const actionParams = storage.listEndpointParams(runId)
      .filter(param => param.endpointId === action.id)
      .map(param => `${param.name}@${param.location}`)
    assert.ok(actionParams.includes('Next-Action@header'),
      'Next-Action header schema was attached past the default page')

    // The metric accounts for the paged surface, not the truncated view.
    assert.ok(metric.considered >= FILLER_COUNT, `metric considered the full surface (${metric.considered})`)
    assert.equal(metric.truncated, false, 'crawl read is complete (truncated=false)')
    assert.ok(metric.reads >= 1)
    assert.ok(metric.pages >= Math.ceil(FILLER_COUNT / 1000), 'crawl paged through the store')
    assert.equal(metric.origin, ORIGIN)
    assert.ok(metric.used >= 2, `both tail lookups counted as resolved (${metric.used})`)
    assert.ok(metric.used <= metric.considered, 'resolved routes never exceed the rows read')
    assert.deepEqual(result.crawlPaged, metric, 'crawl result carries the same paged-read metric')
  })

  test('crawl lookups are deterministic across arrival orders', async (t: TestContext) => {
    const forward = await crawlSurface(t, 'forward')
    const reverse = await crawlSurface(t, 'reverse', { reverse: true })

    assert.equal(forward.metric.considered, reverse.metric.considered,
      'both arrival orders page the same number of rows')
    assert.equal(forward.metric.used, reverse.metric.used,
      'both arrival orders resolve the same number of routes')
    assert.equal(forward.metric.truncated, reverse.metric.truncated)

    const paramsFor = (surface: CrawlSurface, pathTemplate: string): string[] => {
      const endpoint = listEndpointsPaged(surface.storage, surface.runId, { origin: ORIGIN })
        .find(row => row.method === 'POST' && row.pathTemplate === pathTemplate)
      assert.ok(endpoint, `${pathTemplate} is stored`)
      return surface.storage.listEndpointParams(surface.runId)
        .filter(param => param.endpointId === endpoint.id)
        .map(param => `${param.name}@${param.location}`)
        .sort()
    }
    assert.deepEqual(paramsFor(forward, TAIL_PATH), paramsFor(reverse, TAIL_PATH))
    assert.deepEqual(paramsFor(forward, ACTION_PATH), paramsFor(reverse, ACTION_PATH))
    assert.deepEqual(paramsFor(forward, TAIL_PATH), ['filter@query', 'sort@query'])
  })

  test('no default-500 truncation: routes ranked past page one stay visible', async (t: TestContext) => {
    const { runId, storage, metric } = await crawlSurface(t, 'no-truncation')

    const unpaged = storage.listEndpoints(runId, { origin: ORIGIN })
    assert.equal(unpaged.length, 500)
    const unpagedKeys = new Set(unpaged.map(endpoint => `${endpoint.method} ${endpoint.pathTemplate}`))
    assert.ok(!unpagedKeys.has(`POST ${TAIL_PATH}`), 'the default page cannot see the tail route')
    assert.ok(!unpagedKeys.has(`POST ${ACTION_PATH}`), 'the default page cannot see the action route')

    const full = listEndpointsPaged(storage, runId, { origin: ORIGIN })
    const fullKeys = new Set(full.map(endpoint => `${endpoint.method} ${endpoint.pathTemplate}`))
    assert.ok(fullKeys.has(`POST ${TAIL_PATH}`))
    assert.ok(fullKeys.has(`POST ${ACTION_PATH}`))
    assert.equal(full.length, fullKeys.size, 'the paged read dedupes duplicate route keys')
    assert.ok(metric.considered >= FILLER_COUNT + 2)
    assert.ok(metric.considered <= full.length,
      'the read snapshot never exceeds the surface visible at the end of the crawl')
  })
})
