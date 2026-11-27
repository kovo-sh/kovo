/**
 * Kovo v6 — Phase-0 planning reads must page past the store's default 500-row page.
 *
 * Regression for the monorepo fixture finding: `runPhase0Recon` ingested the declared surface
 * losslessly, but the discovery planning phases (nav targets, GraphQL argument pass, XML surface,
 * sibling derivation, api-dependency inference, persona visibility) still read
 * `listEndpoints(runId, { origin })`, which the store caps at 500 rows. On a 6,000-endpoint app
 * those phases planned against a truncated surface: a GraphQL root, an XML feed, or a detail route
 * that ranked past the first page was invisible, and sibling derivation re-created methods that
 * already existed. Every planning read now goes through `listEndpointsPaged` and reports a
 * `phase0.read_paged` metric with `truncated: false`.
 *
 * Fixtures are synthetic; no benchmark challenge literals appear in engine-facing assertions.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Store } from '../src/server/store.ts'
import { listEndpointsPaged, runPhase0Recon } from '../src/server/phase0-recon.ts'
import { makeLabGrant, makeStore, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

const BASE = '/api/v7/things'
/** Filler surface large enough that the default 500-row page is a small fraction of the store. */
const FILLER_COUNT = 6000

const GRAPHQL_PATH = '/api/graphql'
const XML_PATH = '/api/feed.xml'
const DETAIL_PATH = `${BASE}/:id`

const INTROSPECTION = {
  data: {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: { name: 'Mutation' },
      types: [
        {
          name: 'Query', kind: 'OBJECT',
          fields: [{ name: 'node', args: [{ name: 'nodeId', type: { kind: 'SCALAR', name: 'ID', ofType: null } }] }],
        },
        {
          name: 'Mutation', kind: 'OBJECT',
          fields: [{ name: 'setFlag', args: [{ name: 'flagName', type: { kind: 'SCALAR', name: 'String', ofType: null } }] }],
        },
      ],
    },
  },
}

/**
 * Deterministic fixture: a SPA shell that links one JSON collection (so sibling derivation has a
 * real collection to derive from), a GraphQL root answering introspection, and an XML route that
 * only reveals its element schema through a parse error.
 */
async function startSurfaceFixture(t: TestContext) {
  return startHttpFixture(t, (req, _body, res) => {
    const url = (req.url ?? '/').split('?')[0] ?? '/'
    if (req.method === 'GET' && url === '/') {
      res.setHeader('Content-Type', 'text/html')
      res.end(`<html><body><nav><a href="${BASE}">things</a></nav></body></html>`)
      return
    }
    if (req.method === 'GET' && url === BASE) {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ items: [{ ext_id: 'TH-1' }, { ext_id: 'TH-2' }] }))
      return
    }
    if (req.method === 'OPTIONS' && url.startsWith(`${BASE}/`)) {
      res.statusCode = 204
      res.setHeader('Allow', 'GET, PATCH, DELETE, OPTIONS')
      res.setHeader('allow', 'GET, PATCH, DELETE, OPTIONS')
      res.end()
      return
    }
    if (req.method === 'POST' && url === GRAPHQL_PATH) {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify(INTROSPECTION))
      return
    }
    if (req.method === 'POST' && url === XML_PATH) {
      res.statusCode = 400
      res.setHeader('Content-Type', 'application/xml')
      res.end('<error><feedItem><entryId/></feedItem></error>')
      return
    }
    res.statusCode = 404
    res.setHeader('Content-Type', 'text/plain')
    res.end('not found')
  })
}

/**
 * Seed the full stored surface. Filler rows carry the higher risk band so the tail rows (GraphQL,
 * XML, the existing detail PATCH) rank past the store's default 500-row page.
 */
function seedSurface(
  storage: Store,
  runId: string,
  origin: string,
  options: { reverse?: boolean } = {},
): void {
  const filler = Array.from({ length: FILLER_COUNT }, (_unused, index) => index)
  const order = options.reverse ? filler.reverse() : filler
  storage.transaction(() => {
    for (const index of order) {
      storage.upsertEndpoint({
        runId,
        origin,
        method: 'GET',
        pathTemplate: `/api/v7/surface/s${index}`,
        source: 'spa_crawl',
        riskScore: 50 + (index % 50),
      })
    }
    // Tail rows: risk 0, so they land far past the 500-row default page.
    storage.upsertEndpoint({
      runId, origin, method: 'POST', pathTemplate: GRAPHQL_PATH, source: 'spa_crawl', riskScore: 0,
    })
    storage.upsertEndpoint({
      runId, origin, method: 'GET', pathTemplate: XML_PATH, source: 'spa_crawl', riskScore: 0,
    })
    storage.upsertEndpoint({
      runId, origin, method: 'PATCH', pathTemplate: DETAIL_PATH, source: 'spa_crawl', riskScore: 0,
    })
  })
}

type RunOutcome = {
  runId: string
  storage: Store
  result: Awaited<ReturnType<typeof runPhase0Recon>>
  metrics: Map<string, { considered: number; used: number; truncated: boolean }>
}

async function reconWithSurface(
  t: TestContext,
  label: string,
  options: { reverse?: boolean } = {},
): Promise<RunOutcome> {
  const fx = await startSurfaceFixture(t)
  const { storage } = makeStore(t, `kovo-v6-phase0-paging-${label}-`)
  const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 900 })
  seedSurface(storage, setup.runId, fx.origin, options)
  const result = await withEnv(
    { KOVO_ALLOW_LOCAL_LAB: '1', KOVO_RECON_SIBLINGS: '1' },
    () => runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 2,
      origins: [fx.origin],
      budgetRequests: 900,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeLabGrant(fx.origin, { tier: 2 }),
      signal: AbortSignal.timeout(60_000),
    }),
  )
  const metrics = new Map<string, { considered: number; used: number; truncated: boolean }>()
  for (const event of storage.eventsAfter(setup.runId, 0, 20_000)) {
    if (event.kind !== 'phase0.read_paged') continue
    const detail = event.detail as { phase: string; considered: number; used: number; truncated: boolean }
    metrics.set(detail.phase, detail)
  }
  return { runId: setup.runId, storage, result, metrics }
}

describe('v6 phase-0 planning reads: full-surface paging', () => {
  test('nav/GraphQL/XML/sibling phases see 6,000+ endpoints and report truncated=false', async (t: TestContext) => {
    const fx = await startSurfaceFixture(t)
    const { storage } = makeStore(t, 'kovo-v6-phase0-paging-assert-')
    const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 900 })
    seedSurface(storage, setup.runId, fx.origin)

    // The regression: a single unpaged read still truncates, the paged read does not.
    assert.equal(storage.listEndpoints(setup.runId, { origin: fx.origin }).length, 500,
      'unpaged read is the 500-row default the regression is about')
    assert.ok(
      listEndpointsPaged(storage, setup.runId, { origin: fx.origin }).length >= FILLER_COUNT,
      'paged read sees the whole seeded surface',
    )

    const result = await withEnv(
      { KOVO_ALLOW_LOCAL_LAB: '1', KOVO_RECON_SIBLINGS: '1' },
      () => runPhase0Recon({
        storage,
        runId: setup.runId,
        scopeRevision: setup.run.scopeRevision,
        tier: 2,
        origins: [fx.origin],
        budgetRequests: 900,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        grant: makeLabGrant(fx.origin, { tier: 2 }),
        signal: AbortSignal.timeout(60_000),
      }),
    )

    const pagedEvents = storage.eventsAfter(setup.runId, 0, 20_000)
      .filter(event => event.kind === 'phase0.read_paged')
      .map(event => event.detail as { phase: string; origin: string; considered: number; used: number; truncated: boolean; reads: number; pages: number })
    assert.ok(pagedEvents.length > 0, 'planning reads report paged-read metrics')

    const byPhase = new Map(pagedEvents.map(event => [event.phase, event]))
    for (const phase of ['detail_methods', 'nav_targets', 'api_dependencies', 'persona_visibility']) {
      const metric = byPhase.get(phase)
      assert.ok(metric, `${phase} reports a paged-read metric`)
      assert.equal(metric.truncated, false, `${phase} read is complete (truncated=false)`)
      assert.ok(metric.considered >= FILLER_COUNT, `${phase} considered the full surface (${metric.considered})`)
      assert.ok(metric.used <= metric.considered, `${phase} used <= considered`)
      assert.ok(metric.pages >= Math.ceil(metric.considered / 1000), `${phase} paged through the store`)
      assert.equal(metric.origin, fx.origin)
    }
    // The detail read is the one sibling derivation depends on: it must see the tail PATCH row.
    assert.ok((byPhase.get('detail_methods')?.used ?? 0) >= 1,
      'detail-method map is built from the full surface, past the default page')

    // GraphQL: the root ranks past the 500-row page; introspection arguments must still be learned.
    const gqlMetric = byPhase.get('graphql_args')
    assert.ok(gqlMetric, 'graphql argument phase reports a paged read')
    assert.equal(gqlMetric.truncated, false)
    assert.ok(gqlMetric.used >= 1, 'GraphQL root was found past the default page')
    const gqlEndpoints = listEndpointsPaged(storage, setup.runId, { origin: fx.origin })
      .filter(endpoint => endpoint.method === 'POST' && endpoint.pathTemplate === GRAPHQL_PATH)
    assert.equal(gqlEndpoints.length, 1, 'GraphQL root is persisted exactly once')
    const gqlParams = storage.listEndpointParams(setup.runId, gqlEndpoints[0]!.id).map(param => param.name).sort()
    assert.deepEqual(gqlParams, ['flagName', 'nodeId'], 'introspection arguments were learned from the tail-ranked root')

    // XML: same story for the feed route that reveals its element via a parse error.
    const xmlMetric = byPhase.get('xml_surface')
    assert.ok(xmlMetric, 'XML surface phase reports a paged read')
    assert.equal(xmlMetric.truncated, false)
    const xmlEndpoint = listEndpointsPaged(storage, setup.runId, { origin: fx.origin })
      .find(endpoint => endpoint.method === 'POST' && endpoint.pathTemplate === XML_PATH)
    assert.ok(xmlEndpoint, 'XML feed was found past the default page')
    const xmlParams = storage.listEndpointParams(setup.runId, xmlEndpoint.id)
    assert.ok(xmlParams.some(param => param.location === 'xml'), 'XML element schema was learned')

    // Sibling derivation: the pre-existing tail PATCH must suppress a duplicate sibling PATCH while
    // GET/DELETE siblings are still derived. With a truncated detail read the PATCH would be re-created.
    const detailRows = listEndpointsPaged(storage, setup.runId, { origin: fx.origin })
      .filter(endpoint => endpoint.pathTemplate === DETAIL_PATH)
    const methods = detailRows.map(endpoint => endpoint.method).sort()
    assert.deepEqual(methods, ['DELETE', 'GET', 'PATCH'],
      `sibling derivation deduped against the full surface (got ${methods.join(', ')})`)
    assert.equal(detailRows.filter(endpoint => endpoint.method === 'PATCH').length, 1,
      'the tail PATCH method is not duplicated by sibling derivation')
    assert.ok((result.siblingEndpoints ?? 0) >= 2, 'GET/DELETE siblings were derived from the collection')
    assert.equal(result.siblingDerivationSuppressed, undefined)

    // api-dependency inference reads the same full surface.
    const dependencies = storage.listApiDependencies(setup.runId)
    assert.ok(dependencies.some(edge => edge.resourceKey === 'id'),
      'api-dependency inference ran over the full surface')

    // The metric summary is also attached to the discovery event.
    const discovery = storage.eventsAfter(setup.runId, 0, 20_000)
      .find(event => event.kind === 'phase0.discovery')
    assert.ok(discovery, 'discovery event is emitted')
    const summary = (discovery.detail as { readPaged?: Array<{ phase: string; truncated: boolean }> }).readPaged
    assert.ok(Array.isArray(summary) && summary.length > 0, 'discovery event carries paged-read metrics')
    assert.ok(summary.every(entry => entry.truncated === false))
  })

  test('planning reads are deterministic across independently seeded stores', async (t: TestContext) => {
    const forward = await reconWithSurface(t, 'forward')
    const reverse = await reconWithSurface(t, 'reverse')

    assert.deepEqual([...forward.metrics.keys()].sort(), [...reverse.metrics.keys()].sort(),
      'both runs report the same planning phases')
    for (const [phase, metric] of forward.metrics) {
      const twin = reverse.metrics.get(phase)
      assert.ok(twin, `${phase} reported in both runs`)
      assert.deepEqual(
        { considered: metric.considered, used: metric.used, truncated: metric.truncated },
        { considered: twin.considered, used: twin.used, truncated: twin.truncated },
        `${phase} metrics are identical across store arrival order`,
      )
    }

    const detailMethods = (outcome: RunOutcome): string[] =>
      listEndpointsPaged(outcome.storage, outcome.runId)
        .filter(endpoint => endpoint.pathTemplate === DETAIL_PATH)
        .map(endpoint => endpoint.method)
        .sort()
    assert.deepEqual(detailMethods(forward), detailMethods(reverse), 'derived sibling method set is identical')

    const gqlParams = (outcome: RunOutcome): string[] => {
      const root = listEndpointsPaged(outcome.storage, outcome.runId)
        .find(endpoint => endpoint.pathTemplate === GRAPHQL_PATH && endpoint.method === 'POST')
      assert.ok(root, 'GraphQL root persisted in both runs')
      return outcome.storage.listEndpointParams(outcome.runId, root.id).map(param => param.name).sort()
    }
    assert.deepEqual(gqlParams(forward), gqlParams(reverse), 'GraphQL argument set is identical')

    assert.deepEqual(
      [...forward.result.dynamicWordlist.paths].sort(),
      [...reverse.result.dynamicWordlist.paths].sort(),
      'discovered path wordlist is identical',
    )
    assert.deepEqual(
      [...forward.result.dynamicWordlist.params].sort(),
      [...reverse.result.dynamicWordlist.params].sort(),
      'discovered parameter wordlist is identical',
    )
    assert.equal(forward.result.siblingEndpoints, reverse.result.siblingEndpoints)
    assert.equal(forward.result.endpointsDiscovered, reverse.result.endpointsDiscovered)
    assert.equal(forward.result.requestsUsed, reverse.result.requestsUsed)
  })
})
