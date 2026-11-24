/**
 * v7 parameter discovery — structural, provenance-aware params for randomized surfaces.
 *
 * Layer-2 held-out surfaces may randomize a search/filter parameter name so it never appears
 * verbatim on the wire. Recon still has evidence the crawler already collected (URL query keys,
 * form fields, client-bundle literals, response field names, same-origin redirects). Those names
 * are attached with a provenance: `observed` (wire/declaration/verified differential) or `inferred`
 * (bundle literal, response field, route vocabulary). An inferred name only lets the floor form a
 * hypothesis; it is never enough to confirm one.
 *
 * Fixtures are synthetic; no benchmark route or challenge literal appears here.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { inferEndpointParams } from '../src/server/deterministic-engine.ts'
import {
  compareDiscoveredParams,
  isUsefulParamForLocation,
  listEndpointsPaged,
  paramDiscoveryConfidence,
  paramProvenanceOfSource,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { Store } from '../src/server/store.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import { makeLabGrant, makeStore, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

const BASE = '/api/v7'

async function withLocalLab<T>(fn: () => Promise<T>): Promise<T> {
  return withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, fn)
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(body))
}

/** Root shell: a bundle plus links, in either arrival order. */
function shell(options: { links: string[]; reverse?: boolean }): string {
  const links = options.reverse ? [...options.links].reverse() : options.links
  return `<html><body><script src="/app.js"></script>${links
    .map(href => `<a href="${href}">link</a>`)
    .join('')}</body></html>`
}

async function runRecon(
  t: TestContext,
  label: string,
  handler: (req: IncomingMessage, res: ServerResponse) => boolean,
): Promise<{ storage: Store; runId: string; origin: string; result: Awaited<ReturnType<typeof runPhase0Recon>> }> {
  const fx = await startHttpFixture(t, (req, _body, res) => {
    if (handler(req, res)) return
    res.statusCode = 404
    res.setHeader('Content-Type', 'text/plain')
    res.end('not found')
  })
  const { storage } = makeStore(t, `guardian-v7-param-discovery-${label}-`)
  const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 900 })
  const result = await withLocalLab(() => runPhase0Recon({
    storage,
    runId: setup.runId,
    scopeRevision: setup.run.scopeRevision,
    tier: 2,
    origins: [fx.origin],
    budgetRequests: 900,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant: makeLabGrant(fx.origin, { tier: 2 }),
    signal: AbortSignal.timeout(60_000),
  }))
  return { storage, runId: setup.runId, origin: fx.origin, result }
}

describe('v7 parameter discovery: provenance and evidence', () => {
  test('noise filter keeps dotted JSON body fields and drops JS/UI literals', () => {
    // A JSON body path like `filter.name` is a real injectable field; a query key never has a dot.
    assert.equal(isUsefulParamForLocation('filter.name', 'json'), true)
    assert.equal(isUsefulParamForLocation('filter.name', 'query'), false)
    for (const noise of ['undefined', 'constructor', 'addEventListener', 'textContent', 'innerHTML', '$props']) {
      assert.equal(isUsefulParamForLocation(noise, 'json'), false, `${noise} is JS/UI noise`)
    }
  })

  test('bundle literal is inferred (still lets the floor form a hypothesis); link ?q= is observed; unrelated route invents nothing', async (t: TestContext) => {
    const { storage, runId } = await runRecon(t, 'bundle-link', (req, res) => {
      const url = (req.url ?? '/').split('?')[0] ?? '/'
      if (req.method === 'GET' && url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end(shell({ links: [`${BASE}/items?q=alpha`, `${BASE}/health`] }))
        return true
      }
      if (req.method === 'GET' && url === '/app.js') {
        // Client bundle downloads the collection with a free-text filter. The name exists only in
        // shipped JS; the crawler never sees it on the wire before it probes.
        res.setHeader('Content-Type', 'text/javascript')
        res.end(`export async function load(){ return fetch("${BASE}/bundle-items?flavor=" + encodeURIComponent("x")).then(r=>r.json()) }`)
        return true
      }
      if (req.method === 'GET' && url === `${BASE}/bundle-items`) {
        const flavor = new URL(req.url ?? '/', 'http://x').searchParams.get('flavor') ?? ''
        // The bundle-supplied name is real: a benign value narrows the collection.
        const items = flavor ? [] : [{ id: '1' }]
        json(res, 200, { items })
        return true
      }
      if (req.method === 'GET' && url === `${BASE}/items`) {
        json(res, 200, { query: String(new URL(req.url ?? '/', 'http://x').searchParams.get('q') ?? ''), items: [] })
        return true
      }
      if (req.method === 'GET' && url === `${BASE}/health`) {
        json(res, 200, { status: 'ok' })
        return true
      }
      return false
    })

    const endpoints = listEndpointsPaged(storage, runId)
    const bundle = endpoints.find(ep => ep.method === 'GET' && ep.pathTemplate === `${BASE}/bundle-items`)
    assert.ok(bundle, 'bundle-referenced route was discovered')
    const bundleParam = storage.listEndpointParams(runId, bundle.id).find(param => param.name === 'flavor')
    assert.ok(bundleParam, 'bundle literal produced the candidate parameter')
    assert.equal(paramProvenanceOfSource(bundleParam.source), 'inferred_bundle', 'bundle-derived names are inferred_bundle')
    assert.match(bundleParam.source, /sensitive/, 'the paired sensitivity check kept a live bundle parameter')
    assert.ok(paramDiscoveryConfidence(bundleParam.source) >= 80, 'sensitivity-checked bundle evidence has high confidence')

    // The inferred name is enough input for the floor to plan a hypothesis against the route.
    const engineEndpoint = {
      id: bundle.id, origin: bundle.origin, method: bundle.method, pathTemplate: bundle.pathTemplate,
      params: storage.listEndpointParams(runId, bundle.id).map(param => ({
        name: param.name, location: param.location, isObjectId: param.isObjectId, isCsrf: param.isCsrf,
      })),
      riskScore: bundle.riskScore, source: bundle.source,
    }
    assert.ok(inferEndpointParams(engineEndpoint as never).some(param => param.name === 'flavor'),
      'inferred bundle parameter is offered to the hypothesis planner')

    const listed = endpoints.find(ep => ep.method === 'GET' && ep.pathTemplate === `${BASE}/items`)
    assert.ok(listed, 'link-referenced route was discovered')
    const linkParam = storage.listEndpointParams(runId, listed.id).find(param => param.name === 'q')
    assert.ok(linkParam, 'crawled link query key was recorded')
    assert.equal(paramProvenanceOfSource(linkParam.source), 'observed', 'link ?key= is observed')

    const health = endpoints.find(ep => ep.method === 'GET' && ep.pathTemplate === `${BASE}/health`)
    assert.ok(health, 'health route was discovered')
    assert.deepEqual(storage.listEndpointParams(runId, health.id).map(param => param.name), [],
      'no parameter is invented when nothing supports it')
  })

  test('randomized search parameter is discovered from a response field and kept as sensitivity-checked inferred_html', async (t: TestContext) => {
    const rows = [{ id: '1', title: 'alpha' }, { id: '2', title: 'beta' }]
    const { storage, runId, result } = await runRecon(t, 'active-diff', (req, res) => {
      const parsed = new URL(req.url ?? '/', 'http://x')
      const url = parsed.pathname
      if (req.method === 'GET' && url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end(shell({ links: [`${BASE}/search`] }))
        return true
      }
      if (req.method === 'GET' && url === `${BASE}/search`) {
        const term = parsed.searchParams.get('query') ?? ''
        // A randomized name: only `query` reads; every other candidate is ignored.
        const filtered = term ? rows.filter(row => row.title.includes(term)) : rows
        json(res, 200, { query: term, items: filtered })
        return true
      }
      return false
    })

    const search = listEndpointsPaged(storage, runId).find(ep => ep.method === 'GET' && ep.pathTemplate === `${BASE}/search`)
    assert.ok(search, 'search route was discovered')
    const param = storage.listEndpointParams(runId, search.id).find(entry => entry.name === 'query')
    assert.ok(param, 'response field `query` plus a positive differential discovered the real name')
    assert.equal(paramProvenanceOfSource(param.source), 'inferred_html', 'document-derived name stays inferred_html')
    assert.match(param.source, /sensitive/, 'sensitivity passed is recorded in the provenance tag')
    assert.ok(paramDiscoveryConfidence(param.source) >= 80, 'sensitivity-checked inference has high confidence')
    assert.ok(search.riskScore >= 70, `verified reading parameter raises probe priority (risk ${search.riskScore})`)

    const event = storage.eventsAfter(runId, 0, 20_000).find(entry => entry.kind === 'phase0.param_discovery')
    assert.ok(event, 'one param-discovery metric event is emitted')
    const detail = event.detail as {
      endpoints: Array<{ endpoint: string; observed: number; inferred: number; sensitivityPassed: number; byProvenance: Record<string, number>; bySource: Record<string, number> }>
      totals: { observed: number; inferred: number; sensitivityPassed: number; byProvenance: Record<string, number> }
      sensitivity: { checked: number; passed: number; dropped: number }
    }
    assert.ok((detail.totals.byProvenance.inferred_html ?? 0) >= 1, 'metrics count inferred_html params')
    assert.ok(detail.sensitivity.passed >= 1, 'metrics count sensitivity-checked inferences')
    const row = detail.endpoints.find(entry => entry.endpoint === `GET ${BASE}/search`)
    assert.ok(row, 'metrics are recorded per endpoint')
    assert.ok(row.inferred >= 1 && (row.byProvenance.inferred_html ?? 0) >= 1)
    assert.ok((row.bySource['inferred_html:sensitive'] ?? 0) >= 1)
    assert.equal(detail.totals.observed, detail.totals.byProvenance.observed, 'provenance totals add up')
    assert.ok(result.paramDiscovery, 'recon result exposes the discovery summary')
  })

  test('determinism: shuffled crawl arrival order yields the same ordered parameter set', async (t: TestContext) => {
    const links = [`${BASE}/search?q=a`, `${BASE}/search?term=b`, `${BASE}/items?filter=c`]
    const makeHandler = (reverse: boolean) => (req: IncomingMessage, res: ServerResponse): boolean => {
      const url = (req.url ?? '/').split('?')[0] ?? '/'
      if (req.method === 'GET' && url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end(shell({ links, reverse }))
        return true
      }
      if (req.method === 'GET' && (url === `${BASE}/search` || url === `${BASE}/items`)) {
        json(res, 200, { items: [] })
        return true
      }
      return false
    }
    const first = await runRecon(t, 'determinism-forward', makeHandler(false))
    const second = await runRecon(t, 'determinism-reverse', makeHandler(true))
    const snapshot = (outcome: Awaited<ReturnType<typeof runRecon>>) => {
      const endpoints = listEndpointsPaged(outcome.storage, outcome.runId)
      const rows: Array<{ endpoint: string; name: string; location: string; source: string }> = []
      for (const endpoint of endpoints) {
        for (const param of outcome.storage.listEndpointParams(outcome.runId, endpoint.id)) {
          rows.push({
            endpoint: `${endpoint.method} ${endpoint.pathTemplate}`,
            name: param.name,
            location: param.location,
            source: param.source,
          })
        }
      }
      return rows
        .sort((a, b) => a.endpoint.localeCompare(b.endpoint) || compareDiscoveredParams(
          { name: a.name, location: a.location as never, source: a.source },
          { name: b.name, location: b.location as never, source: b.source },
        ))
        .map(row => `${row.endpoint}|${row.name}|${row.location}|${paramProvenanceOfSource(row.source)}`)
    }
    assert.deepEqual(snapshot(second), snapshot(first), 'identical crawl input yields identical ordered params')
  })
})

// ---------------------------------------------------------------------------------------------
// Precision: a wrong inferred name must stay silent on a hardened route
// ---------------------------------------------------------------------------------------------

async function hardenedFixture(t: TestContext) {
  const server = createServer((req, res) => {
    const parsed = new URL(req.url ?? '/', 'http://x')
    if (req.method === 'GET' && parsed.pathname === '/search') {
      const q = parsed.searchParams.get('q') ?? ''
      // Parameterized lookup: the real name reads, the injected inferred name is ignored.
      const rows = ['alpha', 'beta'].filter(name => name.includes(q))
      json(res, 200, { query: q, items: rows.map(name => ({ name })) })
      return
    }
    res.statusCode = 404
    res.end('not found')
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  return `http://127.0.0.1:${address.port}`
}

function grant(origin: string): Grant {
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 30,
    allowLocalLab: true,
    canRead: (candidate: string) => candidate === origin,
    audit: () => {},
  }
}

describe('v7 parameter discovery: precision guard', () => {
  test('wrong inferred parameter on a hardened route yields no confirmation', async (t: TestContext) => {
    const origin = await hardenedFixture(t)
    await withLocalLab(async () => {
      const broker = new RequestBroker({ rejectUnauthorized: false })
      const res = await probeDifferential({
        probeClass: 'sqli_boolean',
        origin,
        pathAndQuery: '/search',
        method: 'GET',
        param: 'query',
        paramLocation: 'query',
        baselineValue: 'alpha',
      }, broker, grant(origin), undefined, AbortSignal.timeout(15_000))
      assert.notEqual(res.verdict, 'signal', 'an inferred-but-wrong name cannot create a finding')
      const hit = res.anomalies.find(anomaly => anomaly.type === 'boolean_differential')
      assert.equal(hit, undefined, 'no boolean differential for an ignored parameter')
    })
  })
})
