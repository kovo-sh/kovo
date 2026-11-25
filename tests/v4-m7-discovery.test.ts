/**
 * M7 discovery stream: generic parameter extraction (OpenAPI / HTML / JS / XML shape probes)
 * and parameter/route-semantics -> probe-class hypothesis mapping.
 *
 * These tests use synthetic fixtures only; no benchmark challenge identifiers or endpoint
 * literals from any manifest appear in engine-facing assertions.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { Store } from '../src/server/store.ts'
import {
  extractHtmlLinksAndScripts,
  extractXmlHintTags,
  harvestJsRequestParams,
  parseOpenApiDoc,
} from '../src/server/phase0-recon.ts'
import {
  formHypotheses,
  profileCaps,
  hasPathPlaceholder,
  fillPlaceholders,
} from '../scripts/benchmark-probes.ts'
import type { DiscoveredEndpoint } from '../scripts/benchmark-probes.ts'
import { makeTempDir } from './v4-tier-helpers.ts'

function makeRunStore(t: TestContext): { storage: Store; runId: string; origin: string; scopeRevision: number } {
  const dir = makeTempDir(t, 'kovo-m7-discovery-')
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
  })
  const origin = 'https://app.fixture.test'
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'M7 discovery fixtures', environment: 'local-lab', seeds: [origin],
  } as unknown as Parameters<Store['createProject']>[0])
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'M7 discovery unit fixtures', sourceMode: 'prepared',
    capabilityTier: 3, budgetUsd: 1, budgetRequests: 500, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 20,
  } as unknown as Parameters<Store['createRun']>[0])
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const assetIds = storage.runDetail(runId).run.candidates.map(c => c.id)
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds, consent: true } as unknown as Parameters<Store['command']>[0])
  return { storage, runId, origin, scopeRevision: storage.runDetail(runId).run.scopeRevision }
}

function param(name: string, location: string): DiscoveredEndpoint['params'][number] {
  return { name, location, isObjectId: false, isCsrf: false }
}

describe('M7 discovery: HTML form/control/link extraction', () => {
  test('records link query parameters, form enctype, and standalone controls', () => {
    const html = `<!doctype html><html><body>
      <a href="/greet?name=guest&lang=en">Greeting</a>
      <a href="/assets/app.css">asset</a>
      <form method="POST" action="/account/search" enctype="multipart/form-data">
        <input type="hidden" name="_csrf" value="tok">
        <input type="text" name="q" value="invoices">
        <select name="scope"><option>all</option></select>
      </form>
      <section>
        <input id="display-name" name="display-name" type="text">
        <button id="continue" type="button">Continue</button>
      </section>
    </body></html>`
    const parsed = extractHtmlLinksAndScripts(html, 'https://app.fixture.test')
    assert.deepEqual(parsed.links, ['/greet?name=guest&lang=en'])
    assert.equal(parsed.forms.length, 1)
    assert.equal(parsed.forms[0].action, '/account/search')
    assert.equal(parsed.forms[0].method, 'POST')
    assert.equal(parsed.forms[0].enctype, 'multipart/form-data')
    assert.deepEqual(parsed.forms[0].inputs, ['_csrf', 'q', 'scope'])
    const names = parsed.inputs.map(i => i.name)
    assert.ok(names.includes('display-name'), 'standalone named control must be recorded')
    assert.ok(names.includes('q'), 'in-form controls must also appear in the control inventory')
    const display = parsed.inputs.find(i => i.name === 'display-name')
    assert.equal(display?.id, 'display-name')
    assert.equal(display?.type, 'text')
  })
})

describe('M7 discovery: JavaScript request-literal scanner', () => {
  const bundle = `
    async function search(term) {
      return fetch('/api/search', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ term: term }) })
    }
    async function postComment(text) {
      return fetch('/api/comments', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ body: text }) })
    }
    async function xmlLookup(n) {
      return fetch('/api/xml/lookup', { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: '<lookup><name>' + n + '</name></lookup>' })
    }
    axios.post('/api/reports', { title: title, filter: filter })
    const xhr = new XMLHttpRequest(); xhr.open('POST', '/api/xhr'); xhr.send(JSON.stringify({ alpha: 1, beta: 2 }))
    fetch('/api/items?page=2&limit=10')
  `
  test('derives HTTP methods and JSON/form/XML/query parameter names', () => {
    const specs = harvestJsRequestParams(bundle)
    const byPath = new Map(specs.map(s => [s.path, s]))
    assert.equal(byPath.get('/api/search')?.method, 'POST')
    assert.deepEqual(byPath.get('/api/search')?.params, [{ name: 'term', location: 'json' }])
    assert.deepEqual(byPath.get('/api/comments')?.params, [{ name: 'body', location: 'json' }])
    assert.equal(byPath.get('/api/xml/lookup')?.method, 'POST')
    assert.deepEqual(byPath.get('/api/xml/lookup')?.params, [{ name: 'name', location: 'xml' }])
    assert.deepEqual(byPath.get('/api/reports')?.params.map(p => p.name).sort(), ['filter', 'title'])
    assert.deepEqual(byPath.get('/api/xhr')?.params.map(p => p.name).sort(), ['alpha', 'beta'])
    assert.deepEqual(byPath.get('/api/items')?.params.map(p => p.name).sort(), ['limit', 'page'])
    for (const spec of specs) assert.ok(spec.path.startsWith('/'), 'only same-origin paths are emitted')
  })

  test('does not leak an XML content-type from a later call into unrelated requests', () => {
    const specs = harvestJsRequestParams(bundle)
    const jsonSpecs = specs.filter(s => s.path === '/api/search' || s.path === '/api/comments')
    for (const spec of jsonSpecs) {
      assert.ok(spec.params.every(p => p.location !== 'xml'), `${spec.path} must not inherit XML element params`)
    }
  })
})

describe('M7 discovery: OpenAPI parameter extraction', () => {
  test('extracts query/header params and JSON, XML and urlencoded body properties', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const doc = {
      openapi: '3.0.3',
      paths: {
        '/api/search': {
          post: {
            parameters: [
              { name: 'trace', in: 'header', schema: { type: 'string' } },
              { name: 'ref', in: 'query', schema: { type: 'string' } },
            ],
            requestBody: {
              content: {
                'application/json': { schema: { properties: { term: { type: 'string' }, filter: { type: 'string' } } } },
                'application/xml': { schema: { properties: { criteria: { type: 'string', xml: { name: 'query' } } } } },
                'application/x-www-form-urlencoded': { schema: { properties: { page: { type: 'integer' } } } },
              },
            },
          },
        },
        '/api/legacy': {
          post: {
            parameters: [{ in: 'body', name: 'payload', schema: { properties: { title: { type: 'string' } } } }],
          },
        },
      },
    }
    const dynamicPaths = new Set<string>()
    const dynamicParams = new Set<string>()
    const res = parseOpenApiDoc(JSON.stringify(doc), origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)
    assert.equal(res.endpoints, 2)
    assert.ok(dynamicPaths.has('/api/search') && dynamicPaths.has('/api/legacy'))

    const endpoints = storage.listEndpoints(runId, { origin })
    const search = endpoints.find(e => e.pathTemplate === '/api/search' && e.method === 'POST')
    assert.ok(search)
    const params = storage.listEndpointParams(runId).filter(p => p.endpointId === search.id)
    const seen = params.map(p => `${p.name}@${p.location}`).sort()
    assert.deepEqual(seen, [
      'filter@json', 'page@form', 'query@xml', 'ref@query', 'term@json', 'trace@header',
    ].sort())
    const legacy = endpoints.find(e => e.pathTemplate === '/api/legacy')
    assert.ok(legacy)
    assert.ok(storage.listEndpointParams(runId).some(p => p.endpointId === legacy.id && p.name === 'title' && p.location === 'json'))
  })
})

describe('M7 discovery: XML shape inference', () => {
  test('learns element names from a parse-error hint and ignores wrapper tags', () => {
    const tags = extractXmlHintTags('<?xml version="1.0"?><error>expected &lt;lookup&gt;&lt;name&gt; element</error>')
    assert.equal(tags[tags.length - 1], 'name')
    assert.ok(!tags.includes('error'))
    assert.deepEqual(extractXmlHintTags('<error>missing parameter</error>'), [])
  })
})

describe('M7 hypothesis mapping: route/parameter semantics', () => {
  const endpoints: DiscoveredEndpoint[] = [
    { method: 'GET', path: '/greet', source: 'surface_probe', params: [param('name', 'query')] },
    { method: 'GET', path: '/wizard', source: 'surface_probe', params: [param('display-name', 'query')] },
    { method: 'POST', path: '/api/xml/lookup', source: 'js_ast', params: [param('name', 'xml')] },
    { method: 'POST', path: '/api/xml/import', source: 'js_ast', params: [] },
    { method: 'GET', path: '/api/comments', source: 'openapi', params: [] },
    { method: 'POST', path: '/api/comments', source: 'openapi', params: [param('body', 'json')] },
    { method: 'GET', path: '/comments', source: 'surface_probe', params: [] },
    { method: 'GET', path: '/cache/banner', source: 'surface_probe', params: [] },
    { method: 'GET', path: '/account/summary', source: 'surface_probe', params: [] },
    { method: 'GET', path: '/api/profile', source: 'openapi', params: [] },
    {
      method: 'GET', path: '/oauth/authorize', source: 'surface_probe',
      params: [param('client_id', 'query'), param('redirect_uri', 'query'), param('state', 'query'), param('code_challenge', 'query')],
    },
    { method: 'POST', path: '/graphql', source: 'graphql', params: [param('category', 'graphql_var')] },
    { method: 'GET', path: '/api/track', source: 'openapi', params: [param('X-Tracking-Id', 'header')] },
  ]
  const caps = profileCaps('v4-full')
  const plan = formHypotheses(endpoints, caps)
  const find = (probeClass: string, path: string, paramName?: string) =>
    plan.hypotheses.find(h => h.probeClass === probeClass && h.endpoint.path === path && (paramName === undefined || h.param?.name === paramName))

  test('maps body/XML/header/GraphQL encodings to injection probes', () => {
    assert.ok(find('sqli_boolean', '/greet', 'name'))
    assert.ok(find('ssti_math', '/greet', 'name'))
    assert.ok(find('xss_context', '/greet', 'name'))
    assert.equal(find('sqli_boolean', '/api/xml/lookup', 'name')?.location, 'xml')
    assert.ok(find('xxe_canary', '/api/xml/import'), 'body-wide XML import gets an XXE probe')
    assert.equal(find('sqli_boolean', '/api/track', 'X-Tracking-Id')?.location, 'header')
    const gql = find('sqli_boolean', '/graphql', 'category')
    assert.equal(gql?.location, 'graphql_var')
    assert.ok(find('sqli_time_diff', '/graphql', 'category'))
  })

  test('attaches second-order read routes and browser fallback hints', () => {
    const stored = find('xss_context', '/api/comments', 'body')
    assert.equal(stored?.secondOrder, true)
    assert.ok(stored?.readPaths?.includes('/comments'), 'stored probe must re-read the rendered listing route')
    const dom = find('xss_context', '/wizard', 'display-name')
    assert.equal(dom?.browserEligible, true)
  })

  test('forms cache probes only for parameterless GETs and bounds their count', () => {
    const cache = plan.hypotheses.filter(h => h.probeClass === 'cache_poison_deception')
    assert.ok(cache.length > 0 && cache.length <= 5)
    const paths = cache.map(h => h.endpoint.path)
    assert.ok(paths.includes('/cache/banner'))
    assert.ok(paths.includes('/account/summary'))
    for (const h of cache) assert.equal(h.endpoint.params.filter(p => !p.isCsrf).length, 0)
  })

  test('keeps auth protocol auditing on parameterized auth routes but skips protocol params as inject targets', () => {
    assert.ok(find('auth_protocol_audit', '/oauth/authorize'))
    const injections = plan.hypotheses.filter(h =>
      h.endpoint.path === '/oauth/authorize' && ['sqli_boolean', 'ssti_math', 'xss_context', 'ssrf_canary'].includes(h.probeClass))
    assert.deepEqual(injections, [], 'client_id/state/code_challenge are protocol controls, not user sinks')
  })

  test('deduplicates write-only probe classes and honors path placeholders', () => {
    const mass = plan.hypotheses.filter(h => h.probeClass === 'mass_assignment' && h.endpoint.path === '/api/profile')
    assert.equal(mass.length, 1)
    assert.ok(hasPathPlaceholder('/api/items/{sku}'))
    assert.equal(fillPlaceholders('/api/items/{sku}', 'abc'), '/api/items/abc')
  })

  test('v3-baseline profile reports unsupported XML/GraphQL encodings instead of dropping them silently', () => {
    const baseline = formHypotheses(endpoints, profileCaps('v3-baseline'))
    assert.ok(baseline.hypotheses.every(h => h.location !== 'xml' && h.location !== 'graphql_var'))
    const skipped = new Set(baseline.encodingSkips.map(s => s.location))
    assert.ok(skipped.has('xml'))
    assert.ok(skipped.has('graphql_var'))
  })
})
