/**
 * M7/v5-M2 SPA/API discovery stream: structural route-map/config artifact expansion, JS router
 * tables and module/manifest recursion, deep OpenAPI (YAML + `$ref`/composition + servers),
 * intercepted XHR request shapes, authenticated recon, and soft-404 calibration.
 *
 * Fixtures are synthetic; no benchmark challenge literals appear in engine-facing assertions.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { Store } from '../src/server/store.ts'
import {
  bodyStructuralSignature,
  crawlStateGraph,
  extractAssetReferences,
  extractJsModuleImports,
  extractJsonFieldNames,
  extractJsonLinkTargets,
  extractJsonRecordIds,
  harvestConfigParamBindings,
  harvestRouteMapDocument,
  harvestRouteMapParamHints,
  harvestJsRouteTable,
  harvestJsRequestParams,
  harvestTrpcProcedures,
  inferXhrRequestShape,
  isSoftNotFound,
  normalizeDiscoveryTemplate,
  parseJsonOrYaml,
  parseOpenApiDoc,
  parseRouteMapDoc,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { makeStore, makeLabGrant, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

function makeRunStore(t: TestContext): { storage: Store; runId: string; origin: string; scopeRevision: number } {
  const { storage } = makeStore(t, 'kovo-m7-spa-')
  const origin = 'https://spa.fixture.test'
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'M7 SPA fixtures', environment: 'local-lab', seeds: [origin],
  } as unknown as Parameters<Store['createProject']>[0])
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'M7 SPA discovery unit fixtures', sourceMode: 'prepared',
    capabilityTier: 3, budgetUsd: 1, budgetRequests: 900, maxRpsPerOrigin: 10, workerConcurrency: 2, workerMaxTurns: 20,
  } as unknown as Parameters<Store['createRun']>[0])
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const assetIds = storage.runDetail(runId).run.candidates.map(c => c.id)
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds, consent: true } as unknown as Parameters<Store['command']>[0])
  return { storage, runId, origin, scopeRevision: storage.runDetail(runId).run.scopeRevision }
}

const routeMapDoc = {
  apiPrefix: '/api/v3',
  idFormat: 'prefixed',
  routes: {
    me: { method: 'GET', path: '/api/v3/me' },
    listTickets: { method: 'GET', path: '/api/v3/tickets' },
    getTicket: { method: 'GET', path: '/api/v3/tickets/:ticketId' },
    ticketView: { method: 'GET', path: '/api/v3/tickets/:ticketId/view' },
    createTicket: { method: 'POST', path: '/api/v3/tickets' },
    ticketNoteCreate: { method: 'POST', path: '/api/v3/tickets/:ticketId/notes' },
    reportRender: { method: 'POST', path: '/api/v3/reports/render' },
  },
  params: {
    templateSrc: 'template',
    noteBody: 'note',
  },
}

describe('M7 SPA: route-map/config artifact expansion', () => {
  test('harvests keyed {method, path} config tables and logical parameter dictionaries', () => {
    const entries = harvestRouteMapDocument(routeMapDoc)
    const byPath = new Map(entries.map(entry => [`${entry.method} ${entry.path}`, entry]))
    assert.ok(byPath.has('GET /api/v3/tickets/:ticketId'))
    assert.equal(byPath.get('POST /api/v3/tickets/:ticketId/notes')?.key, 'ticketNoteCreate')
    const hints = harvestRouteMapParamHints(routeMapDoc)
    assert.equal(hints.paramMap.templateSrc, 'template')
    assert.ok(hints.paramHints.includes('note'))
  })

  test('expands a config artifact into endpoints with preserved named params and bindings', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const dynamicPaths = new Set<string>()
    const dynamicParams = new Set<string>()
    const bindings = new Map([['reportRender', [{ routeKey: 'reportRender', name: 'templateSrc', location: 'json' as const }]]])
    const res = parseRouteMapDoc(JSON.stringify(routeMapDoc), origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings })
    assert.equal(res.endpoints, 7)

    const endpoints = storage.listEndpoints(runId, { origin })
    const detail = endpoints.find(e => e.method === 'GET' && e.pathTemplate === '/api/v3/tickets/:ticketId')
    assert.ok(detail, 'named path parameter is preserved by normalizeDiscoveryTemplate')
    assert.ok(storage.listEndpointParams(runId).some(p => p.endpointId === detail.id && p.name === 'ticketId' && p.location === 'path'))

    const note = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/v3/tickets/:ticketId/notes')
    assert.ok(note)
    assert.ok(storage.listEndpointParams(runId).some(p => p.endpointId === note.id && p.name === 'note' && p.location === 'json'), 'logical->actual body hint linked by name token')

    const render = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/v3/reports/render')
    assert.ok(render)
    assert.ok(storage.listEndpointParams(runId).some(p => p.endpointId === render.id && p.name === 'template' && p.location === 'json'), 'bundle binding resolved through params map')

    // Re-expanding must dedupe against the store.
    parseRouteMapDoc(JSON.stringify(routeMapDoc), origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams, { bindings })
    assert.equal(storage.listEndpoints(runId, { origin }).length, 7)
  })

  test('does not treat OpenAPI documents as generic route maps', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const res = parseRouteMapDoc(JSON.stringify({ openapi: '3.0.3', paths: { '/x': { get: {} } } }), origin, storage, runId, scopeRevision, new Set(), new Set())
    assert.deepEqual(res, { endpoints: 0, params: 0 })
  })

  test('harvests runtime parameter bindings from the bundle', () => {
    const bundle = `
      async function render() {
        const field = (config.params && config.params.templateSrc) || 'template'
        const body = {}
        body[field] = document.getElementById('layout').value
        await api('reportRender', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
        })
      }
    `
    assert.deepEqual(harvestConfigParamBindings(bundle), [{ routeKey: 'reportRender', name: 'templateSrc', location: 'json' }])
  })
})

describe('M7 SPA: JS router tables, manifests and tRPC', () => {
  test('extracts router table path literals', () => {
    const code = `
      const routes = [
        { path: '/reports', component: ReportView },
        { path: '/api/tickets/:ticketId/notes', method: 'POST' },
      ]
      router.get('/api/tickets', list)
      router.push('/dashboard')
      fetch('/api/search?term=x')
    `
    const paths = harvestJsRouteTable(code)
    assert.ok(paths.includes('/reports'))
    assert.ok(paths.includes('/api/tickets/:ticketId/notes'))
    assert.ok(paths.includes('/api/tickets'))
    assert.ok(paths.includes('/dashboard'))
    const literals = harvestJsRequestParams(code)
    assert.deepEqual(literals.find(s => s.path === '/api/search')?.params, [{ name: 'term', location: 'query' }])
  })

  test('follows module imports, manifests and build chunk references', () => {
    const code = `
      import { loadConfig } from '/api.js'
      export { call } from './client.ts'
      import('/lazy/chunk.js')
      import 'https://cdn.example.invalid/lib.js'
      self.__BUILD_MANIFEST = { "/dashboard": ["static/pages/dashboard-abc.js"] }
    `
    assert.deepEqual(extractJsModuleImports(code), ['/api.js', './client.ts', '/lazy/chunk.js'])
    const assets = extractAssetReferences(code)
    assert.ok(assets.includes('static/pages/dashboard-abc.js') === false, 'relative chunk paths are resolved by the caller, not emitted bare')
    assert.ok(extractAssetReferences(`const m = { "/app.js": "/assets/app-123.js", "/app.css": "/assets/app.css" }`).includes('/assets/app-123.js'))
  })

  test('extracts tRPC procedure references', () => {
    const code = `
      const a = trpc.user.byId.useQuery({ id })
      const b = trpc['invoice']['list'].useMutation()
      fetch('/trpc/report.render?input=%7B%7D')
    `
    const procs = harvestTrpcProcedures(code).map(p => `${p.router}.${p.procedure}`).sort()
    assert.deepEqual(procs, ['invoice.list', 'report.render', 'user.byId'])
  })
})

describe('M7 SPA: discovery template normalization', () => {
  test('preserves named parameters and casing, normalizing only token shapes', () => {
    assert.equal(normalizeDiscoveryTemplate('/api/orgs/:orgId/invoices/:invoiceId'), '/api/orgs/:orgId/invoices/:invoiceId')
    assert.equal(normalizeDiscoveryTemplate('/api/getInvoice'), '/api/getInvoice')
    assert.equal(normalizeDiscoveryTemplate('/trpc/user.getById'), '/trpc/user.getById')
    assert.equal(normalizeDiscoveryTemplate('/api/items/[id]'), '/api/items/:id')
    assert.equal(normalizeDiscoveryTemplate('/api/items/{id}'), '/api/items/:id')
    assert.equal(normalizeDiscoveryTemplate('/api/items/<int:id>/view/'), '/api/items/:id/view')
  })
})

describe('M7 SPA: OpenAPI depth (YAML, $ref, composition, servers)', () => {
  test('resolves nested local $ref and prefixes the servers base path', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const yaml = `openapi: 3.0.3
servers:
  - url: https://api.example.test/v2
paths:
  /profiles/{profileId}:
    parameters:
      - $ref: "#/components/parameters/ProfileId"
    patch:
      requestBody:
        $ref: "#/components/requestBodies/ProfileBody"
components:
  parameters:
    ProfileId:
      name: profileId
      in: path
      schema:
        type: string
  requestBodies:
    ProfileBody:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/Profile"
  schemas:
    Profile:
      allOf:
        - properties:
            displayName:
              type: string
        - properties:
            address:
              $ref: "#/components/schemas/Address"
    Address:
      properties:
        city:
          type: string
`
    const res = parseOpenApiDoc(yaml, origin, storage, runId, scopeRevision, new Set(), new Set())
    assert.equal(res.endpoints, 1)
    const ep = storage.listEndpoints(runId, { origin })[0]
    assert.ok(ep)
    assert.equal(ep.pathTemplate, '/v2/profiles/{profileId}', 'servers base path is prefixed; {param} preserved')
    const params = storage.listEndpointParams(runId).map(p => `${p.name}@${p.location}`)
    for (const expected of ['profileId@path', 'displayName@json', 'address.city@json']) {
      assert.ok(params.includes(expected), `missing ${expected} in ${params.join(',')}`)
    }
  })

  test('extracts Swagger 2 body and formData parameters through definitions', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const doc = {
      swagger: '2.0',
      paths: {
        '/api/items': {
          post: {
            parameters: [
              { in: 'body', name: 'payload', schema: { $ref: '#/definitions/Item' } },
              { in: 'formData', name: 'attachment', type: 'file' },
            ],
          },
        },
      },
      definitions: { Item: { properties: { title: { type: 'string' }, price: { type: 'number' } } } },
    }
    parseOpenApiDoc(JSON.stringify(doc), origin, storage, runId, scopeRevision, new Set(), new Set())
    const ep = storage.listEndpoints(runId, { origin }).find(e => e.method === 'POST')
    assert.ok(ep)
    const params = storage.listEndpointParams(runId).filter(p => p.endpointId === ep.id).map(p => `${p.name}@${p.location}`)
    assert.ok(params.includes('title@json'))
    assert.ok(params.includes('price@json'))
    assert.ok(params.includes('attachment@form'))
  })

  test('parses YAML mappings/sequences without a YAML dependency', () => {
    const parsed = parseJsonOrYaml('a:\n  - b: 1\n    c: two\n  - plain\nd:\n  - "quoted # not a comment"\n')
    assert.deepEqual(parsed, { a: [{ b: 1, c: 'two' }, 'plain'], d: ['quoted # not a comment'] })
  })
})

describe('M7 SPA: JSON navigation, XHR shapes and soft-404 calibration', () => {
  test('infers XHR body and query parameters from an intercepted call', () => {
    const shape = inferXhrRequestShape({
      url: '/api/orders?page=2&sort=asc',
      method: 'POST',
      body: JSON.stringify({ sku: 'A-1', quantity: 2, address: { city: 'Oslo' } }),
      contentType: 'application/json',
    })
    assert.ok(shape)
    const names = shape.params.map(p => `${p.name}@${p.location}`).sort()
    assert.deepEqual(names, ['address.city@json', 'page@query', 'quantity@json', 'sku@json', 'sort@query'])
    const form = inferXhrRequestShape({ url: '/api/notes', method: 'POST', body: 'title=Hi&body=There' })
    assert.deepEqual(form?.params.map(p => p.name).sort(), ['body', 'title'])
  })

  test('collects HATEOAS links, record ids and response field names', () => {
    const body = JSON.stringify({
      items: [
        { ext_id: 'TK-7', subject: 'Printer', status: 'open', _links: { self: { href: '/api/tickets/TK-7' } } },
      ],
      next: '/api/tickets?page=2',
    })
    const links = extractJsonLinkTargets(body, 'https://spa.fixture.test')
    assert.ok(links.includes('/api/tickets/TK-7'))
    assert.ok(links.includes('/api/tickets?page=2'))
    assert.deepEqual(extractJsonRecordIds(body), ['TK-7'])
    const fields = extractJsonFieldNames(body)
    assert.ok(fields.includes('subject'))
    assert.ok(fields.includes('status'))
  })

  test('soft-404 calibration rejects structurally identical catch-all responses only', () => {
    const shell = '<html><body><div id="app">Loading…</div><script src="/app.js"></script></body></html>'
    const calibration = {
      statuses: [200, 200],
      mediaTypes: ['text/html', 'text/html'],
      lengths: [shell.length, shell.length],
      signatures: [bodyStructuralSignature(shell), bodyStructuralSignature(shell)],
    }
    assert.ok(isSoftNotFound(calibration, { status: 200, mediaType: 'text/html', body: shell }))
    assert.ok(!isSoftNotFound(calibration, { status: 200, mediaType: 'application/json', body: '{"items":[]}' }))
    assert.ok(!isSoftNotFound(calibration, { status: 404, mediaType: 'text/html', body: shell }))
  })

  test('crawlStateGraph records intercepted request bodies and query params', async t => {
    const { storage } = makeStore(t, 'kovo-m7-spa-crawl-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: ['https://spa.fixture.test'], budgetRequests: 900 })
    const origin = 'https://spa.fixture.test'
    const xhr = {
      method: 'POST',
      url: `${origin}/api/orders?page=1`,
      origin,
      resourceType: 'fetch',
      status: 200,
      body: JSON.stringify({ sku: 'A-1', quantity: 2 }),
    }
    const browser = {
      visitPage: async () => ({
        origin,
        finalUrl: `${origin}/`,
        title: 'fixture',
        status: 200,
        domSnippet: '',
        links: [],
        forms: [],
        xhrRequests: [xhr],
        allRequests: [xhr],
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
      }),
    } as unknown as ScopedBrowser

    await crawlStateGraph({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      origin,
      maxPages: 3,
      maxDepth: 1,
      browser,
      grant: makeLabGrant(origin),
      signal: AbortSignal.timeout(10_000),
    })

    const ep = storage.listEndpoints(runId, { origin }).find(e => e.pathTemplate === '/api/orders')
    assert.ok(ep, 'intercepted fetch becomes an endpoint')
    assert.equal(ep.method, 'POST')
    const params = storage.listEndpointParams(runId).filter(p => p.endpointId === ep.id).map(p => `${p.name}@${p.location}`)
    assert.ok(params.includes('page@query'))
    assert.ok(params.includes('sku@json'))
    assert.ok(params.includes('quantity@json'))
  })
})

describe('M7 SPA: authenticated recon with config artifact expansion', () => {
  test('fetches config/route-map and API listings with the approved persona session', async t => {
    const SESSION = 'sid=m7-fixture-session'
    const shell = '<html><body><div id="app">Loading…</div><script type="module" src="/app.js"></script></body></html>'
    const authorized = (headers: Record<string, string | string[] | undefined>): boolean => {
      const cookie = headers.cookie
      const raw = Array.isArray(cookie) ? cookie.join('; ') : (cookie ?? '')
      return raw.includes('sid=m7-fixture-session')
    }
    const routes = {
      apiPrefix: '/api',
      routes: {
        me: { method: 'GET', path: '/api/me' },
        listTickets: { method: 'GET', path: '/api/tickets' },
        getTicket: { method: 'GET', path: '/api/tickets/:ticketId' },
        createTicket: { method: 'POST', path: '/api/tickets' },
        reportRender: { method: 'POST', path: '/api/reports/render' },
      },
      params: { templateSrc: 'template' },
    }
    // The entry bundle only imports the API client; the config fetch literal lives in /api.js.
    const appBundle = `
      import { loadConfig } from '/api.js'
      async function boot() { loadConfig(); await fetch('/api/me') }
      async function render() {
        const field = (config.params && config.params.templateSrc) || 'template'
        const body = {}
        body[field] = document.getElementById('layout').value
        await api('reportRender', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      }
      function api(key, init) { return fetch('/api/' + key, init) }
    `
    const apiClient = `
      export async function loadConfig() {
        const res = await fetch('/app-config.json')
        return res.json()
      }
    `
    const fx = await startHttpFixture(t, (req, _body, res) => {
      const url = req.url ?? '/'
      if (url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end(`${shell.replace('</body>', '<a href="/ghost-page">Ghost</a></body>')}`)
        return
      }
      if (url === '/app.js' || url === '/api.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(url === '/app.js' ? appBundle : apiClient)
        return
      }
      if (url === '/app-config.json' || url.startsWith('/api/')) {
        if (!authorized(req.headers)) {
          res.statusCode = 401
          res.setHeader('Content-Type', 'application/json')
          res.end('{"error":"auth_required"}')
          return
        }
        res.setHeader('Content-Type', 'application/json')
        if (url === '/app-config.json') { res.end(JSON.stringify(routes)); return }
        if (url === '/api/me') { res.end('{"authenticated":true}'); return }
        if (url === '/api/tickets') {
          res.end(JSON.stringify({ items: [{ ext_id: 'TK-1', subject: 'First ticket', status: 'open' }] }))
          return
        }
        if (url === '/api/tickets/TK-1') {
          res.end(JSON.stringify({ ext_id: 'TK-1', subject: 'First ticket', status: 'open' }))
          return
        }
        if (url === '/api/reports/render') { res.end('{"rendered":true}'); return }
        res.statusCode = 404
        res.end('{"error":"not_found"}')
        return
      }
      // SPA catch-all: unknown navigation routes render the same shell with HTTP 200.
      res.setHeader('Content-Type', 'text/html')
      res.end(shell)
    })

    const { storage } = makeStore(t, 'kovo-m7-spa-auth-')
    const setup = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      budgetRequests: 900,
      personas: [{ handle: 'owner', roleLabel: 'owner', authKind: 'cookie', secret: SESSION }],
    })
    const grant: Grant = makeLabGrant(fx.origin, { tier: 3, personas: setup.personaMap })

    const result = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 3,
      origins: [fx.origin],
      budgetRequests: 900,
      personas: ['owner'],
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant,
      signal: AbortSignal.timeout(30_000),
    }))

    const configReq = fx.requests.find(r => r.url === '/app-config.json')
    assert.ok(configReq, 'config artifact was discovered from the imported API client and fetched')
    assert.ok(authorized(configReq.headers), 'config fetch carried the persona session cookie')
    assert.ok((result.authRequests ?? 0) > 0)
    assert.ok((result.routeMapEndpoints ?? 0) >= 5)

    const endpoints = storage.listEndpoints(setup.runId, { origin: fx.origin })
    const render = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/reports/render')
    assert.ok(render, 'route-map write route discovered')
    const renderParams = storage.listEndpointParams(setup.runId).filter(p => p.endpointId === render.id)
    assert.ok(renderParams.some(p => p.name === 'template' && p.location === 'json'), 'bundle binding attached the body field')

    const create = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/tickets')
    assert.ok(create)
    const createParams = storage.listEndpointParams(setup.runId).filter(p => p.endpointId === create.id)
    assert.ok(createParams.some(p => p.name === 'subject' && p.location === 'json'), 'observed listing fields seed sibling write params')

    const detailReq = fx.requests.find(r => r.url === '/api/tickets/TK-1')
    assert.ok(detailReq, 'collection ids were walked into the sibling detail route')
    assert.ok(authorized(detailReq.headers), 'detail walk stayed authenticated')

    assert.ok(!endpoints.some(e => e.pathTemplate === '/ghost-page'), 'soft-404 catch-all navigation route was rejected')
    assert.ok((result.soft404Rejected ?? 0) > 0)
  })
})
