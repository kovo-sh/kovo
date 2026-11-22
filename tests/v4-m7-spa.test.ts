/**
 * M7 SPA/API discovery stream: structural route-map expansion, JS router tables, deep OpenAPI
 * (`$ref`, Swagger 2 bodies), intercepted XHR request shapes, and authenticated recon.
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
  crawlStateGraph,
  extractJsonFieldNames,
  extractJsonLinkTargets,
  extractJsonRecordIds,
  extractJsModuleImports,
  extractRouteMapEntries,
  harvestConfigParamBindings,
  harvestJsRequestParams,
  inferXhrRequestShape,
  parseJsRouterTable,
  parseOpenApiDoc,
  parseRouteMapDoc,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { makeStore, makeLabGrant, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

function makeRunStore(t: TestContext): { storage: Store; runId: string; origin: string; scopeRevision: number } {
  const { storage } = makeStore(t, 'guardian-m7-spa-')
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
    legacySearch: { method: 'GET', path: '/api/v3/search' },
  },
  params: {
    templateSrc: 'template',
    noteBody: 'note',
    searchQuery: 'search',
  },
}

describe('M7 SPA: structural JSON route-map expansion', () => {
  test('expands object route tables into endpoints with methods and path params', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const dynamicPaths = new Set<string>()
    const dynamicParams = new Set<string>()
    const res = parseRouteMapDoc(JSON.stringify(routeMapDoc), origin, storage, runId, scopeRevision, dynamicPaths, dynamicParams)

    assert.equal(res.endpoints, 8)
    assert.ok(res.routeKeys.includes('getTicket'))
    const endpoints = storage.listEndpoints(runId, { origin })
    const detail = endpoints.find(e => e.method === 'GET' && e.pathTemplate === '/api/v3/tickets/:id')
    assert.ok(detail, 'named path parameter collapses to the shared :id template')
    const detailParams = storage.listEndpointParams(runId).filter(p => p.endpointId === detail.id)
    assert.ok(detailParams.some(p => p.name === 'ticketId' && p.location === 'path'))

    const note = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/v3/tickets/:id/notes')
    assert.ok(note)
    const noteParams = storage.listEndpointParams(runId).filter(p => p.endpointId === note.id)
    assert.ok(noteParams.some(p => p.name === 'note' && p.location === 'json'), 'logical->actual body hint linked by name token')
    assert.ok(dynamicParams.has('template'))
  })

  test('accepts array route tables and path->method maps; dedupes against the store', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const arrayDoc = {
      endpoints: [
        { path: '/api/items', method: 'GET' },
        { path: '/api/items', verb: 'POST' },
      ],
    }
    const first = parseRouteMapDoc(JSON.stringify(arrayDoc), origin, storage, runId, scopeRevision, new Set(), new Set())
    const second = parseRouteMapDoc(JSON.stringify(arrayDoc), origin, storage, runId, scopeRevision, new Set(), new Set())
    assert.equal(first.endpoints, 2)
    assert.equal(second.endpoints, 2)
    assert.equal(storage.listEndpoints(runId, { origin }).length, 2, 'repeat expansion must not duplicate endpoints')

    const mapDoc = { api: { '/api/ping': 'GET', '/api/pong': 'POST' } }
    const expansion = extractRouteMapEntries(mapDoc)
    assert.equal(expansion.entries.length, 2)
    assert.equal(expansion.entries[0].method, 'GET')
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
    const bindings = harvestConfigParamBindings(bundle)
    assert.deepEqual(bindings, [{ routeKey: 'reportRender', name: 'templateSrc', location: 'json' }])
  })

  test('applies harvested bindings when expanding the route map', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const bindings = new Map([['reportRender', [{ routeKey: 'reportRender', name: 'templateSrc', location: 'json' as const }]]])
    parseRouteMapDoc(JSON.stringify(routeMapDoc), origin, storage, runId, scopeRevision, new Set(), new Set(), bindings)
    const render = storage.listEndpoints(runId, { origin }).find(e => e.method === 'POST' && e.pathTemplate === '/api/v3/reports/render')
    assert.ok(render)
    // The route map's logical->actual params dictionary resolves templateSrc -> template.
    assert.ok(storage.listEndpointParams(runId).some(p => p.endpointId === render.id && p.name === 'template' && p.location === 'json'))
  })
})

describe('M7 SPA: JS router tables', () => {
  test('extracts method + path templates from router calls and route objects', () => {
    const code = `
      router.get('/api/tickets', list)
      app.post('/api/tickets', create)
      router.route('/api/tickets/:ticketId').put(update).delete(remove)
      const routes = [
        { path: '/reports', component: ReportView },
        { path: '/api/tickets/:ticketId/notes', method: 'POST' },
        { method: 'PATCH', path: '/api/tickets/:ticketId' },
      ]
      fetch('/api/search?term=x')
    `
    const specs = parseJsRouterTable(code)
    const key = (method: string, path: string) => specs.some(s => s.method === method && s.path === path)
    assert.ok(key('GET', '/api/tickets'))
    assert.ok(key('POST', '/api/tickets'))
    assert.ok(key('PUT', '/api/tickets/:ticketId'))
    assert.ok(key('DELETE', '/api/tickets/:ticketId'))
    assert.ok(key('GET', '/reports'), 'client route objects default to GET')
    assert.ok(key('POST', '/api/tickets/:ticketId/notes'))
    assert.ok(key('PATCH', '/api/tickets/:ticketId'))
    // Request-literal scanning remains a separate source and keeps query params.
    const literals = harvestJsRequestParams(code)
    const search = literals.find(s => s.path === '/api/search')
    assert.deepEqual(search?.params, [{ name: 'term', location: 'query' }])
  })
  test('follows same-origin module imports so the API client chunk is scanned', () => {
    const code = `
      import { loginView, dashboardView } from '/views.js'
      export { call } from './client.ts'
      import('/lazy/chunk.js').then((m) => m.boot())
      import 'https://cdn.example.invalid/lib.js'
    `
    assert.deepEqual(extractJsModuleImports(code), ['/views.js', './client.ts', '/lazy/chunk.js'])
  })
})

describe('M7 SPA: OpenAPI depth', () => {
  test('resolves nested local $ref for parameters, request bodies and schemas', t => {
    const { storage, runId, origin, scopeRevision } = makeRunStore(t)
    const doc = {
      openapi: '3.0.3',
      paths: {
        '/api/profiles/{profileId}': {
          parameters: [{ $ref: '#/components/parameters/ProfileId' }],
          patch: {
            requestBody: { $ref: '#/components/requestBodies/ProfileBody' },
          },
        },
      },
      components: {
        parameters: { ProfileId: { name: 'profileId', in: 'path', schema: { type: 'string' } } },
        requestBodies: { ProfileBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Profile' } } } } },
        schemas: {
          Profile: {
            allOf: [
              { properties: { displayName: { type: 'string' } } },
              {
                properties: {
                  address: { $ref: '#/components/schemas/Address' },
                  lines: { type: 'array', items: { $ref: '#/components/schemas/Line' } },
                },
              },
            ],
          },
          Address: { properties: { city: { type: 'string' }, postalCode: { type: 'string' } } },
          Line: { properties: { sku: { type: 'string' }, qty: { type: 'integer' } } },
        },
      },
    }
    const res = parseOpenApiDoc(JSON.stringify(doc), origin, storage, runId, scopeRevision, new Set(), new Set())
    assert.equal(res.endpoints, 1)
    const ep = storage.listEndpoints(runId, { origin })[0]
    assert.ok(ep)
    assert.equal(ep.pathTemplate, '/api/profiles/{profileId}', 'OpenAPI {param} templates are preserved')
    const params = storage.listEndpointParams(runId).filter(p => p.endpointId === ep.id).map(p => `${p.name}@${p.location}`)
    for (const expected of [
      'profileId@path', 'displayName@json', 'address.city@json', 'address.postalCode@json',
      'lines.0.sku@json', 'lines.0.qty@json',
    ]) {
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
})

describe('M7 SPA: JSON schema-observed navigation and request shapes', () => {
  test('infers XHR body and query parameters from an intercepted call', () => {
    const shape = inferXhrRequestShape({
      url: '/api/orders?page=2&sort=asc',
      method: 'POST',
      body: JSON.stringify({ sku: 'A-1', quantity: 2, address: { city: 'Oslo' } }),
      contentType: 'application/json',
    })
    assert.ok(shape)
    assert.equal(shape.method, 'POST')
    assert.equal(shape.path, '/api/orders')
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

  test('crawlStateGraph records intercepted request bodies and query params', async t => {
    const { storage } = makeStore(t, 'guardian-m7-spa-crawl-')
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

describe('M7 SPA: authenticated recon', () => {
  test('fetches config/route-map and API listings with the approved persona session', async t => {
    const SESSION = 'sid=m7-fixture-session'
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
    const bundle = `
      import { loadConfig } from '/api.js'
      async function boot() {
        loadConfig()
        const me = await fetch('/api/me')
      }
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
        res.end('<html><body><script type="module" src="/app.js"></script></body></html>')
        return
      }
      if (url === '/app.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(bundle)
        return
      }
      if (url === '/api.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(apiClient)
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
        if (url === '/api/reports/render') { res.end('{"html":"ok"}'); return }
        res.statusCode = 404
        res.end('{"error":"not_found"}')
        return
      }
      res.statusCode = 404
      res.end('not found')
    })

    const { storage } = makeStore(t, 'guardian-m7-spa-auth-')
    const setup = await setupApprovedRun(storage, {
      seeds: [fx.origin],
      budgetRequests: 900,
      personas: [{ handle: 'owner', roleLabel: 'owner', authKind: 'cookie', secret: SESSION }],
    })
    const grant: Grant = makeLabGrant(fx.origin, { tier: 3, personas: setup.personaMap })

    const result = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => runPhase0Recon({
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
    assert.ok(configReq, 'runtime config document was fetched')
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
  })
})
