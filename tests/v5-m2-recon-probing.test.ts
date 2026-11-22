/**
 * v5 M2 follow-up: discovered-route probing, XHR route-map expansion, static route filtering and
 * soft-404 calibration under an API prefix.
 *
 * Fixtures are synthetic; no benchmark challenge literals appear in engine-facing assertions.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  bodyStructuralSignature,
  crawlStateGraph,
  extractStaticFrameworkRoutes,
  isPathLikeRouteLiteral,
  isSoftNotFound,
  normalizeDiscoveryTemplate,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { ScopedBrowser } from '../src/server/scoped-browser.ts'
import {
  makeLabGrant, makeStore, makeTempDir, setupApprovedRun, startHttpFixture, withEnv,
} from './v4-tier-helpers.ts'

describe('v5 M2 recon probing: static route literals', () => {
  test('rejects SQL/query fragments picked up from verb-named data helpers', (t: TestContext) => {
    const repoDir = makeTempDir(t, 'guardian-v5m2-repo-')
    const write = (rel: string, content: string) => {
      const full = join(repoDir, rel)
      mkdirSync(join(full, '..'), { recursive: true })
      writeFileSync(full, content, 'utf8')
    }
    write('svc/routes.ts', [
      'import express from "express"',
      'const app = express()',
      'const db = { all: (sql: string, args: unknown[]) => args }',
      'function listTickets(team: string) {',
      '  return db.all("SELECT ext_id, subject, status FROM tickets WHERE team_id = ?", [team])',
      '}',
      'app.all("SELECT ext_id, subject FROM tickets WHERE team_id = ?", [])',
      'app.get("/api/tickets", (_req, res) => res.json(listTickets("t1")))',
      'app.get("/api/tickets/:ticketId", (_req, res) => res.json({}))',
      'app.post("/api/tickets/:ticketId/notes", (_req, res) => res.json({}))',
    ].join('\n'))

    assert.equal(isPathLikeRouteLiteral('SELECT ext_id, subject FROM tickets WHERE team_id = ?'), false)
    assert.equal(isPathLikeRouteLiteral('/api/tickets/:ticketId'), true)
    assert.equal(isPathLikeRouteLiteral('api/tickets'), true)

    const { routes } = extractStaticFrameworkRoutes(repoDir)
    const paths = routes.map(route => route.pathTemplate)
    assert.ok(paths.includes('/api/tickets'), 'legit collection route survives')
    assert.ok(paths.includes('/api/tickets/:id'), 'legit detail route survives')
    assert.ok(paths.includes('/api/tickets/:id/notes'), 'legit nested route survives')
    assert.ok(
      !paths.some(path => /\bselect\b|\bfrom\b|\bwhere\b|\s/i.test(path)),
      `no SQL fragment should become a route: ${paths.join(', ')}`,
    )
  })
})

describe('v5 M2 recon probing: XHR route-map documents', () => {
  const config = {
    apiPrefix: '/api',
    routes: {
      issues: { method: 'GET', path: '/api/issues' },
      issueGet: { method: 'GET', path: '/api/issues/:issueId' },
      issueView: { method: 'GET', path: '/api/issues/:issueId/view' },
      issueNoteCreate: { method: 'POST', path: '/api/issues/:issueId/notes' },
    },
    params: { noteBody: 'note' },
  }

  function visitFor(origin: string, pathAndQuery: string, xhr: Array<{ path: string; body: string }>) {
    const requests = xhr.map(item => ({
      method: 'GET',
      url: `${origin}${item.path}`,
      origin,
      resourceType: 'fetch',
      status: 200,
      mediaType: 'application/json',
      bodyPreview: item.body,
    }))
    return {
      origin,
      finalUrl: `${origin}${pathAndQuery}`,
      title: 'fixture',
      status: 200,
      domSnippet: '',
      links: [],
      forms: [],
      xhrRequests: requests,
      allRequests: requests,
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

  test('expands route maps and walks collection ids into detail templates', async (t: TestContext) => {
    const { storage } = makeStore(t, 'guardian-v5m2-crawl-')
    const origin = 'https://recon.fixture.test'
    const { runId, run } = await setupApprovedRun(storage, { seeds: [origin], budgetRequests: 900 })
    const visited: string[] = []
    const browser = {
      visitPage: async (req: { origin: string; pathAndQuery: string }) => {
        visited.push(req.pathAndQuery)
        if (req.pathAndQuery === '/') {
          return visitFor(origin, '/', [{ path: '/app-config.json', body: JSON.stringify(config) }])
        }
        if (req.pathAndQuery === '/api/issues') {
          return visitFor(origin, '/api/issues', [{
            path: '/api/issues',
            body: JSON.stringify({ items: [{ ext_id: 'AX-9', subject: 'first' }] }),
          }])
        }
        if (req.pathAndQuery.startsWith('/api/issues/')) {
          return visitFor(origin, req.pathAndQuery, [{
            path: req.pathAndQuery,
            body: JSON.stringify({ ext_id: req.pathAndQuery.split('/').at(-1) }),
          }])
        }
        return visitFor(origin, req.pathAndQuery, [])
      },
    } as unknown as ScopedBrowser

    const result = await crawlStateGraph({
      storage,
      runId,
      scopeRevision: run.scopeRevision,
      origin,
      maxPages: 8,
      maxDepth: 2,
      browser,
      grant: makeLabGrant(origin),
      signal: AbortSignal.timeout(10_000),
    })

    const endpoints = storage.listEndpoints(runId, { origin })
    const routeMapGet = endpoints.find(e => e.method === 'GET' && e.pathTemplate === '/api/issues')
    assert.ok(routeMapGet, 'route-map GET entry expanded from the intercepted config body')
    const detail = endpoints.find(e => e.method === 'GET' && /\/api\/issues\/:issueId$/.test(e.pathTemplate))
    assert.ok(detail, 'templated detail entry expanded')
    const noteCreate = endpoints.find(e => e.method === 'POST' && e.pathTemplate.endsWith('/:issueId/notes'))
    assert.ok(noteCreate, 'templated write entry expanded')
    const detailParams = storage.listEndpointParams(runId).filter(p => p.endpointId === detail.id)
    assert.ok(detailParams.some(p => p.name === 'issueId' && p.location === 'path'))
    assert.ok(visited.includes('/api/issues'), 'collection route was explored')
    assert.ok(visited.includes('/api/issues/AX-9'), 'collection id was walked into the detail template')
    assert.ok((result.routeMapEndpoints ?? 0) >= 3)
  })
})

describe('v5 M2 recon probing: phase-0 route-map probing and soft-404 calibration', () => {
  test('probes templated entry routes with harvested ids and rejects the API catch-all shell', async (t: TestContext) => {
    const shell = '<html><body><div id="app">Loading…</div><script src="/app.js"></script></body></html>'
    const routes = {
      apiPrefix: '/api',
      routes: {
        issues: { method: 'GET', path: '/api/issues' },
        issueGet: { method: 'GET', path: '/api/issues/:issueId' },
        issueView: { method: 'GET', path: '/api/issues/:issueId/view' },
        issueNoteCreate: { method: 'POST', path: '/api/issues/:issueId/notes' },
        reportRender: { method: 'POST', path: '/api/reports/render' },
      },
      params: { templateSrc: 'template' },
    }
    const appBundle = `
      async function boot() { await fetch('/app-config.json'); await fetch('/api/issues') }
      function render() {
        const field = (config.params && config.params.templateSrc) || 'template'
        const body = {}
        body[field] = document.getElementById('layout').value
        return api('reportRender', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
      }
      boot()
    `
    const fx = await startHttpFixture(t, (req, _body, res) => {
      const url = req.url ?? '/'
      if (url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end(shell.replace('</body>', '<a href="/ghost-page">Ghost</a></body>'))
        return
      }
      if (url === '/app.js') {
        res.setHeader('Content-Type', 'application/javascript')
        res.end(appBundle)
        return
      }
      if (url === '/app-config.json') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify(routes))
        return
      }
      if (url === '/api/issues') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ items: [{ ext_id: 'AX-1', subject: 'First' }, { ext_id: 'AX-2', subject: 'Second' }] }))
        return
      }
      if (url === '/api/issues/AX-1' || url === '/api/issues/AX-2') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ ext_id: url.split('/').at(-1), subject: 'First' }))
        return
      }
      if (url === '/api/issues/AX-1/view' || url === '/api/issues/AX-2/view') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ view: 'detail' }))
        return
      }
      if (url === '/api/reports/render') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ rendered: true }))
        return
      }
      // SPA catch-all for unknown navigation *and* unknown API paths: same shell with HTTP 200.
      res.setHeader('Content-Type', 'text/html')
      res.end(shell)
    })

    const { storage } = makeStore(t, 'guardian-v5m2-phase0-')
    const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 900 })
    const grant: Grant = makeLabGrant(fx.origin, { tier: 1 })

    const result = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 1,
      origins: [fx.origin],
      budgetRequests: 900,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant,
      signal: AbortSignal.timeout(30_000),
    }))

    const requested = fx.requests.map(r => r.url ?? '/')
    assert.ok(requested.includes('/api/issues/AX-1'), `entry route probed with a harvested id (${requested.join(', ')})`)
    const requestedPaths = requested.map(url => {
      try { return new URL(url, fx.origin).pathname } catch { return url.split('?')[0] ?? url }
    })
    assert.ok(
      !requestedPaths.some(path => /:[A-Za-z]|\{|\}/.test(path)),
      `templates are never probed with placeholder literals (${requestedPaths.join(', ')})`,
    )
    assert.ok((result.routeMapEndpoints ?? 0) >= 4, 'route-map entries expanded')
    assert.ok((result.soft404Rejected ?? 0) > 0, 'SPA catch-all rejected by calibration')

    const endpoints = storage.listEndpoints(setup.runId, { origin: fx.origin })
    assert.ok(!endpoints.some(e => e.pathTemplate === '/ghost-page'), 'catch-all navigation route rejected')
    assert.ok(!endpoints.some(e => /\/api\/\.guardian-cal-/.test(e.pathTemplate)), 'calibration probes are not surface')
    const probed = endpoints.filter(e => e.method === 'GET' && e.pathTemplate.startsWith('/api/issues'))
    assert.ok(probed.length >= 2, 'collection and detail routes recorded as live surface')

    const render = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/reports/render')
    assert.ok(render, 'route-map write route discovered')
    const renderParams = storage.listEndpointParams(setup.runId).filter(p => p.endpointId === render.id)
    assert.ok(renderParams.some(p => p.name === 'template' && p.location === 'json'), 'logical->actual param binding kept')
  })

  test('calibration under an API prefix rejects the shell but keeps real JSON routes', () => {
    const shell = '<html><body><div id="app">Loading…</div><script src="/app.js"></script></body></html>'
    const calibration = {
      statuses: [200, 200, 200, 200],
      mediaTypes: ['text/html', 'text/html', 'text/html', 'text/html'],
      lengths: [shell.length, shell.length, shell.length, shell.length],
      signatures: [
        bodyStructuralSignature(shell), bodyStructuralSignature(shell),
        bodyStructuralSignature(shell), bodyStructuralSignature(shell),
      ],
    }
    assert.ok(isSoftNotFound(calibration, { status: 200, mediaType: 'text/html', body: shell }))
    const jsonRoute = JSON.stringify({ items: [{ ext_id: 'AX-1' }] })
    assert.ok(!isSoftNotFound(calibration, { status: 200, mediaType: 'application/json', body: jsonRoute }))
    assert.equal(normalizeDiscoveryTemplate('/api/issues/:issueId'), '/api/issues/:issueId')
  })
})
