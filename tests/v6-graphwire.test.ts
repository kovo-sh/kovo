/**
 * v6 GraphWire: wire the code-first Program Graph into Phase-0 discovery.
 *
 * Covers AST-derived routes (full mounted prefixes, guard chains, input schemas) merged with
 * declared/OpenAPI surface without duplicates, middleware-aware auth inference surfaced through
 * recon output, monorepo service→origin attribution, code-to-runtime hypotheses, and multi-hop
 * suspect binding through the Program Graph with a clean no-repo fallback.
 *
 * Fixtures are synthetic; no benchmark app, seed, route or challenge identifier is consulted.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  astRouteClusterSignature,
  extractRepoProgramGraph,
  extractStaticFrameworkRoutes,
  mergeStaticRouteExtractions,
  rankAndClusterAstRoutes,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { StaticExtractedRoute } from '../src/server/phase0-recon.ts'
import { extractProgramGraph } from '../src/server/program-graph.ts'
import type { CodeToRuntimeHypothesis } from '../src/server/program-graph.ts'
import { callGraphFromProgramGraph, resolveSuspectEntrypoint } from '../src/server/semantic-audit.ts'
import { makeLabGrant, makeStore, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeRepoDir(t: TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function writeTree(root: string, files: Record<string, string>): void {
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
}

const OPENAPI_SPEC = JSON.stringify({
  openapi: '3.0.3',
  info: { title: 'synthetic', version: '1' },
  paths: {
    '/api/v2/invoices/{id}': {
      get: { responses: { '200': { description: 'ok' } } },
      delete: { responses: { '204': { description: 'deleted' } } },
    },
    '/api/v2/reports': { get: { responses: { '200': { description: 'ok' } } } },
  },
})

async function runStaticRecon(input: {
  t: TestContext
  reposDir?: string
  origin: string
  openapi?: string
}): Promise<{
  result: Awaited<ReturnType<typeof runPhase0Recon>>
  endpoints: ReturnType<ReturnType<typeof makeStore>['storage']['listEndpoints']>
}> {
  const { storage } = makeStore(input.t, 'kovo-v6-graphwire-')
  const setup = await setupApprovedRun(storage, { seeds: [input.origin], budgetRequests: 900 })
  if (input.openapi) {
    storage.upsertProjectSpecRaw(setup.projectId, { name: 'reference.json', kind: 'openapi', content: input.openapi })
  }
  const grant: Grant = makeLabGrant(input.origin, { tier: 0 })
  const result = await runPhase0Recon({
    storage,
    runId: setup.runId,
    scopeRevision: setup.run.scopeRevision,
    tier: 0,
    origins: [input.origin],
    budgetRequests: 900,
    ...(input.reposDir ? { reposDir: input.reposDir } : {}),
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    signal: AbortSignal.timeout(20_000),
  })
  return { result, endpoints: storage.listEndpoints(setup.runId, { origin: input.origin }) }
}

describe('v6 graphwire: AST routes merged with declared surface', () => {
  test('nested Express mounts yield /v2/... routes merged with OpenAPI without duplicates', async (t) => {
    const origin = 'https://app.graphwire.test'
    const reposDir = makeRepoDir(t, 'graphwire-nested-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        "const express = require('express')",
        'const app = express()',
        'const api = express.Router()',
        'const v2 = express.Router()',
        "app.use('/api', api)",
        "api.use('/v2', v2)",
        "v2.get('/invoices/:id', requireAuth, getInvoice)",
        "v2.delete('/invoices/:id', requireAuth, deleteInvoice)",
      ].join('\n'),
      'acme/app/src/health.ts': [
        'const router = express.Router()',
        "router.get('/health', healthCheck)",
      ].join('\n'),
    })

    const extracted = extractRepoProgramGraph({ reposDir, origins: [origin] })
    assert.ok(extracted, 'AST extraction must run for a mounted repo')
    const astPaths = extracted.routes.map(route => `${route.method} ${route.pathTemplate}`)
    assert.ok(astPaths.includes('GET /api/v2/invoices/:id'), `full mounted prefix resolved (${astPaths.join(', ')})`)
    assert.ok(astPaths.includes('DELETE /api/v2/invoices/:id'))

    const regex = extractStaticFrameworkRoutes(reposDir)
    const merged = mergeStaticRouteExtractions({
      astRoutes: extracted.routes,
      regexRoutes: regex.routes,
      defaultOrigin: origin,
    })
    assert.ok(merged.duplicates >= 1, 'the unmounted /health route is deduped across AST and regex')
    assert.equal(
      merged.routes.filter(route => route.method === 'GET' && route.pathTemplate === '/health').length,
      1,
      'dedupe key is (origin, METHOD, pathTemplate)',
    )

    const { result, endpoints } = await runStaticRecon({ t, reposDir, origin, openapi: OPENAPI_SPEC })
    const invoices = endpoints.filter(endpoint => endpoint.pathTemplate === '/api/v2/invoices/:id')
    assert.equal(invoices.filter(endpoint => endpoint.method === 'GET').length, 1, 'GET declared + AST is stored once')
    assert.equal(invoices.filter(endpoint => endpoint.method === 'DELETE').length, 1, 'DELETE declared + AST is stored once')
    assert.ok(endpoints.some(endpoint => endpoint.method === 'GET' && endpoint.pathTemplate === '/api/v2/reports'))

    const summary = result.repoStaticExtraction
    assert.ok(summary, 'recon result reports the AST/regex split')
    assert.ok(summary.astRoutes >= 3)
    assert.equal(
      summary.mergedRoutes,
      summary.astRoutes + summary.regexFallbackRoutes - summary.duplicateRoutes,
      'merged route accounting is consistent',
    )
    assert.ok(result.frameworksDetected.includes('express'))
    assert.equal(result.requestsUsed, 0, 'Tier-0 extraction never issues live requests')
  })

  test('declared-surface route count does not decrease when a repo is mounted', async (t) => {
    const origin = 'https://app.graphwire.test'
    const reposDir = makeRepoDir(t, 'graphwire-declared-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        "const express = require('express')",
        'const app = express()',
        "app.get('/api/v2/invoices/:id', getInvoice)",
      ].join('\n'),
    })
    const control = await runStaticRecon({ t, origin, openapi: OPENAPI_SPEC })
    const withRepo = await runStaticRecon({ t, reposDir, origin, openapi: OPENAPI_SPEC })

    const key = (endpoint: { method: string; pathTemplate: string }) => `${endpoint.method} ${endpoint.pathTemplate}`
    const controlKeys = new Set(control.endpoints.map(key))
    const repoKeys = new Set(withRepo.endpoints.map(key))
    for (const declared of controlKeys) {
      assert.ok(repoKeys.has(declared), `declared route ${declared} must survive repo ingestion`)
    }
    assert.ok(control.result.declaredSurface && control.result.declaredSurface.endpoints > 0)
    assert.ok((withRepo.result.declaredSurface?.endpoints ?? 0) >= 0)
    assert.ok(withRepo.endpoints.length >= control.endpoints.length)
    assert.equal(control.result.repoStaticExtraction, undefined, 'no repo means no AST summary')
  })
})

describe('v6 graphwire: middleware-aware auth inference', () => {
  test('resolved guard chains tag admin, tenant and unguarded routes', async (t) => {
    const origin = 'https://app.graphwire.test'
    const reposDir = makeRepoDir(t, 'graphwire-guards-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        "const express = require('express')",
        'const app = express()',
        'const api = express.Router()',
        "app.use('/api', api)",
        "api.get('/admin/users', requireAuth, requireAdmin, listUsers)",
        "api.get('/admin/audit', listAudit)",
        "api.patch('/orgs/:orgId/invoices/:id', requireAuth, tenantScope, updateInvoice)",
      ].join('\n'),
    })

    const extracted = extractRepoProgramGraph({ reposDir, origins: [origin] })
    assert.ok(extracted)
    const admin = extracted.routes.find(route => route.pathTemplate === '/api/admin/users')
    assert.equal(admin?.authClass, 'admin')
    assert.equal(admin?.authRequirement, 'admin:requireAuth,requireAdmin')
    assert.deepEqual(admin?.guards, ['requireAuth', 'requireAdmin'])
    const tenant = extracted.routes.find(route => route.pathTemplate === '/api/orgs/:orgId/invoices/:id')
    assert.equal(tenant?.authClass, 'tenant')
    assert.equal(tenant?.ownershipGuard, 'tenantScope')
    const unguarded = extracted.routes.find(route => route.pathTemplate === '/api/admin/audit')
    assert.equal(unguarded?.authClass, 'unguarded')
    assert.equal(unguarded?.authRequirement, null)

    const { endpoints, result } = await runStaticRecon({ t, reposDir, origin })
    const adminEndpoint = endpoints.find(endpoint => endpoint.method === 'GET' && endpoint.pathTemplate === '/api/admin/users')
    assert.ok(adminEndpoint?.authRequirement?.startsWith('admin:'), 'endpoint carries the resolved guard chain')
    assert.deepEqual(result.visibleToPersonas?.['GET /api/admin/users'], ['role:admin'])
    assert.deepEqual(result.visibleToPersonas?.['PATCH /api/orgs/:orgId/invoices/:id'], ['role:tenant'])
    assert.deepEqual(result.visibleToPersonas?.['GET /api/admin/audit'], ['anonymous'])
    const reasons = new Map((result.privilegedEndpoints ?? []).map(entry => [`${entry.method} ${entry.pathTemplate}`, entry.reason]))
    assert.equal(reasons.get('GET /api/admin/users'), 'code_admin_guard')
    assert.equal(reasons.get('GET /api/admin/audit'), 'code_admin_route_unguarded')
  })
})

describe('v6 graphwire: monorepo origin mapping', () => {
  test('multi-origin targets attribute each service route to the right origin', (t) => {
    const reposDir = makeRepoDir(t, 'graphwire-monorepo-')
    writeTree(reposDir, {
      'acme/product/docker-compose.yml': [
        'services:',
        '  api:',
        '    build: ./services/api',
        '    labels:',
        '      traefik.http.routers.api.rule: Host(`api.shop.test`)',
        '  web:',
        '    build: ./services/web',
        '    labels:',
        '      traefik.http.routers.web.rule: Host(`shop.test`)',
      ].join('\n'),
      'acme/product/services/api/Dockerfile': 'FROM node:24\nEXPOSE 8080\n',
      'acme/product/services/web/Dockerfile': 'FROM node:24\nEXPOSE 3000\n',
      'acme/product/services/api/src/routes.ts': [
        'const router = express.Router()',
        "router.get('/v1/accounts', requireAuth, listAccounts)",
      ].join('\n'),
      'acme/product/services/web/src/routes.ts': [
        'const router = express.Router()',
        "router.get('/v1/views', listViews)",
      ].join('\n'),
    })

    const extracted = extractRepoProgramGraph({
      reposDir,
      origins: ['https://api.shop.test', 'https://shop.test'],
    })
    assert.ok(extracted)
    const byPath = new Map(extracted.routes.map(route => [route.pathTemplate, route]))
    assert.equal(byPath.get('/v1/accounts')?.origin, 'https://api.shop.test')
    assert.equal(byPath.get('/v1/accounts')?.originConfidence, 'exact')
    assert.equal(byPath.get('/v1/accounts')?.service, 'api')
    assert.equal(byPath.get('/v1/views')?.origin, 'https://shop.test')
    assert.equal(byPath.get('/v1/views')?.service, 'web')

    const mappings = new Map(extracted.originMappings.map(mapping => [mapping.root, mapping]))
    assert.equal(mappings.get('acme/product/services/api')?.origin, 'https://api.shop.test')
    assert.equal(mappings.get('acme/product/services/web')?.origin, 'https://shop.test')
  })

  test('single-origin runs attribute without service evidence; fallback is explicit', (t) => {
    const reposDir = makeRepoDir(t, 'graphwire-single-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        'const app = express()',
        "app.get('/status', status)",
      ].join('\n'),
    })
    const extracted = extractRepoProgramGraph({ reposDir, origins: ['https://only.example.test'] })
    assert.ok(extracted)
    assert.equal(extracted.routes[0]?.origin, 'https://only.example.test')
    assert.equal(extracted.routes[0]?.originConfidence, 'exact')

    const multi = extractRepoProgramGraph({ reposDir, origins: ['https://a.example.test', 'https://b.example.test'] })
    assert.ok(multi)
    assert.equal(multi.routes[0]?.originConfidence, 'fallback')
    assert.ok((multi.routeOrigins['GET /status']?.evidence ?? []).some(evidence => evidence.includes('origins[0]')))
  })
})

describe('v6 graphwire: code-to-runtime hypotheses', () => {
  test('recon result surfaces typed Program Graph hypotheses', async (t) => {
    const origin = 'https://app.graphwire.test'
    const reposDir = makeRepoDir(t, 'graphwire-hyp-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        "const express = require('express')",
        'const app = express()',
        'const api = express.Router()',
        "app.use('/api', api)",
        "api.get('/admin/audit', listAudit)",
        "api.delete('/admin/users/:id', requireAuth, removeUser)",
      ].join('\n'),
    })
    const { result } = await runStaticRecon({ t, reposDir, origin })
    const hypotheses = result.codeToRuntimeHypotheses ?? []
    assert.ok(hypotheses.length > 0, 'hypotheses are forwarded through the recon result')
    const admin = hypotheses.find(hypothesis => hypothesis.kind === 'admin_route_missing_admin_guard')
    assert.ok(admin, 'expected an unguarded admin route hypothesis')
    assert.equal(admin.path, '/api/admin/audit')
    assert.equal(admin.probeClass, 'auth_bypass')
    assert.ok(hypotheses.some(hypothesis => hypothesis.kind === 'tenant_param_without_scope' && hypothesis.path === '/api/admin/users/:id'))
    assert.ok(hypotheses.every(hypothesis => hypothesis.file.length > 0 && hypothesis.line > 0))
  })
})

describe('v6 graphwire: ranked probe plan (lossless store)', () => {
  function route(over: Partial<StaticExtractedRoute> & Pick<StaticExtractedRoute, 'method' | 'pathTemplate'>): StaticExtractedRoute {
    return {
      framework: 'express',
      authRequirement: null,
      ownershipGuard: null,
      sinkKinds: [],
      riskScore: 50,
      params: [],
      codeLocation: { repo: 'acme/app', file: 'src/app.ts', startLine: 1, endLine: 2 },
      extraction: 'ast',
      authClass: 'unguarded',
      guards: [],
      ...over,
    }
  }

  test('prioritizes hypothesis-linked and mutating/schema routes before clustered long tail', () => {
    const hypothesis: CodeToRuntimeHypothesis = {
      id: 'hyp:admin:r1',
      kind: 'admin_route_missing_admin_guard',
      severity: 'high',
      confidence: 0.8,
      framework: 'express',
      method: 'DELETE',
      path: '/admin/users/:id',
      file: 'src/app.ts',
      line: 3,
      routeId: 'r1',
      rationale: 'unguarded admin route',
      evidence: ['guards=[]'],
      probeClass: 'auth_bypass',
    }
    const routes = [
      route({ method: 'DELETE', pathTemplate: '/admin/users/:id', routeId: 'r1', riskScore: 90 }),
      route({ method: 'PATCH', pathTemplate: '/rest/projects/:id', params: [{ name: 'id', location: 'path', isObjectId: true }], riskScore: 70 }),
      route({ method: 'POST', pathTemplate: '/rest/reports', params: [{ name: 'title', location: 'json', isObjectId: false }], riskScore: 60 }),
      route({ method: 'GET', pathTemplate: '/rest/projects', riskScore: 55 }),
      route({ method: 'GET', pathTemplate: '/rest/billing-docs', riskScore: 54 }),
      route({ method: 'GET', pathTemplate: '/rest/audit-events', riskScore: 53 }),
      route({
        method: 'GET',
        pathTemplate: '/admin/settings',
        authClass: 'admin',
        guards: ['requireAdmin'],
        authRequirement: 'admin:requireAdmin',
        riskScore: 80,
      }),
    ]
    const plan = rankAndClusterAstRoutes({ routes, hypotheses: [hypothesis] })
    assert.equal(plan.totalRoutes, routes.length, 'raw store count stays lossless')
    assert.deepEqual(plan.priority.map(item => item.pathTemplate), ['/admin/users/:id'])
    assert.deepEqual(
      plan.schemaTyped.map(item => `${item.method} ${item.pathTemplate}`).sort(),
      ['GET /admin/settings', 'PATCH /rest/projects/:id', 'POST /rest/reports'],
      'role-exclusive admin and mutating ID/schema routes are tier B',
    )
    assert.deepEqual(
      plan.longTail.map(item => item.pathTemplate).sort(),
      ['/rest/audit-events', '/rest/billing-docs', '/rest/projects'],
    )

    const getCollections = plan.clusters.filter(cluster => cluster.signature.includes('|GET|/rest/'))
    assert.equal(getCollections.length, 1, 'CRUD boilerplate collapses to one structural cluster')
    assert.equal(getCollections[0]?.routes, 3)
    assert.equal(getCollections[0]?.representatives.length, 1, 'one representative is sampled per cluster')
    assert.ok(plan.probeSubset.length < plan.totalRoutes, 'the probe subset is smaller than the lossless store')
    assert.equal(plan.probeSubset.length, plan.priority.length + plan.schemaTyped.length + plan.representatives.length)

    assert.equal(
      astRouteClusterSignature(routes[3]!),
      astRouteClusterSignature(routes[4]!),
      'different resource literals share the CRUD signature',
    )

    const diffHypothesis: CodeToRuntimeHypothesis = {
      id: 'hyp:diff:abc',
      kind: 'recent_diff_touches_sink',
      severity: 'medium',
      confidence: 0.6,
      framework: 'express',
      method: 'GET',
      path: '/rest/audit-events',
      file: 'src/app.ts',
      line: 9,
      sinkKind: 'db_query',
      rationale: 'recent diff touches a sink reachable from this route',
      evidence: ['+1: db.query(...)'],
      probeClass: 'injection',
    }
    const withDiff = rankAndClusterAstRoutes({ routes, hypotheses: [hypothesis, diffHypothesis] })
    assert.ok(
      withDiff.priority.some(item => item.pathTemplate === '/rest/audit-events'),
      'recent-diff hypotheses promote their route into tier A',
    )
  })

  test('guard chain is part of the cluster boundary', () => {
    const guarded = route({
      method: 'GET',
      pathTemplate: '/rest/projects',
      authClass: 'auth',
      guards: ['requireAuth'],
      authRequirement: 'auth:requireAuth',
    })
    const unguarded = route({ method: 'GET', pathTemplate: '/rest/billing-docs' })
    assert.notEqual(astRouteClusterSignature(guarded), astRouteClusterSignature(unguarded), 'unguarded siblings are never merged away')
    const plan = rankAndClusterAstRoutes({ routes: [guarded, unguarded] })
    assert.equal(plan.clusters.length, 2)
    assert.equal(plan.representatives.length, 2, 'each guard class keeps its own representative')
  })

  test('recon reports both lossless store and ranked probe subset', async (t) => {
    const origin = 'https://app.graphwire.test'
    const reposDir = makeRepoDir(t, 'graphwire-plan-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        "const express = require('express')",
        'const app = express()',
        'const v2 = express.Router()',
        "app.use('/rest', v2)",
        "v2.get('/projects', listProjects)",
        "v2.get('/billing-docs', listBilling)",
        "v2.patch('/projects/:id', updateProject)",
        "v2.get('/admin/audit', listAudit)",
      ].join('\n'),
    })
    const { result, endpoints } = await runStaticRecon({ t, reposDir, origin })
    assert.ok(result.probePlan)
    assert.equal(result.probePlan.totalRoutes, result.repoStaticExtraction?.astRoutes)
    assert.ok(result.probePlan.probeSubset <= result.probePlan.totalRoutes)
    assert.ok(result.probePlan.sample.length > 0)
    assert.equal(endpoints.length, result.probePlan.totalRoutes, 'all AST routes remain stored')
  })
})

describe('v6 graphwire: sibling derivation suppression', () => {
  test('declared/AST surface disables speculative collection->item derivation', async (t) => {
    const fx = await startHttpFixture(t, (req, _body, res) => {
      const url = req.url ?? '/'
      if ((req.method ?? 'GET').toUpperCase() === 'OPTIONS') {
        res.statusCode = 204
        res.setHeader('Allow', 'GET, PATCH, DELETE, OPTIONS')
        res.end()
        return
      }
      if (url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end('<html><body><a href="/api/things">things</a></body></html>')
        return
      }
      if (url === '/api/things') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ items: [{ id: 'k-1', label: 'first' }] }))
        return
      }
      res.statusCode = 404
      res.end('{"error":"not found"}')
    })
    const reposDir = makeRepoDir(t, 'graphwire-siblings-')
    writeTree(reposDir, {
      'acme/app/src/app.ts': [
        'const app = express()',
        "app.get('/api/things', listThings)",
      ].join('\n'),
    })

    const { storage } = makeStore(t, 'kovo-v6-graphwire-sib-')
    const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 900 })
    const grant: Grant = makeLabGrant(fx.origin, { tier: 1 })
    const result = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1', KOVO_RECON_SIBLINGS: '1' }, () => runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 1,
      origins: [fx.origin],
      budgetRequests: 900,
      reposDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant,
      signal: AbortSignal.timeout(20_000),
    }))

    assert.equal(result.siblingDerivationSuppressed, 'declared_surface')
    const endpoints = storage.listEndpoints(setup.runId, { origin: fx.origin })
    assert.equal(
      endpoints.filter(endpoint => endpoint.pathTemplate === '/api/things/:id').length,
      0,
      'no speculative item routes are added beside the AST-declared surface',
    )
    assert.equal(
      fx.requests.filter(request => (request.method ?? 'GET').toUpperCase() === 'OPTIONS').length,
      0,
      'suppression also skips sibling OPTIONS probes',
    )
  })
})

describe('v6 graphwire: multi-hop SAST binding', () => {
  const chainFiles = [
    {
      path: 'src/routes/orders.ts',
      content: [
        'const router = express.Router()',
        "router.patch('/orders/:id', handleOrderPatch)",
        'module.exports = router',
      ].join('\n'),
    },
    {
      path: 'src/controllers/order.ts',
      content: [
        'export async function handleOrderPatch(req, res) {',
        '  return loadOrderProfile(req.body.orderId)',
        '}',
      ].join('\n'),
    },
    {
      path: 'src/services/order.ts',
      content: [
        'export async function loadOrderProfile(orderId) {',
        '  return findOrderRow(orderId)',
        '}',
      ].join('\n'),
    },
    {
      path: 'src/repos/order.ts',
      content: [
        'export async function findOrderRow(orderId) {',
        "  return db.query('select * from orders where id = ' + orderId)",
        '}',
      ].join('\n'),
    },
  ]

  test('a 4-hop suspect resolves through the Program Graph edges', () => {
    const graph = extractProgramGraph({ files: chainFiles })
    const callGraph = callGraphFromProgramGraph(graph, { repo: 'acme/app' })
    const viaCallGraph = resolveSuspectEntrypoint(callGraph, { file: 'src/repos/order.ts', line: 2 })
    assert.ok(viaCallGraph)
    assert.equal(viaCallGraph.routePath, '/orders/:id')
    assert.equal(viaCallGraph.httpMethod, 'PATCH')
    assert.equal(viaCallGraph.matchedBy, 'reverse', 'resolution walks repository -> service -> controller -> route')

    const viaProgramGraph = resolveSuspectEntrypoint(undefined, { file: 'src/repos/order.ts', line: 2 }, undefined, {
      programGraph: graph,
      maxHops: 8,
    })
    assert.ok(viaProgramGraph)
    assert.equal(viaProgramGraph.routePath, '/orders/:id')
    assert.deepEqual(viaProgramGraph.paramNames, ['id'])

    const tooShallow = resolveSuspectEntrypoint(callGraph, { file: 'src/repos/order.ts', line: 2 }, undefined, { maxHops: 2 })
    assert.equal(tooShallow, null, 'hop budget bounds the reverse walk')
  })

  test('falls back cleanly when no repo graph is available', async (t) => {
    assert.equal(extractRepoProgramGraph({ origins: ['https://app.graphwire.test'] }), null)
    const emptyDir = makeRepoDir(t, 'graphwire-empty-')
    assert.equal(extractRepoProgramGraph({ reposDir: emptyDir, origins: ['https://app.graphwire.test'] }), null)
    assert.equal(resolveSuspectEntrypoint(undefined, { file: 'src/app.ts', line: 1 }), null)

    const origin = 'https://app.graphwire.test'
    const { result, endpoints } = await runStaticRecon({ t, origin, openapi: OPENAPI_SPEC })
    assert.equal(result.repoStaticExtraction, undefined)
    assert.equal(result.codeToRuntimeHypotheses, undefined)
    assert.ok(endpoints.length >= 3, 'declared surface ingestion is unaffected by the missing repo')
  })
})
