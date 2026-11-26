/**
 * Systemic Quality Move Q5 regression tests:
 * - Phase-0 multi-file compose/ingress discovery, spec scaling (no 6-spec drop), raised caps & truncation telemetry
 * - Single-denial auth fallback (no global discoveryPersona wipe) & followed-redirect protectedPaths + param harvesting
 * - ProgramGraph shared-router multi-prefix expansion, unresolved mount warnings, explicit `unmapped` origins,
 *   and first-class cross-service (`client_call`) + async (`async_dispatch`) edge extraction
 * - SemanticAudit structured analyzer warning diagnostics (replacing silent catch swallowing)
 *
 * Strictly synthetic fixtures (zero benchmark literals).
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import {
  extractRepoProgramGraph,
  ingestDeclaredApiSurfaceAsync,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import {
  extractProgramGraph,
  mapServicesToOrigins,
  resolveRouteSinkPaths,
} from '../src/server/program-graph.ts'
import {
  runThreeStageSemanticAudit,
  type SemanticAuditContext,
} from '../src/server/semantic-audit.ts'
import { buildStaticWorkspaceSnapshot } from '../src/server/static-workspace-snapshot.ts'
import { maxParamCandidates, maxWorkerPaths, probeSurface } from '../src/server/surface-engine.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeLabGrant, makeStore, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

function writeTree(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(root, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content, 'utf8')
  }
}

function makeTempDir(t: TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

describe('Q5.1: Multi-file compose/ingress, spec scaling, raised caps & truncation telemetry', () => {
  test('parses ALL compose & ingress files with path-prefix retention and marks unmapped services unmapped (never origins[0])', async t => {
    const reposDir = makeTempDir(t, 'kovo-q5-compose-')
    writeTree(reposDir, {
      'acme/mono/services/billing/Dockerfile': 'FROM node:24\nEXPOSE 4001\n',
      'acme/mono/services/billing/docker-compose.yml': [
        'services:',
        '  billing:',
        '    build: .',
        '    ports:',
        '      - "4001:4001"',
        '    labels:',
        '      - "traefik.http.routers.billing.rule=Host(`billing.shop.test`) && PathPrefix(`/billing`)"',
      ].join('\n'),
      'acme/mono/services/billing/routes.ts': [
        'const app = express()',
        "app.get('/invoices', listInvoices)",
      ].join('\n'),
      'acme/mono/services/portal/compose.prod.yml': [
        'services:',
        '  portal:',
        '    build: .',
        '    ports:',
        '      - "4002:3000"',
      ].join('\n'),
      'acme/mono/services/portal/Dockerfile': 'FROM node:24\nEXPOSE 3000\n',
      'acme/mono/services/portal/routes.ts': [
        'const app = express()',
        "app.get('/home', showHome)",
      ].join('\n'),
      'acme/mono/k8s/ingress-api.yaml': [
        'apiVersion: networking.k8s.io/v1',
        'kind: Ingress',
        'spec:',
        '  rules:',
        '  - host: api.shop.test',
        '    http:',
        '      paths:',
        '      - path: /api',
        '        backend:',
        '          service:',
        '            name: catalog',
      ].join('\n'),
      'acme/mono/k8s/gateway-routes.yaml': [
        'apiVersion: networking.k8s.io/v1',
        'kind: Ingress',
        'spec:',
        '  rules:',
        '  - host: portal.shop.test',
        '    http:',
        '      paths:',
        '      - path: /portal',
        '        backend:',
        '          service:',
        '            name: portal',
      ].join('\n'),
      'acme/mono/services/catalog/Dockerfile': 'FROM node:24\nEXPOSE 4003\n',
      'acme/mono/services/catalog/routes.ts': [
        'const app = express()',
        "app.get('/items', listItems)",
      ].join('\n'),
      // Internal background worker exposing a port not in approved origins -> must stay `unmapped`
      'acme/mono/services/worker/Dockerfile': 'FROM node:24\nEXPOSE 9090\n',
      'acme/mono/services/worker/routes.ts': [
        'const app = express()',
        "app.post('/internal/tick', runTick)",
      ].join('\n'),
    })

    const origins = ['https://billing.shop.test', 'https://api.shop.test', 'https://portal.shop.test']
    const extracted = extractRepoProgramGraph({ reposDir, origins })
    assert.ok(extracted)

    const byPath = new Map(extracted.routes.map(r => [r.pathTemplate, r]))
    assert.equal(byPath.get('/invoices')?.origin, 'https://billing.shop.test')
    assert.equal(byPath.get('/invoices')?.originConfidence, 'exact')
    assert.equal(extracted.routeOrigins['GET /invoices']?.pathPrefix, '/billing')

    assert.equal(byPath.get('/items')?.origin, 'https://api.shop.test')
    assert.equal(byPath.get('/items')?.originConfidence, 'path')
    assert.equal(extracted.routeOrigins['GET /items']?.pathPrefix, '/api')

    assert.equal(byPath.get('/home')?.origin, 'https://portal.shop.test')
    assert.equal(byPath.get('/home')?.originConfidence, 'exact')
    assert.equal(extracted.routeOrigins['GET /home']?.pathPrefix, '/portal')

    // Internal worker must NOT be misattributed to origins[0] (`https://billing.shop.test`)
    assert.equal(byPath.get('/internal/tick')?.origin, undefined)
    assert.equal(byPath.get('/internal/tick')?.originConfidence, 'unmapped')

    // Also verify Phase-0 Tier 0 does not pollute origins[0] with unmapped microservice routes
    const { storage } = makeStore(t, 'kovo-q5-unmapped-')
    const setup = await setupApprovedRun(storage, { seeds: origins })
    const res = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 0,
      origins,
      reposDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeLabGrant(origins[0]!, { tier: 0 }),
      signal: AbortSignal.timeout(15_000),
    })
    assert.equal(res.repoStaticExtraction?.unmappedRoutes, 1)
    const billingEndpoints = storage.listEndpoints(setup.runId, { origin: origins[0]!, limit: 200 })
    assert.ok(billingEndpoints.some(e => e.pathTemplate === '/invoices'))
    assert.ok(!billingEndpoints.some(e => e.pathTemplate === '/internal/tick'), 'unmapped service route must not be persisted under origins[0]')

    // Verify mapServicesToOrigins directly with multiple composeFiles & ingressFiles
    const directMappings = mapServicesToOrigins({
      services: [
        { name: 'svc-a', root: 'a' },
        { name: 'svc-b', root: 'b' },
        { name: 'svc-orphan', root: 'orphan' },
      ],
      origins: ['https://a.example.test', 'https://b.example.test'],
      composeFiles: [
        { path: 'a/docker-compose.yml', content: 'services:\n  svc-a:\n    ports:\n      - "443:8080"\n' },
        { path: 'b/docker-compose.yml', content: 'services:\n  svc-b:\n    labels:\n      - "Host(`b.example.test`) && PathPrefix(`/v2`)"\n' },
      ],
      ingressFiles: [
        { path: 'k8s/ing1.yaml', content: 'spec:\n  rules:\n  - host: a.example.test\n    http:\n      paths:\n      - path: /alpha\n        backend:\n          service:\n            name: svc-a\n' },
      ],
    })
    assert.equal(directMappings.find(m => m.service === 'svc-a')?.pathPrefix, '/alpha')
    assert.equal(directMappings.find(m => m.service === 'svc-b')?.pathPrefix, '/v2')
    assert.equal(directMappings.find(m => m.service === 'svc-orphan')?.confidence, 'unmapped')
    assert.equal(directMappings.find(m => m.service === 'svc-orphan')?.origin, undefined)
  })

  test('ingests more than 6 declared OpenAPI specs (no hard 6-spec drop) and emits structured truncation telemetry', async t => {
    const { storage } = makeStore(t, 'kovo-q5-specs-')
    const origin = 'https://api.specs.test'
    const setup = await setupApprovedRun(storage, { seeds: [origin] })
    const run = storage.run(setup.runId)

    // Store 10 OpenAPI specs on the project (previously specs #7..#10 were silently dropped by `.slice(0, 6)`)
    for (let i = 1; i <= 10; i += 1) {
      storage.upsertProjectSpecRaw(run.projectId, {
        name: `spec-${i}.json`,
        kind: 'openapi',
        origin,
        content: JSON.stringify({
          openapi: '3.0.3',
          info: { title: `Spec ${i}`, version: '1.0' },
          paths: {
            [`/api/spec-${i}/items`]: {
              get: { operationId: `listSpec${i}`, responses: { '200': { description: 'ok' } } },
            },
          },
        }),
      })
    }

    const summary = await ingestDeclaredApiSurfaceAsync({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      origin,
    })
    assert.equal(summary.specs, 10)
    assert.equal(summary.declaredOpsSeen, 10)
    assert.equal(summary.declaredOpsMatched, 10)
    const eps = storage.listEndpoints(setup.runId, { origin, limit: 100 })
    assert.ok(eps.some(e => e.pathTemplate === '/api/spec-10/items'), '10th OpenAPI spec must not be dropped')

    // Repo graph file cap truncation telemetry
    const reposDir = makeTempDir(t, 'kovo-q5-trunc-')
    writeTree(reposDir, {
      'acme/big/a.ts': "const app = express(); app.get('/a', hA)\n",
      'acme/big/b.ts': "const app = express(); app.get('/b', hB)\n",
      'acme/big/c.ts': "const app = express(); app.get('/c', hC)\n",
      'acme/big/d.ts': "const app = express(); app.get('/d', hD)\n",
    })
    const capped = extractRepoProgramGraph({ reposDir, origins: [origin], maxFiles: 2 })
    assert.ok(capped)
    const fileTrunc = capped.truncations.find(tr => tr.category === 'repo_graph_files')
    assert.ok(fileTrunc, 'expected structured truncation record when maxFiles cap is reached')
    assert.equal(fileTrunc.cap, 2)
    assert.ok(fileTrunc.observed >= 4 && fileTrunc.dropped >= 2)

    // Surface engine raised caps & truncation telemetry
    assert.ok(maxWorkerPaths >= 500)
    assert.ok(maxParamCandidates >= 500)
    const fx = await startHttpFixture(t, (_req, _body, res) => {
      res.statusCode = 404
      res.setHeader('Content-Type', 'text/plain')
      res.end('not found')
    })
    const manyPaths = Array.from({ length: maxWorkerPaths + 5 }, (_, idx) => `/p${idx}`)
    const probeRes = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => probeSurface({
      origin: fx.origin,
      mode: 'paths',
      paths: manyPaths,
      wordlists: [],
      maxRequests: 6,
    }, new RequestBroker({ rejectUnauthorized: false }), makeLabGrant(fx.origin, { tier: 2 }), AbortSignal.timeout(15_000)))
    assert.ok(probeRes.truncations?.some(tr => tr.category === 'worker_paths' && tr.dropped === 5))
  })
})

describe('Q5.2: Single-denial auth fallback & followed-redirect protectedPaths + param harvesting', () => {
  test('single-request BrokerDenied falls back anonymously for that request only without wiping discoveryPersona, and harvests followed redirect params', async t => {
    const authHeadersSeen: Array<{ path: string; auth: string | undefined }> = []
    const fx = await startHttpFixture(t, (req, _body, res) => {
      const full = req.url ?? '/'
      const pathOnly = full.split('?')[0] ?? '/'
      authHeadersSeen.push({ path: pathOnly, auth: req.headers.authorization })
      if (pathOnly === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end([
          '<html><body>',
          '<a href="/admin/panel">Admin</a>',
          '<a href="/oauth/start">OAuth</a>',
          '<a href="/api/denied-for-persona">Restricted</a>',
          '<a href="/api/profile">Profile</a>',
          '</body></html>',
        ].join(''))
        return
      }
      if (pathOnly === '/admin/panel') {
        res.statusCode = 302
        res.setHeader('Location', '/login?next=%2Fadmin%2Fpanel&returnUrl=%2Fdashboard')
        res.end()
        return
      }
      if (pathOnly === '/login') {
        res.setHeader('Content-Type', 'text/html')
        res.end('<html><body><h1>Sign in</h1></body></html>')
        return
      }
      if (pathOnly === '/oauth/start') {
        res.statusCode = 302
        res.setHeader('Location', '/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.test%2Fcb&state=xyz&code=abc')
        res.end()
        return
      }
      if (pathOnly === '/oauth/authorize') {
        res.setHeader('Content-Type', 'text/html')
        res.end('<html><body><h1>Authorize</h1></body></html>')
        return
      }
      if (pathOnly === '/api/denied-for-persona') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ publicInfo: true }))
        return
      }
      if (pathOnly === '/api/profile') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ user: req.headers.authorization ? 'owner' : 'anon' }))
        return
      }
      res.statusCode = 404
      res.setHeader('Content-Type', 'text/plain')
      res.end('not found')
    })

    class SinglePathDenyBroker extends RequestBroker {
      override async executeHttp(req: BrokerHttpRequest, grant: Grant, signal: AbortSignal): Promise<BrokerExchangeResult> {
        // Deny persona ONLY on `/api/denied-for-persona` with a message containing "persona"
        if (req.persona === 'owner' && req.pathAndQuery.startsWith('/api/denied-for-persona')) {
          throw new BrokerDenied('Route policy denied persona access on /api/denied-for-persona')
        }
        return super.executeHttp(req, grant, signal)
      }
    }

    const { storage } = makeStore(t, 'kovo-q5-auth-redir-')
    const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 800 })
    const grant = makeLabGrant(fx.origin, { tier: 2 })
    grant.personas = new Map([
      ['owner', {
        id: 'persona-owner',
        handle: 'owner',
        roleLabel: 'owner',
        originAllowlist: [fx.origin],
        authKind: 'bearer' as const,
        headerName: null,
        secret: 'owner-token-q5',
        canaryMarkers: [],
      }],
    ])

    const res = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 2,
      origins: [fx.origin],
      personas: ['owner'],
      budgetRequests: 800,
      broker: new SinglePathDenyBroker({ rejectUnauthorized: false }),
      grant,
      signal: AbortSignal.timeout(20_000),
    }))

    // 1. Single-request BrokerDenied must NOT wipe discoveryPersona globally
    const profileReq = authHeadersSeen.find(r => r.path === '/api/profile')
    assert.ok(profileReq, 'expected /api/profile to be probed')
    assert.equal(profileReq.auth, 'Bearer owner-token-q5', 'discoveryPersona must remain active after a single-path BrokerDenied')
    assert.ok(authHeadersSeen.some(r => r.path === '/api/denied-for-persona' && !r.auth), 'denied path must fall back anonymously')
    assert.ok((res.authRequests ?? 0) >= 2)

    // 2. Followed 3xx redirects (ending in 200) must still harvest redirect target endpoints & query params
    const endpoints = storage.listEndpoints(setup.runId, { origin: fx.origin, limit: 200 })
    const loginEp = endpoints.find(e => e.pathTemplate === '/login' && e.method === 'GET')
    assert.ok(loginEp, 'expected /login redirect target endpoint to be recorded')
    const loginParams = storage.listEndpointParams(setup.runId, loginEp.id).map(p => p.name)
    assert.ok(loginParams.includes('next'), `expected 'next' harvested from followed redirect, got ${loginParams.join(',')}`)
    assert.ok(loginParams.includes('returnUrl'), `expected 'returnUrl' harvested from followed redirect, got ${loginParams.join(',')}`)

    const oauthEp = endpoints.find(e => e.pathTemplate === '/oauth/authorize' && e.method === 'GET')
    assert.ok(oauthEp, 'expected /oauth/authorize redirect target endpoint to be recorded')
    const oauthParams = storage.listEndpointParams(setup.runId, oauthEp.id).map(p => p.name)
    assert.ok(oauthParams.includes('redirect_uri'))
    assert.ok(oauthParams.includes('state'))
    assert.ok(oauthParams.includes('code'))
  })
})

describe('Q5.3: ProgramGraph shared-router mounts, unresolved warnings & cross-service/async edges', () => {
  test('expands shared sub-routers mounted at multiple prefixes, blocks cycles, and warns on unresolved mounts', () => {
    const graph = extractProgramGraph({
      files: [
        {
          path: 'src/shared.ts',
          content: [
            "import express from 'express'",
            'export const sharedRouter = express.Router()',
            'export function listItems(req: any, res: any) { return res.json([]) }',
            "sharedRouter.get('/items', listItems)",
          ].join('\n'),
        },
        {
          path: 'src/app.ts',
          content: [
            "import express from 'express'",
            "import { sharedRouter } from './shared'",
            "import { missingRouter } from './missing'",
            'const app = express()',
            'const loopA = express.Router()',
            'const loopB = express.Router()',
            "app.use('/v1', requireAuth, sharedRouter)",
            "app.use('/v2', requireAdmin, sharedRouter)",
            "app.use('/missing', missingRouter)",
            "app.use('/loop', loopA)",
            "loopA.use('/b', loopB)",
            "loopB.use('/a', loopA)",
            "loopA.get('/ping', pingHandler)",
          ].join('\n'),
        },
      ],
    })

    const v1 = graph.routes.find(r => r.path === '/v1/items')
    const v2 = graph.routes.find(r => r.path === '/v2/items')
    assert.ok(v1, 'expected /v1/items from first shared-router mount')
    assert.ok(v2, 'expected /v2/items from second shared-router mount')
    assert.ok(v1.guards.includes('requireAuth'))
    assert.ok(!v1.guards.includes('requireAdmin'))
    assert.ok(v2.guards.includes('requireAdmin'))
    assert.ok(!v2.guards.includes('requireAuth'))
    assert.ok(graph.warnings.some(w => /Unresolved router mount target.*missingRouter/i.test(w)))
    assert.ok(graph.warnings.some(w => /cyclic router mount/i.test(w)))
  })

  test('extracts first-class client_call and async_dispatch edges and chains resolveRouteSinkPaths across services', () => {
    const graph = extractProgramGraph({
      files: [
        {
          path: 'services/gateway/routes.ts',
          content: [
            "import express from 'express'",
            'const app = express()',
            'export async function createOrder(req: any, res: any) {',
            '  await fetch("http://billing:8080/internal/charge", { method: "POST", body: JSON.stringify(req.body) })',
            '  await orderQueue.add("order.settled", { id: req.body.id })',
            '  await ledgerClient.reconcileEntry(req.body.id)',
            '  return res.json({ ok: true })',
            '}',
            "app.post('/api/orders', requireAuth, createOrder)",
          ].join('\n'),
        },
        {
          path: 'services/billing/routes.ts',
          content: [
            "import express from 'express'",
            'const billingApp = express()',
            'export async function chargeAccount(req: any, res: any) {',
            '  const rows = await db.query("SELECT * FROM accounts WHERE id = " + req.body.id)',
            '  return res.json(rows)',
            '}',
            "billingApp.post('/internal/charge', chargeAccount)",
          ].join('\n'),
        },
        {
          path: 'services/worker/consumer.ts',
          content: [
            'export function handleOrderSettled(job: any) {',
            '  return execSync(job.cmd)',
            '}',
            'orderQueue.process("order.settled", handleOrderSettled)',
          ].join('\n'),
        },
      ],
    })

    const httpClientEdge = graph.edges.find(e => e.kind === 'client_call' && e.protocol === 'http' && e.targetPath === '/internal/charge')
    assert.ok(httpClientEdge, 'expected client_call edge to /internal/charge')
    assert.equal(httpClientEdge.targetService, 'billing')

    const rpcEdge = graph.edges.find(e => e.kind === 'client_call' && e.protocol === 'rpc' && e.targetService === 'ledger')
    assert.ok(rpcEdge, 'expected RPC client_call edge for ledgerClient.reconcileEntry')

    const asyncEdge = graph.edges.find(e => e.kind === 'async_dispatch' && e.protocol === 'queue' && e.channel === 'order.settled')
    assert.ok(asyncEdge, 'expected async_dispatch edge for orderQueue.add("order.settled")')

    // Cross-service & async sink paths must trace back to the upstream gateway route POST /api/orders
    const sinkPaths = resolveRouteSinkPaths(graph)
    const crossHttpSink = sinkPaths.find(p => p.route.path === '/api/orders' && p.sinkKind === 'db_query' && p.sinkFile === 'services/billing/routes.ts')
    assert.ok(crossHttpSink, 'expected resolveRouteSinkPaths to trace POST /api/orders -> client_call -> billing db_query sink')
    const crossAsyncSink = sinkPaths.find(p => p.route.path === '/api/orders' && p.sinkKind === 'command' && p.sinkFile === 'services/worker/consumer.ts')
    assert.ok(crossAsyncSink, 'expected resolveRouteSinkPaths to trace POST /api/orders -> async_dispatch -> worker command sink')
  })
})

describe('Q5.4: SemanticAudit structured analyzer warning diagnostics', () => {
  test('surfaces structured warnings instead of silently swallowing analyzer errors across stages', async t => {
    const reposDir = makeTempDir(t, 'kovo-q5-audit-')
    writeTree(reposDir, {
      'acme/app/src/routes.ts': [
        "import express from 'express'",
        'const app = express()',
        'export async function findUser(req: any, res: any) {',
        '  return res.json(await db.query("SELECT * FROM users WHERE id = " + req.query.id))',
        '}',
        "app.get('/api/users', findUser)",
      ].join('\n'),
    })
    const snapshot = buildStaticWorkspaceSnapshot(reposDir)
    const { storage } = makeStore(t, 'kovo-q5-audit-store-')
    const origin = 'https://audit.example.test'
    const setup = await setupApprovedRun(storage, { seeds: [origin] })

    const failingSession = {
      id: 'failing-session',
      async callGraph() {
        throw new Error('callGraph analyzer crashed')
      },
      async analyze() {
        throw new Error('analyze fallback crashed')
      },
      async runScript() {
        throw new Error('git worker script failed')
      },
      async close() {},
    } as unknown as WorkerSession

    const ctx: SemanticAuditContext = {
      run: storage.run(setup.runId),
      approvedOrigins: [origin],
      reposDir,
      mountedRepos: ['../invalid-repo', 'acme/app'],
      backend: { async openSession() { return failingSession } } as unknown as WorkerBackend,
      session: failingSession,
      staticSnapshot: snapshot,
      storage,
      llmCall: async () => 'NOT_VALID_JSON{{{',
      signal: AbortSignal.timeout(15_000),
    }

    const result = await runThreeStageSemanticAudit(ctx, {
      enableStage1Llm: true,
      enableStage3GitMiner: true,
      persistToStore: false,
    })

    const warnings = result.warnings ?? []
    assert.ok(warnings.some(w => w.stage === 'pipeline' && /invalid repository/i.test(w.message)), 'expected pipeline warning for invalid repo')
    assert.ok(warnings.some(w => w.stage === 'stage1_spec_llm'), 'expected stage1_spec_llm warning on malformed LLM JSON')
    assert.ok(warnings.some(w => w.stage === 'stage2_call_graph' && w.analyzer === 'session.callGraph'), 'expected stage2_call_graph warning for callGraph failure')
    assert.ok(warnings.some(w => w.stage === 'stage2_call_graph' && w.analyzer === 'session.analyze'), 'expected stage2_call_graph warning for analyze failure')
    assert.ok(warnings.some(w => w.stage === 'stage3_git_miner'), 'expected stage3_git_miner warning for git worker failure')

    // Structured event persisted to store
    const events = storage.eventsAfter(setup.runId, 0, 1000)
    assert.ok(events.some(ev => ev.kind === 'semantic_audit.warnings'), 'expected semantic_audit.warnings store event')
    // ProgramGraph fallback still produced call-graph nodes & backward paths
    assert.ok((result.callGraphsByRepo['acme/app']?.nodes ?? 0) > 0)
  })
})
