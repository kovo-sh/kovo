import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import type { TestContext } from 'node:test'
import { promisify } from 'node:util'
import { specialistProfiles } from '../src/domain.ts'
import type { SpecialistProfile } from '../src/domain.ts'
import {
  SPECIALIST_PROFILES,
  filterHandlersForSpecialist,
  resolveSpecialistProfile,
  routeStepToSpecialist,
} from '../src/server/agent-session.ts'
import type { WorkerToolHandlers } from '../src/server/agent-session.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  Execution,
  computeDynamicStepBudget,
  computeMultiTrialFanout,
  convertCodeAuditSuspectsToChainSteps,
  countConsecutiveDrySteps,
} from '../src/server/execution.ts'
import type { LabRunner, LabTargetHandle, StartLabTargetParams } from '../src/server/lab-runner.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import {
  crawlStateGraph,
  extractStaticFrameworkRoutes,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import { retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { ScopedBrowser } from '../src/server/scoped-browser.ts'
import { Store } from '../src/server/store.ts'
import { parseGraphqlSdl, probeDifferential } from '../src/server/surface-engine.ts'
import type { WorkerBackend, WorkerJob, WorkerResult, WorkerSession } from '../src/server/worker-backend.ts'
import {
  baseReplaySpecFields,
  makeLabGrant,
  makeStore,
  makeTempDir,
  setupApprovedRun,
  startHttpFixture,
  startMockLlmServer,
  stopExecution,
  withEnv,
} from './v4-tier-helpers.ts'

const execFileAsync = promisify(execFile)

/** Local air-gapped jq WorkerBackend mock for deterministic non-Docker unit/integration testing. */
function createLocalJqBackend(): WorkerBackend {
  const runJq = async (job: WorkerJob, signal: AbortSignal): Promise<WorkerResult> => {
    const payloadFile = job.files.find(f => f.name === 'replay-results.json')
    const match = /jq\s+'([\s\S]*?)'\s+\/evidence\/replay-results\.json/.exec(job.command)
    if (!payloadFile || !match) {
      return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} }
    }
    const filter = match[1].replaceAll("'\"'\"'", "'")
    const dir = mkdtempSync(join(tmpdir(), 'guardian-m4-jq-'))
    try {
      const inPath = join(dir, 'replay-results.json')
      writeFileSync(inPath, payloadFile.content, 'utf8')
      const { stdout, stderr } = await execFileAsync('jq', ['-c', filter, inPath], {
        signal,
        timeout: job.timeoutMs ?? 15_000,
        maxBuffer: 2 * 1024 * 1024,
      })
      return {
        exitCode: 0,
        stdout,
        stderr,
        outputs: { 'outcome.json': stdout },
      }
    } catch (err) {
      const e = err as { code?: number; stdout?: string; stderr?: string; message?: string }
      return {
        exitCode: typeof e.code === 'number' ? e.code : 1,
        stdout: e.stdout ?? '',
        stderr: e.stderr ?? e.message ?? String(err),
        outputs: {},
      }
    } finally {
      try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
    }
  }

  return {
    run: runJq,
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({
          repo: req.repo,
          enginesRun: req.engines,
          engineStatus: {},
          findings: [],
          totalFindings: 0,
          truncated: false,
          durationMs: 1,
        }),
        runScript: async req => ({
          runtime: req.runtime,
          exitCode: 0,
          stdout: '',
          stderr: '',
          durationMs: 1,
          timedOut: false,
        }),
        verifyStaticAst: async req => ({
          verified: false,
          engine: req.engine,
          repo: req.repo,
          file: req.file,
          startLine: req.startLine,
          endLine: req.endLine,
          matchedLines: [],
          codeExcerpt: '',
          matchCount: 0,
          durationMs: 1,
        }),
        close: async () => undefined,
      }
    },
    async verifyStaticAst(_aid, req) {
      return {
        verified: false,
        engine: req.engine,
        repo: req.repo,
        file: req.file,
        startLine: req.startLine,
        endLine: req.endLine,
        matchedLines: [],
        codeExcerpt: '',
        matchCount: 0,
        durationMs: 1,
      }
    },
  }
}

// ============================================================================
// 1. Phase-0 Recon: 11-Framework Static Extraction & Budget Cap
// ============================================================================

test('M4.1 extractStaticFrameworkRoutes detects all 11 frameworks with params, sinks & guards', (t) => {
  const repoDir = makeTempDir(t, 'guardian-m4-frameworks-')
  const write = (rel: string, content: string) => {
    const full = join(repoDir, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content, 'utf8')
  }

  write('nextapp/app/api/orders/[orderId]/route.ts', 'export async function GET(req: Request) { return db.query("SELECT * FROM orders") }\nexport async function DELETE() {}\n')
  write('nextapp/pages/api/billing/export.ts', 'export default function handler(req: any, res: any) { return fetch(req.body.url) }\n')
  write('nextapp/app/actions.ts', '"use server"\nexport async function updateTenantRole(userId: string) { return db.execute(userId) }\n')
  write('express/routes.ts', 'import express from "express"\nconst app = express()\napp.post("/api/v1/invoices/:invoiceId", requireAuth, (req, res) => { res.json({}) })\n')
  write('fastify/server.ts', 'const fastify = createFastify()\nfastify.get("/api/fast/items/:itemId", async () => ({}))\n')
  write('nest/users.controller.ts', '@Controller("api/nest")\nexport class UsersCtrl {\n  @Get("profile/:id")\n  getProfile() {}\n}\n')
  write('django/urls.py', 'urlpatterns = [path("api/django/orders/<int:order_id>/", view)]\n')
  write('fastapi/main.py', 'from fastapi import FastAPI\n@app.post("/api/fastapi/reports/{report_id}")\ndef create_report(): pass\n')
  write('flask/app.py', 'from flask import Flask\n@app.route("/api/flask/export", methods=["GET", "POST"])\ndef export(): pass\n')
  write('spring/OrderController.java', '@RequestMapping("/api/spring")\npublic class OrderController {\n  @GetMapping("/orders/{id}")\n  public String get() { return ""; }\n}\n')
  write('rails/config/routes.rb', 'get "/api/rails/health", to: "health#show"\nresources :widgets\n')
  write('go/main.go', 'r.GET("/api/go/accounts/:accountId", getAccount)\n')
  write('gql/schema.graphql', 'type Query { me: String }\n')

  const { routes, frameworks } = extractStaticFrameworkRoutes(repoDir)
  for (const fw of ['nextjs', 'express', 'fastify', 'nestjs', 'django', 'fastapi', 'flask', 'spring', 'rails', 'go', 'graphql']) {
    assert.ok(frameworks.includes(fw), `Expected framework "${fw}" to be detected; got: ${frameworks.join(', ')}`)
  }
  assert.ok(routes.some(r => r.framework === 'nextjs' && r.pathTemplate === '/api/orders/:id' && r.method === 'DELETE'))
  assert.ok(routes.some(r => r.framework === 'nextjs' && r.pathTemplate === '/_actions/updateTenantRole' && r.sinkKinds.includes('server_action')))
  assert.ok(routes.some(r => r.framework === 'express' && r.pathTemplate === '/api/v1/invoices/:id' && r.authRequirement === 'requireAuth'))
  const goRoute = routes.find(r => r.framework === 'go' && r.pathTemplate === '/api/go/accounts/:id')
  assert.ok(goRoute, 'Expected Go route')
  assert.ok(goRoute.params.some(p => p.name === 'id' && p.location === 'path' && p.isObjectId === true))
})

test('M4.2 runPhase0Recon enforces min(floor(15% * budgetRequests), 250) cap, Tier-0 offline mode, and OpenAPI/JS/dependency discovery', async (t) => {
  const repoDir = makeTempDir(t, 'guardian-m4-p0-repo-')
  mkdirSync(join(repoDir, 'app/api/secret'), { recursive: true })
  writeFileSync(join(repoDir, 'app/api/secret/route.ts'), 'export async function GET() { return new Response("ok") }\n')

  let liveHits = 0
  const fx = await startHttpFixture(t, (req, _b, res) => {
    liveHits += 1
    const u = new URL(req.url ?? '/', fx.origin)
    if (u.pathname === '/') {
      res.setHeader('Content-Type', 'text/html')
      const links = Array.from({ length: 120 }, (_, i) => `<a href="/page-${i}">P${i}</a>`).join('')
      res.end(`<html><body>${links}<form action="/api/orders" method="POST"><input type="hidden" name="_csrf" value="x"><input name="itemId"></form><script src="/bundle.js"></script></body></html>`)
      return
    }
    if (u.pathname === '/bundle.js') {
      res.setHeader('Content-Type', 'application/javascript')
      res.end('fetch("/api/internal/audit", { method: "POST", body: JSON.stringify({ tenantId: "t1" }) })')
      return
    }
    if (u.pathname === '/openapi.json') {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({
        openapi: '3.0.3',
        paths: {
          '/api/orders': {
            post: { requestBody: { content: { 'application/json': { schema: { properties: { itemId: { type: 'string' } } } } } } },
          },
          '/api/orders/{orderId}': {
            get: { parameters: [{ name: 'orderId', in: 'path' }, { name: 'include', in: 'query' }] },
          },
        },
      }))
      return
    }
    res.statusCode = 404
    res.end('not found')
  })

  // Tier 0: zero live HTTP requests, static routes populated
  const { storage: s0 } = makeStore(t)
  const { runId: r0 } = await setupApprovedRun(s0, { seeds: [fx.origin], tier: 0, budgetRequests: 100 })
  const res0 = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
    runPhase0Recon({
      storage: s0,
      runId: r0,
      scopeRevision: 1,
      tier: 0,
      origins: [fx.origin],
      budgetRequests: 100,
      reposDir: repoDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeLabGrant(fx.origin, { tier: 0 }),
      signal: AbortSignal.timeout(15_000),
    }),
  )
  assert.equal(liveHits, 0, 'Tier 0 must send zero live HTTP requests')
  assert.equal(res0.requestsUsed, 0)
  assert.equal(res0.perOriginCap, 15)
  assert.ok(s0.listEndpoints(r0).some(e => e.pathTemplate === '/api/secret' && e.source === 'repo_ast'))
  assert.ok(s0.run(r0).phase0CompletedAt !== null)

  // Tier 1 with tight budgetRequests = 80 -> perOriginCap = floor(80 * 0.15) = 12
  const { storage: s1 } = makeStore(t)
  const { runId: r1 } = await setupApprovedRun(s1, { seeds: [fx.origin], tier: 1, budgetRequests: 80 })
  const res1 = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
    runPhase0Recon({
      storage: s1,
      runId: r1,
      scopeRevision: 1,
      tier: 1,
      origins: [fx.origin],
      budgetRequests: 80,
      reposDir: repoDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeLabGrant(fx.origin, { tier: 1 }),
      signal: AbortSignal.timeout(15_000),
    }),
  )
  assert.equal(res1.perOriginCap, 12)
  assert.ok(res1.requestsUsed <= 12, `Expected requestsUsed (${res1.requestsUsed}) <= 12`)
  const eps = s1.listEndpoints(r1)
  assert.ok(eps.some(e => e.pathTemplate === '/api/orders'))
  assert.ok(eps.some(e => e.pathTemplate === '/api/orders/{orderId}'))
  assert.ok(eps.some(e => e.pathTemplate === '/api/internal/audit' && e.source === 'js_ast'))
  assert.ok(s1.listApiDependencies(r1).length >= 1, 'Expected producer -> consumer api_dependency edge')

  // Verify ceiling at 250 for very large budgetRequests
  const { storage: s2 } = makeStore(t)
  const { runId: r2 } = await setupApprovedRun(s2, { seeds: [fx.origin], tier: 0, budgetRequests: 50_000 })
  const res2 = await runPhase0Recon({
    storage: s2,
    runId: r2,
    scopeRevision: 1,
    tier: 0,
    origins: [fx.origin],
    budgetRequests: 50_000,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant: makeLabGrant(fx.origin, { tier: 0 }),
    signal: AbortSignal.timeout(10_000),
  })
  assert.equal(res2.perOriginCap, 250)
})

// ============================================================================
// 2. crawlStateGraph: Multi-Persona SPA Crawl, Forms/CSRF, postMessage & Scope
// ============================================================================

test('M4.3 crawlStateGraph crawls personas, intercepts XHR/forms/CSRF/postMessage/storage keys without secret values, and enforces depth/scope bounds', async (t) => {
  const secretVal = 'super-secret-storage-value-9911'
  const fx = await startHttpFixture(t, (req, _b, res) => {
    const auth = req.headers.authorization ?? ''
    const u = new URL(req.url ?? '/', fx.origin)
    if (u.pathname === '/api/admin-panel') {
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ ok: auth === 'Bearer tok-admin' }))
      return
    }
    res.setHeader('Content-Type', 'text/html')
    if (u.pathname === '/') {
      const adminSnippet = auth === 'Bearer tok-admin'
        ? `<a href="/admin">Admin</a><script>fetch('/api/admin-panel')</script>`
        : `<a href="/public-sub">Sub</a>`
      res.end(`<!doctype html><html><body>
        ${adminSnippet}
        <a href="https://thirdparty.example/escape">External</a>
        <form action="/api/profile" method="POST">
          <input type="hidden" name="_csrf" value="csrf_tok_1">
          <input name="displayName">
        </form>
        <script>
          localStorage.setItem('auth_meta', ${JSON.stringify(secretVal)});
          window.addEventListener('message', (e) => { window.__lastMsg = e.data; });
        </script>
      </body></html>`)
      return
    }
    res.end('<!doctype html><html><body><p>Subpage</p></body></html>')
  })

  const { storage } = makeStore(t)
  const { runId, personaMap } = await setupApprovedRun(storage, {
    seeds: [fx.origin],
    tier: 2,
    personas: [{ handle: 'admin', roleLabel: 'Admin', authKind: 'bearer', secret: 'tok-admin' }],
  })
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const browser = new ScopedBrowser(broker)
  t.after(() => browser.close())
  const grant = makeLabGrant(fx.origin, { tier: 2, personas: personaMap })

  const res = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
    crawlStateGraph({
      storage,
      runId,
      scopeRevision: 1,
      origin: fx.origin,
      personas: ['admin'],
      maxPages: 6,
      maxDepth: 1,
      browser,
      grant,
      signal: AbortSignal.timeout(30_000),
    }),
  )

  assert.ok(res.personasCrawled.includes('anonymous'))
  assert.ok(res.personasCrawled.includes('admin'))
  assert.equal(res.hasPostMessageListener, true)
  assert.ok(res.storageKeys.includes('auth_meta'))
  assert.ok(!JSON.stringify(res).includes(secretVal), 'Storage values must NEVER be leaked')
  const eps = storage.listEndpoints(runId)
  assert.ok(eps.some(e => e.pathTemplate === '/api/admin-panel'), 'Expected admin XHR endpoint')
  assert.ok(eps.some(e => e.method === 'POST' && e.pathTemplate === '/api/profile'), 'Expected POST form endpoint')
  assert.ok(!eps.some(e => e.origin.includes('thirdparty.example')), 'Third-party origin must be excluded')
  const params = storage.listEndpointParams(runId)
  assert.ok(params.some(p => p.name === '_csrf' && p.isCsrf === true), 'Expected _csrf flagged isCsrf=true')
})

// ============================================================================
// 3. GraphQL SDL Resolver Fuzzer & graphql_var SQLi Differential
// ============================================================================

test('M4.4 GraphQL SDL fuzzer parses nested types, respects non-DoS bounds, detects nested-edge BOLA, and gates Tier-2 mutations', async (t) => {
  const sdl = `
    type BillingInvoice { id: ID! amount: Int! }
    type Org { id: ID! billingInvoices: [BillingInvoice!]! }
    type User { id: ID! email: String! org: Org! }
    type Query { user(id: ID!, verbose: Boolean!): User }
    type Mutation { promoteUser(id: ID!): User }
  `
  const parsed = parseGraphqlSdl(sdl)
  assert.equal(parsed.queryType, 'Query')
  assert.equal(parsed.mutationType, 'Mutation')
  assert.ok(parsed.types.Query.some(f => f.name === 'user' && f.args.length === 2))
  assert.ok(parsed.types.Org.some(f => f.name === 'billingInvoices' && f.returnTypeName === 'BillingInvoice' && f.isList))

  const seenBodies: string[] = []
  let sawMutation = false
  const fx = await startHttpFixture(t, (req, body, res) => {
    seenBodies.push(body)
    res.setHeader('Content-Type', 'application/json')
    const payload = JSON.parse(body || '{}') as { query?: string }
    const q = payload.query ?? ''
    if (q.includes('__schema')) {
      res.statusCode = 403
      res.end(JSON.stringify({ errors: [{ message: 'Introspection disabled' }] }))
      return
    }
    if (q.startsWith('mutation')) {
      sawMutation = true
      res.end(JSON.stringify({ data: { promoteUser: { id: '1' } } }))
      return
    }
    if (q.includes('billingInvoices')) {
      // Root query runs for both personas; child billingInvoices leaks cross-persona data!
      res.end(JSON.stringify({ data: { user: { id: '1', email: 'a@x', org: { id: 'o1', billingInvoices: [{ id: 'inv_1', amount: 500 }] } } } }))
      return
    }
    res.end(JSON.stringify({ data: { __typename: 'Query' } }))
  })

  const { storage } = makeStore(t)
  const { personaMap } = await setupApprovedRun(storage, {
    seeds: [fx.origin],
    personas: [
      { handle: 'owner', roleLabel: 'Owner', authKind: 'bearer', secret: 'tok-owner' },
      { handle: 'attacker', roleLabel: 'Attacker', authKind: 'bearer', secret: 'tok-attacker' },
    ],
  })

  // Nested BOLA via SDL fallback when introspection is disabled + strict non-DoS bounds
  const res = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
    probeDifferential(
      {
        probeClass: 'graphql_audit',
        origin: fx.origin,
        pathAndQuery: '/graphql',
        sdl,
        ownerPersona: 'owner',
        otherPersona: 'attacker',
      },
      new RequestBroker({ rejectUnauthorized: false }),
      makeLabGrant(fx.origin, { tier: 2, personas: personaMap, isIdempotentPostAllowed: () => true }),
      undefined,
      AbortSignal.timeout(15_000),
    ),
  )

  assert.equal(res.verdict, 'signal')
  assert.ok(res.anomalies.some(a => a.type === 'graphql_nested_bola'), 'Expected graphql_nested_bola anomaly')
  for (const raw of seenBodies) {
    const q = (JSON.parse(raw || '{}') as { query?: string }).query ?? ''
    const depth = (q.match(/\{/g) ?? []).length
    const aliases = (q.match(/\b[a-zA-Z_]\w*\s*:/g) ?? []).length
    assert.ok(depth <= 12, `GraphQL query depth exceeded 12: ${depth}`)
    assert.ok(aliases <= 20, `GraphQL query aliases exceeded 20: ${aliases}`)
  }

  // Public Tier 2 without sandboxWriteAllowlist must block mutation fuzzing
  sawMutation = false
  const pubOrigin = 'https://gql-public.example.invalid'
  let pubSawMutation = false
  const pubBroker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async (_url, _addr, _sig, opts) => {
      try {
        const parsedBody = JSON.parse(opts?.body ?? '{}') as { query?: string }
        if (/^\s*mutation\b/i.test(parsedBody.query ?? '')) pubSawMutation = true
      } catch { /* ignore */ }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"data":{"__typename":"Query"}}', bodyBytes: 31, bodyTruncated: false }
    },
  })
  const pubGrant: Grant = {
    tier: 2,
    allowLocalLab: false,
    sandboxWriteAllowlist: [],
    canRead: o => o === pubOrigin,
    audit: () => undefined,
    isIdempotentPostAllowed: () => true,
  }
  const pubRes = await probeDifferential(
    { probeClass: 'graphql_audit', origin: pubOrigin, pathAndQuery: '/graphql', sdl, testMutations: true },
    pubBroker,
    pubGrant,
    undefined,
    AbortSignal.timeout(10_000),
  )
  assert.equal(pubSawMutation, false, 'Mutations must NOT run on public Tier 2 without sandboxWriteAllowlist')
  assert.ok(pubRes.notes.some(n => /mutation fuzzing skipped/i.test(n)))
})

test('M4.5 sqli_boolean over graphql_var preserves SQL error dialect signal without circuit-open loss', async (t) => {
  const fx = await startHttpFixture(t, (_req, body, res) => {
    res.setHeader('Content-Type', 'application/json')
    if (body.includes("'")) {
      res.statusCode = 500
      res.end(JSON.stringify({ errors: [{ message: 'SQLITE_ERROR: near syntax error' }] }))
      return
    }
    res.end(JSON.stringify({ data: { search: [] } }))
  })
  const res = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () =>
    probeDifferential(
      {
        probeClass: 'sqli_boolean',
        origin: fx.origin,
        pathAndQuery: '/graphql',
        method: 'POST',
        param: 'term',
        paramLocation: 'graphql_var',
        baselineValue: 'hello',
      },
      new RequestBroker({ rejectUnauthorized: false }),
      makeLabGrant(fx.origin, { isIdempotentPostAllowed: () => true }),
      undefined,
      AbortSignal.timeout(15_000),
    ),
  )
  assert.equal(res.verdict, 'signal')
  assert.ok(res.anomalies.some(a => a.type === 'db_error_fingerprint' && a.dialect === 'sqlite'))
})

// ============================================================================
// 4. Dynamic Step Budget Clamping & K=6 Diminishing-Returns Stopping
// ============================================================================

test('M4.6 computeDynamicStepBudget clamps [24..200] and countConsecutiveDrySteps tracks K=6 stopping', async (t) => {
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage)

  // Floor BVA: 0 endpoints + 0 suspects -> 24
  assert.equal(computeDynamicStepBudget(storage, runId), 24)

  // Mid BVA: 25 crown-jewel endpoints (risk >= 80) + 15 suspects -> 65 (> old 32 cap)
  for (let i = 0; i < 25; i += 1) {
    storage.upsertEndpoint({
      runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'POST', pathTemplate: `/api/admin/r${i}`,
      source: 'openapi', riskScore: 85,
    })
  }
  const tmWorker = storage.makeWorker(run, 'threat_model', run.candidates[0], 'TM', 'TM')
  for (let i = 0; i < 15; i += 1) {
    storage.addFact(run, tmWorker, {
      kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: `Suspect ${i}`, data: { file: `f${i}.ts` },
    })
  }
  const midBudget = computeDynamicStepBudget(storage, runId)
  assert.equal(midBudget, 65)
  storage.updateRunDynamicStepBudget(runId, midBudget)
  assert.equal(storage.run(runId).dynamicStepBudget, 65)

  // Ceiling BVA: 100 more crown jewels -> clamped at 200
  for (let i = 0; i < 100; i += 1) {
    storage.upsertEndpoint({
      runId, scopeRevision: 1, origin: 'http://127.0.0.1:9', method: 'GET', pathTemplate: `/api/crown/${i}`,
      source: 'openapi', riskScore: 95,
    })
  }
  assert.equal(computeDynamicStepBudget(storage, runId), 200)

  // K=6 consecutive dry steps: 1 productive step followed by 6 dry completed steps
  const prodWorker = storage.makeWorker(run, 'investigation', run.candidates[0], 'Prod', 'Prod')
  const prodStep = storage.addChainStep(run, {
    title: 'Productive Step', hypothesis: 'Found fact', category: 'broken-access-control', priority: 90,
    targetAssetIds: run.approved,
  })
  storage.addFact(run, prodWorker, { kind: 'endpoint', origin: 'http://127.0.0.1:9', summary: 'Found real lead' })
  storage.updateChainStep(prodStep.id, { status: 'complete', assignedWorkerId: prodWorker.id })
  assert.equal(countConsecutiveDrySteps(storage, run), 0)

  for (let i = 1; i <= 6; i += 1) {
    const w = storage.makeWorker(run, 'investigation', run.candidates[0], `Dry ${i}`, `Dry ${i}`)
    const st = storage.addChainStep(run, {
      title: `Dry Step ${i}`, hypothesis: 'Nothing', category: 'misconfig-exposure', priority: 50,
      targetAssetIds: run.approved,
    })
    // Ensure strictly increasing updatedAt so sort order is deterministic
    storage.client.prepare('UPDATE chain_steps SET status = ?, assigned_worker_id = ?, updated_at = ? WHERE id = ?')
      .run('complete', w.id, Date.now() + i * 10, st.id)
  }
  assert.equal(countConsecutiveDrySteps(storage, run), 6)
})

// ============================================================================
// 5. All 7 Specialist Worker Profiles & Tool Filtering
// ============================================================================

test('M4.7 all 7 specialist worker profiles define scoped tools/skills, enforce turn bounds, and route accurately without skill-name collisions', async (t) => {
  assert.equal(specialistProfiles.length, 7)

  const dummyHandler = async () => ({ ok: true })
  const allHandlers: WorkerToolHandlers = {
    spillOutput: async () => '/evidence/x',
    request_http: dummyHandler,
    request_http_batch: dummyHandler,
    request_http_race: dummyHandler,
    requestHttpRace: dummyHandler,
    inspect_dns: dummyHandler,
    inspect_tls: dummyHandler,
    browser_visit: dummyHandler,
    browser_session: dummyHandler,
    crawl_state_graph: dummyHandler,
    probe_websocket: dummyHandler,
    probe_surface: dummyHandler,
    probe_differential: dummyHandler,
    run_safe_templates: dummyHandler,
    run_sast_scan: dummyHandler,
    run_offline_script: dummyHandler,
    derive_evidence: dummyHandler,
    analyze_artifact: dummyHandler,
    query_cves: dummyHandler,
    mint_canary: dummyHandler,
    check_canary: dummyHandler,
    mint_second_order_canary: dummyHandler,
    list_second_order_canaries: dummyHandler,
    verify_replay_spec: dummyHandler,
    propose_chain_finding: dummyHandler,
    update_proposed_finding: dummyHandler,
    record_fact: dummyHandler,
    record_coverage: dummyHandler,
    search_facts: dummyHandler,
    search_exchanges: dummyHandler,
    get_exchange: dummyHandler,
    read_peer_trace: dummyHandler,
    expand_digest: dummyHandler,
    load_skill: dummyHandler,
    suggest_candidate_host: dummyHandler,
    complete_intent: dummyHandler,
  }

  for (const id of specialistProfiles) {
    const cfg = resolveSpecialistProfile(id)
    assert.equal(cfg.id, id)
    assert.ok(cfg.defaultMaxTurns >= 25 && cfg.defaultMaxTurns <= 40, `${id} defaultMaxTurns out of 25..40`)
    assert.ok(cfg.maxTurnsCeiling <= 60, `${id} maxTurnsCeiling > 60`)
    assert.ok(cfg.skills.length >= 2, `${id} must declare curated skills`)
    const filtered = filterHandlersForSpecialist(allHandlers, cfg)
    const keys = Object.keys(filtered)
    assert.ok(keys.includes('verify_replay_spec'), `${id} must include verify_replay_spec`)
    assert.ok(keys.includes('complete_intent'), `${id} must include complete_intent`)
    assert.ok(keys.includes('propose_chain_finding'), `${id} must include propose_chain_finding`)
  }

  // Scoped isolation checks
  const bolaTools = Object.keys(filterHandlersForSpecialist(allHandlers, SPECIALIST_PROFILES['bola-bfla-specialist']))
  assert.ok(bolaTools.includes('probe_differential') && bolaTools.includes('request_http'))
  assert.ok(!bolaTools.includes('browser_visit') && !bolaTools.includes('probe_websocket'))

  const browserTools = Object.keys(filterHandlersForSpecialist(allHandlers, SPECIALIST_PROFILES['client-browser-dom-specialist']))
  assert.ok(browserTools.includes('browser_visit') && browserTools.includes('browser_session') && browserTools.includes('crawl_state_graph') && browserTools.includes('probe_websocket'))

  assert.throws(() => resolveSpecialistProfile('nonexistent-specialist'), /Unknown specialist profile/i)

  // Routing accuracy across all 7 profiles (including skills=['bola-idor-race'] regression guard)
  const cases: Array<[Parameters<typeof routeStepToSpecialist>[0], SpecialistProfile]> = [
    [{ title: 'GraphQL nested resolver BOLA', endpoint: '/graphql', skills: ['bola-idor-race'] }, 'graphql-api-specialist'],
    [{ title: 'Cache poisoning X-Forwarded-Host', category: 'misconfig-exposure', skills: ['bola-idor-race'] }, 'protocol-cache-edge-specialist'],
    [{ title: 'Coupon double-spend race', category: 'business-logic-race', hypothesis: 'race_burst' }, 'business-logic-race-specialist'],
    [{ title: 'DOM XSS innerHTML sink', category: 'cors-client-side' }, 'client-browser-dom-specialist'],
    [{ title: 'JWT alg=none bypass', category: 'auth-session' }, 'auth-session-oauth-specialist'],
    [{ title: 'SQLi on /search?q=', category: 'injection-input' }, 'injection-parser-specialist'],
    [{ title: 'Cross-tenant IDOR on /orders/{id}', category: 'broken-access-control', skills: ['bola-idor-race'] }, 'bola-bfla-specialist'],
  ]
  for (const [input, expected] of cases) {
    assert.equal(routeStepToSpecialist(input), expected)
  }

  // convertCodeAuditSuspectsToChainSteps preserves exact specialist routing in SQLite
  const { storage } = makeStore(t)
  const { runId, run } = await setupApprovedRun(storage)
  const tmWorker = storage.makeWorker(run, 'threat_model', run.candidates[0], 'TM', 'TM')
  const suspects = [
    storage.addFact(run, tmWorker, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'Cross-tenant IDOR on /orders/:id', data: { category: 'broken-access-control', endpoint: '/orders/:id' } }),
    storage.addFact(run, tmWorker, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'Cache poisoning X-Forwarded-Host', data: { category: 'misconfig-exposure', endpoint: '/home' } }),
    storage.addFact(run, tmWorker, { kind: 'code_audit_suspect', origin: 'http://127.0.0.1:9', summary: 'SQL injection on /search', data: { category: 'injection-input', endpoint: '/search' } }),
  ]
  convertCodeAuditSuspectsToChainSteps(storage, run, suspects)
  const steps = storage.listChainSteps(runId)
  assert.equal(steps.find(s => s.title.includes('IDOR'))?.specialistProfile, 'bola-bfla-specialist')
  assert.equal(steps.find(s => s.title.includes('Cache'))?.specialistProfile, 'protocol-cache-edge-specialist')
  assert.equal(steps.find(s => s.title.includes('SQL'))?.specialistProfile, 'injection-parser-specialist')
})

// ============================================================================
// 6. Multi-Trial Parallel Branching + Early-Stopping Cancellation
// ============================================================================

test('M4.8 computeMultiTrialFanout BVA and live Execution multi-trial early stopping cancels sibling & emits trial.early_stopped', async (t) => {
  const highFacts = new Set(['fact-suspect-1'])
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 4 }, { priority: 40, dependsOnFactIds: [], trialGroupId: null }, highFacts), 1)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 4 }, { priority: 88, dependsOnFactIds: [], trialGroupId: null }, highFacts), 2)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 4 }, { priority: 96, dependsOnFactIds: [], trialGroupId: null }, highFacts), 3)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 2 }, { priority: 99, dependsOnFactIds: [], trialGroupId: null }, highFacts), 2)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 4 }, { priority: 60, dependsOnFactIds: ['fact-suspect-1'], trialGroupId: null }, highFacts), 2)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: false, workerConcurrency: 4 }, { priority: 99, dependsOnFactIds: ['fact-suspect-1'], trialGroupId: null }, highFacts), 1)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 4 }, { priority: 99, dependsOnFactIds: [], trialGroupId: 'grp-1' }, highFacts), 1)

  // Live Execution multi-trial test with local jq backend (zero Docker dependency)
  const slowTimers = new Set<ReturnType<typeof setTimeout>>()
  t.after(() => {
    for (const timer of slowTimers) clearTimeout(timer)
    slowTimers.clear()
  })
  const fx = await startHttpFixture(t, async (req, _b, res) => {
    if (req.url === '/slow-sibling') {
      await new Promise<void>(resolve => {
        const done = () => {
          clearTimeout(timer)
          slowTimers.delete(timer)
          resolve()
        }
        const timer = setTimeout(done, 30_000)
        timer.unref?.()
        slowTimers.add(timer)
        res.once('close', done)
      })
      if (res.writableEnded || res.destroyed) return
    }
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (reqUrl.searchParams.get('id')?.includes("'")) {
      res.statusCode = 500
      res.setHeader('Content-Type', 'text/plain')
      res.end('SQLITE_ERROR: near syntax error')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ ok: true }))
  })

  let llmCalls = 0
  let trialCalls = 0
  const llm = await startMockLlmServer(t, (call) => {
    llmCalls += 1
    const bodyText = JSON.stringify(call.body.input ?? '')
    // The mock must not depend on prompt wording (v5 adds board/trial text): the first trial model
    // call becomes the slow sibling, the second proposes immediately so early-stop can cancel it.
    const trialPrompt = bodyText.includes('Crown Jewel Auth Bypass Check')
    if (trialPrompt) trialCalls += 1
    if (bodyText.includes('c_sib_req')) {
      return {
        type: 'tool_call',
        callId: `c_sib_done_${llmCalls}`,
        name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'ruled_out', summary: 'slow sibling' }),
      }
    }
    if (trialPrompt && trialCalls === 1) {
      return {
        type: 'tool_call',
        callId: 'c_sib_req',
        name: 'request_http',
        argumentsJson: JSON.stringify({ origin: fx.origin, method: 'GET', pathAndQuery: '/slow-sibling' }),
      }
    }
    if (bodyText.includes('c_win_m4')) {
      return {
        type: 'tool_call',
        callId: `c_done_${llmCalls}`,
        name: 'complete_intent',
        argumentsJson: JSON.stringify({ status: 'proved', summary: 'Confirmed crown-jewel flaw' }),
      }
    }
    return {
      type: 'tool_call',
      callId: 'c_win_m4',
      name: 'propose_chain_finding',
      argumentsJson: JSON.stringify({
        counterevidence: 'Control endpoint returns leaked=false while probe returns leaked=true.',
        confidenceRationale: 'Deterministic replay differential confirmed bypass.',
        chainFactIds: [],
        exchangeIds: [],
        verifyNow: true,
        replaySpec: {
          ...baseReplaySpecFields(fx.origin),
          title: 'Crown Jewel SQL Injection',
          category: 'injection-input',
          cwe: 'CWE-89',
          severity: 'critical',
          kind: 'http_chain',
          assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 500 and (.steps.p1.body | contains("SQLITE_ERROR"))), observed: (.steps.p1.status | tostring), expected: "200 without SQLITE_ERROR" }',
          steps: [
            { id: 'c1', role: 'control', description: 'Control', request: { origin: fx.origin, method: 'GET', pathAndQuery: '/probe?id=1' } },
            { id: 'p1', role: 'probe', description: 'Probe', request: { origin: fx.origin, method: 'GET', pathAndQuery: "/probe?id=1'" } },
          ],
        },
      }),
    }
  })

  const { storage } = makeStore(t)
  await saveModelProfile({
    name: 'M4-Tactical', endpoint: llm.endpoint, model: 'mock-t', protocol: 'responses', key: 'sk-m4-12345678',
    priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'medium', roleAffinity: 'tactical',
    inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, { seeds: [fx.origin] })
  // Seed a single priority-90 crown-jewel step and let Execution expand it into 2 trials sharing trialGroupId
  storage.addChainStep(run, {
    title: 'Crown Jewel Auth Bypass Check',
    hypothesis: 'Test auth bypass on /probe',
    category: 'auth-session',
    priority: 90,
    targetAssetIds: run.approved,
    sourceOrigins: [fx.origin],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 2, multiTrialEnabled: true })

  const engine = new Execution(storage, { backend: createLocalJqBackend() })
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 25_000
    while (Date.now() < deadline) {
      const steps = storage.listChainSteps(runId)
      if (steps.length >= 2 && steps.some(s => s.status === 'canceled')) break
      await new Promise(r => setTimeout(r, 50))
    }
    await stopExecution(engine as never)
  })

  const steps = storage.listChainSteps(runId)
  assert.equal(steps.length, 2, 'Expected priority 90 lead to fan out to 2 trials')
  assert.ok(steps[0].trialGroupId && steps[0].trialGroupId === steps[1].trialGroupId, 'Both trials must share trialGroupId')
  assert.deepEqual(steps.map(s => s.trialIndex).sort(), [0, 1])
  assert.ok(steps.some(s => s.status === 'canceled'), 'Sibling trial must be canceled on confirmation')
  const events = storage.client.prepare('SELECT kind FROM events WHERE run_id = ?').all(runId) as Array<{ kind: string }>
  assert.ok(events.some(e => e.kind === 'trial.early_stopped'), 'Expected trial.early_stopped SSE event')
})

// ============================================================================
// 7. LabRunner Lifecycle Hook Wiring & CWE-639 requireControlNonError Check
// ============================================================================

test('M4.9 Execution wires LabRunner startLabTarget -> expose origin -> teardown when local-lab labConfig.enabled', async (t) => {
  const fx = await startHttpFixture(t, (_req, _b, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ ok: true }))
  })
  const { dir, storage } = makeStore(t)
  const { runId, projectId } = await setupApprovedRun(storage, {
    environment: 'local-lab',
    seeds: ['http://127.0.0.1:19999'],
    tier: 1,
    labConfig: { enabled: true, image: 'node:24-bookworm-slim', startCommand: 'node server.mjs', internalPort: 3000 },
  })
  // Mount a dummy repo directory at projectReposDir(dir, projectId)/<owner>/<repo>
  const repoDir = join(dir, 'repos', projectId, 'local', 'app')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.mjs'), 'console.log("ok")\n')

  const startedCalls: StartLabTargetParams[] = []
  const stoppedRunIds: string[] = []
  let stopAllCalled = false
  const mockLabRunner = {
    async startLabTarget(params: StartLabTargetParams): Promise<LabTargetHandle> {
      startedCalls.push(params)
      return {
        targetId: 'lab-mock-1',
        runId: params.runId,
        networkName: 'guardian-lab-mock',
        containerName: 'guardian-lab-app',
        containerNames: ['guardian-lab-app'],
        containerIp: '172.30.0.2',
        imageName: 'node:24-bookworm-slim',
        origin: fx.origin,
        baseUrls: { app: fx.origin },
        hostPort: Number(new URL(fx.origin).port),
        internalPort: 3000,
        healthPath: '/health',
        sanitizedRepoDir: params.repoDir,
        seededPersonas: [],
        startedAt: Date.now(),
        stop: async () => { stoppedRunIds.push(params.runId) },
      }
    },
    async stopLabTarget(rid: string) { stoppedRunIds.push(rid) },
    async stopAll() { stopAllCalled = true },
  } as unknown as LabRunner

  storage.updateRun(runId, { phase: 'threat_model', status: 'running' })
  const engine = new Execution(storage, { labRunner: mockLabRunner, backend: createLocalJqBackend() })
  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 6_000
    while (Date.now() < deadline && startedCalls.length === 0) {
      await new Promise(r => setTimeout(r, 50))
    }
    // Wait briefly for lab.started event & origin exposure
    const evDeadline = Date.now() + 3_000
    while (Date.now() < evDeadline) {
      const evs = storage.client.prepare('SELECT kind FROM events WHERE run_id = ?').all(runId) as Array<{ kind: string }>
      if (evs.some(e => e.kind === 'lab.started')) break
      await new Promise(r => setTimeout(r, 40))
    }
    assert.equal(startedCalls.length, 1, 'Expected LabRunner.startLabTarget to be invoked once')
    assert.equal(engine.getLabTargetHandle(runId)?.origin, fx.origin)
    const updatedRun = storage.run(runId)
    assert.ok(updatedRun.candidates.some(c => c.origin === fx.origin && updatedRun.approved.includes(c.id)), 'Booted local-lab origin must be exposed in approved run scope')
    // Mark run complete and trigger tick teardown
    storage.updateRun(runId, { status: 'complete' })
    engine.wake()
    await new Promise(r => setTimeout(r, 100))
    await stopExecution(engine as never)
  })

  assert.ok(stoppedRunIds.includes(runId) || stopAllCalled, 'Expected LabRunner teardown on run completion / stop')
  assert.equal(engine.getLabTargetHandle(runId), undefined)
})

test('M4.10 replay-verifier requireControlNonError under CWE-639 allows explicitly asserted probe 500, rejects unexpected control 500, and supports retest fixed transition', async (t) => {
  let patched = false
  let breakControl = false
  const fx = await startHttpFixture(t, (req, _b, res) => {
    const u = new URL(req.url ?? '/', fx.origin)
    const id = u.searchParams.get('id') ?? '1'
    if (breakControl && id === '1') {
      res.statusCode = 500
      res.end('Internal Error')
      return
    }
    if (!patched && id.includes("'")) {
      res.statusCode = 500
      res.end('SQLITE_ERROR: near syntax error')
      return
    }
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ id, ok: true }))
  })

  const spec = {
    ...baseReplaySpecFields(fx.origin),
    cwe: 'CWE-639',
    category: 'broken-access-control',
    kind: 'http_chain' as const,
    assertionsJq: '{ controlPassed: (.steps.c1.status == 200), confirmed: (.steps.p1.status == 500 and (.steps.p1.body | contains("SQLITE_ERROR"))), observed: ("status=" + (.steps.p1.status | tostring)), expected: "HTTP 200 without SQLITE_ERROR" }',
    steps: [
      { id: 'c1', role: 'control' as const, description: 'Numeric ID', request: { origin: fx.origin, method: 'GET' as const, pathAndQuery: '/api/orders?id=1' } },
      { id: 'p1', role: 'probe' as const, description: 'Quote injection', request: { origin: fx.origin, method: 'GET' as const, pathAndQuery: "/api/orders?id=1'" } },
    ],
  }

  const broker = new RequestBroker({ rejectUnauthorized: false })
  const backend = createLocalJqBackend()
  const grant = makeLabGrant(fx.origin)

  await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, async () => {
    // 1. Control=200, Probe=500 asserted in jq -> confirmed even under CWE-639 default requireControlNonError=true
    const confirmed = await verifyReplaySpec({ spec, broker, backend, grant, signal: AbortSignal.timeout(15_000) })
    assert.equal(confirmed.verdict, 'confirmed', `Expected confirmed, got ${confirmed.verdict}: ${confirmed.outcome.reason}`)

    // 2. Control=500 (unexpected!) -> forced inconclusive by requireControlNonError
    breakControl = true
    const brokenCtrl = await verifyReplaySpec({ spec, broker, backend, grant, signal: AbortSignal.timeout(15_000) })
    assert.equal(brokenCtrl.verdict, 'inconclusive')
    assert.match(brokenCtrl.outcome.reason ?? '', /requireControlNonError/i)

    // 3. Patch applied -> Control=200, Probe=200 -> retestReplaySpec reports fixed
    breakControl = false
    patched = true
    const afterFix = await retestReplaySpec({ spec, broker, backend, grant, signal: AbortSignal.timeout(15_000) })
    assert.equal(afterFix.verdict, 'fixed')
  })
})
