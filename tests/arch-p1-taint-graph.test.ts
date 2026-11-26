/**
 * Regression tests for Architectural Move P1:
 * ProgramGraph-backed Stage-2 call graph + taint-qualified sink filtering.
 *
 * Strictly synthetic fixtures (zero benchmark literals).
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { buildStaticWorkspaceSnapshot } from '../src/server/static-workspace-snapshot.ts'
import {
  analyzeSinkBackwardPaths,
  buildRepoCallGraph,
  inferProjectSecuritySpecDeterministic,
  runThreeStageSemanticAudit,
  toChainStepInputs,
  type SemanticAuditContext,
  type SemanticAuditSuspect,
} from '../src/server/semantic-audit.ts'
import type { Run } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'

function makeWorkspace(t: { after: (fn: () => void) => void }, repo: string, files: Record<string, string>): {
  reposDir: string
} {
  const root = mkdtempSync(join(tmpdir(), 'kovo-arch-p1-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const reposDir = join(root, 'repos')
  const repoRoot = join(reposDir, repo)
  for (const [rel, content] of Object.entries(files)) {
    const full = join(repoRoot, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content, 'utf8')
  }
  return { reposDir }
}

function makeStubRun(origin: string): SemanticAuditContext['run'] & Pick<Run, 'candidates' | 'approved'> {
  return {
    id: 'run-arch-p1',
    projectId: 'proj-arch-p1',
    goal: 'Verify ProgramGraph taint-qualified Stage-2 analysis',
    goalRevision: 1,
    scopeRevision: 1,
    capabilityTier: 1,
    budgetUsd: 5,
    spentUsd: 0,
    budgetRequests: 100,
    spentRequests: 0,
    candidates: [{ id: 'asset-1', origin } as Run['candidates'][number]],
    approved: ['asset-1'],
  }
}

function makeNoScriptSession(): { session: WorkerSession; runScriptCalls: () => number } {
  let calls = 0
  const session = {
    id: 'mock-p1-session',
    async runScript() {
      calls += 1
      throw new Error('runScript must not be called for Stage-2 call-graph extraction')
    },
    async close() {},
  } as unknown as WorkerSession
  return { session, runScriptCalls: () => calls }
}

const throwingBackend = {
  async openSession(): Promise<WorkerSession> {
    throw new Error('openSession should not be called when staticSnapshot serves Stage 1 & 2')
  },
} as unknown as WorkerBackend

describe('Move P1: ProgramGraph + taint-qualified Stage-2 filtering', () => {
  test('unreachable helpers, constant-arg sinks, safe parameterized queries, and ORM calls emit ZERO stage2_backward_taint suspects', async t => {
    const origin = 'https://safe-app.example.test'
    const { reposDir } = makeWorkspace(t, 'acme/safe-app', {
      'src/helpers/maintenance.ts': [
        '// Unreachable utility helpers (never invoked from any HTTP route)',
        'export async function seedDatabase(db: any, tableName: string) {',
        '  return db.query("SELECT * FROM " + tableName)',
        '}',
        'export async function syncRemoteMirror(url: string) {',
        '  return fetch(url)',
        '}',
        'export function readMaintenanceFile(p: string) {',
        '  return fs.readFileSync(p, "utf8")',
        '}',
      ].join('\n'),
      'src/routes/safe.ts': [
        "import express from 'express'",
        "import path from 'node:path'",
        "import fs from 'node:fs'",
        'export const router = express.Router()',
        'export function requireAuth(req: any, _res: any, next: any) { return next() }',
        '',
        'function runStaticReport(db: any, tableName: string) {',
        '  return db.query(`SELECT * FROM ${tableName}`)',
        '}',
        '',
        'export async function getOrder(req: any, res: any) {',
        '  const row = await db.query("SELECT * FROM orders WHERE tenant_id = $1 AND id = $2", [req.tenantId, req.params.id])',
        '  return res.json(row)',
        '}',
        '',
        'export async function getOrderLocalConst(req: any, res: any) {',
        '  const sqlText = "SELECT * FROM orders WHERE id = ?"',
        '  const row = await db.execute(sqlText, [req.params.id])',
        '  return res.json(row)',
        '}',
        '',
        'export async function getOrderTagged(req: any, res: any) {',
        '  const row = await prisma.$queryRaw`SELECT * FROM orders WHERE id = ${req.params.id}`',
        '  return res.json(row)',
        '}',
        '',
        'export async function getOrderOrm(req: any, res: any) {',
        '  const row = await ormSession.query(Order)',
        '  return res.json(row)',
        '}',
        '',
        'export async function notifyWorker(req: any, res: any) {',
        '  const r = await fetch("http://worker-service:9000/settle", {',
        '    method: "POST",',
        '    headers: { "x-user": req.user.id },',
        '    body: JSON.stringify(req.body),',
        '  })',
        '  return res.json({ ok: r.ok })',
        '}',
        '',
        'export function redirectHome(_req: any, res: any) {',
        '  return res.redirect(302, "/dashboard")',
        '}',
        '',
        'export function readSafeAsset(req: any, res: any) {',
        '  const cfg = fs.readFileSync(path.join(__dirname, "config.json"), "utf8")',
        '  const file = fs.readFileSync(path.join("/uploads", path.basename(req.params.name)), "utf8")',
        '  return res.json({ cfg, file })',
        '}',
        '',
        'export function renderSafeView(req: any, res: any) {',
        '  const rev = execSync("git rev-parse HEAD")',
        '  return res.render("orders/show", { id: req.params.id, rev })',
        '}',
        '',
        'export async function dailyMetrics(_req: any, res: any) {',
        '  return res.json(await runStaticReport(db, "daily_metrics"))',
        '}',
        '',
        "router.get('/api/orders/:id', requireAuth, getOrder)",
        "router.get('/api/orders/:id/local', requireAuth, getOrderLocalConst)",
        "router.get('/api/orders/:id/tagged', requireAuth, getOrderTagged)",
        "router.get('/api/orders/:id/orm', requireAuth, getOrderOrm)",
        "router.post('/api/orders/:id/notify', requireAuth, notifyWorker)",
        "router.get('/api/home', requireAuth, redirectHome)",
        "router.get('/api/assets/:name', requireAuth, readSafeAsset)",
        "router.get('/api/views/:id', requireAuth, renderSafeView)",
        "router.get('/api/metrics/daily', requireAuth, dailyMetrics)",
      ].join('\n'),
    })

    const snapshot = buildStaticWorkspaceSnapshot(reposDir)
    const { session, runScriptCalls } = makeNoScriptSession()
    const run = makeStubRun(origin)

    const audit = await runThreeStageSemanticAudit(
      {
        run,
        approvedOrigins: [origin],
        reposDir,
        mountedRepos: ['acme/safe-app'],
        backend: throwingBackend,
        session,
        staticSnapshot: snapshot,
        signal: new AbortController().signal,
      },
      { enableStage1Llm: false, enableStage3GitMiner: false, persistToStore: false },
    )

    assert.equal(runScriptCalls(), 0, 'Stage 2 must not invoke regex runScript fallback')
    const stage2 = audit.rankedSuspects.filter(s => s.stage === 'stage2_backward_taint')
    assert.deepEqual(
      stage2.map(s => `${s.routeOrAction}@${s.file}:${s.line}`),
      [],
      'Unreachable helpers, constant-arg sinks, safe parameterized queries, and ORM queries must not emit stage2_backward_taint suspects',
    )
    assert.equal(toChainStepInputs(run, stage2).length, 0)
  })

  test('real route-reachable untrusted-input sinks indexed by ProgramGraph emit accurate stage2_backward_taint suspects', async t => {
    const origin = 'https://vuln-app.example.test'
    const { reposDir } = makeWorkspace(t, 'acme/vuln-app', {
      'src/routes/orders.ts': [
        "import express from 'express'",
        "import { handleOrderPatch } from '../controllers/order'",
        'export const router = express.Router()',
        'export function requireAuth(req: any, _res: any, next: any) { return next() }',
        "router.patch('/api/v1/orders/:id', requireAuth, handleOrderPatch)",
        "router.get('/api/v1/search', requireAuth, (req: any, res: any) => {",
        '  return res.json(db.query(`SELECT * FROM catalog WHERE q = ${req.query.q}`))',
        '})',
        "router.post('/api/v1/webhooks/test', requireAuth, (req: any, res: any) => {",
        '  return fetch(req.body.targetUrl).then(r => res.json({ ok: r.ok }))',
        '})',
        "router.get('/api/v1/jump', requireAuth, (req: any, res: any) => {",
        '  return res.redirect(req.query.next)',
        '})',
        "router.get('/api/v1/export/:name', requireAuth, (req: any, res: any) => {",
        '  return res.send(fs.readFileSync(path.join("/exports", req.params.name), "utf8"))',
        '})',
      ].join('\n'),
      'src/controllers/order.ts': [
        "import { loadOrderProfile } from '../services/order'",
        'export async function handleOrderPatch(req: any, res: any) {',
        '  const data = await loadOrderProfile(req.params.id)',
        '  return res.json(data)',
        '}',
      ].join('\n'),
      'src/services/order.ts': [
        "import { findOrderRow } from '../repos/order'",
        'export async function loadOrderProfile(orderId: string) {',
        '  return findOrderRow(orderId)',
        '}',
      ].join('\n'),
      'src/repos/order.ts': [
        'export async function findOrderRow(orderId: string) {',
        "  return db.query('SELECT * FROM orders WHERE id = ' + orderId)",
        '}',
      ].join('\n'),
    })

    const snapshot = buildStaticWorkspaceSnapshot(reposDir)
    const { session, runScriptCalls } = makeNoScriptSession()
    const run = makeStubRun(origin)

    const audit = await runThreeStageSemanticAudit(
      {
        run,
        approvedOrigins: [origin],
        reposDir,
        mountedRepos: ['acme/vuln-app'],
        backend: throwingBackend,
        session,
        staticSnapshot: snapshot,
        signal: new AbortController().signal,
      },
      { enableStage1Llm: false, enableStage3GitMiner: false, persistToStore: false },
    )

    assert.equal(runScriptCalls(), 0)
    const stage2 = audit.rankedSuspects.filter(s => s.stage === 'stage2_backward_taint')

    // 4-hop SQLi chain through controller -> service -> repo
    const deepSql = stage2.find(s => s.routeOrAction === '/api/v1/orders/:id' && s.sinkKind === 'db_query')
    assert.ok(deepSql, `expected 4-hop SQLi suspect, got: ${JSON.stringify(stage2.map(s => [s.routeOrAction, s.sinkKind]))}`)
    assert.equal(deepSql.httpMethod, 'PATCH')
    assert.equal(deepSql.file, 'src/repos/order.ts')
    assert.equal(deepSql.line, 2)
    assert.deepEqual(deepSql.paramNames, ['id'])
    assert.match(deepSql.sourceToSinkTrace ?? '', /handleOrderPatch.*loadOrderProfile.*findOrderRow/)

    // Inline template SQLi
    const inlineSql = stage2.find(s => s.routeOrAction === '/api/v1/search' && s.sinkKind === 'db_query')
    assert.ok(inlineSql, 'expected template-interpolated SQLi suspect on /api/v1/search')

    // Dynamic SSRF
    const ssrf = stage2.find(s => s.routeOrAction === '/api/v1/webhooks/test' && s.sinkKind === 'outbound_fetch')
    assert.ok(ssrf, 'expected dynamic outbound_fetch suspect on /api/v1/webhooks/test')
    assert.equal(ssrf.httpMethod, 'POST')

    // Dynamic open redirect
    const redirect = stage2.find(s => s.routeOrAction === '/api/v1/jump' && s.sinkKind === 'redirect')
    assert.ok(redirect, 'expected dynamic redirect suspect on /api/v1/jump')

    // Dynamic file read
    const fileRead = stage2.find(s => s.routeOrAction === '/api/v1/export/:name' && s.sinkKind === 'upload_storage')
    assert.ok(fileRead, 'expected dynamic file path suspect on /api/v1/export/:name')

    // All route-bound Stage-2 suspects promote to chain_steps; unbound non-route Stage-2 suspects are blocked
    const steps = toChainStepInputs(run, stage2)
    assert.equal(steps.length, stage2.length)
    const unboundSuspect: SemanticAuditSuspect = {
      ...deepSql,
      id: 'unbound-1',
      fingerprint: 'unbound-fp',
      routeOrAction: 'orphanHelper',
      httpMethod: undefined,
      reconciledEndpoint: undefined,
      ruleId: undefined,
    }
    assert.equal(toChainStepInputs(run, [unboundSuspect]).length, 0, 'unbound stage2_backward_taint suspect must not enter chain_steps')
  })

  test('worker AST callGraph analyzer is never silently bypassed when staticSnapshot/ProgramGraph is present', async t => {
    const { reposDir } = makeWorkspace(t, 'acme/hybrid', {
      'src/app.ts': [
        "import express from 'express'",
        'const app = express()',
        "app.get('/api/items/:id', (req: any, res: any) => res.json(db.query('SELECT * FROM items WHERE id = ' + req.params.id)))",
      ].join('\n'),
    })
    const snapshot = buildStaticWorkspaceSnapshot(reposDir)
    const spec = inferProjectSecuritySpecDeterministic('acme/hybrid', {
      repo: 'acme/hybrid',
      filesScanned: 1,
      languages: ['typescript'],
      frameworks: ['express'],
      ormLibraries: [],
      authLibraries: [],
      snippets: [],
    }).spec

    let workerCallGraphCalls = 0
    let runScriptCalls = 0
    const workerSession = {
      id: 'worker-spy',
      async callGraph() {
        workerCallGraphCalls += 1
        return {
          filesScanned: 1,
          nodes: [
            { id: 'w-ep', file: 'src/extra.ts', line: 1, symbol: 'GET /api/worker-only', kind: 'entrypoint' as const, httpMethod: 'GET', routePath: '/api/worker-only', guards: [], sanitizers: [], calls: ['wSink'] },
            { id: 'w-sink', file: 'src/extra.ts', line: 5, symbol: 'wSink', kind: 'sink' as const, sinkKind: 'db_query' as const, guards: [], sanitizers: [], calls: [] },
          ],
          edges: [{ fromId: 'w-ep', toId: 'w-sink', file: 'src/extra.ts', line: 2 }],
          taintPaths: [],
        }
      },
      async runScript() {
        runScriptCalls += 1
        throw new Error('regex fallback script must never run')
      },
      async close() {},
    } as unknown as WorkerSession

    const cg = await buildRepoCallGraph(workerSession, 'acme/hybrid', spec, new AbortController().signal, snapshot)
    assert.equal(workerCallGraphCalls, 1, 'session.callGraph must be invoked even when staticSnapshot is present')
    assert.equal(runScriptCalls, 0)
    assert.equal(cg.analyzerSource, 'worker_analyzer')
    assert.ok(cg.nodes.some(n => n.id === 'w-ep'), 'worker AST nodes must be preserved')
    assert.ok(cg.nodes.some(n => n.routePath === '/api/items/:id'), 'ProgramGraph nodes must also be merged')
  })

  test('repos/languages without ProgramGraph or worker AST coverage return cleanly without regex noise', async t => {
    const { reposDir } = makeWorkspace(t, 'acme/php-only', {
      'public/index.php': [
        '<?php',
        'function getUser($pdo, $id) {',
        '  return $pdo->query("SELECT * FROM users WHERE id = 1");',
        '}',
      ].join('\n'),
    })
    const snapshot = buildStaticWorkspaceSnapshot(reposDir)
    const { session, runScriptCalls } = makeNoScriptSession()
    const spec = inferProjectSecuritySpecDeterministic('acme/php-only', {
      repo: 'acme/php-only',
      filesScanned: 1,
      languages: ['php'],
      frameworks: [],
      ormLibraries: [],
      authLibraries: [],
      snippets: [],
    }).spec

    const cg = await buildRepoCallGraph(session, 'acme/php-only', spec, new AbortController().signal, snapshot)
    assert.equal(runScriptCalls(), 0, 'must not invoke brittle regex runScript fallback for uncovered languages')
    assert.equal(cg.nodes.length, 0)
    assert.equal(cg.edges.length, 0)
    assert.equal(analyzeSinkBackwardPaths(cg, spec, { sourceByPath: snapshot.sourceByPath }).length, 0)
  })
})
