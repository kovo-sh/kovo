import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import {
  hasCuratedAdvisory,
  parseDependencyManifests,
  queryCves,
  templateIdsForCves,
  versionSatisfiesRange,
} from '../src/server/cve-broker.ts'
import {
  detectUnconditionalCallerBreak,
  generateAndReviewPatch,
} from '../src/server/patch-workflow.ts'
import {
  extractRemovedGuardsFromDiff,
  generateVariantSweepQueries,
  reconcileSuspectWithEndpoints,
  resolveSuspectEntrypoint,
  routeTemplateParamNames,
  type CallGraphIndex,
  type SemanticAuditContext,
} from '../src/server/semantic-audit.ts'
import { runSafeTemplates } from '../src/server/surface-engine.ts'
import {
  loadSafeTemplates,
  selectTemplatesForTech,
  vendorApplianceTechTags,
} from '../src/templates/loader.ts'
import {
  mergeTechTags,
  techTagsFromManifests,
  techTagsFromResponse,
} from '../src/templates/tech-tags.ts'
import { transpileNucleiTemplate } from '../scripts/transpile-nuclei-templates.ts'
import { buildCallGraphFromFiles } from '../worker/analyzers.ts'
import { makeLabGrant, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))
const compiledDir = join(repoRoot, 'src', 'templates', 'compiled')

// ============================================================================
// M4-T1: Compiled corpus is modern, ranked, and free of appliance noise
// ============================================================================

test('M4-T1: compiled corpus includes 2021+ CVEs and Express limit 60 selects 0 appliance templates', () => {
  const compiled = loadSafeTemplates({ dir: compiledDir, refresh: true })
  assert.equal(compiled.errors.length, 0, `compiled template errors: ${JSON.stringify(compiled.errors.slice(0, 2))}`)
  assert.ok(compiled.templates.length >= 1000, `expected >= 1000 compiled templates, got ${compiled.templates.length}`)

  const modern = compiled.templates.filter(t => t.cve && Number(t.cve.split('-')[1]) >= 2021)
  assert.ok(modern.length >= 100, `expected a meaningful modern CVE set, got ${modern.length}`)
  const years = new Set(modern.map(t => Number(t.cve!.split('-')[1])))
  assert.ok(years.has(2021), 'expected >= 2021 CVEs in compiled inventory')
  assert.ok(years.has(2025) || years.has(2026), 'expected 2025/2026 CVEs in compiled inventory')

  const expressSel = selectTemplatesForTech(compiled.templates, { techTags: ['express'], tier: 2, maxTemplates: 60 })
  assert.equal(expressSel.selected.length, 60)
  const appliance = expressSel.selected.filter(t => t.tech.some(tag => vendorApplianceTechTags.has(tag)))
  assert.deepEqual(appliance.map(t => t.id), [], 'Express target must never select vendor appliance templates')
  assert.ok(expressSel.selected.some(t => t.tech.includes('express')), 'expected Express-specific templates')

  // Empty fingerprint still runs universal exposure checks (never appliance checks).
  const genericSel = selectTemplatesForTech(compiled.templates, { techTags: [], tier: 2, maxTemplates: 60 })
  assert.ok(genericSel.selected.some(t => t.tech.includes('generic-web-exposure')), 'expected generic-web-exposure templates with an empty fingerprint')
  assert.equal(genericSel.selected.filter(t => t.tech.some(tag => vendorApplianceTechTags.has(tag))).length, 0)

  // Ranking: a legacy (<2021) CVE must not outrank a modern one for the same stack.
  const ranked = selectTemplatesForTech(compiled.templates, { techTags: [], tier: 2, maxTemplates: 400 }).selected
  const firstLegacy = ranked.findIndex(t => t.cve && Number(t.cve.split('-')[1]) < 2021)
  const firstModern = ranked.findIndex(t => t.cve && Number(t.cve.split('-')[1]) >= 2021)
  if (firstLegacy >= 0 && firstModern >= 0) assert.ok(firstModern < firstLegacy, 'modern CVEs must rank ahead of legacy CVEs')
})

test('M4-T2: transpiler splits generic into generic-web-exposure and vendor appliance tags (AEM is not GraphQL)', () => {
  const base = (id: string, name: string, path: string, tags: string) => [
    `id: ${id}`,
    'info:',
    `  name: ${name}`,
    '  severity: high',
    `  tags: ${tags}`,
    'http:',
    '  - method: GET',
    `    path: ["${path}"]`,
    '    matchers:',
    '      - type: word',
    '        part: body',
    '        words: [example]',
  ].join('\n')

  const aem = transpileNucleiTemplate(base('aem-querybuilder-bypass', 'AEM QueryBuilder Bypass', '/bin/querybuilder.json', 'aem,graphql'))
  assert.equal(aem.ok, true)
  if (aem.ok) {
    assert.ok(aem.template.tech.includes('aem'), `AEM template tagged ${aem.template.tech.join(',')}`)
    assert.ok(!aem.template.tech.includes('graphql'), 'AEM appliance template must not be mis-tagged as GraphQL')
  }

  const exposure = transpileNucleiTemplate(base('env-file-exposed-generic', 'Environment File Exposed', '/.env', 'exposure,misconfig'))
  assert.equal(exposure.ok, true)
  if (exposure.ok) assert.ok(exposure.template.tech.includes('generic-web-exposure'), `exposure template tagged ${exposure.template.tech.join(',')}`)
})

// ============================================================================
// M4-T3: Multi-framework call graph (NestJS, Express mounts, TS aliases, Next)
// ============================================================================

test('M4-T3: call graph resolves NestJS ClassMethod, Express app.use prefix+middleware, .js->.ts + @/* aliases, Next app routes', () => {
  const files = [
    { file: 'tsconfig.json', content: JSON.stringify({ compilerOptions: { baseUrl: '.', paths: { '@/*': ['src/*'] } } }) },
    {
      file: 'src/users.controller.ts',
      content: [
        "import { Controller, Get, UseGuards } from '@nestjs/common'",
        "@Controller('users')",
        'export class UsersController {',
        "  @Get(':id')",
        "  @UseGuards(AuthGuard('jwt'))",
        '  findOne(req: any) { return this.repo.findById(req.params.id) }',
        '}',
      ].join('\n'),
    },
    { file: 'src/db.ts', content: 'export function q(db: any, id: string) { return db.query("SELECT * FROM users WHERE id=" + id) }\n' },
    {
      file: 'src/routes.ts',
      content: [
        "import { q } from '@/db.js'",
        "import { Router } from 'express'",
        'const router = Router()',
        "router.get('/orders', (req, res) => res.json(q(db, req.query.id)))",
      ].join('\n'),
    },
    {
      file: 'src/server.ts',
      content: [
        "import express from 'express'",
        "import router from './routes.js'",
        'const app = express()',
        "app.use('/api/v1', requireAuth, router)",
      ].join('\n'),
    },
    {
      file: 'src/app/(admin)/orders/[id]/route.ts',
      content: 'export async function GET(req: Request) { return Response.json({ ok: true }) }\n',
    },
  ]
  const cg = buildCallGraphFromFiles(files)
  const routes = cg.nodes.filter(n => n.kind === 'entrypoint')
  const byPath = new Map(routes.map(n => [n.routePath, n]))

  const nest = byPath.get('/users/:id')
  assert.ok(nest, `expected NestJS route /users/:id in ${[...byPath.keys()].join(',')}`)
  assert.equal(nest.httpMethod, 'GET')
  assert.ok(nest.guards.some(g => /AuthGuard|UseGuards|jwt/i.test(g)), `expected NestJS guard, got ${nest.guards.join(',')}`)

  const express = byPath.get('/api/v1/orders')
  assert.ok(express, 'expected Express mount prefix /api/v1/orders')
  assert.equal(express.httpMethod, 'GET')
  assert.ok(express.guards.includes('requireAuth'), `expected inherited mount guard, got ${express.guards.join(',')}`)

  const next = byPath.get('/orders/:id')
  assert.ok(next, 'expected Next.js app route with (group) removed and [id] normalized')
  assert.equal(next.httpMethod, 'GET')

  const taint = cg.taintPaths.find(p => p.routeOrAction === '/api/v1/orders' && p.sinkKind === 'db_query')
  assert.ok(taint, 'expected backward taint path for Express route')
  assert.equal(taint.isAuthUnguarded, false, 'mount middleware satisfies authorization')
  assert.equal(taint.isInjectionUnsanitized, true, 'auth middleware must not sanitize the SQL sink')
  assert.equal(taint.missingTenantScope, true)
})

// ============================================================================
// M4-T4: Non-JS framework extractors
// ============================================================================

test('M4-T4: FastAPI/Flask/Django, Spring, Go gin/chi, and Rails routes resolve with framework guards', () => {
  const py = [
    'from fastapi import APIRouter, Depends',
    "router = APIRouter(prefix='/api/v1')",
    "@router.post('/orders/{order_id}')",
    'async def update_order(order_id: int, body: dict, user = Depends(get_current_user)):',
    "    return db.execute('UPDATE orders SET note=1 WHERE id=' + order_id)",
    '',
    "app = Flask(__name__)",
    "@app.route('/settings', methods=['GET', 'POST'])",
    'def settings():',
    '    return render()',
    '',
    'urlpatterns = [',
    "    path('api/items/<int:item_id>/', views.ItemView.as_view()),",
    ']',
  ].join('\n')

  const java = [
    '@RestController',
    '@RequestMapping("/api")',
    'public class UserController {',
    '  @GetMapping("/users/{id}")',
    '  @PreAuthorize("hasRole(\'ADMIN\')")',
    '  public User get(String id) { return repo.findById(id); }',
    '}',
  ].join('\n')

  const go = [
    'func main() {',
    '  r := gin.Default()',
    '  api := r.Group("/api", requireOrg())',
    '  api.GET("/orders", listOrders)',
    '}',
  ].join('\n')

  const rails = [
    "Rails.application.routes.draw do",
    "  get '/orders/:id', to: 'orders#show'",
    'end',
  ].join('\n')

  const cg = buildCallGraphFromFiles([
    { file: 'app/main.py', content: py },
    { file: 'src/UserController.java', content: java },
    { file: 'cmd/server/main.go', content: go },
    { file: 'config/routes.rb', content: rails },
  ])
  const routes = cg.nodes.filter(n => n.kind === 'entrypoint')
  const paths = new Set(routes.map(r => r.routePath))

  assert.ok(paths.has('/api/v1/orders/{order_id}'), `FastAPI route missing: ${[...paths].join(',')}`)
  assert.equal(routes.find(r => r.routePath === '/api/v1/orders/{order_id}')?.httpMethod, 'POST')
  assert.ok(routes.some(r => r.routePath === '/api/v1/orders/{order_id}' && r.guards.includes('get_current_user')), 'FastAPI Depends guard missing')
  assert.ok(paths.has('/settings'), 'Flask route missing')
  assert.ok(paths.has('/api/users/{id}') || paths.has('/api/users/:id'), 'Spring @GetMapping route missing')
  assert.ok(paths.has('/api/orders'), `Go gin group route missing: ${[...paths].join(',')}`)
  assert.ok(paths.has('/orders/:id'), 'Rails route missing')
})

// ============================================================================
// M4-T5: SAST->DAST bridge: git diffs, entrypoint resolution, route reconcile
// ============================================================================

test('M4-T5: Git Miner parses removed guards from unified diffs and resolves file:line to a live entrypoint', () => {
  const diff = [
    'diff --git a/src/routes/orders.ts b/src/routes/orders.ts',
    '--- a/src/routes/orders.ts',
    '+++ b/src/routes/orders.ts',
    '@@ -10,7 +10,5 @@',
    ' router.get("/api/orders/:id", async (req, res) => {',
    '-  if (!req.user || req.user.tenantId !== order.tenantId) {',
    '-    return res.status(403).json({ error: "forbidden" })',
    '-  }',
    '   return res.json(await db.query("SELECT * FROM orders WHERE id=" + req.params.id))',
    ' })',
  ].join('\n')
  const removed = extractRemovedGuardsFromDiff(diff)
  assert.ok(removed.length >= 1, 'expected removed guard lines')
  assert.equal(removed[0].file, 'src/routes/orders.ts')
  assert.ok(removed[0].line >= 10)

  const graph: CallGraphIndex = {
    repo: 'app',
    filesScanned: 1,
    analyzerSource: 'worker_analyzer',
    nodes: [
      {
        id: 'ep', file: 'src/routes/orders.ts', line: 10, endLine: 22, symbol: 'GET /api/orders/:id',
        kind: 'entrypoint', httpMethod: 'GET', routePath: '/api/orders/:id', guards: [], sanitizers: [], calls: ['q'],
      },
    ],
    edges: [],
  }
  const resolved = resolveSuspectEntrypoint(
    graph,
    { file: 'src/routes/orders.ts', line: 14 },
    [{ method: 'GET', path: '/api/orders/:orderId' }],
  )
  assert.ok(resolved, 'expected enclosing entrypoint resolution')
  assert.equal(resolved.routePath, '/api/orders/:id')
  assert.equal(resolved.httpMethod, 'GET')
  assert.deepEqual(resolved.paramNames, ['id'])
  assert.equal(resolved.reconciledEndpoint, 'GET /api/orders/:orderId')

  // Next.js route groups normalize to the same live endpoint as Phase-0.
  assert.equal(reconcileSuspectWithEndpoints('GET', '/app/(group)/orders/[id]', [{ method: 'GET', path: '/orders/42' }]), undefined)
  assert.equal(reconcileSuspectWithEndpoints('GET', '/orders/[id]', [{ method: 'GET', path: '/orders/:orderId' }]), 'GET /orders/:orderId')
  assert.deepEqual(routeTemplateParamNames('/orders/{order_id}/items/:itemId'), ['order_id', 'itemId'])
})

test('M4-T5b: Variant Sweep wildcard rule is constrained (no bare $ARG catch-all)', async () => {
  const ctx = {
    run: {} as never,
    approvedOrigins: ['https://api.app.invalid'],
    reposDir: '/tmp',
    mountedRepos: [],
    backend: {} as never,
    signal: AbortSignal.timeout(5_000),
  } as SemanticAuditContext
  const { queries } = await generateVariantSweepQueries(
    ctx,
    { id: 'f1', origin: 'https://api.app.invalid', title: 'SQLi', cwe: 'CWE-89', category: 'injection-input', severity: 'high', status: 'confirmed', codeLocations: [] },
    { repo: 'app', file: 'src/db.ts', startLine: 1, endLine: 2 },
    'db.query("SELECT * FROM t WHERE id=" + id)',
  )
  assert.ok(queries.length >= 1)
  const yaml = queries.map(q => q.rule.yaml).join('\n')
  assert.ok(!/\$OBJ\.query\(\$ARG\)/.test(yaml), 'wildcard rule must not match any single-argument query call')
  assert.ok(/\$OBJ\.query\(\$ARG \+ \$OTHER, \.\.\.\)/.test(yaml), 'expected arithmetic-concat pattern')
})

// ============================================================================
// M4-T6: Patch Gate 6 — guarded returns, skip semantics, baseline caller
// ============================================================================

test('M4-T6: Gate 6 never passes when skipped and guarded 403 guards do not count as breaks_callers', async (t) => {
  const guardedDiff = [
    '--- a/server.ts',
    '+++ b/server.ts',
    '@@ -1,5 +1,8 @@',
    ' app.get("/orders", (req, res) => {',
    '+  if (!req.user) {',
    '+    return res.status(403).json({ error: "forbidden" })',
    '+  }',
    '   res.json(listOrders(req))',
    ' })',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(guardedDiff), false, 'guarded 403 must not break legitimate callers')

  const unconditionalDiff = [
    '--- a/server.ts',
    '+++ b/server.ts',
    '@@ -1,5 +1,6 @@',
    ' app.get("/orders", (req, res) => {',
    '+  return res.status(403).end()',
    '   res.json(listOrders(req))',
    ' })',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(unconditionalDiff), true, 'unconditional top-level block must be flagged')

  const root = mkdtempSync(join(tmpdir(), 'kovo-m4-patch-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const repo = 'app'
  mkdirSync(join(root, repo), { recursive: true })
  const relFile = 'server.ts'
  writeFileSync(join(root, repo, relFile), [
    'const app = express()',
    'app.get("/orders", (req, res) => {',
    '  const id = req.query.id',
    '  res.json(db.query("SELECT * FROM orders WHERE id=" + id))',
    '})',
    '',
  ].join('\n'))
  const fixBefore = '  const id = req.query.id\n  res.json(db.query("SELECT * FROM orders WHERE id=" + id))'
  const fixAfter = '  const id = Number.parseInt(String(req.query.id ?? "1"), 10)\n  res.json(db.query("SELECT * FROM orders WHERE id = $1", [id]))'

  const result = await generateAndReviewPatch({
    runId: 'run-m4',
    finding: {
      id: 'finding-m4', origin: 'http://127.0.0.1:3000', title: 'SQL injection', cwe: 'CWE-89',
      category: 'injection-input', severity: 'high', status: 'confirmed',
      reason: 'Request input reaches a raw SQL query.', remediation: 'Parameterize the query.',
      evidenceIds: [], scopeRevision: 1,
      codeLocations: [{ repo, file: relFile, startLine: 3, endLine: 4 }],
    },
    repo,
    reposDir: root,
    candidatePatch: {
      fixBefore, fixAfter, rationale: 'Parameterize the query.',
      codeLocations: [{ repo, file: relFile, startLine: 3, endLine: 4 }],
      coverageInventory: [],
    },
  })
  const gate6 = result.gates.find(g => g.gate === 6)
  assert.ok(gate6)
  assert.equal(gate6.passed, false, 'Gate 6 must never be passed when no dynamic retest ran')
  assert.match(gate6.detail, /unverified|skipped/i)
  assert.equal(result.dynamicRetestVerdict, 'skipped')
  assert.equal(result.status, 'approved', 'static gates 1-5 should still approve the safe patch')

  // A breaking patch is withheld even when static gates otherwise pass.
  const breaking = await generateAndReviewPatch({
    runId: 'run-m4-b',
    finding: {
      id: 'finding-m4-b', origin: 'http://127.0.0.1:3000', title: 'Broken patch', cwe: 'CWE-89',
      category: 'injection-input', severity: 'high', status: 'confirmed',
      reason: 'Request input reaches a raw SQL query.', remediation: 'Parameterize the query.',
      evidenceIds: [], scopeRevision: 1,
      codeLocations: [{ repo, file: relFile, startLine: 3, endLine: 4 }],
    },
    repo,
    reposDir: root,
    candidatePatch: {
      fixBefore, fixAfter: '  return res.status(403).end()', rationale: 'disable route',
      codeLocations: [{ repo, file: relFile, startLine: 3, endLine: 4 }],
      coverageInventory: [],
    },
  })
  assert.equal(breaking.callerCompatibility, 'breaks_callers')
  assert.equal(breaking.status, 'withheld')
})

// ============================================================================
// M4-T7: Dynamic template placeholders target real 401/403 routes
// ============================================================================

test('M4-T7: runSafeTemplates resolves {{discovered_protected_path}} and skips it when discovery is empty', async (t) => {
  const dir = join(repoRoot, 'src', 'templates', 'nextjs')
  const fx = await startHttpFixture(t, (req, _body, res) => {
    const isProbe = Boolean(req.headers['x-middleware-subrequest'])
    if (req.url === '/admin' && isProbe) {
      res.statusCode = 200
      res.setHeader('content-type', 'text/html')
      res.end('<!doctype html><html><body>admin dashboard</body></html>')
      return
    }
    res.statusCode = req.url === '/admin' ? 403 : 404
    res.end('forbidden')
  })

  const withDiscovery = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runSafeTemplates(
    {
      origin: fx.origin,
      techFingerprint: ['nextjs'],
      templatesDir: dir,
      maxTemplates: 8,
      discoveredPaths: { protectedPaths: ['/admin'] },
    },
    new RequestBroker({ rejectUnauthorized: false }),
    makeLabGrant(fx.origin, { tier: 2 }),
    undefined,
    AbortSignal.timeout(20_000),
  ))
  assert.ok(withDiscovery.matches.some(m => m.templateId === 'nextjs-middleware-subrequest-bypass'), `expected dynamic-path match; skipped=${JSON.stringify(withDiscovery.skipped.slice(0, 3))}`)
  assert.ok(fx.requests.some(r => r.url === '/admin' && r.headers['x-middleware-subrequest']), 'probe must target the discovered protected route')

  const withoutDiscovery = await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, () => runSafeTemplates(
    {
      origin: fx.origin,
      techFingerprint: ['nextjs'],
      templatesDir: dir,
      maxTemplates: 8,
    },
    new RequestBroker({ rejectUnauthorized: false }),
    makeLabGrant(fx.origin, { tier: 2 }),
    undefined,
    AbortSignal.timeout(20_000),
  ))
  assert.equal(withoutDiscovery.matches.length, 0)
  assert.ok(withoutDiscovery.skipped.some(s => s.id === 'nextjs-middleware-subrequest-bypass' && /discovered path/i.test(s.reason)))
})

// ============================================================================
// M4-T8: Unified tech fingerprint (live + manifests) & SCA correlation
// ============================================================================

test('M4-T8: tech tags unify live headers with mounted manifests; SCA advisories cover Python/Java/Go/Ruby', async () => {
  const live = techTagsFromResponse({ 'x-powered-by': 'Next.js 14.2.0', server: 'nginx/1.25' }, '<div id="__next">shell</div>')
  const repo = techTagsFromManifests([
    { name: 'package.json', content: JSON.stringify({ dependencies: { express: '4.18.2', next: '14.2.0' } }) },
    { name: 'backend/requirements.txt', content: 'django==4.0.1\nfastapi==0.110.0\n' },
    { name: 'go.mod', content: 'require github.com/gin-gonic/gin v1.8.0\n' },
    { name: 'pom.xml', content: '<dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>6.0.10</version></dependency>' },
    { name: 'Gemfile', content: "gem 'rails', '7.0.4'\n" },
  ])
  const merged = mergeTechTags(live, repo)
  for (const expected of ['nextjs', 'express', 'django', 'fastapi', 'go', 'springboot', 'rails']) {
    assert.ok(merged.includes(expected), `expected merged tech tag ${expected}, got ${merged.join(',')}`)
  }

  const manifests = [
    { name: 'backend/requirements.txt', content: 'django==4.0.1\n' },
    { name: 'services/api/pom.xml', content: '<dependency><artifactId>spring-core</artifactId><version>6.0.10</version></dependency>' },
    { name: 'cmd/app/go.mod', content: 'require github.com/gin-gonic/gin v1.8.0\n' },
    { name: 'web/Gemfile', content: "gem 'rails', '7.0.4'\n" },
  ]
  const deps = parseDependencyManifests(manifests)
  assert.ok(deps.some(d => d.ecosystem === 'PyPI' && d.package === 'django' && d.version === '4.0.1'))
  assert.ok(deps.some(d => d.ecosystem === 'Maven' && d.package === 'spring-core'))
  assert.ok(deps.some(d => d.ecosystem === 'Go' && d.package.includes('gin-gonic')))
  assert.ok(deps.some(d => d.ecosystem === 'RubyGems' && d.package === 'rails'))

  assert.equal(versionSatisfiesRange('4.0.1', '>=3.2.0 <3.2.13 || >=4.0.0 <4.0.4'), true)
  assert.equal(versionSatisfiesRange('4.0.5', '>=3.2.0 <3.2.13 || >=4.0.0 <4.0.4'), false)
  assert.equal(hasCuratedAdvisory('PyPI', 'django'), true)

  const advisories = await withEnv({ KOVO_OFFLINE: '1' }, () => queryCves({ ecosystem: 'PyPI', package: 'django', version: '4.0.1' }))
  assert.ok(advisories.some(a => a.id === 'CVE-2022-28346'), 'expected curated Django SQLi advisory for 4.0.1')
  assert.ok(templateIdsForCves(['CVE-2025-29927']).includes('nextjs-middleware-subrequest-bypass'))
})

// ============================================================================
// M4-T9: Offline SCA lockfile bridge (optional Docker worker)
// ============================================================================

test('M4-T9: worker trivy-fs reports Python/Go/Java/Ruby advisory IDs from mounted manifests', async (t) => {
  let hasImage = false
  try {
    const { execFile } = await import('node:child_process')
    const { promisify } = await import('node:util')
    await promisify(execFile)('docker', ['image', 'inspect', 'kovo-worker:v4'], { timeout: 5_000 })
    hasImage = true
  } catch {
    hasImage = false
  }
  if (!hasImage) {
    t.skip('kovo-worker:v4 image not available')
    return
  }

  const { LinuxWorkerBackend } = await import('../src/server/worker-backend.ts')
  const { randomUUID } = await import('node:crypto')
  const reposDir = mkdtempSync(join(tmpdir(), 'kovo-m4-sca-'))
  chmodSync(reposDir, 0o755)
  t.after(() => rmSync(reposDir, { recursive: true, force: true }))
  const appDir = join(reposDir, 'app')
  mkdirSync(appDir, { recursive: true })
  writeFileSync(join(appDir, 'requirements.txt'), 'django==4.0.1\n')
  writeFileSync(join(appDir, 'go.mod'), 'module example.test/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.8.0\n')
  writeFileSync(join(appDir, 'Gemfile'), "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n")
  writeFileSync(join(appDir, 'pom.xml'), '<project><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>6.0.10</version></dependency></dependencies></project>\n')

  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => session.close())
  const res = await session.sast({ repo: 'app', engines: ['trivy-fs'] }, AbortSignal.timeout(90_000))
  const ids = res.findings.map(f => f.ruleId).join(',')
  assert.ok(/CVE-2022-28346/.test(ids), `expected Django advisory, got ${ids}`)
  assert.ok(res.findings.some(f => /CVE-2023-26125|CVE-2020-26160|CVE-2023-44487/.test(f.ruleId)), 'expected Go advisory')
  assert.ok(res.findings.some(f => /CVE-2022-32224|CVE-2023-28362/.test(f.ruleId)), 'expected Ruby advisory')
  assert.ok(res.findings.some(f => /CVE-2024-22233|CVE-2021-44228|CVE-2020-36518/.test(f.ruleId)), 'expected Java advisory')
})
