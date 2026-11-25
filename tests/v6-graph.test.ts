/**
 * v6 Phase 4: code-first Program Graph.
 *
 * Covers mount-aware route extraction across frameworks, middleware/guard
 * chains, multi-hop reverse call graphs with sink kinds, code-to-runtime
 * hypotheses, monorepo service->origin mapping, preserved git history with
 * bounded commit-diff mining, dynamic CVE template indexing and Maven pom
 * multi-dependency parsing. Fixtures are synthetic; no benchmark identifiers.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import {
  deriveCodeToRuntimeHypotheses,
  extractProgramGraph,
  mapServicesToOrigins,
  mineSecurityRelevantCommitDiffs,
  resolveRouteForLocation,
  resolveRouteSinkPaths,
} from '../src/server/program-graph.ts'
import { cloneGithubRepos, readRepoCommitDiffs } from '../src/server/github-connector.ts'
import {
  CVE_TEMPLATE_IDS,
  buildCveTemplateIndex,
  parseDependencyManifests,
  parsePomDependencies,
  templateIdsForCves,
} from '../src/server/cve-broker.ts'
import {
  analyzeSinkBackwardPaths,
  projectSecuritySpecSchema,
  resolveSuspectEntrypoint,
  type CallGraphEdge,
  type CallGraphIndex,
  type CallGraphNode,
} from '../src/server/semantic-audit.ts'

function makeTempDir(t: TestContext, prefix: string): string {
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

function git(cwd: string, args: readonly string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
}

describe('program graph: framework-aware routes and mounts', () => {
  test('resolves nested Express mounts, methods and middleware chains', () => {
    const files = [
      {
        path: 'src/app.ts',
        content: [
          "const app = express()",
          "const api = express.Router()",
          "const v1 = express.Router()",
          "const users = express.Router()",
          "app.use('/api', api)",
          "api.use('/v1', requireAuth, v1)",
          "v1.use('/users', users)",
          "users.get('/:id', requireAdmin, getUser)",
          "users.route('/:id').patch(tenantScope, updateUser).delete(requireAdmin, deleteUser)",
          "users.post('/:id/restore', restoreUser)",
        ].join('\n'),
      },
      {
        path: 'src/admin.ts',
        content: [
          "const router = express.Router()",
          "router.get('/admin/users', requireAuth, listAllUsers)",
          "router.delete('/admin/users/:id', requireAuth, removeUser)",
          "module.exports = router",
        ].join('\n'),
      },
      {
        path: 'src/mount.ts',
        content: [
          "import adminRouter from './admin'",
          "const root = express()",
          "root.use('/internal', requireAuth, adminRouter)",
        ].join('\n'),
      },
    ]
    const graph = extractProgramGraph({ files })
    assert.deepEqual([...new Set(graph.frameworks)], ['express'])
    const getRoute = graph.routes.find(route => route.handler === 'getUser')
    assert.ok(getRoute, 'nested GET route must be extracted')
    assert.equal(getRoute.path, '/api/v1/users/:id')
    assert.equal(getRoute.method, 'GET')
    assert.deepEqual(getRoute.mountedFrom, ['/api', '/v1', '/users'])
    assert.deepEqual(getRoute.middleware, ['requireAuth', 'requireAdmin'])
    assert.ok(getRoute.guards.includes('requireAuth'))
    assert.ok(getRoute.guards.includes('requireAdmin'))

    const patchRoute = graph.routes.find(route => route.handler === 'updateUser')
    assert.equal(patchRoute?.method, 'PATCH')
    assert.equal(patchRoute?.path, '/api/v1/users/:id')
    assert.ok(patchRoute?.middleware.includes('tenantScope'))

    const crossFile = graph.routes.find(route => route.handler === 'removeUser')
    assert.equal(crossFile?.path, '/internal/admin/users/:id', 'cross-file router import must resolve the mounted prefix')
    assert.deepEqual(crossFile?.mountedFrom, ['/internal'])
  })

  test('extracts Next, Nest, FastAPI, Spring, Gin, Chi and Rails route samples', () => {
    const files = [
      {
        path: 'apps/web/src/app/api/users/[id]/route.ts',
        content: [
          'export async function GET(req: Request) { return listUser(req) }',
          'export async function DELETE(req: Request) { return deleteUser(req) }',
        ].join('\n'),
      },
      {
        path: 'src/cats.controller.ts',
        content: [
          "@Controller('cats')",
          '@UseGuards(AuthGuard)',
          'export class CatsController {',
          "  @Get(':id')",
          "  @Roles('admin')",
          "  async findOne(@Param('id') id: string) { return this.svc.find(id) }",
          '  @Post()',
          '  async create(@Body() dto: CreateCatDto) { return this.svc.create(dto) }',
          '}',
        ].join('\n'),
      },
      {
        path: 'services/api/main.py',
        content: [
          'from fastapi import APIRouter, Depends, FastAPI',
          'app = FastAPI()',
          "router = APIRouter(prefix='/items', dependencies=[Depends(get_user)])",
          "@router.get('/{item_id}')",
          'async def read_item(item_id: int, q: str = None):',
          '    return item_id',
          "app.include_router(router, prefix='/api/v1')",
        ].join('\n'),
      },
      {
        path: 'UsersController.java',
        content: [
          '@RestController',
          '@RequestMapping("/api/users")',
          'public class UsersController {',
          '  @GetMapping("/{id}")',
          '@PreAuthorize("hasRole(\'ADMIN\')")',
          '  public User get(@PathVariable Long id) { return repo.findById(id); }',
          '}',
        ].join('\n'),
      },
      {
        path: 'cmd/api/main.go',
        content: [
          'package main',
          'func main() {',
          '  r := gin.Default()',
          '  v1 := r.Group("/v1")',
          '  v1.GET("/users/:id", authMiddleware(), getUser)',
          '}',
        ].join('\n'),
      },
      {
        path: 'cmd/chi/main.go',
        content: [
          'package main',
          'func main() {',
          '  r := chi.NewRouter()',
          '  r.Route("/v1", func(r chi.Router) {',
          '    r.With(authMiddleware).Get("/users/{id}", getUser)',
          '  })',
          '}',
        ].join('\n'),
      },
      {
        path: 'config/routes.rb',
        content: [
          'Rails.application.routes.draw do',
          '  namespace :api do',
          '    resources :users, only: [:index, :show]',
          "    get 'health', to: 'health#show'",
          '  end',
          'end',
        ].join('\n'),
      },
    ]
    const graph = extractProgramGraph({ files })
    const find = (framework: string, method: string, path: string) =>
      graph.routes.find(route => route.framework === framework && route.method === method && route.path === path)

    assert.ok(find('nextjs', 'GET', '/api/users/:id'), 'Next app-router GET')
    assert.ok(find('nextjs', 'DELETE', '/api/users/:id'), 'Next app-router DELETE')

    const nest = find('nestjs', 'GET', '/cats/:id')
    assert.ok(nest, 'Nest @Controller + @Get')
    assert.deepEqual(nest?.guards, ['UseGuards(AuthGuard)', "Roles('admin')"])
    assert.ok(graph.routes.find(route => route.framework === 'nestjs' && route.method === 'POST' && route.path === '/cats'))

    const fastapi = find('fastapi', 'GET', '/api/v1/items/:item_id')
    assert.ok(fastapi, 'FastAPI APIRouter prefix + include_router')
    assert.ok(fastapi?.guards.some(guard => guard.includes('get_user')), 'FastAPI dependencies are guards')

    const spring = find('spring', 'GET', '/api/users/:id')
    assert.ok(spring, 'Spring class + method mapping')
    assert.ok(spring?.guards.some(guard => guard.includes('PreAuthorize')))

    const gin = find('gin', 'GET', '/v1/users/:id')
    assert.ok(gin, 'Gin group prefix')
    assert.ok(gin?.guards.some(guard => guard.startsWith('authMiddleware')))

    const chi = find('chi', 'GET', '/v1/users/:id')
    assert.ok(chi, 'Chi Route block + With middleware')
    assert.ok(chi?.guards.includes('authMiddleware'))

    assert.ok(find('rails', 'GET', '/api/users'), 'Rails namespace + resources index')
    assert.ok(find('rails', 'GET', '/api/users/:id'), 'Rails resources show')
    assert.ok(find('rails', 'GET', '/api/health'), 'Rails namespace + explicit get')
  })
})

describe('program graph: reverse call graph and hypotheses', () => {
  const chainFiles = [
    {
      path: 'src/routes/orders.ts',
      content: [
        'const router = express.Router()',
        "router.patch('/orders/:id', requireAuth, handleOrderPatch)",
        'export default router',
      ].join('\n'),
    },
    {
      path: 'src/controllers/order.ts',
      content: [
        'export async function handleOrderPatch(req, res) {',
        '  const result = await loadOrderProfile(req.params.id)',
        '  return res.json(result)',
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

  test('records a 4-hop route -> controller -> service -> repository sink chain with file:line', () => {
    const graph = extractProgramGraph({ files: chainFiles })
    const paths = resolveRouteSinkPaths(graph, { maxDepth: 7 })
    assert.equal(paths.length, 1, 'one route-to-sink path expected')
    const path = paths[0]
    assert.equal(path.route.path, '/orders/:id')
    assert.equal(path.sinkKind, 'db_query')
    assert.equal(path.hops, 4)
    assert.deepEqual(path.chain.map(hop => hop.symbol), [
      'handleOrderPatch',
      'handleOrderPatch',
      'loadOrderProfile',
      'findOrderRow',
      'findOrderRow:db_query',
    ])
    assert.equal(path.sinkFile, 'src/repos/order.ts')
    assert.equal(path.sinkLine, 2)
    assert.ok(path.chain.every(hop => hop.file.length > 0 && hop.line > 0), 'every hop records file:line')

    const shallow = resolveRouteSinkPaths(graph, { maxDepth: 2 })
    assert.equal(shallow.length, 0, 'maxDepth is configurable and bounds the reverse traversal')
  })

  test('multi-hop resolveSuspectEntrypoint walks controller/service/repository edges beyond one hop', () => {
    const node = (
      id: string,
      kind: CallGraphNode['kind'],
      file: string,
      line: number,
      symbol: string,
      extra: Partial<CallGraphNode> = {},
    ): CallGraphNode => ({ id, kind, file, line, symbol, guards: [], sanitizers: [], calls: [], ...extra })
    const nodes: CallGraphNode[] = [
      node('ep', 'entrypoint', 'src/routes/orders.ts', 4, 'listOrders', { routePath: '/orders', httpMethod: 'GET' }),
      node('ctrl', 'function', 'src/controllers/order.ts', 2, 'listOrdersCtrl'),
      node('svc', 'function', 'src/services/order.ts', 2, 'readOrders'),
      node('repo', 'function', 'src/repos/order.ts', 2, 'selectOrders'),
      node('sink', 'sink', 'src/repos/order.ts', 5, 'db.query', { sinkKind: 'db_query' }),
    ]
    const edges: CallGraphEdge[] = [
      { fromId: 'ep', toId: 'ctrl', file: 'src/routes/orders.ts', line: 4 },
      { fromId: 'ctrl', toId: 'svc', file: 'src/controllers/order.ts', line: 2 },
      { fromId: 'svc', toId: 'repo', file: 'src/services/order.ts', line: 2 },
      { fromId: 'repo', toId: 'sink', file: 'src/repos/order.ts', line: 5 },
    ]
    const graph: CallGraphIndex = {
      repo: 'acme/api',
      filesScanned: 4,
      nodes,
      edges,
      analyzerSource: 'worker_analyzer',
    }
    const resolved = resolveSuspectEntrypoint(graph, { file: 'src/repos/order.ts', line: 5 }, undefined, { maxHops: 7 })
    assert.ok(resolved)
    assert.equal(resolved.routePath, '/orders')
    assert.equal(resolved.httpMethod, 'GET')
    assert.equal(resolved.matchedBy, 'reverse')

    const spec = projectSecuritySpecSchema.parse({ repo: 'acme/api', generatedAt: 1 })
    const paths = analyzeSinkBackwardPaths(graph, spec, { maxDepth: 7 })
    assert.equal(paths.length, 1)
    assert.equal(paths[0].sinkKind, 'db_query')
    assert.equal(paths[0].callChain.length, 5)
    assert.equal(analyzeSinkBackwardPaths(graph, spec, { maxDepth: 1 }).length, 0)
  })

  test('emits admin, tenant-scope and recent-diff code-to-runtime hypotheses', () => {
    const files = [
      {
        path: 'src/admin.ts',
        content: [
          "const router = express.Router()",
          "router.get('/admin/users', requireAuth, listAllUsers)",
          "router.delete('/admin/users/:id', requireAuth, removeUser)",
          "module.exports = router",
        ].join('\n'),
      },
      ...chainFiles,
    ]
    const graph = extractProgramGraph({ files })
    const base = deriveCodeToRuntimeHypotheses(graph)
    assert.ok(base.some(hypothesis => hypothesis.kind === 'admin_route_missing_admin_guard' && hypothesis.path === '/admin/users'))
    assert.ok(base.some(hypothesis => hypothesis.kind === 'tenant_param_without_scope' && hypothesis.path === '/admin/users/:id'))
    assert.ok(base.every(hypothesis => hypothesis.rationale.length > 0 && hypothesis.probeClass.length > 0))

    const diff = [
      'diff --git a/src/repos/order.ts b/src/repos/order.ts',
      '--- a/src/repos/order.ts',
      '+++ b/src/repos/order.ts',
      '@@ -1,3 +1,4 @@',
      ' export async function findOrderRow(orderId) {',
      "+  await db.query('select * from audit_log where id = ' + orderId)",
      '   return findOrderRow(orderId)',
      ' }',
    ].join('\n')
    const signals = mineSecurityRelevantCommitDiffs([{ sha: 'a'.repeat(40), subject: 'tighten order lookup', diff }])
    assert.equal(signals.length, 1)
    assert.equal(signals[0].sinkKinds.includes('db_query'), true)
    assert.equal(signals[0].routeTouched, false)
    assert.equal(signals[0].securityRelevant, true)

    const withDiff = deriveCodeToRuntimeHypotheses(graph, { recentDiffSignals: signals })
    const recent = withDiff.find(hypothesis => hypothesis.kind === 'recent_diff_touches_sink')
    assert.ok(recent, 'recent diff hypothesis must be emitted')
    assert.equal(recent.sinkKind, 'db_query')
    assert.equal(recent.path, '/orders/:id', 'diff location resolves to the live route through the call graph')

    const location = resolveRouteForLocation(graph, { file: 'src/repos/order.ts', line: 2 }, { maxDepth: 7 })
    assert.equal(location?.route.path, '/orders/:id')
    assert.equal(location?.depth, 4)
  })

  test('maps monorepo services to origins via compose labels, ingress and ports', () => {
    const compose = [
      'services:',
      '  api:',
      '    build: ./services/api',
      '    ports: ["8080:8080"]',
      '    labels:',
      '      traefik.http.routers.api.rule: Host(`api.shop.test`)',
      '  web:',
      '    build: ./services/web',
      '    ports: ["3000:3000"]',
      '  worker:',
      '    build: ./services/worker',
    ].join('\n')
    const ingress = [
      'spec:',
      '  rules:',
      '  - host: shop.test',
      '    http:',
      '      paths:',
      '      - path: /api',
      '        pathType: Prefix',
      '        backend:',
      '          service:',
      '            name: api',
    ].join('\n')
    const mappings = mapServicesToOrigins({
      services: [
        { name: 'api', root: 'services/api' },
        { name: 'web', root: 'services/web' },
        { name: 'worker', root: 'services/worker' },
      ],
      origins: ['https://api.shop.test', 'https://shop.test', 'http://localhost:3000'],
      compose,
      ingress,
      dockerfiles: [{ path: 'services/worker/Dockerfile', content: 'FROM node:24\nEXPOSE 9090\n' }],
    })
    const api = mappings.find(mapping => mapping.service === 'api')
    assert.equal(api?.origin, 'https://api.shop.test')
    assert.equal(api?.confidence, 'exact')
    const web = mappings.find(mapping => mapping.service === 'web')
    assert.equal(web?.origin, 'http://localhost:3000')
    assert.equal(web?.confidence, 'port')
    const worker = mappings.find(mapping => mapping.service === 'worker')
    assert.equal(worker?.origin, 'https://api.shop.test')
    assert.equal(worker?.confidence, 'fallback', 'origins[0] is an explicit last resort, not the default')
  })
})

describe('github connector: preserved history and diff mining', () => {
  test('clones with bounded depth, keeps sanitized .git, and mines security-relevant commits', { timeout: 45_000 }, async t => {
    const work = makeTempDir(t, 'kovo-v6-git-')
    const source = join(work, 'source')
    const origin = join(work, 'origin')
    const bare = join(origin, 'acme', 'app.git')
    const pat = join(work, 'github.pat')
    writeFileSync(pat, 'dummy-token-1234567890', { mode: 0o600 })

    mkdirSync(source, { recursive: true })
    mkdirSync(join(origin, 'acme'), { recursive: true })
    execFileSync('git', ['init', '-b', 'main', source], { stdio: 'ignore' })
    git(source, ['config', 'user.email', 'test@kovo.local'])
    git(source, ['config', 'user.name', 'Kovo Hunter Test'])
    writeTree(source, {
      'package.json': JSON.stringify({ name: 'app', dependencies: { express: '^4.19.0' } }),
      'routes/users.ts': "router.get('/users/:id', requireAuth, getUser)\n",
    })
    git(source, ['add', '.'])
    git(source, ['commit', '-m', 'initial routes'])
    writeTree(source, {
      'routes/users.ts': [
        "router.get('/users/:id', requireAuth, getUser)",
        '// authorize before destructive handler',
        "router.delete('/users/:id', requireAuth, removeUser)",
      ].join('\n'),
    })
    git(source, ['add', '.'])
    git(source, ['commit', '-m', 'harden user route authorization'])
    execFileSync('git', ['clone', '--bare', source, bare], { stdio: 'ignore' })

    const repos = await cloneGithubRepos(['acme/app'], join(work, 'data'), AbortSignal.timeout(30_000), {
      patPath: pat,
      gitBaseUrl: `file://${origin}`,
    })
    assert.equal(repos.length, 1)
    const repo = repos[0]
    const checkout = join(work, 'data', 'acme', 'app')
    assert.equal(existsSync(join(checkout, '.git')), true, 'bounded .git history must be preserved')
    assert.equal(repo.gitHistory?.metadataPreserved, true)
    assert.equal(repo.gitHistory?.depth, 100)
    assert.ok((repo.gitHistory?.commitsScanned ?? 0) >= 2)
    assert.ok(repo.gitHistory?.commitDiffs.some(signal => signal.file === 'routes/users.ts' && signal.authMiddlewareTouched))
    assert.ok(repo.gitHistory?.commitDiffs.every(signal => signal.securityRelevant))

    const config = readFileSync(join(checkout, '.git', 'config'), 'utf8')
    assert.equal(/extraheader/i.test(config), false, 'credential headers must never persist in .git/config')
    assert.equal(/dummy-token/.test(config), false)

    const direct = readRepoCommitDiffs(checkout, { maxCommits: 10 })
    assert.equal(direct.available, true)
    assert.ok(direct.commitsScanned >= 2)
    assert.ok(direct.commitDiffs.some(signal => signal.authMiddlewareTouched))

    const stripped = await cloneGithubRepos(['acme/app'], join(work, 'data-stripped'), AbortSignal.timeout(30_000), {
      patPath: pat,
      gitBaseUrl: `file://${origin}`,
      stripGitMetadata: true,
    })
    assert.equal(existsSync(join(work, 'data-stripped', 'acme', 'app', '.git')), false)
    assert.equal(stripped[0].gitHistory?.metadataPreserved, false)
    assert.ok((stripped[0].gitHistory?.commitDiffs.length ?? 0) > 0, 'diffs survive optional metadata cleanup')
  })
})

describe('cve broker: dynamic template index and Maven dependencies', () => {
  test('indexes every compiled template by CVE id, including ids absent from the legacy map', () => {
    const dynamic = buildCveTemplateIndex([
      { id: 'custom-cve-2020-9999', cve: 'CVE-2020-9999' },
      { id: 'another-template', cve: 'CVE-2020-9999' },
    ])
    assert.deepEqual(dynamic['CVE-2020-9999'], ['custom-cve-2020-9999', 'another-template'])
    assert.deepEqual(
      templateIdsForCves(['CVE-2020-9999'], { templates: [{ id: 'custom-cve-2020-9999', cve: 'CVE-2020-9999' }] }),
      ['custom-cve-2020-9999'],
    )

    assert.equal(CVE_TEMPLATE_IDS['CVE-2000-0760'], undefined, 'legacy single-entry map must not list this CVE')
    assert.ok(
      templateIdsForCves(['CVE-2000-0760']).includes('cve-2000-0760'),
      'dynamically loaded compiled template must be discoverable by CVE id',
    )
    assert.deepEqual(templateIdsForCves(['CVE-2025-29927']), ['nextjs-middleware-subrequest-bypass'])
  })

  test('parses multiple pom.xml dependency blocks with resolved properties', () => {
    const pom = [
      '<project>',
      '  <properties>',
      '    <spring.version>5.3.20</spring.version>',
      '    <auth.version>1.2.3</auth.version>',
      '  </properties>',
      '  <dependencies>',
      '    <dependency>',
      '      <groupId>org.springframework</groupId>',
      '      <artifactId>spring-web</artifactId>',
      '      <version>${spring.version}</version>',
      '    </dependency>',
      '    <dependency>',
      '      <groupId>com.example</groupId>',
      '      <artifactId>auth-lib</artifactId>',
      '      <version>${auth.version}</version>',
      '    </dependency>',
      '    <dependency>',
      '      <groupId>junit</groupId>',
      '      <artifactId>junit</artifactId>',
      '      <version>4.13</version>',
      '      <scope>test</scope>',
      '    </dependency>',
      '  </dependencies>',
      '</project>',
    ].join('\n')
    const deps = parsePomDependencies(pom, 'pom.xml')
    assert.deepEqual(deps, [
      { ecosystem: 'Maven', package: 'spring-web', version: '5.3.20', sourceFile: 'pom.xml' },
      { ecosystem: 'Maven', package: 'auth-lib', version: '1.2.3', sourceFile: 'pom.xml' },
    ])
    assert.deepEqual(parseDependencyManifests([{ name: 'pom.xml', content: pom }]), deps)
  })
})
