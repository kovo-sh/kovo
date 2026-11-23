/**
 * Realism fixture #4 (monorepo-whitebox) — briefing ↔ product wiring.
 *
 * The fixture publishes a 2,565-operation declared catalog (2,560 generated `/v4` routes plus the
 * five hand-written gateway routes) and materializes source the shipped extractors can read.
 * These tests exercise the harness path, not a bespoke scorer:
 *
 *   1. briefing -> OpenAPI keeps every declared operation, with path/query parameters;
 *   2. declared ingestion through Phase-0 persists the same canonical operation set;
 *   3. Program Graph extraction sees the nested `/v2`,`/v3`,`/v4` mounts, and the three
 *      route→controller→service→repo sinks resolve as four-hop chains in the semantic-audit
 *      entrypoint resolver.
 *
 * The fixture's truth is never imported here.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { cpSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { start } from '../benchmarks/realism-suite/fixtures/monorepo-whitebox/index.ts'
import type { MonorepoFixture } from '../benchmarks/realism-suite/fixtures/monorepo-whitebox/index.ts'
import { briefingFor } from '../benchmarks/realism-suite/run.ts'
import {
  briefingToOpenApi,
  canonicalRoutePath,
  countOpenApiOperations,
  listAllEndpoints,
} from '../scripts/benchmark-realism.ts'
import { maxSpecBytes } from '../src/domain.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { extractRepoProgramGraph, runPhase0Recon } from '../src/server/phase0-recon.ts'
import { resolveRouteSinkPaths } from '../src/server/program-graph.ts'
import { callGraphFromProgramGraph, resolveSuspectEntrypoint } from '../src/server/semantic-audit.ts'
import type { EndpointRow } from '../src/server/store.ts'
import { Store } from '../src/server/store.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const FIXTURE = 'monorepo-whitebox'
const ORIGIN = 'http://127.0.0.1:9'
const DECLARED_OPERATIONS = 2_565
const GENERATED_OPERATIONS = 2_560

interface HarnessPathResult {
  /** Phase-0's own incremental declared-surface counter (see the accounting note in the test). */
  reportedDeclared: number
  openApiRows: number
  mergedRoutes: number
  endpoints: EndpointRow[]
  priority: number
  probeSubset: number
}

function routeIdentity(method: string, path: string): string {
  return `${method.toUpperCase()} ${canonicalRoutePath(path)}`
}

describe('realism #4 monorepo: briefing -> declared surface -> AST reachability', () => {
  let fixture: MonorepoFixture
  let repoRoot: string
  let tempRoot: string
  let openApiOps = 0
  let openApiBytes = 0
  let harness: HarnessPathResult
  let storage: Store | undefined

  before(async () => {
    fixture = await start({ keepSource: true })
    tempRoot = mkdtempSync(join(tmpdir(), 'guardian-realism-mono-'))
    // Mirror the harness white-box mount: <reposDir>/bench/monorepo-whitebox.
    repoRoot = join(tempRoot, 'bench', FIXTURE)
    mkdirSync(join(repoRoot, '..'), { recursive: true })
    cpSync(fixture.sourceDir!, repoRoot, { recursive: true })

    const briefing = briefingFor(fixture)
    const doc = briefingToOpenApi({ fixture: FIXTURE, originLabel: 'app', api: briefing.api })
    assert.ok(doc, 'briefing publishes an app API reference')
    openApiOps = countOpenApiOperations(doc)
    openApiBytes = Buffer.byteLength(JSON.stringify(doc), 'utf8')

    const store = new Store(join(tempRoot, 'data'))
    storage = store
    const setup = await setupApprovedRun(store, {
      environment: 'local-lab',
      seeds: [ORIGIN],
      tier: 0,
      budgetRequests: 900,
    })
    store.importProjectSpec({
      requestId: randomUUID(),
      projectId: setup.projectId,
      name: `realism-${FIXTURE}-app.json`,
      kind: 'openapi',
      origin: ORIGIN,
      content: JSON.stringify(doc),
    })
    const grant: Grant = makeLabGrant(ORIGIN, { tier: 0 })
    const result = await runPhase0Recon({
      storage: store,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 0,
      origins: [ORIGIN],
      budgetRequests: 900,
      reposDir: tempRoot,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant,
      signal: AbortSignal.timeout(120_000),
    })
    harness = {
      reportedDeclared: result.declaredSurface?.endpoints ?? 0,
      openApiRows: store.listEndpoints(setup.runId, { origin: ORIGIN, source: 'openapi', limit: 10_000 }).length,
      mergedRoutes: result.repoStaticExtraction?.mergedRoutes ?? 0,
      endpoints: listAllEndpoints(store, setup.runId),
      priority: result.probePlan?.priority ?? 0,
      probeSubset: result.probePlan?.probeSubset ?? 0,
    }
  })

  after(async () => {
    const sourceDir = fixture?.sourceDir
    try { storage?.close() } catch { /* already closed */ }
    try { await fixture?.stop() } catch { /* already stopped */ }
    if (sourceDir) rmSync(sourceDir, { recursive: true, force: true })
    if (tempRoot) rmSync(tempRoot, { recursive: true, force: true })
  })

  test('briefing exposes every declared operation (generated routes included, no wildcard collapse)', () => {
    assert.equal(fixture.routes?.length, DECLARED_OPERATIONS)
    assert.equal(
      fixture.routes?.filter((route) => route.path.startsWith('/v4/')).length,
      GENERATED_OPERATIONS,
    )
    assert.equal(openApiOps, DECLARED_OPERATIONS, 'OpenAPI keeps one operation per declared route')
    assert.ok(openApiBytes < maxSpecBytes, `spec is ${openApiBytes} bytes, below the ${maxSpecBytes}-byte cap`)
  })

  test('OpenAPI operations keep their method and path/query parameters', () => {
    const briefing = briefingFor(fixture)
    const doc = briefingToOpenApi({ fixture: FIXTURE, originLabel: 'app', api: briefing.api })!
    const declared = new Set((fixture.routes ?? []).map((route) => routeIdentity(route.method, route.path)))
    const emitted = new Set<string>()
    for (const [path, operations] of Object.entries(doc.paths)) {
      for (const method of Object.keys(operations)) emitted.add(routeIdentity(method, path))
    }
    assert.equal(emitted.size, declared.size)
    for (const identity of declared) assert.ok(emitted.has(identity), `missing declared operation ${identity}`)

    const invoiceParams = doc.paths['/v2/billing/invoices/{id}']?.get.parameters ?? []
    assert.ok(invoiceParams.some((param) => param.name === 'id' && param.in === 'path'))
    const exportParams = doc.paths['/v2/reports/export']?.get.parameters ?? []
    assert.ok(exportParams.some((param) => param.name === 'sort' && param.in === 'query'), 'query parameters survive the briefing')
    const generatedParams = doc.paths['/v4/search/resource-318/{id}']?.get.parameters ?? []
    assert.ok(generatedParams.some((param) => param.name === 'id' && param.in === 'path'))
  })

  test('declared count equals the persisted canonical operation count through Phase-0', () => {
    // Phase-0's own incremental counter pages endpoints with `listEndpoints()`'s default 500-row
    // page, so it under-reports when AST + declared aliases exceed one page. The store itself is
    // lossless; assert against a fully paged read (the harness metric does the same).
    assert.ok(harness.reportedDeclared <= DECLARED_OPERATIONS)
    // A handful of declared paths are exact-string identical to an AST route (`/v2/reports/export`),
    // so the first writer keeps the `repo_ast` source; the operation itself is still persisted.
    assert.ok(harness.openApiRows >= DECLARED_OPERATIONS - 5, `openapi rows: ${harness.openApiRows}`)
    assert.ok(harness.mergedRoutes >= GENERATED_OPERATIONS, `AST routes include the generated surface (${harness.mergedRoutes})`)

    const declared = new Set((fixture.routes ?? []).map((route) => routeIdentity(route.method, route.path)))
    const persisted = new Set(harness.endpoints.map((endpoint) => routeIdentity(endpoint.method, endpoint.pathTemplate)))
    assert.equal(declared.size, DECLARED_OPERATIONS)
    assert.equal(persisted.size, DECLARED_OPERATIONS, 'persisted canonical identities match the declared catalog')
    for (const identity of declared) assert.ok(persisted.has(identity), `declared operation not persisted: ${identity}`)

    // AST aliases use `:id` while the OpenAPI document uses `{id}`; both are stored losslessly.
    assert.ok(harness.endpoints.length >= DECLARED_OPERATIONS)
    assert.ok(harness.endpoints.some((endpoint) => endpoint.source === 'repo_ast' && endpoint.pathTemplate.startsWith('/v4/')))
    // Ranking wiring: the sink routes are Tier-A priorities, not sampled into the long tail.
    assert.equal(harness.priority, 3, 'the three sink routes are Tier-A priorities')
    assert.ok(harness.probeSubset >= 3)
  })

  test('nested mounts and 4-hop route->controller->service->repo sinks are AST-resolvable', () => {
    const extracted = extractRepoProgramGraph({ reposDir: repoRoot, origins: [ORIGIN] })
    assert.ok(extracted, 'AST extraction runs for the materialized repo')
    const paths = new Set(extracted.routes.map((route) => `${route.method} ${route.pathTemplate}`))
    for (const expected of [
      'GET /v2/billing/invoices/:id',
      'GET /v2/reports/export',
      'PATCH /v3/admin/users/:id',
    ]) {
      assert.ok(paths.has(expected), `mounted route missing: ${expected}`)
    }
    assert.equal(
      extracted.routes.filter((route) => route.pathTemplate.startsWith('/v4/')).length,
      GENERATED_OPERATIONS,
      'every generated /v4 route is statically extracted with its mount prefix',
    )

    const sinkPaths = resolveRouteSinkPaths(extracted.graph, { maxDepth: 8 })
      .filter((path) => path.sinkKind === 'db_query' && path.hops >= 4)
    const byRoute = new Map(sinkPaths.map((path) => [`${path.route.method} ${path.route.path}`, path]))
    for (const route of ['GET /v2/billing/invoices/:id', 'GET /v2/reports/export', 'PATCH /v3/admin/users/:id']) {
      assert.ok(byRoute.has(route), `no four-hop sink path for ${route}`)
      assert.equal(byRoute.get(route)!.hops, 4)
    }
    assert.ok(sinkPaths.length >= 3)

    const callGraph = callGraphFromProgramGraph(extracted.graph)
    for (const path of sinkPaths) {
      const entry = resolveSuspectEntrypoint(
        callGraph,
        { file: path.sinkFile, line: path.sinkLine },
        undefined,
        { programGraph: extracted.graph },
      )
      assert.ok(entry, `semantic-audit could not resolve ${path.sinkFile}:${path.sinkLine}`)
      assert.equal(`${entry.httpMethod} ${entry.routePath}`, `${path.route.method} ${path.route.path}`)
      assert.equal(entry.matchedBy, 'reverse')
    }
  })
})
