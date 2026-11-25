/**
 * v7 whitebox-wire (integration half): dataflow slices attached to Phase-0 hypotheses.
 *
 * The Program Graph builder is already covered in `v7-whitebox.test.ts`; this suite only proves
 * the product wiring against synthetic monorepo sources (no benchmark app, seed, route, challenge
 * or truth file is consulted):
 *
 *   1. a graph route with a four-hop sink receives a <= 600 B slice stored on the hypothesis;
 *   2. an unguarded admin route carries the sibling `missing_guard` diff inside that slice;
 *   3. a run without a mounted graph attaches nothing and records `codeSlice: 'unavailable'`;
 *   4. attachment is deterministic across independent extractions;
 *   5. the per-run slice cap (200) is respected on a 2,500-route graph within the CPU budget,
 *      and Tier-A routes are preferred over the long tail.
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
  PHASE0_MAX_CODE_SLICES,
  attachCodeSlicesToPhase0Hypotheses,
  extractRepoProgramGraph,
  rankAndClusterAstRoutes,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { CodeSliceHypothesis } from '../src/server/phase0-recon.ts'
import type {
  CodeToRuntimeHypothesis,
  ProgramGraph,
  ProgramNode,
  ProgramRoute,
} from '../src/server/program-graph.ts'
import { makeLabGrant, makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://wire.whitebox.test'
const BILLING_ROUTE = ['GET', '/v2/billing/invoices/:id'] as const
const ADMIN_ROUTE = ['PATCH', '/v3/admin/users/:id'] as const

function writeRepo(t: TestContext, files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v7-wire-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

/**
 * Synthetic monorepo: `/v2` billing (four-hop db sink) and `/v3` admin (unguarded) plus a `/v4`
 * admin sibling that does carry `requireAdmin` — the guard-diff control.
 */
const MONOREPO: Record<string, string> = {
  'services/gateway/src/router.ts': [
    "import { Router } from 'express'",
    "import { billingRouter } from '../../billing/src/routes'",
    "import { adminRouter } from '../../admin/src/routes'",
    "import { adminGeneratedRouter } from '../../admin/src/routes.generated.runtime'",
    '',
    'export const app = Router()',
    "app.use('/v2', billingRouter)",
    "app.use('/v3', adminRouter)",
    "app.use('/v4', adminGeneratedRouter)",
    '',
  ].join('\n'),
  'services/billing/src/routes.ts': [
    "import { Router } from 'express'",
    "import { getInvoice } from './controllers/invoices'",
    '',
    'export const billingRouter = Router()',
    "billingRouter.get('/billing/invoices/:id', getInvoice)",
    '',
  ].join('\n'),
  'services/billing/src/controllers/invoices.ts': [
    "import { loadInvoice } from '../services/invoice-service'",
    '',
    'export async function getInvoice(req: any, res: any) {',
    '  const invoice = await loadInvoice(req.params.id)',
    '  res.json({ invoice })',
    '}',
    '',
  ].join('\n'),
  'services/billing/src/services/invoice-service.ts': [
    "import { findById } from '../repos/invoice-repo'",
    '',
    'export async function loadInvoice(id: string) {',
    '  return findById(id)',
    '}',
    '',
  ].join('\n'),
  'services/billing/src/repos/invoice-repo.ts': [
    "import { db } from '../../../../platform/src/db'",
    '',
    'export async function findById(id: string) {',
    "  const rows = await db.all('SELECT id FROM invoices WHERE id = ?', [id])",
    '  return rows[0] ?? null',
    '}',
    '',
  ].join('\n'),
  'services/admin/src/routes.ts': [
    "import { Router } from 'express'",
    "import { updateUser } from './controllers/users'",
    '',
    'export const adminRouter = Router()',
    "adminRouter.patch('/admin/users/:id', updateUser)",
    '',
  ].join('\n'),
  'services/admin/src/controllers/users.ts': [
    "import { setRole } from '../services/user-service'",
    '',
    'export async function updateUser(req: any, res: any) {',
    '  const user = await setRole(req.params.id, String(req.body?.role ?? "member"))',
    '  res.json({ user })',
    '}',
    '',
  ].join('\n'),
  'services/admin/src/services/user-service.ts': [
    "import { saveRole } from '../repos/user-repo'",
    '',
    'export async function setRole(id: string, role: string) {',
    '  return saveRole(id, role)',
    '}',
    '',
  ].join('\n'),
  'services/admin/src/repos/user-repo.ts': [
    "import { db } from '../../../../platform/src/db'",
    '',
    'export async function saveRole(id: string, role: string) {',
    "  await db.run('UPDATE users SET role = ? WHERE id = ?', [role, id])",
    '  return { id, role }',
    '}',
    '',
  ].join('\n'),
  'services/admin/src/routes.generated.runtime.ts': [
    "import { Router } from 'express'",
    "import { requireAdmin } from './middleware/authz'",
    '',
    'export const adminGeneratedRouter = Router()',
    'adminGeneratedRouter.use(requireAdmin)',
    "adminGeneratedRouter.patch('/admin/resource-1/:id', generatedHandler)",
    '',
    'function generatedHandler(_req: unknown, res: any) {',
    '  res.json({ ok: true })',
    '}',
    '',
  ].join('\n'),
  'services/admin/src/middleware/authz.ts': [
    'export function requireAdmin(req: any, res: any, next: any) {',
    '  if (req.user?.role !== "admin") { res.status(403).json({ error: "admin_required" }); return }',
    '  next()',
    '}',
    '',
  ].join('\n'),
}

function sliceFor(hypotheses: readonly CodeSliceHypothesis[], method: string, path: string) {
  return hypotheses.find(hypothesis =>
    hypothesis.method?.toUpperCase() === method && hypothesis.path === path)?.codeSlice
}

async function runWireRecon(t: TestContext, reposDir: string | undefined, maxCodeSlices?: number) {
  const { storage } = makeStore(t, 'kovo-v7-wire-db-')
  const setup = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 0, budgetRequests: 900 })
  const grant: Grant = makeLabGrant(ORIGIN, { tier: 0 })
  const result = await runPhase0Recon({
    storage,
    runId: setup.runId,
    scopeRevision: setup.run.scopeRevision,
    tier: 0,
    origins: [ORIGIN],
    budgetRequests: 900,
    ...(reposDir ? { reposDir } : {}),
    ...(maxCodeSlices !== undefined ? { maxCodeSlices } : {}),
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant,
    signal: AbortSignal.timeout(20_000),
  })
  const events = storage.eventsAfter(setup.runId, 0, 5000).filter(event => event.kind === 'phase0.code_slices')
  return { result, storage, events }
}

describe('v7 whitebox-wire: slices attached to Phase-0 hypotheses', () => {
  test('a four-hop sink route gets a <= 600 B slice stored on its hypothesis', async (t) => {
    const reposDir = writeRepo(t, MONOREPO)
    const { result } = await runWireRecon(t, reposDir)
    const hypotheses = result.codeToRuntimeHypotheses ?? []
    assert.ok(hypotheses.length > 0, 'the fixture yields code-to-runtime hypotheses')

    const slice = sliceFor(hypotheses, ...BILLING_ROUTE)
    assert.ok(slice, `expected a slice on ${BILLING_ROUTE.join(' ')}`)
    assert.equal(slice?.route, 'GET /v2/billing/invoices/:id')
    assert.deepEqual(slice?.mounts, ['/v2'])
    assert.equal(slice?.sink?.kind, 'db_query')
    assert.ok((slice?.hops.length ?? 0) >= 5, `expected route + 2 functions + sink, got ${slice?.hops.length}`)
    assert.ok(Buffer.byteLength(JSON.stringify(slice), 'utf8') <= 600)

    const summary = result.codeSlices
    assert.ok(summary, 'recon reports slice accounting')
    assert.equal(summary?.codeSlice, 'attached')
    assert.ok((summary?.attached ?? 0) >= 2, `attached=${summary?.attached}`)
    assert.ok((summary?.routes ?? 0) >= 2)
    assert.ok((summary?.avgBytes ?? 0) > 0 && (summary?.avgBytes ?? 0) <= 600, `avg=${summary?.avgBytes}`)
    assert.equal(summary?.candidates, hypotheses.filter(h => h.routeId || h.path).length)
    assert.equal(summary?.attached ?? 0, hypotheses.filter(h => h.codeSlice).length)
  })

  test('the unguarded admin route carries its sibling missing_guard diff inside the slice', async (t) => {
    const reposDir = writeRepo(t, MONOREPO)
    const { result } = await runWireRecon(t, reposDir)
    const slice = sliceFor(result.codeToRuntimeHypotheses ?? [], ...ADMIN_ROUTE)
    assert.ok(slice, `expected a slice on ${ADMIN_ROUTE.join(' ')}`)
    const diff = slice?.guardDiff?.find(entry => entry.kind === 'missing_guard')
    assert.ok(diff, 'expected missing_guard evidence inside the attached slice')
    assert.equal(diff?.guard, 'admin')
    assert.equal(diff?.symbol, 'requireAdmin')
    assert.match(String(diff?.sibling), /^PATCH \/v4\/admin\/resource-1\/:id$/)
    assert.ok((result.codeSlices?.guardDiffs ?? 0) >= 1, 'guard diffs are counted in metrics')
  })

  test('metrics event mirrors the summary and uses the documented metric names', async (t) => {
    const reposDir = writeRepo(t, MONOREPO)
    const { result, events } = await runWireRecon(t, reposDir)
    assert.equal(events.length, 1, 'one code-slice metric event per run')
    const detail = events[0]!.detail as Record<string, unknown>
    assert.equal(detail.codeSlice, 'attached')
    assert.equal(detail.code_slices_attached, result.codeSlices?.attached)
    assert.equal(detail.code_slices_unavailable, result.codeSlices?.unavailable)
    assert.equal(detail.avg_slice_bytes, result.codeSlices?.avgBytes)
    assert.equal(detail.guard_diffs, result.codeSlices?.guardDiffs)
    assert.equal(detail.max_slices, PHASE0_MAX_CODE_SLICES)
  })

  test('no mounted graph attaches nothing and records codeSlice unavailable', async (t) => {
    const { result, events } = await runWireRecon(t, undefined)
    assert.equal(result.codeToRuntimeHypotheses, undefined, 'no graph means no hypotheses')
    const summary = result.codeSlices
    assert.equal(summary?.attached, 0)
    assert.equal(summary?.routes, 0)
    assert.equal(summary?.codeSlice, 'unavailable')
    assert.ok(!JSON.stringify(result).includes('"hops"'), 'no fabricated slice payload')
    assert.equal(events.length, 1)
    const detail = events[0]!.detail as Record<string, unknown>
    assert.equal(detail.codeSlice, 'unavailable')
    assert.equal(detail.code_slices_attached, 0)
  })

  test('attachment is deterministic across independent extractions', (t) => {
    const reposDir = writeRepo(t, MONOREPO)
    const attach = () => {
      const extracted = extractRepoProgramGraph({ reposDir, origins: [ORIGIN] })
      assert.ok(extracted, 'AST extraction runs')
      const plan = rankAndClusterAstRoutes({ routes: extracted.routes, hypotheses: extracted.hypotheses })
      return attachCodeSlicesToPhase0Hypotheses({
        graph: extracted.graph,
        hypotheses: extracted.hypotheses,
        priorityRouteIds: new Set(plan.priority.map(route => route.routeId).filter((id): id is string => Boolean(id))),
        priorityRouteKeys: new Set(plan.priority.map(route => `${route.method.toUpperCase()} ${route.pathTemplate}`)),
        schemaTypedRouteIds: new Set(plan.schemaTyped.map(route => route.routeId).filter((id): id is string => Boolean(id))),
        schemaTypedRouteKeys: new Set(plan.schemaTyped.map(route => `${route.method.toUpperCase()} ${route.pathTemplate}`)),
      })
    }
    const first = attach()
    const second = attach()
    assert.deepEqual(first.summary, second.summary)
    assert.deepEqual(
      first.hypotheses.map(hypothesis => hypothesis.codeSlice),
      second.hypotheses.map(hypothesis => hypothesis.codeSlice),
    )
    assert.ok(first.summary.attached > 0)
  })
})

/** Synthetic 2,500-route graph: no nodes/edges, so each slice is a compact route hop. */
function syntheticGraph(routeCount: number): { graph: ProgramGraph; hypotheses: CodeToRuntimeHypothesis[] } {
  const routes: ProgramRoute[] = []
  const nodes: ProgramNode[] = []
  const hypotheses: CodeToRuntimeHypothesis[] = []
  for (let i = 0; i < routeCount; i += 1) {
    const route: ProgramRoute = {
      id: `route-${i}`,
      framework: 'express',
      method: 'GET',
      path: `/v4/generated/resource-${i}/:id`,
      file: `services/generated/src/routes/resource-${i}.ts`,
      line: 4,
      handler: `handler${i}`,
      input: { params: ['id'], query: [], body: [], schemas: [] },
      middleware: [],
      guards: [],
      mountedFrom: ['/v4'],
      extraction: 'ast',
    }
    routes.push(route)
    nodes.push({
      id: `node-${i}`,
      kind: 'route',
      symbol: `route${i}`,
      file: route.file,
      line: route.line,
      routePath: route.path,
      httpMethod: route.method,
      guards: [],
      calls: [],
    })
    hypotheses.push({
      id: `hyp:tenant:route-${i}`,
      kind: 'tenant_param_without_scope',
      severity: 'high',
      confidence: 0.7,
      framework: 'express',
      method: route.method,
      path: route.path,
      file: route.file,
      line: route.line,
      routeId: route.id,
      rationale: `Mutating ${route.method} ${route.path} reads an object id without a tenant guard.`,
      evidence: [],
      probeClass: 'bola_bfla',
    })
  }
  return {
    graph: { filesScanned: routeCount, frameworks: ['express'], routes, nodes, edges: [], globalMiddleware: [], warnings: [] },
    hypotheses,
  }
}

describe('v7 whitebox-wire: bounded slice budget', () => {
  test('2,500 routes respect the 200-slice cap, slice Tier-A first and stay under 1 s', () => {
    const routeCount = 2_500
    const { graph, hypotheses } = syntheticGraph(routeCount)
    // Tier-A: a single hypothesis-linked route at the very end of the graph ordering, so only
    // priority ranking (not input order) can slice it inside the cap.
    const priorityId = `route-${routeCount - 1}`
    const started = performance.now()
    const attached = attachCodeSlicesToPhase0Hypotheses({
      graph,
      hypotheses,
      priorityRouteIds: new Set([priorityId]),
    })
    const elapsedMs = performance.now() - started

    assert.ok(attached.summary.routes <= PHASE0_MAX_CODE_SLICES, `routes=${attached.summary.routes}`)
    assert.equal(attached.summary.routes, PHASE0_MAX_CODE_SLICES)
    assert.equal(attached.summary.attached, PHASE0_MAX_CODE_SLICES)
    assert.equal(attached.summary.capped, routeCount - PHASE0_MAX_CODE_SLICES)
    assert.equal(attached.summary.codeSlice, 'attached')
    assert.ok((attached.summary.avgBytes ?? 0) <= 600, `avg=${attached.summary.avgBytes}`)

    const priorityHypothesis = attached.hypotheses.find(hypothesis => hypothesis.routeId === priorityId)
    assert.ok(priorityHypothesis?.codeSlice, 'Tier-A route is sliced before the long tail')
    const unslicedTail = attached.hypotheses.find(hypothesis => hypothesis.routeId !== priorityId && !hypothesis.codeSlice)
    assert.ok(unslicedTail, 'non-priority tail routes stay slice-free once capped')

    assert.ok(elapsedMs < 1_000, `slice attachment took ${Math.round(elapsedMs)} ms for ${routeCount} routes`)
  })
})
