/**
 * v7 Whitebox (M1/M2): code evidence in agent briefs.
 *
 * Covers the five brief-evidence deliverables against synthetic monorepo sources only
 * (no benchmark app, seed, route or challenge identifier is consulted):
 *
 *   1. a 4-hop route -> controller -> service -> repository sink produces a <= 600 B slice that
 *      the assignment brief renders;
 *   2. a sibling route carrying `requireAdmin` yields explicit `missing_guard` evidence with the
 *      sibling file:line, both on the hypothesis and inside the slice;
 *   3. module secret-shaped literals become value-free `code_hint`s (the literal is never rendered);
 *   4. briefs stay under the 4 KB hard ceiling, even with an expanded slice and adversarial inputs;
 *   5. output is deterministic and building slices/briefs never edits repository sources;
 *   6. `resolveSuspectEntrypoint` returns the full chain (depth >= 6) plus guards and sink.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import {
  ASSIGNMENT_BRIEF_CODE_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES,
  ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE,
  buildAssignmentBriefPacket,
  measureAssignmentBriefBytes,
} from '../src/server/assignment-brief.ts'
import {
  CODE_DATAFLOW_SLICE_MAX_BYTES,
  buildCodeDataflowSlice,
  deriveCodeToRuntimeHypotheses,
  expandCodeSlicePath,
  extractProgramGraph,
  renderCodeDataflowSlice,
  renderCodeDataflowSliceText,
} from '../src/server/program-graph.ts'
import type { CodeDataflowSlice } from '../src/server/program-graph.ts'
import { resolveSuspectEntrypoint } from '../src/server/semantic-audit.ts'

const ADMIN_USERS_ROUTE = ['PATCH', '/v3/admin/users/:id'] as const
const BILLING_ROUTE = ['GET', '/v2/billing/invoices/:id'] as const
const DEEP_ROUTE = ['GET', '/deep/:id'] as const
const SECRET_VALUE = 'sk_live_ABCDEFGHIJKLMNOP'

interface RepoTree {
  dir: string
  files: ReadonlyArray<{ path: string; content: string }>
}

function writeTree(t: TestContext, files: Record<string, string>): RepoTree {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v7-whitebox-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return {
    dir,
    files: Object.entries(files).map(([path, content]) => ({ path, content })),
  }
}

/**
 * Synthetic monorepo: nested /v2 + /v3 mounts, a four-hop billing sink, an admin route mounted
 * before its authz middleware, a generated `/v4/admin` router that *does* carry `requireAdmin`
 * (the sibling diff), a secret in the billing module, and a seven-hop `/deep` chain.
 */
const MONOREPO: Record<string, string> = {
  'services/gateway/src/router.ts': [
    "import { Router } from 'express'",
    "import { billingRouter } from '../../billing/src/routes'",
    "import { adminRouter } from '../../admin/src/routes'",
    "import { adminGeneratedRouter } from '../../admin/src/routes.generated.runtime'",
    "import { deepRouter } from '../../deep/src/routes'",
    '',
    'export const app = Router()',
    "app.use('/v2', billingRouter)",
    // Mounted before any authz middleware: the ordering regression under test.
    "app.use('/v3', adminRouter)",
    "app.use('/v4', adminGeneratedRouter)",
    "app.use('/deep', deepRouter)",
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
    '  const actor = req.user',
    '  if (!actor) { res.status(401).json({ error: "unauthorized" }); return }',
    '  const invoice = await loadInvoice(req.params.id, actor.tenantId)',
    '  res.json({ invoice })',
    '}',
    '',
  ].join('\n'),
  'services/billing/src/services/invoice-service.ts': [
    "import { findById } from '../repos/invoice-repo'",
    '',
    'export async function loadInvoice(id: string, tenantId: string) {',
    '  return findById(id, tenantId)',
    '}',
    '',
  ].join('\n'),
  'services/billing/src/repos/invoice-repo.ts': [
    "import { db } from '../../../../platform/src/db'",
    '',
    'export async function findById(id: string, _tenantId: string) {',
    "  const rows = await db.all('SELECT id FROM invoices WHERE id = ?', [id])",
    '  return rows[0] ?? null',
    '}',
    '',
  ].join('\n'),
  // Secret-shaped literal in the billing module: hint must never carry the value.
  'services/billing/.env.production': [
    'DATABASE_URL=postgres://billing:hunter2@db.internal/billing',
    `PAYMENT_API_KEY=${SECRET_VALUE}`,
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
  'services/deep/src/routes.ts': [
    "import { Router } from 'express'",
    '',
    'export const deepRouter = Router()',
    '',
    'function requireAuth(req: any, res: any, next: any) {',
    '  if (!req.user) { res.status(401).json({}); return }',
    '  next()',
    '}',
    '',
    'export function getDeep(req: any, res: any) {',
    '  const rows = levelOne(req.params.id)',
    '  res.json({ rows })',
    '}',
    '',
    "deepRouter.get('/:id', requireAuth, getDeep)",
    '',
  ].join('\n'),
  'services/deep/src/levels.ts': [
    'export function levelOne(id: string) { return levelTwo(id) }',
    'export function levelTwo(id: string) { return levelThree(id) }',
    'export function levelThree(id: string) { return levelFour(id) }',
    'export function levelFour(id: string) { return levelFive(id) }',
    '',
    'export function levelFive(id: string) {',
    "  return db.query('SELECT * FROM deep WHERE id = ' + id)",
    '}',
    '',
  ].join('\n'),
  // Nest controller proving the input schema (query names) survives extraction into the slice.
  'services/reports/src/export.controller.ts': [
    "import { Controller, Get, Query, UseGuards } from '@nestjs/common'",
    "import { TenantGuard } from './tenant.guard'",
    '',
    "@Controller('reports')",
    '@UseGuards(TenantGuard)',
    'export class ReportsController {',
    "  @Get('export')",
    '  exportCsv(@Query("sort") sort: string): string {',
    '    return buildCsv(sort)',
    '  }',
    '}',
    '',
  ].join('\n'),
  'services/reports/src/tenant.guard.ts': [
    'export class TenantGuard {',
    '  canActivate(context: unknown): boolean { return Boolean(context) }',
    '}',
    '',
  ].join('\n'),
}

function graphFor(repo: RepoTree) {
  return extractProgramGraph({ files: repo.files, repo: 'synthetic-monorepo' })
}

function findSlice(repo: RepoTree, method: string, path: string): CodeDataflowSlice {
  const graph = graphFor(repo)
  const slice = buildCodeDataflowSlice(graph, `${method} ${path}`, { files: repo.files })
  assert.ok(slice, `expected a slice for ${method} ${path}`)
  return slice
}

describe('v7 whitebox: dataflow slices in briefs', () => {
  test('4-hop route slice carries mounts, input, sink kind and exact file:line hops', (t) => {
    const repo = writeTree(t, MONOREPO)
    const slice = findSlice(repo, ...BILLING_ROUTE)

    assert.equal(slice.route, 'GET /v2/billing/invoices/:id')
    assert.deepEqual(slice.mounts, ['/v2'])
    // The only declared input on this route is the path parameter, already visible in `route`.
    assert.equal(slice.input, undefined)
    assert.equal(slice.auth, 'unguarded')
    assert.equal(slice.sink?.kind, 'db_query')
    assert.ok(slice.sink?.at.includes('invoice-repo.ts'))
    assert.ok(slice.hops.length >= 5, `expected route + 3 functions + sink, got ${slice.hops.length}`)
    assert.equal(slice.hops[0].kind, 'route')
    assert.equal(slice.hops[slice.hops.length - 1].kind, 'sink')
    assert.equal(slice.truncated, undefined)
    const expanded = slice.hops.map(hop => expandCodeSlicePath(slice, hop.at))
    assert.ok(expanded.some(at => at.startsWith('services/billing/src/repos/invoice-repo.ts:')))
    assert.ok(Buffer.byteLength(JSON.stringify(slice), 'utf8') <= CODE_DATAFLOW_SLICE_MAX_BYTES)
  })

  test('brief renders the slice and keeps it inside the slice budget', (t) => {
    const repo = writeTree(t, MONOREPO)
    const slice = findSlice(repo, ...BILLING_ROUTE)
    const packet = buildAssignmentBriefPacket({
      missionKind: 'class_scan',
      origin: 'https://mono.local',
      routes: [{ method: 'GET', path: '/v2/billing/invoices/:id', params: ['id'], riskScore: 80 }],
      personas: [{ handle: 'mono-alice', role: 'member', harvestedIds: ['inv-alpha-1'] }],
      codeSlice: slice,
    })
    const parsed = JSON.parse(packet.text) as { code?: CodeDataflowSlice; routes: unknown[] }
    assert.ok(parsed.code, 'brief must render the code slice')
    assert.equal(parsed.code?.sink?.kind, 'db_query')
    assert.ok((parsed.code?.hops.length ?? 0) >= 4)
    assert.ok(Buffer.byteLength(JSON.stringify(parsed.code), 'utf8') <= ASSIGNMENT_BRIEF_CODE_MAX_BYTES)
    assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  })

  test('Nest input schema (query names) and guard chain survive into the slice', (t) => {
    const repo = writeTree(t, MONOREPO)
    const slice = findSlice(repo, 'GET', '/reports/export')
    assert.deepEqual(slice.input?.query, ['sort'])
    assert.equal(slice.auth, 'guarded')
    assert.ok(slice.guards.some(guard => guard.includes('TenantGuard')))
  })

  test('slice rendering is deterministic and hard-truncated', (t) => {
    const repo = writeTree(t, MONOREPO)
    const graph = graphFor(repo)
    const first = buildCodeDataflowSlice(graph, `${BILLING_ROUTE[0]} ${BILLING_ROUTE[1]}`, { files: repo.files })
    const second = buildCodeDataflowSlice(graphFor(repo), `${BILLING_ROUTE[0]} ${BILLING_ROUTE[1]}`, { files: repo.files })
    assert.deepEqual(first, second)

    const fat: CodeDataflowSlice = {
      ...(first as CodeDataflowSlice),
      mounts: ['/a'.repeat(40)],
      guards: Array.from({ length: 12 }, (_, i) => `guard_${i}_with_a_long_name`),
      hops: Array.from({ length: 20 }, (_, i) => ({ at: `very/long/path/segment-${i}/file-${i}.ts:${i + 1}` })),
      hints: Array.from({ length: 6 }, (_, i) => ({ kind: 'secret' as const, at: `svc/.env:${i + 1}`, note: 'secret-shaped assignment' })),
    }
    const rendered = renderCodeDataflowSlice(fat, 320)
    assert.ok(rendered.bytes <= 320)
    assert.equal(rendered.truncated, true)
    assert.equal(measureSize(rendered.text), rendered.bytes)
    assert.equal(renderCodeDataflowSliceText(fat, 320), rendered.text)
  })
})

function measureSize(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}

describe('v7 whitebox: sibling guard diffs', () => {
  test('admin route without its guard yields missing_guard with the sibling file:line', (t) => {
    const repo = writeTree(t, MONOREPO)
    const graph = graphFor(repo)
    const slice = buildCodeDataflowSlice(graph, `${ADMIN_USERS_ROUTE[0]} ${ADMIN_USERS_ROUTE[1]}`, { files: repo.files })
    assert.ok(slice)
    assert.equal(slice?.auth, 'unguarded')
    const diff = slice?.guardDiff?.find(candidate => candidate.kind === 'missing_guard')
    assert.ok(diff, 'expected missing_guard evidence on the unguarded admin route')
    assert.equal(diff?.guard, 'admin')
    assert.equal(diff?.symbol, 'requireAdmin')
    assert.match(String(diff?.at), /services\/admin\/src\/routes\.generated\.runtime\.ts:\d+/)
    assert.match(String(diff?.sibling), /^PATCH \/v4\/admin\/resource-1\/:id$/)

    const hypothesis = deriveCodeToRuntimeHypotheses(graph)
      .find(candidate => candidate.kind === 'admin_route_missing_admin_guard' && candidate.path === '/v3/admin/users/:id')
    assert.ok(hypothesis, 'expected the admin guard hypothesis')
    const evidence = hypothesis?.evidence.find(item => item.startsWith('missing_guard=admin'))
    assert.ok(evidence, `expected missing_guard evidence, got ${JSON.stringify(hypothesis?.evidence)}`)
    assert.match(evidence as string, /requireAdmin@services\/admin\/src\/routes\.generated\.runtime\.ts:\d+/)
    assert.match(evidence as string, /sibling PATCH \/v4\/admin\/resource-1\/:id/)
  })

  test('the guarded sibling itself reports no diff', (t) => {
    const repo = writeTree(t, MONOREPO)
    const slice = findSlice(repo, 'PATCH', '/v4/admin/resource-1/:id')
    assert.equal(slice.auth, 'guarded')
    assert.deepEqual(slice.guards, ['requireAdmin'])
    assert.equal(slice.guardDiff, undefined)
  })

  test('tenant-scope sibling diff uses the same missing_guard evidence shape', (t) => {
    const repo = writeTree(t, {
      'services/catalog/src/routes.ts': [
        "import { Router } from 'express'",
        "import { getItem } from './controllers/items'",
        'export const catalogRouter = Router()',
        "catalogRouter.get('/catalog/items/:id', getItem)",
        '',
      ].join('\n'),
      'services/catalog/src/controllers/items.ts': [
        'export function getItem(req: any, res: any) { res.json({ id: req.params.id }) }',
        '',
      ].join('\n'),
      'services/catalog/src/routes.generated.runtime.ts': [
        "import { Router } from 'express'",
        "import { requireTenantScope } from './middleware/tenant'",
        'export const catalogGeneratedRouter = Router()',
        'catalogGeneratedRouter.use(requireTenantScope)',
        "catalogGeneratedRouter.get('/catalog/resource-1/:id', handler)",
        'function handler(_req: unknown, res: any) { res.json({ ok: true }) }',
        '',
      ].join('\n'),
      'services/catalog/src/middleware/tenant.ts': [
        'export function requireTenantScope(req: any, res: any, next: any) {',
        '  if (!req.user?.tenantId) { res.status(403).json({}); return }',
        '  next()',
        '}',
        '',
      ].join('\n'),
    })
    const slice = findSlice(repo, 'GET', '/catalog/items/:id')
    assert.equal(slice.auth, 'unguarded')
    const diff = slice.guardDiff?.find(candidate => candidate.kind === 'missing_guard')
    assert.ok(diff, 'expected a tenant missing_guard diff')
    assert.equal(diff?.guard, 'tenant')
    assert.equal(diff?.symbol, 'requireTenantScope')
    assert.match(String(diff?.at), /services\/catalog\/src\/routes\.generated\.runtime\.ts:\d+/)
    assert.equal(diff?.sibling, 'GET /catalog/resource-1/:id')
  })
})

describe('v7 whitebox: secrets and IaC hints', () => {
  test('secret-shaped literals become value-free hints and never leak', (t) => {
    const repo = writeTree(t, MONOREPO)
    const slice = findSlice(repo, ...BILLING_ROUTE)
    const hints = slice.hints ?? []
    assert.ok(hints.length >= 1, 'expected at least one module secret hint')
    assert.ok(hints.every(hint => hint.kind === 'secret' || hint.kind === 'iac'))
    assert.ok(hints.some(hint => hint.kind === 'secret'))
    assert.ok(hints.every(hint => /\.env[^:]*:\d+$/.test(hint.at)))
    assert.ok(hints.every(hint => !hint.note.includes(SECRET_VALUE)))

    const text = renderCodeDataflowSliceText(slice)
    assert.ok(!text.includes(SECRET_VALUE), 'slice text must not contain the secret value')
    assert.ok(!text.includes('hunter2'), 'slice text must not contain connection-string credentials')

    const packet = buildAssignmentBriefPacket({
      missionKind: 'class_scan',
      origin: 'https://mono.local',
      routes: [{ method: 'GET', path: '/v2/billing/invoices/:id', params: ['id'], riskScore: 80 }],
      codeSlice: slice,
      codeExpansion: 'full',
    })
    assert.ok(!packet.text.includes(SECRET_VALUE))
    assert.ok(!packet.text.includes('hunter2'))
    assert.match(packet.text, /"kind":"secret"/)

    // Hints are also attached to the program graph at extraction time, so a caller without
    // repository sources still gets them (values stay redacted).
    const graph = graphFor(repo)
    const fromGraph = buildCodeDataflowSlice(graph, `${BILLING_ROUTE[0]} ${BILLING_ROUTE[1]}`)
    assert.ok((fromGraph?.hints?.length ?? 0) >= 1)
    assert.ok(!JSON.stringify(fromGraph).includes(SECRET_VALUE))
  })
})

describe('v7 whitebox: brief size and determinism', () => {
  test('brief stays under the 4 KB ceiling with an expanded slice and adversarial input', (t) => {
    const repo = writeTree(t, MONOREPO)
    const slice = findSlice(repo, ...BILLING_ROUTE)
    const routes = Array.from({ length: 40 }, (_, i) => ({
      method: i % 2 ? 'POST' : 'GET',
      path: `/api/tenant/${i}/resource-with-a-long-name/${'x'.repeat(60)}`,
      params: Array.from({ length: 10 }, (_, p) => `parameter_${p}_with_a_long_name`),
      riskScore: i % 100,
    }))
    const packet = buildAssignmentBriefPacket({
      missionKind: 'class_scan',
      origin: 'https://mono.local',
      routes,
      linkedRoutes: routes.slice(0, 20),
      personas: Array.from({ length: 20 }, (_, i) => ({
        handle: `persona_${i}`,
        role: 'tenant_member',
        harvestedIds: [`resource-${i}`],
      })),
      baseline: {
        status: 200,
        topLevelKeys: Array.from({ length: 40 }, (_, i) => `top_level_key_${i}`),
        sampleNumericOrStateFields: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`field_${i}`, i])),
      },
      alreadyConfirmedOnOrigin: Array.from({ length: 20 }, (_, i) => ({ method: 'GET', path: `/api/confirmed/${i}` })),
      codeSlice: slice,
      codeExpansion: 'full',
    })
    assert.ok(packet.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE, `bytes=${packet.bytes}`)
    assert.ok(packet.bytes <= 4096)
    assert.equal(measureAssignmentBriefBytes(packet.text), packet.bytes)
    assert.equal(JSON.parse(packet.text).mission, 'class_scan')

    const compact = buildAssignmentBriefPacket({ missionKind: 'class_scan', origin: 'https://mono.local', codeSlice: slice })
    assert.ok(compact.bytes <= ASSIGNMENT_BRIEF_MAX_BYTES)
  })

  test('repeated slice and brief builds are byte-identical', (t) => {
    const repo = writeTree(t, MONOREPO)
    const first = findSlice(repo, ...BILLING_ROUTE)
    const second = findSlice(repo, ...BILLING_ROUTE)
    assert.deepEqual(first, second)
    const briefInput = {
      missionKind: 'class_scan' as const,
      origin: 'https://mono.local',
      routes: [{ method: 'GET', path: '/v2/billing/invoices/:id', params: ['id'], riskScore: 80 }],
      personas: [{ handle: 'mono-alice', role: 'member', harvestedIds: ['inv-alpha-1'] }],
      codeSlice: first,
    }
    const a = buildAssignmentBriefPacket(briefInput)
    const b = buildAssignmentBriefPacket({ ...briefInput, codeSlice: second })
    assert.equal(a.text, b.text)
    assert.equal(a.bytes, b.bytes)
  })
})

describe('v7 whitebox: runtime purity and multi-hop binding', () => {
  test('building slices and briefs never edits repository sources', (t) => {
    const repo = writeTree(t, MONOREPO)
    const relative = Object.keys(MONOREPO)
    const snapshot = () => relative.map(path => {
      const full = join(repo.dir, path)
      const stat = statSync(full)
      return {
        path,
        hash: createHash('sha256').update(readFileSync(full)).digest('hex'),
        bytes: stat.size,
        mtimeMs: stat.mtimeMs,
      }
    })
    const before = snapshot()
    const graph = graphFor(repo)
    for (const [method, path] of [BILLING_ROUTE, ADMIN_USERS_ROUTE, DEEP_ROUTE]) {
      const slice = buildCodeDataflowSlice(graph, `${method} ${path}`, { files: repo.files })
      if (slice) {
        buildAssignmentBriefPacket({ missionKind: 'class_scan', origin: 'https://mono.local', codeSlice: slice })
      }
    }
    deriveCodeToRuntimeHypotheses(graph)
    resolveSuspectEntrypoint(undefined, { file: 'services/deep/src/levels.ts', line: 7 }, undefined, { programGraph: graph })
    assert.deepEqual(snapshot(), before)
  })

  test('suspect binding returns the full chain and guards (depth >= 6)', (t) => {
    const repo = writeTree(t, MONOREPO)
    const graph = graphFor(repo)
    const resolved = resolveSuspectEntrypoint(
      undefined,
      { file: 'services/deep/src/levels.ts', line: 7 },
      undefined,
      { programGraph: graph },
    )
    assert.ok(resolved, 'expected a resolved entrypoint for the deep sink')
    assert.equal(resolved?.routePath, '/deep/:id')
    assert.equal(resolved?.httpMethod, 'GET')
    assert.equal(resolved?.matchedBy, 'reverse')
    assert.ok((resolved?.chain?.length ?? 0) >= 6, `chain=${JSON.stringify(resolved?.chain)}`)
    assert.ok((resolved?.depth ?? 0) >= 5)
    assert.equal(resolved?.chain?.[0].kind, 'route')
    assert.equal(resolved?.chain?.[resolved.chain.length - 1].kind, 'sink')
    assert.equal(resolved?.sink?.kind, 'db_query')
    assert.ok(resolved?.guards?.includes('requireAuth'), `guards=${JSON.stringify(resolved?.guards)}`)
    const symbols = resolved?.chain?.map(hop => hop.symbol) ?? []
    assert.deepEqual(symbols.slice(0, 5), ['getDeep', 'getDeep', 'levelOne', 'levelTwo', 'levelThree'])
  })
})
