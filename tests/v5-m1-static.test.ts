import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  advisoryMatchesVersion,
  parseSemver,
  queryCves,
  versionSatisfiesRange,
} from '../src/server/cve-broker.ts'
import {
  analyzeSinkBackwardPaths,
  codeAuditSuspectLocationKey,
  dedupeCodeAuditSuspects,
  toChainStepInputs,
} from '../src/server/semantic-audit.ts'
import type {
  CallGraphIndex,
  CallGraphNode,
  ProjectSecuritySpec,
  SemanticAuditSuspect,
} from '../src/server/semantic-audit.ts'
import type { CodeAuditSuspectData } from '../src/server/agent-session.ts'
import type { Run } from '../src/server/store.ts'
import { buildCallGraphFromFiles } from '../worker/analyzers.ts'

// ---------------------------------------------------------------------------
// 1. Guard vs. sanitizer separation and statement-order dominance (worker AST)
// ---------------------------------------------------------------------------

const staticFiles = [
  {
    file: 'src/db.ts',
    content: `export function runQuery(db: any, sql: string) { return db.query(sql); }\n`,
  },
  {
    file: 'src/routes/orders.ts',
    content: `import { runQuery } from '../db.ts'\n` + [
      `app.get('/api/admin/orders', async (req, res) => {`,
      `  // requireAuth(req) — commented out, must not dominate`,
      `  const page = parseInt(String(req.query.page ?? '1'), 10)`,
      `  return res.json(await runQuery(db, 'SELECT * FROM orders LIMIT ' + page))`,
      `})`,
      ``,
      `app.get('/api/reports', async (req, res) => {`,
      `  requireAuth(req)`,
      `  return res.json(await runQuery(db, 'SELECT * FROM reports WHERE id = ' + req.query.id))`,
      `})`,
      ``,
      `app.get('/api/proxy', async (req, res) => {`,
      `  requireAuth(req)`,
      `  return fetch(req.query.url).then(r => res.send(r))`,
      `})`,
      ``,
      `app.get('/api/post-check', async (req, res) => {`,
      `  const rows = await runQuery(db, 'SELECT * FROM t WHERE id=' + req.query.id)`,
      `  requireAuth(req) // post-sink check, must not dominate`,
      `  return res.json(rows)`,
      `})`,
      ``,
      `app.get('/api/string-guard', async (req, res) => {`,
      `  const note = 'requireAuth(req)'`,
      `  return res.json(await runQuery(db, 'SELECT * FROM t WHERE name=' + req.query.name))`,
      `})`,
    ].join('\n'),
  },
]

function pathsFor(route: string) {
  const cg = buildCallGraphFromFiles(staticFiles)
  const paths = cg.taintPaths.filter(p => p.routeOrAction === route)
  assert.ok(paths.length > 0, `expected a taint path for ${route}`)
  return paths
}

test('M1-static T1: parseInt sanitizer does not suppress a missing authz guard', () => {
  const [path] = pathsFor('/api/admin/orders')
  assert.equal(path.isAuthUnguarded, true, 'missing authz guard must be reported')
  assert.equal(path.dominatingGuards.length, 0, 'comment-only/absent guards must not dominate')
  assert.equal(path.isInjectionUnsanitized, false, 'parseInt is a real sanitizer for this sink')
  assert.ok(path.dominatingSanitizers.includes('parseInt'))
  assert.equal(path.isUnguardedPath, true)
})

test('M1-static T2: an auth guard does not sanitize a SQL or SSRF sink', () => {
  const reports = pathsFor('/api/reports')
  assert.ok(reports.some(p => p.isAuthUnguarded === false && p.isInjectionUnsanitized === true))
  const proxy = pathsFor('/api/proxy')
  assert.ok(proxy.some(p => p.isAuthUnguarded === false && p.isInjectionUnsanitized === true))
  assert.ok(proxy.every(p => p.dominatingGuards.includes('requireAuth')))
})

test('M1-static T3: post-sink checks, comments and string literals do not dominate', () => {
  const postCheck = pathsFor('/api/post-check')
  assert.ok(postCheck.every(p => !p.dominatingGuards.includes('requireAuth')))
  assert.ok(postCheck.some(p => p.isAuthUnguarded === true))

  const stringGuard = pathsFor('/api/string-guard')
  assert.ok(stringGuard.every(p => p.dominatingGuards.length === 0))
})

// ---------------------------------------------------------------------------
// 2. Semantic audit graph-level separation
// ---------------------------------------------------------------------------

function node(partial: Partial<CallGraphNode> & Pick<CallGraphNode, 'id' | 'symbol'>): CallGraphNode {
  return {
    file: 'src/app.ts',
    line: 1,
    kind: 'function',
    guards: [],
    sanitizers: [],
    calls: [],
    ...partial,
  }
}

function graph(nodes: CallGraphNode[], edges: CallGraphIndex['edges']): CallGraphIndex {
  return { repo: 'app', filesScanned: nodes.length, nodes, edges, analyzerSource: 'worker_analyzer' }
}

const emptySpec = { sinks: [] } as unknown as ProjectSecuritySpec

test('M1-static T4: semantic backward paths keep auth and injection findings independent', () => {
  const g = graph([
    node({ id: 'ep-admin', symbol: 'GET /api/admin', kind: 'entrypoint', routePath: '/api/admin', sanitizers: ['parseInt'] }),
    node({ id: 'sink-route', symbol: 'handler', kind: 'sink', sinkKind: 'api_route' }),
    node({ id: 'ep-sql', symbol: 'GET /api/reports', kind: 'entrypoint', routePath: '/api/reports', guards: ['requireAuth'] }),
    node({ id: 'sink-sql', symbol: 'runQuery', kind: 'sink', sinkKind: 'db_query' }),
  ], [
    { fromId: 'ep-admin', toId: 'sink-route', file: 'src/app.ts', line: 1 },
    { fromId: 'ep-sql', toId: 'sink-sql', file: 'src/app.ts', line: 10 },
  ])

  const paths = analyzeSinkBackwardPaths(g, emptySpec)
  const authPath = paths.find(p => p.routeOrAction === '/api/admin')
  assert.ok(authPath)
  assert.equal(authPath.isAuthUnguarded, true, 'parseInt must not substitute for an auth guard')
  assert.equal(authPath.isInjectionUnsanitized, false)

  const sqlPath = paths.find(p => p.routeOrAction === '/api/reports')
  assert.ok(sqlPath)
  assert.equal(sqlPath.isAuthUnguarded, false, 'requireAuth satisfies the auth check')
  assert.equal(sqlPath.isInjectionUnsanitized, true, 'requireAuth must not sanitize a SQL sink')
  assert.equal(sqlPath.isUnguardedPath, true)
})

// ---------------------------------------------------------------------------
// 3. dependsOnFactIds and suspect dedupe
// ---------------------------------------------------------------------------

function suspect(overrides: Partial<SemanticAuditSuspect> = {}): SemanticAuditSuspect {
  const data: CodeAuditSuspectData = {
    subkind: 'code_audit_suspect',
    repo: 'app',
    file: 'src/routes/orders.ts',
    line: 10,
    routeOrAction: '/api/orders',
    authCheck: 'missing',
    ownershipCheck: 'missing',
    sinkKind: 'db_query',
    hypothesis: 'SQL sink reached without sanitizer.',
    recommendedTier: 2,
  }
  return {
    id: 'suspect-1',
    fingerprint: 'fp-1',
    stage: 'stage2_backward_taint',
    origin: 'https://app.m1test.example',
    repo: data.repo,
    file: data.file,
    line: data.line,
    routeOrAction: data.routeOrAction,
    authCheck: data.authCheck,
    ownershipCheck: data.ownershipCheck,
    sinkKind: data.sinkKind,
    severity: 'high',
    priorityScore: 72,
    recommendedTier: 2,
    specialistProfile: 'injection-parser-specialist',
    hypothesis: data.hypothesis,
    data,
    ...overrides,
  }
}

const runStub = {
  candidates: [{ id: 'asset-1', origin: 'https://app.m1test.example' }],
  approved: ['asset-1'],
} as unknown as Pick<Run, 'candidates' | 'approved'>

test('M1-static T5: toChainStepInputs links persisted fact ids and dedupes locations', () => {
  const first = suspect()
  const duplicate = suspect({ id: 'suspect-2', fingerprint: 'fp-2', stage: 'stage3_variant_sweep' })
  const otherSink = suspect({
    id: 'suspect-3',
    fingerprint: 'fp-3',
    sinkKind: 'outbound_fetch',
    data: { ...first.data, sinkKind: 'outbound_fetch', line: 30 },
    line: 30,
  })

  const steps = toChainStepInputs(
    runStub,
    [first, duplicate, otherSink],
    undefined,
    ['fact-1', 'fact-2', 'fact-3'],
  )
  assert.equal(steps.length, 2, 'same (repo, file, line, sinkKind) must be queued once')
  assert.deepEqual(steps[0].dependsOnFactIds, ['fact-1'])
  assert.deepEqual(steps[1].dependsOnFactIds, ['fact-3'])
})

test('M1-static T6: code-audit suspects dedupe by (repo, file, line, sinkKind)', () => {
  const base = suspect()
  const facts = [
    { id: 'fact-1', data: base.data },
    { id: 'fact-2', data: { ...base.data } },
    { id: 'fact-3', data: { ...base.data, line: 11 } },
    { id: 'fact-4', data: { ...base.data, sinkKind: 'outbound_fetch' } },
  ]
  const deduped = dedupeCodeAuditSuspects(facts)
  assert.deepEqual(deduped.map(f => f.id), ['fact-1', 'fact-3', 'fact-4'])
  assert.equal(
    codeAuditSuspectLocationKey({ repo: 'app', file: 'src/a.ts', line: 3, sinkKind: 'api_route' }),
    'app|src/a.ts|3|api_route',
  )
  // Facts without a file location fall back to their own id (never collapse).
  assert.equal(dedupeCodeAuditSuspects([{ id: 'a', data: {} }, { id: 'b', data: {} }]).length, 2)
})

// ---------------------------------------------------------------------------
// 4. CVE affected-range semver evaluation
// ---------------------------------------------------------------------------

test('M1-static T7: semver comparator matrix (unions, hyphen ranges, patches)', () => {
  const union = '<15.2.3 || >=16.0.0 <16.1.0'
  assert.equal(versionSatisfiesRange('15.2.2', union), true)
  assert.equal(versionSatisfiesRange('15.2.3', union), false)
  assert.equal(versionSatisfiesRange('15.5.0', union), false)
  assert.equal(versionSatisfiesRange('16.0.0', union), true)
  assert.equal(versionSatisfiesRange('16.0.9', union), true)
  assert.equal(versionSatisfiesRange('16.1.0', union), false)

  const hyphen = '19.0.0 - 19.2.0'
  assert.equal(versionSatisfiesRange('19.0.0', hyphen), true)
  assert.equal(versionSatisfiesRange('19.1.4', hyphen), true)
  assert.equal(versionSatisfiesRange('19.2.0', hyphen), true)
  assert.equal(versionSatisfiesRange('19.2.1', hyphen), false)
  assert.equal(versionSatisfiesRange('18.9.9', hyphen), false)

  assert.equal(versionSatisfiesRange('1.2.3', '^1.2.0'), true)
  assert.equal(versionSatisfiesRange('2.0.0', '^1.2.0'), false)
  assert.equal(versionSatisfiesRange('1.2.9', '~1.2.3'), true)
  assert.equal(versionSatisfiesRange('1.3.0', '~1.2.3'), false)
  assert.equal(versionSatisfiesRange('15.0.0-canary.1', '<15.2.3'), true)
  assert.equal(versionSatisfiesRange('v14.2.20', '<14.2.25'), true)
  assert.equal(parseSemver('not-a-version'), null)
})

test('M1-static T8: curated advisories respect affectedRange for patched versions', async () => {
  const prevOffline = process.env.KOVO_OFFLINE
  process.env.KOVO_OFFLINE = '1'
  try {
    assert.deepEqual(await queryCves({ ecosystem: 'npm', package: 'next', version: '15.5.0' }), [])
    assert.deepEqual(await queryCves({ ecosystem: 'npm', package: 'express', version: '5.1.0' }), [])

    const nextPatchedLine = await queryCves({ ecosystem: 'npm', package: 'next', version: '14.2.20' })
    assert.ok(nextPatchedLine.some(a => a.id === 'CVE-2025-29927'))
    assert.ok(!nextPatchedLine.some(a => a.id === 'CVE-2024-46982'), '14.2.20 is patched for the cache-poisoning advisory')

    const nextVulnerable = await queryCves({ ecosystem: 'npm', package: 'next', version: '14.2.5' })
    assert.ok(nextVulnerable.some(a => a.id === 'CVE-2025-29927'))
    assert.ok(nextVulnerable.some(a => a.id === 'CVE-2024-46982'))

    assert.equal((await queryCves({ ecosystem: 'npm', package: 'vite', version: '6.2.2' })).length, 1)
    assert.equal((await queryCves({ ecosystem: 'npm', package: 'vite', version: '6.2.3' })).length, 0)

    const reactVulnerable = await queryCves({ ecosystem: 'npm', package: 'react', version: '19.1.0' })
    assert.ok(reactVulnerable.some(a => a.id === 'CVE-2025-55182'))
    assert.equal((await queryCves({ ecosystem: 'npm', package: 'react', version: '19.2.1' })).length, 0)

    // Versionless lookups remain fingerprint-only and keep the curated corpus.
    assert.ok((await queryCves({ ecosystem: 'npm', package: 'next' })).length >= 3)
    assert.equal(advisoryMatchesVersion({ affectedRange: '<1.0.0' }, undefined), true)
    assert.equal(advisoryMatchesVersion({ affectedRange: '<1.0.0' }, 'latest'), true)
  } finally {
    if (prevOffline === undefined) delete process.env.KOVO_OFFLINE
    else process.env.KOVO_OFFLINE = prevOffline
  }
})
