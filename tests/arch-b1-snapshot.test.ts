/**
 * Unit & integration tests for Architecture Wave 2 Proposal B1:
 * Single Phase A `StaticWorkspaceSnapshot` (`src/server/static-workspace-snapshot.ts`).
 *
 * Strictly synthetic fixtures (zero benchmark literals).
 */
import assert from 'node:assert/strict'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import {
  buildStaticWorkspaceSnapshot,
  getOrBuildStaticWorkspaceSnapshot,
  isSecretWorkspacePath,
  snapshotSourceFiles,
} from '../src/server/static-workspace-snapshot.ts'
import { extractProgramGraph } from '../src/server/program-graph.ts'
import { synthesizeInvariants } from '../src/server/invariant-synthesizer.ts'
import {
  extractRepoProgramGraph,
  extractStaticFrameworkRoutes,
  readRepoManifests,
} from '../src/server/phase0-recon.ts'
import { runThreeStageSemanticAudit } from '../src/server/semantic-audit.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => {
    try {
      rmSync(dir, { recursive: true, force: true })
    } catch {
      // already removed by test
    }
  })
  return dir
}

const SECRET_CANARIES = {
  dotenv: 'CANARY_DOTENV_SECRET_9911',
  dotenvLocal: 'CANARY_DOTENV_LOCAL_9912',
  dotenvProd: 'CANARY_DOTENV_PROD_9913',
  keyFile: 'CANARY_PRIVATE_KEY_9914',
  pemFile: 'CANARY_PEM_CERT_9915',
  patFile: 'CANARY_GITHUB_PAT_9916',
  saltFile: 'CANARY_HELDOUT_SALT_9917',
  credsJson: 'CANARY_CREDS_JSON_9918',
  credsDir: 'CANARY_CREDS_DIR_9919',
  sshKey: 'CANARY_SSH_KEY_9920',
  outsideSymlink: 'CANARY_OUTSIDE_SYMLINK_9921',
} as const

function createSyntheticWorkspace(t: { after: (fn: () => void) => void }): {
  root: string
  reposDir: string
  outsideDir: string
} {
  const root = makeTempDir(t, 'guardian-b1-snap-')
  const reposDir = join(root, 'repos')
  const outsideDir = join(root, 'outside')
  const repoRoot = join(reposDir, 'acme', 'shop')

  mkdirSync(join(repoRoot, 'services', 'api', 'src'), { recursive: true })
  mkdirSync(join(repoRoot, 'services', 'stream', 'src'), { recursive: true })
  mkdirSync(join(repoRoot, 'node_modules', 'dep'), { recursive: true })
  mkdirSync(join(repoRoot, '.git'), { recursive: true })
  mkdirSync(join(repoRoot, 'dist'), { recursive: true })
  mkdirSync(join(repoRoot, 'build'), { recursive: true })
  mkdirSync(join(repoRoot, 'vendor', 'lib'), { recursive: true })
  mkdirSync(join(repoRoot, 'credentials'), { recursive: true })
  mkdirSync(outsideDir, { recursive: true })

  // Primary Express API routes with guards, sinks, and lifecycle mutations
  writeFileSync(
    join(repoRoot, 'services', 'api', 'src', 'orders.ts'),
    [
      "import express from 'express'",
      'export const router = express.Router()',
      'export function requireAuth(req: any, _res: any, next: any) { return next() }',
      'export function requireTenantScope(req: any, _res: any, next: any) { return next() }',
      'export function checkRevokedToken(req: any, _res: any, next: any) { return next() }',
      '',
      'export async function getOrder(req: any, res: any) {',
      '  const row = await db.query("SELECT * FROM orders WHERE tenantId = $1 AND id = $2", [req.tenantId, req.params.id])',
      '  return res.json(row)',
      '}',
      '',
      'export async function batchOrders(req: any, res: any) {',
      '  const ids = req.body.ids',
      '  const rows = await db.query("SELECT * FROM orders WHERE id = ANY($1)", [ids])',
      '  return res.json(rows)',
      '}',
      '',
      'export async function approveOrder(req: any, res: any) {',
      '  order.approvedBy = req.user.id',
      '  order.status = "approved"',
      '  account.balance -= order.amount',
      '  return fetch("http://worker-service:9000/settle", { headers: { "x-forwarded-user": req.user.id }, body: JSON.stringify(order) })',
      '}',
      '',
      "router.get('/api/v1/orders/:id', requireAuth, requireTenantScope, checkRevokedToken, getOrder)",
      "router.post('/api/v1/orders/batch', requireAuth, batchOrders)",
      "router.post('/api/v1/orders/:id/approve', requireAuth, requireTenantScope, approveOrder)",
      '',
    ].join('\n'),
  )

  // Secondary SSE stream surface on the same entity omitting tenant/revocation guards
  writeFileSync(
    join(repoRoot, 'services', 'stream', 'src', 'orders-stream.ts'),
    [
      "import express from 'express'",
      'export const streamRouter = express.Router()',
      'export function streamOrders(req: any, res: any) {',
      '  res.setHeader("Content-Type", "text/event-stream")',
      '  return res.end(req.params.id)',
      '}',
      "streamRouter.get('/events/orders/:id', streamOrders)",
      '',
    ].join('\n'),
  )

  // Manifest, Dockerfile, docker-compose, GraphQL SDL, and benign .env.example
  writeFileSync(
    join(repoRoot, 'package.json'),
    JSON.stringify({ name: 'acme-shop', dependencies: { express: '^4.19.0' } }, null, 2),
  )
  writeFileSync(
    join(repoRoot, 'services', 'api', 'Dockerfile'),
    'FROM node:22-slim\nEXPOSE 8080\nCMD ["node", "server.js"]\n',
  )
  writeFileSync(
    join(repoRoot, 'docker-compose.yml'),
    [
      'services:',
      '  api:',
      '    ports: ["8080:8080"]',
      '    environment:',
      '      - WORKER_URL=http://worker-service:9000',
      '  worker-service:',
      '    ports: ["9000:9000"]',
      '',
    ].join('\n'),
  )
  writeFileSync(join(repoRoot, 'schema.graphql'), 'type Query { order(id: ID!): String }\n')
  writeFileSync(join(repoRoot, '.env.example'), 'PORT=8080\nAPI_BASE_URL=http://localhost:8080\n')

  // Excluded directories (must NEVER be scanned or included)
  writeFileSync(
    join(repoRoot, 'node_modules', 'dep', 'index.js'),
    "const app = require('express')(); app.get('/from-node-modules', () => {});\n",
  )
  writeFileSync(join(repoRoot, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n')
  writeFileSync(join(repoRoot, 'dist', 'bundle.js'), "app.get('/from-dist', () => {});\n")
  writeFileSync(join(repoRoot, 'build', 'out.js'), "app.get('/from-build', () => {});\n")
  writeFileSync(join(repoRoot, 'vendor', 'lib', 'vendored.py'), "@app.get('/from-vendor')\ndef v(): pass\n")

  // Binary files (both known binary extension AND NUL-byte payload in .ts-like or .txt file)
  writeFileSync(join(repoRoot, 'logo.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]))
  writeFileSync(join(repoRoot, 'services', 'api', 'src', 'binary-blob.js'), Buffer.from([0x2f, 0x2f, 0x00, 0xff, 0xfe]))

  // Secret files (MUST NEVER be read into sourceByPath)
  writeFileSync(join(repoRoot, '.env'), `API_KEY=${SECRET_CANARIES.dotenv}\n`)
  writeFileSync(join(repoRoot, '.env.local'), `LOCAL_SECRET=${SECRET_CANARIES.dotenvLocal}\n`)
  writeFileSync(join(repoRoot, '.env.production'), `PROD_SECRET=${SECRET_CANARIES.dotenvProd}\n`)
  writeFileSync(join(repoRoot, 'tls.key'), `-----BEGIN PRIVATE KEY-----\n${SECRET_CANARIES.keyFile}\n`)
  writeFileSync(join(repoRoot, 'ca.pem'), `-----BEGIN CERTIFICATE-----\n${SECRET_CANARIES.pemFile}\n`)
  writeFileSync(join(repoRoot, 'github.pat'), `${SECRET_CANARIES.patFile}\n`)
  writeFileSync(join(repoRoot, 'heldout.salt'), `${SECRET_CANARIES.saltFile}\n`)
  writeFileSync(join(repoRoot, 'credentials.json'), JSON.stringify({ token: SECRET_CANARIES.credsJson }))
  writeFileSync(join(repoRoot, 'credentials', 'model-key'), `${SECRET_CANARIES.credsDir}\n`)
  writeFileSync(join(repoRoot, 'id_rsa'), `${SECRET_CANARIES.sshKey}\n`)

  // Symlink escape attempts (must NEVER be followed)
  writeFileSync(join(outsideDir, 'outside.ts'), `// ${SECRET_CANARIES.outsideSymlink}\napp.get('/outside-escape', () => {})\n`)
  symlinkSync(join(outsideDir, 'outside.ts'), join(repoRoot, 'services', 'api', 'src', 'linked.ts'))
  symlinkSync(outsideDir, join(repoRoot, 'linked-outside-dir'))

  return { root, reposDir, outsideDir }
}

describe('StaticWorkspaceSnapshot: single walk, parity & zero re-walks', () => {
  test('building once and reusing across program-graph, phase0-recon, invariant-synthesizer, and semantic-audit yields identical outputs with ONLY ONE filesystem walk', async t => {
    const { reposDir } = createSyntheticWorkspace(t)
    const origins = ['https://shop.example.test']

    // 1. Capture baseline outputs WITHOUT staticSnapshot (direct filesystem walks)
    const baselineManifests = readRepoManifests(reposDir)
    const baselineRegexRoutes = extractStaticFrameworkRoutes(reposDir)
    const baselineGraphExtraction = extractRepoProgramGraph({ reposDir, origins })
    assert.ok(baselineGraphExtraction, 'baseline ProgramGraph extraction should succeed')
    assert.ok(baselineGraphExtraction.routes.length >= 4, 'expected AST routes from baseline')

    // 2. Build ONE StaticWorkspaceSnapshot
    const snapshot = buildStaticWorkspaceSnapshot(reposDir)
    assert.equal(snapshot.walkStats.walkCount, 1)
    assert.ok(snapshot.walkStats.filesScanned >= 6)
    assert.ok(snapshot.walkStats.bytesRead > 0)
    assert.ok(snapshot.createdAtMs > 0)
    assert.deepEqual(snapshot.mountedRepos, ['acme/shop'])

    // Verify getOrBuildStaticWorkspaceSnapshot reuses the exact snapshot instance (0 walks)
    assert.equal(getOrBuildStaticWorkspaceSnapshot(reposDir, snapshot), snapshot)

    const baselineSourceFiles = snapshotSourceFiles(snapshot)
    const baselineInvariants = synthesizeInvariants({
      mode: 'white-box',
      graph: baselineGraphExtraction.graph,
      sourceFiles: baselineSourceFiles,
      compose: snapshot.compose,
      totalRunBudgetUsd: 5.0,
    })
    assert.ok(baselineInvariants.hypotheses.length >= 2, 'expected synthesized invariants in baseline')

    // 3. DELETE the repo directory from disk to guarantee 0 downstream filesystem walks/reads!
    rmSync(reposDir, { recursive: true, force: true })

    // 3a. program-graph: reuses prebuilt graph identically (same object reference, 0 re-parse)
    const sortById = <T extends { id: string }>(arr: readonly T[]) =>
      [...arr].sort((a, b) => a.id.localeCompare(b.id))
    const reusedGraph = extractProgramGraph({ staticSnapshot: snapshot })
    assert.equal(reusedGraph, snapshot.programGraph)
    assert.deepEqual(sortById(reusedGraph.routes), sortById(baselineGraphExtraction.graph.routes))
    assert.deepEqual(reusedGraph.frameworks, baselineGraphExtraction.graph.frameworks)
    assert.equal(reusedGraph.nodes.length, baselineGraphExtraction.graph.nodes.length)
    assert.equal(reusedGraph.edges.length, baselineGraphExtraction.graph.edges.length)

    // 3b. phase0-recon helpers: identical manifests, regex routes, and AST graph extraction without disk
    const snapManifests = readRepoManifests(reposDir, 60, snapshot)
    assert.deepEqual(snapManifests, baselineManifests)

    const snapRegexRoutes = extractStaticFrameworkRoutes(reposDir, snapshot)
    const sortByKey = <T extends { method: string; pathTemplate: string }>(arr: readonly T[]) =>
      [...arr].sort((a, b) => `${a.method} ${a.pathTemplate}`.localeCompare(`${b.method} ${b.pathTemplate}`))
    assert.deepEqual(sortByKey(snapRegexRoutes.routes), sortByKey(baselineRegexRoutes.routes))
    assert.deepEqual([...snapRegexRoutes.frameworks].sort(), [...baselineRegexRoutes.frameworks].sort())

    const snapGraphExtraction = extractRepoProgramGraph({
      reposDir,
      origins,
      staticSnapshot: snapshot,
    })
    assert.ok(snapGraphExtraction, 'snapshot-backed extractRepoProgramGraph should succeed after disk removal')
    assert.equal(snapGraphExtraction.graph, snapshot.programGraph)
    assert.deepEqual(sortByKey(snapGraphExtraction.routes), sortByKey(baselineGraphExtraction.routes))
    assert.deepEqual(snapGraphExtraction.hypotheses, baselineGraphExtraction.hypotheses)
    assert.deepEqual(snapGraphExtraction.originMappings, baselineGraphExtraction.originMappings)

    // 3c. invariant-synthesizer: identical hypotheses and capabilitySeeds without disk
    const snapInvariants = synthesizeInvariants({
      mode: 'white-box',
      staticSnapshot: snapshot,
      totalRunBudgetUsd: 5.0,
    })
    assert.deepEqual(snapInvariants.hypotheses, baselineInvariants.hypotheses)
    assert.deepEqual(snapInvariants.capabilitySeeds, baselineInvariants.capabilitySeeds)

    // 3d. semantic-audit: reuses snapshot file list, source cache, and programGraph without disk or worker walks
    let openSessionCalls = 0
    let runScriptCalls = 0
    const strictBackend = {
      async openSession(): Promise<WorkerSession> {
        openSessionCalls += 1
        throw new Error('openSession should not be called when staticSnapshot serves Stage 1 & 2 with no dynamic rules / git miner')
      },
    } as unknown as WorkerBackend
    const strictSession = {
      id: 'mock-session',
      async runScript() {
        runScriptCalls += 1
        throw new Error('session.runScript should not be called to walk disk when staticSnapshot is supplied')
      },
      async close() {},
    } as unknown as WorkerSession

    const auditResult = await runThreeStageSemanticAudit(
      {
        run: {
          id: 'run-b1-test',
          projectId: 'proj-b1-test',
          goal: 'Verify snapshot reuse',
          goalRevision: 1,
          scopeRevision: 1,
          capabilityTier: 1,
          budgetUsd: 5,
          spentUsd: 0,
          budgetRequests: 100,
          spentRequests: 0,
        },
        approvedOrigins: origins,
        reposDir,
        mountedRepos: ['acme/shop'],
        backend: strictBackend,
        session: strictSession,
        staticSnapshot: snapshot,
        signal: new AbortController().signal,
      },
      {
        enableStage1Llm: false,
        enableStage3GitMiner: false,
        persistToStore: false,
      },
    )

    assert.equal(openSessionCalls, 0)
    assert.equal(runScriptCalls, 0, 'semantic-audit must not invoke worker repo-walk scripts when staticSnapshot is provided')
    assert.ok(auditResult.specsByRepo['acme/shop'], 'expected deterministic ProjectSecuritySpec from snapshot')
    assert.ok(auditResult.specsByRepo['acme/shop'].frameworks.includes('express'))
    assert.ok(auditResult.specsByRepo['acme/shop'].languages.includes('typescript'))
    assert.ok(auditResult.callGraphsByRepo['acme/shop']!.filesScanned >= 2)
    assert.ok(auditResult.callGraphsByRepo['acme/shop']!.nodes >= 3)
    assert.ok(auditResult.allSuspectsCount > 0, 'expected suspects built using snapshot call graph & programGraph')
  })
})

describe('StaticWorkspaceSnapshot: secret exclusion, directory filters, bounds & immutability', () => {
  test('never reads secret files (.env*, *.key, *.pem, *.pat, *.salt, credentials) while allowing .env.example', t => {
    const { reposDir } = createSyntheticWorkspace(t)
    const snapshot = buildStaticWorkspaceSnapshot(reposDir)

    const allPaths = [...snapshot.files, ...snapshot.sourceByPath.keys()]
    const forbiddenBasenames = [
      '.env',
      '.env.local',
      '.env.production',
      'tls.key',
      'ca.pem',
      'github.pat',
      'heldout.salt',
      'credentials.json',
      'model-key',
      'id_rsa',
      'linked.ts',
      'outside.ts',
      'logo.png',
      'binary-blob.js',
    ]
    for (const forbidden of forbiddenBasenames) {
      assert.equal(
        allPaths.some(p => p.endsWith(`/${forbidden}`) || p === forbidden),
        false,
        `forbidden/secret/binary file "${forbidden}" must never appear in snapshot`,
      )
    }

    // Excluded directories must never appear
    for (const dir of ['node_modules/', '.git/', 'dist/', 'build/', 'vendor/', 'credentials/', 'linked-outside-dir/']) {
      assert.equal(
        allPaths.some(p => p.includes(dir)),
        false,
        `excluded directory "${dir}" must never appear in snapshot`,
      )
    }

    // Secret canary values must NEVER appear anywhere in cached source contents
    for (const [label, canary] of Object.entries(SECRET_CANARIES)) {
      for (const [filePath, content] of snapshot.sourceByPath.entries()) {
        assert.equal(
          content.includes(canary),
          false,
          `secret canary "${label}" leaked into snapshot.sourceByPath[${filePath}]`,
        )
      }
    }

    // .env.example MUST be allowed
    assert.ok(
      snapshot.sourceByPath.has('acme/shop/.env.example'),
      '.env.example must be preserved in snapshot.sourceByPath',
    )

    // Direct predicate checks
    assert.equal(isSecretWorkspacePath('.env'), true)
    assert.equal(isSecretWorkspacePath('app/.env.production'), true)
    assert.equal(isSecretWorkspacePath('app/.env.example'), false)
    assert.equal(isSecretWorkspacePath('certs/server.key'), true)
    assert.equal(isSecretWorkspacePath('certs/root.pem'), true)
    assert.equal(isSecretWorkspacePath('tokens/gh.pat'), true)
    assert.equal(isSecretWorkspacePath('bench/heldout.salt'), true)
    assert.equal(isSecretWorkspacePath('config/credentials.json'), true)
    assert.equal(isSecretWorkspacePath('credentials/api-token'), true)
    assert.equal(isSecretWorkspacePath('src/routes/credentials.ts'), false)
  })

  test('enforces immutability, bounded size caps, and permission-safe error handling', t => {
    const { reposDir } = createSyntheticWorkspace(t)

    // Add a permission-restricted file (skipped cleanly when running non-root)
    const unreadable = join(reposDir, 'acme', 'shop', 'services', 'api', 'src', 'restricted.ts')
    writeFileSync(unreadable, 'export const hidden = 1\n')
    try {
      chmodSync(unreadable, 0o000)
    } catch {
      // ignore if filesystem disallows chmod
    }
    t.after(() => {
      try {
        chmodSync(unreadable, 0o600)
      } catch {
        // ignore
      }
    })

    const capped = buildStaticWorkspaceSnapshot(reposDir, {
      maxFileBytes: 4096,
      maxTotalBytes: 4096,
    })
    assert.equal(capped.walkStats.walkCount, 1)
    assert.ok(capped.walkStats.bytesRead <= 4096, `bytesRead (${capped.walkStats.bytesRead}) exceeded cap 4096`)

    // Immutability assertions
    assert.equal(Object.isFrozen(capped), true)
    assert.equal(Object.isFrozen(capped.files), true)
    assert.equal(Object.isFrozen(capped.walkStats), true)
    assert.throws(
      () => (capped.sourceByPath as unknown as Map<string, string>).set('x', 'y'),
      TypeError,
    )
    assert.throws(
      () => (capped.sourceByPath as unknown as Map<string, string>).delete('acme/shop/package.json'),
      TypeError,
    )
    assert.throws(
      () => (capped.sourceByPath as unknown as Map<string, string>).clear(),
      TypeError,
    )

    // Missing directory returns empty immutable snapshot cleanly
    const missing = buildStaticWorkspaceSnapshot(join(reposDir, 'does-not-exist'))
    assert.equal(missing.walkStats.walkCount, 1)
    assert.equal(missing.walkStats.filesScanned, 0)
    assert.equal(missing.files.length, 0)
    assert.equal(missing.sourceByPath.size, 0)
  })
})
