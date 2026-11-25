import assert from 'node:assert/strict'
import { execFile as execFileCb } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  extractProjectSecuritySpecAndRules,
  inferProjectSecuritySpecDeterministic,
  MAX_AUDIT_SUSPECTS_CEILING,
  mineGitSecurityHistory,
  rankAndBudgetAuditSuspects,
  runThreeStageSemanticAudit,
  runValidatedDynamicRulesInWorker,
  runVariantSweepForFinding,
  sanitizeGitDiffBase,
  scoreAndBuildSuspects,
  toChainStepInputs,
  validateAndSerializeDynamicRule,
  validateRawRuleYaml,
  validateSafeRegex,
  analyzeSinkBackwardPaths,
  type CallGraphIndex,
  type SemanticAuditContext,
} from '../src/server/semantic-audit.ts'
import { Store } from '../src/server/store.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import {
  compiledTemplateLimitCeiling,
  defaultCompiledTemplateLimit,
  loadSafeTemplates,
  parseSafeTemplateYaml,
  selectTemplatesForTech,
  TemplateValidationError,
} from '../src/templates/loader.ts'
import { MiniYamlError, parseMiniYaml } from '../src/templates/yaml.ts'
import { transpileNucleiDirectory, transpileNucleiTemplate } from '../scripts/transpile-nuclei-templates.ts'
import { buildCallGraphFromFiles, jsHarvest, runAnalyzer } from '../worker/analyzers.ts'

const execFile = promisify(execFileCb)
const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)))

const TEST_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
const TEST_STRIPE_KEY = 'sk_live_' + '51Abcdefghijklmnopqrstuvwxyz123456'

function makeTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  chmodSync(dir, 0o755)
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

async function dockerHasImage(image: string): Promise<boolean> {
  try {
    await execFile('docker', ['image', 'inspect', image], { timeout: 5_000 })
    return true
  } catch {
    return false
  }
}

function makeTestStore(t: test.TestContext) {
  const dir = makeTempDir(t, 'kovo-m3-store-')
  const storage = new Store(dir)
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'M3 Semantic Audit Project',
    environment: 'local-lab',
    seeds: ['https://api.app.invalid'],
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Audit API and source code',
    sourceMode: 'prepared',
    capabilityTier: 2,
    budgetUsd: 10,
    budgetRequests: 500,
    maxRpsPerOrigin: 10,
    workerConcurrency: 2,
    workerMaxTurns: 30,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const asset = storage.run(runId).candidates[0]
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  const run = storage.run(runId)
  const aid = randomUUID()
  storage.client.prepare(
    `INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at)
     VALUES (?, ?, 'threat_model', 'running', 1, 0, ?, '[]', ?, 'semantic-audit', 'audit', ?)`,
  ).run(aid, run.id, randomUUID(), JSON.stringify(['https://api.app.invalid']), Date.now())
  const assignment = storage.worker(aid)
  return { dir, storage, run, assignment }
}

// ============================================================================
// Suite 1: kovo-worker:v4 Hardened Offline Toolchain & worker-backend.ts
// ============================================================================

test('M3-T1: worker/Dockerfile & worker-backend.ts enforce kovo-worker:v4, TRIVY_CACHE_DIR, and 1536m/256 defaults', () => {
  const dockerfile = readFileSync(join(repoRoot, 'worker', 'Dockerfile'), 'utf8')
  const backendSrc = readFileSync(join(repoRoot, 'src', 'server', 'worker-backend.ts'), 'utf8')
  const workerPkg = JSON.parse(readFileSync(join(repoRoot, 'worker', 'package.json'), 'utf8')) as { dependencies: Record<string, string> }
  const rootPkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as { scripts: Record<string, string> }

  assert.match(dockerfile, /TRIVY_CACHE_DIR="\/opt\/trivy-cache"/)
  assert.match(dockerfile, /USER 10001:10001/)
  assert.match(backendSrc, /image = 'kovo-worker:v4'/)
  assert.match(backendSrc, /1536/)
  assert.match(backendSrc, /256/)
  assert.match(backendSrc, /4096/)
  assert.match(backendSrc, /384/)
  assert.ok(workerPkg.dependencies['@swc/core'], 'worker/package.json must include @swc/core')
  assert.ok(workerPkg.dependencies.acorn, 'worker/package.json must include acorn')
  assert.ok(rootPkg.scripts['worker:build']?.includes('kovo-worker:v4'))
  assert.ok(rootPkg.scripts['templates:transpile']?.includes('transpile-nuclei-templates.ts'))
})

test('M3-T2: worker/rules/opengrep contains >= 1,500 deduplicated rules across >= 50 YAML files and executes offline with 0 errors', async (t) => {
  const rulesRoot = join(repoRoot, 'worker', 'rules', 'opengrep')
  const manifestPath = join(rulesRoot, 'MANIFEST.json')
  assert.ok(existsSync(manifestPath), 'MANIFEST.json missing in worker/rules/opengrep')

  const yamlFiles: string[] = []
  const walk = (d: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name)
      if (entry.isDirectory()) walk(full)
      else if (/\.ya?ml$/i.test(entry.name)) yamlFiles.push(full)
    }
  }
  walk(rulesRoot)
  assert.ok(yamlFiles.length >= 50, `Expected >= 50 YAML rule files, got ${yamlFiles.length}`)

  const ruleIds = new Set<string>()
  for (const f of yamlFiles) {
    const raw = readFileSync(f, 'utf8')
    for (const m of raw.matchAll(/^(?:- |\s+- |\s{2,4})id:\s*["']?([^"'\s#]+)["']?/gm)) {
      assert.ok(!ruleIds.has(m[1]), `Duplicate Opengrep rule id "${m[1]}" found in ${f}`)
      ruleIds.add(m[1])
    }
  }
  assert.ok(ruleIds.size >= 1500, `Expected >= 1,500 curated Opengrep rules, got ${ruleIds.size}`)

  if (!(await dockerHasImage('kovo-worker:v4'))) {
    t.skip('kovo-worker:v4 image not built')
    return
  }

  const reposDir = makeTempDir(t, 'kovo-m3-og-')
  const appDir = join(reposDir, 'app')
  mkdirSync(join(appDir, 'src'), { recursive: true })
  writeFileSync(join(appDir, 'src', 'vuln.ts'), `export function q(db: any, req: any) { return db.query("SELECT * FROM users WHERE id=" + req.query.id); }\n`)
  writeFileSync(join(appDir, 'src', 'cmd.py'), `import subprocess\ndef run(x):\n    return subprocess.run(x, shell=True)\n`)

  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => session.close())

  const sast = await session.sast({ repo: 'app', engines: ['opengrep'] }, AbortSignal.timeout(90_000))
  assert.equal(sast.engineStatus.opengrep?.ok, true, sast.engineStatus.opengrep?.note ?? '')
  assert.ok(sast.findings.length >= 2, `Expected >= 2 Opengrep findings on TS+Python fixture, got ${sast.findings.length}`)
})

test('M3-T3: trivy-fs runs offline CVE + misconfig scan against /opt/trivy-cache under --network none --read-only', async (t) => {
  if (!(await dockerHasImage('kovo-worker:v4'))) {
    t.skip('kovo-worker:v4 image not built')
    return
  }
  const reposDir = makeTempDir(t, 'kovo-m3-trivy-')
  const appDir = join(reposDir, 'app')
  mkdirSync(appDir, { recursive: true })
  writeFileSync(join(appDir, 'package.json'), JSON.stringify({ name: 'trivy-test', version: '1.0.0', dependencies: { lodash: '4.17.15' } }))
  writeFileSync(join(appDir, 'package-lock.json'), JSON.stringify({
    name: 'trivy-test',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': { name: 'trivy-test', version: '1.0.0', dependencies: { lodash: '4.17.15' } },
      'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
    },
  }))
  writeFileSync(join(appDir, 'Dockerfile'), 'FROM ubuntu:latest\nUSER root\n')

  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => session.close())

  const res = await session.sast({ repo: 'app', engines: ['trivy-fs'] }, AbortSignal.timeout(60_000))
  assert.equal(res.engineStatus['trivy-fs']?.ok, true, res.engineStatus['trivy-fs']?.note ?? '')
  assert.ok(res.findings.some(f => /CVE-2021-23337|CVE-2020-8203|lodash/i.test(f.ruleId + f.message)), 'Expected Trivy offline DB to detect lodash 4.17.15 CVE')
  assert.ok(res.findings.some(f => f.file.includes('Dockerfile') || /DS-?0002|DS-?0026/i.test(f.ruleId)), 'Expected Trivy offline misconfig check on Dockerfile')
})

test('M3-T4: kovo-worker:v4 masks secrets, blocks traversal, and denies network/RO-mount writes', async (t) => {
  if (!(await dockerHasImage('kovo-worker:v4'))) {
    t.skip('kovo-worker:v4 image not built')
    return
  }
  const reposDir = makeTempDir(t, 'kovo-m3-sec-')
  const appDir = join(reposDir, 'app')
  mkdirSync(appDir, { recursive: true })
  writeFileSync(join(appDir, 'secrets.ts'), `export const A = "${TEST_AWS_KEY}";\nexport const S = "${TEST_STRIPE_KEY}";\n`)

  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => session.close())

  const sast = await session.sast({ repo: 'app', engines: ['gitleaks'] }, AbortSignal.timeout(30_000))
  const serialized = JSON.stringify(sast)
  assert.ok(!serialized.includes(TEST_AWS_KEY), 'Raw AWS key leaked from SAST')
  assert.ok(!serialized.includes(TEST_STRIPE_KEY), 'Raw Stripe key leaked from SAST')

  await assert.rejects(() => session.sast({ repo: '../etc', engines: ['gitleaks'] }, AbortSignal.timeout(15_000)))

  const scriptRes = await session.runScript({
    runtime: 'node',
    code: `
import fs from 'node:fs';
import net from 'node:net';
let roErr = false;
try { fs.writeFileSync('/repos/app/pwn.txt', 'x'); } catch { roErr = true; }
const sock = net.connect({ host: '1.1.1.1', port: 80, timeout: 500 });
sock.on('error', () => { process.stdout.write(JSON.stringify({ uid: process.getuid(), roErr, netBlocked: true })); });
sock.on('connect', () => { process.stdout.write(JSON.stringify({ uid: process.getuid(), roErr, netBlocked: false })); sock.destroy(); });
`,
    timeoutMs: 10_000,
  }, AbortSignal.timeout(15_000))
  const probe = JSON.parse(scriptRes.stdout) as { uid: number; roErr: boolean; netBlocked: boolean }
  assert.equal(probe.uid, 10001)
  assert.equal(probe.roErr, true)
  assert.equal(probe.netBlocked, true)
})

// ============================================================================
// Suite 2: AST-Based JS/TS & Source-Map Harvester + Call-Graph Indexer
// ============================================================================

test('M3-T5: jsHarvest AST extracts router tables, concats, fetch/axios/tRPC, Next-Action, gql, featureFlags, and postMessage origin audit', () => {
  const hash = 'b'.repeat(40)
  const bundle = `
    const routes = [
      { path: "/admin/users", component: AdminUsers },
      { path: '/api/' + 'internal/flags' }
    ];
    router.push("/billing/invoices");
    await fetch("/api/orders/export", { method: "POST", body: JSON.stringify({ orgId: 1, format: "csv" }) });
    await axios.patch("/api/profile", { role: "admin" });
    await trpc.billing.updatePlan.mutate({ planId: "pro" });
    const headers = { "Next-Action": "${hash}" };
    const doc = gql\`mutation RotateKey($id: ID!) { rotateKey(id: $id) { secret } }\`;
    const enabled = useFeatureFlag("beta_billing_v2");
    const FEATURE_ADMIN_IMPERSONATE = true;
    window.addEventListener("message", (ev) => { el.innerHTML = ev.data.html; });
    window.addEventListener("message", (ev) => { if (ev.origin !== "https://app.invalid") return; safe(ev.data); });
  `
  const out = jsHarvest(bundle, 'https://app.invalid/bundle.js')
  const apiPaths = out.apiPaths as string[]
  const adminPaths = out.adminPaths as string[]
  const httpCalls = out.httpCalls as Array<{ client: string; url: string; method: string; bodyKeys: string[] }>
  const graphqlDocs = out.graphqlDocs as Array<{ kind: string; name: string }>
  const nextActions = out.nextActions as Array<{ id: string }>
  const featureFlags = out.featureFlags as string[]
  const domSinks = out.domSinks as string[]
  const domSinkDetails = out.domSinkDetails as Array<{ kind: string; missingOriginCheck?: boolean }>

  assert.ok(apiPaths.includes('/admin/users'))
  assert.ok(apiPaths.includes('/api/internal/flags'))
  assert.ok(apiPaths.includes('/billing/invoices'))
  assert.ok(adminPaths.includes('/admin/users'))
  assert.ok(adminPaths.includes('/api/internal/flags'))
  assert.ok(httpCalls.some(c => c.client === 'fetch' && c.url === '/api/orders/export' && c.method === 'POST' && c.bodyKeys.includes('orgId')))
  assert.ok(httpCalls.some(c => c.client === 'axios' && c.url === '/api/profile' && c.method === 'PATCH' && c.bodyKeys.includes('role')))
  assert.ok(httpCalls.some(c => c.client === 'trpc' && c.url === '/trpc/billing.updatePlan' && c.method === 'POST' && c.bodyKeys.includes('planId')))
  assert.ok(nextActions.some(a => a.id === hash))
  assert.ok(graphqlDocs.some(d => d.kind === 'mutation' && d.name === 'RotateKey'))
  assert.ok(featureFlags.includes('beta_billing_v2'))
  assert.ok(featureFlags.includes('FEATURE_ADMIN_IMPERSONATE'))
  assert.ok(domSinks.includes('innerHTML'))
  assert.ok(domSinks.includes('message-listener-missing-origin'))
  assert.ok(domSinkDetails.some(d => d.kind === 'message-listener' && d.missingOriginCheck === true))
  assert.ok(domSinkDetails.some(d => d.kind === 'message-listener' && d.missingOriginCheck === false))
})

test('M3-T6: jsHarvest recovers .map source maps with size caps, masks secrets, and survives malformed JS', () => {
  const mapJson = JSON.stringify({
    version: 3,
    sources: ['src/admin/secret-panel.ts'],
    sourcesContent: [`export const k = "${TEST_STRIPE_KEY}"; export async function go() { return fetch("/api/internal/super-admin"); }`],
    mappings: '',
  })
  const out = runAnalyzer('js-harvest', {
    text: 'console.log(1)\n//# sourceMappingURL=app.js.map',
    sourceMapContent: mapJson,
  }, () => mapJson)
  const serialized = JSON.stringify(out)
  assert.ok(serialized.includes('/api/internal/super-admin'))
  assert.ok(!serialized.includes(TEST_STRIPE_KEY), 'Source map secret leaked unmasked')

  const oversized = jsHarvest('const a = 1;', 'big.js', {
    sourceMapContent: mapJson,
    maxMapBytes: 10,
  })
  const mapAnalysis = oversized.sourceMapAnalysis as { parsed: boolean; truncated: boolean }
  assert.equal(mapAnalysis.parsed, false)
  assert.equal(mapAnalysis.truncated, true)

  const malformed = jsHarvest('function broken( { {{{ "/api/still-ok" const x = "', 'broken.js')
  assert.equal(malformed.parserUsed, 'regex')
  assert.ok((malformed.apiPaths as string[]).includes('/api/still-ok'))
})

test('M3-T7: live --network none --read-only session.analyze("js-harvest") executes @swc/core under UID 10001:10001', async (t) => {
  if (!(await dockerHasImage('kovo-worker:v4'))) {
    t.skip('kovo-worker:v4 image not built')
    return
  }
  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000))
  t.after(() => session.close())

  const out = await session.analyze('js-harvest', {
    text: `export const routes = [{ path: '/api/' + 'v4/internal-audit' }];`,
    sourceName: 'https://app.invalid/ro.ts',
  }, AbortSignal.timeout(15_000))
  assert.equal(out.parserUsed, 'swc')
  assert.ok((out.apiPaths as string[]).includes('/api/v4/internal-audit'))
})

test('M3-T8: buildCallGraphFromFiles & live session.callGraph trace multi-file route -> helper -> sink and guard dominance', async (t) => {
  const files = [
    { file: 'src/db.ts', content: `export function queryOrder(db: any, id: string) { return db.query("SELECT * FROM orders WHERE id=" + id); }\n` },
    { file: 'src/routes/public-orders.ts', content: `import { queryOrder } from '../db.ts'\napp.get('/api/orders', (req, res) => res.json(queryOrder(db, req.query.id)));\n` },
    { file: 'src/routes/admin-orders.ts', content: `import { queryOrder } from '../db.ts'\napp.get('/api/admin/orders', (req, res) => { requireOrgMembership(req); return res.json(queryOrder(db, req.query.id)); });\n` },
  ]
  const cg = buildCallGraphFromFiles(files, { customGuardPatterns: ['requireOrgMembership'] })
  const unguarded = cg.taintPaths.find(p => p.routeOrAction === '/api/orders')
  const guarded = cg.taintPaths.find(p => p.routeOrAction === '/api/admin/orders')
  assert.ok(unguarded, 'Expected backward taint path for unguarded /api/orders')
  assert.equal(unguarded.isUnguardedPath, true)
  assert.equal(unguarded.dominatingGuards.length, 0)
  assert.ok(guarded, 'Expected backward taint path for guarded /api/admin/orders')
  // v5: an auth guard is not an input sanitizer — the SQL sink stays injection-unsanitized.
  assert.equal(guarded.isAuthUnguarded, false)
  assert.equal(guarded.isInjectionUnsanitized, true)
  assert.equal(guarded.isUnguardedPath, true)
  assert.ok(guarded.dominatingGuards.includes('requireOrgMembership'))

  if (!(await dockerHasImage('kovo-worker:v4'))) return
  const reposDir = makeTempDir(t, 'kovo-m3-cg-')
  const appDir = join(reposDir, 'app')
  mkdirSync(join(appDir, 'src', 'routes'), { recursive: true })
  for (const f of files) writeFileSync(join(appDir, f.file), f.content)

  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => session.close())
  const remoteCg = await session.callGraph!({ repo: 'app', customGuardPatterns: ['requireOrgMembership'] }, AbortSignal.timeout(30_000))
  assert.ok(remoteCg.filesScanned >= 3)
  assert.ok(remoteCg.taintPaths.some(p => p.routeOrAction === '/api/orders' && p.isUnguardedPath))
})

// ============================================================================
// Suite 3: 3-Stage Offline Semantic Audit Pipeline (src/server/semantic-audit.ts)
// ============================================================================

test('M3-T9: Stage-1 rule sanitization rejects ReDoS/anchors/fix:/wildcards and executes valid dynamic rules offline', async (t) => {
  assert.equal(validateSafeRegex('(a+)+$').ok, false)
  assert.equal(validateSafeRegex('^[a-z0-9_-]{1,32}$').ok, true)

  assert.equal(validateAndSerializeDynamicRule({
    id: 'bad.fix', engine: 'opengrep', languages: ['typescript'], message: 'bad fix', patterns: ['foo($X)\nfix: bar($X)'],
  }).ok, false)
  assert.equal(validateAndSerializeDynamicRule({
    id: 'bad.wildcard', engine: 'opengrep', languages: ['typescript'], message: 'bad wildcard', patterns: ['$X'],
  }).ok, false)
  assert.equal(validateAndSerializeDynamicRule({
    id: 'bad.redos', engine: 'opengrep', languages: ['typescript'], message: 'bad redos',
    patterns: ['foo($X)'], metavariableRegex: { $X: '(a+)+$' },
  }).ok, false)

  assert.equal(validateRawRuleYaml('rules:\n  - id: x\n    pattern: &anchor foo\n', 'opengrep').ok, false)
  assert.throws(() => sanitizeGitDiffBase('-exec=sh'))
  assert.throws(() => sanitizeGitDiffBase('main..evil'))
  assert.equal(sanitizeGitDiffBase('origin/main'), 'origin/main')

  // Deterministic ProjectSecuritySpec inference detects custom guard & custom ORM sink
  const det = inferProjectSecuritySpecDeterministic('app', {
    repo: 'app',
    filesScanned: 2,
    languages: ['typescript'],
    frameworks: ['express'],
    ormLibraries: ['prisma'],
    authLibraries: ['jwt'],
    snippets: [
      { file: 'src/auth.ts', excerpt: 'export function requireOrgMembership(req: any) { return req.user.orgId; }' },
      { file: 'src/db.ts', excerpt: 'export function q(customDb: any, id: string) { return customDb.unsafeExec("SELECT * FROM t WHERE id=" + id); }' },
    ],
  })
  assert.ok(det.spec.authTenantGuards.some(g => g.name === 'requireOrgMembership'))
  assert.ok(det.candidateRules.some(r => r.id.includes('unsafeexec')))

  if (!(await dockerHasImage('kovo-worker:v4'))) return
  const { storage, run, assignment } = makeTestStore(t)
  const reposDir = makeTempDir(t, 'kovo-m3-s1-')
  const appDir = join(reposDir, 'app')
  mkdirSync(join(appDir, 'src'), { recursive: true })
  writeFileSync(join(appDir, 'src', 'auth.ts'), 'export function requireOrgMembership(req: any) { return req.user.orgId; }\n')
  writeFileSync(join(appDir, 'src', 'db.ts'), 'export function q(customDb: any, x: string) { return customDb.unsafeExec("SELECT * FROM users WHERE q=" + x); }\n')

  const backend = new LinuxWorkerBackend()
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => session.close())

  const ctx: SemanticAuditContext = {
    run,
    approvedOrigins: ['https://api.app.invalid'],
    reposDir,
    mountedRepos: ['app'],
    backend,
    session,
    storage,
    assignment,
    signal: AbortSignal.timeout(45_000),
  }
  const stage1 = await extractProjectSecuritySpecAndRules(ctx, 'app', session, { enableLlm: false })
  assert.ok(stage1.rules.length >= 1, 'Expected deterministic dynamic rule for customDb.unsafeExec')
  const dynFindings = await runValidatedDynamicRulesInWorker(session, 'app', stage1.rules, ctx.signal)
  assert.ok(dynFindings.some(f => f.file.includes('db.ts')), 'Dynamic rule must match customDb.unsafeExec inside --network none worker')
})

test('M3-T10: Stage-2 path dominance detects partialGuards and rankAndBudgetAuditSuspects lifts 12-cap up to ceiling 80', (t) => {
  const graph: CallGraphIndex = {
    repo: 'app',
    filesScanned: 3,
    analyzerSource: 'worker_analyzer',
    nodes: [
      { id: 'ep1', file: 'a.ts', line: 1, symbol: 'GET /api/unguarded', kind: 'entrypoint', httpMethod: 'GET', routePath: '/api/unguarded', guards: [], sanitizers: [], calls: ['sharedSink'] },
      { id: 'ep2', file: 'b.ts', line: 1, symbol: 'GET /api/guarded', kind: 'entrypoint', httpMethod: 'GET', routePath: '/api/guarded', guards: ['requireAuth'], sanitizers: [], calls: ['sharedSink'] },
      { id: 'sink', file: 'db.ts', line: 10, symbol: 'sharedSink', kind: 'sink', sinkKind: 'db_query', guards: [], sanitizers: [], calls: [] },
    ],
    edges: [
      { fromId: 'ep1', toId: 'sink', file: 'a.ts', line: 1 },
      { fromId: 'ep2', toId: 'sink', file: 'b.ts', line: 1 },
    ],
  }
  const spec = inferProjectSecuritySpecDeterministic('app', {
    repo: 'app', filesScanned: 3, languages: ['typescript'], frameworks: [], ormLibraries: [], authLibraries: [], snippets: [],
  }).spec
  const paths = analyzeSinkBackwardPaths(graph, spec)
  assert.equal(paths.length, 2)
  assert.equal(paths.find(p => p.routeOrAction === '/api/unguarded')?.isUnguardedPath, true)
  // v5: requireAuth satisfies authorization but does not sanitize the db_query sink.
  const guardedPath = paths.find(p => p.routeOrAction === '/api/guarded')
  assert.equal(guardedPath?.isAuthUnguarded, false)
  assert.equal(guardedPath?.isInjectionUnsanitized, true)
  assert.equal(guardedPath?.isUnguardedPath, true)

  // Verify 12-cap is lifted (25 -> 25, 100 -> 80)
  const many = Array.from({ length: 100 }, (_, i) => ({
    id: `s-${i}`,
    fingerprint: `fp-${i}`,
    stage: 'stage2_backward_taint' as const,
    origin: 'https://api.app.invalid',
    repo: 'app',
    file: `src/r${i}.ts`,
    line: 10 + i,
    routeOrAction: `/api/r/${i}`,
    authCheck: 'missing',
    ownershipCheck: 'missing',
    sinkKind: 'db_query' as const,
    severity: 'high' as const,
    priorityScore: 50 + (i % 40),
    recommendedTier: 2 as const,
    specialistProfile: 'bola-bfla-specialist' as const,
    hypothesis: `Suspect ${i}`,
    data: {
      subkind: 'code_audit_suspect' as const,
      repo: 'app',
      file: `src/r${i}.ts`,
      line: 10 + i,
      routeOrAction: `/api/r/${i}`,
      authCheck: 'missing',
      ownershipCheck: 'missing',
      sinkKind: 'db_query' as const,
      hypothesis: `Suspect ${i}`,
      recommendedTier: 2 as const,
    },
  }))

  assert.equal(rankAndBudgetAuditSuspects(many.slice(0, 25), { budgetCap: 25 }).length, 25)
  assert.equal(rankAndBudgetAuditSuspects(many, { budgetCap: 100 }).length, MAX_AUDIT_SUSPECTS_CEILING)

  const { run } = makeTestStore(t)
  const steps = toChainStepInputs(run, rankAndBudgetAuditSuspects(many.slice(0, 25), { budgetCap: 25 }))
  assert.equal(steps.length, 25)
  assert.ok(steps.every(s => s.specialistProfile === 'bola-bfla-specialist'))
})

test('M3-T11: Stage-3 git-history miner & post-confirmation Variant Sweep preserve Zero-LLM invariant', async (t) => {
  const { storage, run, assignment } = makeTestStore(t)
  const reposDir = makeTempDir(t, 'kovo-m3-s3-')
  const appDir = join(reposDir, 'app')
  mkdirSync(join(appDir, 'src'), { recursive: true })
  writeFileSync(join(appDir, 'README.md'), '# hello\n')
  writeFileSync(join(appDir, 'src', 'orders.ts'), `export function getOrder(db: any, id: string) {\n  return db.query("SELECT * FROM orders WHERE id = '" + id + "'");\n}\n`)
  writeFileSync(join(appDir, 'src', 'billing.ts'), `export function getBilling(db: any, id: string) {\n  return db.query("SELECT * FROM billing WHERE id = '" + id + "'");\n}\n`)

  if (!(await dockerHasImage('kovo-worker:v4'))) {
    t.skip('kovo-worker:v4 image not built')
    return
  }

  const backend = new LinuxWorkerBackend()
  const ctx: SemanticAuditContext = {
    run,
    approvedOrigins: ['https://api.app.invalid'],
    reposDir,
    mountedRepos: ['app'],
    backend,
    storage,
    assignment,
    signal: AbortSignal.timeout(60_000),
  }

  // 1. Missing .git handled gracefully
  const sessionNoGit = await backend.openSession(randomUUID(), AbortSignal.timeout(30_000), { reposDir })
  t.after(() => sessionNoGit.close())
  const spec = inferProjectSecuritySpecDeterministic('app', {
    repo: 'app', filesScanned: 2, languages: ['typescript'], frameworks: [], ormLibraries: [], authLibraries: [], snippets: [],
  }).spec
  const noGit = await mineGitSecurityHistory(ctx, 'app', sessionNoGit, spec)
  assert.equal(noGit.available, false)

  // 2. With .git history: filters security commits and ignores docs commits
  await execFile('git', ['init'], { cwd: appDir })
  await execFile('git', ['config', 'user.email', 'test@kovo.local'], { cwd: appDir })
  await execFile('git', ['config', 'user.name', 'Tester'], { cwd: appDir })
  await execFile('git', ['add', 'README.md'], { cwd: appDir })
  await execFile('git', ['commit', '-m', 'docs: update README'], { cwd: appDir })
  await execFile('git', ['add', 'src'], { cwd: appDir })
  await execFile('git', ['commit', '-m', 'fix: prevent IDOR / SQLi bypass in orders'], { cwd: appDir })

  const gitRes = await mineGitSecurityHistory(ctx, 'app', sessionNoGit, spec)
  assert.equal(gitRes.available, true)
  assert.equal(gitRes.commitsScanned, 2)
  assert.equal(gitRes.securityCommits.length, 1)
  assert.match(gitRes.securityCommits[0].subject, /IDOR|SQLi/i)

  // 3. Variant sweep rejects unconfirmed finding
  await assert.rejects(() => runVariantSweepForFinding(ctx, {
    finding: {
      id: randomUUID(),
      origin: 'https://api.app.invalid',
      title: 'Pending',
      cwe: 'CWE-89',
      category: 'injection-input',
      severity: 'high',
      status: 'pending',
      codeLocations: [{ repo: 'app', file: 'src/orders.ts', startLine: 1, endLine: 3 }],
    },
  }))

  // 4. Variant sweep on confirmed finding finds sibling src/billing.ts and excludes src/orders.ts
  const sweep = await runVariantSweepForFinding({ ...ctx, session: sessionNoGit }, {
    finding: {
      id: randomUUID(),
      origin: 'https://api.app.invalid',
      title: 'SQL Injection in getOrder',
      cwe: 'CWE-89',
      category: 'injection-input',
      severity: 'high',
      status: 'confirmed',
      codeLocations: [{ repo: 'app', file: 'src/orders.ts', startLine: 1, endLine: 3 }],
    },
  })
  assert.ok(sweep.newSuspects.some(s => s.file.includes('billing.ts')), 'Variant sweep must discover sibling src/billing.ts')
  assert.ok(!sweep.newSuspects.some(s => s.file.includes('orders.ts')), 'Variant sweep must exclude original location')
  // Zero-LLM invariant: semantic-audit never writes confirmed findings
  const row = storage.client.prepare('SELECT count(*) AS c FROM findings WHERE run_id = ?').get(run.id) as { c: number }
  assert.equal(row.c, 0)
})

// ============================================================================
// Suite 4: MiniYaml, loader.ts & Safe Nuclei Transpiler (Feature #21)
// ============================================================================

test('M3-T12: MiniYaml strictness BVA accepts valid escapes/maps and rejects dangerous YAML constructs', () => {
  const ok = parseMiniYaml('id: test-id\nname: "Hello \\u003cworld\\u003e"\nsingle: \'it\'\'s fine\'\nflow: { a: 1, b: [true, "x"] }\n') as Record<string, unknown>
  assert.equal(ok.name, 'Hello <world>')
  assert.equal(ok.single, "it's fine")

  const invalidCases = [
    '\tid: tabbed',
    'a: 1\na: 2',
    '__proto__: { polluted: true }',
    'a: &anc value',
    'a: *alias',
    'a: !!js/function "1"',
    'a: |\n  block scalar',
    'a: >\n  folded scalar',
    '<<: { a: 1 }',
    'a: 1\n---\nb: 2',
    'a: 1\n...',
    '&anc foo: bar',
  ]
  for (const bad of invalidCases) {
    assert.throws(() => parseMiniYaml(bad), MiniYamlError, `MiniYaml must reject: ${bad}`)
  }
})

test('M3-T13: loader.ts safety gate blocks destructive, webshell, private IP, OAST, ReDoS, forbidden headers & unreviewed mutating methods', () => {
  const validTier3 = [
    'id: valid-tier3-post',
    'name: Valid Tier 3 POST',
    'severity: medium',
    'description: Safe Tier 3 POST check',
    'tech: [generic]',
    'requiresTier3: true',
    'request:',
    '  method: POST',
    '  path: /api/check?r={{rand}}',
    '  body: "{}"',
    'control:',
    '  method: GET',
    '  path: /.kovo-none-{{rand}}',
    'matchers:',
    '  - type: word',
    '    part: body',
    '    words: [ok]',
  ].join('\n')
  assert.equal(parseSafeTemplateYaml(validTier3).requiresTier3, true)

  const unsafeCases = [
    'id: bad-1\nname: Bad\nseverity: high\ndescription: encoded rm\ntech: [generic]\nrequest:\n  method: GET\n  path: /run?c=rm+-rf+/\ncontrol:\n  path: /c\nmatchers:\n  - type: word\n    words: [ok]',
    'id: bad-2\nname: Bad\nseverity: high\ndescription: meta ip\ntech: [generic]\nrequest:\n  method: GET\n  path: /p?u=169.254.169.254/latest\ncontrol:\n  path: /c\nmatchers:\n  - type: word\n    words: [ami]',
    'id: bad-3\nname: Bad\nseverity: high\ndescription: webshell\ntech: [generic]\nrequest:\n  method: GET\n  path: /p?c=<?php+system(1);?>\ncontrol:\n  path: /c\nmatchers:\n  - type: word\n    words: [ok]',
    'id: bad-4\nname: Bad\nseverity: high\ndescription: oast\ntech: [generic]\nrequest:\n  method: GET\n  path: /p?u=x.oast.fun\ncontrol:\n  path: /c\nmatchers:\n  - type: word\n    words: [ok]',
    'id: bad-5\nname: Bad\nseverity: high\ndescription: redos\ntech: [generic]\nrequest:\n  method: GET\n  path: /p\ncontrol:\n  path: /c\nmatchers:\n  - type: regex\n    regex: ["(a+)+$"]',
    'id: bad-6\nname: Bad\nseverity: high\ndescription: auth header\ntech: [generic]\nrequest:\n  method: GET\n  path: /p\n  headers:\n    Authorization: Bearer x\ncontrol:\n  path: /c\nmatchers:\n  - type: word\n    words: [ok]',
    'id: bad-7\nname: Bad\nseverity: high\ndescription: no control\ntech: [generic]\nrequest:\n  method: GET\n  path: /p\nmatchers:\n  - type: word\n    words: [ok]',
  ]
  for (const bad of unsafeCases) {
    assert.throws(() => parseSafeTemplateYaml(bad), TemplateValidationError)
  }
})

test('M3-T14: transpileNucleiTemplate & transpileNucleiDirectory enforce safety filters and rewrite interactsh placeholders', async (t) => {
  const inDir = makeTempDir(t, 'kovo-m3-nuc-in-')
  const outDir = makeTempDir(t, 'kovo-m3-nuc-out-')

  writeFileSync(join(inDir, 'dns-bad.yaml'), 'id: bad-dns\ninfo:\n  name: DNS\n  severity: high\ndns:\n  - name: "{{FQDN}}"\n')
  writeFileSync(join(inDir, 'dsl-bad.yaml'), 'id: bad-dsl\ninfo:\n  name: DSL Only\n  severity: medium\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}/a"]\n    matchers:\n      - type: dsl\n        dsl: ["status_code == 200"]\n')
  writeFileSync(join(inDir, 'unknown-ph.yaml'), 'id: bad-ph\ninfo:\n  name: Unknown Placeholder\n  severity: medium\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}/a?x={{custom_var}}"]\n    matchers:\n      - type: word\n        words: [ok]\n')
  writeFileSync(join(inDir, 'raw-good.yaml'), [
    'id: cve-2025-12345-raw',
    'info:',
    '  name: Raw HTTP SSRF Canary Check',
    '  severity: high',
    '  tags: nextjs,ssrf,cve',
    'http:',
    '  - raw:',
    '      - |',
    '        GET /api/proxy?u=https://{{interactsh-url}}/cb HTTP/1.1',
    '        Host: {{Hostname}}',
    '        X-Probe: {{randstr}}',
    '    matchers:',
    '      - type: word',
    '        part: interactsh_protocol',
    '        words:',
    '          - http',
  ].join('\n'))

  const report = await transpileNucleiDirectory(inDir, outDir)
  assert.equal(report.scanned, 4)
  assert.equal(report.transpiled, 1)
  assert.equal(report.rejected.length, 3)

  const emitted = readFileSync(join(outDir, 'cve-2025-12345-raw.yaml'), 'utf8')
  assert.ok(emitted.includes('{{kovo_canary_http}}'))
  assert.ok(emitted.includes('{{rand}}'))
  assert.ok(!emitted.includes('interactsh'))
  const parsed = parseSafeTemplateYaml(emitted)
  assert.equal(parsed.request.headers['X-Probe'], '{{rand}}')
  assert.ok(parsed.control?.path?.includes('kovo-none-{{rand}}'))

  // Direct transpileNucleiTemplate check
  assert.equal(transpileNucleiTemplate('id: x\ninfo:\n  name: Bad\n  severity: high\nhttp:\n  - method: POST\n    path: ["/a"]\n    matchers:\n      - type: word\n        words: [ok]\n').ok, false)
})

test('M3-T15: 100% of src/templates/compiled/ passes Zod validation (>= 1,000) and selectTemplatesForTech ranks stack tags ahead of generic', () => {
  const compiledDir = join(repoRoot, 'src', 'templates', 'compiled')
  const compiled = loadSafeTemplates({ dir: compiledDir, refresh: true })
  assert.equal(compiled.errors.length, 0, `Compiled errors: ${JSON.stringify(compiled.errors.slice(0, 3))}`)
  assert.ok(compiled.templates.length >= 1000, `Expected >= 1,000 compiled templates, got ${compiled.templates.length}`)

  const combined = loadSafeTemplates({ refresh: true })
  assert.equal(combined.errors.length, 0, `Combined template errors: ${JSON.stringify(combined.errors.slice(0, 3))}`)
  assert.ok(combined.templates.length >= compiled.templates.length + 30)

  assert.equal(defaultCompiledTemplateLimit, 150)
  assert.equal(compiledTemplateLimitCeiling, 400)

  const nextSel = selectTemplatesForTech(compiled.templates, { techTags: ['nextjs'], tier: 1 })
  assert.ok(nextSel.selected.length > 0 && nextSel.selected.length <= 150)
  assert.ok(nextSel.selected[0].tech.includes('nextjs'), `Expected explicit tech 'nextjs' ranked first, got ${nextSel.selected[0].tech.join(',')}`)

  const ceilingSel = selectTemplatesForTech(compiled.templates, { techTags: ['generic'], tier: 1, maxTemplates: 999 })
  assert.equal(ceilingSel.selected.length, 400)
})
