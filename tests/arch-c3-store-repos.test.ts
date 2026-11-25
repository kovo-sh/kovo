import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { newProject, newRun } from '../src/domain.ts'
import * as resourceHarvest from '../src/server/resource-harvest.ts'
import * as storeFindings from '../src/server/store-findings.ts'
import * as storeProjects from '../src/server/store-projects.ts'
import * as storeRuns from '../src/server/store-runs.ts'
import * as storeSession from '../src/server/store-session.ts'
import * as storeMod from '../src/server/store.ts'
import { Store } from '../src/server/store.ts'

const SERVER_DIR = resolve(import.meta.dirname, '../src/server')

function lineCount(fileName: string): number {
  return readFileSync(join(SERVER_DIR, fileName), 'utf8').split('\n').length
}

function readSource(fileName: string): string {
  return readFileSync(join(SERVER_DIR, fileName), 'utf8')
}

test('arch-c3 store line budgets: store.ts <= 3,500 LOC thin facade and extracted repos populated', () => {
  const storeLines = lineCount('store.ts')
  const sessionLines = lineCount('store-session.ts')
  const projectsLines = lineCount('store-projects.ts')
  const runsLines = lineCount('store-runs.ts')
  const findingsLines = lineCount('store-findings.ts')
  const harvestLines = lineCount('resource-harvest.ts')

  assert.ok(storeLines <= 3500, `Expected store.ts <= 3500 LOC, got ${storeLines}`)
  assert.ok(sessionLines > 300, `Expected store-session.ts to hold shared DbSession/helpers, got ${sessionLines}`)
  assert.ok(projectsLines > 200, `Expected store-projects.ts to hold project domain repo, got ${projectsLines}`)
  assert.ok(runsLines > 500, `Expected store-runs.ts to hold runs domain repo, got ${runsLines}`)
  assert.ok(findingsLines > 500, `Expected store-findings.ts to hold findings domain repo, got ${findingsLines}`)
  assert.ok(harvestLines > 100, `Expected resource-harvest.ts to hold pure resource harvesting helpers, got ${harvestLines}`)
})

test('arch-c3 store module boundaries: strictly acyclic imports across repositories and leaf helpers', () => {
  const harvestSrc = readSource('resource-harvest.ts')
  const sessionSrc = readSource('store-session.ts')
  const projectsSrc = readSource('store-projects.ts')
  const findingsSrc = readSource('store-findings.ts')
  const runsSrc = readSource('store-runs.ts')
  const storeSrc = readSource('store.ts')

  // resource-harvest.ts is a pure leaf module with zero store* imports.
  assert.equal(/from\s+['"]\.\/store(?:-[a-z-]+)?\.ts['"]/.test(harvestSrc), false,
    'resource-harvest.ts must not depend on any store*.ts module')

  // store-session.ts must not import store.ts, any domain repository, or resource-harvest.ts.
  assert.equal(/from\s+['"]\.\/(?:store|store-projects|store-runs|store-findings|resource-harvest)\.ts['"]/.test(sessionSrc), false,
    'store-session.ts must not depend on store.ts or any repository')

  // store-projects.ts must not depend on store.ts, store-runs.ts, store-findings.ts, or resource-harvest.ts.
  assert.equal(/from\s+['"]\.\/(?:store|store-runs|store-findings|resource-harvest)\.ts['"]/.test(projectsSrc), false,
    'store-projects.ts must only depend on store-session.ts')

  // store-findings.ts must not depend on store.ts, store-projects.ts, or store-runs.ts.
  assert.equal(/from\s+['"]\.\/(?:store|store-projects|store-runs)\.ts['"]/.test(findingsSrc), false,
    'store-findings.ts must only depend on store-session.ts and resource-harvest.ts')

  // store-runs.ts must never import store.ts (and only type-only imports from sibling repos).
  assert.equal(/from\s+['"]\.\/store\.ts['"]/.test(runsSrc), false,
    'store-runs.ts must not depend on store.ts')
  assert.equal(/^\s*import\s+(?!type\b).*from\s+['"]\.\/store-(?:projects|findings)\.ts['"]/m.test(runsSrc), false,
    'store-runs.ts should only use type-only imports for sibling repositories')

  // store.ts wires all extracted modules.
  assert.match(storeSrc, /from\s+['"]\.\/store-session\.ts['"]/)
  assert.match(storeSrc, /from\s+['"]\.\/store-projects\.ts['"]/)
  assert.match(storeSrc, /from\s+['"]\.\/store-runs\.ts['"]/)
  assert.match(storeSrc, /from\s+['"]\.\/store-findings\.ts['"]/)
  assert.match(storeSrc, /from\s+['"]\.\/resource-harvest\.ts['"]/)
})

test('arch-c3 store export parity: store.ts preserves 100% of public runtime exports and identity', () => {
  const expectedRuntimeExports = [
    'DEFAULT_EXCHANGE_RETENTION_DAYS',
    'DEFAULT_FTS_MAX_BODY_BYTES',
    'DEFAULT_FTS_MODE',
    'DEFAULT_MAX_FULL_FTS_DB_BYTES',
    'FtsModeRefusedError',
    'InvariantError',
    'MAX_FTS_MAX_BODY_BYTES',
    'MIN_FTS_MAX_BODY_BYTES',
    'STORE_SCHEMA_VERSION',
    'Store',
    'TenantIsolationError',
    'assertConfirmedVerificationClass',
    'assessmentAssignments',
    'collectionPathFor',
    'dataDirectory',
    'deleteProjectWithActiveGuard',
    'deleteRunWithActiveGuard',
    'extractResourceRefsFromExchange',
    'ftsModes',
    'isOpaqueResourceId',
    'replayVerdictConfirmsRuntime',
    'resolvePageLimit',
    'resolvePageOffset',
    'store',
    'verificationClassForFinding',
  ].sort()

  const actualRuntimeExports = Object.keys(storeMod).sort()
  assert.deepEqual(actualRuntimeExports, expectedRuntimeExports)

  // Verify exact reference identity for re-exported resource-harvest helpers.
  for (const sym of ['collectionPathFor', 'extractResourceRefsFromExchange', 'isOpaqueResourceId'] as const) {
    assert.strictEqual(storeMod[sym], resourceHarvest[sym], `store.${sym} must re-export resource-harvest.${sym}`)
  }

  // Verify exact reference identity for re-exported store-session helpers/errors/constants.
  for (const sym of [
    'DEFAULT_EXCHANGE_RETENTION_DAYS',
    'DEFAULT_FTS_MAX_BODY_BYTES',
    'DEFAULT_FTS_MODE',
    'DEFAULT_MAX_FULL_FTS_DB_BYTES',
    'FtsModeRefusedError',
    'InvariantError',
    'MAX_FTS_MAX_BODY_BYTES',
    'MIN_FTS_MAX_BODY_BYTES',
    'STORE_SCHEMA_VERSION',
    'TenantIsolationError',
    'assertConfirmedVerificationClass',
    'assessmentAssignments',
    'dataDirectory',
    'ftsModes',
    'replayVerdictConfirmsRuntime',
    'resolvePageLimit',
    'resolvePageOffset',
    'verificationClassForFinding',
  ] as const) {
    assert.strictEqual(storeMod[sym], storeSession[sym], `store.${sym} must re-export store-session.${sym}`)
  }

  // Verify repository classes are exported from their respective modules.
  assert.equal(typeof storeSession.StoreSession, 'function')
  assert.equal(typeof storeProjects.ProjectsRepository, 'function')
  assert.equal(typeof storeRuns.RunsRepository, 'function')
  assert.equal(typeof storeFindings.FindingsRepository, 'function')
})

test('arch-c3 runtime facade parity: Store delegates through shared DbSession to projectsRepo, runsRepo, findingsRepo', t => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-arch-c3-store-'))
  const s = new Store(dir, { ftsMode: 'preview' })
  t.after(() => {
    s.close()
    rmSync(dir, { recursive: true, force: true })
  })

  // Shared session + domain repositories attached and live.
  assert.ok(s.session instanceof storeSession.StoreSession)
  assert.ok(s.projectsRepo instanceof storeProjects.ProjectsRepository)
  assert.ok(s.runsRepo instanceof storeRuns.RunsRepository)
  assert.ok(s.findingsRepo instanceof storeFindings.FindingsRepository)
  assert.equal(s.hasCascadeSchema(), true, 'fresh Store DB must report cascade schema enabled')

  // Projects repo parity: createProject, workspaceSummary, specs, projectDetail.
  const created = s.createProject(newProject.parse({
    requestId: randomUUID(),
    name: 'Facade Parity App',
    environment: 'public',
    seeds: ['https://app.example.test'],
  }))
  assert.equal(s.project(created.id).name, 'Facade Parity App')
  assert.equal(s.projectsRepo.project(created.id).id, created.id)

  const spec = s.upsertProjectSpecRaw(created.id, {
    name: 'openapi.json',
    kind: 'openapi',
    origin: 'https://app.example.test',
    content: '{"openapi":"3.1.0","paths":{}}',
  })
  assert.equal(s.listProjectSpecs(created.id).length, 1)
  assert.equal(s.getProjectSpec(created.id, spec.id).name, 'openapi.json')

  // Runs repo parity: createRun, discover, scope, runShellSummary, runDetail, capabilityLedger.
  const runCreated = s.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: created.id,
    goal: 'Verify facade delegation parity across repositories',
    capabilityTier: 1,
  }))
  const run = s.run(runCreated.id)
  assert.equal(s.runsRepo.run(run.id).id, run.id)

  s.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
  const afterDiscover = s.run(run.id)
  assert.equal(afterDiscover.phase, 'review')
  assert.equal(afterDiscover.candidates.length, 1)

  s.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'scope',
    assetIds: [afterDiscover.candidates[0]!.id],
    expectedScopeRevision: afterDiscover.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 1,
  })
  const scopedRun = s.run(run.id)
  assert.equal(scopedRun.scopeRevision, 1)

  // Findings repo parity: worker, fact, exchange, resource harvest, endpoint, replay spec + confirmation invariant.
  const worker = s.makeWorker(scopedRun, 'investigation', scopedRun.candidates[0], 'Check API', 'Inspect endpoints')
  const fact = s.addFact(scopedRun, worker, {
    kind: 'endpoint',
    origin: 'https://app.example.test',
    summary: 'Observed /api/invoices/42',
  })
  assert.equal(s.listFacts(run.id).some(f => f.id === fact.id), true)

  const ex = s.recordExchange({
    runId: run.id,
    assignmentId: worker.id,
    scopeRevision: scopedRun.scopeRevision,
    origin: 'https://app.example.test',
    finalOrigin: 'https://app.example.test',
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/api/invoices/42',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"invoiceId":"inv_123456"}',
    durationMs: 14,
  })
  const loadedEx = s.getExchange(run.id, ex.id)
  assert.equal(loadedEx.body, '{"invoiceId":"inv_123456"}')

  const harvested = s.trackExchangeResources({
    runId: run.id,
    exchange: {
      origin: 'https://app.example.test',
      method: 'GET',
      pathAndQuery: '/api/invoices/42',
      status: 200,
      mediaType: 'application/json',
      body: '{"invoiceId":"inv_123456"}',
    },
  })
  assert.ok(harvested.some(ref => ref.resourceId === 'inv_123456'))
  assert.ok(s.listResourceSamples(run.id).some(sample => sample.resourceId === 'inv_123456'))

  // Workspace summary & Run shell summary parity.
  const wsSummary = s.workspaceSummary()
  assert.equal(wsSummary.projects.length, 1)
  assert.equal(wsSummary.projects[0]!.runCount, 1)
  assert.equal(wsSummary.recentRuns[0]!.id, run.id)

  const shellSummary = s.runShellSummary(run.id)
  assert.equal(shellSummary.runs[0]!.id, run.id)
  assert.equal(shellSummary.counts.exchanges, 1)
  assert.ok(shellSummary.counts.events >= 1)

  const detail = s.runDetail(run.id, { limit: 10 })
  assert.equal(detail.run.id, run.id)
  assert.equal(detail.exchangesSummary.length, 1)
  assert.equal(detail.paging?.totals?.exchanges, 1)

  // CapabilityLedger shared-handle wiring preserved.
  const ledger = s.capabilityLedger(run.id)
  assert.equal(ledger.db, s.client)

  // Tenant audit log append-only immutability preserved across deleteRun/deleteProject.
  s.setProjectTenant(created.id, 'tenant-alpha')
  assert.equal(s.getProjectTenant(created.id), 'tenant-alpha')
  assert.equal(s.getRunTenant(run.id), 'tenant-alpha')
  const auditEntry = s.appendTenantAuditLog({
    tenantId: 'tenant-alpha',
    runId: run.id,
    actor: 'operator',
    action: 'run.audit',
    resourceKind: 'run',
    resourceId: run.id,
    outcome: 'allowed',
  })
  assert.equal(s.verifyTenantAuditLogChain('tenant-alpha').valid, true)

  // Cascade deleteRun & deleteProject preserve tenant_audit_log.
  const delRun = s.deleteRun(run.id)
  assert.equal(delRun.deleted, true)
  const delProj = s.deleteProject(created.id)
  assert.equal(delProj.deleted, true)
  const auditAfter = s.listTenantAuditLog('tenant-alpha')
  assert.equal(auditAfter.length, 1)
  assert.equal(auditAfter[0]!.id, auditEntry.id)
})
