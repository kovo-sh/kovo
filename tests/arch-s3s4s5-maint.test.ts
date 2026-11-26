/**
 * Move S3 + S4 + S5 Architectural Tests:
 *  - S3: StorageMaintenanceController (WAL PASSIVE vs idle-only TRUNCATE + incremental_vacuum,
 *        wired artifact-ttl sweeps, bounded operations retention, symlink-safe orphan disk
 *        sweeper across scratch/artifacts/agent-sessions, AppRuntime lifecycle with .unref()
 *        timers, and session.afterCommit rollback safety).
 *  - S4: Canonical FindingCodec & promoted indexed columns (status, severity, cwe, origin,
 *        triage_status), idempotent backfill from legacy JSON-only rows, indexed queryFindings,
 *        and invariant-exact confirmedCount rollups excluding static_verified & superseded rows.
 *  - S5: Transactional versioned MIGRATIONS runner (BEGIN EXCLUSIVE per step, data backfill
 *        before constraints, PRAGMA user_version bump inside tx, upgrade from user_version = 0
 *        and v9 user DB copy, downgrade protection, and atomic rollback on failed step).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { newProject, newRun } from '../src/domain.ts'
import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import {
  FindingCodec,
  PROMOTED_FINDING_COLUMNS,
  type RawFindingRow,
} from '../src/server/finding-codec.ts'
import {
  DEFAULT_OPERATIONS_RETENTION_MS,
  StorageMaintenanceController,
} from '../src/server/storage-maintenance.ts'
import {
  SchemaDowngradeError,
  STORE_SCHEMA_VERSION,
  runSqliteMigrations,
  type MigrationStep,
} from '../src/server/store-session.ts'
import { Store } from '../src/server/store.ts'

const ORIGIN = 'https://maint.example.test'
const HOUR_MS = 60 * 60_000
const DAY_MS = 24 * HOUR_MS

function makeTempDir(t: test.TestContext, prefix = 'kovo-s3s4s5-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => {
    rmSync(dir, { recursive: true, force: true })
  })
  return dir
}

function makeTempStore(t: test.TestContext, prefix = 'kovo-s3s4s5-'): { dir: string; store: Store } {
  const dir = makeTempDir(t, prefix)
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
  })
  return { dir, store }
}

function setupRun(store: Store, name = 'Maint App', origin = ORIGIN) {
  const proj = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [origin],
  }))
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: `Assess ${name}`,
    capabilityTier: 1,
  }))
  store.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
  const discovered = store.run(createdRun.id)
  store.command({
    requestId: randomUUID(),
    runId: createdRun.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 1,
  })
  const run = store.run(createdRun.id)
  const asset = run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'Maint Worker', 'Verify controls')
  return { projectId: proj.id, runId: run.id, run, asset, worker }
}

function sampleSpec(title: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Authorization boundary',
    impact: 'Cross-account data read',
    remediation: 'Enforce ownership checks',
    recheckInstructions: 'Replay request chain',
    assertionsJq: '.status == 200',
    spaCatchallControl: false,
    steps: [{
      id: 'probe-1',
      role: 'probe',
      description: 'Read target object',
      request: {
        origin,
        method: 'GET',
        pathAndQuery: '/api/items/1',
        followRedirects: false,
      },
    }],
  } as unknown as DeclarativeReplaySpec
}

function confirmedFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    controlPassed: true,
    assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
    stepStatuses: [{ id: 'probe-1', role: 'probe', status: 200, bodyLen: 16 }],
    retriesRemaining: 0,
  }
}

function setOldMtime(path: string, ageMs: number, now = Date.now()): void {
  const ts = new Date(now - ageMs)
  utimesSync(path, ts, ts)
}

// ============================================================================
// Move S3 — StorageMaintenanceController, AppRuntime lifecycle & afterCommit
// ============================================================================

test('S3: AppRuntime owns StorageMaintenanceController lifecycle and runs PASSIVE vs idle-only TRUNCATE + incremental_vacuum', async t => {
  const dir = makeTempDir(t, 'kovo-s3-wal-')
  const runtime = createAppRuntime({
    dataDir: dir,
    maintenance: {
      walCheckpointIntervalMs: 60_000,
      maintenanceIntervalMs: 120_000,
      incrementalVacuumPages: 50,
    },
  })
  t.after(async () => {
    if (!runtime.isDisposed) await runtime.dispose()
  })

  // Lazy-init preserved: Store and Maintenance are not created until accessed.
  assert.equal(runtime.hasStore(), false)
  assert.equal(runtime.hasMaintenance(), false)

  const st = runtime.store
  assert.equal(runtime.hasStore(), true)
  assert.equal(runtime.hasMaintenance(), true)
  assert.equal(runtime.maintenance.isRunning(), true)

  // Brand-new DB has incremental auto_vacuum enabled (2 = INCREMENTAL).
  const autoVac = st.client.prepare('PRAGMA auto_vacuum').get() as { auto_vacuum: number }
  assert.equal(Number(autoVac.auto_vacuum), 2, 'new databases must enable PRAGMA auto_vacuum = INCREMENTAL')

  // Generate WAL activity.
  const { runId, run, worker } = setupRun(st, 'WAL App')
  for (let i = 0; i < 20; i += 1) {
    st.recordExchange({
      runId,
      assignmentId: worker.id,
      scopeRevision: run.scopeRevision,
      origin: ORIGIN,
      finalOrigin: ORIGIN,
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: `/api/wal/${i}`,
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: {},
      body: JSON.stringify({ idx: i, pad: 'x'.repeat(256) }),
      durationMs: 3,
    })
  }
  st.flushNow()

  // With an active RunContext, checkpoint must stay PASSIVE and skip TRUNCATE/incremental_vacuum.
  const runCtx = runtime.createRunContext(runId)
  const activeCkpt = runtime.maintenance.runCheckpoint({ allowTruncate: true })
  assert.equal(activeCkpt.mode, 'passive')
  assert.equal(activeCkpt.activeRuns, 1)
  assert.equal(activeCkpt.incrementalVacuumRan, false)

  // After disposing RunContext (and run not marked running in DB), checkpoint upgrades to TRUNCATE + incremental_vacuum.
  await runCtx.dispose()
  st.updateRun(runId, { status: 'complete' })
  const idleCkpt = runtime.maintenance.runCheckpoint({ allowTruncate: true })
  assert.equal(idleCkpt.mode, 'truncate')
  assert.equal(idleCkpt.activeRuns, 0)
  assert.equal(idleCkpt.incrementalVacuumRan, true)
  assert.equal(idleCkpt.incrementalVacuumPages, 50)

  // AppRuntime.dispose() stops StorageMaintenanceController cleanly before closing Store.
  const disposeReport = await runtime.dispose()
  assert.deepEqual(disposeReport.errors, [])
  assert.equal(disposeReport.maintenanceStopped, true)
  assert.equal(disposeReport.storeClosed, true)
})

test('S3: StorageMaintenanceController sweeps TTL, bounds operations retention, and cleans orphans safely without touching active runs or symlinks', t => {
  const { dir, store } = makeTempStore(t, 'kovo-s3-sweep-')
  const now = Date.now()
  const idle = setupRun(store, 'Idle Sweep App', 'https://idle.example.test')
  const active = setupRun(store, 'Active Sweep App', 'https://active.example.test')
  store.updateRun(idle.runId, { status: 'complete' })
  store.updateRun(active.runId, { status: 'running' })

  // 1. Seed aged exchange + aged evidence (one protected by confirmed finding, one unprotected) + aged tmp file.
  const agedEx = store.recordExchange({
    runId: idle.runId,
    assignmentId: idle.worker.id,
    scopeRevision: idle.run.scopeRevision,
    origin: 'https://idle.example.test',
    finalOrigin: 'https://idle.example.test',
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/api/old-ex',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    body: '{"aged":true}',
    durationMs: 2,
  })
  store.flushNow()
  store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?').run(now - 20 * DAY_MS, agedEx.id)

  const unprotectedArt = store.addArtifact(idle.run, idle.worker, 'observation', 'Aged observation', 'old-content')
  const protectedArt = store.addArtifact(idle.run, idle.worker, 'verification', 'Confirmed proof', 'keep-this-proof')
  store.client.prepare('UPDATE evidence SET created_at = ? WHERE id IN (?, ?)').run(
    now - 20 * DAY_MS,
    unprotectedArt.id,
    protectedArt.id,
  )

  const confirmedFindingId = randomUUID()
  const spec = store.createReplaySpec(idle.run, idle.worker, confirmedFindingId, sampleSpec('Keep Evidence', 'https://idle.example.test'), ['https://idle.example.test'], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.upsertChainFinding(idle.run, idle.asset.id, {
    id: confirmedFindingId,
    origin: 'https://idle.example.test',
    title: 'Confirmed finding with protected evidence',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Verified runtime proof',
    remediation: 'Fix access check',
    evidenceIds: [protectedArt.id],
    scopeRevision: idle.run.scopeRevision,
    verificationTier: 'runtime_confirmed',
  }, spec.id, ['https://idle.example.test'])

  // 2. Seed operations rows: one older than 7 days, one fresh.
  const oldOpId = randomUUID()
  const freshOpId = randomUUID()
  store.operate({ requestId: oldOpId }, () => ({ id: 'old-op-res' }))
  store.operate({ requestId: freshOpId }, () => ({ id: 'fresh-op-res' }))
  store.client.prepare('UPDATE operations SET created_at = ? WHERE id = ?').run(now - 10 * DAY_MS, oldOpId)

  // 3. Seed scratch/, artifacts/, agent-sessions/, tmp/ with:
  //    - stale orphans (MUST be deleted)
  //    - fresh in-flight files inside graceMs (MUST survive)
  //    - active run directories (MUST survive)
  //    - symlinks pointing outside (MUST be skipped and target MUST survive)
  const externalDir = makeTempDir(t, 'kovo-s3-symtarget-')
  const externalFile = join(externalDir, 'do-not-delete.txt')
  writeFileSync(externalFile, 'precious-external-target', 'utf8')

  const scratchRoot = join(dir, 'scratch')
  const staleScratchDir = join(scratchRoot, 'orphan-job-1')
  const activeScratchDir = join(scratchRoot, `run-${active.runId}`)
  const freshScratchFile = join(scratchRoot, 'inflight.tmp')
  mkdirSync(staleScratchDir, { recursive: true })
  mkdirSync(activeScratchDir, { recursive: true })
  const staleScratchFile = join(staleScratchDir, 'dump.txt')
  const activeScratchFile = join(activeScratchDir, 'active-work.txt')
  writeFileSync(staleScratchFile, 'stale-scratch', 'utf8')
  writeFileSync(activeScratchFile, 'active-work', 'utf8')
  writeFileSync(freshScratchFile, 'just-created', 'utf8')
  const scratchSymlink = join(scratchRoot, 'escape-link.txt')
  symlinkSync(externalFile, scratchSymlink)
  setOldMtime(staleScratchFile, 2 * HOUR_MS, now)
  setOldMtime(staleScratchDir, 2 * HOUR_MS, now)
  setOldMtime(activeScratchFile, 2 * HOUR_MS, now)
  setOldMtime(activeScratchDir, 2 * HOUR_MS, now)

  const orphanArtRunDir = join(dir, 'artifacts', 'orphan-deleted-run-999')
  mkdirSync(orphanArtRunDir, { recursive: true })
  const orphanArtFile = join(orphanArtRunDir, 'dead-art.txt')
  writeFileSync(orphanArtFile, 'stale-orphan-artifact', 'utf8')
  setOldMtime(orphanArtFile, 2 * HOUR_MS, now)
  setOldMtime(orphanArtRunDir, 2 * HOUR_MS, now)

  const orphanFlatArt = join(dir, 'artifacts', 'unreferenced-flat-1.txt')
  writeFileSync(orphanFlatArt, 'orphan-flat-artifact', 'utf8')
  setOldMtime(orphanFlatArt, 2 * HOUR_MS, now)

  const activeArtDir = join(dir, 'artifacts', active.runId)
  mkdirSync(activeArtDir, { recursive: true })
  const activeArtFile = join(activeArtDir, 'in-flight-active.txt')
  writeFileSync(activeArtFile, 'active-run-artifact', 'utf8')
  setOldMtime(activeArtFile, 2 * HOUR_MS, now)

  const sessionsRoot = join(dir, 'agent-sessions')
  mkdirSync(sessionsRoot, { recursive: true })
  const staleSessionDb = join(sessionsRoot, 'orphan-session-xyz.sqlite')
  const liveSessionDb = join(sessionsRoot, `${idle.worker.sessionId}.sqlite`)
  const freshSessionDb = join(sessionsRoot, 'brand-new-session.sqlite')
  writeFileSync(staleSessionDb, 'stale-session-db', 'utf8')
  writeFileSync(liveSessionDb, 'live-session-db', 'utf8')
  writeFileSync(freshSessionDb, 'fresh-session-db', 'utf8')
  setOldMtime(staleSessionDb, 2 * HOUR_MS, now)
  setOldMtime(liveSessionDb, 2 * HOUR_MS, now)

  const maint = new StorageMaintenanceController({
    store,
    dataDir: dir,
    getActiveRunIds: () => [active.runId],
    operationsRetentionMs: DEFAULT_OPERATIONS_RETENTION_MS,
    orphanGraceMs: 30 * 60_000,
    now: () => now,
  })

  const report = maint.runMaintenanceCycle({ now })
  assert.deepEqual(report.errors, [])

  // TTL sweep ran automatically: aged exchange & unprotected artifact deleted, confirmed artifact preserved!
  assert.equal(report.ttl?.exchangesDeleted, 1)
  assert.equal(report.ttl?.artifactsDeleted, 1)
  assert.equal(report.ttl?.artifactFilesDeleted, 1)
  assert.equal(store.artifact(idle.runId, protectedArt.id).content, 'keep-this-proof')

  // Operations retention bounded to 7 days.
  assert.equal(report.operations.deleted, 1)
  const remainingOps = (store.client.prepare('SELECT id FROM operations').all() as Array<{ id: string }>).map(r => r.id)
  assert.equal(remainingOps.includes(oldOpId), false)
  assert.equal(remainingOps.includes(freshOpId), true)

  // Orphan sweep cleaned stale scratch/artifacts/agent-sessions while protecting active runs, in-flight files, live refs, and symlinks!
  assert.equal(existsSync(staleScratchFile), false)
  assert.equal(existsSync(staleScratchDir), false)
  assert.equal(existsSync(activeScratchFile), true, 'active run scratch dir must never be deleted')
  assert.equal(existsSync(freshScratchFile), true, 'in-flight file inside grace window must never be deleted')
  assert.equal(existsSync(externalFile), true, 'symlink target outside scratch must never be deleted')
  assert.ok(report.orphans.symlinksSkipped >= 1)

  assert.equal(existsSync(orphanArtFile), false)
  assert.equal(existsSync(orphanArtRunDir), false)
  assert.equal(existsSync(orphanFlatArt), false)
  assert.equal(existsSync(activeArtFile), true, 'active run artifact dir must never be deleted')

  assert.equal(existsSync(staleSessionDb), false)
  assert.equal(existsSync(liveSessionDb), true, 'DB-referenced session DB must never be deleted')
  assert.equal(existsSync(freshSessionDb), true, 'recent in-flight session DB inside grace window must survive')

  // Because active run was running, checkpoint stayed PASSIVE.
  assert.equal(report.checkpoint.mode, 'passive')
  assert.equal(report.checkpoint.activeRuns, 1)
})

test('S3: session.afterCommit runs disk deletions strictly AFTER COMMIT and discards them on ROLLBACK or savepoint rollback', t => {
  const { dir, store } = makeTempStore(t, 'kovo-s3-aftercommit-')
  const rollbackFile = join(dir, 'artifacts', 'rollback-protected.txt')
  const innerRollbackFile = join(dir, 'artifacts', 'savepoint-rollback.txt')
  const commitFile = join(dir, 'artifacts', 'committed-delete.txt')
  writeFileSync(rollbackFile, 'must-survive-rollback', 'utf8')
  writeFileSync(innerRollbackFile, 'must-survive-savepoint-rollback', 'utf8')
  writeFileSync(commitFile, 'should-be-unlinked-after-commit', 'utf8')

  // 1. Outermost transaction rollback must NOT execute afterCommit hooks.
  let rollbackHookRan = false
  assert.throws(() => {
    store.transaction(() => {
      store.session.afterCommit(() => {
        rollbackHookRan = true
        rmSync(rollbackFile, { force: true })
      })
      throw new Error('simulated failure before commit')
    })
  }, /simulated failure before commit/)
  assert.equal(rollbackHookRan, false)
  assert.equal(existsSync(rollbackFile), true, 'disk file must NOT be deleted when SQLite transaction rolls back')

  // 2. Nested savepoint rollback discards inner afterCommit while outer COMMIT runs outer afterCommit strictly AFTER commit.
  const order: string[] = []
  store.transaction(() => {
    order.push('outer-tx-body')
    store.session.afterCommit(() => {
      order.push('outer-after-commit')
      rmSync(commitFile, { force: true })
    })
    assert.equal(existsSync(commitFile), true, 'file must still exist before COMMIT')
    try {
      store.transaction(() => {
        store.session.afterCommit(() => {
          order.push('inner-after-commit-should-not-run')
          rmSync(innerRollbackFile, { force: true })
        })
        throw new Error('inner savepoint abort')
      })
    } catch { /* expected savepoint rollback */ }
    order.push('outer-tx-end')
  })
  assert.deepEqual(order, ['outer-tx-body', 'outer-tx-end', 'outer-after-commit'])
  assert.equal(existsSync(innerRollbackFile), true, 'rolled-back savepoint must not delete its disk file')
  assert.equal(existsSync(commitFile), false, 'committed outer transaction must execute afterCommit file deletion')

  // 3. purgeExpiredArtifacts respects enclosing transaction rollback via session.afterCommit.
  const { runId, run, worker } = setupRun(store, 'TTL Rollback App')
  store.updateRun(runId, { status: 'complete' })
  const art = store.addArtifact(run, worker, 'observation', 'Rollback-safe artifact', 'preserve-me')
  store.client.prepare('UPDATE evidence SET created_at = ? WHERE id = ?').run(Date.now() - 10 * DAY_MS, art.id)

  assert.throws(() => {
    store.transaction(() => {
      store.purgeArtifactsByTtl({
        runId,
        artifactTtlMs: DAY_MS,
        skipActiveRuns: false,
      })
      throw new Error('abort ttl batch')
    })
  }, /abort ttl batch/)
  // Both DB row and disk file survived the rollback intact!
  assert.equal(store.artifact(runId, art.id).content, 'preserve-me')
})

// ============================================================================
// Move S4 — Canonical FindingCodec, Promoted Indexed Columns & confirmedCount
// ============================================================================

test('S4: FindingCodec keeps promoted indexed columns in lockstep with JSON and produces invariant-exact confirmedCount rollups', t => {
  const { store } = makeTempStore(t, 'kovo-s4-codec-')
  const { projectId, runId, run, asset, worker } = setupRun(store, 'Codec App')

  // Verify promoted columns and indexes exist on findings.
  const cols = new Set(
    (store.client.prepare('PRAGMA table_info(findings)').all() as Array<{ name: string }>).map(r => r.name),
  )
  for (const col of PROMOTED_FINDING_COLUMNS) {
    assert.equal(cols.has(col), true, `findings must have promoted column ${col}`)
  }
  const indexes = new Set(
    (store.client.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'findings'").all() as Array<{ name: string }>)
      .map(r => r.name),
  )
  for (const idx of ['findings_run_verified', 'findings_run_status_severity', 'findings_run_triage', 'findings_run_origin_cwe']) {
    assert.equal(indexes.has(idx), true, `findings must have index ${idx}`)
  }

  // 1. Confirmed runtime finding
  const confirmedId = randomUUID()
  const confirmedSpec = store.createReplaySpec(run, worker, confirmedId, sampleSpec('Confirmed IDOR'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: confirmedId,
    origin: ORIGIN,
    title: 'Confirmed IDOR',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Cross-user read verified',
    remediation: 'Enforce ownership',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-confirmed-1',
  }, confirmedSpec.id, [ORIGIN])

  // 2. Static advisory finding (MUST NOT be counted in confirmedCount!)
  const staticId = randomUUID()
  const staticSpec = store.createReplaySpec(run, worker, staticId, sampleSpec('Static Advisory'), [ORIGIN])
  store.upsertChainFinding(run, asset.id, {
    id: staticId,
    origin: ORIGIN,
    title: 'Static Advisory',
    status: 'static_verified',
    severity: 'medium',
    category: 'injection-input',
    cwe: 'CWE-79',
    reason: 'Static code pattern',
    remediation: 'Encode output',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
    fingerprintHash: 'fp-static-1',
  }, staticSpec.id, [ORIGIN])

  // 3. Superseded confirmed finding (MUST NOT be counted in confirmedCount or findingCount!)
  const supersededId = randomUUID()
  const supersededSpec = store.createReplaySpec(run, worker, supersededId, sampleSpec('Superseded Confirmed'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: supersededId,
    origin: ORIGIN,
    title: 'Superseded Confirmed',
    status: 'confirmed',
    severity: 'critical',
    category: 'broken-access-control',
    cwe: 'CWE-284',
    reason: 'Superseded duplicate',
    remediation: 'Enforce authorization',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    supersededByFindingId: confirmedId,
    fingerprintHash: 'fp-superseded-1',
  }, supersededSpec.id, [ORIGIN])

  // 4. Pending finding -> triage it -> verify promoted triage_status updates atomically.
  const pendingId = randomUUID()
  const pendingSpec = store.createReplaySpec(run, worker, pendingId, sampleSpec('Pending Lead'), [ORIGIN])
  store.upsertChainFinding(run, asset.id, {
    id: pendingId,
    origin: ORIGIN,
    title: 'Pending Lead',
    status: 'pending',
    severity: 'low',
    category: 'misconfig-exposure',
    cwe: 'CWE-200',
    reason: 'Needs runtime verification',
    remediation: 'Restrict debug output',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    fingerprintHash: 'fp-pending-1',
  }, pendingSpec.id, [ORIGIN])

  store.findingsRepo.triageFinding(pendingId, { status: 'accepted_risk', notes: 'Approved by security team' })

  // Verify raw SQL promoted columns match JSON 1:1.
  const rawConfirmed = store.client.prepare('SELECT * FROM findings WHERE id = ?').get(confirmedId) as unknown as RawFindingRow
  assert.equal(rawConfirmed.status, 'confirmed')
  assert.equal(rawConfirmed.severity, 'high')
  assert.equal(rawConfirmed.cwe, 'CWE-639')
  assert.equal(rawConfirmed.origin, ORIGIN)
  assert.equal(rawConfirmed.triage_status, 'open')
  const decodedConfirmed = FindingCodec.fromRow(rawConfirmed)
  assert.equal(decodedConfirmed.id, confirmedId)
  assert.equal(decodedConfirmed.status, 'confirmed')
  assert.equal(decodedConfirmed.verificationStatus, 'runtime_confirmed')

  const rawPending = store.client.prepare('SELECT * FROM findings WHERE id = ?').get(pendingId) as unknown as RawFindingRow
  assert.equal(rawPending.triage_status, 'accepted_risk')
  assert.equal(FindingCodec.fromRow(rawPending).operatorTriage?.status, 'accepted_risk')

  // Verify indexed queryFindings filters cleanly without scanning JSON.
  assert.deepEqual(store.queryFindings(runId, { status: 'confirmed' }).map(f => f.id), [confirmedId])
  assert.deepEqual(store.queryFindings(runId, { triageStatus: 'accepted_risk' }).map(f => f.id), [pendingId])
  assert.deepEqual(store.queryFindings(runId, { cwe: 'CWE-79', origin: ORIGIN }).map(f => f.id), [staticId])
  assert.equal(store.queryFindings(runId, { includeSuperseded: true }).length, 4)
  assert.equal(store.queryFindings(runId).length, 3)

  // Verify dashboard confirmedCount rollups exclude static_verified & superseded!
  assert.equal(store.confirmedFindingCount(runId), 1)
  const ws = store.workspaceSummary()
  const projSummary = ws.projects.find(p => p.id === projectId)!
  assert.equal(projSummary.latestRun?.confirmedCount, 1, 'workspaceSummary latestRun must count ONLY runtime_confirmed non-superseded findings')
  assert.equal(projSummary.latestRun?.findingCount, 3)
  assert.equal(ws.recentRuns[0]?.confirmedCount, 1)

  const detail = store.projectDetail(projectId)
  assert.equal(detail.runs[0]?.confirmedCount, 1, 'projectDetail must count ONLY runtime_confirmed non-superseded findings')
  assert.equal(detail.runs[0]?.findingCount, 3)

  // Demoting confirmed finding via contradicting replay diff updates BOTH JSON and promoted status column!
  store.incrementReplaySpecAttempt(confirmedSpec.id, {
    verdict: 'inconclusive',
    controlPassed: false,
    stepStatuses: [{ id: 'probe-1', role: 'probe', status: 403, bodyLen: 0 }],
    retriesRemaining: 0,
  })
  const afterDemote = store.client.prepare('SELECT status, verification_class FROM findings WHERE id = ?').get(confirmedId) as {
    status: string
    verification_class: string
  }
  assert.equal(afterDemote.status, 'inconclusive')
  assert.equal(afterDemote.verification_class, 'open_proof_gap')
  assert.equal(store.confirmedFindingCount(runId), 0)
  assert.equal(store.workspaceSummary().projects[0]?.latestRun?.confirmedCount, 0)
})

test('S4: FindingCodec.backfillPromotedColumns is idempotent on legacy JSON-only rows', t => {
  const { store } = makeTempStore(t, 'kovo-s4-backfill-')
  const { runId, run, asset, worker } = setupRun(store, 'Backfill App')
  const fid = randomUUID()
  const spec = store.createReplaySpec(run, worker, fid, sampleSpec('Legacy Row'), [ORIGIN])
  store.upsertChainFinding(run, asset.id, {
    id: fid,
    origin: ORIGIN,
    title: 'Legacy Row',
    status: 'pending',
    severity: 'high',
    category: 'injection-input',
    cwe: 'CWE-89',
    reason: 'Needs replay',
    remediation: 'Parameterize query',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
  }, spec.id, [ORIGIN])
  store.findingsRepo.triageFinding(fid, { status: 'false_positive' })

  // Simulate stale/default promoted columns left over from a pre-v10 schema.
  store.client.prepare(
    "UPDATE findings SET status = 'pending', severity = 'medium', cwe = NULL, origin = '', triage_status = 'open' WHERE id = ?",
  ).run(fid)

  const changedFirst = FindingCodec.backfillPromotedColumns(store.client)
  assert.equal(changedFirst, 1)
  const changedSecond = FindingCodec.backfillPromotedColumns(store.client)
  assert.equal(changedSecond, 0, 'backfill must be strictly idempotent')

  const row = store.client.prepare('SELECT status, severity, cwe, origin, triage_status FROM findings WHERE id = ?').get(fid) as {
    status: string
    severity: string
    cwe: string | null
    origin: string
    triage_status: string
  }
  assert.deepEqual({ ...row }, {
    status: 'pending',
    severity: 'high',
    cwe: 'CWE-89',
    origin: ORIGIN,
    triage_status: 'false_positive',
  })
})

// ============================================================================
// Move S5 — Transactional Versioned MIGRATIONS Runner
// ============================================================================

test('S5: transactional MIGRATIONS runner upgrades legacy user_version = 0 DB (including static_verified+confirmed wedge) and skips on subsequent boots', t => {
  const { dir, store } = makeTempStore(t, 'kovo-s5-legacy0-')
  const { runId, run, asset } = setupRun(store, 'Legacy V0 App')
  const legacyStaticId = randomUUID()
  const legacyOpId = randomUUID()
  store.operate({ requestId: legacyOpId }, () => ({ id: 'op-v0' }))
  store.close()

  // Simulate a pre-v6 / user_version = 0 database missing provenance, verification_class,
  // promoted finding columns, and operations.created_at — WITH a wedging static_verified+confirmed row!
  const raw = new DatabaseSync(join(dir, 'kovo.sqlite'))
  raw.exec(`
    PRAGMA foreign_keys = OFF;
    DROP TABLE findings;
    CREATE TABLE findings (
      id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL REFERENCES runs(id),
      asset_id TEXT NOT NULL,
      goal_revision INTEGER NOT NULL,
      check_id TEXT NOT NULL DEFAULT 'hsts',
      case_id TEXT NOT NULL DEFAULT '',
      finding_kind TEXT NOT NULL DEFAULT 'baseline_check',
      replay_spec_id TEXT,
      source_origins TEXT NOT NULL,
      verification_tier TEXT,
      fingerprint_hash TEXT,
      superseded_by_finding_id TEXT,
      counterevidence TEXT,
      confidence_rationale TEXT,
      severity_change_conditions TEXT,
      code_locations TEXT,
      finding TEXT NOT NULL
    );
    DROP TABLE operations;
    CREATE TABLE operations (
      id TEXT PRIMARY KEY NOT NULL,
      workspace_id TEXT NOT NULL REFERENCES workspaces(id),
      fingerprint TEXT NOT NULL,
      result TEXT NOT NULL
    );
    PRAGMA user_version = 0;
  `)
  const wsId = (raw.prepare('SELECT id FROM workspaces LIMIT 1').get() as { id: string }).id
  raw.prepare('INSERT INTO operations (id, workspace_id, fingerprint, result) VALUES (?, ?, ?, ?)').run(
    legacyOpId,
    wsId,
    'legacy-fp',
    '{"id":"op-v0"}',
  )
  const wedgingFinding: Finding = {
    id: legacyStaticId,
    origin: ORIGIN,
    title: 'Legacy Static Row Marked Confirmed',
    status: 'confirmed',
    severity: 'high',
    category: 'injection-input',
    cwe: 'CWE-79',
    reason: 'Static match from pre-v6 schema',
    remediation: 'Sanitize output',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
  }
  raw.prepare(`
    INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, source_origins, verification_tier, finding)
    VALUES (?, ?, ?, ?, 'chain', ?, 'multi_step_chain', ?, 'static_verified', ?)
  `).run(legacyStaticId, runId, asset.id, run.goalRevision, legacyStaticId, JSON.stringify([ORIGIN]), JSON.stringify(wedgingFinding))
  raw.close()

  // Reopen with Store: transactional migrations v1..v10 must normalize data BEFORE CHECK constraints and backfill promoted columns!
  const upgraded = new Store(dir)
  assert.equal(upgraded.migrationReport.fromVersion, 0)
  assert.equal(upgraded.migrationReport.toVersion, STORE_SCHEMA_VERSION)
  assert.equal(upgraded.migrationReport.applied.length, STORE_SCHEMA_VERSION)
  const stamped = (upgraded.client.prepare('PRAGMA user_version').get() as { user_version: number }).user_version
  assert.equal(Number(stamped), STORE_SCHEMA_VERSION)

  const migratedRow = upgraded.client.prepare(
    'SELECT status, severity, cwe, origin, triage_status, verification_class FROM findings WHERE id = ?',
  ).get(legacyStaticId) as {
    status: string
    severity: string
    cwe: string | null
    origin: string
    triage_status: string
    verification_class: string
  }
  assert.equal(migratedRow.status, 'static_verified', 'legacy static_verified+confirmed row must be normalized to static_verified')
  assert.equal(migratedRow.verification_class, 'static_advisory')
  assert.equal(migratedRow.severity, 'high')
  assert.equal(migratedRow.cwe, 'CWE-79')
  assert.equal(migratedRow.origin, ORIGIN)
  assert.equal(migratedRow.triage_status, 'open')
  assert.equal(upgraded.confirmedFindingCount(runId), 0)

  const opRow = upgraded.client.prepare('SELECT created_at FROM operations WHERE id = ?').get(legacyOpId) as { created_at: number }
  assert.ok(opRow.created_at > 0, 'legacy operations row must backfill created_at')
  upgraded.close()

  // Reopening an already-migrated DB is an instant no-op with zero migrations applied.
  const reopened = new Store(dir)
  t.after(() => reopened.close())
  assert.equal(reopened.migrationReport.fromVersion, STORE_SCHEMA_VERSION)
  assert.equal(reopened.migrationReport.toVersion, STORE_SCHEMA_VERSION)
  assert.equal(reopened.migrationReport.applied.length, 0)
})

test('S5: downgrade protection refuses newer user_version and failed migration rolls back atomically', t => {
  // 1. Downgrade protection on Store open (must throw SchemaDowngradeError and release process lock).
  const dir = makeTempDir(t, 'kovo-s5-downgrade-')
  const seeded = new Store(dir)
  seeded.close()

  const futureDb = new DatabaseSync(join(dir, 'kovo.sqlite'))
  futureDb.exec(`PRAGMA user_version = ${STORE_SCHEMA_VERSION + 5};`)
  futureDb.close()

  assert.throws(
    () => new Store(dir),
    (err: unknown) => err instanceof SchemaDowngradeError
      && err.code === 'SCHEMA_DOWNGRADE_REFUSED'
      && err.dbVersion === STORE_SCHEMA_VERSION + 5
      && err.supportedVersion === STORE_SCHEMA_VERSION,
  )

  // Process lock must have been cleanly released so restoring version allows reopening!
  const restored = new DatabaseSync(join(dir, 'kovo.sqlite'))
  restored.exec(`PRAGMA user_version = ${STORE_SCHEMA_VERSION};`)
  restored.close()
  const okStore = new Store(dir)
  t.after(() => okStore.close())
  assert.equal(okStore.migrationReport.toVersion, STORE_SCHEMA_VERSION)

  // 2. Atomic rollback on failed migration step (neither DDL/rows nor user_version persists).
  const rollbackDir = makeTempDir(t, 'kovo-s5-txrollback-')
  const dbPath = join(rollbackDir, 'mig.sqlite')
  const raw = new DatabaseSync(dbPath)
  t.after(() => raw.close())

  const steps: MigrationStep[] = [
    {
      version: 1,
      name: 'create_alpha',
      up(ctx) {
        ctx.client.exec('CREATE TABLE alpha (id INTEGER PRIMARY KEY, val TEXT NOT NULL);')
        ctx.client.prepare('INSERT INTO alpha (id, val) VALUES (1, ?)').run('ok')
      },
    },
    {
      version: 2,
      name: 'failing_beta',
      up(ctx) {
        ctx.client.exec('CREATE TABLE beta (id INTEGER PRIMARY KEY);')
        ctx.client.prepare('INSERT INTO alpha (id, val) VALUES (2, ?)').run('should-rollback')
        throw new Error('boom mid-migration')
      },
    },
  ]

  assert.throws(() => runSqliteMigrations(raw, steps), /Migration v2 \(failing_beta\) failed: boom mid-migration/)

  // Step 1 stayed committed, Step 2 completely rolled back (including user_version staying at 1).
  const versionAfterFail = Number((raw.prepare('PRAGMA user_version').get() as { user_version: number }).user_version)
  assert.equal(versionAfterFail, 1, 'PRAGMA user_version must roll back atomically on failed migration step')
  const betaExists = raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'beta'").get()
  assert.equal(betaExists, undefined, 'DDL from failed migration step must be rolled back')
  const alphaRows = raw.prepare('SELECT id FROM alpha ORDER BY id').all() as Array<{ id: number }>
  assert.deepEqual(alphaRows.map(r => r.id), [1], 'DML from failed migration step must be rolled back')
})

test('S5: upgrades a copy of existing pre-v10 user database (/home/omarchy/guardian-user-data/kovo.sqlite) losslessly when present', t => {
  const sourceDb = '/home/omarchy/guardian-user-data/kovo.sqlite'
  if (!existsSync(sourceDb)) {
    t.skip('host user kovo.sqlite not present')
    return
  }
  const copyDir = makeTempDir(t, 'kovo-s5-userdb-copy-')
  const destDb = join(copyDir, 'kovo.sqlite')
  copyFileSync(sourceDb, destDb)
  // Also copy WAL/SHM if present so snapshot is consistent before opening.
  for (const suffix of ['-wal', '-shm']) {
    if (existsSync(sourceDb + suffix)) {
      copyFileSync(sourceDb + suffix, destDb + suffix)
    }
  }

  const pre = new DatabaseSync(destDb, { readOnly: true })
  const preFindings = Number((pre.prepare('SELECT count(*) AS c FROM findings').get() as { c: number }).c)
  const preRuns = Number((pre.prepare('SELECT count(*) AS c FROM runs').get() as { c: number }).c)
  pre.close()

  const upgraded = new Store(copyDir)
  t.after(() => upgraded.close())

  assert.equal(upgraded.migrationReport.toVersion, STORE_SCHEMA_VERSION)
  const postFindings = Number((upgraded.client.prepare('SELECT count(*) AS c FROM findings').get() as { c: number }).c)
  const postRuns = Number((upgraded.client.prepare('SELECT count(*) AS c FROM runs').get() as { c: number }).c)
  assert.equal(postFindings, preFindings, 'upgrade must preserve 100% of existing findings')
  assert.equal(postRuns, preRuns, 'upgrade must preserve 100% of existing runs')

  const integrity = upgraded.client.prepare('PRAGMA integrity_check').get() as { integrity_check: string }
  assert.equal(integrity.integrity_check, 'ok')

  // Every finding row has backfilled promoted columns matching its JSON payload.
  const mismatched = upgraded.client.prepare(`
    SELECT count(*) AS c FROM findings
    WHERE status <> coalesce(json_extract(finding, '$.status'), 'pending')
       OR origin <> trim(coalesce(json_extract(finding, '$.origin'), ''))
  `).get() as { c: number }
  assert.equal(Number(mismatched.c), 0, 'all existing findings must have aligned promoted columns after upgrade')
})
