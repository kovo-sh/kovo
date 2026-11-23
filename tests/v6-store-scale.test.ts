/**
 * Guardian v6 Phase 1 — store scale & data-integrity suite.
 *
 * Covers: WAL/NORMAL pragmas + VACUUM INTO snapshot compatibility, additive
 * `resource_samples.collection_path` migration and multi-collection integrity, bounded async
 * exchange batching (p99 main-thread stall), pagination without silent 500/2000 caps, idempotent
 * crash recovery, artifact sharding with a compatible read path, and flush-on-teardown.
 */
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'

import type { Candidate } from '../src/domain.ts'
import { captureRunSnapshot } from '../src/server/run-snapshot.ts'
import { STORE_SCHEMA_VERSION, Store, collectionPathFor } from '../src/server/store.ts'

const ORIGIN = 'https://scale.example'

interface Fixture {
  dir: string
  snapshotDir: string
  store: Store
  projectId: string
  runId: string
  workerId: string
  asset: Candidate
}

function makeStore(t: { after: (fn: () => void) => void }, label: string): Fixture {
  const dir = mkdtempSync(join(tmpdir(), `guardian-v6-${label}-`))
  const snapshotDir = join(dir, 'snapshot')
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  t.after(() => store.close())
  const { id: projectId } = store.createProject({
    requestId: randomUUID(), name: `v6 ${label}`, seeds: [ORIGIN], environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Exercise store scale limits.',
    sourceMode: 'public', capabilityTier: 2, budgetUsd: 5, budgetRequests: 5000,
    maxRpsPerOrigin: 50, workerConcurrency: 2, workerMaxTurns: 20,
  })
  const run = store.run(runId)
  const asset = run.candidates.find(candidate => candidate.origin === ORIGIN) ?? run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'Scale worker', 'Exercise the store.')
  return { dir, snapshotDir, store, projectId, runId, workerId: worker.id, asset }
}

function exchangeInput(runId: string, workerId: string, index: number, body = '{"ok":true}') {
  return {
    runId,
    assignmentId: workerId,
    scopeRevision: 1,
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: `/api/bulk/${index}?page=${index}`,
    personaHandle: 'persona_a',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: { accept: 'application/json' },
    respHeaders: { 'content-type': 'application/json' },
    body,
    durationMs: 3,
  }
}

test('v6 store enables WAL/NORMAL, a busy timeout and stamps the schema version', t => {
  const { store } = makeStore(t, 'pragmas')
  const journal = store.client.prepare('PRAGMA journal_mode').get() as { journal_mode: string }
  const synchronous = store.client.prepare('PRAGMA synchronous').get() as { synchronous: number }
  const busy = store.client.prepare('PRAGMA busy_timeout').get() as { timeout: number }
  const version = store.client.prepare('PRAGMA user_version').get() as { user_version: number }
  const foreignKeys = store.client.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number }
  assert.equal(String(journal.journal_mode).toLowerCase(), 'wal')
  assert.equal(Number(synchronous.synchronous), 1, 'synchronous=NORMAL')
  assert.equal(Number(busy.timeout), 5000)
  assert.equal(Number(version.user_version), STORE_SCHEMA_VERSION)
  assert.equal(Number(foreignKeys.foreign_keys), 1)
})

test('v6 resource_samples collection_path migrates additively and keeps /invoices /orders /tickets distinct', t => {
  const { dir, store, runId } = makeStore(t, 'resource-migration')
  store.recordResourceSample({
    runId, ownerPersona: 'persona_a', resourceKey: 'id', resourceId: 'inv_1001',
    origin: ORIGIN, endpoint: '/invoices', method: 'GET',
  })
  store.close()

  // Simulate a pre-v6 database: no collection_path column and the old 4-column unique index.
  const raw = new DatabaseSync(join(dir, 'guardian.sqlite'))
  raw.exec(`
    PRAGMA user_version = 0;
    DROP INDEX IF EXISTS resource_samples_key;
    DROP TABLE resource_samples;
    CREATE TABLE resource_samples (
      id TEXT PRIMARY KEY NOT NULL,
      run_id TEXT NOT NULL REFERENCES runs(id),
      owner_persona TEXT NOT NULL,
      resource_key TEXT NOT NULL,
      resource_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      media_type TEXT,
      authenticated INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX resource_samples_key ON resource_samples (run_id, owner_persona, resource_key, origin);
  `)
  raw.prepare(
    `INSERT INTO resource_samples (id, run_id, owner_persona, resource_key, resource_id, origin, endpoint, method, authenticated, created_at, updated_at)
     VALUES (?, ?, 'persona_a', 'id', 'legacy_1', ?, '/invoices', 'GET', 0, ?, ?)`,
  ).run(randomUUID(), runId, ORIGIN, Date.now(), Date.now())
  raw.close()

  const reopened = new Store(dir)
  t.after(() => reopened.close())
  const columns = new Set((reopened.client.prepare('PRAGMA table_info(resource_samples)').all() as Array<{ name: string }>)
    .map(row => row.name))
  assert.ok(columns.has('collection_path'))
  const indexColumns = (reopened.client.prepare('PRAGMA index_info(resource_samples_key)').all() as Array<{ name: string }>)
    .map(row => row.name)
  assert.deepEqual(indexColumns, ['run_id', 'owner_persona', 'origin', 'collection_path', 'resource_key'])
  const legacy = reopened.listResourceSamples(runId).find(row => row.resourceId === 'legacy_1')
  assert.equal(legacy?.collectionPath, '', 'legacy rows backfill to an empty collection path')
  assert.equal((reopened.client.prepare('PRAGMA user_version').get() as { user_version: number }).user_version, STORE_SCHEMA_VERSION)

  for (const [endpoint, id] of [['/invoices', 'inv_2002'], ['/orders', 'ord_3003'], ['/tickets', 'tkt_4004']] as const) {
    reopened.recordResourceSample({
      runId, ownerPersona: 'persona_a', resourceKey: 'id', resourceId: id,
      origin: ORIGIN, endpoint, method: 'GET',
    })
  }
  const rows = reopened.listResourceSamples(runId)
  const ids = new Set(rows.map(row => row.resourceId))
  for (const expected of ['legacy_1', 'inv_2002', 'ord_3003', 'tkt_4004']) assert.ok(ids.has(expected), expected)
  const byCollection = new Map(rows.map(row => [row.collectionPath, row.resourceId]))
  assert.equal(byCollection.get('/invoices'), 'inv_2002')
  assert.equal(byCollection.get('/orders'), 'ord_3003')
  assert.equal(byCollection.get('/tickets'), 'tkt_4004')
  assert.equal(collectionPathFor('/invoices/9001'), '/invoices')
  assert.equal(collectionPathFor('/api/orders/00000000-0000-4000-8000-000000000000'), '/api/orders')
})

test('v6 2,500-endpoint run has no truncation and paginates runDetail/listEndpoints stably', t => {
  const { store, runId } = makeStore(t, 'endpoints-2500')
  const total = 2500
  store.transaction(() => {
    for (let i = 0; i < total; i += 1) {
      store.upsertEndpoint({
        runId,
        origin: ORIGIN,
        method: i % 3 === 0 ? 'POST' : 'GET',
        pathTemplate: `/api/v6/resources/${i}/:id`,
        source: 'spa_crawl',
        riskScore: i % 100,
      })
    }
  })

  assert.equal(store.listEndpoints(runId, { limit: total }).length, total, 'explicit limit above 2,000 is honored')

  const firstPage = store.listEndpoints(runId, { limit: 1000, offset: 0 })
  const secondPage = store.listEndpoints(runId, { limit: 1000, offset: 1000 })
  const finalPage = store.listEndpoints(runId, { limit: 1000, offset: 2000 })
  assert.equal(firstPage.length, 1000)
  assert.equal(secondPage.length, 1000)
  assert.equal(finalPage.length, 500)
  const ids = new Set([...firstPage, ...secondPage, ...finalPage].map(endpoint => endpoint.id))
  assert.equal(ids.size, total, 'offset pagination is stable and lossless')

  const repeat = store.listEndpoints(runId, { limit: 5, offset: 0 }).map(endpoint => endpoint.id)
  assert.deepEqual(repeat, firstPage.slice(0, 5).map(endpoint => endpoint.id), 'ordering is deterministic')

  const detail = store.runDetail(runId, { endpoints: { limit: 1000, offset: 0 } })
  assert.equal(detail.endpoints.length, 1000)
  assert.equal(detail.paging?.totals?.endpoints, total)
  const detailTail = store.runDetail(runId, { endpoints: { limit: 1000, offset: 2000 } })
  assert.equal(detailTail.endpoints.length, 500)
  assert.equal(detailTail.paging?.totals?.endpoints, total)
})

test('v6 exchange batching keeps p99 main-thread stall well below 50 ms and loses no rows', t => {
  const { store, runId, workerId } = makeStore(t, 'batching')
  const calls = 500
  const samples: number[] = []
  for (let i = 0; i < calls; i += 1) {
    const started = performance.now()
    store.recordExchange(exchangeInput(runId, workerId, i))
    samples.push(performance.now() - started)
  }
  const sorted = [...samples].sort((a, b) => a - b)
  const p99 = sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.99) - 1)]!
  const max = sorted[sorted.length - 1]!
  // Visible only after an explicit read-after-write boundary.
  store.flushNow()
  const persisted = store.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE run_id = ?').get(runId) as { c: number }
  assert.equal(Number(persisted.c), calls)
  const spent = store.run(runId).spentRequests
  assert.equal(spent, calls, 'run request counter increments once per exchange')
  const detail = store.runDetail(runId, { exchanges: { limit: 100, offset: 0 } })
  assert.equal(detail.exchangesSummary.length, 100)
  assert.equal(detail.paging?.totals?.exchanges, calls)
  assert.ok(p99 < 50, `p99 batched write stall ${p99.toFixed(2)} ms must be < 50 ms`)
  assert.ok(max < 250, `worst batched write stall ${max.toFixed(2)} ms must stay bounded`)
  t.diagnostic(`batched exchange writes: p99=${p99.toFixed(2)}ms max=${max.toFixed(2)}ms (${calls} writes)`)
})

test('v6 batched exchanges flush on teardown (close without an explicit flush)', t => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v6-teardown-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  const { id: projectId } = store.createProject({
    requestId: randomUUID(), name: 'teardown', seeds: [ORIGIN], environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Flush on teardown.', sourceMode: 'public',
    capabilityTier: 1, budgetUsd: 1, budgetRequests: 50, maxRpsPerOrigin: 10,
    workerConcurrency: 1, workerMaxTurns: 5,
  })
  const run = store.run(runId)
  const worker = store.makeWorker(run, 'investigation', run.candidates[0], 'Teardown worker', 'Flush.')
  store.recordExchange(exchangeInput(runId, worker.id, 1))
  store.close()

  const raw = new DatabaseSync(join(dir, 'guardian.sqlite'), { readOnly: true })
  try {
    const count = raw.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE run_id = ?').get(runId) as { c: number }
    assert.equal(Number(count.c), 1)
  } finally {
    raw.close()
  }
})

test('v6 recover pauses runs, resets board/assignments, expires approvals and reclaims containers idempotently', t => {
  const { store, runId, workerId, asset } = makeStore(t, 'recover')
  const run = store.run(runId)
  const failedWorker = store.makeWorker(run, 'verification', asset, 'Permanently failed', 'Fail once.')
  store.updateWorker(failedWorker.id, { status: 'failed', attempt: 3, outcome: 'exhausted retries' })
  const approvalWorker = store.makeWorker(run, 'verification', asset, 'Needs approval', 'Wait for a lease.')
  store.updateWorker(workerId, { status: 'running', lease: randomUUID(), leaseExpiresAt: Date.now() + 60_000 })
  store.updateBoardMemberState(runId, 'coordinator', { state: 'working', activeAssignmentId: workerId })
  const approval = store.createApprovalRequest(run, approvalWorker, {
    origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders',
    rationale: 'State-changing probe', requestPreview: '{"id":1}', expiresInMs: -1_000,
  })
  store.recordLabContainer({ runId, assignmentId: workerId, containerName: 'guardian-lab-live', imageName: 'lab:1' })
  store.recordLabContainer({ runId, containerName: 'guardian-lab-orphan', status: 'orphaned' })

  // Simulate a process killed mid-run (createRun leaves the run in its pre-execution phase).
  store.updateRun(runId, { status: 'running' })
  const report = store.recover()
  assert.equal(report.pausedRuns, 1)
  assert.ok(report.requeuedAssignments >= 2, 'running + waiting_approval assignments are re-queued')
  assert.equal(report.resetBoardMembers, 1)
  assert.equal(report.expiredApprovals, 1)
  assert.equal(report.reclaimedContainers.length, 2)
  assert.equal(report.changed, true)

  assert.equal(store.run(runId).status, 'paused')
  assert.equal(store.worker(workerId).status, 'queued')
  assert.equal(store.worker(approvalWorker.id).status, 'queued')
  assert.equal(store.worker(failedWorker.id).status, 'failed', 'permanently failed assignments are never re-queued')
  assert.equal(store.boardMember(runId, 'coordinator')?.state, 'waiting')
  assert.equal(store.boardMember(runId, 'coordinator')?.activeAssignmentId, null)
  assert.equal(store.getApprovalRequest(runId, approval.id).status, 'expired')
  assert.equal(store.listLabContainers(runId).length, 0)
  const recoveryNotes = () => Number((store.client.prepare(
    "SELECT count(*) AS c FROM events WHERE kind = 'recovery.completed'",
  ).get() as { c: number }).c)
  assert.ok(recoveryNotes() >= 1, 'recovery emits a workspace-level recovery note')

  const eventsBefore = recoveryNotes()
  const second = store.recover()
  assert.equal(second.changed, false)
  assert.equal(second.pausedRuns, 0)
  assert.equal(second.requeuedAssignments, 0)
  assert.equal(second.expiredApprovals, 0)
  assert.equal(second.reclaimedContainers.length, 0)
  assert.equal(recoveryNotes(), eventsBefore, 'second recovery emits no duplicate notes')
})

test('v6 artifact writes shard under artifacts/<runId>/<bucket>/ and keep the legacy read path', t => {
  const { dir, store, runId, workerId } = makeStore(t, 'artifacts')
  const handoff = store.client.prepare(
    "SELECT id FROM evidence WHERE run_id = ? AND kind = 'handoff' LIMIT 1",
  ).get(runId) as { id: string }
  assert.ok(handoff?.id)
  const read = store.artifact(runId, handoff.id)
  assert.ok(read.content.includes('Exercise the store.'))
  assert.ok(!existsSync(join(dir, 'artifacts', `${handoff.id}.txt`)), 'new artifacts are not written flat')
  const runDir = join(dir, 'artifacts', runId)
  const expectedBucket = createHash('sha256').update(handoff.id).digest('hex').slice(0, 2)
  assert.ok(existsSync(join(runDir, expectedBucket, `${handoff.id}.txt`)), 'artifact is sharded by bucket')

  // Compatible read: a pre-v6 flat artifact still resolves through Store.artifact().
  const legacyId = randomUUID()
  store.client.prepare(
    `INSERT INTO evidence (id, run_id, assignment_id, scope_revision, goal_revision, title, kind, created_at)
     VALUES (?, ?, ?, 1, 1, 'Legacy observation', 'observation', ?)`,
  ).run(legacyId, runId, workerId, Date.now())
  writeFileSync(join(dir, 'artifacts', `${legacyId}.txt`), '{"legacy":true}', { mode: 0o600 })
  assert.equal(store.artifact(runId, legacyId).content, '{"legacy":true}')

  // Exchange bodies use the sharded blob group and still round-trip via getExchange().
  const saved = store.recordExchange({ ...exchangeInput(runId, workerId, 7, '{"body":"sharded"}') })
  assert.equal(store.getExchange(runId, saved.id).body, '{"body":"sharded"}')
  const blobBuckets = readdirSync(join(runDir, 'blobs'))
  assert.ok(blobBuckets.length > 0)
})

test('v6 captureRunSnapshot flushes batched exchanges before VACUUM INTO under WAL', t => {
  const { store, runId, projectId, snapshotDir } = makeStore(t, 'snapshot')
  store.recordExchange(exchangeInput(runId, store.makeWorker(store.run(runId), 'investigation', store.run(runId).candidates[0], 'Snap', 'Snap.').id, 1))
  const result = captureRunSnapshot({
    storage: store,
    snapshotDir,
    checkpoint: 'manual',
    target: {
      app: 'v6-scale', seed: 42, seedSet: 'dev', mode: 'scan', origin: ORIGIN,
      loginPath: '/login', canaryBaseUrls: [], projectId, runId,
    },
    gitSha: 'test-sha',
  })
  assert.ok(existsSync(result.databasePath))
  assert.equal(result.counts.brokerExchanges, 1, 'pending exchanges are flushed before VACUUM INTO')
  const copy = new DatabaseSync(result.databasePath, { readOnly: true })
  try {
    const count = copy.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE run_id = ?').get(runId) as { c: number }
    assert.equal(Number(count.c), 1)
    const version = copy.prepare('PRAGMA user_version').get() as { user_version: number }
    assert.equal(Number(version.user_version), STORE_SCHEMA_VERSION)
  } finally {
    copy.close()
  }
})
