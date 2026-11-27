/**
 * Kovo v6.2 — bounded opt-in FTS + exchange retention GC + footprint guard.
 *
 * Covers: `ftsMode: 'off' | 'preview' | 'full'` write/search semantics with a hard per-exchange
 * body cap; `pruneExchanges()` deleting rows + FTS rows + unreferenced sharded blobs in bounded
 * batches for one run/age window; `keepLatest`; `Store.prune({ retentionDays })` per-run retention;
 * `storeFootprint()` reporting; the `full` mode DB size guard; snapshot capture after pruning; and
 * an orphan-free artifacts directory.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'

import type { Candidate } from '../src/domain.ts'
import { captureRunSnapshot } from '../src/server/run-snapshot.ts'
import {
  FtsModeRefusedError,
  Store,
} from '../src/server/store.ts'
import type { StoreOptions } from '../src/server/store.ts'

const ORIGIN = 'https://fts.example'
const HOUR_MS = 60 * 60_000

interface Fixture {
  dir: string
  store: Store
  projectId: string
  runId: string
  workerId: string
  asset: Candidate
}

function makeStore(t: { after: (fn: () => void) => void }, label: string, options?: StoreOptions): Fixture {
  const dir = mkdtempSync(join(tmpdir(), `kovo-v6-fts-${label}-`))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir, options)
  t.after(() => store.close())
  const { id: projectId } = store.createProject({
    requestId: randomUUID(), name: `v6 fts ${label}`, seeds: [ORIGIN], environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Exercise FTS retention.',
    sourceMode: 'public', capabilityTier: 2, budgetUsd: 5, budgetRequests: 5000,
    maxRpsPerOrigin: 50, workerConcurrency: 2, workerMaxTurns: 20,
  })
  const run = store.run(runId)
  const asset = run.candidates.find(candidate => candidate.origin === ORIGIN) ?? run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'FTS worker', 'Exercise retention.')
  return { dir, store, projectId, runId, workerId: worker.id, asset }
}

function createRun(store: Store, projectId: string, goal: string): { runId: string; workerId: string } {
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal, sourceMode: 'public', capabilityTier: 1,
    budgetUsd: 1, budgetRequests: 500, maxRpsPerOrigin: 10, workerConcurrency: 1, workerMaxTurns: 10,
  })
  const run = store.run(runId)
  const worker = store.makeWorker(run, 'investigation', run.candidates[0], 'FTS worker 2', 'Exercise retention.')
  return { runId, workerId: worker.id }
}

let exchangeSeq = 0
function exchangeInput(runId: string, workerId: string, body: string, path?: string) {
  exchangeSeq += 1
  return {
    runId,
    assignmentId: workerId,
    scopeRevision: 1,
    origin: ORIGIN,
    finalOrigin: ORIGIN,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: path ?? `/api/fts/${exchangeSeq}`,
    personaHandle: 'persona_a',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: { accept: 'application/json' },
    respHeaders: { 'content-type': 'application/json' },
    body,
    durationMs: 2,
  }
}

/** Pad `token` beyond the preview window but within the full-body window. */
function paddedBody(token: string, offset: number, extra = ''): string {
  const head = `${token} `
  return `${head}${'x'.repeat(Math.max(0, offset - head.length))}${extra}`
}

function ftsRowCount(store: Store): number {
  return Number((store.client.prepare('SELECT count(*) AS c FROM broker_exchanges_fts').get() as { c: number }).c)
}

function ftsBodyLength(store: Store, exchangeId: string): number {
  const row = store.client.prepare(
    'SELECT body_preview AS body FROM broker_exchanges_fts WHERE exchange_id = ?',
  ).get(exchangeId) as { body?: string } | undefined
  return row?.body?.length ?? 0
}

function foundIds(store: Store, runId: string, query: string): Set<string> {
  return new Set(store.searchExchanges(runId, query).map(exchange => exchange.id))
}

function backdate(store: Store, exchangeIds: readonly string[], createdAt: number): void {
  store.flushNow()
  const update = store.client.prepare('UPDATE broker_exchanges SET created_at = ? WHERE id = ?')
  for (const id of exchangeIds) update.run(createdAt, id)
}

function retentionEvents(store: Store, runId?: string): Array<{ kind: string; detail: Record<string, unknown> }> {
  const rows = runId
    ? store.client.prepare("SELECT kind, detail FROM events WHERE kind = 'retention.pruned' AND run_id = ?").all(runId)
    : store.client.prepare("SELECT kind, detail FROM events WHERE kind = 'retention.pruned'").all()
  return (rows as Array<{ kind: string; detail: string }>).map(row => ({
    kind: row.kind, detail: JSON.parse(row.detail) as Record<string, unknown>,
  }))
}

function insertFinding(store: Store, runId: string, assetId: string): string {
  const id = randomUUID()
  const run = store.run(runId)
  store.client.prepare(
    `INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, source_origins, finding)
     VALUES (?, ?, ?, ?, 'hsts', 'retention-case', 'baseline_check', ?, ?)`,
  ).run(id, runId, assetId, run.goalRevision, JSON.stringify([ORIGIN]), JSON.stringify({
    id, origin: ORIGIN, title: 'Retention keeps findings', status: 'static_verified', severity: 'low',
    reason: 'Store-only fixture.', remediation: 'None.', evidenceIds: [], scopeRevision: run.scopeRevision,
  }))
  return id
}

function blobFiles(dir: string, runId: string): string[] {
  const root = join(dir, 'artifacts', runId, 'blobs')
  const out: string[] = []
  let buckets: string[]
  try { buckets = readdirSync(root) } catch { return out }
  for (const bucket of buckets) {
    for (const name of readdirSync(join(root, bucket))) out.push(join(root, bucket, name))
  }
  return out
}

test('v6 fts mode off writes no FTS rows and search falls back to LIKE', t => {
  const { store, runId, workerId } = makeStore(t, 'off', { ftsMode: 'off' })
  store.recordExchange(exchangeInput(runId, workerId, '{"marker":"offmodemarker"}'))
  store.flushNow()
  const footprint = store.storeFootprint()
  assert.equal(footprint.ftsMode, 'off')
  assert.equal(footprint.ftsRows, 0)
  assert.equal(footprint.exchangeRows, 1)
  const hits = store.searchExchanges(runId, 'offmodemarker')
  assert.equal(hits.length, 1, 'LIKE fallback still searches the stored preview')
  const settings = store.client.prepare("SELECT value FROM store_settings WHERE key = 'fts_mode'").get() as { value: string }
  assert.equal(settings.value, 'off', 'the active mode is recorded durably')
})

test('v6 fts preview indexes the bounded preview only (default mode)', t => {
  const { store, runId, workerId } = makeStore(t, 'preview')
  assert.equal(store.ftsMode, 'preview')
  const body = paddedBody('alphamarker', 40) + `${'y'.repeat(9_000)} omegamarker`
  store.recordExchange(exchangeInput(runId, workerId, body))
  store.flushNow()
  assert.equal(ftsRowCount(store), 1)
  assert.equal((store.client.prepare('SELECT length(body_preview) AS l FROM broker_exchanges').get() as { l: number }).l, 8_192)
  assert.ok(foundIds(store, runId, 'alphamarker').size === 1, 'preview body is searchable')
  assert.equal(foundIds(store, runId, 'omegamarker').size, 0, 'text beyond the preview window is not indexed')
  assert.ok(ftsBodyLength(store, (store.client.prepare('SELECT id FROM broker_exchanges').get() as { id: string }).id) <= 8_192)
})

test('v6 fts full indexes more of the body but never beyond the configured cap', t => {
  const { store, runId, workerId } = makeStore(t, 'full-cap', { ftsMode: 'full', ftsMaxBodyBytes: 16_384 })
  const body = paddedBody('alphamarker', 40) + `${'y'.repeat(12_000)} omegamarker ${'z'.repeat(20_000)} lateboundary`
  const saved = store.recordExchange(exchangeInput(runId, workerId, body))
  store.flushNow()
  assert.equal(store.ftsMode, 'full')
  assert.equal(ftsRowCount(store), 1)
  assert.equal(foundIds(store, runId, 'alphamarker').size, 1)
  assert.equal(foundIds(store, runId, 'omegamarker').size, 1, 'full mode indexes past the 8 KiB preview')
  assert.equal(foundIds(store, runId, 'lateboundary').size, 0, 'the 16 KiB cap bounds the FTS body')
  assert.ok(ftsBodyLength(store, saved.id) <= 16_384)
  assert.ok(existsSync(join(store.directory, 'artifacts', runId)), 'full body blob still stored once')
})

test('v6 fts full mode is refused above the DB size cap unless forced', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-fts-guard-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const seed = new Store(dir)
  const { id: projectId } = seed.createProject({
    requestId: randomUUID(), name: 'guard', seeds: [ORIGIN], environment: 'public',
  })
  seed.close()
  const dbBytes = statSync(join(dir, 'kovo.sqlite')).size
  assert.ok(dbBytes > 0)
  const refusedDir = dir
  assert.throws(
    () => new Store(refusedDir, { ftsMode: 'full', maxFullFtsDbBytes: Math.max(1, Math.floor(dbBytes / 4)) }),
    (error: unknown) => {
      assert.ok(error instanceof FtsModeRefusedError)
      assert.equal(error.code, 'FTS_FULL_REFUSED')
      assert.ok(error.dbBytes >= dbBytes)
      return true
    },
  )
  // The refused open released the process lock, so a correctly configured reopen works.
  const forced = new Store(dir, { ftsMode: 'full', forceFullFts: true })
  t.after(() => forced.close())
  assert.equal(forced.ftsMode, 'full')
  assert.equal(forced.storeFootprint().maxFullFtsDbBytes > 0, true)
  assert.ok(projectId)
})

test('v6 pruneExchanges removes rows, FTS rows and blobs only for the targeted run and age', t => {
  const { dir, store, projectId, runId, workerId } = makeStore(t, 'prune-scope')
  const other = createRun(store, projectId, 'Keep this run intact.')
  const old = [
    store.recordExchange(exchangeInput(runId, workerId, '{"id":"old-one"}', '/api/old/1')),
    store.recordExchange(exchangeInput(runId, workerId, '{"id":"old-two"}', '/api/old/2')),
  ]
  const keep = store.recordExchange(exchangeInput(runId, workerId, '{"id":"new-one"}', '/api/new/1'))
  const otherOld = store.recordExchange(
    exchangeInput(other.runId, other.workerId, '{"id":"other-old"}', '/api/old/other'),
  )
  backdate(store, [old[0]!.id, old[1]!.id, otherOld.id], Date.now() - 2 * HOUR_MS)

  const run = store.run(runId)
  const fact = store.addFact(run, store.worker(workerId), {
    kind: 'auth', origin: ORIGIN, summary: 'Retention must keep facts.', data: { path: '/api/new/1' },
    exchangeIds: [keep.id],
  })
  const findingId = insertFinding(store, runId, run.candidates[0]?.id ?? 'asset-retention')

  const result = store.pruneExchanges({ runId, olderThanMs: HOUR_MS, batchSize: 1 })
  assert.equal(result.exchanges, 2)
  assert.equal(result.ftsRows, 2)
  assert.equal(result.blobs, 2)
  assert.ok(result.blobBytes > 0)
  assert.equal(result.batches, 2, 'bounded batches of 1 commit once per row')
  assert.equal(result.keepLatest, 0)
  assert.ok(result.cutoff !== null)

  const remaining = store.client.prepare(
    'SELECT id FROM broker_exchanges WHERE run_id = ? ORDER BY created_at DESC',
  ).all(runId) as Array<{ id: string }>
  assert.deepEqual(remaining.map(row => row.id), [keep.id])
  for (const pruned of old) {
    assert.equal((store.client.prepare(
      'SELECT count(*) AS c FROM broker_exchanges_fts WHERE exchange_id = ?',
    ).get(pruned.id) as { c: number }).c, 0, 'FTS row is deleted with the exchange')
  }
  assert.equal(ftsRowCount(store), 2, 'kept exchange + other run stay indexed')
  assert.equal(blobFiles(dir, runId).length, 1, 'only the kept exchange blob remains')
  assert.equal(blobFiles(dir, other.runId).length, 1, 'the other run blob is untouched')
  void otherOld

  const detail = store.runDetail(runId, { exchanges: { limit: 10, offset: 0 } })
  assert.equal(detail.paging?.totals?.exchanges, 1)
  assert.equal(detail.exchangesSummary.length, 1)
  assert.equal(detail.facts.filter(item => item.id === fact.id).length, 1, 'facts survive pruning')
  assert.deepEqual(detail.findings.map(item => item.id), [findingId], 'findings survive pruning')

  const notes = retentionEvents(store, runId)
  assert.equal(notes.length, 1, 'one structured retention.pruned note')
  assert.equal(notes[0]!.detail.exchanges, 2)
  assert.equal(notes[0]!.detail.ftsRows, 2)
  assert.equal(notes[0]!.detail.blobs, 2)
})

test('v6 pruneExchanges honours keepLatest regardless of age', t => {
  const { store, runId, workerId } = makeStore(t, 'keep-latest')
  const saved: string[] = []
  for (let i = 0; i < 10; i += 1) {
    saved.push(store.recordExchange(exchangeInput(runId, workerId, `{"i":${i}}`)).id)
  }
  backdate(store, saved, Date.now() - 30 * HOUR_MS)
  const result = store.pruneExchanges({ runId, olderThanMs: HOUR_MS, keepLatest: 4 })
  assert.equal(result.exchanges, 6)
  const remaining = (store.client.prepare(
    'SELECT id FROM broker_exchanges WHERE run_id = ? ORDER BY rowid ASC',
  ).all(runId) as Array<{ id: string }>).map(row => row.id)
  assert.deepEqual(remaining, saved.slice(6), 'the newest four exchanges are preserved')
  assert.equal(store.storeFootprint().ftsRows, 4)
})

test('v6 pruneExchanges refuses an unbounded delete without a keepLatest floor', t => {
  const { store, runId, workerId } = makeStore(t, 'unbounded')
  store.recordExchange(exchangeInput(runId, workerId, '{"safe":true}'))
  const result = store.pruneExchanges({ runId })
  assert.equal(result.exchanges, 0)
  assert.equal(store.storeFootprint().exchangeRows, 1)
})

test('v6 store.prune applies per-run retentionDays and emits aggregated counts', t => {
  const { store, projectId, runId, workerId } = makeStore(t, 'retention')
  const second = createRun(store, projectId, 'Second retained run.')
  store.updateRun(runId, { status: 'complete' })
  store.updateRun(second.runId, { status: 'complete' })
  const oldA = store.recordExchange(exchangeInput(runId, workerId, '{"run":"a","age":"old"}'))
  const newA = store.recordExchange(exchangeInput(runId, workerId, '{"run":"a","age":"new"}'))
  const oldB = store.recordExchange(exchangeInput(second.runId, second.workerId, '{"run":"b","age":"old"}'))
  const newB = store.recordExchange(exchangeInput(second.runId, second.workerId, '{"run":"b","age":"new"}'))
  backdate(store, [oldA.id, oldB.id], Date.now() - 20 * 24 * HOUR_MS)

  const noop = store.prune({ retentionDays: 0 })
  assert.equal(noop.exchanges, 0)
  assert.equal(retentionEvents(store).length, 0, 'disabled retention writes no note')

  const result = store.prune({ retentionDays: 14, batchSize: 250 })
  assert.equal(result.runs, 2)
  assert.equal(result.exchanges, 2)
  assert.equal(result.ftsRows, 2)
  assert.equal(result.retentionDays, 14)
  assert.equal(result.keepLatest, 0)
  assert.equal(result.perRun.length, 2)
  assert.deepEqual(
    (store.client.prepare('SELECT id FROM broker_exchanges ORDER BY id').all() as Array<{ id: string }>)
      .map(row => row.id).sort(),
    [newA.id, newB.id].sort(),
  )
  const notes = retentionEvents(store)
  assert.equal(notes.length, 1)
  assert.equal(notes[0]!.detail.exchanges, 2)
  assert.equal(notes[0]!.detail.runs, 2)
  assert.equal(notes[0]!.detail.retentionDays, 14)
  assert.equal(Array.isArray(notes[0]!.detail.perRun), true)
  assert.equal((notes[0]!.detail.perRun as unknown[]).length, 2)
})

test('v6 store.prune skips actively running runs unless asked to include them', t => {
  const { store, projectId, runId, workerId } = makeStore(t, 'active')
  const idle = createRun(store, projectId, 'Idle run.')
  store.updateRun(idle.runId, { status: 'complete' })
  const active = store.recordExchange(exchangeInput(runId, workerId, '{"active":true}'))
  const idleOld = store.recordExchange(exchangeInput(idle.runId, idle.workerId, '{"idle":true}'))
  backdate(store, [active.id, idleOld.id], Date.now() - 20 * 24 * HOUR_MS)
  store.updateRun(runId, { status: 'running' })
  const skipped = store.prune({ retentionDays: 14 })
  assert.equal(skipped.runs, 1)
  assert.equal(skipped.exchanges, 1)
  assert.equal((store.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE id = ?').get(active.id) as { c: number }).c, 1)
  const forced = store.prune({ retentionDays: 14, skipActiveRuns: false })
  assert.equal(forced.exchanges, 1)
})

test('v6 storeFootprint reports db/blob bytes and FTS rows before and after pruning', t => {
  const { store, runId, workerId } = makeStore(t, 'footprint')
  const before = store.storeFootprint()
  assert.ok(before.mainDbBytes > 0)
  assert.ok(before.dbBytes >= before.mainDbBytes)
  assert.equal(before.exchangeRows, 0)
  assert.equal(before.ftsRows, 0)
  assert.equal(before.ftsMode, 'preview')
  assert.equal(before.ftsMaxBodyBytes, 8 * 1024)

  const saved = store.recordExchange(exchangeInput(runId, workerId, `{"payload":"${'p'.repeat(4_000)}"}`))
  backdate(store, [saved.id], Date.now() - 60_000)
  const mid = store.storeFootprint()
  assert.equal(mid.exchangeRows, 1)
  assert.equal(mid.ftsRows, 1)
  assert.ok(mid.blobBytes >= 4_000)
  assert.ok(mid.artifactBytes >= mid.blobBytes)

  store.pruneExchanges({ runId, olderThanMs: 1_000 })
  const after = store.storeFootprint()
  assert.equal(after.exchangeRows, 0)
  assert.equal(after.ftsRows, 0)
  assert.equal(after.blobBytes, 0)
  assert.equal(after.artifactBytes < mid.artifactBytes, true)
  void saved.id
})

test('v6 pruning leaves no orphan blob files under the run artifacts dir', t => {
  const { dir, store, runId, workerId } = makeStore(t, 'orphans')
  const ids: string[] = []
  for (let i = 0; i < 5; i += 1) {
    ids.push(store.recordExchange(exchangeInput(runId, workerId, `{"unique":"body-${i}-${randomUUID()}"}`)).id)
  }
  backdate(store, ids, Date.now() - 60_000)
  assert.equal(blobFiles(dir, runId).length, 5)
  const result = store.pruneExchanges({ runId, olderThanMs: 1_000 })
  assert.equal(result.exchanges, 5)
  assert.equal(result.blobs, 5)
  assert.deepEqual(blobFiles(dir, runId), [])
  assert.equal(existsSync(join(dir, 'artifacts')), true, 'the artifacts root survives')
})

test('v6 captureRunSnapshot after pruning is consistent and keeps FTS rows', t => {
  const { dir, store, runId, workerId } = makeStore(t, 'snapshot-after-prune')
  const old = store.recordExchange(exchangeInput(runId, workerId, '{"marker":"snapshotold"}'))
  const keep = store.recordExchange(exchangeInput(runId, workerId, '{"marker":"snapshotkeep"}'))
  backdate(store, [old.id], Date.now() - 3 * 24 * HOUR_MS)
  store.pruneExchanges({ runId, olderThanMs: 24 * HOUR_MS })

  const snapshotDir = join(dir, 'snap')
  const result = captureRunSnapshot({
    storage: store,
    snapshotDir,
    checkpoint: 'manual',
    target: {
      app: 'v6-fts', seed: 42, seedSet: 'dev', mode: 'scan', origin: ORIGIN, loginPath: '/login',
      canaryBaseUrls: [], projectId: store.run(runId).projectId, runId,
    },
    gitSha: 'test-sha',
  })
  assert.equal(result.counts.brokerExchanges, 1)
  const copy = new DatabaseSync(result.databasePath, { readOnly: true })
  try {
    const exchanges = copy.prepare('SELECT id FROM broker_exchanges WHERE run_id = ?').all(runId) as Array<{ id: string }>
    assert.deepEqual(exchanges.map(row => row.id), [keep.id])
    const fts = copy.prepare('SELECT exchange_id FROM broker_exchanges_fts WHERE run_id = ?').all(runId) as Array<{ exchange_id: string }>
    assert.deepEqual(fts.map(row => row.exchange_id), [keep.id])
    const integrity = copy.prepare('PRAGMA integrity_check').get() as { integrity_check: string }
    assert.equal(integrity.integrity_check, 'ok')
  } finally {
    copy.close()
  }
})
