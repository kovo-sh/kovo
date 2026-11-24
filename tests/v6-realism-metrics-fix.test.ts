/**
 * Realism metrics + micro-slice snapshot contract.
 *
 * Two high-signal fixes are pinned here:
 *
 *   1. `latePromotions` must count the conversions the engine actually reported
 *      (`oob.receipt_confirmed` / drain `promotedReceipts`), not only relay promotions seen by the
 *      bounded drain. Realism #2 converts late callbacks before the drain starts, so the old
 *      drain-only counter reported 0 while the finding count was 2.
 *   2. The Tier-1 monorepo micro-slice reports its post-recon snapshot state honestly: consumed
 *      when the harness supports resume, otherwise an explicit unsupported/cold fallback with a
 *      bounded longer timeout instead of a silent 180 s wall.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, describe, test } from 'node:test'

import {
  collectWiringMetrics,
  countReceiptPromotions,
  resolveLatePromotions,
} from '../scripts/benchmark-realism.ts'
import {
  DEFAULT_MICRO_RECON_TIMEOUT_SEC,
  formatSnapshotStatus,
  parseSmokeArgs,
  planMicroSlices,
  realismReconSnapshotDir,
  renderCompactTable,
  resolveMicroSlice,
  type CellMetrics,
  type MicroSnapshotStatus,
} from '../scripts/smoke-agentic.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:9'
const tempRoot = mkdtempSync(join(tmpdir(), 'guardian-realism-metrics-fix-'))
after(() => rmSync(tempRoot, { recursive: true, force: true }))

/** Minimal `pending_oob` relay shape read by the harness. */
function writeOobRelay(dataDir: string, rows: Array<{
  status: string
  createdAt: number
  promotedAt: number | null
  immediateMs: number
  runId: string
}>): void {
  mkdirSync(dataDir, { recursive: true })
  const db = new DatabaseSync(join(dataDir, 'oob-relay.sqlite'))
  db.exec(`
    create table pending_oob (
      run_id text not null,
      status text not null,
      created_at integer not null,
      promoted_at integer,
      immediate_ms integer not null
    );
  `)
  const insert = db.prepare(
    'insert into pending_oob (run_id, status, created_at, promoted_at, immediate_ms) values (?, ?, ?, ?, ?)',
  )
  for (const row of rows) insert.run(row.runId, row.status, row.createdAt, row.promotedAt, row.immediateMs)
  db.close()
}

describe('latePromotions counts conversion events, not just the drain counter', () => {
  test('two receipts + a zero drain counter report two promotions', () => {
    assert.equal(resolveLatePromotions({
      drainPromotedLate: 0,
      drainPromotedReceipts: 0,
      receiptConfirmed: 2,
    }), 2)
  })

  test('pre-drain receipts are counted even when the drain never ran', () => {
    assert.equal(resolveLatePromotions({
      drainPromotedLate: null,
      drainPromotedReceipts: null,
      receiptConfirmed: 2,
    }), 2)
  })

  test('drain-promoted receipts are a second conversion source', () => {
    assert.equal(resolveLatePromotions({
      drainPromotedLate: 3,
      drainPromotedReceipts: 3,
      receiptConfirmed: 0,
    }), 3)
  })

  test('legacy drain counter remains the fallback when no receipt evidence exists', () => {
    assert.equal(resolveLatePromotions({
      drainPromotedLate: 4,
      drainPromotedReceipts: null,
      receiptConfirmed: null,
    }), 4)
  })

  test('measured zero stays zero; fully unmeasured stays null (fail closed)', () => {
    assert.equal(resolveLatePromotions({
      drainPromotedLate: 0,
      drainPromotedReceipts: 0,
      receiptConfirmed: 0,
    }), 0)
    assert.equal(resolveLatePromotions({
      drainPromotedLate: null,
      drainPromotedReceipts: null,
      receiptConfirmed: null,
    }), null)
  })

  test('receipt events are deduplicated by subscription id', () => {
    const events = [
      { kind: 'oob.receipt_confirmed', detail: { oobSubscriptionId: 'sub-1' } },
      { kind: 'oob.receipt_confirmed', detail: { oobSubscriptionId: 'sub-1' } },
      { kind: 'oob.receipt_confirmed', detail: { oobSubscriptionId: 'sub-2' } },
      { kind: 'oob.receipt_confirmed', detail: {} },
      { kind: 'oob.drain_complete', detail: { promotedLate: 0 } },
    ]
    assert.equal(countReceiptPromotions(events), 3)
    assert.equal(countReceiptPromotions(null), null)
  })
})

describe('collectWiringMetrics fixture: 2 receipts + 4 matched callbacks', () => {
  test('latePromotions matches conversions while lateCallbacksMatched keeps the callback count', async () => {
    const { Store } = await import('../src/server/store.ts')
    const root = join(tempRoot, 'wiring')
    const dataDir = join(root, 'data')
    mkdirSync(dataDir, { recursive: true })
    const storage = new Store(dataDir)
    try {
      const setup = await setupApprovedRun(storage, {
        environment: 'local-lab',
        seeds: [ORIGIN],
        tier: 0,
        budgetRequests: 100,
      })
      const runId = setup.runId
      // The four promoted callbacks the relay matched after the immediate window.
      writeOobRelay(dataDir, [1, 2, 3, 4].map(index => ({
        runId,
        status: 'promoted',
        createdAt: 1_000 + index,
        promotedAt: 30_000 + index,
        immediateMs: 5_000,
      })))
      // Two of them were converted into findings by ProofReceipt before the drain started.
      storage.event(runId, 'oob.receipt_confirmed', 'Late SQLI callback promoted to a runtime_confirmed finding.', {
        findingId: 'finding-1', oobSubscriptionId: 'sub-1', rule: 'oob-proof',
      })
      storage.event(runId, 'oob.receipt_confirmed', 'Late SSRF callback promoted to a runtime_confirmed finding.', {
        findingId: 'finding-2', oobSubscriptionId: 'sub-2', rule: 'oob-proof',
      })
      // The bounded drain saw no relay promotions of its own (they were already claimed).
      storage.event(runId, 'oob.drain_complete', 'OOB drain finished.', {
        oobDrainMs: 16_000, promotedLate: 0, promotedReceipts: 2, remaining: 0,
      })
      const metrics = collectWiringMetrics({
        fixture: 'wan-oob',
        storage,
        runId,
        dataDir,
        routes: [],
      })
      assert.equal(metrics.pendingOobRegistered, 4)
      assert.equal(metrics.lateCallbacksMatched, 4)
      assert.equal(metrics.oobDrainWaitedMs, 16_000)
      assert.equal(metrics.latePromotions, 2, 'metric must match the two converted findings')
    } finally {
      storage.close()
    }
  })
})

describe('monorepo micro-slice post-recon snapshot status', () => {
  const base = parseSmokeArgs([
    '--out-dir', join(tempRoot, 'out'),
    '--snapshot-root', join(tempRoot, 'snapshots'),
    '--micro-recon-timeout-sec', '480',
  ])

  test('#4 is white-box with a bounded cold fallback when no snapshot exists', () => {
    const plan = resolveMicroSlice({
      fixture: 'monorepo-whitebox', seed: 1, snapshotRoot: base.snapshotRoot,
      microDurationSec: 300, microReconTimeoutSec: 480,
    })
    assert.equal(plan.mode, 'white-box')
    assert.equal(plan.snapshot.state, 'cold')
    assert.equal(plan.snapshot.used, false)
    assert.equal(plan.timeoutSec, 480)
    assert.match(plan.snapshot.reason, /cannot capture\/resume one yet/)
  })

  test('a cached snapshot is consumed when the harness supports resume', () => {
    const dir = realismReconSnapshotDir(base.snapshotRoot, 'monorepo-whitebox', 1)
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'snapshot.json'), '{"phase0":{"completedAt":1}}\n')
    const used = resolveMicroSlice({
      fixture: 'monorepo-whitebox', seed: 1, snapshotRoot: base.snapshotRoot,
      microDurationSec: 300, microReconTimeoutSec: 480, resumeSupported: true,
    })
    assert.equal(used.snapshot.state, 'snapshot')
    assert.equal(used.snapshot.used, true)
    assert.equal(used.timeoutSec, 300)
    assert.equal(formatSnapshotStatus(used.snapshot, used.timeoutSec), 'snapshot')
  })

  test('a cached snapshot from an unsupported harness falls back explicitly, never silently', () => {
    const fallback = resolveMicroSlice({
      fixture: 'monorepo-whitebox', seed: 1, snapshotRoot: base.snapshotRoot,
      microDurationSec: 300, microReconTimeoutSec: 480, resumeSupported: false,
    })
    assert.equal(fallback.snapshot.state, 'unsupported')
    assert.equal(fallback.snapshot.used, false)
    assert.equal(fallback.timeoutSec, 480)
    assert.match(fallback.snapshot.reason, /no --resume-recon-snapshot/)
    assert.equal(formatSnapshotStatus(fallback.snapshot, fallback.timeoutSec), 'unsupported+480s')
  })

  test('default fallback budget is the documented extended slice', () => {
    const plan = resolveMicroSlice({
      fixture: 'monorepo-whitebox', seed: 2, snapshotRoot: base.snapshotRoot,
      microDurationSec: 180,
    })
    assert.equal(plan.timeoutSec, Math.max(180, DEFAULT_MICRO_RECON_TIMEOUT_SEC))
  })

  test('planMicroSlices keeps #2/#3 on their normal grey-box budget', () => {
    const plans = planMicroSlices(base)
    assert.deepEqual(plans.map(plan => plan.fixture), ['wan-oob', 'staging-concurrency', 'monorepo-whitebox'])
    for (const plan of plans.slice(0, 2)) {
      assert.equal(plan.mode, 'grey-box')
      assert.equal(plan.timeoutSec, 300)
      assert.equal(plan.snapshot.state, 'not-applicable')
    }
    assert.equal(plans[2]!.mode, 'white-box')
  })
})

describe('Tier-1 compact output shows latePromotions and snapshot status', () => {
  test('compact table carries the late and snap columns', () => {
    const cell: CellMetrics = {
      id: 'micro', kind: 'micro', app: 'wan-oob,staging-concurrency,monorepo-whitebox', source: 'local',
      targets: 3, confirmed: 1, precision: 1, decoyFalsePositives: 0, unmatchedFalsePositives: 0,
      netNew: null, floorConfirmed: null, floorPreserved: null, conversion: null, costUsd: 0.2,
      p50AssignmentMs: null, completedAssignments: 3, wallMs: 60_000, crashes: 0,
      wiring: 'pass', capability: 1, latePromotions: 2, snapshot: 'cold+480s',
      detail: 'wan-oob: latePromotions=2 snapshot=n/a',
    }
    const table = renderCompactTable([cell])
    const [header, , row] = table.split('\n')
    assert.ok(header!.includes('late'), 'missing late column')
    assert.ok(header!.includes('snap'), 'missing snap column')
    assert.match(row!, /\b2\b.*cold\+480s$/)
    const status: MicroSnapshotStatus = { state: 'not-applicable', used: false, dir: '', reason: '' }
    assert.equal(formatSnapshotStatus(status, 300), 'n/a')
  })
})
