/**
 * v6 provenance / advisory report contract.
 *
 * Pins the certification contract from plans/ROADMAP-v5.md check-ins #5/#6:
 *  - `findings.provenance` is one of floor | agent_only | chain_from_floor;
 *  - floor-confirmed rows are immutable and agent re-discovery is a suppressed no-op;
 *  - `confirmed` requires `verification_class = 'runtime_confirmed'` (CHECK + write assertion);
 *  - static/open-proof-gap proof persists as an advisory, never as a confirmed finding;
 *  - the product report exposes provenanceCounts and a separate advisories bucket;
 *  - legacy databases without the columns backfill defaults and remain readable.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'
import { eq } from 'drizzle-orm'

import type { Finding, ReportBody } from '../src/domain.ts'
import { Store, STORE_SCHEMA_VERSION, verificationClassForFinding } from '../src/server/store.ts'
import * as tables from '../src/server/schema.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function finding(origin: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id: randomUUID(),
    origin,
    title: 'Differential proof on protected route',
    status: 'confirmed',
    severity: 'high',
    reason: 'Control vs variant differential proved an authorization boundary crossing.',
    remediation: 'Enforce ownership checks server-side.',
    evidenceIds: [randomUUID()],
    exchangeIds: [randomUUID()],
    scopeRevision: 1,
    fingerprintHash: overrides.fingerprintHash ?? randomUUID(),
    findingKind: 'multi_step_chain',
    ...overrides,
  }
}

async function setup(t: Parameters<typeof makeStore>[0], label: string) {
  const { dir, storage } = makeStore(t, `guardian-v6-provenance-${label}-`)
  const { runId } = await setupApprovedRun(storage, { budgetRequests: 500 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Provenance', 'Provenance test')
  const artifact = storage.addArtifact(run, worker, 'replay', 'Proof', '{}')
  return { dir, storage, runId, asset, origin: asset.origin, artifact }
}

test('v6 provenance: schema columns exist with additive defaults', async t => {
  const { storage } = await setup(t, 'schema')
  const columns = storage.client.prepare('PRAGMA table_info(findings)').all() as Array<{ name: string; dflt_value: string | null; notnull: number }>
  const byName = new Map(columns.map(column => [column.name, column]))
  assert.equal(byName.get('provenance')?.dflt_value, "'agent_only'")
  assert.equal(byName.get('provenance')?.notnull, 1)
  assert.ok(byName.has('parent_finding_ids'))
  assert.equal(byName.get('verification_class')?.dflt_value, "'runtime_confirmed'")
  assert.equal(byName.get('verification_class')?.notnull, 1)
  assert.equal(
    (storage.client.prepare('PRAGMA user_version').get() as { user_version: number }).user_version,
    STORE_SCHEMA_VERSION,
  )
  assert.equal(verificationClassForFinding({ status: 'static_verified' }), 'static_advisory')
  assert.equal(verificationClassForFinding({ status: 'inconclusive' }), 'open_proof_gap')
  assert.throws(
    () => verificationClassForFinding({ status: 'confirmed', verificationTier: 'static_verified' }),
    /never as confirmed/,
  )
  assert.equal(
    verificationClassForFinding({ status: 'pending', runtimeProofGap: 'awaiting pending_oob callback' }),
    'pending_oob',
  )
})

test('v6 provenance: confirmed + static verification class is rejected by the store', async t => {
  const { storage, runId, asset, origin, artifact } = await setup(t, 'reject')
  assert.throws(
    () => storage.upsertChainFinding(
      storage.run(runId),
      asset.id,
      finding(origin, { evidenceIds: [artifact.id] }),
      randomUUID(),
      [origin],
      { verificationClass: 'static_advisory' },
    ),
    /confirmed findings require verification_class='runtime_confirmed'/,
  )
  assert.equal(storage.runDetail(runId).findings.length, 0, 'rejected write must not persist')

  // The database CHECK constraint is the last line of defence for direct writers.
  const saved = storage.upsertChainFinding(
    storage.run(runId), asset.id, finding(origin, { evidenceIds: [artifact.id] }), randomUUID(), [origin],
  )
  assert.throws(
    () => storage.client.prepare("UPDATE findings SET verification_class = 'static_advisory' WHERE id = ?").run(saved.id),
    /CHECK constraint failed/,
  )
})

test('v6 provenance: static proof persists as an advisory and never as confirmed', async t => {
  const { storage, runId, asset, origin, artifact } = await setup(t, 'advisory')
  const staticFinding = finding(origin, {
    title: 'Source-to-sink SSRF suspect',
    status: 'static_verified',
    severity: 'medium',
    evidenceIds: [artifact.id],
    verificationTier: 'static_verified',
  })
  storage.upsertChainFinding(storage.run(runId), asset.id, staticFinding, randomUUID(), [origin])

  const detail = storage.runDetail(runId)
  const stored = detail.findings.find(item => item.id === staticFinding.id) as (Finding & { verificationStatus?: string }) | undefined
  assert.equal(stored?.status, 'static_verified')
  assert.equal(stored?.verificationStatus, 'static_advisory')

  const reportId = storage.writeReport(storage.run(runId), true)
  const body = storage.runDetail(runId).reports.find(row => row.id === reportId)!.body as ReportBody & {
    provenanceCounts: { floor: number; agent_only: number; chain_from_floor: number }
    confirmedFindings: Finding[]
    advisories: Finding[]
  }
  assert.equal(body.confirmedFindings.length, 0)
  assert.ok(body.advisories.some(item => item.id === staticFinding.id), 'static item is in the advisory bucket')
  assert.equal(body.provenanceCounts.floor + body.provenanceCounts.agent_only + body.provenanceCounts.chain_from_floor, 0)
})

test('v6 provenance: floor, agent_only and chain_from_floor are counted separately', async t => {
  const { storage, runId, asset, origin, artifact } = await setup(t, 'counts')
  const run = storage.run(runId)

  const floorParent = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-floor' })
  storage.upsertChainFinding(
    run, asset.id, floorParent, randomUUID(), [origin],
    { provenance: 'floor', verificationClass: 'runtime_confirmed' },
  )

  const agentOnly = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-agent' })
  storage.upsertChainFinding(run, asset.id, agentOnly, randomUUID(), [origin])

  const chain = finding(origin, {
    evidenceIds: [artifact.id],
    fingerprintHash: 'fp-chain',
    title: 'Privilege escalation from floor-confirmed primitive',
  })
  const chained = storage.upsertChainFinding(
    run, asset.id, chain, randomUUID(), [origin],
    { parentFindingIds: [floorParent.id] },
  )

  const counts = storage.runDetail(runId).provenanceCounts
  assert.deepEqual(
    { floor: counts.floor, agent_only: counts.agent_only, chain_from_floor: counts.chain_from_floor, incremental: counts.incremental },
    { floor: 1, agent_only: 1, chain_from_floor: 1, incremental: 2 },
  )
  assert.equal(counts.agentOnly, 1)
  assert.equal(counts.chainFromFloor, 1)
  const chainRow = storage.db.select().from(tables.findings)
    .where(eq(tables.findings.id, chained.id)).get()
  assert.equal(chainRow?.provenance, 'chain_from_floor')
  assert.deepEqual(chainRow?.parentFindingIds, [floorParent.id])
})

test('v6 provenance: a chain without a floor parent stays agent_only', async t => {
  const { storage, runId, asset, origin, artifact } = await setup(t, 'chain-no-parent')
  const run = storage.run(runId)
  const agentParent = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-agent-parent' })
  storage.upsertChainFinding(run, asset.id, agentParent, randomUUID(), [origin])

  const orphanChain = finding(origin, {
    evidenceIds: [artifact.id],
    fingerprintHash: 'fp-orphan-chain',
    title: 'Downstream chain without a floor primitive',
  })
  const saved = storage.upsertChainFinding(
    run, asset.id, orphanChain, randomUUID(), [origin],
    { parentFindingIds: [agentParent.id] },
  )
  assert.equal((saved as Finding & { provenance?: string }).provenance, 'agent_only')

  const bogus = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-bogus', title: 'No parent exists' })
  const bogusSaved = storage.upsertChainFinding(
    run, asset.id, bogus, randomUUID(), [origin],
    { parentFindingIds: [randomUUID()] },
  )
  assert.equal((bogusSaved as Finding & { provenance?: string }).provenance, 'agent_only')
})

test('v6 provenance: duplicate agent re-discovery of a floor finding is suppressed', async t => {
  const { storage, runId, asset, origin, artifact } = await setup(t, 'floor-immutable')
  const run = storage.run(runId)
  const floorFinding = finding(origin, {
    evidenceIds: [artifact.id],
    fingerprintHash: 'fp-shared-floor',
    title: 'Floor-confirmed BOLA on invoices',
    severity: 'high',
  })
  const savedFloor = storage.upsertChainFinding(
    run, asset.id, floorFinding, randomUUID(), [origin],
    { provenance: 'floor', verificationClass: 'runtime_confirmed' },
  )
  const before = storage.db.select().from(tables.findings).all()

  // Same canonical dedupe key, agent attribution, different id and a lower severity attempt.
  const rediscovery = finding(origin, {
    evidenceIds: [artifact.id],
    fingerprintHash: 'fp-shared-floor',
    title: 'Agent rediscovery of invoices BOLA',
    severity: 'low',
  })
  const returned = storage.upsertChainFinding(run, asset.id, rediscovery, randomUUID(), [origin])

  assert.equal(returned.id, savedFloor.id, 'returns the canonical floor row')
  const after = storage.db.select().from(tables.findings).all()
  assert.equal(after.length, before.length, 'no duplicate row is created')
  const stored = after.find(row => row.id === savedFloor.id)
  assert.equal(stored?.finding.title, 'Floor-confirmed BOLA on invoices')
  assert.equal(stored?.finding.severity, 'high')
  assert.equal(stored?.provenance, 'floor')

  // updateProposedFinding must also refuse to mutate a floor row.
  const patched = storage.updateProposedFinding(run, savedFloor.id, { finding: { status: 'dismissed' } })
  assert.equal(patched.status, 'confirmed')
  assert.equal(patched.severity, 'high')
})

test('v6 provenance: report counts are correct and advisories stay out of confirmed', async t => {
  const { storage, runId, asset, origin, artifact } = await setup(t, 'report')
  const run = storage.run(runId)
  const floor = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-r-floor' })
  storage.upsertChainFinding(run, asset.id, floor, randomUUID(), [origin], { provenance: 'floor' })
  const agent = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-r-agent' })
  storage.upsertChainFinding(run, asset.id, agent, randomUUID(), [origin])
  const chain = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-r-chain', title: 'Chained downstream impact' })
  storage.upsertChainFinding(run, asset.id, chain, randomUUID(), [origin], { parentFindingIds: [floor.id] })
  const advisory = finding(origin, {
    evidenceIds: [artifact.id], status: 'static_verified', verificationTier: 'static_verified', title: 'Static advisory', fingerprintHash: 'fp-r-static',
  })
  storage.upsertChainFinding(run, asset.id, advisory, randomUUID(), [origin])

  const reportId = storage.writeReport(storage.run(runId), true)
  const storedReport = storage.runDetail(runId).reports.find(row => row.id === reportId)!
  const body = storedReport.body as ReportBody & {
    provenanceCounts: { floor: number; agent_only: number; chain_from_floor: number; incremental: number }
    confirmedFindings: Finding[]
    advisories: Finding[]
  }
  assert.deepEqual(
    {
      floor: body.provenanceCounts.floor,
      agent_only: body.provenanceCounts.agent_only,
      chain_from_floor: body.provenanceCounts.chain_from_floor,
      incremental: body.provenanceCounts.incremental,
    },
    { floor: 1, agent_only: 1, chain_from_floor: 1, incremental: 2 },
  )
  assert.equal(body.confirmedFindings.length, 3)
  assert.ok(body.confirmedFindings.every(item => item.status === 'confirmed'))
  assert.ok(body.confirmedFindings.every(item => (item as Finding & { verificationStatus?: string }).verificationStatus === 'runtime_confirmed'))
  assert.equal(body.advisories.length, 1)
  assert.equal(body.advisories[0]!.id, advisory.id)
  assert.ok(!body.confirmedFindings.some(item => item.id === advisory.id), 'static advisory is excluded from confirmed')
})

test('v6 provenance: legacy database without provenance columns backfills and reads', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v6-provenance-legacy-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const seeded = new Store(dir)
  const { runId } = await setupApprovedRun(seeded, { budgetRequests: 500 })
  const run = seeded.run(runId)
  const asset = run.candidates[0]!
  const origin = asset.origin
  const worker = seeded.makeWorker(run, 'investigation', asset, 'Legacy', 'Legacy')
  const artifact = seeded.addArtifact(run, worker, 'replay', 'Proof', '{}')

  const floor = finding(origin, { evidenceIds: [artifact.id], fingerprintHash: 'fp-legacy-floor' })
  const staticLegacy = finding(origin, {
    evidenceIds: [artifact.id], status: 'static_verified', verificationTier: 'static_verified',
    title: 'Legacy static', fingerprintHash: 'fp-legacy-static',
  })
  seeded.upsertChainFinding(run, asset.id, floor, randomUUID(), [origin], { provenance: 'floor' })
  seeded.upsertChainFinding(run, asset.id, staticLegacy, randomUUID(), [origin])
  seeded.event(runId, 'deterministic_engine.confirmed', 'legacy floor marker', { findingId: floor.id })
  seeded.close()

  // Rebuild findings as a pre-v6 table (no provenance / verification_class columns).
  const raw = new DatabaseSync(join(dir, 'guardian.sqlite'))
  const rows = raw.prepare('SELECT * FROM findings').all() as Array<Record<string, unknown>>
  raw.exec(`
    DROP INDEX IF EXISTS findings_provenance;
    DROP INDEX IF EXISTS findings_check_case;
    DROP INDEX IF EXISTS findings_fingerprint;
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
      finding TEXT NOT NULL,
      verification_tier TEXT,
      fingerprint_hash TEXT,
      superseded_by_finding_id TEXT,
      counterevidence TEXT,
      confidence_rationale TEXT,
      severity_change_conditions TEXT,
      code_locations TEXT
    );
    PRAGMA user_version = 0;
  `)
  const insert = raw.prepare(`
    INSERT INTO findings (id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind, replay_spec_id, source_origins, finding, verification_tier, fingerprint_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)
  const sqlValue = (value: unknown): string | number | null =>
    value === null || value === undefined ? null : (typeof value === 'number' ? value : String(value))
  for (const row of rows) {
    insert.run(
      sqlValue(row.id), sqlValue(row.run_id), sqlValue(row.asset_id), sqlValue(row.goal_revision),
      sqlValue(row.check_id), sqlValue(row.case_id), sqlValue(row.finding_kind),
      sqlValue(row.replay_spec_id), sqlValue(row.source_origins), sqlValue(row.finding),
      sqlValue(row.verification_tier), sqlValue(row.fingerprint_hash),
    )
  }
  raw.close()

  const reopened = new Store(dir)
  t.after(() => reopened.close())
  const columns = new Set((reopened.client.prepare('PRAGMA table_info(findings)').all() as Array<{ name: string }>)
    .map(row => row.name))
  assert.ok(columns.has('provenance'))
  assert.ok(columns.has('parent_finding_ids'))
  assert.ok(columns.has('verification_class'))

  const detail = reopened.runDetail(runId)
  const floorRow = detail.findings.find(item => item.id === floor.id) as (Finding & { provenance?: string }) | undefined
  const staticRow = detail.findings.find(item => item.id === staticLegacy.id) as (Finding & { verificationStatus?: string }) | undefined
  assert.equal(floorRow?.provenance, 'floor', 'legacy floor event backfills provenance')
  assert.equal(staticRow?.verificationStatus, 'static_advisory', 'legacy static rows become advisories')
  assert.equal(detail.provenanceCounts.floor, 1)
  assert.equal(detail.provenanceCounts.agent_only, 0)

  // New writes remain guarded after the additive backfill.
  assert.throws(
    () => reopened.upsertChainFinding(
      reopened.run(runId), asset.id, finding(origin, { evidenceIds: [artifact.id] }), randomUUID(), [origin],
      { verificationClass: 'static_advisory' },
    ),
    /confirmed findings require verification_class='runtime_confirmed'/,
  )
})
