/**
 * v7 confirmation consistency (precision integrity).
 *
 * Defect: a finding could be persisted `runtime_confirmed` while its own persisted replay diff
 * said `inconclusive` — a confirmed claim contradicted by its evidence (reproduced in a held-out
 * shopflow cell: floor `mass_assignment` finding whose anchor spec was re-verified to inconclusive
 * by a repair attempt; the finding kept its confirmed status).
 *
 * Invariant under test: a finding may only be persisted `runtime_confirmed` while its persisted
 * evidence (linked spec diff `confirmed`, an OOB ProofReceipt, a baseline review, or a legacy floor
 * artifact) satisfies the oracle. A later downgrade demotes it, emits `finding.confirmation_conflict`
 * and is counted.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import { Store } from '../src/server/store.ts'
import { events, findings } from '../src/server/schema.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const executionSource = readFileSync(join(repoRoot, 'src/server/execution.ts'), 'utf8')

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:7788'

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-v7-confirm-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function specFor(title: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Object ownership boundary.',
    impact: 'A cross-actor write persists.',
    remediation: 'Enforce per-object ownership.',
    recheckInstructions: 'Replay the before/write/after chain.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'b1', role: 'control', description: 'Read', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/objects/1', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Write', expectedStatus: 200, request: { origin, method: 'PATCH', pathAndQuery: '/api/objects/1', jsonBody: { owner: 'other' }, followRedirects: false } },
      { id: 'a1', role: 'control', description: 'Read back', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/objects/1', followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
}

function feedback(verdict: InlineVerifyFeedback['verdict'], reason = 'fixture'): InlineVerifyFeedback {
  return {
    verdict,
    controlPassed: verdict === 'confirmed',
    assertionSummary: { observed: reason, expected: 'confirmation' },
    stepStatuses: [{ id: 'p1', role: 'probe', status: verdict === 'confirmed' ? 200 : 401, bodyLen: 2 }],
    retriesRemaining: 0,
  }
}

function confirmedFinding(id: string, title: string, cwe: string, verification = 'Zero-LLM http_chain inline replay verdict: confirmed'): Finding {
  return {
    id,
    origin: ORIGIN,
    title,
    status: 'confirmed',
    severity: 'high',
    reason: 'Differential evidence reproduced.',
    remediation: 'Enforce ownership.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'broken-access-control',
    cwe,
    confidence: 'high',
    verification,
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
  }
}

async function fixture(t: { after: (fn: () => void) => void }) {
  const storage = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Confirm-consistency fixture', 'fixture')
  return { storage, run, asset, assignment }
}

test('confirm-consistency: a promotion followed by an inconclusive diff cannot stay confirmed', async (t) => {
  const { storage, run, asset, assignment } = await fixture(t)
  const findingId = '00000000-0000-4000-8000-000000000001'
  const spec = storage.createReplaySpec(run, assignment, findingId, specFor('Cross-actor owner write'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed', 'owner moved and persisted'),
  })
  const saved = storage.upsertChainFinding(run, asset.id, confirmedFinding(findingId, 'Cross-actor owner write', 'CWE-639'), spec.id, [ORIGIN])
  assert.equal(saved.status, 'confirmed')
  const confirmedRow = storage.db.select().from(findings).get()!
  assert.equal(confirmedRow.verificationClass, 'runtime_confirmed')

  storage.incrementReplaySpecAttempt(spec.id, feedback('inconclusive', 'probe returned 401'))

  const row = storage.db.select().from(findings).get()!
  assert.equal(row.finding.status, 'inconclusive', 'the demoted claim must not stay confirmed')
  assert.equal(row.verificationClass, 'open_proof_gap')
  assert.equal(row.verificationTier, null)
  assert.equal(row.replaySpecId, spec.id, 'the contradicted spec stays linked for audit')
  assert.equal(storage.confirmationConflictCount(run.id), 1)
  const conflict = storage.db.select().from(events).all()
    .filter(e => e.kind === 'finding.confirmation_conflict')
  assert.equal(conflict.length, 1)
  const detail = conflict[0]!.detail as Record<string, unknown>
  assert.equal(detail.findingId, findingId)
  assert.equal(detail.previousStatus, 'confirmed')
  assert.equal(detail.evidenceVerdict, 'inconclusive')
  assert.equal(detail.conflictsForRun, 1)

  // A second non-confirming write on an already-demoted claim is not a new conflict.
  storage.incrementReplaySpecAttempt(spec.id, feedback('inconclusive', 'probe returned 401 again'))
  assert.equal(storage.confirmationConflictCount(run.id), 1)
})

test('confirm-consistency: a confirmed write without confirming evidence is rejected at persistence', async (t) => {
  const { storage, run, asset, assignment } = await fixture(t)
  const findingId = '00000000-0000-4000-8000-000000000002'
  const spec = storage.createReplaySpec(run, assignment, findingId, specFor('Unproven owner write'), [ORIGIN], {
    verifiedInline: false,
    lastVerificationDiff: feedback('inconclusive', 'control failed'),
  })
  const saved = storage.upsertChainFinding(run, asset.id, confirmedFinding(findingId, 'Unproven owner write', 'CWE-639'), spec.id, [ORIGIN])
  assert.equal(saved.status, 'inconclusive')
  const row = storage.db.select().from(findings).get()!
  assert.equal(row.verificationClass, 'open_proof_gap')
  assert.equal(storage.confirmationConflictCount(run.id), 1)
})

test('confirm-consistency: a confirmed trial with an inconclusive losing sibling keeps only the confirmed one', async (t) => {
  const { storage, run, asset, assignment } = await fixture(t)
  const winnerId = '00000000-0000-4000-8000-000000000003'
  const winnerSpec = storage.createReplaySpec(run, assignment, winnerId, specFor('Trial A confirmed'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed'),
  })
  storage.upsertChainFinding(run, asset.id, confirmedFinding(winnerId, 'Trial A confirmed', 'CWE-639'), winnerSpec.id, [ORIGIN])

  // Sibling trial reused the same finding id with a second, non-confirming spec.
  const siblingSpec = storage.createReplaySpec(run, assignment, winnerId, specFor('Trial A repaired'), [ORIGIN], { initialAttemptCount: 2 })
  storage.incrementReplaySpecAttempt(siblingSpec.id, feedback('inconclusive', 'sibling repair failed'))

  const winner = storage.db.select().from(findings).get()!
  assert.equal(winner.finding.status, 'confirmed', 'an inconclusive sibling must not demote the confirmed anchor')
  assert.equal(winner.verificationClass, 'runtime_confirmed')
  assert.equal(storage.confirmationConflictCount(run.id), 0)

  // The losing sibling claim itself is never runtime_confirmed.
  const loserId = '00000000-0000-4000-8000-000000000004'
  const loserSpec = storage.createReplaySpec(run, assignment, loserId, specFor('Trial B inconclusive'), [ORIGIN], {
    lastVerificationDiff: feedback('inconclusive', 'no impact'),
  })
  const loser = storage.upsertChainFinding(run, asset.id, {
    ...confirmedFinding(loserId, 'Trial B inconclusive', 'CWE-918'),
    status: 'inconclusive',
  }, loserSpec.id, [ORIGIN])
  assert.equal(loser.status, 'inconclusive')
  const loserRow = storage.db.select().from(findings).all().find(r => r.id === loserId)!
  assert.equal(loserRow.verificationClass, 'open_proof_gap')
})

test('confirm-consistency: existing confirmed evidence (floor artifact, receipt, baseline) is untouched', async (t) => {
  const { storage, run, asset, assignment } = await fixture(t)

  // Legacy floor row: no persisted spec diff yet, but the deterministic-engine event is its anchor.
  const floorId = '00000000-0000-4000-8000-000000000005'
  const floorSpec = storage.createReplaySpec(run, assignment, floorId, specFor('Floor confirmed'), [ORIGIN])
  storage.upsertChainFinding(run, asset.id, confirmedFinding(floorId, 'Floor confirmed', 'CWE-915'), floorSpec.id, [ORIGIN], {
    provenance: 'floor',
  })
  storage.event(run.id, 'deterministic_engine.confirmed', 'floor anchor', { findingId: floorId })
  assert.equal(storage.enforceConfirmationEvidence(run.id, floorId, 'fixture recheck'), false)
  let floorRow = storage.db.select().from(findings).all().find(r => r.id === floorId)!
  assert.equal(floorRow.finding.status, 'confirmed')

  // Receipt-only finding (late OOB promotion): no spec diff, but a ProofReceipt owns the proof.
  const receiptId = '00000000-0000-4000-8000-000000000006'
  storage.upsertChainFinding(run, asset.id, confirmedFinding(receiptId, 'OOB receipt finding', 'CWE-918',
    'ProofReceipt receipt:oob:1 · oob_callback rule · canary fired'), 'orphan-spec', [ORIGIN])
  assert.equal(storage.enforceConfirmationEvidence(run.id, receiptId, 'fixture recheck'), false)

  // A confirmed finding backed by a confirming linked diff survives unrelated failures.
  const anchorId = '00000000-0000-4000-8000-000000000007'
  const anchorSpec = storage.createReplaySpec(run, assignment, anchorId, specFor('Anchored confirmed'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed'),
  })
  storage.upsertChainFinding(run, asset.id, confirmedFinding(anchorId, 'Anchored confirmed', 'CWE-639'), anchorSpec.id, [ORIGIN])
  const otherSpec = storage.createReplaySpec(run, assignment, '00000000-0000-4000-8000-000000000008', specFor('Unrelated failing'), [ORIGIN])
  storage.incrementReplaySpecAttempt(otherSpec.id, feedback('inconclusive'))
  const anchorRow = storage.db.select().from(findings).all().find(r => r.id === anchorId)!
  assert.equal(anchorRow.finding.status, 'confirmed')
  assert.equal(storage.confirmationConflictCount(run.id), 0)
})

test('confirm-consistency: engine wiring routes every evidence write through the invariant', () => {
  // Phase-3 retest writes the diff through the store so a downgrade demotes the claim.
  assert.match(executionSource, /recordReplaySpecVerification\(/)
  assert.ok(!/update\(replaySpecs\)\.set\(\{\s*lastVerificationDiff/.test(executionSource))
  // Floor confirmations persist their own confirming diff on the spec.
  assert.match(executionSource, /lastVerificationDiff: buildInlineVerifyFeedback\(/)
  // The inline path reports the persisted status after the evidence write, never the stale row.
  assert.match(executionSource, /const verdictRow = findingRow/)
})

test('confirm-consistency: an FP autopsy attributes the confirming spec, not a failed retry', async () => {
  const { buildFalsePositiveEvidence } = await import('../scripts/benchmark-realistic.ts')
  const steps = (path: string) => [
    { id: 'b1', role: 'control', request: { method: 'GET', pathAndQuery: path } },
    { id: 'p1', role: 'probe', request: { method: 'POST', pathAndQuery: path } },
  ]
  const evidence = buildFalsePositiveEvidence({
    findingIds: ['finding-1'],
    findings: [{ id: 'finding-1', category: 'xss_stored', verificationStatus: 'runtime_confirmed' }],
    replaySpecs: [
      {
        findingId: 'finding-1',
        spec: { kind: 'http_chain', steps: steps('/api/testimonials') },
        lastVerificationDiff: {
          verdict: 'inconclusive',
          failedStepId: 's2',
          assertionSummary: { reason: 'csrf claim has no successful state-changing probe' },
        },
      },
      {
        findingId: 'finding-1',
        spec: { kind: 'browser_chain', steps: steps('/api/testimonials') },
        lastVerificationDiff: { verdict: 'confirmed' },
      },
    ],
  })
  assert.equal(evidence.length, 1)
  assert.equal(evidence[0]!.oracleRulePassed, true, 'the confirming anchor backs the claim')
  assert.ok(!/csrf/i.test(evidence[0]!.claimedDeltaSummary), 'an inconclusive retry must not be attributed to the finding')
})
