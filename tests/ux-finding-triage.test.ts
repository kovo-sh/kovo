import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { eq } from 'drizzle-orm'
import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { events, findings } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import type { TriagedFinding } from '../src/server/store-findings.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'http://127.0.0.1:7799'

function readRepoFile(...segments: string[]): string {
  return readFileSync(join(REPO_ROOT, ...segments), 'utf8')
}

function makeTempDir(t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-triage-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeSpec(title: string): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin: ORIGIN,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Ownership check missing.',
    impact: 'Cross-actor read/write.',
    remediation: 'Enforce ownership checks.',
    recheckInstructions: 'Replay request as secondary user.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "403" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'c1', role: 'control', description: 'Control', expectedStatus: 403, request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Probe', expectedStatus: 200, request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/1', followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
}

function feedback(verdict: InlineVerifyFeedback['verdict'], reason = 'fixture'): InlineVerifyFeedback {
  return {
    verdict,
    controlPassed: verdict === 'confirmed',
    assertionSummary: { observed: reason, expected: 'confirmation' },
    stepStatuses: [{ id: 'p1', role: 'probe', status: verdict === 'confirmed' ? 200 : 403, bodyLen: 12 }],
    retriesRemaining: 0,
  }
}

function chainFinding(id: string, status: Finding['status'], title: string): Finding {
  return {
    id,
    origin: ORIGIN,
    title,
    status,
    severity: 'high',
    reason: 'Differential check observed cross-actor access.',
    remediation: 'Verify tenant ownership on read.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: status === 'confirmed' ? 'high' : 'medium',
    verification: status === 'confirmed' ? 'Zero-LLM http_chain inline replay verdict: confirmed' : undefined,
    verificationTier: status === 'confirmed' ? 'runtime_confirmed' : undefined,
    findingKind: 'multi_step_chain',
  }
}

async function setupFixture(t: { after: (fn: () => void) => void }) {
  const dir = makeTempDir(t)
  let storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* may already be closed */ }
  })
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Triage fixture', 'fixture')
  const reopen = () => {
    storage.close()
    storage = new Store(dir)
    return storage
  }
  return { getStore: () => storage, reopen, run, asset, assignment }
}

test('triageFinding persists operator triage cleanly across reopen without violating H-4/H-18 invariants', async (t) => {
  const { getStore, reopen, run, asset, assignment } = await setupFixture(t)
  const storage = getStore()

  // 1. Confirmed finding backed by a confirming replay spec.
  const confirmedId = randomUUID()
  const confirmedSpec = storage.createReplaySpec(storage.run(run.id), assignment, confirmedId, makeSpec('IDOR item read'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed', 'cross-actor 200'),
  })
  storage.upsertChainFinding(storage.run(run.id), asset.id, chainFinding(confirmedId, 'confirmed', 'IDOR item read'), confirmedSpec.id, [ORIGIN])

  // 2. Pending finding without confirming evidence.
  const pendingId = randomUUID()
  const pendingSpec = storage.createReplaySpec(storage.run(run.id), assignment, pendingId, makeSpec('Pending lead'), [ORIGIN])
  storage.upsertChainFinding(storage.run(run.id), asset.id, chainFinding(pendingId, 'pending', 'Pending lead'), pendingSpec.id, [ORIGIN])

  // 3. Floor-provenance confirmed finding.
  const floorId = randomUUID()
  const floorSpec = storage.createReplaySpec(storage.run(run.id), assignment, floorId, makeSpec('Floor IDOR'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: feedback('confirmed', 'floor confirmed'),
  })
  storage.upsertChainFinding(
    storage.run(run.id),
    asset.id,
    chainFinding(floorId, 'confirmed', 'Floor IDOR'),
    floorSpec.id,
    [ORIGIN],
    { provenance: 'floor' },
  )

  // Triage confirmed finding as false_positive + severityOverride=low + notes.
  const triagedConfirmed = storage.findingsRepo.triageFinding(confirmedId, {
    status: 'false_positive',
    severityOverride: 'low',
    notes: 'Edge WAF already blocks external callers.',
  })
  assert.equal(triagedConfirmed.status, 'confirmed', 'H-4/H-18: machine verdict must remain confirmed')
  assert.equal(triagedConfirmed.severity, 'high', 'H-4/H-18: machine severity must remain high')
  assert.equal(triagedConfirmed.cwe, 'CWE-639')
  assert.equal(triagedConfirmed.verificationTier, 'runtime_confirmed')
  assert.equal(triagedConfirmed.operatorTriage?.status, 'false_positive')
  assert.equal(triagedConfirmed.operatorTriage?.severityOverride, 'low')
  assert.equal(triagedConfirmed.operatorTriage?.notes, 'Edge WAF already blocks external callers.')
  assert.ok((triagedConfirmed.operatorTriage?.updatedAt ?? 0) > 0)

  // Triage pending finding as confirmed_by_operator: MUST NOT forge machine status='confirmed' or runtime_confirmed.
  const triagedPending = storage.findingsRepo.triageFinding(pendingId, {
    status: 'confirmed_by_operator',
    severityOverride: 'critical',
    notes: 'Reproduced manually by operator.',
  })
  assert.equal(triagedPending.status, 'pending', 'Operator confirmation must not forge machine confirmed status')
  assert.equal(triagedPending.severity, 'high', 'Machine severity must stay untouched')
  assert.equal(triagedPending.operatorTriage?.status, 'confirmed_by_operator')
  assert.equal(triagedPending.operatorTriage?.severityOverride, 'critical')

  // Triage floor-confirmed finding as accepted_risk: must succeed without touching floor provenance/status.
  const triagedFloor = storage.findingsRepo.triageFinding(floorId, {
    status: 'accepted_risk',
    notes: 'Accepted for Q4.',
  })
  assert.equal(triagedFloor.status, 'confirmed')
  assert.equal(triagedFloor.operatorTriage?.status, 'accepted_risk')

  // Clear severityOverride while preserving existing status & notes when omitted.
  const clearedOverride = storage.findingsRepo.triageFinding(confirmedId, {
    severityOverride: null,
  })
  assert.equal(clearedOverride.operatorTriage?.status, 'false_positive')
  assert.equal(clearedOverride.operatorTriage?.severityOverride, null)
  assert.equal(clearedOverride.operatorTriage?.notes, 'Edge WAF already blocks external callers.')

  // Non-floor updateProposedFinding preserves existing operatorTriage.
  storage.updateProposedFinding(storage.run(run.id), pendingId, {
    finding: { reason: 'Updated hypothesis text' },
  })

  // Reopen store and verify runDetail() exposes persisted operatorTriage & intact machine state.
  const reopened = reopen()
  const detail = reopened.runDetail(run.id)
  const confirmedRow = reopened.db.select().from(findings).where(eq(findings.id, confirmedId)).get()!
  const pendingRow = reopened.db.select().from(findings).where(eq(findings.id, pendingId)).get()!
  const floorRow = reopened.db.select().from(findings).where(eq(findings.id, floorId)).get()!

  assert.equal(confirmedRow.verificationClass, 'runtime_confirmed')
  assert.equal(confirmedRow.finding.status, 'confirmed')
  assert.equal(pendingRow.verificationClass, 'open_proof_gap')
  assert.equal(pendingRow.finding.status, 'pending')
  assert.equal((pendingRow.finding as TriagedFinding).operatorTriage?.status, 'confirmed_by_operator')
  assert.equal(floorRow.provenance, 'floor')
  assert.equal(floorRow.verificationClass, 'runtime_confirmed')

  const detailConfirmed = detail.findings.find(f => f.id === confirmedId) as TriagedFinding | undefined
  assert.equal(detailConfirmed?.operatorTriage?.status, 'false_positive')
  assert.equal(detailConfirmed?.operatorTriage?.notes, 'Edge WAF already blocks external callers.')
  assert.equal(detailConfirmed?.status, 'confirmed')

  // Audit events recorded.
  const triageEvents = reopened.db.select().from(events).where(eq(events.runId, run.id)).all()
    .filter(e => e.kind === 'finding.triaged')
  assert.equal(triageEvents.length, 4)

  // Confirmation-consistency invariant still demotes confirmed finding on inconclusive diff while preserving triage.
  reopened.incrementReplaySpecAttempt(confirmedSpec.id, feedback('inconclusive', 'probe returned 403'))
  const demotedRow = reopened.db.select().from(findings).where(eq(findings.id, confirmedId)).get()!
  assert.equal(demotedRow.finding.status, 'inconclusive')
  assert.equal(demotedRow.verificationClass, 'open_proof_gap')
  assert.equal((demotedRow.finding as TriagedFinding).operatorTriage?.status, 'false_positive')
  assert.equal(reopened.confirmationConflictCount(run.id), 1)

  // Validation guards.
  assert.throws(() => reopened.findingsRepo.triageFinding('missing-id', { status: 'fixed' }), /Finding not found/i)
  assert.throws(() => reopened.findingsRepo.triageFinding(pendingId, { status: 'bogus' as never }), /Invalid operator triage status/i)
  assert.throws(() => reopened.findingsRepo.triageFinding(pendingId, { severityOverride: 'urgent' as never }), /Invalid severity override/i)
})

test('updatePatchProposalReview persists status transitions and reviewNotes across reopen', async (t) => {
  const { getStore, reopen, run } = await setupFixture(t)
  const storage = getStore()

  const findingId = randomUUID()
  const created = storage.savePatchProposal({
    runId: run.id,
    findingId,
    repo: 'app-repo',
    status: 'draft',
    callerCompatibility: 'attacker_only',
    diff: '--- a/routes.ts\n+++ b/routes.ts\n@@ -1 +1 @@\n-allow()\n+deny()\n',
    codeLocations: [{ repo: 'app-repo', file: 'routes.ts', startLine: 10, endLine: 14 }],
    reviewNotes: 'Initial automated review.',
    dynamicRetestVerdict: 'fixed',
  })
  assert.equal(created.status, 'draft')

  const approved = storage.findingsRepo.updatePatchProposalReview(created.id, {
    status: 'approved',
    reviewNotes: 'Approved by security lead after verifying caller compatibility.',
  }, { runId: run.id })
  assert.equal(approved.status, 'approved')
  assert.equal(approved.reviewNotes, 'Approved by security lead after verifying caller compatibility.')
  assert.ok(approved.updatedAt >= created.updatedAt)

  const rejected = storage.findingsRepo.updatePatchProposalReview(created.id, {
    status: 'rejected',
    reviewNotes: 'Rejected: misses sibling admin route.',
  })
  assert.equal(rejected.status, 'rejected')
  assert.equal(rejected.reviewNotes, 'Rejected: misses sibling admin route.')

  // Resetting to 'pending' maps cleanly to domain 'draft' and preserves reviewNotes when omitted.
  const reset = storage.findingsRepo.updatePatchProposalReview(created.id, {
    status: 'pending',
  })
  assert.equal(reset.status, 'draft')
  assert.equal(reset.reviewNotes, 'Rejected: misses sibling admin route.')

  // Re-approve and check persistence across reopen + runDetail().
  storage.findingsRepo.updatePatchProposalReview(created.id, {
    status: 'approved',
    reviewNotes: 'Re-approved with sibling coverage confirmed.',
  })
  const reopened = reopen()
  const detail = reopened.runDetail(run.id)
  const persisted = detail.patchProposals.find(p => p.id === created.id)!
  assert.equal(persisted.status, 'approved')
  assert.equal(persisted.reviewNotes, 'Re-approved with sibling coverage confirmed.')

  const reviewEvents = reopened.db.select().from(events).where(eq(events.runId, run.id)).all()
    .filter(e => e.kind === 'patch.reviewed')
  assert.equal(reviewEvents.length, 4)

  assert.throws(() => reopened.findingsRepo.updatePatchProposalReview('missing-patch', { status: 'approved' }), /Patch proposal not found/i)
  assert.throws(() => reopened.findingsRepo.updatePatchProposalReview(created.id, { status: 'invalid' as never }), /Invalid patch proposal review status/i)
})

test('actions-triage and UI views wire triage bar, list badges, and patch proposal Approve/Reject controls', () => {
  const actionsTriageSrc = readRepoFile('src', 'actions-triage.ts')
  assert.match(actionsTriageSrc, /export const triageFindingAction = createServerFn/)
  assert.match(actionsTriageSrc, /export const reviewPatchProposalAction = createServerFn/)
  assert.match(actionsTriageSrc, /const db = store\(\)/)
  assert.match(actionsTriageSrc, /db\.findingsRepo\.triageFinding/)
  assert.match(actionsTriageSrc, /db\.findingsRepo\.updatePatchProposalReview/)

  const inspectorSrc = readRepoFile('src', 'components', 'run', 'views', 'findings-inspector.tsx')
  assert.match(inspectorSrc, /triageFindingAction/)
  assert.match(inspectorSrc, /reviewPatchProposalAction/)
  assert.match(inspectorSrc, /data-slot="finding-triage-bar"/)
  assert.match(inspectorSrc, /aria-label="Triage status"/)
  assert.match(inspectorSrc, /aria-label="Severity override"/)
  assert.match(inspectorSrc, /aria-label="Operator triage notes"/)
  assert.match(inspectorSrc, /export function PatchProposalReview/)
  assert.match(inspectorSrc, /aria-label="Patch review notes"/)
  assert.match(inspectorSrc, /Approve/)
  assert.match(inspectorSrc, /Reject/)

  const findingsSrc = readRepoFile('src', 'components', 'run', 'views', 'findings.tsx')
  assert.match(findingsSrc, /FindingTriageBadges/)
  assert.match(findingsSrc, /Accepted risk/)
  assert.match(findingsSrc, /False positive/)
  assert.match(findingsSrc, /Fixed/)

  const reportSrc = readRepoFile('src', 'components', 'run', 'views', 'report.tsx')
  assert.match(reportSrc, /PatchProposalReview/)
  assert.match(reportSrc, /<PatchProposalReview/)
})
