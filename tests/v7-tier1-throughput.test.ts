/**
 * v7 tier1-throughput-fix — unit tests for:
 *  1. Evidence-gated early exit on hardened 400/422 validation denials, repeated identical-body
 *     non-anomalous responses (`unchanged_response`), and immediate wrap-up after a confirmed
 *     `guardian_verify` proof (`proof_confirmed`).
 *  2. All 7 specialist `focusPrompt`s steering to `guardian_verify` with zero retired VM kinds.
 *  3. `scripts/smoke-agentic.ts` `resolveLiftBaseline` resolution chain (explicit scorecard ->
 *     snapshotRoot baseline -> default baseline -> cold-captured post-floor `snapshot.json`)
 *     without weakening `evaluateGates`.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  EARLY_EXIT_HARDENED_STATUSES,
  EARLY_EXIT_MIN_TURNS,
  EARLY_EXIT_UNCHANGED_MIN_ATTEMPTS,
  SPECIALIST_PROFILES,
  SpecSubmissionTracker,
  buildEarlyExitEvent,
  earlyExitDirectiveMessage,
  earlyExitEligible,
} from '../src/server/agent-session.ts'
import { evaluateGates, resolveLiftBaseline, type CellMetrics } from '../scripts/smoke-agentic.ts'

test('400/422 validation denials earn hardened_denial early exit when distinct and anomaly-free', () => {
  assert.ok(EARLY_EXIT_HARDENED_STATUSES.has(400))
  assert.ok(EARLY_EXIT_HARDENED_STATUSES.has(422))

  const tracker = new SpecSubmissionTracker()
  tracker.noteObservation({ method: 'POST', pathAndQuery: '/api/v1/orders?amount=-1', origin: 'https://app.example', status: 422, bodySha256: 'sha-1' })
  tracker.noteObservation({ method: 'POST', pathAndQuery: '/api/v1/orders?amount=0', origin: 'https://app.example', status: 400, bodySha256: 'sha-2' })

  const decision = earlyExitEligible({
    evidence: tracker.observationSnapshot(),
    turnsUsed: EARLY_EXIT_MIN_TURNS,
    maxTurns: 18,
  })
  assert.equal(decision.eligible, true)
  assert.equal(decision.eligible && decision.reason, 'hardened_denial')
})

test('repeated identical-body clean 2xx probes earn unchanged_response only at >=3 distinct attempts and 0 anomalies', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteObservation({ method: 'GET', pathAndQuery: '/api/v1/items?q=a', origin: 'https://app.example', status: 200, bodySha256: 'sha-same' })
  tracker.noteObservation({ method: 'GET', pathAndQuery: '/api/v1/items?q=b', origin: 'https://app.example', status: 200, bodySha256: 'sha-same' })

  // 2 attempts is not enough for unchanged_response on 2xx
  const two = earlyExitEligible({ evidence: tracker.observationSnapshot(), turnsUsed: 5, maxTurns: 18 })
  assert.equal(two.eligible, false)

  // 3rd distinct attempt with same body hash earns unchanged_response
  assert.equal(EARLY_EXIT_UNCHANGED_MIN_ATTEMPTS, 3)
  tracker.noteObservation({ method: 'GET', pathAndQuery: '/api/v1/items?q=c', origin: 'https://app.example', status: 200, bodySha256: 'sha-same' })
  const snap = tracker.observationSnapshot()
  const three = earlyExitEligible({ evidence: snap, turnsUsed: 5, maxTurns: 18 })
  assert.equal(three.eligible, true)
  assert.equal(three.eligible && three.reason, 'unchanged_response')

  const event = buildEarlyExitEvent({ reason: 'unchanged_response', evidence: snap, turnsUsed: 5, maxTurns: 18 })
  const directive = earlyExitDirectiveMessage({ ...event, proofTools: ['guardian_verify'] })
  assert.match(directive, /unchanged_response/)
  assert.match(directive, /identical non-anomalous response body/)

  // Diverging response body blocks unchanged_response
  tracker.noteObservation({ method: 'GET', pathAndQuery: '/api/v1/items?q=d', origin: 'https://app.example', status: 200, bodySha256: 'sha-different' })
  const diverged = earlyExitEligible({ evidence: tracker.observationSnapshot(), turnsUsed: 6, maxTurns: 18 })
  assert.equal(diverged.eligible, false)
})

test('confirmed guardian_verify proof earns immediate proof_confirmed early exit while respecting open blockers', () => {
  const tracker = new SpecSubmissionTracker()
  tracker.noteAssignedRoutes([{ method: 'GET', path: '/api/v1/admin/config', origin: 'https://app.example' }])
  tracker.noteVerifyScript('await ctx.prove_access_boundary({ path: "/api/v1/admin/config" })', [{ method: 'GET', path: '/api/v1/admin/config' }], { confirmed: true })
  assert.equal(tracker.hasConfirmedProof(), true)

  // Eligible even at turn 2 (below EARLY_EXIT_MIN_TURNS) so a confirmed worker finishes immediately
  const decision = earlyExitEligible({
    evidence: tracker.observationSnapshot(),
    turnsUsed: 2,
    maxTurns: 18,
    proofConfirmed: tracker.hasConfirmedProof(),
  })
  assert.equal(decision.eligible, true)
  assert.equal(decision.eligible && decision.reason, 'proof_confirmed')

  // Still blocked if another assigned target route remains unprobed
  const blocked = earlyExitEligible({
    evidence: tracker.observationSnapshot(),
    turnsUsed: 2,
    maxTurns: 18,
    proofConfirmed: true,
    unprobedAssignedRoutes: true,
  })
  assert.deepEqual(blocked, { eligible: false, blockedBy: 'unprobed_assigned_routes' })

  const event = buildEarlyExitEvent({ reason: 'proof_confirmed', evidence: tracker.observationSnapshot(), turnsUsed: 2, maxTurns: 18 })
  const directive = earlyExitDirectiveMessage({ ...event, proofTools: ['guardian_verify'] })
  assert.match(directive, /proof_confirmed/)
  assert.match(directive, /ProofReceipt/)
})

test('all 7 specialist focusPrompts steer to guardian_verify and avoid retired legacy VM kinds', () => {
  for (const [id, profile] of Object.entries(SPECIALIST_PROFILES)) {
    assert.match(profile.focusPrompt, /guardian_verify/, `${id} focusPrompt must mention guardian_verify`)
    assert.doesNotMatch(profile.focusPrompt, /\b(?:ws_chain|dns_takeover|tls_audit|browser_dom|upload_probe)\b/, `${id} must not cite retired VM kinds`)
  }
})

test('resolveLiftBaseline resolves cold post-floor snapshot counts and default baseline without weakening conversion gate', () => {
  const root = mkdtempSync(join(tmpdir(), 'guardian-lift-baseline-'))
  try {
    const snapRoot = join(root, 'run-snapshots')
    const defaultRoot = join(root, 'default-snapshots')
    const snapDir = join(snapRoot, 'acme-saas-seed1-grey-box')
    mkdirSync(snapDir, { recursive: true })

    // 1. Nothing present -> null (gate must still FAIL)
    assert.equal(
      resolveLiftBaseline({ snapshotRoot: snapRoot, defaultSnapshotRoot: defaultRoot, snapshotDir: snapDir, app: 'acme-saas', seed: 1, liftTargets: 22 }),
      null,
    )

    // 2. Cold run captures snapshot.json with runtimeConfirmed = 14 -> baselineConversion = 14/22
    writeFileSync(join(snapDir, 'snapshot.json'), JSON.stringify({ counts: { runtimeConfirmed: 14 } }))
    const fromSnap = resolveLiftBaseline({ snapshotRoot: snapRoot, defaultSnapshotRoot: defaultRoot, snapshotDir: snapDir, app: 'acme-saas', seed: 1, liftTargets: 22 })
    assert.ok(fromSnap)
    assert.equal(fromSnap.source, 'snapshot-counts')
    assert.equal(fromSnap.card.confirmed, 14)
    assert.ok(Math.abs((fromSnap.conversion ?? 0) - 14 / 22) < 1e-6)

    // Verify conversion gate passes when lift confirms 15/22 and fails if conversion drops >10pp
    const liftCell: CellMetrics = {
      id: 'lift', kind: 'lift', app: 'acme-saas', source: 'cold', targets: 22, confirmed: 15, precision: 1,
      decoyFalsePositives: 0, unmatchedFalsePositives: 0, netNew: 1, floorConfirmed: 14, floorPreserved: null,
      conversion: 15 / 22, costUsd: 0.25, p50AssignmentMs: 65_000, completedAssignments: 14, wallMs: 300_000, crashes: 0,
    }
    const passGates = new Map(evaluateGates({
      cells: [liftCell], liftBaseline: 0, baselineConversion: fromSnap.conversion, trapConfirmed: 0, rerunExecuted: false, perCellBudgetUsd: 0.8,
    }).map(g => [g.id, g.pass]))
    assert.equal(passGates.get('conversion'), true)

    const dropGates = new Map(evaluateGates({
      cells: [{ ...liftCell, confirmed: 10, conversion: 10 / 22 }], liftBaseline: 0, baselineConversion: fromSnap.conversion, trapConfirmed: 0, rerunExecuted: false, perCellBudgetUsd: 0.8,
    }).map(g => [g.id, g.pass]))
    assert.equal(dropGates.get('conversion'), false, 'conversion drop >10pp must still fail the gate')

    // 3. Default baseline takes precedence over snapshot-counts when present
    mkdirSync(join(defaultRoot, 'baseline'), { recursive: true })
    writeFileSync(join(defaultRoot, 'baseline', 'acme-saas-seed1-grey-box.json'), JSON.stringify({ targets: 22, confirmed: 13 }))
    const fromDefault = resolveLiftBaseline({ snapshotRoot: snapRoot, defaultSnapshotRoot: defaultRoot, snapshotDir: snapDir, app: 'acme-saas', seed: 1, liftTargets: 22 })
    assert.equal(fromDefault?.source, 'default-baseline')
    assert.equal(fromDefault?.card.confirmed, 13)

    // 4. Local snapshotRoot baseline takes precedence over default baseline
    mkdirSync(join(snapRoot, 'baseline'), { recursive: true })
    writeFileSync(join(snapRoot, 'baseline', 'acme-saas-seed1-grey-box.json'), JSON.stringify({ targets: 22, confirmed: 14 }))
    const fromLocal = resolveLiftBaseline({ snapshotRoot: snapRoot, defaultSnapshotRoot: defaultRoot, snapshotDir: snapDir, app: 'acme-saas', seed: 1, liftTargets: 22 })
    assert.equal(fromLocal?.source, 'snapshot-baseline')
    assert.equal(fromLocal?.card.confirmed, 14)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
