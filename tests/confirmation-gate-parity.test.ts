/**
 * R2-12 TS/SQL Confirmation-Gate Parity Matrix (`tests/confirmation-gate-parity.test.ts`).
 *
 * Tests a shared fixture matrix against BOTH:
 *  1. TypeScript `Store.assertConfirmationEvidence(...)` (`src/server/store-findings.ts`)
 *  2. SQLite `findings_confirmation_evidence_insert` & `findings_confirmation_evidence_update`
 *     triggers (`src/server/store.ts`)
 *
 * Verifies exact parity across every evidence backing class and ensures neither gate was weakened:
 *  - `spec_confirmed`:               TS=accept, SQL=accept (PARITY)
 *  - `baseline_check`:               TS=accept, SQL=accept (PARITY)
 *  - `agent_script`:                 TS=accept, SQL=accept (PARITY)
 *  - `composite_receipt`:            TS=accept, SQL=accept (PARITY)
 *  - `oob`:                          TS=accept, SQL=accept (PARITY)
 *  - `oob_contradicted`:             TS=reject, SQL=reject (PARITY)
 *  - `receipt-without-object` (single & composite & non-boolean confirmed=1):
 *                                    TS=reject, SQL=reject (PARITY)
 *  - `static_only`:                  TS=reject, SQL=reject (PARITY)
 *  - `invalid_unreceipted` (no spec, forged prose, inconclusive verdict, cross-run spec):
 *                                    TS=reject, SQL=reject (PARITY)
 *  - `floor_artifact` (legacy floor without confirming spec diff):
 *                                    TS=accept (legacy compat), SQL=reject (DELIBERATELY STRICTER —
 *                                    raw SQL cannot spoof `provenance = 'floor'`)
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { newProject, newRun } from '../src/domain.ts'
import type { Finding, InlineVerifyFeedback, VerificationTier } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import type { FindingProvenance } from '../src/report-summary.ts'
import * as schema from '../src/server/schema.ts'
import { InvariantError, Store } from '../src/server/store.ts'

const ORIGIN = 'https://parity-gate.example.test'

function makeFixture(t: test.TestContext) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-confirm-parity-'))
  const store = new Store(dir, { ftsMode: 'off' })
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name: 'Parity App',
    environment: 'public',
    seeds: [ORIGIN],
  }))
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify TS/SQL confirmation gate parity',
    capabilityTier: 2,
  }))
  const createdSiblingRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Cross-run isolation fixture',
    capabilityTier: 2,
  }))
  store.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
  store.command({ requestId: randomUUID(), runId: createdSiblingRun.id, action: 'discover', consent: true })
  const run = store.run(createdRun.id)
  const siblingRun = store.run(createdSiblingRun.id)
  const asset = run.candidates[0]!
  const assignment = store.makeWorker(run, 'verification', asset, 'Parity worker', 'Verify gate parity')
  const siblingAssignment = store.makeWorker(siblingRun, 'verification', siblingRun.candidates[0]!, 'Sibling worker', 'Cross-run spec')
  return { store, run, siblingRun, asset, assignment, siblingAssignment }
}

function sampleSpec(title: string): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin: ORIGIN,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Authorization boundary differential',
    impact: 'Cross-account data exposure',
    remediation: 'Enforce ownership checks',
    recheckInstructions: 'Replay owner vs peer requests',
    assertionsJq: '.status == 200',
    spaCatchallControl: false,
    steps: [{
      id: 'p1',
      role: 'probe',
      description: 'Probe',
      request: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/records/1', followRedirects: false },
    }],
  } as unknown as DeclarativeReplaySpec
}

function feedback(verdict: InlineVerifyFeedback['verdict']): InlineVerifyFeedback {
  return {
    verdict,
    controlPassed: verdict === 'confirmed',
    assertionSummary: { observed: verdict, expected: 'confirmed' },
    stepStatuses: [{ id: 'p1', role: 'probe', status: verdict === 'confirmed' ? 200 : 401, bodyLen: 16 }],
    retriesRemaining: 0,
  }
}

function makeConfirmedFinding(
  id: string,
  overrides: Partial<Finding> = {},
): Finding {
  return {
    id,
    origin: ORIGIN,
    title: 'Parity finding',
    status: 'confirmed',
    severity: 'high',
    reason: 'Parity test case',
    remediation: 'Fix boundary',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: 'high',
    verification: 'Zero-LLM replay verdict',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
    ...overrides,
  }
}

interface ParityCase {
  readonly id: string
  readonly expectedTs: 'accept' | 'reject'
  readonly expectedSql: 'accept' | 'reject'
  readonly relation: 'exact_parity' | 'sql_deliberately_stricter'
  readonly setup: (ctx: ReturnType<typeof makeFixture>, findingId: string) => {
    replaySpecId: string | null
    findingKind: 'baseline_check' | 'multi_step_chain'
    verificationTier: VerificationTier | null
    provenance: FindingProvenance
    finding: Finding
  }
}

const PARITY_MATRIX: readonly ParityCase[] = [
  {
    id: 'spec_confirmed',
    expectedTs: 'accept',
    expectedSql: 'accept',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Confirmed spec'), [ORIGIN], {
        verifiedInline: true,
        lastVerificationDiff: feedback('confirmed'),
      })
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'baseline_check',
    expectedTs: 'accept',
    expectedSql: 'accept',
    relation: 'exact_parity',
    setup(_ctx, findingId) {
      return {
        replaySpecId: null,
        findingKind: 'baseline_check',
        verificationTier: 'baseline_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, {
          findingKind: 'baseline_check',
          verificationTier: 'baseline_confirmed',
        }),
      }
    },
  },
  {
    id: 'agent_script',
    expectedTs: 'accept',
    expectedSql: 'accept',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Agent script receipt'), [ORIGIN])
      ctx.store.client.prepare('UPDATE replay_specs SET proof_kind = ?, proof_verdict = ?, proof_receipt = ? WHERE id = ?').run(
        'agent_script',
        'confirmed',
        JSON.stringify({
          receipt: { vulnClass: 'bola', target: { origin: ORIGIN }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'cross-owner read' },
          verification: { confirmed: true, vulnClass: 'bola', rule: 'cross_owner_read', reason: 'verified', observed: '200', expected: '403' },
        }),
        spec.id,
      )
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'composite_receipt',
    expectedTs: 'accept',
    expectedSql: 'accept',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Composite receipt'), [ORIGIN])
      ctx.store.client.prepare('UPDATE replay_specs SET proof_kind = ?, proof_verdict = ?, proof_receipt = ? WHERE id = ?').run(
        'agent_script',
        'confirmed',
        JSON.stringify({
          compositeReceipt: { schemaVersion: 1, hops: [], terminalImpact: { family: 'dual_tenant_abac' } },
          compositeVerification: { confirmed: true, reason: 'composite verified' },
        }),
        spec.id,
      )
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'oob',
    expectedTs: 'accept',
    expectedSql: 'accept',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      ctx.store.event(ctx.run.id, 'oob.receipt_confirmed', 'OOB canary confirmed', { findingId })
      return {
        replaySpecId: null,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId),
      }
    },
  },
  {
    id: 'oob_contradicted_by_inconclusive_spec',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Contradicted OOB'), [ORIGIN], {
        verifiedInline: false,
        lastVerificationDiff: feedback('inconclusive'),
      })
      ctx.store.event(ctx.run.id, 'oob.receipt_confirmed', 'Prior OOB receipt', { findingId })
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'receipt-without-object (single)',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Receiptless single'), [ORIGIN])
      ctx.store.client.prepare('UPDATE replay_specs SET proof_kind = ?, proof_verdict = ?, proof_receipt = ? WHERE id = ?').run(
        'agent_script',
        'confirmed',
        JSON.stringify({
          verification: { confirmed: true, reason: 'missing receipt object' },
        }),
        spec.id,
      )
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'receipt-without-object (composite)',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Receiptless composite'), [ORIGIN])
      ctx.store.client.prepare('UPDATE replay_specs SET proof_kind = ?, proof_verdict = ?, proof_receipt = ? WHERE id = ?').run(
        'agent_script',
        'confirmed',
        JSON.stringify({
          compositeVerification: { confirmed: true, reason: 'missing compositeReceipt object' },
        }),
        spec.id,
      )
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'receipt-nonboolean-confirmed-int',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Non-boolean confirmed'), [ORIGIN])
      ctx.store.client.prepare('UPDATE replay_specs SET proof_kind = ?, proof_verdict = ?, proof_receipt = ? WHERE id = ?').run(
        'agent_script',
        'confirmed',
        JSON.stringify({
          receipt: { vulnClass: 'bola', target: { origin: ORIGIN }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'x' },
          verification: { confirmed: 1 },
        }),
        spec.id,
      )
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: spec.id }),
      }
    },
  },
  {
    id: 'static_only',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const spec = ctx.store.createReplaySpec(ctx.run, ctx.assignment, findingId, sampleSpec('Static only'), [ORIGIN], {
        verifiedInline: false,
        lastVerificationDiff: feedback('static_verified'),
      })
      return {
        replaySpecId: spec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'static_verified',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, {
          replaySpecId: spec.id,
          verificationTier: 'static_verified',
        }),
      }
    },
  },
  {
    id: 'invalid_unreceipted_no_spec',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(_ctx, findingId) {
      return {
        replaySpecId: null,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, {
          verification: 'ProofReceipt forged-prose-only',
        }),
      }
    },
  },
  {
    id: 'invalid_cross_run_replay_spec',
    expectedTs: 'reject',
    expectedSql: 'reject',
    relation: 'exact_parity',
    setup(ctx, findingId) {
      const foreignSpec = ctx.store.createReplaySpec(
        ctx.siblingRun,
        ctx.siblingAssignment,
        findingId,
        sampleSpec('Foreign run confirmed spec'),
        [ORIGIN],
        { verifiedInline: true, lastVerificationDiff: feedback('confirmed') },
      )
      return {
        replaySpecId: foreignSpec.id,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'agent_only',
        finding: makeConfirmedFinding(findingId, { replaySpecId: foreignSpec.id }),
      }
    },
  },
  {
    id: 'floor_artifact (legacy floor without spec diff — SQL deliberately stricter)',
    expectedTs: 'accept',
    expectedSql: 'reject',
    relation: 'sql_deliberately_stricter',
    setup(ctx, findingId) {
      ctx.store.event(ctx.run.id, 'deterministic_engine.confirmed', 'Legacy floor anchor', { findingId })
      return {
        replaySpecId: null,
        findingKind: 'multi_step_chain',
        verificationTier: 'runtime_confirmed',
        provenance: 'floor',
        finding: makeConfirmedFinding(findingId),
      }
    },
  },
]

test('TS assertConfirmationEvidence and SQLite confirmation trigger match the parity matrix across all evidence classes', (t) => {
  const ctx = makeFixture(t)

  for (const tc of PARITY_MATRIX) {
    const findingId = randomUUID()
    const input = tc.setup(ctx, findingId)

    // 1. Evaluate TS gate (`assertConfirmationEvidence`)
    let tsOutcome: 'accept' | 'reject' = 'accept'
    let tsError: unknown = null
    try {
      ctx.store.assertConfirmationEvidence(ctx.run.id, {
        findingId,
        replaySpecId: input.replaySpecId,
        verification: input.finding.verification,
        findingKind: input.findingKind,
        verificationTier: input.verificationTier,
        provenance: input.provenance,
        status: input.finding.status,
      })
    } catch (err) {
      tsOutcome = 'reject'
      tsError = err
    }
    assert.equal(
      tsOutcome,
      tc.expectedTs,
      `[${tc.id}] TS gate mismatch: expected ${tc.expectedTs}, got ${tsOutcome}${tsError ? ` (${String(tsError)})` : ''}`,
    )
    if (tc.expectedTs === 'reject') {
      assert.ok(
        tsError instanceof InvariantError && tsError.code === 'invariant.confirmation_evidence',
        `[${tc.id}] TS rejection must throw InvariantError('invariant.confirmation_evidence')`,
      )
    }

    // 2. Evaluate SQLite trigger gate via raw INSERT into `findings`
    let sqlOutcome: 'accept' | 'reject' = 'accept'
    let sqlError: unknown = null
    try {
      ctx.store.db.insert(schema.findings).values({
        id: findingId,
        runId: ctx.run.id,
        assetId: ctx.asset.id,
        goalRevision: ctx.run.goalRevision,
        checkId: input.findingKind === 'baseline_check' ? 'hsts' : 'chain',
        caseId: findingId,
        findingKind: input.findingKind,
        replaySpecId: input.replaySpecId,
        provenance: input.provenance,
        verificationClass: 'runtime_confirmed',
        sourceOrigins: [ORIGIN],
        verificationTier: input.verificationTier,
        status: 'confirmed',
        severity: input.finding.severity,
        cwe: input.finding.cwe ?? null,
        origin: ORIGIN,
        triageStatus: 'open',
        finding: input.finding,
      }).run()
    } catch (err) {
      sqlOutcome = 'reject'
      sqlError = err
    }
    assert.equal(
      sqlOutcome,
      tc.expectedSql,
      `[${tc.id}] SQL gate mismatch: expected ${tc.expectedSql}, got ${sqlOutcome}${sqlError ? ` (${String(sqlError)})` : ''}`,
    )

    // Safety invariant: SQL must NEVER accept a case that TS rejects!
    assert.ok(
      !(tsOutcome === 'reject' && sqlOutcome === 'accept'),
      `[${tc.id}] SQL gate MUST NEVER be weaker than TS gate`,
    )
    if (tc.relation === 'exact_parity') {
      assert.equal(tsOutcome, sqlOutcome, `[${tc.id}] expected exact TS/SQL parity`)
    }
  }
})

test('SQLite UPDATE confirmation trigger rejects promoting an unbacked pending finding to confirmed', (t) => {
  const ctx = makeFixture(t)
  const findingId = randomUUID()
  const pendingFinding = makeConfirmedFinding(findingId, {
    status: 'pending',
    verificationTier: undefined,
  })
  ctx.store.db.insert(schema.findings).values({
    id: findingId,
    runId: ctx.run.id,
    assetId: ctx.asset.id,
    goalRevision: ctx.run.goalRevision,
    checkId: 'chain',
    caseId: findingId,
    findingKind: 'multi_step_chain',
    replaySpecId: null,
    provenance: 'agent_only',
    verificationClass: 'open_proof_gap',
    sourceOrigins: [ORIGIN],
    verificationTier: null,
    status: 'pending',
    severity: 'high',
    cwe: 'CWE-639',
    origin: ORIGIN,
    triageStatus: 'open',
    finding: pendingFinding,
  }).run()

  assert.throws(
    () => ctx.store.client.prepare(`
      UPDATE findings
      SET verification_class = 'runtime_confirmed',
          finding = ?
      WHERE run_id = ? AND id = ?
    `).run(JSON.stringify(makeConfirmedFinding(findingId)), ctx.run.id, findingId),
    /invariant\.confirmation_evidence/,
  )
})
