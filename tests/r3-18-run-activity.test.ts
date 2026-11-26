/**
 * R3-18 Verification Suite (`tests/r3-18-run-activity.test.ts`):
 *  1. Paused run with parked `waiting_approval` worker: `isRunActive` is false, `runActivity`
 *     reports `hasLiveWork: false`, `hasParkedApprovals: true`, `blockingReasons: ['parked_approvals']`,
 *     and `deleteRunWithActiveGuard` refuses unconfirmed delete while confirming with `stopActive: true`.
 *  2. Report step metrics & `glyphs.tsx` derived directly from `STEP_STATUS` (`turn_capped`,
 *     `model_failure`, `infra_failed`, `nudged_out`, `rotated_partial`).
 *  3. `deriveRunActivity` shipped identically on `RunDetail`, `ProjectDetail`, and `Store.runActivity`.
 *  4. Triage-aware confirmed SQL predicate (`operatorConfirmedFindingPredicateSql`) 1:1 parity
 *     with `projectRunFindings(...).counts.confirmed` across workspace & project rollups.
 *  5. Terminal `projectRunFindings` collapsible-duplicate fixture: duplicate multi-step chains &
 *     multiple baseline HTTP header hygiene findings collapse identically across `projectRunFindings`,
 *     `buildVerdict`, `reportHighlights`, `exportReportMarkdown`, and `buildSarifLog`.
 *  6. `scripts/check-exhaustive.ts` catches missing branches / missing `assertNever` and passes on repo.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import ts from 'typescript'
import {
  checkExhaustiveSource,
  loadDefaultGuardedUnions,
  runExhaustiveCheck,
} from '../scripts/check-exhaustive.ts'
import { buildVerdict } from '../src/components/run/model.ts'
import type { Detail, FindingRow } from '../src/components/run/model.ts'
import { newProject, newRun } from '../src/domain.ts'
import type { Finding, InlineVerifyFeedback, ReportBody } from '../src/domain.ts'
import { projectRunFindings } from '../src/findings-view.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { reportHighlights } from '../src/report-summary.ts'
import { FindingCodec } from '../src/server/finding-codec.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import {
  deriveRunActivity,
  isRunDeleteBlocked,
  isRunInProgress,
  summarizeReportChainSteps,
} from '../src/server/run-status.ts'
import { buildSarifLog, exportReportSarif } from '../src/server/sarif-export.ts'
import {
  Store,
  deleteProjectWithActiveGuard,
  deleteRunWithActiveGuard,
  type DeleteExecutionControl,
  type DeleteLabControl,
} from '../src/server/store.ts'
import { STEP_STATUS, chainStepStatuses } from '../src/step-status.ts'

const TEST_ORIGIN = 'https://r3-18-qa.example.test'

function makeTempStore(t: TestContext, prefix = 'kovo-r3-18-'): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { dir, store }
}

function setupApprovedRun(store: Store, name = 'R3-18 App', origin = TEST_ORIGIN) {
  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [origin],
  }))
  const created = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: `Assess ${name}`,
    capabilityTier: 3,
  }))
  store.command({ requestId: randomUUID(), runId: created.id, action: 'discover', consent: true })
  const discovered = store.run(created.id)
  store.command({
    requestId: randomUUID(),
    runId: created.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 3,
  })
  const run = store.run(created.id)
  const asset = run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'R3-18 Worker', 'Verify controls')
  return { projectId: project.id, runId: run.id, run, asset, worker }
}

function sampleHttpSpec(title: string, origin = TEST_ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Authorization boundary bypass',
    impact: 'Cross-account record read',
    remediation: 'Enforce strict resource ownership validation',
    recheckInstructions: 'Replay control vs variant requests',
    assertionsJq: '.status == 200',
    spaCatchallControl: false,
    steps: [{
      id: 'probe-1',
      role: 'probe',
      description: 'Read foreign resource',
      request: { origin, method: 'GET', pathAndQuery: '/api/items/42', followRedirects: false },
    }],
  } as unknown as DeclarativeReplaySpec
}

function sampleStaticSpec(title: string, origin = TEST_ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'static_ast_proof',
    origin,
    title,
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'medium',
    severityRationale: 'Static query interpolation pattern',
    impact: 'Potential untrusted query composition',
    remediation: 'Use parameterized query bindings',
    recheckInstructions: 'Re-run static AST check',
    engine: 'ast-grep',
    repo: 'app',
    file: 'src/db.ts',
    startLine: 12,
    endLine: 16,
    rulePattern: 'db.query($X)',
    runtimeProofGap: 'Verified via static AST match only.',
  } as unknown as DeclarativeReplaySpec
}

function confirmedFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    controlPassed: true,
    assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
    stepStatuses: [{ id: 'probe-1', role: 'probe', status: 200, bodyLen: 32 }],
    retriesRemaining: 0,
  }
}

function staticFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'static_verified',
    verificationTier: 'static_verified',
    controlPassed: true,
    assertionSummary: { observed: 'ast-match', expected: 'ast-match' },
    stepStatuses: [],
    retriesRemaining: 0,
  }
}

describe('R3-18: Single derived RunActivity & paused-run parked-approval handling', () => {
  test('paused run with parked waiting_approval row is NOT active work, but blocks unconfirmed delete via blockingReasons', async t => {
    const { store } = makeTempStore(t, 'kovo-r3-18-parked-')
    const { projectId, runId, run, worker } = setupApprovedRun(store, 'Parked Approval App')

    // Park the worker waiting on an approval, then pause the run (pause preserves parked waiting_approval rows).
    store.parkWorkerForApproval(run, worker.id)
    store.command({ requestId: randomUUID(), runId, action: 'pause' })

    const pausedRun = store.run(runId)
    assert.equal(pausedRun.status, 'paused')
    const parkedWorker = store.worker(worker.id)
    assert.equal(parkedWorker.status, 'waiting_approval')
    assert.ok(parkedWorker.approvalParkedAt !== null, 'parked approval timestamp must be preserved across pause')

    // Core R3-18 bug fix: parked waiting_approval on paused run MUST NOT count as active live work.
    assert.equal(store.isRunActive(runId), false, 'paused run with parked approval must NOT report isRunActive=true')

    const activity = store.runActivity(runId)
    assert.equal(activity.lifecycle, 'paused')
    assert.equal(activity.hasLiveWork, false)
    assert.equal(activity.hasParkedApprovals, true)
    assert.equal(isRunDeleteBlocked(activity), true)
    assert.ok(
      activity.blockingReasons.some(reason => reason.code === 'parked_approvals'),
      `expected blockingReasons to include parked_approvals, got: ${JSON.stringify(activity.blockingReasons)}`,
    )

    // RunDetail and ProjectDetail must ship the exact same derived RunActivity.
    const detail = store.runDetail(runId)
    assert.deepEqual(detail.activity, activity)

    const projDetail = store.projectDetail(projectId)
    const projRun = projDetail.runs.find(r => r.id === runId)!
    assert.ok(projRun)
    assert.equal(projRun.isActive, false)
    assert.deepEqual(projRun.activity, activity)
    assert.equal(isRunInProgress(projRun.activity), true, 'paused non-terminal run stays in-progress')
    assert.equal(isRunDeleteBlocked(projRun.activity), true, 'parked approval blocks unconfirmed delete')

    // Delete guard must refuse silently discarding a parked operator approval unless stopActive: true.
    const mockExec: DeleteExecutionControl = {
      wake: () => undefined,
      getLabTargetHandle: () => undefined,
    }
    const mockLab: DeleteLabControl = {
      getTarget: () => undefined,
      stopLabTarget: async () => undefined,
    }

    await assert.rejects(
      () => deleteRunWithActiveGuard(store, mockExec, mockLab, { runId }),
      /parked approval/i,
      'Unconfirmed delete of paused run with parked approval must require explicit confirmation',
    )
    await assert.rejects(
      () => deleteProjectWithActiveGuard(store, mockExec, mockLab, { projectId }),
      /parked approval/i,
      'Unconfirmed project delete with parked approval must require explicit confirmation',
    )

    // Confirmed Stop & Delete cleanly stops the run, settles parked approval, and deletes without busy timeout.
    const deleted = await deleteRunWithActiveGuard(store, mockExec, mockLab, {
      runId,
      stopActive: true,
      waitTimeoutMs: 500,
    })
    assert.deepEqual(deleted, { deleted: true, projectId, runId })
  })

  test('deriveRunActivity separates live work, parked approvals, lab containers, and terminal runs cleanly', () => {
    const running = deriveRunActivity({ status: 'running', runningAssignments: 2, parkedApprovalAssignments: 1 })
    assert.equal(running.hasLiveWork, true)
    assert.equal(running.hasParkedApprovals, true)
    assert.deepEqual(running.blockingReasons.map(r => r.code), ['run_running', 'live_workers', 'parked_approvals'])

    const pausedWithParked = deriveRunActivity({ status: 'paused', runningAssignments: 0, parkedApprovalAssignments: 1 })
    assert.equal(pausedWithParked.hasLiveWork, false)
    assert.equal(pausedWithParked.hasParkedApprovals, true)
    assert.deepEqual(pausedWithParked.blockingReasons.map(r => r.code), ['parked_approvals'])

    const pausedClean = deriveRunActivity({ status: 'paused' })
    assert.equal(pausedClean.hasLiveWork, false)
    assert.equal(pausedClean.hasParkedApprovals, false)
    assert.deepEqual(pausedClean.blockingReasons, [])

    const complete = deriveRunActivity({ status: 'complete', parkedApprovalAssignments: 2 })
    assert.equal(complete.hasLiveWork, false)
    assert.equal(complete.hasParkedApprovals, false)
    assert.deepEqual(complete.blockingReasons, [])
  })
})

describe('R3-18: STEP_STATUS-driven report step metrics & glyphs.tsx rendering', () => {
  test('summarizeReportChainSteps and writeReport count turn_capped, model_failure, infra_failed, nudged_out, rotated_partial from STEP_STATUS', t => {
    const summary = summarizeReportChainSteps([
      { status: 'complete' },
      { status: 'pending' },
      { status: 'turn_capped' },
      { status: 'model_failure' },
      { status: 'infra_failed' },
      { status: 'nudged_out' },
      { status: 'rotated_partial' },
      { status: 'tainted' },
    ])
    assert.equal(summary.completed, 1)
    assert.equal(summary.tainted, 1)
    assert.equal(summary.untested, 6, 'all non-complete, non-tainted active/lost-work STEP_STATUS entries count as untested')
    assert.equal(summary.incompleteByStatus.turn_capped, 1)
    assert.equal(summary.incompleteByStatus.model_failure, 1)
    assert.equal(summary.incompleteByStatus.infra_failed, 1)

    // End-to-end Store.writeReport persists STEP_STATUS-derived metrics & gap copy.
    const { store } = makeTempStore(t, 'kovo-r3-18-steps-')
    const { runId, run, asset } = setupApprovedRun(store, 'Step Metrics App')
    const s1 = store.addChainStep(run, { title: 'Step complete', hypothesis: 'H1', targetAssetIds: [asset.id] })
    const s2 = store.addChainStep(run, { title: 'Step turn capped', hypothesis: 'H2', targetAssetIds: [asset.id] })
    const s3 = store.addChainStep(run, { title: 'Step model failure', hypothesis: 'H3', targetAssetIds: [asset.id] })
    const s4 = store.addChainStep(run, { title: 'Step infra failed', hypothesis: 'H4', targetAssetIds: [asset.id] })
    store.updateChainStep(s1.id, { status: 'complete' })
    store.updateChainStep(s2.id, { status: 'turn_capped' })
    store.updateChainStep(s3.id, { status: 'model_failure' })
    store.updateChainStep(s4.id, { status: 'infra_failed' })

    const reportId = store.writeReport(store.run(runId), false)
    const report = store.runDetail(runId).reports.find(r => r.id === reportId)!
    assert.equal(report.body.metrics?.chainStepsCompleted, 1)
    assert.equal(report.body.metrics?.chainStepsUntested, 3, 'turn_capped + model_failure + infra_failed must be counted as untested')
    assert.ok(
      report.body.gaps.some(g => g.includes('3 planned investigation steps remained untested')),
      `expected gap copy mentioning 3 untested steps, got: ${JSON.stringify(report.body.gaps)}`,
    )
  })

  test('glyphs.tsx derives every ChainStepStatus exhaustively from STEP_STATUS (including turn_capped, model_failure, infra_failed)', () => {
    const glyphsPath = join(import.meta.dirname, '..', 'src', 'components', 'run', 'glyphs.tsx')
    const source = readFileSync(glyphsPath, 'utf8')
    const sf = ts.createSourceFile(glyphsPath, source, ts.ScriptTarget.Latest, true)
    const handledStepCases = new Set<string>()
    let hasAssertNever = false

    function visit(node: ts.Node): void {
      if (ts.isFunctionDeclaration(node) && node.name?.text === 'renderStepStatusGlyph') {
        const walkFn = (n: ts.Node) => {
          if (ts.isSwitchStatement(n)) {
            for (const clause of n.caseBlock.clauses) {
              if (ts.isDefaultClause(clause)) {
                hasAssertNever = clause.getText(sf).includes('assertNever')
              } else if (ts.isStringLiteral(clause.expression)) {
                handledStepCases.add(clause.expression.text)
              }
            }
          }
          ts.forEachChild(n, walkFn)
        }
        walkFn(node)
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)

    assert.equal(hasAssertNever, true, 'renderStepStatusGlyph must enforce assertNever in default clause')
    for (const status of chainStepStatuses) {
      assert.equal(
        handledStepCases.has(status),
        true,
        `glyphs.tsx renderStepStatusGlyph must explicitly handle STEP_STATUS entry "${status}" (glyph=${STEP_STATUS[status].glyph})`,
      )
    }
  })
})

describe('R3-18: Triage-aware SQL/TS confirmed parity & terminal projectRunFindings dedupe/collapse', () => {
  test('TS/SQL parity: operatorConfirmedFindingPredicateSql matches projectRunFindings().counts.confirmed across every triage/status combo', t => {
    const { store } = makeTempStore(t, 'kovo-r3-18-parity-')
    const { projectId, runId, run, asset, worker } = setupApprovedRun(store, 'Parity App')

    const addEv = (label: string) => store.addArtifact(run, worker, 'replay', label, JSON.stringify({ origin: TEST_ORIGIN })).id

    const addConfirmedChain = (title: string, fp: string) => {
      const id = randomUUID()
      const spec = store.createReplaySpec(run, worker, id, sampleHttpSpec(title), [TEST_ORIGIN], {
        verifiedInline: true,
        lastVerificationDiff: confirmedFeedback(),
      })
      store.upsertChainFinding(run, asset.id, {
        id,
        origin: TEST_ORIGIN,
        title,
        status: 'confirmed',
        severity: 'high',
        category: 'broken-access-control',
        cwe: 'CWE-639',
        reason: title,
        remediation: 'Enforce ownership checks',
        evidenceIds: [addEv(title)],
        scopeRevision: run.scopeRevision,
        verificationTier: 'runtime_confirmed',
        fingerprintHash: fp,
      }, spec.id, [TEST_ORIGIN])
      return id
    }

    const openConfirmedId = addConfirmedChain('Open Confirmed IDOR', 'fp-parity-open')
    const opConfirmedId = addConfirmedChain('Operator Confirmed IDOR', 'fp-parity-opconf')
    const fixedConfirmedId = addConfirmedChain('Fixed Confirmed IDOR', 'fp-parity-fixed')
    const fpId = addConfirmedChain('False Positive IDOR', 'fp-parity-fp')
    const acceptedId = addConfirmedChain('Accepted Risk IDOR', 'fp-parity-accepted')
    const supersededId = addConfirmedChain('Superseded IDOR', 'fp-parity-superseded')

    // Static advisory (must NOT be counted as confirmed in SQL or TS)
    const staticId = randomUUID()
    const staticSpec = store.createReplaySpec(run, worker, staticId, sampleStaticSpec('Static SQL Sink'), [TEST_ORIGIN], {
      verifiedInline: true,
      lastVerificationDiff: staticFeedback(),
    })
    store.upsertChainFinding(run, asset.id, {
      id: staticId,
      origin: TEST_ORIGIN,
      title: 'Static SQL Sink',
      status: 'static_verified',
      severity: 'medium',
      category: 'injection-input',
      cwe: 'CWE-89',
      reason: 'Static sink',
      remediation: 'Parameterize query',
      evidenceIds: [addEv('static')],
      scopeRevision: run.scopeRevision,
      verificationTier: 'static_verified',
      fingerprintHash: 'fp-parity-static',
    }, staticSpec.id, [TEST_ORIGIN])

    // Apply operator triage overlays & supersession
    const scoped = store.forTenant('default')
    scoped.triageFinding(openConfirmedId, { status: 'open' }, { runId })
    scoped.triageFinding(opConfirmedId, { status: 'confirmed_by_operator' }, { runId })
    scoped.triageFinding(fixedConfirmedId, { status: 'fixed' }, { runId })
    scoped.triageFinding(fpId, { status: 'false_positive', notes: 'benign decoy' }, { runId })
    scoped.triageFinding(acceptedId, { status: 'accepted_risk', notes: 'accepted' }, { runId })
    store.client.prepare('UPDATE findings SET superseded_by_finding_id = ? WHERE id = ?').run(openConfirmedId, supersededId)

    // 1. TS projection count
    const detail = store.runDetail(runId)
    const tsView = projectRunFindings(detail.findings, {
      approvedOrigins: [TEST_ORIGIN],
      approvedAssetIds: [asset.id],
    })
    assert.equal(tsView.counts.confirmed, 3, 'open + confirmed_by_operator + fixed = 3 operator-confirmed findings')
    assert.equal(tsView.counts.suppressed, 2, 'false_positive + accepted_risk = 2 suppressed findings')
    assert.equal(tsView.counts.advisories, 1, 'static_verified = 1 advisory')

    // 2. SQL triage-aware twin count
    const sqlOpConfirmed = FindingCodec.countOperatorConfirmedForRun(store.client, runId)
    assert.equal(sqlOpConfirmed, tsView.counts.confirmed, 'SQL operator-confirmed count must match projectRunFindings().counts.confirmed 1:1')

    // 3. Machine-confirmed count remains scorer-independent (5 non-superseded runtime-confirmed rows)
    assert.equal(FindingCodec.countConfirmedForRun(store.client, runId), 5)

    // 4. Operator SQL rollups in workspaceSummary and projectDetail match TS projection 1:1
    const ws = store.workspaceSummary()
    const wsProj = ws.projects.find(p => p.id === projectId)!
    assert.equal(wsProj.latestRun?.confirmedCount, tsView.counts.confirmed, 'workspaceSummary.latestRun.confirmedCount must match TS projection')
    assert.equal(ws.recentRuns.find(r => r.id === runId)?.confirmedCount, tsView.counts.confirmed, 'workspaceSummary.recentRuns.confirmedCount must match TS projection')

    const pd = store.projectDetail(projectId)
    assert.equal(pd.runs.find(r => r.id === runId)?.confirmedCount, tsView.counts.confirmed, 'projectDetail.runs.confirmedCount must match TS projection')
  })

  test('Collapsible-duplicate fixture: projectRunFindings dedupes chains & collapses baseline headers identically across all surfaces', t => {
    const { store } = makeTempStore(t, 'kovo-r3-18-dedupe-')
    const { runId, run, asset, worker } = setupApprovedRun(store, 'Dedupe Fixture App')
    const ev1 = store.addArtifact(run, worker, 'replay', 'ev-1', JSON.stringify({ origin: TEST_ORIGIN })).id
    const ev2 = store.addArtifact(run, worker, 'replay', 'ev-2', JSON.stringify({ origin: TEST_ORIGIN })).id

    // Collapsible pair 1: two multi_step_chain findings sharing origin-wide CWE-942 (CORS)
    const chainDupA: Finding = {
      id: randomUUID(),
      origin: TEST_ORIGIN,
      title: 'Permissive CORS on /api/v1/profile',
      status: 'confirmed',
      severity: 'high',
      reason: 'Reflected arbitrary origin with credentials',
      remediation: 'Restrict Access-Control-Allow-Origin to allowlist',
      impact: 'Cross-origin session data theft',
      recheck: 'Replay cross-origin fetch',
      category: 'cors-client-side',
      cwe: 'CWE-942',
      confidence: 'high',
      verification: 'Confirmed via replay',
      findingKind: 'multi_step_chain',
      verificationTier: 'runtime_confirmed',
      evidenceIds: [ev1],
      scopeRevision: run.scopeRevision,
      fingerprintHash: 'fp-cors-1',
    }
    const chainDupB: Finding = {
      ...chainDupA,
      id: randomUUID(),
      title: 'Permissive CORS on /api/v1/orders',
      severity: 'medium',
      evidenceIds: [ev2],
      fingerprintHash: 'fp-cors-2',
    }

    // Collapsible pair 2: two baseline HTTP security-header hygiene findings on the same origin
    const headerCsp: Finding = {
      id: randomUUID(),
      origin: TEST_ORIGIN,
      title: 'Content Security Policy is not enforced',
      status: 'confirmed',
      severity: 'low',
      reason: 'Missing Content-Security-Policy header',
      remediation: 'Add a restrictive Content-Security-Policy header.',
      impact: 'Reduced client-side defense in depth',
      recheck: 'Inspect response headers',
      category: 'Browser hardening',
      cwe: 'CWE-693',
      confidence: 'high',
      verification: 'Header check',
      findingKind: 'baseline_check',
      evidenceIds: [ev1],
      scopeRevision: run.scopeRevision,
      check: { id: 'content-security-policy', caseId: 'csp', observed: 'missing', expected: 'present' },
    }
    const headerNosniff: Finding = {
      ...headerCsp,
      id: randomUUID(),
      title: 'MIME sniffing protection missing',
      severity: 'informational',
      reason: 'Missing X-Content-Type-Options: nosniff',
      remediation: 'Set X-Content-Type-Options: nosniff.',
      evidenceIds: [ev2],
      check: { id: 'nosniff', caseId: 'nosniff', observed: 'missing', expected: 'nosniff' },
    }

    const rawFindings = [chainDupA, chainDupB, headerCsp, headerNosniff]

    // 1. Direct projectRunFindings collapses 4 raw rows -> 2 canonical confirmed findings (1 CORS chain + 1 consolidated header posture)
    const direct = projectRunFindings(rawFindings, { approvedOrigins: [TEST_ORIGIN] })
    assert.equal(direct.counts.confirmed, 2, '2 duplicate CORS chains + 2 header hygiene rows must collapse to 2 confirmed findings')
    assert.equal(direct.counts.reportable, 2)
    assert.equal(direct.confirmed.some(item => item.finding.title.startsWith('HTTP Security Header Posture (2 header gaps)')), true)
    assert.equal(direct.confirmed.filter(item => item.finding.cwe === 'CWE-942').length, 1)

    // 2. buildVerdict agrees (2 confirmed)
    const detail = store.runDetail(runId) as unknown as Detail
    const verdict = buildVerdict(detail, rawFindings as unknown as FindingRow[], false)
    assert.equal(verdict.confirmed, 2)
    assert.equal(verdict.reportable, 2)

    // 3. reportHighlights agrees (2 confirmed, 1 chainConfirmed, 1 headerPostureCount)
    const reportBody: ReportBody = {
      goal: run.goal,
      capabilityTier: run.capabilityTier,
      scope: run.candidates,
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      coverage: [],
      findings: rawFindings,
      gaps: [],
    }
    const highlights = reportHighlights(reportBody)
    assert.equal(highlights.confirmed, 2)
    assert.equal(highlights.chainConfirmed, 1)
    assert.equal(highlights.headerPostureCount, 1)

    // 4. buildSarifLog agrees (2 confirmed, 2 reportable — without post-projection dedupe!)
    const sarif = buildSarifLog({
      runId,
      reportVersion: 1,
      goal: run.goal,
      capabilityTier: run.capabilityTier,
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      approvedOrigins: [TEST_ORIGIN],
      findings: rawFindings,
    })
    assert.equal(sarif.runs[0]!.properties.confirmedCount, 2)
    assert.equal(sarif.runs[0]!.properties.reportableCount, 2)
    assert.equal(sarif.runs[0]!.results.length, 2)

    // 5. Markdown export agrees (persisted report + live export)
    const specA = store.createReplaySpec(run, worker, chainDupA.id, sampleHttpSpec(chainDupA.title), [TEST_ORIGIN], {
      verifiedInline: true,
      lastVerificationDiff: confirmedFeedback(),
    })
    const specB = store.createReplaySpec(run, worker, chainDupB.id, sampleHttpSpec(chainDupB.title), [TEST_ORIGIN], {
      verifiedInline: true,
      lastVerificationDiff: confirmedFeedback(),
    })
    store.upsertChainFinding(run, asset.id, chainDupA, specA.id, [TEST_ORIGIN])
    store.upsertChainFinding(run, asset.id, chainDupB, specB.id, [TEST_ORIGIN])
    store.upsertFindingRecord({
      runId,
      assetId: asset.id,
      goalRevision: run.goalRevision,
      findingId: headerCsp.id,
      checkId: headerCsp.check!.id,
      caseId: headerCsp.check!.caseId!,
      findingKind: 'baseline_check',
      sourceOrigins: [TEST_ORIGIN],
      verificationTier: 'baseline_confirmed',
      verificationClass: 'runtime_confirmed',
      finding: headerCsp,
    })
    store.upsertFindingRecord({
      runId,
      assetId: asset.id,
      goalRevision: run.goalRevision,
      findingId: headerNosniff.id,
      checkId: headerNosniff.check!.id,
      caseId: headerNosniff.check!.caseId!,
      findingKind: 'baseline_check',
      sourceOrigins: [TEST_ORIGIN],
      verificationTier: 'baseline_confirmed',
      verificationClass: 'runtime_confirmed',
      finding: headerNosniff,
    })
    const reportId = store.writeReport(store.run(runId), false)
    const md = exportReportMarkdown(store, runId, reportId).content
    assert.ok(md.includes('**2 runtime/baseline confirmed findings**'), `Markdown header must report 2 collapsed confirmed findings:\n${md.slice(0, 400)}`)
    const exportedSarif = exportReportSarif(store, runId, reportId).log
    assert.equal(exportedSarif.runs[0]!.properties.confirmedCount, 2)
  })
})

describe('R3-18: scripts/check-exhaustive.ts AST exhaustiveness lint', () => {
  test('passes on the live repository with 0 violations', () => {
    const report = runExhaustiveCheck()
    assert.equal(
      report.ok,
      true,
      `check-exhaustive failed on repo:\n${report.violations.map(v => `${v.file}:${v.line} ${v.reason}`).join('\n')}`,
    )
    assert.ok(report.switchesChecked >= 4, `expected >= 4 checked union switches, got ${report.switchesChecked}`)
  })

  test('detects missing ChainStepStatus / RunStatus / ReplayVerdict branches and missing assertNever', () => {
    const unions = loadDefaultGuardedUnions(join(import.meta.dirname, '..'))

    // Missing `turn_capped`, `model_failure`, etc. on ChainStepStatus
    const badStepSwitch = `
      function label(status: string) {
        switch (status) {
          case 'pending':
          case 'ready':
          case 'running':
          case 'complete':
            return status
          default:
            return 'other'
        }
      }
    `
    const stepRes = checkExhaustiveSource('src/fake-step.ts', badStepSwitch, unions)
    assert.equal(stepRes.violations.length, 1)
    assert.equal(stepRes.violations[0]!.unionName, 'ChainStepStatus')
    assert.ok(stepRes.violations[0]!.missingMembers.includes('turn_capped'))
    assert.ok(stepRes.violations[0]!.missingMembers.includes('model_failure'))
    assert.equal(stepRes.violations[0]!.hasAssertNever, false)

    // Missing `assertNever` on an otherwise full ReplayVerdict switch
    const badVerdictSwitch = `
      function score(verdict: string) {
        switch (verdict) {
          case 'confirmed':
          case 'static_verified':
          case 'dismissed':
          case 'inconclusive':
            return 1
          default:
            return 0
        }
      }
    `
    const verdictRes = checkExhaustiveSource('src/fake-verdict.ts', badVerdictSwitch, unions)
    assert.equal(verdictRes.violations.length, 1)
    assert.equal(verdictRes.violations[0]!.unionName, 'ReplayVerdict')
    assert.equal(verdictRes.violations[0]!.missingMembers.length, 0)
    assert.equal(verdictRes.violations[0]!.hasAssertNever, false)

    // Full RunStatus switch with assertNever passes
    const goodRunSwitch = `
      function bucket(status: RunStatus) {
        switch (status) {
          case 'waiting':
          case 'running':
          case 'paused':
          case 'budget_paused':
          case 'stopped':
          case 'failed':
          case 'complete':
            return status
          default:
            return assertNever(status)
        }
      }
    `
    const goodRes = checkExhaustiveSource('src/fake-good.ts', goodRunSwitch, unions)
    assert.equal(goodRes.violations.length, 0)
  })
})
