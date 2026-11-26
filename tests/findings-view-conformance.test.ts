import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { eq } from 'drizzle-orm'
import { buildVerdict } from '../src/components/run/model.ts'
import type { Detail, FindingRow } from '../src/components/run/model.ts'
import type { Finding, InlineVerifyFeedback, ReportBody } from '../src/domain.ts'
import {
  normalizeFindingSeverity,
  normalizeFindingSeverityOverride,
  projectRunFindings,
} from '../src/findings-view.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { buildProvenanceReport, reportHighlights } from '../src/report-summary.ts'
import { FindingCodec, operatorSeverityOverrides } from '../src/server/finding-codec.ts'
import { exportRunReceiptBundle, verifyProofReceiptBundle } from '../src/server/receipt-export.ts'
import { exportReportMarkdown, snapshotReportCoverageGaps } from '../src/server/report-export.ts'
import { buildSarifLog, exportReportSarif } from '../src/server/sarif-export.ts'
import { coverageEntries, endpoints, events, facts, findings as findingsTable, replaySpecs } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const APPROVED_ORIGIN = 'http://127.0.0.1:7788'
const UNAPPROVED_ORIGIN = 'http://127.0.0.1:7799'

function makeTempDir(t: { after: (fn: () => void) => void }, prefix = 'kovo-r2-18-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function sampleHttpSpec(title: string, origin = APPROVED_ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Cross-tenant object access.',
    impact: 'Unauthorized tenant data read.',
    remediation: 'Enforce server-side tenant ownership validation.',
    recheckInstructions: 'Replay request as secondary user and confirm HTTP 403.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "403" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'c1', role: 'control', description: 'Control', expectedStatus: 403, request: { origin, method: 'GET', pathAndQuery: '/api/items/1', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Probe', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: '/api/items/2', followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
}

function sampleStaticSpec(title: string, origin = APPROVED_ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'static_ast_proof',
    origin,
    title,
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high',
    repo: 'app-repo',
    file: 'src/db/query.ts',
    startLine: 40,
    endLine: 44,
    engine: 'semgrep',
    ruleId: 'sql-concat',
    runtimeProofGap: 'Verified via static AST rule; runtime execution was not attempted.',
    remediation: 'Use parameterized query bindings.',
  } as unknown as DeclarativeReplaySpec
}

function confirmedFeedback(reason = 'confirmed diff'): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    controlPassed: true,
    assertionSummary: { observed: reason, expected: '403' },
    stepStatuses: [{ id: 'p1', role: 'probe', status: 200, bodyLen: 64 }],
    retriesRemaining: 0,
  }
}

function staticFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'static_verified',
    controlPassed: true,
    assertionSummary: { observed: 'ast sink match', expected: 'parameterized query' },
    stepStatuses: [],
    retriesRemaining: 0,
  }
}

test('R2-18: src/findings-view.ts is strictly browser-safe (zero node:* or server imports)', () => {
  const src = readFileSync(join(REPO_ROOT, 'src', 'findings-view.ts'), 'utf8')
  assert.equal(/\bfrom\s+['"]node:/.test(src), false, 'src/findings-view.ts must not import node:*')
  assert.equal(/\bfrom\s+['"][^'"]*server\//.test(src), false, 'src/findings-view.ts must not import src/server/*')
})

test('R2-18: FindingCodec unifies severity vocabulary ("info" -> "informational") with backward-compatible decode alias', async (t) => {
  assert.ok((operatorSeverityOverrides as readonly string[]).includes('informational'))
  assert.ok((operatorSeverityOverrides as readonly string[]).includes('info'))
  assert.equal(normalizeFindingSeverity('info'), 'informational')
  assert.equal(normalizeFindingSeverity('INFO'), 'informational')
  assert.equal(normalizeFindingSeverity('informational'), 'informational')
  assert.equal(normalizeFindingSeverityOverride('info'), 'informational')
  assert.equal(normalizeFindingSeverityOverride('informational'), 'informational')
  assert.equal(normalizeFindingSeverityOverride(null), null)

  // Raw DB decode alias: legacy 'info' in both severity and operatorTriage.severityOverride -> 'informational'.
  const decodedLegacy = FindingCodec.fromRow({
    id: 'legacy-info-1',
    run_id: 'run-1',
    asset_id: 'asset-1',
    goal_revision: 0,
    check_id: 'chain',
    case_id: 'case-1',
    finding_kind: 'multi_step_chain',
    replay_spec_id: null,
    provenance: 'agent_only',
    parent_finding_ids: null,
    verification_class: 'runtime_confirmed',
    source_origins: JSON.stringify([APPROVED_ORIGIN]),
    verification_tier: 'runtime_confirmed',
    fingerprint_hash: null,
    superseded_by_finding_id: null,
    counterevidence: null,
    confidence_rationale: null,
    severity_change_conditions: null,
    code_locations: null,
    status: 'confirmed',
    severity: 'info',
    cwe: 'CWE-200',
    origin: APPROVED_ORIGIN,
    triage_status: 'open',
    finding: JSON.stringify({
      id: 'legacy-info-1',
      origin: APPROVED_ORIGIN,
      title: 'Legacy info finding',
      status: 'confirmed',
      severity: 'info',
      reason: 'Header banner exposed',
      remediation: 'Remove Server header',
      evidenceIds: [],
      scopeRevision: 1,
      operatorTriage: {
        status: 'open',
        severityOverride: 'info',
        notes: 'Downgraded via legacy client',
        updatedAt: 1000,
      },
    }),
  })
  assert.equal(decodedLegacy.severity, 'informational')
  assert.equal(decodedLegacy.operatorTriage?.severityOverride, 'informational')

  // Live store triageFinding accepts both 'info' (legacy alias) and 'informational' and persists 'informational'.
  const dir = makeTempDir(t, 'kovo-r2-18-codec-')
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { runId } = await setupApprovedRun(storage, { seeds: [APPROVED_ORIGIN], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'verification', asset, 'Codec test', 'codec')
  const fId = randomUUID()
  const spec = storage.createReplaySpec(run, worker, fId, sampleHttpSpec('Codec Severity Test'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: fId,
    origin: APPROVED_ORIGIN,
    title: 'Codec Severity Test',
    status: 'confirmed',
    severity: 'high',
    reason: 'Confirmed differential probe.',
    remediation: 'Restrict access.',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    verificationTier: 'runtime_confirmed',
  }, spec.id, [APPROVED_ORIGIN])

  const viaLegacyAlias = storage.findingsRepo.triageFinding(fId, { severityOverride: 'info' })
  assert.equal(viaLegacyAlias.operatorTriage?.severityOverride, 'informational')
  assert.equal(viaLegacyAlias.severity, 'high', 'Machine severity must stay intact')

  const viaCanonical = storage.findingsRepo.triageFinding(fId, { severityOverride: 'informational' })
  assert.equal(viaCanonical.operatorTriage?.severityOverride, 'informational')
})

test('R2-18: cross-surface conformance across headline, report, Markdown, SARIF, receipt bundle, and scorer independence', async (t) => {
  const dir = makeTempDir(t, 'kovo-r2-18-conform-')
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { runId } = await setupApprovedRun(storage, { seeds: [APPROVED_ORIGIN], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'verification', asset, 'Conformance fixture', 'fixture')

  const addEv = (title: string) =>
    storage.addArtifact(run, worker, 'replay', title, JSON.stringify({ origin: APPROVED_ORIGIN, verdict: 'confirmed' })).id

  // Record a real broker exchange for receipted finding
  const exReceipt = storage.recordExchange({
    runId,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin: APPROVED_ORIGIN,
    finalOrigin: APPROVED_ORIGIN,
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/api/invoices/42',
    personaHandle: 'tenant-b',
    status: 200,
    mediaType: 'application/json',
    reqHeaders: { authorization: 'Bearer secret-token' },
    respHeaders: { 'content-type': 'application/json' },
    body: '{"owner":"tenant-a","amount":900}',
    durationMs: 14,
  })
  storage.flushNow()

  // 1. Confirmed finding with persisted ProofReceipt (backingKind: 'receipt', severity: high)
  const receiptedId = randomUUID()
  const receiptedSpec = storage.createReplaySpec(run, worker, receiptedId, sampleHttpSpec('Confirmed Receipted IDOR'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('tenant-b read tenant-a invoice'),
  })
  storage.db.update(replaySpecs).set({
    proofReceipt: {
      receipt: {
        vulnClass: 'idor',
        target: { origin: APPROVED_ORIGIN, method: 'GET', pathAndQuery: '/api/invoices/42' },
        exchangeIds: [exReceipt.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Secondary tenant read foreign invoice 42',
      },
      verification: {
        confirmed: true,
        vulnClass: 'idor',
        rule: 'idor_cross_actor_read',
        reason: 'Cross-actor read verified against control.',
        observed: 'HTTP 200 with tenant-a record',
        expected: 'HTTP 403 Forbidden',
      },
    } as never,
  }).where(eq(replaySpecs.id, receiptedSpec.id)).run()
  storage.upsertChainFinding(run, asset.id, {
    id: receiptedId,
    origin: APPROVED_ORIGIN,
    title: 'Confirmed Receipted IDOR',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Cross-actor read verified.',
    remediation: 'Verify tenant ownership before returning invoice.',
    evidenceIds: [addEv('receipted')],
    exchangeIds: [exReceipt.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-receipted-1',
  }, receiptedSpec.id, [APPROVED_ORIGIN])

  // 2. Confirmed finding with severityOverride = legacy 'info' -> effectiveSeverity = 'informational'
  const overriddenId = randomUUID()
  const overriddenSpec = storage.createReplaySpec(run, worker, overriddenId, sampleHttpSpec('Severity Overridden Disclosure'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('metadata endpoint exposed'),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: overriddenId,
    origin: APPROVED_ORIGIN,
    title: 'Severity Overridden Disclosure',
    status: 'confirmed',
    severity: 'high',
    category: 'misconfig-exposure',
    cwe: 'CWE-200',
    reason: 'Debug metadata exposed.',
    remediation: 'Disable debug metadata endpoint.',
    evidenceIds: [addEv('overridden')],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-overridden-2',
  }, overriddenSpec.id, [APPROVED_ORIGIN])
  storage.findingsRepo.triageFinding(overriddenId, { severityOverride: 'info', notes: 'Public non-sensitive build info' })

  // 3. Floor-confirmed finding WITHOUT persisted ProofReceipt (backingKind: 'floor_spec', receipt confirmed: false)
  const floorId = randomUUID()
  const floorSpec = storage.createReplaySpec(run, worker, floorId, sampleHttpSpec('Floor Unreceipted Access Control'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('floor probe matched'),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: floorId,
    origin: APPROVED_ORIGIN,
    title: 'Floor Unreceipted Access Control',
    status: 'confirmed',
    severity: 'medium',
    category: 'broken-access-control',
    cwe: 'CWE-284',
    reason: 'Deterministic floor check detected missing auth guard.',
    remediation: 'Require authenticated session on admin route.',
    evidenceIds: [addEv('floor')],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-floor-3',
  }, floorSpec.id, [APPROVED_ORIGIN], { provenance: 'floor' })

  // 4. Static-verified advisory (in advisories & reportable, NOT confirmed, backingKind: 'static_only')
  const staticId = randomUUID()
  const staticSpec = storage.createReplaySpec(run, worker, staticId, sampleStaticSpec('Static SQL Sink Advisory'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: staticFeedback(),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: staticId,
    origin: APPROVED_ORIGIN,
    title: 'Static SQL Sink Advisory',
    status: 'static_verified',
    severity: 'medium',
    category: 'injection-input',
    cwe: 'CWE-89',
    reason: 'Static AST detected string concatenation in SQL query.',
    remediation: 'Use bound parameters.',
    evidenceIds: [addEv('static')],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
    runtimeProofGap: 'Offline AST proof only.',
    fingerprintHash: 'fp-static-4',
  }, staticSpec.id, [APPROVED_ORIGIN])

  // 5. Critical confirmed finding triaged as false_positive -> MUST be SARIF suppression & excluded from Fix first!
  const fpId = randomUUID()
  const fpSpec = storage.createReplaySpec(run, worker, fpId, sampleHttpSpec('Critical False Positive Candidate'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('fp fixture'),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: fpId,
    origin: APPROVED_ORIGIN,
    title: 'Critical False Positive Candidate',
    status: 'confirmed',
    severity: 'critical',
    category: 'injection-input',
    cwe: 'CWE-78',
    reason: 'Honeypot response simulated execution.',
    remediation: 'N/A — intentional honeypot.',
    evidenceIds: [addEv('fp')],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-false-positive-5',
  }, fpSpec.id, [APPROVED_ORIGIN])
  storage.findingsRepo.triageFinding(fpId, {
    status: 'false_positive',
    notes: 'Confirmed synthetic honeypot endpoint by security team.',
  })

  // 6. Critical confirmed finding triaged as accepted_risk -> MUST be SARIF suppression & excluded from Fix first!
  const acceptedId = randomUUID()
  const acceptedSpec = storage.createReplaySpec(run, worker, acceptedId, sampleHttpSpec('Critical Accepted Risk Legacy Route'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('accepted risk fixture'),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: acceptedId,
    origin: APPROVED_ORIGIN,
    title: 'Critical Accepted Risk Legacy Route',
    status: 'confirmed',
    severity: 'critical',
    category: 'auth-identity',
    cwe: 'CWE-287',
    reason: 'Legacy API key endpoint lacks rotation.',
    remediation: 'Retire legacy endpoint in Q4.',
    evidenceIds: [addEv('accepted')],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-accepted-6',
  }, acceptedSpec.id, [APPROVED_ORIGIN])
  storage.findingsRepo.triageFinding(acceptedId, {
    status: 'accepted_risk',
    notes: 'Approved exception ticket SEC-404 until Q4 sunset.',
  })

  // 7. Out-of-scope confirmed finding (on UNAPPROVED_ORIGIN) -> excluded!
  const oosId = randomUUID()
  const oosSpec = storage.createReplaySpec(run, worker, oosId, sampleHttpSpec('Out-Of-Scope SSRF', UNAPPROVED_ORIGIN), [UNAPPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('oos'),
  })
  storage.upsertChainFinding(run, 'unapproved-asset', {
    id: oosId,
    origin: UNAPPROVED_ORIGIN,
    title: 'Out-Of-Scope SSRF',
    status: 'confirmed',
    severity: 'critical',
    category: 'ssrf-redirects',
    cwe: 'CWE-918',
    reason: 'Observed on out-of-scope origin.',
    remediation: 'Restrict egress.',
    evidenceIds: [addEv('oos')],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-oos-7',
  }, oosSpec.id, [UNAPPROVED_ORIGIN])

  // 8. Tainted-fact confirmed finding -> excluded!
  const taintedFactId = randomUUID()
  storage.db.insert(facts).values({
    id: taintedFactId,
    runId,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    kind: 'object_ref',
    origin: UNAPPROVED_ORIGIN,
    summary: 'Tainted upstream reference',
    data: {},
    sourceOrigins: [UNAPPROVED_ORIGIN],
    evidenceIds: [],
    exchangeIds: [],
    tainted: true,
    createdAt: Date.now(),
  }).run()
  const taintedId = randomUUID()
  const taintedSpec = storage.createReplaySpec(run, worker, taintedId, sampleHttpSpec('Tainted Chain Finding'), [APPROVED_ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback('tainted'),
  })
  storage.upsertChainFinding(run, asset.id, {
    id: taintedId,
    origin: APPROVED_ORIGIN,
    title: 'Tainted Chain Finding',
    status: 'confirmed',
    severity: 'critical',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Depends on revoked origin fact.',
    remediation: 'N/A',
    evidenceIds: [addEv('tainted')],
    chainFactIds: [taintedFactId],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-tainted-8',
  }, taintedSpec.id, [APPROVED_ORIGIN])

  // Mark run complete and save report
  storage.updateRun(runId, { status: 'complete', phase: 'complete' })
  const reportId = storage.writeReport(storage.run(runId), false)
  const detail = storage.runDetail(runId) as unknown as Detail
  const report = detail.reports.find(r => r.id === reportId)!
  assert.ok(report)

  // Expected active counts:
  //   confirmed  = 3 (receiptedId, overriddenId, floorId)
  //   advisories = 1 (staticId)
  //   reportable = 4 (3 confirmed + 1 advisory)
  //   suppressed = 2 (fpId, acceptedId)
  const EXPECTED_CONFIRMED = 3
  const EXPECTED_ADVISORIES = 1
  const EXPECTED_REPORTABLE = 4
  const EXPECTED_SUPPRESSED = 2

  // --- Surface 1: Direct projectRunFindings ---
  const directView = projectRunFindings(detail.findings, {
    approvedOrigins: [APPROVED_ORIGIN],
    approvedAssetIds: [asset.id],
    taintedFactIds: [taintedFactId],
  })
  assert.equal(directView.counts.confirmed, EXPECTED_CONFIRMED)
  assert.equal(directView.counts.advisories, EXPECTED_ADVISORIES)
  assert.equal(directView.counts.reportable, EXPECTED_REPORTABLE)
  assert.equal(directView.counts.suppressed, EXPECTED_SUPPRESSED)
  assert.equal(directView.counts.byExclusion.out_of_scope, 1)
  assert.equal(directView.counts.byExclusion.tainted_fact, 1)

  // --- Surface 2: Live Headline (model.ts buildVerdict) ---
  const verdict = buildVerdict(detail, detail.findings as unknown as FindingRow[], false)
  assert.equal(verdict.confirmed, EXPECTED_CONFIRMED, 'Headline confirmed count must match projection')
  assert.equal(verdict.reportable, EXPECTED_REPORTABLE, 'Headline reportable count must match projection')
  assert.equal(verdict.suppressed, EXPECTED_SUPPRESSED, 'Headline suppressed count must match projection')
  // Since the two critical findings were triaged false_positive / accepted_risk, and the other high was overridden to informational,
  // ONLY ONE high-severity finding remains (Confirmed Receipted IDOR)!
  assert.match(verdict.hed, /^One high-severity weakness confirmed across one host\./, `Unexpected headline: ${verdict.hed}`)
  assert.equal(verdict.worst?.id, receiptedId)

  // --- Surface 3: Report UI / Summary (reportHighlights) ---
  const highlights = reportHighlights(report.body as unknown as ReportBody, { taintedFactIds: [taintedFactId] })
  assert.equal(highlights.confirmed, EXPECTED_CONFIRMED, 'Report confirmed count must match projection')
  assert.equal(highlights.staticVerified, EXPECTED_ADVISORIES, 'Report static advisory count must match projection')
  assert.equal(highlights.reportable, EXPECTED_REPORTABLE, 'Report reportable count must match projection')
  assert.equal(highlights.suppressed, EXPECTED_SUPPRESSED, 'Report suppressed count must match projection')
  // Fix first MUST NOT pick false_positive or accepted_risk critical findings, and MUST pick Confirmed Receipted IDOR (high)!
  assert.equal(highlights.priority?.finding?.id, receiptedId, 'Fix first must exclude false_positive/accepted_risk findings')

  // --- Surface 4: Markdown Export (exportReportMarkdown) ---
  const md = exportReportMarkdown(storage, runId, reportId).content
  assert.ok(md.includes(`**${EXPECTED_CONFIRMED} runtime/baseline confirmed findings**`), 'Markdown header confirmed count must match')
  assert.ok(md.includes(`**${EXPECTED_ADVISORIES} static-verified finding**`), 'Markdown header static count must match')
  // Fix first section must point to Confirmed Receipted IDOR, NOT the false_positive or accepted_risk critical findings
  const fixFirstIdx = md.indexOf('## Fix first')
  const approvedScopeIdx = md.indexOf('## Approved scope')
  assert.ok(fixFirstIdx >= 0 && approvedScopeIdx > fixFirstIdx)
  const fixFirstBlock = md.slice(fixFirstIdx, approvedScopeIdx)
  assert.ok(fixFirstBlock.includes('Confirmed Receipted IDOR'), 'Markdown Fix first must pick highest non-suppressed finding')
  assert.equal(fixFirstBlock.includes('Critical False Positive Candidate'), false, 'Markdown Fix first must exclude false_positive')
  assert.equal(fixFirstBlock.includes('Critical Accepted Risk Legacy Route'), false, 'Markdown Fix first must exclude accepted_risk')
  // Suppressed findings appear under dedicated suppressed section, and out-of-scope / tainted are absent
  assert.ok(md.includes('## Suppressed Findings (Operator Triage)'))
  assert.equal(md.includes('Out-Of-Scope SSRF'), false)
  assert.equal(md.includes('Tainted Chain Finding'), false)
  // Overridden finding displays effective severity 'informational'
  const overriddenIdx = md.indexOf('### Severity Overridden Disclosure')
  assert.ok(overriddenIdx >= 0)
  assert.ok(md.slice(overriddenIdx, overriddenIdx + 300).includes('**Severity** informational'))

  // --- Surface 5: SARIF Export (exportReportSarif & buildSarifLog) ---
  const sarif = exportReportSarif(storage, runId, reportId).log
  const sarifRun = sarif.runs[0]!
  assert.equal(sarifRun.properties.confirmedCount, EXPECTED_CONFIRMED, 'SARIF confirmedCount must match projection')
  assert.equal(sarifRun.properties.staticAdvisoryCount, EXPECTED_ADVISORIES, 'SARIF staticAdvisoryCount must match projection')
  assert.equal(sarifRun.properties.reportableCount, EXPECTED_REPORTABLE, 'SARIF reportableCount must match projection')
  assert.equal(sarifRun.properties.suppressedCount, EXPECTED_SUPPRESSED, 'SARIF suppressedCount must match projection')

  const activeFailResults = sarifRun.results.filter(r => r.kind === 'fail' && !(r.suppressions?.length))
  assert.equal(activeFailResults.length, EXPECTED_REPORTABLE, 'Active non-suppressed SARIF fail results must match reportable count')

  const fpSarif = sarifRun.results.find(r => r.properties.kovo.findingId === fpId)
  assert.ok(fpSarif, 'false_positive finding must be emitted in SARIF with suppressions')
  assert.equal(fpSarif.suppressions?.length, 1)
  assert.equal(fpSarif.suppressions![0]!.kind, 'external')
  assert.equal(fpSarif.suppressions![0]!.status, 'accepted')
  assert.match(fpSarif.suppressions![0]!.justification ?? '', /honeypot/i)

  const acceptedSarif = sarifRun.results.find(r => r.properties.kovo.findingId === acceptedId)
  assert.ok(acceptedSarif, 'accepted_risk finding must be emitted in SARIF with suppressions')
  assert.equal(acceptedSarif.suppressions?.length, 1)
  assert.equal(acceptedSarif.suppressions![0]!.kind, 'external')

  const overriddenSarif = sarifRun.results.find(r => r.properties.kovo.findingId === overriddenId)
  assert.ok(overriddenSarif)
  assert.equal(overriddenSarif.level, 'note', 'informational override maps to SARIF note level')
  assert.equal(overriddenSarif.properties.kovo.effectiveSeverity, 'informational')
  assert.equal(overriddenSarif.properties.kovo.machineSeverity, 'high')

  // Direct buildSarifLog with raw detail.findings also excludes out-of-scope & tainted
  const directSarif = buildSarifLog({
    runId,
    reportVersion: 1,
    goal: run.goal,
    capabilityTier: run.capabilityTier,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    approvedOrigins: [APPROVED_ORIGIN],
    taintedFactIds: [taintedFactId],
    findings: detail.findings as unknown as Parameters<typeof buildSarifLog>[0]['findings'],
  })
  assert.equal(directSarif.runs[0]!.properties.confirmedCount, EXPECTED_CONFIRMED)
  assert.equal(directSarif.runs[0]!.properties.reportableCount, EXPECTED_REPORTABLE)
  assert.equal(directSarif.runs[0]!.results.some(r => r.properties.kovo.findingId === oosId), false)
  assert.equal(directSarif.runs[0]!.results.some(r => r.properties.kovo.findingId === taintedId), false)

  // --- Surface 6: Signed ProofReceipt Bundle (exportRunReceiptBundle) ---
  const hmacSecret = 'r2-18-conformance-hmac-secret-key-012345'
  const bundle = exportRunReceiptBundle(storage, runId, {
    signing: { algorithm: 'hmac-sha256', secret: hmacSecret },
  })
  assert.equal(verifyProofReceiptBundle(bundle, { secret: hmacSecret }).valid, true)
  assert.equal(bundle.payload.findingsSummary?.confirmed, EXPECTED_CONFIRMED, 'Receipt bundle confirmed summary must match')
  assert.equal(bundle.payload.findingsSummary?.reportable, EXPECTED_REPORTABLE, 'Receipt bundle reportable summary must match')
  assert.equal(bundle.payload.findingsSummary?.suppressed, EXPECTED_SUPPRESSED, 'Receipt bundle suppressed summary must match')
  assert.equal(bundle.payload.records.length, EXPECTED_CONFIRMED, 'Receipt bundle records must include all non-suppressed confirmed rows')

  const receiptedRec = bundle.payload.records.find(r => r.findingId === receiptedId)!
  assert.ok(receiptedRec)
  assert.equal(receiptedRec.backingKind, 'receipt')
  assert.equal(receiptedRec.verification.confirmed, true)

  const floorRec = bundle.payload.records.find(r => r.findingId === floorId)!
  assert.ok(floorRec)
  assert.equal(floorRec.backingKind, 'floor_spec', 'Unreceipted floor finding must carry explicit backingKind: floor_spec')
  assert.equal(floorRec.receipt, null)
  assert.equal(floorRec.verification.confirmed, false, 'Offline-verifiable contract: unreceipted rows MUST keep confirmed: false')
  assert.equal(floorRec.verification.rule, 'legacy_unreceipted')

  const overriddenRec = bundle.payload.records.find(r => r.findingId === overriddenId)!
  assert.ok(overriddenRec)
  assert.equal(overriddenRec.effectiveSeverity, 'informational')
  assert.equal(overriddenRec.severity, 'high', 'Receipt record keeps persisted machine severity alongside effectiveSeverity')

  assert.equal(bundle.payload.records.some(r => r.findingId === fpId || r.findingId === acceptedId), false, 'Suppressed findings must not be exported as active confirmed receipts')
  assert.equal(bundle.payload.records.some(r => r.findingId === oosId || r.findingId === taintedId), false, 'Excluded findings must not leak into receipt bundle')

  // --- Scorer independence invariant ---
  // Persisted machine confirmation state and benchmark scorer inputs (`countConfirmedForRun`, `buildProvenanceReport`)
  // MUST NOT be altered by operator triage (`false_positive`, `accepted_risk`, severity override)!
  const rawDbRows = storage.db.select().from(findingsTable).where(eq(findingsTable.runId, runId)).all()
  const fpDbRow = rawDbRows.find(r => r.id === fpId)!
  assert.equal(fpDbRow.status, 'confirmed', 'Machine DB status must stay confirmed after false_positive triage')
  assert.equal(fpDbRow.verificationClass, 'runtime_confirmed')
  assert.equal(fpDbRow.triageStatus, 'false_positive')

  const overriddenDbRow = rawDbRows.find(r => r.id === overriddenId)!
  assert.equal(overriddenDbRow.severity, 'high', 'Machine DB severity must stay high after info override')

  // All 7 machine-confirmed DB rows (receipted, overridden, floor, fp, accepted, oos, tainted) remain machine-confirmed in DB rollup.
  assert.equal(FindingCodec.countConfirmedForRun(storage.client, runId), 7)
  // Report provenance surface (used by benchmark graders) still counts fp + accepted as machine-confirmed TPs.
  const provenance = buildProvenanceReport(report.body.findings as unknown as Finding[])
  assert.equal(provenance.confirmedFindings.length, 5, 'Benchmark provenance TP pool must ignore operator triage overlays')
  assert.ok(provenance.confirmedFindings.some(f => f.id === fpId))
  assert.ok(provenance.confirmedFindings.some(f => f.id === acceptedId))
})

test('R2-18: coverage gaps snapshotted for version-N reports do not drift when live gaps change later', async (t) => {
  const dir = makeTempDir(t, 'kovo-r2-18-gaps-')
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { runId } = await setupApprovedRun(storage, { seeds: [APPROVED_ORIGIN], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Gap snapshot test', 'gaps')

  // Save report v1 BEFORE any operational gaps or open proof gaps exist, and snapshot it.
  const reportV1Id = storage.writeReport(storage.run(runId), true)
  const snapV1 = snapshotReportCoverageGaps(storage, runId, reportV1Id)
  assert.equal(snapV1.totalGaps, 0)
  const mdV1Before = exportReportMarkdown(storage, runId, reportV1Id).content
  assert.equal(mdV1Before.includes('## Operational coverage gaps'), false)
  assert.equal(mdV1Before.includes('## Open Proof Gaps'), false)

  // Now add live operational gaps & open proof gaps AFTER v1 was saved (timestamp strictly later).
  const laterTs = Date.now() + 5000
  storage.db.insert(events).values({
    workspaceId: run.workspaceId,
    runId,
    kind: 'coverage.precondition_unmet',
    message: 'Skipped write probes due to tier cap',
    detail: { origin: APPROVED_ORIGIN, precondition: 'tier_3_required', vulnClass: 'csrf', route: '/api/transfer', method: 'POST', skippedCount: 2 },
    createdAt: laterTs,
  }).run()
  storage.db.insert(endpoints).values({
    id: randomUUID(),
    runId,
    scopeRevision: run.scopeRevision,
    origin: APPROVED_ORIGIN,
    method: 'POST',
    pathTemplate: '/api/later-uncovered',
    source: 'openapi',
    sinkKinds: ['sqli'],
    testedClasses: [],
    createdAt: laterTs,
    updatedAt: laterTs,
  }).run()
  storage.db.insert(coverageEntries).values({
    id: randomUUID(),
    runId,
    scopeRevision: run.scopeRevision,
    goalRevision: run.goalRevision,
    origin: APPROVED_ORIGIN,
    category: 'broken-access-control',
    status: 'needs_follow_up',
    summary: 'Later proof gap',
    proofGapReason: 'Secondary tenant credential expired later',
    assignmentId: worker.id,
    updatedAt: laterTs,
  }).run()

  // Re-export report v1: MUST stay byte-for-byte identical (zero drift from live gaps!).
  const mdV1After = exportReportMarkdown(storage, runId, reportV1Id).content
  assert.equal(mdV1After, mdV1Before, 'Version-1 report export must not drift when live coverage gaps change later')

  // Also test a v1b saved BEFORE live gaps where exportReportMarkdown is called for the FIRST time AFTER live gaps are added.
  // Save report v2 AFTER the live gaps exist: v2 MUST include the new operational & open proof gaps!
  const reportV2Id = storage.writeReport(storage.run(runId), false)
  // Ensure v2 createdAt >= laterTs so the laterTs telemetry belongs to v2
  storage.client.prepare('UPDATE reports SET created_at = ? WHERE id = ?').run(laterTs + 1000, reportV2Id)
  const mdV2 = exportReportMarkdown(storage, runId, reportV2Id).content
  assert.ok(mdV2.includes('## Operational coverage gaps'), 'Version-2 report export must include operational gaps present at v2 save')
  assert.ok(mdV2.includes('precondition_unmet'))
  assert.ok(mdV2.includes('/api/later-uncovered'))
  assert.ok(mdV2.includes('## Open Proof Gaps'))
  assert.ok(mdV2.includes('Secondary tenant credential expired later'))
})
