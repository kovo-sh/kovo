import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ts from 'typescript'
import { newProject, newRun } from '../src/domain.ts'
import type { EvidenceSummary, Finding, InlineVerifyFeedback, ReportBody } from '../src/domain.ts'
import { FSTAT_ORDER, normFStatus, stLabel } from '../src/components/run/meta.ts'
import { buildVerdict } from '../src/components/run/model.ts'
import type { Detail, FindingRow } from '../src/components/run/model.ts'
import {
  buildProvenanceReport,
  filterActiveFindings,
  isActiveFinding,
  isRuntimeConfirmedFinding,
  reportHighlights,
} from '../src/report-summary.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  isReportSource,
  projectReportEvidence,
  REPORT_EVIDENCE_VERDICTS,
  reportEvidenceVerdictSchema,
} from '../src/server/report-evidence.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { buildSarifLog, exportReportSarif } from '../src/server/sarif-export.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const ORIGIN = 'https://q7.example.test'

function makeTempStore(t: test.TestContext, prefix = 'kovo-q7-'): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { dir, store }
}

function setupApprovedRun(store: Store, name = 'Q7 App', origin = ORIGIN) {
  const proj = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name,
    environment: 'public',
    seeds: [origin],
  }))
  const createdRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: `Assess ${name}`,
    capabilityTier: 2,
  }))
  store.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
  const discovered = store.run(createdRun.id)
  store.command({
    requestId: randomUUID(),
    runId: createdRun.id,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    saveProject: true,
    capabilityTier: 2,
  })
  const run = store.run(createdRun.id)
  const asset = run.candidates[0]!
  const worker = store.makeWorker(run, 'investigation', asset, 'Q7 Worker', 'Verify controls')
  return { projectId: proj.id, runId: run.id, run, asset, worker }
}

function sampleHttpSpec(title: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Authorization boundary bypass',
    impact: 'Cross-account data read',
    remediation: 'Enforce ownership checks',
    recheckInstructions: 'Replay cross-account control vs probe',
    assertionsJq: '.status == 200',
    spaCatchallControl: false,
    steps: [{
      id: 'probe-1',
      role: 'probe',
      description: 'Read foreign object',
      request: {
        origin,
        method: 'GET',
        pathAndQuery: '/api/items/42',
        followRedirects: false,
      },
    }],
  } as unknown as DeclarativeReplaySpec
}

function sampleStaticSpec(title: string, origin = ORIGIN): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'static_ast_proof',
    origin,
    title,
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'Unsanitized query construction',
    impact: 'Query manipulation sink',
    remediation: 'Use parameterized queries',
    recheckInstructions: 'Re-run static AST proof and live replay',
    engine: 'ast-grep',
    repo: 'app',
    file: 'src/search.ts',
    startLine: 12,
    endLine: 18,
    rulePattern: 'db.query($X)',
    runtimeProofGap: 'Verified via offline AST match only; runtime replay not yet executed.',
  } as unknown as DeclarativeReplaySpec
}

function confirmedFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    controlPassed: true,
    assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
    stepStatuses: [{ id: 'probe-1', role: 'probe', status: 200, bodyLen: 64 }],
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

function loadInspectorHelpers() {
  const src = readFileSync(join(REPO_ROOT, 'src/components/run/views/findings-inspector.tsx'), 'utf8')
  const start = src.indexOf('/** Unified Verify Fix gate')
  const end = src.indexOf('const text = (v: unknown) =>')
  assert.ok(start >= 0 && end > start, 'Expected helper + DAG block in findings-inspector.tsx')
  const snippet = src.slice(start, end)
  const transpiled = ts.transpileModule(snippet, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      jsx: ts.JsxEmit.React,
    },
  }).outputText
  const exportsObj: Record<string, unknown> = {}
  const StubTag = ({ children, tone }: { children?: React.ReactNode; tone?: string }) =>
    React.createElement('span', { 'data-tag': tone ?? 'default' }, children)
  const StubIcon = ({ name }: { name: string }) =>
    React.createElement('span', { 'data-icon': name })
  const StubStatusGlyph = ({ status }: { status?: string }) =>
    React.createElement('span', { 'data-status-glyph': status ?? '' })
  const cn = (...parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(' ')
  const host = (origin: string) => {
    try { return new URL(origin).host } catch { return origin }
  }
  const fn = new Function(
    'exports', 'React', 'normFStatus', 'Tag', 'Icon', 'StatusGlyph', 'cn', 'host',
    transpiled,
  )
  fn(exportsObj, React, normFStatus, StubTag, StubIcon, StubStatusGlyph, cn, host)
  return exportsObj as {
    canVerifyFix: (f: { status: string; replaySpecId?: string | null }) => boolean
    canGeneratePatch: (f: { status: string; codeLocations?: unknown[] }) => boolean
    extractCompositeProofSummary: (
      replaySpec: { proofReceipt?: unknown; proofVerdict?: string | null; lastVerificationDiff?: unknown } | null | undefined,
      retests?: ReadonlyArray<{ verdict?: string | null; summary?: string | null; patchBrokeHopId?: string | null }>,
    ) => {
      chainId: string
      replayMode: string
      confirmed: boolean | null
      terminalOracleFamily: string | null
      terminalHopId: string
      patchBrokeHopId: string | null
      hops: Array<{ hopId: string; order: number; surface: string; actor: string | null; isTerminal: boolean; patchBrokeHere: boolean; producedCapabilities: string[]; consumedCapabilities: string[] }>
      edges: Array<{ fromHopId: string; toHopId: string; kind: string; capabilityHandles: string[]; verified: boolean | null }>
    } | null
    CompositeProofDagCard: (props: { summary: unknown; title?: string; compact?: boolean }) => React.ReactElement
  }
}

// ============================================================================
// 1. Canonical non-superseded projection across summary, store, Markdown, SARIF
// ============================================================================

test('Q7.1: canonical non-superseded helper prevents double-counting across isRuntimeConfirmedFinding, saveReport, Markdown & SARIF', t => {
  const { store } = makeTempStore(t, 'kovo-q7-superseded-')
  const { runId, run, asset, worker } = setupApprovedRun(store, 'Superseded Projection App')

  const evActive = store.addArtifact(run, worker, 'replay', 'Active replay', JSON.stringify({
    origin: ORIGIN,
    verdict: 'confirmed',
    kind: 'http_chain',
  }))
  const evSuperseded = store.addArtifact(run, worker, 'replay', 'Superseded replay', JSON.stringify({
    origin: ORIGIN,
    verdict: 'confirmed',
    kind: 'http_chain',
  }))
  const evStatic = store.addArtifact(run, worker, 'replay', 'Static AST receipt', JSON.stringify({
    origin: ORIGIN,
    verdict: 'static_verified',
    kind: 'static_ast_proof',
  }))

  const activeId = randomUUID()
  const activeSpec = store.createReplaySpec(run, worker, activeId, sampleHttpSpec('Active Cross-Tenant Read'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: activeId,
    origin: ORIGIN,
    title: 'Active Cross-Tenant Read',
    status: 'confirmed',
    severity: 'critical',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Runtime cross-tenant exposure confirmed',
    remediation: 'Enforce tenant ownership check',
    evidenceIds: [evActive.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-active-chain',
  }, activeSpec.id, [ORIGIN])

  const supersededId = randomUUID()
  const supersededSpec = store.createReplaySpec(run, worker, supersededId, sampleHttpSpec('Superseded Upstream Chain'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: supersededId,
    origin: ORIGIN,
    title: 'Superseded Upstream Chain',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-284',
    reason: 'Superseded by higher-impact downstream chain',
    remediation: 'Enforce tenant isolation',
    evidenceIds: [evSuperseded.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    supersededByFindingId: activeId,
    fingerprintHash: 'fp-superseded-chain',
  }, supersededSpec.id, [ORIGIN])

  const staticId = randomUUID()
  const staticSpec = store.createReplaySpec(run, worker, staticId, sampleStaticSpec('Static Query Sink Advisory'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: staticFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: staticId,
    origin: ORIGIN,
    title: 'Static Query Sink Advisory',
    status: 'static_verified',
    severity: 'high',
    category: 'injection-input',
    cwe: 'CWE-89',
    reason: 'Static AST pattern matched unparameterized query',
    remediation: 'Use bound query parameters',
    evidenceIds: [evStatic.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
    runtimeProofGap: 'Runtime execution was not attempted.',
    fingerprintHash: 'fp-static-advisory',
  }, staticSpec.id, [ORIGIN])

  // Direct helper invariants
  const activeFinding: Finding = {
    id: activeId, origin: ORIGIN, title: 'Active', status: 'confirmed', severity: 'critical',
    reason: 'r', remediation: 'fix', evidenceIds: [], scopeRevision: 1, verificationTier: 'runtime_confirmed',
  }
  const supersededFinding: Finding = {
    ...activeFinding, id: supersededId, title: 'Superseded', supersededByFindingId: activeId,
  }
  const staticFinding: Finding = {
    ...activeFinding, id: staticId, title: 'Static', status: 'static_verified', verificationTier: 'static_verified',
  }
  assert.equal(isActiveFinding(activeFinding), true)
  assert.equal(isActiveFinding(supersededFinding), false)
  assert.deepEqual(filterActiveFindings([activeFinding, supersededFinding, staticFinding]).map(f => f.id), [activeId, staticId])
  assert.equal(isRuntimeConfirmedFinding(activeFinding), true)
  assert.equal(isRuntimeConfirmedFinding(supersededFinding), false, 'superseded finding must NEVER pass isRuntimeConfirmedFinding')
  assert.equal(isRuntimeConfirmedFinding(staticFinding), false, 'static_verified must NEVER pass isRuntimeConfirmedFinding')

  const prov = buildProvenanceReport([activeFinding, supersededFinding, staticFinding])
  assert.deepEqual(prov.confirmedFindings.map(f => f.id), [activeId])
  assert.deepEqual(prov.advisories.map(f => f.id), [staticId], 'superseded findings must not leak into advisories either')
  assert.equal(prov.provenanceCounts.agent_only, 1)

  const hl = reportHighlights({
    goal: 'test',
    capabilityTier: 2,
    scopeRevision: 1,
    goalRevision: 1,
    scope: [{ id: asset.id, origin: ORIGIN, source: 'seed', thirdParty: false }],
    findings: [activeFinding, supersededFinding, staticFinding],
    coverage: [],
    gaps: [],
  } as ReportBody)
  assert.equal(hl.confirmed, 1)
  assert.equal(hl.staticVerified, 1)

  // saveReport excludes superseded finding completely
  const reportId = store.writeReport(store.run(runId), false)
  const report = store.runDetail(runId).reports.find(r => r.id === reportId)!
  assert.ok(report)
  assert.deepEqual(report.body.findings.map(f => f.id).sort(), [activeId, staticId].sort())
  assert.equal(report.body.findings.some(f => f.id === supersededId), false, 'saveReport must exclude superseded findings')

  // Markdown export excludes superseded finding and separates Confirmed vs Static-Verified Advisories
  const md = exportReportMarkdown(store, runId, reportId).content
  assert.ok(md.includes('Active Cross-Tenant Read'))
  assert.ok(!md.includes('Superseded Upstream Chain'), 'Markdown export must omit superseded finding')
  const findingsIdx = md.indexOf('## Findings')
  const staticSecIdx = md.indexOf('## Static-Verified Advisories')
  const activeHeadingIdx = md.indexOf('### Active Cross-Tenant Read')
  const staticHeadingIdx = md.indexOf('### Static Query Sink Advisory')
  assert.ok(findingsIdx >= 0 && staticSecIdx > findingsIdx, 'Markdown export must separate ## Static-Verified Advisories from ## Findings')
  assert.ok(activeHeadingIdx > findingsIdx && activeHeadingIdx < staticSecIdx, 'Confirmed finding must live under ## Findings')
  assert.ok(staticHeadingIdx > staticSecIdx, 'Static-verified finding must live under ## Static-Verified Advisories')

  // SARIF export (direct buildSarifLog AND store exportReportSarif) excludes superseded and separates tiers
  const directSarif = buildSarifLog({
    runId,
    reportVersion: 1,
    goal: 'SARIF test',
    capabilityTier: 2,
    scopeRevision: 1,
    goalRevision: 1,
    approvedOrigins: [ORIGIN],
    findings: [activeFinding, supersededFinding, staticFinding],
  })
  const directFails = directSarif.runs[0]!.results.filter(r => r.kind === 'fail')
  assert.deepEqual(directFails.map(r => r.properties.kovo.findingId).sort(), [activeId, staticId].sort())
  assert.equal(directSarif.runs[0]!.properties.confirmedCount, 1)
  assert.equal(directSarif.runs[0]!.properties.staticAdvisoryCount, 1)
  assert.equal(directSarif.runs[0]!.properties.supersededExcludedCount, 1)
  const runtimeResult = directFails.find(r => r.properties.kovo.findingId === activeId)!
  const staticResult = directFails.find(r => r.properties.kovo.findingId === staticId)!
  assert.equal(runtimeResult.properties.kovo.runtimeConfirmed, true)
  assert.equal(runtimeResult.properties.kovo.tierSection, 'confirmed')
  assert.equal(staticResult.properties.kovo.runtimeConfirmed, false)
  assert.equal(staticResult.properties.kovo.tierSection, 'static_advisory')

  const exportedSarif = exportReportSarif(store, runId, reportId).log
  const exportedFails = exportedSarif.runs[0]!.results.filter(r => r.kind === 'fail')
  assert.deepEqual(exportedFails.map(r => r.properties.kovo.findingId).sort(), [activeId, staticId].sort())
})

// ============================================================================
// 2. Monotonic static_verified -> confirmed & pending floor upgrades
// ============================================================================

test('Q7.2: static_verified advisories and pending floor rows monotonically upgrade to confirmed while floor-confirmed rows stay immutable', t => {
  const { store } = makeTempStore(t, 'kovo-q7-monotonic-')
  const { runId, run, asset, worker } = setupApprovedRun(store, 'Monotonic Lifecycle App')

  // Case A: static_verified upgraded to confirmed via updateProposedFinding
  const staticId = randomUUID()
  const staticSpec = store.createReplaySpec(run, worker, staticId, sampleStaticSpec('Static SQLi Sink'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: staticFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: staticId,
    origin: ORIGIN,
    title: 'Static SQLi Sink',
    status: 'static_verified',
    severity: 'medium',
    category: 'injection-input',
    cwe: 'CWE-89',
    reason: 'Offline AST sink detected',
    remediation: 'Parameterize query',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
    runtimeProofGap: 'Runtime reproduction pending.',
    fingerprintHash: 'fp-upgrade-a',
  }, staticSpec.id, [ORIGIN])
  assert.equal(store.confirmedFindingCount(runId), 0)

  const runtimeSpecA = store.createReplaySpec(run, worker, staticId, sampleHttpSpec('Runtime SQLi Confirmed'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  const upgradedA = store.updateProposedFinding(run, staticId, {
    replaySpecId: runtimeSpecA.id,
    verificationTier: 'runtime_confirmed',
    finding: {
      title: 'Runtime SQLi Confirmed',
      status: 'confirmed',
      severity: 'critical',
      reason: 'Differential runtime proof confirmed SQL injection',
    },
  })
  assert.equal(upgradedA.status, 'confirmed')
  assert.equal(upgradedA.verificationTier, 'runtime_confirmed')
  assert.equal(upgradedA.replaySpecId, runtimeSpecA.id, 'runtime upgrade must replace static replaySpecId')
  assert.equal(upgradedA.severity, 'critical', 'static_verified -> confirmed upgrade may refine severity')
  assert.equal(upgradedA.runtimeProofGap, null, 'stale static runtimeProofGap must clear on runtime confirmation')
  assert.equal(store.confirmedFindingCount(runId), 1)

  // Attempt to downgrade confirmed -> static_verified must be ignored and identity preserved
  const afterDowngradeAttempt = store.updateProposedFinding(run, staticId, {
    finding: {
      status: 'static_verified',
      title: 'Mutated Title Should Be Ignored',
      severity: 'low',
    },
  })
  assert.equal(afterDowngradeAttempt.status, 'confirmed', 'confirmed finding must NEVER downgrade to static_verified')
  assert.equal(afterDowngradeAttempt.title, 'Runtime SQLi Confirmed')
  assert.equal(afterDowngradeAttempt.severity, 'critical')

  // Case B: static_verified upgraded to confirmed via upsertChainFinding (same dedupe key!)
  const staticIdB = randomUUID()
  const staticSpecB = store.createReplaySpec(run, worker, staticIdB, sampleStaticSpec('Static IDOR Sink'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: staticFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: staticIdB,
    origin: ORIGIN,
    title: 'Static IDOR Sink',
    status: 'static_verified',
    severity: 'medium',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Static check flagged missing owner check',
    remediation: 'Verify ownership',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'static_verified',
    runtimeProofGap: 'No runtime check yet.',
    fingerprintHash: 'fp-upgrade-b',
  }, staticSpecB.id, [ORIGIN])

  const runtimeSpecB = store.createReplaySpec(run, worker, staticIdB, sampleHttpSpec('Confirmed Cross-Tenant IDOR'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  const upgradedB = store.upsertChainFinding(run, asset.id, {
    id: randomUUID(),
    origin: ORIGIN,
    title: 'Confirmed Cross-Tenant IDOR',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Runtime proof verified cross-tenant read',
    remediation: 'Enforce tenant check',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
    fingerprintHash: 'fp-upgrade-b',
  }, runtimeSpecB.id, [ORIGIN])
  assert.equal(upgradedB.id, staticIdB)
  assert.equal(upgradedB.status, 'confirmed')
  assert.equal(upgradedB.verificationTier, 'runtime_confirmed')
  assert.equal(upgradedB.replaySpecId, runtimeSpecB.id)
  assert.equal(upgradedB.runtimeProofGap, null)
  assert.equal(store.confirmedFindingCount(runId), 2)

  // Case C: pending floor row CAN monotonically upgrade to confirmed, whereas floor-confirmed row stays immutable!
  const floorPendingId = randomUUID()
  const floorPendingSpec = store.createReplaySpec(run, worker, floorPendingId, sampleHttpSpec('Floor Pending Candidate'), [ORIGIN])
  store.upsertChainFinding(run, asset.id, {
    id: floorPendingId,
    origin: ORIGIN,
    title: 'Floor Pending Candidate',
    status: 'pending',
    severity: 'medium',
    category: 'auth-identity',
    cwe: 'CWE-287',
    reason: 'Awaiting runtime proof',
    remediation: 'Require auth',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    fingerprintHash: 'fp-floor-pending',
  }, floorPendingSpec.id, [ORIGIN], { provenance: 'floor' })

  const floorRuntimeSpec = store.createReplaySpec(run, worker, floorPendingId, sampleHttpSpec('Floor Pending Now Confirmed'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  const upgradedFloor = store.updateProposedFinding(run, floorPendingId, {
    replaySpecId: floorRuntimeSpec.id,
    verificationTier: 'runtime_confirmed',
    finding: {
      status: 'confirmed',
      severity: 'high',
      reason: 'Runtime replay proved unauthenticated access',
    },
  })
  assert.equal(upgradedFloor.status, 'confirmed', 'pending floor row must monotonically upgrade to confirmed')
  assert.equal(store.confirmedFindingCount(runId), 3)

  // Now that floor row IS confirmed, subsequent agent updates MUST be rejected immutably!
  const blockedFloorUpdate = store.updateProposedFinding(run, floorPendingId, {
    finding: {
      status: 'dismissed',
      title: 'Attempted overwrite of floor-confirmed row',
    },
  })
  assert.equal(blockedFloorUpdate.status, 'confirmed', 'floor-confirmed row must remain immutable')
  const blockedFloorUpsert = store.upsertChainFinding(run, asset.id, {
    id: randomUUID(),
    origin: ORIGIN,
    title: 'Agent duplicate of floor-confirmed row',
    status: 'confirmed',
    severity: 'low',
    category: 'auth-identity',
    cwe: 'CWE-287',
    reason: 'Agent duplicate',
    remediation: 'Fix',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    fingerprintHash: 'fp-floor-pending',
  }, floorRuntimeSpec.id, [ORIGIN], { provenance: 'agent_only' })
  assert.equal(blockedFloorUpsert.id, floorPendingId)
  assert.equal(blockedFloorUpsert.severity, 'high')
})

// ============================================================================
// 3. Exhaustive projectReportEvidence & Markdown report evidence export
// ============================================================================

test('Q7.3: projectReportEvidence handles every EvidenceSummary kind + static_verified verdicts without silent evidence loss', t => {
  // Verify canonical verdict schema covers ReplayVerdict | RetestVerdict including static_verified
  for (const verdict of ['confirmed', 'static_verified', 'dismissed', 'inconclusive', 'reproduced', 'fixed'] as const) {
    assert.ok(REPORT_EVIDENCE_VERDICTS.includes(verdict))
    assert.equal(reportEvidenceVerdictSchema.safeParse(verdict).success, true)
  }

  const approved = new Set([ORIGIN])
  const staticOrigin = 'https://static-analysis.invalid'

  // Every previously-dropped kind projects structured data cleanly
  const sastProj = projectReportEvidence('sast', JSON.stringify({ engine: 'semgrep', origin: staticOrigin, matches: 2 }), staticOrigin, approved)
  const surfaceProj = projectReportEvidence('surface', JSON.stringify({ origin: ORIGIN, probeClass: 'method_matrix', status: 200 }), ORIGIN, approved)
  const patchProj = projectReportEvidence('patch', JSON.stringify({ repo: 'app', origin: staticOrigin, dynamicRetestVerdict: 'fixed' }), staticOrigin, approved)
  const wsProj = projectReportEvidence('ws', JSON.stringify({ origin: ORIGIN, frames: 3 }), ORIGIN, approved)
  const staticReplayProj = projectReportEvidence('replay', JSON.stringify({
    origin: staticOrigin,
    kind: 'static_ast_proof',
    verdict: 'static_verified',
    outcome: { confirmed: false, controlPassed: true, observed: 'ast match', expected: 'sanitized' },
  }), staticOrigin, approved)

  assert.ok(sastProj?.data)
  assert.ok(surfaceProj?.data)
  assert.ok(patchProj?.data)
  assert.ok(wsProj?.data)
  assert.ok(staticReplayProj?.data)
  assert.equal(isReportSource('sast'), true)
  assert.equal(isReportSource('surface'), true)
  assert.equal(isReportSource('patch'), true)
  assert.equal(isReportSource('ws'), true)

  // Internal orchestration records explicitly return undefined
  assert.equal(projectReportEvidence('inventory', '{}', ORIGIN, approved), undefined)
  assert.equal(projectReportEvidence('handoff', '{}', ORIGIN, approved), undefined)

  // End-to-end Markdown export with all 5 artifact kinds + parent artifact citing them as inputEvidence
  const { store } = makeTempStore(t, 'kovo-q7-evidence-')
  const { runId, run, asset, worker } = setupApprovedRun(store, 'Exhaustive Evidence App')
  const evSast = store.addArtifact(run, worker, 'sast', 'SAST scan', JSON.stringify({ engine: 'ast-grep', origin: ORIGIN, rule: 'sql-sink' }))
  const evSurface = store.addArtifact(run, worker, 'surface', 'Surface probe', JSON.stringify({ origin: ORIGIN, path: '/api/v1/export', status: 200 }))
  const evPatch = store.addArtifact(run, worker, 'patch', 'Patch verification', JSON.stringify({ origin: ORIGIN, dynamicRetestVerdict: 'fixed' }))
  const evWs = store.addArtifact(run, worker, 'ws', 'WebSocket probe', JSON.stringify({ origin: ORIGIN, channel: '/ws/live', frames: 2 }))
  const evStaticReplay = store.addArtifact(run, worker, 'replay', 'Static AST replay receipt', JSON.stringify({
    origin: ORIGIN,
    kind: 'static_ast_proof',
    verdict: 'static_verified',
  }))
  const evDerived = store.addArtifact(run, worker, 'analysis', 'Derived chain analysis', JSON.stringify({
    origin: ORIGIN,
    inputEvidence: [evSast.id, evSurface.id, evPatch.id, evWs.id],
    summary: 'Combined evidence chain',
  }))

  const fId = randomUUID()
  const spec = store.createReplaySpec(run, worker, fId, sampleHttpSpec('Full Evidence Finding'), [ORIGIN], {
    verifiedInline: true,
    lastVerificationDiff: confirmedFeedback(),
  })
  store.upsertChainFinding(run, asset.id, {
    id: fId,
    origin: ORIGIN,
    title: 'Full Evidence Finding',
    status: 'confirmed',
    severity: 'high',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    reason: 'Verified with multi-kind supporting artifacts',
    remediation: 'Enforce authorization',
    evidenceIds: [evSast.id, evSurface.id, evPatch.id, evWs.id, evStaticReplay.id, evDerived.id],
    scopeRevision: run.scopeRevision,
    verificationTier: 'runtime_confirmed',
  }, spec.id, [ORIGIN])

  const reportId = store.writeReport(store.run(runId), false)
  const md = exportReportMarkdown(store, runId, reportId).content
  assert.equal(
    md.includes('Supporting record unavailable for this report version.'),
    false,
    'Markdown export must project sast, surface, patch, ws, static_verified replay, and derived parent records without falling back to unavailable',
  )
  for (const marker of ['"kind": "sast"', '"kind": "surface"', '"kind": "patch"', '"kind": "ws"', '"verdict": "static_verified"', '"kind": "analysis"']) {
    assert.ok(md.includes(marker), `Expected Markdown evidence appendix to contain ${marker}`)
  }

  // Verify EvidenceSummary['kind'] exhaustive union check exists in report-evidence.ts
  const reportEvidenceSrc = readFileSync(join(REPO_ROOT, 'src/server/report-evidence.ts'), 'utf8')
  assert.match(reportEvidenceSrc, /const _exhaustive:\s*never\s*=\s*kind/)
  const _kindSample: EvidenceSummary['kind'] = 'ws'
  assert.equal(_kindSample, 'ws')
})

// ============================================================================
// 4. UI Static/Runtime Tier Separation, Composite DAG Rendering & Pagination
// ============================================================================

test('Q7.4: UI meta, verdict model, canVerifyFix, CompositeProofDagCard, and expandable pagination maintain strict tier separation', () => {
  // meta.ts tier separation
  assert.equal(normFStatus('confirmed'), 'confirmed')
  assert.equal(normFStatus('static_verified'), 'static_verified')
  assert.notEqual(normFStatus('static_verified'), 'confirmed')
  assert.ok(FSTAT_ORDER.confirmed < FSTAT_ORDER.static_verified)
  assert.ok(FSTAT_ORDER.static_verified < FSTAT_ORDER.pending)
  assert.equal(stLabel('confirmed'), 'Confirmed by replay')
  assert.equal(stLabel('static_verified'), 'Static advisory')

  // model.ts buildVerdict must NEVER count static_verified as confirmed by replay
  const fakeDetail = {
    run: {
      id: 'run-q7',
      status: 'complete',
      phase: 'complete',
      approved: ['a1'],
      candidates: [{ id: 'a1', origin: ORIGIN }],
    },
    approvals: [],
    coverageEntries: [],
  } as unknown as Detail
  const staticOnlyRows: FindingRow[] = [{
    id: 'f-static-1',
    origin: ORIGIN,
    title: 'Static SQLi advisory',
    status: 'static_verified',
    severity: 'high',
    reason: 'AST match',
    remediation: 'Use params',
    evidenceIds: [],
    scopeRevision: 1,
    verificationTier: 'static_verified',
  } as unknown as FindingRow]
  const verdict = buildVerdict(fakeDetail, staticOnlyRows, false)
  assert.equal(verdict.confirmed, 0, 'static_verified must NOT increment verdict.confirmed')
  assert.match(verdict.hed, /No weakness could be confirmed/)
  assert.match(verdict.dek ?? '', /static advisory/i)
  assert.match(verdict.conf.text, /0 of 1 standing findings confirmed by automated replay/)
  assert.match(verdict.conf.text, /1 static advisory/)
  assert.ok(verdict.conf.seg.some(([, , label]) => label === 'Static advisory'))

  // Regression (#954): newly created running run with zero findings must NEVER set verdict.dek to literal "null"
  const runningEmptyDetail = {
    run: {
      id: 'run-q7-empty',
      status: 'running',
      phase: 'investigation',
      approved: ['a1'],
      candidates: [{ id: 'a1', origin: ORIGIN }],
    },
    approvals: [],
    coverageEntries: [],
  } as unknown as Detail
  const runningEmptyVerdict = buildVerdict(runningEmptyDetail, [], false)
  assert.equal(runningEmptyVerdict.hed, 'No findings drafted yet; the investigation is running.')
  assert.equal(runningEmptyVerdict.dek, null, 'running empty run must have dek === null, never literal "null"')
  const runningInterruptedVerdict = buildVerdict(runningEmptyDetail, [], true)
  assert.equal(runningInterruptedVerdict.dek, 'The application restarted mid-round.')
  assert.equal(runningInterruptedVerdict.dek?.includes('null'), false)

  // findings-inspector.tsx helpers: canVerifyFix + CompositeProofDagCard
  const { canVerifyFix, canGeneratePatch, extractCompositeProofSummary, CompositeProofDagCard } = loadInspectorHelpers()
  assert.equal(canVerifyFix({ status: 'confirmed', replaySpecId: 'spec-1' }), true)
  assert.equal(canVerifyFix({ status: 'static_verified', replaySpecId: 'spec-1' }), false, 'Verify Fix must NEVER enable on static_verified advisories')
  assert.equal(canGeneratePatch({ status: 'static_verified', codeLocations: [{ repo: 'app', file: 'a.ts', startLine: 1, endLine: 2 }] }), true)

  const summary = extractCompositeProofSummary({
    proofVerdict: 'confirmed',
    proofReceipt: {
      compositeReceipt: {
        chainId: 'chain-q7-multihop',
        terminalVulnClass: 'dual_tenant_abac',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop-2-export',
            surface: 'http',
            target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/exports/job-9' },
            claimedDelta: 'Reads foreign tenant invoice export via sealed token',
            consumedCapabilities: ['cap:export-token-1'],
            producedCapabilities: [],
          },
          {
            hopId: 'hop-1-mint',
            surface: 'graphql',
            target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/graphql' },
            claimedDelta: 'Mints unscoped export handle for foreign tenant',
            consumedCapabilities: [],
            producedCapabilities: ['cap:export-token-1'],
          },
        ],
        causalEdges: [{
          kind: 'value_binding',
          fromHopId: 'hop-1-mint',
          toHopId: 'hop-2-export',
          capabilityHandle: 'cap:export-token-1',
        }],
        terminalImpact: {
          terminalHopId: 'hop-2-export',
          claimedImpact: 'Unauthorized cross-tenant financial ledger disclosure',
          oracleFamily: 'dual_tenant_abac',
        },
      },
      compositeVerification: {
        confirmed: true,
        terminalOracleFamily: 'dual_tenant_abac',
        reason: 'Mode-A clean replay verified causal handoff and cross-tenant disclosure.',
        verifiedEdges: [{ fromHopId: 'hop-1-mint', toHopId: 'hop-2-export', kind: 'value_binding', verified: true }],
      },
      hopActors: {
        'hop-1-mint': 'tenant_a_member',
        'hop-2-export': 'tenant_a_member',
      },
    },
  }, [{ verdict: 'fixed', summary: 'Blocked at hop-1-mint', patchBrokeHopId: 'hop-1-mint' }])

  assert.ok(summary)
  assert.equal(summary.chainId, 'chain-q7-multihop')
  assert.deepEqual(summary.hops.map(h => h.hopId), ['hop-1-mint', 'hop-2-export'], 'hops must be topologically ordered')
  assert.equal(summary.hops[0]!.patchBrokeHere, true)
  assert.equal(summary.hops[1]!.isTerminal, true)
  assert.equal(summary.edges[0]!.verified, true)
  assert.equal(summary.patchBrokeHopId, 'hop-1-mint')

  const html = renderToStaticMarkup(React.createElement(CompositeProofDagCard, { summary }))
  assert.match(html, /chain-q7-multihop/)
  assert.match(html, /Mode-A/)
  assert.match(html, /Terminal oracle: Confirmed/)
  assert.match(html, /dual_tenant_abac/)
  assert.match(html, /cap:export-token-1/)
  assert.match(html, /value binding/)
  assert.match(html, /Patch broke at hop-1-mint/)
  assert.match(html, /Unauthorized cross-tenant financial ledger disclosure/)

  // Source guards: pagination, DAG rendering in both views, and zero node:* imports in client components
  const inspectorSrc = readFileSync(join(REPO_ROOT, 'src/components/run/views/findings-inspector.tsx'), 'utf8')
  const reportSrc = readFileSync(join(REPO_ROOT, 'src/components/run/views/report.tsx'), 'utf8')
  const headerSrc = readFileSync(join(REPO_ROOT, 'src/components/run/header.tsx'), 'utf8')
  const findingsSrc = readFileSync(join(REPO_ROOT, 'src/components/run/views/findings.tsx'), 'utf8')

  assert.match(inspectorSrc, /Show all \$\{exIds\.length\} items/)
  assert.match(inspectorSrc, /Show all \$\{evs\.length\} items/)
  assert.match(inspectorSrc, /<CompositeProofDagCard/)
  assert.match(reportSrc, /<CompositeProofDagCard/)
  assert.match(reportSrc, /Static advisories/)
  assert.match(reportSrc, /Show all \$\{f\.evidenceIds\.length\} items/)
  assert.equal(headerSrc.includes("'static_verified'"), false, 'header.tsx must not conflate static_verified into confirmedFindings')
  assert.match(findingsSrc, /\['static_verified', 'Static advisory'\]/)

  for (const rel of [
    'src/components/run/meta.ts',
    'src/components/run/glyphs.tsx',
    'src/components/run/model.ts',
    'src/components/run/header.tsx',
    'src/components/run/views/findings.tsx',
    'src/components/run/views/overview.tsx',
    'src/components/run/views/findings-inspector.tsx',
    'src/components/run/views/report.tsx',
  ]) {
    const content = readFileSync(join(REPO_ROOT, rel), 'utf8')
    assert.doesNotMatch(content, /from\s+['"]node:/, `${rel} must remain free of Node builtins for browser bundle`)
  }
})
