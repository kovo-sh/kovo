import { useState } from 'react'
import { downloadReportMarkdown, exportSarifAction, generatePatchAction } from '../actions.ts'
import {
  callerCompatibilityLabels,
  capabilityTierLabel,
  checkLabels,
  dynamicRetestLabels,
  findingVerificationTier,
  owaspCategoryTitles,
  owaspStatusLabels,
  patchStatusLabels,
  reportEvidenceSource,
  reportHighlights,
  reportPlanLabel,
  retestVerdictLabels,
  verificationTierLabels,
} from '../report-summary.ts'
import { FormError, Status, timeText } from './common.tsx'
import type { Command } from './run-overview.tsx'
import { formatUsd } from './run-state.ts'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from './ui/dropdown-menu.tsx'
import { NativeSelect } from './ui/input.tsx'

function download(content: string, filename: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function replayKindLabel(spec: unknown): string | undefined {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return undefined
  const kind = (spec as Record<string, unknown>).kind
  if (kind === 'http_chain') return 'HTTP chain replay'
  if (kind === 'dns_takeover') return 'DNS takeover replay'
  if (kind === 'tls_audit') return 'TLS audit replay'
  if (kind === 'browser_dom') return 'Browser DOM replay'
  if (kind === 'browser_chain') return 'Interactive browser chain'
  if (kind === 'race_burst') return 'Race-condition burst'
  if (kind === 'rce_proof') return 'Non-destructive RCE proof'
  if (kind === 'sql_boolean_diff') return 'SQLi boolean differential'
  if (kind === 'ws_chain') return 'WebSocket chain replay'
  if (kind === 'upload_probe') return 'Upload pipeline probe'
  if (kind === 'static_ast_proof') return 'Deterministic Static AST proof'
  return undefined
}

function verificationTierBadgeClass(tier: string) {
  if (tier === 'runtime_confirmed') return 'badge badge-complete'
  if (tier === 'static_verified') return 'badge badge-trace'
  return 'badge badge-accent'
}

function patchStatusBadgeClass(status: string) {
  if (status === 'approved') return 'badge badge-complete'
  if (status === 'withheld') return 'badge badge-attention'
  if (status === 'rejected') return 'badge badge-danger'
  return 'badge'
}

function callerCompatBadgeClass(compat: string) {
  if (compat === 'attacker_only') return 'badge badge-complete'
  if (compat === 'needs_operator_step') return 'badge badge-attention'
  return 'badge badge-danger'
}

function dynamicRetestBadgeClass(verdict: string) {
  if (verdict === 'fixed') return 'badge badge-complete'
  if (verdict === 'reproduced') return 'badge badge-danger'
  return 'badge'
}

function safeHostLabel(origin: string) {
  try {
    const url = new URL(origin)
    return url.port ? `${url.hostname}:${url.port}` : url.hostname
  } catch {
    return origin
  }
}

function severityBadgeClass(severity: string) {
  if (severity === 'critical') return 'badge badge-danger'
  if (severity === 'high') return 'badge badge-attention'
  if (severity === 'medium') return 'badge badge-running'
  return 'badge'
}

export function RunReport({ detail, execute, pending, openEvidence }: {
  detail: RunDetail
  execute?: (command: Command, onSuccess?: () => void) => void
  pending?: boolean
  openEvidence: (id: string) => void
}) {
  const [version, setVersion] = useState<number>()
  const [exporting, setExporting] = useState(false)
  const [patchingId, setPatchingId] = useState<string | null>(null)
  const [exportError, setExportError] = useState('')
  const report = detail.reports.find(item => item.version === version) ?? detail.reports[0]
  if (!report) return <div className="report-body"><h2>Report</h2><p className="muted">The report will appear here once verification or a partial checkpoint completes.</p></div>

  const { body } = report
  const { coverage, confirmed, staticVerified, chainConfirmed, priority } = reportHighlights(body)
  const findingCount = [
    confirmed ? confirmed + (confirmed === 1 ? ' runtime/baseline confirmed finding' : ' runtime/baseline confirmed findings') : 'No runtime confirmed findings',
    ...(staticVerified ? [staticVerified + (staticVerified === 1 ? ' static-verified finding' : ' static-verified findings')] : []),
  ].join(' · ')
  const approvedHosts = body.scope.length === 1 ? '1 approved host' : body.scope.length + ' approved hosts'
  const evidenceSource = reportEvidenceSource(detail.run.sourceMode, body.selectedChecks, body.capabilityTier)
  const plannedChecks = reportPlanLabel(body.selectedChecks)
  const evidenceTitles = new Map(detail.evidence.map(item => [item.id, item.title]))
  const replaySpecById = new Map(detail.replaySpecs.map(row => [row.id, row]))
  const replaySpecByFinding = new Map(detail.replaySpecs.map(row => [row.findingId, row]))
  const retestsByFinding = new Map<string, RunDetail['retestRuns']>()
  for (const retest of detail.retestRuns) {
    const list = retestsByFinding.get(retest.findingId) ?? []
    list.push(retest)
    retestsByFinding.set(retest.findingId, list)
  }
  const activeRetestFindingIds = new Set(
    detail.assignments
      .filter(a => a.phase === 'retest' && (a.status === 'queued' || a.status === 'running'))
      .map(a => a.objective),
  )

  const confirmedFindings = body.findings.filter(item => item.status === 'confirmed')
  const staticVerifiedFindings = body.findings.filter(item => item.status === 'static_verified')
  const severityCounts = ['critical', 'high', 'medium', 'low', 'informational'].flatMap(severity => {
    const count = confirmedFindings.filter(item => item.severity === severity).length
    return count ? [`${count} ${severity}`] : []
  })
  const threatEntries = body.threatModel?.length ? body.threatModel : (detail.threatModel?.entries ?? [])
  const owaspRows = body.owaspCoverage?.length ? body.owaspCoverage : detail.coverageEntries
  const openProofGaps = body.openProofGaps?.length
    ? body.openProofGaps
    : (detail.openProofGaps ?? []).map(g => ({
        origin: g.origin,
        category: g.category,
        summary: g.summary,
        proofGapReason: g.proofGapReason || g.summary,
      }))
  const patchProposals = body.patchProposals?.length
    ? body.patchProposals
    : (detail.patchProposals ?? [])
  const findingTitleById = new Map(body.findings.map(f => [f.id, f.title]))

  async function exportMarkdown(reportId: string) {
    setExportError('')
    setExporting(true)
    try {
      const result = await downloadReportMarkdown({ data: { runId: detail.run.id, reportId } })
      download(result.content, result.filename, 'text/markdown; charset=utf-8')
    } catch {
      setExportError('Guardian could not export this report. Try again.')
    } finally {
      setExporting(false)
    }
  }

  async function exportSarif(reportId: string) {
    setExportError('')
    setExporting(true)
    try {
      const result = await exportSarifAction({ data: { runId: detail.run.id, reportId } })
      download(result.content, result.filename, 'application/sarif+json; charset=utf-8')
    } catch {
      setExportError('Guardian could not export SARIF 2.1.0 for this report. Try again.')
    } finally {
      setExporting(false)
    }
  }

  async function triggerPatch(findingId: string, repo?: string) {
    setExportError('')
    setPatchingId(findingId)
    try {
      await generatePatchAction({ data: { runId: detail.run.id, findingId, repo } })
    } catch (error) {
      setExportError(error instanceof Error ? error.message : 'Guardian could not generate a verified patch.')
    } finally {
      setPatchingId(null)
    }
  }

  function exportText() {
    setExportError('')
    const lines = [
      `Guardian ${report.partial ? 'partial report' : 'complete report'} • Version ${report.version}`,
      '', findingCount, ...(coverage ? [coverage] : []),
      '', body.goal, '', evidenceSource,
      `Capability tier: ${capabilityTierLabel(body.capabilityTier)}`,
      `Scope revision ${body.scopeRevision} · Goal revision ${body.goalRevision}`,
      ...(plannedChecks ? [plannedChecks] : []),
      ...body.scope.map(asset => asset.origin),
      ...(threatEntries.length ? [
        '', 'Threat model',
        ...threatEntries.map(entry => `${entry.origin} · ${entry.riskTier} · [${entry.surfaceTags.join(', ')}] · ${entry.rationale}`),
      ] : []),
      ...(priority ? [
        '', 'Fix first', priority.label,
        ...(priority.finding ? [priority.finding.origin, priority.finding.remediation] : []),
      ] : []),
      '', 'Findings',
      ...body.findings.flatMap(item => {
        const retests = retestsByFinding.get(item.id) ?? []
        const latestRetest = retests[0]
        return [
          `${item.title} · ${item.origin} · ${item.severity} · ${item.status}${item.findingKind === 'multi_step_chain' ? ' · multi-step chain' : ''}`,
          ...(item.category ? [`Class: ${item.category}${item.cwe ? ` · ${item.cwe}` : ''}`] : []),
          ...(item.confidence ? [`Confidence: ${item.confidence}`] : []),
          ...(item.check ? [`Observed: ${item.check.observed ?? 'Unavailable'}`, `Expected: ${item.check.expected}`] : []),
          item.reason,
          ...(item.impact ? [`Impact: ${item.impact}`] : []),
          ...(item.verification ? [`Verification: ${item.verification}`] : []),
          `Remediation: ${item.remediation}`,
          ...(item.recheck ? [`Check the fix: ${item.recheck}`] : []),
          ...(latestRetest ? [`Latest Verify Fix retest: ${retestVerdictLabels[latestRetest.verdict]} — ${latestRetest.summary}`] : []),
          `Evidence ${item.evidenceIds.join(', ')}`, '',
        ]
      }),
      ...(owaspRows.length ? [
        'OWASP / API Top 10 coverage',
        ...owaspRows.map(row => `${row.origin} · ${owaspCategoryTitles[row.category] ?? row.category} · ${owaspStatusLabels[row.status]} · ${row.summary}`),
        '',
      ] : []),
      'Coverage',
      ...body.coverage.flatMap(item => [
        [item.origin, item.status, item.evidenceId && `Evidence ${item.evidenceId}`,
          item.analysisEvidenceId && `Derived evidence ${item.analysisEvidenceId}`,
          item.accessEvidence && `Access records ${item.accessEvidence.id}`,
          item.accessEvidence?.recordedAt && `Recorded ${item.accessEvidence.recordedAt}`,
        ].filter(Boolean).join(' · '),
        ...(item.checks ?? []).flatMap(check => [
          `  ${check.title} · ${checkLabels[check.status]}`,
          ...(check.status === 'untested' ? [] : [`    Observed: ${check.observed ?? 'Unavailable'}`]),
          `    Expected: ${check.expected}`,
          `    ${check.reason}`,
        ]),
      ]),
      '', 'Coverage gaps', ...body.gaps,
    ]
    download(lines.join('\n'), `guardian-report-${report.version}.txt`, 'text/plain')
  }

  return <article className="report-body" aria-labelledby="report-title">
    <div className="section-heading report-top">
      <div><p className="eyebrow">Report · {timeText(report.createdAt)}</p>
        <h2 id="report-title">{report.partial ? 'Partial report' : 'Complete report'}</h2>
      </div>
      <div className="toolbar">
        <label>Version <NativeSelect value={report.version} onChange={event => {
          setVersion(Number(event.target.value))
          setExportError('')
        }}>
          {detail.reports.map(item => <option key={item.id} value={item.version}>{item.version}</option>)}
        </NativeSelect></label>
        <Button variant="ghost" disabled={exporting} onClick={() => void exportSarif(report.id)}>
          Download SARIF 2.1.0
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="ghost" />} disabled={exporting}>
            {exporting ? 'Exporting…' : 'Export'}
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onClick={() => void exportMarkdown(report.id)}>Markdown with evidence</DropdownMenuItem>
            <DropdownMenuItem onClick={() => void exportSarif(report.id)}>SARIF 2.1.0 (.sarif.json)</DropdownMenuItem>
            <DropdownMenuItem onClick={exportText}>Plain text</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
    <FormError error={exportError} />
    <p className="report-summary">
      {findingCount}{chainConfirmed > 0 ? ` (${chainConfirmed} multi-step ${chainConfirmed === 1 ? 'chain' : 'chains'})` : ''}
    </p>
    {coverage && <p className="report-check-summary">{coverage}</p>}
    {severityCounts.length > 0 && <p className="muted">Confirmed severity · {severityCounts.join(' · ')}</p>}
    <p>{body.goal}</p>
    <p className="muted">{approvedHosts} · Scope revision {body.scopeRevision} · Goal revision {body.goalRevision}</p>
    <p className="muted">{evidenceSource}</p>
    {plannedChecks && <p className="muted">{plannedChecks}</p>}

    {body.metrics && <div className="metrics-strip" aria-label="Assessment metrics">
      <span>Turns <strong>{body.metrics.turnsUsed}</strong></span>
      <span>Requests <strong>{body.metrics.requestsUsed}</strong></span>
      <span>Facts <strong>{body.metrics.factsRecorded}</strong></span>
      <span>Chain steps <strong>{body.metrics.chainStepsCompleted}</strong> completed{body.metrics.chainStepsUntested > 0 ? `, ${body.metrics.chainStepsUntested} untested` : ''}</span>
      <span>Spend <strong>{formatUsd(body.metrics.spentUsd)}</strong></span>
    </div>}

    {priority && <section className="report-priority" aria-labelledby="report-priority-title">
      <h3 id="report-priority-title">Fix first</h3>
      <a href={priority.finding ? '#report-finding-' + priority.finding.id : '#report-findings'}>{priority.label}</a>
      {priority.finding && <>
        <p className="finding-meta">{new URL(priority.finding.origin).hostname} · {priority.finding.severity}</p>
        <p>{priority.finding.remediation}</p>
      </>}
    </section>}

    {threatEntries.length > 0 && <section className="stacked-section" aria-label="Threat model">
      <h3>Threat model ranking</h3>
      <div className="threat-grid">
        {threatEntries.map(entry => <div key={entry.origin} className="threat-card">
          <div className="threat-card-head">
            <strong>{new URL(entry.origin).hostname}</strong>
            <div className="inline-badges">
              {entry.surfaceTags.map(tag => <span key={tag} className="badge">{tag}</span>)}
              <span className={severityBadgeClass(entry.riskTier)}>{entry.riskTier}</span>
            </div>
          </div>
          <p className="muted">{entry.rationale}</p>
        </div>)}
      </div>
    </section>}

    {body.findings.length > 0 && <section className="stacked-section" id="report-findings" tabIndex={-1}>
      <h3>Findings</h3>
      {body.findings.map(item => {
        const replayRow = (item.replaySpecId ? replaySpecById.get(item.replaySpecId) : undefined) ?? replaySpecByFinding.get(item.id)
        const replayLabel = replayRow ? replayKindLabel(replayRow.spec) : undefined
        const retests = retestsByFinding.get(item.id) ?? []
        const latestRetest = retests[0]
        const retestQueued = [...activeRetestFindingIds].some(obj => obj.includes(item.id))
        const canRetest = Boolean(execute && item.status === 'confirmed' && (item.replaySpecId || replayRow))
        const tier = findingVerificationTier(item)
        const canPatch = Boolean(
          (item.status === 'confirmed' || item.status === 'static_verified') &&
          item.codeLocations && item.codeLocations.length > 0,
        )

        return <div key={item.id} className="finding" id={'report-finding-' + item.id} tabIndex={-1}>
          <div className="section-heading">
            <h4>{item.title}</h4>
            <div className="inline-badges">
              {tier && <span className={verificationTierBadgeClass(tier)}>{verificationTierLabels[tier]}</span>}
              <Status status={item.status} />
            </div>
          </div>
          <div className="inline-badges">
            <span className="finding-meta">{safeHostLabel(item.origin)}</span>
            <span className={severityBadgeClass(item.severity)}>{item.severity}</span>
            {item.findingKind === 'multi_step_chain' && <span className="badge badge-trace">Multi-step chain</span>}
            {replayLabel && <span className="badge badge-accent">{replayLabel}</span>}
            {item.cwe && <span className="badge">{item.cwe}</span>}
            {item.chainFactIds && item.chainFactIds.length > 0 && <span className="badge">{item.chainFactIds.length} chain facts</span>}
            {item.exchangeIds && item.exchangeIds.length > 0 && <span className="badge">{item.exchangeIds.length} exchanges</span>}
          </div>
          <dl className="finding-details">
            {item.category && <><dt>Class</dt><dd>{item.category}{item.cwe && <> · {item.cwe}</>}</dd></>}
            {item.confidence && <><dt>Confidence</dt><dd>{item.confidence}{item.confidenceRationale ? ` — ${item.confidenceRationale}` : ''}</dd></>}
            {item.check && <>
              <dt>Observed</dt><dd>{item.check.observed ?? 'Unavailable'}</dd>
              <dt>Expected</dt><dd>{item.check.expected}</dd>
            </>}
            {item.impact && <><dt>Impact</dt><dd>{item.impact}</dd></>}
            {item.counterevidence && <><dt>Counterevidence</dt><dd>{item.counterevidence}</dd></>}
            {item.runtimeProofGap && <><dt>Runtime proof gap</dt><dd>{item.runtimeProofGap}</dd></>}
            {item.codeLocations && item.codeLocations.length > 0 && <>
              <dt>Code locations</dt>
              <dd>{item.codeLocations.map(loc => `${loc.repo}/${loc.file}:${loc.startLine}${loc.endLine > loc.startLine ? `-${loc.endLine}` : ''}`).join(', ')}</dd>
            </>}
            {item.verification && <><dt>Verification</dt><dd>{item.verification}</dd></>}
            <dt>{item.status === 'confirmed' || item.status === 'static_verified' ? 'Remediation' : 'Follow-up'}</dt><dd>{item.remediation}</dd>
            {item.recheck && <><dt>Check the fix</dt><dd>{item.recheck}</dd></>}
          </dl>
          {(!item.check || item.status !== 'confirmed') && <p>{item.reason}</p>}
          <div className="toolbar report-evidence">
            {item.evidenceIds.map(id => <Button key={id} variant="ghost" onClick={() => openEvidence(id)}>
              {evidenceTitles.get(id) ?? 'Open finding evidence'}
            </Button>)}
            {canPatch && <Button variant="ghost" disabled={patchingId === item.id} onClick={() => {
              void triggerPatch(item.id, item.codeLocations?.[0]?.repo)
            }}>{patchingId === item.id ? 'Generating patch…' : 'Generate Verified Patch'}</Button>}
          </div>
          {(canRetest || latestRetest) && <div className="retest-bar">
            <div className="inline-badges">
              {latestRetest ? <>
                <Status status={latestRetest.verdict} />
                <strong>{retestVerdictLabels[latestRetest.verdict]}</strong>
                <span className="muted">{latestRetest.summary} · {timeText(latestRetest.createdAt)}</span>
                {latestRetest.evidenceIds.map(eid => <Button key={eid} variant="ghost" onClick={() => openEvidence(eid)}>
                  Retest evidence ↗
                </Button>)}
              </> : <span className="muted">Deterministic zero-LLM replay spec ready for fix verification.</span>}
            </div>
            {canRetest && <Button disabled={pending || retestQueued} onClick={() => {
              execute?.({ action: 'retest_finding', findingId: item.id })
            }}>{retestQueued ? 'Verifying fix…' : 'Verify Fix'}</Button>}
          </div>}
        </div>
      })}
    </section>}

    {(confirmedFindings.length > 0 || staticVerifiedFindings.length > 0) && <section className="stacked-section">
      <h3>Remediation plan</h3>
      <ol>{[...confirmedFindings, ...staticVerifiedFindings].map(item => {
        const tier = findingVerificationTier(item)
        return <li key={item.id}>
          <strong>{item.title}</strong>{tier && <> <span className={verificationTierBadgeClass(tier)}>{verificationTierLabels[tier]}</span></>}
          <p>{item.remediation}</p>
          {item.recheck && <p className="muted">Recheck · {item.recheck}</p>}
        </li>
      })}</ol>
    </section>}

    {patchProposals.length > 0 && <section className="stacked-section" aria-label="Verified Patch Diffs">
      <h3>Verified Patch Diffs</h3>
      <div className="threat-grid">
        {patchProposals.map(patch => <article key={patch.id} className="threat-card">
          <div className="threat-card-head">
            <strong>{findingTitleById.get(patch.findingId) ?? patch.findingId} · {patch.repo}</strong>
            <div className="inline-badges">
              <span className={patchStatusBadgeClass(patch.status)}>{patchStatusLabels[patch.status]}</span>
              <span className={callerCompatBadgeClass(patch.callerCompatibility)}>{callerCompatibilityLabels[patch.callerCompatibility]}</span>
              <span className={dynamicRetestBadgeClass(patch.dynamicRetestVerdict)}>{dynamicRetestLabels[patch.dynamicRetestVerdict]}</span>
            </div>
          </div>
          {patch.codeLocations.length > 0 && <p className="muted">
            {patch.codeLocations.map(l => `${l.file}:${l.startLine}-${l.endLine}`).join(', ')}
          </p>}
          {patch.reviewNotes && <p className="muted">{patch.reviewNotes}</p>}
          {patch.status === 'approved' && patch.diff.trim()
            ? <pre className="approval-preview">{patch.diff}</pre>
            : patch.status === 'withheld' && <p className="muted">Diff withheld automatically because the independent patch reviewer flagged caller compatibility or gate failure.</p>}
        </article>)}
      </div>
    </section>}

    {openProofGaps.length > 0 && <section className="stacked-section" aria-label="Open Proof Gaps">
      <h3>Open Proof Gaps</h3>
      <div className="table-scroll">
        <table className="owasp-table">
          <thead>
            <tr>
              <th scope="col">Host</th>
              <th scope="col">Category</th>
              <th scope="col">Proof Gap Reason</th>
              <th scope="col">Summary</th>
            </tr>
          </thead>
          <tbody>
            {openProofGaps.map((gap, index) => <tr key={`${gap.origin}-${gap.category}-${index}`}>
              <td><strong>{safeHostLabel(gap.origin)}</strong></td>
              <td>{owaspCategoryTitles[gap.category as keyof typeof owaspCategoryTitles] ?? gap.category}</td>
              <td><span className="badge badge-attention">{gap.proofGapReason}</span></td>
              <td className="muted">{gap.summary}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </section>}

    {owaspRows.length > 0 && <section className="stacked-section" aria-label="OWASP and API Top 10 coverage">
      <h3>OWASP / API Top 10 coverage</h3>
      <div className="table-scroll">
        <table className="owasp-table">
          <thead>
            <tr>
              <th scope="col">Host</th>
              <th scope="col">Category</th>
              <th scope="col">Status</th>
              <th scope="col">Summary</th>
            </tr>
          </thead>
          <tbody>
            {owaspRows.map((row, index) => <tr key={`${row.origin}-${row.category}-${index}`}>
              <td><strong>{new URL(row.origin).hostname}</strong></td>
              <td>{owaspCategoryTitles[row.category] ?? row.category}</td>
              <td><span className={row.status === 'reported' ? 'badge badge-danger'
                : row.status === 'needs_follow_up' ? 'badge badge-attention'
                  : row.status === 'no_issue_found' || row.status === 'ruled_out' ? 'badge badge-complete'
                    : 'badge'}>{owaspStatusLabels[row.status]}</span></td>
              <td className="muted">{row.summary}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </section>}

    <section className="stacked-section">
      <h3>Host coverage</h3>
      <ul className="report-hosts">{body.coverage.map(item => <li key={item.origin}>
        <div className="list-row">
          <span><strong>{new URL(item.origin).hostname}</strong><small>{item.status}</small>
            {item.accessEvidence?.recordedAt && <small>Access decisions recorded <time dateTime={item.accessEvidence.recordedAt}>
              {timeText(Date.parse(item.accessEvidence.recordedAt))}
            </time></small>}
          </span>
          <div className="toolbar report-evidence">
            {item.evidenceId && <Button variant="ghost" onClick={() => openEvidence(item.evidenceId!)}>Open evidence</Button>}
            {item.analysisEvidenceId && <Button variant="ghost" onClick={() => openEvidence(item.analysisEvidenceId!)}>Derived evidence</Button>}
            {item.accessEvidence && <Button variant="ghost" onClick={() => openEvidence(item.accessEvidence!.id)}>Access records</Button>}
          </div>
        </div>
        {item.checks && <details className="report-checks">
          <summary>Checks for {new URL(item.origin).hostname}</summary>
          <ul>{item.checks.map(check => <li key={check.caseId ? check.id + ':' + check.caseId : check.id}>
            <div className="section-heading"><strong>{check.title}</strong><span>{checkLabels[check.status]}</span></div>
            <dl className="finding-details">
              {check.status !== 'untested' && <><dt>Observed</dt><dd>{check.observed ?? 'Unavailable'}</dd></>}
              <dt>Expected</dt><dd>{check.expected}</dd>
            </dl>
            <p className="muted">{check.reason}</p>
          </li>)}</ul>
        </details>}
      </li>)}</ul>
    </section>

    {body.gaps.length > 0 && <section className="stacked-section">
      <h3>Coverage gaps</h3><ul>{body.gaps.map(gap => <li key={gap}>{gap}</li>)}</ul>
    </section>}

    <section className="stacked-section">
      <h3>Methodology and limitations</h3>
      <p>Guardian evaluated only the approved hosts, capability tier, personas, and recorded evidence in this report. Model commentary and CVE version matches only create hypotheses; every confirmed finding requires deterministic Zero-LLM Replay Verification against a clean control check.</p>
      <p className="muted">Inconclusive, ruled-out, not-applicable, and untested categories remain visible rather than counting as passes. This evidence-led review does not guarantee that no other vulnerability exists.</p>
    </section>
  </article>
}
