import { useState } from 'react'
import { downloadReportMarkdown } from '../actions.ts'
import { checkLabels, reportEvidenceSource, reportHighlights, reportPlanLabel } from '../report-summary.ts'
import { FormError, Status, timeText } from './common.tsx'
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

export function RunReport({ detail, openEvidence }: {
  detail: RunDetail
  openEvidence: (id: string) => void
}) {
  const [version, setVersion] = useState<number>()
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')
  const report = detail.reports.find(item => item.version === version) ?? detail.reports[0]
  if (!report) return <div className="report-body"><h2>Report</h2><p className="muted">The report will appear here when the run ends.</p></div>

  const { body } = report
  const { coverage, confirmed, priority } = reportHighlights(body)
  const findingCount = confirmed ? confirmed + (confirmed === 1 ? ' confirmed finding' : ' confirmed findings') : 'No confirmed findings'
  const approvedHosts = body.scope.length === 1 ? '1 approved host' : body.scope.length + ' approved hosts'
  const evidenceSource = reportEvidenceSource(detail.run.sourceMode, body.selectedChecks)
  const plannedChecks = reportPlanLabel(body.selectedChecks)
  const evidenceTitles = new Map(detail.evidence.map(item => [item.id, item.title]))
  const confirmedFindings = body.findings.filter(item => item.status === 'confirmed')
  const severityCounts = ['critical', 'high', 'medium', 'low', 'informational'].flatMap(severity => {
    const count = confirmedFindings.filter(item => item.severity === severity).length
    return count ? [`${count} ${severity}`] : []
  })

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

  function exportText() {
    setExportError('')
    const lines = [
      `Guardian ${report.partial ? 'partial report' : 'complete report'} • Version ${report.version}`,
      '', findingCount, ...(coverage ? [coverage] : []),
      '', body.goal, '', evidenceSource, `Scope revision ${body.scopeRevision} · Goal revision ${body.goalRevision}`,
      ...(plannedChecks ? [plannedChecks] : []),
      ...body.scope.map(asset => asset.origin),
      ...(priority ? [
        '', 'Fix first', priority.label,
        ...(priority.finding ? [priority.finding.origin, priority.finding.remediation] : []),
      ] : []),
      '', 'Coverage',
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
      '', 'Findings',
      ...body.findings.flatMap(item => [
        `${item.title} · ${item.origin} · ${item.severity} · ${item.status}`,
        ...(item.category ? [`Class: ${item.category}${item.cwe ? ` · ${item.cwe}` : ''}`] : []),
        ...(item.confidence ? [`Confidence: ${item.confidence}`] : []),
        ...(item.check ? [`Observed: ${item.check.observed ?? 'Unavailable'}`, `Expected: ${item.check.expected}`] : []),
        item.reason,
        ...(item.impact ? [`Impact: ${item.impact}`] : []),
        ...(item.verification ? [`Verification: ${item.verification}`] : []),
        `Remediation: ${item.remediation}`,
        ...(item.recheck ? [`Check the fix: ${item.recheck}`] : []),
        `Evidence ${item.evidenceIds.join(', ')}`, '',
      ]),
      'Coverage gaps', ...body.gaps,
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
        <DropdownMenu>
          <DropdownMenuTrigger render={<Button variant="ghost" />} disabled={exporting}>
            {exporting ? 'Exporting…' : 'Export'}
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onClick={() => void exportMarkdown(report.id)}>Markdown with evidence</DropdownMenuItem>
            <DropdownMenuItem onClick={exportText}>Plain text</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
    <FormError error={exportError} />
    <p className="report-summary">{findingCount}</p>
    {coverage && <p className="report-check-summary">{coverage}</p>}
    {severityCounts.length > 0 && <p className="muted">Confirmed severity · {severityCounts.join(' · ')}</p>}
    <p>{body.goal}</p>
    <p className="muted">{approvedHosts} · Scope revision {body.scopeRevision} · Goal revision {body.goalRevision}</p>
    <p className="muted">{evidenceSource}</p>
    {plannedChecks && <p className="muted">{plannedChecks}</p>}
    {priority && <section className="report-priority" aria-labelledby="report-priority-title">
      <h3 id="report-priority-title">Fix first</h3>
      <a href={priority.finding ? '#report-finding-' + priority.finding.id : '#report-findings'}>{priority.label}</a>
      {priority.finding && <>
        <p className="finding-meta">{new URL(priority.finding.origin).hostname} · {priority.finding.severity}</p>
        <p>{priority.finding.remediation}</p>
      </>}
    </section>}
    {body.findings.length > 0 && <section className="stacked-section" id="report-findings" tabIndex={-1}>
      <h3>Findings</h3>
      {body.findings.map(item => <div key={item.id} className="finding" id={'report-finding-' + item.id} tabIndex={-1}>
        <div className="section-heading"><h4>{item.title}</h4><Status status={item.status} /></div>
        <p className="finding-meta">{new URL(item.origin).hostname} · {item.severity}</p>
        {item.check && <dl className="finding-details">
          {item.category && <><dt>Class</dt><dd>{item.category}{item.cwe && <> · {item.cwe}</>}</dd></>}
          {item.confidence && <><dt>Confidence</dt><dd>{item.confidence}</dd></>}
          <dt>Observed</dt><dd>{item.check.observed ?? 'Unavailable'}</dd>
          <dt>Expected</dt><dd>{item.check.expected}</dd>
          {item.impact && <><dt>Impact</dt><dd>{item.impact}</dd></>}
          {item.verification && <><dt>Verification</dt><dd>{item.verification}</dd></>}
          <dt>{item.status === 'confirmed' ? 'Remediation' : 'Follow-up'}</dt><dd>{item.remediation}</dd>
          {item.recheck && <><dt>Check the fix</dt><dd>{item.recheck}</dd></>}
        </dl>}
        {(!item.check || item.status !== 'confirmed') && <p>{item.reason}</p>}
        {!item.check && <p>{item.remediation}</p>}
        <div className="toolbar report-evidence">
          {item.evidenceIds.map(id => <Button key={id} variant="ghost" onClick={() => openEvidence(id)}>
            {evidenceTitles.get(id) ?? 'Open finding evidence'}
          </Button>)}
        </div>
      </div>)}
    </section>}
    {confirmedFindings.length > 0 && <section className="stacked-section">
      <h3>Remediation plan</h3>
      <ol>{confirmedFindings.map(item => <li key={item.id}>
        <strong>{item.title}</strong><p>{item.remediation}</p><p className="muted">Recheck · {item.recheck}</p>
      </li>)}</ol>
    </section>}
    <section className="stacked-section">
      <h3>Coverage</h3>
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
      <p>Guardian evaluated only the approved hosts, selected checks, and recorded evidence in this report. A confirmed finding requires an isolated-worker comparison linked to source evidence; model commentary alone cannot confirm it.</p>
      <p className="muted">Inconclusive, not-applicable, and untested checks remain visible rather than counting as passes. This evidence-led review does not guarantee that no other vulnerability exists.</p>
    </section>
  </article>
}
