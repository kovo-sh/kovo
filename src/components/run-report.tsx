import { useState } from 'react'
import { downloadReportMarkdown } from '../actions.ts'
import { checkLabels, reportEvidenceSource, reportPlanLabel } from '../report-summary.ts'
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
  const confirmed = body.findings.filter(item => item.status === 'confirmed').length
  const approvedHosts = body.scope.length === 1 ? '1 approved host' : body.scope.length + ' approved hosts'
  const evidenceSource = reportEvidenceSource(detail.run.sourceMode, body.selectedChecks)
  const plannedChecks = reportPlanLabel(body.selectedChecks)
  const evidenceTitles = new Map(detail.evidence.map(item => [item.id, item.title]))

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
      '', body.goal, '', evidenceSource, `Scope revision ${body.scopeRevision} · Goal revision ${body.goalRevision}`,
      ...(plannedChecks ? [plannedChecks] : []),
      ...body.scope.map(asset => asset.origin), '', 'Coverage',
      ...body.coverage.flatMap(item => [
        [item.origin, item.status, item.evidenceId && `Evidence ${item.evidenceId}`,
          item.analysisEvidenceId && `Derived evidence ${item.analysisEvidenceId}`,
          item.accessEvidence && `Access records ${item.accessEvidence.id}`,
          item.accessEvidence?.recordedAt && `Recorded ${item.accessEvidence.recordedAt}`,
        ].filter(Boolean).join(' · '),
        ...(item.checks ?? []).flatMap(check => [
          `  ${check.title} · ${checkLabels[check.status]}`,
          `    Observed: ${check.observed ?? 'Unavailable'}`,
          `    Expected: ${check.expected}`,
          `    ${check.reason}`,
        ]),
      ]),
      '', 'Findings',
      ...body.findings.flatMap(item => [
        `${item.title} · ${item.origin} · ${item.severity} · ${item.status}`,
        ...(item.check ? [`Observed: ${item.check.observed ?? 'Unavailable'}`, `Expected: ${item.check.expected}`] : []),
        item.reason,
        ...(item.impact ? [`Impact: ${item.impact}`] : []),
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
    <p className="report-summary">{confirmed ? `${confirmed} confirmed ${confirmed === 1 ? 'finding' : 'findings'}` : 'No confirmed findings'}</p>
    <p>{body.goal}</p>
    <p className="muted">{approvedHosts} · Scope revision {body.scopeRevision} · Goal revision {body.goalRevision}</p>
    <p className="muted">{evidenceSource}</p>
    {plannedChecks && <p className="muted">{plannedChecks}</p>}
    {body.findings.length > 0 && <section className="stacked-section">
      <h3>Findings</h3>
      {body.findings.map(item => <div key={item.id} className="finding">
        <div className="section-heading"><h4>{item.title}</h4><Status status={item.status} /></div>
        <p className="finding-meta">{new URL(item.origin).hostname} · {item.severity}</p>
        {item.check && <dl className="finding-details">
          <dt>Observed</dt><dd>{item.check.observed ?? 'Unavailable'}</dd>
          <dt>Expected</dt><dd>{item.check.expected}</dd>
          {item.impact && <><dt>Impact</dt><dd>{item.impact}</dd></>}
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
              <dt>Observed</dt><dd>{check.observed ?? 'Unavailable'}</dd>
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
  </article>
}
