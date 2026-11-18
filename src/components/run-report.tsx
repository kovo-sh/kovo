import { useState } from 'react'
import { Status, timeText } from './common.tsx'
import type { RunDetail } from './run-state.ts'
import { Button } from './ui/button.tsx'
import { NativeSelect } from './ui/input.tsx'

export function RunReport({ detail, openEvidence }: {
  detail: RunDetail
  openEvidence: (id: string) => void
}) {
  const [version, setVersion] = useState<number>()
  const report = detail.reports.find(item => item.version === version) ?? detail.reports[0]
  if (!report) return <div className="report-body"><h2>Report</h2><p className="muted">The report will appear here when the run ends.</p></div>

  const { body } = report
  const confirmed = body.findings.filter(item => item.status === 'confirmed').length

  function exportText() {
    const lines = [
      `Guardian ${report.partial ? 'partial report' : 'complete report'} • Version ${report.version}`,
      '', body.goal, '', `Scope revision ${body.scopeRevision} · Goal revision ${body.goalRevision}`,
      ...body.scope.map(asset => asset.origin), '', 'Coverage',
      ...body.coverage.map(item => [item.origin, item.status, item.evidenceId && `Evidence ${item.evidenceId}`,
        item.analysisEvidenceId && `Derived evidence ${item.analysisEvidenceId}`].filter(Boolean).join(' · ')),
      '', 'Findings',
      ...body.findings.flatMap(item => [
        `${item.title} · ${item.origin} · ${item.severity} · ${item.status}`,
        item.reason, item.remediation, `Evidence ${item.evidenceIds.join(', ')}`, '',
      ]),
      'Coverage gaps', ...body.gaps,
    ]
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/plain' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `guardian-report-${report.version}.txt`
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return <article className="report-body" aria-labelledby="report-title">
    <div className="section-heading report-top">
      <div><p className="eyebrow">Report · {timeText(report.createdAt)}</p>
        <h2 id="report-title">{report.partial ? 'Partial report' : 'Complete report'}</h2>
      </div>
      <div className="toolbar">
        <label>Version <NativeSelect value={report.version} onChange={event => setVersion(Number(event.target.value))}>
          {detail.reports.map(item => <option key={item.id} value={item.version}>{item.version}</option>)}
        </NativeSelect></label>
        <Button variant="ghost" onClick={exportText}>Export text</Button>
      </div>
    </div>
    <p className="report-summary">{confirmed ? `${confirmed} confirmed ${confirmed === 1 ? 'finding' : 'findings'}` : 'No confirmed findings'}</p>
    <p>{body.goal}</p>
    <p className="muted">Scope revision {body.scopeRevision} · Goal revision {body.goalRevision}</p>
    <section className="stacked-section">
      <h3>Coverage</h3>
      <ul className="project-list">{body.coverage.map(item => <li key={item.origin}><div className="list-row">
        <span><strong>{new URL(item.origin).hostname}</strong><small>{item.status}</small></span>
        <div className="toolbar">
          {item.evidenceId && <Button variant="ghost" onClick={() => openEvidence(item.evidenceId!)}>Open evidence</Button>}
          {item.analysisEvidenceId && <Button variant="ghost" onClick={() => openEvidence(item.analysisEvidenceId!)}>Derived evidence</Button>}
        </div>
      </div></li>)}</ul>
    </section>
    <section className="stacked-section">
      <h3>Findings</h3>
      {body.findings.length === 0 && <p className="muted">No findings recorded.</p>}
      {body.findings.map(item => <div key={item.id} className="finding">
        <div className="section-heading"><h4>{item.title}</h4><Status status={item.status} /></div>
        <p className="muted">{new URL(item.origin).hostname} · {item.severity}</p>
        <p>{item.reason}</p>
        <p>{item.remediation}</p>
        {item.evidenceIds.map(id => <Button key={id} onClick={() => openEvidence(id)}>Open finding evidence</Button>)}
      </div>)}
    </section>
    {body.gaps.length > 0 && <section className="stacked-section">
      <h3>Coverage gaps</h3><ul>{body.gaps.map(gap => <li key={gap}>{gap}</li>)}</ul>
    </section>}
  </article>
}
