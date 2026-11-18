import { createHash } from 'node:crypto'
import { and, eq } from 'drizzle-orm'
import { id as evidenceId } from '../domain.ts'
import type { EvidenceSummary } from '../domain.ts'
import { checkLabels, reportEvidenceSource, reportHighlights, reportPlanLabel, suppliedResponseLabel } from '../report-summary.ts'
import { redact } from './redact.ts'
import { isReportSource, projectReportEvidence } from './report-evidence.ts'
import { reports } from './schema.ts'
import type { Store } from './store.ts'

type Attachment = {
  number: number
  origin: string
  kind?: EvidenceSummary['kind']
  json?: string
  sources?: Attachment[]
}

const evidenceLabels: Partial<Record<EvidenceSummary['kind'], string>> = {
  observation: 'Response observation',
  'access-policy': 'Supplied access policy records',
  analysis: 'Analysis record',
  verification: 'Worker verification',
}

function inline(value: string) {
  return redact(value).replace(/\s+/g, ' ')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replace(/[\\`*_{}\[\]()#|~]/g, '\\$&')
}

function linkTo({ number }: Attachment) {
  return `[Evidence ${number}](#evidence-${number})`
}

export function exportReportMarkdown(storage: Store, runId: string, reportId: string) {
  const run = storage.run(runId)
  const report = storage.db.select().from(reports).where(and(eq(reports.runId, run.id), eq(reports.id, reportId))).get()
  if (!report) throw new Error('Report version not found.')

  const { body, createdAt } = report
  const scope = new Map(body.scope.map(asset => [asset.origin, asset.id]))
  const approved = new Set(scope.keys())
  const assignments = new Map(storage.workerList(run.id).map(worker => [worker.id, worker]))
  const attachments = new Map<string, Attachment>()

  function includeEvidence(origin: string, id: string, sourceOnly = false): Attachment | undefined {
    const key = origin + ' ' + id
    const existing = attachments.get(key)
    if (existing) return sourceOnly && (!existing.kind || !isReportSource(existing.kind)) ? undefined : existing
    const record = (() => {
      if (!approved.has(origin) || !evidenceId.safeParse(id).success) return
      try { return storage.artifact(run.id, id) } catch { return }
    })()
    if (sourceOnly && record && !isReportSource(record.kind)) return

    const entry: Attachment = { number: attachments.size + 1, origin, kind: record?.kind }
    attachments.set(key, entry)
    if (!record || !evidenceLabels[record.kind]) return entry
    const assignment = assignments.get(record.assignmentId)
    if (!assignment || assignment.assetId !== scope.get(origin) ||
        assignment.phase !== (record.kind === 'verification' ? 'verification' : 'analysis') ||
        record.goalRevision !== body.goalRevision || assignment.goalRevision !== body.goalRevision ||
        record.scopeRevision > body.scopeRevision || assignment.scopeRevision > body.scopeRevision ||
        record.createdAt > createdAt) return entry
    if (record.kind === 'observation' && storage.brokerOrigins(assignment).some(host => !approved.has(host))) return entry

    const projected = projectReportEvidence(record.kind, record.content, origin, approved)
    if (!projected) return entry
    const sources = [...new Set(projected.sources ?? [])].map(source => includeEvidence(origin, source, true))
    entry.sources = sources.filter(source => source !== undefined)
    if (sources.some(source => !source?.json)) return entry
    const json = JSON.stringify({
      kind: record.kind, artifactId: record.id, assignmentId: assignment.id, origin,
      capturedAt: new Date(record.createdAt).toISOString(),
      scopeRevision: record.scopeRevision, goalRevision: record.goalRevision,
      ...(projected.sources ? { inputEvidence: [...new Set(projected.sources)] } : {}),
      ...projected.data,
    }, null, 2)
    if (redact(json) === json) entry.json = json
    return entry
  }

  function evidenceLinks(origin: string, ids: string[]) {
    return [...new Set(ids)].flatMap(id => {
      const entry = includeEvidence(origin, id)
      return entry ? [linkTo(entry)] : []
    }).join(' · ')
  }

  const findings = body.findings.filter(item => approved.has(item.origin))
  const { coverage, confirmed, priority } = reportHighlights(body)
  const plan = reportPlanLabel(body.selectedChecks)
  const confirmedFindings = findings.filter(item => item.status === 'confirmed')
  const severityCounts = ['critical', 'high', 'medium', 'low', 'informational'].flatMap(severity => {
    const count = confirmedFindings.filter(item => item.severity === severity).length
    return count ? [`- **${severity[0].toUpperCase() + severity.slice(1)}** ${count}`] : []
  })
  const lines = [
    `# Guardian ${report.partial ? 'partial' : 'complete'} report`, '',
    `**${confirmed} confirmed ${confirmed === 1 ? 'finding' : 'findings'}**`, '',
    ...(coverage ? [inline(coverage), ''] : []),
    `- **Run** ${run.id}`,
    `- **Report version** ${report.version}`,
    `- **Saved** ${new Date(createdAt).toISOString()}`,
    `- **Goal** ${inline(body.goal)}`,
    `- **Scope revision** ${body.scopeRevision} · **Goal revision** ${body.goalRevision}`,
    `- **Evidence source** ${inline(reportEvidenceSource(run.sourceMode, body.selectedChecks))}`,
    ...(plan ? ['- ' + inline(plan)] : []),
    '', '## Executive summary', '',
    ...(confirmedFindings.length ? [
      `${confirmedFindings.length} evidence-backed ${confirmedFindings.length === 1 ? 'finding was' : 'findings were'} confirmed within the approved scope. ` +
        `${severityCounts.length ? 'The confirmed severity distribution is listed below.' : ''}`, '',
      ...severityCounts, '',
    ] : ['No evidence-backed security gap was confirmed in the completed checks. This does not mean the approved assets are free of vulnerabilities.', '']),
    ...(priority ? [
      '## Fix first', '',
      ...(priority.finding ? [
        `**${inline(priority.label)}** · ${inline(priority.finding.origin)}`, '', inline(priority.finding.remediation),
      ] : [inline(priority.label), '', '[Findings](#findings)']),
    ] : []),
    '', '## Approved scope', '',
    ...(approved.size ? [...approved].map(origin => '- ' + inline(origin)) : ['No approved hosts.']),
    '', '## Findings', '',
  ]
  if (!findings.length) lines.push('No findings recorded.', '')
  for (const finding of findings) {
    const links = evidenceLinks(finding.origin, finding.evidenceIds)
    lines.push(
      `### ${inline(finding.title)}`, '',
      `- **Host** ${inline(finding.origin)}`,
      `- **Severity** ${inline(finding.severity)} · **Status** ${inline(finding.status)}`,
      ...(finding.category ? [`- **Class** ${inline(finding.category)}${finding.cwe ? ` · ${inline(finding.cwe)}` : ''}`] : []),
      ...(finding.confidence ? [`- **Confidence** ${inline(finding.confidence)}`] : []),
      ...(finding.check ? [
        `- **Observed** ${inline(finding.check.observed ?? 'Unavailable')}`,
        `- **Expected** ${inline(finding.check.expected)}`,
      ] : []),
      `- **Result** ${inline(finding.reason)}`,
      ...(finding.impact ? [`- **Impact** ${inline(finding.impact)}`] : []),
      ...(finding.verification ? [`- **Verification** ${inline(finding.verification)}`] : []),
      `- **${finding.status === 'confirmed' ? 'Remediation' : 'Follow-up'}** ${inline(finding.remediation)}`,
      ...(finding.recheck ? [`- **Check the fix** ${inline(finding.recheck)}`] : []),
      ...(links ? ['- **Evidence** ' + links] : []), '',
    )
  }

  if (confirmedFindings.length) {
    lines.push('## Remediation plan', '')
    for (const [index, finding] of confirmedFindings.entries()) {
      lines.push(`${index + 1}. **${inline(finding.title)}** — ${inline(finding.remediation)} Recheck: ${inline(finding.recheck ?? 'repeat the verified evidence check after the change.')}`)
    }
    lines.push('')
  }

  lines.push('## Coverage', '')
  for (const row of body.coverage.filter(item => approved.has(item.origin))) {
    const ids = [row.evidenceId, row.analysisEvidenceId, row.accessEvidence?.id].filter((id): id is string => Boolean(id))
    const links = evidenceLinks(row.origin, ids)
    lines.push(`### ${inline(row.origin)}`, '', `- ${inline(row.status)}`)
    if (row.accessEvidence?.recordedAt) lines.push('- **Access decisions recorded** ' + inline(row.accessEvidence.recordedAt))
    if (links) lines.push('- **Evidence** ' + links)
    for (const check of row.checks ?? []) {
      lines.push(
        `- **${inline(check.title)}** · ${checkLabels[check.status]}`,
        ...(check.status === 'untested' ? [] : [`  - **Observed** ${inline(check.observed ?? 'Unavailable')}`]),
        `  - **Expected** ${inline(check.expected)}`,
        `  - ${inline(check.reason)}`,
      )
    }
    lines.push('')
  }
  if (body.gaps.length) lines.push('## Coverage gaps', '', ...body.gaps.map(gap => '- ' + inline(gap)), '')
  lines.push('## Methodology and limitations', '',
    '- Guardian evaluated only the approved hosts, selected checks, and recorded evidence identified in this report.',
    '- A confirmed finding requires a successful isolated-worker comparison linked to its source evidence. Model commentary alone cannot confirm a finding.',
    '- Inconclusive, not-applicable, and untested checks are retained in coverage instead of being treated as passes.',
    '- This evidence-led review is not a guarantee that no other vulnerability exists. New routes, authenticated roles, application state, and infrastructure changes can alter the result.', '')
  if (attachments.size) lines.push('## Evidence', '')
  for (const entry of attachments.values()) {
    lines.push(`### Evidence ${entry.number}`, '')
    if (!entry.json) {
      lines.push('Supporting record unavailable for this report version.', '')
      continue
    }
    const sha = createHash('sha256').update(entry.json).digest('hex')
    const label = entry.kind === 'observation' && run.sourceMode === 'prepared'
      ? suppliedResponseLabel : entry.kind && evidenceLabels[entry.kind]
    lines.push(
      `${label} · ${inline(entry.origin)}`, '',
      ...(entry.sources?.length ? ['**Inputs** ' + entry.sources.map(linkTo).join(' · '), ''] : []),
      `**SHA-256 of the JSON below** \`${sha}\``, '',
      '~~~json', entry.json, '~~~', '',
    )
  }
  return { filename: `guardian-report-${run.id.slice(0, 8)}-v${report.version}.md`, content: lines.join('\n') }
}
