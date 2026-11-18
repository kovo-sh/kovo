import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { findingSeverities } from '../src/domain.ts'
import type { CheckCoverage, EvidenceSummary, Finding, ReportBody } from '../src/domain.ts'
import { checkLabels } from '../src/report-summary.ts'
import { benchmarkAttachment, benchmarkCaseId, benchmarkScenarios } from './report-benchmark.ts'
import type { BenchmarkInput, ExpectedCase, ReportResult, ScenarioId, Verdict } from './report-benchmark.ts'

type Evidence = {
  artifactId: string
  origin: string
  kind: EvidenceSummary['kind']
  scopeRevision: number
  goalRevision: number
  observation?: object | null
  snapshot?: object | null
  inputEvidence?: string[]
  exitStatus?: number
  checks?: Pick<CheckCoverage, 'id' | 'caseId' | 'status'>[]
  comparisons?: { id: string }[]
}

function section(markdown: string, heading: string) {
  return markdown.split('\n## ' + heading + '\n')[1]?.split('\n## ')[0] ?? ''
}

function subsections(markdown: string, heading: string) {
  return section(markdown, heading).split('\n### ').slice(1).map(block => {
    const [title, ...lines] = block.split('\n')
    return { title, lines }
  })
}

function readEvidence(markdown: string) {
  const records = new Map<string, Evidence>()
  for (const { title, lines } of subsections(markdown, 'Evidence')) {
    const match = lines.join('\n').match(/^\*\*SHA-256 of the JSON below\*\* `([a-f0-9]{64})`\n\n~~~json\n([\s\S]*?)\n~~~$/m)
    if (match && createHash('sha256').update(match[2]).digest('hex') === match[1]) {
      records.set(title, JSON.parse(match[2]) as Evidence)
    }
  }
  return records
}

function matchingCheck(check: Pick<CheckCoverage, 'id' | 'caseId'> | undefined, expected: ExpectedCase) {
  return check?.id === expected.check && check.caseId === expected.caseId
}

function supportsFinding(records: ReadonlyMap<string, Evidence>, lines: string[], finding: Finding,
  expected: ExpectedCase, report: ReportBody) {
  const links = [...lines.join('\n').matchAll(/\[Evidence (\d+)\]\(#evidence-\1\)/g)]
  const linked = links.flatMap(link => {
    const record = records.get('Evidence ' + link[1])
    return record && record.origin === finding.origin && finding.evidenceIds.includes(record.artifactId) &&
      record.scopeRevision <= report.scopeRevision && record.goalRevision === report.goalRevision ? [record] : []
  })
  const source = linked.find(record => expected.check === 'access-policy'
    ? record.kind === 'access-policy' && record.snapshot : record.kind === 'observation' && record.observation)
  const comparisonId = expected.caseId ? expected.check + ':' + expected.caseId : expected.check
  const proof = linked.find(record => record.kind === 'verification' && record.exitStatus === 0 &&
    record.checks?.some(check => check.status === 'gap' && matchingCheck(check, expected)) &&
    record.comparisons?.some(comparison => comparison.id === comparisonId))
  return Boolean(source && proof?.inputEvidence?.includes(source.artifactId))
}

function readReportRecording(db: DatabaseSync, runId: string, reportId: string, createdAt: number,
  version: number, report: ReportBody) {
  const checkpoint = db.prepare(`SELECT id, kind, json_extract(detail, '$.version') AS version,
      json_extract(detail, '$.phase') AS phase, json_extract(detail, '$.status') AS status
    FROM events WHERE run_id = ? AND json_extract(detail, '$.reportId') = ?`).get(runId, reportId)
  if (!checkpoint || typeof checkpoint.id !== 'number' || typeof checkpoint.phase !== 'string' ||
      typeof checkpoint.status !== 'string' || checkpoint.version !== version) {
    throw new Error('The benchmark report has no matching run event.')
  }
  const approval = db.prepare(`SELECT id, json_extract(detail, '$.approved') AS scope
    FROM events WHERE run_id = ? AND kind = 'scope.approved' AND id < ?
      AND json_extract(detail, '$.scopeRevision') = ? ORDER BY id DESC LIMIT 1`)
    .get(runId, checkpoint.id, report.scopeRevision)
  if (typeof approval?.id !== 'number' || typeof approval.scope !== 'string') {
    throw new Error('The benchmark report has no matching scope approval.')
  }
  const approvalId = approval.id
  const scope = JSON.parse(approval.scope) as string[]
  const rows = db.prepare(`SELECT id, kind, created_at AS createdAt,
      json_extract(detail, '$.origin') AS origin, json_extract(detail, '$.assignmentId') AS assignmentId,
      json_extract(detail, '$.artifactId') AS artifactId,
      CASE WHEN kind = 'scope.approved' THEN json_extract(detail, '$.approved') END AS approved,
      CASE WHEN kind IN ('report.partial', 'report.complete') THEN json_extract(detail, '$.reportId') END AS reportId,
      CASE WHEN kind IN ('report.partial', 'report.complete') THEN json_extract(detail, '$.version') END AS reportVersion
    FROM events WHERE run_id = ? AND id <= ? AND kind IN (
      'run.created', 'discovery.consented', 'discovery.complete', 'scope.approved', 'review.planned',
      'evidence.committed', 'broker.allowed', 'broker.observed', 'interrupted', 'run.resumed',
      'worker.started', 'worker.complete', 'verification.started', 'report.partial', 'report.complete'
    ) ORDER BY id`).all(runId, checkpoint.id) as (Omit<ReportResult['recording']['events'][number], 'scope'> & {
      approved: string | null
    })[]
  const events = rows.map(({ approved, ...event }) => ({
    ...event,
    ...(approved === null ? {} : { scope: JSON.parse(approved) as string[] }),
  }))
  expect(events.at(-1)?.id).toBe(checkpoint.id)
  return {
    runId, reportId, reportVersion: version, createdAt, scopeRevision: report.scopeRevision, goalRevision: report.goalRevision,
    approval: { eventId: approvalId, scope }, phase: checkpoint.phase, status: checkpoint.status, events,
  }
}

export async function collectReportBenchmark(
  scenario: ScenarioId,
  directory: string,
  url: string,
  exportFile: { name: string; content: string },
) {
  const fixture = benchmarkScenarios[scenario]
  const input: BenchmarkInput = fixture.input
  const runId = new URL(url).pathname.split('/')[2]
  const db = new DatabaseSync(join(directory, 'guardian.sqlite'), { readOnly: true })
  let report: ReportBody
  let recording: ReportResult['recording']
  try {
    const saved = db.prepare('SELECT id, body, partial, created_at AS createdAt FROM reports WHERE run_id = ? AND version = ?')
      .get(runId, fixture.version)
    if (typeof saved?.body !== 'string' || typeof saved.id !== 'string' || typeof saved.createdAt !== 'number') {
      throw new Error('The benchmark report version is missing.')
    }
    expect(saved.partial).toBe(fixture.partial ? 1 : 0)
    report = JSON.parse(saved.body) as ReportBody
    recording = readReportRecording(db, runId, saved.id, saved.createdAt, fixture.version, report)
  } finally {
    db.close()
  }
  const lastEvent = recording.events.at(-1)
  expect(lastEvent?.kind).toBe(fixture.partial ? 'report.partial' : 'report.complete')
  expect(recording.status).toBe(fixture.partial ? 'stopped' : 'complete')
  expect(recording.phase).toBe(fixture.partial ? 'analysis' : 'complete')
  expect(recording.events.some(row => row.kind === 'verification.started')).toBe(!fixture.partial)
  const markdown = exportFile.content
  expect(exportFile.name).toBe('guardian-report-' + runId.slice(0, 8) + '-v' + fixture.version + '.md')
  expect(markdown).toContain('**Run** ' + runId)
  expect(markdown).toContain('**Report version** ' + fixture.version)
  expect(markdown.startsWith('# Guardian ' + (fixture.partial ? 'partial' : 'complete') + ' report\n')).toBe(true)
  const expectedHosts = [...fixture.input.scope].sort()
  expect(report.goal).toBe(fixture.input.goal)
  expect([...recording.approval.scope].sort()).toEqual(expectedHosts)
  expect(report.scope.map(asset => asset.origin).sort()).toEqual(expectedHosts)
  expect(section(markdown, 'Approved scope').trim().split('\n').sort()).toEqual(expectedHosts.map(origin => '- ' + origin))

  const coverage = subsections(markdown, 'Coverage')
  const findings = subsections(markdown, 'Findings').filter(block => block.lines.some(line => line.endsWith('**Status** confirmed')))
  const confirmed = report.findings.filter(finding => finding.status === 'confirmed')
  const evidence = readEvidence(markdown)
  const recordedResponses = [...evidence.values()].filter(row => row.observation)
  const recordedDecisions = [...evidence.values()].filter(row => row.snapshot)
  const expectedResponses = input.capturedEvidence.responseObservations ?? []
  const expectedDecisions = input.capturedEvidence.accessDecisions ?? []
  for (const row of recordedResponses) expect(row.observation).toEqual(expectedResponses.find(item => item.origin === row.origin))
  for (const row of recordedDecisions) expect(row.snapshot).toEqual(expectedDecisions.find(item => item.origin === row.origin))
  expect(recordedResponses.map(row => row.origin).sort()).toEqual(
    (fixture.partial ? expectedResponses.slice(0, 1) : expectedResponses).map(row => row.origin).sort(),
  )
  expect(recordedDecisions.map(row => row.origin).sort()).toEqual(expectedDecisions.map(row => row.origin).sort())
  expect(findings).toHaveLength(confirmed.length)
  const fields = ['Expected', 'Observed', 'Impact', 'Remediation', 'Check the fix']

  const cases = fixture.cases.map(expected => {
    const check = report.coverage.find(row => row.origin === expected.origin)?.checks?.find(item => matchingCheck(item, expected))
    const finding = confirmed.find(item => item.origin === expected.origin && matchingCheck(item.check, expected))
    const reported: Verdict = finding ? 'confirmed' : check?.status === 'met' ? 'met'
      : !check || check.status === 'untested' ? 'untested' : 'inconclusive'
    const coverageLines = coverage.find(block => block.title === expected.origin)?.lines ?? []
    const visibleCoverage = Boolean(check && coverageLines.includes('- **' + check.title + '** · ' + checkLabels[check.status]))
    const block = finding && findings.find(item => item.title === finding.title && item.lines.includes('- **Host** ' + expected.origin))
    const visible = visibleCoverage && (!finding || (Boolean(block) && check?.status === 'gap'))
    const result = { id: benchmarkCaseId(scenario, expected), reported, visible }
    if (!finding) return result
    const lines = block?.lines ?? []
    const reportedSeverity = findingSeverities.find(level => lines.includes('- **Severity** ' + level + ' · **Status** confirmed'))
    expect.soft(reportedSeverity).toBe(finding.severity)
    if (expected.expected === 'confirmed') expect.soft(reportedSeverity).toBe(expected.severity)
    const fixGuidance = fields.every(field => {
      const prefix = '- **' + field + '** '
      return lines.some(line => line.startsWith(prefix) && line.slice(prefix.length).trim().length > 0)
    })
    return { ...result, reportedSeverity, linkedEvidence: supportsFinding(evidence, lines, finding, expected, report), fixGuidance }
  })
  const unmatchedConfirmations = confirmed.length - cases.filter(row => row.reported === 'confirmed').length
  const result: ReportResult = { scenario, cases, unmatchedConfirmations, recording }
  await test.info().attach(benchmarkAttachment + scenario + '.json', {
    body: JSON.stringify(result), contentType: 'application/json',
  })
  await test.info().attach(benchmarkAttachment + scenario + '.md', {
    body: markdown, contentType: 'text/markdown',
  })

  expect.soft(cases.map(({ id, reported }) => ({ id, reported }))).toEqual(fixture.cases.map(row => ({
    id: benchmarkCaseId(scenario, row), reported: row.expected,
  })))
  expect.soft(unmatchedConfirmations).toBe(0)
  expect.soft(cases.filter(row => !row.visible)).toEqual([])
  expect.soft(cases.filter(row => row.reported === 'confirmed' &&
    !('linkedEvidence' in row && row.linkedEvidence && row.fixGuidance))).toEqual([])
}
