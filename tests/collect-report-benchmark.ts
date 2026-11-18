import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import type { CheckCoverage, EvidenceSummary, Finding, ReportBody } from '../src/domain.ts'
import { checkLabels } from '../src/report-summary.ts'
import { benchmarkAttachment, benchmarkCaseId, benchmarkScenarios } from './report-benchmark.ts'
import type { ExpectedCase, ReportResult, ScenarioId, Verdict } from './report-benchmark.ts'

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

export async function collectReportBenchmark(
  scenario: ScenarioId,
  directory: string,
  url: string,
  exportFile: { name: string; content: string },
) {
  const fixture = benchmarkScenarios[scenario]
  const runId = new URL(url).pathname.split('/')[2]
  const db = new DatabaseSync(join(directory, 'guardian.sqlite'), { readOnly: true })
  let saved
  try {
    saved = db.prepare('SELECT body, partial FROM reports WHERE run_id = ? AND version = ?').get(runId, fixture.version)
  } finally {
    db.close()
  }
  if (typeof saved?.body !== 'string') throw new Error('The benchmark report version is missing.')
  expect(saved.partial).toBe(fixture.partial ? 1 : 0)
  const report = JSON.parse(saved.body) as ReportBody
  const markdown = exportFile.content
  expect(exportFile.name).toBe('guardian-report-' + runId.slice(0, 8) + '-v' + fixture.version + '.md')
  expect(markdown).toContain('**Run** ' + runId)
  expect(markdown).toContain('**Report version** ' + fixture.version)
  expect(markdown.startsWith('# Guardian ' + (fixture.partial ? 'partial' : 'complete') + ' report\n')).toBe(true)
  const expectedHosts = [...new Set(fixture.cases.map(row => row.origin))].sort()
  expect(report.scope.map(asset => asset.origin).sort()).toEqual(expectedHosts)
  expect(section(markdown, 'Approved scope').trim().split('\n').sort()).toEqual(expectedHosts.map(origin => '- ' + origin))

  const coverage = subsections(markdown, 'Coverage')
  const findings = subsections(markdown, 'Findings').filter(block => block.lines.some(line => line.endsWith('**Status** confirmed')))
  const confirmed = report.findings.filter(finding => finding.status === 'confirmed')
  const evidence = readEvidence(markdown)
  expect(findings).toHaveLength(confirmed.length)
  const fields = ['Expected', 'Observed', 'Impact', 'Remediation', 'Check the fix']

  const cases = fixture.cases.map(expected => {
    const check = report.coverage.find(row => row.origin === expected.origin)?.checks?.find(item => matchingCheck(item, expected))
    const finding = confirmed.find(item => item.origin === expected.origin && matchingCheck(item.check, expected))
    const reported: Verdict = finding ? 'confirmed' : check?.status === 'met' ? 'met'
      : check?.status === 'inconclusive' || check?.status === 'gap' ? 'inconclusive' : 'untested'
    const coverageLines = coverage.find(block => block.title === expected.origin)?.lines ?? []
    const visibleCoverage = check
      ? coverageLines.includes('- **' + check.title + '** · ' + checkLabels[check.status])
      : coverageLines.some(line => /Verification pending|Pending review/.test(line))
    const block = finding && findings.find(item => item.title === finding.title && item.lines.includes('- **Host** ' + expected.origin))
    const visible = visibleCoverage && (!finding || (Boolean(block) && check?.status === 'gap'))
    const result = { id: benchmarkCaseId(scenario, expected), reported, visible }
    if (!finding) return result
    const lines = block?.lines ?? []
    const fixGuidance = fields.every(field => {
      const prefix = '- **' + field + '** '
      return lines.some(line => line.startsWith(prefix) && line.slice(prefix.length).trim().length > 0)
    })
    return { ...result, linkedEvidence: supportsFinding(evidence, lines, finding, expected, report), fixGuidance }
  })
  const unmatchedConfirmations = confirmed.length - cases.filter(row => row.reported === 'confirmed').length
  const result: ReportResult = { scenario, cases, unmatchedConfirmations }
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
