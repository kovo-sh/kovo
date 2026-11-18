import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { FullConfig, FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter'
import { z } from 'zod'
import { compareReports } from '../scripts/report-comparison.ts'
import { DEFAULT_PROVIDER } from '../src/domain.ts'
import { benchmarkAttachment, benchmarkCaseId, benchmarkScenarios, benchmarkSuite, scoreReportCases, verdictSchema } from './report-benchmark.ts'
import type { ReportResult, ScenarioId } from './report-benchmark.ts'

const artexResults = z.strictObject({
  suite: z.literal(benchmarkSuite),
  version: z.string().trim().min(1),
  model: z.string().trim().min(1),
  unmatchedConfirmations: z.number().int().nonnegative(),
  cases: z.record(z.string(), verdictSchema),
})
const scenarioIds = Object.keys(benchmarkScenarios) as ScenarioId[]
const regressionIds = scenarioIds.filter(id => id !== 'policy-multi-host')

function readArtexResults(path: string, caseIds: string[]) {
  let input: unknown
  try {
    input = JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    throw new Error('Could not read the Artex benchmark JSON.')
  }
  const parsed = artexResults.safeParse(input)
  if (!parsed.success) throw new Error('The Artex benchmark file has invalid metadata or verdicts. See the README.')
  const { cases } = parsed.data
  if (Object.keys(cases).length !== caseIds.length || !caseIds.every(id => Object.hasOwn(cases, id))) {
    throw new Error('The Artex benchmark file must contain one verdict per case in this suite.')
  }
  return parsed.data
}

function percent(value: number | null) {
  return value === null ? 'unavailable' : new Intl.NumberFormat('en', { style: 'percent', maximumFractionDigits: 1 }).format(value)
}

export default class ReportBenchmarkReporter implements Reporter {
  private directory = ''
  private readonly snapshots = new Map<ScenarioId, { report: ReportResult; markdown: string }>()
  private readonly duplicates = new Set<ScenarioId>()

  onBegin(config: FullConfig) {
    this.directory = join(config.projects[0].outputDir, 'report-benchmark')
  }

  onTestEnd(_test: TestCase, result: TestResult) {
    for (const scenario of scenarioIds) {
      const read = (extension: string) => {
        const attachment = result.attachments.find(item => item.name === benchmarkAttachment + scenario + extension)
        return attachment?.body?.toString() ?? (attachment?.path ? readFileSync(attachment.path, 'utf8') : undefined)
      }
      const scores = read('.json')
      const markdown = read('.md')
      if (!scores || !markdown) continue
      const report = JSON.parse(scores) as ReportResult
      if (report.scenario !== scenario) throw new Error('Report benchmark attachment identifies the wrong scenario.')
      if (this.snapshots.has(scenario)) this.duplicates.add(scenario)
      this.snapshots.set(scenario, { report, markdown })
    }
  }

  async onEnd(result: FullResult) {
    if (result.status === 'interrupted' || result.status === 'timedout') return
    try {
      await this.writeScorecard(result.status)
    } catch (error) {
      console.error(error instanceof Error ? error.message : 'Could not write the report benchmark.')
      return { status: 'failed' as const }
    }
  }

  private writeArtifact(path: string, content: string) {
    writeFileSync(join(this.directory, path), content, { mode: 0o600 })
    return { path, sha256: createHash('sha256').update(content).digest('hex') }
  }

  private writeJson(path: string, data: object) {
    return this.writeArtifact(path, JSON.stringify(data, null, 2) + '\n')
  }

  private async writeComparison(version: string) {
    const scenarios = scenarioIds.map(id => {
      const { report, markdown } = this.snapshots.get(id)!
      const fixture = benchmarkScenarios[id]
      const input = this.writeJson(id + '.input.json', fixture.input)
      const exportedReport = this.writeArtifact(id + '.md', markdown)
      const recording = this.writeJson(id + '.recording.json', report.recording)
      const runRecord = this.writeJson(id + '.run.json', {
        inputSha256: input.sha256, reportSha256: exportedReport.sha256, recording,
      })
      const results = new Map(report.cases.map(row => [row.id, row]))
      const cases = fixture.cases.map(expected => {
        const issue = expected.caseId ? expected.check + ':' + expected.caseId : expected.check
        return {
          asset: expected.origin, issue, expected: expected.expected,
          ...(expected.expected === 'confirmed' ? { severity: expected.severity } : {}),
        }
      })
      const verdicts = fixture.cases.map((expected, index) => {
        const row = results.get(benchmarkCaseId(id, expected))
        if (!row) throw new Error('Missing comparison verdict for ' + id + '.')
        const { asset, issue } = cases[index]
        return { asset, issue, verdict: row.reported,
          ...(row.reported === 'confirmed' ? { evidence: row.linkedEvidence ? 'supported' : 'missing' } : {}) }
      })
      return { id, input, cases, guardian: {
        version, model: DEFAULT_PROVIDER.model, inputSha256: input.sha256,
        report: exportedReport, runRecord, verdicts,
      } }
    })
    const manifest = this.writeJson('comparison-manifest.json', {
      format: 1, suite: 'northstar-assessment-v1', mode: 'assessment', scenarios,
    })
    const comparison = await compareReports(join(this.directory, manifest.path))
    this.writeJson('comparison-scorecard.json', comparison)
    if (comparison.evidence.status !== 'passed' || !comparison.accuracy.guardian || !comparison.coverage.multiHost) {
      throw new Error('The Guardian comparison is missing scope, evidence, or recorded cases.')
    }
    console.log('Saved Guardian run evidence for ' + comparison.accuracy.guardian.agreeingVerdicts + '/' +
      comparison.accuracy.guardian.cases + ' matched case verdicts. Release comparison is ' + comparison.status + '.')
  }

  private async writeScorecard(browserStatus: 'passed' | 'failed') {
    if (this.duplicates.size || this.snapshots.size !== scenarioIds.length) {
      throw new Error('The benchmark requires exactly one export from each of its report scenarios.')
    }
    const cases = regressionIds.flatMap(scenario => {
      const result = this.snapshots.get(scenario)!.report
      const entries = new Map(result.cases.map(row => [row.id, row]))
      return benchmarkScenarios[scenario].cases.map(expected => {
        const id = benchmarkCaseId(scenario, expected)
        const row = entries.get(id)
        if (!row) throw new Error('Missing Guardian verdict for ' + id + '.')
        return { ...expected, ...row, scenario }
      })
    })
    const unexpected = regressionIds.reduce((count, id) => count + this.snapshots.get(id)!.report.unmatchedConfirmations, 0)
    const version = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout?.trim() || 'local checkout'
    const guardian = {
      version, model: DEFAULT_PROVIDER.model,
      ...scoreReportCases(cases, unexpected),
      linkedEvidence: cases.filter(row => row.linkedEvidence).length,
      fixGuidance: cases.filter(row => row.fixGuidance).length,
    }
    const baselinePath = process.env.GUARDIAN_ARTEX_REPORT_RESULTS
    const baseline = baselinePath ? readArtexResults(baselinePath, cases.map(row => row.id)) : undefined
    const artex = baseline && {
      version: baseline.version, model: baseline.model,
      ...scoreReportCases(cases.map(row => ({ expected: row.expected, reported: baseline.cases[row.id] })), baseline.unmatchedConfirmations),
    }
    mkdirSync(this.directory, { recursive: true, mode: 0o700 })
    const scenarios = regressionIds.map(id => {
      const { markdown } = this.snapshots.get(id)!
      const file = id + '.md'
      const { sha256 } = this.writeArtifact(file, markdown)
      const { version, partial, basis } = benchmarkScenarios[id]
      return { id, version, partial, basis, report: file, sha256 }
    })
    const rows = cases.map(row => ({ ...row, ...(baseline ? { artex: baseline.cases[row.id] } : {}) }))
    this.writeJson('summary.json', { suite: benchmarkSuite, browserStatus, guardian, artex: artex ?? null, scenarios, cases: rows })
    console.log('\nGuardian report benchmark')
    console.log(guardian.agreeingVerdicts + '/' + guardian.cases + ' verdicts matched, ' +
      percent(guardian.precision) + ' precision, ' + percent(guardian.recall) + ' recall.')
    console.log(guardian.linkedEvidence + '/' + guardian.reportedConfirmations + ' confirmations have linked evidence and a verification receipt.')
    console.log(artex
      ? 'Imported Artex results had ' + percent(artex.precision) + ' precision and ' + percent(artex.recall) + ' recall.'
      : 'Awaiting matched Artex results.')
    console.log('Scorecard and report exports in ' + relative(process.cwd(), this.directory) + '.')
    if (browserStatus === 'passed') await this.writeComparison(version)
  }
}
