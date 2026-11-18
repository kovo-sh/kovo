import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { FullConfig, FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter'
import { z } from 'zod'
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
      this.writeScorecard(result.status)
    } catch (error) {
      console.error(error instanceof Error ? error.message : 'Could not write the report benchmark.')
      return { status: 'failed' as const }
    }
  }

  private writeScorecard(browserStatus: 'passed' | 'failed') {
    if (this.duplicates.size || this.snapshots.size !== scenarioIds.length) {
      throw new Error('The benchmark requires exactly one export from each of its four report scenarios.')
    }
    const cases = scenarioIds.flatMap(scenario => {
      const result = this.snapshots.get(scenario)!.report
      const entries = new Map(result.cases.map(row => [row.id, row]))
      return benchmarkScenarios[scenario].cases.map(expected => {
        const id = benchmarkCaseId(scenario, expected)
        const row = entries.get(id)
        if (!row) throw new Error('Missing Guardian verdict for ' + id + '.')
        return { ...expected, ...row, scenario }
      })
    })
    const unexpected = [...this.snapshots.values()].reduce((count, entry) => count + entry.report.unmatchedConfirmations, 0)
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
    mkdirSync(this.directory, { recursive: true })
    const scenarios = scenarioIds.map(id => {
      const { markdown } = this.snapshots.get(id)!
      const file = id + '.md'
      writeFileSync(join(this.directory, file), markdown)
      const { version, partial, basis } = benchmarkScenarios[id]
      const sha256 = createHash('sha256').update(markdown).digest('hex')
      return { id, version, partial, basis, report: file, sha256 }
    })
    const rows = cases.map(row => ({ ...row, ...(baseline ? { artex: baseline.cases[row.id] } : {}) }))
    const scorecard = join(this.directory, 'summary.json')
    writeFileSync(scorecard, JSON.stringify({ suite: benchmarkSuite, browserStatus, guardian, artex: artex ?? null, scenarios, cases: rows }, null, 2) + '\n')
    console.log('\nGuardian report benchmark')
    console.log(guardian.agreeingVerdicts + '/' + guardian.cases + ' verdicts matched, ' +
      percent(guardian.precision) + ' precision, ' + percent(guardian.recall) + ' recall.')
    console.log(guardian.linkedEvidence + '/' + guardian.reportedConfirmations + ' confirmations have linked evidence and a verification receipt.')
    console.log(artex
      ? 'Imported Artex results had ' + percent(artex.precision) + ' precision and ' + percent(artex.recall) + ' recall.'
      : 'Awaiting matched Artex results.')
    console.log('Scorecard and report exports in ' + relative(process.cwd(), this.directory) + '.')
  }
}
