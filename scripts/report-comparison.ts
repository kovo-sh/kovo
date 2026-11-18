import { createHash } from 'node:crypto'
import { readFile, realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { z } from 'zod'
import { assetOrigin } from '../src/domain.ts'
import { scoreReportCases, verdictSchema } from './report-metrics.ts'

const label = z.string().trim().min(1)
const digest = z.string().regex(/^[a-f0-9]{64}$/)
const artifact = z.strictObject({ path: label, sha256: digest })
const runRecordSchema = z.strictObject({
  inputSha256: digest,
  reportSha256: digest,
  recording: artifact,
})
const severity = z.enum(['critical', 'high', 'medium', 'low', 'informational'])
const caseIdentity = { asset: assetOrigin, issue: label }
const expectedCase = z.discriminatedUnion('expected', [
  z.strictObject({ ...caseIdentity, expected: z.literal('confirmed'), severity }),
  z.strictObject({ ...caseIdentity, expected: verdictSchema.exclude(['confirmed']) }),
])
const evidenceQuality = z.enum(['supported', 'missing', 'unrelated', 'out-of-scope'])
const verdict = z.discriminatedUnion('verdict', [
  z.strictObject({ ...caseIdentity, verdict: z.literal('confirmed'), evidence: evidenceQuality.optional() }),
  z.strictObject({ ...caseIdentity, verdict: verdictSchema.exclude(['confirmed']) }),
])
const productReport = z.strictObject({
  version: label,
  model: label,
  inputSha256: digest,
  report: artifact,
  runRecord: artifact.optional(),
  verdicts: z.array(verdict),
})
const tasks = z.enum(['priority', 'remediation', 'impact', 'evidence', 'recheck'])
const answer = z.strictObject({
  reportSha256: digest,
  tasks: z.record(tasks, z.enum(['correct', 'incorrect', 'unanswered'])),
})
const review = z.strictObject({ reader: label, guardian: answer, artex: answer, notes: label.optional() })
const scenario = z.strictObject({
  id: label,
  input: artifact,
  heldOut: z.boolean().default(false),
  cases: z.array(expectedCase).min(1),
  guardian: productReport.optional(),
  artex: productReport.optional(),
  reviews: z.array(review).default([]),
})
const manifestSchema = z.strictObject({
  format: z.literal(1),
  suite: label,
  mode: z.enum(['assessment', 'report-only']),
  scenarios: z.array(scenario).min(1),
})
const inputSchema = z.object({
  goal: label,
  scope: z.array(assetOrigin).min(1),
  stoppingPoint: z.enum(['complete', 'interrupted']),
  overlappingObservations: z.boolean().default(false),
  capturedEvidence: z.json(),
})

type Artifact = z.infer<typeof artifact>
type Verdict = z.infer<typeof verdict>
type Scenario = z.infer<typeof scenario>
type Product = 'guardian' | 'artex'
type Status = 'passed' | 'failed' | 'pending'

function caseKey({ asset, issue }: { asset: string; issue: string }) {
  return JSON.stringify([asset, issue])
}

function sha256(bytes: Buffer) {
  return createHash('sha256').update(bytes).digest('hex')
}

function readJson<T>(schema: z.ZodType<T>, data: Buffer, name: string): T {
  let value: unknown
  try { value = JSON.parse(data.toString('utf8')) } catch { throw new Error(name + ' is not valid JSON.') }
  const parsed = schema.safeParse(value)
  if (parsed.success) return parsed.data
  const fields = parsed.error.issues.map(issue => issue.path.join('.') || 'document')
  throw new Error('Invalid ' + name + ' at ' + [...new Set(fields)].join(', ') + '.')
}

async function readArtifact(directory: string, ref: Artifact) {
  const name = JSON.stringify(ref.path)
  let bytes: Buffer
  try {
    const path = await realpath(resolve(directory, ref.path))
    const location = relative(directory, path)
    if (isAbsolute(ref.path) || isAbsolute(location) || location === '..' || location.startsWith('..' + sep)) {
      throw new Error('Path outside the comparison directory.')
    }
    if (!(await stat(path)).isFile()) throw new Error('Regular file required.')
    bytes = await readFile(path)
  } catch {
    throw new Error('Could not read ' + name + ' as a file inside the comparison directory.')
  }
  if (!bytes.length) throw new Error(name + ' is empty.')
  if (sha256(bytes) !== ref.sha256) {
    throw new Error('SHA-256 mismatch for ' + name + '.')
  }
  return bytes
}

async function readProduct(directory: string, entry: Scenario, product: Product, scope: Set<string>) {
  const result = entry[product]
  if (!result) return null
  const context = product + ' report for ' + JSON.stringify(entry.id)
  if (result.inputSha256 !== entry.input.sha256) throw new Error(context + ' references different inputs.')
  await readArtifact(directory, result.report)
  let recording: Artifact | undefined
  if (result.runRecord) {
    const record = readJson(runRecordSchema, await readArtifact(directory, result.runRecord), 'run record')
    if (record.inputSha256 !== entry.input.sha256 || record.reportSha256 !== result.report.sha256) {
      throw new Error(context + ' is linked to a run record with different inputs or report.')
    }
    recording = record.recording
    await readArtifact(directory, recording)
  }

  const observations = new Map<string, Verdict>()
  const evidenceIssues: { asset: string; issue: string; reason: z.infer<typeof evidenceQuality> | 'unreviewed' }[] = []
  let duplicates = 0
  for (const row of result.verdicts) {
    const key = caseKey(row)
    const previous = observations.get(key)
    if (previous) {
      if (previous.verdict !== 'confirmed' || row.verdict !== 'confirmed') {
        throw new Error(context + ' has repeated or conflicting case verdicts.')
      }
      duplicates++
    } else observations.set(key, row)
    if (row.verdict === 'confirmed') {
      const reason = scope.has(row.asset) ? row.evidence ?? 'unreviewed' : 'out-of-scope'
      if (reason !== 'supported') evidenceIssues.push({ asset: row.asset, issue: row.issue, reason })
    }
  }
  const cases = entry.cases.map(expected => {
    const key = caseKey(expected)
    const actual = observations.get(key)
    if (!actual) throw new Error(context + ' is missing a labeled case. Use untested for unsupported checks.')
    observations.delete(key)
    return { ...expected, reported: actual.verdict }
  })
  const unexpectedConfirmations = [...observations.values()]
  if (unexpectedConfirmations.some(row => row.verdict !== 'confirmed')) {
    throw new Error(context + ' has an unmatched case without a confirmed finding.')
  }
  const { verdicts, ...metadata } = result
  return { ...metadata, recording, cases, duplicates, unexpectedConfirmations, evidenceIssues }
}

async function readScenario(directory: string, entry: Scenario) {
  const input = readJson(inputSchema, await readArtifact(directory, entry.input), 'comparison input')
  const scope = new Set(input.scope)
  if (scope.size !== input.scope.length || new Set(entry.cases.map(caseKey)).size !== entry.cases.length ||
      entry.cases.some(row => !scope.has(row.asset))) {
    throw new Error('Invalid scope or duplicate case labels for ' + JSON.stringify(entry.id) + '.')
  }
  const guardian = await readProduct(directory, entry, 'guardian', scope)
  const artex = await readProduct(directory, entry, 'artex', scope)
  const readers = new Set<string>()
  for (const review of entry.reviews) {
    if (readers.has(review.reader)) throw new Error('Duplicate reader for ' + JSON.stringify(entry.id) + '.')
    readers.add(review.reader)
    if (review.guardian.reportSha256 !== guardian?.report.sha256 || review.artex.reportSha256 !== artex?.report.sha256) {
      throw new Error('Reader answers for ' + JSON.stringify(entry.id) + ' reference different reports.')
    }
  }
  const { capturedEvidence, ...context } = input
  return { id: entry.id, input: entry.input, heldOut: entry.heldOut, ...context,
    cases: entry.cases, guardian, artex, reviews: entry.reviews }
}

type CheckedScenario = Awaited<ReturnType<typeof readScenario>>

function scoreProduct(scenarios: CheckedScenario[], product: Product) {
  const reports = scenarios.flatMap(item => {
    const report = item[product]
    return report ? [report] : []
  })
  if (reports.length !== scenarios.length || reports.some(report => !report.runRecord)) return null
  const cases = reports.flatMap(report => report.cases)
  const unmatched = reports.reduce((total, report) => total + report.unexpectedConfirmations.length, 0)
  const misses = cases.filter(row => row.expected === 'confirmed' && row.reported !== 'confirmed')
  return {
    ...scoreReportCases(cases, unmatched),
    duplicates: reports.reduce((total, report) => total + report.duplicates, 0),
    missesBySeverity: Object.fromEntries(severity.options.map(level => [
      level, misses.filter(row => row.expected === 'confirmed' && row.severity === level).length,
    ])),
  }
}

function compareAccuracy(guardian: ReturnType<typeof scoreProduct>, artex: ReturnType<typeof scoreProduct>): Status {
  if (!guardian || !artex) return 'pending'
  if (guardian.recall !== null && artex.recall !== null && guardian.recall < artex.recall) return 'failed'
  if (guardian.precision === null || artex.precision === null || artex.recall === null) return 'pending'
  return guardian.precision >= artex.precision ? 'passed' : 'failed'
}

function compareReaders(scenarios: CheckedScenario[]) {
  const actionable = scenarios.filter(item => item.cases.some(row => row.expected === 'confirmed'))
  const reviews = actionable.flatMap(item => item.reviews)
  const results = Object.fromEntries(tasks.options.map(task => [task, {
    guardian: reviews.filter(review => review.guardian.tasks[task] === 'correct').length,
    artex: reviews.filter(review => review.artex.tasks[task] === 'correct').length,
  }]))
  const missedPriority = actionable.some(item => item.reviews.length &&
    !item.reviews.some(review => review.guardian.tasks.priority === 'correct'))
  const remaining = actionable.filter(item => !item.reviews.length).map(item => item.id)
  let status: Status = 'pending'
  if (missedPriority) status = 'failed'
  else if (actionable.length && !remaining.length) {
    status = Object.values(results).some(row => row.guardian < row.artex) ? 'failed' : 'passed'
  }
  return { status, pairs: reviews.length, results, awaitingReview: remaining }
}

export async function compareReports(manifestPath: string) {
  const path = await realpath(manifestPath)
  const directory = dirname(path)
  const bytes = await readFile(path)
  const manifest = readJson(manifestSchema, bytes, 'comparison manifest')
  if (new Set(manifest.scenarios.map(item => item.id)).size !== manifest.scenarios.length) {
    throw new Error('Comparison scenario IDs must be unique.')
  }
  const scenarios = []
  for (const entry of manifest.scenarios) scenarios.push(await readScenario(directory, entry))
  const guardian = manifest.mode === 'assessment' ? scoreProduct(scenarios, 'guardian') : null
  const artex = manifest.mode === 'assessment' ? scoreProduct(scenarios, 'artex') : null
  const accuracy = { status: compareAccuracy(guardian, artex), guardian, artex }
  const evidenceIssues = scenarios.flatMap(item => item.guardian?.evidenceIssues.map(issue => ({ scenario: item.id, ...issue })) ?? [])
  const evidenceStatus: Status = evidenceIssues.some(issue => issue.reason !== 'unreviewed') ? 'failed'
    : scenarios.some(item => !item.guardian) || evidenceIssues.length ? 'pending' : 'passed'
  const evidence = { status: evidenceStatus, issues: evidenceIssues }
  const readers = compareReaders(scenarios)
  const coverage = {
    multiHost: scenarios.some(item => item.scope.length > 1 && item.overlappingObservations),
    healthy: scenarios.some(item => item.stoppingPoint === 'complete' && item.cases.every(row => row.expected === 'met')),
    missingEvidence: scenarios.some(item => item.cases.some(row => row.expected === 'inconclusive')),
    interrupted: scenarios.some(item => item.stoppingPoint === 'interrupted' && item.cases.some(row => row.expected === 'untested')),
    heldOut: scenarios.some(item => item.heldOut),
  }
  const statuses = [accuracy.status, evidence.status, readers.status]
  const status: Status = statuses.includes('failed') ? 'failed'
    : statuses.every(item => item === 'passed') && Object.values(coverage).every(Boolean) ? 'passed' : 'pending'
  return {
    format: manifest.format, suite: manifest.suite, mode: manifest.mode, manifestSha256: sha256(bytes),
    status, coverage, accuracy, evidence, readers, scenarios,
  }
}
