import { createHash } from 'node:crypto'
import { readFile, realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import { z } from 'zod'
import { assetOrigin, findingSeverities } from '../src/domain.ts'
import { scoreReportCases, verdictSchema } from './report-metrics.ts'

const label = z.string().trim().min(1)
const digest = z.string().regex(/^[a-f0-9]{64}$/)
const artifact = z.strictObject({ path: label, sha256: digest })
const runRecordSchema = z.strictObject({
  inputSha256: digest,
  reportSha256: digest,
  recording: artifact,
  audit: artifact.optional(),
})
const eventId = z.number().int().positive()
const recordingScope = z.array(assetOrigin)
const recordingAuditSchema = z.object({
  runId: label,
  reportId: label.optional(),
  reportVersion: z.number().int().positive().optional(),
  status: z.enum(['complete', 'stopped', 'paused', 'failed']),
  approval: z.object({ eventId, scope: recordingScope }),
  events: z.array(z.object({
    id: eventId,
    kind: label,
    origin: assetOrigin.nullish(),
    scope: recordingScope.nullish(),
    reportId: label.nullish(),
    reportVersion: z.number().int().positive().nullish(),
  })).min(3),
})
const severity = z.enum(findingSeverities)
const caseIdentity = { asset: assetOrigin, issue: label }
const expectedCase = z.discriminatedUnion('expected', [
  z.strictObject({ ...caseIdentity, expected: z.literal('confirmed'), severity }),
  z.strictObject({ ...caseIdentity, expected: verdictSchema.exclude(['confirmed']) }),
])
const evidenceQuality = z.enum(['supported', 'missing', 'unrelated', 'out-of-scope'])
const verdict = z.discriminatedUnion('verdict', [
  z.strictObject({ ...caseIdentity, verdict: z.literal('confirmed'), evidence: evidenceQuality.optional(), severity: severity.optional() }),
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
const tasks = z.enum(['priority', 'remediation', 'impact', 'evidence', 'recheck', 'coverage'])
const grade = z.enum(['correct', 'incorrect', 'unanswered'])
const answer = z.strictObject({
  reportSha256: digest,
  tasks: z.partialRecord(tasks, grade).refine(value => Object.keys(value).length > 0),
})
const review = z.strictObject({ reader: label, guardian: answer, artex: answer, notes: label.optional() }).refine(
  ({ guardian, artex }) => tasks.options.every(task => (guardian.tasks[task] === undefined) === (artex.tasks[task] === undefined)),
  { message: 'Provide a grade for the same tasks in both reports.' },
)
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
type RecordingAudit = z.infer<typeof recordingAuditSchema>
type StoppingPoint = z.infer<typeof inputSchema>['stoppingPoint']

function caseKey({ asset, issue }: { asset: string; issue: string }) {
  return JSON.stringify([asset, issue])
}

function sha256(bytes: Buffer) {
  return createHash('sha256').update(bytes).digest('hex')
}

function parseJson(data: Buffer): unknown {
  try { return JSON.parse(data.toString('utf8')) } catch { return undefined }
}

function readJson<T>(schema: z.ZodType<T>, data: Buffer, name: string): T {
  const value = parseJson(data)
  if (value === undefined) throw new Error(name + ' is not valid JSON.')
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

function sameScope(origins: string[], scope: ReadonlySet<string>) {
  return origins.length === scope.size && new Set(origins).size === scope.size && origins.every(origin => scope.has(origin))
}

function validateRecording(audit: RecordingAudit, scope: ReadonlySet<string>, stoppingPoint: StoppingPoint, context: string) {
  const complete = stoppingPoint === 'complete'
  const checkpoint = audit.events.at(-1)!
  if (audit.events[0].kind !== 'run.created' || checkpoint.kind !== (complete ? 'report.complete' : 'report.partial') ||
      (audit.status === 'complete') !== complete ||
      (checkpoint.reportId != null && checkpoint.reportId !== audit.reportId) ||
      (checkpoint.reportVersion != null && checkpoint.reportVersion !== audit.reportVersion)) {
    throw new Error(context + ' has a recording with a different stopping point or report checkpoint.')
  }
  let previous = 0
  let approval: number | undefined
  let effectiveScope = new Set<string>()
  for (const event of audit.events) {
    if (event.id <= previous) throw new Error(context + ' has run events out of order.')
    previous = event.id
    if (event.kind === 'scope.approved') {
      approval = event.id
      const origins = event.scope ?? (approval === audit.approval.eventId ? audit.approval.scope : [])
      effectiveScope = new Set(origins)
      if (effectiveScope.size !== origins.length) throw new Error(context + ' has a scope approval with duplicate hosts.')
    }
    if ((event.kind === 'broker.allowed' || event.kind === 'broker.observed') &&
        (!event.origin || !effectiveScope.has(event.origin))) {
      throw new Error(context + ' has a recorded read outside its approved scope.')
    }
  }
  if (approval !== audit.approval.eventId || !sameScope(audit.approval.scope, scope) ||
      !sameScope([...effectiveScope], scope)) {
    throw new Error(context + ' has a recording for a different approved scope.')
  }
}

async function readProduct(directory: string, entry: Scenario, product: Product, scope: Set<string>, stoppingPoint: StoppingPoint) {
  const result = entry[product]
  if (!result) return null
  const context = product + ' report for ' + JSON.stringify(entry.id)
  if (result.inputSha256 !== entry.input.sha256) throw new Error(context + ' references different inputs.')
  const report = await readArtifact(directory, result.report)
  let recording: Artifact | undefined
  let recordingAudit: 'missing' | 'unreviewed' | 'verified' = 'missing'
  if (result.runRecord) {
    const record = readJson(runRecordSchema, await readArtifact(directory, result.runRecord), 'run record')
    if (record.inputSha256 !== entry.input.sha256 || record.reportSha256 !== result.report.sha256) {
      throw new Error(context + ' is linked to a run record with different inputs or report.')
    }
    recording = record.recording
    const raw = await readArtifact(directory, recording)
    const audit = record.audit
      ? readJson(recordingAuditSchema, await readArtifact(directory, record.audit), 'run audit')
      : recordingAuditSchema.safeParse(parseJson(raw)).data
    recordingAudit = 'unreviewed'
    if (audit) {
      validateRecording(audit, scope, stoppingPoint, context)
      if (product === 'guardian') {
        const lines = report.toString('utf8').split(/\r?\n/)
        if (!audit.reportVersion || !lines.includes('- **Run** ' + audit.runId) ||
            !lines.includes('- **Report version** ' + audit.reportVersion)) {
          throw new Error(context + ' has a recording for a different Guardian report version.')
        }
      }
      recordingAudit = 'verified'
    }
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
    return {
      ...expected,
      reported: actual.verdict,
      ...(actual.verdict === 'confirmed' && actual.severity ? { reportedSeverity: actual.severity } : {}),
    }
  })
  const unexpectedConfirmations = [...observations.values()]
  if (unexpectedConfirmations.some(row => row.verdict !== 'confirmed')) {
    throw new Error(context + ' has an unmatched case without a confirmed finding.')
  }
  const { verdicts, ...metadata } = result
  return { ...metadata, recording, recordingAudit, cases, duplicates, unexpectedConfirmations, evidenceIssues }
}

async function readScenario(directory: string, entry: Scenario) {
  const input = readJson(inputSchema, await readArtifact(directory, entry.input), 'comparison input')
  const scope = new Set(input.scope)
  if (scope.size !== input.scope.length || new Set(entry.cases.map(caseKey)).size !== entry.cases.length ||
      entry.cases.some(row => !scope.has(row.asset))) {
    throw new Error('Invalid scope or duplicate case labels for ' + JSON.stringify(entry.id) + '.')
  }
  const guardian = await readProduct(directory, entry, 'guardian', scope, input.stoppingPoint)
  const artex = await readProduct(directory, entry, 'artex', scope, input.stoppingPoint)
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

function findSeriousFindingIssues(scenarios: CheckedScenario[]) {
  return scenarios.flatMap(({ id, guardian }) => {
    if (guardian?.recordingAudit !== 'verified') return []
    return guardian.cases.flatMap(row => {
      if (row.expected !== 'confirmed' || (row.severity !== 'high' && row.severity !== 'critical')) return []
      if (row.reported === 'confirmed' && row.reportedSeverity === row.severity) return []
      return [{
        scenario: id,
        asset: row.asset,
        issue: row.issue,
        expectedSeverity: row.severity,
        reportedVerdict: row.reported,
        reportedSeverity: row.reportedSeverity ?? null,
      }]
    })
  })
}

function findCoverageOverclaims(scenarios: CheckedScenario[]) {
  return scenarios.flatMap(({ id, guardian }) => {
    if (guardian?.recordingAudit !== 'verified') return []
    return guardian.cases.filter(({ expected, reported }) => {
      if (expected === 'untested') return reported !== 'untested'
      return expected === 'inconclusive' && (reported === 'confirmed' || reported === 'met')
    }).map(({ asset, issue, expected, reported }) => ({ scenario: id, asset, issue, expected, reported }))
  })
}

function scoreProduct(scenarios: CheckedScenario[], product: Product) {
  const reports = scenarios.flatMap(item => {
    const report = item[product]
    return report ? [report] : []
  })
  if (reports.length !== scenarios.length || reports.some(report => report.recordingAudit !== 'verified')) return null
  const cases = reports.flatMap(report => report.cases)
  const unmatched = reports.reduce((total, report) => total + report.unexpectedConfirmations.length, 0)
  const expectedConfirmations = cases.filter(row => row.expected === 'confirmed')
  const misses = expectedConfirmations.filter(row => row.reported !== 'confirmed')
  const matched = expectedConfirmations.filter(row => row.reported === 'confirmed')
  return {
    ...scoreReportCases(cases, unmatched),
    duplicates: reports.reduce((total, report) => total + report.duplicates, 0),
    missesBySeverity: Object.fromEntries(severity.options.map(level => [
      level, misses.filter(row => row.expected === 'confirmed' && row.severity === level).length,
    ])),
    severityRatings: {
      correct: matched.filter(row => row.reportedSeverity === row.severity).length,
      incorrect: matched.filter(row => row.reportedSeverity && row.reportedSeverity !== row.severity).length,
      ungraded: matched.filter(row => !row.reportedSeverity).length,
    },
  }
}

function compareAccuracy(guardian: ReturnType<typeof scoreProduct>, artex: ReturnType<typeof scoreProduct>): Status {
  if (!guardian || !artex) return 'pending'
  if (guardian.recall !== null && artex.recall !== null && guardian.recall < artex.recall) return 'failed'
  if (guardian.precision === null || artex.precision === null || artex.recall === null) return 'pending'
  return guardian.precision >= artex.precision ? 'passed' : 'failed'
}

function compareReaders(scenarios: CheckedScenario[]) {
  const byScenario = scenarios.map(item => {
    const relevant = item.cases.some(row => row.expected === 'confirmed') ? tasks.options : ['coverage'] as const
    const reviews = item.reviews.filter(review => relevant.some(task => review.guardian.tasks[task] !== undefined))
    return {
      id: item.id,
      pairs: reviews.length,
      tasks: relevant.map(task => {
        const graded = reviews.filter(review => review.guardian.tasks[task] !== undefined)
        return {
          task, pairs: graded.length,
          guardian: graded.filter(review => review.guardian.tasks[task] === 'correct').length,
          artex: graded.filter(review => review.artex.tasks[task] === 'correct').length,
        }
      }),
    }
  })
  const scores = byScenario.flatMap(item => item.tasks)
  const results = Object.fromEntries(tasks.options.map(task => {
    const rows = scores.filter(row => row.task === task)
    return [task, {
      guardian: rows.reduce((total, row) => total + row.guardian, 0),
      artex: rows.reduce((total, row) => total + row.artex, 0),
    }]
  }))
  const missedEssentialTask = scores.some(row =>
    row.pairs && (row.task === 'priority' || row.task === 'coverage') && !row.guardian)
  const remaining = byScenario.filter(item => item.tasks.some(task => !task.pairs)).map(item => item.id)
  let status: Status = 'pending'
  if (missedEssentialTask) status = 'failed'
  else if (!remaining.length) {
    status = Object.values(results).some(row => row.guardian < row.artex) ? 'failed' : 'passed'
  }
  return { status, pairs: byScenario.reduce((total, row) => total + row.pairs, 0), results, byScenario, awaitingReview: remaining }
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
  const seriousFindingIssues = manifest.mode === 'assessment' ? findSeriousFindingIssues(scenarios) : []
  const coverageOverclaims = manifest.mode === 'assessment' ? findCoverageOverclaims(scenarios) : []
  const accuracyStatus: Status = seriousFindingIssues.length || coverageOverclaims.length ? 'failed' : compareAccuracy(guardian, artex)
  const accuracy = { status: accuracyStatus, guardian, artex, seriousFindingIssues, coverageOverclaims }
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
