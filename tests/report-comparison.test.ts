import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import type { TestContext } from 'node:test'
import { compareReports } from '../scripts/report-comparison.ts'

const primary = 'https://portal.example'
const secondary = 'https://audit.portal.example'

async function comparison(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'guardian-comparison-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const write = async (path: string, data: string | object) => {
    const content = typeof data === 'string' ? data : JSON.stringify(data)
    await writeFile(join(directory, path), content)
    return { path, sha256: createHash('sha256').update(content).digest('hex') }
  }
  const cases: { asset: string; issue: string; expected: string; severity?: string }[][] = [
    [{ asset: primary, issue: 'export', expected: 'confirmed', severity: 'high' },
      { asset: secondary, issue: 'export', expected: 'confirmed', severity: 'medium' }],
    [{ asset: primary, issue: 'export', expected: 'met' }],
    [{ asset: primary, issue: 'export', expected: 'inconclusive' }],
    [{ asset: primary, issue: 'export', expected: 'untested' }],
  ]
  const scenarios = []
  for (const [index, id] of ['multi-host', 'healthy', 'missing', 'stopped'].entries()) {
    const scope = index ? [primary] : [primary, secondary]
    const partial = id === 'stopped'
    const input = await write(id + '-input.json', {
      goal: 'Compare the supplied owner policy records.',
      scope,
      stoppingPoint: partial ? 'interrupted' : 'complete',
      overlappingObservations: !index,
      capturedEvidence: { fixture: id },
    })
    async function product(name: 'guardian' | 'artex') {
      const runId = id + '-' + name
      const reportId = runId + '-report'
      const report = await write(runId + '.md', '# Synthetic report\n- **Run** ' + runId + '\n- **Report version** 1\n')
      const recording = await write(runId + '-transcript.json', {
        runId, reportId, reportVersion: 1, status: partial ? 'stopped' : 'complete',
        approval: { eventId: 2, scope },
        events: [
          { id: 1, kind: 'run.created' },
          { id: 2, kind: 'scope.approved', scope },
          { id: 3, kind: partial ? 'report.partial' : 'report.complete', reportId, reportVersion: 1 },
        ],
      })
      const runRecord = await write(id + '-' + name + '-run.json', {
        inputSha256: input.sha256, reportSha256: report.sha256, recording,
      })
      const verdicts: { asset: string; issue: string; verdict: string; evidence?: string; severity?: string }[] =
        cases[index].map(({ asset, issue, expected, severity }) => ({
          asset, issue, verdict: expected, ...(expected === 'confirmed' ? { evidence: 'supported', severity } : {}),
        }))
      if (name === 'artex' && !index) verdicts[0] = { asset: primary, issue: 'export', verdict: 'untested' }
      return { version: 'fixture-revision', model: 'fixture-model', report, runRecord, inputSha256: input.sha256, verdicts }
    }
    const guardian = await product('guardian')
    const artex = await product('artex')
    const correct: Record<string, string> = index ? { coverage: 'correct' } : {
      priority: 'correct', remediation: 'correct', impact: 'correct', evidence: 'correct', recheck: 'correct', coverage: 'correct',
    }
    scenarios.push({
      id, input, cases: cases[index], guardian, artex, heldOut: id === 'multi-host',
      reviews: [{
        reader: 'fixture-reader',
        guardian: { reportSha256: guardian.report.sha256, tasks: { ...correct } },
        artex: { reportSha256: artex.report.sha256, tasks: { ...correct } },
      }],
    })
  }
  const manifest = { format: 1, suite: 'comparison-fixture', mode: 'assessment', scenarios }
  const path = join(directory, 'manifest.json')
  return { write, path, directory, manifest, async score() {
    await write('manifest.json', manifest)
    return compareReports(path)
  } }
}

test('compares matched reports and counts duplicates and missed finding severity', async t => {
  const fixture = await comparison(t)
  const { guardian, artex } = fixture.manifest.scenarios[0]
  delete guardian.verdicts[1].severity
  artex.verdicts[1].severity = 'low'
  guardian.verdicts.push({ ...guardian.verdicts[0] })
  const score = await fixture.score()
  assert.equal(score.status, 'passed')
  assert.equal(score.accuracy.guardian?.duplicates, 1)
  assert.equal(score.accuracy.guardian?.precision, 1)
  assert.equal(score.accuracy.guardian?.recall, 1)
  assert.equal(score.accuracy.artex?.recall, 0.5)
  assert.equal(score.accuracy.artex?.missesBySeverity.high, 1)
  assert.deepEqual(score.accuracy.guardian?.severityRatings, { correct: 1, incorrect: 0, ungraded: 1 })
  assert.deepEqual(score.accuracy.artex?.severityRatings, { correct: 0, incorrect: 1, ungraded: 0 })
  assert.equal(score.readers.pairs, 4)
  assert.deepEqual(score.readers.results.coverage, { guardian: 4, artex: 4 })
  assert.deepEqual(score.accuracy.seriousFindingIssues, [])
})

test('fails the scorecard for a missed or incorrectly rated serious finding', async t => {
  const fixture = await comparison(t)
  const { cases, guardian } = fixture.manifest.scenarios[0]
  const confirmed = guardian.verdicts[0]
  const issue = { scenario: 'multi-host', asset: primary, issue: 'export' }

  guardian.verdicts[0] = { asset: primary, issue: 'export', verdict: 'untested' }
  const missed = await fixture.score()
  assert.equal(missed.accuracy.guardian?.precision, missed.accuracy.artex?.precision)
  assert.equal(missed.accuracy.guardian?.recall, missed.accuracy.artex?.recall)
  assert.equal(missed.status, 'failed')
  assert.deepEqual(missed.accuracy.seriousFindingIssues, [{
    ...issue, expectedSeverity: 'high', reportedVerdict: 'untested', reportedSeverity: null,
  }])

  guardian.verdicts[0] = { ...confirmed, severity: undefined }
  const ungraded = await fixture.score()
  assert.equal(ungraded.accuracy.status, 'failed')
  assert.deepEqual(ungraded.accuracy.seriousFindingIssues, [{
    ...issue, expectedSeverity: 'high', reportedVerdict: 'confirmed', reportedSeverity: null,
  }])

  cases[0].severity = 'critical'
  guardian.verdicts[0] = confirmed
  const path = 'guardian-only.json'
  await fixture.write(path, {
    ...fixture.manifest,
    scenarios: fixture.manifest.scenarios.map(({ artex, ...scenario }) => ({ ...scenario, reviews: [] })),
  })
  const downgraded = await compareReports(join(fixture.directory, path))
  assert.equal(downgraded.accuracy.artex, null)
  assert.equal(downgraded.status, 'failed')
  assert.deepEqual(downgraded.accuracy.seriousFindingIssues, [{
    ...issue, expectedSeverity: 'critical', reportedVerdict: 'confirmed', reportedSeverity: 'high',
  }])

  guardian.verdicts[0].severity = 'critical'
  const corrected = await fixture.score()
  assert.equal(corrected.status, 'passed')
  assert.deepEqual(corrected.accuracy.seriousFindingIssues, [])
})

test('keeps assessment pending for renderer-only data or missing reader reviews', async t => {
  const fixture = await comparison(t)
  fixture.manifest.mode = 'report-only'
  const renderer = await fixture.score()
  assert.equal(renderer.status, 'pending')
  assert.equal(renderer.accuracy.guardian, null)
  assert.equal(renderer.readers.status, 'passed')
  fixture.manifest.mode = 'assessment'
  fixture.manifest.scenarios[0].heldOut = false
  const withoutHoldout = await fixture.score()
  assert.equal(withoutHoldout.status, 'pending')
  assert.equal(withoutHoldout.coverage.heldOut, false)
  fixture.manifest.scenarios[0].heldOut = true
  fixture.manifest.scenarios[0].reviews = []
  const unreviewed = await fixture.score()
  assert.equal(unreviewed.status, 'pending')
  assert.equal(unreviewed.accuracy.status, 'passed')
  assert.deepEqual(unreviewed.readers.awaitingReview, ['multi-host'])
})

test('fails a scope claim, unsupported evidence, and a lower reader score', async t => {
  const fixture = await comparison(t)
  const entry = fixture.manifest.scenarios[0]
  entry.guardian.verdicts[0].evidence = 'missing'
  entry.guardian.verdicts.push({ asset: 'https://outside.example', issue: 'export', verdict: 'confirmed', evidence: 'supported' })
  entry.reviews[0].guardian.tasks.recheck = 'incorrect'
  const score = await fixture.score()
  assert.equal(score.status, 'failed')
  assert.equal(score.accuracy.guardian?.falseConfirmations, 1)
  assert.deepEqual(score.evidence.issues.map(issue => issue.reason), ['missing', 'out-of-scope'])
  assert.equal(score.readers.status, 'failed')
  assert.deepEqual(score.readers.results.recheck, { guardian: 0, artex: 1 })
})

test('requires a paired coverage grade on an interrupted report', async t => {
  const fixture = await comparison(t)
  const entry = fixture.manifest.scenarios[3]
  const reviews = entry.reviews
  entry.reviews = []
  const missing = await fixture.score()
  assert.equal(missing.accuracy.status, 'passed')
  assert.equal(missing.readers.status, 'pending')
  assert.deepEqual(missing.readers.awaitingReview, ['stopped'])

  entry.reviews = reviews
  reviews[0].guardian.tasks.coverage = 'incorrect'
  const failed = await fixture.score()
  assert.equal(failed.readers.status, 'failed')
  assert.deepEqual(failed.readers.results.coverage, { guardian: 3, artex: 4 })
  assert.deepEqual(failed.readers.byScenario[3].tasks, [{ task: 'coverage', pairs: 1, guardian: 0, artex: 1 }])

  reviews[0].guardian.tasks.priority = 'correct'
  await assert.rejects(fixture.score(), /Invalid comparison manifest/)
})

test('rejects a different input, an inconsistent run record, and a stale reader score', async t => {
  const fixture = await comparison(t)
  const [{ input, artex, reviews }] = fixture.manifest.scenarios
  artex.inputSha256 = '0'.repeat(64)
  await assert.rejects(fixture.score(), /references different inputs/)
  artex.inputSha256 = input.sha256
  const runRecord = artex.runRecord
  artex.runRecord = await fixture.write('wrong-run.json', {
    inputSha256: input.sha256, reportSha256: '0'.repeat(64), recording: artex.report,
  })
  await assert.rejects(fixture.score(), /run record with different inputs or report/)
  artex.runRecord = runRecord
  reviews[0].artex.reportSha256 = '0'.repeat(64)
  await assert.rejects(fixture.score(), /reference different reports/)
  reviews[0].artex.reportSha256 = artex.report.sha256
  artex.verdicts.shift()
  await assert.rejects(fixture.score(), /missing a labeled case/)
})

test('validates scopes at the time of each recorded read', async t => {
  const fixture = await comparison(t)
  const { input, artex } = fixture.manifest.scenarios[1]
  const recording = await fixture.write('native-artex.log', 'Synthetic archive from an external report runner.')
  const runRecord = { inputSha256: input.sha256, reportSha256: artex.report.sha256, recording }
  artex.runRecord = await fixture.write('artex-reviewed-run.json', runRecord)
  const opaque = await fixture.score()
  assert.equal(opaque.scenarios[1].artex?.recordingAudit, 'unreviewed')
  assert.equal(opaque.accuracy.status, 'pending')

  const events = [
    { id: 1, kind: 'run.created' },
    { id: 2, kind: 'scope.approved', scope: [secondary] },
    { id: 3, kind: 'broker.allowed', origin: secondary },
    { id: 4, kind: 'broker.observed', origin: secondary },
    { id: 5, kind: 'scope.approved', scope: [primary] },
    { id: 6, kind: 'report.complete' },
  ]
  const record = async () => {
    const audit = await fixture.write('artex-reviewed-audit.json', {
      runId: 'healthy-artex', status: 'complete', approval: { eventId: 5, scope: [primary] }, events,
    })
    artex.runRecord = await fixture.write('artex-reviewed-run.json', { ...runRecord, audit })
  }
  await record()
  const approved = await fixture.score()
  assert.equal(approved.scenarios[1].artex?.recordingAudit, 'verified')
  assert.equal(approved.status, 'passed')

  events[3] = { id: 4, kind: 'scope.approved', scope: [primary] }
  events[4] = { id: 5, kind: 'broker.observed', origin: secondary }
  await record()
  await assert.rejects(fixture.score(), /recorded read outside its approved scope/)
})

test('rejects a correctly hashed recording from another scope, report version, or stopping point', async t => {
  const fixture = await comparison(t)
  const { input, guardian } = fixture.manifest.scenarios[3]
  const events = [
    { id: 1, kind: 'run.created' },
    { id: 2, kind: 'scope.approved', scope: [primary] },
    { id: 3, kind: 'report.partial', reportVersion: 1, reportId: 'stopped-guardian-report' },
  ]
  const audit = {
    runId: 'stopped-guardian', reportVersion: 1, reportId: 'stopped-guardian-report',
    status: 'stopped', approval: { eventId: 2, scope: [primary] }, events,
  }
  const record = async () => {
    const recording = await fixture.write('guardian-recording.json', audit)
    guardian.runRecord = await fixture.write('guardian-reviewed-run.json', {
      inputSha256: input.sha256, reportSha256: guardian.report.sha256, recording,
    })
  }
  await record()
  assert.equal((await fixture.score()).scenarios[3].guardian?.recordingAudit, 'verified')
  events[1].scope = [secondary]
  await record()
  await assert.rejects(fixture.score(), /recording for a different approved scope/)
  events[1].scope = [primary]
  events[1].id = 1
  await record()
  await assert.rejects(fixture.score(), /run events out of order/)
  events[1].id = 2
  audit.reportVersion = events[2].reportVersion = 2
  await record()
  await assert.rejects(fixture.score(), /recording for a different Guardian report version/)
  audit.reportVersion = events[2].reportVersion = 1
  audit.status = 'complete'
  events[2].kind = 'report.complete'
  await record()
  await assert.rejects(fixture.score(), /different stopping point or report checkpoint/)
})

test('rejects modified artifacts and report paths outside the comparison directory', async t => {
  const fixture = await comparison(t)
  const [{ guardian }] = fixture.manifest.scenarios
  await fixture.write(guardian.report.path, 'File changed after review.')
  await assert.rejects(fixture.score(), /SHA-256 mismatch/)
  await symlink(import.meta.filename, join(fixture.directory, 'external.md'))
  guardian.report.path = 'external.md'
  await assert.rejects(fixture.score(), /file inside the comparison directory/)
})
