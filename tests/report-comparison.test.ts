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
  const cases = [
    [{ asset: primary, issue: 'export', expected: 'confirmed', severity: 'high' },
      { asset: secondary, issue: 'export', expected: 'confirmed', severity: 'medium' }],
    [{ asset: primary, issue: 'export', expected: 'met' }],
    [{ asset: primary, issue: 'export', expected: 'inconclusive' }],
    [{ asset: primary, issue: 'export', expected: 'untested' }],
  ]
  const scenarios = []
  for (const [index, id] of ['multi-host', 'healthy', 'missing', 'stopped'].entries()) {
    const input = await write(id + '-input.json', {
      goal: 'Compare the supplied owner policy records.',
      scope: index ? [primary] : [primary, secondary],
      stoppingPoint: id === 'stopped' ? 'interrupted' : 'complete',
      overlappingObservations: !index,
      capturedEvidence: { fixture: id },
    })
    async function product(name: 'guardian' | 'artex') {
      const report = await write(id + '-' + name + '.md', '# Synthetic ' + name + ' report\n' + id)
      const recording = await write(id + '-' + name + '-transcript.json', { scenario: id, result: 'simulated' })
      const runRecord = await write(id + '-' + name + '-run.json', {
        inputSha256: input.sha256, reportSha256: report.sha256, recording,
      })
      const verdicts: { asset: string; issue: string; verdict: string; evidence?: string }[] =
        cases[index].map(({ asset, issue, expected }) => ({
          asset, issue, verdict: expected, ...(expected === 'confirmed' ? { evidence: 'supported' } : {}),
        }))
      if (name === 'artex' && !index) verdicts[0] = { asset: primary, issue: 'export', verdict: 'untested' }
      return { version: 'fixture-revision', model: 'fixture-model', report, runRecord, inputSha256: input.sha256, verdicts }
    }
    const guardian = await product('guardian')
    const artex = await product('artex')
    const correct = { priority: 'correct', remediation: 'correct', impact: 'correct', evidence: 'correct', recheck: 'correct' }
    scenarios.push({
      id, input, cases: cases[index], guardian, artex, heldOut: id === 'multi-host',
      reviews: index ? [] : [{
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
  const { guardian } = fixture.manifest.scenarios[0]
  guardian.verdicts.push({ ...guardian.verdicts[0] })
  const score = await fixture.score()
  assert.equal(score.status, 'passed')
  assert.equal(score.accuracy.guardian?.duplicates, 1)
  assert.equal(score.accuracy.guardian?.precision, 1)
  assert.equal(score.accuracy.guardian?.recall, 1)
  assert.equal(score.accuracy.artex?.recall, 0.5)
  assert.equal(score.accuracy.artex?.missesBySeverity.high, 1)
  assert.equal(score.readers.pairs, 1)
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

test('rejects modified artifacts and report paths outside the comparison directory', async t => {
  const fixture = await comparison(t)
  const [{ guardian }] = fixture.manifest.scenarios
  await fixture.write(guardian.report.path, 'File changed after review.')
  await assert.rejects(fixture.score(), /SHA-256 mismatch/)
  await symlink(import.meta.filename, join(fixture.directory, 'external.md'))
  guardian.report.path = 'external.md'
  await assert.rejects(fixture.score(), /file inside the comparison directory/)
})
