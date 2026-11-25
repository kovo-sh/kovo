/**
 * M6 Part C: recall benchmark harness tests (funnel, taxonomy, diff maths, persistence,
 * reports, CLI parsing, local-lab gate). Uses temp manifests so it runs before the lab
 * fixtures are merged; live-engine coverage is added once the servers exist.
 */
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { promisify } from 'node:util'
import { failureTaxonomyBuckets } from '../src/domain.ts'
import {
  attributeFailureBucket,
  buildFailureTaxonomy,
  buildFunnel,
  computeBenchmarkDiff,
  isMonotonicFunnel,
  simulateTraceFromManifest,
} from '../scripts/benchmark-core.ts'
import type { BenchmarkManifest, ManifestChallenge, TargetTrace } from '../scripts/benchmark-core.ts'
import {
  formatBenchmarkMarkdown,
  parseBenchmarkCliArgs,
  resolveSuites,
  runBenchmarkSuite,
} from '../scripts/benchmark-recall.ts'
import { makeStore, makeTempDir, repoRoot, withEnv } from './v4-tier-helpers.ts'

const exec = promisify(execFile)

function challenge(i: number, over: Partial<ManifestChallenge> = {}): ManifestChallenge {
  return {
    id: `t-${String(i).padStart(2, '0')}`,
    vulnClass: 'sqli',
    endpoint: `/api/item${i}`,
    method: 'GET',
    param: 'q',
    encoding: 'query',
    ...over,
  }
}

function fixtureManifest(): BenchmarkManifest {
  const vulns: ManifestChallenge[] = [
    challenge(1),
    challenge(2, { encoding: 'form', requiresV4Feature: 'form_encoding', method: 'POST' }),
    challenge(3, { requiresCsrf: true, requiresV4Feature: 'csrf_bind', method: 'POST' }),
    challenge(4, { requiresBrowser: true, requiresV4Feature: 'persistent_browser' }),
    challenge(5, { vulnClass: 'idor', endpoint: '/api/orgs/{org}/invoices/{id}' }),
    challenge(6, { requiresV4Feature: 'sqli_time_diff' }),
    challenge(7, { tierRequired: 3 }),
    challenge(8, { requiresV4Feature: 'inline_verify' }),
  ]
  const decoys: ManifestChallenge[] = [challenge(90, { isDecoy: true, decoyReason: 'parameterized query' })]
  return { challenges: [...vulns, ...decoys] }
}

const base = (over: Partial<TargetTrace> = {}): TargetTrace => ({
  id: 'x',
  isDecoy: false,
  surfaceDiscovered: true,
  hypothesisFormed: true,
  signalObserved: true,
  specSubmitted: true,
  confirmed: false,
  ...over,
})

describe('M6 benchmark harness: funnel + taxonomy', () => {
  test('funnel is monotonic and excludes decoys from the denominator', () => {
    const traces = fixtureManifest().challenges.map(c => simulateTraceFromManifest(c, 'v3-baseline'))
    const funnel = buildFunnel(traces)
    assert.equal(funnel.targetVulns, 8)
    assert.ok(isMonotonicFunnel(funnel))
    const v4 = buildFunnel(fixtureManifest().challenges.map(c => simulateTraceFromManifest(c, 'v4-full')))
    assert.equal(v4.targetVulns, 8)
    assert.equal(v4.zeroLlmConfirmed, 8)
    assert.ok(v4.zeroLlmConfirmed > funnel.zeroLlmConfirmed, 'v4-full must beat v3-baseline in the capability model')
  })

  test('stage flags cascade so a later stage can never exceed an earlier one', () => {
    const funnel = buildFunnel([base({ surfaceDiscovered: false, confirmed: true })])
    assert.deepEqual(funnel, { targetVulns: 1, surfaceDiscovered: 0, hypothesisFormed: 0, signalObserved: 0, specSubmitted: 0, zeroLlmConfirmed: 0 })
  })

  test('attributeFailureBucket reaches all 11 taxonomy buckets deterministically', () => {
    const cases: Array<[Partial<TargetTrace>, string | null]> = [
      [{ confirmed: true }, null],
      [{ budgetExhausted: true }, 'budget_exhausted'],
      [{ surfaceDiscovered: false }, 'surface_miss'],
      [{ hypothesisFormed: false }, 'hypothesis_miss'],
      [{ hypothesisFormed: false, encodingUnsupported: true }, 'form_encoding_missing'],
      [{ signalObserved: false, csrfRejected: true }, 'csrf_blocked'],
      [{ signalObserved: false, contextReset: true }, 'context_reset'],
      [{ signalObserved: false, tierBlocked: true }, 'tier_blocked'],
      [{ signalObserved: false }, 'trigger_miss'],
      [{ specSubmitted: false }, 'replay_spec_miss'],
      [{ jqError: true }, 'jq_assertion_bug'],
      [{ spaCatchall: true }, 'spa_catchall_fp'],
    ]
    const seen = new Set<string>()
    for (const [over, expected] of cases) {
      const bucket = attributeFailureBucket(base(over))
      assert.equal(bucket, expected, JSON.stringify(over))
      if (bucket) seen.add(bucket)
    }
    for (const b of failureTaxonomyBuckets) assert.ok(seen.has(b), `bucket ${b} never attributed`)
    assert.equal(seen.size, 11)
  })

  test('taxonomy counts every missed target exactly once and skips decoys', () => {
    const traces = [base({ id: 'a', confirmed: true }), base({ id: 'b', surfaceDiscovered: false }), base({ id: 'c', isDecoy: true, confirmed: true })]
    const tax = buildFailureTaxonomy(traces)
    assert.equal(tax.surface_miss, 1)
    assert.equal(Object.values(tax).reduce((a, b) => a + b, 0), 1)
  })
})

describe('M6 benchmark harness: diff maths', () => {
  test('zero-division safe when targetsTotal and confirmedCount are 0', () => {
    const d = computeBenchmarkDiff(
      { targetsTotal: 0, confirmedCount: 0, falsePositiveCount: 0, funnelCounts: {}, failureTaxonomy: {}, totalCostUsd: 0 },
      { targetsTotal: 0, confirmedCount: 0, falsePositiveCount: 0, funnelCounts: {}, failureTaxonomy: {}, totalCostUsd: 0 },
    )
    assert.equal(d.recall, 0)
    assert.equal(d.precision, null)
    assert.equal(d.costPerVuln, null)
    assert.equal(d.recallDelta, 0)
    assert.ok(Number.isFinite(d.recallDelta ?? NaN))
  })

  test('computes recall/FP/cost deltas and ranks bucket drops', () => {
    const d = computeBenchmarkDiff(
      { targetsTotal: 20, confirmedCount: 15, falsePositiveCount: 0, totalCostUsd: 3, failureTaxonomy: { csrf_blocked: 0, surface_miss: 1, trigger_miss: 4 }, gitSha: 'new' },
      { targetsTotal: 20, confirmedCount: 5, falsePositiveCount: 1, totalCostUsd: 4, failureTaxonomy: { csrf_blocked: 4, surface_miss: 6, trigger_miss: 4 }, gitSha: 'old' },
    )
    assert.equal(d.hasBaseline, true)
    assert.ok(Math.abs((d.recallDelta ?? 0) - 0.5) < 1e-9)
    assert.equal(d.confirmedDelta, 10)
    assert.equal(d.fpDelta, -1)
    assert.equal(d.costPerVuln, 0.2)
    assert.equal(d.baselineCostPerVuln, 0.8)
    assert.deepEqual(d.topBucketDrops.map(x => x.bucket), ['surface_miss', 'csrf_blocked'])
    assert.equal(d.bucketDeltas.surface_miss, -5)
  })

  test('without a baseline every delta is null', () => {
    const d = computeBenchmarkDiff({ targetsTotal: 4, confirmedCount: 2, falsePositiveCount: 0 }, null)
    assert.equal(d.recallDelta, null)
    assert.equal(d.hasBaseline, false)
    assert.equal(d.recall, 0.5)
  })
})

describe('M6 benchmark harness: runBenchmarkSuite (dry run)', () => {
  test('persists rows, excludes decoys, and writes JSON + Markdown diff against a baseline SHA', async t => {
    const { dir, storage } = makeStore(t)
    const manifests = { 'held-out-saas': fixtureManifest() }
    const outJson = join(dir, 'diff.json')
    const outMd = join(dir, 'diff.md')
    const v3 = await runBenchmarkSuite({ suite: 'held-out-saas', dryRun: true, profileMode: 'v3-baseline', gitSha: 'sha-v3', storage, manifests })
    const v4 = await runBenchmarkSuite({
      suite: 'saas-lab', dryRun: true, profileMode: 'v4-full', gitSha: 'sha-v4', baselineSha: 'sha-v3', storage, manifests, outJson, outMd,
    })
    assert.equal(v3.suite, 'held-out-saas')
    assert.equal(v4.targetsTotal, 8)
    assert.equal(v4.funnelCounts.targetVulns, 8)
    assert.equal(v4.decoysTotal, 1)
    assert.equal(v4.falsePositiveCount, 0)
    assert.ok(isMonotonicFunnel(v4.funnelCounts))
    assert.equal(storage.listBenchmarkRuns('held-out-saas', 10).length, 2)
    assert.equal(storage.getLatestBenchmarkRun('held-out-saas')?.gitSha, 'sha-v4')
    assert.ok((v4.recallDelta ?? 0) > 0)
    assert.ok((v4.confirmedDelta ?? 0) > 0)
    const json = JSON.parse(readFileSync(outJson, 'utf8')) as Record<string, unknown>
    assert.equal(typeof json.recallDelta, 'number')
    assert.equal(typeof json.confirmedDelta, 'number')
    const md = readFileSync(outMd, 'utf8')
    assert.match(md, /sha-v3/)
    assert.match(md, /sha-v4/)
    for (const b of failureTaxonomyBuckets) assert.ok(md.includes(b), `markdown missing bucket ${b}`)
    assert.match(md, /Top bucket drops/)
  })

  test('falls back to the previous stored run when no baseline SHA is given, and tolerates an unknown SHA', async t => {
    const { storage } = makeStore(t)
    const manifests = { 'xben-25': fixtureManifest() }
    await runBenchmarkSuite({ suite: 'xben-25', dryRun: true, gitSha: 'one', storage, manifests })
    const second = await runBenchmarkSuite({ suite: 'xben-25', dryRun: true, gitSha: 'two', storage, manifests })
    assert.equal(second.baselineSha, 'one')
    const third = await runBenchmarkSuite({ suite: 'xben-25', dryRun: true, gitSha: 'three', baselineSha: 'missing', storage, manifests })
    assert.equal(third.recallDelta, null)
    assert.ok(third.notes.some(n => /missing/.test(n)))
  })

  test('empty manifest does not divide by zero', async t => {
    const { storage } = makeStore(t)
    const res = await runBenchmarkSuite({ suite: 'xben-25', dryRun: true, storage, gitSha: 'empty', manifests: { 'xben-25': { challenges: [] } } })
    assert.equal(res.targetsTotal, 0)
    assert.equal(res.recall, 0)
    assert.equal(res.precision, null)
    assert.equal(res.costPerVuln, null)
  })

  test('suite "all" runs both suites and writes per-suite files to outDir', async t => {
    const { dir, storage } = makeStore(t)
    const outDir = join(dir, 'reports')
    const res = await runBenchmarkSuite({
      suite: 'all', dryRun: true, storage, gitSha: 'allsha', outDir,
      manifests: { 'xben-25': fixtureManifest(), 'held-out-saas': fixtureManifest() },
    })
    assert.equal(res.children?.length, 2)
    assert.equal(res.targetsTotal, 16)
    assert.ok(existsSync(join(outDir, 'benchmark-xben-25-v4-full-allsha.json')))
    assert.ok(existsSync(join(outDir, 'benchmark-held-out-saas-v4-full-allsha.md')))
  })

  test('markdown formatter handles a baseline-less run', async t => {
    const { storage } = makeStore(t)
    const res = await runBenchmarkSuite({ suite: 'xben-25', dryRun: true, storage, gitSha: 'solo', manifests: { 'xben-25': fixtureManifest() } })
    const md = formatBenchmarkMarkdown(res)
    assert.match(md, /solo/)
    assert.match(md, /No baseline run available/)
  })
})

describe('M6 benchmark harness: gate + CLI', () => {
  test('refuses a live local-lab run without KOVO_ALLOW_LOCAL_LAB=1 but allows dry runs', async t => {
    const { storage } = makeStore(t)
    const manifests = { 'held-out-saas': fixtureManifest() }
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => runBenchmarkSuite({ suite: 'held-out-saas', storage, manifests })),
      /KOVO_ALLOW_LOCAL_LAB/,
    )
    await assert.rejects(
      () => withEnv({ KOVO_ALLOW_LOCAL_LAB: '0' }, () => runBenchmarkSuite({ suite: 'xben-25', storage, manifests })),
      /KOVO_ALLOW_LOCAL_LAB/,
    )
    const dry = await withEnv({ KOVO_ALLOW_LOCAL_LAB: undefined }, () => runBenchmarkSuite({ suite: 'held-out-saas', dryRun: true, storage, manifests }))
    assert.equal(dry.targetsTotal, 8)
    assert.equal(storage.listBenchmarkRuns('held-out-saas').length, 1)
  })

  test('parseBenchmarkCliArgs parses every flag and rejects unknown ones', () => {
    const opts = parseBenchmarkCliArgs([
      '--suite', 'saas-lab', '--baseline-sha', 'base', '--git-sha=head', '--out-json', 'a.json', '--out-md', 'a.md',
      '--out-dir', 'out', '--db', '/tmp/x/kovo.sqlite', '--dry-run', '--profile-mode', 'v3-baseline', '--diff', '--verify-patches',
      '--verifier-backend', 'local-jq',
    ])
    assert.equal(opts.suite, 'saas-lab')
    assert.equal(opts.baselineSha, 'base')
    assert.equal(opts.gitSha, 'head')
    assert.equal(opts.outJson, 'a.json')
    assert.equal(opts.outMd, 'a.md')
    assert.equal(opts.outDir, 'out')
    assert.equal(opts.dbPath, '/tmp/x')
    assert.equal(opts.dryRun, true)
    assert.equal(opts.profileMode, 'v3-baseline')
    assert.equal(opts.diff, true)
    assert.equal(opts.verifyPatches, true)
    assert.equal(opts.verifierBackend, 'local-jq')
    assert.deepEqual(resolveSuites('saas-lab'), ['held-out-saas'])
    assert.deepEqual(resolveSuites('all'), ['xben-25', 'held-out-saas'])
    assert.throws(() => parseBenchmarkCliArgs(['--nope']), /Unknown benchmark option/)
    assert.throws(() => parseBenchmarkCliArgs(['--suite']), /requires a value/)
    assert.throws(() => parseBenchmarkCliArgs(['--suite', 'bogus']), /Unknown benchmark suite/)
    assert.throws(() => parseBenchmarkCliArgs(['--profile-mode', 'v9']), /profile-mode/)
  })

  test('importing the module has no side effects and the CLI prints help', async () => {
    const script = resolve(repoRoot, 'scripts/benchmark-recall.ts')
    const help = await exec('node', [script, '--help'], { cwd: repoRoot })
    assert.match(help.stdout, /Kovo(?: Hunter)? v4 recall benchmark/)
    const bad = await exec('node', [script, '--bogus'], { cwd: repoRoot }).then(() => null, (e: { code?: number; stderr?: string }) => e)
    assert.ok(bad && bad.code === 1)
    assert.match(bad?.stderr ?? '', /Unknown benchmark option/)
  })

  test('CLI --dry-run writes JSON + Markdown and persists to --db', async t => {
    const dir = makeTempDir(t, 'kovo-m6-cli-')
    const outJson = join(dir, 'cli.json')
    const outMd = join(dir, 'cli.md')
    const manifest = resolve(repoRoot, 'benchmarks/xben-25/manifest.json')
    if (!existsSync(manifest)) {
      t.skip('xben-25 manifest not merged yet')
      return
    }
    const res = await exec('node', [
      resolve(repoRoot, 'scripts/benchmark-recall.ts'), '--suite', 'xben-25', '--dry-run', '--git-sha', 'cli1', '--db', join(dir, 'db'),
      '--out-json', outJson, '--out-md', outMd,
    ], { cwd: repoRoot })
    assert.match(res.stdout, /suite=xben-25/)
    assert.ok(existsSync(outJson))
    assert.ok(existsSync(outMd))
  })
})
