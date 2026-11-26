/**
 * R3-01 CI parallelization & sharding tests:
 *  1. `scripts/run-fast-tests.sh --shard 1/6 .. 6/6` forms an exact disjoint union of all fast
 *     test files (0 missing, 0 duplicates, balanced counts).
 *  2. Playwright/UI suites (`tests/ux-*.test.ts`, `tests/fix-*.test.ts`) are spread evenly
 *     across all 6 shards (max difference <= 1).
 *  3. Invalid `--shard` specs (`0/6`, `7/6`, `abc`, `1/0`, `-1/6`, `01/6`) fail fast with
 *     non-zero exit.
 *  4. Execution & stale-quarantine detection are scoped to the shard's files while orphan
 *     check and `maxQuarantinedCases` cap still validate the full repo inventory.
 *  5. `.github/workflows/verify.yml` is valid YAML, parallelizes across 4 jobs + `verify`
 *     aggregator, covers all 6 shards, and preserves every mandatory check.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const RUN_FAST_TESTS_SH = join(REPO_ROOT, 'scripts/run-fast-tests.sh')
const VERIFY_YML = join(REPO_ROOT, '.github/workflows/verify.yml')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function runFastRunner(args: string[]) {
  const res = spawnSync('bash', [RUN_FAST_TESTS_SH, '--suites-only', '--json', '--jobs', '2', ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 60_000,
  })
  let parsed: Record<string, unknown> | null = null
  try {
    parsed = JSON.parse(res.stdout)
  } catch {
    parsed = null
  }
  return { status: res.status ?? 1, stdout: res.stdout, stderr: res.stderr, parsed }
}

test('R3-01: --shard 1/6..6/6 forms an exact disjoint union and spreads ux-/fix- UI suites evenly', () => {
  const full = runFastRunner(['--check-only', '--quarantine', 'tests/QUARANTINE.json'])
  assert.equal(full.status, 0, `full --check-only failed: ${full.stdout} ${full.stderr}`)
  assert.equal(full.parsed?.ok, true)
  const expectedFastCount = Number(full.parsed?.fast)
  assert.ok(expectedFastCount > 50, `expected >50 fast files, got ${expectedFastCount}`)

  const N = 6
  const shardFileLists: string[][] = []
  for (let k = 1; k <= N; k += 1) {
    const res = runFastRunner(['--check-only', '--quarantine', 'tests/QUARANTINE.json', '--shard', `${k}/${N}`])
    assert.equal(res.status, 0, `shard ${k}/${N} --check-only failed: ${res.stdout} ${res.stderr}`)
    assert.equal(res.parsed?.ok, true)
    assert.equal(res.parsed?.shard, `${k}/${N}`)
    assert.equal(res.parsed?.fast, expectedFastCount)
    const files = (res.parsed?.shardFiles as string[]) ?? []
    assert.equal(res.parsed?.shardFast, files.length)
    shardFileLists.push(files)
  }

  // Exact disjoint union: 0 duplicates, 0 dropped.
  const seen = new Set<string>()
  const duplicates: string[] = []
  for (const list of shardFileLists) {
    for (const f of list) {
      if (seen.has(f)) duplicates.push(f)
      seen.add(f)
    }
  }
  assert.deepEqual(duplicates, [], `duplicate files across shards: ${duplicates.join(', ')}`)
  assert.equal(seen.size, expectedFastCount, `union size ${seen.size} != total fast count ${expectedFastCount}`)

  // Total file counts balanced (max - min <= 1).
  const totals = shardFileLists.map(l => l.length)
  assert.ok(
    Math.max(...totals) - Math.min(...totals) <= 1,
    `unbalanced shard sizes: ${totals.join(', ')}`,
  )

  // Playwright/UI suites (tests/ux-*.test.ts and tests/fix-*.test.ts) spread evenly (max - min <= 1).
  const uiRe = /^tests\/(?:ux|fix)-[^/]+\.test\.ts$/
  const uiCounts = shardFileLists.map(l => l.filter(f => uiRe.test(f)).length)
  const totalUi = uiCounts.reduce((a, b) => a + b, 0)
  assert.ok(totalUi >= 20, `expected >=20 ux-/fix- files, got ${totalUi}`)
  assert.ok(
    Math.max(...uiCounts) - Math.min(...uiCounts) <= 1,
    `uneven ux-/fix- distribution across shards: ${uiCounts.join(', ')}`,
  )

  // Determinism: shard 1/6 returns identical file list on repeated calls.
  const repeat = runFastRunner(['--check-only', '--quarantine', 'tests/QUARANTINE.json', '--shard', '1/6'])
  assert.deepEqual(repeat.parsed?.shardFiles, shardFileLists[0])
})

test('R3-01: invalid --shard specs fail fast with non-zero exit', () => {
  for (const bad of ['0/6', '7/6', 'abc', '1/0', '-1/6', '01/6', '2/', '/6', '1/2/3']) {
    const res = runFastRunner(['--check-only', '--shard', bad])
    assert.notEqual(res.status, 0, `expected non-zero exit for --shard ${bad}`)
    assert.match(res.stderr, /invalid --shard/i, `expected error diagnostic for --shard ${bad}`)
  }
})

test('R3-01: sharded execution scopes stale-quarantine checks to own shard while keeping global orphan/cap validation', (t) => {
  const dir = makeTempDir(t, 'r301-shard-exec-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })

  // Create 4 files: 2 ux-* (indices 0, 1 -> shard 1, shard 2) and 2 regular (indices 2, 3 -> shard 1, shard 2).
  writeFileSync(join(testsDir, 'ux-alpha.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('ux alpha pass', () => { assert.ok(true) })",
    "test('ux alpha known fail', () => { assert.equal(1, 2) })",
  ].join('\n') + '\n')

  writeFileSync(join(testsDir, 'ux-beta.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('ux beta pass', () => { assert.ok(true) })",
    "test('ux beta known fail', () => { assert.equal(1, 2) })",
  ].join('\n') + '\n')

  writeFileSync(join(testsDir, 'unit-a.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('unit a pass', () => { assert.ok(true) })",
  ].join('\n') + '\n')

  writeFileSync(join(testsDir, 'unit-b.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('unit b pass', () => { assert.ok(true) })",
  ].join('\n') + '\n')

  const qPath = join(dir, 'QUARANTINE.json')
  writeFileSync(qPath, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 2,
    entries: [
      {
        file: 'tests/ux-alpha.test.ts',
        testName: 'ux alpha known fail',
        ownerStream: 'team-ux',
        reason: 'known shard 1 failure',
        expires: '2026-12-26',
      },
      {
        file: 'tests/ux-beta.test.ts',
        testName: 'ux beta known fail',
        ownerStream: 'team-ux',
        reason: 'known shard 2 failure',
        expires: '2026-12-26',
      },
    ],
  }, null, 2))

  // Shard 1/2 runs ux-alpha + unit-a; ux-beta's quarantine entry must NOT trigger false stale/missing errors.
  const s1 = runFastRunner(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26', '--shard', '1/2'])
  assert.equal(s1.status, 0, `shard 1/2 should PASS: ${s1.stdout} ${s1.stderr}`)
  assert.equal(s1.parsed?.ok, true)
  assert.equal(s1.parsed?.fast, 2)
  assert.equal(s1.parsed?.totalQuarantinedFail, 1)
  assert.deepEqual(s1.parsed?.staleEntries, [])

  // Shard 2/2 runs ux-beta + unit-b; passes cleanly too.
  const s2 = runFastRunner(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26', '--shard', '2/2'])
  assert.equal(s2.status, 0, `shard 2/2 should PASS: ${s2.stdout} ${s2.stderr}`)
  assert.equal(s2.parsed?.ok, true)
  assert.equal(s2.parsed?.fast, 2)
  assert.equal(s2.parsed?.totalQuarantinedFail, 1)
  assert.deepEqual(s2.parsed?.staleEntries, [])

  // Global validation still catches an orphan nested test even when running shard 1/2.
  const nestedDir = join(testsDir, 'nested')
  mkdirSync(nestedDir, { recursive: true })
  writeFileSync(join(nestedDir, 'orphan.test.ts'), 'export {}\n')
  const orphanRes = runFastRunner(['--check-only', '--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26', '--shard', '1/2'])
  assert.notEqual(orphanRes.status, 0, 'sharded mode must still fail on orphan nested test')
  const orphanErrors = (orphanRes.parsed?.errors as string[]) ?? []
  assert.ok(orphanErrors.some(e => /orphan/i.test(e)), `expected orphan error: ${orphanErrors.join('; ')}`)
  rmSync(nestedDir, { recursive: true, force: true })

  // Global validation still enforces maxQuarantinedCases across all entries even in shard 1/2.
  const overCapQ = join(dir, 'QUARANTINE.overcap.json')
  writeFileSync(overCapQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 1,
    entries: [
      {
        file: 'tests/ux-alpha.test.ts',
        testName: 'ux alpha known fail',
        ownerStream: 'team-ux',
        reason: 'known',
        expires: '2026-12-26',
      },
      {
        file: 'tests/ux-beta.test.ts',
        testName: 'ux beta known fail',
        ownerStream: 'team-ux',
        reason: 'known',
        expires: '2026-12-26',
      },
    ],
  }, null, 2))
  const capRes = runFastRunner(['--check-only', '--tests-dir', testsDir, '--quarantine', overCapQ, '--now', '2026-11-26', '--shard', '1/2'])
  assert.notEqual(capRes.status, 0, 'sharded mode must still enforce full maxQuarantinedCases cap')
  const capErrors = (capRes.parsed?.errors as string[]) ?? []
  assert.ok(capErrors.some(e => /quarantine cap exceeded/i.test(e)), `expected cap error: ${capErrors.join('; ')}`)
})

test('R3-01: .github/workflows/verify.yml is valid YAML, 6-way sharded, parallelized, and preserves every mandatory check', () => {
  const raw = readFileSync(VERIFY_YML, 'utf8')

  // Validate YAML syntax and parse structure using PyYAML.
  const py = spawnSync(
    'python3',
    ['-c', 'import json, sys, yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))'],
    { input: raw, encoding: 'utf8' },
  )
  assert.equal(py.status, 0, `verify.yml is not valid YAML: ${py.stderr}`)
  const doc = JSON.parse(py.stdout) as {
    concurrency?: { group?: string; 'cancel-in-progress'?: unknown }
    jobs?: Record<string, {
      needs?: string[] | string
      if?: string
      strategy?: { 'fail-fast'?: boolean; matrix?: { shard?: number[] } }
      steps?: Array<{ run?: string; uses?: string; with?: Record<string, unknown> }>
    }>
  }

  assert.ok(doc.jobs, 'verify.yml must define jobs')
  const expectedJobs = ['static-and-typecheck', 'fast-tests', 'docker-and-boundaries', 'e2e-ui', 'verify']
  for (const jobName of expectedJobs) {
    assert.ok(doc.jobs[jobName], `verify.yml missing required job '${jobName}'`)
  }

  // Matrix sharding invariants on fast-tests.
  const fastJob = doc.jobs['fast-tests']!
  assert.equal(fastJob.strategy?.['fail-fast'], false, 'fast-tests strategy.fail-fast must be false')
  assert.deepEqual(fastJob.strategy?.matrix?.shard, [1, 2, 3, 4, 5, 6], 'fast-tests must run shards [1, 2, 3, 4, 5, 6]')

  // Aggregator job preserves `verify` name and waits on all 4 parallel jobs.
  const verifyJob = doc.jobs.verify!
  const needs = Array.isArray(verifyJob.needs) ? verifyJob.needs : [verifyJob.needs]
  for (const reqJob of ['static-and-typecheck', 'fast-tests', 'docker-and-boundaries', 'e2e-ui']) {
    assert.ok(needs.includes(reqJob), `verify aggregator job must need '${reqJob}'`)
  }
  assert.equal(verifyJob.if, 'always()', 'verify aggregator must use if: always() and fail if any needed job is not success')

  // Preserve every mandatory check in verify.yml.
  const mandatorySubstrings = [
    'node scripts/check-v8-contamination.ts',
    'node scripts/check-fixture-contamination.ts',
    'node scripts/check-unwired.ts',
    'node scripts/check-contract-change.ts --base',
    'NODE_OPTIONS: "--max-old-space-size=6144"',
    '--extendedDiagnostics',
    'node scripts/check-tsc-budget.ts',
    'bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json --jobs 2 --shard ${{ matrix.shard }}/6',
    'worker:build',
    'kovo-worker:v4',
    'bash scripts/docker-smoke.sh',
    'npm run test:boundaries',
    'npm run build && KOVO_ALLOW_LOCAL_MODEL=1 node --test tests/e2e-ui-journeys.test.ts',
    '~/.cache/ms-playwright',
    'npx playwright install-deps chromium',
    'kernel.apparmor_restrict_unprivileged_userns=0',
  ]
  for (const snippet of mandatorySubstrings) {
    assert.ok(raw.includes(snippet), `verify.yml missing mandatory check: ${snippet}`)
  }
})
