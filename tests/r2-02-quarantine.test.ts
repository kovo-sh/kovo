/**
 * R2-02 regression tests (`plans/claude_quality_2.md` §2):
 *  1. Per-case quarantine catches unlisted failures inside files that have quarantined cases.
 *  2. Drift detection: quarantined case passing 2x in a row triggers `"stale quarantine entry — remove"`
 *     without modifying the quarantine file; a 1-pass/1-fail nondeterministic case stays quarantined.
 *  3. Canonical `scripts/test-tiers.ts` (`KERNEL_TEST_RE`, `SCHEMA_AUTHORITY_TESTS`,
 *     `PROVIDER_REDACTION_TESTS`, `isKernelOrCriticalTestFile`) enforces `expires <= 14d` and
 *     concrete `ownerStream` (rejecting generic triage buckets & missing owners), while forbidding
 *     core gate invariant suites and whole-file v1 entries.
 *  4. `scripts/runtime-profile.ts` (`PRODUCTION_NODE_FLAGS`, `buildHermeticTestEnv`,
 *     `parseTapOutput`) strips ambient `KOVO_*`/`OPENROUTER_*`/proxy leaks, injects isolated
 *     `KOVO_DATA_DIR`/`TMPDIR`, and runs child tests under production hardened Node flags.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  buildHermeticNodeTestArgs,
  buildHermeticTestEnv,
  parseTapOutput,
  PRODUCTION_NODE_FLAGS,
} from '../scripts/runtime-profile.ts'
import {
  CORE_GATE_INVARIANT_TESTS,
  isCoreGateInvariantTestFile,
  isGenericTriageOwner,
  isKernelOrCriticalTestFile,
  KERNEL_TEST_RE,
  MAX_KERNEL_QUARANTINE_DAYS,
  PROVIDER_REDACTION_TESTS,
  SCHEMA_AUTHORITY_TESTS,
} from '../scripts/test-tiers.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const RUN_FAST_TESTS_SH = join(REPO_ROOT, 'scripts/run-fast-tests.sh')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function runFastRunner(args: string[], extraEnv: Record<string, string> = {}) {
  const res = spawnSync('bash', [RUN_FAST_TESTS_SH, '--suites-only', '--json', '--jobs', '2', ...args], {
    cwd: REPO_ROOT,
    env: { ...process.env, ...extraEnv },
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

// ============================================================================
// 1. Canonical scripts/test-tiers.ts & schema v2 validation
// ============================================================================

test('test-tiers exports canonical KERNEL_TEST_RE, SCHEMA_AUTHORITY_TESTS, PROVIDER_REDACTION_TESTS, and classifier', () => {
  const contractSrc = readFileSync(join(REPO_ROOT, 'scripts/check-contract-change.ts'), 'utf8')
  assert.ok(
    contractSrc.includes(KERNEL_TEST_RE.source),
    'KERNEL_TEST_RE must stay identical to scripts/check-contract-change.ts',
  )
  assert.equal(MAX_KERNEL_QUARANTINE_DAYS, 14)
  assert.ok(SCHEMA_AUTHORITY_TESTS.includes('tests/arch-b3-cascade.test.ts'))
  assert.ok(PROVIDER_REDACTION_TESTS.includes('tests/provider-stream.test.ts'))
  assert.ok(PROVIDER_REDACTION_TESTS.includes('tests/r3-provider-scrub.test.ts'))
  assert.ok(CORE_GATE_INVARIANT_TESTS.includes('tests/r2-02-quarantine.test.ts'))

  assert.equal(isKernelOrCriticalTestFile('tests/t2-oracle-invariants.test.ts'), true)
  assert.equal(isKernelOrCriticalTestFile('tests/v7-proofreceipt.test.ts'), true)
  assert.equal(isKernelOrCriticalTestFile('tests/arch-b3-cascade.test.ts'), true)
  assert.equal(isKernelOrCriticalTestFile('tests/provider-stream.test.ts'), true)
  assert.equal(isKernelOrCriticalTestFile('tests/v7-dispatch-funnel.test.ts'), true)
  assert.equal(isKernelOrCriticalTestFile('tests/some-ordinary-ui.test.ts'), false)

  assert.equal(isCoreGateInvariantTestFile('tests/v7-dispatch-funnel.test.ts'), true)
  assert.equal(isCoreGateInvariantTestFile('tests/t2-oracle-invariants.test.ts'), false)

  assert.equal(isGenericTriageOwner('v7-triage'), true)
  assert.equal(isGenericTriageOwner('arch-triage'), true)
  assert.equal(isGenericTriageOwner('triage'), true)
  assert.equal(isGenericTriageOwner(''), true)
  assert.equal(isGenericTriageOwner('triage-kernel-oracle-invariants'), false)
  assert.equal(isGenericTriageOwner('r2-12-schema-auth'), false)
})

test('KERNEL_TEST_RE quarantine entries with expires > 14d, missing owner, or generic triage owner fail validation', (t) => {
  const dir = makeTempDir(t, 'r202-kval-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'sample-oracle.test.ts'), 'export {}\n')
  writeFileSync(join(testsDir, 'arch-b3-cascade.test.ts'), 'export {}\n')

  const badQ = join(dir, 'QUARANTINE.bad.json')
  writeFileSync(badQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 4,
    entries: [
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'too long expiry',
        ownerStream: 'triage-kernel-sample-oracle',
        reason: 'drift',
        expires: '2026-12-20',
      },
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'generic owner bucket',
        ownerStream: 'v7-triage',
        reason: 'drift',
        expires: '2026-12-10',
      },
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'missing owner',
        ownerStream: '',
        reason: 'drift',
        expires: '2026-12-10',
      },
      {
        file: 'tests/arch-b3-cascade.test.ts',
        testName: 'schema authority long expiry',
        ownerStream: 'arch-triage',
        reason: 'drift',
        expires: '2026-12-26',
      },
    ],
  }))

  const badRes = runFastRunner(['--check-only', '--tests-dir', testsDir, '--quarantine', badQ, '--now', '2026-11-26'])
  assert.notEqual(badRes.status, 0, 'invalid kernel/critical entries must fail')
  const errs = (badRes.parsed?.errors as string[]) ?? []
  assert.ok(errs.some(e => e.includes('sample-oracle.test.ts') && e.includes('max 14d')), `expected >14d error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('sample-oracle.test.ts') && e.includes('generic triage owner')), `expected generic owner error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('sample-oracle.test.ts') && e.includes("missing required non-empty 'owner'")), `expected missing owner error: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes('arch-b3-cascade.test.ts') && e.includes('max 14d')), `expected schema authority >14d error: ${errs.join('; ')}`)

  const goodQ = join(dir, 'QUARANTINE.good.json')
  writeFileSync(goodQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 2,
    entries: [
      {
        file: 'tests/sample-oracle.test.ts',
        testName: 'scoped kernel case',
        assertionLocation: 'tests/sample-oracle.test.ts:10:1',
        ownerStream: 'triage-kernel-sample-oracle',
        reason: 'tracked in wave 2',
        expires: '2026-12-10',
      },
      {
        file: 'tests/arch-b3-cascade.test.ts',
        testName: 'schema authority',
        ownerStream: 'r2-12-schema-auth',
        reason: 'tracked in R2-12',
        expires: '2026-12-10',
      },
    ],
  }))
  const goodRes = runFastRunner(['--check-only', '--tests-dir', testsDir, '--quarantine', goodQ, '--now', '2026-11-26'])
  assert.equal(goodRes.status, 0, `valid kernel/critical entries should pass: ${goodRes.stdout} ${goodRes.stderr}`)
  assert.equal(goodRes.parsed?.ok, true)
  assert.equal(goodRes.parsed?.kernelQuarantinedCases, 2)
})

// ============================================================================
// 2. Per-case execution: unlisted failure fails, stale 2x pass fails
// ============================================================================

test('deliberately injected unlisted failure inside a file with a quarantined case FAILS the runner', (t) => {
  const dir = makeTempDir(t, 'r202-unlisted-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  const testFile = join(testsDir, 'mixed-oracle.test.ts')
  writeFileSync(testFile, [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('known quarantined failure', () => { assert.equal(1, 2) })",
    "test('gated passing assertion', () => { assert.equal(2, 2) })",
    "test('deliberately injected new failure', () => { assert.equal('actual', 'expected') })",
  ].join('\n') + '\n')

  const qPath = join(dir, 'QUARANTINE.json')
  writeFileSync(qPath, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 1,
    entries: [
      {
        file: 'tests/mixed-oracle.test.ts',
        testName: 'known quarantined failure',
        ownerStream: 'triage-kernel-mixed-oracle',
        reason: 'tracked',
        expires: '2026-12-10',
      },
    ],
  }))

  const failRes = runFastRunner(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26'])
  assert.notEqual(failRes.status, 0, 'unlisted failure inside quarantined file must FAIL runner')
  assert.equal(failRes.parsed?.ok, false)
  const failedFiles = (failRes.parsed?.failedFiles as Array<{ file: string; quarantinedFail: number; unlistedFailures: Array<{ name: string }> }>) ?? []
  assert.equal(failedFiles.length, 1)
  assert.equal(failedFiles[0]!.file, 'tests/mixed-oracle.test.ts')
  assert.equal(failedFiles[0]!.quarantinedFail, 1)
  assert.deepEqual(
    failedFiles[0]!.unlistedFailures.map(f => f.name),
    ['deliberately injected new failure'],
  )

  // Once the unlisted failure is fixed, the same file passes while still executing the gated passing case!
  writeFileSync(testFile, [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('known quarantined failure', () => { assert.equal(1, 2) })",
    "test('gated passing assertion', () => { assert.equal(2, 2) })",
  ].join('\n') + '\n')
  const passRes = runFastRunner(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26'])
  assert.equal(passRes.status, 0, `expected PASS once unlisted failure fixed: ${passRes.stdout} ${passRes.stderr}`)
  assert.equal(passRes.parsed?.ok, true)
  assert.equal(passRes.parsed?.totalPass, 1)
  assert.equal(passRes.parsed?.totalQuarantinedFail, 1)
})

test('quarantined case passing 2x in a row triggers stale-entry failure without editing QUARANTINE.json; flaky case stays quarantined', (t) => {
  const dir = makeTempDir(t, 'r202-stale-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  const counterFile = join(dir, 'flake-counter.txt')

  writeFileSync(join(testsDir, 'fixed-case.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('now passing case', () => { assert.ok(true) })",
    "test('still failing case', () => { assert.equal(1, 2) })",
  ].join('\n') + '\n')

  const qPath = join(dir, 'QUARANTINE.json')
  const qContent = JSON.stringify({
    version: 2,
    maxQuarantinedCases: 2,
    entries: [
      {
        file: 'tests/fixed-case.test.ts',
        testName: 'now passing case',
        ownerStream: 'team-x',
        reason: 'used to fail',
        expires: '2026-12-26',
      },
      {
        file: 'tests/fixed-case.test.ts',
        testName: 'still failing case',
        ownerStream: 'team-x',
        reason: 'still fails',
        expires: '2026-12-26',
      },
    ],
  }, null, 2)
  writeFileSync(qPath, qContent)

  const staleRes = runFastRunner(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26'])
  assert.notEqual(staleRes.status, 0, 'quarantined case passing 2x must fail with stale-entry error')
  assert.equal(staleRes.parsed?.ok, false)
  const staleEntries = (staleRes.parsed?.staleEntries as Array<{ testName: string; kind: string; message: string }>) ?? []
  assert.equal(staleEntries.length, 1)
  assert.equal(staleEntries[0]!.testName, 'now passing case')
  assert.equal(staleEntries[0]!.kind, 'passed_2x')
  assert.ok(staleEntries[0]!.message.includes('stale quarantine entry — remove'))
  assert.equal(readFileSync(qPath, 'utf8'), qContent, 'runner must NEVER silently edit QUARANTINE.json')

  // Verify 2nd-pass nondeterminism guard: passes run 1, fails run 2 => NOT flagged as stale.
  const flakyDir = makeTempDir(t, 'r202-flaky-')
  const flakyTestsDir = join(flakyDir, 'tests')
  mkdirSync(flakyTestsDir, { recursive: true })
  writeFileSync(join(flakyTestsDir, 'flaky.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { existsSync, readFileSync, writeFileSync } from 'node:fs'",
    "import { test } from 'node:test'",
    `const counterPath = ${JSON.stringify(counterFile)}`,
    "test('flaky case', () => {",
    "  const n = existsSync(counterPath) ? Number(readFileSync(counterPath, 'utf8')) : 0",
    "  writeFileSync(counterPath, String(n + 1))",
    '  assert.equal(n % 2, 0, "fails on second run")',
    '})',
  ].join('\n') + '\n')
  const flakyQ = join(flakyDir, 'QUARANTINE.json')
  writeFileSync(flakyQ, JSON.stringify({
    version: 2,
    maxQuarantinedCases: 1,
    entries: [
      {
        file: 'tests/flaky.test.ts',
        testName: 'flaky case',
        ownerStream: 'team-x',
        reason: 'nondeterministic',
        expires: '2026-12-26',
      },
    ],
  }))

  const flakyRes = runFastRunner(['--tests-dir', flakyTestsDir, '--quarantine', flakyQ, '--now', '2026-11-26'])
  assert.equal(flakyRes.status, 0, `flaky case failing 2nd verification pass should stay quarantined: ${flakyRes.stdout}`)
  assert.equal(flakyRes.parsed?.ok, true)
  assert.deepEqual(flakyRes.parsed?.staleEntries, [])
  assert.equal(((flakyRes.parsed?.flakyQuarantined as unknown[]) ?? []).length, 1)
})

// ============================================================================
// 3. Hermetic env + production Node flags (scripts/runtime-profile.ts)
// ============================================================================

test('buildHermeticTestEnv strips ambient KOVO_*/OPENROUTER_*/proxy leaks and injects hardened Node flags', (t) => {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')) as {
    scripts: Record<string, string>
  }
  assert.deepEqual(PRODUCTION_NODE_FLAGS, [
    '--disable-proto=delete',
    '--enable-experimental-regexp-engine-on-excessive-backtracks',
    '--regexp-backtracks-before-fallback=10000',
  ])
  for (const flag of PRODUCTION_NODE_FLAGS) {
    assert.ok(pkg.scripts.start?.includes(flag), `package.json start missing ${flag}`)
    assert.ok(pkg.scripts.scan?.includes(flag), `package.json scan missing ${flag}`)
  }

  const fakeTmp = join(tmpdir(), 'r202-herm-unit')
  const env = buildHermeticTestEnv(fakeTmp, {
    baseEnv: {
      PATH: '/usr/bin:/bin',
      HOME: '/home/tester',
      KOVO_DATA_DIR: '/home/tester/prod-data',
      KOVO_ALLOW_LOCAL_LAB: '1',
      KOVO_RB_HELDOUT_SALT: 'deadbeef',
      OPENROUTER_API_KEY: 'sk-secret',
      HTTP_PROXY: 'http://127.0.0.1:8888',
      HTTPS_PROXY: 'http://127.0.0.1:8888',
      http_proxy: 'http://127.0.0.1:8888',
      NO_PROXY: '*',
      NODE_OPTIONS: '--inspect',
      GH_TOKEN: 'ghp_secret',
    },
  })

  assert.equal(env.PATH, '/usr/bin:/bin')
  assert.equal(env.HOME, '/home/tester')
  assert.equal(env.KOVO_DATA_DIR, join(resolve(fakeTmp), 'd'))
  assert.equal(env.TMPDIR, join(resolve(fakeTmp), 't'))
  assert.equal(env.KOVO_ALLOW_LOCAL_LAB, undefined)
  assert.equal(env.KOVO_RB_HELDOUT_SALT, undefined)
  assert.equal(env.OPENROUTER_API_KEY, undefined)
  assert.equal(env.HTTP_PROXY, undefined)
  assert.equal(env.HTTPS_PROXY, undefined)
  assert.equal(env.http_proxy, undefined)
  assert.equal(env.NO_PROXY, undefined)
  assert.equal(env.GH_TOKEN, undefined)
  assert.equal(env.NODE_OPTIONS, '--max-old-space-size=2048')

  const args = buildHermeticNodeTestArgs('tests/foo.test.ts')
  for (const flag of PRODUCTION_NODE_FLAGS) {
    assert.ok(args.includes(flag), `node test args missing ${flag}`)
  }
  assert.ok(args.includes('--test-reporter=tap'))

  // End-to-end verification: child process run by run-fast-tests.sh has --disable-proto=delete
  // active and receives ZERO leaked KOVO_*/OPENROUTER_*/proxy ambient env vars.
  const dir = makeTempDir(t, 'r202-env-e2e-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'hermetic-probe.test.ts'), [
    "import assert from 'node:assert/strict'",
    "import { test } from 'node:test'",
    "test('child runs with hardened flags and isolated env', () => {",
    "  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, '__proto__'), undefined, '--disable-proto=delete must be active')",
    "  assert.ok(process.execArgv.includes('--enable-experimental-regexp-engine-on-excessive-backtracks'))",
    "  assert.ok(process.execArgv.includes('--regexp-backtracks-before-fallback=10000'))",
    "  assert.equal(process.env.KOVO_LEAK_SENTINEL, undefined)",
    "  assert.equal(process.env.OPENROUTER_LEAK_SENTINEL, undefined)",
    "  assert.equal(process.env.HTTP_PROXY, undefined)",
    "  assert.ok(process.env.KOVO_DATA_DIR && process.env.KOVO_DATA_DIR !== '/should/not/leak')",
    '})',
  ].join('\n') + '\n')

  const res = runFastRunner(['--tests-dir', testsDir], {
    KOVO_LEAK_SENTINEL: 'leaked',
    OPENROUTER_LEAK_SENTINEL: 'leaked',
    HTTP_PROXY: 'http://127.0.0.1:9999',
    KOVO_DATA_DIR: '/should/not/leak',
  })
  assert.equal(res.status, 0, `hermetic e2e child failed: ${res.stdout} ${res.stderr}`)
  assert.equal(res.parsed?.ok, true)
})

test('parseTapOutput extracts nested leaf cases, skips suite rollups, and normalizes repo-relative locations', () => {
  const sampleTap = [
    'TAP version 13',
    '# Subtest: parent suite',
    '    # Subtest: leaf ok',
    '    ok 1 - leaf ok',
    '      ---',
    '      duration_ms: 1.0',
    "      type: 'test'",
    '      ...',
    '    # Subtest: leaf fail',
    '    not ok 2 - leaf fail',
    '      ---',
    '      duration_ms: 2.0',
    "      type: 'test'",
    "      location: '/repo/tests/foo.test.ts:42:3'",
    "      failureType: 'testCodeFailure'",
    "      error: 'boom'",
    '      ...',
    '    1..2',
    'not ok 1 - parent suite',
    '  ---',
    "  type: 'suite'",
    "  failureType: 'subtestsFailed'",
    '  ...',
    '# Subtest: skipped test',
    'ok 2 - skipped test # SKIP not applicable',
    '1..2',
    '# tests 3',
    '# pass 1',
    '# fail 1',
    '# skipped 1',
  ].join('\n')

  const parsed = parseTapOutput(sampleTap, '/repo')
  assert.equal(parsed.cases.length, 3)
  assert.deepEqual(
    parsed.cases.map(c => ({ name: c.name, status: c.status, location: c.location })),
    [
      { name: 'parent suite > leaf ok', status: 'pass', location: '' },
      { name: 'parent suite > leaf fail', status: 'fail', location: 'tests/foo.test.ts:42:3' },
      { name: 'skipped test', status: 'skipped', location: '' },
    ],
  )
})
