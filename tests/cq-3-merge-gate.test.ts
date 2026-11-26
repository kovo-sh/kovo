/**
 * cq-3-merge-gate regression tests (plans/claude_quality.md #3).
 *
 * Covers:
 *  1. QUARANTINE.json schema, hard cap (`entries.length <= maxQuarantined`), expiry,
 *     duplicate/stale detection, and unquarantinable core gate suites.
 *  2. Recursive orphan-test detection in `scripts/run-fast-tests.sh --check-only`.
 *  3. `scripts/check-contract-change.ts` trailer enforcement on tunable constants
 *     (`*_DEFAULT`, `*_BUDGET`, `*_MS`) and gate/kernel `assert.*` numeric literals,
 *     including real temp git repos (warn-only dirty tree vs strict committed merge).
 *  4. `scripts/regression-floor.sh` fail-closed missing-baseline check.
 *  5. `tests/v7-dispatch-funnel.test.ts` migration off `planRoundRobinDispatch` onto `FrontierDispatcher`.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  checkGitRepo,
  detectContractChanges,
  evaluateContractChange,
  extractCodeNumericLiterals,
  hasContractChangeTrailer,
  isGateOrKernelTestFile,
  isTunableSourceFile,
} from '../scripts/check-contract-change.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const RUN_FAST_TESTS_SH = join(REPO_ROOT, 'scripts/run-fast-tests.sh')
const REGRESSION_FLOOR_SH = join(REPO_ROOT, 'scripts/regression-floor.sh')
const CHECK_CONTRACT_TS = join(REPO_ROOT, 'scripts/check-contract-change.ts')

function runFastCheck(args: string[]) {
  const res = spawnSync('bash', [RUN_FAST_TESTS_SH, '--check-only', '--json', ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
  let parsed: Record<string, unknown> | null = null
  try {
    parsed = JSON.parse(res.stdout)
  } catch {
    parsed = null
  }
  return { status: res.status ?? 1, stdout: res.stdout, stderr: res.stderr, parsed }
}

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

// ============================================================================
// 1. QUARANTINE.json validation & orphan-test detection
// ============================================================================

test('checked-in tests/QUARANTINE.json passes schema, cap, expiry, and 0-orphan check', () => {
  const res = runFastCheck(['--quarantine', 'tests/QUARANTINE.json'])
  assert.equal(res.status, 0, `expected exit 0, stderr=${res.stderr}, stdout=${res.stdout}`)
  assert.ok(res.parsed, 'expected JSON output')
  assert.equal(res.parsed.ok, true)
  assert.deepEqual(res.parsed.orphans, [])
  assert.ok(Number(res.parsed.discovered) > 300, 'must discover full test suite')
  assert.ok(Number(res.parsed.fast) > 200, 'must execute >200 fast suites')
  assert.ok(
    Number(res.parsed.quarantined) <= Number(res.parsed.maxQuarantined),
    'quarantined entries must not exceed maxQuarantined',
  )
})

test('QUARANTINE.json rejects cap overflow (entries.length > maxQuarantined)', (t) => {
  const dir = makeTempDir(t, 'cq3-qcap-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'a.test.ts'), 'export {}\n')
  writeFileSync(join(testsDir, 'b.test.ts'), 'export {}\n')
  const qPath = join(dir, 'QUARANTINE.json')
  writeFileSync(qPath, JSON.stringify({
    maxQuarantined: 1,
    entries: [
      { file: 'tests/a.test.ts', owner: 'team-a', reason: 'known issue 1', expires: '2026-12-31' },
      { file: 'tests/b.test.ts', owner: 'team-b', reason: 'known issue 2', expires: '2026-12-31' },
    ],
  }))

  const res = runFastCheck(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26'])
  assert.notEqual(res.status, 0, 'cap overflow must fail')
  assert.equal(res.parsed?.ok, false)
  const errs = (res.parsed?.errors as string[]) ?? []
  assert.ok(errs.some(e => e.includes('quarantine cap exceeded')), `expected cap error, got: ${errs.join('; ')}`)
})

test('QUARANTINE.json rejects expired entries and missing owner/reason fields', (t) => {
  const dir = makeTempDir(t, 'cq3-qexp-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'expired.test.ts'), 'export {}\n')
  writeFileSync(join(testsDir, 'no-owner.test.ts'), 'export {}\n')
  const qPath = join(dir, 'QUARANTINE.json')
  writeFileSync(qPath, JSON.stringify({
    maxQuarantined: 5,
    entries: [
      { file: 'tests/expired.test.ts', owner: 'team-a', reason: 'old failure', expires: '2026-11-01' },
      { file: 'tests/no-owner.test.ts', owner: '', reason: '', expires: '2026-12-31' },
    ],
  }))

  const res = runFastCheck(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26'])
  assert.notEqual(res.status, 0, 'expired / malformed entries must fail')
  const errs = (res.parsed?.errors as string[]) ?? []
  assert.ok(errs.some(e => e.includes('expired quarantine entry')), `expected expiry error, got: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes("missing required non-empty 'owner'")), `expected owner error, got: ${errs.join('; ')}`)
  assert.ok(errs.some(e => e.includes("missing required non-empty 'reason'")), `expected reason error, got: ${errs.join('; ')}`)
})

test('QUARANTINE.json forbids quarantining core gate invariant suites', (t) => {
  const dir = makeTempDir(t, 'cq3-qcore-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'v7-dispatch-funnel.test.ts'), 'export {}\n')
  const qPath = join(dir, 'QUARANTINE.json')
  writeFileSync(qPath, JSON.stringify({
    maxQuarantined: 2,
    entries: [
      { file: 'tests/v7-dispatch-funnel.test.ts', owner: 'someone', reason: 'trying to bypass', expires: '2026-12-31' },
    ],
  }))

  const res = runFastCheck(['--tests-dir', testsDir, '--quarantine', qPath, '--now', '2026-11-26'])
  assert.notEqual(res.status, 0)
  const errs = (res.parsed?.errors as string[]) ?? []
  assert.ok(errs.some(e => e.includes('core gate invariant suite') && e.includes('cannot be quarantined')))
})

test('orphan-test check fails when nested *.test.ts is neither fast-run nor categorized', (t) => {
  const dir = makeTempDir(t, 'cq3-orphan-')
  const testsDir = join(dir, 'tests')
  mkdirSync(join(testsDir, 'nested'), { recursive: true })
  writeFileSync(join(testsDir, 'ok.test.ts'), 'export {}\n')
  writeFileSync(join(testsDir, 'nested', 'forgotten.test.ts'), 'export {}\n')

  const res = runFastCheck(['--tests-dir', testsDir])
  assert.notEqual(res.status, 0, 'orphan nested test must fail')
  assert.deepEqual(res.parsed?.orphans, ['tests/nested/forgotten.test.ts'])
  const errs = (res.parsed?.errors as string[]) ?? []
  assert.ok(errs.some(e => e.includes('Orphan test file(s)') && e.includes('tests/nested/forgotten.test.ts')))
})

test('orphan-test check passes when all tests/*.test.ts are top-level or categorized', (t) => {
  const dir = makeTempDir(t, 'cq3-no-orphan-')
  const testsDir = join(dir, 'tests')
  mkdirSync(testsDir, { recursive: true })
  writeFileSync(join(testsDir, 'a.test.ts'), 'export {}\n')
  writeFileSync(join(testsDir, 'b.test.ts'), 'export {}\n')

  const res = runFastCheck(['--tests-dir', testsDir])
  assert.equal(res.status, 0, res.stderr)
  assert.equal(res.parsed?.ok, true)
  assert.equal(res.parsed?.fast, 2)
  assert.deepEqual(res.parsed?.orphans, [])
})

// ============================================================================
// 2. check-contract-change.ts unit & git integration tests
// ============================================================================

test('file classifiers identify tunable sources and gate/kernel test suites', () => {
  assert.equal(isTunableSourceFile('src/server/run-actor.ts'), true)
  assert.equal(isTunableSourceFile('scripts/benchmark-core.ts'), true)
  assert.equal(isTunableSourceFile('src/server/foo.test.ts'), false)
  assert.equal(isTunableSourceFile('tests/v4-m7-orch.test.ts'), false)

  assert.equal(isGateOrKernelTestFile('tests/v4-m7-orch.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/v7-dispatch-funnel.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/t2-receipt-kernel.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/t2-oracle-invariants.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/v7-confirm-consistency.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/some-unrelated-ui.test.ts'), false)
})

test('extractCodeNumericLiterals ignores string messages and normalizes underscore separators', () => {
  assert.deepEqual(extractCodeNumericLiterals("assert.equal(cap, 72_000, 'was 168_000 before')"), ['72000'])
  assert.deepEqual(extractCodeNumericLiterals('assert.ok(ms <= 1500) // old 2000'), ['1500'])
})

test('detectContractChanges flags tunable *_DEFAULT/*_BUDGET/*_MS edits and gate assert literal edits', () => {
  const diff = [
    'diff --git a/scripts/benchmark-core.ts b/scripts/benchmark-core.ts',
    '--- a/scripts/benchmark-core.ts',
    '+++ b/scripts/benchmark-core.ts',
    '@@ -10,3 +10,3 @@',
    '-export const BENCH_MAX_REQUESTS_DEFAULT = 3800',
    '+export const BENCH_MAX_REQUESTS_DEFAULT = 6000',
    'diff --git a/src/server/run-actor.ts b/src/server/run-actor.ts',
    '--- a/src/server/run-actor.ts',
    '+++ b/src/server/run-actor.ts',
    '@@ -810,3 +810,3 @@',
    '-export const PHASE_A_FLOOR_MAX_WALL_CLOCK_MS = 168_000',
    '+export const PHASE_A_FLOOR_MAX_WALL_CLOCK_MS = 72_000',
    'diff --git a/tests/v4-m7-orch.test.ts b/tests/v4-m7-orch.test.ts',
    '--- a/tests/v4-m7-orch.test.ts',
    '+++ b/tests/v4-m7-orch.test.ts',
    '@@ -40,3 +40,3 @@',
    '-  assert.equal(cfg.maxRequests, 3800)',
    '+  assert.equal(cfg.maxRequests, 6000)',
  ].join('\n')

  const hits = detectContractChanges(diff)
  assert.equal(hits.length, 3)
  assert.equal(hits[0]!.kind, 'tunable_constant_change')
  assert.equal(hits[0]!.symbol, 'BENCH_MAX_REQUESTS_DEFAULT')
  assert.equal(hits[1]!.kind, 'tunable_constant_change')
  assert.equal(hits[1]!.symbol, 'PHASE_A_FLOOR_MAX_WALL_CLOCK_MS')
  assert.equal(hits[2]!.kind, 'gate_assert_literal_change')
  assert.equal(hits[2]!.file, 'tests/v4-m7-orch.test.ts')

  const rejected = evaluateContractChange({
    diffText: diff,
    commitMessages: 'restore held-out-saas 20/20\n',
    mode: 'strict',
    sourceLabel: 'test',
  })
  assert.equal(rejected.ok, false)
  assert.equal(rejected.trailerPresent, false)

  const accepted = evaluateContractChange({
    diffText: diff,
    commitMessages: 'tune floor cap\n\nContract-change: A/B ledger row #42 shows +3pp recall with 6000 req budget\n',
    mode: 'strict',
    sourceLabel: 'test',
  })
  assert.equal(accepted.ok, true)
  assert.equal(accepted.trailerPresent, true)
})

test('detectContractChanges ignores pure formatting, message-only edits, and newly added tests/constants', () => {
  const benignDiff = [
    'diff --git a/src/server/exec-dispatch.ts b/src/server/exec-dispatch.ts',
    '--- a/src/server/exec-dispatch.ts',
    '+++ b/src/server/exec-dispatch.ts',
    '@@ -267,3 +267,4 @@',
    '-export const DEFAULT_FLOOR_REQUEST_BUDGET = 6000',
    '+export const DEFAULT_FLOOR_REQUEST_BUDGET = 6_000',
    '+export const BRAND_NEW_FEATURE_MS = 12_000',
    'diff --git a/tests/v7-dispatch-funnel.test.ts b/tests/v7-dispatch-funnel.test.ts',
    '--- a/tests/v7-dispatch-funnel.test.ts',
    '+++ b/tests/v7-dispatch-funnel.test.ts',
    '@@ -80,3 +80,4 @@',
    "-  assert.equal(dispatched.length, 6, 'old text 123')",
    "+  assert.equal(dispatched.length, 6, 'new text 456')",
    '+  assert.equal(extra.length, 99)',
  ].join('\n')

  assert.deepEqual(detectContractChanges(benignDiff), [])
  assert.equal(hasContractChangeTrailer('Contract-change: short').present, false)
  assert.equal(hasContractChangeTrailer('Contract-change: ledger-ref-001 budget update').present, true)
})

test('checkGitRepo warns on uncommitted tunable edits, rejects un-trailered commits, and accepts trailered commits', (t) => {
  const repo = makeTempDir(t, 'cq3-git-')
  const git = (...args: string[]) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
  git('init', '-b', 'main')
  git('config', 'user.email', 'test@example.invalid')
  git('config', 'user.name', 'Test User')

  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'tests'), { recursive: true })
  writeFileSync(join(repo, 'src/server/tunables.ts'), 'export const WORKER_STEP_BUDGET = 100\n')
  writeFileSync(join(repo, 'tests/v4-m7-orch.test.ts'), 'assert.equal(budget, 100)\n')
  git('add', '.')
  git('commit', '-m', 'initial commit')

  // Uncommitted edit: default warn-only passes, --strict-uncommitted fails.
  writeFileSync(join(repo, 'src/server/tunables.ts'), 'export const WORKER_STEP_BUDGET = 250\n')
  const warnRes = checkGitRepo({ rootDir: repo, strictUncommitted: false })
  assert.equal(warnRes.ok, true)
  assert.equal(warnRes.uncommitted?.warned, true)
  assert.equal(warnRes.uncommitted?.hits.length, 1)

  const strictDirtyRes = checkGitRepo({ rootDir: repo, strictUncommitted: true })
  assert.equal(strictDirtyRes.ok, false)

  // Commit WITHOUT Contract-change trailer -> strict failure on HEAD~1..HEAD.
  git('add', 'src/server/tunables.ts')
  git('commit', '-m', 'bump budget silently')
  const badCommitRes = checkGitRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(badCommitRes.ok, false)
  assert.equal(badCommitRes.committed.hits.length, 1)

  // CLI exit code check on bad commit.
  const cliFail = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(cliFail.status, 1)
  assert.ok(cliFail.stderr.includes('Contract-change:'))

  // Amend commit WITH Contract-change trailer -> PASS!
  git('commit', '--amend', '-m', 'bump budget\n\nContract-change: A/B ledger row #99 validated 250 step budget')
  const goodCommitRes = checkGitRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(goodCommitRes.ok, true)
  assert.equal(goodCommitRes.committed.trailerPresent, true)

  const cliPass = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(cliPass.status, 0, cliPass.stderr)
})

// ============================================================================
// 3. regression-floor.sh & v7-dispatch-funnel.test.ts contracts
// ============================================================================

test('scripts/regression-floor.sh exposes help and fails closed when baseline JSON is missing', (t) => {
  const helpRes = spawnSync('bash', [REGRESSION_FLOOR_SH, '--help'], { cwd: REPO_ROOT, encoding: 'utf8' })
  assert.equal(helpRes.status, 0)
  assert.ok(helpRes.stdout.includes('--with-xben'))
  assert.ok(helpRes.stdout.includes('--with-heldout-saas'))

  const missingDir = makeTempDir(t, 'cq3-floor-')
  const missingBaseline = join(missingDir, 'does-not-exist.json')
  const failRes = spawnSync(
    'bash',
    [REGRESSION_FLOOR_SH, '--skip-golden', '--skip-boundaries', '--with-xben', '--baseline', missingBaseline],
    { cwd: REPO_ROOT, encoding: 'utf8' },
  )
  assert.notEqual(failRes.status, 0, 'missing baseline must fail closed')
  assert.ok(failRes.stderr.includes('baseline JSON not found'))
})

test('tests/v7-dispatch-funnel.test.ts uses FrontierDispatcher and does not call planRoundRobinDispatch', () => {
  const src = readFileSync(join(REPO_ROOT, 'tests/v7-dispatch-funnel.test.ts'), 'utf8')
  assert.ok(src.includes('FrontierDispatcher'), 'v7-dispatch-funnel must exercise FrontierDispatcher')
  assert.ok(src.includes('FrontierWaveController'), 'v7-dispatch-funnel must instantiate FrontierWaveController')
  assert.equal(src.includes('planRoundRobinDispatch'), false, 'v7-dispatch-funnel must not reference dead planRoundRobinDispatch')
})
