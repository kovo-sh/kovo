/**
 * R2-03 regression tests (`plans/claude_quality_2.md` §3):
 *  1. Merged-tree merge queue (`scripts/merge-stream.sh`) on temp git repos:
 *     passing branch fast-forwards `main` cleanly, failing branch leaves `main` untouched,
 *     `--dry-run` validates without moving `main`, red-main lock blocks merges until
 *     `--clear-red-lock` verifies green, and tests-only branches still run the merged-tree gate.
 *  2. Monotone reachability-aware `scripts/check-unwired.ts`:
 *     own-module-only noise filtering (`usedInternallyInModule: true`), prune-fail on
 *     `resolvedBaselineExports > 0`, stale `keepUnwired` detection, removal-only
 *     `--write-baseline` refusal on additions, and `--allow-add-with-ticket` metadata validation.
 *  3. Widened `scripts/check-contract-change.ts`:
 *     `defaultMaxRpsPerOrigin` in `src/domain.ts`, `*_CAP`/`*_MAX_*`/`*_IN_FLIGHT`/`*_RPS`/`*_LIMIT`,
 *     `tests/r2-*`/`tests/r3-*`/`tests/*security*` assert literal protection, per-ID trailer
 *     enforcement, and graceful `--base` / merge-base resolution (including CI all-zero SHA).
 *  4. Fast-tier CI wiring (`.github/workflows/verify.yml`) and Option 2 fast `<60s` gate guard
 *     in `scripts/worker-gate.sh`.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  checkGitRepo,
  detectContractChanges,
  evaluateContractChange,
  isGateOrKernelTestFile,
  isTunableSourceFile,
  resolveCommitBaseRef,
} from '../scripts/check-contract-change.ts'
import {
  runUnwiredCheck,
  updateBaselineMonotone,
  type UnwiredBaseline,
} from '../scripts/check-unwired.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const MERGE_STREAM_SH = join(REPO_ROOT, 'scripts/merge-stream.sh')
const CHECK_UNWIRED_TS = join(REPO_ROOT, 'scripts/check-unwired.ts')
const CHECK_CONTRACT_TS = join(REPO_ROOT, 'scripts/check-contract-change.ts')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function initTempGitRepo(t: { after: (fn: () => void) => void }, prefix: string): {
  repo: string
  git: (...args: string[]) => string
} {
  const repo = makeTempDir(t, prefix)
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '-b', 'main')
  git('config', 'user.email', 'r203-test@example.invalid')
  git('config', 'user.name', 'R203 Tester')
  return { repo, git }
}

// ============================================================================
// 1. scripts/merge-stream.sh E2E tests on temp git repo
// ============================================================================

test('merge-stream.sh fast-forwards passing branch, blocks failing branch without touching main, and supports --dry-run', (t) => {
  const { repo, git } = initTempGitRepo(t, 'r203-merge-')
  const stateDir = makeTempDir(t, 'r203-lock-')

  writeFileSync(join(repo, 'app.txt'), 'ok\n')
  git('add', '.')
  git('commit', '-m', 'initial main')
  const baseSha = git('rev-parse', 'main')

  // Create a passing branch (including a tests-only branch to prove tests-only is still gated).
  git('checkout', '-b', 'feat/pass-tests-only')
  mkdirSync(join(repo, 'tests'), { recursive: true })
  writeFileSync(join(repo, 'tests/only-test.test.ts'), 'export const passMarker = 1\n')
  git('add', '.')
  git('commit', '-m', 'tests-only change')
  const passBranchSha = git('rev-parse', 'HEAD')

  // Create a failing branch that breaks the merged-tree gate.
  git('checkout', '-b', 'feat/fail', 'main')
  writeFileSync(join(repo, 'app.txt'), 'BROKEN\n')
  git('add', '.')
  git('commit', '-m', 'break app')

  // Return to main.
  git('checkout', 'main')

  const gateCmd = 'test "$(cat app.txt)" = "ok" && ! grep -q FAIL_MARKER tests/only-test.test.ts 2>/dev/null'
  const runMerge = (args: string[]) =>
    spawnSync('bash', [MERGE_STREAM_SH, ...args], {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir },
      encoding: 'utf8',
    })

  // 1a. Failing branch: exits non-zero and leaves main untouched at baseSha.
  const failRes = runMerge(['feat/fail', '--base', 'main', '--gate-cmd', gateCmd, '--json'])
  assert.notEqual(failRes.status, 0, 'failing branch must fail merge-stream')
  assert.equal(git('rev-parse', 'main'), baseSha, 'main MUST remain untouched on gate failure')
  assert.equal(git('worktree', 'list', '--porcelain').split('worktree ').length - 1, 1, 'temp worktree must be cleaned up')

  // 1b. Dry-run on passing branch: exits 0, reports PASS_DRY_RUN, leaves main untouched.
  const dryRes = runMerge(['feat/pass-tests-only', '--base', 'main', '--dry-run', '--gate-cmd', gateCmd, '--json'])
  assert.equal(dryRes.status, 0, `dry-run failed: ${dryRes.stderr}`)
  const dryParsed = JSON.parse(dryRes.stdout) as { ok: boolean; status: string; dryRun: boolean }
  assert.equal(dryParsed.ok, true)
  assert.equal(dryParsed.status, 'PASS_DRY_RUN')
  assert.equal(dryParsed.dryRun, true)
  assert.equal(git('rev-parse', 'main'), baseSha, '--dry-run must not advance main')

  // 1c. Real merge of passing branch: fast-forwards main to passBranchSha and cleans temp worktree.
  const passRes = runMerge(['feat/pass-tests-only', '--base', 'main', '--gate-cmd', gateCmd, '--json'])
  assert.equal(passRes.status, 0, `expected merge PASS: ${passRes.stderr}`)
  const passParsed = JSON.parse(passRes.stdout) as { ok: boolean; status: string; newSha: string }
  assert.equal(passParsed.ok, true)
  assert.equal(passParsed.status, 'PASS')
  assert.equal(passParsed.newSha, passBranchSha)
  assert.equal(git('rev-parse', 'main'), passBranchSha, 'main must fast-forward to passing branch SHA')
  assert.ok(existsSync(join(repo, 'tests/only-test.test.ts')), 'checked-out main working tree must reflect fast-forward')
  assert.equal(git('worktree', 'list', '--porcelain').split('worktree ').length - 1, 1, 'temp worktree must be cleaned up')
})

test('merge-stream.sh blocks merges when external red-main lock exists and clears lock only after passing with --clear-red-lock', (t) => {
  const { repo, git } = initTempGitRepo(t, 'r203-redlock-')
  const stateDir = makeTempDir(t, 'r203-redlock-state-')
  const lockPath = join(stateDir, 'main-red.lock')

  writeFileSync(join(repo, 'status.txt'), 'green\n')
  git('add', '.')
  git('commit', '-m', 'initial')
  const baseSha = git('rev-parse', 'main')

  git('checkout', '-b', 'feat/good')
  writeFileSync(join(repo, 'extra.txt'), 'ok\n')
  git('add', '.')
  git('commit', '-m', 'good branch')
  const goodSha = git('rev-parse', 'HEAD')

  git('checkout', 'main')

  const runMerge = (args: string[]) =>
    spawnSync('bash', [MERGE_STREAM_SH, ...args], {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir },
      encoding: 'utf8',
    })

  // Set external red-main lock.
  const setRes = runMerge(['--set-red-lock', 'ci failure on main', '--json'])
  assert.equal(setRes.status, 0, setRes.stderr)
  assert.ok(existsSync(lockPath), 'red-main lock file must exist')

  // Merge WITHOUT --clear-red-lock is refused immediately.
  const blockedRes = runMerge(['feat/good', '--base', 'main', '--gate-cmd', 'true', '--json'])
  assert.notEqual(blockedRes.status, 0, 'red-main lock must block merge')
  const blockedParsed = JSON.parse(blockedRes.stdout) as { ok: boolean; status: string }
  assert.equal(blockedParsed.ok, false)
  assert.equal(blockedParsed.status, 'BLOCKED_RED_MAIN')
  assert.equal(git('rev-parse', 'main'), baseSha)
  assert.ok(existsSync(lockPath), 'lock must remain after blocked merge')

  // Merge WITH --clear-red-lock when gate FAILS must NOT clear the lock or advance main.
  const failClearRes = runMerge(['feat/good', '--base', 'main', '--clear-red-lock', '--gate-cmd', 'false', '--json'])
  assert.notEqual(failClearRes.status, 0)
  assert.equal(git('rev-parse', 'main'), baseSha)
  assert.ok(existsSync(lockPath), 'lock must NOT be cleared if gate fails')

  // Merge WITH --clear-red-lock when gate PASSES advances main AND removes the lock.
  const okClearRes = runMerge(['feat/good', '--base', 'main', '--clear-red-lock', '--gate-cmd', 'true', '--json'])
  assert.equal(okClearRes.status, 0, okClearRes.stderr)
  const okClearParsed = JSON.parse(okClearRes.stdout) as { ok: boolean; redLockCleared: boolean }
  assert.equal(okClearParsed.ok, true)
  assert.equal(okClearParsed.redLockCleared, true)
  assert.equal(git('rev-parse', 'main'), goodSha)
  assert.equal(existsSync(lockPath), false, 'red-main lock must be removed after green --clear-red-lock merge')
})

// ============================================================================
// 2. Monotone reachability-aware scripts/check-unwired.ts
// ============================================================================

test('check-unwired filters own-module-only noise, prune-fails on resolvedBaselineExports, and flags stale keepUnwired', (t) => {
  const dir = makeTempDir(t, 'r203-unwired-')
  mkdirSync(join(dir, 'src/server'), { recursive: true })
  mkdirSync(join(dir, 'scripts'), { recursive: true })

  // Entrypoint consumes `liveEntry` from `src/server/mod.ts`.
  // `internalHelper` is exported ONLY for visibility/tests and called by `liveEntry` inside `mod.ts`
  // -> own-module noise (MUST be filtered out of `unwiredExports`).
  // `trulyDead` is exported and called by nobody -> real unwired export.
  writeFileSync(join(dir, 'src/server.ts'), "import { liveEntry } from './server/mod.ts'\nconsole.log(liveEntry())\n")
  writeFileSync(
    join(dir, 'src/server/mod.ts'),
    [
      'export function internalHelper(): number { return 42 }',
      'export function liveEntry(): number { return internalHelper() + 1 }',
      'export function trulyDead(): number { return 0 }',
    ].join('\n') + '\n',
  )
  // A completely unreferenced module: even though deadA calls deadB internally, the module has NO
  // production consumer, so BOTH remain unwired.
  writeFileSync(
    join(dir, 'src/server/orphan.ts'),
    [
      'export function deadB(): number { return 1 }',
      'export function deadA(): number { return deadB() }',
    ].join('\n') + '\n',
  )

  const baselinePath = join(dir, 'scripts/unwired-baseline.json')
  const writeBase = (b: UnwiredBaseline) => writeFileSync(baselinePath, `${JSON.stringify(b, null, 2)}\n`)

  // Exact clean baseline: only trulyDead, deadA, deadB are unwired (NOT internalHelper!).
  writeBase({
    version: 1,
    allowedCycles: [],
    keepUnwired: [],
    baselinedExports: [
      'src/server/mod.ts::trulyDead',
      'src/server/orphan.ts::deadA',
      'src/server/orphan.ts::deadB',
    ],
  })

  const clean = runUnwiredCheck({ rootDir: dir, baselinePath, now: '2026-11-26' })
  assert.equal(clean.ok, true, `expected clean PASS: ${JSON.stringify(clean)}`)
  assert.equal(clean.ownModuleOnlyExportCount, 1, 'internalHelper must be counted as ownModuleOnly')
  assert.deepEqual(
    clean.unwiredExports.map(u => u.key),
    ['src/server/mod.ts::trulyDead', 'src/server/orphan.ts::deadA', 'src/server/orphan.ts::deadB'],
  )
  assert.equal(clean.unwiredExports.some(u => u.key.includes('internalHelper')), false)

  // Prune-fail: adding a stale/resolved export (e.g. internalHelper or deleted symbol) MUST FAIL!
  writeBase({
    version: 1,
    allowedCycles: [],
    keepUnwired: [],
    baselinedExports: [
      'src/server/mod.ts::internalHelper',
      'src/server/mod.ts::trulyDead',
      'src/server/orphan.ts::deadA',
      'src/server/orphan.ts::deadB',
    ],
  })
  const staleBaselineRes = runUnwiredCheck({ rootDir: dir, baselinePath, now: '2026-11-26' })
  assert.equal(staleBaselineRes.ok, false, 'resolvedBaselineExports > 0 MUST prune-fail')
  assert.deepEqual(staleBaselineRes.resolvedBaselineExports, ['src/server/mod.ts::internalHelper'])

  // Stale keepUnwired: marking an internally-wired symbol as keep-unwired MUST FAIL!
  writeBase({
    version: 1,
    allowedCycles: [],
    keepUnwired: [
      {
        key: 'src/server/mod.ts::internalHelper',
        disposition: 'keep-unwired',
        ticket: 'OLD-TICKET',
        reason: 'stale keep entry',
      },
    ],
    baselinedExports: [
      'src/server/mod.ts::trulyDead',
      'src/server/orphan.ts::deadA',
      'src/server/orphan.ts::deadB',
    ],
  })
  const staleKeepRes = runUnwiredCheck({ rootDir: dir, baselinePath, now: '2026-11-26' })
  assert.equal(staleKeepRes.ok, false, 'stale keepUnwired wired internally MUST FAIL')
  assert.deepEqual(staleKeepRes.staleKeepUnwired, [
    { key: 'src/server/mod.ts::internalHelper', status: 'wired_internally' },
  ])
})

test('check-unwired --write-baseline is removal-only by default and requires ticket metadata for additions', (t) => {
  const dir = makeTempDir(t, 'r203-monotone-')
  mkdirSync(join(dir, 'src/server'), { recursive: true })
  mkdirSync(join(dir, 'scripts'), { recursive: true })

  writeFileSync(join(dir, 'src/server.ts'), "import { used } from './server/a.ts'\nconsole.log(used())\n")
  writeFileSync(
    join(dir, 'src/server/a.ts'),
    'export function used(): number { return 1 }\nexport function oldDead(): number { return 2 }\nexport function newlyAddedDead(): number { return 3 }\n',
  )

  const baselinePath = join(dir, 'scripts/unwired-baseline.json')
  const initialContent = `${JSON.stringify({
    version: 1,
    allowedCycles: [],
    keepUnwired: [],
    baselinedExports: ['src/server/a.ts::oldDead', 'src/server/a.ts::alreadyDeleted'],
  }, null, 2)}\n`
  writeFileSync(baselinePath, initialContent)

  // 1. Default --write-baseline MUST refuse because `newlyAddedDead` would be added!
  const refusedCli = spawnSync(
    process.execPath,
    [CHECK_UNWIRED_TS, '--root', dir, '--baseline', baselinePath, '--write-baseline', '--now', '2026-11-26'],
    { encoding: 'utf8' },
  )
  assert.notEqual(refusedCli.status, 0, '--write-baseline must refuse additions by default')
  assert.ok(refusedCli.stderr.includes('removal-only'), `expected removal-only error, got: ${refusedCli.stderr}`)
  assert.equal(readFileSync(baselinePath, 'utf8'), initialContent, 'baseline file must remain untouched on refusal')

  // 2. --allow-add-with-ticket WITHOUT valid { owner, ticket, expires } MUST also refuse!
  const missingMeta = updateBaselineMonotone({
    rootDir: dir,
    baselinePath,
    allowAddWithTicket: true,
    defaultTicketMeta: { owner: '', ticket: 'T-1', expires: '2026-12-10' },
    now: '2026-11-26',
  })
  assert.equal(missingMeta.ok, false)
  assert.equal(missingMeta.wrote, false)

  // 3. --allow-add-with-ticket WITH valid { owner, ticket, expires } succeeds, records metadata, and prunes stale entry!
  const addedCli = spawnSync(
    process.execPath,
    [
      CHECK_UNWIRED_TS,
      '--root', dir,
      '--baseline', baselinePath,
      '--write-baseline',
      '--allow-add-with-ticket',
      '--owner', 'r2-03-merge-gate',
      '--ticket', 'R2-03-TEST',
      '--expires', '2026-12-10',
      '--now', '2026-11-26',
    ],
    { encoding: 'utf8' },
  )
  assert.equal(addedCli.status, 0, `expected ticketed add PASS: ${addedCli.stderr}`)
  const updated = JSON.parse(readFileSync(baselinePath, 'utf8')) as UnwiredBaseline
  assert.deepEqual(updated.baselinedExports, ['src/server/a.ts::newlyAddedDead', 'src/server/a.ts::oldDead'])
  assert.deepEqual(updated.ticketedAdditions, [
    {
      key: 'src/server/a.ts::newlyAddedDead',
      owner: 'r2-03-merge-gate',
      ticket: 'R2-03-TEST',
      expires: '2026-12-10',
    },
  ])

  // 4. Removal-only prune succeeds without --allow-add-with-ticket once `newlyAddedDead` is deleted!
  writeFileSync(
    join(dir, 'src/server/a.ts'),
    'export function used(): number { return 1 }\nexport function oldDead(): number { return 2 }\n',
  )
  const pruneCli = spawnSync(
    process.execPath,
    [CHECK_UNWIRED_TS, '--root', dir, '--baseline', baselinePath, '--write-baseline', '--now', '2026-11-26'],
    { encoding: 'utf8' },
  )
  assert.equal(pruneCli.status, 0, `expected removal-only prune PASS: ${pruneCli.stderr}`)
  const pruned = JSON.parse(readFileSync(baselinePath, 'utf8')) as UnwiredBaseline
  assert.deepEqual(pruned.baselinedExports, ['src/server/a.ts::oldDead'])
  assert.equal(pruned.ticketedAdditions, undefined, 'resolved ticketedAddition should be pruned')
})

// ============================================================================
// 3. Widened scripts/check-contract-change.ts
// ============================================================================

test('check-contract-change catches src/domain.ts defaultMaxRpsPerOrigin, widened *_CAP/*_IN_FLIGHT/*_RPS/*_LIMIT, and tests/r2-*/r3-*/*security*', () => {
  assert.equal(isTunableSourceFile('src/domain.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/r2-ws19-graph-dos.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/r3-provider-scrub.test.ts'), true)
  assert.equal(isGateOrKernelTestFile('tests/auth-security-regression.test.ts'), true)

  const diff = [
    'diff --git a/src/domain.ts b/src/domain.ts',
    '--- a/src/domain.ts',
    '+++ b/src/domain.ts',
    '@@ -22,3 +22,3 @@',
    '-export const defaultMaxRpsPerOrigin = 5',
    '+export const defaultMaxRpsPerOrigin = 10',
    'diff --git a/src/server/broker.ts b/src/server/broker.ts',
    '--- a/src/server/broker.ts',
    '+++ b/src/server/broker.ts',
    '@@ -1862,5 +1862,5 @@',
    '-export const EXTERNAL_ORIGIN_MAX_IN_FLIGHT = 4',
    '+export const EXTERNAL_ORIGIN_MAX_IN_FLIGHT = 8',
    '-export const EXTERNAL_ORIGIN_MAX_RPS_CAP = 20',
    '+export const EXTERNAL_ORIGIN_MAX_RPS_CAP = 40',
    '-export const ORIGIN_DEFAULT_RPS = 10',
    '+export const ORIGIN_DEFAULT_RPS = 20',
    '-export const DRY_ROUND_LIMIT = 2',
    '+export const DRY_ROUND_LIMIT = 5',
    'diff --git a/tests/r3-provider-scrub.test.ts b/tests/r3-provider-scrub.test.ts',
    '--- a/tests/r3-provider-scrub.test.ts',
    '+++ b/tests/r3-provider-scrub.test.ts',
    '@@ -50,3 +50,3 @@',
    '-  assert.ok(elapsedMs <= 100)',
    '+  assert.ok(elapsedMs <= 250)',
  ].join('\n')

  const hits = detectContractChanges(diff)
  assert.deepEqual(
    hits.map(h => h.id),
    [
      'defaultMaxRpsPerOrigin',
      'EXTERNAL_ORIGIN_MAX_IN_FLIGHT',
      'EXTERNAL_ORIGIN_MAX_RPS_CAP',
      'ORIGIN_DEFAULT_RPS',
      'DRY_ROUND_LIMIT',
      'tests/r3-provider-scrub.test.ts',
    ],
  )

  // Single generic trailer MUST FAIL under per-ID enforcement!
  const genericFail = evaluateContractChange({
    diffText: diff,
    commitMessages: 'sweep limits\n\nContract-change: raised limits across the board per bench #1\n',
    mode: 'strict',
    sourceLabel: 'test',
    requirePerId: true,
  })
  assert.equal(genericFail.ok, false)
  assert.equal(genericFail.missingTrailerIds.length, 6)

  // Packing two IDs onto ONE Contract-change line MUST STILL FAIL (1 trailer line per ID)!
  const twoOnOneDiff = [
    'diff --git a/src/domain.ts b/src/domain.ts',
    '--- a/src/domain.ts',
    '+++ b/src/domain.ts',
    '@@ -22,3 +22,3 @@',
    '-export const defaultMaxRpsPerOrigin = 5',
    '+export const defaultMaxRpsPerOrigin = 10',
    'diff --git a/tests/r3-provider-scrub.test.ts b/tests/r3-provider-scrub.test.ts',
    '--- a/tests/r3-provider-scrub.test.ts',
    '+++ b/tests/r3-provider-scrub.test.ts',
    '@@ -50,3 +50,3 @@',
    '-  assert.ok(elapsedMs <= 100)',
    '+  assert.ok(elapsedMs <= 250)',
  ].join('\n')

  const packedFail = evaluateContractChange({
    diffText: twoOnOneDiff,
    commitMessages:
      'bump both\n\nContract-change: defaultMaxRpsPerOrigin and tests/r3-provider-scrub.test.ts adjusted together\n',
    mode: 'strict',
    sourceLabel: 'test',
    requirePerId: true,
  })
  assert.equal(packedFail.ok, false, 'one trailer line cannot authorize two changed IDs')
  assert.deepEqual(packedFail.missingTrailerIds, ['tests/r3-provider-scrub.test.ts'])

  // One dedicated Contract-change trailer line per changed ID -> PASS!
  const perIdPass = evaluateContractChange({
    diffText: twoOnOneDiff,
    commitMessages: [
      'bump both intentionally',
      '',
      'Contract-change: defaultMaxRpsPerOrigin raised 5->10 per throughput ledger #7',
      'Contract-change: tests/r3-provider-scrub.test.ts adjusted timing budget after regex engine profile',
    ].join('\n'),
    mode: 'strict',
    sourceLabel: 'test',
    requirePerId: true,
  })
  assert.equal(perIdPass.ok, true)
  assert.deepEqual(perIdPass.missingTrailerIds, [])
})

test('check-contract-change CLI enforces per-ID trailers on multi-ID commits and handles CI all-zero --base gracefully', (t) => {
  const { repo, git } = initTempGitRepo(t, 'r203-contract-git-')
  mkdirSync(join(repo, 'src'), { recursive: true })
  mkdirSync(join(repo, 'tests'), { recursive: true })

  writeFileSync(join(repo, 'src/domain.ts'), 'export const defaultMaxRpsPerOrigin = 5\n')
  writeFileSync(join(repo, 'tests/r3-timing.test.ts'), 'assert.ok(ms <= 100)\n')
  git('add', '.')
  git('commit', '-m', 'init')

  // First commit with all-zero --base resolves cleanly to null (0 parents) without crashing.
  assert.equal(resolveCommitBaseRef(repo, '0000000000000000000000000000000000000000'), null)

  // Edit both domain tunable and r3 test with ONLY one generic trailer -> CLI MUST FAIL!
  writeFileSync(join(repo, 'src/domain.ts'), 'export const defaultMaxRpsPerOrigin = 10\n')
  writeFileSync(join(repo, 'tests/r3-timing.test.ts'), 'assert.ok(ms <= 250)\n')
  git('add', '.')
  git('commit', '-m', 'realign\n\nContract-change: one generic trailer for everything')

  const failCli = spawnSync(
    process.execPath,
    [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'],
    { encoding: 'utf8' },
  )
  assert.equal(failCli.status, 1, 'generic trailer covering 2 IDs must FAIL CLI')
  assert.ok(failCli.stderr.includes('defaultMaxRpsPerOrigin'))
  assert.ok(failCli.stderr.includes('tests/r3-timing.test.ts'))

  // Amend with dedicated per-ID trailers -> PASS (including with CI all-zero --base falling back to HEAD~1!).
  git(
    'commit',
    '--amend',
    '-m',
    [
      'realign with per-id justification',
      '',
      'Contract-change: defaultMaxRpsPerOrigin raised 5->10 per bench #42',
      'Contract-change: tests/r3-timing.test.ts updated ceiling after profiling',
    ].join('\n'),
  )
  const passRes = checkGitRepo({ rootDir: repo, baseRef: 'HEAD~1' })
  assert.equal(passRes.ok, true)

  const zeroBaseCli = spawnSync(
    process.execPath,
    [CHECK_CONTRACT_TS, '--root', repo, '--base', '0000000000000000000000000000000000000000'],
    { encoding: 'utf8' },
  )
  assert.equal(zeroBaseCli.status, 0, `CI zero-SHA --base fallback should pass: ${zeroBaseCli.stderr}`)
})

// ============================================================================
// 4. CI workflow & fast worker-gate wiring invariants
// ============================================================================

test('verify.yml enforces fast tier + ratchets and worker-gate.sh stays strictly fast (<60s, no Playwright/Docker)', () => {
  const verifyYml = readFileSync(join(REPO_ROOT, '.github/workflows/verify.yml'), 'utf8')
  assert.ok(verifyYml.includes('fetch-depth: 0'), 'verify.yml must fetch history for merge-base contract-change lint')
  assert.ok(verifyYml.includes('node scripts/check-unwired.ts'), 'verify.yml must run check-unwired.ts')
  assert.ok(verifyYml.includes('node scripts/check-contract-change.ts --base'), 'verify.yml must run check-contract-change.ts --base')
  assert.ok(
    verifyYml.includes('bash scripts/run-fast-tests.sh --suites-only --quarantine tests/QUARANTINE.json'),
    'verify.yml must run fast hermetic unit suites with quarantine enforcement',
  )

  const workerGate = readFileSync(join(REPO_ROOT, 'scripts/worker-gate.sh'), 'utf8')
  assert.ok(workerGate.includes('node scripts/check-unwired.ts'), 'worker-gate.sh must wire check-unwired.ts')
  assert.ok(workerGate.includes('node scripts/check-contract-change.ts'), 'worker-gate.sh must wire check-contract-change.ts')
  assert.equal(workerGate.includes('qa:ui'), false, 'worker-gate.sh must NEVER run slow Playwright qa:ui')
  assert.equal(workerGate.includes('e2e-ui-journeys'), false, 'worker-gate.sh must NEVER run slow Playwright E2E')
  assert.equal(workerGate.includes('docker-smoke.sh'), false, 'worker-gate.sh must NEVER run slow Docker smoke')
})
