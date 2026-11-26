// @kernel @fixes R3-01
/**
 * R3-01 regression & unit tests (`plans/claude_quality_3.md` §1):
 *  1. `.githooks/reference-transaction` + `scripts/install-main-guard.sh`:
 *     refuses direct `refs/heads/main` updates without a valid `refs/notes/merge-gate` note
 *     matching `merge-gate: PASS <digest> <tree-sha>`, refuses mismatched tree SHAs, permits
 *     non-main branches, permits valid noted fast-forwards, and records an audit event in
 *     `main-guard-overrides.log` when `KOVO_MAIN_GUARD_OVERRIDE=1` is used.
 *  2. `scripts/merge-stream.sh`:
 *     stamps `refs/notes/merge-gate` BEFORE fast-forwarding `main` (passing through the installed
 *     `reference-transaction` hook), auto-sets `main-red.lock` and blocks merges when `gh` reports
 *     `verify.yml` `conclusion: "failure"`, and skips cleanly with an explicit notice when `gh`
 *     is unavailable or `--skip-ci-check` is passed.
 *  3. `scripts/parallel-pulse.sh`:
 *     reports 0 `ACTION NON-QUEUE MERGE` entries for noted `merge-stream.sh` fast-forwards,
 *     emits `ACTION NON-QUEUE MERGE` for non-queue updates on `main` since guard install, and
 *     emits `CI RED` when latest `verify.yml` on `main` failed.
 *  4. `scripts/check-tsc-budget.ts` + `.github/workflows/verify.yml`:
 *     parses `tsc --noEmit --extendedDiagnostics` metrics, enforces memory/time ceilings, fails
 *     closed on missing diagnostics, and verifies CI sets `--max-old-space-size=6144`.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  TSC_BUDGET_BASELINE,
  evaluateTscBudget,
  parseTscDiagnostics,
} from '../scripts/check-tsc-budget.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const HOOK_SRC = join(REPO_ROOT, '.githooks/reference-transaction')
const INSTALL_GUARD_SH = join(REPO_ROOT, 'scripts/install-main-guard.sh')
const MERGE_STREAM_SH = join(REPO_ROOT, 'scripts/merge-stream.sh')
const PARALLEL_PULSE_SH = join(REPO_ROOT, 'scripts/parallel-pulse.sh')
const CHECK_TSC_BUDGET_TS = join(REPO_ROOT, 'scripts/check-tsc-budget.ts')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function initGuardedTempRepo(t: { after: (fn: () => void) => void }, prefix: string): {
  repo: string
  stateDir: string
  git: (...args: string[]) => string
  gitRaw: (args: string[], extraEnv?: Record<string, string>) => ReturnType<typeof spawnSync>
} {
  const repo = makeTempDir(t, prefix)
  const stateDir = makeTempDir(t, `${prefix}state-`)
  const gitRaw = (args: string[], extraEnv: Record<string, string> = {}) =>
    spawnSync('git', args, {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, ...extraEnv },
      encoding: 'utf8',
    })
  const git = (...args: string[]) =>
    execFileSync('git', args, {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim()

  git('init', '-b', 'main')
  git('config', 'user.email', 'r301-test@example.invalid')
  git('config', 'user.name', 'R301 Tester')

  mkdirSync(join(repo, '.githooks'), { recursive: true })
  copyFileSync(HOOK_SRC, join(repo, '.githooks/reference-transaction'))
  writeFileSync(join(repo, 'app.txt'), 'ok\n')
  git('add', '.')
  git('commit', '-m', 'initial main')

  const installRes = spawnSync('bash', [INSTALL_GUARD_SH, '--repo', repo], {
    cwd: repo,
    env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir },
    encoding: 'utf8',
  })
  assert.equal(installRes.status, 0, `install-main-guard.sh failed: ${installRes.stderr}`)
  assert.equal(git('config', '--get', 'core.hooksPath'), '.githooks')
  assert.ok(existsSync(join(stateDir, 'main-guard-installed')))

  return { repo, stateDir, git, gitRaw }
}

function makeFakeGh(dir: string, name: string, payloadJson: string, exitCode = 0): string {
  const shimPath = join(dir, name)
  writeFileSync(
    shimPath,
    `#!/usr/bin/env bash\nprintf '%s\\n' '${payloadJson.replace(/'/g, "'\\''")}'\nexit ${exitCode}\n`,
  )
  chmodSync(shimPath, 0o755)
  return shimPath
}

// ============================================================================
// 1. .githooks/reference-transaction refusal, valid note, mismatched tree, audited override
// ============================================================================

test('R3-01.1: reference-transaction refuses unnoted main updates, rejects wrong tree SHA, permits valid note & audited override', (t) => {
  const { repo, stateDir, git, gitRaw } = initGuardedTempRepo(t, 'r301-hook-')
  const baseSha = git('rev-parse', 'main')

  // 1a. Direct commit on main without note MUST be refused and leave main unchanged.
  writeFileSync(join(repo, 'direct.txt'), 'bypass attempt\n')
  git('add', 'direct.txt')
  const directCommit = gitRaw(['commit', '-m', 'direct commit on main'])
  assert.notEqual(directCommit.status, 0, 'direct commit on guarded main must be refused')
  assert.match(String(directCommit.stderr), /main-guard: REFUSED/)
  assert.equal(git('rev-parse', 'main'), baseSha, 'main SHA must remain untouched after refusal')
  git('reset', '--hard', baseSha)

  // 1b. Commits on a feature branch are NOT blocked by the main guard.
  git('checkout', '-b', 'feat/work')
  writeFileSync(join(repo, 'feature.txt'), 'good\n')
  git('add', 'feature.txt')
  git('commit', '-m', 'feature branch commit')
  const featSha = git('rev-parse', 'HEAD')
  const featTree = git('rev-parse', `${featSha}^{tree}`)

  // 1c. Fast-forward onto main WITHOUT note is refused.
  git('checkout', 'main')
  const unnotedMerge = gitRaw(['merge', '--ff-only', 'feat/work'])
  assert.notEqual(unnotedMerge.status, 0, 'unnoted ff-only merge onto main must be refused')
  assert.equal(git('rev-parse', 'main'), baseSha)

  // 1d. Note with mismatched tree SHA MUST still be refused.
  const wrongTree = 'f'.repeat(40)
  const digest = 'a'.repeat(64)
  git('notes', '--ref=refs/notes/merge-gate', 'add', '-f', '-m', `merge-gate: PASS ${digest} ${wrongTree}`, featSha)
  const wrongTreeMerge = gitRaw(['merge', '--ff-only', 'feat/work'])
  assert.notEqual(wrongTreeMerge.status, 0, 'note with mismatched tree SHA must be refused')
  assert.equal(git('rev-parse', 'main'), baseSha)

  // 1e. Note with valid digest + matching tree SHA ALLOWS updating main.
  git('notes', '--ref=refs/notes/merge-gate', 'add', '-f', '-m', `merge-gate: PASS ${digest} ${featTree}`, featSha)
  const validMerge = gitRaw(['merge', '--ff-only', 'feat/work'])
  assert.equal(validMerge.status, 0, `valid noted merge must succeed: ${validMerge.stderr}`)
  assert.equal(git('rev-parse', 'main'), featSha)

  // 1f. Audited override allows direct commit on main AND appends to main-guard-overrides.log.
  writeFileSync(join(repo, 'hotfix.txt'), 'emergency\n')
  git('add', 'hotfix.txt')
  const overrideRes = gitRaw(
    ['commit', '-m', 'emergency override'],
    { KOVO_MAIN_GUARD_OVERRIDE: '1', KOVO_MAIN_GUARD_OVERRIDE_REASON: 'unit-test-emergency' },
  )
  assert.equal(overrideRes.status, 0, `audited override should succeed: ${overrideRes.stderr}`)
  const newMainSha = git('rev-parse', 'main')
  assert.notEqual(newMainSha, featSha)
  const overrideLog = readFileSync(join(stateDir, 'main-guard-overrides.log'), 'utf8')
  assert.match(overrideLog, /ref=refs\/heads\/main/)
  assert.ok(overrideLog.includes(`old=${featSha}`))
  assert.ok(overrideLog.includes(`new=${newMainSha}`))
  assert.ok(overrideLog.includes('reason=unit-test-emergency'))
})

// ============================================================================
// 2. merge-stream.sh stamps refs/notes/merge-gate & enforces CI status
// ============================================================================

test('R3-01.2: merge-stream.sh stamps valid merge-gate note through guard and auto-locks on red CI', (t) => {
  const { repo, stateDir, git } = initGuardedTempRepo(t, 'r301-queue-')
  const shimDir = makeTempDir(t, 'r301-gh-')
  const baseSha = git('rev-parse', 'main')

  git('checkout', '-b', 'feat/queued')
  writeFileSync(join(repo, 'queued.txt'), 'ok\n')
  git('add', 'queued.txt')
  git('commit', '-m', 'queued change')
  const queuedSha = git('rev-parse', 'HEAD')
  const queuedTree = git('rev-parse', `${queuedSha}^{tree}`)
  git('checkout', 'main')

  // 2a. Red CI from gh auto-creates main-red.lock and blocks merge!
  const redGh = makeFakeGh(shimDir, 'fake-gh-red', '[{"conclusion":"failure","status":"completed","databaseId":45824078785}]')
  const blockedRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/queued', '--base', 'main', '--gate-cmd', 'true', '--json'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_GH_BIN: redGh },
      encoding: 'utf8',
    },
  )
  assert.notEqual(blockedRes.status, 0, 'red CI must block merge-stream.sh')
  const blockedJson = JSON.parse(blockedRes.stdout) as { ok: boolean; status: string }
  assert.equal(blockedJson.ok, false)
  assert.equal(blockedJson.status, 'BLOCKED_RED_MAIN')
  assert.equal(git('rev-parse', 'main'), baseSha)
  const lockText = readFileSync(join(stateDir, 'main-red.lock'), 'utf8')
  assert.match(lockText, /45824078785/)
  assert.match(lockText, /source=ci_check/)

  // 2b. --clear-red-lock passes gate, stamps refs/notes/merge-gate BEFORE ff, and satisfies reference-transaction hook!
  const clearRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/queued', '--base', 'main', '--clear-red-lock', '--gate-cmd', 'true', '--json'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_GH_BIN: redGh },
      encoding: 'utf8',
    },
  )
  assert.equal(clearRes.status, 0, `merge-stream.sh --clear-red-lock failed: ${clearRes.stderr}`)
  const clearJson = JSON.parse(clearRes.stdout) as { ok: boolean; status: string; newSha: string; redLockCleared: boolean }
  assert.equal(clearJson.ok, true)
  assert.equal(clearJson.status, 'PASS')
  assert.equal(clearJson.newSha, queuedSha)
  assert.equal(clearJson.redLockCleared, true)
  assert.equal(git('rev-parse', 'main'), queuedSha)
  assert.equal(existsSync(join(stateDir, 'main-red.lock')), false)

  const note = git('notes', '--ref=refs/notes/merge-gate', 'show', queuedSha)
  assert.match(note, new RegExp(`^merge-gate: PASS [a-f0-9]{64} ${queuedTree}$`))

  // 2c. Unavailable gh skips cleanly with explicit notice (and --skip-ci-check skips silently).
  git('checkout', '-b', 'feat/offline')
  writeFileSync(join(repo, 'offline.txt'), 'ok\n')
  git('add', 'offline.txt')
  git('commit', '-m', 'offline change')
  const offlineSha = git('rev-parse', 'HEAD')
  git('checkout', 'main')

  const offlineRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/offline', '--base', 'main', '--gate-cmd', 'true'],
    {
      cwd: repo,
      env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_GH_BIN: '/nonexistent/gh-missing' },
      encoding: 'utf8',
    },
  )
  assert.equal(offlineRes.status, 0, `offline merge-stream failed: ${offlineRes.stderr}`)
  assert.match(offlineRes.stderr, /skipping CI check/)
  assert.equal(git('rev-parse', 'main'), offlineSha)
})

// ============================================================================
// 3. parallel-pulse.sh non-queue merge detection and CI RED alerting
// ============================================================================

test('R3-01.3: parallel-pulse.sh passes on merge-stream fast-forwards, flags non-queue merges, and reports CI RED', (t) => {
  const { repo, stateDir, git, gitRaw } = initGuardedTempRepo(t, 'r301-pulse-')
  const shimDir = makeTempDir(t, 'r301-pulse-gh-')
  const greenGh = makeFakeGh(shimDir, 'fake-gh-green', '[{"conclusion":"success","status":"completed","databaseId":101,"headSha":"abcdef1234567890"}]')
  const redGh = makeFakeGh(shimDir, 'fake-gh-red', '[{"conclusion":"failure","status":"completed","databaseId":202,"headSha":"deadbeef12345678"}]')

  // Queue a legitimate branch through merge-stream.sh.
  git('checkout', '-b', 'feat/legit')
  writeFileSync(join(repo, 'legit.txt'), 'ok\n')
  git('add', 'legit.txt')
  git('commit', '-m', 'legit branch')
  git('checkout', 'main')

  const mergeRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/legit', '--base', 'main', '--skip-ci-check', '--gate-cmd', 'true'],
    { cwd: repo, env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir }, encoding: 'utf8' },
  )
  assert.equal(mergeRes.status, 0, mergeRes.stderr)

  // Pulse with green CI and only queued fast-forward -> ZERO ACTION NON-QUEUE MERGE, CI GREEN.
  const cleanPulse = spawnSync('bash', [PARALLEL_PULSE_SH], {
    cwd: repo,
    env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_GH_BIN: greenGh },
    encoding: 'utf8',
  })
  assert.equal(cleanPulse.status, 0, cleanPulse.stderr)
  assert.equal(cleanPulse.stdout.includes('ACTION NON-QUEUE MERGE'), false, `unexpected non-queue alert: ${cleanPulse.stdout}`)
  assert.match(cleanPulse.stdout, /CI status: GREEN/)

  // Perform a direct commit via audited override (non-queue merge on main!).
  writeFileSync(join(repo, 'bypass.txt'), 'direct\n')
  git('add', 'bypass.txt')
  const direct = gitRaw(['commit', '-m', 'direct bypass'], { KOVO_MAIN_GUARD_OVERRIDE: '1' })
  assert.equal(direct.status, 0, String(direct.stderr))

  // Pulse with red CI -> MUST print BOTH `ACTION NON-QUEUE MERGE` AND `CI RED`!
  const redPulse = spawnSync('bash', [PARALLEL_PULSE_SH], {
    cwd: repo,
    env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_GH_BIN: redGh },
    encoding: 'utf8',
  })
  assert.equal(redPulse.status, 0, redPulse.stderr)
  assert.match(redPulse.stdout, /ACTION NON-QUEUE MERGE/)
  assert.match(redPulse.stdout, /CI RED/)

  // JSON mode also exposes structured nonQueueMerges and ci.state === 'red'.
  const redPulseJson = spawnSync('bash', [PARALLEL_PULSE_SH, '--json'], {
    cwd: repo,
    env: { ...process.env, KOVO_GATE_STATE_DIR: stateDir, KOVO_GH_BIN: redGh },
    encoding: 'utf8',
  })
  assert.equal(redPulseJson.status, 0, redPulseJson.stderr)
  const parsed = JSON.parse(redPulseJson.stdout) as {
    nonQueueMerges: Array<{ sha: string; reason: string }>
    ci: { state: string; conclusion: string; runId: string }
  }
  assert.equal(parsed.nonQueueMerges.length, 1)
  assert.equal(parsed.ci.state, 'red')
  assert.equal(parsed.ci.conclusion, 'failure')
  assert.equal(parsed.ci.runId, '202')
})

// ============================================================================
// 4. scripts/check-tsc-budget.ts parser, evaluator, CLI, and verify.yml wiring
// ============================================================================

test('R3-01.4: check-tsc-budget parses extendedDiagnostics, enforces ceilings, and verify.yml wires heap + budget', (t) => {
  const sampleDiag = [
    'Files:                         3313',
    'Lines of Library:             52693',
    'Lines of Definitions:        496832',
    'Lines of TypeScript:         610044',
    'Instantiations:             1544584',
    'Memory used:               2486980K',
    'Program time:                 2.79s',
    'Bind time:                    1.54s',
    'Check time:                  19.41s',
    'Total time:                  23.75s',
  ].join('\n')

  const parsed = parseTscDiagnostics(sampleDiag)
  assert.equal(parsed.files, 3313)
  assert.equal(parsed.linesOfTypeScript, 610044)
  assert.equal(parsed.instantiations, 1544584)
  assert.equal(parsed.memoryUsedKb, 2486980)
  assert.equal(parsed.totalTimeSec, 23.75)

  const okEval = evaluateTscBudget(parsed)
  assert.equal(okEval.ok, true)
  assert.deepEqual(okEval.violations, [])

  const memFail = evaluateTscBudget({ ...parsed, memoryUsedKb: TSC_BUDGET_BASELINE.maxMemoryUsedKb + 1 })
  assert.equal(memFail.ok, false)
  assert.match(memFail.violations[0] ?? '', /memoryUsedKb/)

  const timeFail = evaluateTscBudget({ ...parsed, totalTimeSec: TSC_BUDGET_BASELINE.maxTotalTimeSec + 0.5 })
  assert.equal(timeFail.ok, false)
  assert.match(timeFail.violations[0] ?? '', /totalTimeSec/)

  const missingFail = evaluateTscBudget(parseTscDiagnostics('no diagnostics here'))
  assert.equal(missingFail.ok, false)
  assert.equal(missingFail.violations.length, 2)

  // CLI --from-file PASS and FAIL paths.
  const dir = makeTempDir(t, 'r301-tsc-')
  const goodFile = join(dir, 'good.txt')
  const badFile = join(dir, 'bad.txt')
  writeFileSync(goodFile, sampleDiag)
  writeFileSync(badFile, sampleDiag.replace('2486980K', '9999999K'))

  const cliPass = spawnSync(process.execPath, [CHECK_TSC_BUDGET_TS, '--from-file', goodFile, '--json'], { encoding: 'utf8' })
  assert.equal(cliPass.status, 0, cliPass.stderr)
  assert.equal((JSON.parse(cliPass.stdout) as { ok: boolean }).ok, true)

  const cliFail = spawnSync(process.execPath, [CHECK_TSC_BUDGET_TS, '--from-file', badFile], { encoding: 'utf8' })
  assert.equal(cliFail.status, 1)
  assert.match(cliFail.stderr, /check-tsc-budget: FAIL/)

  // Verify `.github/workflows/verify.yml` wires `--max-old-space-size=6144`, `--extendedDiagnostics`, and `check-tsc-budget.ts`.
  const verifyYml = readFileSync(join(REPO_ROOT, '.github/workflows/verify.yml'), 'utf8')
  assert.match(verifyYml, /NODE_OPTIONS:\s*"--max-old-space-size=6144"/)
  assert.match(verifyYml, /--extendedDiagnostics/)
  assert.match(verifyYml, /node scripts\/check-tsc-budget\.ts/)
})
