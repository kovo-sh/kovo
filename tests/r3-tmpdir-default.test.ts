/**
 * Regression tests for `/tmp` tmpfs protection in `scripts/merge-stream.sh` and
 * `scripts/run-fast-tests.sh`.
 *
 * Verifies:
 *  1. When `TMPDIR` is unset/empty and `KOVO_TMPDIR` (or `$HOME/guardian-bench-tmp`)
 *     exists and is writable, both scripts create a per-invocation `kovo-gate-*`
 *     subdirectory, export `TMPDIR` to it (placing merge worktrees and per-test
 *     sandboxes under it), and remove it cleanly on exit (pass or fail).
 *  2. When neither `KOVO_TMPDIR` nor `$HOME/guardian-bench-tmp` exists, both scripts
 *     fall back cleanly to `/tmp` with zero errors.
 *  3. When `TMPDIR` is already explicitly set by the caller, both scripts preserve it
 *     and never delete the caller's directory on exit.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const MERGE_STREAM_SH = join(REPO_ROOT, 'scripts/merge-stream.sh')
const RUN_FAST_TESTS_SH = join(REPO_ROOT, 'scripts/run-fast-tests.sh')

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function cleanTmpEnv(overrides: Record<string, string | undefined>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env }
  delete env.TMPDIR
  delete env.TMP
  delete env.TEMP
  delete env.KOVO_TMPDIR
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) delete env[k]
    else env[k] = v
  }
  return env
}

function initTempGitRepo(t: { after: (fn: () => void) => void }): {
  repo: string
  git: (...args: string[]) => string
} {
  const repo = makeTempDir(t, 'kt-repo-')
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '-b', 'main')
  git('config', 'user.email', 'tmpdir-test@example.invalid')
  git('config', 'user.name', 'Tmpdir Tester')
  writeFileSync(join(repo, 'app.txt'), 'ok\n')
  git('add', '.')
  git('commit', '-m', 'initial main')
  git('checkout', '-b', 'feat/change')
  writeFileSync(join(repo, 'app.txt'), 'updated\n')
  git('add', '.')
  git('commit', '-m', 'update app')
  git('checkout', 'main')
  return { repo, git }
}

test('merge-stream.sh uses per-run KOVO_TMPDIR subdir for TMPDIR and merge worktree, cleans up on pass/fail, and falls back cleanly', (t) => {
  const { repo } = initTempGitRepo(t)
  const stateDir = makeTempDir(t, 'kt-state-')
  const kovoTmp = makeTempDir(t, 'kt-kovo-')
  const markerDir = makeTempDir(t, 'kt-mark-')

  // (a) KOVO_TMPDIR exists & TMPDIR unset -> worktree + TMPDIR inside KOVO_TMPDIR/kovo-gate-*, removed on EXIT (pass)
  const passMarker = join(markerDir, 'pass.json')
  const passGate = `node -e 'require("node:fs").writeFileSync(process.argv[1], JSON.stringify({ cwd: process.cwd(), tmpdir: process.env.TMPDIR || "" }))' ${JSON.stringify(passMarker)}`
  const passRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', passGate, '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: kovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(passRes.status, 0, `merge-stream dry-run failed: ${passRes.stderr}`)
  const passData = JSON.parse(readFileSync(passMarker, 'utf8')) as { cwd: string; tmpdir: string }
  assert.ok(
    passData.tmpdir.startsWith(`${resolve(kovoTmp)}/kovo-gate-`),
    `expected TMPDIR under ${kovoTmp}/kovo-gate-*, got ${passData.tmpdir}`,
  )
  assert.ok(
    passData.cwd.startsWith(`${passData.tmpdir}/kovo-merge-stream-`),
    `expected merge worktree under ${passData.tmpdir}/kovo-merge-stream-*, got ${passData.cwd}`,
  )
  assert.equal(existsSync(passData.tmpdir), false, 'per-run TMPDIR must be removed on exit')
  assert.deepEqual(readdirSync(kovoTmp), [], 'KOVO_TMPDIR must have no leftover kovo-gate-* subdirs after pass')

  // (a2) Cleanup also runs on gate failure
  const failMarker = join(markerDir, 'fail.json')
  const failGate = `node -e 'require("node:fs").writeFileSync(process.argv[1], JSON.stringify({ tmpdir: process.env.TMPDIR || "" })); process.exit(1)' ${JSON.stringify(failMarker)}`
  const failRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', failGate, '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: kovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.notEqual(failRes.status, 0, 'failing gate must exit non-zero')
  const failData = JSON.parse(readFileSync(failMarker, 'utf8')) as { tmpdir: string }
  assert.ok(failData.tmpdir.startsWith(`${resolve(kovoTmp)}/kovo-gate-`))
  assert.equal(existsSync(failData.tmpdir), false, 'per-run TMPDIR must be removed even on gate failure')
  assert.deepEqual(readdirSync(kovoTmp), [], 'KOVO_TMPDIR must have no leftovers after failure')

  // (b) KOVO_TMPDIR points to nonexistent dir & TMPDIR unset -> falls back cleanly to /tmp
  const missingKovoTmp = join(markerDir, 'does-not-exist')
  const fbMarker = join(markerDir, 'fallback.json')
  const fbGate = `node -e 'require("node:fs").writeFileSync(process.argv[1], JSON.stringify({ cwd: process.cwd(), tmpdir: process.env.TMPDIR || "" }))' ${JSON.stringify(fbMarker)}`
  const fbRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', fbGate, '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: missingKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(fbRes.status, 0, `fallback merge-stream failed: ${fbRes.stderr}`)
  const fbData = JSON.parse(readFileSync(fbMarker, 'utf8')) as { cwd: string; tmpdir: string }
  assert.equal(fbData.tmpdir, '', 'TMPDIR should remain unset when KOVO_TMPDIR does not exist')
  assert.ok(fbData.cwd.startsWith('/tmp/kovo-merge-stream-'), `expected /tmp fallback worktree, got ${fbData.cwd}`)
  assert.equal(existsSync(missingKovoTmp), false, 'nonexistent KOVO_TMPDIR must not be created')

  // (c) Explicit caller TMPDIR is preserved and never deleted on exit
  const callerTmp = makeTempDir(t, 'kt-caller-')
  const expMarker = join(markerDir, 'explicit.json')
  const expGate = `node -e 'require("node:fs").writeFileSync(process.argv[1], JSON.stringify({ cwd: process.cwd(), tmpdir: process.env.TMPDIR || "" }))' ${JSON.stringify(expMarker)}`
  const expRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', expGate, '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, TMPDIR: callerTmp, KOVO_TMPDIR: kovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(expRes.status, 0, `explicit TMPDIR merge-stream failed: ${expRes.stderr}`)
  const expData = JSON.parse(readFileSync(expMarker, 'utf8')) as { cwd: string; tmpdir: string }
  assert.equal(expData.tmpdir, callerTmp, 'caller TMPDIR must be preserved')
  assert.ok(expData.cwd.startsWith(`${callerTmp}/kovo-merge-stream-`), 'worktree must use caller TMPDIR')
  assert.equal(existsSync(callerTmp), true, 'caller TMPDIR must NOT be deleted on exit')
  assert.deepEqual(readdirSync(kovoTmp), [], 'KOVO_TMPDIR must remain untouched when TMPDIR is set')

  // (d) Default $HOME/guardian-bench-tmp discovery when KOVO_TMPDIR and TMPDIR are both unset
  const fakeHome = makeTempDir(t, 'kt-home-')
  const defaultBenchTmp = join(fakeHome, 'guardian-bench-tmp')
  mkdirSync(defaultBenchTmp, { recursive: true })
  const homeMarker = join(markerDir, 'home.json')
  const homeGate = `node -e 'require("node:fs").writeFileSync(process.argv[1], JSON.stringify({ cwd: process.cwd(), tmpdir: process.env.TMPDIR || "" }))' ${JSON.stringify(homeMarker)}`
  const homeRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', homeGate, '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, HOME: fakeHome }),
      encoding: 'utf8',
    },
  )
  assert.equal(homeRes.status, 0, `default HOME bench-tmp merge-stream failed: ${homeRes.stderr}`)
  const homeData = JSON.parse(readFileSync(homeMarker, 'utf8')) as { cwd: string; tmpdir: string }
  assert.ok(homeData.tmpdir.startsWith(`${defaultBenchTmp}/kovo-gate-`), `expected $HOME/guardian-bench-tmp, got ${homeData.tmpdir}`)
  assert.deepEqual(readdirSync(defaultBenchTmp), [], '$HOME/guardian-bench-tmp must be clean after exit')
})

test('run-fast-tests.sh uses per-run KOVO_TMPDIR subdir when TMPDIR is unset, cleans up on exit, and falls back cleanly', (t) => {
  const miniTestsDir = makeTempDir(t, 'kt-tests-')
  const kovoTmp = makeTempDir(t, 'kt-rft-')
  const markerDir = makeTempDir(t, 'kt-rft-m-')

  const markerFile = join(markerDir, 'observed.txt')
  // Mini test writes its observed hermetic TMPDIR to a fixed path so we can inspect it after exit.
  writeFileSync(
    join(miniTestsDir, 'probe-tmpdir.test.ts'),
    `import { writeFileSync } from 'node:fs'\n` +
      `import { test } from 'node:test'\n` +
      `test('record tmpdir', () => {\n` +
      `  writeFileSync(${JSON.stringify(markerFile)}, process.env.TMPDIR || '')\n` +
      `})\n`,
  )

  // (a) KOVO_TMPDIR exists & TMPDIR unset -> child sandbox TMPDIR lives inside KOVO_TMPDIR/kovo-gate-*, cleaned up on exit
  const res = spawnSync(
    'bash',
    [RUN_FAST_TESTS_SH, '--suites-only', '--tests-dir', miniTestsDir, '--jobs', '1', '--json'],
    {
      cwd: REPO_ROOT,
      env: cleanTmpEnv({ KOVO_TMPDIR: kovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(res.status, 0, `run-fast-tests failed: ${res.stdout}\n${res.stderr}`)
  const observedTmp = readFileSync(markerFile, 'utf8').trim()
  assert.ok(
    observedTmp.startsWith(`${resolve(kovoTmp)}/kovo-gate-`),
    `expected child TMPDIR inside ${kovoTmp}/kovo-gate-*, got ${observedTmp}`,
  )
  assert.deepEqual(readdirSync(kovoTmp), [], 'run-fast-tests must remove per-run kovo-gate-* dir on exit')

  // (b) KOVO_TMPDIR points to nonexistent dir & TMPDIR unset -> falls back cleanly to /tmp
  const missingDir = join(markerDir, 'missing-kovo-tmp')
  const fbRes = spawnSync(
    'bash',
    [RUN_FAST_TESTS_SH, '--suites-only', '--tests-dir', miniTestsDir, '--jobs', '1', '--json'],
    {
      cwd: REPO_ROOT,
      env: cleanTmpEnv({ KOVO_TMPDIR: missingDir }),
      encoding: 'utf8',
    },
  )
  assert.equal(fbRes.status, 0, `run-fast-tests fallback failed: ${fbRes.stdout}\n${fbRes.stderr}`)
  const observedFallback = readFileSync(markerFile, 'utf8').trim()
  assert.ok(
    observedFallback.startsWith('/tmp/kf-'),
    `expected /tmp/kf-* fallback when KOVO_TMPDIR is absent, got ${observedFallback}`,
  )
  assert.equal(existsSync(missingDir), false, 'nonexistent KOVO_TMPDIR must not be created')

  // (c) Explicit caller TMPDIR is preserved and not deleted on exit
  const callerTmp = makeTempDir(t, 'kt-rft-caller-')
  const expRes = spawnSync(
    'bash',
    [RUN_FAST_TESTS_SH, '--suites-only', '--tests-dir', miniTestsDir, '--jobs', '1', '--json'],
    {
      cwd: REPO_ROOT,
      env: cleanTmpEnv({ TMPDIR: callerTmp, KOVO_TMPDIR: kovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(expRes.status, 0, `run-fast-tests explicit TMPDIR failed: ${expRes.stdout}\n${expRes.stderr}`)
  const observedExplicit = readFileSync(markerFile, 'utf8').trim()
  assert.ok(
    observedExplicit.startsWith(`${resolve(callerTmp)}/kf-`),
    `expected child TMPDIR under explicit caller TMPDIR ${callerTmp}, got ${observedExplicit}`,
  )
  assert.equal(existsSync(callerTmp), true, 'explicit caller TMPDIR must not be deleted on exit')
  assert.deepEqual(readdirSync(kovoTmp), [], 'KOVO_TMPDIR must remain unused when TMPDIR is set')
})
