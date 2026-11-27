/**
 * Regression tests for `/tmp` tmpfs protection + short AF_UNIX-safe TMPDIR paths in
 * `scripts/merge-stream.sh` and `scripts/run-fast-tests.sh`.
 *
 * Verifies:
 *  1. When `TMPDIR` is unset/empty and `KOVO_TMPDIR` (or `$HOME/guardian-bench-tmp`)
 *     exists and is writable, both scripts create a per-invocation `kg-*` subdirectory
 *     on disk; when that path exceeds 24 bytes, they bridge it via a short `/tmp/kt-*`
 *     symlink (`<= 24` bytes) resolving via `realpathSync` into `KOVO_TMPDIR`, and remove
 *     BOTH the symlink and target directory cleanly on exit (pass or fail).
 *  2. When the real `kg-*` path is already `<= 24` bytes, `TMPDIR` points directly to it
 *     without creating an unnecessary `/tmp/kt-*` symlink.
 *  3. When neither `KOVO_TMPDIR` nor `$HOME/guardian-bench-tmp` exists, both scripts
 *     fall back cleanly to `/tmp` with zero errors.
 *  4. When `TMPDIR` is already explicitly set by the caller, both scripts preserve it
 *     and never delete the caller's directory on exit.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
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

function pathAbsent(p: string): boolean {
  try {
    lstatSync(p)
    return false
  } catch {
    return true
  }
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

interface MergeProbeData {
  cwd: string
  tmpdir: string
  tmpdirReal: string
  tmpdirIsSymlink: boolean
}

function makeMergeProbeGate(markerPath: string, exitCode = 0): string {
  const script =
    `const fs = require("node:fs");` +
    `const td = process.env.TMPDIR || "";` +
    `fs.writeFileSync(process.argv[1], JSON.stringify({` +
    `  cwd: process.cwd(),` +
    `  tmpdir: td,` +
    `  tmpdirReal: td ? fs.realpathSync(td) : "",` +
    `  tmpdirIsSymlink: td ? fs.lstatSync(td).isSymbolicLink() : false,` +
    `}));` +
    (exitCode !== 0 ? `process.exit(${exitCode});` : '')
  return `node -e '${script}' ${JSON.stringify(markerPath)}`
}

test('merge-stream.sh uses short symlinked TMPDIR for long KOVO_TMPDIR, cleans up symlink + target on pass/fail, and falls back cleanly', (t) => {
  const { repo } = initTempGitRepo(t)
  const stateDir = makeTempDir(t, 'kt-state-')
  const kovoTmpRoot = makeTempDir(t, 'kt-kovo-')
  const longKovoTmp = join(kovoTmpRoot, 'deeply-nested-btrfs-storage-path-exceeding-fifty-bytes')
  mkdirSync(longKovoTmp, { recursive: true })
  assert.ok(longKovoTmp.length > 50, `expected long KOVO_TMPDIR > 50 bytes, got ${longKovoTmp.length}`)
  const longKovoTmpReal = realpathSync(longKovoTmp)
  const markerDir = makeTempDir(t, 'kt-mark-')

  // (a) Long KOVO_TMPDIR (>50 bytes) & TMPDIR unset -> short TMPDIR (<=24 bytes) resolving into KOVO_TMPDIR/kg-*, both cleaned on EXIT (pass)
  const passMarker = join(markerDir, 'pass.json')
  const passRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', makeMergeProbeGate(passMarker), '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: longKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(passRes.status, 0, `merge-stream dry-run failed: ${passRes.stderr}`)
  const passData = JSON.parse(readFileSync(passMarker, 'utf8')) as MergeProbeData
  assert.ok(
    passData.tmpdir.length > 0 && passData.tmpdir.length <= 24,
    `expected short TMPDIR <= 24 bytes, got ${passData.tmpdir.length} (${passData.tmpdir})`,
  )
  assert.equal(passData.tmpdirIsSymlink, true, `expected symlinked TMPDIR for long KOVO_TMPDIR, got ${passData.tmpdir}`)
  assert.ok(
    passData.tmpdirReal.startsWith(`${longKovoTmpReal}/kg-`),
    `expected realpath(TMPDIR) under ${longKovoTmpReal}/kg-*, got ${passData.tmpdirReal}`,
  )
  assert.ok(
    passData.cwd.startsWith(`${passData.tmpdirReal}/kovo-merge-stream-`),
    `expected merge worktree under ${passData.tmpdirReal}/kovo-merge-stream-*, got ${passData.cwd}`,
  )
  assert.equal(pathAbsent(passData.tmpdir), true, 'short TMPDIR symlink must be removed on exit')
  assert.equal(pathAbsent(passData.tmpdirReal), true, 'real TMPDIR target dir must be removed on exit')
  assert.deepEqual(readdirSync(longKovoTmp), [], 'KOVO_TMPDIR must have no leftover kg-* subdirs after pass')

  // (a2) Cleanup removes BOTH symlink and target dir even on gate failure
  const failMarker = join(markerDir, 'fail.json')
  const failRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', makeMergeProbeGate(failMarker, 1), '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: longKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.notEqual(failRes.status, 0, 'failing gate must exit non-zero')
  const failData = JSON.parse(readFileSync(failMarker, 'utf8')) as MergeProbeData
  assert.ok(failData.tmpdir.length <= 24, `expected short TMPDIR <= 24 bytes on failure, got ${failData.tmpdir}`)
  assert.ok(failData.tmpdirReal.startsWith(`${longKovoTmpReal}/kg-`))
  assert.equal(pathAbsent(failData.tmpdir), true, 'short TMPDIR symlink must be removed even on gate failure')
  assert.equal(pathAbsent(failData.tmpdirReal), true, 'real TMPDIR target dir must be removed even on gate failure')
  assert.deepEqual(readdirSync(longKovoTmp), [], 'KOVO_TMPDIR must have no leftovers after failure')

  // (a3) Short KOVO_TMPDIR where REAL_TMPDIR <= 24 bytes -> exported directly without symlink
  const shortKovoTmp = mkdtempSync('/tmp/ks-')
  t.after(() => rmSync(shortKovoTmp, { recursive: true, force: true }))
  // '/tmp/ks-XXXXXX' is 14 bytes; '/tmp/ks-XXXXXX/kg-YYYYYY' is 24 bytes (<= 24).
  assert.ok(shortKovoTmp.length + '/kg-XXXXXX'.length <= 24, `expected short real tmpdir <= 24 bytes for ${shortKovoTmp}`)
  const shortMarker = join(markerDir, 'short.json')
  const shortRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', makeMergeProbeGate(shortMarker), '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: shortKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(shortRes.status, 0, `short KOVO_TMPDIR merge-stream failed: ${shortRes.stderr}`)
  const shortData = JSON.parse(readFileSync(shortMarker, 'utf8')) as MergeProbeData
  assert.equal(shortData.tmpdirIsSymlink, false, `expected direct TMPDIR without symlink when <= 24 bytes, got ${shortData.tmpdir}`)
  assert.ok(shortData.tmpdir.startsWith(`${shortKovoTmp}/kg-`), `expected ${shortKovoTmp}/kg-*, got ${shortData.tmpdir}`)
  assert.equal(pathAbsent(shortData.tmpdir), true, 'direct short TMPDIR must be removed on exit')
  assert.deepEqual(readdirSync(shortKovoTmp), [], 'short KOVO_TMPDIR must be clean after exit')

  // (b) KOVO_TMPDIR points to nonexistent dir & TMPDIR unset -> falls back cleanly to /tmp
  const missingKovoTmp = join(markerDir, 'does-not-exist')
  const fbMarker = join(markerDir, 'fallback.json')
  const fbRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', makeMergeProbeGate(fbMarker), '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, KOVO_TMPDIR: missingKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(fbRes.status, 0, `fallback merge-stream failed: ${fbRes.stderr}`)
  const fbData = JSON.parse(readFileSync(fbMarker, 'utf8')) as MergeProbeData
  assert.equal(fbData.tmpdir, '', 'TMPDIR should remain unset when KOVO_TMPDIR does not exist')
  assert.ok(fbData.cwd.startsWith('/tmp/kovo-merge-stream-'), `expected /tmp fallback worktree, got ${fbData.cwd}`)
  assert.equal(existsSync(missingKovoTmp), false, 'nonexistent KOVO_TMPDIR must not be created')

  // (c) Explicit caller TMPDIR is preserved and never deleted on exit
  const callerTmp = makeTempDir(t, 'kt-caller-')
  const expMarker = join(markerDir, 'explicit.json')
  const expRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', makeMergeProbeGate(expMarker), '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, TMPDIR: callerTmp, KOVO_TMPDIR: longKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(expRes.status, 0, `explicit TMPDIR merge-stream failed: ${expRes.stderr}`)
  const expData = JSON.parse(readFileSync(expMarker, 'utf8')) as MergeProbeData
  assert.equal(expData.tmpdir, callerTmp, 'caller TMPDIR must be preserved')
  assert.ok(expData.cwd.startsWith(`${realpathSync(callerTmp)}/kovo-merge-stream-`), 'worktree must use caller TMPDIR')
  assert.equal(existsSync(callerTmp), true, 'caller TMPDIR must NOT be deleted on exit')
  assert.deepEqual(readdirSync(longKovoTmp), [], 'KOVO_TMPDIR must remain untouched when TMPDIR is set')

  // (d) Default $HOME/guardian-bench-tmp discovery when KOVO_TMPDIR and TMPDIR are both unset
  const fakeHome = makeTempDir(t, 'kt-home-')
  const defaultBenchTmp = join(fakeHome, 'guardian-bench-tmp')
  mkdirSync(defaultBenchTmp, { recursive: true })
  const defaultBenchTmpReal = realpathSync(defaultBenchTmp)
  const homeMarker = join(markerDir, 'home.json')
  const homeRes = spawnSync(
    'bash',
    [MERGE_STREAM_SH, 'feat/change', '--base', 'main', '--dry-run', '--skip-ci-check', '--skip-kernel-review', '--gate-cmd', makeMergeProbeGate(homeMarker), '--json'],
    {
      cwd: repo,
      env: cleanTmpEnv({ KOVO_GATE_STATE_DIR: stateDir, HOME: fakeHome }),
      encoding: 'utf8',
    },
  )
  assert.equal(homeRes.status, 0, `default HOME bench-tmp merge-stream failed: ${homeRes.stderr}`)
  const homeData = JSON.parse(readFileSync(homeMarker, 'utf8')) as MergeProbeData
  assert.ok(homeData.tmpdir.length > 0 && homeData.tmpdir.length <= 24, `expected short TMPDIR <= 24 bytes, got ${homeData.tmpdir}`)
  assert.ok(
    homeData.tmpdirReal.startsWith(`${defaultBenchTmpReal}/kg-`),
    `expected realpath(TMPDIR) under ${defaultBenchTmpReal}/kg-*, got ${homeData.tmpdirReal}`,
  )
  assert.equal(pathAbsent(homeData.tmpdir), true, 'short TMPDIR symlink must be removed after exit')
  assert.equal(pathAbsent(homeData.tmpdirReal), true, 'real TMPDIR under $HOME/guardian-bench-tmp must be removed after exit')
  assert.deepEqual(readdirSync(defaultBenchTmp), [], '$HOME/guardian-bench-tmp must be clean after exit')
})

interface RftProbeData {
  childTmp: string
  childTmpReal: string
  parentTmp: string
  parentTmpReal: string
  parentIsSymlink: boolean
}

test('run-fast-tests.sh uses short symlinked TMPDIR for long KOVO_TMPDIR, cleans up symlink + target on exit, and falls back cleanly', (t) => {
  const miniTestsDir = makeTempDir(t, 'kt-tests-')
  const kovoTmpRoot = makeTempDir(t, 'kt-rft-')
  const longKovoTmp = join(kovoTmpRoot, 'deeply-nested-btrfs-storage-path-exceeding-fifty-bytes')
  mkdirSync(longKovoTmp, { recursive: true })
  assert.ok(longKovoTmp.length > 50, `expected long KOVO_TMPDIR > 50 bytes, got ${longKovoTmp.length}`)
  const longKovoTmpReal = realpathSync(longKovoTmp)
  const markerDir = makeTempDir(t, 'kt-rft-m-')

  const markerFile = join(markerDir, 'observed.json')
  // Mini test records its observed hermetic TMPDIR and parent run TMPDIR before exit cleanup runs.
  writeFileSync(
    join(miniTestsDir, 'probe-tmpdir.test.ts'),
    `import { lstatSync, realpathSync, writeFileSync } from 'node:fs'\n` +
      `import { dirname } from 'node:path'\n` +
      `import { test } from 'node:test'\n` +
      `test('record tmpdir', () => {\n` +
      `  const childTmp = process.env.TMPDIR || ''\n` +
      `  const parentTmp = childTmp ? dirname(dirname(childTmp)) : ''\n` +
      `  writeFileSync(${JSON.stringify(markerFile)}, JSON.stringify({\n` +
      `    childTmp,\n` +
      `    childTmpReal: childTmp ? realpathSync(childTmp) : '',\n` +
      `    parentTmp,\n` +
      `    parentTmpReal: parentTmp ? realpathSync(parentTmp) : '',\n` +
      `    parentIsSymlink: parentTmp ? lstatSync(parentTmp).isSymbolicLink() : false,\n` +
      `  }))\n` +
      `})\n`,
  )

  // (a) Long KOVO_TMPDIR (>50 bytes) & TMPDIR unset -> effective parent TMPDIR <= 24 bytes resolving into KOVO_TMPDIR/kg-*, both cleaned on exit
  const res = spawnSync(
    'bash',
    [RUN_FAST_TESTS_SH, '--suites-only', '--tests-dir', miniTestsDir, '--jobs', '1', '--json'],
    {
      cwd: REPO_ROOT,
      env: cleanTmpEnv({ KOVO_TMPDIR: longKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(res.status, 0, `run-fast-tests failed: ${res.stdout}\n${res.stderr}`)
  const observed = JSON.parse(readFileSync(markerFile, 'utf8')) as RftProbeData
  assert.ok(
    observed.parentTmp.length > 0 && observed.parentTmp.length <= 24,
    `expected effective run TMPDIR <= 24 bytes, got ${observed.parentTmp.length} (${observed.parentTmp})`,
  )
  assert.equal(observed.parentIsSymlink, true, `expected symlinked run TMPDIR for long KOVO_TMPDIR, got ${observed.parentTmp}`)
  assert.ok(
    observed.parentTmpReal.startsWith(`${longKovoTmpReal}/kg-`),
    `expected realpath(TMPDIR) under ${longKovoTmpReal}/kg-*, got ${observed.parentTmpReal}`,
  )
  assert.ok(
    observed.childTmpReal.startsWith(`${observed.parentTmpReal}/kf-`),
    `expected child sandbox realpath inside ${observed.parentTmpReal}/kf-*, got ${observed.childTmpReal}`,
  )
  assert.equal(pathAbsent(observed.parentTmp), true, 'short TMPDIR symlink must be removed on exit')
  assert.equal(pathAbsent(observed.parentTmpReal), true, 'real TMPDIR target dir must be removed on exit')
  assert.deepEqual(readdirSync(longKovoTmp), [], 'run-fast-tests must remove per-run kg-* dir on exit')

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
  const observedFallback = JSON.parse(readFileSync(markerFile, 'utf8')) as RftProbeData
  assert.ok(
    observedFallback.childTmp.startsWith('/tmp/kf-'),
    `expected /tmp/kf-* fallback when KOVO_TMPDIR is absent, got ${observedFallback.childTmp}`,
  )
  assert.equal(existsSync(missingDir), false, 'nonexistent KOVO_TMPDIR must not be created')

  // (c) Explicit caller TMPDIR is preserved and not deleted on exit
  const callerTmp = makeTempDir(t, 'kt-rft-caller-')
  const expRes = spawnSync(
    'bash',
    [RUN_FAST_TESTS_SH, '--suites-only', '--tests-dir', miniTestsDir, '--jobs', '1', '--json'],
    {
      cwd: REPO_ROOT,
      env: cleanTmpEnv({ TMPDIR: callerTmp, KOVO_TMPDIR: longKovoTmp }),
      encoding: 'utf8',
    },
  )
  assert.equal(expRes.status, 0, `run-fast-tests explicit TMPDIR failed: ${expRes.stdout}\n${expRes.stderr}`)
  const observedExplicit = JSON.parse(readFileSync(markerFile, 'utf8')) as RftProbeData
  assert.ok(
    observedExplicit.childTmp.startsWith(`${resolve(callerTmp)}/kf-`),
    `expected child TMPDIR under explicit caller TMPDIR ${callerTmp}, got ${observedExplicit.childTmp}`,
  )
  assert.equal(existsSync(callerTmp), true, 'explicit caller TMPDIR must not be deleted on exit')
  assert.deepEqual(readdirSync(longKovoTmp), [], 'KOVO_TMPDIR must remain unused when TMPDIR is set')
})
