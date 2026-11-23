/**
 * v5 security wave 2 — lab confinement regression tests (re-audit HIGH #2 residual, MEDIUM #7).
 *
 * HIGH #2 residual — `safeResolveUnderRoot`/patch application must fail closed on dangling
 *   symlinks and must never write through an existing path.
 * MEDIUM #7 — `GUARDIAN_LAB_USER` must be parsed numerically, and IAST telemetry must be a unique,
 *   owner-only, per-run mount that is read-only when telemetry is off and fails fast on uid mismatch.
 */
import assert from 'node:assert/strict'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  applyUnifiedDiffToDirectory,
  assertIastTelemetryDirWritable,
  buildIastTelemetryMountArgs,
  createPerRunIastTelemetryDir,
  pruneLabTelemetryDirs,
  resolveLabContainerUser,
  safeResolveUnderRoot,
} from '../src/server/lab-runner.ts'

const OUTSIDE_CANARY = 'OUTSIDE-LAB2-CANARY-4b71'

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function diffFor(relPath: string, from: string, to: string): string {
  return [
    `--- a/${relPath}`,
    `+++ b/${relPath}`,
    '@@ -1 +1 @@',
    `-${from}`,
    `+${to}`,
    '',
  ].join('\n')
}

function createDiff(relPath: string, content: string): string {
  return [
    '--- /dev/null',
    `+++ b/${relPath}`,
    `@@ -0,0 +1 @@`,
    `+${content}`,
    '',
  ].join('\n')
}

// ============================================================================
// HIGH #2 residual — dangling symlink escape in the containment primitive
// ============================================================================

test('safeResolveUnderRoot rejects dangling symlink components (leaf and nested dir)', t => {
  const root = makeTempDir(t, 'guardian-lab2-resolve-')
  const outside = makeTempDir(t, 'guardian-lab2-resolve-out-')

  symlinkSync(join(outside, 'not-yet-created.ts'), join(root, 'dangling.ts'))
  symlinkSync(join(outside, 'missing-dir'), join(root, 'dangling-dir'))

  assert.throws(() => safeResolveUnderRoot(root, 'dangling.ts'), /symlink|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, 'dangling-dir/new.ts'), /symlink|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, 'dangling-dir/deeper/new.ts'), /symlink|escapes/i)

  // A legitimate new file still resolves.
  assert.equal(safeResolveUnderRoot(root, 'fresh.ts'), join(root, 'fresh.ts'))
})

test('create-file patch cannot be written through a dangling symlink', t => {
  const root = makeTempDir(t, 'guardian-lab2-create-link-')
  const outside = makeTempDir(t, 'guardian-lab2-create-link-out-')
  const escapeTarget = join(outside, 'escaped.ts')
  symlinkSync(escapeTarget, join(root, 'dangling.ts'))

  assert.throws(
    () => applyUnifiedDiffToDirectory(root, createDiff('dangling.ts', 'export const pwned = true')),
    /symlink|escapes/i,
  )
  assert.equal(existsSync(escapeTarget), false, 'create-file hunk must not materialise the link target')
  assert.equal(lstatSync(join(root, 'dangling.ts')).isSymbolicLink(), true, 'the link itself is untouched')
})

test('modify hunk cannot be applied through a dangling symlink', t => {
  const root = makeTempDir(t, 'guardian-lab2-modify-link-')
  const outside = makeTempDir(t, 'guardian-lab2-modify-link-out-')
  const escapeTarget = join(outside, 'escaped.ts')
  symlinkSync(escapeTarget, join(root, 'dangling.ts'))

  assert.throws(
    () => applyUnifiedDiffToDirectory(root, diffFor('dangling.ts', 'original', 'pwned')),
    /symlink|escapes/i,
  )
  assert.equal(existsSync(escapeTarget), false)
})

test('existing-file overwrite through a link is refused', t => {
  const root = makeTempDir(t, 'guardian-lab2-overwrite-link-')
  const outside = makeTempDir(t, 'guardian-lab2-overwrite-link-out-')
  const victim = join(outside, 'victim.ts')
  writeFileSync(victim, 'export const value = "original"\n')
  symlinkSync(victim, join(root, 'victim.ts'))

  assert.throws(
    () => applyUnifiedDiffToDirectory(root, diffFor('victim.ts', 'export const value = "original"', 'export const value = "pwned"')),
    /symlink|escapes/i,
  )
  assert.equal(readFileSync(victim, 'utf8'), 'export const value = "original"\n')
})

test('nested symlinked directory is refused for create and modify hunks', t => {
  const root = makeTempDir(t, 'guardian-lab2-nested-link-')
  const outside = makeTempDir(t, 'guardian-lab2-nested-link-out-')
  symlinkSync(outside, join(root, 'linked-dir'))

  assert.throws(
    () => applyUnifiedDiffToDirectory(root, createDiff('linked-dir/new.ts', 'export const pwned = true')),
    /symlink|escapes/i,
  )
  writeFileSync(join(outside, 'existing.ts'), 'original\n')
  assert.throws(
    () => applyUnifiedDiffToDirectory(root, diffFor('linked-dir/existing.ts', 'original', 'pwned')),
    /symlink|escapes/i,
  )
  assert.equal(readFileSync(join(outside, 'existing.ts'), 'utf8'), 'original\n')
  assert.equal(existsSync(join(outside, 'new.ts')), false)
})

test('legitimate create and modify hunks still apply inside the root', t => {
  const root = makeTempDir(t, 'guardian-lab2-legit-')
  writeFileSync(join(root, 'app.ts'), 'export const value = "original"\n')
  mkdirSync(join(root, 'src'), { recursive: true })
  writeFileSync(join(root, 'src', 'existing.ts'), 'export const flag = false\n')

  const created = applyUnifiedDiffToDirectory(root, createDiff('new.ts', 'export const added = true'))
  assert.deepEqual(created.filesModified, ['new.ts'])
  assert.equal(readFileSync(join(root, 'new.ts'), 'utf8'), 'export const added = true\n')
  assert.equal(statSync(join(root, 'new.ts')).mode & 0o777, 0o644)

  const nestedCreate = applyUnifiedDiffToDirectory(root, createDiff('src/deep/new.ts', 'export const nested = true'))
  assert.deepEqual(nestedCreate.filesModified, ['src/deep/new.ts'])
  assert.equal(readFileSync(join(root, 'src', 'deep', 'new.ts'), 'utf8'), 'export const nested = true\n')

  const modified = applyUnifiedDiffToDirectory(
    root,
    diffFor('src/existing.ts', 'export const flag = false', 'export const flag = true'),
  )
  assert.deepEqual(modified.filesModified, ['src/existing.ts'])
  assert.equal(readFileSync(join(root, 'src', 'existing.ts'), 'utf8'), 'export const flag = true\n')

  // A create hunk must not silently overwrite an existing regular file either.
  assert.throws(
    () => applyUnifiedDiffToDirectory(root, createDiff('new.ts', 'export const replaced = true')),
    /already exists/i,
  )
  assert.equal(readFileSync(join(root, 'new.ts'), 'utf8'), 'export const added = true\n')
})

// ============================================================================
// MEDIUM #7a — GUARDIAN_LAB_USER numeric parsing
// ============================================================================

test('resolveLabContainerUser rejects numeric-root and non-numeric forms', () => {
  for (const bad of ['00:00', '000:1000', '0:1000', '1000:0', '0000:0000', '-1:0', 'root:root', 'nobody', '1000', '1000:1000:0']) {
    assert.throws(
      () => resolveLabContainerUser({ GUARDIAN_LAB_USER: bad }),
      /non-root|numeric|rejected/i,
      `GUARDIAN_LAB_USER=${JSON.stringify(bad)} must be rejected`,
    )
  }

  assert.equal(resolveLabContainerUser({ GUARDIAN_LAB_USER: '1000:1000' }), '1000:1000')
  assert.equal(resolveLabContainerUser({ GUARDIAN_LAB_USER: '01000:01000' }), '1000:1000')

  const fallback = resolveLabContainerUser({})
  assert.match(fallback, /^\d+:\d+$/)
  assert.notEqual(fallback.split(':')[0], '0')
  assert.notEqual(fallback.split(':')[1], '0')
})

// ============================================================================
// MEDIUM #7b — per-run, owner-only, read-only-when-off telemetry mount
// ============================================================================

test('two lab runs receive distinct 0700 telemetry dirs under the shared base', t => {
  const base = join(makeTempDir(t, 'guardian-lab2-telemetry-'), 'evidence', 'lab-telemetry')

  const first = createPerRunIastTelemetryDir(base, 'run-one')
  const second = createPerRunIastTelemetryDir(base, 'run-two')

  assert.notEqual(first, second, 'each run must get its own telemetry dir')
  assert.equal(first.startsWith(base), true)
  assert.equal(second.startsWith(base), true)
  assert.equal(statSync(first).mode & 0o777, 0o700)
  assert.equal(statSync(second).mode & 0o777, 0o700)
  assert.equal(statSync(base).mode & 0o777, 0o700)
  assert.deepEqual(readdirSync(base).sort(), [first, second].map(p => p.slice(base.length + 1)).sort())
})

test('IAST telemetry mount is read-only when telemetry is not enabled', () => {
  const off = buildIastTelemetryMountArgs('/host/telemetry', false)
  assert.deepEqual(off, ['--mount', 'type=bind,source=/host/telemetry,target=/var/run/guardian-iast,readonly'])

  const on = buildIastTelemetryMountArgs('/host/telemetry', true)
  assert.deepEqual(on, ['--mount', 'type=bind,source=/host/telemetry,target=/var/run/guardian-iast'])
  assert.equal(on.some(a => a.endsWith(',readonly')), false)
})

test('telemetry dirs stay bounded: old per-run dirs are pruned', t => {
  const base = join(makeTempDir(t, 'guardian-lab2-prune-'), 'lab-telemetry')
  mkdirSync(base, { recursive: true, mode: 0o700 })

  const created: string[] = []
  for (let i = 0; i < 6; i += 1) {
    const dir = join(base, `run-old-${i}`)
    mkdirSync(dir, { mode: 0o700 })
    writeFileSync(join(dir, 'trace.json'), '{}')
    created.push(dir)
  }

  const removed = pruneLabTelemetryDirs(base, 2)
  const remaining = readdirSync(base).sort()
  assert.equal(remaining.length, 2)
  assert.equal(removed.length, 4)
  assert.ok(remaining.every(name => name.startsWith('run-')))
})

test('mismatched GUARDIAN_LAB_USER fails fast instead of silently losing IAST data', t => {
  const base = join(makeTempDir(t, 'guardian-lab2-mismatch-'), 'lab-telemetry')
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined
  if (uid === 0 || uid === undefined) {
    // Root can chown the dir to any container user, so the mismatch case does not exist.
    return
  }
  const gid = typeof process.getgid === 'function' ? process.getgid() : uid
  const otherUser = `${uid + 1}:${gid}`

  assert.throws(
    () => createPerRunIastTelemetryDir(base, 'run-mismatch', otherUser),
    (err: unknown) => {
      assert.ok(err instanceof Error)
      assert.match(err.message, /IAST telemetry dir/i)
      assert.match(err.message, /GUARDIAN_LAB_USER/)
      return true
    },
  )

  // The same check is exported for callers that prepare a dir themselves.
  const dir = join(base, 'run-check')
  mkdirSync(dir, { mode: 0o700 })
  chmodSync(dir, 0o700)
  assert.throws(() => assertIastTelemetryDirWritable(dir, otherUser), /GUARDIAN_LAB_USER/)
  assert.doesNotThrow(() => assertIastTelemetryDirWritable(dir, `${uid}:${gid}`))
})
