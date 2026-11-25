/**
 * v5 security sprint (HIGH #2, MEDIUM #9, MEDIUM #11) regression tests.
 *
 * HIGH #2  — `--repo` and the patch/recon pipelines must never copy or read through symlinks.
 * MEDIUM #9 — IAST telemetry mounted into a lab container is owner-only and the container is non-root.
 * MEDIUM #11 — worker stdout is bounded per line and in total, terminating on flood.
 */
import assert from 'node:assert/strict'
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  applyUnifiedDiffToDirectory,
  buildLabContainerRunArgs,
  prepareIastTelemetryDir,
  resolveLabContainerUser,
  safeResolveUnderRoot,
} from '../src/server/lab-runner.ts'
import { copyRepoTreeWithoutSymlinks } from '../src/server/patch-workflow.ts'
import { extractStaticFrameworkRoutes, readRepoManifests } from '../src/server/phase0-recon.ts'
import {
  BoundedLineDecoder,
  MAX_WORKER_LINE_BYTES,
  MAX_WORKER_OUTPUT_BYTES,
  WorkerOutputStreamError,
} from '../src/server/worker-backend.ts'
import { mountLocalReposReadOnlyCopy } from '../scripts/cli.ts'

const OUTSIDE_CANARY = 'OUTSIDE-REPO-CANARY-9f2c'

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function hasSymlinkUnder(root: string): boolean {
  const stack = [root]
  while (stack.length > 0) {
    const dir = stack.pop()!
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      const st = lstatSync(full)
      if (st.isSymbolicLink()) return true
      if (st.isDirectory()) stack.push(full)
    }
  }
  return false
}

function buildFixtureRepo(t: { after: (fn: () => void) => void }) {
  const root = makeTempDir(t, 'kovo-sec-repo-')
  const outside = join(root, 'outside')
  mkdirSync(outside, { recursive: true })
  writeFileSync(join(outside, 'outside.ts'), `import express from 'express'\nconst r = express.Router()\nr.get('/outside-route', (_req, res) => res.end('x'))\n`)
  writeFileSync(join(outside, 'outside-manifest.json'), JSON.stringify({ name: 'outside-pkg', dependencies: { 'left-pad': '1.0.0' } }))
  writeFileSync(join(outside, 'secret.txt'), OUTSIDE_CANARY)

  const repo = join(root, 'repo')
  mkdirSync(join(repo, 'src'), { recursive: true })
  writeFileSync(join(repo, 'src', 'app.ts'), `import express from 'express'\nconst app = express()\napp.get('/inside-route', (_req, res) => res.end('ok'))\n`)
  writeFileSync(join(repo, 'package.json'), JSON.stringify({ name: 'inside-pkg', dependencies: { express: '4.0.0' } }))
  symlinkSync('/etc/passwd', join(repo, 'passwd-link.txt'))
  symlinkSync(join(outside, 'secret.txt'), join(repo, 'linked-secret.txt'))
  symlinkSync(outside, join(repo, 'linked-dir'))
  symlinkSync(join(outside, 'outside.ts'), join(repo, 'linked-route.ts'))
  symlinkSync(join(outside, 'outside-manifest.json'), join(repo, 'requirements.txt'))
  return { root, repo, outside }
}

// ============================================================================
// HIGH #2a — CLI repo mount copy never follows symlinks
// ============================================================================

test('cli --repo copy excludes file and directory symlinks and leaves no links in the mounted copy', t => {
  const { root, repo } = buildFixtureRepo(t)
  const dest = join(root, 'mounted')

  const names = mountLocalReposReadOnlyCopy([repo], dest)
  assert.deepEqual(names, ['repo'])
  const mounted = join(dest, 'repo')

  // Legitimate files are copied.
  assert.match(readFileSync(join(mounted, 'src', 'app.ts'), 'utf8'), /inside-route/)
  assert.match(readFileSync(join(mounted, 'package.json'), 'utf8'), /inside-pkg/)

  // Links to host files and outside dirs are never reproduced.
  assert.equal(lstatSafe(join(mounted, 'passwd-link.txt')), false)
  assert.equal(lstatSafe(join(mounted, 'linked-secret.txt')), false)
  assert.equal(lstatSafe(join(mounted, 'linked-dir')), false)
  assert.equal(lstatSafe(join(mounted, 'linked-route.ts')), false)
  assert.equal(hasSymlinkUnder(mounted), false)
  assert.equal(statSafe(join(mounted, 'linked-dir')), false)
})

function lstatSafe(path: string): boolean {
  try {
    lstatSync(path)
    return true
  } catch {
    return false
  }
}

function statSafe(path: string): boolean {
  try {
    statSync(path)
    return true
  } catch {
    return false
  }
}

// ============================================================================
// HIGH #2b — recon walkers and manifest reads ignore symlinks
// ============================================================================

test('recon does not read symlinked manifests or routes', t => {
  const { repo } = buildFixtureRepo(t)

  const manifests = readRepoManifests(repo)
  const names = manifests.map(m => m.name)
  assert.ok(names.includes('package.json'), 'regular manifest is still read')
  assert.equal(names.includes('requirements.txt'), false, 'symlinked manifest is skipped')
  assert.ok(manifests.every(m => !m.content.includes(OUTSIDE_CANARY)), 'outside content is never read')

  const { routes } = extractStaticFrameworkRoutes(repo)
  assert.ok(routes.some(r => r.pathTemplate === '/inside-route'), 'regular route is still extracted')
  assert.equal(routes.some(r => r.pathTemplate.includes('outside-route')), false, 'symlinked route file is never read')
})

// ============================================================================
// HIGH #2c — safeResolveUnderRoot rejects traversal and symlink escapes
// ============================================================================

test('safeResolveUnderRoot rejects traversal, absolute paths and symlinked components', t => {
  const root = makeTempDir(t, 'kovo-safe-resolve-')
  const outside = makeTempDir(t, 'kovo-safe-resolve-out-')
  writeFileSync(join(outside, 'secret.ts'), OUTSIDE_CANARY)
  writeFileSync(join(root, 'app.ts'), 'export const ok = true\n')
  symlinkSync('/etc/passwd', join(root, 'passwd-link.ts'))
  symlinkSync(outside, join(root, 'linked-dir'))

  assert.throws(() => safeResolveUnderRoot(root, '../etc/passwd'), /Unsafe|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, '/etc/passwd'), /Unsafe|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, 'a/../../etc/passwd'), /Unsafe|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, 'passwd-link.ts'), /symlink|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, 'linked-dir/secret.ts'), /symlink|escapes/i)
  assert.throws(() => safeResolveUnderRoot(root, 'linked-dir/new.ts'), /symlink|escapes/i)

  // Legitimate existing files and new files resolve under the root.
  assert.equal(safeResolveUnderRoot(root, 'app.ts'), join(root, 'app.ts'))
  assert.equal(safeResolveUnderRoot(root, 'new-file.ts'), join(root, 'new-file.ts'))
})

test('patch application cannot write through a symlinked target', t => {
  const root = makeTempDir(t, 'kovo-patch-symlink-')
  const outside = makeTempDir(t, 'kovo-patch-symlink-out-')
  const victim = join(outside, 'victim.ts')
  writeFileSync(victim, 'export const value = "original"\n')
  symlinkSync(victim, join(root, 'victim.ts'))
  writeFileSync(join(root, 'safe.ts'), 'export const value = "original"\n')

  const escapeDiff = [
    '--- a/victim.ts',
    '+++ b/victim.ts',
    '@@ -1 +1 @@',
    '-export const value = "original"',
    '+export const value = "pwned"',
    '',
  ].join('\n')
  assert.throws(() => applyUnifiedDiffToDirectory(root, escapeDiff), /symlink|escapes/i)
  assert.equal(readFileSync(victim, 'utf8'), 'export const value = "original"\n', 'outside file is untouched')

  const legitDiff = [
    '--- a/safe.ts',
    '+++ b/safe.ts',
    '@@ -1 +1 @@',
    '-export const value = "original"',
    '+export const value = "patched"',
    '',
  ].join('\n')
  const { filesModified } = applyUnifiedDiffToDirectory(root, legitDiff)
  assert.deepEqual(filesModified, ['safe.ts'])
  assert.match(readFileSync(join(root, 'safe.ts'), 'utf8'), /patched/)
})

test('patch work copy is built without symlinks', t => {
  const { root, repo } = buildFixtureRepo(t)
  const dest = join(root, 'patch-work')

  copyRepoTreeWithoutSymlinks(repo, dest)
  assert.match(readFileSync(join(dest, 'src', 'app.ts'), 'utf8'), /inside-route/)
  assert.equal(hasSymlinkUnder(dest), false)
  assert.equal(lstatSafe(join(dest, 'passwd-link.txt')), false)
  assert.equal(lstatSafe(join(dest, 'linked-dir')), false)
  assert.equal(lstatSafe(join(dest, 'linked-route.ts')), false)
})

// ============================================================================
// MEDIUM #9 — IAST telemetry dir perms + non-root container user
// ============================================================================

test('IAST telemetry dir is owner-only and lab containers run as a non-root user', t => {
  const root = makeTempDir(t, 'kovo-iast-perms-')
  const telemetryDir = join(root, 'telemetry')
  prepareIastTelemetryDir(telemetryDir)

  const mode = statSync(telemetryDir).mode & 0o777
  assert.equal(mode & 0o077, 0, `telemetry dir must not be group/world accessible (mode ${mode.toString(8)})`)
  assert.equal(mode & 0o777, 0o700)

  const user = resolveLabContainerUser()
  assert.match(user, /^\d+:\d+$/)
  assert.notEqual(user.split(':')[0], '0', 'lab container user must not be root')
  assert.throws(() => resolveLabContainerUser({ KOVO_LAB_USER: '0:0' }), /non-root|rejected/i)
  assert.throws(() => resolveLabContainerUser({ KOVO_LAB_USER: 'nobody' }), /numeric/i)

  const runArgs = buildLabContainerRunArgs({
    containerName: 'kovo-lab-app-test',
    networkName: 'kovo-lab-net-test',
    runId: 'run-test',
    serviceName: 'app',
    imageName: 'node:24-bookworm-slim',
    cmd: ['node', '/app/app.js'],
    internalPort: 8080,
    mountArgs: [
      '--mount', `type=bind,source=${telemetryDir},target=/var/run/kovo-iast`,
      '--mount', 'type=bind,source=/repos/app,target=/app,readonly', '--workdir', '/app',
    ],
    env: {},
    extraEnv: { KOVO_IAST_OUT_DIR: '/var/run/kovo-iast' },
    memoryLimit: '512m',
    cpus: '1.0',
    pidsLimit: 128,
    user,
  })

  const userIdx = runArgs.indexOf('--user')
  assert.ok(userIdx >= 0, 'container spec must set --user')
  assert.notEqual(runArgs[userIdx + 1].split(':')[0], '0', 'container spec user must be non-root')
  assert.ok(runArgs.includes('--cap-drop'))
  assert.equal(runArgs[runArgs.indexOf('--cap-drop') + 1], 'ALL')
  assert.ok(runArgs.includes('--read-only'))
  assert.ok(runArgs.some(a => a.includes('target=/var/run/kovo-iast')))

  // The only writable bind mount is the 0700 telemetry dir; /app stays read-only.
  const writableMounts = runArgs.filter(a => a.startsWith('type=bind,') && !a.endsWith('readonly'))
  assert.equal(writableMounts.length, 1)
  assert.match(writableMounts[0], /kovo-iast/)
  assert.equal(mode & 0o002, 0, 'writable telemetry mount must not be world-writable')
})

// ============================================================================
// MEDIUM #11 — bounded worker output
// ============================================================================

test('worker output caps are 64 KiB per line and 4 MiB total', () => {
  assert.equal(MAX_WORKER_LINE_BYTES, 64 * 1024)
  assert.equal(MAX_WORKER_OUTPUT_BYTES, 4 * 1024 * 1024)
})

test('bounded worker decoder passes normal chunked NDJSON through unchanged', () => {
  const decoder = new BoundedLineDecoder()
  assert.deepEqual(decoder.push('{"id":"a","ok":true}\n'), ['{"id":"a","ok":true}'])
  assert.deepEqual(decoder.push('{"id":"b",'), [])
  assert.deepEqual(decoder.push('"ok":true}\r\n'), ['{"id":"b","ok":true}'])
  assert.deepEqual(decoder.push('{"id":"c","ok":true}\n{"id":"d","ok":tru'), ['{"id":"c","ok":true}'])
  assert.deepEqual(decoder.push('e}\n'), ['{"id":"d","ok":true}'])
  assert.equal(decoder.pendingBytes, 0)
})

test('bounded worker decoder rejects a single flood line', () => {
  const decoder = new BoundedLineDecoder()
  assert.throws(
    () => decoder.push(Buffer.alloc(MAX_WORKER_LINE_BYTES + 1, 0x41)),
    (err: unknown) => err instanceof WorkerOutputStreamError && err.limit === 'line',
  )
})

test('bounded worker decoder enforces the total output cap', () => {
  const decoder = new BoundedLineDecoder({ maxLineBytes: 64, maxTotalBytes: 128 })
  assert.deepEqual(decoder.push('{"chunk":"' + 'a'.repeat(40) + '"}\n'), ['{"chunk":"' + 'a'.repeat(40) + '"}'])
  assert.throws(
    () => decoder.push(Buffer.alloc(128, 0x42)),
    (err: unknown) => err instanceof WorkerOutputStreamError && err.limit === 'total',
  )
  assert.ok(decoder.totalBytes > 128)
})
