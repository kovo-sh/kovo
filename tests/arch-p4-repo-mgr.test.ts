import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'
import {
  resyncProjectRepoInStore,
  unlinkProjectRepoInStore,
} from '../src/actions-sources.ts'
import { newProject, newRun } from '../src/domain.ts'
import * as tables from '../src/server/schema.ts'
import {
  clearGithubPat,
  getGithubAuthStatus,
  getGithubPatStatus,
  isLegacyFixtureGithubPatFallbackEnabled,
  listAccessibleGithubRepos,
  readGithubVaultCredential,
  resolveFreshGithubCredential,
  saveGithubPat,
  saveGithubVaultCredential,
} from '../src/server/github-auth.ts'
import {
  RepoDiskQuotaExceededError,
  RepoWorkspaceBusyError,
  RepoWorkspaceManager,
  buildHardenedGitCloneArgs,
  cleanupOrphanedRepoDirs,
  cloneGithubRepos,
  isRepoOperationLocked,
  listMountedRepos,
  projectReposDir,
  readRepoCommitDiffs,
  unlinkProjectMountedRepo,
  unlinkProjectMountedRepoLocked,
  verifyAndStripRepoSymlinks,
  withRepoOperationLock,
} from '../src/server/github-repo-sync.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function runGitSync(cwd: string, args: string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

function createBareOriginRepo(
  workDir: string,
  owner: string,
  repo: string,
  commits: Array<{
    message: string
    files?: Record<string, string>
    symlinks?: Record<string, string>
  }>,
): { originRoot: string; barePath: string; sourcePath: string } {
  const originRoot = join(workDir, 'git-origin')
  const sourcePath = join(workDir, `src-${owner}-${repo}-${randomUUID().slice(0, 6)}`)
  const barePath = join(originRoot, owner, `${repo}.git`)
  mkdirSync(sourcePath, { recursive: true })
  mkdirSync(join(originRoot, owner), { recursive: true })

  execFileSync('git', ['init', '-b', 'main', sourcePath], { stdio: 'ignore' })
  runGitSync(sourcePath, ['config', 'user.email', 'qa@example.test'])
  runGitSync(sourcePath, ['config', 'user.name', 'QA Bot'])

  for (const commit of commits) {
    for (const [relPath, content] of Object.entries(commit.files ?? {})) {
      const fullPath = join(sourcePath, relPath)
      mkdirSync(join(fullPath, '..'), { recursive: true })
      writeFileSync(fullPath, content)
    }
    for (const [relPath, target] of Object.entries(commit.symlinks ?? {})) {
      const fullPath = join(sourcePath, relPath)
      mkdirSync(join(fullPath, '..'), { recursive: true })
      rmSync(fullPath, { force: true })
      symlinkSync(target, fullPath)
    }
    runGitSync(sourcePath, ['add', '-A'])
    runGitSync(sourcePath, ['commit', '-m', commit.message])
  }

  rmSync(barePath, { recursive: true, force: true })
  execFileSync('git', ['clone', '--bare', sourcePath, barePath], { stdio: 'ignore' })
  return { originRoot, barePath, sourcePath }
}

function writeTestPat(dir: string, token = 'github_pat_11TEST_REPO_MGR_SECRET_9876543210'): string {
  const patPath = join(dir, 'test-github.pat')
  writeFileSync(patPath, `${token}\n`, { mode: 0o600 })
  chmodSync(patPath, 0o600)
  return patPath
}

test('per-repo locking serializes concurrent operations on the same (projectId, repoSlug) while allowing distinct repos in parallel', async t => {
  const dataDir = makeTempDir(t, 'kovo-p4-lock-')
  const reposDir = projectReposDir(dataDir, 'proj-lock')
  mkdirSync(reposDir, { recursive: true })

  const timeline: string[] = []
  let activeSameRepo = 0
  let maxActiveSameRepo = 0

  const hold = (label: string, ms: number) =>
    withRepoOperationLock(reposDir, 'acme/service', async () => {
      assert.equal(isRepoOperationLocked(reposDir, 'acme/service'), true)
      activeSameRepo += 1
      maxActiveSameRepo = Math.max(maxActiveSameRepo, activeSameRepo)
      timeline.push(`${label}:start`)
      await new Promise(resolvePromise => setTimeout(resolvePromise, ms))
      timeline.push(`${label}:end`)
      activeSameRepo -= 1
      return label
    })

  // Distinct repo should NOT block on acme/service
  let siblingCompletedWhileLocked = false
  const first = hold('op1', 60)
  const second = hold('op2', 30)
  const sibling = withRepoOperationLock(reposDir, 'acme/other-service', async () => {
    await new Promise(resolvePromise => setTimeout(resolvePromise, 10))
    if (isRepoOperationLocked(reposDir, 'acme/service')) {
      siblingCompletedWhileLocked = true
    }
    return 'sibling'
  })

  // Aborting a queued waiter must reject immediately without breaking subsequent waiters
  const ac = new AbortController()
  const abortedWaiter = withRepoOperationLock(reposDir, 'acme/service', async () => {
    timeline.push('aborted:should-not-run')
    return 'bad'
  }, { signal: ac.signal })
  const third = hold('op3', 10)
  ac.abort(new Error('caller cancelled'))

  await assert.rejects(() => abortedWaiter, /caller cancelled/)
  const results = await Promise.all([first, second, third, sibling])

  assert.deepEqual(results, ['op1', 'op2', 'op3', 'sibling'])
  assert.equal(maxActiveSameRepo, 1, 'Same repo operations must never overlap')
  assert.equal(siblingCompletedWhileLocked, true, 'Different repo slugs must not block each other')
  assert.deepEqual(timeline, ['op1:start', 'op1:end', 'op2:start', 'op2:end', 'op3:start', 'op3:end'])
  assert.equal(isRepoOperationLocked(reposDir, 'acme/service'), false)

  // Synchronous unlink refuses while lock is held; locked async unlink waits cleanly and succeeds
  const repoDir = join(reposDir, 'acme', 'service')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'index.ts'), 'export const x = 1\n')

  let releaseLock!: () => void
  const heldGate = new Promise<void>(resolvePromise => { releaseLock = resolvePromise })
  let enteredLock!: () => void
  const enteredPromise = new Promise<void>(resolvePromise => { enteredLock = resolvePromise })

  const holder = withRepoOperationLock(reposDir, 'acme/service', async () => {
    enteredLock()
    await heldGate
  })
  await enteredPromise

  assert.throws(
    () => unlinkProjectMountedRepo(dataDir, 'proj-lock', 'acme/service'),
    err => err instanceof RepoWorkspaceBusyError && err.code === 'REPO_SYNC_IN_PROGRESS',
  )

  const queuedUnlink = unlinkProjectMountedRepoLocked(dataDir, 'proj-lock', 'acme/service')
  releaseLock()
  await holder
  const unlinkRes = await queuedUnlink
  assert.deepEqual(unlinkRes, { unlinked: true, fullName: 'acme/service' })
  assert.equal(existsSync(repoDir), false)
})

test('active-run protection blocks destructive unlink/resync and unlinking purges phantom repo-derived specs', async t => {
  const dir = makeTempDir(t, 'kovo-p4-store-')
  const store = new Store(dir, { ftsMode: 'preview' })
  t.after(() => store.close())

  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name: 'Active Run Guard Project',
    seeds: ['https://app.example.test'],
  }))

  const patPath = writeTestPat(dir)
  const { originRoot } = createBareOriginRepo(dir, 'acme', 'demo-app', [
    {
      message: 'initial',
      files: {
        'package.json': JSON.stringify({ name: 'demo-app', dependencies: { express: '^4.19.0' } }),
        'openapi.yaml': 'openapi: 3.1.0\ninfo:\n  title: Demo\n  version: 1.0.0\npaths: {}\n',
      },
    },
  ])

  // Initial sync succeeds with no active runs
  const firstSync = await resyncProjectRepoInStore(store, project.id, 'acme/demo-app', {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
  })
  assert.equal(firstSync.fullName, 'acme/demo-app')
  assert.ok(firstSync.specsImported >= 2)

  // Add a stale repo-derived spec AND an unrelated manual spec
  store.upsertProjectSpecRaw(project.id, {
    name: 'acme/demo-app:removed-schema.yaml',
    kind: 'openapi',
    content: 'openapi: 3.0.0\npaths: {}\n',
  })
  store.importProjectSpec({
    requestId: randomUUID(),
    projectId: project.id,
    name: 'manual-notes.md',
    kind: 'notes',
    content: 'Keep this manual spec intact.',
  })

  // Start an active run on the project (transition to running status)
  const run = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify active run mount protection',
  }))
  store.db.update(tables.runs).set({ status: 'running' }).where(eq(tables.runs.id, run.id)).run()
  assert.equal(store.isRunActive(run.id), true)

  // Both unlink and resync MUST be refused with a clear operator-facing error while the run is active
  assert.throws(
    () => unlinkProjectRepoInStore(store, project.id, 'acme/demo-app'),
    new RegExp(`Cannot unlink repository "acme/demo-app".*active run.*${run.id}`, 'i'),
  )
  await assert.rejects(
    () => resyncProjectRepoInStore(store, project.id, 'acme/demo-app', {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
    }),
    new RegExp(`Cannot re-sync repository "acme/demo-app".*active run.*${run.id}`, 'i'),
  )

  // RepoWorkspaceManager activeRunChecker also refuses both sync and unlink
  const mgr = new RepoWorkspaceManager({
    activeRunChecker: () => [run.id],
  })
  await assert.rejects(
    () => mgr.syncRepos(dir, project.id, ['acme/demo-app'], undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
    }),
    err => err instanceof RepoWorkspaceBusyError && err.code === 'REPO_ACTIVE_RUN_LOCKED',
  )
  await assert.rejects(
    () => mgr.unlinkRepo(dir, project.id, 'acme/demo-app'),
    err => err instanceof RepoWorkspaceBusyError && err.code === 'REPO_ACTIVE_RUN_LOCKED',
  )

  // Mounted checkout and all specs remain intact after refused mutations
  assert.deepEqual(listMountedRepos(projectReposDir(dir, project.id)), ['/repos/acme/demo-app'])

  // Stop the active run
  store.command({ requestId: randomUUID(), runId: run.id, action: 'stop' })
  assert.equal(store.isRunActive(run.id), false)

  // Resync succeeds now and prunes the stale repo-derived spec while preserving manual-notes.md
  await resyncProjectRepoInStore(store, project.id, 'acme/demo-app', {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
  })
  const specsAfterResync = store.listProjectSpecs(project.id).map(s => s.name)
  assert.equal(specsAfterResync.includes('acme/demo-app:removed-schema.yaml'), false)
  assert.equal(specsAfterResync.includes('acme/demo-app:inventory'), true)
  assert.equal(specsAfterResync.includes('manual-notes.md'), true)

  // Unlink removes the mounted checkout AND all phantom repo-derived specs, preserving manual specs
  const unlinked = unlinkProjectRepoInStore(store, project.id, 'acme/demo-app')
  assert.deepEqual(unlinked, { unlinked: true, fullName: 'acme/demo-app' })
  assert.deepEqual(listMountedRepos(projectReposDir(dir, project.id)), [])
  const specsAfterUnlink = store.listProjectSpecs(project.id).map(s => s.name)
  assert.deepEqual(specsAfterUnlink, ['manual-notes.md'])
})

test('orphan .tmp-* and .old-* checkout directories are deterministically cleaned up without touching real repos or symlink targets', async t => {
  const work = makeTempDir(t, 'kovo-p4-orphan-')
  const reposDir = projectReposDir(work, 'proj-orphan')
  const outsideSecret = join(work, 'outside-secret')
  mkdirSync(outsideSecret, { recursive: true })
  writeFileSync(join(outsideSecret, 'keep.txt'), 'do-not-touch')

  // Create valid mounted repo + stale orphans + empty-after-cleanup owner + symlink orphan
  mkdirSync(join(reposDir, 'acme', 'live-repo'), { recursive: true })
  writeFileSync(join(reposDir, 'acme', 'live-repo', 'README.md'), '# live\n')
  mkdirSync(join(reposDir, 'acme', '.tmp-live-repo-crashed-1'), { recursive: true })
  writeFileSync(join(reposDir, 'acme', '.tmp-live-repo-crashed-1', 'partial.txt'), 'stale')
  mkdirSync(join(reposDir, 'acme', '.old-live-repo-crashed-2'), { recursive: true })
  mkdirSync(join(reposDir, 'ghost-owner', '.tmp-orphan-only'), { recursive: true })
  mkdirSync(join(reposDir, '.tmp-root-orphan'), { recursive: true })
  symlinkSync(outsideSecret, join(reposDir, 'acme', '.tmp-evil-link'))

  const cleaned = cleanupOrphanedRepoDirs(reposDir)
  assert.deepEqual(cleaned.warnings, [])
  assert.deepEqual(cleaned.removed, [
    '.tmp-root-orphan',
    'acme/.old-live-repo-crashed-2',
    'acme/.tmp-evil-link',
    'acme/.tmp-live-repo-crashed-1',
    'ghost-owner/.tmp-orphan-only',
  ])

  assert.equal(existsSync(join(reposDir, 'acme', 'live-repo', 'README.md')), true)
  assert.equal(existsSync(join(reposDir, 'ghost-owner')), false, 'Empty owner dir should be pruned')
  assert.equal(existsSync(join(outsideSecret, 'keep.txt')), true, 'Symlink target outside root must never be touched')

  // Also verify cloneGithubRepos automatically sweeps stale orphans during sync
  const patPath = writeTestPat(work)
  const { originRoot } = createBareOriginRepo(work, 'acme', 'fresh-repo', [
    { message: 'init', files: { 'README.md': 'hello\n' } },
  ])
  mkdirSync(join(reposDir, 'acme', '.tmp-stale-before-sync'), { recursive: true })
  mkdirSync(join(reposDir, 'acme', '.old-stale-before-sync'), { recursive: true })

  await cloneGithubRepos(['acme/fresh-repo'], reposDir, undefined, {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
  })
  assert.equal(existsSync(join(reposDir, 'acme', '.tmp-stale-before-sync')), false)
  assert.equal(existsSync(join(reposDir, 'acme', '.old-stale-before-sync')), false)
  assert.equal(existsSync(join(reposDir, 'acme', 'fresh-repo', 'README.md')), true)
})

test('disk quotas enforce pre-clone size cap, per-repo on-disk quota, and per-project combined quota', async t => {
  const work = makeTempDir(t, 'kovo-p4-quota-')
  const patPath = writeTestPat(work)
  const reposDir = projectReposDir(work, 'proj-quota')

  // 1. Pre-clone GitHub API size check rejects oversized repo BEFORE spawning git
  let fetchCalled = false
  const oversizedApiFetch: typeof fetch = async () => {
    fetchCalled = true
    return new Response(JSON.stringify({ size: 2048 }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
  await assert.rejects(
    () => cloneGithubRepos(['acme/huge-repo'], reposDir, undefined, {
      patPath,
      apiBaseUrl: 'https://api.github.test',
      gitBaseUrl: 'https://github.test',
      fetchImpl: oversizedApiFetch,
      maxRepoDiskBytes: 512 * 1024,
    }),
    err => err instanceof RepoDiskQuotaExceededError && err.scope === 'repo' && err.actualBytes === 2048 * 1024,
  )
  assert.equal(fetchCalled, true)

  // 2. Post-clone on-disk per-repo quota rejects oversized checkout and preserves existing mounted checkout
  const { originRoot } = createBareOriginRepo(work, 'acme', 'big-local', [
    {
      message: 'large payload',
      files: {
        'blob.txt': 'A'.repeat(32 * 1024),
      },
    },
  ])
  const existingDir = join(reposDir, 'acme', 'big-local')
  mkdirSync(existingDir, { recursive: true })
  writeFileSync(join(existingDir, 'previous.txt'), 'still-here')

  await assert.rejects(
    () => cloneGithubRepos(['acme/big-local'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      stripGitMetadata: true,
      maxRepoDiskBytes: 8 * 1024,
    }),
    err => err instanceof RepoDiskQuotaExceededError && err.scope === 'repo',
  )
  assert.equal(readFileSync(join(existingDir, 'previous.txt'), 'utf8'), 'still-here')
  assert.deepEqual(cleanupOrphanedRepoDirs(reposDir).removed, [], 'Failed quota clone must not leave orphan staging dirs')

  // 3. Per-project combined disk quota rejects second repo when sum exceeds maxProjectDiskBytes
  rmSync(existingDir, { recursive: true, force: true })
  const repoA = createBareOriginRepo(work, 'acme', 'repo-a', [
    { message: 'init a', files: { 'data.txt': 'X'.repeat(14 * 1024) } },
  ])
  createBareOriginRepo(work, 'acme', 'repo-b', [
    { message: 'init b', files: { 'data.txt': 'Y'.repeat(14 * 1024) } },
  ])

  const mgr = new RepoWorkspaceManager({
    maxRepoDiskBytes: 32 * 1024,
    maxProjectDiskBytes: 20 * 1024,
  })
  const syncedA = await mgr.syncRepos(work, 'proj-quota', ['acme/repo-a'], undefined, {
    patPath,
    gitBaseUrl: `file://${repoA.originRoot}`,
    allowLocalFileProtocol: true,
    stripGitMetadata: true,
  })
  assert.equal(syncedA.length, 1)

  await assert.rejects(
    () => mgr.syncRepos(work, 'proj-quota', ['acme/repo-b'], undefined, {
      patPath,
      gitBaseUrl: `file://${repoA.originRoot}`,
      allowLocalFileProtocol: true,
      stripGitMetadata: true,
    }),
    err => err instanceof RepoDiskQuotaExceededError && err.scope === 'project',
  )
  assert.deepEqual(listMountedRepos(reposDir), ['/repos/acme/repo-a'])
})

test('git hardening enforces shallow --depth 1, disables hooks/submodules/file protocol, and rejects escaping symlinks', async t => {
  const work = makeTempDir(t, 'kovo-p4-git-hardening-')
  const patPath = writeTestPat(work)

  // 1. Verify hardened clone argv for production HTTPS origins
  const prodArgs = buildHardenedGitCloneArgs({
    repoUrl: 'https://github.com/acme/app.git',
    stagingDir: '/tmp/stage',
  })
  assert.ok(prodArgs.includes('core.hooksPath=/dev/null'))
  assert.ok(prodArgs.includes('core.fsmonitor=false'))
  assert.ok(prodArgs.includes('core.symlinks=false'))
  assert.ok(prodArgs.includes('protocol.file.allow=never'))
  assert.ok(prodArgs.includes('protocol.ext.allow=never'))
  assert.ok(prodArgs.includes('submodule.recurse=false'))
  assert.ok(prodArgs.includes('fetch.recurseSubmodules=false'))
  assert.ok(prodArgs.includes('--single-branch'))
  assert.ok(prodArgs.includes('--no-tags'))
  assert.ok(prodArgs.includes('--no-recurse-submodules'))
  assert.equal(prodArgs[prodArgs.indexOf('--depth') + 1], '1')

  // 2. Reject file:// git origin when allowLocalFileProtocol is explicitly false
  await assert.rejects(
    () => cloneGithubRepos(['acme/app'], join(work, 'out-no-file'), undefined, {
      patPath,
      gitBaseUrl: `file://${work}`,
      allowLocalFileProtocol: false,
    }),
    /file:\/\/ protocol is disabled/i,
  )

  // 3. Default shallow clone (--depth 1) only fetches 1 commit from a 3-commit origin
  const multiCommit = createBareOriginRepo(work, 'acme', 'shallow-app', [
    { message: 'commit 1', files: { 'a.ts': 'export const v = 1\n' } },
    { message: 'commit 2', files: { 'a.ts': 'export const v = 2\n' } },
    { message: 'commit 3', files: { 'a.ts': 'export const v = 3\n' } },
  ])
  const shallowRepos = await cloneGithubRepos(['acme/shallow-app'], join(work, 'shallow-root'), undefined, {
    patPath,
    gitBaseUrl: `file://${multiCommit.originRoot}`,
    allowLocalFileProtocol: true,
  })
  assert.equal(shallowRepos.length, 1)
  assert.equal(shallowRepos[0]!.gitHistory?.depth, 1)
  const commitCount = Number(runGitSync(shallowRepos[0]!.localPath!, ['rev-list', '--count', 'HEAD']))
  assert.equal(commitCount, 1, 'Default clone must be shallow (--depth 1)')

  // Verify readRepoCommitDiffs works cleanly with hardened --no-ext-diff args
  const diffRes = readRepoCommitDiffs(shallowRepos[0]!.localPath!, { maxCommits: 5 })
  assert.equal(diffRes.available, true)
  assert.equal(diffRes.commitsScanned, 1)

  // 4. Committed escaping symlink (git mode 120000 -> /etc/passwd) is rejected and never swapped into finalDir
  const evilRepo = createBareOriginRepo(work, 'acme', 'evil-symlink', [
    {
      message: 'add escaping symlink',
      files: { 'README.md': 'benign\n' },
      symlinks: { 'leak.txt': '/etc/passwd' },
    },
  ])
  const evilRoot = join(work, 'evil-root')
  await assert.rejects(
    () => cloneGithubRepos(['acme/evil-symlink'], evilRoot, undefined, {
      patPath,
      gitBaseUrl: `file://${evilRepo.originRoot}`,
      allowLocalFileProtocol: true,
    }),
    /symlink escaping checkout root/i,
  )
  assert.equal(existsSync(join(evilRoot, 'acme', 'evil-symlink')), false)

  // 5. verifyAndStripRepoSymlinks strips in-tree OS symlinks unconditionally and rejects out-of-tree OS symlinks
  const treeA = join(work, 'tree-intree')
  mkdirSync(treeA, { recursive: true })
  writeFileSync(join(treeA, 'target.txt'), 'ok')
  symlinkSync('./target.txt', join(treeA, 'local-link.txt'))
  const strippedInTree = verifyAndStripRepoSymlinks(treeA)
  assert.deepEqual(strippedInTree.removedSymlinks, ['local-link.txt'])
  assert.deepEqual(strippedInTree.escapingSymlinks, [])
  assert.equal(existsSync(join(treeA, 'local-link.txt')), false)
  assert.equal(existsSync(join(treeA, 'target.txt')), true)

  const treeB = join(work, 'tree-escape')
  mkdirSync(treeB, { recursive: true })
  symlinkSync('/etc/passwd', join(treeB, 'escape-link'))
  assert.throws(
    () => verifyAndStripRepoSymlinks(treeB),
    /symlink escaping checkout root/i,
  )
  assert.equal(existsSync(join(treeB, 'escape-link')), false)
})

test('OAuth single-flight refresh isolates caller abort signals, clears cached installations, and rejects unrefreshable expired tokens', async t => {
  const dataDir = makeTempDir(t, 'kovo-p4-oauth-')
  const testClientId = 'Iv23liISOLATIONTEST01'
  const oldAccess = 'ghu_11OLD_ACCESS_TOKEN_FOR_ISOLATION_001'
  const oldRefresh = 'ghr_11OLD_REFRESH_TOKEN_FOR_ISOLATION_002'
  const newAccess = 'ghu_11NEW_ROTATED_ACCESS_TOKEN_ISOL_003'
  const newRefresh = 'ghr_11NEW_ROTATED_REFRESH_TOKEN_ISOL_004'

  saveGithubVaultCredential(dataDir, {
    accessToken: oldAccess,
    refreshToken: oldRefresh,
    expiresAt: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
    refreshTokenExpiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    clientId: testClientId,
    login: 'octo-iso',
    authKind: 'github_app_device',
  })

  let refreshFetchCalls = 0
  let fetchSignalAborted = false
  let releaseRefresh!: () => void
  const refreshGate = new Promise<void>(resolvePromise => { releaseRefresh = resolvePromise })
  let refreshStarted!: () => void
  const refreshStartedPromise = new Promise<void>(resolvePromise => { refreshStarted = resolvePromise })

  const mockFetch: typeof fetch = async (_url, init) => {
    refreshFetchCalls += 1
    refreshStarted()
    await refreshGate
    fetchSignalAborted = Boolean(init?.signal?.aborted)
    if (init?.signal?.aborted) {
      throw init.signal.reason ?? new DOMException('Aborted', 'AbortError')
    }
    return new Response(JSON.stringify({
      access_token: newAccess,
      refresh_token: newRefresh,
      expires_in: 28800,
      refresh_token_expires_in: 15897600,
    }), { status: 200, headers: { 'content-type': 'application/json' } })
  }

  const acA = new AbortController()
  const acB = new AbortController()

  // Caller A starts the shared single-flight refresh; Caller B joins it
  const callerA = resolveFreshGithubCredential({ dataDir, fetchImpl: mockFetch, signal: acA.signal })
  await refreshStartedPromise
  const callerB = resolveFreshGithubCredential({ dataDir, fetchImpl: mockFetch, signal: acB.signal })

  // Caller A cancels while refresh is in flight
  acA.abort(new Error('caller A cancelled'))
  await assert.rejects(() => callerA, /caller A cancelled/)

  // Allow shared refresh to complete — Caller B MUST still succeed!
  releaseRefresh()
  const credB = await callerB
  assert.equal(refreshFetchCalls, 1, 'Concurrent callers must share one single-flight refresh')
  assert.equal(fetchSignalAborted, false, 'Caller A abort must NEVER abort the underlying refresh fetch')
  assert.equal(credB.accessToken, newAccess)
  assert.equal(credB.refreshToken, newRefresh)

  const persisted = readGithubVaultCredential(join(dataDir, 'credentials', 'github.pat'))
  assert.equal(persisted.accessToken, newAccess)
  assert.equal(statSync(join(dataDir, 'credentials', 'github.pat')).mode & 0o777, 0o600)

  // Cached installations observed under an older token must be cleared on refresh
  const listFetch: typeof fetch = async input => {
    const u = String(input)
    if (u.includes('/user/installations')) {
      return new Response(JSON.stringify({ installations: [] }), { status: 200 })
    }
    return new Response(JSON.stringify([]), { status: 200 })
  }
  await listAccessibleGithubRepos({ dataDir, fetchImpl: listFetch })
  assert.equal(getGithubAuthStatus(dataDir).needsAppInstall, true)

  // Force another near-expiry refresh and confirm observed installations are cleared
  saveGithubVaultCredential(dataDir, {
    accessToken: newAccess,
    refreshToken: newRefresh,
    expiresAt: new Date(Date.now() + 60 * 1000).toISOString(),
    clientId: testClientId,
    login: 'octo-iso',
    authKind: 'github_app_device',
  })
  // Re-seed observation for newAccess, then trigger refresh
  await listAccessibleGithubRepos({
    dataDir,
    fetchImpl: async input => {
      const u = String(input)
      if (u.includes('/login/oauth/access_token')) {
        return new Response(JSON.stringify({
          access_token: 'ghu_11THIRD_ROTATED_ACCESS_TOKEN_005',
          refresh_token: 'ghr_11THIRD_ROTATED_REFRESH_TOKEN_006',
          expires_in: 28800,
        }), { status: 200 })
      }
      if (u.includes('/user/installations')) {
        return new Response(JSON.stringify({ installations: [{ id: 77, account: { login: 'acme', type: 'Organization' }, repository_selection: 'all' }] }), { status: 200 })
      }
      return new Response(JSON.stringify([]), { status: 200 })
    },
  })
  assert.equal(getGithubAuthStatus(dataDir).installations?.length, 1)

  // Now expire the token with no refresh token -> must reject instead of silently passing through
  const expiredDir = makeTempDir(t, 'kovo-p4-expired-')
  saveGithubVaultCredential(expiredDir, {
    accessToken: 'ghu_11ALREADY_EXPIRED_NO_REFRESH_007',
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
    authKind: 'github_app_device',
  })
  await assert.rejects(
    () => resolveFreshGithubCredential({ dataDir: expiredDir }),
    /expired and cannot be refreshed/i,
  )
})

test('production paths do not silently fall back to legacy host fixture PAT unless KOVO_ALLOW_FIXTURE_GITHUB_PAT=1', async t => {
  const work = makeTempDir(t, 'kovo-p4-fixture-')
  const dataDir = join(work, 'workspace')
  mkdirSync(dataDir, { recursive: true })
  const fixturePath = join(work, 'legacy-fixture.pat')
  writeFileSync(fixturePath, 'github_pat_11LEGACY_FIXTURE_TOKEN_SHOULD_NOT_LEAK\n', { mode: 0o600 })
  chmodSync(fixturePath, 0o600)

  const prevAllow = process.env.KOVO_ALLOW_FIXTURE_GITHUB_PAT
  const prevPath = process.env.KOVO_GITHUB_FIXTURE_PAT_PATH
  delete process.env.KOVO_ALLOW_FIXTURE_GITHUB_PAT
  process.env.KOVO_GITHUB_FIXTURE_PAT_PATH = fixturePath

  t.after(() => {
    if (prevAllow === undefined) delete process.env.KOVO_ALLOW_FIXTURE_GITHUB_PAT
    else process.env.KOVO_ALLOW_FIXTURE_GITHUB_PAT = prevAllow
    if (prevPath === undefined) delete process.env.KOVO_GITHUB_FIXTURE_PAT_PATH
    else process.env.KOVO_GITHUB_FIXTURE_PAT_PATH = prevPath
  })

  assert.equal(isLegacyFixtureGithubPatFallbackEnabled(), false)
  assert.deepEqual(getGithubPatStatus(dataDir), { configured: false, source: null, tokenKind: null })
  assert.equal(getGithubAuthStatus(dataDir).configured, false)
  await assert.rejects(
    () => resolveFreshGithubCredential({ dataDir }),
    /GitHub is not connected/i,
  )

  // Save a vault PAT then clear it -> must NOT silently fall back to fixturePath
  saveGithubPat(dataDir, 'github_pat_11REAL_VAULT_PAT_TO_CLEAR_001')
  assert.equal(getGithubPatStatus(dataDir).source, 'vault')
  const cleared = clearGithubPat(dataDir)
  assert.equal(cleared.cleared, true)
  assert.deepEqual(cleared.status, { configured: false, source: null, tokenKind: null })

  // Only explicit dev env opt-in enables legacy fixture fallback
  process.env.KOVO_ALLOW_FIXTURE_GITHUB_PAT = '1'
  assert.equal(isLegacyFixtureGithubPatFallbackEnabled(), true)
  assert.deepEqual(getGithubPatStatus(dataDir), {
    configured: true,
    source: 'fixture',
    tokenKind: 'fine_grained',
  })
  const cred = await resolveFreshGithubCredential({ dataDir })
  assert.equal(cred.accessToken, 'github_pat_11LEGACY_FIXTURE_TOKEN_SHOULD_NOT_LEAK')
})

test('actions-sources.ts keeps zero top-level ./server/* runtime imports for Vite browser safety', () => {
  const src = readFileSync(join(REPO_ROOT, 'src/actions-sources.ts'), 'utf8')
  const topLevelServerValueImports = src
    .split('\n')
    .filter(line => /^\s*import\s+(?!type\b).*['"]\.\/server\//.test(line))
  assert.deepEqual(topLevelServerValueImports, [])
})
