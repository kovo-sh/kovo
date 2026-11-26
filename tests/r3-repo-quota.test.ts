import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  DEFAULT_MAX_REPO_DEPTH,
  DEFAULT_MAX_REPO_FILES,
  RepoDepthLimitExceededError,
  RepoDiskQuotaExceededError,
  RepoFileLimitExceededError,
  RepoWorkspaceManager,
  buildHardenedGitCloneArgs,
  cleanupOrphanedRepoDirs,
  cloneGithubRepos,
  listMountedRepos,
  listProjectMountedRepos,
  measureDirectoryBytes,
  measureProjectDiskBytes,
  projectReposDir,
} from '../src/server/github-repo-sync.ts'
import {
  DEFAULT_MAX_STAGE_BYTES,
  DEFAULT_MAX_STAGE_DEPTH,
  DEFAULT_MAX_STAGE_FILES,
  RepoStagingQuotaExceededError,
  prepareReposMount,
  stageReadableReposTree,
} from '../src/server/worker-backend.ts'

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
  files: Record<string, string | Buffer>,
): { originRoot: string; barePath: string } {
  const originRoot = join(workDir, 'git-origin')
  const sourcePath = join(workDir, `src-${owner}-${repo}-${randomUUID().slice(0, 6)}`)
  const barePath = join(originRoot, owner, `${repo}.git`)
  mkdirSync(sourcePath, { recursive: true })
  mkdirSync(join(originRoot, owner), { recursive: true })

  execFileSync('git', ['init', '-b', 'main', sourcePath], { stdio: 'ignore' })
  runGitSync(sourcePath, ['config', 'user.email', 'qa@example.test'])
  runGitSync(sourcePath, ['config', 'user.name', 'QA Bot'])

  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(sourcePath, relPath)
    mkdirSync(join(fullPath, '..'), { recursive: true })
    writeFileSync(fullPath, content)
  }
  runGitSync(sourcePath, ['add', '-A'])
  runGitSync(sourcePath, ['commit', '-m', 'init'])

  rmSync(barePath, { recursive: true, force: true })
  execFileSync('git', ['clone', '--bare', sourcePath, barePath], { stdio: 'ignore' })
  return { originRoot, barePath }
}

function writeTestPat(dir: string): string {
  const patPath = join(dir, 'test-github.pat')
  writeFileSync(patPath, 'github_pat_11TEST_R3_REPO_QUOTA_0123456789\n', { mode: 0o600 })
  chmodSync(patPath, 0o600)
  return patPath
}

function buildNestedPath(levels: number, fileName = 'leaf.txt'): string {
  const dirs = Array.from({ length: levels }, (_, i) => `d${String(i + 1).padStart(2, '0')}`)
  return [...dirs, fileName].join('/')
}

test('R3-H-17: buildHardenedGitCloneArgs enforces --no-checkout by default and cloneGithubRepos writes zero working-tree files prior to pre-checkout inspection', async t => {
  const args = buildHardenedGitCloneArgs({
    repoUrl: 'https://github.com/acme/sample.git',
    stagingDir: '/tmp/stage',
  })
  assert.ok(args.includes('--no-checkout'), 'hardened clone args must include --no-checkout by default')

  const work = makeTempDir(t, 'kovo-r3-nocheckout-')
  const patPath = writeTestPat(work)
  const reposDir = projectReposDir(work, 'proj-nocheckout')
  const { originRoot } = createBareOriginRepo(work, 'acme', 'clean-app', {
    'README.md': '# clean app\n',
    'src/index.ts': 'export const ok = true\n',
  })

  let observedEntriesBeforeCheckout: string[] | null = null
  const observedSummaries: Array<{ blobBytes: number; fileCount: number; maxDepth: number }> = []
  const synced = await cloneGithubRepos(['acme/clean-app'], reposDir, undefined, {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
    onBeforeCheckout: info => {
      observedEntriesBeforeCheckout = readdirSync(info.stagingDir).sort()
      observedSummaries.push({
        blobBytes: info.blobBytes,
        fileCount: info.fileCount,
        maxDepth: info.maxDepth,
      })
    },
  })

  assert.equal(synced.length, 1)
  assert.deepEqual(
    observedEntriesBeforeCheckout,
    ['.git'],
    'only .git may exist in stagingDir prior to git checkout',
  )
  assert.equal(observedSummaries.length, 1)
  assert.equal(observedSummaries[0]!.fileCount, 2)
  assert.equal(observedSummaries[0]!.maxDepth, 1)
  assert.ok(observedSummaries[0]!.blobBytes >= 30)
  assert.equal(existsSync(join(reposDir, 'acme', 'clean-app', 'src', 'index.ts')), true)
})

test('R3-H-17: compression-amplified blob bomb and project quota overrun are rejected BEFORE git checkout', async t => {
  const work = makeTempDir(t, 'kovo-r3-bomb-')
  const patPath = writeTestPat(work)
  const reposDir = projectReposDir(work, 'proj-bomb')

  // 4 MiB of repeated zeros compresses to ~4 KiB in git packfile, far smaller than the 128 KiB cap,
  // but uncompressed blob bytes (4 MiB) must be caught via `git ls-tree` BEFORE checkout.
  const fourMiB = Buffer.alloc(4 * 1024 * 1024, 'A')
  const { originRoot } = createBareOriginRepo(work, 'acme', 'zip-bomb', {
    'compressible-bomb.bin': fourMiB,
  })

  let checkoutReached = false
  await assert.rejects(
    () => cloneGithubRepos(['acme/zip-bomb'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      maxRepoDiskBytes: 128 * 1024,
      onBeforeCheckout: () => {
        checkoutReached = true
      },
    }),
    err => err instanceof RepoDiskQuotaExceededError
      && err.scope === 'repo'
      && err.actualBytes >= 4 * 1024 * 1024
      && err.quotaBytes === 128 * 1024,
  )
  assert.equal(checkoutReached, false, 'oversized compressible blob must be rejected BEFORE checkout')
  assert.equal(existsSync(join(reposDir, 'acme', 'zip-bomb')), false)
  assert.deepEqual(cleanupOrphanedRepoDirs(reposDir).removed, [])

  // Project-level combined quota also rejects BEFORE checkout.
  createBareOriginRepo(work, 'acme', 'small-a', {
    'a.txt': 'X'.repeat(20 * 1024),
  })
  createBareOriginRepo(work, 'acme', 'small-b', {
    'b.txt': 'Y'.repeat(40 * 1024),
  })

  const mgr = new RepoWorkspaceManager({
    maxRepoDiskBytes: 128 * 1024,
    maxProjectDiskBytes: 48 * 1024,
  })
  await mgr.syncRepos(work, 'proj-bomb', ['acme/small-a'], undefined, {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
    stripGitMetadata: true,
  })

  let secondCheckoutReached = false
  await assert.rejects(
    () => mgr.syncRepos(work, 'proj-bomb', ['acme/small-b'], undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      stripGitMetadata: true,
      onBeforeCheckout: () => {
        secondCheckoutReached = true
      },
    }),
    err => err instanceof RepoDiskQuotaExceededError && err.scope === 'project',
  )
  assert.equal(secondCheckoutReached, false, 'project quota overrun must reject BEFORE checkout')
  assert.deepEqual(listMountedRepos(reposDir), ['/repos/acme/small-a'])
  assert.ok((await mgr.measureProjectBytes(work, 'proj-bomb')) >= 20 * 1024)
})

test('R3-H-17: high-fan-out file count and over-depth git trees (>32) are rejected BEFORE git checkout', async t => {
  assert.equal(DEFAULT_MAX_REPO_FILES, 50_000)
  assert.equal(DEFAULT_MAX_REPO_DEPTH, 32)

  const work = makeTempDir(t, 'kovo-r3-fanout-depth-')
  const patPath = writeTestPat(work)
  const reposDir = projectReposDir(work, 'proj-fanout')

  // 1. High-fan-out repo (80 tiny files vs maxRepoFiles=40) rejected before checkout
  const fanoutFiles: Record<string, string> = {}
  for (let i = 0; i < 80; i += 1) {
    fanoutFiles[`dir-${i % 4}/f-${String(i).padStart(3, '0')}.txt`] = 'x\n'
  }
  const { originRoot } = createBareOriginRepo(work, 'acme', 'inode-fanout', fanoutFiles)

  let fanoutCheckoutReached = false
  await assert.rejects(
    () => cloneGithubRepos(['acme/inode-fanout'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      maxRepoFiles: 40,
      onBeforeCheckout: () => {
        fanoutCheckoutReached = true
      },
    }),
    err => err instanceof RepoFileLimitExceededError
      && err.code === 'REPO_FILE_LIMIT_EXCEEDED'
      && err.scope === 'repo'
      && err.maxFiles === 40,
  )
  assert.equal(fanoutCheckoutReached, false, 'high-fan-out tree must be rejected BEFORE checkout')
  assert.equal(existsSync(join(reposDir, 'acme', 'inode-fanout')), false)

  // 2. Deeply nested git tree (34 levels deep > default 32) rejected before checkout
  createBareOriginRepo(work, 'acme', 'deep-tree', {
    [buildNestedPath(34, 'hidden.txt')]: 'A'.repeat(4096),
  })

  let deepCheckoutReached = false
  await assert.rejects(
    () => cloneGithubRepos(['acme/deep-tree'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      onBeforeCheckout: () => {
        deepCheckoutReached = true
      },
    }),
    err => err instanceof RepoDepthLimitExceededError
      && err.code === 'REPO_DEPTH_LIMIT_EXCEEDED'
      && err.depth > 32
      && err.maxDepth === 32,
  )
  assert.equal(deepCheckoutReached, false, 'over-depth git tree must be rejected BEFORE checkout')
  assert.equal(existsSync(join(reposDir, 'acme', 'deep-tree')), false)
  assert.deepEqual(cleanupOrphanedRepoDirs(reposDir).removed, [])
})

test('R3-H-17: async measureDirectoryBytes fails closed on depth >32, enforces file/inode caps, and yields to event loop', async t => {
  const work = makeTempDir(t, 'kovo-r3-measure-')

  // 1. Over-depth directory (>32 levels) MUST fail closed (throw RepoDepthLimitExceededError), never return 0!
  const deepDir = join(work, 'over-depth')
  const deepFile = join(deepDir, buildNestedPath(34, 'payload.bin'))
  mkdirSync(join(deepFile, '..'), { recursive: true })
  writeFileSync(deepFile, Buffer.alloc(64 * 1024, 'Z'))

  await assert.rejects(
    () => measureDirectoryBytes(deepDir),
    err => err instanceof RepoDepthLimitExceededError && err.depth === 33 && err.maxDepth === 32,
  )

  // Also ensure measureProjectDiskBytes and listProjectMountedRepos fail closed on an over-depth mounted repo.
  const projectId = 'proj-deep-check'
  const mountedDeepRepo = join(projectReposDir(work, projectId), 'acme', 'nested-bypass')
  const mountedDeepFile = join(mountedDeepRepo, buildNestedPath(34, 'hidden.bin'))
  mkdirSync(join(mountedDeepFile, '..'), { recursive: true })
  writeFileSync(mountedDeepFile, Buffer.alloc(16 * 1024, 'Q'))

  await assert.rejects(
    () => measureProjectDiskBytes(projectReposDir(work, projectId)),
    err => err instanceof RepoDepthLimitExceededError && err.maxDepth === 32,
  )
  assert.throws(
    () => listProjectMountedRepos(work, projectId),
    err => err instanceof RepoDepthLimitExceededError && err.maxDepth === 32,
  )

  // 2. Boundary: exactly 32 directories deep succeeds and reports exact bytes (not 0).
  const okDeepDir = join(work, 'exact-depth-32')
  const okDeepFile = join(okDeepDir, buildNestedPath(32, 'exact.bin'))
  mkdirSync(join(okDeepFile, '..'), { recursive: true })
  writeFileSync(okDeepFile, Buffer.alloc(1234, 'B'))
  const measuredExact = await measureDirectoryBytes(okDeepDir)
  assert.equal(measuredExact, 1234)

  // 3. File/inode cap enforcement during directory walk.
  const manyFilesDir = join(work, 'many-files')
  mkdirSync(manyFilesDir, { recursive: true })
  for (let i = 0; i < 30; i += 1) {
    writeFileSync(join(manyFilesDir, `file-${i}.txt`), 'hello')
  }
  await assert.rejects(
    () => measureDirectoryBytes(manyFilesDir, { maxFiles: 15 }),
    err => err instanceof RepoFileLimitExceededError && err.maxFiles === 15,
  )

  // 4. Async non-blocking walk yields to the event loop.
  const asyncWalkDir = join(work, 'async-walk')
  mkdirSync(asyncWalkDir, { recursive: true })
  for (let i = 0; i < 350; i += 1) {
    writeFileSync(join(asyncWalkDir, `item-${i}.txt`), 'abcd')
  }
  let timerFired = false
  const timer = setTimeout(() => { timerFired = true }, 0)
  const measuredPromise = measureDirectoryBytes(asyncWalkDir)
  assert.equal(typeof measuredPromise.then, 'function', 'measureDirectoryBytes must be async')
  const measuredBytes = await measuredPromise
  clearTimeout(timer)
  assert.equal(measuredBytes, 350 * 4)
  assert.equal(timerFired, true, 'async directory walk must yield to the Node event loop')
})

test('R3-H-17: stageReadableReposTree and prepareReposMount enforce byte cap, file/inode cap, and over-depth fail-closed with clean rollback', t => {
  assert.equal(DEFAULT_MAX_STAGE_BYTES, 256 * 1024 * 1024)
  assert.equal(DEFAULT_MAX_STAGE_FILES, 50_000)
  assert.equal(DEFAULT_MAX_STAGE_DEPTH, 32)

  const work = makeTempDir(t, 'kovo-r3-stage-')
  const dataDir = join(work, 'kovo-data')

  // 1. Staging byte cap rejects oversized tree and leaves zero partial files in scratch or pre-existing targetDir.
  const byteHeavyRepo = join(work, 'byte-heavy')
  mkdirSync(byteHeavyRepo, { recursive: true })
  writeFileSync(join(byteHeavyRepo, 'a.bin'), Buffer.alloc(10 * 1024, 'A'))
  writeFileSync(join(byteHeavyRepo, 'b.bin'), Buffer.alloc(10 * 1024, 'B'))

  const emptyTarget = join(work, 'empty-target')
  mkdirSync(emptyTarget, { recursive: true })
  assert.throws(
    () => stageReadableReposTree(realpathSync(byteHeavyRepo), emptyTarget, { maxBytes: 15 * 1024 }),
    err => err instanceof RepoStagingQuotaExceededError
      && err.code === 'REPO_STAGING_BYTES_EXCEEDED'
      && err.limitKind === 'bytes'
      && err.limit === 15 * 1024,
  )
  assert.deepEqual(readdirSync(emptyTarget), [], 'pre-existing targetDir must be cleaned on byte-cap failure')

  assert.throws(
    () => stageReadableReposTree(realpathSync(byteHeavyRepo), undefined, {
      env: { KOVO_DATA_DIR: dataDir, KOVO_MAX_STAGE_REPO_BYTES: String(12 * 1024) },
    }),
    err => err instanceof RepoStagingQuotaExceededError && err.code === 'REPO_STAGING_BYTES_EXCEEDED',
  )
  assert.deepEqual(readdirSync(join(dataDir, 'scratch')), [], 'auto-created scratch dir must be removed on failure')

  // 2. Staging file/inode cap rejects high-fan-out tree.
  const manyFilesRepo = join(work, 'many-stage-files')
  mkdirSync(manyFilesRepo, { recursive: true })
  for (let i = 0; i < 25; i += 1) {
    writeFileSync(join(manyFilesRepo, `f-${i}.txt`), 'ok\n')
  }
  assert.throws(
    () => stageReadableReposTree(realpathSync(manyFilesRepo), undefined, {
      env: { KOVO_DATA_DIR: dataDir },
      maxFiles: 10,
    }),
    err => err instanceof RepoStagingQuotaExceededError
      && err.code === 'REPO_STAGING_FILES_EXCEEDED'
      && err.limitKind === 'files'
      && err.limit === 10,
  )
  assert.deepEqual(readdirSync(join(dataDir, 'scratch')), [])

  // 3. Over-depth (>32) tree fails closed in BOTH stageReadableReposTree and prepareReposMount (never silently skips!).
  const deepStageRepo = join(work, 'deep-stage')
  const deepStageFile = join(deepStageRepo, buildNestedPath(34, 'deep.ts'))
  mkdirSync(join(deepStageFile, '..'), { recursive: true })
  writeFileSync(deepStageFile, 'export const deep = true\n')

  assert.throws(
    () => stageReadableReposTree(realpathSync(deepStageRepo), undefined, {
      env: { KOVO_DATA_DIR: dataDir },
    }),
    err => err instanceof RepoStagingQuotaExceededError
      && err.code === 'REPO_STAGING_DEPTH_EXCEEDED'
      && err.limitKind === 'depth'
      && err.actual === 33
      && err.limit === 32,
  )
  assert.deepEqual(readdirSync(join(dataDir, 'scratch')), [])

  // Even when permissions are 0o755/0o644 (would normally direct-mount), prepareReposMount must fail closed on >32 depth!
  chmodSync(deepStageRepo, 0o755)
  assert.throws(
    () => prepareReposMount(deepStageRepo, { env: { KOVO_DATA_DIR: dataDir } }),
    err => err instanceof RepoStagingQuotaExceededError
      && err.code === 'REPO_STAGING_DEPTH_EXCEEDED',
  )

  // 4. Boundary: 32-level-deep tree within byte & file/inode caps stages cleanly and reports accurate totals.
  const okStageRepo = join(work, 'ok-depth-32')
  const okStageFile = join(okStageRepo, buildNestedPath(32, 'ok.txt'))
  mkdirSync(join(okStageFile, '..'), { recursive: true })
  writeFileSync(okStageFile, 'exact-depth-ok')

  // Directory-only inode cap: 32 nested dirs + 1 file = 33 inodes > maxInodes(20) fails closed.
  assert.throws(
    () => stageReadableReposTree(realpathSync(okStageRepo), undefined, {
      env: { KOVO_DATA_DIR: dataDir },
      maxBytes: 1024,
      maxFiles: 10,
      maxDepth: 32,
    }),
    err => err instanceof RepoStagingQuotaExceededError && err.code === 'REPO_STAGING_FILES_EXCEEDED',
  )
  assert.deepEqual(readdirSync(join(dataDir, 'scratch')), [])

  const staged = stageReadableReposTree(realpathSync(okStageRepo), undefined, {
    env: { KOVO_DATA_DIR: dataDir },
    maxBytes: 1024,
    maxFiles: 50,
    maxDepth: 32,
  })
  t.after(() => rmSync(staged.mountDir, { recursive: true, force: true }))
  assert.equal(staged.stagedFiles, 1)
  assert.equal(staged.stagedBytes, Buffer.byteLength('exact-depth-ok'))
  assert.equal(existsSync(join(staged.mountDir, buildNestedPath(32, 'ok.txt'))), true)
})
