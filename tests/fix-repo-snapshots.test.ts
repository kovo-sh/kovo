import assert from 'node:assert/strict'
import { execFileSync, type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import test from 'node:test'
import { eq } from 'drizzle-orm'
import {
  resyncProjectRepoInStore,
  unlinkProjectRepoInStore,
} from '../src/actions-sources.ts'
import { newProject, newRun } from '../src/domain.ts'
import {
  RepoWorkspaceBusyError,
  RepoWorkspaceManager,
  isRepoOperationLocked,
  listMountedRepos,
  projectReposDir,
  unlinkProjectMountedRepo,
  withRepoOperationLock,
} from '../src/server/github-repo-sync.ts'
import * as tables from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  DEFAULT_MAX_STAGE_BYTES,
  LinuxWorkerBackend,
  RepoStagingQuotaExceededError,
  buildWarmPoolPolicy,
  prepareReposMount,
  type DockerRunner,
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
  files: Record<string, string>,
): { originRoot: string; barePath: string; sourcePath: string } {
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
  return { originRoot, barePath, sourcePath }
}

function addCommitToBareOrigin(
  sourcePath: string,
  barePath: string,
  files: Record<string, string>,
  message: string,
): void {
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(sourcePath, relPath)
    mkdirSync(join(fullPath, '..'), { recursive: true })
    writeFileSync(fullPath, content)
  }
  runGitSync(sourcePath, ['add', '-A'])
  runGitSync(sourcePath, ['commit', '-m', message])
  runGitSync(sourcePath, ['push', barePath, 'main:main'])
}

function writeTestPat(dir: string): string {
  const patPath = join(dir, 'test-github.pat')
  writeFileSync(patPath, 'github_pat_11TEST_SNAPSHOT_PAT_0123456789\n', { mode: 0o600 })
  chmodSync(patPath, 0o600)
  return patPath
}

function makeFakeSessionSpawner(onStop?: Map<string, () => void>) {
  const started: string[] = []
  const spawner = (name: string): ChildProcess => {
    started.push(name)
    const emitter = new EventEmitter() as EventEmitter & {
      stdin: PassThrough
      stdout: PassThrough
      stderr: PassThrough
      kill: () => boolean
    }
    emitter.stdin = new PassThrough()
    emitter.stdout = new PassThrough()
    emitter.stderr = new PassThrough()
    let closed = false
    const finish = () => {
      if (closed) return
      closed = true
      emitter.emit('close', 0)
    }
    emitter.kill = () => { finish(); return true }
    onStop?.set(name, finish)
    return emitter as unknown as ChildProcess
  }
  return { spawner, started }
}

function makeDockerStub(onStop?: Map<string, () => void>) {
  const states = new Map<string, { status: string; instance: string }>()
  const createMounts: string[] = []
  const calls: string[][] = []
  const runner: DockerRunner = async args => {
    calls.push([...args])
    const verb = args[0] === 'container' ? args[1] : args[0]
    if (verb === 'create') {
      const name = args[args.indexOf('--name') + 1]!
      const instArg = args.find(a => a.startsWith('dev.kovo.pool_instance=')) ?? ''
      const instance = instArg.slice('dev.kovo.pool_instance='.length)
      states.set(name, { status: 'created', instance })
      const mountArg = args.find(a => a.includes('target=/repos,readonly')) ?? ''
      const match = /^type=bind,source=([^,]+),target=\/repos,readonly$/.exec(mountArg)
      if (match?.[1]) createMounts.push(match[1])
      return 'created'
    }
    if (verb === 'inspect') {
      const name = args[args.length - 1]!
      const entry = states.get(name)
      if (!entry) throw new Error(`No such container: ${name}`)
      const fmtIdx = args.indexOf('-f')
      const fmt = fmtIdx >= 0 ? args[fmtIdx + 1] ?? '' : ''
      if (fmt.includes('\\t')) return `${entry.status}\t${entry.instance}\n`
      return `${entry.status}\n`
    }
    if (verb === 'stop') {
      const name = args[args.length - 1]!
      const entry = states.get(name)
      if (entry) entry.status = 'exited'
      onStop?.get(name)?.()
      return ''
    }
    if (verb === 'start') {
      return JSON.stringify({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} })
    }
    if (verb === 'rm') {
      for (const arg of args.slice(args.indexOf('--force') + 1)) states.delete(arg)
      return ''
    }
    return ''
  }
  return { runner, createMounts, calls }
}

async function waitFor(predicate: () => boolean, label: string, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.fail(`Timed out waiting for: ${label}`)
}

test('prepareReposMount ALWAYS stages an isolated snapshot even on clean 0o755/0o644 repos and strips .git, .env, node_modules, and symlinks', t => {
  assert.equal(DEFAULT_MAX_STAGE_BYTES, 256 * 1024 * 1024)

  const work = makeTempDir(t, 'kovo-snap-always-')

  // 1. Completely clean, world-readable 0o755/0o644 repo with ZERO sensitive files must STILL stage.
  const cleanRepo = join(work, 'clean-world-readable')
  mkdirSync(join(cleanRepo, 'src'), { recursive: true, mode: 0o755 })
  const srcFile = join(cleanRepo, 'src', 'app.ts')
  writeFileSync(srcFile, 'export const clean = true\n', { mode: 0o644 })
  chmodSync(cleanRepo, 0o755)
  chmodSync(join(cleanRepo, 'src'), 0o755)
  chmodSync(srcFile, 0o644)

  const preparedClean = prepareReposMount(cleanRepo, { env: { KOVO_DATA_DIR: join(work, 'data') } })
  assert.ok(preparedClean)
  const cleanMountDir = preparedClean.mountDir
  try {
    assert.equal(preparedClean.staged, true, 'clean 0o755/0o644 repo must ALWAYS return staged: true')
    assert.notEqual(preparedClean.mountDir, realpathSync(cleanRepo))
    assert.equal(preparedClean.excludedCount, 0)
    assert.equal(readFileSync(join(preparedClean.mountDir, 'src', 'app.ts'), 'utf8'), 'export const clean = true\n')
    assert.equal(statSync(preparedClean.mountDir).mode & 0o005, 0o005)
    assert.equal(statSync(join(preparedClean.mountDir, 'src', 'app.ts')).mode & 0o004, 0o004)
  } finally {
    preparedClean.cleanup()
  }
  assert.equal(existsSync(cleanMountDir), false, 'cleanup must remove staged snapshot')
  assert.equal(existsSync(srcFile), true, 'cleanup must never modify or remove host repo')

  // 2. World-readable repo with .git, .env, node_modules, and symlinks strips all of them while preserving source + .env.example.
  const mixedRepo = join(work, 'mixed-world-readable')
  mkdirSync(join(mixedRepo, 'acme', 'app', '.git', 'hooks'), { recursive: true, mode: 0o755 })
  mkdirSync(join(mixedRepo, 'acme', 'app', 'node_modules', 'dep'), { recursive: true, mode: 0o755 })
  writeFileSync(join(mixedRepo, 'acme', 'app', 'index.ts'), 'export const v = 1\n', { mode: 0o644 })
  writeFileSync(join(mixedRepo, 'acme', 'app', '.env'), 'SECRET_KEY=do_not_mount\n', { mode: 0o644 })
  writeFileSync(join(mixedRepo, 'acme', 'app', '.env.example'), 'SECRET_KEY=placeholder\n', { mode: 0o644 })
  writeFileSync(join(mixedRepo, 'acme', 'app', '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n', { mode: 0o644 })
  writeFileSync(join(mixedRepo, 'acme', 'app', 'node_modules', 'dep', 'index.js'), 'module.exports = {}\n', { mode: 0o644 })
  symlinkSync('/etc/hosts', join(mixedRepo, 'acme', 'app', 'sym-escape'))

  const preparedMixed = prepareReposMount(mixedRepo, { env: { KOVO_DATA_DIR: join(work, 'data') } })
  assert.ok(preparedMixed)
  try {
    assert.equal(preparedMixed.staged, true)
    assert.equal(readFileSync(join(preparedMixed.mountDir, 'acme', 'app', 'index.ts'), 'utf8'), 'export const v = 1\n')
    assert.equal(readFileSync(join(preparedMixed.mountDir, 'acme', 'app', '.env.example'), 'utf8'), 'SECRET_KEY=placeholder\n')
    assert.equal(existsSync(join(preparedMixed.mountDir, 'acme', 'app', '.git')), false)
    assert.equal(existsSync(join(preparedMixed.mountDir, 'acme', 'app', '.env')), false)
    assert.equal(existsSync(join(preparedMixed.mountDir, 'acme', 'app', 'node_modules')), false)
    assert.equal(existsSync(join(preparedMixed.mountDir, 'acme', 'app', 'sym-escape')), false)
  } finally {
    preparedMixed.cleanup()
  }

  // 3. KOVO_MAX_STAGE_REPO_BYTES env override is enforced cleanly.
  const quotaRepo = join(work, 'quota-repo')
  mkdirSync(quotaRepo, { recursive: true })
  writeFileSync(join(quotaRepo, 'blob.bin'), Buffer.alloc(4096, 'X'))
  assert.throws(
    () => prepareReposMount(quotaRepo, { env: { KOVO_DATA_DIR: join(work, 'data'), KOVO_MAX_STAGE_REPO_BYTES: '1024' } }),
    err => err instanceof RepoStagingQuotaExceededError && err.code === 'REPO_STAGING_BYTES_EXCEEDED' && err.limit === 1024,
  )
})

test('mutating or deleting live host repo checkout AFTER prepareReposMount leaves staged snapshot 100% intact', t => {
  const work = makeTempDir(t, 'kovo-snap-immutable-')
  const hostReposDir = join(work, 'host-repos')
  const appDir = join(hostReposDir, 'acme', 'service')
  mkdirSync(join(appDir, 'src'), { recursive: true })
  writeFileSync(join(appDir, 'src', 'handler.ts'), 'export const version = "v1"\n')
  writeFileSync(join(appDir, 'README.md'), '# Original Snapshot\n')

  const prepared = prepareReposMount(hostReposDir, { env: { KOVO_DATA_DIR: join(work, 'data') } })
  assert.ok(prepared && prepared.staged)
  t.after(() => prepared.cleanup())

  // Simulate mid-run re-sync mutating existing files and adding/removing files on the host checkout.
  writeFileSync(join(appDir, 'src', 'handler.ts'), 'export const version = "v2-mutated-mid-run"\n')
  rmSync(join(appDir, 'README.md'))
  writeFileSync(join(appDir, 'src', 'new-file.ts'), 'export const added = true\n')

  assert.equal(
    readFileSync(join(prepared.mountDir, 'acme', 'service', 'src', 'handler.ts'), 'utf8'),
    'export const version = "v1"\n',
    'staged snapshot must preserve original file contents after host mutation',
  )
  assert.equal(
    readFileSync(join(prepared.mountDir, 'acme', 'service', 'README.md'), 'utf8'),
    '# Original Snapshot\n',
    'staged snapshot must retain files deleted from host checkout',
  )
  assert.equal(
    existsSync(join(prepared.mountDir, 'acme', 'service', 'src', 'new-file.ts')),
    false,
    'staged snapshot must not reflect newly written host files',
  )

  // Simulate mid-run repo unlink deleting the ENTIRE host checkout directory.
  rmSync(hostReposDir, { recursive: true, force: true })
  assert.equal(existsSync(hostReposDir), false)
  assert.equal(
    readFileSync(join(prepared.mountDir, 'acme', 'service', 'src', 'handler.ts'), 'utf8'),
    'export const version = "v1"\n',
    'staged snapshot must remain 100% readable after entire host checkout is unlinked/deleted',
  )
})

test('two workers sharing the same runId reuse a single immutable per-run snapshot and evictRunWarmPool / close cleans it up once all leases release', async t => {
  const work = makeTempDir(t, 'kovo-snap-run-reuse-')
  const reposDir = join(work, 'repos')
  mkdirSync(join(reposDir, 'acme', 'api'), { recursive: true, mode: 0o755 })
  writeFileSync(join(reposDir, 'acme', 'api', 'server.ts'), 'export const rev = 1\n', { mode: 0o644 })
  const rpcDir = join(work, 'rpc')
  mkdirSync(rpcDir, { recursive: true, mode: 0o755 })

  // Part A: Warm pool enabled — warm worker + concurrent cold worker + Layer-1 rpcMountDir worker all share ONE snapshot.
  const stopHooks = new Map<string, () => void>()
  const docker = makeDockerStub(stopHooks)
  const { spawner } = makeFakeSessionSpawner(stopHooks)

  const backend = new LinuxWorkerBackend({
    workspace: { id: 'ws-snap-reuse', directory: work },
    cell: 'cell-snap-reuse',
    dockerRunner: docker.runner,
    sessionSpawner: spawner,
  })
  t.after(() => backend.close())

  const runId = `run-${randomUUID().slice(0, 8)}`
  const policy = buildWarmPoolPolicy({ runId, reposDir, mountedRepos: ['/repos/acme/api'], image: 'kovo-worker:v4' })
  backend.setWarmPoolPolicy(policy, { reposDir })
  await waitFor(() => backend.getWarmPoolStats(policy)?.idle === 1, 'warm pool container prewarmed')

  assert.equal(docker.createMounts.length, 1)
  const sharedSnapshotDir = docker.createMounts[0]!
  assert.notEqual(sharedSnapshotDir, realpathSync(reposDir))
  assert.equal(existsSync(sharedSnapshotDir), true)

  // Worker 1 takes warm container; Worker 2 opens concurrently (cold create) + Worker 3 opens with rpcMountDir (cold bypass).
  const s1 = await backend.openSession('asgn-w1', AbortSignal.timeout(5_000), { warmPoolPolicy: policy, reposDir })
  const s2 = await backend.openSession('asgn-w2', AbortSignal.timeout(5_000), { warmPoolPolicy: policy, reposDir })
  const s3 = await backend.openSession('asgn-w3-rpc', AbortSignal.timeout(5_000), { warmPoolPolicy: policy, reposDir, rpcMountDir: rpcDir })

  assert.equal(docker.createMounts.length, 3, 'warm prewarm + cold concurrent + cold rpc sessions created')
  assert.equal(docker.createMounts[1], sharedSnapshotDir, 'concurrent cold worker in same run must reuse single per-run snapshot')
  assert.equal(docker.createMounts[2], sharedSnapshotDir, 'rpcMountDir worker in same run must reuse single per-run snapshot')

  // Delete live host repo while all 3 workers are active -> shared snapshot stays 100% intact.
  rmSync(reposDir, { recursive: true, force: true })
  assert.equal(readFileSync(join(sharedSnapshotDir, 'acme', 'api', 'server.ts'), 'utf8'), 'export const rev = 1\n')

  // Evict run while workers are still active -> cleanup MUST defer until the last active lease releases!
  await backend.evictRunWarmPool(runId)
  assert.equal(existsSync(sharedSnapshotDir), true, 'evictRunWarmPool must defer snapshot removal while sessions are active')

  await s1.close()
  assert.equal(existsSync(sharedSnapshotDir), true, 'snapshot stays alive while s2 & s3 hold leases')
  await s2.close()
  assert.equal(existsSync(sharedSnapshotDir), true, 'snapshot stays alive while s3 holds lease')
  await s3.close()
  assert.equal(existsSync(sharedSnapshotDir), false, 'snapshot is deleted immediately once final active lease releases')

  // Part B: Warm pool disabled (KOVO_WARM_WORKERS=0) — two runs remain isolated; same runId shares one snapshot across openSession & run().
  const prevWarm = process.env.KOVO_WARM_WORKERS
  process.env.KOVO_WARM_WORKERS = '0'
  t.after(() => {
    if (prevWarm === undefined) delete process.env.KOVO_WARM_WORKERS
    else process.env.KOVO_WARM_WORKERS = prevWarm
  })

  const reposDir2 = join(work, 'repos-cold')
  mkdirSync(join(reposDir2, 'acme', 'web'), { recursive: true, mode: 0o755 })
  writeFileSync(join(reposDir2, 'acme', 'web', 'main.ts'), 'export const cold = true\n', { mode: 0o644 })

  const dockerCold = makeDockerStub()
  const spawnerCold = makeFakeSessionSpawner()
  const coldBackend = new LinuxWorkerBackend({
    dockerRunner: dockerCold.runner,
    sessionSpawner: spawnerCold.spawner,
  })
  t.after(() => coldBackend.close())

  const runA = `run-a-${randomUUID().slice(0, 6)}`
  const runB = `run-b-${randomUUID().slice(0, 6)}`

  const a1 = await coldBackend.openSession('asgn-a1', AbortSignal.timeout(5_000), { runId: runA, reposDir: reposDir2 })
  const a2 = await coldBackend.openSession('asgn-a2', AbortSignal.timeout(5_000), { runId: runA, reposDir: reposDir2 })
  await coldBackend.run({ assignmentId: randomUUID(), files: [], command: 'true', outputs: [] }, AbortSignal.timeout(5_000), { runId: runA, reposDir: reposDir2 })
  const b1 = await coldBackend.openSession('asgn-b1', AbortSignal.timeout(5_000), { runId: runB, reposDir: reposDir2 })

  assert.equal(dockerCold.createMounts.length, 4)
  const snapA = dockerCold.createMounts[0]!
  const snapB = dockerCold.createMounts[3]!
  assert.equal(dockerCold.createMounts[1], snapA, 'second cold worker in runA shares runA snapshot')
  assert.equal(dockerCold.createMounts[2], snapA, 'run() call in runA shares runA snapshot')
  assert.notEqual(snapB, snapA, 'distinct runB gets its own isolated immutable snapshot')

  await a1.close()
  await a2.close()
  assert.equal(existsSync(snapA), true, 'runA snapshot stays cached for subsequent runA workers until eviction')

  await coldBackend.evictRunWarmPool(runA)
  assert.equal(existsSync(snapA), false, 'evictRunWarmPool(runA) removes runA snapshot')
  assert.equal(existsSync(snapB), true, 'evictRunWarmPool(runA) does not touch runB snapshot')

  await b1.close()
  await coldBackend.close()
  assert.equal(existsSync(snapB), false, 'backend.close() cleans up remaining runB snapshot')
})

test('re-sync and unlink succeed while project has running, paused, and complete runs while per-repo lock still serializes concurrent mutations', async t => {
  const work = makeTempDir(t, 'kovo-snap-actions-')
  const store = new Store(work, { ftsMode: 'preview' })
  t.after(() => store.close())

  const project = store.createProject(newProject.parse({
    requestId: randomUUID(),
    name: 'Live Multi-Run Repo Project',
    seeds: ['https://app.example.test'],
  }))

  const patPath = writeTestPat(work)
  const { originRoot, barePath, sourcePath } = createBareOriginRepo(work, 'acme', 'shop', {
    'package.json': JSON.stringify({ name: 'shop', dependencies: { hono: '^4.0.0' } }),
    'src/routes.ts': 'export const rev = "v1"\n',
  })

  // Initial sync
  const initial = await resyncProjectRepoInStore(store, project.id, 'acme/shop', {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
  })
  assert.equal(initial.fullName, 'acme/shop')

  // Stage an active worker snapshot before creating runs & mutating host repo
  const reposRoot = projectReposDir(work, project.id)
  const workerSnapshot = prepareReposMount(reposRoot, { env: { KOVO_DATA_DIR: work } })
  assert.ok(workerSnapshot && workerSnapshot.staged)
  t.after(() => workerSnapshot.cleanup())
  assert.equal(readFileSync(join(workerSnapshot.mountDir, 'acme', 'shop', 'src', 'routes.ts'), 'utf8'), 'export const rev = "v1"\n')

  // Create runs in all three states simultaneously: running, paused, AND complete
  const runningRun = store.createRun(newRun.parse({ requestId: randomUUID(), projectId: project.id, goal: 'Running run' }))
  const pausedRun = store.createRun(newRun.parse({ requestId: randomUUID(), projectId: project.id, goal: 'Paused run' }))
  const completeRun = store.createRun(newRun.parse({ requestId: randomUUID(), projectId: project.id, goal: 'Complete run' }))

  store.db.update(tables.runs).set({ status: 'running' }).where(eq(tables.runs.id, runningRun.id)).run()
  store.db.update(tables.runs).set({ status: 'paused' }).where(eq(tables.runs.id, pausedRun.id)).run()
  store.db.update(tables.runs).set({ status: 'complete' }).where(eq(tables.runs.id, completeRun.id)).run()

  assert.equal(store.run(runningRun.id).status, 'running')
  assert.equal(store.run(pausedRun.id).status, 'paused')
  assert.equal(store.run(completeRun.id).status, 'complete')
  assert.equal(store.isRunActive(runningRun.id), true)
  assert.equal(store.isRunActive(completeRun.id), false)

  // Push commit v2 and re-sync while running + paused + complete runs exist
  addCommitToBareOrigin(sourcePath, barePath, { 'src/routes.ts': 'export const rev = "v2"\n' }, 'bump to v2')
  const resynced = await resyncProjectRepoInStore(store, project.id, 'acme/shop', {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
  })
  assert.equal(resynced.fullName, 'acme/shop')
  assert.equal(readFileSync(join(reposRoot, 'acme', 'shop', 'src', 'routes.ts'), 'utf8'), 'export const rev = "v2"\n')
  // Live worker snapshot STILL sees immutable v1!
  assert.equal(readFileSync(join(workerSnapshot.mountDir, 'acme', 'shop', 'src', 'routes.ts'), 'utf8'), 'export const rev = "v1"\n')

  // Per-repo lock still serializes concurrent mutations on the same (projectId, repoSlug)!
  let releaseGate!: () => void
  const gate = new Promise<void>(resolve => { releaseGate = resolve })
  let entered!: () => void
  const enteredPromise = new Promise<void>(resolve => { entered = resolve })

  const lockHolder = withRepoOperationLock(reposRoot, 'acme/shop', async () => {
    entered()
    await gate
  })
  await enteredPromise
  assert.equal(isRepoOperationLocked(reposRoot, 'acme/shop'), true)
  assert.throws(
    () => unlinkProjectMountedRepo(work, project.id, 'acme/shop'),
    err => err instanceof RepoWorkspaceBusyError && err.code === 'REPO_SYNC_IN_PROGRESS',
  )

  const mgr = new RepoWorkspaceManager({
    activeRunChecker: () => [runningRun.id, pausedRun.id],
  })
  const queuedResync = mgr.syncRepos(work, project.id, ['acme/shop'], undefined, {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
  })
  releaseGate()
  await lockHolder
  const [queuedSynced] = await queuedResync
  assert.equal(queuedSynced?.fullName, 'acme/shop')

  // Unlink succeeds cleanly while running + paused + complete runs are still present!
  const unlinked = unlinkProjectRepoInStore(store, project.id, 'acme/shop')
  assert.deepEqual(unlinked, { unlinked: true, fullName: 'acme/shop' })
  assert.deepEqual(listMountedRepos(reposRoot), [])
  // Live worker snapshot STILL sees immutable v1 even after host repo was unlinked!
  assert.equal(readFileSync(join(workerSnapshot.mountDir, 'acme', 'shop', 'src', 'routes.ts'), 'utf8'), 'export const rev = "v1"\n')
})
