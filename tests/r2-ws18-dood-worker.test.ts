import assert from 'node:assert/strict'
import { type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import test from 'node:test'
import ts from 'typescript'
import {
  ContainerSupervisor,
  LAB_OWNER_PID_LABEL,
  LAB_OWNER_PID_NS_LABEL,
  LAB_OWNER_SESSION_LABEL,
  LAB_OWNER_START_TIME_LABEL,
} from '../src/server/container-supervisor.ts'
import { LAB_LABELS, type DockerRunner as LabDockerRunner } from '../src/server/lab-proxy.ts'
import { Store } from '../src/server/store.ts'
import { findings } from '../src/server/schema.ts'
import {
  VERIFY_RPC_CONTAINER_DIR,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
} from '../src/server/verify-rpc.ts'
import {
  LinuxWorkerBackend,
  WORKER_OWNER_PID_LABEL,
  WORKER_OWNER_PID_NS_LABEL,
  WORKER_OWNER_START_TIME_LABEL,
  WORKER_POOL_INSTANCE_LABEL,
  WORKER_SESSION_LABEL,
  WarmWorkerPool,
  isOwnerProvablyDead,
  prepareReposMount,
  prepareSessionScratchDir,
  stageReadableReposTree,
  workerContainerCreateArgs,
  type DockerRunner,
} from '../src/server/worker-backend.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

function withTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function withEnv(t: test.TestContext, overrides: Record<string, string | undefined>): void {
  const prev = new Map<string, string | undefined>()
  for (const [k, v] of Object.entries(overrides)) {
    prev.set(k, process.env[k])
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  t.after(() => {
    for (const [k, v] of prev) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  })
}

function extractMounts(args: string[]): string[] {
  const mounts: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--mount' && args[i + 1]) mounts.push(args[i + 1]!)
  }
  return mounts
}

// ============================================================================
// 1. R2-H-21 + #797/#798: stageReadableReposTree safety, .git/node_modules skip
// ============================================================================

test('R2-H-21: stageReadableReposTree refuses non-empty targetDir and never deletes pre-existing dirs', t => {
  const root = withTempDir(t, 'kovo-r2h21-')
  const srcRepo = join(root, 'src-repo')
  mkdirSync(srcRepo, { recursive: true })
  writeFileSync(join(srcRepo, 'app.ts'), 'export const ok = 1\n')

  // Non-empty pre-existing targetDir must throw and preserve existing files & directory.
  const nonEmptyTarget = join(root, 'non-empty-target')
  mkdirSync(nonEmptyTarget, { recursive: true })
  writeFileSync(join(nonEmptyTarget, 'keep.txt'), 'live-data\n')
  assert.throws(
    () => stageReadableReposTree(realpathSync(srcRepo), nonEmptyTarget),
    /non-empty target directory/i,
  )
  assert.equal(existsSync(nonEmptyTarget), true)
  assert.equal(readFileSync(join(nonEmptyTarget, 'keep.txt'), 'utf8'), 'live-data\n')

  // Pre-existing empty targetDir: on mid-copy failure, cleans partial children WITHOUT deleting targetDir itself.
  const emptyTarget = join(root, 'empty-target')
  mkdirSync(emptyTarget, { recursive: true })
  const badRepo = join(root, 'bad-repo')
  mkdirSync(join(badRepo, 'sub'), { recursive: true })
  writeFileSync(join(badRepo, 'a.txt'), 'copied-before-error\n')
  const unreadableFile = join(badRepo, 'z-unreadable.txt')
  writeFileSync(unreadableFile, 'secret')
  chmodSync(unreadableFile, 0o000)
  t.after(() => { try { chmodSync(unreadableFile, 0o600) } catch { /* ignore */ } })

  if (typeof process.getuid === 'function' && process.getuid() !== 0) {
    assert.throws(() => stageReadableReposTree(realpathSync(badRepo), emptyTarget))
    assert.equal(existsSync(emptyTarget), true, 'pre-existing empty targetDir must NOT be deleted on failure')
    assert.deepEqual(readdirSync(emptyTarget), [], 'partial children copied into pre-existing dir must be cleaned up')

    // Auto-created staging dir (targetDir omitted) IS deleted on mid-copy error and prefers KOVO_DATA_DIR/scratch.
    const dataDir = join(root, 'kovo-data')
    assert.throws(() => stageReadableReposTree(realpathSync(badRepo), undefined, { env: { KOVO_DATA_DIR: dataDir } }))
    const scratchDir = join(dataDir, 'scratch')
    assert.equal(existsSync(scratchDir), true)
    assert.deepEqual(readdirSync(scratchDir), [], 'failed temp staging dir must be removed in catch')
  }
})

test('R2-H-21 addendum: stageReadableReposTree skips .git and node_modules and prefers scratch/KOVO_DATA_DIR', t => {
  const root = withTempDir(t, 'kovo-git-skip-')
  const srcRepo = join(root, 'repo')
  mkdirSync(join(srcRepo, '.git', 'objects', 'aa'), { recursive: true })
  mkdirSync(join(srcRepo, 'node_modules', 'pkg'), { recursive: true })
  mkdirSync(join(srcRepo, 'src'), { recursive: true })
  writeFileSync(join(srcRepo, '.git', 'HEAD'), 'ref: refs/heads/main\n')
  writeFileSync(join(srcRepo, '.git', 'objects', 'aa', 'deadbeef'), 'pack-bytes')
  writeFileSync(join(srcRepo, 'node_modules', 'pkg', 'index.js'), 'module.exports = 1\n')
  writeFileSync(join(srcRepo, 'src', 'index.ts'), 'export const hello = true\n')

  const dataDir = join(root, 'data-dir')
  const staged = stageReadableReposTree(realpathSync(srcRepo), undefined, { env: { KOVO_DATA_DIR: dataDir } })
  t.after(() => rmSync(staged.mountDir, { recursive: true, force: true }))

  assert.ok(staged.mountDir.startsWith(realpathSync(join(dataDir, 'scratch'))), 'should stage under KOVO_DATA_DIR/scratch')
  assert.equal(existsSync(join(staged.mountDir, 'src', 'index.ts')), true)
  assert.equal(existsSync(join(staged.mountDir, '.git')), false, '.git directory must be skipped')
  assert.equal(existsSync(join(staged.mountDir, 'node_modules')), false, 'node_modules must be skipped')
  assert.ok(staged.excludedCount >= 2)
})

test('R2-H-21 addendum: WarmWorkerPool cleans preparedRepos on prewarm failure and run() cleans ipcDir on staging error', async t => {
  const scratchRoot = withTempDir(t, 'kovo-run-leak-')
  const reposRoot = withTempDir(t, 'kovo-repos-leak-')
  const stagedScratch = withTempDir(t, 'kovo-warm-fail-scratch-')
  chmodSync(reposRoot, 0o700)
  writeFileSync(join(reposRoot, 'a.ts'), 'export const x = 1\n', { mode: 0o600 })

  // 1. WarmWorkerPool prewarm failure cleans staged preparedRepos.
  let observedStagedDir = ''
  withEnv(t, { KOVO_CONTAINER_SCRATCH_DIR: stagedScratch })
  const pool = new WarmWorkerPool({
    cell: 'cell-fail-clean',
    image: 'kovo-worker:v4',
    dockerRunner: async args => {
      const mountArg = args.find(a => a.includes('target=/repos,readonly')) ?? ''
      observedStagedDir = /^type=bind,source=([^,]+),target=\/repos,readonly$/.exec(mountArg)?.[1] ?? ''
      throw new Error('simulated docker create failure')
    },
    runLabel: 'run-fail-clean',
    options: { reposDir: reposRoot },
  })
  const warmed = await pool.warm()
  assert.equal(warmed, null)
  assert.ok(observedStagedDir, 'prewarm should have staged repos before docker create failed')
  assert.equal(existsSync(observedStagedDir), false, 'staged preparedRepos must be cleaned up when prewarm fails')
  await pool.close()

  // 2. LinuxWorkerBackend.run() cleans kovo-ipc-* even when prepareReposMount throws.
  withEnv(t, {
    KOVO_CONTAINER_SCRATCH_DIR: scratchRoot,
    KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch',
    KOVO_WARM_WORKERS: '0',
  })
  const badRepoFile = join(reposRoot, 'not-a-dir')
  writeFileSync(badRepoFile, 'file-not-dir')
  const backend = new LinuxWorkerBackend({ dockerRunner: async () => '' })
  await assert.rejects(
    () => backend.run(
      { assignmentId: randomUUID(), files: [], command: 'true', outputs: [] },
      AbortSignal.timeout(5_000),
      { reposDir: badRepoFile },
    ),
    /must be an existing directory/i,
  )
  assert.deepEqual(readdirSync(scratchRoot), [], 'ipc scratch dir must not leak when prepareReposMount throws')
})

// ============================================================================
// 2. R2-H-22: workerContainerCreateArgs with rpcMountDir in DooD modes
// ============================================================================

test('R2-H-22: workerContainerCreateArgs supports rpcMountDir via prepareSessionScratchDir in volume_subpath and host_bind DooD modes', t => {
  const scratchVol = withTempDir(t, 'kovo-r2h22-vol-')
  const volEnv: NodeJS.ProcessEnv = {
    KOVO_CONTAINER_SCRATCH_DIR: scratchVol,
    KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch',
  }
  const rpcVolDir = prepareSessionScratchDir('rpc-verify-1', 'rpc', volEnv)
  const ipcVolDir = prepareSessionScratchDir('rpc-verify-1', 'ipc', volEnv)
  writeFileSync(join(rpcVolDir, 'token'), 'tok-vol\n', { mode: 0o600 })
  writeFileSync(join(rpcVolDir, 'context.json'), '{"nonce":"vol"}\n', { mode: 0o600 })

  const volArgs = workerContainerCreateArgs({
    image: 'kovo-worker:v4',
    name: `kovo-${randomUUID()}`,
    assignmentId: 'asgn-r2h22-vol',
    runLabel: 'run-r2h22-vol',
    ipcDir: ipcVolDir,
    options: { rpcMountDir: rpcVolDir },
    env: volEnv,
  })
  const volMounts = extractMounts(volArgs)
  assert.deepEqual(volMounts, [
    'type=volume,source=kovo_scratch,target=/kovo-rpc,volume-subpath=rpc-verify-1/rpc,readonly',
    'type=volume,source=kovo_scratch,target=/kovo-ipc,volume-subpath=rpc-verify-1/ipc',
  ])
  assert.ok(volArgs.includes(`${VERIFY_RPC_SOCKET_ENV}=${VERIFY_RPC_CONTAINER_DIR}/verify.sock`))
  assert.ok(volArgs.includes(`${VERIFY_RPC_TOKEN_ENV}=${VERIFY_RPC_CONTAINER_DIR}/token`))
  assert.ok(volArgs.includes(`${VERIFY_RPC_CONTEXT_ENV}=${VERIFY_RPC_CONTAINER_DIR}/context.json`))

  // Rejects rpcMountDir outside KOVO_CONTAINER_SCRATCH_DIR when DooD scratch is enabled.
  const outsideRpc = withTempDir(t, 'kovo-outside-rpc-')
  assert.throws(
    () => workerContainerCreateArgs({
      image: 'kovo-worker:v4',
      name: `kovo-${randomUUID()}`,
      assignmentId: 'asgn-r2h22-bad',
      runLabel: 'run-r2h22-bad',
      options: { rpcMountDir: outsideRpc },
      env: volEnv,
    }),
    /per-session subdirectory/i,
  )
})

// ============================================================================
// 3. H-31: PID-namespace-safe sweep, take() inspect + cold fallback, ContainerSupervisor
// ============================================================================

test('H-31: worker containers carry pid_ns + start_time + session labels and isOwnerProvablyDead respects namespaces', async t => {
  const calls: string[][] = []
  const pool = new WarmWorkerPool({
    cell: 'cell-h31-labels',
    image: 'kovo-worker:v4',
    dockerRunner: async args => {
      calls.push([...args])
      return ''
    },
    runLabel: 'run-h31-labels',
    capacity: 1,
  })
  t.after(() => pool.close())
  const warmed = await pool.warm()
  assert.ok(warmed)
  const createCall = calls.find(c => c[0] === 'container' && c[1] === 'create')!
  assert.ok(createCall.some(a => a.startsWith(`${WORKER_OWNER_PID_LABEL}=`)))
  assert.ok(createCall.some(a => a.startsWith(`${WORKER_POOL_INSTANCE_LABEL}=`)))
  assert.ok(createCall.some(a => a.startsWith(`${WORKER_SESSION_LABEL}=`)))
  if (process.platform === 'linux') {
    assert.ok(createCall.some(a => a.startsWith(`${WORKER_OWNER_PID_NS_LABEL}=pid:[`)))
    assert.ok(createCall.some(a => a.startsWith(`${WORKER_OWNER_START_TIME_LABEL}=`)))
  }

  // isOwnerProvablyDead unit checks:
  assert.equal(
    isOwnerProvablyDead(
      { pid: 999999, pidNs: 'pid:[4026539999]' },
      { currentPidNs: 'pid:[4026531836]', isPidAlive: () => false },
    ),
    null,
    'foreign PID namespace must return null (fall back to TTL), never treat ESRCH as dead',
  )
  assert.equal(
    isOwnerProvablyDead(
      { pid: 1234, pidNs: 'pid:[4026531836]', startTime: '100' },
      { currentPidNs: 'pid:[4026531836]', isPidAlive: () => true, readPidStartTime: () => '999' },
    ),
    true,
    'recycled PID in same namespace whose startTime changed must be provably dead',
  )
  assert.equal(
    isOwnerProvablyDead(
      { pid: 1234, pidNs: 'pid:[4026531836]', startTime: '100' },
      { currentPidNs: 'pid:[4026531836]', isPidAlive: () => true, readPidStartTime: () => '100' },
    ),
    false,
    'same namespace + live PID + matching startTime must be alive',
  )

  // LinuxWorkerBackend sweep: foreign-namespace container is kept until foreignOwnerTtlMs; local dead is reaped.
  const foreignFreshId = '1'.repeat(64)
  const foreignFreshName = `kovo-${randomUUID()}`
  const foreignExpiredId = '2'.repeat(64)
  const foreignExpiredName = `kovo-${randomUUID()}`
  const localDeadId = '3'.repeat(64)
  const localDeadName = `kovo-${randomUUID()}`
  const recycledPidId = '4'.repeat(64)
  const recycledPidName = `kovo-${randomUUID()}`
  const now = Date.now()

  const rows = [
    `${foreignFreshId}\t${foreignFreshName}\t${now - 60_000}\t2026-11-25 00:00:00 +0000 UTC\t1\tpool-f1\tpid:[4026539999]\t10\tforeign-sess-1`,
    `${foreignExpiredId}\t${foreignExpiredName}\t${now - 40 * 60_000}\t2026-11-25 00:00:00 +0000 UTC\t1\tpool-f2\tpid:[4026539999]\t10\tforeign-sess-2`,
    `${localDeadId}\t${localDeadName}\t${now - 5_000}\t2026-11-25 00:00:00 +0000 UTC\t424242\tpool-l1\tpid:[4026531836]\t20\tlocal-sess-1`,
    `${recycledPidId}\t${recycledPidName}\t${now - 5_000}\t2026-11-25 00:00:00 +0000 UTC\t12345\tpool-l2\tpid:[4026531836]\t555\tlocal-sess-2`,
  ].join('\n')

  const removedIds: string[] = []
  const sweepBackend = new LinuxWorkerBackend({
    ownerPidNs: 'pid:[4026531836]',
    foreignOwnerTtlMs: 30 * 60_000,
    isPidAlive: pid => pid === 12345,
    readPidStartTime: pid => (pid === 12345 ? '777' : null),
    dockerRunner: async args => {
      if (args[0] === 'container' && args[1] === 'ls') return rows
      if (args[0] === 'container' && args[1] === 'rm') {
        removedIds.push(...args.slice(args.indexOf('--force') + 1))
      }
      return ''
    },
  })
  await sweepBackend.reclaimInactive()

  assert.equal(removedIds.includes(foreignFreshId), false, 'fresh foreign-namespace container must be spared')
  assert.equal(removedIds.includes(foreignExpiredId), true, 'expired foreign-namespace container past TTL must be swept')
  assert.equal(removedIds.includes(localDeadId), true, 'local dead-PID container must be swept')
  assert.equal(removedIds.includes(recycledPidId), true, 'local recycled-PID container (startTime mismatch) must be swept')
})

test('H-31: WarmWorkerPool.take() inspects state/instance, drops stale containers, and openSession falls back to cold create', async t => {
  const states = new Map<string, { status: string; instance: string }>()
  const createdNames: string[] = []
  const startedNames: string[] = []

  const runner: DockerRunner = async args => {
    const verb = args[0] === 'container' ? args[1] : args[0]
    if (verb === 'create') {
      const name = args[args.indexOf('--name') + 1]!
      const instArg = args.find(a => a.startsWith(`${WORKER_POOL_INSTANCE_LABEL}=`)) ?? ''
      const instance = instArg.slice(WORKER_POOL_INSTANCE_LABEL.length + 1)
      states.set(name, { status: 'created', instance })
      createdNames.push(name)
      return ''
    }
    if (verb === 'inspect') {
      const name = args[args.length - 1]!
      const entry = states.get(name)
      if (!entry) throw new Error(`Error: No such container: ${name}`)
      return `${entry.status}\t${entry.instance}\n`
    }
    if (verb === 'rm') {
      for (const arg of args.slice(args.indexOf('--force') + 1)) states.delete(arg)
      return ''
    }
    return ''
  }

  const spawner = (name: string): ChildProcess => {
    startedNames.push(name)
    const emitter = new EventEmitter() as EventEmitter & {
      stdin: PassThrough; stdout: PassThrough; stderr: PassThrough; kill: () => boolean
    }
    emitter.stdin = new PassThrough()
    emitter.stdout = new PassThrough()
    emitter.stderr = new PassThrough()
    emitter.kill = () => { emitter.emit('close', 0); return true }
    return emitter as unknown as ChildProcess
  }

  const backend = new LinuxWorkerBackend({
    workspace: { id: 'ws-h31-take', directory: tmpdir() },
    cell: 'cell-h31-take',
    dockerRunner: runner,
    sessionSpawner: spawner,
  })
  t.after(() => backend.closeWarmPool())
  backend.setWarmPoolPolicy('run-take:e1')
  const deadline = Date.now() + 2_000
  while (Date.now() < deadline && backend.getWarmPoolStats('run-take:e1')?.idle !== 1) {
    await new Promise(r => setTimeout(r, 10))
  }
  const staleWarm = createdNames[0]!
  assert.ok(staleWarm)

  // Simulate external removal (e.g. stale sweep from another process) before take().
  states.delete(staleWarm)

  const sess = await backend.openSession('asgn-cold-fallback', AbortSignal.timeout(5_000), {
    warmPoolPolicy: 'run-take:e1',
  })
  assert.equal(startedNames.length, 1)
  assert.notEqual(startedNames[0], staleWarm, 'take() must drop stale name and fall back to cold container')
  assert.equal(backend.containerStats().coldSessions, 1)
  assert.equal(backend.getWarmPoolStats('run-take:e1')?.idle, 0)
  await sess.close()
})

test('H-31: ContainerSupervisor does not reap a foreign PID 1 within TTL, while reaping local dead PIDs', async t => {
  const ws = withTempDir(t, 'kovo-h31-sup-')
  const live = new Map<string, { runId: string; ownerPid: string; pidNs: string; startTime: string; createdAt: string }>()
  const removed: string[] = []
  const nowIso = new Date().toISOString()
  const oldIso = new Date(Date.now() - 45 * 60_000).toISOString()

  live.set('kovo-lab-foreign-live', {
    runId: 'run-foreign-live',
    ownerPid: '1',
    pidNs: 'pid:[4026539999]',
    startTime: '1',
    createdAt: nowIso,
  })
  live.set('kovo-lab-foreign-expired', {
    runId: 'run-foreign-expired',
    ownerPid: '1',
    pidNs: 'pid:[4026539999]',
    startTime: '1',
    createdAt: oldIso,
  })
  live.set('kovo-lab-local-dead', {
    runId: 'run-local-dead',
    ownerPid: '54321',
    pidNs: 'pid:[4026531836]',
    startTime: '42',
    createdAt: nowIso,
  })

  const docker: LabDockerRunner = async args => {
    if (args[0] === 'ps' && args[1] === '-aq') {
      const f = args.find(a => a.startsWith('label=')) ?? ''
      if (f === `label=${LAB_LABELS.lab}=1`) return [...live.keys()].join('\n')
      if (f.startsWith(`label=${LAB_LABELS.run}=`)) {
        const rid = f.slice(`label=${LAB_LABELS.run}=`.length)
        return [...live.entries()].filter(([, v]) => v.runId === rid).map(([k]) => k).join('\n')
      }
      return ''
    }
    if (args[0] === 'inspect') {
      const fmt = args[2] ?? ''
      if (fmt.includes(LAB_OWNER_PID_LABEL)) {
        return args.slice(3).map(name => {
          const e = live.get(name)
          return e ? `${e.runId}\t${e.ownerPid}\t${e.pidNs}\t${e.startTime}\t${e.createdAt}` : ''
        }).filter(Boolean).join('\n')
      }
      return 'c1'
    }
    if (args[0] === 'container' && args[1] === 'rm') {
      for (const target of args.slice(3)) {
        live.delete(target)
        removed.push(target)
      }
      return ''
    }
    return ''
  }

  const supervisor = new ContainerSupervisor({
    stateDir: join(ws, 'state'),
    docker,
    ownerPid: 1,
    ownerPidNs: 'pid:[4026531836]',
    ownerStartTime: '999',
    foreignOwnerTtlMs: 30 * 60_000,
    isPidAlive: () => false,
  })

  const labels = supervisor.ownerExtraLabels()
  assert.equal(labels[LAB_OWNER_PID_LABEL], '1')
  assert.equal(labels[LAB_OWNER_PID_NS_LABEL], 'pid:[4026531836]')
  assert.equal(labels[LAB_OWNER_START_TIME_LABEL], '999')
  assert.ok(labels[LAB_OWNER_SESSION_LABEL])

  await supervisor.recoverAll()
  assert.equal(live.has('kovo-lab-foreign-live'), true, 'foreign PID 1 within TTL must NOT be reaped')
  assert.equal(removed.includes('kovo-lab-foreign-expired'), true, 'expired foreign container past TTL must be reaped')
  assert.equal(removed.includes('kovo-lab-local-dead'), true, 'local dead-PID container must be reaped')
})

// ============================================================================
// 4. store.ts trigger alignment (ProofReceipt prefix bypass closed)
// ============================================================================

test('store.ts confirmation trigger rejects direct SQL insert claiming ProofReceipt prefix without evidence', async t => {
  const dir = withTempDir(t, 'kovo-store-trig-')
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { runId } = await setupApprovedRun(storage, { seeds: ['http://127.0.0.1:7788'], environment: 'local-lab', tier: 2 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const fid = '00000000-0000-4000-8000-000000000099'

  assert.throws(
    () => storage.db.insert(findings).values({
      id: fid,
      runId: run.id,
      assetId: asset.id,
      goalRevision: run.goalRevision,
      checkId: 'chain',
      caseId: fid,
      findingKind: 'multi_step_chain',
      replaySpecId: null,
      provenance: 'agent_only',
      verificationClass: 'runtime_confirmed',
      sourceOrigins: ['http://127.0.0.1:7788'],
      verificationTier: 'runtime_confirmed',
      finding: {
        id: fid,
        origin: 'http://127.0.0.1:7788',
        title: 'Forged direct SQL ProofReceipt',
        status: 'confirmed',
        severity: 'high',
        reason: 'Forged',
        remediation: 'Fix',
        evidenceIds: [],
        scopeRevision: 1,
        category: 'broken-access-control',
        cwe: 'CWE-639',
        confidence: 'high',
        verification: 'ProofReceipt forged prefix without receipt row',
        verificationTier: 'runtime_confirmed',
        findingKind: 'multi_step_chain',
      },
    }).run(),
    (err: unknown) => /invariant\.confirmation_evidence/.test(String((err as Error)?.message ?? ''))
      || /invariant\.confirmation_evidence/.test(String((err as { cause?: Error })?.cause?.message ?? '')),
  )
})

// ============================================================================
// 5. consent.tsx PSL-backed registrableApex & rankScopeAssets (zero Node builtins)
// ============================================================================

test('consent.tsx uses browser-safe PSL registrableApex & rankScopeAssets with zero Node builtins', async () => {
  const consentPath = join(import.meta.dirname, '..', 'src', 'components', 'run', 'views', 'consent.tsx')
  const consentSrc = readFileSync(consentPath, 'utf8')
  assert.doesNotMatch(consentSrc, /from\s+['"]node:/, 'consent.tsx must never import Node builtins')

  // Transpile the pure PSL + ranking portion of consent.tsx cleanly without React/router runtime.
  const pslBlockEnd = consentSrc.indexOf('/** Hosts and default selection')
  assert.ok(pslBlockEnd > 0)
  const pslListSrc = readFileSync(join(import.meta.dirname, '..', 'src', 'server', 'public-suffix-list.ts'), 'utf8')
  const slice = consentSrc
    .slice(consentSrc.indexOf('const PSL_RULES'), pslBlockEnd)
    .replaceAll('export function ', 'function ')
    .replaceAll('export const ', 'const ')
  const combinedTs = `${pslListSrc}\n${slice}`
  const js = ts.transpileModule(combinedTs, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  const fn = new Function(
    `${js.replace(/^export /gm, '')}\nreturn { registrableApex, isMultiTenantPublicSuffix, rankScopeAssets, defaultScopeAssetIds };`,
  )
  const mod = fn() as {
    registrableApex: (s: string) => string | null
    isMultiTenantPublicSuffix: (h: string) => boolean
    rankScopeAssets: (assets: unknown[], seeds: string[], opts?: { maxAssets?: number }) => Array<{ asset: { id: string } }>
    defaultScopeAssetIds: (
      run: { scopeRevision: number; approved: string[]; candidates: Array<{ id: string; origin: string; source?: string; thirdParty: boolean; includeSubdomains?: boolean; dnsSource?: unknown }> },
      projectDefaultScope: string[],
      options?: { includeSubdomainOrigins?: string[]; maxAutoSelect?: number },
    ) => string[]
  }

  assert.equal(mod.registrableApex('https://api.acme.co.uk:8443/v1'), 'acme.co.uk')
  assert.equal(mod.registrableApex('https://sub.my-app.vercel.app'), 'my-app.vercel.app')
  assert.equal(mod.registrableApex('co.uk'), null)
  assert.equal(mod.registrableApex('vercel.app'), null)
  assert.equal(mod.isMultiTenantPublicSuffix('evil-other.vercel.app'), true)
  assert.equal(mod.isMultiTenantPublicSuffix('api.acme.co.uk'), false)

  // Shared PaaS tenant isolation (R2-H-5 / R3-H-8): vercel.app refuses auto-admit anchor so only seed stays checked!
  const pickedPaas = mod.defaultScopeAssetIds(
    {
      scopeRevision: 0,
      approved: [],
      candidates: [
        { id: 'seed-paas', origin: 'https://my-app.vercel.app', source: 'Project seed', thirdParty: false, includeSubdomains: true },
        { id: 'sub-own', origin: 'https://api.my-app.vercel.app', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
        { id: 'sibling-paas', origin: 'https://other-tenant.vercel.app', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
      ],
    },
    [],
    { includeSubdomainOrigins: ['https://my-app.vercel.app'] },
  )
  assert.deepEqual(pickedPaas, ['seed-paas'])

  // Multi-part ccTLD (.co.uk) includeSubdomains on apex seed selects api.acme.co.uk, not unrelated co.uk!
  const pickedUk = mod.defaultScopeAssetIds(
    {
      scopeRevision: 0,
      approved: [],
      candidates: [
        { id: 'seed-uk', origin: 'https://acme.co.uk', source: 'Project seed', thirdParty: false, includeSubdomains: true },
        { id: 'api-uk', origin: 'https://api.acme.co.uk', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
        { id: 'other-uk', origin: 'https://evil.co.uk', source: 'subdomain_discovery', thirdParty: false, dnsSource: {} },
      ],
    },
    [],
    { includeSubdomainOrigins: ['https://acme.co.uk'] },
  )
  assert.deepEqual(pickedUk, ['seed-uk', 'api-uk'])
})
