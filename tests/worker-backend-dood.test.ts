import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import {
  LinuxWorkerBackend,
  dockerCliRunner,
  dockerEnv,
  dockerHost,
  ensureWorkerImageAvailable,
  prepareReposMount,
  prepareSessionScratchDir,
  resolveDoodMountArg,
  resolveDoodScratchConfig,
  workerAutoPullEnabled,
  workerContainerCreateArgs,
} from '../src/server/worker-backend.ts'

function withTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function withEnv(t: test.TestContext, overrides: Record<string, string | undefined>): void {
  const previous = new Map<string, string | undefined>()
  for (const [key, val] of Object.entries(overrides)) {
    previous.set(key, process.env[key])
    if (val === undefined) delete process.env[key]
    else process.env[key] = val
  }
  t.after(() => {
    for (const [key, val] of previous) {
      if (val === undefined) delete process.env[key]
      else process.env[key] = val
    }
  })
}

function extractMounts(args: string[]): string[] {
  const mounts: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--mount' && args[i + 1]) {
      mounts.push(args[i + 1]!)
    }
  }
  return mounts
}

test('host-native mode: resolveDoodScratchConfig returns null and host bind behavior is unchanged', t => {
  const root = withTempDir(t, 'kovo-dood-native-')
  const ipcDir = join(root, 'ipc')
  const reposDir = join(root, 'repos')
  mkdirSync(ipcDir, { mode: 0o755 })
  mkdirSync(reposDir, { mode: 0o755 })
  writeFileSync(join(reposDir, 'app.ts'), 'export const ok = 1\n', { mode: 0o644 })

  const env: NodeJS.ProcessEnv = {}
  assert.equal(resolveDoodScratchConfig(env), null)
  assert.equal(workerAutoPullEnabled(env), false)

  const args = workerContainerCreateArgs({
    image: 'kovo-worker:v4',
    name: 'kovo-' + randomUUID(),
    assignmentId: randomUUID(),
    runLabel: 'native-test',
    ipcDir,
    options: { reposDir },
    env,
  })
  const mounts = extractMounts(args)
  assert.deepEqual(mounts, [
    `type=bind,source=${realpathSync(reposDir)},target=/repos,readonly`,
    `type=bind,source=${realpathSync(ipcDir)},target=/kovo-ipc`,
  ])
})

test('KOVO_HOST_SCRATCH_DIR translates per-session container paths without exposing root scratch', t => {
  const scratchRoot = realpathSync(withTempDir(t, 'kovo-dood-bind-'))
  const env: NodeJS.ProcessEnv = {
    KOVO_CONTAINER_SCRATCH_DIR: scratchRoot,
    KOVO_HOST_SCRATCH_DIR: '/var/lib/kovo/scratch',
  }

  const config = resolveDoodScratchConfig(env)
  assert.deepEqual(config, {
    mode: 'host_bind',
    containerScratchDir: realpathSync(scratchRoot),
    hostScratchDir: '/var/lib/kovo/scratch',
  })

  const ipcDir = prepareSessionScratchDir('sess-alpha', 'ipc', env)
  const reposDir = prepareSessionScratchDir('sess-alpha', 'repos', env)
  const rpcDir = prepareSessionScratchDir('sess-alpha', 'rpc', env)
  writeFileSync(join(reposDir, 'index.ts'), 'export const a = 1\n', { mode: 0o644 })
  writeFileSync(join(rpcDir, 'token'), 'tok\n', { mode: 0o444 })
  writeFileSync(join(rpcDir, 'context.json'), '{}', { mode: 0o444 })

  const args = workerContainerCreateArgs({
    image: 'ghcr.io/kovo-sh/kovo-worker:latest',
    name: 'kovo-' + randomUUID(),
    assignmentId: randomUUID(),
    runLabel: 'dood-bind',
    ipcDir,
    options: { reposDir, rpcMountDir: rpcDir },
    env,
  })

  const mounts = extractMounts(args)
  assert.deepEqual(mounts, [
    'type=bind,source=/var/lib/kovo/scratch/sess-alpha/repos,target=/repos,readonly',
    'type=bind,source=/var/lib/kovo/scratch/sess-alpha/rpc,target=/kovo-rpc,readonly',
    'type=bind,source=/var/lib/kovo/scratch/sess-alpha/ipc,target=/kovo-ipc',
  ])
})

test('KOVO_WORKER_SCRATCH_VOLUME emits per-session volume-subpath mounts', t => {
  const scratchRoot = realpathSync(withTempDir(t, 'kovo-dood-vol-'))
  const env: NodeJS.ProcessEnv = {
    KOVO_CONTAINER_SCRATCH_DIR: scratchRoot,
    KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch',
  }

  const config = resolveDoodScratchConfig(env)
  assert.deepEqual(config, {
    mode: 'volume_subpath',
    containerScratchDir: realpathSync(scratchRoot),
    volumeName: 'kovo_scratch',
  })

  const ipcDir = prepareSessionScratchDir('sess-beta', 'ipc', env)
  const reposDir = prepareSessionScratchDir('sess-beta', 'repos', env)
  writeFileSync(join(reposDir, 'main.py'), 'print(1)\n', { mode: 0o644 })

  const args = workerContainerCreateArgs({
    image: 'ghcr.io/kovo-sh/kovo-worker:latest',
    name: 'kovo-' + randomUUID(),
    assignmentId: randomUUID(),
    runLabel: 'dood-vol',
    ipcDir,
    options: { reposDir },
    env,
  })

  const mounts = extractMounts(args)
  assert.deepEqual(mounts, [
    'type=volume,source=kovo_scratch,target=/repos,volume-subpath=sess-beta/repos,readonly',
    'type=volume,source=kovo_scratch,target=/kovo-ipc,volume-subpath=sess-beta/ipc',
  ])
})

test('path-traversal, root-scratch mount, outside path, and symlink escape are rejected', t => {
  const scratchRoot = withTempDir(t, 'kovo-dood-sec-')
  const outsideDir = withTempDir(t, 'kovo-dood-outside-')
  writeFileSync(join(outsideDir, 'secret.txt'), 'nope\n')

  const env: NodeJS.ProcessEnv = {
    KOVO_CONTAINER_SCRATCH_DIR: scratchRoot,
    KOVO_HOST_SCRATCH_DIR: '/host/scratch',
  }

  // Root scratch directory itself must NEVER be mounted into a worker.
  assert.throws(
    () => resolveDoodMountArg(scratchRoot, '/kovo-ipc', { env }),
    /per-session subdirectory/i,
  )

  // `..` traversal must be rejected.
  assert.throws(
    () => resolveDoodMountArg(`${scratchRoot}/sess-1/../../etc`, '/kovo-ipc', { env }),
    /Invalid worker scratch mount path/i,
  )
  assert.throws(
    () => resolveDoodMountArg(`${scratchRoot}/../${scratchRoot.split('/').at(-1)}/sess-1`, '/kovo-ipc', { env }),
    /Invalid worker scratch mount path/i,
  )

  // Path outside KOVO_CONTAINER_SCRATCH_DIR must be rejected.
  assert.throws(
    () => resolveDoodMountArg(outsideDir, '/kovo-ipc', { env }),
    /per-session subdirectory/i,
  )

  // Symlink inside scratch pointing outside scratch must be rejected.
  const symlinkEscape = join(scratchRoot, 'sess-symlink-escape')
  symlinkSync(outsideDir, symlinkEscape)
  assert.throws(
    () => resolveDoodMountArg(symlinkEscape, '/kovo-ipc', { env }),
    /per-session subdirectory/i,
  )

  // Comma injection in mount path must be rejected.
  assert.throws(
    () => resolveDoodMountArg(`${scratchRoot}/sess-1,readonly=false`, '/kovo-ipc', { env }),
    /Invalid worker scratch mount path/i,
  )

  // Invalid session identifiers and env configs must be rejected.
  assert.throws(() => prepareSessionScratchDir('../escape', 'ipc', env), /Invalid worker scratch session identifier/i)
  assert.throws(() => prepareSessionScratchDir('sess/nested', 'ipc', env), /Invalid worker scratch session identifier/i)
  assert.throws(
    () => resolveDoodScratchConfig({ KOVO_HOST_SCRATCH_DIR: 'relative/path' }),
    /absolute host path/i,
  )
  assert.throws(
    () => resolveDoodScratchConfig({ KOVO_HOST_SCRATCH_DIR: '/host/../etc' }),
    /Invalid KOVO_HOST_SCRATCH_DIR/i,
  )
  assert.throws(
    () => resolveDoodScratchConfig({ KOVO_WORKER_SCRATCH_VOLUME: 'bad,volume=name' }),
    /Invalid KOVO_WORKER_SCRATCH_VOLUME/i,
  )
})

test('LinuxWorkerBackend.run stages repos & IPC in isolated per-session scratch subdirs and cleans up', async t => {
  const scratchRoot = withTempDir(t, 'kovo-dood-run-scratch-')
  const externalRepos = withTempDir(t, 'kovo-dood-src-repo-')
  mkdirSync(join(externalRepos, 'app'), { mode: 0o700 })
  writeFileSync(join(externalRepos, 'app', 'server.ts'), 'export const x = 1\n', { mode: 0o600 })
  writeFileSync(join(externalRepos, 'app', '.env'), 'SECRET=123\n', { mode: 0o600 })

  withEnv(t, {
    KOVO_CONTAINER_SCRATCH_DIR: scratchRoot,
    KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch',
    KOVO_HOST_SCRATCH_DIR: undefined,
    KOVO_WARM_WORKERS: '0',
  })

  const createCalls: string[][] = []
  const backend = new LinuxWorkerBackend({
    dockerRunner: async args => {
      if (args[0] === 'container' && args[1] === 'create') {
        createCalls.push(args)
        // While container create runs, staged per-session dirs exist under scratchRoot.
        const sessionDirs = readdirSync(scratchRoot)
        assert.equal(sessionDirs.length, 1)
        const stagedRepoDir = join(scratchRoot, sessionDirs[0]!, 'repos')
        assert.equal(existsSync(join(stagedRepoDir, 'app', 'server.ts')), true)
        assert.equal(existsSync(join(stagedRepoDir, 'app', '.env')), false, 'sensitive .env must still be excluded')
        return 'created'
      }
      if (args[0] === 'container' && args[1] === 'start') {
        return JSON.stringify({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} })
      }
      return ''
    },
  })

  const res = await backend.run(
    { assignmentId: randomUUID(), files: [], command: 'echo ok', outputs: [] },
    AbortSignal.timeout(5_000),
    { reposDir: externalRepos },
  )
  assert.equal(res.exitCode, 0)
  assert.equal(createCalls.length, 1)
  const mounts = extractMounts(createCalls[0]!)
  assert.equal(mounts.length, 2)
  assert.match(mounts[0]!, /^type=volume,source=kovo_scratch,target=\/repos,volume-subpath=run-[a-f0-9-]+\/repos,readonly$/)
  assert.match(mounts[1]!, /^type=volume,source=kovo_scratch,target=\/kovo-ipc,volume-subpath=run-[a-f0-9-]+\/ipc$/)

  // Verify cleanup removed all per-session directories after run().
  assert.deepEqual(readdirSync(scratchRoot), [])

  // Also test prepareReposMount cleans up in DooD mode.
  const prep = prepareReposMount(externalRepos, { sessionId: 'unit-prep' })
  assert.ok(prep && prep.staged)
  assert.equal(existsSync(join(scratchRoot, 'unit-prep', 'repos', 'app', 'server.ts')), true)
  prep!.cleanup()
  assert.equal(existsSync(join(scratchRoot, 'unit-prep')), false)
})

test('DOCKER_HOST is preserved for socket-proxy TCP and preserved when spawning docker CLI', async t => {
  assert.equal(dockerHost({}), 'unix:///var/run/docker.sock')
  assert.equal(dockerHost({ DOCKER_HOST: 'tcp://docker-proxy:2375' }), 'tcp://docker-proxy:2375')
  assert.equal(
    dockerHost({
      DOCKER_HOST: 'tcp://custom-socket-proxy:2375',
      KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch',
    }),
    'tcp://custom-socket-proxy:2375',
  )
  assert.throws(
    () => dockerHost({ DOCKER_HOST: 'tcp://docker.example:2376' }),
    /local Docker Unix socket/,
  )

  const envResult = dockerEnv({
    PATH: '/usr/bin',
    DOCKER_HOST: 'tcp://docker-proxy:2375',
    XDG_RUNTIME_DIR: '/run/user/1000',
  })
  assert.equal(envResult.DOCKER_HOST, 'tcp://docker-proxy:2375')

  // Spawn real `dockerCliRunner` against a shim `docker` binary on PATH to verify subprocess env.
  const shimDir = withTempDir(t, 'kovo-docker-shim-')
  const shimBin = join(shimDir, 'docker')
  writeFileSync(
    shimBin,
    '#!/usr/bin/env sh\nprintf "%s" "$DOCKER_HOST"\n',
    { mode: 0o755 },
  )
  chmodSync(shimBin, 0o755)

  withEnv(t, {
    PATH: `${shimDir}:${process.env.PATH ?? ''}`,
    DOCKER_HOST: 'tcp://docker-proxy:2375',
  })
  const observed = await dockerCliRunner(['version'], AbortSignal.timeout(5_000))
  assert.equal(observed, 'tcp://docker-proxy:2375')
})

test('KOVO_WORKER_AUTO_PULL=1 inspects first, deduplicates concurrent pulls, and reports errors clearly', async () => {
  const image = 'ghcr.io/kovo-sh/kovo-worker:sha-1234567'

  // 1. Disabled by default: zero docker calls.
  let disabledCalls = 0
  await ensureWorkerImageAvailable(
    image,
    async () => { disabledCalls += 1; return '' },
    AbortSignal.timeout(5_000),
    { env: {} },
  )
  assert.equal(disabledCalls, 0)

  // 2. Enabled + image already present locally: inspect succeeds, pull NOT called.
  const presentCalls: string[][] = []
  await ensureWorkerImageAvailable(
    image,
    async args => { presentCalls.push(args); return '[{ "Id": "sha256:abc" }]' },
    AbortSignal.timeout(5_000),
    { env: { KOVO_WORKER_AUTO_PULL: '1' } },
  )
  assert.deepEqual(presentCalls, [['image', 'inspect', image]])

  // 3. Enabled + missing locally + 5 concurrent calls: inspect ONCE, pull ONCE!
  let inspectCount = 0
  let pullCount = 0
  let releasePull!: () => void
  const pullGate = new Promise<void>(resolve => { releasePull = resolve })
  const sharedRunner = async (args: string[]) => {
    if (args[0] === 'image' && args[1] === 'inspect') {
      inspectCount += 1
      throw new Error('No such image')
    }
    if (args[0] === 'pull') {
      pullCount += 1
      await pullGate
      return 'Pulled'
    }
    return ''
  }

  const waiters = Array.from({ length: 5 }, () =>
    ensureWorkerImageAvailable(image, sharedRunner, AbortSignal.timeout(5_000), {
      env: { KOVO_WORKER_AUTO_PULL: '1' },
    }),
  )
  // Let all 5 enter the shared task before completing the pull.
  await new Promise(resolve => setTimeout(resolve, 20))
  assert.equal(inspectCount, 1)
  assert.equal(pullCount, 1)
  releasePull()
  await Promise.all(waiters)

  // 4. Failed pull reports clear error and allows retry after recovery.
  let shouldFail = true
  const retryRunner = async (args: string[]) => {
    if (args[0] === 'image' && args[1] === 'inspect') throw new Error('missing')
    if (args[0] === 'pull') {
      if (shouldFail) throw new Error('registry 503')
      return 'Pulled'
    }
    return ''
  }
  await assert.rejects(
    () => ensureWorkerImageAvailable(image, retryRunner, AbortSignal.timeout(5_000), {
      env: { KOVO_WORKER_AUTO_PULL: '1' },
    }),
    /Failed to pull worker image "ghcr\.io\/kovo-sh\/kovo-worker:sha-1234567".*registry 503/,
  )
  shouldFail = false
  await ensureWorkerImageAvailable(image, retryRunner, AbortSignal.timeout(5_000), {
    env: { KOVO_WORKER_AUTO_PULL: '1' },
  })
})

test('LinuxWorkerBackend uses KOVO_WORKER_IMAGE env and deduplicates auto-pull across concurrent runs', async t => {
  withEnv(t, {
    KOVO_WORKER_IMAGE: 'ghcr.io/kovo-sh/kovo-worker:v1.2.3',
    KOVO_WORKER_AUTO_PULL: '1',
    KOVO_WARM_WORKERS: '0',
  })
  const imagesSeen: string[] = []
  let inspectCount = 0
  let pullCount = 0
  const backend = new LinuxWorkerBackend({
    dockerRunner: async args => {
      if (args[0] === 'image' && args[1] === 'inspect') {
        inspectCount += 1
        throw new Error('not found')
      }
      if (args[0] === 'pull') {
        pullCount += 1
        await new Promise(resolve => setTimeout(resolve, 20))
        return 'Pulled'
      }
      if (args[0] === 'container' && args[1] === 'create') {
        imagesSeen.push(args.at(-1)!)
        return 'created'
      }
      if (args[0] === 'container' && args[1] === 'start') {
        return JSON.stringify({ exitCode: 0, stdout: '', stderr: '', outputs: {} })
      }
      return ''
    },
  })
  await Promise.all([
    backend.run({ assignmentId: randomUUID(), files: [], command: 'true', outputs: [] }, AbortSignal.timeout(5_000)),
    backend.run({ assignmentId: randomUUID(), files: [], command: 'true', outputs: [] }, AbortSignal.timeout(5_000)),
  ])
  assert.equal(inspectCount, 1)
  assert.equal(pullCount, 1)
  assert.deepEqual(imagesSeen, [
    'ghcr.io/kovo-sh/kovo-worker:v1.2.3',
    'ghcr.io/kovo-sh/kovo-worker:v1.2.3',
  ])
})

test('packaging artifacts (Dockerfile, .dockerignore, docker-compose.yml, docker-publish.yml) enforce security invariants', () => {
  const repoRoot = join(import.meta.dirname, '..')
  const dockerfile = readFileSync(join(repoRoot, 'Dockerfile'), 'utf8')
  const dockerignore = readFileSync(join(repoRoot, '.dockerignore'), 'utf8')
  const compose = readFileSync(join(repoRoot, 'docker-compose.yml'), 'utf8')
  const workflow = readFileSync(join(repoRoot, '.github/workflows/docker-publish.yml'), 'utf8')

  assert.match(dockerfile, /FROM docker:27-cli AS docker-cli/)
  assert.match(dockerfile, /ARG KOVO_WORKER_IMAGE=ghcr\.io\/kovo-sh\/kovo-worker:latest/)
  assert.match(dockerfile, /USER 10001:10001/)
  assert.match(dockerfile, /http:\/\/127\.0\.0\.1:.*\/health/)
  assert.match(dockerfile, /org\.opencontainers\.image\.source="https:\/\/github\.com\/kovo-sh\/kovo"/)

  for (const ignored of ['.git', 'node_modules', 'build', 'benchmarks', 'local-lab', 'plans', '*.sqlite*', '.env*']) {
    assert.ok(dockerignore.includes(ignored), `.dockerignore missing ${ignored}`)
  }

  assert.match(compose, /tecnativa\/docker-socket-proxy:0\.3/)
  assert.match(compose, /internal:\s*true/)
  assert.match(compose, /DOCKER_HOST:\s*tcp:\/\/docker-proxy:2375/)
  assert.match(compose, /KOVO_WORKER_AUTO_PULL:\s*"1"/)
  assert.match(compose, /kovo_data:/)
  assert.match(compose, /kovo_scratch:/)

  assert.match(workflow, /packages:\s*write/)
  assert.match(workflow, /attestations:\s*write/)
  assert.match(workflow, /platform:\s*linux\/amd64/)
  assert.match(workflow, /platform:\s*linux\/arm64/)
  assert.match(workflow, /actions\/attest-build-provenance@v2/)
  assert.match(workflow, /scripts\/docker-smoke\.sh/)
  assert.match(workflow, /workflow_call:/)
  assert.doesNotMatch(workflow, /tags:\s*\['v\*'\]/)
  assert.doesNotMatch(workflow, /github\.event_name\s*==\s*'workflow_call'/)

  const releaseWorkflow = readFileSync(join(repoRoot, '.github/workflows/release.yml'), 'utf8')
  assert.match(releaseWorkflow, /workflow_dispatch:/)
  assert.match(releaseWorkflow, /environment:\s*release/)
  assert.match(releaseWorkflow, /actions\/create-github-app-token@v2/)
  assert.match(releaseWorkflow, /RELEASE_APP_ID/)
  assert.match(releaseWorkflow, /RELEASE_APP_PRIVATE_KEY/)
  assert.match(releaseWorkflow, /permission-contents:\s*write/)
  assert.match(releaseWorkflow, /verify\.yml\/runs/)
  assert.match(releaseWorkflow, /git merge-base --is-ancestor/)
  assert.match(releaseWorkflow, /uses:\s*\.\/\.github\/workflows\/docker-publish\.yml/)
  assert.match(releaseWorkflow, /needs:\s*\[prepare,\s*approve-and-tag\]/)
  assert.match(releaseWorkflow, /needs:\s*\[prepare,\s*approve-and-tag,\s*publish-containers\]/)
})
