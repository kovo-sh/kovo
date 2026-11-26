import assert from 'node:assert/strict'
import { type ChildProcess } from 'node:child_process'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import test from 'node:test'
import {
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import {
  LinuxWorkerBackend,
  MAX_ACTIVE_WARM_POOLS,
  dockerHost,
  ensureRpcMountReadable,
  prepareReposMount,
  prepareSessionScratchDir,
  type DockerRunner,
} from '../src/server/worker-backend.ts'

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function waitFor(check: () => boolean, label: string, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (check()) return
    await sleep(10)
  }
  throw new Error(`timed out waiting for ${label}`)
}

function dockerStubWithStop(stopHooks: Map<string, () => void>) {
  const calls: string[][] = []
  const states = new Map<string, string>()
  const created: Array<{ name: string; runLabel: string; reposMount?: string }> = []
  const removed: string[] = []
  const runner: DockerRunner = async args => {
    calls.push([...args])
    const verb = args[0] === 'container' ? args[1] : args[0]
    if (verb === 'create') {
      const name = args[args.indexOf('--name') + 1]!
      const runLabel = args.find(a => a.startsWith('dev.kovo.run=')) ?? ''
      const reposMount = args.find(a => a.includes('target=/repos,readonly'))
      states.set(name, 'created')
      created.push({ name, runLabel, reposMount })
      return ''
    }
    if (verb === 'inspect') {
      const name = args[args.length - 1]!
      return `${states.get(name) ?? 'missing'}\n`
    }
    if (verb === 'stop') {
      const name = args[args.length - 1]!
      states.set(name, 'exited')
      stopHooks.get(name)?.()
      return ''
    }
    if (verb === 'rm') {
      for (const arg of args.slice(2)) {
        if (arg.startsWith('-')) continue
        states.delete(arg)
        removed.push(arg)
      }
      return ''
    }
    return ''
  }
  return { runner, calls, states, created, removed }
}

function fakeSessionSpawner(stopHooks: Map<string, () => void>) {
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
    stopHooks.set(name, finish)
    return emitter as unknown as ChildProcess
  }
  return { spawner, started }
}

test('C3: concurrent runs maintain isolated warm pools, never steal across policies, and evict cleanly', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-c3-iso-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const repoA = join(root, 'repo-a')
  const repoB = join(root, 'repo-b')
  mkdirSync(repoA, { mode: 0o700 })
  mkdirSync(repoB, { mode: 0o700 })
  writeFileSync(join(repoA, 'a.ts'), 'export const a = 1\n', { mode: 0o600 })
  writeFileSync(join(repoB, 'b.ts'), 'export const b = 2\n', { mode: 0o600 })

  const stopHooks = new Map<string, () => void>()
  const docker = dockerStubWithStop(stopHooks)
  const { spawner, started } = fakeSessionSpawner(stopHooks)

  const backend = new LinuxWorkerBackend({
    workspace: { id: 'ws-shared', directory: root },
    cell: 'c3-iso-cell',
    dockerRunner: docker.runner,
    sessionSpawner: spawner,
  })
  t.after(() => backend.closeWarmPool())

  // Install Run A and wait for its prewarmed container.
  backend.setWarmPoolPolicy('run-a:epoch1', { reposDir: repoA })
  await waitFor(() => backend.getWarmPoolStats('run-a:epoch1')?.idle === 1, 'run-a warm pool ready')
  const runAContainer1 = docker.created[0]!.name
  const stagedA = /^type=bind,source=(.+),target=\/repos,readonly$/.exec(docker.created[0]!.reposMount ?? '')?.[1]
  assert.ok(stagedA && existsSync(stagedA))

  // Installing Run B MUST NOT retire or destroy Run A's pool or container.
  backend.setWarmPoolPolicy('run-b:epoch1', { reposDir: repoB })
  await waitFor(() => backend.getWarmPoolStats('run-b:epoch1')?.idle === 1, 'run-b warm pool ready')
  const runBContainer1 = docker.created[1]!.name
  assert.equal(backend.activeWarmPoolCount, 2)
  assert.equal(backend.getWarmPoolStats('run-a:epoch1')?.idle, 1, 'Run A pool remains idle after Run B installs policy')
  assert.equal(docker.removed.includes(runAContainer1), false, 'Run A container must NOT be removed by Run B')
  assert.equal(existsSync(stagedA!), true, 'Run A staged /repos must NOT be deleted by Run B')

  // Run A session strictly acquires Run A's container even though Run B was installed last.
  const sessA1 = await backend.openSession('asgn-a1', new AbortController().signal, {
    reposDir: repoA,
    warmPoolPolicy: 'run-a:epoch1',
  })
  assert.equal(started[0], runAContainer1, 'Run A must acquire Run A container')

  // Run B session concurrently acquires Run B's container.
  const sessB1 = await backend.openSession('asgn-b1', new AbortController().signal, {
    reposDir: repoB,
    warmPoolPolicy: 'run-b:epoch1',
  })
  assert.equal(started[1], runBContainer1, 'Run B must acquire Run B container')

  // An unknown policy never steals from Run A or Run B pools (falls back to cold create).
  const sessC = await backend.openSession('asgn-c1', new AbortController().signal, {
    reposDir: repoA,
    warmPoolPolicy: 'run-c:epoch1',
  })
  assert.notEqual(started[2], runAContainer1)
  assert.notEqual(started[2], runBContainer1)
  assert.equal(backend.containerStats().coldSessions, 1)
  await sessC.close()

  // Closing Run A and Run B returns each container to its own run's pool and reuses it.
  await sessA1.close()
  await sessB1.close()
  assert.equal(backend.getWarmPoolStats('run-a:epoch1')?.idle, 1)
  assert.equal(backend.getWarmPoolStats('run-b:epoch1')?.idle, 1)

  const sessA2 = await backend.openSession('asgn-a2', new AbortController().signal, {
    reposDir: repoA,
    warmPoolPolicy: 'run-a:epoch1',
  })
  assert.equal(started[3], runAContainer1, 'Run A reuses its own returned container')
  await sessA2.close()

  // Secret rotation on Run A retires ONLY Run A's epoch1 container and leaves Run B untouched.
  backend.setWarmPoolPolicy('run-a:epoch2', { reposDir: repoA })
  await waitFor(() => backend.getWarmPoolStats('run-a:epoch2')?.idle === 1, 'run-a epoch2 ready')
  assert.equal(docker.removed.includes(runAContainer1), true, 'Run A epoch1 container removed on Run A rotation')
  assert.equal(docker.removed.includes(runBContainer1), false, 'Run B container untouched by Run A rotation')
  assert.equal(backend.getWarmPoolStats('run-a:epoch1'), undefined)
  assert.equal(backend.getWarmPoolStats('run-b:epoch1')?.idle, 1)

  // evictRunWarmPool('run-a') evicts only Run A, leaving Run B operational.
  const runAContainer2 = docker.created.at(-1)!.name
  await backend.evictRunWarmPool('run-a')
  assert.equal(docker.removed.includes(runAContainer2), true, 'Run A epoch2 container removed on evictRunWarmPool')
  assert.equal(backend.getWarmPoolStats('run-a:epoch2'), undefined)
  assert.equal(backend.getWarmPoolStats('run-b:epoch1')?.idle, 1, 'Run B survives Run A eviction')
})

test('C3: LinuxWorkerBackend enforces bounded LRU across distinct run pools', async t => {
  const stopHooks = new Map<string, () => void>()
  const docker = dockerStubWithStop(stopHooks)
  const backend = new LinuxWorkerBackend({
    workspace: { id: 'ws-lru', directory: '/tmp' },
    cell: 'c3-lru-cell',
    dockerRunner: docker.runner,
    maxWarmPools: 2,
  })
  t.after(() => backend.closeWarmPool())
  assert.equal(MAX_ACTIVE_WARM_POOLS, 16)

  backend.setWarmPoolPolicy('run-1:e1')
  await waitFor(() => backend.getWarmPoolStats('run-1:e1')?.idle === 1, 'run-1 warm')
  const c1 = docker.created[0]!.name

  backend.setWarmPoolPolicy('run-2:e1')
  await waitFor(() => backend.getWarmPoolStats('run-2:e1')?.idle === 1, 'run-2 warm')

  // Installing a 3rd run evicts the oldest LRU run ('run-1:e1').
  backend.setWarmPoolPolicy('run-3:e1')
  await waitFor(() => backend.getWarmPoolStats('run-3:e1')?.idle === 1, 'run-3 warm')
  assert.equal(backend.activeWarmPoolCount, 2)
  assert.equal(backend.getWarmPoolStats('run-1:e1'), undefined, 'oldest LRU pool evicted')
  assert.equal(docker.removed.includes(c1), true, 'evicted LRU pool removes its idle container')
  assert.equal(backend.getWarmPoolStats('run-2:e1')?.idle, 1)
  assert.equal(backend.getWarmPoolStats('run-3:e1')?.idle, 1)
})

test('C4: dockerHost restricts tcp:// to loopback/local compose proxy unless KOVO_ALLOW_REMOTE_DOCKER_HOST=1', () => {
  // Always allowed: unix socket, loopback, docker-proxy.
  assert.equal(dockerHost({}), 'unix:///var/run/docker.sock')
  assert.equal(dockerHost({ DOCKER_HOST: 'tcp://127.0.0.1:2375' }), 'tcp://127.0.0.1:2375')
  assert.equal(dockerHost({ DOCKER_HOST: 'tcp://localhost:2375' }), 'tcp://localhost:2375')
  assert.equal(dockerHost({ DOCKER_HOST: 'tcp://[::1]:2375' }), 'tcp://[::1]:2375')
  assert.equal(dockerHost({ DOCKER_HOST: 'tcp://[::ffff:127.0.0.1]:2375' }), 'tcp://[::ffff:127.0.0.1]:2375')
  assert.equal(dockerHost({ DOCKER_HOST: 'tcp://docker-proxy:2375' }), 'tcp://docker-proxy:2375')

  // With DooD scratch configured: compose DNS + RFC1918/ULA allowed, metadata/public REJECTED.
  const doodEnv = { KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch' }
  assert.equal(dockerHost({ ...doodEnv, DOCKER_HOST: 'tcp://custom-socket-proxy:2375' }), 'tcp://custom-socket-proxy:2375')
  assert.equal(dockerHost({ ...doodEnv, DOCKER_HOST: 'tcp://172.18.0.2:2375' }), 'tcp://172.18.0.2:2375')
  assert.equal(dockerHost({ ...doodEnv, DOCKER_HOST: 'tcp://10.0.0.5:2375' }), 'tcp://10.0.0.5:2375')
  assert.equal(dockerHost({ ...doodEnv, DOCKER_HOST: 'tcp://192.168.1.50:2375' }), 'tcp://192.168.1.50:2375')
  assert.equal(dockerHost({ ...doodEnv, DOCKER_HOST: 'tcp://[fd00::2]:2375' }), 'tcp://[fd00::2]:2375')
  assert.equal(dockerHost({ ...doodEnv, DOCKER_HOST: 'tcp://host.docker.internal:2375' }), 'tcp://host.docker.internal:2375')

  for (const blocked of [
    'tcp://169.254.169.254:2375',
    'tcp://[::ffff:169.254.169.254]:2375',
    'tcp://metadata.google.internal:2375',
    'tcp://8.8.8.8:2375',
    'tcp://0.0.0.0:2375',
    'tcp://docker.example:2376',
    'tcp://evil.public.example:2375',
  ]) {
    assert.throws(
      () => dockerHost({ ...doodEnv, DOCKER_HOST: blocked }),
      /local Docker Unix socket/,
      `must reject ${blocked} even when DooD scratch is configured`,
    )
  }

  // Explicit opt-in allows remote TCP endpoints.
  assert.equal(
    dockerHost({ DOCKER_HOST: 'tcp://docker.example:2376', KOVO_ALLOW_REMOTE_DOCKER_HOST: '1' }),
    'tcp://docker.example:2376',
  )
})

test('C4: UID 10001 tightens scratch, RPC, and staged /repos permissions to 0o700 / 0o600', async t => {
  const scratch = mkdtempSync(join(tmpdir(), 'kovo-c4-perms-'))
  t.after(() => rmSync(scratch, { recursive: true, force: true }))

  const originalGetuid = process.getuid
  process.getuid = () => 10001
  t.after(() => { process.getuid = originalGetuid })

  const env: NodeJS.ProcessEnv = {
    KOVO_CONTAINER_SCRATCH_DIR: join(scratch, 'scratch'),
    KOVO_WORKER_SCRATCH_VOLUME: 'kovo_scratch',
  }
  const ipcDir = prepareSessionScratchDir('sess-10001', 'ipc', env)
  assert.equal(statSync(ipcDir).mode & 0o777, 0o700, 'scratch subdir must be 0o700 under UID 10001')

  const rpcDir = join(scratch, 'rpc')
  mkdirSync(rpcDir, { mode: 0o755 })
  chmodSync(rpcDir, 0o755)
  const tokenPath = join(rpcDir, VERIFY_RPC_TOKEN_NAME)
  const contextPath = join(rpcDir, VERIFY_RPC_CONTEXT_NAME)
  const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
  writeFileSync(tokenPath, 'tok\n', { mode: 0o644 })
  writeFileSync(contextPath, '{}\n', { mode: 0o644 })
  const server = createServer()
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, () => {
      server.off('error', reject)
      resolve()
    })
  })
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())))
  chmodSync(socketPath, 0o666)

  ensureRpcMountReadable(rpcDir)
  assert.equal(statSync(rpcDir).mode & 0o777, 0o700, 'RPC dir tightened to 0o700 for UID 10001')
  assert.equal(statSync(tokenPath).mode & 0o777, 0o600, 'RPC token tightened to 0o600 for UID 10001')
  assert.equal(statSync(contextPath).mode & 0o777, 0o600, 'RPC context tightened to 0o600 for UID 10001')
  assert.equal(lstatSync(socketPath).mode & 0o777, 0o600, 'RPC socket tightened to 0o600 for UID 10001')

  const srcRepo = join(scratch, 'repo')
  mkdirSync(srcRepo, { mode: 0o700 })
  writeFileSync(join(srcRepo, 'index.ts'), 'export const ok = 1\n', { mode: 0o600 })
  const staged = prepareReposMount(srcRepo, { sessionId: 'sess-repo-10001', env })
  assert.ok(staged && staged.staged)
  t.after(() => staged?.cleanup())
  assert.equal(statSync(staged!.mountDir).mode & 0o777, 0o700, 'staged /repos dir must be 0o700 under UID 10001')
  assert.equal(statSync(join(staged!.mountDir, 'index.ts')).mode & 0o777, 0o600, 'staged /repos file must be 0o600 under UID 10001')
})

test('C4, worker/Dockerfile arm64, and verify.yml hardening contracts hold', () => {
  const repoRoot = join(import.meta.dirname, '..')
  const compose = readFileSync(join(repoRoot, 'docker-compose.yml'), 'utf8')
  const dockerfile = readFileSync(join(repoRoot, 'Dockerfile'), 'utf8')
  const workerDockerfile = readFileSync(join(repoRoot, 'worker', 'Dockerfile'), 'utf8')
  const verifyYml = readFileSync(join(repoRoot, '.github', 'workflows', 'verify.yml'), 'utf8')

  assert.match(compose, /"\$\{KOVO_BIND_HOST:-127\.0\.0\.1\}:\$\{KOVO_PORT:-8000\}:8000"/)
  assert.match(dockerfile, /chmod 0700 \/data \/scratch/)

  assert.doesNotMatch(workerDockerfile, /ARG TARGETARCH=amd64/, 'must not hardcode TARGETARCH=amd64 default')
  assert.match(workerDockerfile, /ARG TARGETARCH\b/)
  assert.match(workerDockerfile, /arm64\|aarch64/)
  assert.match(workerDockerfile, /TRIVY_ARCH="ARM64"/)
  assert.match(workerDockerfile, /\/out\/bin\/gitleaks version/)
  assert.match(workerDockerfile, /\/out\/bin\/trufflehog --version/)
  assert.match(workerDockerfile, /\/out\/bin\/trivy --version/)
  assert.match(workerDockerfile, /\/out\/bin\/opengrep --version/)

  assert.match(verifyYml, /timeout-minutes:\s*30/)
  assert.match(verifyYml, /timeout-minutes:\s*12/)
  assert.match(verifyYml, /npm run build && KOVO_ALLOW_LOCAL_MODEL=1 node --test tests\/e2e-ui-journeys\.test\.ts/)
})
