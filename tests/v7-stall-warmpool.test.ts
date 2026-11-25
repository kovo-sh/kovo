/**
 * v7 stall + warm-pool throughput guard.
 *
 *   1. per-turn no-token watchdog: 28 s of complete provider silence aborts, every token resets;
 *   2. one bounded requeue per assignment, with timeout/retry/wall-saved metrics;
 *   3. warm containers are reused only within one run + tenant + credential generation;
 *   4. a policy change (secret rotation) retires the pool, and a failed cleanup discards the
 *      container instead of returning it to the idle set;
 *   5. throughput metrics expose reused/idle containers and the reuse hit rate.
 *
 * No benchmark app, seed, route or truth file is consulted; fixtures are synthetic and the
 * container backend is a recording docker stub.
 */
import assert from 'node:assert/strict'
import { spawnSync, type ChildProcess } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { test } from 'node:test'

import {
  Execution,
  MAX_PROVIDER_STALL_RETRIES,
  PROVIDER_STALL_NO_TOKEN_MS,
  ProviderNoTokenWatchdog,
  resolveProviderStallNoTokenMs,
  secretGenerationFingerprint,
  shouldRetryStalledAssignment,
} from '../src/server/execution.ts'
import {
  LinuxWorkerBackend,
  MAX_WARM_POOL_CAPACITY,
  WARM_SCRATCH_RESET_COMMAND,
  WarmWorkerPool,
  warmPoolCapacity,
  type DockerRunner,
} from '../src/server/worker-backend.ts'
import type { Store } from '../src/server/store.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function internals(execution: Execution): Record<string, any> {
  return execution as unknown as Record<string, any>
}

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

/** Recording docker CLI stub: create/inspect/stop/rm/exec are enough for the warm-pool paths. */
function dockerStub() {
  const calls: string[][] = []
  const states = new Map<string, string>()
  const created: string[] = []
  const runner: DockerRunner = async args => {
    calls.push([...args])
    const verb = args[0] === 'container' ? args[1] : args[0]
    if (verb === 'create') {
      const name = args[args.indexOf('--name') + 1]!
      states.set(name, 'created')
      created.push(name)
      return ''
    }
    if (verb === 'inspect') {
      const name = args[args.length - 1]!
      return `${states.get(name) ?? 'missing'}\n`
    }
    if (verb === 'stop') {
      states.set(args[args.length - 1]!, 'exited')
      return ''
    }
    if (verb === 'rm') {
      const name = args[args.length - 1]!
      states.delete(name)
      return ''
    }
    if (verb === 'exec') return ''
    return ''
  }
  return { runner, calls, states, created }
}

// ============================================================================
// 1. Per-turn no-token watchdog
// ============================================================================

test('no-token watchdog fires once after silence and never after a token reset', t => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  assert.equal(PROVIDER_STALL_NO_TOKEN_MS, 28_000, 'product default is inside the 25–30 s window')
  assert.equal(resolveProviderStallNoTokenMs({}), 28_000)
  assert.equal(resolveProviderStallNoTokenMs({ KOVO_PROVIDER_NO_TOKEN_MS: '30000' }), 30_000)
  assert.equal(resolveProviderStallNoTokenMs({ KOVO_PROVIDER_NO_TOKEN_MS: '1' }), 5_000, 'lower bound')

  const fired: Array<{ turn: number; thresholdMs: number }> = []
  const watchdog = new ProviderNoTokenWatchdog({
    thresholdMs: () => 30_000,
    onStall: info => fired.push({ turn: info.turn, thresholdMs: info.thresholdMs }),
  })

  // Hung stream: one firing, no repeated fires from the same arm.
  watchdog.arm(3)
  t.mock.timers.tick(29_999)
  assert.equal(fired.length, 0, 'still inside the no-token window')
  t.mock.timers.tick(1)
  assert.equal(fired.length, 1)
  assert.deepEqual(fired[0], { turn: 3, thresholdMs: 30_000 })
  assert.equal(watchdog.active, false, 'a fired watchdog is disarmed')
  t.mock.timers.tick(60_000)
  assert.equal(fired.length, 1, 'one streak produces one timeout')

  // Slow-but-streaming turn: a token at 20 s restarts the full 30 s window.
  watchdog.arm(4)
  t.mock.timers.tick(20_000)
  watchdog.noteToken()
  t.mock.timers.tick(25_000)
  assert.equal(fired.length, 1, 'a token after 20 s must not trip the timeout')
  t.mock.timers.tick(5_000)
  assert.equal(fired.length, 2, 'silence after the last token still aborts')
  assert.equal(fired[1]!.turn, 4)
})

test('stall retries are bounded to one per assignment', () => {
  assert.equal(MAX_PROVIDER_STALL_RETRIES, 1)
  assert.equal(shouldRetryStalledAssignment(0), true)
  assert.equal(shouldRetryStalledAssignment(1), false)
  assert.equal(shouldRetryStalledAssignment(2), false)
})

test('credential-generation fingerprint changes only on rotation', () => {
  const base = secretGenerationFingerprint(['alice:1', 'bob:4'])
  assert.equal(base, secretGenerationFingerprint(['bob:4', 'alice:1']), 'order independent')
  assert.notEqual(base, secretGenerationFingerprint(['alice:2', 'bob:4']), 'rotation changes the epoch')
  assert.notEqual(base, secretGenerationFingerprint(['alice:1']), 'persona set changes the epoch')
})

// ============================================================================
// 2. Warm-pool reuse rules
// ============================================================================

test('a clean session returns its container to the pool and is reused', async () => {
  const docker = dockerStub()
  const pool = new WarmWorkerPool({
    cell: 'cell-reuse',
    image: 'kovo-worker:test',
    dockerRunner: docker.runner,
    runLabel: 'run-a',
    capacity: 1,
  })
  const created = await pool.warm()
  assert.ok(created)
  const first = await pool.take(new AbortController().signal)
  assert.equal(first, created)
  assert.equal(await pool.release(first!), true, 'clean stopped container is pooled')
  const second = await pool.take(new AbortController().signal)
  assert.equal(second, first, 'same run reuses the same warm container')
  assert.equal(pool.stats.reused, 1)
  assert.equal(pool.stats.returned, 1)
})

test('a failed cleanup discards the container instead of pooling it', async () => {
  const docker = dockerStub()
  const pool = new WarmWorkerPool({
    cell: 'cell-dirty',
    image: 'kovo-worker:test',
    dockerRunner: docker.runner,
    runLabel: 'run-a',
    capacity: 1,
  })
  const created = await pool.warm()
  const taken = await pool.take(new AbortController().signal)
  assert.equal(taken, created)
  // The session died mid-operation: the container is still running.
  docker.states.set(taken!, 'running')
  assert.equal(await pool.release(taken!), false, 'running container is not reusable')
  assert.equal(pool.stats.discarded, 1)
  assert.equal(pool.stats.idle, 0)

  const replacement = await pool.take(new AbortController().signal)
  assert.ok(replacement)
  assert.notEqual(replacement, taken, 'a new container replaces the discarded one')
  assert.equal(pool.stats.reused, 0, 'the dirty container was never reused')
})

test('warm pools never merge two tenants in the same cell', async () => {
  const docker = dockerStub()
  const tenantA = new LinuxWorkerBackend({
    workspace: { id: 'tenant-a', directory: '/tmp' },
    cell: 'shared-cell',
    dockerRunner: docker.runner,
  })
  const tenantB = new LinuxWorkerBackend({
    workspace: { id: 'tenant-b', directory: '/tmp' },
    cell: 'shared-cell',
    dockerRunner: docker.runner,
  })
  tenantA.setWarmPoolPolicy('run-x:gen1')
  tenantB.setWarmPoolPolicy('run-x:gen1')
  await waitFor(() => tenantA.warmPoolStats?.idle === 1 && tenantB.warmPoolStats?.idle === 1, 'both pools warm')
  assert.equal(docker.created.length, 2, 'each tenant gets its own warm container')
  assert.notEqual(tenantA.warmPoolStats?.state, undefined)
  assert.notEqual(tenantB.warmPoolStats?.state, undefined)
})

test('a credential rotation retires idle containers and rebuilds the pool', async () => {
  const docker = dockerStub()
  const backend = new LinuxWorkerBackend({
    workspace: { id: 'tenant-rotate', directory: '/tmp' },
    cell: 'rotate-cell',
    dockerRunner: docker.runner,
  })
  backend.setWarmPoolPolicy('run-z:gen1')
  await waitFor(() => backend.warmPoolStats?.idle === 1, 'first pool warm')
  const firstContainer = docker.created[0]!

  backend.setWarmPoolPolicy('run-z:gen2')
  await waitFor(() => backend.warmPoolStats?.idle === 1 && docker.created.length >= 2, 'second pool warm')
  assert.ok(
    docker.calls.some(args => args[0] === 'container' && args[1] === 'rm' && args.includes(firstContainer)),
    'the old-generation container is removed',
  )
  assert.notEqual(docker.created.at(-1), firstContainer, 'a fresh container serves the rotated generation')
  assert.ok(backend.containerStats().created >= 2, 'launch metrics survive the pool rollover')
})

test('teardown removes idle warm containers from the host', async () => {
  const docker = dockerStub()
  const backend = new LinuxWorkerBackend({
    workspace: { id: 'tenant-teardown', directory: '/tmp' },
    cell: 'teardown-cell',
    dockerRunner: docker.runner,
  })
  backend.setWarmPoolPolicy('run-t:gen1')
  await waitFor(() => backend.warmPoolStats?.idle === 1, 'pool warm')
  const idleName = docker.created[0]!
  await backend.closeWarmPool()
  assert.equal(backend.warmPoolStats, undefined)
  assert.ok(
    docker.calls.some(args => args[0] === 'container' && args[1] === 'rm' && args.includes(idleName)),
    'idle container is removed on teardown',
  )
})

test('warm capacity is bounded up to 12 to match dynamic worker concurrency', () => {
  assert.equal(MAX_WARM_POOL_CAPACITY, 12)
  assert.equal(warmPoolCapacity({ KOVO_WARM_SLOTS: '6' }), 6)
  assert.equal(warmPoolCapacity({ KOVO_WARM_SLOTS: '12' }), 12)
  assert.equal(warmPoolCapacity({ KOVO_WARM_SLOTS: '99' }), 12, 'hard ceiling')
  assert.equal(warmPoolCapacity({}), 1, 'platform default before Execution sizes the pool')

  const docker = dockerStub()
  const pool = new WarmWorkerPool({
    cell: 'cell-cap-12',
    image: 'kovo-worker:test',
    dockerRunner: docker.runner,
    runLabel: 'run-cap',
    capacity: 12,
  })
  assert.equal(pool.stats.capacity, 12)
  pool.setCapacity(20)
  assert.equal(pool.stats.capacity, 12, 'setCapacity enforces the hard ceiling of 12')
})

test('warm scratch reset wipes regular files, single-dot hidden files, and double-dot files in /tmp', t => {
  assert.match(WARM_SCRATCH_RESET_COMMAND, /\/tmp\/\*/)
  assert.match(WARM_SCRATCH_RESET_COMMAND, /\/tmp\/\.\[!\.\]\*/)
  assert.match(WARM_SCRATCH_RESET_COMMAND, /\/tmp\/\.\.\?\*/)
  assert.doesNotMatch(WARM_SCRATCH_RESET_COMMAND, /\/repos|\/kovo-rpc|\/kovo-ipc/)

  const dir = mkdtempSync(join(tmpdir(), 'kovo-warm-reset-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  writeFileSync(join(dir, 'scratch.txt'), 'a')
  writeFileSync(join(dir, '.hidden'), 'b')
  writeFileSync(join(dir, '..double'), 'c')
  mkdirSync(join(dir, '.nested-dir'))
  writeFileSync(join(dir, '.nested-dir', 'inside.txt'), 'd')
  mkdirSync(join(dir, '..double-dir'))
  writeFileSync(join(dir, '..double-dir', 'inside.txt'), 'e')

  const cmd = WARM_SCRATCH_RESET_COMMAND.replaceAll('/tmp', dir)
  const firstRun = spawnSync('sh', ['-c', cmd], { encoding: 'utf8' })
  assert.equal(firstRun.status, 0)
  assert.deepEqual(readdirSync(dir), [], 'all regular, .dot, and ..dot entries are removed')

  // Idempotent when the scratch directory is already empty.
  const secondRun = spawnSync('sh', ['-c', cmd], { encoding: 'utf8' })
  assert.equal(secondRun.status, 0)
})

function fakeSessionSpawner(onStop?: Map<string, () => void>) {
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

test('white-box reposDir reuses warm containers, resets /tmp, bypasses on rpcMountDir, and cleans up staged mounts', async t => {
  const root = mkdtempSync(join(tmpdir(), 'kovo-warm-wb-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  // Restrictive host mode (0o700) forces prepareReposMount() to stage a clean container-readable copy.
  const reposDir = join(root, 'repo-src')
  mkdirSync(reposDir, { mode: 0o700 })
  chmodSync(reposDir, 0o700)
  writeFileSync(join(reposDir, 'app.ts'), 'export const ok = true\n', { mode: 0o600 })
  writeFileSync(join(reposDir, '.env'), 'SECRET=should-not-be-mounted\n', { mode: 0o600 })

  const rpcDir = join(root, 'rpc-sock')
  mkdirSync(rpcDir, { mode: 0o755 })

  const stopHooks = new Map<string, () => void>()
  const docker = dockerStub()
  const runner: DockerRunner = async (args, signal, input) => {
    const out = await docker.runner(args, signal, input)
    if (args[0] === 'container' && args[1] === 'stop') {
      const name = args[args.length - 1]!
      stopHooks.get(name)?.()
    }
    return out
  }
  const { spawner, started } = fakeSessionSpawner(stopHooks)

  const backend = new LinuxWorkerBackend({
    workspace: { id: 'tenant-whitebox', directory: root },
    cell: 'wb-cell',
    dockerRunner: runner,
    sessionSpawner: spawner,
  })
  t.after(() => backend.closeWarmPool())

  backend.setWarmPoolPolicy('run-wb:gen1', { reposDir })
  await waitFor(() => backend.warmPoolStats?.idle === 1, 'white-box warm pool ready')

  const createCalls = () => docker.calls.filter(args => args[0] === 'container' && args[1] === 'create')
  assert.equal(createCalls().length, 1, 'prewarms exactly one container with /repos mounted')
  const mountFlag = createCalls()[0]!.find(arg => arg.includes('target=/repos,readonly'))
  assert.ok(mountFlag, 'warm container mounts /repos read-only')
  const stagedDir1 = /^type=bind,source=(.+),target=\/repos,readonly$/.exec(mountFlag!)?.[1]
  assert.ok(stagedDir1 && stagedDir1 !== reposDir && existsSync(stagedDir1), 'staged /repos dir exists once for policy')
  assert.equal(existsSync(join(stagedDir1!, 'app.ts')), true, 'source file staged')
  assert.equal(existsSync(join(stagedDir1!, '.env')), false, 'sensitive .env excluded from staged /repos')

  // First white-box assignment: warm hit (no cold create).
  const s1 = await backend.openSession('asgn-wb-1', new AbortController().signal, { reposDir })
  assert.equal(backend.containerStats().coldSessions, 0, 'first white-box assignment hits warm pool')
  assert.equal(backend.containerStats().created, 1)
  await s1.close()
  assert.equal(backend.warmPoolStats?.idle, 1, 'clean white-box container returns to idle pool')
  assert.ok(
    docker.calls.some(args => args[0] === 'container' && args[1] === 'exec' && args.includes(WARM_SCRATCH_RESET_COMMAND)),
    'closing pooled session runs hardened /tmp reset command',
  )

  // Second white-box assignment: reuses the exact same warm container without re-staging or re-creating.
  const s2 = await backend.openSession('asgn-wb-2', new AbortController().signal, { reposDir })
  assert.equal(started[1], started[0], 'second assignment reuses the same container')
  assert.equal(backend.containerStats().reused, 1, 'reuse counter increments on white-box hit')
  assert.equal(backend.containerStats().coldSessions, 0, 'still zero cold creates')
  assert.equal(createCalls().length, 1, 'no second container create')
  await s2.close()
  assert.equal(backend.warmPoolStats?.idle, 1)

  // Layer-1 rpcMountDir session MUST cold-bypass the warm pool even when reposDir matches.
  const sRpc = await backend.openSession('asgn-rpc-1', new AbortController().signal, { reposDir, rpcMountDir: rpcDir })
  assert.equal(backend.containerStats().coldSessions, 1, 'rpcMountDir forces cold container bypass')
  assert.equal(backend.warmPoolStats?.idle, 1, 'warm container remains untouched in idle pool')
  assert.equal(createCalls().length, 2, 'cold create runs for rpcMountDir session')
  assert.ok(
    createCalls()[1]!.some(arg => arg.includes('target=/kovo-rpc,readonly')),
    'cold rpc session mounts per-call /kovo-rpc',
  )
  await sRpc.close()

  // Policy rotation cleans up previous staged /repos mount and prepares a new one.
  backend.setWarmPoolPolicy('run-wb:gen2', { reposDir })
  await waitFor(() => backend.warmPoolStats?.idle === 1 && createCalls().length >= 3, 'rotated warm pool ready')
  assert.equal(existsSync(stagedDir1!), false, 'previous staged /repos dir cleaned up on policy rotation')
  const mountFlag2 = createCalls()[2]!.find(arg => arg.includes('target=/repos,readonly'))
  const stagedDir2 = /^type=bind,source=(.+),target=\/repos,readonly$/.exec(mountFlag2 ?? '')?.[1]
  assert.ok(stagedDir2 && existsSync(stagedDir2), 'new staged /repos dir created for rotated policy')

  // Teardown cleans up the active staged /repos mount as well.
  await backend.closeWarmPool()
  assert.equal(existsSync(stagedDir2!), false, 'staged /repos dir cleaned up on closeWarmPool()')
})

// ============================================================================
// 3. Metrics
// ============================================================================

test('throughput metrics expose timeouts, wall saved and container reuse hit rate', async t => {
  const { storage } = makeStore(t, 'kovo-v7-stall-warmpool-db-') as { storage: Store }
  const setup = await setupApprovedRun(storage, { seeds: ['https://stall.warmpool.test'], tier: 3, budgetRequests: 900 })
  storage.updateRun(setup.runId, { phase: 'investigation', status: 'running' })
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const state = internals(execution)
  state.providerStallTurnsByRun.set(setup.runId, 4)
  state.providerStallRetriesByRun.set(setup.runId, 2)
  state.providerStallTimeoutsByRun.set(setup.runId, 2)
  state.providerStallWallSavedByRun.set(setup.runId, 124_000)
  state.warmPoolPolicyRotationsByRun.set(setup.runId, 1)
  state.recordAssignmentMetrics(setup.runId, 'test')

  const metrics = execution.getAssignmentThroughput(setup.runId)
  assert.ok(metrics)
  assert.equal(metrics!.providerStallTimeouts, 2)
  assert.equal(metrics!.providerStallWallSavedMs, 124_000)
  assert.equal(metrics!.warmPoolPolicyRotations, 1)
  assert.equal(metrics!.containerReuseHitRate, 0, 'no sessions yet')
  assert.equal(typeof metrics!.idleWarmContainers, 'number')
  assert.equal(typeof metrics!.warmCapacity, 'number')

  const event = storage.eventsAfter(setup.runId, 0, 500).find(entry => entry.kind === 'agentic.assignment_metrics')
  assert.ok(event, 'metrics are mirrored into a run event')
  const detail = event!.detail as Record<string, unknown>
  assert.equal(detail.providerStallTimeouts, 2)
  assert.equal(detail.providerStallWallSavedMs, 124_000)
  assert.equal(detail.containerReuseHitRate, 0)
})
