// Gate-v5 worker container hygiene: create→start failures, aborts and abandoned
// `created` containers must never outlive the operation that made them.
//
// The stub-runner tests are deterministic and Docker-free; the final test is
// Docker-gated (the release gate runs it with the daemon available) and proves
// reclaim works against real `created` containers without touching fresh ones.
import assert from 'node:assert/strict'
import { execFile as execFileCb } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import test from 'node:test'
import { promisify } from 'node:util'
import { LinuxWorkerBackend, dockerCliRunner } from '../src/server/worker-backend.ts'

const execFile = promisify(execFileCb)

const job = () => ({ assignmentId: randomUUID(), files: [], command: 'true', outputs: [] as string[] })

type Call = { args: string[]; input?: string }

function stubDocker(handler: (args: string[], signal: AbortSignal) => Promise<string> | string) {
  const calls: Call[] = []
  const runner = async (args: string[], signal: AbortSignal, input?: string) => {
    calls.push({ args, input })
    return handler(args, signal)
  }
  return { calls, runner }
}

const isCmd = (call: Call, ...head: string[]) => head.every((h, i) => call.args[i] === h)
const rmTargets = (calls: Call[]) => calls
  .filter(c => isCmd(c, 'container', 'rm', '--force'))
  .flatMap(c => c.args.slice(3))

async function dockerAvailable() {
  try {
    await execFile('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 5_000 })
    return true
  } catch {
    return false
  }
}

test('worker lifecycle: create succeeds but start fails -> the container is removed before the call rejects', async () => {
  const { calls, runner } = stubDocker(args => {
    if (isCmd({ args }, 'container', 'ls')) return ''
    if (isCmd({ args }, 'container', 'create')) return 'created'
    if (isCmd({ args }, 'container', 'start')) throw new Error('daemon refused to start the container')
    return ''
  })
  const backend = new LinuxWorkerBackend({ dockerRunner: runner })
  await assert.rejects(() => backend.run(job(), AbortSignal.timeout(5_000)), /refused to start/)
  const removed = rmTargets(calls)
  assert.equal(removed.length, 1, 'exactly one rm --force must target the failed container')
  assert.match(removed[0], /^guardian-[a-f0-9-]{36}$/)
})

test('worker lifecycle: abort during start -> finally removes the created container', async () => {
  const { calls, runner } = stubDocker((args, signal) => {
    if (isCmd({ args }, 'container', 'ls')) return ''
    if (isCmd({ args }, 'container', 'create')) return 'created'
    if (isCmd({ args }, 'container', 'start')) {
      return new Promise<string>((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true })
      })
    }
    return ''
  })
  const backend = new LinuxWorkerBackend({ dockerRunner: runner })
  await assert.rejects(() => backend.run(job(), AbortSignal.timeout(50)))
  assert.equal(rmTargets(calls).length, 1, 'an aborted startup must still remove the container')
})

test('worker lifecycle: created containers carry run, assignment, session and timestamp labels', async () => {
  const { calls, runner } = stubDocker(args => {
    if (isCmd({ args }, 'container', 'ls')) return ''
    if (isCmd({ args }, 'container', 'create')) return 'created'
    if (isCmd({ args }, 'container', 'start')) return JSON.stringify({ exitCode: 0, stdout: '', stderr: '', outputs: {} })
    return ''
  })
  const backend = new LinuxWorkerBackend({ runId: 'run-gate-v5', dockerRunner: runner })
  const raw = job()
  await backend.run(raw, AbortSignal.timeout(5_000))
  const create = calls.find(c => isCmd(c, 'container', 'create'))
  assert.ok(create, 'create was invoked')
  const labels = create!.args.flatMap((arg, i) => arg === '--label' ? [create!.args[i + 1]] : [])
  const get = (name: string) => labels.find(l => l.startsWith(name + '='))?.slice(name.length + 1)
  assert.equal(get('dev.guardian.run'), 'run-gate-v5')
  assert.equal(get('dev.guardian.assignment'), raw.assignmentId)
  assert.match(get('dev.guardian.session') ?? '', /^[a-f0-9-]{36}$/)
  assert.ok(Number(get('dev.guardian.created-at')) > 0)
})

test('worker lifecycle: ownerless backends reclaim stale created containers but spare in-flight ones', async () => {
  const staleName = 'guardian-' + randomUUID()
  const freshName = 'guardian-' + randomUUID()
  const staleId = 'a'.repeat(64)
  const freshId = 'b'.repeat(64)
  const now = Date.now()
  const rows = [
    `${staleId}\t${staleName}\t${now - 10 * 60_000}\t2026-11-22 02:00:00 -0800 PST`,
    `${freshId}\t${freshName}\t${now}\t2026-11-22 02:00:00 -0800 PST`,
  ].join('\n')
  const { calls, runner } = stubDocker(args => {
    if (isCmd({ args }, 'container', 'ls')) return rows
    return ''
  })
  const backend = new LinuxWorkerBackend({ dockerRunner: runner })
  await backend.reclaimInactive()
  const removed = rmTargets(calls)
  assert.deepEqual(removed, [staleId], 'only the aged created container is reclaimed')
  assert.ok(!removed.includes(freshId))
  assert.ok(!removed.includes(staleName), 'removal is by immutable id, not by name')
})

test('worker lifecycle: reclaim is idempotent and concurrent callers share one sweep', async () => {
  let lists = 0
  const { calls, runner } = stubDocker(args => {
    if (isCmd({ args }, 'container', 'ls')) {
      lists += 1
      return ''
    }
    return ''
  })
  const backend = new LinuxWorkerBackend({ dockerRunner: runner })
  await Promise.all([backend.reclaimInactive(), backend.reclaimInactive(), backend.reclaimInactive()])
  assert.equal(lists, 1, 'in-flight reclaim is coalesced')
  await backend.reclaimInactive()
  assert.equal(lists, 2, 'a later call sweeps again')
  assert.equal(rmTargets(calls).length, 0)
})

test('worker lifecycle (docker): abandoned created container is reaped, fresh created container survives', async t => {
  if (!(await dockerAvailable())) {
    t.skip('Docker daemon unavailable')
    return
  }
  const image = 'guardian-worker:v4'
  const staleName = 'guardian-' + randomUUID()
  const freshName = 'guardian-' + randomUUID()
  const now = Date.now()
  const create = (name: string, createdAt: number) => execFile('docker', [
    'container', 'create', '--name', name, '--network', 'none',
    '--label', 'dev.guardian.assignment=' + randomUUID(),
    '--label', 'dev.guardian.session=gate-v5-test',
    '--label', 'dev.guardian.created-at=' + createdAt,
    image, '--session',
  ], { timeout: 15_000 })
  await create(staleName, now - 10 * 60_000)
  await create(freshName, now)
  t.after(async () => {
    await execFile('docker', ['container', 'rm', '--force', staleName, freshName], { timeout: 15_000 }).catch(() => undefined)
  })
  const backend = new LinuxWorkerBackend()
  await backend.reclaimInactive()
  const list = async (name: string) => (await execFile('docker', ['container', 'ls', '--all', '--no-trunc', '--filter', 'name=^' + name + '$', '--format', '{{.ID}}'], { timeout: 5_000 })).stdout.trim()
  assert.equal(await list(staleName), '', 'aged created container must be reaped')
  assert.notEqual(await list(freshName), '', 'a fresh created container may be an in-flight create from another stream')
})

async function containersForAssignment(assignmentId: string) {
  try {
    const { stdout } = await execFile('docker', [
      'container', 'ls', '--all', '--filter', `label=dev.guardian.assignment=${assignmentId}`, '--format', '{{.ID}} {{.Names}} {{.Status}}',
    ], { timeout: 5_000 })
    return stdout.trim()
  } catch {
    return ''
  }
}

test('worker lifecycle (docker): normal completion leaves no container behind', async t => {
  if (!(await dockerAvailable())) {
    t.skip('Docker daemon unavailable')
    return
  }
  const backend = new LinuxWorkerBackend()
  const raw = job()
  const result = await backend.run(raw, AbortSignal.timeout(60_000))
  assert.equal(result.exitCode, 0)
  assert.equal(await containersForAssignment(raw.assignmentId), '', 'a completed worker must be removed')
})

test('worker lifecycle (docker): forced start failure removes the created container exactly once', async t => {
  if (!(await dockerAvailable())) {
    t.skip('Docker daemon unavailable')
    return
  }
  let createSeen = false
  let removed = 0
  const runner = async (args: string[], signal: AbortSignal, input?: string) => {
    if (args[0] === 'container' && args[1] === 'create') createSeen = true
    if (args[0] === 'container' && args[1] === 'start') throw new Error('simulated start failure')
    if (args[0] === 'container' && args[1] === 'rm') removed += 1
    return dockerCliRunner(args, signal, input)
  }
  const backend = new LinuxWorkerBackend({ dockerRunner: runner })
  const raw = job()
  await assert.rejects(() => backend.run(raw, AbortSignal.timeout(30_000)), /simulated start failure/)
  assert.equal(createSeen, true, 'the container must have been created before start failed')
  assert.equal(removed, 1, 'cleanup must run exactly once')
  assert.equal(await containersForAssignment(raw.assignmentId), '', 'a failed startup must not leak its container')
})

test('worker lifecycle (docker): double-close and abort never throw "removal already in progress"', async t => {
  if (!(await dockerAvailable())) {
    t.skip('Docker daemon unavailable')
    return
  }
  const backend = new LinuxWorkerBackend()
  const raw = job()
  const session = await backend.openSession(raw.assignmentId, AbortSignal.timeout(30_000))
  await Promise.all([session.close(), session.close(), session.close()])
  assert.equal(await containersForAssignment(raw.assignmentId), '', 'double-close must still remove the container')
  await session.close().catch(() => undefined)

  const abortAssignment = randomUUID()
  const controller = new AbortController()
  const aborted = await backend.openSession(abortAssignment, controller.signal)
  controller.abort(new Error('scope revoked'))
  await aborted.close().catch(() => undefined)
  await new Promise(resolve => setTimeout(resolve, 250))
  assert.equal(await containersForAssignment(abortAssignment), '', 'an aborted session must not leak its container')
})
