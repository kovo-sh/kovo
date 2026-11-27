/**
 * Per-Run Warm Container Pool (Proposal 1) unit & isolation tests.
 *
 * Verifies:
 *  1. Cross-run isolation: distinct runs get distinct per-run warm `run-verify` containers and
 *     distinct host RPC root dirs; unattributed calls fail closed to cold single-use containers.
 *  2. Mode-A fresh-attempt isolation & warm container reuse: Attempt 1 & Attempt 2 of `kovo_verify`
 *     reuse ONE hardened per-run `run-verify` container (`container create` count = 1), each with
 *     disjoint `<attemptId>` RPC dirs/sockets/tokens, live Unix-socket forwarding, immediate host
 *     dir deletion on close, and private `/tmp/kovo-attempt-<nonce>` dirs wiped in `finally`.
 *  3. `registerRunDisposer` integration (`runAllRunDisposers(runId)`): evicts all warm verify and
 *     work containers for the disposed run while leaving concurrent runs completely untouched.
 *  4. `worker/bridge.ts` `runVerifyScript`: backward-compatible env fallback, per-op RPC path
 *     overrides, path traversal rejection, and wiped private `TMPDIR`/`HOME` per attempt.
 *  5. Exec spawn failure resilience: unhealthy warm verify container is evicted and falls back
 *     cleanly to a cold container without leaking host RPC dirs.
 */
import assert from 'node:assert/strict'
import { type ChildProcess } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createServer as createHttpServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { PassThrough } from 'node:stream'
import { describe, test } from 'node:test'
import { PTC_CONTAINER_DIR } from '../src/server/ptc-rpc.ts'
import { VERIFY_ROOT_CONTAINER_DIR } from '../src/server/run-container-pool.ts'
import { runAllRunDisposers } from '../src/server/run-disposers.ts'
import {
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-claims.ts'
import { LinuxWorkerBackend, type DockerRunner } from '../src/server/worker-backend.ts'
import { runVerifyScript } from '../worker/bridge.ts'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-wcp-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

async function createFakeVerifyRpcDir(
  t: { after(fn: () => void | Promise<void>): void },
  input: { runId?: string; nonce: string; token: string; withSocket?: boolean },
): Promise<{ dir: string; socketPath: string; hits: string[] }> {
  const dir = makeTempDir(t, 'kovo-rpc-src-')
  writeFileSync(join(dir, VERIFY_RPC_TOKEN_NAME), input.token + '\n', { mode: 0o600 })
  if (input.runId !== undefined) {
    writeFileSync(
      join(dir, VERIFY_RPC_CONTEXT_NAME),
      JSON.stringify({ nonce: input.nonce, runId: input.runId, targetOrigins: ['https://example.test'], sdkVersion: 'kovo_verify/v8' }),
      { mode: 0o600 },
    )
  }
  const socketPath = join(dir, VERIFY_RPC_SOCKET_NAME)
  const hits: string[] = []
  if (input.withSocket) {
    const srv = createHttpServer((req, res) => {
      hits.push(`${req.method} ${req.url} tok=${req.headers['x-kovo-rpc-token'] ?? ''}`)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, nonce: input.nonce }))
    })
    await new Promise<void>((resolve, reject) => {
      srv.once('error', reject)
      srv.listen(socketPath, () => { srv.off('error', reject); resolve() })
    })
    t.after(() => new Promise<void>(resolve => srv.close(() => resolve())))
  }
  return { dir, socketPath, hits }
}

function unixGet(socketPath: string, token: string): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath, path: '/ping', method: 'GET', headers: { 'x-kovo-rpc-token': token } }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown> }))
    })
    req.on('error', reject)
    req.end()
  })
}

function makeStubDocker() {
  const creates: Array<{ name: string; args: string[] }> = []
  const starts: string[] = []
  const removals: string[] = []
  const states = new Map<string, string>()
  const runner: DockerRunner = async args => {
    const verb = args[0] === 'container' ? args[1] : args[0]
    if (verb === 'create') {
      const name = args[args.indexOf('--name') + 1]!
      creates.push({ name, args: [...args] })
      states.set(name, 'created')
      return ''
    }
    if (verb === 'start') {
      const name = args[args.length - 1]!
      starts.push(name)
      states.set(name, 'running')
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
      for (const arg of args.slice(2)) {
        if (!arg.startsWith('-')) {
          states.delete(arg)
          removals.push(arg)
        }
      }
      return ''
    }
    return ''
  }
  return { runner, creates, starts, removals, states }
}

function makeFakeExecSpawner(onVerify?: (msg: Record<string, unknown>) => Record<string, unknown>) {
  const execCalls: Array<{ containerName: string; execArgs: string[] }> = []
  const ndjsonMsgs: Record<string, unknown>[] = []
  const spawnExec = (containerName: string, execArgs: string[]): ChildProcess => {
    execCalls.push({ containerName, execArgs: [...execArgs] })
    const emitter = new EventEmitter() as ChildProcess
    const stdin = new PassThrough()
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    ;(emitter as unknown as { stdin: PassThrough; stdout: PassThrough; stderr: PassThrough }).stdin = stdin
    ;(emitter as unknown as { stdout: PassThrough }).stdout = stdout
    ;(emitter as unknown as { stderr: PassThrough }).stderr = stderr
    let closed = false
    const finish = () => { if (!closed) { closed = true; emitter.emit('close', 0, null) } }
    ;(emitter as unknown as { kill: () => boolean }).kill = () => { finish(); return true }
    let buf = ''
    stdin.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8')
      let nl = buf.indexOf('\n')
      while (nl !== -1) {
        const line = buf.slice(0, nl).trim()
        buf = buf.slice(nl + 1)
        if (line) {
          const msg = JSON.parse(line) as Record<string, unknown>
          ndjsonMsgs.push(msg)
          if (msg.op === 'shutdown') {
            stdout.write(JSON.stringify({ id: msg.id, ok: true }) + '\n')
            finish()
          } else {
            const result = onVerify
              ? onVerify(msg)
              : { runtime: 'ts', exitCode: 0, result: { nonce: msg.nonce, claims: [] }, stdout: '', stderr: '', durationMs: 4, timedOut: false }
            stdout.write(JSON.stringify({ id: msg.id, ok: true, result }) + '\n')
          }
        }
        nl = buf.indexOf('\n')
      }
    })
    return emitter
  }
  return { spawnExec, execCalls, ndjsonMsgs }
}

function extractMountHostDir(args: string[], targetSuffix: string): string | undefined {
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--mount' && args[i + 1]?.includes(`target=${targetSuffix}`)) {
      return /^type=bind,source=([^,]+),/.exec(args[i + 1]!)?.[1]
    }
  }
  return undefined
}

describe('Per-Run Warm Container Pool (Proposal 1)', () => {
  test('reuses one hardened run-verify container across Attempt 1 & Attempt 2 with disjoint bridged sockets/tokens and deletes each attempt dir on close', async t => {
    const docker = makeStubDocker()
    const { spawnExec, execCalls, ndjsonMsgs } = makeFakeExecSpawner()
    const backend = new LinuxWorkerBackend({
      workspace: { id: 'ws-verify-reuse', directory: makeTempDir(t) },
      dockerRunner: docker.runner,
      execSpawner: spawnExec,
    })
    t.after(() => backend.closeWarmPool())

    const runId = `run-verify-${randomUUID().slice(0, 8)}`
    const nonce1 = randomBytes(16).toString('hex')
    const nonce2 = randomBytes(16).toString('hex')
    const token1 = randomBytes(24).toString('hex')
    const token2 = randomBytes(24).toString('hex')
    const rpc1 = await createFakeVerifyRpcDir(t, { runId, nonce: nonce1, token: token1, withSocket: true })
    const rpc2 = await createFakeVerifyRpcDir(t, { runId, nonce: nonce2, token: token2, withSocket: true })

    // Attempt 1 (matches exact `agent-script-proof.ts` call signature: `{ rpcMountDir }` only; runId read from context.json).
    const s1 = await backend.openSession('asgn-1-verify-1', AbortSignal.timeout(5_000), { rpcMountDir: rpc1.dir })
    assert.equal(docker.creates.length, 1, 'Attempt 1 creates exactly one per-run verify container')
    assert.equal(docker.starts.length, 1, 'Attempt 1 starts the long-lived verify container once')
    assert.equal(s1.ptcHostDir, undefined, 'verify container must never expose /kovo-ptc')

    const createArgs = docker.creates[0]!.args
    assert.ok(createArgs.includes('--network') && createArgs[createArgs.indexOf('--network') + 1] === 'none')
    assert.ok(createArgs.includes('--read-only'))
    assert.ok(createArgs.includes('--cap-drop') && createArgs[createArgs.indexOf('--cap-drop') + 1] === 'ALL')
    assert.ok(createArgs.includes('--user') && createArgs[createArgs.indexOf('--user') + 1] === '10001:10001')
    assert.equal(createArgs.some(a => a.includes(`target=${PTC_CONTAINER_DIR}`)), false)
    assert.equal(createArgs.some(a => a.includes('target=/repos')), false)

    const verifyRootHost = extractMountHostDir(createArgs, `${VERIFY_ROOT_CONTAINER_DIR}/rpc,readonly`)
    assert.ok(verifyRootHost && existsSync(verifyRootHost), 'run-verify mounts run-scoped RPC root readonly')

    // Verify Attempt 1 bridged host dir exists with non-world perms and live Unix-socket forwarding!
    const attempt1Subdirs = readdirSync(verifyRootHost!)
    assert.equal(attempt1Subdirs.length, 1, 'exactly one per-attempt subdir exists during Attempt 1')
    const attempt1HostDir = join(verifyRootHost!, attempt1Subdirs[0]!)
    assert.equal(statSync(attempt1HostDir).mode & 0o007, 0, 'attempt RPC dir must not be world-accessible')
    assert.equal(readFileSync(join(attempt1HostDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim(), token1)
    const ping1 = await unixGet(join(attempt1HostDir, VERIFY_RPC_SOCKET_NAME), token1)
    assert.equal(ping1.status, 200)
    assert.equal(ping1.body.nonce, nonce1)
    assert.equal(rpc1.hits.length, 1, 'bridged Unix socket forwards directly to Attempt 1 VerifyRpcServer')

    await s1.verifyScript!({ runtime: 'ts', nonce: nonce1, code: 'export const ok = 1' }, AbortSignal.timeout(5_000))
    const verifyMsg1 = ndjsonMsgs.find(m => m.op === 'verify' && m.nonce === nonce1)
    assert.ok(verifyMsg1)
    assert.equal(verifyMsg1.rpcSocket, `${VERIFY_ROOT_CONTAINER_DIR}/rpc/${attempt1Subdirs[0]}/${VERIFY_RPC_SOCKET_NAME}`)
    assert.equal(verifyMsg1.rpcTokenFile, `${VERIFY_ROOT_CONTAINER_DIR}/rpc/${attempt1Subdirs[0]}/${VERIFY_RPC_TOKEN_NAME}`)
    assert.equal(verifyMsg1.rpcContextFile, `${VERIFY_ROOT_CONTAINER_DIR}/rpc/${attempt1Subdirs[0]}/${VERIFY_RPC_CONTEXT_NAME}`)

    await s1.close()
    assert.equal(existsSync(attempt1HostDir), false, 'Attempt 1 RPC dir (socket/token/context) must be deleted on close')
    assert.equal(docker.removals.length, 0, 'per-run verify container stays warm after Attempt 1')

    // Attempt 2: MUST reuse the exact same container (zero new creates/starts) with a brand-new attempt subdir & socket!
    const s2 = await backend.openSession('asgn-1-verify-2', AbortSignal.timeout(5_000), { rpcMountDir: rpc2.dir })
    assert.equal(docker.creates.length, 1, 'Attempt 2 MUST reuse the per-run verify container without cold create')
    assert.equal(docker.starts.length, 1, 'Attempt 2 MUST NOT call docker start again')
    assert.equal(execCalls.length, 2, 'Attempt 2 runs via docker exec on the warm container')
    assert.equal(execCalls[1]!.containerName, execCalls[0]!.containerName)

    const attempt2Subdirs = readdirSync(verifyRootHost!)
    assert.equal(attempt2Subdirs.length, 1)
    assert.notEqual(attempt2Subdirs[0], attempt1Subdirs[0], 'Attempt 1 and Attempt 2 must have disjoint attemptIds')
    const attempt2HostDir = join(verifyRootHost!, attempt2Subdirs[0]!)
    assert.equal(readFileSync(join(attempt2HostDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim(), token2)
    const ping2 = await unixGet(join(attempt2HostDir, VERIFY_RPC_SOCKET_NAME), token2)
    assert.equal(ping2.status, 200)
    assert.equal(ping2.body.nonce, nonce2)

    await s2.verifyScript!({ runtime: 'ts', nonce: nonce2, code: 'export const ok = 2' }, AbortSignal.timeout(5_000))
    const verifyMsg2 = ndjsonMsgs.find(m => m.op === 'verify' && m.nonce === nonce2)
    assert.ok(verifyMsg2)
    assert.notEqual(verifyMsg2.rpcSocket, verifyMsg1.rpcSocket)
    assert.notEqual(verifyMsg2.rpcTokenFile, verifyMsg1.rpcTokenFile)
    assert.notEqual(verifyMsg2.rpcContextFile, verifyMsg1.rpcContextFile)

    await s2.close()
    assert.equal(existsSync(attempt2HostDir), false, 'Attempt 2 RPC dir must be deleted on close')
    assert.equal(backend.runVerifyPoolStats.verifyContainersCreated, 1)
    assert.equal(backend.runVerifyPoolStats.verifyAttemptsServed, 2)
    assert.equal(backend.runVerifyPoolStats.verifyAttemptsReused, 1)
    assert.equal(backend.containerStats().coldSessions, 0)
    assert.equal(backend.containerStats().reused, 1)
  })

  test('enforces strict cross-run isolation and cleans up per-run containers via registerRunDisposer', async t => {
    const docker = makeStubDocker()
    const { spawnExec, execCalls } = makeFakeExecSpawner()
    const backend = new LinuxWorkerBackend({
      workspace: { id: 'ws-cross-run', directory: makeTempDir(t) },
      cell: `cell-cross-${randomUUID().slice(0, 8)}`,
      dockerRunner: docker.runner,
      execSpawner: spawnExec,
    })
    t.after(() => backend.closeWarmPool())

    const runA = `run-iso-a-${randomUUID().slice(0, 8)}`
    const runB = `run-iso-b-${randomUUID().slice(0, 8)}`
    const rpcA = await createFakeVerifyRpcDir(t, { runId: runA, nonce: randomBytes(16).toString('hex'), token: randomBytes(16).toString('hex') })
    const rpcB = await createFakeVerifyRpcDir(t, { runId: runB, nonce: randomBytes(16).toString('hex'), token: randomBytes(16).toString('hex') })

    const sA = await backend.openSession('asgn-a', AbortSignal.timeout(5_000), { rpcMountDir: rpcA.dir })
    const sB = await backend.openSession('asgn-b', AbortSignal.timeout(5_000), { rpcMountDir: rpcB.dir })
    assert.equal(docker.creates.length, 2, 'distinct runs must NEVER share a verify container')
    const containerA = docker.creates[0]!.name
    const containerB = docker.creates[1]!.name
    assert.notEqual(containerA, containerB)
    assert.equal(execCalls[0]!.containerName, containerA)
    assert.equal(execCalls[1]!.containerName, containerB)

    const rootA = extractMountHostDir(docker.creates[0]!.args, `${VERIFY_ROOT_CONTAINER_DIR}/rpc,readonly`)!
    const rootB = extractMountHostDir(docker.creates[1]!.args, `${VERIFY_ROOT_CONTAINER_DIR}/rpc,readonly`)!
    assert.notEqual(rootA, rootB, 'distinct runs must have disjoint host verify root directories')
    await sA.close()
    await sB.close()

    // Disposing Run A via `runAllRunDisposers` removes ONLY Run A's warm container & host root dir!
    const drain = runAllRunDisposers(runA)
    assert.equal(drain.errors.length, 0)
    await new Promise(resolve => setTimeout(resolve, 30))
    assert.equal(docker.removals.includes(containerA), true, 'registerRunDisposer must remove Run A container')
    assert.equal(existsSync(rootA), false, 'registerRunDisposer must clean up Run A verify root host dir')
    assert.equal(docker.removals.includes(containerB), false, 'Run B container must stay intact when Run A disposes')
    assert.equal(existsSync(rootB), true, 'Run B verify root host dir must stay intact when Run A disposes')

    // Unattributed verify call (no runId, no context.json) fails closed to cold single-use container.
    const unattributedRpc = await createFakeVerifyRpcDir(t, { nonce: randomBytes(16).toString('hex'), token: randomBytes(16).toString('hex') })
    const { spawnExec: coldSpawner } = makeFakeExecSpawner()
    const bareBackend = new LinuxWorkerBackend({
      dockerRunner: docker.runner,
      sessionSpawner: name => coldSpawner(name, []),
    })
    const sCold = await bareBackend.openSession('asgn-unattr', AbortSignal.timeout(5_000), { rpcMountDir: unattributedRpc.dir })
    assert.equal(bareBackend.containerStats().coldSessions, 1)
    assert.equal(bareBackend.runVerifyPoolStats.verifyContainersCreated, 0)
    await sCold.close()

    await backend.closeWarmPool()
    assert.equal(docker.removals.includes(containerB), true, 'closeWarmPool removes remaining Run B container')
    assert.equal(existsSync(rootB), false, 'closeWarmPool removes remaining Run B verify root host dir')
  })

  test('falls back cleanly to cold session if warm verify exec spawn fails', async t => {
    const docker = makeStubDocker()
    const { spawnExec: coldSessionSpawner } = makeFakeExecSpawner()
    let execAttempts = 0
    const backend = new LinuxWorkerBackend({
      runId: 'run-exec-fallback',
      dockerRunner: docker.runner,
      sessionSpawner: name => coldSessionSpawner(name, []),
      execSpawner: () => {
        execAttempts += 1
        throw new Error('simulated docker exec failure')
      },
    })
    t.after(() => backend.closeWarmPool())

    const rpc = await createFakeVerifyRpcDir(t, { runId: 'run-exec-fallback', nonce: randomBytes(16).toString('hex'), token: randomBytes(16).toString('hex') })
    const session = await backend.openSession('asgn-fb', AbortSignal.timeout(5_000), { rpcMountDir: rpc.dir })
    assert.equal(execAttempts, 1)
    assert.equal(backend.containerStats().coldSessions, 1, 'failed exec must fall back to cold session')
    assert.equal(docker.removals.includes(docker.creates[0]!.name), true, 'broken warm verify container is evicted')
    await session.close()
  })

  test('worker/bridge.ts runVerifyScript isolates per-attempt RPC paths and wipes /tmp/kovo-attempt-<nonce> in finally (with env fallback)', async t => {
    const rpc1 = await createFakeVerifyRpcDir(t, { runId: 'run-bridge', nonce: '11111111111111112222222222222222', token: 'tok-attempt-1' })
    const rpc2 = await createFakeVerifyRpcDir(t, { runId: 'run-bridge', nonce: '33333333333333334444444444444444', token: 'tok-attempt-2' })
    const beforeDirs = new Set(readdirSync(tmpdir()).filter(n => n.startsWith('kovo-attempt-')))

    const probeCode = `
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
const tok = readFileSync(process.env.KOVO_RPC_TOKEN_FILE!, 'utf8').trim()
const ctx = JSON.parse(readFileSync(process.env.KOVO_RPC_CONTEXT_FILE!, 'utf8'))
writeFileSync(join(process.env.TMPDIR!, 'leaked-marker.txt'), tok)
writeFileSync(process.env.KOVO_PROOF_RESULT_FILE!, JSON.stringify({
  nonce: process.env.KOVO_VERIFY_NONCE,
  tok,
  ctxNonce: ctx.nonce,
  socket: process.env.KOVO_RPC_SOCKET,
  tmpDir: process.env.TMPDIR,
  homeDir: process.env.HOME,
}))
`
    const res1 = await runVerifyScript({
      runtime: 'ts',
      nonce: '11111111111111112222222222222222',
      code: probeCode,
      rpcSocket: rpc1.socketPath,
      rpcTokenFile: join(rpc1.dir, VERIFY_RPC_TOKEN_NAME),
      rpcContextFile: join(rpc1.dir, VERIFY_RPC_CONTEXT_NAME),
    })
    assert.equal(res1.exitCode, 0, res1.stderr)
    const r1 = res1.result as Record<string, string>
    assert.equal(r1.tok, 'tok-attempt-1')
    assert.equal(r1.socket, rpc1.socketPath)
    assert.equal(existsSync(r1.tmpDir!), false, 'Attempt 1 private TMPDIR must be wiped immediately in finally')
    assert.equal(existsSync(dirname(r1.tmpDir!)), false, 'Attempt 1 /tmp/kovo-attempt-* root must be wiped in finally')

    const res2 = await runVerifyScript({
      runtime: 'ts',
      nonce: '33333333333333334444444444444444',
      code: probeCode,
      rpcSocket: rpc2.socketPath,
      rpcTokenFile: join(rpc2.dir, VERIFY_RPC_TOKEN_NAME),
      rpcContextFile: join(rpc2.dir, VERIFY_RPC_CONTEXT_NAME),
    })
    assert.equal(res2.exitCode, 0, res2.stderr)
    const r2 = res2.result as Record<string, string>
    assert.equal(r2.tok, 'tok-attempt-2')
    assert.notEqual(r2.tmpDir, r1.tmpDir, 'Attempt 1 and Attempt 2 must have disjoint TMPDIR paths')
    assert.equal(existsSync(r2.tmpDir!), false, 'Attempt 2 private TMPDIR must be wiped in finally')

    // Backward compatibility: omitting rpcSocket/rpcTokenFile/rpcContextFile falls back to process.env.KOVO_RPC_*.
    const prevSock = process.env.KOVO_RPC_SOCKET
    const prevTok = process.env.KOVO_RPC_TOKEN_FILE
    const prevCtx = process.env.KOVO_RPC_CONTEXT_FILE
    process.env.KOVO_RPC_SOCKET = rpc1.socketPath
    process.env.KOVO_RPC_TOKEN_FILE = join(rpc1.dir, VERIFY_RPC_TOKEN_NAME)
    process.env.KOVO_RPC_CONTEXT_FILE = join(rpc1.dir, VERIFY_RPC_CONTEXT_NAME)
    t.after(() => {
      if (prevSock === undefined) delete process.env.KOVO_RPC_SOCKET; else process.env.KOVO_RPC_SOCKET = prevSock
      if (prevTok === undefined) delete process.env.KOVO_RPC_TOKEN_FILE; else process.env.KOVO_RPC_TOKEN_FILE = prevTok
      if (prevCtx === undefined) delete process.env.KOVO_RPC_CONTEXT_FILE; else process.env.KOVO_RPC_CONTEXT_FILE = prevCtx
    })
    const resEnv = await runVerifyScript({
      runtime: 'ts',
      nonce: '55555555555555556666666666666666',
      code: probeCode,
    })
    assert.equal(resEnv.exitCode, 0, resEnv.stderr)
    assert.equal((resEnv.result as Record<string, string>).tok, 'tok-attempt-1')

    // Path-traversal override must be rejected.
    await assert.rejects(
      () => runVerifyScript({ runtime: 'ts', nonce: '77777777777777778888888888888888', code: 'export const x = 1', rpcSocket: '/kovo-verify-root/../etc/passwd' }),
      /Invalid verification RPC path/,
    )

    const leaked = readdirSync(tmpdir()).filter(n => n.startsWith('kovo-attempt-') && !beforeDirs.has(n))
    assert.deepEqual(leaked, [], `no kovo-attempt-* temp dirs may leak: ${leaked.join(', ')}`)
  })
})
