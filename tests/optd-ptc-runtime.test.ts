/**
 * Code Mode / PTC (Programmatic Tool Calling) runtime & host RPC bridge tests.
 *
 * Covers:
 *  1. `PtcRpcServer` constant-time token auth (401 on missing/wrong), `allowedOps` enforcement,
 *     256 KiB body cap, per-exec `maxCallsPerExec` budget & `resetCallBudget()`, secret-redacted
 *     error responses, and `close()` unlinking socket+token while preserving `hostDir` for warm reuse.
 *  2. `worker/ptc_client.ts` live Unix-socket round-trip against `PtcRpcServer` for `http` (both
 *     positional and object call forms), `batch`, `race`, `browser`, `oob`, `probe`, `analyze`,
 *     `searchRun`, `repo`, `recordFact`, `queryCves`, and error propagation.
 *  3. `runPtcScript` from `worker/bridge.ts` executing async TS snippets against a live
 *     `PtcRpcServer`, returning structured JSON separately from `console.log` stdout, masking
 *     secrets, capping result JSON at 32 KiB, and removing its temp dir in `finally`.
 *  4. `LinuxWorkerBackend` & `WarmWorkerPool` `/kovo-ptc` readonly mount lifecycle (cold session,
 *     Layer-3 `rpcMountDir` exclusion, warm-pool reuse preservation, and `session.ptcExec` NDJSON).
 */
import assert from 'node:assert/strict'
import { type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { describe, test } from 'node:test'
import {
  DEFAULT_PTC_ALLOWED_OPS,
  PTC_CONTAINER_DIR,
  PTC_RPC_HEADER,
  PtcRpcServer,
  readPtcClientSource,
} from '../src/server/ptc-rpc.ts'
import { LinuxWorkerBackend, type DockerRunner } from '../src/server/worker-backend.ts'
import { runPtcScript } from '../worker/bridge.ts'
import { createKovoClient } from '../worker/ptc_client.ts'

function makeTempDir(t: { after(fn: () => void | Promise<void>): void }, prefix = 'kovo-ptc-test-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function rawUnixRpc(
  socketPath: string,
  opts: { method?: string; path?: string; token?: string; body?: string },
): Promise<{ status: number; body: Record<string, unknown> }> {
  const payload = opts.body ?? ''
  return new Promise((resolve, reject) => {
    const headers: Record<string, string | number> = {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
    }
    if (opts.token !== undefined) headers[PTC_RPC_HEADER] = opts.token
    const req = httpRequest(
      { socketPath, path: opts.path ?? '/rpc', method: opts.method ?? 'POST', headers },
      res => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          resolve({ status: res.statusCode ?? 0, body: JSON.parse(text) as Record<string, unknown> })
        })
      },
    )
    req.on('error', reject)
    req.end(payload)
  })
}

function extractMounts(args: string[]): string[] {
  const mounts: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--mount' && args[i + 1]) mounts.push(args[i + 1]!)
  }
  return mounts
}

function makeFakeSessionSpawner(onRequest: (msg: Record<string, unknown>) => Record<string, unknown>) {
  const children: Array<{ proc: ChildProcess; emitClose: (code: number) => void }> = []
  const spawner = (_name: string): ChildProcess => {
    const emitter = new EventEmitter() as ChildProcess
    const stdin = new PassThrough()
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    ;(emitter as unknown as { stdin: PassThrough; stdout: PassThrough; stderr: PassThrough }).stdin = stdin
    ;(emitter as unknown as { stdout: PassThrough }).stdout = stdout
    ;(emitter as unknown as { stderr: PassThrough }).stderr = stderr
    let buf = ''
    let closed = false
    const emitClose = (code: number) => {
      if (closed) return
      closed = true
      emitter.emit('close', code, null)
    }
    ;(emitter as unknown as { kill: () => boolean }).kill = () => {
      emitClose(0)
      return true
    }
    stdin.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8')
      let nl = buf.indexOf('\n')
      while (nl !== -1) {
        const line = buf.slice(0, nl).trim()
        buf = buf.slice(nl + 1)
        if (line) {
          const msg = JSON.parse(line) as Record<string, unknown>
          if (msg.op === 'shutdown') {
            stdout.write(JSON.stringify({ id: msg.id, ok: true }) + '\n')
            emitClose(0)
          } else {
            const reply = onRequest(msg)
            stdout.write(JSON.stringify({ id: msg.id, ok: true, result: reply }) + '\n')
          }
        }
        nl = buf.indexOf('\n')
      }
    })
    children.push({ proc: emitter, emitClose })
    return emitter
  }
  return { spawner, children }
}

describe('PtcRpcServer', () => {
  test('enforces token auth (401), op allowlist (403), body cap (413), per-exec call budget (429 + reset), and preserves hostDir on close', async t => {
    const hostDir = makeTempDir(t)
    const calls: Array<{ op: string; args: Record<string, unknown> }> = []
    const server = new PtcRpcServer({
      hostDir,
      maxCallsPerExec: 3,
      dispatch: async (op, args) => {
        calls.push({ op, args })
        if (args.failWithSecret) {
          const tok = readFileSync(join(hostDir, 'token'), 'utf8').trim()
          throw new Error(`boom Authorization: Bearer sk-live-secret-abcdef1234567890 token=${tok}`)
        }
        return { echoedOp: op, echoedArgs: args }
      },
    })
    await server.start()
    t.after(() => server.close())

    // Token file (32 random bytes = 64 hex chars) and Unix socket exist with expected non-world perms.
    const token = readFileSync(server.tokenPath, 'utf8').trim()
    assert.match(token, /^[a-f0-9]{64}$/)
    const tokMode = statSync(server.tokenPath).mode & 0o777
    const sockMode = statSync(server.socketPath).mode & 0o777
    assert.equal(tokMode & 0o007, 0, 'token file must not be world-accessible')
    assert.equal(sockMode & 0o007, 0, 'socket must not be world-accessible')

    // Missing or wrong token -> 401 and dispatch never runs.
    const noTok = await rawUnixRpc(server.socketPath, { body: JSON.stringify({ op: 'http', args: {} }) })
    assert.equal(noTok.status, 401)
    const badTok = await rawUnixRpc(server.socketPath, {
      token: '0'.repeat(64),
      body: JSON.stringify({ op: 'http', args: {} }),
    })
    assert.equal(badTok.status, 401)

    // Wrong HTTP method / path -> 404.
    const wrongPath = await rawUnixRpc(server.socketPath, { path: '/other', token, body: '{}' })
    assert.equal(wrongPath.status, 404)

    // Disallowed op -> 403 and does not consume call budget.
    const disallowed = await rawUnixRpc(server.socketPath, {
      token,
      body: JSON.stringify({ op: 'shell_exec', args: {} }),
    })
    assert.equal(disallowed.status, 403)
    assert.equal(server.callsUsed, 0)

    // Oversized body (> 256 KiB) -> 413.
    const huge = await rawUnixRpc(server.socketPath, {
      token,
      body: JSON.stringify({ op: 'http', args: { pad: 'x'.repeat(260 * 1024) } }),
    })
    assert.equal(huge.status, 413)
    assert.equal(calls.length, 0)

    // Budget enforcement (3 calls allowed; 4th returns 429).
    for (let i = 0; i < 3; i += 1) {
      const ok = await rawUnixRpc(server.socketPath, {
        token,
        body: JSON.stringify({ op: 'http', args: { idx: i } }),
      })
      assert.equal(ok.status, 200)
      assert.equal(ok.body.ok, true)
    }
    const overBudget = await rawUnixRpc(server.socketPath, {
      token,
      body: JSON.stringify({ op: 'http', args: { idx: 3 } }),
    })
    assert.equal(overBudget.status, 429)
    assert.equal(overBudget.body.ok, false)
    assert.equal(calls.length, 3)

    // resetCallBudget() restores capacity and secret-scrubbing redacts tokens/bearer secrets.
    server.resetCallBudget()
    assert.equal(server.callsUsed, 0)
    const errRes = await rawUnixRpc(server.socketPath, {
      token,
      body: JSON.stringify({ op: 'probe', args: { failWithSecret: true } }),
    })
    assert.equal(errRes.status, 200)
    assert.equal(errRes.body.ok, false)
    assert.equal(String(errRes.body.error).includes(token), false, 'RPC token must never leak in error message')
    assert.equal(String(errRes.body.error).includes('sk-live-secret-abcdef1234567890'), false, 'bearer secret must be redacted')

    // close() removes ptc.sock + token while leaving hostDir intact for warm container reuse.
    await server.close()
    assert.equal(existsSync(hostDir), true, 'hostDir must remain intact after close()')
    assert.equal(existsSync(server.socketPath), false, 'ptc.sock must be unlinked on close()')
    assert.equal(existsSync(server.tokenPath), false, 'token must be unlinked on close()')

    // A second server can cleanly start on the same preserved hostDir.
    const reused = new PtcRpcServer({
      hostDir,
      dispatch: async op => ({ reused: true, op }),
    })
    await reused.start()
    t.after(() => reused.close())
    const reusedToken = readFileSync(reused.tokenPath, 'utf8').trim()
    assert.notEqual(reusedToken, token, 'warm reuse must mint a fresh per-session token')
    const ping = await rawUnixRpc(reused.socketPath, {
      token: reusedToken,
      body: JSON.stringify({ op: 'searchRun', args: { query: 'invoices' } }),
    })
    assert.equal(ping.status, 200)
    assert.deepEqual(ping.body, { ok: true, result: { reused: true, op: 'searchRun' } })
  })
})

describe('worker/ptc_client.ts end-to-end against PtcRpcServer', () => {
  test('routes http (both overloads), batch, race, searchRun, all allowed ops, and propagates errors', async t => {
    const hostDir = makeTempDir(t)
    const received: Array<{ op: string; args: Record<string, unknown> }> = []
    const server = new PtcRpcServer({
      hostDir,
      maxCallsPerExec: 40,
      dispatch: async (op, args) => {
        received.push({ op, args })
        if (args.triggerError) throw new Error('upstream scope denied')
        return { op, args, status: 200 }
      },
    })
    await server.start()
    t.after(() => server.close())

    const kovo = createKovoClient({ socketPath: server.socketPath, tokenFile: server.tokenPath })

    // Positional http(method, pathAndQuery, opts)
    const r1 = await kovo.http('GET', '/api/test', { as: 'member_b' }) as { op: string; args: Record<string, unknown> }
    assert.equal(r1.op, 'http')
    assert.deepEqual(r1.args, { method: 'GET', pathAndQuery: '/api/test', as: 'member_b' })

    // Object http({ method, pathAndQuery, ... })
    const r2 = await kovo.http({ method: 'post', pathAndQuery: '/api/orders', body: { qty: 1 }, as: 'admin' }) as {
      op: string
      args: Record<string, unknown>
    }
    assert.equal(r2.op, 'http')
    assert.deepEqual(r2.args, { method: 'POST', pathAndQuery: '/api/orders', body: { qty: 1 }, as: 'admin' })

    // batch & race -> http with mode: 'batch' / 'race'
    const rBatch = await kovo.batch([{ method: 'GET', pathAndQuery: '/a' }, { method: 'GET', pathAndQuery: '/b' }]) as {
      op: string
      args: Record<string, unknown>
    }
    assert.equal(rBatch.op, 'http')
    assert.equal(rBatch.args.mode, 'batch')
    assert.equal((rBatch.args.requests as unknown[]).length, 2)

    const rRace = await kovo.race([{ method: 'POST', pathAndQuery: '/redeem' }, { method: 'POST', pathAndQuery: '/redeem' }]) as {
      op: string
      args: Record<string, unknown>
    }
    assert.equal(rRace.op, 'http')
    assert.equal(rRace.args.mode, 'race')
    assert.equal((rRace.args.requests as unknown[]).length, 2)

    // Remaining typed tool methods
    await kovo.browser({ url: '/dashboard' })
    await kovo.oob({ action: 'mint' })
    await kovo.probe({ family: 'authz' })
    await kovo.analyze({ tool: 'jwt-decode' })
    await kovo.searchRun({ query: 'tenant' })
    await kovo.repo({ action: 'list' })
    await kovo.recordFact({ key: 'role', value: 'member' })
    await kovo.queryCves({ package: 'express' })

    const seenOps = new Set(received.map(r => r.op))
    for (const op of DEFAULT_PTC_ALLOWED_OPS) {
      if (op === 'race') continue // kovo.race routes through http with mode: 'race'
      assert.equal(seenOps.has(op), true, `expected op ${op} to be dispatched`)
    }

    // Error propagation
    await assert.rejects(() => kovo.probe({ triggerError: true }), /upstream scope denied/)
  })
})

describe('worker/bridge.ts runPtcScript', () => {
  test('executes async TS snippet, separates JSON result from stdout, masks secrets, caps result size, and cleans temp dir', async t => {
    const hostDir = makeTempDir(t)
    const evidenceDir = makeTempDir(t, 'kovo-ptc-ev-')
    const server = new PtcRpcServer({
      hostDir,
      dispatch: async (op, args) => ({ op, status: 200, path: args.pathAndQuery, actor: args.as }),
    })
    await server.start()
    t.after(() => server.close())

    const clientCode = readPtcClientSource()
    const beforeTmp = new Set(readdirSync(tmpdir()).filter(n => n.startsWith('kovo-ptc-')))

    const res = await runPtcScript(
      {
        code: `
          console.log('probing with Authorization: Bearer supersecret_token_value_123456')
          const first = await kovo.http('GET', '/api/invoices/42', { as: 'member_b' })
          const burst = await kovo.race([{ method: 'POST', pathAndQuery: '/api/redeem' }])
          return { first, burst, count: 2 }
        `,
        clientCode,
        timeoutMs: 15_000,
      },
      evidenceDir,
      { KOVO_PTC_SOCKET: server.socketPath, KOVO_PTC_TOKEN_FILE: server.tokenPath },
    )

    assert.equal(res.ok, true, `expected ok=true, got error=${res.error}, stderr=${res.stderr}`)
    assert.equal(res.exitCode, 0)
    assert.deepEqual(res.result, {
      first: { op: 'http', status: 200, path: '/api/invoices/42', actor: 'member_b' },
      burst: { op: 'http', status: 200 },
      count: 2,
    })
    assert.equal(res.stdout.includes('probing with'), true)
    assert.equal(res.stdout.includes('supersecret_token_value_123456'), false, 'stdout secrets must be masked')
    assert.equal(res.stdout.includes('[masked:'), true)

    // Result cap (> 32 KiB JSON) fails closed.
    const oversized = await runPtcScript(
      { code: `return { big: 'a'.repeat(40 * 1024) }`, clientCode, timeoutMs: 15_000 },
      evidenceDir,
      { KOVO_PTC_SOCKET: server.socketPath, KOVO_PTC_TOKEN_FILE: server.tokenPath },
    )
    assert.equal(oversized.ok, false)
    assert.equal(oversized.result, null)
    assert.match(oversized.error ?? '', /32768-byte limit/i)

    // No leaked kovo-ptc-* temp directories remain after executions.
    const afterTmp = readdirSync(tmpdir()).filter(n => n.startsWith('kovo-ptc-') && !beforeTmp.has(n))
    assert.deepEqual(afterTmp, [], `leaked temp dirs: ${afterTmp.join(', ')}`)
  })
})

describe('LinuxWorkerBackend /kovo-ptc mount & session.ptcExec lifecycle', () => {
  test('cold session mounts /kovo-ptc readonly, executes ptcExec over NDJSON, and cleans up; Layer-3 rpcMountDir omits /kovo-ptc', async t => {
    const createCalls: string[][] = []
    const ndjsonRequests: Record<string, unknown>[] = []
    const dockerRunner: DockerRunner = async args => {
      if (args[0] === 'container' && args[1] === 'create') {
        createCalls.push(args)
        return 'created'
      }
      return ''
    }
    const { spawner } = makeFakeSessionSpawner(msg => {
      ndjsonRequests.push(msg)
      return {
        ok: true,
        result: { pong: true },
        stdout: 'hi\n',
        stderr: '',
        exitCode: 0,
        durationMs: 12,
      }
    })
    const backend = new LinuxWorkerBackend({ dockerRunner, sessionSpawner: spawner })
    const session = await backend.openSession(randomUUID(), AbortSignal.timeout(5_000))
    assert.ok(session.ptcHostDir, 'cold exploiter session must expose ptcHostDir')
    assert.equal(existsSync(session.ptcHostDir), true)
    const ptcHostDir = session.ptcHostDir
    const mounts = extractMounts(createCalls[0]!)
    assert.equal(mounts.some(m => m.includes(`target=${PTC_CONTAINER_DIR},readonly`)), true)

    assert.ok(session.ptcExec, 'session must expose ptcExec')
    const execRes = await session.ptcExec({ code: 'return { pong: true }', timeoutMs: 10_000 }, AbortSignal.timeout(5_000))
    assert.equal(execRes.ok, true)
    assert.deepEqual(execRes.result, { pong: true })
    assert.equal(ndjsonRequests[0]?.op, 'ptc')
    assert.equal(typeof ndjsonRequests[0]?.clientCode, 'string')
    assert.equal((ndjsonRequests[0]?.clientCode as string).includes('createKovoClient'), true)

    await session.close()
    assert.equal(existsSync(ptcHostDir), false, 'cold session ptcHostDir must be removed when container closes')

    // Layer-3 verify container (rpcMountDir set) must NOT mount /kovo-ptc.
    const rpcDir = makeTempDir(t, 'kovo-rpc-only-')
    const verifySession = await backend.openSession(randomUUID(), AbortSignal.timeout(5_000), { rpcMountDir: rpcDir })
    assert.equal(verifySession.ptcHostDir, undefined)
    const verifyMounts = extractMounts(createCalls[1]!)
    assert.equal(verifyMounts.some(m => m.includes(`target=${PTC_CONTAINER_DIR}`)), false)
    await verifySession.close()
  })

  test('warm-pool container preserves /kovo-ptc hostDir across reuse and removes it on pool close', async () => {
    const createCalls: string[][] = []
    const dockerRunner: DockerRunner = async args => {
      if (args[0] === 'container' && args[1] === 'create') {
        createCalls.push(args)
        return 'created'
      }
      if (args[0] === 'container' && args[1] === 'inspect') {
        return args.includes('{{.State.Status}}') ? 'exited' : 'exited\t<no value>'
      }
      return ''
    }
    const { spawner } = makeFakeSessionSpawner(() => ({
      ok: true,
      result: null,
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 5,
    }))
    const backend = new LinuxWorkerBackend({
      runId: 'run-ptc-warm',
      cell: `ptc-warm-${randomUUID().slice(0, 8)}`,
      dockerRunner,
      sessionSpawner: spawner,
    })
    backend.setWarmPoolPolicy('run-ptc-warm:v1')

    const s1 = await backend.openSession(randomUUID(), AbortSignal.timeout(5_000), { warmPoolPolicy: 'run-ptc-warm:v1' })
    assert.ok(s1.ptcHostDir)
    const warmDir = s1.ptcHostDir
    assert.equal(existsSync(warmDir), true)
    assert.equal(extractMounts(createCalls[0]!).some(m => m.includes(`target=${PTC_CONTAINER_DIR},readonly`)), true)
    await s1.close()

    // Warm container returned to idle pool: ptcHostDir MUST remain intact for reuse!
    assert.equal(existsSync(warmDir), true, 'warm container ptcHostDir must survive release into pool')

    const s2 = await backend.openSession(randomUUID(), AbortSignal.timeout(5_000), { warmPoolPolicy: 'run-ptc-warm:v1' })
    assert.equal(s2.ptcHostDir, warmDir, 'reused warm container must keep the same ptcHostDir')
    assert.equal(createCalls.length, 1, 'second session must reuse the warm container without cold create')
    await s2.close()

    await backend.closeWarmPool()
    assert.equal(existsSync(warmDir), false, 'closing the warm pool must clean up container ptcHostDir')
  })
})
