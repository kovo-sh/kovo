// Layer-3 verification MVP (v6 Phase 3): Unix-socket Layer-1 RPC, guardian_verify SDK,
// signed transcript oracle, independent fresh-session re-run, and chunked worker IPC.
//
// Defensive framing: these are differential probes against local fixtures and the isolated
// worker sandbox. The BOLA fixture is an intentional, authorized local benchmark.
import assert from 'node:assert/strict'
import { execFile as execFileCb } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createServer as createHttpServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { ServerHttp2Stream } from 'node:http2'
import { request as httpRequest } from 'node:http'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  createLocalAttemptFactory,
  evaluateClaims,
  mannWhitneyU,
  verifyScript,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import type { VerifyBrowserDriver, VerifyCanaryBroker, VerifyClaim } from '../src/server/verify-rpc.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'

const execFile = promisify(execFileCb)
const SDK_DIR = join(dirname(fileURLToPath(import.meta.url)), '../worker/guardian_verify')

// The broker only permits loopback when the operator explicitly opted into a local lab.
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ALICE_SECRET = 'alice-secret-8f21c4'
const BOB_SECRET = 'bob-secret-3c77d1'

function listen(server: ReturnType<typeof createHttpServer> | ReturnType<typeof createH2Server>): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') reject(new Error('fixture server did not bind a TCP port'))
      else resolve(address.port)
    })
  })
}

function closeServer(server: ReturnType<typeof createHttpServer> | ReturnType<typeof createH2Server>): Promise<void> {
  return new Promise(resolve => server.close(() => resolve()))
}

function json(res: ServerResponse, status: number, value: unknown) {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

function identityOf(req: IncomingMessage): 'alice' | 'bob' | 'anonymous' {
  const raw = String(req.headers['x-user'] ?? '')
  if (raw === ALICE_SECRET) return 'alice'
  if (raw === BOB_SECRET) return 'bob'
  return 'anonymous'
}

let bobSeesItem7 = true
let requestCount = 0

const fixture = createHttpServer(async (req, res) => {
  requestCount += 1
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const who = identityOf(req)
  if (url.pathname === '/items/7') {
    if (who === 'anonymous') return json(res, 401, { error: 'unauthenticated' })
    if (who === 'bob' && !bobSeesItem7) return json(res, 403, { error: 'forbidden' })
    return json(res, 200, { owner: 'alice', item: 7, private: 'alice-private-item-7' })
  }
  if (url.pathname === '/items/8') {
    if (who === 'bob') return json(res, 403, { error: 'forbidden' })
    if (who === 'anonymous') return json(res, 401, { error: 'unauthenticated' })
    return json(res, 200, { owner: 'alice', item: 8, private: 'alice-private-item-8' })
  }
  if (url.pathname === '/echo') {
    return json(res, 200, { headers: req.headers })
  }
  if (url.pathname === '/panel') {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html><body><div id="panel" class="visible">panel-body</div></body></html>')
    return
  }
  if (url.pathname === '/slow') {
    const base = Math.max(0, Number(url.searchParams.get('ms') ?? '0'))
    const jitter = Math.random() * 6
    await new Promise(resolve => setTimeout(resolve, base + jitter))
    return json(res, 200, { ms: base })
  }
  if (url.pathname === '/health') return json(res, 200, { ok: true, requests: requestCount })
  return json(res, 404, { error: 'not found' })
})

const h2Fixture = createH2Server()
h2Fixture.on('stream', (stream: ServerHttp2Stream, headers) => {
  if (headers[':path'] === '/h2-data') {
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ protocol: 'h2', ok: true }))
    return
  }
  stream.respond({ ':status': 404, 'content-type': 'application/json' })
  stream.end('{"error":"not found"}')
})

const httpPort = await listen(fixture)
const h2Port = await listen(h2Fixture)
const origin = `http://127.0.0.1:${httpPort}`
const h2Origin = `http://127.0.0.1:${h2Port}`

test.after(async () => {
  await closeServer(fixture)
  await closeServer(h2Fixture)
})

function persona(handle: 'alice' | 'bob', secret: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel: handle,
    originAllowlist: [origin, h2Origin],
    authKind: 'header',
    headerName: 'X-User',
    secret,
    canaryMarkers: [],
  }
}

function makeGrant(): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    allowedPorts: [httpPort, h2Port],
    maxRpsPerOrigin: 100,
    personas: new Map<string, ResolvedPersona>([
      ['alice', persona('alice', ALICE_SECRET)],
      ['bob', persona('bob', BOB_SECRET)],
    ]),
    canRead: candidate => candidate === origin || candidate === h2Origin,
    audit: () => {},
  }
}

const browserDriver: VerifyBrowserDriver = {
  async open(request) {
    const who = request.headers['X-User'] ?? request.headers['x-user']
    const isAlice = who === ALICE_SECRET
    return {
      status: isAlice ? 200 : 403,
      url: request.url,
      html: isAlice
        ? '<html><body><div id="admin-panel" class="visible">alice-admin-panel</div></body></html>'
        : '<html><body><div id="denied" class="hidden">denied</div></body></html>',
      executedSentinels: isAlice ? ['alert:admin-panel'] : [],
    }
  },
}

const mintedTokens = new Set<string>()
const canary: VerifyCanaryBroker = {
  mintCanary(runId, label) {
    const token = `guardian-canary-${randomUUID().replace(/-/g, '').slice(0, 24)}`
    mintedTokens.add(token)
    return { token, httpUrl: `http://canary.local/c/${token}`, url: `http://canary.local/c/${token}`, dnsHost: `${token}.canary.local`, label }
  },
  checkCanary(token) {
    const hit = triggeredTokens.has(token)
    return {
      found: mintedTokens.has(token),
      hit,
      triggered: hit,
      hits: hit ? [{ protocol: 'http', token, remoteIp: '127.0.0.1', timestamp: Date.now() }] : [],
    }
  },
}
const triggeredTokens = new Set<string>()

interface RpcResponse {
  ok: boolean
  result?: unknown
  error?: string
}

function rpc(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}, nonce = server.nonce): Promise<RpcResponse> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-guardian-rpc-token': server.token,
        'x-guardian-verify-nonce': nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (chunk: Buffer) => chunks.push(chunk))
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcResponse) } catch (error) { reject(error) }
      })
    })
    req.once('error', reject)
    req.end(payload)
  })
}

async function startRpc(nonce = randomUUID().replace(/-/g, '')): Promise<VerifyRpcServer> {
  const server = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(),
    runId: `run-${nonce.slice(0, 8)}`,
    assignmentId: 'assignment-verify',
    nonce,
    targetOrigins: [origin, h2Origin],
    browser: browserDriver,
    canary,
  })
  await server.start()
  return server
}

test('RPC round-trip over a real Unix socket records a signed exchange', async () => {
  const server = await startRpc()
  try {
    const res = await rpc(server, 'http', { path: '/items/7', method: 'GET', persona: 'alice' })
    assert.equal(res.ok, true, res.error ?? "RPC call failed")
    const exchange = res.result as { exchangeId: string; status: number; body: string }
    assert.equal(exchange.status, 200)
    assert.match(exchange.exchangeId, /^gx-[a-f0-9-]{36}$/)
    assert.match(exchange.body, /alice-private-item-7/)
    assert.equal(server.transcript.size, 1)
    assert.equal(server.transcript.verifySignatures(), true)
    const listed = await rpc(server, 'transcript', { action: 'list' })
    assert.equal(listed.ok, true)
    const payload = listed.result as { exchanges: Array<{ exchangeId: string }>; digest: string; signaturesValid: boolean }
    assert.equal(payload.exchanges.length, 1)
    assert.equal(payload.exchanges[0].exchangeId, exchange.exchangeId)
    assert.equal(payload.digest, server.transcript.digest())
    assert.equal(payload.signaturesValid, true)

    // Tampering with a recorded exchange breaks the HMAC chain.
    const internal = server.transcript as unknown as { records: Map<string, { response?: { status: number } }> }
    const record = internal.records.get(exchange.exchangeId)
    assert.ok(record?.response)
    record!.response!.status = 500
    assert.equal(server.transcript.verifySignatures(), false)
  } finally {
    await server.close()
  }
})

test('credential injection: scripts never see persona secrets and cannot supply their own', async () => {
  const server = await startRpc()
  try {
    const injected = await rpc(server, 'http', { path: '/echo', persona: 'alice' })
    assert.equal(injected.ok, true, injected.error ?? "RPC call failed")
    const exchange = injected.result as { exchangeId: string; body: string }
    assert.equal(exchange.body.includes(ALICE_SECRET), false, 'persona secret leaked into the response body')
    assert.match(exchange.body, /\[persona:alice:/)
    assert.equal((server.transcript.body(exchange.exchangeId) ?? '').includes(ALICE_SECRET), false)
    assert.equal(JSON.stringify(server.transcript.list()).includes(ALICE_SECRET), false)

    const direct = await rpc(server, 'http', { path: '/echo', headers: { authorization: `Bearer ${ALICE_SECRET}` } })
    assert.equal(direct.ok, false)
    assert.match(direct.error ?? '', /cannot be set directly/i)
    assert.equal((direct.error ?? '').includes(ALICE_SECRET), false)

    // Persona injection crosses the browser driver too; the script only receives page content.
    const browser = await rpc(server, 'browser', { path: '/panel', persona: 'alice' })
    assert.equal(browser.ok, true, browser.error ?? "RPC call failed")
    const page = browser.result as { exchangeId: string; html: string; executedSentinels: string[] }
    assert.match(page.html, /alice-admin-panel/)
    assert.deepEqual(page.executedSentinels, ['alert:admin-panel'])
    assert.equal(JSON.stringify(page).includes(ALICE_SECRET), false)

    const claims: VerifyClaim[] = [
      { kind: 'status', exchangeId: page.exchangeId, expected: 200 },
      { kind: 'css', exchangeId: page.exchangeId, selector: 'div#admin-panel.visible', textContains: 'alice-admin-panel' },
      { kind: 'dom_sentinel', exchangeId: page.exchangeId, sentinel: 'alert:admin-panel', mode: 'executed' },
    ]
    const oracle = evaluateClaims(server.transcript, claims)
    assert.equal(oracle.passed, true, oracle.failures.join('; '))

    const anonymous = await rpc(server, 'browser', { path: '/panel' })
    const anonymousPage = anonymous.result as { exchangeId: string }
    const deniedClaim: VerifyClaim[] = [{ kind: 'css', exchangeId: anonymousPage.exchangeId, selector: '#admin-panel' }]
    assert.equal(evaluateClaims(server.transcript, deniedClaim).passed, false)
  } finally {
    await server.close()
  }
})

test('scope denial: RPC cannot escape the grant, including HTTP/2', async () => {
  const server = await startRpc()
  try {
    for (const target of ['https://evil.example/', 'http://169.254.169.254/latest/meta-data/']) {
      const res = await rpc(server, 'http', { origin: target, path: '/' })
      assert.equal(res.ok, false, `${target} unexpectedly allowed`)
      assert.match(res.error ?? '', /scope|resolve|metadata|link-local|outside/i)
    }
    const h2 = await rpc(server, 'http2', { origin: 'https://evil.example', path: '/' })
    assert.equal(h2.ok, false)
    assert.match(h2.error ?? '', /scope|outside/i)
    const escaped = await rpc(server, 'http', { path: '//evil.example/' })
    assert.equal(escaped.ok, false)
  } finally {
    await server.close()
  }
})

test('HTTP/2 op performs a real h2c exchange through the grant', async () => {
  const server = await startRpc()
  try {
    const res = await rpc(server, 'http2', { origin: h2Origin, path: '/h2-data', method: 'GET' })
    assert.equal(res.ok, true, res.error ?? "RPC call failed")
    const exchange = res.result as { exchangeId: string; status: number; protocol: string; body: string }
    assert.equal(exchange.status, 200)
    assert.equal(exchange.protocol, 'h2')
    assert.match(exchange.body, /"protocol":"h2"/)
    const oracle = evaluateClaims(server.transcript, [
      { kind: 'status', exchangeId: exchange.exchangeId, expected: 200 },
      { kind: 'jsonpath', exchangeId: exchange.exchangeId, path: 'protocol', equals: 'h2' },
    ])
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
  } finally {
    await server.close()
  }
})

test('OOB canary mint/check is transcript-backed and re-checked by the oracle', async () => {
  const server = await startRpc()
  try {
    const mint = await rpc(server, 'oob', { action: 'mint', label: 'ssrf' })
    assert.equal(mint.ok, true, mint.error ?? "RPC call failed")
    const handle = mint.result as { exchangeId: string; token: string }
    const claim: VerifyClaim = { kind: 'oob', exchangeId: handle.exchangeId, expectHit: true }
    assert.equal(evaluateClaims(server.transcript, [claim], { canary }).passed, false, 'untiggered canary must not verify')
    triggeredTokens.add(handle.token)
    const check = await rpc(server, 'oob', { action: 'check', token: handle.token, exchangeId: handle.exchangeId })
    assert.equal(check.ok, true)
    assert.equal((check.result as { hit: boolean }).hit, true)
    const oracle = evaluateClaims(server.transcript, [claim], { canary })
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
  } finally {
    await server.close()
  }
})

test('timing helper separates jittered populations (Mann-Whitney U + median/MAD)', async () => {
  const server = await startRpc()
  try {
    const controlIds: string[] = []
    const variantIds: string[] = []
    for (let i = 0; i < 6; i += 1) {
      const order = i % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
      for (const which of order) {
        const res = await rpc(server, 'http', { path: which === 'control' ? '/slow?ms=2' : '/slow?ms=45' })
        assert.equal(res.ok, true, res.error ?? "RPC call failed")
        const exchange = res.result as { exchangeId: string }
        if (which === 'control') controlIds.push(exchange.exchangeId)
        else variantIds.push(exchange.exchangeId)
      }
    }
    const oracle = evaluateClaims(server.transcript, [{ kind: 'timing', controlIds, variantIds, minPairs: 5 }])
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
    const detail = oracle.checks[0].observed as { pValue: number; separation: number; pairs: number }
    assert.ok(detail.pValue <= 0.05)
    assert.ok(detail.separation >= 3)

    // Overlapping populations must not confirm.
    const overlap = mannWhitneyU([20, 22, 24, 26, 28, 30], [21, 23, 25, 27, 29, 31])
    assert.ok(overlap.pValue > 0.05 || overlap.separation < 3)
  } finally {
    await server.close()
  }
})

test('TS SDK confirms a local BOLA fixture only after two fresh-session runs', async () => {
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce) {
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-bola-${nonce.slice(0, 8)}`,
        assignmentId: 'assignment-bola',
        targetOrigins: [origin],
        browser: browserDriver,
        canary,
      }
    },
  })
  const candidate = {
    name: 'bola.ts',
    runtime: 'ts' as const,
    code: `
import { defineVerification, runVerification } from './guardian_verify.ts'

runVerification(defineVerification({
  async verify(ctx) {
    const attacker = await ctx.http('/items/7', { as: 'bob', session: 'pair', role: 'probe' })
    const owner = await ctx.http('/items/7', { as: 'alice', session: 'pair', role: 'control' })
    ctx.expect.status(attacker, 200)
    ctx.expect.jsonPath(attacker, 'owner', 'alice')
    ctx.expect.bodyContains(attacker, 'alice-private-item-7')
    ctx.expect.status(owner, 200)
    return ctx.result({ title: 'BOLA: bob reads alice item 7', severity: 'high' })
  },
}))
`,
  }
  const verdict = await verifyScript({ candidate, openAttempt: factory })
  assert.equal(verdict.confirmed, true, `${verdict.reason}: ${verdict.detail}`)
  assert.equal(verdict.attempts.length, 2)
  assert.notEqual(verdict.attempts[0].nonce, verdict.attempts[1].nonce, 'attempts must use fresh nonces')
  assert.equal(verdict.attempts[0].oraclePassed, true)
  assert.equal(verdict.attempts[1].oraclePassed, true)
  assert.equal(verdict.attempts[0].signaturesValid, true)
})

test('forged stdout or fabricated exchange ids are rejected by the transcript oracle', async () => {
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce) {
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-forged-${nonce.slice(0, 8)}`,
        assignmentId: 'assignment-forged',
        targetOrigins: [origin],
      }
    },
  })
  const forged = {
    name: 'forged.ts',
    runtime: 'ts' as const,
    code: `
import { writeFileSync } from 'node:fs'

console.log('PASSED: everything is vulnerable, trust me')
writeFileSync(process.env.GUARDIAN_PROOF_RESULT_FILE!, JSON.stringify({
  title: 'forged finding',
  claims: [
    { kind: 'status', exchangeId: 'gx-00000000-0000-0000-0000-000000000000', expected: 200 },
    { kind: 'body_contains', exchangeId: 'gx-forged', text: 'alice-private-item-7' },
  ],
}))
`,
  }
  const forgedVerdict = await verifyScript({ candidate: forged, openAttempt: factory })
  assert.equal(forgedVerdict.confirmed, false)
  assert.equal(forgedVerdict.reason, 'oracle_failed')
  assert.match(forgedVerdict.attempts[0].failures.join(' '), /Unknown exchange|no recorded|not.*record/i)

  const stdoutOnly = {
    name: 'stdout.ts',
    runtime: 'ts' as const,
    code: `console.log('{"confirmed":true,"claims":[]}')\n`,
  }
  const stdoutVerdict = await verifyScript({ candidate: stdoutOnly, openAttempt: factory })
  assert.equal(stdoutVerdict.confirmed, false)
  assert.equal(stdoutVerdict.reason, 'claims_missing')
})

test('a flaky candidate (second fresh run fails) is not confirmed', async () => {
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions(nonce, attempt) {
      bobSeesItem7 = attempt !== 2
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-flaky-${nonce.slice(0, 8)}`,
        assignmentId: 'assignment-flaky',
        targetOrigins: [origin],
      }
    },
  })
  const candidate = {
    name: 'flaky.ts',
    runtime: 'ts' as const,
    code: `
import { defineVerification, runVerification } from './guardian_verify.ts'

runVerification(defineVerification({
  async verify(ctx) {
    const attacker = await ctx.http('/items/7', { as: 'bob' })
    ctx.expect.status(attacker, 200)
    return ctx.result({ title: 'flaky BOLA' })
  },
}))
`,
  }
  const verdict = await verifyScript({ candidate, openAttempt: factory })
  bobSeesItem7 = true
  assert.equal(verdict.confirmed, false)
  assert.equal(verdict.reason, 'oracle_failed')
  assert.equal(verdict.attempts[0].oraclePassed, true)
  assert.equal(verdict.attempts[1].oraclePassed, false)
})

// ---------------------------------------------------------------------------
// Chunked IPC (Docker-gated): oversized outputs survive, timeouts do not kill the session.
// ---------------------------------------------------------------------------

async function dockerReady(): Promise<boolean> {
  try {
    await execFile('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 5_000 })
    const { stdout } = await execFile('docker', ['images', '--format', '{{.Repository}}:{{.Tag}}'], { timeout: 5_000 })
    return stdout.split('\n').includes('guardian-worker:v4')
  } catch {
    return false
  }
}

test('end-to-end: guardian_verify TS script runs inside the sandbox and is oracle-verified', async t => {
  if (!(await dockerReady())) {
    t.skip('docker daemon or guardian-worker:v4 image unavailable')
    return
  }
  const server = await startRpc()
  const backend = new LinuxWorkerBackend({ runId: 'run-v6-verify-sandbox' })
  let session: Awaited<ReturnType<typeof backend.openSession>> | null = null
  try {
    session = await backend.openSession(randomUUID(), AbortSignal.timeout(90_000), { rpcMountDir: server.hostDir })
    assert.equal(typeof session.verifyScript, 'function')
    const execution = await session.verifyScript!({
      runtime: 'ts',
      nonce: server.nonce,
      code: `
import { defineVerification, runVerification } from './guardian_verify.ts'

runVerification(defineVerification({
  async verify(ctx) {
    const attacker = await ctx.http('/items/7', { as: 'bob' })
    const owner = await ctx.http('/items/7', { as: 'alice' })
    ctx.expect.status(attacker, 200)
    ctx.expect.jsonPath(attacker, 'owner', 'alice')
    ctx.expect.status(owner, 200)
    return ctx.result({ title: 'sandbox BOLA', severity: 'high' })
  },
}))
`,
    }, AbortSignal.timeout(90_000))
    assert.equal(execution.exitCode, 0, execution.stderr)
    const oracle = evaluateClaims(server.transcript, (execution.result as { claims: VerifyClaim[] }).claims)
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
    assert.ok(server.transcript.size >= 2)

    // Oversized script output is spilled by the bridge and still delivered intact.
    const large = await session.verifyScript!({
      runtime: 'ts',
      nonce: 'f'.repeat(32),
      code: "console.log('x'.repeat(100000))\n",
    }, AbortSignal.timeout(60_000))
    assert.equal(large.exitCode, 0, large.stderr)
    assert.ok(large.stdout.length >= 100_000)
  } finally {
    if (session) await session.close()
    await server.close()
  }
})

test('chunked IPC: one-shot output >64 KiB hydrates through a tmpfs pointer', async t => {
  if (!(await dockerReady())) {
    t.skip('docker daemon or guardian-worker:v4 image unavailable')
    return
  }
  const backend = new LinuxWorkerBackend({ runId: 'run-v6-verify-ipc-oneshot' })
  const res = await backend.run({
    assignmentId: randomUUID(),
    files: [{ name: 'big.txt', content: 'b'.repeat(120_000) }],
    command: 'cat /evidence/big.txt',
    outputs: [],
    timeoutMs: 30_000,
  }, AbortSignal.timeout(60_000))
  assert.equal(res.exitCode, 0, res.stderr)
  assert.equal(res.stdout.length, 120_000)
})

test('chunked IPC: >64 KiB output survives without terminating the worker session', async t => {
  if (!(await dockerReady())) {
    t.skip('docker daemon or guardian-worker:v4 image unavailable')
    return
  }
  const backend = new LinuxWorkerBackend({ runId: 'run-v6-verify-ipc' })
  const session = await backend.openSession(randomUUID(), AbortSignal.timeout(90_000))
  try {
    // Stage a genuinely large payload; the response envelope must spill to tmpfs instead of
    // tripping the host's 64 KiB NDJSON line guard.
    await session.stage('large.txt', 'a'.repeat(100_000), AbortSignal.timeout(15_000))
    const large = await session.exec('cat /evidence/large.txt', [], AbortSignal.timeout(60_000), 30_000)
    assert.equal(large.exitCode, 0, large.stderr)
    assert.ok(large.stdout.length > 64 * 1024, `expected >64 KiB, got ${large.stdout.length}`)
    assert.equal(large.stdout.length, 100_000)

    const alive = await session.exec('echo still-alive', [], AbortSignal.timeout(30_000), 10_000)
    assert.equal(alive.exitCode, 0)
    assert.match(alive.stdout, /still-alive/)

    const timedOut = await session.exec('sleep 30', [], AbortSignal.timeout(30_000), 1_200)
    assert.equal(timedOut.exitCode, 124)
    assert.equal(timedOut.timedOut, true)

    const afterTimeout = await session.exec('echo alive-after-timeout', [], AbortSignal.timeout(30_000), 10_000)
    assert.equal(afterTimeout.exitCode, 0)
    assert.match(afterTimeout.stdout, /alive-after-timeout/)
  } finally {
    await session.close()
  }
})
