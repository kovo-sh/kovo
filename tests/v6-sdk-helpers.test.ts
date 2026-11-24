// v6 first-class proof helpers: typed transcripts for the Layer-3 oracle.
//
// Defensive framing: these are differential probes against an intentional local-lab fixture.
// Every helper must record the exact transcript roles the oracle reads (control/probe/readback/
// pending_oob/race) and return repair feedback instead of only a boolean.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createServer as createHttpServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createServer as createH2Server } from 'node:http2'
import type { ServerHttp2Stream } from 'node:http2'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  createLocalAttemptFactory,
  evaluateClaims,
  VerifyRpcServer,
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
} from '../src/server/verify-rpc.ts'
import type { VerifyCanaryBroker, VerifyClaim, VerifyOobPromotionView, VerifyOobSubscriptionView } from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/guardian_verify/guardian_verify.ts'

const SDK_DIR = join(dirname(fileURLToPath(import.meta.url)), '../worker/guardian_verify')
process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const ALICE_SECRET = 'alice-secret-helper-1'
const BOB_SECRET = 'bob-secret-helper-2'

function json(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value)
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) })
  res.end(body)
}

// Fixture state: a vulnerable default and a hardened toggle per proof family.
const fixtureState = {
  boundaryHardened: false,
  stateBalance: 100,
  stateHardened: false,
  diffHardened: false,
  timingHardened: false,
  raceCounter: 0,
  raceHardened: false,
}

function resetFixture(): void {
  fixtureState.boundaryHardened = false
  fixtureState.stateBalance = 100
  fixtureState.stateHardened = false
  fixtureState.diffHardened = false
  fixtureState.timingHardened = false
  fixtureState.raceCounter = 0
  fixtureState.raceHardened = false
}

function identityOf(req: IncomingMessage): 'alice' | 'bob' | 'anonymous' {
  const raw = String(req.headers['x-user'] ?? '')
  if (raw === ALICE_SECRET) return 'alice'
  if (raw === BOB_SECRET) return 'bob'
  return 'anonymous'
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks).toString('utf8')
}

function html(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' })
  res.end(body)
}

const fixture = createHttpServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1')
  const who = identityOf(req)
  const nonce = randomUUID()
  if (url.pathname === '/boundary/secret') {
    if (fixtureState.boundaryHardened) return json(res, 403, { error: 'forbidden' })
    if (who === 'bob') return json(res, 403, { error: 'forbidden' })
    if (who === 'alice') return json(res, 200, { owner: 'alice', item: 'secret-42', private: 'alice-private-secret-42' })
    return json(res, 401, { error: 'unauthenticated' })
  }
  if (url.pathname === '/state/item') {
    return json(res, 200, { owner: 'alice', balance: fixtureState.stateBalance, currency: 'USD' })
  }
  if (url.pathname === '/state/mutate') {
    const body = JSON.parse(await readBody(req)) as { balance?: number }
    if (!fixtureState.stateHardened && typeof body.balance === 'number') fixtureState.stateBalance = body.balance
    return json(res, 200, { ok: true })
  }
  if (url.pathname === '/diff') {
    const view = url.searchParams.get('view') ?? 'user'
    if (fixtureState.diffHardened || view !== 'admin') {
      return html(res, 200, `<html><body data-request-id="${nonce}"><p>Access denied</p></body></html>`)
    }
    return html(res, 200, `<html><body data-request-id="${nonce}"><h1>Welcome administrator</h1><table id="admin-panel"><tr><td>ledger-secret</td></tr></table></body></html>`)
  }
  if (url.pathname === '/timing') {
    const requested = Number(url.searchParams.get('ms') ?? '0')
    const ms = fixtureState.timingHardened ? 6 : Math.max(1, requested)
    await new Promise(resolve => setTimeout(resolve, ms + Math.random() * 2))
    return json(res, 200, { ms })
  }
  if (url.pathname === '/race/redeem') {
    if (fixtureState.raceHardened) return json(res, 200, { ok: true })
    fixtureState.raceCounter += 1
    return json(res, 200, { ok: true, slot: fixtureState.raceCounter })
  }
  if (url.pathname === '/oob/fetch') return json(res, 200, { ok: true })
  return json(res, 404, { error: 'not found' })
})

// A separate HTTP/2 fixture for the single-packet barrier leg.
const h2Fixture = createH2Server()
h2Fixture.on('stream', (stream: ServerHttp2Stream, headers) => {
  if (headers[':path'] === '/race/redeem') {
    if (fixtureState.raceHardened) {
      stream.respond({ ':status': 200, 'content-type': 'application/json' })
      stream.end(JSON.stringify({ ok: true }))
      return
    }
    fixtureState.raceCounter += 1
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ ok: true, slot: fixtureState.raceCounter }))
    return
  }
  stream.respond({ ':status': 404, 'content-type': 'application/json' })
  stream.end('{"error":"not found"}')
})

function listen(server: ReturnType<typeof createHttpServer> | ReturnType<typeof createH2Server>): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') reject(new Error('fixture did not bind a port'))
      else resolve(address.port)
    })
  })
}

function closeServer(server: ReturnType<typeof createHttpServer> | ReturnType<typeof createH2Server>): Promise<void> {
  return new Promise(resolve => server.close(() => resolve()))
}

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
    // Both personas are authenticated members of the same tenant: a denial for bob on
    // alice's object is a genuine peer boundary, not an anonymous 401 artifact.
    roleLabel: 'member (acme)',
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
    isStateChangeApproved: () => true,
    audit: () => {},
  }
}

/**
 * Fake durable relay with a controllable clock. A callback received outside the immediate window
 * must remain attributable to the registered `pending_oob` subscription and be promoted.
 */
class FakeCanary implements VerifyCanaryBroker {
  now = 1_000
  private readonly minted = new Map<string, { createdAt: number }>()
  private readonly callbacks = new Map<string, { receivedAt: number; detail: Record<string, unknown> }>()
  private readonly subscriptions: Array<VerifyOobSubscriptionView & { token: string; runId: string; immediateMs: number }> = []
  private sequence = 0

  mintCanary(_runId: string, label: string) {
    const token = `guardian-canary-${randomUUID().replace(/-/g, '').slice(0, 20)}`
    this.minted.set(token, { createdAt: this.now })
    return { token, httpUrl: `http://canary.local/c/${token}`, url: `http://canary.local/c/${token}`, dnsHost: `${token}.canary.local`, label }
  }

  checkCanary(token: string) {
    const callback = this.callbacks.get(token)
    return {
      found: this.minted.has(token),
      hit: Boolean(callback),
      triggered: Boolean(callback),
      hits: callback ? [{ protocol: 'http', token, remoteIp: '127.0.0.1', timestamp: callback.receivedAt }] : [],
      detail: callback ? { timestamp: callback.receivedAt } : null,
    }
  }

  subscribe(input: { runId: string; token: string; immediateMs?: number; windowMs?: number }): VerifyOobSubscriptionView {
    this.sequence += 1
    const subscription = {
      id: `sub-${this.sequence}`,
      token: input.token,
      status: 'pending',
      createdAt: this.now,
      expiresAt: this.now + (input.windowMs ?? 15 * 60_000),
      immediateMs: input.immediateMs ?? 3_000,
      windowMs: input.windowMs ?? 15 * 60_000,
      runId: input.runId,
    }
    this.subscriptions.push(subscription)
    return subscription
  }

  /** Simulate a callback that arrives after the immediate window (fake clock, no sleeping). */
  recordLateCallback(token: string, delayMs = 20_000): void {
    this.now += delayMs
    this.callbacks.set(token, { receivedAt: this.now, detail: { protocol: 'http' } })
  }

  async awaitAny(query: { token?: string }) {
    this.now += 5_000
    const callback = query.token ? this.callbacks.get(query.token) : undefined
    return {
      matched: Boolean(callback),
      callback: callback ? { receivedAt: callback.receivedAt, token: query.token, detail: callback.detail } : null,
    }
  }

  promoteLate(): VerifyOobPromotionView[] {
    const promotions: VerifyOobPromotionView[] = []
    for (const subscription of this.subscriptions) {
      const callback = this.callbacks.get(subscription.token)
      if (!callback || subscription.status === 'promoted') continue
      subscription.status = 'promoted'
      promotions.push({ subscription: { id: subscription.id, token: subscription.token }, callback })
    }
    return promotions
  }

  pending(runId?: string): VerifyOobSubscriptionView[] {
    return this.subscriptions.filter(subscription => subscription.status === 'pending' && (!runId || subscription.runId === runId))
  }
}

async function startRpc(options: {
  transportConfig?: { http2?: boolean }
  canary?: VerifyCanaryBroker
  transport?: RequestBroker
} = {}): Promise<VerifyRpcServer> {
  const server = new VerifyRpcServer({
    broker: options.transport ?? new RequestBroker(options.transportConfig ? { transportConfig: options.transportConfig } : {}),
    grant: makeGrant(),
    runId: `run-helpers-${randomUUID().slice(0, 8)}`,
    assignmentId: 'assignment-helpers',
    nonce: randomUUID().replace(/-/g, ''),
    targetOrigins: [origin, h2Origin],
    ...(options.canary ? { canary: options.canary } : {}),
  })
  await server.start()
  return server
}

function bindEnv(server: VerifyRpcServer): () => void {
  const previous = {
    socket: process.env[VERIFY_RPC_SOCKET_ENV],
    token: process.env[VERIFY_RPC_TOKEN_ENV],
    context: process.env[VERIFY_RPC_CONTEXT_ENV],
    nonce: process.env[VERIFY_NONCE_ENV],
  }
  process.env[VERIFY_RPC_SOCKET_ENV] = server.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(server.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(server.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = server.nonce
  return () => {
    for (const [key, value] of Object.entries({
      [VERIFY_RPC_SOCKET_ENV]: previous.socket,
      [VERIFY_RPC_TOKEN_ENV]: previous.token,
      [VERIFY_RPC_CONTEXT_ENV]: previous.context,
      [VERIFY_NONCE_ENV]: previous.nonce,
    })) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

// ---------------------------------------------------------------------------
// 1. Access boundary
// ---------------------------------------------------------------------------

test('proveAccessBoundary records control_denied + variant_crossed and passes boundary, fails hardened', async () => {
  resetFixture()
  const server = await startRpc()
  const restore = bindEnv(server)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.proveAccessBoundary({
      controlPersona: 'bob',
      probePersona: 'alice',
      route: '/boundary/secret',
    })
    assert.equal(proof.ok, true, proof.missingEvidence.join(','))
    assert.equal(proof.claim.kind, 'boundary')
    assert.match(proof.transcript.control_denied, /^gx-/)
    assert.match(proof.transcript.variant_crossed, /^gx-/)
    assert.deepEqual(proof.transcriptSummary.map(entry => entry.role), ['control_denied', 'variant_crossed'])
    const oracle = evaluateClaims(server.transcript, ctx.claims)
    assert.equal(oracle.passed, true, oracle.failures.join('; '))
    assert.equal(oracle.rejectedBy, null)

    // Hardened: the probe is denied too, so the boundary claim must be rejected with the exact role.
    fixtureState.boundaryHardened = true
    const hardened = await ctx.proveAccessBoundary({
      controlPersona: 'bob',
      probePersona: 'alice',
      route: '/boundary/secret',
    })
    assert.equal(hardened.ok, false)
    assert.deepEqual(hardened.missingEvidence, ['variant_crossed'])
    assert.equal(hardened.rejectedBy, 'boundary')
    const hardenedOracle = evaluateClaims(server.transcript, [hardened.claim])
    assert.equal(hardenedOracle.passed, false)
    assert.equal(hardenedOracle.rejectedBy, 'boundary')
    assert.ok(hardenedOracle.missingEvidence?.includes('variant_crossed'))
    assert.equal(hardenedOracle.transcriptSummary?.some(entry => entry.role === 'probe'), true)
  } finally {
    restore()
    await server.close()
  }
})

// ---------------------------------------------------------------------------
// 2. Persisted mutation
// ---------------------------------------------------------------------------

test('provePersistedMutation records before_get/mutation/after_get and returns the delta', async () => {
  resetFixture()
  const server = await startRpc()
  const restore = bindEnv(server)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.provePersistedMutation({
      readRoute: '/state/item',
      mutation: { target: '/state/mutate', method: 'POST', body: JSON.stringify({ balance: 999 }), as: 'alice' },
      fieldPath: 'balance',
      expectDelta: 999,
      readPersona: 'alice',
    })
    assert.equal(proof.ok, true, proof.missingEvidence.join(','))
    assert.equal(proof.claim.kind, 'impact')
    assert.equal(proof.delta.before, 100)
    assert.equal(proof.delta.after, 999)
    assert.equal(proof.delta.changed, true)
    assert.deepEqual(proof.transcriptSummary.map(entry => entry.role), ['before_get', 'mutation', 'after_get'])
    const oracle = evaluateClaims(server.transcript, ctx.claims, { claimedImpact: 'mass_assignment' })
    assert.equal(oracle.passed, true, oracle.failures.join('; '))

    // Hardened: the server ignores the field, so the readback is an idempotent no-op.
    fixtureState.stateHardened = true
    fixtureState.stateBalance = 100
    const hardened = await ctx.provePersistedMutation({
      readRoute: '/state/item',
      mutation: { target: '/state/mutate', method: 'POST', body: JSON.stringify({ balance: 5000 }), as: 'alice' },
      fieldPath: 'balance',
      expectDelta: 5000,
      readPersona: 'alice',
    })
    assert.equal(hardened.ok, false)
    assert.ok(hardened.missingEvidence.includes('field_delta:balance'))
    assert.ok(hardened.missingEvidence.includes('expected_delta'))
    const hardenedOracle = evaluateClaims(server.transcript, [hardened.claim], { claimedImpact: 'mass_assignment' })
    assert.equal(hardenedOracle.passed, false)
    assert.equal(hardenedOracle.rejectedBy, 'impact')
    assert.ok(hardenedOracle.missingEvidence?.includes('persisted_field_delta'))
  } finally {
    restore()
    await server.close()
  }
})

// ---------------------------------------------------------------------------
// 3. Boolean / timing differential
// ---------------------------------------------------------------------------

test('proveBooleanOrTimingDiff strips rotating tokens and records both arms', async () => {
  resetFixture()
  const server = await startRpc()
  const restore = bindEnv(server)
  try {
    const ctx = new VerifyContext()
    const booleanProof = await ctx.proveBooleanOrTimingDiff({
      control: '/diff?view=user',
      variant: '/diff?view=admin',
      mode: 'boolean',
      rounds: 3,
    })
    assert.equal(booleanProof.ok, true, booleanProof.missingEvidence.join(','))
    assert.equal(booleanProof.claim.kind, 'structural_diff')
    const stableDelta = booleanProof.stats.stableDelta as string[]
    assert.ok(stableDelta.includes('welcome') || stableDelta.includes('administrator'))
    assert.deepEqual([...new Set(booleanProof.transcriptSummary.map(entry => entry.role))].sort(), ['control', 'probe'])
    const oracle = evaluateClaims(server.transcript, ctx.claims)
    assert.equal(oracle.passed, true, oracle.failures.join('; '))

    fixtureState.diffHardened = true
    const hardened = await ctx.proveBooleanOrTimingDiff({
      control: '/diff?view=user',
      variant: '/diff?view=admin',
      mode: 'boolean',
      rounds: 3,
    })
    assert.equal(hardened.ok, false)
    assert.ok(hardened.missingEvidence.includes('stable_variant_delta') || hardened.missingEvidence.includes('arm_differential'))
    const hardenedOracle = evaluateClaims(server.transcript, [hardened.claim])
    assert.equal(hardenedOracle.passed, false)
    assert.equal(hardenedOracle.rejectedBy, 'structural_diff')

    fixtureState.timingHardened = false
    const timing = await ctx.proveBooleanOrTimingDiff({
      control: '/timing?ms=2',
      variant: '/timing?ms=45',
      mode: 'timing',
      rounds: 5,
    })
    assert.equal(timing.claim.kind, 'timing')
    assert.equal(timing.ok, true, timing.missingEvidence.join(','))
    const timingOracle = evaluateClaims(server.transcript, [timing.claim])
    assert.equal(timingOracle.passed, true, timingOracle.failures.join('; '))

    fixtureState.timingHardened = true
    const flat = await ctx.proveBooleanOrTimingDiff({
      control: '/timing?ms=2',
      variant: '/timing?ms=45',
      mode: 'timing',
      rounds: 5,
    })
    assert.equal(flat.ok, false)
    assert.ok(flat.missingEvidence.includes('timing_separation'))
    const flatOracle = evaluateClaims(server.transcript, [flat.claim])
    assert.equal(flatOracle.passed, false)
    assert.ok(flatOracle.missingEvidence?.includes('timing_separation'))
  } finally {
    restore()
    await server.close()
  }
})

// ---------------------------------------------------------------------------
// 4. OOB callback + durable pending_oob promotion
// ---------------------------------------------------------------------------

test('proveOobCallback registers pending_oob before injecting and promotes a late callback', async () => {
  resetFixture()
  const canary = new FakeCanary()
  const server = await startRpc({ canary })
  const restore = bindEnv(server)
  try {
    const ctx = new VerifyContext()
    let pendingAtInjection = -1
    const proof = await ctx.proveOobCallback({
      token: 'ssrf-late',
      immediateMs: 3_000,
      timeoutMs: 5_000,
      inject: async handle => {
        pendingAtInjection = canary.pending().length
        canary.recordLateCallback(handle.token, 20_000)
      },
    })
    assert.equal(pendingAtInjection, 1, 'a durable pending_oob subscription must exist before injection')
    assert.equal(proof.ok, true, proof.missingEvidence.join(','))
    assert.equal(proof.hit, true)
    assert.equal(proof.promoted, true)
    assert.equal(proof.stage, 'late')
    assert.match(proof.subscriptionId ?? '', /^sub-/)
    assert.deepEqual([...new Set(proof.transcriptSummary.map(entry => entry.role))].sort(), ['oob_mint', 'oob_wait', 'pending_oob'].sort())
    const oracle = evaluateClaims(server.transcript, ctx.claims, { canary })
    assert.equal(oracle.passed, true, oracle.failures.join('; '))

    // No callback: the subscription stays pending and the helper names the missing hit.
    const emptyCanary = new FakeCanary()
    const emptyServer = await startRpc({ canary: emptyCanary })
    const restoreEmpty = bindEnv(emptyServer)
    try {
      const emptyCtx = new VerifyContext()
      const pending = await emptyCtx.proveOobCallback({
        token: 'ssrf-silent',
        immediateMs: 1_000,
        timeoutMs: 1_000,
        inject: async () => undefined,
      })
      assert.equal(pending.ok, false)
      assert.equal(pending.stage, 'pending')
      assert.deepEqual(pending.missingEvidence, ['oob_callback_hit'])
      assert.equal(pending.subscriptionId !== null, true)
      const emptyOracle = evaluateClaims(emptyServer.transcript, [pending.claim], { canary: emptyCanary })
      assert.equal(emptyOracle.passed, false)
      assert.ok(emptyOracle.missingEvidence?.includes('oob_callback_hit'))
    } finally {
      restoreEmpty()
      await emptyServer.close()
    }
  } finally {
    restore()
    await server.close()
  }
})

// ---------------------------------------------------------------------------
// 5. Race burst
// ---------------------------------------------------------------------------

test('proveRaceBurst reports h2 single-packet vs explicit HTTP/1.1 fallback', async () => {
  resetFixture()
  const h2Server = await startRpc({ transportConfig: { http2: true } })
  const restoreH2 = bindEnv(h2Server)
  try {
    const ctx = new VerifyContext()
    const proof = await ctx.proveRaceBurst({
      requests: [
        { path: `${h2Origin}/race/redeem`, method: 'GET', as: 'alice' },
        { path: `${h2Origin}/race/redeem`, method: 'GET', as: 'alice' },
      ],
      barrier: 'auto',
    })
    assert.equal(proof.mode, 'h2-single-packet')
    assert.equal(proof.fallbackReason, null)
    assert.equal(proof.claim.kind, 'race')
    assert.equal(proof.transcriptSummary.length, 2)
    assert.equal(proof.transcriptSummary[0]?.method, 'GET')
    const oracle = evaluateClaims(h2Server.transcript, [proof.claim])
    assert.equal(oracle.passed, true, oracle.failures.join('; '))

    // Idempotent handler: identical bodies and statuses must not look like a race.
    fixtureState.raceHardened = true
    const hardened = await ctx.proveRaceBurst({
      requests: [
        { path: `${h2Origin}/race/redeem`, method: 'GET', as: 'alice' },
        { path: `${h2Origin}/race/redeem`, method: 'GET', as: 'alice' },
      ],
      barrier: 'h2',
    })
    assert.equal(hardened.ok, false)
    assert.ok(hardened.missingEvidence.includes('duplicate_effect'))
    const hardenedOracle = evaluateClaims(h2Server.transcript, [hardened.claim])
    assert.equal(hardenedOracle.passed, false)
    assert.ok(hardenedOracle.missingEvidence?.includes('duplicate_effect'))
  } finally {
    restoreH2()
    await h2Server.close()
  }

  resetFixture()
  const fallbackServer = await startRpc({ transportConfig: { http2: false } })
  const restoreFallback = bindEnv(fallbackServer)
  try {
    const ctx = new VerifyContext()
    const fallback = await ctx.proveRaceBurst({
      requests: [
        { path: `${origin}/race/redeem`, method: 'GET', as: 'alice' },
        { path: `${origin}/race/redeem`, method: 'GET', as: 'alice' },
      ],
      barrier: 'auto',
    })
    assert.equal(fallback.mode, 'http1-fallback')
    assert.match(fallback.fallbackReason ?? '', /HTTP\/2 transport is unavailable/)
    assert.equal(fallback.ok, true, fallback.missingEvidence.join(','))
    const fbOracle = evaluateClaims(fallbackServer.transcript, [fallback.claim])
    assert.equal(fbOracle.passed, true, fbOracle.failures.join('; '))
  } finally {
    restoreFallback()
    await fallbackServer.close()
  }
})

// ---------------------------------------------------------------------------
// End-to-end: helpers flow through verifyScript (two fresh runs) + Python parity
// ---------------------------------------------------------------------------

test('access-boundary helper confirms through verifyScript fresh-session double run', async () => {
  resetFixture()
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-helper-boundary-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-helper-boundary',
        targetOrigins: [origin],
      }
    },
  })
  const { verifyScript } = await import('../src/server/verify-rpc.ts')
  const verdict = await verifyScript({
    candidate: {
      name: 'boundary-helper.ts',
      runtime: 'ts',
      code: `
import { defineVerification, runVerification } from './guardian_verify.ts'

runVerification(defineVerification({
  async verify(ctx) {
    const proof = await ctx.prove_access_boundary({ controlPersona: 'bob', probePersona: 'alice', route: '/boundary/secret' })
    if (!proof.ok) throw new Error(proof.missingEvidence.join(','))
    return ctx.result({ title: 'BOLA access-control boundary', severity: 'high' })
  },
}))
`,
    },
    openAttempt: factory,
  })
  assert.equal(verdict.confirmed, true, `${verdict.reason}: ${verdict.attempts.map(attempt => attempt.failures.join('; ')).join(' | ')}`)
  assert.equal(verdict.rejectedBy, null)
  assert.equal(verdict.missingEvidence.length, 0)
  assert.ok(verdict.transcriptSummary.some(entry => entry.role === 'control'))
  assert.ok(verdict.transcriptSummary.some(entry => entry.role === 'probe'))
})

test('packaged-helper failure names the exact missing role in the same verdict feedback', async () => {
  resetFixture()
  fixtureState.boundaryHardened = true
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-helper-gap-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-helper-gap',
        targetOrigins: [origin],
      }
    },
  })
  const { verifyScript } = await import('../src/server/verify-rpc.ts')
  const verdict = await verifyScript({
    candidate: {
      name: 'boundary-helper-gap.ts',
      runtime: 'ts',
      code: `
import { defineVerification, runVerification } from './guardian_verify.ts'

runVerification(defineVerification({
  async verify(ctx) {
    await ctx.proveAccessBoundary({ controlPersona: 'bob', probePersona: 'alice', route: '/boundary/secret' })
    return ctx.result({ title: 'BOLA access-control boundary', severity: 'high' })
  },
}))
`,
    },
    openAttempt: factory,
  })
  assert.equal(verdict.confirmed, false)
  assert.equal(verdict.reason, 'oracle_failed')
  assert.equal(verdict.rejectedBy, 'boundary')
  assert.ok(verdict.missingEvidence.includes('variant_crossed'))
  assert.ok(verdict.missingEvidence.includes('owner_scoped_disclosure') || verdict.missingEvidence.includes('boundary_or_disclosure'))
  const failureText = verdict.attempts.flatMap(attempt => attempt.failures).join('\n')
  assert.match(failureText, /missing-evidence: variant_crossed/)
  assert.match(failureText, /rejected-by: boundary/)
  assert.match(failureText, /transcript-role: (control_denied|control)/)
})

test('Python helper parity: boundary helper emits the same claim and feedback shape', async () => {
  resetFixture()
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-helper-python-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-helper-python',
        targetOrigins: [origin],
      }
    },
  })
  const { verifyScript } = await import('../src/server/verify-rpc.ts')
  const verdict = await verifyScript({
    candidate: {
      name: 'helpers.py',
      runtime: 'python',
      code: `
from guardian_verify import define, run

def verify(ctx):
    proof = ctx.proveAccessBoundary('bob', 'alice', '/boundary/secret')
    assert proof['claim']['kind'] == 'boundary', proof
    assert proof['transcript']['control_denied'], proof
    assert proof['transcript']['variant_crossed'], proof
    assert proof['missingEvidence'] == [], proof
    assert [item['role'] for item in proof['transcriptSummary']] == ['control_denied', 'variant_crossed'], proof
    return ctx.result('BOLA access-control boundary')

run(define(verify=verify))
`,
    },
    openAttempt: factory,
  })
  assert.equal(verdict.confirmed, true, `${verdict.reason}: ${verdict.attempts.map(attempt => attempt.failures.join('; ')).join(' | ')}`)
  assert.equal(verdict.attempts[0]?.claimCount, 1)
})

test('Python helper parity: persisted mutation and boolean diff emit oracle-backed claims', async () => {
  resetFixture()
  const factory = createLocalAttemptFactory({
    sdkDir: SDK_DIR,
    createRpcOptions() {
      return {
        broker: new RequestBroker(),
        grant: makeGrant(),
        runId: `run-helper-python2-${randomUUID().slice(0, 8)}`,
        assignmentId: 'assignment-helper-python2',
        targetOrigins: [origin],
      }
    },
  })
  const { verifyScript } = await import('../src/server/verify-rpc.ts')
  const verdict = await verifyScript({
    candidate: {
      name: 'mutation-diff.py',
      runtime: 'python',
      code: `
import time
from guardian_verify import define, run

def verify(ctx):
    value = int(time.time() * 1000) % 1000000
    mutation = ctx.prove_persisted_mutation(
        '/state/item',
        {'target': '/state/mutate', 'method': 'POST', 'body': '{"balance": %d}' % value, 'as': 'alice'},
        'balance',
        value,
        read_persona='alice',
    )
    assert mutation['ok'], (mutation['missingEvidence'], mutation['delta'])
    diff = ctx.prove_boolean_or_timing_diff('/diff?view=user', '/diff?view=admin', 'boolean', rounds=3)
    assert diff['ok'], diff['missingEvidence']
    return ctx.result('Mass assignment and boolean differential')

run(define(verify=verify))
`,
    },
    openAttempt: factory,
  })
  assert.equal(verdict.confirmed, true, `${verdict.reason}: ${verdict.attempts.map(attempt => attempt.failures.join('; ') + ' | stderr=' + (attempt.stderr ?? '')).join(' | ')}`)
  assert.equal(verdict.attempts[0]?.claimCount, 2)
})
