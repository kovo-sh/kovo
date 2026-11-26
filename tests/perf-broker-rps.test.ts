import assert from 'node:assert/strict'
import test from 'node:test'
import { defaultMaxRpsPerOrigin, maxRpsPerOriginCeiling } from '../src/domain.ts'
import {
  BrokerCircuitOpen,
  brokerExternalApexRpsCap,
  brokerPerOriginConcurrencyCap,
  brokerPerOriginRpsCap,
  EXTERNAL_APEX_MAX_RPS_CAP,
  EXTERNAL_ORIGIN_MAX_IN_FLIGHT,
  EXTERNAL_ORIGIN_MAX_RPS_CAP,
  externalApexBucketKey,
  LOOPBACK_ORIGIN_MAX_RPS_CAP,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant, Transport } from '../src/server/broker.ts'

async function withEnv<T>(patch: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const prev = new Map<string, string | undefined>()
  for (const [k, v] of Object.entries(patch)) {
    prev.set(k, process.env[k])
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of prev) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

function makeExternalGrant(origins: readonly string[], opts: Partial<Grant> = {}): Grant {
  const allowed = new Set(origins)
  return {
    origin: origins[0],
    tier: 1,
    allowLocalLab: false,
    canRead: o => allowed.has(o),
    audit: () => undefined,
    ...opts,
  }
}

test('default RPS and external concurrency constants are raised safely while keeping ceilings and 429 backoff intact', async () => {
  assert.equal(defaultMaxRpsPerOrigin, 10)
  assert.equal(maxRpsPerOriginCeiling, 100)
  assert.equal(EXTERNAL_ORIGIN_MAX_IN_FLIGHT, 4)
  assert.equal(EXTERNAL_ORIGIN_MAX_RPS_CAP, 20)
  assert.equal(LOOPBACK_ORIGIN_MAX_RPS_CAP, 100)
  assert.equal(EXTERNAL_APEX_MAX_RPS_CAP, 45)
  assert.equal(brokerPerOriginConcurrencyCap('https://api.example.test'), 4)
  assert.equal(brokerPerOriginRpsCap('https://api.example.test', 50), 20)
  assert.equal(brokerPerOriginRpsCap('http://127.0.0.1:8080', 50), 50)

  // Verify external origin allows 4 concurrent in-flight requests (and strictly caps at 4).
  let active = 0
  let peak = 0
  const origin = 'https://concurrency.example.test'
  const transport: Transport = async () => {
    active += 1
    if (active > peak) peak = active
    await new Promise(resolve => setTimeout(resolve, 60))
    active -= 1
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
  }
  const broker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport,
  })
  const grant = makeExternalGrant([origin], { maxRpsPerOrigin: 20 })
  await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      broker.executeHttp({ origin, method: 'GET', pathAndQuery: `/slot/${i}` }, grant, AbortSignal.timeout(5_000)),
    ),
  )
  assert.equal(peak, 4, `expected external origin peak in-flight to be 4, got ${peak}`)

  // Verify 429 adaptive RPS halving still backs down smoothly from default 10 -> 5 -> 2 -> 1.
  let rateLimitedCalls = 0
  const rlOrigin = 'https://ratelimit.example.test'
  const rlBroker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => {
      rateLimitedCalls += 1
      return { status: 429, headers: { 'content-type': 'text/plain' }, body: 'slow down' }
    },
    circuit429Threshold: 10,
  })
  const rlGrant = makeExternalGrant([rlOrigin])
  await rlBroker.executeHttp({ origin: rlOrigin, method: 'GET', pathAndQuery: '/a' }, rlGrant, AbortSignal.timeout(5_000))
  assert.equal(rlBroker.getCircuitState(rlOrigin).adaptiveRps, 5)
  await rlBroker.executeHttp({ origin: rlOrigin, method: 'GET', pathAndQuery: '/b' }, rlGrant, AbortSignal.timeout(5_000))
  assert.equal(rlBroker.getCircuitState(rlOrigin).adaptiveRps, 2)
  await rlBroker.executeHttp({ origin: rlOrigin, method: 'GET', pathAndQuery: '/c' }, rlGrant, AbortSignal.timeout(5_000))
  assert.equal(rlBroker.getCircuitState(rlOrigin).adaptiveRps, 1)
  assert.equal(rateLimitedCalls, 3)
})

test('per-request AbortSignal.timeout trips origin circuit when run signal is active, while run-level abort does not', async () => {
  const origin = 'https://timeout.example.test'
  let transportCalls = 0
  const auditEvents: Array<{ action: string; origin: string }> = []
  const hangingTransport: Transport = async (_url, _addr, signal) => {
    transportCalls += 1
    await new Promise<never>((_resolve, reject) => {
      if (signal.aborted) return reject(signal.reason)
      signal.addEventListener('abort', () => reject(signal.reason), { once: true })
    })
    throw new Error('unreachable')
  }

  const broker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: hangingTransport,
    circuit5xxThreshold: 3,
    circuitWindowMs: 30_000,
  })
  const grant = makeExternalGrant([origin], {
    maxRpsPerOrigin: 10,
    audit: (action, o) => { auditEvents.push({ action, origin: o }) },
  })

  // 1. Run-level signal abort MUST NOT increment transport failures or trip the circuit.
  const runAbort = new AbortController()
  const abortedPromises = Array.from({ length: 3 }, (_, i) =>
    broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: `/cancel/${i}`, timeoutMs: 10_000 },
      grant,
      runAbort.signal,
    ),
  )
  setTimeout(() => runAbort.abort(new Error('run cancelled by operator')), 50)
  const abortedResults = await Promise.allSettled(abortedPromises)
  assert.equal(abortedResults.every(r => r.status === 'rejected'), true)
  assert.equal(broker.getCircuitState(origin).failures5xx, 0, 'run-level abort must not record transport failures')
  assert.equal(broker.isCircuitOpen(origin), false, 'run-level abort must not open circuit')
  assert.equal(auditEvents.some(e => e.action === 'circuit_open'), false)

  // 2. Per-request timeouts (run signal NOT aborted) MUST increment transport failures and open the circuit.
  const runActive = new AbortController()
  const callsBeforeTimeouts = transportCalls
  const timeoutPromises = Array.from({ length: 3 }, (_, i) =>
    broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: `/hang/${i}`, timeoutMs: 1_000 },
      grant,
      runActive.signal,
    ),
  )
  const timeoutResults = await Promise.allSettled(timeoutPromises)
  assert.equal(timeoutResults.every(r => r.status === 'rejected'), true)
  assert.equal(runActive.signal.aborted, false)
  assert.equal(transportCalls - callsBeforeTimeouts, 3)
  assert.equal(
    timeoutResults.some(r => r.status === 'rejected' && r.reason instanceof BrokerCircuitOpen),
    true,
    '3rd per-request timeout should throw BrokerCircuitOpen',
  )
  assert.equal(broker.isCircuitOpen(origin), true, 'origin circuit must open after threshold per-request timeouts')
  assert.equal(auditEvents.some(e => e.action === 'circuit_open' && e.origin === origin), true)

  // 3. Subsequent request fails fast without hitting transport.
  const callsWhenOpen = transportCalls
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/after-open', timeoutMs: 1_000 }, grant, runActive.signal),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(transportCalls, callsWhenOpen, 'open circuit must fail fast before transport')
})

test('Cloudflare/origin-down 520-526 responses across distinct path templates open the origin-wide circuit breaker', async () => {
  // 1. Repeated HTTP 525 (SSL Handshake Failed) across 5 distinct path templates opens origin-wide circuit.
  const origin525 = 'https://tls-broken.example.test'
  let calls525 = 0
  const broker525 = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => {
      calls525 += 1
      return { status: 525, headers: { 'content-type': 'text/html' }, body: 'SSL Handshake Failed' }
    },
    circuit5xxThreshold: 5,
    circuitWindowMs: 30_000,
  })
  const grant525 = makeExternalGrant([origin525], { maxRpsPerOrigin: 20 })
  const distinctPaths = ['/', '/robots.txt', '/sitemap.xml', '/api/status', '/login']
  for (let i = 0; i < 4; i += 1) {
    const res = await broker525.executeHttp(
      { origin: origin525, method: 'GET', pathAndQuery: distinctPaths[i] },
      grant525,
      AbortSignal.timeout(5_000),
    )
    assert.equal(res.status, 525)
    assert.equal(broker525.isCircuitOpen(origin525), false)
  }
  await assert.rejects(
    broker525.executeHttp(
      { origin: origin525, method: 'GET', pathAndQuery: distinctPaths[4] },
      grant525,
      AbortSignal.timeout(5_000),
    ),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker525.isCircuitOpen(origin525), true)
  assert.equal(calls525, 5)
  // Yet another distinct path fails fast without touching transport.
  await assert.rejects(
    broker525.executeHttp(
      { origin: origin525, method: 'GET', pathAndQuery: '/pricing' },
      grant525,
      AbortSignal.timeout(5_000),
    ),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(calls525, 5)

  // 2. Mixed 521/522/524/520/526 across distinct paths also trip the origin-wide circuit,
  // while ordinary HTTP 500 across distinct paths remains route-scoped.
  const originMixed = 'https://cf-down.example.test'
  const statuses = [521, 522, 524, 526]
  let idx = 0
  const brokerMixed = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({
      status: statuses[Math.min(idx++, statuses.length - 1)],
      headers: { 'content-type': 'text/plain' },
      body: 'edge origin error',
    }),
    circuit5xxThreshold: 4,
    circuitWindowMs: 30_000,
  })
  const grantMixed = makeExternalGrant([originMixed], { maxRpsPerOrigin: 20 })
  for (let i = 0; i < 3; i += 1) {
    await brokerMixed.executeHttp(
      { origin: originMixed, method: 'GET', pathAndQuery: `/distinct-${i}` },
      grantMixed,
      AbortSignal.timeout(5_000),
    )
  }
  await assert.rejects(
    brokerMixed.executeHttp(
      { origin: originMixed, method: 'GET', pathAndQuery: '/distinct-3' },
      grantMixed,
      AbortSignal.timeout(5_000),
    ),
    err => err instanceof BrokerCircuitOpen,
  )
  assert.equal(brokerMixed.isCircuitOpen(originMixed), true)

  const origin500 = 'https://app-error.example.test'
  const broker500 = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 500, headers: { 'content-type': 'text/plain' }, body: 'boom' }),
    circuit5xxThreshold: 4,
  })
  const grant500 = makeExternalGrant([origin500], { maxRpsPerOrigin: 20 })
  for (let i = 0; i < 4; i += 1) {
    const res = await broker500.executeHttp(
      { origin: origin500, method: 'GET', pathAndQuery: `/route-${i}` },
      grant500,
      AbortSignal.timeout(5_000),
    )
    assert.equal(res.status, 500)
  }
  assert.equal(broker500.isCircuitOpen(origin500), false, 'ordinary 500 across distinct paths stays route-scoped')
})

test('shared-apex rate limiter caps aggregate RPS across subdomains, bypasses loopback/local-lab, keeps per-origin caps independent, and cleans up on disposeRun', async () => {
  // Helper unit invariants
  assert.equal(brokerExternalApexRpsCap({}), 45)
  assert.equal(brokerExternalApexRpsCap({ KOVO_EXTERNAL_APEX_MAX_RPS: '30' }), 30)
  assert.equal(brokerExternalApexRpsCap({ KOVO_EXTERNAL_APEX_MAX_RPS: '9999' }), 200)
  assert.equal(brokerExternalApexRpsCap({ KOVO_EXTERNAL_APEX_MAX_RPS: '0' }), 45)
  assert.equal(brokerExternalApexRpsCap({ KOVO_EXTERNAL_APEX_MAX_RPS: 'invalid' }), 45)

  assert.equal(externalApexBucketKey('https://a.example.test'), 'example.test')
  assert.equal(externalApexBucketKey('https://api.sub.acme.co.uk'), 'acme.co.uk')
  assert.equal(externalApexBucketKey('https://a.example.test', true), null)
  assert.equal(externalApexBucketKey('http://127.0.0.1:8080'), null)
  assert.equal(externalApexBucketKey('http://localhost:3000'), null)
  assert.equal(externalApexBucketKey('http://10.0.0.5:8080'), null)
  assert.equal(externalApexBucketKey('https://svc.lab.local'), null)

  // 1. Aggregate cap across a.example.test, b.example.test, c.example.test sharing registrable apex `example.test`.
  // Each subdomain allows 10 req/s (30 tokens combined if uncapped), but shared apex cap = 6 req/s (burst = 6),
  // so 18 requests across the 3 subdomains require (18 - 6) / 6 = ~2.0s.
  await withEnv({ KOVO_EXTERNAL_APEX_MAX_RPS: '6' }, async () => {
    const origins = ['https://a.example.test', 'https://b.example.test', 'https://c.example.test']
    const broker = new RequestBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }),
    })
    const grant = makeExternalGrant(origins, { maxRpsPerOrigin: 10 })

    const start = Date.now()
    await Promise.all(
      Array.from({ length: 18 }, (_, i) =>
        broker.executeHttp(
          { origin: origins[i % origins.length], method: 'GET', pathAndQuery: `/apex/${i}`, runId: 'run-alpha' },
          grant,
          AbortSignal.timeout(10_000),
        ),
      ),
    )
    const elapsedMs = Date.now() - start
    assert.ok(
      elapsedMs >= 1_650,
      `expected shared apex cap (6 req/s, burst 6) to pace 18 requests across 3 subdomains >= 1650ms, got ${elapsedMs}ms`,
    )
    assert.equal(broker.getApexBucketCount(), 1, 'all 3 subdomains must share a single apex bucket')

    // 2. Concurrent run reference counting + clean disposal via disposeRun().
    await broker.executeHttp(
      { origin: origins[0], method: 'GET', pathAndQuery: '/run-beta', runId: 'run-beta' },
      grant,
      AbortSignal.timeout(5_000),
    )
    broker.disposeRun('run-alpha')
    assert.equal(broker.getApexBucketCount(), 1, 'apex bucket must persist while run-beta still references it')
    broker.disposeRun('run-beta')
    assert.equal(broker.getApexBucketCount(), 0, 'disposeRun must release unreferenced apex buckets cleanly')
  })

  // 3. Loopback origins bypass the external apex cap even when KOVO_EXTERNAL_APEX_MAX_RPS is very low.
  await withEnv({ KOVO_EXTERNAL_APEX_MAX_RPS: '2', KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const loopbackOrigins = ['http://127.0.0.1:19101', 'http://127.0.0.1:19102', 'http://localhost:19103']
    const broker = new RequestBroker({
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }),
    })
    const grant: Grant = {
      origin: loopbackOrigins[0],
      tier: 1,
      maxRpsPerOrigin: 20,
      allowLocalLab: true,
      canRead: o => loopbackOrigins.includes(o),
      audit: () => undefined,
    }
    const start = Date.now()
    await Promise.all(
      Array.from({ length: 18 }, (_, i) =>
        broker.executeHttp(
          { origin: loopbackOrigins[i % loopbackOrigins.length], method: 'GET', pathAndQuery: `/local/${i}` },
          grant,
          AbortSignal.timeout(5_000),
        ),
      ),
    )
    const elapsedMs = Date.now() - start
    assert.ok(elapsedMs < 800, `expected loopback origins to bypass external apex cap, took ${elapsedMs}ms`)
    assert.equal(broker.getApexBucketCount(), 0, 'loopback origins must never create external apex buckets')
  })

  // 4. Per-origin cap remains enforced independently when below the apex ceiling.
  await withEnv({ KOVO_EXTERNAL_APEX_MAX_RPS: '45' }, async () => {
    const originA = 'https://per-origin-a.example.test'
    const originB = 'https://per-origin-b.example.test'
    const broker = new RequestBroker({
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }),
    })
    const grant = makeExternalGrant([originA, originB], { maxRpsPerOrigin: 3 })

    // 7 requests to originA at 3 req/s (burst 3) must pace >= ~1.0s (4 / 3 = 1.33s),
    // while 3 requests to sibling originB finish immediately on originB's own bucket.
    const startA = Date.now()
    const promiseA = Promise.all(
      Array.from({ length: 7 }, (_, i) =>
        broker.executeHttp({ origin: originA, method: 'GET', pathAndQuery: `/a/${i}` }, grant, AbortSignal.timeout(8_000)),
      ),
    )
    const startB = Date.now()
    await Promise.all(
      Array.from({ length: 3 }, (_, i) =>
        broker.executeHttp({ origin: originB, method: 'GET', pathAndQuery: `/b/${i}` }, grant, AbortSignal.timeout(5_000)),
      ),
    )
    const elapsedB = Date.now() - startB
    await promiseA
    const elapsedA = Date.now() - startA

    assert.ok(elapsedB < 500, `sibling originB should use its own independent per-origin bucket, took ${elapsedB}ms`)
    assert.ok(elapsedA >= 1_000, `originA per-origin cap (3 req/s) must still pace 7 requests >= 1000ms, got ${elapsedA}ms`)
  })
})
