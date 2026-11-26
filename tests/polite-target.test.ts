/**
 * R2-16 Stage 1 class-level guard (<10s, zero-LLM, real loopback HTTP):
 *  1. Single host-owned `TargetLoadPolicy` + ONE unified HTTP target-load status taxonomy
 *     (`origin_down` / `throttled` / `transient` / `client_error` / `healthy`), value-preserving
 *     for local-lab and external defaults, re-exported through `run-safety-budgets.ts`.
 *  2. Injected `targetClassOverride: 'external'` on broker / grant construction exercises REAL
 *     external politeness caps on loopback `local-lab/polite-target` WITHOUT toggling process-wide
 *     `KOVO_ALLOW_LOCAL_LAB` flags.
 *  3. Real HTTP 429 + `Retry-After` honoring, adaptive RPS halving/recovery, 429 breaker trip,
 *     and structured `broker.target_throttled` / `broker.origin_breaker_open` telemetry.
 *  4. Real HTTP 503 & Cloudflare 52x (`520`-`526`) origin-down bursts open the origin breaker
 *     even under active injection `probeClass`, while plain 500 stays `transient` / route-scoped.
 *  5. Per-IP aggregate RPS & concurrency buckets enforce shared external limits across:
 *     - IP-literal multi-port targets (`127.0.0.1:p1` + `127.0.0.1:p2`, where `registrableApex` is null)
 *     - Multi-vhost domains on distinct apexes resolving to one IP (`alpha.site-one.test` + `beta.site-two.test`).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { startPoliteTargetServer } from '../local-lab/polite-target/server.ts'
import {
  BrokerCircuitOpen,
  EXTERNAL_ORIGIN_MAX_IN_FLIGHT,
  RequestBroker,
} from '../src/server/broker.ts'
import type { BrokerLoadEvent, Grant } from '../src/server/broker.ts'
import type { SecondOrderStore } from '../src/server/canary-broker.ts'
import { RequestAdmissionEngine } from '../src/server/request-admission.ts'
import {
  classifyTargetClass,
  classifyTargetLoadStatus,
  normalizeIpBucketKey,
  ORIGIN_DOWN_HTTP_STATUSES,
  PROBE_INDUCED_EXEMPT_HTTP_STATUSES,
  resolveRunSafetyBudgets,
  resolveTargetLoadPolicy,
  RUN_SAFETY_BUDGET_DEFAULTS,
  TARGET_LOAD_POLICY_DEFAULTS,
  THROTTLED_HTTP_STATUSES,
} from '../src/server/run-safety-budgets.ts'
import type { TargetClass } from '../src/server/target-load-policy.ts'

function makeLocalAdmissionEngine(): RequestAdmissionEngine {
  // Scoped engine allows loopback dialing cleanly WITHOUT mutating process.env.KOVO_ALLOW_LOCAL_LAB.
  return new RequestAdmissionEngine({ env: { KOVO_ALLOW_LOCAL_LAB: '1' } })
}

function makeRecordingEventStore() {
  const events: Array<{ runId: string | null; kind: string; message: string; detail?: Record<string, unknown> }> = []
  const store: SecondOrderStore = {
    insertSecondOrderCanary: () => { throw new Error('unused') },
    markSecondOrderCanarySurfaced: () => { throw new Error('unused') },
    listSecondOrderCanaries: () => [],
    event: (runId, kind, message, detail) => {
      events.push({ runId, kind, message, detail })
    },
  }
  return { store, events }
}

function makeLoopbackGrant(
  origins: readonly string[],
  overrides: Partial<Grant> = {},
): Grant {
  const allowed = new Set(origins)
  return {
    origin: origins[0],
    tier: 2,
    allowLocalLab: true,
    maxRpsPerOrigin: 50,
    canRead: candidate => allowed.has(candidate),
    audit: () => {},
    ...overrides,
  }
}

test('R2-16.1: TargetLoadPolicy snapshot, unified HTTP status taxonomy, and IP normalization are authoritative and value-preserving', () => {
  // 1. Unified HTTP status taxonomy: origin_down (502-504, 520-526) vs throttled (429) vs transient (500/501/etc.)
  for (const code of [502, 503, 504, 520, 521, 522, 523, 524, 525, 526]) {
    assert.equal(classifyTargetLoadStatus(code), 'origin_down', `HTTP ${code} must classify as origin_down`)
    assert.equal(ORIGIN_DOWN_HTTP_STATUSES.has(code), true)
    assert.equal(PROBE_INDUCED_EXEMPT_HTTP_STATUSES.has(code), false, `origin_down ${code} must NEVER be probe-exempt`)
  }
  assert.equal(classifyTargetLoadStatus(429), 'throttled')
  assert.equal(THROTTLED_HTTP_STATUSES.has(429), true)
  for (const code of [500, 501, 505, 507, 511, 527]) {
    assert.equal(classifyTargetLoadStatus(code), 'transient', `HTTP ${code} must classify as transient`)
  }
  for (const code of [400, 401, 403, 404, 422]) {
    assert.equal(classifyTargetLoadStatus(code), 'client_error', `HTTP ${code} must classify as client_error`)
  }
  for (const code of [200, 201, 204, 301, 302]) {
    assert.equal(classifyTargetLoadStatus(code), 'healthy', `HTTP ${code} must classify as healthy`)
  }

  // 2. Existing WS-9 RunSafetyBudgets defaults remain completely untouched.
  assert.deepEqual(resolveRunSafetyBudgets({ env: {} }), RUN_SAFETY_BUDGET_DEFAULTS)

  // 3. Value-preserving TargetLoadPolicy defaults & effective origin snapshot
  const localSnap = resolveTargetLoadPolicy({
    env: {},
    origins: ['http://127.0.0.1:8080', 'https://app.example.test'],
    allowLocalLab: true,
    requestedMaxRpsPerOrigin: 50,
  })
  assert.equal(localSnap.broker.externalOriginMaxInFlight, 4)
  assert.equal(localSnap.broker.loopbackOriginMaxInFlight, 12)
  assert.equal(localSnap.broker.externalOriginMaxRps, 20)
  assert.equal(localSnap.broker.loopbackOriginMaxRps, 100)
  assert.equal(localSnap.broker.externalApexMaxRps, 45)
  assert.equal(localSnap.broker.externalIpMaxRps, 45)
  assert.equal(localSnap.broker.externalIpMaxInFlight, 8)
  assert.equal(localSnap.lanes.phase0OriginConcurrency, 6)
  assert.equal(localSnap.lanes.phase0BrowserConcurrency, 3)
  assert.equal(localSnap.lanes.baselineCaptureConcurrency, 6)
  assert.equal(localSnap.lanes.phaseBAimdWarmStart, 6)

  const loopbackEntry = localSnap.origins[0]!
  assert.equal(loopbackEntry.targetClass, 'loopback')
  assert.equal(loopbackEntry.maxInFlight, 12)
  assert.equal(loopbackEntry.maxRps, 50)
  assert.equal(loopbackEntry.apexBucketKey, null)
  assert.equal(loopbackEntry.ipBucketKey, null)
  assert.equal(loopbackEntry.aggregateMaxRps, null)

  // 4. Forcing TargetClass='external' on loopback applies external caps and IP-literal bucket key
  const forcedSnap = resolveTargetLoadPolicy({
    env: {},
    origins: ['http://127.0.0.1:8080', 'http://vhost-a.polite.test:8080'],
    allowLocalLab: true,
    targetClassOverride: 'external',
    requestedMaxRpsPerOrigin: 50,
  })
  assert.equal(forcedSnap.targetClassOverride, 'external')
  assert.equal(forcedSnap.origins[0]!.targetClass, 'external')
  assert.equal(forcedSnap.origins[0]!.maxInFlight, TARGET_LOAD_POLICY_DEFAULTS.externalOriginMaxInFlight)
  assert.equal(forcedSnap.origins[0]!.maxRps, TARGET_LOAD_POLICY_DEFAULTS.externalOriginMaxRps)
  assert.equal(forcedSnap.origins[0]!.apexBucketKey, null)
  assert.equal(forcedSnap.origins[0]!.ipBucketKey, '127.0.0.1')
  assert.equal(forcedSnap.origins[0]!.aggregateMaxRps, 45)
  assert.equal(forcedSnap.origins[1]!.apexBucketKey, 'polite.test')

  // 5. TargetClass classifier & IPv4-mapped IPv6 normalization
  assert.equal(classifyTargetClass('http://127.0.0.1:9000'), 'loopback')
  assert.equal(classifyTargetClass('http://127.0.0.1:9000', { targetClassOverride: 'external' }), 'external')
  assert.equal(normalizeIpBucketKey('127.0.0.1'), '127.0.0.1')
  assert.equal(normalizeIpBucketKey('::ffff:127.0.0.1'), '127.0.0.1')
  assert.equal(normalizeIpBucketKey('[::1]'), '::1')
  assert.equal(normalizeIpBucketKey('not-an-ip'), null)
})

test('R2-16.2: polite-target honors 429 Retry-After, halves/recovers adaptiveRps, trips 429 breaker, and emits structured telemetry without toggling env flags', async t => {
  const envBefore = process.env.KOVO_ALLOW_LOCAL_LAB
  const fixture = await startPoliteTargetServer()
  t.after(() => fixture.close())

  const { store, events: storeEvents } = makeRecordingEventStore()
  const callbackEvents: BrokerLoadEvent[] = []
  const broker = new RequestBroker({
    admissionEngine: makeLocalAdmissionEngine(),
    storage: store,
    targetClassOverride: 'external',
    circuit429Threshold: 3,
    circuitBackoffBaseMs: 200,
    onLoadEvent: evt => callbackEvents.push(evt),
  })
  t.after(() => broker.closeTransport())

  const grant = makeLoopbackGrant([fixture.origin], { maxRpsPerOrigin: 20, storage: store })
  const snap = broker.resolveEffectiveLoadPolicy({ origins: [fixture.origin], grant })
  assert.equal(snap.origins[0]?.targetClass, 'external')
  assert.equal(snap.origins[0]?.maxInFlight, 4)
  assert.equal(snap.origins[0]?.maxRps, 20)

  const signal = AbortSignal.timeout(10_000)

  // 1. First request hits 429 with Retry-After: 1
  const first = await broker.executeHttp(
    { origin: fixture.origin, method: 'GET', pathAndQuery: '/throttle/once?retryAfter=1&key=ra', runId: 'run-polite-429' },
    grant,
    signal,
  )
  assert.equal(first.status, 429)
  const stateAfter429 = broker.getCircuitState(fixture.origin)
  assert.equal(stateAfter429.errors429, 1)
  assert.equal(stateAfter429.adaptiveRps, 10, '429 must halve configured external RPS (20 -> 10)')
  assert.ok(stateAfter429.retryAfterUntil !== null && stateAfter429.retryAfterUntil > Date.now(), 'Retry-After deadline must be recorded')

  const throttleCb = callbackEvents.find(e => e.kind === 'broker.target_throttled')
  assert.ok(throttleCb, 'onLoadEvent must receive broker.target_throttled')
  assert.equal(throttleCb.targetClass, 'external')
  assert.equal(throttleCb.status, 429)
  assert.equal(throttleCb.statusClass, 'throttled')
  assert.equal(throttleCb.retryAfterSec, 1)
  assert.equal(throttleCb.adaptiveRps, 10)
  assert.ok(
    storeEvents.some(e => e.kind === 'broker.target_throttled' && e.runId === 'run-polite-429' && e.detail?.retryAfterSec === 1),
    'store.event must persist structured broker.target_throttled telemetry',
  )

  // 2. Follow-up request honors Retry-After (~1s) before hitting server, then recovers adaptiveRps (+1) on 200
  const retryStart = Date.now()
  const second = await broker.executeHttp(
    { origin: fixture.origin, method: 'GET', pathAndQuery: '/throttle/once?retryAfter=1&key=ra', runId: 'run-polite-429' },
    grant,
    signal,
  )
  const retryElapsedMs = Date.now() - retryStart
  assert.equal(second.status, 200)
  assert.ok(retryElapsedMs >= 850, `expected Retry-After: 1 to pace follow-up >= 850ms, got ${retryElapsedMs}ms`)
  assert.equal(broker.getCircuitState(fixture.origin).adaptiveRps, 11, 'healthy 200 recovers adaptiveRps (+1)')

  // 3. Sustained 429 burst trips the origin breaker at circuit429Threshold=3 and emits broker.origin_breaker_open
  const third = await broker.executeHttp(
    { origin: fixture.origin, method: 'GET', pathAndQuery: '/throttle/always?retryAfter=0', runId: 'run-polite-429' },
    grant,
    signal,
  )
  assert.equal(third.status, 429)
  await assert.rejects(
    () => broker.executeHttp(
      { origin: fixture.origin, method: 'GET', pathAndQuery: '/throttle/always?retryAfter=0', runId: 'run-polite-429' },
      grant,
      signal,
    ),
    (err: unknown) => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(fixture.origin), true)
  const openEvent = callbackEvents.find(e => e.kind === 'broker.origin_breaker_open' && e.status === 429)
  assert.ok(openEvent, '429 breaker trip must emit broker.origin_breaker_open telemetry')
  assert.equal(openEvent.statusClass, 'throttled')
  assert.equal(openEvent.targetClass, 'external')

  assert.equal(process.env.KOVO_ALLOW_LOCAL_LAB, envBefore, 'process.env.KOVO_ALLOW_LOCAL_LAB must never be mutated')
})

test('R2-16.3: polite-target 503 and Cloudflare 52x bursts open origin breaker under active probeClass while plain 500 stays transient/route-scoped', async t => {
  const envBefore = process.env.KOVO_ALLOW_LOCAL_LAB
  const fixture = await startPoliteTargetServer()
  t.after(() => fixture.close())

  const { store, events: storeEvents } = makeRecordingEventStore()
  const callbackEvents: BrokerLoadEvent[] = []
  const broker = new RequestBroker({
    admissionEngine: makeLocalAdmissionEngine(),
    storage: store,
    targetClassOverride: 'external',
    circuit5xxThreshold: 2,
    circuitBackoffBaseMs: 250,
    onLoadEvent: evt => callbackEvents.push(evt),
  })
  t.after(() => broker.closeTransport())

  const grant = makeLoopbackGrant([fixture.origin], { storage: store })
  const signal = AbortSignal.timeout(10_000)

  // 1. Plain 500 under error-inducing probeClass is transient evidence and does NOT open origin breaker.
  for (let i = 0; i < 3; i += 1) {
    const res = await broker.executeHttp(
      { origin: fixture.origin, method: 'GET', pathAndQuery: '/transient/500', probeClass: 'sqli_boolean', runId: 'run-polite-52x' },
      grant,
      signal,
    )
    assert.equal(res.status, 500)
  }
  assert.equal(broker.isCircuitOpen(fixture.origin), false)
  assert.equal(broker.getCircuitState(fixture.origin).probeInduced5xx, 3)
  assert.equal(broker.getCircuitState(fixture.origin).failures5xx, 0)

  // 2. Cloudflare 522 + 525 burst under active injection probeClass MUST open the origin breaker!
  const first522 = await broker.executeHttp(
    { origin: fixture.origin, method: 'GET', pathAndQuery: '/edge-down/522', probeClass: 'sqli_boolean', runId: 'run-polite-52x' },
    grant,
    signal,
  )
  assert.equal(first522.status, 522)
  assert.equal(broker.isCircuitOpen(fixture.origin), false)

  await assert.rejects(
    () => broker.executeHttp(
      { origin: fixture.origin, method: 'GET', pathAndQuery: '/edge-down/525', probeClass: 'ssti_math', runId: 'run-polite-52x' },
      grant,
      signal,
    ),
    (err: unknown) => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(fixture.origin), true)
  const state = broker.getCircuitState(fixture.origin)
  assert.equal(state.failures5xx, 2)
  assert.equal(state.probeInduced5xx, 3, '522/525 must NEVER be counted as probeInduced5xx')

  const openEvt = callbackEvents.find(e => e.kind === 'broker.origin_breaker_open')
  assert.ok(openEvt, '52x origin-down trip must emit broker.origin_breaker_open')
  assert.equal(openEvt.status, 525)
  assert.equal(openEvt.statusClass, 'origin_down')
  assert.equal(openEvt.targetClass, 'external')
  assert.ok(
    storeEvents.some(e => e.kind === 'broker.origin_breaker_open' && e.detail?.statusClass === 'origin_down'),
    'store.event must persist broker.origin_breaker_open telemetry',
  )

  // 3. Reset and verify 503 burst also opens origin breaker with statusClass='origin_down'
  broker.resetCircuit(fixture.origin)
  const first503 = await broker.executeHttp(
    { origin: fixture.origin, method: 'GET', pathAndQuery: '/edge-down/503', probeClass: 'xxe_canary', runId: 'run-polite-52x' },
    grant,
    signal,
  )
  assert.equal(first503.status, 503)
  await assert.rejects(
    () => broker.executeHttp(
      { origin: fixture.origin, method: 'GET', pathAndQuery: '/edge-down/503', probeClass: 'xxe_canary', runId: 'run-polite-52x' },
      grant,
      signal,
    ),
    (err: unknown) => err instanceof BrokerCircuitOpen,
  )
  assert.equal(broker.isCircuitOpen(fixture.origin), true)
  assert.ok(callbackEvents.some(e => e.kind === 'broker.origin_breaker_open' && e.status === 503 && e.statusClass === 'origin_down'))

  assert.equal(process.env.KOVO_ALLOW_LOCAL_LAB, envBefore, 'process.env.KOVO_ALLOW_LOCAL_LAB must never be mutated')
})

test('R2-16.4: per-IP aggregate RPS & concurrency buckets cap IP-literal multi-port and multi-vhost loopback targets under external TargetClass', async t => {
  const envBefore = process.env.KOVO_ALLOW_LOCAL_LAB
  const serverA = await startPoliteTargetServer()
  const serverB = await startPoliteTargetServer()
  t.after(async () => {
    await Promise.all([serverA.close(), serverB.close()])
  })

  // (a) Multi-port IP-literal origins (`127.0.0.1:p1` + `127.0.0.1:p2`, registrableApex === null)
  //     Use Grant-level targetClassOverride: 'external' to prove grant-level forcing works too!
  const ipEvents: BrokerLoadEvent[] = []
  const ipBroker = new RequestBroker({
    admissionEngine: makeLocalAdmissionEngine(),
    externalIpMaxRps: 6,
    externalIpMaxInFlight: 3,
    onLoadEvent: evt => ipEvents.push(evt),
  })
  t.after(() => ipBroker.closeTransport())

  const ipOrigins = [serverA.origin, serverB.origin]
  const forcedTargetClass: TargetClass = 'external'
  const ipGrant = makeLoopbackGrant(ipOrigins, {
    maxRpsPerOrigin: 20,
    targetClassOverride: forcedTargetClass,
  })
  const signal = AbortSignal.timeout(10_000)

  const ipStart = Date.now()
  await Promise.all(
    Array.from({ length: 12 }, (_, idx) =>
      ipBroker.executeHttp(
        { origin: ipOrigins[idx % ipOrigins.length]!, method: 'GET', pathAndQuery: `/health?i=${idx}`, runId: 'run-ip-multiport' },
        ipGrant,
        signal,
      ),
    ),
  )
  const ipElapsedMs = Date.now() - ipStart
  // 12 requests at 6 req/s aggregate (burst 6) requires (12 - 6) / 6 = 1.0s
  assert.ok(
    ipElapsedMs >= 800,
    `expected per-IP aggregate RPS cap (6 req/s across 2 ports) to pace 12 reqs >= 800ms, got ${ipElapsedMs}ms`,
  )
  assert.equal(ipBroker.getApexBucketCount(), 0, 'IP-literal origins have null registrableApex and must not create apex buckets')
  assert.equal(ipBroker.getIpBucketCount(), 1, 'both ports on 127.0.0.1 must share ONE per-IP aggregate bucket')
  assert.equal(ipBroker.getIpInFlight('127.0.0.1'), 0, 'all per-IP in-flight slots must release cleanly')
  assert.ok(
    ipEvents.some(e => e.kind === 'broker.aggregate_cap_wait' && e.bucketKind === 'ip' && e.bucketKey === '127.0.0.1'),
    'per-IP aggregate pacing must emit broker.aggregate_cap_wait telemetry',
  )
  ipBroker.disposeRun('run-ip-multiport')
  assert.equal(ipBroker.getIpBucketCount(), 0, 'disposeRun must release unreferenced per-IP buckets cleanly')

  // (b) Multi-vhost origins on DIFFERENT registrable apexes resolving to ONE loopback IP (127.0.0.1):
  //     externalIpMaxInFlight=3 bounds aggregate concurrency across BOTH vhosts, and single-origin
  //     concurrency remains capped at EXTERNAL_ORIGIN_MAX_IN_FLIGHT (4) even on loopback!
  serverA.resetStats()
  const vhostOrigins = [
    `http://alpha.site-one.test:${serverA.port}`,
    `http://beta.site-two.test:${serverA.port}`,
  ]
  const vhostBroker = new RequestBroker({
    admissionEngine: makeLocalAdmissionEngine(),
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
    targetClassOverride: 'external',
    externalIpMaxInFlight: 3,
    externalIpMaxRps: 40,
  })
  t.after(() => vhostBroker.closeTransport())

  const vhostGrant = makeLoopbackGrant(vhostOrigins, { maxRpsPerOrigin: 20 })
  await Promise.all(
    Array.from({ length: 10 }, (_, idx) =>
      vhostBroker.executeHttp(
        { origin: vhostOrigins[idx % vhostOrigins.length]!, method: 'GET', pathAndQuery: '/slow?delayMs=80', runId: 'run-ip-vhost' },
        vhostGrant,
        signal,
      ),
    ),
  )
  const vhostStats = serverA.getStats()
  assert.equal(vhostStats.totalRequests, 10)
  assert.equal(vhostStats.requestsByHost['alpha.site-one.test'], 5)
  assert.equal(vhostStats.requestsByHost['beta.site-two.test'], 5)
  assert.ok(
    vhostStats.peakInFlight <= 3,
    `expected per-IP aggregate concurrency cap (3) across distinct apex vhosts on 127.0.0.1, got peakInFlight=${vhostStats.peakInFlight}`,
  )
  assert.equal(vhostBroker.getApexBucketCount(), 2, 'distinct apexes create 2 apex buckets')
  assert.equal(vhostBroker.getIpBucketCount(), 1, 'both distinct apex vhosts share ONE per-IP bucket (127.0.0.1)')
  vhostBroker.disposeRun('run-ip-vhost')
  assert.equal(vhostBroker.getApexBucketCount(), 0)
  assert.equal(vhostBroker.getIpBucketCount(), 0)

  // (c) Single loopback origin forced to external TargetClass enforces EXTERNAL_ORIGIN_MAX_IN_FLIGHT (4), not 12!
  serverA.resetStats()
  const singleOriginBroker = new RequestBroker({
    admissionEngine: makeLocalAdmissionEngine(),
    targetClassOverride: 'external',
    externalIpMaxInFlight: 12,
    externalIpMaxRps: 40,
  })
  t.after(() => singleOriginBroker.closeTransport())
  const singleGrant = makeLoopbackGrant([serverA.origin], { maxRpsPerOrigin: 20 })
  await Promise.all(
    Array.from({ length: 8 }, () =>
      singleOriginBroker.executeHttp(
        { origin: serverA.origin, method: 'GET', pathAndQuery: '/slow?delayMs=80', runId: 'run-single-ext' },
        singleGrant,
        signal,
      ),
    ),
  )
  const singleStats = serverA.getStats()
  assert.equal(singleStats.totalRequests, 8)
  assert.ok(
    singleStats.peakInFlight <= EXTERNAL_ORIGIN_MAX_IN_FLIGHT,
    `forced external TargetClass on loopback must cap per-origin concurrency at ${EXTERNAL_ORIGIN_MAX_IN_FLIGHT}, got ${singleStats.peakInFlight}`,
  )

  assert.equal(process.env.KOVO_ALLOW_LOCAL_LAB, envBefore, 'process.env.KOVO_ALLOW_LOCAL_LAB must never be mutated')
})
