process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * WS-9 (`R4-H-19` + shared `RunSafetyBudgets` keys for WS-10, WS-11, WS-14) class-level guards:
 *  1. 10,000 rotating-cookie + rotating-CSRF responses through one jar in `RequestBroker`
 *     keep succeeding with ZERO `RedactionCapacityError`, flat active registry size, and
 *     active secret redaction intact (including rotating across distinct paths and deletions).
 *  2. Shared/cloned jar reference counting & pinned secrets: rotating a secret in a `probe`
 *     jar never unregisters a value still held by the `setup` jar or a pinned secret.
 *  3. Fail-closed BEFORE sending placement invariant:
 *     - Once genuinely full of distinct non-superseded active secrets, mutating requests
 *       throw `RedactionCapacityError` BEFORE any bytes hit the wire (`transportCalls === 0`).
 *     - If a mutating request sent with remaining headroom receives a multi-cookie response
 *       that saturates capacity post-send, evidence of the already-sent mutation is preserved
 *       (never thrown away), the overflowing secret is still scrubbed from that response,
 *       structured capacity telemetry is emitted, and the NEXT request fails closed pre-send
 *       with zero wire sends.
 *  4. `resolveRunSafetyBudgets(...)` exposes finite positive workload-scaled values and hard
 *     OOM ceilings for `maxRedactedSecretsPerRun`, WS-10 origin quarantine thresholds,
 *     WS-11 `search_repo` deadline/byte budgets, and WS-14 OOB callback quotas.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  DEFAULT_MAX_REDACTED_SECRETS_PER_RUN,
  HARD_MAX_REDACTED_SECRETS_PER_RUN,
  RedactionCapacityError,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse } from '../src/server/broker.ts'
import type { SecondOrderStore } from '../src/server/canary-broker.ts'
import {
  RUN_SAFETY_BUDGET_DEFAULTS,
  RUN_SAFETY_BUDGET_ENV_KEYS,
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
  resolveRunSafetyBudgets,
} from '../src/server/run-safety-budgets.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'

const APP_ORIGIN = 'https://app.r4-budgets.test'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeScopePolicy(runId: string): ScopePolicy {
  return {
    runId,
    mode: 'staging_isolated',
    tenantTag: `kovo-qa-${runId}-`,
    targetOrigins: [APP_ORIGIN],
  }
}

function makeGrant(options: { runId: string; storage?: SecondOrderStore }): Grant {
  return {
    origin: APP_ORIGIN,
    tier: 3,
    maxRpsPerOrigin: 100_000,
    canRead: (o: string) => o === APP_ORIGIN,
    isStateChangeApproved: () => true,
    audit: () => {},
    scopePolicy: makeScopePolicy(options.runId),
    ...(options.storage ? { storage: options.storage } : {}),
  }
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

test('R4-H-19.1: 10,000 rotating-cookie + rotating-CSRF responses through one jar succeed with flat registry size and active redaction', async () => {
  const { store, events } = makeRecordingEventStore()
  const TOTAL_ROTATIONS = 10_000
  let seq = 0
  let prevSid = ''
  let prevCsrf = ''

  const transport = async (): Promise<RawHttpResponse> => {
    seq += 1
    const sid = `rot_sid_${String(seq).padStart(6, '0')}_secret`
    const csrf = `rot_csrf_${String(seq).padStart(6, '0')}_token`
    // Echo BOTH current and previous tokens in body to verify zero leak even during rotation.
    const body = `ok seq=${seq} cur=${sid} csrf=${csrf} prev=${prevSid} prevCsrf=${prevCsrf}`
    prevSid = sid
    prevCsrf = csrf
    return {
      status: 200,
      headers: {
        'content-type': 'text/plain',
        'set-cookie': [`session_id=${sid}; Path=/; HttpOnly`],
        'x-csrf-token': csrf,
      },
      body,
      bodyBytes: Buffer.byteLength(body),
    }
  }

  // Deliberately tight cap (16) far below 10,000 to prove lifecycle-aware slot reuse rather than large-cap masking.
  // Use RequestBroker's injectable clock (`now`) so all 10,000 exchanges execute through the real rate-limited
  // `executeHttp` pipeline without real wall-clock sleep.
  let fakeNow = Date.now()
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport,
    storage: store,
    maxRedactedSecretsPerRun: 16,
    now: () => fakeNow,
  })
  const grant = makeGrant({ runId: 'run-rot-10k', storage: store })
  const signal = AbortSignal.timeout(30_000)

  let maxObservedActive = 0
  let lastBody = ''
  for (let i = 1; i <= TOTAL_ROTATIONS; i += 1) {
    fakeNow += 1_000
    // Alternate GET and POST to verify rotating responses keep succeeding across both read and mutating traffic.
    const method = i % 5 === 0 ? 'POST' : 'GET'
    const res = await broker.executeHttp(
      {
        origin: APP_ORIGIN,
        method,
        pathAndQuery: '/kovo-qa-run-rot-10k-account/profile',
        ...(method === 'POST'
          ? { headers: { 'content-type': 'application/json' }, body: '{"tenant":"kovo-qa-run-rot-10k-item","ok":true}' }
          : {}),
        runId: 'run-rot-10k',
        session: 'main',
      },
      grant,
      signal,
    )
    lastBody = res.body
    if (i === 1 || i === 5000 || i === TOTAL_ROTATIONS) {
      const activeCount = broker.getRunStateCounts('run-rot-10k').redactedSecrets
      if (activeCount > maxObservedActive) maxObservedActive = activeCount
      assert.ok(!res.body.includes(`rot_sid_${String(i).padStart(6, '0')}_secret`), `iteration ${i} must redact active session cookie`)
      assert.ok(!res.body.includes(`rot_csrf_${String(i).padStart(6, '0')}_token`), `iteration ${i} must redact active CSRF token`)
      if (i > 1) {
        assert.ok(
          !res.body.includes(`rot_sid_${String(i - 1).padStart(6, '0')}_secret`),
          `iteration ${i} must still redact just-superseded session cookie on the rotation response`,
        )
      }
    }
  }

  assert.equal(seq, TOTAL_ROTATIONS)
  assert.equal(events.filter(e => e.kind === 'broker.redaction_capacity_exceeded').length, 0)
  assert.equal(broker.getRunStateCounts('run-rot-10k').redactedSecrets, 2, 'only the 2 active slots (session cookie + CSRF) remain registered')
  assert.ok(maxObservedActive <= 2, `active secret registry stayed flat (max=${maxObservedActive})`)

  const registeredValues = new Set(broker.getRegisteredSecrets('run-rot-10k').map(s => s.value))
  assert.ok(registeredValues.has('rot_sid_010000_secret'), 'latest session cookie must stay registered')
  assert.ok(registeredValues.has('rot_csrf_010000_token'), 'latest CSRF token must stay registered')
  assert.ok(!registeredValues.has('rot_sid_000001_secret'), 'superseded session cookie must be unregistered')
  assert.ok(!registeredValues.has('rot_csrf_000001_token'), 'superseded CSRF token must be unregistered')
  assert.ok(!lastBody.includes('rot_sid_010000_secret'))
  assert.ok(!lastBody.includes('rot_csrf_010000_token'))

  // Explicit cookie deletion (Max-Age=0) also releases the secret slot cleanly.
  const delBroker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (url) => ({
      status: 200,
      headers: {
        'content-type': 'text/plain',
        'set-cookie': url.pathname === '/logout'
          ? ['session_id=; Path=/; Max-Age=0']
          : ['session_id=temp_del_secret_9999; Path=/'],
      },
      body: 'ok temp_del_secret_9999',
      bodyBytes: 23,
    }),
    maxRedactedSecretsPerRun: 8,
  })
  const delGrant = makeGrant({ runId: 'run-del' })
  await delBroker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/login', runId: 'run-del', session: 's1' }, delGrant, signal)
  assert.equal(delBroker.getRunStateCounts('run-del').redactedSecrets, 1)
  const logoutRes = await delBroker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/logout', runId: 'run-del', session: 's1' }, delGrant, signal)
  assert.ok(!logoutRes.body.includes('temp_del_secret_9999'), 'deleted cookie still scrubbed on logout response itself')
  assert.equal(delBroker.getRunStateCounts('run-del').redactedSecrets, 0, 'deleted cookie unregistered after logout')
})

test('R4-H-19.2: shared/cloned jar reference counting preserves setup jar secrets when probe jar rotates', async () => {
  let reqNum = 0
  const transport = async (url: URL): Promise<RawHttpResponse> => {
    reqNum += 1
    if (url.pathname === '/setup') {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain', 'set-cookie': ['sid=setup_shared_secret_0001; Path=/'] },
        body: 'setup setup_shared_secret_0001',
        bodyBytes: 30,
      }
    }
    return {
      status: 200,
      headers: { 'content-type': 'text/plain', 'set-cookie': [`sid=probe_rotated_secret_${reqNum}; Path=/`] },
      body: `probe setup_shared_secret_0001 probe_rotated_secret_${reqNum}`,
      bodyBytes: 60,
    }
  }
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport,
    maxRedactedSecretsPerRun: 8,
  })
  const grant = makeGrant({ runId: 'run-refcount' })
  const signal = AbortSignal.timeout(10_000)

  // Setup jar receives initial secret
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/setup', runId: 'run-refcount', assignmentId: 'a1', sessionGroupRole: 'setup', session: 's1' },
    grant,
    signal,
  )
  assert.equal(broker.getRunStateCounts('run-refcount').redactedSecrets, 1)

  // Probe jar clones setup jar and rotates its cookie -> setup jar's secret MUST remain registered (refCount=1)!
  const probeRes = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/probe', runId: 'run-refcount', assignmentId: 'a1', sessionGroupRole: 'probe', session: 's1' },
    grant,
    signal,
  )
  assert.ok(!probeRes.body.includes('setup_shared_secret_0001'))
  assert.ok(!probeRes.body.includes('probe_rotated_secret_2'))
  const values = new Set(broker.getRegisteredSecrets('run-refcount').map(s => s.value))
  assert.ok(values.has('setup_shared_secret_0001'), 'setup jar still owns setup_shared_secret_0001')
  assert.ok(values.has('probe_rotated_secret_2'), 'probe jar owns rotated secret')
  assert.equal(values.size, 2)

  // Further probe rotation replaces only probe's secret, keeping setup's secret intact
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/probe', runId: 'run-refcount', assignmentId: 'a1', sessionGroupRole: 'probe', session: 's1' },
    grant,
    signal,
  )
  const valuesAfter = new Set(broker.getRegisteredSecrets('run-refcount').map(s => s.value))
  assert.ok(valuesAfter.has('setup_shared_secret_0001'))
  assert.ok(valuesAfter.has('probe_rotated_secret_3'))
  assert.ok(!valuesAfter.has('probe_rotated_secret_2'))
  assert.equal(valuesAfter.size, 2)
})

test('R4-H-19.3: genuine cap overflow fails closed BEFORE sending on mutating requests and never discards already-sent mutation evidence', async () => {
  const { store, events } = makeRecordingEventStore()
  let transportCalls = 0

  const transport = async (url: URL): Promise<RawHttpResponse> => {
    transportCalls += 1
    if (url.pathname === '/fill-1') {
      return { status: 200, headers: { 'set-cookie': ['c1=distinct_secret_0001; Path=/'] }, body: 'ok', bodyBytes: 2 }
    }
    if (url.pathname === '/fill-2') {
      return { status: 200, headers: { 'set-cookie': ['c2=distinct_secret_0002; Path=/'] }, body: 'ok', bodyBytes: 2 }
    }
    if (url.pathname === '/fill-3') {
      return { status: 200, headers: { 'set-cookie': ['c3=distinct_secret_0003; Path=/'] }, body: 'ok', bodyBytes: 2 }
    }
    if (url.pathname === '/kovo-qa-run-cap-burst-mutate') {
      // Returns 2 distinct new cookies when only 1 slot remained (2 -> 3 fits, 4th overflows post-send).
      return {
        status: 201,
        headers: {
          'content-type': 'application/json',
          'set-cookie': [
            'c3=distinct_secret_0003; Path=/',
            'c4=distinct_secret_OVERFLOW_0004; Path=/',
          ],
        },
        body: '{"created":true,"leaked":"distinct_secret_OVERFLOW_0004"}',
        bodyBytes: 57,
      }
    }
    return { status: 200, headers: {}, body: 'should-not-hit-wire', bodyBytes: 19 }
  }

  // Case A: Registry already full (3/3 distinct active cookies) -> mutating POST MUST fail closed BEFORE sending!
  const brokerFull = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport,
    storage: store,
    maxRedactedSecretsPerRun: 3,
  })
  const grantA = makeGrant({ runId: 'run-cap-presend', storage: store })
  const signal = AbortSignal.timeout(10_000)

  for (const path of ['/fill-1', '/fill-2', '/fill-3']) {
    await brokerFull.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: path, runId: 'run-cap-presend', session: 's1' }, grantA, signal)
  }
  assert.equal(brokerFull.getRunStateCounts('run-cap-presend').redactedSecrets, 3)
  const callsBeforeMutate = transportCalls

  await assert.rejects(
    () => brokerFull.executeHttp(
      {
        origin: APP_ORIGIN,
        method: 'POST',
        pathAndQuery: '/kovo-qa-run-cap-presend-transfer',
        headers: { 'content-type': 'application/json' },
        body: '{"tenant":"kovo-qa-run-cap-presend-item","amount":100}',
        runId: 'run-cap-presend',
        session: 's1',
      },
      grantA,
      signal,
    ),
    (err: unknown) => {
      assert.ok(err instanceof RedactionCapacityError)
      assert.equal(err.runId, 'run-cap-presend')
      assert.equal(err.cap, 3)
      assert.equal(err.activeCount, 3)
      return true
    },
  )
  assert.equal(transportCalls, callsBeforeMutate, 'ZERO wire sends allowed once redaction cap is full for a mutating request')
  const preSendEvent = events.find(e => e.kind === 'broker.redaction_capacity_exceeded' && e.detail?.phase === 'pre_send')
  assert.ok(preSendEvent, 'pre-send denial must emit structured broker.redaction_capacity_exceeded telemetry')

  // Case B: Mutating POST sent with headroom (2/3) receives 2 new cookies -> evidence is preserved + scrubbed,
  //         overflowing cookie is NOT persisted, and the NEXT request fails closed BEFORE sending (0 wire sends)!
  const brokerBurst = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport,
    storage: store,
    maxRedactedSecretsPerRun: 3,
  })
  const grantB = makeGrant({ runId: 'run-cap-burst', storage: store })
  for (const path of ['/fill-1', '/fill-2']) {
    await brokerBurst.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: path, runId: 'run-cap-burst', session: 's1' }, grantB, signal)
  }
  const burstRes = await brokerBurst.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/kovo-qa-run-cap-burst-mutate',
      headers: { 'content-type': 'application/json' },
      body: '{"tenant":"kovo-qa-run-cap-burst-item","action":"create"}',
      runId: 'run-cap-burst',
      session: 's1',
    },
    grantB,
    signal,
  )
  assert.equal(burstRes.status, 201, 'evidence of already-sent mutating POST must NEVER be discarded')
  assert.ok(!burstRes.body.includes('distinct_secret_OVERFLOW_0004'), 'overflowing secret must STILL be scrubbed from the response')
  assert.equal(brokerBurst.getRunStateCounts('run-cap-burst').redactedSecrets, 3)

  const callsAfterBurst = transportCalls
  await assert.rejects(
    () => brokerBurst.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/after-saturation', runId: 'run-cap-burst', session: 's1' },
      grantB,
      signal,
    ),
    RedactionCapacityError,
  )
  assert.equal(transportCalls, callsAfterBurst, 'next exchange after saturation MUST fail closed pre-send with zero wire send')
})

test('R4-H-19.4: resolveRunSafetyBudgets exposes workload-scaled finite caps & hard ceilings for WS-9, WS-10, WS-11, and WS-14', () => {
  const defaults = resolveRunSafetyBudgets({ env: {} })
  assert.deepEqual(defaults, RUN_SAFETY_BUDGET_DEFAULTS)

  // WS-9 (R4-H-19): broker redaction cap synced with RunSafetyBudgets
  assert.equal(defaults.maxRedactedSecretsPerRun, DEFAULT_MAX_REDACTED_SECRETS_PER_RUN)
  assert.equal(RUN_SAFETY_BUDGET_HARD_CEILINGS.maxRedactedSecretsPerRun, HARD_MAX_REDACTED_SECRETS_PER_RUN)
  assert.ok(defaults.maxRedactedSecretsPerRun > 0)

  // WS-10 (R4-H-11): per-origin quarantine thresholds
  assert.ok(defaults.originQuarantineMin52xCount >= 3)
  assert.ok(defaults.originQuarantineMin401Count >= 3)
  assert.ok(defaults.originQuarantineMinDistinctPaths >= 2)
  assert.ok(defaults.originQuarantineWindowMs >= 60_000)

  // WS-11 (R4-H-15): host search_repo deadline & byte budget
  assert.ok(defaults.searchRepoDeadlineMs > 0 && defaults.searchRepoDeadlineMs <= RUN_SAFETY_BUDGET_HARD_CEILINGS.searchRepoDeadlineMs)
  assert.ok(defaults.searchRepoMaxBytes > 0 && defaults.searchRepoMaxBytes <= RUN_SAFETY_BUDGET_HARD_CEILINGS.searchRepoMaxBytes)

  // WS-14 (R4-H-20): OOB callback quotas
  assert.ok(defaults.oobMaxCallbacksPerToken > 0)
  assert.ok(defaults.oobMaxCallbacksPerRun >= defaults.oobMaxProtectedCallbacks)
  assert.ok(defaults.oobMaxProtectedCallbacks > 0)
  assert.ok(defaults.oobMaxCallbacksPerIpWindow > 0)

  // Workload scaling raises run-scoped caps while staying strictly <= hard ceilings
  const scaled = resolveRunSafetyBudgets({ maxAssignments: 400, dualReplay: true, env: {} })
  assert.ok(scaled.maxRedactedSecretsPerRun > defaults.maxRedactedSecretsPerRun)
  assert.ok(scaled.maxRedactedSecretsPerRun <= RUN_SAFETY_BUDGET_HARD_CEILINGS.maxRedactedSecretsPerRun)
  assert.ok(scaled.oobMaxCallbacksPerRun > defaults.oobMaxCallbacksPerRun)
  assert.ok(scaled.oobMaxProtectedCallbacks > defaults.oobMaxProtectedCallbacks)

  // Extreme env overrides clamp unconditionally at hard ceilings
  const hugeEnv: Record<string, string> = {}
  for (const key of Object.values(RUN_SAFETY_BUDGET_ENV_KEYS)) hugeEnv[key] = '999999999'
  const clamped = resolveRunSafetyBudgets({ maxAssignments: 1_000_000, env: hugeEnv })
  assert.deepEqual(clamped, RUN_SAFETY_BUDGET_HARD_CEILINGS)

  // Capacity high-watermark warning telemetry fires at >=80% utilization
  const { store, events } = makeRecordingEventStore()
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (url) => ({
      status: 200,
      headers: { 'set-cookie': [`k_${url.pathname.slice(1)}=val_${url.pathname.slice(1)}_secret; Path=/`] },
      body: 'ok',
      bodyBytes: 2,
    }),
    storage: store,
    maxRedactedSecretsPerRun: 5,
  })
  const grant = makeGrant({ runId: 'run-warn', storage: store })
  const signal = AbortSignal.timeout(10_000)
  return (async () => {
    for (let i = 1; i <= 4; i += 1) {
      await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: `/s${i}`, runId: 'run-warn', session: 's1' }, grant, signal)
    }
    const warnEvents = events.filter(e => e.kind === 'broker.redaction_capacity_warning')
    assert.equal(warnEvents.length, 1, 'high-watermark warning should emit once at >=80% utilization')
    assert.equal(warnEvents[0]?.detail?.activeCount, 4)
    assert.equal(warnEvents[0]?.detail?.cap, 5)
  })()
})
