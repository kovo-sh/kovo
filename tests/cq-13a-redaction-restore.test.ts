process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'
/**
 * Wave 2 / Item #13a (`scope-isolation-invariants` P0 safety slice) tests:
 *  1. Per-run fail-closed `redactedSecretsByRun` (no cross-run eviction; cap overflow throws
 *     typed `RedactionCapacityError`, emits structured degradation telemetry, preserves all live
 *     secrets, and never returns unredacted text).
 *  2. Unified `resolveJarKey(req, grant)` parity between HTTP session jars and
 *     `sessionCookiesForBrowser()` when `runId` comes from `grant.scopePolicy.runId`.
 *  3. `Execution.disposeRun(runId)` / `RunActor` disposal purges all broker per-run maps
 *     (`sessionJars`, `latestScopeRevisionByRun`, `personaSessionOwnersByRun`,
 *     `personaScopeMismatchesByRun`, `personaScopeMismatchKeysByRun`,
 *     `ephemeralTokenDigestsByRun`, `redactedSecretsByRun`) AND `derived-custody` run budgets
 *     strictly to zero without disturbing concurrent sibling runs.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  BrokerDenied,
  RedactionCapacityError,
  RequestBroker,
  resolveJarKey,
} from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse } from '../src/server/broker.ts'
import type { SecondOrderStore } from '../src/server/canary-broker.ts'
import {
  consumeRunCompositeVerifyBudget,
  consumeRunSealBudget,
  getRunCustodyBudgetUsage,
  hasRunCustodyBudget,
  resetRunCustodyBudgets,
} from '../src/server/derived-custody.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { setupApprovedRun, stopExecution } from './v4-tier-helpers.ts'

const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeScopePolicy(runId: string): ScopePolicy {
  return {
    runId,
    mode: 'staging_isolated',
    targetOrigins: [APP_ORIGIN],
  }
}

function makePersona(handle: string, cookieSecret: string): ResolvedPersona {
  return {
    id: `id-${handle}`,
    handle,
    roleLabel: handle,
    originAllowlist: [APP_ORIGIN],
    authKind: 'cookie',
    headerName: null,
    secret: `sid=${cookieSecret}`,
    canaryMarkers: [],
  }
}

function makeGrant(options: {
  runId?: string
  personas?: ReadonlyArray<ResolvedPersona>
  storage?: SecondOrderStore
} = {}): Grant {
  return {
    origin: APP_ORIGIN,
    tier: 2,
    maxRpsPerOrigin: 50,
    canRead: (o: string) => o === APP_ORIGIN,
    audit: () => {},
    ...(options.runId ? { scopePolicy: makeScopePolicy(options.runId) } : {}),
    ...(options.personas ? { personas: new Map(options.personas.map(p => [p.handle, p])) } : {}),
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

function makeStore(t: { after: (fn: () => void) => void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-cq13a-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function stubBackend(): WorkerBackend {
  return {
    openSession: async () => ({
      stage: async (name: string) => `/work/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async () => ({ repo: 'app', enginesRun: [], engineStatus: {}, findings: [], durationMs: 1 }),
      runScript: async () => ({ runtime: 'python', exitCode: 0, stdout: '', stderr: '', timedOut: false, durationMs: 1 }),
      close: async () => undefined,
    }),
  } as unknown as WorkerBackend
}

test('13a.1: per-run redactedSecrets isolates runs, fails closed on cap overflow with telemetry, and never FIFO-evicts live secrets', async () => {
  const { store, events } = makeRecordingEventStore()
  const secretPool = new Map<string, { cookieName: string; cookieVal: string; echo?: string }>([
    ['/a1', { cookieName: 'sid_a1', cookieVal: 'secret-runA-0001' }],
    ['/a2', { cookieName: 'sid_a2', cookieVal: 'secret-runA-0002' }],
    ['/a3', { cookieName: 'sid_a3', cookieVal: 'secret-runA-0003' }],
    ['/a3-dup', { cookieName: 'sid_a3', cookieVal: 'secret-runA-0003', echo: 'echo secret-runA-0001 and secret-runA-0003' }],
    ['/a4-overflow', { cookieName: 'sid_a4', cookieVal: 'secret-runA-OVERFLOW-0004', echo: 'leaked secret-runA-OVERFLOW-0004' }],
    ['/a-check', { cookieName: '', cookieVal: '', echo: 'check secret-runA-0001 still redacted' }],
    ['/b1', { cookieName: 'sid_b1', cookieVal: 'secret-runB-0001' }],
    ['/b2', { cookieName: 'sid_b2', cookieVal: 'secret-runB-0002' }],
    ['/b3', { cookieName: 'sid_b3', cookieVal: 'secret-runB-0003', echo: 'echo secret-runB-0001' }],
  ])

  const transport = async (url: URL): Promise<RawHttpResponse> => {
    const spec = secretPool.get(url.pathname) ?? { cookieName: '', cookieVal: '', echo: 'ok' }
    const headers: Record<string, string | string[]> = { 'content-type': 'text/plain' }
    if (spec.cookieName && spec.cookieVal) {
      headers['set-cookie'] = [`${spec.cookieName}=${spec.cookieVal}; Path=/`]
    }
    const body = spec.echo ?? `issued ${spec.cookieVal}`
    return { status: 200, headers, body, bodyBytes: Buffer.byteLength(body) }
  }

  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport,
    storage: store,
    maxRedactedSecretsPerRun: 3,
  })
  const grantA = makeGrant({ runId: 'run-A', storage: store })
  const grantB = makeGrant({ runId: 'run-B', storage: store })
  const signal = AbortSignal.timeout(10_000)

  // Fill Run A to exact cap (3 distinct secrets)
  for (const path of ['/a1', '/a2', '/a3']) {
    const res = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: path, runId: 'run-A', session: 's1' }, grantA, signal)
    assert.ok(!res.body.includes('secret-runA-'), `response on ${path} must scrub newly registered secret`)
  }
  assert.equal(broker.getRegisteredSecrets('run-A').length, 3)

  // Fill Run B to its own cap (3 distinct secrets) — must NEVER evict Run A's secrets!
  for (const path of ['/b1', '/b2', '/b3']) {
    const res = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: path, runId: 'run-B', session: 's1' }, grantB, signal)
    assert.ok(!res.body.includes('secret-runB-'), `response on ${path} must scrub Run B secret`)
  }
  assert.equal(broker.getRegisteredSecrets('run-A').length, 3, 'Run B must not evict Run A secrets')
  assert.equal(broker.getRegisteredSecrets('run-B').length, 3, 'Run B tracks its own 3 secrets')
  assert.ok(
    broker.getRegisteredSecrets('run-A').some(s => s.value === 'secret-runA-0001'),
    'Run A first live secret must still be registered after Run B filled its own cap',
  )

  // Re-observing an existing secret at cap is idempotent and must succeed while redacting live secrets
  const dupRes = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a3-dup', runId: 'run-A', session: 's1' },
    grantA,
    signal,
  )
  assert.ok(!dupRes.body.includes('secret-runA-0001'), 'Run A secret #1 must still be redacted')
  assert.ok(!dupRes.body.includes('secret-runA-0003'), 'Run A secret #3 must still be redacted')

  // 4th distinct secret in Run A MUST fail closed with typed RedactionCapacityError + degradation event
  await assert.rejects(
    () => broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a4-overflow', runId: 'run-A', session: 's1' },
      grantA,
      signal,
    ),
    (err: unknown) => {
      assert.ok(err instanceof RedactionCapacityError, `expected RedactionCapacityError, got ${String(err)}`)
      assert.equal(err.runId, 'run-A')
      assert.equal(err.cap, 3)
      assert.equal(err.activeCount, 3)
      return true
    },
  )

  const degradationEvent = events.find(e => e.kind === 'broker.redaction_capacity_exceeded')
  assert.ok(degradationEvent, 'cap overflow must emit structured broker.redaction_capacity_exceeded telemetry')
  assert.equal(degradationEvent.runId, 'run-A')
  assert.equal(degradationEvent.detail?.degradation, 'redaction_fail_closed')
  assert.equal(degradationEvent.detail?.cap, 3)
  assert.equal(degradationEvent.detail?.activeCount, 3)

  // Verify live Run A secret #1 was NEVER FIFO-evicted and overflowing secret was not silently admitted
  const aSecrets = broker.getRegisteredSecrets('run-A').map(s => s.value)
  assert.deepEqual(aSecrets.sort(), ['secret-runA-0001', 'secret-runA-0002', 'secret-runA-0003'])
  const checkRes = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a-check', runId: 'run-A', session: 's1' },
    grantA,
    signal,
  )
  assert.ok(!checkRes.body.includes('secret-runA-0001'), 'live secret #1 must still be scrubbed after overflow rejection')

  // Disposing Run A drops Run A's secrets cleanly without affecting Run B
  broker.disposeRun('run-A')
  assert.equal(broker.getRegisteredSecrets('run-A').length, 0)
  assert.equal(broker.getRegisteredSecrets('run-B').length, 3)

  // After disposal, Run A can cleanly register new secrets again
  const postDispose = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a4-overflow', runId: 'run-A', session: 's1' },
    grantA,
    signal,
  )
  assert.ok(!postDispose.body.includes('secret-runA-OVERFLOW-0004'))
  assert.equal(broker.getRegisteredSecrets('run-A').length, 1)
})

test('13a.2: unified resolveJarKey keeps HTTP session jars and sessionCookiesForBrowser in lockstep for grant.scopePolicy.runId', async () => {
  const transport = async (): Promise<RawHttpResponse> => ({
    status: 200,
    headers: {
      'content-type': 'application/json',
      'set-cookie': [
        'XSRF-TOKEN=csrf_mirror_value_42; Path=/',
        'HttpOnlySid=hidden_server_cookie_99; Path=/; HttpOnly',
      ],
    },
    body: JSON.stringify({ ok: true }),
    bodyBytes: 11,
  })
  const broker = new RequestBroker({ resolve: async () => [PUBLIC_ADDR], transport })
  const alicePersona = makePersona('alice', 'alice_vault_tok_42')
  const grantRun42 = makeGrant({ runId: 'run-policy-42', personas: [alicePersona] })
  const grantOther = makeGrant({ runId: 'run-policy-99', personas: [alicePersona] })
  const signal = AbortSignal.timeout(10_000)

  // Note: req.runId is intentionally omitted so runId comes solely from grant.scopePolicy.runId
  const reqScope = {
    session: 'sess-alpha',
    persona: 'alice',
    assignmentId: 'asgn-7',
    sessionGroupRole: 'probe' as const,
  }
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/bootstrap', ...reqScope },
    grantRun42,
    signal,
  )

  const resolvedHttp = resolveJarKey(reqScope, grantRun42)
  const resolvedBrowser = broker.resolveJarKey({ ...reqScope, persona: undefined, personaHandle: 'alice' }, grantRun42)
  assert.equal(resolvedHttp.runId, 'run-policy-42')
  assert.equal(resolvedHttp.jarKey, resolvedBrowser.jarKey)

  // Browser mirror via grant argument sees the exact non-HttpOnly cookie stored by HTTP path
  const mirroredViaGrant = broker.sessionCookiesForBrowser(reqScope, APP_ORIGIN, grantRun42)
  assert.equal(mirroredViaGrant.length, 1, 'only the non-HttpOnly jar cookie should be mirrored')
  assert.equal(mirroredViaGrant[0]?.name, 'XSRF-TOKEN')
  assert.equal(mirroredViaGrant[0]?.value, 'csrf_mirror_value_42')

  // Browser mirror via scope.scopePolicy also agrees identically
  const mirroredViaScopePolicy = broker.sessionCookiesForBrowser(
    { ...reqScope, scopePolicy: grantRun42.scopePolicy },
    APP_ORIGIN,
  )
  assert.deepEqual(mirroredViaScopePolicy, mirroredViaGrant)

  // Unrelated runId must never see run-policy-42's jar cookies
  assert.deepEqual(broker.sessionCookiesForBrowser(reqScope, APP_ORIGIN, grantOther), [])
  assert.deepEqual(broker.sessionCookiesForBrowser(reqScope, APP_ORIGIN), [])
})

test('13a.3: Execution.disposeRun purges all broker per-run maps and derived-custody run budgets to empty while preserving sibling runs', async (t) => {
  const storage = makeStore(t)
  const { runId: runA } = await setupApprovedRun(storage, { budgetRequests: 200 })
  const { runId: runB } = await setupApprovedRun(storage, { budgetRequests: 200 })
  t.after(() => {
    resetRunCustodyBudgets(runA)
    resetRunCustodyBudgets(runB)
  })

  // Synthetic 3-segment signed-looking JWT (non-secret test fixture) for Q4 ephemeral digest observation
  const fakeJwt = (tag: string) =>
    `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: tag })).toString('base64url')}.${Buffer.from(`sig_${tag}_1234567890`).toString('base64url')}`

  const transport = async (url: URL): Promise<RawHttpResponse> => {
    const tag = url.searchParams.get('run') ?? 'x'
    const body = JSON.stringify({ access_token: fakeJwt(tag) })
    return {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'set-cookie': [`app_sid=cookie_val_${tag}_9999; Path=/`],
        'x-csrf-token': `csrf_val_${tag}_8888`,
      },
      body,
      bodyBytes: Buffer.byteLength(body),
    }
  }

  const broker = new RequestBroker({ resolve: async () => [PUBLIC_ADDR], transport })
  const engine = new Execution(storage, { backend: stubBackend(), broker, deterministicSweep: false })
  t.after(() => stopExecution(engine as never))

  const signal = AbortSignal.timeout(10_000)

  const populateRun = async (runId: string) => {
    const p1 = makePersona('alice', `shared_sess_${runId}_abcdef`)
    const p2 = makePersona('bob', `shared_sess_${runId}_abcdef`)
    const grant = makeGrant({ runId, personas: [p1, p2] })

    // 1. Populate sessionJars, redactedSecretsByRun, ephemeralTokenDigestsByRun, personaSessionOwnersByRun
    await broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: `/api/me?run=${runId}`, runId, session: 's1', persona: 'alice' },
      grant,
      signal,
    )
    // 2. Trigger personaScopeMismatchesByRun + personaScopeMismatchKeysByRun for this run
    await assert.rejects(
      () => broker.executeHttp(
        { origin: APP_ORIGIN, method: 'GET', pathAndQuery: `/api/me?run=${runId}`, runId, session: 's2', persona: 'bob' },
        grant,
        signal,
      ),
      BrokerDenied,
    )
    // 3. Populate latestScopeRevisionByRun (keeping jar alive by revoking at rev 0 or re-creating jar at rev 2)
    broker.revokeScope(runId, 2)
    await broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: `/api/me?run=${runId}`, runId, session: 's1', persona: 'alice', scopeRevision: 2 },
      grant,
      signal,
    )
    // 4. Populate derived-custody run budgets
    consumeRunSealBudget(runId, 'GET /api/me')
    consumeRunCompositeVerifyBudget(runId)
  }

  // Ensure RunActor exists for runA (exercises actor.registerResource disposal) while runB tests direct disposal too
  const execPriv = engine as unknown as { ensureRunActor: (runId: string) => unknown }
  execPriv.ensureRunActor(runA)

  await populateRun(runA)
  await populateRun(runB)

  // Confirm all per-run buckets are populated BEFORE disposal
  const beforeA = broker.getRunStateCounts(runA)
  assert.ok(beforeA.sessionJars > 0, 'runA sessionJars populated')
  assert.equal(beforeA.hasScopeRevision, true, 'runA latestScopeRevisionByRun populated')
  assert.ok(beforeA.personaSessionOwners > 0, 'runA personaSessionOwners populated')
  assert.ok(beforeA.personaScopeMismatches > 0, 'runA personaScopeMismatches populated')
  assert.ok(beforeA.ephemeralTokenDigests > 0, 'runA ephemeralTokenDigests populated')
  assert.ok(beforeA.redactedSecrets > 0, 'runA redactedSecrets populated')
  assert.equal(hasRunCustodyBudget(runA), true, 'runA custody budget populated')
  assert.equal(getRunCustodyBudgetUsage(runA).sealTotal, 1)
  assert.equal(getRunCustodyBudgetUsage(runA).compositeVerifyTotal, 1)

  // Dispose runA through Execution.disposeRun
  await engine.disposeRun(runA, { terminalState: 'completed', reason: 'test cleanup' })

  // Assert EVERY broker per-run bucket and custody budget for runA is strictly empty
  assert.deepEqual(broker.getRunStateCounts(runA), {
    sessionJars: 0,
    hasScopeRevision: false,
    personaSessionOwners: 0,
    personaScopeMismatches: 0,
    ephemeralTokenDigests: 0,
    redactedSecrets: 0,
  })
  assert.deepEqual(broker.getRegisteredSecrets(runA), [])
  assert.deepEqual(broker.getPersonaScopeMismatches(runA), [])
  assert.equal(hasRunCustodyBudget(runA), false, 'runA custody budget entry must be deleted on disposeRun')
  assert.deepEqual(getRunCustodyBudgetUsage(runA), { sealTotal: 0, compositeVerifyTotal: 0, sealByEndpoint: {} })

  // Sibling runB must remain completely untouched
  const siblingB = broker.getRunStateCounts(runB)
  assert.ok(siblingB.sessionJars > 0)
  assert.equal(siblingB.hasScopeRevision, true)
  assert.ok(siblingB.personaSessionOwners > 0)
  assert.ok(siblingB.personaScopeMismatches > 0)
  assert.ok(siblingB.ephemeralTokenDigests > 0)
  assert.ok(siblingB.redactedSecrets > 0)
  assert.equal(hasRunCustodyBudget(runB), true)

  // Dispose runB (no RunActor created for runB -> exercises Execution.disposeRun fallback cleanupRunState)
  await engine.disposeRun(runB, { terminalState: 'completed', reason: 'test cleanup B' })
  assert.equal(hasRunCustodyBudget(runB), false)

  // Verify raw private maps on RequestBroker have ZERO lingering entries after both runs dispose
  const brokerPriv = broker as unknown as {
    sessionJars: Map<string, unknown>
    latestScopeRevisionByRun: Map<string, unknown>
    personaSessionOwnersByRun: Map<string, unknown>
    personaScopeMismatchesByRun: Map<string, unknown>
    personaScopeMismatchKeysByRun: Map<string, unknown>
    ephemeralTokenDigestsByRun: Map<string, unknown>
    redactedSecretsByRun: Map<string, unknown>
  }
  assert.equal(brokerPriv.sessionJars.size, 0)
  assert.equal(brokerPriv.latestScopeRevisionByRun.size, 0)
  assert.equal(brokerPriv.personaSessionOwnersByRun.size, 0)
  assert.equal(brokerPriv.personaScopeMismatchesByRun.size, 0)
  assert.equal(brokerPriv.personaScopeMismatchKeysByRun.size, 0)
  assert.equal(brokerPriv.ephemeralTokenDigestsByRun.size, 0)
  assert.equal(brokerPriv.redactedSecretsByRun.size, 0)
})
