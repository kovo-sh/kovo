import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { RequestListener } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createPersona, runCommand } from '../src/domain.ts'
import type { Finding } from '../src/domain.ts'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { PersonaSessionPool } from '../src/server/persona-auth.ts'
import {
  buildPersonaHeader,
  createProjectPersona,
  resolveRunPersonas,
  writePersonaSessionFile,
} from '../src/server/persona-vault.ts'
import type { MintedPersonaSession, ResolvedPersona } from '../src/server/persona-vault.ts'
import { cloneWorkerPersona } from '../src/server/session-isolation.ts'
import { Store } from '../src/server/store.ts'

// ---------------------------------------------------------------------------
// Shared test harness helpers (local-lab HTTP mock + single Store/Broker)
// ---------------------------------------------------------------------------

function enableLocalLab(t: { after(fn: () => void): void }) {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })
}

function makeTempStore(t: { after(fn: () => void): void }): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-prop-multirun-'))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return { dir, store }
}

async function startMockServer(
  t: { after(fn: () => void | Promise<void>): void },
  handler: RequestListener,
): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = createServer(handler)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port
  const origin = `http://127.0.0.1:${port}`
  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
  t.after(close)
  return { origin, close }
}

function createLocalLabRun(
  store: Store,
  projectId: string,
  opts: {
    goal?: string
    tier?: 0 | 1 | 2 | 3
    maxRpsPerOrigin?: number
    approvedPersonaIds?: string[]
  } = {},
) {
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId,
    goal: opts.goal ?? 'Multi-run concurrency isolation property check',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 2,
    ...(opts.maxRpsPerOrigin !== undefined ? { maxRpsPerOrigin: opts.maxRpsPerOrigin } : {}),
  } as Parameters<Store['createRun']>[0])

  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    ...(opts.approvedPersonaIds ? { approvedPersonaIds: opts.approvedPersonaIds } : {}),
  }))
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  return store.run(runId)
}

function buildWorkerGrant(
  execution: Execution,
  store: Store,
  runId: string,
  origin: string,
  label = 'prop-worker',
): {
  grant: Grant
  assignmentId: string
  currentSecrets: () => Array<{ placeholder: string; value: string }>
} {
  const run = store.run(runId)
  const asset = run.candidates.find(c => c.origin === origin) ?? run.candidates[0]!
  const created = store.makeWorker(run, 'investigation', asset, label, 'Verify isolation invariant', {
    sourceOrigins: [origin],
  })
  const assignment = store.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
  const job = { assignment, origins: new Set([origin]), controller: new AbortController() }
  const priv = execution as unknown as {
    buildGrant: (
      job: { assignment: typeof assignment; origins: Set<string>; controller: AbortController },
      run: ReturnType<Store['run']>,
      allowed: ReadonlySet<string>,
    ) => { grant: Grant; currentSecrets: () => Array<{ placeholder: string; value: string }> }
  }
  const built = priv.buildGrant(job, run, new Set([origin]))
  return {
    grant: built.grant,
    assignmentId: assignment.id,
    currentSecrets: built.currentSecrets,
  }
}

function makeScopedGrant(origin: string, runId: string, scopeRevision: number, maxRpsPerOrigin = 50): Grant {
  return {
    tier: 2,
    allowLocalLab: true,
    maxRpsPerOrigin,
    scopeRevision,
    scopePolicy: {
      runId,
      mode: 'ephemeral_lab',
      targetOrigins: [origin],
      authOrigins: [],
      assetOrigins: [],
      routeDenylist: [],
    },
    canRead: o => o === origin,
    audit: () => undefined,
  }
}

// ---------------------------------------------------------------------------
// Property 1: Per-run latestScopeRevision isolation across concurrent runs
// ---------------------------------------------------------------------------

test('Prop 1: per-run latestScopeRevision isolation — revokeScope(runA, 3) denies stale runA while concurrent runB rev 1 succeeds with zero BrokerDenied', async t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const received: Array<{ path: string; cookie: string }> = []
  const { origin } = await startMockServer(t, (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    received.push({ path: url.pathname + url.search, cookie: req.headers.cookie ?? '' })
    if (url.pathname === '/seed-jar') {
      const tag = url.searchParams.get('run') ?? 'unknown'
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `sid=cookie_${tag}_rev1; Path=/`,
      })
      res.end(JSON.stringify({ seeded: tag }))
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, path: url.pathname, cookie: req.headers.cookie ?? '' }))
  })

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Prop1 MultiRun Scope',
    seeds: [origin],
    environment: 'local-lab',
  })
  const runA = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80 })
  const runB = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80 })
  const runC = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80 })

  // Single shared RequestBroker bound to the shared Store
  const broker = new RequestBroker({ storage: store })

  // Seed per-run session jars at scopeRevision 1 for both runA and runB
  const seedA = await broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/seed-jar?run=runA',
    runId: runA.id,
    assignmentId: 'worker-a',
    session: 'jar',
    scopeRevision: 1,
  }, makeScopedGrant(origin, runA.id, 1, 80), AbortSignal.timeout(5_000))
  assert.equal(seedA.status, 200)

  const seedB = await broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/seed-jar?run=runB',
    runId: runB.id,
    assignmentId: 'worker-b',
    session: 'jar',
    scopeRevision: 1,
  }, makeScopedGrant(origin, runB.id, 1, 80), AbortSignal.timeout(5_000))
  assert.equal(seedB.status, 200)

  // Advance runA scope revision to 3 via explicit revokeScope(runA.id, 3) while runB stays at rev 1
  broker.revokeScope(runA.id, 3)
  // Also advance runC to rev 5 to verify N>2 runs stay mutually isolated
  broker.revokeScope(runC.id, 5)

  // Concurrent interleaved traffic across runA (stale rev 1 & fresh rev 3), runB (rev 1), and runC (stale rev 2 & fresh rev 5)
  const runBPromises = Array.from({ length: 8 }, (_, i) =>
    broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: `/runB/ok-${i}`,
      runId: runB.id,
      assignmentId: 'worker-b',
      session: 'jar',
      scopeRevision: 1,
    }, makeScopedGrant(origin, runB.id, 1, 80), AbortSignal.timeout(5_000)),
  )

  const runAStalePromises = Array.from({ length: 6 }, (_, i) =>
    broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: `/runA/stale-${i}`,
      runId: runA.id,
      assignmentId: 'worker-a',
      session: 'jar',
      scopeRevision: 1,
    }, makeScopedGrant(origin, runA.id, 1, 80), AbortSignal.timeout(5_000))
      .then(() => ({ ok: true as const, err: null as unknown }))
      .catch(err => ({ ok: false as const, err })),
  )

  const runAFreshPromises = Array.from({ length: 4 }, (_, i) =>
    broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: `/runA/fresh-${i}`,
      runId: runA.id,
      assignmentId: 'worker-a',
      session: 'jar',
      scopeRevision: 3,
    }, makeScopedGrant(origin, runA.id, 3, 80), AbortSignal.timeout(5_000)),
  )

  const runCStalePromise = broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/runC/stale-rev2',
    runId: runC.id,
    assignmentId: 'worker-c',
    scopeRevision: 2,
  }, makeScopedGrant(origin, runC.id, 2, 80), AbortSignal.timeout(5_000))
    .then(() => ({ ok: true as const, err: null as unknown }))
    .catch(err => ({ ok: false as const, err }))

  const runCFreshPromise = broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/runC/fresh-rev5',
    runId: runC.id,
    assignmentId: 'worker-c',
    scopeRevision: 5,
  }, makeScopedGrant(origin, runC.id, 5, 80), AbortSignal.timeout(5_000))

  const [runBResults, runAStaleResults, runAFreshResults, runCStaleResult, runCFreshResult] = await Promise.all([
    Promise.all(runBPromises),
    Promise.all(runAStalePromises),
    Promise.all(runAFreshPromises),
    runCStalePromise,
    runCFreshPromise,
  ])

  // Property 1a: runB at rev 1 succeeds 100% with zero BrokerDenied and keeps its rev-1 session jar cookie!
  for (let i = 0; i < runBResults.length; i += 1) {
    const res = runBResults[i]!
    assert.equal(res.status, 200, 'runB rev 1 must never receive BrokerDenied when runA advances to rev 3')
    const parsed = JSON.parse(res.body) as { ok: boolean; cookie: string }
    assert.equal(parsed.ok, true)
    assert.equal(
      received.find(r => r.path === `/runB/ok-${i}`)?.cookie,
      'sid=cookie_runB_rev1',
      'runB session jar must stay intact on the wire after runA revokeScope',
    )
    assert.equal(
      parsed.cookie.includes('cookie_runB_rev1'),
      false,
      'broker must redact echoed jar cookie in response body',
    )
  }

  // Property 1b: EVERY stale runA rev-1 request is rejected with BrokerDenied and never reaches the wire!
  for (const outcome of runAStaleResults) {
    assert.equal(outcome.ok, false, 'stale runA rev 1 request must be denied after revokeScope(runA, 3)')
    assert.ok(outcome.err instanceof BrokerDenied, `expected BrokerDenied, got ${String(outcome.err)}`)
    assert.match(outcome.err.message, /stale/i)
  }
  assert.equal(
    received.some(r => r.path.startsWith('/runA/stale-')),
    false,
    'stale runA requests must be blocked before hitting the mock HTTP server',
  )

  // Property 1c: runA at rev 3 succeeds and its stale rev-1 jar cookie was evicted!
  for (let i = 0; i < runAFreshResults.length; i += 1) {
    const res = runAFreshResults[i]!
    assert.equal(res.status, 200)
    assert.equal(
      received.find(r => r.path === `/runA/fresh-${i}`)?.cookie,
      '',
      'runA stale rev-1 jar cookie must have been evicted by revokeScope(runA, 3)',
    )
  }

  // Property 1d: runC isolation mirrors runA without affecting runB
  assert.equal(runCStaleResult.ok, false)
  assert.ok(runCStaleResult.err instanceof BrokerDenied)
  assert.equal(runCFreshResult.status, 200)
})

// ---------------------------------------------------------------------------
// Property 2: Live worker session rotation & sibling logout isolation
// ---------------------------------------------------------------------------

test('Prop 2: sessionPool.rotate() propagates Clerk/Bearer/Cookie tokens immediately to already-cloned workers while sibling logout() stays isolated', async t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const seenRequests: Array<{ path: string; cookie: string; authorization: string }> = []
  const { origin } = await startMockServer(t, (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    seenRequests.push({
      path: url.pathname,
      cookie: req.headers.cookie ?? '',
      authorization: req.headers.authorization ?? '',
    })
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      ok: true,
      path: url.pathname,
      hasCookie: Boolean(req.headers.cookie),
      hasAuth: Boolean(req.headers.authorization),
    }))
  })

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Prop2 Live Rotation',
    seeds: [origin],
    environment: 'local-lab',
  })

  // Create three distinct login personas: Clerk cookie, Bearer token, and standard session cookie
  const clerkPersona = createProjectPersona(store, createPersona.parse({
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'clerk_member',
    roleLabel: 'Clerk Member',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'clerk_client', clientCookie: '__client=prop2_clerk_client_seed_1111' },
  }))
  const bearerPersona = createProjectPersona(store, createPersona.parse({
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'bearer_member',
    roleLabel: 'Bearer Member',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'json', loginUrl: `${origin}/auth/login`, email: 'bearer@example.test' },
  }))
  const cookiePersona = createProjectPersona(store, createPersona.parse({
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'cookie_member',
    roleLabel: 'Cookie Member',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'form', loginUrl: `${origin}/login`, email: 'cookie@example.test' },
  }))

  const allPersonaIds = [clerkPersona.id, bearerPersona.id, cookiePersona.id]
  const runA = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80, approvedPersonaIds: allPersonaIds })
  const runB = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80, approvedPersonaIds: [cookiePersona.id] })

  const resolvedMap = resolveRunPersonas(store, project.id, allPersonaIds)
  const clerkV1: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=clerk_jwt_v1_alpha11111111; __client_uat=1700000100',
    adapterUsed: 'clerk_client',
  }
  const bearerV1: MintedPersonaSession = {
    headerType: 'bearer',
    value: 'bearer_jwt_v1_alpha22222222',
    adapterUsed: 'json_login',
  }
  const cookieV1: MintedPersonaSession = {
    headerType: 'cookie',
    value: 'app_sid=cookie_v1_alpha33333333',
    adapterUsed: 'form',
  }
  writePersonaSessionFile(resolvedMap.get('clerk_member')!.sessionPath!, clerkV1)
  writePersonaSessionFile(resolvedMap.get('bearer_member')!.sessionPath!, bearerV1)
  writePersonaSessionFile(resolvedMap.get('cookie_member')!.sessionPath!, cookieV1)

  const execution = new Execution(store)
  t.after(() => execution.stop())

  execution.personaAuth.registerSession('clerk_member', { session: clerkV1, allowlist: [origin] })
  execution.personaAuth.registerSession('bearer_member', { session: bearerV1, allowlist: [origin] })
  execution.personaAuth.registerSession('cookie_member', { session: cookieV1, allowlist: [origin] })

  // Build two already-cloned worker grants on runA and one concurrent worker grant on runB
  const worker1 = buildWorkerGrant(execution, store, runA.id, origin, 'runA-w1')
  const worker2 = buildWorkerGrant(execution, store, runA.id, origin, 'runA-w2')
  const workerB = buildWorkerGrant(execution, store, runB.id, origin, 'runB-w1')

  // Initial baseline requests verify v1 tokens on the wire
  await Promise.all([
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/clerk-v1', runId: runA.id, persona: 'clerk_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/bearer-v1', runId: runA.id, persona: 'bearer_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/cookie-v1', runId: runA.id, persona: 'cookie_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w2/clerk-v1', runId: runA.id, persona: 'clerk_member' }, worker2.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/wB/cookie-v1', runId: runB.id, persona: 'cookie_member' }, workerB.grant, AbortSignal.timeout(5_000)),
  ])
  assert.equal(seenRequests.find(r => r.path === '/w1/clerk-v1')?.cookie, clerkV1.value)
  assert.equal(seenRequests.find(r => r.path === '/w1/bearer-v1')?.authorization, `Bearer ${bearerV1.value}`)
  assert.equal(seenRequests.find(r => r.path === '/w1/cookie-v1')?.cookie, cookieV1.value)
  assert.equal(seenRequests.find(r => r.path === '/w2/clerk-v1')?.cookie, clerkV1.value)
  assert.equal(seenRequests.find(r => r.path === '/wB/cookie-v1')?.cookie, cookieV1.value)

  // Rotate all 3 token types mid-run via sessionPool.rotate() WITHOUT rebuilding any Grant
  const clerkV2: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=clerk_jwt_v2_bravo44444444; __client_uat=1700000200',
    adapterUsed: 'clerk_client',
  }
  const bearerV2: MintedPersonaSession = {
    headerType: 'bearer',
    value: 'bearer_jwt_v2_bravo55555555',
    adapterUsed: 'json_login',
  }
  const cookieV2: MintedPersonaSession = {
    headerType: 'cookie',
    value: 'app_sid=cookie_v2_bravo66666666',
    adapterUsed: 'form',
  }
  assert.equal(execution.personaAuth.sessions.rotate('clerk_member', clerkV2), 2)
  assert.equal(execution.personaAuth.sessions.rotate('bearer_member', bearerV2), 2)
  assert.equal(execution.personaAuth.sessions.rotate('cookie_member', cookieV2), 2)

  // Already-cloned worker1 and runB workerB immediately send fresh v2 tokens on their very next request
  await Promise.all([
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/clerk-v2', runId: runA.id, persona: 'clerk_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/bearer-v2', runId: runA.id, persona: 'bearer_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/cookie-v2', runId: runA.id, persona: 'cookie_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/wB/cookie-v2', runId: runB.id, persona: 'cookie_member' }, workerB.grant, AbortSignal.timeout(5_000)),
  ])
  assert.equal(seenRequests.find(r => r.path === '/w1/clerk-v2')?.cookie, clerkV2.value)
  assert.equal(seenRequests.find(r => r.path === '/w1/bearer-v2')?.authorization, `Bearer ${bearerV2.value}`)
  assert.equal(seenRequests.find(r => r.path === '/w1/cookie-v2')?.cookie, cookieV2.value)
  assert.equal(seenRequests.find(r => r.path === '/wB/cookie-v2')?.cookie, cookieV2.value)

  // Now worker2 logs out: it MUST stay isolated without breaking worker1 or runB's workerB!
  const loggedOutCount = execution.logoutWorkerSession(worker2.assignmentId)
  assert.equal(loggedOutCount, 3, 'logoutWorkerSession must log out all 3 persona clones belonging to worker2')
  assert.equal(buildPersonaHeader(worker2.grant.personas!.get('clerk_member')!, origin), null)
  assert.equal(buildPersonaHeader(worker2.grant.personas!.get('bearer_member')!, origin), null)
  assert.equal(buildPersonaHeader(worker2.grant.personas!.get('cookie_member')!, origin), null)

  // Rotate a third time (v3): worker1 & workerB pick up v3; logged-out worker2 remains logged out!
  const clerkV3: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=clerk_jwt_v3_charlie777777; __client_uat=1700000300',
    adapterUsed: 'clerk_client',
  }
  const bearerV3: MintedPersonaSession = {
    headerType: 'bearer',
    value: 'bearer_jwt_v3_charlie888888',
    adapterUsed: 'json_login',
  }
  assert.equal(execution.personaAuth.sessions.rotate('clerk_member', clerkV3), 3)
  assert.equal(execution.personaAuth.sessions.rotate('bearer_member', bearerV3), 3)

  await Promise.all([
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/clerk-v3', runId: runA.id, persona: 'clerk_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/w1/bearer-v3', runId: runA.id, persona: 'bearer_member' }, worker1.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/wB/cookie-after-w2-logout', runId: runB.id, persona: 'cookie_member' }, workerB.grant, AbortSignal.timeout(5_000)),
  ])
  assert.equal(seenRequests.find(r => r.path === '/w1/clerk-v3')?.cookie, clerkV3.value)
  assert.equal(seenRequests.find(r => r.path === '/w1/bearer-v3')?.authorization, `Bearer ${bearerV3.value}`)
  assert.equal(seenRequests.find(r => r.path === '/wB/cookie-after-w2-logout')?.cookie, cookieV2.value)

  // Logged-out worker2 still exposes no credentials even after v3 rotation
  assert.equal(buildPersonaHeader(worker2.grant.personas!.get('clerk_member')!, origin), null)
  assert.equal(buildPersonaHeader(worker2.grant.personas!.get('bearer_member')!, origin), null)

  // Also verify direct standalone PersonaSessionPool + clone.logout() isolation (zero Execution wrapper)
  const directPool = new PersonaSessionPool()
  directPool.register('direct_tok', { session: bearerV1, allowlist: [origin] })
  const basePersona: ResolvedPersona = {
    id: 'p-direct',
    handle: 'direct_tok',
    roleLabel: 'Direct',
    originAllowlist: [origin],
    authKind: 'login',
    headerName: null,
    secret: 'unused',
    canaryMarkers: [],
    session: bearerV1,
  }
  const clone1 = cloneWorkerPersona(basePersona, 'direct-w1', (h, wid) => directPool.clone(h, wid))!
  const clone2 = cloneWorkerPersona(basePersona, 'direct-w2', (h, wid) => directPool.clone(h, wid))!
  clone2.clone.logout()
  directPool.rotate('direct_tok', bearerV2)
  assert.deepEqual(buildPersonaHeader(clone1.persona, origin), { Authorization: `Bearer ${bearerV2.value}` })
  assert.equal(buildPersonaHeader(clone2.persona, origin), null)
})

// ---------------------------------------------------------------------------
// Property 3: Broker 401 single-flight reauth & rotated-token redaction
// ---------------------------------------------------------------------------

test('Prop 3: broker 401 invokes single-flight reauth exactly once across concurrent in-flight requests, retries cleanly, and redacts rotated token from stored exchanges/events', async t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const EXPIRED_TOKEN = 'expired_bearer_tok_1111222233334444'
  const ROTATED_TOKEN = 'rotated_bearer_tok_9999888877776666'
  const RUNB_TOKEN = 'runb_stable_bearer_5555666677778888'
  const CONCURRENT_401_REQS = 6

  let observedExpired401s = 0
  let observedRotated200s = 0
  let resolveAllExpiredSeen: (() => void) | null = null
  const allExpiredSeen = new Promise<void>(resolve => { resolveAllExpiredSeen = resolve })

  const { origin } = await startMockServer(t, (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = req.headers.authorization ?? ''

    if (url.pathname.startsWith('/runB/')) {
      assert.equal(auth, `Bearer ${RUNB_TOKEN}`)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ run: 'B', ok: true }))
      return
    }

    if (auth === `Bearer ${ROTATED_TOKEN}`) {
      observedRotated200s += 1
      res.writeHead(200, {
        'Content-Type': 'application/json',
        // Deliberately echo the rotated token in both response header and body to prove redaction!
        'X-Echo-Credential': ROTATED_TOKEN,
      })
      res.end(JSON.stringify({
        ok: true,
        path: url.pathname,
        echoedSecret: ROTATED_TOKEN,
      }))
      return
    }

    observedExpired401s += 1
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'token_expired', seen: EXPIRED_TOKEN }))
    if (observedExpired401s >= CONCURRENT_401_REQS) resolveAllExpiredSeen?.()
  })

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Prop3 SingleFlight Reauth',
    seeds: [origin],
    environment: 'local-lab',
  })
  const personaA = createProjectPersona(store, createPersona.parse({
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'reauth_target',
    roleLabel: 'Member A',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'json', loginUrl: `${origin}/login`, email: 'member-a@example.test' },
  }))
  const personaB = createProjectPersona(store, createPersona.parse({
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'stable_runb',
    roleLabel: 'Member B',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'json', loginUrl: `${origin}/login`, email: 'member-b@example.test' },
  }))

  const runA = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80, approvedPersonaIds: [personaA.id] })
  const runB = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80, approvedPersonaIds: [personaB.id] })

  const resolvedA = resolveRunPersonas(store, project.id, [personaA.id]).get('reauth_target')!
  const resolvedB = resolveRunPersonas(store, project.id, [personaB.id]).get('stable_runb')!

  const expiredSession: MintedPersonaSession = {
    headerType: 'bearer',
    value: EXPIRED_TOKEN,
    adapterUsed: 'json_login',
  }
  const rotatedSession: MintedPersonaSession = {
    headerType: 'bearer',
    value: ROTATED_TOKEN,
    adapterUsed: 'json_login',
  }
  const runBSession: MintedPersonaSession = {
    headerType: 'bearer',
    value: RUNB_TOKEN,
    adapterUsed: 'json_login',
  }
  writePersonaSessionFile(resolvedA.sessionPath!, expiredSession)
  writePersonaSessionFile(resolvedB.sessionPath!, runBSession)

  // Construct Execution without custom broker so it wires broker.setReauth -> personaAuth.requestReauth
  const execution = new Execution(store)
  t.after(() => execution.stop())

  let reauthInvocations = 0
  execution.personaAuth.registerSession('reauth_target', {
    session: expiredSession,
    allowlist: [origin],
    refresh: async () => {
      reauthInvocations += 1
      // Wait until all 6 concurrent 401 responses have been sent AND delivered over loopback so
      // every in-flight caller deterministically joins the same single-flight refresh promise.
      await Promise.race([allExpiredSeen, new Promise<void>(r => setTimeout(r, 120))])
      await new Promise<void>(r => setTimeout(r, 25))
      writePersonaSessionFile(resolvedA.sessionPath!, rotatedSession)
      return rotatedSession
    },
  })
  execution.personaAuth.registerSession('stable_runb', {
    session: runBSession,
    allowlist: [origin],
  })

  // Two concurrent worker grants on runA + one worker grant on runB sharing the single Execution/Broker
  const workerA1 = buildWorkerGrant(execution, store, runA.id, origin, 'runA-reauth-1')
  const workerA2 = buildWorkerGrant(execution, store, runA.id, origin, 'runA-reauth-2')
  const workerB = buildWorkerGrant(execution, store, runB.id, origin, 'runB-concurrent')

  const runACalls = Array.from({ length: CONCURRENT_401_REQS }, (_, i) => {
    const worker = i % 2 === 0 ? workerA1 : workerA2
    return execution.broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: `/runA/protected-${i}?probe=${i}`,
      runId: runA.id,
      assignmentId: worker.assignmentId,
      persona: 'reauth_target',
    }, worker.grant, AbortSignal.timeout(5_000)).then(res => ({ res, worker }))
  })
  const runBCalls = Array.from({ length: 4 }, (_, i) =>
    execution.broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: `/runB/healthy-${i}`,
      runId: runB.id,
      assignmentId: workerB.assignmentId,
      persona: 'stable_runb',
    }, workerB.grant, AbortSignal.timeout(5_000)),
  )

  const [runAResults, runBResults] = await Promise.all([
    Promise.all(runACalls),
    Promise.all(runBCalls),
  ])

  // Single-flight guarantee: refresh invoked ONCE across all 6 concurrent 401s
  assert.equal(reauthInvocations, 1, `reauth must be single-flight (expected 1 invocation, got ${reauthInvocations})`)
  assert.equal(observedExpired401s, CONCURRENT_401_REQS)
  assert.equal(observedRotated200s, CONCURRENT_401_REQS)

  // Concurrent runB stayed completely unaffected
  for (const res of runBResults) {
    assert.equal(res.status, 200)
  }

  // Every retried runA response succeeded with 200 AND redacted the rotated token
  const storedExchangeIds: string[] = []
  for (const { res, worker } of runAResults) {
    assert.equal(res.status, 200, 'each concurrent 401 request must retry cleanly to 200')
    assert.equal(res.body.includes(ROTATED_TOKEN), false, 'broker response body must redact rotated token')
    assert.equal(res.bodyPreview.includes(ROTATED_TOKEN), false, 'broker bodyPreview must redact rotated token')
    assert.equal(JSON.stringify(res.reqHeaders).includes(ROTATED_TOKEN), false, 'broker reqHeaders must redact rotated token')
    assert.equal(JSON.stringify(res.respHeaders).includes(ROTATED_TOKEN), false, 'broker respHeaders must redact rotated token')
    assert.equal(res.body.includes(EXPIRED_TOKEN), false, 'broker response must not leak expired token')

    // Persist exchange through the real Store path using worker.currentSecrets() (which now includes ROTATED_TOKEN)
    const secrets = worker.currentSecrets()
    assert.ok(
      secrets.some(s => s.value === ROTATED_TOKEN),
      'worker.currentSecrets() must include the newly rotated token',
    )
    const recorded = store.recordExchange({
      runId: runA.id,
      assignmentId: worker.assignmentId,
      scopeRevision: runA.scopeRevision,
      origin: res.origin,
      finalOrigin: res.finalOrigin,
      redirectOrigins: res.redirectOrigins,
      method: res.method,
      pathAndQuery: res.pathAndQuery,
      personaHandle: res.personaHandle,
      status: res.status,
      mediaType: res.mediaType,
      reqHeaders: { ...res.reqHeaders, Authorization: `Bearer ${ROTATED_TOKEN}` },
      respHeaders: { ...res.respHeaders, 'x-echo-credential': ROTATED_TOKEN },
      body: `{"ok":true,"rawEcho":"${ROTATED_TOKEN}","staleEcho":"${EXPIRED_TOKEN}"}`,
      durationMs: res.durationMs,
      secrets,
      secretMatches: res.secretMatches,
    })
    storedExchangeIds.push(recorded.id)
  }

  // Also record a run event carrying a Bearer token literal (verifying store.event redaction too)
  store.event(runA.id, 'reauth.completed', `Reauth rotated Bearer ${ROTATED_TOKEN}`, {
    reauthInvocations,
    status: 200,
  })
  store.flushNow()

  // Verify ZERO leakage of ROTATED_TOKEN or EXPIRED_TOKEN across stored exchanges, FTS index, blobs, and events
  for (const exId of storedExchangeIds) {
    const ex = store.getExchange(runA.id, exId)
    assert.ok(ex)
    const serialized = JSON.stringify({
      reqHeaders: ex.reqHeaders,
      respHeaders: ex.respHeaders,
      bodyPreview: ex.bodyPreview,
      pathAndQuery: ex.pathAndQuery,
    })
    assert.equal(serialized.includes(ROTATED_TOKEN), false, 'stored broker_exchanges row must redact rotated token')
    assert.equal(serialized.includes(EXPIRED_TOKEN), false, 'stored broker_exchanges row must redact expired token')
    if (ex.bodyArtifactId) {
      const blob = store.readBlob(ex.bodyArtifactId)
      assert.equal(blob.includes(ROTATED_TOKEN), false, 'stored body artifact blob must redact rotated token')
      assert.equal(blob.includes(EXPIRED_TOKEN), false, 'stored body artifact blob must redact expired token')
    }
  }

  // Raw SQLite scan of broker_exchanges and events tables for runA
  const leakedExchanges = store.client.prepare(
    `SELECT count(*) AS c FROM broker_exchanges
     WHERE run_id = ? AND (req_headers LIKE ? OR resp_headers LIKE ? OR body_preview LIKE ?)`,
  ).get(runA.id, `%${ROTATED_TOKEN}%`, `%${ROTATED_TOKEN}%`, `%${ROTATED_TOKEN}%`) as { c: number }
  assert.equal(Number(leakedExchanges.c), 0, 'zero raw rotated tokens allowed in broker_exchanges SQLite rows')

  const events = store.eventsAfter(runA.id, 0)
  assert.ok(events.length > 0, 'broker audit and run events must have been recorded for runA')
  for (const ev of events) {
    const rawEv = JSON.stringify(ev)
    assert.equal(rawEv.includes(ROTATED_TOKEN), false, `event ${ev.kind} leaked rotated token`)
    assert.equal(rawEv.includes(EXPIRED_TOKEN), false, `event ${ev.kind} leaked expired token`)
  }
})

// ---------------------------------------------------------------------------
// Property 4: Live dynamic maxRpsPerOrigin on an existing Grant
// ---------------------------------------------------------------------------

test('Prop 4: updating run.maxRpsPerOrigin mid-run changes the live rate observed on an existing Grant without rebuilding it', async t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  // Two loopback mock servers so runA and runB have distinct per-origin token buckets on the same RequestBroker
  const { origin: originA } = await startMockServer(t, (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end('{"run":"A"}')
  })
  const { origin: originB } = await startMockServer(t, (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end('{"run":"B"}')
  })

  const projectA = store.createProject({
    requestId: randomUUID(),
    name: 'Prop4 RunA',
    seeds: [originA],
    environment: 'local-lab',
  })
  const projectB = store.createProject({
    requestId: randomUUID(),
    name: 'Prop4 RunB',
    seeds: [originB],
    environment: 'local-lab',
  })

  // Start runA throttled at 3 RPS and runB fast at 50 RPS
  const runA = createLocalLabRun(store, projectA.id, { maxRpsPerOrigin: 3 })
  const runB = createLocalLabRun(store, projectB.id, { maxRpsPerOrigin: 50 })

  const execution = new Execution(store)
  t.after(() => execution.stop())

  // Build BOTH grants ONCE and never rebuild them
  const { grant: grantA } = buildWorkerGrant(execution, store, runA.id, originA, 'rps-runA')
  const { grant: grantB } = buildWorkerGrant(execution, store, runB.id, originB, 'rps-runB')

  assert.equal(grantA.maxRpsPerOrigin, 3)
  assert.equal(grantA.getMaxRpsPerOrigin?.(), 3)
  assert.equal(grantB.maxRpsPerOrigin, 50)

  const sendSequential = async (grant: Grant, origin: string, runId: string, count: number, tag: string) => {
    const start = Date.now()
    for (let i = 0; i < count; i += 1) {
      const res = await execution.broker.executeHttp({
        origin,
        method: 'GET',
        pathAndQuery: `/${tag}/${i}`,
        runId,
      }, grant, AbortSignal.timeout(5_000))
      assert.equal(res.status, 200)
    }
    return Date.now() - start
  }

  // Phase 1: runA at 3 RPS (initial 3 tokens + 2 refilled tokens => ~667ms) while concurrent runB runs fast at 50 RPS
  const [phase1MsA, phase1MsB] = await Promise.all([
    sendSequential(grantA, originA, runA.id, 5, 'p1-a'),
    sendSequential(grantB, originB, runB.id, 5, 'p1-b'),
  ])
  assert.ok(
    phase1MsA >= 480,
    `Phase 1 at 3 RPS (5 reqs after 3-token burst) should take >= 480ms, observed ${phase1MsA}ms`,
  )
  assert.ok(
    phase1MsB < 350,
    `Concurrent runB at 50 RPS (5 reqs) must stay fast (< 350ms), observed ${phase1MsB}ms`,
  )

  // Phase 2: Raise runA.maxRpsPerOrigin mid-run via real `raise_budget` command WITHOUT rebuilding grantA!
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId: runA.id,
    action: 'raise_budget',
    maxRpsPerOrigin: 60,
    resume: false,
  }))

  // Existing grantA immediately reflects 60 RPS; runB stays untouched at 50 RPS
  assert.equal(grantA.maxRpsPerOrigin, 60, 'existing Grant getter must immediately observe updated maxRpsPerOrigin=60')
  assert.equal(grantA.getMaxRpsPerOrigin?.(), 60)
  assert.equal(grantB.maxRpsPerOrigin, 50, 'runB Grant maxRpsPerOrigin must remain isolated at 50')

  // Immediately fire 14 requests from ~0 tokens on the EXACT SAME grantA:
  // At 60 RPS this finishes well under 900ms; at the stale 3 RPS it would take ~4,667ms!
  const phase2MsA = await sendSequential(grantA, originA, runA.id, 14, 'p2-a-fast')
  const phase2Rps = (14 * 1000) / Math.max(1, phase2MsA)
  assert.ok(
    phase2MsA < 900 && phase2Rps > 15,
    `Phase 2 after live bump to 60 RPS should finish < 900ms (>15 rps), observed ${phase2MsA}ms (${phase2Rps.toFixed(1)} rps)`,
  )

  // Phase 3: Lower runA.maxRpsPerOrigin back down to 2 RPS mid-run WITHOUT rebuilding grantA
  store.updateRun(runA.id, { maxRpsPerOrigin: 2 })
  assert.equal(grantA.maxRpsPerOrigin, 2, 'existing Grant must also observe mid-run throttle-down to 2 RPS')
  assert.equal(grantA.getMaxRpsPerOrigin?.(), 2)

  // Fire 3 requests: token bucket clamps to <= 2, so req 3 must wait ~500ms at 2 RPS (reliably >= 320ms)
  const phase3MsA = await sendSequential(grantA, originA, runA.id, 3, 'p3-a-slow')
  assert.ok(
    phase3MsA >= 320,
    `Phase 3 after live throttle-down to 2 RPS (3 reqs) should take >= 320ms, observed ${phase3MsA}ms`,
  )
})

// ---------------------------------------------------------------------------
// Property 5: Concurrent run deletion isolation
// ---------------------------------------------------------------------------

test('Prop 5: deleting runA while runB is actively writing events, facts, exchanges, and findings succeeds with zero unhandled rejections and zero impact on runB', async t => {
  enableLocalLab(t)
  const { dir, store } = makeTempStore(t)

  const unhandled: unknown[] = []
  const onUnhandled = (reason: unknown) => { unhandled.push(reason) }
  process.on('unhandledRejection', onUnhandled)
  t.after(() => { process.off('unhandledRejection', onUnhandled) })

  const { origin } = await startMockServer(t, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true, path: req.url ?? '/' }))
  })

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Prop5 Concurrent Deletion',
    seeds: [origin],
    environment: 'local-lab',
  })
  const runA = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80, goal: 'Run A to be deleted mid-flight' })
  const runB = createLocalLabRun(store, project.id, { maxRpsPerOrigin: 80, goal: 'Run B active writer' })

  const broker = new RequestBroker({ storage: store })
  const assetA = runA.candidates[0]!
  const assetB = runB.candidates[0]!

  const workerA = store.updateWorker(
    store.makeWorker(runA, 'investigation', assetA, 'worker-A', 'Seed runA', { sourceOrigins: [origin] }).id,
    { status: 'running', lease: randomUUID() },
  )!
  const workerB = store.updateWorker(
    store.makeWorker(runB, 'investigation', assetB, 'worker-B', 'Active writer runB', { sourceOrigins: [origin] }).id,
    { status: 'running', lease: randomUUID() },
  )!

  // Seed rich state on runA (events, facts, exchanges, findings, and on-disk run artifacts)
  for (let i = 0; i < 6; i += 1) {
    const ex = store.recordExchange({
      runId: runA.id,
      assignmentId: workerA.id,
      scopeRevision: runA.scopeRevision,
      origin,
      finalOrigin: origin,
      redirectOrigins: [],
      method: 'GET',
      pathAndQuery: `/runA/seed-${i}`,
      status: 200,
      mediaType: 'application/json',
      reqHeaders: {},
      respHeaders: { 'content-type': 'application/json' },
      body: JSON.stringify({ run: 'A', idx: i }),
      durationMs: 3,
    })
    store.addFact(runA, workerA, {
      kind: 'endpoint',
      origin,
      summary: `runA seed fact ${i}`,
      exchangeIds: [ex.id],
    })
    store.event(runA.id, 'prop.seed', `runA seed event ${i}`, { idx: i })
  }
  const runAArtifactDir = join(dir, 'artifacts', runA.id)
  mkdirSync(runAArtifactDir, { recursive: true })
  writeFileSync(join(runAArtifactDir, 'seed.txt'), 'runA artifact payload')

  const makePendingFinding = (runId: string, scopeRevision: number, idx: number): Finding => ({
    id: randomUUID(),
    origin,
    title: `Pending finding ${runId.slice(0, 6)} #${idx}`,
    category: 'broken-access-control',
    severity: 'medium',
    status: 'pending',
    reason: `Candidate observation ${idx} on /api/runB/items/${idx}`,
    remediation: 'Enforce per-tenant ownership check',
    evidenceIds: [],
    scopeRevision,
    cwe: 'CWE-639',
  })

  // Launch concurrent active writers for runB: HTTP broker calls + events + facts + exchanges + findings
  const TOTAL_ITERATIONS = 24
  const expectedFactSummaries: string[] = []
  const expectedFindingIds: string[] = []
  const expectedExchangeIds: string[] = []
  let deleteTriggered = false
  let deleteResult: { deleted: boolean; projectId: string; runId: string } | null = null

  const grantB = makeScopedGrant(origin, runB.id, runB.scopeRevision, 80)

  const writerTask = (async () => {
    for (let i = 0; i < TOTAL_ITERATIONS; i += 1) {
      // Interleave real broker HTTP I/O + synchronous Store writes across event loop turns
      const httpRes = await broker.executeHttp({
        origin,
        method: 'GET',
        pathAndQuery: `/runB/live-${i}`,
        runId: runB.id,
        assignmentId: workerB.id,
        scopeRevision: runB.scopeRevision,
      }, grantB, AbortSignal.timeout(5_000))
      assert.equal(httpRes.status, 200)

      const ex = store.recordExchange({
        runId: runB.id,
        assignmentId: workerB.id,
        scopeRevision: runB.scopeRevision,
        origin: httpRes.origin,
        finalOrigin: httpRes.finalOrigin,
        redirectOrigins: httpRes.redirectOrigins,
        method: httpRes.method,
        pathAndQuery: httpRes.pathAndQuery,
        status: httpRes.status,
        mediaType: httpRes.mediaType,
        reqHeaders: httpRes.reqHeaders,
        respHeaders: httpRes.respHeaders,
        body: httpRes.body,
        durationMs: httpRes.durationMs,
      })
      expectedExchangeIds.push(ex.id)

      const summary = `runB concurrent fact #${i}`
      store.addFact(runB, workerB, {
        kind: 'endpoint',
        origin,
        summary,
        exchangeIds: [ex.id],
      })
      expectedFactSummaries.push(summary)

      store.event(runB.id, 'prop.live_write', `runB live event #${i}`, { idx: i })

      if (i % 4 === 0) {
        const finding = makePendingFinding(runB.id, runB.scopeRevision, i)
        const spec = store.createReplaySpec(runB, workerB, finding.id, {
          version: 1,
          kind: 'static_ast_proof',
          origin,
          title: finding.title,
          category: 'broken-access-control',
          cwe: 'CWE-639',
          severity: 'medium',
          severityRationale: 'Candidate cross-tenant ownership gap.',
          impact: 'Cross-tenant read exposure.',
          remediation: finding.remediation,
          recheckInstructions: 'Replay with control and probe requests.',
          repo: 'app',
          file: `src/items-${i}.ts`,
          startLine: 1,
          endLine: 3,
          engine: 'ast-grep',
          ruleOrPattern: 'items.get(id)',
          runtimeProofGap: 'Pending runtime replay verification.',
          assertionsJq: '{ controlPassed: true, confirmed: (.static.verified == true), observed: "matched", expected: "no match" }',
        }, [origin])
        store.upsertChainFinding(runB, assetB.id, finding, spec.id, [origin], { provenance: 'agent_only' })
        expectedFindingIds.push(finding.id)
      }

      // Yield between iterations so the concurrent deletion task interleaves mid-stream
      await new Promise<void>(resolve => setImmediate(resolve))
    }
  })()

  // Concurrent deletion task deletes runA right in the middle of runB's live write stream
  const deleteTask = (async () => {
    await new Promise<void>(resolve => setTimeout(resolve, 15))
    deleteResult = store.deleteRun(runA.id)
    deleteTriggered = true
    // Second idempotent delete must also succeed cleanly without disturbing runB
    const secondDelete = store.deleteRun(runA.id)
    assert.deepEqual(secondDelete, { deleted: false, projectId: '', runId: runA.id })
  })()

  await Promise.all([writerTask, deleteTask])
  store.flushNow()
  // Allow any queued microtask event emitters to settle before asserting zero unhandled rejections
  await new Promise<void>(resolve => setImmediate(resolve))

  assert.equal(deleteTriggered, true)
  assert.deepEqual(deleteResult, { deleted: true, projectId: project.id, runId: runA.id })
  assert.equal(unhandled.length, 0, `expected zero unhandled rejections, got: ${unhandled.map(String).join('; ')}`)

  // Verify runA is completely purged from SQLite and disk
  for (const table of ['runs', 'assignments', 'events', 'facts', 'findings', 'broker_exchanges', 'broker_exchanges_fts']) {
    const col = table === 'runs' ? 'id' : 'run_id'
    const row = store.client.prepare(`SELECT count(*) AS c FROM ${table} WHERE ${col} = ?`).get(runA.id) as { c: number }
    assert.equal(Number(row.c), 0, `expected 0 remaining rows for deleted runA in ${table}`)
  }
  assert.equal(existsSync(runAArtifactDir), false, 'runA on-disk artifact directory must be removed')

  // Verify runB suffered ZERO data loss across events, facts, exchanges, and findings
  const detailB = store.runDetail(runB.id)
  assert.equal(detailB.run.id, runB.id)
  assert.equal(detailB.run.status, 'running')

  const factsB = store.listFacts(runB.id)
  assert.equal(factsB.length, expectedFactSummaries.length, 'all runB facts written across deleteRun(runA) must persist')
  for (const summary of expectedFactSummaries) {
    assert.ok(factsB.some(f => f.summary === summary), `missing runB fact: ${summary}`)
  }

  const liveEventsB = store.eventsAfter(runB.id, 0).filter(e => e.kind === 'prop.live_write')
  assert.equal(liveEventsB.length, TOTAL_ITERATIONS, 'all runB live events must persist')

  for (const exId of expectedExchangeIds) {
    assert.ok(store.getExchange(runB.id, exId), `missing runB exchange ${exId}`)
  }

  const findingRowsB = store.client.prepare(`SELECT id FROM findings WHERE run_id = ?`).all(runB.id) as Array<{ id: string }>
  assert.equal(findingRowsB.length, expectedFindingIds.length, 'all runB findings must persist')
  for (const fid of expectedFindingIds) {
    assert.ok(findingRowsB.some(r => r.id === fid), `missing runB finding ${fid}`)
  }

  // Post-deletion sanity: runB can still execute broker HTTP requests and write new facts cleanly
  const postDeleteHttp = await broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/runB/post-delete-ok',
    runId: runB.id,
    assignmentId: workerB.id,
    scopeRevision: runB.scopeRevision,
  }, grantB, AbortSignal.timeout(5_000))
  assert.equal(postDeleteHttp.status, 200)
  store.addFact(runB, workerB, { kind: 'endpoint', origin, summary: 'runB post-delete fact' })
  assert.equal(store.listFacts(runB.id).length, expectedFactSummaries.length + 1)
})
