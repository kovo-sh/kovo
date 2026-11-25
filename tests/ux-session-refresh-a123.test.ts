import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createPersona, runCommand } from '../src/domain.ts'
import { BrokerApprovalRequired, BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { PersonaSessionPool } from '../src/server/persona-auth.ts'
import {
  buildPersonaHeader,
  createProjectPersona,
  personaSecrets,
  resolveRunPersonas,
  writePersonaSessionFile,
} from '../src/server/persona-vault.ts'
import type { MintedPersonaSession, ResolvedPersona } from '../src/server/persona-vault.ts'
import { cloneWorkerPersona } from '../src/server/session-isolation.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'

const APP_ORIGIN = 'https://app.example.test'
const PUBLIC_ADDRESS = { address: '93.184.216.34', family: 4 }

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-a123-'))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return storage
}

function makeStubBroker(calls: Array<{ method: string; url: string; headers: Record<string, string> }>): RequestBroker {
  return new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { method?: string; headers?: Record<string, string> }) => {
      calls.push({ method: options?.method ?? 'GET', url: url.href, headers: { ...(options?.headers ?? {}) } })
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
}

function createProjectAndRun(
  storage: Store,
  opts: {
    origin?: string
    environment?: 'public' | 'local-lab'
    tier?: 0 | 1 | 2 | 3
    approvalPolicy?: 'auto_review' | 'yolo' | 'strict'
    budgetRequests?: number
    workerConcurrency?: number
    maxRpsPerOrigin?: number
    sandboxWriteAllowlist?: Array<{ origin: string; method: string; pathPattern: string }>
    approvedPersonaIds?: string[]
  } = {},
) {
  const origin = opts.origin ?? APP_ORIGIN
  const project = storage.createProject({
    requestId: randomUUID(),
    name: `UX A123 ${randomUUID().slice(0, 6)}`,
    seeds: [origin],
    environment: opts.environment ?? 'public',
    ...(opts.sandboxWriteAllowlist ? { sandboxWriteAllowlist: opts.sandboxWriteAllowlist } : {}),
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify A1/A2/A3 & Grant propagation',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 2,
    ...(opts.approvalPolicy ? { approvalPolicy: opts.approvalPolicy } : {}),
    ...(opts.budgetRequests !== undefined ? { budgetRequests: opts.budgetRequests } : {}),
    ...(opts.workerConcurrency !== undefined ? { workerConcurrency: opts.workerConcurrency } : {}),
    ...(opts.maxRpsPerOrigin !== undefined ? { maxRpsPerOrigin: opts.maxRpsPerOrigin } : {}),
  } as Parameters<Store['createRun']>[0])
  return { projectId: project.id, runId, origin }
}

function approveScopeForRun(
  storage: Store,
  runId: string,
  overrides: { approvedPersonaIds?: string[]; capabilityTier?: 0 | 1 | 2 | 3 } = {},
) {
  storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = storage.run(runId)
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    ...overrides,
  }))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  return storage.run(runId)
}

function buildExecutionGrant(
  execution: Execution,
  storage: Store,
  runId: string,
  origin = APP_ORIGIN,
): { grant: Grant; assignmentId: string; currentSecrets: () => Array<{ placeholder: string; value: string }> } {
  const run = storage.run(runId)
  const created = storage.makeWorker(run, 'investigation', run.candidates[0], 'A123 worker', 'Verify runtime contract', {
    sourceOrigins: [origin],
  })
  const assignment = storage.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
  const job = { assignment, origins: new Set([origin]), controller: new AbortController() }
  const priv = execution as unknown as Record<string, any>
  const built = priv.buildGrant(job, run, new Set([origin])) as {
    grant: Grant
    currentSecrets: () => Array<{ placeholder: string; value: string }>
  }
  return { grant: built.grant, assignmentId: assignment.id, currentSecrets: built.currentSecrets }
}

// ---------------------------------------------------------------------------
// 1. A1a: Live worker session refresh via sessionPool.rotate()
// ---------------------------------------------------------------------------

test('A1a: sessionPool.rotate() updates headers seen by an already-cloned worker persona on the next request', async t => {
  // Part 1: Standalone 3-arg cloneWorkerPersona (without currentSession getter) across flat cookie, bearer, and header sessions
  const pool = new PersonaSessionPool()

  const initialCookieSession: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=clerk_jwt_v1_aaaaaaaaaaaaaaaa; __client_uat=1700000001',
    adapterUsed: 'clerk_client',
  }
  pool.register('clerk_user', { session: initialCookieSession, allowlist: [APP_ORIGIN] })
  const baseClerkPersona: ResolvedPersona = {
    id: 'p-clerk',
    handle: 'clerk_user',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    headerName: null,
    secret: 'client-cookie-secret',
    canaryMarkers: [],
    session: initialCookieSession,
  }
  const clonedClerk = cloneWorkerPersona(baseClerkPersona, 'w-clerk-1', (h, wid) => pool.clone(h, wid))
  assert.ok(clonedClerk)
  assert.equal(
    buildPersonaHeader(clonedClerk.persona, APP_ORIGIN)?.Cookie,
    '__session=clerk_jwt_v1_aaaaaaaaaaaaaaaa; __client_uat=1700000001',
  )

  // Rotate Clerk 60s __session JWT (flat cookie, no v2 bundle)
  pool.rotate('clerk_user', {
    headerType: 'cookie',
    value: '__session=clerk_jwt_v2_bbbbbbbbbbbbbbbb; __client_uat=1700000036',
    adapterUsed: 'clerk_client',
  })
  assert.equal(
    buildPersonaHeader(clonedClerk.persona, APP_ORIGIN)?.Cookie,
    '__session=clerk_jwt_v2_bbbbbbbbbbbbbbbb; __client_uat=1700000036',
    'already-cloned flat cookie persona must immediately reflect rotated Clerk __session JWT',
  )

  // Flat bearer (Supabase / JSON login) rotation on 3-arg cloneWorkerPersona
  const initialBearer: MintedPersonaSession = {
    headerType: 'bearer',
    value: 'supabase_access_token_v1_aaaa',
    adapterUsed: 'supabase',
  }
  pool.register('supa_user', { session: initialBearer, allowlist: [APP_ORIGIN] })
  const clonedSupa = cloneWorkerPersona({
    ...baseClerkPersona,
    id: 'p-supa',
    handle: 'supa_user',
    session: initialBearer,
  }, 'w-supa-1', (h, wid) => pool.clone(h, wid))
  assert.ok(clonedSupa)
  assert.deepEqual(buildPersonaHeader(clonedSupa.persona, APP_ORIGIN), {
    Authorization: 'Bearer supabase_access_token_v1_aaaa',
  })
  pool.rotate('supa_user', {
    headerType: 'bearer',
    value: 'supabase_access_token_v2_bbbb',
    adapterUsed: 'supabase',
  })
  assert.deepEqual(buildPersonaHeader(clonedSupa.persona, APP_ORIGIN), {
    Authorization: 'Bearer supabase_access_token_v2_bbbb',
  })

  // Part 2: End-to-end through Execution.buildGrant() + RequestBroker + sibling logout isolation
  const storage = makeStorage(t)
  const { projectId, runId } = createProjectAndRun(storage, { tier: 2 })
  const createdPersona = createProjectPersona(storage, createPersona.parse({
    requestId: randomUUID(),
    projectId,
    handle: 'clerk_live',
    roleLabel: 'Clerk User',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'clerk_client', clientCookie: '__client=secret_clerk_client_cookie_value_1234' },
  }))
  approveScopeForRun(storage, runId, { approvedPersonaIds: [createdPersona.id] })
  const resolved = resolveRunPersonas(storage, projectId, [createdPersona.id]).get('clerk_live')!
  const v1: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=live_clerk_jwt_v1_1111111111111111; __client_uat=100',
    adapterUsed: 'clerk_client',
  }
  writePersonaSessionFile(resolved.sessionPath!, v1)

  const calls: Array<{ method: string; url: string; headers: Record<string, string> }> = []
  const execution = new Execution(storage, { broker: makeStubBroker(calls) })
  t.after(() => execution.stop())
  execution.personaAuth.registerSession('clerk_live', { session: v1, allowlist: [APP_ORIGIN] })

  const workerA = buildExecutionGrant(execution, storage, runId)
  const workerB = buildExecutionGrant(execution, storage, runId)

  await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/me',
    persona: 'clerk_live',
  }, workerA.grant, AbortSignal.timeout(5_000))
  assert.equal(calls[0]!.headers.Cookie, '__session=live_clerk_jwt_v1_1111111111111111; __client_uat=100')

  // Simulate 35s background refresher rotating sessionPool without rebuilding grants
  const v2: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=live_clerk_jwt_v2_2222222222222222; __client_uat=135',
    adapterUsed: 'clerk_client',
  }
  execution.personaAuth.sessions.rotate('clerk_live', v2)

  // Next request from ALREADY-CLONED workerA sends v2 immediately!
  await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/me',
    persona: 'clerk_live',
  }, workerA.grant, AbortSignal.timeout(5_000))
  assert.equal(calls[1]!.headers.Cookie, '__session=live_clerk_jwt_v2_2222222222222222; __client_uat=135')

  // Newly rotated token is also visible to personaSecrets() / currentSecrets() for redaction
  const secrets = workerA.currentSecrets()
  assert.ok(
    secrets.some(s => s.value.includes('live_clerk_jwt_v2_2222222222222222')),
    'currentSecrets() must include the rotated session token',
  )

  // Logging out workerB still isolates workerB while workerA keeps receiving v2
  assert.equal(execution.logoutWorkerSession(workerB.assignmentId), 1)
  assert.equal(buildPersonaHeader(workerB.grant.personas!.get('clerk_live')!, APP_ORIGIN), null)
  assert.equal(
    buildPersonaHeader(workerA.grant.personas!.get('clerk_live')!, APP_ORIGIN)?.Cookie,
    '__session=live_clerk_jwt_v2_2222222222222222; __client_uat=135',
  )
})

// ---------------------------------------------------------------------------
// 2. A1b: Broker 401 triggers Execution-wired reauth & retries cleanly
// ---------------------------------------------------------------------------

test('A1b: Execution.createBroker() wires reauth so a persona-bound 401 refreshes once and retries cleanly', async t => {
  const prevLocalLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLocalLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLocalLab
  })

  const observedCookies: string[] = []
  const server = createServer((req, res) => {
    const cookie = req.headers.cookie ?? ''
    observedCookies.push(cookie)
    if (cookie.includes('refreshed_jwt_token_999999999999')) {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      // Echo the token back to verify broker redacts the newly refreshed credential too
      res.end(JSON.stringify({ ok: true, echoed: 'refreshed_jwt_token_999999999999' }))
      return
    }
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'token_expired' }))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', () => resolve()))
  const labOrigin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  t.after(async () => {
    server.closeAllConnections?.()
    await new Promise<void>(resolve => server.close(() => resolve()))
  })

  const storage = makeStorage(t)
  const { projectId, runId } = createProjectAndRun(storage, {
    origin: labOrigin,
    environment: 'local-lab',
    tier: 2,
  })
  const createdPersona = createProjectPersona(storage, createPersona.parse({
    requestId: randomUUID(),
    projectId,
    handle: 'auto_reauth_user',
    roleLabel: 'Member',
    originAllowlist: [labOrigin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'clerk_client', clientCookie: '__client=clerk_reauth_secret_123456' },
  }))
  approveScopeForRun(storage, runId, { approvedPersonaIds: [createdPersona.id] })
  const resolved = resolveRunPersonas(storage, projectId, [createdPersona.id]).get('auto_reauth_user')!
  const staleSession: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=stale_jwt_token_000000000000',
    adapterUsed: 'clerk_client',
  }
  const freshSession: MintedPersonaSession = {
    headerType: 'cookie',
    value: '__session=refreshed_jwt_token_999999999999',
    adapterUsed: 'clerk_client',
  }
  writePersonaSessionFile(resolved.sessionPath!, staleSession)

  // Construct Execution WITHOUT options.broker so createBroker() wires reauth automatically!
  const execution = new Execution(storage)
  t.after(() => execution.stop())

  let refreshCount = 0
  execution.personaAuth.registerSession('auto_reauth_user', {
    session: staleSession,
    allowlist: [labOrigin],
    refresh: async () => {
      refreshCount += 1
      writePersonaSessionFile(resolved.sessionPath!, freshSession)
      return freshSession
    },
  })

  const { grant } = buildExecutionGrant(execution, storage, runId, labOrigin)
  const res = await execution.broker.executeHttp({
    origin: labOrigin,
    method: 'GET',
    pathAndQuery: '/api/protected',
    persona: 'auto_reauth_user',
  }, grant, AbortSignal.timeout(5_000))

  assert.equal(res.status, 200, '401 must trigger reauth and retry cleanly to 200')
  assert.equal(refreshCount, 1, 'reauth callback must run exactly once')
  assert.equal(observedCookies.length, 2, 'wire must see initial 401 attempt + refreshed retry')
  assert.ok(observedCookies[0]!.includes('stale_jwt_token_000000000000'))
  assert.ok(observedCookies[1]!.includes('refreshed_jwt_token_999999999999'))
  assert.ok(
    !res.body.includes('refreshed_jwt_token_999999999999'),
    'broker must redact the newly refreshed credential in the retried response body',
  )
})

// ---------------------------------------------------------------------------
// 3. A2: Per-run latestScopeRevision isolation
// ---------------------------------------------------------------------------

test('A2: bumping Run A scopeRevision to 3 does NOT cause BrokerDenied on Run B at scopeRevision 1', async () => {
  let setCookieForNext = ''
  const observedCookies: Array<{ path: string; cookie: string | undefined }> = []
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDRESS],
    transport: async (url: URL, _address: unknown, _signal: AbortSignal, options?: { headers?: Record<string, string> }) => {
      observedCookies.push({ path: url.pathname, cookie: options?.headers?.Cookie })
      const headers: Record<string, string> = { 'content-type': 'application/json' }
      if (setCookieForNext) {
        headers['set-cookie'] = setCookieForNext
        setCookieForNext = ''
      }
      return { status: 200, headers, body: '{"ok":true}' }
    },
  })

  const makeGrant = (runId: string, scopeRevision: number): Grant => ({
    tier: 1,
    scopeRevision,
    scopePolicy: {
      runId,
      mode: 'prod_readonly',
      targetOrigins: [APP_ORIGIN],
      authOrigins: [],
      assetOrigins: [],
      routeDenylist: [],
    },
    canRead: origin => origin === APP_ORIGIN,
    audit: () => undefined,
  })

  // Seed jars for both Run A (rev 1) and Run B (rev 1)
  setCookieForNext = 'sid=run_a_rev1_cookie; Path=/'
  await broker.executeHttp({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a-login',
    runId: 'run-a', assignmentId: 'w-a', session: 'jar', scopeRevision: 1,
  }, makeGrant('run-a', 1), AbortSignal.timeout(5_000))

  setCookieForNext = 'sid=run_b_rev1_cookie; Path=/'
  await broker.executeHttp({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b-login',
    runId: 'run-b', assignmentId: 'w-b', session: 'jar', scopeRevision: 1,
  }, makeGrant('run-b', 1), AbortSignal.timeout(5_000))

  // Bump Run A to scopeRevision 3 (both via executeHttp and explicit revokeScope(runId, rev))
  const runARev3 = await broker.executeHttp({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a-rev3',
    runId: 'run-a', assignmentId: 'w-a', session: 'jar', scopeRevision: 3,
  }, makeGrant('run-a', 3), AbortSignal.timeout(5_000))
  assert.equal(runARev3.status, 200)
  // Run A's stale rev-1 jar cookie must have been evicted
  assert.equal(observedCookies.at(-1)?.cookie, undefined, 'Run A rev-1 jar must be evicted on advance to rev 3')

  // Run A at stale rev 1 MUST still be rejected with BrokerDenied
  await assert.rejects(
    broker.executeHttp({
      origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/a-stale',
      runId: 'run-a', assignmentId: 'w-a', scopeRevision: 1,
    }, makeGrant('run-a', 1), AbortSignal.timeout(5_000)),
    (err: unknown) => err instanceof BrokerDenied && /stale/i.test(err.message),
  )

  // Run B at rev 1 MUST succeed cleanly (both with req.runId and with only grant.scopePolicy.runId)
  // AND its jar cookie must remain intact!
  const runBRes = await broker.executeHttp({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b-rev1',
    runId: 'run-b', assignmentId: 'w-b', session: 'jar', scopeRevision: 1,
  }, makeGrant('run-b', 1), AbortSignal.timeout(5_000))
  assert.equal(runBRes.status, 200)
  assert.equal(observedCookies.at(-1)?.cookie, 'sid=run_b_rev1_cookie', 'Run B jar must not be evicted by Run A scope bump')

  const runBFromPolicyRes = await broker.executeHttp({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/b-rev1-policy-id',
  }, makeGrant('run-b', 1), AbortSignal.timeout(5_000))
  assert.equal(runBFromPolicyRes.status, 200)

  // Legacy 1-arg revokeScope(5) must still work for default-scoped calls without locking out a new Run C at rev 1
  broker.revokeScope(5)
  const runCRes = await broker.executeHttp({
    origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/c-rev1',
    runId: 'run-c', scopeRevision: 1,
  }, makeGrant('run-c', 1), AbortSignal.timeout(5_000))
  assert.equal(runCRes.status, 200)

  await assert.rejects(
    broker.executeHttp({
      origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/default-stale',
      scopeRevision: 1,
    }, {
      tier: 1,
      scopeRevision: 1,
      canRead: origin => origin === APP_ORIGIN,
      audit: () => undefined,
    }, AbortSignal.timeout(5_000)),
    (err: unknown) => err instanceof BrokerDenied && /stale/i.test(err.message),
  )
})

// ---------------------------------------------------------------------------
// 4. A3: Unlimited requests (budgetRequests === 0) does NOT trip tightControlBounds in AIMD
// ---------------------------------------------------------------------------

test('A3: budgetRequests === 0 (Unlimited requests) does NOT trip tightControlBounds and keeps AIMD active', async t => {
  const makeNoopBackend = (capacities: number[]): WorkerBackend => ({
    setWarmCapacity(cap: number) { capacities.push(cap) },
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
        close: async () => undefined,
      }
    },
    async verifyStaticAst(_aid, req) {
      return { verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  })

  const runDispatchProbe = (budgetRequests: number): { maxConc: number; aimdConc: number; dispatchedCount: number } => {
    const storage = makeStorage(t)
    const { runId } = createProjectAndRun(storage, {
      tier: 1,
      budgetRequests,
      workerConcurrency: 1,
      maxRpsPerOrigin: 10,
    })
    const run = approveScopeForRun(storage, runId)
    // Seed 6 ready Phase-B chain steps so readyPrimarySteps >= PHASE_B_MIN_CONCURRENCY_FLOOR
    for (let i = 1; i <= 6; i += 1) {
      storage.addChainStep(run, {
        title: `Step ${i}`,
        category: 'broken-access-control',
        hypothesis: `Check route /api/items/${i}`,
        targetAssetIds: run.candidates.map(c => c.id),
        skills: ['bola-bfla'],
        sourceOrigins: [APP_ORIGIN],
      })
    }
    const capacities: number[] = []
    const execution = new Execution(storage, {
      broker: makeStubBroker([]),
      backend: makeNoopBackend(capacities),
      deterministicOnly: true,
    })
    t.after(() => execution.stop())

    const priv = execution as unknown as Record<string, any>
    // Stub floor lane & specialist spawn so we measure the exact Phase-B `maxConc` calculation
    // and dispatch slot count with zero network/LLM I/O.
    let dispatchedCount = 0
    priv.startDeterministicLane = () => false
    priv.startInvestigationStep = () => { dispatchedCount += 1 }
    priv.reconPlanner = { ensureWave1InvariantChainSteps: () => undefined }
    const freshRun = storage.run(runId)
    const controller = priv.phaseBControllerFor(freshRun)
    const aimdConc = controller.getEffectiveConcurrency({ remainingBudgetUsd: freshRun.budgetUsd }) as number
    priv.driveInvestigation(freshRun, [{ id: 'mock-profile', name: 'Mock', model: 'mock', endpoint: 'http://127.0.0.1:1', protocol: 'responses', apiKey: 'test' }])
    assert.ok(capacities.length >= 1, 'driveInvestigation must compute and apply Phase-B maxConc')
    return { maxConc: capacities[0]!, aimdConc, dispatchedCount }
  }

  // Unlimited requests (budgetRequests === 0): MUST use AIMD controller concurrency (not forced to 1!)
  const unlimited = runDispatchProbe(0)
  assert.ok(unlimited.aimdConc >= 2, `expected host AIMD warm-start >= 2, got ${unlimited.aimdConc}`)
  assert.equal(
    unlimited.maxConc,
    unlimited.aimdConc,
    'budgetRequests === 0 must treat remaining requests as Infinity and use AIMD concurrency',
  )
  assert.equal(
    unlimited.dispatchedCount,
    Math.min(6, unlimited.aimdConc),
    'unlimited-request run must dispatch full AIMD slot count instead of clamping to 1',
  )

  // Contrast: a genuinely tight finite request budget (5 < 30) still trips tightControlBounds -> configuredConcurrency (1)
  const tight = runDispatchProbe(5)
  assert.equal(tight.maxConc, 1, 'finite budgetRequests < 30 must still respect tightControlBounds')
  assert.equal(tight.dispatchedCount, 1)
})

// ---------------------------------------------------------------------------
// 5. Bug 4: project.sandboxWriteAllowlist & run.approvalPolicy propagate onto Grant
// ---------------------------------------------------------------------------

test('Grant propagation: project.sandboxWriteAllowlist and run.approvalPolicy propagate cleanly from Execution.buildGrant()', async t => {
  const storage = makeStorage(t)
  const allowlist = [{ origin: APP_ORIGIN, method: 'POST', pathPattern: '/api/sandbox/*' }]

  // Case A: Non-empty sandboxWriteAllowlist on a Tier-2 public run propagates onto Grant and authorizes matching POSTs
  const withAllowlist = createProjectAndRun(storage, {
    tier: 2,
    approvalPolicy: 'strict',
    sandboxWriteAllowlist: allowlist,
  })
  approveScopeForRun(storage, withAllowlist.runId)

  const calls: Array<{ method: string; url: string; headers: Record<string, string> }> = []
  const execution = new Execution(storage, { broker: makeStubBroker(calls) })
  t.after(() => execution.stop())

  const { grant: grantWithRules } = buildExecutionGrant(execution, storage, withAllowlist.runId)
  assert.deepEqual(grantWithRules.sandboxWriteAllowlist, allowlist)
  assert.equal(grantWithRules.approvalPolicy, 'strict')

  // Matching non-multipart POST on Tier-2 public run succeeds via sandboxWriteAllowlist
  const allowedPost = await execution.broker.executeHttp({
    origin: APP_ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/sandbox/create',
    headers: { 'Content-Type': 'application/json' },
    body: '{"ok":true}',
  }, grantWithRules, AbortSignal.timeout(5_000))
  assert.equal(allowedPost.status, 200)
  assert.equal(calls.length, 1)

  // Non-matching POST on the same Tier-2 public run is still denied
  await assert.rejects(
    execution.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/other/create',
      headers: { 'Content-Type': 'application/json' },
      body: '{"ok":true}',
    }, grantWithRules, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )
  assert.equal(calls.length, 1)

  // Case B: Empty sandboxWriteAllowlist is omitted from Grant so local-lab fallback is preserved
  const prevLocalLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLocalLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLocalLab
  })
  const emptyAllowlist = createProjectAndRun(storage, {
    origin: 'http://127.0.0.1:41234',
    environment: 'local-lab',
    tier: 2,
    approvalPolicy: 'auto_review',
  })
  approveScopeForRun(storage, emptyAllowlist.runId)
  const { grant: labGrant } = buildExecutionGrant(execution, storage, emptyAllowlist.runId, 'http://127.0.0.1:41234')
  assert.equal(
    labGrant.sandboxWriteAllowlist,
    undefined,
    'empty project.sandboxWriteAllowlist must be omitted so local-lab fallback stays intact',
  )
  assert.equal(labGrant.approvalPolicy, 'auto_review')

  // Case C: Live approvalPolicy switch mid-run still takes precedence on an existing Grant
  const t3 = createProjectAndRun(storage, { tier: 3, approvalPolicy: 'yolo' })
  approveScopeForRun(storage, t3.runId)
  const { grant: t3Grant } = buildExecutionGrant(execution, storage, t3.runId)
  assert.equal(t3Grant.approvalPolicy, 'yolo')

  // Switch live run to strict -> existing grant must now escalate writes with BrokerApprovalRequired!
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId: t3.runId,
    action: 'set_approval_policy',
    approvalPolicy: 'strict',
  }))
  await assert.rejects(
    execution.broker.executeHttp({
      origin: APP_ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/items',
      headers: { 'Content-Type': 'application/json' },
      body: '{"name":"x"}',
    }, t3Grant, AbortSignal.timeout(5_000)),
    BrokerApprovalRequired,
    'mid-run set_approval_policy(strict) must take live effect even on an already-built Grant',
  )
})
