import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { RequestListener } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { runCommand } from '../src/domain.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import {
  createProjectPersona,
  resolveRunPersonas,
  writePersonaSessionFile,
} from '../src/server/persona-vault.ts'
import type { MintedPersonaSession } from '../src/server/persona-vault.ts'
import { cleanupRunFilesOnDisk, isDeadRunFkError } from '../src/server/store-session.ts'
import { Store } from '../src/server/store.ts'

function enableLocalLab(t: { after(fn: () => void): void }) {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })
}

function makeTempStore(t: { after(fn: () => void): void }): { dir: string; store: Store } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-fix-m16-runid-vault-'))
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
    approvedPersonaIds?: string[]
  } = {},
) {
  const { id: runId } = store.createRun({
    requestId: randomUUID(),
    projectId,
    goal: opts.goal ?? 'Verify run-scoped lifecycle invariants',
    sourceMode: 'public',
    capabilityTier: opts.tier ?? 2,
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
  label = 'worker',
): {
  grant: Grant
  assignmentId: string
} {
  const run = store.run(runId)
  const asset = run.candidates.find(c => c.origin === origin) ?? run.candidates[0]!
  const created = store.makeWorker(run, 'investigation', asset, label, 'Verify runId isolation', {
    sourceOrigins: [origin],
  })
  const assignment = store.updateWorker(created.id, { status: 'running', lease: randomUUID() })!
  const job = { assignment, origins: new Set([origin]), controller: new AbortController() }
  const priv = execution as unknown as {
    buildGrant: (
      job: { assignment: typeof assignment; origins: Set<string>; controller: AbortController },
      run: ReturnType<Store['run']>,
      allowed: ReadonlySet<string>,
    ) => { grant: Grant }
  }
  const built = priv.buildGrant(job, run, new Set([origin]))
  return { grant: built.grant, assignmentId: assignment.id }
}

// ---------------------------------------------------------------------------
// 1. H-22: Live Execution passes run.id through cloneSession, sessions.session,
//    and Broker 401 reauth so identical `user-a` handles never collide across runs.
// ---------------------------------------------------------------------------

test('H-22: live Execution passes run.id through cloneSession, sessions.session, and Broker 401 reauth for identical handles', async t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const TOKEN_A_EXPIRED = 'tok_runA_expired_111111111111'
  const TOKEN_A_FRESH = 'tok_runA_fresh_222222222222'
  const TOKEN_B_INITIAL = 'tok_runB_initial_333333333333'
  const TOKEN_B_FRESH = 'tok_runB_fresh_444444444444'

  const observedAuth: Array<{ path: string; auth: string }> = []
  let expireRunB = false

  const { origin } = await startMockServer(t, (req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    observedAuth.push({ path: url.pathname, auth })

    if (url.pathname === '/runA') {
      if (auth === `Bearer ${TOKEN_A_EXPIRED}`) {
        res.writeHead(401, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'expired_runA' }))
        return
      }
      if (auth === `Bearer ${TOKEN_A_FRESH}`) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, owner: 'runA' }))
        return
      }
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'wrong_run_credential', got: auth }))
      return
    }

    if (url.pathname === '/runB') {
      if (auth === `Bearer ${TOKEN_B_INITIAL}` && !expireRunB) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, owner: 'runB', phase: 'initial' }))
        return
      }
      if (auth === `Bearer ${TOKEN_B_INITIAL}` && expireRunB) {
        res.writeHead(401, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'expired_runB' }))
        return
      }
      if (auth === `Bearer ${TOKEN_B_FRESH}`) {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, owner: 'runB', phase: 'fresh' }))
        return
      }
      res.writeHead(403, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'wrong_run_credential', got: auth }))
      return
    }

    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'unauthorized' }))
  })

  // Two separate projects (and a third unauthenticated run) all using the exact same handle `user-a`
  const projectA = store.createProject({
    requestId: randomUUID(),
    name: 'H22 Project A',
    seeds: [origin],
    environment: 'local-lab',
  })
  const projectB = store.createProject({
    requestId: randomUUID(),
    name: 'H22 Project B',
    seeds: [origin],
    environment: 'local-lab',
  })
  const projectC = store.createProject({
    requestId: randomUUID(),
    name: 'H22 Project C',
    seeds: [origin],
    environment: 'local-lab',
  })

  const personaA = createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectA.id,
    handle: 'user-a',
    roleLabel: 'Run A User',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'json', loginUrl: `${origin}/login`, email: 'a@example.test' },
    canaryMarkers: [],
  })
  const personaB = createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectB.id,
    handle: 'user-a',
    roleLabel: 'Run B User',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'json', loginUrl: `${origin}/login`, email: 'b@example.test' },
    canaryMarkers: [],
  })
  const personaC = createProjectPersona(store, {
    requestId: randomUUID(),
    projectId: projectC.id,
    handle: 'user-a',
    roleLabel: 'Run C Unregistered User',
    originAllowlist: [origin],
    authKind: 'login',
    secret: 'unused',
    loginConfig: { adapter: 'json', loginUrl: `${origin}/login`, email: 'c@example.test' },
    canaryMarkers: [],
  })

  const runA = createLocalLabRun(store, projectA.id, { approvedPersonaIds: [personaA.id] })
  const runB = createLocalLabRun(store, projectB.id, { approvedPersonaIds: [personaB.id] })
  const runC = createLocalLabRun(store, projectC.id, { approvedPersonaIds: [personaC.id] })

  const resolvedA = resolveRunPersonas(store, projectA.id, [personaA.id]).get('user-a')!
  const resolvedB = resolveRunPersonas(store, projectB.id, [personaB.id]).get('user-a')!
  const resolvedC = resolveRunPersonas(store, projectC.id, [personaC.id]).get('user-a')!

  const sessionAExpired: MintedPersonaSession = { headerType: 'bearer', value: TOKEN_A_EXPIRED, adapterUsed: 'json_login' }
  const sessionAFresh: MintedPersonaSession = { headerType: 'bearer', value: TOKEN_A_FRESH, adapterUsed: 'json_login' }
  const sessionBInitial: MintedPersonaSession = { headerType: 'bearer', value: TOKEN_B_INITIAL, adapterUsed: 'json_login' }
  const sessionBFresh: MintedPersonaSession = { headerType: 'bearer', value: TOKEN_B_FRESH, adapterUsed: 'json_login' }

  writePersonaSessionFile(resolvedA.sessionPath!, sessionAExpired)
  writePersonaSessionFile(resolvedB.sessionPath!, sessionBInitial)
  writePersonaSessionFile(resolvedC.sessionPath!, { headerType: 'bearer', value: 'tok_runC_file_only_5555555555', adapterUsed: 'json_login' })

  const execution = new Execution(store)
  t.after(() => execution.stop())

  let refreshCallsA = 0
  let refreshCallsB = 0

  // Register both runs under the EXACT SAME handle `user-a`, keyed by runId!
  execution.personaAuth.registerSession('user-a', {
    session: sessionAExpired,
    allowlist: [origin],
    runId: runA.id,
    refresh: async () => {
      refreshCallsA += 1
      writePersonaSessionFile(resolvedA.sessionPath!, sessionAFresh)
      return sessionAFresh
    },
  }, runA.id)

  execution.personaAuth.registerSession('user-a', {
    session: sessionBInitial,
    allowlist: [origin],
    runId: runB.id,
    refresh: async () => {
      refreshCallsB += 1
      writePersonaSessionFile(resolvedB.sessionPath!, sessionBFresh)
      return sessionBFresh
    },
  }, runB.id)

  // Build grants for runA, runB, and runC (which has NO pool entry for `user-a`)
  const workerA = buildWorkerGrant(execution, store, runA.id, origin, 'worker-a')
  const workerB = buildWorkerGrant(execution, store, runB.id, origin, 'worker-b')
  const workerC = buildWorkerGrant(execution, store, runC.id, origin, 'worker-c')

  // Verify cloneSession + sessions.session resolved each run's OWN pool entry (not the latest-registered entry)
  assert.equal(workerA.grant.personas?.get('user-a')?.session?.value, TOKEN_A_EXPIRED)
  assert.equal(workerB.grant.personas?.get('user-a')?.session?.value, TOKEN_B_INITIAL)
  // Run C must NOT inherit Run A or Run B's pool entry!
  assert.equal(workerC.grant.personas?.get('user-a')?.session?.value, 'tok_runC_file_only_5555555555')

  // Execute concurrent requests: runA hits 401 -> refreshes ONLY runA -> retries to 200; runB succeeds with its own token
  const [resA, resB] = await Promise.all([
    execution.broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: '/runA',
      runId: runA.id,
      assignmentId: workerA.assignmentId,
      persona: 'user-a',
    }, workerA.grant, AbortSignal.timeout(5_000)),
    execution.broker.executeHttp({
      origin,
      method: 'GET',
      pathAndQuery: '/runB',
      runId: runB.id,
      assignmentId: workerB.assignmentId,
      persona: 'user-a',
    }, workerB.grant, AbortSignal.timeout(5_000)),
  ])

  assert.equal(resA.status, 200, 'runA must refresh its own user-a entry on 401 and retry to 200')
  assert.equal(resB.status, 200, 'runB must authenticate cleanly with its own user-a entry')
  assert.equal(refreshCallsA, 1, 'runA refresh must run once')
  assert.equal(refreshCallsB, 0, 'runB refresh must NOT be triggered by runA 401')

  // Live sessions.session getter on workerA now reflects TOKEN_A_FRESH while workerB still sees TOKEN_B_INITIAL
  assert.equal(workerA.grant.personas?.get('user-a')?.session?.value, TOKEN_A_FRESH)
  assert.equal(workerB.grant.personas?.get('user-a')?.session?.value, TOKEN_B_INITIAL)

  // Now expire runB and verify broker 401 refreshes ONLY runB (even when req.runId is omitted and derived from grant.scopePolicy.runId)
  expireRunB = true
  const resB2 = await execution.broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/runB',
    assignmentId: workerB.assignmentId,
    persona: 'user-a',
  }, workerB.grant, AbortSignal.timeout(5_000))
  assert.equal(resB2.status, 200, 'runB must refresh its own user-a entry on 401 via grant.scopePolicy.runId')
  assert.equal(refreshCallsB, 1, 'runB refresh must run once')
  assert.equal(refreshCallsA, 1, 'runA refresh must NOT be re-invoked by runB 401')
  assert.equal(workerB.grant.personas?.get('user-a')?.session?.value, TOKEN_B_FRESH)

  // Run C getting a 401 must NOT trigger runA or runB's refresh handler!
  const resC = await execution.broker.executeHttp({
    origin,
    method: 'GET',
    pathAndQuery: '/runC',
    runId: runC.id,
    assignmentId: workerC.assignmentId,
    persona: 'user-a',
  }, workerC.grant, AbortSignal.timeout(5_000))
  assert.equal(resC.status, 401)
  assert.equal(refreshCallsA, 1, 'runC 401 must never trigger runA refresh')
  assert.equal(refreshCallsB, 1, 'runC 401 must never trigger runB refresh')

  // Verify wire traffic never crossed credentials between runs
  assert.ok(observedAuth.some(e => e.path === '/runA' && e.auth === `Bearer ${TOKEN_A_EXPIRED}`))
  assert.ok(observedAuth.some(e => e.path === '/runA' && e.auth === `Bearer ${TOKEN_A_FRESH}`))
  assert.ok(observedAuth.some(e => e.path === '/runB' && e.auth === `Bearer ${TOKEN_B_INITIAL}`))
  assert.ok(observedAuth.some(e => e.path === '/runB' && e.auth === `Bearer ${TOKEN_B_FRESH}`))
  assert.equal(observedAuth.some(e => e.path === '/runA' && e.auth.includes('runB')), false)
  assert.equal(observedAuth.some(e => e.path === '/runB' && e.auth.includes('runA')), false)
})

// ---------------------------------------------------------------------------
// 2. M-16: Deleting runA while a queued batch contains writes for both runA
//    and runB drops runA's dead-run FK rows cleanly while committing runB's
//    writes with ZERO SQLite queue poisoning.
// ---------------------------------------------------------------------------

test('M-16: multi-run batch flush drops deleted runA FK writes while committing live runB writes without poisoning SQLite', t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'M16 Queue Isolation',
    seeds: ['http://127.0.0.1:9999'],
    environment: 'local-lab',
  })
  const runA = createLocalLabRun(store, project.id, { goal: 'Run A (will be deleted mid-batch)' })
  const runB = createLocalLabRun(store, project.id, { goal: 'Run B (stays alive)' })

  const workerA = store.makeWorker(runA, 'investigation', runA.candidates[0]!, 'worker-a', 'Run A work')
  const workerB = store.makeWorker(runB, 'investigation', runB.candidates[0]!, 'worker-b', 'Run B work')

  const makeExchangeInput = (runId: string, assignmentId: string, scopeRevision: number, pathAndQuery: string) => ({
    runId,
    assignmentId,
    scopeRevision,
    origin: 'http://127.0.0.1:9999',
    finalOrigin: 'http://127.0.0.1:9999',
    redirectOrigins: [] as string[],
    method: 'GET',
    pathAndQuery,
    personaHandle: null,
    status: 200,
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: { 'content-type': 'application/json' },
    body: `{"path":"${pathAndQuery}"}`,
    durationMs: 4,
  })

  // Delete runA via Store.deleteRun while late exchanges for runA arrive alongside live runB writes
  store.deleteRun(runA.id)

  // Queue interleaved exchanges for deleted runA and live runB into the SAME pending batch (synchronously, before microtask flush)
  const exA1 = store.recordExchange(makeExchangeInput(runA.id, workerA.id, runA.scopeRevision, '/runA/first'))
  const exB1 = store.recordExchange(makeExchangeInput(runB.id, workerB.id, runB.scopeRevision, '/runB/first'))
  const exA2 = store.recordExchange(makeExchangeInput(runA.id, workerA.id, runA.scopeRevision, '/runA/second'))
  const exB2 = store.recordExchange(makeExchangeInput(runB.id, workerB.id, runB.scopeRevision, '/runB/second'))

  const sessionPriv = (store as unknown as {
    session: {
      pendingExchanges: unknown[]
      client: { prepare: (sql: string) => { get: (...args: unknown[]) => { c?: number } } }
    }
  }).session
  assert.equal(sessionPriv.pendingExchanges.length, 4, 'all 4 mixed runA+runB exchanges must be in one batch before flushNow()')

  // Flushing MUST NOT throw and MUST NOT poison SQLite!
  assert.doesNotThrow(() => store.flushNow())
  assert.equal(sessionPriv.pendingExchanges.length, 0, 'queue must be completely drained after per-item FK isolation')

  // Both live runB exchanges committed cleanly with accurate counters and FTS indexing
  const loadedB1 = store.getExchange(runB.id, exB1.id)
  const loadedB2 = store.getExchange(runB.id, exB2.id)
  assert.equal(loadedB1?.pathAndQuery, '/runB/first')
  assert.equal(loadedB2?.pathAndQuery, '/runB/second')
  assert.equal(store.run(runB.id).spentRequests, 2, 'runB spent_requests must reflect both committed writes')

  // Dead runA rows were cleanly dropped
  const runARows = sessionPriv.client.prepare('SELECT count(*) AS c FROM broker_exchanges WHERE run_id = ?').get(runA.id)
  assert.equal(Number(runARows?.c ?? 0), 0, 'deleted runA must have zero rows persisted')
  assert.ok(exA1.id && exA2.id)

  // Single-item dead-run FK write also drops cleanly without poisoning
  store.recordExchange(makeExchangeInput(runA.id, workerA.id, runA.scopeRevision, '/runA/solo-stale'))
  assert.doesNotThrow(() => store.flushNow())

  // Subsequent writes & reads on runB stay 100% healthy (zero lingering flushError or stuck queue)
  const exB3 = store.recordExchange(makeExchangeInput(runB.id, workerB.id, runB.scopeRevision, '/runB/after-recovery'))
  assert.doesNotThrow(() => store.flushNow())
  assert.equal(store.getExchange(runB.id, exB3.id)?.pathAndQuery, '/runB/after-recovery')
  assert.equal(store.run(runB.id).spentRequests, 3)

  // Verify helper classification: FK / Run not found are dead-run errors, generic I/O errors are NOT
  assert.equal(isDeadRunFkError(new Error('FOREIGN KEY constraint failed')), true)
  assert.equal(isDeadRunFkError(Object.assign(new Error('constraint'), { code: 'SQLITE_CONSTRAINT_FOREIGNKEY' })), true)
  assert.equal(isDeadRunFkError(Object.assign(new Error('constraint'), { errcode: 787 })), true)
  assert.equal(isDeadRunFkError(new Error('Run not found.')), true)
  assert.equal(isDeadRunFkError(new Error('SQLITE_IOERR: disk I/O error')), false)
  assert.equal(isDeadRunFkError(new Error('database or disk is full')), false)
})

test('M-16: flushNow still rethrows genuine non-FK storage errors instead of swallowing them', t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'M16 Non-FK Error',
    seeds: ['http://127.0.0.1:9999'],
    environment: 'local-lab',
  })
  const run = createLocalLabRun(store, project.id)
  const worker = store.makeWorker(run, 'investigation', run.candidates[0]!, 'worker-io', 'Work')

  // Install a trigger that raises a genuine non-FK ABORT error on insert into broker_exchanges
  const rawClient = (store as unknown as { session: { client: { exec: (sql: string) => void } } }).session.client
  rawClient.exec(`
    CREATE TRIGGER test_fail_non_fk BEFORE INSERT ON broker_exchanges
    BEGIN
      SELECT RAISE(ABORT, 'simulated disk I/O fault');
    END;
  `)

  store.recordExchange({
    runId: run.id,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin: 'http://127.0.0.1:9999',
    finalOrigin: 'http://127.0.0.1:9999',
    redirectOrigins: [],
    method: 'GET',
    pathAndQuery: '/io-fail',
    personaHandle: null,
    status: 200,
    mediaType: 'text/plain',
    reqHeaders: {},
    respHeaders: {},
    body: 'ok',
    durationMs: 1,
  })

  assert.throws(() => store.flushNow(), (err: unknown) => {
    const e = err as { message?: string; cause?: { message?: string } }
    return /simulated disk I\/O fault/.test(e?.message ?? '') || /simulated disk I\/O fault/.test(e?.cause?.message ?? '')
  })

  // Non-FK failing batch must remain queued (not silently dropped)
  const pending = (store as unknown as { session: { pendingExchanges: unknown[] } }).session.pendingExchanges
  assert.equal(pending.length, 1, 'genuine non-FK failure must retain the queued item rather than dropping it')
})

// ---------------------------------------------------------------------------
// 3. M-28: cleanupRunFilesOnDisk removes capability-vaults/<runId>.json AND
//    Execution evicts capabilityVaults on run finalization and Execution.stop().
// ---------------------------------------------------------------------------

test('M-28: cleanupRunFilesOnDisk removes capability-vaults/<runId>.json and Execution evicts capabilityVaults on finalization and stop()', async t => {
  enableLocalLab(t)
  const { dir, store } = makeTempStore(t)

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'M28 Vault Cleanup',
    seeds: ['http://127.0.0.1:9999'],
    environment: 'local-lab',
  })
  const runA = createLocalLabRun(store, project.id, { goal: 'Vault run A' })
  const runB = createLocalLabRun(store, project.id, { goal: 'Vault run B' })

  const execution = new Execution(store)
  const vaultsMap = (execution as unknown as { capabilityVaults: Map<string, unknown> }).capabilityVaults

  // Create & persist capability vault files for both runs
  const vaultA = execution.capabilityVaultFor(runA.id)
  const vaultB = execution.capabilityVaultFor(runB.id)
  vaultA.seal({
    hopReceiptId: 'hop_a1',
    slot: 'token',
    rawValue: 'secret-derived-token-runA-1234567890',
  })
  vaultB.seal({
    hopReceiptId: 'hop_b1',
    slot: 'token',
    rawValue: 'secret-derived-token-runB-1234567890',
  })

  const vaultFileA = join(dir, 'capability-vaults', `${runA.id}.json`)
  const vaultFileB = join(dir, 'capability-vaults', `${runB.id}.json`)
  assert.equal(existsSync(vaultFileA), true, 'runA capability vault file must exist on disk')
  assert.equal(existsSync(vaultFileB), true, 'runB capability vault file must exist on disk')
  assert.equal(vaultsMap.has(runA.id), true)
  assert.equal(vaultsMap.has(runB.id), true)

  // Direct unit check on cleanupRunFilesOnDisk: removes runA's vault file without touching runB's
  cleanupRunFilesOnDisk(dir, runA.id, [], [])
  assert.equal(existsSync(vaultFileA), false, 'cleanupRunFilesOnDisk must remove capability-vaults/<runA>.json')
  assert.equal(existsSync(vaultFileB), true, 'cleanupRunFilesOnDisk must not touch sibling runB vault file')

  // Also check end-to-end Store.deleteRun removes a run's vault file on disk
  mkdirSync(join(dir, 'capability-vaults'), { recursive: true })
  writeFileSync(vaultFileA, '{"runId":"a"}', { mode: 0o600 })
  assert.equal(existsSync(vaultFileA), true)
  store.deleteRun(runA.id)
  assert.equal(existsSync(vaultFileA), false, 'Store.deleteRun must remove capability-vaults/<runA>.json')

  // Finalizing runB via scheduleFinalReport evicts runB from RAM capabilityVaults
  store.updateRun(runB.id, { phase: 'verification', status: 'running' })
  const runBVerifying = store.run(runB.id)
  ;(execution as unknown as { scheduleFinalReport: (r: typeof runBVerifying) => void }).scheduleFinalReport(runBVerifying)
  assert.equal(store.run(runB.id).status, 'complete')
  assert.equal(vaultsMap.has(runB.id), false, 'scheduleFinalReport must evict completed runB capability vault from RAM')

  // Re-cache a run vault and verify Execution.stop() clears capabilityVaults completely
  const runC = createLocalLabRun(store, project.id, { goal: 'Vault run C' })
  execution.capabilityVaultFor(runC.id)
  assert.equal(vaultsMap.has(runC.id), true)
  await execution.stop()
  assert.equal(vaultsMap.size, 0, 'Execution.stop() must clear all cached capabilityVaults')
})

// ---------------------------------------------------------------------------
// 4. M-10: Aborting a deterministic floor lane during Phase A must NOT mark
//    `agenticLaneCompleted` so resuming re-runs the deterministic floor.
// ---------------------------------------------------------------------------

test('M-10: aborting Phase A deterministic floor lane does NOT mark agenticLaneCompleted; normal completion does', async t => {
  enableLocalLab(t)
  const { store } = makeTempStore(t)

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'M10 Floor Abort',
    seeds: ['http://127.0.0.1:9999'],
    environment: 'local-lab',
  })
  const run = createLocalLabRun(store, project.id, { goal: 'Verify Phase A pause/resume floor' })

  const execution = new Execution(store, { deterministicSweep: 'always' })
  t.after(() => execution.stop())

  type PrivExec = {
    agenticLaneCompleted: Set<string>
    agenticLaneJobs: Map<string, { controller: AbortController; key: string; promise: Promise<void> }>
    deterministicLaneKey: (r: typeof run) => string
    shouldStartDeterministicLane: (r: typeof run, profiles: readonly unknown[]) => boolean
    startDeterministicLane: (r: typeof run, profiles: readonly unknown[]) => boolean
    abortAgenticLane: (r: typeof run, reason: string) => Promise<void>
    runEngineInvestigation: (r: typeof run, opts: { signal: AbortSignal }) => Promise<void>
  }
  const priv = execution as unknown as PrivExec
  const fakeProfiles = [{ id: 'p1', name: 'Test Model' }]
  const key = priv.deterministicLaneKey(run)

  // First invocation: stay pending until aborted (simulating pause mid-Phase A)
  let engineCalls = 0
  let resolveSecondRun: (() => void) | null = null
  priv.runEngineInvestigation = async (_r, opts) => {
    engineCalls += 1
    if (engineCalls === 1) {
      await new Promise<void>((_, reject) => {
        if (opts.signal.aborted) {
          reject(new Error('aborted'))
          return
        }
        opts.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
      })
      return
    }
    await new Promise<void>(resolve => {
      resolveSecondRun = resolve
    })
  }

  // Start Phase A floor lane
  assert.equal(priv.startDeterministicLane(run, fakeProfiles), true)
  assert.equal(priv.agenticLaneJobs.has(run.id), true)
  assert.equal(engineCalls, 1)

  // Abort Phase A mid-flight (e.g. operator paused run)
  store.updateRun(run.id, { status: 'paused' })
  await priv.abortAgenticLane(run, 'operator paused during Phase A')

  // Key must NOT be marked completed after abort!
  assert.equal(priv.agenticLaneJobs.has(run.id), false)
  assert.equal(priv.agenticLaneCompleted.has(key), false, 'aborted Phase A must NOT mark agenticLaneCompleted')

  // Resume Phase A and let it finish cleanly without abort
  store.updateRun(run.id, { status: 'running' })
  const resumedRun = store.run(run.id)
  assert.equal(
    priv.shouldStartDeterministicLane(resumedRun, fakeProfiles),
    true,
    'resumed run must still be eligible to start Phase A deterministic floor',
  )
  assert.equal(priv.startDeterministicLane(resumedRun, fakeProfiles), true)
  assert.equal(engineCalls, 2)
  const secondPromise = priv.agenticLaneJobs.get(run.id)!.promise
  resolveSecondRun!()
  await secondPromise

  assert.equal(priv.agenticLaneCompleted.has(key), true, 'completed Phase A MUST mark agenticLaneCompleted')
  assert.equal(priv.shouldStartDeterministicLane(resumedRun, fakeProfiles), false)
})
