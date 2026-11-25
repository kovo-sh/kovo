import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { createKovoLocalServer } from '../scripts/serve.ts'
import {
  createRunWithAsyncDiscovery,
  isSubdomainDiscoveryPendingFromEvents,
  launchSubdomainDiscoveryInBackground,
  SUBDOMAIN_DISCOVERY_TIMEOUT_MS,
} from '../src/actions.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { GlobalKillSwitch, globalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import { PersonaAuthManager, personaPoolKey, PersonaSessionPool } from '../src/server/persona-auth.ts'
import type { MintedPersonaSession } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'
import type { RunDiscoverySubdomainsResult } from '../src/server/subdomain-discovery.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeGrant(tenantId?: string): Grant {
  const origin = 'https://app.example.test'
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 50,
    canRead: o => o === origin,
    audit: () => {},
    ...(tenantId ? { tenantId } : {}),
  }
}

async function availablePort(): Promise<number> {
  const probe = createServer().listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const address = probe.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate port')
  await new Promise<void>(r => probe.close(() => r()))
  return address.port
}

function makeCookieSession(cookieValue: string, origin = 'https://app.example.test'): MintedPersonaSession {
  const host = new URL(origin).hostname
  return {
    headerType: 'cookie',
    value: `sid=${cookieValue}`,
    adapterUsed: 'json',
    updatedAt: Date.now(),
    bundle: {
      v: 2,
      cookies: [{ name: 'sid', value: cookieValue, domain: host, path: '/' }],
    },
  }
}

// ---------------------------------------------------------------------------
// 1. H-1 + H-2 + M-18: Shared GlobalKillSwitch + serve.ts wiring + tenant isolation
// ---------------------------------------------------------------------------

test('H-1 + M-18: serve.ts wires shared globalKillSwitch & store; HTTP /api/ops/kill-switch trips exact RequestBroker instance', async t => {
  // Static wiring guard on scripts/serve.ts main()
  const serveSrc = readFileSync(join(REPO_ROOT, 'scripts', 'serve.ts'), 'utf8')
  assert.match(serveSrc, /configureGlobalKillSwitch\(/, 'serve.ts main() must configure the shared globalKillSwitch')
  assert.match(serveSrc, /const sharedStore = store\(\)/, 'serve.ts main() must obtain the shared store()')
  assert.match(
    serveSrc,
    /createKovoLocalServer\(\{[\s\S]*?killSwitch:\s*sharedKillSwitch[\s\S]*?store:\s*sharedStore/,
    'serve.ts main() must pass shared killSwitch and store into createKovoLocalServer()',
  )

  // Process-wide singleton uses globalThis[Symbol.for('kovo.globalKillSwitch')] so Vite SSR bundle + Node ESM share one instance
  const sym = Symbol.for('kovo.globalKillSwitch')
  assert.equal((globalThis as Record<symbol, unknown>)[sym], globalKillSwitch)

  const dir = mkdtempSync(join(tmpdir(), 'kovo-t1-serve-ks-'))
  t.after(() => {
    globalKillSwitch.reset()
    rmSync(dir, { recursive: true, force: true })
  })

  const storage = new Store(join(dir, 'data'))
  t.after(() => storage.close())

  const port = await availablePort()
  const local = createKovoLocalServer({
    app: { fetch: () => new Response('ok', { status: 200 }) },
    directory: join(dir, 'srv'),
    port,
    // Default killSwitch must resolve to globalKillSwitch; store attached explicitly
    store: storage,
  })
  local.server.listen(port, '127.0.0.1')
  await once(local.server, 'listening')
  t.after(async () => {
    local.server.closeAllConnections()
    await new Promise<void>(r => local.server.close(() => r()))
  })

  const baseUrl = `http://127.0.0.1:${port}`
  const boot = await fetch(local.bootstrapUrl(baseUrl), { redirect: 'manual' })
  assert.equal(boot.status, 303)
  const cookie = (boot.headers.get('set-cookie') ?? '').split(';')[0]!

  // RequestBroker using the default process-wide globalKillSwitch (same as production Execution)
  let transportCalls = 0
  const broker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => {
      transportCalls += 1
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }
    },
  })
  const caller = new AbortController()

  // Before trip -> broker allows traffic
  const okBefore = await broker.executeHttp(
    { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/ok' },
    makeGrant('tenant-alpha'),
    caller.signal,
  )
  assert.equal(okBefore.status, 200)
  assert.equal(transportCalls, 1)

  // Trip ONLY tenant-alpha via HTTP -> tenant-alpha blocked, tenant-beta allowed, global status STILL inactive
  const tripTenantRes = await fetch(`${baseUrl}/api/ops/kill-switch`, {
    method: 'POST',
    headers: { cookie, origin: baseUrl, 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'trip', tenantId: 'tenant-alpha', reason: 'Tenant alpha pause' }),
  })
  assert.equal(tripTenantRes.status, 200)
  const tripTenantBody = await tripTenantRes.json() as { active: boolean; tenantId: string | null }
  assert.equal(tripTenantBody.active, true)
  assert.equal(tripTenantBody.tenantId, 'tenant-alpha')

  // Global status must remain inactive!
  const globalStatus = await (await fetch(`${baseUrl}/api/ops/kill-switch`, { headers: { cookie } })).json() as { active: boolean; tenantId: string | null }
  assert.equal(globalStatus.active, false, 'tenant-scoped trip must NOT mark global status active')
  assert.equal(globalStatus.tenantId, null)

  // Tenant query status reports active for tenant-alpha and inactive for tenant-beta
  const alphaStatus = await (await fetch(`${baseUrl}/api/ops/kill-switch?tenantId=tenant-alpha`, { headers: { cookie } })).json() as { active: boolean; tenantId: string | null }
  assert.equal(alphaStatus.active, true)
  assert.equal(alphaStatus.tenantId, 'tenant-alpha')
  const betaStatus = await (await fetch(`${baseUrl}/api/ops/kill-switch?tenantId=tenant-beta`, { headers: { cookie } })).json() as { active: boolean }
  assert.equal(betaStatus.active, false)

  // Broker enforces tenant-alpha halt while tenant-beta continues!
  await assert.rejects(
    broker.executeHttp({ origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/alpha' }, makeGrant('tenant-alpha'), caller.signal),
    KillSwitchTrippedError,
  )
  const betaRes = await broker.executeHttp(
    { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/beta' },
    makeGrant('tenant-beta'),
    caller.signal,
  )
  assert.equal(betaRes.status, 200)
  assert.equal(transportCalls, 2)

  // Reset tenant-alpha via HTTP -> traffic resumes
  const resetTenantRes = await fetch(`${baseUrl}/api/ops/kill-switch`, {
    method: 'POST',
    headers: { cookie, origin: baseUrl, 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'reset', tenantId: 'tenant-alpha' }),
  })
  assert.equal(resetTenantRes.status, 200)
  const alphaAfterReset = await broker.executeHttp(
    { origin: 'https://app.example.test', method: 'GET', pathAndQuery: '/alpha-ok' },
    makeGrant('tenant-alpha'),
    caller.signal,
  )
  assert.equal(alphaAfterReset.status, 200)
})

test('H-2: GlobalKillSwitch isolates tenant trips from global state, preserves global trip, and persists tenants across file & SQLite', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-t1-ks-tenant-'))
  const ksFile = join(dir, 'kill-switch.json')
  const db = new DatabaseSync(join(dir, 'ks.db'))
  t.after(() => {
    db.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const ks = new GlobalKillSwitch({ filePath: ksFile, db, pollIntervalMs: 0 })

  // 1. Trip tenant-a -> global MUST remain inactive, tenant-b MUST remain allowed
  ks.trip({ reason: 'Pause tenant A', tenantId: 'tenant-a' })
  assert.equal(ks.status().active, false)
  assert.equal(ks.isActive(), false)
  assert.equal(ks.isActive('tenant-a'), true)
  assert.equal(ks.isActive('tenant-b'), false)

  // 2. Trip tenant-b -> tenant-a MUST stay active (not overwritten by tenant-b!)
  ks.trip({ reason: 'Pause tenant B', tenantId: 'tenant-b' })
  assert.equal(ks.status().active, false)
  assert.equal(ks.isActive('tenant-a'), true)
  assert.equal(ks.isActive('tenant-b'), true)
  assert.equal(ks.isActive('tenant-c'), false)
  assert.equal(ks.activeTenants().length, 2)

  // 3. Sibling instances (file-backed and DB-backed) observe both tenant trips without tripping global
  const fileSibling = new GlobalKillSwitch({ filePath: ksFile, pollIntervalMs: 0 })
  assert.equal(fileSibling.isActive(), false)
  assert.equal(fileSibling.isActive('tenant-a'), true)
  assert.equal(fileSibling.isActive('tenant-b'), true)
  assert.equal(fileSibling.isActive('tenant-c'), false)

  const dbSibling = new GlobalKillSwitch({ db, pollIntervalMs: 0 })
  assert.equal(dbSibling.isActive(), false)
  assert.equal(dbSibling.isActive('tenant-a'), true)
  assert.equal(dbSibling.isActive('tenant-b'), true)
  assert.equal(dbSibling.isActive('tenant-c'), false)

  // 4. Resetting only tenant-a leaves tenant-b tripped
  ks.reset({ tenantId: 'tenant-a' })
  assert.equal(ks.isActive('tenant-a'), false)
  assert.equal(ks.isActive('tenant-b'), true)

  // 5. Global trip halts ALL tenants, AND a subsequent tenant trip MUST NOT overwrite or clear global state!
  ks.trip({ reason: 'Global emergency stop' })
  assert.equal(ks.status().active, true)
  assert.equal(ks.status().tenantId, null)
  assert.equal(ks.isActive('tenant-a'), true)
  assert.equal(ks.isActive('tenant-c'), true)

  ks.trip({ reason: 'Tenant A extra note', tenantId: 'tenant-a' })
  assert.equal(ks.status().active, true, 'tenant trip after global trip must NOT overwrite global state')
  assert.equal(ks.status().tenantId, null)
  assert.equal(ks.isActive('tenant-c'), true, 'global trip must continue halting all other tenants')
  assert.throws(() => ks.assertAllowed('tenant-c'), KillSwitchTrippedError)

  // Resetting tenant-a while global is active must NOT clear global
  ks.reset({ tenantId: 'tenant-a' })
  assert.equal(ks.status().active, true)
  assert.equal(ks.isActive('tenant-a'), true)

  // Full global reset clears global AND tenants
  ks.reset()
  assert.equal(ks.status().active, false)
  assert.equal(ks.isActive('tenant-a'), false)
  assert.equal(ks.isActive('tenant-b'), false)
  assert.equal(ks.activeTenants().length, 0)
})

// ---------------------------------------------------------------------------
// 2. H-22: PersonaSessionPool run-scoped isolation (`${runId}:${handle}`)
// ---------------------------------------------------------------------------

test('H-22: PersonaSessionPool isolates identical persona handles across concurrent runIds while keeping unscoped fallback', async () => {
  const origin = 'https://app.example.test'
  const pool = new PersonaSessionPool()

  assert.equal(personaPoolKey('user-a', 'run-1'), 'run-1:user-a')
  assert.equal(personaPoolKey('user-a', 'run-2'), 'run-2:user-a')
  assert.equal(personaPoolKey('user-a'), 'user-a')

  let run1Refreshes = 0
  let run2Refreshes = 0

  pool.register('user-a', {
    session: makeCookieSession('run1-token-v1', origin),
    allowlist: [origin],
    refresh: async () => {
      run1Refreshes += 1
      return makeCookieSession('run1-token-v2', origin)
    },
  }, 'run-1')

  pool.register('user-a', {
    session: makeCookieSession('run2-token-v1', origin),
    allowlist: [origin],
    refresh: async () => {
      run2Refreshes += 1
      return makeCookieSession('run2-token-v2', origin)
    },
  }, 'run-2')

  // Strict per-run isolation
  assert.equal(pool.has('user-a', 'run-1'), true)
  assert.equal(pool.has('user-a', 'run-2'), true)
  assert.equal(pool.has('user-a', 'run-3'), false)

  const clone1 = pool.clone('user-a', 'w1', 'run-1')!
  const clone2 = pool.clone('user-a', 'w2', 'run-2')!
  assert.ok(clone1 && clone2)
  assert.equal(clone1.runId, 'run-1')
  assert.equal(clone2.runId, 'run-2')
  assert.equal(clone1.headersFor(origin)?.Cookie, 'sid=run1-token-v1')
  assert.equal(clone2.headersFor(origin)?.Cookie, 'sid=run2-token-v1')

  // Rotating run-1 must NEVER touch run-2
  pool.rotate('user-a', makeCookieSession('run1-rotated', origin), 'run-1')
  assert.equal(clone1.headersFor(origin)?.Cookie, 'sid=run1-rotated')
  assert.equal(clone2.headersFor(origin)?.Cookie, 'sid=run2-token-v1')
  assert.equal(pool.session('user-a', 'run-2')?.value, 'sid=run2-token-v1')

  // First 401 on clone1 observes the rotation generation bump -> already-fresh (zero upstream call)
  assert.equal(await clone1.reportUnauthorized(), 'already-fresh')
  assert.equal(run1Refreshes, 0)
  assert.equal(run2Refreshes, 0)

  // Next 401 on clone1 triggers upstream refresh ONLY for run-1 (never touches run-2)
  const refreshOutcome = await clone1.reportUnauthorized()
  assert.equal(refreshOutcome, 'refreshed')
  assert.equal(run1Refreshes, 1)
  assert.equal(run2Refreshes, 0)
  assert.equal(clone1.headersFor(origin)?.Cookie, 'sid=run1-token-v2')
  assert.equal(clone2.headersFor(origin)?.Cookie, 'sid=run2-token-v1')

  // Unregistering run-1 leaves run-2 intact
  pool.unregisterRun('run-1')
  assert.equal(pool.has('user-a', 'run-1'), false)
  assert.equal(pool.has('user-a', 'run-2'), true)
  assert.equal(pool.session('user-a', 'run-2')?.value, 'sid=run2-token-v1')

  // Backwards-compatible fallback when callers omit runId
  assert.equal(pool.has('user-a'), true)
  const fallbackClone = pool.clone('user-a', 'legacy-worker')!
  assert.ok(fallbackClone)
  assert.equal(fallbackClone.headersFor(origin)?.Cookie, 'sid=run2-token-v1')

  // PersonaAuthManager run-scoped registration & stopRunRefreshers isolation
  const mgr = new PersonaAuthManager()
  mgr.registerSession('user-a', { session: makeCookieSession('mgr-run1', origin), allowlist: [origin] }, 'run-1')
  mgr.registerSession('user-a', { session: makeCookieSession('mgr-run2', origin), allowlist: [origin] }, 'run-2')
  assert.equal(mgr.cloneSession('user-a', 'w1', 'run-1')?.headersFor(origin)?.Cookie, 'sid=mgr-run1')
  assert.equal(mgr.cloneSession('user-a', 'w2', 'run-2')?.headersFor(origin)?.Cookie, 'sid=mgr-run2')
  mgr.stopRunRefreshers('run-1')
  assert.equal(mgr.sessions.has('user-a', 'run-1'), false)
  assert.equal(mgr.sessions.has('user-a', 'run-2'), true)
  assert.equal(mgr.cloneSession('user-a', 'w2', 'run-2')?.headersFor(origin)?.Cookie, 'sid=mgr-run2')
})

// ---------------------------------------------------------------------------
// 3. Instant Navigation + Optimistic Scope Review (`actions.ts` & `consent.tsx`)
// ---------------------------------------------------------------------------

test('Instant Navigation: createRun returns in < 200ms while slow async discovery completes in background with 30s timeout', async t => {
  assert.equal(SUBDOMAIN_DISCOVERY_TIMEOUT_MS, 30_000)

  const dir = mkdtempSync(join(tmpdir(), 'kovo-t1-instant-nav-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'Instant Nav Public App',
    seeds: ['https://instant-nav.example'],
    environment: 'public',
    includeSubdomains: true,
  })

  let discoverStarted = false
  let discoverFinished = false
  let observedTimeoutMs = 0

  const slowDiscover = async (
    db: Store,
    runId: string,
    opts?: { timeoutMs?: number },
  ): Promise<RunDiscoverySubdomainsResult> => {
    discoverStarted = true
    observedTimeoutMs = opts?.timeoutMs ?? 0
    await new Promise(r => setTimeout(r, 350))
    const current = db.run(runId)
    db.suggestCandidateHost(current, 'https://api.instant-nav.example', 'subdomain_discovery', false, {
      zone: 'instant-nav.example',
      recordTypes: ['A'],
      externalAliases: [],
    })
    db.event(runId, 'discovery.subdomains_discovered', 'Found 1 live subdomain.', {
      discoveredCount: 1,
      addedCount: 1,
      thirdPartyCount: 0,
      addedOrigins: ['https://api.instant-nav.example'],
      thirdPartyOrigins: [],
    })
    discoverFinished = true
    return {
      skipped: false,
      discovery: {
        discovered: [],
        queriedApexes: ['instant-nav.example'],
        skippedOrigins: [],
        warnings: [],
        wildcardApexes: [],
      },
      addedOrigins: ['https://api.instant-nav.example'],
      thirdPartyOrigins: [],
      totalCandidates: 2,
    }
  }

  const t0 = performance.now()
  const { created, discoveryPromise } = createRunWithAsyncDiscovery(
    storage,
    {
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'Assess instant-nav.example and live subdomains',
      sourceMode: 'public',
      capabilityTier: 1,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [],
      budgetUsd: 10,
      budgetRequests: 0,
      maxRpsPerOrigin: 4,
      workerConcurrency: 2,
      workerMaxTurns: 20,
      multiTrialEnabled: true,
    },
    { discover: slowDiscover },
  )
  const elapsedMs = performance.now() - t0

  // 1. Returned IMMEDIATELY without waiting for the 350ms background discovery!
  assert.ok(elapsedMs < 200, `Expected createRun to return in < 200ms, got ${elapsedMs.toFixed(1)}ms`)
  assert.equal(discoverFinished, false, 'discovery must still be running in background when createRun returns')

  // 2. Run is ALREADY in phase === 'review' and discovery.subdomains_started is recorded!
  const runBeforeBg = storage.run(created.id)
  assert.equal(runBeforeBg.phase, 'review')
  assert.equal(runBeforeBg.status, 'waiting')
  const eventsBeforeBg = storage.eventsAfter(created.id, 0)
  assert.ok(eventsBeforeBg.some(e => e.kind === 'discovery.subdomains_started'))
  assert.equal(eventsBeforeBg.some(e => e.kind === 'discovery.subdomains_discovered'), false)
  assert.equal(isSubdomainDiscoveryPendingFromEvents(eventsBeforeBg), true)

  // 3. Wait for background discovery to finish -> candidates live-populated & pending flag clears
  assert.ok(discoveryPromise)
  await discoveryPromise
  assert.equal(discoverStarted, true)
  assert.equal(discoverFinished, true)
  assert.equal(observedTimeoutMs, 30_000)

  const runAfterBg = storage.run(created.id)
  assert.ok(runAfterBg.candidates.some(c => c.origin === 'https://api.instant-nav.example'))
  const eventsAfterBg = storage.eventsAfter(created.id, 0)
  assert.equal(eventsAfterBg.filter(e => e.kind === 'discovery.subdomains_discovered').length, 1)
  assert.equal(isSubdomainDiscoveryPendingFromEvents(eventsAfterBg), false)

  // 4. Error in background discovery STILL emits discovery.subdomains_discovered so spinner clears
  const errRun = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Check error fallback event pairing',
    sourceMode: 'public',
    capabilityTier: 1,
    approvalPolicy: 'auto_review',
    approvedPersonaIds: [],
    budgetUsd: 5,
    budgetRequests: 0,
    maxRpsPerOrigin: 3,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  await launchSubdomainDiscoveryInBackground(
    storage,
    errRun.id,
    async () => { throw new Error('Simulated CT outage') },
    30_000,
  )
  const errEvents = storage.eventsAfter(errRun.id, 0)
  assert.ok(errEvents.some(e => e.kind === 'discovery.subdomains_started'))
  assert.ok(errEvents.some(e => e.kind === 'discovery.subdomains_discovered'))
  assert.equal(isSubdomainDiscoveryPendingFromEvents(errEvents), false)
})

test('Scope Review consent.tsx: pre-selects live subdomains (Top 30 ranked), keeps default-editable & live discovery banner', () => {
  const consentSrc = readFileSync(join(REPO_ROOT, 'src', 'components', 'run', 'views', 'consent.tsx'), 'utf8')
  assert.match(consentSrc, /Discovering subdomains \(CT logs \+ DNS\)/, 'consent.tsx must render live discovery banner')
  assert.match(consentSrc, /useState\(!discovery\)/, 'ConsentView must default to editable state on phase === review')
  assert.match(consentSrc, /High-signal/, 'consent.tsx must include High-signal quick-select')
  assert.match(consentSrc, /All first-party/, 'consent.tsx must include All first-party quick-select')
  assert.match(consentSrc, /Bind test accounts/, 'consent.tsx must render Bind test accounts section')

  // Evaluate exported pure helpers from consent.tsx directly via Node's TS stripper
  const loadExported = <T,>(name: string): T => {
    const start = consentSrc.indexOf(`export function ${name}(`)
    assert.notEqual(start, -1, `Expected export function ${name}`)
    // Advance past the parameter list `(...)` first so `{` inside inline TS parameter types isn't treated as the body.
    const openParen = consentSrc.indexOf('(', start)
    let parenDepth = 0
    let afterParams = -1
    for (let i = openParen; i < consentSrc.length; i += 1) {
      const ch = consentSrc[i]
      if (ch === '(') parenDepth += 1
      else if (ch === ')') {
        parenDepth -= 1
        if (parenDepth === 0) {
          afterParams = i + 1
          break
        }
      }
    }
    assert.notEqual(afterParams, -1)
    let depth = 0
    let bodyStart = -1
    let end = -1
    for (let i = afterParams; i < consentSrc.length; i += 1) {
      const ch = consentSrc[i]
      if (ch === '{') {
        if (depth === 0) bodyStart = i
        depth += 1
      } else if (ch === '}') {
        depth -= 1
        if (depth === 0 && bodyStart !== -1) {
          end = i + 1
          break
        }
      }
    }
    assert.notEqual(end, -1)
    const stripped = stripTypeScriptTypes(consentSrc.slice(start, end).replace(/^export\s+/, ''))
    return new Function(`${stripped}\nreturn ${name};`)() as T
  }

  type DefaultScopeFn = (
    run: {
      scopeRevision: number
      approved: readonly string[]
      candidates: readonly {
        id: string
        origin: string
        source?: string
        thirdParty: boolean
        includeSubdomains?: boolean
        dnsSource?: unknown
      }[]
    },
    projectDefaultScope: readonly string[],
    options?: { includeSubdomainOrigins?: readonly string[]; maxAutoSelect?: number },
  ) => string[]

  type IsDiscoveryActiveFn = (
    phase: string,
    initialPending: boolean | undefined,
    events: readonly { id: number; kind: string }[],
  ) => boolean

  const defaultScopeAssetIds = loadExported<DefaultScopeFn>('defaultScopeAssetIds')
  const isSubdomainDiscoveryActive = loadExported<IsDiscoveryActiveFn>('isSubdomainDiscoveryActive')

  // 1. Live banner state transitions (snapshot -> SSE started -> SSE discovered -> phase change)
  assert.equal(isSubdomainDiscoveryActive('review', true, []), true)
  assert.equal(isSubdomainDiscoveryActive('review', false, []), false)
  assert.equal(isSubdomainDiscoveryActive('review', true, [{ id: 10, kind: 'discovery.subdomains_discovered' }]), false)
  assert.equal(isSubdomainDiscoveryActive('review', false, [{ id: 10, kind: 'discovery.subdomains_started' }]), true)
  assert.equal(
    isSubdomainDiscoveryActive('review', false, [
      { id: 10, kind: 'discovery.subdomains_started' },
      { id: 11, kind: 'discovery.subdomains_discovered' },
    ]),
    false,
  )
  assert.equal(isSubdomainDiscoveryActive('investigation', true, []), false)

  // 2. Subdomain pre-selection: subdomain_discovery & phase0_ct_discovery MUST NOT be excluded by !a.dnsSource,
  // while bulk DNS zone imports & third-party CNAMEs stay unchecked, and Top-30 signal ranking prioritizes
  // seeds + high-value prefixes over noisy preview hosts.
  const manyCandidates = [
    { id: 'seed', origin: 'https://acme.example', source: 'Project seed', thirdParty: false, dnsSource: null },
    { id: 'bulk-dns', origin: 'https://legacy.acme.example', source: 'DNS import', thirdParty: false, dnsSource: { zone: 'acme.example' } },
    { id: 'third-party', origin: 'https://docs.acme.example', source: 'subdomain_discovery', thirdParty: true, dnsSource: { externalAliases: ['hosting.gitbook.io'] } },
    ...Array.from({ length: 30 }, (_, i) => ({
      id: `noisy-${i}`,
      origin: `https://pr-${100 + i}.acme.example`,
      source: 'subdomain_discovery',
      thirdParty: false,
      dnsSource: { zone: 'acme.example', recordTypes: ['A'], externalAliases: [] },
    })),
    { id: 'api', origin: 'https://api.acme.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: { zone: 'acme.example', recordTypes: ['A'], externalAliases: [] } },
    { id: 'auth', origin: 'https://auth.acme.example', source: 'phase0_ct_discovery', thirdParty: false, dnsSource: { zone: 'acme.example', recordTypes: ['A'], externalAliases: [] } },
    { id: 'billing', origin: 'https://billing.acme.example', source: 'subdomain_discovery', thirdParty: false, dnsSource: { zone: 'acme.example', recordTypes: ['A'], externalAliases: [] } },
  ]

  const picked = defaultScopeAssetIds(
    { scopeRevision: 0, approved: [], candidates: manyCandidates },
    [],
    { includeSubdomainOrigins: ['https://acme.example'] },
  )
  assert.equal(picked.length, 30, 'auto-selected hosts must cap at Top 30')
  assert.ok(picked.includes('seed'), 'seed must be pre-selected')
  assert.ok(picked.includes('api'), 'high-value subdomain_discovery host must be pre-selected')
  assert.ok(picked.includes('auth'), 'high-value phase0_ct_discovery host must be pre-selected')
  assert.ok(picked.includes('billing'), 'high-value billing subdomain must be pre-selected')
  assert.equal(picked.includes('bulk-dns'), false, 'bulk DNS zone import must stay unchecked by default')
  assert.equal(picked.includes('third-party'), false, 'third-party CNAME must stay unchecked by default')

  // When parent seed has includeSubdomains: false (includeSubdomainOrigins: []), discovered subdomains stay unchecked
  const strictPicked = defaultScopeAssetIds(
    { scopeRevision: 0, approved: [], candidates: manyCandidates },
    [],
    { includeSubdomainOrigins: [] },
  )
  assert.deepEqual(strictPicked, ['seed'])
})
