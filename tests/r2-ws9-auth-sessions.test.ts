import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import { GlobalKillSwitch, KillSwitchTrippedError } from '../src/server/kill-switch.ts'
import {
  detectSessionExpiry,
  extractSupabaseConfigFromText,
  isSupabaseCredentialHost,
  PersonaAuthError,
  PersonaAuthManager,
  PersonaSessionPool,
  scanJwtCandidatesLinear,
} from '../src/server/persona-auth.ts'
import {
  buildPersonaHeader,
  createProjectPersona,
  isSessionExpired,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import type { MintedPersonaSession, ResolvedPersona } from '../src/server/persona-vault.ts'
import { cloneWorkerPersona } from '../src/server/session-isolation.ts'
import { Store } from '../src/server/store.ts'
import { testPersonaAuth } from '../src/server/worker-session-reader.ts'

const APP_ORIGIN = 'https://app.northstar.example'

function makeFakeJwt(payload: Record<string, unknown>, sigSuffix = 'sig_998877665544'): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.${sigSuffix}`
}

function makeTempStore(t: { after(fn: () => void): void }, prefix = 'kovo-r2-ws9-'): Store {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => {
    try { storage.close() } catch { /* already closed */ }
  })
  return storage
}

// ---------------------------------------------------------------------------
// 1. R2-H-3: Supabase auto-discovery never trusts HTML/JS-injected origins
// ---------------------------------------------------------------------------

test('R2-H-3: Supabase credential routing refuses attacker HTML/JS origins and only trusts loginUrl or originAllowlist', async t => {
  const attackerOrigin = 'https://attackerproj99.supabase.co'
  const allowedOrigin = 'https://legitproj1234.supabase.co'
  const operatorOrigin = 'https://operatorproj55.supabase.co'

  // Deprecated 4th argument is ignored: discovered origins are NEVER self-authorizing.
  assert.equal(isSupabaseCredentialHost(attackerOrigin, [APP_ORIGIN], undefined, attackerOrigin), false)
  assert.equal(isSupabaseCredentialHost(attackerOrigin, [APP_ORIGIN]), false)
  assert.equal(isSupabaseCredentialHost('https://evil.example', [APP_ORIGIN], 'https://evil.example'), false)

  // Explicitly allowlisted or operator-configured hosted Supabase origin IS accepted.
  assert.equal(isSupabaseCredentialHost(allowedOrigin, [APP_ORIGIN, allowedOrigin]), true)
  assert.equal(isSupabaseCredentialHost(operatorOrigin, [APP_ORIGIN], `${operatorOrigin}/auth/v1/token`), true)

  // Attacker-injected storage URL + anon JWT in target HTML must NOT produce supabaseOrigin or supabaseAnonKey.
  const attackerJwt = makeFakeJwt({ iss: 'supabase', ref: 'attackerproj99', role: 'anon' }, 'att_sig_123456')
  const legitJwt = makeFakeJwt({ iss: 'supabase', ref: 'legitproj1234', role: 'anon' }, 'legit_sig_123456')
  const poisonedHtml = `
    <img src="${attackerOrigin}/storage/v1/object/public/ugc/avatar.png" />
    <script>window.__UGC={NEXT_PUBLIC_SUPABASE_URL:"${attackerOrigin}",NEXT_PUBLIC_SUPABASE_ANON_KEY:"${attackerJwt}"};</script>
  `
  const extractedPoisoned = extractSupabaseConfigFromText(poisonedHtml, [APP_ORIGIN])
  assert.equal(extractedPoisoned.supabaseOrigin, null)
  assert.equal(extractedPoisoned.supabaseAnonKey, null)

  // When an allowlisted Supabase origin also appears AFTER an attacker URL, the allowlisted one wins cleanly.
  const mixedHtml = `${poisonedHtml}\n<script>window.__APP={NEXT_PUBLIC_SUPABASE_URL:"${allowedOrigin}",NEXT_PUBLIC_SUPABASE_ANON_KEY:"${legitJwt}"};</script>`
  const extractedMixed = extractSupabaseConfigFromText(mixedHtml, [APP_ORIGIN, allowedOrigin])
  assert.equal(extractedMixed.supabaseOrigin, allowedOrigin)
  assert.equal(extractedMixed.supabaseAnonKey, legitJwt)

  // End-to-end: auto adapter MUST NEVER POST credentials to attacker-injected Supabase origin.
  const storage = makeTempStore(t, 'kovo-r2-h3-')
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'R2-H-3 Supabase Guard',
    seeds: [APP_ORIGIN],
    environment: 'public',
  })

  const autoPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'ugc_victim',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    loginConfig: { adapter: 'auto', email: 'victim@northstar.example' },
    secret: 'VictimSuperSecret!1',
    canaryMarkers: [],
  })

  const postedUrls: string[] = []
  const ks = new GlobalKillSwitch()
  const mgr = new PersonaAuthManager({
    killSwitch: ks,
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if ((init?.method ?? 'GET').toUpperCase() === 'POST') postedUrls.push(url)
      if (url === APP_ORIGIN) {
        return new Response(poisonedHtml, { status: 200, headers: { 'content-type': 'text/html' } })
      }
      return new Response('not found', { status: 404 })
    },
    launchBrowser: async () => {
      throw new Error('form_fallback_reached')
    },
  })
  t.after(() => mgr.stopAll())

  // Because poisoned HTML has no authorized Supabase origin, auto adapter does NOT switch to Supabase
  // and NEVER sends a POST to attackerproj99.supabase.co.
  await assert.rejects(mgr.authenticatePersona(storage, projectId, autoPersona.id), /form_fallback_reached/)
  assert.deepEqual(postedUrls, [], 'Credentials must NEVER be POSTed to attacker-injected Supabase origin')

  // Operator-configured loginUrl for hosted Supabase works end-to-end and picks up matching anon key.
  const opJwt = makeFakeJwt({ iss: 'supabase', ref: 'operatorproj55', role: 'anon' }, 'op_anon_sig_1234')
  const access1 = makeFakeJwt({ sub: 'op_user', exp: Math.floor(Date.now() / 1000) + 600 }, 'op_acc_sig_1234')
  const opPersona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'supa_operator',
    roleLabel: 'Operator Configured',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    loginConfig: {
      adapter: 'auto',
      email: 'op@northstar.example',
      loginUrl: operatorOrigin,
    },
    secret: 'OperatorSecret!2',
    canaryMarkers: [],
  })

  const opPosts: Array<{ url: string; apikey: string | null }> = []
  const opMgr = new PersonaAuthManager({
    killSwitch: ks,
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      const h = new Headers(init?.headers)
      if (url === APP_ORIGIN) {
        return new Response(
          `<html><script>window.__ENV={SUPABASE_URL:"${operatorOrigin}",SUPABASE_ANON_KEY:"${opJwt}"}</script></html>`,
          { status: 200, headers: { 'content-type': 'text/html' } },
        )
      }
      if (url === `${operatorOrigin}/auth/v1/token?grant_type=password`) {
        opPosts.push({ url, apikey: h.get('apikey') })
        return new Response(JSON.stringify({ access_token: access1, expires_in: 600 }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      return new Response('unexpected', { status: 404 })
    },
  })
  t.after(() => opMgr.stopAll())

  const opRes = await opMgr.authenticatePersona(storage, projectId, opPersona.id)
  assert.equal(opRes.adapterUsed, 'supabase')
  assert.equal(opPosts.length, 1)
  assert.equal(opPosts[0]!.url, `${operatorOrigin}/auth/v1/token?grant_type=password`)
  assert.equal(opPosts[0]!.apikey, opJwt)
})

// ---------------------------------------------------------------------------
// 2. R2-H-23: Linear JWT scanner defeats quadratic ReDoS on 250KB+ inputs
// ---------------------------------------------------------------------------

test('R2-H-23: linear JWT scanner and Supabase extractor stay sub-second on 250KB+ adversarial payloads', () => {
  const hyphenEyjPayload = '-eyJ'.repeat(70_000) // 280 KB: previously caused ~40s quadratic backtracking
  const dottedPayload = 'eyJaaaaaaaaaa.eyJbbbbbbbbbb.'.repeat(10_000) // 280 KB dotted repeats
  const longRunPayload = 'eyJ' + 'a'.repeat(300_000) + '.eyJ' + 'b'.repeat(300_000)

  const t0 = performance.now()
  assert.deepEqual(scanJwtCandidatesLinear(hyphenEyjPayload), [])
  assert.deepEqual(scanJwtCandidatesLinear(dottedPayload), [])
  assert.deepEqual(scanJwtCandidatesLinear(longRunPayload), [])
  const r1 = extractSupabaseConfigFromText(hyphenEyjPayload, [APP_ORIGIN])
  const r2 = extractSupabaseConfigFromText(dottedPayload, [APP_ORIGIN])
  const elapsedMs = performance.now() - t0

  assert.equal(r1.supabaseAnonKey, null)
  assert.equal(r2.supabaseAnonKey, null)
  assert.ok(elapsedMs < 500, `Expected linear scan < 500ms on adversarial 280KB inputs, took ${elapsedMs.toFixed(1)}ms`)

  // Legitimate anon JWT within cap IS found; JWT placed beyond the 256 KiB scan cap is skipped cleanly.
  const allowSupa = 'https://linearref99.supabase.co'
  const validJwt = makeFakeJwt({ iss: 'supabase', ref: 'linearref99', role: 'anon' }, 'linear_sig_123456')
  const withinCap = `const prefix = "${'x'.repeat(20_000)}"; const tok = "${validJwt}";`
  const found = extractSupabaseConfigFromText(withinCap, [APP_ORIGIN, allowSupa])
  assert.equal(found.supabaseAnonKey, validJwt)
  assert.equal(found.supabaseOrigin, allowSupa)

  const beyondCap = `${'x'.repeat(300_000)} "${validJwt}"`
  const skipped = extractSupabaseConfigFromText(beyondCap, [APP_ORIGIN, allowSupa])
  assert.equal(skipped.supabaseAnonKey, null)
})

// ---------------------------------------------------------------------------
// 3. H-2: Kill-switch gate on testPersonaAuth & refresher AbortSignal
// ---------------------------------------------------------------------------

test('H-2: testPersonaAuth enforces global & tenant-scoped kill switch and sets tenantId on grant', async t => {
  const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
  })

  let serverHits = 0
  const server = createServer((req, res) => {
    serverHits += 1
    if ((req.headers.cookie ?? '').includes('sid=valid_tok_1234')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ user: 'alice' }))
      return
    }
    res.writeHead(401, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'unauthorized' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(r => server.close(() => r())))
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  const storage = makeTempStore(t, 'kovo-h2-testauth-')
  const projA = storage.createProject({
    requestId: randomUUID(),
    name: 'Tenant A Project',
    seeds: [origin],
    environment: 'local-lab',
  })
  storage.setProjectTenant(projA.id, 'tenant-a')
  const projB = storage.createProject({
    requestId: randomUUID(),
    name: 'Tenant B Project',
    seeds: [origin],
    environment: 'local-lab',
  })
  storage.setProjectTenant(projB.id, 'tenant-b')
  const personaA = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId: projA.id,
    handle: 'alice_a',
    roleLabel: 'Member',
    originAllowlist: [origin],
    authKind: 'cookie',
    secret: 'sid=valid_tok_1234',
    canaryMarkers: [],
  })
  const personaB = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId: projB.id,
    handle: 'bob_b',
    roleLabel: 'Member',
    originAllowlist: [origin],
    authKind: 'cookie',
    secret: 'sid=valid_tok_1234',
    canaryMarkers: [],
  })

  const ks = new GlobalKillSwitch()
  const broker = new RequestBroker({
    killSwitch: ks,
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
  })
  const authMgr = new PersonaAuthManager({ killSwitch: ks })
  t.after(() => authMgr.stopAll())

  // Trip kill switch for tenant-a only: tenant-a throws with ZERO hits; tenant-b still succeeds.
  ks.trip({ reason: 'Contain tenant A', tenantId: 'tenant-a' })
  await assert.rejects(
    testPersonaAuth(storage, broker, { projectId: projA.id, personaId: personaA.id, origin, path: '/api/me' }, authMgr),
    err => err instanceof KillSwitchTrippedError && err.tenantId === 'tenant-a',
  )
  assert.equal(serverHits, 0, 'Tripped tenant must not send any HTTP request')

  const resB = await testPersonaAuth(storage, broker, { projectId: projB.id, personaId: personaB.id, origin, path: '/api/me' }, authMgr)
  assert.equal(resB.ok, true)
  assert.ok(serverHits >= 1)

  // Global trip blocks tenant-b too with zero additional hits.
  const hitsBeforeGlobal = serverHits
  ks.trip({ reason: 'Global emergency stop' })
  await assert.rejects(
    testPersonaAuth(storage, broker, { projectId: projB.id, personaId: personaB.id, origin, path: '/api/me' }, authMgr),
    err => err instanceof KillSwitchTrippedError && err.tenantId === null,
  )
  assert.equal(serverHits, hitsBeforeGlobal, 'Global kill switch must block testPersonaAuth before any HTTP hit')
})

test('H-2: background refreshers abort in-flight requests and make ZERO fetches after kill-switch trip', async t => {
  const storage = makeTempStore(t, 'kovo-h2-refresher-')
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Refresher KillSwitch App',
    seeds: [APP_ORIGIN],
    environment: 'public',
  })
  storage.setProjectTenant(projectId, 'tenant-refresh')

  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'refresh_user',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    loginConfig: {
      adapter: 'supabase',
      email: 'refresh@northstar.example',
      loginUrl: `${APP_ORIGIN}/auth/v1/token`,
      refreshIntervalSec: 0.05 as unknown as number, // 50ms tick for fast deterministic verification
    },
    secret: 'RefreshPass!9',
    canaryMarkers: [],
  })

  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify refresher stops on kill switch',
    sourceMode: 'public',
    capabilityTier: 2,
    approvedPersonaIds: [persona.id],
    budgetUsd: 5,
    budgetRequests: 0,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })

  const ks = new GlobalKillSwitch()
  let refreshFetchCalls = 0
  let inFlightAborted = false
  let releaseInFlight: (() => void) | null = null
  let blockNextRefresh = false

  const mgr = new PersonaAuthManager({
    killSwitch: ks,
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.includes('grant_type=password')) {
        return new Response(JSON.stringify({
          access_token: makeFakeJwt({ sub: 'u1', exp: Math.floor(Date.now() / 1000) + 60 }, 'init_sig_1111'),
          refresh_token: 'rot_refresh_1',
          expires_in: 60,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (url.includes('grant_type=refresh_token')) {
        refreshFetchCalls += 1
        if (blockNextRefresh) {
          await new Promise<void>((resolve, reject) => {
            releaseInFlight = resolve
            init?.signal?.addEventListener('abort', () => {
              inFlightAborted = true
              reject(init.signal?.reason ?? new Error('aborted'))
            }, { once: true })
          })
        }
        return new Response(JSON.stringify({
          access_token: makeFakeJwt({ sub: 'u1', exp: Math.floor(Date.now() / 1000) + 60 }, `rot_${refreshFetchCalls}`),
          refresh_token: `rot_refresh_${refreshFetchCalls + 1}`,
          expires_in: 60,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      return new Response('not found', { status: 404 })
    },
  })
  t.after(() => {
    releaseInFlight?.()
    mgr.stopAll()
  })

  await mgr.startRunRefreshers(storage, runId, projectId, [persona.id])
  blockNextRefresh = true

  // Wait until one refresh fetch is in-flight, then trip the tenant kill switch!
  const waitStart = Date.now()
  while (refreshFetchCalls === 0 && Date.now() - waitStart < 2_000) {
    await new Promise(r => setTimeout(r, 15))
  }
  assert.equal(refreshFetchCalls, 1, 'Expected scheduled refresher tick to start')

  ks.trip({ reason: 'Tenant emergency stop', tenantId: 'tenant-refresh' })
  await new Promise(r => setTimeout(r, 160))

  assert.equal(inFlightAborted, true, 'In-flight refresher fetch must abort immediately on kill-switch trip')
  const countAfterTrip = refreshFetchCalls
  await new Promise(r => setTimeout(r, 180))
  assert.equal(refreshFetchCalls, countAfterTrip, 'Refresher fetch count MUST remain zero after kill-switch trip')
  assert.equal(await mgr.requestReauth('refresh_user', undefined, runId), false)
  assert.equal(refreshFetchCalls, countAfterTrip)
})

// ---------------------------------------------------------------------------
// 4. H-23: Single-flight owner, generation dedup, pacing/circuit, expiry,
//    clone servedGeneration, and ephemeral retest session bootstrap
// ---------------------------------------------------------------------------

test('H-23: 3 sequential 401s produce 1 refresh; failure backoff & circuit breaker prevent login storms', async () => {
  let fakeNow = 1_000_000
  let upstreamCalls = 0
  let shouldFail = false

  const pool = new PersonaSessionPool({
    minRefreshIntervalMs: 5_000,
    failureBackoffBaseMs: 1_000,
    failureBackoffMaxMs: 10_000,
    circuitBreakerThreshold: 2,
    circuitBreakerOpenMs: 30_000,
    now: () => fakeNow,
  })

  const makeSess = (tok: string): MintedPersonaSession => ({
    headerType: 'bearer',
    value: tok,
    adapterUsed: 'json',
  })

  pool.register('alice', {
    session: makeSess('tok_v1'),
    allowlist: [APP_ORIGIN],
    refresh: async () => {
      upstreamCalls += 1
      if (shouldFail) throw new Error('upstream 503')
      return makeSess(`tok_v${upstreamCalls + 1}`)
    },
  }, 'run-seq')

  // 1. Three sequential 401s observing gen 1 -> 1 refresh, next 2 already-fresh.
  assert.equal(await pool.refresh('alice', 1, 'run-seq'), 'refreshed')
  assert.equal(await pool.refresh('alice', 1, 'run-seq'), 'already-fresh')
  assert.equal(await pool.refresh('alice', 1, 'run-seq'), 'already-fresh')
  assert.equal(upstreamCalls, 1)

  // 2. Sequential 401s omitting observedGeneration or observing current gen (2) inside pacing window -> STILL 1 upstream call.
  assert.equal(await pool.refresh('alice', undefined, 'run-seq'), 'already-fresh')
  assert.equal(await pool.refresh('alice', 2, 'run-seq'), 'paced')
  assert.equal(upstreamCalls, 1)

  // 3. Advance clock past pacing window & inject failures -> exponential backoff -> circuit breaker opens!
  fakeNow += 6_000
  shouldFail = true
  assert.equal(await pool.refresh('alice', 2, 'run-seq'), 'failed') // failure #1 -> backoff 1000ms
  assert.equal(upstreamCalls, 2)
  assert.equal(await pool.refresh('alice', 2, 'run-seq'), 'paced') // within 1000ms backoff
  assert.equal(upstreamCalls, 2)

  fakeNow += 1_500
  assert.equal(await pool.refresh('alice', 2, 'run-seq'), 'failed') // failure #2 -> opens circuit (30_000ms)
  assert.equal(upstreamCalls, 3)
  fakeNow += 5_000
  assert.equal(await pool.refresh('alice', 2, 'run-seq'), 'circuit-open')
  assert.equal(upstreamCalls, 3)

  // 4. After circuitOpenMs elapses, half-open probe succeeds and resets circuit cleanly!
  fakeNow += 30_000
  shouldFail = false
  assert.equal(await pool.refresh('alice', 2, 'run-seq'), 'refreshed')
  assert.equal(upstreamCalls, 4)
  assert.equal(pool.session('alice', 'run-seq')?.value, 'tok_v5')
})

test('H-23: periodic timer + concurrent 401 share ONE single-flight upstream POST (no rotating-token race)', async t => {
  const storage = makeTempStore(t, 'kovo-h23-singleflight-')
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Single Flight App',
    seeds: [APP_ORIGIN],
    environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'rot_user',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    loginConfig: {
      adapter: 'supabase',
      email: 'rot@northstar.example',
      loginUrl: `${APP_ORIGIN}/auth/v1/token`,
      refreshIntervalSec: 0.06 as unknown as number, // 60ms tick
    },
    secret: 'RotSecret!7',
    canaryMarkers: [],
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify timer + 401 single-flight',
    sourceMode: 'public',
    capabilityTier: 2,
    approvedPersonaIds: [persona.id],
    budgetUsd: 5,
    budgetRequests: 0,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })

  const seenRefreshTokens: string[] = []
  let activeRefreshPosts = 0
  let maxConcurrentRefreshPosts = 0
  let currentExpectedRefreshTok = 'rt_1'
  let tokenVersion = 1

  const mgr = new PersonaAuthManager({
    killSwitch: new GlobalKillSwitch(),
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url.includes('grant_type=password')) {
        return new Response(JSON.stringify({
          access_token: makeFakeJwt({ sub: 'rot', exp: Math.floor(Date.now() / 1000) + 120 }, 'acc_v1'),
          refresh_token: 'rt_1',
          expires_in: 120,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (url.includes('grant_type=refresh_token')) {
        activeRefreshPosts += 1
        maxConcurrentRefreshPosts = Math.max(maxConcurrentRefreshPosts, activeRefreshPosts)
        const parsed = JSON.parse(String(init?.body ?? '{}')) as { refresh_token?: string }
        seenRefreshTokens.push(parsed.refresh_token ?? '')
        await new Promise(r => setTimeout(r, 80))
        activeRefreshPosts -= 1
        // Simulate strict single-use rotating refresh token family!
        if (parsed.refresh_token !== currentExpectedRefreshTok) {
          return new Response(JSON.stringify({ error: 'refresh_token_reused' }), { status: 400 })
        }
        tokenVersion += 1
        currentExpectedRefreshTok = `rt_${tokenVersion}`
        return new Response(JSON.stringify({
          access_token: makeFakeJwt({ sub: 'rot', exp: Math.floor(Date.now() / 1000) + 120 }, `acc_v${tokenVersion}`),
          refresh_token: currentExpectedRefreshTok,
          expires_in: 120,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      return new Response('not found', { status: 404 })
    },
  })
  t.after(() => mgr.stopAll())

  await mgr.startRunRefreshers(storage, runId, projectId, [persona.id])

  // Wait until the first timer tick starts its 80ms refresh POST, then fire concurrent 401 reauths!
  const start = Date.now()
  while (seenRefreshTokens.length === 0 && Date.now() - start < 2_000) {
    await new Promise(r => setTimeout(r, 10))
  }
  assert.equal(seenRefreshTokens.length, 1)
  const [r1, r2] = await Promise.all([
    mgr.requestReauth('rot_user', 1, runId),
    mgr.requestReauth('rot_user', 1, runId),
  ])
  assert.equal(r1, true)
  assert.equal(r2, true)
  assert.equal(maxConcurrentRefreshPosts, 1, 'Timer and 401 reauth MUST share one single-flight upstream POST')
  assert.equal(seenRefreshTokens.length, 1, 'Concurrent 401s must join the in-flight timer refresh without replaying rt_1')
  mgr.stopRunRefreshers(runId)
})

test('H-23: cloneWorkerPersona tracks servedGeneration accurately across live rotation and multi-run ambiguity fails closed', () => {
  const pool = new PersonaSessionPool()
  const v1: MintedPersonaSession = { headerType: 'bearer', value: 'tok_gen1', adapterUsed: 'json' }
  const v2: MintedPersonaSession = { headerType: 'bearer', value: 'tok_gen2', adapterUsed: 'json' }
  pool.register('shared_handle', { session: v1, allowlist: [APP_ORIGIN] }, 'run-a')
  pool.register('shared_handle', { session: { headerType: 'bearer', value: 'tok_run_b', adapterUsed: 'json' }, allowlist: [APP_ORIGIN] }, 'run-b')

  // Unscoped lookup fails closed when two concurrent runs share the same handle!
  assert.equal(pool.has('shared_handle'), false)
  assert.equal(pool.clone('shared_handle'), null)

  const base: ResolvedPersona = {
    id: 'p1',
    handle: 'shared_handle',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    headerName: null,
    secret: 'pw',
    canaryMarkers: [],
    session: v1,
  }
  const workerA = cloneWorkerPersona(
    base,
    'w-a',
    (h, wid) => pool.clone(h, wid, 'run-a'),
    h => pool.session(h, 'run-a'),
  )!
  assert.ok(workerA)
  assert.deepEqual(buildPersonaHeader(workerA.persona, APP_ORIGIN), { Authorization: 'Bearer tok_gen1' })
  assert.equal(workerA.persona.session?.generation, 1)

  // Pool rotates to gen 2 while workerA's gen-1 request is in flight:
  // workerA.persona.session.generation STILL reports 1 (the generation it actually sent)!
  pool.rotate('shared_handle', v2, 'run-a')
  assert.equal(workerA.persona.session?.generation, 1)

  // Once workerA reads headers for its retry, it receives gen 2 and servedGeneration advances to 2.
  assert.deepEqual(buildPersonaHeader(workerA.persona, APP_ORIGIN), { Authorization: 'Bearer tok_gen2' })
  assert.equal(workerA.persona.session?.generation, 2)
})

test('H-23: detectSessionExpiry cleanly identifies 401, Clerk signed-out, login-redirect, and 403 expiry without RBAC false positives', async t => {
  assert.deepEqual(detectSessionExpiry({ status: 401 }), { expired: true, reason: 'http_401' })
  assert.deepEqual(
    detectSessionExpiry({ status: 200, headers: { 'X-Clerk-Auth-Status': 'signed-out' } }),
    { expired: true, reason: 'clerk_signed_out' },
  )
  assert.deepEqual(
    detectSessionExpiry({
      status: 302,
      headers: { Location: '/login?next=/dashboard' },
      requestOrigin: APP_ORIGIN,
    }),
    { expired: true, reason: 'login_redirect', redirectTarget: '/login?next=/dashboard' },
  )
  assert.deepEqual(
    detectSessionExpiry({
      status: 302,
      headers: { Location: '/dashboard' },
      requestOrigin: APP_ORIGIN,
    }),
    { expired: false, reason: null },
  )
  assert.deepEqual(
    detectSessionExpiry({
      status: 403,
      body: JSON.stringify({ error: 'session_expired', message: 'Your session has expired' }),
    }),
    { expired: true, reason: 'http_403_session_expired' },
  )
  assert.deepEqual(
    detectSessionExpiry({
      status: 403,
      headers: { 'WWW-Authenticate': 'Bearer error="invalid_token"' },
    }),
    { expired: true, reason: 'http_403_session_expired' },
  )
  // Normal RBAC 403 must NOT be mistaken for session expiry!
  assert.deepEqual(
    detectSessionExpiry({
      status: 403,
      body: JSON.stringify({ error: 'Forbidden: admin role required' }),
    }),
    { expired: false, reason: null },
  )

  // isSessionExpired helper
  assert.equal(isSessionExpired(null), true)
  assert.equal(isSessionExpired({ headerType: 'bearer', value: 'x', adapterUsed: 'json', expiresAt: Date.now() - 1000 }), true)
  assert.equal(isSessionExpired({ headerType: 'bearer', value: 'x', adapterUsed: 'json', expiresAt: Date.now() + 60_000 }), false)

  // testPersonaAuth refuses to follow a same-origin 302 -> /login into a false-green 200 login page!
  const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
  })

  const server = createServer((req, res) => {
    if (req.url === '/protected') {
      res.writeHead(302, { location: '/login?next=/protected' })
      res.end()
      return
    }
    if (req.url?.startsWith('/login')) {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(`<html><body>Sign in ${randomUUID()}</body></html>`)
      return
    }
    res.writeHead(403, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'token_expired' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(r => server.close(() => r())))
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  const storage = makeTempStore(t, 'kovo-h23-expiry-')
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'Expiry Test App',
    seeds: [origin],
    environment: 'local-lab',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'expired_user',
    roleLabel: 'Member',
    originAllowlist: [origin],
    authKind: 'cookie',
    secret: 'sid=stale_1234',
    canaryMarkers: [],
  })
  const broker = new RequestBroker({
    killSwitch: new GlobalKillSwitch(),
    resolve: async () => [{ address: '127.0.0.1', family: 4 }],
  })

  const redirRes = await testPersonaAuth(storage, broker, { projectId: project.id, personaId: persona.id, origin, path: '/protected' })
  assert.equal(redirRes.ok, false)
  assert.equal(redirRes.status, 302)
  assert.match(redirRes.authHint, /Session expired \(redirected to login\)/)

  const forbiddenRes = await testPersonaAuth(storage, broker, { projectId: project.id, personaId: persona.id, origin, path: '/api/data' })
  assert.equal(forbiddenRes.ok, false)
  assert.equal(forbiddenRes.status, 403)
  assert.match(forbiddenRes.authHint, /Session expired \(HTTP 403\)/)
})

test('H-23: bootstrapEphemeralRunSessions refreshes post-completion retests and reports inconclusive cleanly on auth failure', async t => {
  const storage = makeTempStore(t, 'kovo-h23-retest-')
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Retest Ephemeral Auth',
    seeds: [APP_ORIGIN],
    environment: 'public',
  })
  storage.setProjectTenant(projectId, 'tenant-retest')
  const secretPw = 'RetestSuperSecret!99'
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'retest_user',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN],
    authKind: 'login',
    loginConfig: {
      adapter: 'json',
      email: 'retest@northstar.example',
      loginUrl: `${APP_ORIGIN}/api/auth/login`,
    },
    secret: secretPw,
    canaryMarkers: [],
  })

  let failLogin = false
  let loginSeq = 0
  const ks = new GlobalKillSwitch()
  const mgr = new PersonaAuthManager({
    killSwitch: ks,
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async () => {
      loginSeq += 1
      if (failLogin) {
        return new Response(JSON.stringify({ error: `invalid credentials for ${secretPw}` }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        })
      }
      return new Response(JSON.stringify({ access_token: `fresh_retest_tok_${loginSeq}` }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    },
  })
  t.after(() => mgr.stopAll())

  // 1. Successful ephemeral retest bootstrap registers isolated scopeId and disposes cleanly after callback.
  const scopeId = 'retest:worker-123'
  let observedToken: string | null = null
  await mgr.withEphemeralRunSessions(storage, {
    scopeId,
    projectId,
    approvedPersonaIds: [persona.id],
  }, async handle => {
    assert.equal(handle.ready, true)
    assert.equal(handle.inconclusive, false)
    assert.deepEqual(handle.authenticatedHandles, ['retest_user'])
    assert.equal(mgr.sessions.has('retest_user', scopeId), true)
    observedToken = mgr.sessions.session('retest_user', scopeId)?.value ?? null
  })
  assert.equal(observedToken, 'fresh_retest_tok_1')
  assert.equal(mgr.sessions.has('retest_user', scopeId), false, 'Ephemeral scope must be cleaned up on dispose')

  // 2. When credentials cannot be refreshed, bootstrap reports unavailable/inconclusive cleanly (and scrubs secrets!).
  failLogin = true
  const failed = await mgr.bootstrapEphemeralRunSessions(storage, {
    scopeId: 'retest:worker-456',
    projectId,
    approvedPersonaIds: [persona.id],
  })
  t.after(() => failed.dispose())
  assert.equal(failed.ready, false)
  assert.equal(failed.inconclusive, true)
  assert.equal(failed.unavailable.length, 1)
  assert.equal(failed.unavailable[0]!.handle, 'retest_user')
  assert.equal(failed.unavailable[0]!.code, 'INVALID_CREDENTIALS')
  assert.ok(failed.reason && /Inconclusive/i.test(failed.reason))
  assert.ok(!failed.reason!.includes(secretPw), 'Unavailable reason must redact persona password')
  assert.ok(!failed.unavailable[0]!.reason.includes(secretPw), 'Per-persona reason must redact persona password')

  // 3. Tripped kill switch still rejects ephemeral bootstrap immediately.
  ks.trip({ reason: 'Halt retests', tenantId: 'tenant-retest' })
  await assert.rejects(
    mgr.bootstrapEphemeralRunSessions(storage, {
      scopeId: 'retest:worker-789',
      projectId,
      approvedPersonaIds: [persona.id],
    }),
    err => err instanceof KillSwitchTrippedError,
  )
})
