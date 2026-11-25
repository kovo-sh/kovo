import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  decodeClerkPublishableKey,
  PersonaAuthError,
  PersonaAuthManager,
} from '../src/server/persona-auth.ts'
import type { PlaywrightFormBrowserLike } from '../src/server/persona-auth.ts'
import {
  buildPersonaHeader,
  createProjectPersona,
  deleteProjectPersona,
  listProjectPersonas,
  personaSecrets,
  resolveRunPersonas,
} from '../src/server/persona-vault.ts'
import { redact } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'
import { testPersonaAuth } from '../src/server/worker-session-reader.ts'

const targetOrigin = 'https://app.northstar.example'
const secondaryOrigin = 'https://docs.northstar.example'
const publicAddr = { address: '93.184.216.34', family: 4 as const }

function makeFakeJwt(payload: Record<string, unknown>, sigSuffix: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.sig_${sigSuffix}_998877665544332211`
}

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    tier: 2,
    maxRpsPerOrigin: 20,
    canRead: origin => origin === targetOrigin || origin === secondaryOrigin,
    audit: () => undefined,
    ...overrides,
  }
}

test('Clerk FAPI login, automatic token refresh rotation, header injection, zero secret leakage, and clean deletion', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-persona-clerk-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Clerk Login Project',
    seeds: [targetOrigin, secondaryOrigin],
    environment: 'public',
  })

  const rawPassword = 'UltraSecretClerkPassword!42'
  const email = 'kovo-a@northstar.example'
  const clientCookie = 'clerk_client_cookie_super_secret_token_9876543210'
  const iat1 = 1_760_000_100
  const exp1 = iat1 + 60
  const jwt1 = makeFakeJwt({ sub: 'user_clerk_1', sid: 'sess_clerk_99', iat: iat1, exp: exp1 }, 'initial_jwt_v1')
  const iat2 = 1_760_000_140
  const exp2 = iat2 + 60
  const jwt2 = makeFakeJwt({ sub: 'user_clerk_1', sid: 'sess_clerk_99', iat: iat2, exp: exp2 }, 'rotated_jwt_v2')

  const pkHost = Buffer.from('clerk.northstar.example$').toString('base64')
  const publishableKey = `pk_live_${pkHost}`
  assert.equal(decodeClerkPublishableKey(publishableKey), 'https://clerk.northstar.example')

  const created = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'user_a',
    roleLabel: 'User A (Control)',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'auto',
      email,
      refreshIntervalSec: 35,
    },
    secret: rawPassword,
    canaryMarkers: [],
  })

  // Auto-appended email to canaryMarkers & PublicPersona never leaks password
  const listed = listProjectPersonas(storage, projectId)
  assert.equal(listed.length, 1)
  assert.equal(listed[0].authKind, 'login')
  assert.equal(listed[0].loginConfig?.email, email)
  assert.ok(listed[0].canaryMarkers.includes(email))
  assert.ok(!JSON.stringify(listed).includes(rawPassword))

  // SQLite file contains zero passwords
  const sqliteRaw = readFileSync(join(dir, 'kovo.sqlite'))
  assert.ok(!sqliteRaw.includes(rawPassword), 'Raw password must never be stored in SQLite.')

  // Credential file is strictly 0600 JSON { v: 1, email, password }
  const credDir = join(dir, 'credentials')
  const filesBefore = readdirSync(credDir)
  assert.equal(filesBefore.length, 1)
  const credPath = join(credDir, filesBefore[0])
  assert.equal(statSync(credPath).mode & 0o777, 0o600)
  const credJson = JSON.parse(readFileSync(credPath, 'utf8')) as Record<string, unknown>
  assert.deepEqual(credJson, { v: 1, email, password: rawPassword })

  // Before authentication, buildPersonaHeader MUST return null (never emit raw password!)
  const resolvedBefore = resolveRunPersonas(storage, projectId, [created.id])
  const personaBefore = resolvedBefore.get('user_a')!
  assert.equal(buildPersonaHeader(personaBefore, targetOrigin), null)

  // Mock Clerk HTML discovery + FAPI sign_ins + /sessions/<id>/tokens refresh
  let tokenMintCount = 0
  const seenFapiCalls: Array<{ url: string; method: string; cookie?: string | null }> = []
  const mockFetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    const hdrs = new Headers(init?.headers)
    seenFapiCalls.push({ url, method, cookie: hdrs.get('cookie') })

    if (url === targetOrigin && method === 'GET') {
      return new Response(`<html><script data-clerk-publishable-key="${publishableKey}"></script></html>`, {
        status: 200,
        headers: { 'content-type': 'text/html', 'x-clerk-auth-status': 'signed-out' },
      })
    }

    if (url === 'https://clerk.northstar.example/v1/client/sign_ins' && method === 'POST') {
      const formParams = new URLSearchParams(String(init?.body ?? ''))
      assert.equal(formParams.get('identifier'), email)
      assert.equal(formParams.get('password'), rawPassword)
      assert.equal(formParams.get('strategy'), 'password')
      const resHeaders = new Headers({
        'content-type': 'application/json',
        'set-cookie': `__client=${clientCookie}; Path=/; HttpOnly; Secure`,
      })
      return new Response(JSON.stringify({
        response: {
          status: 'complete',
          created_session_id: 'sess_clerk_99',
          user_data: { id: 'user_clerk_1' },
        },
        client: {
          last_active_session_id: 'sess_clerk_99',
          sessions: [{
            id: 'sess_clerk_99',
            user: { id: 'user_clerk_1' },
            last_active_token: { jwt: jwt1 },
          }],
        },
      }), { status: 200, headers: resHeaders })
    }

    if (url === 'https://clerk.northstar.example/v1/client/sessions/sess_clerk_99/tokens' && method === 'POST') {
      assert.equal(hdrs.get('cookie'), `__client=${clientCookie}`)
      tokenMintCount += 1
      return new Response(JSON.stringify({ jwt: jwt2 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }

    return new Response('not found', { status: 404 })
  }

  const authManager = new PersonaAuthManager({ fetchImpl: mockFetch })
  t.after(() => authManager.stopAll())

  // Authenticate via auto-detected Clerk adapter
  const authRes = await authManager.authenticatePersona(storage, projectId, created.id)
  assert.equal(authRes.adapterUsed, 'clerk')
  assert.equal(authRes.headerType, 'cookie')
  assert.equal(authRes.refreshIntervalSec, 35)
  assert.ok(typeof authRes.refresh === 'function')

  // Companion .session file exists and is strictly 0600
  const sessionPath = credPath + '.session'
  assert.ok(existsSync(sessionPath))
  assert.equal(statSync(sessionPath).mode & 0o777, 0o600)

  // Live refresh on existing ResolvedPersona picks up minted __session & __client_uat
  const header1 = buildPersonaHeader(personaBefore, targetOrigin)
  assert.deepEqual(header1, { Cookie: `__session=${jwt1}; __client_uat=${iat1}` })
  assert.equal(buildPersonaHeader(personaBefore, secondaryOrigin), null)

  // RequestBroker injects minted Cookie on allowlisted origin, strips on cross-origin redirect, and scrubs all echoed secrets
  const sentCookies: Array<{ origin: string; cookie?: string }> = []
  const broker = new RequestBroker({
    resolve: async () => [publicAddr],
    transport: async (url, _addr, _sig, opts) => {
      sentCookies.push({ origin: url.origin, cookie: opts?.headers?.Cookie })
      if (url.pathname === '/cross') {
        return { status: 302, headers: { location: secondaryOrigin + '/dest' } }
      }
      return {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'x-clerk-auth-status': 'signed-in',
          'x-echo': `${rawPassword} ${clientCookie} ${jwt1} ${jwt2}`,
        },
        body: JSON.stringify({ pw: rawPassword, client: clientCookie, j1: jwt1, j2: jwt2 }),
      }
    },
  })

  const grant = makeGrant({ personas: resolvedBefore, secrets: personaSecrets(resolvedBefore) })
  const ex1 = await broker.executeHttp(
    { origin: targetOrigin, method: 'GET', pathAndQuery: '/cross', persona: 'user_a', followRedirects: true },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.deepEqual(sentCookies, [
    { origin: targetOrigin, cookie: `__session=${jwt1}; __client_uat=${iat1}` },
    { origin: secondaryOrigin, cookie: undefined },
  ])
  const serialized1 = JSON.stringify(ex1)
  assert.ok(!serialized1.includes(rawPassword), 'Raw password leaked!')
  assert.ok(!serialized1.includes(clientCookie), '__client cookie leaked!')
  assert.ok(!serialized1.includes(jwt1), 'Initial JWT leaked!')

  // Trigger Clerk token refresh rotation -> jwt2
  await authRes.refresh!()
  assert.equal(tokenMintCount, 1)

  const header2 = buildPersonaHeader(personaBefore, targetOrigin)
  assert.deepEqual(header2, { Cookie: `__session=${jwt2}; __client_uat=${iat2}` })

  // Even on a brand-new resolveRunPersonas(), personaSecrets() scrubs password, __client, jwt1, AND jwt2!
  const freshResolved = resolveRunPersonas(storage, projectId, [created.id])
  const freshSecrets = personaSecrets(freshResolved)
  const probeText = `pw=${rawPassword} client=${clientCookie} old=${jwt1} new=${jwt2}`
  const scrubbed = redact(probeText, freshSecrets)
  assert.ok(!scrubbed.includes(rawPassword), 'Password not scrubbed!')
  assert.ok(!scrubbed.includes(clientCookie), '__client not scrubbed!')
  assert.ok(!scrubbed.includes(jwt1), 'Initial JWT not scrubbed!')
  assert.ok(!scrubbed.includes(jwt2), 'Rotated JWT not scrubbed!')

  // Verify SQLite STILL has zero password, __client, or JWTs
  const sqliteAfter = readFileSync(join(dir, 'kovo.sqlite'))
  assert.ok(!sqliteAfter.includes(rawPassword))
  assert.ok(!sqliteAfter.includes(clientCookie))
  assert.ok(!sqliteAfter.includes(jwt1))
  assert.ok(!sqliteAfter.includes(jwt2))

  // End-to-end testPersonaAuth reports signed-in + Clerk auto-refresh hint
  const testResult = await testPersonaAuth(storage, broker, { projectId, personaId: created.id }, authManager)
  assert.equal(testResult.ok, true)
  assert.equal(testResult.status, 200)
  assert.match(testResult.authHint, /signed-in.*Clerk \(auto-refresh 35s\)/)

  // Verify startRunRefreshers emits clean persona.authenticated event with ZERO secrets and stopRunRefreshers cleans up
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Test login persona refresher lifecycle',
    sourceMode: 'public',
    capabilityTier: 2,
    approvedPersonaIds: [created.id],
    budgetUsd: 10,
    budgetRequests: 0,
    maxRpsPerOrigin: 5,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  const started = await authManager.startRunRefreshers(storage, runId, projectId, [created.id])
  assert.equal(started.length, 1)
  assert.equal(started[0].adapterUsed, 'clerk')
  const runEvents = storage.eventsAfter(runId, 0)
  const authEvt = runEvents.find(e => e.kind === 'persona.authenticated')
  assert.ok(authEvt, 'Expected persona.authenticated run event')
  assert.ok(!JSON.stringify(authEvt).includes(rawPassword))
  assert.ok(!JSON.stringify(authEvt).includes(clientCookie))
  assert.ok(!JSON.stringify(authEvt).includes(jwt1))
  assert.ok(!JSON.stringify(authEvt).includes(jwt2))
  authManager.stopRunRefreshers(runId)

  // Clean deletion removes BOTH credential file AND .session companion file
  deleteProjectPersona(storage, { requestId: randomUUID(), projectId, personaId: created.id })
  assert.equal(existsSync(credPath), false)
  assert.equal(existsSync(sessionPath), false)
})

test('Clerk adapter immediately refuses CAPTCHA / Cloudflare Turnstile and MFA without writing session', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-persona-captcha-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Captcha Guard Project',
    seeds: [targetOrigin],
    environment: 'public',
  })

  const created = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'user_captcha',
    roleLabel: 'Test User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'clerk',
      email: 'captcha@northstar.example',
      loginUrl: 'https://clerk.northstar.example',
    },
    secret: 'Password123!',
    canaryMarkers: [],
  })

  // 1. CAPTCHA / Turnstile rejection
  const captchaManager = new PersonaAuthManager({
    fetchImpl: async () => new Response(JSON.stringify({
      errors: [{
        code: 'captcha_invalid',
        message: 'CAPTCHA verification failed (Cloudflare Turnstile challenges.cloudflare.com required)',
      }],
    }), { status: 400, headers: { 'content-type': 'application/json' } }),
  })
  await assert.rejects(
    captchaManager.authenticatePersona(storage, projectId, created.id),
    err => err instanceof PersonaAuthError && err.code === 'CAPTCHA_DETECTED' && /CAPTCHA|Turnstile/i.test(err.message),
  )

  // 2. MFA / needs_second_factor rejection
  const mfaManager = new PersonaAuthManager({
    fetchImpl: async () => new Response(JSON.stringify({
      response: { status: 'needs_second_factor' },
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  })
  await assert.rejects(
    mfaManager.authenticatePersona(storage, projectId, created.id),
    err => err instanceof PersonaAuthError && err.code === 'MFA_REQUIRED' && /MFA|second factor/i.test(err.message),
  )

  // No .session file should exist
  const files = readdirSync(join(dir, 'credentials'))
  assert.equal(files.filter(f => f.endsWith('.session')).length, 0)
})

test('JSON API (Set-Cookie & Bearer) and Supabase login + refresh rotation with zero secret leaks', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-persona-json-supa-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'JSON and Supabase Project',
    seeds: [targetOrigin],
    environment: 'public',
  })

  // --- 1. JSON Set-Cookie ---
  const jsonCookieSecret = 'better_auth_session_cookie_val_998877665544'
  const pCookie = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'json_cookie',
    roleLabel: 'Better Auth User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'json',
      email: 'better@northstar.example',
      loginUrl: `${targetOrigin}/api/auth/sign-in/email`,
    },
    secret: 'BetterAuthPass!1',
    canaryMarkers: [],
  })

  const jsonCookieManager = new PersonaAuthManager({
    fetchImpl: async (_url, init) => {
      const parsed = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>
      assert.equal(parsed.email, 'better@northstar.example')
      assert.equal(parsed.password, 'BetterAuthPass!1')
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'set-cookie': `better-auth.session_token=${jsonCookieSecret}; Path=/; HttpOnly; Secure`,
        },
      })
    },
  })

  const resCookie = await jsonCookieManager.authenticatePersona(storage, projectId, pCookie.id)
  assert.equal(resCookie.adapterUsed, 'json')
  assert.equal(resCookie.headerType, 'cookie')
  const resolvedCookie = resolveRunPersonas(storage, projectId, [pCookie.id])
  assert.deepEqual(
    buildPersonaHeader(resolvedCookie.get('json_cookie')!, targetOrigin),
    { Cookie: `better-auth.session_token=${jsonCookieSecret}` },
  )
  assert.ok(!redact(jsonCookieSecret, personaSecrets(resolvedCookie)).includes(jsonCookieSecret))

  // --- 2. JSON Bearer via custom fields + tokenJsonPath ---
  const bearerTok = 'json_custom_nested_bearer_token_1122334455'
  const pBearer = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'json_bearer',
    roleLabel: 'API Bearer User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'json',
      email: 'api@northstar.example',
      loginUrl: `${targetOrigin}/api/v2/login`,
      emailField: 'username',
      passwordField: 'passphrase',
      tokenJsonPath: 'data.auth.accessToken',
    },
    secret: 'CustomApiPass!2',
    canaryMarkers: [],
  })

  const jsonBearerManager = new PersonaAuthManager({
    fetchImpl: async (_url, init) => {
      const parsed = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>
      assert.equal(parsed.username, 'api@northstar.example')
      assert.equal(parsed.passphrase, 'CustomApiPass!2')
      return new Response(JSON.stringify({ data: { auth: { accessToken: bearerTok } } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    },
  })

  const resBearer = await jsonBearerManager.authenticatePersona(storage, projectId, pBearer.id)
  assert.equal(resBearer.adapterUsed, 'json')
  assert.equal(resBearer.headerType, 'bearer')
  const resolvedBearer = resolveRunPersonas(storage, projectId, [pBearer.id])
  assert.deepEqual(
    buildPersonaHeader(resolvedBearer.get('json_bearer')!, targetOrigin),
    { Authorization: `Bearer ${bearerTok}` },
  )

  // --- 3. Supabase password login + refresh_token rotation ---
  const supaAccess1 = makeFakeJwt({ sub: 'supa_1', exp: Math.floor(Date.now() / 1000) + 300 }, 'supa_v1')
  const supaAccess2 = makeFakeJwt({ sub: 'supa_1', exp: Math.floor(Date.now() / 1000) + 600 }, 'supa_v2')
  const supaRefresh1 = 'supabase_refresh_tok_1_secret_aaa'
  const supaRefresh2 = 'supabase_refresh_tok_2_secret_bbb'

  const pSupa = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'supa_user',
    roleLabel: 'Supabase User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'supabase',
      email: 'supa@northstar.example',
    },
    secret: 'SupaPass!3',
    canaryMarkers: [],
  })

  const supaManager = new PersonaAuthManager({
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      const parsed = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>
      if (url.includes('grant_type=password')) {
        assert.equal(parsed.email, 'supa@northstar.example')
        assert.equal(parsed.password, 'SupaPass!3')
        return new Response(JSON.stringify({
          access_token: supaAccess1,
          refresh_token: supaRefresh1,
          expires_in: 300,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (url.includes('grant_type=refresh_token')) {
        assert.equal(parsed.refresh_token, supaRefresh1)
        return new Response(JSON.stringify({
          access_token: supaAccess2,
          refresh_token: supaRefresh2,
          expires_in: 300,
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      return new Response('unexpected', { status: 404 })
    },
  })

  const resSupa = await supaManager.authenticatePersona(storage, projectId, pSupa.id)
  assert.equal(resSupa.adapterUsed, 'supabase')
  assert.equal(resSupa.headerType, 'bearer')
  assert.ok(resSupa.refresh)

  const resolvedSupa = resolveRunPersonas(storage, projectId, [pSupa.id])
  assert.deepEqual(
    buildPersonaHeader(resolvedSupa.get('supa_user')!, targetOrigin),
    { Authorization: `Bearer ${supaAccess1}` },
  )

  await resSupa.refresh!()
  assert.deepEqual(
    buildPersonaHeader(resolvedSupa.get('supa_user')!, targetOrigin),
    { Authorization: `Bearer ${supaAccess2}` },
  )

  // Verify ALL Supabase secrets (password, access1, access2, refresh1, refresh2) are scrubbed
  const freshSupaSecrets = personaSecrets(resolveRunPersonas(storage, projectId, [pSupa.id]))
  const scrubbedSupa = redact(`SupaPass!3 ${supaAccess1} ${supaAccess2} ${supaRefresh1} ${supaRefresh2}`, freshSupaSecrets)
  assert.ok(!scrubbedSupa.includes('SupaPass!3'))
  assert.ok(!scrubbedSupa.includes(supaAccess1))
  assert.ok(!scrubbedSupa.includes(supaAccess2))
  assert.ok(!scrubbedSupa.includes(supaRefresh1))
  assert.ok(!scrubbedSupa.includes(supaRefresh2))
})

test('Form adapter aborts immediately BEFORE interacting when CAPTCHA/Turnstile is present, and succeeds on clean login forms', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-persona-form-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())

  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: 'Form Adapter Project',
    seeds: [targetOrigin],
    environment: 'public',
  })

  const pForm = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'form_user',
    roleLabel: 'Form User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: {
      adapter: 'form',
      email: 'form@northstar.example',
      loginUrl: `${targetOrigin}/login`,
    },
    secret: 'FormPassword!9',
    canaryMarkers: [],
  })

  // 1. CAPTCHA frame detected BEFORE fill/click -> must abort immediately without touching inputs!
  let interacted = false
  const captchaBrowser: PlaywrightFormBrowserLike = {
    newContext: async () => ({
      route: async () => undefined,
      newPage: async () => ({
        goto: async () => undefined,
        waitForTimeout: async () => undefined,
        url: () => `${targetOrigin}/login`,
        frames: () => [{ url: () => 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile' }],
        evaluate: async () => ({ captcha: false, mfa: false }) as never,
        locator: () => ({
          count: async () => 1,
          first() { return this },
          fill: async () => { interacted = true },
          click: async () => { interacted = true },
        }),
        close: async () => undefined,
      }),
      cookies: async () => [],
      close: async () => undefined,
    }),
    close: async () => undefined,
  }

  const blockedManager = new PersonaAuthManager({ launchBrowser: async () => captchaBrowser })
  await assert.rejects(
    blockedManager.authenticatePersona(storage, projectId, pForm.id),
    err => err instanceof PersonaAuthError && err.code === 'CAPTCHA_DETECTED',
  )
  assert.equal(interacted, false, 'Must NEVER fill or click inputs when CAPTCHA/Turnstile is detected!')

  // 2. Clean login form succeeds & captures allowlisted origin cookies
  const filledValues: string[] = []
  const cleanBrowser: PlaywrightFormBrowserLike = {
    newContext: async () => ({
      route: async () => undefined,
      newPage: async () => ({
        goto: async () => undefined,
        waitForTimeout: async () => undefined,
        waitForLoadState: async () => undefined,
        url: () => `${targetOrigin}/dashboard`,
        frames: () => [{ url: () => `${targetOrigin}/login` }],
        evaluate: async () => ({ captcha: false, mfa: false }) as never,
        locator: () => ({
          count: async () => 1,
          first() { return this },
          fill: async v => { filledValues.push(v) },
          click: async () => undefined,
        }),
        close: async () => undefined,
      }),
      cookies: async () => [{ name: 'sid', value: 'form_session_cookie_1234567890abcdef', domain: 'app.northstar.example' }],
      close: async () => undefined,
    }),
    close: async () => undefined,
  }

  const cleanManager = new PersonaAuthManager({ launchBrowser: async () => cleanBrowser })
  const res = await cleanManager.authenticatePersona(storage, projectId, pForm.id)
  assert.equal(res.adapterUsed, 'form')
  assert.equal(res.headerType, 'cookie')
  assert.deepEqual(filledValues, ['form@northstar.example', 'FormPassword!9'])
  const resolved = resolveRunPersonas(storage, projectId, [pForm.id])
  assert.deepEqual(
    buildPersonaHeader(resolved.get('form_user')!, targetOrigin),
    { Cookie: 'sid=form_session_cookie_1234567890abcdef' },
  )
})
