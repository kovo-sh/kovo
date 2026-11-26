/**
 * Systemic Quality Move Q4 Regression Suite:
 *  1. Broker session-expiry auto-reauth via `detectSessionExpiry()` across HTTP 401,
 *     pre-redirect 3xx `/login` redirects, HTTP 403 session-expired bodies / WWW-Authenticate,
 *     and Clerk `X-Clerk-Auth-Status: signed-out` (both HTTP/1.1 and HTTP/2), bounded to
 *     prevent re-auth loops, without false-triggering on RBAC 403 or intentional `/logout`.
 *  2. First-rotation `Set-Cookie` superseding stale Persona Vault cookies immediately on
 *     the VERY FIRST server-issued rotation (`writeCount === 1`) on HTTP/1.1 and HTTP/2,
 *     while untouched Vault cookies stay intact and post-reauth / fresher Vault refreshes
 *     immediately supersede older jar entries.
 *  3. Multi-origin `storageByOrigin` isolation & per-origin attachment resolution across
 *     `importStorageState()`, `importHar()`, `buildImportedBundle()`, `buildSessionFromBrowserBundle()`,
 *     `frameForSessionOrigin()`, `buildPersonaHeader()`, and `buildPersonaBrowserAttachment()`
 *     (zero cross-origin key clobbering, zero `origins[0]` collapse, full secret scrubbing).
 *  4. Provenance-bound ephemeral credential channel: admits signed/opaque Bearer tokens whose
 *     exact SHA-256 digest was observed in an in-scope non-privileged exchange response during
 *     the same run with accurate `wireCredentialProvenance` (`ephemeral_observed`), while keeping
 *     `FORBIDDEN_CALLER_HEADERS` 100% strict against arbitrary, hardcoded, cross-run, privileged,
 *     revoked-origin, or Vault-leaked credentials (`C-3` / `H-8` / `H-14`).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer as createH2Server } from 'node:http2'
import type { IncomingHttpHeaders as H2IncomingHeaders, ServerHttp2Session, ServerHttp2Stream } from 'node:http2'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import { importHar, importStorageState } from '../src/server/persona-auth.ts'
import {
  buildPersonaBrowserAttachment,
  buildPersonaHeader,
  buildSessionFromBrowserBundle,
  bundleSecrets,
  createProjectPersona,
  frameForSessionOrigin,
  normalizeBrowserStorageBundle,
  personaSecrets,
  resolveRunPersonas,
  writePersonaSessionFile,
} from '../src/server/persona-vault.ts'
import type { BrowserStorageBundle, MintedPersonaSession, ResolvedPersona } from '../src/server/persona-vault.ts'
import { redact } from '../src/server/redact.ts'
import { extractBearerTokenDigest, validateCallerHeaders } from '../src/server/request-admission.ts'
import { Store } from '../src/server/store.ts'

const APP_ORIGIN = 'https://app.q4test.example'
const API_ORIGIN = 'https://api.q4test.example'
const OTHER_ORIGIN = 'https://other.q4test.example'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeSignedJwt(payload: Record<string, unknown>, sig = 'valid_hmac_sig_0123456789abcdef'): string {
  const hdr = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${hdr}.${body}.${sig}`
}

function makeGrant(origins: string[], overrides: Partial<Grant> = {}): Grant {
  const allowed = new Set(origins)
  return {
    origin: origins[0],
    tier: 2,
    allowLocalLab: false,
    maxRpsPerOrigin: 50,
    canRead: o => allowed.has(o),
    audit: () => {},
    ...overrides,
  }
}

async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const prev: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k]
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    return await fn()
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

function makePersona(handle: string, overrides: Partial<ResolvedPersona> = {}): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel: 'member:tenant-a',
    originAllowlist: [APP_ORIGIN],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: 'initial_stale_token_1234567890',
    canaryMarkers: [],
    ...overrides,
  }
}

// ============================================================================
// 1. Session-expiry auto-reauth via detectSessionExpiry() (HTTP/1.1 & HTTP/2)
// ============================================================================

test('Q4.1: broker auto-reauth triggers on 302 /login (pre-redirect), 403 session-expired, Clerk signed-out, and stays bounded', async t => {
  const seenPaths: string[] = []
  let activeToken = 'stale_tok_v1_abcdef1234'
  let reauthCalls = 0
  let alwaysExpire = false

  const persona = makePersona('member_a', {
    authKind: 'login',
    secret: 'pw',
    session: { headerType: 'bearer', value: activeToken, adapterUsed: 'json' },
  })

  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    reauth: async () => {
      reauthCalls += 1
      activeToken = `fresh_tok_v${reauthCalls + 1}_abcdef1234`
      persona.session = {
        headerType: 'bearer',
        value: activeToken,
        adapterUsed: 'json',
        updatedAt: Date.now(),
      }
      return true
    },
    transport: async (url, _addr, _sig, opts) => {
      seenPaths.push(url.pathname)
      const auth = opts?.headers?.Authorization ?? opts?.headers?.authorization ?? ''
      const isFresh = !alwaysExpire && auth === `Bearer ${activeToken}` && reauthCalls > 0
      if (url.pathname === '/login') {
        return { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>Login Form</html>' }
      }
      if (url.pathname === '/dashboard') {
        if (!isFresh) {
          return { status: 302, headers: { location: '/login?next=/dashboard' }, body: '' }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"page":"dashboard"}' }
      }
      if (url.pathname === '/api/expired-body') {
        if (!isFresh) {
          return {
            status: 403,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ error: 'session_expired', message: 'Your session has expired' }),
          }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
      }
      if (url.pathname === '/api/expired-www-auth') {
        if (!isFresh) {
          return {
            status: 403,
            headers: { 'www-authenticate': 'Bearer error="invalid_token"' },
            body: 'Forbidden',
          }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
      }
      if (url.pathname === '/api/clerk-signed-out') {
        if (!isFresh) {
          return {
            status: 200,
            headers: { 'x-clerk-auth-status': 'signed-out', 'content-type': 'application/json' },
            body: '{"signedIn":false}',
          }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"signedIn":true}' }
      }
      if (url.pathname === '/api/admin-rbac') {
        return {
          status: 403,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ error: 'Forbidden: admin role required' }),
        }
      }
      if (url.pathname === '/logout') {
        return { status: 302, headers: { location: '/login' }, body: '' }
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
  t.after(() => broker.closeTransport())

  const grant = makeGrant([APP_ORIGIN], { personas: new Map([['member_a', persona]]) })
  const sig = AbortSignal.timeout(5_000)

  // 1. Pre-redirect 302 -> /login triggers reauth BEFORE following redirect (never follows into /login HTML!)
  const dash = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/dashboard', persona: 'member_a' }, grant, sig)
  assert.equal(dash.status, 200)
  assert.equal(reauthCalls, 1)
  assert.equal(seenPaths.includes('/login'), false, 'must NOT follow 302 /login before auto-reauth')

  // Reset to stale token for each expiry signal
  const resetStale = () => {
    reauthCalls = 0
    activeToken = 'stale_tok_reset_123456'
    persona.session = { headerType: 'bearer', value: activeToken, adapterUsed: 'json' }
  }

  // 2. 403 with session_expired JSON body triggers reauth once
  resetStale()
  const expBody = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/expired-body', persona: 'member_a' }, grant, sig)
  assert.equal(expBody.status, 200)
  assert.equal(reauthCalls, 1)

  // 3. 403 with WWW-Authenticate invalid_token triggers reauth once
  resetStale()
  const expWww = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/expired-www-auth', persona: 'member_a' }, grant, sig)
  assert.equal(expWww.status, 200)
  assert.equal(reauthCalls, 1)

  // 4. Clerk X-Clerk-Auth-Status: signed-out triggers reauth once
  resetStale()
  const clerk = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/clerk-signed-out', persona: 'member_a' }, grant, sig)
  assert.equal(clerk.status, 200)
  assert.equal(reauthCalls, 1)

  // 5. Normal RBAC 403 MUST NOT trigger reauth!
  resetStale()
  const rbac = await broker.executeHttp({ origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/admin-rbac', persona: 'member_a' }, grant, sig)
  assert.equal(rbac.status, 403)
  assert.equal(reauthCalls, 0, 'normal RBAC 403 must never trigger auto-reauth')

  // 6. Intentional /logout 302 -> /login MUST NOT trigger reauth!
  resetStale()
  const logoutRes = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/logout', persona: 'member_a', followRedirects: false },
    grant,
    sig,
  )
  assert.equal(logoutRes.status, 302)
  assert.equal(reauthCalls, 0, 'intentional /logout redirect to /login must never trigger auto-reauth')

  // 7. Bounded retry: if retry STILL returns 302 /login (alwaysExpire), reauth runs at most ONCE (no loop!)
  resetStale()
  alwaysExpire = true
  const bounded = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/dashboard', persona: 'member_a', followRedirects: false },
    grant,
    sig,
  )
  assert.equal(bounded.status, 302)
  assert.equal(reauthCalls, 1, 'auto-reauth must be strictly bounded to 1 attempt per exchange')
})

test('Q4.1b: HTTP/2 executeHttp2Exchange auto-reauths on 403 session_expired and 302 /login', async t => {
  const sessions = new Set<ServerHttp2Session>()
  let expectedToken = 'h2_stale_token_123456'
  let reauthCalls = 0

  const h2Server = createH2Server()
  h2Server.on('session', s => {
    sessions.add(s)
    s.once('close', () => sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream, headers: H2IncomingHeaders) => {
    const path = String(headers[':path'] ?? '/')
    const auth = String(headers.authorization ?? '')
    if (auth === `Bearer ${expectedToken}` && reauthCalls > 0) {
      stream.respond({ ':status': 200, 'content-type': 'application/json' })
      stream.end(JSON.stringify({ ok: true, path }))
      return
    }
    if (path === '/h2-redirect') {
      stream.respond({ ':status': 302, location: '/signin?next=/h2-redirect' })
      stream.end()
      return
    }
    stream.respond({ ':status': 403, 'content-type': 'application/json' })
    stream.end(JSON.stringify({ error: 'token_expired' }))
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${(h2Server.address() as AddressInfo).port}`
  t.after(async () => {
    for (const s of sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const persona = makePersona('h2_member', {
      originAllowlist: [origin],
      authKind: 'login',
      secret: 'pw',
      session: { headerType: 'bearer', value: expectedToken, adapterUsed: 'json' },
    })
    const broker = new RequestBroker({
      resolve: async () => [{ address: '127.0.0.1', family: 4 }],
      reauth: async () => {
        reauthCalls += 1
        expectedToken = `h2_fresh_token_${reauthCalls}_abcdef`
        persona.session = { headerType: 'bearer', value: expectedToken, adapterUsed: 'json', updatedAt: Date.now() }
        return true
      },
    })
    t.after(() => broker.closeTransport())

    const grant = makeGrant([origin], { allowLocalLab: true, personas: new Map([['h2_member', persona]]) })
    const res403 = await broker.executeHttp2Exchange(
      { origin, method: 'GET', pathAndQuery: '/h2-data', persona: 'h2_member' },
      grant,
      AbortSignal.timeout(5_000),
    )
    assert.equal(res403.status, 200)
    assert.equal(reauthCalls, 1)

    // Also verify 302 /signin on HTTP/2
    reauthCalls = 0
    expectedToken = 'h2_stale_redir_123456'
    persona.session = { headerType: 'bearer', value: expectedToken, adapterUsed: 'json' }
    const res302 = await broker.executeHttp2Exchange(
      { origin, method: 'GET', pathAndQuery: '/h2-redirect', persona: 'h2_member' },
      grant,
      AbortSignal.timeout(5_000),
    )
    assert.equal(res302.status, 200)
    assert.equal(reauthCalls, 1)
  })
})

// ============================================================================
// 2. First-rotation Set-Cookie beats stale Vault cookie immediately
// ============================================================================

test('Q4.2: first server-issued Set-Cookie rotation wins immediately while untouched Vault cookies and post-reauth refreshes remain intact', async t => {
  const seenCookies: string[] = []
  let shouldExpireAfterRot = false

  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    reauth: async () => {
      // Simulate Vault refreshing `sid` to a brand-new session value after expiry!
      persona.session = {
        headerType: 'cookie',
        value: 'sid=VAULT_REAUTH_V2; pref=VAULT_PREF',
        adapterUsed: 'form',
        updatedAt: Date.now() + 10,
      }
      shouldExpireAfterRot = false
      return true
    },
    transport: async (url, _addr, _sig, opts) => {
      const cookie = String(opts?.headers?.Cookie ?? opts?.headers?.cookie ?? '')
      seenCookies.push(cookie)
      if (url.pathname === '/rotate-once') {
        return {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'set-cookie': ['sid=JAR_FIRST_ROT_1; Path=/; HttpOnly'],
          },
          body: '{"rotated":true}',
        }
      }
      if (url.pathname === '/check-expiry' && shouldExpireAfterRot) {
        return {
          status: 302,
          headers: {
            location: '/login',
            // Even if the expired response tries to clear/overwrite sid, reauth retry must use fresh Vault!
            'set-cookie': ['sid=EXPIRED_ANON_COOKIE; Path=/'],
          },
          body: '',
        }
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }
    },
  })
  t.after(() => broker.closeTransport())

  const persona = makePersona('cookie_rot', {
    authKind: 'login',
    secret: 'pw',
    session: {
      headerType: 'cookie',
      value: 'sid=VAULT_SEED_V1; pref=VAULT_PREF',
      adapterUsed: 'form',
      updatedAt: Date.now() - 1_000,
    },
  })
  const grant = makeGrant([APP_ORIGIN], { personas: new Map([['cookie_rot', persona]]) })
  const sig = AbortSignal.timeout(5_000)

  // 1. Trigger a SINGLE Set-Cookie rotation (`writeCount === 1`)
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/rotate-once', persona: 'cookie_rot', session: 's1', runId: 'r-q4' },
    grant,
    sig,
  )
  assert.match(seenCookies[0]!, /sid=VAULT_SEED_V1/)
  assert.match(seenCookies[0]!, /pref=VAULT_PREF/)

  // 2. Immediately on the NEXT request, JAR_FIRST_ROT_1 MUST win over VAULT_SEED_V1, while untouched pref=VAULT_PREF stays intact!
  const afterFirstRot = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/me', persona: 'cookie_rot', session: 's1', runId: 'r-q4' },
    grant,
    sig,
  )
  assert.match(seenCookies[1]!, /sid=JAR_FIRST_ROT_1/, 'very first Set-Cookie rotation must supersede stale Vault cookie')
  assert.doesNotMatch(seenCookies[1]!, /VAULT_SEED_V1/, 'stale Vault cookie must not clobber first rotation')
  assert.match(seenCookies[1]!, /pref=VAULT_PREF/, 'untouched Vault cookie must remain intact')
  assert.deepEqual(afterFirstRot.wireCredentialProvenance?.jarCookieNames, ['sid'])
  assert.deepEqual(afterFirstRot.wireCredentialProvenance?.vaultCookieNames, ['pref'])

  // 3. When session expires and broker auto-reauth refreshes Vault to VAULT_REAUTH_V2, the fresh Vault cookie MUST supersede the older jar cookie!
  shouldExpireAfterRot = true
  const afterReauth = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/check-expiry', persona: 'cookie_rot', session: 's1', runId: 'r-q4' },
    grant,
    sig,
  )
  assert.equal(afterReauth.status, 200)
  const finalCookie = seenCookies.at(-1)!
  assert.match(finalCookie, /sid=VAULT_REAUTH_V2/, 'post-reauth fresh Vault cookie must supersede older jar rotation')
  assert.doesNotMatch(finalCookie, /JAR_FIRST_ROT_1/)
  assert.doesNotMatch(finalCookie, /EXPIRED_ANON_COOKIE/)
})

test('Q4.2b: HTTP/2 first-rotation Set-Cookie wins immediately without clobbering untouched Vault cookies', async t => {
  const sessions = new Set<ServerHttp2Session>()
  const seenH2Cookies: string[] = []
  const h2Server = createH2Server()
  h2Server.on('session', s => {
    sessions.add(s)
    s.once('close', () => sessions.delete(s))
  })
  h2Server.on('stream', (stream: ServerHttp2Stream, headers: H2IncomingHeaders) => {
    seenH2Cookies.push(String(headers.cookie ?? ''))
    if (headers[':path'] === '/h2-rot') {
      stream.respond({
        ':status': 200,
        'content-type': 'application/json',
        'set-cookie': 'sid=H2_ROT_1; Path=/',
      })
      stream.end('{"rotated":true}')
      return
    }
    stream.respond({ ':status': 200, 'content-type': 'application/json' })
    stream.end('{"ok":true}')
  })
  await new Promise<void>(resolve => h2Server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${(h2Server.address() as AddressInfo).port}`
  t.after(async () => {
    for (const s of sessions) s.destroy()
    await new Promise<void>(resolve => h2Server.close(() => resolve()))
  })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-q4-h2rot-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const storage = new Store(dir)
    t.after(() => storage.close())
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: 'Q4 H2 Rot', seeds: [origin], environment: 'local-lab',
    })
    const { id: personaId } = createProjectPersona(storage, {
      requestId: randomUUID(),
      projectId,
      handle: 'h2_rot_user',
      roleLabel: 'Member',
      originAllowlist: [origin],
      authKind: 'cookie',
      secret: 'sid=H2_VAULT_OLD; keep=VAULT_KEEP',
      canaryMarkers: [],
    })
    const personas = resolveRunPersonas(storage, projectId, [personaId])
    const grant = makeGrant([origin], { allowLocalLab: true, personas })
    const broker = new RequestBroker({ resolve: async () => [{ address: '127.0.0.1', family: 4 }] })
    t.after(() => broker.closeTransport())

    const sig = AbortSignal.timeout(5_000)
    await broker.executeHttp2Exchange({ origin, method: 'GET', pathAndQuery: '/h2-rot', persona: 'h2_rot_user', session: 'h2j' }, grant, sig)
    await broker.executeHttp2Exchange({ origin, method: 'GET', pathAndQuery: '/h2-me', persona: 'h2_rot_user', session: 'h2j' }, grant, sig)

    assert.match(seenH2Cookies[1]!, /sid=H2_ROT_1/)
    assert.doesNotMatch(seenH2Cookies[1]!, /H2_VAULT_OLD/)
    assert.match(seenH2Cookies[1]!, /keep=VAULT_KEEP/)
  })
})

// ============================================================================
// 3. Multi-origin storageByOrigin isolation & per-origin header resolution
// ============================================================================

test('Q4.3: importStorageState, importHar, and buildSessionFromBrowserBundle isolate storageByOrigin & per-origin headers', async t => {
  // (a) Multi-origin Playwright storageState with colliding `token` & `access_token` keys
  const imported = importStorageState({
    cookies: [
      { name: 'app_sid', value: 'app_cookie_secret_111111', domain: 'app.q4test.example', path: '/', httpOnly: true, secure: true },
      { name: 'api_sid', value: 'api_cookie_secret_222222', domain: 'api.q4test.example', path: '/', httpOnly: true, secure: true },
    ],
    origins: [
      {
        origin: APP_ORIGIN,
        localStorage: [
          { name: 'token', value: 'app_local_token_secret_aaaa' },
          { name: 'access_token', value: 'app_access_secret_1111' },
        ],
      },
      {
        origin: API_ORIGIN,
        localStorage: [
          { name: 'token', value: 'api_local_token_secret_bbbb' },
          { name: 'access_token', value: 'api_access_secret_2222' },
        ],
      },
    ],
  }, [APP_ORIGIN, API_ORIGIN, OTHER_ORIGIN])

  const bundle = imported.session.bundle!
  assert.ok(bundle.storageByOrigin, 'bundle must preserve per-origin storageByOrigin')
  assert.deepEqual(bundle.storageByOrigin?.[APP_ORIGIN]?.localStorage, {
    token: 'app_local_token_secret_aaaa',
    access_token: 'app_access_secret_1111',
  })
  assert.deepEqual(bundle.storageByOrigin?.[API_ORIGIN]?.localStorage, {
    token: 'api_local_token_secret_bbbb',
    access_token: 'api_access_secret_2222',
  })

  // Frame resolution returns strictly origin-isolated storage & cookies (zero clobbering, zero cross-origin leak!)
  const appFrame = frameForSessionOrigin(imported.session, [APP_ORIGIN, API_ORIGIN, OTHER_ORIGIN], APP_ORIGIN)
  const apiFrame = frameForSessionOrigin(imported.session, [APP_ORIGIN, API_ORIGIN, OTHER_ORIGIN], API_ORIGIN)
  const otherFrame = frameForSessionOrigin(imported.session, [APP_ORIGIN, API_ORIGIN, OTHER_ORIGIN], OTHER_ORIGIN)
  assert.equal(appFrame?.storage?.localStorage?.token, 'app_local_token_secret_aaaa')
  assert.equal(apiFrame?.storage?.localStorage?.token, 'api_local_token_secret_bbbb')
  assert.equal(appFrame?.headers.Cookie, 'app_sid=app_cookie_secret_111111')
  assert.equal(apiFrame?.headers.Cookie, 'api_sid=api_cookie_secret_222222')
  assert.equal(otherFrame, null, 'unmapped sibling origin must receive null')

  // All per-origin storage secrets are scrubbed by bundleSecrets() (H-8!)
  const secrets = bundleSecrets(bundle)
  assert.ok(secrets.includes('app_local_token_secret_aaaa'))
  assert.ok(secrets.includes('api_local_token_secret_bbbb'))
  assert.ok(secrets.includes('app_access_secret_1111'))
  assert.ok(secrets.includes('api_access_secret_2222'))

  // (b) Multi-origin HAR where origins[0] has only cookies while origins[1] (api) has Authorization + tenant header
  const har = importHar({
    log: {
      entries: [
        {
          request: {
            url: `${APP_ORIGIN}/dashboard`,
            headers: [{ name: 'X-Tenant-Id', value: 'tenant-app' }],
            cookies: [{ name: 'app_sid', value: 'har_app_cookie_111111', domain: 'app.q4test.example', path: '/' }],
          },
        },
        {
          request: {
            url: `${API_ORIGIN}/v1/items`,
            headers: [
              { name: 'Authorization', value: 'Bearer har_api_bearer_token_999999' },
              { name: 'X-Tenant-Id', value: 'tenant-api' },
            ],
            cookies: [{ name: 'api_sid', value: 'har_api_cookie_222222', domain: 'api.q4test.example', path: '/' }],
          },
        },
      ],
    },
  }, [APP_ORIGIN, API_ORIGIN, OTHER_ORIGIN])

  const dir = mkdtempSync(join(tmpdir(), 'kovo-q4-har-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Q4 Multi-Origin', seeds: [APP_ORIGIN], environment: 'public',
  })
  const created = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'multi_origin_user',
    roleLabel: 'Member',
    originAllowlist: [APP_ORIGIN, API_ORIGIN, OTHER_ORIGIN],
    authKind: 'login',
    loginConfig: { adapter: 'form', email: 'multi@q4test.example' },
    secret: 'MultiPass!123',
    canaryMarkers: [],
  })
  const resolved = resolveRunPersonas(storage, projectId, [created.id]).get('multi_origin_user')!
  writePersonaSessionFile(resolved.sessionPath!, har.session)

  const appHdrs = buildPersonaHeader(resolved, APP_ORIGIN)
  const apiHdrs = buildPersonaHeader(resolved, API_ORIGIN)
  assert.deepEqual(appHdrs, { 'X-Tenant-Id': 'tenant-app', Cookie: 'app_sid=har_app_cookie_111111' })
  assert.deepEqual(apiHdrs, {
    Authorization: 'Bearer har_api_bearer_token_999999',
    'X-Tenant-Id': 'tenant-api',
    Cookie: 'api_sid=har_api_cookie_222222',
  })
  assert.equal(buildPersonaHeader(resolved, OTHER_ORIGIN), null)

  // (c) Multi-origin BrowserStorageBundle preserves per-origin storageByOrigin & observedHeadersByOrigin
  const browserBundle: BrowserStorageBundle = normalizeBrowserStorageBundle({
    v: 1,
    kind: 'browser_session',
    targetOrigin: APP_ORIGIN,
    capturedAt: Date.now(),
    storageState: {
      cookies: [
        { name: 'app_c', value: 'app_val_111111', domain: 'app.q4test.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
        { name: 'api_c', value: 'api_val_222222', domain: 'api.q4test.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
      ],
      origins: [
        { origin: APP_ORIGIN, localStorage: [{ name: 'token', value: 'browser_app_token_111111' }] },
        { origin: API_ORIGIN, localStorage: [{ name: 'token', value: 'browser_api_token_222222' }] },
      ],
    },
    observedHeadersByOrigin: {
      [APP_ORIGIN]: { 'X-Org-Id': 'org-app' },
      [API_ORIGIN]: { Authorization: 'Bearer browser_api_bearer_333333', 'X-Org-Id': 'org-api' },
    },
  })
  const browserSession: MintedPersonaSession = buildSessionFromBrowserBundle(browserBundle, [APP_ORIGIN, API_ORIGIN])
  writePersonaSessionFile(resolved.sessionPath!, browserSession)

  const appAttach = buildPersonaBrowserAttachment(resolved, APP_ORIGIN)
  const apiAttach = buildPersonaBrowserAttachment(resolved, API_ORIGIN)
  assert.equal(appAttach?.storage?.localStorage?.token, 'browser_app_token_111111')
  assert.equal(apiAttach?.storage?.localStorage?.token, 'browser_api_token_222222')
  assert.equal(appAttach?.headers['X-Org-Id'], 'org-app')
  assert.equal(appAttach?.headers.Authorization, undefined, 'API bearer must not leak onto APP origin')
  assert.equal(apiAttach?.headers['X-Org-Id'], 'org-api')
  assert.equal(apiAttach?.headers.Authorization, 'Bearer browser_api_bearer_333333')

  const scrubbed = redact(
    'browser_app_token_111111 browser_api_token_222222 browser_api_bearer_333333',
    personaSecrets(new Map([[resolved.handle, resolved]])),
  )
  assert.equal(scrubbed.includes('browser_app_token_111111'), false)
  assert.equal(scrubbed.includes('browser_api_token_222222'), false)
  assert.equal(scrubbed.includes('browser_api_bearer_333333'), false)
})

// ============================================================================
// 4. Provenance-bound ephemeral credential channel (strict C-3 / H-8 / H-14)
// ============================================================================

test('Q4.4: provenance-bound ephemeral signed tokens pass within same run with accurate wireCredentialProvenance, while arbitrary/cross-run/privileged/Vault tokens stay strictly denied', async t => {
  const mintedJwt = makeSignedJwt({ sub: 'self_reg_user', role: 'user' }, 'self_reg_sig_abcdef123456')
  const mintedOpaque = 'ephem_opaque_signed_tok_9988776655443322'
  const adminMintedJwt = makeSignedJwt({ sub: 'admin_issued', role: 'admin' }, 'admin_only_sig_1122334455')
  const vaultSecretJwt = makeSignedJwt({ sub: 'vault_alice', role: 'member' }, 'vault_secret_sig_77889900')
  const forgedJwt = makeSignedJwt({ sub: 'forged_attacker', role: 'admin' }, 'forged_sig_deadbeef123456')
  const seenAuthHeaders: Array<string | undefined> = []

  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (url, _addr, _sig, opts) => {
      seenAuthHeaders.push(opts?.headers?.authorization ?? opts?.headers?.Authorization)
      if (url.pathname === '/api/auth/register') {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ access_token: mintedJwt, user: { id: 'u-self' } }),
        }
      }
      if (url.pathname === '/api/auth/header-mint') {
        return {
          status: 200,
          headers: { 'content-type': 'application/json', 'x-auth-token': mintedOpaque },
          body: JSON.stringify({ ok: true }),
        }
      }
      if (url.pathname === '/api/admin/mint') {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: adminMintedJwt }),
        }
      }
      if (url.pathname === '/api/leak-vault-echo') {
        // Adversarial simulation: an unauthenticated endpoint echoes a Vault persona's secret JWT!
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ token: vaultSecretJwt }),
        }
      }
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ authed: Boolean(opts?.headers?.authorization || opts?.headers?.Authorization) }),
      }
    },
  })
  t.after(() => broker.closeTransport())

  const vaultAlice = makePersona('alice', { secret: vaultSecretJwt, originAllowlist: [APP_ORIGIN, API_ORIGIN] })
  const adminPersona = makePersona('admin_owner', {
    roleLabel: 'admin:tenant-a',
    secret: 'admin_vault_secret_abcdef123456',
    originAllowlist: [APP_ORIGIN],
  })
  const grant = makeGrant([APP_ORIGIN, API_ORIGIN], {
    tier: 3,
    personas: new Map([
      ['alice', vaultAlice],
      ['admin_owner', adminPersona],
    ]),
    isStateChangeApproved: () => true,
  })
  const sig = AbortSignal.timeout(5_000)

  // 1. Forged / arbitrary signed Bearer token is STILL strictly rejected (C-3)
  await assert.rejects(
    broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', headers: { Authorization: `Bearer ${forgedJwt}` } },
      grant,
      sig,
    ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )

  // 2. Forged Cookie header is STILL strictly rejected
  await assert.rejects(
    broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', headers: { Cookie: 'sid=forged_cookie_1234' } },
      grant,
      sig,
    ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )

  // 3. Self-register in run-A (unauthenticated -> non-privileged): observes mintedJwt digest
  const regRes = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'POST', pathAndQuery: '/api/auth/register', runId: 'run-A', body: '{"email":"new@q4.test"}' },
    grant,
    sig,
  )
  assert.equal(regRes.status, 200)

  // 4. Subsequent request in SAME run-A carrying `Authorization: Bearer <mintedJwt>` SUCCEEDS
  //    and stamps accurate `wireCredentialProvenance` with zero raw token leakage (H-14)!
  const meRes = await broker.executeHttp(
    { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', headers: { Authorization: `Bearer ${mintedJwt}` } },
    grant,
    sig,
  )
  assert.equal(meRes.status, 200)
  assert.equal(seenAuthHeaders.at(-1), `Bearer ${mintedJwt}`)
  const wp = meRes.wireCredentialProvenance!
  assert.equal(wp.authenticated, true)
  assert.equal(wp.source, 'ephemeral_observed')
  assert.deepEqual(wp.sources, ['ephemeral_observed'])
  assert.equal(wp.personaHandle, null)
  assert.deepEqual(wp.headerNames, ['authorization'])
  assert.deepEqual(wp.callerAuthHeaderNames, ['authorization'])
  assert.equal(JSON.stringify(wp).includes(mintedJwt), false, 'raw token must never leak in wireCredentialProvenance')
  assert.equal(JSON.stringify(meRes.reqHeaders).includes(mintedJwt), false, 'raw token must be redacted in reqHeaders')

  // 5. Opaque token observed from response header also works in same run-A
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/auth/header-mint', runId: 'run-A' },
    grant,
    sig,
  )
  const opaqueUse = await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', headers: { Authorization: `Bearer ${mintedOpaque}` } },
    grant,
    sig,
  )
  assert.equal(opaqueUse.status, 200)
  assert.equal(opaqueUse.wireCredentialProvenance?.source, 'ephemeral_observed')

  // 6. Cross-run isolation: mintedJwt from run-A MUST BE DENIED in run-B!
  await assert.rejects(
    broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-B', headers: { Authorization: `Bearer ${mintedJwt}` } },
      grant,
      sig,
    ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )

  // 7. Privileged exchange isolation: token observed from admin_owner response MUST NEVER enter ephemeral channel!
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/admin/mint', persona: 'admin_owner', runId: 'run-A' },
    grant,
    sig,
  )
  await assert.rejects(
    broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', headers: { Authorization: `Bearer ${adminMintedJwt}` } },
      grant,
      sig,
    ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )

  // 8. H-8 Vault secret isolation: even if an unauthenticated response echoes a Vault persona's secret JWT,
  //    it MUST NEVER be admitted via caller Authorization header!
  await broker.executeHttp(
    { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/leak-vault-echo', runId: 'run-A' },
    grant,
    sig,
  )
  await assert.rejects(
    broker.executeHttp(
      { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', headers: { Authorization: `Bearer ${vaultSecretJwt}` } },
      grant,
      sig,
    ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )

  // 9. Scope revocation invalidates observed ephemeral tokens for the revoked origin!
  broker.revokeOrigin(APP_ORIGIN, 1, 'run-A')
  await assert.rejects(
    broker.executeHttp(
      { origin: API_ORIGIN, method: 'GET', pathAndQuery: '/api/me', runId: 'run-A', scopeRevision: 1, headers: { Authorization: `Bearer ${mintedJwt}` } },
      grant,
      sig,
    ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )

  // 10. Direct unit check of validateCallerHeaders & extractBearerTokenDigest
  const digestInfo = extractBearerTokenDigest('Authorization', `Bearer ${mintedJwt}`)
  assert.ok(digestInfo && digestInfo.sha256.length === 64)
  const denied = validateCallerHeaders({ Authorization: `Bearer ${mintedJwt}` }, { isAuthorizedEphemeralBearer: () => false })
  assert.equal(denied.ok, false)
  const allowed = validateCallerHeaders(
    { Authorization: `Bearer ${mintedJwt}` },
    { isAuthorizedEphemeralBearer: d => d === digestInfo.sha256 },
  )
  assert.equal(allowed.ok, true)
  if (allowed.ok) assert.equal(allowed.ephemeralObservedAuth, true)
})
