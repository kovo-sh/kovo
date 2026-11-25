import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  generateTotp,
  importHar,
  importStorageState,
  normalizeTotpSeed,
  PersonaAuthError,
  PersonaAuthManager,
  PersonaSessionPool,
} from '../src/server/persona-auth.ts'
import type { PlaywrightFormBrowserLike } from '../src/server/persona-auth.ts'
import {
  buildPersonaBrowserAttachment,
  buildPersonaHeader,
  createProjectPersona,
  personaSecrets,
  resolveRunPersonas,
  storageHydrationScript,
  writePersonaSessionFile,
} from '../src/server/persona-vault.ts'
import type { MintedPersonaSession, ResolvedPersona } from '../src/server/persona-vault.ts'
import { redact } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'

const appOrigin = 'https://app.example.com'
const apiOrigin = 'https://api.example.com'
const idpOrigin = 'https://idp.example.com'
const otherOrigin = 'https://other.example.com'

const bundleSession: MintedPersonaSession = {
  headerType: 'cookie',
  value: 'app_sid=app-cookie-value-1234567890',
  adapterUsed: 'form',
  bundle: {
    v: 2,
    cookies: [
      {
        name: 'app_sid',
        value: 'app-cookie-value-1234567890',
        domain: 'app.example.com',
        path: '/',
        httpOnly: true,
        secure: true,
      },
      {
        name: 'api_token',
        value: 'api-cookie-value-0987654321',
        domain: 'api.example.com',
        path: '/',
        secure: true,
      },
    ],
    headers: { 'X-Tenant-Id': 'tenant-42' },
    attachments: [
      {
        origin: appOrigin,
        cookies: ['app_sid'],
        headers: { 'X-Org-Id': 'org-app' },
        storage: 'both',
      },
      {
        origin: apiOrigin,
        cookies: ['api_token'],
        headers: { 'X-Org-Id': 'org-api' },
        storage: false,
      },
    ],
    storage: {
      localStorage: { 'kovo.bundle.token': 'storage-jwt-value-abcdef123456' },
      sessionStorage: { 'session-hint': 'session-storage-value-11223344' },
    },
  },
}

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v6-auth-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  return storage
}

function makeLoginPersona(
  storage: Store,
  overrides: {
    handle?: string
    origins?: string[]
    adapter?: 'form' | 'auto'
    loginUrl?: string
    email?: string
    loginExtra?: Record<string, unknown>
  } = {},
): { projectId: string; persona: { id: string; handle: string } } {
  const origins = overrides.origins ?? [appOrigin, apiOrigin, otherOrigin]
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: `v6 auth ${overrides.handle ?? 'bundle'}`,
    seeds: [origins[0]],
    environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: overrides.handle ?? 'bundle_user',
    roleLabel: 'Bundle User',
    originAllowlist: origins,
    authKind: 'login',
    loginConfig: {
      adapter: overrides.adapter ?? 'form',
      email: overrides.email ?? 'bundle@example.com',
      ...(overrides.loginUrl ? { loginUrl: overrides.loginUrl } : {}),
      ...(overrides.loginExtra ?? {}),
    },
    secret: 'V6BundlePassword!42',
    canaryMarkers: [],
  })
  return { projectId, persona }
}

function resolvedPersona(storage: Store, projectId: string, personaId: string): ResolvedPersona {
  const resolved = resolveRunPersonas(storage, projectId, [personaId]).get('bundle_user')
  if (!resolved) throw new Error('persona missing')
  return resolved
}

function persistSession(storage: Store, projectId: string, personaId: string, session: MintedPersonaSession): void {
  const persona = resolvedPersona(storage, projectId, personaId)
  writePersonaSessionFile(persona.sessionPath!, session)
}

interface MockBrowserOptions {
  finalUrl: string
  cookies?: Array<{ name: string; value: string; domain: string; path?: string; httpOnly?: boolean; secure?: boolean; sameSite?: 'Strict' | 'Lax' | 'None'; expires?: number }>
  storage?: { localStorage?: Record<string, string>; sessionStorage?: Record<string, string> }
  otp?: boolean
  captchaWidget?: boolean
  captchaAfterSubmit?: boolean
  ssoButton?: boolean
}

function makeInteractiveBrowser(options: MockBrowserOptions): {
  browser: PlaywrightFormBrowserLike
  filled: Array<{ selector: string; value: string }>
  route: (request: {
    url: string
    method?: string
    resourceType?: string
    headers?: Record<string, string>
  }) => Promise<'aborted' | 'continued' | 'fulfilled'>
  gotoUrls: string[]
} {
  const filled: Array<{ selector: string; value: string }> = []
  const gotoUrls: string[] = []
  let routeHandler: ((route: any) => Promise<void> | void) | undefined
  let phase: 'initial' | 'submitted' = 'initial'
  let otpDone = false
  let currentUrl = options.finalUrl

  const svgSelectors = (selector: string) => ({
    count: async () => {
      if (selector.includes('one-time-code')) return options.otp && phase === 'submitted' && !otpDone ? 1 : 0
      if (selector.includes('password')) return 1
      if (selector.includes('type="email"') || selector.includes('identifier')) return 1
      if (selector.includes('data-kovo-sso')) return options.ssoButton ? 1 : 0
      if (selector.includes('button[type="submit"]')) return 1
      return 0
    },
    first() { return this },
    fill: async (value: string) => {
      filled.push({ selector, value })
      if (selector.includes('one-time-code')) otpDone = true
    },
    click: async () => {
      if (selector.includes('type="submit"')) {
        phase = 'submitted'
        currentUrl = options.finalUrl
      }
    },
    press: async () => {
      phase = 'submitted'
      currentUrl = options.finalUrl
    },
  })

  const page = {
    goto: async (url: string) => {
      gotoUrls.push(url)
      currentUrl = url
    },
    waitForTimeout: async () => undefined,
    waitForLoadState: async () => undefined,
    url: () => currentUrl,
    frames: () => (options.captchaAfterSubmit && phase === 'submitted'
      ? [{ url: () => 'https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile' }]
      : [{ url: () => options.finalUrl }]),
    evaluate: async (fn: () => unknown) => {
      const source = fn.toString()
      if (source.includes('cf-turnstile-response')) return { captcha: options.captchaWidget ?? false, mfa: false }
      if (source.includes('looksJwt') || source.includes('JWT_SHAPE') || source.includes('shape.test')) return []
      if (source.includes('localStorage') || source.includes('sessionStorage')) return options.storage ?? {}
      return null
    },
    locator: (selector: string) => svgSelectors(selector),
    close: async () => undefined,
  }

  const context = {
    route: async (_pattern: string, handler: (route: any) => Promise<void> | void) => { routeHandler = handler },
    addInitScript: async () => undefined,
    routeWebSocket: async () => undefined,
    newPage: async () => page,
    cookies: async () => options.cookies ?? [],
    close: async () => undefined,
  }

  return {
    browser: {
      newContext: async () => context as any,
      close: async () => undefined,
    },
    filled,
    gotoUrls,
    route: async request => {
      if (!routeHandler) return 'fulfilled'
      let decision: 'aborted' | 'continued' | 'fulfilled' = 'fulfilled'
      const route = {
        request: () => ({
          url: () => request.url,
          method: () => request.method ?? 'GET',
          resourceType: () => request.resourceType ?? 'document',
          headers: () => request.headers ?? {},
        }),
        abort: async () => { decision = 'aborted' },
        continue: async () => { decision = 'continued' },
        fulfill: async () => { decision = 'fulfilled' },
      }
      await routeHandler(route)
      return decision
    },
  }
}

test('composite bundle attaches per origin (cookies, tenant/org/CSRF headers) and never leaks cross-origin', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = makeLoginPersona(storage)
  persistSession(storage, projectId, persona.id, bundleSession)
  const resolved = resolvedPersona(storage, projectId, persona.id)

  const app = buildPersonaHeader(resolved, appOrigin)
  assert.deepEqual(app, {
    'X-Tenant-Id': 'tenant-42',
    'X-Org-Id': 'org-app',
    Cookie: 'app_sid=app-cookie-value-1234567890',
  })
  const api = buildPersonaHeader(resolved, apiOrigin)
  assert.deepEqual(api, {
    'X-Tenant-Id': 'tenant-42',
    'X-Org-Id': 'org-api',
    Cookie: 'api_token=api-cookie-value-0987654321',
  })
  // Unmapped sibling origin inside the allowlist receives nothing (no credential fan-out).
  assert.equal(buildPersonaHeader(resolved, otherOrigin), null)
  // Outside the allowlist always null.
  assert.equal(buildPersonaHeader(resolved, 'https://evil.example.net'), null)
})

test('HttpOnly cookies and storage hydrate into a browser attachment and survive a fresh resolve', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = makeLoginPersona(storage)
  persistSession(storage, projectId, persona.id, bundleSession)
  const resolved = resolvedPersona(storage, projectId, persona.id)
  assert.ok(resolved.session?.bundle, 'bundle must persist in the 0600 session file')

  const app = buildPersonaBrowserAttachment(resolved, appOrigin)
  assert.ok(app)
  const httpOnly = app.cookies.find(cookie => cookie.name === 'app_sid')
  assert.ok(httpOnly)
  assert.equal(httpOnly.httpOnly, true)
  assert.equal(httpOnly.secure, true)
  assert.ok(app.cookies.every(cookie => cookie.name !== 'api_token'), 'api cookie must not attach to app origin')
  assert.deepEqual(app.storage?.localStorage, bundleSession.bundle?.storage?.localStorage)
  assert.deepEqual(app.storage?.sessionStorage, bundleSession.bundle?.storage?.sessionStorage)
  assert.ok(app.initScript?.includes('kovo.bundle.token'))

  const api = buildPersonaBrowserAttachment(resolved, apiOrigin)
  assert.ok(api)
  assert.equal(api.storage, null, 'api attachment disables storage hydration')
  assert.ok(api.cookies.every(cookie => cookie.name !== 'app_sid'))

  // Legacy single-cookie path still renders exactly the old Cookie header value.
  const legacyResolved = resolvedPersona(storage, projectId, persona.id)
  legacyResolved.session = {
    headerType: 'cookie',
    value: 'legacy=abc1234567890',
    adapterUsed: 'form',
  }
  assert.deepEqual(buildPersonaHeader(legacyResolved, appOrigin), { Cookie: 'legacy=abc1234567890' })
})

test('storage init script escapes markup and cannot break out of the script context', () => {
  const script = storageHydrationScript({
    localStorage: { payload: '</script><script>alert(1)</script>' },
  })
  assert.ok(script)
  assert.ok(!script!.includes('</script>'))
  assert.ok(script!.includes('\\u003c/script\\u003e'))
})

test('single-flight refresh: three clones share one upstream refresh and retry with the new generation', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = makeLoginPersona(storage)
  persistSession(storage, projectId, persona.id, bundleSession)

  let upstreamCalls = 0
  const pool = new PersonaSessionPool()
  const refreshed: MintedPersonaSession = {
    ...bundleSession,
    value: 'app_sid=rotated-cookie-value-abcdef',
    bundle: {
      ...bundleSession.bundle!,
      cookies: [{ name: 'app_sid', value: 'rotated-cookie-value-abcdef', domain: 'app.example.com', path: '/' }],
    },
  }
  pool.register('bundle_user', {
    session: bundleSession,
    allowlist: [appOrigin, apiOrigin, otherOrigin],
    refresh: async () => {
      upstreamCalls += 1
      await new Promise(resolve => setTimeout(resolve, 25))
      return refreshed
    },
  })

  const clones = [pool.clone('bundle_user')!, pool.clone('bundle_user')!, pool.clone('bundle_user')!]
  assert.ok(clones.every(clone => clone.headersFor(appOrigin)?.Cookie === 'app_sid=app-cookie-value-1234567890'))
  const generations = clones.map(clone => clone.generation)
  const outcomes = await Promise.all(clones.map(clone => clone.reportUnauthorized()))
  assert.deepEqual(outcomes, ['refreshed', 'refreshed', 'refreshed'])
  assert.equal(upstreamCalls, 1, 'one upstream refresh for three sibling clones')
  assert.equal(pool.refreshCount('bundle_user'), 1)
  for (const [index, clone] of clones.entries()) {
    assert.ok(clone.generation > generations[index])
    assert.equal(clone.headersFor(appOrigin)?.Cookie, 'app_sid=rotated-cookie-value-abcdef')
  }
  t.after(() => clones.forEach(clone => clone.dispose()))
})

test('logout isolation: one clone logout cannot clear siblings or trigger a refresh storm', async t => {
  let upstreamCalls = 0
  const pool = new PersonaSessionPool()
  const refreshed: MintedPersonaSession = {
    ...bundleSession,
    bundle: {
      ...bundleSession.bundle!,
      cookies: [{ name: 'app_sid', value: 'post-refresh-cookie-value-998877', domain: 'app.example.com', path: '/' }],
    },
  }
  pool.register('bundle_user', {
    session: bundleSession,
    allowlist: [appOrigin],
    refresh: async () => {
      upstreamCalls += 1
      return refreshed
    },
  })
  const a = pool.clone('bundle_user', 'worker-a')!
  const b = pool.clone('bundle_user', 'worker-b')!
  const c = pool.clone('bundle_user', 'worker-c')!
  const observedByC = c.generation

  b.logout()
  assert.equal(b.isLoggedOut(), true)
  assert.equal(b.headersFor(appOrigin), null)
  assert.ok(a.headersFor(appOrigin)?.Cookie.includes('app-cookie-value'))
  assert.ok(c.headersFor(appOrigin)?.Cookie.includes('app-cookie-value'))
  assert.equal(await b.reportUnauthorized(), 'logged-out')
  assert.equal(upstreamCalls, 0, 'a logged-out clone never triggers refresh')

  // Sibling A rotates the shared credential once.
  assert.equal(await a.reportUnauthorized(), 'refreshed')
  assert.equal(upstreamCalls, 1)

  // C saw the pre-rotation generation: it retries with the fresh credential, no new upstream call.
  assert.equal(await c.reportUnauthorized(observedByC), 'already-fresh')
  assert.equal(upstreamCalls, 1)
  assert.ok(c.headersFor(appOrigin)?.Cookie.includes('post-refresh-cookie-value'))
  t.after(() => [a, b, c].forEach(clone => clone.dispose()))
})

test('OIDC login traverses only allowlisted authOrigins, captures HttpOnly cookies + storage, and accepts TOTP', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = makeLoginPersona(storage, {
    origins: [appOrigin, idpOrigin],
    loginUrl: `${idpOrigin}/oauth2/authorize?client_id=kovo`,
    adapter: 'auto',
    email: 'sso@example.com',
    loginExtra: { authOrigins: ['https://evil.example.net'], totpSeed: 'JBSWY3DPEHPK3PXP' },
  })
  const seed = 'JBSWY3DPEHPK3PXP'
  const mock = makeInteractiveBrowser({
    finalUrl: `${appOrigin}/dashboard`,
    cookies: [
      { name: 'app_session', value: 'sso-session-cookie-value-445566', domain: 'app.example.com', path: '/', httpOnly: true, secure: true },
      { name: 'idp_hint', value: 'idp-hint-value-778899', domain: 'idp.example.com', path: '/', httpOnly: true },
    ],
    storage: { localStorage: { 'app.access_token': 'storage-token-value-123456' } },
    otp: true,
    ssoButton: true,
  })
  const manager = new PersonaAuthManager({
    launchBrowser: async () => mock.browser,
    resolveHost: async host => (host === 'evil.example.net' ? [] : ['93.184.216.34']),
  })
  manager.registerSession(persona.handle, {
    session: { ...bundleSession, headerType: 'cookie', value: '' },
    allowlist: [appOrigin, idpOrigin],
  })
  // Runtime authOrigins outside the existing allowlist are ignored by the traversal guard.
  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.headerType, 'cookie')
  assert.equal(result.adapterUsed, 'form')

  // TOTP was generated from the seed (allow adjacent windows for clock rollover).
  const otpFill = mock.filled.find(entry => entry.selector.includes('one-time-code'))
  assert.ok(otpFill, 'OTP field must be filled from the TOTP seed')
  const now = Date.now()
  const validCodes = new Set([
    generateTotp(seed, { atMs: now }),
    generateTotp(seed, { atMs: now - 30_000 }),
    generateTotp(seed, { atMs: now + 30_000 }),
  ])
  assert.ok(validCodes.has(otpFill!.value), `generated TOTP ${otpFill!.value} must be accepted`)
  assert.equal(seed.length, 16)

  const fresh = resolvedPersona(storage, projectId, persona.id)
  assert.ok(fresh.session?.bundle?.cookies?.some(cookie => cookie.name === 'app_session' && cookie.httpOnly === true))
  assert.deepEqual(fresh.session?.bundle?.storage?.localStorage, { 'app.access_token': 'storage-token-value-123456' })
  assert.deepEqual(buildPersonaHeader(fresh, appOrigin), { Cookie: 'app_session=sso-session-cookie-value-445566' })

  // Route guard: IdP navigation continues, non-allowlisted identity providers are aborted —
  // even when named in a runtime authOrigins list.
  assert.equal(await mock.route({ url: `${idpOrigin}/oauth2/authorize`, method: 'GET', resourceType: 'document' }), 'continued')
  assert.equal(await mock.route({ url: 'https://evil.example.net/oauth2/authorize', method: 'GET', resourceType: 'document' }), 'aborted')
  assert.equal(await mock.route({ url: 'https://cdn.evil.example.net/app.js', method: 'GET', resourceType: 'script' }), 'aborted')

  // The IdP cookie never attaches to the application origin.
  assert.ok(!(buildPersonaHeader(fresh, appOrigin)?.Cookie ?? '').includes('idp_hint'))
})

test('TOTP generation follows RFC 6238 and accepts otpauth URIs', () => {
  // RFC 6238 SHA-1 test vector: ASCII "12345678901234567890" base32.
  const seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
  assert.equal(generateTotp(seed, { digits: 8, atMs: 59_000 }), '94287082')
  assert.equal(generateTotp(seed, { digits: 8, atMs: 1_111_111_109_000 }), '07081804')
  assert.ok(normalizeTotpSeed(`otpauth://totp/Kovo:test?secret=${seed}&issuer=Kovo`))
  assert.equal(normalizeTotpSeed('not a base32 secret!'), null)
  assert.throws(() => generateTotp('bad seed!'), (err: unknown) => err instanceof PersonaAuthError)
})

test('storageState import hydrates HttpOnly cookies and per-origin storage without network access', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = makeLoginPersona(storage)
  const manager = new PersonaAuthManager()

  const result = await manager.importSession(storage, projectId, persona.id, {
    cookies: [
      {
        name: 'app_sid',
        value: 'imported-cookie-value-1122334455',
        domain: 'app.example.com',
        path: '/',
        expires: Math.floor(Date.now() / 1000) + 3600,
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      },
      {
        name: 'api_sid',
        value: 'imported-api-cookie-value-6677889900',
        domain: 'api.example.com',
        path: '/',
        httpOnly: true,
        secure: true,
      },
    ],
    origins: [
      {
        origin: appOrigin,
        localStorage: [{ name: 'app.jwt', value: 'imported-storage-jwt-value-556677' }],
      },
    ],
  }, 'storage-state')

  assert.equal(result.adapterUsed, 'import')
  assert.equal(result.headerType, 'cookie')
  const resolved = resolvedPersona(storage, projectId, persona.id)
  assert.deepEqual(buildPersonaHeader(resolved, appOrigin), { Cookie: 'app_sid=imported-cookie-value-1122334455' })
  assert.deepEqual(buildPersonaHeader(resolved, apiOrigin), { Cookie: 'api_sid=imported-api-cookie-value-6677889900' })

  const app = buildPersonaBrowserAttachment(resolved, appOrigin)
  assert.equal(app?.cookies.find(cookie => cookie.name === 'app_sid')?.httpOnly, true)
  assert.deepEqual(app?.storage?.localStorage, { 'app.jwt': 'imported-storage-jwt-value-556677' })
  assert.equal(buildPersonaBrowserAttachment(resolved, apiOrigin)?.storage, null)

  // HAR import: Authorization + tenant header scoped to the API origin only.
  const har = importHar({
    log: {
      entries: [
        {
          request: {
            url: `${apiOrigin}/v1/me`,
            headers: [
              { name: 'Authorization', value: 'Bearer har-imported-token-value-1234567890' },
              { name: 'X-Tenant-Id', value: 'tenant-har' },
              { name: 'X-Org-Id', value: 'org-har' },
              { name: 'X-CSRF-Token', value: 'csrf-har-value-99887766' },
              { name: 'Accept', value: 'application/json' },
            ],
            cookies: [{ name: 'api_sid', value: 'har-cookie-value-1234567890', domain: 'api.example.com', path: '/' }],
          },
        },
      ],
    },
  }, [appOrigin, apiOrigin])
  assert.ok(har.session.bundle)
  const harApiHeaders = har.session.bundle?.attachments?.find(rule => rule.origin === apiOrigin)?.headers
  assert.ok(harApiHeaders)
  assert.equal(harApiHeaders!.Authorization, 'Bearer har-imported-token-value-1234567890')
  assert.equal(harApiHeaders!['X-Tenant-Id'], 'tenant-har')
  assert.equal(harApiHeaders!['X-Org-Id'], 'org-har')
  assert.equal(harApiHeaders!['X-CSRF-Token'], 'csrf-har-value-99887766')
  assert.equal(harApiHeaders!.Accept, undefined)
})

test('CAPTCHA: a script tag alone never blocks, a rendered widget does, and a post-submit challenge is terminal', async t => {
  // 1. Script-tag-only page: login succeeds.
  {
    const storage = makeStorage(t)
    const { projectId, persona } = makeLoginPersona(storage, { handle: 'bundle_user', origins: [appOrigin], loginUrl: `${appOrigin}/login`, adapter: 'form' })
    const mock = makeInteractiveBrowser({
      finalUrl: `${appOrigin}/dashboard`,
      cookies: [{ name: 'sid', value: 'script-only-cookie-value-123456', domain: 'app.example.com', path: '/' }],
    })
    const manager = new PersonaAuthManager({ launchBrowser: async () => mock.browser })
    const result = await manager.authenticatePersona(storage, projectId, persona.id)
    assert.equal(result.headerType, 'cookie')
    assert.ok(mock.filled.some(entry => entry.value === 'bundle@example.com'))
  }

  // 2. Rendered challenge widget: aborts before any interaction.
  {
    const storage = makeStorage(t)
    const { projectId, persona } = makeLoginPersona(storage, { origins: [appOrigin], loginUrl: `${appOrigin}/login`, adapter: 'form' })
    const mock = makeInteractiveBrowser({ finalUrl: `${appOrigin}/login`, captchaWidget: true })
    const manager = new PersonaAuthManager({ launchBrowser: async () => mock.browser })
    await assert.rejects(
      manager.authenticatePersona(storage, projectId, persona.id),
      (err: unknown) => err instanceof PersonaAuthError && err.code === 'CAPTCHA_DETECTED',
    )
    assert.equal(mock.filled.length, 0, 'must never type credentials into a challenge page')
  }

  // 3. Enterprise OIDC: credentials submitted, then the challenge blocks the session.
  {
    const storage = makeStorage(t)
    const { projectId, persona } = makeLoginPersona(storage, {
      origins: [appOrigin, idpOrigin],
      loginUrl: `${idpOrigin}/oauth2/authorize`,
      adapter: 'auto',
    })
    const mock = makeInteractiveBrowser({
      finalUrl: `${appOrigin}/dashboard`,
      cookies: [{ name: 'sid', value: 'blocked-cookie-value-123456', domain: 'app.example.com', path: '/' }],
      captchaAfterSubmit: true,
    })
    const manager = new PersonaAuthManager({ launchBrowser: async () => mock.browser })
    await assert.rejects(
      manager.authenticatePersona(storage, projectId, persona.id),
      (err: unknown) => err instanceof PersonaAuthError && err.code === 'CAPTCHA_DETECTED',
    )
    assert.ok(mock.filled.some(entry => entry.value === 'bundle@example.com'))
  }
})

test('no secrets leak: bundle values are scrubbed everywhere and rejected imports never echo credentials', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = makeLoginPersona(storage)
  persistSession(storage, projectId, persona.id, bundleSession)
  const resolved = resolvedPersona(storage, projectId, persona.id)
  const secrets = personaSecrets(new Map([[resolved.handle, resolved]]))
  const everything = [
    'app-cookie-value-1234567890',
    'api-cookie-value-0987654321',
    'storage-jwt-value-abcdef123456',
    'session-storage-value-11223344',
    'tenant-42',
  ].join(' ')
  const scrubbed = redact(everything, secrets)
  for (const value of ['app-cookie-value-1234567890', 'api-cookie-value-0987654321', 'storage-jwt-value-abcdef123456', 'session-storage-value-11223344']) {
    assert.ok(!scrubbed.includes(value), `${value} must be scrubbed from logs`)
  }

  // Import failure for an out-of-scope origin does not echo the credential value.
  assert.throws(
    () => importStorageState({
      cookies: [{ name: 'x', value: 'out-of-scope-secret-value-99887766', domain: 'evil.example.net', path: '/' }],
      origins: [],
    }, [appOrigin]),
    (err: unknown) => {
      assert.ok(err instanceof PersonaAuthError)
      assert.ok(!err.message.includes('out-of-scope-secret-value-99887766'))
      return true
    },
  )
})
