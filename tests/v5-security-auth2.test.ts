import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { once } from 'node:events'
import {
  classifyAddress,
  createPinnedLookup,
  formChromiumLaunchArgs,
  isClerkCredentialHost,
  isHostInScope,
  PersonaAuthError,
  PersonaAuthManager,
  registrableDomain,
} from '../src/server/persona-auth.ts'
import type { PlaywrightFormBrowserLike } from '../src/server/persona-auth.ts'
import { isCredentialScopeHost, isPublicSuffixHost } from '../src/server/public-suffix.ts'
import { createProjectPersona } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

// Loopback credential targets are a local-lab feature; the store validates seeds against it.
process.env.GUARDIAN_ALLOW_LOCAL_LAB ??= '1'

const targetOrigin = 'https://app.example.com'

function makeStorage(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'guardian-sec2-auth-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  return storage
}

function createPersona(
  storage: Store,
  overrides: {
    handle: string
    originAllowlist: string[]
    adapter: 'json' | 'form' | 'clerk'
    loginUrl?: string
    email?: string
    environment?: 'public' | 'local-lab'
  },
) {
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name: `sec2 ${overrides.handle}`,
    seeds: [overrides.originAllowlist[0]],
    environment: overrides.environment ?? 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: overrides.handle,
    roleLabel: overrides.handle,
    originAllowlist: overrides.originAllowlist,
    authKind: 'login',
    loginConfig: {
      adapter: overrides.adapter,
      email: overrides.email ?? `${overrides.handle}@example.com`,
      ...(overrides.loginUrl ? { loginUrl: overrides.loginUrl } : {}),
    },
    secret: 'Sec2AuthPassword!7',
    canaryMarkers: [],
  })
  return { projectId, persona }
}

async function startJsonServer(): Promise<{
  origin: string
  requests: Array<{ url?: string; host?: string; body: string }>
  close: () => Promise<void>
}> {
  const requests: Array<{ url?: string; host?: string; body: string }> = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', chunk => { body += String(chunk) })
    req.on('end', () => {
      requests.push({ url: req.url, host: req.headers.host, body })
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ access_token: 'opaque-session-token-value', expires_in: 3600 }))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('No port.')
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    close: async () => { await new Promise<void>(resolve => server.close(() => resolve())) },
  }
}

function makeFormBrowser(options: {
  requestUrl?: string
  resourceType?: string
  cookies?: Array<{ name: string; value: string; domain: string }>
  withRouteWebSocket?: boolean
  withInitScript?: boolean
  onContext?: (options: Record<string, unknown>) => void
} = {}): {
  browser: PlaywrightFormBrowserLike
  routeDecisions: Array<'aborted' | 'continued'>
  wsDecisions: Array<'closed' | 'connected'>
  initScripts: string[]
  pinnedHostsSeen: Array<ReadonlyMap<string, readonly string[]> | undefined>
} {
  const routeDecisions: Array<'aborted' | 'continued'> = []
  const wsDecisions: Array<'closed' | 'connected'> = []
  const initScripts: string[] = []
  const pinnedHostsSeen: Array<ReadonlyMap<string, readonly string[]> | undefined> = []
  let router: ((route: unknown) => Promise<void> | void) | undefined
  let wsHandler: ((ws: {
    url(): string
    close(options?: { code?: number; reason?: string }): Promise<void> | void
    connectToServer?(): Promise<void> | void
  }) => Promise<void> | void) | undefined

  const page = {
    goto: async () => {
      if (!router) return
      await router({
        request: () => ({
          url: () => options.requestUrl ?? `${targetOrigin}/login`,
          method: () => 'GET',
          resourceType: () => options.resourceType ?? 'document',
          headers: () => ({}),
        }),
        abort: async () => { routeDecisions.push('aborted') },
        continue: async () => { routeDecisions.push('continued') },
      })
    },
    waitForTimeout: async () => undefined,
    waitForLoadState: async () => undefined,
    url: () => `${targetOrigin}/login`,
    frames: () => [{ url: () => `${targetOrigin}/login` }],
    evaluate: async () => ({ captcha: false, mfa: false }),
    locator: () => ({
      count: async () => 1,
      first() { return this },
      fill: async () => undefined,
      click: async () => undefined,
    }),
    close: async () => undefined,
  }

  const context = {
    route: async (_pattern: string, handler: (route: unknown) => Promise<void> | void) => { router = handler },
    ...(options.withRouteWebSocket === false ? {} : {
      routeWebSocket: async (_pattern: string, handler: typeof wsHandler) => { wsHandler = handler },
    }),
    ...(options.withInitScript === false ? {} : {
      addInitScript: async (script: string) => { initScripts.push(script) },
    }),
    newPage: async () => page,
    cookies: async () => options.cookies ?? [{ name: 'sid', value: 'sec2_form_session_cookie_1234567890', domain: 'app.example.com' }],
    close: async () => undefined,
  }

  const browser: PlaywrightFormBrowserLike = {
    newContext: async (contextOptions?: Record<string, unknown>) => {
      options.onContext?.(contextOptions ?? {})
      return context as never
    },
    close: async () => undefined,
  }

  return {
    browser,
    routeDecisions,
    wsDecisions,
    initScripts,
    pinnedHostsSeen,
  }
}

test('PSL scoping: shared tenant suffixes never widen credential scope', () => {
  // github.io is a PRIVATE-section suffix: each tenant is its own principal.
  assert.equal(registrableDomain('app.example.github.io'), 'example.github.io')
  assert.equal(isHostInScope('app.example.github.io', ['https://app.example.github.io']), true)
  assert.equal(isHostInScope('evil.github.io', ['https://app.example.github.io']), false)
  // Subdomains of the tenant itself remain in scope; only sibling tenants are excluded.
  assert.equal(isHostInScope('other.example.github.io', ['https://app.example.github.io']), true)

  // Vercel / S3 / ccTLD second levels are suffixes themselves and cannot anchor scope.
  assert.equal(isPublicSuffixHost('vercel.app'), true)
  assert.equal(isPublicSuffixHost('s3.amazonaws.com'), true)
  assert.equal(isPublicSuffixHost('com.co'), true)
  assert.equal(isCredentialScopeHost('vercel.app'), false)
  assert.equal(isCredentialScopeHost('s3.amazonaws.com'), false)
  assert.equal(isCredentialScopeHost('com.co'), false)
  assert.equal(registrableDomain('a.b.example.com.co'), 'example.com.co')
  assert.equal(isHostInScope('attacker.com.co', ['https://a.b.example.com.co']), false)

  // Ordinary registrable domains still work.
  assert.equal(registrableDomain('app.example.com'), 'example.com')
  assert.equal(isHostInScope('static.example.com', ['https://app.example.com']), true)
  assert.equal(isHostInScope('example.com', ['https://app.example.com']), true)
  assert.equal(isHostInScope('attacker.example.net', ['https://app.example.com']), false)

  // Wildcard and exception rules from the PSL are honoured.
  assert.equal(isPublicSuffixHost('foo.ck'), true, '*.ck makes X.ck a suffix')
  assert.equal(registrableDomain('a.b.ck'), 'a.b.ck')
  assert.equal(registrableDomain('www.ck'), 'www.ck', '!www.ck is an exception rule')
  assert.equal(registrableDomain('city.kawasaki.jp'), 'city.kawasaki.jp', '!city.kawasaki.jp is an exception rule')

  // Clerk/IdP credential hosts must be named exactly (or be the derived clerk.<apex>).
  assert.equal(isClerkCredentialHost('https://clerk.example.com', ['https://app.example.com']), true)
  assert.equal(isClerkCredentialHost('https://login.example.com', ['https://app.example.com']), false)
  assert.equal(isClerkCredentialHost('https://auth.example.com', ['https://app.example.com']), false)
  // An operator-named URL authorizes exactly that host, not an arbitrary sibling.
  assert.equal(isClerkCredentialHost('https://auth.other.example', ['https://app.example.com'], 'https://login.example.com'), false)
  assert.equal(isClerkCredentialHost('https://login.example.com', ['https://app.example.com'], 'https://login.example.com'), true)
})

test('credential targets on shared suffixes are refused before any request', async t => {
  const storage = makeStorage(t)
  for (const [host, label] of [
    ['https://vercel.app', 'vercel'],
    ['https://s3.amazonaws.com', 's3'],
    ['https://com.co', 'comco'],
    ['https://github.io', 'githubio'],
  ] as const) {
    const { projectId, persona } = createPersona(storage, {
      handle: `${label}_user`,
      originAllowlist: [host],
      adapter: 'json',
      loginUrl: `${host}/api/login`,
    })
    let calls = 0
    const manager = new PersonaAuthManager({
      fetchImpl: async () => { calls += 1; return new Response('{}', { status: 200 }) },
      resolveHost: async () => ['93.184.216.34'],
    })
    await assert.rejects(
      manager.authenticatePersona(storage, projectId, persona.id),
      (err: unknown) => err instanceof PersonaAuthError && /shared public\/private suffix|opaque single-label/i.test(err.message),
      `${host} must not anchor a credential scope`,
    )
    assert.equal(calls, 0, `${host} must be refused before credentials are sent`)
  }
})

test('a normal registrable-domain credential target still authenticates', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = createPersona(storage, {
    handle: 'normal_user',
    originAllowlist: [targetOrigin],
    adapter: 'json',
    loginUrl: `${targetOrigin}/api/login`,
  })
  const manager = new PersonaAuthManager({
    fetchImpl: async () => new Response(JSON.stringify({ access_token: 'opaque-normal-token' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
    resolveHost: async () => ['93.184.216.34'],
  })
  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.adapterUsed, 'json')
  assert.equal(result.headerType, 'bearer')
})

test('form loginUrl outside the allowlist or on plain HTTP is refused before launch', async t => {
  const storage = makeStorage(t)
  let launches = 0
  const manager = new PersonaAuthManager({
    launchBrowser: async () => { launches += 1; return makeFormBrowser().browser },
    resolveHost: async () => ['93.184.216.34'],
  })

  const outOfScope = createPersona(storage, {
    handle: 'form_out_of_scope',
    originAllowlist: [targetOrigin],
    adapter: 'form',
    loginUrl: 'https://login.attacker.example/login',
  })
  await assert.rejects(
    manager.authenticatePersona(storage, outOfScope.projectId, outOfScope.persona.id),
    (err: unknown) => err instanceof PersonaAuthError && /outside the persona origin allowlist/i.test(err.message),
  )

  const plaintext = createPersona(storage, {
    handle: 'form_plaintext',
    originAllowlist: [targetOrigin],
    adapter: 'form',
    loginUrl: `http://${new URL(targetOrigin).hostname}/login`,
  })
  await assert.rejects(
    manager.authenticatePersona(storage, plaintext.projectId, plaintext.persona.id),
    (err: unknown) => err instanceof PersonaAuthError && /must use HTTPS/i.test(err.message),
  )

  assert.equal(launches, 0, 'No browser may start for a refused login URL')
})

test('form login on an explicitly allowlisted loopback origin still works', async t => {
  const storage = makeStorage(t)
  const loopbackOrigin = 'http://127.0.0.1:43871'
  const fake = makeFormBrowser({ requestUrl: `${loopbackOrigin}/login` })
  const manager = new PersonaAuthManager({ launchBrowser: async () => fake.browser })
  const { projectId, persona } = createPersona(storage, {
    handle: 'form_loopback',
    originAllowlist: [loopbackOrigin],
    adapter: 'form',
    loginUrl: `${loopbackOrigin}/login`,
    environment: 'local-lab',
  })
  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.adapterUsed, 'form')
  assert.equal(result.headerType, 'cookie')
  assert.deepEqual(fake.routeDecisions, ['continued'])
  assert.equal(classifyAddress('localhost'), 'loopback')
})

test('empty DNS resolution is refused for credential targets', async t => {
  const storage = makeStorage(t)
  const { projectId, persona } = createPersona(storage, {
    handle: 'empty_resolution',
    originAllowlist: [targetOrigin],
    adapter: 'json',
    loginUrl: `${targetOrigin}/api/login`,
  })
  let calls = 0
  const manager = new PersonaAuthManager({
    fetchImpl: async () => { calls += 1; return new Response('{}', { status: 200 }) },
    resolveHost: async () => [],
  })
  await assert.rejects(
    manager.authenticatePersona(storage, projectId, persona.id),
    (err: unknown) => err instanceof PersonaAuthError && /did not resolve/i.test(err.message),
  )
  assert.equal(calls, 0, 'NXDOMAIN at check time must not be re-resolved at connect time')
})

test('pinned lookup refuses other hosts and never re-consults the resolver', async () => {
  const lookup = createPinnedLookup('api.example.com', ['93.184.216.34'])
  const pinned = await new Promise<{ address?: string; error?: Error }>(resolve => {
    lookup('api.example.com', {}, (error: unknown, address: unknown) => {
      resolve({ error: error instanceof Error ? error : undefined, address: typeof address === 'string' ? address : undefined })
    })
  })
  assert.equal(pinned.error, undefined)
  assert.equal(pinned.address, '93.184.216.34')

  const other = await new Promise<Error | undefined>(resolve => {
    lookup('attacker.example.com', {}, (error: unknown) => resolve(error instanceof Error ? error : undefined))
  })
  assert.ok(other, 'The pinned resolver must refuse a host it was not validated for')
})

test('validated address is pinned for the connection; a later answer cannot redirect it', async t => {
  const server = await startJsonServer()
  t.after(() => server.close())
  const storage = makeStorage(t)
  let resolutions = 0
  const { projectId, persona } = createPersona(storage, {
    handle: 'pinned_json',
    originAllowlist: [server.origin],
    adapter: 'json',
    loginUrl: `${server.origin}/api/login`,
    environment: 'local-lab',
  })
  const manager = new PersonaAuthManager({
    // First (validated) answer is loopback for the explicitly allowlisted origin; any later
    // answer would be a rebinding attempt and must never be used.
    resolveHost: async () => {
      resolutions += 1
      return resolutions === 1 ? ['127.0.0.1'] : ['10.0.0.5']
    },
  })
  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.adapterUsed, 'json')
  assert.equal(resolutions, 1, 'The connect path must not resolve the host a second time')
  assert.equal(server.requests.length, 1, 'The request must reach the validated address exactly once')
})

test('allowlisted localhost login works and resolves to a loopback literal', async t => {
  const server = await startJsonServer()
  t.after(() => server.close())
  const port = new URL(server.origin).port
  const storage = makeStorage(t)
  const { projectId, persona } = createPersona(storage, {
    handle: 'localhost_json',
    originAllowlist: [`http://localhost:${port}`],
    adapter: 'json',
    loginUrl: `http://localhost:${port}/api/login`,
    environment: 'local-lab',
  })
  const manager = new PersonaAuthManager()
  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.adapterUsed, 'json')
  assert.equal(server.requests.length, 1)
  assert.equal(classifyAddress('localhost'), 'loopback')
})

test('form browser is sandboxed, blocks service workers, and pins resolved hosts', async t => {
  const storage = makeStorage(t)
  let contextOptions: Record<string, unknown> = {}
  let launchArgs: string[] = []
  let pinned: ReadonlyMap<string, readonly string[]> | undefined
  const fake = makeFormBrowser({
    onContext: options => { contextOptions = options },
  })
  const manager = new PersonaAuthManager({
    launchBrowser: async pinnedHosts => {
      pinned = pinnedHosts
      launchArgs = formChromiumLaunchArgs({ pinnedHosts })
      return fake.browser
    },
    resolveHost: async hostname => hostname === 'app.example.com' ? ['93.184.216.34'] : ['93.184.216.35'],
  })
  const { projectId, persona } = createPersona(storage, {
    handle: 'form_pinned',
    originAllowlist: [targetOrigin],
    adapter: 'form',
    loginUrl: `${targetOrigin}/login`,
  })
  await manager.authenticatePersona(storage, projectId, persona.id)

  assert.equal(contextOptions.serviceWorkers, 'block')
  assert.equal(contextOptions.ignoreHTTPSErrors, false)
  assert.equal(pinned?.get('app.example.com')?.[0], '93.184.216.34')
  assert.ok(launchArgs.some(arg => arg.includes('MAP app.example.com 93.184.216.34')))
  assert.ok(launchArgs.some(arg => arg.includes('MAP * ~NOTFOUND')))
  assert.equal(launchArgs.includes('--no-sandbox'), false, 'Sandbox must stay enabled by default')
})

test('form browser blocks service workers, unknown DNS, rebound pins, and non-http schemes', async t => {
  const storage = makeStorage(t)
  const runRoute = async (
    requestUrl: string,
    resolveHost: (hostname: string) => Promise<string[]>,
    resourceType = 'stylesheet',
  ) => {
    const fake = makeFormBrowser({ requestUrl, resourceType })
    const manager = new PersonaAuthManager({ launchBrowser: async () => fake.browser, resolveHost })
    const { projectId, persona } = createPersona(storage, {
      handle: `form_route_${randomUUID().slice(0, 8)}`,
      originAllowlist: [targetOrigin],
      adapter: 'form',
      loginUrl: `${targetOrigin}/login`,
    })
    await manager.authenticatePersona(storage, projectId, persona.id)
    return fake.routeDecisions
  }

  assert.deepEqual(
    await runRoute('https://cdn.attacker.example/theme.css', async () => ['93.184.216.34']),
    ['aborted'],
    'Off-scope subresources must be blocked',
  )
  assert.deepEqual(
    await runRoute('https://static.example.com/theme.css', async () => []),
    ['aborted'],
    'An unknown/empty resolution must never be treated as safe',
  )
  assert.deepEqual(
    await runRoute('file:///etc/hosts', async () => ['93.184.216.34']),
    ['aborted'],
    'file: URLs are not a credential channel',
  )
  assert.deepEqual(
    await runRoute('https://static.example.com/theme.css', async () => ['93.184.216.34']),
    ['continued'],
    'In-scope static assets on a validated public host may load',
  )

  // Rebind after launch: the host was pinned to 93.184.216.34, then resolves to loopback.
  let calls = 0
  const rebound = await runRoute('https://app.example.com/theme.css', async () => {
    calls += 1
    return calls === 1 ? ['93.184.216.34'] : ['127.0.0.1']
  })
  assert.deepEqual(rebound, ['aborted'], 'A host that rebinds after launch must be refused')
})

test('form browser WebSocket guard closes off-scope sockets and fails closed without routeWebSocket', async t => {
  const storage = makeStorage(t)
  let wsHandler: ((ws: {
    url(): string
    close(options?: { code?: number; reason?: string }): Promise<void> | void
    connectToServer?(): Promise<void> | void
  }) => Promise<void> | void) | undefined
  const decisions: string[] = []
  const browser = makeFormBrowser()
  const context = {
    route: async () => undefined,
    routeWebSocket: async (_pattern: string, handler: typeof wsHandler) => { wsHandler = handler },
    addInitScript: async () => undefined,
    newPage: async () => ({
      goto: async () => undefined,
      waitForTimeout: async () => undefined,
      waitForLoadState: async () => undefined,
      url: () => `${targetOrigin}/login`,
      frames: () => [{ url: () => `${targetOrigin}/login` }],
      evaluate: async () => ({ captcha: false, mfa: false }),
      locator: () => ({ count: async () => 1, first() { return this }, fill: async () => undefined, click: async () => undefined }),
      close: async () => undefined,
    }),
    cookies: async () => [{ name: 'sid', value: 'sec2_ws_cookie_1234567890', domain: 'app.example.com' }],
    close: async () => undefined,
  }
  const manager = new PersonaAuthManager({
    launchBrowser: async () => ({ newContext: async () => context as never, close: async () => undefined }),
    resolveHost: async () => ['93.184.216.34'],
  })
  const { projectId, persona } = createPersona(storage, {
    handle: 'form_ws',
    originAllowlist: [targetOrigin],
    adapter: 'form',
    loginUrl: `${targetOrigin}/login`,
  })
  await manager.authenticatePersona(storage, projectId, persona.id)
  assert.ok(wsHandler, 'The form browser must install a WebSocket guard')

  const socket = (url: string, withConnect = true) => ({
    url: () => url,
    close: () => { decisions.push('closed') },
    ...(withConnect ? { connectToServer: () => { decisions.push('connected') } } : {}),
  })
  await wsHandler!(socket('wss://attacker.example/socket'))
  await wsHandler!(socket('wss://app.example.com/socket'))
  await wsHandler!(socket('ws://app.example.com/socket'))
  assert.deepEqual(decisions, ['closed', 'connected', 'closed'])

  // Older Playwright without routeWebSocket: the page loses the socket constructors.
  const fallback = makeFormBrowser({ withRouteWebSocket: false, withInitScript: true })
  const fallbackManager = new PersonaAuthManager({ launchBrowser: async () => fallback.browser, resolveHost: async () => ['93.184.216.34'] })
  const second = createPersona(storage, {
    handle: 'form_ws_fallback',
    originAllowlist: [targetOrigin],
    adapter: 'form',
    loginUrl: `${targetOrigin}/login`,
  })
  await fallbackManager.authenticatePersona(storage, second.projectId, second.persona.id)
  assert.ok(fallback.initScripts.some(script => /WebSocket/.test(script)), 'A fail-closed socket deny script must be installed')
  assert.ok(browser, 'baseline browser helper is used')
})
