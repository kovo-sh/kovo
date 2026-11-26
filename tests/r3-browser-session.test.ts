import assert from 'node:assert/strict'
import { once } from 'node:events'
import { readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { resolve } from 'node:path'
import { test } from 'node:test'
import {
  browserSessionChromiumArgs,
  BrowserSessionRefreshBlockedError,
  buildBrowserSessionChromiumLaunchOptions,
  cookieMatchesAllowedOrigins,
  createBrowserSessionProxy,
  evaluateBrowserSessionProxyOrigin,
  filterStorageStateForRefresh,
  formatChromiumSandboxLaunchError,
  isVerifyPathModifiedByRun,
  refreshBrowserSession,
  resolveBrowserSessionEgressPolicy,
  startInteractiveLoginCapture,
} from '../src/server/browser-session-auth.ts'
import type {
  BrowserSessionChromiumLaunchOptions,
  PlaywrightBrowserLike,
  PlaywrightRouteLike,
  PlaywrightStorageState,
  PlaywrightWebSocketRouteLike,
} from '../src/server/browser-session-auth.ts'
import type { ScopePolicy } from '../src/server/scope-policy.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeMockBrowser(capture: {
  launchOpts?: BrowserSessionChromiumLaunchOptions
  contextOpts?: Record<string, unknown>
  routeHandler?: (route: PlaywrightRouteLike) => Promise<void> | void
  wsHandler?: (ws: PlaywrightWebSocketRouteLike) => Promise<void> | void
  initScripts?: string[]
  onGoto?: (url: string, fireRequest: (req: { url: () => string; headers: () => Record<string, string> }) => void) => void
  returnedState?: PlaywrightStorageState
}) {
  return async (opts: BrowserSessionChromiumLaunchOptions): Promise<PlaywrightBrowserLike> => {
    capture.launchOpts = opts
    return {
      async newContext(ctxOpts) {
        capture.contextOpts = ctxOpts
        let requestListener: ((req: unknown) => void) | undefined
        let currentUrl = ''
        const seededState = (ctxOpts?.storageState as PlaywrightStorageState | undefined) ?? { cookies: [], origins: [] }
        const page = {
          async goto(url: string) {
            currentUrl = url
            capture.onGoto?.(url, req => requestListener?.(req))
          },
          async waitForLoadState() {},
          async waitForTimeout() {},
          url: () => currentUrl,
          async title() { return 'Mock Page' },
          on(event: string, listener: (...args: unknown[]) => void) {
            if (event === 'request') requestListener = listener as (req: unknown) => void
          },
          async close() {},
        }
        return {
          async newPage() { return page },
          async addInitScript(script: string) {
            capture.initScripts ??= []
            capture.initScripts.push(script)
          },
          async route(_pattern: string, handler: (route: PlaywrightRouteLike) => Promise<void> | void) {
            capture.routeHandler = handler
          },
          async routeWebSocket(_pattern: string, handler: (ws: PlaywrightWebSocketRouteLike) => Promise<void> | void) {
            capture.wsHandler = handler
          },
          async storageState() {
            return capture.returnedState ?? seededState
          },
          async close() {},
        }
      },
      async close() {},
    }
  }
}

// ---------------------------------------------------------------------------
// 1. R3-H-3: Strict Refresher Proxy Origin Policy (NO "any public HTTPS"!)
// ---------------------------------------------------------------------------

test('R3-H-3: browser-session proxy policy denies arbitrary public HTTPS origins and allows only allowlist + explicit IdP origins', () => {
  const policy = resolveBrowserSessionEgressPolicy({
    targetUrl: new URL('https://app.northstar.example'),
    allowLocalLab: false,
    allowedOrigins: ['https://app.northstar.example', 'https://api.northstar.example'],
    idpOrigins: ['https://auth.idp.example'],
  })

  // Allowed: target origin, persona originAllowlist, and explicit approved IdP origin
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example', 'GET', new URL('https://app.northstar.example/dashboard')).allowed,
    true,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://api.northstar.example', 'POST', new URL('https://api.northstar.example/v1/refresh')).allowed,
    true,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://auth.idp.example', 'CONNECT', new URL('https://auth.idp.example')).allowed,
    true,
  )

  // Denied: arbitrary public HTTPS origins (even on GET, POST, or CONNECT!)
  for (const method of ['GET', 'POST', 'CONNECT']) {
    const evilVerdict = evaluateBrowserSessionProxyOrigin(
      policy,
      'https://attacker.example',
      method,
      new URL('https://attacker.example/collect'),
    )
    assert.equal(evilVerdict.allowed, false, `Arbitrary public HTTPS (${method}) must be denied`)

    const unapprovedIdp = evaluateBrowserSessionProxyOrigin(
      policy,
      'https://accounts.google.com',
      method,
      new URL('https://accounts.google.com/o/oauth2/token'),
    )
    assert.equal(unapprovedIdp.allowed, false, `Unapproved IdP origin (${method}) must be denied`)
  }

  // Denied: non-standard port on allowlisted host, plaintext HTTP, and non-HTTP schemes
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example:8443', 'CONNECT', new URL('https://app.northstar.example:8443')).allowed,
    false,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'http://app.northstar.example', 'GET', new URL('http://app.northstar.example/')).allowed,
    false,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'file://', 'GET', new URL('file:///etc/passwd')).allowed,
    false,
  )
})

test('R3-H-3: ScopePolicy intersects persona originAllowlist, admits ScopePolicy.authOrigins, and enforces routeDenylist', () => {
  const scopePolicy: ScopePolicy = {
    mode: 'staging_isolated',
    targetOrigins: ['https://app.northstar.example'],
    authOrigins: ['https://sso.northstar-idp.example'],
    routeDenylist: ['/admin/delete-all'],
  }

  const policy = resolveBrowserSessionEgressPolicy({
    targetUrl: new URL('https://app.northstar.example'),
    allowLocalLab: false,
    // api.other.example is NOT in scopePolicy and must be excluded!
    allowedOrigins: ['https://app.northstar.example', 'https://api.other.example'],
    idpOrigins: ['https://extra-idp.example'],
    scopePolicy,
  })

  assert.equal(policy.personaOrigins.has('https://app.northstar.example'), true)
  assert.equal(policy.personaOrigins.has('https://api.other.example'), false, 'Origin outside ScopePolicy must be stripped from personaOrigins')
  assert.equal(policy.idpOrigins.has('https://sso.northstar-idp.example'), true, 'ScopePolicy.authOrigins must be admitted as IdP origins')
  assert.equal(policy.idpOrigins.has('https://extra-idp.example'), true)

  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://api.other.example', 'GET', new URL('https://api.other.example/me')).allowed,
    false,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://sso.northstar-idp.example', 'CONNECT', new URL('https://sso.northstar-idp.example')).allowed,
    true,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://app.northstar.example', 'GET', new URL('https://app.northstar.example/admin/delete-all')).allowed,
    false,
    'ScopePolicy routeDenylist must be enforced',
  )

  // Rejects targetOrigin outside ScopePolicy
  assert.throws(
    () => resolveBrowserSessionEgressPolicy({
      targetUrl: new URL('https://unrelated.example'),
      allowLocalLab: false,
      scopePolicy,
    }),
    /outside the project ScopePolicy/i,
  )

  // Rejects unsafe explicit idpOrigins (plaintext HTTP, metadata IP, loopback in public mode)
  assert.throws(
    () => resolveBrowserSessionEgressPolicy({
      targetUrl: new URL('https://app.northstar.example'),
      allowLocalLab: false,
      idpOrigins: ['http://idp.insecure.example'],
    }),
    /blocked for public projects/i,
  )
  assert.throws(
    () => resolveBrowserSessionEgressPolicy({
      targetUrl: new URL('https://app.northstar.example'),
      allowLocalLab: false,
      idpOrigins: ['https://169.254.169.254'],
    }),
    /metadata|link-local/i,
  )
})

test('R3-H-3: live createBrowserSessionProxy denies out-of-scope CONNECT and HTTP origins while allowing allowlisted + IdP origins', async t => {
  // Start two local servers: one in allowlist, one explicit IdP, and one unapproved out-of-scope server.
  const startStubServer = async (body: string) => {
    const srv = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(body)
    })
    srv.listen(0, '127.0.0.1')
    await once(srv, 'listening')
    t.after(() => new Promise<void>(r => srv.close(() => r())))
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`
  }

  const allowedOrigin = await startStubServer('allowed-app')
  const idpOrigin = await startStubServer('approved-idp')
  const blockedOrigin = await startStubServer('should-never-be-reached')

  const proxy = await createBrowserSessionProxy({
    targetUrl: new URL(allowedOrigin),
    allowLocalLab: true,
    allowedOrigins: [allowedOrigin],
    idpOrigins: [idpOrigin],
    resolveHost: async () => ['93.184.216.34'],
  })
  t.after(() => proxy.close())

  const proxyGet = (targetUrl: string) => new Promise<{ status: number; body: string }>((resolveReq, rejectReq) => {
    const req = httpRequest({
      host: proxy.host,
      port: proxy.port,
      method: 'GET',
      path: targetUrl,
      headers: {
        host: new URL(targetUrl).host,
        'proxy-authorization': proxy.authorizationHeader,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => resolveReq({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('error', rejectReq)
    req.end()
  })

  const proxyConnect = (authority: string) => new Promise<number>((resolveReq, rejectReq) => {
    const req = httpRequest({
      host: proxy.host,
      port: proxy.port,
      method: 'CONNECT',
      path: authority,
      headers: {
        host: authority,
        'proxy-authorization': proxy.authorizationHeader,
      },
    })
    req.on('connect', (res, socket) => {
      socket.destroy()
      resolveReq(res.statusCode ?? 0)
    })
    req.on('response', res => {
      res.resume()
      resolveReq(res.statusCode ?? 0)
    })
    req.on('error', rejectReq)
    req.end()
  })

  // Allowed app origin succeeds through proxy
  const okApp = await proxyGet(`${allowedOrigin}/health`)
  assert.equal(okApp.status, 200)
  assert.equal(okApp.body, 'allowed-app')

  // Approved IdP origin succeeds through proxy
  const okIdp = await proxyGet(`${idpOrigin}/token`)
  assert.equal(okIdp.status, 200)
  assert.equal(okIdp.body, 'approved-idp')

  // Out-of-scope local origin is denied with 403
  const deniedLocal = await proxyGet(`${blockedOrigin}/exfil`)
  assert.equal(deniedLocal.status, 403)
  assert.ok(!deniedLocal.body.includes('should-never-be-reached'))

  // Arbitrary public HTTPS origin over CONNECT is denied with 403 (even in local-lab!)
  const deniedPublicConnect = await proxyConnect('attacker.example:443')
  assert.equal(deniedPublicConnect, 403, 'CONNECT to arbitrary public HTTPS origin must be denied with 403')

  // Public-mode proxy also blocks arbitrary HTTPS CONNECT
  const publicProxy = await createBrowserSessionProxy({
    targetUrl: new URL('https://app.northstar.example'),
    allowLocalLab: false,
    allowedOrigins: ['https://app.northstar.example'],
    idpOrigins: ['https://auth.idp.example'],
    resolveHost: async () => ['93.184.216.34'],
  })
  t.after(() => publicProxy.close())

  const deniedPublic = await new Promise<number>((resolveReq, rejectReq) => {
    const req = httpRequest({
      host: publicProxy.host,
      port: publicProxy.port,
      method: 'CONNECT',
      path: 'evil-collector.example:443',
      headers: {
        host: 'evil-collector.example:443',
        'proxy-authorization': publicProxy.authorizationHeader,
      },
    })
    req.on('connect', (res, socket) => {
      socket.destroy()
      resolveReq(res.statusCode ?? 0)
    })
    req.on('response', res => {
      res.resume()
      resolveReq(res.statusCode ?? 0)
    })
    req.on('error', rejectReq)
    req.end()
  })
  assert.equal(deniedPublic, 403)
})

// ---------------------------------------------------------------------------
// 2. R3-H-3: Third-Party Cookie Filtering, serviceWorkers: 'block', Route/WS Guards, H-8 Isolation
// ---------------------------------------------------------------------------

test('R3-H-3: filterStorageStateForRefresh strips third-party cookies and out-of-scope localStorage unless explicitly opted in', () => {
  const allowedOrigins = new Set(['https://app.northstar.example', 'https://auth.idp.example'])
  const storageState: PlaywrightStorageState = {
    cookies: [
      { name: 'app_sid', value: 'v_app', domain: 'app.northstar.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'parent_sid', value: 'v_parent', domain: '.northstar.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'idp_client', value: 'v_idp', domain: 'auth.idp.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'None' },
      { name: 'third_party_ad', value: 'v_3p', domain: '.tracker.evil.example', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'None' },
      { name: 'sibling_host', value: 'v_sib', domain: 'billing.northstar.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'public_suffix_abuse', value: 'v_tld', domain: '.com', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'None' },
      { name: 'multi_tenant_psl', value: 'v_gh', domain: '.github.io', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'None' },
    ],
    origins: [
      { origin: 'https://app.northstar.example', localStorage: [{ name: 'jwt', value: 'tok_app' }] },
      { origin: 'https://auth.idp.example', localStorage: [{ name: 'idp_state', value: 'tok_idp' }] },
      { origin: 'https://tracker.evil.example', localStorage: [{ name: 'secret', value: 'tok_evil' }] },
    ],
  }

  // Default: third-party cookies and out-of-scope localStorage stripped
  const filtered = filterStorageStateForRefresh(storageState, { allowedOrigins })
  assert.deepEqual(
    filtered.storageState.cookies.map(c => c.name),
    ['app_sid', 'parent_sid', 'idp_client'],
  )
  assert.equal(filtered.droppedCookiesCount, 4)
  assert.deepEqual(
    filtered.storageState.origins.map(o => o.origin),
    ['https://app.northstar.example', 'https://auth.idp.example'],
  )
  assert.equal(filtered.droppedOriginsCount, 1)

  // Public suffix rejection check directly
  assert.equal(cookieMatchesAllowedOrigins('.com', allowedOrigins), false)
  assert.equal(cookieMatchesAllowedOrigins('.co.uk', new Set(['https://app.example.co.uk'])), false)
  assert.equal(cookieMatchesAllowedOrigins('.github.io', new Set(['https://tenant.github.io'])), false)

  // Explicit opt-in preserves third-party cookies (still scoping localStorage origins)
  const optedIn = filterStorageStateForRefresh(storageState, { allowedOrigins, allowThirdPartyCookies: true })
  assert.equal(optedIn.storageState.cookies.length, storageState.cookies.length)
  assert.equal(optedIn.droppedCookiesCount, 0)
  assert.deepEqual(
    optedIn.storageState.origins.map(o => o.origin),
    ['https://app.northstar.example', 'https://auth.idp.example'],
  )
})

test('R3-H-3: refreshBrowserSession strips third-party cookies, sets serviceWorkers: block, enforces route/WS guards, and preserves H-8 isolation', async () => {
  const capture: Parameters<typeof makeMockBrowser>[0] = {
    onGoto: (_url, fireRequest) => {
      // Simulate an approved IdP request carrying an IdP-only Authorization header (must NOT leak into persona session!)
      fireRequest({
        url: () => 'https://auth.idp.example/oauth/token',
        headers: () => ({ Authorization: 'Bearer idp_only_secret_should_not_leak_12345' }),
      })
      // Simulate a legitimate target-origin API request carrying the target JWT
      fireRequest({
        url: () => 'https://app.northstar.example/api/me',
        headers: () => ({ Authorization: 'Bearer target_app_secret_token_67890' }),
      })
    },
  }

  const rawState: PlaywrightStorageState = {
    cookies: [
      { name: 'app_session', value: 'app_cookie_val_1111', domain: 'app.northstar.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Lax' },
      { name: 'idp_refresh', value: 'idp_cookie_val_2222', domain: 'auth.idp.example', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'None' },
      { name: 'third_party_leak', value: 'evil_cookie_val_3333', domain: 'evil.thirdparty.example', path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'None' },
    ],
    origins: [
      { origin: 'https://app.northstar.example', localStorage: [{ name: 'theme', value: 'dark' }] },
      { origin: 'https://evil.thirdparty.example', localStorage: [{ name: 'exfil', value: 'bad' }] },
    ],
  }

  const refreshed = await refreshBrowserSession({
    storageState: rawState,
    targetOrigin: 'https://app.northstar.example',
    originAllowlist: ['https://app.northstar.example'],
    idpOrigins: ['https://auth.idp.example'],
    verifyPath: '/auth/health',
    settleMs: 200,
    launchBrowser: makeMockBrowser(capture),
    resolveHost: async () => ['93.184.216.34'],
  })

  // 1. serviceWorkers: 'block' MUST be set on context
  assert.equal(capture.contextOpts?.serviceWorkers, 'block')
  assert.equal(capture.contextOpts?.ignoreHTTPSErrors, false)

  // 2. Third-party cookie and third-party localStorage stripped from storageState passed to newContext
  const seeded = capture.contextOpts?.storageState as PlaywrightStorageState
  assert.deepEqual(seeded.cookies.map(c => c.name), ['app_session', 'idp_refresh'])
  assert.deepEqual(seeded.origins.map(o => o.origin), ['https://app.northstar.example'])

  // 3. H-8 credential isolation: target Authorization observed, IdP Authorization never captured into persona session
  assert.equal(refreshed.observedHeaders.Authorization, 'Bearer target_app_secret_token_67890')
  assert.equal(refreshed.session.value, 'target_app_secret_token_67890')

  // 4. Route guard aborts out-of-scope public HTTPS exfil and allows allowlist + IdP
  assert.ok(capture.routeHandler, 'Expected context.route guard to be installed')
  const evalRoute = async (url: string, method = 'GET') => {
    let aborted = false
    let continued = false
    await capture.routeHandler!({
      request: () => ({ url: () => url, method: () => method, headers: () => ({}) }),
      abort: async () => { aborted = true },
      continue: async () => { continued = true },
    })
    return { aborted, continued }
  }
  assert.deepEqual(await evalRoute('https://exfil.attacker.example/steal', 'POST'), { aborted: true, continued: false })
  assert.deepEqual(await evalRoute('https://app.northstar.example/api/me', 'GET'), { aborted: false, continued: true })
  assert.deepEqual(await evalRoute('https://auth.idp.example/oauth/token', 'POST'), { aborted: false, continued: true })

  // 5. WebSocket guard closes out-of-scope wss:// exfil sockets
  assert.ok(capture.wsHandler, 'Expected context.routeWebSocket guard to be installed')
  let wsClosedCode: number | undefined
  let wsConnected = false
  await capture.wsHandler!({
    url: () => 'wss://exfil.attacker.example/ws',
    close: opts => { wsClosedCode = opts?.code },
    connectToServer: () => { wsConnected = true },
  })
  assert.equal(wsClosedCode, 1008)
  assert.equal(wsConnected, false)
})

// ---------------------------------------------------------------------------
// 3. R3-H-3: Refuse Automated Refresh on Paths Modified by the Run
// ---------------------------------------------------------------------------

test('R3-H-3: refreshBrowserSession refuses automated refresh on run-modified paths without launching Chromium', async () => {
  assert.equal(isVerifyPathModifiedByRun('/dashboard', 'https://app.northstar.example', ['/dashboard']), true)
  assert.equal(isVerifyPathModifiedByRun('/dashboard?tab=1', 'https://app.northstar.example', ['/dashboard']), true)
  assert.equal(isVerifyPathModifiedByRun('/dashboard', 'https://app.northstar.example', ['https://app.northstar.example/dashboard']), true)
  assert.equal(isVerifyPathModifiedByRun('/profile/settings', 'https://app.northstar.example', ['/profile/*']), true)
  assert.equal(isVerifyPathModifiedByRun('/auth/health', 'https://app.northstar.example', ['/comments', 'https://other.example/auth/health']), false)

  let launched = false
  const countingLauncher = async (opts: BrowserSessionChromiumLaunchOptions) => {
    launched = true
    return makeMockBrowser({})(opts)
  }

  // Flagged via modifiedPaths
  await assert.rejects(
    () => refreshBrowserSession({
      storageState: { cookies: [], origins: [] },
      targetOrigin: 'https://app.northstar.example',
      verifyPath: '/dashboard?view=feed',
      modifiedPaths: ['/dashboard'],
      launchBrowser: countingLauncher,
      resolveHost: async () => ['93.184.216.34'],
    }),
    err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
  )
  assert.equal(launched, false, 'Chromium must NOT be launched when verifyPath was modified by the run')

  // Flagged via verifyPathModifiedByRun boolean
  await assert.rejects(
    () => refreshBrowserSession({
      storageState: { cookies: [], origins: [] },
      targetOrigin: 'https://app.northstar.example',
      verifyPath: '/',
      verifyPathModifiedByRun: true,
      launchBrowser: countingLauncher,
      resolveHost: async () => ['93.184.216.34'],
    }),
    err => err instanceof BrowserSessionRefreshBlockedError && err.code === 'VERIFY_PATH_MODIFIED',
  )
  assert.equal(launched, false)
})

// ---------------------------------------------------------------------------
// 4. R3-H-6: Chromium Sandbox Enabled by Default (`chromiumSandbox: true`)
// ---------------------------------------------------------------------------

test('R3-H-6: Chromium launch options explicitly set chromiumSandbox: true by default and false ONLY when KOVO_INSECURE_NO_SANDBOX=1', async () => {
  // Pure helper assertions across env permutations
  const defaultOpts = buildBrowserSessionChromiumLaunchOptions({ env: {} })
  assert.equal(defaultOpts.headless, true)
  assert.equal(defaultOpts.chromiumSandbox, true, 'chromiumSandbox MUST be explicitly true by default')
  assert.equal(defaultOpts.args.includes('--no-sandbox'), false)

  const nonOneEnvOpts = buildBrowserSessionChromiumLaunchOptions({ env: { KOVO_INSECURE_NO_SANDBOX: 'true' } })
  assert.equal(nonOneEnvOpts.chromiumSandbox, true, 'Only exact "1" may disable Chromium sandbox')
  assert.equal(nonOneEnvOpts.args.includes('--no-sandbox'), false)

  const optOutOpts = buildBrowserSessionChromiumLaunchOptions({ env: { KOVO_INSECURE_NO_SANDBOX: '1' } })
  assert.equal(optOutOpts.headless, true)
  assert.equal(optOutOpts.chromiumSandbox, false)
  assert.equal(optOutOpts.args.includes('--no-sandbox'), true)

  assert.equal(browserSessionChromiumArgs({ env: {} }).includes('--no-sandbox'), false)
  assert.equal(browserSessionChromiumArgs({ env: { KOVO_INSECURE_NO_SANDBOX: '1' } }).includes('--no-sandbox'), true)

  // Actionable fail-closed error message when sandboxed Chromium cannot launch
  const sandboxErr = formatChromiumSandboxLaunchError(new Error('No usable sandbox!'))
  assert.match(sandboxErr.message, /chromiumSandbox: true/i)
  assert.match(sandboxErr.message, /Refusing to fall back to --no-sandbox/i)
  assert.match(sandboxErr.message, /KOVO_INSECURE_NO_SANDBOX=1/)

  // Live invocation checks on BOTH refreshBrowserSession and startInteractiveLoginCapture
  const validState: PlaywrightStorageState = {
    cookies: [{
      name: 'sid',
      value: 'sandbox_test_cookie_val_1234',
      domain: 'app.northstar.example',
      path: '/',
      expires: -1,
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
    }],
    origins: [],
  }
  const prevEnv = process.env.KOVO_INSECURE_NO_SANDBOX
  try {
    delete process.env.KOVO_INSECURE_NO_SANDBOX

    const refreshCapture: Parameters<typeof makeMockBrowser>[0] = {}
    await refreshBrowserSession({
      storageState: validState,
      targetOrigin: 'https://app.northstar.example',
      settleMs: 200,
      launchBrowser: makeMockBrowser(refreshCapture),
      resolveHost: async () => ['93.184.216.34'],
    })
    assert.equal(refreshCapture.launchOpts?.headless, true)
    assert.equal(refreshCapture.launchOpts?.chromiumSandbox, true)
    assert.equal(refreshCapture.launchOpts?.args.includes('--no-sandbox'), false)

    const captureCtx: Parameters<typeof makeMockBrowser>[0] = {}
    const capSession = await startInteractiveLoginCapture({
      projectId: 'proj-sandbox-check',
      targetOrigin: 'https://app.northstar.example',
      launchBrowser: makeMockBrowser(captureCtx),
      resolveHost: async () => ['93.184.216.34'],
    })
    await capSession.cancelCapture()
    assert.equal(captureCtx.launchOpts?.headless, true)
    assert.equal(captureCtx.launchOpts?.chromiumSandbox, true)
    assert.equal(captureCtx.launchOpts?.args.includes('--no-sandbox'), false)
    assert.equal(captureCtx.contextOpts?.serviceWorkers, 'block')

    // With explicit KOVO_INSECURE_NO_SANDBOX=1
    process.env.KOVO_INSECURE_NO_SANDBOX = '1'
    const optOutCapture: Parameters<typeof makeMockBrowser>[0] = {}
    await refreshBrowserSession({
      storageState: validState,
      targetOrigin: 'https://app.northstar.example',
      settleMs: 200,
      launchBrowser: makeMockBrowser(optOutCapture),
      resolveHost: async () => ['93.184.216.34'],
    })
    assert.equal(optOutCapture.launchOpts?.chromiumSandbox, false)
    assert.equal(optOutCapture.launchOpts?.args.includes('--no-sandbox'), true)
  } finally {
    if (prevEnv === undefined) delete process.env.KOVO_INSECURE_NO_SANDBOX
    else process.env.KOVO_INSECURE_NO_SANDBOX = prevEnv
  }
})

test('R3-H-3 & R3-H-6 static invariant: browser-session-auth.ts has no wildcard https allow and always passes chromiumSandbox', () => {
  const src = readFileSync(resolve(REPO_ROOT, 'src/server/browser-session-auth.ts'), 'utf8')
  assert.equal(/if\s*\(\s*url\.protocol\s*===\s*'https:'\s*\)\s*return\s+true/.test(src), false, 'Must not allow arbitrary public HTTPS origins')
  assert.equal(/if\s*\(\s*method\s*===\s*'CONNECT'\s*\)\s*return\s+true/.test(src), false, 'Must not allow arbitrary CONNECT origins')
  assert.match(src, /chromiumSandbox:\s*opts\.chromiumSandbox/, 'chromium.launch must explicitly pass chromiumSandbox')
  assert.match(src, /serviceWorkers:\s*'block'/, 'Refresher context must block service workers')
})
