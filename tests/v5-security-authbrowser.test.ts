import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { once } from 'node:events'
import {
  createKovoLocalServer,
  isBootstrapAuthorized,
  isSessionAuthorized,
} from '../scripts/serve.ts'
import {
  classifyAddress,
  decodeClerkPublishableKey,
  isHostInScope,
  PersonaAuthError,
  PersonaAuthManager,
  registrableDomain,
} from '../src/server/persona-auth.ts'
import {
  browserWebRtcGuardScript,
  buildChromiumLaunchOptions,
  chromiumLaunchArgs,
  installWebSocketGuard,
} from '../src/server/scoped-browser.ts'
import { createProjectPersona, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { Store } from '../src/server/store.ts'

const targetOrigin = 'https://app.northstar.example'
const coUkTarget = 'https://app.example.co.uk'

async function availablePort(): Promise<number> {
  const probe = createServer().listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const address = probe.address()
  if (!address || typeof address === 'string') throw new Error('Could not allocate a port.')
  await new Promise<void>(resolve => probe.close(() => resolve()))
  return address.port
}

async function startLocalServer(directory: string) {
  const port = await availablePort()
  let appFetches = 0
  const local = createKovoLocalServer({
    app: {
      fetch: async () => {
        appFetches += 1
        return new Response('<html><body>kovo app</body></html>', {
          headers: { 'content-type': 'text/html; charset=utf-8' },
        })
      },
    },
    directory,
    port,
  })
  local.server.listen(port, '127.0.0.1')
  await once(local.server, 'listening')
  return {
    local,
    origin: `http://127.0.0.1:${port}`,
    appFetches: () => appFetches,
    close: async () => { await new Promise<void>(resolve => local.server.close(() => resolve())) },
  }
}

test('local session cookie is never issued to a bare local HTML/API request', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-local-bootstrap-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const app = await startLocalServer(dir)
  t.after(() => app.close())

  const page = await fetch(`${app.origin}/`, { redirect: 'manual' })
  assert.equal(page.status, 401)
  assert.equal(page.headers.get('set-cookie'), null, 'Bare HTTP GET must not receive the owner session cookie')
  assert.match(await page.text(), /bootstrap/i)
  assert.equal(app.appFetches(), 0, 'Application HTML must not be served before a session exists')

  const api = await fetch(`${app.origin}/api/state`, { redirect: 'manual' })
  assert.equal(api.status, 401)
  assert.equal(api.headers.get('set-cookie'), null)

  const wrong = await fetch(`${app.origin}/?bootstrap=${'0'.repeat(64)}`, { redirect: 'manual' })
  assert.equal(wrong.status, 401)
  assert.equal(wrong.headers.get('set-cookie'), null)
})

test('one-time bootstrap URL exchanges an owner secret for the session cookie exactly once', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-local-bootstrap-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const app = await startLocalServer(dir)
  t.after(() => app.close())
  assert.ok(existsSync(join(dir, 'bootstrap')), 'Per-start bootstrap secret must be written owner-only')
  assert.equal(statSync(join(dir, 'bootstrap')).mode & 0o077, 0, 'Bootstrap secret must be mode 0600')

  const bootstrap = await fetch(
    `${app.origin}/?bootstrap=${app.local.bootstrapSecret}&view=overview`,
    { redirect: 'manual' },
  )
  assert.equal(bootstrap.status, 303)
  assert.equal(bootstrap.headers.get('location'), '/?view=overview')
  const setCookie = bootstrap.headers.get('set-cookie') ?? ''
  assert.match(setCookie, /^kovo_local=[a-f0-9]{64}; Path=\/; HttpOnly; SameSite=Strict/)
  assert.equal(setCookie.includes('Secure'), false, 'Loopback HTTP must not mark the cookie Secure')
  assert.equal(existsSync(join(dir, 'bootstrap')), false, 'Bootstrap secret must be consumed after first use')

  const recycled = await fetch(`${app.origin}/?bootstrap=${app.local.bootstrapSecret}`, { redirect: 'manual' })
  assert.equal(recycled.status, 401)
  assert.equal(recycled.headers.get('set-cookie'), null)

  const cookie = setCookie.split(';')[0]
  const authenticated = await fetch(`${app.origin}/`, { redirect: 'manual', headers: { Cookie: cookie } })
  assert.equal(authenticated.status, 200)
  assert.match(await authenticated.text(), /kovo app/)
  assert.equal(authenticated.headers.get('set-cookie'), null, 'An existing session must not be re-minted')
  assert.equal(app.appFetches(), 1)

  // API calls remain bound to the same session cookie.
  const api = await fetch(`${app.origin}/api/state`, { redirect: 'manual', headers: { Cookie: cookie } })
  assert.equal(api.status, 200)
  assert.equal(app.appFetches(), 2)
})

test('session/bootstrap token comparison is strict and malformed cookies are rejected', () => {
  const token = 'a'.repeat(64)
  assert.equal(isSessionAuthorized(`kovo_local=${token}`, token), true)
  assert.equal(isSessionAuthorized(`kovo_local=${'b'.repeat(64)}`, token), false)
  assert.equal(isSessionAuthorized(`kovo_local=${token.slice(0, 63)}`, token), false)
  assert.equal(isSessionAuthorized(undefined, token), false)
  assert.equal(isBootstrapAuthorized(token, token), true)
  assert.equal(isBootstrapAuthorized('b'.repeat(64), token), false)
  assert.equal(isBootstrapAuthorized('not-hex', token), false)
})

test('registrable domain is public-suffix aware and never collapses to a bare two-label host', () => {
  assert.equal(registrableDomain('app.example.co.uk'), 'example.co.uk')
  assert.equal(registrableDomain('deep.app.example.co.jp'), 'example.co.jp')
  assert.equal(registrableDomain('foo.bar.example.com'), 'example.com')
  assert.equal(registrableDomain('localhost'), null)
  assert.equal(registrableDomain('127.0.0.1'), null)

  const allowlist = [coUkTarget]
  assert.equal(isHostInScope('app.example.co.uk', allowlist), true)
  assert.equal(isHostInScope('clerk.example.co.uk', allowlist), true)
  assert.equal(isHostInScope('clerk.co.uk', allowlist), false, 'The co.uk fallback bug must stay closed')
  assert.equal(isHostInScope('attacker.co.uk', allowlist), false)
  assert.equal(isHostInScope('app.example.co.uk.attacker.example', allowlist), false)
})

test('Clerk discovery rejects an out-of-scope publishable-key host and falls back to the eTLD+1', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-clerk-scope-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Clerk scope', seeds: [coUkTarget], environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'clerk_user',
    roleLabel: 'Clerk User',
    originAllowlist: [coUkTarget],
    authKind: 'login',
    loginConfig: { adapter: 'clerk', email: 'clerk@example.co.uk' },
    secret: 'ClerkScopePassword!7',
    canaryMarkers: [],
  })

  const evilKey = `pk_live_${Buffer.from('attacker.co.uk$').toString('base64')}`
  assert.equal(decodeClerkPublishableKey(evilKey), 'https://attacker.co.uk')
  const requested: string[] = []
  const jwt = (() => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
    const body = Buffer.from(JSON.stringify({ sub: 'u1', exp: 1_760_001_000 })).toString('base64url')
    return `${header}.${body}.clerk_scope_signature_1234567890`
  })()

  const manager = new PersonaAuthManager({
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      requested.push(url)
      if (url === coUkTarget) {
        return new Response(`<html><script data-clerk-publishable-key="${evilKey}"></script></html>`, {
          status: 200,
          headers: { 'content-type': 'text/html', 'x-clerk-auth-status': 'signed-out' },
        })
      }
      if (url === 'https://clerk.example.co.uk/v1/client/sign_ins') {
        assert.equal(init?.redirect, 'manual')
        return new Response(JSON.stringify({
          response: { status: 'complete', created_session_id: 'sess_1' },
          client: { sessions: [{ id: 'sess_1', last_active_token: { jwt } }] },
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      return new Response('unexpected', { status: 404 })
    },
  })
  t.after(() => manager.stopAll())

  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.adapterUsed, 'clerk')
  assert.equal(requested.some(url => url.includes('attacker.co.uk')), false)
  assert.ok(requested.includes('https://clerk.example.co.uk/v1/client/sign_ins'))
  assert.ok(resolveRunPersonas(storage, projectId, [persona.id]).get('clerk_user'))
})

test('credential POSTs never follow redirects and are rejected before replay', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-login-redirect-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Login redirect', seeds: [targetOrigin], environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'json_user',
    roleLabel: 'JSON User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: { adapter: 'json', email: 'json@northstar.example', loginUrl: `${targetOrigin}/api/login` },
    secret: 'RedirectPassword!1',
    canaryMarkers: [],
  })

  const calls: Array<{ url: string; redirect?: RequestRedirect }> = []
  const manager = new PersonaAuthManager({
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      calls.push({ url, redirect: init?.redirect })
      return new Response('', {
        status: 307,
        headers: { location: 'http://169.254.169.254/latest/meta-data/iam' },
      })
    },
  })

  await assert.rejects(
    manager.authenticatePersona(storage, projectId, persona.id),
    (err: unknown) => err instanceof PersonaAuthError && /redirect/i.test(err.message),
  )
  assert.equal(calls.length, 1, 'A redirecting credential POST must never be retried')
  assert.equal(calls[0].url, `${targetOrigin}/api/login`)
  assert.equal(calls[0].redirect, 'manual')
})

test('credential destinations are refused when out of scope or resolving to private/metadata addresses', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-login-ssrf-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Login SSRF', seeds: [targetOrigin], environment: 'public',
  })

  const privateTarget = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'private_user',
    roleLabel: 'Private User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: { adapter: 'json', email: 'p@northstar.example', loginUrl: 'http://10.0.0.5/login' },
    secret: 'PrivatePassword!1',
    canaryMarkers: [],
  })
  let privateCalls = 0
  const privateManager = new PersonaAuthManager({
    fetchImpl: async () => { privateCalls += 1; return new Response('{}', { status: 200 }) },
  })
  await assert.rejects(
    privateManager.authenticatePersona(storage, projectId, privateTarget.id),
    (err: unknown) => err instanceof PersonaAuthError,
  )
  assert.equal(privateCalls, 0, 'Out-of-scope/plaintext login URLs must be rejected before any request')

  const rebinding = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'rebind_user',
    roleLabel: 'Rebind User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: { adapter: 'json', email: 'r@northstar.example', loginUrl: 'https://api.northstar.example/login' },
    secret: 'RebindPassword!1',
    canaryMarkers: [],
  })
  let rebindCalls = 0
  const rebindManager = new PersonaAuthManager({
    resolveHost: async () => ['127.0.0.1'],
    fetchImpl: async () => { rebindCalls += 1; return new Response('{}', { status: 200 }) },
  })
  await assert.rejects(
    rebindManager.authenticatePersona(storage, projectId, rebinding.id),
    (err: unknown) => err instanceof PersonaAuthError && /private|loopback|metadata/i.test(err.message),
  )
  assert.equal(rebindCalls, 0, 'A rebinding hostname must be rejected before credentials are sent')

  assert.equal(classifyAddress('93.184.216.34'), 'public')
  assert.equal(classifyAddress('127.0.0.1'), 'loopback')
  assert.equal(classifyAddress('169.254.169.254'), 'blocked')
  assert.equal(classifyAddress('10.1.2.3'), 'blocked')
  assert.equal(classifyAddress('fe80::1'), 'blocked')
})

test('provider discovery does not follow redirects to attacker-controlled hosts', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-provider-redirect-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Provider redirect', seeds: [targetOrigin], environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'auto_user',
    roleLabel: 'Auto User',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: { adapter: 'auto', email: 'auto@northstar.example', loginUrl: `${targetOrigin}/api/login` },
    secret: 'AutoPassword!1',
    canaryMarkers: [],
  })

  const requested: string[] = []
  const manager = new PersonaAuthManager({
    resolveHost: async () => ['93.184.216.34'],
    fetchImpl: async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      requested.push(url)
      if (url === targetOrigin) {
        assert.equal(init?.redirect, 'manual')
        return new Response('', { status: 302, headers: { location: 'https://attacker.example/clerk' } })
      }
      if (url === `${targetOrigin}/api/login`) {
        return new Response(JSON.stringify({ access_token: 'not-a-jwt-but-opaque-token' }), {
          status: 200, headers: { 'content-type': 'application/json' },
        })
      }
      return new Response('', { status: 404 })
    },
  })
  const result = await manager.authenticatePersona(storage, projectId, persona.id)
  assert.equal(result.adapterUsed, 'json')
  assert.equal(requested.some(url => url.includes('attacker.example')), false)
})

test('form login blocks off-scope subresources and DNS-rebound origins before they load', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-form-egress-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const storage = new Store(dir)
  t.after(() => storage.close())
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Form egress', seeds: [targetOrigin], environment: 'public',
  })
  const persona = createProjectPersona(storage, {
    requestId: randomUUID(),
    projectId,
    handle: 'form_egress',
    roleLabel: 'Form Egress',
    originAllowlist: [targetOrigin],
    authKind: 'login',
    loginConfig: { adapter: 'form', email: 'form@northstar.example', loginUrl: `${targetOrigin}/login` },
    secret: 'FormEgressPassword!1',
    canaryMarkers: [],
  })

  const evaluateRoute = async (requestUrl: string, resolveHost: (hostname: string) => Promise<string[]>) => {
    let router: ((route: unknown) => Promise<void> | void) | undefined
    let aborted = false
    let continued = false
    const browser = {
      newContext: async () => ({
        route: async (_pattern: string, handler: (route: any) => Promise<void> | void) => { router = handler },
        newPage: async () => ({
          goto: async () => {
            await router?.({
              request: () => ({
                url: () => requestUrl,
                method: () => 'GET',
                resourceType: () => 'stylesheet',
                headers: () => ({}),
              }),
              abort: async () => { aborted = true },
              continue: async () => { continued = true },
            })
          },
          waitForTimeout: async () => undefined,
          waitForLoadState: async () => undefined,
          url: () => `${targetOrigin}/login`,
          frames: () => [{ url: () => `${targetOrigin}/login` }],
          evaluate: async () => ({ captcha: false, mfa: false }) as never,
          locator: () => ({
            count: async () => 1,
            first() { return this },
            fill: async () => undefined,
            click: async () => undefined,
          }),
          close: async () => undefined,
        }),
        cookies: async () => [{ name: 'sid', value: 'form_egress_session_cookie_1234567890', domain: 'app.northstar.example' }],
        close: async () => undefined,
      }),
      close: async () => undefined,
    }
    const manager = new PersonaAuthManager({ launchBrowser: async () => browser, resolveHost })
    await manager.authenticatePersona(storage, projectId, persona.id)
    return { aborted, continued }
  }

  const offScope = await evaluateRoute('https://cdn.attacker.example/theme.css', async () => ['93.184.216.34'])
  assert.deepEqual(offScope, { aborted: true, continued: false }, 'Off-scope cross-origin subresources must be blocked')

  const rebound = await evaluateRoute('https://api.northstar.example/theme.css', async () => ['169.254.169.254'])
  assert.deepEqual(rebound, { aborted: true, continued: false }, 'DNS-rebound origins must be blocked')

  const sameSite = await evaluateRoute('https://static.northstar.example/theme.css', async () => ['93.184.216.34'])
  assert.deepEqual(sameSite, { aborted: false, continued: true }, 'In-scope static assets on the allowed eTLD+1 may load')
})

test('Chromium sandbox is enabled by default and insecure mode requires an explicit opt-in', () => {
  const secure = buildChromiumLaunchOptions({ env: {} })
  assert.equal(secure.headless, true)
  assert.equal(secure.chromiumSandbox, true, 'Playwright chromiumSandbox must be explicitly true by default')
  assert.equal(secure.args.includes('--no-sandbox'), false)
  assert.ok(secure.args.some(arg => arg.startsWith('--host-resolver-rules=')))
  assert.ok(secure.args.some(arg => arg.includes('disable_non_proxied_udp')))
  assert.deepEqual(secure.args, chromiumLaunchArgs())

  const insecureByOption = buildChromiumLaunchOptions({ insecureNoSandbox: true, env: {} })
  assert.equal(insecureByOption.chromiumSandbox, false)
  assert.equal(insecureByOption.args.includes('--no-sandbox'), true)

  const insecureByEnv = buildChromiumLaunchOptions({ env: { KOVO_INSECURE_NO_SANDBOX: '1' } })
  assert.equal(insecureByEnv.chromiumSandbox, false)
  assert.equal(insecureByEnv.args.includes('--no-sandbox'), true)
  assert.match(browserWebRtcGuardScript, /RTCPeerConnection/)
})

test('WebSocket upgrades outside the granted scope are closed before connecting', async () => {
  let handler: ((ws: {
    url(): string
    close(options?: { code?: number; reason?: string }): Promise<void> | void
    connectToServer?(): Promise<void> | void
  }) => Promise<void> | void) | undefined
  const context = {
    routeWebSocket: async (_pattern: string, cb: typeof handler) => { handler = cb },
  }
  const decisions: string[] = []
  await installWebSocketGuard(context, {
    canRead: origin => origin === 'https://app.northstar.example',
    allowLocalLab: false,
    audit: (_decision, origin) => decisions.push(origin),
  })
  assert.ok(handler)

  const makeSocket = (url: string) => {
    let closed = 0
    let connected = 0
    return {
      socket: {
        url: () => url,
        close: () => { closed += 1 },
        connectToServer: () => { connected += 1 },
      },
      counts: () => ({ closed, connected }),
    }
  }

  const blocked = makeSocket('wss://attacker.example/socket')
  await handler!(blocked.socket)
  assert.deepEqual(blocked.counts(), { closed: 1, connected: 0 })
  assert.deepEqual(decisions, ['https://attacker.example'])

  const allowed = makeSocket('wss://app.northstar.example/ws')
  await handler!(allowed.socket)
  assert.deepEqual(allowed.counts(), { closed: 0, connected: 1 })

  const plaintext = makeSocket('ws://app.northstar.example/ws')
  await handler!(plaintext.socket)
  assert.deepEqual(plaintext.counts(), { closed: 1, connected: 0 })
})

test('WebSocket guard permits plaintext ws only for an authorized local lab', async () => {
  let handler: ((ws: {
    url(): string
    close(options?: { code?: number; reason?: string }): Promise<void> | void
    connectToServer?(): Promise<void> | void
  }) => Promise<void> | void) | undefined
  const context = { routeWebSocket: async (_pattern: string, cb: typeof handler) => { handler = cb } }
  await installWebSocketGuard(context, {
    canRead: () => true,
    allowLocalLab: true,
  })
  let connected = 0
  await handler!({
    url: () => 'ws://127.0.0.1:4000/socket',
    close: () => undefined,
    connectToServer: () => { connected += 1 },
  })
  assert.equal(connected, 1)
})
