import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { createKovoLocalServer } from '../scripts/serve.ts'
import {
  BrowserCaptureManager,
  refreshBrowserSession,
  startInteractiveLoginCapture,
} from '../src/server/browser-session-auth.ts'
import type { PlaywrightBrowserLike, PlaywrightStorageState } from '../src/server/browser-session-auth.ts'
import { parseCurlCommand, parseCurlOrHeaderInput, tokenizeCurlArgs } from '../src/server/curl-parse.ts'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import {
  buildPersonaHeader,
  createBrowserSessionPersona,
  listProjectPersonas,
  personaSecrets,
  readBrowserSessionCredentialFile,
  resolveRunPersonas,
  updateBrowserSessionPersona,
} from '../src/server/persona-vault.ts'
import { redact } from '../src/server/redact.ts'
import { Store } from '../src/server/store.ts'

process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeFakeJwt(payload: Record<string, unknown>, sigSuffix: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.sig_${sigSuffix}_998877665544`
}

// ---------------------------------------------------------------------------
// 1. Generic Copy-as-cURL Parser Tests
// ---------------------------------------------------------------------------

test('parseCurlCommand extracts origin, Authorization Bearer, Cookies (-H & -b), Basic (-u), custom headers, and multiline quotes', () => {
  // 1a. Multiline Chrome DevTools Copy as cURL with -H Cookie + -b + Bearer + custom header + bash escaping
  const devtoolsCurl = [
    `curl 'https://app.northstar.example/api/v1/profile?tab=billing' \\`,
    `  -X POST \\`,
    `  -H 'accept: application/json' \\`,
    `  -H 'sec-fetch-site: same-origin' \\`,
    `  -H 'Authorization: Bearer eyJhbGciOi.payload_tok.sig_12345' \\`,
    `  -H 'Cookie: sid=sess_abc; theme=dark' \\`,
    `  -b 'csrf=tok_xyz' \\`,
    `  -H 'X-Tenant-Id: org_42' \\`,
    `  --data-raw '{"hello":"world"}'`,
  ].join('\n')

  const parsed = parseCurlCommand(devtoolsCurl)
  assert.ok(parsed)
  assert.equal(parsed.origin, 'https://app.northstar.example')
  assert.equal(parsed.method, 'POST')
  assert.equal(parsed.authorization, 'Bearer eyJhbGciOi.payload_tok.sig_12345')
  assert.equal(parsed.bearerToken, 'eyJhbGciOi.payload_tok.sig_12345')
  assert.equal(parsed.cookie, 'sid=sess_abc; theme=dark; csrf=tok_xyz')
  assert.deepEqual(parsed.cookies, { sid: 'sess_abc', theme: 'dark', csrf: 'tok_xyz' })
  assert.deepEqual(parsed.customHeaders, { 'X-Tenant-Id': 'org_42' })
  assert.equal(parsed.recommended?.authKind, 'bearer')
  assert.equal(parsed.recommended?.secret, 'eyJhbGciOi.payload_tok.sig_12345')

  // 1b. Cookie-only cURL with ANSI-C quotes ($'...') and adjacent quoted concatenation
  const cookieCurl = `curl --url "https://portal.example:8443/me" --cookie $'a=1\\x3b b=two' -H 'Cookie: c=it'\\''s_ok'`
  const parsedCookie = parseCurlCommand(cookieCurl)
  assert.ok(parsedCookie)
  assert.equal(parsedCookie.origin, 'https://portal.example:8443')
  assert.equal(parsedCookie.cookies.a, '1')
  assert.equal(parsedCookie.cookies.b, 'two')
  assert.equal(parsedCookie.cookies.c, "it's_ok")
  assert.equal(parsedCookie.recommended?.authKind, 'cookie')

  // 1c. Basic auth via -u user:pass
  const basicCurl = `curl -u "alice:s3cr3t!" https://api.example/v2/items`
  const parsedBasic = parseCurlCommand(basicCurl)
  assert.ok(parsedBasic)
  assert.equal(parsedBasic.origin, 'https://api.example')
  assert.equal(parsedBasic.authorization, `Basic ${Buffer.from('alice:s3cr3t!').toString('base64')}`)
  assert.equal(parsedBasic.recommended?.authKind, 'header')
  assert.equal(parsedBasic.recommended?.headerName, 'Authorization')

  // 1d. Custom API key header (prefers X-Api-Key over arbitrary custom headers)
  const apiKeyCurl = `curl https://svc.example/data -H "X-Trace-Id: t1" -H "X-Api-Key: kovo_key_999"`
  const parsedKey = parseCurlCommand(apiKeyCurl)
  assert.ok(parsedKey)
  assert.equal(parsedKey.recommended?.authKind, 'header')
  assert.equal(parsedKey.recommended?.headerName, 'X-Api-Key')
  assert.equal(parsedKey.recommended?.secret, 'kovo_key_999')

  // 1e. Windows cmd caret continuation & raw header fallback
  const cmdCurl = `curl ^\r\n  "https://win.example/api" ^\r\n  -H ^"Cookie: win_sid=ok123^"`
  const parsedCmd = parseCurlCommand(cmdCurl)
  assert.ok(parsedCmd)
  assert.equal(parsedCmd.origin, 'https://win.example')
  assert.equal(parsedCmd.cookies.win_sid, 'ok123')

  const rawHeader = parseCurlOrHeaderInput('Authorization: Bearer raw_tok_888')
  assert.equal(rawHeader?.recommended?.authKind, 'bearer')
  assert.equal(rawHeader?.recommended?.secret, 'raw_tok_888')

  assert.equal(parseCurlCommand('not a curl command'), null)
  assert.deepEqual(tokenizeCurlArgs(`curl -H 'A: B' "https://x.test"`), ['curl', '-H', 'A: B', 'https://x.test'])
})

// ---------------------------------------------------------------------------
// 2. Generic Headless storageState Auto-Refresh against a Real Local Mock SPA
// ---------------------------------------------------------------------------

test('refreshBrowserSession & PersonaAuthManager perform 100% generic zero-IdP-code token rotation against a live mock SPA', async t => {
  let rotationCounter = 0
  const initialRefreshCookie = 'long_lived_refresh_tok_initial_11111'
  const initialSessionCookie = 'short_lived_sess_v0_stale_00000'
  const nowSec = Math.floor(Date.now() / 1000)
  const mintedJwts = [
    makeFakeJwt({ sub: 'usr_spa_1', iat: nowSec, exp: nowSec + 120 }, 'spa_rot_v1'),
    makeFakeJwt({ sub: 'usr_spa_1', iat: nowSec + 10, exp: nowSec + 180 }, 'spa_rot_v2'),
  ]
  const mintedCookies = [
    'short_lived_sess_v1_fresh_aaaa1111',
    'short_lived_sess_v2_fresh_bbbb2222',
  ]

  const server = createServer((req, res) => {
    const url = req.url ?? '/'
    const cookie = req.headers.cookie ?? ''

    if (url === '/dashboard' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      // Client-side JS SDK behavior: on page load, silently calls /api/auth/refresh using the
      // HttpOnly refresh cookie, receives a fresh short-lived cookie + Bearer JWT, stores it in
      // localStorage, and calls /api/me with Authorization: Bearer <jwt>.
      res.end(`<!doctype html><html><body><h1>SPA Dashboard</h1>
<script>
(async () => {
  const r = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
  if (r.ok) {
    const data = await r.json();
    localStorage.setItem('spa_access_token', data.accessToken);
    localStorage.setItem('spa_rotation', String(data.rotation));
    await fetch('/api/me', { headers: { Authorization: 'Bearer ' + data.accessToken } });
    document.body.dataset.ready = '1';
  }
})();
</script></body></html>`)
      return
    }

    if (url === '/api/auth/refresh' && req.method === 'POST') {
      if (!cookie.includes(`refresh_tok=${initialRefreshCookie}`)) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: 'missing refresh cookie' }))
        return
      }
      const idx = Math.min(rotationCounter, mintedJwts.length - 1)
      rotationCounter += 1
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `app_session=${mintedCookies[idx]}; Path=/; HttpOnly; SameSite=Lax`,
      })
      res.end(JSON.stringify({ accessToken: mintedJwts[idx], rotation: rotationCounter }))
      return
    }

    if (url === '/api/me' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true, auth: Boolean(req.headers.authorization) }))
      return
    }

    res.writeHead(404).end('not found')
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(resolveClose => server.close(() => resolveClose())))
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  const dir = mkdtempSync(join(tmpdir(), 'kovo-browser-refresh-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const bundlePath = join(dir, 'persona-direct.json')

  const initialStorageState: PlaywrightStorageState = {
    cookies: [
      {
        name: 'refresh_tok',
        value: initialRefreshCookie,
        domain: '127.0.0.1',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
      {
        name: 'app_session',
        value: initialSessionCookie,
        domain: '127.0.0.1',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
    ],
    origins: [],
  }

  // 2a. Direct refreshBrowserSession() call: rotates HttpOnly cookie + observes Authorization Bearer + persists 0600 bundle!
  const refreshed1 = await refreshBrowserSession({
    storageState: initialStorageState,
    targetOrigin: origin,
    verifyPath: '/dashboard',
    allowLocalLab: true,
    settleMs: 800,
    persistBundlePath: bundlePath,
  })

  assert.equal(rotationCounter, 1)
  assert.equal(refreshed1.session.adapterUsed, 'browser_session')
  assert.equal(refreshed1.observedHeaders.Authorization, `Bearer ${mintedJwts[0]}`)
  assert.equal(refreshed1.session.headerType, 'bearer')
  assert.equal(refreshed1.session.value, mintedJwts[0])
  assert.ok(
    refreshed1.bundle.storageState.cookies.some(c => c.name === 'app_session' && c.value === mintedCookies[0]),
    'Expected rotated HttpOnly app_session cookie in fresh storageState',
  )
  assert.ok(existsSync(bundlePath))
  assert.equal(statSync(bundlePath).mode & 0o777, 0o600)
  const persisted = readBrowserSessionCredentialFile(bundlePath)
  assert.ok(persisted.bundle.storageState.cookies.some(c => c.value === mintedCookies[0]))
  assert.equal(persisted.bundle.observedHeaders?.Authorization, `Bearer ${mintedJwts[0]}`)

  // 2b. Full PersonaVault + PersonaAuthManager wiring (initial auth + 2nd rotation + PersonaSessionPool + redaction)
  const store = new Store(dir, { ftsMode: 'preview' })
  t.after(() => store.close())

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Universal Browser Auth SPA',
    seeds: [origin],
    environment: 'local-lab',
  })

  const created = createBrowserSessionPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'spa-user',
    roleLabel: 'SPA User A',
    originAllowlist: [origin],
    storageState: initialStorageState,
    verifyPath: '/dashboard',
  })

  // Confirm secrets never touch SQLite or PublicPersona
  const publicList = listProjectPersonas(store, project.id)
  assert.equal(publicList.length, 1)
  assert.equal((publicList[0]!.loginConfig as { adapter?: string } | null)?.adapter, 'browser_session')
  assert.ok(!JSON.stringify(publicList).includes(initialRefreshCookie))

  const manager = new PersonaAuthManager()
  t.after(() => manager.stopAll())

  // Authenticate triggers rotation #2 -> mintedJwts[1] & mintedCookies[1]
  const authRes = await manager.authenticatePersona(store, project.id, created.id)
  assert.equal(authRes.adapterUsed, 'browser_session')
  assert.equal(authRes.headerType, 'bearer')
  assert.ok(typeof authRes.refresh === 'function')
  assert.ok(authRes.refreshIntervalSec && authRes.refreshIntervalSec >= 30)

  const resolvedMap = resolveRunPersonas(store, project.id, [created.id])
  const persona = resolvedMap.get('spa-user')!
  const headers = buildPersonaHeader(persona, origin)
  assert.ok(headers)
  assert.equal(headers.Authorization, `Bearer ${mintedJwts[1]}`)
  assert.ok(headers.Cookie?.includes(`app_session=${mintedCookies[1]}`))

  // Verify ALL secrets (refresh cookie, initial cookie, rotated cookie, rotated JWT) are scrubbed
  const secrets = personaSecrets(resolvedMap)
  const probe = `ref=${initialRefreshCookie} old=${initialSessionCookie} fresh=${mintedCookies[1]} jwt=${mintedJwts[1]}`
  const scrubbed = redact(probe, secrets)
  assert.ok(!scrubbed.includes(initialRefreshCookie), 'Refresh cookie must be scrubbed')
  assert.ok(!scrubbed.includes(mintedCookies[1]!), 'Rotated session cookie must be scrubbed')
  assert.ok(!scrubbed.includes(mintedJwts[1]!), 'Rotated Bearer JWT must be scrubbed')
})

// ---------------------------------------------------------------------------
// 3. PersonaVault browser_session Storage, Update, and Rotation Tests
// ---------------------------------------------------------------------------

test('PersonaVault browser_session persists 0600 bundle, preserves state on metadata update, and rotates on replacement', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-vault-browser-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir, { ftsMode: 'preview' })
  t.after(() => store.close())

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Vault Browser Project',
    seeds: ['https://app.vault-test.example'],
    environment: 'public',
  })

  const stateV1: PlaywrightStorageState = {
    cookies: [{
      name: '__session',
      value: 'vault_cookie_secret_v1_abcdef',
      domain: 'app.vault-test.example',
      path: '/',
      expires: -1,
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
    }],
    origins: [{
      origin: 'https://app.vault-test.example',
      localStorage: [{ name: 'auth_token', value: 'vault_ls_secret_v1_99887766' }],
    }],
  }

  const created = createBrowserSessionPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    handle: 'vault-browser-user',
    roleLabel: 'Browser User',
    originAllowlist: ['https://app.vault-test.example'],
    storageState: stateV1,
    verifyPath: '/app',
  })

  const resolved1 = resolveRunPersonas(store, project.id, [created.id]).get('vault-browser-user')!
  assert.ok(resolved1.credentialId && resolved1.secretPath)
  assert.equal(statSync(resolved1.secretPath).mode & 0o777, 0o600)
  // Initial .session file should be immediately usable
  assert.deepEqual(
    buildPersonaHeader(resolved1, 'https://app.vault-test.example'),
    { Cookie: '__session=vault_cookie_secret_v1_abcdef' },
  )

  // Metadata-only update (no replacement storageState) preserves credential file
  updateBrowserSessionPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    personaId: created.id,
    roleLabel: 'Browser User Updated',
    originAllowlist: ['https://app.vault-test.example'],
    verifyPath: '/dashboard',
  })
  const resolved2 = resolveRunPersonas(store, project.id, [created.id]).get('vault-browser-user')!
  assert.equal(resolved2.roleLabel, 'Browser User Updated')
  assert.equal(resolved2.credentialId, resolved1.credentialId)
  const storedBundle = readBrowserSessionCredentialFile(resolved2.secretPath!).bundle
  assert.equal(storedBundle.storageState.cookies[0]?.value, 'vault_cookie_secret_v1_abcdef')

  // Replacement storageState rotates credential file (0600) and deletes old file
  const oldPath = resolved2.secretPath!
  const stateV2: PlaywrightStorageState = {
    cookies: [{
      name: '__session',
      value: 'vault_cookie_secret_v2_zyxwvu',
      domain: 'app.vault-test.example',
      path: '/',
      expires: -1,
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
    }],
    origins: [],
  }
  updateBrowserSessionPersona(store, {
    requestId: randomUUID(),
    projectId: project.id,
    personaId: created.id,
    roleLabel: 'Browser User V2',
    originAllowlist: ['https://app.vault-test.example'],
    storageState: stateV2,
  })
  const resolved3 = resolveRunPersonas(store, project.id, [created.id]).get('vault-browser-user')!
  assert.notEqual(resolved3.credentialId, resolved1.credentialId)
  assert.equal(existsSync(oldPath), false, 'Old credential file must be deleted on rotation')
  assert.equal(statSync(resolved3.secretPath!).mode & 0o777, 0o600)
  assert.deepEqual(
    buildPersonaHeader(resolved3, 'https://app.vault-test.example'),
    { Cookie: '__session=vault_cookie_secret_v2_zyxwvu' },
  )
})

// ---------------------------------------------------------------------------
// 4. Interactive Capture Session TTL, Single-Use, Cleanup & Live CDP + HTTP Routes
// ---------------------------------------------------------------------------

test('Interactive capture enforces strict TTL, single-use session ID, and zero leaked browsers on cancel/expiry', async () => {
  let browserCloses = 0
  let contextCloses = 0
  let pageCloses = 0
  let cdpCommands: Array<{ method: string; params?: Record<string, unknown> }> = []

  const mockLaunch = async (): Promise<PlaywrightBrowserLike> => ({
    async newContext() {
      let currentUrl = 'https://app.mock.example/'
      const page = {
        async goto(url: string) { currentUrl = url },
        async waitForTimeout() {},
        url: () => currentUrl,
        async title() { return 'Mock Login' },
        on() {},
        async close() { pageCloses += 1 },
      }
      return {
        async newPage() { return page },
        async newCDPSession() {
          return {
            async send(method: string, params?: Record<string, unknown>) {
              cdpCommands.push({ method, params })
            },
            on() {},
            async detach() {},
          }
        },
        async addInitScript() {},
        async storageState() {
          return {
            cookies: [{
              name: 'sid',
              value: 'captured_mock_sid_12345',
              domain: 'app.mock.example',
              path: '/',
              expires: -1,
              httpOnly: true,
              secure: true,
              sameSite: 'Lax',
            }],
            origins: [],
          }
        },
        async close() { contextCloses += 1 },
      }
    },
    async close() { browserCloses += 1 },
  })

  // 4a. TTL expiry closes browser automatically and removes from manager
  const manager = new BrowserCaptureManager({ maxConcurrent: 2 })
  const expiring = await manager.startCapture({
    projectId: randomUUID(),
    targetOrigin: 'https://app.mock.example',
    ttlMs: 1_000,
    launchBrowser: mockLaunch,
    resolveHost: async () => ['93.184.216.34'],
  })
  assert.equal(manager.activeCount, 1)
  assert.ok(cdpCommands.some(c => c.method === 'Page.startScreencast'))

  // Dispatch mouse + key + navigate
  await expiring.dispatchMouse({ type: 'mousePressed', x: 100, y: 200, button: 'left', clickCount: 1 })
  await expiring.dispatchKey({ type: 'insertText', text: 'hello' })
  const nav = await expiring.navigate('https://app.mock.example/signin')
  assert.equal(nav.url, 'https://app.mock.example/signin')
  assert.ok(cdpCommands.some(c => c.method === 'Input.dispatchMouseEvent'))
  assert.ok(cdpCommands.some(c => c.method === 'Input.insertText'))

  // Wait for 1s TTL to expire
  await new Promise(r => setTimeout(r, 1_150))
  assert.equal(expiring.state, 'expired')
  assert.equal(manager.activeCount, 0)
  assert.equal(browserCloses, 1)
  assert.equal(contextCloses, 1)
  assert.equal(pageCloses, 1)

  // 4b. Single-use complete: succeeds once, second complete fails cleanly
  const session2 = await manager.startCapture({
    projectId: randomUUID(),
    targetOrigin: 'https://app.mock.example',
    launchBrowser: mockLaunch,
    resolveHost: async () => ['93.184.216.34'],
  })
  const bundle = await manager.complete(session2.id)
  assert.equal(bundle.kind, 'browser_session')
  assert.equal(bundle.storageState.cookies[0]?.value, 'captured_mock_sid_12345')
  assert.equal(manager.activeCount, 0)
  assert.equal(browserCloses, 2)
  await assert.rejects(() => manager.complete(session2.id), /not found|already closed/i)
})

test('Live interactive Chromium capture streams CDP screencast frames and scripts/serve.ts gates /_kovo/auth-capture/* with kovo_local session', async t => {
  // Local target app that sets a cookie on /login-done
  const targetServer = createServer((req, res) => {
    if (req.url === '/login-done') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'set-cookie': 'live_cap_cookie=live_secret_val_777; Path=/; HttpOnly',
      })
      res.end('<!doctype html><html><body><h1>Signed In</h1></body></html>')
      return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<!doctype html><html><body style="background:#123456;color:#fff"><h1>Sign In Page</h1></body></html>')
  })
  targetServer.listen(0, '127.0.0.1')
  await once(targetServer, 'listening')
  t.after(() => new Promise<void>(resolveClose => targetServer.close(() => resolveClose())))
  const targetOrigin = `http://127.0.0.1:${(targetServer.address() as AddressInfo).port}`

  // 4c. Live Chromium CDP screencast + navigate + completeCapture
  const liveSession = await startInteractiveLoginCapture({
    projectId: randomUUID(),
    targetOrigin,
    allowLocalLab: true,
    ttlMs: 60_000,
  })
  t.after(() => liveSession.dispose())

  await liveSession.navigate(`${targetOrigin}/login-done`)
  // Wait briefly for at least one CDP screencast frame
  for (let i = 0; i < 20 && !liveSession.latestFrame(); i += 1) {
    await new Promise(r => setTimeout(r, 100))
  }
  const frame = liveSession.latestFrame()
  assert.ok(frame && frame.data.length > 100, 'Expected live base64 JPEG screencast frame from Chromium CDP')
  const captured = await liveSession.completeCapture()
  assert.equal(liveSession.state, 'completed')
  assert.ok(
    captured.storageState.cookies.some(c => c.name === 'live_cap_cookie' && c.value === 'live_secret_val_777'),
    'Expected live captured HttpOnly cookie from Chromium context.storageState()',
  )

  // 4d. Authenticated endpoints in scripts/serve.ts
  const dataDir = mkdtempSync(join(tmpdir(), 'kovo-serve-capture-'))
  t.after(() => rmSync(dataDir, { recursive: true, force: true }))
  const store = new Store(dataDir, { ftsMode: 'preview' })
  t.after(() => store.close())
  const proj = store.createProject({
    requestId: randomUUID(),
    name: 'Serve Capture Test',
    seeds: [targetOrigin],
    environment: 'local-lab',
  })

  const local = createKovoLocalServer({
    app: { fetch: () => new Response('ok') },
    directory: dataDir,
    port: 0,
    store,
  })
  // Bind to an ephemeral port and build matching server with real port for Host/Origin validation
  await new Promise<void>(resolveListen => local.server.listen(0, '127.0.0.1', () => resolveListen()))
  const boundPort = (local.server.address() as AddressInfo).port
  await new Promise<void>(resolveClose => local.server.close(() => resolveClose()))

  const liveLocal = createKovoLocalServer({
    app: { fetch: () => new Response('ok') },
    directory: dataDir,
    port: boundPort,
    store,
  })
  await new Promise<void>(resolveListen => liveLocal.server.listen(boundPort, '127.0.0.1', () => resolveListen()))
  t.after(() => new Promise<void>(resolveClose => liveLocal.server.close(() => resolveClose())))
  const kovoOrigin = `http://127.0.0.1:${boundPort}`

  // Unauthenticated POST /_kovo/auth-capture/start MUST return 401
  const unauthRes = await fetch(`${kovoOrigin}/_kovo/auth-capture/start`, {
    method: 'POST',
    headers: { origin: kovoOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ projectId: proj.id, targetOrigin }),
  })
  assert.equal(unauthRes.status, 401)

  // Authenticated POST /_kovo/auth-capture/start -> poll -> input -> cancel
  const authHeaders = {
    cookie: `kovo_local=${liveLocal.token}`,
    origin: kovoOrigin,
    'content-type': 'application/json',
  }
  const startRes = await fetch(`${kovoOrigin}/_kovo/auth-capture/start`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ projectId: proj.id, targetOrigin }),
  })
  assert.equal(startRes.status, 200)
  const started = await startRes.json() as { captureId: string; targetOrigin: string }
  assert.ok(started.captureId.startsWith('cap_'))

  const pollRes = await fetch(`${kovoOrigin}/_kovo/auth-capture/${started.captureId}/stream?mode=poll`, {
    headers: { cookie: `kovo_local=${liveLocal.token}` },
  })
  assert.equal(pollRes.status, 200)
  const polled = await pollRes.json() as { captureId: string; state: string }
  assert.equal(polled.captureId, started.captureId)
  assert.equal(polled.state, 'active')

  const navRes = await fetch(`${kovoOrigin}/_kovo/auth-capture/${started.captureId}/input`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ kind: 'navigate', url: `${targetOrigin}/login-done` }),
  })
  assert.equal(navRes.status, 200)

  const completeRes = await fetch(`${kovoOrigin}/_kovo/auth-capture/${started.captureId}/complete`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({}),
  })
  assert.equal(completeRes.status, 200)
  const completed = await completeRes.json() as { ok: boolean; summary: { cookieCount: number } }
  assert.equal(completed.ok, true)
  assert.ok(completed.summary.cookieCount >= 1)

  // Single-use: subsequent cancel/complete returns 404
  const secondComplete = await fetch(`${kovoOrigin}/_kovo/auth-capture/${started.captureId}/complete`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({}),
  })
  assert.equal(secondComplete.status, 404)
})

// ---------------------------------------------------------------------------
// 5. PersonaFormModal 3-Mode Universal UI Contract Check
// ---------------------------------------------------------------------------

test('PersonaFormModal exposes the 3 universal auth modes with embedded live-browser canvas, storageState fallback, and cURL parser', () => {
  const modalSrc = readFileSync(join(REPO_ROOT, 'src/components/project/PersonaFormModal.tsx'), 'utf8')
  assert.match(modalSrc, /Browser Session/)
  assert.match(modalSrc, /Recommended/)
  assert.match(modalSrc, /Sign in with browser/)
  assert.match(modalSrc, /I'm signed in — capture session/)
  assert.match(modalSrc, /Import storageState\.json/)
  assert.match(modalSrc, /<canvas\b/)
  assert.match(modalSrc, /Header \/ Cookie \/ cURL/)
  assert.match(modalSrc, /Paste from cURL/)
  assert.match(modalSrc, /Automated Login \(CI \/ Staging\)/)
  assert.match(modalSrc, /registerBrowserSessionPersona/)
})
