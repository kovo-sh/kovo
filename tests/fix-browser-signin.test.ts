import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser } from '@playwright/test'
import {
  BrowserCaptureManager,
  classifyInteractiveCapturedOrigins,
  evaluateBrowserSessionProxyOrigin,
  evaluateInteractiveCaptureOrigin,
  registerBrowserSessionPersonaFromAction,
  resolveBrowserSessionEgressPolicy,
  startInteractiveLoginCapture,
  wwwSiblingOrigin,
} from '../src/server/browser-session-auth.ts'
import { refreshBrowserSessionForTest } from './helpers/browser-session-test-factory.ts'
import { eq } from 'drizzle-orm'
import { PersonaAuthManager } from '../src/server/persona-auth.ts'
import { listProjectPersonas, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { projects } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { HARDENED_NODE_FLAGS } from './app.ts'

process.env.KOVO_ALLOW_LOCAL_LAB ??= '1'

const SYSTEM_CHROMIUM_CANDIDATES = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
]

function makeFakeJwt(payload: Record<string, unknown>, sigSuffix: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${header}.${body}.sig_${sigSuffix}_9988776655`
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address() as AddressInfo
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  let pw: PlaywrightModule | null = null
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') {
        pw = loaded as PlaywrightModule
        break
      }
    } catch {
      // Try next candidate package.
    }
  }
  if (!pw) return null
  const bundled = (() => {
    try { return pw.chromium.executablePath() } catch { return '' }
  })()
  if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) return { pw, executablePath: candidate }
  }
  return null
}

function ensureBuilt(): void {
  if (existsSync(resolve('build/server/server.js')) && existsSync(resolve('build/client'))) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'pipe' })
}

// ---------------------------------------------------------------------------
// 1. Unit & Security Policy Invariants (apex <-> www., Interactive vs Strict Refresher)
// ---------------------------------------------------------------------------

test('wwwSiblingOrigin permits ONLY exact apex <-> www. first-party siblings and never arbitrary subdomains or multi-tenant PSL suffixes', () => {
  assert.equal(wwwSiblingOrigin('https://dyad.sh'), 'https://www.dyad.sh')
  assert.equal(wwwSiblingOrigin('https://www.dyad.sh'), 'https://dyad.sh')
  assert.equal(wwwSiblingOrigin('https://acme.co.uk'), 'https://www.acme.co.uk')
  assert.equal(wwwSiblingOrigin('https://www.acme.co.uk'), 'https://acme.co.uk')
  assert.equal(wwwSiblingOrigin('http://dyad.example:8443'), 'http://www.dyad.example:8443')
  assert.equal(wwwSiblingOrigin('http://www.dyad.example:8443'), 'http://dyad.example:8443')

  // Must NEVER expand non-apex subdomains, multi-tenant PaaS suffixes, IPs, localhost, or TLDs.
  assert.equal(wwwSiblingOrigin('https://academy.dyad.sh'), null)
  assert.equal(wwwSiblingOrigin('https://www.academy.dyad.sh'), null)
  assert.equal(wwwSiblingOrigin('https://my-app.vercel.app'), null)
  assert.equal(wwwSiblingOrigin('https://www.my-app.vercel.app'), null)
  assert.equal(wwwSiblingOrigin('https://tenant.github.io'), null)
  assert.equal(wwwSiblingOrigin('http://127.0.0.1:3000'), null)
  assert.equal(wwwSiblingOrigin('http://localhost:3000'), null)
  assert.equal(wwwSiblingOrigin('https://com'), null)
})

test('R3-H-3 strict refresher policy auto-admits apex <-> www. sibling while keeping arbitrary third-party HTTPS denied', () => {
  const policy = resolveBrowserSessionEgressPolicy({
    targetUrl: new URL('https://dyad.sh'),
    allowLocalLab: false,
    allowedOrigins: ['https://dyad.sh', 'https://academy.dyad.sh'],
    idpOrigins: ['https://clerk.dyad.sh'],
  })

  // apex + automatic www. sibling + explicit subdomain + approved IdP are allowed
  assert.equal(policy.personaOrigins.has('https://dyad.sh'), true)
  assert.equal(policy.personaOrigins.has('https://www.dyad.sh'), true)
  assert.equal(policy.personaOrigins.has('https://academy.dyad.sh'), true)
  assert.equal(policy.idpOrigins.has('https://clerk.dyad.sh'), true)

  // Arbitrary subdomains (not in allowlist) and arbitrary public HTTPS stay strictly DENIED
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://www.dyad.sh', 'GET', new URL('https://www.dyad.sh/')).allowed,
    true,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://billing.dyad.sh', 'GET', new URL('https://billing.dyad.sh/')).allowed,
    false,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://attacker.example', 'CONNECT', new URL('https://attacker.example')).allowed,
    false,
  )
  assert.equal(
    evaluateBrowserSessionProxyOrigin(policy, 'https://accounts.google.com', 'CONNECT', new URL('https://accounts.google.com')).allowed,
    false,
  )
})

test('Interactive capture policy allows public HTTPS SSO/CDNs while strictly blocking SSRF/metadata/loopback/private IPs', () => {
  const publicPolicy = { allowLocalLab: false }

  assert.equal(
    evaluateInteractiveCaptureOrigin(publicPolicy, 'https://www.dyad.sh', 'GET', new URL('https://www.dyad.sh/')).allowed,
    true,
  )
  assert.equal(
    evaluateInteractiveCaptureOrigin(publicPolicy, 'https://clerk.dyad.sh', 'POST', new URL('https://clerk.dyad.sh/v1/client')).allowed,
    true,
  )
  assert.equal(
    evaluateInteractiveCaptureOrigin(publicPolicy, 'https://challenges.cloudflare.com', 'GET', new URL('https://challenges.cloudflare.com/turnstile')).allowed,
    true,
  )
  assert.equal(
    evaluateInteractiveCaptureOrigin(publicPolicy, 'https://accounts.google.com', 'GET', new URL('https://accounts.google.com/o/oauth2/v2/auth')).allowed,
    true,
  )

  // SSRF / metadata / loopback / private IPs / plaintext HTTP MUST stay blocked in public mode
  for (const blocked of [
    'https://169.254.169.254/latest/meta-data/',
    'https://metadata.google.internal/computeMetadata/v1/',
    'https://127.0.0.1/',
    'https://localhost/',
    'https://10.0.0.1/',
    'https://192.168.1.10/',
    'http://dyad.sh/',
  ]) {
    const parsed = new URL(blocked)
    const verdict = evaluateInteractiveCaptureOrigin(publicPolicy, parsed.origin, 'GET', parsed)
    assert.equal(verdict.allowed, false, `Interactive public capture MUST block ${blocked}`)
  }

  // Even in local-lab mode, cloud metadata MUST remain blocked
  const metadataUrl = new URL('http://169.254.169.254/latest/meta-data/')
  assert.equal(
    evaluateInteractiveCaptureOrigin({ allowLocalLab: true }, metadataUrl.origin, 'GET', metadataUrl).allowed,
    false,
  )
})

test('classifyInteractiveCapturedOrigins separates verifyOrigin/verifyPath, same-apex app origins, and IdP origins cleanly', () => {
  const meta = classifyInteractiveCapturedOrigins({
    targetOrigin: 'https://dyad.sh',
    initialAllowedOrigins: ['https://dyad.sh'],
    finalUrl: 'https://academy.dyad.sh/dashboard?tab=courses',
    visitedDocOrigins: new Set([
      'https://dyad.sh',
      'https://www.dyad.sh',
      'https://academy.dyad.sh',
      'https://accounts.google.com',
    ]),
    observedRequestOrigins: new Set([
      'https://clerk.dyad.sh',
      'https://challenges.cloudflare.com',
      'https://fonts.googleapis.com',
    ]),
    allowLocalLab: false,
  })

  assert.equal(meta.verifyOrigin, 'https://academy.dyad.sh')
  assert.equal(meta.verifyPath, '/dashboard?tab=courses')
  assert.deepEqual(meta.capturedAppOrigins, [
    'https://academy.dyad.sh',
    'https://dyad.sh',
    'https://www.dyad.sh',
  ])
  assert.deepEqual(meta.capturedIdpOrigins, [
    'https://accounts.google.com',
    'https://clerk.dyad.sh',
  ])
})

// ---------------------------------------------------------------------------
// 2. Real Live Chromium: 308 apex -> www. + Cross-Origin IdP Hop + Strict Refresher
// ---------------------------------------------------------------------------

test('Live Chromium interactive sign-in handles 308 apex -> www. + cross-origin IdP hop, auto-captures verifyOrigin/verifyPath/IdP, and strict refreshBrowserSession succeeds while blocking unapproved 3rd parties', async t => {
  const nowSec = Math.floor(Date.now() / 1000)
  let tokenCounter = 0
  let unapprovedThirdPartyHits = 0

  // 1. Unapproved third-party server (MUST never be reached during unattended refreshBrowserSession!)
  const evilServer = createServer((_req, res) => {
    unapprovedThirdPartyHits += 1
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' })
    res.end(JSON.stringify({ exfil: true }))
  })
  evilServer.listen(0, '127.0.0.1')
  await once(evilServer, 'listening')
  t.after(() => new Promise<void>(done => evilServer.close(() => done())))
  const evilPort = (evilServer.address() as AddressInfo).port
  const evilOrigin = `http://unapproved-thirdparty.example:${evilPort}`

  // 2. Cross-origin IdP server (simulates Clerk / Google / SSO hop + background token rotation)
  const idpServer = createServer((req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://idp.sso-test.example')
    const reqOrigin = req.headers.origin ?? '*'

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-origin': reqOrigin,
        'access-control-allow-credentials': 'true',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type, x-idp-grant',
      })
      res.end()
      return
    }

    if (reqUrl.pathname === '/authorize') {
      const returnTo = reqUrl.searchParams.get('return_to') ?? '/'
      res.writeHead(302, {
        'set-cookie': 'idp_session=idp_secret_cookie_999111; Path=/; HttpOnly; SameSite=Lax',
        location: `${returnTo}?code=sso_code_ok`,
      })
      res.end()
      return
    }

    if (reqUrl.pathname === '/token' && req.method === 'POST') {
      const cookie = req.headers.cookie ?? ''
      const grant = req.headers['x-idp-grant'] ?? ''
      if (!cookie.includes('idp_session=idp_secret_cookie_999111') && grant !== 'sso_refresh_grant_ok') {
        res.writeHead(401, {
          'content-type': 'application/json',
          'access-control-allow-origin': reqOrigin,
          'access-control-allow-credentials': 'true',
        })
        res.end(JSON.stringify({ error: 'missing idp grant' }))
        return
      }
      tokenCounter += 1
      const jwt = makeFakeJwt({ sub: 'usr_dyad_1', iat: nowSec, exp: nowSec + 180, rot: tokenCounter }, `rot_${tokenCounter}`)
      res.writeHead(200, {
        'content-type': 'application/json',
        'access-control-allow-origin': reqOrigin,
        'access-control-allow-credentials': 'true',
      })
      res.end(JSON.stringify({ accessToken: jwt, rotation: tokenCounter }))
      return
    }

    res.writeHead(404).end('not found')
  })
  idpServer.listen(0, '127.0.0.1')
  await once(idpServer, 'listening')
  t.after(() => new Promise<void>(done => idpServer.close(() => done())))
  const idpPort = (idpServer.address() as AddressInfo).port
  const idpOrigin = `http://idp.sso-test.example:${idpPort}`

  // 3. First-party app server handling Host: dyad.example (308 -> www.), www.dyad.example, and academy.dyad.example
  let appPort = 0
  const appServer = createServer((req, res) => {
    const rawHost = (req.headers.host ?? '').toLowerCase()
    const hostname = rawHost.split(':')[0] ?? ''
    const reqUrl = new URL(req.url ?? '/', `http://${rawHost || 'dyad.example'}`)

    // Apex 308 permanent redirect to www.
    if (hostname === 'dyad.example') {
      res.writeHead(308, { location: `http://www.dyad.example:${appPort}${reqUrl.pathname}${reqUrl.search}` })
      res.end()
      return
    }

    if (hostname === 'www.dyad.example') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'set-cookie': 'www_landing=visited_www_1234; Path=/; SameSite=Lax',
      })
      res.end(`<!doctype html><html><body><h1>Dyad Marketing (www)</h1><a href="http://academy.dyad.example:${appPort}/login">Sign in to Academy</a></body></html>`)
      return
    }

    if (hostname === 'academy.dyad.example') {
      if (reqUrl.pathname === '/login') {
        const callbackUrl = encodeURIComponent(`http://academy.dyad.example:${appPort}/callback`)
        res.writeHead(302, { location: `${idpOrigin}/authorize?return_to=${callbackUrl}` })
        res.end()
        return
      }

      if (reqUrl.pathname === '/callback' && reqUrl.searchParams.get('code') === 'sso_code_ok') {
        res.writeHead(302, {
          'set-cookie': 'academy_sid=academy_cookie_secret_777888; Path=/; HttpOnly; SameSite=Lax',
          location: `http://academy.dyad.example:${appPort}/dashboard`,
        })
        res.end()
        return
      }

      if (reqUrl.pathname === '/dashboard') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end(`<!doctype html><html><body><h1>Academy Dashboard</h1>
<script>
(async () => {
  // Attempt an unapproved third-party beacon (allowed in interactive capture? blocked in strict unattended refresh!)
  fetch(${JSON.stringify(`${evilOrigin}/beacon`)}).catch(() => {});
  const tokRes = await fetch(${JSON.stringify(`${idpOrigin}/token`)}, {
    method: 'POST',
    credentials: 'include',
    headers: { 'x-idp-grant': 'sso_refresh_grant_ok' },
  });
  if (tokRes.ok) {
    const data = await tokRes.json();
    localStorage.setItem('academy_jwt', data.accessToken);
    await fetch('/api/me', { headers: { Authorization: 'Bearer ' + data.accessToken } });
    document.body.dataset.signedIn = '1';
  }
})();
</script></body></html>`)
        return
      }

      if (reqUrl.pathname === '/api/me') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, hasAuth: Boolean(req.headers.authorization) }))
        return
      }
    }

    res.writeHead(404).end('not found')
  })
  appServer.listen(0, '127.0.0.1')
  await once(appServer, 'listening')
  t.after(() => new Promise<void>(done => appServer.close(() => done())))
  appPort = (appServer.address() as AddressInfo).port

  const apexOrigin = `http://dyad.example:${appPort}`
  const wwwOrigin = `http://www.dyad.example:${appPort}`
  const academyOrigin = `http://academy.dyad.example:${appPort}`
  const resolveHost = async () => ['127.0.0.1']

  // Step A: Interactive capture starts at apexOrigin -> automatically follows 308 -> wwwOrigin -> navigates to academy /login -> IdP hop -> lands on academy /dashboard
  const manager = new BrowserCaptureManager({ maxConcurrent: 2 })
  t.after(() => manager.disposeAll())

  const dir = await mkdtemp(join(tmpdir(), 'kovo-fix-signin-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const store = new Store(dir, { ftsMode: 'preview' })
  t.after(() => store.close())

  const project = store.createProject({
    requestId: randomUUID(),
    name: 'Dyad Redirect + IdP Lab',
    seeds: [apexOrigin],
    environment: 'local-lab',
  })

  const capture = await manager.startCapture({
    projectId: project.id,
    targetOrigin: apexOrigin,
    allowedOrigins: [apexOrigin, academyOrigin],
    allowLocalLab: true,
    ttlMs: 60_000,
    resolveHost,
  })
  assert.equal(capture.lastError(), null, 'Initial 308 apex -> www. navigation must succeed without error')
  assert.ok(capture.currentUrl().startsWith(wwwOrigin), `Expected initial 308 redirect to land on ${wwwOrigin}, got ${capture.currentUrl()}`)

  // Navigate to academy /login -> redirects to IdP /authorize -> returns to academy /callback -> lands on academy /dashboard
  const navRes = await capture.navigate(`${academyOrigin}/login`)
  assert.equal(navRes.url, `${academyOrigin}/dashboard`)
  await delay(500) // allow dashboard client JS token exchange to settle

  const escrowed = await manager.completeToEscrow(capture.id)
  assert.equal(escrowed.summary.verifyOrigin, academyOrigin)
  assert.equal(escrowed.summary.verifyPath, '/dashboard')
  assert.ok(escrowed.summary.capturedAppOrigins.includes(academyOrigin), 'capturedAppOrigins must include academyOrigin')
  assert.ok(escrowed.summary.capturedAppOrigins.includes(wwwOrigin), 'capturedAppOrigins must include wwwOrigin')
  assert.ok(escrowed.summary.capturedAppOrigins.includes(apexOrigin), 'capturedAppOrigins must include apexOrigin')
  assert.deepEqual(escrowed.summary.capturedIdpOrigins, [idpOrigin], 'capturedIdpOrigins must capture the visited cross-origin IdP')

  // Step B: Save persona via registerBrowserSessionPersonaFromAction with apexOrigin FIRST in originAllowlist
  // so we prove PersonaAuthManager prefers loginConfig.verifyOrigin (academyOrigin) over originAllowlist[0] (apexOrigin)!
  const created = registerBrowserSessionPersonaFromAction(
    store,
    {
      requestId: randomUUID(),
      projectId: project.id,
      handle: 'dyad-user',
      roleLabel: 'Dyad User',
      originAllowlist: [apexOrigin, wwwOrigin, academyOrigin],
      captureToken: escrowed.captureToken,
    },
    manager.escrow,
  )

  const listed = listProjectPersonas(store, project.id)
  assert.equal(listed.length, 1)
  assert.equal(listed[0]!.loginConfig?.verifyOrigin, academyOrigin)
  assert.equal(listed[0]!.loginConfig?.verifyPath, '/dashboard')
  assert.deepEqual(listed[0]!.loginConfig?.idpOrigins, [idpOrigin])

  // Step C: Unattended background refresh via PersonaAuthManager (Verify sign-in):
  // - Must refresh cleanly at academyOrigin + /dashboard using captured idpOrigins
  // - Must NEVER hit unapprovedThirdParty server (R3-H-3 strict!)
  unapprovedThirdPartyHits = 0
  const authManager = new PersonaAuthManager({ resolveHost })
  t.after(() => authManager.stopAll())

  const authRes = await authManager.authenticatePersona(store, project.id, created.id)
  assert.equal(authRes.adapterUsed, 'browser_session')
  assert.equal(authRes.headerType, 'bearer')
  assert.ok(tokenCounter >= 2, `Expected IdP token rotation during unattended refresh, count=${tokenCounter}`)
  assert.equal(unapprovedThirdPartyHits, 0, 'Unattended refreshBrowserSession MUST block unapproved third-party origins (R3-H-3)')

  const resolved = resolveRunPersonas(store, project.id, [created.id]).get('dyad-user')!
  assert.equal(resolved.loginConfig?.verifyOrigin, academyOrigin)

  // Step D: Direct refreshBrowserSession against apexOrigin (308 -> wwwOrigin) succeeds WITHOUT ERR_TUNNEL_CONNECTION_FAILED
  // even when ONLY apexOrigin is in originAllowlist (automatic apex <-> www. sibling)!
  const apexRefresh = await refreshBrowserSessionForTest({
    storageState: {
      cookies: [{
        name: 'www_landing',
        value: 'seed_cookie_val_5555',
        domain: 'www.dyad.example',
        path: '/',
        expires: -1,
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      }],
      origins: [],
    },
    targetOrigin: apexOrigin,
    originAllowlist: [apexOrigin],
    verifyPath: '/',
    allowLocalLab: true,
    settleMs: 300,
    resolveHost,
  })
  assert.ok(apexRefresh.bundle.storageState.cookies.some(c => c.name === 'www_landing' && c.value === 'visited_www_1234'))
})

test('Interactive capture surfaces navigation errors cleanly instead of swallowing into a blank page', async t => {
  const closedPort = await findFreePort()
  const closedOrigin = `http://127.0.0.1:${closedPort}`

  const capture = await startInteractiveLoginCapture({
    projectId: randomUUID(),
    targetOrigin: closedOrigin,
    allowLocalLab: true,
    ttlMs: 30_000,
  })
  t.after(() => capture.dispose())

  const initialErr = capture.lastError()
  assert.ok(initialErr && initialErr.length > 0, 'Initial failed page.goto must populate capture.lastError()')
  assert.match(initialErr, /Connection refused|ERR_CONNECTION_REFUSED|Failed to load/i)

  const receivedEvents: Array<{ type: string; message?: string }> = []
  const unsub = capture.subscribe(ev => {
    receivedEvents.push(ev.type === 'error' ? { type: 'error', message: ev.message } : { type: ev.type })
  })
  t.after(() => unsub())
  assert.ok(
    receivedEvents.some(e => e.type === 'error' && e.message && e.message.length > 0),
    'New subscribers must immediately receive existing navigation error event',
  )

  await assert.rejects(
    () => capture.navigate(`${closedOrigin}/retry`),
    /Connection refused|ERR_CONNECTION_REFUSED|Failed to load/i,
  )
})

// ---------------------------------------------------------------------------
// 3. Full End-to-End Playwright UI Journey (Starting Host + Live 308/IdP Capture + Option 3 Review Pill + Screenshots)
// ---------------------------------------------------------------------------

test('Playwright E2E: PersonaFormModal seeds from inventory, Starting host selector works, live 308+IdP sign-in renders Review Pill, and Verify sign-in succeeds', async t => {
  const pwLoaded = await loadPlaywright()
  if (!pwLoaded) {
    t.skip('Playwright Chromium binary not available in this environment')
    return
  }
  ensureBuilt()

  const nowSec = Math.floor(Date.now() / 1000)

  // Local IdP server on 127.0.0.1 (different port => cross-origin IdP!)
  const idpServer = createServer((req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1')
    const reqOrigin = req.headers.origin ?? '*'
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-origin': reqOrigin,
        'access-control-allow-credentials': 'true',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
      })
      res.end()
      return
    }
    if (reqUrl.pathname === '/authorize') {
      const returnTo = reqUrl.searchParams.get('return_to') ?? '/'
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'set-cookie': 'idp_ui_sid=idp_ui_secret_12345; Path=/; HttpOnly; SameSite=Lax',
      })
      res.end(`<!doctype html><html><body style="font-family:system-ui;padding:32px;background:#0f172a;color:#f8fafc">
<h1>SSO Identity Provider</h1>
<p>Continue signing in to Academy</p>
<a id="continue-sso" href="${returnTo}?code=ui_ok" style="display:inline-block;padding:10px 18px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none">Continue as User A</a>
</body></html>`)
      return
    }
    if (reqUrl.pathname === '/token' && req.method === 'POST') {
      const jwt = makeFakeJwt({ sub: 'ui_user_a', iat: nowSec, exp: nowSec + 180 }, 'ui_jwt')
      res.writeHead(200, {
        'content-type': 'application/json',
        'access-control-allow-origin': reqOrigin,
        'access-control-allow-credentials': 'true',
      })
      res.end(JSON.stringify({ accessToken: jwt }))
      return
    }
    res.writeHead(404).end('not found')
  })
  idpServer.listen(0, '127.0.0.1')
  await once(idpServer, 'listening')
  t.after(() => new Promise<void>(done => idpServer.close(() => done())))
  const idpOrigin = `http://127.0.0.1:${(idpServer.address() as AddressInfo).port}`

  // Local landing server that 308-redirects `/` -> appServer `/signin`
  let appOrigin = ''
  const landingServer = createServer((_req, res) => {
    res.writeHead(308, { location: `${appOrigin}/signin` })
    res.end()
  })
  landingServer.listen(0, '127.0.0.1')
  await once(landingServer, 'listening')
  t.after(() => new Promise<void>(done => landingServer.close(() => done())))
  const landingOrigin = `http://127.0.0.1:${(landingServer.address() as AddressInfo).port}`

  // Local Academy app server
  const appServer = createServer((req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (reqUrl.pathname === '/signin') {
      const cb = encodeURIComponent(`${appOrigin}/callback`)
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(`<!doctype html><html><body style="font-family:system-ui;padding:32px;background:#ffffff;color:#0f172a">
<h1>Academy Sign-In</h1>
<p>Redirected via 308 from marketing site</p>
<a id="sso-btn" href="${idpOrigin}/authorize?return_to=${cb}" style="display:inline-block;padding:10px 18px;background:#111827;color:#fff;border-radius:6px;text-decoration:none">Sign in with SSO</a>
</body></html>`)
      return
    }
    if (reqUrl.pathname === '/callback' && reqUrl.searchParams.get('code') === 'ui_ok') {
      res.writeHead(302, {
        'set-cookie': 'academy_ui_sid=academy_ui_cookie_secret_98765; Path=/; HttpOnly; SameSite=Lax',
        location: `${appOrigin}/dashboard`,
      })
      res.end()
      return
    }
    if (reqUrl.pathname === '/dashboard') {
      const cookie = req.headers.cookie ?? ''
      const authed = cookie.includes('academy_ui_sid=academy_ui_cookie_secret_98765') || Boolean(req.headers.authorization)
      res.writeHead(authed ? 200 : 401, { 'content-type': 'text/html; charset=utf-8' })
      res.end(`<!doctype html><html><body style="font-family:system-ui;padding:32px;background:#f8fafc;color:#0f172a">
<h1>Academy Dashboard</h1>
<p>Signed in as <strong>User A</strong></p>
<script>
fetch(${JSON.stringify(`${idpOrigin}/token`)}, { method: 'POST', credentials: 'include' })
  .then(r => r.ok ? r.json() : null)
  .then(d => { if (d && d.accessToken) localStorage.setItem('academy_ui_jwt', d.accessToken); })
  .catch(() => {});
</script>
</body></html>`)
      return
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<!doctype html><html><body><h1>Academy Home</h1></body></html>')
  })
  appServer.listen(0, '127.0.0.1')
  await once(appServer, 'listening')
  t.after(() => new Promise<void>(done => appServer.close(() => done())))
  appOrigin = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`

  // Spawn real Kovo server with HARDENED_NODE_FLAGS
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-signin-e2e-'))
  const port = await findFreePort()
  const kovoOrigin = `http://127.0.0.1:${port}`
  let serverOut = ''

  // Seed a project with both landingOrigin (seed) and appOrigin (approved inventory asset in defaultScope)
  const seedStore = new Store(dataDir, { ftsMode: 'preview' })
  const proj = seedStore.createProject({
    requestId: randomUUID(),
    name: 'Academy E2E Project',
    seeds: [landingOrigin],
    environment: 'local-lab',
  })
  seedStore.addProjectAsset({
    requestId: randomUUID(),
    projectId: proj.id,
    origin: appOrigin,
    source: 'manual',
    thirdParty: false,
  })
  seedStore.db.update(projects)
    .set({ defaultScope: [appOrigin, landingOrigin] })
    .where(eq(projects.id, proj.id))
    .run()
  seedStore.close()

  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      KOVO_DATA_DIR: dataDir,
      KOVO_ALLOW_LOCAL_LAB: '1',
      KOVO_ALLOW_LOCAL_MODEL: '1',
      KOVO_OFFLINE: '',
      KOVO_PUBLIC_ORIGIN: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', c => { serverOut += String(c) })
  child.stderr?.on('data', c => { serverOut += String(c) })

  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      const timedOut = await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])
      if (timedOut && child.exitCode === null) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  })

  let healthy = false
  for (let i = 0; i < 150; i += 1) {
    if (child.exitCode !== null) break
    try {
      const r = await fetch(`${kovoOrigin}/health`, { signal: AbortSignal.timeout(300) })
      if (r.ok) { healthy = true; break }
    } catch { /* retry */ }
    await delay(70)
  }
  assert.ok(healthy, `scripts/serve.ts failed to start:\n${serverOut}`)

  const bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim()
  const browser = await pwLoaded.pw.chromium.launch({
    headless: true,
    executablePath: pwLoaded.executablePath,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  })
  t.after(() => browser.close())

  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
  const page = await context.newPage()

  // Bootstrap local session and open Test Accounts tab
  await page.goto(`${kovoOrigin}/?bootstrap=${encodeURIComponent(bootstrapSecret)}`, { waitUntil: 'networkidle' })
  await page.goto(`${kovoOrigin}/projects/${proj.id}?tab=personas`, { waitUntil: 'networkidle' })

  await page.getByRole('button', { name: 'Add test account' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.waitFor({ state: 'visible', timeout: 10_000 })

  // 1. Verify Starting host selector is visible next to Sign in with browser and defaults to appOrigin (first in defaultScope)
  const startHostSelect = dialog.locator('select[name="startingHost"]')
  await startHostSelect.waitFor({ state: 'visible', timeout: 5_000 })
  assert.equal(await startHostSelect.inputValue(), appOrigin, 'Starting host should default to first approved host in defaultScope')

  // Switch Starting host to landingOrigin to exercise live 308 redirect + IdP hop!
  await startHostSelect.selectOption(landingOrigin)
  await dialog.getByRole('button', { name: /Sign in with browser/ }).click()

  const addressBar = dialog.getByRole('textbox', { name: 'Browser address bar' })
  await addressBar.waitFor({ state: 'visible', timeout: 20_000 })
  await delay(600)

  // Should have followed 308 from landingOrigin -> appOrigin/signin cleanly with zero error banner!
  assert.equal(await addressBar.inputValue(), `${appOrigin}/signin`)
  assert.equal(await dialog.getByTestId('capture-nav-error').count(), 0)

  // Navigate to IdP authorize -> callback -> dashboard via address bar
  const idpAuthorizeUrl = `${idpOrigin}/authorize?return_to=${encodeURIComponent(`${appOrigin}/callback`)}`
  await addressBar.fill(idpAuthorizeUrl)
  await page.keyboard.press('Enter')
  await delay(600)
  assert.ok((await addressBar.inputValue()).startsWith(`${idpOrigin}/authorize`))

  // Complete SSO callback -> dashboard
  await addressBar.fill(`${appOrigin}/callback?code=ui_ok`)
  await page.keyboard.press('Enter')
  await delay(800)
  assert.equal(await addressBar.inputValue(), `${appOrigin}/dashboard`)

  const screenshotDir = process.env.KOVO_CAPTURE_SCREENSHOT_DIR
  if (screenshotDir) {
    await mkdir(screenshotDir, { recursive: true })
    await page.screenshot({ path: join(screenshotDir, 'persona-signin-browser-after.png') })
  }

  // Click "I'm signed in — capture session"
  await dialog.getByRole('button', { name: /I'm signed in — capture session/ }).click()

  // 2. Verify Option 3 Review Pill renders with Verify URL, Scope, IdP, and [Edit]
  const reviewPill = dialog.getByTestId('captured-session-review')
  await reviewPill.waitFor({ state: 'visible', timeout: 10_000 })
  const pillText = await reviewPill.innerText()
  assert.ok(pillText.includes(`Verify at ${appOrigin}/dashboard`), `Expected Verify URL in review pill, got: ${pillText}`)
  assert.ok(pillText.includes('Scope:'), `Expected Scope in review pill, got: ${pillText}`)
  assert.ok(pillText.includes('IdP:'), `Expected IdP in review pill, got: ${pillText}`)
  assert.equal(/\b(null|undefined)\b/.test(pillText), false, 'Review pill must never interpolate null/undefined')

  // Check geometry invariants at 1440x900 and 1280x720 (and capture screenshots if requested)
  for (const vp of [
    { width: 1440, height: 900, name: '1440x900' },
    { width: 1280, height: 720, name: '1280x720' },
  ]) {
    await page.setViewportSize({ width: vp.width, height: vp.height })
    await delay(150)
    const geo = await page.evaluate(() => {
      const dlg = document.querySelector('[role="dialog"]') as HTMLElement | null
      const submit = dlg?.querySelector('button[type="submit"]') as HTMLElement | null
      if (!dlg || !submit) return null
      const dr = dlg.getBoundingClientRect()
      const sr = submit.getBoundingClientRect()
      return {
        vpW: window.innerWidth,
        vpH: window.innerHeight,
        dlgScrollW: dlg.scrollWidth,
        dlgClientW: dlg.clientWidth,
        dlgBottom: dr.bottom,
        submitBottom: sr.bottom,
        submitTop: sr.top,
      }
    })
    assert.ok(geo, `Dialog geometry must exist at ${vp.name}`)
    assert.ok(geo.dlgScrollW <= geo.dlgClientW + 2, `Zero horizontal overflow required at ${vp.name} (${geo.dlgScrollW} > ${geo.dlgClientW})`)
    assert.ok(geo.submitBottom <= geo.vpH + 1 && geo.submitTop >= 0, `Primary CTA must be visible above the fold at ${vp.name}`)
    if (screenshotDir) {
      await page.screenshot({ path: join(screenshotDir, `persona-signin-review-${vp.name}.png`) })
    }
  }

  // Click [Edit] on the Review Pill -> expands Advanced configuration with captured fields!
  await reviewPill.getByRole('button', { name: 'Edit' }).click()
  const verifyOriginInput = dialog.locator('input[name="verifyOrigin"]')
  const verifyPathInput = dialog.locator('input[name="verifyPath"]')
  const idpOriginsTextarea = dialog.locator('textarea[name="idpOrigins"]')
  await verifyOriginInput.waitFor({ state: 'visible', timeout: 5_000 })
  assert.equal(await verifyOriginInput.inputValue(), appOrigin)
  assert.equal(await verifyPathInput.inputValue(), '/dashboard')
  assert.ok((await idpOriginsTextarea.inputValue()).includes(idpOrigin))

  // Save test account
  await dialog.getByRole('button', { name: 'Save test account', exact: true }).click()
  await dialog.waitFor({ state: 'hidden', timeout: 10_000 })

  // Click Verify sign-in -> must succeed cleanly!
  const verifyBtn = page.getByRole('button', { name: 'Verify sign-in' })
  await verifyBtn.waitFor({ state: 'visible', timeout: 10_000 })
  await verifyBtn.click()
  const okOrCallout = await Promise.race([
    page.getByRole('button', { name: 'Verify sign-in ✓' }).waitFor({ state: 'visible', timeout: 25_000 }).then(() => ({ ok: true as const })),
    page.locator('[data-slot="persona-error-callout"]').waitFor({ state: 'visible', timeout: 25_000 }).then(async () => ({
      ok: false as const,
      text: await page.locator('[data-slot="persona-error-callout"]').innerText(),
    })),
  ])
  assert.equal(okOrCallout.ok, true, `Verify sign-in failed with callout: ${okOrCallout.ok ? '' : okOrCallout.text}`)
})
