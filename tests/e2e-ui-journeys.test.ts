import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'

const SYSTEM_CHROMIUM_CANDIDATES = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
]

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
    try {
      return pw.chromium.executablePath()
    } catch {
      return ''
    }
  })()
  if (bundled && existsSync(bundled)) {
    return { pw, executablePath: bundled }
  }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) {
      return { pw, executablePath: candidate }
    }
  }
  return null
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate an ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
}

function makeSyntheticJwt(claims: Record<string, unknown>): string {
  const encode = (obj: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url')
  const header = encode({ alg: 'RS256', typ: 'JWT' })
  const payload = encode(claims)
  return `${header}.${payload}.e2e_synthetic_signature`
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx <= 0) continue
    out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim()
  }
  return out
}

function buildResponsesSseToolCall(toolName: string, args: Record<string, unknown>): string {
  const responseId = 'resp_' + randomUUID().slice(0, 12)
  const fcId = 'fc_' + randomUUID().slice(0, 8)
  const callId = 'call_' + randomUUID().slice(0, 8)
  const serialized = JSON.stringify(args)
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } },
    {
      type: 'response.output_item.added',
      output_index: 0,
      item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: callId, name: toolName, arguments: '' },
    },
    { type: 'response.function_call_arguments.delta', output_index: 0, item_id: fcId, delta: serialized },
    { type: 'response.function_call_arguments.done', output_index: 0, item_id: fcId, name: toolName, arguments: serialized },
    {
      type: 'response.output_item.done',
      output_index: 0,
      item: { id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: toolName, arguments: serialized },
    },
    {
      type: 'response.completed',
      response: {
        id: responseId,
        status: 'completed',
        output: [{ id: fcId, type: 'function_call', status: 'completed', call_id: callId, name: toolName, arguments: serialized }],
        usage: { input_tokens: 120, output_tokens: 32, total_tokens: 152 },
      },
    },
  ]
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('') + 'data: [DONE]\n\n'
}

async function closeHttpServer(server: Server | undefined): Promise<void> {
  if (!server) return
  server.closeAllConnections()
  await new Promise<void>(done => server.close(() => done()))
}

interface MockClerkFapi {
  origin: string
  server: Server
  expectedClientCookie: string
  sessionId: string
  mintedJwts: string[]
  clientRequests: number
  tokenRequests: number
}

async function startMockClerkFapi(): Promise<MockClerkFapi> {
  const expectedClientCookie = 'e2e_mock_clerk_client_cookie_99481'
  const sessionId = 'sess_e2e_golden_01'
  const mintedJwts: string[] = []
  let clientRequests = 0
  let tokenRequests = 0

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const cookies = parseCookies(req.headers.cookie)
    if (cookies.__client !== expectedClientCookie) {
      res.writeHead(401, { 'content-type': 'application/json' }).end(JSON.stringify({
        errors: [{ code: 'client_invalid', message: 'Invalid __client cookie' }],
      }))
      return
    }
    if (req.method === 'GET' && url.pathname === '/v1/client') {
      clientRequests += 1
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        response: {
          id: 'client_e2e_golden',
          sessions: [{ id: sessionId, status: 'active' }],
          last_active_session_id: sessionId,
        },
      }))
      return
    }
    if (req.method === 'POST' && url.pathname === `/v1/client/sessions/${sessionId}/tokens`) {
      tokenRequests += 1
      const nowSec = Math.floor(Date.now() / 1000)
      const jwt = makeSyntheticJwt({
        sub: 'user_e2e_a',
        sid: sessionId,
        iat: nowSec,
        exp: nowSec + 300,
      })
      mintedJwts.push(jwt)
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jwt }))
      return
    }
    res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'not_found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not bind mock Clerk FAPI server.')
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    server,
    expectedClientCookie,
    sessionId,
    mintedJwts,
    get clientRequests() { return clientRequests },
    get tokenRequests() { return tokenRequests },
  }
}

interface MockTargetSaas {
  origin: string
  server: Server
  publishableKey: string
  requests: Array<{ method: string; path: string; authed: boolean }>
}

async function startMockTargetSaas(clerk: MockClerkFapi): Promise<MockTargetSaas> {
  // Valid Clerk publishable key encoding a synthetic Clerk FAPI domain.
  const publishableKey = 'pk_test_' + Buffer.from('clerk.e2e-saas.local$', 'utf8').toString('base64')
  const requests: Array<{ method: string; path: string; authed: boolean }> = []

  const isAuthed = (req: IncomingMessage): boolean => {
    const cookies = parseCookies(req.headers.cookie)
    return Boolean(cookies.__session && clerk.mintedJwts.includes(cookies.__session))
  }

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const authed = isAuthed(req)
    requests.push({ method: req.method ?? 'GET', path: url.pathname, authed })

    if (url.pathname === '/api/me') {
      if (!authed) {
        res.writeHead(401, {
          'content-type': 'application/json',
          'x-clerk-auth-status': 'signed-out',
        }).end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.writeHead(200, {
        'content-type': 'application/json',
        'x-clerk-auth-status': 'signed-in',
      }).end(JSON.stringify({ id: 'user_e2e_a', role: 'member', email: 'user-a@e2e-saas.local' }))
      return
    }

    if (authed) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'x-clerk-auth-status': 'signed-in',
      }).end(`<!doctype html><html><head><title>E2E SaaS Dashboard</title><meta name="clerk-pk" content="${publishableKey}"></head><body><h1>Signed in as User A</h1></body></html>`)
      return
    }
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'x-clerk-auth-status': 'signed-out',
    }).end(`<!doctype html><html><head><title>E2E SaaS</title><script data-clerk-publishable-key="${publishableKey}" src="/clerk-stub.js"></script></head><body><h1>Please sign in</h1></body></html>`)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not bind mock target SaaS server.')
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    server,
    publishableKey,
    requests,
  }
}

interface MockModelProvider {
  origin: string
  server: Server
  acceptedKeys: Set<string>
  calls: Array<{ authHeader: string; path: string }>
}

async function startMockModelProvider(acceptedKeys: string[]): Promise<MockModelProvider> {
  const keySet = new Set(acceptedKeys)
  const calls: Array<{ authHeader: string; path: string }> = []

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const authHeader = String(req.headers.authorization ?? '')
      calls.push({ authHeader, path: url.pathname })
      const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length).trim() : ''
      if (!keySet.has(bearer)) {
        res.writeHead(401, { 'content-type': 'application/json' }).end(JSON.stringify({
          error: { message: 'Invalid mock API key' },
        }))
        return
      }
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(Buffer.from(chunk))
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
        tools?: Array<{ name?: string }>
      }
      const toolNames = new Set((body.tools ?? []).map(t => t.name ?? ''))
      if (toolNames.has('kovo_connection')) {
        res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' })
          .end(buildResponsesSseToolCall('kovo_connection', { status: 'ready' }))
        return
      }
      res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8' })
        .end(buildResponsesSseToolCall('kovo_connection', { status: 'ready' }))
    })().catch(() => {
      if (!res.headersSent) res.writeHead(500)
      res.end()
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not bind mock model provider server.')
  return {
    origin: `http://127.0.0.1:${addr.port}`,
    server,
    acceptedKeys: keySet,
    calls,
  }
}

function ensureBuilt(): void {
  const serverEntry = resolve('build/server/server.js')
  const clientDir = resolve('build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'pipe' })
}

interface SpawnedKovoServer {
  origin: string
  port: number
  dataDir: string
  bootstrapSecret: string
  getOutput(): string
  getExitInfo(): { exitCode: number | null; signalCode: NodeJS.Signals | null }
  stop(): Promise<void>
}

async function startKovoServer(): Promise<SpawnedKovoServer> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-e2e-ui-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, ['scripts/serve.ts'], {
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
  child.stdout?.on('data', chunk => { output += String(chunk) })
  child.stderr?.on('data', chunk => { output += String(chunk) })

  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      const timedOut = await Promise.race([
        exited.then(() => false),
        delay(3_000).then(() => true),
      ])
      if (timedOut && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  }

  let healthy = false
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null) break
    try {
      const res = await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })
      if (res.ok) {
        healthy = true
        break
      }
    } catch {
      // Server not bound yet.
    }
    await delay(70)
  }
  if (!healthy) {
    await stop()
    throw new Error(`scripts/serve.ts failed to start on ${origin}.\n${output}`)
  }

  let bootstrapSecret = ''
  for (let read = 0; read < 30 && !bootstrapSecret; read += 1) {
    try {
      bootstrapSecret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim()
    } catch {
      await delay(50)
    }
  }
  if (!bootstrapSecret) {
    await stop()
    throw new Error(`Bootstrap secret file was not written in ${dataDir}.\n${output}`)
  }

  return {
    origin,
    port,
    dataDir,
    bootstrapSecret,
    getOutput: () => output,
    getExitInfo: () => ({ exitCode: child.exitCode, signalCode: child.signalCode }),
    stop,
  }
}

function withSqlite<T>(dataDir: string, fn: (db: DatabaseSync) => T): T {
  const db = new DatabaseSync(join(dataDir, 'kovo.sqlite'))
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    return fn(db)
  } finally {
    db.close()
  }
}

const MODEL_KEY_1 = 'sk-or-v1-e2e-first-profile-secret-11111111'
const MODEL_KEY_2 = 'sk-or-v1-e2e-second-profile-secret-22222222'

describe('Pillar 1 — Real Headless Playwright Full-Stack E2E Golden Journeys', { timeout: 90_000 }, () => {
  let skipReason: string | null = null
  let clerkServer: MockClerkFapi | undefined
  let targetServer: MockTargetSaas | undefined
  let modelServer: MockModelProvider | undefined
  let kovo: SpawnedKovoServer | undefined
  let browser: Browser | undefined
  let context: BrowserContext | undefined
  let page: Page | undefined
  const pageErrors: string[] = []

  // Shared identifiers produced across the sequential golden journeys.
  let projectId = ''
  let runId = ''

  before(async () => {
    const pwEnv = await loadPlaywright()
    if (!pwEnv) {
      skipReason = 'Playwright or Chromium binary unavailable in this environment'
      return
    }
    ensureBuilt()
    clerkServer = await startMockClerkFapi()
    targetServer = await startMockTargetSaas(clerkServer)
    modelServer = await startMockModelProvider([MODEL_KEY_1, MODEL_KEY_2])
    kovo = await startKovoServer()
    browser = await pwEnv.pw.chromium.launch({
      headless: true,
      executablePath: pwEnv.executablePath,
      args: ['--no-sandbox'],
    })
    context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
    page = await context.newPage()
    page.on('pageerror', err => {
      pageErrors.push(err instanceof Error ? err.message : String(err))
    })
  })

  after(async () => {
    if (context) {
      await context.close().catch(() => {})
    }
    if (browser) {
      await browser.close().catch(() => {})
    }
    if (kovo) {
      await kovo.stop().catch(() => {})
    }
    await Promise.all([
      closeHttpServer(targetServer?.server),
      closeHttpServer(clerkServer?.server),
      closeHttpServer(modelServer?.server),
    ])
  })

  it('Journey 1: Bootstrap auth + Project creation + Inventory pre-approved seeds & Settings nav', async t => {
    if (skipReason || !page || !kovo || !targetServer) {
      t.skip(skipReason ?? 'Browser setup unavailable')
      return
    }

    // Bare unauthenticated request must be rejected with 401 before bootstrap.
    const unauth = await fetch(kovo.origin)
    assert.equal(unauth.status, 401, 'Bare unauthenticated GET / must return 401')

    // Open single-use bootstrap URL in real Chromium.
    await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
      waitUntil: 'domcontentloaded',
    })
    await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
    assert.equal(new URL(page.url()).searchParams.has('bootstrap'), false, 'Bootstrap query param must be stripped via 303 redirect')

    // Verify sidebar navigation link says "Settings" (not legacy "Model settings").
    const workspaceNav = page.getByRole('navigation', { name: 'Workspace' })
    const settingsLink = workspaceNav.getByRole('link', { name: 'Settings', exact: true })
    await settingsLink.waitFor({ state: 'visible', timeout: 10_000 })
    assert.equal(await workspaceNav.getByRole('link', { name: 'Model settings' }).count(), 0)

    // Create a Local Lab project targeting the local mock SaaS app.
    await page.getByLabel('Project name').fill('E2E Golden SaaS')
    await page.getByLabel('Sites').fill(targetServer.origin)
    await page.getByRole('button', { name: /Advanced configuration/ }).click()
    await page.getByLabel('Target environment').selectOption('local-lab')
    await page.getByRole('button', { name: 'Create project', exact: true }).click()

    await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
    const match = /\/projects\/([a-f0-9-]+)/.exec(page.url())
    assert.ok(match?.[1], `Expected project URL, got ${page.url()}`)
    projectId = match[1]

    // Open Inventory tab and verify seed host starts pre-approved in scope.
    await page.getByRole('tab', { name: /^Inventory/ }).click()
    const inventorySection = page.getByRole('region', { name: 'Project inventory' })
    await inventorySection.waitFor({ state: 'visible', timeout: 10_000 })
    await inventorySection.getByRole('heading', { name: /Approved in scope\s*\(1\)/ }).waitFor({
      state: 'visible',
      timeout: 10_000,
    })
    assert.equal(
      await inventorySection.getByRole('heading', { name: /Needs approval/ }).count(),
      0,
      'Seed host must start pre-approved, not under Needs approval',
    )
    const targetHost = new URL(targetServer.origin).host
    const approveCheckbox = inventorySection.getByRole('checkbox', {
      name: `Remove host ${targetHost} from project scope`,
    })
    await approveCheckbox.waitFor({ state: 'visible', timeout: 5_000 })
    assert.equal(await approveCheckbox.getAttribute('aria-checked'), 'true')
    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })

  it('Journey 2: Test Accounts (<PersonaFormModal>) auto-label, removed fields, top-level Header name, and Clerk __client auto-refresh', async t => {
    if (skipReason || !page || !kovo || !targetServer || !clerkServer) {
      t.skip(skipReason ?? 'Browser setup unavailable')
      return
    }
    assert.ok(projectId, 'Journey 1 must have created a project')

    // Confirm mock SaaS /api/me rejects anonymous requests with 401.
    const anonMe = await fetch(`${targetServer.origin}/api/me`)
    assert.equal(anonMe.status, 401, 'Mock SaaS /api/me must return 401 anonymously')

    await page.getByRole('tab', { name: /^Test Accounts/ }).click()
    await page.getByRole('button', { name: 'Add test account', exact: true }).click()

    const dialog = page.getByRole('dialog')
    await dialog.waitFor({ state: 'visible', timeout: 10_000 })
    await dialog.getByRole('heading', { name: 'Add test account' }).waitFor({ state: 'visible', timeout: 5_000 })

    // 1. Account label is auto-populated with "User A".
    const labelInput = dialog.locator('input[name="roleLabel"]')
    assert.equal(await labelInput.inputValue(), 'User A', 'Account label should auto-populate with "User A"')

    // 2. Legacy Handle input and canaryMarkers are completely GONE.
    assert.equal(await dialog.locator('input[name="handle"]').count(), 0, 'Handle input must be removed')
    assert.equal(await dialog.getByLabel(/^Handle/i).count(), 0, 'Handle label must be removed')
    assert.equal(await dialog.locator('[name="canaryMarkers"]').count(), 0, 'canaryMarkers input must be removed')
    const dialogTextInitial = await dialog.innerText()
    assert.equal(/canary/i.test(dialogTextInitial), false, 'canaryMarkers copy must not appear in PersonaFormModal')

    // 3. Selecting Custom request header reveals Header name immediately outside Disclosure.
    const signInSelect = dialog.locator('select[name="authKind"]')
    await signInSelect.selectOption('header')
    const headerNameInput = dialog.locator('input[name="headerName"]')
    await headerNameInput.waitFor({ state: 'visible', timeout: 5_000 })
    const advTrigger = dialog.getByRole('button', { name: 'Advanced configuration' })
    assert.equal(
      await advTrigger.getAttribute('aria-expanded'),
      'false',
      'Header name must be visible while Advanced configuration Disclosure stays collapsed',
    )

    // 4. Selecting Clerk __client cookie (auto-refresh) works cleanly end-to-end.
    await signInSelect.selectOption('clerk_client')
    const clerkCookieInput = dialog.locator('input[name="secret"]')
    const clerkFapiInput = dialog.locator('input[name="loginUrl"]')
    await clerkCookieInput.waitFor({ state: 'visible', timeout: 5_000 })
    await clerkFapiInput.waitFor({ state: 'visible', timeout: 5_000 })

    await clerkCookieInput.fill(`__client=${clerkServer.expectedClientCookie}`)
    await clerkFapiInput.fill(clerkServer.origin)

    // Add mock Clerk FAPI loopback origin to Allowed sites (keeping target SaaS first as primary target).
    await advTrigger.click()
    const allowlistTextarea = dialog.locator('textarea[name="originAllowlist"]')
    await allowlistTextarea.waitFor({ state: 'visible', timeout: 5_000 })
    await allowlistTextarea.fill(`${targetServer.origin}\n${clerkServer.origin}`)

    await dialog.getByRole('button', { name: 'Save test account', exact: true }).click()
    await dialog.waitFor({ state: 'hidden', timeout: 10_000 })

    // Verify saved persona renders with derived handle "user-a", Clerk badge, and never leaks secret.
    const personasSection = page.getByRole('region', { name: 'Test accounts' })
    await personasSection.getByRole('status').filter({ hasText: 'Saved test account "user-a"' }).waitFor({
      state: 'visible',
      timeout: 10_000,
    })
    const sectionText = await personasSection.innerText()
    assert.ok(sectionText.includes('Clerk __client (auto-refresh)'), 'Expected Clerk __client badge on saved test account')
    assert.equal(sectionText.includes(clerkServer.expectedClientCookie), false, 'Clerk __client secret must never render in DOM')

    // Click "Verify sign-in" to exercise the real Clerk FAPI -> JWT mint -> target SaaS verification flow.
    await personasSection.getByRole('button', { name: 'Verify sign-in', exact: true }).click()
    await personasSection.getByRole('button', { name: 'Verify sign-in ✓', exact: true }).waitFor({
      state: 'visible',
      timeout: 15_000,
    })
    const verifiedText = await personasSection.innerText()
    assert.match(verifiedText, /HTTP 200/, 'Verify sign-in must display HTTP 200 badge')
    assert.match(verifiedText, /Clerk \(auto-refresh/, 'Verify sign-in must display Clerk auto-refresh adapter hint')
    assert.ok(clerkServer.clientRequests >= 1, 'Mock Clerk FAPI must have received GET /v1/client')
    assert.ok(clerkServer.tokenRequests >= 1, 'Mock Clerk FAPI must have received POST /v1/client/sessions/:id/tokens')
    assert.ok(clerkServer.mintedJwts.length >= 1, 'Mock Clerk FAPI must have minted a fresh session JWT')

    // Confirm mock SaaS /api/me returns 200 with the freshly minted Clerk JWT.
    const authedMe = await fetch(`${targetServer.origin}/api/me`, {
      headers: { Cookie: `__session=${clerkServer.mintedJwts.at(-1)}` },
    })
    assert.equal(authedMe.status, 200, 'Mock SaaS /api/me must return 200 with minted Clerk JWT')
    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })

  it('Journey 3: New Run 3-card Scan Mode + Scope Review fast navigation & hidden Coordinator aside', async t => {
    if (skipReason || !page || !kovo) {
      t.skip(skipReason ?? 'Browser setup unavailable')
      return
    }
    assert.ok(projectId, 'Journey 1 must have created a project')

    await page.getByRole('button', { name: 'New run', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.waitFor({ state: 'visible', timeout: 10_000 })

    // Verify 3-card Scan mode picker exists with Passive / Supervised / Autonomous.
    const scanModeGroup = dialog.getByRole('radiogroup', { name: 'Scan mode' })
    await scanModeGroup.waitFor({ state: 'visible', timeout: 5_000 })
    const passiveCard = scanModeGroup.getByRole('radio', { name: /Passive Scan/ })
    const supervisedCard = scanModeGroup.getByRole('radio', { name: /Supervised Scan/ })
    const autonomousCard = scanModeGroup.getByRole('radio', { name: /Autonomous Scan/ })
    await passiveCard.waitFor({ state: 'visible', timeout: 5_000 })
    await supervisedCard.waitFor({ state: 'visible', timeout: 5_000 })
    await autonomousCard.waitFor({ state: 'visible', timeout: 5_000 })
    assert.equal(await supervisedCard.getAttribute('aria-checked'), 'true', 'Supervised Scan must be selected by default')

    // Expand Advanced configuration so we also verify legacy controls are absent inside it.
    await dialog.getByRole('button', { name: /Advanced configuration/ }).click()
    const dialogText = await dialog.innerText()
    assert.equal(/\bWorkers\b/.test(dialogText), false, 'Legacy Workers control must be removed')
    assert.equal(/\bMax turns\b/i.test(dialogText), false, 'Legacy Max turns control must be removed')
    assert.equal(/\bScan depth\b/i.test(dialogText), false, 'Legacy Scan depth control must be removed')
    assert.equal(
      await dialog.getByRole('radiogroup', { name: /Approval policy/i }).count(),
      0,
      'Separate 3-card Approval Policy picker must be removed',
    )
    assert.equal(await dialog.getByRole('radiogroup').count(), 1, 'Only the single 3-card Scan mode radiogroup should exist')

    // Start run and verify fast navigation to /runs/:runId in Scope Review with right-hand Coordinator <aside> hidden.
    const navStartedAt = Date.now()
    await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
    await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 10_000 })
    const navElapsedMs = Date.now() - navStartedAt
    assert.ok(navElapsedMs < 5_000, `Start run navigation should complete fast (<5000ms), took ${navElapsedMs}ms`)

    const match = /\/runs\/([a-f0-9-]+)/.exec(page.url())
    assert.ok(match?.[1], `Expected run URL, got ${page.url()}`)
    runId = match[1]

    // Confirm run landed in review phase and Proposed scope sheet is visible.
    await page.getByText('Proposed scope').waitFor({ state: 'visible', timeout: 10_000 })
    const runRow = withSqlite(kovo.dataDir, db =>
      db.prepare('SELECT phase, status FROM runs WHERE id = ?').get(runId) as { phase: string; status: string } | undefined,
    )
    assert.equal(runRow?.phase, 'review', `Expected run phase to be 'review', got ${runRow?.phase}`)
    assert.equal(runRow?.status, 'waiting', `Expected run status to be 'waiting', got ${runRow?.status}`)

    // Hard UX invariant: right-hand Coordinator / Inspector <aside> MUST be hidden while in `review`.
    assert.equal(
      await page.locator('aside[aria-label="Inspector"]').count(),
      0,
      'Right-hand Coordinator/Inspector <aside> must be hidden while run is in review phase',
    )
    assert.equal(
      await page.getByTestId('board-pane').count(),
      0,
      'Board/Coordinator pane must not render while run is in review phase',
    )
    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })

  it('Journey 4: Reload Persistence (F5) hydrates historical Activity events and Exchanges cleanly', async t => {
    if (skipReason || !page || !kovo || !targetServer) {
      t.skip(skipReason ?? 'Browser setup unavailable')
      return
    }
    assert.ok(runId, 'Journey 3 must have created a run')

    const now = Date.now()
    const assignmentId = randomUUID()
    const exchangeId = randomUUID()
    const seededEventMsg1 = 'Seeded historical discovery snapshot for reload test'
    const seededEventMsg2 = 'Baseline auth check completed on /api/me'
    const seededDeniedMsg = 'Blocked state-changing POST /api/admin/reset under read-only scope'

    withSqlite(kovo.dataDir, db => {
      const ws = db.prepare('SELECT workspace_id AS workspaceId FROM runs WHERE id = ?').get(runId) as { workspaceId: string }
      db.prepare(`
        INSERT INTO assignments (
          id, run_id, phase, status, scope_revision, goal_revision, session_id,
          attempt, max_turns, turns_used, requests_used, parent_fact_ids, source_origins,
          title, objective, created_at
        ) VALUES (?, ?, 'discovery', 'complete', 0, 1, ?, 1, 50, 2, 2, '[]', ?, 'Baseline Recon', 'Verify reload persistence', ?)
      `).run(assignmentId, runId, `sess-${assignmentId.slice(0, 8)}`, JSON.stringify([targetServer!.origin]), now - 5_000)

      db.prepare(`
        INSERT INTO broker_exchanges (
          id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins,
          method, path_and_query, persona_handle, status, media_type, req_headers, resp_headers,
          body_preview, body_sha256, secret_matches, duration_ms, created_at
        ) VALUES (?, ?, ?, 0, ?, ?, '[]', 'GET', '/api/me', 'user-a', 200, 'application/json', '{}', '{}', ?, ?, '[]', 14, ?)
      `).run(
        exchangeId,
        runId,
        assignmentId,
        targetServer!.origin,
        targetServer!.origin,
        '{"id":"user_e2e_a"}',
        'e2e-body-sha256',
        now - 4_000,
      )

      const insertEvent = db.prepare(`
        INSERT INTO events (workspace_id, run_id, kind, message, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      insertEvent.run(ws.workspaceId, runId, 'discovery.complete', seededEventMsg1, JSON.stringify({ origin: targetServer!.origin }), now - 4_500)
      insertEvent.run(
        ws.workspaceId,
        runId,
        'broker.exchange',
        `GET ${targetServer!.origin}/api/me → 200`,
        JSON.stringify({ exchangeId, origin: targetServer!.origin, status: 200, personaHandle: 'user-a', assignmentId }),
        now - 4_000,
      )
      insertEvent.run(ws.workspaceId, runId, 'worker.started', seededEventMsg2, JSON.stringify({ assignmentId, origin: targetServer!.origin }), now - 3_500)
      insertEvent.run(
        ws.workspaceId,
        runId,
        'broker.denied',
        seededDeniedMsg,
        JSON.stringify({
          method: 'POST',
          origin: targetServer!.origin,
          path: '/api/admin/reset',
          status: 403,
          persona: 'user-a',
          reason: 'Read-only policy blocked state-changing request',
          assignmentId,
        }),
        now - 3_000,
      )
    })

    // Trigger real browser F5 reload on the run page (never wait for networkidle because SSE stays open).
    await page.reload({ waitUntil: 'domcontentloaded' })
    const telemetryNav = page.getByRole('navigation', { name: 'Telemetry views' })
    await telemetryNav.waitFor({ state: 'visible', timeout: 15_000 })

    // Open Activity view and assert historical events render cleanly (NOT "Quiet so far").
    await telemetryNav.getByRole('button', { name: /^Activity/ }).click()
    await page.getByText(seededEventMsg1).waitFor({ state: 'visible', timeout: 15_000 })
    await page.getByText(seededEventMsg2).waitFor({ state: 'visible', timeout: 10_000 })
    await page.getByText(seededDeniedMsg).waitFor({ state: 'visible', timeout: 10_000 })
    assert.equal(await page.getByText('Quiet so far').count(), 0, 'Activity view must not show "Quiet so far" after reload')

    // Open Exchanges view and assert both seeded exchange and historical denied event render cleanly.
    await telemetryNav.getByRole('button', { name: /^Exchanges/ }).click()
    await page.getByText('/api/me').waitFor({ state: 'visible', timeout: 10_000 })
    await page.getByText('/api/admin/reset').waitFor({ state: 'visible', timeout: 10_000 })
    assert.equal(await page.getByText('No exchanges yet').count(), 0, 'Exchanges view must not show "No exchanges yet" after reload')
    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })

  it('Journey 5: Settings Model Profile key safety across 2 OpenRouter profiles + Devices modal real /_kovo/auth/status', async t => {
    if (skipReason || !page || !kovo || !modelServer) {
      t.skip(skipReason ?? 'Browser setup unavailable')
      return
    }

    // Open /settings directly (without ?runId= redirect param) so we stay on Settings between profile additions.
    const exitBeforeJ5 = kovo.getExitInfo()
    assert.equal(
      exitBeforeJ5.exitCode,
      null,
      `Kovo server crashed before Journey 5 (exit=${exitBeforeJ5.exitCode}, signal=${exitBeforeJ5.signalCode}):\n${kovo.getOutput()}`,
    )
    await page.goto(`${kovo.origin}/settings`, { waitUntil: 'domcontentloaded' })
    await page.getByRole('heading', { name: 'Settings', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })

    // --- Add 1st OpenRouter profile ---
    await page.getByRole('button', { name: 'Add model profile' }).click()
    let sheet = page.getByRole('dialog')
    await sheet.waitFor({ state: 'visible', timeout: 10_000 })

    // Verify Default · OpenRouter card is selected by default with OpenRouter badges.
    const defaultOrRadio = sheet.getByRole('radio', { name: /Default · OpenRouter/ })
    await defaultOrRadio.waitFor({ state: 'visible', timeout: 5_000 })
    assert.equal(await defaultOrRadio.getAttribute('aria-checked'), 'true')
    await sheet.getByText('openrouter.ai/api/v1').waitFor({ state: 'visible', timeout: 5_000 })

    // Switch to Custom provider so Base URL points to local mock OpenRouter Responses server (zero external LLM).
    await sheet.getByRole('radio', { name: /Custom provider/ }).click()
    const profile1Name = await sheet.locator('input[name="name"]').inputValue()
    assert.equal(profile1Name, 'OpenRouter DeepSeek V4.1 Flash', '1st profile default name should be OpenRouter DeepSeek V4.1 Flash')
    await sheet.locator('input[name="endpoint"]').fill(`${modelServer.origin}/api/v1`)
    await sheet.locator('input[name="key"]').fill(MODEL_KEY_1)
    await sheet.getByRole('button', { name: 'Save model', exact: true }).click()
    await sheet.waitFor({ state: 'hidden', timeout: 15_000 })

    const profilesTable = page.getByRole('table', { name: 'Configured model profiles' })
    await profilesTable.waitFor({ state: 'visible', timeout: 10_000 })
    assert.equal(await profilesTable.locator('tbody tr').count(), 1, 'Expected 1 model profile after first save')

    // Capture 1st profile's SQLite ID and on-disk credential path & content.
    const firstRows = withSqlite(kovo.dataDir, db =>
      db.prepare('SELECT id, name, credential_id AS credentialId FROM model_profiles').all() as Array<{
        id: string
        name: string
        credentialId: string
      }>,
    )
    assert.equal(firstRows.length, 1)
    const firstProfile = firstRows[0]!
    const firstCredPath = join(kovo.dataDir, 'credentials', firstProfile.credentialId)
    assert.equal(existsSync(firstCredPath), true, '1st profile credential file must exist on disk')
    assert.equal(readFileSync(firstCredPath, 'utf8').trim(), MODEL_KEY_1)

    // --- Add 2nd OpenRouter profile (intentionally reusing exact name to verify non-destructive safety) ---
    await page.getByRole('button', { name: /\+?\s*Add model profile/ }).click()
    sheet = page.getByRole('dialog')
    await sheet.waitFor({ state: 'visible', timeout: 10_000 })

    // Confirm Default · OpenRouter mode suggests a unique "(2)" name in its hidden/disclosure input.
    const defaultSuggested2 = await sheet.locator('input[name="name"]').inputValue()
    assert.equal(
      defaultSuggested2,
      'OpenRouter DeepSeek V4.1 Flash (2)',
      'Default OpenRouter mode must auto-suggest unique "(2)" name for 2nd profile',
    )

    // Switch to Custom provider and intentionally submit the EXACT same name as profile #1 to test backend key safety.
    await sheet.getByRole('radio', { name: /Custom provider/ }).click()
    await sheet.locator('input[name="name"]').fill('OpenRouter DeepSeek V4.1 Flash')
    await sheet.locator('input[name="endpoint"]').fill(`${modelServer.origin}/api/v1`)
    await sheet.locator('input[name="key"]').fill(MODEL_KEY_2)
    await sheet.getByRole('button', { name: 'Save model', exact: true }).click()
    await sheet.waitFor({ state: 'hidden', timeout: 15_000 })

    // Verify both profiles exist in the table.
    await profilesTable.getByText('OpenRouter DeepSeek V4.1 Flash (2)').waitFor({ state: 'visible', timeout: 10_000 })
    assert.equal(await profilesTable.locator('tbody tr').count(), 2, 'Both 1st and 2nd OpenRouter profiles must coexist')

    // Verify 1st profile still exists in SQLite and its credential file was NOT deleted or overwritten!
    const allRows = withSqlite(kovo.dataDir, db =>
      db.prepare('SELECT id, name, credential_id AS credentialId FROM model_profiles ORDER BY name ASC').all() as Array<{
        id: string
        name: string
        credentialId: string
      }>,
    )
    assert.equal(allRows.length, 2, 'SQLite must retain both model profiles')
    const retainedFirst = allRows.find(r => r.id === firstProfile.id)
    const addedSecond = allRows.find(r => r.id !== firstProfile.id)
    assert.ok(retainedFirst, '1st profile row must still exist with its original ID')
    assert.ok(addedSecond, '2nd profile row must exist with a distinct ID')
    assert.notEqual(retainedFirst.credentialId, addedSecond.credentialId, 'Each profile must own a distinct credential file')
    assert.equal(existsSync(firstCredPath), true, '1st profile credential file must NOT be deleted when adding 2nd profile')
    assert.equal(readFileSync(firstCredPath, 'utf8').trim(), MODEL_KEY_1, '1st profile key must remain intact on disk')
    const secondCredPath = join(kovo.dataDir, 'credentials', addedSecond.credentialId)
    assert.equal(existsSync(secondCredPath), true, '2nd profile credential file must exist on disk')
    assert.equal(readFileSync(secondCredPath, 'utf8').trim(), MODEL_KEY_2)

    // Neither secret may ever appear in the DOM.
    const bodyText = await page.locator('body').innerText()
    assert.equal(bodyText.includes(MODEL_KEY_1), false, '1st API key must never appear in browser DOM')
    assert.equal(bodyText.includes(MODEL_KEY_2), false, '2nd API key must never appear in browser DOM')

    // --- Open Devices modal and assert real status from /_kovo/auth/status ---
    const statusResponsePromise = page.waitForResponse(
      res => new URL(res.url()).pathname === '/_kovo/auth/status' && res.request().method() === 'GET',
      { timeout: 10_000 },
    )
    await page.getByRole('button', { name: /Local session/ }).click()
    const statusResponse = await statusResponsePromise
    assert.equal(statusResponse.status(), 200, '/_kovo/auth/status must return HTTP 200')
    const statusJson = (await statusResponse.json()) as {
      authenticated: boolean
      origin: string
      loopbackOnly: boolean
      activePairingLinks: number
    }
    assert.equal(statusJson.authenticated, true)
    assert.equal(statusJson.loopbackOnly, true)
    assert.equal(statusJson.origin, kovo.origin)

    const devicesDialog = page.getByRole('dialog')
    await devicesDialog.waitFor({ state: 'visible', timeout: 10_000 })
    await devicesDialog.getByRole('heading', { name: 'Devices & local session' }).waitFor({ state: 'visible', timeout: 5_000 })
    await devicesDialog.getByText('Active', { exact: true }).waitFor({ state: 'visible', timeout: 10_000 })
    await devicesDialog.getByText('Loopback-only pairing URL').waitFor({ state: 'visible', timeout: 5_000 })

    // Mint a real one-time pairing link to verify full /_kovo/auth/pairing-link round-trip.
    await devicesDialog.getByRole('button', { name: 'Generate pairing link', exact: true }).click()
    const pairingUrlInput = devicesDialog.getByLabel('One-time device pairing URL')
    await pairingUrlInput.waitFor({ state: 'visible', timeout: 10_000 })
    const pairingUrl = await pairingUrlInput.inputValue()
    assert.match(pairingUrl, new RegExp(`^${kovo.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\?bootstrap=[a-f0-9]{64}$`))
    await devicesDialog.getByText(/Expires in \d+:\d{2}/).waitFor({ state: 'visible', timeout: 5_000 })
    await devicesDialog.getByRole('button', { name: 'Close', exact: true }).click()
    await devicesDialog.waitFor({ state: 'hidden', timeout: 5_000 })

    assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
  })
})
