#!/usr/bin/env node
/**
 * Move 3 — Autonomous Dogfooding QA Harness (`scripts/qa-dogfood.ts`).
 *
 * Standalone human-journey runner (strictly selective — NOT run in `worker-gate.sh`) that boots:
 *   1. A realistic local multi-origin mock SaaS target (loopback app server with a `308` redirect
 *      hop, cross-port IdP login server setting session cookies, protected `/api/profile`, and
 *      benign public routes), PLUS
 *   2. A fresh isolated Kovo Hunter server (`scripts/serve.ts` with `HARDENED_NODE_FLAGS` and
 *      `KOVO_QA_ANOMALIES=1`),
 *
 * and drives 5 complete real-user Playwright journeys at 1280×720, saving numbered PNG screenshots
 * and a structured `dogfood-report.json` into `--out-dir` for visual & automated QA inspection.
 *
 * Usage:
 *   node scripts/qa-dogfood.ts [--out-dir <dir>] [--journey=all|1|2|3|4|5]
 */
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomBytes, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { setTimeout as delay } from 'node:timers/promises'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import {
  clearQaAnomalies,
  inspectRunPostCompletionAnomalies,
  isQaAnomaliesEnabled,
  listQaAnomalies,
  QA_ANOMALIES_MAX_ENTRIES,
  qaAnomalyKinds,
  recordQaAnomaly,
} from '../src/server/qa-anomalies.ts'
import type { QaAnomalyKind, QaAnomalyRecord } from '../src/server/qa-anomalies.ts'

const VIEWPORT = { width: 1280, height: 720 } as const

const HARDENED_NODE_FLAGS = [
  '--disable-proto=delete',
  '--enable-experimental-regexp-engine-on-excessive-backtracks',
  '--regexp-backtracks-before-fallback=10000',
] as const

const SYSTEM_CHROMIUM_CANDIDATES = [
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
] as const

interface CliOptions {
  outDir: string
  journeys: Set<number>
  help: boolean
}

function parseCliArgs(argv: readonly string[]): CliOptions {
  const defaultOutDir = resolve(process.env.TMPDIR || tmpdir(), `kovo-qa-dogfood-${Date.now()}`)
  let outDir = defaultOutDir
  let journeySpec = 'all'
  let help = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '-h' || arg === '--help') {
      help = true
    } else if (arg === '--out-dir') {
      const next = argv[i + 1]
      if (!next) throw new Error('--out-dir requires a directory path')
      outDir = resolve(next)
      i += 1
    } else if (arg.startsWith('--out-dir=')) {
      outDir = resolve(arg.slice('--out-dir='.length))
    } else if (arg === '--journey') {
      const next = argv[i + 1]
      if (!next) throw new Error('--journey requires all or 1|2|3|4|5')
      journeySpec = next
      i += 1
    } else if (arg.startsWith('--journey=')) {
      journeySpec = arg.slice('--journey='.length)
    } else {
      throw new Error(`Unknown argument: ${arg}`)
    }
  }

  const journeys = new Set<number>()
  if (journeySpec.trim().toLowerCase() === 'all') {
    for (const n of [1, 2, 3, 4, 5]) journeys.add(n)
  } else {
    for (const part of journeySpec.split(',')) {
      const n = Number(part.trim())
      if (!Number.isInteger(n) || n < 1 || n > 5) {
        throw new Error(`Invalid --journey value "${journeySpec}". Expected all or 1|2|3|4|5.`)
      }
      journeys.add(n)
    }
  }

  return { outDir, journeys, help }
}

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string }> {
  let pw: PlaywrightModule | null = null
  for (const modName of ['@playwright/test', 'playwright-core', 'playwright'] as const) {
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') {
        pw = loaded as PlaywrightModule
        break
      }
    } catch {
      // Try next candidate.
    }
  }
  if (!pw) {
    throw new Error('Playwright module unavailable (@playwright/test / playwright-core / playwright).')
  }

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
  throw new Error('Chromium executable not found (neither Playwright bundled nor system Chromium).')
}

async function findFreePort(): Promise<number> {
  const srv = createNetServer().listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const addr = srv.address()
  if (!addr || typeof addr === 'string') throw new Error('Could not allocate an ephemeral port.')
  await new Promise<void>(done => srv.close(() => done()))
  return addr.port
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

async function closeHttpServer(server: Server | undefined): Promise<void> {
  if (!server) return
  server.closeAllConnections()
  await new Promise<void>(done => server.close(() => done()))
}

// ---------------------------------------------------------------------------
// Realistic local multi-origin mock SaaS fixture
// ---------------------------------------------------------------------------

interface MockMultiOriginSaas {
  appOrigin: string
  idpOrigin: string
  validSessionToken: string
  redirect308Hits: number
  idpLoginHits: number
  profileAuthedHits: number
  close(): Promise<void>
}

async function startMockMultiOriginSaas(): Promise<MockMultiOriginSaas> {
  const validSessionToken = `qa_sess_${randomBytes(12).toString('hex')}`
  const validIdpCookie = `qa_idp_${randomBytes(10).toString('hex')}`
  const issuedTickets = new Set<string>()
  let redirect308Hits = 0
  let idpLoginHits = 0
  let profileAuthedHits = 0

  let appOrigin = ''
  let idpOrigin = ''

  const idpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')

    if (req.method === 'GET' && url.pathname === '/login') {
      idpLoginHits += 1
      const returnTo = url.searchParams.get('returnTo') || `${appOrigin}/auth/callback`
      const safeReturnTo = returnTo.startsWith(appOrigin) ? returnTo : `${appOrigin}/auth/callback`
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Acme IdP — Single Sign-On</title>
  <style>
    body { margin: 0; font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; display: grid; place-items: center; min-height: 100vh; }
    main { width: 420px; background: #1e293b; border: 1px solid #334155; border-radius: 14px; padding: 28px; box-shadow: 0 20px 50px rgba(0,0,0,0.4); }
    h1 { margin: 0 0 8px; font-size: 22px; }
    p { margin: 0 0 18px; color: #cbd5e1; font-size: 14px; }
    label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 6px; }
    input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; margin-bottom: 14px; }
    button { width: 100%; padding: 12px 16px; border: 0; border-radius: 8px; background: #2563eb; color: #fff; font-weight: 600; font-size: 15px; cursor: pointer; }
  </style>
</head>
<body>
  <main>
    <h1>Acme Identity Provider</h1>
    <p>Cross-port SSO sign-in for Acme Workspace</p>
    <form method="POST" action="/login">
      <input type="hidden" name="returnTo" value="${safeReturnTo.replaceAll('"', '&quot;')}" />
      <label for="email">Work email</label>
      <input id="email" name="email" type="email" value="qa@acme-dogfood.local" />
      <button id="idp-submit" type="submit">Continue to Acme Workspace</button>
    </form>
  </main>
</body>
</html>`)
      return
    }

    if ((req.method === 'POST' && url.pathname === '/login') || (req.method === 'GET' && url.pathname === '/complete-sso')) {
      idpLoginHits += 1
      const ticket = `tkt_${randomBytes(10).toString('hex')}`
      issuedTickets.add(ticket)
      const callbackUrl = `${appOrigin}/auth/callback?ticket=${encodeURIComponent(ticket)}`
      res.writeHead(302, {
        'set-cookie': `idp_sid=${validIdpCookie}; Path=/; HttpOnly; SameSite=Lax`,
        location: callbackUrl,
      }).end()
      return
    }

    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ service: 'acme-idp', ok: true }))
  })

  const appServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const cookies = parseCookies(req.headers.cookie)
    const isAuthed = cookies.saas_session === validSessionToken

    // Realistic 308 Permanent Redirect hop on root entry.
    if (url.pathname === '/') {
      redirect308Hits += 1
      res.writeHead(308, { location: '/portal' }).end()
      return
    }

    if (url.pathname === '/auth/callback') {
      const ticket = url.searchParams.get('ticket') ?? ''
      if (!ticket || !issuedTickets.has(ticket)) {
        res.writeHead(400, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'invalid_ticket' }))
        return
      }
      issuedTickets.delete(ticket)
      res.writeHead(302, {
        'set-cookie': `saas_session=${validSessionToken}; Path=/; HttpOnly; SameSite=Lax`,
        location: '/portal',
      }).end()
      return
    }

    if (url.pathname === '/api/profile') {
      if (!isAuthed) {
        res.writeHead(401, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      profileAuthedHits += 1
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        id: 'usr_qa_01',
        email: 'qa@acme-dogfood.local',
        role: 'workspace_admin',
        org: 'acme-dogfood',
      }))
      return
    }

    if (url.pathname === '/status') {
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ status: 'ok', service: 'acme-saas' }))
      return
    }

    if (url.pathname === '/robots.txt') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('User-agent: *\nAllow: /\n')
      return
    }

    if (url.pathname === '/pricing' || url.pathname === '/docs') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(
        `<!doctype html><html><head><title>Acme ${url.pathname.slice(1)}</title></head><body><h1>Acme ${url.pathname.slice(1)}</h1><a href="/portal">Back to portal</a></body></html>`,
      )
      return
    }

    if (url.pathname === '/portal') {
      if (isAuthed) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8" /><title>Acme SaaS — Portal</title></head>
<body style="font-family:system-ui,sans-serif;padding:40px;background:#f8fafc;color:#0f172a">
  <h1>Signed in as QA Admin</h1>
  <p>Workspace: acme-dogfood · Session active</p>
  <nav><a href="/api/profile">Profile JSON</a> · <a href="/docs">Docs</a> · <a href="/pricing">Pricing</a></nav>
</body>
</html>`)
        return
      }
      const ssoUrl = `${idpOrigin}/login?returnTo=${encodeURIComponent(`${appOrigin}/auth/callback`)}`
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8" /><title>Acme SaaS — Sign in</title></head>
<body style="font-family:system-ui,sans-serif;padding:40px;background:#f8fafc;color:#0f172a;text-align:center">
  <h1>Acme SaaS Workspace</h1>
  <p>Please authenticate via Acme Identity Provider.</p>
  <p><a id="sso-link" href="${ssoUrl}" style="display:inline-block;padding:12px 24px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px;font-weight:600">Sign in with SSO</a></p>
  <p><a href="/pricing">Pricing</a> · <a href="/docs">Docs</a> · <a href="/status">Status</a></p>
</body>
</html>`)
      return
    }

    res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'not_found' }))
  })

  idpServer.listen(0, '127.0.0.1')
  appServer.listen(0, '127.0.0.1')
  await Promise.all([once(idpServer, 'listening'), once(appServer, 'listening')])

  const idpAddr = idpServer.address()
  const appAddr = appServer.address()
  if (!idpAddr || typeof idpAddr === 'string' || !appAddr || typeof appAddr === 'string') {
    await Promise.all([closeHttpServer(idpServer), closeHttpServer(appServer)])
    throw new Error('Could not bind local mock SaaS servers.')
  }

  idpOrigin = `http://127.0.0.1:${idpAddr.port}`
  appOrigin = `http://127.0.0.1:${appAddr.port}`

  return {
    appOrigin,
    idpOrigin,
    validSessionToken,
    get redirect308Hits() { return redirect308Hits },
    get idpLoginHits() { return idpLoginHits },
    get profileAuthedHits() { return profileAuthedHits },
    async close() {
      await Promise.all([closeHttpServer(appServer), closeHttpServer(idpServer)])
    },
  }
}

// ---------------------------------------------------------------------------
// Isolated Kovo Hunter server lifecycle
// ---------------------------------------------------------------------------

function ensureBuilt(): void {
  const serverEntry = resolve('build/server/server.js')
  const clientDir = resolve('build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  execFileSync('npm', ['run', 'build'], { cwd: process.cwd(), stdio: 'inherit' })
}

interface SpawnedKovoServer {
  origin: string
  port: number
  dataDir: string
  bootstrapSecret: string
  getOutput(): string
  stop(): Promise<void>
}

async function startIsolatedKovoServer(): Promise<SpawnedKovoServer> {
  const dataDir = await mkdtemp(join(process.env.TMPDIR || tmpdir(), 'kovo-qa-dogfood-data-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      KOVO_DATA_DIR: dataDir,
      KOVO_QA_ANOMALIES: '1',
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
      // Wait for server bind.
    }
    await delay(80)
  }

  if (!healthy) {
    await stop()
    throw new Error(`scripts/serve.ts failed to start on ${origin}.\n${output.slice(-2000)}`)
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
    throw new Error(`Bootstrap secret file missing in ${dataDir}.\n${output.slice(-2000)}`)
  }

  return {
    origin,
    port,
    dataDir,
    bootstrapSecret,
    getOutput: () => output,
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

// ---------------------------------------------------------------------------
// DOM geometry, broken-text, screenshot & report instrumentation
// ---------------------------------------------------------------------------

interface GeometrySnapshot {
  screen: string
  urlPath: string
  viewport: { width: number; height: number }
  docOverflowX: boolean
  docScrollWidth: number
  docClientWidth: number
  dialogOverflowX: boolean
  dialogOutOfViewport: boolean
  clippedCardsCount: number
  brokenTextMatches: string[]
  primaryCtaAboveFold?: boolean
}

interface ScreenshotRecord {
  file: string
  journey: number
  label: string
  urlPath: string
  theme: 'light' | 'dark'
  geometry: GeometrySnapshot
}

interface JourneyReport {
  journey: number
  name: string
  status: 'passed' | 'failed'
  durationMs: number
  checks: string[]
  error?: string
}

interface DogfoodReport {
  startedAt: string
  finishedAt: string
  durationMs: number
  viewport: { width: number; height: number }
  outDir: string
  targetFixtures: {
    appOrigin: string
    idpOrigin: string
    redirect308Hits: number
    idpLoginHits: number
    profileAuthedHits: number
  }
  summary: {
    journeysTotal: number
    journeysPassed: number
    journeysFailed: number
    screenshotsCaptured: number
    anomaliesCount: number
    consoleErrorsCount: number
    pageErrorsCount: number
    failedRequestsCount: number
    geometryViolationsCount: number
    brokenTextViolationsCount: number
  }
  qaAnomaliesConfig: {
    enabled: boolean
    maxEntries: number
    byKind: Record<QaAnomalyKind, number>
  }
  journeys: JourneyReport[]
  screenshots: ScreenshotRecord[]
  anomalies: QaAnomalyRecord[]
  consoleErrors: Array<{ ts: number; urlPath: string; text: string }>
  pageErrors: Array<{ ts: number; urlPath: string; message: string }>
  failedRequests: Array<{ ts: number; method: string; urlPath: string; status: number | null; reason: string }>
}

function safeUrlPath(rawUrl: string): string {
  try {
    const u = new URL(rawUrl)
    return u.pathname || '/'
  } catch {
    return rawUrl.split(/[?#]/, 1)[0] || '/'
  }
}

async function setPageTheme(page: Page, theme: 'light' | 'dark'): Promise<void> {
  await page.evaluate(next => {
    document.documentElement.dataset.appearance = next
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem('kovo-appearance', next)
    } catch {
      // Ignore storage failures.
    }
  }, theme)
  await delay(120)
}

async function inspectDomGeometry(
  page: Page,
  screen: string,
  primaryCtaSelector?: string,
): Promise<GeometrySnapshot> {
  const urlPath = safeUrlPath(page.url())
  const snap = await page.evaluate(
    ({ ctaSel }) => {
      const vp = { width: window.innerWidth, height: window.innerHeight }
      const docEl = document.documentElement
      const docScrollWidth = docEl.scrollWidth
      const docClientWidth = docEl.clientWidth
      const docOverflowX = docScrollWidth > docClientWidth + 2

      let dialogOverflowX = false
      let dialogOutOfViewport = false
      const dlg = document.querySelector('[role="dialog"]') as HTMLElement | null
      if (dlg) {
        const rect = dlg.getBoundingClientRect()
        if (dlg.scrollWidth > dlg.clientWidth + 2) dialogOverflowX = true
        if (rect.left < -2 || rect.top < -2 || rect.right > vp.width + 2 || rect.bottom > vp.height + 2) {
          dialogOutOfViewport = true
        }
        const body = dlg.querySelector('[data-slot="dialog-body"]') as HTMLElement | null
        if (body && body.scrollWidth > body.clientWidth + 2) dialogOverflowX = true
      }

      let clippedCardsCount = 0
      const cards = Array.from(document.querySelectorAll('[role="radio"]')) as HTMLElement[]
      for (const card of cards) {
        const r = card.getBoundingClientRect()
        if (r.width === 0 || r.height === 0) continue
        if (card.scrollWidth > card.clientWidth + 2 || card.scrollHeight > card.clientHeight + 2) {
          clippedCardsCount += 1
        }
      }

      const rawText = document.body?.innerText ?? ''
      const brokenTextMatches: string[] = []
      const patterns: Array<[string, RegExp]> = [
        ['[object Object]', /\[object Object\]/],
        ['NaN', /\bNaN\b/],
        ['undefined interpolation', /\bundefined\b(?:\s*[·•,/|]|$)/],
        ['null interpolation', /\bnull\s*[·•]/],
      ]
      for (const [label, re] of patterns) {
        if (re.test(rawText)) brokenTextMatches.push(label)
      }

      let primaryCtaAboveFold: boolean | undefined
      if (ctaSel) {
        const buttons = Array.from(document.querySelectorAll('button')) as HTMLElement[]
        const cta =
          (document.querySelector(ctaSel) as HTMLElement | null) ??
          buttons.find(b => b.textContent?.includes(ctaSel)) ??
          null
        if (cta) {
          const r = cta.getBoundingClientRect()
          primaryCtaAboveFold = r.width > 0 && r.height > 0 && r.top >= 0 && r.bottom <= vp.height + 1
        } else {
          primaryCtaAboveFold = false
        }
      }

      return {
        vp,
        docOverflowX,
        docScrollWidth,
        docClientWidth,
        dialogOverflowX,
        dialogOutOfViewport,
        clippedCardsCount,
        brokenTextMatches,
        primaryCtaAboveFold,
      }
    },
    { ctaSel: primaryCtaSelector ?? null },
  )

  const geometry: GeometrySnapshot = {
    screen,
    urlPath,
    viewport: snap.vp,
    docOverflowX: snap.docOverflowX,
    docScrollWidth: snap.docScrollWidth,
    docClientWidth: snap.docClientWidth,
    dialogOverflowX: snap.dialogOverflowX,
    dialogOutOfViewport: snap.dialogOutOfViewport,
    clippedCardsCount: snap.clippedCardsCount,
    brokenTextMatches: snap.brokenTextMatches,
    ...(snap.primaryCtaAboveFold !== undefined ? { primaryCtaAboveFold: snap.primaryCtaAboveFold } : {}),
  }

  if (
    geometry.docOverflowX ||
    geometry.dialogOverflowX ||
    geometry.dialogOutOfViewport ||
    geometry.clippedCardsCount > 0 ||
    geometry.primaryCtaAboveFold === false
  ) {
    recordQaAnomaly({
      kind: 'layout_violation',
      routeOrOrigin: urlPath,
      summary: `Layout violation on "${screen}"`,
      detail: {
        screen,
        docOverflowX: geometry.docOverflowX,
        dialogOverflowX: geometry.dialogOverflowX,
        dialogOutOfViewport: geometry.dialogOutOfViewport,
        clippedCardsCount: geometry.clippedCardsCount,
        ...(geometry.primaryCtaAboveFold !== undefined ? { primaryCtaAboveFold: geometry.primaryCtaAboveFold } : {}),
      },
    })
  }

  return geometry
}

// ---------------------------------------------------------------------------
// Journey state & helpers
// ---------------------------------------------------------------------------

interface HarnessState {
  projectId: string
  runId: string
  workspaceId: string
  seededAssignmentId: string
  seededApprovalId: string
  shotSeq: number
  screenshots: ScreenshotRecord[]
}

async function captureScreen(
  page: Page,
  outDir: string,
  state: HarnessState,
  opts: {
    journey: number
    slug: string
    label: string
    theme?: 'light' | 'dark'
    primaryCtaSelector?: string
  },
): Promise<ScreenshotRecord> {
  state.shotSeq += 1
  const prefix = String(state.shotSeq).padStart(2, '0')
  const file = `${prefix}-${opts.slug}.png`
  const theme = opts.theme ?? 'light'
  const geometry = await inspectDomGeometry(page, opts.label, opts.primaryCtaSelector)
  await page.screenshot({ path: join(outDir, file), fullPage: false })
  const rec: ScreenshotRecord = {
    file,
    journey: opts.journey,
    label: opts.label,
    urlPath: geometry.urlPath,
    theme,
    geometry,
  }
  state.screenshots.push(rec)
  return rec
}

async function bootstrapAndCreateProject(
  page: Page,
  kovo: SpawnedKovoServer,
  saas: MockMultiOriginSaas,
  state: HarnessState,
): Promise<void> {
  if (state.projectId) return

  await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
    waitUntil: 'domcontentloaded',
  })
  await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })

  await page.getByLabel('Project name').fill('QA Dogfood Multi-Origin SaaS')
  await page.getByLabel('Sites').fill(`${saas.appOrigin}\n${saas.idpOrigin}`)
  await page.getByRole('button', { name: /Advanced configuration/ }).click()
  await page.getByLabel('Target environment').selectOption('local-lab')
  await page.getByRole('button', { name: 'Create project', exact: true }).click()

  await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
  const match = /\/projects\/([a-f0-9-]+)/.exec(page.url())
  if (!match?.[1]) throw new Error(`Expected project URL after creation, got ${page.url()}`)
  state.projectId = match[1]

  const wsRow = withSqlite(kovo.dataDir, db =>
    db.prepare('SELECT workspace_id AS workspaceId FROM projects WHERE id = ?').get(state.projectId) as
      | { workspaceId: string }
      | undefined,
  )
  state.workspaceId = wsRow?.workspaceId ?? ''
}

function seed25InventoryHosts(kovo: SpawnedKovoServer, projectId: string): number {
  const hostPrefixes = [
    'api', 'app', 'auth', 'admin', 'billing',
    'dashboard', 'portal', 'graphql', 'gateway', 'accounts',
    'docs', 'status', 'cdn', 'assets', 'files',
    'webhooks', 'events', 'search', 'notifications', 'analytics',
    'staging-api', 'staging-app', 'preview-101', 'partners', 'support',
  ]
  return withSqlite(kovo.dataDir, db => {
    const existing = db
      .prepare('SELECT COUNT(*) AS cnt FROM project_assets WHERE project_id = ?')
      .get(projectId) as { cnt: number }
    const insert = db.prepare(`
      INSERT OR IGNORE INTO project_assets (
        id, project_id, origin, source, third_party, include_subdomains
      ) VALUES (?, ?, ?, ?, ?, 0)
    `)
    const needed = Math.max(0, 25 - existing.cnt)
    for (let i = 0; i < hostPrefixes.length && i < needed; i += 1) {
      const sub = hostPrefixes[i]!
      const thirdParty = sub === 'cdn' || sub === 'analytics' ? 1 : 0
      insert.run(
        randomUUID(),
        projectId,
        `https://${sub}.acme-dogfood.local`,
        thirdParty ? 'subdomain_discovery' : 'phase0_subdomain_discovery',
        thirdParty,
      )
    }
    const finalCount = db
      .prepare('SELECT COUNT(*) AS cnt FROM project_assets WHERE project_id = ?')
      .get(projectId) as { cnt: number }
    return finalCount.cnt
  })
}

function seedRunArtifactsForNavigationAndQueue(
  kovo: SpawnedKovoServer,
  saas: MockMultiOriginSaas,
  state: HarnessState,
): void {
  const now = Date.now()
  const assignmentId = randomUUID()
  const approvalId = randomUUID()
  const leaseId = randomUUID()
  const exchangeId = randomUUID()
  const findingId = randomUUID()
  const reportId = randomUUID()

  state.seededAssignmentId = assignmentId
  state.seededApprovalId = approvalId

  withSqlite(kovo.dataDir, db => {
    const runRow = db
      .prepare('SELECT workspace_id AS workspaceId, scope_revision AS scopeRevision, goal_revision AS goalRevision, candidates FROM runs WHERE id = ?')
      .get(state.runId) as { workspaceId: string; scopeRevision: number; goalRevision: number; candidates: string }
    const candidates = JSON.parse(runRow.candidates || '[]') as Array<{ id: string; origin: string }>
    const primaryAsset = candidates.find(c => c.origin === saas.appOrigin) ?? candidates[0]
    const assetId = primaryAsset?.id ?? randomUUID()
    const scopeRev = runRow.scopeRevision || 1
    const goalRev = runRow.goalRevision || 1

    // Transition run into active investigation so Workflow, Queue, Findings, Report, and Leases render fully.
    db.prepare(`UPDATE runs SET phase = 'investigation', status = 'running', scope_revision = ?, spent_requests = 42, turns_used = 4 WHERE id = ?`)
      .run(scopeRev, state.runId)

    db.prepare(`
      INSERT INTO assignments (
        id, run_id, asset_id, phase, status, scope_revision, goal_revision, session_id,
        attempt, max_turns, turns_used, requests_used, parent_fact_ids, source_origins,
        title, objective, outcome, created_at
      ) VALUES (?, ?, ?, 'investigation', 'complete', ?, ?, ?, 1, 50, 4, 18, '[]', ?, 'Auth & Profile Surface Audit', 'Verify redirect chain, session cookie scoping, and profile access controls', 'Completed baseline and profile boundary verification', ?)
    `).run(assignmentId, state.runId, assetId, scopeRev, goalRev, `sess-${assignmentId.slice(0, 8)}`, JSON.stringify([saas.appOrigin]), now - 9_000)

    db.prepare(`
      INSERT INTO broker_exchanges (
        id, run_id, assignment_id, scope_revision, origin, final_origin, redirect_origins,
        method, path_and_query, persona_handle, status, media_type, req_headers, resp_headers,
        body_preview, body_sha256, secret_matches, duration_ms, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, '[]', 'GET', '/api/profile', 'user-a', 200, 'application/json', '{}', '{}', ?, ?, '[]', 18, ?)
    `).run(exchangeId, state.runId, assignmentId, scopeRev, saas.appOrigin, saas.appOrigin, '{"id":"usr_qa_01","role":"workspace_admin"}', 'qa-sha256-profile', now - 7_000)

    const findingPayload = {
      id: findingId,
      origin: saas.appOrigin,
      title: 'Missing Strict-Transport-Security header on portal entry',
      status: 'confirmed',
      severity: 'low',
      category: 'crypto-tls-transport',
      verificationTier: 'baseline_confirmed',
      findingKind: 'baseline_check',
      reason: 'GET /portal responded without a Strict-Transport-Security header.',
      remediation: 'Emit Strict-Transport-Security with max-age>=31536000 on HTTPS responses.',
      evidenceIds: [],
      exchangeIds: [exchangeId],
      scopeRevision: scopeRev,
    }

    db.prepare(`
      INSERT INTO findings (
        id, run_id, asset_id, goal_revision, check_id, case_id, finding_kind,
        provenance, verification_class, source_origins, verification_tier, finding
      ) VALUES (?, ?, ?, ?, 'hsts', 'portal-hsts', 'baseline_check', 'floor', 'runtime_confirmed', ?, 'baseline_confirmed', ?)
    `).run(findingId, state.runId, assetId, goalRev, JSON.stringify([saas.appOrigin]), JSON.stringify(findingPayload))

    // Pending approval request for Journey 4 (Approval Queue interaction).
    db.prepare(`
      INSERT INTO approval_requests (
        id, run_id, assignment_id, scope_revision, origin, method, path_and_query,
        persona_handle, rationale, request_preview, status, risk_level, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, 'POST', '/api/profile/preferences', 'user-a', ?, ?, 'pending', 'medium', ?, ?)
    `).run(
      approvalId,
      state.runId,
      assignmentId,
      scopeRev,
      saas.appOrigin,
      'Verify whether preference updates enforce per-user ownership checks.',
      'POST /api/profile/preferences {"theme":"dark"}',
      now + 15 * 60_000,
      now - 2_000,
    )

    // Pre-existing active approval lease so Leases popover shows grants cleanly.
    db.prepare(`
      INSERT INTO approval_leases (
        id, run_id, scope_revision, origin, method, route_pattern, persona_handle,
        status, created_by, created_at, updated_at, expires_at, uses
      ) VALUES (?, ?, ?, ?, 'POST', '/api/projects/*', 'user-a', 'active', 'operator', ?, ?, ?, 1)
    `).run(leaseId, state.runId, scopeRev, saas.appOrigin, now - 6_000, now - 6_000, now + 60 * 60_000)

    // Report snapshot so the Report view renders structured content cleanly.
    const reportBody = {
      goal: 'Autonomous QA dogfooding run across Acme multi-origin SaaS.',
      capabilityTier: 3,
      scope: candidates,
      scopeRevision: scopeRev,
      goalRevision: goalRev,
      threatModel: [
        {
          origin: saas.appOrigin,
          riskTier: 'high',
          surfaceTags: ['sso', 'api', 'session-cookie'],
          rationale: 'Primary authenticated SaaS origin behind 308 redirect and cross-port IdP.',
        },
      ],
      summary: 'Dogfooding verification confirmed authenticated profile access and baseline header posture.',
    }
    db.prepare(`
      INSERT INTO reports (id, run_id, version, partial, body, created_at)
      VALUES (?, ?, 1, 1, ?, ?)
    `).run(reportId, state.runId, JSON.stringify(reportBody), now - 1_000)
  })
}

// ---------------------------------------------------------------------------
// Main execution
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const opts = parseCliArgs(process.argv.slice(2))
  if (opts.help) {
    console.log('Usage: node scripts/qa-dogfood.ts [--out-dir <dir>] [--journey=all|1|2|3|4|5]')
    process.exit(0)
  }

  process.env.KOVO_QA_ANOMALIES = '1'
  clearQaAnomalies()
  await mkdir(opts.outDir, { recursive: true })

  const startedAtMs = Date.now()
  const startedAt = new Date(startedAtMs).toISOString()

  ensureBuilt()
  const { pw, executablePath } = await loadPlaywright()
  const saas = await startMockMultiOriginSaas()
  const kovo = await startIsolatedKovoServer()

  const consoleErrors: Array<{ ts: number; urlPath: string; text: string }> = []
  const pageErrors: Array<{ ts: number; urlPath: string; message: string }> = []
  const failedRequests: Array<{ ts: number; method: string; urlPath: string; status: number | null; reason: string }> = []
  const journeyReports: JourneyReport[] = []
  const state: HarnessState = {
    projectId: '',
    runId: '',
    workspaceId: '',
    seededAssignmentId: '',
    seededApprovalId: '',
    shotSeq: 0,
    screenshots: [],
  }

  let browser: Browser | undefined
  let context: BrowserContext | undefined
  let page: Page | undefined

  try {
    browser = await pw.chromium.launch({
      headless: true,
      executablePath,
      args: ['--no-sandbox'],
    })
    context = await browser.newContext({ viewport: { ...VIEWPORT } })
    page = await context.newPage()

    page.on('console', msg => {
      if (msg.type() === 'error') {
        const text = msg.text()
        const urlPath = safeUrlPath(page?.url() ?? '/')
        consoleErrors.push({ ts: Date.now(), urlPath, text })
        recordQaAnomaly({
          kind: 'ui_console_error',
          routeOrOrigin: urlPath,
          summary: text,
        })
      }
    })

    page.on('pageerror', err => {
      const message = err instanceof Error ? err.message : String(err)
      const urlPath = safeUrlPath(page?.url() ?? '/')
      pageErrors.push({ ts: Date.now(), urlPath, message })
      recordQaAnomaly({
        kind: 'ui_console_error',
        routeOrOrigin: urlPath,
        summary: `Unhandled pageerror: ${message}`,
      })
    })

    page.on('response', res => {
      if (res.status() >= 400) {
        const urlPath = safeUrlPath(res.url())
        failedRequests.push({
          ts: Date.now(),
          method: res.request().method(),
          urlPath,
          status: res.status(),
          reason: res.statusText() || `HTTP ${res.status()}`,
        })
        if (urlPath.startsWith('/_serverFn') || urlPath.startsWith('/api/') || urlPath.startsWith('/_kovo/')) {
          recordQaAnomaly({
            kind: 'unexpected_ui_rpc_error',
            routeOrOrigin: urlPath,
            summary: `${res.request().method()} ${urlPath} returned HTTP ${res.status()}`,
            detail: { method: res.request().method(), statusCode: res.status() },
          })
        }
      }
    })

    page.on('requestfailed', req => {
      const reason = req.failure()?.errorText ?? 'requestfailed'
      // Ignore normal EventSource/navigation aborts on page transitions.
      if (reason.includes('ERR_ABORTED')) return
      const urlPath = safeUrlPath(req.url())
      failedRequests.push({
        ts: Date.now(),
        method: req.method(),
        urlPath,
        status: null,
        reason,
      })
    })

    const runJourney = async (journey: number, name: string, fn: (checks: string[]) => Promise<void>) => {
      const t0 = Date.now()
      const checks: string[] = []
      try {
        await fn(checks)
        journeyReports.push({
          journey,
          name,
          status: 'passed',
          durationMs: Date.now() - t0,
          checks,
        })
      } catch (err) {
        journeyReports.push({
          journey,
          name,
          status: 'failed',
          durationMs: Date.now() - t0,
          checks,
          error: err instanceof Error ? err.message : String(err),
        })
      }
    }

    // -----------------------------------------------------------------------
    // Journey 1: Project creation + 25-host Inventory seed + all 6 project tabs
    // -----------------------------------------------------------------------
    if (opts.journeys.has(1)) {
      await runJourney(1, 'Project creation + 25-host Inventory seed + 6 project tabs', async checks => {
        await page!.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
          waitUntil: 'domcontentloaded',
        })
        await page!.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
        await captureScreen(page!, opts.outDir, state, {
          journey: 1,
          slug: 'projects-home',
          label: 'Projects landing page',
        })
        checks.push('Bootstrapped local session and opened Projects page')

        await page!.getByLabel('Project name').fill('QA Dogfood Multi-Origin SaaS')
        await page!.getByLabel('Sites').fill(`${saas.appOrigin}\n${saas.idpOrigin}`)
        await page!.getByRole('button', { name: /Advanced configuration/ }).click()
        await page!.getByLabel('Target environment').selectOption('local-lab')
        await page!.getByRole('button', { name: 'Create project', exact: true }).click()

        await page!.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
        const match = /\/projects\/([a-f0-9-]+)/.exec(page!.url())
        if (!match?.[1]) throw new Error(`Expected project URL, got ${page!.url()}`)
        state.projectId = match[1]
        checks.push(`Created project ${state.projectId}`)

        const totalHosts = seed25InventoryHosts(kovo, state.projectId)
        if (totalHosts < 25) throw new Error(`Expected >= 25 inventory hosts, got ${totalHosts}`)
        await page!.reload({ waitUntil: 'domcontentloaded' })
        checks.push(`Seeded ${totalHosts} inventory hosts`)

        const tabs: Array<[string, string]> = [
          ['Overview', 'project-overview'],
          ['Runs', 'project-runs'],
          ['Inventory', 'inventory'],
          ['Test Accounts', 'project-personas'],
          ['Source & Specs', 'project-sources'],
          ['Guardrails & Lab', 'project-guardrails'],
        ]
        for (const [tabLabel, slug] of tabs) {
          const tab = page!.getByRole('tab', { name: new RegExp(`^${tabLabel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`) })
          await tab.waitFor({ state: 'visible', timeout: 10_000 })
          await tab.click()
          await delay(250)
          await captureScreen(page!, opts.outDir, state, {
            journey: 1,
            slug,
            label: `Project tab: ${tabLabel}`,
          })
          checks.push(`Visited project tab "${tabLabel}"`)
        }
      })
    }

    // -----------------------------------------------------------------------
    // Journey 2: Add Test Account dialog (light + dark) + interactive Sign-In Browser + Verify sign-in
    // -----------------------------------------------------------------------
    if (opts.journeys.has(2)) {
      await runJourney(2, 'Add Test Account (light + dark) + Interactive Sign-In Browser + Verify sign-in', async checks => {
        await bootstrapAndCreateProject(page!, kovo, saas, state)
        await page!.goto(`${kovo.origin}/projects/${state.projectId}?tab=personas`, { waitUntil: 'domcontentloaded' })
        await page!.getByRole('button', { name: 'Add test account', exact: true }).waitFor({ state: 'visible', timeout: 15_000 })
        await page!.getByRole('button', { name: 'Add test account', exact: true }).click()

        const dialog = page!.getByRole('dialog')
        await dialog.waitFor({ state: 'visible', timeout: 10_000 })
        await dialog.getByRole('heading', { name: 'Add test account' }).waitFor({ state: 'visible', timeout: 5_000 })

        // Capture light mode dialog
        await setPageTheme(page!, 'light')
        await captureScreen(page!, opts.outDir, state, {
          journey: 2,
          slug: 'personas-modal-light',
          label: 'Add test account modal (light)',
          theme: 'light',
          primaryCtaSelector: 'button[type="submit"]',
        })
        checks.push('Captured Add Test Account modal in light mode')

        // Capture dark mode dialog, then restore light mode
        await setPageTheme(page!, 'dark')
        await captureScreen(page!, opts.outDir, state, {
          journey: 2,
          slug: 'personas-modal-dark',
          label: 'Add test account modal (dark)',
          theme: 'dark',
          primaryCtaSelector: 'button[type="submit"]',
        })
        await setPageTheme(page!, 'light')
        checks.push('Captured Add Test Account modal in dark mode')

        // Launch live interactive Sign-In Browser
        await dialog.getByRole('button', { name: /Sign in with browser/ }).click()
        const addressBar = dialog.getByRole('textbox', { name: 'Browser address bar' })
        await addressBar.waitFor({ state: 'visible', timeout: 20_000 })
        await delay(900) // Allow 308 redirect hop (`/` -> `/portal`) and initial CDP screencast frame.

        await captureScreen(page!, opts.outDir, state, {
          journey: 2,
          slug: 'signin-browser-landing',
          label: 'Interactive Sign-In Browser after 308 redirect',
        })
        checks.push(`Interactive Sign-In Browser opened (308 redirect hits: ${saas.redirect308Hits})`)

        // Navigate to cross-port IdP login via the embedded address bar, then complete SSO callback to mint session cookies.
        await addressBar.click()
        await page!.keyboard.press('Control+A')
        await addressBar.fill(`${saas.idpOrigin}/login`)
        await page!.keyboard.press('Enter')
        await delay(900)

        await captureScreen(page!, opts.outDir, state, {
          journey: 2,
          slug: 'signin-browser-idp',
          label: 'Interactive Sign-In Browser on cross-port IdP',
        })

        // Trigger IdP completion redirect (`/complete-sso` -> `302 /auth/callback?ticket=...` -> `302 /portal` with cookies).
        await addressBar.click()
        await page!.keyboard.press('Control+A')
        await addressBar.fill(`${saas.idpOrigin}/complete-sso`)
        await page!.keyboard.press('Enter')
        await delay(1_200)

        await captureScreen(page!, opts.outDir, state, {
          journey: 2,
          slug: 'signin-browser-authed',
          label: 'Interactive Sign-In Browser signed in on portal',
        })
        checks.push(`Completed cross-port IdP sign-in (IdP hits: ${saas.idpLoginHits})`)

        // Complete interactive session capture
        await dialog.getByRole('button', { name: /I'm signed in — capture session/ }).click()
        await dialog.getByText(/Captured \d+ cookie/).waitFor({ state: 'visible', timeout: 15_000 })
        checks.push('Captured live browser session cookies')

        // Save test account
        await dialog.getByRole('button', { name: 'Save test account', exact: true }).click()
        await dialog.waitFor({ state: 'hidden', timeout: 15_000 })

        const personasSection = page!.getByRole('region', { name: 'Test accounts' })
        const verifyBtn = personasSection.getByRole('button', { name: 'Verify sign-in', exact: true })
        await verifyBtn.waitFor({ state: 'visible', timeout: 10_000 })
        await verifyBtn.click()
        await personasSection.getByRole('button', { name: 'Verify sign-in ✓', exact: true }).waitFor({
          state: 'visible',
          timeout: 20_000,
        })
        await captureScreen(page!, opts.outDir, state, {
          journey: 2,
          slug: 'persona-verified',
          label: 'Test account verified (HTTP 200)',
        })
        checks.push('Verified captured browser session with Verify sign-in ✓')

        // Also confirm protected `/api/profile` rejects anonymous and accepts valid session cookie.
        const unauthProfile = await fetch(`${saas.appOrigin}/api/profile`)
        const authedProfile = await fetch(`${saas.appOrigin}/api/profile`, {
          headers: { cookie: `saas_session=${saas.validSessionToken}` },
        })
        if (unauthProfile.status !== 401 || authedProfile.status !== 200) {
          throw new Error(`Expected /api/profile 401/200, got ${unauthProfile.status}/${authedProfile.status}`)
        }
        checks.push('Confirmed protected /api/profile returns 401 anon / 200 authenticated')
      })
    }

    // -----------------------------------------------------------------------
    // Journey 3: New Run -> Scope Review (`Approve & start` above fold) -> Run views
    // -----------------------------------------------------------------------
    if (opts.journeys.has(3)) {
      await runJourney(3, 'New Run -> Scope Review (Approve & start above fold) -> Run views', async checks => {
        await bootstrapAndCreateProject(page!, kovo, saas, state)
        await page!.goto(`${kovo.origin}/projects/${state.projectId}`, { waitUntil: 'domcontentloaded' })
        await page!.getByRole('button', { name: 'New run', exact: true }).waitFor({ state: 'visible', timeout: 15_000 })
        await page!.getByRole('button', { name: 'New run', exact: true }).click()

        const dialog = page!.getByRole('dialog')
        await dialog.waitFor({ state: 'visible', timeout: 10_000 })
        await captureScreen(page!, opts.outDir, state, {
          journey: 3,
          slug: 'new-run-sheet',
          label: 'New Run sheet',
          primaryCtaSelector: 'Start run',
        })
        checks.push('Opened New Run dialog')

        await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
        await page!.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 })
        const match = /\/runs\/([a-f0-9-]+)/.exec(page!.url())
        if (!match?.[1]) throw new Error(`Expected run URL, got ${page!.url()}`)
        state.runId = match[1]

        await page!.getByRole('button', { name: /Approve & start/ }).waitFor({ state: 'visible', timeout: 15_000 })
        const scopeShot = await captureScreen(page!, opts.outDir, state, {
          journey: 3,
          slug: 'scope-review',
          label: 'Run Scope Review (Approve & start above fold)',
          primaryCtaSelector: 'Approve & start',
        })
        if (scopeShot.geometry.primaryCtaAboveFold !== true) {
          throw new Error('Scope Review primary CTA "Approve & start" was NOT visible above the fold at 1280×720')
        }
        checks.push(`Verified Scope Review "Approve & start" above the fold for run ${state.runId}`)

        // Seed realistic active run artifacts so all run navigation views render substantive state.
        seedRunArtifactsForNavigationAndQueue(kovo, saas, state)
        await page!.reload({ waitUntil: 'domcontentloaded' })
        await delay(500)

        // Overview
        await captureScreen(page!, opts.outDir, state, {
          journey: 3,
          slug: 'run-overview',
          label: 'Run Overview',
        })
        checks.push('Navigated to Run Overview')

        // Workflow (supports both top-level Investigation nav and legacy Telemetry group)
        const directWorkflowBtn = page!.getByRole('button', { name: /^Workflow\b/ }).first()
        if (await directWorkflowBtn.isVisible().catch(() => false)) {
          await directWorkflowBtn.click()
        } else {
          const telemetryToggle = page!.getByRole('button', { name: /^Telemetry/ })
          await telemetryToggle.waitFor({ state: 'visible', timeout: 10_000 })
          if ((await telemetryToggle.getAttribute('aria-expanded')) !== 'true') {
            await telemetryToggle.click()
          }
          const telemetryNav = page!.getByRole('navigation', { name: 'Telemetry views' })
          await telemetryNav.getByRole('button', { name: /^Workflow/ }).click()
        }
        await delay(350)
        await captureScreen(page!, opts.outDir, state, {
          journey: 3,
          slug: 'run-workflow',
          label: 'Run Workflow view',
        })
        checks.push('Navigated to Run Workflow')

        // Investigation views: Queue, Findings, Report
        for (const [viewLabel, slug] of [
          ['Queue', 'run-queue'],
          ['Findings', 'run-findings'],
          ['Report', 'run-report'],
        ] as const) {
          await page!.getByRole('button', { name: new RegExp(`^${viewLabel}\\b`) }).first().click()
          await delay(350)
          await captureScreen(page!, opts.outDir, state, {
            journey: 3,
            slug,
            label: `Run ${viewLabel} view`,
          })
          checks.push(`Navigated to Run ${viewLabel}`)
        }
      })
    }

    // -----------------------------------------------------------------------
    // Journey 4: Approval Queue interaction + Leases popover
    // -----------------------------------------------------------------------
    if (opts.journeys.has(4)) {
      await runJourney(4, 'Approval Queue interaction + Leases popover', async checks => {
        if (!state.runId) {
          await bootstrapAndCreateProject(page!, kovo, saas, state)
          await page!.goto(`${kovo.origin}/projects/${state.projectId}`, { waitUntil: 'domcontentloaded' })
          await page!.getByRole('button', { name: 'New run', exact: true }).click()
          const dlg = page!.getByRole('dialog')
          await dlg.waitFor({ state: 'visible', timeout: 10_000 })
          await dlg.getByRole('button', { name: 'Start run', exact: true }).click()
          await page!.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 })
          state.runId = /\/runs\/([a-f0-9-]+)/.exec(page!.url())?.[1] ?? ''
          seedRunArtifactsForNavigationAndQueue(kovo, saas, state)
        }

        await page!.goto(`${kovo.origin}/runs/${state.runId}?view=queue`, { waitUntil: 'domcontentloaded' })
        await delay(500)

        // Click the pending approval row if present and interact with approval button.
        const approvalText = page!.getByText('/api/profile/preferences').first()
        await approvalText.waitFor({ state: 'visible', timeout: 10_000 })
        await approvalText.click()
        await delay(300)

        await captureScreen(page!, opts.outDir, state, {
          journey: 4,
          slug: 'approval-queue-open',
          label: 'Approval Queue with pending request',
        })
        checks.push('Opened Approval Queue and inspected pending approval card')

        const approveBtn = page!.getByRole('button', { name: /Approve route|Approve once/ }).first()
        if (await approveBtn.isVisible().catch(() => false)) {
          await approveBtn.click()
          await delay(500)
          checks.push('Interacted with Approval Queue primary approval action')
        }

        await captureScreen(page!, opts.outDir, state, {
          journey: 4,
          slug: 'approval-queue-decided',
          label: 'Approval Queue after decision',
        })

        // Open Leases popover from RunHeader (directly on run-line or via "More actions" overflow menu at 1280px).
        const leasesBtn = page!.getByRole('button', { name: /^Leases/ }).first()
        if (await leasesBtn.isVisible().catch(() => false)) {
          await leasesBtn.click()
        } else {
          await page!.getByRole('button', { name: 'More actions', exact: true }).click()
          const menuLeasesItem = page!.getByRole('menu').getByRole('button', { name: /Approval leases/ }).first()
          await menuLeasesItem.waitFor({ state: 'visible', timeout: 5_000 })
          await menuLeasesItem.click()
        }
        await delay(300)

        const leasesDialog = page!.getByRole('dialog').first()
        await leasesDialog.waitFor({ state: 'visible', timeout: 5_000 })
        await captureScreen(page!, opts.outDir, state, {
          journey: 4,
          slug: 'leases-popover',
          label: 'Run Header Leases popover',
        })
        checks.push('Opened and inspected Leases popover')
      })
    }

    // -----------------------------------------------------------------------
    // Journey 5: Settings & Devices modal check
    // -----------------------------------------------------------------------
    if (opts.journeys.has(5)) {
      await runJourney(5, 'Settings & Devices modal check', async checks => {
        if (!state.projectId) {
          await page!.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
            waitUntil: 'domcontentloaded',
          })
          await page!.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
        }

        await page!.goto(`${kovo.origin}/settings`, { waitUntil: 'domcontentloaded' })
        await page!.getByRole('heading', { name: 'Settings', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
        await captureScreen(page!, opts.outDir, state, {
          journey: 5,
          slug: 'settings-page',
          label: 'Settings page',
        })
        checks.push('Opened /settings page')

        const statusResPromise = page!.waitForResponse(
          res => safeUrlPath(res.url()) === '/_kovo/auth/status' && res.request().method() === 'GET',
          { timeout: 10_000 },
        )
        await page!.getByRole('button', { name: /Local session/ }).click()
        const statusRes = await statusResPromise
        if (statusRes.status() !== 200) {
          throw new Error(`Expected /_kovo/auth/status 200, got ${statusRes.status()}`)
        }

        const devicesDialog = page!.getByRole('dialog')
        await devicesDialog.waitFor({ state: 'visible', timeout: 10_000 })
        await devicesDialog.getByRole('heading', { name: 'Devices & local session' }).waitFor({ state: 'visible', timeout: 5_000 })
        await devicesDialog.getByText('Active', { exact: true }).waitFor({ state: 'visible', timeout: 10_000 })
        await captureScreen(page!, opts.outDir, state, {
          journey: 5,
          slug: 'devices-modal',
          label: 'Devices & local session modal',
        })
        checks.push('Opened Devices & local session modal and verified /_kovo/auth/status 200')

        await devicesDialog.getByRole('button', { name: 'Close', exact: true }).click()
        await devicesDialog.waitFor({ state: 'hidden', timeout: 5_000 })
      })
    }

    // Run Move 4 post-completion anomaly inspector against the run DB state if a run was created.
    if (state.runId) {
      withSqlite(kovo.dataDir, db => {
        const runRow = db
          .prepare('SELECT id, status, phase, candidates FROM runs WHERE id = ?')
          .get(state.runId) as { id: string; status: string; phase: string; candidates: string } | undefined
        if (!runRow) return
        const asgRows = db
          .prepare('SELECT id, status, phase, title, source_origins AS sourceOrigins FROM assignments WHERE run_id = ?')
          .all(state.runId) as Array<{ id: string; status: string; phase: string; title: string; sourceOrigins: string }>
        const findingRows = db
          .prepare('SELECT id, verification_tier AS verificationTier, verification_class AS verificationClass, finding_kind AS findingKind, superseded_by_finding_id AS supersededByFindingId, finding FROM findings WHERE run_id = ?')
          .all(state.runId) as Array<{
            id: string
            verificationTier: string | null
            verificationClass: string | null
            findingKind: string | null
            supersededByFindingId: string | null
            finding: string
          }>
        inspectRunPostCompletionAnomalies(
          {
            id: runRow.id,
            status: runRow.status,
            phase: runRow.phase,
            candidates: JSON.parse(runRow.candidates || '[]') as Array<{ origin: string }>,
          },
          asgRows.map(a => ({
            id: a.id,
            status: a.status,
            phase: a.phase,
            title: a.title,
            sourceOrigins: JSON.parse(a.sourceOrigins || '[]') as string[],
          })),
          findingRows.map(f => {
            const parsed = JSON.parse(f.finding || '{}') as { status?: string; origin?: string }
            return {
              id: f.id,
              status: parsed.status ?? null,
              origin: parsed.origin ?? null,
              verificationTier: f.verificationTier,
              verificationClass: f.verificationClass,
              findingKind: f.findingKind,
              supersededByFindingId: f.supersededByFindingId,
            }
          }),
        )
      })
    }
  } finally {
    if (context) await context.close().catch(() => {})
    if (browser) await browser.close().catch(() => {})
    await kovo.stop().catch(() => {})
    await saas.close().catch(() => {})
  }

  const finishedAtMs = Date.now()
  const anomalies = listQaAnomalies()
  const anomaliesByKind = Object.fromEntries(
    qaAnomalyKinds.map(kind => [kind, anomalies.filter(a => a.kind === kind).length]),
  ) as Record<QaAnomalyKind, number>
  const geometryViolationsCount = state.screenshots.filter(
    s =>
      s.geometry.docOverflowX ||
      s.geometry.dialogOverflowX ||
      s.geometry.dialogOutOfViewport ||
      s.geometry.clippedCardsCount > 0 ||
      s.geometry.primaryCtaAboveFold === false,
  ).length
  const brokenTextViolationsCount = state.screenshots.reduce(
    (sum, s) => sum + s.geometry.brokenTextMatches.length,
    0,
  )

  const report: DogfoodReport = {
    startedAt,
    finishedAt: new Date(finishedAtMs).toISOString(),
    durationMs: finishedAtMs - startedAtMs,
    viewport: { ...VIEWPORT },
    outDir: opts.outDir,
    targetFixtures: {
      appOrigin: saas.appOrigin,
      idpOrigin: saas.idpOrigin,
      redirect308Hits: saas.redirect308Hits,
      idpLoginHits: saas.idpLoginHits,
      profileAuthedHits: saas.profileAuthedHits,
    },
    summary: {
      journeysTotal: journeyReports.length,
      journeysPassed: journeyReports.filter(j => j.status === 'passed').length,
      journeysFailed: journeyReports.filter(j => j.status === 'failed').length,
      screenshotsCaptured: state.screenshots.length,
      anomaliesCount: anomalies.length,
      consoleErrorsCount: consoleErrors.length,
      pageErrorsCount: pageErrors.length,
      failedRequestsCount: failedRequests.length,
      geometryViolationsCount,
      brokenTextViolationsCount,
    },
    qaAnomaliesConfig: {
      enabled: isQaAnomaliesEnabled(),
      maxEntries: QA_ANOMALIES_MAX_ENTRIES,
      byKind: anomaliesByKind,
    },
    journeys: journeyReports,
    screenshots: state.screenshots,
    anomalies,
    consoleErrors,
    pageErrors,
    failedRequests,
  }

  const reportPath = join(opts.outDir, 'dogfood-report.json')
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8')

  console.log(
    JSON.stringify(
      {
        reportPath,
        summary: report.summary,
        journeys: report.journeys.map(j => ({
          journey: j.journey,
          name: j.name,
          status: j.status,
          durationMs: j.durationMs,
          ...(j.error ? { error: j.error } : {}),
        })),
      },
      null,
      2,
    ),
  )

  if (report.summary.journeysFailed > 0 || report.summary.pageErrorsCount > 0) {
    process.exitCode = 1
  }
}

void main().catch(err => {
  console.error(err instanceof Error ? err.stack || err.message : String(err))
  process.exit(1)
})
