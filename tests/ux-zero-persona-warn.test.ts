import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { stripTypeScriptTypes } from 'node:module'
import type { Browser, BrowserContext, Page } from '@playwright/test'
import { HARDENED_NODE_FLAGS } from './app.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CONSENT_PATH = join(REPO_ROOT, 'src', 'components', 'run', 'views', 'consent.tsx')

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
  if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
  for (const candidate of SYSTEM_CHROMIUM_CANDIDATES) {
    if (existsSync(candidate)) return { pw, executablePath: candidate }
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

function ensureBuilt(): void {
  const serverEntry = resolve(REPO_ROOT, 'build/server/server.js')
  const clientDir = resolve(REPO_ROOT, 'build/client')
  if (existsSync(serverEntry) && existsSync(clientDir)) return
  execFileSync('npm', ['run', 'build'], { cwd: REPO_ROOT, stdio: 'pipe' })
}

interface SpawnedKovoServer {
  origin: string
  dataDir: string
  bootstrapSecret: string
  stop(): Promise<void>
}

async function startKovoServer(): Promise<SpawnedKovoServer> {
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-zero-persona-warn-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, [...HARDENED_NODE_FLAGS, 'scripts/serve.ts'], {
    cwd: REPO_ROOT,
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

  return { origin, dataDir, bootstrapSecret, stop }
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

function build27Candidates() {
  const prefixes = [
    'app', 'api', 'auth', 'admin', 'billing', 'portal', 'console', 'graphql', 'gateway',
    'accounts', 'sso', 'docs', 'status', 'dashboard', 'webhooks', 'files', 'media', 'cdn',
    'staging', 'beta', 'sandbox', 'internal', 'metrics', 'support',
  ]
  const thirdPartyPrefixes = [
    { sub: 'mail', cname: 'sendgrid.net' },
    { sub: 'help', cname: 'acme.zendesk.com' },
    { sub: 'blog', cname: 'acme.ghost.io' },
  ]
  const out: Array<{
    id: string
    origin: string
    source: string
    thirdParty: boolean
    dnsSource?: { externalAliases: string[] }
  }> = []
  prefixes.forEach((sub, idx) => {
    out.push({
      id: `cand-1p-${idx + 1}`,
      origin: idx === 0 ? 'https://acme-saas.example' : `https://${sub}.acme-saas.example`,
      source: idx < 3 ? 'Project seed' : 'phase0_subdomain_discovery',
      thirdParty: false,
    })
  })
  thirdPartyPrefixes.forEach((entry, idx) => {
    out.push({
      id: `cand-3p-${idx + 1}`,
      origin: `https://${entry.sub}.acme-saas.example`,
      source: 'phase0_subdomain_discovery',
      thirdParty: true,
      dnsSource: { externalAliases: [entry.cname] },
    })
  })
  return out
}

function loadConsentHelper<T>(consentSrc: string, name: string): T {
  const start = consentSrc.indexOf(`export function ${name}(`)
  assert.notEqual(start, -1, `Expected export function ${name}`)
  const openParen = consentSrc.indexOf('(', start)
  let parenDepth = 0
  let afterParams = -1
  for (let i = openParen; i < consentSrc.length; i += 1) {
    const ch = consentSrc[i]
    if (ch === '(') parenDepth += 1
    else if (ch === ')') {
      parenDepth -= 1
      if (parenDepth === 0) {
        afterParams = i + 1
        break
      }
    }
  }
  assert.notEqual(afterParams, -1)
  let depth = 0
  let bodyStart = -1
  let end = -1
  for (let i = afterParams; i < consentSrc.length; i += 1) {
    const ch = consentSrc[i]
    if (ch === '{') {
      if (depth === 0) bodyStart = i
      depth += 1
    } else if (ch === '}') {
      depth -= 1
      if (depth === 0 && bodyStart !== -1) {
        end = i + 1
        break
      }
    }
  }
  assert.notEqual(end, -1)
  const stripped = stripTypeScriptTypes(consentSrc.slice(start, end).replace(/^export\s+/, ''))
  return new Function(`${stripped}\nreturn ${name};`)() as T
}

describe('Scope Review (consent.tsx) — Pre-Run 0-Persona Warning Banner', { timeout: 90_000 }, () => {
  it('unit: shouldShowZeroPersonaWarning returns true only with 0 personas and active/authenticated tier (>= 2)', () => {
    const consentSrc = readFileSync(CONSENT_PATH, 'utf8')
    assert.doesNotMatch(consentSrc, /from ['"]node:/, 'Client component consent.tsx must have zero node:* imports')
    assert.match(consentSrc, /data-testid="consent-zero-persona-warning"/)

    const shouldShowZeroPersonaWarning = loadConsentHelper<
      (
        detail: { personas?: readonly unknown[] | null; run?: { capabilityTier?: 0 | 1 | 2 | 3 } | null },
        capabilityTier?: 0 | 1 | 2 | 3,
      ) => boolean
    >(consentSrc, 'shouldShowZeroPersonaWarning')

    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: { capabilityTier: 3 } }), true)
    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: { capabilityTier: 2 } }), true)
    assert.equal(shouldShowZeroPersonaWarning({ personas: undefined, run: { capabilityTier: 3 } }), true)
    assert.equal(shouldShowZeroPersonaWarning({ personas: null, run: { capabilityTier: 2 } }), true)

    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: { capabilityTier: 1 } }), false)
    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: { capabilityTier: 0 } }), false)
    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: {} }), false)

    assert.equal(shouldShowZeroPersonaWarning({ personas: [{ id: 'p1' }], run: { capabilityTier: 3 } }), false)
    assert.equal(shouldShowZeroPersonaWarning({ personas: [{ id: 'p1' }], run: { capabilityTier: 2 } }), false)

    // Live scan-mode override argument
    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: { capabilityTier: 3 } }, 1), false)
    assert.equal(shouldShowZeroPersonaWarning({ personas: [], run: { capabilityTier: 1 } }, 3), true)
    assert.equal(shouldShowZeroPersonaWarning({ personas: [{ id: 'p1' }], run: { capabilityTier: 1 } }, 3), false)
  })

  describe('Playwright visual, geometry & interaction verification', () => {
    let skipReason: string | null = null
    let kovo: SpawnedKovoServer | undefined
    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let page: Page | undefined
    const pageErrors: string[] = []
    let runId = ''
    let projectId = ''
    let workspaceId = ''

    before(async () => {
      const pwEnv = await loadPlaywright()
      if (!pwEnv) {
        skipReason = 'Playwright or Chromium binary unavailable in this environment'
        return
      }
      ensureBuilt()
      kovo = await startKovoServer()
      browser = await pwEnv.pw.chromium.launch({
        headless: true,
        executablePath: pwEnv.executablePath,
        args: ['--no-sandbox'],
      })
      context = await browser.newContext({ viewport: { width: 1280, height: 720 } })
      page = await context.newPage()
      page.on('pageerror', err => {
        pageErrors.push(err instanceof Error ? err.message : String(err))
      })

      // 1. Bootstrap auth & create a project with 0 personas
      await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
        waitUntil: 'domcontentloaded',
      })
      await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
      await page.getByLabel('Project name').fill('Zero Persona Scope Check')
      await page.getByLabel('Sites').fill('https://acme-saas.example\nhttps://api.acme-saas.example\nhttps://auth.acme-saas.example')
      await page.getByRole('button', { name: 'Create project', exact: true }).click()
      await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
      const projectMatch = /\/projects\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(projectMatch?.[1], `Expected project URL, got ${page.url()}`)
      projectId = projectMatch[1]

      // 2. Start a new Supervised run (lands in review/waiting)
      await page.getByRole('button', { name: 'New run', exact: true }).click()
      const dialog = page.getByRole('dialog')
      await dialog.waitFor({ state: 'visible', timeout: 10_000 })
      await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
      await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 })
      const runMatch = /\/runs\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(runMatch?.[1], `Expected run URL, got ${page.url()}`)
      runId = runMatch[1]

      // 3. Seed 27 candidates in review/waiting with 0 personas and capability_tier = 3
      const candidates = build27Candidates()
      withSqlite(kovo.dataDir, db => {
        const projRow = db.prepare('SELECT workspace_id FROM projects WHERE id = ?').get(projectId) as { workspace_id: string } | undefined
        assert.ok(projRow?.workspace_id, 'Expected project workspace_id')
        workspaceId = projRow.workspace_id
        db.prepare(
          `UPDATE runs
             SET phase = 'review',
                 status = 'waiting',
                 scope_revision = 0,
                 candidates = ?,
                 approved = '[]',
                 capability_tier = 3,
                 approval_policy = 'auto_review'
           WHERE id = ?`,
        ).run(JSON.stringify(candidates), runId)
      })
    })

    after(async () => {
      if (context) await context.close().catch(() => {})
      if (browser) await browser.close().catch(() => {})
      if (kovo) await kovo.stop().catch(() => {})
    })

    it('renders compact 0-persona warning, preserves sticky CTA above fold, links to Test Accounts, and hides when personas exist', async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Browser setup unavailable')
        return
      }

      const captureDir = process.env.KOVO_CAPTURE_ZERO_PERSONA_SHOTS_DIR
      if (captureDir) mkdirSync(captureDir, { recursive: true })

      const viewports = [
        { width: 1280, height: 720, shotName: 'consent-zero-persona-1280x720.png' },
        { width: 1440, height: 900, shotName: 'consent-zero-persona-1440x900.png' },
        { width: 1024, height: 640, shotName: null },
      ] as const

      for (const vp of viewports) {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
        await page.getByRole('heading', { name: 'Review scope', level: 1 }).waitFor({ state: 'visible', timeout: 10_000 })

        const banner = page.getByTestId('consent-zero-persona-warning')
        await banner.waitFor({ state: 'visible', timeout: 5_000 })
        const bannerText = await banner.innerText()
        assert.ok(
          bannerText.includes('No test accounts — auth, BOLA/BFLA, and race checks will only test public surfaces.'),
          `Expected exact 0-persona warning copy, got: ${bannerText}`,
        )

        const ctaLink = banner.getByRole('link', { name: 'Add test accounts →', exact: true })
        await ctaLink.waitFor({ state: 'visible', timeout: 5_000 })
        const href = await ctaLink.getAttribute('href')
        assert.equal(href, `/projects/${projectId}?tab=personas`)

        // Compact single-line geometry & zero overflow/clipping
        const bannerMetrics = await banner.evaluate(el => ({
          scrollWidth: el.scrollWidth,
          clientWidth: el.clientWidth,
          scrollHeight: el.scrollHeight,
          clientHeight: el.clientHeight,
        }))
        assert.ok(
          bannerMetrics.scrollWidth <= bannerMetrics.clientWidth + 1,
          `Warning banner must not overflow horizontally at ${vp.width}x${vp.height}: ${JSON.stringify(bannerMetrics)}`,
        )
        assert.ok(
          bannerMetrics.scrollHeight <= bannerMetrics.clientHeight + 2,
          `Warning banner text must not clip vertically at ${vp.width}x${vp.height}: ${JSON.stringify(bannerMetrics)}`,
        )

        const bannerBox = await banner.boundingBox()
        const linkBox = await ctaLink.boundingBox()
        assert.ok(bannerBox && linkBox, `Expected bounding boxes for banner and link at ${vp.width}x${vp.height}`)
        if (vp.width >= 1280) {
          assert.ok(bannerBox.height <= 36, `Warning strip should stay single-line (<=36px) at ${vp.width}x${vp.height}, got ${bannerBox.height}px`)
        }
        assert.ok(
          linkBox.x + linkBox.width <= bannerBox.x + bannerBox.width + 1,
          `CTA link must stay inside banner width at ${vp.width}x${vp.height}`,
        )

        // Zero horizontal overflow on scroll container and document
        const containerOverflow: {
          scrollWidth: number
          clientWidth: number
          docScrollWidth: number
          docClientWidth: number
        } = await page.getByTestId('consent-scroll-container').evaluate(el => {
          const docEl = el.ownerDocument.documentElement
          return {
            scrollWidth: el.scrollWidth,
            clientWidth: el.clientWidth,
            docScrollWidth: docEl.scrollWidth,
            docClientWidth: docEl.clientWidth,
          }
        })
        assert.ok(
          containerOverflow.scrollWidth <= containerOverflow.clientWidth + 1,
          `Consent scroll container must have zero horizontal overflow at ${vp.width}x${vp.height}`,
        )
        assert.ok(
          containerOverflow.docScrollWidth <= containerOverflow.docClientWidth + 1,
          `Document must have zero horizontal overflow at ${vp.width}x${vp.height}`,
        )

        // Approve & start sticky bar remains 100% visible above the fold
        const stickyBar = page.getByTestId('consent-sticky-bar')
        const approveBtn = page.getByRole('button', { name: /^Approve & start/ })
        const barBox = await stickyBar.boundingBox()
        const btnBox = await approveBtn.boundingBox()
        assert.ok(barBox && btnBox, `Expected sticky bar and Approve & start boxes at ${vp.width}x${vp.height}`)
        assert.ok(
          barBox.y >= 0 && barBox.y + barBox.height <= vp.height + 1,
          `Sticky bar must remain fully above the fold at ${vp.width}x${vp.height}`,
        )
        assert.ok(
          btnBox.y >= 0 && btnBox.y + btnBox.height <= vp.height + 1,
          `Approve & start must remain 100% visible above the fold at ${vp.width}x${vp.height}`,
        )

        if (captureDir && vp.shotName) {
          await page.screenshot({ path: join(captureDir, vp.shotName), fullPage: false })
          if (vp.width === 1280) {
            await page.evaluate(() => {
              const root = (globalThis as unknown as { document: { documentElement: { setAttribute(k: string, v: string): void } } }).document.documentElement
              root.setAttribute('data-appearance', 'dark')
              root.setAttribute('data-theme', 'dark')
            })
            await page.screenshot({ path: join(captureDir, 'consent-zero-persona-1280x720-dark.png'), fullPage: false })
            await page.evaluate(() => {
              const root = (globalThis as unknown as { document: { documentElement: { setAttribute(k: string, v: string): void } } }).document.documentElement
              root.setAttribute('data-appearance', 'light')
              root.setAttribute('data-theme', 'light')
            })
          }
        }
      }

      // Verify toggling Scan mode to Passive hides the warning, and Supervised/Autonomous restores it
      await page.setViewportSize({ width: 1280, height: 720 })
      await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
      await page.getByTestId('consent-zero-persona-warning').waitFor({ state: 'visible', timeout: 5_000 })
      await page.getByLabel('Scan mode').selectOption('passive')
      assert.equal(await page.getByTestId('consent-zero-persona-warning').count(), 0, 'Passive mode (tier 1) must hide 0-persona warning')
      await page.getByLabel('Scan mode').selectOption('autonomous')
      await page.getByTestId('consent-zero-persona-warning').waitFor({ state: 'visible', timeout: 5_000 })

      // Verify CTA link navigates directly to Test Accounts tab
      await page.getByTestId('consent-zero-persona-warning').getByRole('link', { name: 'Add test accounts →', exact: true }).click()
      await page.waitForURL(new RegExp(`/projects/${projectId}\\?tab=personas`), { timeout: 10_000 })
      await page.getByText('Test accounts (0)').waitFor({ state: 'visible', timeout: 10_000 })

      // Seed 1 persona -> reload Scope Review -> warning MUST NOT render
      withSqlite(kovo.dataDir, db => {
        db.prepare(
          `INSERT INTO personas (
            id, project_id, workspace_id, handle, role_label, origin_allowlist, auth_kind,
            header_name, login_config, credential_id, canary_markers, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          'persona-alice-1',
          projectId,
          workspaceId,
          'alice',
          'Standard user',
          JSON.stringify(['https://acme-saas.example']),
          'bearer',
          null,
          null,
          'cred-alice-1',
          JSON.stringify([]),
          Date.now(),
        )
      })
      await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
      await page.getByRole('heading', { name: 'Review scope', level: 1 }).waitFor({ state: 'visible', timeout: 10_000 })
      assert.equal(
        await page.getByTestId('consent-zero-persona-warning').count(),
        0,
        '0-persona warning MUST NOT render when >= 1 persona exists',
      )
      await page.getByText('Bind test accounts').waitFor({ state: 'visible', timeout: 5_000 })

      assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
    })
  })
})
