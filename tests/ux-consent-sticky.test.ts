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
  const dataDir = await mkdtemp(join(tmpdir(), 'kovo-consent-sticky-'))
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''

  const child: ChildProcess = spawn(process.execPath, ['scripts/serve.ts'], {
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
      origin: `https://${sub}.acme-saas.example`,
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
  assert.equal(out.length, 27)
  return out
}

function loadConsentHelper<T>(consentSrc: string, name: string, preamble = ''): T {
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
  return new Function(`${preamble}\n${stripped}\nreturn ${name};`)() as T
}

describe('Scope Review (consent.tsx) — Option 1 Sticky Action Bar & Compact Header', { timeout: 90_000 }, () => {
  it('unit: suppresses built-in preset goals, preserves custom goals, and formats live sticky summary', () => {
    const consentSrc = readFileSync(CONSENT_PATH, 'utf8')
    assert.doesNotMatch(
      consentSrc,
      /Subdomain discovery found \$\{plural\(hosts\.length, 'candidate host'\)\} for/,
      'Verbose 42-word quoted default goal subtitle must be removed',
    )
    assert.match(consentSrc, /sticky bottom-0 z-20/, 'Sticky bottom action bar must use sticky bottom-0 z-20')
    assert.match(consentSrc, /max-h-\[42vh\].*overflow-y-auto/, 'Candidate host list must bound height with max-h-[42vh] overflow-y-auto')
    assert.match(consentSrc, /md:grid-cols-2/, 'Scan mode & approval policy controls must lay out in a 2-column grid on md:+')

    const defaultGoalsBlockMatch = /const DEFAULT_SCAN_MODE_GOALS[\s\S]*?\)\n/.exec(consentSrc)
    assert.ok(defaultGoalsBlockMatch, 'Expected DEFAULT_SCAN_MODE_GOALS set')
    const defaultGoalsJs = stripTypeScriptTypes(defaultGoalsBlockMatch[0])
    const isCustomRunGoal = loadConsentHelper<(goal: string | null | undefined) => boolean>(
      consentSrc,
      'isCustomRunGoal',
      defaultGoalsJs,
    )

    assert.equal(
      isCustomRunGoal('Run safe active checks, auth/access-control probes, and high-impact proofs while pausing for human approval before risky state-changing actions.'),
      false,
      'Default supervised goal must not be treated as a custom goal',
    )
    assert.equal(
      isCustomRunGoal('Map endpoints, API routes, and client bundles, and verify read-only exposures and cross-account reads without state-changing requests.'),
      false,
      'Default passive goal must not be treated as a custom goal',
    )
    assert.equal(
      isCustomRunGoal('Run all in-scope active probes, mutations, and race bursts automatically with full audit logs and no approval pauses.'),
      false,
      'Default autonomous goal must not be treated as a custom goal',
    )
    assert.equal(isCustomRunGoal('   '), false)
    assert.equal(isCustomRunGoal('Focus on billing checkout IDOR and tenant isolation'), true)

    const draftScanModeMatch = /function draftScanMode[\s\S]*?\n\}/.exec(consentSrc)
    assert.ok(draftScanModeMatch, 'Expected draftScanMode helper')
    const summaryPreamble = `
      const plural = (n, word) => n + ' ' + (n === 1 ? word : word + 's');
      ${stripTypeScriptTypes(draftScanModeMatch[0])}
    `
    const consentStickySummary = loadConsentHelper<(input: {
      discovery: boolean
      hostCount: number
      capabilityTier: 0 | 1 | 2 | 3
      approvalPolicy: 'auto_review' | 'yolo' | 'strict'
    }) => string>(consentSrc, 'consentStickySummary', summaryPreamble)

    assert.equal(
      consentStickySummary({ discovery: false, hostCount: 3, capabilityTier: 3, approvalPolicy: 'auto_review' }),
      '3 hosts · Supervised · Ask before risky actions',
    )
    assert.equal(
      consentStickySummary({ discovery: false, hostCount: 1, capabilityTier: 3, approvalPolicy: 'strict' }),
      '1 host · Supervised · Approve every write',
    )
    assert.equal(
      consentStickySummary({ discovery: false, hostCount: 12, capabilityTier: 1, approvalPolicy: 'auto_review' }),
      '12 hosts · Passive · Read-only',
    )
    assert.equal(
      consentStickySummary({ discovery: false, hostCount: 5, capabilityTier: 3, approvalPolicy: 'yolo' }),
      '5 hosts · Autonomous · Auto-approve in scope',
    )
  })

  describe('Playwright geometry & copy verification with 27 candidate hosts', () => {
    let skipReason: string | null = null
    let kovo: SpawnedKovoServer | undefined
    let browser: Browser | undefined
    let context: BrowserContext | undefined
    let page: Page | undefined
    const pageErrors: string[] = []
    let runId = ''
    let projectId = ''

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

      // 1. Bootstrap auth & create a project via UI
      await page.goto(`${kovo.origin}/?bootstrap=${encodeURIComponent(kovo.bootstrapSecret)}`, {
        waitUntil: 'domcontentloaded',
      })
      await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor({ state: 'visible', timeout: 15_000 })
      await page.getByLabel('Project name').fill('Acme SaaS Sticky Scope')
      await page.getByLabel('Sites').fill('https://app.acme-saas.example\nhttps://api.acme-saas.example\nhttps://auth.acme-saas.example')
      await page.getByRole('button', { name: 'Create project', exact: true }).click()
      await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
      const projectMatch = /\/projects\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(projectMatch?.[1], `Expected project URL, got ${page.url()}`)
      projectId = projectMatch[1]

      // 2. Start a new run with the default Supervised Scan goal (lands in review/waiting)
      await page.getByRole('button', { name: 'New run', exact: true }).click()
      const dialog = page.getByRole('dialog')
      await dialog.waitFor({ state: 'visible', timeout: 10_000 })
      await dialog.getByRole('button', { name: 'Start run', exact: true }).click()
      await page.waitForURL(/\/runs\/[a-f0-9-]+/, { timeout: 15_000 })
      const runMatch = /\/runs\/([a-f0-9-]+)/.exec(page.url())
      assert.ok(runMatch?.[1], `Expected run URL, got ${page.url()}`)
      runId = runMatch[1]

      // 3. Seed 27 realistic candidate hosts directly into the waiting review run & set 3 default seeds
      const candidates = build27Candidates()
      const defaultScope = [
        'https://app.acme-saas.example',
        'https://api.acme-saas.example',
        'https://auth.acme-saas.example',
      ]
      withSqlite(kovo.dataDir, db => {
        db.prepare('UPDATE projects SET default_scope = ? WHERE id = ?').run(JSON.stringify(defaultScope), projectId)
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

    it('renders concise header without default goal wall of text and pins Approve & start above the fold across 1280x720, 1024x640, and 1440x900', async t => {
      if (skipReason || !page || !kovo) {
        t.skip(skipReason ?? 'Browser setup unavailable')
        return
      }

      const captureDir = process.env.KOVO_CAPTURE_CONSENT_SHOTS_DIR
      if (captureDir) mkdirSync(captureDir, { recursive: true })

      const viewports = [
        { width: 1280, height: 720, shotName: 'consent-after-1280x720.png' },
        { width: 1440, height: 900, shotName: 'consent-after-1440x900.png' },
        { width: 1024, height: 640, shotName: null },
      ] as const

      for (const vp of viewports) {
        await page.setViewportSize({ width: vp.width, height: vp.height })
        await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
        await page.getByRole('heading', { name: 'Review scope', level: 1 }).waitFor({ state: 'visible', timeout: 10_000 })

        // 1. Header copy: crisp "Review scope" + concise dynamic subtitle; NO default goal wall of text
        const subtitle = await page.getByTestId('consent-subtitle').innerText()
        assert.equal(subtitle.trim(), '27 candidate hosts found · 24 selected')
        const consentText = await page.getByTestId('consent-scroll-container').innerText()
        assert.equal(
          consentText.includes('Run safe active checks, auth/access-control probes'),
          false,
          `Default goal wall of text must NOT render in consent view (${vp.width}x${vp.height})`,
        )
        assert.equal(
          consentText.includes('Subdomain discovery found 27 candidate hosts for'),
          false,
          `Legacy 42-word verbose subtitle must NOT render (${vp.width}x${vp.height})`,
        )
        assert.equal(
          await page.getByTestId('consent-custom-goal-chip').count(),
          0,
          'Custom goal chip must NOT render when using a built-in scan mode default goal',
        )

        // 2. Sticky bottom bar + Approve & start MUST be fully inside viewport without scrolling
        const stickyBar = page.getByTestId('consent-sticky-bar')
        const approveBtn = page.getByRole('button', { name: /^Approve & start/ })
        const cancelLink = stickyBar.getByRole('link', { name: 'Cancel', exact: true })
        await stickyBar.waitFor({ state: 'visible', timeout: 5_000 })
        await approveBtn.waitFor({ state: 'visible', timeout: 5_000 })
        await cancelLink.waitFor({ state: 'visible', timeout: 5_000 })

        const barBox = await stickyBar.boundingBox()
        const btnBox = await approveBtn.boundingBox()
        const cancelBox = await cancelLink.boundingBox()
        assert.ok(barBox && btnBox && cancelBox, `Expected bounding boxes at ${vp.width}x${vp.height}`)

        assert.ok(barBox.y >= 0, `Sticky bar top (${barBox.y}) must be >= 0 at ${vp.width}x${vp.height}`)
        assert.ok(
          barBox.y + barBox.height <= vp.height + 1,
          `Sticky bar bottom (${barBox.y + barBox.height}) must fit inside viewport height ${vp.height}`,
        )
        assert.ok(btnBox.y >= 0 && btnBox.y + btnBox.height <= vp.height + 1, `Approve & start must be fully visible above the fold at ${vp.width}x${vp.height}`)
        assert.ok(btnBox.x >= 0 && btnBox.x + btnBox.width <= vp.width + 1, `Approve & start must not clip horizontally at ${vp.width}x${vp.height}`)
        assert.ok(cancelBox.x + cancelBox.width < btnBox.x, `Cancel and Approve & start must not overlap at ${vp.width}x${vp.height}`)

        // Verify sticky bar CSS position & summary
        const barPosition = await stickyBar.evaluate(el => getComputedStyle(el).position)
        assert.equal(barPosition, 'sticky', 'Bottom action bar must use position: sticky')
        const summaryText = await page.getByTestId('consent-bar-summary').innerText()
        assert.equal(summaryText.trim(), '24 hosts · Supervised · Ask before risky actions')

        // 3. Scan mode & Approval policy laid out side-by-side in 2 columns on md:+
        const scanModeBox = await page.getByLabel('Scan mode').boundingBox()
        const approvalBox = await page.getByLabel('Approval policy').boundingBox()
        assert.ok(scanModeBox && approvalBox, `Expected Scan mode and Approval policy controls at ${vp.width}x${vp.height}`)
        assert.ok(
          Math.abs(scanModeBox.y - approvalBox.y) < 8 && approvalBox.x > scanModeBox.x + scanModeBox.width,
          `Scan mode and Approval policy must sit side-by-side on ${vp.width}x${vp.height}`,
        )

        // 4. Host list is height-bounded (<= 42vh + padding tolerance)
        const hostListBox = await page.getByTestId('scope-host-list').boundingBox()
        assert.ok(hostListBox, 'Expected scrollable host list')
        assert.ok(
          hostListBox.height <= Math.ceil(vp.height * 0.42) + 2,
          `Host list height (${hostListBox.height}px) must stay within 42vh (${Math.ceil(vp.height * 0.42)}px)`,
        )

        if (captureDir && vp.shotName) {
          await page.screenshot({ path: join(captureDir, vp.shotName), fullPage: false })
        }
      }

      // 5. Dynamic updates when toggling hosts and switching Scan Mode / Approval Policy at 1280x720
      await page.setViewportSize({ width: 1280, height: 720 })
      await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
      await page.getByRole('checkbox', { name: 'Include admin.acme-saas.example' }).uncheck()
      assert.equal((await page.getByTestId('consent-subtitle').innerText()).trim(), '27 candidate hosts found · 23 selected')
      assert.equal((await page.getByTestId('consent-bar-summary').innerText()).trim(), '23 hosts · Supervised · Ask before risky actions')

      await page.getByLabel('Approval policy').selectOption('strict')
      assert.equal((await page.getByTestId('consent-bar-summary').innerText()).trim(), '23 hosts · Supervised · Approve every write')

      await page.getByLabel('Scan mode').selectOption('passive')
      assert.equal((await page.getByTestId('consent-bar-summary').innerText()).trim(), '23 hosts · Passive · Read-only')

      // 6. Custom non-default goal renders ONLY as a compact muted 1-line truncated chip
      const longCustomGoal = 'Audit tenant isolation across billing APIs, webhook signing endpoints, and admin impersonation flows before the Q4 enterprise launch.'
      withSqlite(kovo.dataDir, db => {
        db.prepare('UPDATE runs SET goal = ? WHERE id = ?').run(longCustomGoal, runId)
      })
      await page.goto(`${kovo.origin}/runs/${runId}`, { waitUntil: 'networkidle' })
      const chip = page.getByTestId('consent-custom-goal-chip')
      await chip.waitFor({ state: 'visible', timeout: 10_000 })
      const chipBox = await chip.boundingBox()
      assert.ok(chipBox && chipBox.height <= 30, `Custom goal chip must remain single-line (<=30px tall), got ${chipBox?.height}px`)
      assert.equal(await chip.getAttribute('title'), longCustomGoal)

      // Sticky bar still fits cleanly above the fold even with the custom goal chip present
      const btnBoxWithChip = await page.getByRole('button', { name: /^Approve & start/ }).boundingBox()
      assert.ok(btnBoxWithChip && btnBoxWithChip.y + btnBoxWithChip.height <= 721, 'Approve & start must remain above the fold with custom goal chip')

      assert.deepEqual(pageErrors, [], `Unexpected browser pageerror(s): ${pageErrors.join('; ')}`)
    })
  })
})
