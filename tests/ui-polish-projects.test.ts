/**
 * PR 2 Bucket A polish (A-038..A-073): Projects index + Project workbench.
 *
 * Behavioural + DOM-geometry checks against the freshly built HEAD bundle served
 * by a hermetic `scripts/serve.ts` (temp KOVO_DATA_DIR seeded through the real
 * Store API). GitHub repo discovery is served by an in-process `fetch` mock
 * that this same file installs when it is preloaded into the server process
 * (`KOVO_UI_POLISH_GITHUB_MOCK=1`), so no network or credentials are touched.
 *
 * Set `KOVO_UI_POLISH_SCREENSHOT_DIR=<dir>` to also capture the after-state
 * screenshot matrix (1280×720, 1440×900, 390×844 × light/dark).
 */
import assert from 'node:assert/strict'
import { execFileSync, spawn } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer as createNetServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, before, describe, it } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import type { Browser, BrowserContext, Page } from '@playwright/test'

const GITHUB_MOCK_ENV = 'KOVO_UI_POLISH_GITHUB_MOCK'
const THIS_FILE = fileURLToPath(import.meta.url)

// ---------------------------------------------------------------------------
// Preload mode: hermetic GitHub REST mock inside the spawned Kovo server.
// ---------------------------------------------------------------------------

function githubMockRepos() {
  const owners = ['kovo-qa', 'acme-platform-engineering-org']
  const repos: Record<string, unknown>[] = []
  for (const owner of owners) {
    for (let i = 1; i <= 6; i += 1) {
      repos.push({
        full_name: `${owner}/service-${i}${i === 2 ? '-with-a-much-longer-repository-name' : ''}`,
        private: i % 2 === 0,
        default_branch: i === 3 ? 'release/2026-11-hotfix-branch-with-long-name' : 'main',
        updated_at: new Date(Date.UTC(2026, 10, 20 - i)).toISOString(),
        description: i === 1 ? 'Storefront API gateway, checkout, and session services used by the shop frontends.' : null,
      })
    }
  }
  return repos
}

function installGithubFetchMock(): void {
  const original = globalThis.fetch
  globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    if (url.hostname !== 'api.github.com') return original(input, init)
    const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })
    if (url.pathname === '/user') return json({ login: 'kovo-qa' })
    if (url.pathname === '/user/installations') return json({ total_count: 0, installations: [] })
    if (url.pathname === '/user/repos') {
      return json(Number(url.searchParams.get('page') ?? '1') > 1 ? [] : githubMockRepos())
    }
    return json({ message: 'Not Found' }, 404)
  }) as typeof fetch
}


// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const HARDENED_FLAGS = [
  '--disable-proto=delete',
  '--enable-experimental-regexp-engine-on-excessive-backtracks',
  '--regexp-backtracks-before-fallback=10000',
]

const SYSTEM_CHROMIUM = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable']

interface PlaywrightModule {
  chromium: {
    executablePath(): string
    launch(options?: { headless?: boolean; executablePath?: string; args?: string[] }): Promise<Browser>
  }
}

async function loadPlaywright(): Promise<{ pw: PlaywrightModule; executablePath: string } | null> {
  for (const modName of ['@playwright/test', 'playwright-core'] as const) {
    let pw: PlaywrightModule | null = null
    try {
      const loaded = (await import(modName)) as Partial<PlaywrightModule>
      if (loaded.chromium && typeof loaded.chromium.launch === 'function') pw = loaded as PlaywrightModule
    } catch {
      continue
    }
    if (!pw) continue
    let bundled = ''
    try { bundled = pw.chromium.executablePath() } catch { bundled = '' }
    if (bundled && existsSync(bundled)) return { pw, executablePath: bundled }
    const system = SYSTEM_CHROMIUM.find(candidate => existsSync(candidate))
    if (system) return { pw, executablePath: system }
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

interface KovoServer {
  origin: string
  dataDir: string
  cookieHeader: string
  cookies: { name: string; value: string }[]
  stop(): Promise<void>
}

async function startKovo(dataDir: string, extraEnv: Record<string, string>, preload: boolean): Promise<KovoServer> {
  const port = await findFreePort()
  const origin = `http://127.0.0.1:${port}`
  let output = ''
  const args = [...HARDENED_FLAGS, ...(preload ? ['--import', THIS_FILE] : []), 'scripts/serve.ts']
  const child: ChildProcess = spawn(process.execPath, args, {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), KOVO_DATA_DIR: dataDir, KOVO_OFFLINE: '', KOVO_PUBLIC_ORIGIN: '', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', chunk => { output += String(chunk) })
  child.stderr?.on('data', chunk => { output += String(chunk) })
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit')
      child.kill('SIGTERM')
      if (await Promise.race([exited.then(() => false), delay(3_000).then(() => true)])) {
        child.kill('SIGKILL')
        await once(child, 'exit')
      }
    }
    await rm(dataDir, { recursive: true, force: true })
  }
  let healthy = false
  for (let attempt = 0; attempt < 200 && child.exitCode === null; attempt += 1) {
    try {
      if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(300) })).ok) { healthy = true; break }
    } catch { /* not bound yet */ }
    await delay(70)
  }
  if (!healthy) { await stop(); throw new Error(`serve.ts failed to start on ${origin}.\n${output.slice(-2000)}`) }
  let secret = ''
  for (let i = 0; i < 40 && !secret; i += 1) {
    try { secret = (await readFile(join(dataDir, 'bootstrap'), 'utf8')).trim() } catch { await delay(50) }
  }
  if (!secret) { await stop(); throw new Error('bootstrap secret was not written') }
  const res = await fetch(`${origin}/?bootstrap=${encodeURIComponent(secret)}`, { redirect: 'manual' })
  const cookies = res.headers.getSetCookie().map(raw => {
    const [pair] = raw.split(';')
    const eq = pair!.indexOf('=')
    return { name: pair!.slice(0, eq).trim(), value: pair!.slice(eq + 1).trim() }
  })
  assert.ok(cookies.length > 0, 'bootstrap must set a session cookie')
  return { origin, dataDir, cookies, cookieHeader: cookies.map(c => `${c.name}=${c.value}`).join('; '), stop }
}

// ---------------------------------------------------------------------------
// Seed dataset (real Store API; counters set through SQL like e2e Journey 4)
// ---------------------------------------------------------------------------

const BENCH_PREFIX = 'realistic-bench shopflow storefront regression'
const LONG_UNBROKEN_NAME = 'Unbrokenprojectnamewithoutanyspaces'.repeat(6).slice(0, 180)
const LONG_HANDLE = 'qa-tenant-isolation-user-with-a-very-long-handle'.slice(0, 48)
const LONG_ROLE = 'Tenant administrator with delegated billing, audit export, and SSO configuration rights '.repeat(2).trim()

interface SeedIds {
  workbench: string
  unbroken: string
  zeroSeeds: string
  grouped: string
}

async function seedMainWorkspace(dataDir: string): Promise<SeedIds> {
  const { Store } = await import('../src/server/store.ts')
  const { createProjectPersona } = await import('../src/server/persona-vault.ts')
  const s = new Store(dataDir)
  const mk = (name: string, seeds: string[]) =>
    s.createProject({ requestId: randomUUID(), name, seeds, environment: 'public', includeSubdomains: false } as never)
  const mkRun = (projectId: string, goal: string) =>
    s.createRun({
      requestId: randomUUID(), projectId, goal, sourceMode: 'public', capabilityTier: 1, budgetUsd: 25,
      budgetRequests: 0, maxRpsPerOrigin: 5, workerConcurrency: 1, workerMaxTurns: 4,
    } as never)
  try {
    for (let i = 1; i <= 26; i += 1) {
      mk(`${BENCH_PREFIX} seed ${100000 + i}`, [`https://shopflow-${i}.example.com`])
    }
    const workbenchSeeds = ['https://dyad.sh', ...Array.from({ length: 29 }, (_, i) => `https://app-${i + 1}.dyad.sh`)]
    const workbench = mk('Northwind Commerce Platform', workbenchSeeds)
    const unbroken = mk(LONG_UNBROKEN_NAME, ['https://unbroken.example.com'])
    const zeroSeeds = mk('Zero seed hosts', ['https://zero.example.com'])
    const grouped = mk('Grouped count stress', ['https://grouped.example.com'])

    const stress = mkRun(workbench.id, 'Stress run with large counters')
    const paused = mkRun(workbench.id, 'Paused authenticated sweep')
    const waiting = mkRun(workbench.id, 'Awaiting approval write checks')
    const stopped = mkRun(grouped.id, 'Stopped investigation run')
    createProjectPersona(s, {
      requestId: randomUUID(), projectId: workbench.id, handle: LONG_HANDLE, roleLabel: LONG_ROLE,
      originAllowlist: ['https://dyad.sh'], authKind: 'cookie', secret: 'session=qa-fixture', canaryMarkers: [],
    } as never)
    createProjectPersona(s, {
      requestId: randomUUID(), projectId: workbench.id, handle: 'user-b', roleLabel: 'User B',
      originAllowlist: ['https://dyad.sh'], authKind: 'cookie', secret: 'session=qa-fixture-b', canaryMarkers: [],
    } as never)

    const db = s.client
    const now = Date.now()
    const setRun = db.prepare('UPDATE runs SET status = ?, phase = ?, spent_usd = ?, spent_requests = ?, turns_used = ?, created_at = ? WHERE id = ?')
    setRun.run('complete', 'complete', 1234.56, 999_999, 9_999, now - 3_600_000, stress.id)
    setRun.run('paused', 'investigation', 2.5, 120, 14, now - 120_000, paused.id)
    setRun.run('waiting', 'verification', 1.25, 80, 9, now - 60_000, waiting.id)
    setRun.run('stopped', 'investigation', 0.5, 10, 3, now - 30_000, stopped.id)
    const addAsset = db.prepare('INSERT INTO project_assets (id, project_id, origin, source, third_party, include_subdomains) VALUES (?, ?, ?, ?, 0, 0)')
    db.exec('BEGIN')
    addAsset.run(randomUUID(), workbench.id, 'https://extra-31.dyad.sh', 'Manual entry')
    for (let i = 1; i <= 12; i += 1) addAsset.run(randomUUID(), zeroSeeds.id, `https://zero-${i}.example.com`, 'DNS export')
    for (let i = 1; i <= 1_200; i += 1) addAsset.run(randomUUID(), grouped.id, `https://h${i}.grouped.example.com`, 'DNS export')
    db.prepare("UPDATE projects SET seeds = '[]' WHERE id = ?").run(zeroSeeds.id)
    db.exec('COMMIT')
    return { workbench: workbench.id, unbroken: unbroken.id, zeroSeeds: zeroSeeds.id, grouped: grouped.id }
  } finally {
    s.close()
  }
}

// ---------------------------------------------------------------------------
// Page helpers
// ---------------------------------------------------------------------------

type Theme = 'light' | 'dark'
interface Viewport { width: number; height: number; label: string; mobile: boolean }
const VIEWPORTS: readonly Viewport[] = [
  { width: 1280, height: 720, label: '1280x720', mobile: false },
  { width: 1440, height: 900, label: '1440x900', mobile: false },
  { width: 390, height: 844, label: '390x844', mobile: true },
]
const THEMES: readonly Theme[] = ['light', 'dark']
const SHOT_DIR = process.env.KOVO_UI_POLISH_SCREENSHOT_DIR?.trim() || ''

/** Run every viewport × theme combo in its own concurrent browser context (keeps the suite in the fast tier). */
async function forEachCombo(fn: (vp: Viewport, theme: Theme) => Promise<void>): Promise<void> {
  await Promise.all(VIEWPORTS.flatMap(vp => THEMES.map(theme => fn(vp, theme))))
}

async function newContext(browser: Browser, server: KovoServer, vp: Viewport, theme: Theme): Promise<BrowserContext> {
  const ctx = await browser.newContext({
    viewport: { width: vp.width, height: vp.height },
    colorScheme: theme,
    ...(vp.mobile ? { isMobile: true, hasTouch: true, deviceScaleFactor: 1 } : {}),
  })
  const url = new URL(server.origin)
  await ctx.addCookies(server.cookies.map(c => ({ ...c, domain: url.hostname, path: '/' })))
  await ctx.addInitScript(t => { try { localStorage.setItem('kovo-appearance', t) } catch { /* ignore */ } }, theme)
  return ctx
}

async function shot(page: Page, name: string, vp: Viewport, theme: Theme): Promise<void> {
  if (!SHOT_DIR) return
  mkdirSync(SHOT_DIR, { recursive: true })
  await delay(220) // let enter transitions settle
  await page.screenshot({ path: join(SHOT_DIR, `${name}--${vp.label}--${theme}.png`) })
}

async function settle(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.evaluate(() => document.fonts?.ready).catch(() => {})
}

/** Elements matching `selector` whose content overflows horizontally. */
async function horizontalOverflow(page: Page, selector: string): Promise<string[]> {
  return page.$$eval(selector, els => els
    .filter(el => el.getClientRects().length > 0 && el.scrollWidth > el.clientWidth + 1)
    .map(el => `${el.tagName.toLowerCase()}[${el.getAttribute('data-slot') ?? el.className.toString().slice(0, 40)}] ${el.scrollWidth}>${el.clientWidth}`))
}

/** Descendants of `container` whose box extends past the container's right edge. */
async function spillingDescendants(page: Page, container: string): Promise<string[]> {
  return page.$eval(container, root => {
    const edge = root.getBoundingClientRect().right + 1
    return [...root.querySelectorAll('*')].filter(el => {
      const r = el.getBoundingClientRect()
      return r.width > 0 && r.height > 0 && r.right > edge && getComputedStyle(el).visibility !== 'hidden'
    }).map(el => `${el.tagName.toLowerCase()} "${(el.textContent ?? '').trim().slice(0, 30)}" right=${Math.round(el.getBoundingClientRect().right)} edge=${Math.round(edge)}`)
  })
}

/** Visible filled-accent buttons/links outside empty states and dialogs. */
async function filledPrimaryCount(page: Page): Promise<number> {
  return page.evaluate(() => {
    const probe = document.createElement('span')
    probe.className = 'bg-accent'
    document.body.appendChild(probe)
    const accent = getComputedStyle(probe).backgroundColor
    probe.remove()
    return [...document.querySelectorAll('main button, main a')].filter(el => {
      // Empty states and inline sheets (repo picker footer) own their contextual primary.
      if (el.closest('[data-slot=empty-state], [data-slot=dialog-content], .pw-repo-sheet')) return false
      const r = el.getBoundingClientRect()
      return r.width > 0 && r.height > 0 && getComputedStyle(el).backgroundColor === accent
    }).length
  })
}

/**
 * Chromium does not expose computed styles for UA shadow pseudos, so read the
 * CSSOM: some applied rule must set `appearance: none` on this input's
 * `::-webkit-search-cancel-button`.
 */
async function nativeSearchCancelSuppressed(page: Page, selector: string): Promise<boolean> {
  // Iterative walk (no named inner functions: esbuild's keepNames would inject `__name` into the page).
  return page.$eval(selector, input => {
    const pseudo = '::-webkit-search-cancel-button'
    const stack: CSSRule[] = []
    for (const sheet of [...document.styleSheets]) {
      try { stack.push(...sheet.cssRules) } catch { /* cross-origin */ }
    }
    while (stack.length > 0) {
      const rule = stack.pop()!
      if (rule instanceof CSSStyleRule && rule.selectorText.includes(pseudo)) {
        const appearance = rule.style.getPropertyValue('appearance') || rule.style.getPropertyValue('-webkit-appearance')
        const bases = rule.selectorText.split(',').map(part => part.trim()).filter(part => part.endsWith(pseudo))
        if (appearance === 'none' && bases.some(part => input.matches(part.slice(0, -pseudo.length)))) return true
      }
      const nested = (rule as CSSGroupingRule).cssRules
      if (nested) stack.push(...nested)
    }
    return false
  })
}

async function connectGithubCardGeometry(page: Page, scope: string) {
  return page.$eval(scope, root => {
    const badge = [...root.querySelectorAll('span')].find(el => el.textContent?.trim() === 'Recommended')
    const cta = [...root.querySelectorAll('a')].find(el => el.textContent?.includes('Connect in Settings'))
    const copy = [...root.querySelectorAll('span')].find(el => el.textContent?.startsWith('Add source code'))
    return {
      badgeClipped: badge ? badge.scrollWidth > badge.clientWidth + 1 : true,
      copyLines: copy ? Math.round(copy.getBoundingClientRect().height / 17) : 99,
      ctaWidth: cta?.getBoundingClientRect().width ?? 0,
      cardWidth: cta?.parentElement?.getBoundingClientRect().width ?? 1,
    }
  })
}

async function dialogTop(page: Page): Promise<number> {
  return page.$eval('[data-slot=dialog-content]', el => Math.round(el.getBoundingClientRect().top))
}

async function activeDescription(page: Page): Promise<string> {
  return page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null
    if (!el || el === document.body) return 'body'
    return [el.tagName.toLowerCase(), el.getAttribute('name') ?? '', el.getAttribute('role') ?? '', el.getAttribute('aria-checked') ?? '', (el.textContent ?? '').trim().slice(0, 40)].join('|')
  })
}

async function openProject(page: Page, server: KovoServer, projectId: string, tab?: string): Promise<void> {
  await page.goto(`${server.origin}/projects/${projectId}${tab ? `?tab=${tab}` : ''}`, { waitUntil: 'domcontentloaded' })
  await page.locator('main h1').first().waitFor({ state: 'visible', timeout: 15_000 })
  await settle(page)
}

async function openHeaderDialog(page: Page, item: 'Edit project' | 'Delete project'): Promise<void> {
  await page.getByRole('button', { name: 'Project actions' }).click()
  await page.getByRole('menuitem', { name: item }).click()
  await page.locator('[data-slot=dialog-content]').waitFor({ state: 'visible' })
  await delay(200)
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

function defineSuite(): void {
  describe('run-state formatting (A-065)', () => {
    it('groups counts and formats currency', async () => {
      const { formatCount, formatUsd } = await import('../src/components/run-state.ts')
      assert.equal(formatCount(999_999), '999,999')
      assert.equal(formatCount(99_999), '99,999')
      assert.equal(formatCount(Number.NaN), '0')
      assert.equal(formatUsd(1234.56), '$1,234.56')
      assert.equal(formatUsd(25), '$25.00')
      assert.equal(formatUsd(0.004), '<$0.01')
      assert.equal(formatUsd(Number.POSITIVE_INFINITY), '$0.00')
    })
  })

  describe('PR2 projects index + workbench (Playwright)', { timeout: 600_000 }, () => {
    let skipReason: string | null = null
    let browser: Browser | undefined
    let main: KovoServer | undefined
    let empty: KovoServer | undefined
    let ids: SeedIds | undefined
    const pageErrors: string[] = []

    before(async () => {
      const pwEnv = await loadPlaywright()
      if (!pwEnv) { skipReason = 'Playwright/Chromium unavailable'; return }
      if (!existsSync(resolve('build/server/server.js'))) execFileSync('npm', ['run', 'build'], { stdio: 'pipe' })
      const mainDir = await mkdtemp(join(tmpdir(), 'kovo-ui-pr2-'))
      ids = await seedMainWorkspace(mainDir)
      const patPath = join(mainDir, 'github-fixture.pat')
      writeFileSync(patPath, `github_pat_${'q'.repeat(60)}\n`, { mode: 0o600 })
      const emptyDir = await mkdtemp(join(tmpdir(), 'kovo-ui-pr2-empty-'))
      ;[main, empty, browser] = await Promise.all([
        startKovo(mainDir, {
          [GITHUB_MOCK_ENV]: '1',
          KOVO_ALLOW_FIXTURE_GITHUB_PAT: '1',
          KOVO_GITHUB_FIXTURE_PAT_PATH: patPath,
        }, true),
        startKovo(emptyDir, { KOVO_ALLOW_FIXTURE_GITHUB_PAT: '' }, false),
        pwEnv.pw.chromium.launch({ headless: true, executablePath: pwEnv.executablePath, args: ['--no-sandbox'] }),
      ])
    })

    after(async () => {
      await browser?.close().catch(() => {})
      await main?.stop().catch(() => {})
      await empty?.stop().catch(() => {})
    })

    async function withPage<T>(server: KovoServer, vp: Viewport, theme: Theme, fn: (page: Page) => Promise<T>): Promise<T> {
      const ctx = await newContext(browser!, server, vp, theme)
      const page = await ctx.newPage()
      page.on('pageerror', err => pageErrors.push(`${vp.label}/${theme}: ${err.message}`))
      try {
        return await fn(page)
      } catch (err) {
        if (SHOT_DIR) await page.screenshot({ path: join(SHOT_DIR, `FAIL--${vp.label}--${theme}--${Date.now()}.png`) }).catch(() => {})
        throw err
      } finally {
        await ctx.close()
      }
    }

    const desktop = VIEWPORTS[0]!
    const narrow = VIEWPORTS[2]!

    it('projects index geometry across viewports and themes (A-038, A-039, A-046, A-050, A-044)', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(main!, vp, theme, async page => {
        await page.goto(main!.origin + '/', { waitUntil: 'domcontentloaded' })
        await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor()
        await settle(page)
        const ctx = `${vp.label}/${theme}`
        assert.equal(await page.locator('[data-slot=project-row]').count(), 30, ctx)
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=project-row], main > div'), [], `${ctx}: rows must not spill`)
        const cta = await page.locator('header').getByRole('button', { name: 'New project' }).boundingBox()
        assert.ok(cta && cta.x >= 0 && cta.x + cta.width <= vp.width && cta.y + cta.height <= vp.height, `${ctx}: New project CTA in viewport`)
        // Banner copy wraps at sentence width; CTA drops below on narrow widths (A-039).
        const banner = await page.$eval('[data-slot=model-pool-banner]', el => {
          const copy = el.querySelector('[data-slot=model-pool-banner-copy]')!.getBoundingClientRect()
          const link = el.querySelector('a')!.getBoundingClientRect()
          const style = getComputedStyle(el)
          const inner = el.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)
          return { copyWidth: copy.width, inner, copyBottom: copy.bottom, linkTop: link.top, overflow: el.scrollWidth > el.clientWidth + 1 }
        })
        assert.equal(banner.overflow, false, `${ctx}: banner overflow`)
        if (vp.mobile) {
          // Copy takes the full row beside the icon (not ~50px one-word-per-line).
          assert.ok(banner.copyWidth >= Math.min(240, banner.inner - 30), `${ctx}: banner copy width ${banner.copyWidth} of ${banner.inner}`)
          assert.ok(banner.linkTop >= banner.copyBottom - 1, `${ctx}: banner CTA on its own line`)
        }
        // Distinguishing suffix stays visible on every bench row (A-046).
        const qualifiers = await page.$$eval('[data-slot=project-name-qualifier]', els => els.map(el => ({
          text: el.textContent ?? '', clipped: el.scrollWidth > el.clientWidth + 1, title: el.closest('a')?.getAttribute('title') ?? '',
        })))
        assert.equal(qualifiers.length, 26, `${ctx}: qualifier spans`)
        for (const q of qualifiers) {
          assert.match(q.text, /^seed 1000\d\d$/, ctx)
          assert.equal(q.clipped, false, `${ctx}: ${q.text} clipped`)
          assert.ok(q.title.startsWith(BENCH_PREFIX), `${ctx}: name title`)
        }
        if (vp.mobile) {
          assert.equal(await page.locator('[data-slot=project-row-actions]').first().isVisible(), false, 'hover-only cluster hidden on touch')
        }
        if (!vp.mobile) {
          const zeroCell = page.locator('[data-slot=project-row]', { hasText: 'Zero seed hosts' }).locator('[data-slot=seed-host-cell]')
          if (await zeroCell.isVisible()) assert.equal((await zeroCell.innerText()).trim(), '13 hosts', `${ctx}: no "— +N" cell (A-050)`)
          const groupedCell = page.locator('[data-slot=project-row]', { hasText: 'Grouped count stress' }).locator('[data-slot=seed-host-cell]')
          if (await groupedCell.isVisible()) assert.match(await groupedCell.innerText(), /\+1,200/)
        }
        const stoppedLabel = page.locator('[data-slot=project-row]', { hasText: 'Grouped count stress' }).locator('[data-slot=latest-run-label]')
        if (await stoppedLabel.isVisible()) assert.equal(await stoppedLabel.innerText(), 'Stopped')
        await shot(page, 'projects-index-stress', vp, theme)
        if (vp === desktop || vp.mobile || theme === 'light') {
          await page.getByRole('searchbox', { name: 'Filter projects' }).fill('seed 10001')
          await shot(page, 'projects-index-filtered', vp, theme)
          await page.getByRole('searchbox', { name: 'Filter projects' }).fill('zzzz-no-match')
          await page.locator('[data-slot=empty-state]').waitFor()
          await shot(page, 'projects-index-zero-match', vp, theme)
        }
      }))
    })

    it('projects index filter, header count, empty state, deep link, hover cluster (A-040..A-043, A-047..A-049)', async t => {
      if (skipReason) return t.skip(skipReason)
      await withPage(main!, desktop, 'light', async page => {
        await page.goto(main!.origin + '/', { waitUntil: 'domcontentloaded' })
        await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor()
        await settle(page)
        const count = page.locator('[data-slot=project-count]')
        assert.equal(await count.innerText(), '30')
        const input = page.getByRole('searchbox', { name: 'Filter projects' })
        const widthBefore = await input.evaluate(el => el.parentElement!.getBoundingClientRect().width)
        await input.focus()
        const anims = await input.evaluate(el => el.parentElement!.getAnimations().map(a => (a as CSSTransition).transitionProperty ?? ''))
        assert.ok(!anims.includes('width'), `no width transition on focus (${anims.join(',')})`)
        await delay(250)
        assert.equal(await input.evaluate(el => el.parentElement!.getBoundingClientRect().width), widthBefore, 'filter width is fixed (A-042)')
        assert.ok(await nativeSearchCancelSuppressed(page, 'input[aria-label="Filter projects"]'), 'native search cancel hidden (A-041)')
        await input.fill('seed 10001')
        await page.waitForFunction(() => document.querySelector('[data-slot=project-count]')?.textContent?.includes(' of '))
        assert.equal(await count.innerText(), '10 of 30', 'header count reflects filter (A-047)')
        const clear = page.getByRole('button', { name: 'Clear filter' })
        assert.equal(await clear.count(), 1, 'exactly one clear control')
        const clearBox = await clear.boundingBox()
        assert.ok(clearBox && clearBox.width >= 24 && clearBox.height >= 24, 'clear hit area >= 24px')
        await input.fill('zzzz-no-match')
        const emptyState = page.locator('[data-slot=empty-state]')
        await emptyState.waitFor()
        assert.equal(await page.locator('main [role=row]').count(), 0, 'no orphan column header (A-048)')
        assert.equal(await emptyState.getByRole('button', { name: 'Clear filter' }).count(), 1)
        assert.equal(await emptyState.getByRole('button', { name: 'New project' }).count(), 1)
        await emptyState.getByRole('button', { name: 'Clear filter' }).click()
        assert.equal(await page.locator('[data-slot=project-row]').count(), 30)

        // Hover cluster aligns with the 18px gutter and interpolates translate (A-049).
        const row = page.locator('[data-slot=project-row]').first()
        await row.hover()
        await delay(400) // let the translate transition finish
        const geo = await row.evaluate(el => {
          const actions = el.querySelector('[data-slot=project-row-actions]') as HTMLElement
          return {
            gap: el.getBoundingClientRect().right - actions.getBoundingClientRect().right,
            transition: getComputedStyle(actions).transitionProperty,
          }
        })
        assert.ok(Math.abs(geo.gap - 18) <= 1, `actions gutter ${geo.gap}`)
        assert.match(geo.transition, /translate/)
        assert.doesNotMatch(geo.transition, /transform/)

        // Stopped run label in the table (A-043).
        assert.equal(await page.locator('[data-slot=project-row]', { hasText: 'Grouped count stress' }).locator('[data-slot=latest-run-label]').innerText(), 'Stopped')
        assert.match(await page.locator('[data-slot=project-row]', { hasText: 'Grouped count stress' }).innerText(), /\+1,200/, 'grouped host badge (A-044)')

        // /?new=1 deep link opens the modal (A-040).
        await page.goto(main!.origin + '/?new=1', { waitUntil: 'domcontentloaded' })
        await page.locator('[data-slot=dialog-content]').waitFor({ state: 'visible', timeout: 10_000 })
      })
    })

    it('onboarding + New project modal on an empty workspace (A-045, A-051, A-052)', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(empty!, vp, theme, async page => {
        await page.goto(empty!.origin + '/', { waitUntil: 'domcontentloaded' })
        await page.getByRole('heading', { name: 'Start your first project' }).waitFor()
        await settle(page)
        const ctx = `${vp.label}/${theme}`
        assert.equal(await page.locator('[data-slot=project-count]').count(), 0, `${ctx}: no lone 0`)
        assert.equal(await page.locator('main').getByText('New project', { exact: true }).count(), 0, `${ctx}: single onboarding title`)
        // The 390px column is narrowed by the persistent rail (collapse is Bucket B / U1), so assert the
        // padding fix relative to the column: the input spans most of it instead of being crushed by px-8.
        const fit = await page.$eval('main', root => {
          const input = root.querySelector('input[name=name]')!.getBoundingClientRect().width
          return { input, column: root.getBoundingClientRect().width }
        })
        if (vp.mobile) assert.ok(fit.input >= fit.column - 80, `${ctx}: input ${fit.input}px of ${fit.column}px column`)
        else assert.ok(fit.input >= 240, `${ctx}: input width ${fit.input}`)
        assert.deepEqual(await spillingDescendants(page, 'main form'), [], `${ctx}: onboarding form children`)
        const overlap = await page.$eval('[data-slot=include-subdomains-text]', text => {
          const a = text.getBoundingClientRect()
          const b = text.parentElement!.querySelector('code')!.getBoundingClientRect()
          return a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom
        })
        assert.equal(overlap, false, `${ctx}: include-subdomains copy never overlaps the *.domain chip`)
        assert.deepEqual(await horizontalOverflow(page, 'main, main form'), [], ctx)
        const gh = await connectGithubCardGeometry(page, 'main')
        assert.equal(gh.badgeClipped, false, `${ctx}: Recommended badge unclipped`)
        if (vp.mobile) assert.ok(gh.ctaWidth >= gh.cardWidth - 40, `${ctx}: CTA full width below copy`)
        else assert.ok(gh.copyLines <= 3, `${ctx}: Connect GitHub copy lines ${gh.copyLines}`)
        await shot(page, 'projects-onboarding-empty', vp, theme)
      }))

      // The New project modal (full-viewport even at 390) carries the A-052 criterion.
      await withPage(empty!, desktop, 'light', async page => {
        await page.goto(empty!.origin + '/', { waitUntil: 'domcontentloaded' })
        await page.getByLabel('Project name').fill('Modal check project')
        await page.getByLabel('Sites').fill('https://modal-check.example.com')
        await page.getByRole('button', { name: 'Create project', exact: true }).click()
        await page.waitForURL(/\/projects\/[a-f0-9-]+/, { timeout: 15_000 })
      })
      await forEachCombo((vp, theme) => withPage(empty!, vp, theme, async page => {
        const ctx = `${vp.label}/${theme} modal`
        await page.goto(empty!.origin + '/?new=1', { waitUntil: 'domcontentloaded' })
        await page.locator('[data-slot=dialog-content]').waitFor({ state: 'visible', timeout: 10_000 })
        await settle(page)
        const gh = await connectGithubCardGeometry(page, '[data-slot=dialog-content]')
        assert.equal(gh.badgeClipped, false, `${ctx}: Recommended badge unclipped`)
        assert.ok(gh.copyLines <= 3, `${ctx}: Connect GitHub copy lines ${gh.copyLines}`)
        if (vp.mobile) assert.ok(gh.ctaWidth >= gh.cardWidth - 40, `${ctx}: CTA full width below copy`)
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=dialog-content], [data-slot=dialog-content] form'), [], ctx)
        const submit = await page.getByRole('button', { name: 'Create project', exact: true }).boundingBox()
        assert.ok(submit && submit.y + submit.height <= vp.height, `${ctx}: Create project above the fold`)
        await shot(page, 'new-project-modal', vp, theme)
      }))
    })

    it('invalid or missing project ids render the in-shell 404 view (A-053)', async t => {
      if (skipReason) return t.skip(skipReason)
      for (const path of ['/projects/does-not-exist', `/projects/${randomUUID()}`]) {
        const res = await fetch(main!.origin + path, { headers: { cookie: main!.cookieHeader } })
        const body = await res.text()
        assert.equal(res.status, 404, `${path} status`)
        assert.doesNotMatch(body, /ZodError|invalid_format/i)
      }
      await withPage(main!, desktop, 'light', async page => {
        await page.goto(main!.origin + '/projects/does-not-exist', { waitUntil: 'domcontentloaded' })
        await page.getByRole('heading', { name: 'Project not found', level: 1 }).waitFor()
        assert.ok(await page.getByRole('navigation', { name: 'Workspace' }).isVisible(), 'rail stays visible')
        await page.getByRole('link', { name: 'Back to projects' }).click()
        await page.getByRole('heading', { name: 'Projects', level: 1 }).waitFor()
      })
    })

    it('project detail tabs: header seed summary, posture, run rows, quiet delete, one primary (A-055, A-060, A-065..A-070)', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(main!, vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, main!, ids!.workbench)
        const seedSummary = page.locator('[data-slot=header-seed-summary]')
        assert.match(await seedSummary.innerText(), /dyad\.sh\s*\+29/, `${ctx}: seed summary`)
        assert.equal(await page.locator('main h1').getAttribute('title'), 'Northwind Commerce Platform')
        assert.ok(((await page.locator('main h1').boundingBox())?.width ?? 0) > 40, `${ctx}: name not crushed`)
        assert.equal(await page.locator('[data-slot=posture-title]').innerText(), '1 paused · 1 awaiting approval', `${ctx}: posture (A-066)`)
        assert.match(await page.locator('main').innerText(), /9,999 turns · 999,999 reqs · \$1,234\.56/, `${ctx}: grouped run meta (A-065)`)
        assert.match(await page.locator('main').innerText(), /GitHub connected|GitHub not connected/)
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=overview-run-row]'), [], ctx)
        if (vp.mobile) {
          // Status/time cluster stacks under the title so the meta line gets the row's full text width
          // (the rail-narrowed 390px column itself is Bucket B / U1).
          const rows = await page.$$eval('[data-slot=overview-run-row]', els => els.map(el => {
            const meta = el.querySelector('[data-slot=overview-run-meta]')!.getBoundingClientRect()
            const cluster = el.lastElementChild!.getBoundingClientRect()
            return { metaWidth: meta.width, rowWidth: el.getBoundingClientRect().width, stacked: cluster.top >= meta.bottom - 1 }
          }))
          for (const r of rows) {
            assert.ok(r.stacked, `${ctx}: status cluster stacks under the title`)
            assert.ok(r.metaWidth >= r.rowWidth - 40, `${ctx}: meta ${r.metaWidth}px of ${r.rowWidth}px row`)
          }
        }
        assert.equal(await filledPrimaryCount(page), 1, `${ctx}: one filled primary on Overview`)
        await shot(page, 'project-overview', vp, theme)

        await openProject(page, main!, ids!.workbench, 'inventory')
        const deletes = page.locator('[aria-label^="Delete host"]')
        assert.equal(await deletes.count(), 31, `${ctx}: 31 hosts`)
        const tone = await deletes.first().evaluate(el => {
          const probe = document.createElement('span')
          probe.className = 'text-danger'
          document.body.appendChild(probe)
          const danger = getComputedStyle(probe).color
          probe.remove()
          return { color: getComputedStyle(el).color, danger, text: (el.textContent ?? '').trim() }
        })
        assert.notEqual(tone.color, tone.danger, `${ctx}: no red at rest (A-070)`)
        assert.equal(tone.text, '', `${ctx}: icon-only delete`)
        assert.equal(await filledPrimaryCount(page), 1, `${ctx}: one filled primary on Inventory`)
        assert.deepEqual(await spillingDescendants(page, 'section[aria-label="Project inventory"]'), [], `${ctx}: inventory children`)
        assert.deepEqual(await horizontalOverflow(page, 'section[aria-label="Project inventory"]'), [], ctx)
        await shot(page, 'project-inventory', vp, theme)

        await openProject(page, main!, ids!.workbench, 'personas')
        const personaRow = page.locator('section[aria-label="Test accounts"] .border-b', { hasText: LONG_HANDLE }).first()
        const rowGeo = await personaRow.evaluate(el => {
          const strong = el.querySelector('strong')!.getBoundingClientRect()
          const actions = el.querySelector('[data-slot=persona-row-actions]')!.getBoundingClientRect()
          const row = el.firstElementChild as HTMLElement
          return {
            clear: strong.right <= actions.left + 1 || strong.bottom <= actions.top + 1,
            overflow: row.scrollWidth > row.clientWidth + 1,
          }
        })
        assert.equal(rowGeo.overflow, false, `${ctx}: persona row overflow`)
        assert.ok(rowGeo.clear, `${ctx}: handle never runs under the actions (A-060)`)
        assert.equal(await filledPrimaryCount(page), 1, `${ctx}: one filled primary on Test Accounts`)
        await shot(page, 'project-personas', vp, theme)

        await openProject(page, main!, ids!.workbench, 'guardrails')
        assert.equal(await filledPrimaryCount(page), 1, `${ctx}: one filled primary on Guardrails`)
      }))
    })

    it('empty overview offers New run and never says "0 hosts" (A-068); runs tab has no duplicate New run (A-069)', async t => {
      if (skipReason) return t.skip(skipReason)
      await withPage(main!, desktop, 'light', async page => {
        await openProject(page, main!, ids!.unbroken)
        // The empty-state copy interpolates a 180-char unbroken name; it must wrap inside its card.
        assert.deepEqual(await spillingDescendants(page, 'section[aria-label="Run history"]'), [], 'empty runs card wraps long names')
        const text = await page.locator('main').innerText()
        assert.doesNotMatch(text, /\b0 hosts\b/)
        assert.match(await page.locator('[data-slot=posture-title]').innerText(), /^Ready to assess 1 host$/)
        assert.doesNotMatch(text, /Use New run in the header/)
        await page.locator('[data-slot=empty-state]').getByRole('button', { name: 'Start first run' }).click()
        await page.locator('[data-slot=dialog-content]').waitFor()
        await page.keyboard.press('Escape')
        await openProject(page, main!, ids!.workbench, 'runs')
        assert.equal(await page.locator('section[aria-label="Project runs"]').getByRole('button', { name: 'New run' }).count(), 0)
        assert.match(await page.locator('section[aria-label="Project runs"]').innerText(), /999,999 reqs/)
        await openProject(page, main!, ids!.grouped)
        assert.match(await page.locator('[data-slot=posture-title]').innerText(), /^Latest run stopped$/)
      })
    })

    it('New run modal: focus, pills, inline validation, footer error, top anchoring (A-056..A-059, A-061, A-063)', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(main!, vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, main!, ids!.workbench)
        await page.locator('main header').getByRole('button', { name: 'New run' }).click()
        const dialog = page.locator('[data-slot=dialog-content]')
        await dialog.waitFor()
        await delay(200)
        assert.match(await activeDescription(page), /\|radio\|true\|/, `${ctx}: focus starts on checked scan mode`)
        const pills = await dialog.evaluate(root => {
          const box = root.getBoundingClientRect()
          return [...root.querySelectorAll('[data-slot=persona-pill]')].map(pill => {
            const verify = pill.querySelector('button[aria-label^="Verify sign-in"]')!.getBoundingClientRect()
            return { verifyVisible: verify.width > 20 && verify.right <= box.right + 1 && verify.left >= box.left - 1, hasSvg: Boolean(pill.querySelector('svg path')) }
          })
        })
        assert.equal(pills.length, 2, ctx)
        for (const p of pills) {
          assert.ok(p.verifyVisible, `${ctx}: Verify sign-in visible`)
          assert.ok(p.hasSvg, `${ctx}: SVG check`)
        }
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=dialog-content], [data-slot=dialog-body]'), [], ctx)
        const submit = await dialog.getByRole('button', { name: 'Start run' }).boundingBox()
        assert.ok(submit && submit.y + submit.height <= vp.height, `${ctx}: Start run above the fold`)
        await shot(page, 'new-run-modal', vp, theme)

        if (vp !== narrow && theme === 'light') {
          const top0 = await dialogTop(page)
          await dialog.getByRole('button', { name: /Advanced configuration/ }).click()
          await delay(250)
          assert.equal(await dialogTop(page), top0, `${ctx}: dialog grows downward`)
        }
      }))

      await withPage(main!, desktop, 'light', async page => {
        await openProject(page, main!, ids!.workbench)
        await page.locator('main header').getByRole('button', { name: 'New run' }).click()
        const dialog = page.locator('[data-slot=dialog-content]')
        await dialog.waitFor()
        const budget = dialog.getByLabel('USD Spend Cap')
        await budget.fill('')
        assert.equal(await budget.inputValue(), '', 'cleared budget stays empty (A-058)')
        assert.match(await dialog.locator('[data-slot=new-run-footer-summary]').innerText(), /— cap/)
        await budget.blur()
        assert.equal(await budget.getAttribute('aria-invalid'), 'true')
        assert.ok(await dialog.locator('#budget-err').isVisible())
        await dialog.getByRole('button', { name: '$25' }).click()
        assert.equal(await dialog.locator('#budget-err').count(), 0)
        await dialog.getByRole('button', { name: /Advanced configuration/ }).click()
        const rate = dialog.locator('[name=maxRpsPerOrigin]')
        await rate.fill('0')
        await rate.blur()
        assert.ok(await dialog.locator('#rate-err').isVisible(), 'rate=0 inline error')
        assert.match(await dialog.locator('[data-slot=advanced-summary]').innerText(), /— req\/s/)
        await dialog.getByRole('button', { name: 'Start run' }).click()
        await delay(100)
        assert.match(await activeDescription(page), /^input\|maxRpsPerOrigin/, 'invalid submit focuses the field')
        await rate.fill('5')

        // Forced server failure: the error renders in the sticky footer, in view, and takes focus (A-057).
        await page.route('**/_serverFn/**', async route => {
          if (route.request().method() === 'POST' && (route.request().postData() ?? '').includes('sourceMode')) {
            await route.fulfill({ status: 500, contentType: 'text/plain', body: 'Simulated run creation failure' })
            return
          }
          await route.continue()
        })
        await dialog.getByRole('button', { name: 'Start run' }).click()
        const err = dialog.locator('[data-slot=submit-error]')
        await err.waitFor({ state: 'visible', timeout: 10_000 })
        const box = (await err.boundingBox())!
        assert.ok(box.y >= 0 && box.y + box.height <= 720, `error in viewport (${box.y})`)
        assert.match(await activeDescription(page), /^p\|/, 'focus moved to the error')
        await shot(page, 'new-run-modal-error', desktop, 'light')
        await page.unroute('**/_serverFn/**')
      })
    })

    it('Edit project, Delete project, and Persona modals (A-054, A-061..A-064, A-069)', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(main!, vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, main!, ids!.unbroken)
        await openHeaderDialog(page, 'Edit project')
        assert.match(await activeDescription(page), /^input\|name\|/, `${ctx}: Edit focuses name`)
        const dialog = page.locator('[data-slot=dialog-content]')
        const seeds = dialog.locator('textarea[name=seeds]')
        await seeds.fill('https://unbroken.example.com\nnot a url')
        assert.equal(await dialog.locator('[data-slot=seed-count]').innerText(), '2 origins · 1 invalid', ctx)
        assert.match(await dialog.locator('[data-slot=seed-invalid]').innerText(), /not a url$/)
        assert.ok(await dialog.getByRole('button', { name: 'Save changes' }).isDisabled())
        await dialog.locator('input[name=name]').fill('')
        assert.ok(await dialog.getByText('Name is required').isVisible())
        assert.equal(await dialog.locator('input[name=name]').getAttribute('placeholder'), 'e.g. Acme Web')
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=dialog-content]'), [], ctx)
        await shot(page, 'edit-project-modal', vp, theme)
        await dialog.getByRole('button', { name: 'Cancel' }).click()
        await dialog.waitFor({ state: 'hidden' })

        await openHeaderDialog(page, 'Delete project')
        assert.match(await activeDescription(page), /^button\|.*Cancel$/, `${ctx}: delete starts on Cancel`)
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=dialog-content], [data-slot=dialog-body], [data-slot=dialog-description]'), [], `${ctx}: 180-char name wraps`)
        await shot(page, 'delete-project-modal', vp, theme)
        await page.keyboard.press('Escape')
        await page.locator('[data-slot=dialog-content]').waitFor({ state: 'hidden' })

        await openProject(page, main!, ids!.workbench, 'personas')
        await page.locator('section[aria-label="Test accounts"]').getByRole('button', { name: 'Add test account' }).click()
        const persona = page.locator('[data-slot=dialog-content]')
        await persona.waitFor()
        await delay(200)
        assert.match(await activeDescription(page), /^input\|roleLabel\|/, `${ctx}: Account label focused`)
        assert.equal(await persona.evaluate(el => getComputedStyle(el).transitionProperty), 'opacity, scale', `${ctx}: no layout tween (A-064)`)
        const top0 = await dialogTop(page)
        const radios = persona.getByRole('radiogroup', { name: 'Authentication mode' }).getByRole('radio')
        for (let i = 0; i < 3; i += 1) {
          await radios.nth(i).click()
          await delay(120)
          assert.equal(await dialogTop(page), top0, `${ctx}: auth method ${i} keeps top (A-063)`)
        }
        await radios.nth(0).click()
        assert.equal(await persona.getByRole('button', { name: 'Sign in with browser' }).evaluate(el => el.getAttribute('data-variant')), 'outline')
        assert.deepEqual(await horizontalOverflow(page, '[data-slot=dialog-content]'), [], ctx)
        await shot(page, 'persona-modal', vp, theme)
      }))

      await withPage(main!, desktop, 'light', async page => {
        await openProject(page, main!, ids!.workbench, 'personas')
        await page.locator('section[aria-label="Test accounts"]').getByRole('button', { name: 'Add test account' }).click()
        const persona = page.locator('[data-slot=dialog-content]')
        await persona.waitFor()
        await persona.getByRole('radiogroup', { name: 'Authentication mode' }).getByRole('radio').nth(1).click()
        await persona.getByRole('button', { name: /Save test account/ }).click()
        await persona.locator('#persona-secret-err').waitFor({ state: 'visible' })
        assert.equal(await persona.locator('input[name=secret]').getAttribute('aria-invalid'), 'true', 'inline secret validation (A-058)')
        await page.waitForFunction(() => document.activeElement?.getAttribute('name') === 'secret', undefined, { timeout: 3_000 })
      })
    })

    it('Sources tab + GitHub repo picker: one refresh, matching pills, narrow wrap (A-069..A-073)', async t => {
      if (skipReason) return t.skip(skipReason)
      await forEachCombo((vp, theme) => withPage(main!, vp, theme, async page => {
        const ctx = `${vp.label}/${theme}`
        await openProject(page, main!, ids!.workbench, 'sources')
        await page.locator('main').getByRole('button', { name: /Discover repositories|Discover & sync repos/ }).first().click()
        const sheet = page.locator('.pw-repo-sheet')
        await sheet.getByRole('group', { name: 'Accessible GitHub repositories' }).waitFor({ timeout: 15_000 })
        await settle(page)
        const refreshes = await sheet.getByRole('button', { name: /^Refresh/ }).count()
        assert.equal(refreshes, 1, `${ctx}: one refresh control`)
        assert.equal(await page.getByRole('button', { name: 'Discover repositories' }).count(), 0, `${ctx}: no discover while open`)
        const pills = await sheet.evaluate(root => {
          const vis = [...root.querySelectorAll('label span')].filter(el => /^(public|private)$/.test(el.textContent?.trim() ?? ''))
          const counts = [...root.querySelectorAll('[data-slot=owner-count-pill], [data-slot=owner-selected-pill]')]
          return {
            visBorders: vis.map(el => parseFloat(getComputedStyle(el).borderTopWidth)),
            countFit: counts.map(el => el.scrollHeight <= el.clientHeight),
          }
        })
        assert.ok(pills.visBorders.length >= 2 && pills.visBorders.every(w => w >= 1), `${ctx}: both visibility pills bordered`)
        assert.ok(pills.countFit.length >= 2 && pills.countFit.every(Boolean), `${ctx}: count pills centre their digits`)
        assert.deepEqual(await spillingDescendants(page, '.pw-repo-sheet'), [], `${ctx}: picker has no overflowing nodes`)
        const orgRows = await sheet.evaluate(root => [...root.querySelectorAll('[data-slot=org-actions]')].map(actions => {
          const toggle = actions.parentElement!.querySelector('button[aria-expanded]')!
          const pill = toggle.querySelector('[data-slot=owner-count-pill]')!.getBoundingClientRect()
          const visible = [...actions.children].filter(el => Number(getComputedStyle(el).opacity) > 0)
            .map(el => el.getBoundingClientRect())
          const owner = toggle.querySelector('span[title]')!
          return {
            ownerWidth: owner.getBoundingClientRect().width,
            pillInsideToggle: pill.right <= toggle.getBoundingClientRect().right + 1,
            clear: visible.every(r => r.left >= pill.right - 1 || r.top >= pill.bottom - 1),
          }
        }))
        for (const r of orgRows) {
          assert.ok(r.ownerWidth >= 30, `${ctx}: owner name keeps >= 6ch (${r.ownerWidth})`)
          assert.ok(r.pillInsideToggle && r.clear, `${ctx}: owner count pill never overlaps org actions`)
        }
        assert.ok(await nativeSearchCancelSuppressed(page, '.pw-repo-sheet input[type=search]'), `${ctx}: picker search has no native cancel`)
        assert.equal(await filledPrimaryCount(page), 1, `${ctx}: one filled tab-level primary with the picker open`)
        await shot(page, 'sources-repo-picker', vp, theme)
        await sheet.locator('input[type=search]').scrollIntoViewIfNeeded()
        await shot(page, 'sources-repo-picker-list', vp, theme)
      }))
    })

    it('no uncaught page errors', t => {
      if (skipReason) return t.skip(skipReason)
      assert.deepEqual(pageErrors, [])
    })
  })
}

// Entry point (kept last so every module-level constant above is initialised).
if (process.env[GITHUB_MOCK_ENV] === '1') {
  installGithubFetchMock()
} else {
  defineSuite()
}
